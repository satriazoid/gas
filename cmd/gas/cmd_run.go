package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/satriazoid/gas/internal/audit"
	"github.com/satriazoid/gas/internal/config"
	"github.com/satriazoid/gas/internal/isolation"
	"github.com/satriazoid/gas/internal/policy"
	"github.com/satriazoid/gas/internal/proxy"
)

const unsafeBanner = `
  ############################################################
  #  GAS SANDBOX DISABLED  (--unsafe)                        #
  #  The agent now has UNRESTRICTED filesystem access.       #
  #  This run is recorded in the audit log as a bypass.      #
  ############################################################
`

func cmdRun(args []string) error {
	f, rest, err := parseFlags(args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("run needs an agent command, e.g. gas run --project ./app hermes")
	}
	eng, cfg, err := loadEngine(f)
	if err != nil {
		return err
	}
	label := f.agentName
	if label == "" {
		label = filepath.Base(rest[0])
	}
	log := newLogger(cfg, label)

	if f.unsafe {
		fmt.Fprint(os.Stderr, unsafeBanner)
		log.Event(audit.ActionBypass, audit.Entry{Source: "cli", Detail: "agent started with --unsafe; policy not enforced"})
		return runUnsafe(rest, cfg)
	}

	mode, notes, err := isolation.Resolve(f.mode, f.allowDegrade)
	if err != nil {
		return fmt.Errorf("%w (fail-closed: agent not started)", err)
	}
	if f.wrapJSON {
		mode = isolation.ModeFilter
	}
	for _, n := range notes {
		fmt.Fprintf(os.Stderr, "gas: %s\n", n)
	}

	caps := isolation.Capabilities()
	fmt.Fprintf(os.Stderr, "gas: mode=%s project=%s\n", mode, cfg.ProjectDir)
	if len(cfg.Sources) > 0 {
		fmt.Fprintf(os.Stderr, "gas: policy from %s\n", strings.Join(cfg.Sources, ", "))
	}
	if !caps.Namespace && mode != isolation.ModeNamespace {
		fmt.Fprintln(os.Stderr, "gas: note: policy checks apply to agent tool calls; shell commands inside the project are logged by the agent (see docs/design.md)")
	}
	log.Event(audit.ActionStart, audit.Entry{Source: "cli", Detail: string(mode)})

	opt := isolation.Options{
		Config:       cfg,
		ProjectDir:   cfg.ProjectDir,
		Agent:        rest,
		AgentLabel:   label,
		AllowDegrade: f.allowDegrade,
		GasBin:       isolation.Self(),
		Log:          log,
		AllowRoots:   eng.AllowRoots(),
	}

	if mode == isolation.ModeFilter {
		return runFiltered(opt, eng, log, label)
	}

	opt.Stdin, opt.Stdout, opt.Stderr = os.Stdin, os.Stdout, os.Stderr
	sb, err := isolation.Prepare(opt, mode)
	if err != nil {
		return err
	}
	defer sb.Close()
	for _, n := range sb.Notes {
		fmt.Fprintf(os.Stderr, "gas: %s\n", n)
	}
	code := waitFor(sb.Cmd)
	log.Event(audit.ActionExit, audit.Entry{Source: "cli", Detail: fmt.Sprintf("exit=%d", code)})
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

// runUnsafe executes the agent with no policy at all.
func runUnsafe(rest []string, cfg *config.Config) error {
	cmd := exec.Command(rest[0], rest[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Dir = cfg.ProjectDir
	cmd.Env = append(os.Environ(),
		"GAS_SANDBOX=0",
		"GAS_UNSAFE=1",
		"GAS_PROJECT="+cfg.ProjectDir,
	)
	if err := cmd.Start(); err != nil {
		return err
	}
	code := waitFor(cmd)
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

// waitFor blocks until the child exits, forwarding SIGINT/SIGTERM so a
// force-stop kills the whole tree instead of orphaning the agent.
func waitFor(cmd *exec.Cmd) int {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-ch
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()
	err := cmd.Wait()
	signal.Stop(ch)
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	fmt.Fprintf(os.Stderr, "gas: agent exited: %v\n", err)
	return 1
}

// runFiltered starts the agent and filters its stdio JSON messages.
func runFiltered(opt isolation.Options, eng *policy.Engine, log *audit.Logger, label string) error {
	cmd := exec.Command(opt.Agent[0], opt.Agent[1:]...)
	cmd.Dir = opt.ProjectDir
	cmd.Env = append(os.Environ(), isolation.GasEnv(opt.Config, opt.GasBin)...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	filter := proxy.New(eng, log, label)
	go pipeFiltered(os.Stdin, stdin, filter)
	go pipeFiltered(stdout, os.Stdout, filter)

	code := waitFor(cmd)
	log.Event(audit.ActionExit, audit.Entry{Source: "proxy", Detail: fmt.Sprintf("exit=%d", code)})
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

// pipeFiltered copies lines through the filter. The blocked reply is written
// back to the same stream the request came from, which is what the agent is
// reading from (stdout) when it talks to its host over stdio.
func pipeFiltered(src io.Reader, dst io.WriteCloser, filter *proxy.Filter) {
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		out, blocked := filter.Handle(line)
		if blocked {
			logBlocked(filter)
			if _, err := dst.Write(out); err != nil {
				_ = dst.Close()
				return
			}
			if _, err := dst.Write([]byte("\n")); err != nil {
				_ = dst.Close()
				return
			}
			continue
		}
		if _, err := dst.Write(line); err != nil {
			_ = dst.Close()
			return
		}
		if _, err := dst.Write([]byte("\n")); err != nil {
			_ = dst.Close()
			return
		}
	}
	_ = dst.Close()
}

func logBlocked(filter *proxy.Filter) {
	path := filter.LogPath()
	if path == "" {
		fmt.Fprintln(os.Stderr, "gas: blocked tool call")
		return
	}
	fmt.Fprintf(os.Stderr, "gas: blocked tool call (see %s)\n", path)
}
