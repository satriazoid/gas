// Command gas is the Guardian Agent Sandbox CLI: it launches AI coding agents
// under a whitelist/blacklist policy and logs every denied access.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/satriazoid/gas/internal/audit"
	"github.com/satriazoid/gas/internal/config"
	"github.com/satriazoid/gas/internal/isolation"
	"github.com/satriazoid/gas/internal/policy"
)

// version is overridden at build time (-ldflags "-X main.version=...").
var version = "1.0.0-dev"

const usage = `Guardian Agent Sandbox (gas) - run AI agents behind a filesystem policy.

Usage:
  gas init [--global] [--force]        write a starter policy
  gas run [flags] <agent> [args...]    launch an agent inside the sandbox
  gas check [--op read|write|exec] P   ask the policy about a path
  gas status [--json]                  policy + audit summary
  gas log [--tail N] [--json]          recent audit entries
  gas policy [--json]                  effective allow/deny lists
  gas contract [DIR] [--force]         print/install the AGENTS.md agent contract
  gas doctor [--json]                  environment and capability check
  gas version

RUN FLAGS
  --project DIR        project root (default: current directory)
  --agent-name NAME    label used in the audit log
  --mode MODE          auto | namespace | policy | filter
  --read-only          deny every write
  --allow-system-libs  bind-mount /usr/lib read-only (namespace mode)
  --allow-degrade      allow falling back to a weaker mode when needed
  --unsafe             DISABLE the sandbox (audited, loudly warned)
  --wrap-json          filter agent stdio JSON tool calls (proxy mode)

ENVIRONMENT INJECTED INTO THE AGENT
  GAS_SANDBOX=1 GAS_PROJECT GAS_CHECK GAS_LOG GAS_POLICY_FILE GAS_MODE

Exit codes: 0 ok, 1 blocked or error, 2 usage, 126 check denied.
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(2)
	}

	// Internal re-exec entry point used by Linux namespace isolation.
	if args[0] == sandboxInitCmd {
		os.Exit(isolation.RunInit(args[1:]))
	}

	var err error
	switch args[0] {
	case "run", "exec":
		err = cmdRun(args[1:])
	case "check":
		err = cmdCheck(args[1:])
	case "init":
		err = cmdInit(args[1:])
	case "status":
		err = cmdStatus(args[1:])
	case "log", "logs":
		err = cmdLog(args[1:])
	case "policy":
		err = cmdPolicy(args[1:])
	case "contract", "agents":
		err = cmdContract(args[1:])
	case "doctor", "selftest":
		err = cmdDoctor(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("gas %s (%s/%s, go policy engine)\n", version, runtime.GOOS, runtime.GOARCH)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "gas: unknown command %q\n\n%s", args[0], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "gas: %v\n", err)
		os.Exit(1)
	}
}

// sandboxInitCmd is shared with the isolation package.
const sandboxInitCmd = "__sandbox-init"

// flags holds parsed command line options.
type flags struct {
	project         string
	agentName       string
	mode            string
	readOnly        bool
	allowSystemLibs bool
	allowDegrade    bool
	unsafe          bool
	wrapJSON        bool
	jsonOut         bool
	global          bool
	force           bool
	op              string
	tail            int
}

// parseFlags consumes leading flags and returns the remaining arguments.
func parseFlags(args []string) (*flags, []string, error) {
	f := &flags{tail: 20, op: string(policy.OpRead)}
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if !strings.HasPrefix(a, "-") {
			break
		}
		name, val := a, ""
		if j := strings.IndexByte(a, '='); j > 0 {
			name, val = a[:j], a[j+1:]
		}
		next := func() (string, error) {
			if val != "" {
				return val, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag %s needs a value", name)
			}
			i++
			return args[i], nil
		}
		boolVal := func() bool { return val == "" || val == "true" || val == "1" || val == "yes" }
		switch name {
		case "--project", "-p":
			v, err := next()
			if err != nil {
				return nil, nil, err
			}
			f.project = v
		case "--agent-name", "--agent":
			v, err := next()
			if err != nil {
				return nil, nil, err
			}
			f.agentName = v
		case "--mode":
			v, err := next()
			if err != nil {
				return nil, nil, err
			}
			f.mode = v
		case "--op":
			v, err := next()
			if err != nil {
				return nil, nil, err
			}
			f.op = v
		case "--tail", "-n":
			v, err := next()
			if err != nil {
				return nil, nil, err
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, nil, fmt.Errorf("--tail needs a number, got %q", v)
			}
			f.tail = n
		case "--read-only":
			f.readOnly = boolVal()
		case "--allow-system-libs":
			f.allowSystemLibs = boolVal()
		case "--allow-degrade":
			f.allowDegrade = boolVal()
		case "--unsafe":
			f.unsafe = boolVal()
		case "--wrap-json":
			f.wrapJSON = boolVal()
		case "--json":
			f.jsonOut = boolVal()
		case "--global", "-g":
			f.global = boolVal()
		case "--force", "-f":
			f.force = boolVal()
		case "--help", "-h":
			fmt.Print(usage)
			os.Exit(0)
		default:
			return nil, nil, fmt.Errorf("unknown flag %q", name)
		}
	}
	return f, args[i:], nil
}

func loadEngine(f *flags) (*policy.Engine, *config.Config, error) {
	project := f.project
	if project == "" {
		project = "."
	}
	abs, err := filepath.Abs(project)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := config.Load(abs)
	if err != nil {
		return nil, nil, err
	}
	if f.readOnly {
		cfg.ReadOnly = true
	}
	if f.allowSystemLibs {
		cfg.AllowSystemLibs = true
	}
	if f.mode != "" {
		cfg.Mode = f.mode
	}
	return policy.New(cfg), cfg, nil
}

func newLogger(cfg *config.Config, agent string) *audit.Logger {
	return audit.New(cfg, agent)
}
