// Package isolation launches the wrapped agent. It provides kernel-level
// namespace isolation on Linux and an env + job-object containment mode
// everywhere else. The wrapper is fail-closed: when the requested isolation
// cannot be established the agent is not started.
package isolation

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/satriazoid/gas/internal/audit"
	"github.com/satriazoid/gas/internal/config"
)

// Mode is the isolation strategy in use.
type Mode string

// Supported modes.
const (
	// ModeNamespace is Linux user+mount+pid namespace isolation.
	ModeNamespace Mode = "namespace"
	// ModePolicy is env injection + policy checks through `gas check`.
	ModePolicy Mode = "policy"
	// ModeFilter adds the stdio JSON filter on top of ModePolicy.
	ModeFilter Mode = "filter"
)

// Options describes one sandboxed launch.
type Options struct {
	Config       *config.Config
	ProjectDir   string
	Agent        []string
	AgentLabel   string
	AllowDegrade bool
	GasBin       string
	Log          *audit.Logger

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// AllowRoots is the compiled read whitelist (from the policy engine),
	// used by kernel-level namespace isolation.
	AllowRoots []string
}

// Sandbox is a prepared child process.
type Sandbox struct {
	Cmd   *exec.Cmd
	Mode  Mode
	Notes []string
	// Close releases containment resources (job object, namespaces).
	Close func()
}

// Capability describes what the host platform can enforce.
type Capability struct {
	OS        string `json:"os"`
	Namespace bool   `json:"namespace"`
	Policy    bool   `json:"policy"`
	Filter    bool   `json:"filter"`
	Detail    string `json:"detail"`
}

// RunInit is the re-exec entry point used by namespace isolation. Platforms
// that do not implement it leave it as a failure stub.
var RunInit = func([]string) int {
	return 2
}

// GasEnv returns the environment injected into every sandboxed agent.
func GasEnv(cfg *config.Config, self string) []string {
	env := []string{
		"GAS_SANDBOX=1",
		"GAS_VERSION=" + Version,
		"GAS_MODE=strict",
		"GAS_PROJECT=" + cfg.ProjectDir,
		"GAS_CONFIG=" + cfg.GlobalPath,
		"GAS_POLICY_FILE=" + cfg.ProjectPath,
		"GAS_CHECK=" + self + " check",
		"GAS_LOG=" + cfg.LogPath(),
	}
	return env
}

// Version is stamped at build time.
var Version = "1.0.0-dev"

// Self returns the running binary path.
func Self() string {
	p, err := os.Executable()
	if err != nil {
		return "gas"
	}
	return p
}

// joinEnv appends overrides to the current environment, replacing duplicates.
func joinEnv(extra []string) []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+len(extra))
	replaced := map[string]bool{}
	for _, e := range extra {
		if i := strings.IndexByte(e, '='); i > 0 {
			replaced[strings.ToUpper(e[:i])] = true
		}
	}
	for _, e := range base {
		if i := strings.IndexByte(e, '='); i > 0 {
			if replaced[strings.ToUpper(e[:i])] {
				continue
			}
		}
		out = append(out, e)
	}
	return append(out, extra...)
}

// splitList splits a |-separated list.
func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "|")
	out := parts[:0]
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

// baseCmd builds the plain (non-namespace) sandboxed command: agent process
// with the GAS environment injected and the project as working directory.
func baseCmd(opt Options, mode Mode) (*exec.Cmd, error) {
	if len(opt.Agent) == 0 {
		return nil, fmt.Errorf("no agent command given")
	}
	bin := opt.Agent[0]
	if strings.ContainsAny(bin, "/\\") {
		if abs, err := filepath.Abs(bin); err == nil {
			bin = abs
		}
	}
	cmd := exec.Command(bin, opt.Agent[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = opt.Stdin, opt.Stdout, opt.Stderr
	cmd.Dir = opt.ProjectDir
	cmd.Env = joinEnv(GasEnv(opt.Config, opt.GasBin))
	return cmd, nil
}
