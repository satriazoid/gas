//go:build !linux && !windows

package isolation

import (
	"fmt"

	"github.com/satriazoid/gas/internal/config"
)

// Capabilities reports what this platform can enforce.
func Capabilities() Capability {
	return Capability{
		OS:        "other",
		Namespace: false,
		Policy:    true,
		Filter:    true,
		Detail:    "no kernel jail: use policy checks plus the stdio filter",
	}
}

// Resolve maps the requested mode to a supported one.
func Resolve(requested string, allowDegrade bool) (Mode, []string, error) {
	switch requested {
	case "", config.ModeAuto, string(ModePolicy):
		return ModePolicy, []string{"auto-selected policy mode"}, nil
	case string(ModeFilter):
		return ModeFilter, nil, nil
	case string(ModeNamespace):
		if !allowDegrade {
			return "", nil, fmt.Errorf("namespace isolation is Linux only; use --mode policy or pass --allow-degrade")
		}
		return ModePolicy, []string{"namespace requested but unavailable; degraded to policy mode"}, nil
	}
	return "", nil, fmt.Errorf("unknown mode %q", requested)
}

// Prepare launches the agent with the GAS environment injected.
func Prepare(opt Options, mode Mode) (*Sandbox, error) {
	cmd, err := baseCmd(opt, mode)
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &Sandbox{Cmd: cmd, Mode: mode, Close: func() {}}, nil
}
