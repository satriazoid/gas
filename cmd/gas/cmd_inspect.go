package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/satriazoid/gas/internal/audit"
	"github.com/satriazoid/gas/internal/config"
	"github.com/satriazoid/gas/internal/isolation"
	"github.com/satriazoid/gas/internal/policy"
)

// cmdCheck answers the policy question for one path. Exit code 0 = allowed,
// 126 = denied, so hooks can shell out to `gas check <path>`.
func cmdCheck(args []string) error {
	f, rest, err := parseFlags(args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("check needs a path, e.g. gas check --op write ./src/main.go")
	}
	eng, cfg, err := loadEngine(f)
	if err != nil {
		return err
	}
	log := newLogger(cfg, "gas-check")

	op := policy.OpRead
	switch strings.ToLower(f.op) {
	case "read", "r", "":
		op = policy.OpRead
	case "write", "w", "edit":
		op = policy.OpWrite
	case "exec", "run", "x":
		op = policy.OpExec
	default:
		return fmt.Errorf("unknown op %q (use read, write or exec)", f.op)
	}

	d := eng.Check(rest[0], op)
	if !d.Allowed {
		log.Block(audit.Entry{
			Action: audit.ActionBlocked,
			Op:     string(op),
			Path:   d.Path,
			Reason: d.Reason,
			Rule:   d.Rule,
			Scope:  d.Scope,
			Source: "cli-check",
		})
	}
	if f.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(d); err != nil {
			return err
		}
	} else if d.Allowed {
		fmt.Printf("ALLOW  %s  op=%s rule=%s\n", d.Path, d.Op, orDash(d.Rule))
	} else {
		fmt.Printf("DENY   %s  op=%s reason=%s rule=%s\n", d.Path, d.Op, d.Reason, orDash(d.Rule))
	}
	if !d.Allowed {
		os.Exit(126)
	}
	return nil
}

// cmdInit writes starter policy files.
func cmdInit(args []string) error {
	f, _, err := parseFlags(args)
	if err != nil {
		return err
	}
	home := config.GasHome()
	targets := map[string]string{}
	if f.global {
		targets[config.GlobalPath(home)] = config.DefaultGlobalYAML()
	} else {
		project := f.project
		if project == "" {
			project = "."
		}
		targets[config.ProjectPath(project)] = config.DefaultProjectYAML()
		targets[config.GlobalPath(home)] = config.DefaultGlobalYAML()
	}
	for path, body := range targets {
		if _, err := os.Stat(path); err == nil && !f.force {
			fmt.Printf("skip   %s (exists; use --force to overwrite)\n", path)
			continue
		}
		if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			return err
		}
		fmt.Printf("wrote  %s\n", path)
	}
	return nil
}

// cmdStatus prints the compact operator view.
func cmdStatus(args []string) error {
	f, _, err := parseFlags(args)
	if err != nil {
		return err
	}
	eng, cfg, err := loadEngine(f)
	if err != nil {
		return err
	}
	log := newLogger(cfg, "gas-status")
	st := log.Stats()
	caps := isolation.Capabilities()

	if f.jsonOut {
		payload := map[string]any{
			"version":        version,
			"project":        cfg.ProjectDir,
			"home":           config.GasHome(),
			"mode":           cfg.Mode,
			"read_only":      cfg.ReadOnly,
			"fail_closed":    cfg.FailClosed,
			"policy_sources": cfg.Sources,
			"allow_roots":    eng.AllowRoots(),
			"deny_patterns":  len(eng.DenyPatterns()),
			"writable":       len(eng.WritablePaths()),
			"capabilities":   caps,
			"audit":          st,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}

	fmt.Printf("gas %s  os=%s\n", version, caps.OS)
	fmt.Printf("project        %s\n", cfg.ProjectDir)
	fmt.Printf("policy files   %s\n", orDash(strings.Join(cfg.Sources, ", ")))
	fmt.Printf("mode           %s (auto-resolved: %s)\n", cfg.Mode, caps.OS)
	fmt.Printf("read_only      %v   fail_closed %v\n", cfg.ReadOnly, cfg.FailClosed)
	fmt.Printf("allow roots    %d -> %s\n", len(eng.AllowRoots()), strings.Join(eng.AllowRoots(), " | "))
	fmt.Printf("deny patterns  %d\n", len(eng.DenyPatterns()))
	fmt.Printf("writable globs %d\n", len(eng.WritablePaths()))
	fmt.Printf("namespace      %v (%s)\n", caps.Namespace, caps.Detail)
	fmt.Printf("audit log      %s (%d bytes)\n", st.Path, st.SizeBytes)
	fmt.Printf("blocks         total=%d last24h=%d bypass=%d\n", st.Blocked, st.Last24h, st.Bypass)
	if st.Last != nil {
		fmt.Printf("last block     %s %s %s\n", st.Last.TS.Format(time.RFC3339), st.Last.Op, st.Last.Path)
	}
	return nil
}

// cmdLog tails the audit log.
func cmdLog(args []string) error {
	f, _, err := parseFlags(args)
	if err != nil {
		return err
	}
	_, cfg, err := loadEngine(f)
	if err != nil {
		return err
	}
	log := newLogger(cfg, "gas-log")
	entries := log.Tail(f.tail)
	if len(entries) == 0 {
		fmt.Printf("no entries in %s\n", log.Path())
		return nil
	}
	if f.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}
	for _, e := range entries {
		fmt.Printf("%s  %-8s %-6s %-10s %s\n",
			e.TS.Format("2006-01-02 15:04:05"),
			e.Action, e.Op, orDash(e.Reason), e.Path)
	}
	return nil
}

// cmdPolicy dumps the effective compiled policy.
func cmdPolicy(args []string) error {
	f, _, err := parseFlags(args)
	if err != nil {
		return err
	}
	eng, cfg, err := loadEngine(f)
	if err != nil {
		return err
	}
	if f.jsonOut {
		payload := map[string]any{
			"config":         cfg,
			"allow_roots":    eng.AllowRoots(),
			"deny_patterns":  eng.DenyPatterns(),
			"writable_paths": eng.WritablePaths(),
			"exec_paths":     eng.ExecPaths(),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}
	fmt.Println("allow roots (read white box):")
	for _, r := range eng.AllowRoots() {
		fmt.Printf("  %s\n", r)
	}
	fmt.Println("global + project deny patterns:")
	for _, p := range eng.DenyPatterns() {
		fmt.Printf("  %s\n", p)
	}
	fmt.Println("writable globs:")
	for _, p := range eng.WritablePaths() {
		fmt.Printf("  %s\n", p)
	}
	fmt.Println("exec allow-list:")
	for _, p := range eng.ExecPaths() {
		fmt.Printf("  %s\n", p)
	}
	return nil
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i > 0 {
		return p[:i]
	}
	return "."
}
