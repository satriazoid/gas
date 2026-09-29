package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/satriazoid/gas/internal/config"
	"github.com/satriazoid/gas/internal/isolation"
	"github.com/satriazoid/gas/internal/policy"
)

// checkCase is one self-test assertion.
type checkCase struct {
	Name   string `json:"name"`
	Input  string `json:"input"`
	Op     string `json:"op"`
	Want   bool   `json:"want_allow"`
	Got    bool   `json:"got_allow"`
	Reason string `json:"reason"`
	Pass   bool   `json:"pass"`
}

// cmdDoctor verifies the environment and self-tests the policy engine against
// the PRD's default deny list.
func cmdDoctor(args []string) error {
	f, _, err := parseFlags(args)
	if err != nil {
		return err
	}
	eng, cfg, err := loadEngine(f)
	if err != nil {
		return err
	}
	caps := isolation.Capabilities()

	home, _ := os.UserHomeDir()
	cases := []checkCase{
		{"ssh private key never readable", filepath.Join(home, ".ssh", "id_rsa"), "read", false, false, "", false},
		{"aws credentials blocked", filepath.Join(home, ".aws", "credentials"), "read", false, false, "", false},
		{"dotenv blocked in project", filepath.Join(cfg.ProjectDir, ".env"), "read", false, false, "", false},
		{"pem key blocked", filepath.Join(cfg.ProjectDir, "certs", "server.pem"), "read", false, false, "", false},
		{"bash history blocked", filepath.Join(home, ".bash_history"), "read", false, false, "", false},
		{"etc shadow blocked", "/etc/shadow", "read", false, false, "", false},
		{"outside project blocked", filepath.Join(home, "Documents", "private-notes.txt"), "read", false, false, "", false},
		{"project source readable", filepath.Join(cfg.ProjectDir, "src", "main.go"), "read", true, false, "", false},
		{"project readme readable", filepath.Join(cfg.ProjectDir, "README.md"), "read", true, false, "", false},
		{"project write allowed (src)", filepath.Join(cfg.ProjectDir, "src", "app.ts"), "write", true, false, "", false},
		{"write outside writable blocked", filepath.Join(cfg.ProjectDir, "config", "prod.yaml"), "write", false, false, "", false},
		{"parent traversal blocked", filepath.Join(cfg.ProjectDir, "..", "other-project", "secret.txt"), "read", false, false, "", false},
		{"symlinked ssh dir blocked", filepath.Join(cfg.ProjectDir, "link-to-ssh", "id_rsa"), "read", false, false, "", false},
		{"git hooks not executable", filepath.Join(cfg.ProjectDir, ".git", "hooks", "pre-commit"), "exec", false, false, "", false},
		{"node_modules bin not executable", filepath.Join(cfg.ProjectDir, "node_modules", ".bin", "evil"), "exec", false, false, "", false},
	}
	if cfg.ReadOnly {
		cases = append(cases, checkCase{"read-only denies src write", filepath.Join(cfg.ProjectDir, "src", "app.ts"), "write", false, false, "", false})
	}

	failures := 0
	for i := range cases {
		c := &cases[i]
		d := eng.Check(c.Input, policy.Op(c.Op))
		c.Got = d.Allowed
		c.Reason = d.Reason
		c.Pass = d.Allowed == c.Want
		if !c.Pass {
			failures++
		}
	}

	if f.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"version":      version,
			"capabilities": caps,
			"project":      cfg.ProjectDir,
			"policy_files": cfg.Sources,
			"cases":        cases,
			"failures":     failures,
		})
	}

	fmt.Printf("gas doctor  version=%s\n", version)
	fmt.Printf("os              %s\n", caps.OS)
	fmt.Printf("namespace       %v  (%s)\n", caps.Namespace, caps.Detail)
	fmt.Printf("policy files    %s\n", orDash(strings.Join(cfg.Sources, ", ")))
	fmt.Printf("allow roots     %s\n", strings.Join(eng.AllowRoots(), " | "))
	fmt.Printf("deny patterns   %d   writable globs %d\n", len(eng.DenyPatterns()), len(eng.WritablePaths()))
	fmt.Println()
	for _, c := range cases {
		status := "PASS"
		if !c.Pass {
			status = "FAIL"
		}
		fmt.Printf("%s  %-34s want_allow=%-5v got=%-5v reason=%s\n", status, c.Name, c.Want, c.Got, c.Reason)
	}
	fmt.Println()
	if failures > 0 {
		fmt.Printf("result: %d/%d checks failed\n", failures, len(cases))
		return fmt.Errorf("policy self-test failed")
	}
	fmt.Printf("result: all %d checks passed\n", len(cases))
	return nil
}

// ensure config helpers exist for older builds.
var _ = config.GasHome
