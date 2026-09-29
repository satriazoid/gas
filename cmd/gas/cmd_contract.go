package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed templates/agents-contract.md
var agentsContract string

// cmdContract prints the agent-side contract block, optionally installing it
// into a project's AGENTS.md.
func cmdContract(args []string) error {
	f, rest, err := parseFlags(args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		fmt.Print(agentsContract)
		return nil
	}

	project := f.project
	if project == "" {
		project = rest[0]
	}
	target := filepath.Join(project, "AGENTS.md")
	if f.global {
		target = filepath.Join(project, "AGENTS.md")
	}

	existing, err := os.ReadFile(target)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(existing) > 0 && !f.force {
		fmt.Printf("skip   %s (exists; use --force to overwrite)\n", target)
		return nil
	}
	body := agentsContract
	if len(existing) > 0 {
		body = string(existing) + "\n\n" + agentsContract
	}
	if err := os.WriteFile(target, []byte(body), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote  %s\n", target)
	fmt.Println("       the agent now routes file tools through `gas check` ($GAS_CHECK)")
	return nil
}
