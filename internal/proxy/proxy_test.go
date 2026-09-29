package proxy

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/satriazoid/gas/internal/config"
	"github.com/satriazoid/gas/internal/policy"
)

func newFilter(t *testing.T) (*Filter, string) {
	t.Helper()
	project := filepath.Join(t.TempDir(), "proj")
	cfg := config.Default()
	cfg.HomeDir = t.TempDir()
	cfg.ProjectDir = project
	cfg.AllowRoots = []string{project}
	cfg.Audit.Enabled = nil
	return New(policy.New(cfg), nil, "test-agent"), project
}

func TestBlocksDeniedPathInToolCall(t *testing.T) {
	f, project := newFilter(t)
	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "read_file",
			"arguments": map[string]any{"path": filepath.Join(project, ".env")},
		},
	}
	raw, _ := json.Marshal(msg)
	out, blocked := f.Handle(raw)
	if !blocked {
		t.Fatal("expected the .env read to be blocked")
	}
	if !strings.Contains(string(out), "ENOENT") {
		t.Fatalf("blocked reply must look like a fake filesystem error, got %s", out)
	}
	if strings.Contains(string(out), ".env") {
		t.Fatalf("blocked reply leaked the requested path: %s", out)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("fake error is not valid JSON: %v (%s)", err, out)
	}
	if parsed["id"] != float64(1) {
		t.Fatalf("fake error must preserve the request id, got %v", parsed["id"])
	}
}

func TestAllowsProjectPathInToolCall(t *testing.T) {
	f, project := newFilter(t)
	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"params":  map[string]any{"arguments": map[string]any{"file_path": filepath.Join(project, "src", "main.go")}, "name": "read_file"},
	}
	raw, _ := json.Marshal(msg)
	out, blocked := f.Handle(raw)
	if blocked {
		t.Fatalf("in-project read must pass, got %s", out)
	}
	if string(out) != string(raw) {
		t.Fatal("allowed messages must be forwarded unchanged")
	}
}

func TestDetectsWriteAndExecOps(t *testing.T) {
	f, project := newFilter(t)
	write := map[string]any{"params": map[string]any{"tool": "write_file", "arguments": map[string]any{"path": filepath.Join(project, "src/x.ts")}}}
	raw, _ := json.Marshal(write)
	if out, blocked := f.Handle(raw); blocked {
		t.Fatalf("write into src should be allowed: %s", out)
	}
	execMsg := map[string]any{"params": map[string]any{"name": "shell_exec", "command": "cat /etc/shadow"}}
	raw, _ = json.Marshal(execMsg)
	out, blocked := f.Handle(raw)
	if !blocked {
		t.Fatalf("shell command touching /etc/shadow must be blocked, got %s", out)
	}
}

func TestNonJSONPassesThrough(t *testing.T) {
	f, _ := newFilter(t)
	line := []byte("plain text log line")
	out, blocked := f.Handle(line)
	if blocked || string(out) != string(line) {
		t.Fatal("non-JSON lines must pass through untouched")
	}
}
