package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/satriazoid/gas/internal/config"
)

// newTestEngine builds a project with a white box and the shipped defaults.
func newTestEngine(t *testing.T) (*Engine, string) {
	t.Helper()
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	for _, d := range []string{"src", "tests", "docs", ".git/hooks", "node_modules/.bin", "config"} {
		if err := os.MkdirAll(filepath.Join(project, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.HomeDir = home
	cfg.ProjectDir = project
	cfg.AllowRoots = []string{project}
	// Pin the write globs: the test project lives inside a system temp dir, so
	// the shipped "temp/**" glob would allow every write here.
	cfg.WritablePaths = []string{"src/**/*.go", "output/**"}
	return New(cfg), home
}

func TestGlobalDenyWins(t *testing.T) {
	eng, home := newTestEngine(t)
	cases := []struct {
		name string
		path string
		op   Op
	}{
		{"ssh key", filepath.Join(home, ".ssh", "id_rsa"), OpRead},
		{"ssh key inside project", filepath.Join(eng.project, ".ssh", "id_rsa"), OpRead},
		{"aws credentials", filepath.Join(home, ".aws", "credentials"), OpRead},
		{"env file", filepath.Join(eng.project, ".env"), OpRead},
		{"pem", filepath.Join(eng.project, "certs", "x.pem"), OpRead},
		{"bash history", filepath.Join(home, ".bash_history"), OpRead},
		{"etc shadow", "/etc/shadow", OpRead},
		{"windows system32", `C:\Windows\System32\config\SAM`, OpRead},
		{"git hooks exec", filepath.Join(eng.project, ".git", "hooks", "pre-commit"), OpExec},
		{"node_modules bin exec", filepath.Join(eng.project, "node_modules", ".bin", "evil"), OpExec},
	}
	for _, c := range cases {
		d := eng.Check(c.path, c.op)
		if d.Allowed {
			t.Errorf("%s: expected DENY for %s, got allow (reason=%s)", c.name, c.path, d.Reason)
		}
		if d.Reason == ReasonAllowed || d.Reason == "" {
			t.Errorf("%s: missing deny reason", c.name)
		}
	}
}

func TestProjectWhiteBox(t *testing.T) {
	eng, _ := newTestEngine(t)
	allowed := []struct {
		path string
		op   Op
	}{
		{filepath.Join(eng.project, "src", "main.go"), OpRead},
		{filepath.Join(eng.project, "README.md"), OpRead},
		{filepath.Join(eng.project, "src", "main.go"), OpWrite},
		{filepath.Join(eng.project, "output", "report.txt"), OpWrite},
	}
	for _, a := range allowed {
		if d := eng.Check(a.path, a.op); !d.Allowed {
			t.Errorf("expected ALLOW for %s (%s), got deny reason=%s rule=%s", a.path, a.op, d.Reason, d.Rule)
		}
	}

	denied := []struct {
		path string
		op   Op
	}{
		{filepath.Join(eng.project, "..", "outside", "secret.txt"), OpRead},
		{filepath.Join(eng.project, "config", "prod.yaml"), OpWrite},
		{"", OpRead},
	}
	for _, d := range denied {
		if res := eng.Check(d.path, d.op); res.Allowed {
			t.Errorf("expected DENY for %q (%s), got allow", d.path, d.op)
		}
	}
}

func TestParentTraversalBlocked(t *testing.T) {
	eng, _ := newTestEngine(t)
	outside := filepath.Join(eng.project, "..", "..", "outside.txt")
	if d := eng.Check(outside, OpRead); d.Allowed {
		t.Fatalf("traversal escaped the white box: %s allowed", outside)
	}
}

func TestSymlinkEscapeBlocked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	eng, home := newTestEngine(t)
	secret := filepath.Join(home, "payroll.txt")
	if err := os.WriteFile(secret, []byte("salary"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(eng.project, "shortcut")
	if err := os.Symlink(home, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	viaLink := filepath.Join(link, "payroll.txt")
	if d := eng.Check(viaLink, OpRead); d.Allowed {
		t.Fatalf("symlink escape allowed: %s -> %s", viaLink, d.Resolved)
	}
}

func TestReadOnlyMode(t *testing.T) {
	eng, _ := newTestEngine(t)
	eng.cfg.ReadOnly = true
	if d := eng.Check(filepath.Join(eng.project, "src", "main.go"), OpWrite); d.Allowed || d.Reason != ReasonReadOnly {
		t.Fatalf("read-only mode should deny writes, got allowed=%v reason=%s", d.Allowed, d.Reason)
	}
}

func TestFailClosedOnEmptyPath(t *testing.T) {
	eng, _ := newTestEngine(t)
	d := eng.Check("   ", OpRead)
	if d.Allowed || d.Reason != ReasonInvalidPath {
		t.Fatalf("empty path must be denied fail-closed, got %+v", d)
	}
}

func TestMergeNeverLoosens(t *testing.T) {
	base := config.Default()
	base.ReadOnly = true
	base.FailClosed = true
	over := &config.Config{ReadOnly: false, FailClosed: false, DenyPatterns: []string{"**/extra.txt"}}
	config.Merge(base, over)
	if !base.ReadOnly || !base.FailClosed {
		t.Fatal("merge loosened a project-level restriction")
	}
	if len(base.DenyPatterns) < 2 {
		t.Fatal("merge dropped deny patterns")
	}
}
