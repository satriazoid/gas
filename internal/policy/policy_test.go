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

// projectPath joins a relative path to the project using the NATIVE project
// path. Never use eng.project as an input: it is the stripped match key, and
// feeding it back would produce a doubled path.
func projectPath(eng *Engine, rel string) string {
	return filepath.Join(eng.projectNative, filepath.FromSlash(rel))
}

func TestEtcShadowBlockedOnPosix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix system path")
	}
	eng, _ := newTestEngine(t)
	for _, p := range []string{"/etc/shadow", "/etc/passwd", "/etc/sudoers"} {
		if d := eng.Check(p, OpRead); d.Allowed {
			t.Errorf("%s must be denied on posix, got allow (reason=%s)", p, d.Reason)
		}
	}
}

func TestRelativeInputResolvesAgainstProject(t *testing.T) {
	eng, _ := newTestEngine(t)
	// Relative inputs must resolve to the project root, not to a doubled path
	// in which the project prefix appears twice.
	if d := eng.Check("src/main.go", OpRead); !d.Allowed {
		t.Fatalf("relative in-project path denied: reason=%s resolved=%s", d.Reason, d.Resolved)
	}
	if d := eng.Check("output/report.txt", OpWrite); !d.Allowed {
		t.Fatalf("relative writable path denied: reason=%s resolved=%s", d.Reason, d.Resolved)
	}
	if d := eng.Check("../../../etc/shadow", OpRead); d.Allowed {
		t.Fatalf("relative traversal escaped: resolved=%s", d.Resolved)
	}
	if d := eng.Check("../../outside.txt", OpRead); d.Allowed {
		t.Fatalf("relative path escaped the white box: resolved=%s", d.Resolved)
	}
}

func TestGlobalDenyWins(t *testing.T) {
	eng, home := newTestEngine(t)
	cases := []struct {
		name string
		path string
		op   Op
	}{
		{"ssh key", filepath.Join(home, ".ssh", "id_rsa"), OpRead},
		{"ssh key inside project", projectPath(eng, ".ssh/id_rsa"), OpRead},
		{"aws credentials", filepath.Join(home, ".aws", "credentials"), OpRead},
		{"env file", projectPath(eng, ".env"), OpRead},
		{"pem", projectPath(eng, "certs/x.pem"), OpRead},
		{"bash history", filepath.Join(home, ".bash_history"), OpRead},
		{"git hooks exec", projectPath(eng, ".git/hooks/pre-commit"), OpExec},
		{"node_modules bin exec", projectPath(eng, "node_modules/.bin/evil"), OpExec},
	}
	if runtime.GOOS == "windows" {
		cases = append(cases, struct {
			name string
			path string
			op   Op
		}{"windows system32", `C:\Windows\System32\config\SAM`, OpRead})
	}
	for _, c := range cases {
		d := eng.Check(c.path, c.op)
		if d.Allowed {
			t.Errorf("%s: expected DENY for %s, got allow (reason=%s, resolved=%s)", c.name, c.path, d.Reason, d.Resolved)
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
		{projectPath(eng, "src/main.go"), OpRead},
		{projectPath(eng, "README.md"), OpRead},
		{projectPath(eng, "src/main.go"), OpWrite},
		{projectPath(eng, "output/report.txt"), OpWrite},
	}
	for _, a := range allowed {
		if d := eng.Check(a.path, a.op); !d.Allowed {
			t.Errorf("expected ALLOW for %s (%s), got deny reason=%s rule=%s resolved=%s",
				a.path, a.op, d.Reason, d.Rule, d.Resolved)
		}
	}

	denied := []struct {
		path string
		op   Op
	}{
		{projectPath(eng, "../outside/secret.txt"), OpRead},
		{projectPath(eng, "config/prod.yaml"), OpWrite},
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
	outside := projectPath(eng, "../../outside.txt")
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
	link := projectPath(eng, "shortcut")
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
	if d := eng.Check(projectPath(eng, "src/main.go"), OpWrite); d.Allowed || d.Reason != ReasonReadOnly {
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

// TestProjectRootInsideSymlinkedTempDir covers macOS, where the temp dir is
// /var/folders/... (a symlink chain) and /tmp -> /private/tmp. The project root
// must be recognised in both its literal and resolved form, otherwise every
// project-relative write glob silently stops matching.
func TestProjectRootInsideSymlinkedTempDir(t *testing.T) {
	eng, _ := newTestEngine(t)
	if d := eng.Check(projectPath(eng, "output/report.txt"), OpWrite); !d.Allowed {
		t.Fatalf("write into project output denied: reason=%s resolved=%s roots=%v",
			d.Reason, d.Resolved, eng.projectRoots())
	}
	if len(eng.projectRoots()) == 0 {
		t.Fatal("engine has no project roots")
	}
	for _, r := range eng.projectRoots() {
		if filepath.IsAbs(r) && runtime.GOOS != "windows" {
			t.Fatalf("posix project root lost its leading slash: %q", r)
		}
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
