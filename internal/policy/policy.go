// Package policy implements the GAS allow-list / deny-list decision engine.
//
// Order of evaluation (fail-closed, first match wins):
//  1. invalid or unresolvable input          -> deny
//  2. global deny patterns                   -> deny
//  3. project internal deny patterns         -> deny
//  4. operation specific rules (exec/write)  -> deny unless explicitly allowed
//  5. read: inside an allow root             -> allow
//  6. everything else                        -> deny
package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/satriazoid/gas/internal/config"
)

// Op is a filesystem operation.
type Op string

// Supported operations.
const (
	OpRead  Op = "read"
	OpWrite Op = "write"
	OpExec  Op = "exec"
)

// Reason codes returned in a Decision.
const (
	ReasonAllowed        = "allowed"
	ReasonGlobalDeny     = "global_deny"
	ReasonProjectDeny    = "project_deny"
	ReasonWriteDenied    = "write_denied"
	ReasonReadOnly       = "read_only"
	ReasonExecDenied     = "exec_denied"
	ReasonOutsideProject = "outside_allowlist"
	ReasonInvalidPath    = "invalid_path"
	ReasonSymlinkEscape  = "symlink_escape"
	ReasonNoPolicy       = "no_policy"
)

// Decision is the verdict for one path/op pair.
type Decision struct {
	Allowed  bool   `json:"allowed"`
	Op       Op     `json:"op"`
	Path     string `json:"path"`
	Resolved string `json:"resolved,omitempty"`
	Reason   string `json:"reason"`
	Rule     string `json:"rule,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

// Engine evaluates paths against a compiled policy.
type Engine struct {
	cfg     *config.Config
	home    string
	project string
	lower   bool

	// projectNative is the absolute native path used when joining relative
	// inputs; project is the normalized (slash-stripped) form used for
	// matching, and projectResolved is its symlink-resolved twin.
	projectNative   string
	projectResolved string

	globalDeny  []string
	projectDeny []string
	allowRoots  []string
	writable    []string
	allowExec   []string
}

// New compiles a policy engine from cfg.
func New(cfg *config.Config) *Engine {
	if cfg == nil {
		cfg = config.Default()
	}
	e := &Engine{
		cfg:           cfg,
		home:          cfg.HomeDir,
		project:       norm(cfg.ProjectDir),
		projectNative: cfg.ProjectDir,
		lower:         runtime.GOOS == "windows",
	}
	if e.home == "" {
		e.home, _ = os.UserHomeDir()
	}
	if e.projectNative == "" {
		e.projectNative, _ = os.Getwd()
		e.project = norm(e.projectNative)
	}
	e.projectResolved = e.resolve(e.project)

	e.globalDeny = compile(e, cfg.DenyPatterns)
	e.projectDeny = compile(e, cfg.ProjectInternalDeny)
	e.allowRoots = e.resolveRoots(append(append([]string{}, cfg.AllowRoots...), cfg.ProjectAllowRoots...))
	if len(e.allowRoots) == 0 && e.project != "" {
		// Default white box: the project directory itself.
		e.allowRoots = []string{e.project}
	}
	e.writable = compile(e, cfg.WritablePaths)
	e.allowExec = compile(e, cfg.AllowExec)
	return e
}

// AllowRoots exposes the compiled read roots (already resolved).
func (e *Engine) AllowRoots() []string { return append([]string{}, e.allowRoots...) }

// DenyPatterns exposes every deny pattern in evaluation order.
func (e *Engine) DenyPatterns() []string {
	out := append([]string{}, e.globalDeny...)
	return append(out, e.projectDeny...)
}

// WritablePaths exposes the compiled write patterns.
func (e *Engine) WritablePaths() []string { return append([]string{}, e.writable...) }

// ExecPaths exposes the compiled exec patterns.
func (e *Engine) ExecPaths() []string { return append([]string{}, e.allowExec...) }

// Config exposes the underlying configuration.
func (e *Engine) Config() *config.Config { return e.cfg }

func (e *Engine) resolveRoots(roots []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, r := range roots {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		abs := e.absolute(r)
		abs = e.resolve(abs)
		if abs == "" || seen[abs] {
			continue
		}
		seen[abs] = true
		out = append(out, abs)
	}
	// Read-only system libraries, opt in.
	if e.cfg.AllowSystemLibs && runtime.GOOS != "windows" {
		for _, sys := range []string{"/usr/lib", "/usr/share", "/lib", "/lib64", "/etc/ssl/certs"} {
			if !seen[sys] {
				seen[sys] = true
				out = append(out, sys)
			}
		}
	}
	return out
}

func (e *Engine) absolute(p string) string {
	p = expandHome(p, e.home)
	if filepath.IsAbs(p) {
		return norm(p)
	}
	// Join with the native project path: a relative input must resolve against
	// the real filesystem root, not against the slash-stripped match key.
	if e.projectNative != "" {
		return norm(filepath.Join(e.projectNative, filepath.FromSlash(p)))
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return norm(p)
	}
	return norm(abs)
}

func expandHome(p, home string) string {
	p = strings.TrimSpace(p)
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(home, p[2:])
	}
	return p
}

// norm produces the canonical form used for matching: absolute, cleaned,
// slash separated, and lower-cased on Windows. A leading slash is stripped so
// that one pattern set behaves identically on POSIX and Windows paths.
func norm(p string) string {
	if p == "" {
		return ""
	}
	p = filepath.ToSlash(filepath.Clean(p))
	p = strings.TrimPrefix(p, "/")
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

// compile normalizes patterns. Absolute patterns keep their leading slash
// stripped so they match the normalized path form.
func compile(e *Engine, patterns []string) []string {
	out := []string{}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "~") {
			p = expandHome(p, e.home)
		}
		p = filepath.ToSlash(p)
		if e.lower {
			p = strings.ToLower(p)
		}
		p = strings.TrimPrefix(p, "./")
		p = strings.TrimPrefix(p, "/")
		out = append(out, p)
	}
	return out
}

// match reports whether path matches any pattern, returning the winner.
func match(patterns []string, path string) (string, bool) {
	for _, p := range patterns {
		ok, err := doublestar.Match(p, path)
		if err == nil && ok {
			return p, true
		}
		// A pattern ending in "/**" also matches the directory itself.
		if strings.HasSuffix(p, "/**") {
			if base := strings.TrimSuffix(p, "/**"); base == path {
				return p, true
			}
		}
	}
	return "", false
}

// resolve follows symlinks on the deepest existing ancestor of p and re-joins
// the non-existing tail, so a symlink cannot be used to escape the sandbox.
// Paths that do not exist yet (a file the agent is about to create) must come
// back UNCHANGED, otherwise a legitimate in-project path looks like an escape.
func (e *Engine) resolve(p string) string {
	p = norm(p)
	if p == "" {
		return ""
	}
	native := filepath.FromSlash(p)
	if runtime.GOOS != "windows" {
		native = "/" + native
	}
	if real, err := filepath.EvalSymlinks(native); err == nil {
		return norm(real)
	}
	missing := []string{}
	cur := native
	for i := 0; i < 64; i++ {
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		missing = append([]string{filepath.Base(cur)}, missing...)
		cur = parent
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			parts := append([]string{real}, missing...)
			return norm(filepath.Join(parts...))
		}
	}
	return p
}

func within(root, p string) bool {
	if root == "" || p == "" {
		return false
	}
	if p == root {
		return true
	}
	return strings.HasPrefix(p, root+"/")
}

// Decide returns the verdict for input under op.
func (e *Engine) Decide(input string, op Op) Decision {
	d := Decision{Op: op, Path: input}
	if strings.TrimSpace(input) == "" {
		d.Reason = ReasonInvalidPath
		return d
	}
	if op == "" {
		op = OpRead
		d.Op = op
	}

	lexical := e.absolute(input)
	resolved := e.resolve(lexical)
	d.Path = lexical
	d.Resolved = resolved

	// 2 + 3: deny lists win, checked on both the literal and the resolved path
	// so "proj/link-to-ssh/id_rsa" is blocked too.
	for _, cand := range dedup(lexical, resolved) {
		if p, ok := match(e.globalDeny, cand); ok {
			d.Reason, d.Rule, d.Scope = ReasonGlobalDeny, p, "global"
			return d
		}
		if p, ok := match(e.projectDeny, cand); ok {
			d.Reason, d.Rule, d.Scope = ReasonProjectDeny, p, "project"
			return d
		}
	}

	// Symlink that leaves every allow root: refuse even if the literal path
	// looked fine.
	if resolved != lexical && !e.insideAny(resolved) {
		d.Reason, d.Scope = ReasonSymlinkEscape, "global"
		return d
	}

	switch op {
	case OpExec:
		for _, cand := range dedup(lexical, resolved) {
			if p, ok := match(e.allowExec, cand); ok {
				d.Allowed, d.Reason, d.Rule, d.Scope = true, ReasonAllowed, p, "exec"
				return d
			}
		}
		// Anything inside the white box is runnable, except deny-listed
		// paths (node_modules/.bin, .git/hooks) which were rejected above.
		if e.insideAny(lexical) || e.insideAny(resolved) {
			d.Allowed, d.Reason, d.Scope = true, ReasonAllowed, "exec"
			return d
		}
		d.Reason, d.Scope = ReasonExecDenied, "exec"
		return d

	case OpWrite:
		if e.cfg.ReadOnly {
			d.Reason, d.Scope = ReasonReadOnly, "global"
			return d
		}
		for _, cand := range dedup(lexical, resolved) {
			if p, ok := match(e.writable, cand); ok {
				d.Allowed, d.Reason, d.Rule, d.Scope = true, ReasonAllowed, p, "write"
				return d
			}
			// Writable globs are written project-relative ("src/**/*.go"), so a
			// project shipping "temp/**" cannot accidentally whitelist the
			// system temp directory.
			if rel := e.relative(cand); rel != "" {
				if p, ok := match(e.writable, rel); ok {
					d.Allowed, d.Reason, d.Rule, d.Scope = true, ReasonAllowed, p, "write"
					return d
				}
			}
		}
		d.Reason, d.Scope = ReasonWriteDenied, "write"
		return d
	}

	// 5: read
	if e.insideAny(lexical) || e.insideAny(resolved) {
		d.Allowed, d.Reason, d.Scope = true, ReasonAllowed, "read"
		return d
	}
	d.Reason, d.Scope = ReasonOutsideProject, "read"
	return d
}

func (e *Engine) insideAny(p string) bool {
	for _, root := range e.allowRoots {
		if within(root, p) {
			return true
		}
	}
	return false
}

// relative returns p expressed relative to the project root (slash separated),
// or "" when p lies outside the project.
func (e *Engine) relative(p string) string {
	if p == "" {
		return ""
	}
	for _, root := range e.projectRoots() {
		if within(root, p) {
			rel := strings.TrimPrefix(p, root)
			rel = strings.TrimPrefix(rel, "/")
			if rel == "" {
				return "."
			}
			return rel
		}
	}
	return ""
}

// projectRoots returns every matching form of the project root: the normalized
// absolute path and its symlink-resolved twin (macOS /tmp is a symlink to
// /private/tmp, so both forms must be recognised).
func (e *Engine) projectRoots() []string {
	out := []string{}
	if e.project != "" {
		out = append(out, e.project)
	}
	if e.projectResolved != "" && e.projectResolved != e.project {
		out = append(out, e.projectResolved)
	}
	return out
}

func dedup(vals ...string) []string {
	out := vals[:0]
	seen := map[string]bool{}
	for _, v := range vals {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// Check is the convenience wrapper used by the CLI and integrations.
func (e *Engine) Check(input string, op Op) Decision { return e.Decide(input, op) }
