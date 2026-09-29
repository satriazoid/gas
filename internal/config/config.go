// Package config loads and merges GAS policy configuration from the global
// config file (~/.gas/config.yaml) and the per-project file (.gasignore).
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// EnvHome overrides the GAS state directory.
	EnvHome = "GAS_HOME"
	// GlobalFileName is the global config file inside the GAS home.
	GlobalFileName = "config.yaml"
	// ProjectFileName is the per-project policy file.
	ProjectFileName = ".gasignore"

	// ModeAuto picks namespace isolation on Linux when available, else proxy.
	ModeAuto = "auto"
	// ModeNamespace is Linux mount/user namespace isolation (kernel level).
	ModeNamespace = "namespace"
	// ModeProxy is the cross-platform stdio filter + env injection mode.
	ModeProxy = "proxy"

	// FakeNotFound makes blocked accesses look like a missing file.
	FakeNotFound = "not_found"
	// FakePermissionDenied makes blocked accesses look like an ACL denial.
	FakePermissionDenied = "permission_denied"
)

// Network holds the optional egress restrictions.
type Network struct {
	BlockInternalIPs bool     `yaml:"block_internal_ips"`
	AllowPorts       []int    `yaml:"allow_ports"`
	AllowHosts       []string `yaml:"allow_hosts"`
}

// Audit holds access-denied log settings.
type Audit struct {
	Enabled    *bool  `yaml:"enabled"`
	LogAllowed bool   `yaml:"log_allowed"`
	Path       string `yaml:"path"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
}

// Notify holds the optional block notification target.
type Notify struct {
	WebhookURL string   `yaml:"webhook_url"`
	On         []string `yaml:"on"`
}

// Config is the effective policy for one run.
type Config struct {
	Version int    `yaml:"version"`
	Mode    string `yaml:"mode"`

	FailClosed bool `yaml:"fail_closed"`
	ReadOnly   bool `yaml:"read_only"`

	// AllowRoots are global read roots that apply to every project.
	AllowRoots []string `yaml:"allow_roots"`
	// DenyPatterns is the global deny list (never touch these).
	DenyPatterns []string `yaml:"global_deny_patterns"`
	// ProjectAllowRoots is the white box declared by the project (.gasignore).
	ProjectAllowRoots []string `yaml:"project_allow_roots"`
	// ProjectInternalDeny is denied even inside the white box.
	ProjectInternalDeny []string `yaml:"project_internal_deny"`
	// WritablePaths are the only globs a write may touch.
	WritablePaths []string `yaml:"writable_paths"`
	// AllowExec limits which paths may be executed.
	AllowExec []string `yaml:"allow_exec"`

	AllowSystemLibs bool   `yaml:"allow_system_libs"`
	FakeError       string `yaml:"fake_error"`

	Network Network `yaml:"network"`
	Audit   Audit   `yaml:"audit"`
	Notify  Notify  `yaml:"notify"`

	// Runtime context, never serialized.
	HomeDir     string `yaml:"-"`
	ProjectDir  string `yaml:"-"`
	GlobalPath  string `yaml:"-"`
	ProjectPath string `yaml:"-"`
	// Sources records which files were merged.
	Sources []string `yaml:"-"`
}

// GasHome returns the GAS state directory.
func GasHome() string {
	if v := strings.TrimSpace(os.Getenv(EnvHome)); v != "" {
		return expandHome(v)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".gas")
}

// GlobalPath returns the global config path inside the GAS home.
func GlobalPath(home string) string {
	return filepath.Join(home, GlobalFileName)
}

// ProjectPath returns the policy file path inside a project directory.
func ProjectPath(projectDir string) string {
	return filepath.Join(projectDir, ProjectFileName)
}

func expandHome(p string) string {
	if p == "" {
		return p
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home, err := os.UserHomeDir()
		if err == nil {
			if len(p) <= 2 {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// Default returns the shipped policy defaults (PRD section 5).
func Default() *Config {
	enabled := true
	return &Config{
		Version:    1,
		Mode:       ModeAuto,
		FailClosed: true,
		FakeError:  FakeNotFound,
		DenyPatterns: []string{
			// Credentials & keys
			"**/.ssh/**",
			"**/.gnupg/**",
			"**/.aws/credentials",
			"**/.aws/config",
			"**/.azure/**",
			"**/.kube/config",
			"**/.docker/config.json",
			"**/.netrc",
			"**/.npmrc",
			"**/.pypirc",
			// Environment secrets
			"**/.env",
			"**/.env.*",
			"**/secrets.json",
			"**/*.pem",
			"**/*.key",
			"**/*.pfx",
			"**/id_rsa*",
			"**/id_ed25519*",
			// System criticals
			"**/etc/shadow",
			"**/etc/passwd",
			"**/etc/sudoers",
			"**/proc/sys/kernel/core_pattern",
			"**/windows/system32/**",
			"**/windows/syswow64/**",
			// Personal data heuristics
			"**/documents/financial/**",
			"**/pictures/private/**",
			"**/.bash_history",
			"**/.zsh_history",
			"**/.config/gh/hosts.yml",
		},
		ProjectInternalDeny: []string{
			"**/node_modules/.bin/**",
			"**/.git/hooks/**",
			"**/.git/config",
			"**/vendor/**",
		},
		WritablePaths: []string{
			"output/**",
			"temp/**",
			"tmp/**",
			"src/**/*.go",
			"src/**/*.ts",
			"src/**/*.tsx",
			"src/**/*.js",
			"src/**/*.py",
			"src/**/*.rs",
			"README.md",
			"CHANGELOG.md",
		},
		AllowExec: []string{
			// System toolchains: allowed outside the white box so builds work.
			"**/usr/bin/**",
			"**/usr/local/bin/**",
			"**/bin/**",
			"**/windows/system32/cmd.exe", // only the interpreter, not the tree
			"**/.venv/bin/**",
			"**/.venv/Scripts/**",
			"**/node/**",
			"**/python*/**",
		},
		Network: Network{
			BlockInternalIPs: true,
			AllowPorts:       []int{20128, 21128, 11434},
			AllowHosts:       []string{"localhost", "127.0.0.1", "::1"},
		},
		Audit: Audit{
			Enabled:    &enabled,
			LogAllowed: false,
			MaxSizeMB:  5,
			MaxBackups: 3,
		},
		Notify: Notify{
			On: []string{"blocked", "bypass"},
		},
	}
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// AuditEnabled reports whether audit logging is on.
func (c *Config) AuditEnabled() bool { return boolOr(c.Audit.Enabled, true) }

// LogPath returns the resolved audit log path.
func (c *Config) LogPath() string {
	p := strings.TrimSpace(c.Audit.Path)
	if p == "" {
		return filepath.Join(GasHome(), "logs", "access_denied.log")
	}
	return expandHome(p)
}

// Merge overlays src on top of dst in place.
func Merge(dst, src *Config) {
	if src.Version != 0 {
		dst.Version = src.Version
	}
	if src.Mode != "" {
		dst.Mode = src.Mode
	}
	if src.FakeError != "" {
		dst.FakeError = src.FakeError
	}
	// Booleans: a project file may only ever tighten, never loosen, the
	// global policy. ReadOnly stays true once set; FailClosed stays true.
	dst.FailClosed = dst.FailClosed || src.FailClosed
	dst.ReadOnly = dst.ReadOnly || src.ReadOnly
	dst.AllowSystemLibs = dst.AllowSystemLibs || src.AllowSystemLibs

	dst.AllowRoots = append(dst.AllowRoots, src.AllowRoots...)
	dst.DenyPatterns = append(dst.DenyPatterns, src.DenyPatterns...)
	dst.ProjectInternalDeny = append(dst.ProjectInternalDeny, src.ProjectInternalDeny...)
	dst.ProjectAllowRoots = append(dst.ProjectAllowRoots, src.ProjectAllowRoots...)
	dst.WritablePaths = append(dst.WritablePaths, src.WritablePaths...)
	dst.AllowExec = append(dst.AllowExec, src.AllowExec...)

	dst.Network.BlockInternalIPs = dst.Network.BlockInternalIPs || src.Network.BlockInternalIPs
	dst.Network.AllowPorts = append(dst.Network.AllowPorts, src.Network.AllowPorts...)
	dst.Network.AllowHosts = append(dst.Network.AllowHosts, src.Network.AllowHosts...)

	if src.Audit.Enabled != nil {
		dst.Audit.Enabled = src.Audit.Enabled
	}
	dst.Audit.LogAllowed = dst.Audit.LogAllowed || src.Audit.LogAllowed
	if src.Audit.Path != "" {
		dst.Audit.Path = src.Audit.Path
	}
	if src.Audit.MaxSizeMB > 0 {
		dst.Audit.MaxSizeMB = src.Audit.MaxSizeMB
	}
	if src.Audit.MaxBackups > 0 {
		dst.Audit.MaxBackups = src.Audit.MaxBackups
	}
	if src.Notify.WebhookURL != "" {
		dst.Notify.WebhookURL = src.Notify.WebhookURL
	}
	dst.Notify.On = append(dst.Notify.On, src.Notify.On...)
}

// Load builds the effective config for projectDir.
func Load(projectDir string) (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home dir: %w", err)
	}
	if projectDir == "" {
		projectDir = "."
	}
	absProject, err := filepath.Abs(projectDir)
	if err != nil {
		return nil, fmt.Errorf("resolve project dir: %w", err)
	}

	cfg := Default()
	cfg.HomeDir = home
	cfg.ProjectDir = absProject
	cfg.GlobalPath = filepath.Join(GasHome(), GlobalFileName)
	cfg.ProjectPath = filepath.Join(absProject, ProjectFileName)

	if data, err := os.ReadFile(cfg.GlobalPath); err == nil {
		over := &Config{}
		if err := yaml.Unmarshal(data, over); err != nil {
			return nil, fmt.Errorf("parse %s: %w", cfg.GlobalPath, err)
		}
		Merge(cfg, over)
		cfg.Sources = append(cfg.Sources, cfg.GlobalPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", cfg.GlobalPath, err)
	}

	if data, err := os.ReadFile(cfg.ProjectPath); err == nil {
		over := &Config{}
		if err := yaml.Unmarshal(data, over); err != nil {
			return nil, fmt.Errorf("parse %s: %w", cfg.ProjectPath, err)
		}
		Merge(cfg, over)
		cfg.Sources = append(cfg.Sources, cfg.ProjectPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", cfg.ProjectPath, err)
	}

	return cfg, nil
}

// DefaultGlobalYAML renders the commented starter config.
func DefaultGlobalYAML() string {
	enabled := true
	base := Default()
	base.Audit.Enabled = &enabled
	base.Audit.Path = filepath.ToSlash(filepath.Join(GasHome(), "logs", "access_denied.log"))
	body, err := yaml.Marshal(base)
	if err != nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("# Guardian Agent Sandbox (GAS) policy\n")
	b.WriteString("# Docs: https://github.com/satriazoid/gas\n")
	b.WriteString("#\n")
	b.WriteString("# global_deny_patterns  always wins, even inside the project white box\n")
	b.WriteString("# project_allow_roots   white box; empty means \"whole project dir\"\n")
	b.WriteString("# writable_paths        the ONLY globs a write may touch\n")
	b.WriteString("# fail_closed: true     if the sandbox cannot start, the agent must not run\n")
	b.WriteString("\n")
	b.Write(body)
	return b.String()
}

// DefaultProjectYAML renders a starter .gasignore for a project.
func DefaultProjectYAML() string {
	return `# GAS per-project policy (.gasignore)
# Relative paths resolve against this project root.

project_allow_roots:
  - .
  - ../shared-libs        # keep, or delete if the project is self-contained

project_internal_deny:
  - "**/node_modules/.bin/**"
  - "**/.git/hooks/**"
  - "**/vendor/**"

writable_paths:
  - "output/**"
  - "temp/**"

read_only: false
`
}
