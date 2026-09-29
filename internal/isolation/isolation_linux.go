//go:build linux

package isolation

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/satriazoid/gas/internal/config"
	"golang.org/x/sys/unix"
)

const sandboxInitCmd = "__sandbox-init"

// Capabilities reports what Linux can enforce.
func Capabilities() Capability {
	ok, detail := userNSAvailable()
	return Capability{OS: "linux", Namespace: ok, Policy: true, Filter: true, Detail: detail}
}

func userNSAvailable() (bool, string) {
	if b, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		if strings.TrimSpace(string(b)) == "0" {
			return false, "max_user_namespaces is 0"
		}
		return true, "unprivileged user namespaces enabled"
	}
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			return true, "unprivileged_userns_clone=1"
		}
		return false, "unprivileged_userns_clone=0"
	}
	if _, err := os.Stat("/proc/self/ns/user"); err != nil {
		return false, "user namespaces not exposed by this kernel"
	}
	return true, "user namespaces assumed available"
}

// Resolve maps the requested mode to a supported one.
func Resolve(requested string, allowDegrade bool) (Mode, []string, error) {
	ok, detail := userNSAvailable()
	switch requested {
	case "", config.ModeAuto:
		if ok {
			return ModeNamespace, []string{"namespace isolation available (" + detail + ")"}, nil
		}
		return ModePolicy, []string{"namespace isolation unavailable (" + detail + "); using policy mode"}, nil
	case string(ModeNamespace):
		if ok {
			return ModeNamespace, nil, nil
		}
		if !allowDegrade {
			return "", nil, fmt.Errorf("namespace isolation unavailable: %s", detail)
		}
		return ModePolicy, []string{"namespace unavailable (" + detail + "); degraded to policy mode"}, nil
	case string(ModePolicy):
		return ModePolicy, nil, nil
	case string(ModeFilter):
		return ModeFilter, nil, nil
	}
	return "", nil, fmt.Errorf("unknown mode %q", requested)
}

// Prepare launches the agent either inside a fresh mount/user/pid namespace or
// with the plain policy mode.
func Prepare(opt Options, mode Mode) (*Sandbox, error) {
	if mode != ModeNamespace {
		cmd, err := baseCmd(opt, mode)
		if err != nil {
			return nil, err
		}
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return &Sandbox{Cmd: cmd, Mode: mode, Close: func() {}}, nil
	}

	self := opt.GasBin
	if self == "" {
		self = Self()
	}
	roots := allowRootsFor(opt)
	args := []string{sandboxInitCmd, "--project", opt.ProjectDir, "--allow", strings.Join(roots, "|")}
	if opt.Config.AllowSystemLibs {
		args = append(args, "--syslibs")
	}
	args = append(args, "--")
	args = append(args, opt.Agent...)

	cmd := exec.Command(self, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = opt.Stdin, opt.Stdout, opt.Stderr
	cmd.Dir = opt.ProjectDir
	cmd.Env = joinEnv(GasEnv(opt.Config, self))

	cloneFlags := uintptr(unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWUTS)
	if os.Geteuid() != 0 {
		cloneFlags |= unix.CLONE_NEWUSER
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: cloneFlags}
	if os.Geteuid() != 0 {
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
		cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
		cmd.SysProcAttr.GidMappingsEnableSetgroups = false
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start namespace isolation: %w", err)
	}
	sb := &Sandbox{Cmd: cmd, Mode: mode, Close: func() {}}
	sb.Notes = append(sb.Notes, fmt.Sprintf("mount+pid namespace, %d bind mounts", len(roots)))
	return sb, nil
}

func allowRootsFor(opt Options) []string {
	roots := []string{}
	if opt.ProjectDir != "" {
		roots = append(roots, opt.ProjectDir)
	}
	if opt.AllowRoots != nil {
		roots = opt.AllowRoots
	}
	return roots
}

func init() { RunInit = runSandboxInit }

// runSandboxInit builds the jail and execs the agent. It runs as uid 0 inside
// the new user namespace and never returns on success.
func runSandboxInit(args []string) int {
	var project, allow string
	syslibs := false
	var agent []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--project":
			if i+1 < len(args) {
				project = args[i+1]
				i++
			}
		case "--allow":
			if i+1 < len(args) {
				allow = args[i+1]
				i++
			}
		case "--syslibs":
			syslibs = true
		case "--":
			agent = args[i+1:]
			i = len(args)
		}
	}
	if len(agent) == 0 {
		fail("no agent command passed to sandbox init")
		return 2
	}
	roots := splitList(allow)
	if syslibs {
		roots = append(roots, "/usr/lib", "/usr/share", "/lib", "/lib64", "/etc/ssl/certs")
	}
	if len(roots) == 0 {
		fail("refusing to start: empty allow list (fail-closed)")
		return 3
	}

	// 1. Stop mount events from leaking to the host.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		warn("make mounts private: " + err.Error())
	}

	root, err := os.MkdirTemp("", "gas-root-")
	if err != nil {
		fail("create jail root: " + err.Error())
		return 4
	}
	if err := unix.Mount("tmpfs", root, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=64m,mode=0755"); err != nil {
		fail("mount jail root: " + err.Error())
		return 5
	}

	// 2. Bind mount only the allowed subtrees, at their original absolute paths
	// so agent-side paths keep working.
	for _, src := range roots {
		if _, err := os.Stat(src); err != nil {
			warn("allow root missing, skipped: " + src)
			continue
		}
		dst := filepath.Join(root, src)
		if err := os.MkdirAll(dst, 0o755); err != nil {
			fail("mkdir " + dst + ": " + err.Error())
			return 6
		}
		if err := unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			fail("bind mount " + src + ": " + err.Error())
			return 7
		}
		if project != "" && !isUnder(src, project) {
			// Outside the project: read-only by default.
			if err := unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
				warn("remount read-only failed for " + src + ": " + err.Error())
			}
		}
	}

	// 3. Minimal runtime filesystems.
	for _, m := range []struct {
		src, dst, fstype string
		flags            uintptr
	}{
		{"", filepath.Join(root, "proc"), "proc", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV},
		{"tmpfs", filepath.Join(root, "tmp"), "tmpfs", unix.MS_NOSUID | unix.MS_NODEV},
		{"/dev", filepath.Join(root, "dev"), "", unix.MS_BIND | unix.MS_REC},
	} {
		if err := os.MkdirAll(m.dst, 0o755); err != nil {
			warn("mkdir " + m.dst + ": " + err.Error())
			continue
		}
		if err := unix.Mount(m.src, m.dst, m.fstype, m.flags, ""); err != nil {
			warn("mount " + m.dst + ": " + err.Error())
		}
	}
	if err := os.Chmod(filepath.Join(root, "tmp"), 0o1777); err != nil {
		warn("chmod jail tmp: " + err.Error())
	}

	// 4. Pivot into the jail.
	oldroot := filepath.Join(root, ".oldroot")
	if err := os.MkdirAll(oldroot, 0o700); err != nil {
		fail("mkdir oldroot: " + err.Error())
		return 8
	}
	if err := unix.PivotRoot(root, oldroot); err != nil {
		fail("pivot_root: " + err.Error())
		return 9
	}
	_ = unix.Chdir("/")
	if err := unix.Unmount("/.oldroot", unix.MNT_DETACH); err != nil {
		warn("detach old root: " + err.Error())
	}
	_ = os.Remove("/.oldroot")

	// 5. Lock privileges down.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		warn("no_new_privs: " + err.Error())
	}
	if project != "" {
		if err := os.Chdir(project); err != nil {
			warn("chdir project: " + err.Error())
		}
	}

	bin := agent[0]
	if strings.ContainsAny(bin, "/") {
		bin = "./" + strings.TrimPrefix(bin, "./")
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		path = agent[0]
	}
	if err := unix.Exec(path, agent, os.Environ()); err != nil {
		fail("exec " + path + ": " + err.Error())
		return 10
	}
	return 0
}

func isUnder(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func fail(msg string) {
	fmt.Fprintf(os.Stderr, "gas: sandbox init failed: %s\n", msg)
}

func warn(msg string) {
	fmt.Fprintf(os.Stderr, "gas: warning: %s\n", msg)
}
