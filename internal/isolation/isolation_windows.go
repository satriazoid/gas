//go:build windows

package isolation

import (
	"fmt"
	"unsafe"

	"github.com/satriazoid/gas/internal/audit"
	"github.com/satriazoid/gas/internal/config"
	"golang.org/x/sys/windows"
)

// Capabilities reports what Windows can enforce.
func Capabilities() Capability {
	return Capability{
		OS:        "windows",
		Namespace: false,
		Policy:    true,
		Filter:    true,
		Detail:    "no kernel filesystem jail without a filter driver; enforcement is policy checks plus job object containment",
	}
}

// Resolve maps the requested mode to a supported one.
func Resolve(requested string, allowDegrade bool) (Mode, []string, error) {
	switch requested {
	case "", config.ModeAuto:
		return ModePolicy, []string{"auto-selected policy mode (windows)"}, nil
	case string(ModePolicy):
		return ModePolicy, nil, nil
	case string(ModeFilter):
		return ModeFilter, nil, nil
	case string(ModeNamespace):
		if !allowDegrade {
			return "", nil, fmt.Errorf("namespace isolation needs Linux kernel >= 5.0; use --mode policy, or pass --allow-degrade")
		}
		return ModePolicy, []string{"namespace requested but unavailable on windows; degraded to policy mode"}, nil
	}
	return "", nil, fmt.Errorf("unknown mode %q", requested)
}

// Prepare starts the agent inside a Windows job object so the whole process
// tree is contained and dies with the wrapper.
func Prepare(opt Options, mode Mode) (*Sandbox, error) {
	cmd, err := baseCmd(opt, mode)
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	sb := &Sandbox{Cmd: cmd, Mode: mode, Close: func() {}}
	job, err := createJob()
	if err != nil {
		sb.Notes = append(sb.Notes, "job object unavailable: "+err.Error())
		if opt.Log != nil {
			opt.Log.Event(audit.ActionDegrade, audit.Entry{Source: "isolation", Detail: "job object unavailable: " + err.Error()})
		}
		return sb, nil
	}
	if err := assignJob(job, uint32(cmd.Process.Pid)); err != nil {
		_ = windows.CloseHandle(job)
		sb.Notes = append(sb.Notes, "assign to job failed: "+err.Error())
		if opt.Log != nil {
			opt.Log.Event(audit.ActionDegrade, audit.Entry{Source: "isolation", Detail: "assign to job failed: " + err.Error()})
		}
		return sb, nil
	}
	sb.Close = func() { _ = windows.CloseHandle(job) }
	sb.Notes = append(sb.Notes, fmt.Sprintf("job object bound to pid %d (kill-on-close)", cmd.Process.Pid))
	return sb, nil
}

func createJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func assignJob(job windows.Handle, pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.AssignProcessToJobObject(job, h)
}
