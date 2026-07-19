//go:build darwin

package state

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// SZOMB from Darwin's <sys/proc.h>. A zombie has already closed every file
// descriptor and cannot still own either SOW advisory lease, even though its
// PID remains visible until the parent reaps it.
const darwinProcessStatusZombie int8 = 5

func darwinProcessStatusIsDead(status int8) bool {
	return status == darwinProcessStatusZombie
}

func readPlatformProcessIdentity(pid int) (processIdentity, error) {
	if pid <= 0 {
		return processIdentity{}, errProcessIdentityNotFound
	}
	bootTime, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return processIdentity{}, fmt.Errorf("%w: read Darwin boot time: %v", errProcessIdentityUnavailable, err)
	}
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.pid", pid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
			return processIdentity{}, errProcessIdentityNotFound
		}
		return processIdentity{}, fmt.Errorf("%w: read Darwin kinfo for pid %d: %v", errProcessIdentityUnavailable, pid, err)
	}
	if len(processes) == 0 {
		return processIdentity{}, errProcessIdentityNotFound
	}
	if len(processes) != 1 || int(processes[0].Proc.P_pid) != pid {
		return processIdentity{}, fmt.Errorf("%w: Darwin kinfo for pid %d returned %d mismatched records", errProcessIdentityUnavailable, pid, len(processes))
	}
	process := &processes[0]
	if darwinProcessStatusIsDead(process.Proc.P_stat) {
		return processIdentity{}, errProcessIdentityNotFound
	}
	bootToken, err := formatTimevalToken(int64(bootTime.Sec), int64(bootTime.Usec))
	if err != nil {
		return processIdentity{}, fmt.Errorf("%w: normalize Darwin boot time: %v", errProcessIdentityUnavailable, err)
	}
	started := process.Proc.P_starttime
	startToken, err := formatTimevalToken(int64(started.Sec), int64(started.Usec))
	if err != nil {
		return processIdentity{}, fmt.Errorf("%w: normalize Darwin process start time: %v", errProcessIdentityUnavailable, err)
	}
	return processIdentity{Scheme: processIdentityDarwinV1, BootToken: bootToken, StartToken: startToken}, nil
}
