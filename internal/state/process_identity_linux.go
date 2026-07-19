//go:build linux

package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func readPlatformProcessIdentity(pid int) (processIdentity, error) {
	if pid <= 0 {
		return processIdentity{}, errProcessIdentityNotFound
	}
	bootBytes, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return processIdentity{}, fmt.Errorf("%w: read Linux boot ID: %v", errProcessIdentityUnavailable, err)
	}
	bootID := strings.TrimSpace(string(bootBytes))
	statBytes, err := os.ReadFile(filepath.Join("/proc", fmt.Sprintf("%d", pid), "stat"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return processIdentity{}, errProcessIdentityNotFound
		}
		return processIdentity{}, fmt.Errorf("%w: read Linux proc stat for pid %d: %v", errProcessIdentityUnavailable, pid, err)
	}
	processState, startToken, err := parseLinuxProcStatIdentity(pid, statBytes)
	if err != nil {
		return processIdentity{}, fmt.Errorf("%w: parse Linux proc stat for pid %d: %v", errProcessIdentityUnavailable, pid, err)
	}
	if linuxProcessStateIsDead(processState) {
		return processIdentity{}, errProcessIdentityNotFound
	}
	identity := processIdentity{Scheme: processIdentityLinuxV1, BootToken: bootID, StartToken: startToken}
	if err := identity.validate(); err != nil {
		return processIdentity{}, fmt.Errorf("%w: %v", errProcessIdentityUnavailable, err)
	}
	return identity, nil
}
