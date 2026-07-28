package state

import (
	"fmt"
	"os"
)

type stateSecurityIdentity struct {
	uid   uint32
	gid   uint32
	links uint64
}

func admitStateDirectory(info os.FileInfo, description string) (stateSecurityIdentity, error) {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return stateSecurityIdentity{}, fmt.Errorf("%s is not a real directory", description)
	}
	identity, ok := stateSecurityIdentityFromInfo(info)
	if !ok {
		return stateSecurityIdentity{}, fmt.Errorf("%s lacks a POSIX security identity", description)
	}
	if identity.uid != stateEffectiveUID() {
		return stateSecurityIdentity{}, fmt.Errorf(
			"%s owner uid %d does not match effective uid %d",
			description,
			identity.uid,
			stateEffectiveUID(),
		)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return stateSecurityIdentity{}, fmt.Errorf(
			"%s is group/other writable (mode %#o)",
			description,
			info.Mode().Perm(),
		)
	}
	return identity, nil
}

func admitStateControlFile(info os.FileInfo, description string) (stateSecurityIdentity, error) {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return stateSecurityIdentity{}, fmt.Errorf("%s is not a regular file", description)
	}
	identity, ok := stateSecurityIdentityFromInfo(info)
	if !ok {
		return stateSecurityIdentity{}, fmt.Errorf("%s lacks a POSIX security identity", description)
	}
	if identity.uid != stateEffectiveUID() {
		return stateSecurityIdentity{}, fmt.Errorf(
			"%s owner uid %d does not match effective uid %d",
			description,
			identity.uid,
			stateEffectiveUID(),
		)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return stateSecurityIdentity{}, fmt.Errorf(
			"%s is group/other writable (mode %#o)",
			description,
			info.Mode().Perm(),
		)
	}
	if identity.links != 1 {
		return stateSecurityIdentity{}, fmt.Errorf(
			"%s has link count %d; expected exactly one",
			description,
			identity.links,
		)
	}
	return identity, nil
}

func sameStateDirectorySecurity(expected, current os.FileInfo) bool {
	if expected == nil || current == nil {
		return false
	}
	expectedIdentity, expectedOK := stateSecurityIdentityFromInfo(expected)
	currentIdentity, currentOK := stateSecurityIdentityFromInfo(current)
	return expectedOK && currentOK &&
		expectedIdentity.uid == currentIdentity.uid &&
		expectedIdentity.gid == currentIdentity.gid &&
		expected.Mode() == current.Mode()
}

func sameStateControlFileSecurity(expected, current os.FileInfo) bool {
	if expected == nil || current == nil {
		return false
	}
	expectedIdentity, expectedErr := admitStateControlFile(expected, "expected state control file")
	currentIdentity, currentErr := admitStateControlFile(current, "current state control file")
	return expectedErr == nil && currentErr == nil &&
		expectedIdentity == currentIdentity &&
		expected.Mode() == current.Mode()
}

func sameStateOwnership(expected, current os.FileInfo, includeLinks bool) bool {
	if expected == nil || current == nil {
		return false
	}
	expectedIdentity, expectedOK := stateSecurityIdentityFromInfo(expected)
	currentIdentity, currentOK := stateSecurityIdentityFromInfo(current)
	if !expectedOK || !currentOK ||
		expectedIdentity.uid != currentIdentity.uid ||
		expectedIdentity.gid != currentIdentity.gid {
		return false
	}
	return !includeLinks || expectedIdentity.links == currentIdentity.links
}
