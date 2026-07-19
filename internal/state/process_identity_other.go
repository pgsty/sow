//go:build !linux && !darwin

package state

func readPlatformProcessIdentity(pid int) (processIdentity, error) {
	return processIdentity{}, errProcessIdentityUnavailable
}
