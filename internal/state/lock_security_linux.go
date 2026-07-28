//go:build linux

package state

import (
	"os"
	"syscall"
)

func stateSecurityIdentityFromInfo(info os.FileInfo) (stateSecurityIdentity, bool) {
	if info == nil {
		return stateSecurityIdentity{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return stateSecurityIdentity{}, false
	}
	return stateSecurityIdentity{uid: stat.Uid, gid: stat.Gid, links: uint64(stat.Nlink)}, true
}

func stateEffectiveUID() uint32 {
	return uint32(os.Geteuid())
}
