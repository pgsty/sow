//go:build linux

package cli

import (
	"os"
	"syscall"
)

func derivedStateSecurityIdentityFromInfo(info os.FileInfo) (derivedStateSecurityIdentity, bool) {
	if info == nil {
		return derivedStateSecurityIdentity{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return derivedStateSecurityIdentity{}, false
	}
	return derivedStateSecurityIdentity{
		uid:   stat.Uid,
		gid:   stat.Gid,
		links: uint64(stat.Nlink),
	}, true
}

func derivedStateEffectiveUID() uint32 {
	return uint32(os.Geteuid())
}
