//go:build linux

package managed

import "golang.org/x/sys/unix"

func statChangeTimeNano(raw unix.Stat_t) int64 {
	return raw.Ctim.Sec*1_000_000_000 + raw.Ctim.Nsec
}
