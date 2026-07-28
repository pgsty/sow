//go:build linux

package cli

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func derivedStateDirectoryIdentityToken(info os.FileInfo) (string, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return "", false
	}
	return fmt.Sprintf(
		"%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d",
		stat.Dev,
		stat.Ino,
		stat.Uid,
		stat.Gid,
		stat.Ctim.Sec,
		stat.Ctim.Nsec,
		stat.Mtim.Sec,
		stat.Mtim.Nsec,
		stat.Nlink,
		stat.Size,
		stat.Blocks,
	), true
}

func sealDerivedStateDirectoryMutation(directory *os.File, sequence uint64) (derivedStateDirectoryMutationEpoch, error) {
	if directory == nil {
		return derivedStateDirectoryMutationEpoch{}, fmt.Errorf("derived state directory mutation seal is invalid")
	}
	before, err := directory.Stat()
	if err != nil {
		return derivedStateDirectoryMutationEpoch{}, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return derivedStateDirectoryMutationEpoch{}, fmt.Errorf("derived state directory mutation seal lacks a real directory")
	}
	// Keep the marker only two or three seconds ahead of wall time. Directory
	// entry mutations restore filesystem "now"; the epoch expires before wall
	// time can equal it, so a later equality is never trusted.
	markerSeconds := time.Now().Unix() + 2 + int64(sequence&1)
	times := []unix.Timeval{
		unix.NsecToTimeval(stat.Atim.Sec*1_000_000_000 + stat.Atim.Nsec),
		unix.NsecToTimeval(markerSeconds * 1_000_000_000),
	}
	if err := unix.Futimes(int(directory.Fd()), times); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
			errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) ||
			errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return derivedStateDirectoryMutationEpoch{}, nil
		}
		return derivedStateDirectoryMutationEpoch{}, fmt.Errorf("seal derived state directory mutation epoch: %w", err)
	}
	after, err := directory.Stat()
	if err != nil {
		return derivedStateDirectoryMutationEpoch{}, err
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || afterStat == nil || !os.SameFile(before, after) ||
		after.Mode() != before.Mode() {
		return derivedStateDirectoryMutationEpoch{}, fmt.Errorf("derived state directory mutation seal changed before admission")
	}
	if afterStat.Mtim.Sec != markerSeconds || afterStat.Mtim.Nsec != 0 {
		return derivedStateDirectoryMutationEpoch{}, nil
	}
	token, ok := derivedStateDirectoryIdentityToken(after)
	if !ok {
		return derivedStateDirectoryMutationEpoch{}, fmt.Errorf("derived state directory mutation seal lacks an identity")
	}
	return derivedStateDirectoryMutationEpoch{
		token:      token,
		validUntil: time.Unix(markerSeconds, 0).Add(-250 * time.Millisecond),
	}, nil
}

func derivedStateDirectoryLinkCount(info os.FileInfo) (uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, false
	}
	return uint64(stat.Nlink), true
}

func derivedStateDirectoryExpectedLinkDelta(bool) uint64 {
	return 0
}
