package signing

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// ErrUnsafeSourcePath is retained for compatibility with callers checking it.
var ErrUnsafeSourcePath = errors.New("invalid credential source path")

// ResolveSourcePath resolves a passfile or key-file path to a clean absolute
// path, following symlinks cleanly (including Kubernetes Secret mounts and
// operator-managed key links).
func ResolveSourcePath(_ string, candidate string) (string, error) {
	if candidate == "" {
		return "", ErrUnsafeSourcePath
	}
	absCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absCandidate)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func readSourceFile(_ string, path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open passfile %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	var data []byte
	switch {
	case info.Mode().IsRegular():
		data, err = io.ReadAll(io.LimitReader(file, MaxBytes+1))
	case info.Mode()&os.ModeNamedPipe != 0:
		data, err = readFIFO(int(file.Fd()), time.Now().Add(2*time.Second))
	default:
		return nil, fmt.Errorf("passfile %q must be a regular file or named pipe", path)
	}
	if err != nil {
		Clear(data)
		return nil, fmt.Errorf("cannot read passfile %q: %w", path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("passfile %q is empty", path)
	}
	if len(data) > MaxBytes {
		Clear(data)
		return nil, fmt.Errorf("passfile %q exceeds %d bytes", path, MaxBytes)
	}
	return data, nil
}

// Darwin does not support os.File read deadlines for named pipes. Poll the
// nonblocking descriptor with one deadline for both the first byte and EOF.
func readFIFO(fd int, deadline time.Time) ([]byte, error) {
	data := make([]byte, MaxBytes+1)
	used := 0
	for used < len(data) {
		wait := time.Until(deadline)
		if wait <= 0 {
			return data[:used], os.ErrDeadlineExceeded
		}
		n, err := unix.Read(fd, data[used:])
		switch {
		case err == nil:
			if n == 0 {
				return data[:used], nil
			}
			used += n
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			_, err = unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, int((wait+time.Millisecond-1)/time.Millisecond))
			if err != nil && !errors.Is(err, unix.EINTR) {
				return data[:used], err
			}
		default:
			return data[:used], err
		}
	}
	return data, nil
}
