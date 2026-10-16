//go:build linux

package managed

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// O_PATH permits directory lookup and fstat without directory read access.
// O_DIRECTORY and O_NOFOLLOW remain set by callers. See open(2):
// https://man7.org/linux/man-pages/man2/open.2.html
const directorySearchAccess = unix.O_PATH

func physicalDirectoryPath(handle *os.File, original string) (string, error) {
	// procfs exposes the kernel's path for this held descriptor, including the
	// directory-entry spelling on casefold filesystems. See proc_pid_fd(5):
	// https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html
	path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(handle.Fd())))
	if err == nil {
		return path, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) && !errors.Is(err, unix.ENOTDIR) {
		return "", err
	}
	path, fallbackErr := canonicalDirectoryEntrySpellingByReadDir(original)
	if fallbackErr != nil {
		return "", errors.Join(err, fallbackErr)
	}
	return path, nil
}

func normalizePlatformPhysicalPath(path string) string { return path }

// Retain enumeration for Linux environments without access to procfs. The
// caller holds and verifies a no-follow binding around this spelling lookup.
func canonicalDirectoryEntrySpellingByReadDir(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	volume := filepath.VolumeName(abs)
	root := volume + string(filepath.Separator)
	relative, err := filepath.Rel(root, abs)
	if err != nil {
		return "", err
	}
	if relative == "." {
		return root, nil
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		requested := filepath.Join(current, component)
		requestedInfo, err := os.Stat(requested)
		if err != nil || !requestedInfo.IsDir() {
			return "", errors.Join(fmt.Errorf("%w: inspect directory component %q", ErrRejected, requested), err)
		}
		entries, err := os.ReadDir(current)
		if err != nil {
			return "", err
		}
		matched := ""
		for _, entry := range entries {
			entryInfo, infoErr := entry.Info()
			if infoErr == nil && entryInfo.IsDir() && os.SameFile(requestedInfo, entryInfo) {
				matched = entry.Name()
				break
			}
		}
		if matched == "" {
			return "", fmt.Errorf("%w: cannot bind directory spelling for %q", ErrRejected, requested)
		}
		current = filepath.Join(current, matched)
	}
	return current, nil
}
