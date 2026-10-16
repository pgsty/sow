//go:build darwin

package managed

import (
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// O_SEARCH = O_EXEC | O_DIRECTORY; x/sys v0.47 does not expose O_EXEC.
// Present in macOS 13, the minimum supported by Go 1.27:
// https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.81.2/bsd/sys/fcntl.h
const directorySearchAccess = 0x40000000

func physicalDirectoryPath(handle *os.File, _ string) (string, error) {
	// F_GETPATH returns the descriptor's filesystem spelling without ReadDir.
	// Its buffer must hold MAXPATHLEN bytes; see Apple's fcntl(2) manual:
	// https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html
	var path [unix.PathMax]byte
	// FcntlInt accepts an integer, so pin the buffer before converting its
	// address: KeepAlive alone would not prevent a Go stack from moving it.
	// https://pkg.go.dev/runtime#Pinner.Pin
	var pin runtime.Pinner
	pin.Pin(&path[0])
	defer pin.Unpin()
	_, err := unix.FcntlInt(handle.Fd(), unix.F_GETPATH, int(uintptr(unsafe.Pointer(&path[0]))))
	if err != nil {
		return "", err
	}
	return unix.ByteSliceToString(path[:]), nil
}

func normalizePlatformPhysicalPath(path string) string {
	for logical, physical := range map[string]string{
		"/var": "/private/var",
		"/tmp": "/private/tmp",
		"/etc": "/private/etc",
	} {
		if path == logical {
			return physical
		}
		if strings.HasPrefix(path, logical+"/") {
			return physical + strings.TrimPrefix(path, logical)
		}
	}
	return path
}
