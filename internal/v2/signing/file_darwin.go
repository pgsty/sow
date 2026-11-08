//go:build darwin

package signing

import "strings"

const directoryAccess = 0x40000000 // O_SEARCH on macOS 13+

func physicalPath(path string) string {
	for _, prefix := range []string{"/tmp", "/var", "/etc"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return "/private" + path
		}
	}
	return path
}
