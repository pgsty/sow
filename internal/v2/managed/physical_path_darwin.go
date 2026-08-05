//go:build darwin

package managed

import "strings"

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
