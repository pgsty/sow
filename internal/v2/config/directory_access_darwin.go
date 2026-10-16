//go:build darwin

package config

// O_SEARCH = O_EXEC | O_DIRECTORY; x/sys v0.47 does not expose O_EXEC.
// Present in macOS 13, the minimum supported by Go 1.27:
// https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.81.2/bsd/sys/fcntl.h
const directorySearchAccess = 0x40000000
