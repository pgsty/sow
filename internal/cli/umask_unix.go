//go:build darwin || linux

package cli

import "golang.org/x/sys/unix"

// SOW's durable state writers rely on owner-readable 0600/0700 creation
// modes. Normalize all owner-mask bits during single-threaded package
// initialization so an inherited restrictive umask cannot create a crash
// residue before the writer's descriptor-bound chmod/fsync checks. Group and
// other restrictions remain exactly as selected by the invoking environment.
func init() {
	previous := unix.Umask(0o077)
	unix.Umask(previous &^ 0o700)
}
