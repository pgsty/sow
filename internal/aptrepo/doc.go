// Package aptrepo parses Debian binary packages and renders deterministic APT
// index material used by simple and managed SOW repositories.
//
// Package facts are derived from bounded, authenticated readers. Rendered
// Packages, Release, signatures, and by-hash objects are validated against the
// bytes actually written. Managed lifecycle publication and retention are owned
// by internal/v2/managed; this package does not authorize Workspace or SQLite
// transitions.
package aptrepo
