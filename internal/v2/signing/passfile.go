// Package signing supplies operation-local credentials to OpenPGP signers.
// Credential sources never become signing identities or repository state.
package signing

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const Environment = "SOW_GPG_PASSFILE"
const MaxBytes = 64 << 10

var ErrCredential = errors.New("signing credential is unavailable")

type overrideKey struct{}

// WithPassFile supplies a command override. Relative paths are relative to the
// caller's working directory, independently of the selected workspace.
func WithPassFile(ctx context.Context, path string) context.Context {
	if path == "" {
		return ctx
	}
	return context.WithValue(ctx, overrideKey{}, path)
}

// Source contains only a file path or a legacy environment variable name.
// Its zero value delegates unlocking to the existing GPG/RPM environment.
type Source struct {
	path   string
	env    string
	legacy bool
}

func (source Source) Explicit() bool { return source.path != "" || source.env != "" }

// ID distinguishes credential sources in an operation's signer cache. It does
// not contain credential values and must not be used as a persistent identity.
func (source Source) ID() string {
	if source.env != "" {
		return "env:" + source.env
	}
	if source.legacy {
		return "legacy-file:" + source.path
	}
	return "file:" + source.path
}

// ValidatePath checks the syntax shared by --passfile, SOW_GPG_PASSFILE and
// per-key passfile configuration.
func ValidatePath(path string) error {
	if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "\x00\r\n") {
		return errors.New("passfile requires a non-empty path without NUL or line breaks")
	}
	// Neighboring key and legacy passphrase settings use file:// URIs. A
	// passfile is a plain path, so reject the URI form instead of resolving
	// it as a relative path that fails only when signing.
	if strings.Contains(path, "://") {
		return errors.New("passfile takes a filesystem path, not a URI such as file://")
	}
	return nil
}

// Select applies CLI > per-key configuration > environment > ambient GPG.
// It does not read the secret; read-only operations need not call it at all.
// legacy accepts the existing passphrase reference grammar.
func Select(ctx context.Context, root, passfile, legacy string) (Source, error) {
	if ctx == nil {
		return Source{}, errors.New("nil signing context")
	}
	if passfile != "" && legacy != "" {
		return Source{}, errors.New("passfile and passphrase are mutually exclusive")
	}
	if override, _ := ctx.Value(overrideKey{}).(string); override != "" {
		return fileSource("", override, false)
	}
	if passfile != "" {
		return fileSource(root, passfile, false)
	}
	if legacy != "" {
		if strings.HasPrefix(legacy, "env://") {
			return Source{env: strings.TrimPrefix(legacy, "env://"), legacy: true}, nil
		}
		return fileSource(root, strings.TrimPrefix(legacy, "file://"), true)
	}
	if path, set := os.LookupEnv(Environment); set {
		return fileSource("", path, false)
	}
	return Source{}, nil
}

func fileSource(root, path string, legacy bool) (Source, error) {
	if err := ValidatePath(path); err != nil {
		return Source{}, err
	}
	if !filepath.IsAbs(path) && root != "" {
		path = filepath.Join(root, path)
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return Source{}, errors.Join(ErrCredential, errors.New("cannot resolve passfile path"))
	}
	return Source{path: path, legacy: legacy}, nil
}

// Read returns caller-owned bytes. Clear them after use. New passfiles are
// UTF-8 without BOM, one non-empty line, at most MaxBytes including its optional
// LF/CRLF terminator. Spaces, tabs, quotes and '#' are literal password bytes.
// Legacy references retain their existing byte-oriented normalization.
func (source Source) Read() ([]byte, error) {
	if !source.Explicit() {
		return nil, nil
	}
	var data []byte
	if source.env != "" {
		value, ok := os.LookupEnv(source.env)
		if !ok || len(value) > MaxBytes {
			return nil, errors.Join(ErrCredential, errors.New("legacy passphrase environment reference is unset or oversized"))
		}
		data = []byte(value)
	} else {
		var err error
		data, err = readFile(source.path)
		if err != nil {
			return nil, errors.Join(ErrCredential, err)
		}
	}
	secret := data
	if source.legacy {
		secret = bytes.TrimSuffix(secret, []byte("\n"))
		secret = bytes.TrimSuffix(secret, []byte("\r"))
	} else if bytes.HasSuffix(secret, []byte("\r\n")) {
		secret = secret[:len(secret)-2]
	} else if bytes.HasSuffix(secret, []byte("\n")) {
		secret = secret[:len(secret)-1]
	}
	invalid := len(secret) == 0 || len(data) > MaxBytes || bytes.IndexByte(secret, 0) >= 0
	if !source.legacy {
		invalid = invalid || !utf8.Valid(secret) || bytes.HasPrefix(secret, []byte{0xef, 0xbb, 0xbf}) || bytes.ContainsAny(secret, "\r\n")
	}
	if invalid {
		Clear(data)
		return nil, errors.Join(ErrCredential, errors.New("passfile must contain one non-empty UTF-8 line without BOM, NUL or embedded line breaks, at most 64 KiB"))
	}
	return secret, nil
}

func Clear(secret []byte) { clear(secret) }
