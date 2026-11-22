package signing

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func writePass(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPassfileContent(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		invalid           bool
	}{
		{"no terminator", "secret", "secret", false},
		{"LF", "secret\n", "secret", false},
		{"CRLF", "secret\r\n", "secret", false},
		{"literal whitespace", " \t'口令#' \t\r\n", " \t'口令#' \t", false},
		{"only spaces", "  \n", "  ", false},
		{"size limit", strings.Repeat("p", MaxBytes), strings.Repeat("p", MaxBytes), false},
		{"empty", "", "", true},
		{"empty LF", "\n", "", true},
		{"empty CRLF", "\r\n", "", true},
		{"bare CR", "secret\r", "", true},
		{"two lines", "secret\nother", "", true},
		{"extra empty line", "secret\n\n", "", true},
		{"NUL", "secret\x00", "", true},
		{"BOM", "\ufeffsecret", "", true},
		{"invalid UTF8", "secret\xff", "", true},
		{"oversized", strings.Repeat("p", MaxBytes) + "\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pass")
			writePass(t, path, tc.input)
			source, err := Select(context.Background(), "", path, "")
			if err != nil {
				t.Fatal(err)
			}
			got, err := source.Read()
			defer Clear(got)
			if tc.invalid {
				if !errors.Is(err, ErrCredential) || got != nil {
					t.Fatalf("invalid passfile accepted: %v", err)
				}
			} else if err != nil || string(got) != tc.want {
				t.Fatalf("password bytes changed or were rejected: %v", err)
			}
		})
	}
}

func TestPassfilePrecedenceAndPathBases(t *testing.T) {
	cwd, root := t.TempDir(), t.TempDir()
	t.Chdir(cwd)
	writePass(t, filepath.Join(cwd, "cli"), "cli")
	writePass(t, filepath.Join(cwd, "default"), "environment")
	writePass(t, filepath.Join(root, "configured"), "config")
	writePass(t, filepath.Join(root, "legacy"), "legacy\r\n")
	t.Setenv(Environment, "default")
	t.Setenv("SOW_TEST_LEGACY_PASS", "legacy env\r\n")
	for _, tc := range []struct{ cli, configured, legacy, want string }{
		{"cli", "missing", "", "cli"},
		{"cli", "", "env://UNSET_LEGACY", "cli"},
		{"", "configured", "", "config"},
		{"", "", "file://legacy", "legacy"},
		{"", "", "env://SOW_TEST_LEGACY_PASS", "legacy env"},
		{"", "", "", "environment"},
	} {
		source, err := Select(WithPassFile(context.Background(), tc.cli), root, tc.configured, tc.legacy)
		if err != nil {
			t.Fatal(err)
		}
		got, err := source.Read()
		if err != nil || string(got) != tc.want {
			t.Fatalf("wrong credential precedence: %v", err)
		}
		Clear(got)
	}
	source, err := Select(context.Background(), root, "missing", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Read(); !errors.Is(err, ErrCredential) {
		t.Fatal("missing config source fell back to environment")
	}
	t.Setenv(Environment, "")
	if _, err := Select(context.Background(), root, "", ""); err == nil {
		t.Fatal("an explicitly empty environment path was ignored")
	}
	// Legacy passphrase references keep their file:// form; passfile paths do not.
	for _, uri := range []string{"file:///run/secrets/gpg", "s3://bucket/key"} {
		if _, err := Select(WithPassFile(context.Background(), uri), root, "", ""); err == nil || !strings.Contains(err.Error(), "not a URI") {
			t.Fatalf("CLI passfile URI %q error=%v", uri, err)
		}
		if _, err := Select(context.Background(), root, uri, ""); err == nil || !strings.Contains(err.Error(), "not a URI") {
			t.Fatalf("configured passfile URI %q error=%v", uri, err)
		}
	}
	if err := os.Unsetenv(Environment); err != nil {
		t.Fatal(err)
	}
	writePass(t, filepath.Join(cwd, "passfile"), "must not be discovered")
	source, err = Select(context.Background(), root, "", "")
	if err != nil || source.Explicit() {
		t.Fatalf("an implicit passfile was selected: %v", err)
	}
}

func TestPassfileRejectsUnsafeFiles(t *testing.T) {
	root := t.TempDir()
	writePass(t, filepath.Join(root, "real"), "secret")
	if err := os.Symlink("real", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(root, "parent-link")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "link", "fifo", "directory", "parent-link/real"} {
		source, err := Select(context.Background(), root, name, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := source.Read(); !errors.Is(err, ErrCredential) {
			t.Errorf("accepted unsafe file %s: %v", name, err)
		}
	}

	// External secret mounts (e.g. Kubernetes Secret ..data symlink projection)
	// outside the workspace root are allowed, provided they resolve to a safe
	// regular file outside the workspace.
	externalDir := t.TempDir()
	k8sSnapshot := filepath.Join(externalDir, "..2026_11_21_00_00")
	if err := os.Mkdir(k8sSnapshot, 0o700); err != nil {
		t.Fatal(err)
	}
	writePass(t, filepath.Join(k8sSnapshot, "gpg-pass"), "k8s-secret\n")
	if err := os.Symlink("..2026_11_21_00_00", filepath.Join(externalDir, "..data")); err != nil {
		t.Fatal(err)
	}
	externalPass := filepath.Join(externalDir, "gpg-pass")
	if err := os.Symlink(filepath.Join("..data", "gpg-pass"), externalPass); err != nil {
		t.Fatal(err)
	}
	extSource, err := Select(context.Background(), root, externalPass, "")
	if err != nil {
		t.Fatal(err)
	}
	gotExt, err := extSource.Read()
	defer Clear(gotExt)
	if err != nil || string(gotExt) != "k8s-secret" {
		t.Fatalf("external k8s secret symlink passfile failed: got=%q err=%v", gotExt, err)
	}

	// External symlink pointing back inside workspace root must still be rejected.
	bounceLink := filepath.Join(externalDir, "bounce")
	if err := os.Symlink(filepath.Join(root, "real"), bounceLink); err != nil {
		t.Fatal(err)
	}
	bounceSource, err := Select(context.Background(), root, bounceLink, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bounceSource.Read(); !errors.Is(err, ErrCredential) {
		t.Fatalf("external symlink bouncing into workspace was accepted: %v", err)
	}

	// CLI --passfile and SOW_GPG_PASSFILE must enforce the exact same workspace
	// O_NOFOLLOW and anti-bounce-back boundaries while keeping external K8s
	// Secret symlinks working.
	for _, candidate := range []string{filepath.Join(root, "link"), bounceLink} {
		cliSrc, err := Select(WithPassFile(context.Background(), candidate), root, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cliSrc.Read(); !errors.Is(err, ErrCredential) {
			t.Fatalf("CLI --passfile accepted unsafe workspace path %s: %v", candidate, err)
		}
		t.Setenv(Environment, candidate)
		envSrc, err := Select(context.Background(), root, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := envSrc.Read(); !errors.Is(err, ErrCredential) {
			t.Fatalf("SOW_GPG_PASSFILE accepted unsafe workspace path %s: %v", candidate, err)
		}
	}
	_ = os.Unsetenv(Environment)
	cliExt, err := Select(WithPassFile(context.Background(), externalPass), root, "", "")
	if err != nil {
		t.Fatal(err)
	}
	gotCLIExt, err := cliExt.Read()
	defer Clear(gotCLIExt)
	if err != nil || string(gotCLIExt) != "k8s-secret" {
		t.Fatalf("CLI --passfile rejected external k8s secret symlink: got=%q err=%v", gotCLIExt, err)
	}
}

func TestLegacyPassphraseBytesRemainCompatible(t *testing.T) {
	t.Setenv("SOW_TEST_LEGACY_PASS", "line1\nline2\r")
	source, err := Select(context.Background(), "", "", "env://SOW_TEST_LEGACY_PASS")
	if err != nil {
		t.Fatal(err)
	}
	got, err := source.Read()
	defer Clear(got)
	if err != nil || string(got) != "line1\nline2" {
		t.Fatalf("legacy normalization changed: %v", err)
	}
}

func TestRPMCredentialIsPrivateRepeatableAndRemoved(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "pass with % spaces")
	writePass(t, sourcePath, " 'private % value' \r\n")
	source, err := Select(context.Background(), "", sourcePath, "")
	if err != nil {
		t.Fatal(err)
	}
	path, cleanup, err := RPMFile(source)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{path, 0o600}, {filepath.Dir(path), 0o700}} {
		info, err := os.Stat(item.path)
		if err != nil || info.Mode().Perm() != item.mode {
			t.Fatalf("private mode: %v", err)
		}
	}
	for range 2 {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, []byte(" 'private % value' ")) {
			t.Fatalf("repeatable RPM password: %v", err)
		}
		Clear(got)
	}
	if strings.Contains(strings.Join(RPMArgs(path), " "), "private % value") {
		t.Fatal("secret entered RPM arguments")
	}
	cleanup()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temporary password remained")
	}
	if _, err := os.Stat(sourcePath); err != nil {
		t.Fatal("caller password file was removed")
	}
}

func TestPassfileRejectsExternalSubdirSymlinkAndHandlesNonCanonicalRoot(t *testing.T) {
	base := t.TempDir()
	realParent := filepath.Join(base, "real-parent")
	ws := filepath.Join(realParent, "ws")
	sub := filepath.Join(ws, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideSecret := filepath.Join(outside, "ext.pass")
	writePass(t, outsideSecret, "ext-secret\n")
	inWsRegular := filepath.Join(sub, "regular.pass")
	writePass(t, inWsRegular, "in-ws-secret\n")
	inWsEscapeLink := filepath.Join(sub, "escape.link")
	if err := os.Symlink(outsideSecret, inWsEscapeLink); err != nil {
		t.Fatal(err)
	}
	inWsDirLink := filepath.Join(ws, "dir-link")
	if err := os.Symlink(sub, inWsDirLink); err != nil {
		t.Fatal(err)
	}

	// External symlink pointing to a subdirectory of the workspace must be
	// rejected whether its leaf is a regular file inside the workspace or an
	// in-workspace symlink escaping back outside.
	extSubLink := filepath.Join(outside, "to-ws-sub")
	if err := os.Symlink(sub, extSubLink); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{
		filepath.Join(extSubLink, "regular.pass"),
		filepath.Join(extSubLink, "escape.link"),
	} {
		src, err := Select(WithPassFile(context.Background(), candidate), ws, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := src.Read(); !errors.Is(err, ErrCredential) {
			t.Fatalf("external subdir symlink path %s was accepted: %v", candidate, err)
		}
	}

	// A non-canonical workspace root under a symlinked parent must still allow
	// genuine regular passfiles inside the workspace while rejecting symlinks
	// inside the workspace.
	parentAlias := filepath.Join(base, "parent-alias")
	if err := os.Symlink(realParent, parentAlias); err != nil {
		t.Fatal(err)
	}
	aliasWS := filepath.Join(parentAlias, "ws")
	okSrc, err := Select(WithPassFile(context.Background(), filepath.Join(aliasWS, "sub", "regular.pass")), aliasWS, "", "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := okSrc.Read()
	defer Clear(got)
	if err != nil || string(got) != "in-ws-secret" {
		t.Fatalf("regular passfile under symlinked parent alias failed: got=%q err=%v", got, err)
	}
	for _, unsafe := range []string{
		filepath.Join(aliasWS, "sub", "escape.link"),
		filepath.Join(aliasWS, "dir-link", "regular.pass"),
	} {
		badSrc, err := Select(WithPassFile(context.Background(), unsafe), aliasWS, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := badSrc.Read(); !errors.Is(err, ErrCredential) {
			t.Fatalf("in-workspace symlink via parent alias %s was accepted: %v", unsafe, err)
		}
	}

	// External symlink directly to the workspace root itself, multi-hop leaf
	// bounce through an in-workspace symlink, and multi-hop directory bounce
	// through an in-workspace directory symlink must all be rejected.
	extRootLink := filepath.Join(outside, "to-ws-root")
	if err := os.Symlink(ws, extRootLink); err != nil {
		t.Fatal(err)
	}
	extLeafHop := filepath.Join(outside, "leaf-hop")
	if err := os.Symlink(inWsEscapeLink, extLeafHop); err != nil {
		t.Fatal(err)
	}
	inWsDirEscape := filepath.Join(ws, "dir-escape")
	if err := os.Symlink(outside, inWsDirEscape); err != nil {
		t.Fatal(err)
	}
	extDirHop := filepath.Join(outside, "dir-hop")
	if err := os.Symlink(inWsDirEscape, extDirHop); err != nil {
		t.Fatal(err)
	}
	extDotDotHop := filepath.Join(outside, "dotdot-hop")
	if err := os.Symlink(ws+"/sub/../../../outside/ext.pass", extDotDotHop); err != nil {
		t.Fatal(err)
	}
	for _, attack := range []string{
		filepath.Join(extRootLink, "sub", "regular.pass"),
		extLeafHop,
		filepath.Join(extDirHop, "ext.pass"),
		extDotDotHop,
	} {
		src, err := Select(WithPassFile(context.Background(), attack), ws, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := src.Read(); !errors.Is(err, ErrCredential) {
			t.Fatalf("adversarial symlink bounce %s was accepted: %v", attack, err)
		}
	}

	// On case-insensitive filesystems (e.g. macOS APFS), alternating case on the
	// workspace root must not bypass in-workspace O_NOFOLLOW or external
	// bounce-back rejection, while still permitting regular files inside root.
	mixedWS := filepath.Join(realParent, "MixedCaseWS")
	if err := os.MkdirAll(mixedWS, 0o700); err != nil {
		t.Fatal(err)
	}
	lowerWS := filepath.Join(realParent, "mixedcasews")
	if lowerInfo, statErr := os.Stat(lowerWS); statErr == nil {
		if mixedInfo, err := os.Stat(mixedWS); err == nil && os.SameFile(lowerInfo, mixedInfo) {
			mixedReg := filepath.Join(mixedWS, "reg.pass")
			writePass(t, mixedReg, "mixed-secret\n")
			mixedEscape := filepath.Join(mixedWS, "escape.link")
			if err := os.Symlink(outsideSecret, mixedEscape); err != nil {
				t.Fatal(err)
			}
			extBounceLower := filepath.Join(outside, "bounce-lower")
			if err := os.Symlink(filepath.Join(lowerWS, "reg.pass"), extBounceLower); err != nil {
				t.Fatal(err)
			}
			// Regular file accessed via alternate casing must still work.
			regSrc, err := Select(WithPassFile(context.Background(), filepath.Join(lowerWS, "reg.pass")), mixedWS, "", "")
			if err != nil {
				t.Fatal(err)
			}
			regBytes, err := regSrc.Read()
			defer Clear(regBytes)
			if err != nil || string(regBytes) != "mixed-secret" {
				t.Fatalf("regular passfile via alternate FS case failed: got=%q err=%v", regBytes, err)
			}
			// Both in-workspace symlink escape and external bounce via alternate casing must fail.
			for _, attack := range []string{
				filepath.Join(lowerWS, "escape.link"),
				extBounceLower,
			} {
				badSrc, err := Select(WithPassFile(context.Background(), attack), mixedWS, "", "")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := badSrc.Read(); !errors.Is(err, ErrCredential) {
					t.Fatalf("case-insensitive bypass %s was accepted: %v", attack, err)
				}
			}
		}
	}
}
