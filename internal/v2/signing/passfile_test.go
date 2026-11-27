package signing

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		{"BOM stripped", "\ufeffsecret\n", "secret", false},
		{"raw single-line bytes", "secret\xff\n", "secret\xff", false},
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

func TestPassfileSupportsSymlinksAndRejectsDirectoriesOrEmptyFIFOs(t *testing.T) {
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
	for _, name := range []string{"missing", "fifo", "directory"} {
		source, err := Select(context.Background(), root, name, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := source.Read(); !errors.Is(err, ErrCredential) {
			t.Errorf("accepted invalid passfile %s: %v", name, err)
		}
	}
	// Symlinks (in-workspace and external Kubernetes Secret mounts) are accepted.
	for _, name := range []string{"link", "parent-link/real"} {
		source, err := Select(context.Background(), root, name, "")
		if err != nil {
			t.Fatal(err)
		}
		got, err := source.Read()
		defer Clear(got)
		if err != nil || string(got) != "secret" {
			t.Errorf("symlink passfile %s failed: got=%q err=%v", name, got, err)
		}
	}

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

func TestRPMFileUsesTMPDIR(t *testing.T) {
	customTmp := t.TempDir()
	t.Setenv("TMPDIR", customTmp)
	sourcePath := filepath.Join(t.TempDir(), "pass")
	writePass(t, sourcePath, "tmpdir-secret\n")
	source, err := Select(context.Background(), "", sourcePath, "")
	if err != nil {
		t.Fatal(err)
	}
	path, cleanup, err := RPMFile(source)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if !strings.HasPrefix(path, customTmp) {
		t.Fatalf("RPMFile ignored TMPDIR: got %q, want under %q", path, customTmp)
	}
}

func TestPassfileReadDeadlineForIdleWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pass.fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	done := make(chan error, 1)
	go func() { _, err := readSourceFile("", path); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("idle writer: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("FIFO read did not time out")
	}
	// Keep a reader open until the writer has supplied the line and EOF.
	reader, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := writer.WriteString("test line\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := readSourceFile("", path)
	if err != nil || string(data) != "test line\n" {
		t.Fatalf("active FIFO read: %v", err)
	}
}
