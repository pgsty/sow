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
