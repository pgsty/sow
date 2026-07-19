package serving

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadMirrorlistIsBoundedAndRejectsSpecialCoordinates(t *testing.T) {
	root := t.TempDir()
	relative := MirrorlistPath("latest", "rpm-test", "el10", "x86_64")
	filename := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte("https://repo.example.invalid/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if body, exists, err := ReadMirrorlist(root, relative); err != nil || !exists || string(body) != "https://repo.example.invalid/\n" {
		t.Fatalf("baseline body=%q exists=%v err=%v", body, exists, err)
	}
	if err := os.WriteFile(filename, []byte(strings.Repeat("x", mirrorlistMaxBytes+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadMirrorlist(root, relative); err == nil {
		t.Fatal("oversized mirrorlist was accepted")
	}
	if err := os.Remove(filename); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filename, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadMirrorlist(root, relative); err == nil {
		t.Fatal("FIFO mirrorlist was accepted")
	}
}

func TestReconcileMirrorlistRepairsOnlyCanonicalPointerPermissions(t *testing.T) {
	root := t.TempDir()
	manifestPath := writeServingFixture(t, root)
	generation := deriveFixtureGeneration(t, manifestPath)
	channel, err := NewChannel(generation, "https://repo.example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(root, filepath.FromSlash(channel.MirrorlistPath))
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	for current := filepath.Dir(filename); current != root; current = filepath.Dir(current) {
		if err := os.Chmod(current, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	body, err := channel.MirrorlistBody()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := ReconcileMirrorlist(root, channel); err != nil || !changed {
		t.Fatalf("permission reconciliation changed=%v err=%v", changed, err)
	}
	if err := ValidateMirrorlistPermissions(root, channel.MirrorlistPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filename)
	if err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("mirrorlist mode=%v err=%v", info.Mode(), err)
	}
}

func TestMirrorlistPermissionValidationRejectsPrivateFileAndParentInBothModes(t *testing.T) {
	validators := []struct {
		name     string
		validate func(string, string) error
	}{
		{name: "ordinary", validate: ValidateMirrorlistPermissions},
		{
			name: "bound",
			validate: func(root, relative string) error {
				handle, err := os.OpenRoot(root)
				if err != nil {
					return err
				}
				defer handle.Close()
				return ValidateMirrorlistPermissionsRoot(handle, relative)
			},
		},
	}
	for _, validator := range validators {
		validator := validator
		t.Run(validator.name+"/mode-0600-file", func(t *testing.T) {
			root := t.TempDir()
			relative := MirrorlistPath("latest", "rpm-test", "el10", "x86_64")
			filename := filepath.Join(root, filepath.FromSlash(relative))
			if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filename, []byte("https://repo.example.invalid/\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validator.validate(root, relative); err == nil || !strings.Contains(err.Error(), "0444") {
				t.Fatalf("private mirrorlist accepted: %v", err)
			}
		})
		t.Run(validator.name+"/mode-0700-parent", func(t *testing.T) {
			root := t.TempDir()
			relative := MirrorlistPath("latest", "rpm-test", "el10", "x86_64")
			filename := filepath.Join(root, filepath.FromSlash(relative))
			if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filename, []byte("https://repo.example.invalid/\n"), 0o444); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(root, "_sow", "v1"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := validator.validate(root, relative); err == nil || !strings.Contains(err.Error(), "0755") {
				t.Fatalf("private mirrorlist parent accepted: %v", err)
			}
		})
	}
}
