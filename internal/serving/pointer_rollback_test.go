package serving

import (
	"os"
	"strings"
	"testing"
)

func TestRollbackMirrorlistRestoresExactParentOrAbsence(t *testing.T) {
	root := t.TempDir()
	manifestPath := writeServingFixture(t, root)
	first := deriveFixtureGeneration(t, manifestPath)
	parent, err := NewChannel(first, "https://repo.example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileMirrorlist(root, parent); err != nil {
		t.Fatal(err)
	}
	parentBody, exists, err := ReadMirrorlist(root, parent.MirrorlistPath)
	if err != nil || !exists {
		t.Fatalf("read parent pointer: exists=%t err=%v", exists, err)
	}
	manifest, err := os.Open(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := testIdentity()
	identity.RefCommit = strings.Repeat("5", 40)
	second, err := DeriveGeneration(identity, manifest)
	_ = manifest.Close()
	if err != nil {
		t.Fatal(err)
	}
	child, err := NewChannel(second, "https://repo.example.invalid", &parent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileMirrorlist(root, child); err != nil {
		t.Fatal(err)
	}
	if err := RollbackMirrorlist(root, child, parentBody, true); err != nil {
		t.Fatal(err)
	}
	rolledBack, exists, err := ReadMirrorlist(root, child.MirrorlistPath)
	if err != nil || !exists || string(rolledBack) != string(parentBody) {
		t.Fatalf("parent rollback body=%q exists=%t err=%v", rolledBack, exists, err)
	}

	firstRoot := t.TempDir()
	if _, err := ReconcileMirrorlist(firstRoot, parent); err != nil {
		t.Fatal(err)
	}
	if err := RollbackMirrorlist(firstRoot, parent, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := ReadMirrorlist(firstRoot, parent.MirrorlistPath); err != nil || exists {
		t.Fatalf("first-install rollback left pointer: exists=%t err=%v", exists, err)
	}
}
