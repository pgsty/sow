package catalog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRebuildIsDisposableAndEquivalent(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	manifestDir := filepath.Join(stateDir, "state", "manifests")
	if err := os.MkdirAll(manifestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := "asset/a\t1\tca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\nasset/b\t1\t3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d\n"
	if err := os.WriteFile(filepath.Join(manifestDir, "asset.tsv"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Rebuild(stateDir); err != nil {
		t.Fatal(err)
	}
	count, err := Count(stateDir)
	if err != nil || count != 2 {
		t.Fatalf("first cache count=%d err=%v", count, err)
	}
	if err := os.Remove(Path(stateDir)); err != nil {
		t.Fatal(err)
	}
	if err := Rebuild(stateDir); err != nil {
		t.Fatal(err)
	}
	count, err = Count(stateDir)
	if err != nil || count != 2 {
		t.Fatalf("rebuilt cache count=%d err=%v", count, err)
	}
}
