package manifest

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicCopyFailsClosedOnDirectorySyncAndRetryConverges(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "state", "manifest.tsv")
	wanted := []byte("path\t1\t" + string(bytes.Repeat([]byte("a"), 64)) + "\n")
	injected := errors.New("injected directory sync failure")
	err := atomicCopyWithDirectorySync(destination, bytes.NewReader(wanted), 0o600, func(string) error { return injected })
	if !errors.Is(err, injected) {
		t.Fatalf("directory sync failure was hidden: %v", err)
	}
	visible, readErr := os.ReadFile(destination)
	if readErr != nil || !bytes.Equal(visible, wanted) {
		t.Fatalf("post-rename uncertain result is not inspectable: body=%q err=%v", visible, readErr)
	}
	if err := AtomicCopy(destination, bytes.NewReader(wanted), 0o600); err != nil {
		t.Fatalf("retry did not converge after uncertain rename: %v", err)
	}
}
