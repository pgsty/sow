package verify

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
)

func TestManifestSpoolUsesBoundedFanInAndDeduplicates(t *testing.T) {
	spool, err := newManifestSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	for index := 99; index >= 0; index-- {
		body := fmt.Sprintf("body-%03d", index)
		entry := manifestFor(fmt.Sprintf("pool/%03d.deb", index), body)
		if err := spool.Add(entry); err != nil {
			t.Fatal(err)
		}
		if index == 50 {
			if err := spool.Add(entry); err != nil {
				t.Fatal(err)
			}
		}
	}
	filename, err := spool.Finish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reader := manifest.NewReader(f)
	count := 0
	for {
		_, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 100 {
		t.Fatalf("entries = %d, want 100", count)
	}
}

func TestManifestSpoolRejectsConflictingDuplicatePath(t *testing.T) {
	spool, err := newManifestSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	first := sha256.Sum256([]byte("first"))
	second := sha256.Sum256([]byte("second"))
	if err := spool.Add(manifest.Entry{Path: "pool/a.deb", Size: 5, SHA256: first}); err != nil {
		t.Fatal(err)
	}
	if err := spool.Add(manifest.Entry{Path: "pool/a.deb", Size: 6, SHA256: second}); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Finish(context.Background()); err == nil {
		t.Fatal("conflicting duplicate path was accepted")
	}
}
