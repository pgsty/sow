package managed

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/state"
)

func TestRetainPriorAPTByHashCarriesOnlyPreviousRelease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	live := filepath.Join(root, "live")
	staged := filepath.Join(root, "staged")
	architecture := state.Architecture{Family: "x86_64", EcosystemArch: "amd64"}
	relativeRoot := filepath.Join("main", "binary-amd64")

	type artifact struct {
		name    string
		content []byte
		digest  string
	}
	prior := []artifact{
		{name: "Packages", content: []byte("Package: prior\nVersion: 1\n\n")},
		{name: "Packages.gz", content: []byte("prior deterministic gzip bytes")},
	}
	current := []artifact{
		{name: "Packages", content: []byte("Package: current\nVersion: 2\n\n")},
		{name: "Packages.gz", content: []byte("current deterministic gzip bytes")},
	}
	install := func(base string, artifacts []artifact) []artifact {
		t.Helper()
		byHash := filepath.Join(base, relativeRoot, "by-hash", "SHA256")
		if err := os.MkdirAll(byHash, 0o755); err != nil {
			t.Fatal(err)
		}
		for index := range artifacts {
			artifacts[index].digest = bytesSHA(artifacts[index].content)
			indexPath := filepath.Join(base, relativeRoot, artifacts[index].name)
			if err := os.WriteFile(indexPath, artifacts[index].content, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(indexPath, filepath.Join(byHash, artifacts[index].digest)); err != nil {
				t.Fatal(err)
			}
		}
		return artifacts
	}
	prior = install(live, prior)
	current = install(staged, current)
	release := "Origin: SOW\nAcquire-By-Hash: yes\nSHA256:\n"
	for _, entry := range prior {
		release += fmt.Sprintf(" %s %d main/binary-amd64/%s\n", entry.digest, len(entry.content), entry.name)
	}
	if err := os.WriteFile(filepath.Join(live, "Release"), []byte(release), 0o644); err != nil {
		t.Fatal(err)
	}
	oldOldDigest := bytesSHA([]byte("not referenced by prior Release"))
	if err := os.WriteFile(filepath.Join(live, relativeRoot, "by-hash", "SHA256", oldOldDigest), []byte("not referenced by prior Release"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := retainPriorAPTByHash(ctx, live, staged, []state.Architecture{architecture}); err != nil {
		t.Fatal(err)
	}
	for _, entry := range prior {
		sourceInfo, err := os.Stat(filepath.Join(live, relativeRoot, "by-hash", "SHA256", entry.digest))
		if err != nil {
			t.Fatal(err)
		}
		targetInfo, err := os.Stat(filepath.Join(staged, relativeRoot, "by-hash", "SHA256", entry.digest))
		if err != nil || !os.SameFile(sourceInfo, targetInfo) {
			t.Fatalf("prior by-hash %s was not retained as the same immutable object: %v", entry.name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(staged, relativeRoot, "by-hash", "SHA256", oldOldDigest)); !os.IsNotExist(err) {
		t.Fatalf("unreferenced older by-hash object was retained: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(staged, relativeRoot, "by-hash", "SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(entries), len(prior)+len(current); got != want {
		t.Fatalf("retained by-hash object count=%d want bounded two-generation count=%d", got, want)
	}
}
