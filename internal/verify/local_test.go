package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/views"
)

func TestFilesystemManifestAndStateComparisonsUseRealBytes(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "repo", "a.bin"), "alpha")
	writeFile(t, filepath.Join(root, "repo", "b.bin"), "beta")
	expected := manifestText(t,
		manifestFor("repo/a.bin", "alpha"),
		manifestFor("repo/b.bin", "beta"),
	)
	check := FilesystemCheck{CheckID: "tree", Root: root, Scope: manifest.Scope{Path: "repo"}, Expected: ReaderStream(expected), Workers: 2, ChunkEntries: 1}
	clean := Run(context.Background(), Request{Layers: []Layer{LayerL1}, Checks: []Check{check}})
	if clean.Outcome != OutcomePassed {
		t.Fatalf("clean filesystem rejected: %+v", clean)
	}

	writeFile(t, filepath.Join(root, "repo", "b.bin"), "changed")
	drift := Run(context.Background(), Request{Layers: []Layer{LayerL1}, Checks: []Check{check}})
	if drift.Exit != ExitVerification || !hasCode(drift, "FS_CHANGED") {
		t.Fatalf("changed bytes not found: %+v", drift)
	}

	if err := os.Remove(filepath.Join(root, "repo", "b.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "repo", "a.bin"), filepath.Join(root, "repo", "b.bin")); err != nil {
		t.Fatal(err)
	}
	unsafe := Run(context.Background(), Request{Layers: []Layer{LayerL1}, Checks: []Check{check}})
	if !hasCode(unsafe, "FS_TREE_UNSAFE") {
		t.Fatalf("symlink was not rejected: %+v", unsafe)
	}

	remote := strings.Replace(expected, manifestFor("repo/b.bin", "beta").HashString(), strings.Repeat("0", 64), 1)
	l2 := Run(context.Background(), Request{Layers: []Layer{LayerL2}, Checks: []Check{ManifestComparisonCheck{
		CheckID: "remote", AtLayer: LayerL2, Subject: "cf", Desired: ReaderStream(expected), Actual: ReaderStream(remote), CodePrefix: "REMOTE",
	}}})
	if !hasCode(l2, "REMOTE_CHANGED") {
		t.Fatalf("remote drift not found: %+v", l2)
	}

	cache := Run(context.Background(), Request{Layers: []Layer{LayerL1}, Checks: []Check{CacheCheck{
		CheckID: "cache", Canonical: ReaderStream(expected), Projection: ReaderStream(expected), ExpectedSchema: 1, ActualSchema: 2,
		ExpectedCanonicalHead: strings.Repeat("a", 40), ActualCanonicalHead: strings.Repeat("b", 40),
	}}})
	if !hasCode(cache, "CACHE_SCHEMA_DRIFT") || !hasCode(cache, "CACHE_HEAD_DRIFT") {
		t.Fatalf("cache schema drift not found: %+v", cache)
	}
}

func TestCASAuditAndConfidentialityUseProductionParsers(t *testing.T) {
	root := t.TempDir()
	store, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	reachable, err := store.Put(context.Background(), strings.NewReader("reachable"))
	if err != nil {
		t.Fatal(err)
	}
	orphan, err := store.Put(context.Background(), strings.NewReader("orphan"))
	if err != nil {
		t.Fatal(err)
	}
	missingDigest := sha256.Sum256([]byte("missing"))
	rootManifest := manifestText(t,
		manifest.Entry{Path: "repo/missing", Size: 7, SHA256: missingDigest},
		manifest.Entry{Path: "repo/reachable", Size: reachable.Size, SHA256: [sha256.Size]byte(reachable.SHA256)},
	)
	casReport := Run(context.Background(), Request{Layers: []Layer{LayerL1}, Checks: []Check{CASCheck{
		CheckID: "cas", Store: store, Roots: []NamedManifest{{Name: "repo", Open: ReaderStream(rootManifest)}},
	}}})
	if !hasCode(casReport, "CAS_OBJECT_MISSING") || !hasCode(casReport, "CAS_OBJECT_ORPHAN") {
		t.Fatalf("CAS partition incomplete (orphan %s): %+v", orphan.HashString(), casReport)
	}
	if err := os.Remove(store.ObjectPath(orphan.SHA256)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(store.ObjectPath(reachable.SHA256), store.ObjectPath(orphan.SHA256)); err != nil {
		t.Fatal(err)
	}
	unsafeCAS := Run(context.Background(), Request{Layers: []Layer{LayerL1}, Checks: []Check{CASCheck{
		CheckID: "cas", Store: store, Roots: []NamedManifest{{Name: "repo", Open: ReaderStream(rootManifest)}},
	}}})
	if !hasCode(unsafeCAS, "CAS_AUDIT_FAILED") {
		t.Fatalf("symlinked CAS coordinate was not rejected: %+v", unsafeCAS)
	}

	public := viewText(t, views.Entry{Repo: "r", OS: "el9", Arch: "x86_64", Name: "secret", Version: "1", Path: "repo/secret.rpm", Size: 1, SHA256: strings.Repeat("a", 64), Pool: "gated"})
	viewReport := Run(context.Background(), Request{Layers: []Layer{LayerL1}, Checks: []Check{ViewCheck{
		CheckID: "latest/r/el9/x86_64", Open: ReaderStream(public), Repo: "r", OS: "el9", Arch: "x86_64", Public: true,
	}}})
	if viewReport.Outcome != OutcomeFailed || !hasCode(viewReport, "CONFIDENTIALITY_GATED_REFERENCE") {
		t.Fatalf("gated public reference was not blocked: %+v", viewReport)
	}
}

func TestRefPointerCheckRejectsDrift(t *testing.T) {
	report := Run(context.Background(), Request{Layers: []Layer{LayerL2}, Checks: []Check{RefPointerCheck{
		CheckID: "ref", AtLayer: LayerL2, RefName: "refs/sow/remotes/cf/latest/r/el9/x86_64",
		ExpectedCommit: strings.Repeat("a", 40), ActualCommit: strings.Repeat("b", 40),
	}}})
	if !hasCode(report, "REF_POINTER_DRIFT") {
		t.Fatalf("ref drift not found: %+v", report)
	}
}

func manifestFor(path, body string) manifest.Entry {
	digest := sha256.Sum256([]byte(body))
	return manifest.Entry{Path: path, Size: int64(len(body)), SHA256: digest}
}

func manifestText(t *testing.T, entries ...manifest.Entry) string {
	t.Helper()
	var out bytes.Buffer
	for _, entry := range entries {
		if err := manifest.WriteEntry(&out, entry); err != nil {
			t.Fatal(err)
		}
	}
	return out.String()
}

func viewText(t *testing.T, entries ...views.Entry) string {
	t.Helper()
	var out bytes.Buffer
	for _, entry := range entries {
		if err := views.WriteEntry(&out, entry); err != nil {
			t.Fatal(err)
		}
	}
	return out.String()
}

func writeFile(t *testing.T, filename, body string) {
	t.Helper()
	if err := os.WriteFile(filename, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func dumpReport(report Report) string {
	return fmt.Sprintf("%+v", report)
}
