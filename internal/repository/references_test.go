package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
)

func TestReferenceSetCountsDeduplicatedManifestObjects(t *testing.T) {
	object := Object{SHA256: Digest(sha256.Sum256([]byte("shared"))), Size: int64(len("shared"))}
	content := manifestBytes(t,
		manifest.Entry{Path: "a", Size: object.Size, SHA256: [32]byte(object.SHA256)},
		manifest.Entry{Path: "b", Size: object.Size, SHA256: [32]byte(object.SHA256)},
	)
	var references ReferenceSet
	if err := references.AddManifest(bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if references.Len() != 1 || references.Count(object.SHA256) != 2 {
		t.Fatalf("len=%d count=%d", references.Len(), references.Count(object.SHA256))
	}
	bad := []byte("valid\t1\t0000\n")
	if err := references.AddManifest(bytes.NewReader(bad)); err == nil {
		t.Fatal("invalid manifest accepted")
	}
	if references.Count(object.SHA256) != 2 {
		t.Fatal("failed manifest changed the reference set")
	}
}

func TestAuditReportsReachableOrphanAndMissingObjects(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	reachable := putString(t, store, "reachable")
	orphanOne := putString(t, store, "orphan-one")
	orphanTwo := putString(t, store, "orphan-two")
	missing := Object{SHA256: Digest(sha256.Sum256([]byte("missing"))), Size: int64(len("missing"))}
	var references ReferenceSet
	if err := references.Add(reachable); err != nil {
		t.Fatal(err)
	}
	if err := references.Add(reachable); err != nil {
		t.Fatal(err)
	}
	if err := references.Add(missing); err != nil {
		t.Fatal(err)
	}

	report, err := store.Audit(context.Background(), &references)
	if err != nil {
		t.Fatal(err)
	}
	stats := report.Stats
	if stats.ReferenceEntries != 3 || stats.ReferencedObjects != 2 || stats.PoolObjects != 3 ||
		stats.ReachableObjects != 1 || stats.OrphanObjects != 2 || stats.MissingObjects != 1 {
		t.Fatalf("unexpected audit stats: %#v", stats)
	}
	if len(report.Orphans) != 2 || len(report.Missing) != 1 || report.Missing[0] != missing {
		t.Fatalf("unexpected audit report: %#v", report)
	}
	if !containsObject(report.Orphans, orphanOne) || !containsObject(report.Orphans, orphanTwo) {
		t.Fatalf("orphan list missing objects: %#v", report.Orphans)
	}
	if len(report.OrphanSetSHA256) != 64 {
		t.Fatalf("invalid orphan fingerprint %q", report.OrphanSetSHA256)
	}
}

func TestGCIsDryRunByDefaultAndRequiresExactCurrentPlan(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	reachable := putString(t, store, "reachable")
	orphanOne := putString(t, store, "orphan-one")
	orphanTwo := putString(t, store, "orphan-two")
	var references ReferenceSet
	if err := references.Add(reachable); err != nil {
		t.Fatal(err)
	}

	dryRun, err := store.GC(context.Background(), &references, GCOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !dryRun.DryRun || dryRun.DeletedObjects != 0 || dryRun.Report.Stats.OrphanObjects != 2 {
		t.Fatalf("unexpected dry-run result: %#v", dryRun)
	}
	assertObjectExists(t, store, orphanOne, true)
	assertObjectExists(t, store, orphanTwo, true)

	if _, err := store.GC(context.Background(), &references, GCOptions{Apply: true}); !errors.Is(err, ErrGCProtection) {
		t.Fatalf("wanted protection error without confirmation, got %v", err)
	}
	if _, err := store.GC(context.Background(), &references, GCOptions{Apply: true, ConfirmOrphanSetSHA256: "wrong"}); !errors.Is(err, ErrGCProtection) {
		t.Fatalf("wanted protection error for wrong plan, got %v", err)
	}
	assertObjectExists(t, store, orphanOne, true)
	assertObjectExists(t, store, orphanTwo, true)

	deleted, err := store.GC(context.Background(), &references, GCOptions{Apply: true, ConfirmOrphanSetSHA256: dryRun.Report.OrphanSetSHA256})
	if err != nil {
		t.Fatal(err)
	}
	if deleted.DryRun || deleted.DeletedObjects != 2 || deleted.DeletedBytes != orphanOne.Size+orphanTwo.Size {
		t.Fatalf("unexpected delete result: %#v", deleted)
	}
	assertObjectExists(t, store, reachable, true)
	assertObjectExists(t, store, orphanOne, false)
	assertObjectExists(t, store, orphanTwo, false)
}

func TestGCRefusesStalePlanAndMissingReferences(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	first := putString(t, store, "first orphan")
	dryRun, err := store.GC(context.Background(), nil, GCOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second := putString(t, store, "second orphan")
	if _, err := store.GC(context.Background(), nil, GCOptions{Apply: true, ConfirmOrphanSetSHA256: dryRun.Report.OrphanSetSHA256}); !errors.Is(err, ErrGCProtection) {
		t.Fatalf("wanted stale-plan rejection, got %v", err)
	}
	assertObjectExists(t, store, first, true)
	assertObjectExists(t, store, second, true)

	missing := Object{SHA256: Digest(sha256.Sum256([]byte("missing root"))), Size: int64(len("missing root"))}
	var references ReferenceSet
	if err := references.Add(missing); err != nil {
		t.Fatal(err)
	}
	withMissing, err := store.GC(context.Background(), &references, GCOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GC(context.Background(), &references, GCOptions{Apply: true, ConfirmOrphanSetSHA256: withMissing.Report.OrphanSetSHA256}); !errors.Is(err, ErrReferencedObjectMissing) {
		t.Fatalf("wanted missing-reference rejection, got %v", err)
	}
	assertObjectExists(t, store, first, true)
	assertObjectExists(t, store, second, true)
}

func TestAuditRejectsSymlinkAtCASCoordinate(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "object")
	coordinate := store.ObjectPath(object.SHA256)
	if err := os.Remove(coordinate); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("object"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, coordinate); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Audit(context.Background(), nil); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("wanted unsafe CAS coordinate error, got %v", err)
	}
}

func containsObject(objects []Object, wanted Object) bool {
	for _, object := range objects {
		if object == wanted {
			return true
		}
	}
	return false
}

func assertObjectExists(t *testing.T, store *Store, object Object, wanted bool) {
	t.Helper()
	_, err := os.Stat(store.ObjectPath(object.SHA256))
	if wanted && err != nil {
		t.Fatalf("object %s missing: %v", object.HashString(), err)
	}
	if !wanted && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("object %s still exists or stat failed: %v", object.HashString(), err)
	}
}
