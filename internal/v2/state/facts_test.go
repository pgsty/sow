package state

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackageFactsBulkRoundTripAndFingerprint(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	digest := strings.Repeat("a", 64)
	if _, err := store.DB().ExecContext(ctx, `INSERT OR IGNORE INTO package_objects(
sha256, format, coordinate, architecture, pool_path, size, name, source, version,
epoch, release, canonical_arch, kind, filename, storage, created_revision)
VALUES (?, 'deb', 'pkg=1:amd64', 'amd64', 'pool/p/pkg/pkg_1_amd64.deb', 7, 'pkg', 'pkg', '1', '', '', 'x86_64', 'main', 'pkg_1_amd64.deb', 'pending', 0)`, digest); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"schema":"aptrepo/package-facts/v1"}`)
	if err := store.UpsertPackageFacts(ctx, []PackageFact{{PackageSHA256: digest, FactSchema: "aptrepo/package-facts/v1", Facts: body}}); err != nil {
		t.Fatal(err)
	}
	fingerprint := &PackageFingerprint{Device: ^uint64(0), Inode: 42, Size: 7, MTimeNano: -1, CTimeNano: 9}
	if err := store.UpdatePackageFingerprints(ctx, []PackageFact{{PackageSHA256: digest, Fingerprint: fingerprint}}); err != nil {
		t.Fatal(err)
	}
	facts, err := store.ListPackageFacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 || facts[0].PackageSHA256 != digest || facts[0].FactSchema != "aptrepo/package-facts/v1" || !bytes.Equal(facts[0].Facts, body) || facts[0].Fingerprint == nil || *facts[0].Fingerprint != *fingerprint {
		t.Fatalf("facts=%#v", facts)
	}
	fingerprints, err := store.ListPackageFingerprints(ctx)
	if err != nil || len(fingerprints) != 1 || fingerprints[0].PackageSHA256 != digest || fingerprints[0].Fingerprint == nil || *fingerprints[0].Fingerprint != *fingerprint {
		t.Fatalf("fingerprints=%#v err=%v", fingerprints, err)
	}
}

func TestPackageFactsStructuralCorruptionBecomesRebuildableMiss(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	digest := strings.Repeat("b", 64)
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO package_objects(
sha256, format, coordinate, architecture, pool_path, size, name, source, version,
epoch, release, canonical_arch, kind, filename, storage, created_revision)
VALUES (?, 'deb', 'pkg=1:amd64', 'amd64', 'pool/p/pkg/pkg_1_amd64.deb', 7, 'pkg', 'pkg', '1', '', '', 'x86_64', 'main', 'pkg_1_amd64.deb', 'pending', 0)`, digest); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"schema":"aptrepo/package-facts/v1"}`)
	if err := store.UpsertPackageFacts(ctx, []PackageFact{{PackageSHA256: digest, FactSchema: "aptrepo/package-facts/v1", Facts: body}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `PRAGMA ignore_check_constraints = ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE package_facts SET fact_schema = '', device = '1' WHERE package_sha256 = ?`, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `PRAGMA ignore_check_constraints = OFF`); err != nil {
		t.Fatal(err)
	}
	facts, err := store.ListPackageFacts(ctx)
	if err != nil || len(facts) != 1 || !facts[0].Corrupt || facts[0].Fingerprint != nil {
		t.Fatalf("corrupt facts=%#v err=%v", facts, err)
	}
	fingerprints, err := store.ListPackageFingerprints(ctx)
	if err != nil || len(fingerprints) != 1 || fingerprints[0].Fingerprint != nil {
		t.Fatalf("corrupt fingerprints=%#v err=%v", fingerprints, err)
	}
}
