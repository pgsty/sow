package state

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/workmetrics"
)

func TestListPackageFactsForDigestsIsSelectiveBatchedAndDeterministic(t *testing.T) {
	ctx, collector := workmetrics.Ensure(context.Background())
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	facts := make([]PackageFact, 0, packageFactDigestBatchSize+25)
	selected := make([]string, 0, packageFactDigestBatchSize+20)
	for index := 0; index < packageFactDigestBatchSize+25; index++ {
		digest := fmt.Sprintf("%064x", index+1)
		blob := []byte(fmt.Sprintf(`{"index":%d}`, index))
		facts = append(facts, PackageFact{PackageSHA256: digest, FactSchema: "test/v1", Facts: blob})
		if index < packageFactDigestBatchSize+20 {
			selected = append(selected, digest)
		}
	}
	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index, fact := range facts {
		filename := fmt.Sprintf("pkg_%d_amd64.deb", index)
		if _, err := tx.ExecContext(ctx, `INSERT INTO package_objects(
sha256, format, coordinate, architecture, pool_path, size, name, source, version,
epoch, release, canonical_arch, kind, filename, storage, created_revision)
VALUES (?, 'deb', ?, 'amd64', ?, 1, 'pkg', 'pkg', '1', '', '', 'x86_64', 'main', ?, 'pending', 0)`,
			fact.PackageSHA256, fmt.Sprintf("pkg-%d=1:amd64", index), "pool/p/pkg/"+filename, filename); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPackageFacts(ctx, facts); err != nil {
		t.Fatal(err)
	}
	poisoned := facts[len(facts)-1].PackageSHA256
	if _, err := store.DB().Exec(`UPDATE package_facts SET facts_sha256 = ? WHERE package_sha256 = ?`, strings.Repeat("f", 64), poisoned); err != nil {
		t.Fatal(err)
	}
	request := append([]string{selected[len(selected)-1], selected[0], selected[0]}, selected[1:]...)
	got, err := store.ListPackageFactsForDigests(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	sorted := slices.IsSortedFunc(got, func(a, b PackageFact) int { return strings.Compare(a.PackageSHA256, b.PackageSHA256) })
	if len(got) != len(selected) || !sorted {
		t.Fatalf("selected facts=%d sorted=%t", len(got), sorted)
	}
	for _, fact := range got {
		if fact.PackageSHA256 == poisoned || fact.Corrupt {
			t.Fatalf("selective result read unrelated poison: %#v", fact)
		}
	}
	metrics := collector.Snapshot()
	wantBytes := int64(0)
	for _, fact := range facts[:len(selected)] {
		wantBytes += int64(len(fact.Facts))
	}
	if metrics.FactRowsRead != int64(len(selected)) || metrics.FactBytesRead != wantBytes || metrics.SQLStatements != 2 {
		t.Fatalf("selective metrics=%#v want rows=%d bytes=%d batches=2", metrics, len(selected), wantBytes)
	}
}

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
