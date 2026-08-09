package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestOpenMigratesAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	assertSchemaV2(t, store.DB())
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assertSchemaV2(t, store.DB())
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatalf("idempotent open changed database size: %d -> %d", len(before), len(after))
	}
}

func TestOpenExistingForMigrationAddsReverseMembershipIndexesToV8(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=rwc")
	if err != nil {
		t.Fatal(err)
	}
	migrations := []struct {
		schema   string
		checksum string
	}{
		{schemaV1SQL, SchemaV1SHA256},
		{schemaV2SQL, SchemaV2SHA256},
		{schemaV3SQL, SchemaV3SHA256},
		{schemaV4SQL, SchemaV4SHA256},
		{schemaV5SQL, SchemaV5SHA256},
		{schemaV6SQL, SchemaV6SHA256},
		{schemaV7SQL, SchemaV7SHA256},
		{schemaV8SQL, SchemaV8SHA256},
	}
	for index, migration := range migrations {
		if _, err := db.Exec(migration.schema); err != nil {
			db.Close()
			t.Fatalf("apply fixture schema v%d: %v", index+1, err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (?, ?, ?)`, index+1, migration.checksum, "2026-08-01T00:00:00Z"); err != nil {
			db.Close()
			t.Fatalf("record fixture schema v%d: %v", index+1, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := OpenExistingForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assertSchemaV2(t, store.DB())
	assertMembershipReverseIndexes(t, store.DB())
}

func TestMembershipReverseIndexesCoverObjectLookup(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assertMembershipReverseIndexes(t, store.DB())
}

func TestPruneTerminalOperationsHonorsNanosecondCutoff(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	for index, offset := range []time.Duration{400 * time.Nanosecond, 600 * time.Nanosecond} {
		id := strings.Repeat(string(rune('a'+index)), 64)
		at := formatTimestamp(base.Add(offset))
		if _, err := store.DB().ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES (?, 'synthetic', 'done', '{}', '{}', ?, ?)`, id, at, at); err != nil {
			t.Fatal(err)
		}
	}
	count, err := store.PruneTerminalOperations(ctx, base.Add(500*time.Nanosecond))
	if err != nil || count != 1 {
		t.Fatalf("pruned=%d err=%v", count, err)
	}
	var remaining string
	if err := store.DB().QueryRowContext(ctx, `SELECT id FROM operations`).Scan(&remaining); err != nil || remaining != strings.Repeat("b", 64) {
		t.Fatalf("remaining=%q err=%v", remaining, err)
	}
}

func TestPruneTerminalOperationsDoesNotDeleteLaterFractionAtExactSecond(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cutoff := time.Date(2026, 8, 2, 12, 0, 1, 0, time.UTC)
	entries := []struct {
		id string
		at time.Time
	}{
		{strings.Repeat("a", 64), cutoff.Add(-time.Nanosecond)},
		{strings.Repeat("b", 64), cutoff.Add(100 * time.Millisecond)},
		{strings.Repeat("c", 64), cutoff.Add(999 * time.Millisecond)},
	}
	for _, entry := range entries {
		at := formatTimestamp(entry.at)
		if _, err := store.DB().ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES (?, 'synthetic', 'done', '{}', '{}', ?, ?)`, entry.id, at, at); err != nil {
			t.Fatal(err)
		}
	}
	count, err := store.PruneTerminalOperations(ctx, cutoff)
	if err != nil || count != 1 {
		t.Fatalf("pruned=%d err=%v", count, err)
	}
	rows, err := store.DB().QueryContext(ctx, `SELECT id FROM operations ORDER BY updated_at, id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	remaining := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		remaining = append(remaining, id)
	}
	if err := rows.Err(); err != nil || !reflect.DeepEqual(remaining, []string{entries[1].id, entries[2].id}) {
		t.Fatalf("remaining=%q err=%v", remaining, err)
	}
}

func TestFileChangeJSONPreservesZeroByteFileSize(t *testing.T) {
	zeroSHA := strings.Repeat("0", 64)
	data, err := json.Marshal([]FileChange{
		{Operation: "add", Path: "dists/noble/by-hash/empty", Phase: "metadata", Size: 0, SHA256: zeroSHA},
		{Operation: "delete", Path: "dists/noble/obsolete", Phase: "delete"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var wire []map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if size, present := wire[0]["size"]; !present || size != float64(0) {
		t.Fatalf("zero-byte add lost explicit size: %s", data)
	}
	if _, present := wire[1]["size"]; present {
		t.Fatalf("delete unexpectedly claimed a target size: %s", data)
	}
}

func TestPackageObjectReadsRejectCorruptPersistedPoolPath(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AddDist(ctx, Dist{Name: "el9", Format: "rpm", EffectiveConfigSHA256: "cfg", BuiltGeneration: 0, Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}}}); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("7", 64)
	object := PackageObject{SHA256: digest, Format: "rpm", Coordinate: "pkg-0:1-1.x86_64", Architecture: "x86_64", CanonicalArch: "x86_64", PoolPath: "pool/p/pkg/pkg-1-1.x86_64.rpm", Filename: "pkg-1-1.x86_64.rpm", Size: 1, Name: "pkg", Source: "pkg", Version: "1", Release: "1", Kind: "main", Storage: "pending"}
	operationID := strings.Repeat("8", 64)
	if err := store.BeginOperation(ctx, Operation{ID: operationID, Kind: "add", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetOperationState(ctx, operationID, OperationStaged, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyDesiredMutation(ctx, operationID, []PackageObject{object}, map[string][]string{"el9": {digest}}, `{}`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE package_objects SET pool_path = '../escape' WHERE sha256 = ?`, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPackageObject(ctx, digest); err == nil || !strings.Contains(err.Error(), "unsafe pool path") {
		t.Fatalf("GetPackageObject accepted corrupt path: %v", err)
	}
	if _, err := store.ListPackageObjects(ctx, nil, false); err == nil || !strings.Contains(err.Error(), "unsafe pool path") {
		t.Fatalf("ListPackageObjects accepted corrupt path: %v", err)
	}
}

func TestPackageObjectRequiresSourceDerivedPortablePoolPath(t *testing.T) {
	object := PackageObject{
		SHA256: strings.Repeat("7", 64), Format: "rpm", Coordinate: "PolarDB-0:17.9.1.0-1.el10.aarch64",
		Architecture: "aarch64", CanonicalArch: "aarch64", PoolPath: "pool/P/PolarDB/PolarDB-17.9.1.0-1.el10.aarch64.rpm",
		Filename: "PolarDB-17.9.1.0-1.el10.aarch64.rpm", Size: 1, Name: "PolarDB", Source: "PolarDB",
		Version: "17.9.1.0", Release: "1.el10", Kind: "main", Storage: "pending",
	}
	if err := validatePackageObject(object); err == nil || !strings.Contains(err.Error(), "non-canonical pool path") {
		t.Fatalf("case-preserving shard error = %v", err)
	}
	object.PoolPath = "pool/p/PolarDB/PolarDB-17.9.1.0-1.el10.aarch64.rpm"
	if err := validatePackageObject(object); err != nil {
		t.Fatalf("portable pool path rejected: %v", err)
	}
}

func TestApplyDesiredMutationRejectsCaseInsensitivePoolCollision(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AddDist(ctx, Dist{Name: "el9", Format: "rpm", EffectiveConfigSHA256: "cfg", BuiltGeneration: 0, Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}}}); err != nil {
		t.Fatal(err)
	}
	operationID := strings.Repeat("8", 64)
	if err := store.BeginOperation(ctx, Operation{ID: operationID, Kind: "add", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetOperationState(ctx, operationID, OperationStaged, ""); err != nil {
		t.Fatal(err)
	}
	object := func(digit, name, filename string) PackageObject {
		return PackageObject{
			SHA256: strings.Repeat(digit, 64), Format: "rpm", Coordinate: name + "-0:1-1.x86_64",
			Architecture: "x86_64", CanonicalArch: "x86_64", PoolPath: "pool/f/" + name + "/" + filename,
			Filename: filename, Size: 1, Name: name, Source: name, Version: "1", Release: "1", Kind: "main", Storage: "pending",
		}
	}
	upper := object("a", "Foo", "Pkg-1-1.x86_64.rpm")
	lower := object("b", "foo", "pkg-1-1.x86_64.rpm")
	_, err = store.ApplyDesiredMutation(ctx, operationID, []PackageObject{upper, lower}, map[string][]string{"el9": {upper.SHA256, lower.SHA256}}, `{}`)
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "case-insensitively") {
		t.Fatalf("case-insensitive collision error = %v", err)
	}
}

func TestOperationAuditPreservesPerDistPolicyOutcomesWithoutPoolObjects(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, name := range []string{"el9", "el10"} {
		if err := store.AddDist(ctx, Dist{Name: name, Format: "rpm", EffectiveConfigSHA256: "cfg", BuiltGeneration: 0, Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}}}); err != nil {
			t.Fatal(err)
		}
	}
	operationID := strings.Repeat("9", 64)
	if err := store.BeginOperation(ctx, Operation{ID: operationID, Kind: "add", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	excludedSHA := strings.Repeat("a", 64)
	limitedSHA := strings.Repeat("b", 64)
	packages := []OperationPackage{
		{InputPath: "excluded.rpm", PackageSHA256: excludedSHA, Coordinate: "excluded-0:1-1.x86_64", Disposition: "excluded", Message: `{"version":1,"dists":{"fake":"accepted"}}`, Dists: map[string]string{"el9": "excluded"}},
		{InputPath: "limited.rpm", PackageSHA256: limitedSHA, Coordinate: "limited-0:1-1.x86_64", Disposition: "excluded", Dists: map[string]string{"el10": "limited"}},
	}
	if err := store.RecordOperationPackages(ctx, operationID, packages); err != nil {
		t.Fatal(err)
	}
	if err := store.SetOperationState(ctx, operationID, OperationStaged, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyDesiredMutation(ctx, operationID, nil, map[string][]string{"el9": {}, "el10": {}}, `{}`); err != nil {
		t.Fatal(err)
	}
	outcomes := []OperationMembership{
		{DistName: "el10", PackageSHA256: limitedSHA, Action: "limit"},
		{DistName: "el9", PackageSHA256: excludedSHA, Action: "exclude"},
	}
	if err := store.RecordOperationMembershipOutcomes(ctx, operationID, outcomes); err != nil {
		t.Fatal(err)
	}
	detail, err := store.GetOperation(ctx, operationID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(detail.Packages[0].Dists, map[string]string{"el9": "excluded"}) || detail.Packages[0].Message != packages[0].Message {
		t.Fatalf("first package evidence=%#v", detail.Packages[0])
	}
	if !reflect.DeepEqual(detail.Packages[1].Dists, map[string]string{"el10": "limited"}) {
		t.Fatalf("second package evidence=%#v", detail.Packages[1])
	}
	wantMemberships := []OperationMembership{
		{Sequence: 0, DistName: "el10", PackageSHA256: limitedSHA, Action: "limit"},
		{Sequence: 1, DistName: "el9", PackageSHA256: excludedSHA, Action: "exclude"},
	}
	// The canonical audit order is Dist, digest, action, independent of caller
	// order. el10 sorts before el9 lexically.
	if !reflect.DeepEqual(detail.Memberships, wantMemberships) {
		t.Fatalf("membership evidence=%#v want=%#v", detail.Memberships, wantMemberships)
	}
	if err := store.RecordOperationMembershipOutcomes(ctx, operationID, outcomes); err != nil {
		t.Fatalf("idempotent outcome replay: %v", err)
	}
}

func TestOpenExistingForMigrationMigratesKnownV1OnlyAfterReadOnlyProbe(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "repo.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=rwc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schemaV1SQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (1, ?, ?)`, SchemaV1SHA256, "2026-08-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReadOnly(path); !errors.Is(err, ErrSchema) {
		t.Fatalf("OpenReadOnly(v1) error=%v, want ErrSchema", err)
	}
	afterProbe, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(afterProbe, before) {
		t.Fatalf("read-only v1 probe changed database: err=%v", err)
	}

	store, err := OpenExistingForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assertSchemaV2(t, store.DB())
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES (?, 'add', 'done_dirty', '{}', '{}', ?, ?)`, strings.Repeat("c", 64), nowText(), nowText()); err != nil {
		t.Fatalf("v2 operation state unavailable after migration: %v", err)
	}
}

func TestFrozenV6IsReadableButOrdinaryWriterCannotMigrateIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo.db")
	db := createSchemaV5Fixture(t, path)
	if _, err := db.Exec(schemaV6SQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (6, ?, ?)`, SchemaV6SHA256, "2026-08-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExisting(path); !errors.Is(err, ErrSchema) {
		t.Fatalf("ordinary writer error=%v, want ErrSchema", err)
	}
	readOnly, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if readOnly.SchemaVersion() != 6 {
		t.Fatalf("read-only schema=%d, want 6", readOnly.SchemaVersion())
	}
	if _, err := readOnly.Summary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := readOnly.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err := raw.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if version != 6 {
		t.Fatalf("ordinary writer changed schema to %d", version)
	}
	writer, err := OpenExistingForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	if writer.SchemaVersion() != SchemaVersion {
		t.Fatalf("migration writer schema=%d", writer.SchemaVersion())
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGenerationManifestRejectsPackagePayloadUnderDists(t *testing.T) {
	for _, packagePath := range []string{
		"dists/el9/x86_64/pool/p/pkg/pkg-1.x86_64.rpm",
		"dists/el9/x86_64/repodata/hidden.rpm",
		"dists/noble/main/binary-amd64/hidden.deb",
	} {
		manifest := []GenerationFile{{Path: packagePath, Phase: "payload", Size: 1, SHA256: strings.Repeat("a", 64)}}
		if _, _, err := normalizeManifest(manifest); err == nil {
			t.Errorf("normalizeManifest accepted dists payload %q", packagePath)
		}
	}
	manifest := []GenerationFile{{Path: "pool/p/pkg/pkg-1.x86_64.rpm", Phase: "payload", Size: 1, SHA256: strings.Repeat("a", 64)}}
	if _, _, err := normalizeManifest(manifest); err != nil {
		t.Fatalf("normalizeManifest rejected canonical Pool payload: %v", err)
	}
}

func TestOpenExistingForMigrationReanchorsTruncatedV2GenerationLedgerAtomically(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "repo.db")
	firstManifest, _ := createTruncatedV2GenerationLedger(t, path, false)

	store, err := OpenExistingForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateGenerationLedger(ctx); err != nil {
		store.Close()
		t.Fatalf("migrated ledger is invalid: %v", err)
	}
	first, err := store.GetGeneration(ctx, 2)
	if err != nil || first.PreviousGeneration != 0 {
		store.Close()
		t.Fatalf("first retained generation=%#v err=%v", first, err)
	}
	changes, err := store.GenerationChanges(ctx, 2)
	if err != nil || !equalFileChanges(changes, DiffManifests(nil, firstManifest)) {
		store.Close()
		t.Fatalf("rebased baseline=%#v err=%v", changes, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening the migrated database must neither rebase nor rewrite it.
	store, err = OpenExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.ValidateGenerationLedger(ctx); err != nil {
		t.Fatalf("idempotently reopened ledger is invalid: %v", err)
	}
	after, err := store.GenerationChanges(ctx, 2)
	if err != nil || !equalFileChanges(after, changes) {
		t.Fatalf("idempotent reopen changed baseline=%#v err=%v", after, err)
	}
}

func TestOpenExistingRejectsCorruptTruncatedV2GenerationLedgerWithoutMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo.db")
	createTruncatedV2GenerationLedger(t, path, true)
	if _, err := OpenExistingForMigration(path); !errors.Is(err, ErrSchema) {
		t.Fatalf("OpenExisting(corrupt v2 ledger) error=%v, want ErrSchema", err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	var predecessor int64
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT previous_generation FROM generations WHERE generation = 2`).Scan(&predecessor); err != nil {
		t.Fatal(err)
	}
	if version != 2 || predecessor != 1 {
		t.Fatalf("failed migration was not atomic: version=%d predecessor=%d", version, predecessor)
	}
}

func createTruncatedV2GenerationLedger(t *testing.T, databasePath string, corruptLaterChanges bool) ([]GenerationFile, []GenerationFile) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(databasePath)+"?mode=rwc")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schemaV1SQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schemaV2SQL); err != nil {
		t.Fatal(err)
	}
	for _, migration := range []struct {
		version  int
		checksum string
	}{{1, SchemaV1SHA256}, {2, SchemaV2SHA256}} {
		if _, err := db.Exec(`INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (?, ?, '2026-08-01T00:00:00Z')`, migration.version, migration.checksum); err != nil {
			t.Fatal(err)
		}
	}
	first := []GenerationFile{
		{Path: "dists/noble/Release", Phase: "pointer", Size: 2, SHA256: strings.Repeat("2", 64)},
		{Path: "pool/p/pkg/pkg_1_amd64.deb", Phase: "payload", Size: 1, SHA256: strings.Repeat("1", 64)},
	}
	second := []GenerationFile{
		{Path: "dists/noble/Packages", Phase: "metadata", Size: 3, SHA256: strings.Repeat("3", 64)},
		{Path: "dists/noble/Release", Phase: "pointer", Size: 4, SHA256: strings.Repeat("4", 64)},
		{Path: "pool/p/pkg/pkg_1_amd64.deb", Phase: "payload", Size: 1, SHA256: strings.Repeat("1", 64)},
	}
	first, firstSHA, err := normalizeManifest(first)
	if err != nil {
		t.Fatal(err)
	}
	second, secondSHA, err := normalizeManifest(second)
	if err != nil {
		t.Fatal(err)
	}
	firstID, secondID := strings.Repeat("2", 64), strings.Repeat("3", 64)
	for _, operationID := range []string{firstID, secondID} {
		if _, err := db.Exec(`INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES (?, 'build', 'done', '{}', '{}', '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z')`, operationID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO generations(generation, previous_generation, operation_id, manifest_sha256, created_at) VALUES (2, 1, ?, ?, '2026-08-01T00:00:00Z'), (3, 2, ?, ?, '2026-08-01T00:00:01Z')`, firstID, firstSHA, secondID, secondSHA); err != nil {
		t.Fatal(err)
	}
	insertManifest := func(generation int64, manifest []GenerationFile) {
		for _, file := range manifest {
			if _, err := db.Exec(`INSERT INTO generation_files(generation, path, phase, size, sha256) VALUES (?, ?, ?, ?, ?)`, generation, file.Path, file.Phase, file.Size, file.SHA256); err != nil {
				t.Fatal(err)
			}
		}
	}
	insertChanges := func(operationID string, changes []FileChange) {
		for sequence, change := range changes {
			var size, digest any
			if change.Operation != "delete" {
				size, digest = change.Size, change.SHA256
			}
			if _, err := db.Exec(`INSERT INTO operation_files(operation_id, sequence, action, phase, path, size, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)`, operationID, sequence, change.Operation, change.Phase, change.Path, size, digest); err != nil {
				t.Fatal(err)
			}
		}
	}
	insertManifest(2, first)
	insertManifest(3, second)
	// The first delta refers to omitted Generation 1, so only its target-side
	// update can be proven. Migration replaces it with a complete baseline.
	insertChanges(firstID, []FileChange{{Operation: "update", Path: "dists/noble/Release", Phase: "pointer", Size: 2, SHA256: strings.Repeat("2", 64)}})
	secondChanges := DiffManifests(first, second)
	if corruptLaterChanges {
		secondChanges[0].SHA256 = strings.Repeat("f", 64)
	}
	insertChanges(secondID, secondChanges)
	if _, err := db.Exec(`UPDATE repository_state SET built_generation = 3`); err != nil {
		t.Fatal(err)
	}
	return first, second
}

func TestOpenExistingRejectsUnknownV1WithoutMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=rwc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schemaV1SQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (1, 'wrong', '2026-08-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExisting(path); !errors.Is(err, ErrSchema) {
		t.Fatalf("OpenExisting(unknown v1) error=%v, want ErrSchema", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("rejected v1 changed database: err=%v", err)
	}
}

func TestOpenRejectsFutureAndChecksumMismatch(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*sql.DB) error
	}{
		{name: "future", mutate: func(db *sql.DB) error {
			_, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, SchemaVersion+1))
			return err
		}},
		{name: "checksum", mutate: func(db *sql.DB) error {
			_, err := db.Exec(`UPDATE schema_migrations SET checksum = 'wrong' WHERE version = 1`)
			return err
		}},
		{name: "extra migration ledger row", mutate: func(db *sql.DB) error {
			_, err := db.Exec(`INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (?, 'unknown', '2026-08-01T00:00:00Z')`, SchemaVersion+1)
			return err
		}},
		{name: "missing declared index", mutate: func(db *sql.DB) error {
			_, err := db.Exec(`DROP INDEX operations_active_idx`)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "repo.db")
			store, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.mutate(store.DB()); err != nil {
				t.Fatal(err)
			}
			store.Close()
			if _, err := Open(path); !errors.Is(err, ErrSchema) {
				t.Fatalf("Open() error=%v, want ErrSchema", err)
			}
		})
	}
}

func TestReadOnlyOpenDoesNotCreateOrMigrate(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.db")
	if _, err := OpenReadOnly(missing); err == nil {
		t.Fatal("read-only open created a missing database")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing database changed: %v", err)
	}
}

func TestDatabaseOpenRejectsSymlink(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target.db")
	store, err := Open(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "repo.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExisting(link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("database symlink open error = %v", err)
	}
	if _, err := openDatabaseMode(link, "rw", true, false); err == nil {
		t.Fatal("low-level database open followed a symlink")
	}
}

func TestOpenReadOnlyLeavesSettledDatabaseTreeUnchanged(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "repo.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(path + suffix)
		if err != nil {
			t.Fatalf("read persistent database file %s: %v", suffix, err)
		}
		before[suffix] = data
	}
	if info, err := os.Lstat(path + "-shm"); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 {
		t.Fatalf("writer did not retain a usable SQLite shared-memory sidecar: info=%v err=%v", info, err)
	}
	reader, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Summary(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.DB().ExecContext(ctx, `UPDATE repository_state SET desired_revision = 1 WHERE singleton = 1`); err == nil {
		t.Fatal("read-only connection accepted a mutation")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	for suffix, want := range before {
		after, err := os.ReadFile(path + suffix)
		if err != nil || !reflect.DeepEqual(after, want) {
			t.Fatalf("read-only open changed persistent database file %s: err=%v", suffix, err)
		}
	}
	if _, err := os.Lstat(path + "-journal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only open created rollback journal: %v", err)
	}
}

func TestReadOnlyRequiresLifecycleFenceOnlyForSettledLegacyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	needsFence, err := ReadOnlyRequiresLifecycleFence(path)
	if err != nil || needsFence {
		t.Fatalf("current persistent-WAL database needsFence=%t err=%v", needsFence, err)
	}
	if err := os.Remove(path + "-wal"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + "-shm"); err != nil {
		t.Fatal(err)
	}
	needsFence, err = ReadOnlyRequiresLifecycleFence(path)
	if err != nil || !needsFence {
		t.Fatalf("sidecar-free legacy database needsFence=%t err=%v", needsFence, err)
	}
	if err := os.WriteFile(path+"-wal", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	needsFence, err = ReadOnlyRequiresLifecycleFence(path)
	if err != nil || !needsFence {
		t.Fatalf("zero-WAL legacy database needsFence=%t err=%v", needsFence, err)
	}
}

func TestCheckpointAcceptsReaderBlockedTruncateAfterAllFramesCopied(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "repo.db")
	writer, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.DB().ExecContext(ctx, `UPDATE repository_state SET desired_revision = desired_revision + 1 WHERE singleton = 1`); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	readTx, err := reader.DB().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer readTx.Rollback()
	var revision int64
	if err := readTx.QueryRowContext(ctx, `SELECT desired_revision FROM repository_state WHERE singleton = 1`).Scan(&revision); err != nil || revision != 1 {
		t.Fatalf("reader did not pin committed WAL state: revision=%d err=%v", revision, err)
	}
	if err := writer.Checkpoint(ctx); err != nil {
		t.Fatalf("reader-blocked WAL truncate was reported as a committed mutation failure: %v", err)
	}
}

func TestOpenReadOnlySeesCommittedOperationInHotWAL(t *testing.T) {
	const helper = "SOW_STATE_HOT_WAL_HELPER"
	const pathEnv = "SOW_STATE_HOT_WAL_PATH"
	const id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ctx := context.Background()
	if os.Getenv(helper) == "1" {
		writer, err := OpenExisting(os.Getenv(pathEnv))
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Checkpoint(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.DB().ExecContext(ctx, `PRAGMA wal_autocheckpoint = 0`); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.DB().ExecContext(ctx, `
INSERT INTO operations(id, kind, state, payload_json, error_class, created_at, updated_at)
VALUES (?, 'dist.new', 'planned', '{}', NULL, '2026-08-01T00:00:00.000000000Z', '2026-08-01T00:00:00.000000000Z')`, id); err != nil {
			t.Fatal(err)
		}
		// os.Exit deliberately bypasses database/sql Close and all deferred
		// cleanup, reproducing termination after COMMIT and before Checkpoint.
		os.Exit(0)
	}

	path := filepath.Join(t.TempDir(), "repo.db")
	writer, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestOpenReadOnlySeesCommittedOperationInHotWAL$")
	cmd.Env = append(os.Environ(), helper+"=1", pathEnv+"="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hot-WAL helper: %v\n%s", err, output)
	}
	walInfo, err := os.Stat(path + "-wal")
	if err != nil || walInfo.Size() == 0 {
		t.Fatalf("committed operation did not remain in WAL: info=%v err=%v", walInfo, err)
	}

	reader, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := reader.PendingOperations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ID != id || pending[0].State != OperationPlanned {
		t.Fatalf("read-only hot-WAL operations = %#v", pending)
	}
	if _, err := reader.DB().ExecContext(ctx, `DELETE FROM operations WHERE id = ?`, id); err == nil {
		t.Fatal("read-only hot-WAL connection accepted a mutation")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}

	// A hot WAL without -shm is a valid crash artifact, but SQLite would
	// recreate the sidecar on an otherwise read-only open. Refuse that read
	// without touching the Workspace; the next lifecycle write owns recovery.
	if err := os.Remove(path + "-shm"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReadOnly(path); !errors.Is(err, ErrSchema) {
		t.Fatalf("read-only open without hot-WAL shm = %v", err)
	}
	if _, err := os.Lstat(path + "-shm"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed read-only open recreated shm: %v", err)
	}
	writer, err = OpenExisting(path)
	if err != nil {
		t.Fatalf("authorized writable recovery could not recreate hot-WAL shm: %v", err)
	}
	pending, err = writer.PendingOperations(ctx)
	if err != nil || len(pending) != 1 || pending[0].ID != id {
		t.Fatalf("writable recovery lost hot-WAL operation: pending=%#v err=%v", pending, err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDistLifecycleAndArchitectureReferences(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	dist := Dist{Name: "el9", Format: "rpm", EffectiveConfigSHA256: "abc", BuiltGeneration: 1, Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}, {Family: "aarch64", EcosystemArch: "aarch64"}}, EffectiveSigningJSON: "{}"}
	if err := store.AddDist(ctx, dist); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetDist(ctx, "el9")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, dist) {
		t.Fatalf("GetDist()=%#v want=%#v", got, dist)
	}
	refs, err := store.ReferencedArchitectures(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(refs, []string{"x86_64", "aarch64"}) {
		t.Fatalf("ReferencedArchitectures()=%v", refs)
	}
	if err := store.RemoveDist(ctx, "el9"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetDist(ctx, "el9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetDist after remove=%v", err)
	}
}

func TestOperationJournalTransitionsAndPending(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.BeginOperation(ctx, Operation{ID: "../escape", Kind: "dist.new", State: OperationPlanned, PayloadJSON: `{}`}); err == nil {
		t.Fatal("unsafe operation id accepted")
	}

	op := Operation{ID: strings.Repeat("0", 64), Kind: "dist.new", State: OperationPlanned, PayloadJSON: `{"name":"el9"}`}
	if err := store.BeginOperation(ctx, op); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateOperationPayload(ctx, op.ID, `{"name":"el9","tree":"abc"}`); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PendingOperations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ID != op.ID || pending[0].State != OperationPlanned {
		t.Fatalf("pending=%#v", pending)
	}
	for _, next := range []OperationState{OperationStaged, OperationApplied, OperationBuilt, OperationDone} {
		if err := store.SetOperationState(ctx, op.ID, next, ""); err != nil {
			t.Fatalf("transition to %s: %v", next, err)
		}
	}
	if err := store.UpdateOperationPayload(ctx, op.ID, `{}`); !errors.Is(err, ErrTransition) {
		t.Fatalf("terminal payload update=%v", err)
	}
	pending, err = store.PendingOperations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("terminal operation remained pending: %#v", pending)
	}
	if err := store.SetOperationState(ctx, op.ID, OperationStaged, ""); !errors.Is(err, ErrTransition) {
		t.Fatalf("terminal regression error=%v, want ErrTransition", err)
	}
}

func TestOperationPayloadWireLimit(t *testing.T) {
	atLimit := `"` + strings.Repeat("x", MaxOperationPayloadBytes-2) + `"`
	if len(atLimit) != MaxOperationPayloadBytes {
		t.Fatalf("at-limit fixture length = %d", len(atLimit))
	}
	if err := validateOperationPayload(atLimit); err != nil {
		t.Fatalf("payload at limit rejected: %v", err)
	}
	overLimit := `"` + strings.Repeat("x", MaxOperationPayloadBytes-1) + `"`
	if err := validateOperationPayload(overLimit); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("payload over limit error = %v", err)
	}
}

func TestFinalizeDistOperationsAreAtomicAndIdempotent(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	dist := Dist{Name: "noble", Format: "deb", EffectiveConfigSHA256: "cfg", BuiltGeneration: 1, Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "amd64"}}}
	addID := strings.Repeat("a", 64)
	if err := store.BeginOperation(ctx, Operation{ID: addID, Kind: "dist.new", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	for _, next := range []OperationState{OperationStaged, OperationApplied, OperationBuilt} {
		if err := store.SetOperationState(ctx, addID, next, ""); err != nil {
			t.Fatal(err)
		}
	}
	firstManifest := []GenerationFile{{Path: "dists/noble/Release", Phase: "pointer", Size: 1, SHA256: strings.Repeat("1", 64)}}
	firstChanges := DiffManifests(nil, firstManifest)
	if err := store.FinalizeDistAdd(ctx, addID, dist, firstManifest, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("mismatched generation changes error=%v, want ErrConflict", err)
	}
	if summary, err := store.Summary(ctx); err != nil || summary.BuiltGeneration != 0 || summary.DistCount != 0 {
		t.Fatalf("failed finalization mutated summary=%#v err=%v", summary, err)
	}
	if operation, err := store.GetOperation(ctx, addID); err != nil || operation.Operation.State != OperationBuilt {
		t.Fatalf("failed finalization mutated operation=%#v err=%v", operation, err)
	}
	if err := store.FinalizeDistAdd(ctx, addID, dist, firstManifest, firstChanges); err != nil {
		t.Fatal(err)
	}
	if err := store.FinalizeDistAdd(ctx, addID, dist, firstManifest, firstChanges); err != nil {
		t.Fatalf("idempotent add finalization: %v", err)
	}
	if _, err := store.GetDist(ctx, "noble"); err != nil {
		t.Fatal(err)
	}
	rmID := strings.Repeat("b", 64)
	if err := store.BeginOperation(ctx, Operation{ID: rmID, Kind: "dist.rm", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	for _, next := range []OperationState{OperationStaged, OperationApplied, OperationBuilt} {
		if err := store.SetOperationState(ctx, rmID, next, ""); err != nil {
			t.Fatal(err)
		}
	}
	secondManifest := []GenerationFile{}
	secondChanges := DiffManifests(firstManifest, secondManifest)
	if err := store.FinalizeDistRemoval(ctx, rmID, "noble", 2, secondManifest, secondChanges); err != nil {
		t.Fatal(err)
	}
	if err := store.FinalizeDistRemoval(ctx, rmID, "noble", 2, secondManifest, secondChanges); err != nil {
		t.Fatalf("idempotent removal finalization: %v", err)
	}
	if _, err := store.GetDist(ctx, "noble"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed dist still exists: %v", err)
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.BuiltGeneration != 2 || summary.PackageCount != 0 {
		t.Fatalf("summary=%#v", summary)
	}
	if err := store.ValidateGenerationLedger(ctx); err != nil {
		t.Fatalf("valid generation ledger: %v", err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE operation_files SET action = 'update' WHERE operation_id = ? AND action = 'delete'`, rmID); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateGenerationLedger(ctx); !errors.Is(err, ErrConflict) {
		t.Fatalf("tampered generation ledger error=%v, want ErrConflict", err)
	}
}

func TestOpenExistingNeverCreatesMissingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	if _, err := OpenExisting(path); err == nil {
		t.Fatal("OpenExisting created a missing database")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing database was created: %v", err)
	}
}

func TestOpenExistingRejectsUninitializedDatabaseWithoutMutation(t *testing.T) {
	for _, kind := range []string{"zero", "sqlite-v0"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "repo.db")
			if kind == "zero" {
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=rwc")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`PRAGMA user_version = 0`); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OpenExisting(path); err == nil {
				t.Fatal("OpenExisting accepted an uninitialized database")
			}
			after, err := os.ReadFile(path)
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatalf("invalid database changed: before=%x after=%x err=%v", before, after, err)
			}
			for _, suffix := range []string{"-wal", "-shm", "-journal"} {
				if _, err := os.Lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("invalid database acquired sidecar %s: %v", suffix, err)
				}
			}
		})
	}
}

func TestOpenInitializingResumesEmptyV0AndAcceptsCurrentOnly(t *testing.T) {
	for _, kind := range []string{"zero", "sqlite-v0", "current"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "repo.db")
			switch kind {
			case "zero":
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "sqlite-v0":
				db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=rwc")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`VACUUM`); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			case "current":
				store, err := Open(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			}

			store, err := OpenInitializing(path)
			if err != nil {
				t.Fatalf("OpenInitializing: %v", err)
			}
			assertSchemaV2(t, store.DB())
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			readOnly, err := OpenReadOnly(path)
			if err != nil {
				t.Fatalf("migrated database is not readable: %v", err)
			}
			if err := readOnly.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOpenInitializingRejectsKnownPredecessorSchemaWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=rwc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schemaV1SQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (1, ?, ?)`, SchemaV1SHA256, "2026-08-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenInitializing(path); !errors.Is(err, ErrSchema) {
		t.Fatalf("OpenInitializing(v1) error=%v, want ErrSchema", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("rejected predecessor changed: err=%v", err)
	}
}

func TestOpenInitializingRejectsMissingNonemptyUnknownAndCorruptWithoutMutation(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.db")
		if _, err := OpenInitializing(path); err == nil {
			t.Fatal("OpenInitializing created a missing database")
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing database was created: %v", err)
		}
	})

	for _, kind := range []string{"nonempty-v0", "future", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "repo.db")
			switch kind {
			case "nonempty-v0":
				db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=rwc")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`CREATE TABLE foreign_state(value TEXT)`); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			case "future":
				store, err := Open(path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.DB().Exec(fmt.Sprintf(`PRAGMA user_version = %d`, SchemaVersion+1)); err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte("not a sqlite database"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			beforeWAL, beforeWALErr := os.ReadFile(path + "-wal")
			if beforeWALErr != nil && !errors.Is(beforeWALErr, os.ErrNotExist) {
				t.Fatal(beforeWALErr)
			}
			beforeWALMissing := errors.Is(beforeWALErr, os.ErrNotExist)
			if _, err := OpenInitializing(path); !errors.Is(err, ErrSchema) {
				t.Fatalf("OpenInitializing error=%v, want ErrSchema", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatalf("rejected database changed: before=%x after=%x err=%v", before, after, err)
			}
			afterWAL, afterWALErr := os.ReadFile(path + "-wal")
			if errors.Is(afterWALErr, os.ErrNotExist) != beforeWALMissing || (!beforeWALMissing && (afterWALErr != nil || !reflect.DeepEqual(afterWAL, beforeWAL))) {
				t.Fatalf("rejected database changed persistent WAL: beforeErr=%v afterErr=%v", beforeWALErr, afterWALErr)
			}
			if !beforeWALMissing {
				if info, err := os.Lstat(path + "-shm"); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
					t.Fatalf("rejected current database lost safe persistent shared memory: info=%v err=%v", info, err)
				}
			} else if _, err := os.Lstat(path + "-shm"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected legacy database acquired shared memory: %v", err)
			}
			if _, err := os.Lstat(path + "-journal"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected database acquired rollback journal: %v", err)
			}
		})
	}
}

func TestDatabaseOpenRejectsUnsafeSQLiteSidecars(t *testing.T) {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		for _, open := range []struct {
			name string
			fn   func(string) (*Store, error)
		}{{"writable", OpenExisting}, {"initializing", OpenInitializing}, {"read-only", OpenReadOnly}} {
			t.Run(suffix+"/"+open.name, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, "repo.db")
				store, err := Open(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				sentinel := filepath.Join(root, "outside")
				if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(sentinel, path+suffix); err != nil {
					t.Fatal(err)
				}
				if _, err := open.fn(path); err == nil {
					t.Fatal("unsafe SQLite sidecar was accepted")
				}
				if data, err := os.ReadFile(sentinel); err != nil || string(data) != "unchanged" {
					t.Fatalf("sidecar target changed: %q err=%v", data, err)
				}
			})
		}
	}
}

func TestRepositorySummaryAndCounts(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	summary, err := store.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.DesiredRevision != 0 || summary.BuiltGeneration != 0 || summary.Status != "clean" || summary.DistCount != 0 || summary.PackageCount != 0 || summary.MembershipCount != 0 {
		t.Fatalf("new repository summary=%#v", summary)
	}
}

func TestApplyDesiredMutationUsesWholeSetsAndDropsUnreferencedPending(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AddDist(ctx, Dist{Name: "el9", Format: "rpm", EffectiveConfigSHA256: "cfg", BuiltGeneration: 1, Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}}}); err != nil {
		t.Fatal(err)
	}
	object := PackageObject{
		SHA256: strings.Repeat("1", 64), Format: "rpm", Coordinate: "pkg-0:1.0-1.x86_64",
		Architecture: "x86_64", CanonicalArch: "x86_64", PoolPath: "pool/p/pkg/pkg-1.0-1.x86_64.rpm",
		Filename: "pkg-1.0-1.x86_64.rpm", Size: 7, Name: "pkg", Source: "pkg", Version: "1.0",
		Epoch: "0", Release: "1", Kind: "main", PayloadSHA256: strings.Repeat("2", 64), Storage: "pending",
	}
	addID := strings.Repeat("d", 64)
	if err := store.BeginOperation(ctx, Operation{ID: addID, Kind: "add", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetOperationState(ctx, addID, OperationStaged, ""); err != nil {
		t.Fatal(err)
	}
	result, err := store.ApplyDesiredMutation(ctx, addID, []PackageObject{object}, map[string][]string{"el9": {object.SHA256, object.SHA256}}, `{"accepted":1}`)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Revision != 1 || !reflect.DeepEqual(result.ChangedDists, []string{"el9"}) {
		t.Fatalf("add result=%#v", result)
	}
	objects, err := store.ListPackageObjects(ctx, []string{"el9"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || !reflect.DeepEqual(objects[0].Dists, []string{"el9"}) || len(objects[0].BuiltDists) != 0 {
		t.Fatalf("desired objects=%#v", objects)
	}

	rmID := strings.Repeat("e", 64)
	if err := store.BeginOperation(ctx, Operation{ID: rmID, Kind: "rm", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetOperationState(ctx, rmID, OperationStaged, ""); err != nil {
		t.Fatal(err)
	}
	result, err = store.ApplyDesiredMutation(ctx, rmID, nil, map[string][]string{"el9": {}}, `{"removed":1}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.DroppedPending) != 1 || result.DroppedPending[0].SHA256 != object.SHA256 {
		t.Fatalf("dropped pending=%#v", result.DroppedPending)
	}
	if _, err := store.GetPackageObject(ctx, object.SHA256); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unreferenced pending object remains: %v", err)
	}
	summary, err := store.Summary(ctx)
	if err != nil || summary.Status != "clean" || summary.DirtyReason != "" {
		t.Fatalf("reverted Desired set did not return to clean Built projection: summary=%#v err=%v", summary, err)
	}
}

func TestApplyDesiredMutationRejectsCoordinateConflictAtomically(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AddDist(ctx, Dist{Name: "noble", Format: "deb", EffectiveConfigSHA256: "cfg", BuiltGeneration: 1, Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "amd64"}}}); err != nil {
		t.Fatal(err)
	}
	makeObject := func(digit string) PackageObject {
		return PackageObject{SHA256: strings.Repeat(digit, 64), Format: "deb", Coordinate: "pkg=1.0:amd64", Architecture: "amd64", CanonicalArch: "x86_64", PoolPath: "pool/p/pkg/pkg_1.0_amd64.deb", Filename: "pkg_1.0_amd64.deb", Size: 5, Name: "pkg", Source: "pkg", Version: "1.0", Kind: "main", Storage: "pending"}
	}
	first := makeObject("3")
	firstID := strings.Repeat("f", 64)
	if err := store.BeginOperation(ctx, Operation{ID: firstID, Kind: "add", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetOperationState(ctx, firstID, OperationStaged, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyDesiredMutation(ctx, firstID, []PackageObject{first}, map[string][]string{"noble": {first.SHA256}}, `{}`); err != nil {
		t.Fatal(err)
	}
	second := makeObject("4")
	secondID := strings.Repeat("9", 64)
	if err := store.BeginOperation(ctx, Operation{ID: secondID, Kind: "add", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetOperationState(ctx, secondID, OperationStaged, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyDesiredMutation(ctx, secondID, []PackageObject{second}, map[string][]string{"noble": {second.SHA256}}, `{}`); !errors.Is(err, ErrConflict) {
		t.Fatalf("coordinate conflict error=%v", err)
	}
	objects, err := store.ListPackageObjects(ctx, []string{"noble"}, false)
	if err != nil || len(objects) != 1 || objects[0].SHA256 != first.SHA256 {
		t.Fatalf("conflict changed desired state: objects=%#v err=%v", objects, err)
	}
}

func assertSchemaV2(t *testing.T, db *sql.DB) {
	t.Helper()
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != SchemaVersion {
		t.Fatalf("user_version=%d want=%d", version, SchemaVersion)
	}
	var migrationCount int
	if err := db.QueryRow(`SELECT count(*) FROM schema_migrations WHERE (version = 1 AND checksum = ?) OR (version = 2 AND checksum = ?) OR (version = 3 AND checksum = ?) OR (version = 4 AND checksum = ?) OR (version = 5 AND checksum = ?) OR (version = 6 AND checksum = ?) OR (version = 7 AND checksum = ?) OR (version = 8 AND checksum = ?) OR (version = 9 AND checksum = ?)`, SchemaV1SHA256, SchemaV2SHA256, SchemaV3SHA256, SchemaV4SHA256, SchemaV5SHA256, SchemaV6SHA256, SchemaV7SHA256, SchemaV8SHA256, SchemaV9SHA256).Scan(&migrationCount); err != nil {
		t.Fatal(err)
	}
	if migrationCount != SchemaVersion {
		t.Fatalf("schema migration count=%d", migrationCount)
	}
	var foreignKeys int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys=%d", foreignKeys)
	}
}

func assertMembershipReverseIndexes(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, test := range []struct {
		table string
		index string
	}{
		{"memberships", "memberships_package_sha256_idx"},
		{"built_memberships", "built_memberships_package_sha256_idx"},
		{"prior_built_memberships", "prior_built_memberships_package_sha256_idx"},
	} {
		rows, err := db.Query(`EXPLAIN QUERY PLAN SELECT dist_name FROM `+test.table+` WHERE package_sha256 = ?`, strings.Repeat("a", 64))
		if err != nil {
			t.Fatalf("explain reverse lookup on %s: %v", test.table, err)
		}
		used := false
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			used = used || strings.Contains(detail, test.index)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			t.Fatal(err)
		}
		if !used {
			t.Errorf("reverse lookup on %s did not use %s", test.table, test.index)
		}
	}
}
