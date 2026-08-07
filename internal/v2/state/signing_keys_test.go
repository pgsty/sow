package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestRetainedRPMSigningCertificateVersionsCoexist(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "repo.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("A", 40)
	first := RPMSigningKey{Fingerprint: fingerprint, PublicKey: []byte("first public certificate version")}
	second := RPMSigningKey{Fingerprint: fingerprint, PublicKey: []byte("second public certificate version")}
	if err := store.RetainRPMSigningKeys(ctx, []RPMSigningKey{second, first, first}); err != nil {
		t.Fatal(err)
	}
	keys, err := store.ListRPMSigningKeys(ctx)
	if err != nil || len(keys) != 2 {
		t.Fatalf("retained keys=%#v err=%v", keys, err)
	}
	if keys[0].Fingerprint != fingerprint || keys[1].Fingerprint != fingerprint || keys[0].SnapshotSHA256 == keys[1].SnapshotSHA256 {
		t.Fatalf("certificate versions did not retain distinct exact identities: %#v", keys)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopenedKeys, err := reopened.ListRPMSigningKeys(ctx)
	if err != nil || !reflect.DeepEqual(keys, reopenedKeys) {
		t.Fatalf("reopened keys=%#v want=%#v err=%v", reopenedKeys, keys, err)
	}
	bad := first
	bad.SnapshotSHA256 = strings.Repeat("0", 64)
	if err := reopened.RetainRPMSigningKeys(ctx, []RPMSigningKey{bad}); err == nil {
		t.Fatal("certificate bytes were accepted under a false snapshot digest")
	}
}

func TestRPMSigningCertificateRetentionSharesMutationTransaction(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AddDist(ctx, Dist{Name: "el9", Format: "rpm", EffectiveConfigSHA256: "cfg", Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}}}); err != nil {
		t.Fatal(err)
	}
	begin := func(id string) {
		t.Helper()
		if err := store.BeginOperation(ctx, Operation{ID: id, Kind: "add", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
			t.Fatal(err)
		}
		if err := store.SetOperationState(ctx, id, OperationStaged, ""); err != nil {
			t.Fatal(err)
		}
	}
	committed := RPMSigningKey{Fingerprint: strings.Repeat("A", 40), PublicKey: []byte("committed public certificate")}
	begin(strings.Repeat("1", 64))
	if _, err := store.ApplyDesiredMutationWithSigningKeys(ctx, strings.Repeat("1", 64), nil, []RPMSigningKey{committed}, map[string][]string{"el9": {}}, `{}`); err != nil {
		t.Fatal(err)
	}
	keys, err := store.ListRPMSigningKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].Fingerprint != committed.Fingerprint {
		t.Fatalf("committed keys=%#v err=%v", keys, err)
	}

	rolledBack := RPMSigningKey{Fingerprint: strings.Repeat("B", 40), PublicKey: []byte("rolled back public certificate")}
	begin(strings.Repeat("2", 64))
	missing := strings.Repeat("f", 64)
	if _, err := store.ApplyDesiredMutationWithSigningKeys(ctx, strings.Repeat("2", 64), nil, []RPMSigningKey{rolledBack}, map[string][]string{"el9": {missing}}, `{}`); err == nil {
		t.Fatal("invalid Desired mutation unexpectedly committed")
	}
	keys, err = store.ListRPMSigningKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].Fingerprint != committed.Fingerprint {
		t.Fatalf("failed mutation retained certificate: keys=%#v err=%v", keys, err)
	}
}

func TestV5MigrationFreezesExactRPMSigningCertificateSnapshots(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "repo.db")
	db := createSchemaV5Fixture(t, path)
	currentFingerprint := strings.Repeat("A", 40)
	trustedFingerprint := strings.Repeat("B", 40)
	currentCertificate := []byte("current certificate snapshot")
	trustedCertificate := []byte("trusted certificate snapshot")
	for _, key := range []struct {
		fingerprint string
		certificate []byte
	}{{currentFingerprint, currentCertificate}, {trustedFingerprint, trustedCertificate}} {
		if _, err := db.Exec(`INSERT INTO rpm_signing_keys(fingerprint, public_key) VALUES (?, ?)`, key.fingerprint, key.certificate); err != nil {
			t.Fatal(err)
		}
	}
	frozen := `{"rpm":{"packages":{"mode":"fill","key":"file://current.asc","key_fingerprint":"` + currentFingerprint + `","trusted_keys":["file://trusted.asc"],"trusted_key_fingerprints":["` + currentFingerprint + `","` + trustedFingerprint + `"]}}}`
	insertV5Dist(t, db, "el9", frozen)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := OpenExistingForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	dist, err := store.GetDist(ctx, "el9")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(dist.EffectiveSigningJSON), &document); err != nil {
		t.Fatal(err)
	}
	packages := document["rpm"].(map[string]any)["packages"].(map[string]any)
	currentSHA := shaText(currentCertificate)
	trustedSHA := shaText(trustedCertificate)
	if packages["key_snapshot_sha256"] != currentSHA {
		t.Fatalf("current snapshot=%v want=%s", packages["key_snapshot_sha256"], currentSHA)
	}
	wantTrustedStrings := []string{currentSHA, trustedSHA}
	sort.Strings(wantTrustedStrings)
	wantTrusted := []any{wantTrustedStrings[0], wantTrustedStrings[1]}
	if !reflect.DeepEqual(packages["trusted_key_snapshot_sha256s"], wantTrusted) {
		t.Fatalf("trusted snapshots=%#v want=%#v", packages["trusted_key_snapshot_sha256s"], wantTrusted)
	}
	keys, err := store.ListRPMSigningKeys(ctx)
	if err != nil || len(keys) != 2 {
		t.Fatalf("migrated keys=%#v err=%v", keys, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	readOnly, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("v6 exact schema did not reopen read-only: %v", err)
	}
	if err := readOnly.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestV5MigrationAcceptsUnsignedSnapshotsAndRejectsMissingActiveCertificateAtomically(t *testing.T) {
	for _, frozen := range []string{`{}`, `{"rpm":{"packages":{"mode":"never","key":"file://dormant.asc"}}}`} {
		t.Run(frozen, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "repo.db")
			db := createSchemaV5Fixture(t, path)
			insertV5Dist(t, db, "el9", frozen)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			store, err := OpenExistingForMigration(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}

	path := filepath.Join(t.TempDir(), "repo.db")
	db := createSchemaV5Fixture(t, path)
	fingerprint := strings.Repeat("C", 40)
	insertV5Dist(t, db, "el9", `{"rpm":{"packages":{"mode":"always","key":"file://missing.asc","key_fingerprint":"`+fingerprint+`","trusted_key_fingerprints":["`+fingerprint+`"]}}}`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExistingForMigration(path); err == nil {
		t.Fatal("v5 active signing policy without retained certificate migrated")
	}
	raw, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var version int
	if err := raw.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 5 {
		t.Fatalf("failed migration was not atomic: version=%d err=%v", version, err)
	}
	var v6Rows int
	if err := raw.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version = 6`).Scan(&v6Rows); err != nil || v6Rows != 0 {
		t.Fatalf("failed migration left v6 ledger state: count=%d err=%v", v6Rows, err)
	}
}

func createSchemaV5Fixture(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=rwc")
	if err != nil {
		t.Fatal(err)
	}
	for version, migration := range []struct {
		schema   string
		checksum string
	}{{schemaV1SQL, SchemaV1SHA256}, {schemaV2SQL, SchemaV2SHA256}, {schemaV3SQL, SchemaV3SHA256}, {schemaV4SQL, SchemaV4SHA256}, {schemaV5SQL, SchemaV5SHA256}} {
		if _, err := db.Exec(migration.schema); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (?, ?, ?)`, version+1, migration.checksum, "2026-08-01T00:00:00.000000000Z"); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	return db
}

func insertV5Dist(t *testing.T, db *sql.DB, name, signing string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO dists(name, format, effective_config_sha256, built_generation, desired_revision, built_config_sha256, effective_signing_json) VALUES (?, 'rpm', '', 0, 0, '', ?)`, name, signing); err != nil {
		t.Fatal(err)
	}
}

func shaText(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
