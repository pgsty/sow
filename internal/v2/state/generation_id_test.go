package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerationIDExactWireDomain(t *testing.T) {
	tests := []struct {
		generation GenerationID
		wire       string
	}{
		{0, `"00000000000000000000"`},
		{42, `"00000000000000000042"`},
		{GenerationID(math.MaxUint64), `"18446744073709551615"`},
	}
	for _, test := range tests {
		encoded, err := json.Marshal(test.generation)
		if err != nil || string(encoded) != test.wire {
			t.Fatalf("marshal %d = %s, err=%v", test.generation, encoded, err)
		}
		var decoded GenerationID
		if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != test.generation {
			t.Fatalf("unmarshal %s = %d, err=%v", encoded, decoded, err)
		}
		parsed, err := ParseGenerationID(test.wire[1 : len(test.wire)-1])
		if err != nil || parsed != test.generation {
			t.Fatalf("parse %s = %d, err=%v", test.wire, parsed, err)
		}
	}

	for _, invalid := range []string{
		`0`, `42`, `18446744073709551615`,
		`"0"`, `"0000000000000000000"`, `"000000000000000000000"`,
		`"0000000000000000000a"`, `"18446744073709551616"`,
	} {
		var generation GenerationID
		if err := json.Unmarshal([]byte(invalid), &generation); err == nil {
			t.Fatalf("accepted invalid GenerationID JSON %s", invalid)
		}
	}
	if _, err := MaxGeneration.Next(); err == nil {
		t.Fatal("maximum GenerationID wrapped instead of reporting exhaustion")
	}
}

func TestGenerationIDFullDomainRoundTripsSQLiteText(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.DB().ExecContext(ctx, `UPDATE repository_state SET built_generation = ? WHERE singleton = 1`, MaxGeneration); err != nil {
		t.Fatal(err)
	}
	summary, err := store.Summary(ctx)
	if err != nil || summary.BuiltGeneration != MaxGeneration {
		t.Fatalf("summary=%#v err=%v", summary, err)
	}
	var storageType, stored string
	if err := store.DB().QueryRowContext(ctx, `SELECT typeof(built_generation), built_generation FROM repository_state WHERE singleton = 1`).Scan(&storageType, &stored); err != nil {
		t.Fatal(err)
	}
	if storageType != "text" || stored != "18446744073709551615" {
		t.Fatalf("SQLite GenerationID type=%q value=%q", storageType, stored)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE repository_state SET built_generation = '99999999999999999999' WHERE singleton = 1`); err == nil {
		t.Fatal("SQLite GenerationID domain accepted a value above uint64")
	}
	if _, err := summary.BuiltGeneration.Next(); err == nil {
		t.Fatalf("maximum GenerationID Next error=%v", err)
	}
}

func TestFinalizeGenerationAboveMaxInt64DoesNotMutateDesiredRevision(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	head := GenerationID(math.MaxInt64)
	next, err := head.Next()
	if err != nil || next != GenerationID(uint64(math.MaxInt64)+1) {
		t.Fatalf("next Generation=%s err=%v", next, err)
	}
	const desiredRevision int64 = 7
	if _, err := store.DB().ExecContext(ctx, `UPDATE repository_state SET desired_revision = ?, built_generation = ? WHERE singleton = 1`, desiredRevision, head); err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapLegacyGeneration(ctx, strings.Repeat("8", 64), head, nil); err != nil {
		t.Fatal(err)
	}

	operationID := strings.Repeat("9", 64)
	if err := store.BeginOperation(ctx, Operation{ID: operationID, Kind: "dist.new", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	for _, state := range []OperationState{OperationStaged, OperationApplied, OperationBuilt} {
		if err := store.SetOperationState(ctx, operationID, state, ""); err != nil {
			t.Fatal(err)
		}
	}
	dist := Dist{Name: "noble", Format: "deb", EffectiveConfigSHA256: "cfg", BuiltGeneration: next}
	if err := store.FinalizeDistAdd(ctx, operationID, dist, nil, nil); err != nil {
		t.Fatal(err)
	}

	summary, err := store.Summary(ctx)
	if err != nil || summary.BuiltGeneration != next || summary.DesiredRevision != desiredRevision {
		t.Fatalf("summary=%#v err=%v", summary, err)
	}
	var desiredType, generationType, generationText string
	var storedDesired int64
	if err := store.DB().QueryRowContext(ctx, `SELECT typeof(desired_revision), desired_revision, typeof(built_generation), built_generation FROM repository_state WHERE singleton = 1`).Scan(
		&desiredType, &storedDesired, &generationType, &generationText,
	); err != nil {
		t.Fatal(err)
	}
	if desiredType != "integer" || storedDesired != desiredRevision || generationType != "text" || generationText != next.String() {
		t.Fatalf("stored desired=(%s,%d) generation=(%s,%s)", desiredType, storedDesired, generationType, generationText)
	}
	storedDist, err := store.GetDist(ctx, dist.Name)
	if err != nil || storedDist.BuiltGeneration != next {
		t.Fatalf("stored Dist=%#v err=%v", storedDist, err)
	}
}

func TestLegacyBootstrapBatchesLargeManifestAndChangeset(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const count = sqliteManifestInsertBatchSize*2 + 17
	manifest := make([]GenerationFile, count)
	for index := range manifest {
		manifest[index] = GenerationFile{
			Path: fmt.Sprintf("dists/test/metadata-%04d", index), Phase: "metadata",
			Size: int64(index), SHA256: fmt.Sprintf("%064x", index+1),
		}
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE repository_state SET built_generation = ? WHERE singleton = 1`, GenerationID(1)); err != nil {
		t.Fatal(err)
	}
	operationID := strings.Repeat("a", 64)
	if err := store.BootstrapLegacyGeneration(ctx, operationID, 1, manifest); err != nil {
		t.Fatal(err)
	}
	var files, changes int
	if err := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM generation_files WHERE generation = ?`, GenerationID(1)).Scan(&files); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM operation_files WHERE operation_id = ?`, operationID).Scan(&changes); err != nil {
		t.Fatal(err)
	}
	if files != count || changes != count {
		t.Fatalf("batched files=%d changes=%d want=%d", files, changes, count)
	}
}

func TestLegacyBootstrapAnchorsRPMViewSignerEvidenceAtomically(t *testing.T) {
	ctx := context.Background()
	publicKey := []byte("retained legacy metadata signing key")
	digest := sha256.Sum256(publicKey)
	wantIdentity := hex.EncodeToString(digest[:])
	newStore := func(t *testing.T) *Store {
		t.Helper()
		store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		dist := Dist{
			Name: "el9", Format: "rpm", EffectiveConfigSHA256: "cfg", BuiltGeneration: 1,
			Architectures:             []Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}},
			MetadataSignerFingerprint: strings.Repeat("A", 40),
			MetadataSignerPublicKey:   publicKey,
		}
		if err := store.AddDist(ctx, dist); err != nil {
			store.Close()
			t.Fatal(err)
		}
		return store
	}
	pointer := GenerationFile{Path: "dists/el9/x86_64/repodata/repomd.xml", Phase: "pointer", Size: 1, SHA256: strings.Repeat("1", 64)}
	signature := GenerationFile{Path: "dists/el9/x86_64/repodata/repomd.xml.asc", Phase: "pointer", Size: 1, SHA256: strings.Repeat("2", 64)}

	t.Run("signed identity is retained", func(t *testing.T) {
		store := newStore(t)
		defer store.Close()
		if err := store.BootstrapLegacyGeneration(ctx, strings.Repeat("b", 64), 1, []GenerationFile{pointer, signature}); err != nil {
			t.Fatal(err)
		}
		signer, err := store.GenerationViewSigner(ctx, 1, "dists/el9/x86_64")
		if err != nil || signer.SignerIdentity != wantIdentity || string(signer.TrustedPublicKey) != string(publicKey) {
			t.Fatalf("bootstrapped signer=%#v err=%v", signer, err)
		}
		if err := store.ValidateGenerationLedger(ctx); err != nil {
			t.Fatalf("bootstrapped Generation ledger: %v", err)
		}
	})

	t.Run("signedness mismatch rolls back", func(t *testing.T) {
		store := newStore(t)
		defer store.Close()
		operationID := strings.Repeat("c", 64)
		if err := store.BootstrapLegacyGeneration(ctx, operationID, 1, []GenerationFile{pointer}); !errors.Is(err, ErrConflict) {
			t.Fatalf("bootstrap mismatch error=%v", err)
		}
		var generations, operations int
		if err := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM generations`).Scan(&generations); err != nil {
			t.Fatal(err)
		}
		if err := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE id = ?`, operationID).Scan(&operations); err != nil {
			t.Fatal(err)
		}
		if generations != 0 || operations != 0 {
			t.Fatalf("failed bootstrap committed generations=%d operations=%d", generations, operations)
		}
	})

	t.Run("unverified history cannot propagate", func(t *testing.T) {
		store := newStore(t)
		defer store.Close()
		manifest := []GenerationFile{pointer, signature}
		if err := store.BootstrapLegacyGeneration(ctx, strings.Repeat("d", 64), 1, manifest); err != nil {
			t.Fatal(err)
		}
		if _, err := store.DB().ExecContext(ctx, `UPDATE generation_view_signers SET signer_identity = ?, trusted_public_key = NULL WHERE generation = ?`, GenerationSignerUnverified, GenerationID(1)); err != nil {
			t.Fatal(err)
		}
		if err := validateGenerationViewSignerCoverage(ctx, store.DB(), 1, manifest); err != nil {
			t.Fatalf("unverified signed history lost exact coverage: %v", err)
		}
		tx, err := store.DB().BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		carryErr := carryGenerationViewSignersTx(ctx, tx, 1, 2, map[string]struct{}{})
		rollbackErr := tx.Rollback()
		if !errors.Is(carryErr, ErrConflict) || rollbackErr != nil {
			t.Fatalf("unverified carry error=%v rollback=%v", carryErr, rollbackErr)
		}
	})
}

func TestFreshRepositoryIdentityIsPersistentCanonicalAndTerminal(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "repo.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.RepositoryIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !IsCanonicalRepositoryID(first.RepositoryID) || first.LayoutVersion != LayoutSinglePayloadV1 || first.TransitionReceiptSHA256 != "" {
		t.Fatalf("fresh identity=%#v", first)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	second, err := store.RepositoryIdentity(ctx)
	if err != nil || second != first {
		t.Fatalf("reopened identity=%#v want=%#v err=%v", second, first, err)
	}
}

func TestRepositoryIdentitySQLDomainRejectsMalformedUUIDv4(t *testing.T) {
	for name, invalid := range map[string]string{
		"extra-hyphen":   "12345678-1234-4123-8123-123456789ab-",
		"missing-hyphen": "123456781234-4123-8123-123456789abc",
		"uppercase":      "12345678-1234-4123-8123-123456789ABC",
		"wrong-version":  "12345678-1234-5123-8123-123456789abc",
		"wrong-variant":  "12345678-1234-4123-7123-123456789abc",
		"non-hex":        "12345678-1234-4123-8123-123456789abg",
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if _, err := store.DB().ExecContext(ctx, `UPDATE repository_state SET repository_id = ? WHERE singleton = 1`, invalid); err == nil {
				t.Fatalf("SQLite accepted malformed UUIDv4 %q", invalid)
			}
			identity, err := store.RepositoryIdentity(ctx)
			if err != nil || !IsCanonicalRepositoryID(identity.RepositoryID) {
				t.Fatalf("identity after rejected update=%#v err=%v", identity, err)
			}
		})
	}
}

func TestStoreCheckBindsTerminalReceiptToSingleMigrationOperation(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	receipt := strings.Repeat("a", 64)
	if _, err := store.DB().ExecContext(ctx, `UPDATE repository_state SET transition_receipt_sha256 = ? WHERE singleton = 1`, receipt); err != nil {
		t.Fatal(err)
	}
	if err := store.Check(ctx); err == nil || !errors.Is(err, ErrConflict) {
		t.Fatalf("Store.Check accepted a receipt without layout.migrate: %v", err)
	}
}

func TestStoreCheckBindsMigrationReceiptToOwningGeneration(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	receipt := strings.Repeat("b", 64)
	operationID := strings.Repeat("c", 64)
	payload := `{"base_generation":"00000000000000000000","target_generation":"00000000000000000001","transition_receipt_sha256":"` + receipt + `"}`
	const at = "2026-08-06T00:00:00.000000000Z"
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES (?, 'layout.migrate', 'done', ?, '{}', ?, ?)`, operationID, payload, at, at); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE repository_state SET built_generation = '00000000000000000001', transition_receipt_sha256 = ? WHERE singleton = 1`, receipt); err != nil {
		t.Fatal(err)
	}
	if err := store.Check(ctx); err == nil || !errors.Is(err, ErrConflict) {
		t.Fatalf("Store.Check accepted migration receipt without its owning Generation: %v", err)
	}
}
