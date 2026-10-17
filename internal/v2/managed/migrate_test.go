package managed

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestRepositorySchemaMigrationRepairsV10DirtyProjection(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	opts := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if added, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1}); err != nil || !added.Dirty {
		t.Fatalf("skipped add=%#v err=%v", added, err)
	}
	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: opts, Repository: "repo", Name: "el10", Format: "rpm"}); err != nil {
		t.Fatal(err)
	}

	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE repository_state SET status = 'clean', dirty_reason = NULL WHERE singleton = 1`); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `DELETE FROM generation_view_signers
WHERE (generation < (SELECT built_generation FROM repository_state WHERE singleton = 1) AND view_id = 'dists/el9/x86_64')
   OR (generation = (SELECT built_generation FROM repository_state WHERE singleton = 1) AND view_id = 'dists/el10/x86_64')`); err != nil {
		store.Close()
		t.Fatal(err)
	}
	downgradeManagedV11FixtureToV10(t, store.DB())
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Build(ctx, BuildOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("ordinary build crossed v10 migration boundary: %v", err)
	}
	migrated, err := MigrateRepository(ctx, RepositoryMigrationOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1})
	if err != nil || !migrated.Complete || migrated.Phase != "done" {
		t.Fatalf("schema migration=%#v err=%v", migrated, err)
	}
	if migrated.FromLayout != state.LayoutSinglePayloadV1 || migrated.ToLayout != state.LayoutSinglePayloadV1 {
		t.Fatalf("schema migration reported a layout conversion: %#v", migrated)
	}
	status, err := Status(ctx, StatusOptions{WorkspaceOptions: opts, Repository: "repo"})
	if err != nil || status.Status != "dirty" || len(status.DirtyDists) != 1 || status.DirtyDists[0] != "el9" {
		t.Fatalf("migrated status=%#v err=%v", status, err)
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	ledgerErr := store.ValidateGenerationLedger(ctx)
	closeErr := store.Close()
	if err := errors.Join(ledgerErr, closeErr); err != nil {
		t.Fatalf("migrated signer ledger is invalid: %v", err)
	}
	built, err := Build(ctx, BuildOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1})
	if err != nil || built.Dirty || built.Noop {
		t.Fatalf("post-migration build=%#v err=%v", built, err)
	}
}

func TestRepositorySchemaMigrationReportsCurrentLayout(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	opts := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		migrated, err := MigrateRepository(ctx, RepositoryMigrationOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1})
		if err != nil || !migrated.Complete || migrated.Phase != "done" || migrated.FromLayout != state.LayoutSinglePayloadV1 || migrated.ToLayout != state.LayoutSinglePayloadV1 || migrated.SchemaFrom != state.SchemaVersion || migrated.SchemaTo != state.SchemaVersion {
			t.Fatalf("current-schema migration=%#v err=%v", migrated, err)
		}
	}
}

func TestRepositorySchemaMigrationMarksUnprovableSignedV10History(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	opts := WorkspaceOptions{Workdir: root, CWD: root}
	keyA, _ := managedTestPrivateKey(t, "v10-history-a")
	keyB, _ := managedTestPrivateKey(t, "v10-history-b")
	t.Setenv("SOW_TEST_V10_HISTORY_KEY", string(keyA))
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{
		Signing: config.SigningConfig{RPM: config.RPMSigningConfig{Metadata: config.MetadataSigningConfig{Key: "env://SOW_TEST_V10_HISTORY_KEY"}}},
		Dists:   map[string]config.DistConfig{"el9": {Format: "rpm", Architectures: []string{"x86_64"}}},
	}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	initial, err := store.Summary(ctx)
	if closeErr := store.Close(); err != nil || closeErr != nil || initial.BuiltGeneration == 0 {
		t.Fatalf("initial summary=%#v err=%v close=%v", initial, err, closeErr)
	}

	// The v10 init Generation was signed by A but FinalizeDistAdd did not
	// retain a signer row. Rotate to B before the first build so assigning the
	// current Dist key to that historical view would be provably wrong.
	t.Setenv("SOW_TEST_V10_HISTORY_KEY", string(keyB))
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	added, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1})
	if err != nil || added.Generation == initial.BuiltGeneration {
		t.Fatalf("first rotated build=%#v err=%v", added, err)
	}

	store, err = state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `DELETE FROM generation_view_signers WHERE generation = ?`, initial.BuiltGeneration); err != nil {
		store.Close()
		t.Fatal(err)
	}
	downgradeManagedV11FixtureToV10(t, store.DB())
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	migrated, err := MigrateRepository(ctx, RepositoryMigrationOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1})
	if err != nil || !migrated.Complete || migrated.Phase != "done" {
		t.Fatalf("signed v10 migration=%#v err=%v", migrated, err)
	}
	store, err = state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	historical, historicalErr := store.GenerationViewSigner(ctx, initial.BuiltGeneration, "dists/el9/x86_64")
	_, _, retentionErr := store.GenerationRetentionIdentity(ctx, initial.BuiltGeneration)
	head, headErr := store.GenerationViewSigner(ctx, added.Generation, "dists/el9/x86_64")
	_, retainedHead, retainedHeadErr := store.GenerationRetentionIdentity(ctx, added.Generation)
	ledgerErr := store.ValidateGenerationLedger(ctx)
	closeErr := store.Close()
	if err := errors.Join(historicalErr, headErr, retainedHeadErr, ledgerErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if historical.SignerIdentity != state.GenerationSignerUnverified || len(historical.TrustedPublicKey) != 0 || !errors.Is(retentionErr, state.ErrConflict) {
		t.Fatalf("historical signer=%#v retentionErr=%v", historical, retentionErr)
	}
	if head.SignerIdentity == "none" || head.SignerIdentity == state.GenerationSignerUnverified || len(head.TrustedPublicKey) == 0 || retainedHead != head.SignerIdentity {
		t.Fatalf("proven head signer=%#v retained=%q", head, retainedHead)
	}

	// A post-migration rotation creates another fully proven head; the unknown
	// historical identity must neither propagate nor block ordinary builds.
	t.Setenv("SOW_TEST_V10_HISTORY_KEY", string(keyA))
	rebuilt, err := Build(ctx, BuildOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1})
	if err != nil || rebuilt.Noop || rebuilt.Dirty || rebuilt.Generation == added.Generation {
		t.Fatalf("post-migration rotation=%#v err=%v", rebuilt, err)
	}
	store, err = state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	rebuiltSigner, signerErr := store.GenerationViewSigner(ctx, rebuilt.Generation, "dists/el9/x86_64")
	_, rebuiltRetained, retainedErr := store.GenerationRetentionIdentity(ctx, rebuilt.Generation)
	ledgerErr = store.ValidateGenerationLedger(ctx)
	if err := errors.Join(signerErr, retainedErr, ledgerErr); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if rebuiltSigner.SignerIdentity == state.GenerationSignerUnverified || rebuiltRetained != rebuiltSigner.SignerIdentity {
		store.Close()
		t.Fatalf("rebuilt signer=%#v retained=%q", rebuiltSigner, rebuiltRetained)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE generation_view_signers SET signer_identity = ?, trusted_public_key = NULL WHERE generation = ?`, state.GenerationSignerUnverified, rebuilt.Generation); err != nil {
		store.Close()
		t.Fatal(err)
	}
	ledgerErr = store.ValidateGenerationLedger(ctx)
	closeErr = store.Close()
	if !errors.Is(ledgerErr, state.ErrConflict) || closeErr != nil {
		t.Fatalf("unverified head ledgerErr=%v close=%v", ledgerErr, closeErr)
	}
}

func downgradeManagedV11FixtureToV10(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
PRAGMA foreign_keys = OFF;
DROP INDEX package_objects_pool_path_folded;
DROP INDEX publication_inventory_payload_path_folded;
DROP INDEX publication_abandoned_payload_path_folded;
DELETE FROM schema_migrations WHERE version = 13;
DROP TABLE publication_target_binding_revisions;
DELETE FROM schema_migrations WHERE version = 12;
CREATE TEMP TABLE generation_view_signers_fixture AS
SELECT generation, view_id, signer_identity, trusted_public_key FROM generation_view_signers;
DROP TABLE generation_view_signers;
CREATE TABLE generation_view_signers (
    generation TEXT NOT NULL REFERENCES "generations"(generation) ON DELETE CASCADE,
    view_id TEXT NOT NULL,
    signer_identity TEXT NOT NULL CHECK (
        signer_identity = 'none' OR (
            length(signer_identity) = 64
            AND signer_identity = lower(signer_identity)
            AND signer_identity NOT GLOB '*[^0-9a-f]*'
        )
    ),
    trusted_public_key BLOB CHECK (
        (signer_identity = 'none' AND trusted_public_key IS NULL)
        OR (signer_identity != 'none' AND length(trusted_public_key) BETWEEN 1 AND 16777216)
    ),
    PRIMARY KEY (generation, view_id)
) WITHOUT ROWID;
INSERT INTO generation_view_signers(generation, view_id, signer_identity, trusted_public_key)
SELECT generation, view_id, signer_identity, trusted_public_key FROM generation_view_signers_fixture;
DROP TABLE generation_view_signers_fixture;
DELETE FROM schema_migrations WHERE version = 11;
PRAGMA user_version = 10;
PRAGMA foreign_keys = ON;`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMigrateEmptyLegacyRepositoryReusesIdentityAcrossRestart(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	base, _, repositoryID := prepareStartedC2MigrationFixture(t, root, false)
	if base != 0 {
		t.Fatalf("empty repository base=%s", base)
	}
	rewriteConfigAsLegacyV2(t, root)
	options := WorkspaceOptions{Workdir: root, CWD: root}
	legacyRepositories, err := ListRepositories(ctx, options)
	if err != nil || len(legacyRepositories) != 1 || legacyRepositories[0].Name != "repo" {
		t.Fatalf("frozen v0.2 read=%#v err=%v", legacyRepositories, err)
	}
	injected := errors.New("planned migration crash")
	at := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at }, Fault: func(point string) error {
		if point == "migrate.planned" {
			return injected
		}
		return nil
	}}); !errors.Is(err, injected) {
		t.Fatalf("planned fault=%v", err)
	}
	journal, _, err := loadTransitionJournal(root, "repo")
	if err != nil || journal == nil || journal.Phase != "planned" || journal.RepositoryID != repositoryID {
		t.Fatalf("journal=%#v err=%v", journal, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	during, identityErr := store.RepositoryIdentity(ctx)
	if err := errors.Join(identityErr, store.Close()); err != nil {
		t.Fatal(err)
	}
	if during.RepositoryID != repositoryID || during.LayoutVersion != state.LayoutC2ToSingleV1 {
		t.Fatalf("transition identity=%#v", during)
	}
	result, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at }})
	if err != nil || !result.Complete || result.Phase != "done" || result.RepositoryID != repositoryID || result.Generation != 1 {
		t.Fatalf("migration=%#v err=%v", result, err)
	}
	data, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := config.Parse(data)
	if err != nil || parsed.Schema != config.Schema {
		t.Fatalf("migrated config=%#v err=%v", parsed, err)
	}
	journal, _, err = loadTransitionJournal(root, "repo")
	if err != nil || journal != nil {
		t.Fatalf("terminal journal=%#v err=%v", journal, err)
	}
}

func TestMigrateRejectsSubThirtyDayGraceBeforeWorkspaceMutation(t *testing.T) {
	root := t.TempDir()
	_, err := MigrateRepositoryLayout(context.Background(), RepositoryMigrationOptions{
		WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root},
		Repository:       "repo",
		Jobs:             1,
		GracePeriod:      29 * 24 * time.Hour,
	})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("sub-thirty-day grace error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, ".sow")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("rejected grace mutated workspace: %v", statErr)
	}
}

func TestMigrateRepairsFinalManifestAfterSQLiteCommitCrash(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	base, _, repositoryID := prepareStartedC2MigrationFixture(t, root, false)
	options := WorkspaceOptions{Workdir: root, CWD: root}
	at := time.Date(2026, 8, 5, 12, 30, 0, 0, time.UTC)
	injected := errors.New("crash after SQLite transition commit")
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at }, Fault: func(point string) error {
		if point == "migrate.sqlite_committed" {
			return injected
		}
		return nil
	}}); !errors.Is(err, injected) {
		t.Fatalf("SQLite commit fault=%v", err)
	}
	journal, _, err := loadTransitionJournal(root, "repo")
	if err != nil || journal == nil || journal.Phase != "final_manifest" {
		t.Fatalf("post-SQLite journal=%#v err=%v", journal, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	identity, identityErr := store.RepositoryIdentity(ctx)
	summary, summaryErr := store.Summary(ctx)
	if err := errors.Join(identityErr, summaryErr, store.Close()); err != nil {
		t.Fatal(err)
	}
	next, nextErr := base.Next()
	if nextErr != nil || identity.RepositoryID != repositoryID || identity.LayoutVersion != state.LayoutSinglePayloadV1 || summary.BuiltGeneration != next || identity.TransitionReceiptSHA256 == "" {
		t.Fatalf("post-SQLite identity=%#v summary=%#v next=%s err=%v", identity, summary, next, nextErr)
	}
	result, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at }})
	if err != nil || !result.Complete || result.Phase != "done" || result.Generation != next || result.RepositoryID != repositoryID {
		t.Fatalf("repair result=%#v err=%v", result, err)
	}
	journal, _, err = loadTransitionJournal(root, "repo")
	if err != nil || journal != nil {
		t.Fatalf("repair retained journal=%#v err=%v", journal, err)
	}
}

func TestMigrateDoneJournalCanSupplementPendingSQLiteCommit(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	base, _, repositoryID := prepareStartedC2MigrationFixture(t, root, false)
	options := WorkspaceOptions{Workdir: root, CWD: root}
	at := time.Date(2026, 8, 5, 12, 45, 0, 0, time.UTC)
	injected := errors.New("crash at final manifest")
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at }, Fault: func(point string) error {
		if point == "migrate.final_manifest" {
			return injected
		}
		return nil
	}}); !errors.Is(err, injected) {
		t.Fatalf("final-manifest fault=%v", err)
	}
	journal, _, err := loadTransitionJournal(root, "repo")
	if err != nil || journal == nil || journal.Phase != "final_manifest" {
		t.Fatalf("final-manifest journal=%#v err=%v", journal, err)
	}
	journal.Phase = "done"
	if err := persistTransitionJournal(root, "repo", *journal); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at }})
	next, nextErr := base.Next()
	if err != nil || nextErr != nil || !result.Complete || result.Generation != next || result.RepositoryID != repositoryID {
		t.Fatalf("done supplement=%#v next=%s err=%v nextErr=%v", result, next, err, nextErr)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	identity, identityErr := store.RepositoryIdentity(ctx)
	if err := errors.Join(identityErr, store.Close()); err != nil {
		t.Fatal(err)
	}
	if identity.LayoutVersion != state.LayoutSinglePayloadV1 || identity.TransitionReceiptSHA256 == "" {
		t.Fatalf("done supplement identity=%#v", identity)
	}
}

func TestMigrateAPTOnlyPreservesByHashAndClassifiesNoAliases(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"noble": {Format: "deb", Architectures: []string{"aarch64"}},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	deb := decodeManagedFixture(t, filepath.Join("..", "..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(inputs, "package.deb"))
	options := WorkspaceOptions{Workdir: root, CWD: root}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}, Paths: []string{deb}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	before, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	byHash := 0
	for _, file := range before {
		if strings.Contains(file.Path, "/by-hash/SHA256/") {
			byHash++
		}
	}
	if byHash == 0 {
		t.Fatal("APT fixture produced no by-hash closure")
	}
	base, aliases, _ := prepareStartedC2MigrationFixture(t, root, false)
	if len(aliases) != 0 {
		t.Fatalf("APT by-hash was classified as C2 aliases: %v", aliases)
	}
	at := time.Date(2026, 8, 5, 13, 0, 0, 0, time.UTC)
	result, err := MigrateRepository(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at }})
	next, nextErr := base.Next()
	if err != nil || nextErr != nil || !result.Complete || result.LegacyAliases != 0 || result.Generation != next {
		t.Fatalf("migration=%#v next=%s err=%v nextErr=%v", result, next, err, nextErr)
	}
	after, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("APT-only public tree changed:\nbefore=%#v\nafter=%#v\nerr=%v", before, after, err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || !checked.ReadyToCopy || checked.Status != "clean" {
		t.Fatalf("terminal APT-only check=%#v err=%v", checked, err)
	}
}

func TestMigrateRejectsMetadataSignerDriftOnResume(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	keyOne, _ := managedTestPrivateKey(t, "migration-one")
	keyTwo, _ := managedTestPrivateKey(t, "migration-two")
	const keyEnvironment = "SOW_TEST_MIGRATION_METADATA_KEY"
	t.Setenv(keyEnvironment, string(keyOne))
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{
		Signing: config.SigningConfig{RPM: config.RPMSigningConfig{Metadata: config.MetadataSigningConfig{Key: "env://" + keyEnvironment}}},
		Dists:   map[string]config.DistConfig{"el9": {Format: "rpm", Architectures: []string{"x86_64"}}},
	}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	options := WorkspaceOptions{Workdir: root, CWD: root}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	viewRoot := filepath.Join(root, "repo", "dists", "el9", "x86_64")
	rewriteRPMViewAsLegacyC2(t, viewRoot)
	// Re-sign the deliberately rewritten legacy repomd bytes with the Built
	// signer so planning starts from an authentic C2 closure.
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	dist, distErr := store.GetDist(ctx, "el9")
	builtAt, builtAtErr := builtGenerationPublicationTime(ctx, store, dist.BuiltGeneration)
	if err := errors.Join(distErr, builtAtErr, store.Close()); err != nil {
		t.Fatal(err)
	}
	at := ceilUTCSecond(builtAt).Add(time.Second)
	snapshot, err := loadMetadataSignerSnapshotForFormats(ctx, root, cfg.Repositories["repo"], builtAt, true, false)
	if err != nil {
		t.Fatal(err)
	}
	repomdPath := filepath.Join(viewRoot, "repodata", "repomd.xml")
	repomd, err := os.ReadFile(repomdPath)
	if err != nil {
		t.Fatal(err)
	}
	var signature bytes.Buffer
	if err := snapshot.RPMSigner.Sign(ctx, bytes.NewReader(repomd), &signature); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(viewRoot, "repodata", "repomd.xml.asc"), signature.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	prepareStartedC2MigrationFixture(t, root, true)
	stagedCrash := errors.New("crash after signed migration stage")
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at }, Fault: func(point string) error {
		if point == "migrate.staged" {
			return stagedCrash
		}
		return nil
	}}); !errors.Is(err, stagedCrash) {
		t.Fatalf("signed staged fault=%v", err)
	}
	liveBefore, err := os.ReadFile(repomdPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(keyEnvironment, string(keyTwo))
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at }}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("signer-drift resume error=%v", err)
	}
	liveAfter, err := os.ReadFile(repomdPath)
	if err != nil || !bytes.Equal(liveAfter, liveBefore) {
		t.Fatalf("signer-drift resume changed live pointer: err=%v", err)
	}
	t.Setenv(keyEnvironment, "")
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at }}); err == nil {
		t.Fatal("ordinary precommit resume accepted an unavailable private signer")
	}
	if result, err := AbandonRepositoryMigration(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1}); err != nil || result.Phase != "abandoned" {
		t.Fatalf("abort required the discarded plan's private signer: %+v %v", result, err)
	}
	liveAfter, err = os.ReadFile(repomdPath)
	if err != nil || !bytes.Equal(liveAfter, liveBefore) {
		t.Fatalf("signed precommit abort changed old public pointer: %v", err)
	}
}

func TestMigratePostCommitRecoveryDoesNotRequireCurrentPrivateSigner(t *testing.T) {
	for _, test := range []struct {
		name   string
		rotate bool
	}{
		{name: "deleted"},
		{name: "rotated", rotate: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			keyOne, _ := managedTestPrivateKey(t, "postcommit-one-"+test.name)
			keyTwo, _ := managedTestPrivateKey(t, "postcommit-two-"+test.name)
			const keyEnvironment = "SOW_TEST_POSTCOMMIT_METADATA_KEY"
			t.Setenv(keyEnvironment, string(keyOne))
			cfg := config.Default()
			cfg.Repositories["repo"] = config.RepositoryConfig{
				Signing: config.SigningConfig{RPM: config.RPMSigningConfig{Metadata: config.MetadataSigningConfig{Key: "env://" + keyEnvironment}}},
				Dists:   map[string]config.DistConfig{"el9": {Format: "rpm", Architectures: []string{"x86_64"}}},
			}
			writeManagedConfig(t, root, cfg)
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			inputs := filepath.Join(root, "inputs")
			if err := os.Mkdir(inputs, 0o755); err != nil {
				t.Fatal(err)
			}
			rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
			options := WorkspaceOptions{Workdir: root, CWD: root}
			if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			viewRoot := filepath.Join(root, "repo", "dists", "el9", "x86_64")
			rewriteRPMViewAsLegacyC2(t, viewRoot)
			store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			dist, distErr := store.GetDist(ctx, "el9")
			builtAt, builtAtErr := builtGenerationPublicationTime(ctx, store, dist.BuiltGeneration)
			if err := errors.Join(distErr, builtAtErr, store.Close()); err != nil {
				t.Fatal(err)
			}
			at := ceilUTCSecond(builtAt).Add(time.Second)
			snapshot, err := loadMetadataSignerSnapshotForFormats(ctx, root, cfg.Repositories["repo"], builtAt, true, false)
			if err != nil {
				t.Fatal(err)
			}
			repomdPath := filepath.Join(viewRoot, "repodata", "repomd.xml")
			repomd, err := os.ReadFile(repomdPath)
			if err != nil {
				t.Fatal(err)
			}
			var signature bytes.Buffer
			if err := snapshot.RPMSigner.Sign(ctx, bytes.NewReader(repomd), &signature); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(viewRoot, "repodata", "repomd.xml.asc"), signature.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
			_, aliases, _ := prepareStartedC2MigrationFixture(t, root, true)
			injected := errors.New("stop after commit intent")
			if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at }, Fault: func(point string) error {
				if point == "migrate.commit_intent" {
					return injected
				}
				return nil
			}}); !errors.Is(err, injected) {
				t.Fatalf("commit-intent fault=%v", err)
			}
			if test.rotate {
				t.Setenv(keyEnvironment, string(keyTwo))
			} else {
				t.Setenv(keyEnvironment, "")
			}
			if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at }}); !errors.Is(err, ErrNotReady) {
				t.Fatalf("postcommit recovery required current secret: %v", err)
			}
			for _, alias := range aliases {
				if _, err := os.Stat(filepath.Join(root, "repo", filepath.FromSlash(alias))); err != nil {
					t.Fatalf("postcommit recovery removed alias before grace: %v", err)
				}
			}
			result, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at.Add(31 * 24 * time.Hour) }})
			if err != nil || !result.Complete {
				t.Fatalf("postcommit secret-independent completion=%#v err=%v", result, err)
			}
		})
	}
}

func TestValidateMigrationRPMViewSetRequiresExactSQLiteBuiltTopology(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AddDist(ctx, state.Dist{
		Name: "el9", Format: "rpm", EffectiveConfigSHA256: "rpm", BuiltGeneration: 0,
		Architectures: []state.Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}, {Family: "aarch64", EcosystemArch: "aarch64"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddDist(ctx, state.Dist{
		Name: "noble", Format: "deb", EffectiveConfigSHA256: "deb", BuiltGeneration: 0,
		Architectures: []state.Architecture{{Family: "x86_64", EcosystemArch: "amd64"}},
	}); err != nil {
		t.Fatal(err)
	}
	expected, err := expectedMigrationRPMViews(ctx, store)
	want := []migrationRPMView{{ViewID: "dists/el9/aarch64"}, {ViewID: "dists/el9/x86_64"}}
	if err != nil || !reflect.DeepEqual(expected, want) {
		t.Fatalf("SQLite Built RPM views=%#v want=%#v err=%v", expected, want, err)
	}
	pointers := []TransitionPointer{
		{ViewID: want[0].ViewID, Kind: "commit_pointer"},
		{ViewID: want[1].ViewID, Kind: "commit_pointer"},
	}
	if err := validateMigrationRPMViewSet(expected, pointers); err != nil {
		t.Fatalf("exact Built RPM view topology rejected: %v", err)
	}
	for _, test := range []struct {
		name     string
		pointers []TransitionPointer
		want     string
	}{
		{"missing-all", nil, "missing=[dists/el9/aarch64 dists/el9/x86_64] unexpected=[]"},
		{"missing-one", pointers[:1], "missing=[dists/el9/x86_64] unexpected=[]"},
		{"unexpected-view", []TransitionPointer{pointers[0], {ViewID: "dists/el9/ppc64le", Kind: "commit_pointer"}}, "missing=[dists/el9/x86_64] unexpected=[dists/el9/ppc64le]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateMigrationRPMViewSet(expected, test.pointers)
			if !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("view topology error=%v want %q", err, test.want)
			}
		})
	}
}

func TestMigrateRejectsJournalWithMissingBuiltRPMViewsEvenWithRecomputedTarget(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9": {Format: "rpm", Architectures: []string{"x86_64", "aarch64"}},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	baseGeneration, _, _ := prepareStartedC2MigrationFixture(t, root, false)
	options := WorkspaceOptions{Workdir: root, CWD: root}
	at := time.Date(2026, 8, 5, 15, 30, 0, 0, time.UTC)
	injected := errors.New("stop at complete stage")
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2, now: func() time.Time { return at }, Fault: func(point string) error {
		if point == "migrate.staged" {
			return injected
		}
		return nil
	}}); !errors.Is(err, injected) {
		t.Fatalf("staged fault=%v", err)
	}
	original, _, err := loadTransitionJournal(root, "repo")
	if err != nil || original == nil || original.Phase != "staged" {
		t.Fatalf("journal=%#v err=%v", original, err)
	}
	views := map[string]struct{}{}
	for _, pointer := range original.Pointers {
		views[pointer.ViewID] = struct{}{}
	}
	if len(views) != 2 {
		t.Fatalf("planned views=%v", views)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	base, baseErr := store.GenerationManifest(ctx, baseGeneration)
	if err := errors.Join(baseErr, store.Close()); err != nil {
		t.Fatal(err)
	}
	stage, err := scanPublicManifest(ctx, migrationStageRoot(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	targetFor := func(kept map[string]struct{}) string {
		t.Helper()
		target := append([]state.GenerationFile(nil), base...)
		for view := range kept {
			filtered := target[:0]
			for _, file := range target {
				if !strings.HasPrefix(file.Path, view+"/") {
					filtered = append(filtered, file)
				}
			}
			target = filtered
			for _, file := range stage {
				if strings.HasPrefix(file.Path, view+"/") {
					target = append(target, file)
				}
			}
		}
		sort.Slice(target, func(i, j int) bool { return target[i].Path < target[j].Path })
		_, digest, err := state.ManifestBytes(target)
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	viewNames := make([]string, 0, len(views))
	for view := range views {
		viewNames = append(viewNames, view)
	}
	sort.Strings(viewNames)
	for name, kept := range map[string]map[string]struct{}{
		"all-pointers-deleted": {},
		"one-view-deleted":     {viewNames[0]: {}},
	} {
		t.Run(name, func(t *testing.T) {
			forged := *original
			forged.Pointers = nil
			for _, pointer := range original.Pointers {
				if _, keep := kept[pointer.ViewID]; keep {
					forged.Pointers = append(forged.Pointers, pointer)
				}
			}
			forged.TargetManifestSHA256 = targetFor(kept)
			if err := persistTransitionJournal(root, "repo", forged); err != nil {
				t.Fatal(err)
			}
			if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2, now: func() time.Time { return at }}); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("missing-view forged target error=%v", err)
			}
			if err := persistTransitionJournal(root, "repo", *original); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMigrateGraceAnchorCeilsNanosecondsWithoutShorteningThirtyDays(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm", Architectures: []string{"x86_64"}}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	options := WorkspaceOptions{Workdir: root, CWD: root}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	rewriteRPMViewAsLegacyC2(t, filepath.Join(root, "repo", "dists", "el9", "x86_64"))
	_, aliases, _ := prepareStartedC2MigrationFixture(t, root, true)
	if len(aliases) != 1 {
		t.Fatalf("aliases=%v", aliases)
	}
	at := time.Date(2026, 8, 5, 16, 0, 0, 500, time.UTC)
	injected := errors.New("stop after grace journal")
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at }, Fault: func(point string) error {
		if point == "migrate.grace" {
			return injected
		}
		return nil
	}}); !errors.Is(err, injected) {
		t.Fatalf("grace fault=%v", err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	control, controlErr := store.LayoutTransitionControl(ctx)
	if err := errors.Join(controlErr, store.Close()); err != nil {
		t.Fatal(err)
	}
	wantStart := time.Date(2026, 8, 5, 16, 0, 1, 0, time.UTC)
	wantDeadline := wantStart.Add(30 * 24 * time.Hour)
	if control == nil || control.CommitIntentAt != wantStart.Format("2006-01-02T15:04:05Z") || control.NotBefore != wantDeadline.Format("2006-01-02T15:04:05Z") {
		t.Fatalf("nanosecond control=%#v want start=%s deadline=%s", control, wantStart, wantDeadline)
	}
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return at.Add(30 * 24 * time.Hour) }}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("30 days from subsecond observation bypassed ceil: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "repo", filepath.FromSlash(aliases[0]))); err != nil {
		t.Fatalf("ceil boundary removed alias early: %v", err)
	}
	result, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, now: func() time.Time { return wantDeadline }})
	if err != nil || !result.Complete {
		t.Fatalf("deadline migration=%#v err=%v", result, err)
	}
}

func TestMigrateMixedRepositoryRollsForwardAfterCommitAndGrace(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9":   {Format: "rpm", Architectures: []string{"x86_64"}},
		"noble": {Format: "deb", Architectures: []string{"aarch64"}},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	deb := decodeManagedFixture(t, filepath.Join("..", "..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(inputs, "package.deb"))
	options := WorkspaceOptions{Workdir: root, CWD: root}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9", "noble"}, Paths: []string{rpm, deb}, Jobs: 2}); err != nil {
		t.Fatal(err)
	}
	rewriteRPMViewAsLegacyC2(t, filepath.Join(root, "repo", "dists", "el9", "x86_64"))
	before, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	aptBefore := manifestWithPrefix(before, "dists/noble/")
	base, aliases, repositoryID := prepareStartedC2MigrationFixture(t, root, true)
	if len(aliases) != 1 {
		t.Fatalf("legacy aliases=%v", aliases)
	}
	at := time.Date(2026, 8, 5, 14, 0, 0, 0, time.UTC)
	stagedCrash := errors.New("crash after staging")
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2, now: func() time.Time { return at }, Fault: func(point string) error {
		if point == "migrate.staged" {
			return stagedCrash
		}
		return nil
	}}); !errors.Is(err, stagedCrash) {
		t.Fatalf("staged fault=%v", err)
	}
	journal, _, err := loadTransitionJournal(root, "repo")
	if err != nil || journal == nil || journal.Phase != "staged" {
		t.Fatalf("staged journal=%#v err=%v", journal, err)
	}
	status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
	if err != nil || status.Status != "recovering" {
		t.Fatalf("transition status=%#v err=%v", status, err)
	}
	info, err := ShowRepository(ctx, RepositoryShowOptions{WorkspaceOptions: options, Repository: "repo"})
	if err != nil || info.Status != "recovering" {
		t.Fatalf("transition repo show=%#v err=%v", info, err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrNotReady) || checked.Status != "recovering" || checked.ReadyToCopy {
		t.Fatalf("transition check=%#v err=%v", checked, err)
	}
	transitionLayerOK := false
	for _, layer := range checked.Layers {
		if layer.Name == "layout-transition" {
			transitionLayerOK = layer.OK
		}
	}
	if !transitionLayerOK {
		t.Fatalf("transition check lacks a valid layout-transition layer: %#v", checked.Layers)
	}

	// The complete staged closure, not only repomd.xml, is frozen by the
	// journal target digest.  Corrupt a non-pointer metadata artifact and
	// prove resume fails closed before any public pointer changes.
	stageManifest, err := scanPublicManifest(ctx, migrationStageRoot(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	var stagedArtifact state.GenerationFile
	for _, file := range stageManifest {
		if file.Path != "dists/el9/x86_64/repodata/repomd.xml" && file.Path != "dists/el9/x86_64/repodata/repomd.xml.asc" {
			stagedArtifact = file
			break
		}
	}
	if stagedArtifact.Path == "" {
		t.Fatal("migration stage has no non-pointer metadata artifact")
	}
	stagedArtifactPath := filepath.Join(migrationStageRoot(root, "repo"), filepath.FromSlash(stagedArtifact.Path))
	stagedArtifactBytes, err := os.ReadFile(stagedArtifactPath)
	if err != nil || len(stagedArtifactBytes) == 0 {
		t.Fatalf("read staged artifact=%v size=%d", err, len(stagedArtifactBytes))
	}
	corruptArtifact := append([]byte(nil), stagedArtifactBytes...)
	corruptArtifact[len(corruptArtifact)/2] ^= 0xff
	if err := os.WriteFile(stagedArtifactPath, corruptArtifact, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2, now: func() time.Time { return at }}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered stage resume error=%v", err)
	}
	if err := os.WriteFile(stagedArtifactPath, stagedArtifactBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	// A syntactically valid forged journal cannot skip pointer roll-forward by
	// claiming grace has expired.  The live old pointer closure is rebound on
	// resume and the hardlink alias remains protected.
	originalStaged := *journal
	forged := *journal
	forged.Pointers = append([]TransitionPointer(nil), journal.Pointers...)
	for index := range forged.Pointers {
		forged.Pointers[index].State = "new"
	}
	pastDeadline := at.Add(-time.Hour).Format("2006-01-02T15:04:05Z")
	forged.Phase, forged.CommitIntent, forged.GraceNotBefore = "grace", true, &pastDeadline
	if err := persistTransitionJournal(root, "repo", forged); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2, now: func() time.Time { return at }}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("forged past-grace journal error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "repo", filepath.FromSlash(aliases[0]))); err != nil {
		t.Fatalf("forged grace removed legacy alias: %v", err)
	}
	if err := persistTransitionJournal(root, "repo", originalStaged); err != nil {
		t.Fatal(err)
	}

	pointerCrash := errors.New("crash after pointer exchange")
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2, now: func() time.Time { return at }, Fault: func(point string) error {
		if point == "migrate.pointer_exchanged.dists/el9/x86_64" {
			return pointerCrash
		}
		return nil
	}}); !errors.Is(err, pointerCrash) {
		t.Fatalf("pointer exchange fault=%v", err)
	}
	journal, _, err = loadTransitionJournal(root, "repo")
	if err != nil || journal == nil || journal.Phase != "pointer_rollforward" || !journal.CommitIntent || journal.GraceNotBefore != nil || len(journal.LegacyAliases) != len(aliases) {
		t.Fatalf("pre-persist pointer journal=%#v err=%v", journal, err)
	}
	for _, pointer := range journal.Pointers {
		if pointer.State != "old" {
			t.Fatalf("pointer state persisted across pre-journal crash: %#v", pointer)
		}
	}
	for _, alias := range aliases {
		if _, err := os.Stat(filepath.Join(root, "repo", filepath.FromSlash(alias))); err != nil {
			t.Fatalf("grace removed alias %q: %v", alias, err)
		}
	}
	if _, err := Changes(ctx, ChangesOptions{WorkspaceOptions: options, Repository: "repo"}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("changes during transition error=%v", err)
	}
	if _, err := AbandonRepositoryMigration(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo"}); !errors.Is(err, ErrRejected) {
		t.Fatalf("post-commit abandon error=%v", err)
	}
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2, now: func() time.Time { return at }}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("pointer replay did not enter grace: %v", err)
	}
	journal, _, err = loadTransitionJournal(root, "repo")
	if err != nil || journal == nil || journal.Phase != "grace" || journal.GraceNotBefore == nil {
		t.Fatalf("grace journal=%#v err=%v", journal, err)
	}
	for _, pointer := range journal.Pointers {
		if pointer.State != "new" {
			t.Fatalf("pointer replay did not persist new state: %#v", pointer)
		}
	}
	originalGrace := *journal
	forgedDeadline := at.Add(-time.Second).Format("2006-01-02T15:04:05Z")
	journal.GraceNotBefore = &forgedDeadline
	if err := persistTransitionJournal(root, "repo", *journal); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2, now: func() time.Time { return at }}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("forged anchored grace deadline error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "repo", filepath.FromSlash(aliases[0]))); err != nil {
		t.Fatalf("forged anchored deadline removed alias: %v", err)
	}
	if err := persistTransitionJournal(root, "repo", originalGrace); err != nil {
		t.Fatal(err)
	}
	journal = &originalGrace
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2, now: func() time.Time { return at.Add(29 * 24 * time.Hour) }}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("migration ignored grace deadline: %v", err)
	}
	foreign := filepath.Join(filepath.Dir(filepath.Join(root, "repo", filepath.FromSlash(aliases[0]))), "foreign.rpm")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2, now: func() time.Time { return at.Add(31 * 24 * time.Hour) }}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("foreign alias-pool file error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "repo", filepath.FromSlash(aliases[0]))); err != nil {
		t.Fatalf("foreign file failure removed expected alias: %v", err)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	aliasCrash := errors.New("crash after alias removal")
	if _, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2, now: func() time.Time { return at.Add(31 * 24 * time.Hour) }, Fault: func(point string) error {
		if point == "migrate.alias_removed."+aliases[0] {
			return aliasCrash
		}
		return nil
	}}); !errors.Is(err, aliasCrash) {
		t.Fatalf("alias removal fault=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "repo", filepath.FromSlash(aliases[0]))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("alias removal crash did not remove alias: %v", err)
	}
	journal, _, err = loadTransitionJournal(root, "repo")
	if err != nil || journal == nil || journal.Phase != "alias_delete" || journal.LegacyAliases[0].State != "present" || journal.LegacyAliases[0].ReceiptSHA256 != nil {
		t.Fatalf("pre-receipt alias journal=%#v err=%v", journal, err)
	}
	result, err := MigrateRepositoryLayout(ctx, RepositoryMigrationOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2, now: func() time.Time { return at.Add(31 * 24 * time.Hour) }})
	next, nextErr := base.Next()
	if err != nil || nextErr != nil || !result.Complete || result.Generation != next || result.LegacyAliases != len(aliases) || result.RepositoryID != repositoryID {
		t.Fatalf("migration=%#v next=%s err=%v nextErr=%v", result, next, err, nextErr)
	}
	for _, alias := range aliases {
		if _, err := os.Lstat(filepath.Join(root, "repo", filepath.FromSlash(alias))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("terminal migration retained alias %q: %v", alias, err)
		}
	}
	after, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	if aptAfter := manifestWithPrefix(after, "dists/noble/"); !reflect.DeepEqual(aptAfter, aptBefore) {
		t.Fatalf("migration changed APT view:\nbefore=%#v\nafter=%#v", aptBefore, aptAfter)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	identity, identityErr := store.RepositoryIdentity(ctx)
	summary, summaryErr := store.Summary(ctx)
	closeErr := store.Close()
	if err := errors.Join(identityErr, summaryErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if identity.RepositoryID != repositoryID || identity.LayoutVersion != state.LayoutSinglePayloadV1 || !lowercaseSHA256.MatchString(identity.TransitionReceiptSHA256) || summary.BuiltGeneration != next {
		t.Fatalf("identity=%#v summary=%#v", identity, summary)
	}
	baseZero := state.ZeroGeneration
	changes, err := Changes(ctx, ChangesOptions{WorkspaceOptions: options, Repository: "repo", Base: &baseZero})
	if err != nil || !reflect.DeepEqual(changes.Changes, state.DiffManifests(nil, after)) {
		t.Fatalf("changes --base 0=%#v err=%v", changes, err)
	}
	journal, _, err = loadTransitionJournal(root, "repo")
	if err != nil || journal != nil {
		t.Fatalf("terminal journal=%#v err=%v", journal, err)
	}
}

// prepareStartedC2MigrationFixture models an older binary that durably began
// the transition before interruption. New C2 transitions are no longer started.
func prepareStartedC2MigrationFixture(t *testing.T, root string, addRPMAliases bool) (state.GenerationID, []string, string) {
	t.Helper()
	ctx := context.Background()
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	summary, err := store.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []state.GenerationFile{}
	var generationInfo state.GenerationInfo
	if summary.BuiltGeneration > 0 {
		manifest, err = store.GenerationManifest(ctx, summary.BuiltGeneration)
		if err != nil {
			t.Fatal(err)
		}
		generationInfo, err = store.GetGeneration(ctx, summary.BuiltGeneration)
		if err != nil {
			t.Fatal(err)
		}
	}
	aliases := []string{}
	if addRPMAliases {
		objects, err := store.ListPackageObjects(ctx, []string{"el9"}, true)
		if err != nil || len(objects) == 0 {
			t.Fatalf("RPM objects=%#v err=%v", objects, err)
		}
		dist, err := store.GetDist(ctx, "el9")
		if err != nil {
			t.Fatal(err)
		}
		for _, architecture := range dist.Architectures {
			alias := filepath.ToSlash(filepath.Join("dists", "el9", architecture.Family, filepath.FromSlash(objects[0].PoolPath)))
			canonicalPath := filepath.Join(root, "repo", filepath.FromSlash(objects[0].PoolPath))
			aliasPath := filepath.Join(root, "repo", filepath.FromSlash(alias))
			if err := os.MkdirAll(filepath.Dir(aliasPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(canonicalPath, aliasPath); err != nil {
				t.Fatal(err)
			}
			manifest = append(manifest, state.GenerationFile{Path: alias, Phase: "payload", Size: objects[0].Size, SHA256: objects[0].SHA256})
			aliases = append(aliases, alias)
		}
		manifest, err = scanPublicManifestForLayout(ctx, filepath.Join(root, "repo"), state.LayoutC2V1)
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Slice(manifest, func(i, j int) bool { return manifest[i].Path < manifest[j].Path })
	_, manifestSHA, err := state.ManifestBytesForLayout(manifest, state.LayoutC2V1)
	if err != nil {
		t.Fatal(err)
	}
	previous := []state.GenerationFile{}
	if summary.BuiltGeneration > 0 && addRPMAliases {
		previous, err = store.GenerationManifest(ctx, generationInfo.PreviousGeneration)
		if err != nil {
			t.Fatal(err)
		}
	}
	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if summary.BuiltGeneration > 0 && addRPMAliases {
		if _, err := tx.ExecContext(ctx, `DELETE FROM generation_files WHERE generation = ?`, summary.BuiltGeneration); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		for _, file := range manifest {
			if _, err := tx.ExecContext(ctx, `INSERT INTO generation_files(generation, path, phase, size, sha256) VALUES (?, ?, ?, ?, ?)`, summary.BuiltGeneration, file.Path, file.Phase, file.Size, file.SHA256); err != nil {
				tx.Rollback()
				t.Fatal(err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE generations SET manifest_sha256 = ? WHERE generation = ?`, manifestSHA, summary.BuiltGeneration); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM operation_files WHERE operation_id = ?`, generationInfo.OperationID); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		for sequence, change := range state.DiffManifests(previous, manifest) {
			var size, digest any
			if change.Operation != "delete" {
				size, digest = change.Size, change.SHA256
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO operation_files(operation_id, sequence, action, phase, path, size, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)`, generationInfo.OperationID, sequence, change.Operation, change.Phase, change.Path, size, digest); err != nil {
				tx.Rollback()
				t.Fatal(err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE repository_state SET layout_version = ?, transition_receipt_sha256 = NULL WHERE singleton = 1`, state.LayoutC2ToSingleV1); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := store.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateGenerationLedger(ctx); err != nil {
		t.Fatalf("legacy C2 ledger: %v", err)
	}
	physical, err := scanPublicManifestForLayout(ctx, filepath.Join(root, "repo"), state.LayoutC2V1)
	if err != nil || !sameGenerationManifest(physical, manifest) {
		t.Fatalf("legacy physical=%#v manifest=%#v err=%v", physical, manifest, err)
	}
	return summary.BuiltGeneration, aliases, identity.RepositoryID
}

func rewriteConfigAsLegacyV2(t *testing.T, root string) {
	t.Helper()
	path := filepath.Join(root, config.ConfigFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := bytes.Replace(data, []byte("schema: "+config.Schema), []byte("schema: "+config.LegacySchema), 1)
	if bytes.Equal(data, legacy) {
		t.Fatal("canonical config schema was not replaced")
	}
	if err := os.WriteFile(path, legacy, 0o644); err != nil {
		t.Fatal(err)
	}
}

func manifestWithPrefix(manifest []state.GenerationFile, prefix string) []state.GenerationFile {
	result := []state.GenerationFile{}
	for _, file := range manifest {
		if strings.HasPrefix(file.Path, prefix) {
			result = append(result, file)
		}
	}
	return result
}

func rewriteRPMViewAsLegacyC2(t *testing.T, viewRoot string) {
	t.Helper()
	repomdPath := filepath.Join(viewRoot, "repodata", "repomd.xml")
	repomd, err := os.ReadFile(repomdPath)
	if err != nil {
		t.Fatal(err)
	}
	type value struct {
		Value string `xml:",chardata"`
	}
	var document struct {
		Data []struct {
			Type         string `xml:"type,attr"`
			Checksum     value  `xml:"checksum"`
			OpenChecksum value  `xml:"open-checksum"`
			Location     struct {
				Href string `xml:"href,attr"`
			} `xml:"location"`
			Size     int64 `xml:"size"`
			OpenSize int64 `xml:"open-size"`
		} `xml:"data"`
	}
	if err := xml.Unmarshal(repomd, &document); err != nil {
		t.Fatal(err)
	}
	primaryIndex := -1
	for index := range document.Data {
		if document.Data[index].Type == "primary" {
			primaryIndex = index
			break
		}
	}
	if primaryIndex < 0 {
		t.Fatal("repomd has no primary record")
	}
	record := document.Data[primaryIndex]
	artifactPath := filepath.Join(viewRoot, filepath.FromSlash(record.Location.Href))
	compressed, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	openBytes, readErr := io.ReadAll(reader)
	if err := errors.Join(readErr, reader.Close()); err != nil {
		t.Fatal(err)
	}
	legacyOpen := bytes.Replace(openBytes, []byte(`href="../../../pool/`), []byte(`href="pool/`), 1)
	if bytes.Equal(legacyOpen, openBytes) {
		t.Fatal("primary metadata had no parent-relative managed RPM href")
	}
	var compressedOutput bytes.Buffer
	writer := gzip.NewWriter(&compressedOutput)
	writer.Header.ModTime = time.Unix(0, 0).UTC()
	writer.Header.OS = 255
	if _, err := writer.Write(legacyOpen); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	newCompressed := compressedOutput.Bytes()
	compressedHash, openHash := sha256.Sum256(newCompressed), sha256.Sum256(legacyOpen)
	newCompressedSHA, newOpenSHA := hex.EncodeToString(compressedHash[:]), hex.EncodeToString(openHash[:])
	oldBase := filepath.Base(record.Location.Href)
	dash := strings.IndexByte(oldBase, '-')
	if dash < 0 {
		t.Fatalf("unexpected primary artifact %q", oldBase)
	}
	newHref := "repodata/" + newCompressedSHA + oldBase[dash:]
	newArtifactPath := filepath.Join(viewRoot, filepath.FromSlash(newHref))
	if err := os.WriteFile(newArtifactPath, newCompressed, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(artifactPath); err != nil {
		t.Fatal(err)
	}
	startMarker := []byte(`<data type="primary">`)
	start := bytes.Index(repomd, startMarker)
	if start < 0 {
		t.Fatal("repomd primary segment is unavailable")
	}
	endOffset := bytes.Index(repomd[start:], []byte(`</data>`))
	if endOffset < 0 {
		t.Fatal("repomd primary segment is unterminated")
	}
	end := start + endOffset + len(`</data>`)
	segment := string(repomd[start:end])
	replacements := [][2]string{
		{record.Checksum.Value, newCompressedSHA},
		{record.OpenChecksum.Value, newOpenSHA},
		{record.Location.Href, newHref},
		{fmt.Sprintf("<size>%d</size>", record.Size), fmt.Sprintf("<size>%d</size>", len(newCompressed))},
		{fmt.Sprintf("<open-size>%d</open-size>", record.OpenSize), fmt.Sprintf("<open-size>%d</open-size>", len(legacyOpen))},
	}
	for _, replacement := range replacements {
		updated := strings.Replace(segment, replacement[0], replacement[1], 1)
		if updated == segment && replacement[0] != replacement[1] {
			t.Fatalf("repomd primary replacement %q was absent", replacement[0])
		}
		segment = updated
	}
	updatedRepomd := append(append(append([]byte(nil), repomd[:start]...), []byte(segment)...), repomd[end:]...)
	if err := os.WriteFile(repomdPath, updatedRepomd, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateRejectsFreshC2BeforeSchemaOrConfigChanges(t *testing.T) {
	for _, version := range []int{12, state.SchemaVersion} {
		t.Run(fmt.Sprintf("schema-%d", version), func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			cfg := config.Default()
			cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{}}
			writeManagedConfig(t, root, cfg)
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			dbPath := filepath.Join(root, ".sow", "repo.db")
			store, err := state.OpenExisting(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.DB().Exec(`UPDATE repository_state SET layout_version = 'c2-v1' WHERE singleton = 1`); err != nil {
				t.Fatal(err)
			}
			if version == 12 {
				if _, err := store.DB().Exec(`DROP INDEX package_objects_pool_path_folded;
DROP INDEX publication_inventory_payload_path_folded;
DROP INDEX publication_abandoned_payload_path_folded;
DELETE FROM schema_migrations WHERE version = 13;
PRAGMA user_version = 12;`); err != nil {
					t.Fatal(err)
				}
			}
			if err := errors.Join(store.Checkpoint(ctx), store.Close()); err != nil {
				t.Fatal(err)
			}
			rewriteConfigAsLegacyV2(t, root)
			configPath := filepath.Join(root, config.ConfigFilename)
			beforeDB, err := os.ReadFile(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			beforeConfig, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := AbandonRepositoryMigration(ctx, RepositoryMigrationOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1}); err == nil {
				t.Fatal("abort accepted fresh C2 repository")
			}
			_, err = MigrateRepository(ctx, RepositoryMigrationOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
			if !errors.Is(err, ErrRejected) || !errors.Is(err, state.ErrLegacyLayout) || !strings.Contains(err.Error(), "import the original packages") {
				t.Fatalf("fresh C2 migration error=%v", err)
			}
			afterDB, dbErr := os.ReadFile(dbPath)
			afterConfig, configErr := os.ReadFile(configPath)
			if dbErr != nil || configErr != nil || !bytes.Equal(beforeDB, afterDB) || !bytes.Equal(beforeConfig, afterConfig) {
				t.Fatalf("rejection changed database or configuration: db=%v config=%v", dbErr, configErr)
			}
			reader, err := state.OpenReadOnly(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			identity, err := reader.RepositoryIdentity(ctx)
			if err != nil || reader.SchemaVersion() != version || identity.LayoutVersion != state.LayoutC2V1 {
				t.Fatalf("rejection changed schema/layout: version=%d identity=%v err=%v", reader.SchemaVersion(), identity, err)
			}
			journal, _, err := loadTransitionJournal(root, "repo")
			if err != nil || journal != nil {
				t.Fatalf("rejection wrote transition journal: %v %v", journal, err)
			}
		})
	}
}

func migrationAbortFixture(t *testing.T, stop string) (string, RepositoryMigrationOptions) {
	t.Helper()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(context.Background(), InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	prepareStartedC2MigrationFixture(t, root, false)
	opts := RepositoryMigrationOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1}
	injected := errors.New("migration fixture stop")
	opts.Fault = func(point string) error {
		if point == stop {
			return injected
		}
		return nil
	}
	if _, err := MigrateRepositoryLayout(context.Background(), opts); !errors.Is(err, injected) {
		t.Fatalf("migration at %s: %v", stop, err)
	}
	opts.Fault = nil
	return root, opts
}

func TestMigrationAbortAllowsExplicitRestart(t *testing.T) {
	for _, stop := range []string{"migrate.planned", "migrate.staged"} {
		t.Run(stop, func(t *testing.T) {
			root, opts := migrationAbortFixture(t, stop)
			journal, _, err := loadTransitionJournal(root, "repo")
			if err != nil || journal == nil {
				t.Fatal(err)
			}
			before, err := scanPublicManifestForLayout(context.Background(), filepath.Join(root, "repo"), state.LayoutC2V1)
			if err != nil {
				t.Fatal(err)
			}
			for attempt := range 2 {
				result, err := AbandonRepositoryMigration(context.Background(), opts)
				if err != nil || result.Phase != "abandoned" || result.Complete || result.RepositoryID != journal.RepositoryID || result.Generation != journal.BaseGeneration || result.FromLayout != state.LayoutC2V1 {
					t.Fatalf("abort %d result=%+v err=%v", attempt, result, err)
				}
				if _, err := os.Lstat(migrationStageRoot(root, "repo")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("stage remains: %v", err)
				}
				if remaining, _, err := loadTransitionJournal(root, "repo"); err != nil || remaining != nil {
					t.Fatalf("journal remains: %+v %v", remaining, err)
				}
				after, err := scanPublicManifestForLayout(context.Background(), filepath.Join(root, "repo"), state.LayoutC2V1)
				if err != nil || !sameGenerationManifest(before, after) {
					t.Fatalf("abort changed old public tree: %v", err)
				}
			}
			result, err := MigrateRepositoryLayout(context.Background(), opts)
			if err != nil || !result.Complete || result.RepositoryID != journal.RepositoryID || result.Generation != journal.BaseGeneration+1 {
				t.Fatalf("explicit restart result=%+v err=%v", result, err)
			}
		})
	}
}

func TestMigrationAbortWithoutJournalBeforeManifestBootstrap(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	prepareStartedC2MigrationFixture(t, root, false)
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	// An already-started legacy migration may have a Built generation whose
	// physical manifest has not yet been bootstrapped by planC2Transition.
	_, err = store.DB().ExecContext(ctx, `UPDATE repository_state SET built_generation = ? WHERE singleton = 1`, state.GenerationID(1))
	if err := errors.Join(err, store.Close()); err != nil {
		t.Fatal(err)
	}
	rewriteConfigAsLegacyV2(t, root)
	stopped := errors.New("stop before manifest bootstrap")
	opts := RepositoryMigrationOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1, Fault: func(point string) error {
		if point == "migrate.config" {
			return stopped
		}
		return nil
	}}
	if _, err := MigrateRepositoryLayout(ctx, opts); !errors.Is(err, stopped) {
		t.Fatalf("migration before bootstrap: %v", err)
	}
	if journal, _, err := loadTransitionJournal(root, "repo"); err != nil || journal != nil {
		t.Fatalf("unexpected journal: %+v %v", journal, err)
	}
	stage := migrationStageRoot(root, "repo")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "unknown"), []byte("retain before bootstrap"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts.Fault = nil
	for attempt := range 2 {
		result, err := AbandonRepositoryMigration(ctx, opts)
		if err != nil || result.Phase != "abandoned" || result.Repository != "repo" || result.Generation != 1 {
			t.Fatalf("abort %d before bootstrap: %+v %v", attempt, result, err)
		}
		if len(result.Warnings) != 1-attempt {
			t.Fatalf("abort %d warnings=%v", attempt, result.Warnings)
		}
	}
	if data, err := os.ReadFile(filepath.Join(retainedMigrationStage(t, root), "unknown")); err != nil || string(data) != "retain before bootstrap" {
		t.Fatalf("retained stage: %q %v", data, err)
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.GenerationManifest(ctx, 1); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("abort must not create a manifest baseline: %v", err)
	}
}

func TestMigrationAbortManifestErrorsPreserveCause(t *testing.T) {
	root, _ := migrationAbortFixture(t, "migrate.planned")
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	identity, err := store.RepositoryIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	journal, _, err := loadTransitionJournal(root, "repo")
	if err != nil || journal == nil {
		t.Fatalf("journal: %+v %v", journal, err)
	}
	journal.BaseGeneration = 1
	err = validateMigrationAbandon(context.Background(), store, identity, 1, journal, nil)
	if !errors.Is(err, ErrIntegrity) || !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("missing journal base must retain its integrity classification and cause: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = validateMigrationAbandon(ctx, store, identity, 1, journal, nil)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrIntegrity) {
		t.Fatalf("canceled manifest read must not become an integrity error: %v", err)
	}
}

func TestMigrationAbortRecoversCleanupBoundaries(t *testing.T) {
	for _, stop := range []string{"missing-stage", "migrate.abort_stage", "migrate.abort_state", "cancel-after-reset", "journal-unlink-permission"} {
		t.Run(stop, func(t *testing.T) {
			root, opts := migrationAbortFixture(t, "migrate.planned")
			if stop == "migrate.abort_stage" {
				if err := os.WriteFile(filepath.Join(migrationStageRoot(root, "repo"), "unknown"), []byte("preserve across interruption"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			injected := errors.New("abort cleanup stop")
			transitionRoot := filepath.Dir(transitionJournalPath(root, "repo"))
			if stop == "missing-stage" {
				if err := os.Remove(migrationStageRoot(root, "repo")); err != nil {
					t.Fatal(err)
				}
			}
			if stop == "journal-unlink-permission" {
				if os.Geteuid() == 0 {
					t.Skip("unlink permission regression requires an unprivileged user")
				}
				t.Cleanup(func() { _ = os.Chmod(transitionRoot, 0o700) })
			}
			opts.Fault = func(point string) error {
				if point == stop {
					return injected
				}
				if point == "migrate.abort_state" {
					if stop == "cancel-after-reset" {
						cancel()
					}
					if stop == "journal-unlink-permission" {
						return os.Chmod(transitionRoot, 0o500)
					}
				}
				return nil
			}
			result, err := AbandonRepositoryMigration(ctx, opts)
			if stop == "missing-stage" {
				if err != nil || result.Phase != "abandoned" {
					t.Fatalf("missing-stage result=%+v err=%v", result, err)
				}
			} else {
				if err == nil || result.Phase == "abandoned" {
					t.Fatalf("interrupted cleanup reported completion: %+v %v", result, err)
				}
				if stop == "cancel-after-reset" && !errors.Is(err, context.Canceled) || stop == "journal-unlink-permission" && !errors.Is(err, os.ErrPermission) {
					t.Fatalf("lost diagnostic for %s: %v", stop, err)
				}
				journal, _, readErr := loadTransitionJournal(root, "repo")
				if readErr != nil || journal == nil {
					t.Fatalf("lost recovery journal: %+v %v", journal, readErr)
				}
				store, openErr := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
				if openErr != nil {
					t.Fatal(openErr)
				}
				identity, identityErr := store.RepositoryIdentity(context.Background())
				control, controlErr := store.LayoutTransitionControl(context.Background())
				if e := errors.Join(identityErr, controlErr, store.Close()); e != nil || identity.LayoutVersion != state.LayoutC2ToSingleV1 || (control != nil) != (stop == "migrate.abort_stage") {
					t.Fatalf("reset state identity=%+v control=%+v err=%v", identity, control, e)
				}
			}
			if err := os.Chmod(transitionRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			opts.Fault = nil
			if result, err := AbandonRepositoryMigration(context.Background(), opts); err != nil || result.Phase != "abandoned" {
				t.Fatalf("repeat abort: %+v %v", result, err)
			}
			if result, err := MigrateRepositoryLayout(context.Background(), opts); err != nil || !result.Complete {
				t.Fatalf("replan: %+v %v", result, err)
			}
			if stop == "migrate.abort_stage" {
				if data, err := os.ReadFile(filepath.Join(retainedMigrationStage(t, root), "unknown")); err != nil || string(data) != "preserve across interruption" {
					t.Fatal("retry or replan changed the retained stage")
				}
			}
		})
	}
}

func TestMigrationAbortPreservesUnprovenStage(t *testing.T) {
	for _, change := range []string{"symlink", "regular-file", "unknown-file", "unknown-directory", "no-control", "no-journal"} {
		t.Run(change, func(t *testing.T) {
			root, opts := migrationAbortFixture(t, "migrate.planned")
			stage := migrationStageRoot(root, "repo")
			sentinel := filepath.Join(t.TempDir(), "sentinel")
			if err := os.WriteFile(sentinel, []byte("retain external bytes"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "symlink", "regular-file":
				if err := os.Remove(stage); err != nil {
					t.Fatal(err)
				}
				if change == "symlink" {
					if err := os.Symlink(filepath.Dir(sentinel), stage); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(stage, []byte("retain replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "unknown-file":
				if err := os.WriteFile(filepath.Join(stage, "unknown"), []byte("retain unknown"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "unknown-directory":
				if err := os.Mkdir(filepath.Join(stage, "unknown"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "no-control":
				store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
				if err != nil {
					t.Fatal(err)
				}
				_, err = store.DB().Exec(`DELETE FROM layout_transition_control`)
				if err := errors.Join(err, store.Checkpoint(context.Background()), store.Close()); err != nil {
					t.Fatal(err)
				}
			case "no-journal":
				if err := clearTransitionJournal(root, "repo"); err != nil {
					t.Fatal(err)
				}
			}
			before := migrationAbortNoFollowSnapshot(t, stage)
			result, err := AbandonRepositoryMigration(context.Background(), opts)
			if err != nil || result.Phase != "abandoned" {
				t.Fatalf("abort: %+v %v", result, err)
			}
			if change != "no-control" && change != "no-journal" {
				retained := stage
				if change != "symlink" {
					retained = retainedMigrationStage(t, root)
				}
				if after := migrationAbortNoFollowSnapshot(t, retained); !reflect.DeepEqual(before, after) {
					t.Fatal("abort changed retained bytes or entries")
				}
				if len(result.Warnings) == 0 {
					t.Fatal("retained stage was not reported")
				}
			}
			if data, err := os.ReadFile(sentinel); err != nil || string(data) != "retain external bytes" {
				t.Fatal("abort touched external bytes")
			}
			if journal, _, err := loadTransitionJournal(root, "repo"); err != nil || journal != nil {
				t.Fatalf("journal remains: %v %v", journal, err)
			}
			if change == "symlink" {
				if err := os.Remove(stage); err != nil {
					t.Fatal(err)
				}
			}
			if result, err := MigrateRepositoryLayout(context.Background(), opts); err != nil || !result.Complete {
				t.Fatalf("replan: %+v %v", result, err)
			}
			if _, err := LocalGC(context.Background(), LocalGCOptions{WorkspaceOptions: opts.WorkspaceOptions, Repository: "repo"}); err != nil {
				t.Fatalf("discarded migration output blocked GC: %v", err)
			}
		})
	}
}

func retainedMigrationStage(t *testing.T, root string) string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, ".sow", "repo", "abandoned", "c2-*"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("retained stages=%v err=%v", paths, err)
	}
	return paths[0]
}

func TestMigrationAbortWarnsOnStageLookupErrors(t *testing.T) {
	for _, failure := range []string{"permission", "not-directory"} {
		t.Run(failure, func(t *testing.T) {
			root, opts := migrationAbortFixture(t, "migrate.planned")
			stage := migrationStageRoot(root, "repo")
			parent := filepath.Dir(stage)
			if err := os.WriteFile(filepath.Join(stage, "unknown"), []byte("retain unknown"), 0o600); err != nil {
				t.Fatal(err)
			}
			if failure == "permission" {
				if os.Geteuid() == 0 {
					t.Skip("requires unprivileged filesystem permissions")
				}
				if err := os.Chmod(parent, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
			} else {
				if err := os.Rename(parent, parent+"-saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(parent, []byte("retain not-directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			result, err := AbandonRepositoryMigration(context.Background(), opts)
			if err != nil || result.Phase != "abandoned" || len(result.Warnings) != 1 {
				t.Fatalf("cleanup failure blocked abort: %+v %v", result, err)
			}
			if failure == "permission" {
				if err := os.Chmod(parent, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				if data, err := os.ReadFile(parent); err != nil || string(data) != "retain not-directory" {
					t.Fatal("abort changed parent replacement")
				}
				if err := os.Remove(parent); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(parent+"-saved", parent); err != nil {
					t.Fatal(err)
				}
			}
			// A later migration must preserve leftovers that abort could not move.
			result, err = MigrateRepositoryLayout(context.Background(), opts)
			if err != nil || !result.Complete || len(result.Warnings) != 1 {
				t.Fatalf("replan: %+v %v", result, err)
			}
			if data, err := os.ReadFile(filepath.Join(retainedMigrationStage(t, root), "unknown")); err != nil || string(data) != "retain unknown" {
				t.Fatal("replan discarded leftover stage")
			}
		})
	}
}

func TestMigrationAbortRejectsMismatchedAuthorityBeforeCleanup(t *testing.T) {
	for _, field := range []string{"repository", "generation", "base-manifest", "target-manifest", "control-repository", "control-generation", "control-plan", "control-repository-no-journal", "control-generation-no-journal"} {
		t.Run(field, func(t *testing.T) {
			root, opts := migrationAbortFixture(t, "migrate.planned")
			journal, _, err := loadTransitionJournal(root, "repo")
			if err != nil || journal == nil {
				t.Fatal(err)
			}
			switch field {
			case "repository":
				journal.RepositoryID = "00000000-0000-4000-8000-000000000000"
			case "generation":
				journal.BaseGeneration++
			case "base-manifest":
				journal.BaseManifestSHA256 = strings.Repeat("a", 64)
			case "target-manifest":
				journal.TargetManifestSHA256 = strings.Repeat("a", 64)
			default:
				store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
				if err != nil {
					t.Fatal(err)
				}
				queries := map[string]string{
					"control-repository": `UPDATE layout_transition_control SET repository_id = '00000000-0000-4000-8000-000000000000'`,
					"control-generation": `UPDATE layout_transition_control SET base_generation = '00000000000000000001'`,
					"control-plan":       `UPDATE layout_transition_control SET plan_identity_sha256 = '` + strings.Repeat("a", 64) + `'`,
				}
				_, err = store.DB().Exec(queries[strings.TrimSuffix(field, "-no-journal")])
				if err := errors.Join(err, store.Checkpoint(context.Background()), store.Close()); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasSuffix(field, "-no-journal") {
				err = clearTransitionJournal(root, "repo")
			} else {
				err = persistTransitionJournal(root, "repo", *journal)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := persistentWorkspaceSnapshot(t, root)
			if _, err := AbandonRepositoryMigration(context.Background(), opts); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("mismatched %s: %v", field, err)
			}
			if after := persistentWorkspaceSnapshot(t, root); !reflect.DeepEqual(before, after) {
				t.Fatal("rejected abort changed workspace bytes")
			}
		})
	}
}

func TestMigrationAbortRejectsCommitIntentFromEitherAuthority(t *testing.T) {
	for _, stop := range []string{"migrate.commit_anchored", "migrate.commit_intent", "migrate.final_manifest", "migrate.sqlite_committed", "journal-only"} {
		t.Run(stop, func(t *testing.T) {
			fixtureStop := stop
			if stop == "journal-only" {
				fixtureStop = "migrate.staged"
			}
			root, opts := migrationAbortFixture(t, fixtureStop)
			if stop == "journal-only" {
				journal, _, err := loadTransitionJournal(root, "repo")
				if err != nil || journal == nil {
					t.Fatal(err)
				}
				journal.Phase, journal.CommitIntent = "commit_intent", true
				if err := persistTransitionJournal(root, "repo", *journal); err != nil {
					t.Fatal(err)
				}
			}
			before := persistentWorkspaceSnapshot(t, root)
			if _, err := AbandonRepositoryMigration(context.Background(), opts); !errors.Is(err, ErrRejected) {
				t.Fatalf("postcommit abort: %v", err)
			}
			if after := persistentWorkspaceSnapshot(t, root); !reflect.DeepEqual(before, after) {
				t.Fatal("rejected postcommit abort changed bytes")
			}
			if stop != "journal-only" {
				if result, err := MigrateRepositoryLayout(context.Background(), opts); err != nil || !result.Complete {
					t.Fatalf("roll-forward result=%+v err=%v", result, err)
				}
			}
		})
	}
}

func TestMigrationAbortWarnsOnSymlinkStageAncestor(t *testing.T) {
	root, opts := migrationAbortFixture(t, "migrate.planned")
	owner := filepath.Dir(migrationStageRoot(root, "repo"))
	external := t.TempDir()
	sentinel := filepath.Join(external, "sentinel")
	if err := os.WriteFile(sentinel, []byte("retain external tree"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(owner, owner+"-saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, owner); err != nil {
		t.Fatal(err)
	}
	result, err := AbandonRepositoryMigration(context.Background(), opts)
	if err != nil || result.Phase != "abandoned" || len(result.Warnings) != 1 {
		t.Fatalf("abort: %+v %v", result, err)
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "retain external tree" {
		t.Fatal("abort changed external bytes")
	}
	if info, err := os.Lstat(owner); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("abort removed stage owner")
	}
	if _, err := MigrateRepositoryLayout(context.Background(), opts); err == nil {
		t.Fatal("new migration followed unsafe stage owner")
	}
}

func TestMigrationAbortPreservesDirectoryAddedAfterValidation(t *testing.T) {
	root, opts := migrationAbortFixture(t, "migrate.planned")
	unknown := filepath.Join(migrationStageRoot(root, "repo"), "unknown-empty-directory")
	opts.Fault = func(point string) error {
		if point == "migrate.abort_validated" {
			return os.Mkdir(unknown, 0o700)
		}
		return nil
	}
	result, err := AbandonRepositoryMigration(context.Background(), opts)
	if err != nil || result.Phase != "abandoned" || len(result.Warnings) != 1 {
		t.Fatalf("abort: %+v %v", result, err)
	}
	if info, err := os.Lstat(filepath.Join(retainedMigrationStage(t, root), "unknown-empty-directory")); err != nil || !info.IsDir() {
		t.Fatal("abort removed unknown directory")
	}
}

func TestMigrationAbortDoesNotRequireAHealthyPublicTree(t *testing.T) {
	root, opts := migrationAbortFixture(t, "migrate.planned")
	foreign := filepath.Join(root, "repo", "foreign")
	if err := os.WriteFile(foreign, []byte("preserve public bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if result, err := AbandonRepositoryMigration(context.Background(), opts); err != nil || result.Phase != "abandoned" {
		t.Fatalf("abort: %+v %v", result, err)
	}
	if data, err := os.ReadFile(foreign); err != nil || string(data) != "preserve public bytes" {
		t.Fatal("abort touched public data")
	}
	if _, err := MigrateRepositoryLayout(context.Background(), opts); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("replan must still validate public data: %v", err)
	}
}

func migrationAbortTwoViewFixture(t *testing.T) (string, RepositoryMigrationOptions) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9": {Format: "rpm", Architectures: []string{"aarch64", "x86_64"}},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "input.rpm")
	decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), input)
	opts := RepositoryMigrationOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1,
		now: func() time.Time { return time.Date(2026, 8, 5, 14, 0, 0, 0, time.UTC) }}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: opts.WorkspaceOptions, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	for _, architecture := range []string{"aarch64", "x86_64"} {
		rewriteRPMViewAsLegacyC2(t, filepath.Join(root, "repo", "dists", "el9", architecture))
	}
	prepareStartedC2MigrationFixture(t, root, true)
	stopped := errors.New("two view staged stop")
	opts.Fault = func(point string) error {
		if point == "migrate.staged" {
			return stopped
		}
		return nil
	}
	if _, err := MigrateRepositoryLayout(ctx, opts); !errors.Is(err, stopped) {
		t.Fatal(err)
	}
	opts.Fault = nil
	return root, opts
}

func migrationAbortNoFollowSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(name, ".db-shm") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		content := ""
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			content, err = os.Readlink(name)
		case info.Mode().IsRegular():
			var data []byte
			data, err = os.ReadFile(name)
			content = bytesSHA(data)
		}
		result[strings.TrimPrefix(name, root)+":"+info.Mode().String()] = content
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestMigrationAbortPartialStagePreservesUnprovenEntries(t *testing.T) {
	for _, mutation := range []string{"unknown-file", "unknown-directory", "artifact-tamper", "symlink", "stage-file", "no-repomd", "repomd-tamper", "journal-tamper", "no-control", "no-journal"} {
		t.Run(mutation, func(t *testing.T) {
			root, opts := migrationAbortTwoViewFixture(t)
			stage := migrationStageRoot(root, "repo")
			files, err := scanPublicManifest(context.Background(), stage)
			if err != nil || len(files) != 8 {
				t.Fatalf("stage files=%d err=%v", len(files), err)
			}
			// Also accept a partial cleanup left by older SOW versions.
			if err := os.Remove(filepath.Join(stage, files[0].Path)); err != nil {
				t.Fatal(err)
			}
			files = files[1:]
			artifact := filepath.Join(stage, files[0].Path)
			repomd := filepath.Join(filepath.Dir(artifact), "repomd.xml")
			external := filepath.Join(t.TempDir(), "sentinel")
			if err := os.WriteFile(external, []byte("retain external bytes"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "unknown-file":
				data := []byte("self consistent but not authorized")
				if err := os.WriteFile(filepath.Join(filepath.Dir(artifact), bytesSHA(data)+"-other.xml.gz"), data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "unknown-directory":
				if err := os.Mkdir(filepath.Join(filepath.Dir(artifact), "unknown-empty"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "artifact-tamper", "repomd-tamper":
				target := artifact
				if mutation == "repomd-tamper" {
					target = repomd
				}
				if err := os.WriteFile(target, []byte("changed bytes"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(artifact); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(external, artifact); err != nil {
					t.Fatal(err)
				}
			case "stage-file":
				if err := os.Rename(stage, stage+"-saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(stage, []byte("retain replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "no-repomd":
				if err := os.Remove(repomd); err != nil {
					t.Fatal(err)
				}
			case "journal-tamper":
				journal, _, err := loadTransitionJournal(root, "repo")
				if err != nil || journal == nil {
					t.Fatal(err)
				}
				journal.Pointers[0].NewSHA256 = strings.Repeat("b", 64)
				if err := persistTransitionJournal(root, "repo", *journal); err != nil {
					t.Fatal(err)
				}
			case "no-control":
				store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
				if err != nil {
					t.Fatal(err)
				}
				_, err = store.DB().Exec(`DELETE FROM layout_transition_control`)
				if err := errors.Join(err, store.Checkpoint(context.Background()), store.Close()); err != nil {
					t.Fatal(err)
				}
			case "no-journal":
				if err := clearTransitionJournal(root, "repo"); err != nil {
					t.Fatal(err)
				}
			}
			before := migrationAbortNoFollowSnapshot(t, stage)
			result, err := AbandonRepositoryMigration(context.Background(), opts)
			if mutation == "journal-tamper" {
				if !errors.Is(err, ErrIntegrity) {
					t.Fatalf("mismatched authority accepted: %v", err)
				}
				if after := migrationAbortNoFollowSnapshot(t, stage); !reflect.DeepEqual(before, after) {
					t.Fatal("rejected abort changed stage")
				}
				return
			}
			if err != nil || result.Phase != "abandoned" || len(result.Warnings) != 1 {
				t.Fatalf("abort: %+v %v", result, err)
			}
			retained := retainedMigrationStage(t, root)
			if after := migrationAbortNoFollowSnapshot(t, retained); !reflect.DeepEqual(before, after) {
				t.Fatal("abort changed retained bytes or entries")
			}
			result, err = MigrateRepositoryLayout(context.Background(), opts)
			if !errors.Is(err, ErrNotReady) || result.Phase != "grace" {
				t.Fatalf("replan: %+v %v", result, err)
			}
			if after := migrationAbortNoFollowSnapshot(t, retained); !reflect.DeepEqual(before, after) {
				t.Fatal("replan touched retained stage")
			}
			if data, err := os.ReadFile(external); err != nil || string(data) != "retain external bytes" {
				t.Fatal("rejected partial stage cleanup changed external sentinel")
			}
		})
	}
}
