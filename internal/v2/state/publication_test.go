package state

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func publicationStoreFixture(t testing.TB) (*Store, PublicationTargetBinding, []GenerationFile) {
	t.Helper()
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddDist(ctx, Dist{
		Name: "el9", Format: "rpm", EffectiveConfigSHA256: "fixture", BuiltGeneration: 0,
		Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}},
	}); err != nil {
		t.Fatal(err)
	}
	manifest := []GenerationFile{
		{Path: "dists/el9/x86_64/repodata/repomd.xml", Phase: "pointer", Size: 3, SHA256: strings.Repeat("3", 64)},
		{Path: "pool/p/pkg/pkg.rpm", Phase: "payload", Size: 1, SHA256: strings.Repeat("1", 64)},
	}
	_, manifestSHA, err := ManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := store.RepositoryIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES ('1', 'fixture', 'done', '{}', '{}', ?, ?)`, nowText(), nowText()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO operation_events(operation_id, sequence, state, detail_json, occurred_at) VALUES ('1', 0, 'planned', '{}', ?), ('1', 1, 'done', '{}', ?)`, nowText(), nowText()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO generations(generation, previous_generation, operation_id, manifest_sha256, renderer_identity, created_at) VALUES ('00000000000000000001', '00000000000000000000', '1', ?, ?, ?)`, manifestSHA, strings.Repeat("0", 64), nowText()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE repository_state SET built_generation = '00000000000000000001' WHERE singleton = 1;
UPDATE dists SET built_generation = '00000000000000000001' WHERE name = 'el9';
UPDATE dist_architectures SET built_generation = '00000000000000000001' WHERE dist_name = 'el9';
INSERT INTO generation_view_signers(generation, view_id, signer_identity, trusted_public_key) VALUES ('00000000000000000001', 'dists/el9/x86_64', 'none', NULL);`); err != nil {
		t.Fatal(err)
	}
	for _, file := range manifest {
		if _, err := store.DB().ExecContext(ctx, `INSERT INTO generation_files(generation, path, phase, size, sha256) VALUES ('00000000000000000001', ?, ?, ?, ?)`, file.Path, file.Phase, file.Size, file.SHA256); err != nil {
			t.Fatal(err)
		}
	}
	storageID := publicationIdentity("sow/target-storage/v1", "r2", "https://acct.r2.cloudflarestorage.com", "auto", "repo")
	binding := PublicationTargetBinding{
		TargetIdentity: publicationIdentity("sow/target/v1", storageID, "prod/repo"), TargetStorageID: storageID,
		RepositoryID: repository.RepositoryID, TargetName: "prod", Provider: "r2", Endpoint: "https://acct.r2.cloudflarestorage.com",
		Region: "auto", Bucket: "repo", Prefix: "prod/repo", PublicEndpoint: "https://repo.example.test/prod/repo/", MaxCacheTTL: 24 * time.Hour,
		AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true,
	}
	if err := store.BindPublicationTarget(ctx, binding); err != nil {
		t.Fatal(err)
	}
	return store, binding, manifest
}

func TestPublicationTargetBindingCacheTTLBoundary(t *testing.T) {
	for _, test := range []struct {
		name string
		ttl  time.Duration
		ok   bool
	}{
		{name: "maximum accepted", ttl: maximumPublicationCacheTTL, ok: true},
		{name: "maximum plus one rejected", ttl: maximumPublicationCacheTTL + time.Nanosecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, binding, _ := publicationStoreFixture(t)
			defer store.Close()
			binding.TargetName = "boundary"
			binding.Prefix = "boundary/repo"
			binding.TargetStorageID, binding.TargetIdentity = "", ""
			binding.MaxCacheTTL = test.ttl
			binding.ConfigIdentity = ""
			err := store.BindPublicationTarget(context.Background(), binding)
			if test.ok && err != nil || !test.ok && err == nil {
				t.Fatalf("ttl=%s ok=%t err=%v", test.ttl, test.ok, err)
			}
		})
	}
}

func TestPublicationTargetBindingRevisionsAreAppendOnlyAndRebindKeepsStableIdentity(t *testing.T) {
	ctx := context.Background()
	store, binding, manifest := publicationStoreFixture(t)
	defer store.Close()

	revisions, err := store.ListPublicationTargetBindingRevisions(ctx, binding.TargetIdentity)
	if err != nil || len(revisions) != 1 || revisions[0].Revision != 1 || revisions[0].Reason != "initial_bind" || revisions[0].OperatorConfirmed {
		t.Fatalf("initial revisions=%#v err=%v", revisions, err)
	}
	_, manifestSHA, err := ManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	attempt := PublicationAttempt{
		RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1,
		ManifestSHA256: manifestSHA, PlanSHA256: strings.Repeat("b", 64), Phase: "planned",
		Views: []PublicationAttemptView{{ViewID: "dists/el9/x86_64", PointerPath: manifest[0].Path, NewIdentity: manifest[0].SHA256, State: "pending"}},
	}
	if err := store.PutPublicationAttempt(ctx, &attempt); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"payload", "immutable_metadata", "pointer_prepared"} {
		if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetPublicationAttemptViewState(ctx, attempt.AttemptIdentity, attempt.Views[0].ViewID, attempt.Views[0].PointerPath, "prepared"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPublicationCommitIntent(ctx, attempt.AttemptIdentity); err != nil {
		t.Fatal(err)
	}

	rebound := binding
	rebound.TargetName = "prod-fixed"
	rebound.PublicEndpoint = "https://fixed.example.test/prod/repo/"
	rebound.MaxCacheTTL = 48 * time.Hour
	rebound.ConfigIdentity = ""
	input := PublicationTargetRebind{Binding: rebound, Reason: "operator_endpoint_fix", OperatorConfirmed: true}
	if err := store.RebindPublicationTarget(ctx, input); err != nil {
		t.Fatal(err)
	}
	if err := store.RebindPublicationTarget(ctx, input); err != nil {
		t.Fatalf("idempotent rebind: %v", err)
	}
	target, err := store.GetPublicationTarget(ctx, binding.TargetIdentity)
	if err != nil || target.Binding.TargetIdentity != binding.TargetIdentity || target.Binding.TargetStorageID != binding.TargetStorageID ||
		target.Binding.TargetName != rebound.TargetName || target.Binding.PublicEndpoint != rebound.PublicEndpoint || target.Binding.MaxCacheTTL != rebound.MaxCacheTTL {
		t.Fatalf("rebound target=%#v err=%v", target, err)
	}
	active, err := store.GetActivePublicationAttempt(ctx, binding.TargetIdentity)
	if err != nil || active.AttemptIdentity != attempt.AttemptIdentity || !active.CommitIntent {
		t.Fatalf("active attempt after rebind=%#v err=%v", active, err)
	}
	revisions, err = store.ListPublicationTargetBindingRevisions(ctx, binding.TargetIdentity)
	if err != nil || len(revisions) != 2 || revisions[1].Revision != 2 || revisions[1].Reason != input.Reason || !revisions[1].OperatorConfirmed || revisions[1].ConfigIdentity != target.Binding.ConfigIdentity {
		t.Fatalf("rebind revisions=%#v err=%v", revisions, err)
	}
	if _, err := store.DB().Exec(`UPDATE publication_target_binding_revisions SET reason = 'tampered' WHERE target_identity = ? AND revision = 1`, binding.TargetIdentity); err == nil {
		t.Fatal("binding revision UPDATE succeeded")
	}
	if _, err := store.DB().Exec(`DELETE FROM publication_target_binding_revisions WHERE target_identity = ? AND revision = 1`, binding.TargetIdentity); err == nil {
		t.Fatal("binding revision DELETE succeeded")
	}
	tampered := target.Binding
	tampered.PublicEndpoint = "https://tampered.example.test/prod/repo/"
	tampered.ConfigIdentity = PublicationTargetConfigIdentity(tampered)
	if _, err := store.DB().Exec(`UPDATE publication_target_bindings SET public_endpoint = ?, config_identity = ? WHERE target_identity = ?`, tampered.PublicEndpoint, tampered.ConfigIdentity, binding.TargetIdentity); err != nil {
		t.Fatal(err)
	}
	if err := store.Check(ctx); err == nil {
		t.Fatal("Store.Check accepted a binding projection not present in revision history")
	}
}

func TestPublicationTargetRebindRejectsUnconfirmedAndImmutableChanges(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name   string
		mutate func(*PublicationTargetBinding)
	}{
		{name: "storage endpoint", mutate: func(binding *PublicationTargetBinding) { binding.Endpoint = "https://other.r2.cloudflarestorage.com" }},
		{name: "bucket", mutate: func(binding *PublicationTargetBinding) { binding.Bucket = "other" }},
		{name: "prefix", mutate: func(binding *PublicationTargetBinding) { binding.Prefix = "other/repo" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, binding, _ := publicationStoreFixture(t)
			defer store.Close()
			test.mutate(&binding)
			binding.TargetStorageID, binding.TargetIdentity, binding.ConfigIdentity = "", "", ""
			err := store.RebindPublicationTarget(ctx, PublicationTargetRebind{Binding: binding, Reason: "operator_change", OperatorConfirmed: true})
			if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "new target") {
				t.Fatalf("immutable rebind error=%v", err)
			}
		})
	}
	store, binding, _ := publicationStoreFixture(t)
	defer store.Close()
	binding.PublicEndpoint = "https://fixed.example.test/prod/repo/"
	binding.ConfigIdentity = ""
	if err := store.RebindPublicationTarget(ctx, PublicationTargetRebind{Binding: binding, Reason: "operator_change"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("unconfirmed rebind error=%v", err)
	}
}

func TestV12MigrationBackfillsInitialPublicationTargetRevision(t *testing.T) {
	ctx := context.Background()
	store, binding, _ := publicationStoreFixture(t)
	path := store.path
	if _, err := store.DB().Exec(`DROP TABLE publication_target_binding_revisions;
DROP INDEX package_objects_pool_path_folded;
DROP INDEX publication_inventory_payload_path_folded;
DROP INDEX publication_abandoned_payload_path_folded;
DELETE FROM schema_migrations WHERE version IN (12, 13);
PRAGMA user_version = 11;`); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := OpenExistingForMigration(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	revisions, err := migrated.ListPublicationTargetBindingRevisions(ctx, binding.TargetIdentity)
	if err != nil || len(revisions) != 1 || revisions[0].Reason != "backfill" || revisions[0].OperatorConfirmed || revisions[0].Revision != 1 {
		t.Fatalf("backfilled revisions=%#v err=%v", revisions, err)
	}
}

func TestPublicationTargetRebindUsesCurrentTTLWithoutRewritingHistoricalGrace(t *testing.T) {
	ctx := context.Background()
	store, binding, manifest := publicationStoreFixture(t)
	defer store.Close()
	now := time.Now().UTC()
	_, checkpoint, grace := seedPublicationGrace(t, store, binding, manifest, now.Add(-45*24*time.Hour))
	historicalNotBefore := grace.NotBefore

	increased := binding
	increased.MaxCacheTTL = 60 * 24 * time.Hour
	increased.ConfigIdentity = ""
	if err := store.RebindPublicationTarget(ctx, PublicationTargetRebind{Binding: increased, Reason: "operator_cache_increase", OperatorConfirmed: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ExactPublicationCandidates(ctx, checkpoint.CheckpointIdentity, now); !errors.Is(err, ErrTransition) {
		t.Fatalf("increased current TTL did not extend deletion eligibility: %v", err)
	}
	storedGrace, err := store.GetGraceRecord(ctx, checkpoint.CheckpointIdentity)
	if err != nil || !storedGrace.NotBefore.Equal(historicalNotBefore) {
		t.Fatalf("historical grace was rewritten: %#v err=%v", storedGrace, err)
	}

	reduced := increased
	reduced.MaxCacheTTL = 24 * time.Hour
	reduced.ConfigIdentity = ""
	if err := store.RebindPublicationTarget(ctx, PublicationTargetRebind{Binding: reduced, Reason: "operator_cache_reduce", OperatorConfirmed: true}); err != nil {
		t.Fatal(err)
	}
	candidates, err := store.ExactPublicationCandidates(ctx, checkpoint.CheckpointIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	report := PublicationCandidateReport{
		TargetIdentity: binding.TargetIdentity, CheckpointIdentity: checkpoint.CheckpointIdentity,
		InventoryIdentity: checkpoint.InventoryIdentity, Mode: "report_only", Candidates: candidates, CreatedAt: now,
	}
	if err := store.PutPublicationCandidateReport(ctx, &report); err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []time.Duration{time.Hour, 72 * time.Hour} {
		blocked := reduced
		blocked.MaxCacheTTL = ttl
		blocked.ConfigIdentity = ""
		if err := store.RebindPublicationTarget(ctx, PublicationTargetRebind{Binding: blocked, Reason: "operator_pending_ttl", OperatorConfirmed: true}); !errors.Is(err, ErrConflict) {
			t.Fatalf("pending maintenance TTL %s rebind error=%v", ttl, err)
		}
	}
	endpointOnly := reduced
	endpointOnly.PublicEndpoint = "https://fixed.example.test/prod/repo/"
	endpointOnly.ConfigIdentity = ""
	if err := store.RebindPublicationTarget(ctx, PublicationTargetRebind{Binding: endpointOnly, Reason: "operator_report_only_endpoint", OperatorConfirmed: true}); err != nil {
		t.Fatalf("R2 report-only endpoint rebind: %v", err)
	}
}

func TestFilesystemConditionalDeleteBlocksEndpointRebind(t *testing.T) {
	ctx := context.Background()
	store, original, manifest := publicationStoreFixture(t)
	defer store.Close()
	binding := PublicationTargetBinding{
		RepositoryID: original.RepositoryID, TargetName: "filesystem", Provider: "filesystem",
		Endpoint: "file:///srv/publication", Prefix: "prod/repo", PublicEndpoint: "https://cdn.example.test/prod/repo/",
		MaxCacheTTL: 24 * time.Hour, AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true,
	}
	if err := store.BindPublicationTarget(ctx, binding); err != nil {
		t.Fatal(err)
	}
	binding.TargetStorageID = publicationIdentity("sow/target-storage/v1", binding.Provider, binding.Endpoint, binding.Region, binding.Bucket)
	binding.TargetIdentity = publicationIdentity("sow/target/v1", binding.TargetStorageID, binding.Prefix)
	now := time.Now().UTC()
	_, checkpoint, _ := seedPublicationGrace(t, store, binding, manifest, now.Add(-45*24*time.Hour))
	candidates, err := store.ExactPublicationCandidates(ctx, checkpoint.CheckpointIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	report := PublicationCandidateReport{
		TargetIdentity: binding.TargetIdentity, CheckpointIdentity: checkpoint.CheckpointIdentity,
		InventoryIdentity: checkpoint.InventoryIdentity, Mode: "conditional_delete", Candidates: candidates, CreatedAt: now,
	}
	if err := store.PutPublicationCandidateReport(ctx, &report); err != nil {
		t.Fatal(err)
	}
	rebound := binding
	rebound.PublicEndpoint = "https://other.example.test/prod/repo/"
	rebound.ConfigIdentity = ""
	if err := store.RebindPublicationTarget(ctx, PublicationTargetRebind{Binding: rebound, Reason: "operator_endpoint_change", OperatorConfirmed: true}); !errors.Is(err, ErrConflict) {
		t.Fatalf("conditional-delete endpoint rebind error=%v", err)
	}
}

func seedPublicationGrace(t testing.TB, store *Store, binding PublicationTargetBinding, manifest []GenerationFile, appliedAt time.Time) (PublicationAttempt, AppliedCheckpoint, GraceRecord) {
	t.Helper()
	ctx := context.Background()
	_, manifestSHA, err := ManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	attempt := PublicationAttempt{
		RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1,
		ManifestSHA256: manifestSHA, PlanSHA256: strings.Repeat("9", 64), Phase: "planned", Views: []PublicationAttemptView{},
	}
	if err := store.PutPublicationAttempt(ctx, &attempt); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"payload", "immutable_metadata", "pointer_prepared"} {
		if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetPublicationCommitIntent(ctx, attempt.AttemptIdentity); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"pointer_rollforward", "verified"} {
		if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
			t.Fatal(err)
		}
	}
	inventory := make([]PublicationInventoryObject, 0, len(manifest))
	for _, file := range manifest {
		inventory = append(inventory, PublicationInventoryObject{Path: file.Path, Phase: file.Phase, Size: file.Size, SHA256: file.SHA256, RemoteIdentity: "remote-" + file.SHA256})
	}
	checkpoint := AppliedCheckpoint{
		RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: attempt.AttemptIdentity,
		Generation: 1, ManifestSHA256: manifestSHA, InventoryComplete: true, Views: []PublicationCheckpointView{},
		Inventory: inventory, AppliedAt: appliedAt,
	}
	if err := store.PutAppliedCheckpoint(ctx, &checkpoint); err != nil {
		t.Fatal(err)
	}
	grace := GraceRecord{
		TargetIdentity: binding.TargetIdentity, CheckpointIdentity: checkpoint.CheckpointIdentity,
		VerifiedAt: appliedAt, NotBefore: appliedAt.Add(30 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("c", 64),
	}
	if err := store.PutGraceRecord(ctx, &grace); err != nil {
		t.Fatal(err)
	}
	return attempt, checkpoint, grace
}

func TestPublicationStatePersistsPrivateRecordsAndTextGeneration(t *testing.T) {
	ctx := context.Background()
	store, binding, manifest := publicationStoreFixture(t)
	defer store.Close()
	for _, replay := range []PublicationTargetBinding{binding, func() PublicationTargetBinding {
		canonical := binding
		canonical.ConfigIdentity = PublicationTargetConfigIdentity(canonical)
		return canonical
	}()} {
		if err := store.BindPublicationTarget(ctx, replay); err != nil {
			t.Fatalf("binding replay: %v", err)
		}
	}
	badBindingIdentity := binding
	badBindingIdentity.ConfigIdentity = strings.Repeat("f", 64)
	if err := store.BindPublicationTarget(ctx, badBindingIdentity); !errors.Is(err, ErrConflict) {
		t.Fatalf("noncanonical binding identity error=%v", err)
	}
	differentBinding := binding
	differentBinding.PublicEndpoint = "https://other.example.test/prod/repo/"
	if err := store.BindPublicationTarget(ctx, differentBinding); !errors.Is(err, ErrConflict) {
		t.Fatalf("different binding semantics error=%v", err)
	}
	_, manifestSHA, _ := ManifestBytes(manifest)
	attempt := PublicationAttempt{
		RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1,
		ManifestSHA256: manifestSHA, PlanSHA256: strings.Repeat("b", 64), Phase: "planned",
		Views: []PublicationAttemptView{{ViewID: "dists/el9/x86_64", PointerPath: "dists/el9/x86_64/repodata/repomd.xml", NewIdentity: manifest[0].SHA256, State: "pending"}},
	}
	if err := store.PutPublicationAttempt(ctx, &attempt); err != nil {
		t.Fatal(err)
	}
	badAttemptIdentity := attempt
	badAttemptIdentity.AttemptIdentity = strings.Repeat("f", 64)
	if err := store.PutPublicationAttempt(ctx, &badAttemptIdentity); !errors.Is(err, ErrConflict) {
		t.Fatalf("noncanonical attempt identity error=%v", err)
	}
	differentAttempt := attempt
	differentAttempt.PlanSHA256 = strings.Repeat("c", 64)
	if err := store.PutPublicationAttempt(ctx, &differentAttempt); !errors.Is(err, ErrConflict) {
		t.Fatalf("different attempt semantics error=%v", err)
	}
	for _, next := range []string{"payload", "immutable_metadata", "pointer_prepared"} {
		for replay := 0; replay < 2; replay++ {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, next); err != nil {
				t.Fatalf("advance %s replay %d: %v", next, replay, err)
			}
		}
	}
	for replay := 0; replay < 2; replay++ {
		if err := store.SetPublicationAttemptViewState(ctx, attempt.AttemptIdentity, attempt.Views[0].ViewID, attempt.Views[0].PointerPath, "prepared"); err != nil {
			t.Fatalf("prepare view replay %d: %v", replay, err)
		}
	}
	for replay := 0; replay < 2; replay++ {
		if err := store.SetPublicationCommitIntent(ctx, attempt.AttemptIdentity); err != nil {
			t.Fatalf("commit intent replay %d: %v", replay, err)
		}
	}
	for replay := 0; replay < 2; replay++ {
		if err := store.SetPublicationAttemptViewState(ctx, attempt.AttemptIdentity, attempt.Views[0].ViewID, attempt.Views[0].PointerPath, "applied"); err != nil {
			t.Fatalf("apply view replay %d: %v", replay, err)
		}
	}
	for replay := 0; replay < 2; replay++ {
		if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, "pointer_rollforward"); err != nil {
			t.Fatalf("roll forward replay %d: %v", replay, err)
		}
	}
	for replay := 0; replay < 2; replay++ {
		if err := store.SetPublicationAttemptViewState(ctx, attempt.AttemptIdentity, attempt.Views[0].ViewID, attempt.Views[0].PointerPath, "verified"); err != nil {
			t.Fatalf("verify view replay %d: %v", replay, err)
		}
	}
	for replay := 0; replay < 2; replay++ {
		if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, "verified"); err != nil {
			t.Fatalf("verify attempt replay %d: %v", replay, err)
		}
	}
	inventory := []PublicationInventoryObject{
		{Path: manifest[0].Path, Phase: manifest[0].Phase, Size: manifest[0].Size, SHA256: manifest[0].SHA256, RemoteIdentity: "etag-pointer"},
		{Path: manifest[1].Path, Phase: manifest[1].Phase, Size: manifest[1].Size, SHA256: manifest[1].SHA256, RemoteIdentity: "etag-payload"},
		{Path: "pool/z/retained-old.rpm", Phase: "payload", Size: 9, SHA256: strings.Repeat("e", 64), RemoteIdentity: "etag-retained"},
	}
	verified := time.Now().UTC().Add(-31 * 24 * time.Hour)
	checkpoint := AppliedCheckpoint{
		RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: attempt.AttemptIdentity, Generation: 1, ManifestSHA256: manifestSHA, InventoryComplete: true,
		Views: []PublicationCheckpointView{{ViewID: "dists/el9/x86_64", PointerPath: manifest[0].Path, RemoteIdentity: "etag-new"}}, Inventory: inventory, AppliedAt: verified,
	}
	incomplete := checkpoint
	incomplete.InventoryComplete = false
	if err := store.PutAppliedCheckpoint(ctx, &incomplete); err == nil {
		t.Fatal("incomplete checkpoint advanced target head")
	}
	missingClosure := checkpoint
	missingClosure.Inventory = append([]PublicationInventoryObject(nil), inventory[1:]...)
	if err := store.PutAppliedCheckpoint(ctx, &missingClosure); err == nil {
		t.Fatal("checkpoint missing Generation closure advanced target head")
	}
	var revision, emptyHead int
	if err := store.DB().QueryRow(`SELECT revision, checkpoint_identity IS NULL FROM publication_target_heads WHERE target_identity = ?`, binding.TargetIdentity).Scan(&revision, &emptyHead); err != nil || revision != 0 || emptyHead != 1 {
		t.Fatalf("rejected checkpoint changed head: revision=%d empty=%d err=%v", revision, emptyHead, err)
	}
	badInventoryIdentity := checkpoint
	badInventoryIdentity.InventoryIdentity = strings.Repeat("f", 64)
	if err := store.PutAppliedCheckpoint(ctx, &badInventoryIdentity); !errors.Is(err, ErrConflict) {
		t.Fatalf("noncanonical inventory identity error=%v", err)
	}
	badCheckpointIdentity := checkpoint
	badCheckpointIdentity.CheckpointIdentity = strings.Repeat("f", 64)
	if err := store.PutAppliedCheckpoint(ctx, &badCheckpointIdentity); !errors.Is(err, ErrConflict) {
		t.Fatalf("noncanonical checkpoint identity error=%v", err)
	}
	for replay := 0; replay < 2; replay++ {
		if err := store.PutAppliedCheckpoint(ctx, &checkpoint); err != nil {
			t.Fatalf("checkpoint replay %d: %v", replay, err)
		}
	}
	differentCheckpoint := checkpoint
	differentCheckpoint.Inventory = append([]PublicationInventoryObject(nil), checkpoint.Inventory...)
	differentCheckpoint.Inventory[2].RemoteIdentity = "etag-different"
	if err := store.PutAppliedCheckpoint(ctx, &differentCheckpoint); !errors.Is(err, ErrConflict) {
		t.Fatalf("different checkpoint semantics error=%v", err)
	}
	if err := store.DB().QueryRow(`SELECT revision, checkpoint_identity IS NULL FROM publication_target_heads WHERE target_identity = ?`, binding.TargetIdentity).Scan(&revision, &emptyHead); err != nil || revision != 1 || emptyHead != 0 {
		t.Fatalf("checkpoint replay changed head more than once: revision=%d empty=%d err=%v", revision, emptyHead, err)
	}
	if _, err := store.DB().Exec(`UPDATE publication_target_bindings SET max_cache_ttl_ns = ? WHERE target_identity = ?`, int64(maximumPublicationCacheTTL)+1, binding.TargetIdentity); err != nil {
		t.Fatal(err)
	}
	overflow := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: checkpoint.CheckpointIdentity, VerifiedAt: verified, NotBefore: verified.Add(30 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("d", 64)}
	if err := store.PutGraceRecord(ctx, &overflow); err == nil || !strings.Contains(err.Error(), "invalid publication cache TTL") {
		t.Fatalf("overflowing stored TTL grace error=%v", err)
	}
	if _, err := store.DB().Exec(`UPDATE publication_target_bindings SET max_cache_ttl_ns = ? WHERE target_identity = ?`, binding.MaxCacheTTL.Nanoseconds(), binding.TargetIdentity); err != nil {
		t.Fatal(err)
	}
	short := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: checkpoint.CheckpointIdentity, VerifiedAt: verified, NotBefore: verified.Add(29 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("c", 64)}
	if err := store.PutGraceRecord(ctx, &short); !errors.Is(err, ErrConflict) {
		t.Fatalf("short grace error=%v", err)
	}
	grace := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: checkpoint.CheckpointIdentity, VerifiedAt: verified, NotBefore: verified.Add(30 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("c", 64)}
	badGraceIdentity := grace
	badGraceIdentity.GraceIdentity = strings.Repeat("f", 64)
	if err := store.PutGraceRecord(ctx, &badGraceIdentity); !errors.Is(err, ErrConflict) {
		t.Fatalf("noncanonical grace identity error=%v", err)
	}
	for replay := 0; replay < 2; replay++ {
		if err := store.PutGraceRecord(ctx, &grace); err != nil {
			t.Fatalf("grace replay %d: %v", replay, err)
		}
	}
	differentGrace := grace
	differentGrace.NotBefore = grace.NotBefore.Add(time.Hour)
	if err := store.PutGraceRecord(ctx, &differentGrace); !errors.Is(err, ErrConflict) {
		t.Fatalf("different grace semantics error=%v", err)
	}
	report := PublicationCandidateReport{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: checkpoint.CheckpointIdentity, InventoryIdentity: checkpoint.InventoryIdentity, Mode: "report_only", Candidates: []PublicationCandidate{{Path: "pool/z/retained-old.rpm", Phase: "payload", Size: 9, SHA256: strings.Repeat("e", 64), RemoteIdentity: "etag-retained"}}}
	badReportIdentity := report
	badReportIdentity.ReportIdentity = strings.Repeat("f", 64)
	if err := store.PutPublicationCandidateReport(ctx, &badReportIdentity); !errors.Is(err, ErrConflict) {
		t.Fatalf("noncanonical report identity error=%v", err)
	}
	pointerCandidate := report
	pointerCandidate.Candidates = append([]PublicationCandidate(nil), report.Candidates...)
	pointerCandidate.Candidates[0].Phase = "pointer"
	if err := store.PutPublicationCandidateReport(ctx, &pointerCandidate); err == nil {
		t.Fatal("pointer retention candidate accepted")
	}
	for replay := 0; replay < 2; replay++ {
		if err := store.PutPublicationCandidateReport(ctx, &report); err != nil {
			t.Fatalf("candidate report replay %d: %v", replay, err)
		}
	}
	conditional := PublicationCandidateReport{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: checkpoint.CheckpointIdentity, InventoryIdentity: checkpoint.InventoryIdentity, Mode: "conditional_delete", Candidates: report.Candidates}
	if err := store.PutPublicationCandidateReport(ctx, &conditional); !errors.Is(err, ErrConflict) {
		t.Fatalf("R2 conditional delete report error=%v", err)
	}
	differentReport := report
	differentReport.Candidates = append([]PublicationCandidate(nil), report.Candidates...)
	differentReport.Candidates[0].RemoteIdentity = "etag-different"
	if err := store.PutPublicationCandidateReport(ctx, &differentReport); !errors.Is(err, ErrConflict) {
		t.Fatalf("different report semantics error=%v", err)
	}
	for _, blocked := range []string{"deletion_verified", "retained_reported", "done"} {
		if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, blocked); err == nil {
			t.Fatalf("generic Advance entered %s", blocked)
		}
	}
	if err := store.MarkPublicationRetainedReported(ctx, attempt.AttemptIdentity, report.ReportIdentity, grace.NotBefore.Add(-time.Nanosecond)); !errors.Is(err, ErrTransition) {
		t.Fatalf("retention accepted before grace expiry: %v", err)
	}
	requirement, err := store.PublicationRootRequirement(ctx)
	if err != nil || !requirement.HasEvidence || !requirement.StateComplete || len(requirement.MinimumRoots) != 2 || requirement.MinimumRoots[0].Path != manifest[1].Path || requirement.MinimumRoots[1].Path != "pool/z/retained-old.rpm" {
		t.Fatalf("unresolved grace root requirement=%#v err=%v", requirement, err)
	}
	if _, err := store.DB().Exec(`UPDATE publication_checkpoints SET inventory_complete = 0 WHERE checkpoint_identity = ?`, checkpoint.CheckpointIdentity); err != nil {
		t.Fatal(err)
	}
	incompleteRequirement, err := store.PublicationRootRequirement(ctx)
	if err != nil || incompleteRequirement.StateComplete {
		t.Fatalf("incomplete checkpoint attestation=%#v err=%v", incompleteRequirement, err)
	}
	if _, err := store.DB().Exec(`UPDATE publication_checkpoints SET inventory_complete = 1 WHERE checkpoint_identity = ?`, checkpoint.CheckpointIdentity); err != nil {
		t.Fatal(err)
	}
	for replay := 0; replay < 2; replay++ {
		if err := store.MarkPublicationRetainedReported(ctx, attempt.AttemptIdentity, report.ReportIdentity, grace.NotBefore); err != nil {
			t.Fatalf("retained report replay %d: %v", replay, err)
		}
	}
	var phase, graceState string
	if err := store.DB().QueryRow(`SELECT a.phase, g.state FROM publication_attempts AS a JOIN publication_checkpoints AS c ON c.attempt_identity = a.attempt_identity JOIN publication_grace_records AS g ON g.checkpoint_identity = c.checkpoint_identity WHERE a.attempt_identity = ?`, attempt.AttemptIdentity).Scan(&phase, &graceState); err != nil || phase != "retained_reported" || graceState != "retained_reported" {
		t.Fatalf("retention state phase=%q grace=%q err=%v", phase, graceState, err)
	}
	requirement, err = store.PublicationRootRequirement(ctx)
	if err != nil || len(requirement.MinimumRoots) != 1 || requirement.MinimumRoots[0].Path != manifest[1].Path {
		t.Fatalf("post-retention roots=%#v err=%v", requirement, err)
	}
	for replay := 0; replay < 2; replay++ {
		if err := store.CompletePublicationAttempt(ctx, attempt.AttemptIdentity, report.ReportIdentity); err != nil {
			t.Fatalf("completion replay %d: %v", replay, err)
		}
	}
	if err := store.MarkPublicationRetainedReported(ctx, attempt.AttemptIdentity, report.ReportIdentity, grace.NotBefore); err != nil {
		t.Fatalf("retained report replay after completion: %v", err)
	}
	if err := store.PutPublicationAttempt(ctx, &attempt); err != nil {
		t.Fatalf("attempt replay after completion: %v", err)
	}
	if err := store.PutAppliedCheckpoint(ctx, &checkpoint); err != nil {
		t.Fatalf("checkpoint replay after completion: %v", err)
	}
	if err := store.PutGraceRecord(ctx, &grace); err != nil {
		t.Fatalf("grace replay after completion: %v", err)
	}
	if err := store.PutPublicationCandidateReport(ctx, &report); err != nil {
		t.Fatalf("report replay after completion: %v", err)
	}
	if err := store.SetPublicationCommitIntent(ctx, attempt.AttemptIdentity); err != nil {
		t.Fatalf("commit-intent replay after completion: %v", err)
	}
	if err := store.SetPublicationAttemptViewState(ctx, attempt.AttemptIdentity, attempt.Views[0].ViewID, attempt.Views[0].PointerPath, "verified"); err != nil {
		t.Fatalf("view replay after completion: %v", err)
	}
	if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, "verified"); err != nil {
		t.Fatalf("phase replay after completion: %v", err)
	}
	requirement, err = store.PublicationRootRequirement(ctx)
	if err != nil || !requirement.StateComplete || len(requirement.MinimumRoots) != 0 {
		t.Fatalf("completed roots=%#v err=%v", requirement, err)
	}
	if _, err := store.DB().Exec(`INSERT INTO publication_candidates(report_identity, sequence, path, phase, size, sha256, remote_identity) VALUES (?, 99, 'dists/forbidden-pointer', 'pointer', 0, ?, 'etag')`, report.ReportIdentity, strings.Repeat("0", 64)); err == nil {
		t.Fatal("publication_candidates table accepted pointer phase")
	}
	var storageClass string
	if err := store.DB().QueryRow(`SELECT typeof(target_generation) FROM publication_attempts WHERE attempt_identity = ?`, attempt.AttemptIdentity).Scan(&storageClass); err != nil || storageClass != "text" {
		t.Fatalf("target_generation storage=%q err=%v", storageClass, err)
	}
	if err := store.Check(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationAttemptCanAbandonOnlyBeforeCommitIntent(t *testing.T) {
	ctx := context.Background()
	store, binding, manifest := publicationStoreFixture(t)
	defer store.Close()
	_, manifestSHA, _ := ManifestBytes(manifest)
	newAttempt := func(planByte string) PublicationAttempt {
		return PublicationAttempt{
			RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1,
			ManifestSHA256: manifestSHA, PlanSHA256: strings.Repeat(planByte, 64), Phase: "planned",
			Views: []PublicationAttemptView{{ViewID: "dists/el9/x86_64", PointerPath: manifest[0].Path, NewIdentity: manifest[0].SHA256, State: "pending"}},
		}
	}
	attempt := newAttempt("a")
	if err := store.PutPublicationAttempt(ctx, &attempt); err != nil {
		t.Fatal(err)
	}
	orphans := []PublicationAbandonedObject{{Path: manifest[1].Path, Phase: manifest[1].Phase, Size: manifest[1].Size, SHA256: manifest[1].SHA256, RemoteIdentity: "etag-orphan"}}
	for replay := 0; replay < 2; replay++ {
		if err := store.AbandonPublicationAttempt(ctx, attempt.AttemptIdentity, orphans); err != nil {
			t.Fatalf("abandon replay %d: %v", replay, err)
		}
	}
	active, err := store.HasWriteActivePublication(ctx)
	if err != nil || active {
		t.Fatalf("active=%t err=%v", active, err)
	}
	stored, err := store.GetPublicationAttempt(ctx, attempt.AttemptIdentity)
	listed, listErr := store.ListPublicationAbandonedObjects(ctx, binding.TargetIdentity)
	if err != nil || listErr != nil || stored.Phase != "abandoned" || len(listed) != 1 || listed[0] != orphans[0] {
		t.Fatalf("stored=%#v listed=%#v err=%v listErr=%v", stored, listed, err, listErr)
	}
	if err := store.PutPublicationAttempt(ctx, &attempt); err != nil {
		t.Fatal(err)
	}
	if resumed, err := store.GetActivePublicationAttempt(ctx, binding.TargetIdentity); err != nil || resumed.Phase != "planned" {
		t.Fatalf("resumed=%#v err=%v", resumed, err)
	}
	if listed, err := store.ListPublicationAbandonedObjects(ctx, binding.TargetIdentity); err != nil || len(listed) != 0 {
		t.Fatalf("resurrected attempt retained abandoned evidence=%#v err=%v", listed, err)
	}
	for _, phase := range []string{"payload", "immutable_metadata", "pointer_prepared"} {
		if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetPublicationAttemptViewState(ctx, attempt.AttemptIdentity, attempt.Views[0].ViewID, attempt.Views[0].PointerPath, "prepared"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPublicationCommitIntent(ctx, attempt.AttemptIdentity); err != nil {
		t.Fatal(err)
	}
	if err := store.AbandonPublicationAttempt(ctx, attempt.AttemptIdentity, orphans); !errors.Is(err, ErrTransition) {
		t.Fatalf("post-intent abandon error=%v", err)
	}
}

func TestV11MigrationClearsEvidenceFromResurrectedPublication(t *testing.T) {
	ctx := context.Background()
	store, binding, manifest := publicationStoreFixture(t)
	_, manifestSHA, _ := ManifestBytes(manifest)
	attempt := PublicationAttempt{
		RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1,
		ManifestSHA256: manifestSHA, PlanSHA256: strings.Repeat("a", 64), Phase: "planned", Views: []PublicationAttemptView{},
	}
	if err := store.PutPublicationAttempt(ctx, &attempt); err != nil {
		store.Close()
		t.Fatal(err)
	}
	orphans := []PublicationAbandonedObject{{Path: manifest[1].Path, Phase: manifest[1].Phase, Size: manifest[1].Size, SHA256: manifest[1].SHA256, RemoteIdentity: "etag-orphan"}}
	if err := store.AbandonPublicationAttempt(ctx, attempt.AttemptIdentity, orphans); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE publication_attempts SET phase = 'planned' WHERE attempt_identity = ?`, attempt.AttemptIdentity); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Check(ctx); !errors.Is(err, ErrConflict) {
		store.Close()
		t.Fatalf("semantic check accepted stale active evidence: %v", err)
	}
	path := store.path
	downgradeV11FixtureToV10(t, store.DB())
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := OpenExistingForMigration(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	if listed, err := migrated.ListPublicationAbandonedObjects(ctx, binding.TargetIdentity); err != nil || len(listed) != 0 {
		t.Fatalf("migration retained stale active evidence=%#v err=%v", listed, err)
	}
	if err := migrated.Check(ctx); err != nil {
		t.Fatalf("migrated publication state is invalid: %v", err)
	}
}

func TestPublicationGraceDoesNotBlockTheNextTargetAttempt(t *testing.T) {
	ctx := context.Background()
	store, binding, manifest := publicationStoreFixture(t)
	defer store.Close()
	_, manifestSHA, err := ManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	first := PublicationAttempt{
		RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity,
		TargetGeneration: 1, ManifestSHA256: manifestSHA, PlanSHA256: strings.Repeat("b", 64),
		Phase: "planned", Views: []PublicationAttemptView{},
	}
	if err := store.PutPublicationAttempt(ctx, &first); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"payload", "immutable_metadata", "pointer_prepared"} {
		if err := store.AdvancePublicationAttemptPhase(ctx, first.AttemptIdentity, phase); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetPublicationCommitIntent(ctx, first.AttemptIdentity); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"pointer_rollforward", "verified"} {
		if err := store.AdvancePublicationAttemptPhase(ctx, first.AttemptIdentity, phase); err != nil {
			t.Fatal(err)
		}
	}
	inventory := make([]PublicationInventoryObject, 0, len(manifest))
	for _, file := range manifest {
		inventory = append(inventory, PublicationInventoryObject{
			Path: file.Path, Phase: file.Phase, Size: file.Size, SHA256: file.SHA256, RemoteIdentity: "remote-" + file.SHA256,
		})
	}
	checkpoint := AppliedCheckpoint{
		RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity,
		AttemptIdentity: first.AttemptIdentity, Generation: 1, ManifestSHA256: manifestSHA,
		InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: inventory,
	}
	if err := store.PutAppliedCheckpoint(ctx, &checkpoint); err != nil {
		t.Fatal(err)
	}
	verified := time.Now().UTC()
	grace := GraceRecord{
		TargetIdentity: binding.TargetIdentity, CheckpointIdentity: checkpoint.CheckpointIdentity,
		VerifiedAt: verified, NotBefore: verified.Add(30 * 24 * time.Hour),
		CachePolicyIdentity: strings.Repeat("c", 64),
	}
	if err := store.PutGraceRecord(ctx, &grace); err != nil {
		t.Fatal(err)
	}
	second := PublicationAttempt{
		RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity,
		BaseCheckpoint: checkpoint.CheckpointIdentity, TargetGeneration: 1,
		ManifestSHA256: manifestSHA, PlanSHA256: strings.Repeat("d", 64), Phase: "planned",
		Views: []PublicationAttemptView{},
	}
	if err := store.PutPublicationAttempt(ctx, &second); err != nil {
		t.Fatalf("start next attempt while prior checkpoint is in grace: %v", err)
	}
	active, err := store.GetActivePublicationAttempt(ctx, binding.TargetIdentity)
	if err != nil || active.AttemptIdentity != second.AttemptIdentity {
		t.Fatalf("active attempt=%#v err=%v", active, err)
	}
}

func TestPublicationCandidatesProtectCurrentHeadAndOtherGraceClosures(t *testing.T) {
	ctx := context.Background()
	store, binding, firstManifest := publicationStoreFixture(t)
	defer store.Close()
	extra := GenerationFile{Path: "pool/z/shared-by-next.rpm", Phase: "payload", Size: 9, SHA256: strings.Repeat("e", 64)}
	secondManifest := append(append([]GenerationFile(nil), firstManifest...), extra)
	_, firstSHA, _ := ManifestBytes(firstManifest)
	_, secondSHA, _ := ManifestBytes(secondManifest)
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES ('2', 'fixture', 'done', '{}', '{}', ?, ?)`, nowText(), nowText()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO operation_events(operation_id, sequence, state, detail_json, occurred_at) VALUES ('2', 0, 'planned', '{}', ?), ('2', 1, 'done', '{}', ?)`, nowText(), nowText()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO generations(generation, previous_generation, operation_id, manifest_sha256, renderer_identity, created_at) VALUES ('00000000000000000002', '00000000000000000001', '2', ?, ?, ?)`, secondSHA, strings.Repeat("0", 64), nowText()); err != nil {
		t.Fatal(err)
	}
	for _, file := range secondManifest {
		if _, err := store.DB().ExecContext(ctx, `INSERT INTO generation_files(generation, path, phase, size, sha256) VALUES ('00000000000000000002', ?, ?, ?, ?)`, file.Path, file.Phase, file.Size, file.SHA256); err != nil {
			t.Fatal(err)
		}
	}
	advance := func(attempt *PublicationAttempt) {
		t.Helper()
		if err := store.PutPublicationAttempt(ctx, attempt); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"payload", "immutable_metadata", "pointer_prepared"} {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.SetPublicationCommitIntent(ctx, attempt.AttemptIdentity); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"pointer_rollforward", "verified"} {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
				t.Fatal(err)
			}
		}
	}
	first := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1, ManifestSHA256: firstSHA, PlanSHA256: strings.Repeat("a", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	advance(&first)
	firstInventory := []PublicationInventoryObject{}
	for _, file := range firstManifest {
		firstInventory = append(firstInventory, PublicationInventoryObject{Path: file.Path, Phase: file.Phase, Size: file.Size, SHA256: file.SHA256, RemoteIdentity: "etag-" + file.SHA256})
	}
	firstInventory = append(firstInventory, PublicationInventoryObject{Path: extra.Path, Phase: extra.Phase, Size: extra.Size, SHA256: extra.SHA256, RemoteIdentity: "etag-" + extra.SHA256})
	oldVerified := time.Now().UTC().Add(-31 * 24 * time.Hour)
	firstCheckpoint := AppliedCheckpoint{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: first.AttemptIdentity, Generation: 1, ManifestSHA256: firstSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: firstInventory, AppliedAt: oldVerified}
	if err := store.PutAppliedCheckpoint(ctx, &firstCheckpoint); err != nil {
		t.Fatal(err)
	}
	firstGrace := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: firstCheckpoint.CheckpointIdentity, VerifiedAt: oldVerified, NotBefore: oldVerified.Add(30 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("c", 64)}
	if err := store.PutGraceRecord(ctx, &firstGrace); err != nil {
		t.Fatal(err)
	}
	second := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, BaseCheckpoint: firstCheckpoint.CheckpointIdentity, TargetGeneration: 2, ManifestSHA256: secondSHA, PlanSHA256: strings.Repeat("b", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	advance(&second)
	secondCheckpoint := AppliedCheckpoint{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: second.AttemptIdentity, Generation: 2, ManifestSHA256: secondSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: firstInventory}
	if err := store.PutAppliedCheckpoint(ctx, &secondCheckpoint); err != nil {
		t.Fatal(err)
	}
	secondVerified := time.Now().UTC()
	secondGrace := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: secondCheckpoint.CheckpointIdentity, VerifiedAt: secondVerified, NotBefore: secondVerified.Add(30 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("d", 64)}
	if err := store.PutGraceRecord(ctx, &secondGrace); err != nil {
		t.Fatal(err)
	}
	candidates, err := store.ExactPublicationCandidates(ctx, firstCheckpoint.CheckpointIdentity, time.Now().UTC())
	if err != nil || len(candidates) != 0 {
		t.Fatalf("old checkpoint tried to collect current-head payload: %#v err=%v", candidates, err)
	}
}

func TestPublicationStateRejectsUnsortedViewsOverlapShortGraceAndR2Delete(t *testing.T) {
	ctx := context.Background()
	store, binding, manifest := publicationStoreFixture(t)
	defer store.Close()
	overlap := binding
	overlap.TargetName = "overlap"
	overlap.Prefix = "prod"
	overlap.TargetIdentity = publicationIdentity("sow/target/v1", overlap.TargetStorageID, overlap.Prefix)
	if err := store.BindPublicationTarget(ctx, overlap); !errors.Is(err, ErrConflict) {
		t.Fatalf("overlap error=%v", err)
	}
	_, manifestSHA, _ := ManifestBytes(manifest)
	attempt := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1, ManifestSHA256: manifestSHA, PlanSHA256: strings.Repeat("b", 64), Phase: "planned", Views: []PublicationAttemptView{
		{ViewID: "dists/z", PointerPath: "dists/z/Release", NewIdentity: "z", State: "pending"},
		{ViewID: "dists/a", PointerPath: "dists/a/Release", NewIdentity: "a", State: "pending"},
	}}
	if err := store.PutPublicationAttempt(ctx, &attempt); err == nil {
		t.Fatal("unsorted views accepted")
	}
	valid := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1, ManifestSHA256: manifestSHA, PlanSHA256: strings.Repeat("b", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	if err := store.PutPublicationAttempt(ctx, &valid); err != nil {
		t.Fatal(err)
	}
	second := valid
	second.AttemptIdentity = ""
	second.PlanSHA256 = strings.Repeat("c", 64)
	if err := store.PutPublicationAttempt(ctx, &second); err == nil {
		t.Fatal("second active attempt for one target accepted")
	}
	badCommit := valid
	badCommit.AttemptIdentity = ""
	badCommit.PlanSHA256 = strings.Repeat("d", 64)
	badCommit.CommitIntent = true
	if err := validatePublicationAttempt(badCommit); err == nil {
		t.Fatal("pre-commit phase with commit_intent=true accepted")
	}
	badCommit.Phase, badCommit.CommitIntent = "pointer_rollforward", false
	if err := validatePublicationAttempt(badCommit); err == nil {
		t.Fatal("post-commit phase with commit_intent=false accepted")
	}
}

func TestFilesystemDeletionRequiresExactReceiptsAndProjectsLiveInventory(t *testing.T) {
	ctx := context.Background()
	store, r2Binding, manifest := publicationStoreFixture(t)
	defer store.Close()
	endpoint := "file:///srv/sow/repo"
	storageID := publicationIdentity("sow/target-storage/v1", "filesystem", endpoint, "", "")
	binding := PublicationTargetBinding{
		TargetIdentity: publicationIdentity("sow/target/v1", storageID, "filesystem/repo"), TargetStorageID: storageID,
		RepositoryID: r2Binding.RepositoryID, TargetName: "filesystem", Provider: "filesystem", Endpoint: endpoint,
		Prefix: "filesystem/repo", PublicEndpoint: endpoint + "/filesystem/repo/", AuthoritativeWorkspace: true,
		SingleWriter: true, ExclusiveWriteAuthority: true,
	}
	if err := store.BindPublicationTarget(ctx, binding); err != nil {
		t.Fatal(err)
	}
	_, manifestSHA, _ := ManifestBytes(manifest)
	attempt := PublicationAttempt{
		RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1,
		ManifestSHA256: manifestSHA, PlanSHA256: strings.Repeat("d", 64), Phase: "planned", Views: []PublicationAttemptView{},
	}
	if err := store.PutPublicationAttempt(ctx, &attempt); err != nil {
		t.Fatal(err)
	}
	for _, next := range []string{"payload", "immutable_metadata", "pointer_prepared"} {
		if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, next); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetPublicationCommitIntent(ctx, attempt.AttemptIdentity); err != nil {
		t.Fatal(err)
	}
	for _, next := range []string{"pointer_rollforward", "verified"} {
		if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, next); err != nil {
			t.Fatal(err)
		}
	}
	inventory := make([]PublicationInventoryObject, len(manifest))
	for index, file := range manifest {
		inventory[index] = PublicationInventoryObject{Path: file.Path, Phase: file.Phase, Size: file.Size, SHA256: file.SHA256, RemoteIdentity: "filesystem-etag"}
	}
	inventory = append(inventory, PublicationInventoryObject{Path: "pool/z/old.rpm", Phase: "payload", Size: 9, SHA256: strings.Repeat("e", 64), RemoteIdentity: strings.Repeat("e", 64)})
	verified := time.Now().UTC().Add(-31 * 24 * time.Hour)
	checkpoint := AppliedCheckpoint{
		RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: attempt.AttemptIdentity,
		Generation: 1, ManifestSHA256: manifestSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: inventory, AppliedAt: verified,
	}
	if err := store.PutAppliedCheckpoint(ctx, &checkpoint); err != nil {
		t.Fatal(err)
	}
	grace := GraceRecord{
		TargetIdentity: binding.TargetIdentity, CheckpointIdentity: checkpoint.CheckpointIdentity, VerifiedAt: verified,
		NotBefore: verified.Add(30 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("c", 64),
	}
	if err := store.PutGraceRecord(ctx, &grace); err != nil {
		t.Fatal(err)
	}
	report := PublicationCandidateReport{
		TargetIdentity: binding.TargetIdentity, CheckpointIdentity: checkpoint.CheckpointIdentity,
		InventoryIdentity: checkpoint.InventoryIdentity, Mode: "conditional_delete", Candidates: []PublicationCandidate{{
			Path: "pool/z/old.rpm", Phase: "payload", Size: 9, SHA256: strings.Repeat("e", 64), RemoteIdentity: strings.Repeat("e", 64),
		}},
	}
	if err := store.PutPublicationCandidateReport(ctx, &report); err != nil {
		t.Fatal(err)
	}
	for _, blocked := range []string{"deletion_verified", "retained_reported", "done"} {
		if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, blocked); err == nil {
			t.Fatalf("generic Advance entered filesystem %s", blocked)
		}
	}
	if err := store.MarkPublicationRetainedReported(ctx, attempt.AttemptIdentity, report.ReportIdentity, time.Now().UTC()); !errors.Is(err, ErrTransition) {
		t.Fatalf("filesystem used R2 retained-report gate: %v", err)
	}
	if err := store.CompletePublicationAttempt(ctx, attempt.AttemptIdentity, report.ReportIdentity); !errors.Is(err, ErrTransition) {
		t.Fatalf("filesystem completed without deletion receipts: %v", err)
	}
	if err := store.MarkPublicationDeletionVerified(ctx, attempt.AttemptIdentity, report.ReportIdentity, grace.NotBefore); !errors.Is(err, ErrTransition) {
		t.Fatalf("filesystem verified an incomplete receipt closure: %v", err)
	}
	receipt := PublicationDeletionReceipt{
		ReportIdentity: report.ReportIdentity, Path: report.Candidates[0].Path, Phase: report.Candidates[0].Phase,
		Size: report.Candidates[0].Size, SHA256: report.Candidates[0].SHA256, RemoteIdentity: report.Candidates[0].RemoteIdentity,
		StorageAbsent: true, PublicAbsent: true, ObservedAt: grace.NotBefore,
	}
	badReceipt := receipt
	badReceipt.ReceiptIdentity = strings.Repeat("f", 64)
	if err := store.PutPublicationDeletionReceipt(ctx, &badReceipt); !errors.Is(err, ErrConflict) {
		t.Fatalf("noncanonical deletion receipt identity error=%v", err)
	}
	for replay := 0; replay < 2; replay++ {
		copyReceipt := receipt
		copyReceipt.ObservedAt = copyReceipt.ObservedAt.Add(time.Duration(replay) * time.Hour)
		if err := store.PutPublicationDeletionReceipt(ctx, &copyReceipt); err != nil {
			t.Fatalf("deletion receipt replay %d: %v", replay, err)
		}
		if replay == 1 && copyReceipt.ReceiptIdentity != receipt.ReceiptIdentity {
			t.Fatalf("receipt replay minted a different identity: %s != %s", copyReceipt.ReceiptIdentity, receipt.ReceiptIdentity)
		}
		receipt = copyReceipt
	}
	storedReceipt, err := store.GetPublicationDeletionReceipt(ctx, receipt.ReportIdentity, receipt.Path)
	if err != nil || storedReceipt.ReceiptIdentity != receipt.ReceiptIdentity ||
		deletionReceiptSemanticIdentity(storedReceipt) != storedReceipt.ReceiptIdentity ||
		!storedReceipt.StorageAbsent || !storedReceipt.PublicAbsent {
		t.Fatalf("public deletion receipt lookup=%#v err=%v", storedReceipt, err)
	}
	for replay := 0; replay < 2; replay++ {
		if err := store.MarkPublicationDeletionVerified(ctx, attempt.AttemptIdentity, report.ReportIdentity, grace.NotBefore); err != nil {
			t.Fatalf("deletion verification replay %d: %v", replay, err)
		}
	}
	for replay := 0; replay < 2; replay++ {
		if err := store.CompletePublicationAttempt(ctx, attempt.AttemptIdentity, report.ReportIdentity); err != nil {
			t.Fatalf("filesystem completion replay %d: %v", replay, err)
		}
	}
	live, err := store.PublicationLiveInventory(ctx, checkpoint.CheckpointIdentity)
	if err != nil || len(live) != len(manifest) {
		t.Fatalf("live inventory=%#v err=%v", live, err)
	}
	var phase string
	if err := store.DB().QueryRow(`SELECT phase FROM publication_attempts WHERE attempt_identity = ?`, attempt.AttemptIdentity).Scan(&phase); err != nil || phase != "done" {
		t.Fatalf("filesystem phase=%q err=%v", phase, err)
	}
	if err := store.Check(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestObserveRepositoryTimeNormalizesLegacySeedAndBoundsYear(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.DB().ExecContext(ctx, `UPDATE repository_time_witness SET max_observed_at = '1970-01-01T00:00:00Z' WHERE singleton = 1`); err != nil {
		t.Fatal(err)
	}
	epoch := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := store.ObserveRepositoryTime(ctx, epoch); err != nil {
		t.Fatalf("ObserveRepositoryTime rejected legacy RFC3339Nano seed: %v", err)
	}
	var stored string
	if err := store.DB().QueryRowContext(ctx, `SELECT max_observed_at FROM repository_time_witness WHERE singleton = 1`).Scan(&stored); err != nil || stored != "1970-01-01T00:00:00.000000000Z" {
		t.Fatalf("stored witness=%q err=%v", stored, err)
	}
	for _, outOfRange := range []time.Time{
		time.Date(0, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		if err := store.ObserveRepositoryTime(ctx, outOfRange); !errors.Is(err, ErrConflict) {
			t.Fatalf("ObserveRepositoryTime(%v) = %v, want ErrConflict", outOfRange, err)
		}
	}
	next := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	if err := store.ObserveRepositoryTime(ctx, next); err != nil {
		t.Fatalf("ObserveRepositoryTime after rejected out-of-range year failed: %v", err)
	}
}

func TestListPackageObjectsBatchesManyDists(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const distCount = 520
	distNames := make([]string, 0, distCount)
	desired := make(map[string][]string, distCount)
	shaA := strings.Repeat("a", 64)
	shaB := strings.Repeat("b", 64)
	for i := range distCount {
		name := fmt.Sprintf("el-%04d", i)
		distNames = append(distNames, name)
		if err := store.AddDist(ctx, Dist{
			Name: name, Format: "rpm", EffectiveConfigSHA256: "cfg",
			Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}},
		}); err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			desired[name] = []string{shaA, shaB}
		} else {
			desired[name] = []string{shaA}
		}
	}
	opID := strings.Repeat("1", 64)
	if err := store.BeginOperation(ctx, Operation{ID: opID, Kind: "add", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetOperationState(ctx, opID, OperationStaged, ""); err != nil {
		t.Fatal(err)
	}
	objs := []PackageObject{
		{SHA256: shaB, Format: "rpm", Coordinate: "beta-0:1-1.x86_64", Architecture: "x86_64", CanonicalArch: "x86_64", PoolPath: "pool/b/beta/beta-1-1.x86_64.rpm", Filename: "beta-1-1.x86_64.rpm", Size: 10, Name: "beta", Source: "beta", Version: "1", Release: "1", Kind: "main", Storage: "pending"},
		{SHA256: shaA, Format: "rpm", Coordinate: "alpha-0:1-1.x86_64", Architecture: "x86_64", CanonicalArch: "x86_64", PoolPath: "pool/a/alpha/alpha-1-1.x86_64.rpm", Filename: "alpha-1-1.x86_64.rpm", Size: 10, Name: "alpha", Source: "alpha", Version: "1", Release: "1", Kind: "main", Storage: "pending"},
	}
	if _, err := store.ApplyDesiredMutation(ctx, opID, objs, desired, `{}`); err != nil {
		t.Fatal(err)
	}
	listed, err := store.ListPackageObjects(ctx, append(distNames, distNames[0]), false)
	if err != nil || len(listed) != 2 || listed[0].Name != "alpha" || listed[1].Name != "beta" || len(listed[0].Dists) != distCount || len(listed[1].Dists) != distCount/2 {
		t.Fatalf("ListPackageObjects across %d dists: len=%d err=%v listed=%+v", distCount, len(listed), err, listed)
	}
}

func TestPublicationLiveInventoryAvoidsFullHistoryScanAcrossGenerations(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "scale.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	binding := PublicationTargetBinding{
		RepositoryID: identity.RepositoryID, TargetName: "prod", Provider: "r2",
		Endpoint: "https://acct.r2.cloudflarestorage.com", Region: "auto", Bucket: "repo", Prefix: "p",
		PublicEndpoint: "https://repo.example.test/p/", MaxCacheTTL: 0,
		AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true,
	}
	if err := store.BindPublicationTarget(ctx, binding); err != nil {
		t.Fatal(err)
	}
	binding, err = store.canonicalPublicationTargetBinding(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}

	const (
		objectCount = 300
		generations = 12
	)
	baseObjects := make([]GenerationFile, 0, objectCount)
	baseObjects = append(baseObjects, GenerationFile{
		Path: "dists/el9/x86_64/repodata/repomd.xml", Phase: "pointer", Size: 64, SHA256: strings.Repeat("a", 64),
	})
	for i := 1; i < objectCount; i++ {
		sha := fmt.Sprintf("%064x", i)
		baseObjects = append(baseObjects, GenerationFile{
			Path: fmt.Sprintf("pool/p/pkg-%05d/pkg-%05d-1.0-1.el9.x86_64.rpm", i, i), Phase: "payload", Size: 1024, SHA256: sha,
		})
	}

	var firstCheckpointID, lastCheckpointID string
	baseCheckpoint := ""
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for g := 1; g <= generations; g++ {
		gen := GenerationID(g)
		prevGen := GenerationID(g - 1)
		manifest := make([]GenerationFile, len(baseObjects))
		copy(manifest, baseObjects)
		manifest[0].SHA256 = fmt.Sprintf("%064x", 1000000+g)
		_, manifestSHA, err := ManifestBytes(manifest)
		if err != nil {
			t.Fatal(err)
		}
		opID := fmt.Sprintf("%d", g)
		tx, err := store.DB().BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES (?, 'fixture', 'done', '{}', '{}', ?, ?)`, opID, nowText(), nowText()); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO generations(generation, previous_generation, operation_id, manifest_sha256, renderer_identity, created_at) VALUES (?, ?, ?, ?, ?, ?)`, gen.String(), prevGen.String(), opID, manifestSHA, strings.Repeat("0", 64), nowText()); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		for start := 0; start < len(manifest); start += sqliteManifestInsertBatchSize {
			end := min(start+sqliteManifestInsertBatchSize, len(manifest))
			var q strings.Builder
			q.WriteString(`INSERT INTO generation_files(generation, path, phase, size, sha256) VALUES `)
			args := make([]any, 0, (end-start)*5)
			for idx, f := range manifest[start:end] {
				if idx != 0 {
					q.WriteByte(',')
				}
				q.WriteString(`(?, ?, ?, ?, ?)`)
				args = append(args, gen.String(), f.Path, f.Phase, f.Size, f.SHA256)
			}
			if _, err := tx.ExecContext(ctx, q.String(), args...); err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		views := []PublicationAttemptView{{
			ViewID: "rpm:el9/x86_64", PointerPath: manifest[0].Path, NewIdentity: manifest[0].SHA256, State: "pending",
		}}
		if g > 1 {
			views[0].OldIdentity = fmt.Sprintf("%064x", 1000000+g-1)
		}
		attempt := PublicationAttempt{
			RepositoryID: identity.RepositoryID, TargetIdentity: binding.TargetIdentity, BaseCheckpoint: baseCheckpoint,
			TargetGeneration: gen, ManifestSHA256: manifestSHA, PlanSHA256: fmt.Sprintf("%064x", 2000000+g),
			Phase: "planned", Views: views,
		}
		if err := store.PutPublicationAttempt(ctx, &attempt); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"payload", "immutable_metadata", "pointer_prepared"} {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.SetPublicationAttemptViewState(ctx, attempt.AttemptIdentity, views[0].ViewID, views[0].PointerPath, "prepared"); err != nil {
			t.Fatal(err)
		}
		if err := store.SetPublicationCommitIntent(ctx, attempt.AttemptIdentity); err != nil {
			t.Fatal(err)
		}
		if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, "pointer_rollforward"); err != nil {
			t.Fatal(err)
		}
		if err := store.SetPublicationAttemptViewState(ctx, attempt.AttemptIdentity, views[0].ViewID, views[0].PointerPath, "applied"); err != nil {
			t.Fatal(err)
		}
		if err := store.SetPublicationAttemptViewState(ctx, attempt.AttemptIdentity, views[0].ViewID, views[0].PointerPath, "verified"); err != nil {
			t.Fatal(err)
		}
		if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, "verified"); err != nil {
			t.Fatal(err)
		}
		inventory := make([]PublicationInventoryObject, len(manifest))
		for idx, f := range manifest {
			inventory[idx] = PublicationInventoryObject{Path: f.Path, Phase: f.Phase, Size: f.Size, SHA256: f.SHA256, RemoteIdentity: "etag-" + f.SHA256[:12]}
		}
		cp := AppliedCheckpoint{
			RepositoryID: identity.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: attempt.AttemptIdentity,
			Generation: gen, ManifestSHA256: manifestSHA, InventoryComplete: true,
			Views:     []PublicationCheckpointView{{ViewID: views[0].ViewID, PointerPath: views[0].PointerPath, RemoteIdentity: inventory[0].RemoteIdentity}},
			Inventory: inventory, AppliedAt: at.Add(time.Duration(g) * time.Second),
		}
		if err := store.PutAppliedCheckpoint(ctx, &cp); err != nil {
			t.Fatal(err)
		}
		grace := GraceRecord{
			TargetIdentity: binding.TargetIdentity, CheckpointIdentity: cp.CheckpointIdentity,
			VerifiedAt: cp.AppliedAt, NotBefore: cp.AppliedAt.Add(30 * 24 * time.Hour),
			CachePolicyIdentity: strings.Repeat("c", 64), State: "grace",
		}
		if err := store.PutGraceRecord(ctx, &grace); err != nil {
			t.Fatal(err)
		}
		baseCheckpoint = cp.CheckpointIdentity
		if g == 1 {
			firstCheckpointID = cp.CheckpointIdentity
		}
		lastCheckpointID = cp.CheckpointIdentity
	}

	measureAllocBytes := func(checkpointID string) uint64 {
		// Run two GCs before measuring so sync.Pool victims (such as encoding/json
		// encode buffers) are drained identically for every call.
		runtime.GC()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		inv, err := store.PublicationLiveInventory(ctx, checkpointID)
		if err != nil || len(inv) != objectCount {
			t.Fatalf("PublicationLiveInventory(%s) len=%d err=%v", checkpointID, len(inv), err)
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}

	// Warm up prepared state / SQLite page cache for both checkpoints.
	_ = measureAllocBytes(firstCheckpointID)
	_ = measureAllocBytes(lastCheckpointID)
	allocFirst := measureAllocBytes(firstCheckpointID)
	allocLast := measureAllocBytes(lastCheckpointID)
	// With zero receipts, reading the 12th generation must not scale linearly
	// with generation count (previously ~6-12x because every historical manifest
	// was scanned and keyed unconditionally).
	if allocLast > allocFirst*2 {
		t.Fatalf("PublicationLiveInventory scaled with history depth on 0 receipts: gen1=%d bytes, gen%d=%d bytes", allocFirst, generations, allocLast)
	}
}

func TestPublicationLiveInventoryTracksReabandonedObjectAfterDeletion(t *testing.T) {
	ctx := context.Background()
	store, binding, firstManifest := publicationStoreFixture(t)
	defer store.Close()

	// Create generation 2 without the payload from generation 1.
	payload := firstManifest[1]
	secondManifest := []GenerationFile{firstManifest[0]}
	_, firstSHA, _ := ManifestBytes(firstManifest)
	_, secondSHA, _ := ManifestBytes(secondManifest)
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES ('2', 'fixture', 'done', '{}', '{}', ?, ?)`, nowText(), nowText()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO generations(generation, previous_generation, operation_id, manifest_sha256, renderer_identity, created_at) VALUES ('00000000000000000002', '00000000000000000001', '2', ?, ?, ?)`, secondSHA, strings.Repeat("0", 64), nowText()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO generation_files(generation, path, phase, size, sha256) VALUES ('00000000000000000002', ?, ?, ?, ?)`, secondManifest[0].Path, secondManifest[0].Phase, secondManifest[0].Size, secondManifest[0].SHA256); err != nil {
		t.Fatal(err)
	}
	advanceToVerified := func(attempt *PublicationAttempt) {
		t.Helper()
		if err := store.PutPublicationAttempt(ctx, attempt); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"payload", "immutable_metadata", "pointer_prepared"} {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.SetPublicationCommitIntent(ctx, attempt.AttemptIdentity); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"pointer_rollforward", "verified"} {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
				t.Fatal(err)
			}
		}
	}

	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	a1 := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1, ManifestSHA256: firstSHA, PlanSHA256: strings.Repeat("1", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	advanceToVerified(&a1)
	inv1 := []PublicationInventoryObject{
		{Path: firstManifest[0].Path, Phase: firstManifest[0].Phase, Size: firstManifest[0].Size, SHA256: firstManifest[0].SHA256, RemoteIdentity: "etag-ptr"},
		{Path: payload.Path, Phase: payload.Phase, Size: payload.Size, SHA256: payload.SHA256, RemoteIdentity: "etag-payload"},
	}
	c1 := AppliedCheckpoint{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: a1.AttemptIdentity, Generation: 1, ManifestSHA256: firstSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: inv1, AppliedAt: at}
	if err := store.PutAppliedCheckpoint(ctx, &c1); err != nil {
		t.Fatal(err)
	}
	g1 := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c1.CheckpointIdentity, VerifiedAt: at, NotBefore: at.Add(30 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("c", 64)}
	if err := store.PutGraceRecord(ctx, &g1); err != nil {
		t.Fatal(err)
	}

	// Publish gen 2 (removing payload from manifest, retaining it in inventory),
	// then delete payload via C2's conditional_delete report.
	a2 := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, BaseCheckpoint: c1.CheckpointIdentity, TargetGeneration: 2, ManifestSHA256: secondSHA, PlanSHA256: strings.Repeat("2", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	advanceToVerified(&a2)
	c2 := AppliedCheckpoint{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: a2.AttemptIdentity, Generation: 2, ManifestSHA256: secondSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: inv1, AppliedAt: at.Add(time.Hour)}
	if err := store.PutAppliedCheckpoint(ctx, &c2); err != nil {
		t.Fatal(err)
	}
	g2 := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c2.CheckpointIdentity, VerifiedAt: at.Add(time.Hour), NotBefore: at.Add(31 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("c", 64)}
	if err := store.PutGraceRecord(ctx, &g2); err != nil {
		t.Fatal(err)
	}
	expired := at.Add(32 * 24 * time.Hour)
	r1 := PublicationCandidateReport{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c1.CheckpointIdentity, InventoryIdentity: c1.InventoryIdentity, Mode: "conditional_delete", Candidates: []PublicationCandidate{}, CreatedAt: expired}
	if err := store.PutPublicationCandidateReport(ctx, &r1); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkPublicationDeletionVerified(ctx, a1.AttemptIdentity, r1.ReportIdentity, expired); err != nil {
		t.Fatal(err)
	}
	if err := store.CompletePublicationAttempt(ctx, a1.AttemptIdentity, r1.ReportIdentity); err != nil {
		t.Fatal(err)
	}
	r2 := PublicationCandidateReport{
		TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c2.CheckpointIdentity, InventoryIdentity: c2.InventoryIdentity, Mode: "conditional_delete", CreatedAt: expired,
		Candidates: []PublicationCandidate{{Path: payload.Path, Phase: payload.Phase, Size: payload.Size, SHA256: payload.SHA256, RemoteIdentity: "etag-payload"}},
	}
	if err := store.PutPublicationCandidateReport(ctx, &r2); err != nil {
		t.Fatal(err)
	}
	receipt := PublicationDeletionReceipt{
		ReportIdentity: r2.ReportIdentity, Path: payload.Path, Phase: payload.Phase, Size: payload.Size, SHA256: payload.SHA256,
		RemoteIdentity: "etag-payload", StorageAbsent: true, PublicAbsent: true, ObservedAt: expired,
	}
	if err := store.PutPublicationDeletionReceipt(ctx, &receipt); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkPublicationDeletionVerified(ctx, a2.AttemptIdentity, r2.ReportIdentity, expired); err != nil {
		t.Fatal(err)
	}
	if err := store.CompletePublicationAttempt(ctx, a2.AttemptIdentity, r2.ReportIdentity); err != nil {
		t.Fatal(err)
	}
	liveBeforeAbandon, err := store.PublicationLiveInventory(ctx, c2.CheckpointIdentity)
	if err != nil || len(liveBeforeAbandon) != 1 {
		t.Fatalf("live inventory after deletion = %+v err=%v, want 1 object", liveBeforeAbandon, err)
	}

	// Simulate an abandoned pre-commit publish based on C2 that re-uploaded the
	// exact same payload (same path, sha256, remote_identity), followed by a new
	// checkpoint C3 whose inventory includes that abandoned object.
	abandoned := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, BaseCheckpoint: c2.CheckpointIdentity, TargetGeneration: 1, ManifestSHA256: firstSHA, PlanSHA256: strings.Repeat("3", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	if err := store.PutPublicationAttempt(ctx, &abandoned); err != nil {
		t.Fatal(err)
	}
	if err := store.AbandonPublicationAttempt(ctx, abandoned.AttemptIdentity, []PublicationAbandonedObject{{
		Path: payload.Path, Phase: payload.Phase, Size: payload.Size, SHA256: payload.SHA256, RemoteIdentity: "etag-payload",
	}}); err != nil {
		t.Fatal(err)
	}
	thirdManifest := []GenerationFile{{
		Path: firstManifest[0].Path, Phase: firstManifest[0].Phase, Size: firstManifest[0].Size, SHA256: strings.Repeat("9", 64),
	}}
	_, thirdSHA, _ := ManifestBytes(thirdManifest)
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES ('3', 'fixture', 'done', '{}', '{}', ?, ?)`, nowText(), nowText()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO generations(generation, previous_generation, operation_id, manifest_sha256, renderer_identity, created_at) VALUES ('00000000000000000003', '00000000000000000002', '3', ?, ?, ?)`, thirdSHA, strings.Repeat("0", 64), nowText()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO generation_files(generation, path, phase, size, sha256) VALUES ('00000000000000000003', ?, ?, ?, ?)`, thirdManifest[0].Path, thirdManifest[0].Phase, thirdManifest[0].Size, thirdManifest[0].SHA256); err != nil {
		t.Fatal(err)
	}
	a3 := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, BaseCheckpoint: c2.CheckpointIdentity, TargetGeneration: 3, ManifestSHA256: thirdSHA, PlanSHA256: strings.Repeat("4", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	advanceToVerified(&a3)
	inv3 := []PublicationInventoryObject{
		{Path: thirdManifest[0].Path, Phase: thirdManifest[0].Phase, Size: thirdManifest[0].Size, SHA256: thirdManifest[0].SHA256, RemoteIdentity: "etag-ptr-3"},
		{Path: payload.Path, Phase: payload.Phase, Size: payload.Size, SHA256: payload.SHA256, RemoteIdentity: "etag-payload"},
	}
	c3 := AppliedCheckpoint{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: a3.AttemptIdentity, Generation: 3, ManifestSHA256: thirdSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: inv3, AppliedAt: expired.Add(time.Hour)}
	if err := store.PutAppliedCheckpoint(ctx, &c3); err != nil {
		t.Fatal(err)
	}
	g3 := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c3.CheckpointIdentity, VerifiedAt: expired.Add(time.Hour), NotBefore: expired.Add(31 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("c", 64)}
	if err := store.PutGraceRecord(ctx, &g3); err != nil {
		t.Fatal(err)
	}

	liveAfterAbandon, err := store.PublicationLiveInventory(ctx, c3.CheckpointIdentity)
	if err != nil || len(liveAfterAbandon) != 2 {
		t.Fatalf("live inventory must keep re-abandoned identical object alive: len=%d err=%v", len(liveAfterAbandon), err)
	}
	// And once C3 expires, that re-abandoned payload must be eligible for collection again!
	candidatesC3, err := store.ExactPublicationCandidates(ctx, c3.CheckpointIdentity, g3.NotBefore.Add(time.Minute))
	if err != nil || len(candidatesC3) != 1 || candidatesC3[0].Path != payload.Path {
		t.Fatalf("C3 candidates after re-abandon = %+v err=%v, want [%s]", candidatesC3, err, payload.Path)
	}
}

func TestListPublicationMaintenancePreservesCausalOrderForInvertedRetainedReports(t *testing.T) {
	ctx := context.Background()
	store, binding, firstManifest := publicationStoreFixture(t)
	defer store.Close()

	secondManifest := []GenerationFile{firstManifest[0]}
	_, firstSHA, _ := ManifestBytes(firstManifest)
	_, secondSHA, _ := ManifestBytes(secondManifest)
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES ('2', 'fixture', 'done', '{}', '{}', ?, ?)`, nowText(), nowText()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO generations(generation, previous_generation, operation_id, manifest_sha256, renderer_identity, created_at) VALUES ('00000000000000000002', '00000000000000000001', '2', ?, ?, ?)`, secondSHA, strings.Repeat("0", 64), nowText()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO generation_files(generation, path, phase, size, sha256) VALUES ('00000000000000000002', ?, ?, ?, ?)`, secondManifest[0].Path, secondManifest[0].Phase, secondManifest[0].Size, secondManifest[0].SHA256); err != nil {
		t.Fatal(err)
	}
	advanceToVerified := func(attempt *PublicationAttempt) {
		t.Helper()
		if err := store.PutPublicationAttempt(ctx, attempt); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"payload", "immutable_metadata", "pointer_prepared"} {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.SetPublicationCommitIntent(ctx, attempt.AttemptIdentity); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"pointer_rollforward", "verified"} {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
				t.Fatal(err)
			}
		}
	}

	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	inv := []PublicationInventoryObject{
		{Path: firstManifest[0].Path, Phase: firstManifest[0].Phase, Size: firstManifest[0].Size, SHA256: firstManifest[0].SHA256, RemoteIdentity: "etag-ptr"},
		{Path: firstManifest[1].Path, Phase: firstManifest[1].Phase, Size: firstManifest[1].Size, SHA256: firstManifest[1].SHA256, RemoteIdentity: "etag-payload"},
	}
	a1 := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1, ManifestSHA256: firstSHA, PlanSHA256: strings.Repeat("5", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	advanceToVerified(&a1)
	c1 := AppliedCheckpoint{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: a1.AttemptIdentity, Generation: 1, ManifestSHA256: firstSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: inv, AppliedAt: at}
	if err := store.PutAppliedCheckpoint(ctx, &c1); err != nil {
		t.Fatal(err)
	}
	// Legacy inverted deadlines: C1 expires at +61d, C2 expires at +30d.
	g1 := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c1.CheckpointIdentity, VerifiedAt: at, NotBefore: at.Add(61 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("c", 64)}
	if err := store.PutGraceRecord(ctx, &g1); err != nil {
		t.Fatal(err)
	}
	a2 := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, BaseCheckpoint: c1.CheckpointIdentity, TargetGeneration: 2, ManifestSHA256: secondSHA, PlanSHA256: strings.Repeat("6", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	advanceToVerified(&a2)
	c2 := AppliedCheckpoint{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: a2.AttemptIdentity, Generation: 2, ManifestSHA256: secondSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: inv, AppliedAt: at.Add(time.Hour)}
	if err := store.PutAppliedCheckpoint(ctx, &c2); err != nil {
		t.Fatal(err)
	}
	g2 := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c2.CheckpointIdentity, VerifiedAt: at.Add(time.Hour), NotBefore: at.Add(30*24*time.Hour + time.Hour), CachePolicyIdentity: strings.Repeat("c", 64)}
	if err := store.PutGraceRecord(ctx, &g2); err != nil {
		t.Fatal(err)
	}

	// Report-only both checkpoints past C1's deadline so both enter retained_reported.
	afterBoth := at.Add(62 * 24 * time.Hour)
	for _, cp := range []struct {
		id         string
		attempt    string
		invID      string
		candidates []PublicationCandidate
	}{
		{c1.CheckpointIdentity, a1.AttemptIdentity, c1.InventoryIdentity, []PublicationCandidate{}},
		{c2.CheckpointIdentity, a2.AttemptIdentity, c2.InventoryIdentity, []PublicationCandidate{{Path: firstManifest[1].Path, Phase: firstManifest[1].Phase, Size: firstManifest[1].Size, SHA256: firstManifest[1].SHA256, RemoteIdentity: "etag-payload"}}},
	} {
		rep := PublicationCandidateReport{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: cp.id, InventoryIdentity: cp.invID, Mode: "report_only", Candidates: cp.candidates, CreatedAt: afterBoth}
		if err := store.PutPublicationCandidateReport(ctx, &rep); err != nil {
			t.Fatal(err)
		}
		if err := store.MarkPublicationRetainedReported(ctx, cp.attempt, rep.ReportIdentity, afterBoth); err != nil {
			t.Fatal(err)
		}
		if err := store.CompletePublicationAttempt(ctx, cp.attempt, rep.ReportIdentity); err != nil {
			t.Fatal(err)
		}
	}

	items, err := store.ListPublicationMaintenance(ctx, binding.TargetIdentity, true)
	if err != nil || len(items) != 2 {
		t.Fatalf("ListPublicationMaintenance(includeRetained=true) = %+v err=%v", items, err)
	}
	if items[0].CheckpointIdentity != c1.CheckpointIdentity || items[1].CheckpointIdentity != c2.CheckpointIdentity {
		t.Fatalf("inverted retained_reported order broke causal sequence: got [%s, %s], want [%s, %s]",
			items[0].CheckpointIdentity, items[1].CheckpointIdentity, c1.CheckpointIdentity, c2.CheckpointIdentity)
	}
}

func TestAbandonedUploadUsesHalfStepCausalEpochAndFiltersSupersededOrphans(t *testing.T) {
	ctx := context.Background()
	store, binding, firstManifest := publicationStoreFixture(t)
	defer store.Close()

	payload := firstManifest[1]
	ptr := firstManifest[0]
	extra := GenerationFile{Path: "pool/q/other/other.rpm", Phase: "payload", Size: 11, SHA256: strings.Repeat("d", 64)}
	secondManifest := []GenerationFile{ptr, extra}
	thirdManifest := []GenerationFile{{Path: ptr.Path, Phase: ptr.Phase, Size: ptr.Size, SHA256: strings.Repeat("8", 64)}, extra}
	fourthManifest := []GenerationFile{{Path: ptr.Path, Phase: ptr.Phase, Size: ptr.Size, SHA256: strings.Repeat("7", 64)}, extra, payload}
	_, firstSHA, _ := ManifestBytes(firstManifest)
	_, secondSHA, _ := ManifestBytes(secondManifest)
	_, thirdSHA, _ := ManifestBytes(thirdManifest)
	_, fourthSHA, _ := ManifestBytes(fourthManifest)

	insertGen := func(num int, manifest []GenerationFile, digest string) {
		t.Helper()
		gen := GenerationID(num)
		prev := GenerationID(num - 1)
		opID := fmt.Sprintf("%d", num)
		if _, err := store.DB().ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES (?, 'fixture', 'done', '{}', '{}', ?, ?)`, opID, nowText(), nowText()); err != nil {
			t.Fatal(err)
		}
		if _, err := store.DB().ExecContext(ctx, `INSERT INTO generations(generation, previous_generation, operation_id, manifest_sha256, renderer_identity, created_at) VALUES (?, ?, ?, ?, ?, ?)`, gen.String(), prev.String(), opID, digest, strings.Repeat("0", 64), nowText()); err != nil {
			t.Fatal(err)
		}
		for _, f := range manifest {
			if _, err := store.DB().ExecContext(ctx, `INSERT INTO generation_files(generation, path, phase, size, sha256) VALUES (?, ?, ?, ?, ?)`, gen.String(), f.Path, f.Phase, f.Size, f.SHA256); err != nil {
				t.Fatal(err)
			}
		}
	}
	insertGen(2, secondManifest, secondSHA)
	insertGen(3, thirdManifest, thirdSHA)
	insertGen(4, fourthManifest, fourthSHA)

	advance := func(attempt *PublicationAttempt) {
		t.Helper()
		if err := store.PutPublicationAttempt(ctx, attempt); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"payload", "immutable_metadata", "pointer_prepared"} {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.SetPublicationCommitIntent(ctx, attempt.AttemptIdentity); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"pointer_rollforward", "verified"} {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
				t.Fatal(err)
			}
		}
	}

	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	// First abandoned upload (pre-C0) with ETag1, later absorbed & deleted by C1.
	aPre := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1, ManifestSHA256: firstSHA, PlanSHA256: strings.Repeat("a", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	if err := store.PutPublicationAttempt(ctx, &aPre); err != nil {
		t.Fatal(err)
	}
	if err := store.AbandonPublicationAttempt(ctx, aPre.AttemptIdentity, []PublicationAbandonedObject{{
		Path: payload.Path, Phase: payload.Phase, Size: payload.Size, SHA256: payload.SHA256, RemoteIdentity: "etag-old",
	}}); err != nil {
		t.Fatal(err)
	}

	// C0: Gen 1 = [ptr, payload(etag-old)], expires T+30d.
	a0 := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1, ManifestSHA256: firstSHA, PlanSHA256: strings.Repeat("1", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	advance(&a0)
	inv0 := []PublicationInventoryObject{
		{Path: ptr.Path, Phase: ptr.Phase, Size: ptr.Size, SHA256: ptr.SHA256, RemoteIdentity: "etag-ptr-0"},
		{Path: payload.Path, Phase: payload.Phase, Size: payload.Size, SHA256: payload.SHA256, RemoteIdentity: "etag-old"},
	}
	c0 := AppliedCheckpoint{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: a0.AttemptIdentity, Generation: 1, ManifestSHA256: firstSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: inv0, AppliedAt: at}
	if err := store.PutAppliedCheckpoint(ctx, &c0); err != nil {
		t.Fatal(err)
	}
	g0 := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c0.CheckpointIdentity, VerifiedAt: at, NotBefore: at.Add(30 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("c", 64)}
	if err := store.PutGraceRecord(ctx, &g0); err != nil {
		t.Fatal(err)
	}

	// C1: Gen 2 = [ptr, extra], carries payload(etag-old) in inventory, expires T+31d.
	a1 := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, BaseCheckpoint: c0.CheckpointIdentity, TargetGeneration: 2, ManifestSHA256: secondSHA, PlanSHA256: strings.Repeat("2", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	advance(&a1)
	inv1 := []PublicationInventoryObject{
		{Path: ptr.Path, Phase: ptr.Phase, Size: ptr.Size, SHA256: ptr.SHA256, RemoteIdentity: "etag-ptr-1"},
		{Path: payload.Path, Phase: payload.Phase, Size: payload.Size, SHA256: payload.SHA256, RemoteIdentity: "etag-old"},
		{Path: extra.Path, Phase: extra.Phase, Size: extra.Size, SHA256: extra.SHA256, RemoteIdentity: "etag-extra"},
	}
	c1 := AppliedCheckpoint{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: a1.AttemptIdentity, Generation: 2, ManifestSHA256: secondSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: inv1, AppliedAt: at.Add(24 * time.Hour)}
	if err := store.PutAppliedCheckpoint(ctx, &c1); err != nil {
		t.Fatal(err)
	}
	g1 := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c1.CheckpointIdentity, VerifiedAt: at.Add(24 * time.Hour), NotBefore: at.Add(31 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("c", 64)}
	if err := store.PutGraceRecord(ctx, &g1); err != nil {
		t.Fatal(err)
	}

	// C2: Gen 3 = [ptr3, extra], still carries payload(etag-old) in inventory, expires T+50d.
	a2 := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, BaseCheckpoint: c1.CheckpointIdentity, TargetGeneration: 3, ManifestSHA256: thirdSHA, PlanSHA256: strings.Repeat("3", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	advance(&a2)
	inv2 := []PublicationInventoryObject{
		{Path: thirdManifest[0].Path, Phase: thirdManifest[0].Phase, Size: thirdManifest[0].Size, SHA256: thirdManifest[0].SHA256, RemoteIdentity: "etag-ptr-2"},
		{Path: payload.Path, Phase: payload.Phase, Size: payload.Size, SHA256: payload.SHA256, RemoteIdentity: "etag-old"},
		{Path: extra.Path, Phase: extra.Phase, Size: extra.Size, SHA256: extra.SHA256, RemoteIdentity: "etag-extra"},
	}
	c2 := AppliedCheckpoint{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: a2.AttemptIdentity, Generation: 3, ManifestSHA256: thirdSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: inv2, AppliedAt: at.Add(20 * 24 * time.Hour)}
	if err := store.PutAppliedCheckpoint(ctx, &c2); err != nil {
		t.Fatal(err)
	}
	g2 := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c2.CheckpointIdentity, VerifiedAt: at.Add(20 * 24 * time.Hour), NotBefore: at.Add(50 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("c", 64)}
	if err := store.PutGraceRecord(ctx, &g2); err != nil {
		t.Fatal(err)
	}

	// At T+32d: C0 finishes (0 candidates), C1 deletes payload(etag-old) and finishes. C2 stays in grace.
	at32 := at.Add(32 * 24 * time.Hour)
	r0 := PublicationCandidateReport{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c0.CheckpointIdentity, InventoryIdentity: c0.InventoryIdentity, Mode: "conditional_delete", Candidates: []PublicationCandidate{}, CreatedAt: at32}
	if err := store.PutPublicationCandidateReport(ctx, &r0); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkPublicationDeletionVerified(ctx, a0.AttemptIdentity, r0.ReportIdentity, at32); err != nil {
		t.Fatal(err)
	}
	if err := store.CompletePublicationAttempt(ctx, a0.AttemptIdentity, r0.ReportIdentity); err != nil {
		t.Fatal(err)
	}
	r1 := PublicationCandidateReport{
		TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c1.CheckpointIdentity, InventoryIdentity: c1.InventoryIdentity, Mode: "conditional_delete", CreatedAt: at32,
		Candidates: []PublicationCandidate{{Path: payload.Path, Phase: payload.Phase, Size: payload.Size, SHA256: payload.SHA256, RemoteIdentity: "etag-old"}},
	}
	if err := store.PutPublicationCandidateReport(ctx, &r1); err != nil {
		t.Fatal(err)
	}
	rc1 := PublicationDeletionReceipt{
		ReportIdentity: r1.ReportIdentity, Path: payload.Path, Phase: payload.Phase, Size: payload.Size, SHA256: payload.SHA256,
		RemoteIdentity: "etag-old", StorageAbsent: true, PublicAbsent: true, ObservedAt: at32,
	}
	if err := store.PutPublicationDeletionReceipt(ctx, &rc1); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkPublicationDeletionVerified(ctx, a1.AttemptIdentity, r1.ReportIdentity, at32); err != nil {
		t.Fatal(err)
	}
	if err := store.CompletePublicationAttempt(ctx, a1.AttemptIdentity, r1.ReportIdentity); err != nil {
		t.Fatal(err)
	}

	// At T+33d: Abandoned attempt A4 based on C2 re-uploads payload with a NEW ETag ("etag-new").
	a4 := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, BaseCheckpoint: c2.CheckpointIdentity, TargetGeneration: 4, ManifestSHA256: fourthSHA, PlanSHA256: strings.Repeat("4", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	if err := store.PutPublicationAttempt(ctx, &a4); err != nil {
		t.Fatal(err)
	}
	if err := store.AbandonPublicationAttempt(ctx, a4.AttemptIdentity, []PublicationAbandonedObject{{
		Path: payload.Path, Phase: payload.Phase, Size: payload.Size, SHA256: payload.SHA256, RemoteIdentity: "etag-new",
	}}); err != nil {
		t.Fatal(err)
	}

	// 1) PublicationLiveInventory(C2) must NOT resurrect C2's deleted (payload, etag-old):
	//    post-C2 abandoned upload sits at epoch 2*2+1=5 > C2's epoch 4.
	liveC2, err := store.PublicationLiveInventory(ctx, c2.CheckpointIdentity)
	if err != nil || len(liveC2) != 2 {
		t.Fatalf("PublicationLiveInventory(C2) must stay at 2 objects without deleted etag-old: len=%d err=%v live=%+v", len(liveC2), err, liveC2)
	}
	// 2) ListPublicationAbandonedObjects must ignore the deleted pre-C0 (etag-old)
	//    and return only the live (etag-new) without ErrConflict.
	orphans, err := store.ListPublicationAbandonedObjects(ctx, binding.TargetIdentity)
	if err != nil || len(orphans) != 1 || orphans[0].RemoteIdentity != "etag-new" {
		t.Fatalf("ListPublicationAbandonedObjects = %+v err=%v, want [etag-new]", orphans, err)
	}
	// 3) When C2 expires at T+51d, ExactPublicationCandidates(C2) must NOT claim
	//    payload (because A4 re-uploaded it at epoch 5 > C2's epoch 4).
	candidatesC2, err := store.ExactPublicationCandidates(ctx, c2.CheckpointIdentity, at.Add(51*24*time.Hour))
	if err != nil || len(candidatesC2) != 0 {
		t.Fatalf("ExactPublicationCandidates(C2) claimed post-C2 abandoned upload: %+v err=%v", candidatesC2, err)
	}
}

func TestInterruptedLegacyReportOnlyUnblocksDespiteInvertedDeadlines(t *testing.T) {
	ctx := context.Background()
	store, binding, firstManifest := publicationStoreFixture(t)
	defer store.Close()

	secondManifest := []GenerationFile{firstManifest[0]}
	_, firstSHA, _ := ManifestBytes(firstManifest)
	_, secondSHA, _ := ManifestBytes(secondManifest)
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES ('2', 'fixture', 'done', '{}', '{}', ?, ?)`, nowText(), nowText()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO generations(generation, previous_generation, operation_id, manifest_sha256, renderer_identity, created_at) VALUES ('00000000000000000002', '00000000000000000001', '2', ?, ?, ?)`, secondSHA, strings.Repeat("0", 64), nowText()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO generation_files(generation, path, phase, size, sha256) VALUES ('00000000000000000002', ?, ?, ?, ?)`, secondManifest[0].Path, secondManifest[0].Phase, secondManifest[0].Size, secondManifest[0].SHA256); err != nil {
		t.Fatal(err)
	}
	advance := func(attempt *PublicationAttempt) {
		t.Helper()
		if err := store.PutPublicationAttempt(ctx, attempt); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"payload", "immutable_metadata", "pointer_prepared"} {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.SetPublicationCommitIntent(ctx, attempt.AttemptIdentity); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"pointer_rollforward", "verified"} {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
				t.Fatal(err)
			}
		}
	}

	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	inv := []PublicationInventoryObject{
		{Path: firstManifest[0].Path, Phase: firstManifest[0].Phase, Size: firstManifest[0].Size, SHA256: firstManifest[0].SHA256, RemoteIdentity: "etag-ptr"},
		{Path: firstManifest[1].Path, Phase: firstManifest[1].Phase, Size: firstManifest[1].Size, SHA256: firstManifest[1].SHA256, RemoteIdentity: "etag-payload"},
	}
	a0 := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1, ManifestSHA256: firstSHA, PlanSHA256: strings.Repeat("7", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	advance(&a0)
	c0 := AppliedCheckpoint{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: a0.AttemptIdentity, Generation: 1, ManifestSHA256: firstSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: inv, AppliedAt: at}
	if err := store.PutAppliedCheckpoint(ctx, &c0); err != nil {
		t.Fatal(err)
	}
	g0 := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c0.CheckpointIdentity, VerifiedAt: at, NotBefore: at.Add(60 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("c", 64)}
	if err := store.PutGraceRecord(ctx, &g0); err != nil {
		t.Fatal(err)
	}
	a1 := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, BaseCheckpoint: c0.CheckpointIdentity, TargetGeneration: 2, ManifestSHA256: secondSHA, PlanSHA256: strings.Repeat("8", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	advance(&a1)
	c1 := AppliedCheckpoint{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: a1.AttemptIdentity, Generation: 2, ManifestSHA256: secondSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: inv, AppliedAt: at.Add(time.Hour)}
	if err := store.PutAppliedCheckpoint(ctx, &c1); err != nil {
		t.Fatal(err)
	}
	g1 := GraceRecord{TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c1.CheckpointIdentity, VerifiedAt: at.Add(time.Hour), NotBefore: at.Add(31 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("c", 64)}
	if err := store.PutGraceRecord(ctx, &g1); err != nil {
		t.Fatal(err)
	}

	// Simulate an interrupted v0.7.1 report_only candidate report persisted at T+32d
	// before MarkPublicationRetainedReported could run.
	at32 := at.Add(32 * 24 * time.Hour)
	rep := PublicationCandidateReport{
		SchemaVersion: 1, TargetIdentity: binding.TargetIdentity, CheckpointIdentity: c1.CheckpointIdentity,
		InventoryIdentity: c1.InventoryIdentity, Mode: "report_only", Candidates: []PublicationCandidate{}, CreatedAt: at32,
	}
	rep.ReportIdentity = candidateReportSemanticIdentity(rep)
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO publication_candidate_reports(report_identity, schema_version, target_identity, checkpoint_identity, inventory_identity, mode, created_at) VALUES (?, 1, ?, ?, ?, 'report_only', ?)`,
		rep.ReportIdentity, rep.TargetIdentity, rep.CheckpointIdentity, rep.InventoryIdentity, formatTimestamp(rep.CreatedAt)); err != nil {
		t.Fatal(err)
	}

	at33 := at.Add(33 * 24 * time.Hour)
	items, err := store.ListPublicationMaintenance(ctx, binding.TargetIdentity, false)
	if err != nil || len(items) != 2 {
		t.Fatalf("ListPublicationMaintenance = %+v err=%v", items, err)
	}
	if items[0].CheckpointIdentity != c1.CheckpointIdentity || items[0].NotBefore.After(at33) {
		t.Fatalf("interrupted legacy report_only must sort ready for completion at T+33d: got %+v", items)
	}
	if err := store.MarkPublicationRetainedReported(ctx, a1.AttemptIdentity, rep.ReportIdentity, at33); err != nil {
		t.Fatalf("MarkPublicationRetainedReported blocked interrupted legacy report_only: %v", err)
	}
	if err := store.CompletePublicationAttempt(ctx, a1.AttemptIdentity, rep.ReportIdentity); err != nil {
		t.Fatalf("CompletePublicationAttempt failed: %v", err)
	}
	pending, err := store.HasPendingPublicationMaintenance(ctx, binding.TargetIdentity)
	if err != nil || pending {
		t.Fatalf("HasPendingPublicationMaintenance remained %v (err=%v) after resuming legacy report_only", pending, err)
	}
}
