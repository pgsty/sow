package state

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func publicationStoreFixture(t *testing.T) (*Store, PublicationTargetBinding, []GenerationFile) {
	t.Helper()
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
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
	if _, err := store.DB().ExecContext(ctx, `UPDATE repository_state SET built_generation = '00000000000000000001' WHERE singleton = 1`); err != nil {
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
	checkpoint := AppliedCheckpoint{
		RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: attempt.AttemptIdentity, Generation: 1, ManifestSHA256: manifestSHA, InventoryComplete: true,
		Views: []PublicationCheckpointView{{ViewID: "dists/el9/x86_64", PointerPath: manifest[0].Path, RemoteIdentity: "etag-new"}}, Inventory: inventory,
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
	verified := time.Now().UTC().Add(-31 * 24 * time.Hour)
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
	firstCheckpoint := AppliedCheckpoint{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: first.AttemptIdentity, Generation: 1, ManifestSHA256: firstSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: firstInventory}
	if err := store.PutAppliedCheckpoint(ctx, &firstCheckpoint); err != nil {
		t.Fatal(err)
	}
	oldVerified := time.Now().UTC().Add(-31 * 24 * time.Hour)
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
	checkpoint := AppliedCheckpoint{
		RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: attempt.AttemptIdentity,
		Generation: 1, ManifestSHA256: manifestSHA, InventoryComplete: true, Views: []PublicationCheckpointView{}, Inventory: inventory,
	}
	if err := store.PutAppliedCheckpoint(ctx, &checkpoint); err != nil {
		t.Fatal(err)
	}
	verified := time.Now().UTC().Add(-31 * 24 * time.Hour)
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
