package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestApplyRefUpdateTargetsExistingCommit(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	target := installTransactionTestCommit(t, store, "views/latest/asset/all/all.tsv", "desired view")
	stage := transactionTestStage(t, stateDir, "remote.tsv", "published metadata")
	ref, err := RemoteRef("cf", "latest", "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	commit, changed, err := store.Apply(context.Background(), "publish", "record cf publish", map[string]string{
		"remotes/cf/latest/asset/all/all.tsv": stage,
	}, []RefUpdate{{Name: ref, Expected: plumbing.ZeroHash, Target: target}}, ApplyOptions{})
	if err != nil || !changed || commit.IsZero() || commit == target {
		t.Fatalf("apply commit=%s target=%s changed=%v err=%v", commit, target, changed, err)
	}
	assertTransactionTestRef(t, store, ref, target)
	journals, err := store.readJournals()
	if err != nil || len(journals) != 1 || len(journals[0].Refs) != 1 {
		t.Fatalf("journals=%+v err=%v", journals, err)
	}
	if journals[0].Phase != "complete" || journals[0].Refs[0].Target != target.String() {
		t.Fatalf("journal did not preserve explicit target: %+v", journals[0])
	}
}

func TestRecoverAbortedRequiresExactRecordAndReplaysRepairedFrozenStage(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/packages/jammy/arm64.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "old\n")
	if baseline.IsZero() {
		t.Fatal("baseline commit is zero")
	}
	desired := transactionTestStage(t, stateDir, "desired.tsv", "new\n")
	backup := desired + ".repair"
	ref, err := ViewRef("beta", "packages", "jammy", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	transactionID, err := NewTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	_, _, applyErr := store.Apply(t.Context(), "add", "test aborted exact replay", map[string]string{canonicalPath: desired}, []RefUpdate{{Name: ref}}, ApplyOptions{
		TransactionID: transactionID,
		AfterIntent: func() error {
			if err := os.Rename(desired, backup); err != nil {
				return err
			}
			return os.Mkdir(desired, 0o700)
		},
	})
	if applyErr == nil {
		t.Fatal("real staged-path filesystem fault did not abort Apply")
	}
	record, exists, err := store.Transaction(transactionID)
	if err != nil || !exists || record.Phase != "aborted" || !record.Commit.IsZero() {
		t.Fatalf("aborted record exists=%t record=%+v err=%v apply_err=%v", exists, record, err, applyErr)
	}
	if head, err := store.HeadHash(); err != nil || head != baseline {
		t.Fatalf("aborted Apply changed HEAD head=%s want=%s err=%v", head, baseline, err)
	}
	if _, exists, err := store.Ref(ref); err != nil || exists {
		t.Fatalf("aborted Apply advanced ref exists=%t err=%v", exists, err)
	}
	if err := os.Remove(desired); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, desired); err != nil {
		t.Fatal(err)
	}

	tampered := record
	tampered.Message = "different higher-level intent"
	if _, err := store.RecoverAborted(t.Context(), tampered); err == nil || !strings.Contains(err.Error(), "changed after higher-level recovery admission") {
		t.Fatalf("tampered aborted recovery err=%v", err)
	}
	stillAborted, exists, err := store.Transaction(transactionID)
	if err != nil || !exists || stillAborted.Phase != "aborted" {
		t.Fatalf("rejected retry changed record exists=%t record=%+v err=%v", exists, stillAborted, err)
	}
	otherStage := transactionTestStage(t, stateDir, "other-aborted.tsv", "unrelated\n")
	other, err := store.buildJournal("rm", "unrelated aborted transaction", baseline, map[string]string{"views/beta/packages/jammy/amd64.tsv": otherStage}, nil)
	if err != nil {
		t.Fatal(err)
	}
	other.Phase = "aborted"
	other.Failure = "aborted before canonical commit"
	if err := store.writeJournal(other); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecoverAborted(t.Context(), record); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("aborted retry crossed another non-complete transaction: %v", err)
	}
	if err := os.Remove(filepath.Join(stateDir, "journal", other.ID+".json")); err != nil {
		t.Fatal(err)
	}

	recovered, err := store.RecoverAborted(t.Context(), record)
	if err != nil || !recovered.Recovered || recovered.ID != transactionID || recovered.Commit.IsZero() {
		t.Fatalf("recover aborted result=%+v err=%v", recovered, err)
	}
	completed, exists, err := store.Transaction(transactionID)
	if err != nil || !exists || completed.Phase != "complete" || completed.Commit != recovered.Commit {
		t.Fatalf("completed record exists=%t record=%+v err=%v", exists, completed, err)
	}
	if current, exists, err := store.Ref(ref); err != nil || !exists || current != recovered.Commit {
		t.Fatalf("recovered ref current=%s exists=%t commit=%s err=%v", current, exists, recovered.Commit, err)
	}
	reader, err := store.OpenPathAt(recovered.Commit, canonicalPath)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || string(body) != "new\n" {
		t.Fatalf("recovered canonical body=%q read_err=%v close_err=%v", body, readErr, closeErr)
	}
}

func TestApplyRefUpdateTargetRecoversExactlyAfterCommit(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	target := installTransactionTestCommit(t, store, "views/latest/asset/all/all.tsv", "desired view")
	stage := transactionTestStage(t, stateDir, "remote.tsv", "published metadata")
	ref, err := RemoteRef("cos", "latest", "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected process stop")
	canonical, changed, err := store.Apply(context.Background(), "publish", "record cos publish", map[string]string{
		"remotes/cos/latest/asset/all/all.tsv": stage,
	}, []RefUpdate{{Name: ref, Expected: plumbing.ZeroHash, Target: target}}, ApplyOptions{AfterCommit: func() error { return injected }})
	if !errors.Is(err, injected) || !changed || canonical.IsZero() || canonical == target {
		t.Fatalf("apply canonical=%s target=%s changed=%v err=%v", canonical, target, changed, err)
	}
	journals, err := store.readJournals()
	if err != nil || len(journals) != 1 || journals[0].Phase != "committed" || journals[0].Refs[0].Target != target.String() {
		t.Fatalf("committed journal=%+v err=%v", journals, err)
	}

	// Move aggregate HEAD again before recovery. The durable journal must still
	// replay the explicitly recorded leaf target, not either aggregate commit.
	later := installTransactionTestCommit(t, store, "metadata/unrelated.tsv", "later aggregate state")
	if later == canonical || later == target {
		t.Fatalf("later commit did not advance aggregate HEAD: %s", later)
	}
	results, err := store.Recover(context.Background())
	if err != nil || len(results) != 1 || results[0].Commit != canonical {
		t.Fatalf("recover results=%+v err=%v", results, err)
	}
	assertTransactionTestRef(t, store, ref, target)
}

func TestApplyRefDeletionRecoversIdempotentlyAfterCommit(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	ref, err := ViewRef("beta", "assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	firstStage := transactionTestStage(t, stateDir, "first.tsv", "first\n")
	first, _, err := store.Apply(t.Context(), "test", "create ref", map[string]string{"views/beta/assets/all/all.tsv": firstStage}, []RefUpdate{{Name: ref}}, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	secondStage := transactionTestStage(t, stateDir, "second.tsv", "second\n")
	injected := errors.New("after delete commit")
	commit, _, err := store.Apply(t.Context(), "test", "delete ref", map[string]string{"views/beta/assets/all/all.tsv": secondStage}, []RefUpdate{{Name: ref, Expected: first, Delete: true}}, ApplyOptions{AfterCommit: func() error { return injected }})
	if !errors.Is(err, injected) || commit.IsZero() {
		t.Fatalf("commit=%s err=%v", commit, err)
	}
	if current, exists, err := store.Ref(ref); err != nil || !exists || current != first {
		t.Fatalf("ref changed before recovery current=%s exists=%v err=%v", current, exists, err)
	}
	results, err := store.Recover(t.Context())
	if err != nil || len(results) != 1 {
		t.Fatalf("recover results=%#v err=%v", results, err)
	}
	if _, exists, err := store.Ref(ref); err != nil || exists {
		t.Fatalf("deleted ref remains exists=%v err=%v", exists, err)
	}
	if results, err := store.Recover(t.Context()); err != nil || len(results) != 0 {
		t.Fatalf("idempotent recover results=%#v err=%v", results, err)
	}
}

func TestCanonicalFileDeletionRecoversFromIntentAndRemainsAbsent(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const removed = "remotes/cf/channels/latest/rpm/el10/x86_64.json"
	oldStage := transactionTestStage(t, stateDir, "old-channel.json", "old-channel\n")
	baseline, _, err := store.InstallPaths(map[string]string{removed: oldStage}, "seed stale channel")
	if err != nil {
		t.Fatal(err)
	}
	marker := transactionTestStage(t, stateDir, "generation.json", "generation\n")
	journal, err := store.buildJournalWithDeletes("publish", "prune stale channel", baseline, map[string]string{
		"remotes/cf/generation.json": marker,
	}, []string{removed}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeJournal(journal); err != nil {
		t.Fatal(err)
	}

	results, err := store.Recover(t.Context())
	if err != nil || len(results) != 1 || !results[0].Recovered {
		t.Fatalf("recover results=%#v err=%v", results, err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "state", filepath.FromSlash(removed))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted canonical channel remains: %v", err)
	}
	if reader, err := store.OpenPathAt(results[0].Commit, removed); !errors.Is(err, object.ErrFileNotFound) {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("deleted canonical channel remains in recovered commit: %v", err)
	}
	if results, err := store.Recover(t.Context()); err != nil || len(results) != 0 {
		t.Fatalf("second recovery results=%#v err=%v", results, err)
	}
}

func TestCanonicalFileDeletionRecoversAfterCommitBeforeJournalAdvance(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const removed = "remotes/cos/channels/beta/rpm/el10/aarch64.json"
	oldStage := transactionTestStage(t, stateDir, "old-channel.json", "old-channel\n")
	baseline, _, err := store.InstallPaths(map[string]string{removed: oldStage}, "seed stale channel")
	if err != nil {
		t.Fatal(err)
	}
	marker := transactionTestStage(t, stateDir, "generation.json", "generation\n")
	staged := map[string]string{"remotes/cos/generation.json": marker}
	journal, err := store.buildJournalWithDeletes("publish", "prune stale channel", baseline, staged, []string{removed}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeJournal(journal); err != nil {
		t.Fatal(err)
	}
	commit, changed, err := store.installPathChanges(staged, []string{removed}, journal.Message)
	if err != nil || !changed || commit == baseline {
		t.Fatalf("simulated commit=%s changed=%v err=%v", commit, changed, err)
	}
	// The journal deliberately remains at intent, simulating process death after
	// Git commit but before the durable journal phase update. The caller has
	// already returned an error and removed transaction staging, so recovery
	// must prove the exact committed tree before it asks for staged bytes.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	results, err := store.Recover(t.Context())
	if err != nil || len(results) != 1 || results[0].Commit != commit {
		t.Fatalf("recover results=%#v err=%v", results, err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "state", filepath.FromSlash(removed))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted canonical channel reappeared: %v", err)
	}
}

func TestCanonicalFileDeletionRecoversPartialWorktreeMutation(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const removed = "remotes/cf/channels/beta/rpm/el10/x86_64.json"
	oldStage := transactionTestStage(t, stateDir, "old-channel.json", "old-channel\n")
	baseline, _, err := store.InstallPaths(map[string]string{removed: oldStage}, "seed stale channel")
	if err != nil {
		t.Fatal(err)
	}
	marker := transactionTestStage(t, stateDir, "generation.json", "generation\n")
	staged := map[string]string{"remotes/cf/generation.json": marker}
	journal, err := store.buildJournalWithDeletes("publish", "prune stale channel", baseline, staged, []string{removed}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeJournal(journal); err != nil {
		t.Fatal(err)
	}
	canonicalPath := filepath.Join(stateDir, "state", filepath.FromSlash(removed))
	crashBackup := filepath.Join(stateDir, "simulated-crash-backup")
	if err := os.Rename(canonicalPath, crashBackup); err != nil {
		t.Fatal(err)
	}
	// Simulate process death after moving the tracked deletion candidate out of
	// the worktree but before staging or committing the deletion.
	results, err := store.Recover(t.Context())
	if err != nil || len(results) != 1 || !results[0].Recovered {
		t.Fatalf("recover results=%#v err=%v", results, err)
	}
	if _, err := os.Stat(canonicalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partially deleted canonical channel remains after recovery: %v", err)
	}
}

func TestCanonicalInstallRecoversAfterFilesWereStagedBeforeCommit(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const existing = "views/beta/assets/all/all.tsv"
	const added = "remotes/cf/generation.json"
	baselineStage := transactionTestStage(t, stateDir, "baseline.tsv", "old\n")
	baseline, _, err := store.InstallPaths(map[string]string{existing: baselineStage}, "seed baseline")
	if err != nil {
		t.Fatal(err)
	}
	existingStage := transactionTestStage(t, stateDir, "desired.tsv", "new\n")
	addedStage := transactionTestStage(t, stateDir, "generation.json", "generation\n")
	ref, err := ViewRef("beta", "assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	staged := map[string]string{existing: existingStage, added: addedStage}
	journal, err := store.buildJournal("publish", "install after precommit crash", baseline, staged, []RefUpdate{{Name: ref}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeJournal(journal); err != nil {
		t.Fatal(err)
	}
	repository, err := store.ensureRepository()
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	for canonical, source := range staged {
		body, readErr := os.ReadFile(source)
		if readErr != nil {
			t.Fatal(readErr)
		}
		destination := filepath.Join(stateDir, "state", filepath.FromSlash(canonical))
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, body, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := worktree.Add(canonical); err != nil {
			t.Fatal(err)
		}
	}
	if head, err := store.HeadHash(); err != nil || head != baseline {
		t.Fatalf("simulated precommit crash moved HEAD=%s want=%s err=%v", head, baseline, err)
	}

	results, err := store.Recover(t.Context())
	if err != nil || len(results) != 1 || results[0].Commit == baseline || results[0].Commit.IsZero() {
		t.Fatalf("recover results=%#v baseline=%s err=%v", results, baseline, err)
	}
	commit := results[0].Commit
	assertTransactionTestRef(t, store, ref, commit)
	for canonical, want := range map[string]string{existing: "new\n", added: "generation\n"} {
		got, readErr := os.ReadFile(filepath.Join(stateDir, "state", filepath.FromSlash(canonical)))
		if readErr != nil || string(got) != want {
			t.Fatalf("recovered %s=%q want=%q err=%v", canonical, got, want, readErr)
		}
	}
	status, err := worktree.Status()
	if err != nil || !status.IsClean() {
		t.Fatalf("recovered worktree status=%v err=%v", status, err)
	}
}

func TestCanonicalInstallZeroHeadRecoversOnlyJournalPaths(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonical = "manifests/assets.tsv"
	stage := transactionTestStage(t, stateDir, "assets.tsv", "desired\n")
	journal, err := store.buildJournal("init", "recover first canonical commit", plumbing.ZeroHash, map[string]string{canonical: stage}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeJournal(journal); err != nil {
		t.Fatal(err)
	}
	repository, err := store.ensureRepository()
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(stateDir, "state", filepath.FromSlash(canonical))
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("desired\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add(canonical); err != nil {
		t.Fatal(err)
	}

	results, err := store.Recover(t.Context())
	if err != nil || len(results) != 1 || results[0].Commit.IsZero() {
		t.Fatalf("zero-head recovery results=%#v err=%v", results, err)
	}
	if got, err := os.ReadFile(destination); err != nil || string(got) != "desired\n" {
		t.Fatalf("recovered canonical=%q err=%v", got, err)
	}
	status, err := worktree.Status()
	if err != nil || !status.IsClean() {
		t.Fatalf("zero-head recovery status=%v err=%v", status, err)
	}
}

func TestRecoveryRejectsAndPreservesExternalChangesAfterIntent(t *testing.T) {
	for _, scenario := range []string{"tracked", "untracked"} {
		t.Run(scenario, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), ".sow")
			store := New(stateDir)
			const target = "views/beta/assets/all/all.tsv"
			const unrelated = "metadata/unrelated.tsv"
			baselineTarget := transactionTestStage(t, stateDir, "baseline-target.tsv", "old\n")
			baselineUnrelated := transactionTestStage(t, stateDir, "baseline-unrelated.tsv", "original\n")
			baseline, _, err := store.InstallPaths(map[string]string{target: baselineTarget, unrelated: baselineUnrelated}, "seed recovery baseline")
			if err != nil {
				t.Fatal(err)
			}
			desired := transactionTestStage(t, stateDir, "desired.tsv", "desired\n")
			journal, err := store.buildJournal("publish", "recover without erasing external work", baseline, map[string]string{target: desired}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.writeJournal(journal); err != nil {
				t.Fatal(err)
			}
			repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
			if err != nil {
				t.Fatal(err)
			}
			worktree, err := repository.Worktree()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stateDir, "state", filepath.FromSlash(target)), []byte("desired\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := worktree.Add(target); err != nil {
				t.Fatal(err)
			}
			manualPath := filepath.Join(stateDir, "state", filepath.FromSlash(unrelated))
			manualBody := "manual tracked repair\n"
			if scenario == "untracked" {
				manualPath = filepath.Join(stateDir, "state", "manual-repair.txt")
				manualBody = "manual untracked repair\n"
			}
			if err := os.WriteFile(manualPath, []byte(manualBody), 0o644); err != nil {
				t.Fatal(err)
			}

			if results, err := store.Recover(t.Context()); err == nil || !errors.Is(err, ErrRefConflict) || len(results) != 0 {
				t.Fatalf("external change recovery results=%#v err=%v", results, err)
			}
			if got, err := os.ReadFile(manualPath); err != nil || string(got) != manualBody {
				t.Fatalf("external repair was lost got=%q err=%v", got, err)
			}
			if head, err := store.HeadHash(); err != nil || head != baseline {
				t.Fatalf("rejected recovery moved HEAD=%s want=%s err=%v", head, baseline, err)
			}
			journals, err := store.readJournals()
			if err != nil || len(journals) != 1 || journals[0].Phase != "intent" {
				t.Fatalf("rejected recovery journal=%#v err=%v", journals, err)
			}
		})
	}
}

func TestRecoveryRejectsCommittedCandidateWithNonJournalChanges(t *testing.T) {
	for _, scenario := range []string{"same-commit-extra", "later-descendant"} {
		t.Run(scenario, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), ".sow")
			store := New(stateDir)
			const target = "views/beta/assets/all/all.tsv"
			const unrelated = "metadata/unrelated.tsv"
			baselineTarget := transactionTestStage(t, stateDir, "baseline-target.tsv", "old\n")
			baselineUnrelated := transactionTestStage(t, stateDir, "baseline-unrelated.tsv", "original\n")
			baseline, _, err := store.InstallPaths(map[string]string{target: baselineTarget, unrelated: baselineUnrelated}, "seed recovery baseline")
			if err != nil {
				t.Fatal(err)
			}
			desired := transactionTestStage(t, stateDir, "desired.tsv", "desired\n")
			manual := transactionTestStage(t, stateDir, "manual.tsv", "manual change\n")
			ref, err := ViewRef("beta", "assets", "all", "all")
			if err != nil {
				t.Fatal(err)
			}
			journal, err := store.buildJournal("publish", "recover only the exact transaction commit", baseline, map[string]string{target: desired}, []RefUpdate{{Name: ref}})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.writeJournal(journal); err != nil {
				t.Fatal(err)
			}

			firstChanges := map[string]string{target: desired}
			if scenario == "same-commit-extra" {
				firstChanges[unrelated] = manual
			}
			candidate, changed, err := store.installPathChanges(firstChanges, nil, "simulated transaction commit")
			if err != nil || !changed || candidate == baseline {
				t.Fatalf("candidate=%s changed=%v err=%v", candidate, changed, err)
			}
			if scenario == "later-descendant" {
				candidate, changed, err = store.installPathChanges(map[string]string{unrelated: manual}, nil, "later unrelated commit")
				if err != nil || !changed {
					t.Fatalf("descendant=%s changed=%v err=%v", candidate, changed, err)
				}
			}

			if results, err := store.Recover(t.Context()); err == nil || !errors.Is(err, ErrRefConflict) || len(results) != 0 {
				t.Fatalf("non-journal candidate recovery results=%#v err=%v", results, err)
			}
			if head, err := store.HeadHash(); err != nil || head != candidate {
				t.Fatalf("rejected recovery moved HEAD=%s want=%s err=%v", head, candidate, err)
			}
			if got, err := os.ReadFile(filepath.Join(stateDir, "state", filepath.FromSlash(unrelated))); err != nil || string(got) != "manual change\n" {
				t.Fatalf("unrelated committed work was lost got=%q err=%v", got, err)
			}
			if _, exists, err := store.Ref(ref); err != nil || exists {
				t.Fatalf("rejected recovery advanced ref exists=%v err=%v", exists, err)
			}
			journals, err := store.readJournals()
			if err != nil || len(journals) != 1 || journals[0].Phase != "intent" {
				t.Fatalf("rejected recovery journal=%#v err=%v", journals, err)
			}
		})
	}
}

func TestRecoveryRejectsAndPreservesPostCommitWorktreeChanges(t *testing.T) {
	for _, scenario := range []string{"tracked", "untracked", "chmod"} {
		t.Run(scenario, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), ".sow")
			store := New(stateDir)
			const target = "views/beta/assets/all/all.tsv"
			const unrelated = "metadata/unrelated.tsv"
			baselineTarget := transactionTestStage(t, stateDir, "baseline-target.tsv", "old\n")
			baselineUnrelated := transactionTestStage(t, stateDir, "baseline-unrelated.tsv", "original\n")
			baseline, _, err := store.InstallPaths(map[string]string{target: baselineTarget, unrelated: baselineUnrelated}, "seed post-commit baseline")
			if err != nil {
				t.Fatal(err)
			}
			desired := transactionTestStage(t, stateDir, "desired.tsv", "desired\n")
			ref, err := ViewRef("beta", "assets", "all", "all")
			if err != nil {
				t.Fatal(err)
			}
			journal, err := store.buildJournal("publish", "recognize exact committed candidate", baseline, map[string]string{target: desired}, []RefUpdate{{Name: ref}})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.writeJournal(journal); err != nil {
				t.Fatal(err)
			}
			candidate, changed, err := store.installPathChanges(map[string]string{target: desired}, nil, journal.Message)
			if err != nil || !changed || candidate == baseline {
				t.Fatalf("candidate=%s changed=%v err=%v", candidate, changed, err)
			}

			manualPath := filepath.Join(stateDir, "state", filepath.FromSlash(unrelated))
			manualBody := "manual tracked repair\n"
			manualMode := os.FileMode(0o644)
			switch scenario {
			case "tracked":
				if err := os.WriteFile(manualPath, []byte(manualBody), manualMode); err != nil {
					t.Fatal(err)
				}
			case "untracked":
				manualPath = filepath.Join(stateDir, "state", "manual-untracked-repair.txt")
				manualBody = "manual untracked repair\n"
				if err := os.WriteFile(manualPath, []byte(manualBody), manualMode); err != nil {
					t.Fatal(err)
				}
			case "chmod":
				manualBody = "original\n"
				manualMode = 0o600
				if err := os.Chmod(manualPath, manualMode); err != nil {
					t.Fatal(err)
				}
			}

			if results, err := store.Recover(t.Context()); err == nil || !errors.Is(err, ErrRefConflict) || len(results) != 0 {
				t.Fatalf("post-commit external change recovery results=%#v err=%v", results, err)
			}
			body, err := os.ReadFile(manualPath)
			info, statErr := os.Lstat(manualPath)
			if err != nil || statErr != nil {
				t.Fatalf("post-commit external work became unreadable read_err=%v stat_err=%v", err, statErr)
			}
			if string(body) != manualBody || info.Mode().Perm() != manualMode {
				t.Fatalf("post-commit external work was not preserved body=%q mode=%v", body, info.Mode().Perm())
			}
			if head, err := store.HeadHash(); err != nil || head != candidate {
				t.Fatalf("rejected recovery moved HEAD=%s want=%s err=%v", head, candidate, err)
			}
			if _, exists, err := store.Ref(ref); err != nil || exists {
				t.Fatalf("rejected recovery advanced ref exists=%v err=%v", exists, err)
			}
		})
	}
}

func TestRecoveryRejectsUnrelatedNonExecutablePermissionChangeAtExpectedHead(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const target = "views/beta/assets/all/all.tsv"
	const unrelated = "metadata/unrelated.tsv"
	baselineTarget := transactionTestStage(t, stateDir, "baseline-target.tsv", "old\n")
	baselineUnrelated := transactionTestStage(t, stateDir, "baseline-unrelated.tsv", "original\n")
	baseline, _, err := store.InstallPaths(map[string]string{target: baselineTarget, unrelated: baselineUnrelated}, "seed unrelated chmod baseline")
	if err != nil {
		t.Fatal(err)
	}
	desired := transactionTestStage(t, stateDir, "desired.tsv", "desired\n")
	journal, err := store.buildJournal("publish", "reject unrelated chmod", baseline, map[string]string{target: desired}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeJournal(journal); err != nil {
		t.Fatal(err)
	}
	unrelatedPath := filepath.Join(stateDir, "state", filepath.FromSlash(unrelated))
	if err := os.Chmod(unrelatedPath, 0o600); err != nil {
		t.Fatal(err)
	}

	if results, err := store.Recover(t.Context()); err == nil || !errors.Is(err, ErrRefConflict) || len(results) != 0 {
		t.Fatalf("unrelated chmod recovery results=%#v err=%v", results, err)
	}
	info, err := os.Lstat(unrelatedPath)
	if err != nil {
		t.Fatalf("unrelated chmod path became unreadable: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unrelated chmod was not preserved mode=%v", info.Mode().Perm())
	}
	if head, err := store.HeadHash(); err != nil || head != baseline {
		t.Fatalf("rejected chmod recovery moved HEAD=%s want=%s err=%v", head, baseline, err)
	}
}

func TestRecoveryRejectsAndPreservesPermissionOnlyJournalPathChanges(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		body    string
		mode    os.FileMode
		stageIt bool
	}{
		{name: "baseline-0600", body: "old\n", mode: 0o600},
		{name: "baseline-0755", body: "old\n", mode: 0o755},
		{name: "desired-0600", body: "desired\n", mode: 0o600, stageIt: true},
		{name: "desired-0755", body: "desired\n", mode: 0o755, stageIt: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), ".sow")
			store := New(stateDir)
			const target = "views/beta/assets/all/all.tsv"
			baselineStage := transactionTestStage(t, stateDir, "baseline.tsv", "old\n")
			baseline, _, err := store.InstallPaths(map[string]string{target: baselineStage}, "seed permission baseline")
			if err != nil {
				t.Fatal(err)
			}
			desired := transactionTestStage(t, stateDir, "desired.tsv", "desired\n")
			journal, err := store.buildJournal("publish", "reject external chmod", baseline, map[string]string{target: desired}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.writeJournal(journal); err != nil {
				t.Fatal(err)
			}
			canonical := filepath.Join(stateDir, "state", filepath.FromSlash(target))
			if err := os.WriteFile(canonical, []byte(scenario.body), 0o644); err != nil {
				t.Fatal(err)
			}
			if scenario.stageIt {
				repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
				if err != nil {
					t.Fatal(err)
				}
				worktree, err := repository.Worktree()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := worktree.Add(target); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(canonical, scenario.mode); err != nil {
				t.Fatal(err)
			}

			if results, err := store.Recover(t.Context()); err == nil || !errors.Is(err, ErrRefConflict) || len(results) != 0 {
				t.Fatalf("permission-only recovery results=%#v err=%v", results, err)
			}
			body, err := os.ReadFile(canonical)
			info, statErr := os.Lstat(canonical)
			if err != nil || statErr != nil {
				t.Fatalf("external chmod path became unreadable read_err=%v stat_err=%v", err, statErr)
			}
			if string(body) != scenario.body || info.Mode().Perm() != scenario.mode {
				t.Fatalf("external chmod was not preserved body=%q mode=%v", body, info.Mode().Perm())
			}
			if head, err := store.HeadHash(); err != nil || head != baseline {
				t.Fatalf("rejected chmod recovery moved HEAD=%s want=%s err=%v", head, baseline, err)
			}
		})
	}
}

func TestApplyRejectsDirtyCanonicalIndexBeforeWritingJournal(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	baselineStage := transactionTestStage(t, stateDir, "baseline.tsv", "baseline\n")
	baseline, _, err := store.InstallPaths(map[string]string{"manifests/assets.tsv": baselineStage}, "seed baseline")
	if err != nil {
		t.Fatal(err)
	}
	repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(stateDir, "state", "unrelated.tsv")
	if err := os.WriteFile(unrelated, []byte("unrelated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add("unrelated.tsv"); err != nil {
		t.Fatal(err)
	}
	stage := transactionTestStage(t, stateDir, "desired.tsv", "desired\n")
	if _, _, err := store.Apply(t.Context(), "test", "must reject dirty index", map[string]string{"manifests/desired.tsv": stage}, nil, ApplyOptions{}); err == nil || !strings.Contains(err.Error(), "worktree/index is dirty") {
		t.Fatalf("dirty canonical index was accepted: %v", err)
	}
	if head, err := store.HeadHash(); err != nil || head != baseline {
		t.Fatalf("dirty rejection changed HEAD=%s want=%s err=%v", head, baseline, err)
	}
	if journals, err := store.readJournals(); err != nil || len(journals) != 0 {
		t.Fatalf("dirty rejection wrote journal=%#v err=%v", journals, err)
	}
}

func TestNormalMutationRejectsTrackedPermissionDrift(t *testing.T) {
	for _, api := range []string{"apply", "install-paths"} {
		t.Run(api, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), ".sow")
			store := New(stateDir)
			const canonical = "manifests/assets.tsv"
			baselineStage := transactionTestStage(t, stateDir, "baseline.tsv", "baseline\n")
			baseline, _, err := store.InstallPaths(map[string]string{canonical: baselineStage}, "seed permission baseline")
			if err != nil {
				t.Fatal(err)
			}
			canonicalPath := filepath.Join(stateDir, "state", filepath.FromSlash(canonical))
			if err := os.Chmod(canonicalPath, 0o600); err != nil {
				t.Fatal(err)
			}
			desired := transactionTestStage(t, stateDir, "desired.tsv", "desired\n")
			if api == "apply" {
				_, _, err = store.Apply(t.Context(), "test", "reject chmod", map[string]string{canonical: desired}, nil, ApplyOptions{})
			} else {
				_, _, err = store.InstallPaths(map[string]string{canonical: desired}, "reject chmod")
			}
			if err == nil || !errors.Is(err, ErrRefConflict) {
				t.Fatalf("normal %s accepted permission drift: %v", api, err)
			}
			body, readErr := os.ReadFile(canonicalPath)
			info, statErr := os.Lstat(canonicalPath)
			if readErr != nil || statErr != nil {
				t.Fatalf("rejected %s made chmod path unreadable read_err=%v stat_err=%v", api, readErr, statErr)
			}
			if string(body) != "baseline\n" || info.Mode().Perm() != 0o600 {
				t.Fatalf("rejected %s lost external chmod body=%q mode=%v", api, body, info.Mode().Perm())
			}
			if head, err := store.HeadHash(); err != nil || head != baseline {
				t.Fatalf("rejected %s moved HEAD=%s want=%s err=%v", api, head, baseline, err)
			}
			if api == "apply" {
				if journals, err := store.readJournals(); err != nil || len(journals) != 0 {
					t.Fatalf("rejected apply wrote journal=%#v err=%v", journals, err)
				}
			}
		})
	}
}

func TestApplyRejectsTrackedPathThroughParentSymlink(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonical = "metadata/nested/value.tsv"
	baselineStage := transactionTestStage(t, stateDir, "baseline.tsv", "baseline\n")
	baseline, _, err := store.InstallPaths(map[string]string{canonical: baselineStage}, "seed parent path baseline")
	if err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "nested")
	if err := os.MkdirAll(external, 0o755); err != nil {
		t.Fatal(err)
	}
	externalPath := filepath.Join(external, "value.tsv")
	if err := os.WriteFile(externalPath, []byte("baseline\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(stateDir, "state", "metadata", "nested")
	if err := os.RemoveAll(nested); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, nested); err != nil {
		t.Fatal(err)
	}
	desired := transactionTestStage(t, stateDir, "desired.tsv", "desired\n")
	if _, _, err := store.Apply(t.Context(), "test", "reject parent symlink", map[string]string{canonical: desired}, nil, ApplyOptions{}); err == nil || !errors.Is(err, ErrRefConflict) {
		t.Fatalf("parent symlink was accepted: %v", err)
	}
	if body, err := os.ReadFile(externalPath); err != nil || string(body) != "baseline\n" {
		t.Fatalf("external symlink target was changed body=%q err=%v", body, err)
	}
	if head, err := store.HeadHash(); err != nil || head != baseline {
		t.Fatalf("parent symlink rejection moved HEAD=%s want=%s err=%v", head, baseline, err)
	}
}

func TestCommittedJournalRecoveryRejectsDirtyCurrentWorktree(t *testing.T) {
	for _, scenario := range []string{"tracked", "untracked", "chmod"} {
		t.Run(scenario, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), ".sow")
			store := New(stateDir)
			const unrelated = "metadata/unrelated.tsv"
			baseline := transactionTestStage(t, stateDir, "baseline.tsv", "original\n")
			if _, _, err := store.InstallPaths(map[string]string{unrelated: baseline}, "seed committed recovery baseline"); err != nil {
				t.Fatal(err)
			}
			stage := transactionTestStage(t, stateDir, "published.tsv", "published\n")
			ref, err := RemoteRef("cf", "latest", "asset", "all", "all")
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("stop after committed journal")
			commit, _, err := store.Apply(t.Context(), "publish", "commit before ref", map[string]string{"remotes/cf/latest/asset/all/all.tsv": stage}, []RefUpdate{{Name: ref}}, ApplyOptions{AfterCommit: func() error { return injected }})
			if !errors.Is(err, injected) || commit.IsZero() {
				t.Fatalf("commit=%s err=%v", commit, err)
			}
			manualPath := filepath.Join(stateDir, "state", filepath.FromSlash(unrelated))
			manualBody := "manual tracked repair\n"
			manualMode := os.FileMode(0o644)
			switch scenario {
			case "tracked":
				if err := os.WriteFile(manualPath, []byte(manualBody), manualMode); err != nil {
					t.Fatal(err)
				}
			case "untracked":
				manualPath = filepath.Join(stateDir, "state", "manual-untracked-repair.txt")
				manualBody = "manual untracked repair\n"
				if err := os.WriteFile(manualPath, []byte(manualBody), manualMode); err != nil {
					t.Fatal(err)
				}
			case "chmod":
				manualBody = "original\n"
				manualMode = 0o600
				if err := os.Chmod(manualPath, manualMode); err != nil {
					t.Fatal(err)
				}
			}
			if results, err := store.Recover(t.Context()); err == nil || !errors.Is(err, ErrRefConflict) || len(results) != 0 {
				t.Fatalf("committed dirty recovery results=%#v err=%v", results, err)
			}
			body, readErr := os.ReadFile(manualPath)
			info, statErr := os.Lstat(manualPath)
			if readErr != nil || statErr != nil {
				t.Fatalf("committed external work became unreadable read_err=%v stat_err=%v", readErr, statErr)
			}
			if string(body) != manualBody || info.Mode().Perm() != manualMode {
				t.Fatalf("committed external work was not preserved body=%q mode=%v", body, info.Mode().Perm())
			}
			if _, exists, err := store.Ref(ref); err != nil || exists {
				t.Fatalf("dirty committed recovery advanced ref exists=%v err=%v", exists, err)
			}
			journals, err := store.readJournals()
			if err != nil || len(journals) != 1 || journals[0].Phase != "committed" {
				t.Fatalf("dirty committed journal=%#v err=%v", journals, err)
			}
		})
	}
}

func TestApplyRejectsStageInsideCanonicalWorktree(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	baselineStage := transactionTestStage(t, stateDir, "baseline.tsv", "baseline\n")
	if _, _, err := store.InstallPaths(map[string]string{"manifests/assets.tsv": baselineStage}, "seed baseline"); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(stateDir, "state", "inside-stage.tsv")
	if err := os.WriteFile(inside, []byte("inside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Apply(t.Context(), "test", "reject in-worktree stage", map[string]string{"manifests/desired.tsv": inside}, nil, ApplyOptions{}); err == nil || !strings.Contains(err.Error(), "outside the canonical state worktree") {
		t.Fatalf("in-worktree stage was accepted: %v", err)
	}
}

func TestApplyRefUpdateRejectsMissingTargetCommit(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	baseline := installTransactionTestCommit(t, store, "views/latest/asset/all/all.tsv", "desired view")
	stage := transactionTestStage(t, stateDir, "remote.tsv", "published metadata")
	ref, err := RemoteRef("cf", "latest", "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	missing := plumbing.NewHash(strings.Repeat("f", 40))
	commit, changed, err := store.Apply(context.Background(), "publish", "reject missing target", map[string]string{
		"remotes/cf/latest/asset/all/all.tsv": stage,
	}, []RefUpdate{{Name: ref, Expected: plumbing.ZeroHash, Target: missing}}, ApplyOptions{})
	if err == nil || !strings.Contains(err.Error(), "not a local commit") || !commit.IsZero() || changed {
		t.Fatalf("missing target commit=%s changed=%v err=%v", commit, changed, err)
	}
	head, err := store.HeadHash()
	if err != nil || head != baseline {
		t.Fatalf("missing target changed HEAD to %s, want %s, err=%v", head, baseline, err)
	}
	journals, err := store.readJournals()
	if err != nil || len(journals) != 0 {
		t.Fatalf("missing target left journal=%+v err=%v", journals, err)
	}
}

func TestJournalRejectsInvalidRefTargetHash(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	stage := transactionTestStage(t, stateDir, "remote.tsv", "published metadata")
	ref, err := RemoteRef("cf", "latest", "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := store.buildJournal("publish", "invalid target", plumbing.ZeroHash, map[string]string{
		"remotes/cf/latest/asset/all/all.tsv": stage,
	}, []RefUpdate{{Name: ref}})
	if err != nil {
		t.Fatal(err)
	}
	journal.Refs[0].Target = "not-a-git-hash"
	if err := store.writeJournal(journal); err == nil || !strings.Contains(err.Error(), "invalid target ref hash") {
		t.Fatalf("invalid target accepted: %v", err)
	}

	journal.Refs[0].Target = plumbing.ZeroHash.String()
	journal.Commit = strings.Repeat("a", 40)
	journal.Phase = "committed"
	if err := validateJournal(journal); err == nil || !strings.Contains(err.Error(), "unresolved target ref hash") {
		t.Fatalf("committed zero target accepted: %v", err)
	}
}

func TestApplyRefUpdateZeroTargetUsesCanonicalCommit(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	stage := transactionTestStage(t, stateDir, "beta.tsv", "canonical")
	ref, err := ViewRef("beta", "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	commit, changed, err := store.Apply(context.Background(), "promote", "default target", map[string]string{
		"views/beta/asset/all/all.tsv": stage,
	}, []RefUpdate{{Name: ref, Expected: plumbing.ZeroHash}}, ApplyOptions{})
	if err != nil || !changed || commit.IsZero() {
		t.Fatalf("apply commit=%s changed=%v err=%v", commit, changed, err)
	}
	assertTransactionTestRef(t, store, ref, commit)
	journals, err := store.readJournals()
	if err != nil || len(journals) != 1 || journals[0].Refs[0].Target != commit.String() {
		t.Fatalf("default target not resolved in journal: %+v err=%v", journals, err)
	}
}

func TestApplyRecoversInterruptionAfterCommit(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	transactionDir := filepath.Join(stateDir, "transactions", "fixture")
	if err := os.MkdirAll(transactionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(transactionDir, "beta.tsv")
	if err := os.WriteFile(stage, []byte("canonical"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(stateDir)
	ref, err := ViewRef("beta", "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected process stop")
	commit, changed, err := store.Apply(context.Background(), "promote", "fixture", map[string]string{
		"views/beta/asset/all/all.tsv": stage,
	}, []RefUpdate{{Name: ref, Expected: plumbing.ZeroHash}}, ApplyOptions{AfterCommit: func() error { return injected }})
	if !errors.Is(err, injected) || !changed || commit.IsZero() {
		t.Fatalf("apply commit=%s changed=%v err=%v", commit, changed, err)
	}
	if _, exists, err := store.Ref(ref); err != nil || exists {
		t.Fatalf("ref advanced before recovery exists=%v err=%v", exists, err)
	}
	if err := store.RequireNoIncompleteTransactions(); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("incomplete transaction not detected: %v", err)
	}
	results, err := store.Recover(context.Background())
	if err != nil || len(results) != 1 || results[0].Commit != commit {
		t.Fatalf("recover results=%+v err=%v", results, err)
	}
	after, exists, err := store.Ref(ref)
	if err != nil || !exists || after != commit {
		t.Fatalf("recovered ref=%s exists=%v err=%v", after, exists, err)
	}
	results, err = store.Recover(context.Background())
	if err != nil || len(results) != 0 {
		t.Fatalf("recovery replay not idempotent: %+v %v", results, err)
	}
}

func TestApplyRejectsStageOutsideStateAndTamperedRecovery(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, ".sow")
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(stateDir)
	if _, _, err := store.Apply(context.Background(), "init", "bad", map[string]string{"manifests/a.tsv": outside}, nil, ApplyOptions{}); err == nil || !strings.Contains(err.Error(), "below .sow") {
		t.Fatalf("outside stage accepted: %v", err)
	}
	transactionDir := filepath.Join(stateDir, "transactions", "tamper")
	if err := os.MkdirAll(transactionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(transactionDir, "a.tsv")
	if err := os.WriteFile(stage, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	journal, err := store.buildJournal("init", "tamper", plumbing.ZeroHash, map[string]string{"manifests/a.tsv": stage}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeJournal(journal); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Recover(context.Background()); err == nil || !strings.Contains(err.Error(), "changed after intent") {
		t.Fatalf("tampered recovery accepted: %v", err)
	}
}

func TestInterruptedJournalTemporaryFileDoesNotBlockRecovery(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	journalDir := filepath.Join(stateDir, "state", "journal")
	if err := os.MkdirAll(journalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// This is the exact suffix used by older atomic-write temporaries. A stop
	// before Rename can leave an incomplete JSON fragment at this pathname.
	if err := os.WriteFile(filepath.Join(journalDir, ".journal-interrupted.json"), []byte(`{"schema":`), 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(stateDir)
	if incomplete, err := store.IncompleteTransactions(); err != nil || len(incomplete) != 0 {
		t.Fatalf("temporary journal blocked inspection: incomplete=%v err=%v", incomplete, err)
	}
	if recovered, err := store.Recover(t.Context()); err != nil || len(recovered) != 0 {
		t.Fatalf("temporary journal blocked recovery: recovered=%v err=%v", recovered, err)
	}
}

func TestCallerBoundTransactionIDRecoversExactCompletedCommit(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	path := "provenance/evidence/sha256/" + strings.Repeat("a", 64)
	stage := transactionTestStage(t, stateDir, "evidence", "verified evidence")
	id, err := NewTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	commit, changed, err := store.Apply(t.Context(), "sync", "bound provenance input", map[string]string{path: stage}, nil, ApplyOptions{TransactionID: id})
	if err != nil || !changed || commit.IsZero() {
		t.Fatalf("bound apply commit=%s changed=%v err=%v", commit, changed, err)
	}
	record, exists, err := store.Transaction(id)
	if err != nil || !exists || record.Phase != "complete" || record.Operation != "sync" || record.Message != "bound provenance input" || record.Commit != commit {
		t.Fatalf("transaction record=%+v exists=%v err=%v", record, exists, err)
	}
	if _, _, err := store.Apply(t.Context(), "sync", "reuse", map[string]string{path: stage}, nil, ApplyOptions{TransactionID: id}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate caller-bound transaction ID was accepted: %v", err)
	}

	// An unchanged replay still writes a journal whose commit is the existing
	// HEAD; lookup must prove its desired files instead of requiring a child.
	noopID, err := NewTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	noop, changed, err := store.Apply(t.Context(), "sync", "bound no-op", map[string]string{path: stage}, nil, ApplyOptions{TransactionID: noopID})
	if err != nil || changed || noop != commit {
		t.Fatalf("no-op apply commit=%s changed=%v err=%v", noop, changed, err)
	}
	record, exists, err = store.Transaction(noopID)
	if err != nil || !exists || record.Commit != commit {
		t.Fatalf("no-op transaction record=%+v exists=%v err=%v", record, exists, err)
	}
}

func TestApplyExpectedFileIdentityRejectsStaleConfigWriter(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	firstStage := transactionTestStage(t, stateDir, "config-a.yaml", "config A\n")
	first, _, err := store.Apply(t.Context(), "init", "config A", map[string]string{"config/sow.yaml": firstStage}, nil, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	secondStage := transactionTestStage(t, stateDir, "config-b.yaml", "config B\n")
	second, _, err := store.Apply(t.Context(), "init", "config B", map[string]string{"config/sow.yaml": secondStage}, nil, ApplyOptions{})
	if err != nil || second == first {
		t.Fatalf("second config commit=%s first=%s err=%v", second, first, err)
	}
	firstSHA := sha256.Sum256([]byte("config A\n"))
	staleStage := transactionTestStage(t, stateDir, "stale-view.tsv", "stale view\n")
	_, _, err = store.Apply(t.Context(), "add", "stale writer", map[string]string{
		"views/beta/assets/all/all.tsv": staleStage,
	}, nil, ApplyOptions{ExpectedFiles: map[string]FileExpectation{
		"config/sow.yaml": {Identities: []FileIdentity{{Size: int64(len("config A\n")), SHA256: hex.EncodeToString(firstSHA[:])}}},
	}})
	if !errors.Is(err, ErrFileConflict) {
		t.Fatalf("stale config writer was accepted: %v", err)
	}
	reader, err := store.OpenPath("config/sow.yaml")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil || string(body) != "config B\n" {
		t.Fatalf("stale writer changed canonical config: body=%q err=%v close=%v", body, err, closeErr)
	}
}

func TestFileIdentityAtHeadIgnoresUncommittedWorktreeBytes(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	stage := transactionTestStage(t, stateDir, "config-a.yaml", "config A\n")
	if _, _, err := store.Apply(t.Context(), "init", "config A", map[string]string{"config/sow.yaml": stage}, nil, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	worktreeConfig := filepath.Join(stateDir, "state", "config", "sow.yaml")
	if err := os.WriteFile(worktreeConfig, []byte("config B before commit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	identity, exists, err := store.FileIdentityAtHead("config/sow.yaml")
	if err != nil || !exists {
		t.Fatalf("identity exists=%v err=%v", exists, err)
	}
	want := sha256.Sum256([]byte("config A\n"))
	if identity.Size != int64(len("config A\n")) || identity.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("identity came from mutable worktree: %+v", identity)
	}
}

func TestFileIdentityAtHeadDoesNotInitializeMissingRepository(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	identity, exists, err := New(stateDir).FileIdentityAtHead("config/sow.yaml")
	if err != nil || exists || identity != (FileIdentity{}) {
		t.Fatalf("identity=%+v exists=%v err=%v", identity, exists, err)
	}
	if _, err := os.Lstat(filepath.Join(stateDir, "state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only baseline capture initialized canonical state: %v", err)
	}
}

func transactionTestStage(t *testing.T, stateDir, name, contents string) string {
	t.Helper()
	base := filepath.Join(stateDir, "transactions")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(base, "state-test-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func installTransactionTestCommit(t *testing.T, store *Store, canonical, contents string) plumbing.Hash {
	t.Helper()
	stage := filepath.Join(t.TempDir(), "canonical-stage")
	if err := os.WriteFile(stage, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	commit, changed, err := store.InstallPaths(map[string]string{canonical: stage}, "transaction test fixture")
	if err != nil || !changed || commit.IsZero() {
		t.Fatalf("install commit=%s changed=%v err=%v", commit, changed, err)
	}
	return commit
}

func assertTransactionTestRef(t *testing.T, store *Store, ref plumbing.ReferenceName, want plumbing.Hash) {
	t.Helper()
	got, exists, err := store.Ref(ref)
	if err != nil || !exists || got != want {
		t.Fatalf("ref %s=%s exists=%v, want %s, err=%v", ref, got, exists, want, err)
	}
}
