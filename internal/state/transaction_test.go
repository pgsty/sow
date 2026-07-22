package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	indexformat "github.com/go-git/go-git/v5/plumbing/format/index"
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

func TestApplyExpectedStagesRejectsMutationAfterIntent(t *testing.T) {
	const canonicalPath = "views/beta/assets/all/all.tsv"
	for _, test := range []struct {
		name    string
		mutate  func(string) error
		staged  string
		present string
	}{
		{
			name:    "same bytes replacement inode",
			staged:  "approved\n",
			present: "approved\n",
			mutate: func(path string) error {
				if err := os.Rename(path, path+".approved"); err != nil {
					return err
				}
				return os.WriteFile(path, []byte("approved\n"), 0o600)
			},
		},
		{
			name:    "different bytes replacement inode",
			staged:  "approved\n",
			present: "unapproved\n",
			mutate: func(path string) error {
				if err := os.Rename(path, path+".approved"); err != nil {
					return err
				}
				return os.WriteFile(path, []byte("unapproved\n"), 0o600)
			},
		},
		{
			name:    "approved inode changed in place",
			staged:  "approved\n",
			present: "unapproved and larger\n",
			mutate: func(path string) error {
				return os.WriteFile(path, []byte("unapproved and larger\n"), 0o600)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), ".sow")
			store := New(stateDir)
			baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
			stage := transactionTestStage(t, stateDir, "approved.tsv", test.staged)
			digest := sha256.Sum256([]byte(test.staged))
			transactionID, err := NewTransactionID()
			if err != nil {
				t.Fatal(err)
			}

			_, _, err = store.Apply(t.Context(), "add", "bind approved stage", map[string]string{
				canonicalPath: stage,
			}, nil, ApplyOptions{
				TransactionID: transactionID,
				ExpectedStages: map[string]FileIdentity{
					canonicalPath: {
						Size:   int64(len(test.staged)),
						SHA256: hex.EncodeToString(digest[:]),
					},
				},
				AfterIntent: func() error { return test.mutate(stage) },
			})
			if err == nil {
				t.Fatal("Apply accepted a staged file changed after durable intent")
			}
			if head, headErr := store.HeadHash(); headErr != nil || head != baseline {
				t.Fatalf("rejected Apply changed HEAD head=%s want=%s err=%v apply_err=%v", head, baseline, headErr, err)
			}
			record, exists, recordErr := store.Transaction(transactionID)
			if recordErr != nil || !exists || record.Phase != "aborted" || !record.Commit.IsZero() {
				t.Fatalf("record exists=%t record=%+v err=%v apply_err=%v", exists, record, recordErr, err)
			}
			body, readErr := os.ReadFile(stage)
			if readErr != nil || string(body) != test.present {
				t.Fatalf("replacement body=%q want=%q err=%v", body, test.present, readErr)
			}
		})
	}
}

func TestApplyExpectedStagesRequiresExactCanonicalVector(t *testing.T) {
	const canonicalPath = "views/beta/assets/all/all.tsv"
	for _, test := range []struct {
		name     string
		expected func(FileIdentity) map[string]FileIdentity
	}{
		{
			name: "missing canonical identity",
			expected: func(FileIdentity) map[string]FileIdentity {
				return map[string]FileIdentity{}
			},
		},
		{
			name: "extra canonical identity",
			expected: func(identity FileIdentity) map[string]FileIdentity {
				return map[string]FileIdentity{canonicalPath: identity, "config/sow.yaml": identity}
			},
		},
		{
			name: "wrong byte identity",
			expected: func(identity FileIdentity) map[string]FileIdentity {
				identity.Size++
				return map[string]FileIdentity{canonicalPath: identity}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), ".sow")
			store := New(stateDir)
			baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
			const body = "approved\n"
			stage := transactionTestStage(t, stateDir, "approved.tsv", body)
			digest := sha256.Sum256([]byte(body))
			identity := FileIdentity{Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])}
			_, _, err := store.Apply(t.Context(), "add", "reject partial stage vector", map[string]string{canonicalPath: stage}, nil, ApplyOptions{
				ExpectedStages: test.expected(identity),
			})
			if err == nil {
				t.Fatal("Apply accepted a partial or mismatched expected stage vector")
			}
			if head, headErr := store.HeadHash(); headErr != nil || head != baseline {
				t.Fatalf("rejected stage vector changed HEAD head=%s want=%s err=%v", head, baseline, headErr)
			}
			journals, journalErr := store.readJournals()
			if journalErr != nil || len(journals) != 0 {
				t.Fatalf("rejected stage vector wrote journals=%+v err=%v", journals, journalErr)
			}
		})
	}
}

func TestRecoverRetainsJournalStageDescriptorThroughInstall(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	journal, err := store.buildJournal("add", "recover bound stage", baseline, map[string]string{canonicalPath: stage}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeJournal(journal); err != nil {
		t.Fatal(err)
	}
	original := stage + ".approved"
	store.beforeBoundStageInstall = func() error {
		store.beforeBoundStageInstall = nil
		if err := os.Rename(stage, original); err != nil {
			return err
		}
		return os.WriteFile(stage, []byte("approved\n"), 0o600)
	}
	if _, err := store.Recover(t.Context()); err == nil {
		t.Fatal("recovery accepted a same-byte staged-path replacement after binding")
	}
	if head, err := store.HeadHash(); err != nil || head != baseline {
		t.Fatalf("rejected recovery changed HEAD head=%s want=%s err=%v", head, baseline, err)
	}
	record, exists, err := store.Transaction(journal.ID)
	if err != nil || !exists || record.Phase != "intent" || !record.Commit.IsZero() {
		t.Fatalf("rejected recovery record exists=%t record=%+v err=%v", exists, record, err)
	}
	body, err := os.ReadFile(stage)
	if err != nil || string(body) != "approved\n" {
		t.Fatalf("recovery did not preserve replacement body=%q err=%v", body, err)
	}
	if err := os.Remove(stage); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, stage); err != nil {
		t.Fatal(err)
	}
	results, err := store.Recover(t.Context())
	if err != nil || len(results) != 1 || !results[0].Recovered || results[0].Commit.IsZero() {
		t.Fatalf("repaired exact stage did not recover results=%+v err=%v", results, err)
	}
	reader, err := store.OpenPath(canonicalPath)
	if err != nil {
		t.Fatal(err)
	}
	committed, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || string(committed) != "approved\n" {
		t.Fatalf("recovered canonical body=%q read_err=%v close_err=%v", committed, readErr, closeErr)
	}
}

func TestRecoverAbortedRetainsOneStageBindingAndRestoresRetryBoundary(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	digest := sha256.Sum256([]byte("approved\n"))
	transactionID, err := NewTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	store.beforeBoundStageInstall = func() error {
		store.beforeBoundStageInstall = nil
		return errors.New("injected initial install failure")
	}
	_, _, err = store.Apply(t.Context(), "add", "retry one retained binding", map[string]string{canonicalPath: stage}, nil, ApplyOptions{
		TransactionID: transactionID,
		ExpectedStages: map[string]FileIdentity{
			canonicalPath: {Size: int64(len("approved\n")), SHA256: hex.EncodeToString(digest[:])},
		},
	})
	if err == nil {
		t.Fatal("initial Apply did not create an aborted retry boundary")
	}
	record, exists, err := store.Transaction(transactionID)
	if err != nil || !exists || record.Phase != "aborted" {
		t.Fatalf("initial aborted record exists=%t record=%+v err=%v", exists, record, err)
	}
	original := stage + ".approved"
	store.beforeBoundStageInstall = func() error {
		store.beforeBoundStageInstall = nil
		if err := os.Rename(stage, original); err != nil {
			return err
		}
		return os.WriteFile(stage, []byte("approved\n"), 0o600)
	}
	if _, err := store.RecoverAborted(t.Context(), record); !errors.Is(err, ErrFileConflict) {
		t.Fatalf("aborted retry replacement err=%v want ErrFileConflict", err)
	}
	restored, exists, err := store.Transaction(transactionID)
	if err != nil || !exists || restored.Phase != "aborted" || !restored.Commit.IsZero() {
		t.Fatalf("failed retry did not restore aborted boundary exists=%t record=%+v err=%v", exists, restored, err)
	}
	if head, err := store.HeadHash(); err != nil || head != baseline {
		t.Fatalf("failed aborted retry changed HEAD head=%s want=%s err=%v", head, baseline, err)
	}
	if err := os.Remove(stage); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, stage); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.RecoverAborted(t.Context(), record)
	if err != nil || !recovered.Recovered || recovered.Commit.IsZero() {
		t.Fatalf("repaired aborted retry result=%+v err=%v", recovered, err)
	}
}

func TestApplyRejectsFIFOReplacementAfterIntentWithoutBlocking(t *testing.T) {
	if os.Getenv("SOW_TEST_APPLY_FIFO_STAGE") == "1" {
		stateDir := filepath.Join(t.TempDir(), ".sow")
		store := New(stateDir)
		const canonicalPath = "views/beta/assets/all/all.tsv"
		baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
		stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
		digest := sha256.Sum256([]byte("approved\n"))
		transactionID, err := NewTransactionID()
		if err != nil {
			t.Fatal(err)
		}
		ref, err := ViewRef("beta", "assets", "all", "all")
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = store.Apply(t.Context(), "add", "reject FIFO stage replacement", map[string]string{canonicalPath: stage}, []RefUpdate{{Name: ref}}, ApplyOptions{
			TransactionID:  transactionID,
			ExpectedStages: map[string]FileIdentity{canonicalPath: {Size: int64(len("approved\n")), SHA256: hex.EncodeToString(digest[:])}},
			AfterIntent: func() error {
				if err := os.Rename(stage, stage+".approved"); err != nil {
					return err
				}
				return syscall.Mkfifo(stage, 0o600)
			},
		})
		if !errors.Is(err, ErrFileConflict) {
			t.Fatalf("Apply FIFO replacement err=%v want ErrFileConflict", err)
		}
		if head, headErr := store.HeadHash(); headErr != nil || head != baseline {
			t.Fatalf("FIFO rejection changed HEAD head=%s want=%s err=%v", head, baseline, headErr)
		}
		if _, exists, refErr := store.Ref(ref); refErr != nil || exists {
			t.Fatalf("FIFO rejection advanced ref exists=%t err=%v", exists, refErr)
		}
		record, exists, recordErr := store.Transaction(transactionID)
		if recordErr != nil || !exists || record.Phase != "aborted" || !record.Commit.IsZero() {
			t.Fatalf("FIFO rejection record exists=%t record=%+v err=%v", exists, record, recordErr)
		}
		if info, statErr := os.Lstat(stage); statErr != nil || info.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("FIFO replacement was not preserved info=%v err=%v", info, statErr)
		}
		return
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestApplyRejectsFIFOReplacementAfterIntentWithoutBlocking$")
	command.Env = append(os.Environ(), "SOW_TEST_APPLY_FIFO_STAGE=1")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("Apply blocked while rejecting FIFO stage replacement: %v output=%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("FIFO stage rejection helper failed: %v output=%s", err, output)
	}
}

func TestApplyBoundedCopyRejectsInPlaceStageMutation(t *testing.T) {
	const canonicalPath = "views/beta/assets/all/all.tsv"
	for _, replacement := range []string{"x\n", "unapproved and larger\n", "altered!\n"} {
		name := "same-size"
		switch {
		case len(replacement) < len("approved\n"):
			name = "truncate"
		case len(replacement) > len("approved\n"):
			name = "grow"
		}
		t.Run(name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), ".sow")
			store := New(stateDir)
			baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
			stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
			stageInfo, err := os.Stat(stage)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte("approved\n"))
			store.beforeBoundStageCopy = func() error {
				store.beforeBoundStageCopy = nil
				if err := os.WriteFile(stage, []byte(replacement), 0o600); err != nil {
					return err
				}
				return os.Chtimes(stage, stageInfo.ModTime(), stageInfo.ModTime())
			}
			transactionID, err := NewTransactionID()
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = store.Apply(t.Context(), "add", "reject in-place stage mutation", map[string]string{canonicalPath: stage}, nil, ApplyOptions{
				TransactionID: transactionID,
				ExpectedStages: map[string]FileIdentity{
					canonicalPath: {Size: int64(len("approved\n")), SHA256: hex.EncodeToString(digest[:])},
				},
			})
			if !errors.Is(err, ErrFileConflict) {
				t.Fatalf("in-place mutation err=%v want ErrFileConflict", err)
			}
			if head, headErr := store.HeadHash(); headErr != nil || head != baseline {
				t.Fatalf("bounded-copy rejection changed HEAD head=%s want=%s err=%v", head, baseline, headErr)
			}
			record, exists, recordErr := store.Transaction(transactionID)
			if recordErr != nil || !exists || record.Phase != "aborted" || !record.Commit.IsZero() {
				t.Fatalf("bounded-copy record exists=%t record=%+v err=%v apply_err=%v", exists, record, recordErr, err)
			}
			body, readErr := os.ReadFile(stage)
			if readErr != nil || string(body) != replacement {
				t.Fatalf("bounded-copy mutation body=%q want=%q err=%v", body, replacement, readErr)
			}
		})
	}
}

func TestApplyRevalidatesWholeStageVectorBeforeCommit(t *testing.T) {
	const (
		firstPath  = "views/beta/assets/all/a.tsv"
		secondPath = "views/beta/assets/all/b.tsv"
		firstBody  = "approved first\n"
		secondBody = "approved second\n"
	)
	for _, test := range []struct {
		name   string
		mutate func(string, string, string) error
	}{
		{
			name: "earlier source path replaced during later copy",
			mutate: func(stateDir, firstStage, _ string) error {
				if err := os.Rename(firstStage, firstStage+".approved"); err != nil {
					return err
				}
				return os.WriteFile(firstStage, []byte(firstBody), 0o600)
			},
		},
		{
			name: "earlier canonical destination overwritten during later copy",
			mutate: func(stateDir, _, firstCanonical string) error {
				return os.WriteFile(firstCanonical, []byte("unapproved canonical bytes\n"), 0o644)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), ".sow")
			store := New(stateDir)
			_ = installTransactionTestCommit(t, store, firstPath, "baseline first\n")
			baseline := installTransactionTestCommit(t, store, secondPath, "baseline second\n")
			firstStage := transactionTestStage(t, stateDir, "first.tsv", firstBody)
			secondStage := transactionTestStage(t, stateDir, "second.tsv", secondBody)
			firstDigest := sha256.Sum256([]byte(firstBody))
			secondDigest := sha256.Sum256([]byte(secondBody))
			transactionID, err := NewTransactionID()
			if err != nil {
				t.Fatal(err)
			}
			copyCalls := 0
			store.beforeBoundStageCopy = func() error {
				copyCalls++
				if copyCalls != 2 {
					return nil
				}
				store.beforeBoundStageCopy = nil
				return test.mutate(stateDir, firstStage, filepath.Join(stateDir, "state", filepath.FromSlash(firstPath)))
			}
			_, _, err = store.Apply(t.Context(), "add", "revalidate full stage vector", map[string]string{
				firstPath: firstStage, secondPath: secondStage,
			}, nil, ApplyOptions{
				TransactionID: transactionID,
				ExpectedStages: map[string]FileIdentity{
					firstPath:  {Size: int64(len(firstBody)), SHA256: hex.EncodeToString(firstDigest[:])},
					secondPath: {Size: int64(len(secondBody)), SHA256: hex.EncodeToString(secondDigest[:])},
				},
			})
			if !errors.Is(err, ErrFileConflict) {
				t.Fatalf("multi-stage mutation err=%v want ErrFileConflict", err)
			}
			if copyCalls != 2 {
				t.Fatalf("multi-stage mutation copy calls=%d want=2", copyCalls)
			}
			if head, headErr := store.HeadHash(); headErr != nil || head != baseline {
				t.Fatalf("multi-stage rejection changed HEAD head=%s want=%s err=%v", head, baseline, headErr)
			}
			record, exists, recordErr := store.Transaction(transactionID)
			if recordErr != nil || !exists || record.Phase != "aborted" || !record.Commit.IsZero() {
				t.Fatalf("multi-stage record exists=%t record=%+v err=%v apply_err=%v", exists, record, recordErr, err)
			}
			for canonical, want := range map[string]string{firstPath: "baseline first\n", secondPath: "baseline second\n"} {
				body, readErr := os.ReadFile(filepath.Join(stateDir, "state", filepath.FromSlash(canonical)))
				if readErr != nil || string(body) != want {
					t.Fatalf("rolled back canonical %s body=%q want=%q err=%v", canonical, body, want, readErr)
				}
			}
		})
	}
}

func TestApplyRejectsStageHardLinkedToCanonicalDestination(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	const body = "approved\n"
	baseline := installTransactionTestCommit(t, store, canonicalPath, body)
	stageDirectory := filepath.Join(stateDir, "transactions", "hardlink")
	if err := os.MkdirAll(stageDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(stageDirectory, "approved.tsv")
	if err := os.Link(filepath.Join(stateDir, "state", filepath.FromSlash(canonicalPath)), stage); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(body))
	transactionID, err := NewTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = store.Apply(t.Context(), "add", "reject canonical hardlink source", map[string]string{canonicalPath: stage}, nil, ApplyOptions{
		TransactionID: transactionID,
		ExpectedStages: map[string]FileIdentity{
			canonicalPath: {Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])},
		},
	})
	if !errors.Is(err, ErrFileConflict) || !strings.Contains(err.Error(), "hard-linked") {
		t.Fatalf("canonical hardlink stage err=%v", err)
	}
	if head, headErr := store.HeadHash(); headErr != nil || head != baseline {
		t.Fatalf("hardlink rejection changed HEAD head=%s want=%s err=%v", head, baseline, headErr)
	}
	if stageInfo, stageErr := os.Stat(stage); stageErr != nil || !stageInfo.Mode().IsRegular() {
		t.Fatalf("hardlink stage was not preserved info=%v err=%v", stageInfo, stageErr)
	}
}

func TestApplyRejectsHeadMoveBeforeCanonicalMutation(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	prior := installTransactionTestCommit(t, store, canonicalPath, "prior\n")
	baseline := installTransactionTestCommit(t, store, "config/sow.yaml", "baseline config\n")
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	store.beforeBoundStageInstall = func() error {
		store.beforeBoundStageInstall = nil
		repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
		if err != nil {
			return err
		}
		head, err := repository.Head()
		if err != nil {
			return err
		}
		return repository.Storer.SetReference(plumbing.NewHashReference(head.Name(), prior))
	}
	_, _, err := store.Apply(t.Context(), "add", "reject moved HEAD", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
	if !errors.Is(err, ErrRefConflict) {
		t.Fatalf("moved HEAD err=%v want ErrRefConflict", err)
	}
	if head, headErr := store.HeadHash(); headErr != nil || head != prior || head == baseline {
		t.Fatalf("Apply overwrote external HEAD move head=%s prior=%s baseline=%s err=%v", head, prior, baseline, headErr)
	}
}

func TestApplyRejectsRawHeadBranchSwitchAtSameCommit(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	const alternate = plumbing.ReferenceName("refs/heads/external-same-hash")
	store.beforeBoundStageInstall = func() error {
		store.beforeBoundStageInstall = nil
		repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
		if err != nil {
			return err
		}
		if err := repository.Storer.SetReference(plumbing.NewHashReference(alternate, baseline)); err != nil {
			return err
		}
		return repository.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, alternate))
	}
	_, _, err := store.Apply(t.Context(), "add", "reject raw HEAD branch switch", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
	if !errors.Is(err, ErrRefConflict) {
		t.Fatalf("same-hash raw HEAD switch err=%v want ErrRefConflict", err)
	}
	repository, openErr := git.PlainOpen(filepath.Join(stateDir, "state"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	raw, rawErr := repository.Storer.Reference(plumbing.HEAD)
	if rawErr != nil || raw.Type() != plumbing.SymbolicReference || raw.Target() != alternate {
		t.Fatalf("Apply overwrote raw HEAD switch raw=%v err=%v", raw, rawErr)
	}
}

func TestApplyRejectsRawHeadBranchSwitchAfterIntent(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	const alternate = plumbing.ReferenceName("refs/heads/external-after-intent")
	transactionID, err := NewTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = store.Apply(t.Context(), "add", "reject raw HEAD switch after intent", map[string]string{canonicalPath: stage}, nil, ApplyOptions{
		TransactionID: transactionID,
		AfterIntent: func() error {
			repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
			if err != nil {
				return err
			}
			if err := repository.Storer.SetReference(plumbing.NewHashReference(alternate, baseline)); err != nil {
				return err
			}
			return repository.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, alternate))
		},
	})
	if !errors.Is(err, ErrRefConflict) {
		t.Fatalf("after-intent same-hash raw HEAD switch err=%v want ErrRefConflict", err)
	}
	repository, openErr := git.PlainOpen(filepath.Join(stateDir, "state"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	raw, rawErr := repository.Storer.Reference(plumbing.HEAD)
	if rawErr != nil || raw.Type() != plumbing.SymbolicReference || raw.Target() != alternate {
		t.Fatalf("rejected Apply overwrote after-intent raw HEAD raw=%v err=%v", raw, rawErr)
	}
	record, exists, recordErr := store.Transaction(transactionID)
	if recordErr != nil || !exists || record.Phase != "aborted" || !record.Commit.IsZero() {
		t.Fatalf("after-intent conflict record exists=%t record=%+v err=%v", exists, record, recordErr)
	}
}

func TestRecoverRejectsRawHeadBranchSwitchAtSameExpectedCommit(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	stage := transactionTestStage(t, stateDir, "approved-recovery.tsv", "approved\n")
	const alternate = plumbing.ReferenceName("refs/heads/external-recovery-same-hash")
	injected := errors.New("stop after durable intent")
	transactionID, err := NewTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = store.Apply(t.Context(), "add", "reject recovery raw HEAD switch", map[string]string{canonicalPath: stage}, nil, ApplyOptions{
		TransactionID: transactionID,
		AfterIntent: func() error {
			repository, openErr := git.PlainOpen(filepath.Join(stateDir, "state"))
			if openErr != nil {
				return openErr
			}
			if refErr := repository.Storer.SetReference(plumbing.NewHashReference(alternate, baseline)); refErr != nil {
				return refErr
			}
			if refErr := repository.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, alternate)); refErr != nil {
				return refErr
			}
			return injected
		},
	})
	if !errors.Is(err, injected) {
		t.Fatalf("Apply stop err=%v want injected", err)
	}
	if _, err := store.Recover(t.Context()); !errors.Is(err, ErrRefConflict) {
		t.Fatalf("same-hash raw HEAD recovery err=%v want ErrRefConflict", err)
	}
	repository, openErr := git.PlainOpen(filepath.Join(stateDir, "state"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	raw, rawErr := repository.Storer.Reference(plumbing.HEAD)
	if rawErr != nil || raw.Type() != plumbing.SymbolicReference || raw.Target() != alternate {
		t.Fatalf("recovery overwrote external raw HEAD raw=%v err=%v", raw, rawErr)
	}
	if got, readErr := os.ReadFile(filepath.Join(stateDir, "state", filepath.FromSlash(canonicalPath))); readErr != nil || string(got) != "baseline\n" {
		t.Fatalf("rejected recovery changed canonical bytes=%q err=%v", got, readErr)
	}
	record, exists, recordErr := store.Transaction(transactionID)
	if recordErr != nil || !exists || record.Phase != "intent" || record.ExpectedHeadRaw == "" {
		t.Fatalf("rejected recovery record exists=%t record=%+v err=%v", exists, record, recordErr)
	}
}

func TestApplySupportsDetachedHeadWithExactCAS(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Storer.SetReference(plumbing.NewHashReference(plumbing.HEAD, baseline)); err != nil {
		t.Fatal(err)
	}
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	commit, changed, err := store.Apply(t.Context(), "add", "detached exact CAS", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
	if err != nil || !changed || commit.IsZero() || commit == baseline {
		t.Fatalf("detached Apply commit=%s changed=%t err=%v", commit, changed, err)
	}
	raw, err := repository.Storer.Reference(plumbing.HEAD)
	if err != nil || raw.Type() != plumbing.HashReference || raw.Hash() != commit {
		t.Fatalf("detached Apply raw HEAD=%v commit=%s err=%v", raw, commit, err)
	}
	created, err := repository.CommitObject(commit)
	if err != nil {
		t.Fatal(err)
	}
	if len(created.ParentHashes) != 1 || created.ParentHashes[0] != baseline {
		t.Fatalf("detached commit parents=%v baseline=%s", created.ParentHashes, baseline)
	}
}

func TestRecoverReplaysFrozenDetachedHeadCoordinate(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Storer.SetReference(plumbing.NewHashReference(plumbing.HEAD, baseline)); err != nil {
		t.Fatal(err)
	}
	stage := transactionTestStage(t, stateDir, "detached-recovery.tsv", "approved\n")
	injected := errors.New("stop detached transaction after intent")
	_, _, err = store.Apply(t.Context(), "add", "recover detached exact CAS", map[string]string{canonicalPath: stage}, nil, ApplyOptions{
		AfterIntent: func() error { return injected },
	})
	if !errors.Is(err, injected) {
		t.Fatalf("detached Apply stop err=%v want injected", err)
	}
	results, err := store.Recover(t.Context())
	if err != nil || len(results) != 1 || results[0].Commit.IsZero() || results[0].Commit == baseline {
		t.Fatalf("detached recovery results=%#v err=%v", results, err)
	}
	raw, err := repository.Storer.Reference(plumbing.HEAD)
	if err != nil || raw.Type() != plumbing.HashReference || raw.Hash() != results[0].Commit {
		t.Fatalf("detached recovery raw HEAD=%v commit=%s err=%v", raw, results[0].Commit, err)
	}
}

func TestApplySupportsPackedOnlyHeadTarget(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	head, err := snapshotRepositoryHead(repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Storer.PackRefs(); err != nil {
		t.Fatal(err)
	}
	loose, err := canonicalLooseReferencePath(filepath.Join(stateDir, "state"), head.name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(loose); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("PackRefs retained loose HEAD target %s: %v", loose, err)
	}
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	commit, changed, err := store.Apply(t.Context(), "add", "packed HEAD exact CAS", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
	if err != nil || !changed || commit.IsZero() || commit == baseline {
		t.Fatalf("packed HEAD Apply commit=%s changed=%t baseline=%s err=%v", commit, changed, baseline, err)
	}
	updated, err := repository.Storer.Reference(head.name)
	if err != nil || updated.Hash() != commit {
		t.Fatalf("packed HEAD target ref=%v commit=%s err=%v", updated, commit, err)
	}
}

func TestApplyUnbornHeadCreateIsExclusive(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	external := plumbing.NewHash(strings.Repeat("a", 40))
	store.beforeUnbornHeadCreate = func() error {
		store.beforeUnbornHeadCreate = nil
		repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
		if err != nil {
			return err
		}
		raw, err := repository.Storer.Reference(plumbing.HEAD)
		if err != nil {
			return err
		}
		return repository.Storer.SetReference(plumbing.NewHashReference(raw.Target(), external))
	}
	_, _, err := store.Apply(t.Context(), "add", "exclusive unborn HEAD", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
	if !errors.Is(err, ErrRefConflict) {
		t.Fatalf("unborn ref race err=%v want ErrRefConflict", err)
	}
	repository, openErr := git.PlainOpen(filepath.Join(stateDir, "state"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	head, headErr := repository.Head()
	if headErr != nil || head.Hash() != external {
		t.Fatalf("exclusive create overwrote external root head=%v external=%s err=%v", head, external, headErr)
	}
	if _, statErr := os.Lstat(filepath.Join(stateDir, "state", filepath.FromSlash(canonicalPath))); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unborn race retained canonical mutation err=%v", statErr)
	}
}

func TestApplyReferencePublishFsyncFailureCompensates(t *testing.T) {
	for _, test := range []struct {
		name     string
		baseline bool
	}{
		{name: "existing HEAD", baseline: true},
		{name: "unborn HEAD", baseline: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), ".sow")
			store := New(stateDir)
			const canonicalPath = "views/beta/assets/all/all.tsv"
			baseline := plumbing.ZeroHash
			if test.baseline {
				baseline = installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
			}
			stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
			injected := errors.New("injected reference parent fsync failure")
			store.syncReferenceDirectory = func(string) error {
				store.syncReferenceDirectory = nil
				return injected
			}
			_, _, err := store.Apply(t.Context(), "add", "compensate ref fsync failure", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
			if !errors.Is(err, injected) {
				t.Fatalf("reference fsync failure err=%v want injected", err)
			}
			head, headErr := store.HeadHash()
			if headErr != nil || head != baseline {
				t.Fatalf("reference fsync compensation head=%s want=%s err=%v", head, baseline, headErr)
			}
			canonical := filepath.Join(stateDir, "state", filepath.FromSlash(canonicalPath))
			body, readErr := os.ReadFile(canonical)
			if test.baseline {
				if readErr != nil || string(body) != "baseline\n" {
					t.Fatalf("existing ref compensation body=%q err=%v", body, readErr)
				}
			} else if !errors.Is(readErr, os.ErrNotExist) {
				t.Fatalf("unborn ref compensation retained canonical body=%q err=%v", body, readErr)
			}
		})
	}
}

func TestApplyLateReferenceReleaseFailurePersistsCommittedRecoveryBoundary(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	stage := transactionTestStage(t, stateDir, "late-release.tsv", "approved\n")
	transactionID, err := NewTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected held reference release failure")
	store.beforeReferenceRelease = func() error {
		store.beforeReferenceRelease = nil
		return injected
	}
	commit, changed, err := store.Apply(t.Context(), "add", "late reference release", map[string]string{canonicalPath: stage}, nil, ApplyOptions{TransactionID: transactionID})
	if !errors.Is(err, injected) || !changed || commit.IsZero() || commit == baseline {
		t.Fatalf("late release commit=%s changed=%t baseline=%s err=%v", commit, changed, baseline, err)
	}
	record, exists, recordErr := store.Transaction(transactionID)
	if recordErr != nil || !exists || record.Phase != "committed" || record.Commit != commit {
		t.Fatalf("late release boundary exists=%t record=%+v err=%v", exists, record, recordErr)
	}
	results, recoverErr := store.Recover(t.Context())
	if recoverErr != nil || len(results) != 1 || results[0].Commit != commit {
		t.Fatalf("late release recovery results=%#v err=%v", results, recoverErr)
	}
	completed, exists, recordErr := store.Transaction(transactionID)
	if recordErr != nil || !exists || completed.Phase != "complete" || completed.Commit != commit {
		t.Fatalf("late release completion exists=%t record=%+v err=%v", exists, completed, recordErr)
	}
}

func TestApplyRecoversOnlyProvenStaleSOWReferenceLock(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	head, err := snapshotRepositoryHead(repository)
	if err != nil {
		t.Fatal(err)
	}
	referencePath, err := canonicalLooseReferencePath(filepath.Join(stateDir, "state"), head.name)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := readProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	marker := referenceLockMarker{
		pid: 1 << 30, identity: identity,
		tempName: ".sow-ref-stale-fixture", markerName: ".sow-lock-stale-fixture",
	}
	lockPath := referencePath + ".lock"
	markerStage := filepath.Join(filepath.Dir(referencePath), marker.markerName)
	if err := os.WriteFile(markerStage, []byte(marker.encode()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(markerStage, lockPath); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(filepath.Dir(referencePath), marker.tempName)
	if err := os.WriteFile(temporary, []byte("stale temporary\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	commit, changed, err := store.Apply(t.Context(), "add", "recover stale SOW ref lock", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
	if err != nil || !changed || commit.IsZero() {
		t.Fatalf("stale SOW lock recovery commit=%s changed=%t err=%v", commit, changed, err)
	}
	for _, filename := range []string{lockPath, temporary, markerStage} {
		if _, err := os.Lstat(filename); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale SOW ref debris survived at %s: %v", filename, err)
		}
	}
}

func TestApplyDoesNotRemoveForeignReferenceLock(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	head, err := snapshotRepositoryHead(repository)
	if err != nil {
		t.Fatal(err)
	}
	referencePath, err := canonicalLooseReferencePath(filepath.Join(stateDir, "state"), head.name)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := referencePath + ".lock"
	foreign := []byte(strings.Repeat("b", 40) + "\n")
	if err := os.WriteFile(lockPath, foreign, 0o644); err != nil {
		t.Fatal(err)
	}
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	_, _, err = store.Apply(t.Context(), "add", "preserve foreign ref lock", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
	if !errors.Is(err, ErrRefConflict) {
		t.Fatalf("foreign reference lock err=%v want ErrRefConflict", err)
	}
	body, readErr := os.ReadFile(lockPath)
	if readErr != nil || string(body) != string(foreign) {
		t.Fatalf("foreign reference lock changed body=%q err=%v", body, readErr)
	}
}

func TestApplyRetainsCompleteNativeReferenceLockThroughPostCommitValidation(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	head, err := snapshotRepositoryHead(repository)
	if err != nil {
		t.Fatal(err)
	}
	referencePath, err := canonicalLooseReferencePath(filepath.Join(stateDir, "state"), head.name)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := referencePath + ".lock"
	rawLockPath := filepath.Join(stateDir, "state", ".git", "HEAD.lock")
	observed := false
	store.afterBoundCommit = func(plumbing.Hash) error {
		for _, candidate := range []string{lockPath, rawLockPath} {
			file, createErr := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if createErr == nil {
				_ = file.Close()
				_ = os.Remove(candidate)
				return fmt.Errorf("native Git lock %s was released before post-commit validation", candidate)
			}
			if !errors.Is(createErr, os.ErrExist) {
				return createErr
			}
			body, readErr := os.ReadFile(candidate)
			if readErr != nil {
				return readErr
			}
			if _, parseErr := parseReferenceLockMarker(string(body)); parseErr != nil {
				return fmt.Errorf("published native Git lock marker %s is incomplete: %w", candidate, parseErr)
			}
		}
		for _, directory := range []string{filepath.Dir(referencePath), filepath.Join(stateDir, "state", ".git")} {
			markerDebris, globErr := filepath.Glob(filepath.Join(directory, ".sow-lock-*"))
			if globErr != nil || len(markerDebris) != 0 {
				return errors.Join(globErr, fmt.Errorf("hidden lock marker debris remained after atomic publication: %v", markerDebris))
			}
		}
		observed = true
		return nil
	}
	stage := transactionTestStage(t, stateDir, "native-lock-held.tsv", "approved\n")
	commit, changed, err := store.Apply(t.Context(), "add", "retain native lock", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
	if err != nil || !changed || commit.IsZero() || !observed {
		t.Fatalf("held native lock commit=%s changed=%t observed=%t err=%v", commit, changed, observed, err)
	}
	for _, candidate := range []string{lockPath, rawLockPath} {
		if _, err := os.Lstat(candidate); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("native Git lock %s survived completed transaction: %v", candidate, err)
		}
	}
}

func TestApplyRollbackFailureStillReleasesNativeReferenceLocks(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	head, err := snapshotRepositoryHead(repository)
	if err != nil {
		t.Fatal(err)
	}
	referencePath, err := canonicalLooseReferencePath(filepath.Join(stateDir, "state"), head.name)
	if err != nil {
		t.Fatal(err)
	}
	locks := []string{referencePath + ".lock", filepath.Join(stateDir, "state", ".git", "HEAD.lock")}
	destination := filepath.Join(stateDir, "state", filepath.FromSlash(canonicalPath))
	injected := errors.New("inject post-commit rollback")
	store.afterBoundCommit = func(plumbing.Hash) error {
		if err := os.Remove(destination); err != nil {
			return err
		}
		if err := os.Mkdir(destination, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(destination, "foreign"), []byte("preserve\n"), 0o644); err != nil {
			return err
		}
		return injected
	}
	stage := transactionTestStage(t, stateDir, "rollback-lock-release.tsv", "approved\n")
	_, _, err = store.Apply(t.Context(), "add", "release locks after rollback failure", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
	if !errors.Is(err, injected) || !strings.Contains(err.Error(), "backup retained") {
		t.Fatalf("rollback failure err=%v want injected and retained backup", err)
	}
	if head, headErr := store.HeadHash(); headErr != nil || head != baseline {
		t.Fatalf("rollback failure HEAD=%s baseline=%s err=%v", head, baseline, headErr)
	}
	for _, lock := range locks {
		if _, statErr := os.Lstat(lock); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("native Git lock %s survived rollback failure: %v", lock, statErr)
		}
	}
}

func TestApplyRejectsNoncanonicalIndexFlags(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*git.Repository) error
	}{
		{name: "merge stage", mutate: func(repository *git.Repository) error {
			index, err := repository.Storer.Index()
			if err != nil {
				return err
			}
			index.Entries[0].Stage = 2
			return repository.Storer.SetIndex(index)
		}},
		{name: "skip worktree", mutate: func(repository *git.Repository) error {
			index, err := repository.Storer.Index()
			if err != nil {
				return err
			}
			index.Entries[0].SkipWorktree = true
			return repository.Storer.SetIndex(index)
		}},
		{name: "intent to add", mutate: func(repository *git.Repository) error {
			index, err := repository.Storer.Index()
			if err != nil {
				return err
			}
			index.Entries[0].IntentToAdd = true
			return repository.Storer.SetIndex(index)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), ".sow")
			store := New(stateDir)
			const canonicalPath = "views/beta/assets/all/all.tsv"
			baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
			stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
			store.beforeBoundStageInstall = func() error {
				store.beforeBoundStageInstall = nil
				repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
				if err != nil {
					return err
				}
				return test.mutate(repository)
			}
			_, _, err := store.Apply(t.Context(), "add", "reject noncanonical index flags", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
			if !errors.Is(err, ErrRefConflict) {
				t.Fatalf("noncanonical index err=%v want ErrRefConflict", err)
			}
			if head, headErr := store.HeadHash(); headErr != nil || head != baseline {
				t.Fatalf("index flag rejection changed HEAD head=%s want=%s err=%v", head, baseline, headErr)
			}
		})
	}
}

func TestApplyRejectsForeignIndexEntryBeforeCanonicalMutation(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	foreign := filepath.Join(stateDir, "state", "foreign.txt")
	store.beforeBoundStageInstall = func() error {
		store.beforeBoundStageInstall = nil
		if err := os.WriteFile(foreign, []byte("external index entry\n"), 0o644); err != nil {
			return err
		}
		repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
		if err != nil {
			return err
		}
		worktree, err := repository.Worktree()
		if err != nil {
			return err
		}
		_, err = worktree.Add("foreign.txt")
		return err
	}
	_, _, err := store.Apply(t.Context(), "add", "reject foreign index entry", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
	if !errors.Is(err, ErrRefConflict) {
		t.Fatalf("foreign index err=%v want ErrRefConflict", err)
	}
	if head, headErr := store.HeadHash(); headErr != nil || head != baseline {
		t.Fatalf("foreign index rejection changed HEAD head=%s want=%s err=%v", head, baseline, headErr)
	}
	body, readErr := os.ReadFile(foreign)
	if readErr != nil || string(body) != "external index entry\n" {
		t.Fatalf("foreign index writer was not preserved body=%q err=%v", body, readErr)
	}
}

func TestApplyRollsBackCommitWithFinalForeignIndexEntry(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	foreign := filepath.Join(stateDir, "state", "final-foreign.txt")
	transactionID, err := NewTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	store.afterBoundCommit = func(plumbing.Hash) error {
		store.afterBoundCommit = nil
		if err := os.WriteFile(foreign, []byte("final foreign index entry\n"), 0o644); err != nil {
			return err
		}
		repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
		if err != nil {
			return err
		}
		worktree, err := repository.Worktree()
		if err != nil {
			return err
		}
		_, err = worktree.Add("final-foreign.txt")
		return err
	}
	_, _, err = store.Apply(t.Context(), "add", "reject final foreign index", map[string]string{canonicalPath: stage}, nil, ApplyOptions{TransactionID: transactionID})
	if !errors.Is(err, ErrRefConflict) {
		t.Fatalf("final foreign index err=%v want ErrRefConflict", err)
	}
	if head, headErr := store.HeadHash(); headErr != nil || head != baseline {
		t.Fatalf("invalid commit was not rolled back head=%s want=%s err=%v", head, baseline, headErr)
	}
	record, exists, recordErr := store.Transaction(transactionID)
	if recordErr != nil || !exists || record.Phase != "aborted" || !record.Commit.IsZero() {
		t.Fatalf("invalid commit record exists=%t record=%+v err=%v", exists, record, recordErr)
	}
	body, readErr := os.ReadFile(filepath.Join(stateDir, "state", filepath.FromSlash(canonicalPath)))
	if readErr != nil || string(body) != "baseline\n" {
		t.Fatalf("invalid commit rollback canonical body=%q err=%v", body, readErr)
	}
	foreignBody, readErr := os.ReadFile(foreign)
	if readErr != nil || string(foreignBody) != "final foreign index entry\n" {
		t.Fatalf("invalid commit rollback erased external file body=%q err=%v", foreignBody, readErr)
	}
	repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	index, err := repository.Storer.Index()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range index.Entries {
		if entry.Name == "final-foreign.txt" {
			t.Fatal("invalid commit rollback retained foreign index entry")
		}
	}
}

func TestApplyRejectsFinalCanonicalWorktreeDrift(t *testing.T) {
	for _, test := range []struct {
		name string
		hook func(*Store, func() error)
	}{
		{name: "before commit", hook: func(store *Store, mutate func() error) {
			store.beforeBoundCommit = func() error {
				store.beforeBoundCommit = nil
				return mutate()
			}
		}},
		{name: "after commit", hook: func(store *Store, mutate func() error) {
			store.afterBoundCommit = func(plumbing.Hash) error {
				store.afterBoundCommit = nil
				return mutate()
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), ".sow")
			store := New(stateDir)
			const canonicalPath = "views/beta/assets/all/all.tsv"
			baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
			stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
			canonical := filepath.Join(stateDir, "state", filepath.FromSlash(canonicalPath))
			test.hook(store, func() error { return os.WriteFile(canonical, []byte("tampered\n"), 0o644) })
			_, _, err := store.Apply(t.Context(), "add", "reject final worktree drift", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
			if err == nil {
				t.Fatal("Apply accepted final canonical worktree drift")
			}
			if head, headErr := store.HeadHash(); headErr != nil || head != baseline {
				t.Fatalf("worktree drift rollback head=%s want=%s err=%v", head, baseline, headErr)
			}
			body, readErr := os.ReadFile(canonical)
			if readErr != nil || string(body) != "baseline\n" {
				t.Fatalf("worktree drift rollback body=%q err=%v", body, readErr)
			}
		})
	}
}

func TestApplyNoOpRejectsUnrelatedCanonicalDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(string) error
	}{
		{name: "tracked", mutate: func(workDir string) error {
			return os.WriteFile(filepath.Join(workDir, "config", "sow.yaml"), []byte("tampered config\n"), 0o644)
		}},
		{name: "untracked", mutate: func(workDir string) error {
			return os.WriteFile(filepath.Join(workDir, "untracked.txt"), []byte("foreign\n"), 0o644)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), ".sow")
			store := New(stateDir)
			const canonicalPath = "views/beta/assets/all/all.tsv"
			installTransactionTestCommit(t, store, canonicalPath, "same\n")
			baseline := installTransactionTestCommit(t, store, "config/sow.yaml", "baseline config\n")
			stage := transactionTestStage(t, stateDir, "same.tsv", "same\n")
			store.beforeBoundStageInstall = func() error {
				store.beforeBoundStageInstall = nil
				return test.mutate(filepath.Join(stateDir, "state"))
			}
			_, _, err := store.Apply(t.Context(), "add", "reject no-op unrelated drift", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
			if err == nil {
				t.Fatal("no-op Apply accepted unrelated canonical drift")
			}
			if head, headErr := store.HeadHash(); headErr != nil || head != baseline {
				t.Fatalf("no-op drift changed HEAD head=%s want=%s err=%v", head, baseline, headErr)
			}
		})
	}
}

func TestApplyRestoresRawHeadAfterCommitAndPreservesExternalBranch(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	const alternate = plumbing.ReferenceName("refs/heads/external-after-commit")
	repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	originalHead, err := snapshotRepositoryHead(repository)
	if err != nil {
		t.Fatal(err)
	}
	transactionID, err := NewTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	var created plumbing.Hash
	store.afterBoundCommit = func(hash plumbing.Hash) error {
		store.afterBoundCommit = nil
		created = hash
		repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
		if err != nil {
			return err
		}
		if err := repository.Storer.SetReference(plumbing.NewHashReference(alternate, hash)); err != nil {
			return err
		}
		return repository.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, alternate))
	}
	_, _, err = store.Apply(t.Context(), "add", "reject post-commit raw HEAD switch", map[string]string{canonicalPath: stage}, nil, ApplyOptions{TransactionID: transactionID})
	if !errors.Is(err, ErrRefConflict) || created.IsZero() {
		t.Fatalf("post-commit raw HEAD switch created=%s err=%v", created, err)
	}
	raw, rawErr := repository.Storer.Reference(plumbing.HEAD)
	if rawErr != nil || !referencesEqual(raw, originalHead.raw) {
		t.Fatalf("rollback did not restore raw HEAD raw=%v want=%v err=%v", raw, originalHead.raw, rawErr)
	}
	alternateRef, refErr := repository.Storer.Reference(alternate)
	if refErr != nil || alternateRef.Hash() != created {
		t.Fatalf("rollback erased external branch ref=%v created=%s err=%v", alternateRef, created, refErr)
	}
	originalBranch, refErr := repository.Storer.Reference(originalHead.name)
	if refErr != nil || originalBranch.Hash() != baseline {
		t.Fatalf("rollback did not compare-and-set original branch ref=%v baseline=%s err=%v", originalBranch, baseline, refErr)
	}
	body, readErr := os.ReadFile(filepath.Join(stateDir, "state", filepath.FromSlash(canonicalPath)))
	if readErr != nil || string(body) != "baseline\n" {
		t.Fatalf("raw HEAD rollback left checkout inconsistent body=%q err=%v", body, readErr)
	}
	record, exists, recordErr := store.Transaction(transactionID)
	if recordErr != nil || !exists || record.Phase != "aborted" {
		t.Fatalf("post-commit drift journal exists=%t record=%+v err=%v", exists, record, recordErr)
	}
	result, recoverErr := store.RecoverAborted(t.Context(), record)
	if recoverErr != nil || !result.Recovered || result.Commit.IsZero() {
		t.Fatalf("restored rollback boundary was not retryable result=%+v err=%v", result, recoverErr)
	}
	completed, exists, recordErr := store.Transaction(transactionID)
	if recordErr != nil || !exists || completed.Phase != "complete" {
		t.Fatalf("retried transaction did not complete exists=%t record=%+v err=%v", exists, completed, recordErr)
	}
}

func TestApplyRawHeadRestoreUsesExactSymbolicCAS(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	const alternate = plumbing.ReferenceName("refs/heads/external-alternate")
	const third = plumbing.ReferenceName("refs/heads/external-third")
	var created plumbing.Hash
	store.afterBoundCommit = func(hash plumbing.Hash) error {
		store.afterBoundCommit = nil
		created = hash
		repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
		if err != nil {
			return err
		}
		if err := repository.Storer.SetReference(plumbing.NewHashReference(alternate, hash)); err != nil {
			return err
		}
		return repository.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, alternate))
	}
	store.beforeRawHeadRestore = func() error {
		store.beforeRawHeadRestore = nil
		repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
		if err != nil {
			return err
		}
		if err := repository.Storer.SetReference(plumbing.NewHashReference(third, baseline)); err != nil {
			return err
		}
		return repository.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, third))
	}
	_, _, err := store.Apply(t.Context(), "add", "exact symbolic HEAD rollback", map[string]string{canonicalPath: stage}, nil, ApplyOptions{})
	if !errors.Is(err, ErrRefConflict) || created.IsZero() {
		t.Fatalf("symbolic CAS race created=%s err=%v", created, err)
	}
	repository, openErr := git.PlainOpen(filepath.Join(stateDir, "state"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	raw, rawErr := repository.Storer.Reference(plumbing.HEAD)
	if rawErr != nil || raw.Type() != plumbing.SymbolicReference || raw.Target() != third {
		t.Fatalf("exact symbolic CAS overwrote third branch raw=%v err=%v", raw, rawErr)
	}
	head, headErr := repository.Head()
	if headErr != nil || head.Hash() != baseline {
		t.Fatalf("third branch does not preserve consistent baseline head=%v err=%v", head, headErr)
	}
	alternateRef, refErr := repository.Storer.Reference(alternate)
	if refErr != nil || alternateRef.Hash() != created {
		t.Fatalf("symbolic CAS erased alternate branch ref=%v created=%s err=%v", alternateRef, created, refErr)
	}
}

func TestApplyCommitObjectReadFailureRestoresNonInitialHead(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	stage := transactionTestStage(t, stateDir, "approved.tsv", "approved\n")
	transactionID, err := NewTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	store.afterBoundCommit = func(hash plumbing.Hash) error {
		store.afterBoundCommit = nil
		value := hash.String()
		return os.Remove(filepath.Join(stateDir, "state", ".git", "objects", value[:2], value[2:]))
	}
	_, _, err = store.Apply(t.Context(), "add", "rollback unreadable created commit", map[string]string{canonicalPath: stage}, nil, ApplyOptions{TransactionID: transactionID})
	if err == nil {
		t.Fatal("Apply accepted an unreadable created commit object")
	}
	if head, headErr := store.HeadHash(); headErr != nil || head != baseline {
		t.Fatalf("unreadable commit rollback head=%s want=%s err=%v", head, baseline, headErr)
	}
	body, readErr := os.ReadFile(filepath.Join(stateDir, "state", filepath.FromSlash(canonicalPath)))
	if readErr != nil || string(body) != "baseline\n" {
		t.Fatalf("unreadable commit rollback body=%q err=%v", body, readErr)
	}
	record, exists, recordErr := store.Transaction(transactionID)
	if recordErr != nil || !exists || record.Phase != "aborted" {
		t.Fatalf("unreadable commit journal exists=%t record=%+v err=%v", exists, record, recordErr)
	}
	result, recoverErr := store.RecoverAborted(t.Context(), record)
	if recoverErr != nil || !result.Recovered || result.Commit.IsZero() {
		t.Fatalf("unreadable commit rollback was not retryable result=%+v err=%v", result, recoverErr)
	}
}

func TestCommitVectorRejectsForeignGitlink(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	const canonicalPath = "views/beta/assets/all/all.tsv"
	baseline := installTransactionTestCommit(t, store, canonicalPath, "baseline\n")
	repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	index, err := repository.Storer.Index()
	if err != nil {
		t.Fatal(err)
	}
	expected := make(map[string]canonicalWorktreeEntry, len(index.Entries))
	for _, entry := range index.Entries {
		expected[entry.Name] = canonicalWorktreeEntry{hash: entry.Hash, mode: entry.Mode}
	}
	index.Entries = append(index.Entries, &indexformat.Entry{
		Name: "foreign-submodule", Hash: baseline, Mode: filemode.Submodule,
	})
	if err := repository.Storer.SetIndex(index); err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	commit, err := worktree.Commit("foreign gitlink fixture", &git.CommitOptions{
		Author:  &object.Signature{Name: "test", Email: "test@localhost", When: now},
		Parents: []plumbing.Hash{baseline},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := requireCommitMatchesIndexVector(repository, commit, baseline, expected); !errors.Is(err, ErrRefConflict) {
		t.Fatalf("foreign gitlink verification err=%v want ErrRefConflict", err)
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

func TestFileIdentityAtHeadBoundedRejectsOversizedCanonicalBlob(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	store := New(stateDir)
	stage := transactionTestStage(t, stateDir, "config-large.yaml", strings.Repeat("x", 33))
	if _, _, err := store.Apply(t.Context(), "init", "large config", map[string]string{"config/sow.yaml": stage}, nil, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if identity, exists, err := store.FileIdentityAtHeadBounded("config/sow.yaml", 32); err == nil || exists || identity != (FileIdentity{}) || !strings.Contains(err.Error(), "exceeds 32 bytes") {
		t.Fatalf("bounded identity=%+v exists=%v err=%v", identity, exists, err)
	}
	identity, exists, err := store.FileIdentityAtHead("config/sow.yaml")
	if err != nil || !exists || identity.Size != 33 {
		t.Fatalf("unbounded compatibility identity=%+v exists=%v err=%v", identity, exists, err)
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
