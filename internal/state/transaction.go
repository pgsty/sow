package state

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/index"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pgsty/sow/internal/manifest"
)

const transactionSchema = "sow-local-transaction/v1"

var (
	ErrRecoveryRequired = errors.New("incomplete local transaction requires recovery")
	ErrFileConflict     = errors.New("canonical file changed since operation start")
)

type FileIdentity struct {
	Size   int64
	SHA256 string
}

// FileIdentityAtHead returns the exact byte identity recorded for one file by
// a single snapshot of aggregate HEAD. It never reads the mutable worktree and
// never initializes a missing repository, so callers cannot mistake another
// transaction's pre-commit AtomicCopy window for committed canonical state.
func (s *Store) FileIdentityAtHead(relative string) (FileIdentity, bool, error) {
	if err := validateStatePath(relative); err != nil {
		return FileIdentity{}, false, err
	}
	repository, err := s.OpenRepository()
	if errors.Is(err, git.ErrRepositoryNotExists) {
		if _, metadataErr := os.Lstat(filepath.Join(s.workDir, ".git")); metadataErr == nil {
			return FileIdentity{}, false, fmt.Errorf("open canonical state repository: %w", err)
		} else if !errors.Is(metadataErr, os.ErrNotExist) {
			return FileIdentity{}, false, metadataErr
		}
		return FileIdentity{}, false, nil
	}
	if err != nil {
		return FileIdentity{}, false, fmt.Errorf("open canonical state repository: %w", err)
	}
	var head plumbing.Hash
	if s != nil && s.readRepository != nil {
		head = s.readHead
		if head.IsZero() {
			return FileIdentity{}, false, nil
		}
	} else {
		reference, err := repository.Head()
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return FileIdentity{}, false, nil
		}
		if err != nil {
			return FileIdentity{}, false, fmt.Errorf("read canonical state HEAD: %w", err)
		}
		head = reference.Hash()
	}
	tree, err := canonicalTree(repository, head)
	if err != nil {
		return FileIdentity{}, false, fmt.Errorf("read canonical state tree at %s: %w", head, err)
	}
	if _, exists, err := treeBlobEntry(tree, relative); err != nil || !exists {
		return FileIdentity{}, false, err
	}
	file, err := tree.File(relative)
	if err != nil {
		return FileIdentity{}, false, fmt.Errorf("open canonical state %s at %s: %w", relative, head, err)
	}
	reader, err := file.Reader()
	if err != nil {
		return FileIdentity{}, false, fmt.Errorf("read canonical state %s at %s: %w", relative, head, err)
	}
	hasher := sha256.New()
	size, copyErr := io.Copy(hasher, reader)
	closeErr := reader.Close()
	if copyErr != nil || closeErr != nil {
		return FileIdentity{}, false, errors.Join(copyErr, closeErr)
	}
	return FileIdentity{Size: size, SHA256: hex.EncodeToString(hasher.Sum(nil))}, true, nil
}

// FileExpectation is a compare-and-set precondition evaluated against the
// aggregate HEAD selected by Apply. It may admit absence and one or more exact
// byte identities, allowing an idempotent peer to have already installed the
// same desired config while rejecting a stale writer with different bytes.
type FileExpectation struct {
	AllowAbsent bool
	Identities  []FileIdentity
}

type RefUpdate struct {
	Name     plumbing.ReferenceName
	Expected plumbing.Hash
	// Target optionally names an existing canonical commit. The zero hash
	// means the commit created by this transaction, preserving the default
	// behavior for callers that only update refs to their canonical mutation.
	Target    plumbing.Hash
	Immutable bool
	// Delete removes the ref after comparing Expected. It is journaled and
	// replay-idempotent, allowing an exact remote ref vector to converge during
	// topology restore and snapshot expiry. Delete and Target are mutually
	// exclusive.
	Delete bool
}

// ApplyOptions carries recoverable canonical-file deletions plus deterministic
// fault injection used by recovery tests. Production callers leave AfterCommit
// nil and may provide only exact DeletePaths proven from canonical state.
type ApplyOptions struct {
	AfterCommit func() error
	// AfterIntent is a deterministic fault-injection seam invoked after the
	// exact intent journal is durable but before any canonical worktree or Git
	// state is changed. Production callers leave it nil.
	AfterIntent func() error
	// TransactionID lets a higher-level durable workflow bind its own progress
	// record to this exact local transaction before any canonical mutation. An
	// empty value preserves the default cryptographically random allocation.
	TransactionID string
	ExpectedFiles map[string]FileExpectation
	// DeletePaths removes exact canonical worktree files in the same recoverable
	// Git commit as Staged. The intent journal binds the bytes being removed so a
	// retry cannot silently delete a different local-state object.
	DeletePaths []string
}

// TransactionRecord is the durable, verified result of one local transaction.
// Staged paths and file identities remain internal to the state layer; callers
// bind the public operation/message fields to their own progress identity.
type TransactionRecord struct {
	ID           string
	Operation    string
	Message      string
	Phase        string
	ExpectedHead plumbing.Hash
	Commit       plumbing.Hash
	Files        []TransactionFileRecord
	Refs         []TransactionRefRecord
}

type TransactionFileRecord struct {
	Canonical string
	Size      int64
	SHA256    string
	Delete    bool
}

// TransactionRefRecord exposes the immutable compare-and-set coordinates of a
// verified local transaction to higher-level recovery bridges. It contains no
// staged filesystem path and cannot be used to mutate the journal.
type TransactionRefRecord struct {
	Name      plumbing.ReferenceName
	Expected  plumbing.Hash
	Target    plumbing.Hash
	Immutable bool
	Delete    bool
}

type journalFile struct {
	Canonical string `json:"canonical"`
	Staged    string `json:"staged,omitempty"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Delete    bool   `json:"delete,omitempty"`
}

type journalRef struct {
	Name      string `json:"name"`
	Expected  string `json:"expected"`
	Target    string `json:"target"`
	Immutable bool   `json:"immutable"`
	Delete    bool   `json:"delete,omitempty"`
}

type transactionJournal struct {
	Schema       string        `json:"schema"`
	ID           string        `json:"id"`
	Operation    string        `json:"operation"`
	Phase        string        `json:"phase"`
	Message      string        `json:"message"`
	ExpectedHead string        `json:"expected_head"`
	Commit       string        `json:"commit,omitempty"`
	Files        []journalFile `json:"files"`
	Refs         []journalRef  `json:"refs"`
	CreatedAt    string        `json:"created_at"`
	UpdatedAt    string        `json:"updated_at"`
	Failure      string        `json:"failure,omitempty"`
}

type RecoveryResult struct {
	ID        string
	Operation string
	Commit    plumbing.Hash
	Recovered bool
}

// RecoverAborted retries one pre-commit transaction whose installer returned
// an error after the durable intent was written. The caller must hold the SOW
// mutation lock and must first bind expected to its higher-level recovery
// record. Requiring the complete public record here prevents a caller from
// turning an arbitrary aborted journal ID into a generic mutation primitive.
//
// Once the exact frozen stages, old HEAD, old refs, and clean journal-owned
// worktree paths have been re-proved, the aborted phase is durably returned to
// intent and ordinary recovery performs the one replay. A stop after that
// phase change is safe: Store.Recover will resume the same immutable journal.
func (s *Store) RecoverAborted(ctx context.Context, expected TransactionRecord) (RecoveryResult, error) {
	if err := s.requireWritable(); err != nil {
		return RecoveryResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return RecoveryResult{}, err
	}
	if err := validateTransactionID(expected.ID); err != nil {
		return RecoveryResult{}, err
	}
	current, exists, err := s.Transaction(expected.ID)
	if err != nil || !exists {
		return RecoveryResult{}, errors.Join(err, fmt.Errorf("aborted transaction %s is unavailable", expected.ID))
	}
	if !transactionRecordsEqual(current, expected) {
		return RecoveryResult{}, errors.New("aborted transaction changed after higher-level recovery admission")
	}
	if current.Phase == "complete" {
		return RecoveryResult{ID: current.ID, Operation: current.Operation, Commit: current.Commit}, nil
	}
	if current.Phase != "aborted" || !current.Commit.IsZero() {
		return RecoveryResult{}, fmt.Errorf("transaction %s is not an aborted pre-commit transaction", current.ID)
	}
	incomplete, err := s.IncompleteTransactions()
	if err != nil {
		return RecoveryResult{}, err
	}
	if len(incomplete) != 0 {
		return RecoveryResult{}, fmt.Errorf("%w: %s", ErrRecoveryRequired, strings.Join(incomplete, ","))
	}

	journals, err := s.readJournals()
	if err != nil {
		return RecoveryResult{}, err
	}
	var journal *transactionJournal
	var otherPending []string
	for _, candidate := range journals {
		if candidate.ID == current.ID {
			journal = candidate
			continue
		}
		if candidate.Phase != "complete" {
			otherPending = append(otherPending, candidate.ID+":"+candidate.Phase)
		}
	}
	if len(otherPending) != 0 {
		sort.Strings(otherPending)
		return RecoveryResult{}, fmt.Errorf("%w: %s", ErrRecoveryRequired, strings.Join(otherPending, ","))
	}
	if journal == nil || journal.Phase != "aborted" || journal.Commit != "" || journal.Failure != "aborted before canonical commit" {
		return RecoveryResult{}, errors.New("aborted transaction journal has an invalid retry boundary")
	}
	head, err := s.HeadHash()
	if err != nil || head != current.ExpectedHead {
		return RecoveryResult{}, errors.Join(err, errors.New("aborted transaction canonical HEAD changed before retry"))
	}
	for _, update := range current.Refs {
		value, refExists, err := s.Ref(update.Name)
		if err != nil || refExists != !update.Expected.IsZero() || refExists && value != update.Expected {
			return RecoveryResult{}, errors.Join(err, fmt.Errorf("aborted transaction ref %s changed before retry", update.Name))
		}
	}
	if _, err := s.verifyJournalFiles(journal); err != nil {
		return RecoveryResult{}, fmt.Errorf("verify aborted transaction stages: %w", err)
	}
	if err := s.resetCanonicalWorktree(current.ExpectedHead, journal); err != nil {
		return RecoveryResult{}, fmt.Errorf("reset aborted transaction worktree: %w", err)
	}
	if _, err := s.verifyJournalDeletes(journal); err != nil {
		return RecoveryResult{}, fmt.Errorf("verify aborted transaction deletions: %w", err)
	}
	journal.Phase = "intent"
	journal.Failure = ""
	if err := s.writeJournal(journal); err != nil {
		return RecoveryResult{}, fmt.Errorf("persist aborted transaction retry intent: %w", err)
	}
	results, err := s.Recover(ctx)
	if err != nil {
		return RecoveryResult{}, err
	}
	for _, result := range results {
		if result.ID == current.ID {
			return result, nil
		}
	}
	return RecoveryResult{}, errors.New("aborted transaction retry produced no recovery result")
}

func transactionRecordsEqual(left, right TransactionRecord) bool {
	if left.ID != right.ID || left.Operation != right.Operation || left.Message != right.Message || left.Phase != right.Phase ||
		left.ExpectedHead != right.ExpectedHead || left.Commit != right.Commit || len(left.Files) != len(right.Files) || len(left.Refs) != len(right.Refs) {
		return false
	}
	for index := range left.Files {
		if left.Files[index] != right.Files[index] {
			return false
		}
	}
	for index := range left.Refs {
		if left.Refs[index] != right.Refs[index] {
			return false
		}
	}
	return true
}

// Apply commits canonical files and advances all named refs as one recoverable
// local transaction. The Git commit is the durable commit point. If the process
// stops after it, Recover completes the exact recorded compare-and-set updates.
func (s *Store) Apply(ctx context.Context, operation, message string, staged map[string]string, refs []RefUpdate, options ApplyOptions) (plumbing.Hash, bool, error) {
	if err := s.requireWritable(); err != nil {
		return plumbing.ZeroHash, false, err
	}
	if err := ctx.Err(); err != nil {
		return plumbing.ZeroHash, false, err
	}
	if err := validateOperation(operation); err != nil {
		return plumbing.ZeroHash, false, err
	}
	if options.TransactionID != "" {
		if err := validateTransactionID(options.TransactionID); err != nil {
			return plumbing.ZeroHash, false, err
		}
		if _, exists, err := s.Transaction(options.TransactionID); err != nil {
			return plumbing.ZeroHash, false, err
		} else if exists {
			return plumbing.ZeroHash, false, fmt.Errorf("local transaction ID %s already exists", options.TransactionID)
		}
	}
	incomplete, err := s.IncompleteTransactions()
	if err != nil {
		return plumbing.ZeroHash, false, err
	}
	if len(incomplete) != 0 {
		return plumbing.ZeroHash, false, fmt.Errorf("%w: %s", ErrRecoveryRequired, strings.Join(incomplete, ","))
	}
	expectedHead, err := s.HeadHash()
	if err != nil {
		return plumbing.ZeroHash, false, err
	}
	if err := s.verifyExpectedFilesAt(expectedHead, options.ExpectedFiles); err != nil {
		return plumbing.ZeroHash, false, err
	}
	journal, err := s.buildJournalWithDeletes(operation, message, expectedHead, staged, options.DeletePaths, refs)
	if err != nil {
		return plumbing.ZeroHash, false, err
	}
	if options.TransactionID != "" {
		journal.ID = options.TransactionID
	}
	if err := s.requireCanonicalWorktreeMatchesHead(); err != nil {
		return plumbing.ZeroHash, false, err
	}
	if err := s.writeJournal(journal); err != nil {
		return plumbing.ZeroHash, false, err
	}
	if options.AfterIntent != nil {
		if err := options.AfterIntent(); err != nil {
			return plumbing.ZeroHash, false, err
		}
	}
	commit, changed, err := s.installPathChanges(staged, options.DeletePaths, message)
	if err != nil {
		journal.Phase = "aborted"
		journal.Failure = "aborted before canonical commit"
		_ = s.writeJournal(journal)
		return plumbing.ZeroHash, false, err
	}
	journal.Commit = commit.String()
	resolveJournalRefTargets(journal, commit)
	journal.Phase = "committed"
	if err := s.writeJournal(journal); err != nil {
		return commit, changed, err
	}
	if options.AfterCommit != nil {
		if err := options.AfterCommit(); err != nil {
			return commit, changed, err
		}
	}
	if err := s.applyJournalRefs(journal); err != nil {
		return commit, changed, err
	}
	journal.Phase = "complete"
	journal.Failure = ""
	if err := s.writeJournal(journal); err != nil {
		return commit, changed, err
	}
	return commit, changed, nil
}

func (s *Store) verifyExpectedFilesAt(commit plumbing.Hash, expected map[string]FileExpectation) error {
	if len(expected) == 0 {
		return nil
	}
	repository, err := s.ensureRepository()
	if err != nil {
		return err
	}
	tree, err := canonicalTree(repository, commit)
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(expected))
	for canonical := range expected {
		if err := validateStatePath(canonical); err != nil {
			return err
		}
		paths = append(paths, canonical)
	}
	sort.Strings(paths)
	for _, canonical := range paths {
		expectation := expected[canonical]
		entry, exists, err := treeBlobEntry(tree, canonical)
		if err != nil {
			return err
		}
		if !exists && expectation.AllowAbsent {
			continue
		}
		matched := false
		if exists && entry != nil {
			for _, identity := range expectation.Identities {
				if identity.Size < 0 || len(identity.SHA256) != sha256.Size*2 || !isLowerHex(identity.SHA256) {
					return fmt.Errorf("invalid expected identity for canonical file %s", canonical)
				}
				matches, err := s.canonicalBlobMatches(commit, canonical, identity.Size, identity.SHA256)
				if err != nil {
					return err
				}
				if matches {
					matched = true
					break
				}
			}
		}
		if !matched {
			return fmt.Errorf("%w: %s", ErrFileConflict, canonical)
		}
	}
	return nil
}

// RequireExpectedFiles evaluates compare-and-set preconditions against the
// current aggregate HEAD without mutating canonical state. Callers use it
// immediately after acquiring the global state lock so expensive external
// side effects never run under a stale configuration snapshot.
func (s *Store) RequireExpectedFiles(expected map[string]FileExpectation) error {
	head, err := s.HeadHash()
	if err != nil {
		return err
	}
	return s.verifyExpectedFilesAt(head, expected)
}

// NewTransactionID allocates the opaque identity a higher-level recovery
// record can persist before calling Apply.
func NewTransactionID() (string, error) { return transactionID() }

// Transaction returns one journal result after proving every completed record
// still names the exact canonical commit it described. Missing IDs are not an
// error. Incomplete records are returned only so the caller can fail closed;
// Store.Recover must advance them before they can be used as commit evidence.
func (s *Store) Transaction(id string) (TransactionRecord, bool, error) {
	if s != nil && s.readRepository != nil {
		return TransactionRecord{}, false, ErrReadOnly
	}
	if err := validateTransactionID(id); err != nil {
		return TransactionRecord{}, false, err
	}
	journals, err := s.readJournals()
	if err != nil {
		return TransactionRecord{}, false, err
	}
	for _, journal := range journals {
		if journal.ID != id {
			continue
		}
		record := TransactionRecord{
			ID: journal.ID, Operation: journal.Operation, Message: journal.Message, Phase: journal.Phase,
			ExpectedHead: plumbing.NewHash(journal.ExpectedHead), Files: make([]TransactionFileRecord, 0, len(journal.Files)),
			Refs: make([]TransactionRefRecord, 0, len(journal.Refs)),
		}
		if journal.Commit != "" {
			record.Commit = plumbing.NewHash(journal.Commit)
		}
		for _, file := range journal.Files {
			record.Files = append(record.Files, TransactionFileRecord{Canonical: file.Canonical, Size: file.Size, SHA256: file.SHA256, Delete: file.Delete})
		}
		for _, ref := range journal.Refs {
			record.Refs = append(record.Refs, TransactionRefRecord{
				Name: plumbing.ReferenceName(ref.Name), Expected: plumbing.NewHash(ref.Expected), Target: plumbing.NewHash(ref.Target),
				Immutable: ref.Immutable, Delete: ref.Delete,
			})
		}
		if journal.Phase != "complete" {
			return record, true, nil
		}
		commit := plumbing.NewHash(journal.Commit)
		expected := plumbing.NewHash(journal.ExpectedHead)
		repository, err := s.ensureRepository()
		if err != nil {
			return TransactionRecord{}, false, err
		}
		if commit == expected {
			for _, file := range journal.Files {
				if file.Delete {
					return TransactionRecord{}, false, fmt.Errorf("completed no-op transaction %s contains a deletion", id)
				}
				matches, err := s.canonicalBlobMatches(commit, file.Canonical, file.Size, file.SHA256)
				if err != nil || !matches {
					return TransactionRecord{}, false, errors.Join(err, fmt.Errorf("completed no-op transaction %s no longer matches canonical bytes", id))
				}
			}
		} else {
			matches, err := s.commitExactlyAppliesJournal(repository, commit, expected, journal)
			if err != nil || !matches {
				return TransactionRecord{}, false, errors.Join(err, fmt.Errorf("completed transaction %s does not exactly match its journal", id))
			}
		}
		current, err := s.HeadHash()
		if err != nil || current.IsZero() {
			return TransactionRecord{}, false, errors.Join(err, fmt.Errorf("completed transaction %s has no canonical HEAD", id))
		}
		committed, err := repository.CommitObject(commit)
		if err != nil {
			return TransactionRecord{}, false, err
		}
		currentCommit, err := repository.CommitObject(current)
		if err != nil {
			return TransactionRecord{}, false, err
		}
		ancestor := current == commit
		if !ancestor {
			ancestor, err = committed.IsAncestor(currentCommit)
		}
		if err != nil || !ancestor {
			return TransactionRecord{}, false, errors.Join(err, fmt.Errorf("completed transaction %s is not an ancestor of canonical HEAD", id))
		}
		record.Commit = commit
		return record, true, nil
	}
	return TransactionRecord{}, false, nil
}

func (s *Store) HeadHash() (plumbing.Hash, error) {
	if s != nil && s.readRepository != nil {
		return s.readHead, nil
	}
	repository, err := s.ensureRepository()
	if err != nil {
		return plumbing.ZeroHash, err
	}
	head, err := repository.Head()
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return plumbing.ZeroHash, nil
	}
	if err != nil {
		return plumbing.ZeroHash, err
	}
	return head.Hash(), nil
}

func (s *Store) buildJournal(operation, message string, expected plumbing.Hash, staged map[string]string, refs []RefUpdate) (*transactionJournal, error) {
	return s.buildJournalWithDeletes(operation, message, expected, staged, nil, refs)
}

func (s *Store) buildJournalWithDeletes(operation, message string, expected plumbing.Hash, staged map[string]string, deleted []string, refs []RefUpdate) (*transactionJournal, error) {
	if len(staged) == 0 && len(deleted) == 0 {
		return nil, errors.New("transaction has no canonical files")
	}
	id, err := transactionID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	journal := &transactionJournal{
		Schema: transactionSchema, ID: id, Operation: operation, Phase: "intent", Message: message,
		ExpectedHead: expected.String(), CreatedAt: now, UpdatedAt: now,
	}
	paths := make([]string, 0, len(staged))
	for canonical := range staged {
		paths = append(paths, canonical)
	}
	sort.Strings(paths)
	for _, canonical := range paths {
		if err := validateStatePath(canonical); err != nil {
			return nil, err
		}
		stagedRelative, err := s.journalStagedPath(staged[canonical])
		if err != nil {
			return nil, fmt.Errorf("stage %s: %w", canonical, err)
		}
		digest, size, err := hashRegularFile(staged[canonical])
		if err != nil {
			return nil, err
		}
		journal.Files = append(journal.Files, journalFile{Canonical: canonical, Staged: stagedRelative, Size: size, SHA256: digest})
	}
	deletePaths := append([]string(nil), deleted...)
	sort.Strings(deletePaths)
	for index, canonical := range deletePaths {
		if err := validateStatePath(canonical); err != nil {
			return nil, err
		}
		if _, replaced := staged[canonical]; replaced {
			return nil, fmt.Errorf("canonical state path %s cannot be installed and deleted together", canonical)
		}
		if index != 0 && deletePaths[index-1] == canonical {
			return nil, fmt.Errorf("duplicate canonical state deletion %s", canonical)
		}
		digest, size, err := hashRegularFile(filepath.Join(s.workDir, filepath.FromSlash(canonical)))
		if err != nil {
			return nil, fmt.Errorf("bind canonical state deletion %s: %w", canonical, err)
		}
		journal.Files = append(journal.Files, journalFile{Canonical: canonical, Size: size, SHA256: digest, Delete: true})
	}
	sort.Slice(journal.Files, func(i, j int) bool { return journal.Files[i].Canonical < journal.Files[j].Canonical })
	for index := 1; index < len(journal.Files); index++ {
		if journal.Files[index-1].Canonical == journal.Files[index].Canonical {
			return nil, fmt.Errorf("duplicate transaction canonical path %s", journal.Files[index].Canonical)
		}
	}
	for _, update := range refs {
		if err := validateSOWRef(update.Name); err != nil {
			return nil, err
		}
		if update.Delete {
			if update.Expected.IsZero() || !update.Target.IsZero() || update.Immutable {
				return nil, fmt.Errorf("transaction ref %s has invalid delete semantics", update.Name)
			}
		} else if !update.Target.IsZero() {
			if err := s.requireLocalCommit(update.Target); err != nil {
				return nil, fmt.Errorf("transaction ref %s target: %w", update.Name, err)
			}
		}
		journal.Refs = append(journal.Refs, journalRef{
			Name: update.Name.String(), Expected: update.Expected.String(), Target: update.Target.String(), Immutable: update.Immutable, Delete: update.Delete,
		})
	}
	sort.Slice(journal.Refs, func(i, j int) bool { return journal.Refs[i].Name < journal.Refs[j].Name })
	for i := 1; i < len(journal.Refs); i++ {
		if journal.Refs[i-1].Name == journal.Refs[i].Name {
			return nil, fmt.Errorf("duplicate transaction ref %s", journal.Refs[i].Name)
		}
	}
	return journal, nil
}

func (s *Store) journalStagedPath(value string) (string, error) {
	abs, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	stateAbs, err := filepath.Abs(s.stateDir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(stateAbs, abs)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("staged transaction file must be below .sow")
	}
	workAbs, err := filepath.Abs(s.workDir)
	if err != nil {
		return "", err
	}
	if workRel, relErr := filepath.Rel(workAbs, abs); relErr != nil || workRel == "." || workRel != ".." && !strings.HasPrefix(workRel, ".."+string(filepath.Separator)) {
		return "", errors.New("staged transaction file must be outside the canonical state worktree")
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("staged transaction file must be a regular non-symlink")
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	stateReal, err := filepath.EvalSymlinks(stateAbs)
	if err != nil {
		return "", err
	}
	realRel, err := filepath.Rel(stateReal, real)
	if err != nil || realRel == "." || realRel == ".." || strings.HasPrefix(realRel, ".."+string(filepath.Separator)) {
		return "", errors.New("staged transaction file resolves outside .sow")
	}
	workReal, err := filepath.EvalSymlinks(workAbs)
	if errors.Is(err, os.ErrNotExist) {
		return filepath.ToSlash(rel), nil
	}
	if err != nil {
		return "", err
	}
	if workRel, relErr := filepath.Rel(workReal, real); relErr != nil || workRel == "." || workRel != ".." && !strings.HasPrefix(workRel, ".."+string(filepath.Separator)) {
		return "", errors.New("staged transaction file resolves inside the canonical state worktree")
	}
	return filepath.ToSlash(rel), nil
}

func (s *Store) writeJournal(journal *transactionJournal) error {
	if err := validateJournal(journal); err != nil {
		return err
	}
	directory := filepath.Join(s.stateDir, "journal")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create transaction journal directory: %w", err)
	}
	journal.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	temporary, err := os.CreateTemp(directory, ".journal-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		if !keep {
			temporary.Close()
			os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(journal); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	destination := filepath.Join(directory, journal.ID+".json")
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	keep = true
	return syncStateDirectory(directory)
}

func (s *Store) IncompleteTransactions() ([]string, error) {
	if s != nil && s.readRepository != nil {
		return nil, ErrReadOnly
	}
	journals, err := s.readJournals()
	if err != nil {
		return nil, err
	}
	var result []string
	for _, journal := range journals {
		if journal.Phase == "intent" || journal.Phase == "committed" {
			result = append(result, journal.ID+":"+journal.Phase)
		}
	}
	sort.Strings(result)
	return result, nil
}

func (s *Store) RequireNoIncompleteTransactions() error {
	if s != nil && s.readRepository != nil {
		return ErrReadOnly
	}
	incomplete, err := s.IncompleteTransactions()
	if err != nil {
		return err
	}
	if len(incomplete) > 0 {
		return fmt.Errorf("%w: %s", ErrRecoveryRequired, strings.Join(incomplete, ","))
	}
	return nil
}

// Recover safely replays every incomplete local transaction in journal order.
// The caller must hold the SOW mutation lock.
func (s *Store) Recover(ctx context.Context) ([]RecoveryResult, error) {
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	journals, err := s.readJournals()
	if err != nil {
		return nil, err
	}
	var results []RecoveryResult
	for _, journal := range journals {
		if journal.Phase != "intent" && journal.Phase != "committed" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return results, err
		}
		if err := s.requireJournalRefTargets(journal); err != nil {
			return results, fmt.Errorf("recover %s ref targets: %w", journal.ID, err)
		}
		var commit plumbing.Hash
		if journal.Phase == "intent" {
			head, err := s.HeadHash()
			if err != nil {
				return results, err
			}
			expected := plumbing.NewHash(journal.ExpectedHead)
			switch {
			case head == expected:
				// No commit exists yet, so replay still depends on the exact
				// staged sources recorded by the intent journal.
				staged, verifyErr := s.verifyJournalFiles(journal)
				if verifyErr != nil {
					return results, fmt.Errorf("recover %s: %w", journal.ID, verifyErr)
				}
				// An intent can stop after any staged file was copied and added to
				// the index but before Commit. Reset every replay, not only delete
				// transactions, or equal source/destination bytes can make the
				// installer return the old HEAD and resolve refs to the wrong commit.
				if resetErr := s.resetCanonicalWorktree(expected, journal); resetErr != nil {
					return results, fmt.Errorf("recover %s partial canonical mutation: %w", journal.ID, resetErr)
				}
				deleted, verifyErr := s.verifyJournalDeletes(journal)
				if verifyErr != nil {
					return results, fmt.Errorf("recover %s: %w", journal.ID, verifyErr)
				}
				commit, _, err = s.installPathChanges(staged, deleted, journal.Message)
				if err != nil {
					return results, fmt.Errorf("recover %s commit: %w", journal.ID, err)
				}
			case !head.IsZero():
				// Apply may have created the exact Git commit and then failed to
				// durably advance intent -> committed. Callers are allowed to
				// remove transaction staging on return, so prove the committed
				// tree directly before consulting any staged pathname.
				repository, openErr := s.ensureRepository()
				if openErr != nil {
					return results, openErr
				}
				matches, matchErr := s.commitExactlyAppliesJournal(repository, head, expected, journal)
				if matchErr != nil {
					return results, matchErr
				}
				if !matches {
					return results, fmt.Errorf("recover %s: %w: HEAD is %s, expected %s", journal.ID, ErrRefConflict, head, expected)
				}
				if matchErr := s.requireCanonicalWorktreeMatchesCommit(repository, head); matchErr != nil {
					return results, fmt.Errorf("recover %s committed canonical mutation: %w", journal.ID, matchErr)
				}
				commit = head
			default:
				return results, fmt.Errorf("recover %s: canonical HEAD disappeared", journal.ID)
			}
			journal.Commit = commit.String()
			resolveJournalRefTargets(journal, commit)
			journal.Phase = "committed"
			if err := s.writeJournal(journal); err != nil {
				return results, err
			}
		} else {
			commit = plumbing.NewHash(journal.Commit)
			if commit.IsZero() {
				return results, fmt.Errorf("recover %s: committed journal has no commit", journal.ID)
			}
			currentHead, headErr := s.HeadHash()
			if headErr != nil || currentHead.IsZero() {
				return results, errors.Join(headErr, fmt.Errorf("recover %s: canonical HEAD disappeared after transaction commit", journal.ID))
			}
			repository, openErr := s.ensureRepository()
			if openErr != nil {
				return results, openErr
			}
			journalCommit, commitErr := repository.CommitObject(commit)
			currentCommit, currentErr := repository.CommitObject(currentHead)
			if commitErr != nil || currentErr != nil {
				return results, errors.Join(commitErr, currentErr)
			}
			ancestor, ancestorErr := journalCommit.IsAncestor(currentCommit)
			if ancestorErr != nil || !ancestor {
				return results, errors.Join(ancestorErr, fmt.Errorf("recover %s: %w: current HEAD no longer descends from the committed transaction", journal.ID, ErrRefConflict))
			}
			if err := s.requireCanonicalWorktreeMatchesRepositoryHead(repository); err != nil {
				return results, fmt.Errorf("recover %s committed canonical worktree: %w", journal.ID, err)
			}
		}
		if err := s.requireLocalCommit(commit); err != nil {
			return results, fmt.Errorf("recover %s canonical commit: %w", journal.ID, err)
		}
		if err := s.applyJournalRefs(journal); err != nil {
			return results, fmt.Errorf("recover %s refs: %w", journal.ID, err)
		}
		journal.Phase = "complete"
		journal.Failure = ""
		if err := s.writeJournal(journal); err != nil {
			return results, err
		}
		results = append(results, RecoveryResult{ID: journal.ID, Operation: journal.Operation, Commit: commit, Recovered: true})
	}
	return results, nil
}

func resolveJournalRefTargets(journal *transactionJournal, commit plumbing.Hash) {
	for index := range journal.Refs {
		if !journal.Refs[index].Delete && plumbing.NewHash(journal.Refs[index].Target).IsZero() {
			journal.Refs[index].Target = commit.String()
		}
	}
}

func (s *Store) applyJournalRefs(journal *transactionJournal) error {
	for _, update := range journal.Refs {
		name := plumbing.ReferenceName(update.Name)
		expected := plumbing.NewHash(update.Expected)
		if update.Delete {
			if err := s.DeleteRef(name, expected); err != nil {
				return err
			}
			continue
		}
		target := plumbing.NewHash(update.Target)
		if err := s.AdvanceRef(name, expected, target, update.Immutable); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) requireLocalCommit(hash plumbing.Hash) error {
	if hash.IsZero() {
		return errors.New("target is the zero hash")
	}
	repository, err := s.ensureRepository()
	if err != nil {
		return err
	}
	if _, err := repository.CommitObject(hash); err != nil {
		return fmt.Errorf("%s is not a local commit: %w", hash, err)
	}
	return nil
}

func (s *Store) requireJournalRefTargets(journal *transactionJournal) error {
	for _, update := range journal.Refs {
		if update.Delete {
			continue
		}
		target := plumbing.NewHash(update.Target)
		if target.IsZero() {
			continue
		}
		if err := s.requireLocalCommit(target); err != nil {
			return fmt.Errorf("transaction ref %s target: %w", update.Name, err)
		}
	}
	return nil
}

func (s *Store) readJournals() ([]*transactionJournal, error) {
	directory := filepath.Join(s.stateDir, "journal")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var journals []*transactionJournal
	for _, entry := range entries {
		// Atomic journal writes use a hidden temporary name. A process can stop
		// before Rename, leaving a partial legacy .journal-*.json or current
		// .journal-*.tmp file behind. Neither is a durable transaction intent.
		if strings.HasPrefix(entry.Name(), ".journal-") {
			continue
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("transaction journal %q is a symlink", entry.Name())
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("transaction journal %q is not a regular file", entry.Name())
		}
		file, err := os.Open(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(file)
		decoder.DisallowUnknownFields()
		var journal transactionJournal
		decodeErr := decoder.Decode(&journal)
		var trailing any
		trailingErr := decoder.Decode(&trailing)
		closeErr := file.Close()
		if decodeErr != nil || !errors.Is(trailingErr, io.EOF) || closeErr != nil {
			return nil, fmt.Errorf("read transaction journal %s: %w", entry.Name(), errors.Join(decodeErr, trailingErr, closeErr))
		}
		if entry.Name() != journal.ID+".json" {
			return nil, fmt.Errorf("journal filename %q does not match ID %q", entry.Name(), journal.ID)
		}
		if err := validateJournal(&journal); err != nil {
			return nil, fmt.Errorf("validate journal %s: %w", journal.ID, err)
		}
		journals = append(journals, &journal)
	}
	sort.Slice(journals, func(i, j int) bool {
		if journals[i].CreatedAt != journals[j].CreatedAt {
			return journals[i].CreatedAt < journals[j].CreatedAt
		}
		return journals[i].ID < journals[j].ID
	})
	return journals, nil
}

func (s *Store) verifyJournalFiles(journal *transactionJournal) (map[string]string, error) {
	staged := make(map[string]string, len(journal.Files))
	for _, file := range journal.Files {
		if file.Delete {
			continue
		}
		path := filepath.Join(s.stateDir, filepath.FromSlash(file.Staged))
		digest, size, err := hashRegularFile(path)
		if err != nil {
			return nil, err
		}
		if digest != file.SHA256 || size != file.Size {
			return nil, fmt.Errorf("staged file %s changed after intent was recorded", file.Canonical)
		}
		staged[file.Canonical] = path
	}
	return staged, nil
}

func (s *Store) verifyJournalDeletes(journal *transactionJournal) ([]string, error) {
	var deleted []string
	for _, file := range journal.Files {
		if !file.Delete {
			continue
		}
		candidate := filepath.Join(s.workDir, filepath.FromSlash(file.Canonical))
		digest, size, err := hashRegularFile(candidate)
		if err != nil {
			return nil, err
		}
		if digest != file.SHA256 || size != file.Size {
			return nil, fmt.Errorf("canonical file %s changed after delete intent was recorded", file.Canonical)
		}
		deleted = append(deleted, file.Canonical)
	}
	return deleted, nil
}

// resetCanonicalWorktree discards only an uncommitted partial application of
// the exact journal paths. Any dirty or untracked path outside that closed set
// appeared after intent was recorded and is preserved by failing recovery.
// Staged transaction sources live outside the embedded worktree, so the exact
// intent can then be replayed from a clean index and tracked-file baseline.
func (s *Store) resetCanonicalWorktree(expected plumbing.Hash, journal *transactionJournal) error {
	repository, err := s.ensureRepository()
	if err != nil {
		return err
	}
	worktree, err := repository.Worktree()
	if err != nil {
		return err
	}
	paths, err := s.validatePartialCanonicalMutation(repository, worktree, expected, journal)
	if err != nil {
		return err
	}
	expectedTree, err := canonicalTree(repository, expected)
	if err != nil {
		return err
	}
	for _, canonical := range paths {
		entry, exists, err := treeBlobEntry(expectedTree, canonical)
		if err != nil {
			return err
		}
		candidate := filepath.Join(s.workDir, filepath.FromSlash(canonical))
		if !exists {
			if err := os.Remove(candidate); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		}
		reader, err := s.OpenPathAt(expected, canonical)
		if err != nil {
			return err
		}
		mode, err := entry.Mode.ToOSFileMode()
		if err != nil {
			_ = reader.Close()
			return err
		}
		if err := os.MkdirAll(filepath.Dir(candidate), 0o755); err != nil {
			_ = reader.Close()
			return err
		}
		copyErr := manifest.AtomicCopy(candidate, reader, mode.Perm())
		closeErr := reader.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
	}
	current, err := repository.Storer.Index()
	if err != nil {
		return err
	}
	remove := make(map[string]struct{}, len(paths))
	for _, canonical := range paths {
		remove[canonical] = struct{}{}
	}
	entries := current.Entries[:0]
	for _, entry := range current.Entries {
		if _, owned := remove[entry.Name]; !owned {
			entries = append(entries, entry)
		}
	}
	for _, canonical := range paths {
		entry, exists, err := treeBlobEntry(expectedTree, canonical)
		if err != nil {
			return err
		}
		if exists {
			entries = append(entries, &index.Entry{Name: canonical, Hash: entry.Hash, Mode: entry.Mode})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	current.Entries = entries
	current.Cache = nil
	if current.Version == 0 {
		current.Version = 2
	}
	if err := repository.Storer.SetIndex(current); err != nil {
		return err
	}
	if err := s.requireCanonicalWorktreeMatchesHead(); err != nil {
		return fmt.Errorf("canonical worktree remains dirty after journal-scoped reset: %w", err)
	}
	return nil
}

func (s *Store) validatePartialCanonicalMutation(repository *git.Repository, worktree *git.Worktree, expected plumbing.Hash, journal *transactionJournal) ([]string, error) {
	allowed := make(map[string]journalFile, len(journal.Files))
	paths := make([]string, 0, len(journal.Files))
	for _, file := range journal.Files {
		allowed[file.Canonical] = file
		paths = append(paths, file.Canonical)
	}
	status, err := worktree.Status()
	if err != nil {
		return nil, err
	}
	for name := range status {
		name = filepath.ToSlash(name)
		if _, owned := allowed[name]; !owned {
			return nil, fmt.Errorf("%w: canonical state path %s changed after transaction intent", ErrRefConflict, name)
		}
	}

	currentIndex, err := repository.Storer.Index()
	if err != nil {
		return nil, err
	}
	expectedTree, err := canonicalTree(repository, expected)
	if err != nil {
		return nil, err
	}
	if err := s.validateCanonicalTrackedModes(expectedTree, allowed); err != nil {
		return nil, err
	}
	for _, file := range journal.Files {
		baselineEntry, baselineExists, err := treeBlobEntry(expectedTree, file.Canonical)
		if err != nil {
			return nil, err
		}
		entry, entryErr := currentIndex.Entry(file.Canonical)
		indexExists := entryErr == nil
		if entryErr != nil && !errors.Is(entryErr, index.ErrEntryNotFound) {
			return nil, fmt.Errorf("inspect canonical index entry %s: %w", file.Canonical, entryErr)
		}
		indexAllowed := !indexExists && (!baselineExists || file.Delete) ||
			indexExists && baselineExists && entry.Hash == baselineEntry.Hash && entry.Mode == baselineEntry.Mode
		if !file.Delete && indexExists {
			desiredHash, err := journalGitBlobHash(filepath.Join(s.stateDir, filepath.FromSlash(file.Staged)), file.Size, file.SHA256)
			if err != nil {
				return nil, err
			}
			desiredMode := filemode.Regular
			baselineIsDesired := false
			if baselineExists {
				baselineIsDesired, err = s.canonicalBlobMatches(expected, file.Canonical, file.Size, file.SHA256)
				if err != nil {
					return nil, err
				}
			}
			if baselineIsDesired {
				desiredMode = baselineEntry.Mode
			}
			indexAllowed = indexAllowed || entry.Hash == desiredHash && entry.Mode == desiredMode
		}
		if !indexAllowed {
			return nil, fmt.Errorf("%w: canonical state index for %s changed outside transaction intent", ErrRefConflict, file.Canonical)
		}
		if err := s.validatePartialCanonicalFile(expected, file, baselineEntry, baselineExists); err != nil {
			return nil, err
		}
	}
	return paths, nil
}

func canonicalTree(repository *git.Repository, expected plumbing.Hash) (*object.Tree, error) {
	if expected.IsZero() {
		return nil, nil
	}
	commit, err := repository.CommitObject(expected)
	if err != nil {
		return nil, err
	}
	return commit.Tree()
}

func treeBlobEntry(tree *object.Tree, canonical string) (*object.TreeEntry, bool, error) {
	if tree == nil {
		return nil, false, nil
	}
	entry, err := tree.FindEntry(canonical)
	if errors.Is(err, object.ErrFileNotFound) || errors.Is(err, object.ErrDirectoryNotFound) || errors.Is(err, object.ErrEntryNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !entry.Mode.IsFile() || entry.Mode == filemode.Symlink {
		return nil, false, fmt.Errorf("canonical baseline path %s is not a regular file", canonical)
	}
	return entry, true, nil
}

func journalGitBlobHash(filename string, size int64, digest string) (plumbing.Hash, error) {
	before, err := os.Lstat(filename)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() != size {
		return plumbing.ZeroHash, errors.Join(err, errors.New("staged transaction file changed after intent"))
	}
	file, err := os.Open(filename)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		_ = file.Close()
		return plumbing.ZeroHash, errors.Join(err, errors.New("staged transaction file changed while opening"))
	}
	gitHasher := plumbing.NewHasher(plumbing.BlobObject, size)
	shaHasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(gitHasher, shaHasher), file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return plumbing.ZeroHash, errors.Join(copyErr, closeErr)
	}
	after, err := os.Lstat(filename)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !os.SameFile(opened, after) || before.Mode() != after.Mode() || written != size || hex.EncodeToString(shaHasher.Sum(nil)) != digest {
		return plumbing.ZeroHash, errors.Join(err, errors.New("staged transaction file changed after intent"))
	}
	return gitHasher.Sum(), nil
}

func (s *Store) validatePartialCanonicalFile(expected plumbing.Hash, file journalFile, baselineEntry *object.TreeEntry, baselineExists bool) error {
	candidate := filepath.Join(s.workDir, filepath.FromSlash(file.Canonical))
	before, statErr := s.canonicalWorktreeFileInfo(file.Canonical)
	if errors.Is(statErr, os.ErrNotExist) {
		return nil
	}
	if statErr != nil {
		return fmt.Errorf("%w: inspect canonical recovery path %s: %v", ErrRefConflict, file.Canonical, statErr)
	}
	digest, size, err := hashRegularFile(candidate)
	if err != nil {
		return fmt.Errorf("%w: inspect canonical recovery path %s: %v", ErrRefConflict, file.Canonical, err)
	}
	after, statErr := s.canonicalWorktreeFileInfo(file.Canonical)
	if statErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return fmt.Errorf("%w: canonical recovery path %s changed while validating", ErrRefConflict, file.Canonical)
	}
	if file.Delete {
		if digest == file.SHA256 && size == file.Size && baselineExists && canonicalFileModeMatches(after.Mode(), baselineEntry.Mode) {
			return nil
		}
		return fmt.Errorf("%w: canonical delete path %s changed after transaction intent", ErrRefConflict, file.Canonical)
	}
	desiredMode := filemode.Regular
	if baselineExists {
		baselineIsDesired, matchErr := s.canonicalBlobMatches(expected, file.Canonical, file.Size, file.SHA256)
		if matchErr != nil {
			return matchErr
		}
		if baselineIsDesired {
			desiredMode = baselineEntry.Mode
		}
	}
	if digest == file.SHA256 && size == file.Size && canonicalFileModeMatches(after.Mode(), desiredMode) {
		return nil
	}
	if expected.IsZero() || !baselineExists || !canonicalFileModeMatches(after.Mode(), baselineEntry.Mode) {
		return fmt.Errorf("%w: canonical install path %s changed after transaction intent", ErrRefConflict, file.Canonical)
	}
	reader, err := s.OpenPathAt(expected, file.Canonical)
	if errors.Is(err, object.ErrFileNotFound) {
		return fmt.Errorf("%w: canonical install path %s changed after transaction intent", ErrRefConflict, file.Canonical)
	}
	if err != nil {
		return err
	}
	hasher := sha256.New()
	baselineSize, copyErr := io.Copy(hasher, reader)
	closeErr := reader.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	if baselineSize == size && hex.EncodeToString(hasher.Sum(nil)) == digest {
		return nil
	}
	return fmt.Errorf("%w: canonical install path %s changed after transaction intent", ErrRefConflict, file.Canonical)
}

func canonicalFileModeMatches(mode os.FileMode, gitMode filemode.FileMode) bool {
	expected, err := gitMode.ToOSFileMode()
	return err == nil && mode.IsRegular() && mode.Perm() == expected.Perm() && mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func (s *Store) requireCanonicalWorktreeMatchesCommit(repository *git.Repository, commitHash plumbing.Hash) error {
	worktree, err := repository.Worktree()
	if err != nil {
		return err
	}
	status, err := worktree.Status()
	if err != nil {
		return err
	}
	if !status.IsClean() {
		return fmt.Errorf("%w: canonical worktree/index changed after transaction commit", ErrRefConflict)
	}
	commit, err := repository.CommitObject(commitHash)
	if err != nil {
		return err
	}
	tree, err := commit.Tree()
	if err != nil {
		return err
	}
	return s.validateCanonicalTrackedModes(tree, nil)
}

// validateCanonicalTrackedModes closes a gap in go-git's status model: Git
// records only the executable bit, so changes such as 0644 -> 0600 otherwise
// look clean. Journal-owned paths are validated separately because a crash may
// legitimately leave them at either the baseline or intended mode.
func (s *Store) validateCanonicalTrackedModes(tree *object.Tree, exempt map[string]journalFile) error {
	if tree == nil {
		return nil
	}
	files := tree.Files()
	defer files.Close()
	return files.ForEach(func(file *object.File) error {
		if _, owned := exempt[file.Name]; owned {
			return nil
		}
		info, err := s.canonicalWorktreeFileInfo(file.Name)
		if err != nil || !canonicalFileModeMatches(info.Mode(), file.Mode) {
			return fmt.Errorf("%w: canonical state path %s type or permissions changed after transaction intent", ErrRefConflict, file.Name)
		}
		return nil
	})
}

func (s *Store) canonicalWorktreeFileInfo(canonical string) (os.FileInfo, error) {
	if err := validateStatePath(canonical); err != nil {
		return nil, err
	}
	current := s.workDir
	parts := strings.Split(canonical, "/")
	for index, part := range parts {
		current = filepath.Join(current, filepath.FromSlash(part))
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if index != len(parts)-1 {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return nil, fmt.Errorf("canonical state directory %s is not a real directory", strings.Join(parts[:index+1], "/"))
			}
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("canonical state path %s is not a regular non-symlink file", canonical)
		}
		return info, nil
	}
	return nil, os.ErrNotExist
}

// commitExactlyAppliesJournal recognizes the narrow crash window after Git
// committed the transaction but before the intent journal advanced. The
// candidate must be the transaction's direct child (or the initial root
// commit), contain every desired journal path with the fixed canonical mode,
// and have no tree change outside the journal's effective change set.
func (s *Store) commitExactlyAppliesJournal(repository *git.Repository, candidate, expected plumbing.Hash, journal *transactionJournal) (bool, error) {
	commit, err := repository.CommitObject(candidate)
	if err != nil {
		return false, err
	}
	if expected.IsZero() {
		if len(commit.ParentHashes) != 0 {
			return false, nil
		}
	} else if len(commit.ParentHashes) != 1 || commit.ParentHashes[0] != expected {
		return false, nil
	}
	beforeTree, err := canonicalTree(repository, expected)
	if err != nil {
		return false, err
	}
	afterTree, err := commit.Tree()
	if err != nil {
		return false, err
	}
	expectedChanges := make(map[string]struct{}, len(journal.Files))
	for _, file := range journal.Files {
		beforeEntry, beforeExists, err := treeBlobEntry(beforeTree, file.Canonical)
		if err != nil {
			return false, err
		}
		afterEntry, afterExists, err := treeBlobEntry(afterTree, file.Canonical)
		if err != nil {
			return false, err
		}
		if file.Delete {
			if !beforeExists || afterExists {
				return false, nil
			}
			matches, err := s.canonicalBlobMatches(expected, file.Canonical, file.Size, file.SHA256)
			if err != nil || !matches {
				return false, err
			}
			expectedChanges[file.Canonical] = struct{}{}
			continue
		}
		afterMatches, err := s.canonicalBlobMatches(candidate, file.Canonical, file.Size, file.SHA256)
		if err != nil || !afterMatches {
			return false, err
		}
		beforeMatches := false
		if beforeExists {
			beforeMatches, err = s.canonicalBlobMatches(expected, file.Canonical, file.Size, file.SHA256)
			if err != nil {
				return false, err
			}
		}
		desiredMode := filemode.Regular
		if beforeMatches {
			desiredMode = beforeEntry.Mode
		}
		if !afterExists || afterEntry.Mode != desiredMode {
			return false, nil
		}
		if !beforeExists || !beforeMatches || beforeEntry.Mode != desiredMode {
			expectedChanges[file.Canonical] = struct{}{}
		}
	}
	changes, err := object.DiffTree(beforeTree, afterTree)
	if err != nil || len(changes) != len(expectedChanges) {
		return false, err
	}
	for _, change := range changes {
		name := change.To.Name
		if name == "" {
			name = change.From.Name
		}
		if _, expected := expectedChanges[name]; !expected {
			return false, nil
		}
	}
	return true, nil
}

func (s *Store) canonicalBlobMatches(commit plumbing.Hash, canonical string, size int64, digest string) (bool, error) {
	reader, err := s.OpenPathAt(commit, canonical)
	if err != nil {
		return false, err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, reader)
	closeErr := reader.Close()
	if copyErr != nil || closeErr != nil {
		return false, errors.Join(copyErr, closeErr)
	}
	return written == size && hex.EncodeToString(hasher.Sum(nil)) == digest, nil
}

func validateJournal(journal *transactionJournal) error {
	if journal == nil || journal.Schema != transactionSchema {
		return errors.New("unsupported or nil transaction journal")
	}
	if err := validateTransactionID(journal.ID); err != nil {
		return err
	}
	if err := validateOperation(journal.Operation); err != nil {
		return err
	}
	switch journal.Phase {
	case "intent", "committed", "complete", "aborted":
	default:
		return fmt.Errorf("invalid transaction phase %q", journal.Phase)
	}
	if len(journal.Files) == 0 {
		return errors.New("transaction journal has no files")
	}
	if len(journal.ExpectedHead) != 40 || !isLowerHex(journal.ExpectedHead) {
		return errors.New("transaction journal has invalid expected HEAD")
	}
	if journal.Phase == "committed" || journal.Phase == "complete" {
		if len(journal.Commit) != 40 || !isLowerHex(journal.Commit) || journal.Commit == plumbing.ZeroHash.String() {
			return errors.New("transaction journal has invalid commit")
		}
	}
	for _, file := range journal.Files {
		if err := validateStatePath(file.Canonical); err != nil {
			return err
		}
		if file.Delete {
			if file.Staged != "" {
				return errors.New("transaction journal deletion has a staged path")
			}
		} else {
			if err := validateStatePath(file.Staged); err != nil {
				return err
			}
		}
		if file.Size < 0 || len(file.SHA256) != sha256.Size*2 || !isLowerHex(file.SHA256) {
			return errors.New("transaction journal has invalid staged evidence")
		}
	}
	for index := 1; index < len(journal.Files); index++ {
		if journal.Files[index-1].Canonical >= journal.Files[index].Canonical {
			return errors.New("transaction journal canonical paths are not strictly sorted")
		}
	}
	for _, ref := range journal.Refs {
		if err := validateSOWRef(plumbing.ReferenceName(ref.Name)); err != nil {
			return err
		}
		if len(ref.Expected) != 40 || !isLowerHex(ref.Expected) {
			return errors.New("transaction journal has invalid expected ref hash")
		}
		if len(ref.Target) != 40 || !isLowerHex(ref.Target) {
			return errors.New("transaction journal has invalid target ref hash")
		}
		if ref.Delete {
			if ref.Expected == plumbing.ZeroHash.String() || ref.Target != plumbing.ZeroHash.String() || ref.Immutable {
				return errors.New("transaction journal has invalid ref deletion")
			}
		} else if (journal.Phase == "committed" || journal.Phase == "complete") && ref.Target == plumbing.ZeroHash.String() {
			return errors.New("committed transaction journal has unresolved target ref hash")
		}
	}
	return nil
}

func validateTransactionID(value string) error {
	if len(value) != 32 || !isLowerHex(value) {
		return errors.New("invalid transaction ID")
	}
	return nil
}

func validateOperation(value string) error {
	if value == "" || len(value) > 64 || strings.ContainsAny(value, "\x00\t\r\n/\\") {
		return fmt.Errorf("unsafe transaction operation %q", value)
	}
	return nil
}

func transactionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func hashRegularFile(path string) (string, int64, error) {
	beforePath, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if beforePath.Mode()&os.ModeSymlink != 0 || !beforePath.Mode().IsRegular() {
		return "", 0, fmt.Errorf("staged file %q is not a regular non-symlink", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return "", 0, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(beforePath, info) {
		file.Close()
		return "", 0, fmt.Errorf("staged file %q is not regular", path)
	}
	hasher := sha256.New()
	size, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return "", 0, errors.Join(copyErr, closeErr)
	}
	if size != info.Size() {
		return "", 0, fmt.Errorf("staged file %q changed while hashing", path)
	}
	after, err := os.Lstat(path)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return "", 0, fmt.Errorf("staged file %q changed while hashing", path)
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func syncStateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}
