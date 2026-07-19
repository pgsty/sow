package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ParentExpectation struct {
	Exists           bool
	Generation       uint64
	CheckpointSHA256 string
	ETag             string
}

type Request struct {
	TransactionID string
	Generation    TargetGeneration
	Plan          Plan
	Expected      ParentExpectation
	UpdatedAt     time.Time
}

type Hooks struct {
	// AfterPhase runs only after the phase has been durably journaled. It is a
	// deterministic crash/fault injection point; production leaves it nil.
	AfterPhase func(target TargetName, phase Phase) error
}

// TrustBoundary identifies publication commit points whose authorization must
// still match the immutable trust snapshot constructed with the exact target
// ref vector. The publish package deliberately knows nothing about OpenPGP or
// repository configuration; callers supply a TrustGuard that revalidates
// their policy inputs at these serial saga boundaries.
type TrustBoundary string

const (
	TrustBeforeRemoteMutation TrustBoundary = "before-remote-mutation"
	TrustBeforePointerFlip    TrustBoundary = "before-pointer-flip"
	TrustAfterPointerFlip     TrustBoundary = "after-pointer-flip"
	TrustBeforeCheckpoint     TrustBoundary = "before-checkpoint-commit"
	TrustAfterCheckpoint      TrustBoundary = "after-checkpoint-commit"
	TrustBeforeLocalPersist   TrustBoundary = "before-local-persist"
	TrustAfterLocalPersist    TrustBoundary = "after-local-persist"
)

type TrustGuard func(target TargetName, boundary TrustBoundary) error

type Result struct {
	Target              TargetName
	Generation          uint64
	GenerationSHA256    string
	CheckpointSHA256    string
	CheckpointETag      string
	Phase               Phase
	JournalPath         string
	PurgeEvidencePath   string
	PurgeEvidenceSHA256 string
	RemoteRefReady      bool
	RefVector           []RefState
}

type Publisher struct {
	target                 TargetName
	source                 Source
	journal                journalStore
	hooks                  Hooks
	trust                  TrustGuard
	driver                 targetDriver
	workers                int
	requirePurgeEvidence   bool
	checkpointFencedDelete bool
}

const defaultPublishWorkers = 8
const maxPublishWorkers = 64

var errConditionalDeleteDemonstrablyUnsupported = errors.New("conditional DeleteObject demonstrably ignores If-Match")

func NewR2CloudflarePublisher(provider R2CloudflareProvider, source Source, journalDir string, hooks Hooks) *Publisher {
	return &Publisher{
		target: TargetCloudflare, source: source,
		journal: journalStore{dir: journalDir}, hooks: hooks,
		driver:  r2Driver{provider: provider},
		workers: defaultPublishWorkers,
	}
}

func NewCOSEdgeOnePublisher(provider COSEdgeOneProvider, source Source, journalDir string, hooks Hooks) *Publisher {
	return &Publisher{
		target: TargetTencent, source: source,
		journal: journalStore{dir: journalDir}, hooks: hooks,
		driver:  cosDriver{provider: provider},
		workers: defaultPublishWorkers,
	}
}

// WithWorkers returns a publisher configured with a bounded upload worker
// pool. Mutable commit points are deliberately excluded from the pool and
// remain serial. Run rejects non-positive values so callers cannot silently
// disable progress.
func (p *Publisher) WithWorkers(workers int) *Publisher {
	if p == nil {
		return nil
	}
	configured := *p
	configured.workers = workers
	return &configured
}

// WithRequiredPurgeEvidence makes publication fail closed unless the concrete
// vendor provider can return and durably bind an operational receipt for every
// exact-URL purge batch.  It is enabled by the real CLI; legacy embedders and
// narrow unit fakes retain the historical error-only provider interface.
func (p *Publisher) WithRequiredPurgeEvidence() *Publisher {
	if p == nil {
		return nil
	}
	configured := *p
	configured.requirePurgeEvidence = true
	return &configured
}

// WithCheckpointFencedDeletion enables the explicit single-writer fallback
// for providers whose DeleteObject operation cannot enforce If-Match. It is
// intentionally opt-in: callers must first retire every legacy writer. The
// publisher still requires the remote publication fence (R2 checkpoint or COS
// generation lock), repeats the complete streamed identity proof immediately
// before DELETE, and verifies both origin absence and the unchanged fence
// afterwards.
func (p *Publisher) WithCheckpointFencedDeletion() *Publisher {
	if p == nil {
		return nil
	}
	configured := *p
	configured.checkpointFencedDelete = true
	return &configured
}

// WithTrustGuard returns a publisher that revalidates the caller's immutable
// trust snapshot at every serial remote commit boundary. A nil guard preserves
// the generic package behavior for callers with no external trust policy.
func (p *Publisher) WithTrustGuard(guard TrustGuard) *Publisher {
	if p == nil {
		return nil
	}
	configured := *p
	configured.trust = guard
	return &configured
}

func (p *Publisher) requireTrust(boundary TrustBoundary) error {
	if p == nil || p.trust == nil {
		return nil
	}
	if err := p.trust(p.target, boundary); err != nil {
		return fmt.Errorf("publication trust rejected at %s: %w", boundary, err)
	}
	return nil
}

func (p *Publisher) Run(ctx context.Context, request Request) (result Result, resultErr error) {
	result = Result{Generation: request.Generation.Generation, Phase: PhasePlanned}
	if ctx == nil {
		return result, errors.New("publish: nil context")
	}
	if p == nil {
		return result, errors.New("publish target, provider, and source are required")
	}
	result.Target = p.target
	if p.driver == nil || p.source == nil {
		return result, errors.New("publish target, provider, and source are required")
	}
	if p.workers < 1 || p.workers > maxPublishWorkers {
		return result, fmt.Errorf("publish worker count must be between 1 and %d", maxPublishWorkers)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := p.validateRequest(request); err != nil {
		return result, err
	}
	if err := p.driver.preflight(ctx, request.Plan); err != nil {
		return result, fmt.Errorf("publish provider preflight: %w", err)
	}
	if err := p.requirePurgeEvidenceCapability(request.Plan); err != nil {
		return result, err
	}
	releaseJournal, err := p.journal.acquire(ctx, p.target, request.TransactionID)
	if err != nil {
		return result, err
	}
	defer propagateJournalUnlock(releaseJournal, &resultErr)
	normalizedPlan, err := request.Plan.normalized()
	if err != nil {
		return result, err
	}
	request.Plan = normalizedPlan
	generationBody, err := request.Generation.Canonical()
	if err != nil {
		return result, err
	}
	generationSHA := digestBytes(generationBody)
	result.GenerationSHA256 = generationSHA
	planSHA, err := request.Plan.Digest()
	if err != nil {
		return result, err
	}
	lockedCheckpoint, err := NewCheckpoint(request.Generation, request.TransactionID, planSHA, PhaseLocked, request.UpdatedAt)
	if err != nil {
		return result, err
	}
	lockedBody, err := lockedCheckpoint.Canonical()
	if err != nil {
		return result, err
	}
	finalCheckpoint, err := NewCheckpoint(request.Generation, request.TransactionID, planSHA, PhaseCheckpointCommitted, request.UpdatedAt)
	if err != nil {
		return result, err
	}
	finalBody, err := finalCheckpoint.Canonical()
	if err != nil {
		return result, err
	}
	result.CheckpointSHA256 = digestBytes(finalBody)

	journal, created, journalPath, err := p.journal.loadOrCreate(request, generationSHA, planSHA, result.CheckpointSHA256)
	result.JournalPath = journalPath
	if err != nil {
		return result, err
	}
	generationKey, _ := GenerationKey(request.Generation.Generation)
	if err := validateJournalPlan(journal, request.Plan, generationKey); err != nil {
		return result, err
	}
	// Adopted immutable objects are must-exist assertions, not uploads. Verify
	// their origin bytes on every invocation before acquiring or mutating the
	// remote checkpoint. replay=true deliberately ignores journal completion:
	// a durable local bit cannot prove that a foreign actor kept the object.
	if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectAdoptedImmutable), true, true); err != nil {
		return result, err
	}
	result.Phase = journal.Phase
	if created {
		if err := p.afterPhase(PhasePlanned); err != nil {
			return result, err
		}
	}
	if err := p.requireTrust(TrustBeforeRemoteMutation); err != nil {
		return result, err
	}
	checkpointFencedDelete, err := p.selectDeletionMode(ctx, request.TransactionID, request.Plan.Deletes)
	if err != nil {
		return result, err
	}

	lockToken, alreadyCommitted, err := p.driver.acquire(ctx, request, generationSHA, lockedBody, finalBody)
	if err != nil {
		return result, err
	}
	if alreadyCommitted {
		if lockToken == "" {
			return result, fmt.Errorf("%w: committed checkpoint has no ETag", ErrCapability)
		}
		if err := p.requireTrust(TrustAfterCheckpoint); err != nil {
			return result, err
		}
		result.CheckpointETag = lockToken
		replaysMutableClosure := len(request.Plan.objects(ObjectLegacyMetadata))+len(request.Plan.objects(ObjectYUMAliasMetadata))+
			len(request.Plan.objects(ObjectYUMAliasPointer))+len(request.Plan.objects(ObjectCompatibilityRollbackMetadata))+
			len(request.Plan.objects(ObjectCompatibilityRollbackPointer))+len(request.Plan.objects(ObjectPointer))+len(request.Plan.Deletes) != 0
		if replaysMutableClosure {
			if err := p.requireTrust(TrustBeforePointerFlip); err != nil {
				return result, err
			}
		}
		// The final checkpoint establishes transaction ownership, not continued
		// integrity of mutable serving keys. A crash immediately after checkpoint
		// commit can leave the local journal behind, and a later operator/provider
		// fault can remove or corrupt an alias without changing that checkpoint.
		// Replay the complete ordered mutable closure before purge+verification so
		// an already-committed retry is a repair operation rather than a permanent
		// verification failure. The writes remain O(the persisted change set).
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectLegacyMetadata), false, true); err != nil {
			return result, err
		}
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectYUMAliasMetadata), false, true); err != nil {
			return result, err
		}
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectCompatibilityRollbackMetadata), false, true); err != nil {
			return result, err
		}
		for _, object := range orderedYUMAliasPointers(request.Plan) {
			if err := p.uploadPlanned(ctx, journalPath, journal, object, false, true); err != nil {
				return result, err
			}
		}
		for _, object := range request.Plan.objects(ObjectCompatibilityRollbackPointer) {
			if err := p.uploadPlanned(ctx, journalPath, journal, object, false, true); err != nil {
				return result, err
			}
		}
		for _, object := range request.Plan.objects(ObjectPointer) {
			if err := p.uploadPlanned(ctx, journalPath, journal, object, false, true); err != nil {
				return result, err
			}
		}
		deleteFenceToken := lockToken
		journalFenceToken := lockToken
		// COS acquire returns the final checkpoint ETag for an already-committed
		// replay, while checkpoint-fenced deletion is admitted by the original
		// create-only generation lock. Preserve and reuse the durable journal
		// token when it exists; a lost journal remains safely unrecoverable rather
		// than manufacturing a generation-lock token from a checkpoint ETag.
		if p.target == TargetTencent && journal.LockToken != "" {
			deleteFenceToken = journal.LockToken
			journalFenceToken = journal.LockToken
		}
		if len(request.Plan.Deletes) != 0 {
			if err := p.deletePlanned(ctx, journalPath, journal, request.Plan.Deletes, true, deleteFenceToken, checkpointFencedDelete); err != nil {
				return result, err
			}
		}
		// A committed checkpoint does not prove that every CDN retained the
		// purge. Re-issue the plan's exact, normalization-validated closure so
		// replay repairs both client routes and internal clean-cache keys. This
		// is deliberately the complete plan set: pointer and deletion purges are
		// idempotent, while purging only VerifyAbsent URLs omits routed .sow keys.
		if len(request.Plan.PurgeURLs) != 0 {
			if err := p.purgeAndRecord(ctx, request, &result, generationSHA, planSHA, result.CheckpointSHA256,
				request.Plan.PurgeURLs, PurgeAttemptFull, true); err != nil {
				return result, fmt.Errorf("replay committed purge closure: %w", err)
			}
		}
		if replaysMutableClosure {
			if err := p.requireTrust(TrustAfterPointerFlip); err != nil {
				return result, err
			}
		}
		// A crash may occur after the remote checkpoint write and before the
		// local journal update. The checkpoint proves all preceding phases ran;
		// repair/verify the immutable generation and verify through the CDN once
		// more before making the local ref ready. A checkpoint alone is not proof
		// that a foreign actor did not remove its generation document.
		generationKey, _ := GenerationKey(request.Generation.Generation)
		if err := p.requireTrust(TrustBeforeRemoteMutation); err != nil {
			return result, err
		}
		if err := p.ensureTargetGeneration(ctx, generationKey, generationBody, generationSHA); err != nil {
			return result, fmt.Errorf("verify committed target generation: %w", err)
		}
		if err := p.requireTrust(TrustAfterCheckpoint); err != nil {
			return result, err
		}
		if err := p.verify(ctx, positiveVerificationExpectations(request.Plan)); err != nil {
			return result, err
		}
		if err := p.verifyDeletionClosure(ctx, request.Plan.Deletes, request.Plan.VerifyAbsent); err != nil {
			return result, err
		}
		if !phaseAtLeast(journal.Phase, PhaseCheckpointCommitted) {
			if err := p.journal.advance(journalPath, journal, PhaseCheckpointCommitted, journalFenceToken); err != nil {
				return result, err
			}
		}
		result.Phase = PhaseCheckpointCommitted
		if err := p.requireTrust(TrustAfterCheckpoint); err != nil {
			return result, err
		}
		return p.finishRemoteRef(result, journalPath, journal, request.Generation)
	}
	if lockToken == "" {
		return result, errors.New("provider returned an empty publish lock token")
	}
	if phaseAtLeast(journal.Phase, PhaseCheckpointCommitted) {
		return result, fmt.Errorf("%w: local journal says checkpoint committed but remote checkpoint is not final", ErrDrift)
	}
	if !phaseAtLeast(journal.Phase, PhaseLocked) {
		if err := p.journal.advance(journalPath, journal, PhaseLocked, lockToken); err != nil {
			return result, err
		}
		result.Phase = PhaseLocked
		if err := p.afterPhase(PhaseLocked); err != nil {
			return result, err
		}
	} else if journal.LockToken != "" && journal.LockToken != lockToken {
		return result, fmt.Errorf("%w: remote lock token changed", ErrDrift)
	}

	// A durable phase means the corresponding remote side effects completed at
	// least once, not that a foreign actor could not remove them afterward.
	// Interrupted recovery therefore replays the already-finished closure in
	// dependency order before trusting a mutable pointer. Calls remain bounded
	// by the original change set and are idempotent by provider contract.
	if !created && phaseAtLeast(journal.Phase, PhaseImmutableUploaded) {
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectImmutable), true, true); err != nil {
			return result, err
		}
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectCopyImmutable), true, true); err != nil {
			return result, err
		}
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectReuseImmutable), true, true); err != nil {
			return result, err
		}
	}
	if !created && phaseAtLeast(journal.Phase, PhaseGenerationReady) {
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectMetadata), true, true); err != nil {
			return result, err
		}
		if err := p.ensureTargetGeneration(ctx, generationKey, generationBody, generationSHA); err != nil {
			return result, fmt.Errorf("repair target generation during recovery: %w", err)
		}
	}
	// loadOrCreate returning an existing journal means an earlier invocation may
	// have durably recorded only part of the stage whose phase marker is still
	// pending. A CompletedObjects bit is progress, not remote integrity proof:
	// recovery must replay those completed members together with the remaining
	// stage before any mutable commit point can advance.
	replayInterruptedStage := !created
	replayedMutableClosure := false
	if !created && phaseAtLeast(journal.Phase, PhasePointerFlipped) {
		if err := p.requireTrust(TrustBeforePointerFlip); err != nil {
			return result, err
		}
		replayedMutableClosure = len(request.Plan.objects(ObjectLegacyMetadata))+len(request.Plan.objects(ObjectYUMAliasMetadata))+
			len(request.Plan.objects(ObjectYUMAliasPointer))+len(request.Plan.objects(ObjectCompatibilityRollbackMetadata))+
			len(request.Plan.objects(ObjectCompatibilityRollbackPointer))+len(request.Plan.objects(ObjectPointer))+len(request.Plan.Deletes) != 0
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectLegacyMetadata), false, true); err != nil {
			return result, err
		}
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectYUMAliasMetadata), false, true); err != nil {
			return result, err
		}
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectCompatibilityRollbackMetadata), false, true); err != nil {
			return result, err
		}
		for _, object := range orderedYUMAliasPointers(request.Plan) {
			if err := p.uploadPlanned(ctx, journalPath, journal, object, false, true); err != nil {
				return result, err
			}
		}
		for _, object := range request.Plan.objects(ObjectCompatibilityRollbackPointer) {
			if err := p.uploadPlanned(ctx, journalPath, journal, object, false, true); err != nil {
				return result, err
			}
		}
		for _, object := range request.Plan.objects(ObjectPointer) {
			if err := p.uploadPlanned(ctx, journalPath, journal, object, false, true); err != nil {
				return result, err
			}
		}
		if len(request.Plan.Deletes) != 0 {
			if err := p.deletePlanned(ctx, journalPath, journal, request.Plan.Deletes, true, lockToken, checkpointFencedDelete); err != nil {
				return result, err
			}
			if phaseAtLeast(journal.Phase, PhasePurged) {
				if urls := absenceVerificationURLs(request.Plan.VerifyAbsent); len(urls) != 0 {
					if err := p.purgeAndRecord(ctx, request, &result, generationSHA, planSHA, result.CheckpointSHA256,
						urls, PurgeAttemptDeletionRepair, true); err != nil {
						return result, fmt.Errorf("replay deletion purge: %w", err)
					}
				}
			}
		}
		if err := p.requireTrust(TrustAfterPointerFlip); err != nil {
			return result, err
		}
	}

	if !phaseAtLeast(journal.Phase, PhaseImmutableUploaded) {
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectImmutable), true, replayInterruptedStage); err != nil {
			return result, err
		}
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectCopyImmutable), true, replayInterruptedStage); err != nil {
			return result, err
		}
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectReuseImmutable), true, replayInterruptedStage); err != nil {
			return result, err
		}
		if err := p.journal.advance(journalPath, journal, PhaseImmutableUploaded, lockToken); err != nil {
			return result, err
		}
		result.Phase = PhaseImmutableUploaded
		if err := p.afterPhase(PhaseImmutableUploaded); err != nil {
			return result, err
		}
	}

	if !phaseAtLeast(journal.Phase, PhaseGenerationReady) {
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectMetadata), true, replayInterruptedStage); err != nil {
			return result, err
		}
		if err := p.ensureTargetGeneration(ctx, generationKey, generationBody, generationSHA); err != nil {
			return result, fmt.Errorf("upload target generation: %w", err)
		}
		if !journalHas(journal, "generation:"+generationKey) {
			if err := p.journal.completeObject(journalPath, journal, "generation:"+generationKey); err != nil {
				return result, err
			}
		}
		if err := p.journal.advance(journalPath, journal, PhaseGenerationReady, lockToken); err != nil {
			return result, err
		}
		result.Phase = PhaseGenerationReady
		if err := p.afterPhase(PhaseGenerationReady); err != nil {
			return result, err
		}
	} else {
		if err := p.ensureTargetGeneration(ctx, generationKey, generationBody, generationSHA); err != nil {
			return result, fmt.Errorf("verify target generation during recovery: %w", err)
		}
	}

	if !phaseAtLeast(journal.Phase, PhasePointerFlipped) {
		if err := p.requireTrust(TrustBeforePointerFlip); err != nil {
			return result, err
		}
		// APT's legacy Packages*/Release* aliases are mutable, but they are
		// never the commit point. They must be installed before the sole signed
		// InRelease pointer. Modern apt clients remain coherent through the
		// already-uploaded by-hash closure; the unavoidable apt<1.2 limitation
		// is tracked as a compatibility gate rather than hidden in ordering.
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectLegacyMetadata), false, replayInterruptedStage); err != nil {
			return result, err
		}
		// Legacy YUM aliases preserve existing raw baseurls. Non-pointer
		// repodata is installed first, followed by each signed pair in the
		// strict repomd.xml.asc -> repomd.xml commit order.
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectYUMAliasMetadata), false, replayInterruptedStage); err != nil {
			return result, err
		}
		// Exact S0 rollback has an unsigned repomd.xml. Install all frozen
		// repodata first, then that single legacy commit point.
		if err := p.uploadStage(ctx, journalPath, journal, request.Plan.objects(ObjectCompatibilityRollbackMetadata), false, replayInterruptedStage); err != nil {
			return result, err
		}
		for _, object := range orderedYUMAliasPointers(request.Plan) {
			if err := p.uploadPlanned(ctx, journalPath, journal, object, false, replayInterruptedStage); err != nil {
				return result, err
			}
		}
		for _, object := range request.Plan.objects(ObjectCompatibilityRollbackPointer) {
			if err := p.uploadPlanned(ctx, journalPath, journal, object, false, replayInterruptedStage); err != nil {
				return result, err
			}
		}
		// APT InRelease and channel objects are deterministic serial commit
		// points even when independent data uploads use a worker pool.
		for _, object := range request.Plan.objects(ObjectPointer) {
			if err := p.uploadPlanned(ctx, journalPath, journal, object, false, replayInterruptedStage); err != nil {
				return result, err
			}
		}
		if err := p.deletePlanned(ctx, journalPath, journal, request.Plan.Deletes, replayInterruptedStage, lockToken, checkpointFencedDelete); err != nil {
			return result, err
		}
		if err := p.requireTrust(TrustAfterPointerFlip); err != nil {
			return result, err
		}
		if err := p.journal.advance(journalPath, journal, PhasePointerFlipped, lockToken); err != nil {
			return result, err
		}
		result.Phase = PhasePointerFlipped
		if err := p.afterPhase(PhasePointerFlipped); err != nil {
			return result, err
		}
	}

	if !phaseAtLeast(journal.Phase, PhasePurged) || replayedMutableClosure || p.requirePurgeEvidence && len(request.Plan.PurgeURLs) != 0 {
		pointers := pointerObjects(request.Plan)
		if len(pointers)+routedDeleteCount(request.Plan.Deletes) != 0 && len(request.Plan.PurgeURLs) == 0 {
			return result, errors.New("pointer flip requires a mandatory minimal purge set")
		}
		if len(request.Plan.PurgeURLs) != 0 {
			if err := p.purgeAndRecord(ctx, request, &result, generationSHA, planSHA, result.CheckpointSHA256,
				request.Plan.PurgeURLs, PurgeAttemptFull, replayedMutableClosure); err != nil {
				return result, fmt.Errorf("mandatory CDN purge: %w", err)
			}
		}
		if !phaseAtLeast(journal.Phase, PhasePurged) {
			if err := p.journal.advance(journalPath, journal, PhasePurged, lockToken); err != nil {
				return result, err
			}
			result.Phase = PhasePurged
			if err := p.afterPhase(PhasePurged); err != nil {
				return result, err
			}
		}
	}

	if !phaseAtLeast(journal.Phase, PhaseVerified) || replayedMutableClosure {
		if len(request.Plan.Objects) != 0 && len(request.Plan.Verify) != len(request.Plan.Objects) {
			return result, errors.New("CDN verification must cover every changed object")
		}
		if err := p.verify(ctx, positiveVerificationExpectations(request.Plan)); err != nil {
			return result, err
		}
		if err := p.verifyDeletionClosure(ctx, request.Plan.Deletes, request.Plan.VerifyAbsent); err != nil {
			return result, err
		}
		if !phaseAtLeast(journal.Phase, PhaseVerified) {
			if err := p.journal.advance(journalPath, journal, PhaseVerified, lockToken); err != nil {
				return result, err
			}
			result.Phase = PhaseVerified
			if err := p.afterPhase(PhaseVerified); err != nil {
				return result, err
			}
		}
	} else if err := p.verifyDeletionClosure(ctx, request.Plan.Deletes, request.Plan.VerifyAbsent); err != nil {
		return result, err
	}

	if !phaseAtLeast(journal.Phase, PhaseCheckpointCommitted) {
		if err := p.requireTrust(TrustBeforeCheckpoint); err != nil {
			return result, err
		}
		checkpointETag, err := p.driver.commit(ctx, request, lockToken, finalBody)
		if err != nil {
			return result, err
		}
		result.CheckpointETag = checkpointETag
		if err := p.requireTrust(TrustAfterCheckpoint); err != nil {
			return result, err
		}
		if err := p.journal.advance(journalPath, journal, PhaseCheckpointCommitted, lockToken); err != nil {
			return result, err
		}
		result.Phase = PhaseCheckpointCommitted
		if err := p.afterPhase(PhaseCheckpointCommitted); err != nil {
			return result, err
		}
	}
	return p.finishRemoteRef(result, journalPath, journal, request.Generation)
}

func (p *Publisher) finishRemoteRef(
	current Result,
	journalPath string,
	journal *publishJournal,
	generation TargetGeneration,
) (Result, error) {
	if !phaseAtLeast(journal.Phase, PhaseRemoteRefReady) {
		if err := p.journal.advance(journalPath, journal, PhaseRemoteRefReady, journal.LockToken); err != nil {
			return current, err
		}
		if err := p.afterPhase(PhaseRemoteRefReady); err != nil {
			return current, err
		}
	}
	normalized, _ := generation.normalized()
	current.Phase = PhaseRemoteRefReady
	current.RemoteRefReady = true
	current.RefVector = append([]RefState(nil), normalized.Refs...)
	return current, nil
}

func (p *Publisher) validateRequest(request Request) error {
	if p.target.Validate() != nil || request.Generation.Target != p.target {
		return fmt.Errorf("generation target %q does not match publisher %q", request.Generation.Target, p.target)
	}
	if !transactionIDPat.MatchString(request.TransactionID) {
		return errors.New("invalid publish transaction ID")
	}
	if _, err := request.Generation.Canonical(); err != nil {
		return err
	}
	normalizedPlan, err := request.Plan.normalized()
	if err != nil {
		return err
	}
	if len(normalizedPlan.Objects) != 0 || len(normalizedPlan.Deletes) != 0 {
		if normalizedPlan.CDNBaseURL == "" || len(normalizedPlan.Verify) != len(normalizedPlan.Objects) || len(normalizedPlan.VerifyAbsent) != routedDeleteCount(normalizedPlan.Deletes) {
			return errors.New("publish execution requires exact CDN verification for every changed object")
		}
		// Plan normalization has already proven exact purge-set equality. An
		// internally routed .sow pointer or deletion contributes both its
		// client-facing URL and its credential-free clean cache key, so purge
		// cardinality is intentionally not equal to pointer cardinality.
	}
	for _, object := range normalizedPlan.Objects {
		format := "APT"
		match := aptGenerationKeyPattern.FindStringSubmatch(object.RemoteKey)
		if len(match) == 0 {
			format = "YUM"
			match = yumGenerationKeyPattern.FindStringSubmatch(object.RemoteKey)
		}
		if len(match) == 0 {
			continue
		}
		objectGeneration, parseErr := strconv.ParseUint(match[2], 10, 64)
		if parseErr != nil || objectGeneration != request.Generation.Generation {
			return fmt.Errorf("%s metadata key %q does not belong to target generation %d", format, object.RemoteKey, request.Generation.Generation)
		}
	}
	if err := validateIntentCDNBindings(request.Generation, normalizedPlan); err != nil {
		return err
	}
	if err := validateIntentDeletes(request.Generation, normalizedPlan.Deletes); err != nil {
		return err
	}
	if err := validateYUMAliasAtomicRoutes(request.Generation, normalizedPlan); err != nil {
		return err
	}
	// Ref vectors are cumulative target state: a later public latest publish
	// legitimately retains historical stable and snapshot refs. Confidential
	// generation namespace enforcement is therefore bound to the exact current
	// publication intent, never inferred from retained refs.
	gatedIntent := request.Generation.IntentView == "stable" || request.Generation.IntentView == "snapshot"
	if gatedIntent {
		for _, object := range normalizedPlan.Objects {
			match := yumGenerationKeyPattern.FindStringSubmatch(object.RemoteKey)
			if len(match) != 0 && match[1] == "" {
				return fmt.Errorf("stable YUM metadata %q must use the gated generation namespace", object.RemoteKey)
			}
		}
	}
	if request.UpdatedAt.IsZero() {
		return errors.New("publish request requires a stable updated_at value")
	}
	if request.Expected.Generation != request.Generation.ParentGeneration {
		return errors.New("expected checkpoint generation does not match target parent")
	}
	if request.Expected.Generation == 0 {
		if request.Expected.Exists || request.Expected.CheckpointSHA256 != "" || request.Expected.ETag != "" {
			return errors.New("initial publication cannot expect a remote checkpoint")
		}
	} else if !request.Expected.Exists || !hexSHA256Pattern.MatchString(request.Expected.CheckpointSHA256) {
		return errors.New("non-initial publication requires the canonical parent checkpoint digest")
	}
	if p.target == TargetCloudflare && request.Expected.Exists && request.Expected.ETag == "" {
		return errors.New("R2 publication requires the observed parent checkpoint ETag")
	}
	return nil
}

// validateIntentCDNBindings binds every persisted client route to the exact
// publication intent before any remote lock or object mutation. Plan-level
// validation closes namespace-local pointer aliases; this request-level pass
// supplies the stable/snapshot context that a standalone plan intentionally
// does not carry and also derives the sole supported transformed response (a
// stable dynamic YUM mirrorlist) from canonical ChannelState.
func validateIntentCDNBindings(generation TargetGeneration, plan Plan) error {
	channels := make(map[string]ChannelState, len(generation.Channels))
	snapshotRouteSeen := false
	for _, channel := range generation.Channels {
		channels[channel.RemoteKey] = channel
	}
	for _, object := range plan.Objects {
		cdnPath, _, _, err := object.cdnExpectation()
		if err != nil {
			return err
		}
		want, err := intentObjectCDNPath(generation, object.RemoteKey)
		if err != nil {
			return err
		}
		if cdnPath != want {
			return fmt.Errorf("publication intent %s binds %s to CDN path %q, got %q", generation.IntentView, object.RemoteKey, want, cdnPath)
		}
		if strings.HasPrefix(object.RemoteKey, ".sow/snapshots/") {
			snapshotRouteSeen = true
			body, bodyErr := SnapshotRouteBody(generation.IntentSnapshot, generation.Generation)
			if bodyErr != nil {
				return bodyErr
			}
			if object.Class != ObjectPointer || object.Size != int64(len(body)) || object.SHA256 != digestBytes(body) {
				return fmt.Errorf("snapshot route %s does not upload the canonical intent body", object.RemoteKey)
			}
		}
		if !strings.HasPrefix(object.RemoteKey, ".sow/channels/") {
			continue
		}
		channel, exists := channels[object.RemoteKey]
		if !exists || channel.View != "stable" || channel.Generation != generation.Generation {
			return fmt.Errorf("channel pointer %s is not bound to the current stable generation", object.RemoteKey)
		}
		body, err := channel.CanonicalBody()
		if err != nil {
			return err
		}
		if object.Class != ObjectPointer || object.Size != int64(len(body)) || object.SHA256 != digestBytes(body) {
			return fmt.Errorf("channel pointer %s does not upload its canonical channel body", object.RemoteKey)
		}
		rendered := []byte(strings.TrimSuffix(plan.CDNBaseURL, "/") + "/pro/v1/basic/_sow/v1/g/" +
			fmt.Sprintf("%020d", generation.Generation) + "/" + channel.LegacyRoot + "/\n")
		if object.VerificationSize != int64(len(rendered)) || object.VerificationSHA256 != digestBytes(rendered) {
			return fmt.Errorf("channel pointer %s has an unbound transformed verification expectation", object.RemoteKey)
		}
	}
	if generation.IntentView == "snapshot" && !snapshotRouteSeen {
		return fmt.Errorf("snapshot publication %s has no canonical route pointer", generation.IntentSnapshot)
	}
	return nil
}

// validateIntentDeletes prevents a persisted plan from relabelling a valid,
// evidence-bound deletion as a mutation for another publication view. Snapshot
// retention is target-wide and may accompany any intent, but a snapshot is
// deletable only after the new immutable ref vector no longer retains it.
func validateIntentDeletes(generation TargetGeneration, deletions []PlannedDelete) error {
	retainedSnapshots := make(map[string]struct{})
	for _, ref := range generation.Refs {
		parts := strings.Split(ref.Name, "/")
		if len(parts) == 7 && parts[0] == "refs" && parts[1] == "sow" && parts[2] == "snapshots" {
			retainedSnapshots[parts[3]] = struct{}{}
		}
	}
	for _, deletion := range deletions {
		class := deletion.Class
		if class == "" {
			class = DeleteSnapshotOwned
		}
		switch class {
		case DeleteSnapshotOwned:
			snapshotID := snapshotDeleteID(deletion.RemoteKey)
			if snapshotID == "" {
				return fmt.Errorf("snapshot deletion %s has no canonical snapshot identity", deletion.RemoteKey)
			}
			if snapshotID == generation.IntentSnapshot {
				return fmt.Errorf("publication cannot delete its current snapshot %s", snapshotID)
			}
			if _, retained := retainedSnapshots[snapshotID]; retained {
				return fmt.Errorf("snapshot deletion %s remains reachable from the target ref vector", deletion.RemoteKey)
			}
		case DeleteAssetServing, DeleteAPTByHash, DeleteRestoreIndexServing, DeleteCompatibilityServing:
			view, err := servingDeleteView(deletion)
			if err != nil {
				return err
			}
			if generation.IntentView == "snapshot" || view != generation.IntentView {
				return fmt.Errorf("%s deletion %s belongs to %s, not publication intent %s", class, deletion.RemoteKey, view, generation.IntentView)
			}
		default:
			return fmt.Errorf("unsupported deletion class %q", class)
		}
	}
	return nil
}

func snapshotDeleteID(remoteKey string) string {
	if strings.HasPrefix(remoteKey, ".sow/snapshots/") && strings.HasSuffix(remoteKey, ".json") {
		return strings.TrimSuffix(strings.TrimPrefix(remoteKey, ".sow/snapshots/"), ".json")
	}
	if strings.HasPrefix(remoteKey, ".sow/gated/snapshots/") {
		remainder := strings.TrimPrefix(remoteKey, ".sow/gated/snapshots/")
		id, _, found := strings.Cut(remainder, "/")
		if found {
			return id
		}
	}
	return ""
}

func servingDeleteView(deletion PlannedDelete) (string, error) {
	if deletion.Class == DeleteCompatibilityServing {
		return "latest", nil
	}
	if deletion.Class == DeleteRestoreIndexServing && strings.HasPrefix(deletion.RemoteKey, "_sow/v1/mirrorlist/") {
		parts := strings.Split(deletion.RemoteKey, "/")
		if len(parts) != 7 {
			return "", fmt.Errorf("restore mirrorlist deletion %s is not canonical", deletion.RemoteKey)
		}
		return parts[3], nil
	}
	_, view, err := deleteLogicalPath(deletion.SourcePath, deletion.RemoteKey)
	if err != nil {
		return "", fmt.Errorf("derive publication intent for deletion %s: %w", deletion.RemoteKey, err)
	}
	return view, nil
}

func intentObjectCDNPath(generation TargetGeneration, remoteKey string) (string, error) {
	switch generation.IntentView {
	case "latest":
		if strings.HasPrefix(remoteKey, ".sow/generations/") {
			return generationStrongCDNPath(remoteKey)
		}
		if strings.HasPrefix(remoteKey, ".sow/") {
			return "", fmt.Errorf("latest publication cannot route private control object %s", remoteKey)
		}
		return remoteKey, nil
	case "beta":
		switch {
		case strings.HasPrefix(remoteKey, ".sow/beta/"):
			return strings.TrimPrefix(remoteKey, ".sow/beta/"), nil
		case strings.HasPrefix(remoteKey, ".sow/generations/"):
			return generationStrongCDNPath(remoteKey)
		case strings.HasPrefix(remoteKey, ".sow/"):
			return "", fmt.Errorf("beta publication cannot route control object %s", remoteKey)
		default:
			return remoteKey, nil
		}
	case "stable":
		switch {
		case strings.HasPrefix(remoteKey, ".sow/gated/generations/"):
			return generationStrongCDNPath(remoteKey)
		case strings.HasPrefix(remoteKey, ".sow/generations/"):
			return "", fmt.Errorf("stable metadata %s must use the gated generation namespace", remoteKey)
		case strings.HasPrefix(remoteKey, ".sow/channels/"):
			return channelPointerCDNPath(remoteKey)
		case strings.HasPrefix(remoteKey, ".sow/gated/"):
			return path.Join("pro/v1/basic", strings.TrimPrefix(remoteKey, ".sow/gated/")), nil
		case strings.HasPrefix(remoteKey, ".sow/"):
			return "", fmt.Errorf("stable publication cannot route non-gated control object %s", remoteKey)
		default:
			return path.Join("pro/v1/basic", remoteKey), nil
		}
	case "snapshot":
		if ValidatePublicationIntent("snapshot", generation.IntentSnapshot) != nil {
			return "", errors.New("snapshot publication has an invalid intent ID")
		}
		prefix := path.Join("pro/v1/basic/_sow/v1/snapshots", generation.IntentSnapshot)
		switch {
		case strings.HasPrefix(remoteKey, ".sow/snapshots/"):
			want, err := snapshotRouteCDNPath(remoteKey)
			if err != nil {
				return "", err
			}
			if remoteKey != path.Join(".sow/snapshots", generation.IntentSnapshot+".json") {
				return "", fmt.Errorf("snapshot route %s differs from intent %s", remoteKey, generation.IntentSnapshot)
			}
			return want, nil
		case strings.HasPrefix(remoteKey, ".sow/gated/generations/"):
			_, _, kind, tail, err := generationRemoteParts(remoteKey)
			if err != nil {
				return "", err
			}
			return path.Join(prefix, kind, tail), nil
		case strings.HasPrefix(remoteKey, ".sow/gated/snapshots/"):
			want, err := directSnapshotObjectCDNPath(remoteKey)
			if err != nil {
				return "", err
			}
			if !strings.HasPrefix(remoteKey, path.Join(".sow/gated/snapshots", generation.IntentSnapshot)+"/") {
				return "", fmt.Errorf("snapshot object %s differs from intent %s", remoteKey, generation.IntentSnapshot)
			}
			return want, nil
		case strings.HasPrefix(remoteKey, ".sow/gated/apt/"):
			return path.Join(prefix, "apt", strings.TrimPrefix(remoteKey, ".sow/gated/")), nil
		case strings.HasPrefix(remoteKey, ".sow/"):
			return "", fmt.Errorf("snapshot publication cannot route control object %s", remoteKey)
		case strings.HasPrefix(remoteKey, "apt/"):
			return path.Join(prefix, "apt", remoteKey), nil
		default:
			return "", fmt.Errorf("snapshot publication object %s has no canonical snapshot route", remoteKey)
		}
	default:
		return "", fmt.Errorf("unsupported publication intent %s", generation.IntentView)
	}
}

// validateYUMAliasAtomicRoutes prevents the legacy raw-baseurl compatibility
// copies from becoming the only publication entry point. R2 and COS cannot
// atomically replace repomd.xml and repomd.xml.asc, so serial alias PUTs are
// never sufficient for FR-26. Every changed alias pair must have an identical
// immutable generation pair plus the generation-pinned mirrorlist/channel
// pointer for the same leaf in the same transaction.
//
// This does not claim that the raw alias itself is atomic: a dnf client can
// straddle the two alias writes. It makes the supported strong-consistency
// route structural and fail-closed while the raw URL remains a migration
// bridge.
func validateYUMAliasAtomicRoutes(generation TargetGeneration, plan Plan) error {
	objects := make(map[string]PlannedObject, len(plan.Objects))
	for _, object := range plan.Objects {
		objects[object.RemoteKey] = object
	}

	currentChannels := make(map[string]ChannelState)
	currentChannelAliases := make(map[string][]ChannelState)
	pointerChannels := make(map[string]ChannelState)
	for _, channel := range generation.Channels {
		if channel.Generation != generation.Generation {
			continue
		}
		if channel.View != generation.IntentView || generation.IntentView == "snapshot" {
			return fmt.Errorf("current YUM channel %s belongs to view %s, not publication intent %s", channel.RemoteKey, channel.View, generation.IntentView)
		}
		if previous, duplicate := currentChannels[channel.LegacyRoot]; duplicate {
			// One repo+arch physical owner may have several logical OS aliases
			// (for example rocky and el10). They intentionally share one exact
			// immutable repodata generation, while retaining distinct channel
			// and mirrorlist keys. Never extend that exception across repositories,
			// architectures, views, or generations.
			if previous.View != channel.View || previous.Repo != channel.Repo || previous.Arch != channel.Arch || previous.Generation != channel.Generation {
				return fmt.Errorf("current YUM channels %s and %s illegally share legacy root %s", previous.RemoteKey, channel.RemoteKey, channel.LegacyRoot)
			}
		} else {
			currentChannels[channel.LegacyRoot] = channel
		}
		currentChannelAliases[channel.LegacyRoot] = append(currentChannelAliases[channel.LegacyRoot], channel)
		pointerKey, _, err := YUMChannelPointer(plan.CDNBaseURL, channel)
		if err != nil {
			return err
		}
		pointerChannels[pointerKey] = channel
	}

	// Snapshot publications route their immutable generation directly and do
	// not update a mutable channel or raw compatibility alias.
	if generation.IntentView == "snapshot" {
		return validateSnapshotYUMMetadataClosure(plan)
	}

	generationID := fmt.Sprintf("%020d", generation.Generation)
	generationPrefix := ".sow/generations/"
	aliasPrefix := ""
	if generation.IntentView == "beta" {
		aliasPrefix = ".sow/beta/"
	} else if generation.IntentView == "stable" {
		generationPrefix = ".sow/gated/generations/"
		aliasPrefix = ".sow/gated/"
	}

	type leafClosure struct {
		metadataKinds map[string]int
	}
	leaves := make(map[string]*leafClosure)
	leaf := func(legacyRoot string) *leafClosure {
		result := leaves[legacyRoot]
		if result == nil {
			result = &leafClosure{metadataKinds: make(map[string]int)}
			leaves[legacyRoot] = result
		}
		return result
	}

	for _, object := range plan.Objects {
		if strings.HasPrefix(object.RemoteKey, "_sow/v1/mirrorlist/") {
			channel, exists := pointerChannels[object.RemoteKey]
			if !exists {
				return fmt.Errorf("YUM mirrorlist %s has no current target channel", object.RemoteKey)
			}
			if err := validateYUMChannelPointer(plan.CDNBaseURL, channel, object); err != nil {
				return err
			}
		}

		match := yumGenerationKeyPattern.FindStringSubmatch(object.RemoteKey)
		if len(match) != 0 {
			legacyRoot, relative, ok := splitYUMRepodataTail(match[3])
			if !ok {
				return fmt.Errorf("YUM generation metadata %s is outside a repodata leaf", object.RemoteKey)
			}
			if _, exists := currentChannels[legacyRoot]; !exists {
				return fmt.Errorf("YUM generation metadata %s has no current target channel", object.RemoteKey)
			}
			kind, recognized := yumMetadataKind(relative)
			if !recognized {
				return fmt.Errorf("YUM generation metadata %s is outside the primary/filelists/other/repomd contract", object.RemoteKey)
			}
			leaf(legacyRoot).metadataKinds[kind]++
			aliasKey := aliasPrefix + legacyRoot + "/" + relative
			alias, exists := objects[aliasKey]
			wantClass := ObjectYUMAliasMetadata
			if kind == "repomd.xml" || kind == "repomd.xml.asc" {
				wantClass = ObjectYUMAliasPointer
			}
			if !exists || alias.Class != wantClass || alias.Size != object.Size || alias.SHA256 != object.SHA256 {
				return fmt.Errorf("YUM generation metadata %s requires identical compatibility alias %s", object.RemoteKey, aliasKey)
			}
		}

		if object.Class != ObjectYUMAliasMetadata && object.Class != ObjectYUMAliasPointer {
			continue
		}
		aliasKey := object.RemoteKey
		if aliasPrefix != "" {
			if !strings.HasPrefix(aliasKey, aliasPrefix) {
				return fmt.Errorf("YUM alias %s is outside publication intent %s", aliasKey, generation.IntentView)
			}
			aliasKey = strings.TrimPrefix(aliasKey, aliasPrefix)
		}
		legacyRoot, relative, ok := splitYUMRepodataTail(aliasKey)
		if !ok {
			return fmt.Errorf("YUM alias %s is outside a repodata leaf", object.RemoteKey)
		}
		if _, exists := currentChannels[legacyRoot]; !exists {
			return fmt.Errorf("YUM alias %s has no current target channel", object.RemoteKey)
		}
		generationKey := generationPrefix + generationID + "/yum/" + legacyRoot + "/" + relative
		immutable, exists := objects[generationKey]
		if !exists || immutable.Class != ObjectMetadata || immutable.Size != object.Size || immutable.SHA256 != object.SHA256 {
			return fmt.Errorf("YUM alias %s requires identical immutable generation metadata %s", object.RemoteKey, generationKey)
		}
	}

	for legacyRoot, channels := range currentChannelAliases {
		channel := channels[0]
		closure := leaves[legacyRoot]
		if closure == nil {
			return fmt.Errorf("current YUM channel %s has no immutable generation metadata", channel.RemoteKey)
		}
		for _, kind := range []string{"primary", "filelists", "other", "repomd.xml", "repomd.xml.asc"} {
			if closure.metadataKinds[kind] != 1 {
				return fmt.Errorf("current YUM channel %s requires exactly one %s object, got %d", channel.RemoteKey, kind, closure.metadataKinds[kind])
			}
		}
		for _, channel := range channels {
			pointerKey, _, err := YUMChannelPointer(plan.CDNBaseURL, channel)
			if err != nil {
				return err
			}
			pointer, exists := objects[pointerKey]
			if !exists {
				return fmt.Errorf("current YUM channel %s requires generation-pinned pointer %s", channel.RemoteKey, pointerKey)
			}
			if err := validateYUMChannelPointer(plan.CDNBaseURL, channel, pointer); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSnapshotYUMMetadataClosure(plan Plan) error {
	leaves := make(map[string]map[string]int)
	payloadRoots := make(map[string]struct{})
	for _, object := range plan.Objects {
		if strings.HasPrefix(object.RemoteKey, ".sow/gated/snapshots/") {
			remainder := strings.TrimPrefix(object.RemoteKey, ".sow/gated/snapshots/")
			parts := strings.SplitN(remainder, "/", 3)
			if len(parts) == 3 && parts[1] == "yum" {
				index := strings.Index(parts[2], "/Packages/")
				if index <= 0 || index+len("/Packages/") == len(parts[2]) {
					return fmt.Errorf("snapshot YUM payload %s is outside a Packages leaf", object.RemoteKey)
				}
				payloadRoots[parts[2][:index]] = struct{}{}
			}
		}
		match := yumGenerationKeyPattern.FindStringSubmatch(object.RemoteKey)
		if len(match) == 0 {
			continue
		}
		legacyRoot, relative, ok := splitYUMRepodataTail(match[3])
		if !ok {
			return fmt.Errorf("snapshot YUM metadata %s is outside a repodata leaf", object.RemoteKey)
		}
		kind, recognized := yumMetadataKind(relative)
		if !recognized {
			return fmt.Errorf("snapshot YUM metadata %s is outside the primary/filelists/other/repomd contract", object.RemoteKey)
		}
		if leaves[legacyRoot] == nil {
			leaves[legacyRoot] = make(map[string]int)
		}
		leaves[legacyRoot][kind]++
	}
	for legacyRoot, kinds := range leaves {
		for _, kind := range []string{"primary", "filelists", "other", "repomd.xml", "repomd.xml.asc"} {
			if kinds[kind] != 1 {
				return fmt.Errorf("snapshot YUM leaf %s requires exactly one %s object, got %d", legacyRoot, kind, kinds[kind])
			}
		}
	}
	for legacyRoot := range payloadRoots {
		if leaves[legacyRoot] == nil {
			return fmt.Errorf("snapshot YUM payload leaf %s has no complete generation metadata", legacyRoot)
		}
	}
	return nil
}

func splitYUMRepodataTail(value string) (legacyRoot, relative string, ok bool) {
	index := strings.LastIndex(value, "/repodata/")
	if index <= 0 || index+len("/repodata/") == len(value) {
		return "", "", false
	}
	return value[:index], value[index+1:], true
}

func yumMetadataKind(relative string) (string, bool) {
	base := path.Base(relative)
	switch base {
	case "repomd.xml", "repomd.xml.asc":
		return base, true
	}
	for _, candidate := range []string{"primary", "filelists", "other"} {
		for _, extension := range []string{".xml.gz", ".xml.zst"} {
			if base == candidate+extension || strings.HasSuffix(base, "-"+candidate+extension) {
				return candidate, true
			}
		}
	}
	return "", false
}

func validateYUMChannelPointer(cdnBaseURL string, channel ChannelState, pointer PlannedObject) error {
	pointerKey, body, err := YUMChannelPointer(cdnBaseURL, channel)
	if err != nil {
		return err
	}
	if pointer.RemoteKey != pointerKey || pointer.Class != ObjectPointer {
		return fmt.Errorf("YUM channel %s has invalid pointer %s", channel.RemoteKey, pointer.RemoteKey)
	}
	if pointer.Size != int64(len(body)) || pointer.SHA256 != digestBytes(body) {
		return fmt.Errorf("YUM channel %s pointer %s does not contain its canonical generation route", channel.RemoteKey, pointerKey)
	}
	return nil
}

func (p *Publisher) deletePlanned(ctx context.Context, journalPath string, journal *publishJournal, deletions []PlannedDelete, replay bool, lockToken string, checkpointFenced bool) error {
	for _, deletion := range deletions {
		identity := "delete:" + deletion.RemoteKey
		if journalHas(journal, identity) && !replay {
			continue
		}
		candidate, existsExact, err := p.verifyDeletionCandidate(ctx, deletion)
		if err != nil {
			return err
		}
		if existsExact {
			deleteErr := error(nil)
			if checkpointFenced {
				deleteErr = p.deleteCheckpointFenced(ctx, deletion, candidate, lockToken)
			} else {
				deleteErr = p.driver.delete(ctx, deletion.RemoteKey, candidate.ETag)
			}
			if deleteErr != nil {
				if errors.Is(deleteErr, ErrConflict) || errors.Is(deleteErr, ErrNotFound) {
					return errors.Join(
						ErrDrift,
						fmt.Errorf("deletion candidate or remote publication fence for %s changed before the admitted DELETE: %w", deletion.RemoteKey, deleteErr),
					)
				}
				return fmt.Errorf("delete authorized object %s: %w", deletion.RemoteKey, deleteErr)
			}
		}
		info, headErr := p.driver.head(ctx, deletion.RemoteKey)
		if headErr != nil {
			return fmt.Errorf("verify deletion of %s: %w", deletion.RemoteKey, headErr)
		}
		if info.Exists {
			return fmt.Errorf("%w: deleted object %s is still present in object storage", ErrVerification, deletion.RemoteKey)
		}
		if !journalHas(journal, identity) {
			if err := p.journal.completeObject(journalPath, journal, identity); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *Publisher) deleteCheckpointFenced(ctx context.Context, deletion PlannedDelete, first ObjectInfo, lockToken string) error {
	if err := p.driver.verifyDeleteFence(ctx, lockToken); err != nil {
		return fmt.Errorf("recheck remote publication fence before checkpoint-fenced deletion: %w", err)
	}
	second, exists, err := p.verifyDeletionCandidate(ctx, deletion)
	if err != nil {
		return err
	}
	if !exists || second.ETag != first.ETag || second.Size != first.Size || second.SHA256 != first.SHA256 {
		return fmt.Errorf("%w: deletion candidate %s changed between consecutive identity proofs", ErrDrift, deletion.RemoteKey)
	}
	if err := p.driver.verifyDeleteFence(ctx, lockToken); err != nil {
		return fmt.Errorf("recheck remote publication fence immediately before checkpoint-fenced deletion: %w", err)
	}
	if err := p.driver.deleteCheckpointFenced(ctx, deletion.RemoteKey); err != nil {
		return err
	}
	if err := p.driver.verifyDeleteFence(ctx, lockToken); err != nil {
		return fmt.Errorf("recheck remote publication fence after checkpoint-fenced deletion: %w", err)
	}
	return nil
}

// selectDeletionMode proves the endpoint's conditional-delete behavior before
// acquiring the publication lock or changing any live mutable route. Only one
// exact outcome admits the opt-in fallback: a deliberately stale If-Match
// request succeeds and the run-owned probe is observed absent. Network errors,
// incomplete reads, missing interfaces, and retained probes remain fail-closed
// even when checkpoint-fenced mode was configured.
func (p *Publisher) selectDeletionMode(ctx context.Context, transactionID string, deletions []PlannedDelete) (bool, error) {
	if len(deletions) == 0 {
		return false, nil
	}
	err := p.probeConditionalDelete(ctx, transactionID)
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, errConditionalDeleteDemonstrablyUnsupported):
		if !p.checkpointFencedDelete {
			return false, err
		}
		return true, nil
	default:
		return false, err
	}
}

// probeConditionalDelete proves the endpoint honors If-Match before SOW
// touches a live serving key. The probe key and bytes are deterministic for the
// transaction, so an interrupted probe is safely replayable. A provider that
// ignores the deliberately wrong condition deletes only this SOW-owned probe
// and is rejected before it can delete user content.
func (p *Publisher) probeConditionalDelete(ctx context.Context, transactionID string) error {
	probeID := digestBytes([]byte(transactionID))
	key := path.Join(".sow/probes/conditional-delete", probeID)
	body := []byte("sow conditional delete probe v1 " + probeID + "\n")
	sha := digestBytes(body)
	if err := p.driver.putImmutable(ctx, key, bytes.NewReader(body), int64(len(body)), sha); err != nil {
		return fmt.Errorf("prepare conditional deletion capability probe: %w", err)
	}
	observed, err := p.driver.head(ctx, key)
	if err != nil || !observed.Exists || observed.ETag == "" || observed.Size != int64(len(body)) || observed.SHA256 != sha {
		return errors.Join(err, fmt.Errorf("%w: conditional deletion probe read-back is incomplete", ErrCapability))
	}
	wrongETag := `"sow-conditional-delete-mismatch"`
	if wrongETag == observed.ETag {
		wrongETag = `"sow-conditional-delete-mismatch-2"`
	}
	wrongErr := p.driver.delete(ctx, key, wrongETag)
	afterWrong, headErr := p.driver.head(ctx, key)
	if wrongErr == nil && headErr == nil && !afterWrong.Exists {
		return errors.Join(ErrCapability, errConditionalDeleteDemonstrablyUnsupported)
	}
	exactRetained := headErr == nil && afterWrong.Exists && afterWrong.ETag == observed.ETag &&
		afterWrong.Size == observed.Size && afterWrong.SHA256 == observed.SHA256
	if errors.Is(wrongErr, ErrConflict) && exactRetained {
		cleanupErr := p.driver.delete(ctx, key, observed.ETag)
		removed, verifyErr := p.driver.head(ctx, key)
		if verifyErr == nil && !removed.Exists {
			// A matching delete whose response was lost is still a proven cleanup
			// once origin absence is observed.
			return nil
		}
		return errors.Join(cleanupErr, verifyErr, fmt.Errorf("%w: conditional deletion probe remained after matching DELETE", ErrVerification))
	}
	var cleanupErr error
	if exactRetained {
		cleanupErr = p.driver.delete(ctx, key, observed.ETag)
	}
	return errors.Join(
		wrongErr, headErr, cleanupErr,
		fmt.Errorf("%w: object endpoint did not conclusively prove conditional DeleteObject semantics", ErrVerification),
	)
}

// verifyDeletionCandidate proves that the live origin still contains exactly
// the bytes authorized by the old target manifest before issuing DELETE. SOW
// A provider-returned sow-sha256 value is only an untrusted hint: an external
// writer can preserve or forge custom metadata while replacing the body. Every
// destructive candidate therefore requires a stable ETag plus a streamed GET
// hash. A mismatching explicit metadata value still fails early, but a matching
// value never substitutes for hashing the bytes that are about to be deleted.
func (p *Publisher) verifyDeletionCandidate(ctx context.Context, deletion PlannedDelete) (ObjectInfo, bool, error) {
	info, err := p.driver.head(ctx, deletion.RemoteKey)
	if err != nil {
		return ObjectInfo{}, false, fmt.Errorf("verify deletion candidate %s HEAD: %w", deletion.RemoteKey, err)
	}
	if !info.Exists {
		return ObjectInfo{}, false, nil
	}
	if info.ETag == "" {
		return ObjectInfo{}, false, fmt.Errorf("%w: deletion candidate %s has no origin ETag", ErrCapability, deletion.RemoteKey)
	}
	// Legacy snapshot plans predate content binding. Their exact owned prefix is
	// still structurally validated; new asset and by-hash plans cannot use this
	// compatibility branch.
	if deletion.SourcePath == "" {
		return ObjectInfo{}, false, fmt.Errorf("%w: legacy deletion candidate %s has no content evidence and cannot be removed safely", ErrCapability, deletion.RemoteKey)
	}
	if info.Size != deletion.Size {
		return ObjectInfo{}, false, fmt.Errorf("%w: deletion candidate %s size changed", ErrDrift, deletion.RemoteKey)
	}
	if info.SHA256 != "" {
		if info.SHA256 != deletion.SHA256 {
			return ObjectInfo{}, false, fmt.Errorf("%w: deletion candidate %s digest changed", ErrDrift, deletion.RemoteKey)
		}
	}
	content, err := p.driver.openObject(ctx, deletion.RemoteKey)
	if err != nil {
		return ObjectInfo{}, false, fmt.Errorf("%w: open legacy deletion candidate %s: %v", ErrDrift, deletion.RemoteKey, err)
	}
	if content.Body == nil {
		return ObjectInfo{}, false, fmt.Errorf("%w: deletion candidate %s returned no body", ErrCapability, deletion.RemoteKey)
	}
	limit := deletion.Size
	if limit != math.MaxInt64 {
		limit++
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, io.LimitReader(content.Body, limit))
	closeErr := content.Body.Close()
	if copyErr != nil || closeErr != nil {
		return ObjectInfo{}, false, errors.Join(copyErr, closeErr)
	}
	if !content.Info.Exists || content.Info.Size != deletion.Size || content.Info.ETag == "" || content.Info.ETag != info.ETag ||
		content.Info.SHA256 != "" && content.Info.SHA256 != deletion.SHA256 || written != deletion.Size ||
		hex.EncodeToString(hasher.Sum(nil)) != deletion.SHA256 {
		return ObjectInfo{}, false, fmt.Errorf("%w: deletion candidate %s changed between HEAD and streamed GET", ErrDrift, deletion.RemoteKey)
	}
	return content.Info, true, nil
}

func routedDeleteCount(deletions []PlannedDelete) int {
	count := 0
	for _, deletion := range deletions {
		if deletion.CDNPath != "" {
			count++
		}
	}
	return count
}

func absenceVerificationURLs(expectations []VerifyAbsentObject) []string {
	urls := make([]string, 0, len(expectations))
	for _, expectation := range expectations {
		urls = append(urls, expectation.URL)
	}
	return urls
}

func positiveVerificationExpectations(plan Plan) []VerifyObject {
	expectations := make([]VerifyObject, 0, len(plan.Verify)+len(plan.Probes))
	expectations = append(expectations, plan.Verify...)
	expectations = append(expectations, plan.Probes...)
	return expectations
}

func (p *Publisher) verifyDeletionClosure(ctx context.Context, deletions []PlannedDelete, expectations []VerifyAbsentObject) error {
	for _, deletion := range deletions {
		info, err := p.driver.head(ctx, deletion.RemoteKey)
		if err != nil {
			return fmt.Errorf("%w: read deleted object %s: %v", ErrVerification, deletion.RemoteKey, err)
		}
		if info.Exists {
			return fmt.Errorf("%w: deleted object %s is still present in object storage", ErrVerification, deletion.RemoteKey)
		}
	}
	for _, expectation := range expectations {
		safeURL := redactURLString(expectation.URL)
		body, err := p.driver.openCDN(ctx, expectation.URL)
		if err != nil {
			var status *httpStatusError
			if errors.Is(err, ErrNotFound) || errors.As(err, &status) && (status.Status == 404 || status.Status == 410) {
				continue
			}
			return fmt.Errorf("%w: negative GET %s: %v", ErrVerification, safeURL, err)
		}
		closeErr := body.Close()
		if closeErr != nil {
			return fmt.Errorf("%w: close unexpected body for %s: %v", ErrVerification, safeURL, closeErr)
		}
		return fmt.Errorf("%w: deleted CDN route %s still returns a successful response", ErrVerification, safeURL)
	}
	return nil
}

func (p *Publisher) uploadPlanned(ctx context.Context, journalPath string, journal *publishJournal, object PlannedObject, immutable, replay bool) error {
	identity := string(object.Class) + ":" + object.RemoteKey
	if journalHas(journal, identity) && !replay {
		return nil
	}
	if err := p.uploadObject(ctx, journalPath, object, immutable); err != nil {
		return err
	}
	if !journalHas(journal, identity) {
		if err := p.journal.completeObject(journalPath, journal, identity); err != nil {
			return err
		}
	}
	return nil
}

type uploadOutcome struct {
	object PlannedObject
	err    error
}

// uploadStage bounds remote concurrency while keeping journal mutation on the
// caller goroutine. Successful uploads are durably recorded even if a sibling
// fails; unrecorded or canceled work is safely replayed by the same phase.
func (p *Publisher) uploadStage(ctx context.Context, journalPath string, journal *publishJournal, objects []PlannedObject, immutable, replay bool) error {
	pending := make([]PlannedObject, 0, len(objects))
	for _, object := range objects {
		identity := string(object.Class) + ":" + object.RemoteKey
		if !replay && journalHas(journal, identity) {
			continue
		}
		pending = append(pending, object)
	}
	if len(pending) == 0 {
		return nil
	}
	workers := p.workers
	if workers > len(pending) {
		workers = len(pending)
	}
	stageCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan PlannedObject)
	results := make(chan uploadOutcome, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for object := range jobs {
				err := p.uploadObject(stageCtx, journalPath, object, immutable)
				results <- uploadOutcome{object: object, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, object := range pending {
			select {
			case jobs <- object:
			case <-stageCtx.Done():
				return
			}
		}
	}()
	go func() {
		wait.Wait()
		close(results)
	}()

	var firstErr error
	journalWritable := true
	for outcome := range results {
		if outcome.err != nil {
			if firstErr == nil {
				firstErr = outcome.err
				cancel()
			}
			continue
		}
		if !journalWritable {
			continue
		}
		identity := string(outcome.object.Class) + ":" + outcome.object.RemoteKey
		if journalHas(journal, identity) {
			continue
		}
		if err := p.journal.completeObject(journalPath, journal, identity); err != nil {
			journalWritable = false
			if firstErr == nil {
				firstErr = err
				cancel()
			}
		}
	}
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

func (p *Publisher) uploadObject(ctx context.Context, journalPath string, object PlannedObject, immutable bool) error {
	if object.Class == ObjectAdoptedImmutable {
		if err := p.validateLocalObject(object); err != nil {
			return err
		}
		return p.driver.requireAdoptedImmutable(ctx, object.RemoteKey, object.Size, object.SHA256)
	}
	if object.Class == ObjectReuseImmutable {
		if err := p.validateLocalObject(object); err != nil {
			return err
		}
		exists, err := p.driver.hasImmutable(ctx, object.RemoteKey, object.Size, object.SHA256)
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
	}
	if object.Class == ObjectCopyImmutable {
		if err := p.validateLocalObject(object); err != nil {
			return err
		}
		copied, err := p.driver.copyImmutable(ctx, object.RemoteKey, object.CopySource, object.Size, object.SHA256)
		if err != nil {
			return fmt.Errorf("copy %s from %s: %w", object.RemoteKey, object.CopySource, err)
		}
		if copied {
			return nil
		}
	}
	reader, err := p.source.Open(object.SourcePath)
	if err != nil {
		return fmt.Errorf("open publish source %s: %w", object.SourcePath, err)
	}
	spool, err := validatedSpool(reader, filepath.Dir(journalPath), object)
	closeErr := reader.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		_ = spool.Close()
		return fmt.Errorf("close publish source %s: %w", object.SourcePath, closeErr)
	}
	defer spool.Close()
	hasher := sha256.New()
	counting := &countingReader{reader: io.TeeReader(spool, hasher)}
	if immutable {
		err = p.driver.putImmutable(ctx, object.RemoteKey, counting, object.Size, object.SHA256)
	} else {
		err = p.driver.putMutable(ctx, object.RemoteKey, counting, object.Size, object.SHA256)
	}
	if err != nil {
		return fmt.Errorf("upload %s: %w", object.RemoteKey, err)
	}
	if counting.count != object.Size || hex.EncodeToString(hasher.Sum(nil)) != object.SHA256 {
		return fmt.Errorf("source %s changed after manifest planning", object.SourcePath)
	}
	return nil
}

func (p *Publisher) validateLocalObject(object PlannedObject) error {
	reader, err := p.source.Open(object.SourcePath)
	if err != nil {
		return fmt.Errorf("open publish source %s: %w", object.SourcePath, err)
	}
	hasher := sha256.New()
	limit := object.Size
	if limit != math.MaxInt64 {
		limit++
	}
	count, readErr := io.Copy(hasher, io.LimitReader(reader, limit))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	if count != object.Size || hex.EncodeToString(hasher.Sum(nil)) != object.SHA256 {
		return fmt.Errorf("source %s changed after manifest planning", object.SourcePath)
	}
	return nil
}

func pointerObjects(plan Plan) []PlannedObject {
	objects := append([]PlannedObject(nil), plan.objects(ObjectYUMAliasPointer)...)
	objects = append(objects, plan.objects(ObjectCompatibilityRollbackPointer)...)
	objects = append(objects, plan.objects(ObjectPointer)...)
	return objects
}

// orderedYUMAliasPointers returns each complete pair with its detached
// signature immediately before repomd.xml. Plan validation guarantees the
// counterpart exists; sorting here makes replay identical to first execution.
func orderedYUMAliasPointers(plan Plan) []PlannedObject {
	objects := append([]PlannedObject(nil), plan.objects(ObjectYUMAliasPointer)...)
	sort.Slice(objects, func(i, j int) bool {
		leftBase := strings.TrimSuffix(objects[i].RemoteKey, ".asc")
		rightBase := strings.TrimSuffix(objects[j].RemoteKey, ".asc")
		if leftBase != rightBase {
			return leftBase < rightBase
		}
		leftASC := strings.HasSuffix(objects[i].RemoteKey, ".asc")
		rightASC := strings.HasSuffix(objects[j].RemoteKey, ".asc")
		return leftASC && !rightASC
	})
	return objects
}

func validateJournalPlan(journal *publishJournal, plan Plan, generationKey string) error {
	allowed := make(map[string]struct{}, len(plan.Objects)+len(plan.Deletes)+1)
	for _, object := range plan.Objects {
		allowed[string(object.Class)+":"+object.RemoteKey] = struct{}{}
	}
	allowed["generation:"+generationKey] = struct{}{}
	for _, deletion := range plan.Deletes {
		allowed["delete:"+deletion.RemoteKey] = struct{}{}
	}
	for _, identity := range journal.CompletedObjects {
		if _, ok := allowed[identity]; !ok {
			return fmt.Errorf("%w: journal contains an object outside its canonical plan", ErrJournalConflict)
		}
	}
	requireCompleted := func(objects []PlannedObject) error {
		for _, object := range objects {
			if !journalHas(journal, string(object.Class)+":"+object.RemoteKey) {
				return fmt.Errorf("%w: phase %s is missing completed object %s", ErrJournalConflict, journal.Phase, object.RemoteKey)
			}
		}
		return nil
	}
	if phaseAtLeast(journal.Phase, PhaseLocked) && journal.LockToken == "" {
		return fmt.Errorf("%w: locked journal has no remote lock token", ErrJournalConflict)
	}
	if phaseAtLeast(journal.Phase, PhaseImmutableUploaded) {
		if err := requireCompleted(plan.objects(ObjectImmutable)); err != nil {
			return err
		}
		if err := requireCompleted(plan.objects(ObjectAdoptedImmutable)); err != nil {
			return err
		}
		if err := requireCompleted(plan.objects(ObjectCopyImmutable)); err != nil {
			return err
		}
		if err := requireCompleted(plan.objects(ObjectReuseImmutable)); err != nil {
			return err
		}
	}
	if phaseAtLeast(journal.Phase, PhaseGenerationReady) {
		if err := requireCompleted(plan.objects(ObjectMetadata)); err != nil {
			return err
		}
		if !journalHas(journal, "generation:"+generationKey) {
			return fmt.Errorf("%w: generation-ready journal has no generation document", ErrJournalConflict)
		}
	}
	if phaseAtLeast(journal.Phase, PhasePointerFlipped) {
		if err := requireCompleted(plan.objects(ObjectLegacyMetadata)); err != nil {
			return err
		}
		if err := requireCompleted(plan.objects(ObjectYUMAliasMetadata)); err != nil {
			return err
		}
		if err := requireCompleted(plan.objects(ObjectYUMAliasPointer)); err != nil {
			return err
		}
		if err := requireCompleted(plan.objects(ObjectCompatibilityRollbackMetadata)); err != nil {
			return err
		}
		if err := requireCompleted(plan.objects(ObjectCompatibilityRollbackPointer)); err != nil {
			return err
		}
		if err := requireCompleted(plan.objects(ObjectPointer)); err != nil {
			return err
		}
	}
	if phaseAtLeast(journal.Phase, PhasePurged) {
		for _, deletion := range plan.Deletes {
			if !journalHas(journal, "delete:"+deletion.RemoteKey) {
				return fmt.Errorf("%w: purged phase is missing deletion %s", ErrJournalConflict, deletion.RemoteKey)
			}
		}
	}
	return nil
}

func (p *Publisher) ensureTargetGeneration(ctx context.Context, key string, body []byte, sha string) error {
	if err := p.driver.putImmutable(ctx, key, bytes.NewReader(body), int64(len(body)), sha); err != nil {
		return err
	}
	observed, err := p.driver.getControl(ctx, key)
	if err != nil {
		return err
	}
	if !observed.Exists || observed.ETag == "" || !bytes.Equal(observed.Body, body) {
		return fmt.Errorf("%w: immutable target generation read-back mismatch", ErrDrift)
	}
	decoded, err := DecodeTargetGeneration(observed.Body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDrift, err)
	}
	digest, err := decoded.Digest()
	if err != nil || digest != sha {
		return fmt.Errorf("%w: immutable target generation digest mismatch", ErrDrift)
	}
	return nil
}

// validatedSpool proves the source bytes before any remote side effect. This
// is intentionally a disk spool, not an in-memory buffer: package objects can
// be large, and an upload-time source race must never poison a create-only key
// whose metadata claims the planned digest.
func validatedSpool(reader io.Reader, journalDir string, object PlannedObject) (*os.File, error) {
	temp, err := createUnlinkedTemp(journalDir, ".publish-object-")
	if err != nil {
		return nil, fmt.Errorf("create validated publish spool: %w", err)
	}
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return nil, err
	}
	hasher := sha256.New()
	limit := object.Size
	if limit != math.MaxInt64 {
		limit++
	}
	count, err := io.Copy(io.MultiWriter(temp, hasher), io.LimitReader(reader, limit))
	if err != nil {
		_ = temp.Close()
		return nil, fmt.Errorf("read publish source %s: %w", object.SourcePath, err)
	}
	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if count != object.Size || actualSHA != object.SHA256 {
		_ = temp.Close()
		return nil, fmt.Errorf("source %s changed after manifest planning", object.SourcePath)
	}
	if _, err := temp.Seek(0, io.SeekStart); err != nil {
		_ = temp.Close()
		return nil, err
	}
	return temp, nil
}

// verify checks the complete changed-object closure through the CDN with the
// same bounded concurrency configured for uploads. The dispatcher keeps at
// most workers requests in flight, while results are resolved in plan order so
// the reported failure is deterministic. Once any request fails, no additional
// work is dispatched; earlier plan entries already in flight decide whether a
// lower-index error takes precedence. On failure the shared context is
// cancelled and all started workers are joined before returning, so readers
// are never abandoned by the coordinator.
func (p *Publisher) verify(ctx context.Context, expectations []VerifyObject) error {
	if len(expectations) == 0 {
		return nil
	}
	if p.workers < 1 || p.workers > maxPublishWorkers {
		return fmt.Errorf("publish worker count must be between 1 and %d", maxPublishWorkers)
	}
	workerCount := min(p.workers, len(expectations))
	verifyCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type verificationJob struct {
		index    int
		expected VerifyObject
	}
	type verificationResult struct {
		index int
		err   error
	}
	jobs := make(chan verificationJob, workerCount)
	results := make(chan verificationResult, workerCount)
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for job := range jobs {
				var err error
				if contextErr := verifyCtx.Err(); contextErr != nil {
					err = contextErr
				} else {
					err = p.verifyObject(verifyCtx, job.expected)
				}
				results <- verificationResult{index: job.index, err: err}
			}
		}()
	}

	nextDispatch := 0
	nextResolve := 0
	inFlight := 0
	lowestFailure := len(expectations)
	completed := make(map[int]error, workerCount)
	dispatch := func() {
		for nextDispatch < len(expectations) && nextDispatch < lowestFailure && inFlight < workerCount {
			jobs <- verificationJob{index: nextDispatch, expected: expectations[nextDispatch]}
			nextDispatch++
			inFlight++
		}
	}
	dispatch()
	for nextResolve < len(expectations) {
		result := <-results
		inFlight--
		completed[result.index] = result.err
		if result.err != nil && result.index < lowestFailure {
			lowestFailure = result.index
		}
		for {
			err, ready := completed[nextResolve]
			if !ready {
				break
			}
			delete(completed, nextResolve)
			if err != nil {
				cancel()
				close(jobs)
				workers.Wait()
				if errors.Is(err, ErrVerification) {
					return err
				}
				return fmt.Errorf("%w: %w", ErrVerification, err)
			}
			nextResolve++
		}
		dispatch()
	}
	close(jobs)
	workers.Wait()
	return nil
}

func (p *Publisher) verifyObject(ctx context.Context, expected VerifyObject) error {
	safeURL := redactURLString(expected.URL)
	body, err := p.driver.openCDN(ctx, expected.URL)
	if err != nil {
		return fmt.Errorf("%w: GET %s: %w", ErrVerification, safeURL, err)
	}
	hasher := sha256.New()
	limit := expected.Size
	if limit != math.MaxInt64 {
		limit++
	}
	count, copyErr := io.Copy(hasher, io.LimitReader(body, limit))
	closeErr := body.Close()
	if copyErr != nil {
		return fmt.Errorf("%w: read %s: %w", ErrVerification, safeURL, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("%w: close %s: %w", ErrVerification, safeURL, closeErr)
	}
	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if count != expected.Size || actualSHA != expected.SHA256 {
		return fmt.Errorf("%w: %s got size=%d sha256=%s, want size=%d sha256=%s", ErrVerification, safeURL, count, actualSHA, expected.Size, expected.SHA256)
	}
	return nil
}

func (p *Publisher) afterPhase(phase Phase) error {
	if p.hooks.AfterPhase == nil {
		return nil
	}
	return p.hooks.AfterPhase(p.target, phase)
}

func journalHas(journal *publishJournal, identity string) bool {
	index := sort.SearchStrings(journal.CompletedObjects, identity)
	return index < len(journal.CompletedObjects) && journal.CompletedObjects[index] == identity
}

type countingReader struct {
	reader io.Reader
	count  int64
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	r.count += int64(n)
	return n, err
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type Job struct {
	Publisher *Publisher
	Request   Request
}

type MultiTargetError struct {
	Failures map[TargetName]error
}

func (e *MultiTargetError) Error() string {
	targets := make([]string, 0, len(e.Failures))
	for target := range e.Failures {
		targets = append(targets, string(target))
	}
	sort.Strings(targets)
	var message string
	for _, target := range targets {
		if message != "" {
			message += "; "
		}
		message += target + ": " + e.Failures[TargetName(target)].Error()
	}
	return "publish target failures: " + message
}

func (e *MultiTargetError) Unwrap() []error {
	result := make([]error, 0, len(e.Failures))
	for _, err := range e.Failures {
		result = append(result, err)
	}
	return result
}

// RunTargets does not cancel successful siblings when one target fails. This
// is the NFR-09 independent-progress contract: the aggregate returns failure,
// while each completed target keeps its durable checkpoint and remote ref.
func RunTargets(ctx context.Context, jobs ...Job) (map[TargetName]Result, error) {
	if ctx == nil {
		return nil, errors.New("publish: nil context")
	}
	results := make(map[TargetName]Result, len(jobs))
	failures := make(map[TargetName]error)
	seen := make(map[TargetName]struct{}, len(jobs))
	for _, job := range jobs {
		if job.Publisher == nil {
			return nil, errors.New("nil publisher job")
		}
		if _, duplicate := seen[job.Publisher.target]; duplicate {
			return nil, fmt.Errorf("duplicate publish target %s", job.Publisher.target)
		}
		seen[job.Publisher.target] = struct{}{}
	}
	var mutex sync.Mutex
	var wait sync.WaitGroup
	for _, job := range jobs {
		job := job
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := job.Publisher.Run(ctx, job.Request)
			mutex.Lock()
			defer mutex.Unlock()
			results[job.Publisher.target] = result
			if err != nil {
				failures[job.Publisher.target] = err
			}
		}()
	}
	wait.Wait()
	if len(failures) != 0 {
		return results, &MultiTargetError{Failures: failures}
	}
	return results, nil
}
