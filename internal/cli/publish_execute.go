package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

type preparedTargetPublication struct {
	target      string
	publication targetPublication
	workers     int
	err         error
}

type targetPublicationPipelineOutcome struct {
	target      string
	workers     int
	publication targetPublication
	result      pub.Result
	commit      plumbing.Hash
	status      string
	err         error
}

type targetPublicationSequenceOutcome struct {
	target  string
	workers int
	output  []byte
	err     error
}

// runTargetPublicationSequencesConcurrently runs one strictly ordered intent
// sequence per provider target. Outer target concurrency is independent of the
// inner worker budget: even --workers=1 must not let a blocked provider prevent
// its sibling from advancing through later views or snapshots. Each sequence
// receives a private output buffer and transaction directory; callers flush the
// buffers in target order after the join so CLI output remains deterministic.
func runTargetPublicationSequencesConcurrently(
	ctx context.Context,
	targetNames []string,
	txDir string,
	totalWorkers int,
	run func(context.Context, string, string, int, io.Writer) error,
) ([]targetPublicationSequenceOutcome, error) {
	if len(targetNames) == 0 {
		return nil, nil
	}
	if totalWorkers < 1 {
		return nil, errors.New("worker count must be positive")
	}
	if run == nil {
		return nil, errors.New("target publication sequence is unavailable")
	}
	seen := make(map[string]struct{}, len(targetNames))
	for _, target := range targetNames {
		if target != "cf" && target != "cos" {
			return nil, fmt.Errorf("unsupported publication target %q", target)
		}
		if _, duplicate := seen[target]; duplicate {
			return nil, fmt.Errorf("duplicate publication target %s", target)
		}
		seen[target] = struct{}{}
	}
	innerWorkers := max(1, totalWorkers/len(targetNames))
	results := make([]targetPublicationSequenceOutcome, len(targetNames))
	var group sync.WaitGroup
	for index, target := range targetNames {
		index, target := index, target
		group.Add(1)
		go func() {
			defer group.Done()
			result := targetPublicationSequenceOutcome{target: target, workers: innerWorkers}
			if err := ctx.Err(); err != nil {
				result.err = err
				results[index] = result
				return
			}
			targetDir := filepath.Join(txDir, "sequence-"+target)
			if err := os.Mkdir(targetDir, 0o700); err != nil {
				result.err = fmt.Errorf("create isolated target sequence directory: %w", err)
				results[index] = result
				return
			}
			var output bytes.Buffer
			result.err = run(ctx, target, targetDir, innerWorkers, &output)
			result.output = append([]byte(nil), output.Bytes()...)
			results[index] = result
		}()
	}
	group.Wait()
	return results, nil
}

// runTargetPublicationPipelinesConcurrently gives each selected cloud target
// its own build -> saga -> local-persist pipeline. The outer orchestration is
// always concurrent (there are at most two product targets), including when a
// caller requests one inner worker; otherwise a provider stuck in observation
// or retry could prevent its healthy sibling from reaching a durable remote
// checkpoint. CPU-heavy inner work still receives a divided worker budget.
// Results retain caller order and one pipeline never cancels another.
func runTargetPublicationPipelinesConcurrently(
	ctx context.Context,
	targetNames []string,
	txDir string,
	totalWorkers int,
	run func(context.Context, string, string, int) targetPublicationPipelineOutcome,
) ([]targetPublicationPipelineOutcome, error) {
	if len(targetNames) == 0 {
		return nil, nil
	}
	if totalWorkers < 1 {
		return nil, errors.New("worker count must be positive")
	}
	if run == nil {
		return nil, errors.New("target publication pipeline is unavailable")
	}
	seen := make(map[string]struct{}, len(targetNames))
	for _, target := range targetNames {
		if target != "cf" && target != "cos" {
			return nil, fmt.Errorf("unsupported publication target %q", target)
		}
		if _, duplicate := seen[target]; duplicate {
			return nil, fmt.Errorf("duplicate publication target %s", target)
		}
		seen[target] = struct{}{}
	}
	innerWorkers := max(1, totalWorkers/len(targetNames))
	results := make([]targetPublicationPipelineOutcome, len(targetNames))
	var group sync.WaitGroup
	for index, target := range targetNames {
		index, target := index, target
		group.Add(1)
		go func() {
			defer group.Done()
			outcome := targetPublicationPipelineOutcome{target: target, workers: innerWorkers}
			if err := ctx.Err(); err != nil {
				outcome.status, outcome.err = "failed-before-saga", err
				results[index] = outcome
				return
			}
			targetDir := filepath.Join(txDir, "target-"+target)
			if err := os.Mkdir(targetDir, 0o700); err != nil {
				outcome.status, outcome.err = "failed-before-saga", fmt.Errorf("create isolated target transaction directory: %w", err)
				results[index] = outcome
				return
			}
			outcome = run(ctx, target, targetDir, innerWorkers)
			outcome.target, outcome.workers = target, innerWorkers
			results[index] = outcome
		}()
	}
	group.Wait()
	return results, nil
}

// prepareTargetPublicationsConcurrently keeps one slow provider observation
// from preventing its sibling from reaching the same pre-saga boundary. Each
// target receives a private transaction workspace and a share of the caller's
// global worker budget, so concurrent plan construction cannot collide on
// staged files or multiply inner hashing/verification pools by target count.
//
// Results retain the caller's target order and include per-target failures;
// one provider's error must never cancel a healthy sibling's preparation.
func prepareTargetPublicationsConcurrently(
	ctx context.Context,
	targetNames []string,
	txDir string,
	totalWorkers int,
	build func(context.Context, string, string, int) (targetPublication, error),
) ([]preparedTargetPublication, error) {
	if len(targetNames) == 0 {
		return nil, nil
	}
	if totalWorkers < 1 {
		return nil, errors.New("worker count must be positive")
	}
	if build == nil {
		return nil, errors.New("target publication builder is unavailable")
	}
	seen := make(map[string]struct{}, len(targetNames))
	for _, target := range targetNames {
		if target != "cf" && target != "cos" {
			return nil, fmt.Errorf("unsupported publication target %q", target)
		}
		if _, duplicate := seen[target]; duplicate {
			return nil, fmt.Errorf("duplicate publication target %s", target)
		}
		seen[target] = struct{}{}
	}

	outerWorkers := min(totalWorkers, len(targetNames))
	innerWorkers := max(1, totalWorkers/outerWorkers)
	results := make([]preparedTargetPublication, len(targetNames))
	jobs := make(chan int, len(targetNames))
	for index := range targetNames {
		jobs <- index
	}
	close(jobs)
	var group sync.WaitGroup
	for range outerWorkers {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				target := targetNames[index]
				result := preparedTargetPublication{target: target, workers: innerWorkers}
				if err := ctx.Err(); err != nil {
					result.err = err
					results[index] = result
					continue
				}
				targetDir := filepath.Join(txDir, "target-"+target)
				if err := os.Mkdir(targetDir, 0o700); err != nil {
					result.err = fmt.Errorf("create isolated target transaction directory: %w", err)
					results[index] = result
					continue
				}
				result.publication, result.err = build(ctx, target, targetDir, innerWorkers)
				results[index] = result
			}
		}()
	}
	group.Wait()
	return results, nil
}

// publishPreparedView runs the selected targets independently and returns the
// identity of every target that did not reach the durable remote-ref-ready
// boundary. Callers publishing an ordered set of views must carry this set
// forward so a target that failed beta can never skip ahead to latest or
// stable in the same invocation.
func publishPreparedView(ctx context.Context, cfg *config.Config, canonical *state.Store, repos []config.Repo, prepared preparedPublication, targetNames []string, desiredCommit plumbing.Hash, txDir string, values commonFlags, stdout io.Writer) (map[string]error, error) {
	var persistMutex sync.Mutex
	return publishPreparedViewWithPersistMutex(ctx, cfg, canonical, repos, prepared, targetNames, desiredCommit, txDir, values, stdout, &persistMutex)
}

// publishPreparedViewWithPersistMutex is the single-intent compatibility
// wrapper around the target pipeline. Multi-intent publication passes one
// invocation-wide mutex so independent target sequences may advance at their
// own pace while canonical Git commits remain linear.
func publishPreparedViewWithPersistMutex(ctx context.Context, cfg *config.Config, canonical *state.Store, repos []config.Repo, prepared preparedPublication, targetNames []string, desiredCommit plumbing.Hash, txDir string, values commonFlags, stdout io.Writer, persistMutex *sync.Mutex) (map[string]error, error) {
	failures := make(map[string]error)
	if persistMutex == nil {
		return failures, errors.New("publication canonical persist coordinator is unavailable")
	}
	outcomes, err := runTargetPublicationPipelinesConcurrently(ctx, targetNames, txDir, values.workers,
		func(ctx context.Context, target, targetDir string, workers int) targetPublicationPipelineOutcome {
			return publishPreparedTarget(ctx, cfg, canonical, repos, prepared, target, desiredCommit, targetDir, values, workers, persistMutex)
		})
	if err != nil {
		return failures, err
	}
	for _, outcome := range outcomes {
		if failure := emitTargetPublicationOutcome(stdout, prepared, outcome); failure != nil {
			failures[outcome.target] = failure
		}
	}
	if len(failures) == 0 {
		return failures, nil
	}
	if len(targetNames) == 1 {
		for _, err := range failures {
			return failures, publishTargetExitError(err)
		}
		return failures, errors.New("single publication target failed without a recorded cause")
	}
	return failures, nil
}

// publishPreparedTarget executes exactly one target+intent pipeline. It never
// starts a goroutine and never cancels a sibling; target-major orchestration can
// therefore call it repeatedly to preserve one target's release order. Only
// canonical state persistence is serialized across targets.
func publishPreparedTarget(ctx context.Context, cfg *config.Config, canonical *state.Store, repos []config.Repo, prepared preparedPublication, target string, desiredCommit plumbing.Hash, targetDir string, values commonFlags, workers int, persistMutex *sync.Mutex) targetPublicationPipelineOutcome {
	outcome := targetPublicationPipelineOutcome{target: target, workers: workers}
	if persistMutex == nil {
		outcome.status, outcome.err = "failed-before-saga", errors.New("publication canonical persist coordinator is unavailable")
		return outcome
	}
	targetValues := values
	targetValues.workers = workers
	publication, buildErr := buildTargetPublication(ctx, cfg, canonical, repos, prepared, target, desiredCommit, targetDir, targetValues)
	outcome.publication = publication
	if buildErr != nil {
		if errors.Is(buildErr, pub.ErrVerification) {
			outcome.status = "failed-preflight-verification"
		} else {
			outcome.status = "failed-before-saga"
		}
		outcome.err = buildErr
		return outcome
	}
	if publication.unchanged {
		outcome.status = "unchanged"
		return outcome
	}
	publisher, publisherErr := publication.client.publisher(cfg.Root, filepath.Join(cfg.StatePath(), "publish-journal"))
	if publisherErr != nil {
		outcome.status, outcome.err = "failed-before-saga", publisherErr
		return outcome
	}
	publisher = publisher.WithWorkers(workers).WithTrustGuard(publication.trustGuard(cfg))
	name := pub.TargetName(target)
	results, runErr := pub.RunTargets(ctx, pub.Job{Publisher: publisher, Request: publication.request})
	result := results[name]
	outcome.result = result
	if !result.RemoteRefReady {
		if runErr != nil {
			outcome.status, outcome.err = "failed", targetFailure(runErr, name)
			return outcome
		}
		outcome.status = "failed"
		outcome.err = fmt.Errorf("target %s publication stopped at phase %s before remote refs were ready", target, result.Phase)
		return outcome
	}
	if !sameRefStates(result.RefVector, publication.request.Generation.Refs) {
		outcome.status = "failed"
		outcome.err = withExitCode(ExitConflict, "publish target %s returned a different ref vector", target)
		return outcome
	}
	// Canonical Git HEAD is shared even though provider transactions are
	// independent. Serialize only this short local commit; a slow build or remote
	// saga never holds the mutex or delays a healthy sibling.
	persistMutex.Lock()
	commit, persistErr := persistPublishedTarget(ctx, cfg, canonical, publication, result, targetDir)
	persistMutex.Unlock()
	if persistErr != nil {
		outcome.status = "failed-local-persist"
		outcome.err = withExitCode(ExitConflict, "persist successful target %s remote refs: %v", target, persistErr)
		return outcome
	}
	outcome.status, outcome.commit = "published", commit
	return outcome
}

func emitTargetPublicationOutcome(stdout io.Writer, prepared preparedPublication, outcome targetPublicationPipelineOutcome) error {
	target := outcome.target
	publication := outcome.publication
	switch outcome.status {
	case "unchanged":
		fmt.Fprintf(stdout, "publish target=%s %s status=unchanged\n", target, prepared.outputSelection())
		return nil
	case "published":
		fmt.Fprintf(stdout, "publish target=%s %s generation=%d phase=%s remote_refs=%d commit=%s status=published\n", target, prepared.outputSelection(), outcome.result.Generation, outcome.result.Phase, len(outcome.result.RefVector), outcome.commit)
		return nil
	case "failed-before-saga":
		fmt.Fprintf(stdout, "publish target=%s %s status=failed-before-saga error=%q\n", target, prepared.outputSelection(), redactPublishError(outcome.err))
		return outcome.err
	case "failed-preflight-verification":
		fmt.Fprintf(stdout, "publish target=%s %s status=failed-preflight-verification error=%q\n", target, prepared.outputSelection(), redactPublishError(outcome.err))
		return outcome.err
	case "failed-local-persist":
		fmt.Fprintf(stdout, "publish target=%s %s generation=%d phase=%s status=failed-local-persist error=%q\n", target, prepared.outputSelection(), outcome.result.Generation, outcome.result.Phase, redactPublishError(outcome.err))
		return outcome.err
	default:
		generation := uint64(0)
		if publication.request.Generation.Generation != 0 {
			generation = publication.request.Generation.Generation
		}
		fmt.Fprintf(stdout, "publish target=%s %s generation=%d phase=%s status=failed error=%q\n", target, prepared.outputSelection(), generation, outcome.result.Phase, redactPublishError(outcome.err))
		return outcome.err
	}
}

func persistPublishedTarget(ctx context.Context, cfg *config.Config, canonical *state.Store, publication targetPublication, result pub.Result, txDir string) (plumbing.Hash, error) {
	if err := validateCheckpointETag(result.CheckpointETag); err != nil {
		return plumbing.ZeroHash, fmt.Errorf("persist checkpoint ETag: %w", err)
	}
	generationBody, err := publication.request.Generation.Canonical()
	if err != nil {
		return plumbing.ZeroHash, err
	}
	planSHA, err := publication.request.Plan.Digest()
	if err != nil {
		return plumbing.ZeroHash, err
	}
	checkpoint, err := pub.NewCheckpoint(publication.request.Generation, publication.request.TransactionID, planSHA, pub.PhaseCheckpointCommitted, publication.request.UpdatedAt)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	checkpointBody, err := checkpoint.Canonical()
	if err != nil {
		return plumbing.ZeroHash, err
	}
	if digestBytesCLI(generationBody) != result.GenerationSHA256 || digestBytesCLI(checkpointBody) != result.CheckpointSHA256 {
		return plumbing.ZeroHash, errors.New("remote result digest disagrees with canonical publication")
	}
	persistDir := filepath.Join(txDir, "persist-"+publication.target)
	if err := os.MkdirAll(persistDir, 0o700); err != nil {
		return plumbing.ZeroHash, err
	}
	purgeEvidenceSource, purgeEvidenceStatePath, err := stagePublishedPurgeEvidence(publication, result, persistDir)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("stage purge evidence: %w", err)
	}
	generationPath := filepath.Join(persistDir, "generation.json")
	checkpointPath := filepath.Join(persistDir, "checkpoint.json")
	checkpointETagPath := filepath.Join(persistDir, "checkpoint.etag")
	inventoryPath := filepath.Join(persistDir, "inventory.tsv")
	if err := writeExclusiveBytes(generationPath, generationBody); err != nil {
		return plumbing.ZeroHash, err
	}
	if err := writeExclusiveBytes(checkpointPath, checkpointBody); err != nil {
		return plumbing.ZeroHash, err
	}
	if err := writeExclusiveBytes(checkpointETagPath, []byte(result.CheckpointETag)); err != nil {
		return plumbing.ZeroHash, err
	}
	coverage, err := stageRemoteInventory(canonical, publication, generationBody, checkpointBody, inventoryPath)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("stage remote inventory: %w", err)
	}
	coveragePath, err := stageInventoryCoverage(persistDir, coverage)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	canonicalConfig, _, err := stageCanonicalConfig(cfg, persistDir)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	staged := map[string]string{
		remoteStatePath(publication.target, "content.tsv"):        publication.desiredManifest,
		remoteStatePath(publication.target, "generation.json"):    generationPath,
		remoteStatePath(publication.target, "checkpoint.json"):    checkpointPath,
		remoteStatePath(publication.target, "checkpoint.etag"):    checkpointETagPath,
		remoteStatePath(publication.target, "plan.json"):          publication.planPath,
		remoteStatePath(publication.target, "inventory.tsv"):      inventoryPath,
		remoteStatePath(publication.target, "inventory.coverage"): coveragePath,
		"config/sow.yaml": canonicalConfig,
	}
	if purgeEvidenceSource != "" {
		staged[purgeEvidenceStatePath] = purgeEvidenceSource
	}
	operation := "publish"
	message := fmt.Sprintf("sow publish: %s generation %d", publication.target, publication.request.Generation.Generation)
	if publication.restore != nil {
		restoreBody, err := encodeRestoreAudit(publication)
		if err != nil {
			return plumbing.ZeroHash, fmt.Errorf("encode restore audit: %w", err)
		}
		restorePath := filepath.Join(persistDir, "restore.json")
		if err := writeExclusiveBytes(restorePath, restoreBody); err != nil {
			return plumbing.ZeroHash, err
		}
		staged[remoteStatePath(publication.target, filepath.ToSlash(filepath.Join("restores", fmt.Sprintf("%020d.json", publication.request.Generation.Generation))))] = restorePath
		operation = "restore"
		message = fmt.Sprintf("sow restore: %s generation %d from %d", publication.target, publication.request.Generation.Generation, publication.restore.Generation)
	}
	// The target-global files above remain the recovery truth for the bucket's
	// latest checkpoint. Retain an immutable-by-intent verification projection
	// as well, otherwise a beta→latest→stable invocation would overwrite the
	// only plan and make the first two published views unverifiable.
	for filename, source := range map[string]string{
		"generation.json": generationPath,
		"checkpoint.json": checkpointPath,
		"checkpoint.etag": checkpointETagPath,
		"plan.json":       publication.planPath,
	} {
		intentPath, err := remoteIntentStatePath(publication.target, publication.request.Generation.IntentView, publication.request.Generation.IntentSnapshot, filename)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		staged[intentPath] = source
	}
	desiredChannelPaths := make(map[string]struct{}, len(publication.request.Generation.Channels))
	for _, channel := range publication.request.Generation.Channels {
		body, err := channel.CanonicalBody()
		if err != nil || digestBytesCLI(body) != channel.BodySHA256 {
			return plumbing.ZeroHash, errors.Join(err, errors.New("canonical channel body disagrees with target generation"))
		}
		channelPath := filepath.Join(persistDir, "channels", channel.View, channel.Repo, channel.OS, channel.Arch+".json")
		if err := os.MkdirAll(filepath.Dir(channelPath), 0o700); err != nil {
			return plumbing.ZeroHash, err
		}
		if err := writeExclusiveBytes(channelPath, body); err != nil {
			return plumbing.ZeroHash, err
		}
		canonicalChannelPath := remoteStatePath(publication.target, filepath.ToSlash(filepath.Join("channels", channel.View, channel.Repo, channel.OS, channel.Arch+".json")))
		staged[canonicalChannelPath] = channelPath
		desiredChannelPaths[canonicalChannelPath] = struct{}{}
	}
	channelPrefix := remoteStatePath(publication.target, "channels") + "/"
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return plumbing.ZeroHash, errors.Join(err, errors.New("enumerate canonical channel state without an initialized HEAD"))
	}
	existingChannelPaths, err := canonical.ListFilesAt(head, channelPrefix)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("enumerate canonical target channels: %w", err)
	}
	deleteChannelPaths := make([]string, 0, len(existingChannelPaths))
	for _, existing := range existingChannelPaths {
		if _, retained := desiredChannelPaths[existing]; !retained {
			deleteChannelPaths = append(deleteChannelPaths, existing)
		}
	}
	updates := make([]state.RefUpdate, 0, len(publication.request.Generation.Refs))
	desiredRemoteRefs := make(map[plumbing.ReferenceName]struct{}, len(publication.request.Generation.Refs))
	for _, desired := range publication.request.Generation.Refs {
		remoteRef, err := desiredToRemoteRef(publication.target, desired.Name)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		expected, _, err := canonical.Ref(remoteRef)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		desiredRemoteRefs[remoteRef] = struct{}{}
		updates = append(updates, state.RefUpdate{Name: remoteRef, Expected: expected, Target: plumbing.NewHash(desired.Commit)})
	}
	allRefs, err := canonical.SOWRefs()
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("enumerate canonical remote refs: %w", err)
	}
	remotePrefix := "refs/sow/remotes/" + publication.target + "/"
	for _, current := range allRefs {
		if !strings.HasPrefix(current.Name.String(), remotePrefix) {
			continue
		}
		if _, retained := desiredRemoteRefs[current.Name]; retained {
			continue
		}
		updates = append(updates, state.RefUpdate{Name: current.Name, Expected: current.Hash, Delete: true})
	}
	sort.Slice(updates, func(i, j int) bool { return updates[i].Name < updates[j].Name })
	if err := publication.requireTrust(cfg, pub.TrustBeforeLocalPersist); err != nil {
		return plumbing.ZeroHash, err
	}
	commit, changed, err := applyCanonicalConfig(ctx, cfg, canonical, operation, message, staged, updates, state.ApplyOptions{DeletePaths: deleteChannelPaths})
	if err != nil {
		return commit, err
	}
	if !changed {
		return commit, errors.New("remote generation advanced without a canonical state change")
	}
	if err := publication.requireTrust(cfg, pub.TrustAfterLocalPersist); err != nil {
		return commit, err
	}
	return commit, nil
}

func stagePublishedPurgeEvidence(publication targetPublication, result pub.Result, persistDir string) (string, string, error) {
	if len(publication.request.Plan.PurgeURLs) == 0 {
		if result.PurgeEvidencePath != "" || result.PurgeEvidenceSHA256 != "" {
			return "", "", errors.New("purge-free publication returned unexpected purge evidence")
		}
		return "", "", nil
	}
	if result.PurgeEvidencePath == "" || result.PurgeEvidenceSHA256 == "" {
		return "", "", errors.New("publication with mandatory purge has no durable provider evidence")
	}
	evidence, body, err := pub.LoadPurgeEvidenceFile(result.PurgeEvidencePath)
	if err != nil {
		return "", "", err
	}
	planSHA, err := publication.request.Plan.Digest()
	if err != nil {
		return "", "", err
	}
	urlsSHA, err := pub.PurgeURLsDigest(publication.request.Plan.PurgeURLs)
	if err != nil {
		return "", "", err
	}
	if evidence.Target != pub.TargetName(publication.target) || evidence.TransactionID != publication.request.TransactionID ||
		evidence.Generation != publication.request.Generation.Generation || evidence.GenerationSHA256 != result.GenerationSHA256 ||
		evidence.PlanSHA256 != planSHA || evidence.CheckpointSHA256 != result.CheckpointSHA256 ||
		evidence.URLCount != len(publication.request.Plan.PurgeURLs) || evidence.URLsSHA256 != urlsSHA ||
		digestBytesCLI(body) != result.PurgeEvidenceSHA256 {
		return "", "", errors.New("purge evidence disagrees with the committed publication")
	}
	latestFullAttempt := uint64(0)
	for _, attempt := range evidence.Attempts {
		if attempt.Purpose == pub.PurgeAttemptFull {
			latestFullAttempt = attempt.ID
		}
	}
	if latestFullAttempt == 0 {
		return "", "", errors.New("purge evidence contains no full closure")
	}
	if err := evidence.ValidateFullClosure(latestFullAttempt, publication.request.Plan.PurgeURLs); err != nil {
		return "", "", fmt.Errorf("validate latest purge closure: %w", err)
	}
	stagedPath := filepath.Join(persistDir, "purge-evidence.json")
	if err := writeExclusiveBytes(stagedPath, body); err != nil {
		return "", "", err
	}
	statePath := remoteStatePath(publication.target, filepath.ToSlash(filepath.Join(
		"purges",
		fmt.Sprintf("%020d-%s.json", publication.request.Generation.Generation, publication.request.TransactionID),
	)))
	return stagedPath, statePath, nil
}

func targetFailure(err error, target pub.TargetName) error {
	var multi *pub.MultiTargetError
	if errors.As(err, &multi) {
		if targetErr, exists := multi.Failures[target]; exists {
			return targetErr
		}
	}
	return err
}

func publishTargetExitError(err error) error {
	var coded *exitError
	if errors.As(err, &coded) {
		return err
	}
	if errors.Is(err, pub.ErrConflict) || errors.Is(err, pub.ErrDrift) || errors.Is(err, pub.ErrJournalConflict) || errors.Is(err, pub.ErrCapability) {
		return withExitCode(ExitConflict, "%v", err)
	}
	if errors.Is(err, pub.ErrVerification) {
		return withExitCode(ExitVerification, "%v", err)
	}
	return withExitCode(ExitNetworkAuth, "%v", err)
}

func redactPublishError(err error) string {
	if err == nil {
		return "unknown"
	}
	// Provider and publish errors already redact response bodies and bearer
	// segments. Bound the operator-facing value to avoid logging accidental
	// oversized wrappers from an HTTP stack.
	value := err.Error()
	if len(value) > 1024 {
		value = value[:1024] + "..."
	}
	return value
}
