package managed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/v2/state"
	"golang.org/x/sys/unix"
)

const (
	localGCSchema       = "sow/local-gc/v1"
	localGCPlanName     = "plan.json"
	localGCPayloadDir   = "payload"
	maxLocalGCPlanBytes = 64 << 20
)

// LocalGCPublicationRootProvider attests a complete exact root set against one
// state-backed publication evidence identity. Nil is legal only when SQLite
// contains no target/attempt/checkpoint/grace/report evidence.
type LocalGCPublicationRootProvider interface {
	LocalGCPayloadRoots(context.Context, LocalGCPublicationRootQuery) (LocalGCPublicationRootAttestation, error)
}

type LocalGCPublicationRootQuery struct {
	Repository       string
	RepositoryID     string
	Generation       state.GenerationID
	EvidenceIdentity string
	StateComplete    bool
	MinimumRoots     []state.GenerationFile
}

type LocalGCPublicationRootAttestation struct {
	EvidenceIdentity string
	Complete         bool
	Roots            []state.GenerationFile
}

type LocalGCOptions struct {
	WorkspaceOptions
	LockOptions
	Repository       string
	PublicationRoots LocalGCPublicationRootProvider
	Fault            func(string) error
}

type LocalGCResult struct {
	Operation      string             `json:"operation,omitempty"`
	Repository     string             `json:"repository"`
	BaseGeneration state.GenerationID `json:"base_generation"`
	Generation     state.GenerationID `json:"generation"`
	Objects        int                `json:"objects"`
	Bytes          int64              `json:"bytes"`
	Noop           bool               `json:"noop"`
}

type localGCEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type localGCPlan struct {
	Schema             string                 `json:"schema"`
	Repository         string                 `json:"repository"`
	RepositoryID       string                 `json:"repository_id"`
	OperationID        string                 `json:"operation_id"`
	BaseGeneration     state.GenerationID     `json:"base_generation"`
	Generation         state.GenerationID     `json:"generation"`
	BaseManifestSHA256 string                 `json:"base_manifest_sha256"`
	ManifestSHA256     string                 `json:"manifest_sha256"`
	Entries            []localGCEntry         `json:"entries"`
	Objects            []state.PackageObject  `json:"objects"`
	Manifest           []state.GenerationFile `json:"manifest"`
	Changes            []state.FileChange     `json:"changes"`
}

type localGCOperationPayload struct {
	Schema       string             `json:"schema"`
	Repository   string             `json:"repository"`
	RepositoryID string             `json:"repository_id"`
	OperationID  string             `json:"operation_id"`
	Base         state.GenerationID `json:"base_generation"`
	Generation   state.GenerationID `json:"generation"`
	PlanSHA256   string             `json:"plan_sha256"`
}

func LocalGC(ctx context.Context, opts LocalGCOptions) (result LocalGCResult, resultErr error) {
	if ctx == nil {
		return result, fmt.Errorf("%w: nil local GC context", ErrRejected)
	}
	ws, _, rootGuard, err := workspace(opts.WorkspaceOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	_, _, repoName, workspaceLock, repoLock, err := acquireSelectedRepositoryLocks(ctx, ws, opts.Repository, opts.LockOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close(), repoLock.Close()) }()
	result.Repository = repoName
	if err := validateRepositoryLayout(ws.Root, repoName); err != nil {
		return result, err
	}
	store, err := openExistingState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	if err := store.RequireTerminalLayout(ctx); err != nil {
		return result, err
	}
	if err := recoverDistOperations(ctx, ws.Root, repoName, store); err != nil {
		return result, err
	}
	if err := validateCurrentPublicGeneration(ctx, ws.Root, repoName, store); err != nil {
		return result, err
	}
	if err := requireLocalGCPrivateRootsSettled(ws.Root, repoName); err != nil {
		return result, err
	}
	inventory, err := store.LocalGCInventory(ctx)
	if err != nil {
		return result, fmt.Errorf("%w: local GC inventory: %v", ErrIntegrity, err)
	}
	result.BaseGeneration, result.Generation = inventory.Generation, inventory.Generation

	allObjects, err := store.ListPackageObjects(ctx, nil, false)
	if err != nil {
		return result, err
	}
	objectByPath := make(map[string]state.PackageObject, len(allObjects))
	for _, object := range allObjects {
		if _, duplicate := objectByPath[object.PoolPath]; duplicate || object.Storage != "pool" {
			return result, fmt.Errorf("%w: package object inventory is not a unique physical Pool map", ErrIntegrity)
		}
		objectByPath[object.PoolPath] = object
	}
	protected, err := verifiedRetainedPayloadRootsLocked(ctx, ws.Root, repoName, inventory.RepositoryID, objectByPath)
	if err != nil {
		return result, err
	}
	requirement, err := store.PublicationRootRequirement(ctx)
	if err != nil {
		return result, fmt.Errorf("%w: publication root requirement: %v", ErrIntegrity, err)
	}
	if !requirement.StateComplete {
		return result, fmt.Errorf("%w: state-backed publication root attestation is incomplete", ErrIntegrity)
	}
	// The state attestor is always present and is sufficient for binding-only
	// evidence. Nonterminal attempts root their source Generation; unresolved
	// applied/grace checkpoints additionally root their observed payload inventory.
	if err := mergeLocalGCPayloadRoots(protected, requirement.MinimumRoots, objectByPath, "publication state"); err != nil {
		return result, err
	}
	if opts.PublicationRoots != nil {
		attestation, err := opts.PublicationRoots.LocalGCPayloadRoots(ctx, LocalGCPublicationRootQuery{
			Repository: repoName, RepositoryID: inventory.RepositoryID, Generation: inventory.Generation,
			EvidenceIdentity: requirement.EvidenceIdentity, StateComplete: requirement.StateComplete,
			MinimumRoots: append([]state.GenerationFile(nil), requirement.MinimumRoots...),
		})
		if err != nil {
			return result, fmt.Errorf("%w: publication roots are unavailable: %v", ErrIntegrity, err)
		}
		if !attestation.Complete || attestation.EvidenceIdentity != requirement.EvidenceIdentity {
			return result, fmt.Errorf("%w: publication root attestation is incomplete or bound to stale evidence", ErrIntegrity)
		}
		if err := requireAttestedMinimumRoots(attestation.Roots, requirement.MinimumRoots); err != nil {
			return result, err
		}
		if err := mergeLocalGCPayloadRoots(protected, attestation.Roots, objectByPath, "publication"); err != nil {
			return result, err
		}
	}
	candidates := make([]state.PackageObject, 0, len(inventory.Candidates))
	for _, object := range inventory.Candidates {
		if _, keep := protected[object.PoolPath]; !keep {
			candidates = append(candidates, object)
		}
	}
	if len(candidates) == 0 {
		result.Noop = true
		return result, nil
	}
	baseManifest, err := store.GenerationManifest(ctx, inventory.Generation)
	if err != nil {
		return result, err
	}
	plan, planBytes, err := buildLocalGCPlan(repoName, inventory, candidates, baseManifest)
	if err != nil {
		return result, err
	}
	payload := localGCOperationPayload{
		Schema: localGCSchema, Repository: repoName, RepositoryID: inventory.RepositoryID, OperationID: plan.OperationID,
		Base: plan.BaseGeneration, Generation: plan.Generation, PlanSHA256: bytesSHA(planBytes),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return result, err
	}
	if err := store.BeginOperation(ctx, state.Operation{ID: plan.OperationID, Kind: "local.gc", State: state.OperationPlanned, PayloadJSON: string(payloadBytes)}); err != nil {
		return result, err
	}
	recoveryRoot := localGCRecoveryRoot(ws.Root, repoName, plan.OperationID)
	if err := durableMkdir(recoveryRoot, 0o700); err != nil {
		return result, err
	}
	if err := writeRootedNewRegular(recoveryRoot, localGCPlanName, planBytes, 0o600); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "gc.planned"); err != nil {
		return result, err
	}
	if err := store.SetOperationState(ctx, plan.OperationID, state.OperationStaged, ""); err != nil {
		return result, err
	}
	if err := applyLocalGCPlan(ctx, ws.Root, repoName, store, plan, opts.Fault); err != nil {
		return result, err
	}
	result = localGCResult(plan)
	return result, nil
}

func buildLocalGCPlan(repoName string, inventory state.LocalGCInventory, candidates []state.PackageObject, base []state.GenerationFile) (localGCPlan, []byte, error) {
	id, err := operationID()
	if err != nil {
		return localGCPlan{}, nil, err
	}
	next, err := inventory.Generation.Next()
	if err != nil {
		return localGCPlan{}, nil, err
	}
	baseBytes, baseSHA, err := state.ManifestBytes(base)
	if err != nil || len(baseBytes) == 0 {
		return localGCPlan{}, nil, errors.Join(errors.New("local GC has no canonical base manifest"), err)
	}
	byPath := make(map[string]state.PackageObject, len(candidates))
	for _, object := range candidates {
		if object.Storage != "pool" || object.PoolPath == "" || object.Size < 0 || !lowercaseSHA256.MatchString(object.SHA256) {
			return localGCPlan{}, nil, errors.New("local GC candidate identity is invalid")
		}
		if _, duplicate := byPath[object.PoolPath]; duplicate {
			return localGCPlan{}, nil, errors.New("local GC candidates repeat a Pool path")
		}
		byPath[object.PoolPath] = object
	}
	target := make([]state.GenerationFile, 0, len(base)-len(candidates))
	entries := make([]localGCEntry, 0, len(candidates))
	for _, file := range base {
		object, remove := byPath[file.Path]
		if !remove {
			target = append(target, file)
			continue
		}
		if file.Phase != "payload" || file.Size != object.Size || file.SHA256 != object.SHA256 {
			return localGCPlan{}, nil, fmt.Errorf("%w: candidate %q differs from current Generation", ErrIntegrity, file.Path)
		}
		entries = append(entries, localGCEntry{Path: file.Path, Size: file.Size, SHA256: file.SHA256})
		delete(byPath, file.Path)
	}
	if len(byPath) != 0 {
		return localGCPlan{}, nil, fmt.Errorf("%w: a candidate is absent from current Generation", ErrIntegrity)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].PoolPath < candidates[j].PoolPath })
	_, targetSHA, err := state.ManifestBytes(target)
	if err != nil {
		return localGCPlan{}, nil, err
	}
	plan := localGCPlan{
		Schema: localGCSchema, Repository: repoName, RepositoryID: inventory.RepositoryID, OperationID: id,
		BaseGeneration: inventory.Generation, Generation: next, BaseManifestSHA256: baseSHA, ManifestSHA256: targetSHA,
		Entries: entries, Objects: candidates, Manifest: target, Changes: state.DiffManifests(base, target),
	}
	planBytes, err := json.Marshal(plan)
	if err != nil || len(planBytes) > maxLocalGCPlanBytes {
		return localGCPlan{}, nil, errors.Join(fmt.Errorf("%w: local GC plan exceeds its bound", ErrRejected), err)
	}
	return plan, planBytes, nil
}

func parseLocalGCPlan(data []byte) (localGCPlan, error) {
	if len(data) == 0 || len(data) > maxLocalGCPlanBytes {
		return localGCPlan{}, errors.New("local GC plan is empty or unbounded")
	}
	if err := rejectDuplicateJSONMembers(data); err != nil {
		return localGCPlan{}, err
	}
	var plan localGCPlan
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return localGCPlan{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return localGCPlan{}, errors.New("local GC plan has trailing content")
	}
	canonical, err := json.Marshal(plan)
	if err != nil || !bytes.Equal(canonical, data) {
		return localGCPlan{}, errors.Join(errors.New("local GC plan is not canonical JSON"), err)
	}
	if err := validateLocalGCPlan(plan); err != nil {
		return localGCPlan{}, err
	}
	return plan, nil
}

func validateLocalGCPlan(plan localGCPlan) error {
	if plan.Schema != localGCSchema || configNameInvalid(plan.Repository) || !state.IsCanonicalRepositoryID(plan.RepositoryID) ||
		!validStoredOperationID(plan.OperationID) || plan.BaseGeneration == 0 || plan.Generation == 0 ||
		!lowercaseSHA256.MatchString(plan.BaseManifestSHA256) || !lowercaseSHA256.MatchString(plan.ManifestSHA256) ||
		len(plan.Entries) == 0 || len(plan.Entries) != len(plan.Objects) {
		return errors.New("invalid local GC plan header")
	}
	next, err := plan.BaseGeneration.Next()
	if err != nil || plan.Generation != next {
		return errors.New("invalid local GC plan Generation sequence")
	}
	_, targetSHA, err := state.ManifestBytes(plan.Manifest)
	if err != nil || targetSHA != plan.ManifestSHA256 {
		return errors.Join(errors.New("local GC target manifest differs from plan"), err)
	}
	for index, entry := range plan.Entries {
		object := plan.Objects[index]
		if entry.Path == "" || filepath.ToSlash(filepath.Clean(filepath.FromSlash(entry.Path))) != entry.Path || !strings.HasPrefix(entry.Path, "pool/") ||
			entry.Size < 0 || !lowercaseSHA256.MatchString(entry.SHA256) || index > 0 && plan.Entries[index-1].Path >= entry.Path ||
			object.PoolPath != entry.Path || object.Size != entry.Size || object.SHA256 != entry.SHA256 || object.Storage != "pool" {
			return fmt.Errorf("invalid local GC entry %d", index)
		}
	}
	return nil
}

func applyLocalGCPlan(ctx context.Context, root, repoName string, store *state.Store, plan localGCPlan, fault func(string) error) error {
	if err := validateLocalGCRecoveryInventory(ctx, root, repoName, plan); err != nil {
		return err
	}
	for _, entry := range plan.Entries {
		public := filepath.Join(repoName, filepath.FromSlash(entry.Path))
		tombstone := filepath.Join(".sow", repoName, "recovery", plan.OperationID, localGCPayloadDir, filepath.FromSlash(entry.Path))
		publicOK, err := exactLocalGCFile(ctx, root, public, entry.Size, entry.SHA256)
		if err != nil {
			return err
		}
		tombstoneOK, err := exactLocalGCFile(ctx, root, tombstone, entry.Size, entry.SHA256)
		if err != nil {
			return err
		}
		switch {
		case publicOK && !tombstoneOK:
			if err := renameRootedRegular(ctx, root, public, tombstone, entry.Size, entry.SHA256, 0o600, 0o700); err != nil {
				return err
			}
		case publicOK && tombstoneOK:
			if err := removeRootedRegularExact(ctx, root, public, entry.Size, entry.SHA256); err != nil {
				return err
			}
		case !publicOK && tombstoneOK:
			// Already detached by an interrupted invocation.
		default:
			return fmt.Errorf("%w: local GC payload %q is absent from both public and recovery paths", ErrIntegrity, entry.Path)
		}
		if err := callFault(fault, "gc.detached."+entry.Path); err != nil {
			return err
		}
	}
	operation, err := store.GetOperation(ctx, plan.OperationID)
	if err != nil {
		return err
	}
	if operation.Operation.State == state.OperationStaged || operation.Operation.State == state.OperationRecovering {
		if err := store.SetOperationState(ctx, plan.OperationID, state.OperationApplied, ""); err != nil {
			return err
		}
	}
	if err := callFault(fault, "gc.applied"); err != nil {
		return err
	}
	if err := store.FinalizeLocalGC(ctx, state.FinalizeLocalGCInput{
		OperationID: plan.OperationID, RepositoryID: plan.RepositoryID, BaseGeneration: plan.BaseGeneration,
		Generation: plan.Generation, Objects: plan.Objects, Manifest: plan.Manifest, Changes: plan.Changes,
	}); err != nil {
		return err
	}
	if err := callFault(fault, "gc.committed"); err != nil {
		return err
	}
	return cleanupLocalGCPlan(ctx, root, repoName, plan, fault)
}

func recoverLocalGCOperation(ctx context.Context, root, repoName string, store *state.Store, operation state.Operation) error {
	payload, err := decodeLocalGCOperationPayload(operation.PayloadJSON)
	if err != nil || payload.Repository != repoName || payload.OperationID != operation.ID {
		return errors.Join(fmt.Errorf("%w: invalid pending local GC payload", ErrIntegrity), err)
	}
	recoveryRoot := localGCRecoveryRoot(root, repoName, operation.ID)
	if info, statErr := os.Lstat(recoveryRoot); errors.Is(statErr, os.ErrNotExist) {
		if operation.State != state.OperationPlanned {
			return fmt.Errorf("%w: pending local GC lacks its recovery directory", ErrIntegrity)
		}
		return store.SetOperationState(ctx, operation.ID, state.OperationRolledBack, "")
	} else if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(fmt.Errorf("%w: local GC recovery directory is unsafe", ErrIntegrity), statErr)
	}
	data, readErr := readRootedPrivateRegular(recoveryRoot, localGCPlanName, maxLocalGCPlanBytes, false)
	if errors.Is(readErr, os.ErrNotExist) || errors.Is(readErr, unix.ENOENT) {
		if operation.State != state.OperationPlanned {
			return fmt.Errorf("%w: pending local GC lacks its immutable plan", ErrIntegrity)
		}
		if info, statErr := os.Lstat(recoveryRoot); statErr == nil {
			entries, listErr := os.ReadDir(recoveryRoot)
			if listErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || len(entries) != 0 {
				return errors.Join(fmt.Errorf("%w: planless local GC recovery directory is not empty", ErrIntegrity), listErr)
			}
			if err := removeRootedEmptyDirectory(filepath.Join(root, ".sow", repoName, "recovery"), operation.ID); err != nil {
				return err
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		return store.SetOperationState(ctx, operation.ID, state.OperationRolledBack, "")
	}
	if readErr != nil {
		return readErr
	}
	plan, err := parseLocalGCPlan(data)
	if err != nil || bytesSHA(data) != payload.PlanSHA256 || plan.Repository != payload.Repository || plan.RepositoryID != payload.RepositoryID ||
		plan.OperationID != payload.OperationID || plan.BaseGeneration != payload.Base || plan.Generation != payload.Generation {
		return errors.Join(fmt.Errorf("%w: local GC plan differs from operation journal", ErrIntegrity), err)
	}
	if operation.State == state.OperationPlanned {
		if err := store.SetOperationState(ctx, operation.ID, state.OperationStaged, ""); err != nil {
			return err
		}
	}
	return applyLocalGCPlan(ctx, root, repoName, store, plan, nil)
}

func recoverDoneLocalGCCleanup(ctx context.Context, root, repoName string, operation state.Operation) error {
	payload, err := decodeLocalGCOperationPayload(operation.PayloadJSON)
	if err != nil || payload.Repository != repoName || payload.OperationID != operation.ID {
		return errors.Join(fmt.Errorf("%w: invalid completed local GC payload", ErrIntegrity), err)
	}
	recoveryRoot := localGCRecoveryRoot(root, repoName, operation.ID)
	if info, statErr := os.Lstat(recoveryRoot); errors.Is(statErr, os.ErrNotExist) {
		return nil
	} else if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(fmt.Errorf("%w: completed local GC recovery directory is unsafe", ErrIntegrity), statErr)
	}
	data, err := readRootedPrivateRegular(recoveryRoot, localGCPlanName, maxLocalGCPlanBytes, false)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		entries, listErr := listRootedDirectory(recoveryRoot)
		if listErr != nil {
			return fmt.Errorf("%w: inspect planless completed local GC recovery root: %v", ErrIntegrity, listErr)
		}
		if len(entries) != 0 {
			return fmt.Errorf("%w: completed local GC recovery remainder lacks its plan and is not empty", ErrIntegrity)
		}
		return removeRootedEmptyDirectory(filepath.Join(root, ".sow", repoName, "recovery"), operation.ID)
	}
	if err != nil {
		return err
	}
	plan, err := parseLocalGCPlan(data)
	if err != nil || bytesSHA(data) != payload.PlanSHA256 {
		return errors.Join(fmt.Errorf("%w: completed local GC plan differs from journal", ErrIntegrity), err)
	}
	return cleanupLocalGCPlan(ctx, root, repoName, plan, nil)
}

func cleanupLocalGCPlan(ctx context.Context, root, repoName string, plan localGCPlan, fault func(string) error) error {
	recoveryRoot := localGCRecoveryRoot(root, repoName, plan.OperationID)
	if err := validateLocalGCRecoveryInventory(ctx, root, repoName, plan); err != nil {
		return err
	}
	directories := map[string]struct{}{localGCPayloadDir: {}}
	for _, entry := range plan.Entries {
		relative := filepath.Join(localGCPayloadDir, filepath.FromSlash(entry.Path))
		if err := removeRootedRegularExact(ctx, recoveryRoot, relative, entry.Size, entry.SHA256); err != nil {
			return err
		}
		for parent := filepath.Dir(relative); parent != "."; parent = filepath.Dir(parent) {
			directories[parent] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(directories))
	for directory := range directories {
		ordered = append(ordered, directory)
	}
	sort.Slice(ordered, func(i, j int) bool {
		left, right := strings.Count(ordered[i], string(filepath.Separator)), strings.Count(ordered[j], string(filepath.Separator))
		if left != right {
			return left > right
		}
		return ordered[i] > ordered[j]
	})
	for _, directory := range ordered {
		if err := removeRootedEmptyDirectory(recoveryRoot, directory); err != nil {
			return fmt.Errorf("%w: local GC recovery directory %q is not empty: %v", ErrIntegrity, directory, err)
		}
	}
	planData, err := readRootedPrivateRegular(recoveryRoot, localGCPlanName, maxLocalGCPlanBytes, false)
	if err != nil {
		return err
	}
	if _, err := parseLocalGCPlan(planData); err != nil {
		return err
	}
	if err := removeRootedRegularExact(ctx, recoveryRoot, localGCPlanName, int64(len(planData)), bytesSHA(planData)); err != nil {
		return err
	}
	if err := callFault(fault, "gc.plan_unlinked"); err != nil {
		return err
	}
	return removeRootedEmptyDirectory(filepath.Join(root, ".sow", repoName, "recovery"), plan.OperationID)
}

func validateLocalGCRecoveryInventory(ctx context.Context, root, repoName string, plan localGCPlan) error {
	recoveryRoot := localGCRecoveryRoot(root, repoName, plan.OperationID)
	expectedFiles := map[string]localGCEntry{}
	planData, err := readRootedPrivateRegular(recoveryRoot, localGCPlanName, maxLocalGCPlanBytes, false)
	if err != nil {
		return err
	}
	expectedFiles[localGCPlanName] = localGCEntry{Path: localGCPlanName, Size: int64(len(planData)), SHA256: bytesSHA(planData)}
	expectedDirs := map[string]struct{}{localGCPayloadDir: {}}
	for _, entry := range plan.Entries {
		path := filepath.ToSlash(filepath.Join(localGCPayloadDir, filepath.FromSlash(entry.Path)))
		expectedFiles[path] = localGCEntry{Path: path, Size: entry.Size, SHA256: entry.SHA256}
		for parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(path))); parent != "."; parent = filepath.ToSlash(filepath.Dir(filepath.FromSlash(parent))) {
			expectedDirs[parent] = struct{}{}
		}
	}
	err = walkRootedTree(ctx, recoveryRoot, func(relative string, file *os.File, info os.FileInfo) error {
		path := filepath.ToSlash(relative)
		expected, exists := expectedFiles[path]
		if !exists || info.Size() != expected.Size {
			return fmt.Errorf("%w: unknown or changed local GC recovery file %q", ErrIntegrity, path)
		}
		digest, err := hashRegularDescriptor(ctx, file)
		if err != nil || digest != expected.SHA256 {
			return errors.Join(fmt.Errorf("%w: changed local GC recovery file %q", ErrIntegrity, path), err)
		}
		return nil
	}, func(relative string, _ *os.File, _ os.FileInfo) error {
		path := filepath.ToSlash(relative)
		if path == "" {
			return nil
		}
		if _, exists := expectedDirs[path]; !exists {
			return fmt.Errorf("%w: unknown local GC recovery directory %q", ErrIntegrity, path)
		}
		return nil
	})
	return err
}

func verifiedRetainedPayloadRootsLocked(ctx context.Context, root, repoName, repositoryID string, objects map[string]state.PackageObject) (map[string]state.GenerationFile, error) {
	protected := map[string]state.GenerationFile{}
	entries, err := listRootedDirectory(filepath.Join(root, ".sow", repoName, "retained"))
	if err != nil {
		return nil, fmt.Errorf("%w: retained inventory is unavailable: %v", ErrIntegrity, err)
	}
	for _, entry := range entries {
		generation, err := state.ParseGenerationID(entry.Name)
		if err != nil || generation == 0 || uint32(entry.Stat.Mode)&unix.S_IFMT != unix.S_IFDIR {
			return nil, fmt.Errorf("%w: non-canonical retained entry %q", ErrIntegrity, entry.Name)
		}
		if _, err := verifyRetainedGenerationLocked(ctx, root, repoName, generation, repositoryID); err != nil {
			return nil, err
		}
		data, err := readRootedPrivateRegular(filepath.Join(root, ".sow", repoName, "retained", generation.String()), "manifest.tsv", maxRetainedManifestBytes, true)
		if err != nil {
			return nil, err
		}
		manifest, err := parseRetainedManifest(data)
		if err != nil {
			return nil, err
		}
		if err := mergeLocalGCPayloadRoots(protected, manifest, objects, "retained"); err != nil {
			return nil, err
		}
	}
	return protected, nil
}

func mergeLocalGCPayloadRoots(protected map[string]state.GenerationFile, roots []state.GenerationFile, objects map[string]state.PackageObject, source string) error {
	for _, file := range roots {
		if file.Phase != "payload" {
			continue
		}
		object, exists := objects[file.Path]
		if !exists || object.Size != file.Size || object.SHA256 != file.SHA256 {
			return fmt.Errorf("%w: %s payload root %q is unknown or drifted", ErrIntegrity, source, file.Path)
		}
		if prior, duplicate := protected[file.Path]; duplicate && prior != file {
			return fmt.Errorf("%w: conflicting payload roots for %q", ErrIntegrity, file.Path)
		}
		protected[file.Path] = file
	}
	return nil
}

func requireAttestedMinimumRoots(attested, minimum []state.GenerationFile) error {
	byPath := make(map[string]state.GenerationFile, len(attested))
	for _, file := range attested {
		if file.Phase != "payload" {
			return fmt.Errorf("%w: publication attestation contains non-payload root %q", ErrIntegrity, file.Path)
		}
		if prior, duplicate := byPath[file.Path]; duplicate && prior != file {
			return fmt.Errorf("%w: publication attestation conflicts for %q", ErrIntegrity, file.Path)
		}
		byPath[file.Path] = file
	}
	for _, required := range minimum {
		if got, ok := byPath[required.Path]; !ok || got != required {
			return fmt.Errorf("%w: publication attestation omits or drifts required payload %q", ErrIntegrity, required.Path)
		}
	}
	return nil
}

func requireLocalGCPrivateRootsSettled(root, repoName string) error {
	for _, child := range []string{"stage", "pending", "recovery", "transitions"} {
		entries, err := listRootedDirectory(filepath.Join(root, ".sow", repoName, child))
		if err != nil {
			return fmt.Errorf("%w: local GC private root %q is unavailable: %v", ErrIntegrity, child, err)
		}
		if len(entries) != 0 {
			return fmt.Errorf("%w: local GC private root %q is not settled", ErrIntegrity, child)
		}
	}
	return nil
}

func decodeLocalGCOperationPayload(data string) (localGCOperationPayload, error) {
	var payload localGCOperationPayload
	decoder := json.NewDecoder(strings.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return payload, errors.New("local GC payload has trailing content")
	}
	if payload.Schema != localGCSchema || configNameInvalid(payload.Repository) || !state.IsCanonicalRepositoryID(payload.RepositoryID) ||
		!validStoredOperationID(payload.OperationID) || payload.Base == 0 || payload.Generation == 0 || !lowercaseSHA256.MatchString(payload.PlanSHA256) {
		return payload, errors.New("invalid local GC operation payload")
	}
	return payload, nil
}

func exactLocalGCFile(ctx context.Context, root, relative string, size int64, digest string) (bool, error) {
	opened, err := openRootedRegular(root, relative)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) || strings.Contains(errString(err), "no such file or directory") {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: inspect local GC path %q: %v", ErrIntegrity, relative, err)
	}
	actual, hashErr := hashRegularDescriptor(ctx, opened.file)
	closeErr := opened.CloseVerified()
	if hashErr != nil || closeErr != nil || opened.before.Size() != size || actual != digest {
		return false, errors.Join(fmt.Errorf("%w: local GC path %q differs from its plan", ErrIntegrity, relative), hashErr, closeErr)
	}
	return true, nil
}

func localGCRecoveryRoot(root, repoName, operationID string) string {
	return filepath.Join(root, ".sow", repoName, "recovery", operationID)
}

func localGCResult(plan localGCPlan) LocalGCResult {
	result := LocalGCResult{Operation: plan.OperationID, Repository: plan.Repository, BaseGeneration: plan.BaseGeneration, Generation: plan.Generation, Objects: len(plan.Entries)}
	for _, entry := range plan.Entries {
		result.Bytes += entry.Size
	}
	return result
}

func configNameInvalid(value string) bool {
	return value == "" || filepath.Base(value) != value || value == "." || value == ".." || strings.ContainsAny(value, "/\\\x00")
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
