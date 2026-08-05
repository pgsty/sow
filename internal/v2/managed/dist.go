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
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

const distOperationVersion = 2

type distOperationPayload struct {
	Version                      int                            `json:"version"`
	Repository                   string                         `json:"repository"`
	Name                         string                         `json:"name"`
	Format                       string                         `json:"format"`
	Architectures                []state.Architecture           `json:"architectures"`
	Generation                   int64                          `json:"generation"`
	EffectiveConfigSHA256        string                         `json:"effective_config_sha256"`
	EffectiveSigning             *config.EffectiveSigningConfig `json:"effective_signing,omitempty"`
	MetadataSignerSnapshotSHA256 string                         `json:"metadata_signer_snapshot_sha256,omitempty"`
	OldConfigSHA256              string                         `json:"old_config_sha256"`
	NewConfigSHA256              string                         `json:"new_config_sha256"`
	NewConfig                    []byte                         `json:"new_config"`
	TreeSHA256                   string                         `json:"tree_sha256"`
}

func ListDists(ctx context.Context, opts DistListOptions) (result []DistInfo, resultErr error) {
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts.WorkspaceOptions, true)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	repoName, err := selectRepo(ws, cfg, opts.Repository)
	if err != nil {
		return nil, err
	}
	repoLock, err := acquireSharedFileLock(ctx, filepath.Join(ws.Root, ".sow", "repo-locks", repoName+".lock"))
	if err != nil {
		return nil, classifyReadLockError(fmt.Sprintf("acquire repository %q read lock", repoName), err)
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	if err := validateRepositoryLayout(ws.Root, repoName); err != nil {
		return nil, err
	}
	if _, err := validateReadOnlyStateRoot(ws.Root, false); err != nil {
		return nil, err
	}
	store, err := openReadOnlyState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	dists, err := store.ListDists(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: list repository Dist state: %v", ErrIntegrity, err)
	}
	result = make([]DistInfo, 0, len(dists))
	seen := make(map[string]struct{}, len(dists))
	for _, dist := range dists {
		info, err := makeDistInfo(ctx, store, ws.Root, repoName, cfg, dist)
		if err != nil {
			return nil, fmt.Errorf("%w: inspect Dist %q state: %v", ErrIntegrity, dist.Name, err)
		}
		result = append(result, info)
		seen[dist.Name] = struct{}{}
	}
	for _, name := range sortedDistConfigNames(cfg.Repositories[repoName]) {
		if _, ok := seen[name]; ok {
			continue
		}
		if err := rejectUninitializedDistAdoption(ws.Root, repoName, name); err != nil {
			return nil, err
		}
		configured := cfg.Repositories[repoName].Dists[name]
		architectures, err := configuredArchitectureState(cfg, repoName, name, configured.Format)
		if err != nil {
			return nil, err
		}
		effectiveView, err := config.EffectiveView(cfg, config.ViewOptions{Repository: repoName, Dist: name})
		if err != nil {
			return nil, err
		}
		effectiveConfig := effectiveView.Repositories[repoName].Dists[name]
		result = append(result, DistInfo{Name: name, Format: configured.Format, Architectures: architectures, Dirty: true, Status: "dirty", DirtyReasons: []string{"configured dist is not initialized"}, Config: effectiveConfig})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func ShowDist(ctx context.Context, opts DistShowOptions) (result DistInfo, resultErr error) {
	if err := config.ValidateName(opts.Name); err != nil {
		return DistInfo{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts.WorkspaceOptions, true)
	if err != nil {
		return DistInfo{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	repoName, err := selectRepo(ws, cfg, opts.Repository)
	if err != nil {
		return DistInfo{}, err
	}
	repoLock, err := acquireSharedFileLock(ctx, filepath.Join(ws.Root, ".sow", "repo-locks", repoName+".lock"))
	if err != nil {
		return DistInfo{}, classifyReadLockError(fmt.Sprintf("acquire repository %q read lock", repoName), err)
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	if err := validateRepositoryLayout(ws.Root, repoName); err != nil {
		return DistInfo{}, err
	}
	if _, err := validateReadOnlyStateRoot(ws.Root, false); err != nil {
		return DistInfo{}, err
	}
	store, err := openReadOnlyState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return DistInfo{}, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	dist, err := store.GetDist(ctx, opts.Name)
	if errors.Is(err, state.ErrNotFound) {
		configured, ok := cfg.Repositories[repoName].Dists[opts.Name]
		if !ok {
			return DistInfo{}, fmt.Errorf("%w: dist %q does not exist", ErrRejected, opts.Name)
		}
		if err := rejectUninitializedDistAdoption(ws.Root, repoName, opts.Name); err != nil {
			return DistInfo{}, err
		}
		architectures, archErr := configuredArchitectureState(cfg, repoName, opts.Name, configured.Format)
		if archErr != nil {
			return DistInfo{}, archErr
		}
		effectiveView, configErr := config.EffectiveView(cfg, config.ViewOptions{Repository: repoName, Dist: opts.Name})
		if configErr != nil {
			return DistInfo{}, configErr
		}
		effectiveConfig := effectiveView.Repositories[repoName].Dists[opts.Name]
		return DistInfo{Name: opts.Name, Format: configured.Format, Architectures: architectures, Dirty: true, Status: "dirty", DirtyReasons: []string{"configured dist is not initialized"}, Config: effectiveConfig}, nil
	}
	if err != nil {
		return DistInfo{}, fmt.Errorf("%w: read Dist %q state: %v", ErrIntegrity, opts.Name, err)
	}
	info, err := makeDistInfo(ctx, store, ws.Root, repoName, cfg, dist)
	if err != nil {
		return DistInfo{}, fmt.Errorf("%w: inspect Dist %q state: %v", ErrIntegrity, opts.Name, err)
	}
	return info, nil
}

func makeDistInfo(ctx context.Context, store *state.Store, root, repoName string, cfg config.Config, dist state.Dist) (DistInfo, error) {
	counts, err := store.CountsForDist(ctx, dist.Name)
	if err != nil {
		return DistInfo{}, fmt.Errorf("read Dist membership counts: %w", err)
	}
	repo := cfg.Repositories[repoName]
	configured, ok := repo.Dists[dist.Name]
	if !ok {
		return DistInfo{Name: dist.Name, Format: dist.Format, Architectures: dist.Architectures, DesiredMembers: counts.Memberships, BuiltMembers: counts.BuiltMemberships, Generation: dist.BuiltGeneration, EffectiveConfigSHA: dist.EffectiveConfigSHA256, Dirty: true, Status: "error", DirtyReasons: []string{"built dist is absent from configuration"}}, nil
	}
	effectiveView, err := config.EffectiveView(cfg, config.ViewOptions{Repository: repoName, Dist: dist.Name})
	if err != nil {
		return DistInfo{}, err
	}
	effectiveConfig := effectiveView.Repositories[repoName].Dists[dist.Name]
	effectiveSHA, configDirty, err := observedEffectiveDistConfig(ctx, root, cfg, repoName, dist.Name, dist)
	if err != nil {
		return DistInfo{}, err
	}
	effectiveArchitectures, err := configuredArchitectureState(cfg, repoName, dist.Name, configured.Format)
	if err != nil {
		return DistInfo{}, err
	}
	info := DistInfo{Name: dist.Name, Format: dist.Format, Architectures: effectiveArchitectures, DesiredMembers: counts.Memberships, BuiltMembers: counts.BuiltMemberships, Generation: dist.BuiltGeneration, EffectiveConfigSHA: dist.EffectiveConfigSHA256, Status: "clean", Config: effectiveConfig}
	desiredMemberships, err := store.MembershipDigests(ctx, dist.Name, false)
	if err != nil {
		return DistInfo{}, fmt.Errorf("read Dist Desired Membership: %w", err)
	}
	builtMemberships, err := store.MembershipDigests(ctx, dist.Name, true)
	if err != nil {
		return DistInfo{}, fmt.Errorf("read Dist Built Membership: %w", err)
	}
	if !sameStringSet(desiredMemberships, builtMemberships) {
		info.Dirty, info.Status = true, "dirty"
		info.DirtyReasons = append(info.DirtyReasons, "Desired and Built membership sets differ")
	}
	effective, err := config.EffectiveArchitectures(cfg, repoName, dist.Name)
	if err != nil {
		return DistInfo{}, err
	}
	if configured.Format != dist.Format {
		info.Dirty, info.Status = true, "dirty"
		info.DirtyReasons = append(info.DirtyReasons, "format differs from built state")
	}
	if !sameArchitectureFamilies(effective, dist.Architectures) {
		info.Dirty, info.Status = true, "dirty"
		info.DirtyReasons = append(info.DirtyReasons, "effective architectures differ from built state")
	}
	if configDirty || effectiveSHA != "" && effectiveSHA != dist.EffectiveConfigSHA256 {
		info.Dirty, info.Status = true, "dirty"
		info.DirtyReasons = append(info.DirtyReasons, "effective configuration differs from built state")
	}
	if err := validateLiveDistViews(ctx, root, repoName, dist.Format, dist.Name, dist.Architectures); err != nil {
		info.Dirty, info.Status = true, "error"
		info.DirtyReasons = append(info.DirtyReasons, fmt.Sprintf("architecture views are invalid: %v", err))
	}
	pending, err := store.PendingOperations(ctx)
	if err != nil {
		return DistInfo{}, fmt.Errorf("read pending operations: %w", err)
	}
	for _, operation := range pending {
		touches := false
		switch operation.Kind {
		case "dist.new", "dist.init", "dist.rm":
			payload, err := decodeDistPayload(operation.PayloadJSON)
			if err != nil {
				return DistInfo{}, fmt.Errorf("%w: invalid pending dist payload", ErrIntegrity)
			}
			touches = payload.Name == dist.Name
		case "add", "rm", "build":
			var payload mutationOperationPayload
			if err := jsonUnmarshalStrict(operation.PayloadJSON, &payload); err != nil || payload.Version != mutationOperationVersion || payload.Repository != repoName || payload.Kind != operation.Kind {
				return DistInfo{}, fmt.Errorf("%w: invalid pending mutation payload", ErrIntegrity)
			}
			for _, name := range payload.Dists {
				if name == dist.Name {
					touches = true
					break
				}
			}
		default:
			return DistInfo{}, fmt.Errorf("%w: unsupported pending operation %q", ErrIntegrity, operation.Kind)
		}
		if touches {
			info.Dirty = true
			info.Status = statusAtLeast(info.Status, "recovering")
			info.DirtyReasons = append(info.DirtyReasons, fmt.Sprintf("operation %s is %s", operation.ID, operation.State))
		}
	}
	sort.Strings(info.DirtyReasons)
	return info, nil
}

func effectiveDistConfig(ctx context.Context, root string, cfg config.Config, repoName, distName string) (string, config.EffectiveDist, error) {
	view, err := config.EffectiveView(cfg, config.ViewOptions{Repository: repoName, Dist: distName})
	if err != nil {
		return "", config.EffectiveDist{}, err
	}
	effectiveRepo := view.Repositories[repoName]
	format := effectiveRepo.Dists[distName].Format
	effectiveRepo.Signing, err = resolveEffectiveSigningFingerprintsForFormats(ctx, root, cfg.Repositories[repoName].Signing, effectiveRepo.Signing, format == "rpm", format == "deb")
	if err != nil {
		return "", config.EffectiveDist{}, fmt.Errorf("%w: repository %q Dist %q signing: %v", ErrRejected, repoName, distName, err)
	}
	return hashEffectiveDist(effectiveRepo, distName)
}

func effectiveDistConfigFrozen(cfg config.Config, repoName, distName string, signing config.EffectiveSigningConfig) (string, config.EffectiveDist, error) {
	view, err := config.EffectiveView(cfg, config.ViewOptions{Repository: repoName, Dist: distName})
	if err != nil {
		return "", config.EffectiveDist{}, err
	}
	effectiveRepo := view.Repositories[repoName]
	effectiveRepo.Signing = signing
	return hashEffectiveDist(effectiveRepo, distName)
}

// observedEffectiveDistConfig compares Desired configuration with the retained
// Built signing snapshot. Read-only status/check therefore do not require a
// private key (or even a still-resolvable file/env/agent reference) merely to
// authenticate and describe an existing Generation. If the raw signing
// references changed while the new reference is unavailable, the Dist is
// deterministically dirty without pretending to know the new fingerprint.
func observedEffectiveDistConfig(ctx context.Context, root string, cfg config.Config, repoName, distName string, built state.Dist) (string, bool, error) {
	currentSHA, _, currentErr := effectiveDistConfig(ctx, root, cfg, repoName, distName)
	if currentErr == nil {
		return currentSHA, currentSHA != built.EffectiveConfigSHA256, nil
	}
	if built.EffectiveSigningJSON == "" || built.EffectiveSigningJSON == "{}" {
		return "", false, currentErr
	}
	var frozen config.EffectiveSigningConfig
	decoder := json.NewDecoder(strings.NewReader(built.EffectiveSigningJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frozen); err != nil {
		return "", false, fmt.Errorf("%w: retained Dist signing snapshot is invalid: %v", ErrIntegrity, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return "", false, fmt.Errorf("%w: retained Dist signing snapshot has trailing content", ErrIntegrity)
	}
	if !frozenSigningReferencesMatchForFormat(cfg.Repositories[repoName].Signing, frozen, built.Format) {
		return "", true, nil
	}
	frozenSHA, _, err := effectiveDistConfigFrozen(cfg, repoName, distName, frozen)
	if err != nil {
		return "", false, err
	}
	return frozenSHA, frozenSHA != built.EffectiveConfigSHA256, nil
}

func hashEffectiveDist(effectiveRepo config.EffectiveRepository, distName string) (string, config.EffectiveDist, error) {
	effective := effectiveRepo.Dists[distName]
	architectures := append([]string(nil), effective.Architectures...)
	sort.Slice(architectures, func(i, j int) bool {
		rank := func(value string) int {
			if value == "x86_64" {
				return 0
			}
			return 1
		}
		return rank(architectures[i]) < rank(architectures[j])
	})
	effective.Architectures = architectures
	var signing any
	if effective.Format == "rpm" {
		signing = effectiveRepo.Signing.RPM
	} else {
		signing = effectiveRepo.Signing.DEB
	}
	renderer := ""
	if effective.Format == "deb" {
		renderer = managedAPTReleaseContract
	}
	data, err := json.Marshal(struct {
		Schema   string               `json:"schema"`
		Renderer string               `json:"renderer,omitempty"`
		Signing  any                  `json:"signing"`
		Dist     config.EffectiveDist `json:"dist"`
	}{Schema: "sow.dist-effective/v2", Renderer: renderer, Signing: signing, Dist: effective})
	if err != nil {
		return "", config.EffectiveDist{}, err
	}
	return bytesSHA(data), effective, nil
}

func frozenEffectiveSigning(raw config.SigningConfig, rpmPolicy rpmSigningPolicy, metadata metadataSignerSnapshot) (config.EffectiveSigningConfig, error) {
	return frozenEffectiveSigningForFormats(raw, rpmPolicy, metadata, true, true)
}

func frozenEffectiveSigningForFormats(raw config.SigningConfig, rpmPolicy rpmSigningPolicy, metadata metadataSignerSnapshot, wantRPM, wantDEB bool) (config.EffectiveSigningConfig, error) {
	effective := config.EffectiveSigningConfig{}
	if wantRPM {
		packages, err := canonicalEffectiveRPMPackages(raw.RPM.Packages, rpmPolicy.currentPrint, rpmPolicy.trustedPrint, rpmPolicy.currentSnapshot, rpmPolicy.trustedSnapshots)
		if err != nil {
			return config.EffectiveSigningConfig{}, fmt.Errorf("managed: %w", err)
		}
		effective.RPM.Packages = packages
	}
	if wantRPM && raw.RPM.Metadata.Key != "" {
		if metadata.RPM.Fingerprint == "" || len(metadata.RPM.PublicKey) == 0 {
			return config.EffectiveSigningConfig{}, errors.New("managed: RPM metadata signing snapshot has no public identity")
		}
		effective.RPM.Metadata = &config.EffectiveMetadataSigningConfig{Key: raw.RPM.Metadata.Key, Passphrase: raw.RPM.Metadata.Passphrase, KeyFingerprint: metadata.RPM.Fingerprint}
	}
	if wantDEB && raw.DEB.Metadata.Key != "" {
		if metadata.DEB.Fingerprint == "" || len(metadata.DEB.PublicKey) == 0 {
			return config.EffectiveSigningConfig{}, errors.New("managed: DEB metadata signing snapshot has no public identity")
		}
		effective.DEB = &config.EffectiveDEBSigningConfig{Metadata: config.EffectiveMetadataSigningConfig{Key: raw.DEB.Metadata.Key, Passphrase: raw.DEB.Metadata.Passphrase, KeyFingerprint: metadata.DEB.Fingerprint}}
	}
	return effective, nil
}

func configuredArchitectureState(cfg config.Config, repoName, distName, format string) ([]state.Architecture, error) {
	families, err := config.EffectiveArchitectures(cfg, repoName, distName)
	if err != nil {
		return nil, err
	}
	result := make([]state.Architecture, 0, len(families))
	for _, family := range families {
		ecosystem := family
		if format == "deb" {
			if family == "x86_64" {
				ecosystem = "amd64"
			} else {
				ecosystem = "arm64"
			}
		}
		result = append(result, state.Architecture{Family: family, EcosystemArch: ecosystem})
	}
	return result, nil
}

func NewDist(ctx context.Context, opts DistNewOptions) (result DistInfo, resultErr error) {
	if err := config.ValidateName(opts.Name); err != nil {
		return DistInfo{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	if opts.Format != "rpm" && opts.Format != "deb" {
		return DistInfo{}, fmt.Errorf("%w: dist format must be rpm or deb", ErrRejected)
	}
	ws, cfg, rootGuard, err := workspace(opts.WorkspaceOptions)
	if err != nil {
		return DistInfo{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	repoName, err := selectRepo(ws, cfg, opts.Repository)
	if err != nil {
		return DistInfo{}, err
	}
	workspaceLock, repoLock, err := acquireLifecycleLocks(ctx, ws.Root, repoName, opts.LockOptions)
	if err != nil {
		return DistInfo{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	if err := recoverWorkspaceOperation(ctx, ws.Root); err != nil {
		return DistInfo{}, err
	}
	if err := validateRepositoryLayout(ws.Root, repoName); err != nil {
		return DistInfo{}, err
	}
	store, err := openExistingState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return DistInfo{}, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	if err := recoverDistOperations(ctx, ws.Root, repoName, store); err != nil {
		return DistInfo{}, err
	}
	if err := store.Checkpoint(ctx); err != nil {
		return DistInfo{}, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	var oldData []byte
	cfg, oldData, _, err = config.LoadWorkspaceDocument(ws)
	if err != nil {
		return DistInfo{}, err
	}
	if _, err := checkConfigAtRootWithLockedRepositories(ctx, ws.Root, cfg, map[string]struct{}{repoName: {}}); err != nil {
		return DistInfo{}, err
	}
	repo := cfg.Repositories[repoName]
	if existing, exists := repo.Dists[opts.Name]; exists {
		if existing.Format != opts.Format {
			return DistInfo{}, fmt.Errorf("%w: dist %q already exists with format %s", ErrRejected, opts.Name, existing.Format)
		}
		dist, getErr := store.GetDist(ctx, opts.Name)
		if getErr != nil {
			return DistInfo{}, fmt.Errorf("%w: configured dist %q has no complete state: %v", ErrIntegrity, opts.Name, getErr)
		}
		return makeDistInfo(ctx, store, ws.Root, repoName, cfg, dist)
	}
	if err := rejectUninitializedDistAdoption(ws.Root, repoName, opts.Name); err != nil {
		return DistInfo{}, err
	}
	if repo.Dists == nil {
		repo.Dists = map[string]config.DistConfig{}
	}
	repo.Dists[opts.Name] = config.DistConfig{Format: opts.Format}
	cfg.Repositories[repoName] = repo
	newData, err := config.Marshal(cfg)
	if err != nil {
		return DistInfo{}, err
	}
	return executeDistAdd(ctx, ws.Root, repoName, cfg, opts.Name, oldData, newData, "dist.new", opts.Fault, store)
}

func rejectUninitializedDistAdoption(root, repoName, distName string) error {
	if err := config.ValidateName(repoName); err != nil {
		return fmt.Errorf("%w: %v", ErrRejected, err)
	}
	if err := config.ValidateName(distName); err != nil {
		return fmt.Errorf("%w: %v", ErrRejected, err)
	}
	target := filepath.Join(root, repoName, "dists", distName)
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf("%w: refusing to adopt pre-existing uninitialized Dist path %q", ErrRejected, target)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func RemoveDist(ctx context.Context, opts DistRemoveOptions) error {
	_, err := RemoveDistResult(ctx, opts)
	return err
}

func RemoveDistResult(ctx context.Context, opts DistRemoveOptions) (RemovalResult, error) {
	result := RemovalResult{}
	err := removeDist(ctx, opts, &result)
	return result, err
}

func removeDist(ctx context.Context, opts DistRemoveOptions, result *RemovalResult) (resultErr error) {
	if err := config.ValidateName(opts.Name); err != nil {
		return fmt.Errorf("%w: %v", ErrRejected, err)
	}
	ws, cfg, rootGuard, err := workspace(opts.WorkspaceOptions)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	repoName, err := selectRepo(ws, cfg, opts.Repository)
	if err != nil {
		return err
	}
	workspaceLock, repoLock, err := acquireLifecycleLocks(ctx, ws.Root, repoName, opts.LockOptions)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	if err := recoverWorkspaceOperation(ctx, ws.Root); err != nil {
		return err
	}
	if err := validateRepositoryLayout(ws.Root, repoName); err != nil {
		return err
	}
	store, err := openExistingState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	if err := recoverDistOperations(ctx, ws.Root, repoName, store); err != nil {
		return err
	}
	if err := store.Checkpoint(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	var oldData []byte
	cfg, oldData, _, err = config.LoadWorkspaceDocument(ws)
	if err != nil {
		return err
	}
	check := checkConfigAtRootWithLockedRepositories
	if opts.Force {
		check = func(ctx context.Context, root string, cfg config.Config, locked map[string]struct{}) (ConfigCheckResult, error) {
			return checkConfigAtRootForForcedDistRemovalWithLockedRepositories(ctx, root, cfg, repoName, opts.Name, locked)
		}
	}
	if _, err := check(ctx, ws.Root, cfg, map[string]struct{}{repoName: {}}); err != nil {
		return err
	}
	repo := cfg.Repositories[repoName]
	if _, exists := repo.Dists[opts.Name]; !exists {
		result.Noop = true
		return nil
	}
	counts, err := store.CountsForDist(ctx, opts.Name)
	if err != nil {
		return err
	}
	if counts.Memberships != 0 && !opts.Force {
		return fmt.Errorf("%w: dist %q is not empty; use --force", ErrRejected, opts.Name)
	}
	delete(repo.Dists, opts.Name)
	cfg.Repositories[repoName] = repo
	newData, err := config.Marshal(cfg)
	if err != nil {
		return err
	}
	return executeDistRemove(ctx, ws.Root, repoName, opts.Name, oldData, newData, opts.Force, opts.Fault, store, result)
}

func initializeDeclaredDists(ctx context.Context, root, repoName string, fault func(string) error, lockOptions LockOptions) (created int, resultErr error) {
	started := time.Now()
	workspaceLock, err := acquireFileLock(ctx, filepath.Join(root, ".sow", "workspace.lock"), lockOptions.Timeout, lockOptions.NoWait)
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	if err := recoverWorkspaceOperation(ctx, root); err != nil {
		return 0, err
	}
	currentCfg, currentData, _, err := config.LoadDocument(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		return 0, err
	}
	// Init releases the Workspace lock after creating Repository shells, then
	// reacquires it here in canonical Workspace -> Repository order. Another
	// serialized lifecycle command may have removed this Repository in that
	// interval; the current config is authoritative, so stale Init work is a
	// clean no-op rather than an attempt to recreate or open its retired lock.
	if _, configured := currentCfg.Repositories[repoName]; !configured {
		return 0, nil
	}
	remaining, err := remainingLockTimeout(lockOptions.Timeout, started)
	if err != nil {
		return 0, err
	}
	repoLock, err := acquireFileLock(ctx, filepath.Join(root, ".sow", "repo-locks", repoName+".lock"), remaining, lockOptions.NoWait)
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	if err := validateRepositoryLayout(root, repoName); err != nil {
		return 0, err
	}
	store, err := openExistingState(filepath.Join(root, ".sow", repoName+".db"))
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	if err := recoverDistOperations(ctx, root, repoName, store); err != nil {
		return 0, err
	}
	if err := store.Checkpoint(ctx); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	if _, err := checkConfigAtRootWithLockedRepositories(ctx, root, currentCfg, map[string]struct{}{repoName: {}}); err != nil {
		return 0, err
	}
	created = 0
	for _, distName := range sortedDistConfigNames(currentCfg.Repositories[repoName]) {
		configured := currentCfg.Repositories[repoName].Dists[distName]
		existing, getErr := store.GetDist(ctx, distName)
		if getErr == nil {
			if existing.Format != configured.Format {
				return created, fmt.Errorf("%w: dist %q format differs between config and state", ErrIntegrity, distName)
			}
			effective, err := config.EffectiveArchitectures(currentCfg, repoName, distName)
			if err != nil {
				return created, err
			}
			configuredSet := make(map[string]struct{}, len(effective))
			for _, family := range effective {
				configuredSet[family] = struct{}{}
			}
			if err := validateLiveDistViews(ctx, root, repoName, existing.Format, distName, existing.Architectures); err != nil {
				return created, err
			}
			for _, architecture := range existing.Architectures {
				if _, ok := configuredSet[architecture.Family]; !ok {
					return created, fmt.Errorf("%w: state references architecture %q removed from dist %q", ErrRejected, architecture.Family, distName)
				}
			}
			// This Dist is already initialized. A newly configured architecture
			// is a Desired/Built change, not an unfinished init object: retain the
			// last complete Generation and let read surfaces report it dirty. P1
			// does not expose build, and init must not impersonate that later API.
			continue
		} else if !errors.Is(getErr, state.ErrNotFound) {
			return created, getErr
		}
		if _, err := executeDistAdd(ctx, root, repoName, currentCfg, distName, currentData, currentData, "dist.init", fault, store); err != nil {
			return created, err
		}
		created++
	}
	return created, nil
}

func executeDistAdd(ctx context.Context, root, repoName string, cfg config.Config, distName string, oldData, newData []byte, kind string, fault func(string) error, store *state.Store) (result DistInfo, resultErr error) {
	if err := validateCurrentPublicGeneration(ctx, root, repoName, store); err != nil {
		return DistInfo{}, err
	}
	repo := cfg.Repositories[repoName]
	distCfg := repo.Dists[distName]
	architectures, err := config.EffectiveArchitectures(cfg, repoName, distName)
	if err != nil {
		return DistInfo{}, err
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return DistInfo{}, err
	}
	generation := summary.BuiltGeneration + 1
	payload := distOperationPayload{Version: distOperationVersion, Repository: repoName, Name: distName, Format: distCfg.Format, Generation: generation, OldConfigSHA256: bytesSHA(oldData), NewConfigSHA256: bytesSHA(newData), NewConfig: newData}
	for _, family := range architectures {
		ecosystem := family
		if distCfg.Format == "deb" {
			if family == "x86_64" {
				ecosystem = "amd64"
			} else {
				ecosystem = "arm64"
			}
		}
		payload.Architectures = append(payload.Architectures, state.Architecture{Family: family, EcosystemArch: ecosystem})
	}
	id, err := operationID()
	if err != nil {
		return DistInfo{}, err
	}
	payloadData, _ := json.Marshal(payload)
	defer func() {
		resultErr = finalizePreApplyDistOperation(ctx, root, repoName, id, store, resultErr, func() any {
			return map[string]any{"name": result.Name, "format": result.Format, "generation": result.Generation}
		})
	}()
	if err := store.BeginOperation(ctx, state.Operation{ID: id, Kind: kind, State: state.OperationPlanned, PayloadJSON: string(payloadData)}); err != nil {
		return DistInfo{}, err
	}
	if err := callFault(fault, kind+".planned"); err != nil {
		return DistInfo{}, err
	}
	stageRoot := distStageRoot(root, repoName, id)
	if err := durableMkdir(stageRoot, 0o700); err != nil {
		return DistInfo{}, err
	}
	detail, err := store.GetOperation(ctx, id)
	if err != nil || detail.Operation.ID != id || detail.Operation.CreatedAt.IsZero() {
		return DistInfo{}, fmt.Errorf("%w: new Dist operation has no publication identity", ErrIntegrity)
	}
	operation := detail.Operation
	metadataSnapshot, err := loadMetadataSignerSnapshotForFormats(ctx, root, repo, operation.CreatedAt, distCfg.Format == "rpm", distCfg.Format == "deb")
	if err != nil {
		return DistInfo{}, err
	}
	rpmPolicy := rpmSigningPolicy{mode: "never"}
	if distCfg.Format == "rpm" {
		rpmPolicy, err = loadRPMSigningPolicy(ctx, root, repo.Signing.RPM.Packages)
		if err != nil {
			return DistInfo{}, err
		}
	}
	frozenSigning, err := frozenEffectiveSigningForFormats(repo.Signing, rpmPolicy, metadataSnapshot, distCfg.Format == "rpm", distCfg.Format == "deb")
	if err != nil {
		return DistInfo{}, err
	}
	effectiveSHA, _, err := effectiveDistConfigFrozen(cfg, repoName, distName, frozenSigning)
	if err != nil {
		return DistInfo{}, err
	}
	identity := metadataSnapshot.RPM
	if distCfg.Format == "deb" {
		identity = metadataSnapshot.DEB
	}
	snapshotSHA, err := persistDistMetadataSignerSnapshot(root, repoName, id, identity)
	if err != nil {
		return DistInfo{}, err
	}
	payload.EffectiveConfigSHA256 = effectiveSHA
	payload.EffectiveSigning = &frozenSigning
	payload.MetadataSignerSnapshotSHA256 = snapshotSHA
	spec := ManagedDistSpec{Name: distName, Format: distCfg.Format, Architectures: payload.Architectures, Generation: generation, PublishedAt: operation.CreatedAt}
	if distCfg.Format == "rpm" {
		spec.RPMSigner = metadataSnapshot.RPMSigner
	} else {
		spec.APTSigner = metadataSnapshot.APTSigner
	}
	rendered, err := RenderManagedDist(ctx, stageRoot, spec)
	if err != nil {
		return DistInfo{}, err
	}
	payload.TreeSHA256 = rendered.TreeSHA256
	payloadData, _ = json.Marshal(payload)
	if err := store.UpdateOperationPayload(ctx, id, string(payloadData)); err != nil {
		return DistInfo{}, err
	}
	if err := store.SetOperationState(ctx, id, state.OperationStaged, ""); err != nil {
		return DistInfo{}, err
	}
	if err := callFault(fault, kind+".staged"); err != nil {
		return DistInfo{}, err
	}
	configPath := filepath.Join(root, config.ConfigFilename)
	currentSHA, err := config.FileSHA(configPath)
	if err != nil || currentSHA != payload.OldConfigSHA256 {
		return DistInfo{}, fmt.Errorf("%w: config changed while staging dist", ErrIntegrity)
	}
	if payload.NewConfigSHA256 != payload.OldConfigSHA256 {
		if err := requireSameDevice(filepath.Dir(filepath.Join(stageRoot, "dists", distName)), filepath.Join(root, repoName, "dists")); err != nil {
			return DistInfo{}, err
		}
		if err := writeAtomic(configPath, newData, 0o644); err != nil {
			return DistInfo{}, err
		}
	}
	if err := store.SetOperationState(ctx, id, state.OperationApplied, ""); err != nil {
		return DistInfo{}, err
	}
	if err := callFault(fault, kind+".applied"); err != nil {
		return DistInfo{}, err
	}
	if err := installStagedDist(ctx, root, repoName, distName, id, payload.TreeSHA256); err != nil {
		return DistInfo{}, err
	}
	_, normalizedModes, err := normalizeManagedPublicTree(ctx, filepath.Join(root, repoName), fault, kind+".mode")
	if err != nil {
		return DistInfo{}, err
	}
	if err := recordNormalizedPublicModes(ctx, store, id, normalizedModes); err != nil {
		return DistInfo{}, err
	}
	if err := callFault(fault, kind+".modes"); err != nil {
		return DistInfo{}, err
	}
	if err := store.SetOperationState(ctx, id, state.OperationBuilt, ""); err != nil {
		return DistInfo{}, err
	}
	if err := callFault(fault, kind+".built"); err != nil {
		return DistInfo{}, err
	}
	effectiveSigningJSON, err := json.Marshal(payload.EffectiveSigning)
	if err != nil {
		return DistInfo{}, err
	}
	dist := state.Dist{Name: distName, Format: distCfg.Format, EffectiveConfigSHA256: payload.EffectiveConfigSHA256, BuiltGeneration: generation, Architectures: payload.Architectures, MetadataSignerFingerprint: identity.Fingerprint, MetadataSignerPublicKey: identity.PublicKey, EffectiveSigningJSON: string(effectiveSigningJSON)}
	result = DistInfo{Name: dist.Name, Format: dist.Format, Architectures: append([]state.Architecture(nil), dist.Architectures...), Generation: dist.BuiltGeneration, EffectiveConfigSHA: dist.EffectiveConfigSHA256, Status: "clean"}
	manifest, changes, err := distLifecycleGeneration(ctx, root, repoName, generation, store)
	if err != nil {
		return DistInfo{}, err
	}
	if err := store.FinalizeDistAdd(ctx, id, dist, manifest, changes); err != nil {
		if committed, getErr := store.GetDist(ctx, distName); getErr == nil && committed.BuiltGeneration == generation {
			if complete, infoErr := makeDistInfo(ctx, store, root, repoName, cfg, committed); infoErr == nil {
				result = complete
			} else {
				err = errors.Join(err, infoErr)
			}
			return result, err
		}
		return DistInfo{}, err
	}
	if complete, infoErr := makeDistInfo(ctx, store, root, repoName, cfg, dist); infoErr == nil {
		result = complete
	} else {
		return result, infoErr
	}
	if err := callFault(fault, kind+".finalized"); err != nil {
		return result, err
	}
	if err := removeOwnedDirectory(stageRoot, filepath.Join(root, ".sow", repoName, "stage")); err != nil {
		return result, err
	}
	return result, nil
}

func executeDistRemove(ctx context.Context, root, repoName, distName string, oldData, newData []byte, force bool, fault func(string) error, store *state.Store, result *RemovalResult) (resultErr error) {
	ignoredDist := ""
	if force {
		ignoredDist = distName
	}
	if err := validateCurrentPublicGenerationExceptDist(ctx, root, repoName, store, ignoredDist); err != nil {
		return err
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return err
	}
	livePath := filepath.Join(root, repoName, "dists", distName)
	treeSHA, _, err := digestTree(ctx, livePath)
	if err != nil {
		return err
	}
	payload := distOperationPayload{Version: distOperationVersion, Repository: repoName, Name: distName, Generation: summary.BuiltGeneration + 1, OldConfigSHA256: bytesSHA(oldData), NewConfigSHA256: bytesSHA(newData), NewConfig: newData, TreeSHA256: treeSHA}
	id, err := operationID()
	if err != nil {
		return err
	}
	payloadData, _ := json.Marshal(payload)
	defer func() {
		resultErr = finalizePreApplyDistOperation(ctx, root, repoName, id, store, resultErr, func() any {
			return map[string]any{"removed": result != nil && result.Removed, "name": distName}
		})
	}()
	if err := store.BeginOperation(ctx, state.Operation{ID: id, Kind: "dist.rm", State: state.OperationPlanned, PayloadJSON: string(payloadData)}); err != nil {
		return err
	}
	if err := callFault(fault, "dist.rm.planned"); err != nil {
		return err
	}
	if err := store.SetOperationState(ctx, id, state.OperationStaged, ""); err != nil {
		return err
	}
	if err := callFault(fault, "dist.rm.staged"); err != nil {
		return err
	}
	if current, err := config.FileSHA(filepath.Join(root, config.ConfigFilename)); err != nil || current != payload.OldConfigSHA256 {
		return fmt.Errorf("%w: config changed while staging dist removal", ErrIntegrity)
	}
	if err := requireSameDevice(filepath.Join(root, repoName, "dists"), filepath.Join(root, ".sow", repoName, "recovery")); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(root, config.ConfigFilename), newData, 0o644); err != nil {
		return err
	}
	result.Removed = true
	if err := store.SetOperationState(ctx, id, state.OperationApplied, ""); err != nil {
		return err
	}
	if err := callFault(fault, "dist.rm.applied"); err != nil {
		return err
	}
	if err := moveDistToRecovery(ctx, root, repoName, distName, id, payload.TreeSHA256); err != nil {
		return err
	}
	_, normalizedModes, err := normalizeManagedPublicTree(ctx, filepath.Join(root, repoName), fault, "dist.rm.mode")
	if err != nil {
		return err
	}
	if err := recordNormalizedPublicModes(ctx, store, id, normalizedModes); err != nil {
		return err
	}
	if err := callFault(fault, "dist.rm.modes"); err != nil {
		return err
	}
	if err := store.SetOperationState(ctx, id, state.OperationBuilt, ""); err != nil {
		return err
	}
	if err := callFault(fault, "dist.rm.built"); err != nil {
		return err
	}
	manifest, changes, err := distLifecycleGeneration(ctx, root, repoName, payload.Generation, store)
	if err != nil {
		return err
	}
	droppedPending, err := store.FinalizeDistRemovalAndCollect(ctx, id, distName, payload.Generation, manifest, changes)
	if err != nil {
		return err
	}
	if err := callFault(fault, "dist.rm.finalized"); err != nil {
		return err
	}
	if err := cleanupDroppedPending(root, repoName, droppedPending); err != nil {
		return err
	}
	return cleanupDistRecovery(root, repoName, id)
}

// finalizePreApplyDistOperation terminalizes an ordinary Dist failure only
// while the journal and sow.yml still prove that no Desired change applied.
// A committed config write is deliberately left non-terminal so recovery can
// complete the public/state transition. Injected crash simulation follows the
// same recovery path as a real process stop and therefore bypasses this helper.
func finalizePreApplyDistOperation(parent context.Context, root, repoName, id string, store *state.Store, returned error, result func() any) error {
	if returned == nil || isInjectedFault(returned) || store == nil || id == "" {
		return returned
	}
	if parent == nil {
		parent = context.Background()
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), operationFailureFinalizeTimeout)
	defer cancel()
	detail, err := store.GetOperation(cleanupCtx, id)
	if errors.Is(err, state.ErrNotFound) {
		return returned
	}
	if err != nil {
		return errors.Join(returned, fmt.Errorf("managed: inspect failed Dist operation journal: %w", err))
	}
	operation := detail.Operation
	if operation.State != state.OperationPlanned && operation.State != state.OperationStaged {
		return returned
	}
	payload, err := decodeDistPayload(operation.PayloadJSON)
	if err != nil || payload.Repository != repoName {
		return errors.Join(returned, fmt.Errorf("%w: retain recoverable Dist operation with invalid payload", ErrIntegrity))
	}
	currentSHA, err := config.FileSHA(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		return errors.Join(returned, fmt.Errorf("managed: retain recoverable Dist operation: inspect current config: %w", err))
	}
	if currentSHA != payload.OldConfigSHA256 {
		if currentSHA == payload.NewConfigSHA256 {
			return returned
		}
		return errors.Join(returned, fmt.Errorf("%w: retain recoverable Dist operation with conflicting config evidence", ErrIntegrity))
	}
	if operation.Kind == "dist.new" || operation.Kind == "dist.init" {
		if err := removeOwnedDirectory(distStageRoot(root, repoName, id), filepath.Join(root, ".sow", repoName, "stage")); err != nil {
			return errors.Join(returned, fmt.Errorf("managed: retain recoverable pre-apply Dist operation: %w", err))
		}
	}
	resultJSON := `{}`
	if result != nil {
		if data, marshalErr := json.Marshal(result()); marshalErr == nil && len(data) <= state.MaxOperationPayloadBytes {
			resultJSON = string(data)
		}
	}
	class, message := safeOperationFailure(returned)
	if err := store.FailOperation(cleanupCtx, id, class, message, resultJSON); err != nil {
		return errors.Join(returned, fmt.Errorf("managed: persist pre-apply Dist failure: %w", err))
	}
	return returned
}

func distLifecycleGeneration(ctx context.Context, root, repoName string, generation int64, store *state.Store) ([]state.GenerationFile, []state.FileChange, error) {
	if generation < 1 {
		return nil, nil, fmt.Errorf("%w: invalid Dist lifecycle generation", ErrIntegrity)
	}
	base := []state.GenerationFile{}
	var err error
	if generation > 1 {
		base, err = store.GenerationManifest(ctx, generation-1)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: previous Dist lifecycle generation is unavailable", ErrIntegrity)
		}
	}
	target, err := scanPublicManifest(ctx, filepath.Join(root, repoName))
	if err != nil {
		return nil, nil, err
	}
	changes := state.DiffManifests(base, target)
	if len(changes) == 0 {
		return nil, nil, fmt.Errorf("%w: Dist lifecycle produced no physical Generation change", ErrIntegrity)
	}
	return target, changes, nil
}

func recoverDistOperations(ctx context.Context, root, repoName string, store *state.Store) error {
	pending, err := store.PendingOperations(ctx)
	if err != nil {
		return err
	}
	for _, operation := range pending {
		if !validStoredOperationID(operation.ID) {
			return fmt.Errorf("%w: invalid pending operation id", ErrIntegrity)
		}
		if operation.Kind == "add" || operation.Kind == "rm" || operation.Kind == "build" {
			if err := recoverMutationOperation(ctx, root, repoName, store, operation); err != nil {
				return err
			}
			continue
		}
		if operation.Kind == "log.prune" {
			if err := recoverLogPruneOperation(ctx, repoName, store, operation); err != nil {
				return err
			}
			continue
		}
		if operation.Kind != "dist.new" && operation.Kind != "dist.init" && operation.Kind != "dist.rm" {
			return fmt.Errorf("%w: unsupported pending operation %q", ErrIntegrity, operation.Kind)
		}
		payload, decodeErr := decodeDistPayload(operation.PayloadJSON)
		if decodeErr != nil || payload.Repository != repoName {
			return fmt.Errorf("%w: invalid pending dist payload", ErrIntegrity)
		}
		if err := validateDistPayloadForRecovery(ctx, root, operation.ID, operation.Kind, operation.State, repoName, payload, store); err != nil {
			return fmt.Errorf("%w: invalid pending dist payload: %v", ErrIntegrity, err)
		}
		currentSHA, err := config.FileSHA(filepath.Join(root, config.ConfigFilename))
		if err != nil {
			return err
		}
		if operation.State == state.OperationPlanned || operation.State == state.OperationStaged {
			if operation.Kind == "dist.init" && operation.State == state.OperationPlanned {
				if err := removeOwnedDirectory(distStageRoot(root, repoName, operation.ID), filepath.Join(root, ".sow", repoName, "stage")); err != nil {
					return err
				}
				if err := store.SetOperationState(ctx, operation.ID, state.OperationRolledBack, ""); err != nil {
					return err
				}
				continue
			}
			if currentSHA == payload.OldConfigSHA256 && operation.Kind != "dist.init" {
				if err := removeOwnedDirectory(distStageRoot(root, repoName, operation.ID), filepath.Join(root, ".sow", repoName, "stage")); err != nil {
					return err
				}
				if err := store.SetOperationState(ctx, operation.ID, state.OperationRolledBack, ""); err != nil {
					return err
				}
				continue
			}
			if currentSHA != payload.NewConfigSHA256 {
				return fmt.Errorf("%w: pending operation config evidence conflicts", ErrIntegrity)
			}
			if operation.State == state.OperationPlanned {
				return fmt.Errorf("%w: planned operation has committed config without staged evidence", ErrIntegrity)
			}
			if err := store.SetOperationState(ctx, operation.ID, state.OperationApplied, ""); err != nil {
				return err
			}
			operation.State = state.OperationApplied
		}
		if operation.State == state.OperationApplied {
			if currentSHA != payload.NewConfigSHA256 {
				return fmt.Errorf("%w: applied operation config evidence conflicts", ErrIntegrity)
			}
			if operation.Kind == "dist.rm" {
				err = moveDistToRecovery(ctx, root, repoName, payload.Name, operation.ID, payload.TreeSHA256)
			} else {
				err = installStagedDist(ctx, root, repoName, payload.Name, operation.ID, payload.TreeSHA256)
			}
			if err != nil {
				return err
			}
			if err := store.SetOperationState(ctx, operation.ID, state.OperationBuilt, ""); err != nil {
				return err
			}
			operation.State = state.OperationBuilt
		}
		if operation.State == state.OperationBuilt {
			_, normalizedModes, err := normalizeManagedPublicTree(ctx, filepath.Join(root, repoName), nil, "")
			if err != nil {
				return err
			}
			if err := recordNormalizedPublicModes(ctx, store, operation.ID, normalizedModes); err != nil {
				return err
			}
			if operation.Kind == "dist.rm" {
				manifest, changes, err := distLifecycleGeneration(ctx, root, repoName, payload.Generation, store)
				if err != nil {
					return err
				}
				droppedPending, err := store.FinalizeDistRemovalAndCollect(ctx, operation.ID, payload.Name, payload.Generation, manifest, changes)
				if err != nil {
					return err
				}
				if err := cleanupDroppedPending(root, repoName, droppedPending); err != nil {
					return err
				}
				if err := cleanupDistRecovery(root, repoName, operation.ID); err != nil {
					return err
				}
			} else {
				identity, err := loadDistMetadataSignerSnapshot(root, repoName, operation.ID, payload.MetadataSignerSnapshotSHA256)
				if err != nil {
					return fmt.Errorf("%w: recover Dist metadata signer identity: %v", ErrIntegrity, err)
				}
				effectiveSigningJSON, err := json.Marshal(payload.EffectiveSigning)
				if err != nil {
					return err
				}
				dist := state.Dist{Name: payload.Name, Format: payload.Format, EffectiveConfigSHA256: payload.EffectiveConfigSHA256, BuiltGeneration: payload.Generation, Architectures: payload.Architectures, MetadataSignerFingerprint: identity.Fingerprint, MetadataSignerPublicKey: identity.PublicKey, EffectiveSigningJSON: string(effectiveSigningJSON)}
				manifest, changes, err := distLifecycleGeneration(ctx, root, repoName, payload.Generation, store)
				if err != nil {
					return err
				}
				if err := store.FinalizeDistAdd(ctx, operation.ID, dist, manifest, changes); err != nil {
					return err
				}
				if err := removeOwnedDirectory(distStageRoot(root, repoName, operation.ID), filepath.Join(root, ".sow", repoName, "stage")); err != nil {
					return err
				}
			}
		}
	}
	if err := recoverDoneDistCleanup(ctx, root, repoName, store); err != nil {
		return err
	}
	if err := bootstrapLegacyGeneration(ctx, root, repoName, store); err != nil {
		return err
	}
	return nil
}

func validateCurrentPublicGeneration(ctx context.Context, root, repoName string, store *state.Store) error {
	return validateCurrentPublicGenerationExceptDist(ctx, root, repoName, store, "")
}

// validateCurrentPublicGenerationExceptDist binds an ordinary write to the
// retained public Generation. The sole scoped exception is an explicitly
// forced Dist removal: its target subtree may contain corrupt bytes precisely
// so the operator can remove it, while every other public path must still
// match the retained Generation exactly.
func validateCurrentPublicGenerationExceptDist(ctx context.Context, root, repoName string, store *state.Store, ignoredDist string) error {
	// Recovery is complete before ordinary writers reach this predicate.  At
	// that point every semantic cross-table relation is part of the retained
	// Generation contract, not merely the ledger and public bytes.  Refuse to
	// append even a no-op audit record to corrupt state: doing so would both
	// obscure the original defect and make later recovery reasoning ambiguous.
	if err := store.Check(ctx); err != nil {
		return fmt.Errorf("%w: current repository state is invalid: %v", ErrIntegrity, err)
	}
	if err := store.ValidateGenerationLedger(ctx); err != nil {
		return fmt.Errorf("%w: current Generation ledger is invalid: %v", ErrIntegrity, err)
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return err
	}
	physical, err := scanPublicManifest(ctx, filepath.Join(root, repoName))
	if err != nil {
		return fmt.Errorf("%w: current public delivery tree cannot be scanned: %v", ErrIntegrity, err)
	}
	if summary.BuiltGeneration == 0 {
		if len(physical) != 0 {
			return fmt.Errorf("%w: Generation 0 public delivery tree is not empty", ErrIntegrity)
		}
		return nil
	}
	retained, err := store.GenerationManifest(ctx, summary.BuiltGeneration)
	if err != nil {
		return fmt.Errorf("%w: current Generation manifest is unavailable: %v", ErrIntegrity, err)
	}
	if ignoredDist != "" {
		prefix := "dists/" + ignoredDist + "/"
		retained = filterGenerationManifestPrefix(retained, prefix)
		physical = filterGenerationManifestPrefix(physical, prefix)
	}
	if !sameGenerationManifest(retained, physical) {
		return fmt.Errorf("%w: current public delivery tree differs from Generation %d", ErrIntegrity, summary.BuiltGeneration)
	}
	return nil
}

func filterGenerationManifestPrefix(manifest []state.GenerationFile, prefix string) []state.GenerationFile {
	filtered := make([]state.GenerationFile, 0, len(manifest))
	for _, entry := range manifest {
		if !strings.HasPrefix(entry.Path, prefix) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func bootstrapLegacyGeneration(ctx context.Context, root, repoName string, store *state.Store) error {
	summary, err := store.Summary(ctx)
	if err != nil || summary.BuiltGeneration == 0 {
		return err
	}
	if _, err := store.GetGeneration(ctx, summary.BuiltGeneration); err == nil {
		return nil
	} else if !errors.Is(err, state.ErrNotFound) {
		return err
	}
	manifest, err := scanPublicManifest(ctx, filepath.Join(root, repoName))
	if err != nil {
		return fmt.Errorf("%w: scan legacy Generation baseline: %v", ErrIntegrity, err)
	}
	id, err := operationID()
	if err != nil {
		return err
	}
	if err := store.BootstrapLegacyGeneration(ctx, id, summary.BuiltGeneration, manifest); err != nil {
		return fmt.Errorf("%w: bootstrap legacy Generation ledger: %v", ErrIntegrity, err)
	}
	return nil
}

func recoverDoneDistCleanup(ctx context.Context, root, repoName string, store *state.Store) error {
	done, err := store.DoneOperations(ctx)
	if err != nil {
		return err
	}
	for _, operation := range done {
		if !validStoredOperationID(operation.ID) {
			return fmt.Errorf("%w: invalid completed operation id", ErrIntegrity)
		}
		if operation.Kind == "generation.bootstrap" {
			continue
		}
		if operation.Kind == "log.prune" {
			continue
		}
		if operation.Kind == "add" || operation.Kind == "rm" || operation.Kind == "build" {
			if err := cleanupMutationStage(root, repoName, operation.ID); err != nil {
				return err
			}
			continue
		}
		if operation.Kind != "dist.new" && operation.Kind != "dist.init" && operation.Kind != "dist.rm" {
			return fmt.Errorf("%w: unsupported completed operation %q", ErrIntegrity, operation.Kind)
		}
		payload, err := decodeDistPayload(operation.PayloadJSON)
		if err != nil || payload.Repository != repoName {
			return fmt.Errorf("%w: invalid completed dist payload", ErrIntegrity)
		}
		if operation.Kind == "dist.rm" {
			droppedPending, err := decodeDroppedPendingResult(operation.ResultJSON)
			if err != nil {
				return fmt.Errorf("%w: invalid completed Dist removal result: %v", ErrIntegrity, err)
			}
			if err := cleanupDroppedPending(root, repoName, droppedPending); err != nil {
				return err
			}
			if err := cleanupDistRecovery(root, repoName, operation.ID); err != nil {
				return err
			}
			continue
		}
		if err := removeOwnedDirectory(distStageRoot(root, repoName, operation.ID), filepath.Join(root, ".sow", repoName, "stage")); err != nil {
			return err
		}
	}
	return nil
}

func decodeDroppedPendingResult(data string) ([]string, error) {
	var result struct {
		DroppedPending []string `json:"dropped_pending"`
	}
	dec := json.NewDecoder(strings.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result); err != nil {
		return nil, err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, errors.New("trailing Dist removal result content")
	}
	for _, digest := range result.DroppedPending {
		if !lowercaseSHA256.MatchString(digest) {
			return nil, errors.New("invalid dropped pending digest")
		}
	}
	return result.DroppedPending, nil
}

func cleanupDroppedPending(root, repoName string, digests []string) error {
	for _, digest := range digests {
		if err := removePendingObject(root, repoName, state.PackageObject{SHA256: digest}); err != nil {
			return err
		}
	}
	return nil
}

func decodeDistPayload(data string) (distOperationPayload, error) {
	var payload distOperationPayload
	if len(data) == 0 || len(data) > state.MaxOperationPayloadBytes {
		return payload, errors.New("operation payload is empty or exceeds 16 MiB")
	}
	dec := json.NewDecoder(bytes.NewBufferString(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return payload, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return payload, errors.New("trailing operation payload content")
	}
	if (payload.Version != 1 && payload.Version != distOperationVersion) || config.ValidateName(payload.Repository) != nil || config.ValidateName(payload.Name) != nil || payload.Generation < 1 || !lowercaseSHA256.MatchString(payload.OldConfigSHA256) || !lowercaseSHA256.MatchString(payload.NewConfigSHA256) || bytesSHA(payload.NewConfig) != payload.NewConfigSHA256 {
		return payload, errors.New("invalid operation payload fields")
	}
	if _, err := config.Parse(payload.NewConfig); err != nil {
		return payload, err
	}
	return payload, nil
}

func validateDistPayloadForRecovery(ctx context.Context, root, operationID, kind string, operationState state.OperationState, repoName string, payload distOperationPayload, store *state.Store) error {
	if ctx == nil || store == nil {
		return errors.New("recovery context or state is unavailable")
	}
	if payload.Repository != repoName {
		return errors.New("payload repository does not match the locked repository")
	}
	parsed, err := config.Parse(payload.NewConfig)
	if err != nil {
		return errors.New("payload new config is invalid")
	}
	repo, repoExists := parsed.Repositories[repoName]
	if !repoExists {
		return errors.New("payload new config removed the locked repository")
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return err
	}
	if payload.Generation != summary.BuiltGeneration+1 {
		return fmt.Errorf("payload generation %d does not follow repository generation %d", payload.Generation, summary.BuiltGeneration)
	}
	if payload.TreeSHA256 != "" && !lowercaseSHA256.MatchString(payload.TreeSHA256) {
		return errors.New("payload tree digest is malformed")
	}
	if operationState != state.OperationPlanned && !lowercaseSHA256.MatchString(payload.TreeSHA256) {
		return errors.New("durable staged operation has no valid tree digest")
	}

	switch kind {
	case "dist.rm":
		if payload.OldConfigSHA256 == payload.NewConfigSHA256 {
			return errors.New("dist.rm config hashes do not prove a removal")
		}
		if _, exists := repo.Dists[payload.Name]; exists {
			return errors.New("dist.rm new config still contains the target Dist")
		}
		if payload.Format != "" || len(payload.Architectures) != 0 || payload.EffectiveConfigSHA256 != "" || payload.EffectiveSigning != nil || payload.MetadataSignerSnapshotSHA256 != "" {
			return errors.New("dist.rm payload contains fields outside its closed schema")
		}
		if !lowercaseSHA256.MatchString(payload.TreeSHA256) {
			return errors.New("dist.rm payload has no valid live tree digest")
		}
		if _, err := store.GetDist(ctx, payload.Name); err != nil {
			return fmt.Errorf("dist.rm target is absent from state: %w", err)
		}
		return nil

	case "dist.new", "dist.init":
		configured, exists := repo.Dists[payload.Name]
		if !exists {
			return errors.New("payload new config does not contain the target Dist")
		}
		if payload.Format != "rpm" && payload.Format != "deb" {
			return fmt.Errorf("unsupported payload format %q", payload.Format)
		}
		if configured.Format != payload.Format {
			return errors.New("payload format differs from the new config")
		}
		if err := validateArchitectureProjections(payload.Format, payload.Architectures); err != nil {
			return err
		}
		expected, err := configuredArchitectureState(parsed, repoName, payload.Name, payload.Format)
		if err != nil {
			return err
		}

		if kind == "dist.new" && payload.OldConfigSHA256 == payload.NewConfigSHA256 {
			return errors.New("dist.new config hashes do not prove an addition")
		}
		if kind == "dist.init" && payload.OldConfigSHA256 != payload.NewConfigSHA256 {
			return errors.New("dist.init must initialize one unchanged config")
		}
		if !sameArchitectureProjectionList(payload.Architectures, expected) {
			return errors.New("payload architectures differ from the new config")
		}
		stagedEvidence := payload.TreeSHA256 != ""
		if !stagedEvidence {
			if operationState != state.OperationPlanned || payload.EffectiveConfigSHA256 != "" || payload.EffectiveSigning != nil || payload.MetadataSignerSnapshotSHA256 != "" {
				return errors.New("minimal planned Dist payload contains premature staged evidence")
			}
		} else {
			if !lowercaseSHA256.MatchString(payload.EffectiveConfigSHA256) {
				return errors.New("payload effective config digest is malformed")
			}
			if payload.Version == 1 {
				if payload.EffectiveSigning != nil || payload.MetadataSignerSnapshotSHA256 != "" {
					return errors.New("legacy Dist payload contains v2 signer fields")
				}
				effectiveSHA, _, err := effectiveDistConfig(ctx, root, parsed, repoName, payload.Name)
				if err != nil || effectiveSHA != payload.EffectiveConfigSHA256 {
					return errors.New("legacy payload effective config digest does not match the new config")
				}
			} else {
				if payload.EffectiveSigning == nil || !frozenSigningReferencesMatchForFormat(parsed.Repositories[repoName].Signing, *payload.EffectiveSigning, payload.Format) {
					return errors.New("payload effective signing references differ from the new config")
				}
				effectiveSHA, _, err := effectiveDistConfigFrozen(parsed, repoName, payload.Name, *payload.EffectiveSigning)
				if err != nil || effectiveSHA != payload.EffectiveConfigSHA256 {
					return errors.New("payload effective config digest does not match its frozen signing identity")
				}
				identity, err := loadDistMetadataSignerSnapshot(root, repoName, operationID, payload.MetadataSignerSnapshotSHA256)
				if err != nil {
					return err
				}
				wantFingerprint := frozenMetadataFingerprint(payload.Format, *payload.EffectiveSigning)
				if identity.Fingerprint != wantFingerprint {
					return errors.New("metadata signer snapshot differs from the frozen effective signing identity")
				}
			}
		}
		if _, err := store.GetDist(ctx, payload.Name); !errors.Is(err, state.ErrNotFound) {
			if err == nil {
				return errors.New("dist add target already exists in state")
			}
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported operation kind %q", kind)
	}
}

func frozenSigningReferencesMatchForFormat(raw config.SigningConfig, frozen config.EffectiveSigningConfig, format string) bool {
	wantRPM := format == "rpm" || format == "both"
	wantDEB := format == "deb" || format == "both"
	if wantRPM {
		mode := raw.RPM.Packages.Mode
		if mode == "" {
			mode = "never"
		}
		if frozen.RPM.Packages.Mode != mode || frozen.RPM.Packages.Key != raw.RPM.Packages.Key || !sameStringSet(frozen.RPM.Packages.TrustedKeys, raw.RPM.Packages.TrustedKeys) {
			return false
		}
		if raw.RPM.Packages.Key == "" {
			if frozen.RPM.Packages.KeyFingerprint != "" {
				return false
			}
		} else if !managedFingerprint.MatchString(frozen.RPM.Packages.KeyFingerprint) {
			return false
		}
		for _, fingerprint := range frozen.RPM.Packages.TrustedKeyFingerprints {
			if !managedFingerprint.MatchString(fingerprint) || fingerprint != strings.ToUpper(fingerprint) {
				return false
			}
		}
		if raw.RPM.Metadata.Key == "" {
			if frozen.RPM.Metadata != nil {
				return false
			}
		} else if frozen.RPM.Metadata == nil || frozen.RPM.Metadata.Key != raw.RPM.Metadata.Key || frozen.RPM.Metadata.Passphrase != raw.RPM.Metadata.Passphrase || !managedFingerprint.MatchString(frozen.RPM.Metadata.KeyFingerprint) {
			return false
		}
	}
	if !wantDEB {
		return true
	}
	if raw.DEB.Metadata.Key == "" {
		return frozen.DEB == nil
	}
	return frozen.DEB != nil && frozen.DEB.Metadata.Key == raw.DEB.Metadata.Key && frozen.DEB.Metadata.Passphrase == raw.DEB.Metadata.Passphrase && managedFingerprint.MatchString(frozen.DEB.Metadata.KeyFingerprint)
}

func frozenMetadataFingerprint(format string, frozen config.EffectiveSigningConfig) string {
	if format == "rpm" {
		if frozen.RPM.Metadata != nil {
			return strings.ToUpper(frozen.RPM.Metadata.KeyFingerprint)
		}
		return ""
	}
	if frozen.DEB != nil {
		return strings.ToUpper(frozen.DEB.Metadata.KeyFingerprint)
	}
	return ""
}

func validateArchitectureProjections(format string, architectures []state.Architecture) error {
	if len(architectures) == 0 {
		return errors.New("payload architecture list is empty")
	}
	seen := make(map[string]struct{}, len(architectures))
	for _, architecture := range architectures {
		want := architecture.Family
		switch architecture.Family {
		case "x86_64":
			if format == "deb" {
				want = "amd64"
			}
		case "aarch64":
			if format == "deb" {
				want = "arm64"
			}
		default:
			return fmt.Errorf("invalid architecture family %q", architecture.Family)
		}
		if architecture.EcosystemArch != want {
			return fmt.Errorf("invalid %s projection %q for %q", format, architecture.EcosystemArch, architecture.Family)
		}
		if _, duplicate := seen[architecture.Family]; duplicate {
			return fmt.Errorf("duplicate architecture family %q", architecture.Family)
		}
		seen[architecture.Family] = struct{}{}
	}
	return nil
}

func sameArchitectureProjectionList(left, right []state.Architecture) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func acquireLifecycleLocks(ctx context.Context, root, repoName string, opts LockOptions) (*fileLock, *fileLock, error) {
	started := time.Now()
	workspaceLock, err := acquireFileLock(ctx, filepath.Join(root, ".sow", "workspace.lock"), opts.Timeout, opts.NoWait)
	if err != nil {
		return nil, nil, err
	}
	remaining, err := remainingLockTimeout(opts.Timeout, started)
	if err != nil {
		workspaceLock.Close()
		return nil, nil, err
	}
	repoLock, err := acquireFileLock(ctx, filepath.Join(root, ".sow", "repo-locks", repoName+".lock"), remaining, opts.NoWait)
	if err != nil {
		workspaceLock.Close()
		return nil, nil, err
	}
	return workspaceLock, repoLock, nil
}

// acquireRepositoryLocks freezes Workspace lifecycle/configuration with a
// shared lock while taking the selected Repository's exclusive writer lock.
// Different repositories can therefore progress concurrently, while
// init/repo new/repo rm and Dist lifecycle (which rewrite sow.yml) remain
// serialized by the exclusive Workspace lock.
func acquireSelectedRepositoryLocks(ctx context.Context, ws config.Workspace, explicitRepository string, opts LockOptions) (config.Config, string, string, *fileLock, *fileLock, error) {
	started := time.Now()
	for {
		remaining, err := remainingLockTimeout(opts.Timeout, started)
		if err != nil {
			return config.Config{}, "", "", nil, nil, err
		}
		workspaceLock, err := acquireSharedFileLockWithOptions(ctx, filepath.Join(ws.Root, ".sow", "workspace.lock"), remaining, opts.NoWait)
		if err != nil {
			return config.Config{}, "", "", nil, nil, err
		}
		fail := func(err error) (config.Config, string, string, *fileLock, *fileLock, error) {
			return config.Config{}, "", "", nil, nil, errors.Join(err, workspaceLock.Close())
		}
		journal, err := inspectWorkspaceJournal(ws.Root)
		if err != nil {
			return fail(err)
		}
		if journal != nil {
			// A stale lifecycle journal cannot be repaired under a shared lock.
			// Drop it, acquire the Workspace lock exclusively within the same
			// timeout budget, recover idempotently, then restart selection from
			// the new locked configuration snapshot.
			if err := workspaceLock.Close(); err != nil {
				return config.Config{}, "", "", nil, nil, err
			}
			remaining, err = remainingLockTimeout(opts.Timeout, started)
			if err != nil {
				return config.Config{}, "", "", nil, nil, err
			}
			recoveryLock, err := acquireFileLock(ctx, filepath.Join(ws.Root, ".sow", "workspace.lock"), remaining, opts.NoWait)
			if err != nil {
				return config.Config{}, "", "", nil, nil, err
			}
			recoveryErr := recoverWorkspaceOperation(ctx, ws.Root)
			if err := errors.Join(recoveryErr, recoveryLock.Close()); err != nil {
				return config.Config{}, "", "", nil, nil, err
			}
			continue
		}
		cfg, configSHA, err := loadWorkspaceWithSHA(ws)
		if err != nil {
			return fail(err)
		}
		repoName, err := selectRepo(ws, cfg, explicitRepository)
		if err != nil {
			return fail(err)
		}
		remaining, err = remainingLockTimeout(opts.Timeout, started)
		if err != nil {
			return fail(err)
		}
		repoLock, err := acquireFileLock(ctx, filepath.Join(ws.Root, ".sow", "repo-locks", repoName+".lock"), remaining, opts.NoWait)
		if err != nil {
			return fail(err)
		}
		return cfg, configSHA, repoName, workspaceLock, repoLock, nil
	}
}

func remainingLockTimeout(timeout time.Duration, started time.Time) (time.Duration, error) {
	if timeout == 0 {
		return 0, nil
	}
	remaining := timeout - time.Since(started)
	if remaining <= 0 {
		return 0, ErrLockUnavailable
	}
	return remaining, nil
}

func selectRepo(ws config.Workspace, cfg config.Config, explicit string) (string, error) {
	selection, err := config.SelectRepository(ws, cfg, config.SelectRepositoryOptions{Explicit: explicit})
	if err != nil {
		class := ErrWorkspaceInput
		if explicit != "" {
			class = ErrRejected
		}
		return "", fmt.Errorf("%w: %v", class, err)
	}
	return selection.Name, nil
}

func distStageRoot(root, repoName, id string) string {
	return filepath.Join(root, ".sow", repoName, "stage", id)
}

func distRecoveryPath(root, repoName, id string) string {
	return filepath.Join(root, ".sow", repoName, "recovery", id)
}

func installStagedDist(ctx context.Context, root, repoName, distName, id, expectedSHA string) error {
	source := filepath.Join(distStageRoot(root, repoName, id), "dists", distName)
	target := filepath.Join(root, repoName, "dists", distName)
	if info, err := os.Lstat(target); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: unsafe live Dist path", ErrIntegrity)
		}
		if _, sourceErr := os.Lstat(source); sourceErr == nil {
			return fmt.Errorf("%w: staged and live Dist both exist", ErrIntegrity)
		} else if !errors.Is(sourceErr, os.ErrNotExist) {
			return sourceErr
		}
		actual, _, digestErr := digestTree(ctx, target)
		if digestErr != nil || actual != expectedSHA {
			return fmt.Errorf("%w: live Dist tree digest mismatch", ErrIntegrity)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	info, err := os.Lstat(source)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: staged Dist is missing or unsafe", ErrIntegrity)
	}
	actual, _, err := digestTree(ctx, source)
	if err != nil || actual != expectedSHA {
		return fmt.Errorf("%w: staged Dist tree digest mismatch", ErrIntegrity)
	}
	if err := requireSameDevice(filepath.Dir(source), filepath.Dir(target)); err != nil {
		return err
	}
	if err := durableRename(root, source, target); err != nil {
		return err
	}
	return nil
}

func moveDistToRecovery(ctx context.Context, root, repoName, distName, id, expectedSHA string) error {
	live := filepath.Join(root, repoName, "dists", distName)
	recovery := distRecoveryPath(root, repoName, id)
	if info, err := os.Lstat(recovery); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: unsafe Dist recovery path", ErrIntegrity)
		}
		if _, liveErr := os.Lstat(live); liveErr == nil {
			return fmt.Errorf("%w: live and recovery Dist both exist", ErrIntegrity)
		} else if !errors.Is(liveErr, os.ErrNotExist) {
			return liveErr
		}
		actual, _, digestErr := digestTree(ctx, recovery)
		if digestErr != nil || actual != expectedSHA {
			return fmt.Errorf("%w: recovery Dist tree digest mismatch", ErrIntegrity)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	info, err := os.Lstat(live)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: Dist is absent from both live and recovery", ErrIntegrity)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: unsafe live Dist path", ErrIntegrity)
	}
	actual, _, err := digestTree(ctx, live)
	if err != nil || actual != expectedSHA {
		return fmt.Errorf("%w: live Dist tree digest mismatch before removal", ErrIntegrity)
	}
	if err := requireSameDevice(filepath.Dir(live), filepath.Dir(recovery)); err != nil {
		return err
	}
	if err := durableRename(root, live, recovery); err != nil {
		return err
	}
	return nil
}

func cleanupDistRecovery(root, repoName, id string) error {
	path := distRecoveryPath(root, repoName, id)
	if info, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: unsafe Dist recovery path", ErrIntegrity)
	}
	return removeOwnedDirectory(path, filepath.Join(root, ".sow", repoName, "recovery"))
}

func liveArchitectureView(root, repoName, distName, format string, architecture state.Architecture) string {
	if format == "rpm" {
		return filepath.Join(root, repoName, "dists", distName, architecture.Family)
	}
	return filepath.Join(root, repoName, "dists", distName, "main", "binary-"+architecture.EcosystemArch)
}

func validateLiveDistViews(ctx context.Context, root, repoName, format, distName string, architectures []state.Architecture) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil validation context", ErrIntegrity)
	}
	if err := validateLiveDistViewPaths(root, repoName, format, distName, architectures); err != nil {
		return err
	}
	switch format {
	case "rpm":
		for _, architecture := range architectures {
			repodata := filepath.Join(liveArchitectureView(root, repoName, distName, format, architecture), "repodata")
			var err error
			if _, statErr := os.Lstat(filepath.Join(repodata, "repomd.xml.asc")); statErr == nil {
				_, err = yumrepo.ValidateManagedDirectory(ctx, repodata, yumrepo.CompressionGzip, structuralDetachedVerifier{})
			} else if errors.Is(statErr, os.ErrNotExist) {
				_, err = yumrepo.ValidateManagedUnsignedDirectory(ctx, repodata, yumrepo.CompressionGzip)
			} else {
				err = statErr
			}
			if err != nil {
				return fmt.Errorf("%w: invalid managed RPM view %q: %v", ErrIntegrity, architecture.Family, err)
			}
		}
	case "deb":
		if err := validateManagedAPTDist(ctx, filepath.Join(root, repoName), distName, architectures, nil, nil, nil); err != nil {
			return fmt.Errorf("%w: invalid managed DEB Dist: %v", ErrIntegrity, err)
		}
	default:
		return fmt.Errorf("%w: built Dist has unsupported format %q", ErrIntegrity, format)
	}
	return nil
}

func validateLiveDistViewPaths(root, repoName, format, distName string, architectures []state.Architecture) error {
	if len(architectures) == 0 {
		return fmt.Errorf("%w: built Dist has no architecture views", ErrIntegrity)
	}
	if err := config.ValidateName(repoName); err != nil {
		return fmt.Errorf("%w: invalid built repository name: %v", ErrIntegrity, err)
	}
	if err := config.ValidateName(distName); err != nil {
		return fmt.Errorf("%w: invalid built Dist name: %v", ErrIntegrity, err)
	}
	if err := validateRepositoryLayout(root, repoName); err != nil {
		return err
	}
	for _, architecture := range architectures {
		if architecture.Family != "x86_64" && architecture.Family != "aarch64" {
			return fmt.Errorf("%w: invalid built architecture family %q", ErrIntegrity, architecture.Family)
		}
		wantEcosystem := architecture.Family
		if format == "deb" {
			if architecture.Family == "x86_64" {
				wantEcosystem = "amd64"
			} else {
				wantEcosystem = "arm64"
			}
		}
		if architecture.EcosystemArch != wantEcosystem {
			return fmt.Errorf("%w: invalid %s projection %q for %q", ErrIntegrity, format, architecture.EcosystemArch, architecture.Family)
		}
		view := liveArchitectureView(root, repoName, distName, format, architecture)
		repositoryRoot := filepath.Join(root, repoName)
		relative, err := filepath.Rel(repositoryRoot, view)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("%w: built architecture view %q escapes repository", ErrIntegrity, architecture.Family)
		}
		if err := rejectSymlinkChain(repositoryRoot, relative, false); err != nil {
			return fmt.Errorf("%w: built architecture view %q is unsafe: %v", ErrIntegrity, architecture.Family, err)
		}
		info, err := os.Lstat(view)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: built architecture view %q is missing or unsafe", ErrIntegrity, architecture.Family)
		}
	}
	if format != "rpm" && format != "deb" {
		return fmt.Errorf("%w: built Dist has unsupported format %q", ErrIntegrity, format)
	}
	return nil
}
