package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

// renderMaterializeEdgeContract is the product entrypoint for the exact same
// raw/active admission consumed by both edge adapters. It is read-only and
// secret-free: provider credentials remain references/names in the returned
// deployment document, and no provider client is constructed.
func renderMaterializeEdgeContract(ctx context.Context, cfg *config.Config, targetName string, values commonFlags, stdout io.Writer) (resultErr error) {
	if cfg == nil || targetName == "" {
		return withExitCode(ExitUsage, "--edge-contract requires one configured target")
	}
	if _, exists := cfg.Targets[targetName]; !exists {
		return withExitCode(ExitConfig, "edge deployment target %q is not configured", targetName)
	}
	var targetRepos []config.Repo
	for _, repo := range cfg.Repos {
		if repo.IsActive() && repo.PublishesToTarget(targetName) {
			targetRepos = append(targetRepos, repo)
		}
	}
	session, err := openLocalReadAdmission(cfg)
	if err != nil {
		return withExitCode(ExitVerification, "edge read admission: %v", err)
	}
	defer func() { resultErr = errors.Join(resultErr, session.Close()) }()
	raw, active, err := admittedNginxCompatibilityWithSession(ctx, cfg, targetRepos, "latest", cfg.Root, values, session)
	if err != nil {
		return withExitCode(ExitVerification, "edge compatibility admission: %v", err)
	}
	if err := runNginxCompatibilityAdmissionHook(ctx, "after-compat-admission", targetName); err != nil {
		return withExitCode(ExitVerification, "edge read admission hook: %v", err)
	}
	snapshots, err := admittedEdgeSnapshotsWithSession(cfg, targetName, session)
	if err != nil {
		return withExitCode(ExitVerification, "edge snapshot admission: %v", err)
	}
	if err := runNginxCompatibilityAdmissionHook(ctx, "after-snapshot-admission", targetName); err != nil {
		return withExitCode(ExitVerification, "edge snapshot admission hook: %v", err)
	}
	contract, err := cfg.EdgeDeployment(targetName, config.EdgeCompatibilityAdmission{RawIDs: raw, ActiveIDs: active, Snapshots: snapshots})
	if err != nil {
		return withExitCode(ExitConfig, "edge deployment contract: %v", err)
	}
	body, err := json.MarshalIndent(contract, "", "  ")
	if err != nil {
		return withExitCode(ExitInternal, "encode edge deployment contract: %v", err)
	}
	body = append(body, '\n')
	if err := session.Verify(cfg.Root); err != nil {
		return withExitCode(ExitVerification, "edge final read admission: %v", err)
	}
	if _, err := stdout.Write(body); err != nil {
		return withExitCode(ExitInternal, "write edge deployment contract: %v", err)
	}
	return nil
}

type edgeSnapshotRouteSet struct {
	aptRoots   map[string]struct{}
	yumRoots   map[string]struct{}
	assetRoots map[string]struct{}
	assetKeys  map[string]struct{}
}

// admittedEdgeSnapshots derives a per-snapshot route closure from immutable
// snapshot refs and the configuration committed at each ref. Current active
// flags and mutable view membership are intentionally irrelevant: an EOL
// snapshot remains routable, while its roots cannot be borrowed by a sibling
// snapshot because every ID receives a separate exact inventory.
func admittedEdgeSnapshots(cfg *config.Config, targetName string) (result []config.EdgeSnapshotAdmission, resultErr error) {
	session, err := openLocalReadAdmission(cfg)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, session.Close()) }()
	result, resultErr = admittedEdgeSnapshotsWithSession(cfg, targetName, session)
	if resultErr == nil {
		resultErr = session.Verify(cfg.Root)
	}
	return result, resultErr
}

func admittedEdgeSnapshotsWithSession(cfg *config.Config, targetName string, session *localReadAdmission) (result []config.EdgeSnapshotAdmission, resultErr error) {
	if cfg == nil || targetName == "" {
		return nil, errors.New("edge snapshot admission dependencies are unavailable")
	}
	if _, exists := cfg.Targets[targetName]; !exists {
		return nil, fmt.Errorf("edge deployment target %q is not configured", targetName)
	}
	if session == nil || session.root == nil {
		return nil, errors.New("edge snapshot read admission is unavailable")
	}
	if session.canonical == nil {
		return []config.EdgeSnapshotAdmission{}, nil
	}
	if err := session.requireNoMutationLock(); err != nil {
		return nil, err
	}
	canonical := session.canonical
	refs, err := canonical.SOWRefs()
	if err != nil {
		return nil, err
	}
	sets := make(map[string]*edgeSnapshotRouteSet)
	configAt := make(map[string]*config.Config)
	for _, ref := range refs {
		snapshotID, repoID, osName, arch, snapshot, err := parseEdgeSnapshotRef(ref.Name.String())
		if err != nil {
			return nil, err
		}
		if !snapshot {
			continue
		}
		committed := configAt[ref.Hash.String()]
		if committed == nil {
			committed, err = canonicalConfigurationAt(canonical, ref.Hash, cfg)
			if err != nil {
				return nil, fmt.Errorf("edge snapshot %s historical config at %s: %w", snapshotID, ref.Hash, err)
			}
			configAt[ref.Hash.String()] = committed
		}
		repo, exists := committed.RepoByName(repoID)
		if !exists {
			return nil, fmt.Errorf("edge snapshot ref %s has no historical repository owner", ref.Name)
		}
		if err := validateEdgeSnapshotRefCoordinate(repo, osName, arch); err != nil {
			return nil, fmt.Errorf("edge snapshot ref %s: %w", ref.Name, err)
		}
		snapshotPath, pathErr := state.SnapshotPath(snapshotID, repoID, osName, arch)
		if pathErr != nil {
			return nil, fmt.Errorf("edge snapshot ref %s path: %w", ref.Name, pathErr)
		}
		if err := validateViewAt(canonical, ref.Hash, snapshotPath, viewLeaf{repo: repo, os: osName, arch: arch}, false); err != nil {
			return nil, fmt.Errorf("edge snapshot ref %s manifest: %w", ref.Name, err)
		}
		if !repo.PublishesToTarget(targetName) {
			continue
		}
		set := sets[snapshotID]
		if set == nil {
			set = &edgeSnapshotRouteSet{aptRoots: map[string]struct{}{}, yumRoots: map[string]struct{}{}, assetRoots: map[string]struct{}{}, assetKeys: map[string]struct{}{}}
			sets[snapshotID] = set
		}
		switch repo.Type {
		case "apt":
			set.aptRoots[repo.Path] = struct{}{}
		case "yum":
			root, pathErr := repo.PathForArch(arch)
			if pathErr != nil {
				return nil, fmt.Errorf("edge snapshot ref %s root: %w", ref.Name, pathErr)
			}
			set.yumRoots[root] = struct{}{}
		case "asset":
			if root := repo.AssetPublicRoot(); root == "." {
				for _, key := range repo.Asset.RootKeys {
					set.assetKeys[key] = struct{}{}
				}
			} else {
				set.assetRoots[root] = struct{}{}
			}
		default:
			return nil, fmt.Errorf("edge snapshot ref %s has unsupported repository type %q", ref.Name, repo.Type)
		}
	}
	ids := make([]string, 0, len(sets))
	for id := range sets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		set := sets[id]
		result = append(result, config.EdgeSnapshotAdmission{
			ID: id, APTRoots: sortedEdgeSnapshotRoutes(set.aptRoots), YUMRoots: sortedEdgeSnapshotRoutes(set.yumRoots),
			AssetRoots: sortedEdgeSnapshotRoutes(set.assetRoots), AssetKeys: sortedEdgeSnapshotRoutes(set.assetKeys),
		})
	}
	return result, nil
}

func parseEdgeSnapshotRef(name string) (snapshotID, repoID, osName, arch string, snapshot bool, err error) {
	const prefix = "refs/sow/snapshots/"
	if !strings.HasPrefix(name, prefix) {
		return "", "", "", "", false, nil
	}
	parts := strings.Split(strings.TrimPrefix(name, prefix), "/")
	if len(parts) != 4 || views.ValidateSnapshotID(parts[0]) != nil || parts[1] == "" || parts[2] == "" || parts[3] == "" {
		return "", "", "", "", false, fmt.Errorf("invalid canonical snapshot ref %s", name)
	}
	return parts[0], parts[1], parts[2], parts[3], true, nil
}

func validateEdgeSnapshotRefCoordinate(repo config.Repo, osName, arch string) error {
	switch repo.Type {
	case "asset":
		if repo.Asset == nil || osName != "all" || arch != "all" {
			return errors.New("asset coordinate must be all/all")
		}
	case "apt":
		if repo.APT == nil || !contains(repo.APT.Suites, osName) || !contains(repo.Arches, arch) {
			return errors.New("APT coordinate is outside the historical repository contract")
		}
	case "yum":
		if repo.YUM == nil || !contains(repo.OSSelectorValues(), osName) || !contains(repo.Arches, arch) {
			return errors.New("YUM coordinate is outside the historical repository contract")
		}
	default:
		return fmt.Errorf("unsupported repository type %q", repo.Type)
	}
	return nil
}

func sortedEdgeSnapshotRoutes(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
