package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

type selectedWorkingArchive struct {
	Root     string
	Manifest string
}

// buildSelectedWorkingArchive derives an offline tree from the logical
// selector, independently of the physical-owner closure used to update the
// directly hosted working tree. In particular, two YUM OS aliases may share
// one live repo+arch owner while the archive contains only the requested
// alias: its repodata and immutable serving generation are rebuilt from that
// alias's exact ref, so no index can reference an omitted sibling payload.
func buildSelectedWorkingArchive(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	source materializeCanonicalSource,
	requested []viewLeaf,
	compatibility preparedPublication,
	baseURL, repositoryKeySHA, txDir string,
	privateKey, passphrase []byte,
	values commonFlags,
) (selectedWorkingArchive, error) {
	var result selectedWorkingArchive
	if cfg == nil || canonical == nil || pool == nil || len(requested) == 0 {
		return result, errors.New("selected working archive dependencies are unavailable")
	}
	root := filepath.Join(txDir, "selected-offline-tree")
	if err := os.Mkdir(root, 0o700); err != nil {
		return result, err
	}
	payload := filepath.Join(txDir, "selected-offline-payload.tsv")
	if _, _, err := projectCanonicalMaterializationLeaves(canonical, source, requested, payload); err != nil {
		return result, fmt.Errorf("project selected offline payload: %w", err)
	}
	payloadFile, err := os.Open(payload)
	if err != nil {
		return result, err
	}
	_, materializeErr := pool.MaterializeWithOptions(ctx, payloadFile, root, repository.MaterializeOptions{
		Workers: values.workers,
	})
	closeErr := payloadFile.Close()
	if materializeErr != nil || closeErr != nil {
		return result, fmt.Errorf("materialize selected offline payload: %w", errors.Join(materializeErr, closeErr))
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustPayloadAfter); err != nil {
		return result, err
	}

	// The archive tree is an ephemeral derivative, not another durable selected
	// set. The outer working-tree transaction remains its recovery fence. Turn
	// off nested unit completion while retaining explicit all-repository trust
	// barriers before and after deterministic metadata/serving construction.
	archiveValues := values
	archiveValues.materializeTrust = nil
	archiveValues.materializeTarget = root
	archiveValues.materializeUnit = ""
	metadataDir := filepath.Join(txDir, "selected-offline-metadata")
	if err := os.Mkdir(metadataDir, 0o700); err != nil {
		return result, err
	}
	if _, err := materializeRepositoryMetadata(ctx, cfg, canonical, requested, source, root, metadataDir, privateKey, passphrase, archiveValues); err != nil {
		return result, fmt.Errorf("generate selected offline metadata: %w", err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustExactReconcileAfter); err != nil {
		return result, err
	}
	if err := installSelectedArchiveYUMServing(ctx, cfg, canonical, pool, source, root, baseURL, repositoryKeySHA, metadataDir, requested, archiveValues); err != nil {
		return result, err
	}
	if err := installSelectedArchiveYUMCompatibility(ctx, cfg, canonical, pool, root, baseURL, metadataDir, compatibility, archiveValues); err != nil {
		return result, err
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustServingPublishBefore); err != nil {
		return result, err
	}
	if err := serving.PublishHostableTree(root); err != nil {
		return result, fmt.Errorf("publish selected offline tree: %w", err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustServingPublishAfter); err != nil {
		return result, err
	}
	if _, err := serving.CleanupTransactionTemps(cfg.Root, root); err != nil {
		return result, err
	}
	exact := filepath.Join(txDir, "selected-offline-exact.tsv")
	if _, err := manifest.Scan(ctx, root, manifest.Scope{Path: "."}, exact, manifest.ScanOptions{
		Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp"),
	}); err != nil {
		return result, fmt.Errorf("scan selected offline tree: %w", err)
	}
	return selectedWorkingArchive{Root: root, Manifest: exact}, nil
}

func installSelectedArchiveYUMServing(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	source materializeCanonicalSource,
	targetRoot, baseURL, repositoryKeySHA, txDir string,
	requested []viewLeaf,
	values commonFlags,
) error {
	byOwner := make(map[string][]viewLeaf)
	for _, leaf := range requested {
		if leaf.repo.Type != "yum" {
			continue
		}
		key := yumPublicationOwnerKey(leaf.repo.ID, leaf.arch)
		byOwner[key] = append(byOwner[key], leaf)
	}
	if len(byOwner) == 0 {
		return nil
	}
	if baseURL == "" || repositoryKeySHA == "" {
		return errors.New("selected offline YUM serving identity is incomplete")
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(byOwner))
	for key := range byOwner {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	installOptions := serving.InstallOptions{
		Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp"),
	}
	for ownerIndex, key := range keys {
		leaves := byOwner[key]
		sort.Slice(leaves, func(i, j int) bool {
			if leaves[i].os != leaves[j].os {
				return leaves[i].os < leaves[j].os
			}
			return leaves[i].arch < leaves[j].arch
		})
		legacyRoot, err := leaves[0].repo.PathForArch(leaves[0].arch)
		if err != nil {
			return err
		}
		rawManifest := filepath.Join(txDir, fmt.Sprintf("selected-offline-yum-%06d.tsv", ownerIndex))
		if _, err := manifest.Scan(ctx, targetRoot, manifest.Scope{Path: legacyRoot}, rawManifest, manifest.ScanOptions{
			Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp"),
		}); err != nil {
			return fmt.Errorf("scan selected offline YUM owner %s: %w", key, err)
		}
		for _, leaf := range leaves {
			_, _, commit, err := source.resolveLeaf(canonical, leaf.repo.ID, leaf.os, leaf.arch)
			if err != nil {
				return err
			}
			manifestFile, err := os.Open(rawManifest)
			if err != nil {
				return err
			}
			generation, deriveErr := serving.DeriveGeneration(serving.Identity{
				View: source.ID, Repo: leaf.repo.ID, OS: leaf.os, Arch: leaf.arch,
				LegacyRoot: legacyRoot, RefCommit: commit.String(), ConfigSHA256: configSHA,
				RepositoryKeySHA256: repositoryKeySHA,
			}, manifestFile)
			closeErr := manifestFile.Close()
			if deriveErr != nil || closeErr != nil {
				return errors.Join(deriveErr, closeErr)
			}
			if _, err := serving.InstallGeneration(ctx, pool, targetRoot, generation, rawManifest, installOptions); err != nil {
				return fmt.Errorf("install selected offline YUM generation %s/%s/%s: %w", leaf.repo.ID, leaf.os, leaf.arch, err)
			}
			channel, err := serving.NewChannel(generation, baseURL, nil)
			if err != nil {
				return err
			}
			if _, err := serving.ReconcileMirrorlist(targetRoot, channel); err != nil {
				return fmt.Errorf("write selected offline YUM mirrorlist %s: %w", channel.MirrorlistPath, err)
			}
			if err := serving.ValidateInstalledGeneration(ctx, pool, targetRoot, generation, rawManifest, installOptions); err != nil {
				return err
			}
		}
	}
	return nil
}

func installSelectedArchiveYUMCompatibility(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	targetRoot, baseURL, txDir string,
	prepared preparedPublication,
	values commonFlags,
) error {
	projections, err := selectedPreparedYUMCompatibilityProjections(cfg, prepared)
	if err != nil || len(projections) == 0 {
		return err
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return err
	}
	installOptions := serving.InstallOptions{
		Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp"),
	}
	for index, projection := range projections {
		evidence, err := loadFrozenYUMCompatibilityServingEvidence(cfg, canonical, projection)
		if err != nil {
			return err
		}
		if _, err := installFrozenYUMCompatibilityTrust(ctx, cfg, canonical, pool, targetRoot, evidence, txDir, values.workers); err != nil {
			return fmt.Errorf("install selected offline compatibility trust %s: %w", projection.ID, err)
		}
		candidate := filepath.Join(txDir, fmt.Sprintf("selected-offline-compat-%06d.tsv", index))
		if err := copyCanonicalPathAt(canonical, evidence.freezeCommit, evidence.candidatePath, candidate, evidence.receipt.CandidateManifestSize); err != nil {
			return err
		}
		candidateFile, err := os.Open(candidate)
		if err != nil {
			return err
		}
		_, materializeErr := pool.MaterializeWithOptions(ctx, candidateFile, filepath.Join(targetRoot, filepath.FromSlash(projection.Root)), repository.MaterializeOptions{Workers: values.workers})
		closeErr := candidateFile.Close()
		if materializeErr != nil || closeErr != nil {
			return fmt.Errorf("materialize selected offline compatibility %s: %w", projection.ID, errors.Join(materializeErr, closeErr))
		}
		rooted := filepath.Join(txDir, fmt.Sprintf("selected-offline-compat-rooted-%06d.tsv", index))
		if err := buildYUMCompatibilityGenerationManifest(candidate, rooted, projection.Root); err != nil {
			return err
		}
		rootedFile, err := os.Open(rooted)
		if err != nil {
			return err
		}
		generation, deriveErr := serving.DeriveGeneration(serving.Identity{
			View: "latest", Repo: projection.ID, OS: "cross-el", Arch: projection.Source.Arch,
			LegacyRoot: projection.Root, RefCommit: evidence.freezeCommit.String(), ConfigSHA256: configSHA,
			RepositoryKeySHA256: evidence.receipt.RepositoryKeySHA256,
		}, rootedFile)
		closeErr = rootedFile.Close()
		if deriveErr != nil || closeErr != nil {
			return errors.Join(deriveErr, closeErr)
		}
		if _, err := serving.InstallGeneration(ctx, pool, targetRoot, generation, rooted, installOptions); err != nil {
			return err
		}
		channel, err := serving.NewChannel(generation, baseURL, nil)
		if err != nil {
			return err
		}
		if _, err := serving.ReconcileMirrorlist(targetRoot, channel); err != nil {
			return err
		}
		if err := serving.ValidateInstalledGeneration(ctx, pool, targetRoot, generation, rooted, installOptions); err != nil {
			return err
		}
		if err := validateInstalledFrozenYUMCompatibilityTrust(ctx, pool, targetRoot, evidence); err != nil {
			return err
		}
	}
	return nil
}
