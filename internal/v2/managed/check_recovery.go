package managed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

// mutationRecoveryView is read-only evidence for a journal-bound physical
// transition. A mutation build deliberately publishes payloads before Dist
// pointers and commits SQLite last. Check must therefore accept only the exact
// old/new combinations recoverMutationOperation can deterministically finish;
// it must not mistake an arbitrary public-tree difference for recoverability.
type mutationRecoveryView struct {
	operation    state.Operation
	manifest     mutationManifest
	base         []state.GenerationFile
	physical     []state.GenerationFile
	pooledPublic map[string]struct{}
	targetDists  map[string]mutationBuildDist
}

func inspectMutationRecoveryView(ctx context.Context, root, repoName string, store *state.Store, summary state.RepositorySummary, pending []state.Operation) (*mutationRecoveryView, error) {
	var candidate *state.Operation
	for index := range pending {
		operation := &pending[index]
		if operation.Kind != "add" && operation.Kind != "rm" && operation.Kind != "build" {
			continue
		}
		if candidate != nil {
			return nil, fmt.Errorf("%w: multiple pending package mutations", ErrIntegrity)
		}
		candidate = operation
	}
	if candidate == nil {
		return nil, nil
	}

	var payload mutationOperationPayload
	if err := jsonUnmarshalStrict(candidate.PayloadJSON, &payload); err != nil || payload.Version != mutationOperationVersion || payload.Repository != repoName || payload.Kind != candidate.Kind || !lowercaseSHA256.MatchString(payload.ConfigSHA256) || len(payload.Dists) == 0 {
		return nil, fmt.Errorf("%w: invalid pending mutation binding", ErrIntegrity)
	}
	configSHA, err := config.FileSHA(filepath.Join(root, config.ConfigFilename))
	if err != nil || configSHA != payload.ConfigSHA256 {
		return nil, fmt.Errorf("%w: current config differs from pending mutation", ErrIntegrity)
	}
	if payload.ManifestSHA256 == "" {
		if candidate.State != state.OperationPlanned && candidate.State != state.OperationRecovering {
			return nil, fmt.Errorf("%w: pending mutation has no bound manifest in state %s", ErrIntegrity, candidate.State)
		}
		return nil, nil
	}
	operation, payload, manifest, err := loadMutationOperation(ctx, store, root, repoName, candidate.ID)
	if err != nil {
		return nil, err
	}
	if !sameStringSet(payload.Dists, mapsKeys(manifest.Desired)) {
		return nil, fmt.Errorf("%w: mutation manifest Dist set differs from journal", ErrIntegrity)
	}
	if manifest.Build == nil {
		return nil, nil
	}
	if operation.State != state.OperationApplied && operation.State != state.OperationBuilt && operation.State != state.OperationRecovering {
		return nil, fmt.Errorf("%w: mutation build plan exists in state %s", ErrIntegrity, operation.State)
	}
	nextGeneration, nextErr := summary.BuiltGeneration.Next()
	if nextErr != nil || manifest.Build.Generation != nextGeneration || manifest.Build.Generation < 1 || !lowercaseSHA256.MatchString(manifest.Build.BaseManifestSHA256) {
		return nil, fmt.Errorf("%w: mutation build generation is inconsistent", ErrIntegrity)
	}
	base, err := readMutationBaseManifest(root, repoName, operation.ID, manifest.Build.BaseManifestSHA256)
	if err != nil {
		return nil, err
	}
	retained, err := store.GenerationManifest(ctx, summary.BuiltGeneration)
	if err != nil {
		return nil, err
	}
	if !sameGenerationManifest(base, retained) {
		return nil, fmt.Errorf("%w: mutation base manifest differs from current Generation", ErrIntegrity)
	}

	view := &mutationRecoveryView{
		operation:    operation,
		manifest:     manifest,
		base:         base,
		pooledPublic: map[string]struct{}{},
		targetDists:  map[string]mutationBuildDist{},
	}
	expected := generationManifestMap(base)
	seenPooled := map[string]struct{}{}
	for _, digest := range manifest.Build.Pooled {
		if !lowercaseSHA256.MatchString(digest) {
			return nil, fmt.Errorf("%w: mutation build has invalid pooled digest", ErrIntegrity)
		}
		if _, duplicate := seenPooled[digest]; duplicate {
			return nil, fmt.Errorf("%w: mutation build repeats pooled digest %s", ErrIntegrity, digest)
		}
		seenPooled[digest] = struct{}{}
		object, err := store.GetPackageObject(ctx, digest)
		if err != nil || object.Storage != "pending" {
			return nil, fmt.Errorf("%w: mutation pooled package %s is absent from pending state", ErrIntegrity, digest)
		}
		pendingRelative := filepath.Join(".sow", repoName, "pending", digest)
		publicRelative := filepath.Join(repoName, filepath.FromSlash(object.PoolPath))
		pendingOK, err := exactPackageCopy(ctx, root, pendingRelative, object)
		if err != nil {
			return nil, err
		}
		publicOK, err := exactPackageCopy(ctx, root, publicRelative, object)
		if err != nil {
			return nil, err
		}
		if pendingOK == publicOK {
			return nil, fmt.Errorf("%w: pooled package %s has %d durable publication locations, want exactly one", ErrIntegrity, digest, map[bool]int{true: 2, false: 0}[pendingOK])
		}
		if publicOK {
			view.pooledPublic[digest] = struct{}{}
			expected[object.PoolPath] = state.GenerationFile{Path: object.PoolPath, Phase: "payload", Size: object.Size, SHA256: object.SHA256}
		}
	}

	buildDistNames := make([]string, 0, len(manifest.Build.Dists))
	for _, buildDist := range manifest.Build.Dists {
		if buildDist.Name == "" || !lowercaseSHA256.MatchString(buildDist.TreeSHA256) || !lowercaseSHA256.MatchString(buildDist.EffectiveConfigSHA256) || len(buildDist.Architectures) == 0 {
			return nil, fmt.Errorf("%w: invalid mutation build Dist binding", ErrIntegrity)
		}
		if _, duplicate := view.targetDists[buildDist.Name]; duplicate {
			return nil, fmt.Errorf("%w: mutation build repeats Dist %q", ErrIntegrity, buildDist.Name)
		}
		buildDistNames = append(buildDistNames, buildDist.Name)
		liveRoot := filepath.Join(root, repoName, "dists", buildDist.Name)
		stageRoot := filepath.Join(mutationStageRoot(root, repoName, operation.ID), "build", "dists", buildDist.Name)
		prefix := "dists/" + buildDist.Name + "/"
		baseDist := generationManifestPrefix(base, prefix)
		live, err := scanTreeManifest(ctx, liveRoot, prefix)
		if err != nil {
			return nil, fmt.Errorf("%w: inspect live Dist %q: %v", ErrIntegrity, buildDist.Name, err)
		}
		staged, err := scanTreeManifest(ctx, stageRoot, prefix)
		if err != nil {
			return nil, fmt.Errorf("%w: inspect staged Dist %q: %v", ErrIntegrity, buildDist.Name, err)
		}
		liveTree, _, err := digestTree(ctx, liveRoot)
		if err != nil {
			return nil, err
		}
		stageTree, _, err := digestTree(ctx, stageRoot)
		if err != nil {
			return nil, err
		}
		switch {
		case liveTree == buildDist.TreeSHA256:
			if !sameGenerationManifest(staged, baseDist) {
				return nil, fmt.Errorf("%w: staged Dist %q is not the journaled old tree after exchange", ErrIntegrity, buildDist.Name)
			}
			for path := range expected {
				if strings.HasPrefix(path, prefix) {
					delete(expected, path)
				}
			}
			for _, file := range live {
				expected[file.Path] = file
			}
			view.targetDists[buildDist.Name] = buildDist
		case sameGenerationManifest(live, baseDist):
			if stageTree != buildDist.TreeSHA256 {
				return nil, fmt.Errorf("%w: staged Dist %q differs from journal target", ErrIntegrity, buildDist.Name)
			}
		default:
			return nil, fmt.Errorf("%w: live Dist %q is neither the old nor journal target tree", ErrIntegrity, buildDist.Name)
		}
	}
	if !sameStringSet(buildDistNames, payload.BuildDists) {
		return nil, fmt.Errorf("%w: mutation build Dist set differs from operation", ErrIntegrity)
	}
	if len(view.targetDists) != 0 && len(view.pooledPublic) != len(manifest.Build.Pooled) {
		return nil, fmt.Errorf("%w: a new Dist pointer is public before all journal payloads", ErrIntegrity)
	}
	physical, err := scanPublicManifest(ctx, filepath.Join(root, repoName))
	if err != nil {
		return nil, err
	}
	view.physical = physical
	if !sameGenerationManifest(generationManifestValues(expected), physical) {
		return nil, fmt.Errorf("%w: recovering public tree exceeds the journaled transition", ErrIntegrity)
	}
	return view, nil
}

func exactPackageCopy(ctx context.Context, root, relative string, object state.PackageObject) (bool, error) {
	source := ManagedPackageSource{Object: object, Owner: root, Relative: relative, Path: filepath.Join(root, relative)}
	opened, err := source.open()
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: package copy %s is unsafe", ErrIntegrity, object.SHA256)
	}
	digest, hashErr := hashOpenedFileContext(ctx, opened.file)
	verifyErr := opened.CloseVerified()
	if hashErr != nil || verifyErr != nil || digest != object.SHA256 {
		return false, fmt.Errorf("%w: package copy %s checksum differs", ErrIntegrity, object.SHA256)
	}
	return true, nil
}

func scanTreeManifest(ctx context.Context, root, prefix string) ([]state.GenerationFile, error) {
	files := []state.GenerationFile{}
	err := walkRootedTree(ctx, root, func(relative string, file *os.File, info os.FileInfo) error {
		path := prefix + relative
		phase := publicFilePhase(path)
		if phase == "" {
			return fmt.Errorf("%w: recovery dists contains package payload %s", ErrIntegrity, path)
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, &managedContextReader{ctx: ctx, reader: file}); err != nil {
			return err
		}
		files = append(files, state.GenerationFile{Path: path, Phase: phase, Size: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil))})
		return nil
	}, nil)
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func generationManifestPrefix(files []state.GenerationFile, prefix string) []state.GenerationFile {
	result := []state.GenerationFile{}
	for _, file := range files {
		if strings.HasPrefix(file.Path, prefix) {
			result = append(result, file)
		}
	}
	return result
}

func generationManifestMap(files []state.GenerationFile) map[string]state.GenerationFile {
	result := make(map[string]state.GenerationFile, len(files))
	for _, file := range files {
		result[file.Path] = file
	}
	return result
}

func generationManifestValues(files map[string]state.GenerationFile) []state.GenerationFile {
	result := make([]state.GenerationFile, 0, len(files))
	for _, file := range files {
		result = append(result, file)
	}
	return result
}

func recoveringRPMMetadataVerifier(build mutationBuildDist, at state.Operation) (yumrepo.DetachedVerifier, bool, error) {
	identity := metadataSignerIdentity{Fingerprint: build.MetadataSignerFingerprint, PublicKey: build.MetadataSignerPublicKey}
	if err := validateMetadataSignerIdentity(identity); err != nil {
		return nil, false, err
	}
	if identity.Fingerprint == "" {
		return nil, false, nil
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(identity.PublicKey), at.CreatedAt.UTC())
	return verifier, true, err
}

func recoveringAPTMetadataVerifier(build mutationBuildDist) (APTMetadataVerifier, bool, error) {
	identity := metadataSignerIdentity{Fingerprint: build.MetadataSignerFingerprint, PublicKey: build.MetadataSignerPublicKey}
	if err := validateMetadataSignerIdentity(identity); err != nil {
		return nil, false, err
	}
	if identity.Fingerprint == "" {
		return nil, false, nil
	}
	verifier, err := aptrepo.NewVerifierBytes(identity.PublicKey)
	if err != nil {
		return nil, true, err
	}
	return &inProcessAPTMetadataVerifier{verifier: verifier}, true, nil
}
