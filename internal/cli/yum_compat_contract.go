package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
)

const maximumYUMCompatibilityWitnessBytes = 64 << 10

func requireAllYUMCompatibilityFrozen(cfg *config.Config, canonical *state.Store) error {
	for _, projection := range config.SortedYUMCompatibilityProjections(cfg.CompatibilityProjections) {
		witnessPath, err := state.YUMCompatibilityProjectionPath(projection.ID)
		if err != nil {
			return err
		}
		body, exists, err := readOptionalCanonical(canonical, witnessPath)
		if err != nil || !exists {
			return errors.Join(err, fmt.Errorf("YUM compatibility projection %s is not explicitly frozen; run the compatibility candidate/freeze workflow first", projection.ID))
		}
		witness, err := decodeYUMCompatibilityWitness(body)
		if err != nil {
			return err
		}
		if err := requireYUMCompatibilityWitnessMatchesProjection(witness, projection); err != nil {
			return err
		}
		compatRef, _ := state.YUMCompatibilityRef(projection.ID)
		freezeCommit, exists, err := canonical.Ref(compatRef)
		if err != nil || !exists || freezeCommit.IsZero() {
			return errors.Join(err, fmt.Errorf("YUM compatibility projection %s frozen ref is missing or changed", projection.ID))
		}
		sourceRef, _ := state.YUMCompatibilitySourceRef(projection.ID)
		sourceCommit, sourceExists, err := canonical.Ref(sourceRef)
		if err != nil || !sourceExists || sourceCommit.String() != witness.SourceCommit {
			return errors.Join(err, fmt.Errorf("YUM compatibility projection %s source ref does not pin witness S1 commit", projection.ID))
		}
		if descendant, ancestryErr := canonical.IsAncestor(sourceCommit, freezeCommit); ancestryErr != nil || !descendant {
			return errors.Join(ancestryErr, fmt.Errorf("YUM compatibility projection %s S2 freeze does not descend from S1 source", projection.ID))
		}
		for _, required := range []func(string) (string, error){state.YUMCompatibilityProjectionPath, state.YUMCompatibilityManifestPath, state.YUMCompatibilityCandidateManifestPath, state.YUMCompatibilityCandidateReceiptPath, state.YUMCompatibilityPackageTrustPath, state.YUMCompatibilityRepositoryTrustPath, state.YUMCompatibilitySourcePath, state.YUMCompatibilityAdoptionPath} {
			canonicalPath, pathErr := required(projection.ID)
			if pathErr != nil {
				return pathErr
			}
			if _, present, identityErr := canonical.BlobIdentityAt(freezeCommit, canonicalPath); identityErr != nil || !present {
				return errors.Join(identityErr, fmt.Errorf("YUM compatibility projection %s S2 freeze is missing %s", projection.ID, canonicalPath))
			}
		}
	}
	return nil
}

// validateCanonicalYUMCompatibilityContracts is an ordinary command-load
// gate. Once a projection witness has existed in canonical history, its ID,
// physical root, source coordinate, pinned commit, mode and flat-alias promise
// cannot be removed or edited. The immutable ref and both current witness
// files must remain present as a complete preservation root. This reads Git
// metadata and the small witness documents only; package bodies are never
// opened and no provider client can be constructed before it succeeds.
func validateCanonicalYUMCompatibilityContracts(cfg *config.Config) error {
	if cfg == nil || cfg.Root == "" {
		return errors.New("cannot validate YUM compatibility contract without a rooted config")
	}
	canonical := state.New(cfg.StatePath())
	head, err := canonicalAssetProjectionHead(canonical)
	if err != nil {
		return fmt.Errorf("inspect YUM compatibility canonical HEAD: %w", err)
	}
	if head.IsZero() {
		if _, metadataErr := os.Lstat(filepath.Join(canonical.StateDir(), "state", ".git")); errors.Is(metadataErr, os.ErrNotExist) {
			return nil
		} else if metadataErr != nil {
			return fmt.Errorf("inspect YUM compatibility Git metadata: %w", metadataErr)
		}
	}
	refs, err := canonical.SOWRefs()
	if err != nil {
		return fmt.Errorf("enumerate YUM compatibility preservation refs: %w", err)
	}
	if head.IsZero() && len(refs) == 0 {
		return nil
	}
	return validateCanonicalYUMCompatibilityStateHistory(cfg, canonical, head, refs)
}

// reachableYUMCompatibilityHistory is the union of every commit reachable from
// aggregate HEAD and every direct refs/sow/* preservation root. Imported or
// repaired state can retain an off-HEAD ownership branch through a view,
// snapshot, remote, or compatibility ref; omitting those commits would allow a
// later merge/reuse to erase an already frozen URL owner from the audit.
func reachableYUMCompatibilityHistory(gitHistory *historicalAssetProjectionGit, head plumbing.Hash, refs []state.RefRecord) ([]plumbing.Hash, error) {
	if gitHistory == nil || gitHistory.repository == nil {
		return nil, errors.New("YUM compatibility Git metadata reader is unavailable")
	}
	roots := make([]plumbing.Hash, 0, len(refs)+1)
	if !head.IsZero() {
		roots = append(roots, head)
	}
	for _, ref := range refs {
		if !ref.Hash.IsZero() {
			roots = append(roots, ref.Hash)
		}
	}
	seen := make(map[plumbing.Hash]struct{})
	for _, root := range roots {
		iterator, err := gitHistory.repository.Log(&git.LogOptions{From: root, Order: git.LogOrderDFS})
		if err != nil {
			return nil, fmt.Errorf("walk reachable root %s: %w", root, err)
		}
		for {
			commit, nextErr := iterator.Next()
			if errors.Is(nextErr, io.EOF) {
				break
			}
			if nextErr != nil {
				iterator.Close()
				return nil, fmt.Errorf("walk reachable root %s: %w", root, nextErr)
			}
			seen[commit.Hash] = struct{}{}
		}
		iterator.Close()
	}
	result := make([]plumbing.Hash, 0, len(seen))
	for commit := range seen {
		result = append(result, commit)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result, nil
}

type yumCompatibilityAncestryKey struct {
	ancestor   plumbing.Hash
	descendant plumbing.Hash
}

type yumCompatibilityAncestry struct {
	canonical *state.Store
	cache     map[yumCompatibilityAncestryKey]bool
}

func (a *yumCompatibilityAncestry) isAncestor(ancestor, descendant plumbing.Hash) (bool, error) {
	if ancestor == descendant {
		return true, nil
	}
	key := yumCompatibilityAncestryKey{ancestor: ancestor, descendant: descendant}
	if value, exists := a.cache[key]; exists {
		return value, nil
	}
	value, err := a.canonical.IsAncestor(ancestor, descendant)
	if err == nil {
		a.cache[key] = value
	}
	return value, err
}

func canonicalConfigAtForYUMCompatibility(canonical *state.Store, gitHistory *historicalAssetProjectionGit, commit plumbing.Hash, cache map[plumbing.Hash]*config.Config) (*config.Config, error) {
	identity, exists, err := gitHistory.blobIdentityAt(commit, "config/sow.yaml")
	if err != nil || !exists {
		return nil, errors.Join(err, fmt.Errorf("canonical config is missing at YUM compatibility descendant %s", commit))
	}
	if cached := cache[identity.Hash]; cached != nil {
		return cached, nil
	}
	body, exists, err := readCanonicalBytesAt(canonical, commit, "config/sow.yaml", 16<<20)
	if err != nil || !exists {
		return nil, errors.Join(err, fmt.Errorf("read canonical config at YUM compatibility descendant %s", commit))
	}
	committed, err := config.Decode(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("decode canonical config at YUM compatibility descendant %s: %w", commit, err)
	}
	cache[identity.Hash] = committed
	return committed, nil
}

func decodeYUMCompatibilityWitness(body []byte) (yumCompatibilityWitness, error) {
	var witness yumCompatibilityWitness
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&witness); err != nil {
		return witness, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return witness, errors.New("YUM compatibility witness has trailing JSON")
		}
		return witness, err
	}
	if witness.Schema != yumCompatibilityWitnessSchema || witness.ID == "" || witness.Root == "" || witness.Mode != config.YUMCompatibilityModeFrozenCrossEL || witness.Carrier == "" ||
		witness.SourceRepo == "" || witness.SourceView != "latest" || witness.SourceOS == "" || witness.SourceArch == "" || witness.SourceRoot == "" || witness.SourceRef == "" ||
		witness.SourceCommit == "" || witness.SourceManifestLen < 0 || witness.AdoptionLen < 1 || witness.PayloadManifestLen < 0 || witness.PackageTrustLen < 1 || witness.Packages < 0 || witness.Bytes < 0 || !witness.FlatAliases {
		return witness, errors.New("YUM compatibility witness is incomplete or has unsupported schema/policy")
	}
	digest, err := hex.DecodeString(witness.PayloadManifestSHA)
	if err != nil || len(digest) != 32 || strings.ToLower(witness.PayloadManifestSHA) != witness.PayloadManifestSHA {
		return witness, errors.New("YUM compatibility witness has invalid payload manifest SHA-256")
	}
	if !plumbing.IsHash(witness.PayloadManifestGit) || strings.ToLower(witness.PayloadManifestGit) != witness.PayloadManifestGit {
		return witness, errors.New("YUM compatibility witness has invalid payload manifest Git blob identity")
	}
	sourceDigest, err := hex.DecodeString(witness.SourceManifestSHA)
	if err != nil || len(sourceDigest) != 32 || strings.ToLower(witness.SourceManifestSHA) != witness.SourceManifestSHA {
		return witness, errors.New("YUM compatibility witness has invalid source manifest SHA-256")
	}
	if !plumbing.IsHash(witness.SourceManifestGit) || strings.ToLower(witness.SourceManifestGit) != witness.SourceManifestGit {
		return witness, errors.New("YUM compatibility witness has invalid source manifest Git blob identity")
	}
	adoptionDigest, err := hex.DecodeString(witness.AdoptionSHA)
	if err != nil || len(adoptionDigest) != 32 || strings.ToLower(witness.AdoptionSHA) != witness.AdoptionSHA {
		return witness, errors.New("YUM compatibility witness has invalid adoption SHA-256")
	}
	if !plumbing.IsHash(witness.AdoptionGit) || strings.ToLower(witness.AdoptionGit) != witness.AdoptionGit {
		return witness, errors.New("YUM compatibility witness has invalid adoption Git blob identity")
	}
	trustDigest, err := hex.DecodeString(witness.PackageTrustSHA)
	if err != nil || len(trustDigest) != 32 || strings.ToLower(witness.PackageTrustSHA) != witness.PackageTrustSHA {
		return witness, errors.New("YUM compatibility witness has invalid package trust SHA-256")
	}
	if !plumbing.IsHash(witness.PackageTrustGit) || strings.ToLower(witness.PackageTrustGit) != witness.PackageTrustGit {
		return witness, errors.New("YUM compatibility witness has invalid package trust Git blob identity")
	}
	return witness, nil
}

func sameYUMCompatibilityWitnessContract(left, right yumCompatibilityWitness) bool {
	return left.Schema == right.Schema && left.ID == right.ID && left.Root == right.Root && left.Mode == right.Mode && left.Carrier == right.Carrier &&
		left.SourceRepo == right.SourceRepo && left.SourceView == right.SourceView && left.SourceOS == right.SourceOS &&
		left.SourceArch == right.SourceArch && left.SourceRoot == right.SourceRoot && left.SourceRef == right.SourceRef && left.SourceCommit == right.SourceCommit &&
		left.SourceManifestSHA == right.SourceManifestSHA && left.SourceManifestGit == right.SourceManifestGit && left.SourceManifestLen == right.SourceManifestLen &&
		left.AdoptionSHA == right.AdoptionSHA && left.AdoptionGit == right.AdoptionGit && left.AdoptionLen == right.AdoptionLen &&
		left.PayloadManifestSHA == right.PayloadManifestSHA && left.PayloadManifestGit == right.PayloadManifestGit &&
		left.PayloadManifestLen == right.PayloadManifestLen && left.PackageTrustSHA == right.PackageTrustSHA &&
		left.PackageTrustGit == right.PackageTrustGit && left.PackageTrustLen == right.PackageTrustLen && left.Packages == right.Packages && left.Bytes == right.Bytes &&
		left.FlatAliases == right.FlatAliases
}

func requireYUMCompatibilityWitnessMatchesProjection(witness yumCompatibilityWitness, projection config.YUMCompatibilityProjection) error {
	ref, err := state.YUMCompatibilitySourceRef(projection.ID)
	if err != nil {
		return err
	}
	// The exact physical source root is part of the frozen provenance contract;
	// a later path-template edit cannot redirect an old witness.
	sourceRoot, err := state.YUMCompatibilitySourcePath(projection.ID)
	if err != nil || witness.SourceRoot != sourceRoot || path.Clean(witness.SourceRoot) != witness.SourceRoot {
		return errors.New("frozen witness source root is invalid")
	}
	if witness.ID != projection.ID || witness.Root != projection.Root || witness.Mode != projection.Mode || witness.Carrier != projection.Carrier ||
		witness.SourceRepo != projection.Source.Repo || witness.SourceView != projection.Source.View ||
		witness.SourceOS != projection.Source.OS || witness.SourceArch != projection.Source.Arch ||
		(projection.Source.Commit != config.YUMCompatibilityPinAtFirstFreeze && witness.SourceCommit != projection.Source.Commit) || witness.SourceRef != ref.String() {
		return errors.New("id/root/mode/source/ref/commit differs from the frozen witness")
	}
	if !plumbing.IsHash(witness.SourceCommit) || witness.SourceCommit == strings.Repeat("0", 40) {
		return errors.New("frozen witness source commit is invalid")
	}
	return nil
}

func expectedYUMCompatibilityChannelKey(viewName string, projection config.YUMCompatibilityProjection) string {
	return path.Join(".sow/channels", viewName, projection.ID, "cross-el", projection.Source.Arch+".json")
}
