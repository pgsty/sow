package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-billy/v5/osfs"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
)

type yumCompatibilityHistoryStateV2 struct {
	id        string
	stage     yumCompatibilityStage
	adoption  yumCompatibilityAdoption
	witness   yumCompatibilityWitness
	candidate yumCompatibilityCandidate
	events    []yumCompatibilityCutoverEvent

	sourceBlob            state.BlobIdentity
	adoptionBlob          state.BlobIdentity
	packageTrustBlob      state.BlobIdentity
	witnessBlob           state.BlobIdentity
	payloadBlob           state.BlobIdentity
	candidateReceiptBlob  state.BlobIdentity
	candidateManifestBlob state.BlobIdentity
	repositoryTrustBlob   state.BlobIdentity
	cutoverBlob           state.BlobIdentity

	// Content digests are streamed once per Git blob through the shared
	// hashCache.  Keeping them in the scanned state lets initial S1/S2 anchors
	// receive the same content-bound admission as current-state replay without
	// reopening (and potentially inflating) large manifests.
	sourceSHA            string
	adoptionSHA          string
	packageTrustSHA      string
	payloadSHA           string
	candidateManifestSHA string
	repositoryTrustSHA   string
}

type yumCompatibilityHistoryAnchorV2 struct {
	commit plumbing.Hash
	state  yumCompatibilityHistoryStateV2
}

func validateCanonicalYUMCompatibilityStateHistory(cfg *config.Config, canonical *state.Store, head plumbing.Hash, refs []state.RefRecord) (resultErr error) {
	gitHistory, err := openHistoricalAssetProjectionGit(canonical)
	if err != nil {
		return fmt.Errorf("open YUM compatibility Git metadata reader: %w", err)
	}
	history, err := reachableYUMCompatibilityHistory(gitHistory, head, refs)
	if err != nil {
		return fmt.Errorf("inspect YUM compatibility reachable history: %w", err)
	}
	commits := append([]plumbing.Hash(nil), history...)
	sort.Slice(commits, func(i, j int) bool { return commits[i].String() < commits[j].String() })
	statesAtCommit := make(map[string]map[string]yumCompatibilityHistoryStateV2, len(commits))
	streamingGit, closeStreaming, err := openStreamingYUMCompatibilityGit(canonical)
	if err != nil {
		return fmt.Errorf("open streaming YUM compatibility Git reader: %w", err)
	}
	defer func() {
		if closeErr := closeStreaming(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	hashCache := make(map[plumbing.Hash]string)
	for _, commit := range commits {
		states, scanErr := historicalYUMCompatibilityStatesAtV2(canonical, gitHistory, streamingGit, commit, hashCache)
		if scanErr != nil {
			return scanErr
		}
		statesAtCommit[commit.String()] = states
	}
	if err := validateYUMCompatibilityHistoryEdgesV2(gitHistory, commits, statesAtCommit); err != nil {
		return err
	}
	ancestry := &yumCompatibilityAncestry{canonical: canonical, cache: make(map[yumCompatibilityAncestryKey]bool)}
	adoptionAnchors, err := minimalYUMCompatibilityAnchorsV2(commits, statesAtCommit, ancestry, false)
	if err != nil {
		return err
	}
	freezeAnchors, err := minimalYUMCompatibilityAnchorsV2(commits, statesAtCommit, ancestry, true)
	if err != nil {
		return err
	}
	adoptionByID, err := uniqueYUMCompatibilityAnchorsV2(adoptionAnchors, false)
	if err != nil {
		return err
	}
	freezeByID, err := uniqueYUMCompatibilityAnchorsV2(freezeAnchors, true)
	if err != nil {
		return err
	}

	currentByID := make(map[string]config.YUMCompatibilityProjection, len(cfg.CompatibilityProjections))
	for _, projection := range cfg.CompatibilityProjections {
		currentByID[projection.ID] = projection
	}
	sourceRefs, freezeRefs, repoRefs, err := splitYUMCompatibilityRefsV2(refs)
	if err != nil {
		return err
	}
	configCache := make(map[plumbing.Hash]*config.Config)
	for id, anchor := range adoptionByID {
		for _, commit := range commits {
			descendant, ancestryErr := ancestry.isAncestor(anchor.commit, commit)
			if ancestryErr != nil {
				return ancestryErr
			}
			if !descendant {
				continue
			}
			current, exists := statesAtCommit[commit.String()][id]
			if !exists {
				return fmt.Errorf("YUM compatibility adoption %s established at %s was removed at descendant %s", id, anchor.commit, commit)
			}
			if current.sourceBlob != anchor.state.sourceBlob || current.adoptionBlob != anchor.state.adoptionBlob || current.packageTrustBlob != anchor.state.packageTrustBlob ||
				!sameYUMCompatibilityAdoptionContractV2(current.adoption, anchor.state.adoption) {
				return fmt.Errorf("YUM compatibility adoption %s source/adoption/package-trust changed between %s and descendant %s", id, anchor.commit, commit)
			}
			committed, configErr := canonicalConfigAtForYUMCompatibility(canonical, gitHistory, commit, configCache)
			if configErr != nil {
				return configErr
			}
			projection, exists, projectionErr := config.YUMCompatibilityProjectionByID(committed.CompatibilityProjections, id)
			if projectionErr != nil || !exists {
				return errors.Join(projectionErr, fmt.Errorf("YUM compatibility adoption %s is absent from descendant config %s", id, commit))
			}
			if contractErr := requireYUMCompatibilityAdoptionProjectionV2(anchor.state.adoption, projection, committed); contractErr != nil {
				return fmt.Errorf("YUM compatibility adoption %s config changed at descendant %s: %w", id, commit, contractErr)
			}
		}
		projection, exists := currentByID[id]
		if !exists {
			return fmt.Errorf("YUM compatibility projection %s cannot be removed after S1 adoption", id)
		}
		if err := requireYUMCompatibilityAdoptionProjectionV2(anchor.state.adoption, projection, cfg); err != nil {
			return fmt.Errorf("YUM compatibility projection %s immutable S1 contract changed: %w", id, err)
		}
		if configured := projection.Source.Commit; configured != config.YUMCompatibilityPinAtFirstFreeze && configured != anchor.commit.String() {
			return fmt.Errorf("YUM compatibility projection %s configured source commit differs from S1 anchor %s", id, anchor.commit)
		}
		if sourceRefs[id] != anchor.commit {
			return fmt.Errorf("YUM compatibility source ref %s is missing, recreated, or does not pin S1 commit %s", id, anchor.commit)
		}
		if carrierRef, refErr := state.RepoRef(anchor.state.adoption.Carrier); refErr != nil || repoRefs[carrierRef.String()].String() != anchor.state.adoption.BaselineCommit {
			return errors.Join(refErr, fmt.Errorf("YUM compatibility carrier %s S0 ref moved from adopted baseline %s", anchor.state.adoption.Carrier, anchor.state.adoption.BaselineCommit))
		}
	}

	for id, anchor := range freezeByID {
		// historicalYUMCompatibilityStatesAtV2 has already streamed every
		// content-bearing blob and checked the confirmation plus both trust
		// identities.  Require those results to be present before this minimal
		// anchor can become the permanent owner.
		if anchor.state.sourceSHA == "" || anchor.state.adoptionSHA == "" || anchor.state.packageTrustSHA == "" ||
			anchor.state.payloadSHA == "" || anchor.state.candidateManifestSHA == "" || anchor.state.repositoryTrustSHA == "" {
			return fmt.Errorf("YUM compatibility freeze %s at %s lacks full content-bound admission", id, anchor.commit)
		}
		adoptionAnchor, exists := adoptionByID[id]
		if !exists {
			return fmt.Errorf("YUM compatibility freeze %s has no S1 adoption anchor", id)
		}
		if descendant, ancestryErr := ancestry.isAncestor(adoptionAnchor.commit, anchor.commit); ancestryErr != nil || !descendant {
			return errors.Join(ancestryErr, fmt.Errorf("YUM compatibility freeze %s at %s does not descend from S1 %s", id, anchor.commit, adoptionAnchor.commit))
		}
		for _, commit := range commits {
			descendant, ancestryErr := ancestry.isAncestor(anchor.commit, commit)
			if ancestryErr != nil {
				return ancestryErr
			}
			if !descendant {
				continue
			}
			current, exists := statesAtCommit[commit.String()][id]
			if !exists || current.stage == yumCompatibilityStageS1 {
				return fmt.Errorf("YUM compatibility freeze %s established at %s regressed at descendant %s", id, anchor.commit, commit)
			}
			if !sameYUMCompatibilityFrozenStateV2(anchor.state, current) {
				return fmt.Errorf("YUM compatibility freeze %s witness/candidate/trust identity changed between %s and descendant %s", id, anchor.commit, commit)
			}
			if err := requireYUMCompatibilityLedgerPrefix(anchor.state.events, current.events); err != nil {
				return fmt.Errorf("YUM compatibility freeze %s cutover history changed at %s: %w", id, commit, err)
			}
			for _, event := range current.events {
				if event.ID != id || event.FreezeCommit != anchor.commit.String() || event.CandidateManifestSHA256 != anchor.state.candidate.CandidateManifestSHA256 {
					return fmt.Errorf("YUM compatibility cutover event %s does not bind S2 freeze %s", id, anchor.commit)
				}
			}
		}
		if freezeRefs[id] != anchor.commit {
			return fmt.Errorf("YUM compatibility freeze ref %s is missing, recreated, or does not pin S2 commit %s", id, anchor.commit)
		}
	}

	if head.IsZero() {
		if len(adoptionByID) != 0 || len(sourceRefs) != 0 || len(freezeRefs) != 0 {
			return errors.New("YUM compatibility continuity requires canonical HEAD")
		}
		return nil
	}
	headStates := statesAtCommit[head.String()]
	for id := range adoptionByID {
		if _, exists := headStates[id]; !exists {
			return fmt.Errorf("YUM compatibility adoption %s is absent from canonical HEAD", id)
		}
	}
	for id := range sourceRefs {
		if _, exists := adoptionByID[id]; !exists {
			return fmt.Errorf("YUM compatibility source ref %s has no canonical S1 adoption", id)
		}
	}
	for id := range freezeRefs {
		if _, exists := freezeByID[id]; !exists {
			return fmt.Errorf("YUM compatibility freeze ref %s has no canonical S2 witness", id)
		}
	}
	for id, stateAtHead := range headStates {
		if stateAtHead.stage != yumCompatibilityStageS1 {
			if _, exists := freezeByID[id]; !exists {
				return fmt.Errorf("YUM compatibility S2 state %s has no immutable freeze anchor", id)
			}
		}
	}
	return nil
}

// validateYUMCompatibilityHistoryEdgesV2 makes the S3 ledger append-only on
// every reachable Git edge. Comparing descendants only with the ledger-empty
// S2 freeze anchor would miss a later truncation or rewrite; checking direct
// parents also rejects divergent merge histories unless the merge result
// preserves both parent prefixes exactly.
func validateYUMCompatibilityHistoryEdgesV2(gitHistory *historicalAssetProjectionGit, commits []plumbing.Hash, states map[string]map[string]yumCompatibilityHistoryStateV2) error {
	for _, commit := range commits {
		object, err := gitHistory.repository.CommitObject(commit)
		if err != nil {
			return err
		}
		currentStates := states[commit.String()]
		for _, parent := range object.ParentHashes {
			parentStates, reachable := states[parent.String()]
			if !reachable {
				return fmt.Errorf("reachable YUM compatibility commit %s has unscanned parent %s", commit, parent)
			}
			for id, prior := range parentStates {
				if prior.stage == yumCompatibilityStageS1 {
					continue
				}
				current, exists := currentStates[id]
				if !exists || current.stage == yumCompatibilityStageS1 {
					return fmt.Errorf("YUM compatibility freeze %s regressed at descendant %s on Git edge %s -> %s", id, commit, parent, commit)
				}
				if err := requireYUMCompatibilityLedgerPrefix(prior.events, current.events); err != nil {
					return fmt.Errorf("YUM compatibility cutover ledger %s changed on Git edge %s -> %s: %w", id, parent, commit, err)
				}
			}
		}
	}
	return nil
}

func historicalYUMCompatibilityStatesAtV2(canonical *state.Store, gitHistory *historicalAssetProjectionGit, streamingGit *git.Repository, commit plumbing.Hash, hashCache map[plumbing.Hash]string) (map[string]yumCompatibilityHistoryStateV2, error) {
	files := make(map[string]map[string]state.BlobIdentity)
	err := gitHistory.forEachFileAt(commit, "compatibility/yum/", func(name string, identity state.BlobIdentity) error {
		parts := strings.Split(name, "/")
		if len(parts) != 4 || parts[0] != "compatibility" || parts[1] != "yum" || parts[2] == "" {
			return fmt.Errorf("invalid canonical YUM compatibility path %q at %s", name, commit)
		}
		switch parts[3] {
		case "source.tsv", "adoption.json", "package-trust.pgp", "projection.json", "manifest.tsv", "candidate.tsv", "candidate.json", "repository-trust.pgp", "cutover.jsonl":
		default:
			return fmt.Errorf("unexpected canonical YUM compatibility file %q at %s", name, commit)
		}
		if files[parts[2]] == nil {
			files[parts[2]] = make(map[string]state.BlobIdentity)
		}
		files[parts[2]][parts[3]] = identity
		return nil
	})
	if err != nil {
		return nil, err
	}
	result := make(map[string]yumCompatibilityHistoryStateV2, len(files))
	for id, present := range files {
		stateAtCommit := yumCompatibilityHistoryStateV2{id: id, stage: yumCompatibilityStageS1,
			sourceBlob: present["source.tsv"], adoptionBlob: present["adoption.json"], packageTrustBlob: present["package-trust.pgp"],
			witnessBlob: present["projection.json"], payloadBlob: present["manifest.tsv"], candidateReceiptBlob: present["candidate.json"],
			candidateManifestBlob: present["candidate.tsv"], repositoryTrustBlob: present["repository-trust.pgp"], cutoverBlob: present["cutover.jsonl"]}
		if stateAtCommit.sourceBlob.Hash.IsZero() || stateAtCommit.adoptionBlob.Hash.IsZero() || stateAtCommit.packageTrustBlob.Hash.IsZero() {
			return nil, fmt.Errorf("YUM compatibility adoption %s is incomplete at %s", id, commit)
		}
		adoptionPath, _ := state.YUMCompatibilityAdoptionPath(id)
		adoptionBody, exists, readErr := readCanonicalBytesAt(canonical, commit, adoptionPath, maximumYUMCompatibilityWitnessBytes)
		if readErr != nil || !exists {
			return nil, errors.Join(readErr, fmt.Errorf("read YUM compatibility adoption %s at %s", id, commit))
		}
		stateAtCommit.adoption, err = decodeYUMCompatibilityAdoption(adoptionBody)
		if err != nil || stateAtCommit.adoption.ID != id || stateAtCommit.sourceBlob.Hash.String() != stateAtCommit.adoption.SourceManifestGit || stateAtCommit.sourceBlob.Size != stateAtCommit.adoption.SourceManifestSize ||
			stateAtCommit.packageTrustBlob.Hash.String() != stateAtCommit.adoption.PackageTrustGit || stateAtCommit.packageTrustBlob.Size != stateAtCommit.adoption.PackageTrustSize {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility adoption %s receipt/tree identity differs at %s", id, commit))
		}
		stateAtCommit.sourceSHA, err = hashYUMCompatibilityHistoryBlob(streamingGit, stateAtCommit.sourceBlob, hashCache)
		if err != nil || stateAtCommit.sourceSHA != stateAtCommit.adoption.SourceManifestSHA256 {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility adoption %s source content identity differs at %s", id, commit))
		}
		stateAtCommit.adoptionSHA, err = hashYUMCompatibilityHistoryBlob(streamingGit, stateAtCommit.adoptionBlob, hashCache)
		if err != nil {
			return nil, fmt.Errorf("hash YUM compatibility adoption %s at %s: %w", id, commit, err)
		}
		stateAtCommit.packageTrustSHA, err = hashYUMCompatibilityHistoryBlob(streamingGit, stateAtCommit.packageTrustBlob, hashCache)
		if err != nil || stateAtCommit.packageTrustSHA != stateAtCommit.adoption.PackageTrustSHA256 {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility adoption %s package trust content identity differs at %s", id, commit))
		}
		if stateAtCommit.witnessBlob.Hash.IsZero() {
			if !stateAtCommit.payloadBlob.Hash.IsZero() || !stateAtCommit.candidateReceiptBlob.Hash.IsZero() || !stateAtCommit.candidateManifestBlob.Hash.IsZero() || !stateAtCommit.repositoryTrustBlob.Hash.IsZero() || !stateAtCommit.cutoverBlob.Hash.IsZero() {
				return nil, fmt.Errorf("YUM compatibility adoption %s has S2/S3 files without a witness at %s", id, commit)
			}
			result[id] = stateAtCommit
			continue
		}
		if stateAtCommit.payloadBlob.Hash.IsZero() || stateAtCommit.candidateReceiptBlob.Hash.IsZero() || stateAtCommit.candidateManifestBlob.Hash.IsZero() || stateAtCommit.repositoryTrustBlob.Hash.IsZero() {
			return nil, fmt.Errorf("YUM compatibility freeze %s is incomplete at %s", id, commit)
		}
		witnessPath, _ := state.YUMCompatibilityProjectionPath(id)
		witnessBody, exists, readErr := readCanonicalBytesAt(canonical, commit, witnessPath, maximumYUMCompatibilityWitnessBytes)
		if readErr != nil || !exists {
			return nil, errors.Join(readErr, fmt.Errorf("read YUM compatibility witness %s at %s", id, commit))
		}
		stateAtCommit.witness, err = decodeYUMCompatibilityWitness(witnessBody)
		if err != nil || stateAtCommit.witness.ID != id || stateAtCommit.payloadBlob.Hash.String() != stateAtCommit.witness.PayloadManifestGit || stateAtCommit.payloadBlob.Size != stateAtCommit.witness.PayloadManifestLen ||
			stateAtCommit.sourceBlob.Hash.String() != stateAtCommit.witness.SourceManifestGit || stateAtCommit.sourceBlob.Size != stateAtCommit.witness.SourceManifestLen ||
			stateAtCommit.adoptionBlob.Hash.String() != stateAtCommit.witness.AdoptionGit || stateAtCommit.adoptionBlob.Size != stateAtCommit.witness.AdoptionLen ||
			stateAtCommit.packageTrustBlob.Hash.String() != stateAtCommit.witness.PackageTrustGit || stateAtCommit.packageTrustBlob.Size != stateAtCommit.witness.PackageTrustLen {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility witness %s tree identity differs at %s", id, commit))
		}
		stateAtCommit.payloadSHA, err = hashYUMCompatibilityHistoryBlob(streamingGit, stateAtCommit.payloadBlob, hashCache)
		if err != nil || stateAtCommit.payloadSHA != stateAtCommit.witness.PayloadManifestSHA ||
			stateAtCommit.sourceSHA != stateAtCommit.witness.SourceManifestSHA || stateAtCommit.adoptionSHA != stateAtCommit.witness.AdoptionSHA ||
			stateAtCommit.packageTrustSHA != stateAtCommit.witness.PackageTrustSHA {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility witness %s content identity differs at %s", id, commit))
		}
		candidatePath, _ := state.YUMCompatibilityCandidateReceiptPath(id)
		candidateBody, exists, readErr := readCanonicalBytesAt(canonical, commit, candidatePath, maximumYUMCompatibilityWitnessBytes)
		if readErr != nil || !exists {
			return nil, errors.Join(readErr, fmt.Errorf("read YUM compatibility candidate receipt %s at %s", id, commit))
		}
		stateAtCommit.candidate, err = decodeYUMCompatibilityCandidate(candidateBody)
		if err != nil || stateAtCommit.candidate.ID != id || stateAtCommit.candidateManifestBlob.Hash.String() != stateAtCommit.candidate.CandidateManifestGit || stateAtCommit.candidateManifestBlob.Size != stateAtCommit.candidate.CandidateManifestSize ||
			stateAtCommit.candidate.Root != stateAtCommit.witness.Root || stateAtCommit.candidate.Carrier != stateAtCommit.witness.Carrier || stateAtCommit.candidate.OwnerRepo != stateAtCommit.witness.SourceRepo ||
			stateAtCommit.candidate.SourceRef != stateAtCommit.witness.SourceRef || stateAtCommit.candidate.SourceCommit != stateAtCommit.witness.SourceCommit ||
			stateAtCommit.candidate.SourceManifestSHA256 != stateAtCommit.sourceSHA || stateAtCommit.candidate.SourceManifestGit != stateAtCommit.witness.SourceManifestGit || stateAtCommit.candidate.SourceManifestSize != stateAtCommit.witness.SourceManifestLen ||
			stateAtCommit.candidate.AdoptionSHA256 != stateAtCommit.adoptionSHA || stateAtCommit.candidate.AdoptionGit != stateAtCommit.witness.AdoptionGit || stateAtCommit.candidate.AdoptionSize != stateAtCommit.witness.AdoptionLen ||
			stateAtCommit.candidate.PackageTrustSHA256 != stateAtCommit.packageTrustSHA || stateAtCommit.candidate.PackageTrustGit != stateAtCommit.witness.PackageTrustGit || stateAtCommit.candidate.PackageTrustSize != stateAtCommit.witness.PackageTrustLen ||
			stateAtCommit.candidate.Packages != stateAtCommit.witness.Packages || stateAtCommit.candidate.Bytes != stateAtCommit.witness.Bytes {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility candidate %s fails full content-bound admission at %s: identity differs", id, commit))
		}
		confirmation, confirmationErr := yumCompatibilityConfirmation("freeze", stateAtCommit.candidate)
		if confirmationErr != nil || confirmation != stateAtCommit.candidate.FreezeConfirm {
			return nil, errors.Join(confirmationErr, fmt.Errorf("YUM compatibility candidate %s fails full content-bound admission at %s: invalid freeze confirmation", id, commit))
		}
		stateAtCommit.candidateManifestSHA, err = hashYUMCompatibilityHistoryBlob(streamingGit, stateAtCommit.candidateManifestBlob, hashCache)
		if err != nil || stateAtCommit.candidateManifestSHA != stateAtCommit.candidate.CandidateManifestSHA256 {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility candidate manifest %s SHA-256 differs at %s", id, commit))
		}
		repositoryTrustPath, _ := state.YUMCompatibilityRepositoryTrustPath(id)
		repositoryTrust, exists, readErr := readCanonicalBytesAt(canonical, commit, repositoryTrustPath, maxSecretBytes)
		stateAtCommit.repositoryTrustSHA = digestBytesCLI(repositoryTrust)
		if readErr != nil || !exists || stateAtCommit.repositoryTrustBlob.Hash.String() != stateAtCommit.candidate.RepositoryTrustGit ||
			stateAtCommit.repositoryTrustBlob.Size != stateAtCommit.candidate.RepositoryTrustSize || int64(len(repositoryTrust)) != stateAtCommit.candidate.RepositoryTrustSize ||
			stateAtCommit.repositoryTrustSHA != stateAtCommit.candidate.RepositoryTrustSHA256 || repositoryTrustAnchorDigest(repositoryTrust) != stateAtCommit.candidate.RepositoryKeySHA256 {
			return nil, errors.Join(readErr, fmt.Errorf("YUM compatibility repository trust %s fails full content-bound admission at %s", id, commit))
		}
		stateAtCommit.stage = yumCompatibilityStageS2
		if !stateAtCommit.cutoverBlob.Hash.IsZero() {
			cutoverPath, _ := state.YUMCompatibilityCutoverPath(id)
			cutoverBody, exists, readErr := readCanonicalBytesAt(canonical, commit, cutoverPath, maximumYUMCompatibilityLedgerBytes)
			if readErr != nil || !exists {
				return nil, errors.Join(readErr, fmt.Errorf("read YUM compatibility cutover ledger %s at %s", id, commit))
			}
			stateAtCommit.events, err = decodeYUMCompatibilityCutoverLedger(cutoverBody)
			if err != nil {
				return nil, fmt.Errorf("decode YUM compatibility cutover ledger %s at %s: %w", id, commit, err)
			}
			if stateAtCommit.events[0].FromTarget != stateAtCommit.candidate.Root {
				return nil, fmt.Errorf("YUM compatibility first cutover raw target %q differs from frozen root %q at %s", stateAtCommit.events[0].FromTarget, stateAtCommit.candidate.Root, commit)
			}
			stateAtCommit.stage = yumCompatibilityLedgerStage(stateAtCommit.events)
		}
		result[id] = stateAtCommit
	}
	return result, nil
}

func openStreamingYUMCompatibilityGit(canonical *state.Store) (*git.Repository, func() error, error) {
	if canonical == nil || canonical.StateDir() == "" {
		return nil, nil, errors.New("canonical YUM compatibility state is unavailable")
	}
	if canonical.HasBoundRepository() {
		repository, err := canonical.OpenRepository()
		if err != nil {
			return nil, nil, err
		}
		return repository, func() error { return nil }, nil
	}
	dotGit := osfs.New(filepath.Join(canonical.StateDir(), "state", git.GitDirName))
	storage := filesystem.NewStorageWithOptions(dotGit, cache.NewObjectLRUDefault(), filesystem.Options{LargeObjectThreshold: 1 << 20})
	repository, err := git.Open(storage, nil)
	if err != nil {
		_ = storage.Close()
		return nil, nil, err
	}
	return repository, storage.Close, nil
}

func hashYUMCompatibilityHistoryBlob(repository *git.Repository, identity state.BlobIdentity, cache map[plumbing.Hash]string) (string, error) {
	if value := cache[identity.Hash]; value != "" {
		return value, nil
	}
	if repository == nil || identity.Hash.IsZero() || identity.Size < 0 {
		return "", errors.New("YUM compatibility history blob identity is unavailable")
	}
	encoded, err := repository.Storer.EncodedObject(plumbing.BlobObject, identity.Hash)
	if err != nil {
		return "", err
	}
	if encoded.Size() != identity.Size {
		return "", errors.New("YUM compatibility history blob size changed")
	}
	reader, err := encoded.Reader()
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, reader)
	closeErr := reader.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	value := hex.EncodeToString(hasher.Sum(nil))
	cache[identity.Hash] = value
	return value, nil
}

func minimalYUMCompatibilityAnchorsV2(commits []plumbing.Hash, states map[string]map[string]yumCompatibilityHistoryStateV2, ancestry *yumCompatibilityAncestry, frozen bool) ([]yumCompatibilityHistoryAnchorV2, error) {
	var anchors []yumCompatibilityHistoryAnchorV2
	for _, commit := range commits {
		for id, stateAtCommit := range states[commit.String()] {
			if frozen && stateAtCommit.stage == yumCompatibilityStageS1 {
				continue
			}
			candidate := yumCompatibilityHistoryAnchorV2{commit: commit, state: stateAtCommit}
			redundant := false
			for index := 0; index < len(anchors); {
				existing := anchors[index]
				if existing.state.id != id {
					index++
					continue
				}
				if ancestor, err := ancestry.isAncestor(existing.commit, candidate.commit); err != nil {
					return nil, err
				} else if ancestor {
					redundant = true
					break
				}
				if ancestor, err := ancestry.isAncestor(candidate.commit, existing.commit); err != nil {
					return nil, err
				} else if ancestor {
					anchors = append(anchors[:index], anchors[index+1:]...)
					continue
				}
				index++
			}
			if !redundant {
				anchors = append(anchors, candidate)
			}
		}
	}
	return anchors, nil
}

func uniqueYUMCompatibilityAnchorsV2(anchors []yumCompatibilityHistoryAnchorV2, frozen bool) (map[string]yumCompatibilityHistoryAnchorV2, error) {
	result := make(map[string]yumCompatibilityHistoryAnchorV2)
	for _, anchor := range anchors {
		if prior, exists := result[anchor.state.id]; exists {
			phase := "adoption"
			if frozen {
				phase = "freeze"
			}
			return nil, fmt.Errorf("YUM compatibility %s %s has conflicting disconnected ownership anchors %s and %s", phase, anchor.state.id, prior.commit, anchor.commit)
		}
		result[anchor.state.id] = anchor
	}
	return result, nil
}

func splitYUMCompatibilityRefsV2(refs []state.RefRecord) (map[string]plumbing.Hash, map[string]plumbing.Hash, map[string]plumbing.Hash, error) {
	sources, freezes, repos := make(map[string]plumbing.Hash), make(map[string]plumbing.Hash), make(map[string]plumbing.Hash)
	for _, ref := range refs {
		name := ref.Name.String()
		var target map[string]plumbing.Hash
		var id string
		switch {
		case strings.HasPrefix(name, "refs/sow/compatibility/yum-source/"):
			target, id = sources, strings.TrimPrefix(name, "refs/sow/compatibility/yum-source/")
		case strings.HasPrefix(name, "refs/sow/compatibility/yum/"):
			target, id = freezes, strings.TrimPrefix(name, "refs/sow/compatibility/yum/")
		case strings.HasPrefix(name, "refs/sow/repos/"):
			repos[name] = ref.Hash
			continue
		default:
			continue
		}
		if id == "" || strings.Contains(id, "/") {
			return nil, nil, nil, fmt.Errorf("invalid YUM compatibility ref %s", name)
		}
		target[id] = ref.Hash
	}
	return sources, freezes, repos, nil
}

func sameYUMCompatibilityAdoptionContractV2(left, right yumCompatibilityAdoption) bool {
	return left == right
}

func sameYUMCompatibilityFrozenStateV2(left, right yumCompatibilityHistoryStateV2) bool {
	return left.witnessBlob == right.witnessBlob && left.payloadBlob == right.payloadBlob && left.candidateReceiptBlob == right.candidateReceiptBlob &&
		left.candidateManifestBlob == right.candidateManifestBlob && left.repositoryTrustBlob == right.repositoryTrustBlob &&
		sameYUMCompatibilityWitnessContract(left.witness, right.witness) && left.candidate == right.candidate
}

func requireYUMCompatibilityAdoptionProjectionV2(adoption yumCompatibilityAdoption, projection config.YUMCompatibilityProjection, cfg *config.Config) error {
	if adoption.ID != projection.ID || adoption.Root != projection.Root || adoption.Carrier != projection.Carrier || adoption.OwnerRepo != projection.Source.Repo ||
		adoption.View != projection.Source.View || adoption.OS != projection.Source.OS || adoption.Arch != projection.Source.Arch {
		return errors.New("id/root/carrier/owner/source differs from immutable adoption")
	}
	carrier, exists := cfg.RepoByName(projection.Carrier)
	if !exists {
		return errors.New("adopted compatibility carrier is absent")
	}
	baselineRef, err := state.RepoRef(carrier.ID)
	if err != nil || adoption.BaselineRef != baselineRef.String() {
		return errors.Join(err, errors.New("adopted S0 baseline ref differs from carrier"))
	}
	return nil
}
