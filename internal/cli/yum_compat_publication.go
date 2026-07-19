package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

// validateGenerationCompatibility validates the compatibility vector already
// present in a committed target generation. It deliberately does not require
// every projection in the current config: a valid pre-compatibility or partial
// parent must remain a legal baseline for the 0->N and N->N+M transitions.
// Completeness belongs to the desired generation gate below.
func validateGenerationCompatibility(cfg *config.Config, canonical *state.Store, target string, generation pub.TargetGeneration) error {
	if cfg == nil || canonical == nil {
		return errors.New("compatibility publication validation dependencies are unavailable")
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return errors.Join(err, errors.New("compatibility publication validation requires canonical HEAD"))
	}
	return validateGenerationCompatibilityAt(cfg, canonical, target, generation, head, true)
}

// validateHistoricalGenerationCompatibility is the restore/read-side variant.
// Every tree object is resolved at the publication's exact canonical state
// commit; mutable refs at today's HEAD cannot reinterpret historical evidence.
func validateHistoricalGenerationCompatibility(cfg *config.Config, canonical *state.Store, target string, generation pub.TargetGeneration, commit plumbing.Hash) error {
	if cfg == nil || canonical == nil || commit.IsZero() {
		return errors.New("historical compatibility publication validation dependencies are unavailable")
	}
	return validateGenerationCompatibilityAt(cfg, canonical, target, generation, commit, false)
}

func validateGenerationCompatibilityAt(cfg *config.Config, canonical *state.Store, target string, generation pub.TargetGeneration, stateCommit plumbing.Hash, requireCurrentRefs bool) error {
	seen := make(map[string]struct{}, len(generation.Compatibility))
	channels := make(map[string]pub.ChannelState, len(generation.Channels))
	for _, channel := range generation.Channels {
		channels[channel.RemoteKey] = channel
	}
	for _, identity := range generation.Compatibility {
		if _, duplicate := seen[identity.ID]; duplicate {
			return fmt.Errorf("duplicate compatibility publication identity %s", identity.ID)
		}
		seen[identity.ID] = struct{}{}
		projection, exists, err := config.YUMCompatibilityProjectionByID(cfg.CompatibilityProjections, identity.ID)
		if err != nil || !exists {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s is absent from immutable configuration", identity.ID))
		}
		owner, exists := cfg.RepoByName(projection.Source.Repo)
		if !exists || owner.Type != "yum" || owner.YUM == nil || !owner.PublishesToTarget(target) {
			return fmt.Errorf("published compatibility identity %s has no target-affine source owner", identity.ID)
		}
		carrier, exists := cfg.RepoByName(projection.Carrier)
		if !exists || carrier.Type != "yum" || carrier.YUM == nil || !carrier.YUM.CompatibilityCarrier || carrier.IsActive() {
			return fmt.Errorf("published compatibility identity %s carrier is unavailable", identity.ID)
		}
		sourceRoot, err := state.YUMCompatibilitySourcePath(identity.ID)
		if err != nil || identity.SourceRoot != sourceRoot || identity.Carrier != projection.Carrier || identity.OwnerRepo != projection.Source.Repo {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s source/carrier/owner changed", identity.ID))
		}
		witnessPath, _ := state.YUMCompatibilityProjectionPath(identity.ID)
		witnessBody, exists, err := readCanonicalBytesAt(canonical, stateCommit, witnessPath, maximumYUMCompatibilityWitnessBytes)
		if err != nil || !exists || digestBytesCLI(witnessBody) != identity.WitnessSHA256 {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s witness is missing or changed", identity.ID))
		}
		witness, err := decodeYUMCompatibilityWitness(witnessBody)
		if err != nil || requireYUMCompatibilityWitnessMatchesProjection(witness, projection) != nil {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s witness/config contract changed", identity.ID))
		}
		if identity.Root != witness.Root || identity.SourceRef != witness.SourceRef || identity.SourceCommit != witness.SourceCommit ||
			identity.SourceRoot != witness.SourceRoot || identity.PayloadManifestSHA256 != witness.PayloadManifestSHA ||
			identity.SourceManifestSHA256 != witness.SourceManifestSHA || identity.SourceManifestGit != witness.SourceManifestGit || identity.SourceManifestSize != witness.SourceManifestLen ||
			identity.AdoptionSHA256 != witness.AdoptionSHA || identity.AdoptionGit != witness.AdoptionGit || identity.AdoptionSize != witness.AdoptionLen ||
			identity.PayloadManifestGit != witness.PayloadManifestGit || identity.PayloadManifestSize != witness.PayloadManifestLen ||
			identity.PackageTrustSHA256 != witness.PackageTrustSHA || identity.PackageTrustGit != witness.PackageTrustGit || identity.PackageTrustSize != witness.PackageTrustLen {
			return fmt.Errorf("published compatibility identity %s differs from frozen witness", identity.ID)
		}
		pinned := plumbing.NewHash(identity.SourceCommit)
		sourceRef, _ := state.YUMCompatibilitySourceRef(identity.ID)
		compatRef, _ := state.YUMCompatibilityRef(identity.ID)
		freezeCommit := plumbing.NewHash(identity.FreezeCommit)
		if identity.SourceRef != sourceRef.String() || identity.FreezeRef != compatRef.String() || pinned.IsZero() || freezeCommit.IsZero() {
			return fmt.Errorf("published compatibility identity %s source/freeze refs are not canonical", identity.ID)
		}
		sourceBeforeFreeze, err := canonical.IsAncestor(pinned, freezeCommit)
		if err != nil || !sourceBeforeFreeze {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s freeze does not descend from adopted source", identity.ID))
		}
		freezeBeforeState, err := canonical.IsAncestor(freezeCommit, stateCommit)
		if err != nil || !freezeBeforeState {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s freeze is not reachable from publication state", identity.ID))
		}
		if requireCurrentRefs {
			currentSource, sourceExists, refErr := canonical.Ref(sourceRef)
			if refErr != nil || !sourceExists || currentSource != pinned {
				return errors.Join(refErr, fmt.Errorf("published compatibility identity %s adopted source ref changed", identity.ID))
			}
			frozen, frozenExists, refErr := canonical.Ref(compatRef)
			if refErr != nil || !frozenExists || frozen != freezeCommit {
				return errors.Join(refErr, fmt.Errorf("published compatibility identity %s preservation ref changed", identity.ID))
			}
		}
		witnessBlob, exists, err := canonical.BlobIdentityAt(stateCommit, witnessPath)
		if err != nil || !exists || witnessBlob.Hash.String() != identity.WitnessGit || witnessBlob.Size != identity.WitnessSize || identity.WitnessSize != int64(len(witnessBody)) {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s witness Git identity changed", identity.ID))
		}
		frozenWitness, exists, err := canonical.BlobIdentityAt(freezeCommit, witnessPath)
		if err != nil || !exists || frozenWitness != witnessBlob {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s freeze commit does not preserve witness", identity.ID))
		}
		sourceBlob, exists, err := canonical.BlobIdentityAt(pinned, sourceRoot)
		if err != nil || !exists || sourceBlob.Hash.String() != identity.SourceManifestGit || sourceBlob.Size != identity.SourceManifestSize {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s source manifest blob changed", identity.ID))
		}
		sourceReader, err := canonical.OpenPathAt(pinned, sourceRoot)
		if err != nil {
			return err
		}
		sourceSHA, err := hashReader(sourceReader)
		if err != nil || sourceSHA != identity.SourceManifestSHA256 {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s source manifest bytes changed", identity.ID))
		}
		adoptionPath, _ := state.YUMCompatibilityAdoptionPath(identity.ID)
		adoptionBlob, exists, err := canonical.BlobIdentityAt(pinned, adoptionPath)
		if err != nil || !exists || adoptionBlob.Hash.String() != identity.AdoptionGit || adoptionBlob.Size != identity.AdoptionSize {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s adoption receipt blob changed", identity.ID))
		}
		adoptionReader, err := canonical.OpenPathAt(pinned, adoptionPath)
		if err != nil {
			return err
		}
		adoptionSHA, err := hashReader(adoptionReader)
		if err != nil || adoptionSHA != identity.AdoptionSHA256 {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s adoption receipt bytes changed", identity.ID))
		}
		manifestPath, _ := state.YUMCompatibilityManifestPath(identity.ID)
		manifestBlob, exists, err := canonical.BlobIdentityAt(stateCommit, manifestPath)
		if err != nil || !exists || manifestBlob.Hash.String() != identity.PayloadManifestGit || manifestBlob.Size != identity.PayloadManifestSize {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s payload manifest blob changed", identity.ID))
		}
		frozenManifest, exists, err := canonical.BlobIdentityAt(freezeCommit, manifestPath)
		if err != nil || !exists || frozenManifest != manifestBlob {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s freeze commit does not preserve payload manifest", identity.ID))
		}
		manifestReader, err := canonical.OpenPathAt(stateCommit, manifestPath)
		if err != nil {
			return err
		}
		manifestSHA, err := hashReader(manifestReader)
		if err != nil || manifestSHA != identity.PayloadManifestSHA256 {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s payload manifest bytes changed", identity.ID))
		}
		trustPath, _ := state.YUMCompatibilityPackageTrustPath(identity.ID)
		trustBlob, exists, err := canonical.BlobIdentityAt(stateCommit, trustPath)
		if err != nil || !exists || trustBlob.Hash.String() != identity.PackageTrustGit || trustBlob.Size != identity.PackageTrustSize {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s package trust Git identity changed", identity.ID))
		}
		frozenTrust, exists, err := canonical.BlobIdentityAt(freezeCommit, trustPath)
		if err != nil || !exists || frozenTrust != trustBlob {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s freeze commit does not preserve package trust", identity.ID))
		}
		trust, err := canonical.OpenPathAt(stateCommit, trustPath)
		if err != nil {
			return err
		}
		hasher := sha256.New()
		written, copyErr := io.Copy(hasher, io.LimitReader(trust, maxSecretBytes+1))
		closeErr := trust.Close()
		if copyErr != nil || closeErr != nil || written > maxSecretBytes || written != identity.PackageTrustSize || hex.EncodeToString(hasher.Sum(nil)) != identity.PackageTrustSHA256 {
			return errors.Join(copyErr, closeErr, fmt.Errorf("published compatibility identity %s frozen package trust changed", identity.ID))
		}
		candidateManifestPath, _ := state.YUMCompatibilityCandidateManifestPath(identity.ID)
		candidateManifestBlob, exists, err := canonical.BlobIdentityAt(stateCommit, candidateManifestPath)
		if err != nil || !exists || candidateManifestBlob.Hash.String() != identity.CandidateManifestGit || candidateManifestBlob.Size != identity.CandidateManifestSize {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s candidate manifest Git identity changed", identity.ID))
		}
		frozenCandidateManifest, exists, err := canonical.BlobIdentityAt(freezeCommit, candidateManifestPath)
		if err != nil || !exists || frozenCandidateManifest != candidateManifestBlob {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s freeze commit does not preserve candidate manifest", identity.ID))
		}
		candidateManifestSHA, exists, err := hashCanonicalPathOptionalAt(canonical, stateCommit, candidateManifestPath)
		if err != nil || !exists || candidateManifestSHA != identity.CandidateManifestSHA256 {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s candidate manifest bytes changed", identity.ID))
		}
		candidateReceiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(identity.ID)
		candidateReceiptBlob, exists, err := canonical.BlobIdentityAt(stateCommit, candidateReceiptPath)
		if err != nil || !exists || candidateReceiptBlob.Hash.String() != identity.CandidateReceiptGit || candidateReceiptBlob.Size != identity.CandidateReceiptSize {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s candidate receipt Git identity changed", identity.ID))
		}
		frozenCandidateReceipt, exists, err := canonical.BlobIdentityAt(freezeCommit, candidateReceiptPath)
		if err != nil || !exists || frozenCandidateReceipt != candidateReceiptBlob {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s freeze commit does not preserve candidate receipt", identity.ID))
		}
		candidateReceiptBody, exists, err := readCanonicalBytesAt(canonical, stateCommit, candidateReceiptPath, maximumYUMCompatibilityWitnessBytes)
		if err != nil || !exists || int64(len(candidateReceiptBody)) != identity.CandidateReceiptSize || digestBytesCLI(candidateReceiptBody) != identity.CandidateReceiptSHA256 {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s candidate receipt bytes changed", identity.ID))
		}
		candidateReceipt, err := decodeYUMCompatibilityCandidate(candidateReceiptBody)
		if err != nil || candidateReceipt.ID != identity.ID || candidateReceipt.Root != identity.Root || candidateReceipt.Carrier != identity.Carrier || candidateReceipt.OwnerRepo != identity.OwnerRepo ||
			candidateReceipt.SourceRef != identity.SourceRef || candidateReceipt.SourceCommit != identity.SourceCommit || candidateReceipt.SourceManifestSHA256 != identity.SourceManifestSHA256 || candidateReceipt.SourceManifestGit != identity.SourceManifestGit || candidateReceipt.SourceManifestSize != identity.SourceManifestSize ||
			candidateReceipt.AdoptionSHA256 != identity.AdoptionSHA256 || candidateReceipt.AdoptionGit != identity.AdoptionGit || candidateReceipt.AdoptionSize != identity.AdoptionSize ||
			candidateReceipt.PackageTrustSHA256 != identity.PackageTrustSHA256 || candidateReceipt.PackageTrustGit != identity.PackageTrustGit || candidateReceipt.PackageTrustSize != identity.PackageTrustSize ||
			candidateReceipt.CandidateManifestSHA256 != identity.CandidateManifestSHA256 || candidateReceipt.CandidateManifestGit != identity.CandidateManifestGit || candidateReceipt.CandidateManifestSize != identity.CandidateManifestSize ||
			candidateReceipt.RepomdSHA256 != identity.RepomdSHA256 || candidateReceipt.RepositoryKeySHA256 != identity.RepositoryKeySHA256 {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s candidate receipt semantic identity changed", identity.ID))
		}
		confirmation, err := yumCompatibilityConfirmation("freeze", candidateReceipt)
		if err != nil || candidateReceipt.FreezeConfirm != confirmation {
			return errors.Join(err, fmt.Errorf("published compatibility identity %s candidate receipt confirmation is not content-bound", identity.ID))
		}
		if generation.RepositoryKeySHA256 == "" || generation.RepositoryKeySHA256 != identity.RepositoryKeySHA256 {
			return fmt.Errorf("published compatibility identity %s repository signing identity differs from target generation", identity.ID)
		}
		candidate, err := canonical.OpenPathAt(stateCommit, candidateManifestPath)
		if err != nil {
			return err
		}
		payload, err := canonical.OpenPathAt(stateCommit, manifestPath)
		if err != nil {
			_ = candidate.Close()
			return err
		}
		_, _, candidateErr := validateHistoricalCompatibilityCandidate(candidate, payload, identity)
		candidateCloseErr := errors.Join(candidate.Close(), payload.Close())
		if candidateErr != nil || candidateCloseErr != nil {
			return errors.Join(candidateErr, candidateCloseErr, fmt.Errorf("published compatibility identity %s frozen candidate closure changed", identity.ID))
		}
		cutoverPath, _ := state.YUMCompatibilityCutoverPath(identity.ID)
		cutoverBody, cutoverExists, err := readCanonicalBytesAt(canonical, stateCommit, cutoverPath, 1<<20)
		if err != nil {
			return err
		}
		cutoverBound := identity.CutoverSHA256 != "" || identity.CutoverGit != "" || identity.CutoverSize != 0
		if cutoverExists != cutoverBound {
			return fmt.Errorf("published compatibility identity %s cutover receipt presence differs from frozen publication state", identity.ID)
		}
		if cutoverExists {
			cutoverBlob, exists, err := canonical.BlobIdentityAt(stateCommit, cutoverPath)
			if err != nil || !exists || cutoverBlob.Hash.String() != identity.CutoverGit || cutoverBlob.Size != identity.CutoverSize || int64(len(cutoverBody)) != identity.CutoverSize || digestBytesCLI(cutoverBody) != identity.CutoverSHA256 {
				return errors.Join(err, fmt.Errorf("published compatibility identity %s cutover receipt changed", identity.ID))
			}
		}
		channel, exists := channels[identity.ChannelRemoteKey]
		if !exists || channel.View != "latest" || channel.Repo != identity.ID || channel.OS != "cross-el" || channel.Arch != projection.Source.Arch || channel.LegacyRoot != identity.RouteRoot {
			return fmt.Errorf("published compatibility identity %s independent channel is missing or changed", identity.ID)
		}
		if identity.RouteTarget != "compatibility" || identity.RouteRoot != projection.Root {
			return fmt.Errorf("published compatibility identity %s route target is not canonical", identity.ID)
		}
	}
	for _, channel := range generation.Channels {
		if channel.OS != "cross-el" {
			continue
		}
		if _, exists := seen[channel.Repo]; !exists {
			return fmt.Errorf("cross-el channel %s has no frozen compatibility identity", channel.RemoteKey)
		}
	}
	return nil
}

// validateDesiredGenerationCompatibilityCompleteness is a write-side gate.
// Unlike validation of an existing parent, a newly constructed generation
// must carry every frozen projection owned by this target. Calling it only
// after desired state construction avoids deadlocking first introduction and
// incremental expansion while still making omissions fail closed.
func validateDesiredGenerationCompatibilityCompleteness(cfg *config.Config, target string, generation pub.TargetGeneration) error {
	if cfg == nil {
		return errors.New("desired compatibility completeness requires configuration")
	}
	seen := make(map[string]struct{}, len(generation.Compatibility))
	for _, identity := range generation.Compatibility {
		if _, duplicate := seen[identity.ID]; duplicate {
			return fmt.Errorf("duplicate compatibility publication identity %s", identity.ID)
		}
		seen[identity.ID] = struct{}{}
	}
	for _, projection := range cfg.CompatibilityProjections {
		owner, exists := cfg.RepoByName(projection.Source.Repo)
		if !exists || !owner.PublishesToTarget(target) {
			continue
		}
		if _, exists := seen[projection.ID]; !exists {
			return fmt.Errorf("target %s generation omits configured frozen compatibility identity %s", target, projection.ID)
		}
	}
	return nil
}

func compatibilityStateAtGeneration(generation pub.TargetGeneration, id string) (pub.CompatibilityState, bool) {
	for _, identity := range generation.Compatibility {
		if identity.ID == id {
			return identity, true
		}
	}
	return pub.CompatibilityState{}, false
}
