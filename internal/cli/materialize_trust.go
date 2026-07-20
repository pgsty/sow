package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pgsty/sow/internal/config"
)

const materializationNoRepositoryKeySHA256 = "7b856df7fee8ab71d59e7759fad5b8c117bc27cf143ce2003602e498d70159c2"

type materializationTrustBoundary string

const (
	materializeTrustPayloadBefore         materializationTrustBoundary = "payload-before-mutation"
	materializeTrustPayloadAfter          materializationTrustBoundary = "payload-after-mutation"
	materializeTrustAPTCommitBefore       materializationTrustBoundary = "apt-before-live-commit"
	materializeTrustAPTCommitAfter        materializationTrustBoundary = "apt-after-live-commit"
	materializeTrustYUMActivationBefore   materializationTrustBoundary = "yum-before-live-activation"
	materializeTrustYUMActivationAfter    materializationTrustBoundary = "yum-after-live-activation"
	materializeTrustExactReconcileBefore  materializationTrustBoundary = "exact-reconcile-before-mutation"
	materializeTrustExactReconcileAfter   materializationTrustBoundary = "exact-reconcile-after-mutation"
	materializeTrustServingPublishBefore  materializationTrustBoundary = "serving-publish-before-mutation"
	materializeTrustServingPublishAfter   materializationTrustBoundary = "serving-publish-after-mutation"
	materializeTrustServingActivateBefore materializationTrustBoundary = "serving-activate-before-mutation"
	materializeTrustServingActivateAfter  materializationTrustBoundary = "serving-activate-after-mutation"
	materializeTrustServingLeafBefore     materializationTrustBoundary = "serving-leaf-before-generation"
	materializeTrustServingPointerBefore  materializationTrustBoundary = "serving-pointer-before-commit"
	materializeTrustServingLedgerAfter    materializationTrustBoundary = "serving-ledger-after-commit"
	materializeTrustServingPointerAfter   materializationTrustBoundary = "serving-pointer-after-commit"
	materializeTrustServingRestoreBefore  materializationTrustBoundary = "serving-restore-before-mutation"
	materializeTrustServingRestoreAfter   materializationTrustBoundary = "serving-restore-after-mutation"
	materializeTrustSelectedSetFinal      materializationTrustBoundary = "selected-set-final-barrier"
)

type materializationYUMTrust struct {
	digest  string
	keyring openpgp.KeyRing
}

// materializationTrustSnapshot freezes every trust input that may otherwise be
// replaced in place while a long materialization is running. Maps and parsed
// keyrings are read-only after construction and are safe to share among the
// bounded parallel leaf workers.
type materializationTrustSnapshot struct {
	repositoryKeySHA256 string
	yum                 map[string]materializationYUMTrust
	// verificationTime is set only for a package projection after its signing
	// key was revalidated under the global state lock. Recovery reuses that
	// frozen instant for the exact old transaction; unrelated materialization
	// remains subject to current-time key validity.
	verificationTime time.Time
	operationScope   string
	archiveAdoption  *offlineArchiveAdoptionContract

	selectionMu    sync.Mutex
	selection      *materializationSelectedSet
	completedUnits map[string]struct{}
	firstDrift     error

	// beforeCheck is a deterministic test seam. Production construction never
	// sets it; tests use it to rotate a key at an exact atomic boundary.
	beforeCheck func(materializationTrustBoundary)
	hookMu      sync.Mutex
}

// packageProjectionMaterializationTime returns the durable signing instant for
// an add/rm projection. A package transaction can stop before its canonical
// commit and resume after the repository key expires; deriving metadata time
// from that later replay commit would make the exact frozen operation
// impossible to finish. Other materialization paths never set
// verificationTime and keep their canonical/current fallback unchanged.
func packageProjectionMaterializationTime(values commonFlags, fallback time.Time) time.Time {
	if values.materializeTrust != nil && !values.materializeTrust.verificationTime.IsZero() {
		return values.materializeTrust.verificationTime.UTC().Truncate(time.Second)
	}
	return fallback.UTC()
}

func captureMaterializationTrust(cfg *config.Config, leaves []viewLeaf, privateKey []byte, repositoryKeySHA256 string) (*materializationTrustSnapshot, error) {
	return captureMaterializationTrustAt(cfg, leaves, privateKey, repositoryKeySHA256, time.Now().UTC())
}

func captureMaterializationTrustAt(cfg *config.Config, leaves []viewLeaf, privateKey []byte, repositoryKeySHA256 string, at time.Time) (*materializationTrustSnapshot, error) {
	if at.IsZero() {
		return nil, errors.New("materialization trust validation time is required")
	}
	if cfg == nil {
		return nil, errors.New("materialization configuration is unavailable")
	}
	repos := make(map[string]config.Repo)
	hasMaterializableLeaf := false
	for _, leaf := range leaves {
		if leaf.repo.Type == "apt" || leaf.repo.Type == "yum" || leaf.repo.Type == "asset" {
			hasMaterializableLeaf = true
		}
		if leaf.repo.Type == "apt" || leaf.repo.Type == "yum" {
			repos[leaf.repo.ID] = leaf.repo
		}
	}
	if len(repos) == 0 {
		if !hasMaterializableLeaf {
			return nil, nil
		}
		return &materializationTrustSnapshot{
			repositoryKeySHA256: materializationNoRepositoryKeySHA256,
			yum:                 make(map[string]materializationYUMTrust),
		}, nil
	}
	if !validMaterializationTrustSHA256(repositoryKeySHA256) {
		return nil, errors.New("repository signing key identity is invalid")
	}
	if err := requireRepositorySigningKeyIdentityAt(cfg, privateKey, repositoryKeySHA256, at); err != nil {
		return nil, fmt.Errorf("capture repository signing trust: %w", err)
	}
	snapshot := &materializationTrustSnapshot{
		repositoryKeySHA256: repositoryKeySHA256,
		yum:                 make(map[string]materializationYUMTrust),
	}
	for repoID, repo := range repos {
		if repo.Type != "yum" {
			continue
		}
		if repo.YUM == nil {
			return nil, fmt.Errorf("repo %s has no YUM configuration", repoID)
		}
		keyring, digest, err := loadRPMPackageKeyring(cfg.Path, repo.YUM.PackageKeyring)
		if err != nil || keyring == nil || !validMaterializationTrustSHA256(digest) {
			return nil, errors.Join(err, fmt.Errorf("repo %s has no stable RPM package trust identity", repoID))
		}
		snapshot.yum[repoID] = materializationYUMTrust{digest: digest, keyring: keyring}
	}
	return snapshot, nil
}

func validMaterializationTrustSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func (snapshot *materializationTrustSnapshot) runHook(boundary materializationTrustBoundary) {
	if snapshot == nil || snapshot.beforeCheck == nil {
		return
	}
	// A test hook may be used with parallel YUM leaves. Serialize the hook only;
	// production validation remains fully parallel because the hook is nil.
	snapshot.hookMu.Lock()
	snapshot.beforeCheck(boundary)
	snapshot.hookMu.Unlock()
}

func (snapshot *materializationTrustSnapshot) requireYUM(cfg *config.Config, repo config.Repo, privateKey []byte, boundary materializationTrustBoundary) (openpgp.KeyRing, error) {
	if snapshot == nil {
		keyring, _, err := loadRPMPackageKeyring(cfg.Path, repo.YUM.PackageKeyring)
		if err != nil || keyring == nil {
			return nil, errors.Join(err, fmt.Errorf("repo %s has no usable RPM package keyring", repo.ID))
		}
		return keyring, nil
	}
	snapshot.runHook(boundary)
	frozen, exists := snapshot.yum[repo.ID]
	if !exists || frozen.keyring == nil || !validMaterializationTrustSHA256(frozen.digest) {
		return nil, fmt.Errorf("repo %s is missing from the materialization trust snapshot", repo.ID)
	}
	err := snapshot.rawRequireRepository(cfg, boundary)
	if err == nil {
		_, currentDigest, readErr := loadRPMPackageKeyring(cfg.Path, repo.YUM.PackageKeyring)
		if readErr != nil {
			err = fmt.Errorf("re-read RPM package trust for repo %s at %s: %w", repo.ID, boundary, readErr)
		} else if currentDigest != frozen.digest {
			err = fmt.Errorf("RPM package keyring for repo %s changed at %s", repo.ID, boundary)
		}
	}
	if handled := snapshot.handleMaterializationTrustResult(cfg, "", boundary, err); handled != nil {
		return nil, handled
	}
	return frozen.keyring, nil
}

func (snapshot *materializationTrustSnapshot) rawRequireRepository(cfg *config.Config, boundary materializationTrustBoundary) error {
	at := time.Now().UTC()
	if !snapshot.verificationTime.IsZero() {
		at = snapshot.verificationTime
	}
	if err := requireMaterializationRepositoryPublicIdentityAt(cfg, snapshot.repositoryKeySHA256, at); err != nil {
		return fmt.Errorf("materialization trust changed at %s: %w", boundary, err)
	}
	return nil
}

func (snapshot *materializationTrustSnapshot) rawRequireAll(cfg *config.Config, boundary materializationTrustBoundary) error {
	if snapshot == nil {
		return nil
	}
	if err := snapshot.rawRequireRepository(cfg, boundary); err != nil {
		return err
	}
	repoIDs := make([]string, 0, len(snapshot.yum))
	for repoID := range snapshot.yum {
		repoIDs = append(repoIDs, repoID)
	}
	sort.Strings(repoIDs)
	for _, repoID := range repoIDs {
		frozen := snapshot.yum[repoID]
		repo, exists := cfg.RepoByName(repoID)
		if !exists || repo.Type != "yum" || repo.YUM == nil {
			return fmt.Errorf("materialization YUM trust repo %s is no longer configured", repoID)
		}
		_, currentDigest, err := loadRPMPackageKeyring(cfg.Path, repo.YUM.PackageKeyring)
		if err != nil {
			return fmt.Errorf("re-read RPM package trust for repo %s at %s: %w", repoID, boundary, err)
		}
		if currentDigest != frozen.digest {
			return fmt.Errorf("RPM package keyring for repo %s changed at %s", repoID, boundary)
		}
	}
	return nil
}

func requireMaterializationRepositoryPublicIdentityAt(cfg *config.Config, expected string, at time.Time) error {
	if expected == materializationNoRepositoryKeySHA256 {
		return nil
	}
	if cfg == nil || !validMaterializationTrustSHA256(expected) {
		return errors.New("expected repository public key identity is invalid")
	}
	_, packets, err := loadRepositoryPublicTrustAnchorAt(cfg.Path, cfg.GPG.PublicKey, at)
	if err != nil {
		return err
	}
	if repositoryTrustAnchorDigest(packets) != expected {
		return errors.New("repository public key changed after materialization trust capture")
	}
	return nil
}

func requireMaterializationRepositoryTrust(values commonFlags, cfg *config.Config, privateKey []byte, boundary materializationTrustBoundary) error {
	if values.materializeTrust == nil {
		return nil
	}
	values.materializeTrust.runHook(boundary)
	err := values.materializeTrust.rawRequireRepository(cfg, boundary)
	return values.materializeTrust.handleMaterializationTrustResult(cfg, values.materializeUnit, boundary, err)
}

func requireMaterializationYUMTrust(values commonFlags, cfg *config.Config, repo config.Repo, privateKey []byte, boundary materializationTrustBoundary) (openpgp.KeyRing, error) {
	if values.materializeTrust == nil {
		keyring, _, err := loadRPMPackageKeyring(cfg.Path, repo.YUM.PackageKeyring)
		if err != nil || keyring == nil {
			return nil, errors.Join(err, fmt.Errorf("repo %s has no usable RPM package keyring", repo.ID))
		}
		return keyring, nil
	}
	values.materializeTrust.runHook(boundary)
	frozen, exists := values.materializeTrust.yum[repo.ID]
	if !exists || frozen.keyring == nil || !validMaterializationTrustSHA256(frozen.digest) {
		return nil, fmt.Errorf("repo %s is missing from the materialization trust snapshot", repo.ID)
	}
	err := values.materializeTrust.rawRequireRepository(cfg, boundary)
	if err == nil {
		_, current, readErr := loadRPMPackageKeyring(cfg.Path, repo.YUM.PackageKeyring)
		if readErr != nil {
			err = fmt.Errorf("re-read RPM package trust for repo %s at %s: %w", repo.ID, boundary, readErr)
		} else if current != frozen.digest {
			err = fmt.Errorf("RPM package keyring for repo %s changed at %s", repo.ID, boundary)
		}
	}
	if handled := values.materializeTrust.handleMaterializationTrustResult(cfg, values.materializeUnit, boundary, err); handled != nil {
		return nil, handled
	}
	return frozen.keyring, nil
}

func requireAllMaterializationTrust(values commonFlags, cfg *config.Config, privateKey []byte, boundary materializationTrustBoundary) error {
	if values.materializeTrust == nil {
		return nil
	}
	values.materializeTrust.runHook(boundary)
	err := values.materializeTrust.rawRequireAll(cfg, boundary)
	return values.materializeTrust.handleMaterializationTrustResult(cfg, values.materializeUnit, boundary, err)
}

func materializationYUMTrustDigest(values commonFlags, cfg *config.Config, repo config.Repo) (string, error) {
	if values.materializeTrust != nil {
		frozen, exists := values.materializeTrust.yum[repo.ID]
		if !exists || frozen.keyring == nil || !validMaterializationTrustSHA256(frozen.digest) {
			return "", fmt.Errorf("repo %s is missing from the materialization trust snapshot", repo.ID)
		}
		return frozen.digest, nil
	}
	if repo.YUM == nil {
		return "", fmt.Errorf("repo %s has no YUM configuration", repo.ID)
	}
	_, digest, err := loadRPMPackageKeyring(cfg.Path, repo.YUM.PackageKeyring)
	if err != nil || !validMaterializationTrustSHA256(digest) {
		return "", errors.Join(err, fmt.Errorf("repo %s has no stable RPM package trust identity", repo.ID))
	}
	return digest, nil
}
