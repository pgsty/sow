package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
)

// publicationTrustSnapshot freezes the external trust policy used to build
// one exact target generation. The target generation already persists the
// aggregate identities; this snapshot additionally retains the per-repository
// RPM keyring digests so every irreversible boundary can diagnose which trust
// input changed without retaining secret or mutable file-path state.
type publicationTrustSnapshot struct {
	target                  pub.TargetName
	refs                    []pub.RefState
	repositoryKeySHA256     string
	publicationConfigSHA256 string
	rpmKeyringSHA256        map[string]string

	// beforeCheck is a deterministic test seam. Production never sets it.
	beforeCheck func(pub.TrustBoundary)
	hookMu      sync.Mutex
}

func capturePublicationTrust(generation pub.TargetGeneration, rpm *publicationRPMTrustSnapshot) (*publicationTrustSnapshot, error) {
	if generation.Target.Validate() != nil || rpm == nil || !validPublicationTrustSHA256(rpm.ConfigSHA256) {
		return nil, errors.New("publication trust snapshot is incomplete")
	}
	if generation.ConfigSHA256 != rpm.ConfigSHA256 {
		return nil, errors.New("target generation config identity differs from RPM trust snapshot")
	}
	if generation.RepositoryKeySHA256 != "" && !validPublicationTrustSHA256(generation.RepositoryKeySHA256) {
		return nil, errors.New("target generation repository key identity is invalid")
	}
	snapshot := &publicationTrustSnapshot{
		target:                  generation.Target,
		refs:                    append([]pub.RefState(nil), generation.Refs...),
		repositoryKeySHA256:     generation.RepositoryKeySHA256,
		publicationConfigSHA256: rpm.ConfigSHA256,
		rpmKeyringSHA256:        make(map[string]string, len(rpm.Repos)),
	}
	for repoID, policy := range rpm.Repos {
		if repoID == "" || !validPublicationTrustSHA256(policy.SHA256) || policy.Keyring == nil {
			return nil, fmt.Errorf("publication RPM trust for repo %s is invalid", repoID)
		}
		snapshot.rpmKeyringSHA256[repoID] = policy.SHA256
	}
	return snapshot, nil
}

func validPublicationTrustSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func (snapshot *publicationTrustSnapshot) runHook(boundary pub.TrustBoundary) {
	if snapshot == nil || snapshot.beforeCheck == nil {
		return
	}
	snapshot.hookMu.Lock()
	snapshot.beforeCheck(boundary)
	snapshot.hookMu.Unlock()
}

func (snapshot *publicationTrustSnapshot) require(cfg *config.Config, generation pub.TargetGeneration, target pub.TargetName, boundary pub.TrustBoundary) error {
	if snapshot == nil || cfg == nil {
		return fmt.Errorf("%w: publication trust snapshot is unavailable", pub.ErrDrift)
	}
	snapshot.runHook(boundary)
	if target != snapshot.target || generation.Target != snapshot.target || !sameRefStates(generation.Refs, snapshot.refs) {
		return fmt.Errorf("%w: publication ref vector changed after trust capture", pub.ErrDrift)
	}
	if generation.ConfigSHA256 != snapshot.publicationConfigSHA256 || generation.RepositoryKeySHA256 != snapshot.repositoryKeySHA256 {
		return fmt.Errorf("%w: target generation trust identities changed after plan construction", pub.ErrDrift)
	}
	currentRepositoryKey, err := repositoryTrustAnchorSHA256ForRefs(cfg, snapshot.refs)
	if err != nil {
		return fmt.Errorf("%w: re-read repository signing trust at %s: %v", pub.ErrDrift, boundary, err)
	}
	if currentRepositoryKey != snapshot.repositoryKeySHA256 {
		return fmt.Errorf("%w: repository public key changed at publication boundary %s", pub.ErrDrift, boundary)
	}
	currentRPM, err := loadPublicationRPMTrustSnapshot(cfg, snapshot.refs)
	if err != nil {
		return fmt.Errorf("%w: re-read RPM package trust at %s: %v", pub.ErrDrift, boundary, err)
	}
	if currentRPM.ConfigSHA256 != snapshot.publicationConfigSHA256 || len(currentRPM.Repos) != len(snapshot.rpmKeyringSHA256) {
		return fmt.Errorf("%w: RPM package trust-derived config identity changed at publication boundary %s", pub.ErrDrift, boundary)
	}
	for repoID, expected := range snapshot.rpmKeyringSHA256 {
		current, exists := currentRPM.Repos[repoID]
		if !exists || current.SHA256 != expected {
			return fmt.Errorf("%w: RPM package keyring for repo %s changed at publication boundary %s", pub.ErrDrift, repoID, boundary)
		}
	}
	return nil
}

func (publication targetPublication) trustGuard(cfg *config.Config) pub.TrustGuard {
	generation := publication.request.Generation
	return func(target pub.TargetName, boundary pub.TrustBoundary) error {
		return publication.requireTrustFor(cfg, generation, target, boundary)
	}
}

func (publication targetPublication) requireTrust(cfg *config.Config, boundary pub.TrustBoundary) error {
	return publication.requireTrustFor(cfg, publication.request.Generation, pub.TargetName(publication.target), boundary)
}

func (publication targetPublication) requireTrustFor(cfg *config.Config, generation pub.TargetGeneration, target pub.TargetName, boundary pub.TrustBoundary) error {
	if publication.trust == nil {
		return fmt.Errorf("%w: publication trust snapshot is unavailable", pub.ErrDrift)
	}
	return publication.trust.require(cfg, generation, target, boundary)
}
