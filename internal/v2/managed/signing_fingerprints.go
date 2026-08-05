package managed

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

// effectiveConfigView resolves only public key fingerprints into the public
// effective view. References remain visible, while private bytes and
// passphrases never enter the returned value, renderer hash, state, or log.
func effectiveConfigView(ctx context.Context, root string, cfg config.Config, opts config.ViewOptions) (config.EffectiveConfig, error) {
	view, err := config.EffectiveView(cfg, opts)
	if err != nil {
		return config.EffectiveConfig{}, err
	}
	for repoName, effectiveRepo := range view.Repositories {
		repository := cfg.Repositories[repoName]
		resolved, err := resolveEffectiveSigningFingerprints(ctx, root, repository.Signing, effectiveRepo.Signing)
		if err != nil {
			return config.EffectiveConfig{}, fmt.Errorf("%w: repository %q signing: %v", ErrRejected, repoName, err)
		}
		effectiveRepo.Signing = resolved
		view.Repositories[repoName] = effectiveRepo
	}
	return view, nil
}

// EffectiveConfigView returns the secret-safe effective workspace view with
// all configured public-key fingerprints resolved. It is shared by the CLI's
// scoped config-show projection and renderer identity calculation.
func EffectiveConfigView(ctx context.Context, root string, cfg config.Config, opts config.ViewOptions) (config.EffectiveConfig, error) {
	return effectiveConfigView(ctx, root, cfg, opts)
}

func resolveEffectiveSigningFingerprints(ctx context.Context, root string, signing config.SigningConfig, effective config.EffectiveSigningConfig) (config.EffectiveSigningConfig, error) {
	return resolveEffectiveSigningFingerprintsForFormats(ctx, root, signing, effective, true, true)
}

func resolveEffectiveSigningFingerprintsForFormats(ctx context.Context, root string, signing config.SigningConfig, effective config.EffectiveSigningConfig, wantRPM, wantDEB bool) (config.EffectiveSigningConfig, error) {
	if ctx == nil {
		return config.EffectiveSigningConfig{}, errors.New("nil signing fingerprint context")
	}
	resolveOne := func(label, reference string) (string, error) {
		if reference == "" {
			return "", nil
		}
		fingerprints, err := resolveReferenceFingerprints(ctx, root, reference)
		if err != nil {
			return "", fmt.Errorf("%s: %w", label, err)
		}
		if len(fingerprints) != 1 {
			return "", fmt.Errorf("%s must resolve to exactly one primary OpenPGP key", label)
		}
		return fingerprints[0], nil
	}

	if wantRPM {
		mode := signing.RPM.Packages.Mode
		if mode == "" {
			if signing.RPM.Packages.Key == "" {
				mode = "never"
			} else {
				mode = "fill"
			}
		}
		currentPackageFingerprint := ""
		trustedPackageFingerprints := []string{}
		currentPackageSnapshot := ""
		trustedPackageSnapshots := []string{}
		var err error
		if mode != "never" {
			currentKeys, keyErr := resolveReferenceRPMSnapshots(ctx, root, signing.RPM.Packages.Key)
			if keyErr != nil || len(currentKeys) != 1 {
				return config.EffectiveSigningConfig{}, fmt.Errorf("rpm packages key must resolve to exactly one primary OpenPGP certificate: %w", keyErr)
			}
			currentPackageFingerprint = currentKeys[0].Fingerprint
			currentPackageSnapshot = currentKeys[0].SnapshotSHA256
			for _, reference := range signing.RPM.Packages.TrustedKeys {
				keys, err := resolveReferenceRPMSnapshots(ctx, root, reference)
				if err != nil {
					return config.EffectiveSigningConfig{}, fmt.Errorf("rpm trusted key: %w", err)
				}
				for _, key := range keys {
					trustedPackageFingerprints = append(trustedPackageFingerprints, key.Fingerprint)
					trustedPackageSnapshots = append(trustedPackageSnapshots, key.SnapshotSHA256)
				}
			}
		}
		effective.RPM.Packages, err = canonicalEffectiveRPMPackages(signing.RPM.Packages, currentPackageFingerprint, trustedPackageFingerprints, currentPackageSnapshot, trustedPackageSnapshots)
		if err != nil {
			return config.EffectiveSigningConfig{}, err
		}
		if signing.RPM.Metadata.Key != "" {
			if effective.RPM.Metadata == nil {
				effective.RPM.Metadata = &config.EffectiveMetadataSigningConfig{Key: signing.RPM.Metadata.Key, Passphrase: signing.RPM.Metadata.Passphrase}
			}
			effective.RPM.Metadata.KeyFingerprint, err = resolveOne("rpm metadata key", signing.RPM.Metadata.Key)
			if err != nil {
				return config.EffectiveSigningConfig{}, err
			}
		}
	} else {
		effective.RPM = config.EffectiveRPMSigningConfig{}
	}
	if wantDEB && signing.DEB.Metadata.Key != "" {
		if effective.DEB == nil {
			effective.DEB = &config.EffectiveDEBSigningConfig{Metadata: config.EffectiveMetadataSigningConfig{Key: signing.DEB.Metadata.Key, Passphrase: signing.DEB.Metadata.Passphrase}}
		}
		fingerprint, err := resolveOne("deb metadata key", signing.DEB.Metadata.Key)
		if err != nil {
			return config.EffectiveSigningConfig{}, err
		}
		effective.DEB.Metadata.KeyFingerprint = fingerprint
	} else if !wantDEB {
		effective.DEB = nil
	}
	return effective, nil
}

// canonicalEffectiveRPMPackages is the one normalization boundary shared by
// read/status hashing and the signer-frozen build plan. In an active signing
// mode the current key is always trusted in addition to explicit trusted_keys;
// in never mode key references are dormant and are not resolved or fingerprinted.
func canonicalEffectiveRPMPackages(raw config.RPMPackageSigningConfig, current string, trusted []string, currentSnapshot string, trustedSnapshots []string) (config.EffectiveRPMPackageSigningConfig, error) {
	mode := raw.Mode
	if mode == "" {
		if raw.Key == "" {
			mode = "never"
		} else {
			mode = "fill"
		}
	}
	effective := config.EffectiveRPMPackageSigningConfig{
		Mode: mode, Key: raw.Key, TrustedKeys: append([]string(nil), raw.TrustedKeys...),
	}
	if mode == "never" {
		return effective, nil
	}
	current = strings.ToUpper(current)
	if !managedFingerprint.MatchString(current) {
		return config.EffectiveRPMPackageSigningConfig{}, errors.New("RPM package signing snapshot has no public identity")
	}
	effective.KeyFingerprint = current
	if !lowercaseSHA256.MatchString(currentSnapshot) {
		return config.EffectiveRPMPackageSigningConfig{}, errors.New("RPM package signing snapshot has no exact public certificate identity")
	}
	effective.KeySnapshotSHA256 = currentSnapshot
	allTrusted := append([]string(nil), trusted...)
	allTrusted = append(allTrusted, current)
	for index := range allTrusted {
		allTrusted[index] = strings.ToUpper(allTrusted[index])
		if !managedFingerprint.MatchString(allTrusted[index]) {
			return config.EffectiveRPMPackageSigningConfig{}, errors.New("RPM package signing trust snapshot has an invalid public identity")
		}
	}
	sort.Strings(allTrusted)
	effective.TrustedKeyFingerprints = stableUniqueStrings(allTrusted)
	allSnapshots := append([]string(nil), trustedSnapshots...)
	allSnapshots = append(allSnapshots, currentSnapshot)
	for _, snapshot := range allSnapshots {
		if !lowercaseSHA256.MatchString(snapshot) {
			return config.EffectiveRPMPackageSigningConfig{}, errors.New("RPM package signing trust snapshot has an invalid certificate identity")
		}
	}
	sort.Strings(allSnapshots)
	effective.TrustedKeySnapshotSHA256s = stableUniqueStrings(allSnapshots)
	return effective, nil
}

func resolveReferenceRPMSnapshots(ctx context.Context, root, reference string) ([]state.RPMSigningKey, error) {
	data, err := resolvePublicKeyReference(ctx, root, reference)
	if err != nil {
		return nil, err
	}
	keys, err := retainedRPMSigningKeysFromMaterial(data)
	if err != nil || len(keys) == 0 {
		return nil, errors.New("key reference has no parseable OpenPGP certificate snapshot")
	}
	return keys, nil
}

func resolveReferenceFingerprints(ctx context.Context, root, reference string) ([]string, error) {
	keys, err := resolveReferenceRPMSnapshots(ctx, root, reference)
	if err != nil {
		return nil, err
	}
	fingerprints := make([]string, 0, len(keys))
	for _, key := range keys {
		fingerprints = append(fingerprints, key.Fingerprint)
	}
	sort.Strings(fingerprints)
	return stableUniqueStrings(fingerprints), nil
}

// validateSigningApplicability is the config-check preflight. It proves that
// configured signing keys can actually sign at the current time without
// producing a signature or mutating any repository state.
func validateSigningApplicability(ctx context.Context, root string, signing config.SigningConfig) error {
	return validateSigningApplicabilityForFormats(ctx, root, signing, true, true)
}

func validateSigningApplicabilityForFormats(ctx context.Context, root string, signing config.SigningConfig, wantRPM, wantDEB bool) error {
	if _, err := resolveEffectiveSigningFingerprintsForFormats(ctx, root, signing, config.EffectiveSigningConfig{}, wantRPM, wantDEB); err != nil {
		return err
	}
	if wantRPM && signing.RPM.Packages.Mode != "never" {
		if _, err := loadRPMSigningPolicy(ctx, root, signing.RPM.Packages); err != nil {
			return fmt.Errorf("rpm packages policy is not usable: %w", err)
		}
		if err := validateRPMPackageSigningKey(ctx, root, signing.RPM.Packages.Key); err != nil {
			return fmt.Errorf("rpm packages key is not usable for signing: %w", err)
		}
	}
	repository := config.RepositoryConfig{Signing: signing}
	if _, err := loadMetadataSignerSnapshotForFormats(ctx, root, repository, time.Now().UTC(), wantRPM, wantDEB); err != nil {
		return err
	}
	references := map[string]string{}
	if wantRPM {
		references["rpm metadata key"] = signing.RPM.Metadata.Key
	}
	if wantDEB {
		references["deb metadata key"] = signing.DEB.Metadata.Key
	}
	for label, reference := range references {
		if reference == "" {
			continue
		}
		_, identity, err := resolveKeyReference(root, reference)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if identity == "" {
			continue
		}
		public, err := exportPublicKey(ctx, identity)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		fingerprints, err := yumrepo.RPMPackageKeyringPrimaryFingerprints(public)
		if err != nil || len(fingerprints) != 1 {
			return fmt.Errorf("%s must resolve to exactly one primary OpenPGP key", label)
		}
		if err := probeGPGSigning(ctx, fingerprints[0]); err != nil {
			return fmt.Errorf("%s is not usable for signing: %w", label, err)
		}
	}
	return nil
}
