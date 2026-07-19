package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

type rpmPackageTrustPolicy struct {
	SHA256  string
	Keyring openpgp.KeyRing
}

type publicationRPMTrustSnapshot struct {
	ConfigSHA256 string
	Repos        map[string]rpmPackageTrustPolicy
}

// publicationConfigSHA256ForRefs binds target generations to both canonical YAML and
// the exact public RPM package-trust bundles referenced by that YAML. This
// gives the incremental path a small, durable trust-policy identity: an
// unchanged generation can reuse prior per-ref verification, while any signer
// rotation forces a one-time revalidation of all reachable RPM refs.
func publicationConfigSHA256ForRefs(cfg *config.Config, refs []pub.RefState) (string, error) {
	snapshot, err := loadPublicationRPMTrustSnapshot(cfg, refs)
	if err != nil {
		return "", err
	}
	return snapshot.ConfigSHA256, nil
}

func publicationConfigSHA256ForGeneration(cfg *config.Config, generation pub.TargetGeneration) (string, error) {
	base, err := publicationConfigSHA256ForRefs(cfg, generation.Refs)
	if err != nil {
		return "", err
	}
	return publicationConfigSHAWithCompatibility(base, generation.Compatibility), nil
}

func loadPublicationRPMTrustSnapshot(cfg *config.Config, refs []pub.RefState) (*publicationRPMTrustSnapshot, error) {
	if cfg == nil {
		return nil, errors.New("publication configuration is unavailable")
	}
	base, err := cfg.CanonicalSHA256()
	if err != nil {
		return nil, err
	}
	type packageTrust struct {
		repo string
		sha  string
	}
	reachable := make(map[string]config.Repo)
	for _, ref := range refs {
		parts := strings.Split(ref.Name, "/")
		if len(parts) != 7 || parts[0] != "refs" || parts[1] != "sow" || parts[2] != "views" && parts[2] != "snapshots" {
			return nil, fmt.Errorf("publication config identity received invalid ref %q", ref.Name)
		}
		repo, exists := cfg.RepoByName(parts[4])
		if !exists {
			return nil, fmt.Errorf("publication config identity ref %q names unknown repo", ref.Name)
		}
		if repo.Type == "yum" {
			reachable[repo.ID] = repo
		}
	}
	trust := make([]packageTrust, 0, len(reachable))
	policies := make(map[string]rpmPackageTrustPolicy, len(reachable))
	for _, repo := range reachable {
		if repo.YUM == nil {
			return nil, fmt.Errorf("repo %s has no YUM package trust configuration", repo.ID)
		}
		if repo.Type != "yum" {
			continue
		}
		keyring, digest, err := loadRPMPackageKeyring(cfg.Path, repo.YUM.PackageKeyring)
		if err != nil || digest == "" {
			return nil, errors.Join(err, fmt.Errorf("repo %s has no usable RPM package keyring identity", repo.ID))
		}
		trust = append(trust, packageTrust{repo: repo.ID, sha: digest})
		policies[repo.ID] = rpmPackageTrustPolicy{SHA256: digest, Keyring: keyring}
	}
	sort.Slice(trust, func(i, j int) bool { return trust[i].repo < trust[j].repo })
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("sow-publication-config-v2\x00"))
	_, _ = hasher.Write([]byte(base))
	for _, item := range trust {
		_, _ = hasher.Write([]byte("\x00" + item.repo + "\x00" + item.sha))
	}
	return &publicationRPMTrustSnapshot{ConfigSHA256: hex.EncodeToString(hasher.Sum(nil)), Repos: policies}, nil
}

// preflightPublicationRefsRPMPackageTrust verifies the exact ref vector that
// the next target generation will retain, including inherited views and
// snapshots outside the current selector. A package signer therefore cannot be
// removed while any target-reachable canonical ref still depends on it.
func preflightPublicationRefsRPMPackageTrust(ctx context.Context, cfg *config.Config, canonical *state.Store, target string, refs []pub.RefState, compatibility []pub.CompatibilityState, parent *pub.TargetGeneration, trust *publicationRPMTrustSnapshot, workers int) error {
	if trust == nil {
		return errors.New("publication RPM trust snapshot is unavailable")
	}
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return err
	}
	seen := make(map[string]struct{})
	parentRefs := make(map[string]pub.RefState)
	trustPolicyUnchanged := false
	if parent != nil && sameCompatibilityStates(parent.Compatibility, compatibility) {
		// A compatibility generation wraps the ordinary config/package-trust
		// digest with the immutable cross-EL witness vector. Compare like with
		// like. A cutover or rollback changes the desired compatibility vector
		// and deliberately disables reuse, forcing every reachable RPM ref back
		// through package-signature verification before that transition can be
		// published.
		if len(parent.Compatibility) != 0 {
			if err := validateGenerationCompatibility(cfg, canonical, target, *parent); err != nil {
				return err
			}
		}
		trustPolicyUnchanged = parent.ConfigSHA256 == publicationConfigSHAWithCompatibility(trust.ConfigSHA256, compatibility)
	}
	if trustPolicyUnchanged {
		for _, ref := range parent.Refs {
			parentRefs[ref.Name] = ref
		}
	}
	verificationTime := time.Now().UTC()
	for _, ref := range refs {
		parts := strings.Split(ref.Name, "/")
		if len(parts) != 7 || parts[0] != "refs" || parts[1] != "sow" || parts[2] != "views" && parts[2] != "snapshots" {
			return fmt.Errorf("target ref %q is not a canonical view or snapshot leaf", ref.Name)
		}
		repo, exists := cfg.RepoByName(parts[4])
		if !exists {
			return fmt.Errorf("target ref %q names unknown repo %q", ref.Name, parts[4])
		}
		if repo.Type != "yum" {
			continue
		}
		previous, previouslyTrusted := parentRefs[ref.Name]
		if previouslyTrusted && previous == ref {
			// The parent generation binds the same ref and the same content-bound
			// publication config hash, so its successful preflight is reusable.
			continue
		}
		identity := ref.Name + "\x00" + ref.Commit + "\x00" + ref.ManifestSHA256
		if _, duplicate := seen[identity]; duplicate {
			continue
		}
		seen[identity] = struct{}{}
		commit := plumbing.NewHash(ref.Commit)
		if commit.IsZero() || commit.String() != ref.Commit {
			return fmt.Errorf("target ref %q has invalid canonical commit %q", ref.Name, ref.Commit)
		}
		var manifestPath string
		if parts[2] == "views" {
			manifestPath, err = state.ViewPath(parts[3], repo.ID, parts[5], parts[6])
		} else {
			manifestPath, err = state.SnapshotPath(parts[3], repo.ID, parts[5], parts[6])
		}
		if err != nil {
			return err
		}
		manifestReader, err := canonical.OpenPathAt(commit, manifestPath)
		if err != nil {
			return err
		}
		manifestSHA, err := hashReader(manifestReader)
		if err != nil || manifestSHA != ref.ManifestSHA256 {
			return errors.Join(err, fmt.Errorf("target ref %s manifest digest=%s want=%s", ref.Name, manifestSHA, ref.ManifestSHA256))
		}
		policy, exists := trust.Repos[repo.ID]
		if !exists || policy.Keyring == nil || policy.SHA256 == "" {
			return fmt.Errorf("repo %s is absent from the immutable RPM package-trust snapshot", repo.ID)
		}
		leaf := viewLeaf{repo: repo, os: parts[5], arch: parts[6]}
		reader, err := canonical.OpenPathAt(commit, manifestPath)
		if err != nil {
			return err
		}
		if previouslyTrusted {
			oldCommit := plumbing.NewHash(previous.Commit)
			if oldCommit.IsZero() || oldCommit.String() != previous.Commit {
				_ = reader.Close()
				return fmt.Errorf("parent target ref %q has invalid canonical commit %q", previous.Name, previous.Commit)
			}
			oldHashReader, err := canonical.OpenPathAt(oldCommit, manifestPath)
			if err != nil {
				_ = reader.Close()
				return err
			}
			oldSHA, hashErr := hashReader(oldHashReader)
			if hashErr != nil || oldSHA != previous.ManifestSHA256 {
				_ = reader.Close()
				return errors.Join(hashErr, fmt.Errorf("parent target ref %s manifest digest=%s want=%s", previous.Name, oldSHA, previous.ManifestSHA256))
			}
			oldReader, err := canonical.OpenPathAt(oldCommit, manifestPath)
			if err != nil {
				_ = reader.Close()
				return err
			}
			verifyErr := verifyCanonicalRPMViewDelta(ctx, reader, oldReader, pool, leaf, policy.Keyring, verificationTime, workers)
			closeErr := errors.Join(reader.Close(), oldReader.Close())
			if verifyErr != nil || closeErr != nil {
				return errors.Join(verifyErr, closeErr)
			}
			continue
		}
		verifyErr := verifyCanonicalRPMView(ctx, reader, pool, leaf, policy.Keyring, verificationTime, workers)
		closeErr := reader.Close()
		if verifyErr != nil || closeErr != nil {
			return errors.Join(verifyErr, closeErr)
		}
	}
	return nil
}

func verifyCanonicalRPMView(ctx context.Context, input io.Reader, pool *repository.Store, leaf viewLeaf, keyring openpgp.KeyRing, at time.Time, workers int) error {
	if input == nil || pool == nil || keyring == nil || at.IsZero() {
		return errors.New("canonical RPM trust preflight is not configured")
	}
	return verifyCanonicalRPMEntries(ctx, pool, leaf, keyring, at, workers, func(ctx context.Context, jobs chan<- views.Entry) error {
		reader := views.NewReader(input)
		for {
			entry, err := reader.Next()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
			if err := validateRPMTrustLeafEntry(entry, leaf); err != nil {
				return err
			}
			select {
			case jobs <- entry:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
}

// verifyCanonicalRPMViewDelta streams two canonical manifests and verifies
// package bytes only for additions or replacements. Identical entries inherit
// the parent generation's trust proof; removals require no package work.
func verifyCanonicalRPMViewDelta(ctx context.Context, current, previous io.Reader, pool *repository.Store, leaf viewLeaf, keyring openpgp.KeyRing, at time.Time, workers int) error {
	if current == nil || previous == nil || pool == nil || keyring == nil || at.IsZero() {
		return errors.New("canonical RPM delta trust preflight is not configured")
	}
	return verifyCanonicalRPMEntries(ctx, pool, leaf, keyring, at, workers, func(ctx context.Context, jobs chan<- views.Entry) error {
		currentReader, previousReader := views.NewReader(current), views.NewReader(previous)
		old, oldErr := previousReader.Next()
		for {
			entry, err := currentReader.Next()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
			if err := validateRPMTrustLeafEntry(entry, leaf); err != nil {
				return err
			}
			for oldErr == nil && old.Path < entry.Path {
				old, oldErr = previousReader.Next()
			}
			if oldErr != nil && !errors.Is(oldErr, io.EOF) {
				return oldErr
			}
			changed := oldErr != nil || old.Path != entry.Path || old != entry
			if oldErr == nil && old.Path == entry.Path {
				old, oldErr = previousReader.Next()
			}
			if !changed {
				continue
			}
			select {
			case jobs <- entry:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
}

func validateRPMTrustLeafEntry(entry views.Entry, leaf viewLeaf) error {
	if entry.Repo != leaf.repo.ID || entry.OS != leaf.os || entry.Arch != leaf.arch {
		return fmt.Errorf("view contains RPM outside %s/%s/%s", leaf.repo.ID, leaf.os, leaf.arch)
	}
	return nil
}

func verifyCanonicalRPMEntries(ctx context.Context, pool *repository.Store, leaf viewLeaf, keyring openpgp.KeyRing, at time.Time, workers int, produce func(context.Context, chan<- views.Entry) error) error {
	if workers <= 0 {
		workers = 4
	}
	if workers > 64 {
		workers = 64
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan views.Entry, workers*2)
	errCh := make(chan error, 1)
	recordError := func(err error) {
		select {
		case errCh <- err:
			cancel()
		default:
		}
	}
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for entry := range jobs {
				if ctx.Err() != nil {
					continue
				}
				digest, err := repository.ParseDigest(entry.SHA256)
				if err == nil {
					err = verifyCASRPMObject(ctx, pool, repository.Object{SHA256: digest, Size: entry.Size}, keyring, at)
				}
				if err != nil {
					recordError(fmt.Errorf("verify canonical RPM %s: %w", entry.Path, err))
				}
			}
		}()
	}
	if err := produce(ctx, jobs); err != nil {
		recordError(err)
	}
	close(jobs)
	wait.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return ctx.Err()
	}
}

func verifyCASRPMObject(ctx context.Context, pool *repository.Store, object repository.Object, keyring openpgp.KeyRing, at time.Time) (returnErr error) {
	return verifyCASRPMObjectWithHook(ctx, pool, object, keyring, at, nil)
}

func verifyCASRPMObjectWithHook(ctx context.Context, pool *repository.Store, object repository.Object, keyring openpgp.KeyRing, at time.Time, afterDigest func() error) (returnErr error) {
	file, err := pool.Open(object.SHA256)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != object.Size {
		return errors.Join(err, fmt.Errorf("CAS object %s is not a regular file of expected size %d", object.HashString(), object.Size))
	}
	hasher := sha256.New()
	buffer := make([]byte, 128*1024)
	written, err := io.CopyBuffer(hasher, &rpmTrustContextReader{ctx: ctx, reader: file}, buffer)
	if err != nil || written != object.Size {
		return errors.Join(err, fmt.Errorf("CAS object %s changed size while hashing", object.HashString()))
	}
	var actual repository.Digest
	copy(actual[:], hasher.Sum(nil))
	if actual != object.SHA256 {
		return fmt.Errorf("CAS object %s hashes to %s", object.HashString(), actual.String())
	}
	if afterDigest != nil {
		if err := afterDigest(); err != nil {
			return err
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind CAS object %s: %w", object.HashString(), err)
	}
	if _, err := yumrepo.VerifyEmbeddedRPMSignatures(ctx, file, keyring, at); err != nil {
		return err
	}
	after, err := file.Stat()
	current, pathErr := os.Lstat(pool.ObjectPath(object.SHA256))
	if err != nil || pathErr != nil || !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, after) || !os.SameFile(before, current) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return errors.Join(err, pathErr, fmt.Errorf("CAS object %s changed during trust verification", object.HashString()))
	}
	return nil
}

type rpmTrustContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *rpmTrustContextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
