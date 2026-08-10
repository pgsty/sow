package managed

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

	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
)

type publicPayloadExpectation struct {
	file        state.GenerationFile
	object      state.PackageObject
	fingerprint *state.PackageFingerprint
	factExists  bool
}

// scanCurrentPublicGenerationFast keeps the exhaustive namespace traversal
// and metadata hashing of ordinary writes, but accepts an immutable package
// payload from its persisted descriptor fingerprint. A mismatch or missing
// fingerprint is a cache miss: the package SHA-256 authority is checked once
// and the fingerprint is then repaired. Changed bytes remain an integrity
// failure.
func scanCurrentPublicGenerationFast(ctx context.Context, repositoryRoot string, retained []state.GenerationFile, store *state.Store) (*publicGenerationSnapshot, error) {
	objects, err := store.ListPackageObjects(ctx, nil, false)
	if err != nil {
		return nil, err
	}
	fingerprints, err := store.ListPackageFingerprints(ctx)
	if err != nil {
		return nil, err
	}
	fingerprintByDigest := make(map[string]state.PackageFingerprintRecord, len(fingerprints))
	for _, fingerprint := range fingerprints {
		fingerprintByDigest[fingerprint.PackageSHA256] = fingerprint
	}
	objectByPath := make(map[string]state.PackageObject, len(objects))
	for _, object := range objects {
		objectByPath[object.PoolPath] = object
	}
	expected := make(map[string]state.GenerationFile, len(retained))
	payloads := make(map[string]publicPayloadExpectation)
	for _, file := range retained {
		if _, duplicate := expected[file.Path]; duplicate {
			return nil, fmt.Errorf("%w: retained Generation repeats path %s", ErrIntegrity, file.Path)
		}
		expected[file.Path] = file
		if file.Phase != "payload" {
			continue
		}
		object, exists := objectByPath[file.Path]
		if !exists || object.SHA256 != file.SHA256 || object.Size != file.Size {
			return nil, fmt.Errorf("%w: retained payload %s differs from PackageObject", ErrIntegrity, file.Path)
		}
		fingerprint, factExists := fingerprintByDigest[object.SHA256]
		payloads[file.Path] = publicPayloadExpectation{file: file, object: object, fingerprint: fingerprint.Fingerprint, factExists: factExists}
	}
	files := make([]state.GenerationFile, 0, len(retained))
	identities := make(map[string]rootedRegularIdentity, len(retained))
	seen := make(map[string]struct{}, len(retained))
	backfill := []state.PackageFact{}
	err = walkRootedTree(ctx, repositoryRoot, func(relative string, file *os.File, info os.FileInfo) error {
		if !strings.HasPrefix(relative, "pool/") && !strings.HasPrefix(relative, "dists/") {
			return fmt.Errorf("%w: public Repository contains an unmanaged root entry", ErrIntegrity)
		}
		phase := publicFilePhase(relative)
		if phase == "" {
			return fmt.Errorf("%w: dists contains package payload %s", ErrIntegrity, relative)
		}
		want, exists := expected[relative]
		if !exists || want.Phase != phase || want.Size != info.Size() {
			return fmt.Errorf("%w: current public delivery path differs from retained Generation at %s", ErrIntegrity, relative)
		}
		if _, duplicate := seen[relative]; duplicate {
			return fmt.Errorf("%w: current public delivery repeats %s", ErrIntegrity, relative)
		}
		seen[relative] = struct{}{}
		if phase == "payload" {
			expectation, exists := payloads[relative]
			if !exists {
				return fmt.Errorf("%w: public payload %s has no immutable object", ErrIntegrity, relative)
			}
			identity, identityErr := snapshotRegularDescriptorIdentity(file)
			if identityErr != nil {
				return identityErr
			}
			identities[relative] = identity
			needsHash := false
			if fingerprint := expectation.fingerprint; fingerprint != nil {
				contentMatch := identity.device == fingerprint.Device && identity.inode == fingerprint.Inode &&
					identity.size == fingerprint.Size && identity.modUnixNano == fingerprint.MTimeNano
				ctimeMatch := identity.changeUnixNano == fingerprint.CTimeNano
				if contentMatch && ctimeMatch {
					workmetrics.RecordStatHit(ctx)
				} else {
					// A fingerprint is only a fast cache key. Any stat drift falls
					// back to the package SHA-256 authority and self-heals the row.
					workmetrics.RecordStatMiss(ctx)
					needsHash = true
				}
			} else {
				workmetrics.RecordStatMiss(ctx)
				needsHash = true
			}
			if needsHash {
				hash := sha256.New()
				read, hashErr := io.Copy(hash, &managedContextReader{ctx: ctx, reader: file})
				if hashErr != nil {
					return hashErr
				}
				workmetrics.RecordFullPackageRead(ctx, read)
				if hex.EncodeToString(hash.Sum(nil)) != want.SHA256 {
					return fmt.Errorf("%w: public payload checksum changed at %s", ErrIntegrity, relative)
				}
				if expectation.factExists {
					backfill = append(backfill, state.PackageFact{PackageSHA256: expectation.object.SHA256, Fingerprint: packageFingerprint(identity)})
				}
			}
			files = append(files, want)
			return nil
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, &managedContextReader{ctx: ctx, reader: file}); err != nil {
			return err
		}
		if hex.EncodeToString(hash.Sum(nil)) != want.SHA256 {
			return fmt.Errorf("%w: public metadata checksum changed at %s", ErrIntegrity, relative)
		}
		identity, err := snapshotRegularDescriptorIdentity(file)
		if err != nil {
			return err
		}
		identities[relative] = identity
		files = append(files, want)
		return nil
	}, nil)
	if err != nil {
		return nil, err
	}
	if len(seen) != len(expected) {
		missing := make([]string, 0, len(expected)-len(seen))
		for path := range expected {
			if _, exists := seen[path]; !exists {
				missing = append(missing, path)
			}
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("%w: retained public delivery path is missing: %s", ErrIntegrity, missing[0])
	}
	if !store.ReadOnly() {
		err = store.UpdatePackageFingerprints(ctx, backfill)
	}
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return &publicGenerationSnapshot{Manifest: files, Identities: identities}, nil
}

func packageFingerprint(identity rootedRegularIdentity) *state.PackageFingerprint {
	return &state.PackageFingerprint{
		Device: identity.device, Inode: identity.inode, Size: identity.size,
		MTimeNano: identity.modUnixNano, CTimeNano: identity.changeUnixNano,
	}
}

// persistPublicPackageFingerprints reuses the post-normalization descriptor
// snapshot, avoiding a third Pool traversal. Only new or changed fingerprints
// are written; an unchanged warm build performs no package_facts UPDATEs.
func persistPublicPackageFingerprints(ctx context.Context, snapshot *publicGenerationSnapshot, store *state.Store) error {
	if snapshot == nil {
		return errors.New("managed: package fingerprint snapshot is unavailable")
	}
	if store.ReadOnly() {
		return nil
	}
	fingerprints, err := store.ListPackageFingerprints(ctx)
	if err != nil {
		return err
	}
	fingerprintByDigest := make(map[string]state.PackageFingerprintRecord, len(fingerprints))
	for _, fingerprint := range fingerprints {
		fingerprintByDigest[fingerprint.PackageSHA256] = fingerprint
	}
	updates := make([]state.PackageFact, 0)
	for _, file := range snapshot.Manifest {
		if file.Phase != "payload" {
			continue
		}
		stored, exists := fingerprintByDigest[file.SHA256]
		if !exists {
			continue
		}
		identity, exists := snapshot.Identities[file.Path]
		if !exists || !identity.valid(file.Size) {
			return fmt.Errorf("%w: final Pool fingerprint is unavailable for %s", ErrIntegrity, file.Path)
		}
		fingerprint := packageFingerprint(identity)
		if stored.Fingerprint != nil && *stored.Fingerprint == *fingerprint {
			continue
		}
		updates = append(updates, state.PackageFact{PackageSHA256: file.SHA256, Fingerprint: fingerprint})
	}
	return store.UpdatePackageFingerprints(ctx, updates)
}
