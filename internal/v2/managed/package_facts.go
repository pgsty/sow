package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
	"github.com/pgsty/sow/internal/yumrepo"
)

// loadManagedPackageFacts performs one repository-wide SQLite read, matches
// selected objects in memory, and parallel-backfills only missing or invalid
// cache rows. Cache failures never become repository truth: source bytes remain
// authoritative and every rebuilt fact is checked against PackageObject.
func loadManagedPackageFacts(ctx context.Context, sources map[string]ManagedPackageSource, store *state.Store, jobs int, authenticated *publicGenerationSnapshot) error {
	digests := make([]string, 0, len(sources))
	for digest := range sources {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	stored, err := store.ListPackageFactsForDigests(ctx, digests)
	if err != nil {
		return err
	}
	byDigest := make(map[string]state.PackageFact, len(stored))
	for _, fact := range stored {
		byDigest[fact.PackageSHA256] = fact
	}
	if jobs < 1 {
		jobs = 1
	}
	if jobs > len(digests) {
		jobs = len(digests)
	}
	type factResult struct {
		source ManagedPackageSource
		fact   state.PackageFact
		miss   bool
		err    error
	}
	results := make([]factResult, len(digests))
	if jobs > 0 {
		indices := make(chan int)
		var group sync.WaitGroup
		group.Add(jobs)
		for range jobs {
			go func() {
				defer group.Done()
				for index := range indices {
					digest := digests[index]
					source := sources[digest]
					fact, exists := byDigest[digest]
					if exists && !fact.Corrupt {
						if decoded, decodeErr := decodeManagedPackageFact(source, fact); decodeErr == nil {
							results[index].source = decoded
							workmetrics.RecordFactCacheHit(ctx)
							continue
						}
					}
					var identity *rootedRegularIdentity
					if authenticated != nil && source.Object.Storage == "pool" {
						if value, ok := authenticated.AuthenticatedPayloads[source.Object.PoolPath]; ok {
							copyIdentity := value
							identity = &copyIdentity
						}
					}
					decoded, rebuilt, rebuildErr := rebuildManagedPackageFact(workmetrics.WithPhase(ctx, "facts_backfill"), source, identity)
					results[index] = factResult{source: decoded, fact: rebuilt, miss: true, err: rebuildErr}
					workmetrics.RecordFactCacheMiss(ctx)
				}
			}()
		}
		for index := range digests {
			indices <- index
		}
		close(indices)
		group.Wait()
	}
	updates := make([]state.PackageFact, 0)
	for index, result := range results {
		if result.err != nil {
			return fmt.Errorf("managed: load package facts %s: %w", digests[index], result.err)
		}
		sources[digests[index]] = result.source
		if result.miss {
			updates = append(updates, result.fact)
		}
	}
	if store.ReadOnly() {
		return nil
	}
	return store.UpsertPackageFacts(ctx, updates)
}

func decodeManagedPackageFact(source ManagedPackageSource, fact state.PackageFact) (ManagedPackageSource, error) {
	if fact.PackageSHA256 != source.Object.SHA256 {
		return ManagedPackageSource{}, errors.New("package fact digest differs from object")
	}
	switch source.Object.Format {
	case "rpm":
		if fact.FactSchema != yumrepo.PackageFactsSchema {
			return ManagedPackageSource{}, errors.New("RPM package fact schema is stale")
		}
		parsed, err := yumrepo.ParsePackageFacts(fact.Facts)
		if err != nil {
			return ManagedPackageSource{}, err
		}
		info, err := parsed.PackageInfo()
		if err != nil {
			return ManagedPackageSource{}, err
		}
		actual, err := rpmObjectFromInfo(info, source.Object.Filename, source.Object.PayloadSHA256)
		if err != nil || !sameManagedPackageFacts(source.Object, actual) {
			return ManagedPackageSource{}, errors.Join(errors.New("RPM package facts differ from object"), err)
		}
		source.RPMFacts = parsed
		source.DEBFacts = nil
		return source, nil
	case "deb":
		if fact.FactSchema != aptrepo.PackageFactsSchema {
			return ManagedPackageSource{}, errors.New("DEB package fact schema is stale")
		}
		parsed, err := aptrepo.PackageFromFacts(fact.Facts, source.Path)
		if err != nil {
			return ManagedPackageSource{}, err
		}
		actual, err := debObjectFromInfo(parsed, source.Object.Filename)
		if err != nil || !sameManagedPackageFacts(source.Object, actual) {
			return ManagedPackageSource{}, errors.Join(errors.New("DEB package facts differ from object"), err)
		}
		source.DEBFacts = &parsed
		source.RPMFacts = nil
		return source, nil
	default:
		return ManagedPackageSource{}, errors.New("unsupported package object format")
	}
}

func rebuildManagedPackageFact(ctx context.Context, source ManagedPackageSource, authenticated *rootedRegularIdentity) (ManagedPackageSource, state.PackageFact, error) {
	var fact state.PackageFact
	if source.Object.Format != "rpm" && source.Object.Format != "deb" {
		return ManagedPackageSource{}, fact, errors.New("unsupported package object format")
	}
	opened, err := source.open()
	if err != nil {
		return ManagedPackageSource{}, fact, err
	}
	openedIdentity, err := snapshotRootedRegularIdentity(opened)
	if err != nil {
		return ManagedPackageSource{}, fact, errors.Join(err, opened.CloseVerified())
	}
	var decoded ManagedPackageSource
	for attempt := 0; attempt < 2; attempt++ {
		reuseAuthenticated := attempt == 0 && authenticated != nil && *authenticated == openedIdentity && authenticated.valid(source.Object.Size)
		if !reuseAuthenticated {
			if err := readPackageFactSource(ctx, opened, source.Object); err != nil {
				return ManagedPackageSource{}, fact, errors.Join(err, opened.CloseVerified())
			}
		}
		decoded, err = inspectKnownPackageFacts(ctx, opened.file, source)
		if err != nil {
			return ManagedPackageSource{}, fact, errors.Join(err, opened.CloseVerified())
		}
		after, identityErr := snapshotRootedRegularIdentity(opened)
		if identityErr == nil && openedIdentity == after {
			if err := opened.CloseVerified(); err != nil {
				return ManagedPackageSource{}, fact, err
			}
			switch source.Object.Format {
			case "rpm":
				blob, err := decoded.RPMFacts.MarshalBinary()
				return decoded, state.PackageFact{PackageSHA256: source.Object.SHA256, FactSchema: yumrepo.PackageFactsSchema, Facts: blob}, err
			case "deb":
				blob, err := aptrepo.MarshalPackageFacts(*decoded.DEBFacts)
				return decoded, state.PackageFact{PackageSHA256: source.Object.SHA256, FactSchema: aptrepo.PackageFactsSchema, Facts: blob}, err
			}
		}
		if identityErr != nil || attempt != 0 || !openedIdentity.sameReadTarget(after) {
			return ManagedPackageSource{}, fact, errors.Join(fmt.Errorf("%w: package fact source identity changed during inspection", ErrIntegrity), identityErr, opened.CloseVerified())
		}
		// Discard the parsed facts and authenticate again; old facts do not
		// become evidence for the new ctime even when nlink changed too.
		openedIdentity = after
	}
	return ManagedPackageSource{}, fact, errors.Join(fmt.Errorf("%w: unstable package facts", ErrIntegrity), opened.CloseVerified())
}

func authenticatePackageFactSource(ctx context.Context, opened *rootedRegularFile, object state.PackageObject) error {
	before, err := snapshotRootedRegularIdentity(opened)
	if err != nil {
		return err
	}
	digest, after, err := digestPayloadDescriptor(ctx, opened.file, before)
	if err != nil {
		return err
	}
	if after.size != object.Size || digest != object.SHA256 {
		return errors.New("package bytes differ from immutable object")
	}
	return nil
}

// readPackageFactSource makes one pass within rebuildManagedPackageFact's
// bounded read-and-parse loop. Its caller must verify the complete identity
// across both steps; this bare read is not standalone content authentication.
func readPackageFactSource(ctx context.Context, opened *rootedRegularFile, object state.PackageObject) error {
	if _, err := opened.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hash := sha256.New()
	read, err := io.Copy(hash, &managedContextReader{ctx: ctx, reader: opened.file})
	workmetrics.RecordFullPackageRead(ctx, read)
	if err != nil {
		return err
	}
	if read != object.Size || hex.EncodeToString(hash.Sum(nil)) != object.SHA256 {
		return errors.New("package bytes differ from immutable object")
	}
	return nil
}
