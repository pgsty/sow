package managed

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

// Built membership under the current authentication contract records successful
// verification under these exact certificate snapshots. The public snapshot
// separately authenticates the immutable bytes. Legacy/imported generations or
// changed policies fall back to verification once, with the configured workers.
func prepareRPMBuildAuthorizations(ctx context.Context, root, repo string, cfg config.Config, dists []string, manifest mutationManifest, store *state.Store, policy rpmSigningPolicy, projected []mutationBuildDist, current *publicGenerationSnapshot, preparedInputs bool, jobs int) (map[string]rootedRegularIdentity, error) {
	if policy.mode == "never" {
		return nil, ctx.Err()
	}
	wanted := map[string]bool{}
	rpmDists := []string{}
	for _, name := range dists {
		if cfg.Repositories[repo].Dists[name].Format != "rpm" {
			continue
		}
		rpmDists = append(rpmDists, name)
		for _, digest := range manifest.Desired[name] {
			wanted[digest] = true
		}
	}
	if len(wanted) == 0 {
		return nil, ctx.Err()
	}
	objects, err := store.ListPackageObjects(ctx, rpmDists, false)
	if err != nil {
		return nil, err
	}
	bySHA := make(map[string]state.PackageObject, len(objects)+len(manifest.Objects))
	for _, object := range objects {
		if wanted[object.SHA256] {
			bySHA[object.SHA256] = object
		}
	}
	proofs := map[string]rootedRegularIdentity{}
	eligibleDists := map[string]bool{}
	if current != nil {
		generationTimes := map[state.GenerationID]time.Time{}
		for _, planned := range projected {
			if cfg.Repositories[repo].Dists[planned.Name].Format != "rpm" {
				continue
			}
			built, err := store.GetDist(ctx, planned.Name)
			if err != nil {
				return nil, err
			}
			if built.EffectiveConfigSHA256 != planned.EffectiveConfigSHA256 || built.BuiltGeneration == 0 {
				continue
			}
			at, ok := generationTimes[built.BuiltGeneration]
			if !ok {
				generation, err := store.GetGeneration(ctx, built.BuiltGeneration)
				if err != nil {
					return nil, err
				}
				at = generation.CreatedAt
				generationTimes[built.BuiltGeneration] = at
			}
			// A clock rollback can invalidate the verifier's future-signature rule.
			eligibleDists[planned.Name] = !at.IsZero() && !at.After(time.Now().UTC())
		}
		for _, object := range bySHA {
			if object.Storage != "pool" {
				continue
			}
			identity, ok := current.Identities[object.PoolPath]
			if !ok || !identity.valid(object.Size) {
				continue
			}
			for _, dist := range object.BuiltDists {
				if eligibleDists[dist] {
					proofs[object.SHA256] = identity
					break
				}
			}
		}
	}
	for _, object := range manifest.Objects {
		if !wanted[object.SHA256] {
			continue
		}
		if preparedInputs {
			// Add installs and authenticates the already-authorized staged bytes
			// after preflight, then records the final pending file identity.
			delete(wanted, object.SHA256)
			continue
		}
		bySHA[object.SHA256] = object
	}

	objects = objects[:0]
	for digest := range wanted {
		object, ok := bySHA[digest]
		if !ok {
			// An existing object may be newly added from an unselected Dist.
			// Only these new memberships need an individual metadata lookup.
			object, err = store.GetPackageObject(ctx, digest)
			if err != nil {
				return nil, err
			}
		}
		objects = append(objects, object)
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].SHA256 < objects[j].SHA256 })
	return authorizeBuildRPMObjects(ctx, root, repo, objects, policy, jobs, proofs)
}

// Proofs live only within a single preflight/policy. A rooted stat check guards
// reuse between preflight and rendering without a second payload read.
func authorizeBuildRPMObjects(ctx context.Context, root, repo string, objects []state.PackageObject, policy rpmSigningPolicy, jobs int, prior map[string]rootedRegularIdentity) (map[string]rootedRegularIdentity, error) {
	if policy.mode == "never" {
		return nil, ctx.Err()
	}
	jobs = min(max(jobs, 1), len(objects))
	identities := make([]rootedRegularIdentity, len(objects))
	issues := make([]error, len(objects))
	indices := make(chan int)
	var group sync.WaitGroup
	for range jobs {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range indices {
				object := objects[index]
				if err := ctx.Err(); err != nil {
					issues[index] = err
					continue
				}
				if object.Format != "rpm" {
					issues[index] = fmt.Errorf("%w: non-RPM object reached RPM authorization", ErrIntegrity)
					continue
				}
				source, err := availableManagedPackageSource(root, repo, object)
				if err != nil {
					issues[index] = err
					continue
				}
				opened, err := source.open()
				if err != nil {
					issues[index] = err
					continue
				}
				identity, err := snapshotRootedRegularIdentity(opened)
				if err == nil {
					previous, ok := prior[object.SHA256]
					if !ok || !previous.valid(object.Size) || !previous.sameContentStat(identity) {
						if verifyErr := policy.authorizeDesiredReader(ctx, opened.file); verifyErr != nil {
							err = fmt.Errorf("%w: %w: immutable RPM %s does not satisfy package signing mode %s: %v", ErrRejected, errImmutableRPMSigningPolicy, object.SHA256, policy.mode, verifyErr)
							if ctx.Err() != nil {
								err = ctx.Err()
							}
						}
					}
				}
				issues[index] = errors.Join(err, opened.CloseVerified())
				identities[index] = identity
			}
		}()
	}
	for index := range objects {
		indices <- index
	}
	close(indices)
	group.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make(map[string]rootedRegularIdentity, len(objects))
	for i, object := range objects {
		if issues[i] != nil {
			return nil, issues[i]
		}
		result[object.SHA256] = identities[i]
	}
	return result, nil
}

// Installation authenticates the staged digest before renaming it to pending.
// Record the final identity after rename/chmod, which can change ctime.
func rememberRPMBuildAuthorization(root, repo string, object state.PackageObject, preflight *mutationBuildPreflight) error {
	if preflight == nil || preflight.rpmPolicy.mode == "never" || object.Format != "rpm" {
		return nil
	}
	source, err := availableManagedPackageSource(root, repo, object)
	if err != nil {
		return err
	}
	opened, err := source.open()
	if err != nil {
		return err
	}
	identity, statErr := snapshotRootedRegularIdentity(opened)
	if err := errors.Join(statErr, opened.CloseVerified()); err != nil {
		return err
	}
	if preflight.rpmAuthorizations == nil {
		preflight.rpmAuthorizations = map[string]rootedRegularIdentity{}
	}
	preflight.rpmAuthorizations[object.SHA256] = identity
	return nil
}
