package managed

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/state"
)

// This applies only before creating a new attempt. Frozen publication attempts
// keep their original contract. Only the three small signature metadata files
// are read; package payloads and APT indexes are not scanned again.
func validateNewAPTPublicationMetadata(ctx context.Context, repositoryRoot string, store *state.Store) error {
	dists, err := store.ListDists(ctx)
	if err != nil {
		return err
	}
	for _, dist := range dists {
		if dist.Format != "deb" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		identity, _, signed, err := builtMetadataIdentityAndTime(ctx, store, dist)
		if err != nil {
			return err
		}
		if !signed {
			continue
		}
		verifier, err := aptrepo.NewVerifierBytes(identity.PublicKey)
		if err != nil {
			return err
		}
		metadata := make([][]byte, 3)
		for i, name := range []string{"Release", "InRelease", "Release.gpg"} {
			metadata[i], err = readRootedRegular(repositoryRoot, filepath.ToSlash(filepath.Join("dists", dist.Name, name)), 16<<20, false)
			if err != nil {
				return err
			}
		}
		at, err := parseReleaseDate(metadata[0])
		if err != nil {
			return err
		}
		if err := verifier.VerifyForPublication(metadata[0], metadata[1], metadata[2], at); err != nil {
			return fmt.Errorf("%w: Dist %s APT metadata is not suitable for a new publication: %v", ErrRejected, dist.Name, err)
		}
	}
	return nil
}
