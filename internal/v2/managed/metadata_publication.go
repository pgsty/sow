package managed

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

// This applies only before creating a new attempt. Frozen publication attempts
// keep their original contract. Only the small signature metadata files are
// read; package payloads and repository indexes are not scanned again.
func validateNewAPTPublicationMetadata(ctx context.Context, repositoryRoot string, store *state.Store) error {
	dists, err := store.ListDists(ctx)
	if err != nil {
		return err
	}
	for _, dist := range dists {
		if err := ctx.Err(); err != nil {
			return err
		}
		identity, at, signed, err := builtMetadataIdentityAndTime(ctx, store, dist)
		if err != nil {
			return err
		}
		if !signed {
			continue
		}
		switch dist.Format {
		case "deb":
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
			releaseAt, err := parseReleaseDate(metadata[0])
			if err != nil {
				return err
			}
			if err := verifier.VerifyForPublication(metadata[0], metadata[1], metadata[2], releaseAt); err != nil {
				return fmt.Errorf("%w: Dist %s APT metadata is not suitable for a new publication: %v", ErrRejected, dist.Name, err)
			}
		case "rpm":
			verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(identity.PublicKey), at)
			if err != nil {
				return err
			}
			for _, architecture := range dist.Architectures {
				repodataRel := filepath.ToSlash(filepath.Join("dists", dist.Name, architecture.Family, "repodata"))
				repomd, err := readRootedRegular(repositoryRoot, repodataRel+"/repomd.xml", 16<<20, false)
				if err != nil {
					return err
				}
				signature, err := readRootedRegular(repositoryRoot, repodataRel+"/repomd.xml.asc", 16<<20, false)
				if err != nil {
					return err
				}
				if err := verifier.VerifyForPublication(ctx, bytes.NewReader(repomd), bytes.NewReader(signature)); err != nil {
					return fmt.Errorf("%w: Dist %s/%s RPM metadata is not suitable for a new publication: %v", ErrRejected, dist.Name, architecture.Family, err)
				}
			}
		}
	}
	return nil
}
