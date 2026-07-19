package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

// auditYUMCompatibilityLocal proves the complete local compatibility closure:
// immutable witness/ref, streamed witness SHA-256, exact physical tree,
// canonical Packages plus flat aliases sharing the same CAS inode, package
// signatures, and one exact signed gzip primary/filelists/other generation.
func auditYUMCompatibilityLocal(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, projection config.YUMCompatibilityProjection, txDir string, verifier yumrepo.DetachedVerifier, workers int) error {
	if ctx == nil || cfg == nil || canonical == nil || pool == nil || verifier == nil {
		return errors.New("incomplete YUM compatibility audit dependencies")
	}
	witnessPath, err := state.YUMCompatibilityProjectionPath(projection.ID)
	if err != nil {
		return err
	}
	witnessBody, exists, err := readOptionalCanonical(canonical, witnessPath)
	if err != nil || !exists {
		return errors.Join(err, fmt.Errorf("compatibility witness %s is missing", witnessPath))
	}
	witness, err := decodeYUMCompatibilityWitness(witnessBody)
	if err != nil {
		return err
	}
	if err := requireYUMCompatibilityWitnessMatchesProjection(witness, projection); err != nil {
		return err
	}
	admission, err := admitYUMCompatibilityProjection(cfg, canonical, projection)
	if err != nil {
		return err
	}
	trust, err := stageYUMCompatibilityPackageTrust(cfg, canonical, admission, txDir)
	if err != nil {
		return err
	}
	packageKeyring := trust.keyring
	compatRef, err := state.YUMCompatibilityRef(projection.ID)
	if err != nil {
		return err
	}
	pinned, exists, err := canonical.Ref(compatRef)
	if err != nil || !exists || pinned.String() != witness.SourceCommit {
		return errors.Join(err, fmt.Errorf("compatibility ref %s does not pin witness source %s", compatRef, witness.SourceCommit))
	}

	manifestPath, err := state.YUMCompatibilityManifestPath(projection.ID)
	if err != nil {
		return err
	}
	reader, err := canonical.OpenPath(manifestPath)
	if err != nil {
		return err
	}
	stagedManifest := filepath.Join(txDir, "yum-compat-audit-"+projection.ID+".tsv")
	staged, err := os.OpenFile(stagedManifest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		reader.Close()
		return err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(staged, hasher), reader)
	closeErr := errors.Join(reader.Close(), staged.Sync(), staged.Close())
	if copyErr != nil || closeErr != nil || written != witness.PayloadManifestLen || hex.EncodeToString(hasher.Sum(nil)) != witness.PayloadManifestSHA {
		return errors.Join(copyErr, closeErr, errors.New("compatibility witness manifest content SHA-256/size mismatch"))
	}

	physicalRoot := filepath.Join(cfg.Root, filepath.FromSlash(projection.Root))
	packagesManifest := filepath.Join(txDir, "yum-compat-packages-"+projection.ID+".tsv")
	packagesOut, err := os.OpenFile(packagesManifest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	manifestFile, err := os.Open(stagedManifest)
	if err != nil {
		packagesOut.Close()
		return err
	}
	stream := manifest.NewReader(manifestFile)
	prefix := strings.TrimSuffix(projection.Root, "/") + "/"
	var packages, aliases, bytesTotal int64
	for {
		entry, nextErr := stream.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			manifestFile.Close()
			packagesOut.Close()
			return nextErr
		}
		if !strings.HasPrefix(entry.Path, prefix) {
			manifestFile.Close()
			packagesOut.Close()
			return fmt.Errorf("compatibility manifest path %q escapes root %s", entry.Path, projection.Root)
		}
		relative := strings.TrimPrefix(entry.Path, prefix)
		physical := filepath.Join(physicalRoot, filepath.FromSlash(relative))
		physicalInfo, err := os.Lstat(physical)
		if err != nil || physicalInfo.Mode()&os.ModeSymlink != 0 || !physicalInfo.Mode().IsRegular() || physicalInfo.Size() != entry.Size {
			manifestFile.Close()
			packagesOut.Close()
			return errors.Join(err, fmt.Errorf("compatibility payload %s is absent, unsafe, or changed", relative))
		}
		sha, size, err := fileSHA256AndSize(physical)
		if err != nil || sha != entry.HashString() || size != entry.Size {
			manifestFile.Close()
			packagesOut.Close()
			return errors.Join(err, fmt.Errorf("compatibility payload %s differs from witness", relative))
		}
		digest, err := repository.ParseDigest(entry.HashString())
		if err != nil {
			manifestFile.Close()
			packagesOut.Close()
			return err
		}
		casInfo, err := os.Lstat(pool.ObjectPath(digest))
		if err != nil || casInfo.Mode()&os.ModeSymlink != 0 || !casInfo.Mode().IsRegular() || casInfo.Size() != entry.Size || !os.SameFile(physicalInfo, casInfo) {
			manifestFile.Close()
			packagesOut.Close()
			return errors.Join(err, fmt.Errorf("compatibility payload %s is not the witnessed CAS hardlink", relative))
		}
		parts := strings.Split(relative, "/")
		switch {
		case len(parts) == 3 && parts[0] == "Packages" && len(parts[1]) == 1 && path.Base(relative) == parts[2] && strings.HasSuffix(parts[2], ".rpm"):
			packages++
			bytesTotal += entry.Size
			aliasInfo, err := os.Lstat(filepath.Join(physicalRoot, parts[2]))
			if err != nil || aliasInfo.Mode()&os.ModeSymlink != 0 || !aliasInfo.Mode().IsRegular() || !os.SameFile(physicalInfo, aliasInfo) {
				manifestFile.Close()
				packagesOut.Close()
				return errors.Join(err, fmt.Errorf("compatibility flat alias %s is missing or not the Packages hardlink", parts[2]))
			}
			entry.Path = relative
			if err := manifest.WriteEntry(packagesOut, entry); err != nil {
				manifestFile.Close()
				packagesOut.Close()
				return err
			}
		case len(parts) == 1 && path.Base(relative) == relative && strings.HasSuffix(relative, ".rpm"):
			aliases++
		default:
			manifestFile.Close()
			packagesOut.Close()
			return fmt.Errorf("compatibility witness contains unsupported payload path %q", relative)
		}
	}
	closeErr = errors.Join(manifestFile.Close(), packagesOut.Sync(), packagesOut.Close())
	if closeErr != nil {
		return closeErr
	}
	if packages != witness.Packages || aliases != witness.Packages || bytesTotal != witness.Bytes {
		return fmt.Errorf("compatibility witness counts differ: packages=%d aliases=%d bytes=%d witness=%d/%d", packages, aliases, bytesTotal, witness.Packages, witness.Bytes)
	}
	if err := auditYUMCompatibilityTreeShape(ctx, physicalRoot, packages, aliases); err != nil {
		return err
	}
	generation, err := yumrepo.ValidateDirectory(ctx, filepath.Join(physicalRoot, "repodata"), yumrepo.CompressionGzip, verifier)
	if err != nil || generation == nil || generation.Packages != packages {
		return errors.Join(err, fmt.Errorf("compatibility repodata package count differs: metadata=%d witness=%d", generationPackageCount(generation), packages))
	}
	if err := verifyYUMPackageManifest(ctx, packagesManifest, physicalRoot, packageKeyring, time.Now().UTC(), workers); err != nil {
		return fmt.Errorf("compatibility RPM package trust: %w", err)
	}
	return nil
}

func generationPackageCount(generation *yumrepo.Generation) int64 {
	if generation == nil {
		return -1
	}
	return generation.Packages
}

func auditYUMCompatibilityTreeShape(ctx context.Context, root string, wantPackages, wantAliases int64) error {
	var packages, aliases int64
	err := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("unsafe compatibility tree entry %s", relative))
		}
		parts := strings.Split(relative, "/")
		if info.IsDir() {
			if relative == "." || relative == "Packages" || relative == "repodata" || len(parts) == 2 && parts[0] == "Packages" && len(parts[1]) == 1 {
				return nil
			}
			return fmt.Errorf("unexpected compatibility directory %s", relative)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("special compatibility tree entry %s", relative)
		}
		switch {
		case strings.HasPrefix(relative, "repodata/") && len(parts) == 2:
			return nil
		case len(parts) == 3 && parts[0] == "Packages" && len(parts[1]) == 1 && strings.HasSuffix(parts[2], ".rpm"):
			packages++
			return nil
		case len(parts) == 1 && strings.HasSuffix(relative, ".rpm"):
			aliases++
			return nil
		default:
			return fmt.Errorf("unexpected compatibility tree file %s", relative)
		}
	})
	if err != nil {
		return err
	}
	if packages != wantPackages || aliases != wantAliases {
		return fmt.Errorf("compatibility physical counts differ: packages=%d aliases=%d want=%d/%d", packages, aliases, wantPackages, wantAliases)
	}
	return nil
}
