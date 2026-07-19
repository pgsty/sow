package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

// validateFrozenCompatibilityTree is the local protocol gate shared by
// ordinary publication staging and historical reconstruction. Manifest shape
// is not enough: the exact CAS bytes must form a valid gzip RPM-MD repository,
// repomd must verify under the publication-bound repository key identity, and
// every canonical RPM must verify under the S1-pinned package trust bytes.
func validateFrozenCompatibilityTree(ctx context.Context, cfg *config.Config, canonical *state.Store, identity pub.CompatibilityState, physicalRoot, tempDir string, workers, chunkEntries int) error {
	if ctx == nil || cfg == nil || canonical == nil || identity.ID == "" || physicalRoot == "" {
		return errors.New("frozen compatibility protocol validation dependencies are unavailable")
	}
	freezeCommit := plumbing.NewHash(identity.FreezeCommit)
	if freezeCommit.IsZero() {
		return fmt.Errorf("compatibility %s has no frozen preservation commit", identity.ID)
	}
	_, repositoryPackets, err := loadRepositoryPublicTrustAnchor(cfg.Path, cfg.GPG.PublicKey)
	if err != nil {
		return fmt.Errorf("load compatibility repository trust: %w", err)
	}
	if digest := repositoryTrustAnchorDigest(repositoryPackets); digest != identity.RepositoryKeySHA256 {
		return fmt.Errorf("compatibility %s repository trust identity=%s want=%s", identity.ID, digest, identity.RepositoryKeySHA256)
	}
	verificationTime := timeNowUTC()
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(repositoryPackets), verificationTime)
	if err != nil {
		return err
	}
	generation, err := yumrepo.ValidateDirectory(ctx, filepath.Join(physicalRoot, "repodata"), yumrepo.CompressionGzip, verifier)
	if err != nil || !yumGenerationMatches(generation, identity.RepomdSHA256, -1) {
		return errors.Join(err, fmt.Errorf("compatibility %s signed gzip metadata repomd identity changed", identity.ID))
	}

	receiptPath, err := state.YUMCompatibilityCandidateReceiptPath(identity.ID)
	if err != nil {
		return err
	}
	receiptBody, exists, err := readCanonicalBytesAt(canonical, freezeCommit, receiptPath, maximumYUMCompatibilityWitnessBytes)
	if err != nil || !exists {
		return errors.Join(err, fmt.Errorf("compatibility %s frozen candidate receipt is missing", identity.ID))
	}
	receipt, err := decodeYUMCompatibilityCandidate(receiptBody)
	if err != nil || receipt.ID != identity.ID || receipt.RepomdSHA256 != identity.RepomdSHA256 || receipt.RepositoryKeySHA256 != identity.RepositoryKeySHA256 {
		return errors.Join(err, fmt.Errorf("compatibility %s frozen candidate receipt differs from publication identity", identity.ID))
	}
	confirmation, err := yumCompatibilityConfirmation("freeze", receipt)
	if err != nil || confirmation != receipt.FreezeConfirm {
		return errors.Join(err, fmt.Errorf("compatibility %s frozen candidate receipt confirmation changed", identity.ID))
	}
	if generation.Packages != receipt.Packages {
		return fmt.Errorf("compatibility %s metadata packages=%d want=%d", identity.ID, generation.Packages, receipt.Packages)
	}

	packageKeyring, err := loadFrozenCompatibilityPackageKeyring(canonical, identity)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(tempDir, 0o700); err != nil {
		return err
	}
	packageManifest := filepath.Join(tempDir, "compatibility-"+identity.ID+"-packages.tsv")
	_ = os.Remove(packageManifest)
	stats, err := manifest.Scan(ctx, physicalRoot, manifest.Scope{Path: ".", Include: []string{"Packages/**"}}, packageManifest, manifest.ScanOptions{
		Workers: workers, ChunkEntries: chunkEntries, TempDir: tempDir,
	})
	if err != nil {
		return err
	}
	defer os.Remove(packageManifest)
	if stats.Files != receipt.Packages || stats.Bytes != receipt.Bytes {
		return fmt.Errorf("compatibility %s canonical RPM set=%d/%d want=%d/%d", identity.ID, stats.Files, stats.Bytes, receipt.Packages, receipt.Bytes)
	}
	if err := verifyYUMPackageManifest(ctx, packageManifest, physicalRoot, packageKeyring, verificationTime, workers); err != nil {
		return fmt.Errorf("compatibility %s frozen RPM package trust: %w", identity.ID, err)
	}
	return nil
}
