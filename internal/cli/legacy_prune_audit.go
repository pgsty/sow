package cli

import (
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/state"
)

type legacyIndexPruneAuditStats struct {
	Ledgers          int
	Receipts         int64
	ConfirmationSets int
}

// auditCanonicalLegacyIndexPruneLedgers binds every current negative receipt
// back to an ancestor M0 manifest and recomputes the complete confirmation
// set. It is deliberately independent of repo selectors: a digest may span
// several per-repo ledgers committed by one adoption transaction.
func auditCanonicalLegacyIndexPruneLedgers(canonical *state.Store) (legacyIndexPruneAuditStats, error) {
	var stats legacyIndexPruneAuditStats
	if canonical == nil {
		return stats, errors.New("canonical state is unavailable for legacy prune audit")
	}
	head, err := canonical.HeadHash()
	if err != nil {
		return stats, err
	}
	if head.IsZero() {
		return stats, nil
	}
	if err := auditLegacyIndexPruneLedgerHistory(canonical, head); err != nil {
		return stats, err
	}
	files, err := canonical.ListFilesAt(head, "provenance/legacy-pruned/")
	if err != nil {
		return stats, err
	}
	groups := make(map[string][]provenance.LegacyIndexPruneIdentity)
	for _, canonicalPath := range files {
		repo, err := legacyIndexPruneRepoFromPath(canonicalPath)
		if err != nil {
			return stats, err
		}
		reader, err := canonical.OpenPathAt(head, canonicalPath)
		if err != nil {
			return stats, err
		}
		ledger := provenance.NewLegacyIndexPruneReader(reader)
		var receipts []provenance.LegacyIndexPruneReceipt
		for {
			receipt, readErr := ledger.Next()
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = reader.Close()
				return stats, fmt.Errorf("%s: %w", canonicalPath, readErr)
			}
			if receipt.Repo != repo {
				_ = reader.Close()
				return stats, fmt.Errorf("%s contains receipt for repo %q", canonicalPath, receipt.Repo)
			}
			if len(receipts) != 0 && (receipt.BaselineCommit != receipts[0].BaselineCommit ||
				!receipt.RecordedAt.Equal(receipts[0].RecordedAt) || receipt.ConfirmationSHA256 != receipts[0].ConfirmationSHA256) {
				_ = reader.Close()
				return stats, fmt.Errorf("%s mixes baseline, time, or confirmation identities", canonicalPath)
			}
			receipts = append(receipts, receipt)
			groups[receipt.ConfirmationSHA256] = append(groups[receipt.ConfirmationSHA256], receipt.Identity())
		}
		if err := reader.Close(); err != nil {
			return stats, err
		}
		if len(receipts) == 0 {
			return stats, fmt.Errorf("%s is an empty legacy prune ledger", canonicalPath)
		}
		baseline := plumbing.NewHash(receipts[0].BaselineCommit)
		reachable, err := canonical.IsAncestor(baseline, head)
		if err != nil || !reachable {
			return stats, errors.Join(err, fmt.Errorf("%s baseline commit %s is not an ancestor of HEAD", canonicalPath, baseline))
		}
		repoRef, err := state.RepoRef(repo)
		if err != nil {
			return stats, err
		}
		currentRepo, exists, err := canonical.Ref(repoRef)
		if err != nil || !exists {
			return stats, errors.Join(err, fmt.Errorf("%s has no current repository ref %s", canonicalPath, repoRef))
		}
		reachable, err = canonical.IsAncestor(baseline, currentRepo)
		if err != nil || !reachable {
			return stats, errors.Join(err, fmt.Errorf("%s baseline commit %s is not an ancestor of repository ref %s at %s", canonicalPath, baseline, repoRef, currentRepo))
		}
		baselineTime, err := canonical.CommitTime(baseline)
		if err != nil || !baselineTime.Equal(receipts[0].RecordedAt) {
			return stats, errors.Join(err, fmt.Errorf("%s recorded_at %s does not bind baseline commit time %s", canonicalPath, receipts[0].RecordedAt.Format(time.RFC3339Nano), baselineTime.Format(time.RFC3339Nano)))
		}
		baselineReader, err := canonical.OpenPathAt(baseline, path.Join("manifests", repo+".tsv"))
		if err != nil {
			return stats, fmt.Errorf("%s baseline manifest: %w", canonicalPath, err)
		}
		missing := make(map[string]struct{}, len(receipts))
		for _, receipt := range receipts {
			missing[receipt.Path] = struct{}{}
		}
		manifestReader := manifest.NewReader(baselineReader)
		for {
			entry, readErr := manifestReader.Next()
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = baselineReader.Close()
				return stats, fmt.Errorf("%s baseline manifest: %w", canonicalPath, readErr)
			}
			if _, exists := missing[entry.Path]; exists {
				_ = baselineReader.Close()
				return stats, fmt.Errorf("%s claims baseline-present body %s was missing", canonicalPath, entry.Path)
			}
		}
		if err := baselineReader.Close(); err != nil {
			return stats, err
		}
		stats.Ledgers++
		stats.Receipts += int64(len(receipts))
	}
	for confirmation, identities := range groups {
		actual, err := provenance.LegacyIndexPruneSetSHA256(identities)
		if err != nil {
			return stats, err
		}
		if actual != confirmation {
			return stats, fmt.Errorf("legacy prune confirmation set differs: recorded=%s actual=%s entries=%d", confirmation, actual, len(identities))
		}
		stats.ConfirmationSets++
	}
	return stats, nil
}

// auditLegacyIndexPruneLedgerHistory makes negative provenance permanent.
// Checking only HEAD would let a later commit delete or replace the ledger and
// thereby erase why signed replacement metadata omitted a legacy index entry.
// Blob identities keep the history walk bounded without inflating unchanged
// ledgers at every commit.
func auditLegacyIndexPruneLedgerHistory(canonical *state.Store, head plumbing.Hash) error {
	const prefix = "provenance/legacy-pruned/"
	history, err := canonical.ReachableCommits()
	if err != nil {
		return err
	}
	historical := make(map[string]state.BlobIdentity)
	for _, commit := range history {
		if err := canonical.ForEachFileAt(commit, prefix, func(canonicalPath string) error {
			if _, err := legacyIndexPruneRepoFromPath(canonicalPath); err != nil {
				return err
			}
			identity, exists, err := canonical.BlobIdentityAt(commit, canonicalPath)
			if err != nil || !exists {
				return errors.Join(err, fmt.Errorf("historical legacy prune ledger %s disappeared at %s", canonicalPath, commit))
			}
			if prior, exists := historical[canonicalPath]; exists && prior != identity {
				return fmt.Errorf("legacy prune ledger %s changed across canonical history", canonicalPath)
			}
			historical[canonicalPath] = identity
			return nil
		}); err != nil {
			return err
		}
	}
	for canonicalPath, want := range historical {
		got, exists, err := canonical.BlobIdentityAt(head, canonicalPath)
		if err != nil || !exists {
			return errors.Join(err, fmt.Errorf("historical legacy prune ledger %s was deleted from HEAD", canonicalPath))
		}
		if got != want {
			return fmt.Errorf("historical legacy prune ledger %s differs at HEAD", canonicalPath)
		}
	}
	return nil
}

func legacyIndexPruneRepoFromPath(canonicalPath string) (string, error) {
	const prefix = "provenance/legacy-pruned/"
	if !strings.HasPrefix(canonicalPath, prefix) || !strings.HasSuffix(canonicalPath, ".jsonl") {
		return "", fmt.Errorf("unexpected canonical legacy prune path %q", canonicalPath)
	}
	repo := strings.TrimSuffix(strings.TrimPrefix(canonicalPath, prefix), ".jsonl")
	if repo == "" || strings.Contains(repo, "/") {
		return "", fmt.Errorf("invalid canonical legacy prune repo path %q", canonicalPath)
	}
	return repo, nil
}
