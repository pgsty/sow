package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

const materializedRouteReceiptMaxBytes = 1 << 20

type materializedRouteLedger struct {
	Receipt              serving.MaterializedRoute
	ReceiptPath          string
	ExactCanonicalPath   string
	PayloadCanonicalPath string
	ExactManifest        string
	PayloadManifest      string
}

// stageMaterializedRouteLedger copies an already-derived receipt and its exact
// frozen manifest inputs into a private transaction directory. The returned
// map is directly consumable by state.Store.Apply/InstallPaths. It never scans
// the physical serving tree: callers must build exactPath from canonical view
// manifests plus freshly generated metadata, rather than canonizing whatever
// happens to be present under the Nginx root.
func stageMaterializedRouteLedger(stageDir string, receipt serving.MaterializedRoute, exactPath, payloadPath string) (staged map[string]string, resultErr error) {
	if err := receipt.Validate(); err != nil {
		return nil, err
	}
	if stageDir == "" {
		return nil, errors.New("materialized route ledger stage directory is empty")
	}
	receiptPath, exactCanonical, payloadCanonical, err := materializedRouteLedgerPaths(receipt)
	if err != nil {
		return nil, err
	}
	routeDir, err := os.MkdirTemp(stageDir, "materialized-route-"+receipt.ID[:12]+"-")
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, os.RemoveAll(routeDir))
		}
	}()
	receiptStage := filepath.Join(routeDir, "receipt.json")
	exactStage := filepath.Join(routeDir, "exact.tsv")
	payloadStage := filepath.Join(routeDir, "payload.tsv")
	body, err := receipt.Canonical()
	if err != nil {
		return nil, err
	}
	if err := manifest.AtomicCopy(receiptStage, bytes.NewReader(body), 0o600); err != nil {
		return nil, err
	}
	if err := stageMaterializedRouteManifest(exactPath, exactStage, receipt.ExactManifestSHA256); err != nil {
		return nil, fmt.Errorf("stage exact materialized route manifest: %w", err)
	}
	if err := stageMaterializedRouteManifest(payloadPath, payloadStage, receipt.PayloadManifestSHA256); err != nil {
		return nil, fmt.Errorf("stage payload materialized route manifest: %w", err)
	}
	keep = true
	return map[string]string{
		receiptPath: receiptStage, exactCanonical: exactStage, payloadCanonical: payloadStage,
	}, nil
}

func materializedRouteLedgerPaths(receipt serving.MaterializedRoute) (receiptPath, exactPath, payloadPath string, err error) {
	receiptPath, err = serving.MaterializedRouteReceiptStatePath(receipt)
	if err != nil {
		return "", "", "", err
	}
	exactPath, err = serving.MaterializedRouteExactManifestStatePath(receipt)
	if err != nil {
		return "", "", "", err
	}
	payloadPath, err = serving.MaterializedRoutePayloadManifestStatePath(receipt)
	if err != nil {
		return "", "", "", err
	}
	return receiptPath, exactPath, payloadPath, nil
}

func stageMaterializedRouteManifest(sourcePath, destination, wantSHA256 string) (resultErr error) {
	before, err := os.Lstat(sourcePath)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return errors.Join(err, errors.New("materialized route manifest source is not a regular non-symlink file"))
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, source.Close()) }()
	opened, statErr := source.Stat()
	afterOpen, lstatErr := os.Lstat(sourcePath)
	if statErr != nil || lstatErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, afterOpen) {
		return errors.Join(statErr, lstatErr, errors.New("materialized route manifest source changed while opening"))
	}
	if err := serving.VerifyMaterializedRouteManifest(source, wantSHA256); err != nil {
		return err
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := manifest.AtomicCopy(destination, source, 0o600); err != nil {
		return err
	}
	staged, err := os.Open(destination)
	if err != nil {
		return err
	}
	stagedInfo, statErr := staged.Stat()
	stagedVerifyErr := serving.VerifyMaterializedRouteManifest(staged, wantSHA256)
	stagedCloseErr := staged.Close()
	if statErr != nil || stagedVerifyErr != nil || stagedCloseErr != nil || !stagedInfo.Mode().IsRegular() || stagedInfo.Mode().Perm() != 0o600 {
		return errors.Join(statErr, stagedVerifyErr, stagedCloseErr, errors.New("staged materialized route manifest differs or has unsafe permissions"))
	}
	last, statErr := source.Stat()
	coordinate, coordinateErr := os.Lstat(sourcePath)
	if statErr != nil || coordinateErr != nil || !os.SameFile(opened, last) || !os.SameFile(opened, coordinate) {
		return errors.Join(statErr, coordinateErr, errors.New("materialized route manifest source changed while staging"))
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return serving.VerifyMaterializedRouteManifest(source, wantSHA256)
}

// loadMaterializedRouteLedgerAt copies one canonical receipt triple at an
// exact commit into private local files. Canonical decoding, stable state-path
// identity, and both manifest digests are checked before anything is returned
// to Nginx admission.
func loadMaterializedRouteLedgerAt(canonical *state.Store, commit plumbing.Hash, receiptPath, stageDir string) (ledger materializedRouteLedger, resultErr error) {
	if canonical == nil || commit.IsZero() || !serving.IsMaterializedRouteReceiptStatePath(receiptPath) || stageDir == "" {
		return ledger, errors.New("invalid materialized route ledger load input")
	}
	body, exists, err := readCanonicalBytesAt(canonical, commit, receiptPath, materializedRouteReceiptMaxBytes)
	if err != nil || !exists {
		return ledger, errors.Join(err, fmt.Errorf("canonical materialized route receipt %s is absent", receiptPath))
	}
	receipt, err := serving.DecodeMaterializedRoute(body)
	if err != nil {
		return ledger, fmt.Errorf("decode canonical materialized route receipt %s: %w", receiptPath, err)
	}
	wantReceipt, exactCanonical, payloadCanonical, err := materializedRouteLedgerPaths(receipt)
	if err != nil || wantReceipt != receiptPath {
		return ledger, errors.Join(err, errors.New("canonical materialized route receipt is stored at the wrong identity path"))
	}
	routeDir, err := os.MkdirTemp(stageDir, "loaded-materialized-route-"+receipt.ID[:12]+"-")
	if err != nil {
		return ledger, err
	}
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, os.RemoveAll(routeDir))
		}
	}()
	exactLocal := filepath.Join(routeDir, "exact.tsv")
	payloadLocal := filepath.Join(routeDir, "payload.tsv")
	if err := copyCanonicalMaterializedRouteManifest(canonical, commit, exactCanonical, exactLocal, receipt.ExactManifestSHA256); err != nil {
		return ledger, err
	}
	if err := copyCanonicalMaterializedRouteManifest(canonical, commit, payloadCanonical, payloadLocal, receipt.PayloadManifestSHA256); err != nil {
		return ledger, err
	}
	keep = true
	return materializedRouteLedger{
		Receipt: receipt, ReceiptPath: receiptPath, ExactCanonicalPath: exactCanonical,
		PayloadCanonicalPath: payloadCanonical, ExactManifest: exactLocal, PayloadManifest: payloadLocal,
	}, nil
}

func copyCanonicalMaterializedRouteManifest(canonical *state.Store, commit plumbing.Hash, canonicalPath, localPath, wantSHA256 string) error {
	reader, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return fmt.Errorf("open canonical materialized route manifest %s: %w", canonicalPath, err)
	}
	copyErr := manifest.AtomicCopy(localPath, reader, 0o600)
	closeErr := reader.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	local, err := os.Open(localPath)
	if err != nil {
		return err
	}
	verifyErr := serving.VerifyMaterializedRouteManifest(local, wantSHA256)
	return errors.Join(verifyErr, local.Close())
}

// loadMaterializedRouteLedgersAt enumerates one target/view partition and
// rejects orphan or unknown files instead of silently ignoring a partial
// receipt triple.
func loadMaterializedRouteLedgersAt(canonical *state.Store, commit plumbing.Hash, targetSHA256, view, stageDir string) ([]materializedRouteLedger, error) {
	prefix, err := serving.MaterializedRouteStatePrefix(targetSHA256, view)
	if err != nil {
		return nil, err
	}
	files, err := canonical.ListFilesAt(commit, prefix)
	if err != nil {
		return nil, err
	}
	return loadMaterializedRouteLedgersFromFilesAt(canonical, commit, files, stageDir)
}

// loadMaterializedRouteLedgersFromFilesAt validates one already-enumerated
// partition. Full fsck uses this form after a single canonical tree walk so N
// route partitions do not trigger N additional whole-tree scans.
func loadMaterializedRouteLedgersFromFilesAt(canonical *state.Store, commit plumbing.Hash, files []string, stageDir string) ([]materializedRouteLedger, error) {
	var receiptPaths []string
	for _, name := range files {
		if serving.IsMaterializedRouteReceiptStatePath(name) {
			receiptPaths = append(receiptPaths, name)
		}
	}
	sort.Strings(receiptPaths)
	ledgers := make([]materializedRouteLedger, 0, len(receiptPaths))
	expected := make(map[string]struct{}, len(receiptPaths)*3)
	for _, receiptPath := range receiptPaths {
		ledger, err := loadMaterializedRouteLedgerAt(canonical, commit, receiptPath, stageDir)
		if err != nil {
			return nil, err
		}
		ledgers = append(ledgers, ledger)
		for _, name := range []string{ledger.ReceiptPath, ledger.ExactCanonicalPath, ledger.PayloadCanonicalPath} {
			expected[name] = struct{}{}
		}
	}
	for _, name := range files {
		if _, exists := expected[name]; !exists {
			return nil, fmt.Errorf("orphan or unknown materialized route ledger path %s", name)
		}
	}
	return ledgers, nil
}
