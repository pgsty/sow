package cli

import (
	"bytes"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/upstream"
	"github.com/pgsty/sow/internal/yumrepo"
)

const yumCompatibilityWitnessSchema = "sow-yum-compatibility-projection/v2"

var yumCompatibilityWitnessMu sync.Mutex

type yumCompatibilityAdmission struct {
	projection    config.YUMCompatibilityProjection
	repo          config.Repo
	sourceRef     plumbing.ReferenceName
	sourcePath    string
	sourceCommit  plumbing.Hash
	currentCommit plumbing.Hash
	frozen        bool
}

type yumCompatibilityWitness struct {
	Schema             string `json:"schema"`
	ID                 string `json:"id"`
	Root               string `json:"root"`
	Mode               string `json:"mode"`
	Carrier            string `json:"carrier"`
	SourceRepo         string `json:"source_repo"`
	SourceView         string `json:"source_view"`
	SourceOS           string `json:"source_os"`
	SourceArch         string `json:"source_arch"`
	SourceRoot         string `json:"source_root"`
	SourceRef          string `json:"source_ref"`
	SourceCommit       string `json:"source_commit"`
	SourceManifestSHA  string `json:"source_manifest_sha256"`
	SourceManifestGit  string `json:"source_manifest_git_blob"`
	SourceManifestLen  int64  `json:"source_manifest_size"`
	AdoptionSHA        string `json:"adoption_sha256"`
	AdoptionGit        string `json:"adoption_git_blob"`
	AdoptionLen        int64  `json:"adoption_size"`
	PayloadManifestSHA string `json:"payload_manifest_sha256"`
	PayloadManifestGit string `json:"payload_manifest_git_blob"`
	PayloadManifestLen int64  `json:"payload_manifest_size"`
	PackageTrustSHA    string `json:"package_trust_sha256"`
	PackageTrustGit    string `json:"package_trust_git_blob"`
	PackageTrustLen    int64  `json:"package_trust_size"`
	Packages           int64  `json:"packages"`
	Bytes              int64  `json:"bytes"`
	FlatAliases        bool   `json:"flat_aliases"`
}

type yumCompatibilityMaterializeResult struct {
	Projection config.YUMCompatibilityProjection
	Packages   repository.MaterializeStats
	Aliases    repository.MaterializeStats
	Reconciled repository.ReconcileStats
	Generation *yumrepo.Generation
	Target     string
}

// admitYUMCompatibilityProjection proves that the package source is the
// dedicated immutable cross-EL adoption ref. It is never inferred from an
// active per-EL view: the legacy set can legitimately contain mixed release
// tags and an object that merely remains in .git/objects is not sufficient.
func admitYUMCompatibilityProjection(cfg *config.Config, canonical *state.Store, projection config.YUMCompatibilityProjection) (yumCompatibilityAdmission, error) {
	var result yumCompatibilityAdmission
	if cfg == nil || canonical == nil {
		return result, errors.New("YUM compatibility configuration or canonical state is unavailable")
	}
	repo, exists := cfg.RepoByName(projection.Source.Repo)
	if !exists || repo.Type != "yum" || repo.YUM == nil {
		return result, fmt.Errorf("YUM compatibility projection %s owner repo is unavailable", projection.ID)
	}
	ref, err := state.YUMCompatibilitySourceRef(projection.ID)
	if err != nil {
		return result, err
	}
	canonicalPath, err := state.YUMCompatibilitySourcePath(projection.ID)
	if err != nil {
		return result, err
	}
	current, refExists, err := canonical.Ref(ref)
	if err != nil || !refExists {
		return result, errors.Join(err, fmt.Errorf("YUM compatibility adopted source ref %s is missing; run compatibility yum-adopt first", ref))
	}
	witnessEstablished := false
	var pinned plumbing.Hash
	if projection.Source.Commit == config.YUMCompatibilityPinAtFirstFreeze {
		witnessPath, pathErr := state.YUMCompatibilityProjectionPath(projection.ID)
		if pathErr != nil {
			return result, pathErr
		}
		witnessBody, witnessExists, witnessErr := readOptionalCanonical(canonical, witnessPath)
		if witnessErr != nil {
			return result, fmt.Errorf("read YUM compatibility first-freeze witness: %w", witnessErr)
		}
		compatRef, refErr := state.YUMCompatibilityRef(projection.ID)
		if refErr != nil {
			return result, refErr
		}
		_, frozenExists, frozenErr := canonical.Ref(compatRef)
		if frozenErr != nil {
			return result, frozenErr
		}
		if witnessExists {
			witnessEstablished = true
			witness, decodeErr := decodeYUMCompatibilityWitness(witnessBody)
			if decodeErr != nil {
				return result, decodeErr
			}
			if matchErr := requireYUMCompatibilityWitnessMatchesProjection(witness, projection); matchErr != nil {
				return result, matchErr
			}
			pinned = plumbing.NewHash(witness.SourceCommit)
			if !frozenExists {
				return result, fmt.Errorf("YUM compatibility freeze ref %s is missing", compatRef)
			}
		} else {
			if frozenExists {
				return result, fmt.Errorf("YUM compatibility first-freeze ref %s exists without a witness", compatRef)
			}
			// This is the only resolution point for the sentinel. The exact
			// immutable adoption ref is copied into the witness preservation ref.
			pinned = current
		}
	} else {
		pinned = plumbing.NewHash(projection.Source.Commit)
		witnessPath, pathErr := state.YUMCompatibilityProjectionPath(projection.ID)
		if pathErr != nil {
			return result, pathErr
		}
		_, witnessEstablished, err = readOptionalCanonical(canonical, witnessPath)
		if err != nil {
			return result, fmt.Errorf("read YUM compatibility witness: %w", err)
		}
	}
	if pinned != current {
		return result, fmt.Errorf("YUM compatibility projection %s configured source commit differs from immutable adoption ref", projection.ID)
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return result, errors.Join(err, errors.New("canonical HEAD is unavailable for YUM compatibility admission"))
	}
	reachableFromHEAD, err := canonical.IsAncestor(pinned, head)
	if err != nil || !reachableFromHEAD {
		return result, errors.Join(err, fmt.Errorf("YUM compatibility source commit %s is not reachable from canonical HEAD", pinned))
	}
	reader, err := canonical.OpenPathAt(pinned, canonicalPath)
	if err != nil {
		return result, fmt.Errorf("open adopted YUM compatibility source: %w", err)
	}
	if closeErr := reader.Close(); closeErr != nil {
		return result, closeErr
	}
	return yumCompatibilityAdmission{
		projection: projection, repo: repo, sourceRef: ref, sourcePath: canonicalPath,
		sourceCommit: pinned, currentCommit: current, frozen: witnessEstablished,
	}, nil
}

type yumCompatibilityPackageTrust struct {
	path    string
	keyring openpgp.KeyRing
	sha256  string
	gitBlob plumbing.Hash
	size    int64
}

func stageYUMCompatibilityPackageTrust(cfg *config.Config, canonical *state.Store, admission yumCompatibilityAdmission, txDir string) (yumCompatibilityPackageTrust, error) {
	var result yumCompatibilityPackageTrust
	trustPath, pathErr := state.YUMCompatibilityPackageTrustPath(admission.projection.ID)
	if pathErr != nil {
		return result, pathErr
	}
	reader, openErr := canonical.OpenPathAt(admission.sourceCommit, trustPath)
	if openErr != nil {
		return result, fmt.Errorf("open S1-pinned YUM compatibility package trust: %w", openErr)
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxSecretBytes+1))
	closeErr := reader.Close()
	if err != nil || closeErr != nil || len(data) == 0 || len(data) > maxSecretBytes {
		return result, errors.Join(err, closeErr, errors.New("S1-pinned YUM compatibility package trust is invalid"))
	}
	digest := sha256.Sum256(data)
	wantSHA, wantSize := "", int64(0)
	if admission.frozen {
		witnessPath, _ := state.YUMCompatibilityProjectionPath(admission.projection.ID)
		body, exists, readErr := readOptionalCanonical(canonical, witnessPath)
		if readErr != nil || !exists {
			return result, errors.Join(readErr, errors.New("frozen YUM compatibility witness is missing"))
		}
		witness, decodeErr := decodeYUMCompatibilityWitness(body)
		if decodeErr != nil {
			return result, decodeErr
		}
		wantSHA, wantSize = witness.PackageTrustSHA, witness.PackageTrustLen
	} else {
		adoption, adoptionErr := loadYUMCompatibilityAdoptionAt(canonical, admission.sourceCommit, admission.projection.ID)
		if adoptionErr != nil {
			return result, adoptionErr
		}
		wantSHA, wantSize = adoption.PackageTrustSHA256, adoption.PackageTrustSize
	}
	if int64(len(data)) != wantSize || hex.EncodeToString(digest[:]) != wantSHA {
		return result, errors.New("S1-pinned YUM compatibility package trust differs from immutable adoption/freeze evidence")
	}
	result.keyring, err = yumrepo.ParseRPMPackageKeyring(data)
	if err != nil || result.keyring == nil {
		return result, errors.Join(err, errors.New("YUM compatibility package trust contains no usable public RPM signer history"))
	}
	result.path = filepath.Join(txDir, "yum-compat-"+admission.projection.ID+"-package-trust.pgp")
	if err := os.WriteFile(result.path, data, 0o600); err != nil {
		return result, err
	}
	result.sha256, result.gitBlob, result.size, err = fileSHA256AndGitBlob(result.path)
	return result, err
}

// buildYUMCompatibilityPayload builds both the canonical Packages layout and
// the flat hardlink aliases retained for clients holding old primary metadata.
// The full witness manifest is rooted at projection.Root; the other files are
// relative to that leaf for bounded CAS materialization and exact reconcile.
func buildYUMCompatibilityPayload(canonical *state.Store, admission yumCompatibilityAdmission, txDir string) (packagesRelative, aliasesRelative, payloadRelative, witnessManifest string, packages, bytesTotal int64, err error) {
	source, err := canonical.OpenPathAt(admission.sourceCommit, admission.sourcePath)
	if err != nil {
		return "", "", "", "", 0, 0, err
	}
	base := "yum-compat-" + admission.projection.ID
	packagesRelative = filepath.Join(txDir, base+"-packages.tsv")
	packagesFile, err := os.OpenFile(packagesRelative, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		source.Close()
		return "", "", "", "", 0, 0, err
	}
	_, copyErr := io.Copy(packagesFile, source)
	closeErr := errors.Join(source.Close(), packagesFile.Sync(), packagesFile.Close())
	if copyErr != nil || closeErr != nil {
		return "", "", "", "", 0, 0, errors.Join(copyErr, closeErr)
	}
	if err := validateYUMPayloadManifest(packagesRelative); err != nil {
		return "", "", "", "", 0, 0, err
	}
	aliasesRelative = filepath.Join(txDir, base+"-aliases.tsv")
	packages, bytesTotal, err = writeYUMCompatibilityAliases(packagesRelative, aliasesRelative)
	if err != nil {
		return "", "", "", "", 0, 0, err
	}
	payloadRelative = filepath.Join(txDir, base+"-payload.tsv")
	if err := mergeManifestFiles(packagesRelative, aliasesRelative, payloadRelative); err != nil {
		return "", "", "", "", 0, 0, err
	}
	witnessManifest = filepath.Join(txDir, base+"-witness.tsv")
	if err := prefixManifest(payloadRelative, witnessManifest, admission.projection.Root); err != nil {
		return "", "", "", "", 0, 0, err
	}
	return packagesRelative, aliasesRelative, payloadRelative, witnessManifest, packages, bytesTotal, nil
}

// writeYUMCompatibilityAliases uses one bounded run per canonical package
// bucket. Every run is strictly sorted by basename because its source prefix
// is fixed; a k-way merge emits the flat namespace without loading a
// repository-wide map. This remains correct when an imported RPM basename was
// intentionally different from its package name/bucket.
func writeYUMCompatibilityAliases(sourcePath, destination string) (int64, int64, error) {
	source, err := os.Open(sourcePath)
	if err != nil {
		return 0, 0, err
	}
	defer source.Close()
	tempDir, err := os.MkdirTemp(filepath.Dir(destination), ".yum-compat-alias-")
	if err != nil {
		return 0, 0, err
	}
	defer os.RemoveAll(tempDir)
	runs := make(map[string]*os.File)
	lastByRun := make(map[string]string)
	reader := manifest.NewReader(source)
	var count, bytesTotal int64
	for {
		entry, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return 0, 0, nextErr
		}
		parts := strings.Split(entry.Path, "/")
		basename := path.Base(entry.Path)
		if len(parts) != 3 || parts[0] != "Packages" || len(parts[1]) != 1 || basename == entry.Path || !strings.HasSuffix(basename, ".rpm") || len(basename) == 0 {
			return 0, 0, fmt.Errorf("invalid compatibility alias source %q", entry.Path)
		}
		entry.Path = basename
		key := parts[1]
		if previous := lastByRun[key]; previous != "" && basename <= previous {
			return 0, 0, fmt.Errorf("compatibility alias collision or unsorted basename %q", basename)
		}
		lastByRun[key] = basename
		run := runs[key]
		if run == nil {
			run, err = os.OpenFile(filepath.Join(tempDir, hex.EncodeToString([]byte(key))+".tsv"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return 0, 0, err
			}
			runs[key] = run
		}
		if err := manifest.WriteEntry(run, entry); err != nil {
			return 0, 0, err
		}
		count++
		bytesTotal += entry.Size
	}
	for key, run := range runs {
		if err := errors.Join(run.Sync(), run.Close()); err != nil {
			return 0, 0, fmt.Errorf("close compatibility alias run %q: %w", key, err)
		}
	}
	destinationFile, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, 0, err
	}
	committed := false
	defer func() {
		_ = destinationFile.Close()
		if !committed {
			_ = os.Remove(destination)
		}
	}()
	var cursors yumCompatibilityAliasHeap
	for key := range runs {
		name := filepath.Join(tempDir, hex.EncodeToString([]byte(key))+".tsv")
		run, err := os.Open(name)
		if err != nil {
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, 0, err
		}
		manifestReader := manifest.NewReader(run)
		entry, err := manifestReader.Next()
		if errors.Is(err, io.EOF) {
			run.Close()
			continue
		}
		if err != nil {
			run.Close()
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, 0, err
		}
		cursors = append(cursors, &yumCompatibilityAliasCursor{entry: entry, reader: manifestReader, file: run})
	}
	heap.Init(&cursors)
	last := ""
	for cursors.Len() != 0 {
		cursor := heap.Pop(&cursors).(*yumCompatibilityAliasCursor)
		if cursor.entry.Path <= last {
			cursor.file.Close()
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, 0, fmt.Errorf("compatibility alias collision at %q", cursor.entry.Path)
		}
		if err := manifest.WriteEntry(destinationFile, cursor.entry); err != nil {
			cursor.file.Close()
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, 0, err
		}
		last = cursor.entry.Path
		next, err := cursor.reader.Next()
		if errors.Is(err, io.EOF) {
			cursor.file.Close()
			continue
		}
		if err != nil {
			cursor.file.Close()
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, 0, err
		}
		cursor.entry = next
		heap.Push(&cursors, cursor)
	}
	if err := errors.Join(destinationFile.Sync(), destinationFile.Close()); err != nil {
		return 0, 0, err
	}
	committed = true
	return count, bytesTotal, nil
}

type yumCompatibilityAliasCursor struct {
	entry  manifest.Entry
	reader *manifest.Reader
	file   *os.File
}

type yumCompatibilityAliasHeap []*yumCompatibilityAliasCursor

func (h yumCompatibilityAliasHeap) Len() int           { return len(h) }
func (h yumCompatibilityAliasHeap) Less(i, j int) bool { return h[i].entry.Path < h[j].entry.Path }
func (h yumCompatibilityAliasHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *yumCompatibilityAliasHeap) Push(value any) {
	*h = append(*h, value.(*yumCompatibilityAliasCursor))
}
func (h *yumCompatibilityAliasHeap) Pop() any {
	old := *h
	value := old[len(old)-1]
	*h = old[:len(old)-1]
	return value
}

func closeYUMCompatibilityAliasCursors(cursors yumCompatibilityAliasHeap) {
	for _, cursor := range cursors {
		_ = cursor.file.Close()
	}
}

func prefixManifest(sourcePath, destination, prefix string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	destinationFile, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = destinationFile.Close()
		if !committed {
			_ = os.Remove(destination)
		}
	}()
	reader := manifest.NewReader(source)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		entry.Path = path.Join(prefix, entry.Path)
		if err := manifest.WriteEntry(destinationFile, entry); err != nil {
			return err
		}
	}
	if err := errors.Join(destinationFile.Sync(), destinationFile.Close()); err != nil {
		return err
	}
	committed = true
	return nil
}

// preflightYUMCompatibilityFreeze proves that committing the irreversible
// witness cannot strand an unusable projection. It touches only a transaction
// directory: every manifest object is re-hashed from CAS, linked into an
// isolated tree, checked with the frozen public RPM trust, and used to build
// and re-validate the exact signed gzip metadata generation.
func preflightYUMCompatibilityFreeze(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, admission yumCompatibilityAdmission, packagesPath, aliasesPath, txDir string, values commonFlags, privateKey, passphrase []byte, trust yumCompatibilityPackageTrust) error {
	if pool == nil || trust.keyring == nil {
		return errors.New("YUM compatibility first-freeze CAS/trust preflight is unavailable")
	}
	commitTime, err := canonical.CommitTime(admission.sourceCommit)
	if err != nil {
		return err
	}
	if _, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(privateKey), passphrase, commitTime); err != nil {
		return errors.New("cannot initialize YUM compatibility signing key before freeze")
	}
	signer, err := newDeterministicMaterializeKey(privateKey, passphrase, commitTime)
	if err != nil {
		return errors.New("cannot unlock deterministic YUM compatibility signing key before freeze")
	}
	if err := requireMaterializationRepositoryTrust(values, cfg, privateKey, materializeTrustPayloadBefore); err != nil {
		return err
	}
	root := filepath.Join(txDir, "yum-compat-preflight-"+admission.projection.ID)
	if err := os.Mkdir(root, 0o700); err != nil {
		return err
	}
	if err := linkYUMCompatibilityPreflightCAS(ctx, pool, packagesPath, root); err != nil {
		return fmt.Errorf("preflight canonical package CAS closure: %w", err)
	}
	if err := linkYUMCompatibilityPreflightCAS(ctx, pool, aliasesPath, root); err != nil {
		return fmt.Errorf("preflight flat alias CAS closure: %w", err)
	}
	if err := verifyYUMPackageManifest(ctx, packagesPath, root, trust.keyring, timeNowUTC(), values.workers); err != nil {
		return fmt.Errorf("preflight frozen RPM package trust: %w", err)
	}
	iterator, file, err := openYUMManifestIterator(packagesPath, root)
	if err != nil {
		return err
	}
	generationDir := filepath.Join(txDir, "yum-compat-preflight-generation-"+admission.projection.ID)
	generation, generateErr := yumrepo.Generate(ctx, generationDir, yumrepo.Options{
		ELMajor: 0, Frozen: true, Compatibility: true, Compression: yumrepo.CompressionGzip,
		Revision: commitTime.Unix(), Signer: signer,
	}, iterator)
	closeErr := file.Close()
	if generateErr != nil || closeErr != nil {
		return errors.Join(generateErr, closeErr)
	}
	validated, err := yumrepo.ValidateDirectory(ctx, generationDir, yumrepo.CompressionGzip, signer)
	if err != nil || !yumGenerationMatchesExpected(validated, generation, -1) {
		return errors.Join(err, errors.New("preflight signed YUM compatibility generation identity mismatch"))
	}
	return requireMaterializationRepositoryTrust(values, cfg, privateKey, materializeTrustPayloadAfter)
}

func linkYUMCompatibilityPreflightCAS(ctx context.Context, pool *repository.Store, manifestPath, root string) error {
	file, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	for {
		entry, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			return nil
		}
		if nextErr != nil {
			return nextErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path.Clean(entry.Path) != entry.Path || strings.HasPrefix(entry.Path, "../") || strings.HasPrefix(entry.Path, "/") {
			return fmt.Errorf("unsafe preflight path %q", entry.Path)
		}
		digest, err := repository.ParseDigest(entry.HashString())
		if err != nil {
			return err
		}
		object := pool.ObjectPath(digest)
		info, err := os.Lstat(object)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != entry.Size {
			return errors.Join(err, fmt.Errorf("CAS object %s is missing, unsafe, or has wrong size", entry.HashString()))
		}
		sha, size, err := fileSHA256AndSize(object)
		if err != nil || sha != entry.HashString() || size != entry.Size {
			return errors.Join(err, fmt.Errorf("CAS object %s bytes differ from manifest", entry.HashString()))
		}
		destination := filepath.Join(root, filepath.FromSlash(entry.Path))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return err
		}
		if err := os.Link(object, destination); err != nil {
			return fmt.Errorf("link preflight CAS object: %w", err)
		}
	}
}

func ensureYUMCompatibilityWitness(ctx context.Context, cfg *config.Config, canonical *state.Store, admission yumCompatibilityAdmission, witnessManifest, desiredAliases, txDir string, privateKey []byte, trust yumCompatibilityPackageTrust, packages, bytesTotal int64) error {
	manifestSHA, manifestGit, manifestSize, err := fileSHA256AndGitBlob(witnessManifest)
	if err != nil {
		return err
	}
	sourceBlob, exists, err := canonical.BlobIdentityAt(admission.sourceCommit, admission.sourcePath)
	if err != nil || !exists {
		return errors.Join(err, errors.New("immutable YUM compatibility source manifest is missing"))
	}
	sourceReader, err := canonical.OpenPathAt(admission.sourceCommit, admission.sourcePath)
	if err != nil {
		return err
	}
	sourceSHA, err := hashReader(sourceReader)
	if err != nil {
		return err
	}
	adoptionPath, err := state.YUMCompatibilityAdoptionPath(admission.projection.ID)
	if err != nil {
		return err
	}
	adoptionBlob, exists, err := canonical.BlobIdentityAt(admission.sourceCommit, adoptionPath)
	if err != nil || !exists {
		return errors.Join(err, errors.New("immutable YUM compatibility adoption receipt is missing"))
	}
	adoptionReader, err := canonical.OpenPathAt(admission.sourceCommit, adoptionPath)
	if err != nil {
		return err
	}
	adoptionSHA, err := hashReader(adoptionReader)
	if err != nil {
		return err
	}
	witness := yumCompatibilityWitness{
		Schema: yumCompatibilityWitnessSchema, ID: admission.projection.ID, Root: admission.projection.Root, Mode: admission.projection.Mode, Carrier: admission.projection.Carrier,
		SourceRepo: admission.projection.Source.Repo, SourceView: admission.projection.Source.View, SourceOS: admission.projection.Source.OS, SourceArch: admission.projection.Source.Arch, SourceRoot: admission.sourcePath,
		SourceRef: admission.sourceRef.String(), SourceCommit: admission.sourceCommit.String(), SourceManifestSHA: sourceSHA, SourceManifestGit: sourceBlob.Hash.String(), SourceManifestLen: sourceBlob.Size,
		AdoptionSHA: adoptionSHA, AdoptionGit: adoptionBlob.Hash.String(), AdoptionLen: adoptionBlob.Size, PayloadManifestSHA: manifestSHA,
		PayloadManifestGit: manifestGit.String(), PayloadManifestLen: manifestSize,
		PackageTrustSHA: trust.sha256, PackageTrustGit: trust.gitBlob.String(), PackageTrustLen: trust.size,
		Packages: packages, Bytes: bytesTotal, FlatAliases: true,
	}
	body, err := json.MarshalIndent(witness, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	witnessStage := filepath.Join(txDir, "yum-compat-"+admission.projection.ID+"-projection.json")
	if err := os.WriteFile(witnessStage, body, 0o600); err != nil {
		return err
	}
	witnessPath, err := state.YUMCompatibilityProjectionPath(admission.projection.ID)
	if err != nil {
		return err
	}
	manifestPath, err := state.YUMCompatibilityManifestPath(admission.projection.ID)
	if err != nil {
		return err
	}
	trustPath, err := state.YUMCompatibilityPackageTrustPath(admission.projection.ID)
	if err != nil {
		return err
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return errors.Join(err, errors.New("canonical HEAD unavailable while installing YUM compatibility witness"))
	}
	witnessPresent, witnessEqual, err := canonicalPathEqualsFile(canonical, head, witnessPath, witnessStage)
	if err != nil {
		return err
	}
	manifestPresent, manifestEqual, err := canonicalPathEqualsFile(canonical, head, manifestPath, witnessManifest)
	if err != nil {
		return err
	}
	trustPresent, trustEqual, err := canonicalPathEqualsFile(canonical, head, trustPath, trust.path)
	if err != nil {
		return err
	}
	// package-trust.pgp is created at S1 adoption, before either S2 witness
	// file exists. Its earlier presence is therefore required, not evidence of
	// a partial freeze. Only the witness/payload pair must appear together.
	if witnessPresent != manifestPresent {
		return errors.New("YUM compatibility canonical witness/payload pair is incomplete")
	}
	if !trustPresent || !trustEqual {
		return errors.New("YUM compatibility S1 package trust is missing or changed")
	}
	if witnessPresent && (!witnessEqual || !manifestEqual) {
		return errors.New("YUM compatibility canonical witness differs from the immutable configured projection")
	}
	if !witnessPresent {
		// First freeze always audits the canonical physical owner. An operator may
		// materialize into a dedicated empty --target, but that must never bypass
		// one-for-one adoption of a populated legacy tree under cfg.Root.
		physicalRoot := filepath.Join(cfg.Root, filepath.FromSlash(admission.projection.Root))
		if populated, err := directoryHasEntries(physicalRoot); err != nil {
			return err
		} else if populated {
			if err := verifyLegacyYUMCompatibilityRoot(ctx, physicalRoot, desiredAliases, trust.keyring); err != nil {
				return fmt.Errorf("legacy YUM compatibility bootstrap does not match pinned source: %w", err)
			}
		}
	}
	compatRef, err := state.YUMCompatibilityRef(admission.projection.ID)
	if err != nil {
		return err
	}
	if witnessPresent {
		pinned, exists, err := canonical.Ref(compatRef)
		if err != nil || !exists {
			return errors.Join(err, fmt.Errorf("YUM compatibility preservation ref %s is missing", compatRef))
		}
		for canonicalPath, localPath := range map[string]string{witnessPath: witnessStage, manifestPath: witnessManifest, trustPath: trust.path} {
			present, equal, compareErr := canonicalPathEqualsFile(canonical, pinned, canonicalPath, localPath)
			if compareErr != nil || !present || !equal {
				return errors.Join(compareErr, fmt.Errorf("YUM compatibility freeze ref %s does not preserve %s", compatRef, canonicalPath))
			}
		}
		return nil
	}
	_, _, err = applyCanonicalState(ctx, canonical, "yum-compatibility-witness", "sow: freeze YUM compatibility projection "+admission.projection.ID,
		map[string]string{witnessPath: witnessStage, manifestPath: witnessManifest, trustPath: trust.path},
		[]state.RefUpdate{{Name: compatRef, Immutable: true}}, state.ApplyOptions{})
	return err
}

// prefreezeYUMCompatibilityProjections performs every canonical witness/ref
// mutation deterministically before a selected-set journal is opened and
// before any bounded materialization worker starts. Workers subsequently call
// ensureYUMCompatibilityWitness only as a read-only equality/ref check, so two
// architectures can never race the shared go-git worktree or advance HEAD
// underneath the durable selected-set identity.
func prefreezeYUMCompatibilityProjections(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, projections []config.YUMCompatibilityProjection, txDir string, values commonFlags, privateKey, passphrase []byte) error {
	ordered := config.SortedYUMCompatibilityProjections(projections)
	for _, projection := range ordered {
		admission, err := admitYUMCompatibilityProjection(cfg, canonical, projection)
		if err != nil {
			return err
		}
		if !admission.frozen && !values.allowYUMCompatibilityFreeze {
			return fmt.Errorf("YUM compatibility projection %s requires the explicit compatibility candidate/freeze workflow before materialize or publish", projection.ID)
		}
		stageDir := filepath.Join(txDir, "yum-compat-prefreeze-"+projection.ID)
		if err := os.Mkdir(stageDir, 0o700); err != nil {
			return err
		}
		packagesPath, aliases, _, witness, packages, bytesTotal, err := buildYUMCompatibilityPayload(canonical, admission, stageDir)
		if err != nil {
			return err
		}
		trust, err := stageYUMCompatibilityPackageTrust(cfg, canonical, admission, stageDir)
		if err != nil {
			return err
		}
		if err := preflightYUMCompatibilityFreeze(ctx, cfg, canonical, pool, admission, packagesPath, aliases, stageDir, values, privateKey, passphrase, trust); err != nil {
			return err
		}
		yumCompatibilityWitnessMu.Lock()
		err = ensureYUMCompatibilityWitness(ctx, cfg, canonical, admission, witness, aliases, stageDir, privateKey, trust, packages, bytesTotal)
		yumCompatibilityWitnessMu.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

func selectedYUMCompatibilityProjections(cfg *config.Config, source materializeCanonicalSource, leaves []viewLeaf, values commonFlags) ([]config.YUMCompatibilityProjection, error) {
	if source.ID != "latest" || source.Snapshot || source.RefCommits != nil || values.materializeCompatibility != nil && !values.materializeCompatibility[source.ID] {
		return nil, nil
	}
	byID := make(map[string]config.YUMCompatibilityProjection)
	for _, leaf := range leaves {
		if leaf.repo.Type != "yum" {
			continue
		}
		projection, matched, err := config.YUMCompatibilityProjectionForSource(cfg.CompatibilityProjections, leaf.repo.ID, source.ID, leaf.os, leaf.arch)
		if err != nil {
			return nil, err
		}
		if matched {
			byID[projection.ID] = projection
		}
	}
	result := make([]config.YUMCompatibilityProjection, 0, len(byID))
	for _, projection := range byID {
		result = append(result, projection)
	}
	return config.SortedYUMCompatibilityProjections(result), nil
}

func canonicalPathEqualsFile(canonical *state.Store, commit plumbing.Hash, canonicalPath, localPath string) (bool, bool, error) {
	_, exists, err := canonical.BlobIdentityAt(commit, canonicalPath)
	if err != nil || !exists {
		return exists, false, err
	}
	left, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return true, false, err
	}
	right, err := os.Open(localPath)
	if err != nil {
		left.Close()
		return true, false, err
	}
	equal, compareErr := equalReaders(left, right)
	return true, equal, errors.Join(compareErr, left.Close(), right.Close())
}

func directoryHasEntries(directory string) (bool, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return len(entries) != 0, nil
}

func verifyLegacyYUMCompatibilityRoot(ctx context.Context, root, desiredAliases string, keyring openpgp.KeyRing) error {
	repodataAllowed, err := legacyYUMCompatibilityRepodataAllowlist(ctx, root)
	if err != nil {
		return err
	}
	legacySorted := desiredAliases + ".legacy-sorted"
	indexed, err := writeSortedLegacyYUMCompatibilityManifest(ctx, root, legacySorted, keyring)
	if err != nil {
		return err
	}
	defer os.Remove(legacySorted)
	desired, err := os.Open(desiredAliases)
	if err != nil {
		return err
	}
	defer desired.Close()
	legacy, err := os.Open(legacySorted)
	if err != nil {
		return err
	}
	defer legacy.Close()
	stats, err := manifest.Diff(desired, legacy, nil)
	if err != nil {
		return err
	}
	if !stats.Clean() {
		return fmt.Errorf("legacy primary byte membership differs from pinned aliases: added=%d removed=%d changed=%d", stats.Added, stats.Removed, stats.Changed)
	}
	var physical int64
	err = filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "." {
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return errors.New("legacy compatibility root is not a real directory")
			}
			return nil
		}
		if relative == "repodata" {
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return errors.New("legacy compatibility repodata is not a real directory")
			}
			return nil
		}
		if strings.HasPrefix(relative, "repodata/") {
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
				return fmt.Errorf("legacy compatibility repodata contains unsafe entry %s", relative)
			}
			if _, allowed := repodataAllowed[relative]; !allowed {
				return fmt.Errorf("legacy compatibility repodata contains unreferenced entry %s", relative)
			}
			return nil
		}
		if path.Base(relative) == relative && strings.HasSuffix(relative, ".rpm") && !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 && entry.Type().IsRegular() {
			physical++
			return nil
		}
		return fmt.Errorf("legacy compatibility root contains unexpected entry %s", relative)
	})
	if err != nil {
		return err
	}
	if physical != indexed {
		return fmt.Errorf("legacy compatibility root has %d flat RPM files but structurally validated primary proves %d", physical, indexed)
	}
	return nil
}

// writeSortedLegacyYUMCompatibilityManifest external-sorts the structurally
// validated legacy primary. The old repomd may be unsigned and may advertise
// excluded sqlite/modulemd records; those are migration-input evidence only.
// Package membership is independently bound by exact bytes and embedded RPM
// signatures before the clean three-XML candidate is generated.
// membership because primary.xml order is not a repository contract. Chunks
// are bounded independently of repository size; the merge rejects duplicate
// basenames across chunks before the desired pinned alias manifest is diffed.
func writeSortedLegacyYUMCompatibilityManifest(ctx context.Context, root, destination string, keyring openpgp.KeyRing) (int64, error) {
	tempDir, err := os.MkdirTemp(filepath.Dir(destination), ".yum-compat-legacy-sort-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tempDir)
	const chunkEntries = 4096
	chunk := make([]manifest.Entry, 0, chunkEntries)
	var runs []string
	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		sort.Slice(chunk, func(i, j int) bool { return chunk[i].Path < chunk[j].Path })
		for index := 1; index < len(chunk); index++ {
			if chunk[index-1].Path == chunk[index].Path {
				return fmt.Errorf("legacy signed primary contains duplicate flat RPM %q", chunk[index].Path)
			}
		}
		name := filepath.Join(tempDir, fmt.Sprintf("%08d.tsv", len(runs)))
		file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		for _, entry := range chunk {
			if err := manifest.WriteEntry(file, entry); err != nil {
				file.Close()
				return err
			}
		}
		if err := errors.Join(file.Sync(), file.Close()); err != nil {
			return err
		}
		runs = append(runs, name)
		chunk = chunk[:0]
		return nil
	}
	var count int64
	err = upstream.ParseLocalYUMRepository(ctx, root, upstream.Limits{}, nil, func(pkg upstream.LocalPackage) error {
		if pkg.Location != path.Base(pkg.Location) || !strings.HasSuffix(pkg.Location, ".rpm") || pkg.Size < 0 {
			return fmt.Errorf("legacy primary contains non-flat RPM location %q", pkg.Location)
		}
		digest, err := hex.DecodeString(pkg.SHA256)
		if err != nil || len(digest) != sha256.Size {
			return fmt.Errorf("legacy primary package %s has invalid SHA-256", pkg.Location)
		}
		sha, size, err := fileSHA256AndSize(filepath.Join(root, filepath.FromSlash(pkg.Location)))
		if err != nil || size != pkg.Size || sha != pkg.SHA256 {
			return errors.Join(err, fmt.Errorf("legacy flat RPM %s differs from its signed primary identity", pkg.Location))
		}
		packageFile, err := os.Open(filepath.Join(root, filepath.FromSlash(pkg.Location)))
		if err != nil {
			return err
		}
		_, verifyErr := yumrepo.VerifyEmbeddedRPMSignatures(ctx, packageFile, keyring, timeNowUTC())
		closeErr := packageFile.Close()
		if verifyErr != nil || closeErr != nil {
			return errors.Join(verifyErr, closeErr, fmt.Errorf("legacy flat RPM %s does not satisfy frozen package trust", pkg.Location))
		}
		var hash [sha256.Size]byte
		copy(hash[:], digest)
		chunk = append(chunk, manifest.Entry{Path: pkg.Location, Size: pkg.Size, SHA256: hash})
		count++
		if len(chunk) == cap(chunk) {
			return flush()
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if err := flush(); err != nil {
		return 0, err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		_ = output.Close()
		if !committed {
			_ = os.Remove(destination)
		}
	}()
	var cursors yumCompatibilityAliasHeap
	for _, runName := range runs {
		run, err := os.Open(runName)
		if err != nil {
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, err
		}
		reader := manifest.NewReader(run)
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			run.Close()
			continue
		}
		if err != nil {
			run.Close()
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, err
		}
		cursors = append(cursors, &yumCompatibilityAliasCursor{entry: entry, reader: reader, file: run})
	}
	heap.Init(&cursors)
	previous := ""
	for cursors.Len() != 0 {
		cursor := heap.Pop(&cursors).(*yumCompatibilityAliasCursor)
		if cursor.entry.Path <= previous {
			cursor.file.Close()
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, fmt.Errorf("legacy signed primary contains duplicate flat RPM %q", cursor.entry.Path)
		}
		if err := manifest.WriteEntry(output, cursor.entry); err != nil {
			cursor.file.Close()
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, err
		}
		previous = cursor.entry.Path
		next, err := cursor.reader.Next()
		if errors.Is(err, io.EOF) {
			cursor.file.Close()
			continue
		}
		if err != nil {
			cursor.file.Close()
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, err
		}
		cursor.entry = next
		heap.Push(&cursors, cursor)
	}
	if err := errors.Join(output.Sync(), output.Close()); err != nil {
		return 0, err
	}
	committed = true
	return count, nil
}

func materializeYUMCompatibilityProjection(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, projection config.YUMCompatibilityProjection, targetRoot, txDir string, values commonFlags, privateKey, passphrase []byte) (result yumCompatibilityMaterializeResult, resultErr error) {
	result.Projection = projection
	admission, err := admitYUMCompatibilityProjection(cfg, canonical, projection)
	if err != nil {
		return result, err
	}
	values.materializeUnit, err = materializationUnitFor(values, "yum-compat", projection.Source.View, projection.Source.Repo, projection.Source.OS, projection.Source.Arch, targetRoot)
	if err != nil {
		return result, err
	}
	packagesPath, aliasesPath, payloadPath, witnessPath, packages, bytesTotal, err := buildYUMCompatibilityPayload(canonical, admission, txDir)
	if err != nil {
		return result, err
	}
	trust, err := stageYUMCompatibilityPackageTrust(cfg, canonical, admission, txDir)
	if err != nil {
		return result, err
	}
	yumCompatibilityWitnessMu.Lock()
	witnessErr := ensureYUMCompatibilityWitness(ctx, cfg, canonical, admission, witnessPath, aliasesPath, txDir, privateKey, trust, packages, bytesTotal)
	yumCompatibilityWitnessMu.Unlock()
	if witnessErr != nil {
		return result, witnessErr
	}
	commitTime, err := canonical.CommitTime(admission.sourceCommit)
	if err != nil {
		return result, err
	}
	signer, err := newDeterministicMaterializeKey(privateKey, passphrase, commitTime)
	if err != nil {
		return result, errors.New("cannot initialize YUM compatibility signing key")
	}
	if err := requireMaterializationRepositoryTrust(values, cfg, privateKey, materializeTrustPayloadBefore); err != nil {
		return result, err
	}
	packageKeyring := trust.keyring
	rootRelative, err := filepath.Rel(cfg.Root, filepath.Join(targetRoot, filepath.FromSlash(projection.Root)))
	if err != nil || rootRelative == ".." || strings.HasPrefix(rootRelative, ".."+string(filepath.Separator)) || filepath.IsAbs(rootRelative) {
		return result, errors.Join(err, errors.New("YUM compatibility target escapes repository root"))
	}
	rootRelative = filepath.ToSlash(rootRelative)
	result.Target = rootRelative
	packagesReader, err := os.Open(packagesPath)
	if err != nil {
		return result, err
	}
	result.Packages, err = pool.MaterializeWithOptions(ctx, packagesReader, rootRelative, repository.MaterializeOptions{Workers: values.workers})
	closeErr := packagesReader.Close()
	if err != nil || closeErr != nil {
		return result, errors.Join(err, closeErr)
	}
	aliasesReader, err := os.Open(aliasesPath)
	if err != nil {
		return result, err
	}
	result.Aliases, err = pool.MaterializeWithOptions(ctx, aliasesReader, rootRelative, repository.MaterializeOptions{Workers: values.workers})
	closeErr = aliasesReader.Close()
	if err != nil || closeErr != nil {
		return result, errors.Join(err, closeErr)
	}
	if err := requireMaterializationRepositoryTrust(values, cfg, privateKey, materializeTrustPayloadAfter); err != nil {
		return result, err
	}
	physicalRoot := filepath.Join(cfg.Root, filepath.FromSlash(rootRelative))
	if err := verifyYUMPackageManifest(ctx, packagesPath, physicalRoot, packageKeyring, timeNowUTC(), values.workers); err != nil {
		return result, fmt.Errorf("RPM compatibility package trust preflight: %w", err)
	}
	iterator, file, err := openYUMManifestIterator(packagesPath, physicalRoot)
	if err != nil {
		return result, err
	}
	options := yumrepo.Options{ELMajor: 0, Frozen: true, Compatibility: true, Compression: yumrepo.CompressionGzip, Revision: commitTime.Unix(), Signer: signer}
	generationDir := filepath.Join(txDir, "yum-compat-"+projection.ID+"-generation")
	result.Generation, err = yumrepo.Generate(ctx, generationDir, options, iterator)
	closeErr = file.Close()
	if err != nil || closeErr != nil {
		return result, errors.Join(err, closeErr)
	}
	live := filepath.Join(physicalRoot, "repodata")
	staged := filepath.Join(physicalRoot, ".sow-repodata-"+admission.sourceCommit.String()[:16])
	if err := installYUMStagedGeneration(ctx, generationDir, staged, yumrepo.CompressionGzip, signer, result.Generation.RepomdSHA256); err != nil {
		return result, err
	}
	guard := func(phase yumrepo.ActivationPhase) error {
		boundary := materializeTrustYUMActivationBefore
		if phase == yumrepo.ActivationAfterExchange {
			boundary = materializeTrustYUMActivationAfter
		}
		return requireMaterializationRepositoryTrust(values, cfg, privateKey, boundary)
	}
	if _, statErr := os.Lstat(live); errors.Is(statErr, os.ErrNotExist) {
		err = yumrepo.ActivateInitialLocalGuarded(ctx, live, staged, yumrepo.CompressionGzip, signer, result.Generation.RepomdSHA256, guard)
	} else if statErr != nil {
		return result, statErr
	} else {
		err = yumrepo.ActivateLocalGuarded(ctx, live, staged, yumrepo.CompressionGzip, signer, result.Generation.RepomdSHA256, yumrepo.NativeDirectoryExchanger{}, guard)
	}
	if err != nil {
		return result, err
	}
	if err := os.RemoveAll(staged); err != nil {
		return result, err
	}
	metadataPath := filepath.Join(txDir, "yum-compat-"+projection.ID+"-metadata.tsv")
	if _, err := manifest.Scan(ctx, physicalRoot, manifest.Scope{Path: "repodata"}, metadataPath, manifest.ScanOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp")}); err != nil {
		return result, err
	}
	exactPath := filepath.Join(txDir, "yum-compat-"+projection.ID+"-exact.tsv")
	if err := mergeManifestFiles(payloadPath, metadataPath, exactPath); err != nil {
		return result, err
	}
	if err := requireMaterializationRepositoryTrust(values, cfg, privateKey, materializeTrustExactReconcileBefore); err != nil {
		return result, err
	}
	result.Reconciled, err = pool.ReconcileExact(ctx, exactPath, rootRelative, values.workers, values.chunk)
	if err != nil {
		return result, err
	}
	if err := requireMaterializationRepositoryTrust(values, cfg, privateKey, materializeTrustExactReconcileAfter); err != nil {
		return result, err
	}
	if err := requireMaterializationRepositoryTrust(values, cfg, privateKey, materializeTrustServingPublishBefore); err != nil {
		return result, err
	}
	if err := serving.PublishHostableTree(physicalRoot); err != nil {
		return result, fmt.Errorf("publish hostable YUM compatibility tree: %w", err)
	}
	if err := requireMaterializationRepositoryTrust(values, cfg, privateKey, materializeTrustServingPublishAfter); err != nil {
		return result, err
	}
	active, err := yumrepo.ValidateDirectory(ctx, live, yumrepo.CompressionGzip, signer)
	if err != nil || !yumGenerationMatchesExpected(active, result.Generation, -1) {
		return result, errors.Join(err, errors.New("active YUM compatibility generation identity mismatch"))
	}
	return result, nil
}

func fileSHA256AndSize(filename string) (string, int64, error) {
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", 0, errors.Join(err, errors.New("path is absent, symlinked, or non-regular"))
	}
	file, err := os.Open(filename)
	if err != nil {
		return "", 0, err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	after, statErr := os.Lstat(filename)
	if copyErr != nil || closeErr != nil || statErr != nil || written != info.Size() ||
		after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || after.Size() != info.Size() || !os.SameFile(info, after) {
		return "", 0, errors.Join(copyErr, closeErr, statErr, errors.New("file changed while hashing"))
	}
	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}

// fileSHA256AndGitBlob computes both the externally meaningful manifest
// digest and the exact Git blob identity that the canonical commit must carry.
// It streams once with bounded memory and rejects replacement/truncation during
// hashing. Ordinary command-load gates can then compare BlobIdentityAt in
// constant memory without inflating a large manifest.
func fileSHA256AndGitBlob(filename string) (string, plumbing.Hash, int64, error) {
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", plumbing.ZeroHash, 0, errors.Join(err, errors.New("path is absent, symlinked, or non-regular"))
	}
	file, err := os.Open(filename)
	if err != nil {
		return "", plumbing.ZeroHash, 0, err
	}
	sha := sha256.New()
	gitBlob := plumbing.NewHasher(plumbing.BlobObject, info.Size())
	written, copyErr := io.Copy(io.MultiWriter(sha, gitBlob), file)
	closeErr := file.Close()
	after, statErr := os.Lstat(filename)
	if copyErr != nil || closeErr != nil || statErr != nil || written != info.Size() || after.Size() != info.Size() || !os.SameFile(info, after) {
		return "", plumbing.ZeroHash, 0, errors.Join(copyErr, closeErr, statErr, errors.New("file changed while hashing"))
	}
	return hex.EncodeToString(sha.Sum(nil)), gitBlob.Sum(), written, nil
}
