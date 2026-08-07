package managed

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

const (
	rpmLeafExportSchema  = "sow/export/v1"
	rpmLeafExportProfile = "sow-rpm-leaf-v1"
	maxRPMLeafControl    = 64 << 20
)

type RPMLeafExportOptions struct {
	WorkspaceOptions
	Repository string
	Dist       string
	Arch       string
	Directory  string
	Hardlink   bool
}

type RPMLeafVerifySourceOptions struct {
	WorkspaceOptions
	Repository string
	Directory  string
}

type RPMLeafExportResult struct {
	Repository     string             `json:"repository"`
	RepositoryID   string             `json:"repository_id"`
	Generation     state.GenerationID `json:"generation"`
	Dist           string             `json:"dist"`
	Arch           string             `json:"arch"`
	Directory      string             `json:"directory"`
	Method         string             `json:"method"`
	Signed         bool               `json:"signed"`
	SignerIdentity string             `json:"signer_identity"`
	Packages       int                `json:"packages"`
	Files          int                `json:"files"`
	ManifestSHA256 string             `json:"manifest_sha256"`
}

type RPMLeafExportMarker struct {
	Schema         string             `json:"schema"`
	Profile        string             `json:"profile"`
	RepositoryID   string             `json:"repository_id"`
	Generation     state.GenerationID `json:"-"`
	Dist           string             `json:"dist"`
	Arch           string             `json:"arch"`
	Method         string             `json:"method"`
	Signed         bool               `json:"signed"`
	SignerIdentity string             `json:"signer_identity"`
	ManifestSHA256 string             `json:"manifest_sha256"`
}

type rpmLeafMarkerWire struct {
	Schema         string `json:"schema"`
	Profile        string `json:"profile"`
	RepositoryID   string `json:"repository_id"`
	Generation     string `json:"generation"`
	Dist           string `json:"dist"`
	Arch           string `json:"arch"`
	Method         string `json:"method"`
	Signed         bool   `json:"signed"`
	SignerIdentity string `json:"signer_identity"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

type rpmLeafManifestEntry struct {
	SHA256 string
	Size   int64
	Path   string
}

func canonicalRPMLeafMarker(marker RPMLeafExportMarker) ([]byte, error) {
	if marker.Schema != rpmLeafExportSchema || marker.Profile != rpmLeafExportProfile || !state.IsCanonicalRepositoryID(marker.RepositoryID) || marker.Generation == 0 ||
		!safeExportDist(marker.Dist) || marker.Arch != "x86_64" && marker.Arch != "aarch64" ||
		marker.Method != "copy" && marker.Method != "hardlink" || !lowercaseSHA256.MatchString(marker.ManifestSHA256) ||
		marker.Signed && !lowercaseSHA256.MatchString(marker.SignerIdentity) || !marker.Signed && marker.SignerIdentity != "none" {
		return nil, errors.New("managed: invalid sow-rpm-leaf-v1 marker")
	}
	// RFC 8785 member order is lexicographic by UTF-16 code units. All v1 names
	// and values are restricted ASCII, so this literal is the exact JCS wire.
	data := fmt.Sprintf(`{"arch":%s,"dist":%s,"generation":%s,"manifest_sha256":%s,"method":%s,"profile":%s,"repository_id":%s,"schema":%s,"signed":%t,"signer_identity":%s}`,
		canonicalJSONString(marker.Arch), canonicalJSONString(marker.Dist), canonicalJSONString(marker.Generation.String()), canonicalJSONString(marker.ManifestSHA256),
		canonicalJSONString(marker.Method), canonicalJSONString(marker.Profile), canonicalJSONString(marker.RepositoryID), canonicalJSONString(marker.Schema), marker.Signed, canonicalJSONString(marker.SignerIdentity))
	return []byte(data), nil
}

func safeExportDist(value string) bool {
	if value == "" || !((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= '0' && value[0] <= '9')) {
		return false
	}
	for index := 1; index < len(value); index++ {
		c := value[index]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func parseRPMLeafMarker(data []byte) (RPMLeafExportMarker, error) {
	if len(data) == 0 || len(data) > maxRPMLeafControl || rejectDuplicateJSONMembers(data) != nil {
		return RPMLeafExportMarker{}, errors.New("managed: malformed RPM leaf marker")
	}
	var wire rpmLeafMarkerWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return RPMLeafExportMarker{}, fmt.Errorf("managed: decode RPM leaf marker: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return RPMLeafExportMarker{}, errors.New("managed: RPM leaf marker has trailing content")
	}
	generation, err := state.ParseGenerationID(wire.Generation)
	if err != nil {
		return RPMLeafExportMarker{}, errors.New("managed: RPM leaf marker generation is not canonical")
	}
	marker := RPMLeafExportMarker{Schema: wire.Schema, Profile: wire.Profile, RepositoryID: wire.RepositoryID, Generation: generation, Dist: wire.Dist, Arch: wire.Arch, Method: wire.Method, Signed: wire.Signed, SignerIdentity: wire.SignerIdentity, ManifestSHA256: wire.ManifestSHA256}
	canonical, err := canonicalRPMLeafMarker(marker)
	if err != nil || !bytes.Equal(canonical, data) {
		return RPMLeafExportMarker{}, errors.New("managed: RPM leaf marker is not exact RFC 8785 v1 wire")
	}
	return marker, nil
}

func ExportRPMLeaf(ctx context.Context, opts RPMLeafExportOptions) (result RPMLeafExportResult, resultErr error) {
	if ctx == nil || opts.Directory == "" || !safeExportDist(opts.Dist) || opts.Arch != "x86_64" && opts.Arch != "aarch64" {
		return result, fmt.Errorf("%w: invalid RPM leaf export arguments", ErrRejected)
	}
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts.WorkspaceOptions, true)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	repoName, err := selectRepo(ws, cfg, opts.Repository)
	if err != nil {
		return result, err
	}
	configured, ok := cfg.Repositories[repoName].Dists[opts.Dist]
	if !ok || configured.Format != "rpm" {
		return result, fmt.Errorf("%w: Dist %q is not a configured RPM Dist", ErrRejected, opts.Dist)
	}
	store, repoLock, err := openReadRepository(ctx, ws.Root, repoName)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close(), store.Close()) }()
	if err := store.RequireTerminalLayout(ctx); err != nil {
		return result, fmt.Errorf("%w: RPM leaf export requires terminal Repository layout: %v", ErrNotReady, err)
	}
	if pending, err := store.PendingOperations(ctx); err != nil || len(pending) != 0 {
		return result, fmt.Errorf("%w: RPM leaf export requires settled Repository state", ErrNotReady)
	}
	summary, err := store.Summary(ctx)
	if err != nil || summary.BuiltGeneration == 0 || summary.Status != "clean" {
		return result, fmt.Errorf("%w: RPM leaf export requires a clean Built Generation", ErrNotReady)
	}
	dist, err := store.GetDist(ctx, opts.Dist)
	if err != nil || dist.Format != "rpm" || dist.BuiltGeneration != summary.BuiltGeneration || !distHasArchitecture(dist, opts.Arch) {
		return result, fmt.Errorf("%w: requested RPM view is not bound to the current Built Generation", ErrRejected)
	}
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		return result, err
	}
	viewID := filepath.ToSlash(filepath.Join("dists", opts.Dist, opts.Arch))
	signing, err := store.GenerationViewSigner(ctx, summary.BuiltGeneration, viewID)
	if err != nil {
		return result, fmt.Errorf("%w: read frozen RPM view signing identity: %v", ErrIntegrity, err)
	}
	objects, err := store.ListPackageObjects(ctx, []string{opts.Dist}, true)
	if err != nil {
		return result, err
	}
	selected, err := selectRPMLeafObjects(objects, opts.Arch)
	if err != nil {
		return result, err
	}
	protectedRoots := make([]string, 0, len(cfg.Repositories)+len(cfg.Targets)+1)
	for name := range cfg.Repositories {
		protectedRoots = append(protectedRoots, filepath.Join(ws.Root, name))
	}
	protectedRoots = append(protectedRoots, filepath.Join(ws.Root, ".sow"))
	for _, publicationTarget := range cfg.Targets {
		if publicationTarget.Provider != "filesystem" {
			continue
		}
		publicationRoot, err := filesystemPublicationRoot(publicationTarget)
		if err != nil {
			return result, err
		}
		protectedRoots = append(protectedRoots, publicationRoot)
	}
	target, err := prepareRPMLeafRoot(protectedRoots, opts.Directory)
	if err != nil {
		return result, err
	}
	if err := durableMkdir(filepath.Join(target, "pool"), 0o755); err != nil {
		return result, err
	}
	method := "copy"
	if opts.Hardlink {
		method = "hardlink"
	}
	repositoryRoot := filepath.Join(ws.Root, repoName)
	inputs := make([]yumrepo.PackageInput, 0, len(selected))
	for _, object := range selected {
		if err := exportRPMLeafObject(ctx, repositoryRoot, target, object, opts.Hardlink); err != nil {
			return result, err
		}
		inputs = append(inputs, yumrepo.PackageInput{Path: filepath.Join(target, filepath.FromSlash(object.PoolPath)), Basename: object.Filename, PoolPath: object.PoolPath})
	}
	generationInfo, err := store.GetGeneration(ctx, summary.BuiltGeneration)
	if err != nil {
		return result, err
	}
	operation, err := store.GetOperation(ctx, generationInfo.OperationID)
	if err != nil || operation.Operation.CreatedAt.IsZero() {
		return result, fmt.Errorf("%w: Built Generation has no publication time", ErrIntegrity)
	}
	var signer yumrepo.DetachedSigner
	if signing.SignerIdentity != "none" {
		snapshot, err := loadMetadataSignerSnapshotForFormats(ctx, ws.Root, cfg.Repositories[repoName], operation.Operation.CreatedAt.UTC(), true, false)
		if err != nil {
			return result, fmt.Errorf("%w: signed export requires the bound private metadata signer: %v", ErrRejected, err)
		}
		if snapshot.RPMSigner == nil || metadataSignerRecordIdentity(snapshot.RPM.Fingerprint, snapshot.RPM.PublicKey) != signing.SignerIdentity || !bytes.Equal(snapshot.RPM.PublicKey, signing.TrustedPublicKey) {
			return result, fmt.Errorf("%w: current private signer differs from frozen Built view identity", ErrIntegrity)
		}
		signer = snapshot.RPMSigner
	}
	if _, err := yumrepo.GenerateRPMLeaf(ctx, filepath.Join(target, "repodata"), uint64(summary.BuiltGeneration), &yumrepo.SliceIterator{Inputs: inputs}, signer); err != nil {
		return result, err
	}
	entries, manifest, manifestSHA, err := buildRPMLeafManifest(ctx, target)
	if err != nil {
		return result, err
	}
	if err := writeRPMLeafControl(filepath.Join(target, "manifest.tsv"), manifest, 0o644); err != nil {
		return result, err
	}
	if err := syncTree(target); err != nil {
		return result, err
	}
	marker := RPMLeafExportMarker{Schema: rpmLeafExportSchema, Profile: rpmLeafExportProfile, RepositoryID: identity.RepositoryID, Generation: summary.BuiltGeneration, Dist: opts.Dist, Arch: opts.Arch, Method: method, Signed: signing.SignerIdentity != "none", SignerIdentity: signing.SignerIdentity, ManifestSHA256: manifestSHA}
	markerBytes, err := canonicalRPMLeafMarker(marker)
	if err != nil {
		return result, err
	}
	trust := map[string][]byte{}
	if marker.Signed {
		trust[marker.SignerIdentity] = signing.TrustedPublicKey
	}
	if _, err := verifyRPMLeafExport(ctx, target, trust, false, marker); err != nil {
		return result, fmt.Errorf("%w: RPM leaf pre-marker verification failed: %v", ErrIntegrity, err)
	}
	if err := writeRPMLeafControl(filepath.Join(target, ".sow-export.json"), markerBytes, 0o644); err != nil {
		return result, err
	}
	verified, err := verifyRPMLeafExport(ctx, target, trust, true)
	if err != nil || verified != marker {
		return result, fmt.Errorf("%w: completed RPM leaf failed source-bound verification: %v", ErrIntegrity, err)
	}
	return RPMLeafExportResult{Repository: repoName, RepositoryID: identity.RepositoryID, Generation: summary.BuiltGeneration, Dist: opts.Dist, Arch: opts.Arch, Directory: target, Method: method, Signed: marker.Signed, SignerIdentity: marker.SignerIdentity, Packages: len(selected), Files: len(entries), ManifestSHA256: manifestSHA}, nil
}

func distHasArchitecture(dist state.Dist, family string) bool {
	for _, architecture := range dist.Architectures {
		if architecture.Family == family {
			return true
		}
	}
	return false
}

func selectRPMLeafObjects(objects []state.PackageObject, arch string) ([]state.PackageObject, error) {
	selected := make([]state.PackageObject, 0, len(objects))
	for _, object := range objects {
		if object.Format != "rpm" {
			return nil, fmt.Errorf("%w: RPM Dist Built Membership contains non-RPM object", ErrIntegrity)
		}
		if object.CanonicalArch == "neutral" || object.CanonicalArch == arch {
			if object.Storage != "pool" {
				return nil, fmt.Errorf("%w: Built package %s is not in canonical Pool", ErrIntegrity, object.SHA256)
			}
			selected = append(selected, object)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].PoolPath < selected[j].PoolPath })
	for index := 1; index < len(selected); index++ {
		if selected[index-1].PoolPath == selected[index].PoolPath {
			return nil, fmt.Errorf("%w: duplicate RPM leaf Pool path", ErrIntegrity)
		}
	}
	return selected, nil
}

func prepareRPMLeafRoot(protectedRoots []string, raw string) (string, error) {
	target, err := filepath.Abs(raw)
	if err != nil {
		return "", err
	}
	target = filepath.Clean(target)
	if info, statErr := os.Lstat(target); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: RPM leaf root must not be a symlink", ErrRejected)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", statErr
	}
	physicalTarget, _, err := prospectiveRealDirectory(target)
	if err != nil {
		return "", fmt.Errorf("%w: RPM leaf root must use one canonical physical path: %v", ErrRejected, err)
	}
	target = physicalTarget
	for _, protected := range protectedRoots {
		physicalProtected, _, err := prospectiveRealDirectory(protected)
		if err != nil {
			return "", err
		}
		if pathsOverlap(target, physicalProtected) {
			return "", fmt.Errorf("%w: RPM leaf export must not overlap Repository, private workspace, or filesystem publication roots", ErrRejected)
		}
	}
	if info, err := os.Lstat(target); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: RPM leaf root is not a real directory", ErrRejected)
		}
		entries, err := os.ReadDir(target)
		if err != nil || len(entries) != 0 {
			return "", fmt.Errorf("%w: RPM leaf root must be empty", ErrRejected)
		}
		return target, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(target)
	if info, err := os.Lstat(parent); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: RPM leaf parent must already be a real directory", ErrRejected)
	}
	if err := durableMkdir(target, 0o755); err != nil {
		return "", err
	}
	return target, nil
}

func exportRPMLeafObject(ctx context.Context, repositoryRoot, target string, object state.PackageObject, hardlink bool) error {
	if object.Storage != "pool" {
		return fmt.Errorf("%w: Built package %s is not in canonical Pool", ErrIntegrity, object.SHA256)
	}
	if hardlink {
		return linkRootedRegular(ctx, repositoryRoot, object.PoolPath, target, object.PoolPath, object.Size, object.SHA256, 0o755)
	}
	if err := durableEnsureDirectoryTree(target, filepath.Dir(filepath.Join(target, filepath.FromSlash(object.PoolPath))), 0o755); err != nil {
		return err
	}
	source, err := openRootedRegular(repositoryRoot, object.PoolPath)
	if err != nil {
		return err
	}
	output, err := createRootedRegular(target, object.PoolPath, 0o644)
	if err != nil {
		return errors.Join(err, source.CloseVerified())
	}
	committed := false
	defer func() {
		if !committed {
			_ = output.Abort()
		}
	}()
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output.file, hash), &managedContextReader{ctx: ctx, reader: source.file})
	closeErr := source.CloseVerified()
	if copyErr != nil || closeErr != nil || written != object.Size || hex.EncodeToString(hash.Sum(nil)) != object.SHA256 {
		return errors.Join(fmt.Errorf("%w: copied RPM leaf payload differs from Built object", ErrIntegrity), copyErr, closeErr)
	}
	if err := output.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func buildRPMLeafManifest(ctx context.Context, root string) ([]rpmLeafManifestEntry, []byte, string, error) {
	entries := []rpmLeafManifestEntry{}
	for _, top := range []string{"pool", "repodata"} {
		path := filepath.Join(root, top)
		err := walkRootedTree(ctx, path, func(relative string, file *os.File, info os.FileInfo) error {
			hash := sha256.New()
			if _, err := io.Copy(hash, &managedContextReader{ctx: ctx, reader: file}); err != nil {
				return err
			}
			entries = append(entries, rpmLeafManifestEntry{SHA256: hex.EncodeToString(hash.Sum(nil)), Size: info.Size(), Path: filepath.ToSlash(filepath.Join(top, relative))})
			return nil
		}, nil)
		if err != nil {
			return nil, nil, "", err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	var manifest bytes.Buffer
	for _, entry := range entries {
		fmt.Fprintf(&manifest, "%s %d %s\n", entry.SHA256, entry.Size, entry.Path)
	}
	sum := sha256.Sum256(manifest.Bytes())
	return entries, manifest.Bytes(), hex.EncodeToString(sum[:]), nil
}

func writeRPMLeafControl(filename string, data []byte, mode os.FileMode) error {
	if _, err := os.Lstat(filename); err == nil {
		return fmt.Errorf("%w: RPM leaf control file already exists", ErrIntegrity)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeAtomic(filename, data, mode)
}

// VerifyRPMLeafExportStandalone validates a completed export using only an
// externally supplied signer-identity to public-key trust map.
func VerifyRPMLeafExportStandalone(ctx context.Context, root string, trust map[string][]byte) (RPMLeafExportMarker, error) {
	return verifyRPMLeafExport(ctx, root, trust, true)
}

// VerifyRPMLeafExportSourceBound additionally proves that the marker's
// Repository, Generation/view coordinate, signer identity, and trusted key
// equal the immutable SQLite Built-view signing record.
func VerifyRPMLeafExportSourceBound(ctx context.Context, opts RPMLeafVerifySourceOptions) (marker RPMLeafExportMarker, resultErr error) {
	if ctx == nil || opts.Directory == "" {
		return marker, fmt.Errorf("%w: invalid source-bound RPM leaf verification", ErrRejected)
	}
	markerData, err := readRootedRegular(opts.Directory, ".sow-export.json", maxRPMLeafControl, false)
	if err != nil {
		return marker, err
	}
	marker, err = parseRPMLeafMarker(markerData)
	if err != nil {
		return marker, err
	}
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts.WorkspaceOptions, true)
	if err != nil {
		return marker, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	repository, err := selectRepo(ws, cfg, opts.Repository)
	if err != nil {
		return marker, err
	}
	store, repoLock, err := openReadRepository(ctx, ws.Root, repository)
	if err != nil {
		return marker, err
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close(), store.Close()) }()
	if err := store.RequireTerminalLayout(ctx); err != nil {
		return marker, fmt.Errorf("%w: source Repository is not terminal: %v", ErrIntegrity, err)
	}
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil || identity.RepositoryID != marker.RepositoryID {
		return marker, fmt.Errorf("%w: RPM leaf Repository identity differs from source", ErrIntegrity)
	}
	viewID := filepath.ToSlash(filepath.Join("dists", marker.Dist, marker.Arch))
	signing, err := store.GenerationViewSigner(ctx, marker.Generation, viewID)
	if err != nil || signing.SignerIdentity != marker.SignerIdentity || marker.Signed != (signing.SignerIdentity != "none") {
		return marker, fmt.Errorf("%w: RPM leaf signing identity differs from source Built view", ErrIntegrity)
	}
	trust := map[string][]byte{}
	if marker.Signed {
		trust[marker.SignerIdentity] = signing.TrustedPublicKey
	}
	verified, err := verifyRPMLeafExport(ctx, opts.Directory, trust, true)
	if err != nil || verified != marker {
		return marker, fmt.Errorf("%w: source-bound RPM leaf verification failed: %v", ErrIntegrity, err)
	}
	return marker, nil
}

func verifyRPMLeafExport(ctx context.Context, root string, trust map[string][]byte, requireMarker bool, expected ...RPMLeafExportMarker) (RPMLeafExportMarker, error) {
	if ctx == nil || root == "" {
		return RPMLeafExportMarker{}, fmt.Errorf("%w: invalid RPM leaf verification input", ErrRejected)
	}
	markerPath := filepath.Join(root, ".sow-export.json")
	var marker RPMLeafExportMarker
	if requireMarker {
		data, err := readRootedRegular(root, ".sow-export.json", maxRPMLeafControl, false)
		if err != nil {
			return marker, errors.New("managed: incomplete RPM leaf export has no marker")
		}
		marker, err = parseRPMLeafMarker(data)
		if err != nil {
			return marker, err
		}
	} else {
		if len(expected) != 1 {
			return marker, errors.New("managed: RPM leaf pre-marker verifier lacks bound marker fields")
		}
		marker = expected[0]
		if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
			return marker, errors.New("managed: RPM leaf marker must not exist before final installation")
		}
	}
	manifest, err := readRootedRegular(root, "manifest.tsv", maxRPMLeafControl, false)
	if err != nil {
		return marker, errors.New("managed: RPM leaf manifest is missing or oversized")
	}
	entries, err := parseRPMLeafManifest(manifest)
	if err != nil {
		return marker, err
	}
	sum := sha256.Sum256(manifest)
	manifestSHA := hex.EncodeToString(sum[:])
	if marker.ManifestSHA256 != manifestSHA {
		return marker, errors.New("managed: RPM leaf manifest digest differs from marker")
	}
	expectedFiles := map[string]rpmLeafManifestEntry{}
	expectedRPM := []yumrepo.ManagedRPMPackageExpectation{}
	for _, entry := range entries {
		expectedFiles[entry.Path] = entry
		opened, err := openRootedRegular(root, entry.Path)
		if err != nil || opened.before.Size() != entry.Size {
			if opened != nil {
				_ = opened.CloseVerified()
			}
			return marker, errors.New("managed: RPM leaf manifest entry is missing or differs")
		}
		digest, hashErr := hashRegularDescriptor(ctx, opened.file)
		closeErr := opened.CloseVerified()
		if hashErr != nil || closeErr != nil || digest != entry.SHA256 {
			return marker, errors.New("managed: RPM leaf manifest entry digest differs")
		}
		if strings.HasPrefix(entry.Path, "pool/") {
			pool, err := yumrepo.ParseManagedPoolPath(entry.Path)
			if err != nil {
				return marker, errors.New("managed: RPM leaf manifest has invalid Pool path")
			}
			expectedRPM = append(expectedRPM, yumrepo.ManagedRPMPackageExpectation{SHA256: entry.SHA256, Size: entry.Size, PoolPath: pool})
		}
	}
	actual, _, _, err := buildRPMLeafManifest(ctx, root)
	if err != nil || len(actual) != len(entries) {
		return marker, errors.New("managed: RPM leaf contains foreign or missing data files")
	}
	for _, entry := range actual {
		if expectedFiles[entry.Path] != entry {
			return marker, errors.New("managed: RPM leaf exact data closure differs")
		}
	}
	if err := validateRPMLeafDirectoryClosure(ctx, root, entries, requireMarker); err != nil {
		return marker, err
	}
	var verifier yumrepo.DetachedVerifier
	signed := marker.Signed
	if signed {
		key := trust[marker.SignerIdentity]
		if len(key) == 0 {
			return marker, errors.New("managed: RPM leaf signer identity is not externally trusted")
		}
		signature, err := readRootedRegular(root, "repodata/repomd.xml.asc", maxRPMLeafControl, false)
		if err != nil {
			return marker, errors.New("managed: signed RPM leaf lacks repomd.xml.asc")
		}
		signedAt, err := yumrepo.DetachedSignatureCreationTime(bytes.NewReader(signature))
		if err != nil {
			return marker, err
		}
		verifier, err = yumrepo.NewOpenPGPVerifier(bytes.NewReader(key), signedAt)
		if err != nil {
			return marker, err
		}
		_, err = yumrepo.ValidateRPMLeafDirectory(ctx, filepath.Join(root, "repodata"), yumrepo.CompressionGzip, verifier, expectedRPM)
		if err != nil {
			return marker, err
		}
	} else if _, err := yumrepo.ValidateRPMLeafUnsignedDirectory(ctx, filepath.Join(root, "repodata"), yumrepo.CompressionGzip, expectedRPM); err != nil {
		return marker, err
	}
	return marker, nil
}

func validateRPMLeafDirectoryClosure(ctx context.Context, root string, entries []rpmLeafManifestEntry, markerPresent bool) error {
	rootEntries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	allowedTop := map[string]bool{"pool": true, "repodata": true, "manifest.tsv": true}
	if markerPresent {
		allowedTop[".sow-export.json"] = true
	}
	for _, entry := range rootEntries {
		if !allowedTop[entry.Name()] {
			return errors.New("managed: RPM leaf root contains a foreign entry")
		}
	}
	allowedDirs := map[string]bool{"pool": true, "repodata": true}
	for _, entry := range entries {
		for directory := filepath.ToSlash(filepath.Dir(entry.Path)); directory != "."; directory = filepath.ToSlash(filepath.Dir(directory)) {
			allowedDirs[directory] = true
		}
	}
	for _, top := range []string{"pool", "repodata"} {
		err := walkRootedTree(ctx, filepath.Join(root, top), nil, func(relative string, _ *os.File, _ os.FileInfo) error {
			path := filepath.ToSlash(filepath.Join(top, relative))
			if !allowedDirs[path] {
				return errors.New("managed: RPM leaf data tree contains a foreign directory")
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func parseRPMLeafManifest(data []byte) ([]rpmLeafManifestEntry, error) {
	entries := []rpmLeafManifestEntry{}
	previous := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), maxRPMLeafControl)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, " ", 3)
		if len(parts) != 3 || !lowercaseSHA256.MatchString(parts[0]) || !canonicalRPMLeafSize(parts[1]) {
			return nil, errors.New("managed: RPM leaf manifest line is not canonical")
		}
		size, err := strconv.ParseInt(parts[1], 10, 64)
		path := parts[2]
		if err != nil || size < 0 || path <= previous || filepath.ToSlash(filepath.Clean(path)) != path || strings.ContainsAny(path, "\\\x00\r\n\t") ||
			!strings.HasPrefix(path, "pool/") && !strings.HasPrefix(path, "repodata/") {
			return nil, errors.New("managed: RPM leaf manifest path/size is not canonical")
		}
		entries = append(entries, rpmLeafManifestEntry{SHA256: parts[0], Size: size, Path: path})
		previous = path
	}
	if err := scanner.Err(); err != nil || len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, errors.New("managed: RPM leaf manifest is incomplete")
	}
	return entries, nil
}

func canonicalRPMLeafSize(value string) bool {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}
