package managed

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
	"github.com/pgsty/sow/internal/yumrepo"
	"golang.org/x/sys/unix"
)

type APTMetadataVerifier interface {
	Verify(context.Context, []byte, []byte, []byte, time.Time) error
}

type APTMetadataSigner interface {
	APTMetadataVerifier
	Validate(context.Context, time.Time) error
	ClearSign(context.Context, io.Writer, io.Reader, time.Time) error
	DetachedSign(context.Context, io.Writer, io.Reader, time.Time) error
}

// managedAPTReleaseContract is included in the effective Dist identity and in
// every Release rendered by the current implementation. The generation field
// makes a metadata-only APT publication physically distinct even when its
// package indexes and whole-second publication timestamp are unchanged.
const managedAPTReleaseContract = "sow.apt-release/v2"

type ManagedDistSpec struct {
	Name          string
	Format        string
	Architectures []state.Architecture
	Generation    state.GenerationID
	Jobs          int
	PublishedAt   time.Time
	Packages      []ManagedPackageSource
	RPMSigner     yumrepo.DetachedSigner
	APTSigner     APTMetadataSigner
}

type ManagedPackageSource struct {
	Object   state.PackageObject
	Path     string
	Owner    string
	Relative string
	RPMFacts *yumrepo.PackageFacts
	DEBFacts *aptrepo.Package
}

func (source ManagedPackageSource) open() (*rootedRegularFile, error) {
	owner, relative := source.Owner, source.Relative
	if owner == "" {
		owner, relative = filepath.Dir(source.Path), filepath.Base(source.Path)
	}
	opened, err := openRootedRegular(owner, relative)
	if err != nil {
		return nil, err
	}
	if opened.before.Size() != source.Object.Size {
		return nil, errors.Join(fmt.Errorf("managed: package source %s has unexpected size", source.Object.SHA256), opened.CloseVerified())
	}
	return opened, nil
}

// pendingSourceGuard snapshots every private pending inode before rendering and
// rebinds the same pathname afterward. Keeping every file and root descriptor
// open would consume two descriptors per object. Under Managed's workspace
// lock and trusted local single-writer model, snapshots detect persistent path
// replacement and link-count changes with bounded FDs; they intentionally do
// not claim to defeat a same-user replace-and-restore attack during the build.
type pendingSourceGuard struct {
	entries map[string]pendingSourceGuardEntry
}

type pendingSourceGuardEntry struct {
	owner    string
	relative string
	size     int64
	before   os.FileInfo
	stat     unix.Stat_t
}

func newPendingSourceGuard(sources []ManagedPackageSource) (*pendingSourceGuard, error) {
	guard := &pendingSourceGuard{entries: map[string]pendingSourceGuardEntry{}}
	for _, source := range sources {
		if source.Object.Storage != "pending" {
			continue
		}
		if _, exists := guard.entries[source.Object.SHA256]; exists {
			continue
		}
		opened, err := source.open()
		if err != nil {
			return nil, errors.Join(err, guard.Close())
		}
		if opened.stat.Nlink != 1 {
			return nil, errors.Join(fmt.Errorf("%w: pending package source %s is multiply linked before build", ErrIntegrity, source.Object.SHA256), opened.CloseVerified(), guard.Close())
		}
		owner, relative := source.Owner, source.Relative
		if owner == "" {
			owner, relative = filepath.Dir(source.Path), filepath.Base(source.Path)
		}
		entry := pendingSourceGuardEntry{owner: owner, relative: relative, size: source.Object.Size, before: opened.before, stat: opened.stat}
		if err := opened.CloseVerified(); err != nil {
			return nil, errors.Join(err, guard.Close())
		}
		guard.entries[source.Object.SHA256] = entry
	}
	return guard, nil
}

func (guard *pendingSourceGuard) Close() error {
	if guard == nil {
		return nil
	}
	var result error
	digests := make([]string, 0, len(guard.entries))
	for digest := range guard.entries {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	for _, digest := range digests {
		entry := guard.entries[digest]
		source := ManagedPackageSource{Object: state.PackageObject{SHA256: digest, Size: entry.size}, Owner: entry.owner, Relative: entry.relative}
		opened, err := source.open()
		if err != nil {
			result = errors.Join(result, fmt.Errorf("%w: pending package %s changed during build: %v", ErrIntegrity, digest, err))
			continue
		}
		sameIdentity := os.SameFile(entry.before, opened.before) &&
			entry.before.Size() == opened.before.Size() && entry.before.ModTime().Equal(opened.before.ModTime()) &&
			entry.stat.Dev == opened.stat.Dev && entry.stat.Ino == opened.stat.Ino && entry.stat.Size == opened.stat.Size
		if !sameIdentity || opened.stat.Nlink != 1 {
			result = errors.Join(result, fmt.Errorf("%w: pending package %s was replaced or multiply linked during build", ErrIntegrity, digest))
		}
		result = errors.Join(result, opened.CloseVerified())
	}
	guard.entries = nil
	return result
}

// RenderManagedDist renders a complete non-empty-capable Dist under a private
// repository stage. RPM views contain metadata-only parent-relative hrefs;
// DEB views use raw root Pool Filenames plus by-hash index hardlinks.
func RenderManagedDist(ctx context.Context, repositoryStage string, spec ManagedDistSpec) (RenderedDist, error) {
	if ctx == nil {
		return RenderedDist{}, errors.New("managed: nil context")
	}
	if spec.Name == "" || strings.ContainsAny(spec.Name, "/\\") || spec.Generation < 1 {
		return RenderedDist{}, errors.New("managed: invalid managed Dist spec")
	}
	if spec.Format != "rpm" && spec.Format != "deb" {
		return RenderedDist{}, fmt.Errorf("managed: unsupported Dist format %q", spec.Format)
	}
	ctx = workmetrics.WithPhase(ctx, "render_"+spec.Format)
	if spec.Jobs < 1 {
		spec.Jobs = 1
	}
	if spec.PublishedAt.IsZero() {
		if spec.RPMSigner != nil || spec.APTSigner != nil {
			return RenderedDist{}, errors.New("managed: signed Dist publication time is required")
		}
		spec.PublishedAt = time.Unix(0, 0).UTC()
	} else {
		spec.PublishedAt = spec.PublishedAt.UTC()
	}
	if _, err := validateFamilies(familiesOf(spec.Architectures)); err != nil {
		return RenderedDist{}, err
	}
	root, err := filepath.Abs(repositoryStage)
	if err != nil {
		return RenderedDist{}, err
	}
	if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return RenderedDist{}, fmt.Errorf("managed: repository stage is not a real directory: %w", err)
	}
	dists := filepath.Join(root, "dists")
	if _, err := durableEnsureDir(dists, 0o755); err != nil {
		return RenderedDist{}, err
	}
	distRoot := filepath.Join(dists, spec.Name)
	if err := durableMkdir(distRoot, 0o755); err != nil {
		return RenderedDist{}, err
	}
	for _, source := range spec.Packages {
		if source.Object.Format != spec.Format || source.Path == "" {
			return RenderedDist{}, errors.New("managed: package source does not match Dist format")
		}
		opened, err := source.open()
		if err != nil {
			return RenderedDist{}, fmt.Errorf("managed: package source %s is missing or unsafe: %w", source.Object.SHA256, err)
		}
		if err := opened.CloseVerified(); err != nil {
			return RenderedDist{}, err
		}
	}
	if spec.Format == "rpm" {
		err = renderManagedRPMDist(ctx, root, distRoot, spec)
	} else {
		err = renderManagedDEBDist(ctx, distRoot, spec)
	}
	if err != nil {
		return RenderedDist{}, err
	}
	if err := syncTree(distRoot); err != nil {
		return RenderedDist{}, err
	}
	if err := errors.Join(syncDir(dists), syncDir(root)); err != nil {
		return RenderedDist{}, err
	}
	digest, files, err := digestTree(ctx, distRoot)
	if err != nil {
		return RenderedDist{}, err
	}
	return RenderedDist{Path: distRoot, TreeSHA256: digest, Files: files}, nil
}

func renderManagedRPMDist(ctx context.Context, repositoryRoot, distRoot string, spec ManagedDistSpec) error {
	repositoryBase := &url.URL{Scheme: "file", Path: filepath.ToSlash(repositoryRoot) + "/"}
	for _, architecture := range spec.Architectures {
		view := filepath.Join(distRoot, architecture.Family)
		if err := durableMkdir(view, 0o755); err != nil {
			return err
		}
		viewRelative, err := filepath.Rel(repositoryRoot, view)
		if err != nil {
			return err
		}
		viewPath, err := yumrepo.ParseManagedRPMViewPath(filepath.ToSlash(viewRelative))
		if err != nil {
			return fmt.Errorf("managed: invalid RPM view %s: %w", architecture.Family, err)
		}
		type parsedInput struct {
			location string
			pkg      *yumrepo.ParsedManagedPackage
		}
		parsed := []parsedInput{}
		for _, source := range spec.Packages {
			object := source.Object
			if object.CanonicalArch != "neutral" && object.CanonicalArch != architecture.Family {
				continue
			}
			poolPath, err := yumrepo.ParseManagedPoolPath(object.PoolPath)
			if err != nil || poolPath.Filename() != object.Filename || poolPath.Source() != object.Source {
				return fmt.Errorf("%w: RPM package %s has an invalid canonical Pool path", ErrIntegrity, object.SHA256)
			}
			href, err := yumrepo.RPMParentRelativeHref(viewPath, poolPath)
			if err != nil {
				return err
			}
			if err := yumrepo.ValidateRPMHrefRoundTrip(repositoryBase, viewPath, poolPath, href.String()); err != nil {
				return fmt.Errorf("managed: render RPM href for %s: %w", object.SHA256, err)
			}
			if source.RPMFacts == nil {
				return fmt.Errorf("%w: RPM facts are unavailable for %s", ErrIntegrity, object.SHA256)
			}
			projected, err := yumrepo.ProjectManagedPackageFacts(source.RPMFacts, yumrepo.PackageInput{Path: source.Path, Basename: object.Filename, PoolPath: object.PoolPath, ViewPath: viewPath, Location: href.String()})
			if err != nil {
				return fmt.Errorf("%w: project RPM facts for %s: %v", ErrIntegrity, object.SHA256, err)
			}
			parsed = append(parsed, parsedInput{location: href.String(), pkg: projected})
		}
		sort.Slice(parsed, func(i, j int) bool { return parsed[i].location < parsed[j].location })
		packages := make([]*yumrepo.ParsedManagedPackage, len(parsed))
		for index := range parsed {
			packages[index] = parsed[index].pkg
		}
		if _, err := yumrepo.GenerateManagedParsedConcurrent(ctx, filepath.Join(view, "repodata"), uint64(spec.Generation), packages, spec.RPMSigner, spec.Jobs); err != nil {
			return fmt.Errorf("managed: render RPM view %s: %w", architecture.Family, err)
		}
	}
	return nil
}

func renderManagedDEBDist(ctx context.Context, distRoot string, spec ManagedDistSpec) error {
	parsed := make(map[string]aptrepo.Package, len(spec.Packages))
	for _, source := range spec.Packages {
		if err := ctx.Err(); err != nil {
			return err
		}
		if source.DEBFacts == nil {
			return fmt.Errorf("%w: DEB facts are unavailable for %s", ErrIntegrity, source.Object.SHA256)
		}
		pkg := *source.DEBFacts
		if pkg.SHA256 != source.Object.SHA256 || pkg.Name != source.Object.Name || pkg.Version != source.Object.Version || pkg.Architecture != source.Object.Architecture {
			return fmt.Errorf("%w: DEB pool object %s differs from state", ErrIntegrity, source.Object.SHA256)
		}
		parsed[source.Object.SHA256] = pkg
	}
	workers := spec.Jobs
	if workers > len(spec.Architectures) {
		workers = len(spec.Architectures)
	}
	results := make([][]releaseArtifact, len(spec.Architectures))
	issues := make([]error, len(spec.Architectures))
	if workers > 0 {
		indices := make(chan int)
		var group sync.WaitGroup
		group.Add(workers)
		for range workers {
			go func() {
				defer group.Done()
				for index := range indices {
					results[index], issues[index] = renderManagedDEBArchitecture(ctx, distRoot, spec, spec.Architectures[index], parsed)
				}
			}()
		}
		for index := range spec.Architectures {
			indices <- index
		}
		close(indices)
		group.Wait()
	}
	artifacts := []releaseArtifact{}
	for index := range spec.Architectures {
		if issues[index] != nil {
			return issues[index]
		}
		artifacts = append(artifacts, results[index]...)
	}
	releaseTime := spec.PublishedAt
	release := renderManagedRelease(spec, releaseTime, artifacts)
	releasePath := filepath.Join(distRoot, "Release")
	if err := writeAtomic(releasePath, release, 0o644); err != nil {
		return err
	}
	if spec.APTSigner != nil {
		if err := spec.APTSigner.Validate(ctx, releaseTime); err != nil {
			return err
		}
		inRelease := &bytes.Buffer{}
		detached := &bytes.Buffer{}
		if err := spec.APTSigner.ClearSign(ctx, inRelease, bytes.NewReader(release), releaseTime); err != nil {
			return err
		}
		if err := spec.APTSigner.DetachedSign(ctx, detached, bytes.NewReader(release), releaseTime); err != nil {
			return err
		}
		if err := spec.APTSigner.Verify(ctx, release, inRelease.Bytes(), detached.Bytes(), releaseTime); err != nil {
			return err
		}
		if err := writeAtomic(filepath.Join(distRoot, "InRelease"), inRelease.Bytes(), 0o644); err != nil {
			return err
		}
		if err := writeAtomic(filepath.Join(distRoot, "Release.gpg"), detached.Bytes(), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func renderManagedDEBArchitecture(ctx context.Context, distRoot string, spec ManagedDistSpec, architecture state.Architecture, parsed map[string]aptrepo.Package) ([]releaseArtifact, error) {
	binaryRoot := filepath.Join(distRoot, "main", "binary-"+architecture.EcosystemArch)
	if err := durableEnsureDirectoryTree(distRoot, binaryRoot, 0o755); err != nil {
		return nil, err
	}
	packages := make([]state.PackageObject, 0)
	for _, source := range spec.Packages {
		if source.Object.CanonicalArch == "neutral" || source.Object.CanonicalArch == architecture.Family {
			packages = append(packages, source.Object)
		}
	}
	sort.Slice(packages, func(i, j int) bool {
		left, right := parsed[packages[i].SHA256], parsed[packages[j].SHA256]
		return aptrepo.ComparePackages(left, right) < 0
	})
	packagesPath := filepath.Join(binaryRoot, "Packages")
	created, err := createRootedRegular(binaryRoot, "Packages", 0o644)
	if err != nil {
		return nil, err
	}
	writer, err := aptrepo.NewPackagesWriter(created.file)
	if err == nil {
		for _, object := range packages {
			if err = writer.WriteManaged(parsed[object.SHA256], object.PoolPath); err != nil {
				break
			}
		}
	}
	if err != nil {
		return nil, errors.Join(err, created.Abort())
	}
	if err := created.Commit(); err != nil {
		return nil, err
	}
	plainArtifact, err := inspectReleaseArtifact(packagesPath, filepath.ToSlash(filepath.Join("main", "binary-"+architecture.EcosystemArch, "Packages")))
	if err != nil {
		return nil, err
	}
	gzipPath := packagesPath + ".gz"
	if err := writeDeterministicGzip(packagesPath, gzipPath); err != nil {
		return nil, err
	}
	gzipArtifact, err := inspectReleaseArtifact(gzipPath, plainArtifact.Path+".gz")
	if err != nil {
		return nil, err
	}
	artifacts := []releaseArtifact{plainArtifact, gzipArtifact}
	for _, artifact := range []releaseArtifact{plainArtifact, gzipArtifact} {
		byHash := filepath.Join(binaryRoot, "by-hash", "SHA256", artifact.SHA256)
		source := packagesPath
		if strings.HasSuffix(artifact.Path, ".gz") {
			source = gzipPath
		}
		if err := ensureHardlinkAlias(ctx, binaryRoot, source, byHash, artifact.Size, artifact.SHA256); err != nil {
			return nil, err
		}
	}
	return artifacts, nil
}

type releaseArtifact struct {
	Path   string
	Size   int64
	SHA256 string
}

func inspectReleaseArtifact(filename, relative string) (releaseArtifact, error) {
	opened, err := openRootedRegular(filepath.Dir(filename), filepath.Base(filename))
	if err != nil {
		return releaseArtifact{}, err
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, opened.file)
	closeErr := opened.CloseVerified()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return releaseArtifact{}, err
	}
	return releaseArtifact{Path: relative, Size: size, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func writeDeterministicGzip(source, target string) error {
	opened, err := openRootedRegular(filepath.Dir(source), filepath.Base(source))
	if err != nil {
		return err
	}
	created, err := createRootedRegular(filepath.Dir(target), filepath.Base(target), 0o644)
	if err != nil {
		return errors.Join(err, opened.CloseVerified())
	}
	zw, err := gzip.NewWriterLevel(created.file, gzip.BestCompression)
	if err != nil {
		return errors.Join(err, created.Abort(), opened.CloseVerified())
	}
	zw.Header.ModTime = time.Unix(0, 0).UTC()
	zw.Header.OS = 255
	_, copyErr := io.Copy(zw, opened.file)
	if err := errors.Join(copyErr, zw.Close(), opened.CloseVerified()); err != nil {
		return errors.Join(err, created.Abort())
	}
	return created.Commit()
}

func renderManagedRelease(spec ManagedDistSpec, at time.Time, artifacts []releaseArtifact) []byte {
	architectures := make([]string, 0, len(spec.Architectures))
	for _, architecture := range spec.Architectures {
		architectures = append(architectures, architecture.EcosystemArch)
	}
	sort.Strings(architectures)
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	var output strings.Builder
	fmt.Fprintf(&output, "Origin: SOW\nLabel: %s\nSuite: %s\nCodename: %s\n", spec.Name, spec.Name, spec.Name)
	fmt.Fprintf(&output, "Date: %s\nX-SOW-Generation: %d\nArchitectures: %s\nComponents: main\nAcquire-By-Hash: yes\n", at.Format(time.RFC1123), spec.Generation, strings.Join(architectures, " "))
	output.WriteString("Description: SOW managed distribution\nSHA256:\n")
	for _, artifact := range artifacts {
		fmt.Fprintf(&output, " %s %s %s\n", artifact.SHA256, strconv.FormatInt(artifact.Size, 10), artifact.Path)
	}
	return []byte(output.String())
}

func ensureHardlinkAlias(ctx context.Context, viewRoot, source, target string, expectedSize int64, expectedSHA string) error {
	sourceRelative, err := relativeToRoot(viewRoot, source)
	if err != nil {
		return err
	}
	targetRelative, err := relativeToRoot(viewRoot, target)
	if err != nil {
		return err
	}
	return linkRootedRegular(ctx, viewRoot, sourceRelative, viewRoot, targetRelative, expectedSize, expectedSHA, 0o755)
}

func familiesOf(architectures []state.Architecture) []string {
	result := make([]string, len(architectures))
	for index := range architectures {
		result[index] = architectures[index].Family
	}
	return result
}
