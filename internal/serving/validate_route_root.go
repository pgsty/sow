package serving

import (
	"container/heap"
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

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
)

type materializedRouteValidationHook func(phase, relative string) error
type materializedRouteValidationHookContextKey struct{}

const (
	materializedRouteValidationAfterInitialScan = "after-initial-scan"
	materializedRouteValidationAfterCASVerified = "after-cas-verified"
)

// withMaterializedRouteValidationHook is a deterministic test seam. A normal
// admission never installs a hook.
func withMaterializedRouteValidationHook(ctx context.Context, hook materializedRouteValidationHook) context.Context {
	return context.WithValue(ctx, materializedRouteValidationHookContextKey{}, hook)
}

func runMaterializedRouteValidationHook(ctx context.Context, phase, relative string) error {
	hook, _ := ctx.Value(materializedRouteValidationHookContextKey{}).(materializedRouteValidationHook)
	if hook == nil {
		return nil
	}
	if err := hook(phase, relative); err != nil {
		return fmt.Errorf("materialized route validation hook %s: %w", phase, err)
	}
	return nil
}

// ValidateMaterializedRouteRoot proves that one ordinary APT, YUM, or asset
// subtree is exactly the receipt-bound tree and can be served directly by
// Nginx. The caller supplies a retained target root; every route component is
// opened separately and retained for the whole check. Metadata is admitted by
// exact manifest bytes. Only entries in the payload manifest must additionally
// be the canonical CAS inode and survive a retained-descriptor rehash.
//
// The function is side-effect free apart from private temporary manifests and
// is deliberately safe to run again at the final output-commit barrier.
func ValidateMaterializedRouteRoot(ctx context.Context, pool *repository.Store, targetRoot *os.Root, route MaterializedRoute, exactManifestPath, payloadManifestPath string, options InstallOptions) (resultErr error) {
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("materialized route root validation: %w", resultErr)
		}
	}()
	if ctx == nil || pool == nil || targetRoot == nil {
		return errors.New("bound materialized-route validation dependencies are unavailable")
	}
	if err := route.Validate(); err != nil {
		return err
	}
	if options.Workers < 1 || options.ChunkEntries < 1 || options.TempDir == "" {
		return errors.New("materialized-route validation requires positive workers/chunk entries and a temp directory")
	}
	// Asset-only materializations do not otherwise need a manifest scan before
	// route admission, so the configured state scratch directory may not exist
	// yet. Establish one private validation workspace up front and keep every
	// claim/run file alive until both full scans and retained-CAS checks finish.
	if err := os.MkdirAll(options.TempDir, 0o700); err != nil {
		return fmt.Errorf("create materialized-route validation temp directory: %w", err)
	}
	tempInfo, err := os.Lstat(options.TempDir)
	if err != nil || !tempInfo.IsDir() || tempInfo.Mode()&os.ModeSymlink != 0 {
		return errors.Join(err, errors.New("materialized-route validation temp parent is not a real directory"))
	}
	validationTempDir, err := os.MkdirTemp(options.TempDir, "materialized-route-validation-")
	if err != nil {
		return fmt.Errorf("create private materialized-route validation workspace: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(validationTempDir)) }()
	options.TempDir = validationTempDir
	exact, err := openRetainedRouteManifest(exactManifestPath, route.ExactManifestSHA256)
	if err != nil {
		return fmt.Errorf("open exact route manifest: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, exact.Close()) }()
	payload, err := openRetainedRouteManifest(payloadManifestPath, route.PayloadManifestSHA256)
	if err != nil {
		return fmt.Errorf("open payload route manifest: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, payload.Close()) }()
	if err := exact.Verify(ctx); err != nil {
		return fmt.Errorf("verify exact route manifest: %w", err)
	}
	if err := payload.Verify(ctx); err != nil {
		return fmt.Errorf("verify payload route manifest: %w", err)
	}
	if err := validateRoutePayloadSubset(exact.File(), payload.File()); err != nil {
		return err
	}

	targetIdentity, err := targetRoot.Stat(".")
	if err != nil || !targetIdentity.IsDir() {
		return errors.Join(err, errors.New("materialized route target root is not a directory"))
	}
	if err := validateMaterializedRouteExactClaims(ctx, targetRoot, route.Claims, exact.File(), options); err != nil {
		return fmt.Errorf("initial materialized route scan: %w", err)
	}
	if err := runMaterializedRouteValidationHook(ctx, materializedRouteValidationAfterInitialScan, ""); err != nil {
		return err
	}
	if err := validateMaterializedRoutePayloadCAS(ctx, pool, targetRoot, payload.File()); err != nil {
		return fmt.Errorf("materialized route payload CAS validation: %w", err)
	}

	if err := exact.Verify(ctx); err != nil {
		return fmt.Errorf("final exact route manifest verification: %w", err)
	}
	if err := payload.Verify(ctx); err != nil {
		return fmt.Errorf("final payload route manifest verification: %w", err)
	}
	lastTarget, err := targetRoot.Stat(".")
	if err != nil || !lastTarget.IsDir() || !os.SameFile(targetIdentity, lastTarget) {
		return errors.Join(err, errors.New("materialized route target root changed during validation"))
	}
	// End on a second full byte scan. Metadata is not a CAS hardlink, so this
	// closes the otherwise larger window while payload inodes and receipt
	// manifests are being checked. The surrounding read-admission session runs
	// this complete validator again at its output commit barrier.
	if err := validateMaterializedRouteExactClaims(ctx, targetRoot, route.Claims, exact.File(), options); err != nil {
		return fmt.Errorf("final materialized route scan: %w", err)
	}
	return nil
}

type retainedRouteManifest struct {
	file     *os.File
	identity os.FileInfo
	want     string
}

func openRetainedRouteManifest(name, want string) (*retainedRouteManifest, error) {
	if name == "" || !hexSHA256Pattern.MatchString(want) {
		return nil, errors.New("invalid retained route manifest input")
	}
	before, err := os.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.Join(err, errors.New("route manifest is not a regular non-symlink file"))
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	after, lstatErr := os.Lstat(name)
	if statErr != nil || lstatErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		return nil, errors.Join(statErr, lstatErr, file.Close(), errors.New("route manifest coordinate changed while opening"))
	}
	return &retainedRouteManifest{file: file, identity: opened, want: want}, nil
}

func (value *retainedRouteManifest) File() *os.File {
	if value == nil {
		return nil
	}
	return value.file
}

func (value *retainedRouteManifest) Verify(ctx context.Context) error {
	if value == nil || value.file == nil || value.identity == nil {
		return errors.New("retained route manifest is unavailable")
	}
	if _, err := value.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hasher := sha256.New()
	reader := manifest.NewReader(io.TeeReader(routeContextReader{ctx: ctx, reader: value.file}, hasher))
	for {
		_, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	last, err := value.file.Stat()
	if err != nil || !os.SameFile(value.identity, last) || hex.EncodeToString(hasher.Sum(nil)) != value.want {
		return errors.Join(err, errors.New("retained route manifest bytes or identity changed"))
	}
	_, err = value.file.Seek(0, io.SeekStart)
	return err
}

func (value *retainedRouteManifest) Close() error {
	if value == nil || value.file == nil {
		return nil
	}
	return value.file.Close()
}

type routeContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader routeContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := reader.reader.Read(buffer)
	if err == nil {
		if contextErr := reader.ctx.Err(); contextErr != nil {
			return n, contextErr
		}
	}
	return n, err
}

func validateRoutePayloadSubset(exact, payload io.ReadSeeker) error {
	if exact == nil || payload == nil {
		return errors.New("materialized route manifests are unavailable")
	}
	if _, err := exact.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := payload.Seek(0, io.SeekStart); err != nil {
		return err
	}
	exactReader := manifest.NewReader(exact)
	payloadReader := manifest.NewReader(payload)
	exactEntry, exactErr := exactReader.Next()
	for {
		payloadEntry, payloadErr := payloadReader.Next()
		if errors.Is(payloadErr, io.EOF) {
			_, exactSeekErr := exact.Seek(0, io.SeekStart)
			_, payloadSeekErr := payload.Seek(0, io.SeekStart)
			return errors.Join(exactSeekErr, payloadSeekErr)
		}
		if payloadErr != nil {
			return payloadErr
		}
		for exactErr == nil && exactEntry.Path < payloadEntry.Path {
			exactEntry, exactErr = exactReader.Next()
		}
		if exactErr != nil && !errors.Is(exactErr, io.EOF) {
			return exactErr
		}
		if exactErr != nil || exactEntry.Path != payloadEntry.Path || exactEntry.Size != payloadEntry.Size || exactEntry.SHA256 != payloadEntry.SHA256 {
			return fmt.Errorf("payload route entry %s is absent or differs in the exact route manifest", payloadEntry.Path)
		}
	}
}

func validateMaterializedRouteExactClaims(ctx context.Context, targetRoot *os.Root, claims []MaterializedRouteClaim, exact *os.File, options InstallOptions) error {
	if targetRoot == nil || exact == nil || len(claims) == 0 {
		return errors.New("materialized route exact-claim inputs are unavailable")
	}
	claimManifests := make([]string, 0, len(claims))
	defer func() {
		for _, name := range claimManifests {
			_ = os.Remove(name)
		}
	}()
	for index, claim := range claims {
		if err := claim.Validate(); err != nil {
			return err
		}
		file, err := os.CreateTemp(options.TempDir, fmt.Sprintf("materialized-route-claim-%03d-*.tsv", index))
		if err != nil {
			return err
		}
		name := file.Name()
		if err := file.Close(); err != nil {
			return errors.Join(err, os.Remove(name))
		}
		claimManifests = append(claimManifests, name)
		switch claim.Kind {
		case MaterializedRouteClaimPrefix:
			if _, err := manifest.ScanRoot(ctx, targetRoot, manifest.Scope{Path: claim.RelativeRoot}, name, manifest.ScanOptions{
				Workers: options.Workers, ChunkEntries: options.ChunkEntries, TempDir: options.TempDir,
			}); err != nil {
				return fmt.Errorf("scan materialized route prefix claim: %w", err)
			}
			if err := ValidateHostableTreeRoot(targetRoot, claim.RelativeRoot); err != nil {
				return fmt.Errorf("validate materialized route prefix hostability: %w", err)
			}
		case MaterializedRouteClaimExactFile:
			if err := writeMaterializedRouteExactFileClaim(ctx, targetRoot, claim.RelativeRoot, name); err != nil {
				return fmt.Errorf("scan materialized route exact-file claim: %w", err)
			}
		case MaterializedRouteClaimGeneration:
			if err := scanMaterializedRouteGenerationClaim(ctx, targetRoot, claim, name, options); err != nil {
				return fmt.Errorf("scan materialized route generation claim: %w", err)
			}
			if err := validateMaterializedRouteClaimFilesHostable(targetRoot, name); err != nil {
				return err
			}
		}
	}
	actual, err := os.CreateTemp(options.TempDir, "materialized-route-actual-*.tsv")
	if err != nil {
		return err
	}
	actualPath := actual.Name()
	if err := actual.Close(); err != nil {
		return errors.Join(err, os.Remove(actualPath))
	}
	defer os.Remove(actualPath)
	if err := mergeMaterializedRouteClaimManifests(claimManifests, actualPath); err != nil {
		return fmt.Errorf("merge materialized route claim manifests: %w", err)
	}
	if _, err := exact.Seek(0, io.SeekStart); err != nil {
		return err
	}
	observed, err := os.Open(actualPath)
	if err != nil {
		return err
	}
	diff, diffErr := manifest.Diff(exact, observed, nil)
	closeErr := observed.Close()
	_, seekErr := exact.Seek(0, io.SeekStart)
	if diffErr != nil || closeErr != nil || seekErr != nil {
		return errors.Join(diffErr, closeErr, seekErr)
	}
	if !diff.Clean() {
		return fmt.Errorf("materialized route manifest drift: added=%d removed=%d changed=%d", diff.Added, diff.Removed, diff.Changed)
	}
	return nil
}

func scanMaterializedRouteGenerationClaim(ctx context.Context, targetRoot *os.Root, claim MaterializedRouteClaim, destination string, options InstallOptions) (resultErr error) {
	base, err := openMaterializedRouteDirectoryChain(targetRoot, claim.RelativeRoot)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, base.Close()) }()
	directory, err := base.Leaf().Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	var runs []string
	defer func() {
		for _, name := range runs {
			resultErr = errors.Join(resultErr, os.Remove(name))
		}
	}()
	for _, entry := range entries {
		generation := entry.Name()
		if !isMaterializedRouteGenerationID(generation) {
			continue
		}
		relativeLeaf := path.Join(generation, claim.Leaf)
		exists, err := probeMaterializedRouteDirectory(base.Leaf(), relativeLeaf)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		leaf, err := openMaterializedRouteDirectoryChain(base.Leaf(), relativeLeaf)
		if err != nil {
			return err
		}
		leafRuns := make([]string, 0, 2)
		for _, scope := range []manifest.Scope{{Path: "Packages", Include: []string{"*/*.rpm"}}, {Path: "repodata", Include: []string{"*"}}} {
			if scope.Path == "Packages" {
				exists, err := probeMaterializedRouteDirectory(leaf.Leaf(), scope.Path)
				if err != nil {
					_ = leaf.Close()
					return err
				}
				if !exists {
					// A valid empty YUM generation still has signed repodata but
					// contains no package payload directory.
					continue
				}
			}
			run, err := os.CreateTemp(options.TempDir, "materialized-route-generation-leaf-*.tsv")
			if err != nil {
				_ = leaf.Close()
				return err
			}
			runPath := run.Name()
			if err := run.Close(); err != nil {
				_ = leaf.Close()
				return errors.Join(err, os.Remove(runPath))
			}
			runs = append(runs, runPath)
			leafRuns = append(leafRuns, runPath)
			if _, err := manifest.ScanRoot(ctx, leaf.Leaf(), scope, runPath, manifest.ScanOptions{
				Workers: options.Workers, ChunkEntries: options.ChunkEntries, TempDir: options.TempDir,
			}); err != nil {
				_ = leaf.Close()
				return err
			}
		}
		combined, err := os.CreateTemp(options.TempDir, "materialized-route-generation-combined-*.tsv")
		if err != nil {
			_ = leaf.Close()
			return err
		}
		combinedPath := combined.Name()
		if err := combined.Close(); err != nil {
			_ = leaf.Close()
			return errors.Join(err, os.Remove(combinedPath))
		}
		runs = append(runs, combinedPath)
		if err := mergeMaterializedRouteClaimManifests(leafRuns, combinedPath); err != nil {
			_ = leaf.Close()
			return err
		}
		prefixed, err := os.CreateTemp(options.TempDir, "materialized-route-generation-prefixed-*.tsv")
		if err != nil {
			_ = leaf.Close()
			return err
		}
		prefixedPath := prefixed.Name()
		if err := prefixed.Close(); err != nil {
			_ = leaf.Close()
			return errors.Join(err, os.Remove(prefixedPath))
		}
		runs = append(runs, prefixedPath)
		if err := prefixMaterializedRouteManifest(combinedPath, prefixedPath, path.Join(claim.RelativeRoot, relativeLeaf)); err != nil {
			_ = leaf.Close()
			return err
		}
		if err := leaf.Verify(); err != nil {
			_ = leaf.Close()
			return err
		}
		if err := leaf.Close(); err != nil {
			return err
		}
	}
	var prefixed []string
	for _, name := range runs {
		if strings.Contains(filepath.Base(name), "generation-prefixed-") {
			prefixed = append(prefixed, name)
		}
	}
	if err := mergeMaterializedRouteClaimManifests(prefixed, destination); err != nil {
		return err
	}
	return base.Verify()
}

func isMaterializedRouteGenerationID(value string) bool {
	if len(value) != 20 {
		return false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func probeMaterializedRouteDirectory(root *os.Root, relative string) (_ bool, resultErr error) {
	if root == nil || validateMaterializedRouteRelativeRoot(relative) != nil {
		return false, errors.New("unsafe materialized route directory probe")
	}
	current := root
	var opened []*os.Root
	defer func() {
		for index := len(opened) - 1; index >= 0; index-- {
			resultErr = errors.Join(resultErr, opened[index].Close())
		}
	}()
	for _, component := range strings.Split(filepath.FromSlash(relative), string(filepath.Separator)) {
		before, err := current.Lstat(component)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			return false, errors.Join(err, fmt.Errorf("materialized generation branch %s is symlinked or not a directory", relative))
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			return false, err
		}
		bound, statErr := next.Stat(".")
		after, lstatErr := current.Lstat(component)
		if statErr != nil || lstatErr != nil || !os.SameFile(before, bound) || !os.SameFile(before, after) {
			_ = next.Close()
			return false, errors.Join(statErr, lstatErr, errors.New("materialized generation branch changed while probing"))
		}
		opened = append(opened, next)
		current = next
	}
	return true, nil
}

func prefixMaterializedRouteManifest(source, destination, prefix string) (resultErr error) {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, input.Close()) }()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, output.Close()) }()
	reader := manifest.NewReader(input)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		entry.Path = path.Join(prefix, entry.Path)
		if err := manifest.WriteEntry(output, entry); err != nil {
			return err
		}
	}
}

func writeMaterializedRouteExactFileClaim(ctx context.Context, root *os.Root, relative, destination string) (resultErr error) {
	file, info, coordinate, closeParents, err := openMaterializedRouteFile(root, relative)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close(), closeParents()) }()
	if info.Mode().Perm() != 0o444 {
		return fmt.Errorf("materialized route exact file %s mode=%#o want=0444", relative, info.Mode().Perm())
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, routeContextReader{ctx: ctx, reader: file})
	last, statErr := file.Stat()
	current, coordinateErr := coordinate()
	if err != nil || statErr != nil || coordinateErr != nil || written != info.Size() || last.Mode().Perm() != 0o444 || current.Mode().Perm() != 0o444 ||
		!os.SameFile(info, last) || !os.SameFile(info, current) {
		return errors.Join(err, statErr, coordinateErr, fmt.Errorf("materialized route exact file %s changed while hashing", relative))
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	writeErr := manifest.WriteEntry(output, manifest.Entry{Path: relative, Size: written, SHA256: digest})
	return errors.Join(writeErr, output.Close())
}

func validateMaterializedRouteClaimFilesHostable(root *os.Root, manifestPath string) error {
	file, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := ValidateHostableFileRoot(root, entry.Path); err != nil {
			return err
		}
	}
}

type materializedRouteManifestRun struct {
	index  int
	file   *os.File
	reader *manifest.Reader
	entry  manifest.Entry
}

type materializedRouteManifestHeap []*materializedRouteManifestRun

func (value materializedRouteManifestHeap) Len() int { return len(value) }
func (value materializedRouteManifestHeap) Less(i, j int) bool {
	if value[i].entry.Path == value[j].entry.Path {
		return value[i].index < value[j].index
	}
	return value[i].entry.Path < value[j].entry.Path
}
func (value materializedRouteManifestHeap) Swap(i, j int) { value[i], value[j] = value[j], value[i] }
func (value *materializedRouteManifestHeap) Push(item any) {
	*value = append(*value, item.(*materializedRouteManifestRun))
}
func (value *materializedRouteManifestHeap) Pop() any {
	old := *value
	item := old[len(old)-1]
	*value = old[:len(old)-1]
	return item
}

func mergeMaterializedRouteClaimManifests(sources []string, destination string) (resultErr error) {
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, output.Close()) }()
	runs := make([]*materializedRouteManifestRun, 0, len(sources))
	defer func() {
		for _, run := range runs {
			resultErr = errors.Join(resultErr, run.file.Close())
		}
	}()
	queue := materializedRouteManifestHeap{}
	for index, name := range sources {
		file, err := os.Open(name)
		if err != nil {
			return fmt.Errorf("open materialized route claim source %d: %w", index, err)
		}
		run := &materializedRouteManifestRun{index: index, file: file, reader: manifest.NewReader(file)}
		runs = append(runs, run)
		entry, err := run.reader.Next()
		if errors.Is(err, io.EOF) {
			continue
		}
		if err != nil {
			return err
		}
		run.entry = entry
		heap.Push(&queue, run)
	}
	heap.Init(&queue)
	last := ""
	for queue.Len() > 0 {
		run := heap.Pop(&queue).(*materializedRouteManifestRun)
		if run.entry.Path == last {
			return fmt.Errorf("materialized route claims overlap at %s", run.entry.Path)
		}
		if err := manifest.WriteEntry(output, run.entry); err != nil {
			return err
		}
		last = run.entry.Path
		entry, err := run.reader.Next()
		if errors.Is(err, io.EOF) {
			continue
		}
		if err != nil {
			return err
		}
		run.entry = entry
		heap.Push(&queue, run)
	}
	return nil
}

type materializedRouteDirectoryChain struct {
	root         *os.Root
	rootIdentity os.FileInfo
	edges        []materializedRouteDirectoryEdge
}

func openMaterializedRouteFile(root *os.Root, relative string) (*os.File, os.FileInfo, func() (os.FileInfo, error), func() error, error) {
	if root == nil || relative == "" || filepath.ToSlash(filepath.Clean(filepath.FromSlash(relative))) != relative {
		return nil, nil, nil, nil, errors.New("unsafe materialized route file path")
	}
	name := filepath.FromSlash(relative)
	directory, base := filepath.Dir(name), filepath.Base(name)
	parent := root
	var chain *materializedRouteDirectoryChain
	var err error
	if directory != "." {
		chain, err = openMaterializedRouteDirectoryChain(root, filepath.ToSlash(directory))
		if err != nil {
			return nil, nil, nil, nil, err
		}
		parent = chain.Leaf()
	}
	closeParents := func() error {
		if chain == nil {
			return nil
		}
		return chain.Close()
	}
	fail := func(err error) (*os.File, os.FileInfo, func() (os.FileInfo, error), func() error, error) {
		return nil, nil, nil, nil, errors.Join(err, closeParents())
	}
	before, err := parent.Lstat(base)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return fail(errors.Join(err, fmt.Errorf("materialized route file %s is not a regular non-symlink file", relative)))
	}
	file, err := parent.Open(base)
	if err != nil {
		return fail(err)
	}
	opened, statErr := file.Stat()
	after, lstatErr := parent.Lstat(base)
	if statErr != nil || lstatErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		return nil, nil, nil, nil, errors.Join(statErr, lstatErr, file.Close(), closeParents(), fmt.Errorf("materialized route file %s changed while opening", relative))
	}
	coordinate := func() (os.FileInfo, error) { return parent.Lstat(base) }
	return file, opened, coordinate, closeParents, nil
}

type materializedRouteDirectoryEdge struct {
	parent    *os.Root
	component string
	prefix    string
	child     *os.Root
	identity  os.FileInfo
	mode      os.FileMode
}

func openMaterializedRouteDirectoryChain(root *os.Root, relative string) (_ *materializedRouteDirectoryChain, resultErr error) {
	if root == nil {
		return nil, errors.New("materialized route root is unavailable")
	}
	if err := validateMaterializedRouteRelativeRoot(relative); err != nil {
		return nil, err
	}
	rootIdentity, err := root.Stat(".")
	if err != nil || !rootIdentity.IsDir() {
		return nil, errors.Join(err, errors.New("materialized route target root is not a directory"))
	}
	chain := &materializedRouteDirectoryChain{root: root, rootIdentity: rootIdentity}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, chain.Close())
		}
	}()
	current := root
	prefix := ""
	for _, component := range strings.Split(filepath.FromSlash(relative), string(filepath.Separator)) {
		prefix = filepath.Join(prefix, component)
		before, err := current.Lstat(component)
		if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			return nil, errors.Join(err, fmt.Errorf("materialized route directory %s is not a real directory", filepath.ToSlash(prefix)))
		}
		wanted := os.FileMode(0o755)
		if filepath.ToSlash(prefix) == stateServingCorridorDirectory {
			wanted = 0o711
		}
		if before.Mode().Perm() != wanted {
			return nil, fmt.Errorf("materialized route directory %s mode=%#o want=%#o", filepath.ToSlash(prefix), before.Mode().Perm(), wanted)
		}
		child, err := current.OpenRoot(component)
		if err != nil {
			return nil, err
		}
		opened, statErr := child.Stat(".")
		after, lstatErr := current.Lstat(component)
		if statErr != nil || lstatErr != nil || opened.Mode().Perm() != wanted || after.Mode().Perm() != wanted ||
			after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(before, after) {
			_ = child.Close()
			return nil, errors.Join(statErr, lstatErr, fmt.Errorf("materialized route directory %s changed while opening", filepath.ToSlash(prefix)))
		}
		chain.edges = append(chain.edges, materializedRouteDirectoryEdge{
			parent: current, component: component, prefix: prefix, child: child, identity: opened, mode: wanted,
		})
		current = child
	}
	if err := chain.Verify(); err != nil {
		return nil, err
	}
	return chain, nil
}

func (chain *materializedRouteDirectoryChain) Leaf() *os.Root {
	if chain == nil || len(chain.edges) == 0 {
		return nil
	}
	return chain.edges[len(chain.edges)-1].child
}

func (chain *materializedRouteDirectoryChain) Verify() error {
	if chain == nil || chain.root == nil || chain.rootIdentity == nil || len(chain.edges) == 0 {
		return errors.New("materialized route directory chain is unavailable")
	}
	rootInfo, rootErr := chain.root.Stat(".")
	if rootErr != nil || !rootInfo.IsDir() || !os.SameFile(chain.rootIdentity, rootInfo) {
		return errors.Join(rootErr, errors.New("materialized route target root changed"))
	}
	for _, edge := range chain.edges {
		parentInfo, parentErr := edge.parent.Lstat(edge.component)
		childInfo, childErr := edge.child.Stat(".")
		if parentErr != nil || childErr != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || !childInfo.IsDir() ||
			parentInfo.Mode().Perm() != edge.mode || childInfo.Mode().Perm() != edge.mode ||
			!os.SameFile(edge.identity, parentInfo) || !os.SameFile(edge.identity, childInfo) {
			return errors.Join(parentErr, childErr, fmt.Errorf("materialized route directory component %s changed", filepath.ToSlash(edge.prefix)))
		}
	}
	return nil
}

func (chain *materializedRouteDirectoryChain) Close() error {
	if chain == nil {
		return nil
	}
	var result error
	for index := len(chain.edges) - 1; index >= 0; index-- {
		result = errors.Join(result, chain.edges[index].child.Close())
	}
	chain.edges = nil
	return result
}

func validateMaterializedRoutePayloadCAS(ctx context.Context, pool *repository.Store, routeRoot *os.Root, payload *os.File) error {
	if _, err := payload.Seek(0, io.SeekStart); err != nil {
		return err
	}
	reader := manifest.NewReader(payload)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			_, seekErr := payload.Seek(0, io.SeekStart)
			return seekErr
		}
		if err != nil {
			return err
		}
		if err := validateMaterializedRoutePayloadEntry(ctx, pool, routeRoot, entry); err != nil {
			return err
		}
	}
}

func validateMaterializedRoutePayloadEntry(ctx context.Context, pool *repository.Store, routeRoot *os.Root, entry manifest.Entry) (resultErr error) {
	target, targetInfo, coordinate, closeParents, err := openMaterializedRouteFile(routeRoot, entry.Path)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, target.Close(), closeParents()) }()
	if targetInfo.Mode().Perm() != 0o444 {
		return fmt.Errorf("materialized route payload %s mode=%#o want=0444", entry.Path, targetInfo.Mode().Perm())
	}
	identity := repository.Object{SHA256: repository.Digest(entry.SHA256), Size: entry.Size}
	object, err := pool.OpenVerified(ctx, identity)
	if err != nil {
		return fmt.Errorf("open route CAS object for %s: %w", entry.Path, err)
	}
	defer func() { resultErr = errors.Join(resultErr, object.Close()) }()
	objectInfo, objectStatErr := object.Stat()
	if objectStatErr != nil || targetInfo.Size() != entry.Size || objectInfo.Size() != entry.Size || !os.SameFile(targetInfo, objectInfo) {
		return errors.Join(objectStatErr, fmt.Errorf("materialized route payload %s is not the canonical CAS hardlink", entry.Path))
	}
	if err := runMaterializedRouteValidationHook(ctx, materializedRouteValidationAfterCASVerified, entry.Path); err != nil {
		return err
	}
	lastTarget, lastTargetErr := target.Stat()
	current, coordinateErr := coordinate()
	reverifyErr := repository.VerifyOpenedObject(ctx, object, identity)
	if lastTargetErr != nil || coordinateErr != nil || reverifyErr != nil ||
		lastTarget.Mode().Perm() != 0o444 || current.Mode().Perm() != 0o444 ||
		!os.SameFile(targetInfo, lastTarget) || !os.SameFile(targetInfo, current) {
		return errors.Join(lastTargetErr, coordinateErr, reverifyErr, fmt.Errorf("materialized route payload %s changed during retained rehash", entry.Path))
	}
	return nil
}
