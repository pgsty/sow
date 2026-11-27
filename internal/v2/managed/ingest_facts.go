package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
	"github.com/pgsty/sow/internal/yumrepo"
)

type inputFile struct {
	Path    string
	Display string
	Base    string
}

type inspectedInput struct {
	SHA256     string
	Object     state.PackageObject
	FactSchema string
	Facts      []byte
	Err        error
}

type probedInput struct {
	opened *rootedRegularFile
	before rootedRegularIdentity
	object state.PackageObject // Unauthenticated routing fields; no digest/facts.
}

func inputCoordinateKey(object state.PackageObject) string {
	return object.Format + "\x00" + object.Coordinate
}

// inspectInputs skips temporary copies only for coordinates already in the
// repository. New inputs are staged independently; Add resolves batch conflicts
// in input order after inspection, without reopening the external inputs.
func inspectInputs(ctx context.Context, inputsRoot string, files []inputFile, workers int, store *state.Store) ([]inspectedInput, []coordinateLookup) {
	ctx = workmetrics.WithPhase(ctx, "ingest")
	results := make([]inspectedInput, len(files))
	lookups := make([]coordinateLookup, len(files))
	if workers < 1 {
		workers = 1
	}
	queue := make(chan int)
	var group sync.WaitGroup
	for range min(workers, len(files)) {
		group.Go(func() {
			for index := range queue {
				probe, err := openInputProbe(ctx, files[index])
				if err != nil {
					results[index].Err = err
					continue
				}
				existing, err := store.FindPackageByCoordinate(ctx, probe.object.Format, probe.object.Coordinate)
				lookups[index] = coordinateLookup{object: existing, err: err}
				if err != nil && !errors.Is(err, state.ErrNotFound) {
					results[index].Err = errors.Join(err, probe.opened.CloseVerified())
					continue
				}
				snapshot := filepath.Join(inputsRoot, fmt.Sprintf("%08d-%s", index, files[index].Base))
				results[index] = inspectProbedInput(ctx, probe, snapshot, files[index].Base, errors.Is(err, state.ErrNotFound))
			}
		})
	}
	for index := range files {
		queue <- index
	}
	close(queue)
	group.Wait()
	return results, lookups
}

func openInputProbe(ctx context.Context, input inputFile) (*probedInput, error) {
	opened, err := openRootedRegular(filepath.Dir(input.Path), filepath.Base(input.Path))
	if err != nil {
		return nil, fmt.Errorf("managed: package input is not a safely rooted regular file: %w", err)
	}
	before, err := snapshotRootedRegularIdentity(opened)
	if err != nil {
		return nil, errors.Join(err, opened.CloseVerified())
	}
	object, err := probeInputCoordinate(ctx, opened.file, input.Base, before.size)
	if err != nil {
		return nil, errors.Join(err, opened.CloseVerified())
	}
	return &probedInput{opened: opened, before: before, object: object}, nil
}

func probeInputCoordinate(ctx context.Context, file *os.File, basename string, size int64) (state.PackageObject, error) {
	if strings.HasSuffix(basename, ".rpm") {
		hint, err := yumrepo.ProbePackageCoordinateReader(ctx, file, basename, size)
		if err != nil {
			return state.PackageObject{}, err
		}
		return rpmObjectFromInfo(yumrepo.PackageInfo{Name: hint.Name, Source: hint.Source, SourceRPM: hint.SourceRPM, Version: hint.Version, Release: hint.Release, Arch: hint.Arch, Epoch: hint.Epoch, Size: size}, basename, "")
	}
	hint, err := aptrepo.ProbePackageCoordinateReader(ctx, file, "main", basename, size)
	if err != nil {
		return state.PackageObject{}, err
	}
	return debObjectFromInfo(aptrepo.Package{Name: hint.Name, Source: hint.Source, Version: hint.Version, Architecture: hint.Architecture, Size: size}, basename)
}

// inspectProbedInput owns one held source descriptor. A retry discards all
// metadata and digests and starts again before parsing. There are at most two
// whole attempts, never an inner hash retry that could bless older facts.
func inspectProbedInput(ctx context.Context, probe *probedInput, snapshot, basename string, copyPayload bool) (result inspectedInput) {
	defer func() { result.Err = errors.Join(result.Err, probe.opened.CloseVerified()) }()
	before := probe.before
	var previousDigest string
	for attempt := 0; attempt < 2; attempt++ {
		if attempt != 0 {
			hint, err := probeInputCoordinate(ctx, probe.opened.file, basename, before.size)
			if err != nil {
				return inspectedInput{Err: err}
			}
			if inputCoordinateKey(hint) != inputCoordinateKey(probe.object) || hint.PoolPath != probe.object.PoolPath {
				return inspectedInput{Err: errors.New("managed: package coordinate changed while inspecting")}
			}
		}
		var created *rootedCreatedRegular
		var err error
		if copyPayload {
			created, err = createRootedRegular(filepath.Dir(snapshot), filepath.Base(snapshot), 0o600)
			if err != nil {
				return inspectedInput{Err: err}
			}
		}
		digests, readErr := readInputContent(ctx, probe.opened.file, created, before.size, probe.object.Format == "rpm")
		var object state.PackageObject
		var schema string
		var facts []byte
		if readErr == nil {
			if copyPayload {
				object, schema, facts, readErr = inspectSnapshotWithFacts(ctx, snapshot, basename, digests.SHA256, digests.RPMNeutralSHA256)
			} else {
				object, schema, facts, readErr = inspectInputReaderWithFacts(ctx, probe.opened.file, basename, digests, before.size)
			}
		}
		after, identityErr := snapshotRootedRegularIdentity(probe.opened)
		if identityErr == nil && before.sameContentStat(after) {
			if readErr == nil && previousDigest != "" && previousDigest != digests.SHA256 {
				readErr = errors.New("managed: package bytes changed between inspection attempts")
			}
			if readErr == nil && (inputCoordinateKey(object) != inputCoordinateKey(probe.object) || object.PoolPath != probe.object.PoolPath) {
				readErr = errors.New("managed: authenticated package differs from coordinate probe")
			}
			readErr = errors.Join(readErr, ctx.Err())
			if created != nil {
				if readErr == nil {
					readErr = created.Commit()
				} else {
					readErr = errors.Join(readErr, created.Abort())
				}
			}
			return inspectedInput{SHA256: digests.SHA256, Object: object, FactSchema: schema, Facts: facts, Err: readErr}
		}
		var abortErr error
		if created != nil {
			abortErr = created.Abort()
		}
		if identityErr != nil || abortErr != nil || ctx.Err() != nil || attempt != 0 || !before.sameReadTarget(after) {
			return inspectedInput{Err: errors.Join(errors.New("managed: package input changed while inspecting"), readErr, identityErr, abortErr, ctx.Err())}
		}
		before, previousDigest = after, digests.SHA256
	}
	return inspectedInput{Err: errors.New("managed: unstable package input")}
}

func inspectSnapshotWithFacts(ctx context.Context, filename, originalBasename, knownSHA, knownRPMNeutralSHA string) (state.PackageObject, string, []byte, error) {
	opened, err := openRootedRegular(filepath.Dir(filename), filepath.Base(filename))
	if err != nil {
		return state.PackageObject{}, "", nil, err
	}
	object, schema, facts, inspectErr := inspectInputReaderWithFacts(ctx, opened.file, originalBasename, packageSnapshotDigests{SHA256: knownSHA, RPMNeutralSHA256: knownRPMNeutralSHA}, opened.before.Size())
	return object, schema, facts, errors.Join(inspectErr, opened.CloseVerified())
}

func inspectInputReaderWithFacts(ctx context.Context, file *os.File, basename string, digests packageSnapshotDigests, size int64) (state.PackageObject, string, []byte, error) {
	switch {
	case strings.HasSuffix(basename, ".rpm"):
		facts, info, err := yumrepo.InspectManagedPackageFactsReaderKnown(ctx, file, basename, digests.SHA256, size)
		if err != nil {
			return state.PackageObject{}, "", nil, err
		}
		if digests.RPMNeutralSHA256 == "" {
			return state.PackageObject{}, "", nil, errors.New("managed: missing RPM-neutral input digest")
		}
		object, err := rpmObjectFromInfo(info, basename, digests.RPMNeutralSHA256)
		if err != nil {
			return state.PackageObject{}, "", nil, err
		}
		blob, err := facts.MarshalBinary()
		return object, yumrepo.PackageFactsSchema, blob, err
	case strings.HasSuffix(basename, ".deb"):
		info, err := aptrepo.InspectPackageReaderKnown(ctx, file, "main", basename, digests.SHA256, size)
		if err != nil {
			return state.PackageObject{}, "", nil, err
		}
		object, err := debObjectFromInfo(info, basename)
		if err != nil {
			return state.PackageObject{}, "", nil, err
		}
		blob, err := aptrepo.MarshalPackageFacts(info)
		return object, aptrepo.PackageFactsSchema, blob, err
	default:
		return state.PackageObject{}, "", nil, errors.New("managed: unsupported package suffix")
	}
}

func collectInputFiles(ctx context.Context, inputs []string, recursive bool) ([]inputFile, []MutationItem) {
	seen := make(map[string]bool)
	files := []inputFile{}
	failures := []MutationItem{}
	report := func(input string, err error) {
		failures = append(failures, MutationItem{Input: input, Status: "failed", Error: err.Error()})
	}
	add := func(file inputFile) {
		if !seen[file.Path] {
			seen[file.Path] = true
			files = append(files, file)
		}
	}
	for _, input := range inputs {
		if err := ctx.Err(); err != nil {
			report(input, err)
			continue
		}
		path, err := filepath.Abs(input)
		if err == nil {
			path, err = filepath.EvalSymlinks(path)
		}
		if err != nil {
			report(input, err)
			continue
		}
		info, err := os.Lstat(path)
		if err != nil {
			report(input, err)
			continue
		}
		switch {
		case info.Mode().IsRegular():
			if !isInputPackageName(input) {
				report(input, errors.New("input is not an RPM or DEB package"))
				continue
			}
			add(inputFile{Path: path, Display: input, Base: filepath.Base(input)})
		case info.IsDir():
			candidates, err := scanInputDirectory(ctx, path, input, info, recursive, report)
			if err != nil {
				report(input, err)
			} else if len(candidates) == 0 {
				report(input, errors.New("directory contains no package inputs in the selected scan scope"))
			} else {
				for _, candidate := range candidates {
					add(candidate)
				}
			}
		default:
			report(input, errors.New("input is neither a regular file nor a directory"))
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.SliceStable(failures, func(i, j int) bool { return failures[i].Input < failures[j].Input })
	return files, failures
}

func isInputPackageName(name string) bool {
	return strings.HasSuffix(name, ".rpm") || strings.HasSuffix(name, ".deb")
}

// Scan the selected directory through one open handle. Package symlinks may
// point outside it. A regular entry keeps its path for the verified ingest open.
func scanInputDirectory(ctx context.Context, path, display string, selected os.FileInfo, recursive bool, report func(string, error)) ([]inputFile, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(selected, opened) {
		return nil, errors.Join(errors.New("package input directory changed during scan"), err)
	}
	if recursive {
		display = path
	}
	var files []inputFile
	err = fs.WalkDir(root.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		label := filepath.Join(display, rel)
		if walkErr != nil {
			if rel == "." {
				return walkErr
			}
			if entry == nil || entry.IsDir() || isInputPackageName(rel) {
				report(label, walkErr)
			}
			return nil
		}
		if entry.IsDir() {
			if !recursive && rel != "." {
				return fs.SkipDir
			}
			return nil
		}
		if !isInputPackageName(entry.Name()) {
			return nil
		}
		filename := filepath.Join(path, rel)
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := root.Readlink(rel)
			if err == nil {
				if !filepath.IsAbs(target) {
					target = filepath.Join(filepath.Dir(filename), target)
				}
				filename, err = filepath.EvalSymlinks(target)
			}
			if err != nil {
				report(label, err)
				return nil
			}
			info, err := os.Lstat(filename)
			if err != nil || !info.Mode().IsRegular() {
				report(label, errors.Join(errors.New("package input is not a regular file"), err))
				return nil
			}
		} else if !entry.Type().IsRegular() {
			report(label, errors.New("package input is not a regular file"))
			return nil
		}
		files = append(files, inputFile{Path: filename, Display: label, Base: entry.Name()})
		return nil
	})
	after, statErr := os.Lstat(path)
	if statErr != nil || !os.SameFile(selected, after) {
		return nil, errors.Join(errors.New("package input directory changed during scan"), statErr)
	}
	return files, err
}

type packageSnapshotDigests struct {
	SHA256           string
	RPMNeutralSHA256 string
}

type suffixHashWriter struct {
	skip    int64
	written int64
	target  io.Writer
}

func (writer *suffixHashWriter) Write(buffer []byte) (int, error) {
	original := len(buffer)
	start := int64(0)
	if writer.written < writer.skip {
		start = writer.skip - writer.written
		if start > int64(len(buffer)) {
			start = int64(len(buffer))
		}
	}
	writer.written += int64(len(buffer))
	if start < int64(len(buffer)) {
		if _, err := writer.target.Write(buffer[start:]); err != nil {
			return 0, err
		}
	}
	return original, nil
}

// readInputContent performs exactly one full read. The caller owns the whole
// probe/read/facts identity retry; this helper must never retry on its own.
func readInputContent(ctx context.Context, file *os.File, created *rootedCreatedRegular, size int64, rpm bool) (packageSnapshotDigests, error) {
	neutralOffset := int64(0)
	var err error
	if rpm {
		neutralOffset, err = yumrepo.RPMSignatureNeutralOffset(ctx, file)
		if err != nil {
			return packageSnapshotDigests{}, err
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return packageSnapshotDigests{}, err
	}
	hasher := sha256.New()
	writers := []io.Writer{hasher}
	if created != nil {
		writers = append(writers, created.file)
	}
	neutralHasher := sha256.New()
	if rpm {
		writers = append(writers, &suffixHashWriter{skip: neutralOffset, target: neutralHasher})
	}
	read, err := io.Copy(io.MultiWriter(writers...), &managedContextReader{ctx: ctx, reader: file})
	if err != nil || read != size {
		return packageSnapshotDigests{}, errors.Join(fmt.Errorf("managed: package content read %d bytes, expected %d", read, size), err)
	}
	workmetrics.RecordFullPackageRead(ctx, read)
	result := packageSnapshotDigests{SHA256: hex.EncodeToString(hasher.Sum(nil))}
	if rpm {
		result.RPMNeutralSHA256 = hex.EncodeToString(neutralHasher.Sum(nil))
	}
	return result, nil
}

// verifyIngestReuse rebinds the backing body at the point of reuse. A current
// mutation snapshot may prove an immutable public inode by its persisted full
// fingerprint. Pending and other unproven bodies require a complete expected-
// SHA read. Neutral reuse additionally verifies the configured signing policy
// on this same stable descriptor; a header issuer is never authorization.
func verifyIngestReuse(ctx context.Context, source ManagedPackageSource, evidence *payloadEvidenceRegistry, policy rpmSigningPolicy, neutral bool) (reusable bool, resultErr error) {
	opened, err := source.open()
	if err != nil {
		return false, fmt.Errorf("%w: backing package is unsafe: %v", ErrIntegrity, err)
	}
	defer func() { resultErr = errors.Join(resultErr, opened.CloseVerified()) }()
	before, err := snapshotRootedRegularIdentity(opened)
	if err != nil {
		return false, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		key := physicalPayloadIdentityFrom(before)
		evidence.mu.Lock()
		slot := evidence.slots[key]
		evidence.mu.Unlock()
		proven := false
		if attempt == 0 && slot != nil {
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-slot.done:
			}
			proven = slot.err == nil && slot.evidence != nil && slot.evidence.Identity == before && slot.evidence.File.Size == source.Object.Size && slot.evidence.File.SHA256 == source.Object.SHA256
		}
		if !proven {
			digests, err := readInputContent(workmetrics.WithPhase(ctx, "ingest"), opened.file, nil, source.Object.Size, source.Object.Format == "rpm")
			if err != nil || digests.SHA256 != source.Object.SHA256 || source.Object.Format == "rpm" && digests.RPMNeutralSHA256 != source.Object.PayloadSHA256 {
				return false, errors.Join(fmt.Errorf("%w: backing package content differs from its object", ErrIntegrity), err)
			}
		}
		reusable = !neutral || policy.permitsNeutralReuseReader(ctx, opened.file)
		after, err := snapshotRootedRegularIdentity(opened)
		if err == nil && before == after {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if slot == nil {
				claimed, owner := evidence.claim(key)
				if owner {
					evidence.complete(key, claimed, &checkPayloadEvidence{Identity: after, File: state.GenerationFile{Path: source.Relative, Size: source.Object.Size, SHA256: source.Object.SHA256}}, nil)
				}
			}
			return reusable, nil
		}
		if err != nil || attempt != 0 || !before.sameReadTarget(after) {
			return false, errors.Join(fmt.Errorf("%w: backing package changed during reuse", ErrIntegrity), err)
		}
		before = after
	}
	return false, fmt.Errorf("%w: unstable backing package", ErrIntegrity)
}

func inspectRPMSnapshot(ctx context.Context, filename, originalBasename string) (state.PackageObject, error) {
	opened, err := openRootedRegular(filepath.Dir(filename), filepath.Base(filename))
	if err != nil {
		return state.PackageObject{}, err
	}
	object, inspectErr := inspectRPMSnapshotReader(ctx, opened.file, originalBasename)
	return object, errors.Join(inspectErr, opened.CloseVerified())
}

func inspectRPMSnapshotReader(ctx context.Context, file *os.File, originalBasename string) (state.PackageObject, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return state.PackageObject{}, err
	}
	info, err := yumrepo.InspectPackageReader(ctx, file, originalBasename)
	if err != nil {
		return state.PackageObject{}, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return state.PackageObject{}, err
	}
	payloadSHA, err := yumrepo.RPMSignatureNeutralDigest(ctx, file)
	if err != nil {
		return state.PackageObject{}, err
	}
	return rpmObjectFromInfo(info, originalBasename, payloadSHA)
}

func matchesPersistedSnapshotReader(ctx context.Context, file *os.File, expected state.PackageObject) (bool, error) {
	switch expected.Format {
	case "rpm":
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return false, err
		}
		info, err := yumrepo.InspectPackageReader(ctx, file, expected.Filename)
		if err != nil {
			return false, err
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return false, err
		}
		payloadSHA, err := yumrepo.RPMSignatureNeutralDigest(ctx, file)
		if err != nil {
			return false, err
		}
		return matchesPersistedManagedRPMObject(expected, info, payloadSHA), nil
	case "deb":
		facts, err := inspectDEBSnapshotReader(ctx, file, expected.Filename)
		if err != nil {
			return false, err
		}
		return sameManagedPackageFacts(expected, facts), nil
	default:
		return false, fmt.Errorf("unsupported package format %q", expected.Format)
	}
}

func rpmObjectFromInfo(info yumrepo.PackageInfo, originalBasename, payloadSHA string) (state.PackageObject, error) {
	canonical, neutral, err := canonicalStateArchitecture("rpm", info.Arch)
	if err != nil {
		return state.PackageObject{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	if neutral {
		canonical = "neutral"
	}
	poolPath, err := managedPoolPath(info.Source, originalBasename)
	if err != nil {
		return state.PackageObject{}, err
	}
	warning := ""
	if strings.TrimSpace(info.SourceRPM) == "" {
		warning = "RPM SOURCERPM is absent; source falls back to binary name"
	}
	coordinate := fmt.Sprintf("%s-%d:%s-%s.%s", info.Name, info.Epoch, info.Version, info.Release, info.Arch)
	return state.PackageObject{
		SHA256: info.SHA256, Format: "rpm", Coordinate: coordinate, Architecture: info.Arch,
		CanonicalArch: canonical, PoolPath: poolPath, Filename: originalBasename, Size: info.Size,
		Name: info.Name, Source: info.Source, Version: info.Version, Epoch: strconv.FormatInt(info.Epoch, 10),
		Release: info.Release, Kind: ClassifyPackageKind("rpm", info.Name), PayloadSHA256: payloadSHA,
		Warning: warning, Storage: "pending",
	}, nil
}

func inspectDEBSnapshotReader(ctx context.Context, file *os.File, originalBasename string) (state.PackageObject, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return state.PackageObject{}, err
	}
	info, err := aptrepo.InspectPackageReaderAs(ctx, file, "main", originalBasename)
	if err != nil {
		return state.PackageObject{}, err
	}
	return debObjectFromInfo(info, originalBasename)
}

func debObjectFromInfo(info aptrepo.Package, originalBasename string) (state.PackageObject, error) {
	canonical, neutral, err := canonicalStateArchitecture("deb", info.Architecture)
	if err != nil {
		return state.PackageObject{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	if neutral {
		canonical = "neutral"
	}
	poolPath, err := managedPoolPath(info.Source, originalBasename)
	if err != nil {
		return state.PackageObject{}, err
	}
	coordinate := fmt.Sprintf("%s=%s:%s", info.Name, info.Version, info.Architecture)
	return state.PackageObject{
		SHA256: info.SHA256, Format: "deb", Coordinate: coordinate, Architecture: info.Architecture,
		CanonicalArch: canonical, PoolPath: poolPath, Filename: originalBasename, Size: info.Size,
		Name: info.Name, Source: info.Source, Version: info.Version, Kind: ClassifyPackageKind("deb", info.Name),
		Storage: "pending",
	}, nil
}

func managedPoolPath(source, filename string) (string, error) {
	pool, err := yumrepo.NewManagedPoolPath(source, filename)
	if err != nil {
		return "", fmt.Errorf("managed: unsafe package Pool path: %w", err)
	}
	return pool.String(), nil
}

type managedContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *managedContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func privateTemporaryDirectory(prefix string) (string, error) {
	base, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return "", err
	}
	return os.MkdirTemp(base, prefix)
}
