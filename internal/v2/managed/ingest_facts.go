package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
	"golang.org/x/sys/unix"
)

type inputFile struct {
	Path    string
	Display string
	Base    string
}

type inspectedInput struct {
	SHA256 string
	Object state.PackageObject
	Err    error
}

func inspectInputs(ctx context.Context, inputsRoot string, files []inputFile, workers int) []inspectedInput {
	results := make([]inspectedInput, len(files))
	if len(files) == 0 {
		return results
	}
	if workers > len(files) {
		workers = len(files)
	}
	if workers < 1 {
		workers = 1
	}
	jobs := make(chan int)
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for sequence := range jobs {
				input := files[sequence]
				snapshot := filepath.Join(inputsRoot, fmt.Sprintf("%08d-%s", sequence, input.Base))
				inputSHA, err := snapshotInput(ctx, input.Path, snapshot)
				if err != nil {
					results[sequence].Err = err
					continue
				}
				object, err := inspectSnapshot(ctx, snapshot, input.Base)
				results[sequence] = inspectedInput{SHA256: inputSHA, Object: object, Err: err}
			}
		}()
	}
	for sequence := range files {
		jobs <- sequence
	}
	close(jobs)
	group.Wait()
	return results
}

func collectInputFiles(ctx context.Context, inputs []string, recursive bool) ([]inputFile, []MutationItem) {
	seen := make(map[string]struct{})
	files := []inputFile{}
	failures := []MutationItem{}
	addFile := func(filename, display string, explicit bool) bool {
		base := filepath.Base(filename)
		if !strings.HasSuffix(base, ".rpm") && !strings.HasSuffix(base, ".deb") {
			if explicit {
				failures = append(failures, MutationItem{Input: display, Status: "failed", Error: "input is not an RPM or DEB package"})
			}
			return false
		}
		absolute, err := filepath.Abs(filename)
		if err != nil {
			failures = append(failures, MutationItem{Input: display, Status: "failed", Error: err.Error()})
			return false
		}
		absolute = filepath.Clean(absolute)
		if _, duplicate := seen[absolute]; duplicate {
			return false
		}
		opened, err := openRootedRegular(filepath.Dir(absolute), filepath.Base(absolute))
		if err != nil {
			failures = append(failures, MutationItem{Input: display, Status: "failed", Error: "package input is not a real regular file"})
			return false
		}
		if err := opened.CloseVerified(); err != nil {
			failures = append(failures, MutationItem{Input: display, Status: "failed", Error: "package input changed during scan"})
			return false
		}
		seen[absolute] = struct{}{}
		files = append(files, inputFile{Path: absolute, Display: display, Base: base})
		return true
	}
	for _, input := range inputs {
		absolute, err := filepath.Abs(input)
		if err != nil {
			failures = append(failures, MutationItem{Input: input, Status: "failed", Error: err.Error()})
			continue
		}
		if opened, openErr := openRootedRegular(filepath.Dir(absolute), filepath.Base(absolute)); openErr == nil {
			closeErr := opened.CloseVerified()
			if closeErr != nil {
				failures = append(failures, MutationItem{Input: input, Status: "failed", Error: "package input changed during scan"})
				continue
			}
			addFile(absolute, input, true)
			continue
		}
		directory, binding, dirErr := openBoundRootDirectory(absolute)
		if dirErr != nil {
			failures = append(failures, MutationItem{Input: input, Status: "failed", Error: "input is neither a regular file nor a directory"})
			continue
		}
		if err := errors.Join(verifyBoundRootDirectory(directory, binding), directory.Close()); err != nil {
			failures = append(failures, MutationItem{Input: input, Status: "failed", Error: err.Error()})
			continue
		}
		found := 0
		if recursive {
			candidates := []string{}
			walkErr := walkRootedInputFiles(ctx, absolute, func(relative string, _ *os.File, _ os.FileInfo) error {
				filename := filepath.Join(absolute, filepath.FromSlash(relative))
				base := filepath.Base(filename)
				if strings.HasSuffix(base, ".rpm") || strings.HasSuffix(base, ".deb") {
					candidates = append(candidates, filename)
				}
				return nil
			})
			if walkErr != nil {
				failures = append(failures, MutationItem{Input: input, Status: "failed", Error: walkErr.Error()})
				continue
			}
			for _, filename := range candidates {
				if addFile(filename, filename, false) {
					found++
				}
			}
		} else {
			entries, readErr := listRootedDirectory(absolute)
			if readErr != nil {
				failures = append(failures, MutationItem{Input: input, Status: "failed", Error: readErr.Error()})
				continue
			}
			for _, entry := range entries {
				if uint32(entry.Stat.Mode)&unix.S_IFMT == unix.S_IFREG && addFile(filepath.Join(absolute, entry.Name), filepath.Join(input, entry.Name), false) {
					found++
				}
			}
		}
		if found == 0 {
			failures = append(failures, MutationItem{Input: input, Status: "failed", Error: "directory contains no package inputs in the selected scan scope"})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.SliceStable(failures, func(i, j int) bool { return failures[i].Input < failures[j].Input })
	return files, failures
}

func snapshotInput(ctx context.Context, source, target string) (_ string, resultErr error) {
	opened, err := openRootedRegular(filepath.Dir(source), filepath.Base(source))
	if err != nil {
		return "", fmt.Errorf("managed: package input is not a safely rooted regular file: %w", err)
	}
	created, err := createRootedRegular(filepath.Dir(target), filepath.Base(target), 0o600)
	if err != nil {
		return "", errors.Join(fmt.Errorf("managed: create immutable package snapshot: %w", err), opened.CloseVerified())
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(created.file, hasher), &managedContextReader{ctx: ctx, reader: opened.file})
	if copyErr != nil || written != opened.before.Size() {
		err := errors.Join(copyErr, created.Abort(), opened.CloseVerified())
		return "", fmt.Errorf("managed: copy immutable package snapshot: %w", err)
	}
	if err := created.Commit(); err != nil {
		return "", errors.Join(fmt.Errorf("managed: commit immutable package snapshot: %w", err), opened.CloseVerified())
	}
	if err := opened.CloseVerified(); err != nil {
		_ = removeRootedRegular(filepath.Dir(target), filepath.Base(target), written)
		return "", errors.New("managed: package input changed while snapshotting")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func inspectSnapshot(ctx context.Context, filename, originalBasename string) (state.PackageObject, error) {
	opened, err := openRootedRegular(filepath.Dir(filename), filepath.Base(filename))
	if err != nil {
		return state.PackageObject{}, err
	}
	object, inspectErr := inspectSnapshotReader(ctx, opened.file, originalBasename)
	return object, errors.Join(inspectErr, opened.CloseVerified())
}

func inspectSnapshotReader(ctx context.Context, file *os.File, originalBasename string) (state.PackageObject, error) {
	if file == nil {
		return state.PackageObject{}, errors.New("managed: nil package snapshot")
	}
	switch {
	case strings.HasSuffix(originalBasename, ".rpm"):
		return inspectRPMSnapshotReader(ctx, file, originalBasename)
	case strings.HasSuffix(originalBasename, ".deb"):
		return inspectDEBSnapshotReader(ctx, file, originalBasename)
	default:
		return state.PackageObject{}, errors.New("managed: unsupported package suffix")
	}
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
	canonical, neutral, err := canonicalStateArchitecture("rpm", info.Arch)
	if err != nil {
		return state.PackageObject{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	if neutral {
		canonical = "neutral"
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return state.PackageObject{}, err
	}
	payloadSHA, err := yumrepo.RPMSignatureNeutralDigest(ctx, file)
	if err != nil {
		return state.PackageObject{}, err
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
