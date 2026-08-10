package plain

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/yumrepo"
)

type stagedBuild struct {
	dir        string
	markerSHA  string
	rpmPresent bool
	debPresent bool
}

func renderStage(ctx context.Context, dir string, scan scanResult, opts Options) (_ stagedBuild, _ scanResult, resultErr error) {
	stage, err := os.MkdirTemp(dir, ".sow-plain-stage-")
	if err != nil {
		return stagedBuild{}, scanResult{}, &Error{Kind: KindRuntime, Op: "create stage", Path: dir, Err: err}
	}
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, os.RemoveAll(stage))
		}
	}()
	scan, err = stageSignedRPMs(ctx, stage, scan, opts)
	if err != nil {
		return stagedBuild{}, scanResult{}, err
	}

	if scan.hasRPM {
		var packages []*yumrepo.FlatPackage
		for _, fact := range scan.index {
			if fact.format == formatRPM {
				packages = append(packages, fact.parsedRPM)
			}
		}
		if _, err := yumrepo.GenerateFlatUnsignedParsed(ctx, filepath.Join(stage, "repodata"), 0, packages); err != nil {
			return stagedBuild{}, scanResult{}, &Error{Kind: KindRuntime, Op: "render rpm", Path: dir, Err: err}
		}
	}

	if scan.hasDEB {
		var packages []aptrepo.Package
		for _, fact := range scan.index {
			if fact.format == formatDEB {
				packages = append(packages, fact.deb)
			}
		}
		packagesPath := filepath.Join(stage, "Packages")
		packagesFile, err := os.OpenFile(packagesPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return stagedBuild{}, scanResult{}, &Error{Kind: KindRuntime, Op: "create Packages", Path: packagesPath, Err: err}
		}
		if err := packagesFile.Chmod(0o644); err != nil {
			_ = packagesFile.Close()
			return stagedBuild{}, scanResult{}, &Error{Kind: KindRuntime, Op: "chmod Packages", Path: packagesPath, Err: err}
		}
		writeErr := aptrepo.WriteInspectedFlatPackages(ctx, packagesFile, packages)
		syncErr := error(nil)
		if writeErr == nil {
			syncErr = packagesFile.Sync()
		}
		closeErr := packagesFile.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			return stagedBuild{}, scanResult{}, &Error{Kind: KindRuntime, Op: "render deb", Path: packagesPath, Err: err}
		}
		if err := writeDeterministicGzip(ctx, packagesPath, filepath.Join(stage, "Packages.gz")); err != nil {
			return stagedBuild{}, scanResult{}, &Error{Kind: KindRuntime, Op: "compress deb", Path: packagesPath, Err: err}
		}
		if err := aptrepo.ValidateInspectedFlatPackages(ctx, packagesPath, filepath.Join(stage, "Packages.gz"), packages); err != nil {
			return stagedBuild{}, scanResult{}, &Error{Kind: KindRuntime, Op: "validate deb", Path: packagesPath, Err: err}
		}
	}

	markerSHA := ""
	if opts.Pigsty {
		markerPath := filepath.Join(stage, "repo_complete")
		marker, err := os.OpenFile(markerPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return stagedBuild{}, scanResult{}, &Error{Kind: KindRuntime, Op: "create marker", Path: markerPath, Err: err}
		}
		if err := marker.Chmod(0o644); err != nil {
			_ = marker.Close()
			return stagedBuild{}, scanResult{}, &Error{Kind: KindRuntime, Op: "chmod marker", Path: markerPath, Err: err}
		}
		for _, fact := range scan.kept {
			if _, err := fmt.Fprintf(marker, "%s  %s\n", fact.sha256, fact.base); err != nil {
				_ = marker.Close()
				return stagedBuild{}, scanResult{}, &Error{Kind: KindRuntime, Op: "write marker", Path: markerPath, Err: err}
			}
		}
		if err := errors.Join(marker.Sync(), marker.Close()); err != nil {
			return stagedBuild{}, scanResult{}, &Error{Kind: KindRuntime, Op: "sync marker", Path: markerPath, Err: err}
		}
		markerSHA, err = hashFile(ctx, markerPath)
		if err != nil {
			return stagedBuild{}, scanResult{}, err
		}
	}
	if err := syncDir(stage); err != nil {
		return stagedBuild{}, scanResult{}, &Error{Kind: KindRuntime, Op: "sync stage", Path: stage, Err: err}
	}
	keep = true
	return stagedBuild{dir: stage, markerSHA: markerSHA, rpmPresent: scan.hasRPM, debPresent: scan.hasDEB}, scan, nil
}

func writeDeterministicGzip(ctx context.Context, source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if err := out.Chmod(0o644); err != nil {
		_ = out.Close()
		_ = os.Remove(target)
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(target)
		}
	}()
	zw, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		return err
	}
	zw.Header.ModTime = time.Time{}
	zw.Header.OS = 255
	if _, err := io.Copy(zw, &contextReader{ctx: ctx, reader: in}); err != nil {
		_ = zw.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func hashFile(ctx context.Context, path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", &Error{Kind: KindRuntime, Op: "hash", Path: path, Err: err}
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, &contextReader{ctx: ctx, reader: file})
	closeErr := file.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return "", &Error{Kind: KindRuntime, Op: "hash", Path: path, Err: err}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
