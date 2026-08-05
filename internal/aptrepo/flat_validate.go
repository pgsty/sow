package aptrepo

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
	"strconv"
	"strings"

	"pault.ag/go/debian/control"
)

// ValidateFlatPackages reads back a staged Packages/Packages.gz pair and
// proves that both encodings describe exactly the expected parsed packages.
// It validates entry count, deterministic order, flat locations, sizes and
// SHA-256 closure against the package sources before a caller publishes them.
func ValidateFlatPackages(ctx context.Context, packagesPath, gzipPath string, expected []Package) error {
	if ctx == nil {
		return errors.New("aptrepo: nil context")
	}
	packagesInfo, err := regularFileInfo(packagesPath)
	if err != nil {
		return err
	}
	gzipInfo, err := regularFileInfo(gzipPath)
	if err != nil {
		return err
	}
	rawDigest, rawSize, err := digestFile(ctx, packagesPath, false)
	if err != nil {
		return err
	}
	decodedDigest, decodedSize, err := digestFile(ctx, gzipPath, true)
	if err != nil {
		return err
	}
	if rawDigest != decodedDigest || rawSize != decodedSize {
		return errors.New("aptrepo: Packages.gz does not expand exactly to Packages")
	}

	sorted := append([]Package(nil), expected...)
	SortPackages(sorted)
	index, err := os.Open(packagesPath)
	if err != nil {
		return fmt.Errorf("aptrepo: open staged Packages: %w", err)
	}
	reader, err := control.NewParagraphReader(index, nil)
	if err != nil {
		_ = index.Close()
		return fmt.Errorf("aptrepo: parse staged Packages: %w", err)
	}
	for position, pkg := range sorted {
		if err := ctx.Err(); err != nil {
			_ = index.Close()
			return err
		}
		if err := validatePackageMetadata(pkg); err != nil {
			_ = index.Close()
			return err
		}
		if err := verifyPackageSource(ctx, pkg); err != nil {
			_ = index.Close()
			return err
		}
		paragraph, err := reader.Next()
		if errors.Is(err, io.EOF) {
			_ = index.Close()
			return fmt.Errorf("aptrepo: staged Packages has %d entries, want %d", position, len(sorted))
		}
		if err != nil {
			_ = index.Close()
			return fmt.Errorf("aptrepo: parse staged Packages entry %d: %w", position, err)
		}
		base := filepath.Base(pkg.SourcePath)
		wantFilename := "./" + base
		values := paragraph.Values
		if values["Package"] != pkg.Name || values["Version"] != pkg.Version || values["Architecture"] != pkg.Architecture ||
			values["Filename"] != wantFilename || values["Size"] != strconv.FormatInt(pkg.Size, 10) || values["SHA256"] != pkg.SHA256 {
			_ = index.Close()
			return fmt.Errorf("aptrepo: staged Packages entry %d does not match %s", position, base)
		}
		seen := make(map[string]struct{}, len(paragraph.Order))
		for _, field := range paragraph.Order {
			folded := strings.ToLower(field)
			if _, duplicate := seen[folded]; duplicate {
				_ = index.Close()
				return fmt.Errorf("aptrepo: staged Packages entry %d repeats field %q", position, field)
			}
			seen[folded] = struct{}{}
		}
	}
	if paragraph, err := reader.Next(); !errors.Is(err, io.EOF) {
		_ = index.Close()
		if err != nil {
			return fmt.Errorf("aptrepo: parse trailing staged Packages entry: %w", err)
		}
		return fmt.Errorf("aptrepo: staged Packages contains unexpected package %q", paragraph.Values["Package"])
	}
	if err := index.Close(); err != nil {
		return fmt.Errorf("aptrepo: close staged Packages: %w", err)
	}
	if err := unchangedRegularFile(packagesPath, packagesInfo); err != nil {
		return err
	}
	if err := unchangedRegularFile(gzipPath, gzipInfo); err != nil {
		return err
	}
	return nil
}

func regularFileInfo(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("aptrepo: inspect staged flat index %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("aptrepo: staged flat index %q is not a regular file", path)
	}
	return info, nil
}

func unchangedRegularFile(path string, before os.FileInfo) error {
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return errors.Join(err, fmt.Errorf("aptrepo: staged flat index %q changed during validation", path))
	}
	return nil
}

func digestFile(ctx context.Context, path string, compressed bool) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("aptrepo: open staged flat index %q: %w", path, err)
	}
	var reader io.Reader = file
	var zipper *gzip.Reader
	if compressed {
		zipper, err = gzip.NewReader(file)
		if err != nil {
			_ = file.Close()
			return "", 0, fmt.Errorf("aptrepo: open staged Packages.gz: %w", err)
		}
		reader = zipper
	}
	h := sha256.New()
	size, copyErr := io.Copy(h, &contextReader{ctx: ctx, r: reader})
	var zipperErr error
	if zipper != nil {
		zipperErr = zipper.Close()
	}
	closeErr := file.Close()
	if err := errors.Join(copyErr, zipperErr, closeErr); err != nil {
		return "", 0, fmt.Errorf("aptrepo: read staged flat index %q: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}
