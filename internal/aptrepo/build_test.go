package aptrepo

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ulikunitz/xz"
	"pault.ag/go/debian/control"
)

func TestGenerateRepositoryMetadataEndToEnd(t *testing.T) {
	created := time.Date(2026, 7, 12, 2, 3, 4, 0, time.UTC)
	signer, keyring, _ := testSigningMaterial(t, created.Add(-time.Hour))
	packages := testBuildPackages(t)
	cfg := RepositoryConfig{
		Origin:        "Pigsty",
		Label:         "Pigsty Repository",
		Suite:         "beta",
		Codename:      "bookworm",
		Version:       "1",
		Description:   "SOW generated repository",
		Components:    []string{"contrib", "main"},
		Architectures: []string{"arm64", "amd64"},
		Date:          created,
		ValidUntil:    created.Add(7 * 24 * time.Hour),
	}
	indexes := []Index{
		{Component: "main", Architecture: "amd64", Packages: []Package{packages[1], packages[0]}},
		{Component: "main", Architecture: "arm64", Packages: []Package{packages[1]}},
	}

	firstRoot := t.TempDir()
	first, err := Generate(context.Background(), firstRoot, cfg, indexes, signer)
	if err != nil {
		t.Fatalf("Generate first: %v", err)
	}
	if len(first.PoolObjects) != 2 {
		t.Fatalf("PoolObjects count = %d, want 2", len(first.PoolObjects))
	}
	if first.PoolObjects[0].Path > first.PoolObjects[1].Path {
		t.Fatal("PoolObjects are not deterministically sorted")
	}
	assertGeneratedIndexes(t, firstRoot, first, cfg, keyring)

	secondRoot := t.TempDir()
	second, err := Generate(context.Background(), secondRoot, cfg, []Index{indexes[1], indexes[0]}, signer)
	if err != nil {
		t.Fatalf("Generate second: %v", err)
	}
	if !reflect.DeepEqual(withoutSignatureArtifacts(first), withoutSignatureArtifacts(second)) {
		t.Fatal("unsigned BuildResult depends on input ordering")
	}
	firstFiles, secondFiles := readTree(t, firstRoot), readTree(t, secondRoot)
	delete(firstFiles, first.InReleasePath)
	delete(firstFiles, first.DetachedSignaturePath)
	delete(secondFiles, second.InReleasePath)
	delete(secondFiles, second.DetachedSignaturePath)
	if !reflect.DeepEqual(firstFiles, secondFiles) {
		t.Fatal("repository bytes are not deterministic across identical builds")
	}
}

func TestGeneratePreservesOldByHashContentAcrossCanonicalReplacement(t *testing.T) {
	created := time.Date(2026, 7, 12, 3, 0, 0, 0, time.UTC)
	signer, _, _ := testSigningMaterial(t, created.Add(-time.Hour))
	dir := t.TempDir()
	packages := testBuildPackages(t)
	cfg := RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "beta", Codename: "bookworm",
		Components: []string{"main"}, Architectures: []string{"amd64"}, Date: created,
	}
	first, err := Generate(context.Background(), dir, cfg, []Index{{Component: "main", Architecture: "amd64", Packages: []Package{packages[0]}}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	oldPackagesHashPath := byHashPathForCanonical(t, first, "dists/beta/main/binary-amd64/Packages")
	oldBytes := readFile(t, filepath.Join(dir, filepath.FromSlash(oldPackagesHashPath)))

	cfg.Date = cfg.Date.Add(time.Hour)
	second, err := Generate(context.Background(), dir, cfg, []Index{{Component: "main", Architecture: "amd64", Packages: packages}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldBytes, readFile(t, filepath.Join(dir, "dists/beta/main/binary-amd64/Packages"))) {
		t.Fatal("canonical Packages did not change after adding a package")
	}
	if got := readFile(t, filepath.Join(dir, filepath.FromSlash(oldPackagesHashPath))); !bytes.Equal(got, oldBytes) {
		t.Fatal("old immutable by-hash content changed after canonical replacement")
	}
	if first.ByHashGeneration.ID == second.ByHashGeneration.ID {
		t.Fatal("Release generation ID did not change")
	}
}

func TestGenerateRejectsUnsafeConfigurationAndChangedPackage(t *testing.T) {
	created := time.Date(2026, 7, 12, 4, 0, 0, 0, time.UTC)
	signer, _, _ := testSigningMaterial(t, created.Add(-time.Hour))
	packages := testBuildPackages(t)
	base := RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "beta", Codename: "bookworm",
		Components: []string{"main"}, Architectures: []string{"amd64"}, Date: created,
	}
	unsafe := base
	unsafe.Suite = "../escape"
	if _, err := Generate(context.Background(), t.TempDir(), unsafe, nil, signer); err == nil {
		t.Fatal("Generate accepted an unsafe suite")
	}
	unsafe = base
	unsafe.Description = "safe\nSHA256: injected"
	if _, err := Generate(context.Background(), t.TempDir(), unsafe, nil, signer); err == nil {
		t.Fatal("Generate accepted a Release field injection")
	}
	unsafe = base
	unsafe.Description = "unsafe\x1bcontrol"
	if _, err := Generate(context.Background(), t.TempDir(), unsafe, nil, signer); err == nil {
		t.Fatal("Generate accepted a control character in Release metadata")
	}
	if _, err := Generate(context.Background(), t.TempDir(), base, []Index{{Component: "main", Architecture: "amd64", Packages: []Package{packages[0], packages[0]}}}, signer); err == nil || !strings.Contains(err.Error(), "duplicate package") {
		t.Fatalf("duplicate package error = %v", err)
	}
	duplicateControl := strings.ReplaceAll(fixtureControl, "libfoo-bin", "alpha")
	duplicateControl = strings.Replace(duplicateControl, "Source: libfoo (1.2.3-1)", "Source: alpha", 1)
	duplicate, err := InspectPackage(context.Background(), writeMinimalDeb(t, t.TempDir(), "alpha-copy_1.2.3-1_amd64.deb", duplicateControl), "main")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(context.Background(), t.TempDir(), base, []Index{{Component: "main", Architecture: "amd64", Packages: []Package{packages[0], duplicate}}}, signer); err == nil || !strings.Contains(err.Error(), "duplicate package identity") {
		t.Fatalf("duplicate identity error = %v", err)
	}
	symlinkRoot := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(symlinkRoot, "dists")); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(context.Background(), symlinkRoot, base, []Index{{Component: "main", Architecture: "amd64", Packages: packages[:1]}}, signer); err == nil || !strings.Contains(err.Error(), "unsafe artifact directory") {
		t.Fatalf("symlinked metadata directory error = %v", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("Generate wrote through a symlink outside the output root")
	}
	if err := os.WriteFile(packages[0].SourcePath, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(context.Background(), t.TempDir(), base, []Index{{Component: "main", Architecture: "amd64", Packages: packages[:1]}}, signer); err == nil || !strings.Contains(err.Error(), "package source changed") {
		t.Fatalf("changed package error = %v", err)
	}
}

func TestPublicContextAPIsRejectNil(t *testing.T) {
	created := time.Date(2026, 7, 12, 4, 15, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "must-not-exist")
	//lint:ignore SA1012 This test intentionally exercises public nil-context rejection.
	if _, err := Generate(nil, root, RepositoryConfig{Date: created}, nil, nil); err == nil || !strings.Contains(err.Error(), "nil context") {
		t.Fatalf("Generate nil-context error = %v", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nil-context Generate mutated output: %v", err)
	}
	//lint:ignore SA1012 This test intentionally exercises public nil-context rejection.
	if _, err := InspectPackage(nil, "unused.deb", "main"); err == nil || !strings.Contains(err.Error(), "nil context") {
		t.Fatalf("InspectPackage nil-context error = %v", err)
	}
}

func TestGenerateStagesBeforeCommitAndPreflightsSigner(t *testing.T) {
	created := time.Date(2026, 7, 12, 4, 30, 0, 0, time.UTC)
	packages := testBuildPackages(t)
	cfg := RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "beta", Codename: "bookworm",
		Components: []string{"main"}, Architectures: []string{"amd64"}, Date: created,
	}
	root := filepath.Join(t.TempDir(), "repo")
	if _, err := Generate(context.Background(), root, cfg, []Index{{Component: "main", Architecture: "amd64", Packages: packages}}, &Signer{}); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("invalid signer error = %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("signer preflight left staged or published files: %+v", entries)
	}

	signer, _, _ := testSigningMaterial(t, created.Add(-time.Hour))
	if _, err := Generate(context.Background(), root, cfg, []Index{{Component: "main", Architecture: "amd64", Packages: packages}}, signer); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{root, filepath.Dir(root)} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".sow-apt-stage-") || strings.HasPrefix(entry.Name(), ".sow-apt-backup-") {
				t.Fatalf("private staging artifact leaked at %s", filepath.Join(directory, entry.Name()))
			}
		}
	}
	before := readTree(t, root)
	if err := os.WriteFile(packages[0].SourcePath, []byte("changed after first publication"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.Date = cfg.Date.Add(time.Hour)
	if _, err := Generate(context.Background(), root, cfg, []Index{{Component: "main", Architecture: "amd64", Packages: packages}}, signer); err == nil {
		t.Fatal("Generate accepted a changed package")
	}
	after := readTree(t, root)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed staged build mutated the published repository")
	}
}

func TestLinkByHashVerifiesTheLinkedInode(t *testing.T) {
	root := t.TempDir()
	canonical := "dists/beta/main/binary-amd64/Packages"
	if err := ensureOutputParent(root, canonical, true); err != nil {
		t.Fatal(err)
	}
	old := []byte("old Packages bytes\n")
	newContent := []byte("new Packages bytes\n")
	if len(old) != len(newContent) {
		t.Fatal("test inputs must have the same size")
	}
	digest := sha256.Sum256(old)
	expected := Artifact{Path: canonical, Size: int64(len(old)), SHA256: hex.EncodeToString(digest[:])}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(canonical)), newContent, 0o444); err != nil {
		t.Fatal(err)
	}
	byHash := "dists/beta/main/binary-amd64/by-hash/SHA256/" + expected.SHA256
	if _, err := linkByHash(root, expected, byHash); err == nil || !strings.Contains(err.Error(), "verify immutable") {
		t.Fatalf("link race error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(byHash))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid by-hash link was not rolled back: %v", err)
	}
}

func TestOutputLockHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	unlock, err := acquireOutputLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unlock(); err != nil {
			t.Errorf("release output lock: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := acquireOutputLock(ctx, root); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended lock error = %v, want deadline exceeded", err)
	}
}

func TestOutputUnlockFailureIsPartOfOperationResult(t *testing.T) {
	injected := errors.New("injected output unlock failure")
	var resultErr error
	propagateOutputUnlock(func() error { return injected }, &resultErr)
	if !errors.Is(resultErr, injected) {
		t.Fatalf("successful operation hid output unlock failure: %v", resultErr)
	}

	primary := errors.New("primary build failure")
	resultErr = primary
	propagateOutputUnlock(func() error { return injected }, &resultErr)
	if !errors.Is(resultErr, primary) || !errors.Is(resultErr, injected) {
		t.Fatalf("unlock failure did not preserve both errors: %v", resultErr)
	}
}

func TestCommitFailureRollsBackMutableAndNewByHashFiles(t *testing.T) {
	created := time.Date(2026, 7, 12, 7, 0, 0, 0, time.UTC)
	signer, _, _ := testSigningMaterial(t, created.Add(-time.Hour))
	packages := testBuildPackages(t)
	cfg := RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "beta", Codename: "bookworm",
		Components: []string{"main"}, Architectures: []string{"amd64"}, Date: created,
	}
	root := t.TempDir()
	if _, err := Generate(context.Background(), root, cfg, []Index{{Component: "main", Architecture: "amd64", Packages: packages[:1]}}, signer); err != nil {
		t.Fatal(err)
	}
	before := readTree(t, root)
	stage, err := os.MkdirTemp(root, ".failure-stage-")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Date = cfg.Date.Add(time.Hour)
	result, err := generateTree(context.Background(), stage, cfg, []Index{{Component: "main", Architecture: "amd64", Packages: packages}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	allowedChecks := len(result.Artifacts) + len(result.ByHashGeneration.Paths) + 1
	failing := &errAfterContext{allowed: allowedChecks}
	if err := commitStagedBuild(failing, stage, root, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("injected commit error = %v, want context canceled", err)
	}
	if err := os.RemoveAll(stage); err != nil {
		t.Fatal(err)
	}
	after := readTree(t, root)
	if !reflect.DeepEqual(before, after) {
		for filePath, oldBytes := range before {
			if newBytes, ok := after[filePath]; !ok {
				t.Logf("missing after rollback: %s", filePath)
			} else if !bytes.Equal(oldBytes, newBytes) {
				t.Logf("changed after rollback: %s", filePath)
			}
		}
		for filePath := range after {
			if _, ok := before[filePath]; !ok {
				t.Logf("new after rollback: %s", filePath)
			}
		}
		t.Fatal("failed commit did not restore the exact published file set")
	}
}

type errAfterContext struct {
	context.Context
	allowed int
	calls   int
}

func (c *errAfterContext) Err() error {
	c.calls++
	if c.calls > c.allowed {
		return context.Canceled
	}
	return nil
}

func (c *errAfterContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *errAfterContext) Done() <-chan struct{}       { return nil }
func (c *errAfterContext) Value(any) any               { return nil }

func testBuildPackages(t *testing.T) []Package {
	t.Helper()
	dir := t.TempDir()
	amd64Control := strings.ReplaceAll(fixtureControl, "libfoo-bin", "alpha")
	amd64Control = strings.Replace(amd64Control, "Source: libfoo (1.2.3-1)", "Source: alpha", 1)
	allControl := strings.ReplaceAll(fixtureControl, "libfoo-bin", "zeta-data")
	allControl = strings.Replace(allControl, "Source: libfoo (1.2.3-1)", "Source: zeta-data", 1)
	allControl = strings.Replace(allControl, "Architecture: amd64", "Architecture: all", 1)
	amd64, err := InspectPackage(context.Background(), writeMinimalDeb(t, dir, "alpha_1.2.3-1_amd64.deb", amd64Control), "main")
	if err != nil {
		t.Fatalf("inspect amd64 fixture: %v", err)
	}
	all, err := InspectPackage(context.Background(), writeMinimalDeb(t, dir, "zeta-data_1.2.3-1_all.deb", allControl), "main")
	if err != nil {
		t.Fatalf("inspect all fixture: %v", err)
	}
	return []Package{amd64, all}
}

func assertGeneratedIndexes(t *testing.T, root string, result BuildResult, cfg RepositoryConfig, keyring openpgp.EntityList) {
	t.Helper()
	release := readFile(t, filepath.Join(root, filepath.FromSlash(result.ReleasePath)))
	reader, err := control.NewParagraphReader(bytes.NewReader(release), nil)
	if err != nil {
		t.Fatalf("parse Release: %v", err)
	}
	paragraph, err := reader.Next()
	if err != nil {
		t.Fatalf("read Release paragraph: %v", err)
	}
	if paragraph.Values["Acquire-By-Hash"] != "yes" {
		t.Fatalf("Acquire-By-Hash = %q", paragraph.Values["Acquire-By-Hash"])
	}
	if paragraph.Values["Architectures"] != "amd64 arm64" || paragraph.Values["Components"] != "contrib main" {
		t.Fatalf("unexpected Release dimensions: arch=%q components=%q", paragraph.Values["Architectures"], paragraph.Values["Components"])
	}
	checksums := parseReleaseChecksums(t, paragraph.Values["SHA256"])
	if len(checksums) != len(cfg.Components)*len(cfg.Architectures)*3 {
		t.Fatalf("Release checksum count = %d", len(checksums))
	}
	for relative, expected := range checksums {
		data := readFile(t, filepath.Join(root, "dists", cfg.Suite, filepath.FromSlash(relative)))
		digest := sha256.Sum256(data)
		if int64(len(data)) != expected.size || hex.EncodeToString(digest[:]) != expected.digest {
			t.Fatalf("Release checksum mismatch for %s", relative)
		}
	}

	packagesPath := filepath.Join(root, "dists", cfg.Suite, "main", "binary-amd64", "Packages")
	plain := readFile(t, packagesPath)
	entries, err := control.ParseBinaryIndex(bufio.NewReader(bytes.NewReader(plain)))
	if err != nil {
		t.Fatalf("parse Packages: %v", err)
	}
	if len(entries) != 2 || entries[0].Package != "alpha" || entries[1].Package != "zeta-data" {
		t.Fatalf("unexpected generated Packages entries: %+v", entries)
	}
	if got := decompressGzip(t, packagesPath+".gz"); !bytes.Equal(got, plain) {
		t.Fatal("Packages.gz does not decompress to Packages")
	}
	if got := decompressXZ(t, packagesPath+".xz"); !bytes.Equal(got, plain) {
		t.Fatal("Packages.xz does not decompress to Packages")
	}

	for _, artifact := range result.Artifacts {
		data := readFile(t, filepath.Join(root, filepath.FromSlash(artifact.Path)))
		digest := sha256.Sum256(data)
		if int64(len(data)) != artifact.Size || hex.EncodeToString(digest[:]) != artifact.SHA256 {
			t.Fatalf("artifact metadata mismatch for %s", artifact.Path)
		}
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(artifact.Path)))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o444 {
			t.Fatalf("artifact %s mode = %o, want 444", artifact.Path, info.Mode().Perm())
		}
	}
	for _, byHashPath := range result.ByHashGeneration.Paths {
		data := readFile(t, filepath.Join(root, filepath.FromSlash(byHashPath)))
		digest := filepath.Base(byHashPath)
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != digest {
			t.Fatalf("by-hash path %s does not match content", byHashPath)
		}
		canonical := canonicalPathForByHash(t, result, byHashPath)
		canonicalInfo, err := os.Stat(filepath.Join(root, filepath.FromSlash(canonical)))
		if err != nil {
			t.Fatalf("stat canonical index %s: %v", canonical, err)
		}
		byHashInfo, err := os.Stat(filepath.Join(root, filepath.FromSlash(byHashPath)))
		if err != nil {
			t.Fatalf("stat by-hash index %s: %v", byHashPath, err)
		}
		if os.SameFile(canonicalInfo, byHashInfo) {
			t.Fatalf("by-hash index %s shares a mutable inode with %s", byHashPath, canonical)
		}
	}

	inRelease := readFile(t, filepath.Join(root, filepath.FromSlash(result.InReleasePath)))
	block, rest := clearsign.Decode(inRelease)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("generated InRelease is malformed")
	}
	verifyConfig := &packet.Config{Time: func() time.Time { return cfg.Date }}
	if _, err := block.VerifySignature(keyring, verifyConfig); err != nil {
		t.Fatalf("verify generated InRelease: %v", err)
	}
	if !bytes.Equal(block.Plaintext, release) {
		t.Fatal("InRelease does not sign the generated Release bytes")
	}
	detached := readFile(t, filepath.Join(root, filepath.FromSlash(result.DetachedSignaturePath)))
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(release), bytes.NewReader(detached), verifyConfig); err != nil {
		t.Fatalf("verify generated Release.gpg: %v", err)
	}
}

type releaseChecksum struct {
	digest string
	size   int64
}

func parseReleaseChecksums(t *testing.T, value string) map[string]releaseChecksum {
	t.Helper()
	result := make(map[string]releaseChecksum)
	for _, line := range strings.Split(value, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 {
			t.Fatalf("malformed Release SHA256 line %q", line)
		}
		var size int64
		if _, err := fmt.Sscan(fields[1], &size); err != nil {
			t.Fatalf("parse Release size %q: %v", fields[1], err)
		}
		result[fields[2]] = releaseChecksum{digest: fields[0], size: size}
	}
	return result
}

func decompressGzip(t *testing.T, filePath string) []byte {
	t.Helper()
	f, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decompressXZ(t *testing.T, filePath string) []byte {
	t.Helper()
	f, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := xz.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func byHashPathForCanonical(t *testing.T, result BuildResult, canonical string) string {
	t.Helper()
	for _, artifact := range result.Artifacts {
		if artifact.Path == canonical {
			base := filepath.ToSlash(filepath.Dir(canonical))
			return base + "/by-hash/SHA256/" + artifact.SHA256
		}
	}
	t.Fatalf("canonical artifact not found: %s", canonical)
	return ""
}

func canonicalPathForByHash(t *testing.T, result BuildResult, byHashPath string) string {
	t.Helper()
	parts := strings.Split(byHashPath, "/")
	base := strings.Join(parts[:4], "/")
	digest := parts[len(parts)-1]
	for _, artifact := range result.Artifacts {
		if filepath.ToSlash(filepath.Dir(artifact.Path)) == base && artifact.SHA256 == digest {
			return artifact.Path
		}
	}
	t.Fatalf("canonical artifact for %s not found", byHashPath)
	return ""
}

func readTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	if err := filepath.WalkDir(root, func(filePath string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			relative, err := filepath.Rel(root, filePath)
			if err != nil {
				return err
			}
			result[filepath.ToSlash(relative)] = readFile(t, filePath)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk generated tree: %v", err)
	}
	return result
}

func readFile(t *testing.T, filePath string) []byte {
	t.Helper()
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read %s: %v", filePath, err)
	}
	return data
}

func withoutSignatureArtifacts(result BuildResult) BuildResult {
	artifacts := result.Artifacts[:0:0]
	for _, artifact := range result.Artifacts {
		if artifact.Path != result.InReleasePath && artifact.Path != result.DetachedSignaturePath {
			artifacts = append(artifacts, artifact)
		}
	}
	result.Artifacts = artifacts
	return result
}
