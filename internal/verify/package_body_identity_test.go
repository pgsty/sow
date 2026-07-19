package verify

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/klauspost/compress/zstd"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/yumrepo"
	"github.com/ulikunitz/xz"
)

func TestAPTCheckRejectsResignedMetadataIdentityThatDiffersFromDEBBody(t *testing.T) {
	ctx := context.Background()
	created := time.Unix(1_700_000_000, 0).UTC()
	private := testPrivateKey(t, created)
	signer, err := aptrepo.NewSignerBytes(private, nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewAPTVerifier(bytes.NewReader(private))
	if err != nil {
		t.Fatal(err)
	}
	debPath := decodeFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), "arbitrary-safe-name.deb")
	pkg, err := aptrepo.InspectPackage(ctx, debPath, "main")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	copyFile(t, debPath, filepath.Join(root, filepath.FromSlash(pkg.PoolPath)))
	if _, err := aptrepo.Generate(ctx, root, aptrepo.RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "jammy", Codename: "jammy", Components: []string{"main"}, Architectures: []string{"arm64"}, Date: created,
	}, []aptrepo.Index{{Component: "main", Architecture: "arm64", Packages: []aptrepo.Package{pkg}}}, signer); err != nil {
		t.Fatal(err)
	}
	relabelAPTVersionAndResign(t, root, "jammy", "main", "arm64", pkg.Version, "9:999.0-1", signer, created)
	check := APTCheck{CheckID: "apt-resigned-relabel", Root: root, ExpectedSuites: []string{"jammy"}, ExpectedSuiteComponents: map[string][]string{"jammy": {"main"}}, Verifier: verifier, VerifyAt: created, Workers: 2, ChunkEntries: 1}
	report := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{check}})
	if !hasCode(report, "APT_BODY_IDENTITY_CHANGED") {
		t.Fatalf("validly re-signed APT metadata-only identity relabel was not rejected by DEB body binding: %+v", report)
	}
}

func relabelAPTVersionAndResign(t *testing.T, root, suite, component, architecture, oldVersion, newVersion string, signer *aptrepo.Signer, at time.Time) {
	t.Helper()
	base := filepath.Join(root, "dists", suite)
	prefix := filepath.Join(component, "binary-"+architecture, "Packages")
	plainPath := filepath.Join(base, prefix)
	plain, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatal(err)
	}
	oldField, newField := []byte("Version: "+oldVersion+"\n"), []byte("Version: "+newVersion+"\n")
	if bytes.Count(plain, oldField) != 1 {
		t.Fatalf("expected exactly one APT version field %q", oldVersion)
	}
	plain = bytes.Replace(plain, oldField, newField, 1)
	var gzipBytes bytes.Buffer
	gzipWriter := gzip.NewWriter(&gzipBytes)
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	if _, err := gzipWriter.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	var xzBytes bytes.Buffer
	xzWriter, err := xz.NewWriter(&xzBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xzWriter.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := xzWriter.Close(); err != nil {
		t.Fatal(err)
	}
	variants := map[string][]byte{filepath.ToSlash(prefix): plain, filepath.ToSlash(prefix) + ".gz": gzipBytes.Bytes(), filepath.ToSlash(prefix) + ".xz": xzBytes.Bytes()}
	releasePath := filepath.Join(base, "Release")
	release, err := os.ReadFile(releasePath)
	if err != nil {
		t.Fatal(err)
	}
	document, err := parseAPTRelease(release)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := make(map[string]aptReleaseArtifact, len(document.Artifacts))
	for _, artifact := range document.Artifacts {
		artifacts[artifact.Path] = artifact
	}
	for relative, body := range variants {
		digest := sha256.Sum256(body)
		hexDigest := hex.EncodeToString(digest[:])
		artifact, exists := artifacts[relative]
		if !exists {
			t.Fatalf("Release lacks %s", relative)
		}
		artifact.SHA256, artifact.Size = hexDigest, int64(len(body))
		artifacts[relative] = artifact
		writeMutableTestFile(t, filepath.Join(base, filepath.FromSlash(relative)), body)
		byHash := filepath.Join(base, filepath.Dir(filepath.FromSlash(relative)), "by-hash", "SHA256", hexDigest)
		writeMutableTestFile(t, byHash, body)
	}
	marker := []byte("SHA256:\n")
	index := bytes.Index(release, marker)
	if index < 0 {
		t.Fatal("Release lacks SHA256 marker")
	}
	paths := make([]string, 0, len(artifacts))
	for relative := range artifacts {
		paths = append(paths, relative)
	}
	sort.Strings(paths)
	var rebuilt bytes.Buffer
	rebuilt.Write(release[:index+len(marker)])
	for _, relative := range paths {
		artifact := artifacts[relative]
		fmt.Fprintf(&rebuilt, " %s %d %s\n", artifact.SHA256, artifact.Size, artifact.Path)
	}
	release = rebuilt.Bytes()
	writeMutableTestFile(t, releasePath, release)
	var inRelease, detached bytes.Buffer
	if err := signer.ClearSign(&inRelease, bytes.NewReader(release), at); err != nil {
		t.Fatal(err)
	}
	if err := signer.DetachedSign(&detached, bytes.NewReader(release), at); err != nil {
		t.Fatal(err)
	}
	writeMutableTestFile(t, filepath.Join(base, "InRelease"), inRelease.Bytes())
	writeMutableTestFile(t, filepath.Join(base, "Release.gpg"), detached.Bytes())
}

func TestYUMCheckRejectsResignedMetadataIdentityThatDiffersFromRPMBody(t *testing.T) {
	ctx := context.Background()
	created := time.Unix(1_700_000_000, 0).UTC()
	private := testPrivateKey(t, created)
	signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(private), nil, created)
	if err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeFixture(t, filepath.Join("..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), "arbitrary-safe-name.rpm")
	info, err := yumrepo.InspectPackage(ctx, yumrepo.PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	copyFile(t, rpmPath, filepath.Join(root, filepath.FromSlash(info.Location)))
	generation, err := yumrepo.Generate(ctx, filepath.Join(root, "repodata"), yumrepo.Options{ELMajor: 10, Revision: created.Unix(), Signer: signer}, &yumrepo.SliceIterator{Inputs: []yumrepo.PackageInput{{Path: rpmPath}}})
	if err != nil {
		t.Fatal(err)
	}
	relabelYUMVersionAndResign(t, ctx, root, generation.Artifacts[0], info.Version, "999.0", signer)
	packageKey, err := os.ReadFile(filepath.Join("..", "..", "test", "compat", "testdata", "PGDG-RPM-GPG-KEY-RHEL-nonfree.asc"))
	if err != nil {
		t.Fatal(err)
	}
	packageKeyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(packageKey))
	if err != nil {
		t.Fatal(err)
	}
	check := YUMCheck{CheckID: "yum-resigned-relabel", Root: root, Compression: yumrepo.CompressionZstd, Verifier: signer, PackageKeyring: packageKeyring, VerifyAt: time.Now().UTC(), Workers: 2, ChunkEntries: 1}
	report := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{check}})
	if !hasCode(report, "YUM_BODY_IDENTITY_CHANGED") {
		t.Fatalf("validly re-signed YUM metadata-only identity relabel was not rejected by RPM body binding: %+v", report)
	}
}

func relabelYUMVersionAndResign(t *testing.T, ctx context.Context, root string, old yumrepo.Artifact, oldVersion, newVersion string, signer yumrepo.DetachedSigner) {
	t.Helper()
	oldPath := filepath.Join(root, filepath.FromSlash(old.Path))
	compressed, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := decoder.DecodeAll(compressed, nil)
	decoder.Close()
	if err != nil {
		t.Fatal(err)
	}
	oldField, newField := []byte(`ver="`+oldVersion+`"`), []byte(`ver="`+newVersion+`"`)
	versionStart := bytes.Index(plain, []byte("<version "))
	if versionStart < 0 {
		t.Fatal("primary XML lacks package version")
	}
	versionEnd := bytes.IndexByte(plain[versionStart:], '>')
	if versionEnd < 0 {
		t.Fatal("primary XML package version is truncated")
	}
	versionEnd += versionStart + 1
	versionTag := plain[versionStart:versionEnd]
	if bytes.Count(versionTag, oldField) != 1 {
		t.Fatalf("primary package version tag does not contain %q", oldVersion)
	}
	versionTag = bytes.Replace(versionTag, oldField, newField, 1)
	plain = append(append(append([]byte(nil), plain[:versionStart]...), versionTag...), plain[versionEnd:]...)
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	compressed = encoder.EncodeAll(plain, nil)
	encoder.Close()
	compressedDigest, openDigest := sha256.Sum256(compressed), sha256.Sum256(plain)
	newArtifact := old
	newArtifact.SHA256 = hex.EncodeToString(compressedDigest[:])
	newArtifact.OpenSHA256 = hex.EncodeToString(openDigest[:])
	newArtifact.Size = int64(len(compressed))
	newArtifact.OpenSize = int64(len(plain))
	newArtifact.Path = "repodata/" + newArtifact.SHA256 + "-primary.xml.zst"
	newPath := filepath.Join(root, filepath.FromSlash(newArtifact.Path))
	writeMutableTestFile(t, newPath, compressed)
	if newPath != oldPath {
		if err := os.Remove(oldPath); err != nil {
			t.Fatal(err)
		}
	}
	repomdPath := filepath.Join(root, "repodata", "repomd.xml")
	repomd, err := os.ReadFile(repomdPath)
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(repomd, []byte(`<data type="primary">`))
	if start < 0 {
		t.Fatal("repomd lacks primary data")
	}
	endRelative := bytes.Index(repomd[start:], []byte("</data>"))
	if endRelative < 0 {
		t.Fatal("repomd primary data is truncated")
	}
	end := start + endRelative + len("</data>")
	block := string(repomd[start:end])
	replacements := [][2]string{{"<checksum type=\"sha256\">" + old.SHA256 + "</checksum>", "<checksum type=\"sha256\">" + newArtifact.SHA256 + "</checksum>"},
		{"<open-checksum type=\"sha256\">" + old.OpenSHA256 + "</open-checksum>", "<open-checksum type=\"sha256\">" + newArtifact.OpenSHA256 + "</open-checksum>"},
		{"<location href=\"" + old.Path + "\"/>", "<location href=\"" + newArtifact.Path + "\"/>"},
		{"<size>" + strconv.FormatInt(old.Size, 10) + "</size>", "<size>" + strconv.FormatInt(newArtifact.Size, 10) + "</size>"},
		{"<open-size>" + strconv.FormatInt(old.OpenSize, 10) + "</open-size>", "<open-size>" + strconv.FormatInt(newArtifact.OpenSize, 10) + "</open-size>"}}
	for _, replacement := range replacements {
		if strings.Count(block, replacement[0]) != 1 {
			t.Fatalf("repomd primary block does not contain exactly one %q in %s", replacement[0], block)
		}
		block = strings.Replace(block, replacement[0], replacement[1], 1)
	}
	repomd = append(append(append([]byte(nil), repomd[:start]...), []byte(block)...), repomd[end:]...)
	writeMutableTestFile(t, repomdPath, repomd)
	var signature bytes.Buffer
	if err := signer.Sign(ctx, bytes.NewReader(repomd), &signature); err != nil {
		t.Fatal(err)
	}
	writeMutableTestFile(t, filepath.Join(root, "repodata", "repomd.xml.asc"), signature.Bytes())
}

func writeMutableTestFile(t *testing.T, filename string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, 0o644); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, body, 0o644); err != nil {
		t.Fatal(err)
	}
}
