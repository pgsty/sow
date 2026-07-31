package yumrepo

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/klauspost/compress/zstd"
)

func TestPackageLocation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, base, want string
	}{
		{"PostgreSQL", "postgresql.rpm", "Packages/p/postgresql.rpm"},
		{"9tool", "9tool-1.rpm", "Packages/9/9tool-1.rpm"},
		{"éclair", "e.rpm", "Packages/c/e.rpm"},
	}
	for _, tt := range tests {
		got, err := PackageLocation(tt.name, tt.base)
		if err != nil {
			t.Fatalf("PackageLocation(%q, %q): %v", tt.name, tt.base, err)
		}
		if got != tt.want {
			t.Fatalf("PackageLocation(%q, %q) = %q, want %q", tt.name, tt.base, got, tt.want)
		}
	}
	for _, bad := range []string{"../x.rpm", "/x.rpm", "a/b.rpm", "a\\b.rpm", "x\n.rpm", "x%2fescape.rpm", "x?.rpm", "not-rpm", ""} {
		if _, err := PackageLocation("safe", bad); err == nil {
			t.Errorf("PackageLocation accepted unsafe basename %q", bad)
		}
	}
}

func TestCompressionForEL(t *testing.T) {
	t.Parallel()
	for major, want := range map[int]Compression{8: CompressionGzip, 9: CompressionZstd, 10: CompressionZstd} {
		got, err := CompressionForEL(major)
		if err != nil || got != want {
			t.Fatalf("CompressionForEL(%d) = %q, %v; want %q", major, got, err, want)
		}
	}
	if _, err := CompressionForEL(7); err == nil {
		t.Fatal("EL7 unexpectedly accepted")
	}
}

func TestCompressionForOptionsLegacyFrozenEL7(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		opts    Options
		want    Compression
		wantErr string
	}{
		{name: "legacy frozen EL7 gzip", opts: Options{ELMajor: 7, Frozen: true, Compression: CompressionGzip}, want: CompressionGzip},
		{name: "active EL7", opts: Options{ELMajor: 7, Compression: CompressionGzip}, wantErr: "only for frozen legacy repositories"},
		{name: "frozen EL7 zstd", opts: Options{ELMajor: 7, Frozen: true, Compression: CompressionZstd}, wantErr: "require explicit gzip"},
		{name: "frozen EL7 implicit compression", opts: Options{ELMajor: 7, Frozen: true}, wantErr: "require explicit gzip"},
		{name: "EL8 derived gzip", opts: Options{ELMajor: 8}, want: CompressionGzip},
		{name: "EL8 explicit gzip", opts: Options{ELMajor: 8, Compression: CompressionGzip}, want: CompressionGzip},
		{name: "EL8 zstd mismatch", opts: Options{ELMajor: 8, Compression: CompressionZstd}, wantErr: "does not match"},
		{name: "EL9 derived zstd", opts: Options{ELMajor: 9}, want: CompressionZstd},
		{name: "EL10 explicit zstd", opts: Options{ELMajor: 10, Compression: CompressionZstd}, want: CompressionZstd},
		{name: "EL10 gzip mismatch", opts: Options{ELMajor: 10, Compression: CompressionGzip}, wantErr: "does not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := CompressionForOptions(tt.opts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("CompressionForOptions(%#v) error = %v, want containing %q", tt.opts, err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("CompressionForOptions(%#v) = %q, %v; want %q", tt.opts, got, err, tt.want)
			}
		})
	}
}

func TestCompressionForOptionsFrozenCrossELCompatibility(t *testing.T) {
	valid := Options{ELMajor: 0, Frozen: true, Compatibility: true, Compression: CompressionGzip}
	if got, err := CompressionForOptions(valid); err != nil || got != CompressionGzip {
		t.Fatalf("valid compatibility policy rejected: got=%q err=%v", got, err)
	}
	for _, invalid := range []Options{
		{ELMajor: 9, Frozen: true, Compatibility: true, Compression: CompressionGzip},
		{ELMajor: 0, Compatibility: true, Compression: CompressionGzip},
		{ELMajor: 0, Frozen: true, Compatibility: true, Compression: CompressionZstd},
		{ELMajor: 0, Frozen: true, Compression: CompressionGzip},
	} {
		if _, err := CompressionForOptions(invalid); err == nil {
			t.Fatalf("invalid compatibility policy accepted: %+v", invalid)
		}
	}
}

func TestGenerateLegacyFrozenEL7Gzip(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "legacy-1.2.3-4.x86_64.rpm")
	writeRPMFixture(t, fixture, "legacy")
	signer := testSigner(t)
	dest := filepath.Join(t.TempDir(), "repodata")
	opts := Options{
		ELMajor:     7,
		Frozen:      true,
		Compression: CompressionGzip,
		Revision:    1_700_000_007,
		Signer:      signer,
	}
	generation, err := Generate(t.Context(), dest, opts, &SliceIterator{Inputs: []PackageInput{{
		Path:     fixture,
		FileTime: time.Unix(1_600_000_007, 0),
	}}})
	if err != nil {
		t.Fatalf("Generate frozen EL7: %v", err)
	}
	if generation.Packages != 1 || generation.Revision != opts.Revision {
		t.Fatalf("frozen EL7 generation = %#v", generation)
	}
	for _, artifact := range generation.Artifacts {
		if artifact.Compression != CompressionGzip || !strings.HasSuffix(artifact.Path, ".gz") {
			t.Errorf("frozen EL7 artifact = %#v, want gzip", artifact)
		}
		assertArtifact(t, dest, artifact)
	}
	validated, err := ValidateDirectory(t.Context(), dest, CompressionGzip, signer)
	if err != nil {
		t.Fatalf("ValidateDirectory frozen EL7: %v", err)
	}
	if validated.Packages != 1 || validated.RepomdSHA256 != generation.RepomdSHA256 {
		t.Fatalf("validated frozen EL7 generation = %#v", validated)
	}

	if err := os.WriteFile(filepath.Join(dest, "modules.yaml.gz"), []byte("forbidden modulemd"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateDirectory(t.Context(), dest, CompressionGzip, signer); err == nil {
		t.Fatal("frozen EL7 generation with modulemd unexpectedly validated")
	}
}

func TestValidateDirectoryUsesPrivateScratchAndLeavesReadOnlyServedTreeUnchanged(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "readonly-1.0-1.x86_64.rpm")
	writeRPMFixture(t, fixture, "readonly")
	signer := testSigner(t)
	root := t.TempDir()
	dest := filepath.Join(root, "repodata")
	if _, err := Generate(t.Context(), dest, Options{ELMajor: 8, Revision: 1, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dest, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dest, 0o755) })
	if _, err := ValidateDirectory(t.Context(), dest, CompressionGzip, signer); err != nil {
		t.Fatalf("validate read-only served generation: %v", err)
	}
	after, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("validation exposed scratch in served tree: before=%d after=%d", len(before), len(after))
	}
	for index := range before {
		if before[index].Name() != after[index].Name() {
			t.Fatalf("served tree changed during validation: before=%s after=%s", before[index].Name(), after[index].Name())
		}
	}
}

func TestValidateDirectoryRejectsGenerationSwapAfterSignatureVerification(t *testing.T) {
	signer := testSigner(t)
	parent := t.TempDir()
	live := filepath.Join(parent, "live")
	replacement := filepath.Join(parent, "replacement")
	held := filepath.Join(parent, "held")
	for dir, revision := range map[string]int64{live: 1, replacement: 2} {
		if _, err := Generate(t.Context(), dir, Options{
			ELMajor:  8,
			Revision: revision,
			Signer:   signer,
		}, &SliceIterator{}); err != nil {
			t.Fatalf("generate revision %d: %v", revision, err)
		}
	}

	swapped := false
	verifier := detachedVerifierFunc(func(ctx context.Context, message, signature io.Reader) error {
		if err := signer.Verify(ctx, message, signature); err != nil {
			return err
		}
		if err := os.Rename(live, held); err != nil {
			return fmt.Errorf("hold signed generation: %w", err)
		}
		if err := os.Rename(replacement, live); err != nil {
			_ = os.Rename(held, live)
			return fmt.Errorf("activate replacement generation: %w", err)
		}
		swapped = true
		return nil
	})

	_, err := ValidateDirectory(t.Context(), live, CompressionGzip, verifier)
	if !swapped {
		t.Fatal("test verifier did not swap the public generation")
	}
	if err == nil || !strings.Contains(err.Error(), "generation directory changed") {
		t.Fatalf("generation swap error = %v, want bound-directory rejection", err)
	}
}

func TestValidateDirectoryRejectsRepomdEntrySwapAfterSignatureVerification(t *testing.T) {
	signer := testSigner(t)
	parent := t.TempDir()
	live := filepath.Join(parent, "live")
	if _, err := Generate(t.Context(), live, Options{
		ELMajor: 8, Revision: 1, Signer: signer,
	}, &SliceIterator{}); err != nil {
		t.Fatal(err)
	}
	repomd := filepath.Join(live, "repomd.xml")
	original, err := os.ReadFile(repomd)
	if err != nil {
		t.Fatal(err)
	}
	originalInfo, err := os.Lstat(repomd)
	if err != nil {
		t.Fatal(err)
	}
	replacement := append([]byte(nil), original...)
	replacement[len(replacement)-1] ^= 0x01
	held := filepath.Join(parent, "held-repomd.xml")
	swapped := false
	verifier := detachedVerifierFunc(func(ctx context.Context, message, signature io.Reader) error {
		if err := signer.Verify(ctx, message, signature); err != nil {
			return err
		}
		if err := os.Rename(repomd, held); err != nil {
			return fmt.Errorf("hold signed repomd: %w", err)
		}
		if err := os.WriteFile(repomd, replacement, originalInfo.Mode().Perm()); err != nil {
			_ = os.Rename(held, repomd)
			return fmt.Errorf("install unsigned replacement repomd: %w", err)
		}
		if err := os.Chtimes(repomd, originalInfo.ModTime(), originalInfo.ModTime()); err != nil {
			return err
		}
		swapped = true
		return nil
	})

	_, err = ValidateDirectory(t.Context(), live, CompressionGzip, verifier)
	if !swapped {
		t.Fatal("test verifier did not swap repomd.xml")
	}
	if err == nil || !strings.Contains(err.Error(), "changed after inspection") {
		t.Fatalf("same-directory repomd swap error = %v, want final entry-identity rejection", err)
	}
}

func TestMetadataIdentitySpoolCancellationIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	spool := newMetadataIdentitySpool(ctx, t.TempDir(), "primary")
	for index := 0; index < metadataIdentityChunkEntries; index++ {
		identity := fmt.Sprintf("%064x", index+1)
		if err := spool.Add(identity); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	if _, err := spool.Finish(); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled identity merge continued: %v", err)
	}
}

type detachedVerifierFunc func(context.Context, io.Reader, io.Reader) error

func (verify detachedVerifierFunc) Verify(ctx context.Context, message, signature io.Reader) error {
	return verify(ctx, message, signature)
}

func TestGenerateRejectsEL7OutsideFrozenGzipPolicy(t *testing.T) {
	tests := []struct {
		name string
		opts Options
	}{
		{name: "active gzip", opts: Options{ELMajor: 7, Compression: CompressionGzip}},
		{name: "frozen zstd", opts: Options{ELMajor: 7, Frozen: true, Compression: CompressionZstd}},
		{name: "frozen implicit compression", opts: Options{ELMajor: 7, Frozen: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			dest := filepath.Join(parent, "repodata")
			tt.opts.Revision = 7
			tt.opts.Signer = testSigner(t)
			if _, err := Generate(t.Context(), dest, tt.opts, &SliceIterator{}); err == nil {
				t.Fatalf("Generate(%#v) unexpectedly succeeded", tt.opts)
			}
			if _, err := os.Lstat(dest); !os.IsNotExist(err) {
				t.Fatalf("rejected EL7 policy left destination: %v", err)
			}
			matches, err := filepath.Glob(filepath.Join(parent, ".repodata.build-*"))
			if err != nil || len(matches) != 0 {
				t.Fatalf("rejected EL7 policy left staging residue %v, %v", matches, err)
			}
		})
	}
}

func TestValidatePackageHref(t *testing.T) {
	t.Parallel()
	if err := validatePackageHref("PostgreSQL", "Packages/p/postgresql-1.rpm"); err != nil {
		t.Fatalf("valid href: %v", err)
	}
	for _, href := range []string{
		"/Packages/p/x.rpm", "Packages/p/../x.rpm", "Packages/q/postgresql.rpm",
		"Packages/p/x%2frpm.rpm", "Packages/p/x?.rpm", "other/p/x.rpm",
	} {
		if err := validatePackageHref("PostgreSQL", href); err == nil {
			t.Errorf("unsafe href accepted: %q", href)
		}
	}
}

func TestGenerateEmptyRepository(t *testing.T) {
	signer := testSigner(t)
	dest := filepath.Join(t.TempDir(), "repodata")
	g, err := Generate(context.Background(), dest, Options{ELMajor: 9, Revision: 3, Signer: signer}, &SliceIterator{})
	if err != nil {
		t.Fatalf("Generate empty repository: %v", err)
	}
	if g.Packages != 0 {
		t.Fatalf("empty packages = %d", g.Packages)
	}
	if _, err := ValidateDirectory(context.Background(), dest, CompressionZstd, signer); err != nil {
		t.Fatalf("Validate empty repository: %v", err)
	}
}

func TestGenerateParseableFixtureEL8(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "fixture-1.2.3-4.x86_64.rpm")
	writeRPMFixture(t, fixture, "fixture")
	inspected, err := InspectPackage(context.Background(), PackageInput{Path: fixture})
	if err != nil {
		t.Fatalf("InspectPackage fixture: %v", err)
	}
	if inspected.Name != "fixture" || inspected.Version != "1.2.3" || inspected.Release != "4" || inspected.Epoch != 0 || inspected.Arch != "x86_64" || inspected.Size <= 0 || inspected.Location != "Packages/f/fixture-1.2.3-4.x86_64.rpm" || !validSHA256(inspected.SHA256) {
		t.Fatalf("InspectPackage fixture = %#v", inspected)
	}
	signer := testSigner(t)
	dest := filepath.Join(t.TempDir(), "repodata")
	g, err := Generate(context.Background(), dest, Options{ELMajor: 8, Revision: 1_700_000_000, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture, FileTime: time.Unix(1_600_000_000, 0)}}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if g.Packages != 1 {
		t.Fatalf("packages = %d, want 1", g.Packages)
	}
	for _, artifact := range g.Artifacts {
		if artifact.Compression != CompressionGzip || !strings.HasSuffix(artifact.Path, ".gz") {
			t.Errorf("EL8 artifact = %#v, want gzip", artifact)
		}
		assertArtifact(t, dest, artifact)
	}
	primary := readArtifact(t, dest, g.Artifacts[0])
	assertXMLRoot(t, primary, commonNS, "metadata", 1)
	for _, want := range []string{
		"<name>fixture</name>", `<version epoch="0" ver="1.2.3" rel="4"/>`,
		`<location href="Packages/f/fixture-1.2.3-4.x86_64.rpm"/>`,
		`<rpm:entry name="bash" flags="GE" epoch="0" ver="4.0" rel="1"/>`,
		"<file>/etc/fixture.conf</file>",
	} {
		if !bytes.Contains(primary, []byte(want)) {
			t.Errorf("primary XML missing %s\n%s", want, primary)
		}
	}
	assertXMLRoot(t, readArtifact(t, dest, g.Artifacts[1]), filelistsNS, "filelists", 1)
	other := readArtifact(t, dest, g.Artifacts[2])
	assertXMLRoot(t, other, otherNS, "otherdata", 1)
	if !bytes.Contains(other, []byte(`<changelog author="SOW Test" date="1600000000">fixture release</changelog>`)) {
		t.Fatalf("other XML lacks changelog: %s", other)
	}
	verifyRepomd(t, dest, g, signer)
	validated, err := ValidateDirectory(context.Background(), dest, CompressionGzip, signer)
	if err != nil {
		t.Fatalf("ValidateDirectory: %v", err)
	}
	if validated.Packages != 1 || validated.Revision != g.Revision {
		t.Fatalf("validated generation = %#v", validated)
	}

	g2, err := Generate(context.Background(), dest, Options{ELMajor: 8, Revision: 1_700_000_000, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture, FileTime: time.Unix(1_600_000_000, 0)}}})
	if err != nil {
		t.Fatalf("idempotent Generate: %v", err)
	}
	if !g2.Reused {
		t.Fatal("second identical generation was not reused")
	}
}

func TestGenerateCheckedInExternalRPMEL10(t *testing.T) {
	encoded, err := os.ReadFile("../cli/testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	if err != nil {
		t.Fatalf("read checked-in RPM fixture: %v", err)
	}
	rpmBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatalf("decode checked-in RPM fixture: %v", err)
	}
	rpmPath := filepath.Join(t.TempDir(), "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm")
	if err := os.WriteFile(rpmPath, rpmBytes, 0o444); err != nil {
		t.Fatalf("materialize checked-in RPM fixture: %v", err)
	}
	signer := testSigner(t)
	inspected, err := InspectPackage(context.Background(), PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatalf("InspectPackage checked-in RPM: %v", err)
	}
	if inspected.Name != "pgdg-redhat-nonfree-repo" || inspected.Arch != "noarch" || inspected.Location != "Packages/p/pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm" {
		t.Fatalf("InspectPackage checked-in RPM = %#v", inspected)
	}
	dest := filepath.Join(t.TempDir(), "repodata")
	g, err := Generate(context.Background(), dest, Options{ELMajor: 10, Revision: 1_700_000_001, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: rpmPath, FileTime: time.Unix(1_600_000_001, 0)}}})
	if err != nil {
		t.Fatalf("Generate checked-in RPM: %v", err)
	}
	for _, artifact := range g.Artifacts {
		if artifact.Compression != CompressionZstd || !strings.HasSuffix(artifact.Path, ".zst") {
			t.Errorf("EL10 artifact = %#v, want zstd", artifact)
		}
		assertArtifact(t, dest, artifact)
	}
	primary := readArtifact(t, dest, g.Artifacts[0])
	assertXMLRoot(t, primary, commonNS, "metadata", 1)
	for _, want := range []string{
		"<name>pgdg-redhat-nonfree-repo</name>",
		"<arch>noarch</arch>",
		`<location href="Packages/p/pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm"/>`,
	} {
		if !bytes.Contains(primary, []byte(want)) {
			t.Errorf("checked-in primary XML missing %s", want)
		}
	}
	wantSum := sha256.Sum256(rpmBytes)
	if !bytes.Contains(primary, []byte(hex.EncodeToString(wantSum[:]))) {
		t.Fatal("primary package checksum does not hash checked-in RPM bytes")
	}
	verifyRepomd(t, dest, g, signer)
	if _, err := ValidateDirectory(context.Background(), dest, CompressionZstd, signer); err != nil {
		t.Fatalf("ValidateDirectory checked-in RPM: %v", err)
	}
}

func TestGenerateRejectsUnsortedLocations(t *testing.T) {
	dir := t.TempDir()
	zeta, alpha := filepath.Join(dir, "zeta.rpm"), filepath.Join(dir, "alpha.rpm")
	writeRPMFixture(t, zeta, "zeta")
	writeRPMFixture(t, alpha, "alpha")
	_, err := Generate(context.Background(), filepath.Join(t.TempDir(), "repodata"), Options{ELMajor: 9, Revision: 1, Signer: testSigner(t)}, &SliceIterator{Inputs: []PackageInput{{Path: zeta}, {Path: alpha}}})
	if err == nil || !strings.Contains(err.Error(), ErrUnsortedInput.Error()) {
		t.Fatalf("unsorted Generate error = %v", err)
	}
}

func TestGenerateRejectsDuplicatePackageBodyUnderDifferentLocations(t *testing.T) {
	parent := t.TempDir()
	fixture := filepath.Join(parent, "fixture.rpm")
	writeRPMFixture(t, fixture, "fixture")
	dest := filepath.Join(parent, "repodata")
	_, err := Generate(t.Context(), dest, Options{ELMajor: 9, Revision: 1, Signer: testSigner(t)}, &SliceIterator{Inputs: []PackageInput{
		{Path: fixture, Basename: "fixture-a.rpm"},
		{Path: fixture, Basename: "fixture-b.rpm"},
	}})
	if err == nil || !strings.Contains(err.Error(), "duplicate pkgid") {
		t.Fatalf("duplicate package body Generate error = %v", err)
	}
	if _, statErr := os.Lstat(dest); !os.IsNotExist(statErr) {
		t.Fatalf("duplicate package body left destination: %v", statErr)
	}
	matches, globErr := filepath.Glob(filepath.Join(parent, ".repodata.build-*"))
	if globErr != nil || len(matches) != 0 {
		t.Fatalf("duplicate package body left staging residue %v, %v", matches, globErr)
	}
}

type rejectingSigner struct{}

func (rejectingSigner) Sign(_ context.Context, _ io.Reader, signature io.Writer) error {
	_, err := signature.Write([]byte("not-a-signature"))
	return err
}
func (rejectingSigner) Verify(context.Context, io.Reader, io.Reader) error {
	return errors.New("injected verifier rejection")
}

func TestSignerPreflightFailsBeforeFilesystemMutation(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "not-created", "repodata")
	_, err := Generate(context.Background(), dest, Options{ELMajor: 9, Revision: 1, Signer: rejectingSigner{}}, &SliceIterator{})
	if err == nil || !strings.Contains(err.Error(), "preflight") {
		t.Fatalf("preflight error = %v", err)
	}
	if _, err := os.Lstat(filepath.Dir(dest)); !os.IsNotExist(err) {
		t.Fatalf("signer preflight mutated filesystem: %v", err)
	}
}

func TestGenerateRejectsSymlinkAndMalformedRPMWithoutResidue(t *testing.T) {
	parent := t.TempDir()
	fixture := filepath.Join(parent, "fixture.rpm")
	writeRPMFixture(t, fixture, "fixture")
	link := filepath.Join(parent, "linked.rpm")
	if err := os.Symlink(fixture, link); err != nil {
		t.Fatal(err)
	}
	corruptHeader := filepath.Join(parent, "corrupt-header.rpm")
	corrupt, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	// 96-byte lead + 16-byte empty signature header = main header magic.
	corrupt[112] ^= 0xff
	if err := os.WriteFile(corruptHeader, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t)
	for _, input := range []string{link, filepath.Join(parent, "truncated.rpm"), corruptHeader} {
		if strings.Contains(input, "truncated") {
			if err := os.WriteFile(input, []byte{0xed, 0xab, 0xee, 0xdb}, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		dest := filepath.Join(parent, "repodata")
		if _, err := Generate(context.Background(), dest, Options{ELMajor: 8, Revision: 1, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: input}}}); err == nil {
			t.Fatalf("unsafe/malformed RPM %q unexpectedly generated", input)
		}
		if _, err := os.Lstat(dest); !os.IsNotExist(err) {
			t.Fatalf("failed generation left destination for %q: %v", input, err)
		}
		matches, err := filepath.Glob(filepath.Join(parent, ".repodata.build-*"))
		if err != nil || len(matches) != 0 {
			t.Fatalf("failed generation left staging residue %v, %v", matches, err)
		}
	}
}

func TestMalformedXMLAndSymlinkGenerationAreRejected(t *testing.T) {
	for _, malformed := range []string{
		`<metadata xmlns="` + commonNS + `" packages="1"><package>`,
		`<!DOCTYPE metadata [<!ENTITY x "boom">]><metadata xmlns="` + commonNS + `" packages="0"></metadata>`,
		`<metadata xmlns="` + commonNS + `" packages="1"><package><name>x</name><location href="Packages/x/../x.rpm"/></package></metadata>`,
	} {
		if _, err := validateMetadataXML(strings.NewReader(malformed), "primary"); err == nil {
			t.Fatalf("malformed XML unexpectedly accepted: %s", malformed)
		}
	}

	fixture := filepath.Join(t.TempDir(), "fixture.rpm")
	writeRPMFixture(t, fixture, "fixture")
	signer := testSigner(t)
	realDir := filepath.Join(t.TempDir(), "repodata")
	if _, err := Generate(context.Background(), realDir, Options{ELMajor: 8, Revision: 1, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}}); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(realDir), "repodata-link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateDirectory(context.Background(), link, CompressionGzip, signer); err == nil {
		t.Fatal("symlink generation directory unexpectedly validated")
	}
}

func TestValidateDirectoryRejectsTamper(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "fixture.rpm")
	writeRPMFixture(t, fixture, "fixture")
	signer := testSigner(t)
	dest := filepath.Join(t.TempDir(), "repodata")
	g, err := Generate(context.Background(), dest, Options{ELMajor: 9, Revision: 2, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}})
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(dest, strings.TrimPrefix(g.Artifacts[0].Path, "repodata/"))
	f, err := os.OpenFile(artifact, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("tamper")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateDirectory(context.Background(), dest, CompressionZstd, signer); err == nil {
		t.Fatal("tampered repodata unexpectedly validated")
	}
}

func TestValidateDirectoryRejectsSignatureAndExtraFile(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "fixture.rpm")
	writeRPMFixture(t, fixture, "fixture")
	signer := testSigner(t)
	dest := filepath.Join(t.TempDir(), "repodata")
	if _, err := Generate(context.Background(), dest, Options{ELMajor: 8, Revision: 4, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}}); err != nil {
		t.Fatal(err)
	}
	signature := filepath.Join(dest, "repomd.xml.asc")
	data, err := os.ReadFile(signature)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 1
	if err := os.WriteFile(signature, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateDirectory(context.Background(), dest, CompressionGzip, signer); err == nil {
		t.Fatal("corrupt signature unexpectedly validated")
	}
	if _, err := Generate(context.Background(), dest, Options{ELMajor: 8, Revision: 4, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}}); err == nil {
		t.Fatal("conflicting existing generation with corrupt signature unexpectedly reused")
	}

	clean := filepath.Join(t.TempDir(), "repodata")
	if _, err := Generate(context.Background(), clean, Options{ELMajor: 8, Revision: 4, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clean, "modules.yaml"), []byte("forbidden"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateDirectory(context.Background(), clean, CompressionGzip, signer); err == nil {
		t.Fatal("extra modulemd file unexpectedly validated")
	}
}

func TestActivateLocalUsesNativeDirectoryExchange(t *testing.T) {
	parent := t.TempDir()
	fixture := filepath.Join(parent, "fixture.rpm")
	writeRPMFixture(t, fixture, "fixture")
	signer := testSigner(t)
	live, staged := filepath.Join(parent, "repodata"), filepath.Join(parent, ".repodata.staged")
	if _, err := Generate(context.Background(), live, Options{ELMajor: 8, Revision: 10, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}}); err != nil {
		t.Fatalf("Generate live: %v", err)
	}
	if _, err := Generate(context.Background(), staged, Options{ELMajor: 8, Revision: 11, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}}); err != nil {
		t.Fatalf("Generate staged: %v", err)
	}
	exchanger := NativeDirectoryExchanger{}
	if err := exchanger.Probe(parent); err != nil {
		if errors.Is(err, ErrAtomicUnsupported) {
			t.Skipf("filesystem lacks native directory exchange: %v", err)
		}
		t.Fatal(err)
	}
	stagedBefore, err := ValidateDirectory(context.Background(), staged, CompressionGzip, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := ActivateLocal(context.Background(), live, staged, CompressionGzip, signer, stagedBefore.RepomdSHA256, exchanger); err != nil {
		t.Fatalf("ActivateLocal: %v", err)
	}
	if err := ActivateLocal(context.Background(), live, staged, CompressionGzip, signer, stagedBefore.RepomdSHA256, exchanger); err != nil {
		t.Fatalf("idempotent ActivateLocal: %v", err)
	}
	liveGeneration, err := ValidateDirectory(context.Background(), live, CompressionGzip, signer)
	if err != nil {
		t.Fatal(err)
	}
	oldGeneration, err := ValidateDirectory(context.Background(), staged, CompressionGzip, signer)
	if err != nil {
		t.Fatal(err)
	}
	if liveGeneration.Revision != 11 || oldGeneration.Revision != 10 {
		t.Fatalf("exchange revisions live=%d staged=%d, want 11/10", liveGeneration.Revision, oldGeneration.Revision)
	}
}

type failedExchange struct{ err error }

func (f failedExchange) Probe(string) error            { return nil }
func (f failedExchange) Exchange(string, string) error { return f.err }

func TestActivateLocalExchangeFailureKeepsLiveGeneration(t *testing.T) {
	parent := t.TempDir()
	fixture := filepath.Join(parent, "fixture.rpm")
	writeRPMFixture(t, fixture, "fixture")
	signer := testSigner(t)
	live, staged := filepath.Join(parent, "repodata"), filepath.Join(parent, ".repodata.staged")
	if _, err := Generate(context.Background(), live, Options{ELMajor: 8, Revision: 20, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(context.Background(), staged, Options{ELMajor: 8, Revision: 21, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}}); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("injected exchange failure")
	stagedGeneration, err := ValidateDirectory(context.Background(), staged, CompressionGzip, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := ActivateLocal(context.Background(), live, staged, CompressionGzip, signer, stagedGeneration.RepomdSHA256, failedExchange{err: wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("ActivateLocal error = %v, want %v", err, wantErr)
	}
	g, err := ValidateDirectory(context.Background(), live, CompressionGzip, signer)
	if err != nil {
		t.Fatal(err)
	}
	if g.Revision != 20 {
		t.Fatalf("live revision changed to %d after failed exchange", g.Revision)
	}
}

type errorAfterNativeExchange struct {
	native NativeDirectoryExchanger
	err    error
}

func (e errorAfterNativeExchange) Probe(parent string) error { return e.native.Probe(parent) }
func (e errorAfterNativeExchange) Exchange(first, second string) error {
	if err := e.native.Exchange(first, second); err != nil {
		return err
	}
	return e.err
}

func TestActivateLocalRetryDoesNotSwapBackAfterAmbiguousError(t *testing.T) {
	parent := t.TempDir()
	fixture := filepath.Join(parent, "fixture.rpm")
	writeRPMFixture(t, fixture, "fixture")
	signer := testSigner(t)
	live, staged := filepath.Join(parent, "repodata"), filepath.Join(parent, ".repodata.staged")
	if _, err := Generate(context.Background(), live, Options{ELMajor: 8, Revision: 30, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(context.Background(), staged, Options{ELMajor: 8, Revision: 31, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}}); err != nil {
		t.Fatal(err)
	}
	stagedGeneration, err := ValidateDirectory(context.Background(), staged, CompressionGzip, signer)
	if err != nil {
		t.Fatal(err)
	}
	native := NativeDirectoryExchanger{}
	if err := native.Probe(parent); err != nil {
		if errors.Is(err, ErrAtomicUnsupported) {
			t.Skipf("filesystem lacks native directory exchange: %v", err)
		}
		t.Fatal(err)
	}
	injected := errors.New("ambiguous error after kernel exchange")
	err = ActivateLocal(context.Background(), live, staged, CompressionGzip, signer, stagedGeneration.RepomdSHA256, errorAfterNativeExchange{native: native, err: injected})
	if !errors.Is(err, injected) {
		t.Fatalf("ambiguous activation error = %v", err)
	}
	active, err := ValidateDirectory(context.Background(), live, CompressionGzip, signer)
	if err != nil {
		t.Fatal(err)
	}
	if active.Revision != 31 {
		t.Fatalf("kernel exchange did not activate revision 31: %d", active.Revision)
	}
	if err := ActivateLocal(context.Background(), live, staged, CompressionGzip, signer, stagedGeneration.RepomdSHA256, native); err != nil {
		t.Fatalf("retry after ambiguous exchange: %v", err)
	}
	active, err = ValidateDirectory(context.Background(), live, CompressionGzip, signer)
	if err != nil {
		t.Fatal(err)
	}
	if active.Revision != 31 {
		t.Fatalf("retry swapped old revision back into live: %d", active.Revision)
	}
}

func testSigner(t *testing.T) *OpenPGPKey {
	t.Helper()
	created := time.Unix(1_500_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW Test", "", "sow@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: 2048})
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	var private bytes.Buffer
	if err := entity.SerializePrivate(&private, nil); err != nil {
		t.Fatalf("SerializePrivate: %v", err)
	}
	signer, err := NewOpenPGPSigner(bytes.NewReader(private.Bytes()), nil, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("NewOpenPGPSigner: %v", err)
	}
	return signer
}

func assertArtifact(t *testing.T, dir string, artifact Artifact) {
	t.Helper()
	name := strings.TrimPrefix(artifact.Path, "repodata/")
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read artifact %s: %v", name, err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != artifact.SHA256 {
		t.Fatalf("artifact checksum = %s, want %s", got, artifact.SHA256)
	}
	if int64(len(data)) != artifact.Size {
		t.Fatalf("artifact size = %d, want %d", len(data), artifact.Size)
	}
	if !strings.HasPrefix(name, artifact.SHA256+"-") {
		t.Fatalf("artifact name %q is not SHA256-addressed", name)
	}
	open := readArtifact(t, dir, artifact)
	openSum := sha256.Sum256(open)
	if got := hex.EncodeToString(openSum[:]); got != artifact.OpenSHA256 {
		t.Fatalf("open checksum = %s, want %s", got, artifact.OpenSHA256)
	}
	if int64(len(open)) != artifact.OpenSize {
		t.Fatalf("open size = %d, want %d", len(open), artifact.OpenSize)
	}
}

func readArtifact(t *testing.T, dir string, artifact Artifact) []byte {
	t.Helper()
	data, err := os.Open(filepath.Join(dir, strings.TrimPrefix(artifact.Path, "repodata/")))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	var reader io.Reader
	switch artifact.Compression {
	case CompressionGzip:
		gz, err := gzip.NewReader(data)
		if err != nil {
			t.Fatal(err)
		}
		defer gz.Close()
		reader = gz
	case CompressionZstd:
		zr, err := zstd.NewReader(data, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(32<<20))
		if err != nil {
			t.Fatal(err)
		}
		defer zr.Close()
		reader = zr
	default:
		t.Fatalf("unknown compression %q", artifact.Compression)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertXMLRoot(t *testing.T, data []byte, namespace, local string, packages int) {
	t.Helper()
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			t.Fatalf("decode XML root: %v", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Space != namespace || start.Name.Local != local {
			t.Fatalf("root = {%s}%s, want {%s}%s", start.Name.Space, start.Name.Local, namespace, local)
		}
		for _, attr := range start.Attr {
			if attr.Name.Local == "packages" && attr.Value == fmt.Sprint(packages) {
				return
			}
		}
		t.Fatalf("root packages attribute != %d", packages)
	}
}

func verifyRepomd(t *testing.T, dir string, generation *Generation, signer *OpenPGPKey) {
	t.Helper()
	repomd, err := os.ReadFile(filepath.Join(dir, "repomd.xml"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(filepath.Join(dir, "repomd.xml.asc"))
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Verify(context.Background(), bytes.NewReader(repomd), bytes.NewReader(sig)); err != nil {
		t.Fatalf("verify repomd signature: %v", err)
	}
	if bytes.Count(repomd, []byte("<data type=")) != 3 {
		t.Fatalf("repomd data entries != 3:\n%s", repomd)
	}
	for _, a := range generation.Artifacts {
		for _, want := range []string{a.Type, a.SHA256, a.OpenSHA256, a.Path} {
			if !bytes.Contains(repomd, []byte(want)) {
				t.Errorf("repomd missing %q", want)
			}
		}
	}
	for _, forbidden := range []string{"primary_db", "filelists_db", "other_db", "modules", "zchunk", "sqlite"} {
		if bytes.Contains(repomd, []byte(forbidden)) {
			t.Errorf("repomd contains forbidden %q", forbidden)
		}
	}
}

type fixtureTag struct {
	id, typ uint32
	count   uint32
	data    []byte
}

func stringTag(id uint32, values ...string) fixtureTag {
	var data []byte
	for _, value := range values {
		data = append(data, value...)
		data = append(data, 0)
	}
	typ := uint32(8)
	if len(values) == 1 {
		typ = 6
	}
	return fixtureTag{id: id, typ: typ, count: uint32(len(values)), data: data}
}

func intTag(id uint32, values ...uint32) fixtureTag {
	data := make([]byte, 4*len(values))
	for i, value := range values {
		binary.BigEndian.PutUint32(data[i*4:], value)
	}
	return fixtureTag{id: id, typ: 4, count: uint32(len(values)), data: data}
}

func writeRPMFixture(t *testing.T, filename, name string) {
	t.Helper()
	tags := []fixtureTag{
		stringTag(tagName, name), stringTag(tagVersion, "1.2.3"), stringTag(tagRelease, "4"), intTag(tagEpoch, 0),
		stringTag(tagSummary, "fixture summary"), stringTag(tagDescription, "fixture description"), intTag(tagBuildTime, 1_600_000_000),
		stringTag(tagBuildHost, "builder.example.invalid"), intTag(1009, 1234), stringTag(tagVendor, "Pigsty"), stringTag(tagLicense, "MIT"),
		stringTag(tagPackager, "SOW Test"), stringTag(tagGroup, "System Environment/Base"), stringTag(tagURL, "https://example.invalid/fixture"),
		stringTag(tagArch, "x86_64"), intTag(tagFileModes, 0100644), intTag(tagFileFlags, 1), stringTag(tagSourceRPM, name+"-1.2.3-4.src.rpm"),
		stringTag(tagProvideNames, name), intTag(tagProvideFlags, 1<<3), stringTag(tagProvideEVRs, "0:1.2.3-4"),
		intTag(tagRequireFlags, (1<<2)|(1<<3)), stringTag(tagRequireNames, "bash"), stringTag(tagRequireEVRs, "0:4.0-1"),
		intTag(tagChangelogTime, 1_600_000_000), stringTag(tagChangelogName, "SOW Test"), stringTag(tagChangelogText, "fixture release"),
		intTag(tagDirIndexes, 0), stringTag(tagBaseNames, "fixture.conf"), stringTag(tagDirNames, "/etc/"),
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i].id < tags[j].id })
	var store bytes.Buffer
	indexes := make([]byte, 16*len(tags))
	for i, tag := range tags {
		offset := uint32(store.Len())
		binary.BigEndian.PutUint32(indexes[i*16:], tag.id)
		binary.BigEndian.PutUint32(indexes[i*16+4:], tag.typ)
		binary.BigEndian.PutUint32(indexes[i*16+8:], offset)
		binary.BigEndian.PutUint32(indexes[i*16+12:], tag.count)
		store.Write(tag.data)
	}
	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	copy(lead[10:76], name+"-1.2.3-4")
	binary.BigEndian.PutUint16(lead[78:80], 5)
	signatureHeader := make([]byte, 16)
	copy(signatureHeader, []byte{0x8e, 0xad, 0xe8, 1})
	header := make([]byte, 16)
	copy(header, []byte{0x8e, 0xad, 0xe8, 1})
	binary.BigEndian.PutUint32(header[8:12], uint32(len(tags)))
	binary.BigEndian.PutUint32(header[12:16], uint32(store.Len()))
	data := bytes.Join([][]byte{lead, signatureHeader, header, indexes, store.Bytes(), []byte("fixture payload")}, nil)
	if err := os.WriteFile(filename, data, 0o644); err != nil {
		t.Fatalf("write RPM fixture: %v", err)
	}
}
