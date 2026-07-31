package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestAPTCheckValidatesRealDebSignedMetadataByHashAndExactPool(t *testing.T) {
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
	debPath := decodeFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), "fixture.deb")
	pkg, err := aptrepo.InspectPackage(ctx, debPath, "main")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	copyFile(t, debPath, filepath.Join(root, filepath.FromSlash(pkg.PoolPath)))
	build, err := aptrepo.Generate(ctx, root, aptrepo.RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "jammy", Codename: "jammy",
		Components: []string{"main"}, Architectures: []string{"arm64"}, Date: created,
	}, []aptrepo.Index{{Component: "main", Architecture: "arm64", Packages: []aptrepo.Package{pkg}}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	check := APTCheck{CheckID: "apt", Root: root, ExpectedSuites: []string{"jammy"}, ExpectedSuiteComponents: map[string][]string{"jammy": {"main"}}, Verifier: verifier, VerifyAt: created, Workers: 2, ChunkEntries: 1}
	report := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{check}})
	if report.Outcome != OutcomePassed {
		t.Fatalf("valid APT repository rejected: %+v", report)
	}
	payloadManifest := filepath.Join(t.TempDir(), "apt-payload.tsv")
	writeSingleManifestEntry(t, payloadManifest, testManifestEntry(t, pkg.PoolPath, pkg.Size, pkg.SHA256))
	retainedPool := filepath.Join(t.TempDir(), "retained-pool")
	if err := os.Rename(filepath.Join(root, "pool"), retainedPool); err != nil {
		t.Fatal(err)
	}
	if missing := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{check}}); !hasCode(missing, "APT_PACKAGE_BODY_INVALID") {
		t.Fatalf("indexed DEB with an absent pool was not rejected: %+v", missing)
	}
	capabilityCheck := check
	capabilityCheck.ActualPayload = FileStream(payloadManifest)
	capabilityCheck.OpenPayload = func(entry manifest.Entry) (PayloadReadSeekCloser, error) {
		return os.Open(filepath.Join(retainedPool, filepath.FromSlash(strings.TrimPrefix(entry.Path, "pool/"))))
	}
	if capability := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{capabilityCheck}}); capability.Outcome != OutcomePassed {
		t.Fatalf("APT capability mode copied or required Root/pool instead of using the retained opener: %+v", capability)
	}
	if err := os.Rename(retainedPool, filepath.Join(root, "pool")); err != nil {
		t.Fatal(err)
	}
	phantomContract := check
	phantomContract.ExpectedSuiteComponents = map[string][]string{"jammy": {"main", "18"}}
	if drift := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{phantomContract}}); !hasCode(drift, "APT_COMPONENT_SET_DRIFT") {
		t.Fatalf("configured APT component-set drift not detected: %+v", drift)
	}
	byHashPath := filepath.Join(root, filepath.FromSlash(build.ByHashGeneration.Paths[0]))
	byHashBytes, err := os.ReadFile(byHashPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(byHashPath, 0o644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, byHashPath, "tampered-by-hash")
	brokenByHash := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{check}})
	if !hasCode(brokenByHash, "APT_METADATA_INVALID") {
		t.Fatalf("tampered by-hash object not detected: %+v", brokenByHash)
	}
	if err := os.WriteFile(byHashPath, byHashBytes, 0o444); err != nil {
		t.Fatal(err)
	}
	hidden := filepath.Join(root, "pool", "main", ".sow")
	if err := os.MkdirAll(hidden, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(hidden, "hidden.deb"), "hidden")
	hiddenReport := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{check}})
	if !hasCode(hiddenReport, "APT_POOL_UNSAFE") {
		t.Fatalf("nested shadow point not detected: %+v", hiddenReport)
	}
	if err := os.RemoveAll(hidden); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(filepath.Join(root, filepath.FromSlash(pkg.PoolPath)), 0o644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, filepath.FromSlash(pkg.PoolPath)), "tampered")
	tampered := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{check}})
	if !hasCode(tampered, "APT_POOL_CHANGED") {
		t.Fatalf("tampered DEB not detected: %+v", tampered)
	}
}

func TestAPTVerifierRejectsMalformedOrMultipleKeyMaterial(t *testing.T) {
	if _, err := NewAPTVerifier(bytes.NewBufferString("not a key")); err == nil {
		t.Fatal("malformed public key was accepted")
	}
}

func TestYUMCheckValidatesRealRPMSignedZstdAndExactPackageClosure(t *testing.T) {
	ctx := context.Background()
	created := time.Unix(1_700_000_000, 0).UTC()
	private := testPrivateKey(t, created)
	signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(private), nil, created)
	if err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeFixture(t, filepath.Join("..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), "fixture.rpm")
	info, err := yumrepo.InspectPackage(ctx, yumrepo.PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	copyFile(t, rpmPath, filepath.Join(root, filepath.FromSlash(info.Location)))
	_, err = yumrepo.Generate(ctx, filepath.Join(root, "repodata"), yumrepo.Options{ELMajor: 10, Revision: created.Unix(), Signer: signer}, &yumrepo.SliceIterator{Inputs: []yumrepo.PackageInput{{Path: rpmPath}}})
	if err != nil {
		t.Fatal(err)
	}
	packageKey, err := os.ReadFile(filepath.Join("..", "..", "test", "compat", "testdata", "PGDG-RPM-GPG-KEY-RHEL-nonfree.asc"))
	if err != nil {
		t.Fatal(err)
	}
	packageKeyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(packageKey))
	if err != nil {
		t.Fatal(err)
	}
	check := YUMCheck{CheckID: "yum", Root: root, Compression: yumrepo.CompressionZstd, Verifier: signer, PackageKeyring: packageKeyring, VerifyAt: time.Now().UTC(), Workers: 2, ChunkEntries: 1}
	report := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{check}})
	if report.Outcome != OutcomePassed {
		t.Fatalf("valid YUM repository rejected: %+v", report)
	}
	payloadManifest := filepath.Join(t.TempDir(), "yum-payload.tsv")
	writeSingleManifestEntry(t, payloadManifest, testManifestEntry(t, info.Location, info.Size, info.SHA256))
	retainedPackages := filepath.Join(t.TempDir(), "retained-packages")
	if err := os.Rename(filepath.Join(root, "Packages"), retainedPackages); err != nil {
		t.Fatal(err)
	}
	if missing := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{check}}); !hasCode(missing, "YUM_PACKAGE_BODY_INVALID") {
		t.Fatalf("indexed RPM with an absent Packages tree was not rejected: %+v", missing)
	}
	capabilityCheck := check
	capabilityCheck.ActualPayload = FileStream(payloadManifest)
	capabilityCheck.OpenPayload = func(entry manifest.Entry) (PayloadReadSeekCloser, error) {
		return os.Open(filepath.Join(retainedPackages, filepath.FromSlash(strings.TrimPrefix(entry.Path, "Packages/"))))
	}
	if capability := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{capabilityCheck}}); capability.Outcome != OutcomePassed {
		t.Fatalf("YUM capability mode copied or required Root/Packages instead of using the retained opener: %+v", capability)
	}
	if err := os.Rename(retainedPackages, filepath.Join(root, "Packages")); err != nil {
		t.Fatal(err)
	}
	signaturePath := filepath.Join(root, "repodata", "repomd.xml.asc")
	signature, err := os.ReadFile(signaturePath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, signaturePath, "broken-signature")
	brokenSignature := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{check}})
	if !hasCode(brokenSignature, "YUM_SIGNATURE_INVALID") {
		t.Fatalf("tampered YUM signature not detected: %+v", brokenSignature)
	}
	if err := os.WriteFile(signaturePath, signature, 0o644); err != nil {
		t.Fatal(err)
	}
	wrongPackageKeyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(private))
	if err != nil {
		t.Fatal(err)
	}
	untrustedCheck := check
	untrustedCheck.PackageKeyring = wrongPackageKeyring
	untrusted := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{untrustedCheck}})
	if !hasCode(untrusted, "YUM_PACKAGE_SIGNATURE_INVALID") {
		t.Fatalf("untrusted RPM package signer not detected: %+v", untrusted)
	}

	if err := os.MkdirAll(filepath.Join(root, "Packages", "z"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "Packages", "z", "unindexed.rpm"), "unindexed")
	drift := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{check}})
	if !hasCode(drift, "YUM_PACKAGE_UNEXPECTED") {
		t.Fatalf("unindexed RPM not detected: %+v", drift)
	}
}

func TestYUMCheckRejectsRepodataDirectorySwapAfterSignedValidation(t *testing.T) {
	created := time.Unix(1_700_000_000, 0).UTC()
	privateA := testPrivateKey(t, created)
	privateB := testPrivateKey(t, created.Add(time.Second))
	signerA, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(privateA), nil, created)
	if err != nil {
		t.Fatal(err)
	}
	signerB, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(privateB), nil, created.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	replacement := filepath.Join(parent, "replacement")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(replacement, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := yumrepo.Generate(t.Context(), filepath.Join(root, "repodata"), yumrepo.Options{
		ELMajor: 10, Revision: 1, Signer: signerA,
	}, &yumrepo.SliceIterator{}); err != nil {
		t.Fatal(err)
	}
	if _, err := yumrepo.Generate(t.Context(), filepath.Join(replacement, "repodata"), yumrepo.Options{
		ELMajor: 10, Revision: 2, Signer: signerB,
	}, &yumrepo.SliceIterator{}); err != nil {
		t.Fatal(err)
	}
	packageKeyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(privateA))
	if err != nil {
		t.Fatal(err)
	}
	check := YUMCheck{
		CheckID: "yum-repodata-swap", Root: root, Compression: yumrepo.CompressionZstd,
		Verifier: signerA, PackageKeyring: packageKeyring, VerifyAt: created,
		Workers: 2, ChunkEntries: 1,
	}
	swapped := false
	ctx := withYUMCheckHook(t.Context(), func(phase string) error {
		if phase != yumCheckAfterMetadataValidation || swapped {
			return nil
		}
		if err := os.Rename(filepath.Join(root, "repodata"), filepath.Join(parent, "held-repodata")); err != nil {
			return err
		}
		if err := os.Rename(filepath.Join(replacement, "repodata"), filepath.Join(root, "repodata")); err != nil {
			return err
		}
		swapped = true
		return nil
	})
	report := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{check}})
	if !swapped {
		t.Fatal("repodata replacement hook did not run")
	}
	if !hasCode(report, "YUM_METADATA_INVALID") {
		t.Fatalf("unsigned replacement repodata was not rejected: %+v", report)
	}
}

func TestYUMCheckRejectsSignedEntrySwapAfterMetadataValidation(t *testing.T) {
	for _, entry := range []string{"repomd.xml", "repomd.xml.asc"} {
		t.Run(entry, func(t *testing.T) {
			created := time.Unix(1_700_000_000, 0).UTC()
			privateA := testPrivateKey(t, created)
			privateB := testPrivateKey(t, created.Add(time.Second))
			signerA, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(privateA), nil, created)
			if err != nil {
				t.Fatal(err)
			}
			signerB, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(privateB), nil, created.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			parent := t.TempDir()
			root := filepath.Join(parent, "root")
			replacement := filepath.Join(parent, "replacement")
			for _, directory := range []string{root, replacement} {
				if err := os.MkdirAll(directory, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := yumrepo.Generate(t.Context(), filepath.Join(root, "repodata"), yumrepo.Options{
				ELMajor: 10, Revision: 1, Signer: signerA,
			}, &yumrepo.SliceIterator{}); err != nil {
				t.Fatal(err)
			}
			if _, err := yumrepo.Generate(t.Context(), filepath.Join(replacement, "repodata"), yumrepo.Options{
				ELMajor: 10, Revision: 2, Signer: signerB,
			}, &yumrepo.SliceIterator{}); err != nil {
				t.Fatal(err)
			}
			packageKeyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(privateA))
			if err != nil {
				t.Fatal(err)
			}
			check := YUMCheck{
				CheckID: "yum-signed-entry-swap", Root: root, Compression: yumrepo.CompressionZstd,
				Verifier: signerA, PackageKeyring: packageKeyring, VerifyAt: created,
				Workers: 2, ChunkEntries: 1,
			}
			swapped := false
			ctx := withYUMCheckHook(t.Context(), func(phase string) error {
				if phase != yumCheckAfterMetadataValidation || swapped {
					return nil
				}
				live := filepath.Join(root, "repodata", entry)
				if err := os.Rename(live, filepath.Join(parent, "held-"+entry)); err != nil {
					return err
				}
				if err := os.Rename(filepath.Join(replacement, "repodata", entry), live); err != nil {
					return err
				}
				swapped = true
				return nil
			})
			report := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{check}})
			if !swapped {
				t.Fatal("signed-entry replacement hook did not run")
			}
			if !hasCode(report, "YUM_METADATA_INVALID") {
				t.Fatalf("replacement %s was not rejected: %+v", entry, report)
			}
		})
	}
}

func TestYUMCheckPreservesCancellationDuringFinalMetadataProof(t *testing.T) {
	created := time.Unix(1_700_000_000, 0).UTC()
	private := testPrivateKey(t, created)
	signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(private), nil, created)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if _, err := yumrepo.Generate(t.Context(), filepath.Join(root, "repodata"), yumrepo.Options{
		ELMajor: 10, Revision: 1, Signer: signer,
	}, &yumrepo.SliceIterator{}); err != nil {
		t.Fatal(err)
	}
	packageKeyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(private))
	if err != nil {
		t.Fatal(err)
	}
	check := YUMCheck{
		CheckID: "yum-proof-cancel", Root: root, Compression: yumrepo.CompressionZstd,
		Verifier: signer, PackageKeyring: packageKeyring, VerifyAt: created,
		Workers: 2, ChunkEntries: 1,
	}
	ctx, cancel := context.WithCancel(t.Context())
	ctx = withYUMCheckHook(ctx, func(phase string) error {
		if phase == yumCheckAfterMetadataValidation {
			cancel()
		}
		return nil
	})
	err = check.Verify(ctx, newRecorder(10))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("metadata proof cancellation was converted to integrity drift: %v", err)
	}
}

func TestPackageChecksAcceptAbsentPayloadTreesForEmptySignedIndexes(t *testing.T) {
	ctx := context.Background()
	created := time.Unix(1_700_000_000, 0).UTC()
	private := testPrivateKey(t, created)

	aptSigner, err := aptrepo.NewSignerBytes(private, nil)
	if err != nil {
		t.Fatal(err)
	}
	aptVerifier, err := NewAPTVerifier(bytes.NewReader(private))
	if err != nil {
		t.Fatal(err)
	}
	aptRoot := t.TempDir()
	_, err = aptrepo.Generate(ctx, aptRoot, aptrepo.RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "jammy", Codename: "jammy",
		Components: []string{"main"}, Architectures: []string{"amd64"}, Date: created,
	}, []aptrepo.Index{{Component: "main", Architecture: "amd64"}}, aptSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(aptRoot, "pool")); err != nil {
		t.Fatal(err)
	}
	aptCheck := APTCheck{
		CheckID: "empty-apt", Root: aptRoot, ExpectedSuites: []string{"jammy"},
		ExpectedSuiteComponents: map[string][]string{"jammy": {"main"}},
		Verifier:                aptVerifier, VerifyAt: created, Workers: 2, ChunkEntries: 1,
	}
	if report := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{aptCheck}}); report.Outcome != OutcomePassed {
		t.Fatalf("empty signed APT repository with no pool rejected: %+v", report)
	}
	writeFile(t, filepath.Join(aptRoot, "pool"), "not a directory")
	if report := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{aptCheck}}); !hasCode(report, "APT_POOL_UNSAFE") {
		t.Fatalf("non-directory APT pool was accepted: %+v", report)
	}
	if err := os.Remove(filepath.Join(aptRoot, "pool")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(aptRoot, "pool")); err != nil {
		t.Fatal(err)
	}
	if report := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{aptCheck}}); !hasCode(report, "APT_POOL_UNSAFE") {
		t.Fatalf("symlinked APT pool was accepted: %+v", report)
	}

	yumSigner, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(private), nil, created)
	if err != nil {
		t.Fatal(err)
	}
	packageKeyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(private))
	if err != nil {
		t.Fatal(err)
	}
	yumRoot := t.TempDir()
	_, err = yumrepo.Generate(ctx, filepath.Join(yumRoot, "repodata"), yumrepo.Options{
		ELMajor: 10, Revision: created.Unix(), Signer: yumSigner,
	}, &yumrepo.SliceIterator{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(yumRoot, "Packages")); err != nil {
		t.Fatal(err)
	}
	yumCheck := YUMCheck{
		CheckID: "empty-yum", Root: yumRoot, Compression: yumrepo.CompressionZstd,
		Verifier: yumSigner, PackageKeyring: packageKeyring, VerifyAt: created,
		Workers: 2, ChunkEntries: 1,
	}
	if report := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{yumCheck}}); report.Outcome != OutcomePassed {
		t.Fatalf("empty signed YUM repository with no Packages tree rejected: %+v", report)
	}
	writeFile(t, filepath.Join(yumRoot, "Packages"), "not a directory")
	if report := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{yumCheck}}); !hasCode(report, "YUM_PACKAGE_TREE_UNSAFE") {
		t.Fatalf("non-directory YUM Packages tree was accepted: %+v", report)
	}
	if err := os.Remove(filepath.Join(yumRoot, "Packages")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(yumRoot, "Packages")); err != nil {
		t.Fatal(err)
	}
	if report := Run(ctx, Request{Layers: []Layer{LayerL1}, Checks: []Check{yumCheck}}); !hasCode(report, "YUM_PACKAGE_TREE_UNSAFE") {
		t.Fatalf("symlinked YUM Packages tree was accepted: %+v", report)
	}
}

func testPrivateKey(t *testing.T, created time.Time) []byte {
	t.Helper()
	config := &packet.Config{DefaultHash: crypto.SHA256, RSABits: 1024, Time: func() time.Time { return created }}
	entity, err := openpgp.NewEntity("SOW Verify", "", "verify@example.invalid", config)
	if err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	armored, err := armor.Encode(&raw, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(armored, config); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func decodeFixture(t *testing.T, source, name string) string {
	t.Helper()
	encoded, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(payload, encoded)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(destination, payload[:n], 0o444); err != nil {
		t.Fatal(err)
	}
	return destination
}

func copyFile(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o444); err != nil {
		t.Fatal(err)
	}
}

func testManifestEntry(t *testing.T, path string, size int64, digest string) manifest.Entry {
	t.Helper()
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size {
		t.Fatalf("invalid fixture SHA256 %q", digest)
	}
	entry := manifest.Entry{Path: path, Size: size}
	copy(entry.SHA256[:], decoded)
	return entry
}

func writeSingleManifestEntry(t *testing.T, filename string, entry manifest.Entry) {
	t.Helper()
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.WriteEntry(file, entry); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
