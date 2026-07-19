package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/yumrepo"
)

type flatYUMCompatibilityFixture struct {
	root            string
	flat            string
	canonical       string
	privateKey      []byte
	metadataKeyring openpgp.KeyRing
	packageKeyring  openpgp.KeyRing
	desired         string
}

func newFlatYUMCompatibilityFixture(t *testing.T) flatYUMCompatibilityFixture {
	return newFlatYUMCompatibilityFixtureWithFrozenRecords(t, true)
}

func newFlatYUMCompatibilityFixtureWithFrozenRecords(t *testing.T, frozenRecords bool) flatYUMCompatibilityFixture {
	return newFlatYUMCompatibilityFixtureForArchWithFrozenRecords(t, "x86_64", frozenRecords)
}

func newFlatYUMCompatibilityFixtureForArch(t *testing.T, arch string) flatYUMCompatibilityFixture {
	return newFlatYUMCompatibilityFixtureForArchWithFrozenRecords(t, arch, true)
}

func newFlatYUMCompatibilityFixtureForArchWithFrozenRecords(t *testing.T, arch string, frozenRecords bool) flatYUMCompatibilityFixture {
	t.Helper()
	if arch != "aarch64" && arch != "x86_64" {
		t.Fatalf("unsupported compatibility fixture architecture %q", arch)
	}
	workspace := nginxWorkerTempDir(t)
	privatePath, _ := writeLegacySigningKey(t, workspace)
	privateKey, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	metadataKeyring, err := parseSingleRepositoryKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	packageKeyring, _, err := loadRPMPackageKeyring(filepath.Join(workspace, "sow.yaml"), "package-trust.asc")
	if err != nil {
		t.Fatal(err)
	}
	rpmInput := decodeLegacyFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(workspace, "input.rpm"))
	root := filepath.Join(workspace, "yum", "infra", arch)
	repo := config.Repo{ID: "infra-el9", Type: "yum", Path: "yum/infra/el9/{arch}", Arches: []string{arch}, OS: config.OSConfig{Family: "el", Major: 8, Lifecycle: "frozen"}, YUM: &config.YUMConfig{Compression: "gzip"}}
	flat, canonical := writeAllSelectorFlatYUM(t, repo, root, rpmInput, privatePath)
	if frozenRecords {
		repomdPath := filepath.Join(root, "repodata", "repomd.xml")
		repomd, err := os.ReadFile(repomdPath)
		if err != nil {
			t.Fatal(err)
		}
		var excluded bytes.Buffer
		for index, kind := range []string{"primary_db", "filelists_db", "other_db", "modules"} {
			filename, compressed, open := legacyYUMCompatibilityFixtureArtifact(t, index+3, kind)
			compressedDigest, openDigest := sha256.Sum256(compressed), sha256.Sum256(open)
			fmt.Fprintf(&excluded, `<data type="%s"><checksum type="sha256">%s</checksum><open-checksum type="sha256">%s</open-checksum><location href="repodata/%s"/><timestamp>1</timestamp><size>%d</size><open-size>%d</open-size></data>`,
				kind, hex.EncodeToString(compressedDigest[:]), hex.EncodeToString(openDigest[:]), filename, len(compressed), len(open))
			if err := os.WriteFile(filepath.Join(root, "repodata", filename), compressed, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		repomd = bytes.Replace(repomd, []byte("</repomd>"), append(excluded.Bytes(), []byte("</repomd>")...), 1)
		if err := os.WriteFile(repomdPath, repomd, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(repomdPath + ".asc"); err != nil {
			t.Fatal(err)
		}
	}
	// The compatibility fixture models the already Nginx-hosted S0 leaf. The
	// production generator deliberately installs private 0700 build output;
	// legacy input must instead carry its pre-existing worker-traversable mode.
	if err := os.Chmod(filepath.Join(root, "repodata"), 0o755); err != nil {
		t.Fatal(err)
	}
	sha, size, err := fileSHA256AndSize(filepath.Join(root, flat))
	if err != nil {
		t.Fatal(err)
	}
	digestBytes, err := hex.DecodeString(sha)
	if err != nil || len(digestBytes) != 32 {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], digestBytes)
	desired := filepath.Join(workspace, "desired-aliases.tsv")
	file, err := os.OpenFile(desired, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writeErr := manifest.WriteEntry(file, manifest.Entry{Path: flat, Size: size, SHA256: digest})
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(errors.Join(writeErr, closeErr))
	}
	return flatYUMCompatibilityFixture{root: root, flat: flat, canonical: canonical, privateKey: privateKey, metadataKeyring: metadataKeyring, packageKeyring: packageKeyring, desired: desired}
}

func TestYUMCompatibilityLegacyBootstrapAcceptsStrictSignedFlatGeneration(t *testing.T) {
	fixture := newFlatYUMCompatibilityFixture(t)
	clean := newFlatYUMCompatibilityFixtureWithFrozenRecords(t, false)
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(clean.privateKey), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := yumrepo.ValidateFlatCompatibilityDirectory(t.Context(), filepath.Join(clean.root, "repodata"), yumrepo.CompressionGzip, verifier); err != nil {
		t.Fatalf("strict signed flat compatibility validation: %v", err)
	}
	if _, err := yumrepo.ValidateDirectory(t.Context(), filepath.Join(clean.root, "repodata"), yumrepo.CompressionGzip, verifier); err == nil {
		t.Fatal("canonical YUM validator was silently widened to accept flat hrefs")
	}
	if err := verifyLegacyYUMCompatibilityRoot(t.Context(), fixture.root, fixture.desired, fixture.packageKeyring); err != nil {
		t.Fatalf("complete legacy bootstrap rejected: %v", err)
	}
}

func TestYUMCompatibilityLegacyInspectionAcceptsUnsignedExcludedMetadataAsInputOnly(t *testing.T) {
	fixture := newFlatYUMCompatibilityFixture(t)
	before := filepath.Join(t.TempDir(), "before.tsv")
	if _, err := manifest.Scan(t.Context(), fixture.root, manifest.Scope{Path: "."}, before, manifest.ScanOptions{Workers: 2, ChunkEntries: 3, TempDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := verifyLegacyYUMCompatibilityRoot(t.Context(), fixture.root, fixture.desired, fixture.packageKeyring); err != nil {
		t.Fatalf("unsigned legacy input with excluded metadata was not safely inspected: %v", err)
	}
	after := filepath.Join(t.TempDir(), "after.tsv")
	if _, err := manifest.Scan(t.Context(), fixture.root, manifest.Scope{Path: "."}, after, manifest.ScanOptions{Workers: 2, ChunkEntries: 3, TempDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	beforeBody, _ := os.ReadFile(before)
	afterBody, _ := os.ReadFile(after)
	if !bytes.Equal(beforeBody, afterBody) {
		t.Fatal("legacy inspection changed migration input bytes")
	}
}

func TestYUMCompatibilityLegacyBootstrapRejectsPhysicalAndByteDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, flatYUMCompatibilityFixture)
	}{
		{name: "unknown root file", mutate: func(t *testing.T, f flatYUMCompatibilityFixture) {
			if err := os.WriteFile(filepath.Join(f.root, "unexpected.txt"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unknown root directory", mutate: func(t *testing.T, f flatYUMCompatibilityFixture) {
			if err := os.Mkdir(filepath.Join(f.root, "nested"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "root symlink", mutate: func(t *testing.T, f flatYUMCompatibilityFixture) {
			if err := os.Symlink(f.flat, filepath.Join(f.root, "alias-link.rpm")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "root special file", mutate: func(t *testing.T, f flatYUMCompatibilityFixture) {
			if err := syscall.Mkfifo(filepath.Join(f.root, "special.rpm"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unindexed flat rpm", mutate: func(t *testing.T, f flatYUMCompatibilityFixture) {
			body, err := os.ReadFile(filepath.Join(f.root, f.flat))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.root, "orphan.rpm"), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unreferenced repodata", mutate: func(t *testing.T, f flatYUMCompatibilityFixture) {
			if err := os.WriteFile(filepath.Join(f.root, "repodata", "canary"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unexpected repomd signature", mutate: func(t *testing.T, f flatYUMCompatibilityFixture) {
			if err := os.WriteFile(filepath.Join(f.root, "repodata", "repomd.xml.asc"), []byte("not observed"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unexpected root modulemd sidecar", mutate: func(t *testing.T, f flatYUMCompatibilityFixture) {
			if err := os.WriteFile(filepath.Join(f.root, "modules.yaml"), []byte("not observed"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "missing indexed rpm", mutate: func(t *testing.T, f flatYUMCompatibilityFixture) {
			if err := os.Remove(filepath.Join(f.root, f.flat)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "tampered indexed rpm", mutate: func(t *testing.T, f flatYUMCompatibilityFixture) {
			filename := filepath.Join(f.root, f.flat)
			body, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			body[len(body)-1] ^= 1
			if err := os.WriteFile(filename, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFlatYUMCompatibilityFixture(t)
			test.mutate(t, fixture)
			err := verifyLegacyYUMCompatibilityRoot(t.Context(), fixture.root, fixture.desired, fixture.packageKeyring)
			if err == nil || strings.TrimSpace(err.Error()) == "" {
				t.Fatalf("unsafe legacy compatibility tree %q was accepted", test.name)
			}
		})
	}
}

func TestYUMValidatorsRejectSameCountDifferentPackageIdentitySets(t *testing.T) {
	for _, mode := range []string{"flat", "canonical"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newFlatYUMCompatibilityFixtureWithFrozenRecords(t, false)
			signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(fixture.privateKey), nil, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(fixture.privateKey), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			generation, err := yumrepo.ValidateFlatCompatibilityDirectory(t.Context(), filepath.Join(fixture.root, "repodata"), yumrepo.CompressionGzip, verifier)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "canonical" {
				rewriteCompatibilityMetadataArtifact(t, generation, signer, "primary", func(raw []byte) []byte {
					old := []byte(`location href="` + fixture.flat + `"`)
					replacement := []byte(`location href="` + fixture.canonical + `"`)
					if bytes.Count(raw, old) != 1 {
						t.Fatalf("flat primary href count=%d", bytes.Count(raw, old))
					}
					return bytes.Replace(raw, old, replacement, 1)
				})
				if _, err := yumrepo.ValidateDirectory(t.Context(), filepath.Join(fixture.root, "repodata"), yumrepo.CompressionGzip, verifier); err != nil {
					t.Fatalf("canonical control generation: %v", err)
				}
			}
			originalSHA, _, err := fileSHA256AndSize(filepath.Join(fixture.root, fixture.flat))
			if err != nil {
				t.Fatal(err)
			}
			rewriteCompatibilityMetadataArtifact(t, generation, signer, "filelists", func(raw []byte) []byte {
				old := []byte(`pkgid="` + originalSHA + `"`)
				replacement := []byte(`pkgid="` + strings.Repeat("b", 64) + `"`)
				if bytes.Count(raw, old) != 1 {
					t.Fatalf("filelists pkgid count=%d", bytes.Count(raw, old))
				}
				return bytes.Replace(raw, old, replacement, 1)
			})
			if mode == "flat" {
				_, err = yumrepo.ValidateFlatCompatibilityDirectory(t.Context(), filepath.Join(fixture.root, "repodata"), yumrepo.CompressionGzip, verifier)
			} else {
				_, err = yumrepo.ValidateDirectory(t.Context(), filepath.Join(fixture.root, "repodata"), yumrepo.CompressionGzip, verifier)
			}
			if err == nil || !strings.Contains(err.Error(), "identity set differs") {
				t.Fatalf("%s validator accepted same-count different pkgid set: %v", mode, err)
			}
		})
	}
}

func rewriteCompatibilityMetadataArtifact(t *testing.T, generation *yumrepo.Generation, signer yumrepo.DetachedSigner, kind string, mutate func([]byte) []byte) {
	t.Helper()
	for index := range generation.Artifacts {
		artifact := &generation.Artifacts[index]
		if artifact.Type != kind {
			continue
		}
		oldPath := filepath.Join(generation.Dir, filepath.Base(artifact.Path))
		compressed, err := os.ReadFile(oldPath)
		if err != nil {
			t.Fatal(err)
		}
		raw := mutate(decompressAllSelectorMetadata(t, compressed, yumrepo.CompressionGzip))
		compressed = compressAllSelectorMetadata(t, raw, yumrepo.CompressionGzip)
		compressedSHA, openSHA := sha256.Sum256(compressed), sha256.Sum256(raw)
		name := hex.EncodeToString(compressedSHA[:]) + "-" + kind + ".xml.gz"
		newPath := filepath.Join(generation.Dir, name)
		if err := os.WriteFile(newPath, compressed, 0o644); err != nil {
			t.Fatal(err)
		}
		if newPath != oldPath {
			if err := os.Remove(oldPath); err != nil {
				t.Fatal(err)
			}
		}
		artifact.Path = "repodata/" + name
		artifact.SHA256 = hex.EncodeToString(compressedSHA[:])
		artifact.OpenSHA256 = hex.EncodeToString(openSHA[:])
		artifact.Size = int64(len(compressed))
		artifact.OpenSize = int64(len(raw))
		writeAllSelectorRepomd(t, generation, signer)
		return
	}
	t.Fatalf("metadata generation lacks %s", kind)
}
