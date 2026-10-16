package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
)

func TestValidateManagedPackagesAcceptsExplicitZeroEpoch(t *testing.T) {
	root := t.TempDir()
	const basename = "cri-dockerd_0.3.16~3-0~debian-bullseye_amd64.deb"
	poolPath, err := managedPoolPath("cri-dockerd", basename)
	if err != nil {
		t.Fatal(err)
	}
	packageBytes := []byte("immutable package fixture")
	digestBytes := sha256.Sum256(packageBytes)
	digest := hex.EncodeToString(digestBytes[:])
	fullPoolPath := filepath.Join(root, filepath.FromSlash(poolPath))
	if err := os.MkdirAll(filepath.Dir(fullPoolPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPoolPath, packageBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	packagesPath := filepath.Join(root, "Packages")
	paragraph := fmt.Sprintf("Package: cri-dockerd\nVersion: 0:0.3.16~3-0~debian-bullseye\nArchitecture: amd64\nFilename: %s\nSize: %d\nSHA256: %s\n\n", poolPath, len(packageBytes), digest)
	if err := os.WriteFile(packagesPath, []byte(paragraph), 0o644); err != nil {
		t.Fatal(err)
	}
	expected := map[string]state.PackageObject{digest: {
		SHA256: digest, Name: "cri-dockerd", Source: "cri-dockerd",
		Version: "0.3.16~3-0~debian-bullseye", Architecture: "amd64",
		PoolPath: poolPath, Size: int64(len(packageBytes)),
	}}
	if err := validateManagedPackagesParagraphs(context.Background(), root, "Packages", "amd64", expected, newPayloadEvidenceRegistry()); err != nil {
		t.Fatalf("validate explicit zero epoch: %v", err)
	}
}

func TestValidateManagedPackagesAccountsFallbackAndReusesPayloadEvidence(t *testing.T) {
	root, object, body, _ := managedPackagesEvidenceFixture(t)
	expected := map[string]state.PackageObject{object.SHA256: object}
	evidence := newPayloadEvidenceRegistry()
	ctx, collector := workmetrics.Ensure(context.Background())
	for _, arch := range []string{"amd64", "arm64"} {
		if err := validateManagedPackagesParagraphs(ctx, root, "Packages", arch, expected, evidence); err != nil {
			t.Fatal(err)
		}
	}
	file := state.GenerationFile{Path: object.PoolPath, Phase: "payload", Size: object.Size, SHA256: object.SHA256}
	if err := evidence.verifyRetainedReference(ctx, root, file); err != nil {
		t.Fatal(err)
	}
	metrics := collector.Snapshot()
	if metrics.FullPackageReads != 1 || metrics.PayloadBytesRead != int64(len(body)) || metrics.PayloadByPhase["apt_index_payload"].Full != 1 {
		t.Fatalf("fallback payload metrics=%#v", metrics)
	}
	t.Logf("fallback: %d full read, %d bytes, phases=%v", metrics.FullPackageReads, metrics.PayloadBytesRead, metrics.PayloadByPhase)
}

func TestValidateManagedPackagesRechecksPayloadAndIndexReferences(t *testing.T) {
	for _, test := range []struct {
		name      string
		wantError bool
		wantReads int64
	}{
		{name: "unchanged", wantReads: 1},
		{name: "replaced inode", wantError: true, wantReads: 2},
		{name: "rewritten with restored mtime", wantError: true, wantReads: 2},
		{name: "unchanged bytes in new inode", wantReads: 2},
		{name: "unchanged bytes with new mtime", wantReads: 2},
		{name: "symlink", wantError: true, wantReads: 1},
		{name: "missing pool", wantError: true, wantReads: 1},
		{name: "index SHA256", wantError: true, wantReads: 1},
		{name: "index size", wantError: true, wantReads: 1},
		{name: "index path", wantError: true, wantReads: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, object, body, paragraph := managedPackagesEvidenceFixture(t)
			payload := filepath.Join(root, filepath.FromSlash(object.PoolPath))
			before, err := os.Stat(payload)
			if err != nil {
				t.Fatal(err)
			}
			file := state.GenerationFile{Path: object.PoolPath, Phase: "payload", Size: object.Size, SHA256: object.SHA256}
			evidence := newPayloadEvidenceRegistry()
			ctx, collector := workmetrics.Ensure(context.Background())
			if err := evidence.verifyRetainedReference(ctx, root, file); err != nil {
				t.Fatal(err)
			}
			switch test.name {
			case "replaced inode", "unchanged bytes in new inode":
				if test.wantError {
					body[len(body)-1] ^= 1
				}
				replacement := filepath.Join(root, "replacement.deb")
				if err := os.WriteFile(replacement, body, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(replacement, before.ModTime(), before.ModTime()); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, payload); err != nil {
					t.Fatal(err)
				}
			case "rewritten with restored mtime":
				// Ensure the ctime change is observable even on coarser filesystems.
				time.Sleep(2 * time.Millisecond)
				body[len(body)-1] ^= 1
				if err := os.WriteFile(payload, body, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(payload, before.ModTime(), before.ModTime()); err != nil {
					t.Fatal(err)
				}
			case "unchanged bytes with new mtime":
				changed := before.ModTime().Add(time.Second)
				if err := os.Chtimes(payload, changed, changed); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "same.deb")
				if err := os.WriteFile(target, body, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(payload); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, payload); err != nil {
					t.Fatal(err)
				}
			case "missing pool":
				if err := os.Remove(payload); err != nil {
					t.Fatal(err)
				}
			case "index SHA256":
				paragraph = strings.Replace(paragraph, object.SHA256, strings.Repeat("a", 64), 1)
			case "index size":
				paragraph = strings.Replace(paragraph, fmt.Sprintf("Size: %d", object.Size), fmt.Sprintf("Size: %d", object.Size+1), 1)
			case "index path":
				paragraph = strings.Replace(paragraph, object.Filename, "other_1.0-1_all.deb", 1)
			}
			if err := os.WriteFile(filepath.Join(root, "Packages"), []byte(paragraph), 0o644); err != nil {
				t.Fatal(err)
			}
			err = validateManagedPackagesParagraphs(ctx, root, "Packages", "amd64", map[string]state.PackageObject{object.SHA256: object}, evidence)
			if (err != nil) != test.wantError {
				t.Fatalf("validation err=%v, want error=%t", err, test.wantError)
			}
			if metrics := collector.Snapshot(); metrics.FullPackageReads != test.wantReads || metrics.PayloadBytesRead != int64(len(body))*test.wantReads {
				t.Fatalf("reference revalidation metrics=%#v, want %d reads", metrics, test.wantReads)
			}
		})
	}
}

func managedPackagesEvidenceFixture(t *testing.T) (string, state.PackageObject, []byte, string) {
	t.Helper()
	root := t.TempDir()
	body := []byte("immutable package bytes for index evidence")
	object := state.PackageObject{
		Name: "sow-index", Source: "sow-index", Version: "1.0-1", Architecture: "all",
		Filename: "sow-index_1.0-1_all.deb", Size: int64(len(body)), SHA256: bytesSHA(body),
	}
	var err error
	object.PoolPath, err = managedPoolPath(object.Source, object.Filename)
	if err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(root, filepath.FromSlash(object.PoolPath))
	if err := os.MkdirAll(filepath.Dir(payload), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, body, 0o644); err != nil {
		t.Fatal(err)
	}
	paragraph := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nFilename: %s\nSize: %d\nSHA256: %s\n\n", object.Name, object.Version, object.Architecture, object.PoolPath, object.Size, object.SHA256)
	if err := os.WriteFile(filepath.Join(root, "Packages"), []byte(paragraph), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, object, body, paragraph
}

func TestManagedPoolPathUsesPortableLowercaseShard(t *testing.T) {
	got, err := managedPoolPath("PolarDB", "PolarDB-17.9.1.0-1.el10.aarch64.rpm")
	if err != nil {
		t.Fatal(err)
	}
	if want := "pool/p/PolarDB/PolarDB-17.9.1.0-1.el10.aarch64.rpm"; got != want {
		t.Fatalf("managedPoolPath = %q, want %q", got, want)
	}
	got, err = managedPoolPath("libFoo", "libFoo-1.0-1.x86_64.rpm")
	if err != nil {
		t.Fatal(err)
	}
	if want := "pool/libf/libFoo/libFoo-1.0-1.x86_64.rpm"; got != want {
		t.Fatalf("managedPoolPath(libFoo) = %q, want %q", got, want)
	}
}
