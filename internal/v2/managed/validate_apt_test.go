package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/state"
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
	if err := validateManagedPackagesParagraphs(context.Background(), root, "Packages", "amd64", expected); err != nil {
		t.Fatalf("validate explicit zero epoch: %v", err)
	}
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
