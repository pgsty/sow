package upstream

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

func TestParseLocalAPTIndexSupportsRawGzipXZAndZstd(t *testing.T) {
	payload := []byte("package-body")
	digest := sha256.Sum256(payload)
	packages := []byte(fmt.Sprintf("Package: fixture\nVersion: 1.2.3-1\nArchitecture: amd64\nFilename: pool/main/f/fixture/fixture_1.2.3-1_amd64.deb\nSize: %d\nSHA256: %s\n\n", len(payload), hex.EncodeToString(digest[:])))
	for _, kind := range []string{"raw", "gz", "xz", "zst"} {
		kind := kind
		t.Run(kind, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "Packages"+map[string]string{"raw": "", "gz": ".gz", "xz": ".xz", "zst": ".zst"}[kind])
			writeLocalCompressed(t, filename, kind, packages)
			var got []LocalPackage
			err := ParseLocalAPTIndex(context.Background(), filename, Limits{}, func(pkg LocalPackage) error {
				got = append(got, pkg)
				return nil
			})
			if err != nil || len(got) != 1 || got[0].Name != "fixture" || got[0].Arch != "amd64" || got[0].Location != "pool/main/f/fixture/fixture_1.2.3-1_amd64.deb" || got[0].SHA256 != hex.EncodeToString(digest[:]) {
				t.Fatalf("packages=%+v err=%v", got, err)
			}
		})
	}
}

func TestParseLocalYUMRepositorySupportsGzipZstdAndOptionalSignature(t *testing.T) {
	signing := newTestSigning(t)
	payload := []byte("rpm-body")
	payloadSHA := sha256.Sum256(payload)
	primary := []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1"><package type="rpm"><name>postgresql18</name><arch>x86_64</arch><version epoch="0" ver="18.0" rel="1PGDG"/><checksum type="sha256" pkgid="YES">%s</checksum><size package="%d" installed="1" archive="1"/><location href="Packages/p/postgresql18-18.0-1PGDG.x86_64.rpm"/><format xmlns:rpm="http://linux.duke.edu/metadata/rpm"/></package></metadata>
`, hex.EncodeToString(payloadSHA[:]), len(payload)))
	for _, kind := range []string{"gz", "zst"} {
		kind := kind
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			extension := ".gz"
			if kind == "zst" {
				extension = ".zst"
			}
			primaryRelative := "repodata/primary.xml" + extension
			primaryPath := filepath.Join(root, filepath.FromSlash(primaryRelative))
			if err := os.MkdirAll(filepath.Dir(primaryPath), 0o755); err != nil {
				t.Fatal(err)
			}
			writeLocalCompressed(t, primaryPath, kind, primary)
			compressed, err := os.ReadFile(primaryPath)
			if err != nil {
				t.Fatal(err)
			}
			compressedSHA, openSHA := sha256.Sum256(compressed), sha256.Sum256(primary)
			repomd := []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision><data type="primary"><checksum type="sha256">%s</checksum><open-checksum type="sha256">%s</open-checksum><location href="%s"/><timestamp>1</timestamp><size>%d</size><open-size>%d</open-size></data></repomd>
`, hex.EncodeToString(compressedSHA[:]), hex.EncodeToString(openSHA[:]), primaryRelative, len(compressed), len(primary)))
			repomdPath := filepath.Join(root, "repodata", "repomd.xml")
			if err := os.WriteFile(repomdPath, repomd, 0o644); err != nil {
				t.Fatal(err)
			}
			var signature bytes.Buffer
			if err := signing.yumSigner.Sign(context.Background(), bytes.NewReader(repomd), &signature); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(repomdPath+".asc", signature.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
			var got []LocalPackage
			err = ParseLocalYUMRepository(context.Background(), root, Limits{}, openpgp.EntityList{signing.entity}, func(pkg LocalPackage) error {
				got = append(got, pkg)
				return nil
			})
			if err != nil || len(got) != 1 || got[0].Name != "postgresql18" || got[0].Version != "18.0-1PGDG" || got[0].Location != "Packages/p/postgresql18-18.0-1PGDG.x86_64.rpm" {
				t.Fatalf("packages=%+v err=%v", got, err)
			}
			if err := os.WriteFile(repomdPath, append(append([]byte(nil), repomd...), ' '), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := ParseLocalYUMRepository(context.Background(), root, Limits{}, openpgp.EntityList{signing.entity}, func(LocalPackage) error { return nil }); err == nil {
				t.Fatal("tampered signed repomd was accepted")
			}
		})
	}
}

func writeLocalCompressed(t *testing.T, filename, kind string, body []byte) {
	t.Helper()
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	var writer interface {
		Write([]byte) (int, error)
		Close() error
	}
	switch kind {
	case "raw":
		if _, err := file.Write(body); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		return
	case "gz":
		writer = gzip.NewWriter(file)
	case "xz":
		writer, err = xz.NewWriter(file)
	case "zst":
		writer, err = zstd.NewWriter(file, zstd.WithEncoderConcurrency(1))
	default:
		t.Fatalf("unknown compression %s", kind)
	}
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		writer.Close()
		file.Close()
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
