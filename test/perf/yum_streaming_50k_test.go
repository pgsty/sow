//go:build perf

package perf_test

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pgsty/sow/internal/yumrepo"
)

const yumPerformancePackages = 50_000

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve performance test source")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(filename), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func loadYUMPerformanceFixture(t *testing.T) []byte {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(moduleRoot(t), "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) == 0 {
		t.Fatal("decoded YUM performance fixture is empty")
	}
	return decoded
}

func TestYUMPerformanceFixtureAvailable(t *testing.T) {
	_ = loadYUMPerformanceFixture(t)
}

type distinctRPMIterator struct {
	path  string
	body  []byte
	index int
}

func (iterator *distinctRPMIterator) Next(ctx context.Context) (yumrepo.PackageInput, error) {
	if err := ctx.Err(); err != nil {
		return yumrepo.PackageInput{}, err
	}
	if iterator.index == yumPerformancePackages {
		return yumrepo.PackageInput{}, io.EOF
	}
	// The repository contract forbids publishing one package body more than
	// once in a channel, and pkgid is the full RPM SHA-256. Keep the fixture
	// compact while exercising 50,000 distinct package identities by changing
	// a fixed-width trailer before each synchronous parser call. The production
	// RPM reader stops after the header; the trailer is still included in the
	// package checksum and size recorded in primary.xml.
	binary.BigEndian.PutUint64(iterator.body[len(iterator.body)-8:], uint64(iterator.index))
	if err := os.WriteFile(iterator.path, iterator.body, 0o600); err != nil {
		return yumrepo.PackageInput{}, err
	}
	basename := fmt.Sprintf("pgdg-redhat-nonfree-repo-42.0-20PGDG-%05d.noarch.rpm", iterator.index)
	iterator.index++
	return yumrepo.PackageInput{Path: iterator.path, Basename: basename}, nil
}

// TestYUMStreamingFiftyThousand measures the production RPM parser, XML
// spooling, zstd compression, repomd signing, and streaming self-validation.
// It deliberately reuses one real RPM header with checksum-distinct fixed-size
// trailers and unique canonical basenames. This keeps the fixture small while
// retaining 50,000 complete RPM header parses and 50,000 distinct
// primary/filelists/other records.
func TestYUMStreamingFiftyThousand(t *testing.T) {
	rpmPath := filepath.Join(t.TempDir(), "fixture.rpm")
	decoded := loadYUMPerformanceFixture(t)
	fixtureBody := append(append([]byte(nil), decoded...), []byte("SOWPERF0\x00\x00\x00\x00\x00\x00\x00\x00")...)

	now := time.Unix(1_783_800_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW YUM performance", "", "perf@example.invalid", &packet.Config{
		Time: func() time.Time { return now.Add(-time.Hour) }, RSABits: 2048, DefaultHash: crypto.SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	if err := entity.SerializePrivate(&private, nil); err != nil {
		t.Fatal(err)
	}
	signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(private.Bytes()), nil, now)
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	started := time.Now()
	destination := filepath.Join(t.TempDir(), "repodata")
	generation, err := yumrepo.Generate(context.Background(), destination, yumrepo.Options{
		ELMajor: 10, Revision: now.Unix(), Signer: signer,
	}, &distinctRPMIterator{path: rpmPath, body: fixtureBody})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if generation.Packages != yumPerformancePackages {
		t.Fatalf("packages=%d, want %d", generation.Packages, yumPerformancePackages)
	}
	validated, err := yumrepo.ValidateDirectory(context.Background(), destination, yumrepo.CompressionZstd, signer)
	if err != nil {
		t.Fatal(err)
	}
	if validated.Packages != yumPerformancePackages || validated.RepomdSHA256 != generation.RepomdSHA256 {
		t.Fatalf("validated generation differs: generated=%+v validated=%+v", generation, validated)
	}
	runtime.GC()
	var retained runtime.MemStats
	runtime.ReadMemStats(&retained)
	growth := uint64(0)
	if retained.HeapAlloc > baseline.HeapAlloc {
		growth = retained.HeapAlloc - baseline.HeapAlloc
	}
	var compressed int64
	for _, artifact := range generation.Artifacts {
		compressed += artifact.Size
	}
	t.Logf("yum50k packages=%d elapsed=%s baseline_heap=%d retained_heap=%d growth=%d compressed_metadata=%d repomd_sha256=%s",
		generation.Packages, elapsed, baseline.HeapAlloc, retained.HeapAlloc, growth, compressed, generation.RepomdSHA256)
	if retained.HeapAlloc > 128<<20 || growth > 96<<20 {
		t.Fatalf("YUM 50k retained heap is unbounded: baseline=%d retained=%d growth=%d", baseline.HeapAlloc, retained.HeapAlloc, growth)
	}
}
