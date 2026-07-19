package upstream

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/syncer"
)

func TestNormalizeBaseAcceptsHTTPSRootAndRejectsAmbiguity(t *testing.T) {
	base, err := normalizeBase("https://repo.example.invalid")
	if err != nil {
		t.Fatalf("root URL rejected: %v", err)
	}
	if got := base.String(); got != "https://repo.example.invalid/" {
		t.Fatalf("normalized root = %q", got)
	}
	for _, raw := range []string{
		"https://repo.example.invalid?",
		"https://repo.example.invalid/%2e%2e/private",
		"https://repo.example.invalid/a//b",
	} {
		if _, err := normalizeBase(raw); !errors.Is(err, ErrUnsafeURL) {
			t.Errorf("ambiguous base %q error = %v", raw, err)
		}
	}
	if _, err := resolveRelative(base, "pool/main/a%2fb.deb"); !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("encoded package separator error = %v", err)
	}
}

func TestHTTPSRedirectContractAllowsCanonicalMirrorsOnly(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/encoded":
			w.Header().Set("Location", "/pool%2fsecret")
			w.WriteHeader(http.StatusFound)
		case "/final":
			_, _ = io.WriteString(w, "metadata")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	data, found, err := fetchBytes(context.Background(), server.Client(), server.URL+"/start", 1024, false)
	if err != nil || !found || string(data) != "metadata" {
		t.Fatalf("canonical HTTPS redirect = %q/%v/%v", data, found, err)
	}
	if _, _, err := fetchBytes(context.Background(), server.Client(), server.URL+"/encoded", 1024, false); !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("encoded redirect error = %v", err)
	}
}

func TestYUMDiscoveryFailsClosedWithoutTrustedMetadataSignature(t *testing.T) {
	signing := newTestSigning(t)
	handler := newProtocolServer()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	rpm := rpmPackageFixture{
		name: "pkg", arch: "x86_64", epoch: "0", version: "1", release: "1",
		location: "Packages/p/pkg-1-1.x86_64.rpm", body: []byte("rpm"),
	}
	publishYUMFixture(t, handler, signing, []rpmPackageFixture{rpm}, false)
	base := YUMSource{BaseURL: server.URL, Client: server.Client(), WorkDir: t.TempDir()}
	if _, err := DiscoverYUM(context.Background(), base); !errors.Is(err, ErrSignature) {
		t.Fatalf("keyless YUM discovery error = %v", err)
	}

	base.Keyring = openpgp.EntityList{signing.entity}
	handler.delete("repodata/repomd.xml.asc")
	if _, err := DiscoverYUM(context.Background(), base); !errors.Is(err, ErrSignature) {
		t.Fatalf("unsigned repomd discovery error = %v", err)
	}

	publishYUMFixture(t, handler, signing, []rpmPackageFixture{rpm}, false)
	handler.mu.Lock()
	signature := handler.files["repodata/repomd.xml.asc"]
	signature[len(signature)/2] ^= 0x01
	handler.files["repodata/repomd.xml.asc"] = signature
	handler.mu.Unlock()
	if _, err := DiscoverYUM(context.Background(), base); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered repomd signature error = %v", err)
	}

}

func TestAPTTamperAndExpiredReleaseFailClosed(t *testing.T) {
	signing := newTestSigning(t)
	handler := newProtocolServer()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	pkg := aptPackageFixture{name: "foo", version: "1", arch: "amd64", filename: "pool/main/f/foo/foo_1_amd64.deb", body: []byte("deb")}
	publishAPTFixture(t, handler, signing, []aptPackageFixture{pkg})
	source := APTSource{
		BaseURL: server.URL, Suite: "bookworm", Components: []string{"main"}, Architectures: []string{"amd64"},
		Keyring: openpgp.EntityList{signing.entity}, Client: server.Client(), WorkDir: t.TempDir(),
	}
	handler.mu.Lock()
	inRelease := handler.files["dists/bookworm/InRelease"]
	inRelease = bytes.Replace(inRelease, []byte("Package"), []byte("Packagf"), 1)
	handler.files["dists/bookworm/InRelease"] = inRelease
	handler.mu.Unlock()
	if _, err := DiscoverAPT(context.Background(), source); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered InRelease error = %v", err)
	}

	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	if err := validateReleaseWindow(map[string]string{"valid-until": "Sat, 12 Jul 2025 00:00:00 UTC"}, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("expired Release error = %v", err)
	}
	if err := validateReleaseWindow(map[string]string{"date": "Sat, 12 Jul 2031 00:00:00 UTC"}, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("future Release error = %v", err)
	}
}

func TestAPTIndexCannotEscapeSelectedComponent(t *testing.T) {
	signing := newTestSigning(t)
	handler := newProtocolServer()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	pkg := aptPackageFixture{
		name: "foo", version: "1", arch: "amd64",
		filename: "pool/contrib/f/foo/foo_1_amd64.deb", body: []byte("deb"),
	}
	publishAPTFixture(t, handler, signing, []aptPackageFixture{pkg})
	_, err := DiscoverAPT(context.Background(), APTSource{
		BaseURL: server.URL, Suite: "bookworm", Components: []string{"main"}, Architectures: []string{"amd64"},
		Keyring: openpgp.EntityList{signing.entity}, Client: server.Client(), WorkDir: t.TempDir(),
	})
	if !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("cross-component package path error = %v", err)
	}
}

func TestEvidenceMutationPreventsReceiptCommit(t *testing.T) {
	signing := newTestSigning(t)
	handler := newProtocolServer()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	pkg := aptPackageFixture{name: "foo", version: "1", arch: "amd64", filename: "pool/main/f/foo/foo_1_amd64.deb", body: []byte("deb")}
	publishAPTFixture(t, handler, signing, []aptPackageFixture{pkg})
	discovery, err := DiscoverAPT(context.Background(), APTSource{
		BaseURL: server.URL, Suite: "bookworm", Components: []string{"main"}, Architectures: []string{"amd64"},
		Keyring: openpgp.EntityList{signing.entity}, Client: server.Client(), WorkDir: filepath.Join(t.TempDir(), "metadata"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var evidencePath string
	for _, evidence := range discovery.Evidence {
		if evidence.Kind == "apt-packages" {
			evidencePath = evidence.Path
		}
	}
	if evidencePath == "" {
		t.Fatal("Packages evidence absent")
	}
	if err := os.WriteFile(evidencePath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := provenance.NewStore(filepath.Join(t.TempDir(), "state"))
	_, err = (Executor{
		Downloader: syncer.Downloader{Client: server.Client(), Attempts: 1}, DownloadDir: t.TempDir(),
		Provenance: store, Workers: 1,
	}).Run(context.Background(), discovery, syncer.Filter{}, emptyInventory{})
	if !errors.Is(err, ErrEvidence) {
		t.Fatalf("tampered evidence execution error = %v", err)
	}
	if _, err := store.Get("deb", discovery.Candidates[0].SHA256); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt committed despite evidence tamper: %v", err)
	}
}

func TestEvidenceAndDownloadPathsRejectSymlinks(t *testing.T) {
	work := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(work, "evidence")); err != nil {
		t.Fatal(err)
	}
	if _, err := preserveBytes(work, "apt-inrelease", "https://repo.example.invalid/InRelease", []byte("signed"), true); err == nil {
		t.Fatal("evidence symlink was accepted")
	}

	downloadLink := filepath.Join(t.TempDir(), "downloads")
	if err := os.Symlink(outside, downloadLink); err != nil {
		t.Fatal(err)
	}
	candidate := upstreamCandidateFor("pkg", "1", "amd64", []byte("rpm"), "https://repo.example.invalid/pkg.rpm")
	if _, err := verifiedDownload(context.Background(), candidate, downloadLink, syncer.Downloader{Attempts: 1}); err == nil {
		t.Fatal("download-root symlink was accepted")
	}
}

func TestPreserveBytesFailsClosedOnDirectorySyncAndReplayConverges(t *testing.T) {
	work := t.TempDir()
	wanted := []byte("signed metadata evidence")
	injected := errors.New("injected evidence directory sync failure")
	_, err := preserveBytesWithDirectorySync(
		work, "apt-inrelease", "https://repo.example.invalid/InRelease", wanted, true,
		func(string) error { return injected },
	)
	if !errors.Is(err, injected) {
		t.Fatalf("evidence directory sync failure was hidden: %v", err)
	}
	digest := sha256.Sum256(wanted)
	coordinate := filepath.Join(work, "evidence", "sha256", hex.EncodeToString(digest[:]))
	if body, readErr := os.ReadFile(coordinate); readErr != nil || !bytes.Equal(body, wanted) {
		t.Fatalf("post-link uncertain evidence is not inspectable: body=%q err=%v", body, readErr)
	}
	evidence, err := preserveBytes(work, "apt-inrelease", "https://repo.example.invalid/InRelease", wanted, true)
	if err != nil || evidence.Path != coordinate {
		t.Fatalf("replay did not converge through existing evidence: evidence=%+v err=%v", evidence, err)
	}
}

func TestDownloadUnlockFailureIsPartOfOperationResult(t *testing.T) {
	injected := errors.New("injected download unlock failure")
	var resultErr error
	propagateDownloadUnlock(func() error { return injected }, &resultErr)
	if !errors.Is(resultErr, injected) {
		t.Fatalf("successful download hid unlock failure: %v", resultErr)
	}

	primary := errors.New("primary download failure")
	resultErr = primary
	propagateDownloadUnlock(func() error { return injected }, &resultErr)
	if !errors.Is(resultErr, primary) || !errors.Is(resultErr, injected) {
		t.Fatalf("download unlock failure did not preserve both errors: %v", resultErr)
	}
}

func TestVerifiedDownloadBoundsResponsesAndResumesSafely(t *testing.T) {
	t.Run("overlong chunked body is bounded", func(t *testing.T) {
		wanted := []byte("body")
		var identity atomic.Bool
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity.Store(r.Header.Get("Accept-Encoding") == "identity")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			_, _ = w.Write(bytes.Repeat([]byte("x"), 64*1024))
		}))
		defer server.Close()
		candidate := upstreamCandidateFor("pkg", "1", "amd64", wanted, server.URL+"/pkg")
		dir := t.TempDir()
		_, err := verifiedDownload(context.Background(), candidate, dir, syncer.Downloader{Client: server.Client(), Attempts: 1})
		if err == nil || !strings.Contains(err.Error(), "more bytes") {
			t.Fatalf("overlong response error = %v", err)
		}
		if !identity.Load() {
			t.Fatal("HTTP byte verification did not request identity encoding")
		}
		if _, err := os.Lstat(filepath.Join(dir, candidate.SHA256+".part")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("overlong partial retained: %v", err)
		}
	})

	t.Run("ignored Range restarts instead of appending", func(t *testing.T) {
		body := []byte("complete-body")
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			_, _ = w.Write(body)
		}))
		defer server.Close()
		candidate := upstreamCandidateFor("pkg", "1", "amd64", body, server.URL+"/pkg")
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, candidate.SHA256+".part"), []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
		filename, err := verifiedDownload(context.Background(), candidate, dir, syncer.Downloader{Client: server.Client(), Attempts: 1})
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filename)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("range restart bytes=%q err=%v", got, err)
		}
	})

	t.Run("invalid Content-Range never mutates partial", func(t *testing.T) {
		body := []byte("abcdefgh")
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Range", "bytes 0-7/8")
			w.Header().Set("Content-Length", "8")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(body)
		}))
		defer server.Close()
		candidate := upstreamCandidateFor("pkg", "1", "amd64", body, server.URL+"/pkg")
		dir := t.TempDir()
		partial := []byte("abc")
		partialPath := filepath.Join(dir, candidate.SHA256+".part")
		if err := os.WriteFile(partialPath, partial, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := verifiedDownload(context.Background(), candidate, dir, syncer.Downloader{Client: server.Client(), Attempts: 1}); err == nil {
			t.Fatal("invalid Content-Range was accepted")
		}
		got, err := os.ReadFile(partialPath)
		if err != nil || !bytes.Equal(got, partial) {
			t.Fatalf("partial mutated after invalid Range: %q %v", got, err)
		}
	})
}

func TestVerifiedDownloadSerializesConcurrentWriters(t *testing.T) {
	body := bytes.Repeat([]byte("concurrent"), 4096)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	defer server.Close()
	candidate := upstreamCandidateFor("pkg", "1", "amd64", body, server.URL+"/pkg")
	dir := t.TempDir()
	const goroutines = 8
	errorsOut := make(chan error, goroutines)
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := verifiedDownload(context.Background(), candidate, dir, syncer.Downloader{Client: server.Client(), Attempts: 1})
			errorsOut <- err
		}()
	}
	wg.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("concurrent requests = %d, want 1", got)
	}
}

func TestYUMXMLTokenAttributesAndPackageCountAreBounded(t *testing.T) {
	base, err := normalizeBase("https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("rpm"))
	longName := strings.Repeat("x", 4096)
	oversized := fmt.Sprintf(`<metadata xmlns="%s" packages="1"><package type="rpm"><name>%s</name></package></metadata>`, yumCommonNamespace, longName)
	err = parsePrimaryLimited(newXMLTokenLimitReader(strings.NewReader(oversized), 1024), base, 64, 10, func(syncer.Candidate) error { return nil })
	if !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("oversized XML token error = %v", err)
	}

	tooMany := fmt.Sprintf(`<metadata xmlns="%s" packages="2"></metadata>`, yumCommonNamespace)
	err = parsePrimaryLimited(strings.NewReader(tooMany), base, 64, 1, func(syncer.Candidate) error { return nil })
	if !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("oversized package count error = %v", err)
	}

	duplicateAttribute := fmt.Sprintf(`<metadata xmlns="%s" packages="1"><package type="rpm"><name>pkg</name><arch>x86_64</arch><version epoch="0" ver="1" ver="2" rel="1"/><checksum type="sha256" pkgid="YES">%s</checksum><size package="3"/><location href="Packages/p/pkg.rpm"/></package></metadata>`, yumCommonNamespace, hex.EncodeToString(hash[:]))
	err = parsePrimaryLimited(strings.NewReader(duplicateAttribute), base, 64, 10, func(syncer.Candidate) error { return nil })
	if !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("duplicate XML attribute error = %v", err)
	}
}

func TestAPTParserBoundsCountAndRejectsDuplicateReleaseEntries(t *testing.T) {
	base, err := normalizeBase("https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	paragraph := func(name string) string {
		hash := sha256.Sum256([]byte(name))
		return fmt.Sprintf("Package: %s\nVersion: 1\nArchitecture: amd64\nFilename: pool/main/%s/%s.deb\nSize: %d\nSHA256: %s\n\n", name, name, name, len(name), hex.EncodeToString(hash[:]))
	}
	err = parseDebPackagesLimited(strings.NewReader(paragraph("a")+paragraph("b")), base, 4096, 1, func(syncer.Candidate, string) error { return nil })
	if !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("APT package count error = %v", err)
	}

	hash := strings.Repeat("a", 64)
	release := []byte("Suite: bookworm\nSHA256:\n " + hash + " 10 main/binary-amd64/Packages.gz\n " + hash + " 10 main/binary-amd64/Packages.gz\n")
	if _, _, err := parseRelease(release); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("duplicate Release checksum error = %v", err)
	}
}

func TestHTTPContentEncodingIsNeverImplicitlyExpanded(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, "not-gzip")
	}))
	defer server.Close()
	_, _, err := fetchBytes(context.Background(), server.Client(), server.URL+"/Release", 1024, false)
	if !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("encoded HTTP response error = %v", err)
	}
}

func TestCompressedIndexChecksumFailureIsNotSilenced(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte("signed index payload")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), compressed.Bytes()...)
	corrupt[len(corrupt)-1] ^= 0xff
	filename := filepath.Join(t.TempDir(), "Packages.gz")
	if err := os.WriteFile(filename, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	stream, err := openIndex(filename, "https://repo.example.invalid/Packages.gz", Limits{}.withDefaults())
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(stream)
	closeErr := stream.Close()
	if readErr == nil && closeErr == nil {
		t.Fatal("corrupt gzip checksum was accepted")
	}
}

func TestOpenIndexRejectsPathReplacementAcrossStreamLifetime(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte("index payload\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		swap func(string, string, []byte) error
	}{
		{name: "regular replacement", swap: func(filename, retained string, body []byte) error {
			if err := os.Rename(filename, retained); err != nil {
				return err
			}
			return os.WriteFile(filename, body, 0o600)
		}},
		{name: "symlink replacement", swap: func(filename, retained string, _ []byte) error {
			if err := os.Rename(filename, retained); err != nil {
				return err
			}
			return os.Symlink(filepath.Base(retained), filename)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			filename := filepath.Join(directory, "Packages.gz")
			if err := os.WriteFile(filename, compressed.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			stream, err := openIndex(filename, filename, Limits{}.withDefaults())
			if err != nil {
				t.Fatal(err)
			}
			retained := filepath.Join(directory, "retained.gz")
			if err := test.swap(filename, retained, compressed.Bytes()); err != nil {
				stream.Close()
				t.Fatal(err)
			}
			if _, err := io.ReadAll(stream); err != nil {
				stream.Close()
				t.Fatal(err)
			}
			if err := stream.Close(); !errors.Is(err, ErrInvalidMetadata) {
				t.Fatalf("path replacement close error=%v", err)
			}
		})
	}
}

func TestOpenIndexRejectsReplacementAfterVerifiedHash(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte("verified primary\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	filename := filepath.Join(directory, "primary.xml.gz")
	if err := os.WriteFile(filename, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, identity, err := hashLocalRegular(context.Background(), filename, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filename, filepath.Join(directory, "verified.gz")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openIndex(filename, filename, Limits{}.withDefaults(), identity); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("replacement after verified hash error=%v", err)
	}
}

func TestGzipHeaderAllocationIsBounded(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Name = strings.Repeat("x", 4096)
	if _, err := writer.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "Packages.gz")
	if err := os.WriteFile(filename, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	limits := Limits{}.withDefaults()
	limits.XMLTokenBytes = 1024
	if _, err := openIndex(filename, "https://repo.example.invalid/Packages.gz", limits); !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("oversized gzip header error = %v", err)
	}
}

func upstreamCandidateFor(name, version, arch string, body []byte, rawURL string) syncer.Candidate {
	digest := sha256.Sum256(body)
	return syncer.Candidate{
		Format: "rpm", Name: name, Version: version, Arch: arch,
		URL: rawURL, Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]),
	}
}

func TestLimitsRejectSignatureAllocationAmplification(t *testing.T) {
	limits := Limits{SignatureBytes: (16 << 20) + 1}
	if err := limits.validate(); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("oversized signature budget error = %v", err)
	}
	if err := (Limits{SignatureBytes: 16 << 20}).validate(); err != nil {
		t.Fatalf("maximum signature budget rejected: %v", err)
	}
}

func FuzzResolveRelativeStaysInsideHTTPSBase(f *testing.F) {
	for _, seed := range []string{
		"pool/main/p/pkg/pkg.deb", "../escape", "/absolute", "a%2fb", "a\\b", "a?token=secret", "./a", "a//b",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, reference string) {
		base, err := normalizeBase("https://repo.example.invalid/repository/")
		if err != nil {
			t.Fatal(err)
		}
		resolved, err := resolveRelative(base, reference)
		if err != nil {
			return
		}
		if !strings.HasPrefix(resolved, "https://repo.example.invalid/repository/") {
			t.Fatalf("accepted reference escaped base: %q -> %q", reference, resolved)
		}
	})
}

func FuzzReleaseParserNeverAcceptsUnsafeChecksumPath(f *testing.F) {
	for _, seed := range []string{"main/binary-amd64/Packages.gz", "../escape", "/absolute", "a%2fb", "a\\b", "a?x=y"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, filename string) {
		release := []byte("Suite: bookworm\nSHA256:\n " + strings.Repeat("a", 64) + " 1 " + filename + "\n")
		entries, _, err := parseRelease(release)
		if err != nil {
			return
		}
		for accepted := range entries {
			base, baseErr := normalizeBase("https://repo.example.invalid/")
			if baseErr != nil {
				t.Fatal(baseErr)
			}
			if _, pathErr := resolveRelative(base, accepted); pathErr != nil {
				t.Fatalf("parseRelease accepted unsafe path %q: %v", accepted, pathErr)
			}
		}
	})
}
