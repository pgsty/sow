package verify

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestAPTProtocolProbeAuthenticatesByHashAndDEBThroughBasicCDN(t *testing.T) {
	ctx := context.Background()
	created := time.Unix(1_700_000_000, 0).UTC()
	private := testPrivateKey(t, created.Add(-time.Hour))
	signer, err := aptrepo.NewSignerBytes(private, nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewAPTVerifier(bytes.NewReader(private))
	if err != nil {
		t.Fatal(err)
	}
	debPath := decodeFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb")
	pkg, err := aptrepo.InspectPackage(ctx, debPath, "main")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	copyFile(t, debPath, filepath.Join(root, filepath.FromSlash(pkg.PoolPath)))
	if _, err := aptrepo.Generate(ctx, root, aptrepo.RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "jammy", Codename: "jammy",
		Components: []string{"main"}, Architectures: []string{"arm64"}, Date: created,
	}, []aptrepo.Index{{Component: "main", Architecture: "arm64", Packages: []aptrepo.Package{pkg}}}, signer); err != nil {
		t.Fatal(err)
	}

	server := newProtocolTreeServer(t, root, "/pro/v1/basic/apt/test/", true, nil)
	probe := APTProtocolProbe{
		Client: server.Client(), CDNBaseURL: server.URL, RepositoryPath: "pro/v1/basic/apt/test",
		Suite: "jammy", Component: "main", ExpectedComponents: []string{"main"}, Architecture: "arm64", Headers: protocolBasicHeaders(),
		Verifier: verifier, VerifyAt: created, TempDir: t.TempDir(), ChunkEntries: 1, AllowHTTP: false,
	}
	evidence, err := probe.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Client != "apt" || evidence.PackageName != pkg.Name || evidence.PackageVersion != pkg.Version || evidence.PackageSHA256 != pkg.SHA256 || evidence.MetadataObjects != 2 {
		t.Fatalf("unexpected APT evidence: %+v", evidence)
	}
	phantomRoot := t.TempDir()
	copyFile(t, debPath, filepath.Join(phantomRoot, filepath.FromSlash(pkg.PoolPath)))
	if _, err := aptrepo.Generate(ctx, phantomRoot, aptrepo.RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "jammy", Codename: "jammy",
		Components: []string{"main", "18"}, Architectures: []string{"arm64"}, Date: created,
	}, []aptrepo.Index{{Component: "main", Architecture: "arm64", Packages: []aptrepo.Package{pkg}}, {Component: "18", Architecture: "arm64"}}, signer); err != nil {
		t.Fatal(err)
	}
	phantomServer := newProtocolTreeServer(t, phantomRoot, "/apt/phantom/", false, nil)
	phantomProbe := probe
	phantomProbe.Client, phantomProbe.CDNBaseURL, phantomProbe.RepositoryPath, phantomProbe.Headers = phantomServer.Client(), phantomServer.URL, "apt/phantom", nil
	if _, err := phantomProbe.Run(ctx); !errors.Is(err, ErrClientIntegrity) {
		t.Fatalf("phantom signed APT component passed exact L4 contract: %v", err)
	}
	token := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	tokenServer := newProtocolTreeServer(t, root, "/pro/v1/"+token+"/apt/test/", false, nil)
	tokenProbe := probe
	tokenProbe.Client, tokenProbe.CDNBaseURL = tokenServer.Client(), tokenServer.URL
	tokenProbe.RepositoryPath, tokenProbe.Headers = "pro/v1/"+token+"/apt/test", nil
	if tokenEvidence, err := tokenProbe.Run(ctx); err != nil || tokenEvidence.PackageSHA256 != pkg.SHA256 {
		t.Fatalf("token path APT evidence=%+v err=%v", tokenEvidence, err)
	}
	tokenProbe.Component = "missing"
	if _, err := tokenProbe.Run(ctx); !errors.Is(err, ErrClientIntegrity) || strings.Contains(err.Error(), token) {
		t.Fatalf("token path failure leaked token or passed: %v", err)
	}
	emptyRoot := t.TempDir()
	if _, err := aptrepo.Generate(ctx, emptyRoot, aptrepo.RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "jammy", Codename: "jammy",
		Components: []string{"empty"}, Architectures: []string{"arm64"}, Date: created,
	}, []aptrepo.Index{{Component: "empty", Architecture: "arm64"}}, signer); err != nil {
		t.Fatal(err)
	}
	emptyServer := newProtocolTreeServer(t, emptyRoot, "/apt/empty/", false, nil)
	emptyProbe := probe
	emptyProbe.Client, emptyProbe.CDNBaseURL, emptyProbe.RepositoryPath = emptyServer.Client(), emptyServer.URL, "apt/empty"
	emptyProbe.Component, emptyProbe.ExpectedComponents, emptyProbe.Headers = "empty", []string{"empty"}, nil
	if _, err := emptyProbe.Run(ctx); !errors.Is(err, ErrClientCoverage) {
		t.Fatalf("empty selected APT repository error = %v", err)
	}

	withoutBasic := probe
	withoutBasic.Headers = nil
	if _, err := withoutBasic.Run(ctx); !errors.Is(err, ErrClientNetwork) {
		t.Fatalf("missing Basic error = %v", err)
	}
	badSignature := newProtocolTreeServer(t, root, "/apt/test/", false, func(relative string, body []byte) (int, []byte, http.Header) {
		if relative == "dists/jammy/InRelease" {
			body = bytes.Replace(append([]byte(nil), body...), []byte("Origin: Pigsty"), []byte("Origin: Xigsty"), 1)
		}
		return http.StatusOK, body, nil
	})
	badProbe := probe
	badProbe.Client, badProbe.CDNBaseURL, badProbe.RepositoryPath, badProbe.Headers = badSignature.Client(), badSignature.URL, "apt/test", nil
	if _, err := badProbe.Run(ctx); !errors.Is(err, ErrClientIntegrity) {
		t.Fatalf("bad InRelease error = %v", err)
	}
	missingPackage := newProtocolTreeServer(t, root, "/apt/test/", false, func(relative string, body []byte) (int, []byte, http.Header) {
		if strings.HasPrefix(relative, "pool/") {
			return http.StatusNotFound, nil, nil
		}
		return http.StatusOK, body, nil
	})
	missingProbe := probe
	missingProbe.Client, missingProbe.CDNBaseURL, missingProbe.RepositoryPath, missingProbe.Headers = missingPackage.Client(), missingPackage.URL, "apt/test", nil
	if _, err := missingProbe.Run(ctx); !errors.Is(err, ErrClientIntegrity) {
		t.Fatalf("missing DEB error = %v", err)
	}
	unsafe := probe
	unsafe.RepositoryPath = "apt//test"
	if _, err := unsafe.Run(ctx); !errors.Is(err, ErrClientCoverage) {
		t.Fatalf("non-canonical APT URL error = %v", err)
	}
}

func TestYUMProtocolProbeValidatesGzipAndZstdMetadataAndRPM(t *testing.T) {
	ctx := context.Background()
	created := time.Unix(1_700_000_000, 0).UTC()
	packageVerifyAt := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	packageKeyring := protocolRPMPackageKeyring(t)
	private := testPrivateKey(t, created.Add(-time.Hour))
	rpmPath := decodeFixture(t, filepath.Join("..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), "pgdg-redhat-nonfree-repo.rpm")
	info, err := yumrepo.InspectPackage(ctx, yumrepo.PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	decodedDigest, err := hex.DecodeString(info.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	var packageDigest [32]byte
	copy(packageDigest[:], decodedDigest)
	authenticated := yumPackageSample{Entry: manifest.Entry{Path: info.Location, Size: info.Size, SHA256: packageDigest}, Name: info.Name, Arch: info.Arch, Version: info.Version, Release: info.Release, Epoch: info.Epoch}
	if !yumPackageMatchesAuthenticatedSample(info, authenticated) {
		t.Fatal("matching RPM identity was rejected")
	}
	authenticated.Version += ".metadata-drift"
	if yumPackageMatchesAuthenticatedSample(info, authenticated) {
		t.Fatal("RPM Version drift from authenticated primary metadata was accepted")
	}
	for _, test := range []struct {
		name        string
		el          int
		compression yumrepo.Compression
	}{{"el8-gzip", 8, yumrepo.CompressionGzip}, {"el10-zstd", 10, yumrepo.CompressionZstd}} {
		t.Run(test.name, func(t *testing.T) {
			signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(private), nil, created)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			copyFile(t, rpmPath, filepath.Join(root, filepath.FromSlash(info.Location)))
			if _, err := yumrepo.Generate(ctx, filepath.Join(root, "repodata"), yumrepo.Options{ELMajor: test.el, Revision: created.Unix(), Signer: signer}, &yumrepo.SliceIterator{Inputs: []yumrepo.PackageInput{{Path: rpmPath, Basename: filepath.Base(info.Location)}}}); err != nil {
				t.Fatal(err)
			}
			verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(private), created)
			if err != nil {
				t.Fatal(err)
			}
			server := newYUMProtocolServer(t, root, true, nil)
			probe := YUMProtocolProbe{
				Client: server.Client(), CDNBaseURL: server.URL,
				MirrorlistPath:        "pro/v1/basic/_sow/v1/mirrorlist/stable/rpm-test/el10/x86_64.txt",
				ExpectedGenerationURL: server.URL + "/pro/v1/basic/_sow/v1/g/00000000000000000001/yum/test/x86_64/",
				Headers:               protocolBasicHeaders(), Architecture: "x86_64", Compression: test.compression, Verifier: verifier,
				PackageKeyring: packageKeyring, VerifyAt: packageVerifyAt,
				TempDir: t.TempDir(), ChunkEntries: 1,
			}
			evidence, err := probe.Run(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if evidence.Client != "dnf" || evidence.PackageName != info.Name || evidence.PackageSHA256 != info.SHA256 || evidence.MetadataObjects != 6 {
				t.Fatalf("unexpected YUM evidence: %+v", evidence)
			}
		})
	}
}

func TestYUMProtocolProbeRejectsBadSignatureMissingRPMAndCrossOriginMirror(t *testing.T) {
	ctx := context.Background()
	created := time.Unix(1_700_000_000, 0).UTC()
	packageVerifyAt := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	packageKeyring := protocolRPMPackageKeyring(t)
	private := testPrivateKey(t, created.Add(-time.Hour))
	signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(private), nil, created)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(private), created)
	if err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeFixture(t, filepath.Join("..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), "pgdg-redhat-nonfree-repo.rpm")
	info, err := yumrepo.InspectPackage(ctx, yumrepo.PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	copyFile(t, rpmPath, filepath.Join(root, filepath.FromSlash(info.Location)))
	if _, err := yumrepo.Generate(ctx, filepath.Join(root, "repodata"), yumrepo.Options{ELMajor: 10, Revision: created.Unix(), Signer: signer}, &yumrepo.SliceIterator{Inputs: []yumrepo.PackageInput{{Path: rpmPath, Basename: filepath.Base(info.Location)}}}); err != nil {
		t.Fatal(err)
	}
	baseProbe := YUMProtocolProbe{Architecture: "x86_64", Compression: yumrepo.CompressionZstd, Verifier: verifier, PackageKeyring: packageKeyring, VerifyAt: packageVerifyAt, TempDir: t.TempDir(), ChunkEntries: 1, MirrorlistPath: "_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt"}
	badSignature := newYUMProtocolServer(t, root, false, func(relative string, body []byte) (int, []byte, http.Header) {
		if relative == "repodata/repomd.xml.asc" {
			return http.StatusOK, []byte("broken"), nil
		}
		return http.StatusOK, body, nil
	})
	probe := baseProbe
	probe.Client, probe.CDNBaseURL = badSignature.Client(), badSignature.URL
	probe.ExpectedGenerationURL = badSignature.URL + "/_sow/v1/g/00000000000000000001/yum/test/x86_64/"
	if _, err := probe.Run(ctx); !errors.Is(err, ErrClientIntegrity) {
		t.Fatalf("bad repomd signature error = %v", err)
	}
	missing := newYUMProtocolServer(t, root, false, func(relative string, body []byte) (int, []byte, http.Header) {
		if strings.HasPrefix(relative, "Packages/") {
			return http.StatusNotFound, nil, nil
		}
		return http.StatusOK, body, nil
	})
	probe.Client, probe.CDNBaseURL = missing.Client(), missing.URL
	probe.ExpectedGenerationURL = missing.URL + "/_sow/v1/g/00000000000000000001/yum/test/x86_64/"
	if _, err := probe.Run(ctx); !errors.Is(err, ErrClientIntegrity) {
		t.Fatalf("missing RPM error = %v", err)
	}
	crossOrigin := newYUMProtocolServer(t, root, false, func(relative string, body []byte) (int, []byte, http.Header) {
		if relative == "mirrorlist" {
			return http.StatusOK, []byte("https://attacker.invalid/repo/\n"), nil
		}
		return http.StatusOK, body, nil
	})
	probe.Client, probe.CDNBaseURL = crossOrigin.Client(), crossOrigin.URL
	probe.ExpectedGenerationURL = crossOrigin.URL + "/_sow/v1/g/00000000000000000001/yum/test/x86_64/"
	if _, err := probe.Run(ctx); !errors.Is(err, ErrClientIntegrity) {
		t.Fatalf("cross-origin mirror error = %v", err)
	}

	wrongGeneration := newYUMProtocolServer(t, root, false, func(relative string, body []byte) (int, []byte, http.Header) {
		if relative == "mirrorlist" {
			return http.StatusOK, bytes.Replace(body, []byte("00000000000000000001"), []byte("00000000000000000000"), 1), nil
		}
		return http.StatusOK, body, nil
	})
	probe.Client, probe.CDNBaseURL = wrongGeneration.Client(), wrongGeneration.URL
	probe.ExpectedGenerationURL = wrongGeneration.URL + "/_sow/v1/g/00000000000000000001/yum/test/x86_64/"
	if _, err := probe.Run(ctx); !errors.Is(err, ErrClientIntegrity) {
		t.Fatalf("wrong-generation mirror error = %v", err)
	}

	publicFromStable := newYUMProtocolServer(t, root, true, func(relative string, body []byte) (int, []byte, http.Header) {
		if relative == "mirrorlist" {
			return http.StatusOK, []byte(strings.Replace(string(body), "/pro/v1/basic", "", 1)), nil
		}
		return http.StatusOK, body, nil
	})
	probe.Client, probe.CDNBaseURL = publicFromStable.Client(), publicFromStable.URL
	probe.MirrorlistPath = "pro/v1/basic/_sow/v1/mirrorlist/stable/rpm-test/el10/x86_64.txt"
	probe.ExpectedGenerationURL = publicFromStable.URL + "/pro/v1/basic/_sow/v1/g/00000000000000000001/yum/test/x86_64/"
	probe.Headers = protocolBasicHeaders()
	if _, err := probe.Run(ctx); !errors.Is(err, ErrClientIntegrity) {
		t.Fatalf("stable mirror escaped to public generation route: %v", err)
	}

	publicFromTokenStable := newYUMProtocolServer(t, root, false, nil)
	probe.Client, probe.CDNBaseURL = publicFromTokenStable.Client(), publicFromTokenStable.URL
	probe.MirrorlistPath = "pro/v1/abcdefghijklmnopqrstuvwxyz0123456789/_sow/v1/mirrorlist/stable/rpm-test/el10/x86_64.txt"
	probe.ExpectedGenerationURL = publicFromTokenStable.URL + "/pro/v1/abcdefghijklmnopqrstuvwxyz0123456789/_sow/v1/g/00000000000000000001/yum/test/x86_64/"
	probe.Headers = nil
	if _, err := probe.Run(ctx); !errors.Is(err, ErrClientIntegrity) {
		t.Fatalf("runtime-token stable mirror escaped to public generation route: %v", err)
	}

	wrongPackageKeyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(private))
	if err != nil || len(wrongPackageKeyring) == 0 {
		t.Fatalf("parse wrong RPM package keyring: entities=%d err=%v", len(wrongPackageKeyring), err)
	}
	wrongPackageTrust := newYUMProtocolServer(t, root, false, nil)
	probe = baseProbe
	probe.Client, probe.CDNBaseURL = wrongPackageTrust.Client(), wrongPackageTrust.URL
	probe.ExpectedGenerationURL = wrongPackageTrust.URL + "/_sow/v1/g/00000000000000000001/yum/test/x86_64/"
	probe.PackageKeyring = wrongPackageKeyring
	if _, err := probe.Run(ctx); !errors.Is(err, ErrClientIntegrity) {
		t.Fatalf("untrusted RPM package signer error=%v", err)
	}
}

func protocolRPMPackageKeyring(t *testing.T) openpgp.EntityList {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "compat", "testdata", "PGDG-RPM-GPG-KEY-RHEL-nonfree.asc"))
	if err != nil {
		t.Fatal(err)
	}
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
	if err != nil || len(entities) == 0 {
		t.Fatalf("parse RPM package keyring: entities=%d err=%v", len(entities), err)
	}
	return entities
}

func TestProtocolFetcherRefusesSameOriginRedirectWithoutReplayingCredential(t *testing.T) {
	for _, fixture := range []struct {
		name    string
		path    string
		headers http.Header
	}{
		{name: "basic", path: "pro/v1/basic/object", headers: protocolBasicHeaders()},
		{name: "token", path: "pro/v1/abcdefghijklmnopqrstuvwxyz0123456789/object"},
	} {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			var replayed atomic.Bool
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/"+fixture.path {
					http.Redirect(writer, request, "/public/object", http.StatusFound)
					return
				}
				replayed.Store(true)
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write([]byte("unexpected"))
			}))
			defer server.Close()
			fetcher, err := newProtocolFetcher(server.URL, server.Client(), fixture.headers, false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fetcher.readRelative(context.Background(), fixture.path, 1024); !errors.Is(err, ErrClientIntegrity) {
				t.Fatalf("same-origin redirect error = %v", err)
			}
			if replayed.Load() {
				t.Fatal("redirect Location received a replayed credential-bearing request")
			}
		})
	}
}

func TestYUMPrimarySampleRequiresAnInstallableArchitecture(t *testing.T) {
	checksum := strings.Repeat("a", 64)
	primary := `<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1"><package type="rpm"><name>pkg</name><arch>aarch64</arch><version epoch="0" ver="1" rel="1"/><checksum type="sha256" pkgid="YES">` + checksum + `</checksum><size package="1"/><location href="Packages/p/pkg.rpm"/></package></metadata>`
	packages, err := newManifestSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer packages.Close()
	identities, err := newManifestSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer identities.Close()
	sample, count, err := parseYUMPrimaryWithSampleForArch(context.Background(), strings.NewReader(primary), packages, identities, "x86_64")
	if err != nil || count != 1 || sample.Name != "" {
		t.Fatalf("incompatible architecture sample=%+v count=%d err=%v", sample, count, err)
	}
}

type protocolMutation func(relative string, body []byte) (int, []byte, http.Header)

func newProtocolTreeServer(t *testing.T, root, prefix string, requireBasic bool, mutate protocolMutation) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || !strings.HasPrefix(request.URL.Path, prefix) {
			http.NotFound(writer, request)
			return
		}
		if requireBasic {
			username, password, ok := request.BasicAuth()
			if !ok || username != "verifier" || password != "verify-secret" {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		relative := strings.TrimPrefix(request.URL.Path, prefix)
		filename := filepath.Join(root, filepath.FromSlash(relative))
		body, err := os.ReadFile(filename)
		if err != nil {
			http.NotFound(writer, request)
			return
		}
		status, headers := http.StatusOK, http.Header(nil)
		if mutate != nil {
			status, body, headers = mutate(relative, body)
		}
		for name, values := range headers {
			for _, value := range values {
				writer.Header().Add(name, value)
			}
		}
		writer.WriteHeader(status)
		_, _ = writer.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

func newYUMProtocolServer(t *testing.T, root string, requireBasic bool, mutate protocolMutation) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if requireBasic {
			username, password, ok := request.BasicAuth()
			if !ok || username != "verifier" || password != "verify-secret" {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		relative := ""
		if strings.Contains(request.URL.Path, "/_sow/v1/mirrorlist/") {
			relative = "mirrorlist"
			body := []byte(server.URL + "/pro/v1/basic/_sow/v1/g/00000000000000000001/yum/test/x86_64/\n")
			if !requireBasic {
				body = []byte(server.URL + "/_sow/v1/g/00000000000000000001/yum/test/x86_64/\n")
			}
			status, headers := http.StatusOK, http.Header(nil)
			if mutate != nil {
				status, body, headers = mutate(relative, body)
			}
			for name, values := range headers {
				for _, value := range values {
					writer.Header().Add(name, value)
				}
			}
			writer.WriteHeader(status)
			_, _ = writer.Write(body)
			return
		}
		marker := "/yum/test/x86_64/"
		at := strings.Index(request.URL.Path, marker)
		if at < 0 {
			http.NotFound(writer, request)
			return
		}
		relative = request.URL.Path[at+len(marker):]
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			http.NotFound(writer, request)
			return
		}
		status, headers := http.StatusOK, http.Header(nil)
		if mutate != nil {
			status, body, headers = mutate(relative, body)
		}
		for name, values := range headers {
			for _, value := range values {
				writer.Header().Add(name, value)
			}
		}
		writer.WriteHeader(status)
		_, _ = writer.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

func protocolBasicHeaders() http.Header {
	request, _ := http.NewRequest(http.MethodGet, "https://example.invalid", nil)
	request.SetBasicAuth("verifier", "verify-secret")
	return request.Header
}
