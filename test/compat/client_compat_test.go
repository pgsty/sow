package compat_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pgsty/sow/internal/yumrepo"
)

const (
	defaultAPTImage   = "pgsty/u22:latest"
	defaultAPT12Image = "ubuntu:16.04@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6"
	defaultDNFImage   = "pgsty/el10:latest"
	defaultEL9Image   = "almalinux:9"
	defaultEL8Image   = "almalinux:8"
	defaultEL7Image   = "centos:7@sha256:be65f488b7764ad3638f236b7b515b3678369a5124c47b8d32916d6487418ea4"
	debPackage        = "sow-compat-deb"
	debVersion        = "1.2.3-1"
	newDebVersion     = "2.0.0-1"
	rpmPackage        = "pgdg-redhat-nonfree-repo"
	rpmVersionArch    = "42.0-20PGDG.noarch"
	el7RPMPackage     = "centos-release"
	el7RPMVersionArch = "7-2.1511.el7.centos.2.10.x86_64"
)

// TestDockerClientCompatibility proves that repositories generated and signed
// by the production SOW CLI are consumable by unmodified apt and dnf clients.
// It is deliberately opt-in because it starts privileged package-manager
// processes in disposable Docker containers and relies on local test images.
func TestDockerClientCompatibility(t *testing.T) {
	if os.Getenv("SOW_RUN_DOCKER_COMPAT") != "1" {
		t.Skip("set SOW_RUN_DOCKER_COMPAT=1 to run real apt/dnf Docker compatibility tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	moduleRoot := findModuleRoot(t)
	work := hostableCompatTempDir(t)
	repositoryRoot := filepath.Join(work, "repository")
	if err := os.MkdirAll(repositoryRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	stableServingRoot := filepath.Join(repositoryRoot, "export-stable")
	if err := os.MkdirAll(stableServingRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	routeRequests, routePort, stopRouteServer := serveRepositoryHTTP(t, repositoryRoot)
	defer stopRouteServer()
	stableServingBaseURL := fmt.Sprintf("http://host.docker.internal:%d/pro/v1/basic", routePort)
	var basicRequests *requestLog
	var basicPort int
	if os.Getenv("SOW_COMPAT_NGINX") == "1" {
		var stopBasic func()
		basicRequests, basicPort, stopBasic = serveBasicRepositoryNginx(t, stableServingRoot, stableNginxAllowlist())
		defer stopBasic()
		stableServingBaseURL = fmt.Sprintf("http://host.docker.internal:%d/pro/v1/basic", basicPort)
	}
	configPath := filepath.Join(repositoryRoot, "sow.yaml")
	writeFile(t, configPath, []byte(compatConfig(routePort, stableServingBaseURL)), 0o600)
	for _, directory := range []string{
		filepath.Join(repositoryRoot, "apt", "test"),
		filepath.Join(repositoryRoot, "yum", "test", "x86_64"),
		filepath.Join(repositoryRoot, "yum", "el9", "x86_64"),
		filepath.Join(repositoryRoot, "yum", "el8", "x86_64"),
		filepath.Join(repositoryRoot, "yum", "el7", "x86_64"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	privateKey, publicKey := writeSigningKey(t, work)
	armoredPublicKey := filepath.Join(work, "signing-public.asc")
	upstreamRPMKey := filepath.Join(moduleRoot, "test", "compat", "testdata", "PGDG-RPM-GPG-KEY-RHEL-nonfree.asc")
	if info, err := os.Stat(upstreamRPMKey); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("upstream RPM package key fixture is unavailable: %v", err)
	}
	writeCompatRPMPackageKeyring(t, moduleRoot, repositoryRoot, upstreamRPMKey)
	centos7RPMKey := filepath.Join(moduleRoot, "third_party", "cavaliergopher-rpm", "testdata", "RPM-GPG-KEY-CentOS-7")
	publicKeyBody, err := os.ReadFile(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(repositoryRoot, "signing-public.gpg"), publicKeyBody, 0o644)
	debPath := writeInstallableDEB(t, work, debVersion)
	newDebPath := writeInstallableDEB(t, work, newDebVersion)
	rpmPath := decodeBase64Fixture(t,
		filepath.Join(moduleRoot, "internal", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"),
		filepath.Join(work, "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm"),
	)
	el7RPMPath := filepath.Join(moduleRoot, "third_party", "cavaliergopher-rpm", "testdata", "centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm")
	historyRPMs := copyRPMHistoryFixtures(t, moduleRoot, work)
	generateFrozenYUMRepository(t, privateKey, rpmPath, filepath.Join(repositoryRoot, "yum", "el8", "x86_64"), 8)
	generateFrozenYUMRepository(t, privateKey, el7RPMPath, filepath.Join(repositoryRoot, "yum", "el7", "x86_64"), 7)
	cliPath := buildCLI(ctx, t, moduleRoot, work)

	runCLI(ctx, t, moduleRoot, cliPath, "init", "--config", configPath, "--workers", "2", "--chunk-entries", "2")
	runCLI(ctx, t, moduleRoot, cliPath, "init", "--adopt-content", "--view", "latest", "--config", configPath, "--repo", "yum-el8", "--workers", "2", "--chunk-entries", "2")
	runCLI(ctx, t, moduleRoot, cliPath, "init", "--adopt-content", "--view", "latest", "--config", configPath, "--repo", "yum-el7", "--workers", "2", "--chunk-entries", "2")
	runCLI(ctx, t, moduleRoot, cliPath, "add", debPath, newDebPath, "--config", configPath, "--repo", "apt-test", "--component", "main", "--gpg-private-key-file", privateKey, "--workers", "2", "--chunk-entries", "2")
	yumAddArguments := append([]string{"add", rpmPath}, historyRPMs...)
	yumAddArguments = append(yumAddArguments, "--config", configPath, "--repo", "yum-test", "--gpg-private-key-file", privateKey, "--workers", "2", "--chunk-entries", "2")
	runCLI(ctx, t, moduleRoot, cliPath, yumAddArguments...)
	runCLI(ctx, t, moduleRoot, cliPath, "add", rpmPath, "--config", configPath, "--repo", "yum-el9", "--gpg-private-key-file", privateKey, "--workers", "2", "--chunk-entries", "2")
	runCLI(ctx, t, moduleRoot, cliPath, "promote", "beta", "latest", "--config", configPath, "--repo", "apt-test", "--repo", "yum-test", "--repo", "yum-el9")
	runCLI(ctx, t, moduleRoot, cliPath, "promote", "latest", "stable", "--config", configPath, "--repo", "apt-test", "--repo", "yum-test")
	snapshotID := "jammy-" + time.Now().UTC().Format("20060102")
	runCLI(ctx, t, moduleRoot, cliPath, "promote", "stable", snapshotID, "--config", configPath, "--repo", "apt-test")
	runCLI(ctx, t, moduleRoot, cliPath, "materialize", "beta", "--config", configPath, "--repo", "apt-test", "--target", "export", "--gpg-private-key-file", privateKey, "--workers", "2", "--chunk-entries", "2")
	runCLI(ctx, t, moduleRoot, cliPath, "materialize", "stable", "--config", configPath, "--repo", "apt-test", "--repo", "yum-test", "--target", "export-stable", "--serving-base-url", stableServingBaseURL, "--gpg-private-key-file", privateKey, "--workers", "2", "--chunk-entries", "2")
	runCLI(ctx, t, moduleRoot, cliPath, "materialize", snapshotID, "--config", configPath, "--repo", "apt-test", "--target", "export-snapshot", "--gpg-private-key-file", privateKey, "--workers", "2", "--chunk-entries", "2")
	runCLI(ctx, t, moduleRoot, cliPath, "materialize", "latest", "--config", configPath, "--repo", "apt-test", "--repo", "yum-test", "--repo", "yum-el9", "--repo", "yum-el8", "--repo", "yum-el7", "--gpg-private-key-file", privateKey, "--workers", "4", "--chunk-entries", "2")

	servingRoot := repositoryRoot
	assertGeneratedRepository(t, servingRoot)
	assertGeneratedFrozenYUMRepository(t, servingRoot, "el8", filepath.Base(rpmPath))
	assertGeneratedFrozenYUMRepository(t, servingRoot, "el7", filepath.Base(el7RPMPath))
	requests, port, stopServer := serveRepository(t, servingRoot, latestNginxAllowlist())
	defer stopServer()
	assertGeneratedAPTStableHistory(t, stableServingRoot)
	stableRequests, stablePort, stopStableServer := serveRepository(t, stableServingRoot, stableNginxAllowlist())
	defer stopStableServer()
	snapshotServingRoot := filepath.Join(repositoryRoot, "export-snapshot")
	assertGeneratedAPTSnapshotHistory(t, snapshotServingRoot, snapshotID)
	snapshotRequests, snapshotPort, stopSnapshotServer := serveRepository(t, snapshotServingRoot, nginxRepositoryAllowlist{
		Prefixes: []string{"apt/test"},
	})
	defer stopSnapshotServer()

	t.Run("apt", func(t *testing.T) {
		output := runDocker(ctx, t, compatImage("SOW_COMPAT_APT_IMAGE", defaultAPTImage),
			[]string{"-v", publicKey + ":/etc/apt/keyrings/sow-compat.gpg:ro"},
			aptScript(port),
		)
		writeFile(t, filepath.Join(work, "apt-client.log"), []byte(output), 0o600)
		t.Logf("apt repository requests:\n%s", requests.String())
		if !requests.contains("/apt/test/dists/jammy/main/binary-amd64/by-hash/SHA256/") {
			t.Fatalf("apt did not request an immutable by-hash index; requests:\n%s", requests.String())
		}
		if !requests.contains("/apt/test/pool/main/s/sow-compat-deb/sow-compat-deb_1.2.3-1_amd64.deb") {
			t.Fatalf("apt did not download the exact DEB payload; requests:\n%s", requests.String())
		}
	})

	t.Run("apt-1.2-support-floor", func(t *testing.T) {
		requests.reset()
		output := runDocker(ctx, t, compatImage("SOW_COMPAT_APT12_IMAGE", defaultAPT12Image),
			[]string{"-v", publicKey + ":/etc/apt/keyrings/sow-compat.gpg:ro"},
			apt12Script(port),
		)
		writeFile(t, filepath.Join(work, "apt-1.2-client.log"), []byte(output), 0o600)
		t.Logf("apt 1.2 repository requests:\n%s", requests.String())
		if !requests.contains("/apt/test/dists/jammy/main/binary-amd64/by-hash/SHA256/") {
			t.Fatalf("apt 1.2 support-floor client did not request an immutable by-hash index; requests:\n%s", requests.String())
		}
		if !requests.contains("/apt/test/pool/main/s/sow-compat-deb/sow-compat-deb_1.2.3-1_amd64.deb") {
			t.Fatalf("apt 1.2 support-floor client did not install the exact DEB payload; requests:\n%s", requests.String())
		}
	})

	t.Run("apt-stable-history-pin", func(t *testing.T) {
		output := runDocker(ctx, t, compatImage("SOW_COMPAT_APT_IMAGE", defaultAPTImage),
			[]string{"-v", publicKey + ":/etc/apt/keyrings/sow-compat.gpg:ro"},
			aptScript(stablePort),
		)
		writeFile(t, filepath.Join(work, "apt-stable-client.log"), []byte(output), 0o600)
		t.Logf("stable apt repository requests:\n%s", stableRequests.String())
		if !stableRequests.contains("/apt/test/dists/jammy/main/binary-amd64/by-hash/SHA256/") ||
			!stableRequests.contains("/apt/test/pool/main/s/sow-compat-deb/sow-compat-deb_1.2.3-1_amd64.deb") {
			t.Fatalf("stable apt did not pin the historical payload through by-hash metadata; requests:\n%s", stableRequests.String())
		}
	})

	t.Run("apt-immutable-snapshot-suite", func(t *testing.T) {
		output := runDocker(ctx, t, compatImage("SOW_COMPAT_APT_IMAGE", defaultAPTImage),
			[]string{"-v", publicKey + ":/etc/apt/keyrings/sow-compat.gpg:ro"},
			aptSuiteScript(snapshotPort, snapshotID),
		)
		writeFile(t, filepath.Join(work, "apt-snapshot-client.log"), []byte(output), 0o600)
		t.Logf("snapshot apt repository requests:\n%s", snapshotRequests.String())
		for _, required := range []string{
			"/apt/test/dists/" + snapshotID + "/InRelease",
			"/apt/test/dists/" + snapshotID + "/main/binary-amd64/by-hash/SHA256/",
			"/apt/test/pool/main/s/sow-compat-deb/sow-compat-deb_1.2.3-1_amd64.deb",
		} {
			if !snapshotRequests.contains(required) {
				t.Fatalf("apt snapshot suite did not consume %s; requests:\n%s", required, snapshotRequests.String())
			}
		}
	})

	t.Run("dnf-stable-history-pin", func(t *testing.T) {
		stableRequests.reset()
		output := runDocker(ctx, t, compatImage("SOW_COMPAT_DNF_IMAGE", defaultDNFImage),
			dnfKeyMounts(publicKey, upstreamRPMKey),
			dnfHistoryScript(stablePort, "yum/test/x86_64"),
		)
		writeFile(t, filepath.Join(work, "dnf-stable-history-client.log"), []byte(output), 0o600)
		t.Logf("stable dnf repository requests:\n%s", stableRequests.String())
		for _, filename := range []string{
			"centos-release-4-0.1.x86_64.rpm",
			"centos-release-5-0.0.el5.centos.2.x86_64.rpm",
		} {
			if !stableRequests.contains("/yum/test/x86_64/Packages/c/" + filename) {
				t.Fatalf("stable dnf did not pin historical payload %s; requests:\n%s", filename, stableRequests.String())
			}
		}
	})

	if basicPort != 0 {
		t.Run("basic-fallback-apt-and-dnf", func(t *testing.T) {
			stableGeneration := readStaticYUMGeneration(t, stableServingRoot, "stable", "yum-test", "el10", "x86_64")
			aptOutput := runDocker(ctx, t, compatImage("SOW_COMPAT_APT_IMAGE", defaultAPTImage),
				[]string{"-v", publicKey + ":/etc/apt/keyrings/sow-compat.gpg:ro"}, aptBasicScript(basicPort))
			dnfOutput := runDocker(ctx, t, compatImage("SOW_COMPAT_DNF_IMAGE", defaultDNFImage),
				dnfKeyMounts(publicKey, upstreamRPMKey), dnfBasicScript(basicPort, "yum-test", "el10", "x86_64"))
			writeFile(t, filepath.Join(work, "basic-fallback-clients.log"), []byte(aptOutput+"\n"+dnfOutput), 0o600)
			if !basicRequests.contains("/pro/v1/basic/apt/test/dists/jammy/InRelease") ||
				!basicRequests.contains("/pro/v1/basic/_sow/v1/mirrorlist/stable/yum-test/el10/x86_64.txt") ||
				!basicRequests.contains("/pro/v1/basic/_sow/v1/g/"+stableGeneration+"/yum/test/x86_64/repodata/repomd.xml") ||
				!basicRequests.contains("/pro/v1/basic/_sow/v1/g/"+stableGeneration+"/yum/test/x86_64/repodata/repomd.xml.asc") {
				t.Fatalf("Basic fallback clients did not consume both package protocols:\n%s", basicRequests.String())
			}
			client := &http.Client{Timeout: 5 * time.Second}
			for _, test := range []struct {
				path string
				auth bool
				want int
			}{
				{path: "/apt/test/dists/jammy/InRelease", want: http.StatusNotFound},
				{path: "/pro/v1/basic/apt/test/dists/jammy/InRelease", want: http.StatusUnauthorized},
				{path: "/pro/v1/basic/apt/test/dists/jammy/InRelease", auth: true, want: http.StatusOK},
			} {
				request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", basicPort, test.path), nil)
				if test.auth {
					request.SetBasicAuth("verifier", "verify-secret")
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if response.StatusCode != test.want {
					t.Fatalf("Basic fallback %s auth=%t status=%d want=%d", test.path, test.auth, response.StatusCode, test.want)
				}
				if !strings.Contains(strings.ToLower(response.Header.Get("Server")), "nginx") {
					t.Fatalf("Basic fallback was not served by Nginx: Server=%q", response.Header.Get("Server"))
				}
			}
		})
	}

	t.Run("cloudflare-token-path-apt-and-dnf", func(t *testing.T) {
		token := strings.Repeat("T", 32)
		tokenFile := filepath.Join(work, "edge-client-token")
		writeFile(t, tokenFile, []byte(token), 0o600)
		contractPath := filepath.Join(work, "edge-client-contract.json")
		contract := runCLI(ctx, t, moduleRoot, cliPath, "materialize", "latest", "--config", configPath, "--edge-contract", "cf", "--workers", "2", "--chunk-entries", "2")
		writeFile(t, contractPath, []byte(contract), 0o600)
		edgePort, evidencePath, stopEdge := startCloudflareEdgeClientServer(ctx, t, moduleRoot, stableServingRoot, contractPath, token)
		defer stopEdge()
		tokenMount := []string{"-v", tokenFile + ":/run/secrets/sow-pro-token:ro"}
		aptMounts := append([]string{"-v", publicKey + ":/etc/apt/keyrings/sow-compat.gpg:ro"}, tokenMount...)
		aptOutput := runDockerRedacted(ctx, t, compatImage("SOW_COMPAT_APT_IMAGE", defaultAPTImage), aptMounts, aptTokenScript(edgePort), token)
		dnfMounts := append(dnfKeyMounts(publicKey, upstreamRPMKey), tokenMount...)
		dnfOutput := runDockerRedacted(ctx, t, compatImage("SOW_COMPAT_DNF_IMAGE", defaultDNFImage), dnfMounts, dnfTokenScript(edgePort, "yum/test/x86_64"), token)
		writeFile(t, filepath.Join(work, "edge-token-path-clients.log"), []byte(aptOutput+"\n"+dnfOutput), 0o600)

		probe, err := http.NewRequest(http.MethodHead, fmt.Sprintf("http://127.0.0.1:%d/pro/v1/%s/apt/test/dists/jammy/InRelease", edgePort, token), nil)
		if err != nil {
			t.Fatal("construct valid edge probe")
		}
		response, err := (&http.Client{Timeout: 5 * time.Second}).Do(probe)
		if err != nil {
			t.Fatalf("valid edge probe failed: %s", strings.ReplaceAll(err.Error(), token, "<redacted>"))
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || !strings.Contains(response.Header.Get("Cache-Control"), "private") || response.Header.Get("X-SOW-Edge-Contract") != "sow-edge-runtime/v2" {
			t.Fatalf("valid edge probe status=%d cache=%q contract=%q", response.StatusCode, response.Header.Get("Cache-Control"), response.Header.Get("X-SOW-Edge-Contract"))
		}

		evidence, err := os.ReadFile(evidencePath)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(evidence, []byte(token)) || strings.Contains(aptOutput, token) || strings.Contains(dnfOutput, token) {
			t.Fatal("edge client token escaped redaction or reached persisted evidence")
		}
		tokenDigest := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
		for _, required := range []string{
			`"credential_sha256":"` + tokenDigest + `"`,
			`"clean_path":"/apt/test/dists/jammy/InRelease"`,
			`"clean_path":"/apt/test/pool/main/s/sow-compat-deb/sow-compat-deb_1.2.3-1_amd64.deb"`,
			`"clean_path":"/yum/test/x86_64/repodata/repomd.xml"`,
			`"clean_path":"/yum/test/x86_64/repodata/repomd.xml.asc"`,
			`"clean_path":"/yum/test/x86_64/Packages/p/pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm"`,
		} {
			if !bytes.Contains(evidence, []byte(required)) {
				t.Fatalf("edge client evidence omitted %s", required)
			}
		}
		if bytes.Contains(evidence, []byte(`"key":"pro/`)) || bytes.Contains(evidence, []byte(`"key":"`+tokenDigest)) {
			t.Fatal("edge origin evidence retained a credential namespace")
		}
	})

	t.Run("dnf-package-key-required", func(t *testing.T) {
		output := runDocker(ctx, t, compatImage("SOW_COMPAT_DNF_IMAGE", defaultDNFImage),
			[]string{"-v", publicKey + ":/etc/pki/rpm-gpg/SOW-COMPAT:ro"},
			dnfMissingPackageKeyScript(port, "yum/test/x86_64"),
		)
		writeFile(t, filepath.Join(work, "dnf-package-key-required.log"), []byte(output), 0o600)
	})

	t.Run("dnf", func(t *testing.T) {
		requests.reset()
		output := runDocker(ctx, t, compatImage("SOW_COMPAT_DNF_IMAGE", defaultDNFImage),
			dnfKeyMounts(publicKey, upstreamRPMKey),
			dnfScript(port, "yum/test/x86_64"),
		)
		writeFile(t, filepath.Join(work, "dnf-client.log"), []byte(output), 0o600)
		t.Logf("dnf repository requests:\n%s", requests.String())
		if !requests.contains("/yum/test/x86_64/repodata/repomd.xml.asc") {
			t.Fatalf("dnf did not retrieve the detached repomd signature; requests:\n%s", requests.String())
		}
		for _, kind := range []string{"-primary.xml.zst", "-filelists.xml.zst", "-other.xml.zst"} {
			if !requests.contains(kind) {
				t.Fatalf("dnf did not consume %s metadata; requests:\n%s", kind, requests.String())
			}
		}
		if !requests.contains("/yum/test/x86_64/Packages/p/pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm") {
			t.Fatalf("dnf did not download the exact noarch RPM payload; requests:\n%s", requests.String())
		}
	})

	t.Run("dnf-generation-pinned-mirrorlist", func(t *testing.T) {
		routeRequests.reset()
		generation := readStaticYUMGeneration(t, servingRoot, "latest", "yum-test", "el10", "x86_64")
		output := runDocker(ctx, t, compatImage("SOW_COMPAT_DNF_IMAGE", defaultDNFImage),
			dnfKeyMounts(publicKey, upstreamRPMKey),
			dnfMirrorlistScript(routePort, "yum-test", "el10", "x86_64"),
		)
		writeFile(t, filepath.Join(work, "dnf-generation-pinned-client.log"), []byte(output), 0o600)
		t.Logf("generation-pinned dnf repository requests:\n%s", routeRequests.String())
		for _, required := range []string{
			"/_sow/v1/mirrorlist/latest/yum-test/el10/x86_64.txt",
			"/_sow/v1/g/" + generation + "/yum/test/x86_64/repodata/repomd.xml",
			"/_sow/v1/g/" + generation + "/yum/test/x86_64/repodata/repomd.xml.asc",
			"-primary.xml.zst", "-filelists.xml.zst", "-other.xml.zst",
			"/_sow/v1/g/" + generation + "/yum/test/x86_64/Packages/p/pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm",
		} {
			if !routeRequests.contains(required) {
				t.Fatalf("generation-pinned dnf did not consume %s; requests:\n%s", required, routeRequests.String())
			}
		}
	})

	t.Run("dnf-el9-zstd", func(t *testing.T) {
		requests.reset()
		output := runDocker(ctx, t, compatImage("SOW_COMPAT_EL9_IMAGE", defaultEL9Image),
			dnfKeyMounts(publicKey, upstreamRPMKey),
			dnfScript(port, "yum/el9/x86_64"),
		)
		writeFile(t, filepath.Join(work, "dnf-el9-client.log"), []byte(output), 0o600)
		for _, kind := range []string{"-primary.xml.zst", "-filelists.xml.zst", "-other.xml.zst"} {
			if !requests.contains(kind) {
				t.Fatalf("EL9 dnf did not consume %s metadata; requests:\n%s", kind, requests.String())
			}
		}
	})

	t.Run("dnf-el8-gzip", func(t *testing.T) {
		requests.reset()
		output := runDocker(ctx, t, compatImage("SOW_COMPAT_EL8_IMAGE", defaultEL8Image),
			dnfKeyMounts(publicKey, upstreamRPMKey),
			dnfScript(port, "yum/el8/x86_64"),
		)
		writeFile(t, filepath.Join(work, "dnf-el8-client.log"), []byte(output), 0o600)
		t.Logf("EL8 dnf repository requests:\n%s", requests.String())
		if !requests.contains("/yum/el8/x86_64/repodata/repomd.xml.asc") {
			t.Fatalf("EL8 dnf did not retrieve the detached repomd signature; requests:\n%s", requests.String())
		}
		for _, kind := range []string{"-primary.xml.gz", "-filelists.xml.gz", "-other.xml.gz"} {
			if !requests.contains(kind) {
				t.Fatalf("EL8 dnf did not consume %s metadata; requests:\n%s", kind, requests.String())
			}
		}
		if !requests.contains("/yum/el8/x86_64/Packages/p/pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm") {
			t.Fatalf("EL8 dnf did not download the exact RPM payload; requests:\n%s", requests.String())
		}
	})

	t.Run("yum-el7-frozen-gzip", func(t *testing.T) {
		requests.reset()
		output := runDocker(ctx, t, compatImage("SOW_COMPAT_EL7_IMAGE", defaultEL7Image),
			yumEL7KeyMounts(armoredPublicKey, centos7RPMKey),
			yumEL7Script(port, "yum/el7/x86_64"),
		)
		writeFile(t, filepath.Join(work, "yum-el7-client.log"), []byte(output), 0o600)
		t.Logf("EL7 yum repository requests:\n%s", requests.String())
		if !requests.contains("/yum/el7/x86_64/repodata/repomd.xml.asc") {
			t.Fatalf("EL7 yum did not retrieve the detached repomd signature; requests:\n%s", requests.String())
		}
		for _, kind := range []string{"-primary.xml.gz", "-filelists.xml.gz", "-other.xml.gz"} {
			if !requests.contains(kind) {
				t.Fatalf("EL7 yum did not consume %s metadata; requests:\n%s", kind, requests.String())
			}
		}
		if !requests.contains("/yum/el7/x86_64/Packages/c/centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm") {
			t.Fatalf("EL7 yum did not download the exact RPM payload; requests:\n%s", requests.String())
		}
	})

	t.Run("dnf-generation-flip-keeps-inflight-client-pinned", func(t *testing.T) {
		firstGeneration := readStaticYUMGeneration(t, servingRoot, "latest", "yum-test", "el10", "x86_64")
		routeRequests.reset()
		reached, release, err := routeRequests.installGate("/_sow/v1/g/" + firstGeneration + "/")
		if err != nil {
			t.Fatal(err)
		}
		released := false
		releaseOnce := func() {
			if !released {
				released = true
				release()
			}
		}
		defer releaseOnce()
		client := startDockerCompatibility(ctx, compatImage("SOW_COMPAT_DNF_IMAGE", defaultDNFImage),
			dnfKeyMounts(publicKey, upstreamRPMKey),
			dnfMirrorlistInFlightScript(routePort, "yum-test", "el10", "x86_64"))
		select {
		case <-reached:
		case result := <-client:
			releaseOnce()
			t.Fatalf("generation-pinned DNF exited before its immutable request was gated: %v\n%s", result.err, result.output)
		case <-time.After(90 * time.Second):
			releaseOnce()
			t.Fatal("generation-pinned DNF did not reach its immutable generation before timeout")
		}

		runCLI(ctx, t, moduleRoot, cliPath, "rm", "--view", "latest", "--config", configPath, "--repo", "yum-test", "--gpg-private-key-file", privateKey, rpmPackage)
		runCLI(ctx, t, moduleRoot, cliPath, "materialize", "latest", "--config", configPath, "--repo", "yum-test", "--gpg-private-key-file", privateKey, "--workers", "2", "--chunk-entries", "2")
		secondGeneration := readStaticYUMGeneration(t, servingRoot, "latest", "yum-test", "el10", "x86_64")
		if secondGeneration == firstGeneration {
			releaseOnce()
			t.Fatal("YUM mirrorlist did not advance after the selected package was removed")
		}
		releaseOnce()
		select {
		case result := <-client:
			t.Logf("in-flight generation-pinned dnf:\n%s", result.output)
			if result.err != nil {
				t.Fatalf("in-flight generation-pinned DNF failed after the flip: %v\n%s", result.err, result.output)
			}
		case <-time.After(90 * time.Second):
			t.Fatal("in-flight generation-pinned DNF did not finish after release")
		}
		mirrorlistPath := "/_sow/v1/mirrorlist/latest/yum-test/el10/x86_64.txt"
		firstRoot := "/_sow/v1/g/" + firstGeneration + "/yum/test/x86_64/"
		secondRoot := "/_sow/v1/g/" + secondGeneration + "/yum/test/x86_64/"
		secondPayload := secondRoot + "Packages/p/" + rpmPackage + "-" + rpmVersionArch + ".rpm"
		inFlightEntries := routeRequests.snapshot()
		inFlightRequests := routeRequests.String()
		t.Logf("in-flight generation requests first=%s second=%s:\n%s", firstGeneration, secondGeneration, inFlightRequests)
		for _, required := range []string{
			"GET " + mirrorlistPath + " 200",
			"GET " + firstRoot + "repodata/repomd.xml 200",
			"GET " + firstRoot + "repodata/repomd.xml.asc 200",
			"GET " + secondPayload + " 200",
		} {
			if !strings.Contains(inFlightRequests, required) {
				t.Fatalf("in-flight DNF omitted required request %q first=%s second=%s requests:\n%s", required, firstGeneration, secondGeneration, inFlightRequests)
			}
		}
		firstPrimary := false
		for _, entry := range inFlightEntries {
			if strings.Contains(entry, firstRoot+"repodata/") && strings.Contains(entry, "-primary.xml.zst 200") {
				firstPrimary = true
			}
			if strings.Contains(entry, "/_sow/v1/g/") && strings.Contains(entry, "/repodata/") && !strings.Contains(entry, firstRoot+"repodata/") {
				t.Fatalf("in-flight DNF mixed metadata generations first=%s second=%s request=%q requests:\n%s", firstGeneration, secondGeneration, entry, inFlightRequests)
			}
			if strings.Contains(entry, secondPayload) && entry != "GET "+secondPayload+" 200" {
				t.Fatalf("in-flight DNF could not retrieve the cross-generation payload closure request=%q requests:\n%s", entry, inFlightRequests)
			}
		}
		if !firstPrimary {
			t.Fatalf("in-flight DNF omitted G1 primary metadata first=%s requests:\n%s", firstGeneration, inFlightRequests)
		}

		routeRequests.reset()
		output := runDocker(ctx, t, compatImage("SOW_COMPAT_DNF_IMAGE", defaultDNFImage),
			dnfKeyMounts(publicKey, upstreamRPMKey),
			dnfEmptyMirrorlistScript(routePort, "yum-test", "el10", "x86_64"))
		t.Logf("fresh post-flip generation-pinned dnf:\n%s", output)
		freshEntries := routeRequests.snapshot()
		freshRequests := routeRequests.String()
		for _, required := range []string{
			"GET " + mirrorlistPath + " 200",
			"GET " + secondRoot + "repodata/repomd.xml 200",
			"GET " + secondRoot + "repodata/repomd.xml.asc 200",
		} {
			if !strings.Contains(freshRequests, required) {
				t.Fatalf("fresh DNF omitted required G2 request %q first=%s second=%s requests:\n%s", required, firstGeneration, secondGeneration, freshRequests)
			}
		}
		secondPrimary := false
		for _, entry := range freshEntries {
			if strings.Contains(entry, secondRoot+"repodata/") && strings.Contains(entry, "-primary.xml.zst 200") {
				secondPrimary = true
			}
			if strings.Contains(entry, "/_sow/v1/g/") && strings.Contains(entry, "/repodata/") && !strings.Contains(entry, secondRoot+"repodata/") {
				t.Fatalf("fresh DNF mixed metadata generations first=%s second=%s request=%q requests:\n%s", firstGeneration, secondGeneration, entry, freshRequests)
			}
			if strings.Contains(entry, "/Packages/") {
				t.Fatalf("fresh G2 empty index unexpectedly requested a payload request=%q requests:\n%s", entry, freshRequests)
			}
		}
		if !secondPrimary {
			t.Fatalf("fresh DNF omitted G2 primary metadata second=%s requests:\n%s", secondGeneration, freshRequests)
		}
	})

	writeFile(t, filepath.Join(work, "http-requests.log"), []byte(requests.String()), 0o600)
}

func compatImage(environment, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(environment)); value != "" {
		return value
	}
	return fallback
}

func findModuleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve compatibility test source path")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func buildCLI(ctx context.Context, t *testing.T, moduleRoot, work string) string {
	t.Helper()
	output := filepath.Join(work, "sow")
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", output, "./cmd/sow")
	command.Dir = moduleRoot
	combined, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build production CLI: %v\n%s", err, combined)
	}
	return output
}

func runCLI(ctx context.Context, t *testing.T, moduleRoot, executable string, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir = moduleRoot
	started := time.Now()
	output, err := command.CombinedOutput()
	elapsed := time.Since(started)
	t.Logf("sow %s elapsed=%s\n%s", strings.Join(arguments, " "), elapsed, output)
	if len(arguments) != 0 && arguments[0] == "add" && elapsed >= time.Minute {
		t.Fatalf("single-command add exceeded the PRD one-minute assumption: %s", elapsed)
	}
	if err != nil {
		t.Fatalf("sow %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
	return string(output)
}

func writeSigningKey(t *testing.T, root string) (string, string) {
	t.Helper()
	created := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	randomizedNotation := false
	keyConfig := &packet.Config{
		Time:                                  func() time.Time { return created },
		RSABits:                               2048,
		DefaultHash:                           crypto.SHA256,
		NonDeterministicSignaturesViaNotation: &randomizedNotation,
		InsecureGenerateNonCriticalKeyFlags:   true,
		InsecureGenerateNonCriticalSignatureCreationTime: true,
	}
	entity, err := openpgp.NewEntity("SOW Docker compatibility", "", "compat@example.invalid", keyConfig)
	if err != nil {
		t.Fatal(err)
	}
	var private, public, armoredPublic bytes.Buffer
	if err := entity.SerializePrivate(&private, keyConfig); err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	armoredWriter, err := armor.Encode(&armoredPublic, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	serializeErr := entity.Serialize(armoredWriter)
	closeErr := armoredWriter.Close()
	if serializeErr != nil || closeErr != nil {
		t.Fatal(errors.Join(serializeErr, closeErr))
	}
	privatePath := filepath.Join(root, "signing-private.gpg")
	publicPath := filepath.Join(root, "signing-public.gpg")
	armoredPublicPath := filepath.Join(root, "signing-public.asc")
	writeFile(t, privatePath, private.Bytes(), 0o600)
	writeFile(t, publicPath, public.Bytes(), 0o644)
	writeFile(t, armoredPublicPath, armoredPublic.Bytes(), 0o644)
	return privatePath, publicPath
}

func writeInstallableDEB(t *testing.T, root, version string) string {
	t.Helper()
	control := []byte("Package: " + debPackage + "\n" +
		"Version: " + version + "\n" +
		"Architecture: amd64\n" +
		"Maintainer: SOW Test <compat@example.invalid>\n" +
		"Installed-Size: 1\n" +
		"Section: misc\n" +
		"Priority: optional\n" +
		"Description: SOW apt client compatibility fixture\n")
	controlTar := tarGzip(t, map[string][]byte{"control": control})
	dataTar := tarGzip(t, map[string][]byte{"usr/share/doc/sow-compat/README": []byte("installed version " + version + " by sow compatibility test\n")})
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	writeArMember(t, &archive, "debian-binary", []byte("2.0\n"))
	writeArMember(t, &archive, "control.tar.gz", controlTar)
	writeArMember(t, &archive, "data.tar.gz", dataTar)
	path := filepath.Join(root, "sow-compat-deb_"+version+"_amd64.deb")
	writeFile(t, path, archive.Bytes(), 0o644)
	return path
}

func tarGzip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tw := tar.NewWriter(gz)
	directories := make(map[string]struct{})
	var names []string
	for name := range files {
		names = append(names, name)
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			directories[parent] = struct{}{}
		}
	}
	var directoryNames []string
	for name := range directories {
		directoryNames = append(directoryNames, name)
	}
	sort.Strings(directoryNames)
	for _, name := range directoryNames {
		header := &tar.Header{Name: name + "/", Mode: 0o755, Typeflag: tar.TypeDir}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		body := files[name]
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func writeArMember(t *testing.T, output *bytes.Buffer, name string, body []byte) {
	t.Helper()
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name+"/", 0, 0, 0, 0o644, len(body))
	if len(header) != 60 {
		t.Fatalf("invalid ar header length %d", len(header))
	}
	output.WriteString(header)
	output.Write(body)
	if len(body)%2 != 0 {
		output.WriteByte('\n')
	}
}

func decodeBase64Fixture(t *testing.T, source, destination string) string {
	t.Helper()
	encoded, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, destination, decoded, 0o644)
	return destination
}

func copyRPMHistoryFixtures(t *testing.T, moduleRoot, destinationRoot string) []string {
	t.Helper()
	// The RPM parser dependency ships several tiny, valid historical RPMs as
	// testdata. Resolve its module directory through the Go tool already needed
	// to build this opt-in compatibility test, then copy two versions of the same
	// NEVRA family into the disposable test workspace. The production CLI never
	// invokes go, rpmbuild, or another RPM tool.
	command := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/cavaliergopher/rpm")
	command.Dir = moduleRoot
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("locate RPM history fixtures: %v\n%s", err, output)
	}
	moduleDir := strings.TrimSpace(string(output))
	if moduleDir == "" {
		t.Fatal("locate RPM history fixtures: empty module directory")
	}
	var destinations []string
	for _, name := range []string{
		"centos-release-4-0.1.x86_64.rpm",
		"centos-release-5-0.0.el5.centos.2.x86_64.rpm",
	} {
		body, err := os.ReadFile(filepath.Join(moduleDir, "testdata", name))
		if err != nil {
			t.Fatalf("read RPM history fixture %s: %v", name, err)
		}
		destination := filepath.Join(destinationRoot, name)
		writeFile(t, destination, body, 0o644)
		destinations = append(destinations, destination)
	}
	return destinations
}

func writeCompatRPMPackageKeyring(t *testing.T, moduleRoot, repositoryRoot, pgdgKey string) string {
	t.Helper()
	keyFiles := []string{
		pgdgKey,
		filepath.Join(moduleRoot, "third_party", "cavaliergopher-rpm", "testdata", "RPM-GPG-KEY-CentOS-4"),
		filepath.Join(moduleRoot, "third_party", "cavaliergopher-rpm", "testdata", "RPM-GPG-KEY-CentOS-5"),
		filepath.Join(moduleRoot, "third_party", "cavaliergopher-rpm", "testdata", "RPM-GPG-KEY-CentOS-7"),
	}
	var bundle bytes.Buffer
	for _, filename := range keyFiles {
		body, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(body))
		if err != nil || len(entities) == 0 {
			t.Fatalf("parse package trust key %s: entities=%d err=%v", filename, len(entities), err)
		}
		for _, entity := range entities {
			if err := entity.Serialize(&bundle); err != nil {
				t.Fatal(err)
			}
		}
	}
	filename := filepath.Join(repositoryRoot, "package-trust.gpg")
	writeFile(t, filename, bundle.Bytes(), 0o644)
	return filename
}

func generateFrozenYUMRepository(t *testing.T, privateKeyPath, rpmSource, root string, elMajor int) {
	t.Helper()
	packageFilename := filepath.Base(rpmSource)
	if packageFilename == "." || packageFilename == string(filepath.Separator) || packageFilename == "" {
		t.Fatal("frozen YUM fixture has no package filename")
	}
	packagePath := filepath.Join(root, "Packages", strings.ToLower(packageFilename[:1]), packageFilename)
	if err := os.MkdirAll(filepath.Dir(packagePath), 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(rpmSource)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, packagePath, body, 0o644)
	key, err := os.Open(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	signingTime := time.Now().UTC().Truncate(time.Second)
	signer, signerErr := yumrepo.NewOpenPGPSigner(key, nil, signingTime)
	closeErr := key.Close()
	if signerErr != nil || closeErr != nil {
		t.Fatal(errors.Join(signerErr, closeErr))
	}
	generation, err := yumrepo.Generate(context.Background(), filepath.Join(root, "repodata"), yumrepo.Options{
		ELMajor: elMajor, Frozen: true, Compression: yumrepo.CompressionGzip,
		Revision: signingTime.Unix(), Signer: signer,
	}, &yumrepo.SliceIterator{Inputs: []yumrepo.PackageInput{{Path: packagePath, FileTime: signingTime}}})
	if err != nil {
		t.Fatal(err)
	}
	if generation.Packages != 1 {
		t.Fatalf("legacy EL%d fixture packages=%d", elMajor, generation.Packages)
	}
	for _, artifact := range generation.Artifacts {
		if artifact.Compression != yumrepo.CompressionGzip || !strings.HasSuffix(artifact.Path, ".gz") {
			t.Fatalf("legacy EL%d fixture emitted non-gzip metadata: %+v", elMajor, artifact)
		}
	}
}

func assertGeneratedRepository(t *testing.T, root string) {
	t.Helper()
	required := []string{
		"apt/test/dists/jammy/main/binary-amd64/Packages",
		"apt/test/dists/jammy/Release",
		"apt/test/dists/jammy/InRelease",
		"yum/test/x86_64/repodata/repomd.xml",
		"yum/test/x86_64/repodata/repomd.xml.asc",
	}
	for _, relative := range required {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			t.Fatalf("required repository artifact %s is absent or empty: %v", relative, err)
		}
	}
	byHash, err := filepath.Glob(filepath.Join(root, "apt", "test", "dists", "jammy", "main", "binary-amd64", "by-hash", "SHA256", "*"))
	if err != nil || len(byHash) < 3 {
		t.Fatalf("APT by-hash closure has %d objects: %v", len(byHash), err)
	}
	for _, kind := range []string{"primary", "filelists", "other"} {
		matches, err := filepath.Glob(filepath.Join(root, "yum", "test", "x86_64", "repodata", "*-"+kind+".xml.zst"))
		if err != nil || len(matches) != 1 {
			t.Fatalf("YUM %s zstd metadata matches=%d err=%v", kind, len(matches), err)
		}
	}
}

func readStaticYUMGeneration(t *testing.T, root, view, repo, osName, arch string) string {
	t.Helper()
	relative := path.Join("_sow/v1/mirrorlist", view, repo, osName, arch+".txt")
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatalf("read product-generated YUM mirrorlist %s: %v", relative, err)
	}
	parsed, err := url.Parse(strings.TrimSpace(string(body)))
	if err != nil || !parsed.IsAbs() || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		t.Fatalf("product-generated YUM mirrorlist is not one clean absolute URL: %q err=%v", body, err)
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for index := range parts {
		if parts[index] == "g" && index+1 < len(parts) && len(parts[index+1]) == 20 {
			for _, character := range parts[index+1] {
				if character < '0' || character > '9' {
					t.Fatalf("product-generated YUM generation is not decimal: %q", parts[index+1])
				}
			}
			return parts[index+1]
		}
	}
	t.Fatalf("product-generated YUM mirrorlist has no generation coordinate: %q", body)
	return ""
}

func assertGeneratedFrozenYUMRepository(t *testing.T, root, osName, packageFilename string) {
	t.Helper()
	base := filepath.Join(root, "yum", osName, "x86_64")
	packageRelative := path.Join("Packages", strings.ToLower(packageFilename[:1]), packageFilename)
	for _, relative := range []string{"repodata/repomd.xml", "repodata/repomd.xml.asc", packageRelative} {
		info, err := os.Stat(filepath.Join(base, filepath.FromSlash(relative)))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			t.Fatalf("required %s repository artifact %s is absent or empty: %v", osName, relative, err)
		}
	}
	for _, kind := range []string{"primary", "filelists", "other"} {
		matches, err := filepath.Glob(filepath.Join(base, "repodata", "*-"+kind+".xml.gz"))
		if err != nil || len(matches) != 1 {
			t.Fatalf("%s YUM %s gzip metadata matches=%d err=%v", osName, kind, len(matches), err)
		}
	}
}

func assertGeneratedAPTStableHistory(t *testing.T, root string) {
	t.Helper()
	packagesPath := filepath.Join(root, "apt", "test", "dists", "jammy", "main", "binary-amd64", "Packages")
	packages, err := os.ReadFile(packagesPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{debVersion, newDebVersion} {
		if !bytes.Contains(packages, []byte("Version: "+version+"\n")) {
			t.Fatalf("stable Packages omitted historical version %s", version)
		}
		payload := filepath.Join(root, "apt", "test", "pool", "main", "s", debPackage, debPackage+"_"+version+"_amd64.deb")
		if info, err := os.Stat(payload); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			t.Fatalf("stable historical payload %s missing: %v", version, err)
		}
	}
}

func assertGeneratedAPTSnapshotHistory(t *testing.T, root, snapshotID string) {
	t.Helper()
	packagesPath := filepath.Join(root, "apt", "test", "dists", snapshotID, "main", "binary-amd64", "Packages")
	packages, err := os.ReadFile(packagesPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{debVersion, newDebVersion} {
		if !bytes.Contains(packages, []byte("Version: "+version+"\n")) {
			t.Fatalf("snapshot Packages omitted historical version %s", version)
		}
	}
	for _, relative := range []string{
		filepath.Join("apt", "test", "dists", snapshotID, "InRelease"),
		filepath.Join("apt", "test", "dists", snapshotID, "Release.gpg"),
	} {
		if info, err := os.Stat(filepath.Join(root, relative)); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			t.Fatalf("snapshot artifact %s is absent or empty: %v", relative, err)
		}
	}
	byHash, err := filepath.Glob(filepath.Join(root, "apt", "test", "dists", snapshotID, "main", "binary-amd64", "by-hash", "SHA256", "*"))
	if err != nil || len(byHash) < 3 {
		t.Fatalf("snapshot APT by-hash closure has %d objects: %v", len(byHash), err)
	}
}

type requestLog struct {
	mu      sync.Mutex
	entries []string
	file    string
	gate    *requestGate
}

type requestGate struct {
	prefix      string
	reached     chan struct{}
	release     chan struct{}
	reachedOnce sync.Once
	releaseOnce sync.Once
}

func (log *requestLog) append(entry string) {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.entries = append(log.entries, entry)
}

func (log *requestLog) contains(fragment string) bool {
	for _, entry := range log.snapshot() {
		if strings.Contains(entry, fragment) {
			return true
		}
	}
	return false
}

func (log *requestLog) reset() {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.entries = nil
	if log.file != "" {
		_ = os.WriteFile(log.file, nil, 0o600)
	}
}

func (log *requestLog) String() string {
	return strings.Join(log.snapshot(), "\n") + "\n"
}

func (log *requestLog) snapshot() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	result := append([]string(nil), log.entries...)
	if log.file != "" {
		body, err := os.ReadFile(log.file)
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
				if line != "" {
					result = append(result, line)
				}
			}
		}
	}
	return result
}

func (log *requestLog) installGate(prefix string) (<-chan struct{}, func(), error) {
	if prefix == "" || !strings.HasPrefix(prefix, "/") {
		return nil, nil, errors.New("request gate requires one absolute path prefix")
	}
	gate := &requestGate{prefix: prefix, reached: make(chan struct{}), release: make(chan struct{})}
	log.mu.Lock()
	defer log.mu.Unlock()
	if log.gate != nil {
		return nil, nil, errors.New("request gate is already installed")
	}
	log.gate = gate
	release := func() {
		gate.releaseOnce.Do(func() { close(gate.release) })
		log.mu.Lock()
		if log.gate == gate {
			log.gate = nil
		}
		log.mu.Unlock()
	}
	return gate.reached, release, nil
}

func (log *requestLog) waitAtGate(requestPath string) {
	log.mu.Lock()
	gate := log.gate
	matched := gate != nil && strings.HasPrefix(requestPath, gate.prefix)
	log.mu.Unlock()
	if !matched {
		return
	}
	gate.reachedOnce.Do(func() { close(gate.reached) })
	<-gate.release
}

type responseStatus struct {
	http.ResponseWriter
	status int
}

func (writer *responseStatus) WriteHeader(status int) {
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *responseStatus) Write(body []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	return writer.ResponseWriter.Write(body)
}

type nginxRepositoryAllowlist struct {
	ExactFiles      []string
	Prefixes        []string
	GenerationRoots []string
	Aliases         []nginxAliasRoute
}

type nginxAliasRoute struct {
	URL    string
	Source string
	Prefix bool
}

func latestNginxAllowlist() nginxRepositoryAllowlist {
	return nginxRepositoryAllowlist{
		ExactFiles: []string{
			"signing-public.gpg",
			"_sow/v1/mirrorlist/latest/yum-test/el10/x86_64.txt",
			"_sow/v1/mirrorlist/latest/yum-el9/el9/x86_64.txt",
			"_sow/v1/mirrorlist/latest/yum-el8/el8/x86_64.txt",
			"_sow/v1/mirrorlist/latest/yum-el7/el7/x86_64.txt",
		},
		Prefixes: []string{
			"apt/test",
			"yum/test/x86_64",
			"yum/el9/x86_64",
			"yum/el8/x86_64",
			"yum/el7/x86_64",
		},
		GenerationRoots: []string{
			"yum/test/x86_64",
			"yum/el9/x86_64",
			"yum/el8/x86_64",
			"yum/el7/x86_64",
		},
	}
}

func stableNginxAllowlist() nginxRepositoryAllowlist {
	return nginxRepositoryAllowlist{
		ExactFiles: []string{
			"_sow/v1/mirrorlist/stable/yum-test/el10/x86_64.txt",
		},
		Prefixes:        []string{"apt/test", "yum/test/x86_64"},
		GenerationRoots: []string{"yum/test/x86_64"},
	}
}

func serveRepository(t *testing.T, root string, allowlist nginxRepositoryAllowlist) (*requestLog, int, func()) {
	t.Helper()
	if os.Getenv("SOW_COMPAT_NGINX") == "1" {
		return serveRepositoryNginx(t, root, allowlist)
	}
	return serveRepositoryHTTP(t, root)
}

// serveRepositoryHTTP exposes the exact static tree without synthesizing or
// rewriting generation routes. It is used for the product-generated YUM
// mirrorlist path even when the raw compatibility tree is tested through
// Nginx, and its request gate supports a real in-flight generation flip.
func serveRepositoryHTTP(t *testing.T, root string) (*requestLog, int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	log := &requestLog{}
	files := http.FileServer(http.Dir(root))
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		log.waitAtGate(request.URL.EscapedPath())
		status := &responseStatus{ResponseWriter: writer}
		files.ServeHTTP(status, request)
		if status.status == 0 {
			status.status = http.StatusOK
		}
		log.append(fmt.Sprintf("%s %s %d", request.Method, request.URL.EscapedPath(), status.status))
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		_ = server.Serve(listener)
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}
	return log, port, stop
}

func renderNginxAllowlist(t *testing.T, root, urlBase string, allowlist nginxRepositoryAllowlist, authFile string) string {
	t.Helper()
	if urlBase != "" && urlBase != "/pro/v1/basic" {
		t.Fatalf("unsupported Nginx compatibility URL base %q", urlBase)
	}
	if (authFile == "") != (urlBase == "") {
		t.Fatalf("Nginx compatibility auth and URL base must be enabled together")
	}

	exact := append([]string(nil), allowlist.ExactFiles...)
	prefixes := append([]string(nil), allowlist.Prefixes...)
	generationRoots := append([]string(nil), allowlist.GenerationRoots...)
	aliases := append([]nginxAliasRoute(nil), allowlist.Aliases...)
	sort.Strings(exact)
	sort.Strings(prefixes)
	sort.Strings(generationRoots)
	sort.Slice(aliases, func(i, j int) bool {
		if aliases[i].URL == aliases[j].URL {
			return aliases[i].Source < aliases[j].Source
		}
		return aliases[i].URL < aliases[j].URL
	})

	owned := make(map[string]string)
	claim := func(route, kind string) {
		if previous, exists := owned[route]; exists {
			t.Fatalf("Nginx compatibility route %q is claimed by both %s and %s", route, previous, kind)
		}
		owned[route] = kind
	}
	for _, route := range exact {
		validateNginxCompatibilityRoute(t, route)
		claim(route, "exact")
	}
	for _, route := range prefixes {
		validateNginxCompatibilityRoute(t, route)
		claim(route, "prefix")
	}
	for _, route := range generationRoots {
		validateNginxCompatibilityRoute(t, route)
	}
	for _, route := range aliases {
		validateNginxCompatibilityRoute(t, route.URL)
		validateNginxCompatibilityRoute(t, route.Source)
		claim(route.URL, "alias")
	}

	var locations strings.Builder
	writeAuth := func() {
		if authFile == "" {
			return
		}
		fmt.Fprintf(&locations, "      auth_basic \"SOW Pro repository\";\n      auth_basic_user_file %s;\n", nginxQuoted(authFile))
	}
	writeCacheControl := func() {
		if authFile != "" {
			locations.WriteString("      add_header Cache-Control \"private, no-store\" always;\n")
		}
	}
	writeExact := func(route, source string, forceAlias bool) {
		fmt.Fprintf(&locations, "    location = %s/%s {\n", urlBase, route)
		if authFile == "" && !forceAlias {
			locations.WriteString("      try_files $uri =404;\n")
		} else {
			writeAuth()
			fmt.Fprintf(&locations, "      alias %s;\n", nginxQuoted(filepath.Join(root, filepath.FromSlash(source))))
			writeCacheControl()
		}
		locations.WriteString("    }\n")
	}
	writePrefix := func(route, source string, forceAlias bool) {
		fmt.Fprintf(&locations, "    location ^~ %s/%s/ {\n", urlBase, route)
		if authFile == "" && !forceAlias {
			locations.WriteString("      try_files $uri =404;\n")
		} else {
			writeAuth()
			fmt.Fprintf(&locations, "      alias %s;\n", nginxQuoted(filepath.Join(root, filepath.FromSlash(source))+string(filepath.Separator)))
			writeCacheControl()
		}
		locations.WriteString("    }\n")
	}

	for _, route := range exact {
		writeExact(route, route, false)
	}
	for _, route := range prefixes {
		writePrefix(route, route, false)
	}
	for _, route := range aliases {
		if route.Prefix {
			writePrefix(route.URL, route.Source, true)
		} else {
			writeExact(route.URL, route.Source, true)
		}
	}
	for _, route := range generationRoots {
		literalRoute := regexp.QuoteMeta(route)
		if authFile == "" {
			fmt.Fprintf(&locations, "    location ~ \"^/_sow/v1/g/[0-9]{20}/%s(?:/|$)\" {\n      try_files $uri =404;\n    }\n", literalRoute)
			continue
		}
		fmt.Fprintf(&locations, "    location ~ \"^%s/_sow/v1/g/([0-9]{20})/%s/(.*)$\" {\n", urlBase, literalRoute)
		writeAuth()
		generationSource := filepath.Join(root, "_sow", "v1", "g", "$1", filepath.FromSlash(route), "$2")
		fmt.Fprintf(&locations, "      alias %s;\n", nginxQuoted(generationSource))
		writeCacheControl()
		locations.WriteString("    }\n")
	}
	return strings.TrimSuffix(locations.String(), "\n")
}

func validateNginxCompatibilityRoute(t *testing.T, route string) {
	t.Helper()
	if route == "" || strings.HasPrefix(route, "/") || path.Clean(route) != route || strings.Contains(route, "//") {
		t.Fatalf("unsafe Nginx compatibility route %q", route)
	}
	for _, character := range route {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._-/", character) {
			continue
		}
		t.Fatalf("unsafe character %q in Nginx compatibility route %q", character, route)
	}
}

func serveRepositoryNginx(t *testing.T, root string, allowlist nginxRepositoryAllowlist) (*requestLog, int, func()) {
	t.Helper()
	executable, err := exec.LookPath("nginx")
	if err != nil {
		t.Fatal("SOW_COMPAT_NGINX=1 requires nginx in PATH")
	}
	reservation, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	prefix := t.TempDir()
	accessLog := filepath.Join(prefix, "access.log")
	configPath := filepath.Join(prefix, "nginx.conf")
	if strings.ContainsAny(root+prefix, "\r\n\x00\"") {
		t.Fatal("nginx compatibility path contains an unsafe character")
	}
	config := fmt.Sprintf(`worker_processes 1;
pid %s;
error_log stderr notice;
events { worker_connections 128; }
http {
  log_format sow '$request_method $uri $status';
  access_log %s sow;
  server {
    listen 0.0.0.0:%d;
    root %s;
%s
    location / { return 404; }
  }
}
`, nginxQuoted(filepath.Join(prefix, "nginx.pid")), nginxQuoted(accessLog), port, nginxQuoted(root),
		renderNginxAllowlist(t, root, "", allowlist, ""))
	writeFile(t, configPath, []byte(config), 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, executable, "-p", prefix, "-c", configPath, "-g", "daemon off;")
	var diagnostics bytes.Buffer
	command.Stdout = &diagnostics
	command.Stderr = &diagnostics
	if err := command.Start(); err != nil {
		cancel()
		t.Fatalf("start nginx: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, dialErr := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		select {
		case waitErr := <-done:
			cancel()
			t.Fatalf("nginx exited before readiness: %v\n%s", waitErr, diagnostics.String())
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("nginx readiness timeout\n%s", diagnostics.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	assertNginxControlPathsDenied(t, root, port)
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			if command.Process != nil {
				_ = command.Process.Kill()
			}
		}
	}
	return &requestLog{file: accessLog}, port, stop
}

func serveBasicRepositoryNginx(t *testing.T, root string, allowlist nginxRepositoryAllowlist) (*requestLog, int, func()) {
	t.Helper()
	executable, err := exec.LookPath("nginx")
	if err != nil {
		t.Fatal("SOW_COMPAT_NGINX=1 requires nginx in PATH")
	}
	reservation, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	prefix := t.TempDir()
	accessLog := filepath.Join(prefix, "access.log")
	configPath := filepath.Join(prefix, "nginx.conf")
	authPath := filepath.Join(prefix, "sow.htpasswd")
	writeFile(t, authPath, []byte("verifier:{PLAIN}verify-secret\n"), 0o600)
	config := fmt.Sprintf(`worker_processes 1;
pid %s;
error_log stderr notice;
events { worker_connections 128; }
http {
  log_format sow '$request_method $uri $status';
  access_log %s sow;
  server {
    listen 0.0.0.0:%d;
%s
    location / { return 404; }
  }
}
`, nginxQuoted(filepath.Join(prefix, "nginx.pid")), nginxQuoted(accessLog), port,
		renderNginxAllowlist(t, root, "/pro/v1/basic", allowlist, authPath))
	writeFile(t, configPath, []byte(config), 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, executable, "-p", prefix, "-c", configPath, "-g", "daemon off;")
	var diagnostics bytes.Buffer
	command.Stdout = &diagnostics
	command.Stderr = &diagnostics
	if err := command.Start(); err != nil {
		cancel()
		t.Fatalf("start Basic fallback nginx: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, dialErr := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		select {
		case waitErr := <-done:
			cancel()
			t.Fatalf("Basic fallback nginx exited before readiness: %v\n%s", waitErr, diagnostics.String())
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("Basic fallback nginx readiness timeout\n%s", diagnostics.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			if command.Process != nil {
				_ = command.Process.Kill()
			}
		}
	}
	return &requestLog{file: accessLog}, port, stop
}

func assertNginxControlPathsDenied(t *testing.T, root string, port int) {
	t.Helper()
	operatorCanary := "operator-secret.canary"
	writeFile(t, filepath.Join(root, operatorCanary), []byte("non-secret access-control probe\n"), 0o600)
	t.Cleanup(func() { _ = os.Remove(filepath.Join(root, operatorCanary)) })
	existingPoolObject := ".pool/sha256/not-present"
	poolRoot := filepath.Join(root, ".pool", "sha256")
	if _, statErr := os.Stat(poolRoot); statErr == nil {
		existingPoolObject = ""
		err := filepath.WalkDir(poolRoot, func(filename string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if existingPoolObject == "" && entry.Type().IsRegular() {
				relative, relErr := filepath.Rel(root, filename)
				if relErr != nil {
					return relErr
				}
				existingPoolObject = filepath.ToSlash(relative)
			}
			return nil
		})
		if err != nil || existingPoolObject == "" {
			t.Fatalf("locate existing CAS object for Nginx deny test: path=%q err=%v", existingPoolObject, err)
		}
	} else if !os.IsNotExist(statErr) {
		t.Fatalf("inspect CAS control path for Nginx deny test: %v", statErr)
	}
	statePath := ".sow/state/config/sow.yaml"
	if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(statePath))); err == nil && !info.Mode().IsRegular() {
		t.Fatalf("locate existing canonical state for Nginx deny test: %v", err)
	} else if err != nil && !os.IsNotExist(err) {
		t.Fatalf("inspect canonical state for Nginx deny test: %v", err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, relative := range []string{existingPoolObject, statePath, "sow.yaml", operatorCanary} {
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/%s", port, relative))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		closeErr := response.Body.Close()
		if closeErr != nil || response.StatusCode != http.StatusNotFound {
			t.Fatalf("Nginx exposed reserved path /%s: status=%d close=%v", relative, response.StatusCode, closeErr)
		}
	}
}

func nginxQuoted(value string) string {
	return `"` + strings.ReplaceAll(value, `\\`, `\\\\`) + `"`
}

type dockerExecution struct {
	output []byte
	err    error
}

func dockerCompatibilityCommand(ctx context.Context, image string, mounts []string, script string) *exec.Cmd {
	arguments := []string{"run", "--rm", "--platform", "linux/amd64", "--add-host", "host.docker.internal:host-gateway"}
	arguments = append(arguments, mounts...)
	arguments = append(arguments, image, "sh", "-ec", script)
	return exec.CommandContext(ctx, "docker", arguments...)
}

func startDockerCompatibility(ctx context.Context, image string, mounts []string, script string) <-chan dockerExecution {
	result := make(chan dockerExecution, 1)
	command := dockerCompatibilityCommand(ctx, image, mounts, script)
	go func() {
		output, err := command.CombinedOutput()
		result <- dockerExecution{output: output, err: err}
	}()
	return result
}

func runDocker(ctx context.Context, t *testing.T, image string, mounts []string, script string) string {
	t.Helper()
	command := dockerCompatibilityCommand(ctx, image, mounts, script)
	output, err := command.CombinedOutput()
	t.Logf("docker image=%s\n%s", image, output)
	if err != nil {
		t.Fatalf("docker compatibility client %s: %v\n%s", image, err, output)
	}
	return string(output)
}

func runDockerRedacted(ctx context.Context, t *testing.T, image string, mounts []string, script string, secrets ...string) string {
	t.Helper()
	command := dockerCompatibilityCommand(ctx, image, mounts, script)
	output, err := command.CombinedOutput()
	safe := string(output)
	for _, secret := range secrets {
		if secret != "" {
			safe = strings.ReplaceAll(safe, secret, "<redacted-token>")
		}
	}
	t.Logf("docker image=%s\n%s", image, safe)
	if err != nil {
		t.Fatalf("docker compatibility client %s: %v\n%s", image, err, safe)
	}
	return safe
}

func startCloudflareEdgeClientServer(
	ctx context.Context,
	t *testing.T,
	moduleRoot, root, contractPath, token string,
) (int, string, func()) {
	t.Helper()
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	portPath := filepath.Join(runtimeDir, "port")
	evidencePath := filepath.Join(runtimeDir, "evidence.jsonl")
	diagnosticsPath := filepath.Join(runtimeDir, "node.log")
	diagnostics, err := os.OpenFile(diagnosticsPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "node", filepath.Join(moduleRoot, "test", "compat", "cloudflare_edge_client_server.mjs"))
	command.Dir = moduleRoot
	command.Env = replaceRealCloudSafetyEnvironment(os.Environ(), map[string]string{
		"SOW_EDGE_CLIENT_ROOT":          root,
		"SOW_EDGE_CLIENT_CONTRACT":      contractPath,
		"SOW_EDGE_CLIENT_TOKEN":         token,
		"SOW_EDGE_CLIENT_PORT_FILE":     portPath,
		"SOW_EDGE_CLIENT_EVIDENCE_FILE": evidencePath,
	})
	command.Stdout = diagnostics
	command.Stderr = diagnostics
	if err := command.Start(); err != nil {
		_ = diagnostics.Close()
		t.Fatalf("start Cloudflare edge client server: %v", err)
	}
	_ = diagnostics.Close()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			if command.Process != nil {
				_ = command.Process.Signal(os.Interrupt)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				if command.Process != nil {
					_ = command.Process.Kill()
				}
				<-done
			}
		})
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		body, readErr := os.ReadFile(portPath)
		if readErr == nil {
			var port int
			if _, scanErr := fmt.Sscanf(string(body), "%d", &port); scanErr == nil && port > 0 && port <= 65535 {
				return port, evidencePath, stop
			}
			stop()
			t.Fatal("Cloudflare edge client server wrote an invalid port receipt")
		}
		select {
		case waitErr := <-done:
			once.Do(func() {})
			diagnostic, _ := os.ReadFile(diagnosticsPath)
			safe := strings.ReplaceAll(string(diagnostic), token, "<redacted-token>")
			t.Fatalf("Cloudflare edge client server exited before readiness: %v\n%s", waitErr, safe)
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	stop()
	diagnostic, _ := os.ReadFile(diagnosticsPath)
	t.Fatalf("Cloudflare edge client server readiness timeout\n%s", strings.ReplaceAll(string(diagnostic), token, "<redacted-token>"))
	return 0, "", func() {}
}

func dnfKeyMounts(repositoryKey, upstreamPackageKey string) []string {
	return []string{
		"-v", repositoryKey + ":/etc/pki/rpm-gpg/SOW-COMPAT:ro",
		// Keep the preinstalled trust copy outside the package-owned path. The
		// fixture RPM legitimately installs /etc/pki/rpm-gpg/PGDG-... itself;
		// bind-mounting that destination read-only would make unpack fail after
		// signature verification and would not model a real client.
		"-v", upstreamPackageKey + ":/run/sow-keys/PGDG-RPM-GPG-KEY-RHEL-nonfree:ro",
	}
}

func yumEL7KeyMounts(repositoryKey, packageKey string) []string {
	return []string{
		"-v", repositoryKey + ":/etc/pki/rpm-gpg/SOW-COMPAT:ro",
		"-v", packageKey + ":/run/sow-keys/RPM-GPG-KEY-CentOS-7:ro",
	}
}

func aptScript(port int) string {
	return aptSuiteScript(port, "jammy")
}

func apt12Script(port int) string {
	return fmt.Sprintf(`
apt_version="$(apt-get --version | head -1)"
printf 'support-floor client: %%s\n' "$apt_version"
case "$apt_version" in
  'apt 1.2.'*) ;;
  *) echo 'support-floor image does not contain apt 1.2.x' >&2; exit 1 ;;
esac
%s
`, aptSuiteScript(port, "jammy"))
}

func aptSuiteScript(port int, suite string) string {
	if suite == "" || strings.ContainsAny(suite, " \\t\\r\\n'\"") || path.Clean(suite) != suite {
		panic("unsafe APT compatibility suite")
	}
	return fmt.Sprintf(`
rm -f /etc/apt/sources.list.d/*
printf 'deb [arch=amd64 signed-by=/etc/apt/keyrings/sow-compat.gpg] http://host.docker.internal:%d/apt/test %s main\n' > /etc/apt/sources.list
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/sow-compat-deb_*.deb
apt-get -o Acquire::Retries=0 -o Debug::Acquire::http=true update
apt-cache policy %s
apt-cache madison %s | awk '{print $3}' | grep -Fx %s
apt-cache madison %s | awk '{print $3}' | grep -Fx %s
apt-get -y --no-install-recommends -o Acquire::Retries=0 install %s=%s
test "$(dpkg-query -W -f='${Status}' %s)" = 'install ok installed'
test "$(dpkg-query -W -f='${Version}' %s)" = '%s'
test -f /usr/share/doc/sow-compat/README
`, port, suite, debPackage, debPackage, debVersion, debPackage, newDebVersion, debPackage, debVersion, debPackage, debPackage, debVersion)
}

func aptBasicScript(port int) string {
	return fmt.Sprintf(`
rm -f /etc/apt/sources.list.d/*
install -d -m 700 /etc/apt/auth.conf.d
cat > /etc/apt/auth.conf.d/sow.conf <<'EOF'
machine http://host.docker.internal:%d
login verifier
password verify-secret
EOF
chmod 600 /etc/apt/auth.conf.d/sow.conf
printf 'deb [arch=amd64 signed-by=/etc/apt/keyrings/sow-compat.gpg] http://host.docker.internal:%d/pro/v1/basic/apt/test jammy main\n' > /etc/apt/sources.list
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/sow-compat-deb_*.deb
apt-get -o Acquire::Retries=0 update
apt-get -y --no-install-recommends -o Acquire::Retries=0 install %s=%s
test "$(dpkg-query -W -f='${Version}' %s)" = '%s'
`, port, port, debPackage, debVersion, debPackage, debVersion)
}

func aptTokenScript(port int) string {
	return fmt.Sprintf(`
token="$(cat /run/secrets/sow-pro-token)"
test -n "$token"
rm -f /etc/apt/sources.list.d/*
printf 'deb [arch=amd64 signed-by=/etc/apt/keyrings/sow-compat.gpg] http://host.docker.internal:%d/pro/v1/%%s/apt/test jammy main\n' "$token" > /etc/apt/sources.list
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/sow-compat-deb_*.deb
apt-get -o Acquire::Retries=0 update
apt-get -y --no-install-recommends -o Acquire::Retries=0 install %s=%s
test "$(dpkg-query -W -f='${Version}' %s)" = '%s'
`, port, debPackage, debVersion, debPackage, debVersion)
}

func dnfTokenScript(port int, repositoryPath string) string {
	return fmt.Sprintf(`
token="$(cat /run/secrets/sow-pro-token)"
test -n "$token"
cat > /etc/yum.repos.d/sow-edge-token.repo <<EOF
[sow-edge-token]
name=SOW edge token compatibility repository
baseurl=http://host.docker.internal:%d/pro/v1/${token}/%s/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/SOW-COMPAT file:///run/sow-keys/PGDG-RPM-GPG-KEY-RHEL-nonfree
metadata_expire=0
skip_if_unavailable=0
EOF
rm -rf /var/cache/dnf
dnf -y --disablerepo='*' --enablerepo=sow-edge-token --setopt=install_weak_deps=False makecache --refresh
dnf -y --disablerepo='*' --enablerepo=sow-edge-token --setopt=install_weak_deps=False --setopt=keepcache=True install %s-%s
test "$(rpm -q --qf '%%{VERSION}-%%{RELEASE}.%%{ARCH}' %s)" = '%s'
downloaded_rpm="$(find /var/cache/dnf -type f -name '%s-%s.rpm' -print -quit)"
test -n "$downloaded_rpm"
rpm -K "$downloaded_rpm" | grep -Eq ': digests signatures OK$'
`, port, repositoryPath, rpmPackage, rpmVersionArch, rpmPackage, rpmVersionArch, rpmPackage, rpmVersionArch)
}

func dnfScript(port int, repositoryPath string) string {
	return fmt.Sprintf(`
dnf --version | head -1
rpm --version
cat > /etc/yum.repos.d/sow-compat.repo <<'EOF'
[sow-compat]
name=SOW compatibility repository
baseurl=http://host.docker.internal:%d/%s/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/SOW-COMPAT file:///run/sow-keys/PGDG-RPM-GPG-KEY-RHEL-nonfree
metadata_expire=0
skip_if_unavailable=0
EOF
rm -rf /var/cache/dnf
dnf -y --disablerepo='*' --enablerepo=sow-compat --setopt=install_weak_deps=False makecache --refresh
dnf --disablerepo='*' --enablerepo=sow-compat repolist --enabled
dnf --disablerepo='*' --enablerepo=sow-compat repoquery --list %s-%s
dnf --disablerepo='*' --enablerepo=sow-compat repoquery --changelogs %s-%s
dnf -y --disablerepo='*' --enablerepo=sow-compat --setopt=install_weak_deps=False --setopt=keepcache=True install %s-%s
test "$(rpm -q --qf '%%{VERSION}-%%{RELEASE}.%%{ARCH}' %s)" = '%s'
downloaded_rpm="$(find /var/cache/dnf -type f -name '%s-%s.rpm' -print -quit)"
test -n "$downloaded_rpm"
rpm_check="$(rpm -K "$downloaded_rpm")"
printf 'rpm -K: %%s\n' "$rpm_check"
printf '%%s\n' "$rpm_check" | grep -Eq ': digests signatures OK$'
`, port, repositoryPath, rpmPackage, rpmVersionArch, rpmPackage, rpmVersionArch, rpmPackage, rpmVersionArch, rpmPackage, rpmVersionArch, rpmPackage, rpmVersionArch)
}

func yumEL7Script(port int, repositoryPath string) string {
	return fmt.Sprintf(`
yum --version | head -1
rpm --version
cat > /etc/yum.repos.d/sow-compat.repo <<'EOF'
[sow-compat]
name=SOW frozen EL7 compatibility repository
baseurl=http://host.docker.internal:%d/%s/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/SOW-COMPAT file:///run/sow-keys/RPM-GPG-KEY-CentOS-7
metadata_expire=0
skip_if_unavailable=0
EOF
rm -rf /var/cache/yum
yum -y --disablerepo='*' --enablerepo=sow-compat makecache fast
python - <<'PY'
import yum
base = yum.YumBase()
base.repos.disableRepo('*')
repo = base.repos.getRepo('sow-compat')
repo.enable()
print('EL7 filelists metadata: %%s' %% repo.getFileListsXML())
print('EL7 other metadata: %%s' %% repo.getOtherXML())
PY
available="$(yum -q --showduplicates --disablerepo='*' --enablerepo=sow-compat list %s)"
printf 'EL7 available versions:\n%%s\n' "$available"
printf '%%s\n' "$available" | grep -F '%s'
yum -y --disablerepo='*' --enablerepo=sow-compat --setopt=keepcache=True downgrade %s-%s
test "$(rpm -q --qf '%%{VERSION}-%%{RELEASE}.%%{ARCH}' %s)" = '%s'
downloaded_rpm="$(find /var/cache/yum -type f -name '%s-%s.rpm' -print -quit)"
test -n "$downloaded_rpm"
rpm_check="$(rpm -K "$downloaded_rpm")"
printf 'rpm -K: %%s\n' "$rpm_check"
printf '%%s\n' "$rpm_check" | grep -Eq ': .* OK$'
`, port, repositoryPath, el7RPMPackage, strings.TrimSuffix(el7RPMVersionArch, ".x86_64"), el7RPMPackage, el7RPMVersionArch, el7RPMPackage, el7RPMVersionArch, el7RPMPackage, el7RPMVersionArch)
}

func dnfMissingPackageKeyScript(port int, repositoryPath string) string {
	return fmt.Sprintf(`
for key in $(rpm -qa 'gpg-pubkey-08b40d20*'); do rpm -e "$key"; done
test -z "$(rpm -qa 'gpg-pubkey-08b40d20*')"
cat > /etc/yum.repos.d/sow-missing-package-key.repo <<'EOF'
[sow-missing-package-key]
name=SOW missing package key negative control
baseurl=http://host.docker.internal:%d/%s/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/SOW-COMPAT
metadata_expire=0
skip_if_unavailable=0
EOF
rm -rf /var/cache/dnf /tmp/sow-missing-package-key.log
dnf -y --disablerepo='*' --enablerepo=sow-missing-package-key makecache --refresh
if dnf -y --disablerepo='*' --enablerepo=sow-missing-package-key --setopt=install_weak_deps=False install %s-%s > /tmp/sow-missing-package-key.log 2>&1; then
  cat /tmp/sow-missing-package-key.log
  echo 'DNF accepted an upstream-signed RPM without its package trust key' >&2
  exit 1
fi
cat /tmp/sow-missing-package-key.log
! rpm -q %s >/dev/null 2>&1
grep -Eiq 'GPG|public key|signature' /tmp/sow-missing-package-key.log
printf 'missing upstream package key rejected before install\n'
`, port, repositoryPath, rpmPackage, rpmVersionArch, rpmPackage)
}

func dnfMirrorlistScript(port int, repo, osName, arch string) string {
	return fmt.Sprintf(`
dnf --version | head -1
rpm --version
cat > /etc/yum.repos.d/sow-generation.repo <<'EOF'
[sow-generation]
name=SOW generation-pinned compatibility repository
mirrorlist=http://host.docker.internal:%d/_sow/v1/mirrorlist/latest/%s/%s/%s.txt
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/SOW-COMPAT file:///run/sow-keys/PGDG-RPM-GPG-KEY-RHEL-nonfree
metadata_expire=0
skip_if_unavailable=0
EOF
rm -rf /var/cache/dnf
dnf -y --disablerepo='*' --enablerepo=sow-generation --setopt=install_weak_deps=False makecache --refresh
dnf --disablerepo='*' --enablerepo=sow-generation repoquery --list %s-%s
dnf --disablerepo='*' --enablerepo=sow-generation repoquery --changelogs %s-%s
dnf -y --disablerepo='*' --enablerepo=sow-generation --setopt=install_weak_deps=False --setopt=keepcache=True install %s-%s
test "$(rpm -q --qf '%%{VERSION}-%%{RELEASE}.%%{ARCH}' %s)" = '%s'
`, port, repo, osName, arch, rpmPackage, rpmVersionArch, rpmPackage, rpmVersionArch, rpmPackage, rpmVersionArch, rpmPackage, rpmVersionArch)
}

// dnfMirrorlistInFlightScript deliberately performs one DNF operation. The
// generation flip test gates that process after it resolves the mirrorlist but
// before its first immutable generation response. Splitting makecache and
// install into separate DNF processes would allow the later process to resolve
// the mutable mirrorlist again and would not model an in-flight client.
func dnfMirrorlistInFlightScript(port int, repo, osName, arch string) string {
	return fmt.Sprintf(`
dnf --version | head -1
rpm --version
cat > /etc/yum.repos.d/sow-generation.repo <<'EOF'
[sow-generation]
name=SOW generation-pinned compatibility repository
mirrorlist=http://host.docker.internal:%d/_sow/v1/mirrorlist/latest/%s/%s/%s.txt
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/SOW-COMPAT file:///run/sow-keys/PGDG-RPM-GPG-KEY-RHEL-nonfree
metadata_expire=0
skip_if_unavailable=0
EOF
rm -rf /var/cache/dnf
dnf -y --disablerepo='*' --enablerepo=sow-generation --setopt=install_weak_deps=False install %s-%s
test "$(rpm -q --qf '%%{VERSION}-%%{RELEASE}.%%{ARCH}' %s)" = '%s'
`, port, repo, osName, arch, rpmPackage, rpmVersionArch, rpmPackage, rpmVersionArch)
}

func dnfEmptyMirrorlistScript(port int, repo, osName, arch string) string {
	return fmt.Sprintf(`
cat > /etc/yum.repos.d/sow-generation-empty.repo <<'EOF'
[sow-generation-empty]
name=SOW empty generation-pinned compatibility repository
mirrorlist=http://host.docker.internal:%d/_sow/v1/mirrorlist/latest/%s/%s/%s.txt
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/SOW-COMPAT file:///run/sow-keys/PGDG-RPM-GPG-KEY-RHEL-nonfree
metadata_expire=0
skip_if_unavailable=0
EOF
rm -rf /var/cache/dnf
dnf -y --disablerepo='*' --enablerepo=sow-generation-empty makecache --refresh
available="$(dnf -q --disablerepo='*' --enablerepo=sow-generation-empty repoquery --available %s)"
printf 'empty generation query: %%s\n' "$available"
test -z "$available"
`, port, repo, osName, arch, rpmPackage)
}

func dnfBasicScript(port int, repo, osName, arch string) string {
	return fmt.Sprintf(`
cat > /etc/yum.repos.d/sow-basic.repo <<'EOF'
[sow-basic]
name=SOW Basic fallback repository
mirrorlist=http://host.docker.internal:%d/pro/v1/basic/_sow/v1/mirrorlist/stable/%s/%s/%s.txt
username=verifier
password=verify-secret
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/SOW-COMPAT file:///run/sow-keys/PGDG-RPM-GPG-KEY-RHEL-nonfree
metadata_expire=0
skip_if_unavailable=0
EOF
rm -rf /var/cache/dnf
dnf -y --disablerepo='*' --enablerepo=sow-basic --setopt=install_weak_deps=False makecache --refresh
dnf -y --disablerepo='*' --enablerepo=sow-basic --setopt=install_weak_deps=False install %s-%s
test "$(rpm -q --qf '%%{VERSION}-%%{RELEASE}.%%{ARCH}' %s)" = '%s'
`, port, repo, osName, arch, rpmPackage, rpmVersionArch, rpmPackage, rpmVersionArch)
}

func dnfHistoryScript(port int, repositoryPath string) string {
	return fmt.Sprintf(`
cat > /etc/yum.repos.d/sow-history.repo <<'EOF'
[sow-history]
name=SOW stable history repository
baseurl=http://host.docker.internal:%d/%s/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/SOW-COMPAT file:///run/sow-keys/PGDG-RPM-GPG-KEY-RHEL-nonfree
metadata_expire=0
skip_if_unavailable=0
EOF
rm -rf /var/cache/dnf /tmp/sow-history
mkdir -p /tmp/sow-history
dnf -y --disablerepo='*' --enablerepo=sow-history makecache --refresh
versions="$(dnf -q --disablerepo='*' --enablerepo=sow-history repoquery --available --qf '%%{name} %%{evr} %%{arch}' centos-release)"
printf 'stable versions:\n%%s\n' "$versions"
printf '%%s\n' "$versions" | grep -Fx 'centos-release 6:4-0.1 x86_64'
printf '%%s\n' "$versions" | grep -Fx 'centos-release 10:5-0.0.el5.centos.2 x86_64'
url4="$(dnf -q --disablerepo='*' --enablerepo=sow-history repoquery --location \
  'centos-release-6:4-0.1.x86_64')"
url5="$(dnf -q --disablerepo='*' --enablerepo=sow-history repoquery --location \
  'centos-release-10:5-0.0.el5.centos.2.x86_64')"
printf 'stable locations:\n%%s\n%%s\n' "$url4" "$url5"
test "$(printf '%%s\n' "$url4" | wc -l)" -eq 1
test "$(printf '%%s\n' "$url5" | wc -l)" -eq 1
curl --fail --silent --show-error --location \
  --output /tmp/sow-history/centos-release-4-0.1.x86_64.rpm "$url4"
curl --fail --silent --show-error --location \
  --output /tmp/sow-history/centos-release-5-0.0.el5.centos.2.x86_64.rpm "$url5"
test -s /tmp/sow-history/centos-release-4-0.1.x86_64.rpm
test -s /tmp/sow-history/centos-release-5-0.0.el5.centos.2.x86_64.rpm
`, port, repositoryPath)
}

func writeFile(t *testing.T, path string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
}

func compatConfig(routePort int, stableBaseURL string) string {
	return fmt.Sprintf(`schema: sow/v1
state: {}
gpg:
  public_key: signing-public.gpg
pools:
  public: {}
  gated: {}
repos:
  - id: apt-test
    type: apt
    path: apt/test
    default_pool: public
    publish_targets: [cf]
    arches: [amd64]
    os: {family: ubuntu, major: 22, suite: jammy, lifecycle: active}
    apt:
      suites: [jammy]
      components: [main]
  - id: yum-test
    type: yum
    path: yum/test/x86_64
    default_pool: public
    publish_targets: [cf]
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.gpg}
  - id: yum-el8
    type: yum
    path: yum/el8/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 8, lifecycle: frozen}
    yum: {compression: gzip, package_keyring: package-trust.gpg}
  - id: yum-el7
    type: yum
    path: yum/el7/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 7, lifecycle: frozen}
    yum: {compression: gzip, package_keyring: package-trust.gpg}
  - id: yum-el9
    type: yum
    path: yum/el9/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.gpg}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: "http://host.docker.internal:%d"}
  beta: {base_url: "http://host.docker.internal:%d"}
  stable: {base_url: %q}
targets:
  cf:
    storage: {kind: r2, endpoint: "https://test-account.r2.cloudflarestorage.com", bucket: sow-test-edge-client, credential: env://SOW_TEST_CF_STORAGE}
    cdn: {kind: cloudflare, base_url: "https://host.docker.internal", beta_base_url: "https://beta.host.docker.internal", zone_id: sow-test-edge-client, credential: env://SOW_TEST_CF_CDN}
edge:
  token_verifier: env://SOW_COMPAT_TOKEN_ENTITLEMENTS
`, routePort, routePort, stableBaseURL)
}
