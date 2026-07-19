package compat_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const defaultLegacyAPTImage = "debian/eol:jessie"

// TestLegacyAPTFixedAliasAtomicity is an opt-in negative compatibility probe
// for apt versions older than 1.2. It first proves that two complete,
// independently signed generations produced by the production SOW CLI are
// consumable. It then exposes the unavoidable publication window in which a
// client observes one generation's InRelease and another generation's fixed
// Packages alias.
//
// The redirect case exercises the strongest URL-preserving protocol candidate:
// immutable generation redirects, no-store responses, and a generation cookie
// set while serving InRelease. Debian Jessie apt 1.0 neither rebases later
// index requests onto the InRelease redirect nor returns that cookie, so the
// server has no standard request input with which to select the matching
// generation. This test passes only when the real client rejects both mixed
// closures with a checksum error.
func TestLegacyAPTFixedAliasAtomicity(t *testing.T) {
	if os.Getenv("SOW_RUN_APT_LEGACY_COMPAT") != "1" {
		t.Skip("set SOW_RUN_APT_LEGACY_COMPAT=1 to run the apt < 1.2 fixed-alias probe")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	moduleRoot := findModuleRoot(t)
	work := hostableCompatTempDir(t)
	repositoryRoot := filepath.Join(work, "repository")
	if err := os.MkdirAll(filepath.Join(repositoryRoot, "apt", "legacy"), 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(repositoryRoot, "sow.yaml")
	writeFile(t, configPath, []byte(legacyAPTConfig), 0o600)
	privateKey, publicKey := writeSigningKey(t, work)
	publicKeyBody, err := os.ReadFile(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(repositoryRoot, "signing-public.gpg"), publicKeyBody, 0o644)
	oldPackage := writeInstallableDEB(t, work, debVersion)
	newPackage := writeInstallableDEB(t, work, newDebVersion)
	cliPath := buildCLI(ctx, t, moduleRoot, work)

	runCLI(ctx, t, moduleRoot, cliPath, "init", "--config", configPath, "--workers", "2", "--chunk-entries", "2")
	runCLI(ctx, t, moduleRoot, cliPath, "add", oldPackage, "--config", configPath, "--repo", "apt-legacy", "--component", "main", "--gpg-private-key-file", privateKey)
	runCLI(ctx, t, moduleRoot, cliPath, "promote", "beta", "latest", "--config", configPath, "--repo", "apt-legacy")
	runCLI(ctx, t, moduleRoot, cliPath, "materialize", "latest", "--config", configPath, "--repo", "apt-legacy", "--target", "legacy-generations/old", "--gpg-private-key-file", privateKey)

	runCLI(ctx, t, moduleRoot, cliPath, "add", newPackage, "--config", configPath, "--repo", "apt-legacy", "--component", "main", "--gpg-private-key-file", privateKey)
	runCLI(ctx, t, moduleRoot, cliPath, "promote", "beta", "latest", "--config", configPath, "--repo", "apt-legacy")
	runCLI(ctx, t, moduleRoot, cliPath, "materialize", "latest", "--config", configPath, "--repo", "apt-legacy", "--target", "legacy-generations/new", "--gpg-private-key-file", privateKey)

	oldRoot := filepath.Join(repositoryRoot, "legacy-generations", "old")
	newRoot := filepath.Join(repositoryRoot, "legacy-generations", "new")
	assertLegacyAPTGeneration(t, oldRoot, []string{debVersion})
	assertLegacyAPTGeneration(t, newRoot, []string{debVersion, newDebVersion})
	image := compatImage("SOW_COMPAT_LEGACY_APT_IMAGE", defaultLegacyAPTImage)

	t.Run("coherent-old-generation", func(t *testing.T) {
		requests, port, stop := serveRepository(t, oldRoot, nginxRepositoryAllowlist{Prefixes: []string{"apt/legacy"}})
		defer stop()
		output, runErr := runLegacyAPTDocker(ctx, t, image, publicKey, port, debVersion)
		if runErr != nil {
			t.Fatalf("Jessie apt rejected coherent old generation: %v\n%s", runErr, output)
		}
		assertLegacyAPTUsedFixedAlias(t, requests.String())
	})

	t.Run("coherent-new-generation", func(t *testing.T) {
		requests, port, stop := serveRepository(t, newRoot, nginxRepositoryAllowlist{Prefixes: []string{"apt/legacy"}})
		defer stop()
		output, runErr := runLegacyAPTDocker(ctx, t, image, publicKey, port, newDebVersion)
		if runErr != nil {
			t.Fatalf("Jessie apt rejected coherent new generation: %v\n%s", runErr, output)
		}
		assertLegacyAPTUsedFixedAlias(t, requests.String())
	})

	t.Run("publisher-order-old-inrelease-new-alias", func(t *testing.T) {
		requests, port, stop := serveMixedLegacyAPT(t, oldRoot, newRoot)
		defer stop()
		output, runErr := runLegacyAPTDocker(ctx, t, image, publicKey, port, "")
		if runErr == nil {
			t.Fatalf("Jessie apt unexpectedly accepted old InRelease with new fixed aliases:\n%s\nrequests:\n%s", output, requests.String())
		}
		assertLegacyAPTChecksumFailure(t, output, requests.String())
		if !requests.containsSource("InRelease", "old") || !requests.containsSource("Packages", "new") {
			t.Fatalf("probe did not expose the intended old/new closure:\n%s", requests.String())
		}
	})

	t.Run("redirect-no-store-cookie-cannot-pin-generation", func(t *testing.T) {
		requests, port, stop := serveRedirectedLegacyAPT(t, oldRoot, newRoot)
		defer stop()
		output, runErr := runLegacyAPTDocker(ctx, t, image, publicKey, port, "")
		if runErr == nil {
			t.Fatalf("redirect candidate unexpectedly provided a coherent generation; investigate before retaining the negative gate:\n%s\nrequests:\n%s", output, requests.String())
		}
		assertLegacyAPTChecksumFailure(t, output, requests.String())
		if !requests.containsPath("/_sow-compat/g/new/apt/legacy/dists/jessie/InRelease") {
			t.Fatalf("apt did not follow the immutable InRelease redirect:\n%s", requests.String())
		}
		if !requests.containsSource("Packages", "old") {
			t.Fatalf("apt unexpectedly rebased the Packages request onto the InRelease generation:\n%s", requests.String())
		}
		if requests.packagesSentGenerationCookie() {
			t.Fatalf("apt unexpectedly returned the generation cookie; this candidate needs a fresh protocol review:\n%s", requests.String())
		}
	})
}

func assertLegacyAPTGeneration(t *testing.T, root string, versions []string) {
	t.Helper()
	base := filepath.Join(root, "apt", "legacy", "dists", "jessie")
	for _, relative := range []string{
		"InRelease",
		"Release",
		filepath.Join("main", "binary-amd64", "Packages"),
		filepath.Join("main", "binary-amd64", "Packages.gz"),
	} {
		info, err := os.Stat(filepath.Join(base, relative))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			t.Fatalf("legacy APT generation missing %s: %v", relative, err)
		}
	}
	packages, err := os.ReadFile(filepath.Join(base, "main", "binary-amd64", "Packages"))
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range versions {
		if !strings.Contains(string(packages), "Version: "+version+"\n") {
			t.Fatalf("legacy APT generation omitted version %s", version)
		}
	}
}

func runLegacyAPTDocker(ctx context.Context, t *testing.T, image, publicKey string, port int, installVersion string) (string, error) {
	t.Helper()
	install := ""
	if installVersion != "" {
		install = fmt.Sprintf(`
apt-get -y --no-install-recommends -o Acquire::Retries=0 install %s=%s
test "$(dpkg-query -W -f='${Version}' %s)" = '%s'
`, debPackage, installVersion, debPackage, installVersion)
	}
	script := fmt.Sprintf(`
apt-get --version | head -1
rm -f /etc/apt/sources.list.d/*
printf 'deb http://host.docker.internal:%d/apt/legacy jessie main\n' > /etc/apt/sources.list
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/%s_*.deb
apt-get -o Acquire::Retries=0 -o Debug::Acquire::http=true -o Debug::Acquire::gpgv=true update
%s`, port, debPackage, install)
	arguments := []string{
		"run", "--rm", "--platform", "linux/amd64",
		"--add-host", "host.docker.internal:host-gateway",
		"-v", publicKey + ":/etc/apt/trusted.gpg.d/sow-legacy.gpg:ro",
		image, "sh", "-ec", script,
	}
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	t.Logf("legacy apt image=%s error=%v\n%s", image, err, output)
	return string(output), err
}

func assertLegacyAPTUsedFixedAlias(t *testing.T, requests string) {
	t.Helper()
	if !strings.Contains(requests, "/apt/legacy/dists/jessie/main/binary-amd64/Packages") {
		t.Fatalf("apt < 1.2 did not request a fixed Packages alias:\n%s", requests)
	}
	if strings.Contains(requests, "/by-hash/") {
		t.Fatalf("apt < 1.2 unexpectedly requested by-hash:\n%s", requests)
	}
}

func assertLegacyAPTChecksumFailure(t *testing.T, output, requests string) {
	t.Helper()
	assertLegacyAPTUsedFixedAlias(t, requests)
	if !strings.Contains(output, "Hash Sum mismatch") {
		t.Fatalf("mixed generation failed for an unexpected reason:\n%s\nrequests:\n%s", output, requests)
	}
}

type legacyAPTRequest struct {
	method string
	path   string
	status int
	source string
	cookie string
}

type legacyAPTRequestLog struct {
	mu      sync.Mutex
	entries []legacyAPTRequest
}

func (log *legacyAPTRequestLog) append(entry legacyAPTRequest) {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.entries = append(log.entries, entry)
}

func (log *legacyAPTRequestLog) snapshot() []legacyAPTRequest {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]legacyAPTRequest(nil), log.entries...)
}

func (log *legacyAPTRequestLog) containsSource(fragment, source string) bool {
	for _, entry := range log.snapshot() {
		if strings.Contains(entry.path, fragment) && entry.source == source {
			return true
		}
	}
	return false
}

func (log *legacyAPTRequestLog) containsPath(path string) bool {
	for _, entry := range log.snapshot() {
		if entry.path == path {
			return true
		}
	}
	return false
}

func (log *legacyAPTRequestLog) packagesSentGenerationCookie() bool {
	for _, entry := range log.snapshot() {
		if strings.Contains(entry.path, "/Packages") && strings.Contains(entry.cookie, "sow_generation=") {
			return true
		}
	}
	return false
}

func (log *legacyAPTRequestLog) String() string {
	var output strings.Builder
	for _, entry := range log.snapshot() {
		fmt.Fprintf(&output, "%s %s %d source=%s cookie=%q\n", entry.method, entry.path, entry.status, entry.source, entry.cookie)
	}
	return output.String()
}

func serveMixedLegacyAPT(t *testing.T, inReleaseRoot, aliasRoot string) (*legacyAPTRequestLog, int, func()) {
	t.Helper()
	return serveLegacyAPT(t, func(request *http.Request) (string, string) {
		if strings.HasSuffix(request.URL.Path, "/InRelease") {
			return inReleaseRoot, "old"
		}
		return aliasRoot, "new"
	})
}

func serveRedirectedLegacyAPT(t *testing.T, oldRoot, newRoot string) (*legacyAPTRequestLog, int, func()) {
	t.Helper()
	var mu sync.Mutex
	pointer := "new"
	rootFor := func(generation string) string {
		if generation == "new" {
			return newRoot
		}
		return oldRoot
	}
	return serveLegacyAPT(t, func(request *http.Request) (string, string) {
		for _, generation := range []string{"old", "new"} {
			prefix := "/_sow-compat/g/" + generation
			if strings.HasPrefix(request.URL.Path, prefix+"/") {
				request.URL.Path = strings.TrimPrefix(request.URL.Path, prefix)
				if generation == "new" && strings.HasSuffix(request.URL.Path, "/InRelease") {
					mu.Lock()
					pointer = "old"
					mu.Unlock()
				}
				return rootFor(generation), generation
			}
		}
		if strings.HasSuffix(request.URL.Path, "/InRelease") {
			return "redirect:new", "redirect-new"
		}
		mu.Lock()
		generation := pointer
		mu.Unlock()
		if cookie, err := request.Cookie("sow_generation"); err == nil && (cookie.Value == "old" || cookie.Value == "new") {
			generation = cookie.Value
		}
		return "redirect:" + generation, "redirect-" + generation
	})
}

// serveLegacyAPT serves either a selected generation root or an immutable
// same-host redirect. Cache revalidation is intentionally forced so a failure
// cannot be blamed on a stale proxy object.
func serveLegacyAPT(t *testing.T, selectResponse func(*http.Request) (root, source string)) (*legacyAPTRequestLog, int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	log := &legacyAPTRequestLog{}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		originalPath := request.URL.Path
		root, source := selectResponse(request)
		status := &responseStatus{ResponseWriter: writer}
		status.Header().Set("Cache-Control", "no-store, must-revalidate")
		if strings.HasPrefix(root, "redirect:") {
			generation := strings.TrimPrefix(root, "redirect:")
			http.SetCookie(status, &http.Cookie{Name: "sow_generation", Value: generation, Path: "/", SameSite: http.SameSiteLaxMode})
			status.Header().Set("Location", "/_sow-compat/g/"+generation+originalPath)
			status.WriteHeader(http.StatusFound)
		} else {
			files := http.FileServer(http.Dir(root))
			files.ServeHTTP(status, request)
		}
		if status.status == 0 {
			status.status = http.StatusOK
		}
		log.append(legacyAPTRequest{
			method: request.Method,
			path:   originalPath,
			status: status.status,
			source: source,
			cookie: request.Header.Get("Cookie"),
		})
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	port := listener.Addr().(*net.TCPAddr).Port
	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}
	return log, port, stop
}

func readBodyLimited(response *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	_ = response.Body.Close()
}

const legacyAPTConfig = `schema: sow/v1
state:
  apt_by_hash_retention: 3
gpg:
  public_key: signing-public.gpg
pools:
  public: {}
  gated: {}
repos:
  - id: apt-legacy
    type: apt
    path: apt/legacy
    default_pool: public
    arches: [amd64]
    os: {family: debian, major: 8, suite: jessie, lifecycle: active}
    apt:
      suites: [jessie]
      components: [main]
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://compat-test
`
