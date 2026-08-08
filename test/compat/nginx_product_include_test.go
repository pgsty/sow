package compat_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/serving"
)

func TestProductGeneratedNginxIncludeLoopbackContract(t *testing.T) {
	if os.Getenv("SOW_COMPAT_NGINX") != "1" {
		t.Skip("set SOW_COMPAT_NGINX=1 to run the product-generated Nginx include test")
	}
	repositoryRoot := t.TempDir()
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "sow.yaml")
	writeFile(t, configPath, []byte(productNginxConfigYAML), 0o600)
	if err := os.MkdirAll(filepath.Join(configDir, "keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(configDir, "keys", "repository.asc"), []byte("public repository trust\n"), 0o444)
	writeFile(t, filepath.Join(configDir, "keys", "rpm-signers.asc"), []byte("public rpm signer bundle\n"), 0o444)
	cfg, err := config.Load(configPath, repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("public", func(t *testing.T) {
		writeProductNginxTree(t, repositoryRoot, "latest", true)
		body, err := serving.RenderNginxInclude(cfg, cfg.Repos, serving.NginxIncludeOptions{
			View: "latest", Root: repositoryRoot, RawCompatibilityIDs: []string{"infra-legacy-x86-64"},
		})
		if err != nil {
			t.Fatal(err)
		}
		port, stop := startProductNginxInclude(t, body)
		defer stop()
		client := &http.Client{Timeout: 5 * time.Second}
		checks := []struct {
			path string
			want int
			body string
		}{
			{path: "/apt/pgsql/trixie/probe", want: http.StatusOK, body: "apt public\n"},
			{path: "/yum/pgsql%5Enext/el9.x86_64/raw", want: http.StatusOK, body: "yum raw bridge\n"},
			{path: "/yum/infra/x86_64/legacy", want: http.StatusOK, body: "compat raw bridge\n"},
			{path: "/_sow/v1/mirrorlist/latest/yum-el9/el9/x86_64.txt", want: http.StatusOK, body: "ordinary mirrorlist\n"},
			{path: "/_sow/v1/mirrorlist/latest/infra-legacy-x86-64/cross-el/x86_64.txt", want: http.StatusNotFound},
			{path: "/_sow/v1/g/00000000000000000001/yum/pgsql%5Enext/el9.x86_64/repodata/probe", want: http.StatusOK, body: "ordinary generation\n"},
			{path: "/_sow/v1/g/00000000000000000001/yum/pgsql%5Enext/el9.x86_64/flat.rpm", want: http.StatusNotFound},
			{path: "/_sow/v1/g/00000000000000000001/yum/pgsql%5Enext/el9.x86_64/Packages/p/pkg.rpm", want: http.StatusOK, body: "ordinary package\n"},
			{path: "/_sow/v1/g/00000000000000000001/yum/infra/x86_64/repodata/probe", want: http.StatusNotFound},
			{path: "/keys/repository.asc", want: http.StatusOK, body: "public repository trust\n"},
			{path: "/keys/rpm-signers.asc", want: http.StatusOK, body: "public rpm signer bundle\n"},
			{path: "/pkg", want: http.StatusOK, body: "root exact asset\n"},
			{path: "/pkg/pig/latest", want: http.StatusOK, body: "nested asset\n"},
			{path: "/pkg/", want: http.StatusNotFound},
			{path: "/pkg/child/secret", want: http.StatusNotFound},
			{path: "/apt/unowned-secret", want: http.StatusNotFound},
			{path: "/yum/unowned-secret", want: http.StatusNotFound},
			{path: "/_sow/unowned-secret", want: http.StatusNotFound},
			{path: "/sow.yaml", want: http.StatusNotFound},
			{path: "/operator-secret", want: http.StatusNotFound},
			{path: "/_sow/v1/g/00000000000000000001/yum/pgsql%5Enext/el9Xx86_64/operator-secret", want: http.StatusNotFound},
		}
		for _, check := range checks {
			response := requestNginx(t, client, port, check.path, "", "")
			if response.status != check.want || check.body != "" && response.body != check.body {
				t.Fatalf("GET %s status=%d body=%q want status=%d body=%q", check.path, response.status, response.body, check.want, check.body)
			}
		}
		assertProductNginxMethods(t, client, port, "/apt/pgsql/trixie/probe", "", "")
		assertProductNginxTraversalAndSymlinkDenied(t, port, "")
	})

	t.Run("basic", func(t *testing.T) {
		stableRoot := filepath.Join(repositoryRoot, ".sow", "origin", "gated")
		writeProductNginxTree(t, stableRoot, "stable", false)
		authPath := filepath.Join(t.TempDir(), "sow.htpasswd")
		writeFile(t, authPath, []byte("verifier:{PLAIN}verify-secret\n"), 0o600)
		body, err := serving.RenderNginxInclude(cfg, cfg.Repos, serving.NginxIncludeOptions{
			View: "stable", Root: stableRoot, BasicAuthUserFile: authPath,
		})
		if err != nil {
			t.Fatal(err)
		}
		port, stop := startProductNginxInclude(t, body)
		defer stop()
		client := &http.Client{Timeout: 5 * time.Second}
		owned := "/pro/v1/basic/_sow/v1/g/00000000000000000001/yum/pgsql%5Enext/el9.x86_64/repodata/probe"
		anonymous := requestNginx(t, client, port, owned, "", "")
		if anonymous.status != http.StatusUnauthorized || !strings.HasPrefix(anonymous.wwwAuthenticate, "Basic ") || anonymous.cacheControl != "private, no-store" {
			t.Fatalf("anonymous owned route status=%d auth=%q cache=%q", anonymous.status, anonymous.wwwAuthenticate, anonymous.cacheControl)
		}
		authorized := requestNginx(t, client, port, owned, "verifier", "verify-secret")
		if authorized.status != http.StatusOK || authorized.body != "ordinary generation\n" || authorized.cacheControl != "private, no-store" {
			t.Fatalf("authorized owned route status=%d body=%q cache=%q", authorized.status, authorized.body, authorized.cacheControl)
		}
		for _, check := range []struct {
			path string
			body string
		}{
			{path: "/pro/v1/basic/pkg", body: "root exact asset\n"},
			{path: "/pro/v1/basic/keys/rpm-signers.asc", body: "public rpm signer bundle\n"},
		} {
			response := requestNginx(t, client, port, check.path, "verifier", "verify-secret")
			if response.status != http.StatusOK || response.body != check.body || response.cacheControl != "private, no-store" {
				t.Fatalf("authorized Basic route %s status=%d body=%q cache=%q", check.path, response.status, response.body, response.cacheControl)
			}
		}
		for _, denied := range []string{
			"/apt/pgsql/trixie/probe",
			"/pro/v1/basic/apt/unowned-secret",
			"/pro/v1/basic/yum/unowned-secret",
			"/pro/v1/basic/_sow/unowned-secret",
			"/pro/v1/basic/yum/infra/x86_64/legacy",
		} {
			response := requestNginx(t, client, port, denied, "verifier", "verify-secret")
			if response.status != http.StatusNotFound {
				t.Fatalf("Basic denied path %s status=%d body=%q", denied, response.status, response.body)
			}
		}
		assertProductNginxMethods(t, client, port, owned, "verifier", "verify-secret")
		assertProductNginxTraversalAndSymlinkDenied(t, port, "/pro/v1/basic")
	})
}

func writeProductNginxTree(t *testing.T, root, view string, compatibility bool) {
	t.Helper()
	files := map[string]string{
		"apt/pgsql/trixie/probe":                                                      "apt public\n",
		"yum/pgsql^next/el9.x86_64/raw":                                               "yum raw bridge\n",
		"_sow/v1/mirrorlist/" + view + "/yum-el9/el9/x86_64.txt":                      "ordinary mirrorlist\n",
		"_sow/v1/g/00000000000000000001/yum/pgsql^next/el9.x86_64/repodata/probe":     "ordinary generation\n",
		"_sow/v1/g/00000000000000000001/yum/pgsql^next/el9.x86_64/flat.rpm":           "flat generation canary\n",
		"_sow/v1/g/00000000000000000001/yum/pgsql^next/el9.x86_64/Packages/p/pkg.rpm": "ordinary package\n",
		"_sow/v1/g/00000000000000000001/yum/pgsql^next/el9Xx86_64/operator-secret":    "dotted regex widening canary\n",
		"asset/bootstrap/pkg": "root exact asset\n",
		"asset/pig/latest":    "nested asset\n",
		"pkg/child/secret":    "unowned pkg child canary\n",
		"apt/unowned-secret":  "unowned apt canary\n",
		"yum/unowned-secret":  "unowned yum canary\n",
		"_sow/unowned-secret": "unowned serving canary\n",
		"sow.yaml":            "operator config canary\n",
		"operator-secret":     "operator secret canary\n",
	}
	if compatibility {
		files["yum/infra/x86_64/legacy"] = "compat raw bridge\n"
		files["_sow/v1/mirrorlist/latest/infra-legacy-x86-64/cross-el/x86_64.txt"] = "compat mirrorlist\n"
		files["_sow/v1/g/00000000000000000001/yum/infra/x86_64/repodata/probe"] = "compat generation\n"
	}
	for relative, body := range files {
		filename := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filename, []byte(body), 0o444)
	}
	outside := filepath.Join(t.TempDir(), "outside-secret")
	writeFile(t, outside, []byte("must never escape\n"), 0o444)
	for _, link := range []string{
		"yum/pgsql^next/el9.x86_64/symlink-escape",
		"_sow/v1/g/00000000000000000001/yum/pgsql^next/el9.x86_64/repodata/symlink-escape",
	} {
		filename := filepath.Join(root, filepath.FromSlash(link))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filename); err != nil {
			t.Fatal(err)
		}
	}
	outsideDirectory := t.TempDir()
	writeFile(t, filepath.Join(outsideDirectory, "secret"), []byte("must never escape directory\n"), 0o444)
	for _, link := range []string{
		"yum/pgsql^next/el9.x86_64/symlink-dir",
		"_sow/v1/g/00000000000000000001/yum/pgsql^next/el9.x86_64/repodata/symlink-dir",
	} {
		filename := filepath.Join(root, filepath.FromSlash(link))
		if err := os.Symlink(outsideDirectory, filename); err != nil {
			t.Fatal(err)
		}
	}
}

func assertProductNginxTraversalAndSymlinkDenied(t *testing.T, port int, prefix string) {
	t.Helper()
	base := prefix + "/_sow/v1/g/00000000000000000001/yum/pgsql%5Enext/el9.x86_64/repodata/"
	for _, target := range []string{
		base + "symlink-escape",
		base + "symlink-dir/secret",
		base + "../../../../../../operator-secret",
		base + "%2e%2e/%2e%2e/%2e%2e/%2e%2e/operator-secret",
		base + "%2e%2e%2f%2e%2e%2foperator-secret",
	} {
		status, body := rawProductNginxRequest(t, port, target, prefix != "")
		if status == http.StatusOK || strings.Contains(body, "must never escape") || strings.Contains(body, "operator secret canary") {
			t.Fatalf("unsafe request %q escaped route: status=%d body=%q", target, status, body)
		}
	}
	for _, rawPrefix := range []string{
		prefix + "/yum/pgsql%5Enext/el9.x86_64/symlink-escape",
		prefix + "/yum/pgsql%5Enext/el9.x86_64/symlink-dir/secret",
	} {
		status, body := rawProductNginxRequest(t, port, rawPrefix, prefix != "")
		if status == http.StatusOK || strings.Contains(body, "must never escape") {
			t.Fatalf("raw prefix symlink escaped route %q: status=%d body=%q", rawPrefix, status, body)
		}
	}
}

func assertProductNginxMethods(t *testing.T, client *http.Client, port int, target, user, password string) {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d%s", port, target)
	head, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		head.SetBasicAuth(user, password)
	}
	headResponse, err := client.Do(head)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, headResponse.Body)
	_ = headResponse.Body.Close()
	if headResponse.StatusCode != http.StatusOK || headResponse.ContentLength <= 0 {
		t.Fatalf("HEAD %s status=%d length=%d", target, headResponse.StatusCode, headResponse.ContentLength)
	}

	post, err := http.NewRequest(http.MethodPost, url, strings.NewReader("must not write"))
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		post.SetBasicAuth(user, password)
	}
	postResponse, err := client.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, postResponse.Body)
	_ = postResponse.Body.Close()
	if postResponse.StatusCode != http.StatusForbidden && postResponse.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST %s status=%d, want 403 or 405", target, postResponse.StatusCode)
	}
}

func rawProductNginxRequest(t *testing.T, port int, target string, basic bool) (int, string) {
	t.Helper()
	connection, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	authorization := ""
	if basic {
		authorization = "Authorization: Basic dmVyaWZpZXI6dmVyaWZ5LXNlY3JldA==\r\n"
	}
	if _, err := fmt.Fprintf(connection, "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\n%sConnection: close\r\n\r\n", target, authorization); err != nil {
		t.Fatal(err)
	}
	request := &http.Request{Method: http.MethodGet}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(body)
}

func startProductNginxInclude(t *testing.T, include []byte) (int, func()) {
	t.Helper()
	executable, err := exec.LookPath("nginx")
	if err != nil {
		t.Fatal("SOW_COMPAT_NGINX=1 requires nginx in PATH")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	prefix := t.TempDir()
	includePath := filepath.Join(prefix, "sow.locations.conf")
	configPath := filepath.Join(prefix, "nginx.conf")
	writeFile(t, includePath, include, 0o644)
	document := fmt.Sprintf(`worker_processes 1;
pid %s;
error_log stderr notice;
events { worker_connections 128; }
http {
  access_log off;
  server {
    listen 127.0.0.1:%d;
    include %s;
  }
}
`, nginxQuoted(filepath.Join(prefix, "nginx.pid")), port, nginxQuoted(includePath))
	writeFile(t, configPath, []byte(document), 0o600)
	check := exec.Command(executable, "-p", prefix, "-c", configPath, "-t")
	if diagnostics, err := check.CombinedOutput(); err != nil {
		t.Fatalf("product-generated Nginx include did not parse: %v\n%s\ninclude:\n%s", err, diagnostics, include)
	}
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, executable, "-p", prefix, "-c", configPath, "-g", "daemon off;")
	var diagnostics bytes.Buffer
	command.Stdout = &diagnostics
	command.Stderr = &diagnostics
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
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
			t.Fatalf("Nginx exited before readiness: %v\n%s", waitErr, diagnostics.String())
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("Nginx readiness timeout\n%s", diagnostics.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	return port, func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			if command.Process != nil {
				_ = command.Process.Kill()
			}
		}
	}
}

const productNginxConfigYAML = `schema: sow/v1
state: {}
gpg:
  public_key: keys/repository.asc
  private_key: env://SOW_GPG_PRIVATE_KEY
  passphrase: env://SOW_GPG_PASSPHRASE
pools:
  public: {}
  gated: {}
repos:
  - id: bootstrap
    type: asset
    path: asset/bootstrap
    default_pool: public
    include: ["**"]
    asset: {kind: bootstrap, public_path: '.', root_keys: [pkg]}
  - id: pig
    type: asset
    path: asset/pig
    default_pool: public
    include: ["**"]
    asset: {kind: release, public_path: pkg/pig}
  - id: yum-el9
    type: yum
    path: yum/pgsql^next/el9.x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: keys/rpm-signers.asc}
  - id: infra-carrier
    type: yum
    path: yum/infra/{arch}
    active: false
    default_pool: public
    arches: [x86_64]
    os: {family: cross-el, major: 0, lifecycle: frozen}
    yum: {compression: gzip, compatibility_carrier: true, package_keyring: keys/rpm-signers.asc}
  - id: apt-trixie
    type: apt
    path: apt/pgsql/trixie
    default_pool: public
    arches: [amd64]
    os: {family: debian, major: 13, suite: trixie, lifecycle: active}
    apt: {suites: [trixie], components: [main]}
compatibility_projections:
  - id: infra-legacy-x86-64
    root: yum/infra/x86_64
    mode: frozen-cross-el
    carrier: infra-carrier
    source: {repo: yum-el9, view: latest, os: cross-el, arch: x86_64, commit: pin-at-first-freeze}
upstreams: []
views:
  beta: {access: public, debuginfo: drop, allowed_pools: [public], append_only: false}
  latest: {access: public, debuginfo: drop, allowed_pools: [public], append_only: false}
  stable: {access: pro, debuginfo: keep, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: "https://repo.example"}
  beta: {base_url: "https://beta.example"}
  stable: {base_url: "https://repo.example/pro/v1/basic"}
targets: {}
edge:
  token_verifier: provider://test
`
