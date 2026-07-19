package compat_test

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBasicNginxExampleUsesGeneratedIncludeContract(t *testing.T) {
	document, err := os.ReadFile(filepath.Join(findModuleRoot(t), "edge", "basic", "nginx.conf.example"))
	if err != nil {
		t.Fatal(err)
	}
	config := string(document)
	for _, fragment := range []string{
		"sow materialize stable --config /etc/sow/sow.yaml",
		"--nginx-include /etc/nginx/sow-stable.locations.conf",
		"--nginx-auth-user-file /etc/nginx/sow.htpasswd",
		"include /etc/nginx/sow-stable.locations.conf;",
		"does NOT cache these private,no-store responses",
		"anonymous request could reuse an object",
	} {
		if !strings.Contains(config, fragment) {
			t.Fatalf("Basic Nginx wrapper does not identify the generated include contract: missing %q", fragment)
		}
	}
	for _, line := range strings.Split(config, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && (fields[0] == "location" || fields[0] == "alias" || fields[0] == "try_files") {
			t.Fatalf("Basic Nginx wrapper hand-maintains generated route directive: %s", line)
		}
	}
	if strings.Contains(config, "/(.*)") {
		t.Fatal("Basic Nginx wrapper contains an unbounded generation capture")
	}
}

// TestNginxRepositoryAllowlist isolates the static-origin security boundary
// from the much heavier Docker package-manager matrix. The files denied below
// really exist; a 404 therefore proves the default-deny location rather than
// accidental absence.
func TestNginxRepositoryAllowlist(t *testing.T) {
	if os.Getenv("SOW_COMPAT_NGINX") != "1" {
		t.Skip("set SOW_COMPAT_NGINX=1 to run the real Nginx allowlist test")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "apt", "test"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "apt", "test", "probe"), []byte("public repository byte\n"), 0o444)
	writeFile(t, filepath.Join(root, "signing-public.gpg"), []byte("public trust anchor\n"), 0o444)
	writeFile(t, filepath.Join(root, "sow.yaml"), []byte("schema: sow/v1\n"), 0o600)
	writeFile(t, filepath.Join(root, "operator-token"), []byte("non-secret deny canary\n"), 0o600)
	writeNginxNamespaceDenyCanaries(t, root)
	writeNginxGenerationFixture(t, root)
	exactBody, nestedBody := writeNginxAssetProjectionFixture(t, root)

	_, port, stop := serveRepositoryNginx(t, root, nginxAllowlistTestContract())
	defer stop()
	client := &http.Client{Timeout: 5 * time.Second}
	for _, test := range []struct {
		path     string
		want     int
		wantBody string
	}{
		{path: "/apt/test/probe", want: http.StatusOK, wantBody: "public repository byte\n"},
		{path: "/signing-public.gpg", want: http.StatusOK, wantBody: "public trust anchor\n"},
		{path: "/_sow/v1/mirrorlist/stable/yum-test/el10/x86_64.txt", want: http.StatusOK, wantBody: "generation fixture\n"},
		{path: "/_sow/v1/g/00000000000000000001/yum/test/x86_64/repodata/probe", want: http.StatusOK, wantBody: "generation repository byte\n"},
		{path: "/_sow/v1/g/00000000000000000001/yum/pgsql/el9.x86_64/repodata/probe", want: http.StatusOK, wantBody: "dotted generation repository byte\n"},
		{path: "/pkg", want: http.StatusOK, wantBody: exactBody},
		{path: "/pkg/pig/latest", want: http.StatusOK, wantBody: nestedBody},
		{path: "/pkg/", want: http.StatusNotFound},
		{path: "/pkg/child/", want: http.StatusNotFound},
		{path: "/pkg/child/index.html", want: http.StatusNotFound},
		{path: "/sow.yaml", want: http.StatusNotFound},
		{path: "/operator-token", want: http.StatusNotFound},
		{path: "/apt/unowned-secret", want: http.StatusNotFound},
		{path: "/yum/unowned-secret", want: http.StatusNotFound},
		{path: "/_sow/unowned-secret", want: http.StatusNotFound},
		{path: "/_sow/v1/g/00000000000000000001/yum/unowned/x86_64/secret", want: http.StatusNotFound},
		{path: "/_sow/v1/g/00000000000000000001/yum/pgsql/el9Xx86_64/operator-secret", want: http.StatusNotFound},
		{path: "/unknown", want: http.StatusNotFound},
	} {
		got := requestNginx(t, client, port, test.path, "", "")
		if got.status != test.want || (test.wantBody != "" && got.body != test.wantBody) {
			t.Fatalf("GET %s status=%d body=%q want status=%d body=%q", test.path, got.status, got.body, test.want, test.wantBody)
		}
	}
}

func TestBasicNginxRepositoryAllowlist(t *testing.T) {
	if os.Getenv("SOW_COMPAT_NGINX") != "1" {
		t.Skip("set SOW_COMPAT_NGINX=1 to run the real Basic Nginx allowlist test")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "apt", "test"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "apt", "test", "probe"), []byte("gated repository byte\n"), 0o444)
	writeFile(t, filepath.Join(root, "operator-token"), []byte("non-secret deny canary\n"), 0o600)
	writeNginxNamespaceDenyCanaries(t, root)
	writeNginxGenerationFixture(t, root)
	exactBody, nestedBody := writeNginxAssetProjectionFixture(t, root)
	_, port, stop := serveBasicRepositoryNginx(t, root, nginxAllowlistTestContract())
	defer stop()
	client := &http.Client{Timeout: 5 * time.Second}
	for _, path := range []string{
		"/pro/v1/basic/pkg",
		"/pro/v1/basic/pkg/pig/latest",
		"/pro/v1/basic/_sow/v1/mirrorlist/stable/yum-test/el10/x86_64.txt",
		"/pro/v1/basic/_sow/v1/g/00000000000000000001/yum/test/x86_64/repodata/probe",
		"/pro/v1/basic/_sow/v1/g/00000000000000000001/yum/pgsql/el9.x86_64/repodata/probe",
	} {
		got := requestNginx(t, client, port, path, "", "")
		if got.status != http.StatusUnauthorized || !strings.HasPrefix(got.wwwAuthenticate, "Basic ") {
			t.Fatalf("anonymous GET %s status=%d WWW-Authenticate=%q, want 401 Basic", path, got.status, got.wwwAuthenticate)
		}
		if got.cacheControl != "private, no-store" {
			t.Fatalf("anonymous GET %s Cache-Control=%q, want private,no-store", path, got.cacheControl)
		}
	}
	for _, test := range []struct {
		path        string
		want        int
		wantBody    string
		wantNoStore bool
	}{
		{path: "/pro/v1/basic/apt/test/probe", want: http.StatusOK, wantBody: "gated repository byte\n", wantNoStore: true},
		{path: "/pro/v1/basic/_sow/v1/mirrorlist/stable/yum-test/el10/x86_64.txt", want: http.StatusOK, wantBody: "generation fixture\n", wantNoStore: true},
		{path: "/pro/v1/basic/_sow/v1/g/00000000000000000001/yum/test/x86_64/repodata/probe", want: http.StatusOK, wantBody: "generation repository byte\n", wantNoStore: true},
		{path: "/pro/v1/basic/_sow/v1/g/00000000000000000001/yum/pgsql/el9.x86_64/repodata/probe", want: http.StatusOK, wantBody: "dotted generation repository byte\n", wantNoStore: true},
		{path: "/pro/v1/basic/pkg", want: http.StatusOK, wantBody: exactBody, wantNoStore: true},
		{path: "/pro/v1/basic/pkg/pig/latest", want: http.StatusOK, wantBody: nestedBody, wantNoStore: true},
		{path: "/pro/v1/basic/pkg/", want: http.StatusNotFound},
		{path: "/pro/v1/basic/pkg/child/", want: http.StatusNotFound},
		{path: "/pro/v1/basic/pkg/child/index.html", want: http.StatusNotFound},
		{path: "/pro/v1/basic/operator-token", want: http.StatusNotFound},
		{path: "/pro/v1/basic/apt/unowned-secret", want: http.StatusNotFound},
		{path: "/pro/v1/basic/yum/unowned-secret", want: http.StatusNotFound},
		{path: "/pro/v1/basic/_sow/unowned-secret", want: http.StatusNotFound},
		{path: "/pro/v1/basic/_sow/v1/g/00000000000000000001/yum/unowned/x86_64/secret", want: http.StatusNotFound},
		{path: "/pro/v1/basic/_sow/v1/g/00000000000000000001/yum/pgsql/el9Xx86_64/operator-secret", want: http.StatusNotFound},
		{path: "/pkg", want: http.StatusNotFound},
		{path: "/operator-token", want: http.StatusNotFound},
	} {
		got := requestNginx(t, client, port, test.path, "verifier", "verify-secret")
		if got.status != test.want || (test.wantBody != "" && got.body != test.wantBody) {
			t.Fatalf("authenticated GET %s status=%d body=%q want status=%d body=%q", test.path, got.status, got.body, test.want, test.wantBody)
		}
		if test.wantNoStore && got.cacheControl != "private, no-store" {
			t.Fatalf("authenticated GET %s Cache-Control=%q, want private,no-store", test.path, got.cacheControl)
		}
	}
}

func nginxAllowlistTestContract() nginxRepositoryAllowlist {
	return nginxRepositoryAllowlist{
		ExactFiles: []string{
			"signing-public.gpg",
			"_sow/v1/mirrorlist/stable/yum-test/el10/x86_64.txt",
		},
		Prefixes:        []string{"apt/test"},
		GenerationRoots: []string{"yum/pgsql/el9.x86_64", "yum/test/x86_64"},
		Aliases: []nginxAliasRoute{
			{URL: "pkg", Source: "asset/bootstrap/pkg"},
			{URL: "pkg/pig", Source: "pkg/pig", Prefix: true},
		},
	}
}

func writeNginxGenerationFixture(t *testing.T, root string) {
	t.Helper()
	files := map[string]string{
		"_sow/v1/mirrorlist/stable/yum-test/el10/x86_64.txt":                   "generation fixture\n",
		"_sow/v1/g/00000000000000000001/yum/pgsql/el9.x86_64/repodata/probe":   "dotted generation repository byte\n",
		"_sow/v1/g/00000000000000000001/yum/pgsql/el9Xx86_64/operator-secret":  "regex widening control canary\n",
		"_sow/v1/g/00000000000000000001/yum/test/x86_64/repodata/probe":        "generation repository byte\n",
		"_sow/v1/g/00000000000000000001/yum/unowned/x86_64/secret":             "unowned generation control canary\n",
		"_sow/v1/g/00000000000000000001/yum/test/unowned-arch/operator-secret": "unowned leaf control canary\n",
	}
	for relative, body := range files {
		filename := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filename, []byte(body), 0o600)
	}
}

func writeNginxNamespaceDenyCanaries(t *testing.T, root string) {
	t.Helper()
	for _, relative := range []string{
		"apt/unowned-secret",
		"yum/unowned-secret",
		"_sow/unowned-secret",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, filepath.FromSlash(relative))), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(root, filepath.FromSlash(relative)), []byte("unowned namespace control canary\n"), 0o600)
	}
}

type nginxTestResponse struct {
	status          int
	body            string
	cacheControl    string
	wwwAuthenticate string
}

func requestNginx(t *testing.T, client *http.Client, port int, path, username, password string) nginxTestResponse {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
	if err != nil {
		t.Fatal(err)
	}
	if username != "" {
		request.SetBasicAuth(username, password)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("GET %s read=%v close=%v", path, readErr, closeErr)
	}
	return nginxTestResponse{
		status:          response.StatusCode,
		body:            string(body),
		cacheControl:    response.Header.Get("Cache-Control"),
		wwwAuthenticate: response.Header.Get("WWW-Authenticate"),
	}
}

func writeNginxAssetProjectionFixture(t *testing.T, root string) (string, string) {
	t.Helper()
	exactBody := "root exact bootstrap object\n"
	nestedBody := "4.0.0\n"
	if err := os.MkdirAll(filepath.Join(root, "asset", "bootstrap"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "pkg", "pig"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "pkg", "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "asset", "bootstrap", "pkg"), []byte(exactBody), 0o444)
	writeFile(t, filepath.Join(root, "pkg", "pig", "latest"), []byte(nestedBody), 0o444)
	writeFile(t, filepath.Join(root, "pkg", "child", "index.html"), []byte("unowned child control canary\n"), 0o600)
	return exactBody, nestedBody
}
