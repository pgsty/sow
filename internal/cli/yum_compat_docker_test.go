package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestYUMCompatibilityStateMachineWithRealNginxAndDNF is the client-facing
// acceptance boundary for ADR-0021. It is opt-in because it starts local
// Nginx and disposable EL8/9/10 containers. The fixture has no publish target,
// strips every cloud credential and real-evidence switch from child processes,
// and points DNF only at the loopback-hosted temporary repository.
func TestYUMCompatibilityStateMachineWithRealNginxAndDNF(t *testing.T) {
	if os.Getenv("SOW_RUN_DOCKER_COMPAT") != "1" || os.Getenv("SOW_COMPAT_NGINX") != "1" {
		t.Skip("set SOW_RUN_DOCKER_COMPAT=1 and SOW_COMPAT_NGINX=1 to run the real local YUM compatibility state machine")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("SOW_RUN_DOCKER_COMPAT=1 requires docker")
	}
	if _, err := exec.LookPath("nginx"); err != nil {
		t.Fatal("SOW_COMPAT_NGINX=1 requires nginx")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	fixture := newFlatYUMCompatibilityFixture(t)
	workspace := filepath.Clean(filepath.Join(fixture.root, "..", "..", ".."))
	if err := os.MkdirAll(filepath.Join(workspace, "yum", "infra", "el9", "x86_64"), 0o755); err != nil {
		t.Fatal(err)
	}
	port := reserveYUMCompatibilityPort(t)
	configPath := filepath.Join(workspace, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(localYUMCompatibilityDockerConfig(port)), 0o600); err != nil {
		t.Fatal(err)
	}
	moduleRoot := yumCompatibilityModuleRoot(t)
	// The general parser fixture deliberately carries historical CentOS keys to
	// exercise packet-preserving policy. They do not sign this repository and
	// current rpm/DNF5 correctly rejects importing one of those obsolete
	// certificates. Keep the real client boundary honest by configuring the
	// exact PGDG signer required by the fixture RPM, rather than an unrelated
	// parser-stress bundle.
	clientPackageTrust, err := os.ReadFile(filepath.Join(moduleRoot, "test", "compat", "testdata", "PGDG-RPM-GPG-KEY-RHEL-nonfree.asc"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "package-trust.asc"), clientPackageTrust, 0o644); err != nil {
		t.Fatal(err)
	}
	cliPath := filepath.Join(t.TempDir(), "sow")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", cliPath, "./cmd/sow")
	build.Dir = moduleRoot
	build.Env = localYUMCompatibilityEnvironment(os.Environ())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build production SOW CLI: %v\n%s", err, output)
	}

	run := func(arguments ...string) string {
		t.Helper()
		command := exec.CommandContext(ctx, cliPath, arguments...)
		command.Dir = moduleRoot
		command.Env = localYUMCompatibilityEnvironment(os.Environ())
		output, err := command.CombinedOutput()
		t.Logf("sow %s\n%s", strings.Join(arguments, " "), output)
		if err != nil {
			t.Fatalf("sow %s: %v\n%s", strings.Join(arguments, " "), err, output)
		}
		return string(output)
	}
	runFailure := func(wanted string, arguments ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, cliPath, arguments...)
		command.Dir = moduleRoot
		command.Env = localYUMCompatibilityEnvironment(os.Environ())
		output, err := command.CombinedOutput()
		if err == nil || !strings.Contains(string(output), wanted) {
			t.Fatalf("sow %s err=%v output=%s, want failure containing %q", strings.Join(arguments, " "), err, output, wanted)
		}
	}

	privateKey := filepath.Join(workspace, "legacy-private.key")
	packageTrust := filepath.Join(workspace, "package-trust.asc")
	candidate := filepath.Join(t.TempDir(), "candidate")
	includePath := filepath.Join(t.TempDir(), "sow-yum-compat.locations.conf")
	common := []string{"--config", configPath, "--workers", "2", "--chunk-entries", "2"}

	run(append([]string{"init"}, common...)...)
	// The compatibility projection is selected through its ordinary active
	// owner. Seed that owner exactly as production does so the S3 pass exercises
	// the real selected-set transaction rather than an otherwise empty view.
	run(append([]string{"add", filepath.Join(fixture.root, fixture.flat), "--repo", "infra-el9", "--gpg-private-key-file", privateKey}, common...)...)
	run(append([]string{"promote", "beta", "latest", "--repo", "infra-el9"}, common...)...)
	run(append([]string{"compatibility", "yum-adopt", "--id", "infra-legacy-x86-64"}, common...)...)
	candidateOutput := run(append([]string{"compatibility", "yum-candidate", "--id", "infra-legacy-x86-64", "--output", candidate, "--gpg-private-key-file", privateKey}, common...)...)
	freezeConfirm := nginxTestOutputValue(t, candidateOutput, "freeze_confirm")
	freezeOutput := run(append([]string{"compatibility", "yum-freeze", "--id", "infra-legacy-x86-64", "--candidate", candidate, "--confirm", freezeConfirm}, common...)...)
	cutoverConfirm := nginxTestOutputValue(t, freezeOutput, "cutover_confirm")

	// S2 serves only the separately verified unsigned historical raw bridge.
	run(append([]string{"materialize", "latest", "--nginx-include", includePath}, common...)...)
	server := startYUMCompatibilityNginx(t, port, includePath)
	defer func() { server.stop(t) }()
	assertYUMCompatibilityHTTP(t, port, "/yum/infra/x86_64/repodata/repomd.xml", http.StatusOK)
	assertYUMCompatibilityHTTP(t, port, "/_sow/v1/mirrorlist/latest/infra-legacy-x86-64/cross-el/x86_64.txt", http.StatusNotFound)
	assertYUMCompatibilityHTTP(t, port, "/_sow/v1/trust/yum-compat/infra-legacy-x86-64/packages.pgp", http.StatusNotFound)
	for _, image := range localYUMCompatibilityImages() {
		runYUMCompatibilityDNF(ctx, t, image, packageTrust, rawYUMCompatibilityDNFScript(port))
	}

	cutoverOutput := run(append([]string{"compatibility", "yum-cutover", "--id", "infra-legacy-x86-64", "--confirm", cutoverConfirm}, common...)...)
	rollbackConfirm := nginxTestOutputValue(t, cutoverOutput, "rollback_confirm")
	// Canonical S3 authority alone is not routable until the ordinary local
	// materialization transaction installs generation, mirrorlist and trust.
	runFailure("active compatibility", append([]string{"materialize", "latest", "--nginx-include", "-"}, common...)...)
	assertYUMCompatibilityHTTP(t, port, "/_sow/v1/mirrorlist/latest/infra-legacy-x86-64/cross-el/x86_64.txt", http.StatusNotFound)
	server.stop(t)

	run(append([]string{"materialize", "latest", "--gpg-private-key-file", privateKey}, common...)...)
	run(append([]string{"materialize", "latest", "--nginx-include", includePath}, common...)...)
	server = startYUMCompatibilityNginx(t, port, includePath)
	mirrorlistPath := "/_sow/v1/mirrorlist/latest/infra-legacy-x86-64/cross-el/x86_64.txt"
	mirrorlist := assertYUMCompatibilityHTTP(t, port, mirrorlistPath, http.StatusOK)
	generationPath := yumCompatibilityGenerationPath(t, mirrorlist)
	for _, relative := range []string{
		"/_sow/v1/trust/yum-compat/infra-legacy-x86-64/packages.pgp",
		"/_sow/v1/trust/yum-compat/infra-legacy-x86-64/repository.pgp",
		generationPath + "repodata/repomd.xml",
		generationPath + "repodata/repomd.xml.asc",
	} {
		assertYUMCompatibilityHTTP(t, port, relative, http.StatusOK)
	}
	for _, image := range localYUMCompatibilityImages() {
		runYUMCompatibilityDNF(ctx, t, image, "", strongYUMCompatibilityDNFScript(port))
	}
	run(append([]string{"fsck"}, common...)...)
	run(append([]string{"verify", "--layer", "L1", "--view", "latest", "--repo", "infra-el9"}, common...)...)

	run(append([]string{"compatibility", "yum-rollback", "--id", "infra-legacy-x86-64", "--confirm", rollbackConfirm}, common...)...)
	run(append([]string{"materialize", "latest", "--gpg-private-key-file", privateKey}, common...)...)
	run(append([]string{"materialize", "latest", "--nginx-include", includePath}, common...)...)
	server.stop(t)
	server = startYUMCompatibilityNginx(t, port, includePath)
	assertYUMCompatibilityHTTP(t, port, "/yum/infra/x86_64/repodata/repomd.xml", http.StatusOK)
	for _, relative := range []string{
		mirrorlistPath,
		"/_sow/v1/trust/yum-compat/infra-legacy-x86-64/packages.pgp",
		"/_sow/v1/trust/yum-compat/infra-legacy-x86-64/repository.pgp",
		generationPath + "repodata/repomd.xml",
	} {
		assertYUMCompatibilityHTTP(t, port, relative, http.StatusNotFound)
	}
	for _, image := range localYUMCompatibilityImages() {
		runYUMCompatibilityDNF(ctx, t, image, packageTrust, rawYUMCompatibilityDNFScript(port))
	}
	run(append([]string{"fsck"}, common...)...)
	run(append([]string{"verify", "--layer", "L1", "--view", "latest", "--repo", "infra-el9"}, common...)...)

	if body, err := os.ReadFile(filepath.Join(fixture.root, fixture.flat)); err != nil || len(body) == 0 {
		t.Fatalf("rollback removed raw S0 RPM: bytes=%d err=%v", len(body), err)
	}
	archiveLink := filepath.Join(workspace, ".sow", "serving", "compatibility", "yum", "infra-legacy-x86-64", "current")
	value, err := os.Readlink(archiveLink)
	linkInfo, linkErr := os.Stat(archiveLink)
	rawInfo, rawErr := os.Stat(fixture.root)
	if err != nil || filepath.IsAbs(value) || linkErr != nil || rawErr != nil || !os.SameFile(linkInfo, rawInfo) {
		t.Fatalf("rollback serving link=%q read_err=%v link_err=%v raw_err=%v same_raw=%t", value, err, linkErr, rawErr, linkErr == nil && rawErr == nil && os.SameFile(linkInfo, rawInfo))
	}
}

func localYUMCompatibilityDockerConfig(port int) string {
	base := fmt.Sprintf("http://host.docker.internal:%d", port)
	return fmt.Sprintf(`schema: sow/v1
state: {}
gpg:
  public_key: legacy-public.key
pools: {public: {}, gated: {}}
repos:
  - id: infra-el9
    type: yum
    path: yum/infra/el9/{arch}
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
  - id: infra-carrier
    type: yum
    path: yum/infra/{arch}
    active: false
    default_pool: public
    arches: [x86_64]
    os: {family: cross-el, major: 0, lifecycle: frozen}
    yum: {compression: gzip, compatibility_carrier: true, package_keyring: package-trust.asc}
compatibility_projections:
  - id: infra-legacy-x86-64
    root: yum/infra/x86_64
    mode: frozen-cross-el
    carrier: infra-carrier
    source: {repo: infra-el9, view: latest, os: cross-el, arch: x86_64, commit: pin-at-first-freeze}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: %q}
  beta: {base_url: %q}
  stable: {base_url: %q}
targets: {}
edge: {token_verifier: provider://local-compat-test}
`, base, base, base+"/pro/v1/basic")
}

func yumCompatibilityModuleRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve compatibility test source")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(filename), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func localYUMCompatibilityEnvironment(environment []string) []string {
	blocked := []string{
		"AWS_", "CF_", "CLOUDFLARE_", "TENCENT_", "TENCENTCLOUD_",
		"SOW_REAL_", "SOW_CF", "SOW_COS", "SOW_R2", "SOW_CLOUDFLARE", "SOW_TENCENT", "SOW_AWS",
		"HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "NO_PROXY=", "GOPROXY=",
	}
	result := make([]string, 0, len(environment)+12)
	for _, item := range environment {
		upper := strings.ToUpper(item)
		forbidden := false
		for _, prefix := range blocked {
			if strings.HasPrefix(upper, prefix) {
				forbidden = true
				break
			}
		}
		if !forbidden && !strings.HasPrefix(upper, "SOW_RUN_REAL_") {
			result = append(result, item)
		}
	}
	return append(result,
		"AWS_SHARED_CREDENTIALS_FILE=/dev/null",
		"AWS_CONFIG_FILE=/dev/null",
		"AWS_EC2_METADATA_DISABLED=true",
		"SOW_RUN_REAL_CLOUD=0",
		"SOW_RUN_REAL_EDGE_EVIDENCE=0",
		"SOW_RUN_REAL_UPSTREAM=0",
		"SOW_REAL_CLOUD_PURGE_WATCHER_HELPER=0",
		"HTTP_PROXY=http://127.0.0.1:1",
		"HTTPS_PROXY=http://127.0.0.1:1",
		"ALL_PROXY=http://127.0.0.1:1",
		"NO_PROXY=127.0.0.1,localhost,host.docker.internal",
		"GOPROXY=off",
	)
}

func localYUMCompatibilityImages() []string {
	image := func(name, fallback string) string {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
		return fallback
	}
	return []string{
		image("SOW_COMPAT_EL8_IMAGE", "almalinux:8"),
		image("SOW_COMPAT_EL9_IMAGE", "almalinux:9"),
		image("SOW_COMPAT_DNF_IMAGE", "almalinux:10"),
	}
}

func reserveYUMCompatibilityPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

type yumCompatibilityNginxProcess struct {
	cancel      context.CancelFunc
	done        chan error
	diagnostics *bytes.Buffer
}

func startYUMCompatibilityNginx(t *testing.T, port int, includePath string) *yumCompatibilityNginxProcess {
	t.Helper()
	executable, err := exec.LookPath("nginx")
	if err != nil {
		t.Fatal(err)
	}
	prefix := t.TempDir()
	configPath := filepath.Join(prefix, "nginx.conf")
	document := fmt.Sprintf(`master_process off;
worker_processes 1;
pid %s;
error_log stderr notice;
events { worker_connections 128; }
http {
  access_log %s combined;
  server {
    listen 127.0.0.1:%d;
    include %s;
  }
}
`, quoteYUMCompatibilityNginx(filepath.Join(prefix, "nginx.pid")), quoteYUMCompatibilityNginx(filepath.Join(prefix, "access.log")), port, quoteYUMCompatibilityNginx(includePath))
	if err := os.WriteFile(configPath, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	check := exec.Command(executable, "-p", prefix, "-c", configPath, "-t")
	check.Env = localYUMCompatibilityEnvironment(os.Environ())
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("Nginx rejected product include: %v\n%s", err, output)
	}
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, executable, "-p", prefix, "-c", configPath, "-g", "daemon off;")
	command.Env = localYUMCompatibilityEnvironment(os.Environ())
	diagnostics := &bytes.Buffer{}
	command.Stdout, command.Stderr = diagnostics, diagnostics
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
	return &yumCompatibilityNginxProcess{cancel: cancel, done: done, diagnostics: diagnostics}
}

func quoteYUMCompatibilityNginx(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

func (process *yumCompatibilityNginxProcess) stop(t *testing.T) {
	t.Helper()
	if process == nil || process.cancel == nil {
		return
	}
	process.cancel()
	select {
	case err := <-process.done:
		if err != nil && !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "signal: killed") {
			t.Fatalf("stop local Nginx: %v\n%s", err, process.diagnostics.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("local Nginx did not stop")
	}
	process.cancel = nil
}

func assertYUMCompatibilityHTTP(t *testing.T, port int, relative string, wanted int) string {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, relative))
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal(errors.Join(readErr, closeErr))
	}
	if response.StatusCode != wanted {
		t.Fatalf("GET %s status=%d body=%q, want %d", relative, response.StatusCode, body, wanted)
	}
	return string(body)
}

func yumCompatibilityGenerationPath(t *testing.T, mirrorlist string) string {
	t.Helper()
	value := strings.TrimSpace(mirrorlist)
	prefix := "http://host.docker.internal:"
	if !strings.HasPrefix(value, prefix) {
		t.Fatalf("compatibility mirrorlist is not the local test origin: %q", value)
	}
	index := strings.Index(value[len(prefix):], "/")
	if index < 0 {
		t.Fatalf("compatibility mirrorlist has no generation path: %q", value)
	}
	result := value[len(prefix)+index:]
	if !strings.HasPrefix(result, "/_sow/v1/g/") || !strings.HasSuffix(result, "/yum/infra/x86_64/") {
		t.Fatalf("compatibility mirrorlist has unexpected generation root: %q", value)
	}
	return result
}

func runYUMCompatibilityDNF(ctx context.Context, t *testing.T, image, packageTrust, script string) {
	t.Helper()
	inspect := exec.CommandContext(ctx, "docker", "image", "inspect", image)
	inspect.Env = localYUMCompatibilityEnvironment(os.Environ())
	if output, err := inspect.CombinedOutput(); err != nil {
		t.Fatalf("DNF image %s must be preloaded; automatic network pulls are forbidden: %v\n%s", image, err, output)
	}
	arguments := []string{"run", "--rm", "--pull", "never"}
	if runtime.GOOS == "linux" {
		arguments = append(arguments, "--network", "host", "--add-host", "host.docker.internal:127.0.0.1")
	} else {
		arguments = append(arguments, "--add-host", "host.docker.internal:host-gateway")
	}
	arguments = append(arguments,
		"--dns", "127.0.0.1",
		"-e", "HTTP_PROXY=", "-e", "HTTPS_PROXY=", "-e", "ALL_PROXY=",
		"-e", "NO_PROXY=127.0.0.1,localhost,host.docker.internal",
	)
	if packageTrust != "" {
		arguments = append(arguments, "-v", packageTrust+":/run/sow-keys/packages.pgp:ro")
	}
	arguments = append(arguments, image, "/bin/bash", "-ceu", script)
	command := exec.CommandContext(ctx, "docker", arguments...)
	command.Env = localYUMCompatibilityEnvironment(os.Environ())
	output, err := command.CombinedOutput()
	t.Logf("DNF image=%s\n%s", image, output)
	if err != nil {
		t.Fatalf("real DNF compatibility image %s: %v\n%s", image, err, output)
	}
}

func rawYUMCompatibilityDNFScript(port int) string {
	return fmt.Sprintf(`
rpm -e pgdg-redhat-nonfree-repo >/dev/null 2>&1 || true
for key in $(rpm -qa 'gpg-pubkey-08b40d20*'); do rpm -e "$key"; done
cat > /etc/yum.repos.d/sow-yum-compat.repo <<'EOF'
[sow-yum-compat]
name=SOW unsigned historical raw compatibility bridge
baseurl=http://host.docker.internal:%d/yum/infra/x86_64/
enabled=1
gpgcheck=1
repo_gpgcheck=0
gpgkey=file:///run/sow-keys/packages.pgp
metadata_expire=0
skip_if_unavailable=0
EOF
rm -rf /var/cache/dnf
dnf -y --disablerepo='*' --enablerepo=sow-yum-compat --setopt=install_weak_deps=False makecache --refresh
dnf -y --disablerepo='*' --enablerepo=sow-yum-compat --setopt=install_weak_deps=False --setopt=keepcache=True install pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch
test "$(rpm -q --qf '%%{VERSION}-%%{RELEASE}.%%{ARCH}' pgdg-redhat-nonfree-repo)" = '42.0-20PGDG.noarch'
downloaded="$(find /var/cache/dnf -type f -name 'pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm' -print -quit)"
test -n "$downloaded"
rpm -K "$downloaded" | grep -Eq ': digests signatures OK$'
`, port)
}

func strongYUMCompatibilityDNFScript(port int) string {
	return fmt.Sprintf(`
rpm -e pgdg-redhat-nonfree-repo >/dev/null 2>&1 || true
for key in $(rpm -qa 'gpg-pubkey-08b40d20*'); do rpm -e "$key"; done
cat > /etc/yum.repos.d/sow-yum-compat.repo <<'EOF'
[sow-yum-compat]
name=SOW strong generation-pinned compatibility repository
mirrorlist=http://host.docker.internal:%d/_sow/v1/mirrorlist/latest/infra-legacy-x86-64/cross-el/x86_64.txt
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=http://host.docker.internal:%d/_sow/v1/trust/yum-compat/infra-legacy-x86-64/packages.pgp http://host.docker.internal:%d/_sow/v1/trust/yum-compat/infra-legacy-x86-64/repository.pgp
metadata_expire=0
skip_if_unavailable=0
EOF
rm -rf /var/cache/dnf
dnf -y --disablerepo='*' --enablerepo=sow-yum-compat --setopt=install_weak_deps=False makecache --refresh
dnf -y --disablerepo='*' --enablerepo=sow-yum-compat --setopt=install_weak_deps=False --setopt=keepcache=True install pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch
test "$(rpm -q --qf '%%{VERSION}-%%{RELEASE}.%%{ARCH}' pgdg-redhat-nonfree-repo)" = '42.0-20PGDG.noarch'
downloaded="$(find /var/cache/dnf -type f -name 'pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm' -print -quit)"
test -n "$downloaded"
rpm -K "$downloaded" | grep -Eq ': digests signatures OK$'
`, port, port, port)
}
