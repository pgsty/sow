package compat_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestV2APTClientCompatibility proves that the current public CLI can build a
// flat DEB repository consumed by an unmodified APT client. Repository signing
// is covered separately; trusted=yes scopes this test to metadata and payload
// compatibility.
func TestV2APTClientCompatibility(t *testing.T) {
	if os.Getenv("SOW_RUN_DOCKER_COMPAT") != "1" {
		t.Skip("set SOW_RUN_DOCKER_COMPAT=1 to run the real APT client test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	moduleRoot := findModuleRoot(t)
	work := hostableCompatTempDir(t)
	environment := cleanRoomV2Environment(t, work)
	cliPath := buildCleanRoomV2CLI(ctx, t, moduleRoot, work, environment)
	repositoryRoot := filepath.Join(work, "apt-flat")
	if err := os.MkdirAll(repositoryRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	writeInstallableDEB(t, repositoryRoot, debVersion)
	output := runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment,
		"create", repositoryRoot, "--json")
	assertCleanRoomV2JSONSuccess(t, output, "create")

	requests, port, stop := serveRepositoryHTTP(t, repositoryRoot)
	defer stop()
	script := fmt.Sprintf(`
rm -f /etc/apt/sources.list.d/*
printf 'deb [arch=amd64 trusted=yes] http://host.docker.internal:%d/ ./\n' > /etc/apt/sources.list
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/sow-compat-deb_*.deb
apt-get -o Acquire::Retries=0 -o Acquire::AllowInsecureRepositories=true update
apt-cache policy %s
apt-cache madison %s | awk '{print $3}' | grep -Fx %s
apt-get -y --no-install-recommends -o Acquire::Retries=0 --allow-unauthenticated install %s=%s
test "$(dpkg-query -W -f='${Status}' %s)" = 'install ok installed'
test "$(dpkg-query -W -f='${Version}' %s)" = '%s'
test -f /usr/share/doc/sow-compat/README
`, port, debPackage, debPackage, debVersion, debPackage, debVersion, debPackage, debPackage, debVersion)
	runDocker(ctx, t, compatImage("SOW_COMPAT_APT_IMAGE", defaultAPTImage), nil, script)
	if !requests.contains("/Packages") {
		t.Fatalf("APT did not request the generated package index; requests:\n%s", requests.String())
	}
	if !requests.contains("/sow-compat-deb_" + debVersion + "_amd64.deb") {
		t.Fatalf("APT did not download the generated DEB payload; requests:\n%s", requests.String())
	}
}
