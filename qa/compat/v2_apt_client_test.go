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

func TestV2SignedManagedClientCompatibility(t *testing.T) {
	if os.Getenv("SOW_RUN_DOCKER_COMPAT") != "1" {
		t.Skip("set SOW_RUN_DOCKER_COMPAT=1 to run the signed managed client test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	moduleRoot := findModuleRoot(t)
	work := hostableCompatTempDir(t)
	environment := cleanRoomV2Environment(t, work)
	cliPath := buildCleanRoomV2CLI(ctx, t, moduleRoot, work, environment)

	keyDir := filepath.Join(work, "keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey, publicKey := writeSigningKey(t, keyDir)
	publicAsc := filepath.Join(keyDir, "signing-public.asc")

	workspace := filepath.Join(work, "managed")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	configYAML := fmt.Sprintf(`schema: sow/v3
architectures:
  - x86_64
  - aarch64
repos:
  repo:
    signing:
      rpm:
        metadata:
          key: file://%s
      deb:
        metadata:
          key: file://%s
    dists:
      el9:
        format: rpm
      noble:
        format: deb
`, filepath.ToSlash(privateKey), filepath.ToSlash(privateKey))
	writeFile(t, filepath.Join(workspace, "sow.yml"), []byte(configYAML), 0o644)

	assertCleanRoomV2JSONSuccess(t, runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment, "init", workspace, "--json"), "init")

	inputs := filepath.Join(work, "inputs")
	if err := os.MkdirAll(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	debPath := writeInstallableDEB(t, inputs, debVersion)
	rpmPath := decodeBase64Fixture(t,
		filepath.Join(moduleRoot, "internal", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"),
		filepath.Join(inputs, "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm"),
	)
	assertCleanRoomV2JSONSuccess(t, runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment, "add", debPath, "-C", workspace, "-r", "repo", "-d", "noble", "--json"), "add")
	assertCleanRoomV2JSONSuccess(t, runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment, "add", rpmPath, "-C", workspace, "-r", "repo", "-d", "el9", "--json"), "add")

	requests, port, stop := serveRepositoryHTTP(t, filepath.Join(workspace, "repo"))
	defer stop()

	aptScript := fmt.Sprintf(`
rm -f /etc/apt/sources.list.d/*
printf 'deb [arch=amd64 signed-by=/mnt/signing-public.gpg] http://host.docker.internal:%d noble main\n' > /etc/apt/sources.list
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/sow-compat-deb_*.deb
apt-get -o Acquire::Retries=0 -o Acquire::By-Hash=force update
apt-get -y --no-install-recommends -o Acquire::Retries=0 install %s=%s
test "$(dpkg-query -W -f='${Status}' %s)" = 'install ok installed'
`, port, debPackage, debVersion, debPackage)
	runDocker(ctx, t, compatImage("SOW_COMPAT_APT_IMAGE", defaultAPTImage), []string{"-v", publicKey + ":/mnt/signing-public.gpg:ro"}, aptScript)
	if !requests.contains("/dists/noble/InRelease") || !requests.contains("/by-hash/SHA256/") {
		t.Fatalf("signed APT client did not verify InRelease + by-hash; requests:\n%s", requests.String())
	}

	dnfScript := fmt.Sprintf(`
rm -f /etc/yum.repos.d/*.repo
cat > /etc/yum.repos.d/sow.repo <<'EOF'
[sow]
name=SOW Managed Signed Repo
baseurl=http://host.docker.internal:%d/dists/el9/x86_64
enabled=1
gpgcheck=0
repo_gpgcheck=1
gpgkey=file:///mnt/signing-public.asc
EOF
dnf -y --disablerepo='*' --enablerepo=sow makecache
dnf -q --disablerepo='*' --enablerepo=sow list available pgdg-redhat-nonfree-repo
`, port)
	runDocker(ctx, t, compatImage("SOW_COMPAT_EL9_IMAGE", defaultEL9Image), []string{"-v", publicAsc + ":/mnt/signing-public.asc:ro"}, dnfScript)
	if !requests.contains("/dists/el9/x86_64/repodata/repomd.xml.asc") {
		t.Fatalf("signed DNF client did not request repomd.xml.asc; requests:\n%s", requests.String())
	}
}
