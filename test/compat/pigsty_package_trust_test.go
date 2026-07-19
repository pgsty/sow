package compat_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	crpm "github.com/cavaliergopher/rpm"
	"github.com/pgsty/sow/internal/yumrepo"
)

// TestPigstyBuilderPackageTrustCompatibility proves the FR-17 builder handoff
// with a real, already-built Pigsty-signed RPM. SOW deliberately has no package
// builder, so the artifact and its public key are explicit opt-in CI inputs.
// Repository metadata is signed independently with a fresh SOW test identity;
// real DNF must reject the RPM without the builder key and install it when both
// public trust anchors are configured with gpgcheck/repo_gpgcheck enabled.
func TestPigstyBuilderPackageTrustCompatibility(t *testing.T) {
	if os.Getenv("SOW_RUN_PIGSTY_PACKAGE_TRUST") != "1" {
		t.Skip("set SOW_RUN_PIGSTY_PACKAGE_TRUST=1 with a real Pigsty-signed RPM and public key")
	}
	rpmPath := requireExternalRegularFile(t, "SOW_COMPAT_PIGSTY_RPM", 1<<30)
	packageKey := requireExternalRegularFile(t, "SOW_COMPAT_PIGSTY_PUBLIC_KEY", 1<<20)
	requirePublicOnlyOpenPGPKey(t, packageKey)

	rpmFile, err := os.Open(rpmPath)
	if err != nil {
		t.Fatal(err)
	}
	pkg, parseErr := crpm.Read(bufio.NewReader(rpmFile))
	closeErr := rpmFile.Close()
	if parseErr != nil || closeErr != nil {
		t.Fatal(errors.Join(parseErr, closeErr))
	}
	if pkg.Name() == "" || pkg.Version() == "" || pkg.Release() == "" || pkg.Architecture() == "" {
		t.Fatal("external Pigsty RPM lacks a complete NEVRA")
	}
	packageSpec := fmt.Sprintf("%s-%s-%s.%s", pkg.Name(), pkg.Version(), pkg.Release(), pkg.Architecture())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	work := t.TempDir()
	repositoryRoot := filepath.Join(work, "repository")
	location, err := yumrepo.PackageLocation(pkg.Name(), filepath.Base(rpmPath))
	if err != nil {
		t.Fatal(err)
	}
	servedRPM := filepath.Join(repositoryRoot, filepath.FromSlash(location))
	linkOrCopy(t, rpmPath, servedRPM)
	repositoryPrivate, repositoryPublic := writeSigningKey(t, work)
	private, err := os.Open(repositoryPrivate)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	signer, signerErr := yumrepo.NewOpenPGPSigner(private, nil, now)
	closeErr = private.Close()
	if signerErr != nil || closeErr != nil {
		t.Fatal(errors.Join(signerErr, closeErr))
	}
	if _, err := yumrepo.Generate(ctx, filepath.Join(repositoryRoot, "repodata"), yumrepo.Options{
		ELMajor: 10, Revision: now.Unix(), Signer: signer,
	}, &yumrepo.SliceIterator{Inputs: []yumrepo.PackageInput{{Path: servedRPM, FileTime: now}}}); err != nil {
		t.Fatal(err)
	}
	requests, port, stop := serveRepository(t, repositoryRoot, nginxRepositoryAllowlist{
		Prefixes: []string{"Packages", "repodata"},
	})
	defer stop()

	image := compatImage("SOW_COMPAT_DNF_IMAGE", defaultDNFImage)
	repositoryMount := repositoryPublic + ":/run/sow-keys/SOW-REPOSITORY:ro"
	negative := runDocker(ctx, t, image, []string{"-v", repositoryMount},
		dnfBuilderTrustScript(port, packageSpec, pkg.Name(), false))
	if !strings.Contains(negative, "missing Pigsty builder key rejected before install") {
		t.Fatalf("missing-key negative control did not complete:\n%s", negative)
	}
	positive := runDocker(ctx, t, image, []string{
		"-v", repositoryMount,
		"-v", packageKey + ":/run/sow-keys/PIGSTY-PACKAGE:ro",
	}, dnfBuilderTrustScript(port, packageSpec, pkg.Name(), true))
	if !strings.Contains(positive, "Pigsty builder package signature accepted") {
		t.Fatalf("builder trust positive control did not complete:\n%s", positive)
	}
	if !requests.contains("/"+location) || !requests.contains("/repodata/repomd.xml.asc") {
		t.Fatalf("real DNF did not fetch signed metadata and package:\n%s", requests.String())
	}
	t.Logf("pigsty_builder_trust package=%s bytes=%d requests=\n%s", packageSpec, fileSize(t, rpmPath), requests.String())
}

func requireExternalRegularFile(t *testing.T, environment string, maxBytes int64) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(environment))
	if value == "" || !filepath.IsAbs(value) || strings.ContainsAny(value, "\x00\r\n") {
		t.Fatalf("%s must name one absolute regular file", environment)
	}
	info, err := os.Lstat(value)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxBytes {
		t.Fatalf("%s is not an admissible regular file: %v", environment, err)
	}
	return value
}

func requirePublicOnlyOpenPGPKey(t *testing.T, filename string) {
	t.Helper()
	body, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(body))
	if err != nil || len(entities) == 0 {
		t.Fatalf("Pigsty package key is not a non-empty armored public key: %v", err)
	}
	for _, entity := range entities {
		if entity.PrivateKey != nil {
			t.Fatal("Pigsty package public-key input contains private material")
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PrivateKey != nil {
				t.Fatal("Pigsty package public-key input contains a private subkey")
			}
		}
	}
}

func dnfBuilderTrustScript(port int, packageSpec, packageName string, includeBuilderKey bool) string {
	keys := "file:///run/sow-keys/SOW-REPOSITORY"
	want := "failure"
	if includeBuilderKey {
		keys += " file:///run/sow-keys/PIGSTY-PACKAGE"
		want = "success"
	}
	return fmt.Sprintf(`
cat > /etc/yum.repos.d/sow-pigsty-builder.repo <<'EOF'
[sow-pigsty-builder]
name=SOW Pigsty builder trust compatibility
baseurl=http://host.docker.internal:%d/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=%s
metadata_expire=0
skip_if_unavailable=0
EOF
rm -rf /var/cache/dnf /tmp/sow-pigsty-builder.log
dnf -y --disablerepo='*' --enablerepo=sow-pigsty-builder makecache --refresh
set +e
dnf -y --disablerepo='*' --enablerepo=sow-pigsty-builder --setopt=install_weak_deps=False --setopt=keepcache=True install %q > /tmp/sow-pigsty-builder.log 2>&1
status=$?
set -e
cat /tmp/sow-pigsty-builder.log
case %q in
  failure)
    test "$status" -ne 0
    ! rpm -q %q >/dev/null 2>&1
    grep -Eiq 'GPG|public key|signature' /tmp/sow-pigsty-builder.log
    printf 'missing Pigsty builder key rejected before install\n'
    ;;
  success)
    test "$status" -eq 0
    rpm -q %q
    downloaded_rpm="$(find /var/cache/dnf -type f -name '*.rpm' -print -quit)"
    test -n "$downloaded_rpm"
    rpm_check="$(rpm -K "$downloaded_rpm")"
    printf 'rpm -K: %%s\n' "$rpm_check"
    printf '%%s\n' "$rpm_check" | grep -Eq ': digests signatures OK$'
    printf 'Pigsty builder package signature accepted\n'
    ;;
esac
`, port, keys, packageSpec, want, packageName, packageName)
}

func fileSize(t *testing.T, filename string) int64 {
	t.Helper()
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}
