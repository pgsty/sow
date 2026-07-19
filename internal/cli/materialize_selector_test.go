package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/views"
)

func TestMaterializePartialAPTIsSuiteWideAndPreservesFixedTargetSiblings(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAPTSelectorConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "apt/one", "apt/two")
	keyPath := writePublishTestPrivateKey(t, root)
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	add := func(repo, suite, name, version, arch string) {
		t.Helper()
		input := writeSelectorDEB(t, root, name, version, arch)
		code, stdout, stderr := run("add", input, "--config", configPath, "--repo", repo, "--os", suite, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2")
		if code != ExitOK {
			t.Fatalf("add %s/%s/%s code=%d stdout=%s stderr=%s", repo, suite, arch, code, stdout, stderr)
		}
	}

	add("deb-one", "jammy", "jammy-shared", "1.0-1", "all")
	add("deb-one", "bookworm", "bookworm-shared", "1.0-1", "all")
	add("deb-two", "jammy", "repo-two-shared", "1.0-1", "all")
	if code, stdout, stderr := run("materialize", "beta", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("full view materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	// --arch is only the suite trigger: the selected jammy Release must cover
	// both configured/ref-backed arches, while the unselected bookworm suite
	// and sibling repository already present in this fixed target survive.
	if code, stdout, stderr := run("materialize", "beta", "--config", configPath, "--repo", "deb-one", "--os", "jammy", "--arch", "amd64", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("partial view materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	viewRoot := filepath.Join(root, ".sow", "materialized", "beta")
	for _, relative := range []string{
		"apt/one/dists/jammy/main/binary-amd64/Packages",
		"apt/one/dists/jammy/main/binary-arm64/Packages",
		"apt/one/dists/bookworm/main/binary-amd64/Packages",
		"apt/two/dists/jammy/main/binary-arm64/Packages",
	} {
		if _, err := os.Stat(filepath.Join(viewRoot, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("partial view materialization lost closure path %s: %v", relative, err)
		}
	}
	release, err := os.ReadFile(filepath.Join(viewRoot, "apt", "one", "dists", "jammy", "Release"))
	if err != nil || !bytes.Contains(release, []byte("main/binary-amd64/Packages")) || !bytes.Contains(release, []byte("main/binary-arm64/Packages")) {
		t.Fatalf("partial view emitted an architecture-fragment Release err=%v body=%s", err, release)
	}

	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath); code != ExitOK {
		t.Fatalf("promote latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	snapshotID, err := views.SnapshotID("jammy", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("promote", "stable", snapshotID, "--config", configPath); code != ExitOK {
		t.Fatalf("create snapshot code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("materialize", snapshotID, "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("full snapshot materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("materialize", snapshotID, "--config", configPath, "--repo", "deb-one", "--arch", "amd64", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("partial snapshot materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	snapshotRoot := filepath.Join(root, ".sow", "materialized", "snapshots", snapshotID)
	for _, relative := range []string{
		"apt/one/dists/" + snapshotID + "/main/binary-amd64/Packages",
		"apt/one/dists/" + snapshotID + "/main/binary-arm64/Packages",
		"apt/two/dists/" + snapshotID + "/main/binary-amd64/Packages",
		"apt/two/dists/" + snapshotID + "/main/binary-arm64/Packages",
	} {
		if _, err := os.Stat(filepath.Join(snapshotRoot, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("partial snapshot replay lost fixed-root sibling %s: %v", relative, err)
		}
	}
	snapshotRelease, err := os.ReadFile(filepath.Join(snapshotRoot, "apt", "one", "dists", snapshotID, "Release"))
	if err != nil || !strings.Contains(string(snapshotRelease), "main/binary-amd64/Packages") || !strings.Contains(string(snapshotRelease), "main/binary-arm64/Packages") {
		t.Fatalf("partial snapshot emitted an architecture-fragment Release err=%v body=%s", err, snapshotRelease)
	}
}
