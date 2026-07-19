package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

func TestPromoteCLIUsesCanonicalRefsAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("asset"))
	entry := views.Entry{
		Repo: "asset", OS: "all", Arch: "all", Name: "asset", Version: "1",
		Path: "asset/file", Size: 5, SHA256: hex.EncodeToString(digest[:]), Pool: "public",
	}
	var manifest bytes.Buffer
	if err := views.WriteEntry(&manifest, entry); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "beta.tsv")
	if err := os.WriteFile(stage, manifest.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	store := state.New(filepath.Join(root, ".sow"))
	viewPath, err := state.ViewPath("beta", "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	commit, changed, err := store.InstallPaths(map[string]string{
		"config/sow.yaml": configPath,
		viewPath:          stage,
	}, "seed beta")
	if err != nil || !changed {
		t.Fatalf("seed commit=%s changed=%v err=%v", commit, changed, err)
	}
	ref, err := state.ViewRef("beta", "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceRef(ref, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Main([]string{"promote", "beta", "latest", "--config", configPath}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "destination=latest") {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	latestRef, err := state.ViewRef("latest", "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	latestHash, exists, err := store.Ref(latestRef)
	if err != nil || !exists {
		t.Fatalf("latest ref=%s exists=%v err=%v", latestHash, exists, err)
	}
	latestPath, _ := state.ViewPath("latest", "asset", "all", "all")
	reader, err := store.OpenPathAt(latestHash, latestPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := views.ValidateLeaf(reader, "asset", "all", "all", true); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	stableRef, _ := state.ViewRef("stable", "asset", "all", "all")
	stableHash, exists, err := store.Ref(stableRef)
	if err != nil || !exists {
		t.Fatalf("stable was not extended automatically: hash=%s exists=%v err=%v", stableHash, exists, err)
	}
	stablePath, _ := state.ViewPath("stable", "asset", "all", "all")
	stableReader, err := store.OpenPathAt(stableHash, stablePath)
	if err != nil {
		t.Fatal(err)
	}
	stableContents, err := io.ReadAll(stableReader)
	if closeErr := stableReader.Close(); err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	if !bytes.Equal(stableContents, manifest.Bytes()) {
		t.Fatalf("stable does not contain promoted latest bytes: %q", stableContents)
	}

	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"promote", "beta", "latest", "--config", configPath}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "promote unchanged") {
		t.Fatalf("idempotent promote code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestPromoteMutableAssetAdvancesLatestAndStableWithoutRewritingHistory(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "tool.bin")
	oldBody, newBody := []byte("tool-v1\n"), []byte("tool-v2\n")
	if err := os.WriteFile(input, oldBody, 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(arguments ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	for _, command := range [][]string{
		{"add", input, "--config", configPath, "--repo", "asset", "--dest", "tool.bin"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "asset"},
	} {
		if code, stdout, stderr := run(command...); code != ExitOK {
			t.Fatalf("command=%v code=%d stdout=%s stderr=%s", command, code, stdout, stderr)
		}
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	latestRef, _ := state.ViewRef("latest", "asset", "all", "all")
	stableRef, _ := state.ViewRef("stable", "asset", "all", "all")
	latestPath, _ := state.ViewPath("latest", "asset", "all", "all")
	stablePath, _ := state.ViewPath("stable", "asset", "all", "all")
	oldLatest, latestExists, err := canonical.Ref(latestRef)
	if err != nil || !latestExists {
		t.Fatalf("old latest exists=%v err=%v", latestExists, err)
	}
	oldStable, stableExists, err := canonical.Ref(stableRef)
	if err != nil || !stableExists {
		t.Fatalf("old stable exists=%v err=%v", stableExists, err)
	}

	snapshotID, err := views.SnapshotID("all", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("promote", "stable", snapshotID, "--config", configPath, "--repo", "asset"); code != ExitOK {
		t.Fatalf("snapshot code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	snapshotRef, _ := state.SnapshotRef(snapshotID, "asset", "all", "all")
	snapshotPath, _ := state.SnapshotPath(snapshotID, "asset", "all", "all")
	snapshotCommit, snapshotExists, err := canonical.Ref(snapshotRef)
	if err != nil || !snapshotExists {
		t.Fatalf("snapshot exists=%v err=%v", snapshotExists, err)
	}

	if err := os.WriteFile(input, newBody, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{"add", input, "--replace", "--config", configPath, "--repo", "asset", "--dest", "tool.bin"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "asset"},
	} {
		if code, stdout, stderr := run(command...); code != ExitOK {
			t.Fatalf("replacement command=%v code=%d stdout=%s stderr=%s", command, code, stdout, stderr)
		}
	}
	newLatest, _, err := canonical.Ref(latestRef)
	if err != nil || newLatest == oldLatest {
		t.Fatalf("latest did not advance old=%s new=%s err=%v", oldLatest, newLatest, err)
	}
	newStable, _, err := canonical.Ref(stableRef)
	if err != nil || newStable == oldStable {
		t.Fatalf("stable did not advance old=%s new=%s err=%v", oldStable, newStable, err)
	}
	readEntry := func(commit plumbing.Hash, manifestPath string) views.Entry {
		t.Helper()
		reader, err := canonical.OpenPathAt(commit, manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		entry, err := views.NewReader(reader).Next()
		if err != nil {
			t.Fatal(err)
		}
		return entry
	}
	oldSHA, newSHA := fmt.Sprintf("%x", sha256.Sum256(oldBody)), fmt.Sprintf("%x", sha256.Sum256(newBody))
	for label, entry := range map[string]views.Entry{
		"old-latest": readEntry(oldLatest, latestPath),
		"old-stable": readEntry(oldStable, stablePath),
		"snapshot":   readEntry(snapshotCommit, snapshotPath),
	} {
		if entry.SHA256 != oldSHA {
			t.Fatalf("%s history changed sha=%s want=%s", label, entry.SHA256, oldSHA)
		}
	}
	for label, entry := range map[string]views.Entry{
		"latest": readEntry(newLatest, latestPath),
		"stable": readEntry(newStable, stablePath),
	} {
		if entry.SHA256 != newSHA {
			t.Fatalf("%s mutable pointer did not advance sha=%s want=%s", label, entry.SHA256, newSHA)
		}
	}
	if code, stdout, stderr := run("promote", "stable", snapshotID, "--config", configPath, "--repo", "asset"); code != ExitVerification || !strings.Contains(stderr, "view conflict") {
		t.Fatalf("snapshot rewrite code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if after, _, err := canonical.Ref(snapshotRef); err != nil || after != snapshotCommit {
		t.Fatalf("snapshot ref moved from %s to %s err=%v", snapshotCommit, after, err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	for label, digest := range map[string]repository.Digest{
		"old": repository.Digest(sha256.Sum256(oldBody)),
		"new": repository.Digest(sha256.Sum256(newBody)),
	} {
		if _, err := os.Stat(pool.ObjectPath(digest)); err != nil {
			t.Fatalf("%s CAS object missing: %v", label, err)
		}
	}
}

func TestPromoteCLIAllocatesScratchFilesForUnchangedLeaves(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	const twoAssetConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - {id: a, type: asset, path: a, default_pool: public, asset: {kind: test}}
  - {id: b, type: asset, path: b, default_pool: public, asset: {kind: test}}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
	if err := os.WriteFile(configPath, []byte(twoAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	writeLeaf := func(filename, repo string) {
		t.Helper()
		digest := sha256.Sum256([]byte(repo))
		var contents bytes.Buffer
		if err := views.WriteEntry(&contents, views.Entry{
			Repo: repo, OS: "all", Arch: "all", Name: repo, Version: "1",
			Path: repo + "/file", Size: 1, SHA256: hex.EncodeToString(digest[:]), Pool: "public",
		}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, contents.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	latestA, latestB, stableA := filepath.Join(root, "latest-a.tsv"), filepath.Join(root, "latest-b.tsv"), filepath.Join(root, "stable-a.tsv")
	writeLeaf(latestA, "a")
	writeLeaf(latestB, "b")
	writeLeaf(stableA, "a")
	latestAPath, _ := state.ViewPath("latest", "a", "all", "all")
	latestBPath, _ := state.ViewPath("latest", "b", "all", "all")
	stableAPath, _ := state.ViewPath("stable", "a", "all", "all")
	store := state.New(filepath.Join(root, ".sow"))
	latestCommit, _, err := store.InstallPaths(map[string]string{
		latestAPath: latestA, latestBPath: latestB, "config/sow.yaml": configPath,
	}, "seed latest")
	if err != nil {
		t.Fatal(err)
	}
	for _, repo := range []string{"a", "b"} {
		ref, _ := state.ViewRef("latest", repo, "all", "all")
		if err := store.AdvanceRef(ref, plumbing.ZeroHash, latestCommit, false); err != nil {
			t.Fatal(err)
		}
	}
	stableCommit, _, err := store.InstallPaths(map[string]string{stableAPath: stableA}, "seed first stable leaf")
	if err != nil {
		t.Fatal(err)
	}
	stableARef, _ := state.ViewRef("stable", "a", "all", "all")
	if err := store.AdvanceRef(stableARef, plumbing.ZeroHash, stableCommit, false); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Main([]string{"promote", "latest", "stable", "--config", configPath}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stableBRef, _ := state.ViewRef("stable", "b", "all", "all")
	if _, exists, err := store.Ref(stableBRef); err != nil || !exists {
		t.Fatalf("second stable leaf exists=%v err=%v", exists, err)
	}
}

func TestPromoteCLIRejectsGatedEntryInPublicSource(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("secret"))
	entry := views.Entry{Repo: "asset", OS: "all", Arch: "all", Name: "secret", Version: "1", Path: "asset/secret", Size: 6, SHA256: hex.EncodeToString(digest[:]), Pool: "gated"}
	var manifest bytes.Buffer
	if err := views.WriteEntry(&manifest, entry); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "bad.tsv")
	if err := os.WriteFile(stage, manifest.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	store := state.New(filepath.Join(root, ".sow"))
	viewPath, _ := state.ViewPath("beta", "asset", "all", "all")
	commit, _, err := store.InstallPaths(map[string]string{
		"config/sow.yaml": configPath,
		viewPath:          stage,
	}, "seed invalid beta")
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := state.ViewRef("beta", "asset", "all", "all")
	if err := store.AdvanceRef(ref, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"promote", "beta", "latest", "--config", configPath}, &stdout, &stderr)
	if code != ExitVerification || !strings.Contains(stderr.String(), "closure violation") {
		t.Fatalf("gated promote code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestPromoteStableCreatesImmutableSnapshotRef(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	makeEntry := func(name string) views.Entry {
		digest := sha256.Sum256([]byte(name))
		return views.Entry{Repo: "asset", OS: "all", Arch: "all", Name: name, Version: "1", Path: "asset/" + name, Size: int64(len(name)), SHA256: hex.EncodeToString(digest[:]), Pool: "public"}
	}
	writeView := func(path string, entries ...views.Entry) {
		t.Helper()
		var contents bytes.Buffer
		for _, entry := range entries {
			if err := views.WriteEntry(&contents, entry); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(path, contents.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	stablePath, _ := state.ViewPath("stable", "asset", "all", "all")
	stage := filepath.Join(root, "stable.tsv")
	a, b := makeEntry("a"), makeEntry("b")
	writeView(stage, a)
	stableCommit, _, err := canonical.InstallPaths(map[string]string{
		"config/sow.yaml": configPath,
		stablePath:        stage,
	}, "seed stable")
	if err != nil {
		t.Fatal(err)
	}
	stableRef, _ := state.ViewRef("stable", "asset", "all", "all")
	if err := canonical.AdvanceRef(stableRef, plumbing.ZeroHash, stableCommit, false); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	snapshotID, err := views.SnapshotID("all", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	code := Main([]string{"promote", "stable", snapshotID, "--config", configPath}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("snapshot code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	snapshotRef, _ := state.SnapshotRef(snapshotID, "asset", "all", "all")
	snapshotCommit, exists, err := canonical.Ref(snapshotRef)
	if err != nil || !exists {
		t.Fatalf("snapshot ref commit=%s exists=%v err=%v", snapshotCommit, exists, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"promote", "stable", snapshotID, "--config", configPath}, &stdout, &stderr); code != ExitOK || !strings.Contains(stdout.String(), "unchanged") {
		t.Fatalf("snapshot replay code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	writeView(stage, a, b)
	next, _, err := canonical.InstallPaths(map[string]string{stablePath: stage}, "append stable")
	if err != nil {
		t.Fatal(err)
	}
	if err := canonical.AdvanceRef(stableRef, stableCommit, next, false); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"promote", "stable", snapshotID, "--config", configPath}, &stdout, &stderr)
	if code != ExitConflict || !strings.Contains(stderr.String(), "already exists with different content") {
		t.Fatalf("snapshot rewrite code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	after, _, err := canonical.Ref(snapshotRef)
	if err != nil || after != snapshotCommit {
		t.Fatalf("snapshot moved from %s to %s err=%v", snapshotCommit, after, err)
	}
}

func TestPromoteAPTSnapshotArchSelectorIsAtomicSuiteTrigger(t *testing.T) {
	seed := func(t *testing.T, complete bool) (string, *state.Store) {
		t.Helper()
		root := t.TempDir()
		configPath := filepath.Join(root, "sow.yaml")
		if err := os.WriteFile(configPath, []byte(multiSuiteAPTInitConfig), 0o600); err != nil {
			t.Fatal(err)
		}
		canonical := state.New(filepath.Join(root, ".sow"))
		pool, err := repository.NewStore(root)
		if err != nil {
			t.Fatal(err)
		}
		debPath := decodeLegacyFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(root, "fixture.deb"))
		pkg, err := aptrepo.InspectPackage(t.Context(), debPath, "main")
		if err != nil {
			t.Fatal(err)
		}
		object, err := pool.Import(t.Context(), debPath)
		if err != nil {
			t.Fatal(err)
		}
		staged := make(map[string]string)
		arches := []string{"amd64"}
		if complete {
			arches = append(arches, "arm64")
		}
		for _, arch := range arches {
			entry := views.Entry{
				Repo: "apt-test", OS: "bookworm", Arch: arch, Name: pkg.Name, Version: pkg.Version,
				Path: "apt/test/" + pkg.PoolPath, Size: object.Size, SHA256: object.HashString(), Pool: "public",
			}
			stage := filepath.Join(root, "stable-"+arch+".tsv")
			file, err := os.OpenFile(stage, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			writeErr := views.WriteEntry(file, entry)
			closeErr := file.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatal(errors.Join(writeErr, closeErr))
			}
			canonicalPath, _ := state.ViewPath("stable", entry.Repo, entry.OS, entry.Arch)
			staged[canonicalPath] = stage
		}
		staged["config/sow.yaml"] = configPath
		commit, _, err := canonical.InstallPaths(staged, "seed APT stable suite")
		if err != nil {
			t.Fatal(err)
		}
		for _, arch := range arches {
			ref, _ := state.ViewRef("stable", "apt-test", "bookworm", arch)
			if err := canonical.AdvanceRef(ref, plumbing.ZeroHash, commit, false); err != nil {
				t.Fatal(err)
			}
		}
		return configPath, canonical
	}

	snapshotID, err := views.SnapshotID("bookworm", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	configPath, canonical := seed(t, true)
	var stdout, stderr bytes.Buffer
	code := Main([]string{"promote", "stable", snapshotID, "--config", configPath, "--repo", "apt-test", "--os", "bookworm", "--arch", "amd64"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("suite-closed APT snapshot code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var snapshotCommit plumbing.Hash
	for _, arch := range []string{"amd64", "arm64"} {
		ref, _ := state.SnapshotRef(snapshotID, "apt-test", "bookworm", arch)
		commit, exists, err := canonical.Ref(ref)
		if err != nil || !exists {
			t.Fatalf("snapshot sibling %s exists=%v err=%v", arch, exists, err)
		}
		if snapshotCommit.IsZero() {
			snapshotCommit = commit
		} else if commit != snapshotCommit {
			t.Fatalf("APT snapshot sibling refs are not one atomic commit: %s != %s", commit, snapshotCommit)
		}
	}

	incompletePath, incomplete := seed(t, false)
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"promote", "stable", snapshotID, "--config", incompletePath, "--repo", "apt-test", "--os", "bookworm", "--arch", "amd64"}, &stdout, &stderr)
	if code != ExitConflict || !strings.Contains(stderr.String(), "configured sibling ref") || !strings.Contains(stderr.String(), "arm64") {
		t.Fatalf("partial APT snapshot source code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, arch := range []string{"amd64", "arm64"} {
		ref, _ := state.SnapshotRef(snapshotID, "apt-test", "bookworm", arch)
		if _, exists, err := incomplete.Ref(ref); err != nil || exists {
			t.Fatalf("rejected partial snapshot left ref %s exists=%v err=%v", arch, exists, err)
		}
	}

	partialPath, partial := seed(t, true)
	stableRef, _ := state.ViewRef("stable", "apt-test", "bookworm", "amd64")
	stableCommit, exists, err := partial.Ref(stableRef)
	if err != nil || !exists {
		t.Fatalf("partial destination seed source exists=%v err=%v", exists, err)
	}
	stableCanonicalPath, _ := state.ViewPath("stable", "apt-test", "bookworm", "amd64")
	reader, err := partial.OpenPathAt(stableCommit, stableCanonicalPath)
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(filepath.Dir(partialPath), "partial-snapshot-amd64.tsv")
	file, err := os.OpenFile(stage, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		reader.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(file, reader)
	closeErr := errors.Join(reader.Close(), file.Close())
	if copyErr != nil || closeErr != nil {
		t.Fatal(errors.Join(copyErr, closeErr))
	}
	snapshotPath, _ := state.SnapshotPath(snapshotID, "apt-test", "bookworm", "amd64")
	partialCommit, _, err := partial.InstallPaths(map[string]string{snapshotPath: stage}, "seed legacy partial APT snapshot")
	if err != nil {
		t.Fatal(err)
	}
	partialRef, _ := state.SnapshotRef(snapshotID, "apt-test", "bookworm", "amd64")
	if err := partial.AdvanceRef(partialRef, plumbing.ZeroHash, partialCommit, true); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"promote", "stable", snapshotID, "--config", partialPath, "--repo", "apt-test", "--os", "bookworm", "--arch", "amd64"}, &stdout, &stderr)
	if code != ExitConflict || !strings.Contains(stderr.String(), "immutable sibling ref") || !strings.Contains(stderr.String(), "arm64") {
		t.Fatalf("partial immutable APT snapshot supplementation code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	missingRef, _ := state.SnapshotRef(snapshotID, "apt-test", "bookworm", "arm64")
	if _, exists, err := partial.Ref(missingRef); err != nil || exists {
		t.Fatalf("rejected supplementation created arm64 snapshot ref exists=%v err=%v", exists, err)
	}
}

func TestPromoteSnapshotRejectsDateThatDoesNotNameSourceCommit(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("asset"))
	entry := views.Entry{Repo: "asset", OS: "all", Arch: "all", Name: "asset", Version: "1", Path: "asset/file", Size: 5, SHA256: hex.EncodeToString(digest[:]), Pool: "public"}
	var contents bytes.Buffer
	if err := views.WriteEntry(&contents, entry); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "stable.tsv")
	if err := os.WriteFile(stage, contents.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	stablePath, _ := state.ViewPath("stable", "asset", "all", "all")
	commit, _, err := canonical.InstallPaths(map[string]string{
		"config/sow.yaml": configPath,
		stablePath:        stage,
	}, "seed stable")
	if err != nil {
		t.Fatal(err)
	}
	stableRef, _ := state.ViewRef("stable", "asset", "all", "all")
	if err := canonical.AdvanceRef(stableRef, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}
	wrong := "all-" + time.Now().UTC().AddDate(0, 0, -1).Format("20060102")
	var stdout, stderr bytes.Buffer
	code := Main([]string{"promote", "stable", wrong, "--config", configPath}, &stdout, &stderr)
	if code != ExitConflict || !strings.Contains(stderr.String(), "does not match the UTC capture date") {
		t.Fatalf("date mismatch code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}
