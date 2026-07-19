package cli

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

func TestAuthorizedAssetDeleteUsesExactViewProjection(t *testing.T) {
	for _, test := range []struct {
		view, source, remote, cdn string
	}{
		{view: "latest", source: "pkg/tool", remote: "pkg/tool", cdn: "pkg/tool"},
		{view: "beta", source: ".sow/materialized/beta/pkg/tool", remote: ".sow/beta/pkg/tool", cdn: "pkg/tool"},
		{view: "stable", source: ".sow/origin/gated/pkg/tool", remote: ".sow/gated/pkg/tool", cdn: "pro/v1/basic/pkg/tool"},
	} {
		t.Run(test.view, func(t *testing.T) {
			canonical := state.New(filepath.Join(t.TempDir(), ".sow"))
			entry, err := remoteInventoryEntry(test.source, 5, digestBytesCLI([]byte("asset")))
			if err != nil {
				t.Fatal(err)
			}
			oldManifest := writeDeleteTestManifest(t, []manifest.Entry{entry})
			desiredManifest := writeDeleteTestManifest(t, nil)
			// No mutable_paths match: this exercises immutable asset serving
			// deletion. The CLI protocol E2E separately covers mutable pointers.
			repo := config.Repo{ID: "assets", Type: "asset", Path: "pkg", Asset: &config.AssetConfig{}}
			prepared := preparedPublication{view: test.view, manifestPath: desiredManifest, projections: []publicationProjection{{view: test.view, repo: repo, sourceRoot: path.Dir(test.source), legacyRoot: "pkg"}}}
			if test.view == "latest" {
				prepared.projections[0].sourceRoot = "pkg"
			}
			if test.view == "beta" {
				prepared.projections[0].sourceRoot = ".sow/materialized/beta/pkg"
			}
			if test.view == "stable" {
				prepared.projections[0].sourceRoot = ".sow/origin/gated/pkg"
			}
			classifier := publicationClassifier{view: test.view, generation: 1, projections: prepared.projections}
			plan := pub.Plan{Removed: []string{test.source}}
			if err := augmentAuthorizedRemoteDeletes(canonical, prepared, classifier, oldManifest, desiredManifest, &plan); err != nil {
				t.Fatal(err)
			}
			if len(plan.Deletes) != 1 {
				t.Fatalf("deletes=%#v", plan.Deletes)
			}
			deletion := plan.Deletes[0]
			if deletion.Class != pub.DeleteAssetServing || deletion.SourcePath != test.source || deletion.RemoteKey != test.remote || deletion.CDNPath != test.cdn || deletion.Size != entry.Size || deletion.SHA256 != entry.HashString() {
				t.Fatalf("deletion=%#v", deletion)
			}
		})
	}
}

func TestAssetPublicPathProjectionRoutesEveryPublicationIntent(t *testing.T) {
	repo := config.Repo{
		ID: "bootstrap", Type: "asset", Path: "asset/bootstrap", DefaultPool: "public",
		Asset: &config.AssetConfig{Kind: "bootstrap", PublicPath: "pkg", MutablePaths: []string{"latest"}},
	}
	for _, test := range []struct {
		name, view, snapshot, sourceRoot, sourcePath, remoteKey, cdnPath string
	}{
		{
			name: "latest", view: "latest",
			sourceRoot: "asset/bootstrap", sourcePath: "asset/bootstrap/tool.tar.gz",
			remoteKey: "pkg/tool.tar.gz", cdnPath: "pkg/tool.tar.gz",
		},
		{
			name: "beta", view: "beta",
			sourceRoot: ".sow/materialized/beta/asset/bootstrap", sourcePath: ".sow/materialized/beta/asset/bootstrap/tool.tar.gz",
			remoteKey: ".sow/beta/pkg/tool.tar.gz", cdnPath: "pkg/tool.tar.gz",
		},
		{
			name: "stable", view: "stable",
			sourceRoot: ".sow/origin/gated/asset/bootstrap", sourcePath: ".sow/origin/gated/asset/bootstrap/tool.tar.gz",
			remoteKey: ".sow/gated/pkg/tool.tar.gz", cdnPath: "pro/v1/basic/pkg/tool.tar.gz",
		},
		{
			name: "snapshot", view: "snapshot", snapshot: "stable-20260714",
			sourceRoot: ".sow/materialized/snapshots/stable-20260714/asset/bootstrap", sourcePath: ".sow/materialized/snapshots/stable-20260714/asset/bootstrap/tool.tar.gz",
			remoteKey: ".sow/gated/snapshots/stable-20260714/asset/pkg/tool.tar.gz",
			cdnPath:   "pro/v1/basic/_sow/v1/snapshots/stable-20260714/assets/pkg/tool.tar.gz",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			projection := publicationProjection{
				view: test.view, repo: repo, os: "all", arch: "all", sourceRoot: test.sourceRoot,
				canonicalRoot: repo.Path, remoteRoot: repo.AssetPublicRoot(), legacyRoot: repo.Path,
			}
			if projection.canonicalPathRoot() != "asset/bootstrap" || projection.remotePathRoot() != "pkg" {
				t.Fatalf("projection roots canonical=%q remote=%q", projection.canonicalPathRoot(), projection.remotePathRoot())
			}
			classifier := publicationClassifier{
				view: test.view, snapshotID: test.snapshot, generation: 7,
				projections: []publicationProjection{projection},
			}
			remoteKey, class, err := classifier.classify(manifest.Entry{Path: test.sourcePath, Size: 1})
			if err != nil || class != pub.ObjectImmutable || remoteKey != test.remoteKey {
				t.Fatalf("route key=%q class=%s err=%v", remoteKey, class, err)
			}
			cdnPath := remoteKey
			switch test.view {
			case "beta":
				cdnPath = betaCDNPath(remoteKey)
			case "stable":
				cdnPath = proCDNPath(remoteKey)
			case "snapshot":
				cdnPath = snapshotCDNPath(test.snapshot, projection, test.sourcePath)
			}
			if cdnPath != test.cdnPath {
				t.Fatalf("cdn path=%q want=%q", cdnPath, test.cdnPath)
			}
		})
	}
}

func TestAuthorizedAssetDeleteUsesPublicPathProjection(t *testing.T) {
	canonical := state.New(filepath.Join(t.TempDir(), ".sow"))
	body := []byte("bootstrap\n")
	entry, err := remoteInventoryEntry("asset/bootstrap/tool.tar.gz", int64(len(body)), digestBytesCLI(body))
	if err != nil {
		t.Fatal(err)
	}
	oldManifest := writeDeleteTestManifest(t, []manifest.Entry{entry})
	desiredManifest := writeDeleteTestManifest(t, nil)
	repo := config.Repo{
		ID: "bootstrap", Type: "asset", Path: "asset/bootstrap",
		Asset: &config.AssetConfig{Kind: "bootstrap", PublicPath: "pkg"},
	}
	projection := publicationProjection{
		view: "latest", repo: repo, os: "all", arch: "all", sourceRoot: repo.Path,
		canonicalRoot: repo.Path, remoteRoot: repo.AssetPublicRoot(), legacyRoot: repo.Path,
	}
	prepared := preparedPublication{view: "latest", manifestPath: desiredManifest, projections: []publicationProjection{projection}}
	classifier := publicationClassifier{view: "latest", generation: 1, projections: prepared.projections}
	plan := pub.Plan{Removed: []string{entry.Path}}
	if err := augmentAuthorizedRemoteDeletes(canonical, prepared, classifier, oldManifest, desiredManifest, &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Deletes) != 1 || plan.Deletes[0].RemoteKey != "pkg/tool.tar.gz" || plan.Deletes[0].CDNPath != "pkg/tool.tar.gz" {
		t.Fatalf("projected deletion=%#v", plan.Deletes)
	}
}

func TestRestoreAssetDeleteRequiresExactParentManifestBinding(t *testing.T) {
	canonical := state.New(filepath.Join(t.TempDir(), ".sow"))
	body := []byte("historical-extra\n")
	entry, err := remoteInventoryEntry(".sow/materialized/beta/pkg/extra", int64(len(body)), digestBytesCLI(body))
	if err != nil {
		t.Fatal(err)
	}
	oldManifest := writeDeleteTestManifest(t, []manifest.Entry{entry})
	desiredManifest := writeDeleteTestManifest(t, nil)
	digest, err := hashRegularPath(oldManifest)
	if err != nil {
		t.Fatal(err)
	}
	repo := config.Repo{ID: "assets", Type: "asset", Path: "pkg", Asset: &config.AssetConfig{}}
	prepared := preparedPublication{
		view: "beta", restoreSourceGeneration: 1, restoreParentContentSHA256: digest,
		projections: []publicationProjection{{view: "beta", repo: repo, sourceRoot: ".sow/materialized/beta/pkg", legacyRoot: "pkg"}},
	}
	classifier := publicationClassifier{view: "beta", generation: 3, projections: prepared.projections}
	plan := pub.Plan{Removed: []string{entry.Path}}
	if err := augmentAuthorizedRemoteDeletes(canonical, prepared, classifier, oldManifest, desiredManifest, &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Deletes) != 1 || plan.Deletes[0].RemoteKey != ".sow/beta/pkg/extra" || plan.Deletes[0].CDNPath != "pkg/extra" || plan.Deletes[0].SHA256 != entry.HashString() {
		t.Fatalf("restore deletion=%#v", plan.Deletes)
	}

	for _, test := range []struct {
		name     string
		prepared preparedPublication
		want     string
	}{
		{name: "missing", prepared: func() preparedPublication { value := prepared; value.restoreParentContentSHA256 = ""; return value }(), want: "no parent content manifest binding"},
		{name: "mismatch", prepared: func() preparedPublication {
			value := prepared
			value.restoreParentContentSHA256 = strings.Repeat("f", 64)
			return value
		}(), want: "parent content manifest digest"},
		{name: "stable", prepared: func() preparedPublication { value := prepared; value.view = "stable"; return value }(), want: "append-only or immutable intent"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := pub.Plan{Removed: []string{entry.Path}}
			err := augmentAuthorizedRemoteDeletes(canonical, test.prepared, classifier, oldManifest, desiredManifest, &candidate)
			if err == nil || !strings.Contains(err.Error(), test.want) || len(candidate.Deletes) != 0 {
				t.Fatalf("err=%v deletes=%#v want=%q", err, candidate.Deletes, test.want)
			}
		})
	}
}

func TestAuthorizedRemoteDeletesIgnoreExpiredSnapshotPathsOutsideSelection(t *testing.T) {
	canonical := state.New(filepath.Join(t.TempDir(), ".sow"))
	asset, err := remoteInventoryEntry("pkg/tool", 5, digestBytesCLI([]byte("asset")))
	if err != nil {
		t.Fatal(err)
	}
	snapshotPath := ".sow/materialized/snapshots/el10-20260712/yum/test/x86_64/Packages/p/package.rpm"
	snapshot, err := remoteInventoryEntry(snapshotPath, 7, digestBytesCLI([]byte("package")))
	if err != nil {
		t.Fatal(err)
	}
	oldManifest := writeDeleteTestManifest(t, []manifest.Entry{snapshot, asset})
	desiredManifest := writeDeleteTestManifest(t, nil)
	repo := config.Repo{ID: "assets", Type: "asset", Path: "pkg", Asset: &config.AssetConfig{}}
	prepared := preparedPublication{view: "latest", projections: []publicationProjection{{view: "latest", repo: repo, sourceRoot: "pkg", legacyRoot: "pkg"}}}
	classifier := publicationClassifier{view: "latest", generation: 1, projections: prepared.projections}
	plan := pub.Plan{Removed: []string{asset.Path, snapshot.Path}}
	if err := augmentAuthorizedRemoteDeletes(canonical, prepared, classifier, oldManifest, desiredManifest, &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Deletes) != 1 || plan.Deletes[0].Class != pub.DeleteAssetServing || plan.Deletes[0].SourcePath != asset.Path {
		t.Fatalf("deletes=%#v", plan.Deletes)
	}
}

func TestAuthorizedRemoteDeletesDefersS0RollbackExtrasToCompatibilityClosure(t *testing.T) {
	canonical := state.New(filepath.Join(t.TempDir(), ".sow"))
	entry, err := remoteInventoryEntry("yum/infra/x86_64/Packages/p/pkg.rpm", 7, digestBytesCLI([]byte("package")))
	if err != nil {
		t.Fatal(err)
	}
	oldManifest := writeDeleteTestManifest(t, []manifest.Entry{entry})
	desiredManifest := writeDeleteTestManifest(t, nil)
	owner := config.Repo{ID: "infra-el9", Type: "yum", Path: "yum/infra/el9/{arch}", Arches: []string{"x86_64"}, YUM: &config.YUMConfig{}}
	projection := publicationProjection{
		view: "latest", repo: owner, os: "cross-el", arch: "x86_64", sourceRoot: "yum/infra/x86_64",
		compatibilityID: "infra-legacy", compatibilityRollback: true,
		canonicalRoot: "yum/infra/x86_64", remoteRoot: "yum/infra/x86_64", legacyRoot: "yum/infra/x86_64",
	}
	prepared := preparedPublication{view: "latest", projections: []publicationProjection{projection}}
	classifier := publicationClassifier{view: "latest", generation: 2, projections: prepared.projections}
	plan := pub.Plan{Removed: []string{entry.Path}}
	if err := augmentAuthorizedRemoteDeletes(canonical, prepared, classifier, oldManifest, desiredManifest, &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Deletes) != 0 {
		t.Fatalf("generic deletion planner stole compatibility authority: %#v", plan.Deletes)
	}
}

func TestAuthorizedAPTByHashDeleteUsesCurrentAndHistoricalSealedLedgers(t *testing.T) {
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	ledgerPath, err := state.APTByHashLedgerPath("views", "latest", "apt-test", "jammy")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := aptrepo.NewByHashLedger("views/latest", "apt-test", "jammy")
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	first := deleteTestByHashGeneration("release-1", created, "first")
	second := deleteTestByHashGeneration("release-2", created.Add(time.Hour), "second")
	third := deleteTestByHashGeneration("release-3", created.Add(2*time.Hour), "third")
	ledger, _, err = ledger.Advance(first, 2)
	if err != nil {
		t.Fatal(err)
	}
	installDeleteTestLedger(t, canonical, ledgerPath, ledger, "ledger one")
	ledger, _, err = ledger.Advance(second, 2)
	if err != nil {
		t.Fatal(err)
	}
	installDeleteTestLedger(t, canonical, ledgerPath, ledger, "ledger two")
	ledger, cleanup, err := ledger.Advance(third, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(cleanup.Remove) == 0 {
		t.Fatal("third generation produced no expired by-hash paths")
	}
	installDeleteTestLedger(t, canonical, ledgerPath, ledger, "ledger three")

	removedRelative := first.Paths[0]
	removedSource := path.Join("apt/test", removedRelative)
	removedEntry, err := remoteInventoryEntry(removedSource, int64(len("first-0")), path.Base(removedRelative))
	if err != nil {
		t.Fatal(err)
	}
	releaseEntry, err := remoteInventoryEntry("apt/test/dists/jammy/Release", 9, ledger.LiveGeneration)
	if err != nil {
		t.Fatal(err)
	}
	oldManifest := writeDeleteTestManifest(t, []manifest.Entry{removedEntry})
	desiredManifest := writeDeleteTestManifest(t, []manifest.Entry{releaseEntry})
	repo := config.Repo{ID: "apt-test", Type: "apt", Path: "apt/test", Arches: []string{"amd64"}, APT: &config.APTConfig{Suites: []string{"jammy"}, Components: []string{"main"}}}
	prepared := preparedPublication{view: "latest", manifestPath: desiredManifest, projections: []publicationProjection{{view: "latest", repo: repo, sourceRoot: "apt/test", legacyRoot: "apt/test"}}}
	classifier := publicationClassifier{view: "latest", generation: 4, projections: prepared.projections}

	for _, target := range []string{"cf", "cos"} {
		plan := pub.Plan{Removed: []string{removedSource}}
		if err := augmentAuthorizedRemoteDeletes(canonical, prepared, classifier, oldManifest, desiredManifest, &plan); err != nil {
			t.Fatalf("target %s: %v", target, err)
		}
		if len(plan.Deletes) != 1 || plan.Deletes[0].Class != pub.DeleteAPTByHash || plan.Deletes[0].RemoteKey != removedSource || plan.Deletes[0].CDNPath != "" {
			t.Fatalf("target %s deletion=%#v", target, plan.Deletes)
		}
		// The first target's local remote-state commit must not consume the
		// historical tombstone needed by a lagging second target.
		marker := filepath.Join(t.TempDir(), target+".txt")
		if err := os.WriteFile(marker, []byte(target), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := canonical.InstallPaths(map[string]string{"remotes/" + target + "/delete-test.txt": marker}, "record "+target); err != nil {
			t.Fatal(err)
		}
	}

	sharedRelative := second.Paths[0]
	sharedSource := path.Join("apt/test", sharedRelative)
	sharedEntry, err := remoteInventoryEntry(sharedSource, int64(len("second-0")), path.Base(sharedRelative))
	if err != nil {
		t.Fatal(err)
	}
	sharedOld := writeDeleteTestManifest(t, []manifest.Entry{sharedEntry})
	sharedPlan := pub.Plan{Removed: []string{sharedSource}}
	if err := augmentAuthorizedRemoteDeletes(canonical, prepared, classifier, sharedOld, desiredManifest, &sharedPlan); err != nil {
		t.Fatal(err)
	}
	if len(sharedPlan.Deletes) != 0 {
		t.Fatalf("retained shared by-hash path was deleted: %#v", sharedPlan.Deletes)
	}
}

func TestAuthorizedAPTByHashDeleteRejectsLiveReleaseOrHistoryDrift(t *testing.T) {
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	ledgerPath, _ := state.APTByHashLedgerPath("views", "latest", "apt-test", "jammy")
	ledger, _ := aptrepo.NewByHashLedger("views/latest", "apt-test", "jammy")
	generation := deleteTestByHashGeneration("release", time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC), "current")
	ledger, _, _ = ledger.Advance(generation, 2)
	installDeleteTestLedger(t, canonical, ledgerPath, ledger, "only current ledger")

	unknownSHA := digestBytesCLI([]byte("unknown"))
	unknownRelative := "dists/jammy/main/binary-amd64/by-hash/SHA256/" + unknownSHA
	source := path.Join("apt/test", unknownRelative)
	oldEntry, _ := remoteInventoryEntry(source, 7, unknownSHA)
	badRelease, _ := remoteInventoryEntry("apt/test/dists/jammy/Release", 1, digestBytesCLI([]byte("wrong release")))
	repo := config.Repo{ID: "apt-test", Type: "apt", Path: "apt/test", Arches: []string{"amd64"}, APT: &config.APTConfig{Suites: []string{"jammy"}, Components: []string{"main"}}}
	prepared := preparedPublication{view: "latest", projections: []publicationProjection{{view: "latest", repo: repo, sourceRoot: "apt/test", legacyRoot: "apt/test"}}}
	classifier := publicationClassifier{view: "latest", generation: 2, projections: prepared.projections}
	plan := pub.Plan{Removed: []string{source}}
	err := augmentAuthorizedRemoteDeletes(canonical, prepared, classifier, writeDeleteTestManifest(t, []manifest.Entry{oldEntry}), writeDeleteTestManifest(t, []manifest.Entry{badRelease}), &plan)
	if err == nil || !strings.Contains(err.Error(), "live Release") {
		t.Fatalf("live Release drift err=%v", err)
	}

	goodRelease, _ := remoteInventoryEntry("apt/test/dists/jammy/Release", 1, ledger.LiveGeneration)
	plan = pub.Plan{Removed: []string{source}}
	err = augmentAuthorizedRemoteDeletes(canonical, prepared, classifier, writeDeleteTestManifest(t, []manifest.Entry{oldEntry}), writeDeleteTestManifest(t, []manifest.Entry{goodRelease}), &plan)
	if err == nil || !strings.Contains(err.Error(), "no sealed historical ledger ownership") {
		t.Fatalf("unknown history err=%v", err)
	}
}

func TestNegativeOnlyAssetPublicationRequiresAnExactClosure(t *testing.T) {
	sha := digestBytesCLI([]byte("asset"))
	plan, err := (pub.Plan{Deletes: []pub.PlannedDelete{{
		Class: pub.DeleteAssetServing, SourcePath: "pkg/tool", RemoteKey: "pkg/tool",
		Size: 5, SHA256: sha, CDNPath: "pkg/tool",
	}}}).WithCDN("https://repo.test/")
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := negativeOnlyPublicationAllowed(plan)
	if err != nil || !allowed {
		t.Fatalf("empty negative closure allowed=%v err=%v", allowed, err)
	}
	incomplete := plan
	incomplete.VerifyAbsent = nil
	if allowed, err = negativeOnlyPublicationAllowed(incomplete); err == nil || allowed {
		t.Fatalf("incomplete negative closure allowed=%v err=%v", allowed, err)
	}
	nonAsset, err := (pub.Plan{Deletes: []pub.PlannedDelete{{
		Class: pub.DeleteAPTByHash, SourcePath: "apt/dists/jammy/main/binary-amd64/by-hash/SHA256/" + sha,
		RemoteKey: "apt/dists/jammy/main/binary-amd64/by-hash/SHA256/" + sha, Size: 5, SHA256: sha,
	}}}).WithCDN("https://repo.test/")
	if err != nil {
		t.Fatal(err)
	}
	if allowed, err = negativeOnlyPublicationAllowed(nonAsset); err != nil || allowed {
		t.Fatalf("storage-only by-hash deletion allowed=%v err=%v", allowed, err)
	}
}

func deleteTestByHashGeneration(release string, created time.Time, prefix string) aptrepo.ByHashGeneration {
	paths := make([]string, 0, 3)
	for index := 0; index < 3; index++ {
		sha := digestBytesCLI([]byte(fmt.Sprintf("%s-%d", prefix, index)))
		paths = append(paths, "dists/jammy/main/binary-amd64/by-hash/SHA256/"+sha)
	}
	sort.Strings(paths)
	// Advance validates PathsSHA256 through the unexported ledger seal. Build
	// the seal by first using a real generator-shaped JSON round trip is not
	// available here, so compute the documented newline-delimited SHA-256.
	var lines bytes.Buffer
	for _, value := range paths {
		lines.WriteString(value)
		lines.WriteByte('\n')
	}
	return aptrepo.ByHashGeneration{ID: digestBytesCLI([]byte(release)), CreatedAt: created, Paths: paths, PathsSHA256: digestBytesCLI(lines.Bytes())}
}

func installDeleteTestLedger(t *testing.T, canonical *state.Store, canonicalPath string, ledger aptrepo.ByHashLedger, message string) {
	t.Helper()
	body, err := aptrepo.MarshalByHashLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(t.TempDir(), "ledger.json")
	if err := os.WriteFile(stage, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.InstallPaths(map[string]string{canonicalPath: stage}, message); err != nil {
		t.Fatal(err)
	}
}

func writeDeleteTestManifest(t *testing.T, entries []manifest.Entry) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "delete-manifest-*.tsv")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := manifest.WriteEntry(file, entry); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return file.Name()
}
