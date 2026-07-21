package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

func TestMaterializedRouteOwnerIdentityDoesNotCollideOnHyphens(t *testing.T) {
	left := materializedRouteOwner{kind: "yum", repo: config.Repo{ID: "a-b"}, arch: "c"}.id()
	right := materializedRouteOwner{kind: "yum", repo: config.Repo{ID: "a"}, arch: "b-c"}.id()
	if left == right || left.tempToken() == right.tempToken() {
		t.Fatalf("distinct route owners collided: left=%v/%s right=%v/%s", left, left.tempToken(), right, right.tempToken())
	}
	owners := map[materializedRouteOwnerID]string{left: "left", right: "right"}
	if len(owners) != 2 {
		t.Fatalf("structural owner map collapsed distinct routes: %#v", owners)
	}
}

func TestMaterializedRouteRefBarriersRejectConflictingReceiptVector(t *testing.T) {
	ref := "refs/sow/views/beta/asset/all/all"
	_, err := materializedRouteRefBarriers([]materializedRouteExpected{
		{receipt: serving.MaterializedRoute{Refs: []serving.MaterializedRouteRef{{Name: ref, Commit: strings.Repeat("a", 40)}}}},
		{receipt: serving.MaterializedRoute{Refs: []serving.MaterializedRouteRef{{Name: ref, Commit: strings.Repeat("b", 40)}}}},
	})
	if err == nil || !strings.Contains(err.Error(), "conflicting barriers") {
		t.Fatalf("conflicting receipt ref vector was accepted: %v", err)
	}
}

func TestTargetWideMaterializedRouteCleanupRejectsNamespaceRootBlob(t *testing.T) {
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	targetSHA := strings.Repeat("a", 64)
	prefix, err := serving.MaterializedRouteTargetStatePrefix(targetSHA)
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "namespace-root")
	if err := os.WriteFile(stage, []byte("not a route partition\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	head, changed, err := canonical.InstallPaths(map[string]string{strings.TrimSuffix(prefix, "/"): stage}, "test: seed route namespace root blob")
	if err != nil || !changed {
		t.Fatalf("seed namespace root blob head=%s changed=%t err=%v", head, changed, err)
	}
	if _, err := loadTargetMaterializedRouteLedgersAt(canonical, head, targetSHA, t.TempDir()); err == nil || !strings.Contains(err.Error(), "namespace root is a blob") {
		t.Fatalf("target-wide cleanup accepted namespace root blob: %v", err)
	}
}

func TestCompleteSelectedMaterializedRouteOwnersUsesPhysicalOwnershipUnits(t *testing.T) {
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	stage := filepath.Join(root, "bootstrap")
	if err := os.WriteFile(stage, []byte("bootstrap\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	head, changed, err := canonical.InstallPaths(map[string]string{"test/bootstrap": stage}, "test: bootstrap route owner refs")
	if err != nil || !changed || head.IsZero() {
		t.Fatalf("bootstrap canonical state head=%s changed=%t err=%v", head, changed, err)
	}
	apt := config.Repo{
		ID: "apt-test", Type: "apt", Path: "apt/test", DefaultPool: "public", Arches: []string{"amd64", "arm64"},
		OS:  config.OSConfig{Family: "ubuntu", Suite: "jammy", Lifecycle: "active"},
		APT: &config.APTConfig{Suites: []string{"jammy", "bookworm"}, Components: []string{"main"}},
	}
	yum := config.Repo{
		ID: "yum-test", Type: "yum", Path: "yum/test/{arch}", DefaultPool: "public", Arches: []string{"x86_64", "aarch64"},
		OS:  config.OSConfig{Family: "el", Suite: "rocky", Major: 9, Lifecycle: "active"},
		YUM: &config.YUMConfig{Compression: "zstd"},
	}
	cfg := &config.Config{Root: root, Repos: []config.Repo{apt, yum}, Views: map[string]config.View{"beta": {Access: "public"}}}
	coordinates := []struct{ repo, os, arch string }{
		{"apt-test", "jammy", "amd64"}, {"apt-test", "jammy", "arm64"},
		{"apt-test", "bookworm", "amd64"}, {"apt-test", "bookworm", "arm64"},
		{"yum-test", "rocky", "x86_64"}, {"yum-test", "el9", "x86_64"},
		{"yum-test", "rocky", "aarch64"}, {"yum-test", "el9", "aarch64"},
	}
	emptyManifest := filepath.Join(root, "empty-view.tsv")
	if err := os.WriteFile(emptyManifest, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	viewStages := make(map[string]string, len(coordinates))
	for _, coordinate := range coordinates {
		viewPath, err := state.ViewPath("beta", coordinate.repo, coordinate.os, coordinate.arch)
		if err != nil {
			t.Fatal(err)
		}
		viewStages[viewPath] = emptyManifest
	}
	head, changed, err = canonical.InstallPaths(viewStages, "test: seed route owner view manifests")
	if err != nil || !changed || head.IsZero() {
		t.Fatalf("seed route owner manifests head=%s changed=%t err=%v", head, changed, err)
	}
	var updates []state.RefUpdate
	for _, coordinate := range coordinates {
		ref, refErr := state.ViewRef("beta", coordinate.repo, coordinate.os, coordinate.arch)
		if refErr != nil {
			t.Fatal(refErr)
		}
		updates = append(updates, state.RefUpdate{Name: ref, Expected: plumbing.ZeroHash, Target: head})
	}
	refStage := filepath.Join(root, ".sow", "route-owner-refs-stage")
	if err := os.WriteFile(refStage, []byte("refs\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.Apply(t.Context(), "test-route-refs", "test: seed route owner refs", map[string]string{"test/refs": refStage}, updates, state.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	source := materializeCanonicalSource{ID: "beta", Public: true}
	aptPartial := []viewLeaf{{repo: apt, os: "jammy", arch: "amd64"}, {repo: apt, os: "jammy", arch: "arm64"}}
	owners, err := completeSelectedMaterializedRouteOwners(cfg, canonical, source, aptPartial)
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0].repo.ID != apt.ID || owners[0].arch != "all" || len(owners[0].leaves) != 4 {
		t.Fatalf("partial APT selection did not close to repo-wide owner: %+v", owners)
	}
	aptFull := append(aptPartial,
		viewLeaf{repo: apt, os: "bookworm", arch: "amd64"},
		viewLeaf{repo: apt, os: "bookworm", arch: "arm64"},
	)
	owners, err = completeSelectedMaterializedRouteOwners(cfg, canonical, source, aptFull)
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0].repo.ID != apt.ID || owners[0].arch != "all" || len(owners[0].leaves) != 4 {
		t.Fatalf("full APT physical owner=%+v", owners)
	}
	yumArch := []viewLeaf{{repo: yum, os: "rocky", arch: "x86_64"}, {repo: yum, os: "el9", arch: "x86_64"}}
	owners, err = completeSelectedMaterializedRouteOwners(cfg, canonical, source, yumArch)
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0].repo.ID != yum.ID || owners[0].arch != "x86_64" || len(owners[0].leaves) != 2 {
		t.Fatalf("complete YUM arch owner=%+v", owners)
	}
	owners, err = completeSelectedMaterializedRouteOwners(cfg, canonical, source, yumArch[:1])
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0].repo.ID != yum.ID || owners[0].arch != "x86_64" || len(owners[0].leaves) != 2 {
		t.Fatalf("partial YUM OS selection did not close to arch owner: %+v", owners)
	}
}

func TestMaterializeRouteReceiptCommitCrashRecoversBeforeSelectedSetCleanup(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	addAssetMaterializeFixture(t, configPath, "payload.bin", "route receipt crash payload\n", false)
	target := filepath.Join(root, "receipt-crash-export")
	args := []string{"beta", "--config", configPath, "--repo", "asset", "--target", "receipt-crash-export", "--workers", "1", "--chunk-entries", "1"}
	injected := errors.New("injected route receipt commit crash")
	var stdout, stderr bytes.Buffer
	err := runMaterialize(withMaterializedRouteCommitHook(t.Context(), func() error { return injected }), args, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), injected.Error()) {
		t.Fatalf("receipt commit crash err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "materialized ref=beta target=") {
		t.Fatalf("failed receipt commit emitted final materialize success: %s", stdout.String())
	}
	journal, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow"))
	if err != nil || !exists || journal.Phase != materializationSelectionMaterializing || len(journal.CompletedUnits) != len(journal.Units) {
		t.Fatalf("receipt crash did not retain completed selected-set journal: exists=%t journal=%+v err=%v", exists, journal, err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	incomplete, err := canonical.IncompleteTransactions()
	if err != nil || len(incomplete) != 1 {
		t.Fatalf("receipt crash incomplete canonical transactions=%v err=%v", incomplete, err)
	}
	if ledgers := loadRouteLedgersForTest(t, canonical, target, "beta"); len(ledgers) != 1 || ledgers[0].Receipt.Kind != "asset" {
		t.Fatalf("committed receipt missing before recovery: %+v", ledgers)
	}
	stdout.Reset()
	stderr.Reset()
	err = runMaterialize(t.Context(), append(append([]string(nil), args...), "--recover"), &stdout, &stderr)
	if err != nil || !strings.Contains(stdout.String(), "route_receipts=1") {
		t.Fatalf("receipt recovery err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if _, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("receipt recovery retained selected-set journal exists=%t err=%v", exists, err)
	}
	if incomplete, err := canonical.IncompleteTransactions(); err != nil || len(incomplete) != 0 {
		t.Fatalf("receipt recovery retained canonical transaction=%v err=%v", incomplete, err)
	}
}

func TestMaterializePreflightsSymlinkedRepositoryRootBeforeMutation(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	const destination = "mutable/payload.bin"
	addAssetMaterializeFixture(t, configPath, destination, "latest payload that must not be installed after failed preflight\n", false)
	runCLISuccessForTest(t, "promote", "beta", "latest", "--config", configPath, "--repo", "asset")

	canonical := state.New(filepath.Join(root, ".sow"))
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	workingPath := filepath.Join(root, "asset", filepath.FromSlash(destination))
	if _, err := os.Lstat(workingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("working payload unexpectedly exists before materialize: %v", err)
	}

	tmpInfo, err := os.Lstat("/tmp")
	if err != nil || tmpInfo.Mode()&os.ModeSymlink == 0 {
		t.Skip("platform /tmp is not a symlink")
	}
	aliasRoot := filepath.Join("/tmp", filepath.Base(root))
	resolvedAlias, err := filepath.EvalSymlinks(aliasRoot)
	if err != nil || filepath.Clean(resolvedAlias) != filepath.Clean(root) {
		t.Fatalf("test /tmp alias does not resolve to repository root alias=%s resolved=%s root=%s err=%v", aliasRoot, resolvedAlias, root, err)
	}
	var stdout, stderr bytes.Buffer
	err = runMaterialize(t.Context(), []string{
		"latest", "--config", filepath.Join(aliasRoot, "sow.yaml"), "--repo", "asset", "--workers", "1", "--chunk-entries", "1",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "preflight directly hostable materialization target") || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked repository root was not rejected before materialization err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}

	headAfter, err := canonical.HeadHash()
	if err != nil || headAfter != headBefore {
		t.Fatalf("failed root preflight advanced canonical HEAD %s -> %s err=%v", headBefore, headAfter, err)
	}
	if _, err := os.Lstat(workingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed root preflight installed working payload: %v", err)
	}
	if _, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("failed root preflight created selected-set journal exists=%t err=%v", exists, err)
	}
	if incomplete, err := canonical.IncompleteTransactions(); err != nil || len(incomplete) != 0 {
		t.Fatalf("failed root preflight created canonical transaction=%v err=%v", incomplete, err)
	}
}

func TestMaterializeHostabilityPreflightAllowsMissingTargetBelowSafeAncestor(t *testing.T) {
	root := nginxWorkerTempDir(t)
	target := filepath.Join(root, "not-created", "nested", "export")
	if err := preflightMaterializedRouteTargetHostability(target); err != nil {
		t.Fatalf("missing target below safe ancestor was rejected: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "not-created")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only hostability preflight created target state: %v", err)
	}
}

func TestMaterializeHostabilityPreflightRejectsSymlinkAncestor(t *testing.T) {
	root := nginxWorkerTempDir(t)
	realParent := filepath.Join(root, "real-parent")
	if err := os.Mkdir(realParent, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias-parent")
	if err := os.Symlink(filepath.Base(realParent), alias); err != nil {
		t.Fatal(err)
	}
	err := preflightMaterializedRouteTargetHostability(filepath.Join(alias, "future-export"))
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked target ancestor was admitted: %v", err)
	}
}

func TestMaterializeRouteReceiptRejectsStrayFileInsteadOfCanonizingIt(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	addAssetMaterializeFixture(t, configPath, "payload.bin", "route receipt exact payload\n", false)
	target := filepath.Join(root, "receipt-stray-export")
	stray := filepath.Join(target, "asset", "stray.bin")
	args := []string{"beta", "--config", configPath, "--repo", "asset", "--target", "receipt-stray-export", "--workers", "1", "--chunk-entries", "1"}
	ctx := withMaterializedRouteBeforeValidationHook(t.Context(), func() error {
		return os.WriteFile(stray, []byte("must never enter receipt\n"), 0o444)
	})
	var stdout, stderr bytes.Buffer
	err := runMaterialize(ctx, args, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "materialized route manifest drift") {
		t.Fatalf("stray file was accepted err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	if ledgers := loadRouteLedgersForTest(t, canonical, target, "beta"); len(ledgers) != 0 {
		t.Fatalf("stray file produced canonical route receipt: %+v", ledgers)
	}
	if err := os.Remove(stray); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if err := runMaterialize(t.Context(), append(append([]string(nil), args...), "--recover"), &stdout, &stderr); err != nil {
		t.Fatalf("stray recovery err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	ledgers := loadRouteLedgersForTest(t, canonical, target, "beta")
	if len(ledgers) != 1 {
		t.Fatalf("stray recovery receipts=%d want=1", len(ledgers))
	}
	assertRouteLedgerValidForTest(t, root, target, ledgers[0])
}

func TestMutableViewFullMaterializeDeletesOnlySameTargetViewStaleReceipts(t *testing.T) {
	for _, view := range []string{"beta", "latest", "stable"} {
		t.Run(view, func(t *testing.T) {
			root, configPath := newAssetMaterializeHardeningFixture(t)
			addAssetMaterializeFixture(t, configPath, "payload.bin", view+" route payload\n", false)
			if view == "latest" || view == "stable" {
				runCLISuccessForTest(t, "promote", "beta", view, "--config", configPath, "--repo", "asset")
			}
			args := []string{view, "--config", configPath, "--workers", "1", "--chunk-entries", "1"}
			runMaterializeSuccessForTest(t, args)
			target := defaultRouteTargetForTest(t, root, view)
			canonical := state.New(filepath.Join(root, ".sow"))
			base := loadRouteLedgersForTest(t, canonical, target, view)
			if len(base) != 1 {
				t.Fatalf("initial %s receipts=%d", view, len(base))
			}
			stale := seedRouteVariantForTest(t, root, canonical, base[0], view, target, "removed-repo")
			runMaterializeSuccessForTest(t, append(append([]string(nil), args...), "--repo", "asset"))
			if !canonicalRoutePathExistsForTest(t, canonical, stale) {
				t.Fatalf("partial %s materialize deleted stale same-view receipt", view)
			}
			runMaterializeSuccessForTest(t, args)
			if canonicalRoutePathExistsForTest(t, canonical, stale) {
				t.Fatalf("full %s materialize retained stale same-target/view receipt", view)
			}
			if ledgers := loadRouteLedgersForTest(t, canonical, target, view); len(ledgers) != 1 || ledgers[0].Receipt.Repo != "asset" {
				t.Fatalf("full %s desired receipts=%+v", view, ledgers)
			}
		})
	}
}

func TestExplicitPartialTargetReceiptCleanupDeletesEveryViewAndPreservesOtherTargets(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	addAssetMaterializeFixture(t, configPath, "payload.bin", "explicit route payload\n", false)
	args := []string{"beta", "--config", configPath, "--target", "shared-export", "--workers", "1", "--chunk-entries", "1"}
	runMaterializeSuccessForTest(t, args)
	shared := filepath.Join(root, "shared-export")
	other := filepath.Join(root, "other-export")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	base := loadRouteLedgersForTest(t, canonical, shared, "beta")
	if len(base) != 1 {
		t.Fatalf("initial explicit receipts=%d", len(base))
	}
	same := seedRouteVariantForTest(t, root, canonical, base[0], "beta", shared, "stale-same")
	crossView := seedRouteVariantForTest(t, root, canonical, base[0], "stable", shared, "stale-view")
	crossTarget := seedRouteVariantForTest(t, root, canonical, base[0], "beta", other, "stale-target")
	runMaterializeSuccessForTest(t, append(append([]string(nil), args...), "--repo", "asset"))
	if canonicalRoutePathExistsForTest(t, canonical, same) {
		t.Fatalf("partial explicit materialize retained stale same-target/view receipt %s", same)
	}
	if canonicalRoutePathExistsForTest(t, canonical, crossView) {
		t.Fatalf("partial explicit materialize retained stale cross-view receipt %s", crossView)
	}
	if !canonicalRoutePathExistsForTest(t, canonical, crossTarget) {
		t.Fatalf("explicit receipt cleanup crossed target identity: deleted %s", crossTarget)
	}
	if ledgers := loadRouteLedgersForTest(t, canonical, shared, "stable"); len(ledgers) != 0 {
		t.Fatalf("partial explicit materialize retained cross-view receipt triples: %+v", ledgers)
	}
	if ledgers := loadRouteLedgersForTest(t, canonical, other, "beta"); len(ledgers) != 1 || ledgers[0].Receipt.Repo != "stale-target" {
		t.Fatalf("partial explicit materialize changed another target's receipt triple: %+v", ledgers)
	}
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	runMaterializeSuccessForTest(t, append(append([]string(nil), args...), "--repo", "asset"))
	after, err := canonical.HeadHash()
	if err != nil || after != head {
		t.Fatalf("idempotent explicit target cleanup advanced HEAD %s -> %s err=%v", head, after, err)
	}
}

func TestExplicitSnapshotExactReplacementRetiresAllOrdinaryRouteReceipts(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	addAssetMaterializeFixture(t, configPath, "payload.bin", "snapshot replacement payload\n", false)
	targetName := "snapshot-replacement-export"
	target := filepath.Join(root, targetName)
	runMaterializeSuccessForTest(t, []string{"beta", "--config", configPath, "--target", targetName, "--workers", "1", "--chunk-entries", "1"})
	canonical := state.New(filepath.Join(root, ".sow"))
	if ledgers := loadRouteLedgersForTest(t, canonical, target, "beta"); len(ledgers) != 1 {
		t.Fatalf("initial ordinary route receipts=%d want=1", len(ledgers))
	}
	// beta -> latest also advances the append-only stable view by contract.
	runCLISuccessForTest(t, "promote", "beta", "latest", "--config", configPath, "--repo", "asset")
	snapshotID, err := views.SnapshotID("all", timeNowUTC())
	if err != nil {
		t.Fatal(err)
	}
	runCLISuccessForTest(t, "promote", "stable", snapshotID, "--config", configPath, "--repo", "asset")
	runMaterializeSuccessForTest(t, []string{snapshotID, "--config", configPath, "--repo", "asset", "--target", targetName, "--workers", "1", "--chunk-entries", "1"})
	if ledgers := loadRouteLedgersForTest(t, canonical, target, "beta"); len(ledgers) != 0 {
		t.Fatalf("explicit snapshot exact replacement retained ordinary route receipts: %+v", ledgers)
	}
}

func TestExplicitTargetReceiptCleanupPreflightRejectsCrossViewOrphanBeforeMutation(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	addAssetMaterializeFixture(t, configPath, "payload.bin", "explicit preflight payload\n", false)
	args := []string{"beta", "--config", configPath, "--target", "preflight-export", "--workers", "1", "--chunk-entries", "1"}
	runMaterializeSuccessForTest(t, args)
	target := filepath.Join(root, "preflight-export")
	sentinel := filepath.Join(target, "must-survive-preflight")
	if err := os.WriteFile(sentinel, []byte("old exact tree\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	targetSHA, err := serving.MaterializedRouteTargetSHA256(target)
	if err != nil {
		t.Fatal(err)
	}
	orphanID := strings.Repeat("f", 64)
	orphanPath := filepath.ToSlash(filepath.Join("serving", "materializations", targetSHA, "stable", "routes", orphanID+".exact.tsv"))
	orphanStage := filepath.Join(t.TempDir(), "orphan.tsv")
	if err := os.WriteFile(orphanStage, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.InstallPaths(map[string]string{orphanPath: orphanStage}, "test: seed cross-view orphan route manifest"); err != nil || !changed {
		t.Fatalf("seed route orphan changed=%t err=%v", changed, err)
	}
	var stdout, stderr bytes.Buffer
	err = runMaterialize(t.Context(), append(append([]string(nil), args...), "--repo", "asset"), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "orphan or unknown materialized route ledger path") {
		t.Fatalf("cross-view orphan did not fail closed err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if body, err := os.ReadFile(sentinel); err != nil || string(body) != "old exact tree\n" {
		t.Fatalf("explicit target mutated before receipt cleanup preflight body=%q err=%v", body, err)
	}
}

func TestRootMappedAssetDirectReceiptsAdmitNginxForEveryMutableView(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(rootMappedAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset/bootstrap")
	for _, key := range []string{"get", "pkg"} {
		input := filepath.Join(t.TempDir(), key)
		if err := os.WriteFile(input, []byte(key+" root route\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Main([]string{"add", input, "--config", configPath, "--repo", "bootstrap", "--dest", key, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitOK {
			t.Fatalf("add root key %s code=%d stdout=%s stderr=%s", key, code, stdout.String(), stderr.String())
		}
	}
	runCLISuccessForTest(t, "promote", "beta", "latest", "--config", configPath, "--repo", "bootstrap")
	runCLISuccessForTest(t, "promote", "beta", "stable", "--config", configPath, "--repo", "bootstrap")
	auth := filepath.Join(t.TempDir(), "users.htpasswd")
	if err := os.WriteFile(auth, []byte("tester:$2y$05$012345678901234567890u12345678901234567890123456789012\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, view := range []string{"beta", "latest", "stable"} {
		t.Run(view, func(t *testing.T) {
			targetName := "root-" + view + "-export"
			target := filepath.Join(root, targetName)
			runMaterializeSuccessForTest(t, []string{view, "--config", configPath, "--repo", "bootstrap", "--target", targetName, "--workers", "1", "--chunk-entries", "1"})
			canonical := state.New(filepath.Join(root, ".sow"))
			ledgers := loadRouteLedgersForTest(t, canonical, target, view)
			if len(ledgers) != 1 {
				t.Fatalf("%s root receipts=%d", view, len(ledgers))
			}
			claims := ledgers[0].Receipt.Claims
			wantClaims := []serving.MaterializedRouteClaim{
				{Kind: serving.MaterializedRouteClaimExactFile, RelativeRoot: "asset/bootstrap/get"},
				{Kind: serving.MaterializedRouteClaimExactFile, RelativeRoot: "asset/bootstrap/pkg"},
			}
			if !slices.Equal(claims, wantClaims) {
				t.Fatalf("%s root claims=%+v want=%+v", view, claims, wantClaims)
			}
			assertRouteLedgerValidForTest(t, root, target, ledgers[0])
			arguments := []string{view, "--config", configPath, "--repo", "bootstrap", "--target", targetName, "--nginx-include", "-", "--workers", "1", "--chunk-entries", "1"}
			if view == "stable" {
				arguments = append(arguments, "--nginx-auth-user-file", auth)
			}
			var stdout, stderr bytes.Buffer
			urlPrefix := ""
			if view == "stable" {
				urlPrefix = "/pro/v1/basic"
			}
			if err := runMaterialize(t.Context(), arguments, &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), "location = "+urlPrefix+"/pkg") || !strings.Contains(stdout.String(), "location = "+urlPrefix+"/get") {
				t.Fatalf("%s root Nginx admission err=%v stdout=%s stderr=%s", view, err, stdout.String(), stderr.String())
			}
		})
	}
}

func TestDirectAPTMaterializeDoesNotCanonizePreexistingMetadataStray(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(routeReceiptAPTConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "apt/one")
	keyPath := writePublishTestPrivateKey(t, root)
	input := writeSelectorDEB(t, root, "receipt", "1.0-1", "amd64")
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"add", input, "--config", configPath, "--repo", "deb-one", "--os", "jammy", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("add APT receipt fixture code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	targetName := "apt-export"
	target := filepath.Join(root, targetName)
	stray := filepath.Join(target, "apt", "one", "dists", "jammy", "injected-stray")
	if err := os.MkdirAll(filepath.Dir(stray), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stray, []byte("not generated metadata\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	runMaterializeSuccessForTest(t, []string{"beta", "--config", configPath, "--repo", "deb-one", "--target", targetName, "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"})
	if _, err := os.Lstat(stray); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pre-existing APT metadata stray survived exact reconciliation: %v", err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	ledgers := loadRouteLedgersForTest(t, canonical, target, "beta")
	if len(ledgers) != 1 {
		t.Fatalf("APT route receipts=%d, want 1", len(ledgers))
	}
	exact, err := os.Open(ledgers[0].ExactManifest)
	if err != nil {
		t.Fatal(err)
	}
	reader := manifest.NewReader(exact)
	for {
		entry, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			exact.Close()
			t.Fatal(readErr)
		}
		if entry.Path == "injected-stray" || strings.HasSuffix(entry.Path, "/injected-stray") {
			exact.Close()
			t.Fatalf("route exact.tsv canonized pre-existing metadata stray %q", entry.Path)
		}
	}
	if err := exact.Close(); err != nil {
		t.Fatal(err)
	}
	assertRouteLedgerValidForTest(t, root, target, ledgers[0])
}

func TestPartialAPTMaterializeClosesPhysicalOwnerAndPreservesSiblingRoute(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAPTSelectorConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "apt/one", "apt/two")
	keyPath := writePublishTestPrivateKey(t, root)
	add := func(repo, suite, name string) {
		input := writeSelectorDEB(t, root, name, "1.0-1", "all")
		var stdout, stderr bytes.Buffer
		if code := Main([]string{"add", input, "--config", configPath, "--repo", repo, "--os", suite, "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitOK {
			t.Fatalf("add %s/%s code=%d stdout=%s stderr=%s", repo, suite, code, stdout.String(), stderr.String())
		}
	}
	add("deb-one", "jammy", "jammy-owner")
	add("deb-one", "bookworm", "bookworm-owner")
	add("deb-two", "jammy", "sibling-owner")
	full := []string{"beta", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}
	runMaterializeSuccessForTest(t, full)
	target := filepath.Join(root, ".sow", "materialized", "beta")
	canonical := state.New(filepath.Join(root, ".sow"))
	initial := loadRouteLedgersForTest(t, canonical, target, "beta")
	if len(initial) != 2 {
		t.Fatalf("initial APT route owners=%d want=2", len(initial))
	}
	partial := append(append([]string(nil), full...), "--repo", "deb-one", "--os", "jammy", "--arch", "amd64")
	runMaterializeSuccessForTest(t, partial)
	ledgers := loadRouteLedgersForTest(t, canonical, target, "beta")
	if len(ledgers) != 2 {
		t.Fatalf("partial APT materialize removed sibling route receipts: %+v", ledgers)
	}
	var selected materializedRouteLedger
	for _, ledger := range ledgers {
		if ledger.Receipt.Repo == "deb-one" {
			selected = ledger
		}
	}
	if selected.Receipt.ID == "" || len(selected.Receipt.Refs) != 4 {
		t.Fatalf("partial APT owner receipt has incomplete ref closure: %+v", selected.Receipt)
	}
	assertRouteLedgerValidForTest(t, root, target, selected)
	var stdout, stderr bytes.Buffer
	if err := runMaterialize(t.Context(), []string{"beta", "--config", configPath, "--repo", "deb-one", "--os", "jammy", "--arch", "amd64", "--nginx-include", "-", "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); err != nil {
		t.Fatalf("partial APT owner Nginx admission err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	runMaterializeSuccessForTest(t, partial)
	after, err := canonical.HeadHash()
	if err != nil || after != head {
		t.Fatalf("idempotent partial APT materialize advanced HEAD %s -> %s err=%v", head, after, err)
	}
}

func runMaterializeSuccessForTest(t *testing.T, args []string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := runMaterialize(t.Context(), args, &stdout, &stderr); err != nil {
		t.Fatalf("materialize %v err=%v stdout=%s stderr=%s", args, err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func runCLISuccessForTest(t *testing.T, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := Main(args, &stdout, &stderr); code != ExitOK {
		t.Fatalf("CLI %v code=%d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func defaultRouteTargetForTest(t *testing.T, root, view string) string {
	t.Helper()
	switch view {
	case "latest":
		return root
	case "beta":
		return filepath.Join(root, ".sow", "materialized", "beta")
	case "stable":
		return filepath.Join(root, ".sow", "origin", "gated")
	default:
		t.Fatalf("no mutable route target for %s", view)
		return ""
	}
}

func loadRouteLedgersForTest(t *testing.T, canonical *state.Store, target, view string) []materializedRouteLedger {
	t.Helper()
	targetSHA, err := serving.MaterializedRouteTargetSHA256(target)
	if err != nil {
		t.Fatal(err)
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		t.Fatalf("canonical head=%s err=%v", head, err)
	}
	ledgers, err := loadMaterializedRouteLedgersAt(canonical, head, targetSHA, view, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return ledgers
}

func assertRouteLedgerValidForTest(t *testing.T, repositoryRoot, target string, ledger materializedRouteLedger) {
	t.Helper()
	pool, err := repository.NewStore(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(target)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := serving.ValidateMaterializedRouteRoot(t.Context(), pool, root, ledger.Receipt, ledger.ExactManifest, ledger.PayloadManifest, serving.InstallOptions{
		Workers: 1, ChunkEntries: 1, TempDir: filepath.Join(repositoryRoot, ".sow", "tmp"),
	}); err != nil {
		t.Fatalf("validate route receipt %s: %v", ledger.Receipt.ID, err)
	}
}

func seedRouteVariantForTest(t *testing.T, repositoryRoot string, canonical *state.Store, base materializedRouteLedger, view, target, repo string) string {
	t.Helper()
	targetSHA, err := serving.MaterializedRouteTargetSHA256(target)
	if err != nil {
		t.Fatal(err)
	}
	exact, err := os.Open(base.ExactManifest)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.Open(base.PayloadManifest)
	if err != nil {
		exact.Close()
		t.Fatal(err)
	}
	receipt, receiptErr := serving.NewMaterializedRoute(serving.MaterializedRouteIdentity{
		Kind: base.Receipt.Kind, View: view, Source: view, TargetSHA256: targetSHA,
		Claims: base.Receipt.Claims, ConfigSHA256: base.Receipt.ConfigSHA256, ConfigCommit: base.Receipt.ConfigCommit, ServingTargetID: base.Receipt.ServingTargetID,
		Repo: repo, OS: base.Receipt.OS, Arch: base.Receipt.Arch, Refs: base.Receipt.Refs,
	}, exact, payload)
	closeErr := errors.Join(exact.Close(), payload.Close())
	if receiptErr != nil || closeErr != nil {
		t.Fatal(errors.Join(receiptErr, closeErr))
	}
	stageDir, err := os.MkdirTemp(filepath.Join(repositoryRoot, ".sow"), "route-ledger-seed-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stageDir) })
	staged, err := stageMaterializedRouteLedger(stageDir, receipt, base.ExactManifest, base.PayloadManifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.Apply(t.Context(), "test-route-seed", "test: seed stale route receipt", staged, nil, state.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	receiptPath, _, _, err := materializedRouteLedgerPaths(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return receiptPath
}

func canonicalRoutePathExistsForTest(t *testing.T, canonical *state.Store, wanted string) bool {
	t.Helper()
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	file, err := canonical.OpenPathAt(head, wanted)
	if err != nil {
		return false
	}
	if _, err := io.Copy(io.Discard, file); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return true
}

const routeReceiptAPTConfig = `schema: sow/v1
state: {snapshot_materialization_months: 6}
gpg: {public_key: signing.key.pub}
pools:
  public: {}
  gated: {}
repos:
  - id: deb-one
    type: apt
    path: apt/one
    default_pool: public
    arches: [amd64]
    os: {family: ubuntu, suite: jammy, lifecycle: active}
    apt: {suites: [jammy], components: [main]}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
