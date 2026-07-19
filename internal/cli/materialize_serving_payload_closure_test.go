package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestYUMPayloadClosureExpiresOnlyAfterConfiguredRealFlips(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	// The first retention edit is committed before the first working-tree
	// materialization. Seed the configured zero-byte physical root so init can
	// establish its baseline without fabricating package bytes.
	if err := os.MkdirAll(filepath.Join(root, "yum", "test", "x86_64"), 0o755); err != nil {
		t.Fatal(err)
	}
	rewriteServingRetentionConfig(t, configPath, 6)
	arguments := []string{"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("first materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	mirror := "_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt"
	firstID := mirrorGenerationID(t, root, mirror)
	payloadRelative := filepath.Join("yum", "test", "x86_64", "Packages", "p", "package.rpm")
	if code, stdout, stderr := runServingCLI(t, "rm", "--view", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "pgdg-redhat-nonfree-repo"); code != ExitOK {
		t.Fatalf("rm code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("second materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	secondID := mirrorGenerationID(t, root, mirror)
	if _, err := os.Stat(filepath.Join(root, "_sow", "v1", "g", secondID, payloadRelative)); err != nil {
		t.Fatalf("direct successor omitted in-flight payload: %v", err)
	}

	// Two otherwise harmless canonical config changes are real generation
	// flips. With previous-retention=1, the removed package survives the first
	// subsequent flip for clients already holding G1/G2 metadata, then expires
	// on the next; identical command replays are covered separately above.
	rewriteServingRetentionConfig(t, configPath, 7)
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("third materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	thirdID := mirrorGenerationID(t, root, mirror)
	if thirdID == secondID {
		t.Fatal("config change did not create a real successor generation")
	}
	if _, err := os.Stat(filepath.Join(root, "_sow", "v1", "g", thirdID, payloadRelative)); err != nil {
		t.Fatalf("retention window expired one real flip too early: %v", err)
	}
	rewriteServingRetentionConfig(t, configPath, 8)
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("fourth materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	fourthID := mirrorGenerationID(t, root, mirror)
	if fourthID == thirdID || firstID == fourthID {
		t.Fatalf("second real flip did not advance generation first=%s third=%s fourth=%s", firstID, thirdID, fourthID)
	}
	if _, err := os.Stat(filepath.Join(root, "_sow", "v1", "g", fourthID, payloadRelative)); !os.IsNotExist(err) {
		t.Fatalf("compatibility-only payload survived beyond the configured flip window: %v", err)
	}
	if code, stdout, stderr := runServingCLI(t, "materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--nginx-include", "-", "--workers", "2", "--chunk-entries", "2"); code != ExitOK || !strings.Contains(stdout, "location") {
		t.Fatalf("retired-generation Nginx admission code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := runServingCLI(t, "fsck", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitOK || !strings.Contains(stdout, "fsck clean") {
		t.Fatalf("retired-generation receipt fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestExplicitServingBaseURLMigrationRebindsOnePhysicalPointer(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	baseArguments := []string{"materialize", "beta", "--config", configPath, "--repo", "rpm-test", "--target", "export-beta", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
	oldURL := "https://old-export.example.invalid"
	oldArguments := append(append([]string(nil), baseArguments...), "--serving-base-url", oldURL)
	if code, stdout, stderr := runServingCLI(t, oldArguments...); code != ExitOK {
		t.Fatalf("old target materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	targetRoot := filepath.Join(root, "export-beta")
	mirror := "_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt"
	firstID := mirrorGenerationID(t, targetRoot, mirror)
	oldTarget, err := serving.NewTargetIdentity("beta", "export-beta", oldURL)
	if err != nil {
		t.Fatal(err)
	}
	oldChannelPath := serving.ChannelStatePath(serving.Channel{TargetID: oldTarget.ID, View: "beta", Repo: "rpm-test", OS: "el10", Arch: "x86_64"})
	canonical := state.New(filepath.Join(root, ".sow"))
	if reader, err := canonical.OpenPath(oldChannelPath); err != nil {
		t.Fatalf("old target channel missing: %v", err)
	} else if err := reader.Close(); err != nil {
		t.Fatal(err)
	}

	newURL := "https://new-export.example.invalid"
	newArguments := append(append([]string(nil), baseArguments...), "--serving-base-url", newURL)
	if code, stdout, stderr := runServingCLI(t, newArguments...); code != ExitOK {
		t.Fatalf("migrated target materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if migratedID := mirrorGenerationID(t, targetRoot, mirror); migratedID != firstID {
		t.Fatalf("URL-only migration changed immutable generation %s -> %s", firstID, migratedID)
	}
	body, err := os.ReadFile(filepath.Join(targetRoot, filepath.FromSlash(mirror)))
	if err != nil || string(body) != newURL+"/_sow/v1/g/"+firstID+"/yum/test/x86_64/\n" {
		t.Fatalf("physical mirrorlist was not atomically rebound body=%q err=%v", body, err)
	}
	if reader, err := canonical.OpenPath(oldChannelPath); err == nil {
		_ = reader.Close()
		t.Fatal("old target channel remains after same-root URL migration")
	}
	newTarget, err := serving.NewTargetIdentity("beta", "export-beta", newURL)
	if err != nil {
		t.Fatal(err)
	}
	newChannelPath := serving.ChannelStatePath(serving.Channel{TargetID: newTarget.ID, View: "beta", Repo: "rpm-test", OS: "el10", Arch: "x86_64"})
	reader, err := canonical.OpenPath(newChannelPath)
	if err != nil {
		t.Fatal(err)
	}
	var channelBody bytes.Buffer
	if _, err := channelBody.ReadFrom(reader); err != nil {
		_ = reader.Close()
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	channel, err := serving.DecodeChannel(channelBody.Bytes())
	if err != nil || channel.TargetID != newTarget.ID || channel.ParentTargetID != oldTarget.ID || channel.Generation != firstID {
		t.Fatalf("migrated channel lost target-bound parent channel=%+v err=%v", channel, err)
	}
	if code, stdout, stderr := runServingCLI(t, oldArguments...); code != ExitOK {
		t.Fatalf("A->B->A target materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if body, err := os.ReadFile(filepath.Join(targetRoot, filepath.FromSlash(mirror))); err != nil || string(body) != oldURL+"/_sow/v1/g/"+firstID+"/yum/test/x86_64/\n" {
		t.Fatalf("A->B->A pointer body=%q err=%v", body, err)
	}
	if reader, err := canonical.OpenPath(serving.TargetStatePath(newTarget)); err == nil {
		_ = reader.Close()
		t.Fatal("exact A->B->A rewrite retained the superseded target registry")
	}
	code, stdout, stderr := runGCTestCLI(t, "gc", "--config", configPath, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(stdout, "serving_target_orphans=0") {
		t.Fatalf("exact URL migration left a GC target orphan code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestDefaultHiddenServingRootsAreTraverseOnlyAndDirectlyHostable(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	if code, stdout, stderr := runServingCLI(t, "promote", "beta", "stable", "--config", configPath, "--repo", "rpm-test"); code != ExitOK {
		t.Fatalf("stable promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, view := range []string{"beta", "stable"} {
		if code, stdout, stderr := runServingCLI(t, "materialize", view, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("%s materialize code=%d stdout=%s stderr=%s", view, code, stdout, stderr)
		}
	}
	assertFileMode(t, filepath.Join(root, ".sow"), 0o711)
	for _, protected := range []string{"state", "locks", "transactions"} {
		path := filepath.Join(root, ".sow", protected)
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		}
		assertFileMode(t, path, 0o700)
	}
	for _, target := range []string{
		filepath.Join(root, ".sow", "materialized", "beta"),
		filepath.Join(root, ".sow", "origin", "gated"),
	} {
		if err := filepath.WalkDir(target, func(current string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := os.Lstat(current)
			if err != nil {
				return err
			}
			if info.IsDir() && info.Mode().Perm() != 0o755 {
				t.Errorf("serving directory %s mode=%#o want=0755", current, info.Mode().Perm())
			}
			if !info.IsDir() && (!info.Mode().IsRegular() || info.Mode().Perm() != 0o444) {
				t.Errorf("serving file %s mode=%#o want=0444", current, info.Mode().Perm())
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertFileMode(t, configPath, 0o600)
	assertFileMode(t, keyPath, 0o600)
}

func TestTwoYUMLeavesAdvanceRetainedClosuresInOneTransactionDirectory(t *testing.T) {
	root := nginxWorkerTempDir(t)
	secondRepo := `  - id: rpm-two
    type: yum
    path: yum/two/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
`
	configBody := strings.Replace(servingYUMConfig(), "upstreams: []\n", secondRepo+"upstreams: []\n", 1)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "package.rpm"))
	_, keyPath := writeMaterializeSigningKey(t, root)
	for _, repo := range []string{"rpm-test", "rpm-two"} {
		if code, stdout, stderr := runServingCLI(t, "add", rpmPath, "--config", configPath, "--repo", repo, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("add %s code=%d stdout=%s stderr=%s", repo, code, stdout, stderr)
		}
	}
	if code, stdout, stderr := runServingCLI(t, "promote", "beta", "latest", "--config", configPath, "--repo", "rpm-test", "--repo", "rpm-two"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	arguments := []string{"materialize", "latest", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("first multi-leaf materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	mirrors := []string{
		"_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt",
		"_sow/v1/mirrorlist/latest/rpm-two/el10/x86_64.txt",
	}
	first := []string{mirrorGenerationID(t, root, mirrors[0]), mirrorGenerationID(t, root, mirrors[1])}
	rewriteServingRetentionConfig(t, configPath, 7)
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("second multi-leaf materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	second := []string{mirrorGenerationID(t, root, mirrors[0]), mirrorGenerationID(t, root, mirrors[1])}
	if first[0] == second[0] || first[1] == second[1] {
		t.Fatalf("global config change did not advance both leaves first=%v second=%v", first, second)
	}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK || !strings.Contains(stdout, "pointer=unchanged") {
		t.Fatalf("multi-leaf replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for index, mirror := range mirrors {
		if replayed := mirrorGenerationID(t, root, mirror); replayed != second[index] {
			t.Fatalf("multi-leaf replay advanced mirror %s %s -> %s", mirror, second[index], replayed)
		}
	}
}

func TestLocalYUMServingRunsIndependentLeafWorkersConcurrently(t *testing.T) {
	root := t.TempDir()
	secondRepo := `  - id: rpm-two
    type: yum
    path: yum/two/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
`
	configBody := strings.Replace(servingYUMConfig(), "upstreams: []\n", secondRepo+"upstreams: []\n", 1)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "package.rpm"))
	_, keyPath := writeMaterializeSigningKey(t, root)
	for _, repo := range []string{"rpm-test", "rpm-two"} {
		if code, stdout, stderr := runServingCLI(t, "add", rpmPath, "--config", configPath, "--repo", repo, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("add %s code=%d stdout=%s stderr=%s", repo, code, stdout, stderr)
		}
	}
	if code, stdout, stderr := runServingCLI(t, "promote", "beta", "latest", "--config", configPath, "--repo", "rpm-test", "--repo", "rpm-two"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	values := commonFlags{configPath: configPath, workers: 2, chunk: 2}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	leaves := selectedLeaves(repos, commonFlags{})
	privateKey, passphrase, keySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, leaves, keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	txDir, err := newTransactionDir(cfg.StatePath(), "serving-parallel-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(txDir)
	for _, leaf := range leaves {
		if _, err := materializeYUMLeaf(t.Context(), cfg, canonical, pool, leaf.repo, leaf, "latest", txDir, values, privateKey, passphrase); err != nil {
			t.Fatal(err)
		}
	}
	servingLeaves := localServingLeavesFromViewLeaves(leaves)
	if len(servingLeaves) != 2 {
		t.Fatalf("serving leaves=%d, want 2", len(servingLeaves))
	}
	entered := make(chan struct{}, len(servingLeaves))
	release := make(chan struct{})
	laterPrepared := make(chan struct{})
	var laterPreparedOnce sync.Once
	var commitMutex sync.Mutex
	var committedLeaves []string
	type activationOutcome struct {
		result localServingActivationResult
		err    error
	}
	done := make(chan activationOutcome, 1)
	go func() {
		var stdout bytes.Buffer
		result, err := activateLocalYUMServing(t.Context(), cfg, canonical, pool, materializeCanonicalSource{ID: "latest", Public: true}, root,
			"https://repo.example.invalid", keySHA, txDir, servingLeaves, values, localServingActivationOptions{
				AfterLeafWorkerStart: func(localYUMServingLeaf) error {
					entered <- struct{}{}
					<-release
					return nil
				},
				BeforeLeafCommitTurn: func(leaf localYUMServingLeaf) error {
					if leaf.repo.ID == "rpm-two" {
						laterPreparedOnce.Do(func() { close(laterPrepared) })
						return nil
					}
					<-laterPrepared
					return nil
				},
				AfterLeafCommit: func(leaf localYUMServingLeaf) error {
					commitMutex.Lock()
					committedLeaves = append(committedLeaves, leaf.repo.ID)
					commitMutex.Unlock()
					return nil
				},
			}, &stdout)
		done <- activationOutcome{result: result, err: err}
	}()
	for range servingLeaves {
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			close(release)
			t.Fatal("bounded serving activation did not admit two leaf workers")
		}
	}
	close(release)
	outcome := <-done
	if outcome.err != nil {
		t.Fatal(outcome.err)
	}
	if outcome.result.PeakLeafWorkers < 2 || outcome.result.PeakLeafWorkers > values.workers || outcome.result.Generations != len(servingLeaves) {
		t.Fatalf("parallel activation result=%+v leaves=%d", outcome.result, len(servingLeaves))
	}
	commitMutex.Lock()
	observedCommits := append([]string(nil), committedLeaves...)
	commitMutex.Unlock()
	if strings.Join(observedCommits, ",") != "rpm-test,rpm-two" {
		t.Fatalf("later-prepared leaf overtook deterministic commit order: %v", observedCommits)
	}

	// Advance the frozen config identity, wait until both parallel workers have
	// durable generation-ready journals, then cancel before the first sorted
	// canonical commit and prove recovery converges every leaf.
	cfg.State.SnapshotMaterializationMonths++
	cancelTxDir, err := newTransactionDir(cfg.StatePath(), "serving-parallel-cancel-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(cancelTxDir)
	cancelCtx, cancel := context.WithCancel(t.Context())
	commitReady := make(chan struct{}, len(servingLeaves))
	releaseCommit := make(chan struct{})
	headBeforeCancel, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	cancelOutcome := make(chan error, 1)
	go func() {
		_, activationErr := activateLocalYUMServing(cancelCtx, cfg, canonical, pool, materializeCanonicalSource{ID: "latest", Public: true}, root,
			"https://repo.example.invalid", keySHA, cancelTxDir, servingLeaves, values, localServingActivationOptions{
				BeforeLeafCommitTurn: func(leaf localYUMServingLeaf) error {
					commitReady <- struct{}{}
					if leaf.repo.ID == "rpm-test" {
						for range servingLeaves {
							select {
							case <-commitReady:
							case <-time.After(10 * time.Second):
								return errors.New("parallel leaf did not reach generation-ready commit barrier")
							}
						}
						cancel()
						close(releaseCommit)
						return cancelCtx.Err()
					}
					select {
					case <-releaseCommit:
						return nil
					case <-cancelCtx.Done():
						return cancelCtx.Err()
					}
				},
			}, io.Discard)
		cancelOutcome <- activationErr
	}()
	select {
	case err = <-cancelOutcome:
	case <-time.After(20 * time.Second):
		cancel()
		t.Fatal("early sorted-leaf failure left a later prepared leaf waiting forever")
	}
	cancel()
	if err == nil {
		t.Fatalf("parallel cancellation err=%v", err)
	}
	headAfterCancel, err := canonical.HeadHash()
	if err != nil || headAfterCancel != headBeforeCancel {
		t.Fatalf("later leaf committed after earlier sorted leaf failed head=%s/%s err=%v", headBeforeCancel, headAfterCancel, err)
	}
	journals, err := listLocalServingJournals(cfg.StatePath())
	if err != nil || len(journals) == 0 {
		t.Fatalf("parallel cancellation left no recoverable intent journals=%+v err=%v", journals, err)
	}
	for _, journal := range journals {
		if journal.Phase != localServingGenerationReady {
			t.Fatalf("parallel cancellation journal phase=%s want=%s", journal.Phase, localServingGenerationReady)
		}
	}
	if err := prepareLocalServingState(t.Context(), cfg, canonical, true, values, io.Discard); err != nil {
		t.Fatalf("recover parallel cancellation: %v", err)
	}
	retryTxDir, err := newTransactionDir(cfg.StatePath(), "serving-parallel-retry-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(retryTxDir)
	retried, err := activateLocalYUMServing(t.Context(), cfg, canonical, pool, materializeCanonicalSource{ID: "latest", Public: true}, root,
		"https://repo.example.invalid", keySHA, retryTxDir, servingLeaves, values, localServingActivationOptions{}, io.Discard)
	if err != nil || retried.Generations != len(servingLeaves) || retried.PeakLeafWorkers < 2 {
		t.Fatalf("retry after parallel cancellation result=%+v err=%v", retried, err)
	}
	if journals, err := listLocalServingJournals(cfg.StatePath()); err != nil || len(journals) != 0 {
		t.Fatalf("parallel retry left journals=%+v err=%v", journals, err)
	}
	ready, err := localYUMServingReady(cfg, canonical, repos, "latest", keySHA, values)
	if err != nil || !ready {
		t.Fatalf("parallel retry did not converge current+Previous closure ready=%t err=%v", ready, err)
	}
}

func assertFileMode(t *testing.T, filename string, wanted os.FileMode) {
	t.Helper()
	info, err := os.Lstat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != wanted {
		t.Fatalf("%s mode=%#o want=%#o", filename, info.Mode().Perm(), wanted)
	}
}

func rewriteServingRetentionConfig(t *testing.T, configPath string, snapshotMonths int) {
	t.Helper()
	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(body, []byte("\n"))
	replaced := false
	for index, line := range lines {
		if bytes.HasPrefix(line, []byte("state:")) {
			lines[index] = []byte("state: {snapshot_materialization_months: " + fmt.Sprint(snapshotMonths) + ", yum_generation_retention: 1}")
			replaced = true
			break
		}
	}
	if !replaced {
		t.Fatal("serving fixture has no state mapping")
	}
	if err := os.WriteFile(configPath, bytes.Join(lines, []byte("\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	// Configuration is a canonical publication input. Exercise the supported
	// operator workflow instead of letting the materializer silently bless an
	// uncommitted file edit before it mutates a served tree.
	if code, stdout, stderr := runServingCLI(t, "init", "--config", configPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("commit serving retention config code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestMaterializeRetainsRemovedPayloadInSuccessorWithoutIndexLeak(t *testing.T) {
	root, configPath, rpmPath, keyPath, private := setupServingYUMView(t)
	arguments := []string{"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("first materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	info, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	mirror := "_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt"
	firstID := mirrorGenerationID(t, root, mirror)
	payloadRelative := filepath.Join("yum", "test", "x86_64", filepath.FromSlash(info.Location))
	firstPayload := filepath.Join(root, "_sow", "v1", "g", firstID, payloadRelative)
	firstInfo, err := os.Stat(firstPayload)
	if err != nil {
		t.Fatal(err)
	}

	if code, stdout, stderr := runServingCLI(t, "rm", "--view", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, info.Name); code != ExitOK {
		t.Fatalf("rm code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("second materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	secondID := mirrorGenerationID(t, root, mirror)
	if secondID == firstID {
		t.Fatal("removal did not advance the YUM serving generation")
	}
	secondPayload := filepath.Join(root, "_sow", "v1", "g", secondID, payloadRelative)
	secondInfo, err := os.Stat(secondPayload)
	if err != nil || !os.SameFile(firstInfo, secondInfo) {
		t.Fatalf("successor generation omitted the retained immutable RPM hardlink: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, payloadRelative)); !os.IsNotExist(err) {
		t.Fatalf("removed RPM remains in the mutable raw repository: %v", err)
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(private), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	validated, err := yumrepo.ValidateDirectory(t.Context(), filepath.Join(root, "_sow", "v1", "g", secondID, "yum", "test", "x86_64", "repodata"), yumrepo.CompressionZstd, verifier)
	if err != nil || validated.Packages != 0 {
		t.Fatalf("successor metadata leaked the removed RPM packages=%v err=%v", validated, err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	headBeforeReplay, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("successor replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	headAfterReplay, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	replayedPayload, err := os.Stat(secondPayload)
	if err != nil || mirrorGenerationID(t, root, mirror) != secondID || headAfterReplay != headBeforeReplay || !os.SameFile(firstInfo, replayedPayload) {
		t.Fatalf("identical replay consumed the in-flight compatibility window generation=%s/%s head=%s/%s payload=%v", secondID, mirrorGenerationID(t, root, mirror), headBeforeReplay, headAfterReplay, err)
	}

	target, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	channelPath := serving.ChannelStatePath(serving.Channel{TargetID: target.ID, View: "latest", Repo: "rpm-test", OS: "el10", Arch: "x86_64"})
	reader, err := canonical.OpenPath(channelPath)
	if err != nil {
		t.Fatal(err)
	}
	body := new(bytes.Buffer)
	if _, err := body.ReadFrom(reader); err != nil {
		_ = reader.Close()
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	channel, err := serving.DecodeChannel(body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if channel.Generation != secondID || len(channel.Previous) == 0 || channel.Previous[0].ID != firstID {
		t.Fatalf("successor channel did not pin its predecessor: %+v", channel)
	}
}

func TestServingReplayRestoresCurrentPreviousAndPointerButRejectsDrift(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	arguments := []string{"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("first materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	mirror := "_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt"
	firstID := mirrorGenerationID(t, root, mirror)
	if code, stdout, stderr := runServingCLI(t, "rm", "--view", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "pgdg-redhat-nonfree-repo"); code != ExitOK {
		t.Fatalf("rm code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("second materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	secondID := mirrorGenerationID(t, root, mirror)
	if secondID == firstID {
		t.Fatal("successor generation did not advance")
	}
	firstRoot := filepath.Join(root, "_sow", "v1", "g", firstID)
	secondRoot := filepath.Join(root, "_sow", "v1", "g", secondID)
	if err := os.RemoveAll(firstRoot); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runServingCLI(t, "gc", "--config", configPath, "--limit", "0", "--workers", "2", "--chunk-entries", "2"); code != ExitVerification || !strings.Contains(stderr, "validate retained serving generation") {
		t.Fatalf("GC skipped missing retained generation code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if err := os.RemoveAll(secondRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(mirror))); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK || !strings.Contains(stdout, "pointer=restored") {
		t.Fatalf("replay did not restore closure code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if got := mirrorGenerationID(t, root, mirror); got != secondID {
		t.Fatalf("replay changed generation got=%s want=%s", got, secondID)
	}
	for _, directory := range []string{firstRoot, secondRoot} {
		if info, err := os.Stat(directory); err != nil || !info.IsDir() {
			t.Fatalf("retained generation was not restored %s: %v", directory, err)
		}
	}
	if err := os.WriteFile(filepath.Join(firstRoot, "foreign"), []byte("foreign"), 0o444); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runServingCLI(t, arguments...); code == ExitOK || !strings.Contains(stderr, "drift") {
		t.Fatalf("replay accepted retained drift code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if err := os.Remove(filepath.Join(firstRoot, "foreign")); err != nil {
		t.Fatal(err)
	}
	pointerPath := filepath.Join(root, filepath.FromSlash(mirror))
	if err := os.Chmod(pointerPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pointerPath, []byte("https://foreign.invalid/\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	// The retained-generation drift happened after the selected-set journal
	// entered its materializing phase. A later replay must explicitly adopt
	// that exact durable intent before it reaches the pointer drift check.
	recoveryArguments := append(append([]string(nil), arguments...), "--recover")
	if code, stdout, stderr := runServingCLI(t, recoveryArguments...); code == ExitOK || !strings.Contains(stderr, "committed canonical state") {
		t.Fatalf("replay accepted foreign pointer code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}
