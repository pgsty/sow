package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
)

func setupExactRecoveryDualArchYUMFixture(t *testing.T) topLevelPackageFixture {
	t.Helper()
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishMultiLeafPackageAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"x86_64", "aarch64"} {
		if err := os.MkdirAll(filepath.Join(root, "yum", "test", arch), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := writePublishTestPrivateKey(t, root)
	rpmPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm"))
	if code, stdout, stderr := runTopLevelRecoveryCLI(t, "add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("seed dual-arch RPM code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := runTopLevelRecoveryCLI(t, "init", "--config", configPath, "--repo", "rpm-test", "--workers", "1", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("seed dual-arch repository baseline code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, pair := range [][2]string{{"beta", "latest"}, {"latest", "stable"}} {
		if code, stdout, stderr := runTopLevelRecoveryCLI(t, "promote", pair[0], pair[1], "--config", configPath, "--repo", "rpm-test"); code != ExitOK {
			t.Fatalf("promote %s/%s code=%d stdout=%s stderr=%s", pair[0], pair[1], code, stdout, stderr)
		}
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	return topLevelPackageFixture{root: root, configPath: configPath, keyPath: keyPath, cfg: cfg, canonical: state.New(cfg.StatePath())}
}

func installExactRecoveryJournalGuard(t *testing.T, fixture topLevelPackageFixture) (*cloudProtocolTransport, *journalGuardTransport) {
	t.Helper()
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	protocol := newCloudProtocolTransport()
	guard := &journalGuardTransport{stateRoot: fixture.cfg.StatePath(), delegate: protocol}
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: guard}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	return protocol, guard
}

func assertExactRecoveryRemoteYUMArch(t *testing.T, protocol *cloudProtocolTransport, arch string) {
	t.Helper()
	needle := "/yum/test/" + arch + "/repodata/repomd.xml"
	protocol.mutex.Lock()
	keys := append([]string(nil), protocol.putKeys...)
	protocol.mutex.Unlock()
	for _, key := range keys {
		if strings.Contains(key, needle) {
			return
		}
	}
	t.Fatalf("default publication did not publish YUM arch %s; PUT keys=%v", arch, keys)
}

func seedExactRecoveryHistoricalSnapshots(t *testing.T, fixture topLevelPackageFixture, snapshotIDs []string) {
	t.Helper()
	for _, snapshotID := range snapshotIDs {
		staged := make(map[string]string)
		updates := make([]state.RefUpdate, 0, 2)
		for _, arch := range []string{"x86_64", "aarch64"} {
			stableRef, err := state.ViewRef("stable", "rpm-test", "el10", arch)
			if err != nil {
				t.Fatal(err)
			}
			commit, exists, err := fixture.canonical.Ref(stableRef)
			if err != nil || !exists {
				t.Fatalf("read stable ref %s exists=%t err=%v", stableRef, exists, err)
			}
			stablePath, err := state.ViewPath("stable", "rpm-test", "el10", arch)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := fixture.canonical.OpenPathAt(commit, stablePath)
			if err != nil {
				t.Fatal(err)
			}
			stage, err := os.CreateTemp(fixture.cfg.StatePath(), "historical-snapshot-*.tsv")
			if err != nil {
				reader.Close()
				t.Fatal(err)
			}
			_, copyErr := io.Copy(stage, reader)
			closeErr := errors.Join(reader.Close(), stage.Sync(), stage.Close())
			if err := errors.Join(copyErr, closeErr); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(stage.Name()) })
			snapshotPath, err := state.SnapshotPath(snapshotID, "rpm-test", "el10", arch)
			if err != nil {
				t.Fatal(err)
			}
			snapshotRef, err := state.SnapshotRef(snapshotID, "rpm-test", "el10", arch)
			if err != nil {
				t.Fatal(err)
			}
			staged[snapshotPath] = stage.Name()
			updates = append(updates, state.RefUpdate{Name: snapshotRef, Immutable: true})
		}
		if _, committed, err := fixture.canonical.Apply(t.Context(), "test", fmt.Sprintf("seed historical snapshot %s", snapshotID), staged, updates, state.ApplyOptions{}); err != nil || !committed {
			t.Fatalf("seed historical snapshot %s committed=%t err=%v", snapshotID, committed, err)
		}
	}
}

func leaveSnapshotPublishMaterializationJournal(t *testing.T, fixture topLevelPackageFixture, snapshotID string) materializationSelectionJournal {
	t.Helper()
	values := commonFlags{
		configPath: fixture.configPath,
		repos:      csvFlag{items: []string{"rpm-test"}},
		workers:    1,
		chunk:      2,
	}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := os.ReadFile(fixture.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	repositoryKeySHA, err := repositorySigningKeyIdentity(cfg, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaves := selectedLeaves(repos, values)
	values.materializeTrust, err = captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	values.materializeOperation = "publish"
	targetRoot := defaultMaterializationTarget(snapshotID, true)
	if !filepath.IsAbs(targetRoot) {
		targetRoot = filepath.Join(cfg.Root, filepath.FromSlash(targetRoot))
	}
	values, owner, err := beginMaterializationSelectionForSource(
		cfg,
		fixture.canonical,
		values,
		"publish",
		materializeCanonicalSource{ID: snapshotID, Snapshot: true},
		leaves,
		targetRoot,
		true,
		false,
	)
	if err != nil || !owner {
		t.Fatalf("leave snapshot publication materialization owner=%t err=%v", owner, err)
	}
	values.materializeTrust.resetMaterializationSelection()
	journal, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !exists {
		t.Fatalf("read snapshot publication materialization journal exists=%t err=%v", exists, err)
	}
	for _, unit := range journal.Units {
		if unit.Historical || unit.Source != snapshotID {
			t.Fatalf("durable publication snapshot unit is not exact: %+v", unit)
		}
	}
	return journal
}

func TestPublishRestoreRecoversNonRestoreJournalBeforeRemoteAccess(t *testing.T) {
	for _, test := range []struct {
		name               string
		leaveJournal       func(*testing.T, topLevelPackageFixture) materializationSelectionJournal
		recoveryOutputPart string
	}{
		{
			name: "mutable view",
			leaveJournal: func(t *testing.T, fixture topLevelPackageFixture) materializationSelectionJournal {
				return leaveMutablePublishMaterializationJournal(t, fixture, "beta")
			},
			recoveryOutputPart: "publish materialized view=beta",
		},
		{
			name: "immutable snapshot",
			leaveJournal: func(t *testing.T, fixture topLevelPackageFixture) materializationSelectionJournal {
				const snapshotID = "el10-20260713"
				seedExactRecoveryHistoricalSnapshots(t, fixture, []string{snapshotID})
				return leaveSnapshotPublishMaterializationJournal(t, fixture, snapshotID)
			},
			recoveryOutputPart: "publish materialized snapshot=el10-20260713",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := setupExactRecoveryDualArchYUMFixture(t)
			t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
			t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)

			protocol := newCloudProtocolTransport()
			previousClient := publishProviderHTTPClient
			publishProviderHTTPClient = &http.Client{Transport: protocol}
			t.Cleanup(func() { publishProviderHTTPClient = previousClient })
			for _, viewName := range []string{"beta", "latest"} {
				code, stdout, stderr := runTopLevelRecoveryCLI(t,
					"publish", "--view", viewName, "--target", "cf", "--config", fixture.configPath,
					"--gpg-private-key-file", fixture.keyPath, "--workers", "1", "--chunk-entries", "2",
				)
				if code != ExitOK {
					t.Fatalf("seed %s publication code=%d stdout=%s stderr=%s", viewName, code, stdout, stderr)
				}
			}
			before, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf")
			if err != nil || !exists || before.Generation != 2 {
				t.Fatalf("seed target generation=%+v exists=%t err=%v", before, exists, err)
			}

			journal := test.leaveJournal(t, fixture)
			if journal.Operation != "publish" || len(journal.Units) == 0 {
				t.Fatalf("non-restore journal is not durable: %+v", journal)
			}
			for _, unit := range journal.Units {
				if unit.Historical {
					t.Fatalf("test journal unexpectedly describes historical restore: %+v", unit)
				}
			}

			guard := &journalGuardTransport{stateRoot: fixture.cfg.StatePath(), delegate: protocol}
			publishProviderHTTPClient = &http.Client{Transport: guard}
			code, stdout, stderr := runTopLevelRecoveryCLI(t,
				"publish", "--restore-generation", "1", "--target", "cf", "--config", fixture.configPath,
				"--gpg-private-key-file", fixture.keyPath, "--workers", "1", "--chunk-entries", "2", "--recover",
			)
			if code != ExitOK {
				t.Fatalf("restore after exact local recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			calls, callsWithJournal, journalErr := guard.counts()
			if journalErr != nil || calls == 0 || callsWithJournal != 0 {
				t.Fatalf("restore remote ordering calls=%d while_journal=%d journal_err=%v stdout=%s", calls, callsWithJournal, journalErr, stdout)
			}
			if _, active, err := readMaterializationSelectionJournal(fixture.cfg.StatePath()); err != nil || active {
				t.Fatalf("restore retained recovered local journal active=%t err=%v", active, err)
			}
			recoveryIndex := strings.Index(stdout, test.recoveryOutputPart)
			restoreIndex := strings.Index(stdout, "restore target=cf source_generation=1")
			if recoveryIndex < 0 || restoreIndex <= recoveryIndex || !strings.Contains(stdout, "status=complete") {
				t.Fatalf("local recovery did not precede restore recovery_index=%d restore_index=%d stdout=%s", recoveryIndex, restoreIndex, stdout)
			}
			after, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf")
			if err != nil || !exists || after.Generation != 3 || after.ParentGeneration != 2 || after.IntentView != "beta" {
				t.Fatalf("restored target generation=%+v exists=%t err=%v", after, exists, err)
			}
		})
	}
}

func TestPublishRecoverNarrowYUMJournalBeforeCurrentDefaultSelection(t *testing.T) {
	fixture := setupExactRecoveryDualArchYUMFixture(t)
	journal := leaveMutablePublishMaterializationJournal(t, fixture, "beta")
	if len(journal.Units) != 2 {
		t.Fatalf("narrow x86_64 publication journal units=%d want=2: %+v", len(journal.Units), journal.Units)
	}
	for _, unit := range journal.Units {
		if unit.Source != "beta" || unit.Repo != "rpm-test" || unit.Arch != "x86_64" {
			t.Fatalf("narrow publication journal widened before recovery: %+v", unit)
		}
	}

	protocol, guard := installExactRecoveryJournalGuard(t, fixture)
	code, stdout, stderr := runTopLevelRecoveryCLI(t,
		"publish", "--target", "cf", "--config", fixture.configPath,
		"--gpg-private-key-file", fixture.keyPath, "--workers", "1", "--chunk-entries", "2", "--recover",
	)
	if code != ExitOK {
		t.Fatalf("default publish recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	calls, callsWithJournal, journalErr := guard.counts()
	if journalErr != nil || calls == 0 || callsWithJournal != 0 {
		t.Fatalf("remote ordering calls=%d while_journal=%d journal_err=%v stdout=%s", calls, callsWithJournal, journalErr, stdout)
	}
	if _, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath()); err != nil || exists {
		t.Fatalf("default publish recovery retained narrow journal exists=%t err=%v", exists, err)
	}
	for _, view := range []string{"beta", "latest", "stable"} {
		if !strings.Contains(stdout, "view="+view) {
			t.Fatalf("default selection did not complete view %s after exact recovery: %s", view, stdout)
		}
	}
	assertExactRecoveryRemoteYUMArch(t, protocol, "x86_64")
	assertExactRecoveryRemoteYUMArch(t, protocol, "aarch64")
}

func TestPublishRecoverMultiSnapshotJournalWithoutSnapshotSelectors(t *testing.T) {
	fixture := setupExactRecoveryDualArchYUMFixture(t)
	snapshotIDs := []string{"el10-20260711", "el10-20260712"}
	seedExactRecoveryHistoricalSnapshots(t, fixture, snapshotIDs)

	protocol, guard := installExactRecoveryJournalGuard(t, fixture)
	privateKey, err := os.ReadFile(fixture.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	repositoryKeySHA, err := repositorySigningKeyIdentity(fixture.cfg, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	values := commonFlags{configPath: fixture.configPath, workers: 1, chunk: 2, materializeOperation: "publish"}
	repos := fixture.cfg.Repos
	values.materializeTrust, err = captureMaterializationTrust(fixture.cfg, selectedLeaves(repos, values), privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	originalPublic, err := os.ReadFile(fixture.keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	rotatedKeyPath := writePublishTestPrivateKey(t, t.TempDir())
	rotatedPublic, err := os.ReadFile(rotatedKeyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	var rotateOnce sync.Once
	values.materializeTrust.beforeCheck = func(boundary materializationTrustBoundary) {
		if boundary == materializeTrustSelectedSetFinal {
			rotateOnce.Do(func() {
				atomicReplaceTestFile(t, fixture.keyPath+".pub", rotatedPublic, 0o644)
			})
		}
	}
	pool, err := repository.NewStore(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(fixture.cfg.StatePath(), "multi-snapshot-journal-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(txDir)
	var failedOutput bytes.Buffer
	partial, publishErr := publishSnapshotSet(t.Context(), fixture.cfg, fixture.canonical, pool, repos, snapshotIDs, []string{"cf"}, txDir, values, privateKey, nil, repositoryKeySHA, &failedOutput)
	if publishErr == nil || partial || !strings.Contains(publishErr.Error(), "selected-set trust barrier failed") {
		t.Fatalf("multi-snapshot final-barrier injection partial=%t err=%v output=%s", partial, publishErr, failedOutput.String())
	}
	journal, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath())
	if err != nil || !exists || journal.Phase != materializationSelectionDrifted || len(journal.Units) != 4 || len(journal.CompletedUnits) != 4 {
		t.Fatalf("multi-snapshot publication journal=%+v exists=%t err=%v", journal, exists, err)
	}
	seenSources := make(map[string]int)
	for _, unit := range journal.Units {
		seenSources[unit.Source]++
		if unit.Historical || unit.Repo != "rpm-test" {
			t.Fatalf("multi-snapshot journal contains non-snapshot unit: %+v", unit)
		}
	}
	for _, snapshotID := range snapshotIDs {
		if seenSources[snapshotID] != 2 {
			t.Fatalf("snapshot %s durable units=%d want=2: %+v", snapshotID, seenSources[snapshotID], journal.Units)
		}
	}
	if calls, callsWithJournal, journalErr := guard.counts(); journalErr != nil || calls != 0 || callsWithJournal != 0 {
		t.Fatalf("failed local snapshot set reached remote calls=%d while_journal=%d journal_err=%v", calls, callsWithJournal, journalErr)
	}

	atomicReplaceTestFile(t, fixture.keyPath+".pub", originalPublic, 0o644)
	code, stdout, stderr := runTopLevelRecoveryCLI(t,
		"publish", "--target", "cf", "--config", fixture.configPath,
		"--gpg-private-key-file", fixture.keyPath, "--workers", "1", "--chunk-entries", "2", "--recover",
	)
	if code != ExitOK {
		t.Fatalf("default multi-snapshot recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	calls, callsWithJournal, journalErr := guard.counts()
	if journalErr != nil || calls == 0 || callsWithJournal != 0 {
		t.Fatalf("multi-snapshot remote ordering calls=%d while_journal=%d journal_err=%v stdout=%s", calls, callsWithJournal, journalErr, stdout)
	}
	if _, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath()); err != nil || exists {
		t.Fatalf("default publish recovery retained multi-snapshot journal exists=%t err=%v", exists, err)
	}
	for _, snapshotID := range snapshotIDs {
		if !strings.Contains(stdout, "publish materialized snapshot="+snapshotID) {
			t.Fatalf("default recovery did not materialize durable snapshot %s: %s", snapshotID, stdout)
		}
		protocol.mutex.Lock()
		_, routeExists := protocol.objects[".sow/snapshots/"+snapshotID+".json"]
		protocol.mutex.Unlock()
		if !routeExists {
			t.Fatalf("default publication omitted recovered snapshot route %s", snapshotID)
		}
	}
	for _, view := range []string{"beta", "latest", "stable"} {
		if !strings.Contains(stdout, "view="+view) {
			t.Fatalf("default selection did not complete view %s after multi-snapshot recovery: %s", view, stdout)
		}
	}
}
