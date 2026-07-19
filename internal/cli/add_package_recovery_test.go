package cli

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestPackageAddRecoveryFamilyRejectsMixedAndHistoricalUnits(t *testing.T) {
	base := materializationSelectionJournal{Operation: "add", Units: []materializationSelectedUnit{{Kind: "apt"}}}
	if err := validatePackageAddRecoveryFamily(base, true, "apt"); err != nil {
		t.Fatalf("exact APT family rejected: %v", err)
	}
	for name, mutate := range map[string]func(*materializationSelectionJournal){
		"mixed": func(journal *materializationSelectionJournal) {
			journal.Units = append(journal.Units, materializationSelectedUnit{Kind: "yum"})
		},
		"asset":      func(journal *materializationSelectionJournal) { journal.Units[0].Kind = "asset" },
		"historical": func(journal *materializationSelectionJournal) { journal.Units[0].Historical = true },
		"scope":      func(journal *materializationSelectionJournal) { journal.OperationScope = "unexpected" },
	} {
		t.Run(name, func(t *testing.T) {
			journal := base
			journal.Units = append([]materializationSelectedUnit(nil), base.Units...)
			mutate(&journal)
			if err := validatePackageAddRecoveryFamily(journal, true, "apt"); err == nil {
				t.Fatal("unsafe package add recovery family was admitted")
			}
		})
	}
	if err := validatePackageAddRecoveryFamily(base, false, "apt"); err == nil {
		t.Fatal("package add recovery without --recover was admitted")
	}
}

func TestPackageAddRecoveryFencesCASByFamilyAndFrozenEntries(t *testing.T) {
	root := t.TempDir()
	_, keyPath := writeMaterializeSigningKey(t, root)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(packageRecoveryTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "yum/test/x86_64", "apt/test", "asset/test")

	firstRPM := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "first.rpm"))
	firstInfo, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: firstRPM})
	if err != nil {
		t.Fatal(err)
	}
	// Force the first real CLI add to fail only after it has committed the view
	// and persisted the selected-set fence. A foreign payload at the exact live
	// path is never replaced by package materialization.
	conflict := filepath.Join(root, config.StateDirectory, "materialized", "beta", "yum", "test", "x86_64", filepath.FromSlash(firstInfo.Location))
	if err := os.MkdirAll(filepath.Dir(conflict), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conflict, []byte("foreign-payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"add", firstRPM, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitVerification {
		t.Fatalf("seed interrupted RPM add code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	journal, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !exists || journal.Operation != "add" || len(journal.Units) != 1 || journal.Units[0].Kind != "yum" || journal.Phase != materializationSelectionMaterializing {
		t.Fatalf("seed durable RPM journal exists=%v journal=%+v err=%v", exists, journal, err)
	}
	projection, projectionExists, err := readPackageProjectionIntent(cfg.StatePath())
	if err != nil || !projectionExists || projection.Operation != "add" || projection.Family != "yum" || len(projection.Units) != 1 {
		t.Fatalf("seed durable RPM projection exists=%v projection=%+v err=%v", projectionExists, projection, err)
	}
	firstObject := packageRecoveryObjectPath(t, root, firstInfo.SHA256)
	if _, err := os.Stat(firstObject); err != nil {
		t.Fatalf("seed RPM CAS object missing: %v", err)
	}

	// A different package family must stop under the lock before canonical
	// preparation and, critically, before the candidate DEB reaches CAS.
	novelDEB := writeSyncMinimalDEB(t, root, "novel-deb", "1.0", "arm64")
	novelDEBInfo, err := aptrepo.InspectPackage(t.Context(), novelDEB, "main")
	if err != nil {
		t.Fatal(err)
	}
	novelDEBObject := packageRecoveryObjectPath(t, root, novelDEBInfo.SHA256)
	if _, err := os.Stat(novelDEBObject); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("novel DEB unexpectedly existed before recovery admission: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"add", novelDEB, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--recover", "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitConflict || !strings.Contains(stderr.String(), "family differs") {
		t.Fatalf("cross-family recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(novelDEBObject); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cross-family recovery mutated CAS: %v", err)
	}

	// Asset dispatch has its own importer, so it needs the same early fence as
	// both package branches. The top-level asset recovery intentionally defers a
	// package journal; the locked asset branch must then reject it without CAS.
	novelAsset := filepath.Join(root, "novel.tar.gz")
	novelAssetBody := []byte("novel-asset")
	if err := os.WriteFile(novelAsset, novelAssetBody, 0o444); err != nil {
		t.Fatal(err)
	}
	novelAssetSHA := sha256.Sum256(novelAssetBody)
	novelAssetObject := packageRecoveryObjectPath(t, root, fmt.Sprintf("%x", novelAssetSHA[:]))
	if _, err := os.Stat(novelAssetObject); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("novel asset unexpectedly existed before recovery admission: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"add", novelAsset, "--config", configPath, "--repo", "asset-test", "--recover", "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitConflict || !strings.Contains(stderr.String(), "before a new asset input") {
		t.Fatalf("package-to-asset recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(novelAssetObject); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("package-to-asset recovery mutated CAS: %v", err)
	}

	// A same-family retry has the same leaf unit ID, so unit equality alone is
	// insufficient. The full candidate entry is absent from the frozen ref and
	// must be rejected before its novel digest is imported.
	novelRPM := writeRestoreRPMFixture(t, root, "2.0.0")
	novelRPMInfo, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: novelRPM})
	if err != nil {
		t.Fatal(err)
	}
	novelRPMObject := packageRecoveryObjectPath(t, root, novelRPMInfo.SHA256)
	if _, err := os.Stat(novelRPMObject); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("novel RPM unexpectedly existed before recovery admission: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"add", novelRPM, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--recover", "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitConflict || !strings.Contains(stderr.String(), "absent from frozen ref") {
		t.Fatalf("same-family novel-input recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(novelRPMObject); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("same-family novel-input recovery mutated CAS: %v", err)
	}
	if _, stillExists, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil || !stillExists {
		t.Fatalf("rejected retries changed durable journal exists=%v err=%v", stillExists, err)
	}
	if current, stillExists, err := readPackageProjectionIntent(cfg.StatePath()); err != nil || !stillExists || current.ID != projection.ID {
		t.Fatalf("rejected retries changed durable RPM projection exists=%v current=%+v err=%v", stillExists, current, err)
	}

	// A durable prepared journal belongs to the interrupted operation, not this
	// retry. Exact admission must persist materializing before returning control
	// to any CAS/open/materializer step, so even an immediate caller failure
	// cannot make a later finish path delete the only recovery record.
	journal, _, err = readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	journal.Phase = materializationSelectionPrepared
	if err := writeMaterializationSelectionJournal(cfg.StatePath(), journal); err != nil {
		t.Fatal(err)
	}
	repo, exists := cfg.RepoByName("rpm-test")
	if !exists {
		t.Fatal("rpm-test config disappeared")
	}
	groups, err := planRPMLeafGroups([]rpmInputPlan{{input: firstRPM, snapshot: firstRPM, info: firstInfo, repo: repo, arches: []string{"x86_64"}}})
	if err != nil {
		t.Fatal(err)
	}
	requests, err := packageAddMaterializationRequests(cfg, groups)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	repositoryKeySHA, err := repositorySigningKeyIdentity(cfg, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := captureMaterializationTrust(cfg, []viewLeaf{{repo: repo, os: "el10", arch: "x86_64"}}, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireExactPackageAddRecoveryBeforeCAS(cfg, state.New(cfg.StatePath()), commonFlags{recover: true, materializeTrust: trust}, "yum", requests, groups); err != nil {
		t.Fatalf("exact prepared recovery admission: %v", err)
	}
	promoted, stillExists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !stillExists || promoted.Phase != materializationSelectionMaterializing || promoted.ID != journal.ID || !slices.Equal(promoted.CompletedUnits, journal.CompletedUnits) {
		t.Fatalf("prepared recovery did not advance phase only exists=%v phase=%s id=%s want_id=%s completed=%v want_completed=%v err=%v", stillExists, promoted.Phase, promoted.ID, journal.ID, promoted.CompletedUnits, journal.CompletedUnits, err)
	}

	// Exact same-input recovery is allowed to Put the inspected bytes solely to
	// repair a missing CAS object, then converges the frozen ref and clears the
	// journal without requiring any new canonical business commit.
	if err := os.Remove(firstObject); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(conflict); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"add", firstRPM, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--recover", "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("exact RPM recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(firstObject); err != nil {
		t.Fatalf("exact recovery did not restore CAS: %v", err)
	}
	if _, stillExists, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil || stillExists {
		t.Fatalf("exact recovery did not clear durable journal exists=%v err=%v", stillExists, err)
	}
	if _, stillExists, err := readPackageProjectionIntent(cfg.StatePath()); err != nil || stillExists {
		t.Fatalf("exact recovery did not clear durable RPM projection exists=%v err=%v", stillExists, err)
	}
	liveRPM := filepath.Join(root, config.StateDirectory, "materialized", "beta", "yum", "test", "x86_64", filepath.FromSlash(firstInfo.Location))
	liveInfo, err := os.Stat(liveRPM)
	if err != nil {
		t.Fatal(err)
	}
	casInfo, err := os.Stat(firstObject)
	if err != nil || !os.SameFile(liveInfo, casInfo) {
		t.Fatalf("recovered RPM is not a CAS hardlink: %v", err)
	}
}

func TestDEBAddRecoveryFencesCASByFrozenEntriesAndRestoresExactObject(t *testing.T) {
	root := t.TempDir()
	_, keyPath := writeMaterializeSigningKey(t, root)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(packageRecoveryTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "yum/test/x86_64", "apt/test", "asset/test")

	firstDEB := writeSyncMinimalDEB(t, root, "first-deb", "1.0", "arm64")
	firstInfo, err := aptrepo.InspectPackage(t.Context(), firstDEB, "main")
	if err != nil {
		t.Fatal(err)
	}
	conflict := filepath.Join(root, config.StateDirectory, "materialized", "beta", "apt", "test", filepath.FromSlash(firstInfo.PoolPath))
	if err := os.MkdirAll(filepath.Dir(conflict), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conflict, []byte("foreign-deb-payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"add", firstDEB, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitVerification {
		t.Fatalf("seed interrupted DEB add code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	journal, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !exists || journal.Operation != "add" || len(journal.Units) != 1 || journal.Units[0].Kind != "apt" || journal.Phase != materializationSelectionMaterializing {
		t.Fatalf("seed durable DEB journal exists=%v journal=%+v err=%v", exists, journal, err)
	}
	projection, projectionExists, err := readPackageProjectionIntent(cfg.StatePath())
	if err != nil || !projectionExists || projection.Operation != "add" || projection.Family != "apt" || len(projection.Units) != 1 {
		t.Fatalf("seed durable DEB projection exists=%v projection=%+v err=%v", projectionExists, projection, err)
	}
	firstObject := packageRecoveryObjectPath(t, root, firstInfo.SHA256)
	if _, err := os.Stat(firstObject); err != nil {
		t.Fatalf("seed DEB CAS object missing: %v", err)
	}

	novelDEB := writeSyncMinimalDEB(t, root, "novel-deb", "2.0", "arm64")
	novelInfo, err := aptrepo.InspectPackage(t.Context(), novelDEB, "main")
	if err != nil {
		t.Fatal(err)
	}
	novelObject := packageRecoveryObjectPath(t, root, novelInfo.SHA256)
	if _, err := os.Stat(novelObject); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("novel DEB unexpectedly existed before recovery admission: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"add", novelDEB, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--recover", "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitConflict || !strings.Contains(stderr.String(), "absent from frozen ref") {
		t.Fatalf("same-family novel DEB recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(novelObject); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("same-family novel DEB recovery mutated CAS: %v", err)
	}
	if _, stillExists, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil || !stillExists {
		t.Fatalf("rejected DEB retry changed durable journal exists=%v err=%v", stillExists, err)
	}
	if current, stillExists, err := readPackageProjectionIntent(cfg.StatePath()); err != nil || !stillExists || current.ID != projection.ID {
		t.Fatalf("rejected DEB retry changed durable projection exists=%v current=%+v err=%v", stillExists, current, err)
	}

	if err := os.Remove(firstObject); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(conflict); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"add", firstDEB, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--recover", "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("exact DEB recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(firstObject); err != nil {
		t.Fatalf("exact DEB recovery did not restore CAS: %v", err)
	}
	if _, stillExists, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil || stillExists {
		t.Fatalf("exact DEB recovery did not clear durable journal exists=%v err=%v", stillExists, err)
	}
	if _, stillExists, err := readPackageProjectionIntent(cfg.StatePath()); err != nil || stillExists {
		t.Fatalf("exact DEB recovery did not clear durable projection exists=%v err=%v", stillExists, err)
	}
	liveDEB := filepath.Join(root, config.StateDirectory, "materialized", "beta", "apt", "test", filepath.FromSlash(firstInfo.PoolPath))
	liveInfo, err := os.Stat(liveDEB)
	if err != nil {
		t.Fatal(err)
	}
	casInfo, err := os.Stat(firstObject)
	if err != nil || !os.SameFile(liveInfo, casInfo) {
		t.Fatalf("recovered DEB is not a CAS hardlink: %v", err)
	}
}

func TestPositionalPackageProjectionRecoversPreApplyWindows(t *testing.T) {
	for _, test := range []struct {
		name   string
		family string
	}{
		{name: "apt", family: "apt"},
		{name: "yum", family: "yum"},
	} {
		test := test
		for _, phase := range []string{"after-fence-before-apply", "after-transaction-intent-before-commit"} {
			phase := phase
			t.Run(test.name+"/"+phase, func(t *testing.T) {
				var root, configPath, packagePath, keyPath, repo, digest string
				if test.family == "apt" {
					root, configPath, packagePath, keyPath = preparePackageNoopDEB(t)
					repo = "deb-test"
					info, err := aptrepo.InspectPackage(t.Context(), packagePath, "main")
					if err != nil {
						t.Fatal(err)
					}
					digest = info.SHA256
				} else {
					root, configPath, packagePath, keyPath = preparePackageNoopRPM(t)
					repo = "rpm-test"
					info, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: packagePath})
					if err != nil {
						t.Fatal(err)
					}
					digest = info.SHA256
				}
				previous := packageProjectionMutationHook
				packageProjectionMutationHook = func(current string) error {
					if current == phase {
						return errors.New("injected positional package pre-Apply failure")
					}
					return nil
				}
				t.Cleanup(func() { packageProjectionMutationHook = previous })
				arguments := []string{packagePath, "--config", configPath, "--repo", repo, "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}
				var stdout, stderr bytes.Buffer
				if err := runAdd(t.Context(), arguments, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "injected positional package pre-Apply failure") {
					t.Fatalf("seed positional %s phase=%s err=%v stdout=%s stderr=%s", test.family, phase, err, stdout.String(), stderr.String())
				}
				packageProjectionMutationHook = nil
				cfg, err := config.Load(configPath, "")
				if err != nil {
					t.Fatal(err)
				}
				intent, exists, err := readPackageProjectionIntent(cfg.StatePath())
				if err != nil || !exists || intent.Family != test.family {
					t.Fatalf("positional bridge phase=%s exists=%t intent=%+v err=%v", phase, exists, intent, err)
				}
				record, transactionExists, err := state.New(cfg.StatePath()).Transaction(intent.TransactionID)
				if err != nil {
					t.Fatal(err)
				}
				if phase == "after-fence-before-apply" && transactionExists {
					t.Fatalf("pre-Apply bridge unexpectedly has transaction %+v", record)
				}
				if phase == "after-transaction-intent-before-commit" && (!transactionExists || record.Phase != "intent") {
					t.Fatalf("intent window transaction exists=%t record=%+v", transactionExists, record)
				}
				if _, exists, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil || exists {
					t.Fatalf("pre-Apply positional bridge unexpectedly has selected set exists=%t err=%v", exists, err)
				}

				stdout.Reset()
				stderr.Reset()
				recovered, err := recoverPendingAssetAddMaterialization(t.Context(), cfg, commonFlags{recover: true, workers: 1, chunk: 1}, false, &stdout, &stderr)
				if err != nil || recovered {
					t.Fatalf("asset retry crossed package bridge phase=%s recovered=%t err=%v stdout=%s stderr=%s", phase, recovered, err, stdout.String(), stderr.String())
				}
				afterForeign, afterExists, err := state.New(cfg.StatePath()).Transaction(intent.TransactionID)
				if err != nil || afterExists != transactionExists || afterExists && (afterForeign.Phase != record.Phase || afterForeign.Commit != record.Commit) {
					t.Fatalf("asset retry advanced package transaction phase=%s before=%+v exists=%t after=%+v exists=%t err=%v", phase, record, transactionExists, afterForeign, afterExists, err)
				}

				objectPath := packageRecoveryObjectPath(t, root, digest)
				if err := os.Remove(objectPath); err != nil {
					t.Fatal(err)
				}
				stdout.Reset()
				stderr.Reset()
				code := Main(append([]string{"add"}, append(arguments, "--recover")...), &stdout, &stderr)
				if code != ExitOK {
					t.Fatalf("positional %s recovery phase=%s code=%d stdout=%s stderr=%s", test.family, phase, code, stdout.String(), stderr.String())
				}
				if _, err := os.Stat(objectPath); err != nil {
					t.Fatalf("positional %s recovery did not repair CAS: %v", test.family, err)
				}
				if _, exists, err := readPackageProjectionIntent(cfg.StatePath()); err != nil || exists {
					t.Fatalf("positional %s recovery retained bridge exists=%t err=%v", test.family, exists, err)
				}
				if _, exists, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil || exists {
					t.Fatalf("positional %s recovery retained selected set exists=%t err=%v", test.family, exists, err)
				}
			})
		}
	}
}

func TestDEBAddPrivateSnapshotClosesSourcePathSwapBeforeCAS(t *testing.T) {
	root := t.TempDir()
	source := writeSyncMinimalDEB(t, root, "snapshot-deb", "1.0", "arm64")
	replacementDir := t.TempDir()
	replacement := writeSyncMinimalDEB(t, replacementDir, "replacement-deb", "2.0", "arm64")
	snapshotDir, err := os.MkdirTemp("", "sow-add-deb-snapshot-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(snapshotDir) })
	snapshot, err := snapshotDEBInput(t.Context(), source, snapshotDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	inspected, err := aptrepo.InspectPackageAs(t.Context(), snapshot, "main", filepath.Base(source))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(inspected.PoolPath, "/"+filepath.Base(source)) {
		t.Fatalf("private snapshot lost original DEB basename: %s", inspected.PoolPath)
	}
	replacementBody, err := os.ReadFile(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, replacementBody, 0o444); err != nil {
		t.Fatal(err)
	}
	replacementInfo, err := aptrepo.InspectPackageAs(t.Context(), source, "main", filepath.Base(source))
	if err != nil {
		t.Fatal(err)
	}
	if replacementInfo.SHA256 == inspected.SHA256 {
		t.Fatal("replacement fixture did not change DEB identity")
	}
	digest, err := repository.ParseDigest(inspected.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	wanted := repository.Object{SHA256: digest, Size: inspected.Size}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	object, err := pool.ImportExpected(t.Context(), snapshot, wanted)
	if err != nil || object != wanted {
		t.Fatalf("import private DEB snapshot object=%+v err=%v", object, err)
	}
	if _, err := os.Stat(packageRecoveryObjectPath(t, root, replacementInfo.SHA256)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("post-snapshot caller path replacement entered CAS: %v", err)
	}
}

func packageRecoveryObjectPath(t *testing.T, root, sha256 string) string {
	t.Helper()
	digest, err := repository.ParseDigest(sha256)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	return pool.ObjectPath(digest)
}

const packageRecoveryTestConfig = `schema: sow/v1
state: {}
gpg:
  public_key: repository-public.pgp
pools:
  public: {}
  gated: {}
repos:
  - id: rpm-test
    type: yum
    path: yum/test/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
  - id: deb-test
    type: apt
    path: apt/test
    default_pool: public
    arches: [arm64]
    os: {family: ubuntu, suite: jammy, lifecycle: active}
    apt: {suites: [jammy], components: [main]}
  - id: asset-test
    type: asset
    path: asset/test
    default_pool: public
    asset: {kind: release}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
