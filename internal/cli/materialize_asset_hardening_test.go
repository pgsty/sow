package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

type assetMaterializeCountingTransport struct {
	reads     atomic.Int64
	mutations atomic.Int64
	next      http.RoundTripper
}

func (transport *assetMaterializeCountingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodGet || request.Method == http.MethodHead {
		transport.reads.Add(1)
	} else {
		transport.mutations.Add(1)
	}
	return transport.next.RoundTrip(request)
}

func TestAssetAddAndPublishReplaceOnlyConfiguredMutablePaths(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(assetMaterializePublishConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	mutableInput := addAssetMaterializeFixture(t, configPath, "mutable/tool.bin", "mutable-v1\n", false)
	addAssetMaterializeFixture(t, configPath, "release.bin", "immutable-v1\n", false)

	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	entries := readAssetMaterializeView(t, root, "beta")
	immutable := findAssetMaterializeEntry(t, entries, "asset/release.bin")
	immutableDigest, err := repository.ParseDigest(immutable.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	mutableTarget := filepath.Join(root, ".sow", "materialized", "beta", "asset", "mutable", "tool.bin")
	immutableTarget := filepath.Join(root, ".sow", "materialized", "beta", "asset", "release.bin")
	replaceWithOrdinaryAssetDrift(t, immutableTarget, "immutable add drift\n")
	if err := os.WriteFile(mutableInput, []byte("mutable-v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	addArguments := []string{
		"add", mutableInput, "--config", configPath, "--repo", "asset", "--dest", "mutable/tool.bin", "--replace",
		"--workers", "1", "--chunk-entries", "1",
	}
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t, addArguments...)
	if code != ExitVerification || !strings.Contains(stderr, "materialization path conflict") {
		t.Fatalf("add widened mutable replacement to immutable sibling code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	assertAssetSelectedSetFailure(t, root, "add")
	entries = readAssetMaterializeView(t, root, "beta")
	mutable := findAssetMaterializeEntry(t, entries, "asset/mutable/tool.bin")
	mutableDigest, err := repository.ParseDigest(mutable.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	assertAssetMaterializeHardlink(t, pool.ObjectPath(mutableDigest), mutableTarget, "mutable-v2\n")
	assertAssetOrdinaryDrift(t, pool.ObjectPath(immutableDigest), immutableTarget, "immutable add drift\n")

	if err := os.Remove(immutableTarget); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, append(append([]string(nil), addArguments...), "--recover")...)
	if code != ExitOK || !strings.Contains(stdout, "add unchanged repo=asset") {
		t.Fatalf("add exact recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	assertAssetSelectedSetCleared(t, root)
	assertAssetMaterializeHardlink(t, pool.ObjectPath(immutableDigest), immutableTarget, "immutable-v1\n")

	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	protocol := newCloudProtocolTransport()
	counting := &assetMaterializeCountingTransport{next: protocol}
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: counting}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	publishArguments := []string{
		"publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "asset",
		"--workers", "1", "--chunk-entries", "1",
	}
	replaceWithOrdinaryAssetDrift(t, mutableTarget, "mutable publish drift\n")
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, publishArguments...)
	if code != ExitOK || counting.mutations.Load() == 0 {
		t.Fatalf("publish did not converge configured mutable path code=%d reads=%d mutations=%d stdout=%s stderr=%s", code, counting.reads.Load(), counting.mutations.Load(), stdout, stderr)
	}
	assertAssetMaterializeHardlink(t, pool.ObjectPath(mutableDigest), mutableTarget, "mutable-v2\n")
	if err := os.WriteFile(mutableInput, []byte("mutable-v3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, addArguments...)
	if code != ExitOK || !strings.Contains(stdout, "replaced=1") {
		t.Fatalf("advance mutable ref before publish conflict code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	entries = readAssetMaterializeView(t, root, "beta")
	mutable = findAssetMaterializeEntry(t, entries, "asset/mutable/tool.bin")
	mutableDigest, err = repository.ParseDigest(mutable.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	assertAssetMaterializeHardlink(t, pool.ObjectPath(mutableDigest), mutableTarget, "mutable-v3\n")

	counting.reads.Store(0)
	counting.mutations.Store(0)
	replaceWithOrdinaryAssetDrift(t, immutableTarget, "immutable publish drift\n")
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, publishArguments...)
	if code != ExitVerification || !strings.Contains(stderr, "materialization path conflict") {
		t.Fatalf("publish widened mutable replacement to immutable sibling code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if reads := counting.reads.Load(); reads != 0 {
		t.Fatalf("stale local route capability reached remote preflight before exact local convergence: reads=%d", reads)
	}
	if mutations := counting.mutations.Load(); mutations != 0 {
		t.Fatalf("immutable local drift reached remote mutation path: mutations=%d reads=%d", mutations, counting.reads.Load())
	}
	assertAssetSelectedSetFailure(t, root, "publish")
	assertAssetOrdinaryDrift(t, pool.ObjectPath(immutableDigest), immutableTarget, "immutable publish drift\n")

	if err := os.Remove(immutableTarget); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, append(append([]string(nil), publishArguments...), "--recover")...)
	if code != ExitOK || counting.mutations.Load() == 0 {
		t.Fatalf("publish exact recovery code=%d reads=%d mutations=%d stdout=%s stderr=%s", code, counting.reads.Load(), counting.mutations.Load(), stdout, stderr)
	}
	assertAssetSelectedSetCleared(t, root)
	assertAssetMaterializeHardlink(t, pool.ObjectPath(immutableDigest), immutableTarget, "immutable-v1\n")
	assertAssetMaterializeHardlink(t, pool.ObjectPath(mutableDigest), mutableTarget, "mutable-v3\n")
}

func TestAssetOnlyDirectMaterializeFailureRetainsSelectedSetAndRecoversExactly(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	firstBody := "first asset bytes\n"
	secondBody := "second asset bytes\n"
	addAssetMaterializeFixture(t, configPath, "a-first.bin", firstBody, false)
	addAssetMaterializeFixture(t, configPath, "z-second.bin", secondBody, false)

	entries := readAssetMaterializeView(t, root, "beta")
	if len(entries) != 2 || entries[0].Path != "asset/a-first.bin" || entries[1].Path != "asset/z-second.bin" {
		t.Fatalf("seed asset ref entries=%+v", entries)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := repository.ParseDigest(entries[0].SHA256)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := repository.ParseDigest(entries[1].SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pool.ObjectPath(secondDigest)); err != nil {
		t.Fatal(err)
	}

	arguments := []string{
		"materialize", "beta", "--config", configPath, "--repo", "asset",
		"--target", "failed-export", "--workers", "1", "--chunk-entries", "1",
	}
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t, arguments...)
	if code != ExitConflict || !strings.Contains(stderr, "materialize beta") {
		t.Fatalf("missing-CAS materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	firstTarget := filepath.Join(root, "failed-export", "asset", "a-first.bin")
	secondTarget := filepath.Join(root, "failed-export", "asset", "z-second.bin")
	assertAssetMaterializeHardlink(t, pool.ObjectPath(firstDigest), firstTarget, firstBody)
	if _, err := os.Lstat(secondTarget); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed entry unexpectedly materialized: %v", err)
	}

	journal, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow"))
	if err != nil || !exists {
		t.Fatalf("read active selected-set journal exists=%t err=%v", exists, err)
	}
	if journal.Operation != "materialize" || journal.Phase != materializationSelectionMaterializing || len(journal.Units) != 1 || len(journal.CompletedUnits) != 0 {
		t.Fatalf("partial asset mutation was not durably fenced: %+v", journal)
	}
	unit := journal.Units[0]
	if unit.Kind != "asset" || unit.Source != "beta" || unit.Repo != "asset" || unit.OS != "all" || unit.Arch != "all" {
		t.Fatalf("unexpected durable asset unit: %+v", unit)
	}

	blockedInput := filepath.Join(t.TempDir(), "blocked.bin")
	blockedBody := "must not enter CAS\n"
	if err := os.WriteFile(blockedInput, []byte(blockedBody), 0o600); err != nil {
		t.Fatal(err)
	}
	blockedObject, err := pool.Put(context.Background(), strings.NewReader(blockedBody))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pool.ObjectPath(blockedObject.SHA256)); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"add", blockedInput, "--config", configPath, "--repo", "asset", "--dest", "blocked.bin",
	)
	if code != ExitConflict || !strings.Contains(stderr, "incomplete materialization operation materialize blocks add") {
		t.Fatalf("foreign writer crossed selected-set fence code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Lstat(pool.ObjectPath(blockedObject.SHA256)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blocked writer imported bytes before the fence: %v", err)
	}

	restored, err := pool.Put(context.Background(), strings.NewReader(secondBody))
	if err != nil || restored.SHA256 != secondDigest {
		t.Fatalf("restore missing CAS digest=%s want=%s err=%v", restored.HashString(), secondDigest.String(), err)
	}
	recoveryArguments := append(append([]string(nil), arguments...), "--recover")
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, recoveryArguments...)
	if code != ExitOK {
		t.Fatalf("exact asset recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if current, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("exact recovery retained journal=%+v exists=%t err=%v", current, exists, err)
	}
	assertAssetMaterializeHardlink(t, pool.ObjectPath(firstDigest), firstTarget, firstBody)
	assertAssetMaterializeHardlink(t, pool.ObjectPath(secondDigest), secondTarget, secondBody)
}

func TestStandaloneAssetAddFailureRetainsDurableSelectedSetAndRecovers(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	inputDir := t.TempDir()
	firstInput := filepath.Join(inputDir, "a-first.bin")
	secondInput := filepath.Join(inputDir, "z-second.bin")
	firstBody := "standalone first asset\n"
	secondBody := "standalone second asset\n"
	if err := os.WriteFile(firstInput, []byte(firstBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondInput, []byte(secondBody), 0o600); err != nil {
		t.Fatal(err)
	}
	conflict := filepath.Join(root, ".sow", "materialized", "beta", "asset", "z-second.bin")
	if err := os.MkdirAll(filepath.Dir(conflict), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conflict, []byte("unmanaged conflict\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{
		"add", firstInput, secondInput, "--config", configPath, "--repo", "asset",
		"--workers", "1", "--chunk-entries", "1",
	}
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t, arguments...)
	if code != ExitVerification || !strings.Contains(stderr, "materialize asset view") {
		t.Fatalf("partial standalone add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	entries := readAssetMaterializeView(t, root, "beta")
	if len(entries) != 2 {
		t.Fatalf("standalone add canonical entries=%+v", entries)
	}
	first := findAssetMaterializeEntry(t, entries, "asset/a-first.bin")
	second := findAssetMaterializeEntry(t, entries, "asset/z-second.bin")
	firstDigest, err := repository.ParseDigest(first.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := repository.ParseDigest(second.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	assertAssetMaterializeHardlink(t, pool.ObjectPath(firstDigest), filepath.Join(root, ".sow", "materialized", "beta", "asset", "a-first.bin"), firstBody)
	if body, err := os.ReadFile(conflict); err != nil || string(body) != "unmanaged conflict\n" {
		t.Fatalf("standalone conflict changed body=%q err=%v", body, err)
	}

	journal, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow"))
	if err != nil || !exists {
		t.Fatalf("read standalone add journal exists=%t err=%v", exists, err)
	}
	if journal.Operation != "add" || journal.OperationScope != "" || journal.Phase != materializationSelectionMaterializing ||
		journal.RepositoryKeySHA256 != materializationNoRepositoryKeySHA256 || len(journal.Units) != 1 || len(journal.CompletedUnits) != 0 {
		t.Fatalf("standalone add did not retain exact no-key selected set: %+v", journal)
	}
	unit := journal.Units[0]
	if unit.Kind != "asset" || unit.Source != "beta" || unit.Repo != "asset" || unit.OS != "all" || unit.Arch != "all" {
		t.Fatalf("standalone add durable unit=%+v", unit)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"promote", "beta", "latest", "--config", configPath, "--repo", "asset",
	)
	if code != ExitConflict || !strings.Contains(stderr, "durable materialization intent") {
		t.Fatalf("foreign writer crossed standalone add fence code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	if err := os.Remove(conflict); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(firstInput); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(secondInput); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"add", "--config", configPath, "--repo", "asset", "--workers", "1", "--chunk-entries", "1", "--recover",
	)
	if code != ExitOK || !strings.Contains(stdout, "recovered asset add repo=asset view=beta") {
		t.Fatalf("standalone add recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if current, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("standalone add recovery retained journal=%+v exists=%t err=%v", current, exists, err)
	}
	assertAssetMaterializeHardlink(t, pool.ObjectPath(firstDigest), filepath.Join(root, ".sow", "materialized", "beta", "asset", "a-first.bin"), firstBody)
	assertAssetMaterializeHardlink(t, pool.ObjectPath(secondDigest), filepath.Join(root, ".sow", "materialized", "beta", "asset", "z-second.bin"), secondBody)

	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"add", "--config", configPath, "--repo", "asset", "--recover",
	)
	if code != ExitUsage || !strings.Contains(stderr, "add requires at least one input file") {
		t.Fatalf("inputless add without journal code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestAssetAddHelpDocumentsInputlessRecovery(t *testing.T) {
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t, "add", "--help")
	combined := stdout + stderr
	if code != ExitOK || !strings.Contains(combined, "Usage: sow add [<file>...]") ||
		!strings.Contains(combined, "omitted input list is valid only with --recover") {
		t.Fatalf("asset add help code=%d output=%s", code, combined)
	}
}

func TestAssetAddRecoveryPrecedesCurrentSubtypeDispatch(t *testing.T) {
	tests := []struct {
		name       string
		extension  string
		wantCode   int
		wantStderr string
	}{
		{name: "asset", extension: ".bin", wantCode: ExitConflict, wantStderr: "import"},
		{name: "rpm", extension: ".rpm", wantCode: ExitConflict, wantStderr: "snapshot RPM"},
		{name: "deb", extension: ".deb", wantCode: ExitConflict, wantStderr: "snapshot DEB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, configPath, originalInput, conflict, digest, body, _ := leaveStandaloneAssetAddMaterialization(t)
			if err := os.Remove(originalInput); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(conflict); err != nil {
				t.Fatal(err)
			}
			missingCurrentInput := filepath.Join(t.TempDir(), "new-request"+tt.extension)
			code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
				"add", missingCurrentInput, "--config", configPath, "--repo", "asset",
				"--workers", "1", "--chunk-entries", "1", "--recover",
			)
			if code != tt.wantCode || !strings.Contains(stdout, "recovered asset add repo=asset view=beta") || !strings.Contains(stderr, tt.wantStderr) {
				t.Fatalf("recover-before-%s-dispatch code=%d stdout=%s stderr=%s", tt.name, code, stdout, stderr)
			}
			if current, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
				t.Fatalf("%s dispatch retained recovered journal=%+v exists=%t err=%v", tt.name, current, exists, err)
			}
			pool, err := repository.NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			assertAssetMaterializeHardlink(t, pool.ObjectPath(digest), filepath.Join(root, ".sow", "materialized", "beta", "asset", "frozen.bin"), body)
		})
	}
}

func TestAssetAddRecoveryThenProcessesCurrentNewAsset(t *testing.T) {
	root, configPath, originalInput, conflict, frozenDigest, frozenBody, _ := leaveStandaloneAssetAddMaterialization(t)
	if err := os.Remove(originalInput); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(conflict); err != nil {
		t.Fatal(err)
	}
	currentInput := filepath.Join(t.TempDir(), "current.bin")
	currentBody := "current request after recovery\n"
	if err := os.WriteFile(currentInput, []byte(currentBody), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
		"add", currentInput, "--config", configPath, "--repo", "asset", "--dest", "current.bin",
		"--workers", "1", "--chunk-entries", "1", "--recover",
	)
	if code != ExitOK || !strings.Contains(stdout, "recovered asset add repo=asset view=beta") || !strings.Contains(stdout, "added repo=asset") {
		t.Fatalf("recover then current asset code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if current, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("recover then current asset retained journal=%+v exists=%t err=%v", current, exists, err)
	}
	entries := readAssetMaterializeView(t, root, "beta")
	current := findAssetMaterializeEntry(t, entries, "asset/current.bin")
	currentDigest, err := repository.ParseDigest(current.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	assertAssetMaterializeHardlink(t, pool.ObjectPath(frozenDigest), filepath.Join(root, ".sow", "materialized", "beta", "asset", "frozen.bin"), frozenBody)
	assertAssetMaterializeHardlink(t, pool.ObjectPath(currentDigest), filepath.Join(root, ".sow", "materialized", "beta", "asset", "current.bin"), currentBody)
}

func TestAssetAddRecoveryRejectsNonExactEnvelopeWithoutClearing(t *testing.T) {
	root, configPath, _, _, _, _, journal := leaveStandaloneAssetAddMaterialization(t)
	journal.OperationScope = "not-an-asset-add-scope"
	journal.ID, _ = materializationSelectionJournalID(journal)
	if err := writeMaterializationSelectionJournal(filepath.Join(root, ".sow"), journal); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
		"add", "--config", configPath, "--repo", "asset", "--recover",
	)
	if code != ExitConflict || !strings.Contains(stderr, "decode asset add materialization") {
		t.Fatalf("non-exact inputless recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	current, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow"))
	if err != nil || !exists || current.ID != journal.ID {
		t.Fatalf("rejected recovery changed journal=%+v exists=%t err=%v want_id=%s", current, exists, err, journal.ID)
	}
}

func TestAssetAddRecoveryFailureRetainsPreparedJournal(t *testing.T) {
	root, configPath, _, conflict, digest, _, journal := leaveStandaloneAssetAddMaterialization(t)
	if err := os.Remove(conflict); err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pool.ObjectPath(digest)); err != nil {
		t.Fatal(err)
	}
	journal.Phase = materializationSelectionPrepared
	journal.CompletedUnits = nil
	if err := writeMaterializationSelectionJournal(filepath.Join(root, ".sow"), journal); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
		"add", "--config", configPath, "--repo", "asset", "--recover",
	)
	if code != ExitVerification || !strings.Contains(stderr, "recover asset add materialization") {
		t.Fatalf("prepared recovery failure code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	current, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow"))
	if err != nil || !exists || current.ID != journal.ID || current.Phase != materializationSelectionMaterializing {
		t.Fatalf("failed recovery lost journal=%+v exists=%t err=%v", current, exists, err)
	}
}

func TestDecodeAssetAddMaterializationRequiresExactFrozenAssetUnit(t *testing.T) {
	_, configPath, _, _, _, _, journal := leaveStandaloneAssetAddMaterialization(t)
	cfg, _, err := loadAndSelect(commonFlags{configPath: configPath, workers: 1, chunk: 1})
	if err != nil {
		t.Fatal(err)
	}
	if repo, view, err := decodeAssetAddMaterialization(cfg, journal); err != nil || repo.ID != "asset" || view != "beta" {
		t.Fatalf("valid durable add decode repo=%s view=%s err=%v", repo.ID, view, err)
	}
	tests := []struct {
		name   string
		mutate func(*materializationSelectionJournal)
	}{
		{name: "operation", mutate: func(value *materializationSelectionJournal) { value.Operation = "publish" }},
		{name: "scope", mutate: func(value *materializationSelectionJournal) { value.OperationScope = "scope" }},
		{name: "repository-key", mutate: func(value *materializationSelectionJournal) { value.RepositoryKeySHA256 = strings.Repeat("a", 64) }},
		{name: "yum-keyring", mutate: func(value *materializationSelectionJournal) {
			value.YUMKeyrings = []materializationSelectionKeyring{{Repo: "asset", SHA256: strings.Repeat("b", 64)}}
		}},
		{name: "multiple-units", mutate: func(value *materializationSelectionJournal) { value.Units = append(value.Units, value.Units[0]) }},
		{name: "kind", mutate: func(value *materializationSelectionJournal) { value.Units[0].Kind = "yum" }},
		{name: "historical", mutate: func(value *materializationSelectionJournal) { value.Units[0].Historical = true }},
		{name: "os", mutate: func(value *materializationSelectionJournal) { value.Units[0].OS = "linux" }},
		{name: "arch", mutate: func(value *materializationSelectionJournal) { value.Units[0].Arch = "amd64" }},
		{name: "multiple-refs", mutate: func(value *materializationSelectionJournal) {
			value.Units[0].Refs = append(value.Units[0].Refs, value.Units[0].Refs[0])
		}},
		{name: "source", mutate: func(value *materializationSelectionJournal) { value.Units[0].Source = "stable" }},
		{name: "ref", mutate: func(value *materializationSelectionJournal) {
			value.Units[0].Refs[0].Name = "refs/sow/views/beta/asset/all/other"
		}},
		{name: "target", mutate: func(value *materializationSelectionJournal) { value.Units[0].TargetSHA256 = strings.Repeat("c", 64) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := journal
			candidate.YUMKeyrings = append([]materializationSelectionKeyring(nil), journal.YUMKeyrings...)
			candidate.Units = append([]materializationSelectedUnit(nil), journal.Units...)
			for index := range candidate.Units {
				candidate.Units[index].Refs = append([]materializationSelectionRef(nil), journal.Units[index].Refs...)
			}
			tt.mutate(&candidate)
			if _, _, err := decodeAssetAddMaterialization(cfg, candidate); err == nil {
				t.Fatal("non-exact durable add envelope decoded successfully")
			}
		})
	}
}

func leaveStandaloneAssetAddMaterialization(t *testing.T) (root, configPath, input, conflict string, digest repository.Digest, body string, journal materializationSelectionJournal) {
	t.Helper()
	root, configPath = newAssetMaterializeHardeningFixture(t)
	input = filepath.Join(t.TempDir(), "frozen.bin")
	body = "frozen add recovery bytes\n"
	if err := os.WriteFile(input, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	conflict = filepath.Join(root, ".sow", "materialized", "beta", "asset", "frozen.bin")
	if err := os.MkdirAll(filepath.Dir(conflict), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conflict, []byte("unmanaged conflict\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
		"add", input, "--config", configPath, "--repo", "asset", "--dest", "frozen.bin",
		"--workers", "1", "--chunk-entries", "1",
	)
	if code != ExitVerification || !strings.Contains(stderr, "materialize asset view") {
		t.Fatalf("leave asset add materialization code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	entries := readAssetMaterializeView(t, root, "beta")
	entry := findAssetMaterializeEntry(t, entries, "asset/frozen.bin")
	digest, err := repository.ParseDigest(entry.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	journal, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow"))
	if err != nil || !exists || journal.Operation != "add" || journal.Phase != materializationSelectionMaterializing {
		t.Fatalf("leave asset add journal=%+v exists=%t err=%v", journal, exists, err)
	}
	return root, configPath, input, conflict, digest, body, journal
}

func TestOfflineArchiveAdoptionFailureRecoversScopedAssetBeforeCurrentSelection(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	addAssetMaterializeFixture(t, configPath, "payload.bin", "archive recovery payload\n", false)
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
		"promote", "beta", "latest", "--config", configPath, "--repo", "asset",
	)
	if code != ExitOK {
		t.Fatalf("seed archive recovery latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	conflict := filepath.Join(root, ".sow", "materialized", "beta", "asset", "bundles", "recovery.tgz")
	if err := os.MkdirAll(filepath.Dir(conflict), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conflict, []byte("unmanaged archive conflict\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	failureArguments := []string{
		"materialize", "latest", "--config", configPath, "--repo", "asset", "--target", "archive-source-export",
		"--tgz", "offline/recovery.tgz", "--asset-repo", "asset", "--asset-dest", "bundles/recovery.tgz",
		"--workers", "1", "--chunk-entries", "1",
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, failureArguments...)
	if code != ExitVerification || !strings.Contains(stderr, "materialize asset view") {
		t.Fatalf("archive adoption conflict code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	journal, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow"))
	if err != nil || !exists {
		t.Fatalf("read archive adoption journal exists=%t err=%v", exists, err)
	}
	wantedTarget, err := materializationTargetSHA256(root)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Operation != "materialize" || journal.OperationScope != offlineArchiveAdoptionMaterializationScope ||
		journal.Phase != materializationSelectionMaterializing || journal.RepositoryKeySHA256 != materializationNoRepositoryKeySHA256 ||
		len(journal.Units) != 1 || len(journal.CompletedUnits) != 0 {
		t.Fatalf("archive adoption did not retain scoped asset selected set: %+v", journal)
	}
	if journal.ArchiveAdoption == nil || journal.ArchiveAdoption.Source.ID != "latest" || journal.ArchiveAdoption.Source.Access != "public" ||
		journal.ArchiveAdoption.Source.Confidentiality != "public" || len(journal.ArchiveAdoption.Source.Refs) == 0 ||
		journal.ArchiveAdoption.Destination.Repo != "asset" || journal.ArchiveAdoption.Destination.Pool != "public" ||
		journal.ArchiveAdoption.Destination.View != "beta" || journal.ArchiveAdoption.Destination.Path != "asset/bundles/recovery.tgz" {
		t.Fatalf("archive adoption journal omitted exact source/destination contract: %+v", journal.ArchiveAdoption)
	}
	inspectedArchive, err := inspectOfflineArchiveInput(filepath.Join(root, "offline", "recovery.tgz"))
	if err != nil || inspectedArchive.Marker == nil || inspectedArchive.Object.HashString() != journal.ArchiveAdoption.ArchiveSHA256 ||
		inspectedArchive.Object.Size != journal.ArchiveAdoption.ArchiveSize {
		t.Fatalf("archive adoption journal differs from final archive marker=%+v object=%+v err=%v", inspectedArchive.Marker, inspectedArchive.Object, err)
	}
	receipt, receiptExists, err := readOfflineArchiveTaintReceipt(state.New(filepath.Join(root, ".sow")), journal.ArchiveAdoption.ArchiveSHA256)
	if err != nil || !receiptExists || receipt.Source.EntriesSHA256 != journal.ArchiveAdoption.Source.EntriesSHA256 || receipt.Confidentiality != "public" {
		t.Fatalf("archive adoption journal differs from canonical receipt exists=%t receipt=%+v err=%v", receiptExists, receipt, err)
	}
	projectionIntent, projectionExists, err := readAssetProjectionIntent(filepath.Join(root, ".sow"))
	if err != nil || !projectionExists || projectionIntent.Operation != "materialize" ||
		projectionIntent.OperationScope != offlineArchiveAdoptionMaterializationScope ||
		!offlineArchiveAdoptionContractEqual(projectionIntent.ArchiveAdoption, journal.ArchiveAdoption) {
		t.Fatalf("offline archive adoption did not share the durable asset projection bridge exists=%t intent=%+v err=%v", projectionExists, projectionIntent, err)
	}
	unit := journal.Units[0]
	if unit.Kind != "asset" || unit.Source != "beta" || unit.Repo != "asset" || unit.TargetSHA256 != wantedTarget {
		t.Fatalf("archive adoption durable unit=%+v want_target=%s", unit, wantedTarget)
	}

	// An attacker who can rewrite derived state must not downgrade a completed
	// archive-adoption transaction into an ordinary materialize by deleting both
	// mutually-consistent optional fields and recomputing the intent ID.
	downgraded := projectionIntent
	downgraded.OperationScope = ""
	downgraded.ArchiveAdoption = nil
	downgraded.Message = assetProjectionIntentMessage(downgraded.Operation, downgraded.OperationScope, downgraded.Repo, downgraded.TransactionID, nil)
	downgraded.ID, err = assetProjectionIntentID(downgraded)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAssetProjectionIntent(filepath.Join(root, ".sow"), downgraded); err != nil {
		t.Fatalf("write rehashed archive downgrade: %v", err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "asset", "--target", "downgrade-export",
		"--workers", "1", "--chunk-entries", "1", "--recover",
	)
	if code == ExitOK {
		t.Fatalf("rehashed archive projection downgrade recovered stdout=%s stderr=%s", stdout, stderr)
	}
	if current, exists, readErr := readAssetProjectionIntent(filepath.Join(root, ".sow")); readErr != nil || !exists || current.ID != downgraded.ID {
		t.Fatalf("rejected archive downgrade changed bridge current=%+v exists=%t err=%v", current, exists, readErr)
	}
	if err := writeAssetProjectionIntent(filepath.Join(root, ".sow"), projectionIntent); err != nil {
		t.Fatalf("restore exact archive projection intent: %v", err)
	}

	if err := os.Remove(conflict); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "asset", "--target", "post-adoption-export",
		"--workers", "1", "--chunk-entries", "1", "--recover",
	)
	if code != ExitOK || !strings.Contains(stdout, "recovered pending asset projection operation=materialize repo=asset view=beta") ||
		!strings.Contains(stdout, "recovered offline archive path=") || strings.Contains(stdout, "materialized ref=latest target=post-adoption-export") {
		t.Fatalf("scoped archive adoption recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Lstat(filepath.Join(root, "post-adoption-export")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("frozen archive recovery continued into current selector: %v", err)
	}
	if current, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("archive adoption recovery retained journal=%+v exists=%t err=%v", current, exists, err)
	}
	if current, exists, err := readAssetProjectionIntent(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("archive adoption recovery retained pending projection=%+v exists=%t err=%v", current, exists, err)
	}
	if current, exists, err := readOfflineArchiveProjectionIntent(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("archive adoption recovery retained outer owner=%+v exists=%t err=%v", current, exists, err)
	}
	entries := readAssetMaterializeView(t, root, "beta")
	archiveEntry := findAssetMaterializeEntry(t, entries, "asset/bundles/recovery.tgz")
	archiveDigest, err := repository.ParseDigest(archiveEntry.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	poolInfo, err := os.Stat(pool.ObjectPath(archiveDigest))
	if err != nil {
		t.Fatal(err)
	}
	treeInfo, err := os.Stat(filepath.Join(root, ".sow", "materialized", "beta", "asset", "bundles", "recovery.tgz"))
	if err != nil || !os.SameFile(poolInfo, treeInfo) {
		t.Fatalf("recovered archive adoption is not a CAS hardlink: %v", err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "asset", "--target", "post-adoption-export",
		"--workers", "1", "--chunk-entries", "1",
	)
	if code != ExitOK || !strings.Contains(stdout, "materialized ref=latest target=post-adoption-export") {
		t.Fatalf("current selection after archive recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if body, err := os.ReadFile(filepath.Join(root, "post-adoption-export", "asset", "payload.bin")); err != nil || string(body) != "archive recovery payload\n" {
		t.Fatalf("current selection did not continue after scoped recovery body=%q err=%v", body, err)
	}
}

func TestOfflineArchiveAdoptionSIGKILLRecoversFrozenArchiveBeforeAdvancedSelector(t *testing.T) {
	if os.Getenv("SOW_TEST_ARCHIVE_ADOPTION_OWNER_CHILD") == "1" {
		offlineArchiveAfterProjectionBeforeAdoptionHook = func(offlineArchiveProjectionIntent) error {
			ready, err := os.OpenFile(os.Getenv("SOW_TEST_ARCHIVE_ADOPTION_READY"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				os.Exit(96)
			}
			_, writeErr := ready.Write([]byte("ready\n"))
			closeErr := errors.Join(ready.Sync(), ready.Close())
			if writeErr != nil || closeErr != nil {
				os.Exit(97)
			}
			select {}
		}
		var stdout, stderr bytes.Buffer
		code := Main([]string{
			"materialize", "latest", "--config", os.Getenv("SOW_TEST_ARCHIVE_ADOPTION_CONFIG"), "--repo", "asset",
			"--target", "archive-owner-source", "--tgz", os.Getenv("SOW_TEST_ARCHIVE_ADOPTION_DESTINATION"),
			"--asset-repo", "asset", "--asset-dest", "bundles/sigkill.tgz", "--workers", "1", "--chunk-entries", "1",
		}, &stdout, &stderr)
		os.Exit(code)
	}

	root, configPath := newAssetMaterializeHardeningFixture(t)
	addAssetMaterializeFixture(t, configPath, "payload.bin", "frozen archive payload\n", false)
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t, "promote", "beta", "latest", "--config", configPath, "--repo", "asset")
	if code != ExitOK {
		t.Fatalf("seed frozen latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	destination := filepath.Join(root, "offline", "sigkill.tgz")
	ready := filepath.Join(t.TempDir(), "ready")
	command := exec.Command(os.Args[0], "-test.run=^TestOfflineArchiveAdoptionSIGKILLRecoversFrozenArchiveBeforeAdvancedSelector$")
	command.Env = append(os.Environ(),
		"SOW_TEST_ARCHIVE_ADOPTION_OWNER_CHILD=1",
		"SOW_TEST_ARCHIVE_ADOPTION_READY="+ready,
		"SOW_TEST_ARCHIVE_ADOPTION_CONFIG="+configPath,
		"SOW_TEST_ARCHIVE_ADOPTION_DESTINATION="+destination,
	)
	var childOutput bytes.Buffer
	command.Stdout, command.Stderr = &childOutput, &childOutput
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waiting := true
	t.Cleanup(func() {
		if waiting {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	becameReady := false
	for attempt := 0; attempt < 200; attempt++ {
		if _, err := os.Stat(ready); err == nil {
			becameReady = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !becameReady {
		t.Fatalf("archive adoption child did not reach durable handoff: %s", childOutput.String())
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("SIGKILL archive adoption child exited successfully")
	}
	waiting = false

	stateRoot := filepath.Join(root, ".sow")
	intent, exists, err := readOfflineArchiveProjectionIntent(stateRoot)
	if err != nil || !exists || intent.ArchiveAdoption == nil {
		t.Fatalf("SIGKILL lost outer archive owner exists=%t intent=%+v err=%v output=%s", exists, intent, err, childOutput.String())
	}
	if _, exists, err := readAssetProjectionIntent(stateRoot); err != nil || exists {
		t.Fatalf("SIGKILL crossed into asset bridge exists=%t err=%v", exists, err)
	}
	if _, exists, err := readMaterializationSelectionJournal(stateRoot); err != nil || exists {
		t.Fatalf("SIGKILL crossed into selected-set bridge exists=%t err=%v", exists, err)
	}
	frozen, err := inspectOfflineArchiveInput(destination)
	if err != nil || frozen.Object.HashString() != intent.ArchiveSHA256 {
		t.Fatalf("durable frozen archive object=%+v want=%s err=%v", frozen.Object, intent.ArchiveSHA256, err)
	}

	// Temporarily hide only the two exact owner files in this disposable fixture
	// so an old writer can advance the mutable latest ref. Restore the private
	// stage first and the intent last, preserving the production ordering.
	hidden := t.TempDir()
	intentPath := filepath.Join(stateRoot, offlineArchiveProjectionIntentRelative)
	stagePath := filepath.Join(stateRoot, intent.StageRelative)
	hiddenIntent := filepath.Join(hidden, "intent.json")
	hiddenStage := filepath.Join(hidden, "stage.tgz")
	if err := os.Rename(intentPath, hiddenIntent); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(stagePath, hiddenStage); err != nil {
		t.Fatal(err)
	}
	advancedInput := filepath.Join(t.TempDir(), "advanced.bin")
	if err := os.WriteFile(advancedInput, []byte("advanced mutable ref payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"add", advancedInput, "--config", configPath, "--repo", "asset", "--dest", "advanced.bin",
		"--workers", "1", "--chunk-entries", "1", "--recover",
	)
	if code != ExitOK {
		t.Fatalf("add advanced asset after old-writer crash code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, "promote", "beta", "latest", "--config", configPath, "--repo", "asset")
	if code != ExitOK {
		t.Fatalf("advance latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if err := os.Rename(hiddenStage, stagePath); err != nil {
		t.Fatal(err)
	}
	if err := syncLocalDirectory(filepath.Dir(stagePath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(hiddenIntent, intentPath); err != nil {
		t.Fatal(err)
	}
	if err := syncLocalDirectory(stateRoot); err != nil {
		t.Fatal(err)
	}

	recoveryTarget := filepath.Join(root, "advanced-selector-must-wait")
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "asset", "--target", recoveryTarget,
		"--workers", "1", "--chunk-entries", "1", "--recover",
	)
	if code != ExitOK || !strings.Contains(stdout, "recovered offline archive path=") || strings.Contains(stdout, "materialized ref=latest") {
		t.Fatalf("frozen owner recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Lstat(recoveryTarget); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery executed advanced current selector: %v", err)
	}
	archiveEntry := findAssetMaterializeEntry(t, readAssetMaterializeView(t, root, "beta"), "asset/bundles/sigkill.tgz")
	if archiveEntry.SHA256 != intent.ArchiveSHA256 {
		t.Fatalf("recovered adoption digest=%s want frozen=%s", archiveEntry.SHA256, intent.ArchiveSHA256)
	}
	if _, exists, err := readOfflineArchiveProjectionIntent(stateRoot); err != nil || exists {
		t.Fatalf("recovery retained archive owner exists=%t err=%v", exists, err)
	}
	if _, exists, err := readAssetProjectionIntent(stateRoot); err != nil || exists {
		t.Fatalf("recovery retained asset bridge exists=%t err=%v", exists, err)
	}
	if _, exists, err := readMaterializationSelectionJournal(stateRoot); err != nil || exists {
		t.Fatalf("recovery retained selected-set bridge exists=%t err=%v", exists, err)
	}

	advancedArchive := filepath.Join(root, "offline", "advanced.tgz")
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "asset", "--target", "advanced-selector-after-recovery",
		"--tgz", advancedArchive, "--workers", "1", "--chunk-entries", "1",
	)
	if code != ExitOK {
		t.Fatalf("advanced selector after recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	advanced, err := inspectOfflineArchiveInput(advancedArchive)
	if err != nil || advanced.Object.HashString() == intent.ArchiveSHA256 {
		t.Fatalf("advanced archive digest=%s frozen=%s err=%v", advanced.Object.HashString(), intent.ArchiveSHA256, err)
	}
	if body, err := os.ReadFile(filepath.Join(root, "advanced-selector-after-recovery", "asset", "advanced.bin")); err != nil || string(body) != "advanced mutable ref payload\n" {
		t.Fatalf("advanced selector payload=%q err=%v", body, err)
	}
}

func TestOfflineArchiveAdoptionRecoveryRejectsRehashedJournalContractTamper(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	addAssetMaterializeFixture(t, configPath, "payload.bin", "archive tamper payload\n", false)
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t, "promote", "beta", "latest", "--config", configPath, "--repo", "asset")
	if code != ExitOK {
		t.Fatalf("seed archive tamper latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	conflict := filepath.Join(root, ".sow", "materialized", "beta", "asset", "bundles", "tamper.tgz")
	if err := os.MkdirAll(filepath.Dir(conflict), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conflict, []byte("unmanaged archive conflict\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "asset", "--target", "tamper-source-export",
		"--tgz", "offline/tamper.tgz", "--asset-repo", "asset", "--asset-dest", "bundles/tamper.tgz",
		"--workers", "1", "--chunk-entries", "1",
	)
	if code != ExitVerification {
		t.Fatalf("leave archive tamper journal code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	original, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow"))
	if err != nil || !exists || original.ArchiveAdoption == nil {
		t.Fatalf("read archive tamper journal exists=%t journal=%+v err=%v", exists, original, err)
	}
	cfg, _, err := loadAndSelect(commonFlags{configPath: configPath, workers: 1, chunk: 1})
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	tests := []struct {
		name   string
		mutate func(*offlineArchiveAdoptionContract)
	}{
		{name: "source-id", mutate: func(contract *offlineArchiveAdoptionContract) { contract.Source.ID = "stable" }},
		{name: "source-ref-commit", mutate: func(contract *offlineArchiveAdoptionContract) {
			contract.Source.Refs[0].Commit = strings.Repeat("a", 40)
		}},
		{name: "source-entry-digest", mutate: func(contract *offlineArchiveAdoptionContract) {
			contract.Source.EntriesSHA256 = strings.Repeat("b", 64)
		}},
		{name: "destination-path", mutate: func(contract *offlineArchiveAdoptionContract) { contract.Destination.Path = "asset/bundles/other.tgz" }},
		{name: "destination-policy", mutate: func(contract *offlineArchiveAdoptionContract) {
			contract.Destination.Pool = "gated"
			contract.Destination.View = "stable"
		}},
		{name: "archive-digest", mutate: func(contract *offlineArchiveAdoptionContract) { contract.ArchiveSHA256 = strings.Repeat("c", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := original
			candidate.ArchiveAdoption = cloneOfflineArchiveAdoptionContract(original.ArchiveAdoption)
			test.mutate(candidate.ArchiveAdoption)
			candidate.ArchiveAdoption.ID, err = offlineArchiveAdoptionContractID(*candidate.ArchiveAdoption)
			if err != nil {
				t.Fatal(err)
			}
			candidate.ID, err = materializationSelectionJournalID(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeMaterializationSelectionJournal(filepath.Join(root, ".sow"), candidate); err != nil {
				t.Fatalf("write syntactically rehashed tamper: %v", err)
			}
			defer func() { _ = writeMaterializationSelectionJournal(filepath.Join(root, ".sow"), original) }()
			handled, recoverErr := recoverOfflineArchiveAdoptionMaterialization(t.Context(), cfg, canonical, commonFlags{recover: true, workers: 1, chunk: 1}, io.Discard)
			if !handled || recoverErr == nil {
				t.Fatalf("rehashed archive contract tamper recovered handled=%t err=%v contract=%+v", handled, recoverErr, candidate.ArchiveAdoption)
			}
		})
	}
}

func TestAssetProjectionIntentRecoversEveryCanonicalToJournalProcessStop(t *testing.T) {
	if os.Getenv("SOW_TEST_ASSET_PROJECTION_CRASH") == "1" {
		wanted := os.Getenv("SOW_TEST_ASSET_PROJECTION_PHASE")
		assetProjectionMutationHook = func(phase string) error {
			if phase == wanted {
				os.Exit(92)
			}
			return nil
		}
		var stdout, stderr bytes.Buffer
		code := Main([]string{
			"add", os.Getenv("SOW_TEST_ASSET_PROJECTION_INPUT"),
			"--config", os.Getenv("SOW_TEST_ASSET_PROJECTION_CONFIG"), "--repo", "asset", "--dest", "crash.bin",
			"--workers", "1", "--chunk-entries", "1",
		}, &stdout, &stderr)
		os.Exit(code)
	}

	phases := []string{
		"after-fence-before-apply",
		"after-transaction-intent-before-commit",
		"after-canonical-commit-before-ref",
		"after-ref-before-materialize",
	}
	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			root, configPath := newAssetMaterializeHardeningFixture(t)
			input := filepath.Join(t.TempDir(), "crash.bin")
			body := []byte("asset projection durable bridge " + phase + "\n")
			if err := os.WriteFile(input, body, 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestAssetProjectionIntentRecoversEveryCanonicalToJournalProcessStop$")
			command.Env = append(os.Environ(),
				"SOW_TEST_ASSET_PROJECTION_CRASH=1",
				"SOW_TEST_ASSET_PROJECTION_PHASE="+phase,
				"SOW_TEST_ASSET_PROJECTION_CONFIG="+configPath,
				"SOW_TEST_ASSET_PROJECTION_INPUT="+input,
			)
			output, err := command.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 92 {
				t.Fatalf("asset projection crash helper phase=%s err=%v output=%s", phase, err, output)
			}
			intent, exists, err := readAssetProjectionIntent(filepath.Join(root, ".sow"))
			if err != nil || !exists || intent.Operation != "add" || intent.Repo != "asset" || intent.View != "beta" {
				t.Fatalf("durable bridge missing after phase=%s exists=%t intent=%+v err=%v", phase, exists, intent, err)
			}
			if _, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
				t.Fatalf("phase=%s unexpectedly reached post-ref selected-set journal exists=%t err=%v", phase, exists, err)
			}
			if err := os.Remove(input); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
				"add", "--config", configPath, "--repo", "asset", "--recover", "--workers", "1", "--chunk-entries", "1",
			)
			if code != ExitOK || !strings.Contains(stdout, "recovered pending asset projection operation=add repo=asset view=beta") {
				t.Fatalf("asset projection recovery phase=%s code=%d stdout=%s stderr=%s", phase, code, stdout, stderr)
			}
			if _, exists, err := readAssetProjectionIntent(filepath.Join(root, ".sow")); err != nil || exists {
				t.Fatalf("asset projection recovery retained bridge phase=%s exists=%t err=%v", phase, exists, err)
			}
			if _, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
				t.Fatalf("asset projection recovery retained selected set phase=%s exists=%t err=%v", phase, exists, err)
			}
			entries := readAssetMaterializeView(t, root, "beta")
			entry := findAssetMaterializeEntry(t, entries, "asset/crash.bin")
			digest, err := repository.ParseDigest(entry.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			pool, err := repository.NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			poolInfo, err := os.Stat(pool.ObjectPath(digest))
			if err != nil {
				t.Fatal(err)
			}
			treeInfo, err := os.Stat(filepath.Join(root, ".sow", "materialized", "beta", "asset", "crash.bin"))
			if err != nil || !os.SameFile(poolInfo, treeInfo) {
				t.Fatalf("recovered phase=%s tree is not exact CAS hardlink: %v", phase, err)
			}
			if recovered, err := os.ReadFile(filepath.Join(root, ".sow", "materialized", "beta", "asset", "crash.bin")); err != nil || !bytes.Equal(recovered, body) {
				t.Fatalf("recovered phase=%s bytes=%q err=%v", phase, recovered, err)
			}
		})
	}
}

func TestAssetProjectionReturnedAfterIntentErrorRemainsInputlessRecoverable(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	input := filepath.Join(t.TempDir(), "returned-error.bin")
	if err := os.WriteFile(input, []byte("durable asset returned error\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := assetProjectionMutationHook
	assetProjectionMutationHook = func(phase string) error {
		if phase == "after-transaction-intent-before-commit" {
			return errors.New("injected asset returned after-intent failure")
		}
		return nil
	}
	t.Cleanup(func() { assetProjectionMutationHook = previous })
	var stdout, stderr bytes.Buffer
	err := runAdd(t.Context(), []string{input, "--config", configPath, "--repo", "asset", "--dest", "returned-error.bin", "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "injected asset returned after-intent failure") {
		t.Fatalf("asset returned after-intent failure err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	intent, exists, err := readAssetProjectionIntent(filepath.Join(root, ".sow"))
	if err != nil || !exists {
		t.Fatalf("asset returned failure bridge exists=%t err=%v", exists, err)
	}
	record, exists, err := state.New(filepath.Join(root, ".sow")).Transaction(intent.TransactionID)
	if err != nil || !exists || record.Phase != "intent" || !record.Commit.IsZero() {
		t.Fatalf("asset returned failure transaction exists=%t record=%+v err=%v", exists, record, err)
	}
	for _, relative := range []string{intent.ConfigStage, intent.StageRelative} {
		if _, err := os.Stat(filepath.Join(root, ".sow", relative)); err != nil {
			t.Fatalf("asset returned failure lost durable stage %s: %v", relative, err)
		}
	}
	assetProjectionMutationHook = nil
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	code, stdoutText, stderrText := runAssetMaterializeHardeningCLI(t, "add", "--config", configPath, "--repo", "asset", "--recover", "--workers", "1", "--chunk-entries", "1")
	if code != ExitOK || !strings.Contains(stdoutText, "recovered pending asset projection operation=add repo=asset view=beta") {
		t.Fatalf("asset returned failure inputless recovery code=%d stdout=%s stderr=%s", code, stdoutText, stderrText)
	}
}

func TestAssetProjectionStageTamperFailsBeforeGenericRecovery(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	input := filepath.Join(t.TempDir(), "stage-tamper.bin")
	if err := os.WriteFile(input, []byte("asset stage tamper witness\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestAssetProjectionIntentRecoversEveryCanonicalToJournalProcessStop$")
	command.Env = append(os.Environ(),
		"SOW_TEST_ASSET_PROJECTION_CRASH=1",
		"SOW_TEST_ASSET_PROJECTION_PHASE=after-canonical-commit-before-ref",
		"SOW_TEST_ASSET_PROJECTION_CONFIG="+configPath,
		"SOW_TEST_ASSET_PROJECTION_INPUT="+input,
	)
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 92 {
		t.Fatalf("asset stage preflight crash err=%v output=%s", err, output)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	intent, exists, err := readAssetProjectionIntent(filepath.Join(root, ".sow"))
	if err != nil || !exists {
		t.Fatalf("read asset stage preflight bridge exists=%t err=%v", exists, err)
	}
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	ref := plumbing.ReferenceName(intent.ViewRef)
	if _, exists, err := canonical.Ref(ref); err != nil || exists {
		t.Fatalf("asset stage preflight ref already advanced exists=%t err=%v", exists, err)
	}
	recordBefore, exists, err := canonical.Transaction(intent.TransactionID)
	if err != nil || !exists || recordBefore.Phase != "committed" {
		t.Fatalf("asset stage preflight transaction exists=%t record=%+v err=%v", exists, recordBefore, err)
	}
	stage := filepath.Join(root, ".sow", intent.StageRelative)
	original, err := os.ReadFile(stage)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, []byte("tampered asset projection stage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdoutText, stderrText := runAssetMaterializeHardeningCLI(t, "add", "--config", configPath, "--repo", "asset", "--recover", "--workers", "1", "--chunk-entries", "1")
	if code == ExitOK {
		t.Fatalf("tampered asset projection stage recovered stdout=%s stderr=%s", stdoutText, stderrText)
	}
	headAfter, err := canonical.HeadHash()
	if err != nil || headAfter != headBefore {
		t.Fatalf("asset stage preflight moved HEAD before=%s after=%s err=%v", headBefore, headAfter, err)
	}
	if _, exists, err := canonical.Ref(ref); err != nil || exists {
		t.Fatalf("asset stage preflight advanced ref exists=%t err=%v", exists, err)
	}
	recordAfter, exists, err := canonical.Transaction(intent.TransactionID)
	if err != nil || !exists || recordAfter.Phase != "committed" || recordAfter.Commit != recordBefore.Commit {
		t.Fatalf("asset stage preflight changed transaction exists=%t before=%+v after=%+v err=%v", exists, recordBefore, recordAfter, err)
	}
	if err := os.WriteFile(stage, original, 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdoutText, stderrText = runAssetMaterializeHardeningCLI(t, "add", "--config", configPath, "--repo", "asset", "--recover", "--workers", "1", "--chunk-entries", "1")
	if code != ExitOK {
		t.Fatalf("restored asset stage recovery code=%d stdout=%s stderr=%s", code, stdoutText, stderrText)
	}
}

func TestAssetProjectionIntentRejectsRehashedSemanticTamper(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	input := filepath.Join(t.TempDir(), "tamper.bin")
	if err := os.WriteFile(input, []byte("pending projection tamper bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := assetProjectionMutationHook
	assetProjectionMutationHook = func(phase string) error {
		if phase == "after-ref-before-materialize" {
			return errors.New("leave pending projection after completed transaction")
		}
		return nil
	}
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
		"add", input, "--config", configPath, "--repo", "asset", "--dest", "tamper.bin", "--workers", "1", "--chunk-entries", "1",
	)
	assetProjectionMutationHook = previous
	t.Cleanup(func() { assetProjectionMutationHook = previous })
	if code != ExitConflict || !strings.Contains(stderr, "leave pending projection after completed transaction") {
		t.Fatalf("leave pending projection code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	base, exists, err := readAssetProjectionIntent(filepath.Join(root, ".sow"))
	if err != nil || !exists {
		t.Fatalf("read pending projection base exists=%t err=%v", exists, err)
	}
	tests := []struct {
		name   string
		mutate func(*assetProjectionIntent)
	}{
		{name: "expected-head", mutate: func(intent *assetProjectionIntent) { intent.ExpectedHead = strings.Repeat("a", 40) }},
		{name: "expected-ref", mutate: func(intent *assetProjectionIntent) { intent.ExpectedRef = strings.Repeat("b", 40) }},
		{name: "manifest", mutate: func(intent *assetProjectionIntent) { intent.ManifestSHA256 = strings.Repeat("c", 64) }},
		{name: "repo", mutate: func(intent *assetProjectionIntent) { intent.Repo = "another-asset" }},
		{name: "view", mutate: func(intent *assetProjectionIntent) { intent.View = "stable" }},
		{name: "transaction", mutate: func(intent *assetProjectionIntent) {
			intent.TransactionID = strings.Repeat("d", 32)
			intent.StageRelative = assetProjectionStagePrefix + intent.TransactionID + ".tsv"
			intent.ConfigStage = assetProjectionStagePrefix + intent.TransactionID + "-config.yaml"
			intent.Message = assetProjectionIntentMessage(intent.Operation, intent.OperationScope, intent.Repo, intent.TransactionID, intent.ArchiveAdoption)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.ArchiveAdoption = cloneOfflineArchiveAdoptionContract(base.ArchiveAdoption)
			test.mutate(&candidate)
			candidate.Message = assetProjectionIntentMessage(candidate.Operation, candidate.OperationScope, candidate.Repo, candidate.TransactionID, candidate.ArchiveAdoption)
			candidate.ID, err = assetProjectionIntentID(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeAssetProjectionIntent(filepath.Join(root, ".sow"), candidate); err != nil {
				t.Fatalf("write rehashed pending projection tamper: %v", err)
			}
			defer func() { _ = writeAssetProjectionIntent(filepath.Join(root, ".sow"), base) }()
			code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
				"add", "--config", configPath, "--repo", "asset", "--recover", "--workers", "1", "--chunk-entries", "1",
			)
			if code == ExitOK {
				t.Fatalf("rehashed pending projection tamper recovered stdout=%s stderr=%s", stdout, stderr)
			}
			current, exists, err := readAssetProjectionIntent(filepath.Join(root, ".sow"))
			if err != nil || !exists || current.ID != candidate.ID {
				t.Fatalf("rejected pending projection tamper changed intent current=%+v exists=%t err=%v", current, exists, err)
			}
		})
	}
}

func TestAssetProjectionPreflightRejectsRehashedOldStateBeforeGenericRecovery(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*assetProjectionIntent)
	}{
		{name: "expected-head", mutate: func(intent *assetProjectionIntent) { intent.ExpectedHead = strings.Repeat("a", 40) }},
		{name: "expected-ref", mutate: func(intent *assetProjectionIntent) { intent.ExpectedRef = strings.Repeat("b", 40) }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			root, configPath := newAssetMaterializeHardeningFixture(t)
			input := filepath.Join(t.TempDir(), "preflight.bin")
			if err := os.WriteFile(input, []byte("asset old-state preflight\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestAssetProjectionIntentRecoversEveryCanonicalToJournalProcessStop$")
			command.Env = append(os.Environ(),
				"SOW_TEST_ASSET_PROJECTION_CRASH=1",
				"SOW_TEST_ASSET_PROJECTION_PHASE=after-canonical-commit-before-ref",
				"SOW_TEST_ASSET_PROJECTION_CONFIG="+configPath,
				"SOW_TEST_ASSET_PROJECTION_INPUT="+input,
			)
			output, err := command.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 92 {
				t.Fatalf("asset preflight crash helper err=%v output=%s", err, output)
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			base, exists, err := readAssetProjectionIntent(filepath.Join(root, ".sow"))
			if err != nil || !exists {
				t.Fatalf("read asset preflight bridge exists=%t err=%v", exists, err)
			}
			record, exists, err := canonical.Transaction(base.TransactionID)
			if err != nil || !exists || record.Phase != "committed" {
				t.Fatalf("asset preflight transaction exists=%t record=%+v err=%v", exists, record, err)
			}
			headBefore, err := canonical.HeadHash()
			if err != nil {
				t.Fatal(err)
			}
			ref := plumbing.ReferenceName(base.ViewRef)
			if _, exists, err := canonical.Ref(ref); err != nil || exists {
				t.Fatalf("asset preflight ref unexpectedly advanced exists=%t err=%v", exists, err)
			}
			worktreePath := filepath.Join(root, ".sow", "state", filepath.FromSlash(base.ViewPath))
			worktreeWitness := capturePackageNoopWitnesses(t, worktreePath)
			candidate := base
			test.mutate(&candidate)
			candidate.ID, err = assetProjectionIntentID(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeAssetProjectionIntent(filepath.Join(root, ".sow"), candidate); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
				"add", "--config", configPath, "--repo", "asset", "--recover", "--workers", "1", "--chunk-entries", "1",
			)
			if code == ExitOK {
				t.Fatalf("rehashed asset old-state tamper recovered stdout=%s stderr=%s", stdout, stderr)
			}
			headAfter, err := canonical.HeadHash()
			if err != nil || headAfter != headBefore {
				t.Fatalf("rejected asset preflight moved HEAD before=%s after=%s err=%v", headBefore, headAfter, err)
			}
			if _, exists, err := canonical.Ref(ref); err != nil || exists {
				t.Fatalf("rejected asset preflight advanced ref exists=%t err=%v", exists, err)
			}
			assertPackageNoopWitnessesUnchanged(t, worktreeWitness)
			recordAfter, exists, err := canonical.Transaction(base.TransactionID)
			if err != nil || !exists || recordAfter.Phase != "committed" {
				t.Fatalf("rejected asset preflight mutated transaction exists=%t record=%+v err=%v", exists, recordAfter, err)
			}
			if err := writeAssetProjectionIntent(filepath.Join(root, ".sow"), base); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
				"add", "--config", configPath, "--repo", "asset", "--recover", "--workers", "1", "--chunk-entries", "1",
			)
			if code != ExitOK {
				t.Fatalf("exact asset preflight recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
		})
	}
}

func TestDirectAssetMaterializeRelinksOnlyConfiguredMutablePaths(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	mutableInput := addAssetMaterializeFixture(t, configPath, "mutable/tool.bin", "mutable-v1\n", false)
	immutableInput := addAssetMaterializeFixture(t, configPath, "release.bin", "immutable-v1\n", false)
	arguments := []string{
		"materialize", "beta", "--config", configPath, "--repo", "asset",
		"--target", "mutable-export", "--workers", "1", "--chunk-entries", "1",
	}
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t, arguments...)
	if code != ExitOK {
		t.Fatalf("initial direct asset materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	mutableTarget := filepath.Join(root, "mutable-export", "asset", "mutable", "tool.bin")
	immutableTarget := filepath.Join(root, "mutable-export", "asset", "release.bin")
	oldMutable, err := os.Stat(mutableTarget)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(mutableInput, []byte("mutable-v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"add", mutableInput, "--config", configPath, "--repo", "asset", "--dest", "mutable/tool.bin", "--replace",
	)
	if code != ExitOK || !strings.Contains(stdout, "replaced=1") {
		t.Fatalf("configured mutable replacement code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, arguments...)
	if code != ExitOK || !strings.Contains(stdout, "relinked=1") {
		t.Fatalf("direct mutable convergence code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	entries := readAssetMaterializeView(t, root, "beta")
	mutableEntry := findAssetMaterializeEntry(t, entries, "asset/mutable/tool.bin")
	mutableDigest, err := repository.ParseDigest(mutableEntry.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	assertAssetMaterializeHardlink(t, pool.ObjectPath(mutableDigest), mutableTarget, "mutable-v2\n")
	newMutable, err := os.Stat(mutableTarget)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(oldMutable, newMutable) {
		t.Fatal("mutable explicit target retained the old CAS inode")
	}

	if err := os.WriteFile(immutableInput, []byte("immutable-v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"add", immutableInput, "--config", configPath, "--repo", "asset", "--dest", "release.bin", "--replace",
	)
	if code != ExitConflict || !strings.Contains(stderr, "asset.mutable_paths") {
		t.Fatalf("immutable canonical replacement code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if err := os.Remove(immutableTarget); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(immutableTarget, []byte("tampered explicit target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, arguments...)
	if code != ExitConflict || !strings.Contains(stderr, "materialization path conflict") {
		t.Fatalf("immutable target drift was accepted code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if err := os.Remove(immutableTarget); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, append(append([]string(nil), arguments...), "--recover")...)
	if code != ExitOK {
		t.Fatalf("immutable conflict recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	immutableEntry := findAssetMaterializeEntry(t, entries, "asset/release.bin")
	immutableDigest, err := repository.ParseDigest(immutableEntry.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	assertAssetMaterializeHardlink(t, pool.ObjectPath(immutableDigest), immutableTarget, "immutable-v1\n")
}

func TestLatestAndDirectOfflineAssetReplayIsByteIdenticalAndNeverSelfEmbeds(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	addAssetMaterializeFixture(t, configPath, "payload.bin", "offline payload\n", false)
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
		"promote", "beta", "latest", "--config", configPath, "--repo", "asset",
	)
	if code != ExitOK {
		t.Fatalf("seed latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	archivePath := filepath.Join(root, "offline", "bundle.tgz")
	latestArguments := []string{
		"materialize", "latest", "--config", configPath, "--repo", "asset",
		"--tgz", "offline/bundle.tgz", "--asset-repo", "asset", "--asset-dest", "bundles/bundle.tgz",
		"--workers", "1", "--chunk-entries", "1",
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, latestArguments...)
	if code != ExitOK || !strings.Contains(stdout, "archive adopted repo=asset") {
		t.Fatalf("latest offline loop code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	first := readAssetMaterializeArchive(t, archivePath)
	assertAssetMaterializeArchiveNames(t, first, "asset/payload.bin", "asset/bundles/bundle.tgz")

	// Put the first archive back into latest. The next archive input therefore
	// really contains its previous output and must exclude that exact asset path.
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"promote", "beta", "latest", "--config", configPath, "--repo", "asset",
	)
	if code != ExitOK {
		t.Fatalf("promote adopted archive into latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, latestArguments...)
	if code != ExitOK || !strings.Contains(stdout, "add unchanged repo=asset") {
		t.Fatalf("latest self-containing replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	second := readAssetMaterializeArchive(t, archivePath)
	if !bytes.Equal(first, second) {
		t.Fatal("latest offline archive changed after its prior output entered the source ref")
	}
	assertAssetMaterializeArchiveNames(t, second, "asset/payload.bin", "asset/bundles/bundle.tgz")

	directArguments := append(append([]string(nil), latestArguments...), "--target", "direct-export")
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, directArguments...)
	if code != ExitOK || !strings.Contains(stdout, "add unchanged repo=asset") {
		t.Fatalf("direct offline loop code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	third := readAssetMaterializeArchive(t, archivePath)
	if !bytes.Equal(first, third) {
		t.Fatal("direct and latest branches emitted different archives from the same exact source")
	}
	assertAssetMaterializeArchiveNames(t, third, "asset/payload.bin", "asset/bundles/bundle.tgz")

	code, stdout, stderr = runAssetMaterializeHardeningCLI(t, directArguments...)
	if code != ExitOK || !strings.Contains(stdout, "add unchanged repo=asset") {
		t.Fatalf("direct byte-identical replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	fourth := readAssetMaterializeArchive(t, archivePath)
	if !bytes.Equal(third, fourth) {
		t.Fatal("direct offline archive replay was not byte-identical")
	}
}

func newAssetMaterializeHardeningFixture(t *testing.T) (string, string) {
	t.Helper()
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(assetMaterializeHardeningConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	return root, configPath
}

func addAssetMaterializeFixture(t *testing.T, configPath, destination, body string, replace bool) string {
	t.Helper()
	input := filepath.Join(t.TempDir(), filepath.Base(destination))
	if err := os.WriteFile(input, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{"add", input, "--config", configPath, "--repo", "asset", "--dest", destination, "--workers", "1", "--chunk-entries", "1"}
	if replace {
		arguments = append(arguments, "--replace")
	}
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t, arguments...)
	if code != ExitOK {
		t.Fatalf("add asset %s code=%d stdout=%s stderr=%s", destination, code, stdout, stderr)
	}
	return input
}

func runAssetMaterializeHardeningCLI(t *testing.T, arguments ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Main(arguments, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func readAssetMaterializeView(t *testing.T, root, view string) []views.Entry {
	t.Helper()
	canonical := state.New(filepath.Join(root, ".sow"))
	ref, err := state.ViewRef(view, "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	commit, exists, err := canonical.Ref(ref)
	if err != nil || !exists {
		t.Fatalf("read %s ref exists=%t err=%v", view, exists, err)
	}
	viewPath, err := state.ViewPath(view, "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	file, err := canonical.OpenPathAt(commit, viewPath)
	if err != nil {
		t.Fatal(err)
	}
	var entries []views.Entry
	reader := views.NewReader(file)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return entries
}

func findAssetMaterializeEntry(t *testing.T, entries []views.Entry, wanted string) views.Entry {
	t.Helper()
	for _, entry := range entries {
		if entry.Path == wanted {
			return entry
		}
	}
	t.Fatalf("asset entry %s not found in %+v", wanted, entries)
	return views.Entry{}
}

func assertAssetMaterializeHardlink(t *testing.T, objectPath, targetPath, contents string) {
	t.Helper()
	object, err := os.Stat(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Stat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(object, target) {
		t.Fatalf("%s is not a CAS hardlink to %s", targetPath, objectPath)
	}
	body, err := os.ReadFile(targetPath)
	if err != nil || string(body) != contents {
		t.Fatalf("hardlink contents=%q want=%q err=%v", body, contents, err)
	}
}

func replaceWithOrdinaryAssetDrift(t *testing.T, targetPath, contents string) {
	t.Helper()
	if err := os.Remove(targetPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertAssetOrdinaryDrift(t *testing.T, objectPath, targetPath, contents string) {
	t.Helper()
	object, err := os.Stat(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Stat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(object, target) {
		t.Fatalf("%s unexpectedly points at CAS object %s", targetPath, objectPath)
	}
	body, err := os.ReadFile(targetPath)
	if err != nil || string(body) != contents {
		t.Fatalf("ordinary drift contents=%q want=%q err=%v", body, contents, err)
	}
}

func assertAssetSelectedSetFailure(t *testing.T, root, operation string) {
	t.Helper()
	journal, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow"))
	if err != nil || !exists {
		t.Fatalf("read %s selected-set journal exists=%t err=%v", operation, exists, err)
	}
	if journal.Operation != operation || journal.Phase != materializationSelectionMaterializing ||
		len(journal.Units) != 1 || len(journal.CompletedUnits) != 0 {
		t.Fatalf("%s did not retain failed selected set: %+v", operation, journal)
	}
	unit := journal.Units[0]
	if unit.Kind != "asset" || unit.Source != "beta" || unit.Repo != "asset" || unit.OS != "all" || unit.Arch != "all" {
		t.Fatalf("%s retained unexpected selected-set unit: %+v", operation, unit)
	}
}

func assertAssetSelectedSetCleared(t *testing.T, root string) {
	t.Helper()
	journal, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow"))
	if err != nil || exists {
		t.Fatalf("selected-set journal remained after recovery journal=%+v exists=%t err=%v", journal, exists, err)
	}
}

func readAssetMaterializeArchive(t *testing.T, filename string) []byte {
	t.Helper()
	body, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func assertAssetMaterializeArchiveNames(t *testing.T, body []byte, included, excluded string) {
	t.Helper()
	compressed, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(compressed)
	foundIncluded := false
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			compressed.Close()
			t.Fatal(err)
		}
		if header.Name == included {
			foundIncluded = true
		}
		if header.Name == excluded {
			compressed.Close()
			t.Fatalf("offline archive embedded itself at %s", excluded)
		}
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if !foundIncluded {
		t.Fatalf("offline archive omitted expected payload %s", included)
	}
}

const assetMaterializeHardeningConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: asset
    type: asset
    path: asset
    default_pool: public
    asset: {kind: test, mutable_paths: [mutable/*.bin]}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`

const assetMaterializePublishConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: asset
    type: asset
    path: asset
    default_pool: public
    asset:
      kind: test
      mutable_paths: [mutable/*.bin]
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: "https://repo.test"}
  beta: {base_url: "https://beta.test"}
  stable: {base_url: "https://repo.test/pro/v1/basic"}
targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.test", bucket: repo-bucket, credential: env://SOW_TEST_R2}
    cdn: {kind: cloudflare, base_url: "https://repo.test", beta_base_url: "https://beta.test", zone_id: zone-test, credential: env://SOW_TEST_CF}
edge:
  token_verifier: provider://test
`
