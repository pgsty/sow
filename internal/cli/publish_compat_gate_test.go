package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

func TestPendingCompatibilityCutoverBlocksOrdinaryMaterializeAndPublishBeforeProvider(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAffinityBuildConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"affinity/cf", "affinity/cos", "affinity/shared"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(relative)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	journal := yumCompatibilityCutoverJournal{
		Schema: yumCompatibilityCutoverJournalSchema, ID: "infra-legacy-x86-64", Action: "cutover", Phase: yumCompatibilityCutoverCommitted,
		EventSHA256: strings.Repeat("a", 64), ServingLink: filepath.Join(root, ".sow", "serving", "compatibility", "yum", "infra-legacy-x86-64", "current"),
		FromTarget: filepath.Join(root, "yum", "infra", "x86_64"),
		ToTarget:   filepath.Join(root, ".sow", "materialized", "compatibility", "infra-legacy-x86-64", strings.Repeat("b", 64)),
	}
	body, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	journalPath := filepath.Join(root, ".sow", "yum-compatibility-cutover-"+journal.ID+".journal.json")
	if err := os.WriteFile(journalPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	stateBefore := filepath.Join(t.TempDir(), "state-before.tsv")
	if _, err := manifest.Scan(t.Context(), filepath.Join(root, ".sow"), manifest.Scope{Path: "."}, stateBefore, manifest.ScanOptions{Workers: 1, ChunkEntries: 1, TempDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })

	for _, arguments := range [][]string{
		{"materialize", "latest", "--nginx-include", "-", "--config", configPath},
		{"materialize", "latest", "--edge-contract", "cf", "--config", configPath},
		{"materialize", "latest", "--config", configPath, "--workers", "1", "--chunk-entries", "1"},
		{"publish", "--view", "latest", "--target", "cf", "--config", configPath, "--workers", "1", "--chunk-entries", "1"},
	} {
		stdout.Reset()
		stderr.Reset()
		code := Main(arguments, &stdout, &stderr)
		if code != ExitConflict || !strings.Contains(stderr.String(), "pending YUM compatibility cutover journal") || !strings.Contains(stderr.String(), "--recover") {
			t.Fatalf("pending cutover args=%v code=%d stdout=%s stderr=%s", arguments, code, stdout.String(), stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("pending cutover emitted ordinary-command output args=%v stdout=%s", arguments, stdout.String())
		}
	}
	transport.mutex.Lock()
	remoteCalls := transport.puts + transport.copies + transport.deletes + transport.purges + transport.cdnGets + transport.listCalls + transport.objectGets + transport.headCalls
	transport.mutex.Unlock()
	if remoteCalls != 0 {
		t.Fatalf("pending local cutover reached provider transport calls=%d", remoteCalls)
	}
	stateAfter := filepath.Join(t.TempDir(), "state-after.tsv")
	if _, err := manifest.Scan(t.Context(), filepath.Join(root, ".sow"), manifest.Scope{Path: "."}, stateAfter, manifest.ScanOptions{Workers: 1, ChunkEntries: 1, TempDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := requireManifestFilesEqual(stateBefore, stateAfter); err != nil {
		t.Fatalf("pending local cutover ordinary commands mutated state: %v", err)
	}
}

func TestOrdinaryCompatibilityActivationFollowsAppendOnlyS3Ledger(t *testing.T) {
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	baseline := filepath.Join(root, "baseline")
	if err := os.WriteFile(baseline, []byte("baseline\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.InstallPaths(map[string]string{"baseline": baseline}, "test: initialize compatibility gate"); err != nil || !changed {
		t.Fatalf("initialize changed=%t err=%v", changed, err)
	}
	active := true
	owner := config.Repo{
		ID: "infra-el9", Type: "yum", Path: "yum/infra/el9/{arch}", Active: &active,
		PublishTargets: []string{"cf"}, OS: config.OSConfig{Family: "el", Major: 9, Lifecycle: "active"},
		Arches: []string{"x86_64"}, YUM: &config.YUMConfig{Compression: "zstd"},
	}
	projection := config.YUMCompatibilityProjection{
		ID: "infra-legacy-x86-64", Root: "yum/infra/x86_64", Mode: config.YUMCompatibilityModeFrozenCrossEL, Carrier: "infra-legacy-carrier",
		Source: config.YUMCompatibilitySource{Repo: owner.ID, View: "latest", OS: "cross-el", Arch: "x86_64", Commit: strings.Repeat("a", 40)},
	}
	cfg := &config.Config{Root: root, Repos: []config.Repo{owner}, CompatibilityProjections: []config.YUMCompatibilityProjection{projection}}
	ordinary := preparedPublication{view: "latest", projections: []publicationProjection{{view: "latest", repo: owner, os: "cross-el", arch: "x86_64"}}}

	assertActive := func(want bool) preparedPublication {
		t.Helper()
		prepared, err := activeLocalYUMCompatibilityPrepared(cfg, canonical, ordinary)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(prepared.projections) == 1; got != want {
			t.Fatalf("active compatibility projection=%t want=%t prepared=%+v", got, want, prepared.projections)
		}
		if want {
			leaves := localYUMCompatibilityTopologyLeaves(prepared)
			if len(leaves) != 1 || leaves[0].repo.ID != projection.ID || leaves[0].os != "cross-el" || leaves[0].arch != projection.Source.Arch {
				t.Fatalf("compatibility topology leaves=%+v", leaves)
			}
		}
		return prepared
	}
	assertActive(false)

	cutover := yumCompatibilityCutoverEvent{
		Schema: yumCompatibilityCutoverEventSchema, Sequence: 1, ID: projection.ID, Action: "cutover",
		ServingLink:  path.Join(".sow", "serving", "compatibility", "yum", projection.ID, "current"),
		FromTarget:   projection.Root,
		ToTarget:     path.Join(".sow", "materialized", "compatibility", projection.ID, strings.Repeat("b", 64)),
		FreezeCommit: strings.Repeat("a", 40), CandidateManifestSHA256: strings.Repeat("b", 64),
		PreviousEventSHA256: strings.Repeat("0", 64),
	}
	cutover.EventSHA256 = sealCompatibilityGateTestEvent(t, cutover)
	installCompatibilityGateTestLedger(t, canonical, projection.ID, []yumCompatibilityCutoverEvent{cutover})
	assertActive(true)
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDesiredActiveYUMCompatibilityCompleteness(cfg, canonical, "cf", pub.TargetGeneration{Compatibility: []pub.CompatibilityState{{ID: projection.ID}}}, head); err != nil {
		t.Fatalf("active S3 desired vector rejected: %v", err)
	}
	if err := validateDesiredActiveYUMCompatibilityCompleteness(cfg, canonical, "cf", pub.TargetGeneration{}, head); err == nil {
		t.Fatal("active S3 projection was allowed to disappear from the desired target vector")
	}

	rollback := yumCompatibilityCutoverEvent{
		Schema: yumCompatibilityCutoverEventSchema, Sequence: 2, ID: projection.ID, Action: "rollback",
		ServingLink: cutover.ServingLink, FromTarget: cutover.ToTarget, ToTarget: cutover.FromTarget,
		FreezeCommit: cutover.FreezeCommit, CandidateManifestSHA256: cutover.CandidateManifestSHA256,
		PreviousEventSHA256: cutover.EventSHA256,
	}
	rollback.EventSHA256 = sealCompatibilityGateTestEvent(t, rollback)
	installCompatibilityGateTestLedger(t, canonical, projection.ID, []yumCompatibilityCutoverEvent{cutover, rollback})
	assertActive(false)
	head, err = canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDesiredActiveYUMCompatibilityCompleteness(cfg, canonical, "cf", pub.TargetGeneration{}, head); err != nil {
		t.Fatalf("rolled-back desired vector rejected: %v", err)
	}
	if err := validateDesiredActiveYUMCompatibilityCompleteness(cfg, canonical, "cf", pub.TargetGeneration{Compatibility: []pub.CompatibilityState{{ID: projection.ID}}}, head); err == nil {
		t.Fatal("rolled-back projection remained publishable")
	}

	ledgerPath, _ := state.YUMCompatibilityCutoverPath(projection.ID)
	tampered := filepath.Join(t.TempDir(), "tampered.jsonl")
	body := compatibilityGateTestLedgerBody(t, []yumCompatibilityCutoverEvent{cutover, rollback})
	body[len(body)-3] ^= 1
	if err := os.WriteFile(tampered, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.InstallPaths(map[string]string{ledgerPath: tampered}, "test: tamper compatibility ledger"); err != nil || !changed {
		t.Fatalf("install tamper changed=%t err=%v", changed, err)
	}
	if _, err := activeLocalYUMCompatibilityPrepared(cfg, canonical, ordinary); err == nil {
		t.Fatal("ordinary materialization accepted a tampered compatibility ledger")
	}
}

func sealCompatibilityGateTestEvent(t *testing.T, event yumCompatibilityCutoverEvent) string {
	t.Helper()
	value, err := buildYUMCompatibilityCutoverEventHash(event)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func compatibilityGateTestLedgerBody(t *testing.T, events []yumCompatibilityCutoverEvent) []byte {
	t.Helper()
	var body []byte
	for _, event := range events {
		line, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, line...)
		body = append(body, '\n')
	}
	return body
}

func installCompatibilityGateTestLedger(t *testing.T, canonical *state.Store, id string, events []yumCompatibilityCutoverEvent) {
	t.Helper()
	ledger := filepath.Join(t.TempDir(), "cutover.jsonl")
	if err := os.WriteFile(ledger, compatibilityGateTestLedgerBody(t, events), 0o600); err != nil {
		t.Fatal(err)
	}
	ledgerPath, err := state.YUMCompatibilityCutoverPath(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.InstallPaths(map[string]string{ledgerPath: ledger}, "test: append compatibility ledger"); err != nil || !changed {
		t.Fatalf("install ledger changed=%t err=%v", changed, err)
	}
}
