package cli

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

type historicalAdoptionTestState struct {
	t         *testing.T
	canonical *state.Store
}

func newHistoricalAdoptionTestState(t *testing.T) *historicalAdoptionTestState {
	t.Helper()
	canonical := state.New(filepath.Join(t.TempDir(), ".sow"))
	stage := filepath.Join(t.TempDir(), "baseline")
	if err := os.WriteFile(stage, []byte("baseline\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.InstallPaths(map[string]string{"test/baseline": stage}, "test: initialize historical adoption state"); err != nil {
		t.Fatal(err)
	}
	return &historicalAdoptionTestState{t: t, canonical: canonical}
}

func historicalAdoptionEntry(name, body string) manifest.Entry {
	return manifest.Entry{Path: name, Size: int64(len(body)), SHA256: sha256.Sum256([]byte(body))}
}

func (fixture *historicalAdoptionTestState) writeManifest(entries []manifest.Entry) string {
	fixture.t.Helper()
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	filename := filepath.Join(fixture.t.TempDir(), "manifest.tsv")
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		fixture.t.Fatal(err)
	}
	for _, entry := range entries {
		if err := manifest.WriteEntry(file, entry); err != nil {
			_ = file.Close()
			fixture.t.Fatal(err)
		}
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		fixture.t.Fatal(err)
	}
	return filename
}

func (fixture *historicalAdoptionTestState) installPublication(generation uint64, content []manifest.Entry, objects []pub.PlannedObject, desiredOverride plumbing.Hash, intentPlanOverride *pub.Plan) plumbing.Hash {
	fixture.t.Helper()
	desiredCommit, err := fixture.canonical.HeadHash()
	if err != nil {
		fixture.t.Fatal(err)
	}
	if !desiredOverride.IsZero() {
		desiredCommit = desiredOverride
	}
	contentPath := fixture.writeManifest(append([]manifest.Entry(nil), content...))
	contentBody, err := os.ReadFile(contentPath)
	if err != nil {
		fixture.t.Fatal(err)
	}
	plan, err := (pub.Plan{Objects: append([]pub.PlannedObject(nil), objects...)}).WithCDN("https://repo.test/")
	if err != nil {
		fixture.t.Fatal(err)
	}
	planBody, err := plan.Canonical()
	if err != nil {
		fixture.t.Fatal(err)
	}
	planSHA, err := plan.Digest()
	if err != nil {
		fixture.t.Fatal(err)
	}
	intentPlanBody := planBody
	if intentPlanOverride != nil {
		intentPlanBody, err = intentPlanOverride.Canonical()
		if err != nil {
			fixture.t.Fatal(err)
		}
	}
	generationState := pub.TargetGeneration{
		Target:           pub.TargetCloudflare,
		Generation:       generation,
		ParentGeneration: generation - 1,
		DesiredCommit:    desiredCommit.String(),
		IntentView:       "latest",
		ConfigSHA256:     strings.Repeat("c", 64),
		Refs: []pub.RefState{{
			Name: "refs/sow/views/latest/assets/all/all", Commit: desiredCommit.String(),
			ManifestSHA256: strings.Repeat("d", 64),
		}},
		ContentManifestSHA256: digestBytesCLI(contentBody),
	}
	generationBody, err := generationState.Canonical()
	if err != nil {
		fixture.t.Fatal(err)
	}
	checkpoint, err := pub.NewCheckpoint(generationState, fmt.Sprintf("historical-adoption-%d", generation), planSHA, pub.PhaseCheckpointCommitted, time.Unix(1_700_000_000+int64(generation), 0).UTC())
	if err != nil {
		fixture.t.Fatal(err)
	}
	checkpointBody, err := checkpoint.Canonical()
	if err != nil {
		fixture.t.Fatal(err)
	}
	stageDir := fixture.t.TempDir()
	stage := func(name string, body []byte) string {
		fixture.t.Helper()
		filename := filepath.Join(stageDir, name)
		if err := os.WriteFile(filename, body, 0o600); err != nil {
			fixture.t.Fatal(err)
		}
		return filename
	}
	intentGenerationPath, _ := remoteIntentStatePath("cf", "latest", "", "generation.json")
	intentCheckpointPath, _ := remoteIntentStatePath("cf", "latest", "", "checkpoint.json")
	intentPlanPath, _ := remoteIntentStatePath("cf", "latest", "", "plan.json")
	staged := map[string]string{
		remoteStatePath("cf", "generation.json"): stage("generation.json", generationBody),
		remoteStatePath("cf", "checkpoint.json"): stage("checkpoint.json", checkpointBody),
		remoteStatePath("cf", "plan.json"):       stage("plan.json", planBody),
		remoteStatePath("cf", "content.tsv"):     contentPath,
		intentGenerationPath:                     stage("intent-generation.json", generationBody),
		intentCheckpointPath:                     stage("intent-checkpoint.json", checkpointBody),
		intentPlanPath:                           stage("intent-plan.json", intentPlanBody),
	}
	commit, changed, err := fixture.canonical.InstallPaths(staged, fmt.Sprintf("test: publish generation %d", generation))
	if err != nil || !changed {
		fixture.t.Fatalf("install generation %d changed=%v err=%v", generation, changed, err)
	}
	return commit
}

func (fixture *historicalAdoptionTestState) installInventory(coverage string, entries []manifest.Entry, malformed bool) {
	fixture.t.Helper()
	stageDir := fixture.t.TempDir()
	inventoryPath := filepath.Join(stageDir, "inventory.tsv")
	if malformed {
		if err := os.WriteFile(inventoryPath, []byte("malformed\n"), 0o600); err != nil {
			fixture.t.Fatal(err)
		}
	} else {
		inventoryPath = fixture.writeManifest(append([]manifest.Entry(nil), entries...))
	}
	coveragePath := filepath.Join(stageDir, "inventory.coverage")
	if err := os.WriteFile(coveragePath, []byte(coverage), 0o600); err != nil {
		fixture.t.Fatal(err)
	}
	if _, _, err := fixture.canonical.InstallPaths(map[string]string{
		remoteStatePath("cf", "inventory.tsv"):      inventoryPath,
		remoteStatePath("cf", "inventory.coverage"): coveragePath,
	}, "test: install current remote inventory"); err != nil {
		fixture.t.Fatal(err)
	}
}

func immutableRestorePlan(entry manifest.Entry) pub.Plan {
	return pub.Plan{Objects: []pub.PlannedObject{{
		SourcePath: entry.Path, RemoteKey: entry.Path, Size: entry.Size,
		SHA256: entry.HashString(), Class: pub.ObjectImmutable,
	}}}
}

func adoptedHistoricalObject(entry manifest.Entry) pub.PlannedObject {
	return pub.PlannedObject{
		SourcePath: entry.Path, RemoteKey: entry.Path, Size: entry.Size,
		SHA256: entry.HashString(), Class: pub.ObjectAdoptedImmutable,
	}
}

func ordinaryHistoricalObject(entry manifest.Entry) pub.PlannedObject {
	return pub.PlannedObject{
		SourcePath: entry.Path, RemoteKey: entry.Path, Size: entry.Size,
		SHA256: entry.HashString(), Class: pub.ObjectImmutable,
	}
}

func TestHistoricalAdoptedImmutableRestoreDirectAndCarried(t *testing.T) {
	a := historicalAdoptionEntry("pkg/a.bin", "adopted-a")
	b := historicalAdoptionEntry("pkg/b.bin", "ordinary-b")
	for _, test := range []struct {
		name    string
		carried bool
	}{
		{name: "direct-generation-one"},
		{name: "carried-through-generation-two", carried: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHistoricalAdoptionTestState(t)
			gen1 := fixture.installPublication(1, []manifest.Entry{a}, []pub.PlannedObject{adoptedHistoricalObject(a)}, plumbing.ZeroHash, nil)
			sourceCommit, sourceGeneration := gen1, uint64(1)
			inventory := []manifest.Entry{a}
			if test.carried {
				sourceCommit = fixture.installPublication(2, []manifest.Entry{a, b}, []pub.PlannedObject{ordinaryHistoricalObject(b)}, plumbing.ZeroHash, nil)
				sourceGeneration = 2
				inventory = append(inventory, b)
			}
			fixture.installInventory(remoteInventoryComplete, inventory, false)
			plan := immutableRestorePlan(a)
			if err := markHistoricallyAdoptedImmutableObjects(fixture.canonical, "cf", sourceCommit, sourceGeneration, &plan); err != nil {
				t.Fatal(err)
			}
			if plan.Objects[0].Class != pub.ObjectAdoptedImmutable {
				t.Fatalf("restore class=%s want=%s", plan.Objects[0].Class, pub.ObjectAdoptedImmutable)
			}
		})
	}
}

func TestHistoricalAdoptedImmutableRestoreRequiresCurrentCompleteExactInventory(t *testing.T) {
	a := historicalAdoptionEntry("pkg/a.bin", "adopted-a")
	for _, test := range []struct {
		name      string
		coverage  string
		inventory []manifest.Entry
		malformed bool
		wantClass pub.ObjectClass
		wantError string
	}{
		{name: "legally-deleted-is-uploaded", coverage: remoteInventoryComplete, wantClass: pub.ObjectImmutable},
		{name: "partial-does-not-inherit", coverage: remoteInventoryPartial, inventory: []manifest.Entry{a}, wantClass: pub.ObjectImmutable},
		{name: "mismatch-is-drift", coverage: remoteInventoryComplete, inventory: []manifest.Entry{historicalAdoptionEntry(a.Path, "different")}, wantError: "disagrees with complete remote inventory"},
		{name: "malformed-is-drift", coverage: remoteInventoryComplete, malformed: true, wantError: "read historical adopted remote inventory"},
		{name: "invalid-coverage-is-drift", coverage: "unknown\n", inventory: []manifest.Entry{a}, wantError: "coverage is invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHistoricalAdoptionTestState(t)
			sourceCommit := fixture.installPublication(1, []manifest.Entry{a}, []pub.PlannedObject{adoptedHistoricalObject(a)}, plumbing.ZeroHash, nil)
			fixture.installInventory(test.coverage, test.inventory, test.malformed)
			plan := immutableRestorePlan(a)
			err := markHistoricallyAdoptedImmutableObjects(fixture.canonical, "cf", sourceCommit, 1, &plan)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) || !errors.Is(err, pub.ErrDrift) {
					t.Fatalf("err=%v want drift containing %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if plan.Objects[0].Class != test.wantClass {
				t.Fatalf("restore class=%s want=%s", plan.Objects[0].Class, test.wantClass)
			}
		})
	}
	t.Run("missing-coverage-does-not-inherit", func(t *testing.T) {
		fixture := newHistoricalAdoptionTestState(t)
		sourceCommit := fixture.installPublication(1, []manifest.Entry{a}, []pub.PlannedObject{adoptedHistoricalObject(a)}, plumbing.ZeroHash, nil)
		plan := immutableRestorePlan(a)
		if err := markHistoricallyAdoptedImmutableObjects(fixture.canonical, "cf", sourceCommit, 1, &plan); err != nil {
			t.Fatal(err)
		}
		if plan.Objects[0].Class != pub.ObjectImmutable {
			t.Fatalf("missing coverage inherited class=%s", plan.Objects[0].Class)
		}
	})
	t.Run("complete-coverage-requires-inventory", func(t *testing.T) {
		fixture := newHistoricalAdoptionTestState(t)
		sourceCommit := fixture.installPublication(1, []manifest.Entry{a}, []pub.PlannedObject{adoptedHistoricalObject(a)}, plumbing.ZeroHash, nil)
		coverage := filepath.Join(t.TempDir(), "inventory.coverage")
		if err := os.WriteFile(coverage, []byte(remoteInventoryComplete), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := fixture.canonical.InstallPaths(map[string]string{remoteStatePath("cf", "inventory.coverage"): coverage}, "test: incomplete complete inventory"); err != nil {
			t.Fatal(err)
		}
		plan := immutableRestorePlan(a)
		err := markHistoricallyAdoptedImmutableObjects(fixture.canonical, "cf", sourceCommit, 1, &plan)
		if err == nil || !errors.Is(err, pub.ErrDrift) || !strings.Contains(err.Error(), "inventory manifest is missing") {
			t.Fatalf("missing complete inventory err=%v", err)
		}
	})
}

func TestHistoricalAdoptedImmutableRestoreRejectsForgedOrFutureProof(t *testing.T) {
	a := historicalAdoptionEntry("pkg/a.bin", "adopted-a")
	b := historicalAdoptionEntry("pkg/b.bin", "ordinary-b")
	t.Run("adopted-plan-object-absent-from-bound-content", func(t *testing.T) {
		fixture := newHistoricalAdoptionTestState(t)
		sourceCommit := fixture.installPublication(1, []manifest.Entry{b}, []pub.PlannedObject{adoptedHistoricalObject(a)}, plumbing.ZeroHash, nil)
		fixture.installInventory(remoteInventoryComplete, []manifest.Entry{a, b}, false)
		plan := immutableRestorePlan(a)
		err := markHistoricallyAdoptedImmutableObjects(fixture.canonical, "cf", sourceCommit, 1, &plan)
		if err == nil || !errors.Is(err, pub.ErrDrift) || !strings.Contains(err.Error(), "absent from content manifest") {
			t.Fatalf("forged plan err=%v", err)
		}
	})
	t.Run("nonexistent-desired-commit", func(t *testing.T) {
		fixture := newHistoricalAdoptionTestState(t)
		sourceCommit := fixture.installPublication(1, []manifest.Entry{a}, []pub.PlannedObject{adoptedHistoricalObject(a)}, plumbing.NewHash(strings.Repeat("e", 40)), nil)
		fixture.installInventory(remoteInventoryComplete, []manifest.Entry{a}, false)
		plan := immutableRestorePlan(a)
		err := markHistoricallyAdoptedImmutableObjects(fixture.canonical, "cf", sourceCommit, 1, &plan)
		if err == nil || !errors.Is(err, pub.ErrDrift) || !strings.Contains(err.Error(), "outside canonical HEAD history") {
			t.Fatalf("nonexistent desired commit err=%v", err)
		}
	})
	t.Run("future-desired-commit", func(t *testing.T) {
		canonical := state.New(filepath.Join(t.TempDir(), ".sow"))
		stage := filepath.Join(t.TempDir(), "state")
		if err := os.WriteFile(stage, []byte("state\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		stateCommit, changed, err := canonical.InstallPaths(map[string]string{"tests/state": stage}, "test: publication state")
		if err != nil || !changed {
			t.Fatalf("state commit=%s changed=%t err=%v", stateCommit, changed, err)
		}
		if err := os.WriteFile(stage, []byte("future\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		futureCommit, changed, err := canonical.InstallPaths(map[string]string{"tests/state": stage}, "test: future desired state")
		if err != nil || !changed {
			t.Fatalf("future commit=%s changed=%t err=%v", futureCommit, changed, err)
		}
		generation := pub.TargetGeneration{DesiredCommit: futureCommit.String()}
		err = validateHistoricalDesiredCommit(canonical, generation, stateCommit, 1, map[plumbing.Hash]int{
			futureCommit: 0,
			stateCommit:  1,
		})
		if err == nil || !strings.Contains(err.Error(), "future desired commit") {
			t.Fatalf("future desired commit err=%v", err)
		}
	})
}

func TestHistoricalAdoptedImmutableRestoreExcludesEvidenceAfterSource(t *testing.T) {
	a := historicalAdoptionEntry("pkg/a.bin", "adopted-a")
	fixture := newHistoricalAdoptionTestState(t)
	sourceCommit := fixture.installPublication(1, []manifest.Entry{a}, []pub.PlannedObject{ordinaryHistoricalObject(a)}, plumbing.ZeroHash, nil)
	fixture.installPublication(2, []manifest.Entry{a}, []pub.PlannedObject{adoptedHistoricalObject(a)}, plumbing.ZeroHash, nil)
	fixture.installInventory(remoteInventoryComplete, []manifest.Entry{a}, false)
	plan := immutableRestorePlan(a)
	if err := markHistoricallyAdoptedImmutableObjects(fixture.canonical, "cf", sourceCommit, 1, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Objects[0].Class != pub.ObjectImmutable {
		t.Fatalf("post-source proof changed restore class=%s", plan.Objects[0].Class)
	}
}

func prepareHistoricalAdoptionE2E(t *testing.T) (string, string, []byte, *cloudProtocolTransport, func(...string) (int, string, string)) {
	t.Helper()
	root, configPath, transport, run := prepareRemoteAdoptionAsset(t, "cf")
	payload, err := os.ReadFile(filepath.Join(root, "pkg", "release.bin"))
	if err != nil {
		t.Fatal(err)
	}
	transport.mutex.Lock()
	transport.objects["pkg/release.bin"] = protocolObject{body: append([]byte(nil), payload...), sha: publishDigest(payload), etag: `"historical-adopted"`}
	transport.mutex.Unlock()
	for _, command := range [][]string{
		{"fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"},
		{"publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"},
	} {
		if code, stdout, stderr := run(command...); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", command, code, stdout, stderr)
		}
	}
	planBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pub.DecodePlan(planBody)
	if err != nil || len(plan.Objects) != 1 || plan.Objects[0].RemoteKey != "pkg/release.bin" || plan.Objects[0].Class != pub.ObjectAdoptedImmutable {
		t.Fatalf("generation-one adopted plan=%#v err=%v", plan, err)
	}
	return root, configPath, payload, transport, run
}

func reinsertHistoricalAdoptedRemoteAndInventory(t *testing.T, root string, payload []byte, transport *cloudProtocolTransport) {
	t.Helper()
	entry := historicalAdoptionEntry("pkg/release.bin", string(payload))
	transport.mutex.Lock()
	transport.objects[entry.Path] = protocolObject{body: append([]byte(nil), payload...), sha: entry.HashString(), etag: `"retained-adopted"`}
	transport.mutex.Unlock()
	canonical := state.New(filepath.Join(root, ".sow"))
	parent, exists, err := openOptionalCanonical(canonical, remoteStatePath("cf", "inventory.tsv"))
	if err != nil || !exists {
		t.Fatalf("open current inventory exists=%v err=%v", exists, err)
	}
	destination := filepath.Join(t.TempDir(), "inventory.tsv")
	if err := writeMergedRemoteInventory(parent, map[string]manifest.Entry{entry.Path: entry}, destination); err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.InstallPaths(map[string]string{remoteStatePath("cf", "inventory.tsv"): destination}, "test: attest retained adopted payload"); err != nil || !changed {
		t.Fatalf("install retained inventory changed=%v err=%v", changed, err)
	}
}

func historicalRestorePutKeys(transport *cloudProtocolTransport, offset int) []string {
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	return append([]string(nil), transport.putKeys[offset:]...)
}

func TestPublishRestoreDirectHistoricalAdoptionSkipsOnlyRetainedObject(t *testing.T) {
	for _, test := range []struct {
		name     string
		retained bool
		wantPut  bool
	}{
		{name: "complete-inventory-retains-adopted-object", retained: true},
		{name: "legal-delete-restores-with-put", wantPut: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, configPath, payload, transport, run := prepareHistoricalAdoptionE2E(t)
			for _, command := range [][]string{
				{"rm", "release.bin", "--view", "latest", "--config", configPath, "--repo", "assets"},
				{"publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"},
			} {
				if code, stdout, stderr := run(command...); code != ExitOK {
					t.Fatalf("command %v code=%d stdout=%s stderr=%s", command, code, stdout, stderr)
				}
			}
			if test.retained {
				reinsertHistoricalAdoptedRemoteAndInventory(t, root, payload, transport)
			}
			transport.mutex.Lock()
			putOffset := len(transport.putKeys)
			transport.mutex.Unlock()
			code, stdout, stderr := run("publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--workers", "2")
			if code != ExitOK || !strings.Contains(stdout, "source_generation=1") || !strings.Contains(stdout, "status=complete") {
				t.Fatalf("direct restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			payloadPut := false
			for _, key := range historicalRestorePutKeys(transport, putOffset) {
				if key == "pkg/release.bin" {
					payloadPut = true
				}
			}
			if payloadPut != test.wantPut {
				t.Fatalf("payload PUT=%v want=%v", payloadPut, test.wantPut)
			}
			planBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "plan.json"))
			if err != nil {
				t.Fatal(err)
			}
			plan, err := pub.DecodePlan(planBody)
			if err != nil || len(plan.Objects) != 1 {
				t.Fatalf("restore plan=%#v err=%v", plan, err)
			}
			wantClass := pub.ObjectAdoptedImmutable
			if test.wantPut {
				wantClass = pub.ObjectImmutable
			}
			if plan.Objects[0].Class != wantClass {
				t.Fatalf("restore class=%s want=%s", plan.Objects[0].Class, wantClass)
			}
			transport.mutex.Lock()
			remote := transport.objects["pkg/release.bin"]
			transport.mutex.Unlock()
			if string(remote.body) != string(payload) {
				t.Fatalf("restored payload=%q want=%q", remote.body, payload)
			}
		})
	}
}

func TestPublishRestoreCarriesHistoricalAdoptionAcrossSourcePlan(t *testing.T) {
	root, configPath, payload, transport, run := prepareHistoricalAdoptionE2E(t)
	second := filepath.Join(root, "second.bin")
	if err := os.WriteFile(second, []byte("second-generation\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{"add", second, "--config", configPath, "--repo", "assets", "--dest", "second.bin"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "assets"},
		{"materialize", "latest", "--config", configPath, "--repo", "assets", "--workers", "2"},
		{"publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"},
	} {
		if code, stdout, stderr := run(command...); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", command, code, stdout, stderr)
		}
	}
	gen2PlanBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	gen2Plan, err := pub.DecodePlan(gen2PlanBody)
	if err != nil {
		t.Fatal(err)
	}
	foundSecond := false
	for _, object := range gen2Plan.Objects {
		if object.RemoteKey == "pkg/release.bin" {
			t.Fatalf("generation two plan unexpectedly repeated carried object: %#v", gen2Plan.Objects)
		}
		if object.RemoteKey == "pkg/second.bin" {
			foundSecond = true
		}
	}
	if !foundSecond {
		t.Fatalf("generation two plan omitted changed object: %#v", gen2Plan.Objects)
	}
	for _, command := range [][]string{
		{"rm", "release.bin", "--view", "latest", "--config", configPath, "--repo", "assets"},
		{"publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"},
	} {
		if code, stdout, stderr := run(command...); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", command, code, stdout, stderr)
		}
	}
	reinsertHistoricalAdoptedRemoteAndInventory(t, root, payload, transport)
	transport.mutex.Lock()
	putOffset := len(transport.putKeys)
	transport.mutex.Unlock()
	code, stdout, stderr := run("publish", "--restore-generation", "2", "--target", "cf", "--config", configPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "source_generation=2") || !strings.Contains(stdout, "status=complete") {
		t.Fatalf("carried restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, key := range historicalRestorePutKeys(transport, putOffset) {
		if key == "pkg/release.bin" {
			t.Fatalf("carried adopted payload was retransferred: puts=%v", historicalRestorePutKeys(transport, putOffset))
		}
	}
	restorePlanBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	restorePlan, err := pub.DecodePlan(restorePlanBody)
	if err != nil || len(restorePlan.Objects) != 1 || restorePlan.Objects[0].RemoteKey != "pkg/release.bin" || restorePlan.Objects[0].Class != pub.ObjectAdoptedImmutable {
		t.Fatalf("carried restore plan=%#v err=%v", restorePlan, err)
	}
}
