package publish

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/manifest"
)

func TestTargetGenerationCanonicalDeterministic(t *testing.T) {
	t.Parallel()
	left := generationFixture(TargetCloudflare, 7)
	left.Refs[0], left.Refs[1] = left.Refs[1], left.Refs[0]
	right := generationFixture(TargetCloudflare, 7)
	leftJSON, err := left.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	rightJSON, err := right.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leftJSON, rightJSON) {
		t.Fatalf("canonical generation depends on input ref order:\n%s\n%s", leftJSON, rightJSON)
	}
	if key, _ := GenerationKey(7); key != ".sow/generations/00000000000000000007/generation.json" {
		t.Fatalf("unexpected generation key %q", key)
	}
	left.Refs = append(left.Refs, left.Refs[0])
	if _, err := left.Canonical(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate ref was not rejected: %v", err)
	}
	for _, unsafe := range []string{
		"refs/sow/views/latest/repo/../escape",
		"refs/sow/remotes/cf/latest/repo/el9/amd64",
		"refs/heads/not-sow",
	} {
		invalid := generationFixture(TargetCloudflare, 7)
		invalid.Refs[0].Name = unsafe
		if _, err := invalid.Canonical(); err == nil {
			t.Fatalf("unsafe generation ref %q was accepted", unsafe)
		}
	}
}

func TestTargetGenerationStrictCanonicalDecode(t *testing.T) {
	t.Parallel()
	generation := generationFixture(TargetTencent, 9)
	body, err := generation.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTargetGeneration(body)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, _ := generation.Digest()
	gotDigest, _ := decoded.Digest()
	if gotDigest != wantDigest || decoded.Generation != generation.Generation || len(decoded.Refs) != len(generation.Refs) {
		t.Fatalf("decoded generation lost baseline identity: %#v", decoded)
	}
	withUnknown := append(body[:len(body)-1], []byte(`,"unknown":true}`)...)
	if _, err := DecodeTargetGeneration(withUnknown); err == nil {
		t.Fatal("generation decoder accepted an unknown field")
	}
	if _, err := DecodeTargetGeneration(append(body, '\n')); err == nil {
		t.Fatal("generation decoder accepted non-canonical trailing whitespace")
	}
}

func TestTargetGenerationCarriesCanonicalChannelVector(t *testing.T) {
	t.Parallel()
	makeChannel := func(view, repo string, generation uint64) ChannelState {
		channel := ChannelState{
			View: view, Repo: repo, OS: "el10", Arch: "x86_64", Generation: generation,
			RemoteKey:  ".sow/channels/" + view + "/" + repo + "/el10/x86_64.json",
			LegacyRoot: "yum/" + repo + "/x86_64",
		}
		body, err := channel.CanonicalBody()
		if err != nil {
			t.Fatal(err)
		}
		channel.BodySHA256 = hashString(string(body))
		return channel
	}
	left := generationFixture(TargetCloudflare, 7)
	left.Channels = []ChannelState{makeChannel("stable", "commercial", 5), makeChannel("latest", "infra", 7)}
	right := generationFixture(TargetCloudflare, 7)
	right.Channels = []ChannelState{left.Channels[1], left.Channels[0]}
	leftBody, err := left.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	rightBody, err := right.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leftBody, rightBody) {
		t.Fatal("target generation channel vector depends on caller order")
	}
	invalid := left
	invalid.Channels = append([]ChannelState(nil), left.Channels...)
	invalid.Channels[0].BodySHA256 = hashString("wrong")
	if _, err := invalid.Canonical(); err == nil || !strings.Contains(err.Error(), "body digest") {
		t.Fatalf("invalid channel body digest passed: %v", err)
	}
	duplicate := left
	duplicate.Channels = append(duplicate.Channels, duplicate.Channels[0])
	if _, err := duplicate.Canonical(); err == nil || !strings.Contains(err.Error(), "duplicate channel") {
		t.Fatalf("duplicate channel passed: %v", err)
	}
}

func TestCheckpointStrictCanonicalRoundTrip(t *testing.T) {
	t.Parallel()
	checkpoint, err := NewCheckpoint(generationFixture(TargetTencent, 1), "tx-1", hashString("checkpoint-plan"), PhaseCheckpointCommitted, time.Date(2026, 7, 12, 1, 2, 3, 4, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	data, err := checkpoint.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCheckpoint(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != checkpoint {
		t.Fatalf("checkpoint round trip changed value: %#v != %#v", decoded, checkpoint)
	}
	withUnknown := append(data[:len(data)-1], []byte(`,"unknown":true}`)...)
	if _, err := DecodeCheckpoint(withUnknown); err == nil {
		t.Fatal("checkpoint decoder accepted an unknown field")
	}
	if _, err := DecodeCheckpoint(append(data, '\n')); err == nil {
		t.Fatal("checkpoint decoder accepted non-canonical trailing whitespace")
	}
}

func TestCheckpointV1ReadCompatibilityAndV2PlanBinding(t *testing.T) {
	t.Parallel()
	generation := generationFixture(TargetCloudflare, 1)
	if _, err := NewCheckpoint(generation, "tx-missing-plan", "", PhaseCheckpointCommitted, time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "plan sha256") {
		t.Fatalf("v2 checkpoint accepted no plan binding: %v", err)
	}
	checkpoint, err := NewCheckpoint(generation, "tx-v2", hashString("v2-plan"), PhaseCheckpointCommitted, time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	legacy := checkpoint
	legacy.Schema = CheckpointSchemaV1
	legacy.PlanSHA256 = ""
	body, err := legacy.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCheckpoint(body)
	if err != nil || decoded != legacy {
		t.Fatalf("legacy checkpoint round trip=%#v err=%v", decoded, err)
	}
	legacy.PlanSHA256 = hashString("forbidden-v1-plan")
	if _, err := legacy.Canonical(); err == nil || !strings.Contains(err.Error(), "v1 checkpoint") {
		t.Fatalf("v1 checkpoint accepted a v2 field: %v", err)
	}
}

func TestSnapshotIntentIsExactAndViewWireFormatStaysCompatible(t *testing.T) {
	t.Parallel()
	view := generationFixture(TargetCloudflare, 7)
	viewBody, err := view.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(viewBody, []byte("intent_snapshot")) {
		t.Fatalf("legacy view generation gained an optional field: %s", viewBody)
	}

	snapshot := generationFixture(TargetCloudflare, 7)
	snapshot.IntentView = "snapshot"
	snapshot.IntentSnapshot = "jammy-20260712"
	snapshot.Refs[0].Name = "refs/sow/snapshots/jammy-20260712/repo/el9/amd64"
	snapshot.Refs[1].Name = "refs/sow/snapshots/jammy-20260712/repo/el10/amd64"
	body, err := snapshot.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTargetGeneration(body)
	if err != nil || decoded.IntentSnapshot != snapshot.IntentSnapshot {
		t.Fatalf("snapshot intent was not preserved: %#v err=%v", decoded, err)
	}
	checkpoint, err := NewCheckpoint(snapshot, "tx-snapshot", hashString("snapshot-plan"), PhaseCheckpointCommitted, time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC))
	if err != nil || checkpoint.IntentSnapshot != snapshot.IntentSnapshot {
		t.Fatalf("checkpoint lost snapshot intent: %#v err=%v", checkpoint, err)
	}

	for name, mutate := range map[string]func(*TargetGeneration){
		"snapshot missing id": func(value *TargetGeneration) { value.IntentView = "snapshot" },
		"view carries id":     func(value *TargetGeneration) { value.IntentSnapshot = "jammy-20260712" },
		"invalid date": func(value *TargetGeneration) {
			value.IntentView, value.IntentSnapshot = "snapshot", "jammy-20260230"
		},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := generationFixture(TargetCloudflare, 7)
			mutate(&invalid)
			if _, err := invalid.Canonical(); err == nil {
				t.Fatal("invalid publication intent passed")
			}
		})
	}
}

func TestSnapshotRouteBodyIsCanonicalAndIdentityBound(t *testing.T) {
	t.Parallel()
	body, err := SnapshotRouteBody("jammy-20260712", 42)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"sow-snapshot-route/v1","snapshot":"jammy-20260712","generation":"00000000000000000042"}`
	if string(body) != want {
		t.Fatalf("snapshot route body=%s want=%s", body, want)
	}
	for _, test := range []struct {
		id         string
		generation uint64
	}{{id: "jammy", generation: 1}, {id: "jammy-20260230", generation: 1}, {id: "jammy-20260712", generation: 0}} {
		if _, err := SnapshotRouteBody(test.id, test.generation); err == nil {
			t.Fatalf("invalid snapshot route identity id=%q generation=%d was accepted", test.id, test.generation)
		}
	}
}

func TestBuildPlanStreamingChangeSetAndMinimalPurge(t *testing.T) {
	t.Parallel()
	var oldManifest, desiredManifest bytes.Buffer
	const unchanged = 25_000
	for i := 0; i < unchanged; i++ {
		name := fmt.Sprintf("pool/%05d.pkg", i)
		entry := manifest.Entry{Path: name, Size: int64(i + 1), SHA256: shaArray(name)}
		if err := manifest.WriteEntry(&oldManifest, entry); err != nil {
			t.Fatal(err)
		}
		if err := manifest.WriteEntry(&desiredManifest, entry); err != nil {
			t.Fatal(err)
		}
	}
	pointer := manifest.Entry{Path: "zz/dists/jammy/InRelease", Size: 3, SHA256: shaArray("new")}
	if err := manifest.WriteEntry(&desiredManifest, pointer); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(bytes.NewReader(oldManifest.Bytes()), bytes.NewReader(desiredManifest.Bytes()), func(entry manifest.Entry) (string, ObjectClass, error) {
		if strings.HasSuffix(entry.Path, "/InRelease") {
			return entry.Path, ObjectPointer, nil
		}
		return entry.Path, ObjectImmutable, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Objects) != 1 || plan.Stats.Added != 1 || plan.Stats.Changed != 0 || plan.Stats.Removed != 0 {
		t.Fatalf("plan retained more than the one-entry change set: %#v", plan)
	}
	plan, err = plan.WithCDN("https://repo.example/base/")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := plan.PurgeURLs, []string{"https://repo.example/base/zz/dists/jammy/InRelease"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("purge set=%v, want %v", got, want)
	}
	if len(plan.Verify) != 1 || plan.Verify[0].SHA256 != pointer.HashString() {
		t.Fatalf("unexpected verification closure %#v", plan.Verify)
	}
}

func TestBuildPlanRejectsNilManifestReaders(t *testing.T) {
	t.Parallel()
	for _, readers := range []struct {
		old io.Reader
		new io.Reader
	}{{nil, strings.NewReader("")}, {strings.NewReader(""), nil}, {nil, nil}} {
		if _, err := BuildPlan(readers.old, readers.new, IdentityClassifier); err == nil || !strings.Contains(err.Error(), "manifest readers") {
			t.Fatalf("nil manifest reader was not rejected: %v", err)
		}
	}
}

func TestPlanRejectsUnknownPersistedObjectClass(t *testing.T) {
	t.Parallel()
	plan := Plan{Schema: planSchema, Objects: []PlannedObject{{
		SourcePath: "pkg/object", RemoteKey: "pkg/object", Size: 1,
		SHA256: hashString("x"), Class: ObjectClass("future-or-forged"),
	}}}
	if _, err := plan.Canonical(); err == nil || !strings.Contains(err.Error(), "unknown object class") {
		t.Fatalf("unknown persisted object class was accepted: %v", err)
	}
}

func TestPlanRejectsUnboundPointerCDNRoutesAndVerificationOverrides(t *testing.T) {
	t.Parallel()
	sha := hashString("pointer")
	channelSHA := hashString("channel")
	cases := []PlannedObject{
		{SourcePath: "latest", RemoteKey: "pkg/latest", Size: 7, SHA256: sha, Class: ObjectPointer, CDNPath: "pkg/other"},
		{SourcePath: "beta", RemoteKey: ".sow/beta/pkg/latest", Size: 7, SHA256: sha, Class: ObjectPointer, CDNPath: ".sow/beta/pkg/latest"},
		{SourcePath: "stable", RemoteKey: ".sow/gated/pkg/latest", Size: 7, SHA256: sha, Class: ObjectPointer, CDNPath: "pkg/latest"},
		{SourcePath: "snapshot", RemoteKey: ".sow/snapshots/jammy-20260131.json", Size: 7, SHA256: sha, Class: ObjectPointer, CDNPath: "pro/v1/basic/_sow/v1/snapshots/jammy-20260201/_route.json"},
		{SourcePath: "channel", RemoteKey: ".sow/channels/stable/repo/el10/x86_64.json", Size: 7, SHA256: channelSHA, Class: ObjectPointer,
			CDNPath: "pro/v1/basic/_sow/v1/mirrorlist/stable/repo/el10/aarch64.txt", VerificationSize: 7, VerificationSHA256: sha},
	}
	for _, object := range cases {
		if _, err := (Plan{Schema: planSchema, Objects: []PlannedObject{object}}).WithCDN("https://repo.example/"); err == nil || !strings.Contains(err.Error(), "CDN path") {
			t.Fatalf("unbound pointer route was accepted: object=%#v err=%v", object, err)
		}
	}
	override := PlannedObject{SourcePath: "pkg/latest", RemoteKey: "pkg/latest", Size: 7, SHA256: sha, Class: ObjectPointer,
		CDNPath: "pkg/latest", VerificationSize: 7, VerificationSHA256: hashString("stale")}
	if _, err := (Plan{Schema: planSchema, Objects: []PlannedObject{override}}).WithCDN("https://repo.example/"); err == nil || !strings.Contains(err.Error(), "reserved for a canonical channel") {
		t.Fatalf("ordinary pointer accepted a forged verification override: %v", err)
	}
}

func TestPlanRejectsPresenceAbsenceCDNCollision(t *testing.T) {
	t.Parallel()
	sha := hashString("object")
	plan := Plan{Schema: planSchema,
		Objects: []PlannedObject{{SourcePath: "object", RemoteKey: "object", Size: 6, SHA256: sha, Class: ObjectImmutable, CDNPath: "route"}},
		Deletes: []PlannedDelete{{Class: DeleteAssetServing, SourcePath: "route", RemoteKey: "route", Size: 6, SHA256: sha, CDNPath: "route"}},
	}
	if _, err := plan.WithCDN("https://repo.example/"); err == nil || !strings.Contains(err.Error(), "both written") {
		t.Fatalf("contradictory presence/absence route was accepted: %v", err)
	}
}

func TestWithCDNDoesNotMutateCallerSlices(t *testing.T) {
	t.Parallel()
	objects := make([]PlannedObject, 2, 4)
	objects[0] = PlannedObject{SourcePath: "z", RemoteKey: "z", Size: 1, SHA256: hashString("z"), Class: ObjectPointer}
	objects[1] = PlannedObject{SourcePath: "a", RemoteKey: "a", Size: 1, SHA256: hashString("a"), Class: ObjectPointer}
	plan := Plan{Schema: planSchema, Objects: objects, Removed: []string{"z", "a"}}
	if _, err := plan.WithCDN("https://repo.example/"); err != nil {
		t.Fatal(err)
	}
	if plan.Objects[0].RemoteKey != "z" || plan.Objects[1].RemoteKey != "a" || strings.Join(plan.Removed, ",") != "z,a" {
		t.Fatalf("WithCDN mutated caller-owned slices: objects=%v removed=%v", plan.Objects, plan.Removed)
	}
}

func TestPlanLargeClosureValidationIsLinearInChangedObjects(t *testing.T) {
	if testing.Short() {
		t.Skip("large change-set closure")
	}
	const entries = 50_000
	objects := make([]PlannedObject, 0, entries)
	for index := 0; index < entries; index++ {
		key := fmt.Sprintf("objects/%05d", index)
		objects = append(objects, PlannedObject{SourcePath: key, RemoteKey: key, Size: 1, SHA256: hashString(key), Class: ObjectImmutable})
	}
	started := time.Now()
	plan, err := (Plan{Schema: planSchema, Objects: objects}).WithCDN("https://repo.example/")
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if len(plan.Verify) != entries || elapsed > 5*time.Second {
		t.Fatalf("large closure objects=%d verify=%d elapsed=%s", entries, len(plan.Verify), elapsed)
	}
	t.Logf("publish-full-change-set objects=%d elapsed=%s", entries, elapsed)
}

func TestBuildPlanNeverDeletesRemoteAndRejectsPurgeExpansion(t *testing.T) {
	t.Parallel()
	old := manifestText(t,
		manifest.Entry{Path: "a", Size: 1, SHA256: shaArray("a")},
		manifest.Entry{Path: "b", Size: 1, SHA256: shaArray("b")},
	)
	desired := manifestText(t, manifest.Entry{Path: "b", Size: 1, SHA256: shaArray("b")})
	plan, err := BuildPlan(strings.NewReader(old), strings.NewReader(desired), IdentityClassifier)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Objects) != 0 || len(plan.Removed) != 1 || plan.Removed[0] != "a" {
		t.Fatalf("remove should be audit-only, got %#v", plan)
	}
	bad := Plan{
		Schema:    planSchema,
		Objects:   []PlannedObject{{SourcePath: "pointer", RemoteKey: "pointer", Size: 1, SHA256: hashString("p"), Class: ObjectPointer}},
		PurgeURLs: []string{"https://repo.example/everything"},
	}
	if _, err := bad.Canonical(); err == nil {
		t.Fatal("plan accepted purge expansion outside its pointer set")
	}
}

func TestBuildPlanRejectsNonRoutableKeySegments(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"pkg/bad name.bin", "pkg/tool@latest", "pkg/中文.tar.gz"} {
		t.Run(key, func(t *testing.T) {
			desired := manifestText(t, manifest.Entry{Path: key, Size: 1, SHA256: shaArray(key)})
			if _, err := BuildPlan(strings.NewReader(""), strings.NewReader(desired), IdentityClassifier); err == nil || !strings.Contains(err.Error(), "not edge-routable") {
				t.Fatalf("non-routable publish key %q accepted or misclassified: %v", key, err)
			}
		})
	}
}

func TestPlanAllowsOnlyExactSnapshotOwnedDeletes(t *testing.T) {
	t.Parallel()
	plan := Plan{Schema: planSchema, Deletes: []PlannedDelete{{
		RemoteKey: ".sow/snapshots/jammy-20260131.json",
		CDNPath:   "pro/v1/basic/_sow/v1/snapshots/jammy-20260131/_route.json",
	}, {
		RemoteKey: ".sow/gated/snapshots/jammy-20260131/yum/repo/Packages/pkg.rpm",
	}}}
	plan, err := plan.WithCDN("https://repo.example/")
	if err != nil {
		t.Fatal(err)
	}
	wantPurge := []string{
		"https://repo.example/.sow/snapshots/jammy-20260131.json",
		"https://repo.example/pro/v1/basic/_sow/v1/snapshots/jammy-20260131/_route.json",
	}
	if fmt.Sprint(plan.PurgeURLs) != fmt.Sprint(wantPurge) {
		t.Fatalf("unexpected retention purge closure: %v", plan.PurgeURLs)
	}
	if len(plan.VerifyAbsent) != 1 || plan.VerifyAbsent[0].URL != wantPurge[1] {
		t.Fatalf("unexpected retention absence closure: %#v", plan.VerifyAbsent)
	}
	missingCleanPurge := plan
	missingCleanPurge.PurgeURLs = append([]string(nil), wantPurge[1:]...)
	if _, err := missingCleanPurge.Canonical(); err == nil || !strings.Contains(err.Error(), "purge set does not cover") {
		t.Fatalf("routed deletion without clean-cache purge alias accepted: %v", err)
	}
	missingAbsence := plan
	missingAbsence.VerifyAbsent = nil
	if _, err := missingAbsence.Canonical(); err == nil || !strings.Contains(err.Error(), "absence verification set") {
		t.Fatalf("routed deletion without negative verification accepted: %v", err)
	}
	wrongRoute := Plan{Schema: planSchema, Deletes: []PlannedDelete{{
		RemoteKey: ".sow/snapshots/jammy-20260131.json",
		CDNPath:   "pro/v1/basic/_sow/v1/snapshots/jammy-20260201/_route.json",
	}}}
	if _, err := wrongRoute.WithCDN("https://repo.example/"); err == nil || !strings.Contains(err.Error(), "want") {
		t.Fatalf("snapshot deletion accepted another route ID: %v", err)
	}
	payloadRoute := Plan{Schema: planSchema, Deletes: []PlannedDelete{{
		RemoteKey: ".sow/gated/snapshots/jammy-20260131/yum/repo/Packages/pkg.rpm",
		CDNPath:   "pro/v1/basic/unrelated",
	}}}
	if _, err := payloadRoute.WithCDN("https://repo.example/"); err == nil || !strings.Contains(err.Error(), "must not claim") {
		t.Fatalf("snapshot payload deletion accepted a direct client route: %v", err)
	}
	for _, key := range []string{
		".sow/manifest.json",
		".sow/gated/apt/repo/pool/pkg.deb",
		".sow/gated/generations/00000000000000000001/yum/repo/repodata/repomd.xml",
		".sow/gated/snapshots/not-a-date/yum/repo/Packages/pkg.rpm",
	} {
		invalid := Plan{Schema: planSchema, Deletes: []PlannedDelete{{RemoteKey: key}}}
		if _, err := invalid.Canonical(); err == nil {
			t.Fatalf("unsafe deletion %s passed", key)
		}
	}
}

func TestPlanPurgesClientAndCleanInternalCacheKeys(t *testing.T) {
	t.Parallel()
	sha := hashString("pointer")
	tests := []struct {
		name       string
		object     PlannedObject
		wantPurges []string
	}{
		{
			name: "public-latest-keeps-one-url",
			object: PlannedObject{SourcePath: "apt/repo/dists/jammy/InRelease", RemoteKey: "apt/repo/dists/jammy/InRelease",
				Size: 7, SHA256: sha, Class: ObjectPointer},
			wantPurges: []string{"https://repo.example/apt/repo/dists/jammy/InRelease"},
		},
		{
			name: "beta-apt",
			object: PlannedObject{SourcePath: ".sow/materialized/beta/apt/repo/dists/jammy/InRelease", RemoteKey: ".sow/beta/apt/repo/dists/jammy/InRelease",
				Size: 7, SHA256: sha, Class: ObjectPointer, CDNPath: "apt/repo/dists/jammy/InRelease"},
			wantPurges: []string{
				"https://repo.example/.sow/beta/apt/repo/dists/jammy/InRelease",
				"https://repo.example/apt/repo/dists/jammy/InRelease",
			},
		},
		{
			name: "stable-apt",
			object: PlannedObject{SourcePath: ".sow/origin/gated/apt/repo/dists/jammy/InRelease", RemoteKey: ".sow/gated/apt/repo/dists/jammy/InRelease",
				Size: 7, SHA256: sha, Class: ObjectPointer, CDNPath: "pro/v1/basic/apt/repo/dists/jammy/InRelease"},
			wantPurges: []string{
				"https://repo.example/.sow/gated/apt/repo/dists/jammy/InRelease",
				"https://repo.example/pro/v1/basic/apt/repo/dists/jammy/InRelease",
			},
		},
		{
			name: "snapshot-route",
			object: PlannedObject{SourcePath: ".sow/generated/route.json", RemoteKey: ".sow/snapshots/jammy-20260131.json",
				Size: 7, SHA256: sha, Class: ObjectPointer, CDNPath: "pro/v1/basic/_sow/v1/snapshots/jammy-20260131/_route.json"},
			wantPurges: []string{
				"https://repo.example/.sow/snapshots/jammy-20260131.json",
				"https://repo.example/pro/v1/basic/_sow/v1/snapshots/jammy-20260131/_route.json",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{test.object}}).WithCDN("https://repo.example/")
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(plan.PurgeURLs) != fmt.Sprint(test.wantPurges) {
				t.Fatalf("purge closure=%v want=%v", plan.PurgeURLs, test.wantPurges)
			}
			if len(test.wantPurges) == 2 {
				missingClean := plan
				missingClean.PurgeURLs = append([]string(nil), test.wantPurges[1:]...)
				if _, err := missingClean.Canonical(); err == nil || !strings.Contains(err.Error(), "purge set does not cover") {
					t.Fatalf("plan accepted missing clean-cache purge alias: %v", err)
				}
			}
			extra := plan
			extra.PurgeURLs = append(extra.PurgeURLs, "https://repo.example/.sow/arbitrary")
			if _, err := extra.Canonical(); err == nil || !strings.Contains(err.Error(), "not a planned pointer") {
				t.Fatalf("plan accepted arbitrary clean-cache purge expansion: %v", err)
			}
		})
	}
}

func TestYUMAliasPairPurgesBothClientAndCleanInternalKeys(t *testing.T) {
	t.Parallel()
	sha := hashString("repomd")
	root := ".sow/beta/yum/repo/repodata/repomd.xml"
	objects := []PlannedObject{
		{SourcePath: "repomd.xml", RemoteKey: root, Size: 7, SHA256: sha, Class: ObjectYUMAliasPointer, CDNPath: "yum/repo/repodata/repomd.xml"},
		{SourcePath: "repomd.xml.asc", RemoteKey: root + ".asc", Size: 7, SHA256: sha, Class: ObjectYUMAliasPointer, CDNPath: "yum/repo/repodata/repomd.xml.asc"},
	}
	plan, err := (Plan{Schema: planSchema, Objects: objects}).WithCDN("https://repo.example/")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://repo.example/.sow/beta/yum/repo/repodata/repomd.xml",
		"https://repo.example/.sow/beta/yum/repo/repodata/repomd.xml.asc",
		"https://repo.example/yum/repo/repodata/repomd.xml",
		"https://repo.example/yum/repo/repodata/repomd.xml.asc",
	}
	if fmt.Sprint(plan.PurgeURLs) != fmt.Sprint(want) {
		t.Fatalf("YUM alias purge closure=%v want=%v", plan.PurgeURLs, want)
	}
}

func TestCompatibilityRollbackS0ClassesCloseUnsignedPointerAndDeletion(t *testing.T) {
	t.Parallel()
	root := "yum/infra/x86_64/repodata/"
	metadataBody := "legacy-primary"
	pointerBody := "legacy-repomd"
	removedBody := "candidate-package"
	plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{
		{SourcePath: root + "legacy-primary.xml.gz", RemoteKey: root + "legacy-primary.xml.gz", Size: int64(len(metadataBody)), SHA256: hashString(metadataBody), Class: ObjectCompatibilityRollbackMetadata, CDNPath: root + "legacy-primary.xml.gz"},
		{SourcePath: root + "repomd.xml", RemoteKey: root + "repomd.xml", Size: int64(len(pointerBody)), SHA256: hashString(pointerBody), Class: ObjectCompatibilityRollbackPointer, CDNPath: root + "repomd.xml"},
	}, Deletes: []PlannedDelete{{
		Class: DeleteCompatibilityServing, SourcePath: "yum/infra/x86_64/Packages/p/pkg.rpm", RemoteKey: "yum/infra/x86_64/Packages/p/pkg.rpm",
		Size: int64(len(removedBody)), SHA256: hashString(removedBody), CDNPath: "yum/infra/x86_64/Packages/p/pkg.rpm",
	}}}).WithCDN("https://repo.example/")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Verify) != 2 || len(plan.VerifyAbsent) != 1 || len(plan.PurgeURLs) != 2 {
		t.Fatalf("rollback closure verify=%v absent=%v purge=%v", plan.Verify, plan.VerifyAbsent, plan.PurgeURLs)
	}
	wantPurge := map[string]bool{
		"https://repo.example/" + root + "repomd.xml":              false,
		"https://repo.example/yum/infra/x86_64/Packages/p/pkg.rpm": false,
	}
	for _, rawURL := range plan.PurgeURLs {
		if _, exists := wantPurge[rawURL]; exists {
			wantPurge[rawURL] = true
		}
	}
	for rawURL, found := range wantPurge {
		if !found {
			t.Fatalf("rollback purge omits %s: %v", rawURL, plan.PurgeURLs)
		}
	}

	withoutPointer := plan
	withoutPointer.Objects = withoutPointer.Objects[:1]
	withoutPointer.CDNBaseURL, withoutPointer.PurgeURLs, withoutPointer.Verify, withoutPointer.VerifyAbsent = "", nil, nil, nil
	if _, err := withoutPointer.Canonical(); err == nil || !strings.Contains(err.Error(), "requires the exact S0 repomd.xml") {
		t.Fatalf("rollback metadata without pointer passed: %v", err)
	}
	badPointer := Plan{Schema: planSchema, Objects: []PlannedObject{{
		SourcePath: root + "repomd.xml.asc", RemoteKey: root + "repomd.xml.asc", Size: 1, SHA256: hashString("x"), Class: ObjectCompatibilityRollbackPointer,
	}}}
	if _, err := badPointer.Canonical(); err == nil {
		t.Fatal("signed compatibility rollback pointer passed")
	}
}

func TestPlanAllowsOnlyEvidenceBoundAssetAndAPTByHashDeletes(t *testing.T) {
	t.Parallel()
	assetSHA := hashString("asset")
	byHashSHA := hashString("Packages")
	valid := []PlannedDelete{
		{Class: DeleteAssetServing, SourcePath: "pkg/tool", RemoteKey: "pkg/tool", Size: 5, SHA256: assetSHA, CDNPath: "pkg/tool"},
		{Class: DeleteAssetServing, SourcePath: ".sow/materialized/beta/pkg/tool", RemoteKey: ".sow/beta/pkg/tool", Size: 5, SHA256: assetSHA, CDNPath: "pkg/tool"},
		{Class: DeleteAssetServing, SourcePath: ".sow/origin/gated/pkg/tool", RemoteKey: ".sow/gated/pkg/tool", Size: 5, SHA256: assetSHA, CDNPath: "pro/v1/basic/pkg/tool"},
		{Class: DeleteAPTByHash, SourcePath: "apt/repo/dists/jammy/main/binary-amd64/by-hash/SHA256/" + byHashSHA, RemoteKey: "apt/repo/dists/jammy/main/binary-amd64/by-hash/SHA256/" + byHashSHA, Size: 8, SHA256: byHashSHA},
	}
	for _, deletion := range valid {
		plan, err := (Plan{Schema: planSchema, Deletes: []PlannedDelete{deletion}}).WithCDN("https://repo.example/")
		if err != nil {
			t.Fatalf("valid deletion rejected %#v: %v", deletion, err)
		}
		wantPurges := 0
		wantAbsent := 0
		if deletion.CDNPath != "" {
			wantPurges = 1
			wantAbsent = 1
			if strings.HasPrefix(deletion.RemoteKey, ".sow/") && deletion.RemoteKey != deletion.CDNPath {
				wantPurges++
			}
		}
		if len(plan.PurgeURLs) != wantPurges || len(plan.VerifyAbsent) != wantAbsent {
			t.Fatalf("delete purge/absence closure purges=%v absent=%v", plan.PurgeURLs, plan.VerifyAbsent)
		}
	}

	for _, deletion := range []PlannedDelete{
		{Class: DeleteAssetServing, SourcePath: "pkg/tool", RemoteKey: CheckpointKey, Size: 5, SHA256: assetSHA, CDNPath: "pkg/tool"},
		{Class: DeleteAssetServing, SourcePath: "objects/sha256/" + assetSHA, RemoteKey: "objects/sha256/" + assetSHA, Size: 5, SHA256: assetSHA, CDNPath: "objects/sha256/" + assetSHA},
		{Class: DeleteAssetServing, SourcePath: "yum/repo/Packages/tool.rpm", RemoteKey: "yum/repo/Packages/tool.rpm", Size: 5, SHA256: assetSHA, CDNPath: "yum/repo/Packages/tool.rpm"},
		{Class: DeleteAssetServing, SourcePath: ".sow/origin/gated/pkg/tool", RemoteKey: "pkg/tool", Size: 5, SHA256: assetSHA, CDNPath: "pro/v1/basic/pkg/tool"},
		{Class: DeleteAPTByHash, SourcePath: "apt/repo/dists/jammy/main/binary-amd64/by-hash/SHA256/" + byHashSHA, RemoteKey: "apt/repo/dists/jammy/main/binary-amd64/by-hash/SHA256/" + strings.Repeat("0", 64), Size: 8, SHA256: byHashSHA},
		{Class: DeleteAPTByHash, SourcePath: "apt/repo/dists/jammy/main/binary-amd64/by-hash/SHA256/" + byHashSHA, RemoteKey: "apt/repo/dists/jammy/main/binary-amd64/by-hash/SHA256/" + byHashSHA, Size: 8, SHA256: byHashSHA, CDNPath: "apt/repo/index"},
		{Class: DeleteClass("arbitrary"), SourcePath: "pkg/tool", RemoteKey: "pkg/tool", Size: 5, SHA256: assetSHA, CDNPath: "pkg/tool"},
	} {
		if _, err := (Plan{Schema: planSchema, Deletes: []PlannedDelete{deletion}}).WithCDN("https://repo.example/"); err == nil {
			t.Fatalf("unsafe deletion passed: %#v", deletion)
		}
	}
}

func TestDecodePlanKeepsLegacySnapshotDeleteEncodingCanonical(t *testing.T) {
	t.Parallel()
	legacy := `{"schema":"sow-publish-plan/v1","objects":null,"deletes":[{"remote_key":".sow/snapshots/jammy-20260131.json","cdn_path":"pro/v1/basic/_sow/v1/snapshots/jammy-20260131/_route.json"}],"removed":null,"purge_urls":null,"verify":null,"stats":{"Added":0,"Removed":0,"Changed":0}}`
	plan, err := DecodePlan([]byte(legacy))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Deletes[0].Class != "" {
		t.Fatalf("legacy delete class was rewritten: %#v", plan.Deletes[0])
	}
}

func TestRestoreIndexServingDeleteUnionRejectsPayloadsAndGatedPaths(t *testing.T) {
	sha := hashString("metadata")
	valid := []PlannedDelete{
		{Class: DeleteRestoreIndexServing, SourcePath: ".sow/materialized/beta/apt/repo/dists/jammy/InRelease", RemoteKey: ".sow/beta/apt/repo/dists/jammy/InRelease", Size: 8, SHA256: sha, CDNPath: "apt/repo/dists/jammy/InRelease"},
		{Class: DeleteRestoreIndexServing, SourcePath: "yum/repo/repodata/repomd.xml", RemoteKey: "yum/repo/repodata/repomd.xml", Size: 8, SHA256: sha, CDNPath: "yum/repo/repodata/repomd.xml"},
		{Class: DeleteRestoreIndexServing, SourcePath: "_sow/v1/mirrorlist/latest/repo/el10/x86_64.txt", RemoteKey: "_sow/v1/mirrorlist/latest/repo/el10/x86_64.txt", Size: 8, SHA256: sha, CDNPath: "_sow/v1/mirrorlist/latest/repo/el10/x86_64.txt"},
	}
	for _, deletion := range valid {
		if _, err := (Plan{Schema: planSchema, Deletes: []PlannedDelete{deletion}}).WithCDN("https://cdn.example/"); err != nil {
			t.Fatalf("valid deletion %#v: %v", deletion, err)
		}
	}
	invalid := []PlannedDelete{
		{Class: DeleteRestoreIndexServing, SourcePath: ".sow/materialized/beta/apt/repo/pool/main/p/pkg.deb", RemoteKey: ".sow/beta/apt/repo/pool/main/p/pkg.deb", Size: 8, SHA256: sha, CDNPath: "apt/repo/pool/main/p/pkg.deb"},
		{Class: DeleteRestoreIndexServing, SourcePath: "yum/repo/Packages/p/pkg.rpm", RemoteKey: "yum/repo/Packages/p/pkg.rpm", Size: 8, SHA256: sha, CDNPath: "yum/repo/Packages/p/pkg.rpm"},
		{Class: DeleteRestoreIndexServing, SourcePath: ".sow/origin/gated/apt/repo/dists/jammy/InRelease", RemoteKey: ".sow/gated/apt/repo/dists/jammy/InRelease", Size: 8, SHA256: sha, CDNPath: "pro/v1/basic/apt/repo/dists/jammy/InRelease"},
		{Class: DeleteRestoreIndexServing, SourcePath: "_sow/v1/mirrorlist/stable/repo/el10/x86_64.txt", RemoteKey: "_sow/v1/mirrorlist/stable/repo/el10/x86_64.txt", Size: 8, SHA256: sha, CDNPath: "_sow/v1/mirrorlist/stable/repo/el10/x86_64.txt"},
	}
	for _, deletion := range invalid {
		if _, err := (Plan{Schema: planSchema, Deletes: []PlannedDelete{deletion}}).WithCDN("https://cdn.example/"); err == nil {
			t.Fatalf("invalid restore deletion was accepted: %#v", deletion)
		}
	}
}

func TestPlanAllowsOneBoundedUnchangedCDNProbe(t *testing.T) {
	t.Parallel()
	probe := VerifyObject{URL: "https://repo.example/pkg/anchor", Size: 6, SHA256: hashString("anchor")}
	plan, err := (Plan{}).WithCDN("https://repo.example/")
	if err != nil {
		t.Fatal(err)
	}
	plan.Probes = []VerifyObject{probe}
	if _, err := plan.Canonical(); err != nil {
		t.Fatalf("bounded unchanged probe rejected: %v", err)
	}
	tooMany := plan
	tooMany.Probes = append(tooMany.Probes, VerifyObject{URL: "https://repo.example/pkg/second", Size: 1, SHA256: hashString("x")})
	if _, err := tooMany.Canonical(); err == nil || !strings.Contains(err.Error(), "at most one") {
		t.Fatalf("unbounded unchanged probes accepted: %v", err)
	}
	outside := plan
	outside.Probes[0].URL = "https://other.example/pkg/anchor"
	if _, err := outside.Canonical(); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("outside unchanged probe accepted: %v", err)
	}
}

func TestPlanRejectsMutableOrIncompleteYUMRepomdPair(t *testing.T) {
	t.Parallel()
	sha := hashString("repomd")
	mutable := Plan{Schema: planSchema, Objects: []PlannedObject{{
		SourcePath: "yum/repo/repodata/repomd.xml", RemoteKey: "yum/repo/repodata/repomd.xml",
		Size: 7, SHA256: sha, Class: ObjectPointer,
	}}}
	if _, err := mutable.Canonical(); err == nil || !strings.Contains(err.Error(), "never a mutable pointer") {
		t.Fatalf("mutable YUM repomd was not rejected: %v", err)
	}
	incomplete := Plan{Schema: planSchema, Objects: []PlannedObject{{
		SourcePath: "yum/repo/repodata/repomd.xml",
		RemoteKey:  ".sow/generations/00000000000000000001/yum/repo/repodata/repomd.xml",
		Size:       7, SHA256: sha, Class: ObjectMetadata,
	}}}
	if _, err := incomplete.Canonical(); err == nil || !strings.Contains(err.Error(), "complete xml+asc pair") {
		t.Fatalf("incomplete YUM repomd pair was not rejected: %v", err)
	}
	aliasMetadataOnly := Plan{Schema: planSchema, Objects: []PlannedObject{{
		SourcePath: "primary.xml.zst", RemoteKey: "yum/repo/repodata/primary.xml.zst",
		Size: 7, SHA256: sha, Class: ObjectYUMAliasMetadata,
	}}}
	if _, err := aliasMetadataOnly.Canonical(); err == nil || !strings.Contains(err.Error(), "requires a complete repomd.xml+asc") {
		t.Fatalf("orphan YUM alias metadata was not rejected: %v", err)
	}
}

func generationFixture(target TargetName, generation uint64) TargetGeneration {
	parent := generation - 1
	return TargetGeneration{
		Schema: TargetGenerationSchema, Target: target, Generation: generation, ParentGeneration: parent,
		DesiredCommit: strings.Repeat("a", 40), IntentView: "latest", ConfigSHA256: hashString("config"),
		Refs: []RefState{
			{Name: "refs/sow/views/latest/repo/el9/amd64", Commit: strings.Repeat("b", 40), ManifestSHA256: hashString("latest")},
			{Name: "refs/sow/views/stable/repo/el9/amd64", Commit: strings.Repeat("c", 40), ManifestSHA256: hashString("stable")},
		},
		ContentManifestSHA256: hashString("content"),
	}
}

func shaArray(value string) [sha256.Size]byte { return sha256.Sum256([]byte(value)) }

func hashString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", digest[:])
}

func manifestText(t *testing.T, entries ...manifest.Entry) string {
	t.Helper()
	var buffer bytes.Buffer
	for _, entry := range entries {
		if err := manifest.WriteEntry(&buffer, entry); err != nil {
			t.Fatal(err)
		}
	}
	return buffer.String()
}
