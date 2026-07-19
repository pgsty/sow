package publish

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/manifest"
)

type fixedSource string

func (s fixedSource) Open(string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(string(s))), nil
}

func TestSourceIsProvenBeforeObjectUpload(t *testing.T) {
	t.Parallel()
	remote := newFakeRemote()
	plan := Plan{Schema: planSchema, Objects: []PlannedObject{{
		SourcePath: "pool/a.pkg", RemoteKey: "pool/a.pkg", Size: 4,
		SHA256: hashString("good"), Class: ObjectImmutable,
	}}}
	plan, err := plan.WithCDN("https://cdn.test/")
	if err != nil {
		t.Fatal(err)
	}
	publisher := NewR2CloudflarePublisher(remote, fixedSource("evil"), filepath.Join(t.TempDir(), "journal"), Hooks{})
	_, err = publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, "prevalidate-source"))
	if err == nil || !strings.Contains(err.Error(), "changed after manifest planning") {
		t.Fatalf("raced source was not rejected before upload: %v", err)
	}
	if remote.putAttempts["pool/a.pkg"] != 0 || remote.get("pool/a.pkg").Exists {
		t.Fatal("unverified bytes reached a create-only remote key")
	}
}

func TestReservedControlKeysCannotBePlanned(t *testing.T) {
	t.Parallel()
	for _, key := range []string{
		CheckpointKey,
		".sow/locks/00000000000000000001.json",
		".sow/generations/00000000000000000001/generation.json",
	} {
		plan := Plan{Schema: planSchema, Objects: []PlannedObject{{
			SourcePath: "source", RemoteKey: key, Size: 1, SHA256: hashString("x"), Class: ObjectPointer,
		}}}
		if _, err := plan.Canonical(); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("control key %s was not reserved: %v", key, err)
		}
	}
}

func TestExecutionRejectsMissingCDNClosureBeforeRemoteLock(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	plan.CDNBaseURL = ""
	plan.PurgeURLs = nil
	plan.Verify = nil
	remote := newFakeRemote()
	publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{})
	_, err := publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, "missing-closure"))
	if err == nil || !strings.Contains(err.Error(), "verification for every changed object") {
		t.Fatalf("incomplete execution plan was accepted: %v", err)
	}
	if remote.putAttempts[CheckpointKey] != 0 {
		t.Fatal("remote lock was touched before plan closure validation")
	}
}

func TestJournalBindsParentAndStableRequestTime(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	remote := newFakeRemote()
	journalDir := filepath.Join(t.TempDir(), "journal")
	request := requestFixture(TargetCloudflare, plan, "intent-binding")
	first := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{AfterPhase: func(_ TargetName, phase Phase) error {
		if phase == PhasePlanned {
			return errors.New("stop at durable intent")
		}
		return nil
	}})
	if _, err := first.Run(context.Background(), request); err == nil {
		t.Fatal("fixture did not stop after intent")
	}
	request.UpdatedAt = request.UpdatedAt.Add(time.Nanosecond)
	second := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
	if _, err := second.Run(context.Background(), request); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("journal accepted a different checkpoint identity: %v", err)
	}
}

func TestCommittedCheckpointRepairsMissingGenerationDocument(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	remote := newFakeRemote()
	request := requestFixture(TargetCloudflare, plan, "generation-repair")
	first := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal-a"), Hooks{})
	if result, err := first.Run(context.Background(), request); err != nil || !result.RemoteRefReady {
		t.Fatalf("initial publish failed: %#v %v", result, err)
	}
	generationKey, _ := GenerationKey(1)
	remote.mutex.Lock()
	delete(remote.objects, generationKey)
	remote.mutex.Unlock()
	second := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal-b"), Hooks{})
	result, err := second.Run(context.Background(), request)
	if err != nil || !result.RemoteRefReady {
		t.Fatalf("checkpoint recovery did not repair generation: %#v %v", result, err)
	}
	if !remote.get(generationKey).Exists {
		t.Fatal("committed checkpoint was trusted without its immutable generation document")
	}
}

func TestInterruptedRecoveryReplaysClosureBeforePointer(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	remote := newFakeRemote()
	request := requestFixture(TargetCloudflare, plan, "replay-closure")
	journalDir := filepath.Join(t.TempDir(), "journal")
	first := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{AfterPhase: func(_ TargetName, phase Phase) error {
		if phase == PhasePointerFlipped {
			return errors.New("crash after public flip")
		}
		return nil
	}})
	if _, err := first.Run(context.Background(), request); err == nil {
		t.Fatal("fixture did not stop after pointer flip")
	}
	remote.mutex.Lock()
	delete(remote.objects, "pool/a.pkg")
	start := len(remote.putOrder)
	remote.mutex.Unlock()
	second := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
	if result, err := second.Run(context.Background(), request); err != nil || !result.RemoteRefReady {
		t.Fatalf("recovery did not repair closure: %#v %v", result, err)
	}
	remote.mutex.Lock()
	replayOrder := append([]string(nil), remote.putOrder[start:]...)
	remote.mutex.Unlock()
	position := func(key string) int {
		for index, value := range replayOrder {
			if value == key {
				return index
			}
		}
		return -1
	}
	if position("pool/a.pkg") < 0 || position("dists/jammy/InRelease") < 0 || position("pool/a.pkg") >= position("dists/jammy/InRelease") {
		t.Fatalf("recovery did not restore immutable closure before pointer: %v", replayOrder)
	}
}

func TestJournalPhaseCannotClaimMissingPlanObjects(t *testing.T) {
	t.Parallel()
	_, plan := sourcePlan(t)
	generationKey, _ := GenerationKey(1)
	journal := &publishJournal{
		Phase: PhasePointerFlipped, LockToken: `"lock"`,
		CompletedObjects: []string{"generation:" + generationKey},
	}
	if err := validateJournalPlan(journal, plan, generationKey); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("journal skipped required closure without conflict: %v", err)
	}
}

func TestJournalSymlinkIsRejectedBeforeRemoteMutation(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	journalDir := filepath.Join(t.TempDir(), "journal")
	if err := os.MkdirAll(journalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := requestFixture(TargetCloudflare, plan, "journal-symlink")
	journalPath := filepath.Join(journalDir, "cf-"+request.TransactionID+".json")
	if err := os.Symlink(outside, journalPath); err != nil {
		t.Fatal(err)
	}
	remote := newFakeRemote()
	publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
	if _, err := publisher.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "private regular file") {
		t.Fatalf("journal symlink was not rejected: %v", err)
	}
	if remote.putAttempts[CheckpointKey] != 0 {
		t.Fatal("remote checkpoint was touched after unsafe journal path")
	}
}

func TestAPTLegacyMetadataIsOrderedBeforeSoleInReleasePointer(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	byHashBody := "compressed-packages"
	byHashSHA := hashString(byHashBody)
	objects := []struct {
		source string
		remote string
		body   string
		class  ObjectClass
	}{
		{"stage/by-hash", "dists/jammy/main/binary-amd64/by-hash/SHA256/" + byHashSHA, byHashBody, ObjectImmutable},
		{"dists/jammy/main/binary-amd64/Packages.gz", "dists/jammy/main/binary-amd64/Packages.gz", byHashBody, ObjectLegacyMetadata},
		{"dists/jammy/Release", "dists/jammy/Release", "release", ObjectLegacyMetadata},
		{"dists/jammy/InRelease", "dists/jammy/InRelease", "signed-release", ObjectPointer},
	}
	plan := Plan{Schema: planSchema}
	for _, object := range objects {
		full := filepath.Join(root, filepath.FromSlash(object.source))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(object.body), 0o644); err != nil {
			t.Fatal(err)
		}
		plan.Objects = append(plan.Objects, PlannedObject{
			SourcePath: object.source, RemoteKey: object.remote, Size: int64(len(object.body)),
			SHA256: hashString(object.body), Class: object.class,
		})
	}
	plan, err := plan.WithCDN("https://cdn.test/")
	if err != nil {
		t.Fatal(err)
	}
	remote := newFakeRemote()
	publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{})
	if _, err := publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, "apt-order")); err != nil {
		t.Fatal(err)
	}
	position := func(key string) int {
		for index, value := range remote.putOrder {
			if value == key {
				return index
			}
		}
		return -1
	}
	pointer := position("dists/jammy/InRelease")
	for _, key := range []string{
		"dists/jammy/main/binary-amd64/by-hash/SHA256/" + byHashSHA,
		"dists/jammy/main/binary-amd64/Packages.gz",
		"dists/jammy/Release",
	} {
		if current := position(key); current < 0 || pointer < 0 || current >= pointer {
			t.Fatalf("APT closure was not installed before InRelease: %s=%d pointer=%d order=%v", key, current, pointer, remote.putOrder)
		}
	}
	if got := remote.purgeCalls; len(got) != 1 || len(got[0]) != 1 || !strings.HasSuffix(got[0][0], "/dists/jammy/InRelease") {
		t.Fatalf("APT purge set was not the sole final pointer: %v", got)
	}
}

func TestAPTClassificationFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		objects []PlannedObject
	}{
		{name: "inrelease-create-only", objects: []PlannedObject{{SourcePath: "x", RemoteKey: "dists/jammy/InRelease", Size: 1, SHA256: hashString("x"), Class: ObjectMetadata}}},
		{name: "packages-create-only", objects: []PlannedObject{{SourcePath: "x", RemoteKey: "dists/jammy/main/binary-amd64/Packages.gz", Size: 1, SHA256: hashString("x"), Class: ObjectMetadata}}},
		{name: "legacy-without-pointer", objects: []PlannedObject{{SourcePath: "x", RemoteKey: "dists/jammy/Release", Size: 1, SHA256: hashString("x"), Class: ObjectLegacyMetadata}}},
		{name: "by-hash-name-mismatch", objects: []PlannedObject{{SourcePath: "x", RemoteKey: "dists/jammy/main/binary-amd64/by-hash/SHA256/" + hashString("other"), Size: 1, SHA256: hashString("x"), Class: ObjectImmutable}}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := (Plan{Schema: planSchema, Objects: test.objects}).Canonical(); err == nil {
				t.Fatal("unsafe APT plan was accepted")
			}
		})
	}
}

func TestAPTGenerationArchiveUsesImmutableMetadataWithoutBecomingThePointer(t *testing.T) {
	archive := PlannedObject{
		SourcePath: "apt/infra/dists/bookworm/InRelease",
		RemoteKey:  ".sow/generations/00000000000000000001/apt/apt/infra/dists/bookworm/InRelease",
		Size:       1, SHA256: hashString("x")[:64], Class: ObjectMetadata,
		CDNPath: "_sow/v1/a/00000000000000000001/apt/infra/dists/bookworm/InRelease",
	}
	if _, err := (Plan{Schema: planSchema, Objects: []PlannedObject{archive}}).WithCDN("https://repo.test/"); err != nil {
		t.Fatalf("immutable APT generation archive rejected: %v", err)
	}
	archive.Class = ObjectPointer
	if _, err := (Plan{Schema: planSchema, Objects: []PlannedObject{archive}}).WithCDN("https://repo.test/"); err == nil {
		t.Fatal("APT generation archive accepted as mutable pointer")
	}
}

func TestChangedAssetIdentityRequiresExplicitMutableOrContentAddressedPlan(t *testing.T) {
	t.Parallel()
	oldManifest := manifestText(t, manifest.Entry{Path: "bin/tool", Size: 3, SHA256: shaArray("old")})
	newManifest := manifestText(t, manifest.Entry{Path: "bin/tool", Size: 3, SHA256: shaArray("new")})
	_, err := BuildPlan(bytes.NewBufferString(oldManifest), bytes.NewBufferString(newManifest), IdentityClassifier)
	if err == nil || !strings.Contains(err.Error(), "explicit pointer") {
		t.Fatalf("asset replacement was misclassified as create-only: %v", err)
	}
}

func TestPrivateRemoteKeysUseExplicitPublicCDNRoutes(t *testing.T) {
	t.Parallel()
	generation := "00000000000000000007"
	yum := PlannedObject{
		SourcePath: "repodata/primary.xml.zst",
		RemoteKey:  ".sow/generations/" + generation + "/yum/yum/pgsql/el9/x86_64/repodata/primary.xml.zst",
		Size:       1, SHA256: hashString("x"), Class: ObjectMetadata,
	}
	gated := PlannedObject{
		SourcePath: "private.pkg", RemoteKey: ".sow/gated/pkg/private.pkg",
		Size: 1, SHA256: hashString("x"), Class: ObjectImmutable, CDNPath: "pro/v1/basic/pkg/private.pkg",
	}
	channelBody := "https://cdn.test/pro/v1/basic/_sow/v1/g/" + generation + "/yum/pgsql/el9/x86_64/\n"
	channel := PlannedObject{
		SourcePath: "channel.json", RemoteKey: ".sow/channels/stable/pgsql/el9/x86_64.json",
		Size: 1, SHA256: hashString("x"), Class: ObjectPointer,
		CDNPath:          "pro/v1/basic/_sow/v1/mirrorlist/stable/pgsql/el9/x86_64.txt",
		VerificationSize: int64(len(channelBody)), VerificationSHA256: hashString(channelBody),
	}
	plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{yum, gated, channel}}).WithCDN("https://cdn.test/")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"https://cdn.test/_sow/v1/g/" + generation + "/yum/pgsql/el9/x86_64/repodata/primary.xml.zst": false,
		"https://cdn.test/pro/v1/basic/pkg/private.pkg":                                               false,
		"https://cdn.test/pro/v1/basic/_sow/v1/mirrorlist/stable/pgsql/el9/x86_64.txt":                false,
	}
	for _, verification := range plan.Verify {
		if _, exists := want[verification.URL]; !exists {
			t.Fatalf("private remote key leaked into public verification URL: %s", verification.URL)
		}
		want[verification.URL] = true
	}
	for value, seen := range want {
		if !seen {
			t.Fatalf("missing public verification route %s", value)
		}
	}
	wantPurge := []string{
		"https://cdn.test/.sow/channels/stable/pgsql/el9/x86_64.json",
		"https://cdn.test/pro/v1/basic/_sow/v1/mirrorlist/stable/pgsql/el9/x86_64.txt",
	}
	if fmt.Sprint(plan.PurgeURLs) != fmt.Sprint(wantPurge) {
		t.Fatalf("channel purge omitted a client or clean-cache key: got %v want %v", plan.PurgeURLs, wantPurge)
	}
	unsafeChannel := channel
	unsafeChannel.CDNPath = ""
	unsafeChannel.VerificationSHA256 = ""
	unsafeChannel.VerificationSize = 0
	if _, err := (Plan{Schema: planSchema, Objects: []PlannedObject{unsafeChannel}}).WithCDN("https://cdn.test/"); err == nil {
		t.Fatal("transformed channel pointer was accepted without an explicit verification contract")
	}
}

func TestStableYUMMetadataCannotUsePublicGenerationNamespace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	const source = "repodata/primary.xml.zst"
	full := filepath.Join(root, filepath.FromSlash(source))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	object := PlannedObject{
		SourcePath: source,
		RemoteKey:  ".sow/generations/00000000000000000001/yum/yum/pgsql/el9/x86_64/repodata/primary.xml.zst",
		Size:       1, SHA256: hashString("x"), Class: ObjectMetadata,
	}
	plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{object}}).WithCDN("https://cdn.test/pro/v1/basic/")
	if err != nil {
		t.Fatal(err)
	}
	remote := newFakeRemote()
	publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{})
	request := requestFixture(TargetCloudflare, plan, "stable-public-generation")
	request.Generation.IntentView = "stable"
	_, err = publisher.Run(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "gated generation namespace") {
		t.Fatalf("stable metadata was allowed in public generation namespace: %v", err)
	}
	if remote.putAttempts[CheckpointKey] != 0 {
		t.Fatal("remote lock was touched before stable confidentiality validation")
	}
	object.RemoteKey = ".sow/gated/generations/00000000000000000001/yum/yum/pgsql/el9/x86_64/repodata/primary.xml.zst"
	object.CDNPath = "pro/v1/basic/_sow/v1/g/00000000000000000001/yum/pgsql/el9/x86_64/repodata/primary.xml.zst"
	gatedPlan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{object}}).WithCDN("https://cdn.test/")
	if err != nil {
		t.Fatalf("gated stable generation was rejected: %v", err)
	}
	if got := gatedPlan.Verify[0].URL; got != "https://cdn.test/pro/v1/basic/_sow/v1/g/00000000000000000001/yum/pgsql/el9/x86_64/repodata/primary.xml.zst" {
		t.Fatalf("gated generation mapped to wrong edge route: %s", got)
	}
}

func TestLatestGenerationMayRetainHistoricalStableRefs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	const source = "payload.bin"
	full := filepath.Join(root, filepath.FromSlash(source))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	object := PlannedObject{
		SourcePath: source,
		RemoteKey:  "objects/sha256/" + hashString("x"),
		Size:       1, SHA256: hashString("x"), Class: ObjectImmutable,
	}
	plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{object}}).WithCDN("https://cdn.test/")
	if err != nil {
		t.Fatal(err)
	}
	request := requestFixture(TargetCloudflare, plan, "latest-retains-stable-ref")
	// generationFixture intentionally contains both latest and historical
	// stable refs. The exact current intent remains latest.
	remote := newFakeRemote()
	publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{})
	if _, err := publisher.Run(context.Background(), request); err != nil {
		t.Fatalf("latest intent was inferred as stable from its cumulative ref vector: %v", err)
	}
}

func TestPublishRequestBindsChannelTransformationAndSnapshotRouteIntent(t *testing.T) {
	t.Parallel()
	t.Run("channel transformed verification", func(t *testing.T) {
		channel := ChannelState{
			View: "stable", Repo: "repo", OS: "el10", Arch: "x86_64", Generation: 1,
			RemoteKey: ".sow/channels/stable/repo/el10/x86_64.json", LegacyRoot: "yum/repo/x86_64",
		}
		body, err := channel.CanonicalBody()
		if err != nil {
			t.Fatal(err)
		}
		channel.BodySHA256 = digestBytes(body)
		plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{{
			SourcePath: "channel.json", RemoteKey: channel.RemoteKey, Size: int64(len(body)), SHA256: digestBytes(body), Class: ObjectPointer,
			CDNPath:          "pro/v1/basic/_sow/v1/mirrorlist/stable/repo/el10/x86_64.txt",
			VerificationSize: 5, VerificationSHA256: hashString("stale"),
		}}}).WithCDN("https://cdn.test/")
		if err != nil {
			t.Fatal(err)
		}
		request := requestFixture(TargetCloudflare, plan, "unbound-channel-verification")
		request.Generation.IntentView = "stable"
		request.Generation.Channels = []ChannelState{channel}
		remote := newFakeRemote()
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "unbound transformed verification") {
			t.Fatalf("forged channel verification was accepted: %v", err)
		}
		if remote.putAttempts[CheckpointKey] != 0 {
			t.Fatal("forged channel plan touched remote state")
		}
	})

	t.Run("snapshot route intent", func(t *testing.T) {
		body := []byte(`{"schema":"sow-snapshot-route/v1","snapshot":"jammy-20260131","generation":"00000000000000000001"}`)
		plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{{
			SourcePath: "route.json", RemoteKey: ".sow/snapshots/jammy-20260131.json", Size: int64(len(body)), SHA256: digestBytes(body), Class: ObjectPointer,
			CDNPath: "pro/v1/basic/_sow/v1/snapshots/jammy-20260131/_route.json",
		}}}).WithCDN("https://cdn.test/")
		if err != nil {
			t.Fatal(err)
		}
		request := requestFixture(TargetCloudflare, plan, "mismatched-snapshot-route")
		request.Generation.IntentView, request.Generation.IntentSnapshot = "snapshot", "jammy-20260201"
		remote := newFakeRemote()
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "differs from intent") {
			t.Fatalf("mismatched snapshot route was accepted: %v", err)
		}
		if remote.putAttempts[CheckpointKey] != 0 {
			t.Fatal("mismatched snapshot plan touched remote state")
		}
	})

	t.Run("snapshot route body generation", func(t *testing.T) {
		body := []byte(`{"schema":"sow-snapshot-route/v1","snapshot":"jammy-20260131","generation":"00000000000000000002"}`)
		plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{{
			SourcePath: "route.json", RemoteKey: ".sow/snapshots/jammy-20260131.json", Size: int64(len(body)), SHA256: digestBytes(body), Class: ObjectPointer,
			CDNPath: "pro/v1/basic/_sow/v1/snapshots/jammy-20260131/_route.json",
		}}}).WithCDN("https://cdn.test/")
		if err != nil {
			t.Fatal(err)
		}
		request := requestFixture(TargetCloudflare, plan, "forged-snapshot-route-body")
		request.Generation.IntentView, request.Generation.IntentSnapshot = "snapshot", "jammy-20260131"
		remote := newFakeRemote()
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "canonical intent body") {
			t.Fatalf("snapshot route pointing at another generation was accepted: %v", err)
		}
		if remote.putAttempts[CheckpointKey] != 0 {
			t.Fatal("forged snapshot route body touched remote state")
		}
	})

	t.Run("APT generation ownership", func(t *testing.T) {
		body := []byte("inrelease")
		plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{{
			SourcePath: "apt/repo/dists/jammy/InRelease",
			RemoteKey:  ".sow/generations/00000000000000000002/apt/apt/repo/dists/jammy/InRelease",
			Size:       int64(len(body)), SHA256: digestBytes(body), Class: ObjectMetadata,
			CDNPath: "_sow/v1/a/00000000000000000002/apt/repo/dists/jammy/InRelease",
		}}}).WithCDN("https://cdn.test/")
		if err != nil {
			t.Fatal(err)
		}
		request := requestFixture(TargetCloudflare, plan, "foreign-apt-generation")
		remote := newFakeRemote()
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "APT metadata key") {
			t.Fatalf("foreign APT generation key was accepted: %v", err)
		}
		if remote.putAttempts[CheckpointKey] != 0 {
			t.Fatal("foreign APT generation touched remote state")
		}
	})
}

func TestPublishRequestBindsEveryDeletionToIntentAndRefs(t *testing.T) {
	t.Parallel()
	t.Run("serving view", func(t *testing.T) {
		plan, err := (Plan{Schema: planSchema, Deletes: []PlannedDelete{{
			Class: DeleteAssetServing, SourcePath: ".sow/materialized/beta/pkg/latest", RemoteKey: ".sow/beta/pkg/latest",
			Size: 7, SHA256: hashString("payload"), CDNPath: "pkg/latest",
		}}}).WithCDN("https://cdn.test/")
		if err != nil {
			t.Fatal(err)
		}
		request := requestFixture(TargetCloudflare, plan, "cross-intent-delete")
		remote := newFakeRemote()
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "belongs to beta, not publication intent latest") {
			t.Fatalf("latest request accepted beta deletion: %v", err)
		}
		if remote.putAttempts[CheckpointKey] != 0 {
			t.Fatal("cross-intent deletion touched remote state")
		}
	})

	t.Run("retained snapshot", func(t *testing.T) {
		const snapshotID = "jammy-20260131"
		plan, err := (Plan{Schema: planSchema, Deletes: []PlannedDelete{{
			Class: DeleteSnapshotOwned, SourcePath: ".sow/snapshots/" + snapshotID + ".json", RemoteKey: ".sow/snapshots/" + snapshotID + ".json",
			Size: 5, SHA256: hashString("route"), CDNPath: "pro/v1/basic/_sow/v1/snapshots/" + snapshotID + "/_route.json",
		}}}).WithCDN("https://cdn.test/")
		if err != nil {
			t.Fatal(err)
		}
		request := requestFixture(TargetCloudflare, plan, "retained-snapshot-delete")
		request.Generation.Refs = append(request.Generation.Refs, RefState{
			Name: "refs/sow/snapshots/" + snapshotID + "/repo/el9/amd64", Commit: strings.Repeat("d", 40), ManifestSHA256: hashString("snapshot"),
		})
		remote := newFakeRemote()
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "remains reachable") {
			t.Fatalf("retained snapshot deletion was accepted: %v", err)
		}
		if remote.putAttempts[CheckpointKey] != 0 {
			t.Fatal("retained snapshot deletion touched remote state")
		}
	})
}

func TestSnapshotPayloadNamespaceRejectsMutablePointers(t *testing.T) {
	t.Parallel()
	_, err := (Plan{Schema: planSchema, Objects: []PlannedObject{{
		SourcePath: "pkg/latest", RemoteKey: ".sow/gated/snapshots/jammy-20260131/asset/pkg/latest",
		Size: 7, SHA256: hashString("payload"), Class: ObjectPointer,
		CDNPath: "pro/v1/basic/_sow/v1/snapshots/jammy-20260131/assets/pkg/latest",
	}}}).WithCDN("https://cdn.test/")
	if err == nil || !strings.Contains(err.Error(), "must be create-only") {
		t.Fatalf("mutable snapshot payload pointer was accepted: %v", err)
	}
}

func TestSnapshotYUMPayloadRequiresCompleteMetadataLeaf(t *testing.T) {
	t.Parallel()
	const snapshotID = "jammy-20260712"
	routeBody, err := SnapshotRouteBody(snapshotID, 1)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{
		{
			SourcePath: "route.json", RemoteKey: ".sow/snapshots/" + snapshotID + ".json",
			Size: int64(len(routeBody)), SHA256: digestBytes(routeBody), Class: ObjectPointer,
			CDNPath: "pro/v1/basic/_sow/v1/snapshots/" + snapshotID + "/_route.json",
		},
		{
			SourcePath: "pkg.rpm", RemoteKey: ".sow/gated/snapshots/" + snapshotID + "/yum/yum/repo/Packages/p/pkg.rpm",
			Size: 3, SHA256: hashString("rpm"), Class: ObjectImmutable,
			CDNPath: "pro/v1/basic/_sow/v1/snapshots/" + snapshotID + "/yum/yum/repo/Packages/p/pkg.rpm",
		},
	}}).WithCDN("https://cdn.test/")
	if err != nil {
		t.Fatal(err)
	}
	request := requestFixture(TargetCloudflare, plan, "snapshot-yum-without-metadata")
	request.Generation.IntentView, request.Generation.IntentSnapshot = "snapshot", snapshotID
	remote := newFakeRemote()
	publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
	if _, err := publisher.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "no complete generation metadata") {
		t.Fatalf("snapshot YUM package-only plan was accepted: %v", err)
	}
	if remote.putAttempts[CheckpointKey] != 0 {
		t.Fatal("snapshot package-only plan touched remote state")
	}
}

func TestYUMAliasClosureUsesLinearIndexesAcrossThousandsOfLeaves(t *testing.T) {
	const leaves = 2000
	const generationID = "00000000000000000001"
	plan := Plan{Schema: planSchema, CDNBaseURL: "https://cdn.test/"}
	generation := TargetGeneration{Generation: 1, IntentView: "latest"}
	for index := 0; index < leaves; index++ {
		repo := fmt.Sprintf("repo%04d", index)
		legacyRoot := "yum/" + repo + "/el9/x86_64"
		channel := ChannelState{
			View: "latest", Repo: repo, OS: "el9", Arch: "x86_64", Generation: 1,
			RemoteKey: ".sow/channels/latest/" + repo + "/el9/x86_64.json", LegacyRoot: legacyRoot,
		}
		channelBody, err := channel.CanonicalBody()
		if err != nil {
			t.Fatal(err)
		}
		channel.BodySHA256 = digestBytes(channelBody)
		generation.Channels = append(generation.Channels, channel)

		for _, name := range []string{"primary.xml.zst", "filelists.xml.zst", "other.xml.zst", "repomd.xml", "repomd.xml.asc"} {
			body := repo + ":" + name
			generationKey := ".sow/generations/" + generationID + "/yum/" + legacyRoot + "/repodata/" + name
			aliasKey := legacyRoot + "/repodata/" + name
			aliasClass := ObjectYUMAliasMetadata
			if name == "repomd.xml" || name == "repomd.xml.asc" {
				aliasClass = ObjectYUMAliasPointer
			}
			plan.Objects = append(plan.Objects,
				PlannedObject{RemoteKey: generationKey, Size: int64(len(body)), SHA256: hashString(body), Class: ObjectMetadata},
				PlannedObject{RemoteKey: aliasKey, Size: int64(len(body)), SHA256: hashString(body), Class: aliasClass},
			)
		}
		mirrorBody := "https://cdn.test/_sow/v1/g/" + generationID + "/" + legacyRoot + "/\n"
		pointerKey, _, err := YUMChannelPointer(plan.CDNBaseURL, channel)
		if err != nil {
			t.Fatal(err)
		}
		plan.Objects = append(plan.Objects, PlannedObject{
			RemoteKey: pointerKey, Size: int64(len(mirrorBody)), SHA256: hashString(mirrorBody), Class: ObjectPointer,
		})
	}
	started := time.Now()
	if err := validateYUMAliasAtomicRoutes(generation, plan); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("linear YUM closure validation took %s for %d leaves", elapsed, leaves)
	}
}

func TestCOSVersioningCapabilityFailurePrecedesCheckpointRead(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	remote := newFakeRemote()
	remote.probeErr = ErrCapability
	publisher := NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{})
	_, err := publisher.Run(context.Background(), requestFixture(TargetTencent, plan, "cos-probe"))
	if !errors.Is(err, ErrCapability) {
		t.Fatalf("unsafe COS bucket was not rejected: %v", err)
	}
	if remote.putAttempts[CheckpointKey] != 0 {
		t.Fatal("COS checkpoint was touched before the lock capability probe")
	}
}
