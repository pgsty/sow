package publish

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRecoverySource(t *testing.T, root, name string, body []byte) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func recoveryPublisher(target TargetName, remote *fakeRemote, root, journalDir string, hooks Hooks) *Publisher {
	if target == TargetTencent {
		return NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, journalDir, hooks)
	}
	return NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, hooks)
}

func TestInterruptedCreateOnlyStageRevalidatesCompletedSiblingBeforePointerFlip(t *testing.T) {
	for _, class := range []ObjectClass{ObjectImmutable, ObjectReuseImmutable, ObjectMetadata} {
		class := class
		for _, target := range []TargetName{TargetCloudflare, TargetTencent} {
			t.Run(string(class)+"-"+string(target), func(t *testing.T) {
				root := t.TempDir()
				prefix := strings.ReplaceAll(string(class), "-", "/")
				firstKey := prefix + "/a.bin"
				secondKey := prefix + "/b.bin"
				pointerKey := "current/" + string(class) + ".txt"
				firstBody := []byte("first-" + string(class))
				secondBody := []byte("second-" + string(class))
				pointerBody := []byte("ready-" + string(class))
				writeRecoverySource(t, root, firstKey, firstBody)
				writeRecoverySource(t, root, secondKey, secondBody)
				writeRecoverySource(t, root, pointerKey, pointerBody)

				plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{
					{SourcePath: firstKey, RemoteKey: firstKey, Size: int64(len(firstBody)), SHA256: digestBytes(firstBody), Class: class},
					{SourcePath: secondKey, RemoteKey: secondKey, Size: int64(len(secondBody)), SHA256: digestBytes(secondBody), Class: class},
					{SourcePath: pointerKey, RemoteKey: pointerKey, Size: int64(len(pointerBody)), SHA256: digestBytes(pointerBody), Class: ObjectPointer},
				}}).WithCDN("https://cdn.test/")
				if err != nil {
					t.Fatal(err)
				}

				remote := newFakeRemote()
				remote.failAfterPutKey = secondKey
				journalDir := filepath.Join(t.TempDir(), "journal")
				request := requestFixture(target, plan, "partial-"+string(class)+"-"+string(target))
				first := recoveryPublisher(target, remote, root, journalDir, Hooks{}).WithWorkers(1)
				result, err := first.Run(context.Background(), request)
				if err == nil || !strings.Contains(err.Error(), "response loss") {
					t.Fatalf("first run result=%#v err=%v", result, err)
				}
				journalBytes, err := readJournalFile(result.JournalPath)
				if err != nil {
					t.Fatal(err)
				}
				journal, err := decodeJournal(journalBytes)
				if err != nil {
					t.Fatal(err)
				}
				identity := string(class) + ":" + firstKey
				if !journalHas(&journal, identity) {
					t.Fatalf("sibling success was not journaled: %v", journal.CompletedObjects)
				}

				remote.mutex.Lock()
				remote.objects[firstKey] = fakeObject{
					body: bytes.Repeat([]byte("x"), len(firstBody)),
					sha:  digestBytes(firstBody),
					etag: `"forged-completed"`,
				}
				remote.mutex.Unlock()

				second := recoveryPublisher(target, remote, root, journalDir, Hooks{}).WithWorkers(1)
				result, err = second.Run(context.Background(), request)
				if err == nil || !errors.Is(err, ErrConflict) || result.RemoteRefReady {
					t.Fatalf("resume result=%#v err=%v", result, err)
				}
				if remote.get(pointerKey).Exists || remote.putAttempts[pointerKey] != 0 {
					t.Fatalf("pointer advanced before completed %s was revalidated: object=%#v puts=%d", class, remote.get(pointerKey), remote.putAttempts[pointerKey])
				}
				if remote.objectOpens[firstKey] == 0 {
					t.Fatalf("completed %s was trusted without a streamed origin proof", class)
				}
			})
		}
	}
}

type failAfterCopyRemote struct {
	*fakeRemote
	failKey string
	failed  bool
}

func (f *failAfterCopyRemote) copyThenLoseResponse(destinationKey, sourceKey string, size int64, sha, sourceETag string) (string, error) {
	etag, err := f.fakeRemote.copy(destinationKey, sourceKey, size, sha, sourceETag)
	if err == nil && destinationKey == f.failKey && !f.failed {
		f.failed = true
		return "", errors.New("injected response loss after remote copy")
	}
	return etag, err
}

func (f *failAfterCopyRemote) R2Copy(_ context.Context, destinationKey, sourceKey string, size int64, sha, sourceETag string) (string, error) {
	return f.copyThenLoseResponse(destinationKey, sourceKey, size, sha, sourceETag)
}

func (f *failAfterCopyRemote) COSCopy(_ context.Context, destinationKey, sourceKey string, size int64, sha, sourceETag string) (string, error) {
	return f.copyThenLoseResponse(destinationKey, sourceKey, size, sha, sourceETag)
}

func copyRecoveryPublisher(target TargetName, remote *failAfterCopyRemote, root, journalDir string) *Publisher {
	if target == TargetTencent {
		return NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
	}
	return NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
}

func TestInterruptedCopyStageRevalidatesCompletedDestinationWithBoundedSourceProof(t *testing.T) {
	const snapshot = "jammy-20260712"
	const pointerKey = ".sow/snapshots/jammy-20260712.json"
	for _, target := range []TargetName{TargetCloudflare, TargetTencent} {
		t.Run(string(target), func(t *testing.T) {
			root := t.TempDir()
			sourceA := "yum/repo/Packages/a.rpm"
			sourceB := "yum/repo/Packages/b.rpm"
			destinationA := ".sow/gated/snapshots/" + snapshot + "/yum/yum/repo/Packages/a.rpm"
			destinationB := ".sow/gated/snapshots/" + snapshot + "/yum/yum/repo/Packages/b.rpm"
			bodyA := []byte("rpm-copy-a")
			bodyB := []byte("rpm-copy-b")
			routeBody, err := SnapshotRouteBody(snapshot, 1)
			if err != nil {
				t.Fatal(err)
			}
			writeRecoverySource(t, root, sourceA, bodyA)
			writeRecoverySource(t, root, sourceB, bodyB)
			writeRecoverySource(t, root, "route.json", routeBody)
			plan := Plan{Schema: planSchema, Objects: []PlannedObject{
				{
					SourcePath: sourceA, RemoteKey: destinationA, CopySource: sourceA,
					Size: int64(len(bodyA)), SHA256: digestBytes(bodyA), Class: ObjectCopyImmutable,
					CDNPath: "pro/v1/basic/_sow/v1/snapshots/" + snapshot + "/yum/yum/repo/Packages/a.rpm",
				},
				{
					SourcePath: sourceB, RemoteKey: destinationB, CopySource: sourceB,
					Size: int64(len(bodyB)), SHA256: digestBytes(bodyB), Class: ObjectCopyImmutable,
					CDNPath: "pro/v1/basic/_sow/v1/snapshots/" + snapshot + "/yum/yum/repo/Packages/b.rpm",
				},
				{
					SourcePath: "route.json", RemoteKey: pointerKey,
					Size: int64(len(routeBody)), SHA256: digestBytes(routeBody), Class: ObjectPointer,
					CDNPath: "pro/v1/basic/_sow/v1/snapshots/" + snapshot + "/_route.json",
				},
			}}
			for _, name := range []string{"primary.xml.zst", "filelists.xml.zst", "other.xml.zst", "repomd.xml", "repomd.xml.asc"} {
				metadataBody := []byte("snapshot-" + name)
				source := "generated/" + name
				writeRecoverySource(t, root, source, metadataBody)
				plan.Objects = append(plan.Objects, PlannedObject{
					SourcePath: source,
					RemoteKey:  ".sow/gated/generations/00000000000000000001/yum/yum/repo/repodata/" + name,
					Size:       int64(len(metadataBody)), SHA256: digestBytes(metadataBody), Class: ObjectMetadata,
					CDNPath: "pro/v1/basic/_sow/v1/snapshots/" + snapshot + "/yum/yum/repo/repodata/" + name,
				})
			}
			plan, err = plan.WithCDN("https://cdn.test/")
			if err != nil {
				t.Fatal(err)
			}
			copyRequest := func(transactionID string) Request {
				request := requestFixture(target, plan, transactionID)
				request.Generation.IntentView = "snapshot"
				request.Generation.IntentSnapshot = snapshot
				return request
			}

			t.Run("forged-source-metadata", func(t *testing.T) {
				remote := newFakeRemote()
				remote.objects[sourceA] = fakeObject{
					body: bytes.Repeat([]byte("x"), len(bodyA)), sha: digestBytes(bodyA), etag: `"forged-source-a"`,
				}
				remote.objects[sourceB] = fakeObject{body: append([]byte(nil), bodyB...), sha: digestBytes(bodyB), etag: `"source-b"`}
				journalDir := filepath.Join(t.TempDir(), "journal")
				publisher := recoveryPublisher(target, remote, root, journalDir, Hooks{}).WithWorkers(1)
				result, err := publisher.Run(context.Background(), copyRequest("forged-copy-source-"+string(target)))
				if err != nil || !result.RemoteRefReady {
					t.Fatalf("result=%#v err=%v", result, err)
				}
				if remote.objectOpens[sourceA] != 1 || remote.objectOpens[destinationA] != 0 {
					t.Fatalf("source/destination streamed GETs=%d/%d, want one pre-copy source proof and no failed destination", remote.objectOpens[sourceA], remote.objectOpens[destinationA])
				}
				if remote.copyAttempts[destinationA] != 0 {
					t.Fatalf("forged source reached CopyObject: attempts=%d", remote.copyAttempts[destinationA])
				}
				destination := remote.get(destinationA)
				if !destination.Exists || !bytes.Equal(destination.Body, bodyA) || remote.putAttempts[destinationA] == 0 {
					t.Fatalf("failed copy did not cleanly fall back to authenticated local PUT: destination=%#v puts=%d", destination, remote.putAttempts[destinationA])
				}
			})

			base := newFakeRemote()
			base.objects[sourceA] = fakeObject{body: append([]byte(nil), bodyA...), sha: digestBytes(bodyA), etag: `"source-a"`}
			base.objects[sourceB] = fakeObject{body: append([]byte(nil), bodyB...), sha: digestBytes(bodyB), etag: `"source-b"`}
			remote := &failAfterCopyRemote{fakeRemote: base, failKey: destinationB}
			journalDir := filepath.Join(t.TempDir(), "journal")
			request := copyRequest("partial-copy-" + string(target))
			first := copyRecoveryPublisher(target, remote, root, journalDir).WithWorkers(1)
			result, err := first.Run(context.Background(), request)
			if err == nil || !strings.Contains(err.Error(), "response loss after remote copy") {
				t.Fatalf("first run result=%#v err=%v", result, err)
			}
			journalBytes, err := readJournalFile(result.JournalPath)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := decodeJournal(journalBytes)
			if err != nil {
				t.Fatal(err)
			}
			if !journalHas(&journal, string(ObjectCopyImmutable)+":"+destinationA) {
				t.Fatalf("completed copy was not journaled: %v", journal.CompletedObjects)
			}

			base.mutex.Lock()
			base.objects[destinationA] = fakeObject{
				body: bytes.Repeat([]byte("x"), len(bodyA)), sha: digestBytes(bodyA), etag: `"forged-copy-a"`,
			}
			// The failed sibling is independently repaired so only the forged
			// completed destination can block recovery.
			base.objects[destinationB] = fakeObject{body: append([]byte(nil), bodyB...), sha: digestBytes(bodyB), etag: `"repaired-copy-b"`}
			base.mutex.Unlock()

			second := recoveryPublisher(target, base, root, journalDir, Hooks{}).WithWorkers(1)
			result, err = second.Run(context.Background(), request)
			if err == nil || !errors.Is(err, ErrConflict) || result.RemoteRefReady {
				t.Fatalf("resume result=%#v err=%v", result, err)
			}
			if base.get(pointerKey).Exists || base.putAttempts[pointerKey] != 0 {
				t.Fatalf("snapshot pointer advanced before completed copy proof: object=%#v puts=%d", base.get(pointerKey), base.putAttempts[pointerKey])
			}
			if base.objectOpens[sourceA] < 2 || base.objectOpens[sourceB] < 1 {
				t.Fatalf("copy attempts did not rebind source bodies: a=%d b=%d", base.objectOpens[sourceA], base.objectOpens[sourceB])
			}
			if base.objectOpens[destinationA] < 1 {
				t.Fatalf("copy destination proofs=%d, want replay streamed proof for ambiguous existing key", base.objectOpens[destinationA])
			}
		})
	}
}

func TestInterruptedStrongPointerStageReplaysCompletedPointer(t *testing.T) {
	for _, target := range []TargetName{TargetCloudflare, TargetTencent} {
		t.Run(string(target), func(t *testing.T) {
			root := t.TempDir()
			firstKey, secondKey := "current/a.txt", "current/b.txt"
			firstBody, secondBody := []byte("pointer-a"), []byte("pointer-b")
			writeRecoverySource(t, root, firstKey, firstBody)
			writeRecoverySource(t, root, secondKey, secondBody)
			plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{
				{SourcePath: firstKey, RemoteKey: firstKey, Size: int64(len(firstBody)), SHA256: digestBytes(firstBody), Class: ObjectPointer},
				{SourcePath: secondKey, RemoteKey: secondKey, Size: int64(len(secondBody)), SHA256: digestBytes(secondBody), Class: ObjectPointer},
			}}).WithCDN("https://cdn.test/")
			if err != nil {
				t.Fatal(err)
			}
			remote := newFakeRemote()
			remote.failAfterPutKey = secondKey
			journalDir := filepath.Join(t.TempDir(), "journal")
			request := requestFixture(target, plan, "partial-pointer-"+string(target))
			first := recoveryPublisher(target, remote, root, journalDir, Hooks{})
			if _, err := first.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "response loss") {
				t.Fatalf("first run err=%v", err)
			}
			remote.mutex.Lock()
			remote.objects[firstKey] = fakeObject{body: bytes.Repeat([]byte("x"), len(firstBody)), sha: digestBytes(firstBody), etag: `"forged-pointer"`}
			remote.mutex.Unlock()

			second := recoveryPublisher(target, remote, root, journalDir, Hooks{})
			result, err := second.Run(context.Background(), request)
			if err != nil || !result.RemoteRefReady {
				t.Fatalf("resume result=%#v err=%v", result, err)
			}
			if got := string(remote.get(firstKey).Body); got != string(firstBody) {
				t.Fatalf("completed pointer was not repaired before checkpoint: %q", got)
			}
			if remote.putAttempts[firstKey] != 2 {
				t.Fatalf("completed pointer attempts=%d, want initial plus replay", remote.putAttempts[firstKey])
			}
		})
	}
}

func TestInterruptedLegacyAliasStageReplaysCompletedAlias(t *testing.T) {
	for _, target := range []TargetName{TargetCloudflare, TargetTencent} {
		t.Run(string(target), func(t *testing.T) {
			root := t.TempDir()
			releaseKey := "apt/dists/latest/Release"
			packagesKey := "apt/dists/latest/main/binary-amd64/Packages"
			pointerKey := "apt/dists/latest/InRelease"
			releaseBody, packagesBody, pointerBody := []byte("release-body"), []byte("packages-body"), []byte("inrelease-body")
			writeRecoverySource(t, root, releaseKey, releaseBody)
			writeRecoverySource(t, root, packagesKey, packagesBody)
			writeRecoverySource(t, root, pointerKey, pointerBody)
			plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{
				{SourcePath: releaseKey, RemoteKey: releaseKey, Size: int64(len(releaseBody)), SHA256: digestBytes(releaseBody), Class: ObjectLegacyMetadata},
				{SourcePath: packagesKey, RemoteKey: packagesKey, Size: int64(len(packagesBody)), SHA256: digestBytes(packagesBody), Class: ObjectLegacyMetadata},
				{SourcePath: pointerKey, RemoteKey: pointerKey, Size: int64(len(pointerBody)), SHA256: digestBytes(pointerBody), Class: ObjectPointer},
			}}).WithCDN("https://cdn.test/")
			if err != nil {
				t.Fatal(err)
			}
			remote := newFakeRemote()
			remote.failAfterPutKey = packagesKey
			journalDir := filepath.Join(t.TempDir(), "journal")
			request := requestFixture(target, plan, "partial-legacy-alias-"+string(target))
			first := recoveryPublisher(target, remote, root, journalDir, Hooks{}).WithWorkers(1)
			if _, err := first.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "response loss") {
				t.Fatalf("first run err=%v", err)
			}
			remote.mutex.Lock()
			remote.objects[releaseKey] = fakeObject{body: bytes.Repeat([]byte("x"), len(releaseBody)), sha: digestBytes(releaseBody), etag: `"forged-release"`}
			remote.mutex.Unlock()

			second := recoveryPublisher(target, remote, root, journalDir, Hooks{}).WithWorkers(1)
			result, err := second.Run(context.Background(), request)
			if err != nil || !result.RemoteRefReady {
				t.Fatalf("resume result=%#v err=%v", result, err)
			}
			if got := string(remote.get(releaseKey).Body); got != string(releaseBody) {
				t.Fatalf("completed legacy alias was not repaired: %q", got)
			}
			if remote.putAttempts[releaseKey] != 2 || remote.putAttempts[pointerKey] != 1 {
				t.Fatalf("legacy replay attempts release=%d pointer=%d", remote.putAttempts[releaseKey], remote.putAttempts[pointerKey])
			}
		})
	}
}

func TestInterruptedYUMAliasStageReplaysCompletedAliasBeforeStrongPointer(t *testing.T) {
	const generation = "00000000000000000001"
	const generatedRoot = ".sow/generations/" + generation + "/yum/yum/rocky/9/x86_64/repodata/"
	const aliasRoot = "yum/rocky/9/x86_64/repodata/"
	const strongPointer = "_sow/v1/mirrorlist/latest/rocky/9/x86_64.txt"
	for _, target := range []TargetName{TargetCloudflare, TargetTencent} {
		t.Run(string(target), func(t *testing.T) {
			root := t.TempDir()
			objects := []struct {
				source string
				remote string
				body   string
				class  ObjectClass
			}{
				{"generated/primary.xml.zst", generatedRoot + "primary.xml.zst", "generation-primary", ObjectMetadata},
				{"generated/filelists.xml.zst", generatedRoot + "filelists.xml.zst", "generation-filelists", ObjectMetadata},
				{"generated/other.xml.zst", generatedRoot + "other.xml.zst", "generation-other", ObjectMetadata},
				{"generated/repomd.xml.asc", generatedRoot + "repomd.xml.asc", "signed-generation", ObjectMetadata},
				{"generated/repomd.xml", generatedRoot + "repomd.xml", "generation-repomd", ObjectMetadata},
				{"alias/primary.xml.zst", aliasRoot + "primary.xml.zst", "generation-primary", ObjectYUMAliasMetadata},
				{"alias/filelists.xml.zst", aliasRoot + "filelists.xml.zst", "generation-filelists", ObjectYUMAliasMetadata},
				{"alias/other.xml.zst", aliasRoot + "other.xml.zst", "generation-other", ObjectYUMAliasMetadata},
				{"alias/repomd.xml.asc", aliasRoot + "repomd.xml.asc", "signed-generation", ObjectYUMAliasPointer},
				{"alias/repomd.xml", aliasRoot + "repomd.xml", "generation-repomd", ObjectYUMAliasPointer},
			}
			plan := Plan{Schema: planSchema}
			for _, object := range objects {
				body := []byte(object.body)
				writeRecoverySource(t, root, object.source, body)
				plan.Objects = append(plan.Objects, PlannedObject{
					SourcePath: object.source, RemoteKey: object.remote, Size: int64(len(body)),
					SHA256: digestBytes(body), Class: object.class,
				})
			}
			mirrorBody := []byte("https://cdn.test/_sow/v1/g/" + generation + "/yum/rocky/9/x86_64/\n")
			writeRecoverySource(t, root, "mirrorlist.txt", mirrorBody)
			plan.Objects = append(plan.Objects, PlannedObject{
				SourcePath: "mirrorlist.txt", RemoteKey: strongPointer,
				Size: int64(len(mirrorBody)), SHA256: digestBytes(mirrorBody), Class: ObjectPointer,
			})
			var err error
			plan, err = plan.WithCDN("https://cdn.test/")
			if err != nil {
				t.Fatal(err)
			}
			channel := ChannelState{
				View: "latest", Repo: "rocky", OS: "9", Arch: "x86_64", Generation: 1,
				RemoteKey: ".sow/channels/latest/rocky/9/x86_64.json", LegacyRoot: "yum/rocky/9/x86_64",
			}
			channelBody, err := channel.CanonicalBody()
			if err != nil {
				t.Fatal(err)
			}
			channel.BodySHA256 = digestBytes(channelBody)

			remote := newFakeRemote()
			remote.failAfterPutKey = aliasRoot + "repomd.xml.asc"
			journalDir := filepath.Join(t.TempDir(), "journal")
			request := requestFixture(target, plan, "partial-yum-alias-"+string(target))
			request.Generation.Refs = request.Generation.Refs[:1]
			request.Generation.Channels = []ChannelState{channel}
			first := recoveryPublisher(target, remote, root, journalDir, Hooks{}).WithWorkers(1)
			if _, err := first.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "response loss") {
				t.Fatalf("first run err=%v", err)
			}
			aliasKey := aliasRoot + "primary.xml.zst"
			aliasBody := []byte("generation-primary")
			remote.mutex.Lock()
			remote.objects[aliasKey] = fakeObject{body: bytes.Repeat([]byte("x"), len(aliasBody)), sha: digestBytes(aliasBody), etag: `"forged-yum-alias"`}
			remote.mutex.Unlock()

			second := recoveryPublisher(target, remote, root, journalDir, Hooks{}).WithWorkers(1)
			result, err := second.Run(context.Background(), request)
			if err != nil || !result.RemoteRefReady {
				t.Fatalf("resume result=%#v err=%v", result, err)
			}
			if got := string(remote.get(aliasKey).Body); got != string(aliasBody) {
				t.Fatalf("completed YUM alias was not repaired: %q", got)
			}
			if remote.putAttempts[aliasKey] != 2 || remote.putAttempts[strongPointer] != 1 {
				t.Fatalf("YUM replay attempts alias=%d strong-pointer=%d", remote.putAttempts[aliasKey], remote.putAttempts[strongPointer])
			}
		})
	}
}

type failAfterDeleteRemote struct {
	*fakeRemote
	failKey string
	failed  bool
}

func (f *failAfterDeleteRemote) deleteThenLoseResponse(key, ifMatch string) error {
	if err := f.fakeRemote.delete(key, ifMatch); err != nil {
		return err
	}
	if key == f.failKey && !f.failed {
		f.failed = true
		return errors.New("injected response loss after remote delete")
	}
	return nil
}

func (f *failAfterDeleteRemote) R2Delete(_ context.Context, key, ifMatch string) error {
	return f.deleteThenLoseResponse(key, ifMatch)
}

func (f *failAfterDeleteRemote) COSDelete(_ context.Context, key, ifMatch string) error {
	return f.deleteThenLoseResponse(key, ifMatch)
}

func deleteRecoveryPublisher(target TargetName, remote *failAfterDeleteRemote, root, journalDir string) *Publisher {
	if target == TargetTencent {
		return NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
	}
	return NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
}

func TestInterruptedDeleteStageReplaysCompletedDeletionBeforeCheckpoint(t *testing.T) {
	const (
		firstKey  = ".sow/snapshots/jammy-20260131.json"
		secondKey = ".sow/snapshots/jammy-20260228.json"
	)
	firstBody := []byte("snapshot-route-a")
	secondBody := []byte("snapshot-route-b")
	for _, target := range []TargetName{TargetCloudflare, TargetTencent} {
		t.Run(string(target), func(t *testing.T) {
			root := t.TempDir()
			plan, err := (Plan{Schema: planSchema, Deletes: []PlannedDelete{
				{
					Class: DeleteSnapshotOwned, SourcePath: firstKey, RemoteKey: firstKey,
					Size: int64(len(firstBody)), SHA256: digestBytes(firstBody),
					CDNPath: "pro/v1/basic/_sow/v1/snapshots/jammy-20260131/_route.json",
				},
				{
					Class: DeleteSnapshotOwned, SourcePath: secondKey, RemoteKey: secondKey,
					Size: int64(len(secondBody)), SHA256: digestBytes(secondBody),
					CDNPath: "pro/v1/basic/_sow/v1/snapshots/jammy-20260228/_route.json",
				},
			}}).WithCDN("https://cdn.test/")
			if err != nil {
				t.Fatal(err)
			}
			base := newFakeRemote()
			base.objects[firstKey] = fakeObject{body: append([]byte(nil), firstBody...), sha: digestBytes(firstBody), etag: `"delete-a"`}
			base.objects[secondKey] = fakeObject{body: append([]byte(nil), secondBody...), sha: digestBytes(secondBody), etag: `"delete-b"`}
			remote := &failAfterDeleteRemote{fakeRemote: base, failKey: secondKey}
			journalDir := filepath.Join(t.TempDir(), "journal")
			request := requestFixture(target, plan, "partial-delete-"+string(target))
			first := deleteRecoveryPublisher(target, remote, root, journalDir)
			result, err := first.Run(context.Background(), request)
			if err == nil || !strings.Contains(err.Error(), "response loss after remote delete") {
				t.Fatalf("first run result=%#v err=%v", result, err)
			}
			journalBytes, err := readJournalFile(result.JournalPath)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := decodeJournal(journalBytes)
			if err != nil {
				t.Fatal(err)
			}
			if !journalHas(&journal, "delete:"+firstKey) || journalHas(&journal, "delete:"+secondKey) {
				t.Fatalf("partial deletion journal=%v", journal.CompletedObjects)
			}

			// A foreign replay of the exact authorized object after the first
			// deletion must not be hidden by its durable CompletedObjects bit.
			base.mutex.Lock()
			base.objects[firstKey] = fakeObject{body: append([]byte(nil), firstBody...), sha: digestBytes(firstBody), etag: `"reappeared-a"`}
			base.mutex.Unlock()

			second := recoveryPublisher(target, base, root, journalDir, Hooks{})
			result, err = second.Run(context.Background(), request)
			if err != nil || !result.RemoteRefReady {
				t.Fatalf("resume result=%#v err=%v", result, err)
			}
			if base.get(firstKey).Exists || base.get(secondKey).Exists {
				t.Fatalf("replayed deletion closure left objects: first=%#v second=%#v", base.get(firstKey), base.get(secondKey))
			}
			if base.deleteAttempts[firstKey] != 2 || base.deleteAttempts[secondKey] != 1 {
				t.Fatalf("delete attempts first=%d second=%d, want 2/1", base.deleteAttempts[firstKey], base.deleteAttempts[secondKey])
			}
			if base.objectOpens[firstKey] != 2 || base.objectOpens[secondKey] != 1 {
				t.Fatalf("streamed deletion proofs first=%d second=%d, want 2/1", base.objectOpens[firstKey], base.objectOpens[secondKey])
			}
			checkpoint, err := DecodeCheckpoint(base.get(CheckpointKey).Body)
			if err != nil || checkpoint.Phase != PhaseCheckpointCommitted {
				t.Fatalf("checkpoint committed without converged delete closure: %#v err=%v", checkpoint, err)
			}
		})
	}
}

var _ R2CopyDeleteProvider = (*failAfterCopyRemote)(nil)
var _ COSCopyDeleteProvider = (*failAfterCopyRemote)(nil)
var _ R2CopyDeleteProvider = (*failAfterDeleteRemote)(nil)
var _ COSCopyDeleteProvider = (*failAfterDeleteRemote)(nil)
