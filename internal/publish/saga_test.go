package publish

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeObject struct {
	body []byte
	sha  string
	etag string
}

func TestJournalUnlockFailureIsPartOfPublisherResult(t *testing.T) {
	injected := errors.New("injected journal unlock failure")
	var resultErr error
	propagateJournalUnlock(func() error { return injected }, &resultErr)
	if !errors.Is(resultErr, injected) {
		t.Fatalf("successful publication hid journal unlock failure: %v", resultErr)
	}

	primary := errors.New("primary publication failure")
	resultErr = primary
	propagateJournalUnlock(func() error { return injected }, &resultErr)
	if !errors.Is(resultErr, primary) || !errors.Is(resultErr, injected) {
		t.Fatalf("journal unlock failure did not preserve both errors: %v", resultErr)
	}
}

func TestPublisherEntryPointsRejectNilContextWithoutPanicking(t *testing.T) {
	request := Request{Generation: TargetGeneration{Generation: 1}}
	//lint:ignore SA1012 This is the explicit nil-context rejection contract.
	if _, err := (*Publisher)(nil).Run(nil, request); err == nil || !strings.Contains(err.Error(), "nil context") {
		t.Fatalf("Publisher.Run nil context error=%v", err)
	}
	//lint:ignore SA1012 This is the explicit nil-context rejection contract.
	if _, err := RunTargets(nil); err == nil || !strings.Contains(err.Error(), "nil context") {
		t.Fatalf("RunTargets nil context error=%v", err)
	}
}

type fakeObjectOpenMutation struct {
	at     int
	object fakeObject
}

type fakeRemote struct {
	mutex                  sync.Mutex
	objects                map[string]fakeObject
	cdnObjects             map[string]fakeObject
	etagCounter            int
	putAttempts            map[string]int
	putOrder               []string
	purgeCalls             [][]string
	putDelay               time.Duration
	delayPrefix            string
	activePuts             int
	maxPuts                int
	copyAttempts           map[string]int
	deleteAttempts         map[string]int
	openAttempts           map[string]int
	objectOpens            map[string]int
	mutateOnOpen           map[string]fakeObject
	mutateOnNthObjectOpen  map[string]fakeObjectOpenMutation
	controlReads           map[string]int
	mutateOnControlRead    map[string]map[int]fakeObject
	appearAfterMissingHead map[string]fakeObject
	delayBarrier           chan struct{}
	delayArrivals          int

	failAfterPutKey         string
	failedAfterPut          bool
	failPurgeAfterApply     bool
	failedPurgeAfterApply   bool
	failPurgeAlways         bool
	conflictCheckpointCAS   bool
	probeErr                error
	preflightErr            error
	preflightCalls          int
	corruptCDNKey           string
	mutateCheckpointPurge   []byte
	failDeleteAfterApply    bool
	failedDeleteAfterApply  bool
	failDeleteBeforeApply   bool
	failedDeleteBeforeApply bool
	staleCDNOnPurge         bool
	staleStorageOnDelete    bool
	ignoreDeleteCondition   bool
	mutateBeforeDelete      map[string]fakeObject
}

func newFakeRemote() *fakeRemote {
	return &fakeRemote{
		objects: make(map[string]fakeObject), cdnObjects: make(map[string]fakeObject),
		putAttempts: make(map[string]int), copyAttempts: make(map[string]int), deleteAttempts: make(map[string]int),
		openAttempts: make(map[string]int), objectOpens: make(map[string]int), mutateOnOpen: make(map[string]fakeObject),
		mutateOnNthObjectOpen: make(map[string]fakeObjectOpenMutation), controlReads: make(map[string]int),
		mutateOnControlRead: make(map[string]map[int]fakeObject), appearAfterMissingHead: make(map[string]fakeObject),
		mutateBeforeDelete: make(map[string]fakeObject),
	}
}

func (f *fakeRemote) nextETag() string {
	f.etagCounter++
	return fmt.Sprintf(`"etag-%d"`, f.etagCounter)
}

func (f *fakeRemote) get(key string) ControlObject {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.controlReads[key]++
	if mutations := f.mutateOnControlRead[key]; mutations != nil {
		if replacement, mutate := mutations[f.controlReads[key]]; mutate {
			f.objects[key] = replacement
			delete(mutations, f.controlReads[key])
		}
	}
	object, exists := f.objects[key]
	return ControlObject{Exists: exists, Body: append([]byte(nil), object.body...), ETag: object.etag}
}

func (f *fakeRemote) head(key string) ObjectInfo {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	object, exists := f.objects[key]
	if !exists {
		if replacement, appear := f.appearAfterMissingHead[key]; appear {
			f.objects[key] = replacement
			delete(f.appearAfterMissingHead, key)
		}
	}
	return ObjectInfo{Exists: exists, Size: int64(len(object.body)), SHA256: object.sha, ETag: object.etag}
}

func (f *fakeRemote) create(key string, body io.Reader, size int64, sha string) (string, error) {
	f.mutex.Lock()
	if _, exists := f.objects[key]; exists {
		f.putAttempts[key]++
		f.mutex.Unlock()
		return "", ErrAlreadyExists
	}
	f.mutex.Unlock()
	return f.put(key, body, size, sha, "", false)
}

func (f *fakeRemote) put(key string, body io.Reader, size int64, sha, ifMatch string, ifNone bool) (string, error) {
	f.mutex.Lock()
	f.putAttempts[key]++
	f.putOrder = append(f.putOrder, key)
	delayed := f.putDelay > 0 && strings.HasPrefix(key, f.delayPrefix)
	if delayed {
		f.activePuts++
		f.delayArrivals++
		if f.activePuts > f.maxPuts {
			f.maxPuts = f.activePuts
		}
		if f.delayBarrier != nil && f.delayArrivals == cap(f.delayBarrier) {
			close(f.delayBarrier)
		}
	}
	current, exists := f.objects[key]
	if ifNone && exists {
		if delayed {
			f.activePuts--
		}
		f.mutex.Unlock()
		return "", ErrAlreadyExists
	}
	if ifMatch != "" && (!exists || current.etag != ifMatch) {
		if delayed {
			f.activePuts--
		}
		f.mutex.Unlock()
		return "", ErrConflict
	}
	if key == CheckpointKey && ifMatch != "" && f.conflictCheckpointCAS {
		if delayed {
			f.activePuts--
		}
		f.mutex.Unlock()
		return "", ErrConflict
	}
	f.mutex.Unlock()
	if delayed {
		if f.delayBarrier != nil {
			<-f.delayBarrier
		}
		time.Sleep(f.putDelay)
		defer func() {
			f.mutex.Lock()
			f.activePuts--
			f.mutex.Unlock()
		}()
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}
	if int64(len(data)) != size || hashString(string(data)) != sha {
		return "", errors.New("fake provider received incorrect object metadata")
	}
	f.mutex.Lock()
	etag := f.nextETag()
	f.objects[key] = fakeObject{body: append([]byte(nil), data...), sha: sha, etag: etag}
	shouldFail := f.failAfterPutKey == key && !f.failedAfterPut
	if shouldFail {
		f.failedAfterPut = true
	}
	f.mutex.Unlock()
	if shouldFail {
		return "", errors.New("injected response loss after remote put")
	}
	return etag, nil
}

func (f *fakeRemote) purge(urls []string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.purgeCalls = append(f.purgeCalls, append([]string(nil), urls...))
	if !f.staleCDNOnPurge {
		for _, rawURL := range urls {
			delete(f.cdnObjects, rawURL)
		}
	}
	if len(f.mutateCheckpointPurge) != 0 {
		data := append([]byte(nil), f.mutateCheckpointPurge...)
		f.objects[CheckpointKey] = fakeObject{body: data, sha: digestBytes(data), etag: f.nextETag()}
		f.mutateCheckpointPurge = nil
	}
	if f.failPurgeAlways {
		return errors.New("injected CDN outage")
	}
	if f.failPurgeAfterApply && !f.failedPurgeAfterApply {
		f.failedPurgeAfterApply = true
		return errors.New("injected response loss after purge")
	}
	return nil
}

func (f *fakeRemote) open(rawURL string) (io.ReadCloser, error) {
	f.mutex.Lock()
	f.openAttempts[rawURL]++
	if object, exists := f.cdnObjects[rawURL]; exists {
		body := append([]byte(nil), object.body...)
		f.mutex.Unlock()
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	f.mutex.Unlock()
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	key := strings.TrimPrefix(u.Path, "/")
	snapshotYUMRepodataSuffix := ""
	if strings.HasPrefix(key, "_sow/v1/g/") {
		parts := strings.SplitN(strings.TrimPrefix(key, "_sow/v1/g/"), "/", 2)
		if len(parts) == 2 {
			key = ".sow/generations/" + parts[0] + "/yum/" + parts[1]
		}
	}
	key = strings.TrimPrefix(key, "pro/v1/basic/")
	if strings.HasPrefix(key, "_sow/v1/snapshots/") {
		parts := strings.SplitN(strings.TrimPrefix(key, "_sow/v1/snapshots/"), "/", 3)
		if len(parts) == 2 && parts[1] == "_route.json" {
			key = ".sow/snapshots/" + parts[0] + ".json"
		} else if len(parts) == 3 && parts[1] == "yum" && strings.Contains("/"+parts[2], "/Packages/") {
			key = ".sow/gated/snapshots/" + parts[0] + "/yum/" + parts[2]
		} else if len(parts) == 3 && parts[1] == "yum" && strings.Contains("/"+parts[2], "/repodata/") {
			// The real edge resolves the snapshot route document to one immutable
			// generation. The fake has no route interpreter, so select the unique
			// uploaded generation object with the same YUM leaf suffix.
			snapshotYUMRepodataSuffix = "/yum/" + parts[2]
		} else if len(parts) == 3 && parts[1] == "assets" {
			key = ".sow/gated/snapshots/" + parts[0] + "/asset/" + parts[2]
		}
	}
	f.mutex.Lock()
	if snapshotYUMRepodataSuffix != "" {
		matched := ""
		for candidate := range f.objects {
			if !strings.HasPrefix(candidate, ".sow/gated/generations/") || !strings.HasSuffix(candidate, snapshotYUMRepodataSuffix) {
				continue
			}
			if matched != "" {
				matched = ""
				break
			}
			matched = candidate
		}
		key = matched
	}
	object, exists := f.objects[key]
	corrupt := key == f.corruptCDNKey
	f.mutex.Unlock()
	if !exists {
		return nil, ErrNotFound
	}
	if corrupt {
		return io.NopCloser(strings.NewReader("corrupt")), nil
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), object.body...))), nil
}

func TestRefOnlyPlanRevalidatesCarriedProbeWithoutObjectPUT(t *testing.T) {
	t.Parallel()
	const (
		key      = "pkg/anchor"
		probeURL = "https://cdn.example/pkg/anchor"
	)
	body := []byte("unchanged anchor\n")
	plan, err := (Plan{}).WithCDN("https://cdn.example/")
	if err != nil {
		t.Fatal(err)
	}
	plan.Probes = []VerifyObject{{URL: probeURL, Size: int64(len(body)), SHA256: digestBytes(body)}}
	if _, err := plan.Canonical(); err != nil {
		t.Fatal(err)
	}
	remote := newFakeRemote()
	remote.objects[key] = fakeObject{body: body, sha: digestBytes(body), etag: `"anchor"`}
	request := requestFixture(TargetCloudflare, plan, "ref-only-probe-replay")
	crashed := false
	journalDir := filepath.Join(t.TempDir(), "journal")
	first := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, journalDir, Hooks{AfterPhase: func(_ TargetName, phase Phase) error {
		if phase == PhasePurged && !crashed {
			crashed = true
			return errors.New("injected ref-only crash after purge")
		}
		return nil
	}})
	if _, err := first.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "ref-only crash") {
		t.Fatalf("ref-only crash err=%v", err)
	}
	second := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, journalDir, Hooks{})
	result, err := second.Run(context.Background(), request)
	if err != nil || !result.RemoteRefReady {
		t.Fatalf("ref-only replay result=%#v err=%v", result, err)
	}
	if remote.putAttempts[key] != 0 || remote.openAttempts[probeURL] == 0 {
		t.Fatalf("ref-only side effects anchor_puts=%d probe_gets=%d", remote.putAttempts[key], remote.openAttempts[probeURL])
	}
}

func (f *fakeRemote) R2GetControl(_ context.Context, key string) (ControlObject, error) {
	return f.get(key), nil
}
func (f *fakeRemote) CloudflarePreflight(context.Context, Plan) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.preflightCalls++
	return f.preflightErr
}
func (f *fakeRemote) R2Head(_ context.Context, key string) (ObjectInfo, error) {
	return f.head(key), nil
}
func (f *fakeRemote) R2OpenObject(_ context.Context, key string) (ObjectContent, error) {
	return f.openObject(key)
}
func (f *fakeRemote) R2Put(_ context.Context, key string, body io.Reader, size int64, sha string, condition R2PutCondition) (string, error) {
	return f.put(key, body, size, sha, condition.IfMatch, condition.IfNoneMatch)
}
func (f *fakeRemote) R2Copy(_ context.Context, destinationKey, sourceKey string, size int64, sha, sourceETag string) (string, error) {
	return f.copy(destinationKey, sourceKey, size, sha, sourceETag)
}
func (f *fakeRemote) R2Delete(_ context.Context, key, ifMatch string) error {
	return f.delete(key, ifMatch)
}
func (f *fakeRemote) R2DeleteCheckpointFenced(_ context.Context, key string) error {
	return f.deleteCheckpointFenced(key)
}
func (f *fakeRemote) CloudflarePurge(_ context.Context, urls []string) error {
	return f.purge(urls)
}
func (f *fakeRemote) CloudflareOpen(_ context.Context, rawURL string) (io.ReadCloser, error) {
	return f.open(rawURL)
}

func (f *fakeRemote) COSGetControl(_ context.Context, key string) (ControlObject, error) {
	return f.get(key), nil
}
func (f *fakeRemote) EdgeOnePreflight(context.Context, Plan) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.preflightCalls++
	return f.preflightErr
}
func (f *fakeRemote) COSProbeUnversioned(context.Context) error { return f.probeErr }
func (f *fakeRemote) COSHead(_ context.Context, key string) (ObjectInfo, error) {
	return f.head(key), nil
}
func (f *fakeRemote) COSOpenObject(_ context.Context, key string) (ObjectContent, error) {
	return f.openObject(key)
}
func (f *fakeRemote) COSCreate(_ context.Context, key string, body io.Reader, size int64, sha string) (string, error) {
	return f.create(key, body, size, sha)
}
func (f *fakeRemote) COSPut(_ context.Context, key string, body io.Reader, size int64, sha string) (string, error) {
	return f.put(key, body, size, sha, "", false)
}
func (f *fakeRemote) COSCopy(_ context.Context, destinationKey, sourceKey string, size int64, sha, sourceETag string) (string, error) {
	return f.copy(destinationKey, sourceKey, size, sha, sourceETag)
}
func (f *fakeRemote) COSDelete(_ context.Context, key, ifMatch string) error {
	return f.delete(key, ifMatch)
}
func (f *fakeRemote) COSDeleteCheckpointFenced(_ context.Context, key string) error {
	return f.deleteCheckpointFenced(key)
}
func (f *fakeRemote) EdgeOnePurge(_ context.Context, urls []string) error {
	return f.purge(urls)
}
func (f *fakeRemote) EdgeOneOpen(_ context.Context, rawURL string) (io.ReadCloser, error) {
	return f.open(rawURL)
}

func (f *fakeRemote) copy(destinationKey, sourceKey string, size int64, sha, sourceETag string) (string, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.copyAttempts[destinationKey]++
	if _, exists := f.objects[destinationKey]; exists {
		return "", ErrAlreadyExists
	}
	source, exists := f.objects[sourceKey]
	if !exists {
		return "", ErrNotFound
	}
	if source.etag != sourceETag || int64(len(source.body)) != size || source.sha != sha {
		return "", ErrConflict
	}
	etag := f.nextETag()
	f.objects[destinationKey] = fakeObject{body: append([]byte(nil), source.body...), sha: sha, etag: etag}
	return etag, nil
}

func (f *fakeRemote) openObject(key string) (ObjectContent, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.objectOpens[key]++
	if replacement, mutate := f.mutateOnOpen[key]; mutate {
		f.objects[key] = replacement
		delete(f.mutateOnOpen, key)
	}
	if mutation, mutate := f.mutateOnNthObjectOpen[key]; mutate && mutation.at == f.objectOpens[key] {
		f.objects[key] = mutation.object
		delete(f.mutateOnNthObjectOpen, key)
	}
	object, exists := f.objects[key]
	if !exists {
		return ObjectContent{}, ErrNotFound
	}
	body := append([]byte(nil), object.body...)
	return ObjectContent{Info: ObjectInfo{Exists: true, Size: int64(len(body)), SHA256: object.sha, ETag: object.etag}, Body: io.NopCloser(bytes.NewReader(body))}, nil
}

func (f *fakeRemote) delete(key, ifMatch string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.deleteAttempts[key]++
	if f.failDeleteBeforeApply && !f.failedDeleteBeforeApply {
		f.failedDeleteBeforeApply = true
		return errors.New("injected transport failure before delete apply")
	}
	if replacement, mutate := f.mutateBeforeDelete[key]; mutate {
		f.objects[key] = replacement
		delete(f.mutateBeforeDelete, key)
	}
	current, exists := f.objects[key]
	if !exists {
		return ErrNotFound
	}
	if !f.ignoreDeleteCondition && current.etag != ifMatch {
		return ErrConflict
	}
	if !f.staleStorageOnDelete || strings.HasPrefix(key, ".sow/probes/conditional-delete/") {
		delete(f.objects, key)
	}
	if f.failDeleteAfterApply && !f.failedDeleteAfterApply && !strings.HasPrefix(key, ".sow/probes/conditional-delete/") {
		f.failedDeleteAfterApply = true
		return errors.New("injected response loss after delete")
	}
	return nil
}

func (f *fakeRemote) deleteCheckpointFenced(key string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.deleteAttempts[key]++
	if replacement, mutate := f.mutateBeforeDelete[key]; mutate {
		f.objects[key] = replacement
		delete(f.mutateBeforeDelete, key)
	}
	if _, exists := f.objects[key]; !exists {
		return ErrNotFound
	}
	if !f.staleStorageOnDelete || strings.HasPrefix(key, ".sow/probes/conditional-delete/") {
		delete(f.objects, key)
	}
	if f.failDeleteAfterApply && !f.failedDeleteAfterApply && !strings.HasPrefix(key, ".sow/probes/conditional-delete/") {
		f.failedDeleteAfterApply = true
		return errors.New("injected response loss after checkpoint-fenced delete")
	}
	return nil
}

// r2WithoutCheckpointFencedDelete deliberately exposes the ordinary R2
// provider and conditional-copy/delete surface but not the explicit
// unconditional fallback. It proves opt-in policy alone cannot manufacture a
// provider capability that the concrete client did not expose.
type r2WithoutCheckpointFencedDelete struct{ remote *fakeRemote }

func (p r2WithoutCheckpointFencedDelete) CloudflarePreflight(ctx context.Context, plan Plan) error {
	return p.remote.CloudflarePreflight(ctx, plan)
}
func (p r2WithoutCheckpointFencedDelete) R2GetControl(ctx context.Context, key string) (ControlObject, error) {
	return p.remote.R2GetControl(ctx, key)
}
func (p r2WithoutCheckpointFencedDelete) R2Head(ctx context.Context, key string) (ObjectInfo, error) {
	return p.remote.R2Head(ctx, key)
}
func (p r2WithoutCheckpointFencedDelete) R2OpenObject(ctx context.Context, key string) (ObjectContent, error) {
	return p.remote.R2OpenObject(ctx, key)
}
func (p r2WithoutCheckpointFencedDelete) R2Put(ctx context.Context, key string, body io.Reader, size int64, sha string, condition R2PutCondition) (string, error) {
	return p.remote.R2Put(ctx, key, body, size, sha, condition)
}
func (p r2WithoutCheckpointFencedDelete) R2Copy(ctx context.Context, destinationKey, sourceKey string, size int64, sha, sourceETag string) (string, error) {
	return p.remote.R2Copy(ctx, destinationKey, sourceKey, size, sha, sourceETag)
}
func (p r2WithoutCheckpointFencedDelete) R2Delete(ctx context.Context, key, ifMatch string) error {
	return p.remote.R2Delete(ctx, key, ifMatch)
}
func (p r2WithoutCheckpointFencedDelete) CloudflarePurge(ctx context.Context, urls []string) error {
	return p.remote.CloudflarePurge(ctx, urls)
}
func (p r2WithoutCheckpointFencedDelete) CloudflareOpen(ctx context.Context, rawURL string) (io.ReadCloser, error) {
	return p.remote.CloudflareOpen(ctx, rawURL)
}

func TestSnapshotRetentionDeleteIsJournaledAndReplaySafe(t *testing.T) {
	t.Parallel()
	const key = ".sow/snapshots/jammy-20260131.json"
	body := []byte("route")
	plan := Plan{Schema: planSchema, Deletes: []PlannedDelete{{
		Class: DeleteSnapshotOwned, SourcePath: key, RemoteKey: key, Size: int64(len(body)), SHA256: digestBytes(body),
		CDNPath: "pro/v1/basic/_sow/v1/snapshots/jammy-20260131/_route.json",
	}}}
	var err error
	plan, err = plan.WithCDN("https://cdn.example/")
	if err != nil {
		t.Fatal(err)
	}
	remote := newFakeRemote()
	remote.objects[key] = fakeObject{body: body, sha: digestBytes(body), etag: `"route"`}
	const clientRoute = "https://cdn.example/pro/v1/basic/_sow/v1/snapshots/jammy-20260131/_route.json"
	if len(plan.VerifyAbsent) != 1 || plan.VerifyAbsent[0].URL != clientRoute {
		t.Fatalf("retention absence closure=%#v purge=%v", plan.VerifyAbsent, plan.PurgeURLs)
	}
	remote.cdnObjects[plan.VerifyAbsent[0].URL] = fakeObject{body: []byte("stale route")}
	remote.failDeleteAfterApply = true
	journalDir := filepath.Join(t.TempDir(), "journal")
	request := requestFixture(TargetCloudflare, plan, "retention-delete-replay")
	first := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, journalDir, Hooks{})
	if _, err := first.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "response loss after delete") {
		t.Fatalf("first delete did not expose response loss: %v", err)
	}
	second := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, journalDir, Hooks{})
	result, err := second.Run(context.Background(), request)
	if err != nil || !result.RemoteRefReady {
		t.Fatalf("delete replay failed: result=%#v err=%v", result, err)
	}
	if remote.deleteAttempts[key] != 1 {
		t.Fatalf("idempotent delete attempts=%d", remote.deleteAttempts[key])
	}
	if _, exists := remote.objects[key]; exists {
		t.Fatal("expired snapshot route remains reachable")
	}
	if _, exists := remote.cdnObjects[plan.VerifyAbsent[0].URL]; exists {
		t.Fatal("expired snapshot CDN route remains reachable")
	}
	if len(remote.purgeCalls) != 1 || len(remote.purgeCalls[0]) != 2 {
		t.Fatalf("retention purge closure=%v", remote.purgeCalls)
	}
}

func TestCommittedDeletionReplayRepurgesClientAndCleanCacheKeys(t *testing.T) {
	t.Parallel()
	const key = ".sow/snapshots/jammy-20260131.json"
	body := []byte("route")
	plan, err := (Plan{Schema: planSchema, Deletes: []PlannedDelete{{
		Class: DeleteSnapshotOwned, SourcePath: key, RemoteKey: key, Size: int64(len(body)), SHA256: digestBytes(body),
		CDNPath: "pro/v1/basic/_sow/v1/snapshots/jammy-20260131/_route.json",
	}}}).WithCDN("https://cdn.example/")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.PurgeURLs) != 2 {
		t.Fatalf("snapshot route purge closure=%v", plan.PurgeURLs)
	}
	request := requestFixture(TargetCloudflare, plan, "committed-delete-clean-replay")
	remote := newFakeRemote()
	remote.objects[key] = fakeObject{body: body, sha: digestBytes(body), etag: `"route-1"`}
	journal := filepath.Join(t.TempDir(), "journal")
	first := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, journal, Hooks{})
	if result, err := first.Run(context.Background(), request); err != nil || !result.RemoteRefReady {
		t.Fatalf("initial deletion result=%#v err=%v", result, err)
	}

	clientURL := "https://cdn.example/pro/v1/basic/_sow/v1/snapshots/jammy-20260131/_route.json"
	cleanURL := "https://cdn.example/.sow/snapshots/jammy-20260131.json"
	remote.mutex.Lock()
	remote.objects[key] = fakeObject{body: body, sha: digestBytes(body), etag: `"route-2"`}
	remote.cdnObjects[clientURL] = fakeObject{body: body}
	remote.cdnObjects[cleanURL] = fakeObject{body: body}
	purgesBefore := len(remote.purgeCalls)
	remote.mutex.Unlock()

	second := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, journal, Hooks{})
	if result, err := second.Run(context.Background(), request); err != nil || !result.RemoteRefReady {
		t.Fatalf("committed deletion replay result=%#v err=%v", result, err)
	}
	remote.mutex.Lock()
	defer remote.mutex.Unlock()
	if len(remote.purgeCalls) != purgesBefore+1 {
		t.Fatalf("committed replay purge calls=%v", remote.purgeCalls)
	}
	last := remote.purgeCalls[len(remote.purgeCalls)-1]
	want := map[string]bool{clientURL: false, cleanURL: false}
	for _, rawURL := range last {
		if _, expected := want[rawURL]; expected {
			want[rawURL] = true
		}
	}
	if len(last) != 2 || !want[clientURL] || !want[cleanURL] {
		t.Fatalf("committed replay omitted client/clean purge closure: %v", last)
	}
	if _, exists := remote.cdnObjects[clientURL]; exists {
		t.Fatal("committed replay left client cache entry")
	}
	if _, exists := remote.cdnObjects[cleanURL]; exists {
		t.Fatal("committed replay left clean cache entry")
	}
}

func TestSnapshotRetentionFailsClosedOnStorageOrCDNResidueAndReplays(t *testing.T) {
	t.Parallel()
	const key = ".sow/snapshots/jammy-20260131.json"
	body := []byte("route")
	plan, err := (Plan{Schema: planSchema, Deletes: []PlannedDelete{{
		Class: DeleteSnapshotOwned, SourcePath: key, RemoteKey: key, Size: int64(len(body)), SHA256: digestBytes(body),
		CDNPath: "pro/v1/basic/_sow/v1/snapshots/jammy-20260131/_route.json",
	}}}).WithCDN("https://cdn.example/")
	if err != nil {
		t.Fatal(err)
	}
	request := requestFixture(TargetCloudflare, plan, "retention-negative-closure")

	t.Run("storage-residue", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: body, sha: digestBytes(body), etag: `"route"`}
		remote.staleStorageOnDelete = true
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.Run(context.Background(), request); err == nil || !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), "still present in object storage") {
			t.Fatalf("storage residue err=%v", err)
		}
		checkpoint := remote.get(CheckpointKey)
		decoded, decodeErr := DecodeCheckpoint(checkpoint.Body)
		if decodeErr != nil || decoded.Phase != PhaseLocked {
			t.Fatalf("storage residue committed checkpoint=%#v err=%v", decoded, decodeErr)
		}
	})

	t.Run("stale-cdn-replay", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: body, sha: digestBytes(body), etag: `"route"`}
		remote.cdnObjects[plan.VerifyAbsent[0].URL] = fakeObject{body: []byte("stale cached route")}
		remote.staleCDNOnPurge = true
		journalDir := filepath.Join(t.TempDir(), "journal")
		first := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, journalDir, Hooks{})
		if _, err := first.Run(context.Background(), request); err == nil || !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), "still returns a successful response") {
			t.Fatalf("stale CDN err=%v", err)
		}
		checkpoint := remote.get(CheckpointKey)
		decoded, decodeErr := DecodeCheckpoint(checkpoint.Body)
		if decodeErr != nil || decoded.Phase != PhaseLocked {
			t.Fatalf("stale CDN committed checkpoint=%#v err=%v", decoded, decodeErr)
		}
		remote.mutex.Lock()
		remote.staleCDNOnPurge = false
		remote.mutex.Unlock()
		second := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, journalDir, Hooks{})
		result, err := second.Run(context.Background(), request)
		if err != nil || !result.RemoteRefReady {
			t.Fatalf("stale CDN replay result=%#v err=%v", result, err)
		}
		if remote.deleteAttempts[key] != 1 || len(remote.purgeCalls) < 2 {
			t.Fatalf("negative replay delete_attempts=%d purges=%v", remote.deleteAttempts[key], remote.purgeCalls)
		}
		if _, exists := remote.cdnObjects[plan.VerifyAbsent[0].URL]; exists {
			t.Fatal("replayed purge left stale CDN route")
		}
	})
}

func TestAssetServingDeleteVerifiesOriginPurgesCDNAndWorksOnBothTargets(t *testing.T) {
	t.Parallel()
	const key = "pkg/retired-tool"
	body := []byte("retired asset")
	plan, err := (Plan{Schema: planSchema, Deletes: []PlannedDelete{{
		Class: DeleteAssetServing, SourcePath: key, RemoteKey: key,
		Size: int64(len(body)), SHA256: hashString(string(body)), CDNPath: key,
	}}}).WithCDN("https://cdn.example/")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []TargetName{TargetCloudflare, TargetTencent} {
		target := target
		t.Run(string(target), func(t *testing.T) {
			remote := newFakeRemote()
			remote.objects[key] = fakeObject{body: append([]byte(nil), body...), sha: hashString(string(body)), etag: `"asset"`}
			remote.cdnObjects[plan.VerifyAbsent[0].URL] = fakeObject{body: append([]byte(nil), body...)}
			journal := filepath.Join(t.TempDir(), "journal")
			var publisher *Publisher
			if target == TargetCloudflare {
				publisher = NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, journal, Hooks{})
			} else {
				publisher = NewCOSEdgeOnePublisher(remote, DirectorySource{Root: t.TempDir()}, journal, Hooks{})
			}
			result, err := publisher.Run(context.Background(), requestFixture(target, plan, "asset-delete-"+string(target)))
			if err != nil || !result.RemoteRefReady {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			if remote.deleteAttempts[key] != 1 || len(remote.purgeCalls) != 1 {
				t.Fatalf("delete attempts=%d purges=%v", remote.deleteAttempts[key], remote.purgeCalls)
			}
			if _, exists := remote.objects[key]; exists {
				t.Fatal("asset remains in object storage")
			}
			if _, exists := remote.cdnObjects[plan.VerifyAbsent[0].URL]; exists {
				t.Fatal("asset remains in CDN cache")
			}
		})
	}
}

func TestAssetServingDeleteLegacyHashFallbackAndForeignDriftFailClosed(t *testing.T) {
	const key = "pkg/legacy-tool"
	body := []byte("legacy asset")
	plan, err := (Plan{Schema: planSchema, Deletes: []PlannedDelete{{
		Class: DeleteAssetServing, SourcePath: key, RemoteKey: key,
		Size: int64(len(body)), SHA256: hashString(string(body)), CDNPath: key,
	}}}).WithCDN("https://cdn.example/")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("legacy object without sow sha is streamed", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: append([]byte(nil), body...), etag: `"legacy"`}
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, "asset-delete-legacy")); err != nil {
			t.Fatal(err)
		}
		if remote.objectOpens[key] != 1 || remote.deleteAttempts[key] != 1 {
			t.Fatalf("origin GETs=%d deletes=%d", remote.objectOpens[key], remote.deleteAttempts[key])
		}
	})

	t.Run("foreign metadata drift is never deleted", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: []byte("foreign asset"), sha: hashString("foreign asset"), etag: `"foreign"`}
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, "asset-delete-foreign")); err == nil || !errors.Is(err, ErrDrift) {
			t.Fatalf("err=%v", err)
		}
		if remote.deleteAttempts[key] != 0 {
			t.Fatalf("foreign bytes were deleted attempts=%d", remote.deleteAttempts[key])
		}
	})

	t.Run("forged matching metadata cannot authorize foreign bytes", func(t *testing.T) {
		remote := newFakeRemote()
		foreign := bytes.Repeat([]byte("x"), len(body))
		remote.objects[key] = fakeObject{body: foreign, sha: hashString(string(body)), etag: `"forged-metadata"`}
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, "asset-delete-forged-metadata")); err == nil || !errors.Is(err, ErrDrift) {
			t.Fatalf("err=%v", err)
		}
		if remote.objectOpens[key] != 1 || remote.deleteAttempts[key] != 0 {
			t.Fatalf("forged metadata bypassed streamed proof: opens=%d deletes=%d", remote.objectOpens[key], remote.deleteAttempts[key])
		}
		if retained, exists := remote.objects[key]; !exists || !bytes.Equal(retained.body, foreign) {
			t.Fatalf("foreign bytes were not retained: exists=%t object=%#v", exists, retained)
		}
	})

	t.Run("absent head followed by foreign appearance is not deleted", func(t *testing.T) {
		remote := newFakeRemote()
		remote.appearAfterMissingHead[key] = fakeObject{body: []byte("foreign race"), sha: hashString("foreign race"), etag: `"foreign-race"`}
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, "asset-delete-race")); err == nil || !errors.Is(err, ErrVerification) {
			t.Fatalf("err=%v", err)
		}
		if remote.deleteAttempts[key] != 0 {
			t.Fatalf("racing foreign bytes were deleted attempts=%d", remote.deleteAttempts[key])
		}
	})

	t.Run("foreign overwrite after proof is rejected by conditional delete", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: append([]byte(nil), body...), sha: hashString(string(body)), etag: `"authorized"`}
		foreign := fakeObject{body: []byte("foreign after proof"), sha: hashString("foreign after proof"), etag: `"foreign-after-proof"`}
		remote.mutateBeforeDelete[key] = foreign
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, "asset-delete-conditional-race")); err == nil || !errors.Is(err, ErrDrift) {
			t.Fatalf("err=%v", err)
		}
		if retained, exists := remote.objects[key]; !exists || retained.etag != foreign.etag || !bytes.Equal(retained.body, foreign.body) {
			t.Fatalf("foreign overwrite was not retained: exists=%t object=%#v", exists, retained)
		}
	})

	t.Run("endpoint that ignores If-Match fails capability probe before live deletion", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: append([]byte(nil), body...), sha: hashString(string(body)), etag: `"authorized"`}
		remote.ignoreDeleteCondition = true
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, "asset-delete-conditional-capability")); err == nil || !errors.Is(err, ErrCapability) {
			t.Fatalf("err=%v", err)
		}
		if remote.deleteAttempts[key] != 0 {
			t.Fatalf("live serving object reached DELETE despite failed probe: attempts=%d", remote.deleteAttempts[key])
		}
		if _, exists := remote.objects[key]; !exists {
			t.Fatal("failed capability probe removed the live serving object")
		}
	})

	t.Run("indeterminate conditional-delete probe never activates fallback or acquires lock", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: append([]byte(nil), body...), sha: hashString(string(body)), etag: `"authorized"`}
		remote.failDeleteBeforeApply = true
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		_, err := publisher.WithCheckpointFencedDeletion().Run(context.Background(), requestFixture(TargetCloudflare, plan, "asset-delete-indeterminate-probe"))
		if err == nil || !errors.Is(err, ErrVerification) || errors.Is(err, errConditionalDeleteDemonstrablyUnsupported) {
			t.Fatalf("err=%v", err)
		}
		if remote.deleteAttempts[key] != 0 {
			t.Fatalf("indeterminate probe reached live DELETE: %d", remote.deleteAttempts[key])
		}
		if remote.putAttempts[CheckpointKey] != 0 {
			t.Fatalf("indeterminate probe acquired publication checkpoint: puts=%d", remote.putAttempts[CheckpointKey])
		}
		if _, exists := remote.objects[key]; !exists {
			t.Fatal("indeterminate probe removed the live object")
		}
	})

	t.Run("explicit checkpoint-fenced mode admits single-writer provider deletion", func(t *testing.T) {
		for _, target := range []TargetName{TargetCloudflare, TargetTencent} {
			target := target
			t.Run(string(target), func(t *testing.T) {
				remote := newFakeRemote()
				remote.objects[key] = fakeObject{body: append([]byte(nil), body...), sha: hashString(string(body)), etag: `"authorized"`}
				remote.ignoreDeleteCondition = true
				journal := filepath.Join(t.TempDir(), "journal")
				var publisher *Publisher
				if target == TargetCloudflare {
					publisher = NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, journal, Hooks{})
				} else {
					publisher = NewCOSEdgeOnePublisher(remote, DirectorySource{Root: t.TempDir()}, journal, Hooks{})
				}
				result, err := publisher.WithCheckpointFencedDeletion().Run(context.Background(), requestFixture(target, plan, "asset-delete-checkpoint-fenced-"+string(target)))
				if err != nil || !result.RemoteRefReady {
					t.Fatalf("result=%#v err=%v", result, err)
				}
				if remote.objectOpens[key] != 2 || remote.deleteAttempts[key] != 1 {
					t.Fatalf("identity streams=%d live deletes=%d want=2/1", remote.objectOpens[key], remote.deleteAttempts[key])
				}
				if _, exists := remote.objects[key]; exists {
					t.Fatal("checkpoint-fenced deletion left the admitted object")
				}
			})
		}
	})

	t.Run("checkpoint-fenced mode rejects candidate drift between consecutive proofs", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: append([]byte(nil), body...), sha: hashString(string(body)), etag: `"authorized"`}
		remote.ignoreDeleteCondition = true
		foreignBody := bytes.Repeat([]byte("x"), len(body))
		foreign := fakeObject{body: foreignBody, sha: hashString(string(foreignBody)), etag: `"foreign-second-proof"`}
		remote.mutateOnNthObjectOpen[key] = fakeObjectOpenMutation{at: 2, object: foreign}
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.WithCheckpointFencedDeletion().Run(context.Background(), requestFixture(TargetCloudflare, plan, "asset-delete-checkpoint-fenced-body-drift")); err == nil || !errors.Is(err, ErrDrift) {
			t.Fatalf("err=%v", err)
		}
		if remote.deleteAttempts[key] != 0 {
			t.Fatalf("drifting candidate reached live DELETE: %d", remote.deleteAttempts[key])
		}
		if retained, exists := remote.objects[key]; !exists || retained.etag != foreign.etag || !bytes.Equal(retained.body, foreign.body) {
			t.Fatalf("foreign second-proof bytes were not retained: exists=%t object=%#v", exists, retained)
		}
	})

	t.Run("checkpoint-fenced mode rejects remote fence drift before live deletion", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: append([]byte(nil), body...), sha: hashString(string(body)), etag: `"authorized"`}
		remote.ignoreDeleteCondition = true
		checkpointBody := []byte("foreign checkpoint")
		remote.mutateOnControlRead[CheckpointKey] = map[int]fakeObject{2: {
			body: checkpointBody, sha: digestBytes(checkpointBody), etag: `"foreign-checkpoint"`,
		}}
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		_, err := publisher.WithCheckpointFencedDeletion().Run(context.Background(), requestFixture(TargetCloudflare, plan, "asset-delete-checkpoint-fenced-lock-drift"))
		if err == nil || !errors.Is(err, ErrDrift) || !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "publication fence") {
			t.Fatalf("err=%v", err)
		}
		if remote.deleteAttempts[key] != 0 {
			t.Fatalf("checkpoint drift reached live DELETE: %d", remote.deleteAttempts[key])
		}
		if retained, exists := remote.objects[key]; !exists || retained.etag != `"authorized"` {
			t.Fatalf("authorized candidate was not retained after fence drift: exists=%t object=%#v", exists, retained)
		}
	})

	t.Run("checkpoint-fenced mode rechecks fence after second body proof", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: append([]byte(nil), body...), sha: hashString(string(body)), etag: `"authorized"`}
		remote.ignoreDeleteCondition = true
		checkpointBody := []byte("foreign checkpoint after second proof")
		remote.mutateOnControlRead[CheckpointKey] = map[int]fakeObject{3: {
			body: checkpointBody, sha: digestBytes(checkpointBody), etag: `"foreign-checkpoint-after-proof"`,
		}}
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		_, err := publisher.WithCheckpointFencedDeletion().Run(context.Background(), requestFixture(TargetCloudflare, plan, "asset-delete-checkpoint-fenced-lock-drift-after-proof"))
		if err == nil || !errors.Is(err, ErrDrift) || !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "immediately before") {
			t.Fatalf("err=%v", err)
		}
		if remote.deleteAttempts[key] != 0 {
			t.Fatalf("post-proof checkpoint drift reached live DELETE: %d", remote.deleteAttempts[key])
		}
		if retained, exists := remote.objects[key]; !exists || retained.etag != `"authorized"` {
			t.Fatalf("authorized candidate was not retained after post-proof fence drift: exists=%t object=%#v", exists, retained)
		}
	})

	t.Run("checkpoint-fenced response loss replays without a second live deletion", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: append([]byte(nil), body...), sha: hashString(string(body)), etag: `"authorized"`}
		remote.ignoreDeleteCondition = true
		remote.failDeleteAfterApply = true
		journal := filepath.Join(t.TempDir(), "journal")
		request := requestFixture(TargetCloudflare, plan, "asset-delete-checkpoint-fenced-response-loss")
		first := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, journal, Hooks{}).WithCheckpointFencedDeletion()
		if _, err := first.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "response loss") {
			t.Fatalf("first err=%v", err)
		}
		if _, exists := remote.objects[key]; exists || remote.deleteAttempts[key] != 1 {
			t.Fatalf("first response-loss outcome exists=%t deletes=%d", exists, remote.deleteAttempts[key])
		}
		second := NewR2CloudflarePublisher(remote, DirectorySource{Root: t.TempDir()}, journal, Hooks{}).WithCheckpointFencedDeletion()
		result, err := second.Run(context.Background(), request)
		if err != nil || !result.RemoteRefReady {
			t.Fatalf("replay result=%#v err=%v", result, err)
		}
		if remote.deleteAttempts[key] != 1 {
			t.Fatalf("response-loss replay issued another live DELETE: %d", remote.deleteAttempts[key])
		}
	})

	t.Run("committed COS replay retains the durable generation-lock delete fence", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: append([]byte(nil), body...), sha: hashString(string(body)), etag: `"authorized"`}
		remote.ignoreDeleteCondition = true
		journal := filepath.Join(t.TempDir(), "journal")
		request := requestFixture(TargetTencent, plan, "asset-delete-checkpoint-fenced-cos-committed-repair")
		publisher := NewCOSEdgeOnePublisher(remote, DirectorySource{Root: t.TempDir()}, journal, Hooks{}).WithCheckpointFencedDeletion()
		first, err := publisher.Run(context.Background(), request)
		if err != nil || !first.RemoteRefReady {
			t.Fatalf("first result=%#v err=%v", first, err)
		}
		remote.objects[key] = fakeObject{body: append([]byte(nil), body...), sha: hashString(string(body)), etag: `"authorized-restored"`}
		second, err := publisher.Run(context.Background(), request)
		if err != nil || !second.RemoteRefReady {
			t.Fatalf("committed repair result=%#v err=%v", second, err)
		}
		if _, exists := remote.objects[key]; exists {
			t.Fatal("committed COS repair left the exact restored candidate")
		}
		if remote.deleteAttempts[key] != 2 {
			t.Fatalf("COS committed repair live deletes=%d want=2", remote.deleteAttempts[key])
		}
	})

	t.Run("checkpoint-fenced mode fails closed when concrete provider omits fallback", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: append([]byte(nil), body...), sha: hashString(string(body)), etag: `"authorized"`}
		remote.ignoreDeleteCondition = true
		provider := r2WithoutCheckpointFencedDelete{remote: remote}
		publisher := NewR2CloudflarePublisher(provider, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		if _, err := publisher.WithCheckpointFencedDeletion().Run(context.Background(), requestFixture(TargetCloudflare, plan, "asset-delete-checkpoint-fenced-provider-missing")); err == nil || !errors.Is(err, ErrCapability) {
			t.Fatalf("err=%v", err)
		}
		if remote.deleteAttempts[key] != 0 {
			t.Fatalf("missing fallback provider reached live DELETE: %d", remote.deleteAttempts[key])
		}
		if _, exists := remote.objects[key]; !exists {
			t.Fatal("missing fallback provider removed the live object")
		}
	})
}

func TestR2SagaRecoversAtEveryDurablePhase(t *testing.T) {
	phases := []Phase{
		PhasePlanned, PhaseLocked, PhaseImmutableUploaded, PhaseGenerationReady,
		PhasePointerFlipped, PhasePurged, PhaseVerified,
		PhaseCheckpointCommitted, PhaseRemoteRefReady,
	}
	for _, phase := range phases {
		phase := phase
		t.Run(string(phase), func(t *testing.T) {
			t.Parallel()
			root, plan := sourcePlan(t)
			remote := newFakeRemote()
			failed := false
			hooks := Hooks{AfterPhase: func(_ TargetName, current Phase) error {
				if current == phase && !failed {
					failed = true
					return errors.New("injected crash")
				}
				return nil
			}}
			journalDir := filepath.Join(t.TempDir(), "journal")
			request := requestFixture(TargetCloudflare, plan, "recover-"+string(phase))
			first := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, hooks)
			if _, err := first.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "injected crash") {
				t.Fatalf("first run did not stop after %s: %v", phase, err)
			}
			second := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
			result, err := second.Run(context.Background(), request)
			if err != nil {
				t.Fatalf("resume after %s: %v", phase, err)
			}
			if !result.RemoteRefReady || result.Phase != PhaseRemoteRefReady {
				t.Fatalf("resume after %s incomplete: %#v", phase, result)
			}
			if result.CheckpointETag == "" || !hexSHA256Pattern.MatchString(result.CheckpointSHA256) || !hexSHA256Pattern.MatchString(result.GenerationSHA256) {
				t.Fatalf("remote tracking identity missing after %s: %#v", phase, result)
			}
			checkpoint := remote.get(CheckpointKey)
			decoded, err := DecodeCheckpoint(checkpoint.Body)
			if err != nil || decoded.Phase != PhaseCheckpointCommitted || decoded.TransactionID != request.TransactionID {
				t.Fatalf("invalid final checkpoint after %s: %#v, %v", phase, decoded, err)
			}
			wantPurges := 1
			if phase == PhasePurged || phase == PhaseVerified || phase == PhaseCheckpointCommitted || phase == PhaseRemoteRefReady {
				// Recovery replays mutable pointers. Any prior purge/verification
				// evidence is therefore stale and must be repeated before commit.
				// Once the remote checkpoint is final, replay also reissues the
				// exact purge closure before trusting CDN reads again.
				wantPurges = 2
			}
			if len(remote.purgeCalls) != wantPurges {
				t.Fatalf("phase-aware recovery purge count after %s=%d want=%d", phase, len(remote.purgeCalls), wantPurges)
			}
		})
	}
}

func TestCommittedCheckpointRepairsAPTLegacyAndPointerDrift(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	objects := []struct {
		path  string
		body  string
		class ObjectClass
	}{
		{path: "apt/repo/dists/jammy/Release", body: "release-body", class: ObjectLegacyMetadata},
		{path: "apt/repo/dists/jammy/InRelease", body: "signed-release-body", class: ObjectPointer},
	}
	plan := Plan{Schema: planSchema}
	for _, object := range objects {
		full := filepath.Join(root, filepath.FromSlash(object.path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(object.body), 0o644); err != nil {
			t.Fatal(err)
		}
		plan.Objects = append(plan.Objects, PlannedObject{
			SourcePath: object.path, RemoteKey: object.path, Size: int64(len(object.body)),
			SHA256: hashString(object.body), Class: object.class,
		})
	}
	var err error
	plan, err = plan.WithCDN("https://cdn.test/")
	if err != nil {
		t.Fatal(err)
	}
	remote := newFakeRemote()
	journalDir := filepath.Join(t.TempDir(), "journal")
	crashed := false
	request := requestFixture(TargetCloudflare, plan, "committed-apt-mutable-repair")
	first := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{AfterPhase: func(_ TargetName, phase Phase) error {
		if phase == PhaseCheckpointCommitted && !crashed {
			crashed = true
			return errors.New("checkpoint crash")
		}
		return nil
	}})
	if _, err := first.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "checkpoint crash") {
		t.Fatalf("first run err=%v", err)
	}
	remote.mutex.Lock()
	delete(remote.objects, objects[0].path)
	remote.objects[objects[1].path] = fakeObject{body: []byte("corrupt-pointer"), sha: hashString("corrupt-pointer"), etag: `"foreign"`}
	remote.mutex.Unlock()

	result, err := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{}).Run(context.Background(), request)
	if err != nil || !result.RemoteRefReady {
		t.Fatalf("repair result=%#v err=%v", result, err)
	}
	for _, object := range objects {
		if got := string(remote.get(object.path).Body); got != object.body {
			t.Fatalf("repaired %s=%q want=%q", object.path, got, object.body)
		}
		if remote.putAttempts[object.path] != 2 {
			t.Fatalf("%s attempts=%d want initial+repair", object.path, remote.putAttempts[object.path])
		}
	}
	if len(remote.purgeCalls) != 2 {
		t.Fatalf("checkpoint repair purge calls=%d want 2", len(remote.purgeCalls))
	}
}

func TestPublishUploadPoolIsBoundedAndConcurrent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	plan := Plan{Schema: planSchema}
	for index := 0; index < 12; index++ {
		key := fmt.Sprintf("pool/concurrent-%02d.pkg", index)
		body := fmt.Sprintf("package-%02d", index)
		full := filepath.Join(root, filepath.FromSlash(key))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		plan.Objects = append(plan.Objects, PlannedObject{
			SourcePath: key, RemoteKey: key, Size: int64(len(body)), SHA256: hashString(body), Class: ObjectImmutable,
		})
	}
	var err error
	plan, err = plan.WithCDN("https://cdn.test/")
	if err != nil {
		t.Fatal(err)
	}
	remote := newFakeRemote()
	remote.putDelay = 25 * time.Millisecond
	remote.delayPrefix = "pool/concurrent-"
	remote.delayBarrier = make(chan struct{}, 3)
	publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{}).WithWorkers(3)
	if _, err := publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, "bounded-upload-pool")); err != nil {
		t.Fatal(err)
	}
	remote.mutex.Lock()
	peak := remote.maxPuts
	remote.mutex.Unlock()
	if peak != 3 {
		t.Fatalf("upload concurrency peak=%d, want configured bound 3", peak)
	}
	invalid := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "invalid-journal"), Hooks{}).WithWorkers(0)
	if _, err := invalid.Run(context.Background(), requestFixture(TargetCloudflare, plan, "invalid-upload-pool")); err == nil || !strings.Contains(err.Error(), "worker count") {
		t.Fatalf("non-positive worker count was accepted: %v", err)
	}
	oversized := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "oversized-journal"), Hooks{}).WithWorkers(maxPublishWorkers + 1)
	if _, err := oversized.Run(context.Background(), requestFixture(TargetCloudflare, plan, "oversized-upload-pool")); err == nil || !strings.Contains(err.Error(), "between 1 and 64") {
		t.Fatalf("oversized worker count was accepted: %v", err)
	}
}

func TestAdoptedImmutableMustExistAndNeverUploads(t *testing.T) {
	const key = "pkg/adopted.bin"
	body := []byte("adopted-origin")
	root := t.TempDir()
	full := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, body, 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{{
		SourcePath: key, RemoteKey: key, Size: int64(len(body)), SHA256: hashString(string(body)), Class: ObjectAdoptedImmutable,
	}}}).WithCDN("https://cdn.test/")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("matching legacy object", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: append([]byte(nil), body...), etag: `"legacy"`}
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		result, err := publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, "adopted-match"))
		if err != nil || !result.RemoteRefReady {
			t.Fatalf("result=%#v err=%v", result, err)
		}
		if remote.putAttempts[key] != 0 || remote.objectOpens[key] != 1 {
			t.Fatalf("adopted side effects puts=%d origin_gets=%d", remote.putAttempts[key], remote.objectOpens[key])
		}
	})

	for _, test := range []struct {
		name   string
		object *fakeObject
		mutate *fakeObject
	}{
		{name: "missing"},
		{name: "same-size-rewrite", object: &fakeObject{body: []byte("changed-origin"), etag: `"changed"`}},
		{name: "wrong-metadata", object: &fakeObject{body: append([]byte(nil), body...), sha: strings.Repeat("0", 64), etag: `"wrong-meta"`}},
		{name: "empty-etag", object: &fakeObject{body: append([]byte(nil), body...)}},
		{name: "head-get-etag-drift", object: &fakeObject{body: append([]byte(nil), body...), etag: `"before"`}, mutate: &fakeObject{body: append([]byte(nil), body...), etag: `"after"`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			remote := newFakeRemote()
			if test.object != nil {
				remote.objects[key] = *test.object
			}
			if test.mutate != nil {
				remote.mutateOnOpen[key] = *test.mutate
			}
			publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{})
			if _, err := publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, "adopted-"+test.name)); err == nil || !errors.Is(err, ErrDrift) {
				t.Fatalf("err=%v", err)
			}
			if remote.get(CheckpointKey).Exists || remote.putAttempts[CheckpointKey] != 0 || remote.putAttempts[key] != 0 {
				t.Fatalf("failed adopted validation mutated control/payload checkpoint=%#v checkpoint_puts=%d payload_puts=%d", remote.get(CheckpointKey), remote.putAttempts[CheckpointKey], remote.putAttempts[key])
			}
		})
	}
}

func TestExistingImmutableForgedMetadataFailsBeforePointerFlip(t *testing.T) {
	for _, target := range []TargetName{TargetCloudflare, TargetTencent} {
		t.Run(string(target), func(t *testing.T) {
			root, plan := sourcePlan(t)
			immutable := plan.objects(ObjectImmutable)[0]
			pointer := plan.objects(ObjectPointer)[0]
			wrong := bytes.Repeat([]byte("x"), int(immutable.Size))
			remote := newFakeRemote()
			remote.objects[immutable.RemoteKey] = fakeObject{
				body: wrong, sha: immutable.SHA256, etag: `"forged-immutable-metadata"`,
			}
			journalDir := filepath.Join(t.TempDir(), "journal")
			var publisher *Publisher
			if target == TargetCloudflare {
				publisher = NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
			} else {
				publisher = NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
			}
			result, err := publisher.Run(t.Context(), requestFixture(target, plan, "forged-existing-immutable-"+string(target)))
			if err == nil || !errors.Is(err, ErrConflict) || result.RemoteRefReady {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			if remote.get(pointer.RemoteKey).Exists || remote.putAttempts[pointer.RemoteKey] != 0 {
				t.Fatalf("forged immutable became visible through pointer: object=%#v puts=%d", remote.get(pointer.RemoteKey), remote.putAttempts[pointer.RemoteKey])
			}
			if remote.objectOpens[immutable.RemoteKey] == 0 {
				t.Fatal("immutable conflict was accepted without streamed body proof")
			}
		})
	}
}

func TestAdoptedImmutableRevalidatesAcrossJournalAndCommittedReplay(t *testing.T) {
	const key = "pkg/replay.bin"
	body := []byte("replay-origin")
	root := t.TempDir()
	full := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, body, 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{{
		SourcePath: key, RemoteKey: key, Size: int64(len(body)), SHA256: hashString(string(body)), Class: ObjectAdoptedImmutable,
	}}}).WithCDN("https://cdn.test/")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("completed object in locked journal", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: append([]byte(nil), body...), etag: `"first"`}
		journalDir := filepath.Join(t.TempDir(), "journal")
		crashed := false
		first := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{AfterPhase: func(_ TargetName, phase Phase) error {
			if phase == PhaseLocked && !crashed {
				crashed = true
				return errors.New("locked crash")
			}
			return nil
		}})
		request := requestFixture(TargetCloudflare, plan, "adopted-locked-replay")
		if _, err := first.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "locked crash") {
			t.Fatalf("first err=%v", err)
		}
		remote.mutex.Lock()
		remote.objects[key] = fakeObject{body: []byte("tamper-origin"), etag: `"changed"`}
		remote.mutex.Unlock()
		second := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
		if _, err := second.Run(context.Background(), request); err == nil || !errors.Is(err, ErrDrift) {
			t.Fatalf("replay err=%v", err)
		}
		if remote.objectOpens[key] < 2 {
			t.Fatalf("origin was not re-read across locked replay: %d", remote.objectOpens[key])
		}
	})

	t.Run("already committed checkpoint", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[key] = fakeObject{body: append([]byte(nil), body...), etag: `"first"`}
		journalDir := filepath.Join(t.TempDir(), "journal")
		crashed := false
		first := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{AfterPhase: func(_ TargetName, phase Phase) error {
			if phase == PhaseCheckpointCommitted && !crashed {
				crashed = true
				return errors.New("committed crash")
			}
			return nil
		}})
		request := requestFixture(TargetCloudflare, plan, "adopted-committed-replay")
		if _, err := first.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "committed crash") {
			t.Fatalf("first err=%v", err)
		}
		remote.mutex.Lock()
		remote.cdnObjects[plan.Verify[0].URL] = fakeObject{body: append([]byte(nil), body...)}
		remote.objects[key] = fakeObject{body: []byte("tamper-origin"), etag: `"changed"`}
		cdnBefore := remote.openAttempts[plan.Verify[0].URL]
		remote.mutex.Unlock()
		second := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
		if result, err := second.Run(context.Background(), request); err == nil || !errors.Is(err, ErrDrift) || result.RemoteRefReady {
			t.Fatalf("replay result=%#v err=%v", result, err)
		}
		if remote.openAttempts[plan.Verify[0].URL] != cdnBefore {
			t.Fatal("stale CDN was consulted before adopted origin replay validation")
		}
	})
}

func TestVerifiedPointerReplayRepurgesAndReverifies(t *testing.T) {
	const key = "metadata/latest"
	body := []byte("pointer-body")
	root := t.TempDir()
	full := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, body, 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := (Plan{Schema: planSchema, Objects: []PlannedObject{{
		SourcePath: key, RemoteKey: key, Size: int64(len(body)), SHA256: hashString(string(body)), Class: ObjectPointer,
	}}}).WithCDN("https://cdn.test/")
	if err != nil {
		t.Fatal(err)
	}
	remote := newFakeRemote()
	journalDir := filepath.Join(t.TempDir(), "journal")
	crashed := false
	first := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{AfterPhase: func(_ TargetName, phase Phase) error {
		if phase == PhaseVerified && !crashed {
			crashed = true
			return errors.New("verified crash")
		}
		return nil
	}})
	request := requestFixture(TargetCloudflare, plan, "verified-pointer-replay")
	if _, err := first.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "verified crash") {
		t.Fatalf("first err=%v", err)
	}
	remote.mutex.Lock()
	purgesBefore := len(remote.purgeCalls)
	getsBefore := remote.openAttempts[plan.Verify[0].URL]
	remote.cdnObjects[plan.Verify[0].URL] = fakeObject{body: []byte("stale-cache")}
	remote.mutex.Unlock()
	second := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
	result, err := second.Run(context.Background(), request)
	if err != nil || !result.RemoteRefReady {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if len(remote.purgeCalls) != purgesBefore+1 || remote.openAttempts[plan.Verify[0].URL] != getsBefore+1 {
		t.Fatalf("replay purges=%d/%d verifies=%d/%d", purgesBefore, len(remote.purgeCalls), getsBefore, remote.openAttempts[plan.Verify[0].URL])
	}
}

func TestYUMSnapshotCopyAvoidsRetransmitAndFallsBackWhenSourceMissing(t *testing.T) {
	t.Parallel()
	const sourceKey = "yum/repo/Packages/pkg.rpm"
	const destinationKey = ".sow/gated/snapshots/jammy-20260712/yum/yum/repo/Packages/pkg.rpm"
	body := []byte("rpm payload")
	root := t.TempDir()
	full := filepath.Join(root, filepath.FromSlash(sourceKey))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, body, 0o644); err != nil {
		t.Fatal(err)
	}
	routeBody, err := SnapshotRouteBody("jammy-20260712", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "route.json"), routeBody, 0o644); err != nil {
		t.Fatal(err)
	}
	plan := Plan{Schema: planSchema, Objects: []PlannedObject{
		{
			SourcePath: sourceKey, RemoteKey: destinationKey, CopySource: sourceKey,
			Size: int64(len(body)), SHA256: hashString(string(body)), Class: ObjectCopyImmutable,
			CDNPath: "pro/v1/basic/_sow/v1/snapshots/jammy-20260712/yum/yum/repo/Packages/pkg.rpm",
		},
		{
			SourcePath: "route.json", RemoteKey: ".sow/snapshots/jammy-20260712.json",
			Size: int64(len(routeBody)), SHA256: digestBytes(routeBody), Class: ObjectPointer,
			CDNPath: "pro/v1/basic/_sow/v1/snapshots/jammy-20260712/_route.json",
		},
	}}
	for _, name := range []string{"primary.xml.zst", "filelists.xml.zst", "other.xml.zst", "repomd.xml", "repomd.xml.asc"} {
		metadataBody := []byte("snapshot-" + name)
		source := "generated/" + name
		if err := os.MkdirAll(filepath.Join(root, "generated"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(source)), metadataBody, 0o644); err != nil {
			t.Fatal(err)
		}
		plan.Objects = append(plan.Objects, PlannedObject{
			SourcePath: source,
			RemoteKey:  ".sow/gated/generations/00000000000000000001/yum/yum/repo/repodata/" + name,
			Size:       int64(len(metadataBody)), SHA256: digestBytes(metadataBody), Class: ObjectMetadata,
			CDNPath: "pro/v1/basic/_sow/v1/snapshots/jammy-20260712/yum/yum/repo/repodata/" + name,
		})
	}
	plan, err = plan.WithCDN("https://cdn.example/")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("remote source matches", func(t *testing.T) {
		remote := newFakeRemote()
		remote.objects[sourceKey] = fakeObject{body: append([]byte(nil), body...), sha: hashString(string(body)), etag: `"source"`}
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		request := requestFixture(TargetCloudflare, plan, "snapshot-copy")
		request.Generation.IntentView, request.Generation.IntentSnapshot = "snapshot", "jammy-20260712"
		if _, err := publisher.Run(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		if remote.copyAttempts[destinationKey] != 1 || remote.putAttempts[destinationKey] != 0 {
			t.Fatalf("server-side copy attempts=%d destination uploads=%d", remote.copyAttempts[destinationKey], remote.putAttempts[destinationKey])
		}
	})

	t.Run("remote source missing", func(t *testing.T) {
		remote := newFakeRemote()
		publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{})
		request := requestFixture(TargetCloudflare, plan, "snapshot-copy-fallback")
		request.Generation.IntentView, request.Generation.IntentSnapshot = "snapshot", "jammy-20260712"
		if _, err := publisher.Run(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		if remote.copyAttempts[destinationKey] != 0 || remote.putAttempts[destinationKey] != 1 {
			t.Fatalf("missing source copy attempts=%d fallback uploads=%d", remote.copyAttempts[destinationKey], remote.putAttempts[destinationKey])
		}
	})
}

func TestAPTSnapshotSharedPoolIsHeadReusedWithoutRetransmit(t *testing.T) {
	t.Parallel()
	const key = "apt/repo/pool/main/p/pkg.deb"
	body := []byte("deb payload")
	root := t.TempDir()
	full := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, body, 0o644); err != nil {
		t.Fatal(err)
	}
	plan := Plan{Schema: planSchema, Objects: []PlannedObject{{
		SourcePath: key, RemoteKey: key, Size: int64(len(body)), SHA256: hashString(string(body)), Class: ObjectReuseImmutable,
	}}}
	var err error
	plan, err = plan.WithCDN("https://cdn.example/")
	if err != nil {
		t.Fatal(err)
	}
	remote := newFakeRemote()
	remote.objects[key] = fakeObject{body: append([]byte(nil), body...), sha: hashString(string(body)), etag: `"shared"`}
	publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{})
	if _, err := publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, "apt-snapshot-reuse")); err != nil {
		t.Fatal(err)
	}
	if remote.putAttempts[key] != 0 {
		t.Fatalf("shared APT pool object was retransmitted %d times", remote.putAttempts[key])
	}
}

func TestYUMAliasCompatibilitySequenceRequiresPinnedRouteAndReplays(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	const generation = "00000000000000000001"
	const generatedRoot = ".sow/generations/" + generation + "/yum/yum/rocky/9/x86_64/repodata/"
	const aliasRoot = "yum/rocky/9/x86_64/repodata/"
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
	const mirror = "https://cdn.test/_sow/v1/g/00000000000000000001/yum/rocky/9/x86_64/\n"
	mirrorSource := filepath.Join(root, "mirrorlist.txt")
	if err := os.WriteFile(mirrorSource, []byte(mirror), 0o644); err != nil {
		t.Fatal(err)
	}
	plan.Objects = append(plan.Objects, PlannedObject{
		SourcePath: "mirrorlist.txt", RemoteKey: "_sow/v1/mirrorlist/latest/rocky/9/x86_64.txt",
		Size: int64(len(mirror)), SHA256: hashString(mirror), Class: ObjectPointer,
	})
	var err error
	plan, err = plan.WithCDN("https://cdn.test/")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.PurgeURLs) != 3 {
		t.Fatalf("YUM compatibility+strong-route purge count=%d, want 3: %v", len(plan.PurgeURLs), plan.PurgeURLs)
	}
	remote := newFakeRemote()
	failed := false
	hooks := Hooks{AfterPhase: func(_ TargetName, phase Phase) error {
		if phase == PhasePointerFlipped && !failed {
			failed = true
			return errors.New("injected crash after YUM alias pair")
		}
		return nil
	}}
	journalDir := filepath.Join(t.TempDir(), "journal")
	request := requestFixture(TargetCloudflare, plan, "yum-alias-replay")
	request.Generation.Refs = request.Generation.Refs[:1]
	channel := ChannelState{
		View: "latest", Repo: "rocky", OS: "9", Arch: "x86_64", Generation: 1,
		RemoteKey: ".sow/channels/latest/rocky/9/x86_64.json", LegacyRoot: "yum/rocky/9/x86_64",
	}
	channelBody, err := channel.CanonicalBody()
	if err != nil {
		t.Fatal(err)
	}
	channel.BodySHA256 = digestBytes(channelBody)
	request.Generation.Channels = []ChannelState{channel}

	assertInvalidClosure := func(t *testing.T, transaction string, mutate func([]PlannedObject) []PlannedObject, want string) {
		t.Helper()
		objects := append([]PlannedObject(nil), plan.Objects...)
		objects = mutate(objects)
		candidate, err := (Plan{Schema: planSchema, Objects: objects}).WithCDN("https://cdn.test/")
		if err != nil {
			t.Fatalf("close adversarial plan: %v", err)
		}
		badRequest := request
		badRequest.TransactionID = transaction
		badRequest.Plan = candidate
		badRemote := newFakeRemote()
		badPublisher := NewR2CloudflarePublisher(badRemote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "bad-journal"), Hooks{})
		if _, err := badPublisher.Run(context.Background(), badRequest); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("adversarial YUM closure was accepted, want %q: %v", want, err)
		}
		if badRemote.putAttempts[CheckpointKey] != 0 {
			t.Fatal("adversarial YUM closure touched the remote lock")
		}
	}

	t.Run("alias metadata must equal generation", func(t *testing.T) {
		assertInvalidClosure(t, "yum-alias-content-mismatch", func(objects []PlannedObject) []PlannedObject {
			for index := range objects {
				if objects[index].RemoteKey == aliasRoot+"primary.xml.zst" {
					objects[index].SHA256 = hashString("forged-alias-primary")
				}
			}
			return objects
		}, "requires identical compatibility alias")
	})

	t.Run("all standard metadata kinds required", func(t *testing.T) {
		assertInvalidClosure(t, "yum-missing-other", func(objects []PlannedObject) []PlannedObject {
			kept := objects[:0]
			for _, object := range objects {
				if strings.HasSuffix(object.RemoteKey, "/other.xml.zst") {
					continue
				}
				kept = append(kept, object)
			}
			return kept
		}, "exactly one other object")
	})

	t.Run("current channel requires pointer", func(t *testing.T) {
		assertInvalidClosure(t, "yum-missing-mirrorlist", func(objects []PlannedObject) []PlannedObject {
			kept := objects[:0]
			for _, object := range objects {
				if object.RemoteKey == "_sow/v1/mirrorlist/latest/rocky/9/x86_64.txt" {
					continue
				}
				kept = append(kept, object)
			}
			return kept
		}, "requires generation-pinned pointer")
	})

	t.Run("same physical owner may expose multiple OS aliases", func(t *testing.T) {
		alias := ChannelState{
			View: "latest", Repo: "rocky", OS: "el10", Arch: "x86_64", Generation: 1,
			RemoteKey: ".sow/channels/latest/rocky/el10/x86_64.json", LegacyRoot: channel.LegacyRoot,
		}
		body, err := alias.CanonicalBody()
		if err != nil {
			t.Fatal(err)
		}
		alias.BodySHA256 = digestBytes(body)
		candidate := request.Generation
		candidate.Channels = []ChannelState{channel, alias}
		aliasPlan := plan
		aliasPlan.Objects = append(append([]PlannedObject(nil), plan.Objects...), PlannedObject{
			SourcePath: "mirrorlist.txt", RemoteKey: "_sow/v1/mirrorlist/latest/rocky/el10/x86_64.txt",
			Size: int64(len(mirror)), SHA256: hashString(mirror), Class: ObjectPointer,
		})
		aliasPlan, err = (Plan{Schema: planSchema, Objects: aliasPlan.Objects}).WithCDN("https://cdn.test/")
		if err != nil {
			t.Fatal(err)
		}
		if err := validateYUMAliasAtomicRoutes(candidate, aliasPlan); err != nil {
			t.Fatalf("same repo+arch OS alias vector was rejected: %v", err)
		}

		alias.Repo = "other-repo"
		alias.RemoteKey = ".sow/channels/latest/other-repo/el10/x86_64.json"
		body, err = alias.CanonicalBody()
		if err != nil {
			t.Fatal(err)
		}
		alias.BodySHA256 = digestBytes(body)
		candidate.Channels = []ChannelState{channel, alias}
		if err := validateYUMAliasAtomicRoutes(candidate, aliasPlan); err == nil || !strings.Contains(err.Error(), "illegally share legacy root") {
			t.Fatalf("cross-repository shared legacy root was accepted: %v", err)
		}
	})

	unsafeRequest := request
	unsafeRequest.TransactionID = "yum-alias-without-strong-route"
	unsafeRequest.Generation.Channels = nil
	unsafeRemote := newFakeRemote()
	unsafePublisher := NewR2CloudflarePublisher(unsafeRemote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "unsafe-journal"), Hooks{})
	if _, err := unsafePublisher.Run(context.Background(), unsafeRequest); err == nil || !strings.Contains(err.Error(), "current target channel") {
		t.Fatalf("raw alias-only publication was not rejected: %v", err)
	}
	if unsafeRemote.putAttempts[CheckpointKey] != 0 {
		t.Fatal("unsafe alias-only publication touched the remote lock")
	}

	// A lost response after the first alias PUT leaves an externally observable
	// mixed raw pair. Preserve this adversarial witness so sequential asc->xml
	// uploads can never be relabelled as atomic. The generation-pinned pointer
	// remains unflipped, therefore supported mirrorlist clients still see the
	// complete prior generation.
	windowRemote := newFakeRemote()
	windowRemote.objects[aliasRoot+"repomd.xml"] = fakeObject{body: []byte("old-repomd"), sha: hashString("old-repomd"), etag: `"old-xml"`}
	windowRemote.objects[aliasRoot+"repomd.xml.asc"] = fakeObject{body: []byte("old-signature"), sha: hashString("old-signature"), etag: `"old-asc"`}
	windowRemote.failAfterPutKey = aliasRoot + "repomd.xml.asc"
	windowRequest := request
	windowRequest.TransactionID = "yum-alias-observable-window"
	windowPublisher := NewR2CloudflarePublisher(windowRemote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "window-journal"), Hooks{})
	if _, err := windowPublisher.Run(context.Background(), windowRequest); err == nil || !strings.Contains(err.Error(), "response loss") {
		t.Fatalf("alias transition witness did not stop between the pair: %v", err)
	}
	if got := string(windowRemote.get(aliasRoot + "repomd.xml").Body); got != "old-repomd" {
		t.Fatalf("raw alias witness unexpectedly advanced XML: %q", got)
	}
	if got := string(windowRemote.get(aliasRoot + "repomd.xml.asc").Body); got != "signed-generation" {
		t.Fatalf("raw alias witness did not expose the new signature: %q", got)
	}
	if windowRemote.get("_sow/v1/mirrorlist/latest/rocky/9/x86_64.txt").Exists {
		t.Fatal("generation-pinned mirrorlist advanced across an incomplete raw alias bridge")
	}

	first := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, hooks).WithWorkers(3)
	if _, err := first.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "injected crash") {
		t.Fatalf("first YUM alias publication did not stop after pointer closure: %v", err)
	}
	second := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{}).WithWorkers(3)
	result, err := second.Run(context.Background(), request)
	if err != nil || !result.RemoteRefReady {
		t.Fatalf("YUM alias recovery result=%#v err=%v", result, err)
	}

	remote.mutex.Lock()
	order := append([]string(nil), remote.putOrder...)
	attempts := make(map[string]int, len(remote.putAttempts))
	for key, count := range remote.putAttempts {
		attempts[key] = count
	}
	remote.mutex.Unlock()
	wantPair := []string{aliasRoot + "repomd.xml.asc", aliasRoot + "repomd.xml", aliasRoot + "repomd.xml.asc", aliasRoot + "repomd.xml"}
	var gotPair []string
	for _, key := range order {
		if key == aliasRoot+"repomd.xml.asc" || key == aliasRoot+"repomd.xml" {
			gotPair = append(gotPair, key)
		}
	}
	if fmt.Sprint(gotPair) != fmt.Sprint(wantPair) {
		t.Fatalf("YUM alias pair order=%v, want %v; full order=%v", gotPair, wantPair, order)
	}
	if attempts[aliasRoot+"primary.xml.zst"] != 2 {
		t.Fatalf("completed YUM alias metadata was not replayed as phase closure: attempts=%v", attempts)
	}
	journalBytes, err := readJournalFile(result.JournalPath)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := decodeJournal(journalBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range []string{
		string(ObjectYUMAliasMetadata) + ":" + aliasRoot + "primary.xml.zst",
		string(ObjectYUMAliasPointer) + ":" + aliasRoot + "repomd.xml.asc",
		string(ObjectYUMAliasPointer) + ":" + aliasRoot + "repomd.xml",
	} {
		if !journalHas(&journal, identity) {
			t.Fatalf("YUM alias journal closure missing %s: %v", identity, journal.CompletedObjects)
		}
	}
	if len(remote.purgeCalls) != 1 || len(remote.purgeCalls[0]) != 3 {
		t.Fatalf("YUM alias bridge and generation pointer purge closure is incomplete: %v", remote.purgeCalls)
	}

	// A final remote checkpoint is ownership evidence, not proof that mutable
	// compatibility aliases and the generation-pinned mirrorlist remained
	// intact. Crash after that commit, damage every mutable class, and require a
	// retry to restore the ordered closure before it reports the local ref ready.
	committedRemote := newFakeRemote()
	committedJournal := filepath.Join(t.TempDir(), "committed-journal")
	committedRequest := request
	committedRequest.TransactionID = "yum-alias-committed-repair"
	committedCrash := false
	committedPublisher := NewR2CloudflarePublisher(committedRemote, DirectorySource{Root: root}, committedJournal, Hooks{AfterPhase: func(_ TargetName, phase Phase) error {
		if phase == PhaseCheckpointCommitted && !committedCrash {
			committedCrash = true
			return errors.New("committed YUM crash")
		}
		return nil
	}})
	if _, err := committedPublisher.Run(context.Background(), committedRequest); err == nil || !strings.Contains(err.Error(), "committed YUM crash") {
		t.Fatalf("committed YUM first run err=%v", err)
	}
	mutableBodies := make(map[string]string)
	committedRemote.mutex.Lock()
	for _, object := range plan.Objects {
		if object.Class != ObjectYUMAliasMetadata && object.Class != ObjectYUMAliasPointer && object.Class != ObjectPointer {
			continue
		}
		body, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(object.SourcePath)))
		if readErr != nil {
			committedRemote.mutex.Unlock()
			t.Fatal(readErr)
		}
		mutableBodies[object.RemoteKey] = string(body)
		if object.Class == ObjectYUMAliasMetadata {
			delete(committedRemote.objects, object.RemoteKey)
		} else {
			committedRemote.objects[object.RemoteKey] = fakeObject{body: []byte("corrupt-mutable"), sha: hashString("corrupt-mutable"), etag: `"foreign"`}
		}
	}
	committedRemote.mutex.Unlock()
	committedResult, err := NewR2CloudflarePublisher(committedRemote, DirectorySource{Root: root}, committedJournal, Hooks{}).WithWorkers(3).Run(context.Background(), committedRequest)
	if err != nil || !committedResult.RemoteRefReady {
		t.Fatalf("committed YUM repair result=%#v err=%v", committedResult, err)
	}
	for key, want := range mutableBodies {
		if got := string(committedRemote.get(key).Body); got != want {
			t.Fatalf("committed YUM repaired %s=%q want=%q", key, got, want)
		}
		if committedRemote.putAttempts[key] != 2 {
			t.Fatalf("committed YUM %s attempts=%d want initial+repair", key, committedRemote.putAttempts[key])
		}
	}
	if len(committedRemote.purgeCalls) != 2 {
		t.Fatalf("committed YUM purge calls=%d want 2", len(committedRemote.purgeCalls))
	}
}

func TestCompatibilityS0RollbackSagaReplaysWritesDeletePurgeAndPreservesHistory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	const metadata = "yum/infra/x86_64/repodata/legacy-primary.xml.gz"
	const pointer = "yum/infra/x86_64/repodata/repomd.xml"
	const removed = "yum/infra/x86_64/Packages/p/pkg.rpm"
	bodies := map[string]string{metadata: "legacy-primary", pointer: "legacy-repomd"}
	plan := Plan{Schema: planSchema}
	for key, body := range bodies {
		full := filepath.Join(root, filepath.FromSlash(key))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		class := ObjectCompatibilityRollbackMetadata
		if key == pointer {
			class = ObjectCompatibilityRollbackPointer
		}
		plan.Objects = append(plan.Objects, PlannedObject{
			SourcePath: key, RemoteKey: key, Size: int64(len(body)), SHA256: hashString(body), Class: class, CDNPath: key,
		})
	}
	removedBody := []byte("candidate-package")
	plan.Deletes = []PlannedDelete{{
		Class: DeleteCompatibilityServing, SourcePath: removed, RemoteKey: removed,
		Size: int64(len(removedBody)), SHA256: digestBytes(removedBody), CDNPath: removed,
	}}
	var err error
	plan, err = plan.WithCDN("https://cdn.example/")
	if err != nil {
		t.Fatal(err)
	}
	remote := newFakeRemote()
	remote.objects[removed] = fakeObject{body: removedBody, sha: digestBytes(removedBody), etag: `"candidate"`}
	const generationHistory = ".sow/generations/00000000000000000007/yum/yum/infra/x86_64/repodata/repomd.xml"
	const unrelated = "yum/other/x86_64/repodata/repomd.xml"
	remote.objects[generationHistory] = fakeObject{body: []byte("history"), sha: hashString("history"), etag: `"history"`}
	remote.objects[unrelated] = fakeObject{body: []byte("other"), sha: hashString("other"), etag: `"other"`}
	remote.cdnObjects[plan.VerifyAbsent[0].URL] = fakeObject{body: append([]byte(nil), removedBody...)}

	failed := false
	hooks := Hooks{AfterPhase: func(_ TargetName, phase Phase) error {
		if phase == PhasePointerFlipped && !failed {
			failed = true
			return errors.New("injected crash after exact S0 flip")
		}
		return nil
	}}
	journal := filepath.Join(t.TempDir(), "journal")
	request := requestFixture(TargetCloudflare, plan, "compatibility-s0-rollback-replay")
	first := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journal, hooks)
	if _, err := first.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "injected crash") {
		t.Fatalf("first rollback run err=%v", err)
	}
	second := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journal, Hooks{})
	result, err := second.Run(context.Background(), request)
	if err != nil || !result.RemoteRefReady {
		t.Fatalf("rollback replay result=%#v err=%v", result, err)
	}
	remote.mutex.Lock()
	defer remote.mutex.Unlock()
	if remote.putAttempts[metadata] < 2 || remote.putAttempts[pointer] < 2 {
		t.Fatalf("mutable S0 closure was not replayed: metadata=%d pointer=%d", remote.putAttempts[metadata], remote.putAttempts[pointer])
	}
	firstMetadata, firstPointer := -1, -1
	for index, key := range remote.putOrder {
		if key == metadata && firstMetadata < 0 {
			firstMetadata = index
		}
		if key == pointer && firstPointer < 0 {
			firstPointer = index
		}
	}
	if firstMetadata < 0 || firstPointer < 0 || firstMetadata >= firstPointer {
		t.Fatalf("S0 pointer ordering is unsafe: %v", remote.putOrder)
	}
	if _, exists := remote.objects[removed]; exists {
		t.Fatal("candidate-only raw path survived rollback")
	}
	if _, exists := remote.objects[generationHistory]; !exists {
		t.Fatal("immutable compatibility generation history was deleted")
	}
	if _, exists := remote.objects[unrelated]; !exists {
		t.Fatal("unrelated route was deleted")
	}
	if _, exists := remote.cdnObjects[plan.VerifyAbsent[0].URL]; exists {
		t.Fatal("candidate-only raw CDN path survived purge/replay")
	}
	checkpoint, err := DecodeCheckpoint(remote.objects[CheckpointKey].body)
	if err != nil || checkpoint.Generation != request.Generation.Generation || checkpoint.GenerationSHA256 != result.GenerationSHA256 {
		t.Fatalf("rollback checkpoint does not bind final generation: checkpoint=%#v result=%#v err=%v", checkpoint, result, err)
	}
	generationKey, _ := GenerationKey(request.Generation.Generation)
	if _, exists := remote.objects[generationKey]; !exists {
		t.Fatal("rollback final generation document is missing")
	}
}

func TestR2SecondGenerationRecoveryKeepsParentETagIdentity(t *testing.T) {
	for _, crashPhase := range []Phase{PhaseLocked, PhaseCheckpointCommitted} {
		crashPhase := crashPhase
		t.Run(string(crashPhase), func(t *testing.T) {
			t.Parallel()
			root, plan := sourcePlan(t)
			remote := newFakeRemote()
			parentGeneration := generationFixture(TargetCloudflare, 1)
			parentCheckpoint, err := NewCheckpoint(parentGeneration, "generation-one", hashString("generation-one-plan"), PhaseCheckpointCommitted, stableTime())
			if err != nil {
				t.Fatal(err)
			}
			parentBody, err := parentCheckpoint.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			const parentETag = `"generation-one-etag"`
			remote.objects[CheckpointKey] = fakeObject{body: parentBody, sha: digestBytes(parentBody), etag: parentETag}

			request := requestFixture(TargetCloudflare, plan, "generation-two-"+string(crashPhase))
			request.Generation = generationFixture(TargetCloudflare, 2)
			request.Expected = ParentExpectation{
				Exists: true, Generation: 1,
				CheckpointSHA256: digestBytes(parentBody), ETag: parentETag,
			}
			journalDir := filepath.Join(t.TempDir(), "journal")
			failed := false
			first := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{AfterPhase: func(_ TargetName, phase Phase) error {
				if phase == crashPhase && !failed {
					failed = true
					return errors.New("injected generation-two crash")
				}
				return nil
			}})
			if _, err := first.Run(context.Background(), request); err == nil || !strings.Contains(err.Error(), "injected generation-two crash") {
				t.Fatalf("first run phase=%s err=%v", crashPhase, err)
			}
			interrupted := remote.get(CheckpointKey)
			if interrupted.ETag == parentETag {
				t.Fatalf("interrupted generation reused parent ETag %q", parentETag)
			}
			decoded, err := DecodeCheckpoint(interrupted.Body)
			if err != nil || decoded.Generation != 2 || decoded.Phase != crashPhase {
				t.Fatalf("interrupted checkpoint=%#v err=%v", decoded, err)
			}

			second := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
			result, err := second.Run(context.Background(), request)
			if err != nil || !result.RemoteRefReady {
				t.Fatalf("resume phase=%s result=%#v err=%v", crashPhase, result, err)
			}
			committed := remote.get(CheckpointKey)
			if result.CheckpointETag == "" || result.CheckpointETag != committed.ETag || result.CheckpointETag == parentETag {
				t.Fatalf("checkpoint ETag result=%q committed=%q parent=%q", result.CheckpointETag, committed.ETag, parentETag)
			}
		})
	}
}

func TestSagaReplaysLostUploadAndPurgeResponsesIdempotently(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	remote := newFakeRemote()
	remote.failAfterPutKey = "pool/a.pkg"
	remote.failPurgeAfterApply = true
	request := requestFixture(TargetCloudflare, plan, "lost-response")
	journalDir := filepath.Join(t.TempDir(), "journal")
	publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
	if _, err := publisher.Run(context.Background(), request); err == nil {
		t.Fatal("lost upload response did not interrupt first run")
	}
	if _, err := publisher.Run(context.Background(), request); err == nil {
		t.Fatal("lost purge response did not interrupt second run")
	}
	result, err := publisher.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.RemoteRefReady {
		t.Fatal("third replay did not complete")
	}
	if remote.putAttempts["pool/a.pkg"] != 3 {
		t.Fatalf("immutable upload attempts=%d, want 3 including recovery closure proof", remote.putAttempts["pool/a.pkg"])
	}
	if len(remote.purgeCalls) != 2 {
		t.Fatalf("purge attempts=%d, want 2", len(remote.purgeCalls))
	}
	if got := remote.purgeCalls[0]; len(got) != 1 || got[0] != "https://cdn.test/dists/jammy/InRelease" {
		t.Fatalf("purge was not minimal: %v", got)
	}
}

func TestIndependentTargetsKeepSuccessfulCheckpoint(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	cf := newFakeRemote()
	cos := newFakeRemote()
	cos.failPurgeAlways = true
	journalDir := filepath.Join(t.TempDir(), "journal")
	cfRequest := requestFixture(TargetCloudflare, plan, "dual-cf")
	cosRequest := requestFixture(TargetTencent, plan, "dual-cos")
	results, err := RunTargets(context.Background(),
		Job{Publisher: NewR2CloudflarePublisher(cf, DirectorySource{Root: root}, journalDir, Hooks{}), Request: cfRequest},
		Job{Publisher: NewCOSEdgeOnePublisher(cos, DirectorySource{Root: root}, journalDir, Hooks{}), Request: cosRequest},
	)
	var multi *MultiTargetError
	if !errors.As(err, &multi) || len(multi.Failures) != 1 || multi.Failures[TargetTencent] == nil {
		t.Fatalf("unexpected aggregate error: %v", err)
	}
	if !results[TargetCloudflare].RemoteRefReady || results[TargetTencent].RemoteRefReady {
		t.Fatalf("target independence lost: %#v", results)
	}
	if !cf.get(CheckpointKey).Exists {
		t.Fatal("successful Cloudflare target checkpoint was not retained")
	}
	if cos.get(CheckpointKey).Exists {
		t.Fatal("failed Tencent target advanced its checkpoint")
	}
}

func TestDriftParentAndETagConflictsFailClosed(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	parentGeneration := generationFixture(TargetCloudflare, 1)
	parent, err := NewCheckpoint(parentGeneration, "parent", hashString("parent-plan"), PhaseCheckpointCommitted, stableTime())
	if err != nil {
		t.Fatal(err)
	}
	parentBody, _ := parent.Canonical()
	for _, test := range []struct {
		name        string
		digest      string
		etag        string
		want        error
		casConflict bool
	}{
		{name: "digest-drift", digest: hashString("wrong"), etag: `"parent"`, want: ErrDrift},
		{name: "etag-drift", digest: digestBytes(parentBody), etag: `"wrong"`, want: ErrDrift},
		{name: "cas-race", digest: digestBytes(parentBody), etag: `"parent"`, want: ErrConflict, casConflict: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			remote := newFakeRemote()
			remote.objects[CheckpointKey] = fakeObject{body: parentBody, sha: digestBytes(parentBody), etag: `"parent"`}
			remote.conflictCheckpointCAS = test.casConflict
			request := requestFixture(TargetCloudflare, plan, "conflict-"+test.name)
			request.Generation = generationFixture(TargetCloudflare, 2)
			request.Expected = ParentExpectation{Exists: true, Generation: 1, CheckpointSHA256: test.digest, ETag: test.etag}
			publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{})
			_, err := publisher.Run(context.Background(), request)
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			if remote.putAttempts["pool/a.pkg"] != 0 {
				t.Fatal("content upload started despite checkpoint conflict")
			}
		})
	}
}

func TestCOSForeignCreateOnlyGenerationLockFailsClosed(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	remote := newFakeRemote()
	lockKey, _ := GenerationLockKey(1)
	remote.objects[lockKey] = fakeObject{body: []byte("foreign"), sha: hashString("foreign"), etag: `"foreign"`}
	request := requestFixture(TargetTencent, plan, "cos-lock")
	publisher := NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{})
	_, err := publisher.Run(context.Background(), request)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign COS generation lock was not a conflict: %v", err)
	}
	if remote.get(CheckpointKey).Exists {
		t.Fatal("COS checkpoint advanced despite foreign lock")
	}
}

func TestCOSSagaResumesCreateOnlyLock(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	remote := newFakeRemote()
	request := requestFixture(TargetTencent, plan, "cos-resume")
	journalDir := filepath.Join(t.TempDir(), "journal")
	failed := false
	first := NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{AfterPhase: func(_ TargetName, phase Phase) error {
		if phase == PhaseGenerationReady && !failed {
			failed = true
			return errors.New("crash after COS generation")
		}
		return nil
	}})
	if _, err := first.Run(context.Background(), request); err == nil {
		t.Fatal("COS fixture did not interrupt")
	}
	second := NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
	result, err := second.Run(context.Background(), request)
	if err != nil || !result.RemoteRefReady {
		t.Fatalf("COS lock resume failed: %#v %v", result, err)
	}
	lockKey, _ := GenerationLockKey(1)
	if remote.putAttempts[lockKey] != 2 || !remote.get(lockKey).Exists {
		t.Fatalf("COS lock was not safely replayed and preserved: attempts=%d", remote.putAttempts[lockKey])
	}
}

func TestCOSRechecksParentBeforeUnconditionalCheckpointWrite(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	remote := newFakeRemote()
	remote.mutateCheckpointPurge = []byte(`{"foreign":true}`)
	request := requestFixture(TargetTencent, plan, "cos-parent-race")
	publisher := NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{})
	_, err := publisher.Run(context.Background(), request)
	if !errors.Is(err, ErrDrift) {
		t.Fatalf("COS parent race did not fail closed: %v", err)
	}
	if got := string(remote.get(CheckpointKey).Body); got != `{"foreign":true}` {
		t.Fatalf("COS race overwrote foreign checkpoint: %s", got)
	}
}

func TestCDNVerificationFailureBlocksCheckpointAndCanResume(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	remote := newFakeRemote()
	remote.corruptCDNKey = "dists/jammy/InRelease"
	request := requestFixture(TargetCloudflare, plan, "verify-retry")
	publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{})
	_, err := publisher.Run(context.Background(), request)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("corrupt CDN response did not fail L3 verification: %v", err)
	}
	locked, err := DecodeCheckpoint(remote.get(CheckpointKey).Body)
	if err != nil || locked.Phase != PhaseLocked {
		t.Fatalf("verification failure advanced checkpoint: %#v %v", locked, err)
	}
	remote.mutex.Lock()
	remote.corruptCDNKey = ""
	remote.mutex.Unlock()
	result, err := publisher.Run(context.Background(), request)
	if err != nil || !result.RemoteRefReady {
		t.Fatalf("verification retry did not recover: %#v %v", result, err)
	}
}

func TestJournalRejectsTransactionReuseWithDifferentPlan(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	remote := newFakeRemote()
	journalDir := filepath.Join(t.TempDir(), "journal")
	request := requestFixture(TargetCloudflare, plan, "journal-reuse")
	publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{AfterPhase: func(_ TargetName, phase Phase) error {
		if phase == PhasePlanned {
			return errors.New("stop after journal")
		}
		return nil
	}})
	if _, err := publisher.Run(context.Background(), request); err == nil {
		t.Fatal("fixture did not stop after initial journal")
	}
	changed := plan
	changed.Objects = append([]PlannedObject(nil), plan.Objects...)
	changed.Objects[0].SHA256 = hashString("different")
	changed.PurgeURLs = nil
	changed.Verify = nil
	changed, err := changed.WithCDN("https://cdn.test/")
	if err != nil {
		t.Fatal(err)
	}
	request.Plan = changed
	cleanPublisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
	if _, err := cleanPublisher.Run(context.Background(), request); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("transaction ID reuse did not fail closed: %v", err)
	}
}

func sourcePlan(t *testing.T) (string, Plan) {
	t.Helper()
	root := t.TempDir()
	files := []struct {
		path  string
		body  string
		class ObjectClass
	}{
		{path: "pool/a.pkg", body: "immutable", class: ObjectImmutable},
		{path: "metadata/index", body: "metadata", class: ObjectMetadata},
		{path: "dists/jammy/InRelease", body: "pointer", class: ObjectPointer},
	}
	plan := Plan{Schema: planSchema}
	for _, file := range files {
		full := filepath.Join(root, filepath.FromSlash(file.path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(file.body), 0o644); err != nil {
			t.Fatal(err)
		}
		plan.Objects = append(plan.Objects, PlannedObject{
			SourcePath: file.path, RemoteKey: file.path, Size: int64(len(file.body)),
			SHA256: hashString(file.body), Class: file.class,
		})
	}
	var err error
	plan, err = plan.WithCDN("https://cdn.test/")
	if err != nil {
		t.Fatal(err)
	}
	return root, plan
}

func requestFixture(target TargetName, plan Plan, transaction string) Request {
	return Request{
		TransactionID: transaction,
		Generation:    generationFixture(target, 1),
		Plan:          plan,
		Expected:      ParentExpectation{},
		UpdatedAt:     stableTime(),
	}
}

func stableTime() time.Time { return time.Date(2026, 7, 12, 2, 3, 4, 5, time.UTC) }
