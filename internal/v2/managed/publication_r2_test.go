package managed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/r2"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"golang.org/x/sys/unix"
)

type fakeR2PublicationObject struct {
	body []byte
	sha  string
	etag string
}

type fakeR2PublicationClient struct {
	objects    map[string]fakeR2PublicationObject
	conditions map[string]r2.PutCondition
	next       int
}

type managedRoundTripFunc func(*http.Request) (*http.Response, error)

func (f managedRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func (f *fakeR2PublicationClient) ListObjectsV2Prefix(_ context.Context, prefix, continuation string) (r2.ObjectListPage, error) {
	if continuation != "" {
		return r2.ObjectListPage{}, errors.New("unexpected continuation")
	}
	keys := []string{}
	for key := range f.objects {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	page := r2.ObjectListPage{}
	for _, key := range keys {
		object := f.objects[key]
		page.Objects = append(page.Objects, r2.ListedObject{Key: key, Size: int64(len(object.body)), ETag: object.etag})
	}
	return page, nil
}

func (f *fakeR2PublicationClient) Head(_ context.Context, key string) (r2.ObjectInfo, error) {
	object, ok := f.objects[key]
	if !ok {
		return r2.ObjectInfo{}, nil
	}
	return r2.ObjectInfo{Exists: true, Size: int64(len(object.body)), SHA256: object.sha, ETag: object.etag}, nil
}

func (f *fakeR2PublicationClient) OpenObject(_ context.Context, key string) (r2.ObjectContent, error) {
	info, _ := f.Head(context.Background(), key)
	if !info.Exists {
		return r2.ObjectContent{}, r2.ErrNotFound
	}
	return r2.ObjectContent{Info: info, Body: io.NopCloser(bytes.NewReader(f.objects[key].body))}, nil
}

func (f *fakeR2PublicationClient) Put(_ context.Context, key string, body r2.ReadSeekReaderAt, size int64, sha string, condition r2.PutCondition) (string, error) {
	current, exists := f.objects[key]
	if condition.IfNoneMatch && exists {
		return "", r2.ErrAlreadyExists
	}
	if condition.IfMatch != "" && (!exists || current.etag != condition.IfMatch) {
		return "", r2.ErrConflict
	}
	data, err := io.ReadAll(io.LimitReader(body, size+1))
	if err != nil || int64(len(data)) != size {
		return "", errors.Join(errors.New("bad upload body"), err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != sha {
		return "", errors.New("bad upload digest")
	}
	f.next++
	etag := fmt.Sprintf("\"etag-%d\"", f.next)
	f.objects[key] = fakeR2PublicationObject{body: data, sha: sha, etag: etag}
	if f.conditions == nil {
		f.conditions = map[string]r2.PutCondition{}
	}
	f.conditions[key] = condition
	return etag, nil
}

func TestR2PublicationBackendMapsOneCanonicalKeyAndUsesConditionalPut(t *testing.T) {
	ctx := context.Background()
	fake := &fakeR2PublicationClient{objects: map[string]fakeR2PublicationObject{}}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		relative := strings.TrimPrefix(request.URL.Path, "/repo/")
		object, ok := fake.objects["repos/prod/"+relative]
		if !ok {
			http.NotFound(response, request)
			return
		}
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(object.body)
	}))
	defer server.Close()
	publicBase, err := url.Parse(server.URL + "/repo/")
	if err != nil {
		t.Fatal(err)
	}
	backend := &r2PublicationBackend{objects: fake, prefix: "repos/prod", publicBase: publicBase}
	sourceRoot := t.TempDir()
	objectPath := "pool/p/package.rpm"
	filename := filepath.Join(sourceRoot, filepath.FromSlash(objectPath))
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(body string) state.PublicationPlanOperation {
		t.Helper()
		if err := os.WriteFile(filename, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(body))
		return state.PublicationPlanOperation{Operation: "add", Path: objectPath, Phase: "payload", Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])}
	}
	add := write("first")
	firstETag, err := backend.Put(ctx, sourceRoot, add, strings.Repeat("a", 64))
	if err != nil || firstETag == "" || len(fake.objects) != 1 {
		t.Fatalf("R2 add etag=%q objects=%d err=%v", firstETag, len(fake.objects), err)
	}
	if got := fake.conditions["repos/prod/"+objectPath].CacheControl; got != r2ImmutableCacheControl {
		t.Fatalf("R2 payload Cache-Control=%q", got)
	}
	if replayETag, err := backend.Put(ctx, sourceRoot, add, strings.Repeat("a", 64)); err != nil || replayETag != firstETag || len(fake.objects) != 1 {
		t.Fatalf("R2 add replay etag=%q err=%v", replayETag, err)
	}
	update := write("second")
	update.Operation, update.ExpectedOldSHA256 = "update", add.SHA256
	if _, err := backend.Put(ctx, sourceRoot, update, strings.Repeat("a", 64)); !errors.Is(err, ErrRejected) {
		t.Fatalf("R2 payload overwrite was accepted: %v", err)
	}
	objects, err := backend.List(ctx, nil)
	if err != nil || len(objects) != 1 || objects[0].Path != objectPath || objects[0].RemoteIdentity != firstETag {
		t.Fatalf("R2 list=%#v err=%v", objects, err)
	}
	if err := backend.VerifyPublic(ctx, state.GenerationFile{Path: objectPath, Phase: "payload", Size: add.Size, SHA256: add.SHA256}); err != nil {
		t.Fatal(err)
	}
	if err := backend.DeleteConditional(ctx, state.PublicationCandidate{}); !errors.Is(err, ErrRejected) {
		t.Fatalf("R2 delete was not capability-disabled: %v", err)
	}
	for key := range fake.objects {
		if key != "repos/prod/"+objectPath || strings.Contains(key, ".sow") {
			t.Fatalf("R2 backend created non-public/control key %q", key)
		}
	}
}

func TestR2PublicVerificationWaitsForCanonicalCacheRefresh(t *testing.T) {
	oldBody := []byte("old-pointer")
	newBody := []byte("new-pointer")
	digest := sha256.Sum256(newBody)
	expected := state.GenerationFile{Path: "dists/el9/x86_64/repodata/repomd.xml", Phase: "pointer", Size: int64(len(newBody)), SHA256: hex.EncodeToString(digest[:])}
	refreshed := false
	regular, revalidated := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.RawQuery != "" {
			t.Errorf("public verification changed canonical cache key: %s", request.URL.String())
		}
		if request.Header.Get("Cache-Control") == "no-cache" {
			revalidated++
			refreshed = true
			_, _ = response.Write(newBody)
			return
		}
		regular++
		if refreshed {
			_, _ = response.Write(newBody)
		} else {
			_, _ = response.Write(oldBody)
		}
	}))
	defer server.Close()
	publicBase, err := url.Parse(server.URL + "/repo/")
	if err != nil {
		t.Fatal(err)
	}
	backend := &r2PublicationBackend{
		publicBase: publicBase, publicClient: server.Client(), maxCacheTTL: time.Second,
		verificationSleep: func(context.Context, time.Duration) error { return nil },
	}
	if err := backend.VerifyPublic(context.Background(), expected); err != nil {
		t.Fatal(err)
	}
	if regular != 2 || revalidated != 1 {
		t.Fatalf("public verification regular=%d revalidated=%d", regular, revalidated)
	}
}

func TestR2PublicVerificationBoundsTransientAndIdleFailures(t *testing.T) {
	t.Run("transient retries do not inherit cache TTL", func(t *testing.T) {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			calls++
			response.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()
		publicBase, err := url.Parse(server.URL + "/repo/")
		if err != nil {
			t.Fatal(err)
		}
		current := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
		started := current
		backend := &r2PublicationBackend{
			publicBase: publicBase, publicClient: server.Client(), maxCacheTTL: 24 * time.Hour,
			transientRetryWindow: 500 * time.Millisecond,
			verificationNow:      func() time.Time { return current },
			verificationSleep: func(_ context.Context, duration time.Duration) error {
				current = current.Add(duration)
				return nil
			},
		}
		expected := state.GenerationFile{Path: "pool/p/package.rpm", Phase: "payload", Size: 1, SHA256: strings.Repeat("a", 64)}
		if err := backend.VerifyPublic(context.Background(), expected); err == nil || calls < 2 || current.Sub(started) != 500*time.Millisecond {
			t.Fatalf("transient calls=%d elapsed=%s err=%v", calls, current.Sub(started), err)
		}
	})

	t.Run("idle response body", func(t *testing.T) {
		reader, writer := io.Pipe()
		defer writer.Close()
		client := &http.Client{Transport: managedRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
				Body: reader, Request: request,
			}, nil
		})}
		publicBase, err := url.Parse("https://repo.example.test/")
		if err != nil {
			t.Fatal(err)
		}
		backend := &r2PublicationBackend{
			publicBase: publicBase, publicClient: client, publicReadIdleTimeout: 20 * time.Millisecond,
		}
		expected := state.GenerationFile{Path: "pool/p/package.rpm", Phase: "payload", Size: 1, SHA256: strings.Repeat("a", 64)}
		if err := backend.VerifyPublic(context.Background(), expected); !errors.Is(err, r2.ErrReadNoProgress) {
			t.Fatalf("idle public verification error=%v", err)
		}
	})
}

func TestR2MutablePublicationCachePolicyCoversPointersAndAPTStableAliases(t *testing.T) {
	for _, operation := range []state.PublicationPlanOperation{
		{Path: "dists/el9/x86_64/repodata/repomd.xml", Phase: "pointer"},
		{Path: "dists/noble/main/binary-amd64/Packages.gz", Phase: "metadata"},
	} {
		if !mutableR2PublicationPath(operation) {
			t.Fatalf("mutable publication path was classified immutable: %#v", operation)
		}
	}
	for _, operation := range []state.PublicationPlanOperation{
		{Path: "pool/p/pkg/package.rpm", Phase: "payload"},
		{Path: "dists/noble/main/binary-amd64/by-hash/SHA256/abc", Phase: "metadata"},
		{Path: "dists/el9/x86_64/repodata/abc-primary.xml.gz", Phase: "metadata"},
	} {
		if mutableR2PublicationPath(operation) {
			t.Fatalf("immutable publication path was classified mutable: %#v", operation)
		}
	}
}

func TestResolveR2CredentialsUsesStrictReferencesWithoutInlineSecrets(t *testing.T) {
	t.Setenv("SOW_TEST_R2_CREDENTIAL", `{"access_key_id":"access","secret_access_key":"secret","session_token":"session"}`)
	credentials, err := resolveR2Credentials("env://SOW_TEST_R2_CREDENTIAL", "auto")
	if err != nil || credentials.AccessKeyID != "access" || credentials.SecretAccessKey != "secret" || credentials.SessionToken != "session" || credentials.Region != "auto" {
		t.Fatalf("credentials=%#v err=%v", credentials, err)
	}
	t.Setenv("SOW_TEST_R2_CREDENTIAL", `{"access_key_id":"access","secret_access_key":"secret","unknown":true}`)
	if _, err := resolveR2Credentials("env://SOW_TEST_R2_CREDENTIAL", "auto"); err == nil {
		t.Fatal("credential document with unknown field was accepted")
	}
	credentialFile := filepath.Join(t.TempDir(), "r2.json")
	if err := os.WriteFile(credentialFile, []byte(`{"access_key_id":"file-access","secret_access_key":"file-secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials, err = resolveR2Credentials("file://"+credentialFile, "auto")
	if err != nil || credentials.AccessKeyID != "file-access" || credentials.SecretAccessKey != "file-secret" {
		t.Fatalf("file credentials=%#v err=%v", credentials, err)
	}
	t.Setenv("SOW_TEST_R2_CONSTRUCTOR", `{"access_key_id":"access","secret_access_key":"secret"}`)
	backend, err := newR2PublicationBackend(config.TargetConfig{
		Provider: "r2", Endpoint: "https://acct.r2.cloudflarestorage.com", Region: "auto", Bucket: "sow-repo",
		Prefix: "repos/prod", Credential: "env://SOW_TEST_R2_CONSTRUCTOR", PublicEndpoint: "https://repo.example.test/repos/prod/",
	})
	if err != nil || backend.prefix != "repos/prod" {
		t.Fatalf("R2 backend constructor=%#v err=%v", backend, err)
	}
}

func TestR2PublishAndTargetGCRemainReportOnly(t *testing.T) {
	ctx := context.Background()
	fixture := newLocalGCFixture(t, false)
	fake := &fakeR2PublicationClient{objects: map[string]fakeR2PublicationObject{}}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		relative := strings.TrimPrefix(request.URL.Path, "/repo/")
		object, ok := fake.objects["repos/prod/"+relative]
		if !ok {
			http.NotFound(response, request)
			return
		}
		_, _ = response.Write(object.body)
	}))
	defer server.Close()
	publicBase, err := url.Parse(server.URL + "/repo/")
	if err != nil {
		t.Fatal(err)
	}
	backend := &r2PublicationBackend{objects: fake, prefix: "repos/prod", publicBase: publicBase}
	cfg, err := config.Load(filepath.Join(fixture.root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets = map[string]config.TargetConfig{"prod": {
		Repository: "repo", Provider: "r2", Endpoint: "https://acct.r2.cloudflarestorage.com",
		Region: "auto", Bucket: "sow-repo", Prefix: "repos/prod", Credential: "env://SOW_TEST_UNUSED_R2",
		PublicEndpoint: server.URL + "/repo/", MaxCacheTTL: "0s",
		AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true,
	}}
	writeManagedConfig(t, fixture.root, cfg)
	first, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	firstMaintenanceAt := time.Now().UTC().Add(31 * 24 * time.Hour)
	firstMaintenanceClock := func() time.Time { return firstMaintenanceAt }
	firstMaintenance, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: firstMaintenanceClock})
	if err != nil || firstMaintenance.CompletedAttempts != 1 || firstMaintenance.DeletedObjects != 0 {
		t.Fatalf("first R2 maintenance=%#v err=%v", firstMaintenance, err)
	}
	collected, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
	if err != nil || collected.Noop || collected.Objects != 1 {
		t.Fatalf("local gc=%#v err=%v", collected, err)
	}
	secondPublishAt := firstMaintenanceAt.Add(time.Second)
	secondPublishClock := func() time.Time { return secondPublishAt }
	second, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: secondPublishClock})
	if err != nil || second.Generation == first.Generation {
		t.Fatalf("second R2 publish=%#v err=%v", second, err)
	}
	oldKey := "repos/prod/" + fixture.object.PoolPath
	oldObject, existedBefore := fake.objects[oldKey]
	if !existedBefore {
		t.Fatalf("old R2 payload missing before report-only maintenance: %s", oldKey)
	}
	secondMaintenanceAt := secondPublishAt.Add(31 * 24 * time.Hour)
	secondMaintenanceClock := func() time.Time { return secondMaintenanceAt }
	maintenance, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: secondMaintenanceClock})
	if err != nil || maintenance.RetainedObjects != 1 || maintenance.DeletedObjects != 0 || maintenance.DeletedBytes != 0 {
		t.Fatalf("R2 report-only maintenance=%#v err=%v", maintenance, err)
	}
	if current, ok := fake.objects[oldKey]; !ok || current.sha != oldObject.sha || current.etag != oldObject.etag {
		t.Fatalf("R2 report-only maintenance mutated retained payload: before=%#v after=%#v ok=%t", oldObject, current, ok)
	}
	store, err := state.OpenReadOnly(filepath.Join(fixture.root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	report, reportErr := store.GetPublicationCandidateReport(ctx, second.Checkpoint)
	closeErr := store.Close()
	if err := errors.Join(reportErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if report.Mode != "report_only" || len(report.Candidates) != 1 || report.Candidates[0].Path != fixture.object.PoolPath {
		t.Fatalf("unexpected R2 retained report: %#v", report)
	}
	noop, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: secondMaintenanceClock})
	if err != nil || !noop.Noop {
		t.Fatalf("R2 noop after retained report=%#v err=%v", noop, err)
	}
}

func TestR2CredentialReferenceRejectsFIFOWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "credential.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := resolveR2Credentials("file://"+fifo, "auto")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRejected) {
			t.Fatalf("FIFO credential error=%v, want rejection", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a FIFO credential blocked credential resolution")
	}
}

type inventoryR2PublicationClient struct {
	r2PublicationObjectClient
	list func(context.Context, string, string) (r2.ObjectListPage, error)
	head func(context.Context, string) (r2.ObjectInfo, error)
}

func (c *inventoryR2PublicationClient) ListObjectsV2Prefix(ctx context.Context, prefix, token string) (r2.ObjectListPage, error) {
	return c.list(ctx, prefix, token)
}

func (c *inventoryR2PublicationClient) Head(ctx context.Context, key string) (r2.ObjectInfo, error) {
	return c.head(ctx, key)
}

func r2InventoryFixture(count int) ([]r2.ListedObject, map[string]r2.ObjectInfo) {
	listed := make([]r2.ListedObject, count)
	infos := make(map[string]r2.ObjectInfo, count)
	for index := range count {
		key := fmt.Sprintf("repos/prod/pool/p/%04d.rpm", index)
		info := r2.ObjectInfo{Exists: true, Size: int64(index + 1), SHA256: bytesSHA([]byte(key)), ETag: fmt.Sprintf(`"etag-%d"`, index)}
		listed[index] = r2.ListedObject{Key: key, Size: info.Size, ETag: info.ETag}
		infos[key] = info
	}
	return listed, infos
}

func awaitR2Inventory[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(10 * time.Second):
		t.Fatal("R2 inventory did not finish its controlled operation")
		var zero T
		return zero
	}
}

func TestR2InventoryBoundedOrderedHeadsAcrossPages(t *testing.T) {
	const count = 1003
	listed, infos := r2InventoryFixture(count)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan int, r2InventoryHeadWorkers)
	finished := make(chan int, r2InventoryHeadWorkers)
	release := make([]chan struct{}, r2InventoryHeadWorkers)
	for index := range release {
		release[index] = make(chan struct{})
	}
	var heads, active, maximum atomic.Int32
	lists := 0
	client := &inventoryR2PublicationClient{
		list: func(_ context.Context, prefix, token string) (r2.ObjectListPage, error) {
			lists++
			if prefix != "repos/prod/" {
				return r2.ObjectListPage{}, fmt.Errorf("unexpected prefix %q", prefix)
			}
			switch token {
			case "":
				return r2.ObjectListPage{Objects: listed[:1000], NextContinuationToken: "second"}, nil
			case "second":
				if active.Load() != 0 || heads.Load() != 1000 {
					return r2.ObjectListPage{}, errors.New("next page started before the first page was verified")
				}
				return r2.ObjectListPage{Objects: listed[1000:]}, nil
			default:
				return r2.ObjectListPage{}, fmt.Errorf("unexpected token %q", token)
			}
		},
		head: func(ctx context.Context, key string) (r2.ObjectInfo, error) {
			heads.Add(1)
			current := active.Add(1)
			defer active.Add(-1)
			for old := maximum.Load(); current > old && !maximum.CompareAndSwap(old, current); old = maximum.Load() {
			}
			index := int(infos[key].Size - 1)
			if index < len(release) {
				started <- index
				select {
				case <-release[index]:
					finished <- index
				case <-ctx.Done():
					return r2.ObjectInfo{}, ctx.Err()
				}
			}
			return infos[key], nil
		},
	}
	backend := &r2PublicationBackend{objects: client, prefix: "repos/prod"}
	type outcome struct {
		objects []publicationRemoteObject
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		objects, err := backend.List(ctx, nil)
		done <- outcome{objects, err}
	}()
	seen := map[int]bool{}
	for range r2InventoryHeadWorkers {
		seen[awaitR2Inventory(t, started)] = true
	}
	if len(seen) != r2InventoryHeadWorkers || maximum.Load() != r2InventoryHeadWorkers {
		t.Fatalf("first wave=%v max_inflight=%d", seen, maximum.Load())
	}
	for index := r2InventoryHeadWorkers - 1; index > 0; index-- {
		close(release[index])
		if got := awaitR2Inventory(t, finished); got != index {
			t.Fatalf("completion=%d want=%d", got, index)
		}
	}
	if got := heads.Load(); got != r2InventoryHeadWorkers {
		t.Fatalf("slow first HEAD allowed an unbounded result queue: heads=%d", got)
	}
	close(release[0])
	result := awaitR2Inventory(t, done)
	if result.err != nil || len(result.objects) != count || heads.Load() != count || maximum.Load() != r2InventoryHeadWorkers || active.Load() != 0 || lists != 2 {
		t.Fatalf("objects=%d heads=%d max_inflight=%d active=%d lists=%d err=%v", len(result.objects), heads.Load(), maximum.Load(), active.Load(), lists, result.err)
	}
	baseline := make([]publicationRemoteObject, count)
	for index, object := range listed {
		info := infos[object.Key]
		baseline[index] = publicationRemoteObject{Path: strings.TrimPrefix(object.Key, "repos/prod/"), Size: info.Size, SHA256: info.SHA256, RemoteIdentity: info.ETag}
	}
	if !reflect.DeepEqual(result.objects, baseline) {
		t.Fatal("parallel inventory differs from the serial baseline")
	}
	manifest := make([]state.GenerationFile, count)
	for index, object := range baseline {
		manifest[index] = state.GenerationFile{Path: object.Path, Phase: "payload", Size: object.Size, SHA256: object.SHA256}
	}
	inventory, err := publicationInventory(result.objects, manifest, nil)
	wantInventory, baselineErr := publicationInventory(baseline, manifest, nil)
	if err != nil || baselineErr != nil || !reflect.DeepEqual(inventory, wantInventory) {
		t.Fatalf("publication evidence differs from serial baseline: err=%v baseline=%v", err, baselineErr)
	}
	t.Logf("objects=%d HEAD_requests=%d max_inflight=%d pending_result_limit=%d list_pages=%d", count, heads.Load(), maximum.Load(), r2InventoryHeadWorkers, lists)
}

func TestR2InventoryCancellationAndFailureJoinWorkers(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprintf("head_failure=%t", failure), func(t *testing.T) {
			listed, _ := r2InventoryFixture(1003)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan string, r2InventoryHeadWorkers)
			fail := make(chan struct{})
			var heads, active atomic.Int32
			lists := 0
			client := &inventoryR2PublicationClient{
				list: func(context.Context, string, string) (r2.ObjectListPage, error) {
					lists++
					return r2.ObjectListPage{Objects: listed[:1000], NextContinuationToken: "second"}, nil
				},
				head: func(ctx context.Context, key string) (r2.ObjectInfo, error) {
					heads.Add(1)
					active.Add(1)
					defer active.Add(-1)
					started <- key
					if failure && key == listed[0].Key {
						select {
						case <-fail:
							return r2.ObjectInfo{}, r2.ErrConflict
						case <-ctx.Done():
						}
					}
					<-ctx.Done()
					return r2.ObjectInfo{}, ctx.Err()
				},
			}
			backend := &r2PublicationBackend{objects: client, prefix: "repos/prod"}
			done := make(chan error, 1)
			go func() {
				objects, err := backend.List(ctx, nil)
				if objects != nil {
					err = errors.New("failed inventory returned partial evidence")
				}
				done <- err
			}()
			for range r2InventoryHeadWorkers {
				awaitR2Inventory(t, started)
			}
			cause := error(context.Canceled)
			if failure {
				cause = r2.ErrConflict
				close(fail)
			} else {
				cancel()
			}
			err := awaitR2Inventory(t, done)
			if !errors.Is(err, ErrIntegrity) || !errors.Is(err, cause) || heads.Load() != r2InventoryHeadWorkers || active.Load() != 0 || lists != 1 {
				t.Fatalf("err=%v heads=%d active=%d lists=%d", err, heads.Load(), active.Load(), lists)
			}
		})
	}
}

func TestR2InventorySelectsFirstErrorInKeyOrder(t *testing.T) {
	listed, infos := r2InventoryFixture(16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan string, 16)
	finished := make(chan string, 16)
	release := make(map[string]chan struct{}, len(listed))
	for _, object := range listed {
		release[object.Key] = make(chan struct{})
	}
	var active atomic.Int32
	client := &inventoryR2PublicationClient{
		list: func(context.Context, string, string) (r2.ObjectListPage, error) {
			return r2.ObjectListPage{Objects: listed}, nil
		},
		head: func(ctx context.Context, key string) (r2.ObjectInfo, error) {
			active.Add(1)
			defer active.Add(-1)
			started <- key
			select {
			case <-release[key]:
				finished <- key
			case <-ctx.Done():
				return r2.ObjectInfo{}, ctx.Err()
			}
			if key == listed[2].Key {
				return r2.ObjectInfo{}, r2.ErrConflict
			}
			if key == listed[5].Key {
				return r2.ObjectInfo{}, r2.ErrCapability
			}
			return infos[key], nil
		},
	}
	backend := &r2PublicationBackend{objects: client, prefix: "repos/prod"}
	done := make(chan error, 1)
	go func() {
		_, err := backend.List(ctx, nil)
		done <- err
	}()
	for range r2InventoryHeadWorkers {
		awaitR2Inventory(t, started)
	}
	for _, index := range []int{5, 2, 1, 0} {
		close(release[listed[index].Key])
		awaitR2Inventory(t, finished)
	}
	err := awaitR2Inventory(t, done)
	if !errors.Is(err, ErrIntegrity) || !errors.Is(err, r2.ErrConflict) || errors.Is(err, r2.ErrCapability) || !strings.Contains(err.Error(), "0002.rpm") || active.Load() != 0 {
		t.Fatalf("completion order changed first error or leaked workers: err=%v active=%d", err, active.Load())
	}
}

func TestR2InventoryRequiresExactHeadEvidence(t *testing.T) {
	listed, infos := r2InventoryFixture(1)
	exact := infos[listed[0].Key]
	for _, scenario := range []struct {
		name   string
		mutate func(*r2.ObjectInfo)
	}{
		{"missing", func(info *r2.ObjectInfo) { info.Exists = false }},
		{"size changed", func(info *r2.ObjectInfo) { info.Size++ }},
		{"etag absent", func(info *r2.ObjectInfo) { info.ETag = "" }},
		{"etag changed", func(info *r2.ObjectInfo) { info.ETag = `"changed"` }},
		{"digest absent", func(info *r2.ObjectInfo) { info.SHA256 = "" }},
		{"digest uppercase", func(info *r2.ObjectInfo) { info.SHA256 = strings.ToUpper(info.SHA256) }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			info := exact
			scenario.mutate(&info)
			client := &inventoryR2PublicationClient{
				list: func(context.Context, string, string) (r2.ObjectListPage, error) {
					return r2.ObjectListPage{Objects: listed}, nil
				},
				head: func(context.Context, string) (r2.ObjectInfo, error) { return info, nil },
			}
			backend := &r2PublicationBackend{objects: client, prefix: "repos/prod"}
			objects, err := backend.List(context.Background(), nil)
			if objects != nil || !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "lacks exact HEAD evidence") {
				t.Fatalf("unproven inventory accepted: objects=%v err=%v", objects, err)
			}
		})
	}
}

func TestR2InventoryRetainsListingGuards(t *testing.T) {
	listed, infos := r2InventoryFixture(2)
	for _, scenario := range []struct {
		name  string
		pages []r2.ObjectListPage
		want  string
	}{
		{"empty", []r2.ObjectListPage{{}}, ""},
		{"same page order", []r2.ObjectListPage{{Objects: []r2.ListedObject{listed[1], listed[0]}}}, "globally key-sorted"},
		{"cross page order", []r2.ObjectListPage{{Objects: listed[1:], NextContinuationToken: "next"}, {Objects: listed[:1]}}, "globally key-sorted"},
		{"duplicate key", []r2.ObjectListPage{{Objects: []r2.ListedObject{listed[0], listed[0]}}}, "globally key-sorted"},
		{"foreign prefix", []r2.ObjectListPage{{Objects: []r2.ListedObject{{Key: "repos/other/pool/p/0000.rpm"}}}}, "escaped configured prefix"},
		{"foreign object", []r2.ObjectListPage{{Objects: []r2.ListedObject{{Key: "repos/prod/private/object"}}}}, "foreign object"},
		{"repeated token", []r2.ObjectListPage{{NextContinuationToken: "next"}, {NextContinuationToken: "next"}}, "repeated a continuation token"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			client := &inventoryR2PublicationClient{
				list: func(context.Context, string, string) (r2.ObjectListPage, error) {
					if calls >= len(scenario.pages) {
						return r2.ObjectListPage{}, errors.New("unexpected extra page")
					}
					page := scenario.pages[calls]
					calls++
					return page, nil
				},
				head: func(_ context.Context, key string) (r2.ObjectInfo, error) {
					info, ok := infos[key]
					if !ok {
						t.Errorf("invalid inventory key reached HEAD: %q", key)
					}
					return info, nil
				},
			}
			backend := &r2PublicationBackend{objects: client, prefix: "repos/prod"}
			objects, err := backend.List(context.Background(), nil)
			if scenario.want == "" {
				if err != nil || len(objects) != 0 {
					t.Fatalf("empty inventory=%v err=%v", objects, err)
				}
			} else if objects != nil || !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), scenario.want) {
				t.Fatalf("inventory guard lost: objects=%v err=%v", objects, err)
			}
		})
	}
}

func TestR2InventoryHTTPPreservesSDKFailuresAndRetries(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		status   int
		failures int32
		attempts int32
		wantErr  bool
	}{
		{"hit", http.StatusOK, 0, 1, false},
		{"missing", http.StatusNotFound, 1, 1, true},
		{"forbidden", http.StatusForbidden, 1, 1, true},
		// A bodyless HEAD 429 carries no SDK throttle error code. Preserve the
		// transport's current terminal classification instead of adding retries.
		{"rate limited", http.StatusTooManyRequests, 1, 1, true},
		{"service retry", http.StatusServiceUnavailable, 1, 2, false},
		{"service exhausted", http.StatusInternalServerError, 3, 3, true},
		{"conflict", http.StatusPreconditionFailed, 1, 1, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			listed, infos := r2InventoryFixture(1)
			info := infos[listed[0].Key]
			var heads atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
					t.Error("inventory request was not signed")
				}
				switch request.Method {
				case http.MethodGet:
					if request.URL.Query().Get("prefix") != "repos/prod/" || request.URL.Query().Get("max-keys") != "1000" {
						t.Errorf("unexpected list query: %s", request.URL.RawQuery)
					}
					writer.Header().Set("Content-Type", "application/xml")
					_, _ = io.WriteString(writer, `<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated><Contents><Key>repos%2Fprod%2Fpool%2Fp%2F0000.rpm</Key><Size>1</Size><ETag>&quot;etag-0&quot;</ETag></Contents></ListBucketResult>`)
				case http.MethodHead:
					if heads.Add(1) <= scenario.failures {
						writer.WriteHeader(scenario.status)
						return
					}
					writer.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
					writer.Header().Set("ETag", info.ETag)
					writer.Header().Set("X-Amz-Meta-Sow-Sha256", info.SHA256)
				default:
					t.Errorf("inventory performed unexpected %s", request.Method)
					writer.WriteHeader(http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()
			client, err := r2.NewClient(r2.Config{
				Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", Client: server.Client(), AllowInsecure: true,
				Credentials: r2.S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
			})
			if err != nil {
				t.Fatal(err)
			}
			backend := &r2PublicationBackend{objects: client, prefix: "repos/prod"}
			objects, err := backend.List(context.Background(), nil)
			if heads.Load() != scenario.attempts || (err != nil) != scenario.wantErr || scenario.wantErr && (!errors.Is(err, ErrIntegrity) || objects != nil) {
				t.Fatalf("objects=%v HEAD_attempts=%d want=%d err=%v", objects, heads.Load(), scenario.attempts, err)
			}
			if scenario.wantErr && scenario.status != http.StatusNotFound {
				var status interface{ HTTPStatusCode() int }
				if !errors.As(err, &status) || status.HTTPStatusCode() != scenario.status {
					t.Fatalf("transport error classification lost: %v", err)
				}
			}
			t.Logf("objects=1 HEAD_attempts=%d HTTP_status=%d error=%t", heads.Load(), scenario.status, err != nil)
		})
	}
}

func TestR2InventoryHTTPCancellationAndDeadline(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%t", deadline), func(t *testing.T) {
			count := r2InventoryHeadWorkers
			if deadline {
				count = 1
			}
			listed, _ := r2InventoryFixture(count * 2)
			if deadline {
				listed = listed[:1]
			}
			started := make(chan struct{}, count*2)
			finished := make(chan struct{}, count*2)
			var heads, active atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodHead {
					t.Errorf("unexpected request method %s", request.Method)
					writer.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				heads.Add(1)
				active.Add(1)
				started <- struct{}{}
				<-request.Context().Done()
				active.Add(-1)
				finished <- struct{}{}
			}))
			defer server.Close()
			client, err := r2.NewClient(r2.Config{
				Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", Client: server.Client(), AllowInsecure: true,
				Credentials: r2.S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			}
			defer cancel()
			backend := &r2PublicationBackend{objects: client, prefix: "repos/prod"}
			done := make(chan error, 1)
			go func() {
				_, err := backend.headInventoryPage(ctx, listed, "")
				done <- err
			}()
			for range count {
				awaitR2Inventory(t, started)
			}
			cause := error(context.DeadlineExceeded)
			if !deadline {
				cause = context.Canceled
				cancel()
			}
			err = awaitR2Inventory(t, done)
			for range count {
				awaitR2Inventory(t, finished)
			}
			if !errors.Is(err, ErrIntegrity) || !errors.Is(err, cause) || heads.Load() != int32(count) || active.Load() != 0 {
				t.Fatalf("cancellation not propagated through SDK: heads=%d active=%d err=%v", heads.Load(), active.Load(), err)
			}
		})
	}
}

func TestR2InventoryCanceledBeforeListStartsNoRequests(t *testing.T) {
	client := &inventoryR2PublicationClient{
		list: func(context.Context, string, string) (r2.ObjectListPage, error) {
			t.Error("canceled inventory started a list request")
			return r2.ObjectListPage{}, nil
		},
		head: func(context.Context, string) (r2.ObjectInfo, error) {
			t.Error("canceled inventory started a HEAD request")
			return r2.ObjectInfo{}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	backend := &r2PublicationBackend{objects: client, prefix: "repos/prod"}
	if objects, err := backend.List(ctx, nil); objects != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled inventory=%v err=%v", objects, err)
	}
}

func BenchmarkR2InventoryHeadLatency(b *testing.B) {
	const count = 128
	const latency = 2 * time.Millisecond
	listed, infos := r2InventoryFixture(count)
	for _, parallel := range []bool{false, true} {
		b.Run(fmt.Sprintf("parallel=%t", parallel), func(b *testing.B) {
			var heads, active, maximum atomic.Int64
			var waitNS atomic.Int64
			client := &inventoryR2PublicationClient{
				list: func(context.Context, string, string) (r2.ObjectListPage, error) {
					return r2.ObjectListPage{Objects: listed}, nil
				},
				head: func(ctx context.Context, key string) (r2.ObjectInfo, error) {
					heads.Add(1)
					current := active.Add(1)
					defer active.Add(-1)
					for old := maximum.Load(); current > old && !maximum.CompareAndSwap(old, current); old = maximum.Load() {
					}
					start := time.Now()
					timer := time.NewTimer(latency)
					defer timer.Stop()
					select {
					case <-timer.C:
						waitNS.Add(int64(time.Since(start)))
						return infos[key], nil
					case <-ctx.Done():
						return r2.ObjectInfo{}, ctx.Err()
					}
				},
			}
			backend := &r2PublicationBackend{objects: client, prefix: "repos/prod"}
			ctx := context.Background()
			baseline := make([]publicationRemoteObject, count)
			for index, object := range listed {
				info := infos[object.Key]
				baseline[index] = publicationRemoteObject{Path: strings.TrimPrefix(object.Key, "repos/prod/"), Size: info.Size, SHA256: info.SHA256, RemoteIdentity: info.ETag}
			}
			b.ResetTimer()
			for range b.N {
				var objects []publicationRemoteObject
				if parallel {
					var err error
					objects, err = backend.List(ctx, nil)
					if err != nil {
						b.Fatal(err)
					}
				} else {
					// Reproduce the old serial List loop with identical evidence checks.
					previous := ""
					for _, object := range listed {
						verified, err := backend.headInventoryObject(ctx, object, previous)
						if err != nil {
							b.Fatal(err)
						}
						objects = append(objects, verified)
						previous = object.Key
					}
				}
				if !reflect.DeepEqual(objects, baseline) {
					b.Fatal("measured inventory differs from serial baseline")
				}
			}
			b.StopTimer()
			b.ReportMetric(count, "objects/op")
			b.ReportMetric(float64(heads.Load())/float64(b.N), "HEADs/op")
			b.ReportMetric(float64(maximum.Load()), "max_inflight")
			b.ReportMetric(float64(waitNS.Load())/float64(b.N)/float64(time.Millisecond), "HEAD_wait_ms/op")
			b.ReportMetric(float64(latency)/float64(time.Millisecond), "latency_ms/HEAD")
		})
	}
}
