package managed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	mu         sync.Mutex
	objects    map[string]fakeR2PublicationObject
	conditions map[string]r2.PutCondition
	next       int
	headCounts map[string]int
}

func (f *fakeR2PublicationClient) resetHeadCounts() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headCounts = map[string]int{}
}

func (f *fakeR2PublicationClient) headCount(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.headCounts[key]
}

type managedRoundTripFunc func(*http.Request) (*http.Response, error)

func (f managedRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func (f *fakeR2PublicationClient) ListObjectsV2Prefix(_ context.Context, prefix, continuation string) (r2.ObjectListPage, error) {
	if continuation != "" {
		return r2.ObjectListPage{}, errors.New("unexpected continuation")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
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
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.headCounts == nil {
		f.headCounts = map[string]int{}
	}
	f.headCounts[key]++
	object, ok := f.objects[key]
	if !ok {
		return r2.ObjectInfo{}, nil
	}
	return r2.ObjectInfo{Exists: true, Size: int64(len(object.body)), SHA256: object.sha, ETag: object.etag}, nil
}

func (f *fakeR2PublicationClient) OpenObject(_ context.Context, key string) (r2.ObjectContent, error) {
	f.mu.Lock()
	object, ok := f.objects[key]
	f.mu.Unlock()
	if !ok {
		return r2.ObjectContent{}, r2.ErrNotFound
	}
	return r2.ObjectContent{
		Info: r2.ObjectInfo{Exists: true, Size: int64(len(object.body)), SHA256: object.sha, ETag: object.etag},
		Body: io.NopCloser(bytes.NewReader(object.body)),
	}, nil
}

func (f *fakeR2PublicationClient) Put(_ context.Context, key string, body r2.ReadSeekReaderAt, size int64, sha string, condition r2.PutCondition) (string, error) {
	data, err := io.ReadAll(io.LimitReader(body, size+1))
	if err != nil || int64(len(data)) != size {
		return "", errors.Join(errors.New("bad upload body"), err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != sha {
		return "", errors.New("bad upload digest")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	current, exists := f.objects[key]
	if condition.IfNoneMatch && exists {
		return "", r2.ErrAlreadyExists
	}
	if condition.IfMatch != "" && (!exists || current.etag != condition.IfMatch) {
		return "", r2.ErrConflict
	}
	f.next++
	etag := fmt.Sprintf("\"etag-%s\"", sha[:32])
	f.objects[key] = fakeR2PublicationObject{body: data, sha: sha, etag: etag}
	if f.conditions == nil {
		f.conditions = map[string]r2.PutCondition{}
	}
	f.conditions[key] = condition
	return etag, nil
}

func (f *fakeR2PublicationClient) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, key)
	return nil
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

func TestR2PublishAndTargetGCDeleteWithExplicitFlag(t *testing.T) {
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
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: backend, now: func() time.Time { return firstMaintenanceAt }}); err != nil {
		t.Fatal(err)
	}
	if _, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}); err != nil {
		t.Fatal(err)
	}
	secondPublishAt := firstMaintenanceAt.Add(time.Second)
	second, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return secondPublishAt }})
	if err != nil || second.Generation == first.Generation {
		t.Fatalf("second R2 publish=%#v err=%v", second, err)
	}
	oldKey := "repos/prod/" + fixture.object.PoolPath
	if _, ok := fake.objects[oldKey]; !ok {
		t.Fatalf("old R2 payload missing before conditional-delete GC: %s", oldKey)
	}
	secondMaintenanceAt := secondPublishAt.Add(31 * 24 * time.Hour)
	maintenance, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: backend, now: func() time.Time { return secondMaintenanceAt }})
	if err != nil || maintenance.DeletedObjects != 1 || maintenance.RetainedObjects != 0 || maintenance.DeletedBytes != fixture.object.Size {
		t.Fatalf("R2 conditional-delete maintenance=%#v err=%v", maintenance, err)
	}
	if _, ok := fake.objects[oldKey]; ok {
		t.Fatalf("R2 conditional-delete left deleted object in bucket: %s", oldKey)
	}
	store, err := state.OpenReadOnly(filepath.Join(fixture.root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	report, reportErr := store.GetPublicationCandidateReport(ctx, second.Checkpoint)
	var receipt state.PublicationDeletionReceipt
	var receiptErr error
	if reportErr == nil && len(report.Candidates) == 1 {
		receipt, receiptErr = store.GetPublicationDeletionReceipt(ctx, report.ReportIdentity, fixture.object.PoolPath)
	}
	closeErr := store.Close()
	if err := errors.Join(reportErr, receiptErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if report.Mode != "conditional_delete" || !receipt.StorageAbsent || !receipt.PublicAbsent {
		t.Fatalf("unexpected R2 deletion report/receipt: report=%#v receipt=%#v", report, receipt)
	}
	noop, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return secondMaintenanceAt }})
	if err != nil || !noop.Noop {
		t.Fatalf("R2 noop after conditional delete=%#v err=%v", noop, err)
	}
}

func TestR2KnownImmutableSkipsPayloadHEADsAndDetectsETagDrift(t *testing.T) {
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
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend}); err != nil {
		t.Fatal(err)
	}
	payloadKey := "repos/prod/" + fixture.object.PoolPath
	pointerKey := "repos/prod/dists/el9/x86_64/repodata/repomd.xml"
	fake.resetHeadCounts()
	noop, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend})
	if err != nil || !noop.Noop {
		t.Fatalf("second R2 publish=%#v err=%v", noop, err)
	}
	if got := fake.headCount(payloadKey); got != 0 {
		t.Fatalf("unchanged R2 payload incurred %d HEADs on second publish, want 0", got)
	}
	if got := fake.headCount(pointerKey); got == 0 {
		t.Fatal("mutable R2 pointer skipped HEAD check")
	}
	original := fake.objects[payloadKey]
	fake.objects[payloadKey] = fakeR2PublicationObject{body: original.body, sha: strings.Repeat("f", 64), etag: `"drifted-etag"`}
	fake.resetHeadCounts()
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend}); !errors.Is(err, ErrIntegrity) || fake.headCount(payloadKey) == 0 {
		t.Fatalf("ETag drift err=%v payloadHEADs=%d, want ErrIntegrity after HEAD recheck", err, fake.headCount(payloadKey))
	}
}

func TestR2TargetGCDeleteCrashRecoveryAndModeGuard(t *testing.T) {
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
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend}); err != nil {
		t.Fatal(err)
	}
	firstGCAt := time.Now().UTC().Add(31 * 24 * time.Hour)
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: backend, now: func() time.Time { return firstGCAt }}); err != nil {
		t.Fatal(err)
	}
	if _, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}); err != nil {
		t.Fatal(err)
	}
	secondPublishAt := firstGCAt.Add(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return secondPublishAt }}); err != nil {
		t.Fatal(err)
	}
	gcAt := secondPublishAt.Add(31 * 24 * time.Hour)
	reportFault := errors.New("crash after report")
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: backend, now: func() time.Time { return gcAt }, Fault: func(point string) error {
		if point == "target_gc.report" {
			return reportFault
		}
		return nil
	}}); !errors.Is(err, reportFault) {
		t.Fatalf("report fault=%v", err)
	}
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: false, backend: backend, now: func() time.Time { return gcAt }}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("resuming conditional_delete without --delete returned %v, want ErrNotReady", err)
	}
	deleteFault := errors.New("crash after delete")
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: backend, now: func() time.Time { return gcAt }, Fault: func(point string) error {
		if point == "target_gc.deleted."+fixture.object.PoolPath {
			return deleteFault
		}
		return nil
	}}); !errors.Is(err, deleteFault) {
		t.Fatalf("delete fault=%v", err)
	}
	resumed, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: backend, now: func() time.Time { return gcAt }})
	if err != nil || resumed.DeletedObjects != 1 || resumed.CompletedAttempts != 1 {
		t.Fatalf("resumed R2 conditional delete=%#v err=%v", resumed, err)
	}
}

func TestR2ReviewThenDeleteAndRepublishIdenticalPackage(t *testing.T) {
	ctx := context.Background()
	fixture := newLocalGCFixture(t, false)
	fake := &fakeR2PublicationClient{objects: map[string]fakeR2PublicationObject{}}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		relative := strings.TrimPrefix(request.URL.Path, "/repo/")
		fake.mu.Lock()
		object, ok := fake.objects["repos/prod/"+relative]
		fake.mu.Unlock()
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

	rpmCopy := filepath.Join(t.TempDir(), filepath.Base(fixture.object.Filename))
	rawRPM, err := os.ReadFile(filepath.Join(fixture.root, "repo", filepath.FromSlash(fixture.object.PoolPath)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rpmCopy, rawRPM, 0o644); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * 24 * time.Hour)
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	if _, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}

	// 1. Report-first (`sow gc prod`), then `--delete` (`sow gc prod --delete`).
	now = now.Add(31 * 24 * time.Hour)
	reviewed, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: false, backend: backend, now: func() time.Time { return now }})
	if err != nil || reviewed.RetainedObjects != 1 || reviewed.DeletedObjects != 0 {
		t.Fatalf("review-first R2 GC=%#v err=%v", reviewed, err)
	}
	now = now.Add(time.Second)
	deleted, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: backend, now: func() time.Time { return now }})
	if err != nil || deleted.DeletedObjects != 1 {
		t.Fatalf("delete-after-review R2 GC=%#v err=%v", deleted, err)
	}
	now = now.Add(time.Second)
	noopGC, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: backend, now: func() time.Time { return now }})
	if err != nil || !noopGC.Noop || noopGC.DeletedObjects != 0 {
		t.Fatalf("repeat R2 GC --delete=%#v err=%v", noopGC, err)
	}

	// 2. Re-add identical RPM bytes (producing the exact same ETag!), publish, and
	// verify the next no-op publish succeeds without subtracting stale receipts.
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpmCopy}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	republished, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }})
	if err != nil || republished.Noop {
		t.Fatalf("re-publish identical RPM=%#v err=%v", republished, err)
	}
	now = now.Add(time.Second)
	noopPub, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }})
	if err != nil || !noopPub.Noop {
		t.Fatalf("no-op publish after identical RPM re-upload failed: %#v err=%v", noopPub, err)
	}

	// 3. Remove again -> add a second RPM (rotating prior_built_memberships) ->
	// publish -> expire -> LocalGC -> publish -> expire -> report-only ->
	// re-add & publish BEFORE --delete -> verify --delete re-checks live protection
	// roots and does NOT delete the active payload!
	otherRPM, err := filepath.Abs(filepath.Join("..", "..", "..", "third_party", "cavaliergopher-rpm", "testdata", "epel-release-7-5.noarch.rpm"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{fixture.object.Name}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{otherRPM}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * 24 * time.Hour)
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: false, backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	if collected, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}); err != nil || collected.Objects != 1 {
		t.Fatalf("second LocalGC=%#v err=%v", collected, err)
	}
	now = now.Add(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * 24 * time.Hour)
	if rev2, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: false, backend: backend, now: func() time.Time { return now }}); err != nil || rev2.RetainedObjects < 1 {
		t.Fatalf("second review-first R2 GC=%#v err=%v", rev2, err)
	}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpmCopy}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if safeDelete, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatalf("TargetGC --delete after re-protecting payload failed: %#v err=%v", safeDelete, err)
	}
	fake.mu.Lock()
	_, payloadAlive := fake.objects["repos/prod/"+fixture.object.PoolPath]
	fake.mu.Unlock()
	if !payloadAlive {
		t.Fatal("TargetGC --delete deleted a payload that was re-protected before --delete ran")
	}
}

// TestR2DelayedDeleteAfterReaddAndGraceProtection covers two critical multi-
// generation R2 maintenance contracts:
//  1. Promoting an older report-only checkpoint after the same RPM was re-added
//     and removed again must not delete the object while the newer removal's
//     grace period is still active.
//  2. Once the newer removal's grace expires, promoting all retained reports
//     must attribute the deletion receipt to the newer removing checkpoint so
//     subsequent GC retries, normal Publish, and identical-ETag re-uploads all
//     converge cleanly.
func TestR2DelayedDeleteAfterReaddAndGraceProtection(t *testing.T) {
	runScenario := func(t *testing.T, checkActiveGraceBeforeExpiry bool) {
		t.Helper()
		ctx := context.Background()
		fixture := newLocalGCFixture(t, false)
		fake := &fakeR2PublicationClient{objects: map[string]fakeR2PublicationObject{}}
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			relative := strings.TrimPrefix(request.URL.Path, "/repo/")
			fake.mu.Lock()
			object, ok := fake.objects["repos/prod/"+relative]
			fake.mu.Unlock()
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
		newBackend := func() *r2PublicationBackend {
			return &r2PublicationBackend{objects: fake, prefix: "repos/prod", publicBase: publicBase}
		}
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

		rpmCopy := filepath.Join(t.TempDir(), filepath.Base(fixture.object.Filename))
		rawRPM, err := os.ReadFile(filepath.Join(fixture.root, "repo", filepath.FromSlash(fixture.object.PoolPath)))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rpmCopy, rawRPM, 0o644); err != nil {
			t.Fatal(err)
		}
		thirdRPM, err := filepath.Abs(filepath.Join("..", "..", "..", "third_party", "cavaliergopher-rpm", "testdata", "centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm"))
		if err != nil {
			t.Fatal(err)
		}

		now := time.Now().UTC().Truncate(time.Second)
		clock := func() time.Time { return now }
		publish := func() PublishResult {
			t.Helper()
			res, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: newBackend(), now: clock})
			if err != nil {
				t.Fatalf("publish: %+v %v", res, err)
			}
			return res
		}
		gc := func(del bool) TargetGCResult {
			t.Helper()
			res, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: del, backend: newBackend(), now: clock})
			if err != nil {
				t.Fatalf("target GC (delete=%t): %+v %v", del, res, err)
			}
			return res
		}
		payloadKey := "repos/prod/" + fixture.object.PoolPath
		existsOnR2 := func() bool {
			fake.mu.Lock()
			defer fake.mu.Unlock()
			_, ok := fake.objects[payloadKey]
			return ok
		}

		// C1 (has retained pkg1) -> report-only -> LocalGC -> C2 (pkg1 absent
		// from manifest, retained on R2) -> report-only (lists pkg1).
		publish()
		now = now.Add(31 * 24 * time.Hour)
		gc(false)
		if collected, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}); err != nil || collected.Objects != 1 {
			t.Fatalf("first LocalGC=%#v err=%v", collected, err)
		}
		now = now.Add(time.Second)
		publish()
		now = now.Add(31 * 24 * time.Hour)
		if rev := gc(false); rev.RetainedObjects != 1 {
			t.Fatalf("expected 1 retained candidate in C2, got %#v", rev)
		}

		// Re-add identical pkg1 -> publish (C3) -> remove pkg1, add pkg3 ->
		// publish (C4) -> report-only -> LocalGC -> publish (C5, pkg1 absent).
		if _, err := Add(ctx, AddOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpmCopy}, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
		if restored := publish(); restored.Noop {
			t.Fatal("re-adding pkg1 must publish a new generation")
		}
		if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{fixture.object.Name}, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, AddOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{thirdRPM}, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
		publish()
		now = now.Add(31 * 24 * time.Hour)
		gc(false)
		if collected, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}); err != nil || collected.Objects != 1 {
			t.Fatalf("second LocalGC=%#v err=%v", collected, err)
		}
		now = now.Add(time.Second)
		publish()

		if checkActiveGraceBeforeExpiry {
			// C5 is STILL in its 30-day cache grace period! Promoting old C2 with
			// --delete MUST NOT delete pkg1 prematurely (even if unrelated expired
			// metadata from C3->C4 is collected).
			now = now.Add(time.Minute)
			early := gc(true)
			if early.PendingGrace == 0 {
				t.Fatalf("early --delete during C5 active grace=%#v, want pending>0", early)
			}
			if !existsOnR2() {
				t.Fatal("early --delete violated C5 active grace and deleted pkg1 from R2")
			}
			if pub := publish(); !pub.Noop {
				t.Fatalf("publish after early --delete=%#v, want noop", pub)
			}
			now = now.Add(31 * 24 * time.Hour)
		} else {
			// Expire C5 and run report-only so BOTH C2 and C5 are retained_reported
			// when --delete runs for the first time.
			now = now.Add(31 * 24 * time.Hour)
			gc(false)
		}

		deleted := gc(true)
		if deleted.DeletedObjects < 1 {
			t.Fatalf("delayed --delete=%#v, want deleted>=1", deleted)
		}
		if existsOnR2() {
			t.Fatal("pkg1 remained on R2 after delayed --delete")
		}
		if retry := gc(true); !retry.Noop || retry.DeletedObjects != 0 {
			t.Fatalf("retry --delete=%#v, want noop", retry)
		}
		if pub := publish(); !pub.Noop {
			t.Fatalf("follow-up publish=%#v, want noop", pub)
		}

		// Re-add identical pkg1 again (same ETag) and confirm republish + noop converge.
		if _, err := Add(ctx, AddOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpmCopy}, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
		if repub := publish(); repub.Noop {
			t.Fatal("re-adding pkg1 after delayed delete must publish")
		}
		if !existsOnR2() {
			t.Fatal("re-added pkg1 missing on R2")
		}
		now = now.Add(time.Second)
		if pub := publish(); !pub.Noop {
			t.Fatalf("follow-up publish after second re-add=%#v, want noop", pub)
		}
	}

	t.Run("delayed delete after re-add and re-remove", func(t *testing.T) {
		runScenario(t, false)
	})
	t.Run("delayed delete respects newer removal grace", func(t *testing.T) {
		runScenario(t, true)
	})
}

// TestR2InterruptedConditionalDeleteResumesBeforeEarlierMaintenanceAndAllowsLocalGC
// verifies two recovery invariants:
//  1. When a promoted historical R2 checkpoint is interrupted mid-delete (leaving
//     attempt.phase='grace' even though its target_generation payloads were
//     already legally collected by LocalGC while it was done), LocalGC must not
//     report a false ErrIntegrity on those remote-only historical payloads.
//  2. If another maintenance item precedes an interrupted conditional-delete
//     report in causal order, TargetGC must resume the unfinished conditional-
//     delete report FIRST (with allowCandidateAbsence=true) rather than failing
//     inventory verification on the earlier checkpoint with ErrIntegrity.
func TestR2InterruptedConditionalDeleteResumesBeforeEarlierMaintenanceAndAllowsLocalGC(t *testing.T) {
	ctx := context.Background()
	fixture := newLocalGCFixture(t, false)
	fake := &fakeR2PublicationClient{objects: map[string]fakeR2PublicationObject{}}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		relative := strings.TrimPrefix(request.URL.Path, "/repo/")
		fake.mu.Lock()
		object, ok := fake.objects["repos/prod/"+relative]
		fake.mu.Unlock()
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
	newBackend := func() *r2PublicationBackend {
		return &r2PublicationBackend{objects: fake, prefix: "repos/prod", publicBase: publicBase}
	}
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

	secondRPM, err := filepath.Abs(filepath.Join("..", "..", "..", "third_party", "cavaliergopher-rpm", "testdata", "epel-release-7-5.noarch.rpm"))
	if err != nil {
		t.Fatal(err)
	}
	thirdRPM, err := filepath.Abs(filepath.Join("..", "..", "..", "third_party", "cavaliergopher-rpm", "testdata", "centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm"))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }

	// Add pkg2 (epel-release) while pkg1 is retained in pool -> publish C1
	// (has pkg1 + pkg2) -> report-only -> LocalGC deletes pkg1 -> publish C2
	// (has pkg2; pkg1 retained on R2).
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{secondRPM}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	c1, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: newBackend(), now: clock})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * 24 * time.Hour)
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: newBackend(), now: clock}); err != nil {
		t.Fatal(err)
	}
	if collected, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}); err != nil || collected.Objects != 1 {
		t.Fatalf("first LocalGC=%#v err=%v", collected, err)
	}
	now = now.Add(time.Second)
	c2, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: newBackend(), now: clock})
	if err != nil {
		t.Fatal(err)
	}
	// Remove pkg2, add pkg3, expire C2, run report-only on C2, then LocalGC deletes pkg2
	// (so C2's target_generation payload pkg2 is now absent locally!).
	if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"epel-release"}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{thirdRPM}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: newBackend(), now: clock}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * 24 * time.Hour)
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: newBackend(), now: clock}); err != nil {
		t.Fatal(err)
	}
	if collected, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}); err != nil || collected.Objects != 1 {
		t.Fatalf("second LocalGC=%#v err=%v", collected, err)
	}
	now = now.Add(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: newBackend(), now: clock}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * 24 * time.Hour)
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: newBackend(), now: clock}); err != nil {
		t.Fatal(err)
	}

	// Interrupt right after C2 physically deletes pkg1 on R2 (before receipt).
	interruptErr := errors.New("interrupted after physical delete")
	if _, err := TargetGC(ctx, TargetGCOptions{
		WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: newBackend(), now: clock,
		Fault: func(point string) error {
			if point == "target_gc.deleted."+fixture.object.PoolPath {
				return interruptErr
			}
			return nil
		},
	}); !errors.Is(err, interruptErr) {
		t.Fatalf("expected delete interrupt, got %v", err)
	}

	// 1. LocalGC while C2 (whose target_generation payload pkg2 was already
	// collected) is paused in phase='grace' must succeed as a noop, not fail
	// with ErrIntegrity.
	localAfterInterrupt, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
	if err != nil || !localAfterInterrupt.Noop {
		t.Fatalf("LocalGC during interrupted promoted R2 delete=%#v err=%v, want noop without ErrIntegrity", localAfterInterrupt, err)
	}

	// 2. Also simulate an earlier checkpoint (C1) still being retained_reported
	// ahead of the unfinished C2 conditional_delete report: TargetGC must still
	// prioritize resuming C2 first instead of failing exact inventory check on C1.
	store, err := state.OpenExisting(filepath.Join(fixture.root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE publication_grace_records SET state = 'retained_reported' WHERE checkpoint_identity = ?`, c1.Checkpoint); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE publication_candidate_reports SET mode = 'report_only' WHERE checkpoint_identity = ?`, c1.Checkpoint); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	_ = c2

	// Without --delete, TargetGC must immediately report ErrNotReady (not ErrIntegrity).
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: false, backend: newBackend(), now: clock}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("TargetGC without --delete while earlier item precedes unfinished delete: err=%v, want ErrNotReady", err)
	}

	// With --delete, TargetGC must resume C2 first, then finish C1 and all later
	// checkpoints cleanly.
	resumed, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: newBackend(), now: clock})
	if err != nil || resumed.DeletedObjects == 0 {
		t.Fatalf("resumed TargetGC --delete=%#v err=%v", resumed, err)
	}
	if retry, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: newBackend(), now: clock}); err != nil || !retry.Noop {
		t.Fatalf("repeat TargetGC --delete=%#v err=%v, want noop", retry, err)
	}
	if pub, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: newBackend(), now: clock}); err != nil || !pub.Noop {
		t.Fatalf("follow-up publish=%#v err=%v, want noop", pub, err)
	}
}

func TestSiloManagedR2DeleteRepublishAndNoop(t *testing.T) {
	if os.Getenv("SOW_SILO_TEST") != "1" {
		t.Skip("set SOW_SILO_TEST=1 to run the pinned Silo managed R2 end-to-end test")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatalf("SOW_SILO_TEST=1 requires docker: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	const siloImage = "pgsty/silo@sha256:635197cb9f36d01bee221d34d1c7d7960f6a95c48b0b6c01d99cd13bdae51a46"
	container := fmt.Sprintf("sow-managed-silo-%d", time.Now().UnixNano())
	cmd := exec.CommandContext(ctx, docker,
		"run", "-d", "--rm", "--name", container,
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-e", "MINIO_ROOT_USER=sowtest",
		"-e", "MINIO_ROOT_PASSWORD=sowtest-secret-key",
		"-e", "MINIO_BROWSER=off",
		"-p", "127.0.0.1::9000",
		"--tmpfs", "/data:rw,size=256m,mode=1777",
		siloImage,
		"sh", "-ec", "mkdir -p /data/repo && exec docker-entrypoint.sh server /data --address :9000 --console-address :9001",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("start Silo: %v: %s", err, strings.TrimSpace(string(out)))
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		_ = exec.CommandContext(stopCtx, docker, "rm", "-f", container).Run()
	})
	portOut, err := exec.CommandContext(ctx, docker, "port", container, "9000/tcp").CombinedOutput()
	if err != nil {
		t.Fatalf("discover Silo port: %v: %s", err, strings.TrimSpace(string(portOut)))
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(string(portOut)))
	if err != nil {
		t.Fatal(err)
	}
	r2Client, err := r2.NewClient(r2.Config{
		Bucket: "repo", ObjectBaseURL: "http://127.0.0.1:" + port + "/repo", AllowInsecure: true,
		Credentials: r2.S3Credentials{AccessKeyID: "sowtest", SecretAccessKey: "sowtest-secret-key", Region: "us-east-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := r2Client.ListObjectsV2Prefix(ctx, "", ""); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	publicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		key := "repos/prod/" + strings.TrimPrefix(req.URL.Path, "/repo/")
		obj, openErr := r2Client.OpenObject(req.Context(), key)
		if errors.Is(openErr, r2.ErrNotFound) {
			http.NotFound(w, req)
			return
		}
		if openErr != nil {
			http.Error(w, openErr.Error(), http.StatusBadGateway)
			return
		}
		defer obj.Body.Close()
		_, _ = io.Copy(w, obj.Body)
	}))
	defer publicServer.Close()
	publicBase, err := url.Parse(publicServer.URL + "/repo/")
	if err != nil {
		t.Fatal(err)
	}
	backend := &r2PublicationBackend{objects: r2Client, prefix: "repos/prod", publicBase: publicBase}

	fixture := newLocalGCFixture(t, false)
	rpmCopy := filepath.Join(t.TempDir(), filepath.Base(fixture.object.Filename))
	rawRPM, err := os.ReadFile(filepath.Join(fixture.root, "repo", filepath.FromSlash(fixture.object.PoolPath)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rpmCopy, rawRPM, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(fixture.root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets = map[string]config.TargetConfig{"prod": {
		Repository: "repo", Provider: "r2", Endpoint: "https://acct.r2.cloudflarestorage.com",
		Region: "auto", Bucket: "repo", Prefix: "repos/prod", Credential: "env://SOW_TEST_UNUSED_R2",
		PublicEndpoint: publicServer.URL + "/repo/", MaxCacheTTL: "0s",
		AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true,
	}}
	writeManagedConfig(t, fixture.root, cfg)

	now := time.Now().UTC().Truncate(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * 24 * time.Hour)
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	if _, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * 24 * time.Hour)
	if gcRes, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: backend, now: func() time.Time { return now }}); err != nil || gcRes.DeletedObjects < 1 {
		t.Fatalf("Silo R2 gc --delete=%#v err=%v", gcRes, err)
	}

	// Re-add the exact same RPM bytes -> Silo assigns the exact same MD5 ETag ->
	// publish -> next publish MUST return Noop=true!
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpmCopy}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if repub, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil || repub.Noop {
		t.Fatalf("Silo R2 republish identical RPM=%#v err=%v", repub, err)
	}
	now = now.Add(time.Second)
	if noop, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil || !noop.Noop {
		t.Fatalf("Silo R2 follow-up publish after identical ETag re-upload=%#v err=%v", noop, err)
	}

	// Multi-generation delayed delete: remove -> report-only -> re-add -> remove
	// -> report-only -> --delete must converge on real Silo and allow subsequent
	// GC retries and Publish calls.
	thirdRPM, err := filepath.Abs(filepath.Join("..", "..", "..", "third_party", "cavaliergopher-rpm", "testdata", "centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{fixture.object.Name}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{thirdRPM}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * 24 * time.Hour)
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: false, backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	if _, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * 24 * time.Hour)
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: false, backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpmCopy}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{fixture.object.Name}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * 24 * time.Hour)
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: false, backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	if _, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * 24 * time.Hour)
	if _, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: false, backend: backend, now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	if delRes, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: backend, now: func() time.Time { return now }}); err != nil || delRes.DeletedObjects < 1 {
		t.Fatalf("Silo R2 delayed multi-generation --delete=%#v err=%v", delRes, err)
	}
	if retryRes, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", Delete: true, backend: backend, now: func() time.Time { return now }}); err != nil || !retryRes.Noop {
		t.Fatalf("Silo R2 delayed delete retry=%#v err=%v, want noop", retryRes, err)
	}
	if finalPub, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil || !finalPub.Noop {
		t.Fatalf("Silo R2 follow-up publish after delayed delete=%#v err=%v, want noop", finalPub, err)
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
		// The SDK retries bodyless HEAD 429 responses as throttling errors.
		// Keep the retry bound and preserve the HTTP status after exhaustion.
		{"rate limited retry", http.StatusTooManyRequests, 1, 2, false},
		{"rate limited exhausted", http.StatusTooManyRequests, 3, 3, true},
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
