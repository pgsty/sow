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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/r2"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
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
	secondETag, err := backend.Put(ctx, sourceRoot, update, strings.Repeat("a", 64))
	if err != nil || secondETag == firstETag || len(fake.objects) != 1 {
		t.Fatalf("R2 update etag=%q err=%v", secondETag, err)
	}
	objects, err := backend.List(ctx, nil)
	if err != nil || len(objects) != 1 || objects[0].Path != objectPath || objects[0].RemoteIdentity != secondETag {
		t.Fatalf("R2 list=%#v err=%v", objects, err)
	}
	if err := backend.VerifyPublic(ctx, state.GenerationFile{Path: objectPath, Phase: "payload", Size: update.Size, SHA256: update.SHA256}); err != nil {
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
