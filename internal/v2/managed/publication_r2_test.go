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

	legacyPublish "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

type fakeR2PublicationObject struct {
	body []byte
	sha  string
	etag string
}

type fakeR2PublicationClient struct {
	objects map[string]fakeR2PublicationObject
	next    int
}

func (f *fakeR2PublicationClient) R2ListObjectsV2Prefix(_ context.Context, prefix, continuation string) (legacyPublish.ObjectListPage, error) {
	if continuation != "" {
		return legacyPublish.ObjectListPage{}, errors.New("unexpected continuation")
	}
	keys := []string{}
	for key := range f.objects {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	page := legacyPublish.ObjectListPage{}
	for _, key := range keys {
		object := f.objects[key]
		page.Objects = append(page.Objects, legacyPublish.ListedObject{Key: key, Size: int64(len(object.body)), ETag: object.etag})
	}
	return page, nil
}

func (f *fakeR2PublicationClient) R2Head(_ context.Context, key string) (legacyPublish.ObjectInfo, error) {
	object, ok := f.objects[key]
	if !ok {
		return legacyPublish.ObjectInfo{}, nil
	}
	return legacyPublish.ObjectInfo{Exists: true, Size: int64(len(object.body)), SHA256: object.sha, ETag: object.etag}, nil
}

func (f *fakeR2PublicationClient) R2OpenObject(_ context.Context, key string) (legacyPublish.ObjectContent, error) {
	info, _ := f.R2Head(context.Background(), key)
	if !info.Exists {
		return legacyPublish.ObjectContent{}, legacyPublish.ErrNotFound
	}
	return legacyPublish.ObjectContent{Info: info, Body: io.NopCloser(bytes.NewReader(f.objects[key].body))}, nil
}

func (f *fakeR2PublicationClient) R2Put(_ context.Context, key string, body io.Reader, size int64, sha string, condition legacyPublish.R2PutCondition) (string, error) {
	current, exists := f.objects[key]
	if condition.IfNoneMatch && exists {
		return "", legacyPublish.ErrAlreadyExists
	}
	if condition.IfMatch != "" && (!exists || current.etag != condition.IfMatch) {
		return "", legacyPublish.ErrConflict
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
	future := func() time.Time { return time.Now().UTC().Add(31 * 24 * time.Hour) }
	firstMaintenance, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: future})
	if err != nil || firstMaintenance.CompletedAttempts != 1 || firstMaintenance.DeletedObjects != 0 {
		t.Fatalf("first R2 maintenance=%#v err=%v", firstMaintenance, err)
	}
	collected, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
	if err != nil || collected.Noop || collected.Objects != 1 {
		t.Fatalf("local gc=%#v err=%v", collected, err)
	}
	second, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend})
	if err != nil || second.Generation == first.Generation {
		t.Fatalf("second R2 publish=%#v err=%v", second, err)
	}
	oldKey := "repos/prod/" + fixture.object.PoolPath
	oldObject, existedBefore := fake.objects[oldKey]
	if !existedBefore {
		t.Fatalf("old R2 payload missing before report-only maintenance: %s", oldKey)
	}
	maintenance, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend, now: future})
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
	noop, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "prod", backend: backend})
	if err != nil || !noop.Noop {
		t.Fatalf("R2 noop after retained report=%#v err=%v", noop, err)
	}
}
