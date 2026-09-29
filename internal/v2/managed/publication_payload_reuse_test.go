package managed

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestPublishedPayloadPathCannotBeReusedAfterGC(t *testing.T) {
	for _, scenario := range []string{"overwrite", "create-conflict", "legacy-abort", "legacy-before-intent", "legacy-after-intent", "legacy-tamper", "legacy-frozen-mutation", "legacy-add-reject", "legacy-add-abort", "legacy-add-before-intent", "legacy-add-after-intent"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			root, ws := newRejectionWorkspace(t)
			fake := &fakeR2PublicationClient{objects: map[string]fakeR2PublicationObject{}}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				o, ok := fake.objects["repos/prod/"+strings.TrimPrefix(r.URL.Path, "/repo/")]
				if !ok {
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write(o.body)
			}))
			defer server.Close()
			public, _ := url.Parse(server.URL + "/repo/")
			backend := &r2PublicationBackend{objects: fake, prefix: "repos/prod", publicBase: public}
			cfg, err := config.Load(filepath.Join(root, "sow.yml"))
			if err != nil {
				t.Fatal(err)
			}
			cfg.Targets = map[string]config.TargetConfig{"prod": {Repository: "repo", Provider: "r2", Endpoint: "https://acct.r2.cloudflarestorage.com", Region: "auto", Bucket: "sow-repo", Prefix: "repos/prod", Credential: "env://SOW_REVIEW_UNUSED", PublicEndpoint: server.URL + "/repo/", MaxCacheTTL: "0s", AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true}}
			writeManagedConfig(t, root, cfg)
			input := filepath.Join(root, "centos-release-latest.rpm")
			copyVersion := func(name string) {
				data, e := os.ReadFile(filepath.Join("../../../third_party/cavaliergopher-rpm/testdata", name))
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(input, data, 0644); e != nil {
					t.Fatal(e)
				}
			}
			add := func(path string) {
				_, e := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{path}, Jobs: 1})
				if e != nil {
					t.Fatal(e)
				}
			}
			now := time.Now().UTC()
			publish := func() error {
				_, e := Publish(ctx, PublishOptions{WorkspaceOptions: ws, Target: "prod", backend: backend, now: func() time.Time { return now }})
				return e
			}
			copyVersion("centos-release-6-0.el6.centos.5.x86_64.rpm")
			add(input)
			if err = publish(); err != nil {
				t.Fatal(err)
			}
			key := "repos/prod/pool/c/centos-release/centos-release-latest.rpm"
			old := fake.objects[key]
			if old.sha == "" {
				t.Fatal("payload not found")
			}
			if _, err = Remove(ctx, RemoveOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"centos-release"}, Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			epel, err := filepath.Abs("../../../third_party/cavaliergopher-rpm/testdata/epel-release-7-5.noarch.rpm")
			if err != nil {
				t.Fatal(err)
			}
			add(epel)
			now = now.Add(time.Minute)
			if err = publish(); err != nil {
				t.Fatal(err)
			}
			now = now.Add(31 * 24 * time.Hour)
			if _, err = TargetGC(ctx, TargetGCOptions{WorkspaceOptions: ws, Target: "prod", backend: backend, now: func() time.Time { return now }}); err != nil {
				t.Fatal(err)
			}
			gc, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: ws, Repository: "repo"})
			if err != nil || gc.Objects != 1 {
				t.Fatalf("local gc=%+v err=%v", gc, err)
			}
			if scenario == "create-conflict" || strings.HasPrefix(scenario, "legacy-add-") {
				now = now.Add(time.Second)
				if err = publish(); err != nil {
					t.Fatal(err)
				}
			}
			copyVersion("centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm")
			if strings.HasPrefix(scenario, "legacy-") {
				testLegacyPayloadAttempt(t, root, ws, cfg, backend, fake, input, scenario, now.Add(time.Second))
				return
			}
			result, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1})
			if !errors.Is(err, ErrRejected) || result.Accepted != 0 || result.Failed != 1 {
				t.Fatalf("reused published path accepted: %+v err=%v", result, err)
			}
			if fake.objects[key].sha != old.sha {
				t.Fatal("published payload changed")
			}
			// Rejection must not freeze a target or repository behind an active attempt.
			if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Second)
			if err = publish(); err != nil {
				t.Fatal(err)
			}

		})
	}
}

// Reconstruct a pre-fix workspace: temporarily hide historical inventory only
// while admitting the replacement package, then restore every row before any
// publication/recovery call. The resulting old/new manifests and bound attempt
// are complete, valid records, with real package bytes and generated metadata.
func testLegacyPayloadAttempt(t *testing.T, root string, ws WorkspaceOptions, cfg config.Config, backend *r2PublicationBackend, fake *fakeR2PublicationClient, input, scenario string, now time.Time) {
	t.Helper()
	addPlan := strings.HasPrefix(scenario, "legacy-add-")
	scenario = strings.Replace(scenario, "legacy-add-", "legacy-", 1)
	ctx := context.Background()
	openStore := func() *state.Store {
		s, err := state.OpenExisting(filepath.Join(root, ".sow/repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	store := openStore()
	type inventoryRow struct {
		checkpoint string
		object     state.PublicationInventoryObject
	}
	rows, err := store.DB().QueryContext(ctx, `SELECT checkpoint_identity, path, phase, size, sha256, remote_identity FROM publication_inventory`)
	if err != nil {
		t.Fatal(err)
	}
	saved := []inventoryRow{}
	for rows.Next() {
		var r inventoryRow
		if err := rows.Scan(&r.checkpoint, &r.object.Path, &r.object.Phase, &r.object.Size, &r.object.SHA256, &r.object.RemoteIdentity); err != nil {
			t.Fatal(err)
		}
		saved = append(saved, r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `DELETE FROM publication_inventory`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	crash := errors.New("legacy mutation interruption")
	added, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Skip: true, Jobs: 1, Fault: func(point string) error {
		if scenario == "legacy-frozen-mutation" && point == "add.applied" {
			return crash
		}
		return nil
	}})
	if scenario == "legacy-frozen-mutation" && !errors.Is(err, crash) || scenario != "legacy-frozen-mutation" && err != nil {
		t.Fatal(err)
	}
	store = openStore()
	if scenario == "legacy-frozen-mutation" {
		_, payload, _, err := loadMutationOperation(ctx, store, root, "repo", added.Operation)
		if err != nil {
			t.Fatal(err)
		}
		payload.Skip = false
		wire, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.UpdateOperationPayload(ctx, added.Operation, string(wire)); err != nil {
			t.Fatal(err)
		}
		_, err = buildAppliedMutation(ctx, root, "repo", cfg, []string{"el9"}, added.Operation, store, 1, func(point string) error {
			if point == "build.staged" {
				return crash
			}
			return nil
		}, nil)
		if !errors.Is(err, crash) {
			t.Fatalf("freeze legacy mutation: %v", err)
		}
	}
	for _, r := range saved {
		o := r.object
		if _, err := store.DB().ExecContext(ctx, `INSERT INTO publication_inventory(checkpoint_identity,path,phase,size,sha256,remote_identity) VALUES (?,?,?,?,?,?)`, r.checkpoint, o.Path, o.Phase, o.Size, o.SHA256, o.RemoteIdentity); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Check(ctx); err != nil {
		t.Fatalf("invalid reconstructed legacy state: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	built, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1})
	if err != nil {
		t.Fatalf("legacy build: %v", err)
	}
	if scenario == "legacy-frozen-mutation" || scenario == "legacy-reject" {
		if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
			t.Fatalf("repeat recovered build: %v", err)
		}
		checked, err := Check(ctx, CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1})
		if err != nil || !checked.ReadyToCopy {
			t.Fatalf("recovered local tree: %+v %v", checked, err)
		}
		store = openStore()
		var attemptsBefore int
		if err := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM publication_attempts`).Scan(&attemptsBefore); err != nil {
			t.Fatal(err)
		}
		store.Close()
		writes := fake.next
		_, err = Publish(ctx, PublishOptions{WorkspaceOptions: ws, Target: "prod", backend: backend, now: func() time.Time { return now }})
		if scenario == "legacy-reject" {
			if !errors.Is(err, state.ErrPoolPathConflict) {
				t.Fatalf("retained path conflict lost its reason: %v", err)
			}
		} else if !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "payload URL") {
			t.Fatalf("new publication of reused URL was allowed: %v", err)
		}
		if fake.next != writes {
			t.Fatal("rejected publication wrote remote objects")
		}
		store = openStore()
		defer store.Close()
		var attemptsAfter int
		if err := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM publication_attempts`).Scan(&attemptsAfter); err != nil || attemptsAfter != attemptsBefore {
			t.Fatalf("rejection created attempt: %d -> %d, %v", attemptsBefore, attemptsAfter, err)
		}
		if err := requireNoWriteActivePublication(ctx, store); err != nil {
			t.Fatalf("rejected publication left an active attempt: %v", err)
		}
		return
	}
	store = openStore()
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := publicationTargetBinding(cfg, "prod", identity.RepositoryID)
	if err != nil {
		t.Fatal(err)
	}
	target, err := store.GetPublicationTarget(ctx, binding.TargetIdentity)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := store.GetAppliedCheckpoint(ctx, target.Head.CheckpointIdentity)
	if err != nil {
		t.Fatal(err)
	}
	base, err := store.GenerationManifest(ctx, checkpoint.Generation)
	if err != nil {
		t.Fatal(err)
	}
	next, err := store.GenerationManifest(ctx, built.Generation)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := state.ReconcileLegacyPublicationPlan(state.PublicationPlanInput{RepositoryID: identity.RepositoryID, TargetIdentity: binding.TargetIdentity, BaseCheckpoint: checkpoint.CheckpointIdentity, TargetGeneration: built.Generation, BaseManifest: base, TargetManifest: next, Changes: state.DiffManifests(base, next)})
	if err != nil {
		t.Fatal(err)
	}
	expectedOperation := "update"
	if addPlan {
		expectedOperation = "add"
	}
	if len(plan.Payload) != 1 || plan.Payload[0].Operation != expectedOperation {
		t.Fatalf("legacy payload plan=%+v", plan.Payload)
	}
	views := publicationAttemptViews(plan, checkpoint.Inventory)
	attempt := state.PublicationAttempt{RepositoryID: identity.RepositoryID, TargetIdentity: binding.TargetIdentity, BaseCheckpoint: plan.BaseCheckpoint, TargetGeneration: plan.TargetGeneration, ManifestSHA256: plan.ManifestSHA256, PlanSHA256: plan.PlanSHA256, Phase: "planned", Views: views}
	if err := store.PutPublicationAttempt(ctx, &attempt); err != nil {
		t.Fatal(err)
	}
	if scenario != "legacy-abort" {
		op := plan.Payload[0]
		data, err := os.ReadFile(filepath.Join(root, "repo", filepath.FromSlash(op.Path)))
		if err != nil {
			t.Fatal(err)
		}
		// Only the fixture emulates the old backend's overwrite. Production Put
		// must subsequently perform an exact no-op and never replace these bytes.
		fake.objects["repos/prod/"+op.Path] = fakeR2PublicationObject{body: data, sha: op.SHA256, etag: "legacy-payload"}
		for _, op := range plan.ImmutableMetadata {
			if _, err := backend.Put(ctx, filepath.Join(root, "repo"), op, attempt.AttemptIdentity); err != nil {
				t.Fatal(err)
			}
		}
		for _, phase := range []string{"payload", "immutable_metadata", "pointer_prepared"} {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
				t.Fatal(err)
			}
		}
		for _, view := range views {
			if err := store.SetPublicationAttemptViewState(ctx, attempt.AttemptIdentity, view.ViewID, view.PointerPath, "prepared"); err != nil {
				t.Fatal(err)
			}
		}
		if scenario != "legacy-before-intent" {
			if err := store.SetPublicationCommitIntent(ctx, attempt.AttemptIdentity); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := errors.Join(store.Check(ctx), store.Close()); err != nil {
		t.Fatal(err)
	}
	if scenario == "legacy-abort" {
		result, err := AbandonPublication(ctx, PublicationAbandonOptions{WorkspaceOptions: ws, Target: "prod", backend: backend})
		if err != nil || result.Phase != "abandoned" {
			t.Fatalf("legacy abandon=%+v err=%v", result, err)
		}
		if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
			t.Fatal(err)
		}
		return
	}
	if scenario == "legacy-before-intent" {
		if _, err := AbandonPublication(ctx, PublicationAbandonOptions{WorkspaceOptions: ws, Target: "prod", backend: backend}); !errors.Is(err, ErrRejected) {
			t.Fatalf("changed old payload was abandoned: %v", err)
		}
	}
	op := plan.Payload[0]
	key := "repos/prod/" + op.Path
	if scenario == "legacy-tamper" {
		fake.objects[key] = fakeR2PublicationObject{body: []byte("foreign"), sha: bytesSHA([]byte("foreign")), etag: "foreign"}
	}
	result, err := Publish(ctx, PublishOptions{WorkspaceOptions: ws, Target: "prod", backend: backend, now: func() time.Time { return now }})
	if scenario == "legacy-tamper" {
		if !errors.Is(err, ErrIntegrity) || fake.objects[key].etag != "foreign" {
			t.Fatalf("tamper was overwritten: %+v %v", result, err)
		}
		return
	}
	if err != nil || result.Phase != "grace" || result.Attempt != attempt.AttemptIdentity {
		t.Fatalf("legacy resume=%+v err=%v", result, err)
	}
	if fake.objects[key].etag != "legacy-payload" {
		t.Fatal("recovery overwrote the payload instead of accepting its exact identity")
	}
	if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestFilesystemPublicationRejectsPayloadOverwrite(t *testing.T) {
	ctx := context.Background()
	root, err := realDirectory(t.TempDir(), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	backend := &filesystemPublicationBackend{root: root}
	path := "pool/p/pkg/pkg.rpm"
	filename := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		t.Fatal(err)
	}
	old := []byte("old payload")
	if err := os.WriteFile(filename, old, 0644); err != nil {
		t.Fatal(err)
	}
	op := state.PublicationPlanOperation{Operation: "update", Phase: "payload", Path: path, Size: 3, SHA256: bytesSHA([]byte("new")), ExpectedOldSHA256: bytesSHA(old)}
	if _, err := backend.Put(ctx, root, op, strings.Repeat("a", 64)); !errors.Is(err, ErrRejected) {
		t.Fatalf("payload overwrite accepted: %v", err)
	}
	actual, err := os.ReadFile(filename)
	if err != nil || string(actual) != string(old) {
		t.Fatalf("old bytes changed: %q %v", actual, err)
	}
	// A recovered old attempt may acknowledge exactly the bytes already there.
	op.Size, op.SHA256 = int64(len(old)), bytesSHA(old)
	if _, err := backend.Put(ctx, root, op, strings.Repeat("a", 64)); err != nil {
		t.Fatalf("exact payload replay failed: %v", err)
	}
}
