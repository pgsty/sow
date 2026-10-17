package managed

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

func publicationFixture(t *testing.T) (context.Context, string, WorkspaceOptions, []string) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Architectures = []string{"aarch64"}
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}, "jammy": {Format: "deb"}}}
	key, _ := managedTestPrivateKey(t, "publication-time")
	t.Setenv("SOW_PUBLICATION_KEY", string(key))
	repo := cfg.Repositories["repo"]
	repo.Signing.RPM.Metadata.Key = "env://SOW_PUBLICATION_KEY"
	repo.Signing.DEB.Metadata.Key = "env://SOW_PUBLICATION_KEY"
	cfg.Repositories["repo"] = repo
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "test.rpm"))
	deb := decodeManagedFixture(t, filepath.Join("..", "..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(inputs, "test.deb"))
	return ctx, root, WorkspaceOptions{Workdir: root, CWD: root}, []string{rpm, deb}
}

func publicationStore(t *testing.T, root string) *state.Store {
	t.Helper()
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func assertPublicationMetadata(t *testing.T, ctx context.Context, root string) {
	t.Helper()
	store := publicationStore(t, root)
	dists, err := store.ListDists(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, dist := range dists {
		generation, err := store.GetGeneration(ctx, dist.BuiltGeneration)
		if err != nil {
			t.Fatal(err)
		}
		detail, err := store.GetOperation(ctx, generation.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		publication, err := retainedPublicationIdentity(detail.Operation)
		if err != nil || !publication.Current {
			t.Fatalf("missing publication_time in %s: %+v %v", detail.Operation.Kind, publication, err)
		}
		assertPublicationFileTimes(t, filepath.Join(root, "repo", "dists", dist.Name), dist, publication.Time)
		retained, err := builtGenerationPublicationTime(ctx, store, dist.BuiltGeneration)
		if err != nil || !retained.Equal(publication.Time) {
			t.Fatalf("retained publication=%s want=%s err=%v", retained, publication.Time, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if err != nil || checked.Status != "clean" {
		t.Fatalf("Check after stage cleanup: %+v %v", checked, err)
	}
}

func TestPublicationTimeCurrentOperationsAndNoop(t *testing.T) {
	ctx, root, opts, paths := publicationFixture(t)
	assertPublicationMetadata(t, ctx, root) // dist.init
	for _, kind := range []string{"add", "build", "rm"} {
		if kind == "build" {
			if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9", "jammy"}, Packages: []string{"pgdg-redhat-nonfree-repo", "libpqtypes0"}, Skip: true, Jobs: 1}); err != nil {
				t.Fatal(err)
			}
		}
		if kind == "rm" {
			if _, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9", "jammy"}, Paths: paths, Jobs: 1}); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(1100 * time.Millisecond)
		started := time.Now().UTC().Truncate(time.Second)
		var id string
		switch kind {
		case "add":
			result, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9", "jammy"}, Paths: paths, Jobs: 1})
			if err != nil {
				t.Fatal(err)
			}
			id = result.Operation
		case "build":
			result, err := Build(ctx, BuildOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1})
			if err != nil || result.Noop {
				t.Fatalf("build=%+v err=%v", result, err)
			}
			id = result.Operation
		case "rm":
			result, err := Remove(ctx, RemoveOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9", "jammy"}, Packages: []string{"pgdg-redhat-nonfree-repo", "libpqtypes0"}, Jobs: 1})
			if err != nil {
				t.Fatal(err)
			}
			id = result.Operation
		}
		store := publicationStore(t, root)
		detail, err := store.GetOperation(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		publication, err := retainedPublicationIdentity(detail.Operation)
		if err != nil || !publication.Current || publication.Time.Before(started) || publication.Time.After(time.Now()) {
			t.Fatalf("%s publication=%+v started=%s err=%v", kind, publication, started, err)
		}
		if _, err := os.Stat(mutationStageRoot(root, "repo", id)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("successful operation retained its stage: %v", err)
		}
		_ = store.Close()
		assertPublicationMetadata(t, ctx, root)
	}
	for _, format := range []string{"rpm", "deb"} {
		if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: opts, Repository: "repo", Name: "extra-" + format, Format: format}); err != nil {
			t.Fatal(err)
		}
	}
	assertPublicationMetadata(t, ctx, root) // dist.new
	before, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	result, err := Build(ctx, BuildOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1})
	if err != nil || !result.Noop {
		t.Fatalf("noop=%+v err=%v", result, err)
	}
	store := publicationStore(t, root)
	detail, err := store.GetOperation(ctx, result.Operation)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := retainedPublicationIdentity(detail.Operation)
	if err != nil || publication.Current {
		t.Fatalf("noop has physical time: %+v %v", publication, err)
	}
	after, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil || !sameGenerationManifest(before, after) {
		t.Fatalf("clock changed noop bytes: %v", err)
	}
}

func TestPublicationTimeStrictWire(t *testing.T) {
	for _, raw := range []string{`null`, `""`, `0`, `true`, `[]`, `{}`, `"0001-01-01T00:00:00Z"`, `"1969-12-31T23:59:59Z"`, `"2026-10-16T00:00:00.1Z"`, `"2026-10-16T00:00:00+00:00"`, `"2026-10-16T00:00:00+08:00"`, `"10000-01-01T00:00:00Z"`} {
		for _, target := range []any{&mutationOperationPayload{}, &distOperationPayload{}} {
			if err := json.Unmarshal([]byte(`{"publication_time":`+raw+`}`), target); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("invalid %s accepted by %T: %v", raw, target, err)
			}
		}
	}
	for _, raw := range []string{`{}`, `{"publication_time":"1970-01-01T00:00:00Z"}`, `{"publication_time":"9999-12-31T23:59:59Z"}`} {
		var payload mutationOperationPayload
		if err := json.Unmarshal([]byte(raw), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.PublicationTime.identity().Current != (raw != `{}`) {
			t.Fatalf("wrong legacy discriminator for %s", raw)
		}
	}
}

func TestPublicationTimeInvalidJournalRejectsBeforePublicMutation(t *testing.T) {
	for _, point := range []string{"add.staged", "build.staged"} {
		t.Run(point, func(t *testing.T) {
			ctx, root, opts, paths := publicationFixture(t)
			stopped := errors.New("stop publication")
			result, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9", "jammy"}, Paths: paths, Jobs: 1, Fault: func(at string) error {
				if at == point {
					return stopped
				}
				return nil
			}})
			if !errors.Is(err, stopped) {
				t.Fatal(err)
			}
			store := publicationStore(t, root)
			operation, _, _, err := loadMutationJournal(ctx, store, root, "repo", result.Operation)
			if err != nil {
				t.Fatal(err)
			}
			before, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(operation.PayloadJSON), &fields); err != nil {
				t.Fatal(err)
			}
			for _, raw := range []string{`null`, `""`, `42`, `"1969-12-31T23:59:59Z"`, `"2026-10-16T00:00:00.5Z"`} {
				fields["publication_time"] = json.RawMessage(raw)
				data, _ := json.Marshal(fields)
				if err := store.UpdateOperationPayload(ctx, operation.ID, string(data)); err != nil {
					t.Fatal(err)
				}
				bad := operation
				bad.PayloadJSON = string(data)
				if err := recoverMutationOperation(ctx, root, "repo", store, bad); !errors.Is(err, ErrIntegrity) {
					t.Fatalf("%s: %v", raw, err)
				}
				after, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
				if err != nil || !sameGenerationManifest(before, after) {
					t.Fatalf("invalid journal changed public bytes: %v", err)
				}
			}
			if err := store.UpdateOperationPayload(ctx, operation.ID, operation.PayloadJSON); err != nil {
				t.Fatal(err)
			}
			if err := recoverDistOperations(ctx, root, "repo", store); err != nil {
				t.Fatal(err)
			}
			_ = store.Close()
			assertPublicationMetadata(t, ctx, root)
		})
	}
}

func TestPublicationTimeDriftRejectsFurtherDistPublication(t *testing.T) {
	for _, point := range []string{"build.staged", "build.pointer.el9", "build.pointer.jammy"} {
		t.Run(point, func(t *testing.T) {
			ctx, root, opts, paths := publicationFixture(t)
			stopped := errors.New("stop publication")
			result, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9", "jammy"}, Paths: paths, Jobs: 1, Fault: func(at string) error {
				if at == point {
					return stopped
				}
				return nil
			}})
			if !errors.Is(err, stopped) {
				t.Fatal(err)
			}
			store := publicationStore(t, root)
			operation, _, _, err := loadMutationJournal(ctx, store, root, "repo", result.Operation)
			if err != nil {
				t.Fatal(err)
			}
			distsRoot := filepath.Join(root, "repo", "dists")
			before, _, err := digestTree(ctx, distsRoot)
			if err != nil {
				t.Fatal(err)
			}
			publication, err := retainedPublicationIdentity(operation)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(operation.PayloadJSON), &fields); err != nil {
				t.Fatal(err)
			}
			fields["publication_time"] = json.RawMessage(`"` + publication.Time.Add(time.Second).Format(time.RFC3339) + `"`)
			data, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.UpdateOperationPayload(ctx, operation.ID, string(data)); err != nil {
				t.Fatal(err)
			}
			// Payload promotion is allowed after apply, but a time mismatch in
			// either the staged or already-live Dist must stop further publication.
			for attempt := range 2 {
				if err := recoverDistOperations(ctx, root, "repo", store); !errors.Is(err, ErrIntegrity) {
					t.Fatalf("recovery %d accepted publication time drift: %v", attempt, err)
				}
				after, _, err := digestTree(ctx, distsRoot)
				if err != nil || after != before {
					t.Fatalf("recovery %d changed published Dists: %v", attempt, err)
				}
			}
			if err := store.UpdateOperationPayload(ctx, operation.ID, operation.PayloadJSON); err != nil {
				t.Fatal(err)
			}
			if err := recoverDistOperations(ctx, root, "repo", store); err != nil {
				t.Fatalf("recover after restoring publication time: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			assertPublicationMetadata(t, ctx, root)
		})
	}
}

func copyPublicationFixture(t *testing.T, source, target string) {
	t.Helper()
	hardlinks := map[[2]uint64]string{}
	err := filepath.WalkDir(source, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, name)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return errors.New("unexpected nonregular fixture file")
		}
		stat := info.Sys().(*syscall.Stat_t)
		identity := [2]uint64{uint64(stat.Dev), uint64(stat.Ino)}
		if prior := hardlinks[identity]; prior != "" {
			return os.Link(prior, destination)
		}
		hardlinks[identity] = destination
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, data, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPublicationTimeSIGKILLRecovery(t *testing.T) {
	cases := []struct{ kind, point string }{
		{"add", "add.staged"}, {"add", "add.applied"}, {"add", "build.rendered.el9"},
		{"add", "build.staged"}, {"add", "build.payload-targets"}, {"add", "build.pointer.el9"},
		{"add", "build.built"}, {"add", "build.finalized"},
		{"build", "build.command.staged"}, {"build", "build.command.applied"},
		{"rm", "rm.staged"}, {"rm", "rm.applied"},
	}
	for _, test := range cases {
		t.Run(test.kind+"/"+test.point, func(t *testing.T) {
			ctx, root, opts, paths := publicationFixture(t)
			if test.kind != "add" {
				if _, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9", "jammy"}, Paths: paths, Jobs: 1, Skip: test.kind == "build"}); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command(os.Args[0], "-test.run=^TestPublicationTimeCrashHelper$")
			command.Env = append(os.Environ(), "SOW_PUBLICATION_ROOT="+root, "SOW_PUBLICATION_KIND="+test.kind, "SOW_PUBLICATION_POINT="+test.point)
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("expected SIGKILL: %v %s", err, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("not SIGKILL: %v %s", err, output)
			}
			// Clone one actual interrupted journal, then recover the exact same
			// operation on either side of a wall-clock second. No key or journal
			// clock is rewritten to make the expected output.
			immediate := t.TempDir()
			copyPublicationFixture(t, root, immediate)
			expectedStore := publicationStore(t, immediate)
			if err := recoverDistOperations(ctx, immediate, "repo", expectedStore); err != nil {
				t.Fatal(err)
			}
			expected, err := scanPublicManifest(ctx, filepath.Join(immediate, "repo"))
			if err != nil {
				t.Fatal(err)
			}
			_ = expectedStore.Close()
			time.Sleep(1100 * time.Millisecond)
			store := publicationStore(t, root)
			operation, err := store.LastOperation(ctx)
			if err != nil || operation == nil {
				t.Fatalf("operation=%+v err=%v", operation, err)
			}
			publication, err := retainedPublicationIdentity(*operation)
			if err != nil || !publication.Current {
				t.Fatalf("missing durable time: %+v %v", publication, err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				if err := recoverDistOperations(ctx, root, "repo", store); err != nil {
					t.Fatalf("recovery %d: %v", attempt, err)
				}
				actual, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
				if err != nil || !sameGenerationManifest(expected, actual) {
					t.Fatalf("recovery %d changed bytes: %v", attempt, err)
				}
				detail, err := store.GetOperation(ctx, operation.ID)
				if err != nil {
					t.Fatal(err)
				}
				retained, err := retainedPublicationIdentity(detail.Operation)
				if err != nil || retained != publication {
					t.Fatalf("recovery selected a new time: %+v %+v %v", publication, retained, err)
				}
			}
			_ = store.Close()
			assertPublicationMetadata(t, ctx, root)
		})
	}
}

func TestPublicationTimeCrashHelper(t *testing.T) {
	root := os.Getenv("SOW_PUBLICATION_ROOT")
	if root == "" {
		return
	}
	ctx := context.Background()
	opts := WorkspaceOptions{Workdir: root, CWD: root}
	fault := func(point string) error {
		if point != os.Getenv("SOW_PUBLICATION_POINT") {
			return nil
		}
		process, err := os.FindProcess(os.Getpid())
		if err != nil {
			return err
		}
		if err := process.Kill(); err != nil {
			return err
		}
		select {}
	}
	var err error
	switch os.Getenv("SOW_PUBLICATION_KIND") {
	case "add":
		_, err = Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9", "jammy"}, Paths: []string{filepath.Join(root, "inputs", "test.rpm"), filepath.Join(root, "inputs", "test.deb")}, Jobs: 1, Fault: fault})
	case "build":
		_, err = Build(ctx, BuildOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1, Fault: fault})
	case "rm":
		_, err = Remove(ctx, RemoveOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9", "jammy"}, Packages: []string{"pgdg-redhat-nonfree-repo", "libpqtypes0"}, Jobs: 1, Fault: fault})
	}
	t.Fatalf("crash point was not reached: %v", err)
}

func TestPublicationTimeRetainedFloorAfterDistRemoval(t *testing.T) {
	ctx, root, opts, paths := publicationFixture(t)
	stopped := errors.New("stop before apply")
	result, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9"}, Paths: paths[:1], Jobs: 1, Fault: func(at string) error {
		if at == "add.staged" {
			return stopped
		}
		return nil
	}})
	if !errors.Is(err, stopped) {
		t.Fatal(err)
	}
	store := publicationStore(t, root)
	operation, payload, _, err := loadMutationJournal(ctx, store, root, "repo", result.Operation)
	if err != nil {
		t.Fatal(err)
	}
	// This fixture explicitly controls the persisted publication identity,
	// modeling an operation selected before a subsequent clock rollback.
	future := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	payload.PublicationTime = publicationTime(future.Format(time.RFC3339))
	data, _ := json.Marshal(payload)
	if err := store.UpdateOperationPayload(ctx, operation.ID, string(data)); err != nil {
		t.Fatal(err)
	}
	if err := recoverDistOperations(ctx, root, "repo", store); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if err := RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: opts, Repository: "repo", Name: "jammy"}); err != nil {
		t.Fatal(err)
	}
	store = publicationStore(t, root)
	cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	publication, err := selectMutationPublicationTime(ctx, root, "repo", cfg, store, []string{"el9"}, operation.CreatedAt.Add(-time.Hour))
	if err != nil || !publication.Time.Equal(future) {
		t.Fatalf("surviving Dist floor lost: %+v want=%s %v", publication, future, err)
	}
	_ = store.Close()
	assertPublicationMetadata(t, ctx, root)
}

func TestPublicationTimePreviewIsReadOnlyAndSemantic(t *testing.T) {
	ctx, root, opts, paths := publicationFixture(t)
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9", "jammy"}, Paths: paths, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	before, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	database, err := os.ReadFile(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	previewStarted := time.Now()
	preview, err := Remove(ctx, RemoveOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9", "jammy"}, Packages: []string{"libpqtypes0"}, Jobs: 1, Check: true})
	previewFinished := time.Now()
	if err != nil {
		t.Fatal(err)
	}
	after, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil || !sameGenerationManifest(before, after) {
		t.Fatalf("preview changed public files: %v", err)
	}
	afterDatabase, err := os.ReadFile(filepath.Join(root, ".sow", "repo.db"))
	if err != nil || !bytes.Equal(database, afterDatabase) {
		t.Fatalf("preview changed database: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	actual, err := Remove(ctx, RemoveOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9", "jammy"}, Packages: []string{"libpqtypes0"}, Jobs: 1})
	if err != nil || !sameRemovalChangeSemantics(preview.Changes, actual.Changes) || !reflect.DeepEqual(preview.Removed, actual.Removed) || !reflect.DeepEqual(preview.Dists, actual.Dists) || preview.Generation != actual.Generation || preview.Revision != actual.Revision || preview.Dirty != actual.Dirty {
		t.Fatalf("preview=%+v actual=%+v err=%v", preview, actual, err)
	}
	assertRemovalPreviewMetadata(t, root, preview, previewStarted, previewFinished, []byte(os.Getenv("SOW_PUBLICATION_KEY")))
	changed := false
	for index, file := range actual.Changes {
		if strings.HasSuffix(file.Path, "/Release") && file.SHA256 != preview.Changes[index].SHA256 {
			changed = true
		}
	}
	if !changed {
		t.Fatal("cross-second publication did not change Release bytes")
	}
}

func TestPublicationTimeAddPreparationKeepsCapturedOperationTime(t *testing.T) {
	ctx, root, opts, paths := publicationFixture(t)
	stopped := errors.New("stop staged")
	var preparedAt time.Time
	result, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9", "jammy"}, Paths: paths, Jobs: 1, Fault: func(point string) error {
		if point == "add.planned" {
			time.Sleep(1100 * time.Millisecond)
			preparedAt = time.Now().UTC().Truncate(time.Second)
		}
		if point == "add.staged" {
			return stopped
		}
		return nil
	}})
	if !errors.Is(err, stopped) {
		t.Fatal(err)
	}
	store := publicationStore(t, root)
	detail, err := store.GetOperation(ctx, result.Operation)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := retainedPublicationIdentity(detail.Operation)
	if err != nil || !publication.Time.Equal(detail.Operation.CreatedAt.UTC().Truncate(time.Second)) || !publication.Time.Before(preparedAt) {
		t.Fatalf("publication=%+v created=%s prepared=%s err=%v", publication, detail.Operation.CreatedAt, preparedAt, err)
	}
	if err := recoverDistOperations(ctx, root, "repo", store); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	assertPublicationMetadata(t, ctx, root)
}

func TestPublicationTimeKeyActivationAndFutureRejection(t *testing.T) {
	ctx, root, opts, _ := publicationFixture(t)
	created := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	packetConfig := &packet.Config{DefaultHash: crypto.SHA256, RSABits: 1024, Time: func() time.Time { return created }}
	entity, err := openpgp.NewEntity("future publication", "", "future@example.invalid", packetConfig)
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	armored, err := armor.Encode(&private, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivateWithoutSigning(armored, packetConfig); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_PUBLICATION_KEY", private.String())
	store := publicationStore(t, root)
	cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	publication, err := selectMutationPublicationTime(ctx, root, "repo", cfg, store, []string{"el9", "jammy"}, time.Now())
	if err != nil || !publication.Time.Equal(created) {
		t.Fatalf("key activation floor=%+v want=%s err=%v", publication, created, err)
	}
	before, err := store.LastOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	files, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(ctx, BuildOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1}); !errors.Is(err, ErrRejected) {
		t.Fatalf("future key accepted: %v", err)
	}
	store = publicationStore(t, root)
	after, err := store.LastOperation(ctx)
	if err != nil || before.ID != after.ID {
		t.Fatalf("future key began an operation: %+v %+v %v", before, after, err)
	}
	actual, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil || !sameGenerationManifest(files, actual) {
		t.Fatalf("future key changed public files: %v", err)
	}
}

// Parse the rendered wire files independently of the new production validator.
func assertPublicationFileTimes(t *testing.T, root string, dist state.Dist, want time.Time) {
	t.Helper()
	read := func(relative string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	assertTime := func(name string, at time.Time, err error) {
		t.Helper()
		if err != nil || !at.Equal(want) {
			t.Fatalf("%s time=%s want=%s err=%v", name, at, want, err)
		}
	}
	if dist.Format == "rpm" {
		for _, architecture := range dist.Architectures {
			prefix := filepath.Join(architecture.Family, "repodata")
			var repomd struct {
				Data []struct {
					Timestamp *int64 `xml:"timestamp"`
				} `xml:"data"`
			}
			if err := xml.Unmarshal(read(filepath.Join(prefix, "repomd.xml")), &repomd); err != nil || len(repomd.Data) != 3 {
				t.Fatalf("repomd=%+v err=%v", repomd, err)
			}
			for _, record := range repomd.Data {
				if record.Timestamp == nil || *record.Timestamp != want.Unix() {
					t.Fatalf("repomd timestamp=%v want=%d", record.Timestamp, want.Unix())
				}
			}
			if dist.MetadataSignerFingerprint != "" {
				at, err := yumrepo.DetachedSignatureCreationTime(bytes.NewReader(read(filepath.Join(prefix, "repomd.xml.asc"))))
				assertTime("repomd.xml.asc", at, err)
			}
		}
		return
	}
	at, err := parseReleaseDate(read("Release"))
	assertTime("Release", at, err)
	if dist.MetadataSignerFingerprint == "" {
		return
	}
	at, err = yumrepo.DetachedSignatureCreationTime(bytes.NewReader(read("Release.gpg")))
	assertTime("Release.gpg", at, err)
	block, rest := clearsign.Decode(read("InRelease"))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("invalid InRelease")
	}
	parsed, err := packet.NewReader(block.ArmoredSignature.Body).Next()
	signature, ok := parsed.(*packet.Signature)
	if err != nil || !ok {
		t.Fatalf("InRelease packet=%T err=%v", parsed, err)
	}
	assertTime("InRelease", signature.CreationTime, nil)
}
