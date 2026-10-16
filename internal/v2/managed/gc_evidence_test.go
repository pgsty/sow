package managed

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
)

func gcEvidenceRetainedFixture(t *testing.T, generations int) (localGCFixture, []RetainedGeneration) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	opts := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	repo := config.RepositoryConfig{Dists: map[string]config.DistConfig{"main": {Format: "rpm"}}}
	cfg.Repositories["repo"] = repo
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	input := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(t.TempDir(), "package.rpm"))
	added, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"main"}, Paths: []string{input}, Jobs: 1})
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	object, err := store.GetPackageObject(ctx, added.Items[0].SHA256)
	if err = errors.Join(err, store.Close()); err != nil {
		t.Fatal(err)
	}
	fixture := localGCFixture{root: root, options: opts, object: object, generation: added.Generation}
	retained := make([]RetainedGeneration, 0, generations)
	for i := 0; i < generations; i++ {
		if i > 0 {
			dist := repo.Dists["main"]
			dist.Exclude = []config.ExcludeRule{{Name: []string{fmt.Sprintf("__revision_%d__", i)}}}
			repo.Dists["main"] = dist
			cfg.Repositories["repo"] = repo
			writeManagedConfig(t, root, cfg)
			built, err := Build(ctx, BuildOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1})
			if err != nil {
				t.Fatal(err)
			}
			fixture.generation = built.Generation
		}
		ret, err := RetainAdd(ctx, RetainAddOptions{WorkspaceOptions: opts, Repository: "repo", Generation: fixture.generation})
		if err != nil {
			t.Fatal(err)
		}
		retained = append(retained, ret)
	}
	return fixture, retained
}

func TestGCAuthenticatedSnapshotRequiresFreshRead(t *testing.T) {
	root := t.TempDir()
	body := []byte("payload")
	path := filepath.Join(root, "payload")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	identity, err := authenticateRegularDescriptor(context.Background(), held, int64(len(body)), bytesSHA(body))
	if err != nil {
		t.Fatal(err)
	}
	ref := state.GenerationFile{Path: "payload", Phase: "payload", Size: int64(len(body)), SHA256: bytesSHA(body)}
	snapshot := &publicGenerationSnapshot{Manifest: []state.GenerationFile{ref}, Identities: map[string]rootedRegularIdentity{ref.Path: identity}}
	for _, fresh := range []bool{false, true} {
		if fresh {
			snapshot.AuthenticatedPayloads = map[string]rootedRegularIdentity{ref.Path: identity}
		}
		evidence, err := payloadEvidenceForAuthenticatedSnapshot(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		ctx, collector := workmetrics.Ensure(context.Background())
		if err := evidence.verifyPayloadReference(ctx, root, ref); err != nil {
			t.Fatal(err)
		}
		want := int64(1)
		if fresh {
			want = 0
		}
		if got := collector.Snapshot().FullPackageReads; got != want {
			t.Fatalf("fresh=%t reads=%d want=%d", fresh, got, want)
		}
	}
	// The producer's pre-read identity cannot be refreshed after a link change.
	if err := os.Link(path, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	evidence, err := payloadEvidenceForAuthenticatedSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	ctx, collector := workmetrics.Ensure(context.Background())
	if err := evidence.verifyPayloadReference(ctx, root, ref); err != nil || collector.Snapshot().FullPackageReads != 1 {
		t.Fatalf("old snapshot identity was rebound without hashing: %v, %#v", err, collector.Snapshot())
	}
}

func TestLocalGCDoesNotPromotePersistedFingerprint(t *testing.T) {
	fixture, _ := gcEvidenceRetainedFixture(t, 1)
	path := filepath.Join(fixture.root, "repo", fixture.object.PoolPath)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	identity, identityErr := snapshotRegularDescriptorIdentity(held)
	if err := errors.Join(identityErr, held.Close()); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(fixture.root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	err = store.UpdatePackageFingerprints(context.Background(), []state.PackageFact{{PackageSHA256: fixture.object.SHA256, Fingerprint: packageFingerprint(identity)}})
	if err = errors.Join(err, store.Close()); err != nil {
		t.Fatal(err)
	}
	ctx, collector := workmetrics.Ensure(context.Background())
	_, err = LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
	if !errors.Is(err, ErrIntegrity) || collector.Snapshot().StatHits != 1 || collector.Snapshot().FullPackageReads != 1 {
		t.Fatalf("persisted stat hit substituted for fresh content proof: %v, %#v", err, collector.Snapshot())
	}
}

func TestGCEvidencePhysicalIdentityAndOwnUnlink(t *testing.T) {
	root := t.TempDir()
	body := []byte("payload")
	a, b, c := filepath.Join(root, "a"), filepath.Join(root, "b"), filepath.Join(root, "c")
	if err := os.WriteFile(a, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c, body, 0o644); err != nil {
		t.Fatal(err)
	}
	evidence := newPayloadEvidenceRegistry()
	verify := func(name string, reads int64) {
		t.Helper()
		ctx, collector := workmetrics.Ensure(context.Background())
		ok, err := exactLocalGCFile(ctx, root, name, int64(len(body)), bytesSHA(body), evidence)
		if !ok || err != nil || collector.Snapshot().FullPackageReads != reads {
			t.Fatalf("%s authentication: ok=%t err=%v metrics=%#v", name, ok, err, collector.Snapshot())
		}
	}
	verify("a", 1)
	verify("b", 0)
	verify("c", 1) // Equal digest, different inode still needs all bytes.
	if err := removeRootedRegularExactWithEvidence(context.Background(), root, "b", int64(len(body)), bytesSHA(body), evidence); err != nil {
		t.Fatal(err)
	}
	verify("a", 1) // Our own unlink invalidated its full identity.
	if err := renameRootedRegularWithEvidence(context.Background(), root, "a", "tombstone", int64(len(body)), bytesSHA(body), 0o600, 0o700, evidence); err != nil {
		t.Fatal(err)
	}
	verify("tombstone", 1) // Linkat, Chmod and Unlink never mint a new proof.
	verify("tombstone", 0)
	wrong := state.GenerationFile{Path: "tombstone", Phase: "payload", Size: int64(len(body)), SHA256: strings.Repeat("f", 64)}
	if err := evidence.verifyPayloadReference(context.Background(), root, wrong); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("conflicting reference was accepted: %v", err)
	}
}

func TestGCEvidenceExactMutationGuards(t *testing.T) {
	for _, caller := range []string{"rename", "unlink"} {
		for _, change := range []string{"rewrite", "replacement", "cancel_wait", "cancel_before_mutation", "replacement_before_mutation"} {
			t.Run(caller+"/"+change, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, "payload")
				body := []byte("aaaaaaaa")
				if err := os.WriteFile(path, body, 0o644); err != nil {
					t.Fatal(err)
				}
				held, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer held.Close()
				before, err := snapshotRegularDescriptorIdentity(held)
				if err != nil {
					t.Fatal(err)
				}
				evidence := newPayloadEvidenceRegistry()
				if _, err := evidence.authenticateDescriptor(context.Background(), held, int64(len(body)), bytesSHA(body)); err != nil {
					t.Fatal(err)
				}
				base, cancel := context.WithCancel(context.Background())
				defer cancel()
				mutate := func() {
					if strings.HasPrefix(change, "cancel") {
						cancel()
						return
					}
					if strings.HasPrefix(change, "replacement") {
						if err := os.Rename(path, filepath.Join(root, "original")); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.WriteFile(path, []byte("bbbbbbbb"), 0o644); err != nil {
						t.Fatal(err)
					}
					if change == "rewrite" {
						restoreContentFixtureMTime(t, path, held, before)
					}
				}
				var ctx context.Context = &evidenceWaitContext{Context: base, onWait: mutate}
				if strings.HasSuffix(change, "before_mutation") {
					// The first Err poll accepts the cache hit; the second is
					// the namespace helper's final cancellation/identity guard.
					ctx = &contentBoundaryContext{Context: base, at: map[int]func(){2: mutate}}
				}
				if caller == "rename" {
					err = renameRootedRegularWithEvidence(ctx, root, "payload", "tombstone", int64(len(body)), bytesSHA(body), 0o600, 0o700, evidence)
				} else {
					err = removeRootedRegularExactWithEvidence(ctx, root, "payload", int64(len(body)), bytesSHA(body), evidence)
				}
				if err == nil || strings.HasPrefix(change, "cancel") && !errors.Is(err, context.Canceled) {
					t.Fatalf("unsafe mutation was accepted: %v", err)
				}
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("guarded source was removed: %v", err)
				}
				if _, err := os.Lstat(filepath.Join(root, "tombstone")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("guarded source was published: %v", err)
				}
			})
		}
	}
}

func TestRetainAddRechecksChangedPayloadAfterStaging(t *testing.T) {
	for _, change := range []string{"rewrite", "replacement", "missing", "hardlink"} {
		t.Run(change, func(t *testing.T) {
			fixture, _ := gcEvidenceRetainedFixture(t, 0)
			path := filepath.Join(fixture.root, "repo", fixture.object.PoolPath)
			held, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			before, err := snapshotRegularDescriptorIdentity(held)
			if err != nil {
				t.Fatal(err)
			}
			ctx, collector := workmetrics.Ensure(context.Background())
			_, err = RetainAdd(ctx, RetainAddOptions{WorkspaceOptions: fixture.options, Repository: "repo", Generation: fixture.generation, Fault: func(point string) error {
				if point != "retain.staged" {
					return nil
				}
				if change == "hardlink" {
					return os.Link(path, filepath.Join(fixture.root, "user-link"))
				}
				if change == "missing" {
					return os.Remove(path)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				data[len(data)-1] ^= 1
				if change == "replacement" {
					if err := os.Rename(path, filepath.Join(fixture.root, "original")); err != nil {
						return err
					}
				}
				if err := os.WriteFile(path, data, 0o644); err != nil {
					return err
				}
				if change == "rewrite" {
					restoreContentFixtureMTime(t, path, held, before)
				}
				return nil
			}})
			if change == "hardlink" {
				if err != nil || collector.Snapshot().FullPackageReads != 2 {
					t.Fatalf("changed link identity was not reauthenticated: %v, %#v", err, collector.Snapshot())
				}
			} else if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("changed retained payload accepted: %v", err)
			}
		})
	}
}

func TestLocalGCStillChecksEveryRetainedDirectory(t *testing.T) {
	fixture, retained := gcEvidenceRetainedFixture(t, 3)
	foreign := filepath.Join(retained[len(retained)-1].Path, "foreign")
	if err := os.WriteFile(foreign, []byte("unowned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LocalGC(context.Background(), LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("late retained directory was skipped: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fixture.root, "repo", fixture.object.PoolPath)); err != nil {
		t.Fatalf("retained failure changed payload set: %v", err)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	metadata, err := listRetainedMetadata(filepath.Join(retained[len(retained)-1].Path, "metadata"))
	if err != nil || len(metadata) == 0 {
		t.Fatalf("retained metadata fixture: %v, %v", metadata, err)
	}
	path := filepath.Join(retained[len(retained)-1].Path, "metadata", metadata[0])
	body, err := os.ReadFile(path)
	if err != nil || len(body) == 0 {
		t.Fatalf("metadata bytes: %v", err)
	}
	body[0] ^= 1
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LocalGC(context.Background(), LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("late retained metadata hash was skipped: %v", err)
	}
}

func TestLocalGCRecoveryAuthenticatesInNewProcess(t *testing.T) {
	for _, point := range []string{"gc.planned", "gc.detached", "gc.committed"} {
		t.Run(point, func(t *testing.T) {
			fixture := newLocalGCFixture(t, false)
			stop := errors.New("interrupt before recovery")
			_, err := LocalGC(context.Background(), LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo", Fault: func(got string) error {
				if got == point || point == "gc.detached" && strings.HasPrefix(got, point+".") {
					return stop
				}
				return nil
			}})
			if !errors.Is(err, stop) {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(filepath.Join(fixture.root, ".sow", "repo", "recovery"))
			if err != nil || len(entries) != 1 {
				t.Fatalf("recovery: %v %v", entries, err)
			}
			path := filepath.Join(fixture.root, "repo", fixture.object.PoolPath)
			if point != "gc.planned" {
				path = filepath.Join(fixture.root, ".sow", "repo", "recovery", entries[0].Name(), localGCPayloadDir, fixture.object.PoolPath)
			}
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := append([]byte(nil), original...)
			changed[len(changed)-1] ^= 1
			if err := os.WriteFile(path, changed, info.Mode()); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
			run := func(want string) {
				t.Helper()
				cmd := exec.Command(os.Args[0], "-test.run=^TestGCEvidenceRecoveryProcessHelper$")
				cmd.Env = append(os.Environ(), "SOW_GC_EVIDENCE_ROOT="+fixture.root, "SOW_GC_EVIDENCE_RESULT="+want)
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("child recovery: %v\n%s", err, output)
				}
				t.Logf("new-process recovery expected=%s exit=0 output=%s", want, output)
			}
			run("reject")
			if data, err := os.ReadFile(path); err != nil || bytesSHA(data) != bytesSHA(changed) {
				t.Fatalf("corrupt recovery payload was removed: %v", err)
			}
			if err := os.WriteFile(path, original, info.Mode()); err != nil {
				t.Fatal(err)
			}
			run("collect")
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("authenticated recovery did not collect payload: %v", err)
			}
		})
	}
}

func TestGCEvidenceRecoveryProcessHelper(t *testing.T) {
	root := os.Getenv("SOW_GC_EVIDENCE_ROOT")
	if root == "" {
		t.Skip("subprocess helper")
	}
	_, err := LocalGC(context.Background(), LocalGCOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
	if os.Getenv("SOW_GC_EVIDENCE_RESULT") == "reject" {
		if !errors.Is(err, ErrIntegrity) {
			t.Fatalf("new process accepted corrupt journal payload: %v", err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
}

func TestRetainAddReusesStablePayloadAuthentication(t *testing.T) {
	fixture, _ := gcEvidenceRetainedFixture(t, 0)
	ctx, collector := workmetrics.Ensure(context.Background())
	if _, err := RetainAdd(ctx, RetainAddOptions{WorkspaceOptions: fixture.options, Repository: "repo", Generation: fixture.generation}); err != nil {
		t.Fatal(err)
	}
	if got := collector.Snapshot(); got.FullPackageReads != 1 || got.PayloadBytesRead != fixture.object.Size {
		t.Fatalf("retaining one stable physical payload reread its bytes: %#v", got)
	}
}

func TestLocalGCReusesRetainedAuthenticationAcrossGenerations(t *testing.T) {
	for _, rehash := range []bool{false, true} {
		t.Run(fmt.Sprintf("current_rehash_%t", rehash), func(t *testing.T) {
			fixture, _ := gcEvidenceRetainedFixture(t, 3)
			if rehash {
				if err := os.Link(filepath.Join(fixture.root, "repo", fixture.object.PoolPath), filepath.Join(fixture.root, "user-link")); err != nil {
					t.Fatal(err)
				}
			}
			ctx, collector := workmetrics.Ensure(context.Background())
			result, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
			if err != nil || !result.Noop || result.Objects != 0 {
				t.Fatalf("GC changed retained set: %+v, %v", result, err)
			}
			if got := collector.Snapshot(); got.FullPackageReads != 1 || got.PayloadBytesRead != fixture.object.Size {
				t.Fatalf("shared retained payload authentication: %#v", got)
			}
		})
	}
}
