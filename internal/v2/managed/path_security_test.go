package managed

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
)

type descriptorEOFContext struct {
	context.Context
	file  *os.File
	size  int64
	onEOF func()
	fired bool
}

// Ignore SQL and traversal cancellation polls so the mutation happens after
// the small fixture's data read and immediately before that reader reaches EOF.
type treeReadEOFContext struct {
	context.Context
	reads int
	onEOF func()
}

func (ctx *treeReadEOFContext) Err() error {
	if pc, _, _, ok := runtime.Caller(1); ok {
		if caller := runtime.FuncForPC(pc); caller != nil && strings.HasSuffix(caller.Name(), "(*managedContextReader).Read") {
			ctx.reads++
			if ctx.reads == 2 {
				ctx.onEOF()
			}
		}
	}
	return ctx.Context.Err()
}

func TestPublicSnapshotsAuthenticateFileReads(t *testing.T) {
	for _, relative := range []string{"dists/noble/Release", "pool/p/pkg/pkg-1-1.x86_64.rpm"} {
		for _, scanner := range []string{"full", "fast", "evidence"} {
			for _, change := range []string{"stable", "rewrite", "hardlink"} {
				t.Run(publicFilePhase(relative)+"/"+scanner+"/"+change, func(t *testing.T) {
					base := t.TempDir()
					root := filepath.Join(base, "repo")
					path := filepath.Join(root, filepath.FromSlash(relative))
					if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
						t.Fatal(err)
					}
					body := []byte("original-data")
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
					store, err := state.Open(filepath.Join(base, "state.db"))
					if err != nil {
						t.Fatal(err)
					}
					defer store.Close()
					if publicFilePhase(relative) == "payload" {
						plain := context.Background()
						if err := store.AddDist(plain, state.Dist{Name: "el9", Format: "rpm", EffectiveConfigSHA256: "cfg", Architectures: []state.Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}}}); err != nil {
							t.Fatal(err)
						}
						operationID := strings.Repeat("8", 64)
						if err := store.BeginOperation(plain, state.Operation{ID: operationID, Kind: "add", State: state.OperationPlanned, PayloadJSON: `{}`}); err != nil {
							t.Fatal(err)
						}
						if err := store.SetOperationState(plain, operationID, state.OperationStaged, ""); err != nil {
							t.Fatal(err)
						}
						object := state.PackageObject{SHA256: bytesSHA(body), Format: "rpm", Coordinate: "pkg-0:1-1.x86_64", Architecture: "x86_64", CanonicalArch: "x86_64", PoolPath: relative, Filename: filepath.Base(relative), Size: int64(len(body)), Name: "pkg", Source: "pkg", Version: "1", Release: "1", Kind: "main", Storage: "pending"}
						if _, err := store.ApplyDesiredMutation(plain, operationID, []state.PackageObject{object}, map[string][]string{"el9": {object.SHA256}}, `{}`); err != nil {
							t.Fatal(err)
						}
					}
					fired := false
					ctx := &treeReadEOFContext{Context: context.Background(), onEOF: func() {
						fired = true
						switch change {
						case "rewrite":
							if err := os.WriteFile(path, []byte("replaced-data"), 0o644); err != nil {
								t.Fatal(err)
							}
						case "hardlink":
							if err := os.Link(path, filepath.Join(base, "export-alias")); err != nil {
								t.Fatal(err)
							}
						}
						if change != "stable" {
							restoreContentFixtureMTime(t, path, held, before)
						}
					}}
					want := state.GenerationFile{Path: relative, Phase: publicFilePhase(relative), Size: int64(len(body)), SHA256: bytesSHA(body)}
					var snapshot *publicGenerationSnapshot
					switch scanner {
					case "full":
						snapshot, err = scanPublicGenerationSnapshot(ctx, root)
					case "fast":
						snapshot, _, err = scanCurrentPublicGenerationFast(ctx, root, []state.GenerationFile{want}, store)
					case "evidence":
						snapshot, err = scanPublicGenerationSnapshotForLayoutWithEvidence(ctx, root, state.LayoutSinglePayloadV1, newPayloadEvidenceRegistry())
					}
					if !fired {
						t.Fatalf("EOF boundary was not reached: reads=%d err=%v", ctx.reads, err)
					}
					if change == "rewrite" {
						if !errors.Is(err, ErrIntegrity) || snapshot != nil {
							t.Fatalf("post-read rewrite accepted: snapshot=%+v err=%v", snapshot, err)
						}
						return
					}
					current, identityErr := snapshotRegularDescriptorIdentity(held)
					if err != nil || identityErr != nil || snapshot == nil || len(snapshot.Manifest) != 1 || snapshot.Manifest[0] != want || snapshot.Identities[relative] != current {
						t.Fatalf("stable file identity mismatch: snapshot=%+v current=%+v err=%v", snapshot, current, errors.Join(err, identityErr))
					}
					if want.Phase == "payload" && snapshot.AuthenticatedPayloads[relative] != current {
						t.Fatalf("payload evidence identity is stale: got=%+v want=%+v", snapshot.AuthenticatedPayloads[relative], current)
					}
				})
			}
		}
	}

}

func (ctx *descriptorEOFContext) Err() error {
	position, err := ctx.file.Seek(0, io.SeekCurrent)
	if err == nil && position == ctx.size && !ctx.fired {
		ctx.fired = true
		ctx.onEOF()
	}
	return ctx.Context.Err()
}

func TestDescriptorAuthenticationRejectsRewriteWithRestoredMTime(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "payload")
	body := bytes.Repeat([]byte("immutable-payload"), 4096)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	beforeIdentity, err := snapshotRegularDescriptorIdentity(file)
	if err != nil {
		t.Fatal(err)
	}
	// Change the bytes only after the hasher consumed the original payload,
	// just before its EOF read. The digest alone therefore still matches.
	ctx := &descriptorEOFContext{Context: context.Background(), file: file, size: int64(len(body))}
	ctx.onEOF = func() {
		changed := append([]byte(nil), body...)
		changed[len(changed)-1] ^= 1
		if err := os.WriteFile(path, changed, 0o600); err != nil {
			t.Fatal(err)
		}
		// Filesystems such as tmpfs can keep the same ctime within one clock
		// tick. Establish a changed ctime while retaining the original mtime;
		// this test checks that authentication uses that recorded change.
		deadline := time.Now().Add(time.Second)
		for {
			if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
				t.Fatal(err)
			}
			after, err := snapshotRegularDescriptorIdentity(file)
			if err != nil {
				t.Fatal(err)
			}
			if after.changeUnixNano != beforeIdentity.changeUnixNano {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("filesystem did not record a changed ctime within one second")
			}
			time.Sleep(time.Millisecond)
		}
	}
	if _, err := authenticateRegularDescriptor(ctx, file, int64(len(body)), bytesSHA(body)); err == nil || !ctx.fired {
		t.Fatalf("post-read rewrite accepted: mutation=%t err=%v", ctx.fired, err)
	}
}

// A second read-locked export --hardlink may link the same Pool inode while this
// process authenticates it. link(2) changes only ctime and the link count, so
// unchanged bytes must not be reported as an integrity failure.
func TestDescriptorAuthenticationToleratesConcurrentHardlink(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "payload")
	body := bytes.Repeat([]byte("immutable-payload"), 4096)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ctx := &descriptorEOFContext{Context: context.Background(), file: file, size: int64(len(body))}
	ctx.onEOF = func() {
		if err := os.Link(path, filepath.Join(root, "other-export-alias")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := authenticateRegularDescriptor(ctx, file, int64(len(body)), bytesSHA(body)); err != nil || !ctx.fired {
		t.Fatalf("unchanged bytes rejected after a concurrent hardlink: fired=%t err=%v", ctx.fired, err)
	}
}

type firstErrContext struct {
	context.Context
	onFirst func()
	fired   bool
}

func (ctx *firstErrContext) Err() error {
	if !ctx.fired {
		ctx.fired = true
		ctx.onFirst()
	}
	return ctx.Context.Err()
}

func TestLinkRootedRegularToleratesConcurrentHardlinkExport(t *testing.T) {
	source, targetA, targetB := t.TempDir(), t.TempDir(), t.TempDir()
	body := bytes.Repeat([]byte("pool-payload"), 1<<16)
	if err := os.MkdirAll(filepath.Join(source, "pool/p"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "pool/p/pkg.rpm"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	// The first ctx poll happens inside authentication, after its "before" snapshot.
	ctx := &firstErrContext{Context: context.Background()}
	ctx.onFirst = func() {
		if err := os.MkdirAll(filepath.Join(targetB, "pool/p"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(source, "pool/p/pkg.rpm"), filepath.Join(targetB, "pool/p/pkg.rpm")); err != nil {
			t.Fatal(err)
		}
	}
	if err := linkRootedRegular(ctx, source, "pool/p/pkg.rpm", targetA, "pool/p/pkg.rpm", int64(len(body)), bytesSHA(body), 0o755); err != nil || !ctx.fired {
		t.Fatalf("hardlink export rejected unchanged Pool bytes: fired=%t err=%v", ctx.fired, err)
	}
}

func TestPendingInstallRejectsWrongDigestBeforePublishingName(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, ".sow/repo/stage/op/objects/source")
	if err := os.MkdirAll(filepath.Dir(staged), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".sow/repo/pending"), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte("actual")
	if err := os.WriteFile(staged, body, 0o600); err != nil {
		t.Fatal(err)
	}
	object := state.PackageObject{SHA256: bytesSHA([]byte("wanted")), Size: int64(len(body))}
	if err := installPendingObject(context.Background(), root, "repo", staged, object); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong staged content: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow/repo/pending", object.SHA256)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected bytes acquired pending name: %v", err)
	}
	got, err := os.ReadFile(staged)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("rejected source changed: bytes=%q err=%v", got, err)
	}
}

func TestRenameRootedRegularReplaysExactDualLink(t *testing.T) {
	root := t.TempDir()
	source, target := filepath.Join(root, "source"), filepath.Join(root, "target")
	body := []byte("durable immutable object")
	if err := os.WriteFile(source, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(source, target); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := renameRootedRegular(context.Background(), root, "source", "target", int64(len(body)), bytesSHA(body), 0o644, 0o700); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(target)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0o644 {
		t.Fatalf("replay lost exact inode or final mode: %v", err)
	}
	if _, err := os.Stat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source not removed after target committed: %v", err)
	}
}

func TestRootedRegularDetectsParentSwapAfterOpen(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "safe"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "safe", "value"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "value"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := openRootedRegular(root, "safe/value")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "safe"), filepath.Join(root, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "safe")); err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(opened.file)
	verifyErr := opened.CloseVerified()
	if readErr != nil || string(data) != "inside" {
		t.Fatalf("descriptor was redirected: data=%q err=%v", data, readErr)
	}
	if verifyErr == nil {
		t.Fatal("parent replacement was not detected")
	}
}

func TestRootedRegularDetectsOwnerRootReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "owner")
	original := filepath.Join(parent, "original")
	if err := os.MkdirAll(filepath.Join(root, "safe"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "safe", "value"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := openRootedRegular(root, "safe/value")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, original); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "safe"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "safe", "value"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(opened.file)
	verifyErr := opened.CloseVerified()
	if readErr != nil || string(data) != "inside" {
		t.Fatalf("descriptor was redirected: data=%q err=%v", data, readErr)
	}
	if verifyErr == nil {
		t.Fatal("owner root replacement was not detected")
	}
}

func TestWalkRootedTreeRejectsDirectoryMutationDuringVisit(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "safe"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "safe", "value"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "value"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	mutated := false
	err := walkRootedTree(context.Background(), root, func(relative string, file *os.File, _ os.FileInfo) error {
		if relative != "safe/value" || mutated {
			return nil
		}
		mutated = true
		if err := os.Rename(filepath.Join(root, "safe"), filepath.Join(root, "original")); err != nil {
			return err
		}
		return os.Symlink(outside, filepath.Join(root, "safe"))
	}, nil)
	if !mutated || err == nil {
		t.Fatalf("tree mutation accepted: mutated=%t err=%v", mutated, err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected cancellation: %v", err)
	}
}

func TestWalkRootedDirectoriesRejectChildReplacementWithRestoredParentMTime(t *testing.T) {
	for _, input := range []bool{false, true} {
		for _, symlink := range []bool{false, true} {
			name := map[bool]string{false: "tree", true: "input"}[input] + "/" + map[bool]string{false: "directory", true: "symlink"}[symlink]
			t.Run(name, func(t *testing.T) {
				base := t.TempDir()
				root := filepath.Join(base, "root")
				child := filepath.Join(root, "safe")
				outside := filepath.Join(base, "outside")
				for _, directory := range []string{child, outside} {
					if err := os.MkdirAll(directory, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(directory, "value"), []byte("contents"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				before, err := os.Stat(root)
				if err != nil {
					t.Fatal(err)
				}
				mutated := false
				visit := func(relative string, _ *os.File, _ os.FileInfo) error {
					if relative != "safe/value" || mutated {
						return nil
					}
					mutated = true
					if err := os.Rename(child, filepath.Join(base, "original")); err != nil {
						return err
					}
					if symlink {
						if err := os.Symlink(outside, child); err != nil {
							return err
						}
					} else if err := os.Rename(outside, child); err != nil {
						return err
					}
					if err := os.Chtimes(root, before.ModTime(), before.ModTime()); err != nil {
						return err
					}
					after, err := os.Stat(root)
					if err != nil {
						return err
					}
					if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !os.SameFile(before, after) {
						t.Fatal("fixture must preserve the parent identity, size and mtime")
					}
					return nil
				}
				if input {
					err = walkRootedInputFiles(context.Background(), root, visit)
				} else {
					err = walkRootedTree(context.Background(), root, visit, nil)
				}
				if !mutated || err == nil {
					t.Fatalf("child replacement with unchanged parent metadata accepted: mutated=%t err=%v", mutated, err)
				}
			})
		}
	}
}

func TestWalkRootedTreeRejectsOwnerRootReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "owner")
	original := filepath.Join(parent, "original")
	if err := os.MkdirAll(filepath.Join(root, "safe"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "safe", "value"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	mutated := false
	err := walkRootedTree(context.Background(), root, func(relative string, _ *os.File, _ os.FileInfo) error {
		if relative != "safe/value" || mutated {
			return nil
		}
		mutated = true
		if err := os.Rename(root, original); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Join(root, "safe"), 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(root, "safe", "value"), []byte("replacement"), 0o600)
	}, nil)
	if !mutated || err == nil {
		t.Fatalf("owner root replacement accepted: mutated=%t err=%v", mutated, err)
	}
}

func TestRenameRootedRegularPublishesExactInode(t *testing.T) {
	root := t.TempDir()
	sourceRelative := filepath.Join(".sow", "repo", "pending", "object")
	targetRelative := filepath.Join("repo", "pool", "o", "object")
	source := filepath.Join(root, sourceRelative)
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := renameRootedRegular(context.Background(), root, sourceRelative, targetRelative, before.Size(), bytesSHA([]byte("payload")), 0o644, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source remains after rooted rename: %v", err)
	}
	after, err := os.Lstat(filepath.Join(root, targetRelative))
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0o644 {
		t.Fatalf("target=%#v same=%t err=%v", after, err == nil && os.SameFile(before, after), err)
	}
	for path := filepath.Dir(filepath.Join(root, targetRelative)); path != filepath.Join(root, "repo"); path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("public directory %s: %v", path, err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Fatalf("public directory %s mode=%v", path, info.Mode().Perm())
		}
	}
}

func TestRenameRootedRegularRejectsSymlinkedParentWithoutEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	sourceRelative := filepath.Join(".sow", "repo", "pending", "object")
	source := filepath.Join(root, sourceRelative)
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "repo", "pool")); err != nil {
		t.Fatal(err)
	}
	err := renameRootedRegular(context.Background(), root, sourceRelative, filepath.Join("repo", "pool", "o", "object"), int64(len("payload")), bytesSHA([]byte("payload")), 0o644, 0o755)
	if err == nil {
		t.Fatal("rooted rename followed a symlinked target parent")
	}
	if data, readErr := os.ReadFile(source); readErr != nil || string(data) != "payload" {
		t.Fatalf("source changed: data=%q err=%v", data, readErr)
	}
	if _, statErr := os.Lstat(filepath.Join(outside, "o", "object")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("rooted rename escaped owner: %v", statErr)
	}
}

func TestDurableRenameRejectsOwnerReplacementBetweenParentBindings(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "owner")
	original := filepath.Join(parent, "original")
	source := filepath.Join(root, "stage", "object")
	target := filepath.Join(root, "pool", "object")
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := durableRenameWithHook(root, source, target, func() error {
		if err := os.Rename(root, original); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Join(root, "stage"), 0o700); err != nil {
			return err
		}
		return os.MkdirAll(filepath.Join(root, "pool"), 0o755)
	})
	if err == nil {
		t.Fatal("durable rename accepted a replaced owner root")
	}
	if data, readErr := os.ReadFile(filepath.Join(original, "stage", "object")); readErr != nil || string(data) != "payload" {
		t.Fatalf("original source changed: data=%q err=%v", data, readErr)
	}
	for _, path := range []string{filepath.Join(original, "pool", "object"), filepath.Join(root, "pool", "object")} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("rename published into %s: %v", path, statErr)
		}
	}
}

func TestRootedDirectoryExchangeRejectsAncestorSymlinkRaceWithoutEscape(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "owner")
	originalRepo := filepath.Join(parent, "repo-original")
	outside := filepath.Join(parent, "outside")
	left := filepath.Join(root, "repo", "dists", "el9", "x86_64", "repodata")
	right := filepath.Join(root, ".sow", "repo", "stage", "c2-to-single-v1", "dists", "el9", "x86_64", "repodata")
	for _, directory := range []string{left, right, filepath.Join(outside, "dists", "el9", "x86_64", "repodata")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(left, "marker"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(right, "marker"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideMarker := filepath.Join(outside, "dists", "el9", "x86_64", "repodata", "marker")
	if err := os.WriteFile(outsideMarker, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := exchangeRootedDirectoriesWithHook(root,
		filepath.Join("repo", "dists", "el9", "x86_64", "repodata"),
		filepath.Join(".sow", "repo", "stage", "c2-to-single-v1", "dists", "el9", "x86_64", "repodata"),
		func() error {
			if err := os.Rename(filepath.Join(root, "repo"), originalRepo); err != nil {
				return err
			}
			return os.Symlink(outside, filepath.Join(root, "repo"))
		})
	if err == nil {
		t.Fatal("rooted directory exchange accepted an ancestor symlink race")
	}
	for path, want := range map[string]string{
		filepath.Join(originalRepo, "dists", "el9", "x86_64", "repodata", "marker"): "old",
		filepath.Join(right, "marker"): "new",
		outsideMarker:                  "outside",
	} {
		data, readErr := os.ReadFile(path)
		if readErr != nil || string(data) != want {
			t.Fatalf("marker %s=%q want=%q err=%v", path, data, want, readErr)
		}
	}
}

func TestReadBoundedRegularNoFollowRejectsSymlinkedAncestor(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if data, err := readBoundedRegularNoFollow(filepath.Join(root, "linked", "secret"), 64); err == nil || data != nil {
		t.Fatalf("symlinked ancestor accepted: data=%q err=%v", data, err)
	}
}

func TestReadBoundedRegularNoFollowDetectsParentReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "keys")
	original := filepath.Join(parent, "original")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(root, "secret")
	if err := os.WriteFile(filename, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readBoundedRegularNoFollowWithHook(filename, 64, func() error {
		if err := os.Rename(root, original); err != nil {
			return err
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filename, []byte("replacement"), 0o600)
	})
	if err == nil || data != nil {
		t.Fatalf("parent replacement accepted: data=%q err=%v", data, err)
	}
}

func TestRootedCreatedRegularCommitAndAbortBindExactEntry(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "files"), 0o700); err != nil {
		t.Fatal(err)
	}
	committed, err := createRootedRegular(root, "files/committed", 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := committed.file.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := committed.Commit(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "files", "committed")); err != nil || string(data) != "payload" {
		t.Fatalf("committed data=%q err=%v", data, err)
	}

	aborted, err := createRootedRegular(root, "files/aborted", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := aborted.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "files", "aborted")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("aborted entry remains: %v", err)
	}
}

func TestRootedCreatedRegularRejectsEntryReplacementWithoutDeletingIt(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "files"), 0o700); err != nil {
		t.Fatal(err)
	}
	created, err := createRootedRegular(root, "files/value", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := created.file.Write([]byte("original")); err != nil {
		t.Fatal(err)
	}
	value := filepath.Join(root, "files", "value")
	displaced := filepath.Join(root, "files", "displaced")
	if err := os.Rename(value, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(value, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := created.Commit(); err == nil {
		t.Fatal("created file accepted a replaced directory entry")
	}
	if data, err := os.ReadFile(value); err != nil || string(data) != "replacement" {
		t.Fatalf("replacement was changed: data=%q err=%v", data, err)
	}
	if data, err := os.ReadFile(displaced); err != nil || string(data) != "original" {
		t.Fatalf("displaced original was changed: data=%q err=%v", data, err)
	}
}

func TestLinkRootedRegularRejectsExistingDifferentInode(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "source"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "target"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"source/object", "target/object"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("same bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := linkRootedRegular(context.Background(), root, "source/object", root, "target/object", int64(len("same bytes")), bytesSHA([]byte("same bytes")), 0o700)
	if err == nil || !errors.Is(err, ErrIntegrity) {
		t.Fatalf("existing different inode accepted: %v", err)
	}
	source, err := os.Lstat(filepath.Join(root, "source", "object"))
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Lstat(filepath.Join(root, "target", "object"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(source, target) {
		t.Fatal("preexisting target was replaced")
	}
}

func TestDurableMkdirRejectsEntryReplacementBeforeReturn(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "created")
	displaced := filepath.Join(parent, "displaced")
	err := durableMkdirWithHook(path, 0o750, func() error {
		if err := os.Rename(path, displaced); err != nil {
			return err
		}
		return os.Mkdir(path, 0o750)
	})
	if err == nil {
		t.Fatal("durable mkdir accepted a replaced entry")
	}
	for _, name := range []string{path, displaced} {
		if info, statErr := os.Lstat(name); statErr != nil || !info.IsDir() {
			t.Fatalf("directory %s changed: info=%#v err=%v", name, info, statErr)
		}
	}
}

func TestDurableEnsureRegularFileRejectsEntryReplacementBeforeReturn(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "lock")
	displaced := filepath.Join(parent, "displaced")
	created, err := durableEnsureRegularFileWithHook(path, 0o600, func() error {
		if err := os.Rename(path, displaced); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("replacement"), 0o600)
	})
	if !created || err == nil {
		t.Fatalf("regular file replacement accepted: created=%t err=%v", created, err)
	}
	if data, readErr := os.ReadFile(path); readErr != nil || string(data) != "replacement" {
		t.Fatalf("replacement was changed: data=%q err=%v", data, readErr)
	}
	if info, statErr := os.Lstat(displaced); statErr != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		t.Fatalf("displaced original changed: info=%#v err=%v", info, statErr)
	}
}

func TestRemoveOwnedDirectoryUnlinksSymlinkWithoutFollowingIt(t *testing.T) {
	root := t.TempDir()
	owned := filepath.Join(root, "owned")
	outside := t.TempDir()
	if err := os.Mkdir(owned, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "sentinel"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(owned, "link")); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedDirectory(owned, root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(owned); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned directory remains: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(outside, "sentinel")); err != nil || string(data) != "outside" {
		t.Fatalf("outside sentinel changed: data=%q err=%v", data, err)
	}
}

func TestManagedSurfacesRejectHardlinkedControlFiles(t *testing.T) {
	t.Run("config", func(t *testing.T) {
		root := t.TempDir()
		writeManagedConfig(t, root, config.Default())
		if err := os.Link(filepath.Join(root, config.ConfigFilename), filepath.Join(root, "config-hardlink")); err != nil {
			t.Fatal(err)
		}
		if _, err := CheckConfig(context.Background(), WorkspaceOptions{Workdir: root, CWD: root}); err == nil {
			t.Fatal("config check accepted a multiply linked sow.yml")
		}
	})

	t.Run("workspace lock", func(t *testing.T) {
		ctx := context.Background()
		root := t.TempDir()
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(root, ".sow", "workspace.lock"), filepath.Join(root, "workspace-lock-hardlink")); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("Repository lifecycle accepted a multiply linked Workspace lock: %v", err)
		}
	})

	t.Run("repository lock", func(t *testing.T) {
		ctx := context.Background()
		root := t.TempDir()
		options := WorkspaceOptions{Workdir: root, CWD: root}
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
		writeManagedConfig(t, root, cfg)
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(root, ".sow", "repo-locks", "repo.lock"), filepath.Join(root, "repository-lock-hardlink")); err != nil {
			t.Fatal(err)
		}
		if _, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("Repository writer accepted a multiply linked Repository lock: %v", err)
		}
	})

	t.Run("database", func(t *testing.T) {
		ctx := context.Background()
		root := t.TempDir()
		options := WorkspaceOptions{Workdir: root, CWD: root}
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
		writeManagedConfig(t, root, cfg)
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(root, ".sow", "repo.db"), filepath.Join(root, "database-hardlink")); err != nil {
			t.Fatal(err)
		}
		if _, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("Status accepted a multiply linked Repository database: %v", err)
		}
	})
}

func TestBuildRejectsHardlinkedPrivatePendingObjectWithoutPublicEffect(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	added, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1})
	if err != nil || len(added.Items) != 1 || added.Items[0].SHA256 == "" {
		t.Fatalf("Add=%#v err=%v", added, err)
	}
	before, _, err := digestTree(ctx, filepath.Join(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(root, ".sow", "repo", "pending", added.Items[0].SHA256)
	alias := filepath.Join(root, "pending-hardlink")
	if err := os.Link(pending, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Build accepted a multiply linked private pending object: %v", err)
	}
	after, _, err := digestTree(ctx, filepath.Join(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("failed hardlink build changed public Repository: before=%s after=%s", before, after)
	}
	if pendingInfo, err := os.Lstat(pending); err != nil || pendingInfo.Mode().Perm() != 0o644 {
		t.Fatalf("pending object changed: info=%#v err=%v", pendingInfo, err)
	}
	if aliasInfo, err := os.Lstat(alias); err != nil || aliasInfo.Mode().Perm() != 0o644 {
		t.Fatalf("external hardlink changed: info=%#v err=%v", aliasInfo, err)
	}
}

func TestWalkRootedFilesRejectReplacementWithRestoredParentMTime(t *testing.T) {
	for _, input := range []bool{false, true} {
		for _, symlink := range []bool{false, true} {
			name := map[bool]string{false: "tree", true: "input"}[input] + "/" + map[bool]string{false: "regular", true: "symlink"}[symlink]
			t.Run(name, func(t *testing.T) {
				base := t.TempDir()
				root := filepath.Join(base, "root")
				if err := os.Mkdir(root, 0o700); err != nil {
					t.Fatal(err)
				}
				entry := filepath.Join(root, "value")
				replacement := filepath.Join(base, "replacement")
				if err := os.WriteFile(entry, []byte("original-data"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(replacement, []byte("replaced-data"), 0o600); err != nil {
					t.Fatal(err)
				}
				parentBefore, err := os.Stat(root)
				if err != nil {
					t.Fatal(err)
				}
				original, err := os.Stat(entry)
				if err != nil {
					t.Fatal(err)
				}
				visited := false
				visit := func(relative string, file *os.File, info os.FileInfo) error {
					if relative != "value" {
						t.Fatalf("unexpected visit %q", relative)
					}
					if err := os.Rename(entry, filepath.Join(base, "held-original")); err != nil {
						return err
					}
					if symlink {
						if err := os.Symlink(replacement, entry); err != nil {
							return err
						}
					} else if err := os.Rename(replacement, entry); err != nil {
						return err
					}
					if err := os.Chtimes(root, parentBefore.ModTime(), parentBefore.ModTime()); err != nil {
						return err
					}
					parentAfter, err := os.Stat(root)
					if err != nil {
						return err
					}
					if !os.SameFile(parentBefore, parentAfter) || parentAfter.Size() != parentBefore.Size() || !parentAfter.ModTime().Equal(parentBefore.ModTime()) {
						t.Fatal("fixture failed to preserve parent identity, size and mtime")
					}
					after, err := file.Stat()
					if err != nil {
						return err
					}
					if !os.SameFile(info, after) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
						t.Fatal("fixture unexpectedly modified held file")
					}
					body, err := io.ReadAll(file)
					if err != nil {
						return err
					}
					if string(body) != "original-data" {
						t.Fatalf("descriptor read = %q", body)
					}
					visited = true
					return nil
				}
				if input {
					err = walkRootedInputFiles(context.Background(), root, visit)
				} else {
					err = walkRootedTree(context.Background(), root, visit, nil)
				}
				replacementInfo, statErr := os.Lstat(entry)
				if statErr != nil {
					t.Fatal(statErr)
				}
				current, readErr := os.ReadFile(entry)
				if readErr != nil {
					t.Fatal(readErr)
				}
				t.Logf("visited=%t path_binding_changed=%t current_path_body=%q traversal_error=%v", visited, !os.SameFile(original, replacementInfo), current, err)
				if !visited || os.SameFile(original, replacementInfo) {
					t.Fatal("fixture did not replace the visited entry")
				}
				if err == nil {
					t.Fatal("regular-file replacement accepted after callback with restored parent mtime")
				}
			})
		}
	}
}

type digestFirstEOFContext struct {
	context.Context
	calls      int
	onFirstEOF func()
}

func (ctx *digestFirstEOFContext) Err() error {
	ctx.calls++
	// One walker cancellation check, one pre-read check, then pre-EOF check.
	if ctx.calls == 3 {
		ctx.onFirstEOF()
	}
	return ctx.Context.Err()
}

func TestDigestTreeRejectsFileReplacementAfterRead(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(root, "value")
	replacement := filepath.Join(base, "replacement")
	if err := os.WriteFile(entry, []byte("original-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("replaced-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalDigest, _, err := digestTree(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	parentBefore, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	fired := false
	ctx := &digestFirstEOFContext{Context: context.Background()}
	ctx.onFirstEOF = func() {
		fired = true
		if err := os.Rename(entry, filepath.Join(base, "held-original")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, entry); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(root, parentBefore.ModTime(), parentBefore.ModTime()); err != nil {
			t.Fatal(err)
		}
		parentAfter, err := os.Stat(root)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(parentBefore, parentAfter) || parentAfter.Size() != parentBefore.Size() || !parentAfter.ModTime().Equal(parentBefore.ModTime()) {
			t.Fatal("fixture failed to preserve parent identity, size and mtime")
		}
	}
	acceptedDigest, count, err := digestTree(ctx, root)
	currentDigest, _, currentErr := digestTree(context.Background(), root)
	if currentErr != nil {
		t.Fatal(currentErr)
	}
	t.Logf("fired=%t ctx_checks=%d files=%d accepted_digest=%s original_digest=%s current_digest=%s err=%v", fired, ctx.calls, count, acceptedDigest, originalDigest, currentDigest, err)
	if !fired {
		t.Fatal("post-read hook did not execute")
	}
	if originalDigest == currentDigest {
		t.Fatal("fixture failed to change the tree digest")
	}
	if err == nil && acceptedDigest == originalDigest && acceptedDigest != currentDigest {
		t.Fatal("digestTree authenticated original bytes for a path now containing different regular-file bytes")
	}
	if err == nil {
		t.Fatalf("unexpected success: accepted=%s current=%s", acceptedDigest, currentDigest)
	}
	if acceptedDigest != "" || count != 0 {
		t.Fatalf("rejected tree returned digest=%q files=%d", acceptedDigest, count)
	}
}

func TestDigestTreeAuthenticatesFileRead(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		rewrite, chmod, link bool
		wantErr              bool
	}{
		{name: "unchanged"},
		{name: "rewrite_restored_mtime", rewrite: true, wantErr: true},
		{name: "concurrent_hardlink", link: true},
		{name: "mode_change", chmod: true, wantErr: true},
		{name: "mode_change_and_hardlink", chmod: true, link: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "root")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			entry := filepath.Join(root, "value")
			body := []byte("original-data")
			if err := os.WriteFile(entry, body, 0o600); err != nil {
				t.Fatal(err)
			}
			held, err := os.Open(entry)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			before, err := snapshotRegularDescriptorIdentity(held)
			if err != nil {
				t.Fatal(err)
			}
			originalDigest := bytesSHA([]byte(bytesSHA(body) + "  value\n"))
			fired := false
			ctx := &digestFirstEOFContext{Context: context.Background()}
			ctx.onFirstEOF = func() {
				if tc.rewrite {
					if err := os.WriteFile(entry, []byte("replaced-data"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if tc.chmod {
					if err := os.Chmod(entry, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				if tc.link {
					// Keep the new name outside the tree being digested.
					if err := os.Link(entry, filepath.Join(base, "export-alias")); err != nil {
						t.Fatal(err)
					}
				}
				after := before
				if tc.rewrite || tc.chmod || tc.link {
					// A coarse filesystem clock can retain ctime within one tick.
					// Establish a recorded ctime change, with the original mtime,
					// before checking that the digest uses this evidence.
					deadline := time.Now().Add(time.Second)
					for {
						mtime := time.Unix(0, before.modUnixNano)
						if err := os.Chtimes(entry, mtime, mtime); err != nil {
							t.Fatal(err)
						}
						after, err = snapshotRegularDescriptorIdentity(held)
						if err != nil {
							t.Fatal(err)
						}
						if after.changeUnixNano != before.changeUnixNano {
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("filesystem did not record a changed ctime within one second")
						}
						time.Sleep(time.Millisecond)
					}
				}
				if !before.sameInode(after) || before.size != after.size || before.modUnixNano != after.modUnixNano {
					t.Fatal("fixture failed to preserve inode, size and mtime")
				}
				wantMode, wantLinks := before.mode, before.links
				if tc.chmod {
					wantMode = 0o644
				}
				if tc.link {
					wantLinks++
				}
				if after.mode != wantMode || after.links != wantLinks {
					t.Fatalf("fixture mode=%v links=%d; want mode=%v links=%d", after.mode, after.links, wantMode, wantLinks)
				}
				t.Logf("same inode/size/mtime, ctime=%d->%d mode=%v->%v links=%d->%d", before.changeUnixNano, after.changeUnixNano, before.mode, after.mode, before.links, after.links)
				fired = true
			}
			accepted, count, err := digestTree(ctx, root)
			current, currentCount, currentErr := digestTree(context.Background(), root)
			if currentErr != nil || currentCount != 1 {
				t.Fatalf("fresh digest=%q files=%d err=%v", current, currentCount, currentErr)
			}
			t.Logf("hook=%t polls=%d accepted=%q original=%s current=%s files=%d err=%v", fired, ctx.calls, accepted, originalDigest, current, count, err)
			if !fired {
				t.Fatal("post-read hook did not execute")
			}
			if (current != originalDigest) != tc.rewrite {
				t.Fatal("fixture content change did not match the requested mutation")
			}
			if tc.wantErr {
				if !errors.Is(err, ErrIntegrity) || accepted != "" || count != 0 {
					t.Fatalf("changed file returned digest=%q files=%d err=%v", accepted, count, err)
				}
			} else if err != nil || accepted != originalDigest || count != 1 {
				t.Fatalf("unchanged content returned digest=%q files=%d err=%v", accepted, count, err)
			}
		})
	}
}

func TestDigestTreeCancellationAfterRead(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "value"), []byte("original-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &digestFirstEOFContext{Context: base, onFirstEOF: cancel}
	digest, count, err := digestTree(ctx, root)
	if !errors.Is(err, context.Canceled) || digest != "" || count != 0 {
		t.Fatalf("canceled digest=%q files=%d err=%v", digest, count, err)
	}
}

// contentBoundaryContext mutates real files between a read's last data chunk
// and EOF. These fixtures are smaller than the read buffer, so each full pass
// has exactly two polls; digestTree also polls once before visiting the file.
type contentBoundaryContext struct {
	context.Context
	calls int
	at    map[int]func()
}

func (ctx *contentBoundaryContext) Err() error {
	ctx.calls++
	if f := ctx.at[ctx.calls]; f != nil {
		f()
	}
	return ctx.Context.Err()
}

func restoreContentFixtureMTime(t *testing.T, path string, held *os.File, before rootedRegularIdentity) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		mtime := time.Unix(0, before.modUnixNano)
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		after, err := snapshotRegularDescriptorIdentity(held)
		if err != nil {
			t.Fatal(err)
		}
		if after.changeUnixNano != before.changeUnixNano {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("filesystem did not advance ctime")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestContentAuthenticationLinkChanges(t *testing.T) {
	for _, caller := range []string{"tree", "descriptor", "hash", "export", "reference", "walked"} {
		for _, change := range []string{"stable", "link", "unlink", "ctime_only", "rewrite_link", "rewrite_unlink", "mode_link", "repeated_link", "cancel_retry"} {
			t.Run(caller+"/"+change, func(t *testing.T) {
				base := t.TempDir()
				root := filepath.Join(base, "root")
				if err := os.Mkdir(root, 0o755); err != nil {
					t.Fatal(err)
				}
				path, alias := filepath.Join(root, "payload"), filepath.Join(base, "alias")
				body := []byte("aaaaaaaa")
				if err := os.WriteFile(path, body, 0o644); err != nil {
					t.Fatal(err)
				}
				if change == "unlink" || change == "rewrite_unlink" {
					if err := os.Link(path, alias); err != nil {
						t.Fatal(err)
					}
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
				baseCtx, cancel := context.WithCancel(context.Background())
				defer cancel()
				poll := 2
				if caller == "tree" {
					poll++
				}
				ctx := &contentBoundaryContext{Context: baseCtx, at: make(map[int]func())}
				fired := false
				ctx.at[poll] = func() {
					fired = true
					if change == "stable" {
						return
					}
					if change == "rewrite_link" || change == "rewrite_unlink" {
						if err := os.WriteFile(path, []byte("bbbbbbbb"), 0o644); err != nil {
							t.Fatal(err)
						}
					}
					if change == "mode_link" {
						if err := os.Chmod(path, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					if change == "unlink" || change == "rewrite_unlink" {
						if err := os.Remove(alias); err != nil {
							t.Fatal(err)
						}
					} else if change != "ctime_only" {
						if err := os.Link(path, alias); err != nil {
							t.Fatal(err)
						}
					}
					restoreContentFixtureMTime(t, path, held, before)
				}
				if change == "repeated_link" {
					ctx.at[poll+2] = func() {
						current, err := snapshotRegularDescriptorIdentity(held)
						if err != nil {
							t.Fatal(err)
						}
						if err := os.Link(path, alias+"-again"); err != nil {
							t.Fatal(err)
						}
						restoreContentFixtureMTime(t, path, held, current)
					}
				}
				if change == "cancel_retry" {
					ctx.at[poll+1] = cancel
				}
				var got string
				var count int
				ref := state.GenerationFile{Path: "payload", Phase: "payload", Size: int64(len(body)), SHA256: bytesSHA(body)}
				switch caller {
				case "tree":
					got, count, err = digestTree(ctx, root)
				case "descriptor":
					_, err = authenticateRegularDescriptor(ctx, held, ref.Size, ref.SHA256)
				case "hash":
					got, err = hashRegularDescriptor(ctx, held)
				case "export":
					target := filepath.Join(base, "target")
					if mkErr := os.Mkdir(target, 0o755); mkErr != nil {
						t.Fatal(mkErr)
					}
					err = exportRPMLeafObject(ctx, root, target, state.PackageObject{Storage: "pool", PoolPath: "payload", Size: ref.Size, SHA256: ref.SHA256}, true)
					if err != nil {
						if _, statErr := os.Lstat(filepath.Join(target, "payload")); !errors.Is(statErr, os.ErrNotExist) {
							t.Fatalf("failed authentication published target: %v", statErr)
						}
					}
				case "reference":
					err = newPayloadEvidenceRegistry().verifyPayloadReference(ctx, root, ref)
				case "walked":
					info, statErr := held.Stat()
					if statErr != nil {
						t.Fatal(statErr)
					}
					var result state.GenerationFile
					result, _, err = newPayloadEvidenceRegistry().walkedPayload(ctx, held, info, "payload")
					got = result.SHA256
				}
				if !fired {
					t.Fatalf("mutation boundary not reached: polls=%d err=%v", ctx.calls, err)
				}
				wantErr := change == "rewrite_link" || change == "rewrite_unlink" || change == "mode_link" || change == "repeated_link" || change == "cancel_retry"
				if wantErr {
					cause := ErrIntegrity
					if change == "cancel_retry" {
						cause = context.Canceled
					}
					if !errors.Is(err, cause) || got != "" || count != 0 {
						t.Fatalf("unsafe result: digest=%q count=%d polls=%d err=%v", got, count, ctx.calls, err)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if caller == "tree" && (got != bytesSHA([]byte(ref.SHA256+"  payload\n")) || count != 1) {
						t.Fatalf("tree=%s count=%d", got, count)
					}
					if (caller == "hash" || caller == "walked") && got != ref.SHA256 {
						t.Fatalf("digest=%s", got)
					}
				}
				if ctx.calls > poll+4 {
					t.Fatalf("unbounded authentication: %d polls", ctx.calls)
				}
			})
		}
	}
}

func TestContentAuthenticationCancellationBeforeSuccess(t *testing.T) {
	for _, caller := range []string{"tree", "descriptor", "hash", "export", "reference", "walked"} {
		t.Run(caller, func(t *testing.T) {
			base := t.TempDir()
			root, target := filepath.Join(base, "root"), filepath.Join(base, "target")
			for _, dir := range []string{root, target} {
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			body := []byte("aaaaaaaa")
			path := filepath.Join(root, "payload")
			if err := os.WriteFile(path, body, 0o644); err != nil {
				t.Fatal(err)
			}
			held, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			baseCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// Two read polls precede the success boundary. The tree walker
			// also polls before visiting this file.
			poll := 3
			if caller == "tree" {
				poll++
			}
			fired := false
			ctx := &contentBoundaryContext{Context: baseCtx, at: map[int]func(){poll: func() {
				fired = true
				cancel()
			}}}
			ref := state.GenerationFile{Path: "payload", Phase: "payload", Size: int64(len(body)), SHA256: bytesSHA(body)}
			var digest string
			var count int
			switch caller {
			case "tree":
				digest, count, err = digestTree(ctx, root)
			case "descriptor":
				_, err = authenticateRegularDescriptor(ctx, held, ref.Size, ref.SHA256)
			case "hash":
				digest, err = hashRegularDescriptor(ctx, held)
			case "export":
				err = exportRPMLeafObject(ctx, root, target, state.PackageObject{Storage: "pool", PoolPath: "payload", Size: ref.Size, SHA256: ref.SHA256}, true)
			case "reference":
				err = newPayloadEvidenceRegistry().verifyPayloadReference(ctx, root, ref)
			case "walked":
				info, statErr := held.Stat()
				if statErr != nil {
					t.Fatal(statErr)
				}
				var result state.GenerationFile
				result, _, err = newPayloadEvidenceRegistry().walkedPayload(ctx, held, info, ref.Path)
				digest = result.SHA256
			}
			if !fired || !errors.Is(err, context.Canceled) || digest != "" || count != 0 {
				t.Fatalf("success boundary cancellation: fired=%t digest=%q count=%d polls=%d err=%v", fired, digest, count, ctx.calls, err)
			}
			if caller == "export" {
				if _, err := os.Lstat(filepath.Join(target, ref.Path)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("canceled authentication published target: %v", err)
				}
			}
		})
	}
}

func contentPackageFixture(t *testing.T) (ManagedPackageSource, []byte, *os.File, rootedRegularIdentity) {
	t.Helper()
	body, err := managedBenchmarkDEBBytesForArchitecture("sow-auth", "all", 256)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sow-auth_1.0-1_all.deb")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	parsed, err := aptrepo.InspectPackageReaderKnown(context.Background(), held, "main", filepath.Base(path), bytesSHA(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	object, err := debObjectFromInfo(parsed, filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	before, err := snapshotRegularDescriptorIdentity(held)
	if err != nil {
		t.Fatal(err)
	}
	return ManagedPackageSource{Object: object, Path: path}, body, held, before
}

func TestPackageFactsContentIdentity(t *testing.T) {
	for _, caller := range []string{"audit", "facts", "authenticated_facts", "authentication"} {
		for _, change := range []string{"stable", "link", "unlink", "ctime_only", "rewrite_link", "rewrite_unlink", "mode_link", "repeated_link", "cancel_retry"} {
			t.Run(caller+"/"+change, func(t *testing.T) {
				source, body, held, before := contentPackageFixture(t)
				alias := filepath.Join(t.TempDir(), "alias")
				if change == "unlink" || change == "rewrite_unlink" {
					if err := os.Link(source.Path, alias); err != nil {
						t.Fatal(err)
					}
					var err error
					before, err = snapshotRegularDescriptorIdentity(held)
					if err != nil {
						t.Fatal(err)
					}
				}
				poll := 2
				var authenticated *rootedRegularIdentity
				if caller == "authenticated_facts" {
					poll = 1
					authenticated = &before
				}
				baseCtx, cancel := context.WithCancel(context.Background())
				defer cancel()
				ctx := &contentBoundaryContext{Context: baseCtx, at: make(map[int]func())}
				fired := false
				ctx.at[poll] = func() {
					fired = true
					if change == "stable" {
						return
					}
					if change == "rewrite_link" || change == "rewrite_unlink" {
						changed := append([]byte(nil), body...)
						changed[len(changed)-1] ^= 1
						if err := os.WriteFile(source.Path, changed, 0o644); err != nil {
							t.Fatal(err)
						}
					}
					if change == "mode_link" {
						if err := os.Chmod(source.Path, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					if change == "unlink" || change == "rewrite_unlink" {
						if err := os.Remove(alias); err != nil {
							t.Fatal(err)
						}
					} else if change != "ctime_only" {
						if err := os.Link(source.Path, alias); err != nil {
							t.Fatal(err)
						}
					}
					restoreContentFixtureMTime(t, source.Path, held, before)
				}
				if change == "repeated_link" || change == "cancel_retry" {
					firstPassPolls := 0
					if caller != "authentication" {
						probe := &contentBoundaryContext{Context: context.Background()}
						if _, err := inspectKnownPackageFacts(probe, held, source); err != nil {
							t.Fatal(err)
						}
						firstPassPolls = probe.calls
					}
					// Change the retry's final-read boundary again, or cancel it.
					// Fact callers also parse before deciding to retry.
					if caller != "authenticated_facts" {
						firstPassPolls += 2
					}
					if change == "cancel_retry" {
						ctx.at[firstPassPolls+1] = cancel
					} else {
						ctx.at[firstPassPolls+2] = func() {
							current, err := snapshotRegularDescriptorIdentity(held)
							if err != nil {
								t.Fatal(err)
							}
							if err := os.Link(source.Path, alias+"-again"); err != nil {
								t.Fatal(err)
							}
							restoreContentFixtureMTime(t, source.Path, held, current)
						}
					}
				}
				measured, collector := workmetrics.Ensure(ctx)
				var err error
				if caller == "audit" {
					_, err = newPayloadEvidenceRegistry().auditObject(measured, source, source.Object, nil, checkRPMTrustPlan{}, time.Time{})
				} else if caller == "authentication" {
					opened, openErr := source.open()
					if openErr != nil {
						t.Fatal(openErr)
					}
					err = errors.Join(authenticatePackageFactSource(measured, opened, source.Object), opened.CloseVerified())
				} else {
					_, _, err = rebuildManagedPackageFact(measured, source, authenticated)
				}
				if !fired {
					t.Fatalf("boundary not reached: calls=%d err=%v", ctx.calls, err)
				}
				wantErr := change == "rewrite_link" || change == "rewrite_unlink" || change == "mode_link" || change == "repeated_link" || change == "cancel_retry"
				if (err != nil) != wantErr {
					t.Fatalf("facts returned err=%v wantError=%t", err, wantErr)
				}
				if change == "cancel_retry" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation cause lost: %v", err)
				}
				metrics := collector.Snapshot()
				if metrics.FullPackageReads > 2 {
					t.Fatalf("unbounded facts authentication: %#v", metrics)
				}
				if !wantErr {
					wantReads := int64(1)
					if change != "stable" {
						wantReads++
					}
					if caller == "authenticated_facts" {
						wantReads--
					}
					if metrics.FullPackageReads != wantReads || metrics.PayloadBytesRead != wantReads*int64(len(body)) {
						t.Fatalf("physical authentication budget=%#v wantReads=%d", metrics, wantReads)
					}
				}
				t.Logf("package_size=%d authenticated_reads=%d authenticated_bytes=%d parser_polls=%d", len(body), metrics.FullPackageReads, metrics.PayloadBytesRead, ctx.calls)
			})
		}
	}
}

// Done is evaluated after the opened identity has selected a cache slot. It
// gives a deterministic real-file mutation during the wait, before that slot's
// old evidence is returned; no production hook or timing sleep is needed.
type evidenceWaitContext struct {
	context.Context
	onWait func()
	fired  bool
}

func (ctx *evidenceWaitContext) Done() <-chan struct{} {
	if !ctx.fired {
		ctx.fired = true
		ctx.onWait()
	}
	return ctx.Context.Done()
}

func TestContentEvidenceWaitReauthenticates(t *testing.T) {
	for _, caller := range []string{"audit", "reference", "walked"} {
		for _, rewrite := range []bool{false, true} {
			t.Run(caller+"/rewrite_"+strconv.FormatBool(rewrite), func(t *testing.T) {
				source, body, held, before := contentPackageFixture(t)
				root, relative := filepath.Dir(source.Path), filepath.Base(source.Path)
				ref := state.GenerationFile{Path: relative, Phase: "payload", Size: int64(len(body)), SHA256: bytesSHA(body)}
				registry := newPayloadEvidenceRegistry()
				if _, err := registry.auditObject(context.Background(), source, source.Object, nil, checkRPMTrustPlan{}, time.Time{}); err != nil {
					t.Fatal(err)
				}
				ctx := &evidenceWaitContext{Context: context.Background()}
				ctx.onWait = func() {
					if rewrite {
						changed := append([]byte(nil), body...)
						changed[len(changed)-1] ^= 1
						if err := os.WriteFile(source.Path, changed, 0o644); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.Link(source.Path, filepath.Join(t.TempDir(), "alias")); err != nil {
						t.Fatal(err)
					}
					restoreContentFixtureMTime(t, source.Path, held, before)
				}
				measured, collector := workmetrics.Ensure(ctx)
				var err error
				var got string
				switch caller {
				case "audit":
					_, err = registry.auditObject(measured, source, source.Object, nil, checkRPMTrustPlan{}, time.Time{})
				case "reference":
					err = registry.verifyPayloadReference(measured, root, ref)
				case "walked":
					info, statErr := held.Stat()
					if statErr != nil {
						t.Fatal(statErr)
					}
					var result state.GenerationFile
					result, _, err = registry.walkedPayload(measured, held, info, relative)
					got = result.SHA256
				}
				if !ctx.fired {
					t.Fatal("cache wait boundary was not reached")
				}
				if rewrite && caller == "walked" {
					changed, readErr := os.ReadFile(source.Path)
					if readErr != nil {
						t.Fatal(readErr)
					}
					if err != nil || got != bytesSHA(changed) || got == ref.SHA256 {
						t.Fatalf("stale walked digest=%s err=%v", got, err)
					}
				} else if (err != nil) != rewrite {
					t.Fatalf("cache reuse err=%v rewrite=%t", err, rewrite)
				}
				if metrics := collector.Snapshot(); metrics.FullPackageReads != 1 || metrics.PayloadBytesRead != int64(len(body)) {
					t.Fatalf("cache drift did not authenticate once: %#v", metrics)
				}
			})
		}
	}
}

func TestContentEvidenceWaitCancellation(t *testing.T) {
	for _, caller := range []string{"audit", "reference", "walked"} {
		t.Run(caller, func(t *testing.T) {
			source, body, held, before := contentPackageFixture(t)
			registry := newPayloadEvidenceRegistry()
			registry.claim(physicalPayloadIdentityFrom(before))
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			var err error
			switch caller {
			case "audit":
				_, err = registry.auditObject(ctx, source, source.Object, nil, checkRPMTrustPlan{}, time.Time{})
			case "reference":
				err = registry.verifyPayloadReference(ctx, filepath.Dir(source.Path), state.GenerationFile{Path: filepath.Base(source.Path), Size: int64(len(body)), SHA256: bytesSHA(body)})
			case "walked":
				info, statErr := held.Stat()
				if statErr != nil {
					t.Fatal(statErr)
				}
				_, _, err = registry.walkedPayload(ctx, held, info, filepath.Base(source.Path))
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled evidence wait: %v", err)
			}
		})
	}
}
