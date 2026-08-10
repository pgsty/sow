package managed

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
	"golang.org/x/sys/unix"
)

// TestPendingObjectsAreIngestedPromotionReady pins the cross-module
// contract that lets payload promotion skip a per-object inode fsync: ingest
// must publish the pending name only after fsyncing the payload, and must
// already store it in its final public mode below a private directory. The
// mode is the observable half of that contract. If it ever drifts, promotion
// silently starts chmod+fsyncing every object again, and — worse — any pending
// writer that skipped the ingest barrier would let promotion unlink the last
// durable name over non-durable bytes.
func TestPendingObjectsAreIngestedPromotionReady(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
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
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	injected := errors.New("injected")
	_, err := Add(ctx, AddOptions{
		WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1,
		Fault: func(got string) error {
			if got == "build.staged" {
				return injected
			}
			return nil
		},
	})
	if !errors.Is(err, injected) {
		t.Fatalf("staged fault returned %v", err)
	}
	pendingRoot := filepath.Join(root, ".sow", "repo", "pending")
	entries, err := os.ReadDir(pendingRoot)
	if err != nil || len(entries) != 1 {
		t.Fatalf("pending store entries=%#v err=%v", entries, err)
	}
	pendingInfo, err := os.Stat(pendingRoot)
	if err != nil || pendingInfo.Mode().Perm() != managedPendingDirectoryMode.Perm() {
		t.Fatalf("pending directory mode=%v err=%v want=%v", pendingInfo.Mode().Perm(), err, managedPendingDirectoryMode.Perm())
	}
	digest := entries[0].Name()
	var pendingRaw unix.Stat_t
	if err := unix.Stat(filepath.Join(pendingRoot, digest), &pendingRaw); err != nil {
		t.Fatal(err)
	}
	if os.FileMode(pendingRaw.Mode).Perm() != managedPayloadFileMode.Perm() {
		t.Fatalf("ingested pending mode=%#o want=%#o: promotion would chmod and fsync every object",
			os.FileMode(pendingRaw.Mode).Perm(), managedPayloadFileMode.Perm())
	}
	if pendingRaw.Nlink != 1 {
		t.Fatalf("ingested pending Nlink=%d want=1", pendingRaw.Nlink)
	}

	result, err := Add(ctx, AddOptions{
		WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1,
	})
	if err != nil || result.Dirty {
		t.Fatalf("recovery result=%#v err=%v", result, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	objects, objectsErr := store.ListPackageObjects(ctx, []string{"el9"}, true)
	closeErr := store.Close()
	if err := errors.Join(objectsErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || objects[0].Storage != "pool" || objects[0].SHA256 != digest {
		t.Fatalf("promoted objects=%#v", objects)
	}
	var poolRaw unix.Stat_t
	if err := unix.Stat(filepath.Join(root, "repo", filepath.FromSlash(objects[0].PoolPath)), &poolRaw); err != nil {
		t.Fatal(err)
	}
	if poolRaw.Dev != pendingRaw.Dev || poolRaw.Ino != pendingRaw.Ino {
		t.Fatalf("promotion copied instead of relinking the ingested inode: pending=%d pool=%d", pendingRaw.Ino, poolRaw.Ino)
	}
	if os.FileMode(poolRaw.Mode).Perm() != managedPayloadFileMode.Perm() || poolRaw.Nlink != 1 {
		t.Fatalf("promoted pool mode=%#o Nlink=%d", os.FileMode(poolRaw.Mode).Perm(), poolRaw.Nlink)
	}
	if _, err := os.Lstat(filepath.Join(pendingRoot, digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending name survived promotion: err=%v", err)
	}
}

func TestPromotePendingObjectsGroupCommitSharedParent(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	pendingRoot := filepath.Join(root, ".sow", "repo", "pending")
	if err := os.MkdirAll(pendingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	const objectCount = 64
	objects := make([]state.PackageObject, objectCount)
	for index := range objects {
		body := []byte(fmt.Sprintf("payload-%04d", index))
		digest := bytesSHA(body)
		objects[index] = state.PackageObject{
			SHA256: digest, Size: int64(len(body)), PoolPath: fmt.Sprintf("pool/shared/object-%04d.rpm", index), Storage: "pending",
		}
		if err := os.WriteFile(filepath.Join(pendingRoot, digest), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := promotePendingObjects(ctx, root, "repo", objects, nil); err != nil {
		t.Fatal(err)
	}
	for _, object := range objects {
		if _, err := os.Lstat(filepath.Join(pendingRoot, object.SHA256)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("pending object %s remains: %v", object.SHA256, err)
		}
		target := filepath.Join(root, "repo", filepath.FromSlash(object.PoolPath))
		info, err := os.Lstat(target)
		if err != nil || info.Mode().Perm() != 0o644 || info.Size() != object.Size {
			t.Fatalf("target %s info=%#v err=%v", target, info, err)
		}
		var raw unix.Stat_t
		if err := unix.Stat(target, &raw); err != nil || raw.Nlink != 1 {
			t.Fatalf("target %s links=%d err=%v", target, raw.Nlink, err)
		}
	}
}

func TestPromotePendingObjectsRejectsDigestBeforePublicLink(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	pendingRoot := filepath.Join(root, ".sow", "repo", "pending")
	if err := os.MkdirAll(pendingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("actual")
	digest := bytesSHA([]byte("wanted"))
	object := state.PackageObject{SHA256: digest, Size: int64(len(body)), PoolPath: "pool/bad/object.rpm", Storage: "pending"}
	pending := filepath.Join(pendingRoot, digest)
	if err := os.WriteFile(pending, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := promotePendingObjects(ctx, root, "repo", []state.PackageObject{object}, nil); err == nil {
		t.Fatal("promotion unexpectedly accepted a bad pending digest")
	}
	if _, err := os.Lstat(filepath.Join(root, "repo", filepath.FromSlash(object.PoolPath))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bad pending object acquired a public name: %v", err)
	}
	got, err := os.ReadFile(pending)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("bad pending source changed: body=%q err=%v", got, err)
	}
}

func TestDeferredLinkBarriersIncludeExistingAncestors(t *testing.T) {
	root := t.TempDir()
	pendingRoot := filepath.Join(root, ".sow", "repo", "pending")
	targetParent := filepath.Join(root, "repo", "pool", "a", "pkg")
	if err := os.MkdirAll(pendingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(targetParent, 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("existing ancestor replay")
	digest := bytesSHA(body)
	if err := os.WriteFile(filepath.Join(pendingRoot, digest), body, 0o644); err != nil {
		t.Fatal(err)
	}
	barriers, _, err := linkRootedRegularDeferredTargetSync(
		context.Background(), root,
		filepath.Join(".sow", "repo", "pending", digest),
		filepath.Join("repo", "pool", "a", "pkg", "object.rpm"),
		int64(len(body)), digest, 0o644, 0o755,
	)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]struct{}, len(barriers))
	for _, barrier := range barriers {
		got[filepath.Clean(barrier)] = struct{}{}
	}
	for _, want := range []string{".", "repo", filepath.Join("repo", "pool"), filepath.Join("repo", "pool", "a"), filepath.Join("repo", "pool", "a", "pkg")} {
		if _, exists := got[want]; !exists {
			t.Errorf("existing ancestor barrier %q is missing from %#v", want, barriers)
		}
	}
	object := state.PackageObject{SHA256: digest, Size: int64(len(body)), PoolPath: "pool/a/pkg/object.rpm", Storage: "pending"}
	preparation, err := preparePendingObject(context.Background(), root, "repo", object)
	if err != nil {
		t.Fatal(err)
	}
	replay := make(map[string]struct{}, len(preparation.barriers))
	for _, barrier := range preparation.barriers {
		replay[filepath.Clean(barrier)] = struct{}{}
	}
	for _, want := range []string{".", "repo", filepath.Join("repo", "pool"), filepath.Join("repo", "pool", "a"), filepath.Join("repo", "pool", "a", "pkg")} {
		if _, exists := replay[want]; !exists {
			t.Errorf("replay ancestor barrier %q is missing from %#v", want, preparation.barriers)
		}
	}
}

func TestPromotePendingObjectsFaultLeavesRecoverableBatchState(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	pendingRoot := filepath.Join(root, ".sow", "repo", "pending")
	if err := os.MkdirAll(pendingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	objects := make([]state.PackageObject, 3)
	for index := range objects {
		body := []byte(fmt.Sprintf("ordered-%d", index))
		digest := bytesSHA(body)
		objects[index] = state.PackageObject{SHA256: digest, Size: int64(len(body)), PoolPath: fmt.Sprintf("pool/o/%d.rpm", index), Storage: "pending"}
		if err := os.WriteFile(filepath.Join(pendingRoot, digest), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	injected := errors.New("injected payload boundary")
	err := promotePendingObjects(ctx, root, "repo", objects, func(point string) error {
		if point == "build.payload."+objects[1].SHA256 {
			return injected
		}
		return nil
	})
	if !errors.Is(err, injected) {
		t.Fatalf("promotion error=%v", err)
	}
	for index, object := range objects {
		_, publicErr := os.Lstat(filepath.Join(root, "repo", filepath.FromSlash(object.PoolPath)))
		_, pendingErr := os.Lstat(filepath.Join(pendingRoot, object.SHA256))
		if index < 2 && (publicErr != nil || !errors.Is(pendingErr, os.ErrNotExist)) {
			t.Fatalf("promoted prefix index=%d public=%v pending=%v", index, publicErr, pendingErr)
		}
		if index == 2 && (publicErr != nil || pendingErr != nil) {
			t.Fatalf("prepared suffix is not dual-linked: public=%v pending=%v", publicErr, pendingErr)
		}
	}
	if err := promotePendingObjects(ctx, root, "repo", objects, nil); err != nil {
		t.Fatal(err)
	}
	for _, object := range objects {
		if _, err := os.Lstat(filepath.Join(pendingRoot, object.SHA256)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("pending object %s remains after replay: %v", object.SHA256, err)
		}
	}
}

func TestPromotePendingObjectsTargetBarrierLeavesExactDualLinks(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	pendingRoot := filepath.Join(root, ".sow", "repo", "pending")
	if err := os.MkdirAll(pendingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	objects := make([]state.PackageObject, 4)
	for index := range objects {
		body := []byte(fmt.Sprintf("dual-%d", index))
		digest := bytesSHA(body)
		objects[index] = state.PackageObject{SHA256: digest, Size: int64(len(body)), PoolPath: fmt.Sprintf("pool/d/%d.rpm", index), Storage: "pending"}
		if err := os.WriteFile(filepath.Join(pendingRoot, digest), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	injected := errors.New("target barrier reached")
	err := promotePendingObjects(ctx, root, "repo", objects, func(point string) error {
		if point == "build.payload-targets" {
			return injected
		}
		return nil
	})
	if !errors.Is(err, injected) {
		t.Fatalf("promotion error=%v", err)
	}
	for _, object := range objects {
		pending := filepath.Join(pendingRoot, object.SHA256)
		target := filepath.Join(root, "repo", filepath.FromSlash(object.PoolPath))
		var pendingRaw, targetRaw unix.Stat_t
		if err := unix.Stat(pending, &pendingRaw); err != nil {
			t.Fatal(err)
		}
		if err := unix.Stat(target, &targetRaw); err != nil {
			t.Fatal(err)
		}
		if pendingRaw.Dev != targetRaw.Dev || pendingRaw.Ino != targetRaw.Ino || pendingRaw.Nlink != 2 || targetRaw.Nlink != 2 {
			t.Fatalf("object %s is not one exact dual-linked inode: pending=%#v target=%#v", object.SHA256, pendingRaw, targetRaw)
		}
	}
	if err := promotePendingObjects(ctx, root, "repo", objects, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPromotePendingObjectsRejectsNameReplacementBeforeCleanup(t *testing.T) {
	for _, replace := range []string{"pending", "target"} {
		t.Run(replace, func(t *testing.T) {
			root := t.TempDir()
			pendingRoot := filepath.Join(root, ".sow", "repo", "pending")
			if err := os.MkdirAll(pendingRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(root, "repo"), 0o755); err != nil {
				t.Fatal(err)
			}
			body := []byte("original-payload")
			bad := []byte("replaced-payload")
			if len(body) != len(bad) {
				t.Fatal("replacement fixture sizes differ")
			}
			digest := bytesSHA(body)
			object := state.PackageObject{SHA256: digest, Size: int64(len(body)), PoolPath: "pool/r/object.rpm", Storage: "pending"}
			pending := filepath.Join(pendingRoot, digest)
			target := filepath.Join(root, "repo", filepath.FromSlash(object.PoolPath))
			if err := os.WriteFile(pending, body, 0o644); err != nil {
				t.Fatal(err)
			}
			err := promotePendingObjects(context.Background(), root, "repo", []state.PackageObject{object}, func(point string) error {
				if point != "build.payload-targets" {
					return nil
				}
				path := pending
				if replace == "target" {
					path = target
				}
				if err := os.Remove(path); err != nil {
					return err
				}
				return os.WriteFile(path, bad, 0o644)
			})
			if err == nil {
				t.Fatal("promotion accepted a namespace replacement before cleanup")
			}
			if replace == "pending" {
				got, readErr := os.ReadFile(pending)
				if readErr != nil || !bytes.Equal(got, bad) {
					t.Fatalf("replacement pending name was deleted or changed: body=%q err=%v", got, readErr)
				}
				got, readErr = os.ReadFile(target)
				if readErr != nil || !bytes.Equal(got, body) {
					t.Fatalf("authenticated target changed: body=%q err=%v", got, readErr)
				}
			} else {
				got, readErr := os.ReadFile(pending)
				if readErr != nil || !bytes.Equal(got, body) {
					t.Fatalf("last authenticated pending name was deleted: body=%q err=%v", got, readErr)
				}
			}
		})
	}
}

func TestPromotePendingObjectsCancellationLeavesBoundedRecoverableState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	pendingRoot := filepath.Join(root, ".sow", "repo", "pending")
	if err := os.MkdirAll(pendingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	objects := make([]state.PackageObject, 3)
	for index := range objects {
		body := []byte(fmt.Sprintf("cancel-%d", index))
		digest := bytesSHA(body)
		objects[index] = state.PackageObject{SHA256: digest, Size: int64(len(body)), PoolPath: fmt.Sprintf("pool/c/%d.rpm", index), Storage: "pending"}
		if err := os.WriteFile(filepath.Join(pendingRoot, digest), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	err := promotePendingObjects(ctx, root, "repo", objects, func(point string) error {
		if point == "build.payload-linked."+objects[0].SHA256 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("promotion error=%v, want context cancellation", err)
	}
	for index, object := range objects {
		_, publicErr := os.Lstat(filepath.Join(root, "repo", filepath.FromSlash(object.PoolPath)))
		_, pendingErr := os.Lstat(filepath.Join(pendingRoot, object.SHA256))
		if index == 0 && (publicErr != nil || pendingErr != nil) {
			t.Fatalf("prepared object is not recoverable: public=%v pending=%v", publicErr, pendingErr)
		}
		if index > 0 && (!errors.Is(publicErr, os.ErrNotExist) || pendingErr != nil) {
			t.Fatalf("unprepared object changed: public=%v pending=%v", publicErr, pendingErr)
		}
	}
	if err := promotePendingObjects(context.Background(), root, "repo", objects, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPendingPromotionBatchBounds(t *testing.T) {
	objects := make([]state.PackageObject, pendingPromotionBatchObjects+1)
	for index := range objects {
		objects[index].Size = 1
	}
	if end := pendingPromotionBatchEnd(objects, 0); end != pendingPromotionBatchObjects {
		t.Fatalf("object bounded batch end=%d, want %d", end, pendingPromotionBatchObjects)
	}
	if end := pendingPromotionBatchEnd(objects, pendingPromotionBatchObjects); end != len(objects) {
		t.Fatalf("remaining batch end=%d, want %d", end, len(objects))
	}
	byteBounded := []state.PackageObject{{Size: pendingPromotionBatchBytes - 1}, {Size: 2}}
	if end := pendingPromotionBatchEnd(byteBounded, 0); end != 1 {
		t.Fatalf("byte bounded batch end=%d, want 1", end)
	}
	oversized := []state.PackageObject{{Size: pendingPromotionBatchBytes + 1}, {Size: 1}}
	if end := pendingPromotionBatchEnd(oversized, 0); end != 1 {
		t.Fatalf("oversized object batch end=%d, want 1", end)
	}
}

func TestPendingSourceGuardRebindsOriginalInode(t *testing.T) {
	root := t.TempDir()
	pendingRoot := filepath.Join(root, "pending")
	if err := os.Mkdir(pendingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte("original pending payload")
	digest := bytesSHA(body)
	path := filepath.Join(pendingRoot, digest)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	source := ManagedPackageSource{
		Object: state.PackageObject{SHA256: digest, Size: int64(len(body)), Storage: "pending"},
		Owner:  pendingRoot, Relative: digest, Path: path,
	}
	guard, err := newPendingSourceGuard([]ManagedPackageSource{source})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".replaced"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := guard.Close(); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("replacement error=%v, want ErrIntegrity", err)
	}
}

func TestPendingSourceGuardUsesBoundedDescriptors(t *testing.T) {
	fdRoot := "/dev/fd"
	if runtime.GOOS == "linux" {
		fdRoot = "/proc/self/fd"
	}
	countDescriptors := func() int {
		if runtime.GOOS == "darwin" {
			var limit unix.Rlimit
			if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
				t.Skipf("descriptor limit is unavailable: %v", err)
			}
			ceiling := int(limit.Cur)
			if ceiling > 4096 {
				ceiling = 4096
			}
			count := 0
			for fd := range ceiling {
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
					count++
				} else if !errors.Is(err, unix.EBADF) {
					t.Fatalf("inspect descriptor %d: %v", fd, err)
				}
			}
			return count
		}
		entries, err := os.ReadDir(fdRoot)
		if err != nil {
			t.Skipf("descriptor directory is unavailable: %v", err)
		}
		return len(entries)
	}
	pendingRoot := filepath.Join(t.TempDir(), "pending")
	if err := os.Mkdir(pendingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	const objectCount = 128
	sources := make([]ManagedPackageSource, objectCount)
	for index := range sources {
		body := []byte(fmt.Sprintf("bounded pending descriptor %d", index))
		digest := bytesSHA(body)
		path := filepath.Join(pendingRoot, digest)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		sources[index] = ManagedPackageSource{
			Object: state.PackageObject{SHA256: digest, Size: int64(len(body)), Storage: "pending"},
			Owner:  pendingRoot, Relative: digest, Path: path,
		}
	}
	before := countDescriptors()
	guard, err := newPendingSourceGuard(sources)
	if err != nil {
		t.Fatal(err)
	}
	after := countDescriptors()
	if after > before+32 {
		_ = guard.Close()
		t.Fatalf("pending guard retained %d extra descriptors for %d objects", after-before, objectCount)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedBuildRecordsPhaseProgress(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputRoot := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputRoot, "package.rpm"))
	result, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 2})
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	detail, detailErr := store.GetOperation(ctx, result.Operation)
	closeErr := store.Close()
	if err := errors.Join(detailErr, closeErr); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"rendering": false, "promoting_payload": false, "publishing_dists": false,
		"normalizing_public_tree": false, "finalizing": false,
	}
	metricsObserved := false
	for _, event := range detail.Events {
		var progress struct {
			Version   int    `json:"version"`
			Kind      string `json:"kind"`
			Phase     string `json:"phase"`
			Completed int    `json:"completed"`
			Total     int    `json:"total"`
			Jobs      int    `json:"jobs"`
		}
		if err := jsonUnmarshalStrict(event.DetailJSON, &progress); err == nil && progress.Kind == "build_progress" {
			if _, exists := want[progress.Phase]; exists {
				if progress.Phase == "promoting_payload" && progress.Jobs != 1 {
					t.Fatalf("payload promotion reports jobs=%d, want single writer", progress.Jobs)
				}
				want[progress.Phase] = true
			}
		}
		var metrics struct {
			Version int    `json:"version"`
			Kind    string `json:"kind"`
			workmetrics.Snapshot
		}
		if err := jsonUnmarshalStrict(event.DetailJSON, &metrics); err == nil && metrics.Kind == "build_metrics" {
			metricsObserved = true
			if metrics.Version != 1 || metrics.PayloadBytesRead <= 0 || metrics.FullPackageReads <= 0 {
				t.Fatalf("invalid build metrics: %#v", metrics)
			}
			if metrics.PayloadByPhase["ingest"].Full == 0 {
				t.Fatalf("build metrics omit ingest payload reads: %#v", metrics)
			}
			for _, phase := range []string{"render_rpm", "public_normalization"} {
				if metrics.PayloadByPhase[phase].Full != 0 {
					t.Fatalf("build %s re-read cached payloads: %#v", phase, metrics)
				}
			}
			if metrics.FactCacheHits == 0 || metrics.FactCacheMisses != 0 {
				t.Fatalf("fresh add did not render from its cached facts: %#v", metrics)
			}
			if metrics.PayloadByPhase["ingest"].Full != 1 {
				t.Fatalf("fresh RPM ingest used %d full reads, want one snapshot pass: %#v", metrics.PayloadByPhase["ingest"].Full, metrics)
			}
		}
	}
	for phase, observed := range want {
		if !observed {
			t.Fatalf("missing %s progress: events=%#v", phase, detail.Events)
		}
	}
	if !metricsObserved {
		t.Fatalf("missing build_metrics event: events=%#v", detail.Events)
	}
}

func TestWarmManagedBuildUsesFactsAndStatWithoutPayloadReads(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"noble": {Format: "deb"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputRoot := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := managedBenchmarkDEBBytesWithPayload("sow-warm-stat", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(inputRoot, "sow-warm-stat_1.0-1_amd64.deb")
	if err := os.WriteFile(input, body, 0o644); err != nil {
		t.Fatal(err)
	}
	options := WorkspaceOptions{Workdir: root, CWD: root}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}, Paths: []string{input}, Jobs: 2}); err != nil {
		t.Fatal(err)
	}
	repository := cfg.Repositories["repo"]
	dist := repository.Dists["noble"]
	dist.Exclude = []config.ExcludeRule{{Name: []string{"__no_match__"}}}
	repository.Dists["noble"] = dist
	cfg.Repositories["repo"] = repository
	writeManagedConfig(t, root, cfg)
	result, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}, Jobs: 2})
	if err != nil || result.Noop {
		t.Fatalf("warm build=%#v err=%v", result, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	detail, detailErr := store.GetOperation(ctx, result.Operation)
	closeErr := store.Close()
	if err := errors.Join(detailErr, closeErr); err != nil {
		t.Fatal(err)
	}
	for _, event := range detail.Events {
		var metrics struct {
			Version int    `json:"version"`
			Kind    string `json:"kind"`
			workmetrics.Snapshot
		}
		if err := jsonUnmarshalStrict(event.DetailJSON, &metrics); err != nil || metrics.Kind != "build_metrics" {
			continue
		}
		if metrics.PayloadBytesRead != 0 || metrics.FullPackageReads != 0 {
			t.Fatalf("warm build re-read package bodies: %#v", metrics)
		}
		if metrics.StatHits != 1 || metrics.StatMisses != 0 || metrics.FactCacheHits != 1 || metrics.FactCacheMisses != 0 {
			t.Fatalf("warm build did not use one stat/fact cache hit: %#v", metrics)
		}
		return
	}
	t.Fatalf("warm build omitted build_metrics: events=%#v", detail.Events)
}

func TestAuthenticatedPayloadSnapshotRejectsRestoredMTimeRewrite(t *testing.T) {
	ctx := context.Background()
	repositoryRoot := t.TempDir()
	payload := filepath.Join(repositoryRoot, "pool", "p", "pkg.rpm")
	if err := os.MkdirAll(filepath.Dir(payload), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("authenticated payload snapshot")
	if err := os.WriteFile(payload, body, 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := scanPublicGenerationSnapshot(ctx, repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	originalInfo, err := os.Stat(payload)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	rewritten := append([]byte(nil), body...)
	rewritten[len(rewritten)-1] ^= 1
	if err := os.WriteFile(payload, rewritten, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(payload, originalInfo.ModTime(), originalInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	authenticated, err := buildAuthenticatedPayloads(snapshot, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := normalizeManagedPublicTreeWithPayloads(ctx, repositoryRoot, nil, "", authenticated); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("restored-mtime rewrite passed authenticated snapshot: %v", err)
	}
}

func TestManagedFingerprintDriftRehashesOnceAndSelfHeals(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"noble": {Format: "deb"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputRoot := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := managedBenchmarkDEBBytes("sow-ctime-self-heal")
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(inputRoot, "sow-ctime-self-heal_1.0-1_amd64.deb")
	if err := os.WriteFile(input, body, 0o644); err != nil {
		t.Fatal(err)
	}
	options := WorkspaceOptions{Workdir: root, CWD: root}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}, Paths: []string{input}, Jobs: 2}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	objects, objectErr := store.ListPackageObjects(ctx, nil, false)
	closeErr := store.Close()
	if err := errors.Join(objectErr, closeErr); err != nil || len(objects) != 1 {
		t.Fatalf("objects=%#v err=%v", objects, err)
	}
	pool := filepath.Join(root, "repo", filepath.FromSlash(objects[0].PoolPath))
	opened, err := openRootedRegular(filepath.Dir(pool), filepath.Base(pool))
	if err != nil {
		t.Fatal(err)
	}
	before, identityErr := snapshotRootedRegularIdentity(opened)
	if err := errors.Join(identityErr, opened.CloseVerified()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	link := filepath.Join(root, "ctime-only-link.deb")
	if err := os.Link(pool, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	opened, err = openRootedRegular(filepath.Dir(pool), filepath.Base(pool))
	if err != nil {
		t.Fatal(err)
	}
	after, identityErr := snapshotRootedRegularIdentity(opened)
	if err := errors.Join(identityErr, opened.CloseVerified()); err != nil {
		t.Fatal(err)
	}
	if !before.sameInode(after) || before.size != after.size || before.modUnixNano != after.modUnixNano || before.changeUnixNano == after.changeUnixNano {
		t.Fatalf("ctime-only fixture before=%#v after=%#v", before, after)
	}
	if preview, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}, Packages: []string{"sha256:" + objects[0].SHA256}, Check: true, Jobs: 2}); err != nil || !preview.Check {
		t.Fatalf("read-only preview could not validate stale fingerprint: preview=%#v err=%v", preview, err)
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	fingerprints, fingerprintErr := store.ListPackageFingerprints(ctx)
	closeErr = store.Close()
	wantFingerprint := packageFingerprint(before)
	if err := errors.Join(fingerprintErr, closeErr); err != nil || len(fingerprints) != 1 || fingerprints[0].Fingerprint == nil || *fingerprints[0].Fingerprint != *wantFingerprint {
		t.Fatalf("read-only preview changed the persisted fingerprint: fingerprints=%#v err=%v", fingerprints, err)
	}
	setManagedBenchmarkExclude(t, root, &cfg, "__ctime_rehash__")
	first, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2})
	if err != nil {
		t.Fatal(err)
	}
	metrics := managedBuildMetrics(t, root, first.Operation)
	if metrics.StatMisses != 1 || metrics.StatHits != 0 || metrics.PayloadByPhase["current_public_generation"].Full != 1 || metrics.FactCacheHits != 1 {
		t.Fatalf("ctime drift did not use one hash fallback: %#v", metrics)
	}
	setManagedBenchmarkExclude(t, root, &cfg, "__ctime_healed__")
	second, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2})
	if err != nil {
		t.Fatal(err)
	}
	metrics = managedBuildMetrics(t, root, second.Operation)
	if metrics.StatHits != 1 || metrics.StatMisses != 0 || metrics.FullPackageReads != 0 {
		t.Fatalf("healed fingerprint missed the next warm build: %#v", metrics)
	}
}

func TestManagedMissingAndPoisonedFactsLazilyRebuild(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"noble": {Format: "deb"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputRoot := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := managedBenchmarkDEBBytes("sow-facts-rebuild")
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(inputRoot, "sow-facts-rebuild_1.0-1_amd64.deb")
	if err := os.WriteFile(input, body, 0o644); err != nil {
		t.Fatal(err)
	}
	options := WorkspaceOptions{Workdir: root, CWD: root}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}, Paths: []string{input}, Jobs: 2}); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(root, ".sow", "repo.db")
	store, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := store.ListPackageObjects(ctx, nil, false)
	if err != nil || len(objects) != 1 {
		store.Close()
		t.Fatalf("objects=%#v err=%v", objects, err)
	}
	if _, err := store.DB().ExecContext(ctx, `DELETE FROM package_facts WHERE package_sha256 = ?`, objects[0].SHA256); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if preview, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}, Packages: []string{"sha256:" + objects[0].SHA256}, Check: true, Jobs: 2}); err != nil || !preview.Check {
		t.Fatalf("read-only preview could not rebuild missing facts in memory: preview=%#v err=%v", preview, err)
	}
	store, err = state.OpenReadOnly(database)
	if err != nil {
		t.Fatal(err)
	}
	var factCount int
	countErr := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM package_facts WHERE package_sha256 = ?`, objects[0].SHA256).Scan(&factCount)
	closeErr := store.Close()
	if err := errors.Join(countErr, closeErr); err != nil || factCount != 0 {
		t.Fatalf("read-only preview persisted cache rows: count=%d err=%v", factCount, err)
	}
	setManagedBenchmarkExclude(t, root, &cfg, "__missing_facts__")
	missing, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2})
	if err != nil {
		t.Fatal(err)
	}
	metrics := managedBuildMetrics(t, root, missing.Operation)
	if metrics.FactCacheMisses != 1 || metrics.PayloadByPhase["facts_backfill"].Full != 1 {
		t.Fatalf("missing facts were not lazily rebuilt: %#v", metrics)
	}
	store, err = state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := store.ListPackageFacts(ctx)
	if err != nil || len(facts) != 1 {
		store.Close()
		t.Fatalf("rebuilt facts=%#v err=%v", facts, err)
	}
	var poisoned map[string]any
	if err := json.Unmarshal(facts[0].Facts, &poisoned); err != nil {
		store.Close()
		t.Fatal(err)
	}
	values, ok := poisoned["control_values"].(map[string]any)
	if !ok {
		store.Close()
		t.Fatalf("facts lack control values: %#v", poisoned)
	}
	poolPath, err := managedPoolPath("evil", objects[0].Filename)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	poisoned["name"], poisoned["source"], poisoned["pool_path"] = "evil", "evil", poolPath
	values["Package"] = "evil"
	poisonedBytes, err := json.Marshal(poisoned)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE package_facts SET facts = ?, facts_sha256 = ? WHERE package_sha256 = ?`, poisonedBytes, bytesSHA(poisonedBytes), objects[0].SHA256); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	setManagedBenchmarkExclude(t, root, &cfg, "__poisoned_facts__")
	poisonedBuild, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2})
	if err != nil {
		t.Fatal(err)
	}
	metrics = managedBuildMetrics(t, root, poisonedBuild.Operation)
	if metrics.StatHits != 1 || metrics.FactCacheMisses != 1 || metrics.PayloadByPhase["facts_backfill"].Full != 1 {
		t.Fatalf("coherently poisoned facts were not rebuilt: %#v", metrics)
	}
	store, err = state.OpenReadOnly(database)
	if err != nil {
		t.Fatal(err)
	}
	facts, factErr := store.ListPackageFacts(ctx)
	closeErr = store.Close()
	if err := errors.Join(factErr, closeErr); err != nil || len(facts) != 1 || bytes.Equal(facts[0].Facts, poisonedBytes) {
		t.Fatalf("poisoned facts survived rebuild: facts=%#v err=%v", facts, err)
	}
}

func setManagedBenchmarkExclude(t testing.TB, root string, cfg *config.Config, marker string) {
	t.Helper()
	repository := cfg.Repositories["repo"]
	dist := repository.Dists["noble"]
	dist.Exclude = []config.ExcludeRule{{Name: []string{marker}}}
	repository.Dists["noble"] = dist
	cfg.Repositories["repo"] = repository
	writeManagedConfig(t, root, *cfg)
}

func managedBuildMetrics(t testing.TB, root, operationID string) workmetrics.Snapshot {
	t.Helper()
	ctx := context.Background()
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	detail, detailErr := store.GetOperation(ctx, operationID)
	closeErr := store.Close()
	if err := errors.Join(detailErr, closeErr); err != nil {
		t.Fatal(err)
	}
	for _, event := range detail.Events {
		var metrics struct {
			Version int    `json:"version"`
			Kind    string `json:"kind"`
			workmetrics.Snapshot
		}
		if err := jsonUnmarshalStrict(event.DetailJSON, &metrics); err == nil && metrics.Kind == "build_metrics" {
			return metrics.Snapshot
		}
	}
	t.Fatalf("operation %s omitted build_metrics", operationID)
	return workmetrics.Snapshot{}
}

// BenchmarkManagedBuildPayloadAmplification complements the 50K object-count
// gate with one realistically large package. It measures the warm rebuild path
// after a policy-only config change and reports actual package bytes read, so a
// hot filesystem cache cannot hide read amplification. The payload defaults to
// 64 MiB and can be adjusted with SOW_MANAGED_BENCH_PAYLOAD_MIB.
func BenchmarkManagedBuildPayloadAmplification(b *testing.B) {
	payloadMiB := 64
	if raw := os.Getenv("SOW_MANAGED_BENCH_PAYLOAD_MIB"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1024 {
			b.Fatalf("SOW_MANAGED_BENCH_PAYLOAD_MIB=%q is outside 1..1024", raw)
		}
		payloadMiB = parsed
	}
	payloadBytes := payloadMiB << 20
	b.ReportMetric(float64(payloadBytes), "package_bytes/op")
	ctx := context.Background()
	for range b.N {
		b.StopTimer()
		root := b.TempDir()
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"noble": {Format: "deb"}}}
		writeManagedConfig(b, root, cfg)
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			b.Fatal(err)
		}
		inputRoot := filepath.Join(root, "inputs")
		if err := os.Mkdir(inputRoot, 0o755); err != nil {
			b.Fatal(err)
		}
		body, err := managedBenchmarkDEBBytesWithPayload("sow-payload-amplification", payloadBytes)
		if err != nil {
			b.Fatal(err)
		}
		input := filepath.Join(inputRoot, "sow-payload-amplification_1.0-1_amd64.deb")
		if err := os.WriteFile(input, body, 0o644); err != nil {
			b.Fatal(err)
		}
		options := WorkspaceOptions{Workdir: root, CWD: root}
		if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}, Paths: []string{input}, Jobs: 4}); err != nil {
			b.Fatal(err)
		}
		repository := cfg.Repositories["repo"]
		dist := repository.Dists["noble"]
		dist.Exclude = []config.ExcludeRule{{Name: []string{"__sow_payload_benchmark_no_match__"}}}
		repository.Dists["noble"] = dist
		cfg.Repositories["repo"] = repository
		writeManagedConfig(b, root, cfg)
		b.StartTimer()
		result, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}, Jobs: 4})
		b.StopTimer()
		if err != nil || result.Noop || result.Generation < 2 {
			b.Fatalf("build=%#v err=%v", result, err)
		}
		store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			b.Fatal(err)
		}
		detail, detailErr := store.GetOperation(ctx, result.Operation)
		closeErr := store.Close()
		if err := errors.Join(detailErr, closeErr); err != nil {
			b.Fatal(err)
		}
		reportManagedBuildProgressMetrics(b, detail)
	}
}

// BenchmarkManagedBuildDistinct50K is the end-to-end scale gate for the
// Managed build path. Setup creates real, uniquely coordinated DEBs and writes
// their exact pending state in one private transaction with the timer stopped.
// Each synthetic DEB is only a few hundred bytes, so this benchmark isolates
// per-object query, namespace, and durability overhead; it does not predict
// large-payload hashing throughput. The measured section is
// render -> payload promotion -> Dist publication -> full-tree normalization ->
// Generation finalization. SOW_MANAGED_BENCH_OBJECTS may lower the count for a
// quick local smoke run, and SOW_MANAGED_BENCH_JOBS can confirm that namespace
// publication does not depend on worker concurrency. CI/performance acceptance
// leaves the object count unset at 50,000.
func BenchmarkManagedBuildDistinct50K(b *testing.B) {
	objectCount := 50_000
	if raw := os.Getenv("SOW_MANAGED_BENCH_OBJECTS"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 50_000 {
			b.Fatalf("SOW_MANAGED_BENCH_OBJECTS=%q is outside 1..50000", raw)
		}
		objectCount = parsed
	}
	jobs := 12
	if raw := os.Getenv("SOW_MANAGED_BENCH_JOBS"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 64 {
			b.Fatalf("SOW_MANAGED_BENCH_JOBS=%q is outside 1..64", raw)
		}
		jobs = parsed
	}
	ctx := context.Background()
	b.ReportMetric(float64(jobs), "jobs/op")
	b.ReportMetric(float64(objectCount), "objects/op")
	for range b.N {
		b.StopTimer()
		root := b.TempDir()
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"noble": {Format: "deb"}}}
		data, err := config.Marshal(cfg)
		if err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), data, 0o644); err != nil {
			b.Fatal(err)
		}
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			b.Fatal(err)
		}
		options := WorkspaceOptions{Workdir: root, CWD: root}
		beforeStore, err := state.Open(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			b.Fatal(err)
		}
		before, err := beforeStore.Summary(ctx)
		if err != nil {
			_ = beforeStore.Close()
			b.Fatal(err)
		}
		revision := before.DesiredRevision + 1
		tx, err := beforeStore.DB().BeginTx(ctx, nil)
		if err != nil {
			_ = beforeStore.Close()
			b.Fatal(err)
		}
		insertObject, err := tx.PrepareContext(ctx, `INSERT INTO package_objects(
sha256, format, coordinate, architecture, pool_path, size, name, source, version,
epoch, release, canonical_arch, kind, filename, payload_sha256, signature_key,
warning, storage, created_revision)
VALUES (?, 'deb', ?, 'amd64', ?, ?, ?, ?, '1.0-1', '', '', 'x86_64', 'main', ?, NULL, NULL, NULL, 'pending', ?)`)
		if err != nil {
			_ = tx.Rollback()
			_ = beforeStore.Close()
			b.Fatal(err)
		}
		insertMembership, err := tx.PrepareContext(ctx, `INSERT INTO memberships(dist_name, package_sha256, created_revision) VALUES ('noble', ?, ?)`)
		if err != nil {
			_ = insertObject.Close()
			_ = tx.Rollback()
			_ = beforeStore.Close()
			b.Fatal(err)
		}
		pendingRoot := filepath.Join(root, ".sow", "repo", "pending")
		for index := range objectCount {
			name := fmt.Sprintf("sow-perf-%05d", index)
			filename := name + "_1.0-1_amd64.deb"
			body, err := managedBenchmarkDEBBytes(name)
			if err != nil {
				b.Fatal(err)
			}
			digest := bytesSHA(body)
			poolPath, err := managedPoolPath(name, filename)
			if err != nil {
				b.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(pendingRoot, digest), body, 0o644); err != nil {
				b.Fatal(err)
			}
			if _, err := insertObject.ExecContext(ctx, digest, name+"=1.0-1:amd64", poolPath, len(body), name, name, filename, revision); err != nil {
				b.Fatal(err)
			}
			if _, err := insertMembership.ExecContext(ctx, digest, revision); err != nil {
				b.Fatal(err)
			}
		}
		if err := errors.Join(insertMembership.Close(), insertObject.Close()); err != nil {
			b.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE dists SET desired_revision = ? WHERE name = 'noble'`, revision); err != nil {
			b.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE repository_state SET desired_revision = ?, status = 'dirty', dirty_reason = 'one or more dists differ from their built projections' WHERE singleton = 1`, revision); err != nil {
			b.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			b.Fatal(err)
		}
		checkpointErr := beforeStore.Checkpoint(ctx)
		closeErr := beforeStore.Close()
		if err := errors.Join(checkpointErr, closeErr); err != nil {
			b.Fatal(err)
		}
		wantGeneration, err := before.BuiltGeneration.Next()
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		result, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}, Jobs: jobs})
		b.StopTimer()
		if err != nil || result.Generation != wantGeneration || result.Dirty || result.Noop {
			b.Fatalf("build=%#v err=%v", result, err)
		}
		store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			b.Fatal(err)
		}
		objects, objectsErr := store.ListPackageObjects(ctx, []string{"noble"}, true)
		pending, pendingErr := store.ListPendingPackageObjects(ctx)
		detail, detailErr := store.GetOperation(ctx, result.Operation)
		closeErr = store.Close()
		if err := errors.Join(objectsErr, pendingErr, detailErr, closeErr); err != nil {
			b.Fatal(err)
		}
		if len(objects) != objectCount || len(pending) != 0 {
			b.Fatalf("built objects=%d pending=%d want=%d/0", len(objects), len(pending), objectCount)
		}
		reportManagedBuildProgressMetrics(b, detail)
	}
}

func reportManagedBuildProgressMetrics(b *testing.B, detail state.OperationDetail) {
	type progressEvent struct {
		Version   int    `json:"version"`
		Kind      string `json:"kind"`
		Phase     string `json:"phase"`
		Completed int    `json:"completed"`
		Total     int    `json:"total"`
		Jobs      int    `json:"jobs"`
	}
	started := map[string]time.Time{}
	for _, event := range detail.Events {
		var progress progressEvent
		if err := jsonUnmarshalStrict(event.DetailJSON, &progress); err == nil && progress.Kind == "build_progress" {
			if progress.Completed == 0 {
				started[progress.Phase] = event.OccurredAt
			}
			if start, exists := started[progress.Phase]; exists && progress.Total > 0 && progress.Completed == progress.Total {
				milliseconds := float64(event.OccurredAt.Sub(start).Microseconds()) / 1_000
				b.ReportMetric(milliseconds, progress.Phase+"_ms/op")
			}
		}
		var metrics struct {
			Version int    `json:"version"`
			Kind    string `json:"kind"`
			workmetrics.Snapshot
		}
		if err := jsonUnmarshalStrict(event.DetailJSON, &metrics); err == nil && metrics.Kind == "build_metrics" {
			b.ReportMetric(float64(metrics.PayloadBytesRead), "payload_bytes/op")
			b.ReportMetric(float64(metrics.FullPackageReads), "package_reads/op")
			b.ReportMetric(float64(metrics.StatHits), "stat_hits/op")
			b.ReportMetric(float64(metrics.StatMisses), "stat_misses/op")
			b.ReportMetric(float64(metrics.FactCacheHits), "fact_hits/op")
			b.ReportMetric(float64(metrics.FactCacheMisses), "fact_misses/op")
		}
	}
	b.ReportMetric(float64(detail.DurationMS), "operation_ms/op")
}

func managedBenchmarkDEBBytes(packageName string) ([]byte, error) {
	return managedBenchmarkDEBBytesWithPayload(packageName, 0)
}

func managedBenchmarkDEBBytesWithPayload(packageName string, payloadBytes int) ([]byte, error) {
	control := []byte(fmt.Sprintf("Package: %s\nVersion: 1.0-1\nArchitecture: amd64\nMaintainer: SOW Performance <sow@example.invalid>\nSection: utils\nPriority: optional\nDescription: managed build performance fixture\n", packageName))
	var controlTar bytes.Buffer
	tw := tar.NewWriter(&controlTar)
	if err := tw.WriteHeader(&tar.Header{Name: "control", Mode: 0o644, Size: int64(len(control))}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(control); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	writeManagedBenchmarkARMember(&archive, "debian-binary", []byte("2.0\n"))
	writeManagedBenchmarkARMember(&archive, "control.tar", controlTar.Bytes())
	payload := []byte("payload is intentionally not opened")
	if payloadBytes > 0 {
		payload = make([]byte, payloadBytes)
	}
	writeManagedBenchmarkARMember(&archive, "data.tar.zst", payload)
	return archive.Bytes(), nil
}

func writeManagedBenchmarkARMember(archive *bytes.Buffer, name string, data []byte) {
	fmt.Fprintf(archive, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", name+"/", 0, 0, 0, 0o644, len(data))
	archive.Write(data)
	if len(data)%2 != 0 {
		archive.WriteByte('\n')
	}
}
