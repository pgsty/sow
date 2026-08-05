package managed

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
)

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
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
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
	if pendingInfo, err := os.Lstat(pending); err != nil || pendingInfo.Mode().Perm() != 0o600 {
		t.Fatalf("pending object changed: info=%#v err=%v", pendingInfo, err)
	}
	if aliasInfo, err := os.Lstat(alias); err != nil || aliasInfo.Mode().Perm() != 0o600 {
		t.Fatalf("external hardlink changed: info=%#v err=%v", aliasInfo, err)
	}
}
