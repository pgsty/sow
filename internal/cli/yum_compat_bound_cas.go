package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
)

// yumCompatibilityCASWorkspace prevents repository.NewStore from ever
// resolving the mutable configured repository pathname. New/imported objects
// are built in a private external CAS, while existing objects are streamed from
// the workflow's persistent repository-root capability. A mutation installs
// verified immutable objects with root-bound no-replace links only.
type yumCompatibilityCASWorkspace struct {
	root    string
	pool    *repository.Store
	objects map[repository.Digest]int64
}

// yumCompatibilityBoundDirectory retains both the directory capability and
// the capability for its parent coordinate. Namespace replacement can then be
// detected without ever directing a later write through a multi-component
// pathname that an untrusted rename could retarget.
type yumCompatibilityBoundDirectory struct {
	label    string
	parent   *os.Root
	name     string
	root     *os.Root
	file     *os.File
	identity os.FileInfo
}

func bindYUMCompatibilityCASDirectory(parent *os.Root, name, label string, mode os.FileMode) (*yumCompatibilityBoundDirectory, error) {
	if parent == nil || name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, errors.New("unsafe bound YUM compatibility CAS directory coordinate")
	}
	info, err := parent.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if err := parent.Mkdir(name, mode); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if err := syncYUMCompatibilityRootDirectory(parent); err != nil {
			return nil, err
		}
		info, err = parent.Lstat(name)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.Join(err, fmt.Errorf("bound YUM compatibility CAS directory %s is unsafe", label))
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	identity, err := root.Stat(".")
	if err != nil || !os.SameFile(info, identity) {
		_ = root.Close()
		return nil, errors.Join(err, fmt.Errorf("bound YUM compatibility CAS directory %s changed while opening", label))
	}
	file, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(identity, opened) {
		_ = file.Close()
		_ = root.Close()
		return nil, errors.Join(err, fmt.Errorf("bound YUM compatibility CAS directory %s changed while retaining", label))
	}
	return &yumCompatibilityBoundDirectory{label: label, parent: parent, name: name, root: root, file: file, identity: identity}, nil
}

func (directory *yumCompatibilityBoundDirectory) Verify() error {
	if directory == nil || directory.parent == nil || directory.root == nil || directory.file == nil || directory.identity == nil {
		return errors.New("bound YUM compatibility CAS directory capability is unavailable")
	}
	throughParent, parentErr := directory.parent.Lstat(directory.name)
	throughRoot, rootErr := directory.root.Stat(".")
	throughFile, fileErr := directory.file.Stat()
	if parentErr != nil || rootErr != nil || fileErr != nil || throughParent.Mode()&os.ModeSymlink != 0 || !throughParent.IsDir() ||
		!os.SameFile(directory.identity, throughParent) || !os.SameFile(directory.identity, throughRoot) || !os.SameFile(directory.identity, throughFile) {
		return errors.Join(parentErr, rootErr, fileErr, fmt.Errorf("bound YUM compatibility CAS directory %s was replaced", directory.label))
	}
	return nil
}

func (directory *yumCompatibilityBoundDirectory) Close() error {
	if directory == nil {
		return nil
	}
	fileErr := error(nil)
	rootErr := error(nil)
	if directory.file != nil {
		fileErr = directory.file.Close()
	}
	if directory.root != nil {
		rootErr = directory.root.Close()
	}
	directory.file, directory.root = nil, nil
	return errors.Join(fileErr, rootErr)
}

type yumCompatibilityBoundCASTree struct {
	pool   *yumCompatibilityBoundDirectory
	sha256 *yumCompatibilityBoundDirectory
	tmp    *yumCompatibilityBoundDirectory
	shards map[string]*yumCompatibilityBoundDirectory
}

func bindYUMCompatibilityCASTree(workflow yumCompatibilityWorkflow, digests []repository.Digest) (*yumCompatibilityBoundCASTree, error) {
	if workflow.root == nil || workflow.root.root == nil {
		return nil, errors.New("bound YUM compatibility repository capability is unavailable")
	}
	tree := &yumCompatibilityBoundCASTree{shards: make(map[string]*yumCompatibilityBoundDirectory)}
	var err error
	if tree.pool, err = bindYUMCompatibilityCASDirectory(workflow.root.root, ".pool", ".pool", 0o755); err != nil {
		return nil, err
	}
	if tree.sha256, err = bindYUMCompatibilityCASDirectory(tree.pool.root, "sha256", ".pool/sha256", 0o755); err != nil {
		_ = tree.Close()
		return nil, err
	}
	if tree.tmp, err = bindYUMCompatibilityCASDirectory(tree.sha256.root, ".tmp", ".pool/sha256/.tmp", 0o700); err != nil {
		_ = tree.Close()
		return nil, err
	}
	for _, digest := range digests {
		shard := digest.String()[:2]
		if _, exists := tree.shards[shard]; exists {
			continue
		}
		tree.shards[shard], err = bindYUMCompatibilityCASDirectory(tree.sha256.root, shard, ".pool/sha256/"+shard, 0o755)
		if err != nil {
			_ = tree.Close()
			return nil, err
		}
	}
	if err := tree.Verify(); err != nil {
		_ = tree.Close()
		return nil, err
	}
	return tree, nil
}

func (tree *yumCompatibilityBoundCASTree) Verify() error {
	if tree == nil {
		return errors.New("bound YUM compatibility CAS tree is unavailable")
	}
	err := errors.Join(tree.pool.Verify(), tree.sha256.Verify(), tree.tmp.Verify())
	names := make([]string, 0, len(tree.shards))
	for name := range tree.shards {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		err = errors.Join(err, tree.shards[name].Verify())
	}
	return err
}

func (tree *yumCompatibilityBoundCASTree) Close() error {
	if tree == nil {
		return nil
	}
	var err error
	for _, shard := range tree.shards {
		err = errors.Join(err, shard.Close())
	}
	err = errors.Join(err, tree.tmp.Close(), tree.sha256.Close(), tree.pool.Close())
	tree.pool, tree.sha256, tree.tmp, tree.shards = nil, nil, nil, nil
	return err
}

func newYUMCompatibilityCASWorkspace() (*yumCompatibilityCASWorkspace, error) {
	root, err := os.MkdirTemp("", "sow-yum-cas-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}
	return &yumCompatibilityCASWorkspace{root: root, pool: pool, objects: make(map[repository.Digest]int64)}, nil
}

func (workspace *yumCompatibilityCASWorkspace) Close() error {
	if workspace == nil || workspace.root == "" {
		return nil
	}
	err := os.RemoveAll(workspace.root)
	workspace.root, workspace.pool, workspace.objects = "", nil, nil
	return err
}

func (workspace *yumCompatibilityCASWorkspace) Store() *repository.Store {
	if workspace == nil {
		return nil
	}
	return workspace.pool
}

func (workspace *yumCompatibilityCASWorkspace) TrackManifest(manifestPath string) error {
	if workspace == nil || workspace.pool == nil {
		return errors.New("YUM compatibility CAS workspace is unavailable")
	}
	file, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	reader := manifest.NewReader(file)
	for {
		entry, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			_ = file.Close()
			return nextErr
		}
		digest := repository.Digest(entry.SHA256)
		if entry.Size < 0 {
			_ = file.Close()
			return fmt.Errorf("invalid CAS identity for manifest path %s", entry.Path)
		}
		if size, exists := workspace.objects[digest]; exists && size != entry.Size {
			_ = file.Close()
			return fmt.Errorf("CAS digest %s has conflicting manifest sizes", digest)
		}
		workspace.objects[digest] = entry.Size
	}
	return file.Close()
}

// ImportLocalObject copies one already-identified private workspace file into
// the external CAS sandbox and retains it for the later bound commit. Trust
// packets are canonical state, not serving-manifest entries, so they need this
// explicit object path instead of TrackManifest.
func (workspace *yumCompatibilityCASWorkspace) ImportLocalObject(ctx context.Context, filename string, expected repository.Object) error {
	if workspace == nil || workspace.pool == nil || expected.Size < 0 {
		return errors.New("YUM compatibility CAS workspace object import is unavailable")
	}
	before, err := os.Lstat(filename)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() != expected.Size {
		return errors.Join(err, fmt.Errorf("local CAS source %s is absent, unsafe, or has the wrong size", filename))
	}
	source, err := os.Open(filename)
	if err != nil {
		return err
	}
	opened, statErr := source.Stat()
	if statErr != nil || !os.SameFile(before, opened) {
		return errors.Join(statErr, source.Close(), fmt.Errorf("local CAS source %s changed while opening", filename))
	}
	observed, putErr := workspace.pool.Put(ctx, source)
	after, restatErr := source.Stat()
	closeErr := source.Close()
	current, lstatErr := os.Lstat(filename)
	if putErr != nil || restatErr != nil || closeErr != nil || lstatErr != nil || observed != expected ||
		!os.SameFile(opened, after) || !os.SameFile(opened, current) {
		return errors.Join(putErr, restatErr, closeErr, lstatErr, fmt.Errorf("local CAS source %s changed or differs from expected object %s", filename, expected.HashString()))
	}
	if size, exists := workspace.objects[expected.SHA256]; exists && size != expected.Size {
		return fmt.Errorf("CAS digest %s has conflicting object sizes", expected.HashString())
	}
	workspace.objects[expected.SHA256] = expected.Size
	return nil
}

func (workspace *yumCompatibilityCASWorkspace) MirrorManifest(ctx context.Context, workflow yumCompatibilityWorkflow, manifestPath string) error {
	if err := workspace.TrackManifest(manifestPath); err != nil {
		return err
	}
	digests := make([]repository.Digest, 0, len(workspace.objects))
	for digest := range workspace.objects {
		if len(digest.String()) != 64 {
			return fmt.Errorf("invalid bound YUM compatibility CAS digest %q", digest)
		}
		digests = append(digests, digest)
	}
	sort.Slice(digests, func(i, j int) bool { return digests[i].String() < digests[j].String() })
	for _, digest := range digests {
		object := repository.Object{SHA256: digest, Size: workspace.objects[digest]}
		if err := workspace.mirrorObject(ctx, workflow, object); err != nil {
			return err
		}
	}
	return nil
}

// MaterializeManifest projects a mirrored manifest only inside this private
// external CAS workspace. It is the safe pathname-oriented substrate for RPM
// and metadata libraries which do not accept directory capabilities.
func (workspace *yumCompatibilityCASWorkspace) MaterializeManifest(ctx context.Context, manifestPath, target string, workers int) (string, error) {
	if workspace == nil || workspace.pool == nil || workspace.root == "" || !validYUMCompatibilityLogicalPath(filepath.ToSlash(target)) {
		return "", errors.New("private YUM compatibility CAS materialization is unavailable")
	}
	file, err := os.Open(manifestPath)
	if err != nil {
		return "", err
	}
	_, materializeErr := workspace.pool.MaterializeWithOptions(ctx, file, target, repository.MaterializeOptions{Workers: workers})
	closeErr := file.Close()
	if materializeErr != nil || closeErr != nil {
		return "", errors.Join(materializeErr, closeErr)
	}
	return filepath.Join(workspace.root, filepath.FromSlash(target)), nil
}

func (workspace *yumCompatibilityCASWorkspace) mirrorObject(ctx context.Context, workflow yumCompatibilityWorkflow, object repository.Object) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := workspace.pool.Verify(ctx, object); err == nil {
		return nil
	}
	file, info, err := openYUMCompatibilityBoundCASObject(workflow, object)
	if err != nil {
		return err
	}
	installed, putErr := workspace.pool.Put(ctx, file)
	after, statErr := file.Stat()
	closeErr := file.Close()
	current, lstatErr := workflow.root.root.Lstat(yumCompatibilityCASObjectRelative(object.SHA256))
	if putErr != nil || statErr != nil || closeErr != nil || lstatErr != nil || installed != object || !os.SameFile(info, after) || !os.SameFile(info, current) {
		return errors.Join(putErr, statErr, closeErr, lstatErr, fmt.Errorf("bound CAS object %s changed while mirroring", object.HashString()))
	}
	return nil
}

func (workspace *yumCompatibilityCASWorkspace) Commit(ctx context.Context, workflow yumCompatibilityWorkflow, phase string) (resultErr error) {
	if workspace == nil || workspace.pool == nil || workflow.root == nil || workflow.root.root == nil {
		return errors.New("bound YUM compatibility CAS commit capability is unavailable")
	}
	if len(workspace.objects) == 0 {
		return nil
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "admit "+phase+" bound CAS commit"); err != nil {
		return err
	}
	digests := make([]repository.Digest, 0, len(workspace.objects))
	for digest := range workspace.objects {
		if len(digest.String()) != 64 {
			return fmt.Errorf("invalid bound YUM compatibility CAS digest %q", digest)
		}
		digests = append(digests, digest)
	}
	sort.Slice(digests, func(i, j int) bool { return digests[i].String() < digests[j].String() })
	tree, err := bindYUMCompatibilityCASTree(workflow, digests)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, tree.Close()) }()
	if workflow.mutationHook != nil {
		if err := workflow.mutationHook(phase); err != nil {
			return fmt.Errorf("YUM compatibility CAS mutation hook %s: %w", phase, err)
		}
	}
	if err := errors.Join(
		requireYUMCompatibilityMutationBoundary(workflow, "revalidate "+phase+" bound CAS commit"),
		tree.Verify(),
	); err != nil {
		return err
	}
	for _, digest := range digests {
		if err := ctx.Err(); err != nil {
			return err
		}
		object := repository.Object{SHA256: digest, Size: workspace.objects[digest]}
		shard := tree.shards[digest.String()[:2]]
		destination := digest.String()
		if existing, _, err := openYUMCompatibilityBoundCASObjectAt(shard, object); err == nil {
			if err := existing.Close(); err != nil {
				return err
			}
			continue
		} else if _, lstatErr := shard.root.Lstat(destination); lstatErr == nil || !errors.Is(lstatErr, os.ErrNotExist) {
			return errors.Join(err, lstatErr, fmt.Errorf("occupied bound CAS coordinate %s is invalid", digest))
		}
		source, err := workspace.pool.OpenVerified(ctx, object)
		if err != nil {
			return err
		}
		nonce, err := randomYUMCompatibilityBoundNonce()
		if err != nil {
			_ = source.Close()
			return err
		}
		temporary := "compat-" + nonce
		target, err := tree.tmp.root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = source.Close()
			return err
		}
		hasher := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(target, hasher), source)
		chmodErr := target.Chmod(0o444)
		syncErr := target.Sync()
		temporaryInfo, temporaryStatErr := target.Stat()
		closeTargetErr := target.Close()
		closeSourceErr := source.Close()
		currentTemporary, temporaryLstatErr := tree.tmp.root.Lstat(temporary)
		if copyErr != nil || chmodErr != nil || syncErr != nil || temporaryStatErr != nil || closeTargetErr != nil || closeSourceErr != nil || temporaryLstatErr != nil ||
			written != object.Size || hex.EncodeToString(hasher.Sum(nil)) != object.HashString() || !os.SameFile(temporaryInfo, currentTemporary) {
			var cleanupErr error
			if temporaryInfo != nil {
				cleanupErr = removeExactYUMCompatibilityBoundFile(tree.tmp.root, temporary, temporaryInfo)
			}
			return errors.Join(copyErr, chmodErr, syncErr, temporaryStatErr, closeTargetErr, closeSourceErr, temporaryLstatErr, cleanupErr, fmt.Errorf("staged bound CAS object %s changed while copying", object.HashString()))
		}
		if err := tree.Verify(); err != nil {
			return errors.Join(err, removeExactYUMCompatibilityBoundFile(tree.tmp.root, temporary, temporaryInfo))
		}
		linkErr := linkYUMCompatibilityAcrossRoots(tree.tmp.file.Fd(), temporary, shard.file.Fd(), destination)
		if linkErr != nil && !errors.Is(linkErr, os.ErrExist) {
			return errors.Join(linkErr, removeExactYUMCompatibilityBoundFile(tree.tmp.root, temporary, temporaryInfo))
		}
		if err := removeExactYUMCompatibilityBoundFile(tree.tmp.root, temporary, temporaryInfo); err != nil {
			return err
		}
		file, _, verifyErr := openYUMCompatibilityBoundCASObjectAt(shard, object)
		if file != nil {
			verifyErr = errors.Join(verifyErr, file.Close())
		}
		if verifyErr != nil {
			return verifyErr
		}
		if err := syncYUMCompatibilityRootDirectory(shard.root); err != nil {
			return err
		}
		if err := tree.Verify(); err != nil {
			return err
		}
	}
	return errors.Join(
		tree.Verify(),
		requireYUMCompatibilityMutationBoundary(workflow, "finish "+phase+" bound CAS commit"),
	)
}

func yumCompatibilityCASObjectRelative(digest repository.Digest) string {
	value := digest.String()
	return filepath.Join(".pool", "sha256", value[:2], value)
}

func ensureYUMCompatibilityBoundCASDirectory(root *os.Root, relative string, mode os.FileMode) error {
	current := ""
	for _, part := range filepathSplitComponents(relative) {
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			permission := os.FileMode(0o755)
			if current == relative {
				permission = mode
			}
			if err := root.Mkdir(current, permission); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			info, err = root.Lstat(current)
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.Join(err, fmt.Errorf("bound CAS directory %s is unsafe", current))
		}
	}
	return nil
}

func filepathSplitComponents(value string) []string {
	clean := filepath.Clean(value)
	var reverse []string
	for clean != "." && clean != string(filepath.Separator) && clean != "" {
		reverse = append(reverse, filepath.Base(clean))
		clean = filepath.Dir(clean)
	}
	result := make([]string, len(reverse))
	for index := range reverse {
		result[len(reverse)-1-index] = reverse[index]
	}
	return result
}

func openYUMCompatibilityBoundCASObject(workflow yumCompatibilityWorkflow, object repository.Object) (*os.File, os.FileInfo, error) {
	if workflow.root == nil || workflow.root.root == nil || object.Size < 0 {
		return nil, nil, errors.New("bound CAS object capability is unavailable")
	}
	relative := yumCompatibilityCASObjectRelative(object.SHA256)
	info, err := workflow.root.root.Lstat(relative)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != object.Size {
		return nil, nil, errors.Join(err, fmt.Errorf("bound CAS object %s is absent, unsafe, or has the wrong size", object.HashString()))
	}
	file, err := workflow.root.root.Open(relative)
	if err != nil {
		return nil, nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, nil, errors.Join(statErr, file.Close(), fmt.Errorf("bound CAS object %s changed while opening", object.HashString()))
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, file)
	after, restatErr := file.Stat()
	current, lstatErr := workflow.root.root.Lstat(relative)
	if copyErr != nil || restatErr != nil || lstatErr != nil || written != object.Size || hex.EncodeToString(hasher.Sum(nil)) != object.HashString() ||
		!os.SameFile(opened, after) || !os.SameFile(opened, current) {
		return nil, nil, errors.Join(copyErr, restatErr, lstatErr, file.Close(), fmt.Errorf("bound CAS object %s is corrupt or changed while verifying", object.HashString()))
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	return file, info, nil
}

func openYUMCompatibilityBoundCASObjectAt(shard *yumCompatibilityBoundDirectory, object repository.Object) (*os.File, os.FileInfo, error) {
	digest := object.HashString()
	if shard == nil || shard.root == nil || object.Size < 0 || len(digest) != 64 || digest[:2] != shard.name {
		return nil, nil, errors.New("bound CAS shard object capability is unavailable")
	}
	name := digest
	info, err := shard.root.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != object.Size {
		return nil, nil, errors.Join(err, fmt.Errorf("bound CAS object %s is absent, unsafe, or has the wrong size", object.HashString()))
	}
	file, err := shard.root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, nil, errors.Join(statErr, file.Close(), fmt.Errorf("bound CAS object %s changed while opening", object.HashString()))
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, file)
	after, restatErr := file.Stat()
	current, lstatErr := shard.root.Lstat(name)
	if copyErr != nil || restatErr != nil || lstatErr != nil || written != object.Size || hex.EncodeToString(hasher.Sum(nil)) != object.HashString() ||
		!os.SameFile(opened, after) || !os.SameFile(opened, current) {
		return nil, nil, errors.Join(copyErr, restatErr, lstatErr, file.Close(), fmt.Errorf("bound CAS object %s is corrupt or changed while verifying", object.HashString()))
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	return file, info, nil
}

func linkYUMCompatibilityManifestFromBoundCAS(ctx context.Context, workflow yumCompatibilityWorkflow, manifestPath string, target *os.Root) error {
	if workflow.root == nil || workflow.root.file == nil || target == nil {
		return errors.New("cross-root YUM compatibility hardlink capabilities are unavailable")
	}
	targetFile, err := target.Open(".")
	if err != nil {
		return err
	}
	defer targetFile.Close()
	file, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	for {
		entry, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			return nil
		}
		if nextErr != nil {
			return nextErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		object := repository.Object{SHA256: repository.Digest(entry.SHA256), Size: entry.Size}
		source, sourceInfo, err := openYUMCompatibilityBoundCASObject(workflow, object)
		if err != nil {
			return err
		}
		destination := filepath.FromSlash(entry.Path)
		parent := filepath.Dir(destination)
		if parent != "." {
			if err := ensureYUMCompatibilityBoundCASDirectory(target, parent, 0o700); err != nil {
				_ = source.Close()
				return err
			}
		}
		if _, err := target.Lstat(destination); err == nil {
			_ = source.Close()
			return fmt.Errorf("candidate path %s is already occupied before CAS hardlink", entry.Path)
		} else if !errors.Is(err, os.ErrNotExist) {
			_ = source.Close()
			return err
		}
		if err := linkYUMCompatibilityAcrossRoots(workflow.root.file.Fd(), yumCompatibilityCASObjectRelative(object.SHA256), targetFile.Fd(), destination); err != nil {
			_ = source.Close()
			return fmt.Errorf("link bound CAS object into candidate path %s: %w", entry.Path, err)
		}
		linked, lstatErr := target.Lstat(destination)
		after, statErr := source.Stat()
		closeErr := source.Close()
		if lstatErr != nil || statErr != nil || closeErr != nil || linked.Mode()&os.ModeSymlink != 0 || !linked.Mode().IsRegular() ||
			!os.SameFile(sourceInfo, linked) || !os.SameFile(sourceInfo, after) {
			_ = target.Remove(destination)
			return errors.Join(lstatErr, statErr, closeErr, fmt.Errorf("CAS coordinate changed before candidate hardlink for %s", entry.Path))
		}
		parentHandle, err := target.Open(parent)
		if err != nil {
			return err
		}
		if err := errors.Join(parentHandle.Sync(), parentHandle.Close()); err != nil {
			return err
		}
	}
}
