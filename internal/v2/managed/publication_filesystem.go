package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"golang.org/x/sys/unix"
)

type publicationRemoteObject struct {
	Path           string
	Size           int64
	SHA256         string
	RemoteIdentity string
}

type publicationBackend interface {
	Provider() string
	List(context.Context, map[string]struct{}) ([]publicationRemoteObject, error)
	Head(context.Context, string) (publicationRemoteObject, bool, error)
	Put(context.Context, string, state.PublicationPlanOperation, string) (string, error)
	VerifyPublic(context.Context, state.GenerationFile) error
	DeleteConditional(context.Context, state.PublicationCandidate) error
	VerifyPublicAbsent(context.Context, string) error
}

type filesystemPublicationBackend struct {
	root       string
	publicBase *url.URL
}

func newFilesystemPublicationBackend(target config.TargetConfig) (*filesystemPublicationBackend, error) {
	targetRoot, err := filesystemPublicationRoot(target)
	if err != nil {
		return nil, err
	}
	endpointPath, _, err := filesystemConfiguredPublicationRoot(target)
	if err != nil {
		return nil, err
	}
	if target.Prefix != "" {
		if err := durableEnsureDirectoryTree(endpointPath, targetRoot, 0o755); err != nil {
			return nil, err
		}
	}
	physicalTarget, err := realDirectory(targetRoot, false, 0)
	if err != nil || physicalTarget != filepath.Clean(targetRoot) {
		return nil, fmt.Errorf("%w: filesystem publish prefix is not one canonical real directory: %v", ErrRejected, err)
	}
	publicBase, err := url.Parse(target.PublicEndpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid public endpoint", ErrRejected)
	}
	if publicBase.Scheme == "file" {
		publicPath := filepath.Clean(filepath.FromSlash(strings.TrimSuffix(publicBase.Path, "/")))
		physicalPublic, publicErr := realDirectory(publicPath, false, 0)
		if publicErr != nil || physicalPublic != physicalTarget {
			return nil, fmt.Errorf("%w: file public_endpoint does not name the exact publish prefix: %v", ErrRejected, publicErr)
		}
	}
	return &filesystemPublicationBackend{root: physicalTarget, publicBase: publicBase}, nil
}

func filesystemPublicationRoot(target config.TargetConfig) (string, error) {
	endpointPath, targetRoot, err := filesystemConfiguredPublicationRoot(target)
	if err != nil {
		return "", err
	}
	physicalEndpoint, err := realDirectory(endpointPath, false, 0)
	if err != nil || physicalEndpoint != endpointPath {
		return "", fmt.Errorf("%w: filesystem endpoint must already be one canonical real directory: %v", ErrRejected, err)
	}
	physicalTarget, _, err := prospectiveRealDirectory(targetRoot)
	if err != nil || physicalTarget != filepath.Clean(targetRoot) {
		return "", fmt.Errorf("%w: filesystem publish prefix is not one canonical physical path: %v", ErrRejected, err)
	}
	return targetRoot, nil
}

func filesystemConfiguredPublicationRoot(target config.TargetConfig) (string, string, error) {
	endpoint, err := url.Parse(target.Endpoint)
	if err != nil || endpoint.Scheme != "file" || endpoint.Host != "" {
		return "", "", fmt.Errorf("%w: invalid filesystem publication endpoint", ErrRejected)
	}
	endpointPath := filepath.Clean(filepath.FromSlash(endpoint.Path))
	targetRoot := endpointPath
	if target.Prefix != "" {
		targetRoot = filepath.Join(endpointPath, filepath.FromSlash(target.Prefix))
	}
	return endpointPath, targetRoot, nil
}

func (b *filesystemPublicationBackend) Provider() string { return "filesystem" }

func (b *filesystemPublicationBackend) List(ctx context.Context, ignored map[string]struct{}) ([]publicationRemoteObject, error) {
	objects := []publicationRemoteObject{}
	err := walkRootedTree(ctx, b.root, func(relative string, file *os.File, info os.FileInfo) error {
		path := filepath.ToSlash(relative)
		if _, skip := ignored[path]; skip {
			return nil
		}
		if !strings.HasPrefix(path, "pool/") && !strings.HasPrefix(path, "dists/") || publicFilePhase(path) == "" {
			return fmt.Errorf("%w: filesystem target contains foreign public object %q", ErrIntegrity, path)
		}
		hash := sha256.New()
		count, err := io.Copy(hash, &managedContextReader{ctx: ctx, reader: file})
		if err != nil || count != info.Size() {
			return errors.Join(fmt.Errorf("%w: hash filesystem target object %q", ErrIntegrity, path), err)
		}
		digest := hex.EncodeToString(hash.Sum(nil))
		objects = append(objects, publicationRemoteObject{Path: path, Size: info.Size(), SHA256: digest, RemoteIdentity: digest})
		return nil
	}, func(relative string, _ *os.File, _ os.FileInfo) error {
		path := filepath.ToSlash(relative)
		if path != "" && path != "pool" && path != "dists" && !strings.HasPrefix(path, "pool/") && !strings.HasPrefix(path, "dists/") {
			return fmt.Errorf("%w: filesystem target contains foreign directory %q", ErrIntegrity, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Path < objects[j].Path })
	return objects, nil
}

func (b *filesystemPublicationBackend) Head(ctx context.Context, path string) (publicationRemoteObject, bool, error) {
	opened, err := openRootedRegular(b.root, filepath.FromSlash(path))
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		return publicationRemoteObject{}, false, nil
	}
	if err != nil {
		return publicationRemoteObject{}, false, fmt.Errorf("%w: unsafe filesystem target object %q: %v", ErrIntegrity, path, err)
	}
	info, statErr := opened.file.Stat()
	digest, hashErr := hashOpenedFileContext(ctx, opened.file)
	closeErr := opened.CloseVerified()
	if err := errors.Join(statErr, hashErr, closeErr); err != nil {
		return publicationRemoteObject{}, false, fmt.Errorf("%w: read filesystem target object %q: %v", ErrIntegrity, path, err)
	}
	return publicationRemoteObject{Path: path, Size: info.Size(), SHA256: digest, RemoteIdentity: digest}, true, nil
}

func filesystemStagePath(path, attemptIdentity string) string {
	sum := sha256.Sum256([]byte(path))
	return filepath.ToSlash(filepath.Join(filepath.Dir(filepath.FromSlash(path)), fmt.Sprintf(".sow-publish-%s-%s", attemptIdentity[:16], hex.EncodeToString(sum[:8]))))
}

func (b *filesystemPublicationBackend) Put(ctx context.Context, sourceRoot string, operation state.PublicationPlanOperation, attemptIdentity string) (string, error) {
	if ctx == nil || len(attemptIdentity) != 64 || operation.Operation != "add" && operation.Operation != "update" || operation.Size < 0 || !lowercaseSHA256.MatchString(operation.SHA256) {
		return "", fmt.Errorf("%w: invalid filesystem publication write", ErrRejected)
	}
	if !strings.HasPrefix(operation.Path, "pool/") && !strings.HasPrefix(operation.Path, "dists/") || publicFilePhase(operation.Path) == "" {
		return "", fmt.Errorf("%w: unsafe filesystem publication path %q", ErrRejected, operation.Path)
	}
	parent := filepath.Dir(filepath.Join(b.root, filepath.FromSlash(operation.Path)))
	if err := durableEnsureDirectoryTree(b.root, parent, 0o755); err != nil {
		return "", err
	}
	current, exists, err := b.Head(ctx, operation.Path)
	if err != nil {
		return "", err
	}
	if exists && current.Size == operation.Size && current.SHA256 == operation.SHA256 {
		_ = b.removeStageIfPresent(ctx, filesystemStagePath(operation.Path, attemptIdentity))
		return current.RemoteIdentity, nil
	}
	if operation.Operation == "add" && exists {
		return "", fmt.Errorf("%w: create-only object %q already exists with different identity", ErrIntegrity, operation.Path)
	}
	if operation.Operation == "update" && (!exists || operation.ExpectedOldSHA256 == "" || current.SHA256 != operation.ExpectedOldSHA256) {
		return "", fmt.Errorf("%w: filesystem CAS precondition failed for %q", ErrIntegrity, operation.Path)
	}
	stage := filesystemStagePath(operation.Path, attemptIdentity)
	if err := b.prepareStage(ctx, sourceRoot, operation, stage); err != nil {
		return "", err
	}
	if err := b.installStageCAS(ctx, stage, operation); err != nil {
		return "", err
	}
	installed, ok, err := b.Head(ctx, operation.Path)
	if err != nil || !ok || installed.Size != operation.Size || installed.SHA256 != operation.SHA256 {
		return "", errors.Join(fmt.Errorf("%w: filesystem publication write did not install exact object %q", ErrIntegrity, operation.Path), err)
	}
	return installed.RemoteIdentity, nil
}

func (b *filesystemPublicationBackend) prepareStage(ctx context.Context, sourceRoot string, operation state.PublicationPlanOperation, stage string) error {
	if existing, ok, err := b.Head(ctx, stage); err != nil {
		return err
	} else if ok {
		if existing.Size == operation.Size && existing.SHA256 == operation.SHA256 {
			return nil
		}
		if err := removeRootedRegularExact(ctx, b.root, filepath.FromSlash(stage), existing.Size, existing.SHA256); err != nil {
			return fmt.Errorf("%w: remove incomplete publication stage %q: %v", ErrIntegrity, stage, err)
		}
	}
	source, err := openRootedRegular(sourceRoot, filepath.FromSlash(operation.Path))
	if err != nil {
		return fmt.Errorf("%w: publication source %q is missing or unsafe: %v", ErrIntegrity, operation.Path, err)
	}
	target, err := createRootedRegular(b.root, filepath.FromSlash(stage), 0o644)
	if err != nil {
		return errors.Join(err, source.CloseVerified())
	}
	committed := false
	defer func() {
		if !committed {
			_ = target.Abort()
		}
	}()
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(target.file, hash), &managedContextReader{ctx: ctx, reader: source.file})
	closeErr := source.CloseVerified()
	digest := hex.EncodeToString(hash.Sum(nil))
	if copyErr != nil || closeErr != nil || written != operation.Size || digest != operation.SHA256 {
		return errors.Join(fmt.Errorf("%w: publication source %q changed while staging", ErrIntegrity, operation.Path), copyErr, closeErr)
	}
	if err := target.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func (b *filesystemPublicationBackend) installStageCAS(ctx context.Context, stage string, operation state.PublicationPlanOperation) error {
	current, exists, err := b.Head(ctx, operation.Path)
	if err != nil {
		return err
	}
	if exists && current.Size == operation.Size && current.SHA256 == operation.SHA256 {
		return b.removeStageIfPresent(ctx, stage)
	}
	if operation.Operation == "add" && exists || operation.Operation == "update" && (!exists || current.SHA256 != operation.ExpectedOldSHA256) {
		return fmt.Errorf("%w: filesystem CAS changed before commit for %q", ErrIntegrity, operation.Path)
	}
	stageComponents, err := rootedPathComponents(filepath.FromSlash(stage), false)
	if err != nil {
		return err
	}
	targetComponents, err := rootedPathComponents(filepath.FromSlash(operation.Path), false)
	if err != nil || filepath.Join(stageComponents[:len(stageComponents)-1]...) != filepath.Join(targetComponents[:len(targetComponents)-1]...) {
		return errors.Join(errors.New("filesystem publication stage is not adjacent to its target"), err)
	}
	parentRelative := filepath.Join(targetComponents[:len(targetComponents)-1]...)
	parent, err := openRootedDirectoryChain(b.root, parentRelative, false, 0)
	if err != nil {
		return err
	}
	finish := func(result error) error { return errors.Join(result, parent.close(true)) }
	stageName, targetName := stageComponents[len(stageComponents)-1], targetComponents[len(targetComponents)-1]
	var staged unix.Stat_t
	if err := unix.Fstatat(int(parent.directory().Fd()), stageName, &staged, unix.AT_SYMLINK_NOFOLLOW); err != nil || uint32(staged.Mode)&unix.S_IFMT != unix.S_IFREG || staged.Size != operation.Size {
		return finish(errors.Join(errors.New("filesystem publication stage changed before commit"), err))
	}
	if err := parent.verify(); err != nil {
		return finish(err)
	}
	if operation.Operation == "add" {
		err = renameAtNoReplace(int(parent.directory().Fd()), stageName, int(parent.directory().Fd()), targetName)
	} else {
		err = unix.Renameat(int(parent.directory().Fd()), stageName, int(parent.directory().Fd()), targetName)
	}
	if err != nil {
		return finish(err)
	}
	var installed unix.Stat_t
	targetErr := unix.Fstatat(int(parent.directory().Fd()), targetName, &installed, unix.AT_SYMLINK_NOFOLLOW)
	var missing unix.Stat_t
	stageErr := unix.Fstatat(int(parent.directory().Fd()), stageName, &missing, unix.AT_SYMLINK_NOFOLLOW)
	if targetErr != nil || !errors.Is(stageErr, unix.ENOENT) || installed.Dev != staged.Dev || installed.Ino != staged.Ino || uint32(installed.Mode)&unix.S_IFMT != unix.S_IFREG {
		return finish(errors.Join(errors.New("filesystem publication rename result is inconsistent"), targetErr, stageErr))
	}
	return finish(parent.directory().Sync())
}

func (b *filesystemPublicationBackend) removeStageIfPresent(ctx context.Context, stage string) error {
	object, ok, err := b.Head(ctx, stage)
	if err != nil || !ok {
		return err
	}
	return removeRootedRegularExact(ctx, b.root, filepath.FromSlash(stage), object.Size, object.SHA256)
}

func (b *filesystemPublicationBackend) VerifyPublic(ctx context.Context, expected state.GenerationFile) error {
	if b.publicBase.Scheme == "file" {
		object, ok, err := b.Head(ctx, expected.Path)
		if err != nil || !ok || object.Size != expected.Size || object.SHA256 != expected.SHA256 {
			return errors.Join(fmt.Errorf("%w: file public endpoint differs for %q", ErrIntegrity, expected.Path), err)
		}
		return nil
	}
	u := *b.publicBase
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + expected.Path
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: public GET %q returned %s", ErrIntegrity, expected.Path, response.Status)
	}
	hash := sha256.New()
	written, readErr := io.Copy(hash, io.LimitReader(response.Body, expected.Size))
	var extra [1]byte
	extraCount, extraErr := response.Body.Read(extra[:])
	if extraErr != nil && !errors.Is(extraErr, io.EOF) {
		readErr = errors.Join(readErr, extraErr)
	}
	if readErr != nil || written != expected.Size || extraCount != 0 || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return errors.Join(fmt.Errorf("%w: public GET content differs for %q", ErrIntegrity, expected.Path), readErr)
	}
	return nil
}

func (b *filesystemPublicationBackend) DeleteConditional(ctx context.Context, candidate state.PublicationCandidate) error {
	if candidate.Phase != "payload" && candidate.Phase != "metadata" || candidate.Size < 0 || !lowercaseSHA256.MatchString(candidate.SHA256) || candidate.RemoteIdentity != candidate.SHA256 || !strings.HasPrefix(candidate.Path, "pool/") && !strings.HasPrefix(candidate.Path, "dists/") || publicFilePhase(candidate.Path) == "" {
		return fmt.Errorf("%w: invalid filesystem conditional-delete candidate", ErrRejected)
	}
	current, exists, err := b.Head(ctx, candidate.Path)
	if err != nil {
		return err
	}
	if exists {
		if current.Size != candidate.Size || current.SHA256 != candidate.SHA256 || current.RemoteIdentity != candidate.RemoteIdentity {
			return fmt.Errorf("%w: filesystem conditional-delete identity changed for %q", ErrIntegrity, candidate.Path)
		}
		if err := removeRootedRegularExact(ctx, b.root, filepath.FromSlash(candidate.Path), candidate.Size, candidate.SHA256); err != nil {
			return fmt.Errorf("%w: conditional delete %q: %v", ErrIntegrity, candidate.Path, err)
		}
	}
	if current, exists, err = b.Head(ctx, candidate.Path); err != nil || exists {
		return errors.Join(fmt.Errorf("%w: filesystem object %q is not absent after conditional delete", ErrIntegrity, candidate.Path), err)
	}
	return nil
}

func (b *filesystemPublicationBackend) VerifyPublicAbsent(ctx context.Context, objectPath string) error {
	if b.publicBase.Scheme == "file" {
		_, exists, err := b.Head(ctx, objectPath)
		if err != nil || exists {
			return errors.Join(fmt.Errorf("%w: file public endpoint still serves %q", ErrIntegrity, objectPath), err)
		}
		return nil
	}
	u := *b.publicBase
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + objectPath
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound && response.StatusCode != http.StatusGone {
		return fmt.Errorf("%w: public GET %q returned %s instead of absence", ErrIntegrity, objectPath, response.Status)
	}
	return nil
}
