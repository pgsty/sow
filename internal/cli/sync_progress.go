package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pgsty/sow/internal/config"
	"golang.org/x/sys/unix"
)

const (
	syncProgressSchema   = "sow-sync-progress/v1"
	syncProgressFilename = "progress.json"
	syncProgressMaxBytes = 64 << 10
)

type syncProgressPhase string

const (
	syncPhasePrepared             syncProgressPhase = "prepared"
	syncPhaseProvenanceCommitting syncProgressPhase = "provenance-committing"
	syncPhaseProvenanceCommitted  syncProgressPhase = "provenance-committed"
	syncPhaseIngesting            syncProgressPhase = "ingesting"
	syncPhaseProjectionRepair     syncProgressPhase = "projection-repair"
)

var (
	syncProgressNamePattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$`)
	syncProgressSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	syncProgressGitPattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	syncProgressTxPattern     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	syncOperationOpen         sync.Mutex
)

// syncProgress is deliberately small and secret-free. It records only stable
// operation identities and durable phase boundaries; source URLs, credential
// values, signing material, error strings, and local input paths never enter
// the recovery record.
type syncProgress struct {
	Schema                string            `json:"schema"`
	Upstream              string            `json:"upstream"`
	Repository            string            `json:"repository"`
	Format                string            `json:"format"`
	ConfigSHA256          string            `json:"config_sha256"`
	SelectionSHA256       string            `json:"selection_sha256"`
	ReplaySHA256          string            `json:"replay_sha256"`
	ReplayCount           int64             `json:"replay_count"`
	ProvenanceInputSHA256 string            `json:"provenance_input_sha256"`
	ProvenanceTransaction string            `json:"provenance_transaction,omitempty"`
	ProvenanceCommit      string            `json:"provenance_commit,omitempty"`
	Phase                 syncProgressPhase `json:"phase"`
	CurrentUnit           string            `json:"current_unit,omitempty"`
	CompletedUnits        []string          `json:"completed_units"`
	CreatedAt             string            `json:"created_at"`
	UpdatedAt             string            `json:"updated_at"`
}

type syncOperation struct {
	dir      string
	root     *os.Root
	lockFile *os.File
}

type durableSyncPartialError struct {
	err error
}

func (e *durableSyncPartialError) Error() string { return e.err.Error() }
func (e *durableSyncPartialError) Unwrap() error { return e.err }

type syncProgressSelection struct {
	Repository             config.Repo          `json:"repository"`
	Upstream               config.Upstream      `json:"upstream"`
	Beta                   config.View          `json:"beta"`
	Stable                 config.View          `json:"stable"`
	GPG                    config.GPGConfig     `json:"gpg"`
	RepositoryKeySHA256    string               `json:"repository_key_sha256"`
	UpstreamKeyringSHA256  string               `json:"upstream_keyring_sha256"`
	PackageKeyringSHA256   string               `json:"package_keyring_sha256,omitempty"`
	Serving                config.ServingConfig `json:"serving"`
	APTByHashRetention     int                  `json:"apt_by_hash_retention"`
	YUMGenerationRetention int                  `json:"yum_generation_retention"`
}

func acquireSyncOperation(ctx context.Context, stateDir, upstreamID string) (*syncOperation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !syncProgressNamePattern.MatchString(upstreamID) {
		return nil, errors.New("invalid sync upstream identity")
	}
	dir, err := ensureSyncOperationDirectory(stateDir, upstreamID)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open sync operation directory: %w", err)
	}
	const lockName = ".operation.lock"

	// Serialize the Lstat/open/post-open identity check inside this process.
	// Cross-process exclusion is provided by flock below and automatically
	// disappears after SIGKILL, unlike a stale PID-file lock.
	syncOperationOpen.Lock()
	prior, priorErr := root.Lstat(lockName)
	if priorErr == nil && !privateRegularFile(prior) {
		syncOperationOpen.Unlock()
		root.Close()
		return nil, errors.New("sync operation lock must be a private regular file")
	}
	if priorErr != nil && !errors.Is(priorErr, os.ErrNotExist) {
		syncOperationOpen.Unlock()
		root.Close()
		return nil, priorErr
	}
	lockFile, err := root.OpenFile(lockName, os.O_CREATE|os.O_RDWR, 0o600)
	if err == nil {
		opened, statErr := lockFile.Stat()
		current, lstatErr := root.Lstat(lockName)
		if statErr != nil || lstatErr != nil || !privateRegularFile(opened) || !privateRegularFile(current) || !os.SameFile(opened, current) {
			err = errors.Join(statErr, lstatErr, errors.New("sync operation lock changed while opening"))
		}
	}
	syncOperationOpen.Unlock()
	if err != nil {
		if lockFile != nil {
			_ = lockFile.Close()
		}
		root.Close()
		return nil, err
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lockFile.Close()
		root.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("sync upstream %s is already active", upstreamID)
		}
		return nil, fmt.Errorf("lock sync upstream %s: %w", upstreamID, err)
	}
	return &syncOperation{dir: dir, root: root, lockFile: lockFile}, nil
}

func ensureSyncOperationDirectory(stateDir, upstreamID string) (string, error) {
	stateInfo, err := os.Lstat(stateDir)
	if err != nil || !stateInfo.IsDir() || stateInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.Join(err, errors.New("sync state root must be a real directory"))
	}
	syncDir := filepath.Join(stateDir, "sync")
	if err := ensurePrivateDirectory(syncDir); err != nil {
		return "", fmt.Errorf("prepare sync directory: %w", err)
	}
	upstreamDir := filepath.Join(syncDir, upstreamID)
	if err := ensurePrivateDirectory(upstreamDir); err != nil {
		return "", fmt.Errorf("prepare upstream sync directory: %w", err)
	}
	return upstreamDir, nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(err, errors.New("path is not a real directory"))
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	info, err = os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.Join(err, errors.New("private directory changed while preparing"))
	}
	return syncDirectoryPath(filepath.Dir(path))
}

func privateRegularFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o600
}

func (o *syncOperation) Close() error {
	if o == nil {
		return nil
	}
	var result error
	if o.lockFile != nil {
		result = errors.Join(result, unix.Flock(int(o.lockFile.Fd()), unix.LOCK_UN), o.lockFile.Close())
		o.lockFile = nil
	}
	if o.root != nil {
		result = errors.Join(result, o.root.Close())
		o.root = nil
	}
	return result
}

func (o *syncOperation) Load() (*syncProgress, error) {
	if o == nil || o.root == nil {
		return nil, errors.New("sync operation is closed")
	}
	info, err := o.root.Lstat(syncProgressFilename)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !privateRegularFile(info) {
		return nil, errors.New("sync progress must be a private regular file")
	}
	file, err := o.root.Open(syncProgressFilename)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	current, lstatErr := o.root.Lstat(syncProgressFilename)
	if statErr != nil || lstatErr != nil || !privateRegularFile(opened) || !privateRegularFile(current) || !os.SameFile(opened, current) {
		_ = file.Close()
		return nil, errors.Join(statErr, lstatErr, errors.New("sync progress changed while opening"))
	}
	data, readErr := io.ReadAll(io.LimitReader(file, syncProgressMaxBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if len(data) > syncProgressMaxBytes {
		return nil, errors.New("sync progress exceeds safety limit")
	}
	progress, err := decodeSyncProgress(data)
	if err != nil {
		return nil, fmt.Errorf("decode sync progress: %w", err)
	}
	return &progress, nil
}

func (o *syncOperation) Write(progress *syncProgress) error {
	if o == nil || o.root == nil || progress == nil {
		return errors.New("sync progress store is unavailable")
	}
	data, err := progress.canonical()
	if err != nil {
		return err
	}
	if info, err := o.root.Lstat(syncProgressFilename); err == nil {
		if !privateRegularFile(info) {
			return errors.New("refusing to replace unsafe sync progress file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, tmpName, err := createSyncProgressTemp(o.root)
	if err != nil {
		return err
	}
	defer o.root.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := o.root.Rename(tmpName, syncProgressFilename); err != nil {
		return err
	}
	info, err := o.root.Lstat(syncProgressFilename)
	if err != nil || !privateRegularFile(info) {
		return errors.Join(err, errors.New("atomic sync progress result is unsafe"))
	}
	return syncRootDirectory(o.root)
}

func (o *syncOperation) RemoveProgress() error {
	if o == nil || o.root == nil {
		return errors.New("sync progress store is unavailable")
	}
	info, err := o.root.Lstat(syncProgressFilename)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !privateRegularFile(info) {
		return errors.New("refusing to remove unsafe sync progress file")
	}
	if err := o.root.Remove(syncProgressFilename); err != nil {
		return err
	}
	return syncRootDirectory(o.root)
}

func createSyncProgressTemp(root *os.Root) (*os.File, string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := ".progress-" + hex.EncodeToString(random[:])
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("could not allocate sync progress temporary file")
}

func syncRootDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	return errors.Join(syncErr, directory.Close())
}

func syncDirectoryPath(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func newSyncProgress(cfg *config.Config, repo config.Repo, source config.Upstream) (*syncProgress, error) {
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return nil, err
	}
	selectionSHA, err := syncSelectionSHA256(cfg, repo, source)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return &syncProgress{
		Schema: syncProgressSchema, Upstream: source.ID, Repository: repo.ID, Format: source.Type,
		ConfigSHA256: configSHA, SelectionSHA256: selectionSHA, Phase: syncPhasePrepared,
		CompletedUnits: []string{}, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func syncSelectionSHA256(cfg *config.Config, repo config.Repo, source config.Upstream) (string, error) {
	if cfg == nil {
		return "", errors.New("sync selection requires config view contracts")
	}
	if repo.Type != source.Type || (repo.Type != "apt" && repo.Type != "yum") {
		return "", errors.New("sync selection requires one matching package repository contract")
	}
	_, packets, err := loadRepositoryPublicTrustAnchor(cfg.Path, cfg.GPG.PublicKey)
	if err != nil {
		return "", fmt.Errorf("load repository signing trust identity for sync: %w", err)
	}
	repositoryKeySHA256 := repositoryTrustAnchorDigest(packets)
	if !syncProgressSHA256Pattern.MatchString(repositoryKeySHA256) {
		return "", errors.New("invalid repository signing trust identity for sync")
	}
	_, upstreamKeyringSHA256, err := loadPublicOnlyKeyring(cfg.Path, source.Keyring, "upstream")
	if err != nil || !syncProgressSHA256Pattern.MatchString(upstreamKeyringSHA256) {
		return "", errors.Join(err, errors.New("invalid upstream metadata keyring identity for sync"))
	}
	packageKeyringSHA256 := ""
	if repo.Type == "yum" {
		if repo.YUM == nil {
			return "", errors.New("YUM sync selection requires package trust configuration")
		}
		_, packageKeyringSHA256, err = loadRPMPackageKeyring(cfg.Path, repo.YUM.PackageKeyring)
		if err != nil || !syncProgressSHA256Pattern.MatchString(packageKeyringSHA256) {
			return "", errors.Join(err, errors.New("invalid RPM package keyring identity for sync"))
		}
	}
	return syncSelectionSHA256WithTrust(cfg, repo, source, repositoryKeySHA256, upstreamKeyringSHA256, packageKeyringSHA256)
}

func syncSelectionSHA256WithTrust(cfg *config.Config, repo config.Repo, source config.Upstream, repositoryKeySHA256, upstreamKeyringSHA256, packageKeyringSHA256 string) (string, error) {
	if cfg == nil || repo.Type != source.Type || (repo.Type != "apt" && repo.Type != "yum") ||
		!syncProgressSHA256Pattern.MatchString(repositoryKeySHA256) || !syncProgressSHA256Pattern.MatchString(upstreamKeyringSHA256) ||
		(repo.Type == "apt" && packageKeyringSHA256 != "") || (repo.Type == "yum" && !syncProgressSHA256Pattern.MatchString(packageKeyringSHA256)) {
		return "", errors.New("invalid frozen sync trust identity set")
	}
	selection := syncProgressSelection{
		Repository:             repo,
		Upstream:               source,
		Beta:                   cfg.Views["beta"],
		Stable:                 cfg.Views["stable"],
		GPG:                    cfg.GPG,
		RepositoryKeySHA256:    repositoryKeySHA256,
		UpstreamKeyringSHA256:  upstreamKeyringSHA256,
		PackageKeyringSHA256:   packageKeyringSHA256,
		Serving:                cfg.Serving,
		APTByHashRetention:     cfg.State.APTByHashRetention,
		YUMGenerationRetention: cfg.State.YUMGenerationRetention,
	}
	data, err := json.Marshal(selection)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func reconcileSyncProgress(progress, wanted *syncProgress, _ bool) error {
	if progress.Upstream != wanted.Upstream || progress.Repository != wanted.Repository || progress.Format != wanted.Format {
		return errors.New("unfinished sync progress targets a different upstream repository contract")
	}
	if progress.ConfigSHA256 == wanted.ConfigSHA256 && progress.SelectionSHA256 == wanted.SelectionSHA256 {
		return nil
	}
	return errors.New("unfinished sync contract changed; recovery requires the exact original config, selector set, and repository signing key; --recover cannot rebind durable sync intent")
}

func advanceSyncProgress(progress *syncProgress, phase syncProgressPhase, commit, unit string, completed bool) {
	progress.Phase = phase
	if commit != "" {
		progress.ProvenanceCommit = commit
	}
	progress.CurrentUnit = unit
	if completed && unit != "" {
		index := sort.SearchStrings(progress.CompletedUnits, unit)
		if index == len(progress.CompletedUnits) || progress.CompletedUnits[index] != unit {
			progress.CompletedUnits = append(progress.CompletedUnits, "")
			copy(progress.CompletedUnits[index+1:], progress.CompletedUnits[index:])
			progress.CompletedUnits[index] = unit
		}
	}
	progress.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
}

func (p syncProgress) canonical() ([]byte, error) {
	if p.Schema != syncProgressSchema || !syncProgressNamePattern.MatchString(p.Upstream) || !syncProgressNamePattern.MatchString(p.Repository) ||
		(p.Format != "apt" && p.Format != "yum") || !syncProgressSHA256Pattern.MatchString(p.ConfigSHA256) || !syncProgressSHA256Pattern.MatchString(p.SelectionSHA256) ||
		!syncProgressSHA256Pattern.MatchString(p.ReplaySHA256) || p.ReplayCount < 0 || p.ReplayCount > syncReplayMaxRecords || !syncProgressSHA256Pattern.MatchString(p.ProvenanceInputSHA256) {
		return nil, errors.New("invalid sync progress identity")
	}
	switch p.Phase {
	case syncPhasePrepared:
		if p.ProvenanceCommit != "" || p.ProvenanceTransaction != "" || p.CurrentUnit != "" || len(p.CompletedUnits) != 0 {
			return nil, errors.New("prepared sync phase cannot contain canonical transaction or projection progress")
		}
	case syncPhaseProvenanceCommitting:
		if !syncProgressTxPattern.MatchString(p.ProvenanceTransaction) || p.ProvenanceCommit != "" || p.CurrentUnit != "" || len(p.CompletedUnits) != 0 {
			return nil, errors.New("committing sync phase requires only a provenance transaction ID")
		}
	case syncPhaseProvenanceCommitted, syncPhaseIngesting, syncPhaseProjectionRepair:
		if !syncProgressGitPattern.MatchString(p.ProvenanceCommit) {
			return nil, errors.New("committed sync phase requires a provenance commit")
		}
	default:
		return nil, errors.New("invalid sync progress phase")
	}
	if p.ProvenanceTransaction != "" && !syncProgressTxPattern.MatchString(p.ProvenanceTransaction) {
		return nil, errors.New("invalid sync provenance transaction ID")
	}
	if !safeSyncProgressUnit(p.CurrentUnit) {
		return nil, errors.New("invalid sync progress current unit")
	}
	created, err := canonicalSyncProgressTime(p.CreatedAt)
	if err != nil {
		return nil, errors.New("invalid sync progress creation time")
	}
	updated, err := canonicalSyncProgressTime(p.UpdatedAt)
	if err != nil || updated.Before(created) {
		return nil, errors.New("invalid sync progress update time")
	}
	p.CompletedUnits = append([]string(nil), p.CompletedUnits...)
	sort.Strings(p.CompletedUnits)
	for index, unit := range p.CompletedUnits {
		if !safeSyncProgressUnit(unit) || unit == "" || (index > 0 && p.CompletedUnits[index-1] == unit) {
			return nil, errors.New("invalid sync progress completed unit set")
		}
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(data) > syncProgressMaxBytes {
		return nil, errors.New("sync progress exceeds safety limit")
	}
	return data, nil
}

func decodeSyncProgress(data []byte) (syncProgress, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var progress syncProgress
	if err := decoder.Decode(&progress); err != nil {
		return syncProgress{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return syncProgress{}, errors.New("sync progress contains multiple JSON values")
		}
		return syncProgress{}, err
	}
	canonical, err := progress.canonical()
	if err != nil {
		return syncProgress{}, err
	}
	if !bytes.Equal(data, canonical) {
		return syncProgress{}, errors.New("sync progress is not canonical JSON")
	}
	return progress, nil
}

func canonicalSyncProgressTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("timestamp is not canonical UTC")
	}
	return parsed, nil
}

func safeSyncProgressUnit(value string) bool {
	return len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n\t")
}

func syncPartialCommitError(source config.Upstream, progress *syncProgress, cause error) error {
	phase, commit, unit := syncPhasePrepared, "unknown", ""
	if progress != nil {
		phase = progress.Phase
		if progress.ProvenanceCommit != "" {
			commit = progress.ProvenanceCommit
		}
		unit = progress.CurrentUnit
	}
	unitEvidence := ""
	if unit != "" {
		unitEvidence = " unit=" + unit
	}
	message := fmt.Errorf(
		"sync upstream=%s has durable_partial_commit=true provenance_commit=%s phase=%s%s; retry_action=\"rerun the same sow sync command for --upstream=%s with identical --config, selectors, and signing options; add --recover only if a stale state lock or canonical transaction is reported\": %v",
		source.ID, commit, phase, unitEvidence, source.ID, cause)
	return &exitError{code: exitCode(cause), err: &durableSyncPartialError{err: message}}
}

func isSyncPartialCommitError(err error) bool {
	var partial *durableSyncPartialError
	return errors.As(err, &partial)
}
