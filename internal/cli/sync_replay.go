package cli

import (
	"bufio"
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
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/syncer"
	"github.com/pgsty/sow/internal/upstream"
	"github.com/pgsty/sow/internal/views"
)

const (
	syncReplayFilename       = "replay.jsonl"
	syncReplayMaxRecordBytes = 4096
	syncReplayMaxRecords     = 10_000_000
	emptySyncReplaySHA256    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var syncDownloadResiduePattern = regexp.MustCompile(`^[0-9a-f]{64}\.(?:download|part|lock)$`)

// syncReplayRecord is the frozen O(change-set) package handoff needed after a
// provenance commit. It omits the upstream URL but retains the exact canonical
// view coordinate, so recovery cannot confuse a component/path move with an
// already-present copy of the same digest.
type syncReplayRecord struct {
	Format    string `json:"format"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Arch      string `json:"arch"`
	DebugInfo bool   `json:"debug_info"`
	Basename  string `json:"basename"`
	Component string `json:"component,omitempty"`
}

type syncProvenanceEvidenceIdentity struct {
	Kind     string `json:"kind"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Verified bool   `json:"verified"`
}

func syncProvenanceInputSHA256(discovery *upstream.Discovery, replaySHA string, replayCount int64) (string, error) {
	if discovery == nil || (discovery.Format != "deb" && discovery.Format != "rpm") || !syncProgressSHA256Pattern.MatchString(replaySHA) || replayCount < 0 {
		return "", errors.New("invalid sync provenance input identity")
	}
	evidence := make([]syncProvenanceEvidenceIdentity, 0, len(discovery.Evidence))
	for _, item := range discovery.Evidence {
		if item.Kind == "" || !syncProgressSHA256Pattern.MatchString(item.SHA256) || item.Size < 0 || strings.ContainsAny(item.Kind, "\x00\t\r\n") {
			return "", errors.New("invalid sync provenance evidence identity")
		}
		evidence = append(evidence, syncProvenanceEvidenceIdentity{Kind: item.Kind, SHA256: item.SHA256, Size: item.Size, Verified: item.Verified})
	}
	sort.Slice(evidence, func(i, j int) bool {
		left := evidence[i].Kind + "\x00" + evidence[i].SHA256
		right := evidence[j].Kind + "\x00" + evidence[j].SHA256
		if left != right {
			return left < right
		}
		if evidence[i].Size != evidence[j].Size {
			return evidence[i].Size < evidence[j].Size
		}
		return !evidence[i].Verified && evidence[j].Verified
	})
	for index := 1; index < len(evidence); index++ {
		if evidence[index] == evidence[index-1] {
			return "", errors.New("duplicate sync provenance evidence identity")
		}
	}
	payload, err := json.Marshal(struct {
		Format      string                           `json:"format"`
		ReplaySHA   string                           `json:"replay_sha256"`
		ReplayCount int64                            `json:"replay_count"`
		Evidence    []syncProvenanceEvidenceIdentity `json:"evidence"`
	}{Format: discovery.Format, ReplaySHA: replaySHA, ReplayCount: replayCount, Evidence: evidence})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func (record syncReplayRecord) Validate() error {
	if record.Format != "deb" && record.Format != "rpm" {
		return errors.New("sync replay format must be deb or rpm")
	}
	if !syncProgressSHA256Pattern.MatchString(record.SHA256) || record.Size < 0 ||
		record.Name == "" || record.Version == "" || record.Arch == "" ||
		len(record.Name) > 1024 || len(record.Version) > 1024 || len(record.Arch) > 128 ||
		strings.ContainsAny(record.Name+record.Version+record.Arch, "\x00\t\r\n") {
		return errors.New("invalid sync replay package identity")
	}
	if record.Basename == "" || len(record.Basename) > 1024 || record.Basename != path.Base(record.Basename) || strings.ContainsAny(record.Basename, "/\\%?#\x00\t\r\n") ||
		!strings.HasSuffix(strings.ToLower(record.Basename), "."+record.Format) {
		return errors.New("invalid sync replay package basename")
	}
	if record.Format == "deb" {
		if record.Component == "" || len(record.Component) > 256 || strings.ContainsAny(record.Component, "/\\%?#\x00\t\r\n") {
			return errors.New("invalid sync replay APT component")
		}
	} else if record.Component != "" {
		return errors.New("RPM sync replay cannot carry an APT component")
	}
	return nil
}

func buildSyncReplayRecords(repo config.Repo, source config.Upstream, journal *syncJournal, missing []syncer.Candidate) ([]syncReplayRecord, error) {
	records := make(map[string]syncReplayRecord, len(missing))
	add := func(candidate syncer.Candidate) error {
		basename, err := syncCandidateBasename(candidate)
		if err != nil {
			return err
		}
		record := syncReplayRecord{
			Format: candidate.Format, SHA256: candidate.SHA256, Size: candidate.Size,
			Name: candidate.Name, Version: candidate.Version, Arch: candidate.Arch,
			DebugInfo: candidate.DebugInfo, Basename: basename,
		}
		if candidate.Format == "deb" {
			record.Component, err = syncCandidateComponent(candidate, repo, source)
			if err != nil {
				return err
			}
		}
		if err := record.Validate(); err != nil {
			return err
		}
		if prior, exists := records[record.SHA256]; exists && prior != record {
			return fmt.Errorf("conflicting sync replay identity for %s", record.SHA256)
		}
		records[record.SHA256] = record
		return nil
	}
	if err := journal.ForEach(func(record syncJournalRecord) error {
		if record.Downloaded == nil {
			return nil
		}
		return add(record.Downloaded.Candidate)
	}); err != nil {
		return nil, err
	}
	for _, candidate := range missing {
		if err := add(candidate); err != nil {
			return nil, err
		}
	}
	result := make([]syncReplayRecord, 0, len(records))
	for _, record := range records {
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SHA256 < result[j].SHA256 })
	return result, nil
}

// WriteReplay atomically seals the frozen change set. When expected identity is
// supplied by prepared progress, a fresh discovery may only reproduce the same
// bytes; it cannot rebind an interrupted operation to changed upstream state.
func (o *syncOperation) WriteReplay(records []syncReplayRecord, expectedSHA string, expectedCount int64) (string, int64, error) {
	if o == nil || o.root == nil {
		return "", 0, errors.New("sync replay store is unavailable")
	}
	if len(records) > syncReplayMaxRecords {
		return "", 0, errors.New("sync replay change set exceeds safety limit")
	}
	tmp, tmpName, err := createSyncRootTemp(o.root, ".replay-")
	if err != nil {
		return "", 0, err
	}
	defer o.root.Remove(tmpName)
	hasher := sha256.New()
	writer := bufio.NewWriterSize(io.MultiWriter(tmp, hasher), 64<<10)
	for index, record := range records {
		if err := record.Validate(); err != nil {
			_ = tmp.Close()
			return "", 0, fmt.Errorf("sync replay record %d: %w", index, err)
		}
		if index > 0 && records[index-1].SHA256 >= record.SHA256 {
			_ = tmp.Close()
			return "", 0, errors.New("sync replay records must be strictly SHA256 sorted")
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			_ = tmp.Close()
			return "", 0, err
		}
		if len(encoded)+1 > syncReplayMaxRecordBytes {
			_ = tmp.Close()
			return "", 0, fmt.Errorf("sync replay record %d exceeds safety limit", index)
		}
		if _, err := writer.Write(encoded); err != nil {
			_ = tmp.Close()
			return "", 0, err
		}
		if err := writer.WriteByte('\n'); err != nil {
			_ = tmp.Close()
			return "", 0, err
		}
	}
	if err := writer.Flush(); err != nil {
		_ = tmp.Close()
		return "", 0, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", 0, err
	}
	if err := tmp.Close(); err != nil {
		return "", 0, err
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	count := int64(len(records))
	if expectedSHA != "" && (digest != expectedSHA || count != expectedCount) {
		return "", 0, errors.New("upstream change set differs from prepared durable sync intent")
	}
	if info, err := o.root.Lstat(syncReplayFilename); err == nil {
		if !privateRegularFile(info) {
			return "", 0, errors.New("refusing to replace unsafe sync replay file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", 0, err
	}
	if err := o.root.Rename(tmpName, syncReplayFilename); err != nil {
		return "", 0, err
	}
	if err := syncRootDirectory(o.root); err != nil {
		return "", 0, err
	}
	return digest, count, nil
}

func (o *syncOperation) ValidateReplay(progress *syncProgress) error {
	if progress == nil || !syncProgressSHA256Pattern.MatchString(progress.ReplaySHA256) || progress.ReplayCount < 0 || progress.ReplayCount > syncReplayMaxRecords {
		return errors.New("invalid sync replay identity in progress")
	}
	return o.readReplayPass(progress, nil)
}

// ForEachReplay validates the whole sealed file before invoking fn, preventing
// a late digest/count mismatch from causing partial recovery side effects.
func (o *syncOperation) ForEachReplay(progress *syncProgress, fn func(syncReplayRecord) error) error {
	if fn == nil {
		return errors.New("sync replay callback is required")
	}
	if err := o.ValidateReplay(progress); err != nil {
		return err
	}
	return o.readReplayPass(progress, fn)
}

func (o *syncOperation) readReplayPass(progress *syncProgress, fn func(syncReplayRecord) error) error {
	file, info, err := o.openPrivateFile(syncReplayFilename)
	if err != nil {
		return err
	}
	defer file.Close()
	if progress.ReplayCount == 0 && info.Size() != 0 {
		return errors.New("empty sync replay has non-empty file")
	}
	if progress.ReplayCount > 0 && info.Size() > progress.ReplayCount*syncReplayMaxRecordBytes {
		return errors.New("sync replay file exceeds per-record safety limit")
	}
	hasher := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(file, hasher))
	scanner.Buffer(make([]byte, 4096), syncReplayMaxRecordBytes)
	var count int64
	prior := ""
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line)+1 > syncReplayMaxRecordBytes {
			return errors.New("sync replay record exceeds safety limit")
		}
		record, err := decodeSyncReplayRecord(line)
		if err != nil {
			return err
		}
		if prior != "" && prior >= record.SHA256 {
			return errors.New("sync replay records are not strictly SHA256 sorted")
		}
		prior = record.SHA256
		count++
		if count > progress.ReplayCount || count > syncReplayMaxRecords {
			return errors.New("sync replay record count exceeds durable identity")
		}
		if fn != nil {
			if err := fn(record); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if count != progress.ReplayCount || hex.EncodeToString(hasher.Sum(nil)) != progress.ReplaySHA256 {
		return errors.New("sync replay digest or record count mismatch")
	}
	return nil
}

func decodeSyncReplayRecord(data []byte) (syncReplayRecord, error) {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var record syncReplayRecord
	if err := decoder.Decode(&record); err != nil {
		return syncReplayRecord{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return syncReplayRecord{}, errors.New("sync replay line contains multiple JSON values")
		}
		return syncReplayRecord{}, err
	}
	if err := record.Validate(); err != nil {
		return syncReplayRecord{}, err
	}
	canonical, err := json.Marshal(record)
	if err != nil {
		return syncReplayRecord{}, err
	}
	if !bytes.Equal(data, canonical) {
		return syncReplayRecord{}, errors.New("sync replay record is not canonical JSON")
	}
	return record, nil
}

func (o *syncOperation) openPrivateFile(name string) (*os.File, os.FileInfo, error) {
	if o == nil || o.root == nil {
		return nil, nil, errors.New("sync operation is closed")
	}
	info, err := o.root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !privateRegularFile(info) {
		return nil, nil, errors.New("sync operation file must be a private regular file")
	}
	file, err := o.root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	opened, statErr := file.Stat()
	current, lstatErr := o.root.Lstat(name)
	if statErr != nil || lstatErr != nil || !privateRegularFile(opened) || !privateRegularFile(current) || !os.SameFile(opened, current) {
		_ = file.Close()
		return nil, nil, errors.Join(statErr, lstatErr, errors.New("sync operation file changed while opening"))
	}
	return file, opened, nil
}

func (o *syncOperation) RemoveReplay() error {
	if o == nil || o.root == nil {
		return errors.New("sync replay store is unavailable")
	}
	info, err := o.root.Lstat(syncReplayFilename)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !privateRegularFile(info) {
		return errors.New("refusing to remove unsafe sync replay file")
	}
	if err := o.root.Remove(syncReplayFilename); err != nil {
		return err
	}
	return syncRootDirectory(o.root)
}

// RemoveReplayDownloads removes all recognized transport residue only after
// the frozen change set has been committed to canonical views and CAS. A
// prior failed run may have downloaded a package that disappeared upstream,
// so limiting cleanup to the current replay would leak untracked duplicate
// bodies forever. The per-upstream operation lock excludes concurrent readers;
// interrupted operations deliberately retain these files until convergence.
func (o *syncOperation) RemoveReplayDownloads(progress *syncProgress) error {
	if o == nil || o.root == nil {
		return errors.New("sync replay store is unavailable")
	}
	if err := o.ValidateReplay(progress); err != nil {
		return err
	}
	if info, err := o.root.Lstat("downloads"); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to clean unsafe sync download directory")
	}
	directory, err := o.root.Open("downloads")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	if readErr != nil {
		_ = directory.Close()
		return readErr
	}
	for _, entry := range entries {
		if !syncDownloadResiduePattern.MatchString(entry.Name()) {
			_ = directory.Close()
			return fmt.Errorf("refusing to ignore unknown sync download residue %s", entry.Name())
		}
		name := filepath.ToSlash(filepath.Join("downloads", entry.Name()))
		info, err := o.root.Lstat(name)
		if err != nil {
			_ = directory.Close()
			return err
		}
		if !privateRegularFile(info) {
			_ = directory.Close()
			return fmt.Errorf("refusing to remove unsafe sync download file %s", entry.Name())
		}
		if err := o.root.Remove(name); err != nil {
			_ = directory.Close()
			return err
		}
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func createSyncRootTemp(root *os.Root, prefix string) (*os.File, string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		var nameBytes [16]byte
		if _, err := rand.Read(nameBytes[:]); err != nil {
			return nil, "", err
		}
		name := prefix + hex.EncodeToString(nameBytes[:])
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("could not allocate sync operation temporary file")
}

func missingSyncReplayRecords(canonical *state.Store, repo config.Repo, source config.Upstream, operation *syncOperation, progress *syncProgress) ([]syncReplayRecord, error) {
	type need struct {
		record     syncReplayRecord
		view       string
		leafArches []string
		required   int
		found      int
	}
	wanted := make(map[string]*need)
	if err := operation.ForEachReplay(progress, func(record syncReplayRecord) error {
		leafArches := []string{record.Arch}
		if repo.Type == "yum" {
			leafArches = rpmLeafArches(repo, record.Arch, source.Arches)
		} else if record.Arch == "all" {
			leafArches = append([]string(nil), source.Arches...)
		}
		if len(leafArches) == 0 {
			return fmt.Errorf("replay %s package architecture %s has no selected target leaf", record.Format, record.Arch)
		}
		wanted[record.SHA256] = &need{record: record, view: packageDestinationView(repo, record.DebugInfo), leafArches: leafArches, required: len(leafArches)}
		return nil
	}); err != nil {
		return nil, err
	}
	if len(wanted) == 0 {
		return nil, nil
	}
	oses := []string{"el" + fmt.Sprint(repo.OS.Major)}
	if repo.Type == "apt" {
		oses = []string{source.Suite}
	}
scan:
	for _, viewName := range []string{"beta", "stable"} {
		for _, osName := range oses {
			for _, arch := range source.Arches {
				if len(wanted) == 0 {
					break scan
				}
				ref, err := state.ViewRef(viewName, repo.ID, osName, arch)
				if err != nil {
					return nil, err
				}
				commit, exists, err := canonical.Ref(ref)
				if err != nil {
					return nil, err
				}
				if !exists {
					continue
				}
				viewPath, err := state.ViewPath(viewName, repo.ID, osName, arch)
				if err != nil {
					return nil, err
				}
				reader, err := canonical.OpenPathAt(commit, viewPath)
				if err != nil {
					return nil, err
				}
				viewReader := views.NewReader(reader)
				for {
					entry, err := viewReader.Next()
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						reader.Close()
						return nil, err
					}
					if candidate := wanted[entry.SHA256]; candidate != nil && candidate.view == viewName &&
						contains(candidate.leafArches, arch) &&
						entry.Name == candidate.record.Name && entry.Version == candidate.record.Version && entry.Size == candidate.record.Size &&
						entry.Pool == repo.DefaultPool && entry.DebugInfo == candidate.record.DebugInfo &&
						path.Base(entry.Path) == candidate.record.Basename &&
						(repo.Type != "apt" || aptViewEntryComponent(entry.Path, repo, source.Suite) == candidate.record.Component) {
						candidate.found++
						if candidate.found >= candidate.required {
							delete(wanted, entry.SHA256)
						}
					}
				}
				if err := reader.Close(); err != nil {
					return nil, err
				}
			}
		}
	}
	result := make([]syncReplayRecord, 0, len(wanted))
	for _, candidate := range wanted {
		result = append(result, candidate.record)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SHA256 < result[j].SHA256 })
	return result, nil
}

func stageSyncReplayInputs(ctx context.Context, txDir string, pool *repository.Store, operation *syncOperation, records []syncReplayRecord) (stagedSyncInputs, error) {
	result := stagedSyncInputs{
		paths:       make([]string, 0, len(records)),
		byComponent: make(map[string][]string),
		expected:    make(map[string]repository.Object),
	}
	for _, record := range records {
		digest, err := repository.ParseDigest(record.SHA256)
		if err != nil {
			return stagedSyncInputs{}, err
		}
		object := repository.Object{SHA256: digest, Size: record.Size}
		if err := pool.Verify(ctx, object); errors.Is(err, os.ErrNotExist) {
			cached := filepath.Join(operation.dir, "downloads", record.SHA256+".download")
			imported, importErr := pool.ImportExpected(ctx, cached, object)
			if importErr != nil {
				return stagedSyncInputs{}, fmt.Errorf("recover verified sync cache %s: %w", record.SHA256, importErr)
			}
			if imported.HashString() != record.SHA256 || imported.Size != record.Size {
				return stagedSyncInputs{}, fmt.Errorf("recovered sync cache %s differs from frozen replay identity", record.SHA256)
			}
		} else if err != nil {
			return stagedSyncInputs{}, fmt.Errorf("verify replay CAS object %s: %w", record.SHA256, err)
		}
		dir := filepath.Join(txDir, "inputs", record.SHA256[:16])
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return stagedSyncInputs{}, err
		}
		destination := filepath.Join(dir, record.Basename)
		if err := os.Link(pool.ObjectPath(digest), destination); err != nil {
			return stagedSyncInputs{}, fmt.Errorf("hardlink frozen sync replay input %s: %w", record.SHA256, err)
		}
		result.paths = append(result.paths, destination)
		result.expected[destination] = object
		if record.Format == "deb" {
			result.byComponent[record.Component] = append(result.byComponent[record.Component], destination)
		}
	}
	for component := range result.byComponent {
		sort.Strings(result.byComponent[component])
	}
	sort.Strings(result.paths)
	return result, nil
}
