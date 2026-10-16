package plain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
)

const rpmHistoryName = ".sow-plain-rpm-history.json"

type rpmSnapshot struct {
	RepomdSHA256 string   `json:"repomd_sha256"`
	Metadata     []string `json:"metadata"`
}

type rpmHistory struct {
	Version   int           `json:"version"`
	Snapshots []rpmSnapshot `json:"snapshots"`
}

// The retention list is bounded to [candidate, current, previous]. It is saved
// before the pointer switch so either side of an interrupted switch can find
// its predecessor by the actual repomd digest. It does not replay publication.
func prepareRPMRetention(ctx context.Context, root string, staged stagedBuild, plan *publicationPlan) error {
	historyBytes, historyExists, err := readRetentionFile(ctx, filepath.Join(root, rpmHistoryName), 4096)
	if err != nil {
		return err
	}
	if !staged.rpmPresent {
		plan.removeRPMHistory = historyExists
		plan.changed = plan.changed || historyExists
		return nil
	}
	history := decodeRPMHistory(historyBytes)
	current, err := readRPMSnapshot(ctx, filepath.Join(root, "repodata", "repomd.xml"))
	if err != nil {
		return err
	}
	next, err := readRPMSnapshot(ctx, filepath.Join(staged.dir, "repodata", "repomd.xml"))
	if err != nil {
		return err
	}
	if next == nil {
		return &Error{Kind: KindIntegrity, Op: "prepare rpm retention", Path: staged.dir, Err: errors.New("staged repomd has no canonical SOW references")}
	}
	var previous *rpmSnapshot
	matched := false
	if current != nil {
		for i, snapshot := range history.Snapshots {
			if snapshot.RepomdSHA256 == current.RepomdSHA256 && slices.Equal(snapshot.Metadata, current.Metadata) {
				matched = true
				if i+1 < len(history.Snapshots) {
					previous = &history.Snapshots[i+1]
				}
				break
			}
		}
	}
	retained := previous
	pointerChanges := current == nil || current.RepomdSHA256 != next.RepomdSHA256
	if pointerChanges {
		retained = current
	}
	keep := make(map[string]bool, 3)
	if retained != nil {
		for _, name := range retained.Metadata {
			path := filepath.Join(root, "repodata", name)
			if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err := validateGeneratedMetadataFile(path); err != nil {
				return err
			}
			digest, err := hashFile(ctx, path)
			if err != nil {
				return err
			}
			// A corrupt or missing historical object cannot serve an old reader.
			// Discard it instead of making derived-output repair fail closed.
			keep[name] = digest == name[:64]
		}
	}
	stale := plan.staleRPM[:0]
	for _, name := range plan.staleRPM {
		if !keep[name] {
			stale = append(stale, name)
		}
	}
	plan.staleRPM = stale
	plan.changed = plan.changed || len(stale) != 0
	if !pointerChanges && matched {
		return nil // Noop or cleanup must not advance the retained predecessor.
	}
	nextHistory := rpmHistory{Version: 1, Snapshots: []rpmSnapshot{*next}}
	if pointerChanges && current != nil {
		nextHistory.Snapshots = append(nextHistory.Snapshots, *current)
		if previous != nil {
			nextHistory.Snapshots = append(nextHistory.Snapshots, *previous)
		}
	}
	body, err := json.Marshal(nextHistory)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(staged.dir, rpmHistoryName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "stage rpm retention", Path: staged.dir, Err: err}
	}
	if err := file.Chmod(0o644); err != nil {
		_ = file.Close()
		return &Error{Kind: KindRuntime, Op: "stage rpm retention", Path: staged.dir, Err: err}
	}
	_, writeErr := file.Write(append(body, '\n'))
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return &Error{Kind: KindRuntime, Op: "stage rpm retention", Path: staged.dir, Err: err}
	}
	plan.rpmHistory = true
	plan.changed = true
	return nil
}

func decodeRPMHistory(body []byte) rpmHistory {
	var history rpmHistory
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&history); err != nil || history.Version != 1 || len(history.Snapshots) < 1 || len(history.Snapshots) > 3 {
		return rpmHistory{}
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return rpmHistory{}
	}
	for _, snapshot := range history.Snapshots {
		if !validSHA256(snapshot.RepomdSHA256) || len(snapshot.Metadata) != 3 {
			return rpmHistory{}
		}
		for i, kind := range []string{"primary", "filelists", "other"} {
			name := snapshot.Metadata[i]
			if len(name) != 64+len("-"+kind+".xml.gz") || !validSHA256(name[:64]) || name[64:] != "-"+kind+".xml.gz" {
				return rpmHistory{}
			}
		}
	}
	return history
}

// Only reference shape and compressed object identities matter for retention.
// Malformed old metadata is replaceable; it is not a precondition for rebuilding.
func readRPMSnapshot(ctx context.Context, path string) (*rpmSnapshot, error) {
	body, _, err := readRetentionFile(ctx, path, 4<<20)
	if err != nil || len(body) == 0 {
		return nil, err
	}
	var document struct {
		XMLName xml.Name `xml:"repomd"`
		Data    []struct {
			Type     string `xml:"type,attr"`
			Checksum struct {
				Type  string `xml:"type,attr"`
				Value string `xml:",chardata"`
			} `xml:"checksum"`
			Location struct {
				Href string `xml:"href,attr"`
			} `xml:"location"`
		} `xml:"data"`
	}
	if err := xml.Unmarshal(body, &document); err != nil || document.XMLName.Space != "http://linux.duke.edu/metadata/repo" || len(document.Data) != 3 {
		return nil, nil
	}
	byType := make(map[string]string, 3)
	for _, record := range document.Data {
		name := record.Checksum.Value + "-" + record.Type + ".xml.gz"
		if record.Checksum.Type != "sha256" || !isSOWRPMMetadataName(name) || record.Location.Href != "repodata/"+name || byType[record.Type] != "" {
			return nil, nil
		}
		byType[record.Type] = name
	}
	snapshot := &rpmSnapshot{}
	for _, kind := range []string{"primary", "filelists", "other"} {
		if byType[kind] == "" {
			return nil, nil
		}
		snapshot.Metadata = append(snapshot.Metadata, byType[kind])
	}
	sum := sha256.Sum256(body)
	snapshot.RepomdSHA256 = hex.EncodeToString(sum[:])
	return snapshot, nil
}

// Oversize/malformed regular files are treated as unavailable history. Unsafe
// filesystem types and I/O failures remain errors, including for unused history.
func readRetentionFile(ctx context.Context, path string, maximum int64) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, true, &Error{Kind: KindIntegrity, Op: "read rpm retention", Path: path, Err: errors.Join(err, errors.New("path is not a regular file"))}
	}
	if info.Size() > maximum {
		return nil, true, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, true, &Error{Kind: KindRuntime, Op: "read rpm retention", Path: path, Err: err}
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, true, &Error{Kind: KindIntegrity, Op: "read rpm retention", Path: path, Err: errors.Join(statErr, errors.New("file changed while opening"))}
	}
	body, readErr := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: file}, maximum+1))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, true, &Error{Kind: KindRuntime, Op: "read rpm retention", Path: path, Err: err}
	}
	if int64(len(body)) > maximum {
		return nil, true, nil
	}
	return body, true, nil
}
