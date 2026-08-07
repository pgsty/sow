package managed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pgsty/sow/internal/v2/state"
	"golang.org/x/sys/unix"
)

const (
	retainedSchema            = "sow/retained/v1"
	retainedRecordDomain      = "sow/retained-record/v1"
	retainedRemovalSchema     = "sow/retain-remove/v1"
	payloadRefsetDomain       = "sow/payload-refset/v1"
	metadataRefsetDomain      = "sow/metadata-refset/v1"
	maxRetainedRecordBytes    = 16 << 10
	maxRetainedManifestBytes  = 64 << 20
	maxRetainedRemovalBytes   = 64 << 20
	maxRetainedRemovalEntries = 1 << 20
)

type RetainedRecord struct {
	Schema               string             `json:"schema"`
	RepositoryID         string             `json:"repository_id"`
	Generation           state.GenerationID `json:"generation"`
	ManifestSHA256       string             `json:"manifest_sha256"`
	PayloadRefsetSHA256  string             `json:"payload_refset_sha256"`
	MetadataRefsetSHA256 string             `json:"metadata_refset_sha256"`
	RendererIdentity     string             `json:"renderer_identity"`
	SignerIdentity       string             `json:"signer_identity"`
}

type RetainedGeneration struct {
	Repository     string         `json:"repository"`
	Record         RetainedRecord `json:"record"`
	RecordIdentity string         `json:"record_identity"`
	Path           string         `json:"path"`
}

type RetainListResult struct {
	Repository  string               `json:"repository"`
	Generations []RetainedGeneration `json:"generations"`
}

type RetainAddOptions struct {
	WorkspaceOptions
	LockOptions
	Repository string
	Generation state.GenerationID
	Fault      func(string) error
}

type RetainListOptions struct {
	WorkspaceOptions
	Repository string
}

type RetainVerifyOptions struct {
	WorkspaceOptions
	Repository string
	Generation state.GenerationID
}

type RetainRemoveOptions struct {
	WorkspaceOptions
	LockOptions
	Repository string
	Generation state.GenerationID
	Fault      func(string) error
}

type retainedRemovalEntry struct {
	Kind   string
	Path   string
	Size   int64
	SHA256 string
}

type retainedRemovalPlan struct {
	Schema         string
	RepositoryID   string
	Generation     state.GenerationID
	RecordIdentity string
	Entries        []retainedRemovalEntry
}

func canonicalRetainedRemovalPath(value string) bool {
	if value == "" || value == "." || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "../") ||
		strings.ContainsAny(value, "\\\x00\r\n\t") || filepath.ToSlash(filepath.Clean(filepath.FromSlash(value))) != value {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	_, err := rootedPathComponents(filepath.FromSlash(value), false)
	return err == nil
}

func validateRetainedRemovalPlan(plan retainedRemovalPlan) error {
	if plan.Schema != retainedRemovalSchema || !state.IsCanonicalRepositoryID(plan.RepositoryID) || plan.Generation == 0 ||
		!lowercaseSHA256.MatchString(plan.RecordIdentity) || len(plan.Entries) == 0 || len(plan.Entries) > maxRetainedRemovalEntries {
		return errors.New("invalid retained removal plan header")
	}
	directories := map[string]struct{}{}
	for index, entry := range plan.Entries {
		if !canonicalRetainedRemovalPath(entry.Path) || index > 0 && plan.Entries[index-1].Path >= entry.Path {
			return fmt.Errorf("invalid retained removal plan path at index %d", index)
		}
		switch entry.Kind {
		case "directory":
			if entry.Size != -1 || entry.SHA256 != "" {
				return fmt.Errorf("invalid retained removal directory at index %d", index)
			}
			directories[entry.Path] = struct{}{}
		case "file":
			if entry.Size < 0 || !lowercaseSHA256.MatchString(entry.SHA256) {
				return fmt.Errorf("invalid retained removal file at index %d", index)
			}
		default:
			return fmt.Errorf("invalid retained removal entry kind at index %d", index)
		}
	}
	for _, entry := range plan.Entries {
		for parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(entry.Path))); parent != "."; parent = filepath.ToSlash(filepath.Dir(filepath.FromSlash(parent))) {
			if _, exists := directories[parent]; !exists {
				return fmt.Errorf("retained removal entry %q lacks directory %q", entry.Path, parent)
			}
		}
	}
	required := map[string]string{"manifest.tsv": "file", "metadata": "directory", "record.json": "file"}
	for _, entry := range plan.Entries {
		if kind, exists := required[entry.Path]; exists && kind == entry.Kind {
			delete(required, entry.Path)
		}
	}
	if len(required) != 0 {
		return errors.New("retained removal plan lacks the retained/v1 root inventory")
	}
	return nil
}

func canonicalRetainedRemovalPlan(plan retainedRemovalPlan) ([]byte, error) {
	if err := validateRetainedRemovalPlan(plan); err != nil {
		return nil, err
	}
	var output strings.Builder
	output.WriteString(`{"entries":[`)
	for index, entry := range plan.Entries {
		if index != 0 {
			output.WriteByte(',')
		}
		output.WriteString(`{"kind":` + canonicalJSONString(entry.Kind))
		output.WriteString(`,"path":` + canonicalJSONString(entry.Path))
		output.WriteString(`,"sha256":`)
		if entry.Kind == "directory" {
			output.WriteString("null")
		} else {
			output.WriteString(canonicalJSONString(entry.SHA256))
		}
		output.WriteString(`,"size":`)
		if entry.Kind == "directory" {
			output.WriteString("null")
		} else {
			output.WriteString(canonicalJSONString(strconv.FormatInt(entry.Size, 10)))
		}
		output.WriteByte('}')
	}
	output.WriteString(`],"generation":` + canonicalJSONString(plan.Generation.String()))
	output.WriteString(`,"record_identity":` + canonicalJSONString(plan.RecordIdentity))
	output.WriteString(`,"repository_id":` + canonicalJSONString(plan.RepositoryID))
	output.WriteString(`,"schema":` + canonicalJSONString(plan.Schema))
	output.WriteByte('}')
	return []byte(output.String()), nil
}

func parseRetainedRemovalPlan(data []byte) (retainedRemovalPlan, []byte, error) {
	if len(data) == 0 || len(data) > maxRetainedRemovalBytes {
		return retainedRemovalPlan{}, nil, errors.New("retained removal plan is empty or unbounded")
	}
	if err := rejectDuplicateJSONMembers(data); err != nil {
		return retainedRemovalPlan{}, nil, err
	}
	type wireEntry struct {
		Kind   string  `json:"kind"`
		Path   string  `json:"path"`
		SHA256 *string `json:"sha256"`
		Size   *string `json:"size"`
	}
	type wirePlan struct {
		Entries        []wireEntry        `json:"entries"`
		Generation     state.GenerationID `json:"generation"`
		RecordIdentity string             `json:"record_identity"`
		RepositoryID   string             `json:"repository_id"`
		Schema         string             `json:"schema"`
	}
	var wire wirePlan
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return retainedRemovalPlan{}, nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return retainedRemovalPlan{}, nil, errors.New("retained removal plan has trailing content")
	}
	plan := retainedRemovalPlan{
		Schema: wire.Schema, RepositoryID: wire.RepositoryID, Generation: wire.Generation,
		RecordIdentity: wire.RecordIdentity, Entries: make([]retainedRemovalEntry, 0, len(wire.Entries)),
	}
	for index, entry := range wire.Entries {
		parsed := retainedRemovalEntry{Kind: entry.Kind, Path: entry.Path, Size: -1}
		switch entry.Kind {
		case "directory":
			if entry.SHA256 != nil || entry.Size != nil {
				return retainedRemovalPlan{}, nil, fmt.Errorf("retained removal directory %d has file identity", index)
			}
		case "file":
			if entry.SHA256 == nil || entry.Size == nil || *entry.Size == "" || len(*entry.Size) > 1 && (*entry.Size)[0] == '0' {
				return retainedRemovalPlan{}, nil, fmt.Errorf("retained removal file %d lacks canonical identity", index)
			}
			size, err := strconv.ParseInt(*entry.Size, 10, 64)
			if err != nil || size < 0 || strconv.FormatInt(size, 10) != *entry.Size {
				return retainedRemovalPlan{}, nil, fmt.Errorf("retained removal file %d size is outside int64", index)
			}
			parsed.Size, parsed.SHA256 = size, *entry.SHA256
		default:
			return retainedRemovalPlan{}, nil, fmt.Errorf("retained removal entry %d has an invalid kind", index)
		}
		plan.Entries = append(plan.Entries, parsed)
	}
	canonical, err := canonicalRetainedRemovalPlan(plan)
	if err != nil {
		return retainedRemovalPlan{}, nil, err
	}
	if !bytes.Equal(data, canonical) {
		return retainedRemovalPlan{}, nil, errors.New("retained removal plan is not RFC 8785 canonical JSON")
	}
	return plan, canonical, nil
}

func canonicalRetainedRecord(record RetainedRecord) ([]byte, error) {
	if record.Schema != retainedSchema || !state.IsCanonicalRepositoryID(record.RepositoryID) || record.Generation == 0 ||
		!lowercaseSHA256.MatchString(record.ManifestSHA256) || !lowercaseSHA256.MatchString(record.PayloadRefsetSHA256) ||
		!lowercaseSHA256.MatchString(record.MetadataRefsetSHA256) || !lowercaseSHA256.MatchString(record.RendererIdentity) ||
		(record.SignerIdentity != "none" && !lowercaseSHA256.MatchString(record.SignerIdentity)) {
		return nil, errors.New("managed: invalid retained record")
	}
	// RFC 8785 sorts these ASCII field names by code point.  Every value is a
	// string in v1, so encoding/json's JSON string primitive is sufficient and
	// no floating-point canonicalization surface exists.
	var output strings.Builder
	output.WriteByte('{')
	fields := [][2]string{
		{"generation", record.Generation.String()},
		{"manifest_sha256", record.ManifestSHA256},
		{"metadata_refset_sha256", record.MetadataRefsetSHA256},
		{"payload_refset_sha256", record.PayloadRefsetSHA256},
		{"renderer_identity", record.RendererIdentity},
		{"repository_id", record.RepositoryID},
		{"schema", record.Schema},
		{"signer_identity", record.SignerIdentity},
	}
	for index, field := range fields {
		if index != 0 {
			output.WriteByte(',')
		}
		output.WriteString(canonicalJSONString(field[0]))
		output.WriteByte(':')
		output.WriteString(canonicalJSONString(field[1]))
	}
	output.WriteByte('}')
	return []byte(output.String()), nil
}

func parseRetainedRecord(data []byte) (RetainedRecord, []byte, error) {
	if len(data) == 0 || len(data) > maxRetainedRecordBytes {
		return RetainedRecord{}, nil, errors.New("retained record is empty or unbounded")
	}
	if err := rejectDuplicateJSONMembers(data); err != nil {
		return RetainedRecord{}, nil, err
	}
	var record RetainedRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return RetainedRecord{}, nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return RetainedRecord{}, nil, errors.New("retained record has trailing content")
	}
	canonical, err := canonicalRetainedRecord(record)
	if err != nil {
		return RetainedRecord{}, nil, err
	}
	if !bytes.Equal(data, canonical) {
		return RetainedRecord{}, nil, errors.New("retained record is not RFC 8785 canonical JSON")
	}
	return record, canonical, nil
}

func domainDigest(domain string, content []byte) string {
	hash := sha256.New()
	io.WriteString(hash, domain)
	hash.Write([]byte{0})
	hash.Write(content)
	return hex.EncodeToString(hash.Sum(nil))
}

func retainedRefsets(files []state.GenerationFile) (string, string) {
	var payload, metadata bytes.Buffer
	for _, file := range files {
		line := fmt.Sprintf("%s %d %s %s\n", file.SHA256, file.Size, file.Phase, file.Path)
		if file.Phase == "payload" {
			payload.WriteString(line)
		} else {
			metadata.WriteString(line)
		}
	}
	return domainDigest(payloadRefsetDomain, payload.Bytes()), domainDigest(metadataRefsetDomain, metadata.Bytes())
}

func parseRetainedManifest(data []byte) ([]state.GenerationFile, error) {
	if len(data) > maxRetainedManifestBytes || len(data) != 0 && data[len(data)-1] != '\n' {
		return nil, errors.New("retained manifest is unbounded or lacks terminal LF")
	}
	files := []state.GenerationFile{}
	for _, raw := range bytes.Split(data, []byte{'\n'}) {
		if len(raw) == 0 {
			continue
		}
		parts := bytes.SplitN(raw, []byte{' '}, 4)
		if len(parts) != 4 {
			return nil, errors.New("retained manifest line has the wrong field count")
		}
		sizeText := string(parts[1])
		if sizeText == "" || len(sizeText) > 1 && sizeText[0] == '0' {
			return nil, errors.New("retained manifest size is not canonical decimal")
		}
		size, err := strconv.ParseInt(sizeText, 10, 64)
		if err != nil || size < 0 {
			return nil, errors.New("retained manifest size is outside int64")
		}
		files = append(files, state.GenerationFile{SHA256: string(parts[0]), Size: size, Phase: string(parts[2]), Path: string(parts[3])})
	}
	canonical, _, err := state.ManifestBytes(files)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, errors.New("retained manifest is not the canonical terminal manifest")
	}
	return files, nil
}

func AddRetainedGeneration(ctx context.Context, opts RetainAddOptions) (result RetainedGeneration, resultErr error) {
	if ctx == nil || opts.Generation == 0 {
		return result, fmt.Errorf("%w: retained Generation must be greater than zero", ErrRejected)
	}
	ws, _, rootGuard, err := workspace(opts.WorkspaceOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	_, _, repoName, workspaceLock, repoLock, err := acquireSelectedRepositoryLocks(ctx, ws, opts.Repository, opts.LockOptions)
	if err != nil {
		return result, err
	}
	result.Repository = repoName
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close(), repoLock.Close()) }()
	if err := validateRepositoryLayout(ws.Root, repoName); err != nil {
		return result, err
	}
	store, err := openExistingState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	if err := store.RequireTerminalLayout(ctx); err != nil {
		return result, err
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return result, err
	}
	if opts.Generation != summary.BuiltGeneration {
		return result, fmt.Errorf("%w: retained/v1 add requires the current Built Generation", ErrRejected)
	}
	manifest, err := store.GenerationManifest(ctx, opts.Generation)
	if err != nil {
		return result, err
	}
	manifestBytes, manifestSHA, err := state.ManifestBytes(manifest)
	if err != nil {
		return result, err
	}
	rendererIdentity, signerIdentity, err := store.GenerationRetentionIdentity(ctx, opts.Generation)
	if err != nil {
		return result, err
	}
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		return result, err
	}
	payloadRefset, metadataRefset := retainedRefsets(manifest)
	record := RetainedRecord{
		Schema: retainedSchema, RepositoryID: identity.RepositoryID, Generation: opts.Generation,
		ManifestSHA256: manifestSHA, PayloadRefsetSHA256: payloadRefset, MetadataRefsetSHA256: metadataRefset,
		RendererIdentity: rendererIdentity, SignerIdentity: signerIdentity,
	}
	recordBytes, err := canonicalRetainedRecord(record)
	if err != nil {
		return result, err
	}
	retainedRoot := filepath.Join(ws.Root, ".sow", repoName, "retained")
	target := filepath.Join(retainedRoot, opts.Generation.String())
	if _, err := os.Lstat(target); err == nil {
		return verifyRetainedGenerationLocked(ctx, ws.Root, repoName, opts.Generation, identity.RepositoryID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	stageOwner := filepath.Join(ws.Root, ".sow", repoName, "stage")
	stage := filepath.Join(stageOwner, "retain-"+opts.Generation.String())
	if _, err := os.Lstat(stage); err == nil {
		if err := removeOwnedDirectory(stage, stageOwner); err != nil {
			return result, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	if err := durableMkdir(stage, 0o700); err != nil {
		return result, err
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, removeOwnedDirectory(stage, stageOwner))
		}
	}()
	metadataRoot := filepath.Join(stage, "metadata")
	if err := durableMkdir(metadataRoot, 0o700); err != nil {
		return result, err
	}
	for _, file := range manifest {
		if file.Phase == "payload" {
			if err := verifyRetainedSource(ctx, filepath.Join(ws.Root, repoName), file); err != nil {
				return result, err
			}
			continue
		}
		targetRelative := filepath.Join("metadata", filepath.FromSlash(file.Path))
		if err := durableEnsureDirectoryTree(stage, filepath.Join(stage, filepath.Dir(targetRelative)), 0o700); err != nil {
			return result, err
		}
		if err := copyRetainedMetadata(ctx, filepath.Join(ws.Root, repoName), file, stage, targetRelative); err != nil {
			return result, err
		}
	}
	if err := writeRootedNewRegular(stage, "manifest.tsv", manifestBytes, 0o600); err != nil {
		return result, err
	}
	if err := writeRootedNewRegular(stage, "record.json", recordBytes, 0o600); err != nil {
		return result, err
	}
	if err := syncTree(stage); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "retain.staged"); err != nil {
		return result, err
	}
	privateRoot := filepath.Join(ws.Root, ".sow", repoName)
	if err := durableRename(privateRoot, stage, target); err != nil {
		return result, err
	}
	committed = true
	if err := syncDir(retainedRoot); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "retain.committed"); err != nil {
		return result, err
	}
	return verifyRetainedGenerationLocked(ctx, ws.Root, repoName, opts.Generation, identity.RepositoryID)
}

func RetainAdd(ctx context.Context, opts RetainAddOptions) (RetainedGeneration, error) {
	return AddRetainedGeneration(ctx, opts)
}

func VerifyRetainedGeneration(ctx context.Context, opts RetainVerifyOptions) (result RetainedGeneration, resultErr error) {
	if ctx == nil || opts.Generation == 0 {
		return result, fmt.Errorf("%w: retained Generation must be greater than zero", ErrRejected)
	}
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts.WorkspaceOptions, true)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	repoName, err := selectRepo(ws, cfg, opts.Repository)
	if err != nil {
		return result, err
	}
	store, repoLock, err := openReadRepository(ctx, ws.Root, repoName)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close(), store.Close()) }()
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		return result, err
	}
	return verifyRetainedGenerationLocked(ctx, ws.Root, repoName, opts.Generation, identity.RepositoryID)
}

func verifyRetainedGenerationLocked(ctx context.Context, root, repoName string, generation state.GenerationID, repositoryID string) (RetainedGeneration, error) {
	directory := filepath.Join(root, ".sow", repoName, "retained", generation.String())
	return verifyRetainedGenerationDirectory(ctx, root, repoName, generation, repositoryID, directory)
}

func verifyRetainedGenerationDirectory(ctx context.Context, root, repoName string, generation state.GenerationID, repositoryID, directory string) (RetainedGeneration, error) {
	entries, err := listRootedDirectory(directory)
	if err != nil {
		return RetainedGeneration{}, fmt.Errorf("%w: retained Generation directory is missing or unsafe: %v", ErrIntegrity, err)
	}
	recordData, err := readRootedPrivateRegular(directory, "record.json", maxRetainedRecordBytes, false)
	if err != nil {
		return RetainedGeneration{}, err
	}
	record, canonical, err := parseRetainedRecord(recordData)
	if err != nil || record.RepositoryID != repositoryID || record.Generation != generation {
		return RetainedGeneration{}, fmt.Errorf("%w: retained record identity differs from directory/repository: %v", ErrIntegrity, err)
	}
	manifestData, err := readRootedPrivateRegular(directory, "manifest.tsv", maxRetainedManifestBytes, true)
	if err != nil {
		return RetainedGeneration{}, err
	}
	manifest, err := parseRetainedManifest(manifestData)
	if err != nil || bytesSHA(manifestData) != record.ManifestSHA256 {
		return RetainedGeneration{}, fmt.Errorf("%w: retained manifest differs from record: %v", ErrIntegrity, err)
	}
	payloadRefset, metadataRefset := retainedRefsets(manifest)
	if payloadRefset != record.PayloadRefsetSHA256 || metadataRefset != record.MetadataRefsetSHA256 {
		return RetainedGeneration{}, fmt.Errorf("%w: retained refset digest differs from manifest", ErrIntegrity)
	}
	expectedMetadata := map[string]state.GenerationFile{}
	for _, file := range manifest {
		if file.Phase == "payload" {
			if err := verifyRetainedSource(ctx, filepath.Join(root, repoName), file); err != nil {
				return RetainedGeneration{}, err
			}
		} else {
			expectedMetadata[file.Path] = file
			if err := verifyRetainedSource(ctx, filepath.Join(directory, "metadata"), file); err != nil {
				return RetainedGeneration{}, err
			}
		}
	}
	actualMetadata, err := listRetainedMetadata(filepath.Join(directory, "metadata"))
	if err != nil || len(actualMetadata) != len(expectedMetadata) {
		return RetainedGeneration{}, fmt.Errorf("%w: retained metadata inventory differs: %v", ErrIntegrity, err)
	}
	for _, path := range actualMetadata {
		if _, exists := expectedMetadata[path]; !exists {
			return RetainedGeneration{}, fmt.Errorf("%w: unexpected retained metadata path %q", ErrIntegrity, path)
		}
	}
	if len(entries) != 3 || entries[0].Name != "manifest.tsv" || uint32(entries[0].Stat.Mode)&unix.S_IFMT != unix.S_IFREG ||
		entries[1].Name != "metadata" || uint32(entries[1].Stat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		entries[2].Name != "record.json" || uint32(entries[2].Stat.Mode)&unix.S_IFMT != unix.S_IFREG {
		return RetainedGeneration{}, fmt.Errorf("%w: retained directory has an unexpected top-level entry", ErrIntegrity)
	}
	return RetainedGeneration{Repository: repoName, Record: record, RecordIdentity: domainDigest(retainedRecordDomain, canonical), Path: directory}, nil
}

func verifyRetainedSource(ctx context.Context, root string, file state.GenerationFile) error {
	opened, err := openRootedRegular(root, filepath.FromSlash(file.Path))
	if err != nil {
		return fmt.Errorf("%w: retained source %q is missing or unsafe: %v", ErrIntegrity, file.Path, err)
	}
	hash := sha256.New()
	count, copyErr := io.Copy(hash, &retainedContextReader{ctx: ctx, reader: opened.file})
	closeErr := opened.CloseVerified()
	if err := errors.Join(copyErr, closeErr); err != nil || count != file.Size || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
		return fmt.Errorf("%w: retained source %q differs from manifest: %v", ErrIntegrity, file.Path, err)
	}
	return nil
}

func copyRetainedMetadata(ctx context.Context, sourceRoot string, file state.GenerationFile, targetRoot, targetRelative string) error {
	opened, err := openRootedRegular(sourceRoot, filepath.FromSlash(file.Path))
	if err != nil {
		return err
	}
	destination, err := createRootedRegular(targetRoot, targetRelative, 0o600)
	if err != nil {
		return errors.Join(err, opened.CloseVerified())
	}
	committed := false
	defer func() {
		if !committed {
			_ = destination.Abort()
		}
	}()
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(destination.file, hash), &retainedContextReader{ctx: ctx, reader: opened.file})
	result := errors.Join(copyErr, opened.CloseVerified())
	if result != nil || count != file.Size || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
		return errors.Join(result, fmt.Errorf("retained metadata %q changed while copying", file.Path))
	}
	if err := destination.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func writeRootedNewRegular(root, relative string, data []byte, mode os.FileMode) error {
	created, err := createRootedRegular(root, relative, mode)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = created.Abort()
		}
	}()
	written, err := created.file.Write(data)
	if err != nil || written != len(data) {
		return errors.Join(err, io.ErrShortWrite)
	}
	if err := created.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func listRetainedMetadata(root string) ([]string, error) {
	paths := []string{}
	err := walkRootedTree(context.Background(), root, func(relative string, _ *os.File, _ os.FileInfo) error {
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	}, nil)
	sort.Strings(paths)
	return paths, err
}

func retainedRemovalInventory(ctx context.Context, root string) ([]retainedRemovalEntry, error) {
	entries := make([]retainedRemovalEntry, 0)
	appendEntry := func(entry retainedRemovalEntry) error {
		if len(entries) >= maxRetainedRemovalEntries {
			return errors.New("retained removal inventory exceeds its entry bound")
		}
		entries = append(entries, entry)
		return nil
	}
	err := walkRootedTree(ctx, root, func(relative string, file *os.File, info os.FileInfo) error {
		digest, err := hashRegularDescriptor(ctx, file)
		if err != nil {
			return err
		}
		return appendEntry(retainedRemovalEntry{Kind: "file", Path: filepath.ToSlash(relative), Size: info.Size(), SHA256: digest})
	}, func(relative string, _ *os.File, _ os.FileInfo) error {
		if relative == "" {
			return nil
		}
		return appendEntry(retainedRemovalEntry{Kind: "directory", Path: filepath.ToSlash(relative), Size: -1})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

func sameRetainedRemovalEntry(left, right retainedRemovalEntry) bool {
	return left.Kind == right.Kind && left.Path == right.Path && left.Size == right.Size && left.SHA256 == right.SHA256
}

func sameRetainedRemovalInventory(left, right []retainedRemovalEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !sameRetainedRemovalEntry(left[index], right[index]) {
			return false
		}
	}
	return true
}

func validateRetainedRemovalRemainder(ctx context.Context, root string, plan retainedRemovalPlan) error {
	actual, err := retainedRemovalInventory(ctx, root)
	if err != nil {
		return fmt.Errorf("%w: retained removal remainder is unsafe: %v", ErrIntegrity, err)
	}
	expected := make(map[string]retainedRemovalEntry, len(plan.Entries))
	for _, entry := range plan.Entries {
		expected[entry.Path] = entry
	}
	for _, entry := range actual {
		planned, exists := expected[entry.Path]
		if !exists || !sameRetainedRemovalEntry(entry, planned) {
			return fmt.Errorf("%w: retained removal remainder has unknown or changed entry %q", ErrIntegrity, entry.Path)
		}
	}
	return nil
}

func loadRetainedRemovalPlan(stageRoot, name string) (retainedRemovalPlan, []byte, bool, error) {
	data, err := readRootedPrivateRegular(stageRoot, name, maxRetainedRemovalBytes, false)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		return retainedRemovalPlan{}, nil, false, nil
	}
	if err != nil {
		return retainedRemovalPlan{}, nil, false, err
	}
	plan, canonical, err := parseRetainedRemovalPlan(data)
	if err != nil {
		return retainedRemovalPlan{}, nil, true, fmt.Errorf("%w: retained removal plan is invalid: %v", ErrIntegrity, err)
	}
	return plan, canonical, true, nil
}

func retainedRemovalResult(repoName string, plan retainedRemovalPlan, path string) RetainedGeneration {
	return RetainedGeneration{
		Repository: repoName, Record: RetainedRecord{Generation: plan.Generation}, RecordIdentity: plan.RecordIdentity, Path: path,
	}
}

func listRetainedGenerationsResult(ctx context.Context, opts RetainListOptions) (result RetainListResult, resultErr error) {
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts.WorkspaceOptions, true)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	repoName, err := selectRepo(ws, cfg, opts.Repository)
	if err != nil {
		return result, err
	}
	result.Repository = repoName
	store, repoLock, err := openReadRepository(ctx, ws.Root, repoName)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close(), store.Close()) }()
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		return result, err
	}
	entries, err := os.ReadDir(filepath.Join(ws.Root, ".sow", repoName, "retained"))
	if err != nil {
		return result, err
	}
	result.Generations = []RetainedGeneration{}
	for _, entry := range entries {
		generation, err := state.ParseGenerationID(entry.Name())
		if err != nil || generation == 0 || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return result, fmt.Errorf("%w: non-canonical retained entry %q", ErrIntegrity, entry.Name())
		}
		retained, err := verifyRetainedGenerationLocked(ctx, ws.Root, repoName, generation, identity.RepositoryID)
		if err != nil {
			return result, err
		}
		result.Generations = append(result.Generations, retained)
	}
	return result, nil
}

func ListRetainedGenerations(ctx context.Context, opts RetainListOptions) ([]RetainedGeneration, error) {
	result, err := listRetainedGenerationsResult(ctx, opts)
	return result.Generations, err
}

// verifyAllRetainedGenerationsLocked is the repository-wide retained closure
// predicate used by ordinary check.  It intentionally rejects every
// non-generation entry instead of silently skipping a damaged or attacker-
// supplied retained root.
func verifyAllRetainedGenerationsLocked(ctx context.Context, root, repoName, repositoryID string) (int64, []string) {
	entries, err := listRootedDirectory(filepath.Join(root, ".sow", repoName, "retained"))
	if err != nil {
		return 0, []string{fmt.Sprintf("retained inventory is unavailable: %v", err)}
	}
	issues := []string{}
	for _, entry := range entries {
		generation, parseErr := state.ParseGenerationID(entry.Name)
		if parseErr != nil || generation == 0 || uint32(entry.Stat.Mode)&unix.S_IFMT != unix.S_IFDIR {
			issues = append(issues, fmt.Sprintf("non-canonical retained entry %q", entry.Name))
			continue
		}
		if _, verifyErr := verifyRetainedGenerationLocked(ctx, root, repoName, generation, repositoryID); verifyErr != nil {
			issues = append(issues, fmt.Sprintf("retained Generation %s is invalid: %v", generation, verifyErr))
		}
	}
	return int64(len(entries)), issues
}

func RetainList(ctx context.Context, opts RetainListOptions) (RetainListResult, error) {
	return listRetainedGenerationsResult(ctx, opts)
}

func RemoveRetainedGeneration(ctx context.Context, opts RetainRemoveOptions) (result RetainedGeneration, resultErr error) {
	if ctx == nil || opts.Generation == 0 {
		return result, fmt.Errorf("%w: retained Generation must be greater than zero", ErrRejected)
	}
	ws, _, rootGuard, err := workspace(opts.WorkspaceOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	_, _, repoName, workspaceLock, repoLock, err := acquireSelectedRepositoryLocks(ctx, ws, opts.Repository, opts.LockOptions)
	if err != nil {
		return result, err
	}
	result.Repository = repoName
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close(), repoLock.Close()) }()
	store, err := openExistingState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	if err := store.RequireTerminalLayout(ctx); err != nil {
		return result, err
	}
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		return result, err
	}
	privateRoot := filepath.Join(ws.Root, ".sow", repoName)
	retainedRoot := filepath.Join(privateRoot, "retained")
	stageRoot := filepath.Join(privateRoot, "stage")
	targetRelative := filepath.Join("retained", opts.Generation.String())
	target := filepath.Join(retainedRoot, opts.Generation.String())
	tombstoneName := "retain-remove-" + opts.Generation.String()
	tombstoneRelative := filepath.Join("stage", tombstoneName)
	tombstone := filepath.Join(stageRoot, tombstoneName)
	planName := tombstoneName + ".plan.json"
	targetExists, err := rootedDirectoryExists(privateRoot, targetRelative)
	if err != nil {
		return result, err
	}
	tombstoneExists, err := rootedDirectoryExists(privateRoot, tombstoneRelative)
	if err != nil {
		return result, err
	}
	if targetExists && tombstoneExists {
		return result, fmt.Errorf("%w: retained Generation and removal tombstone both exist", ErrIntegrity)
	}
	plan, planBytes, planExists, err := loadRetainedRemovalPlan(stageRoot, planName)
	if err != nil {
		return result, err
	}
	if planExists && (plan.RepositoryID != identity.RepositoryID || plan.Generation != opts.Generation) {
		return result, fmt.Errorf("%w: retained removal plan belongs to another repository or Generation", ErrIntegrity)
	}
	if targetExists {
		result, err = verifyRetainedGenerationLocked(ctx, ws.Root, repoName, opts.Generation, identity.RepositoryID)
		if err != nil {
			return result, err
		}
		entries, err := retainedRemovalInventory(ctx, target)
		if err != nil {
			return result, fmt.Errorf("%w: retained removal inventory is unsafe: %v", ErrIntegrity, err)
		}
		expectedPlan := retainedRemovalPlan{
			Schema: retainedRemovalSchema, RepositoryID: identity.RepositoryID, Generation: opts.Generation,
			RecordIdentity: result.RecordIdentity, Entries: entries,
		}
		expectedBytes, err := canonicalRetainedRemovalPlan(expectedPlan)
		if err != nil || len(expectedBytes) > maxRetainedRemovalBytes {
			return result, errors.Join(fmt.Errorf("%w: retained removal plan exceeds its bound", ErrRejected), err)
		}
		if planExists {
			if !bytes.Equal(planBytes, expectedBytes) || !sameRetainedRemovalInventory(plan.Entries, expectedPlan.Entries) {
				return result, fmt.Errorf("%w: retained removal plan differs from the complete target inventory", ErrIntegrity)
			}
		} else {
			if err := writeRootedNewRegular(stageRoot, planName, expectedBytes, 0o600); err != nil {
				return result, err
			}
			plan, planBytes, planExists = expectedPlan, expectedBytes, true
			if err := callFault(opts.Fault, "retain.remove.planned"); err != nil {
				return result, err
			}
		}
		if err := durableRename(privateRoot, target, tombstone); err != nil {
			return result, err
		}
		if err := callFault(opts.Fault, "retain.remove.tombstoned"); err != nil {
			return result, err
		}
	} else if tombstoneExists {
		if !planExists {
			return result, fmt.Errorf("%w: retained removal tombstone lacks its sibling plan", ErrIntegrity)
		}
		result = retainedRemovalResult(repoName, plan, target)
	} else if planExists {
		// The exact tombstone inventory has already been removed.  The sibling
		// plan is the last durable replay step and still carries the result
		// identity for this retry.
		result = retainedRemovalResult(repoName, plan, target)
		if err := removeRootedRegularExact(ctx, stageRoot, planName, int64(len(planBytes)), bytesSHA(planBytes)); err != nil {
			return result, fmt.Errorf("%w: remove completed retained removal plan: %v", ErrIntegrity, err)
		}
		return result, nil
	} else {
		// A completed removal is an idempotent no-op.  The generation field
		// keeps the result useful without inventing a record identity that no
		// longer has persisted evidence.
		return RetainedGeneration{Repository: repoName, Record: RetainedRecord{Generation: opts.Generation}, Path: target}, nil
	}
	if !planExists {
		return result, fmt.Errorf("%w: retained removal has no durable sibling plan", ErrIntegrity)
	}
	if result.RecordIdentity == "" {
		result = retainedRemovalResult(repoName, plan, target)
	}
	if err := validateRetainedRemovalRemainder(ctx, tombstone, plan); err != nil {
		return result, err
	}
	for _, entry := range plan.Entries {
		if entry.Kind != "file" {
			continue
		}
		if err := removeRootedRegularExact(ctx, tombstone, filepath.FromSlash(entry.Path), entry.Size, entry.SHA256); err != nil {
			return result, fmt.Errorf("%w: remove planned retained file %q: %v", ErrIntegrity, entry.Path, err)
		}
		if err := callFault(opts.Fault, "retain.remove.entry."+entry.Path); err != nil {
			return result, err
		}
	}
	if err := validateRetainedRemovalRemainder(ctx, tombstone, plan); err != nil {
		return result, err
	}
	for index := len(plan.Entries) - 1; index >= 0; index-- {
		entry := plan.Entries[index]
		if entry.Kind != "directory" {
			continue
		}
		if err := removeRootedEmptyDirectory(tombstone, filepath.FromSlash(entry.Path)); err != nil {
			return result, fmt.Errorf("%w: remove planned retained directory %q: %v", ErrIntegrity, entry.Path, err)
		}
		if err := callFault(opts.Fault, "retain.remove.entry."+entry.Path); err != nil {
			return result, err
		}
	}
	if err := removeRootedEmptyDirectory(stageRoot, tombstoneName); err != nil {
		return result, fmt.Errorf("%w: remove retained tombstone root: %v", ErrIntegrity, err)
	}
	if err := callFault(opts.Fault, "retain.remove.cleaned"); err != nil {
		return result, err
	}
	if err := removeRootedRegularExact(ctx, stageRoot, planName, int64(len(planBytes)), bytesSHA(planBytes)); err != nil {
		return result, fmt.Errorf("%w: remove retained removal plan: %v", ErrIntegrity, err)
	}
	return result, nil
}

func rootedDirectoryExists(root, relative string) (bool, error) {
	chain, err := openRootedDirectoryChain(root, relative, false, 0)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, chain.close(true)
}

func RetainRemove(ctx context.Context, opts RetainRemoveOptions) (RetainedGeneration, error) {
	return RemoveRetainedGeneration(ctx, opts)
}

type retainedContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *retainedContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
