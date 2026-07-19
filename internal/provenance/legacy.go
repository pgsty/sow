package provenance

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"time"
)

const LegacyAdoptionSchema = "sow-legacy-adoption/v1"

var legacyNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$`)

// LegacyAdoptionReceipt records exactly what local serving byte was adopted
// into CAS. It is intentionally not an upstream provenance receipt: no URL,
// Release signature, or RPM signature policy is claimed or inferred.
type LegacyAdoptionReceipt struct {
	Schema         string    `json:"schema"`
	Format         string    `json:"format"`
	Repo           string    `json:"repo"`
	SourcePath     string    `json:"source_path"`
	CanonicalPath  string    `json:"canonical_path"`
	ArtifactSize   int64     `json:"artifact_size"`
	ArtifactSHA256 string    `json:"artifact_sha256"`
	Pool           string    `json:"pool"`
	AdoptedAt      time.Time `json:"adopted_at"`
	ConfigCommit   string    `json:"config_commit"`
}

func (r LegacyAdoptionReceipt) Validate() error {
	if r.Schema != LegacyAdoptionSchema {
		return fmt.Errorf("unsupported legacy adoption schema %q", r.Schema)
	}
	if r.Format != "deb" && r.Format != "rpm" && r.Format != "asset" {
		return fmt.Errorf("unsupported legacy adoption format %q", r.Format)
	}
	if !legacyNamePattern.MatchString(r.Repo) {
		return fmt.Errorf("invalid legacy adoption repo %q", r.Repo)
	}
	if !validLegacyPath(r.SourcePath) {
		return fmt.Errorf("unsafe legacy adoption source_path %q", r.SourcePath)
	}
	canonicalPath := r.CanonicalPath
	if canonicalPath == "" {
		canonicalPath = r.SourcePath
	}
	if !validLegacyPath(canonicalPath) {
		return fmt.Errorf("unsafe legacy adoption canonical_path %q", r.CanonicalPath)
	}
	if r.ArtifactSize < 0 {
		return errors.New("legacy adoption artifact_size cannot be negative")
	}
	if err := validateHash("artifact_sha256", r.ArtifactSHA256); err != nil {
		return err
	}
	if r.Pool != "public" && r.Pool != "gated" {
		return errors.New("legacy adoption pool must be public or gated")
	}
	if r.AdoptedAt.IsZero() || r.AdoptedAt.Location() != time.UTC {
		return errors.New("legacy adoption adopted_at must be a non-zero UTC timestamp")
	}
	if len(r.ConfigCommit) != sha1.Size*2 || r.ConfigCommit != strings.ToLower(r.ConfigCommit) {
		return errors.New("legacy adoption config_commit must be a lowercase Git SHA-1")
	}
	decoded, err := hex.DecodeString(r.ConfigCommit)
	if err != nil || len(decoded) != sha1.Size {
		return errors.New("legacy adoption config_commit must be a lowercase Git SHA-1")
	}
	return nil
}

func (r LegacyAdoptionReceipt) CanonicalJSON() ([]byte, error) {
	// Ledgers written before canonical_path was added used source_path for both
	// identities. Normalize them when callers re-encode an old in-memory value;
	// new flat-YUM receipts always persist the two paths explicitly.
	if r.CanonicalPath == "" {
		r.CanonicalPath = r.SourcePath
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(r); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func DecodeLegacyAdoption(data []byte) (LegacyAdoptionReceipt, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var receipt LegacyAdoptionReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, fmt.Errorf("decode legacy adoption receipt: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return receipt, errors.New("legacy adoption receipt contains trailing JSON")
		}
		return receipt, fmt.Errorf("decode trailing legacy adoption JSON: %w", err)
	}
	if receipt.CanonicalPath == "" {
		receipt.CanonicalPath = receipt.SourcePath
	}
	return receipt, receipt.Validate()
}

func validLegacyPath(value string) bool {
	return value != "" && value != "." && !strings.HasPrefix(value, "/") &&
		!strings.ContainsAny(value, "\\%?#\x00\t\r\n") &&
		path.Clean(value) == value && value != ".." && !strings.HasPrefix(value, "../")
}

func WriteLegacyAdoption(w io.Writer, receipt LegacyAdoptionReceipt) error {
	if w == nil {
		return errors.New("nil legacy adoption writer")
	}
	data, err := receipt.CanonicalJSON()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// LegacyAdoptionReader reads a canonical JSONL ledger. Source paths must be
// strictly sorted, which keeps repeat adoption byte-for-byte deterministic and
// makes large ledgers streamable.
type LegacyAdoptionReader struct {
	scanner *bufio.Scanner
	line    int
	last    string
}

func NewLegacyAdoptionReader(r io.Reader) *LegacyAdoptionReader {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	return &LegacyAdoptionReader{scanner: scanner}
}

func (r *LegacyAdoptionReader) Next() (LegacyAdoptionReceipt, error) {
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return LegacyAdoptionReceipt{}, err
		}
		return LegacyAdoptionReceipt{}, io.EOF
	}
	r.line++
	receipt, err := DecodeLegacyAdoption(append(append([]byte(nil), r.scanner.Bytes()...), '\n'))
	if err != nil {
		return receipt, fmt.Errorf("legacy adoption line %d: %w", r.line, err)
	}
	if r.last != "" && receipt.SourcePath <= r.last {
		return receipt, fmt.Errorf("legacy adoption line %d: source paths are not strictly sorted", r.line)
	}
	r.last = receipt.SourcePath
	return receipt, nil
}
