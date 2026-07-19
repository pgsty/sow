package provenance

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const LegacyIndexPruneSchema = "sow-legacy-index-prune/v1"

// LegacyIndexPruneReceipt is negative provenance: local primary metadata named
// an exact package identity, but the immutable M0 baseline had no body at that
// path. An explicitly confirmed migration may omit that entry while preserving
// the evidence needed to explain the repaired, newly signed metadata.
type LegacyIndexPruneReceipt struct {
	Schema             string    `json:"schema"`
	Repo               string    `json:"repo"`
	Path               string    `json:"path"`
	Name               string    `json:"name"`
	Version            string    `json:"version"`
	Arch               string    `json:"arch"`
	ArtifactSize       int64     `json:"artifact_size"`
	ArtifactSHA256     string    `json:"artifact_sha256"`
	Reason             string    `json:"reason"`
	ConfirmationSHA256 string    `json:"confirmation_sha256"`
	RecordedAt         time.Time `json:"recorded_at"`
	BaselineCommit     string    `json:"baseline_commit"`
}

// LegacyIndexPruneIdentity is the exact primary entry authorized by one
// confirmation-set digest. Time and Git anchors belong to the durable receipt
// but do not change the reviewed missing-artifact set.
type LegacyIndexPruneIdentity struct {
	Repo           string
	Path           string
	Name           string
	Version        string
	Arch           string
	ArtifactSize   int64
	ArtifactSHA256 string
}

func (i LegacyIndexPruneIdentity) Validate() error {
	if !legacyNamePattern.MatchString(i.Repo) || !validLegacyPath(i.Path) ||
		!validLegacyIndexToken(i.Name) || !validLegacyIndexToken(i.Version) || !validLegacyIndexToken(i.Arch) {
		return errors.New("legacy index prune identity is incomplete or unsafe")
	}
	if i.ArtifactSize <= 0 {
		return errors.New("legacy index prune identity artifact_size must be positive")
	}
	return validateHash("artifact_sha256", i.ArtifactSHA256)
}

func (r LegacyIndexPruneReceipt) Identity() LegacyIndexPruneIdentity {
	return LegacyIndexPruneIdentity{
		Repo: r.Repo, Path: r.Path, Name: r.Name, Version: r.Version, Arch: r.Arch,
		ArtifactSize: r.ArtifactSize, ArtifactSHA256: r.ArtifactSHA256,
	}
}

// LegacyIndexPruneSetSHA256 is the domain contract shared by preflight and
// canonical audit. It sorts a detached copy and rejects duplicate coordinates
// so report ordering or map iteration cannot change the authorization token.
func LegacyIndexPruneSetSHA256(identities []LegacyIndexPruneIdentity) (string, error) {
	identities = append([]LegacyIndexPruneIdentity(nil), identities...)
	for _, identity := range identities {
		if err := identity.Validate(); err != nil {
			return "", err
		}
	}
	sort.Slice(identities, func(i, j int) bool {
		if identities[i].Repo != identities[j].Repo {
			return identities[i].Repo < identities[j].Repo
		}
		return identities[i].Path < identities[j].Path
	})
	hash := sha256.New()
	for index, identity := range identities {
		if index > 0 && identities[index-1].Repo == identity.Repo && identities[index-1].Path == identity.Path {
			return "", fmt.Errorf("duplicate legacy index prune coordinate %s/%s", identity.Repo, identity.Path)
		}
		fmt.Fprintf(hash, "indexed-body-missing\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			identity.Repo, identity.Path, identity.ArtifactSize, identity.ArtifactSHA256,
			identity.Name, identity.Version, identity.Arch)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (r LegacyIndexPruneReceipt) Validate() error {
	if r.Schema != LegacyIndexPruneSchema {
		return fmt.Errorf("unsupported legacy index prune schema %q", r.Schema)
	}
	if !legacyNamePattern.MatchString(r.Repo) || !validLegacyPath(r.Path) ||
		!validLegacyIndexToken(r.Name) || !validLegacyIndexToken(r.Version) || !validLegacyIndexToken(r.Arch) {
		return errors.New("legacy index prune identity is incomplete or unsafe")
	}
	if r.ArtifactSize <= 0 {
		return errors.New("legacy index prune artifact_size must be positive")
	}
	if err := validateHash("artifact_sha256", r.ArtifactSHA256); err != nil {
		return err
	}
	if r.Reason != "indexed-body-missing" {
		return fmt.Errorf("unsupported legacy index prune reason %q", r.Reason)
	}
	if err := validateHash("confirmation_sha256", r.ConfirmationSHA256); err != nil {
		return err
	}
	if r.RecordedAt.IsZero() || r.RecordedAt.Location() != time.UTC {
		return errors.New("legacy index prune recorded_at must be a non-zero UTC timestamp")
	}
	if len(r.BaselineCommit) != sha1.Size*2 || r.BaselineCommit != strings.ToLower(r.BaselineCommit) {
		return errors.New("legacy index prune baseline_commit must be a lowercase Git SHA-1")
	}
	decoded, err := hex.DecodeString(r.BaselineCommit)
	if err != nil || len(decoded) != sha1.Size {
		return errors.New("legacy index prune baseline_commit must be a lowercase Git SHA-1")
	}
	return nil
}

func validLegacyIndexToken(value string) bool {
	return value != "" && !strings.ContainsAny(value, "/\\ \t\r\n\x00")
}

func (r LegacyIndexPruneReceipt) CanonicalJSON() ([]byte, error) {
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

func DecodeLegacyIndexPrune(data []byte) (LegacyIndexPruneReceipt, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var receipt LegacyIndexPruneReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, fmt.Errorf("decode legacy index prune receipt: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return receipt, errors.New("legacy index prune receipt contains trailing JSON")
		}
		return receipt, err
	}
	return receipt, receipt.Validate()
}

func WriteLegacyIndexPrune(w io.Writer, receipt LegacyIndexPruneReceipt) error {
	if w == nil {
		return errors.New("nil legacy index prune writer")
	}
	body, err := receipt.CanonicalJSON()
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

type LegacyIndexPruneReader struct {
	scanner *bufio.Scanner
	line    int
	last    string
}

func NewLegacyIndexPruneReader(r io.Reader) *LegacyIndexPruneReader {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	return &LegacyIndexPruneReader{scanner: scanner}
}

func (r *LegacyIndexPruneReader) Next() (LegacyIndexPruneReceipt, error) {
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return LegacyIndexPruneReceipt{}, err
		}
		return LegacyIndexPruneReceipt{}, io.EOF
	}
	r.line++
	receipt, err := DecodeLegacyIndexPrune(append(append([]byte(nil), r.scanner.Bytes()...), '\n'))
	if err != nil {
		return receipt, fmt.Errorf("legacy index prune line %d: %w", r.line, err)
	}
	if r.last != "" && receipt.Path <= r.last {
		return receipt, fmt.Errorf("legacy index prune line %d: paths are not strictly sorted", r.line)
	}
	r.last = receipt.Path
	return receipt, nil
}
