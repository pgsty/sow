package provenance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	// Schema v3 binds every new RPM receipt to a public package-keyring digest
	// and the actual trusted signer(s) that cryptographically verified the RPM.
	// v1/v2 remain decodable for deterministic replay of canonical history, but
	// new ingestion never manufactures verification claims for those receipts.
	Schema         = "sow-provenance/v3"
	PreviousSchema = "sow-provenance/v2"
	LegacySchema   = "sow-provenance/v1"
)

type Receipt struct {
	Schema         string    `json:"schema"`
	Format         string    `json:"format"`
	ArtifactSHA256 string    `json:"artifact_sha256"`
	ArtifactSize   int64     `json:"artifact_size"`
	UpstreamURL    string    `json:"upstream_url"`
	ObservedAt     time.Time `json:"observed_at"`
	RPM            *RPMProof `json:"rpm,omitempty"`
	DEB            *DEBProof `json:"deb,omitempty"`
}

type RPMProof struct {
	IndexURL              string                 `json:"index_url"`
	IndexSHA256           string                 `json:"index_sha256"`
	IndexSize             int64                  `json:"index_size"`
	OriginalRPMSHA        string                 `json:"original_rpm_sha256"`
	SignaturePolicy       string                 `json:"signature_policy"`
	EmbeddedSignatures    []RPMSignatureEvidence `json:"embedded_signatures,omitempty"`
	SignatureVerification string                 `json:"signature_verification,omitempty"`
	PackageKeyringSHA256  string                 `json:"package_keyring_sha256,omitempty"`
}

// RPMSignatureEvidence binds one bounded RPM-header packet to the trusted v4
// OpenPGP key that verified it. Historical v2 receipts omit the signer fields
// and explicitly retain their weaker structural-inspection semantics.
type RPMSignatureEvidence struct {
	HeaderTag                string `json:"header_tag"`
	HeaderTagID              int    `json:"header_tag_id"`
	PacketSHA256             string `json:"packet_sha256"`
	PacketSize               int64  `json:"packet_size"`
	PacketVersion            int    `json:"packet_version"`
	PublicKeyAlgorithm       int    `json:"public_key_algorithm"`
	HashAlgorithm            int    `json:"hash_algorithm"`
	IssuerKeyID              string `json:"issuer_key_id,omitempty"`
	SignatureCreatedAt       string `json:"signature_created_at,omitempty"`
	Coverage                 string `json:"coverage,omitempty"`
	SignedBytes              int64  `json:"signed_bytes,omitempty"`
	SignerFingerprint        string `json:"signer_fingerprint,omitempty"`
	SignerKeyID              string `json:"signer_key_id,omitempty"`
	SignerPrimaryFingerprint string `json:"signer_primary_fingerprint,omitempty"`
	PayloadDigestAlgorithm   string `json:"payload_digest_algorithm,omitempty"`
	PayloadDigest            string `json:"payload_digest,omitempty"`
}

type DEBProof struct {
	PackagesEntrySHA256    string `json:"packages_entry_sha256"`
	PackagesEvidenceSHA256 string `json:"packages_evidence_sha256"`
	SignedReleaseSHA256    string `json:"signed_release_sha256"`
	SignedReleaseKind      string `json:"signed_release_kind"`
}

func NewRPM(artifactSHA string, size int64, upstreamURL string, observed time.Time, proof RPMProof) Receipt {
	return Receipt{Schema: Schema, Format: "rpm", ArtifactSHA256: artifactSHA, ArtifactSize: size, UpstreamURL: upstreamURL, ObservedAt: observed.UTC(), RPM: &proof}
}

func NewDEB(artifactSHA string, size int64, upstreamURL string, observed time.Time, proof DEBProof) Receipt {
	return Receipt{Schema: Schema, Format: "deb", ArtifactSHA256: artifactSHA, ArtifactSize: size, UpstreamURL: upstreamURL, ObservedAt: observed.UTC(), DEB: &proof}
}

func (r Receipt) Validate() error {
	if r.Schema != Schema && r.Schema != PreviousSchema && r.Schema != LegacySchema {
		return fmt.Errorf("unsupported provenance schema %q", r.Schema)
	}
	if r.Format != "rpm" && r.Format != "deb" {
		return fmt.Errorf("unsupported artifact format %q", r.Format)
	}
	if err := validateHash("artifact_sha256", r.ArtifactSHA256); err != nil {
		return err
	}
	if r.ArtifactSize < 0 {
		return errors.New("artifact_size cannot be negative")
	}
	if err := validatePublicURL("upstream_url", r.UpstreamURL); err != nil {
		return err
	}
	if r.ObservedAt.IsZero() || r.ObservedAt.Location() != time.UTC {
		return errors.New("observed_at must be a non-zero UTC timestamp")
	}
	if r.Format == "rpm" {
		if r.RPM == nil || r.DEB != nil {
			return errors.New("rpm receipt requires only the rpm proof")
		}
		return r.RPM.validate(r.ArtifactSHA256, r.Schema)
	}
	if r.DEB == nil || r.RPM != nil {
		return errors.New("deb receipt requires only the deb proof")
	}
	return r.DEB.validate()
}

func (p RPMProof) validate(artifactHash, schema string) error {
	if err := validatePublicURL("rpm.index_url", p.IndexURL); err != nil {
		return err
	}
	if err := validateHash("rpm.index_sha256", p.IndexSHA256); err != nil {
		return err
	}
	if p.IndexSize < 0 {
		return errors.New("rpm.index_size cannot be negative")
	}
	if err := validateHash("rpm.original_rpm_sha256", p.OriginalRPMSHA); err != nil {
		return err
	}
	if p.OriginalRPMSHA != artifactHash {
		return errors.New("mirrored RPM must preserve the original bytes and embedded signature")
	}
	if p.SignaturePolicy != "preserve-upstream" {
		return errors.New("mirrored RPM signature_policy must be preserve-upstream")
	}
	if schema == LegacySchema {
		if len(p.EmbeddedSignatures) != 0 || p.SignatureVerification != "" || p.PackageKeyringSHA256 != "" {
			return errors.New("schema v1 RPM receipts cannot carry signature evidence fields")
		}
		return nil
	}
	if len(p.EmbeddedSignatures) == 0 || len(p.EmbeddedSignatures) > 5 {
		return errors.New("mirrored RPM must record 1..5 embedded signature packets")
	}
	if schema == PreviousSchema {
		if p.SignatureVerification != "not-performed" || p.PackageKeyringSHA256 != "" {
			return errors.New("schema v2 mirrored RPM signature_verification must be not-performed without package-keyring trust")
		}
	} else {
		if p.SignatureVerification != "verified" {
			return errors.New("schema v3 mirrored RPM signature_verification must be verified")
		}
		if err := validateHash("rpm.package_keyring_sha256", p.PackageKeyringSHA256); err != nil {
			return err
		}
	}
	priorTag := -1
	wholePackageCovered := false
	for i, signature := range p.EmbeddedSignatures {
		if err := signature.validate(schema); err != nil {
			return fmt.Errorf("rpm.embedded_signatures[%d]: %w", i, err)
		}
		wholePackageCovered = wholePackageCovered || signature.Coverage == "header+payload-digest" || signature.Coverage == "header+payload"
		if signature.HeaderTagID <= priorTag {
			return errors.New("rpm.embedded_signatures must be strictly ordered by header_tag_id")
		}
		priorTag = signature.HeaderTagID
	}
	if schema == Schema && !wholePackageCovered {
		return errors.New("verified RPM signatures do not authenticate the package payload")
	}
	return nil
}

func (s RPMSignatureEvidence) validate(schema string) error {
	wantName, known := map[int]string{
		267:  "RPMSIGTAG_DSA",
		268:  "RPMSIGTAG_RSA",
		1002: "RPMSIGTAG_PGP",
		1005: "RPMSIGTAG_GPG",
		1006: "RPMSIGTAG_PGP5",
	}[s.HeaderTagID]
	if !known || s.HeaderTag != wantName {
		return errors.New("header_tag and header_tag_id must identify a supported RPM signature tag")
	}
	if err := validateHash("packet_sha256", s.PacketSHA256); err != nil {
		return err
	}
	if s.PacketSize <= 0 || s.PacketSize > 1<<20 {
		return errors.New("packet_size must be between 1 byte and 1 MiB")
	}
	if s.PacketVersion != 3 && s.PacketVersion != 4 {
		return errors.New("packet_version must be OpenPGP v3 or v4")
	}
	if s.PublicKeyAlgorithm < 1 || s.PublicKeyAlgorithm > 255 || s.HashAlgorithm < 1 || s.HashAlgorithm > 255 {
		return errors.New("public_key_algorithm and hash_algorithm must be valid OpenPGP identifiers")
	}
	if s.HeaderTagID == 267 && s.PublicKeyAlgorithm != 17 {
		return errors.New("RPMSIGTAG_DSA must contain a DSA signature packet")
	}
	if s.HeaderTagID == 268 && s.PublicKeyAlgorithm != 1 && s.PublicKeyAlgorithm != 3 {
		return errors.New("RPMSIGTAG_RSA must contain an RSA signature packet")
	}
	if s.IssuerKeyID != "" {
		if len(s.IssuerKeyID) != 16 || strings.ToLower(s.IssuerKeyID) != s.IssuerKeyID {
			return errors.New("issuer_key_id must be 16 lowercase hexadecimal characters")
		}
		if _, err := hex.DecodeString(s.IssuerKeyID); err != nil {
			return errors.New("issuer_key_id must be 16 lowercase hexadecimal characters")
		}
	}
	if schema == PreviousSchema {
		if s.SignatureCreatedAt != "" || s.Coverage != "" || s.SignedBytes != 0 || s.SignerFingerprint != "" || s.SignerKeyID != "" ||
			s.SignerPrimaryFingerprint != "" || s.PayloadDigestAlgorithm != "" || s.PayloadDigest != "" {
			return errors.New("schema v2 signature evidence cannot claim a verified signer")
		}
		return nil
	}
	if schema == LegacySchema {
		return errors.New("schema v1 cannot contain embedded signature evidence")
	}
	createdAt, err := time.Parse(time.RFC3339, s.SignatureCreatedAt)
	if err != nil || createdAt.IsZero() || createdAt.Location() != time.UTC || createdAt.Format(time.RFC3339) != s.SignatureCreatedAt {
		return errors.New("signature_created_at must be a canonical non-zero UTC RFC3339 timestamp")
	}
	if len(s.SignerFingerprint) != 40 || strings.ToLower(s.SignerFingerprint) != s.SignerFingerprint {
		return errors.New("signer_fingerprint must be a 40-character lowercase OpenPGP v4 fingerprint")
	}
	if _, err := hex.DecodeString(s.SignerFingerprint); err != nil {
		return errors.New("signer_fingerprint must be a 40-character lowercase OpenPGP v4 fingerprint")
	}
	if len(s.SignerKeyID) != 16 || strings.ToLower(s.SignerKeyID) != s.SignerKeyID {
		return errors.New("signer_key_id must be 16 lowercase hexadecimal characters")
	}
	if _, err := hex.DecodeString(s.SignerKeyID); err != nil || !strings.HasSuffix(s.SignerFingerprint, s.SignerKeyID) {
		return errors.New("signer_key_id must equal the low 64 bits of signer_fingerprint")
	}
	if len(s.SignerPrimaryFingerprint) != 40 || strings.ToLower(s.SignerPrimaryFingerprint) != s.SignerPrimaryFingerprint {
		return errors.New("signer_primary_fingerprint must be a 40-character lowercase OpenPGP v4 fingerprint")
	}
	if _, err := hex.DecodeString(s.SignerPrimaryFingerprint); err != nil {
		return errors.New("signer_primary_fingerprint must be a 40-character lowercase OpenPGP v4 fingerprint")
	}
	if s.SignedBytes <= 0 {
		return errors.New("signed_bytes must be positive")
	}
	switch s.Coverage {
	case "header":
		if s.HeaderTagID != 267 && s.HeaderTagID != 268 {
			return errors.New("header-only coverage requires an RSA or DSA header signature")
		}
		if s.PayloadDigestAlgorithm != "" || s.PayloadDigest != "" {
			return errors.New("header-only signature evidence cannot carry a payload digest")
		}
	case "header+payload-digest":
		if s.HeaderTagID != 267 && s.HeaderTagID != 268 {
			return errors.New("header+payload-digest coverage requires an RSA or DSA header signature")
		}
		wantHex := map[string]int{"SHA-224": 56, "SHA-256": 64, "SHA-384": 96, "SHA-512": 128}[s.PayloadDigestAlgorithm]
		if wantHex == 0 || len(s.PayloadDigest) != wantHex || strings.ToLower(s.PayloadDigest) != s.PayloadDigest {
			return errors.New("payload_digest must match its supported SHA-2 payload_digest_algorithm")
		}
		if _, err := hex.DecodeString(s.PayloadDigest); err != nil {
			return errors.New("payload_digest must be lowercase hexadecimal")
		}
	case "header+payload":
		if s.HeaderTagID == 267 || s.HeaderTagID == 268 {
			return errors.New("RSA or DSA header signatures require payload-digest coverage")
		}
		if s.PayloadDigestAlgorithm != "" || s.PayloadDigest != "" {
			return errors.New("whole-package signature evidence cannot carry a separate payload digest")
		}
	default:
		return errors.New("coverage must be header, header+payload-digest, or header+payload")
	}
	return nil
}

func (p DEBProof) validate() error {
	for field, value := range map[string]string{
		"deb.packages_entry_sha256":    p.PackagesEntrySHA256,
		"deb.packages_evidence_sha256": p.PackagesEvidenceSHA256,
		"deb.signed_release_sha256":    p.SignedReleaseSHA256,
	} {
		if err := validateHash(field, value); err != nil {
			return err
		}
	}
	if p.SignedReleaseKind != "InRelease" && p.SignedReleaseKind != "Release+Release.gpg" {
		return errors.New("deb.signed_release_kind must be InRelease or Release+Release.gpg")
	}
	return nil
}

func (r Receipt) CanonicalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var result bytes.Buffer
	encoder := json.NewEncoder(&result)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(r); err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

func (r Receipt) ID() (string, error) {
	data, err := r.CanonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func Decode(data []byte) (Receipt, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode provenance receipt: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Receipt{}, errors.New("provenance receipt contains trailing JSON")
		}
		return Receipt{}, fmt.Errorf("decode trailing provenance JSON: %w", err)
	}
	if err := receipt.Validate(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func validateHash(field, value string) error {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return fmt.Errorf("%s must be a lowercase SHA-256", field)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("%s must be a lowercase SHA-256", field)
	}
	return nil
}

func validatePublicURL(field, value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%s must be an absolute HTTPS URL", field)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must not contain credentials, query material, or a fragment", field)
	}
	return nil
}
