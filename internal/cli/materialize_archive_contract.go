package cli

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

const offlineArchiveAdoptionContractSchema = "sow-offline-archive-adoption/v1"

const offlineArchiveTaintReceiptSchema = "sow-offline-archive-taint/v1"

const offlineArchiveMarkerPrefix = "sow-offline-archive/v1;"

const offlineArchivePayloadMarkerSchema = "sow-offline-archive-payload/v1"

const offlineArchivePayloadMarkerPath = ".sow-offline-archive.json"

var errOfflineArchivePolicyEnvelope = errors.New("SOW offline archive policy envelope was observed")

var errOfflineArchiveInspectionBudget = errors.New("offline archive inspection budget exceeded")

type offlineArchiveInspectionLimits struct {
	MaxExpandedBytes  int64
	MaxMembers        int
	MaxExpansionRatio int64
	ExpansionSlack    int64
}

var defaultOfflineArchiveInspectionLimits = offlineArchiveInspectionLimits{
	// Repository archives can legitimately be much larger than memory. The
	// absolute ceiling is therefore only an overflow/corruption guard; the
	// per-member expansion ratio is the practical zip-bomb boundary.
	MaxExpandedBytes:  1 << 50,
	MaxMembers:        64,
	MaxExpansionRatio: 512,
	ExpansionSlack:    16 << 20,
}

type offlineArchiveInspectionMeter struct {
	limits   offlineArchiveInspectionLimits
	expanded int64
}

// offlineArchiveSourceRef freezes the canonical source of an archive. Path is
// deliberately included alongside the ref and commit: recovery must reopen the
// same manifest blob, not derive a new path from current selectors.
type offlineArchiveSourceRef struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
	Path   string `json:"path"`
	Repo   string `json:"repo"`
	OS     string `json:"os"`
	Arch   string `json:"arch"`
}

// offlineArchiveSourceProof is a streaming commitment to the canonical view
// entries that produced an offline archive. Access is policy-derived from the
// configured view (snapshots are always Pro), while GatedEntries is derived by
// parsing the frozen canonical entry bytes. Selector text is never trusted as
// a confidentiality signal.
type offlineArchiveSourceProof struct {
	ID              string                    `json:"id"`
	Snapshot        bool                      `json:"snapshot,omitempty"`
	Access          string                    `json:"access"`
	ExcludedPath    string                    `json:"excluded_path,omitempty"`
	Refs            []offlineArchiveSourceRef `json:"refs"`
	EntriesSHA256   string                    `json:"entries_sha256"`
	Entries         int64                     `json:"entries"`
	GatedEntries    int64                     `json:"gated_entries"`
	DebugEntries    int64                     `json:"debug_entries"`
	Confidentiality string                    `json:"confidentiality"`
}

type offlineArchiveDestinationProof struct {
	Repo string `json:"repo"`
	Pool string `json:"pool"`
	View string `json:"view"`
	Path string `json:"path"`
}

// offlineArchiveAdoptionContract closes the two local transactions involved in
// materialize --tgz --asset-repo. It binds source policy and canonical bytes to
// the final archive bytes and to the exact destination repo/pool/view/path.
// The complete contract is included in the selected-set journal identity.
type offlineArchiveAdoptionContract struct {
	Schema        string                         `json:"schema"`
	ID            string                         `json:"id"`
	Source        offlineArchiveSourceProof      `json:"source"`
	ArchiveSHA256 string                         `json:"archive_sha256"`
	ArchiveSize   int64                          `json:"archive_size"`
	Destination   offlineArchiveDestinationProof `json:"destination"`
}

type offlineArchiveAdoptionPreflight struct {
	Source      offlineArchiveSourceProof
	Destination offlineArchiveDestinationProof
}

// offlineArchiveTaintReceipt is the canonical, path-independent memory of an
// archive's strongest observed confidentiality. Receipts are keyed by archive
// digest and never deleted or downgraded by ordinary lifecycle/GC operations.
// Keeping one witness is sufficient because replacement is permitted only when
// it raises public to gated; the digest and size remain invariant.
type offlineArchiveTaintReceipt struct {
	Schema          string                    `json:"schema"`
	ID              string                    `json:"id"`
	ArchiveSHA256   string                    `json:"archive_sha256"`
	ArchiveSize     int64                     `json:"archive_size"`
	Confidentiality string                    `json:"confidentiality"`
	Source          offlineArchiveSourceProof `json:"source"`
}

type offlineArchiveMarker struct {
	SourceSHA256    string
	Access          string
	Confidentiality string
}

// offlineArchivePayloadMarker is the in-band copy of the gzip FCOMMENT policy
// marker. It is deliberately the first tar entry, so removing only mutable
// gzip header bytes cannot remove or downgrade the archive's taint. This is an
// integrity tripwire, not an unforgeable signature: an actor able to unpack,
// rewrite the envelope, and rebuild the tar/gzip stream can remove both copies.
// Closing that stronger boundary requires an external signature/trust anchor.
type offlineArchivePayloadMarker struct {
	Schema          string `json:"schema"`
	SourceSHA256    string `json:"source_sha256"`
	Access          string `json:"access"`
	Confidentiality string `json:"confidentiality"`
}

type inspectedOfflineArchiveInput struct {
	Object repository.Object
	Marker *offlineArchiveMarker
}

// These hooks bracket the single-pass marker decision for deterministic
// in-place mutation tests. Production never sets them.
var offlineArchiveInputAfterHeaderPeekHook func(*os.File) error
var offlineArchiveInputAfterMarkerHook func(*os.File) error

func offlineArchiveSourceProofSHA256(proof offlineArchiveSourceProof) (string, error) {
	if err := proof.validate(); err != nil {
		return "", err
	}
	semanticRefs := append([]offlineArchiveSourceRef(nil), proof.Refs...)
	for index := range semanticRefs {
		semanticRefs[index].Commit = ""
	}
	body, err := json.Marshal(struct {
		ID              string                    `json:"id"`
		Snapshot        bool                      `json:"snapshot,omitempty"`
		Access          string                    `json:"access"`
		ExcludedPath    string                    `json:"excluded_path,omitempty"`
		Refs            []offlineArchiveSourceRef `json:"refs"`
		EntriesSHA256   string                    `json:"entries_sha256"`
		Entries         int64                     `json:"entries"`
		GatedEntries    int64                     `json:"gated_entries"`
		DebugEntries    int64                     `json:"debug_entries"`
		Confidentiality string                    `json:"confidentiality"`
	}{proof.ID, proof.Snapshot, proof.Access, proof.ExcludedPath, semanticRefs, proof.EntriesSHA256, proof.Entries, proof.GatedEntries, proof.DebugEntries, proof.Confidentiality})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func offlineArchiveMarkerForSource(proof offlineArchiveSourceProof) (string, error) {
	digest, err := offlineArchiveSourceProofSHA256(proof)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%ssource_sha256=%s;access=%s;confidentiality=%s", offlineArchiveMarkerPrefix, digest, proof.Access, proof.Confidentiality), nil
}

func offlineArchivePayloadMarkerForComment(comment string) ([]byte, error) {
	marker, err := parseOfflineArchiveMarker(comment)
	if err != nil || marker == nil {
		return nil, errors.Join(err, errors.New("offline archive payload marker source is invalid"))
	}
	envelope := offlineArchivePayloadMarker{
		Schema:          offlineArchivePayloadMarkerSchema,
		SourceSHA256:    marker.SourceSHA256,
		Access:          marker.Access,
		Confidentiality: marker.Confidentiality,
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func parseOfflineArchiveMarker(comment string) (*offlineArchiveMarker, error) {
	if !strings.HasPrefix(comment, "sow-offline-archive/") {
		return nil, nil
	}
	parts := strings.Split(comment, ";")
	if len(parts) != 4 || parts[0] != "sow-offline-archive/v1" || !strings.HasPrefix(parts[1], "source_sha256=") ||
		!strings.HasPrefix(parts[2], "access=") || !strings.HasPrefix(parts[3], "confidentiality=") {
		return nil, errors.New("malformed SOW offline archive marker")
	}
	marker := &offlineArchiveMarker{
		SourceSHA256:    strings.TrimPrefix(parts[1], "source_sha256="),
		Access:          strings.TrimPrefix(parts[2], "access="),
		Confidentiality: strings.TrimPrefix(parts[3], "confidentiality="),
	}
	if !validMaterializationTrustSHA256(marker.SourceSHA256) || (marker.Access != "public" && marker.Access != "pro") ||
		(marker.Confidentiality != "public" && marker.Confidentiality != "gated") ||
		(marker.Access == "pro" && marker.Confidentiality != "gated") {
		return nil, errors.New("invalid SOW offline archive marker policy")
	}
	return marker, nil
}

func inspectOfflineArchiveInput(filename string) (inspectedOfflineArchiveInput, error) {
	return inspectOfflineArchiveInputWithLimits(context.Background(), filename, defaultOfflineArchiveInspectionLimits)
}

func inspectOfflineArchiveInputContext(ctx context.Context, filename string) (inspectedOfflineArchiveInput, error) {
	return inspectOfflineArchiveInputWithLimits(ctx, filename, defaultOfflineArchiveInspectionLimits)
}

func inspectOfflineArchiveInputWithLimits(ctx context.Context, filename string, limits offlineArchiveInspectionLimits) (inspectedOfflineArchiveInput, error) {
	var inspected inspectedOfflineArchiveInput
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return inspected, err
	}
	if limits.MaxExpandedBytes <= 0 || limits.MaxMembers <= 0 || limits.MaxExpansionRatio <= 0 || limits.ExpansionSlack < 0 {
		return inspected, errors.New("invalid offline archive inspection limits")
	}
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return inspected, errors.Join(err, errors.New("offline archive input is not a regular file"))
	}
	file, err := os.Open(filename)
	if err != nil {
		return inspected, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		file.Close()
		return inspected, errors.Join(err, errors.New("offline archive input changed while opening"))
	}
	// Hash the exact byte stream consumed by marker inspection. The former
	// hash-then-seek design let an in-place writer present different bytes to
	// the two passes while restoring inode/size/mtime. ImportExpected later
	// binds the admitted digest to the copied object; this single pass binds
	// that same digest to the marker decision as well.
	hasher := sha256.New()
	counter := &offlineArchiveByteCounter{}
	hashedInput := io.TeeReader(file, io.MultiWriter(hasher, counter))
	input := bufio.NewReaderSize(hashedInput, 64*1024)
	header, peekErr := input.Peek(64 * 1024)
	if peekErr != nil && !errors.Is(peekErr, io.EOF) && !errors.Is(peekErr, bufio.ErrBufferFull) {
		file.Close()
		return inspected, peekErr
	}
	headerMarker, headerComplete, err := parseOfflineArchiveMarkerHeaderStatus(header)
	if err != nil {
		file.Close()
		return inspected, err
	}
	if offlineArchiveInputAfterHeaderPeekHook != nil {
		if err := offlineArchiveInputAfterHeaderPeekHook(file); err != nil {
			file.Close()
			return inspected, err
		}
	}
	meter := &offlineArchiveInspectionMeter{limits: limits}
	payloadMarker, err := inspectOfflineArchivePayloadMarker(ctx, input, headerMarker, headerComplete, len(header) >= 2 && header[0] == 0x1f && header[1] == 0x8b, meter)
	if err != nil {
		file.Close()
		return inspected, err
	}
	if offlineArchiveInputAfterMarkerHook != nil {
		if err := offlineArchiveInputAfterMarkerHook(file); err != nil {
			file.Close()
			return inspected, err
		}
	}
	marker, err := reconcileOfflineArchiveMarkers(headerMarker, payloadMarker)
	if err != nil {
		file.Close()
		return inspected, err
	}
	if _, err := io.Copy(io.Discard, input); err != nil {
		file.Close()
		return inspected, err
	}
	written := counter.Written
	openedAfter, openedErr := file.Stat()
	closeErr := file.Close()
	after, afterErr := os.Lstat(filename)
	if openedErr != nil || closeErr != nil || afterErr != nil || written != info.Size() || openedAfter.Size() != info.Size() ||
		after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || after.Size() != info.Size() ||
		!openedAfter.ModTime().Equal(info.ModTime()) || !after.ModTime().Equal(info.ModTime()) || !os.SameFile(info, openedAfter) || !os.SameFile(info, after) {
		return inspected, errors.Join(openedErr, closeErr, afterErr, errors.New("offline archive input changed during inspection"))
	}
	digest, err := repository.ParseDigest(hex.EncodeToString(hasher.Sum(nil)))
	if err != nil {
		return inspected, err
	}
	inspected.Object = repository.Object{SHA256: digest, Size: written}
	inspected.Marker = marker
	return inspected, nil
}

type offlineArchiveByteCounter struct {
	Written int64
}

func (counter *offlineArchiveByteCounter) Write(body []byte) (int, error) {
	counter.Written += int64(len(body))
	return len(body), nil
}

func inspectOfflineArchivePayloadMarker(ctx context.Context, input *bufio.Reader, headerMarker *offlineArchiveMarker, headerComplete, startsWithGzip bool, meter *offlineArchiveInspectionMeter) (*offlineArchiveMarker, error) {
	if !startsWithGzip {
		return inspectOfflineArchiveEmbeddedGzipMarker(ctx, input, meter)
	}
	// Parse the gzip envelope ourselves rather than through compress/gzip.
	// The standard reader rejects otherwise valid FNAME/FCOMMENT fields after
	// 512 bytes, which made an ordinary opaque gzip asset depend on a Go
	// implementation limit. The bounded parser below keeps no unbounded field
	// in memory, validates FHCRC/CRC32/ISIZE, and leaves the shared ByteReader at
	// the exact next-member boundary. Ordinary marker-free multi-member gzip
	// assets remain admissible; once any SOW marker is present, the archive must
	// be exactly one self-contained member.
	var observed *offlineArchiveMarker
	members := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, peekErr := input.Peek(1); errors.Is(peekErr, io.EOF) {
			break
		} else if peekErr != nil {
			return nil, peekErr
		}
		if members >= meter.limits.MaxMembers {
			return nil, fmt.Errorf("%w: gzip member count exceeds %d", errOfflineArchiveInspectionBudget, meter.limits.MaxMembers)
		}
		compressed, err := openOfflineArchiveGzipMember(ctx, input, meter)
		if err != nil {
			return nil, errors.Join(err, fmt.Errorf("SOW offline archive has invalid gzip framing after %d complete member(s)", members))
		}

		if strings.HasPrefix(compressed.Name, "sow-offline-archive/") {
			return nil, errors.New("SOW offline archive marker is stored in gzip filename instead of FCOMMENT")
		}
		memberHeader, markerErr := parseOfflineArchiveMarker(compressed.Comment)
		if markerErr != nil {
			return nil, markerErr
		}
		if members == 0 && headerComplete && !offlineArchiveMarkersEqual(headerMarker, memberHeader) {
			return nil, errors.New("SOW offline archive gzip header changed during inspection")
		}

		payloadMarker, tarObserved, tarErr := inspectOfflineArchiveTarMember(compressed)
		if finishErr := compressed.Finish(); finishErr != nil {
			return nil, errors.Join(finishErr, errors.New("SOW offline archive compressed payload failed validation"))
		}
		members++

		if tarErr != nil {
			if tarObserved || observed != nil || headerMarker != nil || memberHeader != nil || payloadMarker != nil || errors.Is(tarErr, errOfflineArchivePolicyEnvelope) {
				return nil, errors.Join(tarErr, errors.New("SOW offline archive tar stream is invalid"))
			}
			// Keep scanning subsequent gzip members: a non-tar prefix must not
			// conceal a later member carrying a SOW marker.
			continue
		}
		memberMarker, err := reconcileOfflineArchiveMarkers(memberHeader, payloadMarker)
		if err != nil {
			return nil, err
		}
		if memberMarker != nil {
			if observed != nil {
				return nil, errors.New("SOW offline archive marker is duplicated across gzip members")
			}
			observed = memberMarker
		}
	}
	if observed != nil && members != 1 {
		return nil, errors.New("SOW offline archive must contain exactly one gzip member")
	}
	if headerMarker != nil && observed == nil {
		return nil, errors.New("SOW offline archive gzip marker has no first-entry payload marker")
	}
	return observed, nil
}

// inspectOfflineArchiveEmbeddedGzipMarker closes the trivial laundering case
// where a byte prefix is placed before an otherwise unchanged SOW gzip. SOW
// archives have a frozen deterministic envelope: zero MTIME, best-compression
// XFL=2, and OS=255. Only that envelope is an embedded archive candidate.
// Treating every incidental 1f8b byte pair as gzip made arbitrary opaque
// assets (notably compressed source archives) fail admission, while parsing
// arbitrary embedded gzip members is neither a policy proof nor a safe file
// type detector. Header flag corruption remains fail-closed because flags are
// deliberately excluded from the fingerprint; the exact member/tar walk still
// proves the in-band marker for header-stripped SOW archives.
func inspectOfflineArchiveEmbeddedGzipMarker(ctx context.Context, input *bufio.Reader, meter *offlineArchiveInspectionMeter) (*offlineArchiveMarker, error) {
	const retainedHeaderBytes = 9
	candidates := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		prefix, err := input.Peek(input.Size())
		if errors.Is(err, io.EOF) {
			if index := embeddedOfflineArchiveGzipCandidate(prefix); index >= 0 {
				_, _ = input.Discard(index)
				candidates++
				if candidates > meter.limits.MaxMembers {
					return nil, fmt.Errorf("%w: embedded gzip candidate count exceeds %d", errOfflineArchiveInspectionBudget, meter.limits.MaxMembers)
				}
				if _, inspectErr := inspectEmbeddedOfflineArchiveGzipCandidate(ctx, input, meter); inspectErr != nil {
					return nil, inspectErr
				}
				continue
			}
			_, _ = input.Discard(len(prefix))
			return nil, nil
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
		if index := embeddedOfflineArchiveGzipCandidate(prefix); index >= 0 {
			_, _ = input.Discard(index)
			candidates++
			if candidates > meter.limits.MaxMembers {
				return nil, fmt.Errorf("%w: embedded gzip candidate count exceeds %d", errOfflineArchiveInspectionBudget, meter.limits.MaxMembers)
			}
			if _, inspectErr := inspectEmbeddedOfflineArchiveGzipCandidate(ctx, input, meter); inspectErr != nil {
				return nil, inspectErr
			}
			continue
		}
		// Retain a complete partial header so a candidate split across buffers
		// remains visible to the next Peek.
		if _, err := input.Discard(len(prefix) - retainedHeaderBytes); err != nil {
			return nil, err
		}
	}
}

func embeddedOfflineArchiveGzipCandidate(body []byte) int {
	for offset := 0; offset+10 <= len(body); {
		index := bytes.Index(body[offset:], []byte{0x1f, 0x8b, 0x08})
		if index < 0 {
			return -1
		}
		index += offset
		if index+10 > len(body) {
			return -1
		}
		// gzip flags are intentionally not constrained. A copied SOW envelope
		// with a stripped FCOMMENT has flags=0, while a malformed/reserved flag
		// must still reach the exact parser and fail closed.
		if body[index+4] == 0 && body[index+5] == 0 && body[index+6] == 0 && body[index+7] == 0 &&
			body[index+8] == 2 && body[index+9] == 255 {
			return index
		}
		offset = index + 1
	}
	return -1
}

func inspectEmbeddedOfflineArchiveGzipCandidate(ctx context.Context, input *bufio.Reader, meter *offlineArchiveInspectionMeter) (*offlineArchiveMarker, error) {
	compressed, err := openOfflineArchiveGzipMember(ctx, input, meter)
	if err != nil {
		return nil, errors.Join(err, errors.New("opaque prefix contains an invalid embedded gzip stream"))
	}
	if strings.HasPrefix(compressed.Name, "sow-offline-archive/") {
		return nil, errors.New("SOW offline archive marker is stored in gzip filename instead of FCOMMENT")
	}
	headerMarker, markerErr := parseOfflineArchiveMarker(compressed.Comment)
	if markerErr != nil {
		return nil, markerErr
	}
	payloadMarker, tarObserved, tarErr := inspectOfflineArchiveTarMember(compressed)
	if finishErr := compressed.Finish(); finishErr != nil {
		return nil, errors.Join(finishErr, errors.New("opaque prefix contains an invalid embedded gzip stream"))
	}
	if tarErr != nil {
		if tarObserved || headerMarker != nil || payloadMarker != nil || errors.Is(tarErr, errOfflineArchivePolicyEnvelope) {
			return nil, errors.Join(tarErr, errors.New("SOW offline archive tar stream is invalid behind an opaque prefix"))
		}
		// A complete marker-free embedded gzip is ordinary opaque content. Its
		// exact member has been consumed; the caller resumes scanning at the
		// following byte instead of requiring the host-file suffix to be gzip.
		return nil, nil
	}
	marker, err := reconcileOfflineArchiveMarkers(headerMarker, payloadMarker)
	if err != nil {
		return nil, err
	}
	if marker != nil {
		return nil, errors.New("SOW offline archive marker is hidden behind an opaque prefix")
	}
	return nil, nil
}

const offlineArchiveGzipFieldCaptureLimit = 4096

// offlineArchiveGzipMember is a single exact gzip member. flate.NewReader is
// given a bufio.Reader (and therefore an io.ByteReader), so it cannot consume
// bytes past the deflate terminator. Finish then validates and consumes the
// eight-byte gzip trailer before the caller attempts to open the next member.
type offlineArchiveGzipMember struct {
	input           *bufio.Reader
	deflate         io.ReadCloser
	crc             hash32Writer
	size            uint32
	done            bool
	ctx             context.Context
	meter           *offlineArchiveInspectionMeter
	compressedBytes int64
	expandedBytes   int64
	readErr         error
	Name            string
	Comment         string
}

// hash32Writer is the small part of hash.Hash32 used by the streaming member.
// Keeping the interface local makes the exact checksum state explicit.
type hash32Writer interface {
	Write([]byte) (int, error)
	Sum32() uint32
}

func openOfflineArchiveGzipMember(ctx context.Context, input *bufio.Reader, meter *offlineArchiveInspectionMeter) (*offlineArchiveGzipMember, error) {
	if input == nil {
		return nil, errors.New("gzip input is unavailable")
	}
	if ctx == nil || meter == nil {
		return nil, errors.New("gzip inspection state is unavailable")
	}
	member := &offlineArchiveGzipMember{input: input, crc: crc32.NewIEEE(), ctx: ctx, meter: meter}
	readFull := func(body []byte) error {
		read, err := io.ReadFull(input, body)
		member.compressedBytes += int64(read)
		return err
	}
	headerCRC := crc32.NewIEEE()
	fixed := make([]byte, 10)
	if err := readFull(fixed); err != nil {
		return nil, errors.Join(err, errors.New("truncated gzip header"))
	}
	_, _ = headerCRC.Write(fixed)
	if fixed[0] != 0x1f || fixed[1] != 0x8b || fixed[2] != 8 || fixed[3]&0xe0 != 0 {
		return nil, errors.New("invalid gzip header")
	}
	flags := fixed[3]
	readHeaderBytes := func(size int) ([]byte, error) {
		body := make([]byte, size)
		if err := readFull(body); err != nil {
			return nil, err
		}
		_, _ = headerCRC.Write(body)
		return body, nil
	}
	if flags&0x04 != 0 {
		lengthBytes, err := readHeaderBytes(2)
		if err != nil {
			return nil, errors.Join(err, errors.New("truncated gzip extra length"))
		}
		length := int(binary.LittleEndian.Uint16(lengthBytes))
		if _, err := readHeaderBytes(length); err != nil {
			return nil, errors.Join(err, errors.New("truncated gzip extra field"))
		}
	}
	readHeaderString := func(field string) (string, bool, error) {
		captured := make([]byte, 0, 256)
		truncated := false
		for {
			value, err := input.ReadByte()
			if err == nil {
				member.compressedBytes++
			}
			if err != nil {
				return "", false, errors.Join(err, fmt.Errorf("unterminated gzip %s", field))
			}
			_, _ = headerCRC.Write([]byte{value})
			if value == 0 {
				return string(captured), truncated, nil
			}
			if len(captured) < offlineArchiveGzipFieldCaptureLimit {
				captured = append(captured, value)
			} else {
				truncated = true
			}
		}
	}
	if flags&0x08 != 0 {
		name, truncated, err := readHeaderString("filename")
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(name, "sow-offline-archive/") {
			return nil, errors.New("SOW offline archive marker is stored in gzip filename instead of FCOMMENT")
		}
		if !truncated {
			member.Name = name
		}
	}
	if flags&0x10 != 0 {
		comment, truncated, err := readHeaderString("comment")
		if err != nil {
			return nil, err
		}
		if truncated && strings.HasPrefix(comment, "sow-offline-archive/") {
			return nil, errors.New("malformed SOW offline archive marker")
		}
		if !truncated {
			member.Comment = comment
		}
	}
	if flags&0x02 != 0 {
		var expected [2]byte
		if err := readFull(expected[:]); err != nil {
			return nil, errors.Join(err, errors.New("truncated gzip header checksum"))
		}
		if binary.LittleEndian.Uint16(expected[:]) != uint16(headerCRC.Sum32()) {
			return nil, errors.New("gzip header checksum mismatch")
		}
	}
	member.deflate = flate.NewReader(&offlineArchiveCompressedCounter{reader: input, count: &member.compressedBytes})
	return member, nil
}

type offlineArchiveCompressedCounter struct {
	reader *bufio.Reader
	count  *int64
}

func (counter *offlineArchiveCompressedCounter) Read(body []byte) (int, error) {
	read, err := counter.reader.Read(body)
	*counter.count += int64(read)
	return read, err
}

func (counter *offlineArchiveCompressedCounter) ReadByte() (byte, error) {
	value, err := counter.reader.ReadByte()
	if err == nil {
		*counter.count++
	}
	return value, err
}

func (member *offlineArchiveGzipMember) Read(body []byte) (int, error) {
	if member == nil || member.deflate == nil || member.done {
		return 0, io.EOF
	}
	if member.readErr != nil {
		return 0, member.readErr
	}
	read, err := member.deflate.Read(body)
	if read != 0 {
		_, _ = member.crc.Write(body[:read])
		member.size += uint32(read)
		member.expandedBytes += int64(read)
		member.meter.expanded += int64(read)
		if member.meter.expanded > member.meter.limits.MaxExpandedBytes {
			member.readErr = fmt.Errorf("%w: expanded bytes exceed %d", errOfflineArchiveInspectionBudget, member.meter.limits.MaxExpandedBytes)
			return read, member.readErr
		}
		allowed := member.meter.limits.ExpansionSlack + member.compressedBytes*member.meter.limits.MaxExpansionRatio
		if member.expandedBytes > allowed {
			member.readErr = fmt.Errorf("%w: gzip expansion exceeds ratio %d with slack %d", errOfflineArchiveInspectionBudget, member.meter.limits.MaxExpansionRatio, member.meter.limits.ExpansionSlack)
			return read, member.readErr
		}
	}
	if ctxErr := member.ctx.Err(); ctxErr != nil {
		member.readErr = ctxErr
		return read, ctxErr
	}
	return read, err
}

func (member *offlineArchiveGzipMember) Finish() error {
	if member == nil || member.deflate == nil {
		return errors.New("gzip member is unavailable")
	}
	if member.done {
		return nil
	}
	_, drainErr := io.Copy(io.Discard, member)
	closeErr := member.deflate.Close()
	member.done = true
	if drainErr != nil || closeErr != nil {
		return errors.Join(drainErr, closeErr)
	}
	var trailer [8]byte
	if _, err := io.ReadFull(member.input, trailer[:]); err != nil {
		return errors.Join(err, errors.New("truncated gzip trailer"))
	}
	if binary.LittleEndian.Uint32(trailer[:4]) != member.crc.Sum32() {
		return errors.New("gzip payload checksum mismatch")
	}
	if binary.LittleEndian.Uint32(trailer[4:]) != member.size {
		return errors.New("gzip payload size mismatch")
	}
	return nil
}

func inspectOfflineArchiveTarMember(compressed io.Reader) (*offlineArchiveMarker, bool, error) {
	input := bufio.NewReaderSize(compressed, 32*1024)
	var payloadMarker *offlineArchiveMarker
	entryIndex := 0
	tarObserved := false
	for {
		firstBlocks, firstErr := input.Peek(1024)
		firstBlockProof := append([]byte(nil), firstBlocks...)
		candidateEmptyTar := (firstErr == nil || errors.Is(firstErr, bufio.ErrBufferFull)) && len(firstBlocks) >= 1024 && bytes.Count(firstBlocks[:1024], []byte{0}) == 1024
		archive := tar.NewReader(input)
		for {
			header, nextErr := archive.Next()
			if errors.Is(nextErr, io.EOF) {
				tarObserved = tarObserved || candidateEmptyTar
				break
			}
			if nextErr != nil {
				if !tarObserved && !errors.Is(nextErr, errOfflineArchiveInspectionBudget) && !errors.Is(nextErr, context.Canceled) && !errors.Is(nextErr, context.DeadlineExceeded) {
					if offlineArchivePolicyBytesPresent(firstBlockProof) {
						return payloadMarker, false, errors.Join(errOfflineArchivePolicyEnvelope, errors.New("SOW offline archive marker is hidden behind malformed tar bytes"))
					}
					if err := rejectOfflineArchivePolicyBytes(input); err != nil {
						return payloadMarker, false, err
					}
					// A gzip payload that never presented a valid tar header or
					// end-of-archive remains an opaque ordinary asset. Its complete
					// remaining stream was nevertheless checked for the reserved
					// policy names before admission.
					return nil, false, nil
				}
				return payloadMarker, tarObserved, nextErr
			}
			tarObserved = true
			reserved := offlineArchivePayloadMarkerPathEquivalent(header.Name)
			if reserved && header.Name != offlineArchivePayloadMarkerPath {
				return payloadMarker, tarObserved, errors.Join(errOfflineArchivePolicyEnvelope, errors.New("SOW offline archive payload marker path is not canonical"))
			}
			if reserved && entryIndex != 0 {
				return payloadMarker, tarObserved, errors.Join(errOfflineArchivePolicyEnvelope, errors.New("SOW offline archive payload marker is not the first tar entry or is duplicated"))
			}
			if reserved {
				if payloadMarker != nil {
					return payloadMarker, tarObserved, errors.Join(errOfflineArchivePolicyEnvelope, errors.New("SOW offline archive payload marker is duplicated"))
				}
				if header.Typeflag != tar.TypeReg || header.Linkname != "" || header.Size <= 0 || header.Size > 4096 ||
					header.Mode != 0o444 || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" ||
					header.Devmajor != 0 || header.Devminor != 0 || !header.ModTime.Equal(time.Unix(0, 0).UTC()) ||
					!header.AccessTime.IsZero() || !header.ChangeTime.IsZero() || header.Format != tar.FormatUSTAR ||
					len(header.PAXRecords) != 0 {
					return payloadMarker, tarObserved, errors.Join(errOfflineArchivePolicyEnvelope, errors.New("SOW offline archive payload marker has an unsafe tar envelope"))
				}
				body, readErr := io.ReadAll(io.LimitReader(archive, header.Size+1))
				if readErr != nil || int64(len(body)) != header.Size {
					return payloadMarker, tarObserved, errors.Join(errOfflineArchivePolicyEnvelope, readErr, errors.New("SOW offline archive payload marker is truncated"))
				}
				payloadMarker, nextErr = parseOfflineArchivePayloadMarker(body)
				if nextErr != nil {
					return payloadMarker, tarObserved, errors.Join(errOfflineArchivePolicyEnvelope, nextErr)
				}
			}
			entryIndex++
		}
		// archive/tar stops at the first two zero blocks. Consume any further
		// zero padding, then keep parsing if another tar stream follows in the
		// same gzip member. A policy marker in that tail is therefore observed
		// and rejected as non-first instead of being discarded by the caller's
		// final gzip drain.
		for {
			block, peekErr := input.Peek(512)
			if errors.Is(peekErr, io.EOF) {
				if len(block) == 0 {
					return payloadMarker, tarObserved, nil
				}
				if bytes.Count(block, []byte{0}) == len(block) {
					_, _ = input.Discard(len(block))
					return payloadMarker, tarObserved, nil
				}
				return payloadMarker, tarObserved, errors.New("non-zero partial data follows tar end-of-archive")
			}
			if peekErr != nil {
				return payloadMarker, tarObserved, peekErr
			}
			if bytes.Count(block, []byte{0}) != len(block) {
				break
			}
			_, _ = input.Discard(len(block))
		}
	}
}

func offlineArchivePolicyBytesPresent(body []byte) bool {
	return bytes.Contains(body, []byte(offlineArchivePayloadMarkerPath)) ||
		bytes.Contains(body, []byte("sow-offline-archive/"))
}

func rejectOfflineArchivePolicyBytes(input io.Reader) error {
	const overlap = 64
	buffer := make([]byte, 64*1024+overlap)
	retained := 0
	for {
		read, err := input.Read(buffer[retained : len(buffer)-overlap+retained])
		if offlineArchivePolicyBytesPresent(buffer[:retained+read]) {
			return errors.Join(errOfflineArchivePolicyEnvelope, errors.New("SOW offline archive marker is hidden behind malformed tar bytes"))
		}
		if read != 0 {
			total := retained + read
			retained = min(overlap, total)
			copy(buffer[:retained], buffer[total-retained:total])
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func offlineArchiveMarkersEqual(left, right *offlineArchiveMarker) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func offlineArchivePayloadMarkerPathEquivalent(value string) bool {
	return path.Clean(value) == offlineArchivePayloadMarkerPath
}

func parseOfflineArchivePayloadMarker(body []byte) (*offlineArchiveMarker, error) {
	if len(body) == 0 || len(body) > 4096 {
		return nil, errors.New("SOW offline archive payload marker has unsafe size")
	}
	var envelope offlineArchivePayloadMarker
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&envelope)
	var trailing any
	trailingErr := decoder.Decode(&trailing)
	if decodeErr != nil || !errors.Is(trailingErr, io.EOF) {
		return nil, errors.Join(decodeErr, trailingErr, errors.New("decode SOW offline archive payload marker"))
	}
	if envelope.Schema != offlineArchivePayloadMarkerSchema {
		return nil, errors.New("SOW offline archive payload marker schema is invalid")
	}
	comment := fmt.Sprintf("%ssource_sha256=%s;access=%s;confidentiality=%s", offlineArchiveMarkerPrefix, envelope.SourceSHA256, envelope.Access, envelope.Confidentiality)
	marker, err := parseOfflineArchiveMarker(comment)
	if err != nil || marker == nil {
		return nil, errors.Join(err, errors.New("SOW offline archive payload marker policy is invalid"))
	}
	canonical, err := offlineArchivePayloadMarkerForComment(comment)
	if err != nil || !bytes.Equal(body, canonical) {
		return nil, errors.Join(err, errors.New("SOW offline archive payload marker is not canonical"))
	}
	return marker, nil
}

func reconcileOfflineArchiveMarkers(header, payload *offlineArchiveMarker) (*offlineArchiveMarker, error) {
	if header == nil {
		return payload, nil
	}
	if payload == nil {
		return nil, errors.New("SOW offline archive gzip marker has no first-entry payload marker")
	}
	if *header != *payload {
		return nil, errors.New("SOW offline archive gzip and payload markers differ")
	}
	return payload, nil
}

func parseOfflineArchiveMarkerHeader(header []byte) (*offlineArchiveMarker, error) {
	marker, _, err := parseOfflineArchiveMarkerHeaderStatus(header)
	return marker, err
}

func parseOfflineArchiveMarkerHeaderStatus(header []byte) (*offlineArchiveMarker, bool, error) {
	if len(header) < 2 || header[0] != 0x1f || header[1] != 0x8b {
		return nil, true, nil
	}
	// Never search the whole bounded prefix for marker bytes: it includes the
	// compressed payload, and arbitrary opaque gzip data may contain the same
	// byte sequence. A fail-closed marker decision is made only after the gzip
	// header grammar identifies FNAME or FCOMMENT as the containing field.
	malformedField := func(value []byte) (*offlineArchiveMarker, error) {
		if bytes.HasPrefix(value, []byte("sow-offline-archive/")) {
			return nil, errors.New("malformed bounded SOW gzip marker header")
		}
		return nil, nil
	}
	if len(header) < 10 || header[2] != 8 || header[3]&0xe0 != 0 {
		return nil, false, nil
	}
	flags := header[3]
	offset := 10
	if flags&0x04 != 0 {
		if offset+2 > len(header) {
			return nil, false, nil
		}
		extraLength := int(header[offset]) | int(header[offset+1])<<8
		offset += 2
		if extraLength < 0 || offset+extraLength > len(header) {
			return nil, false, nil
		}
		offset += extraLength
	}
	consumeTerminated := func() ([]byte, bool) {
		if offset >= len(header) {
			return nil, false
		}
		end := bytes.IndexByte(header[offset:], 0)
		if end < 0 {
			return nil, false
		}
		value := header[offset : offset+end]
		offset += end + 1
		return value, true
	}
	if flags&0x08 != 0 {
		if value, ok := consumeTerminated(); !ok {
			marker, markerErr := malformedField(header[offset:])
			return marker, false, markerErr
		} else if bytes.HasPrefix(value, []byte("sow-offline-archive/")) {
			return nil, true, errors.New("SOW offline archive marker is stored in gzip filename instead of FCOMMENT")
		}
	}
	var comment []byte
	if flags&0x10 != 0 {
		var ok bool
		comment, ok = consumeTerminated()
		if !ok {
			marker, markerErr := malformedField(header[offset:])
			return marker, false, markerErr
		}
	}
	if flags&0x02 != 0 && offset+2 > len(header) {
		marker, markerErr := malformedField(comment)
		return marker, false, markerErr
	}
	marker, err := parseOfflineArchiveMarker(string(comment))
	return marker, true, err
}

func requireOfflineArchiveMarkerAdmission(marker *offlineArchiveMarker, destination config.Repo, receipt *offlineArchiveTaintReceipt, source *offlineArchiveSourceProof) error {
	if marker == nil {
		if receipt != nil || source != nil {
			return errors.New("contracted SOW offline archive is missing its gzip policy marker")
		}
		return nil
	}
	if marker.Confidentiality != "public" && destination.DefaultPool == "public" {
		return fmt.Errorf("SOW gzip marker rejects %s archive from public asset repo %s", marker.Confidentiality, destination.ID)
	}
	if receipt != nil {
		digest, err := offlineArchiveSourceProofSHA256(receipt.Source)
		if err != nil || marker.SourceSHA256 != digest || marker.Access != receipt.Source.Access || marker.Confidentiality != receipt.Confidentiality {
			return errors.Join(err, errors.New("SOW gzip marker differs from canonical digest taint receipt"))
		}
	}
	if source != nil {
		digest, err := offlineArchiveSourceProofSHA256(*source)
		if err != nil || marker.SourceSHA256 != digest || marker.Access != source.Access || marker.Confidentiality != source.Confidentiality {
			return errors.Join(err, errors.New("SOW gzip marker differs from offline archive source contract"))
		}
	}
	return nil
}

func offlineArchiveTaintReceiptPath(digest string) (string, error) {
	if !validMaterializationTrustSHA256(digest) {
		return "", errors.New("invalid offline archive receipt digest")
	}
	return path.Join("archive-taint", "sha256", digest[:2], digest+".json"), nil
}

func offlineArchiveTaintReceiptID(receipt offlineArchiveTaintReceipt) (string, error) {
	receipt.ID = ""
	body, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func (receipt offlineArchiveTaintReceipt) validate() error {
	if receipt.Schema != offlineArchiveTaintReceiptSchema || !validMaterializationTrustSHA256(receipt.ArchiveSHA256) ||
		receipt.ArchiveSize < 0 || receipt.Confidentiality != receipt.Source.Confidentiality {
		return errors.New("invalid offline archive taint receipt envelope")
	}
	if err := receipt.Source.validate(); err != nil {
		return err
	}
	wanted, err := offlineArchiveTaintReceiptID(receipt)
	if err != nil || receipt.ID != wanted {
		return errors.Join(err, errors.New("offline archive taint receipt ID mismatch"))
	}
	return nil
}

func cloneOfflineArchiveAdoptionContract(contract *offlineArchiveAdoptionContract) *offlineArchiveAdoptionContract {
	if contract == nil {
		return nil
	}
	cloned := *contract
	cloned.Source.Refs = append([]offlineArchiveSourceRef(nil), contract.Source.Refs...)
	return &cloned
}

func offlineArchiveAdoptionContractID(contract offlineArchiveAdoptionContract) (string, error) {
	contract.ID = ""
	body, err := json.Marshal(contract)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func (contract offlineArchiveAdoptionContract) validate() error {
	if contract.Schema != offlineArchiveAdoptionContractSchema || !validMaterializationTrustSHA256(contract.ArchiveSHA256) || contract.ArchiveSize < 0 {
		return errors.New("invalid offline archive adoption contract envelope")
	}
	if err := contract.Source.validate(); err != nil {
		return err
	}
	if err := contract.Destination.validate(); err != nil {
		return err
	}
	wanted, err := offlineArchiveAdoptionContractID(contract)
	if err != nil || contract.ID != wanted {
		return errors.Join(err, errors.New("offline archive adoption contract ID mismatch"))
	}
	return nil
}

func (proof offlineArchiveSourceProof) validate() error {
	if !validMaterializationJournalString(proof.ID, 256) || (proof.Access != "public" && proof.Access != "pro") ||
		(proof.Confidentiality != "public" && proof.Confidentiality != "gated") || !validMaterializationTrustSHA256(proof.EntriesSHA256) ||
		len(proof.Refs) == 0 || proof.Entries < 0 || proof.GatedEntries < 0 || proof.DebugEntries < 0 || proof.GatedEntries > proof.Entries || proof.DebugEntries > proof.Entries {
		return errors.New("invalid offline archive source proof")
	}
	if proof.ExcludedPath != "" && !validOfflineArchivePath(proof.ExcludedPath) {
		return errors.New("invalid offline archive source exclusion path")
	}
	if proof.Snapshot && proof.Access != "pro" {
		return errors.New("offline snapshot source must retain Pro access")
	}
	if proof.Confidentiality == "public" && (proof.Access != "public" || proof.GatedEntries != 0 || proof.DebugEntries != 0) {
		return errors.New("offline archive public classification is not closed")
	}
	if proof.Confidentiality == "gated" && proof.Access == "public" && proof.GatedEntries == 0 && proof.DebugEntries == 0 {
		return errors.New("offline archive gated classification has no canonical taint")
	}
	previous := ""
	for _, ref := range proof.Refs {
		if plumbing.ReferenceName(ref.Name).Validate() != nil || !materializationCommitPattern.MatchString(ref.Commit) ||
			!validOfflineArchivePath(ref.Path) || !validMaterializationJournalString(ref.Repo, 256) ||
			!validMaterializationJournalString(ref.OS, 128) || !validMaterializationJournalString(ref.Arch, 128) || ref.Name <= previous {
			return errors.New("invalid or unsorted offline archive source refs")
		}
		previous = ref.Name
	}
	return nil
}

func (proof offlineArchiveDestinationProof) validate() error {
	if !validMaterializationJournalString(proof.Repo, 256) || !validOfflineArchivePath(proof.Path) {
		return errors.New("invalid offline archive destination")
	}
	if (proof.Pool == "public" && proof.View != "beta") || (proof.Pool == "gated" && proof.View != "stable") {
		return errors.New("offline archive destination pool/view mismatch")
	}
	return nil
}

func validOfflineArchivePath(value string) bool {
	return value != "" && !strings.HasPrefix(value, "/") && path.Clean(value) == value && value != "." && value != ".." &&
		!strings.HasPrefix(value, "../") && !strings.ContainsAny(value, "%?#\\\x00\t\r\n")
}

func prepareOfflineArchiveAdoption(
	cfg *config.Config,
	canonical *state.Store,
	source materializeCanonicalSource,
	leaves []viewLeaf,
	destinationRepo config.Repo,
	destinationRelative string,
) (offlineArchiveAdoptionPreflight, error) {
	var preflight offlineArchiveAdoptionPreflight
	sourceProof, err := deriveOfflineArchiveSourceProof(cfg, canonical, source, leaves)
	if err != nil {
		return preflight, fmt.Errorf("derive canonical archive source: %w", err)
	}
	return prepareOfflineArchiveAdoptionFromProof(cfg, sourceProof, destinationRepo, destinationRelative)
}

func prepareOfflineArchiveAdoptionFromProof(
	cfg *config.Config,
	sourceProof offlineArchiveSourceProof,
	destinationRepo config.Repo,
	destinationRelative string,
) (offlineArchiveAdoptionPreflight, error) {
	var preflight offlineArchiveAdoptionPreflight
	if err := sourceProof.validate(); err != nil {
		return preflight, fmt.Errorf("validate canonical archive source: %w", err)
	}
	destination, err := deriveOfflineArchiveDestination(cfg, destinationRepo, destinationRelative)
	if err != nil {
		return preflight, fmt.Errorf("derive archive destination: %w", err)
	}
	if sourceProof.Confidentiality != "public" && destination.Pool == "public" {
		return preflight, fmt.Errorf("confidentiality closure rejects %s source %s adoption into public repo %s", sourceProof.Access, sourceProof.ID, destination.Repo)
	}
	preflight.Source = sourceProof
	preflight.Destination = destination
	return preflight, nil
}

func finalizeOfflineArchiveAdoption(preflight offlineArchiveAdoptionPreflight, archive archiveResult) (*offlineArchiveAdoptionContract, error) {
	contract := offlineArchiveAdoptionContract{
		Schema: offlineArchiveAdoptionContractSchema, Source: preflight.Source,
		ArchiveSHA256: archive.SHA256, ArchiveSize: archive.Size, Destination: preflight.Destination,
	}
	contract.ID, _ = offlineArchiveAdoptionContractID(contract)
	if err := contract.validate(); err != nil {
		return nil, err
	}
	return &contract, nil
}

func deriveOfflineArchiveDestination(cfg *config.Config, repo config.Repo, relative string) (offlineArchiveDestinationProof, error) {
	var proof offlineArchiveDestinationProof
	if cfg == nil {
		return proof, errors.New("offline archive destination configuration is unavailable")
	}
	configured, exists := cfg.RepoByName(repo.ID)
	if !exists || !configured.IsActive() || configured.Type != "asset" || configured.Asset == nil {
		return proof, fmt.Errorf("repo %s is not an active configured asset repository", repo.ID)
	}
	if configured.DefaultPool != repo.DefaultPool || configured.Path != repo.Path {
		return proof, fmt.Errorf("asset repo %s differs from the active configuration", repo.ID)
	}
	viewName := "beta"
	wantedAccess := "public"
	if repo.DefaultPool == "gated" {
		viewName = "stable"
		wantedAccess = "pro"
	} else if repo.DefaultPool != "public" {
		return proof, fmt.Errorf("asset repo %s has unsupported pool %s", repo.ID, repo.DefaultPool)
	}
	view, exists := cfg.Views[viewName]
	if !exists || view.Access != wantedAccess || !contains(view.AllowedPools, repo.DefaultPool) || !viewIncludesRepo(view, repo.ID) {
		return proof, fmt.Errorf("asset repo %s is not admitted by configured %s destination view", repo.ID, viewName)
	}
	logical, err := assetLogicalPath(repo.Path, relative)
	if err != nil {
		return proof, err
	}
	if err := validateAssetProjectionPath(repo, logical); err != nil {
		return proof, err
	}
	return offlineArchiveDestinationProof{Repo: repo.ID, Pool: repo.DefaultPool, View: viewName, Path: logical}, nil
}

func deriveOfflineArchiveSourceProof(cfg *config.Config, canonical *state.Store, source materializeCanonicalSource, leaves []viewLeaf, excludedPaths ...string) (offlineArchiveSourceProof, error) {
	var proof offlineArchiveSourceProof
	if cfg == nil || canonical == nil {
		return proof, errors.New("canonical archive source is unavailable")
	}
	access, err := offlineArchiveSourceAccess(cfg, source)
	if err != nil {
		return proof, err
	}
	excludedPath := ""
	if len(excludedPaths) > 1 {
		return proof, errors.New("offline archive source has multiple self-exclusion paths")
	}
	if len(excludedPaths) == 1 {
		excludedPath = excludedPaths[0]
		if excludedPath != "" && !validOfflineArchivePath(excludedPath) {
			return proof, errors.New("offline archive source self-exclusion path is invalid")
		}
	}
	proof = offlineArchiveSourceProof{ID: source.ID, Snapshot: source.Snapshot, Access: access, ExcludedPath: excludedPath}
	for _, leaf := range leaves {
		ref, canonicalPath, commit, err := source.resolveLeaf(canonical, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return proof, err
		}
		proof.Refs = append(proof.Refs, offlineArchiveSourceRef{
			Name: ref.String(), Commit: commit.String(), Path: canonicalPath,
			Repo: leaf.repo.ID, OS: leaf.os, Arch: leaf.arch,
		})
	}
	sort.Slice(proof.Refs, func(i, j int) bool { return proof.Refs[i].Name < proof.Refs[j].Name })
	if len(proof.Refs) == 0 {
		return proof, errors.New("offline archive source has no canonical refs")
	}
	hasher := sha256.New()
	for index, ref := range proof.Refs {
		if index != 0 && ref.Name == proof.Refs[index-1].Name {
			return proof, fmt.Errorf("offline archive source repeats ref %s", ref.Name)
		}
		semanticRef := ref
		semanticRef.Commit = ""
		if err := json.NewEncoder(hasher).Encode(semanticRef); err != nil {
			return proof, err
		}
		reader, err := canonical.OpenPathAt(plumbing.NewHash(ref.Commit), ref.Path)
		if err != nil {
			return proof, fmt.Errorf("open frozen archive source %s: %w", ref.Name, err)
		}
		entries := views.NewReader(reader)
		for {
			entry, readErr := entries.Next()
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				reader.Close()
				return proof, fmt.Errorf("read frozen archive source %s: %w", ref.Name, readErr)
			}
			if entry.Repo != ref.Repo || entry.OS != ref.OS || entry.Arch != ref.Arch {
				reader.Close()
				return proof, fmt.Errorf("frozen archive source %s contains foreign entry coordinates", ref.Name)
			}
			if proof.ExcludedPath != "" && entry.Path == proof.ExcludedPath {
				continue
			}
			if access == "public" && entry.Pool != "public" {
				reader.Close()
				return proof, fmt.Errorf("public archive source %s contains gated entry %s", ref.Name, entry.Path)
			}
			if entry.Pool == "gated" {
				proof.GatedEntries++
			}
			if entry.DebugInfo {
				proof.DebugEntries++
			}
			if err := views.WriteEntry(hasher, entry); err != nil {
				reader.Close()
				return proof, err
			}
			proof.Entries++
		}
		if err := reader.Close(); err != nil {
			return proof, err
		}
	}
	proof.EntriesSHA256 = hex.EncodeToString(hasher.Sum(nil))
	proof.Confidentiality = "gated"
	if proof.Access == "public" && proof.GatedEntries == 0 && proof.DebugEntries == 0 {
		proof.Confidentiality = "public"
	}
	if err := proof.validate(); err != nil {
		return proof, err
	}
	return proof, nil
}

func offlineArchiveSourceAccess(cfg *config.Config, source materializeCanonicalSource) (string, error) {
	if source.Snapshot {
		if source.Public {
			return "", errors.New("snapshot archive source cannot be downgraded to public")
		}
		return "pro", nil
	}
	view, exists := cfg.Views[source.ID]
	if !exists {
		return "", fmt.Errorf("archive source view %s is not configured", source.ID)
	}
	public := view.Access == "public"
	if source.Public != public {
		return "", fmt.Errorf("archive source %s access differs from configured policy", source.ID)
	}
	if public {
		return "public", nil
	}
	return "pro", nil
}

func requireOfflineArchiveAdoptionContract(cfg *config.Config, canonical *state.Store, contract *offlineArchiveAdoptionContract) error {
	if contract == nil {
		return errors.New("offline archive adoption contract is missing")
	}
	if err := contract.validate(); err != nil {
		return err
	}
	repo, exists := cfg.RepoByName(contract.Destination.Repo)
	if !exists {
		return fmt.Errorf("offline archive destination repo %s is not configured", contract.Destination.Repo)
	}
	prefix := strings.TrimSuffix(repo.Path, "/") + "/"
	if !strings.HasPrefix(contract.Destination.Path, prefix) {
		return errors.New("offline archive destination path is outside its configured repo")
	}
	destination, err := deriveOfflineArchiveDestination(cfg, repo, strings.TrimPrefix(contract.Destination.Path, prefix))
	if err != nil {
		return err
	}
	if destination != contract.Destination {
		return errors.New("offline archive destination differs from configured repo/pool/view")
	}
	leaves := make([]viewLeaf, 0, len(contract.Source.Refs))
	refCommits := make(map[string]plumbing.Hash, len(contract.Source.Refs))
	for _, frozen := range contract.Source.Refs {
		repo, exists := cfg.RepoByName(frozen.Repo)
		if !exists || !repo.IsActive() {
			return fmt.Errorf("offline archive source repo %s is not active", frozen.Repo)
		}
		leaves = append(leaves, viewLeaf{repo: repo, os: frozen.OS, arch: frozen.Arch})
		refCommits[frozen.Name] = plumbing.NewHash(frozen.Commit)
	}
	source := materializeCanonicalSource{
		ID: contract.Source.ID, Snapshot: contract.Source.Snapshot,
		Public: contract.Source.Access == "public", RefCommits: refCommits,
	}
	derived, err := deriveOfflineArchiveSourceProof(cfg, canonical, source, leaves, contract.Source.ExcludedPath)
	if err != nil {
		return err
	}
	if !offlineArchiveSourceProofEqual(derived, contract.Source) {
		return errors.New("offline archive source proof differs from frozen canonical refs/entries")
	}
	if derived.Confidentiality != "public" && destination.Pool == "public" {
		return errors.New("offline archive recovery cannot downgrade gated source taint into a public destination")
	}
	return nil
}

func offlineArchiveSourceProofEqual(left, right offlineArchiveSourceProof) bool {
	leftBody, leftErr := json.Marshal(left)
	rightBody, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftBody) == string(rightBody)
}

func offlineArchiveAdoptionContractEqual(left, right *offlineArchiveAdoptionContract) bool {
	if left == nil || right == nil {
		return left == right
	}
	leftBody, leftErr := json.Marshal(left)
	rightBody, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftBody) == string(rightBody)
}

func requireOfflineArchiveDestinationEntry(canonical *state.Store, contract *offlineArchiveAdoptionContract, ref plumbing.Hash) error {
	if canonical == nil || contract == nil || ref.IsZero() {
		return errors.New("offline archive destination entry proof is unavailable")
	}
	viewPath, err := state.ViewPath(contract.Destination.View, contract.Destination.Repo, "all", "all")
	if err != nil {
		return err
	}
	reader, err := canonical.OpenPathAt(ref, viewPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	entries := views.NewReader(reader)
	for {
		entry, err := entries.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("offline archive destination ref omits its contracted asset entry")
		}
		if err != nil {
			return err
		}
		if entry.Path != contract.Destination.Path {
			continue
		}
		if entry.Repo != contract.Destination.Repo || entry.OS != "all" || entry.Arch != "all" ||
			entry.Pool != contract.Destination.Pool || entry.SHA256 != contract.ArchiveSHA256 || entry.Size != contract.ArchiveSize {
			return errors.New("offline archive destination entry differs from its contracted bytes or policy")
		}
		return nil
	}
}

func newOfflineArchiveTaintReceipt(source offlineArchiveSourceProof, archive archiveResult) (offlineArchiveTaintReceipt, error) {
	receipt := offlineArchiveTaintReceipt{
		Schema: offlineArchiveTaintReceiptSchema, ArchiveSHA256: archive.SHA256, ArchiveSize: archive.Size,
		Confidentiality: source.Confidentiality, Source: source,
	}
	receipt.ID, _ = offlineArchiveTaintReceiptID(receipt)
	if err := receipt.validate(); err != nil {
		return offlineArchiveTaintReceipt{}, err
	}
	return receipt, nil
}

func persistOfflineArchiveTaintReceipt(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	source offlineArchiveSourceProof,
	archive archiveResult,
	txDir string,
) (offlineArchiveTaintReceipt, error) {
	receipt, err := newOfflineArchiveTaintReceipt(source, archive)
	if err != nil {
		return offlineArchiveTaintReceipt{}, err
	}
	existing, exists, err := readOfflineArchiveTaintReceipt(canonical, archive.SHA256)
	if err != nil {
		return offlineArchiveTaintReceipt{}, err
	}
	if exists {
		if existing.ArchiveSize != archive.Size {
			return offlineArchiveTaintReceipt{}, errors.New("canonical archive taint receipt binds the digest to another size")
		}
		if existing.Confidentiality != receipt.Confidentiality {
			// Raising public bytes to gated would leave prior public copies and
			// refs reachable; lowering gated bytes would disclose them. Until a
			// complete public reachability proof exists, both transitions fail
			// closed before the new archive is made visible.
			return offlineArchiveTaintReceipt{}, fmt.Errorf("offline archive digest %s is already classified %s and cannot transition to %s", archive.SHA256, existing.Confidentiality, receipt.Confidentiality)
		}
		if existing.Confidentiality == receipt.Confidentiality {
			return existing, nil
		}
	}
	canonicalPath, err := offlineArchiveTaintReceiptPath(archive.SHA256)
	if err != nil {
		return offlineArchiveTaintReceipt{}, err
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		return offlineArchiveTaintReceipt{}, err
	}
	body = append(body, '\n')
	stage, err := os.CreateTemp(txDir, "archive-taint-*.json")
	if err != nil {
		return offlineArchiveTaintReceipt{}, err
	}
	stagePath := stage.Name()
	if _, err := stage.Write(body); err != nil {
		stage.Close()
		return offlineArchiveTaintReceipt{}, err
	}
	if err := errors.Join(stage.Sync(), stage.Close()); err != nil {
		return offlineArchiveTaintReceipt{}, err
	}
	_, _, err = applyCanonicalConfig(ctx, cfg, canonical, "materialize-archive-taint", "sow materialize: retain offline archive taint "+archive.SHA256,
		map[string]string{canonicalPath: stagePath}, nil, state.ApplyOptions{})
	if err != nil {
		return offlineArchiveTaintReceipt{}, err
	}
	stored, exists, err := readOfflineArchiveTaintReceipt(canonical, archive.SHA256)
	if err != nil || !exists || stored.Confidentiality != receipt.Confidentiality {
		return offlineArchiveTaintReceipt{}, errors.Join(err, errors.New("canonical offline archive taint receipt did not converge"))
	}
	return stored, nil
}

func readOfflineArchiveTaintReceipt(canonical *state.Store, digest string) (offlineArchiveTaintReceipt, bool, error) {
	var receipt offlineArchiveTaintReceipt
	if canonical == nil {
		return receipt, false, errors.New("canonical archive taint store is unavailable")
	}
	canonicalPath, err := offlineArchiveTaintReceiptPath(digest)
	if err != nil {
		return receipt, false, err
	}
	head, err := canonical.HeadHash()
	if err != nil {
		return receipt, false, err
	}
	if head.IsZero() {
		return receipt, false, nil
	}
	identity, exists, err := canonical.BlobIdentityAt(head, canonicalPath)
	if err != nil || !exists {
		return receipt, false, err
	}
	if identity.Size <= 0 || identity.Size > 1<<20 {
		return receipt, false, errors.New("canonical archive taint receipt has unsafe size")
	}
	reader, err := canonical.OpenPathAt(head, canonicalPath)
	if err != nil {
		return receipt, false, err
	}
	decoder := json.NewDecoder(io.LimitReader(reader, (1<<20)+1))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&receipt)
	var trailing any
	trailingErr := decoder.Decode(&trailing)
	closeErr := reader.Close()
	if decodeErr != nil || !errors.Is(trailingErr, io.EOF) || closeErr != nil {
		return offlineArchiveTaintReceipt{}, false, errors.Join(decodeErr, trailingErr, closeErr, errors.New("decode canonical archive taint receipt"))
	}
	if err := receipt.validate(); err != nil {
		return offlineArchiveTaintReceipt{}, false, err
	}
	if receipt.ArchiveSHA256 != digest {
		return offlineArchiveTaintReceipt{}, false, errors.New("canonical archive taint receipt is stored below another digest")
	}
	return receipt, true, nil
}

// requireOfflineArchiveTaintAdmission is called for every asset input after a
// stable pre-hash and before either CAS or canonical ref mutation. Unknown
// ordinary assets remain admissible; known SOW archive bytes inherit the
// strongest canonical digest-level taint regardless of filename or location.
func requireOfflineArchiveTaintAdmission(canonical *state.Store, destination config.Repo, digest string, size int64) (*offlineArchiveTaintReceipt, error) {
	receipt, exists, err := readOfflineArchiveTaintReceipt(canonical, digest)
	if err != nil || !exists {
		return nil, err
	}
	if receipt.ArchiveSize != size {
		return nil, errors.New("asset input size differs from its canonical archive taint receipt")
	}
	if receipt.Confidentiality != "public" && destination.DefaultPool == "public" {
		return nil, fmt.Errorf("canonical digest taint rejects %s archive %s from public asset repo %s", receipt.Confidentiality, digest, destination.ID)
	}
	return &receipt, nil
}
