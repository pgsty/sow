package upstream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/syncer"
)

// APTSource identifies one distribution projection. A trusted upstream keyring
// is mandatory because a Packages checksum without its signed Release root is
// not provenance.
type APTSource struct {
	BaseURL       string
	Suite         string
	Components    []string
	Architectures []string
	Keyring       openpgp.KeyRing
	Client        *http.Client
	WorkDir       string
	Limits        Limits
}

type releaseChecksum struct {
	SHA256 string
	Size   int64
}

// DiscoverAPT is the compatibility, materializing wrapper. New production
// callers should use DiscoverAPTStreaming so repository-sized candidate sets
// remain on disk.
func DiscoverAPT(ctx context.Context, source APTSource) (*Discovery, error) {
	discovery, err := DiscoverAPTStreaming(ctx, source)
	if err != nil {
		return nil, err
	}
	if err := materializeCandidates(discovery); err != nil {
		_ = discovery.Close()
		return nil, err
	}
	return discovery, nil
}

// DiscoverAPTStreaming verifies InRelease (or Release plus Release.gpg),
// downloads each configured Packages index by its signed SHA-256/size, and
// spools authenticated package/proof records to a bounded-memory disk cursor.
func DiscoverAPTStreaming(ctx context.Context, source APTSource) (*Discovery, error) {
	if ctx == nil {
		return nil, errors.New("upstream: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := source.Limits.validate(); err != nil {
		return nil, err
	}
	limits := source.Limits.withDefaults()
	base, err := normalizeBase(source.BaseURL)
	if err != nil {
		return nil, err
	}
	if source.WorkDir == "" || source.Keyring == nil || len(source.Components) == 0 || len(source.Architectures) == 0 {
		return nil, fmt.Errorf("%w: APT work directory, trusted keyring, components, and architectures are required", ErrInvalidMetadata)
	}
	if err := validateRepoSegment("suite", source.Suite); err != nil {
		return nil, err
	}
	if err := validateUniqueSegments("component", source.Components); err != nil {
		return nil, err
	}
	if err := validateUniqueSegments("architecture", source.Architectures); err != nil {
		return nil, err
	}

	releaseBody, signedEvidence, signatureEvidence, releaseKind, err := fetchAPTRelease(ctx, source, base, limits)
	if err != nil {
		return nil, err
	}
	checksums, releaseFields, err := parseRelease(releaseBody)
	if err != nil {
		return nil, err
	}
	if releaseFields["suite"] != source.Suite && releaseFields["codename"] != source.Suite {
		return nil, fmt.Errorf("%w: signed Release suite/codename does not match %q", ErrInvalidMetadata, source.Suite)
	}
	if err := validateReleaseWindow(releaseFields, time.Now().UTC()); err != nil {
		return nil, err
	}

	discovery, err := newDiscovery("deb", source.WorkDir)
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = discovery.Close()
		}
	}()
	discovery.Evidence = append(discovery.Evidence, signedEvidence)
	if signatureEvidence != nil {
		discovery.Evidence = append(discovery.Evidence, *signatureEvidence)
	}
	type selectedIndex struct {
		component string
		arch      string
		path      string
		checksum  releaseChecksum
	}
	var selected []selectedIndex
	for _, component := range source.Components {
		for _, arch := range source.Architectures {
			prefix := path.Join(component, "binary-"+arch, "Packages")
			indexPath, checksum, ok := selectAPTIndex(checksums, prefix)
			if !ok {
				return nil, fmt.Errorf("%w: signed Release lacks Packages for %s/%s", ErrInvalidMetadata, component, arch)
			}
			selected = append(selected, selectedIndex{component: component, arch: arch, path: indexPath, checksum: checksum})
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].path < selected[j].path })
	for _, index := range selected {
		indexURL, err := resolveRelative(base, path.Join("dists", source.Suite, index.path))
		if err != nil {
			return nil, err
		}
		metadataCandidate := syncer.Candidate{
			Format: "deb", Name: "Packages", Version: index.checksum.SHA256,
			Arch: index.arch, URL: indexURL, Size: index.checksum.Size, SHA256: index.checksum.SHA256,
		}
		evidence, err := downloadEvidence(ctx, source.WorkDir, "apt-packages", metadataCandidate, source.Client, limits)
		if err != nil {
			return nil, fmt.Errorf("upstream: download %s: %w", index.path, err)
		}
		discovery.Evidence = append(discovery.Evidence, evidence)
		stream, err := openIndex(evidence.Path, indexURL, limits)
		if err != nil {
			return nil, err
		}
		err = parseDebPackagesLimited(&interruptibleReader{ctx: ctx, r: stream}, base, limits.StanzaBytes, limits.PackageCount, func(candidate syncer.Candidate, entryHash string) error {
			if candidate.Arch != index.arch && candidate.Arch != "all" {
				return fmt.Errorf("%w: package %s architecture %q is in binary-%s", ErrInvalidMetadata, candidate.Name, candidate.Arch, index.arch)
			}
			parsedURL, parseErr := url.Parse(candidate.URL)
			expectedPool := path.Join(base.Path, "pool", index.component) + "/"
			if parseErr != nil || !strings.HasPrefix(parsedURL.Path, expectedPool) {
				return fmt.Errorf("%w: package %s escapes component %s", ErrInvalidMetadata, candidate.Name, index.component)
			}
			proof := provenance.DEBProof{
				PackagesEntrySHA256: entryHash, PackagesEvidenceSHA256: evidence.SHA256,
				SignedReleaseSHA256: signedEvidence.SHA256, SignedReleaseKind: releaseKind,
			}
			return addDiscoveredCandidate(discovery, candidate, candidateProof{deb: &proof})
		})
		closeErr := stream.Close()
		if err != nil || closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
	}
	if err := finalizeDiscovery(discovery); err != nil {
		return nil, err
	}
	if err := sealEvidence(discovery); err != nil {
		return nil, err
	}
	complete = true
	return discovery, nil
}

func fetchAPTRelease(ctx context.Context, source APTSource, baseURL *url.URL, limits Limits) ([]byte, Evidence, *Evidence, string, error) {
	inReleaseRef := path.Join("dists", source.Suite, "InRelease")
	inReleaseURL, err := resolveRelative(baseURL, inReleaseRef)
	if err != nil {
		return nil, Evidence{}, nil, "", err
	}
	inRelease, found, err := fetchBytes(ctx, source.Client, inReleaseURL, limits.ReleaseBytes, true)
	if err != nil {
		return nil, Evidence{}, nil, "", err
	}
	if found {
		if !bytes.HasPrefix(inRelease, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
			return nil, Evidence{}, nil, "", fmt.Errorf("%w: InRelease has an unsigned prefix", ErrSignature)
		}
		block, err := verifyClearSigned(inRelease, source.Keyring)
		if err != nil {
			return nil, Evidence{}, nil, "", fmt.Errorf("%w: InRelease: %v", ErrSignature, err)
		}
		evidence, err := preserveBytes(source.WorkDir, "apt-inrelease", inReleaseURL, inRelease, true)
		return block.Plaintext, evidence, nil, "InRelease", err
	}

	releaseRef := path.Join("dists", source.Suite, "Release")
	releaseURL, err := resolveRelative(baseURL, releaseRef)
	if err != nil {
		return nil, Evidence{}, nil, "", err
	}
	release, _, err := fetchBytes(ctx, source.Client, releaseURL, limits.ReleaseBytes, false)
	if err != nil {
		return nil, Evidence{}, nil, "", err
	}
	sigURL, err := resolveRelative(baseURL, releaseRef+".gpg")
	if err != nil {
		return nil, Evidence{}, nil, "", err
	}
	signature, _, err := fetchBytes(ctx, source.Client, sigURL, limits.SignatureBytes, false)
	if err != nil {
		return nil, Evidence{}, nil, "", err
	}
	if err = verifyDetached(release, signature, source.Keyring); err != nil {
		return nil, Evidence{}, nil, "", fmt.Errorf("%w: Release.gpg: %v", ErrSignature, err)
	}
	releaseEvidence, err := preserveBytes(source.WorkDir, "apt-release", releaseURL, release, true)
	if err != nil {
		return nil, Evidence{}, nil, "", err
	}
	signatureEvidence, err := preserveBytes(source.WorkDir, "apt-release-signature", sigURL, signature, true)
	return release, releaseEvidence, &signatureEvidence, "Release+Release.gpg", err
}

func parseRelease(data []byte) (map[string]releaseChecksum, map[string]string, error) {
	checksums := make(map[string]releaseChecksum)
	fields := make(map[string]string)
	section := ""
	for lineNumber, raw := range bytes.Split(data, []byte{'\n'}) {
		line := strings.TrimSuffix(string(raw), "\r")
		if strings.ContainsRune(line, '\x00') {
			return nil, nil, fmt.Errorf("%w: NUL in Release line %d", ErrInvalidMetadata, lineNumber+1)
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if section != "sha256" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) != 3 || !validSHA256(parts[0]) {
				return nil, nil, fmt.Errorf("%w: malformed Release SHA256 line %d", ErrInvalidMetadata, lineNumber+1)
			}
			size, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil || size < 0 {
				return nil, nil, fmt.Errorf("%w: malformed Release size", ErrInvalidMetadata)
			}
			if err := validateRelativePath(parts[2]); err != nil {
				return nil, nil, err
			}
			if _, exists := checksums[parts[2]]; exists {
				return nil, nil, fmt.Errorf("%w: duplicate Release checksum for %s", ErrInvalidMetadata, parts[2])
			}
			checksums[parts[2]] = releaseChecksum{SHA256: parts[0], Size: size}
			continue
		}
		section = ""
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return nil, nil, fmt.Errorf("%w: malformed Release field on line %d", ErrInvalidMetadata, lineNumber+1)
		}
		key := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := strings.TrimSpace(line[colon+1:])
		if key == "sha256" {
			section = key
		} else {
			if _, exists := fields[key]; exists {
				return nil, nil, fmt.Errorf("%w: duplicate Release field %s", ErrInvalidMetadata, key)
			}
			fields[key] = value
		}
	}
	if len(checksums) == 0 {
		return nil, nil, fmt.Errorf("%w: Release has no SHA256 section", ErrInvalidMetadata)
	}
	return checksums, fields, nil
}

func selectAPTIndex(entries map[string]releaseChecksum, base string) (string, releaseChecksum, bool) {
	for _, suffix := range []string{".zst", ".xz", ".gz", ""} {
		candidate := base + suffix
		if checksum, ok := entries[candidate]; ok {
			return candidate, checksum, true
		}
	}
	return "", releaseChecksum{}, false
}

func parseDebPackages(reader io.Reader, base *url.URL, maxStanza int, accept func(syncer.Candidate, string) error) error {
	return parseDebPackagesLimited(reader, base, maxStanza, 1_000_000, accept)
}

func parseDebPackagesLimited(reader io.Reader, base *url.URL, maxStanza, maxPackages int, accept func(syncer.Candidate, string) error) error {
	if maxPackages <= 0 {
		return fmt.Errorf("%w: invalid package count limit", ErrInvalidMetadata)
	}
	buffered := bufio.NewReaderSize(reader, 128*1024)
	stanza := make([]byte, 0, 4096)
	packages := 0
	flush := func() error {
		if len(stanza) == 0 {
			return nil
		}
		candidate, err := debCandidateFromStanza(stanza, base)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(stanza)
		packages++
		if packages > maxPackages {
			return fmt.Errorf("%w: Packages contains more than %d entries", ErrMetadataTooLarge, maxPackages)
		}
		if err := accept(candidate, hex.EncodeToString(digest[:])); err != nil {
			return err
		}
		stanza = stanza[:0]
		return nil
	}
	for {
		line, err := readLineLimited(buffered, maxStanza+2-len(stanza))
		if len(line) > 0 {
			if len(bytes.TrimRight(line, "\r\n")) == 0 {
				if flushErr := flush(); flushErr != nil {
					return flushErr
				}
			} else {
				if len(stanza)+len(line) > maxStanza {
					return ErrMetadataTooLarge
				}
				stanza = append(stanza, line...)
			}
		}
		if errors.Is(err, io.EOF) {
			return flush()
		}
		if err != nil {
			return err
		}
	}
}

func validateReleaseWindow(fields map[string]string, now time.Time) error {
	if raw := fields["date"]; raw != "" {
		issued, err := parseReleaseTime(raw)
		if err != nil {
			return fmt.Errorf("%w: invalid Release Date", ErrInvalidMetadata)
		}
		if issued.After(now.Add(24 * time.Hour)) {
			return fmt.Errorf("%w: Release Date is implausibly in the future", ErrSignature)
		}
	}
	if raw := fields["valid-until"]; raw != "" {
		expires, err := parseReleaseTime(raw)
		if err != nil {
			return fmt.Errorf("%w: invalid Release Valid-Until", ErrInvalidMetadata)
		}
		if now.After(expires) {
			return fmt.Errorf("%w: Release metadata expired at %s", ErrSignature, expires.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

func parseReleaseTime(raw string) (time.Time, error) {
	var last error
	for _, layout := range []string{time.RFC1123Z, time.RFC1123} {
		parsed, err := time.Parse(layout, raw)
		if err == nil {
			return parsed, nil
		}
		last = err
	}
	return time.Time{}, last
}

func readLineLimited(reader *bufio.Reader, remaining int) ([]byte, error) {
	if remaining <= 0 {
		return nil, ErrMetadataTooLarge
	}
	var line []byte
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(line)+len(fragment) > remaining {
			return nil, ErrMetadataTooLarge
		}
		line = append(line, fragment...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, err
	}
}

func debCandidateFromStanza(raw []byte, base *url.URL) (syncer.Candidate, error) {
	fields := make(map[string]string)
	var previous string
	for _, rawLine := range bytes.Split(raw, []byte{'\n'}) {
		line := strings.TrimSuffix(string(rawLine), "\r")
		if line == "" {
			continue
		}
		if strings.ContainsRune(line, '\x00') {
			return syncer.Candidate{}, fmt.Errorf("%w: NUL in Packages entry", ErrInvalidMetadata)
		}
		if line[0] == ' ' || line[0] == '\t' {
			if previous == "" {
				return syncer.Candidate{}, fmt.Errorf("%w: orphan Packages continuation", ErrInvalidMetadata)
			}
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return syncer.Candidate{}, fmt.Errorf("%w: malformed Packages field", ErrInvalidMetadata)
		}
		key := strings.ToLower(line[:colon])
		if _, exists := fields[key]; exists {
			return syncer.Candidate{}, fmt.Errorf("%w: duplicate Packages field %s", ErrInvalidMetadata, key)
		}
		fields[key] = strings.TrimSpace(line[colon+1:])
		previous = key
	}
	size, err := strconv.ParseInt(fields["size"], 10, 64)
	if err != nil || size <= 0 || !validSHA256(fields["sha256"]) {
		return syncer.Candidate{}, fmt.Errorf("%w: invalid package size or SHA256", ErrInvalidMetadata)
	}
	filename := fields["filename"]
	if err := validateRelativePath(filename); err != nil {
		return syncer.Candidate{}, err
	}
	segments := strings.Split(filename, "/")
	if len(segments) < 4 || segments[0] != "pool" || !strings.HasSuffix(filename, ".deb") {
		return syncer.Candidate{}, fmt.Errorf("%w: non-deb package filename %q", ErrInvalidMetadata, filename)
	}
	packageURL, err := resolveRelative(base, filename)
	if err != nil {
		return syncer.Candidate{}, err
	}
	candidate := syncer.Candidate{
		Format: "deb", Name: fields["package"], Version: fields["version"], Arch: fields["architecture"],
		URL: packageURL, Size: size, SHA256: fields["sha256"],
		DebugInfo: isDebugPackage("deb", fields["package"]),
	}
	if candidate.Name == "" || candidate.Version == "" || candidate.Arch == "" {
		return syncer.Candidate{}, fmt.Errorf("%w: Packages entry lacks identity", ErrInvalidMetadata)
	}
	for kind, value := range map[string]string{"package": candidate.Name, "version": candidate.Version, "architecture": candidate.Arch} {
		if err := validateIdentity(kind, value); err != nil {
			return syncer.Candidate{}, err
		}
	}
	if err := candidate.Validate(); err != nil {
		return syncer.Candidate{}, fmt.Errorf("%w: %v", ErrInvalidMetadata, err)
	}
	return candidate, nil
}

func validateRepoSegment(kind, value string) error {
	if value == "" || value == "." || value == ".." || strings.ContainsAny(value, "/\\\x00\r\n\t") {
		return fmt.Errorf("%w: unsafe %s %q", ErrInvalidMetadata, kind, value)
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("+._-", r)) {
			return fmt.Errorf("%w: unsafe %s %q", ErrInvalidMetadata, kind, value)
		}
	}
	return nil
}

func validateUniqueSegments(kind string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validateRepoSegment(kind, value); err != nil {
			return err
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%w: duplicate %s %q", ErrInvalidMetadata, kind, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateRelativePath(value string) error {
	base, err := normalizeBase("https://validation.invalid/")
	if err != nil {
		return err
	}
	_, err = resolveRelative(base, value)
	return err
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func isDebugPackage(format, name string) bool {
	name = strings.ToLower(name)
	if format == "deb" {
		return strings.HasSuffix(name, "-dbgsym") || strings.HasSuffix(name, "-dbg")
	}
	return strings.HasSuffix(name, "-debuginfo") || strings.HasSuffix(name, "-debugsource")
}

func validateIdentity(kind, value string) error {
	if value == "" || strings.ContainsAny(value, "/\\ \t\r\n\x00") {
		return fmt.Errorf("%w: unsafe %s %q", ErrInvalidMetadata, kind, value)
	}
	return nil
}

func addDiscoveredCandidate(discovery *Discovery, candidate syncer.Candidate, proof candidateProof) error {
	if discovery == nil || discovery.store == nil {
		return fmt.Errorf("%w: candidate store is unavailable", ErrInvalidMetadata)
	}
	return discovery.store.add(candidate, proof)
}

func sortCandidates(candidates []syncer.Candidate) {
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Name != candidates[j].Name {
			return candidates[i].Name < candidates[j].Name
		}
		if candidates[i].Arch != candidates[j].Arch {
			return candidates[i].Arch < candidates[j].Arch
		}
		if candidates[i].Version != candidates[j].Version {
			return candidates[i].Version < candidates[j].Version
		}
		return candidates[i].SHA256 < candidates[j].SHA256
	})
}

func finalizeDiscovery(discovery *Discovery) error {
	if discovery == nil || discovery.store == nil {
		return fmt.Errorf("%w: candidate store is unavailable", ErrInvalidMetadata)
	}
	if err := discovery.store.finalize(); err != nil {
		return err
	}
	discovery.count = discovery.store.count
	return nil
}

func materializeCandidates(discovery *Discovery) error {
	if discovery == nil {
		return fmt.Errorf("%w: empty discovery", ErrInvalidMetadata)
	}
	candidates := make([]syncer.Candidate, 0, discovery.CandidateCount())
	if err := discovery.ForEachCandidate(func(candidate syncer.Candidate) error {
		candidates = append(candidates, candidate)
		return nil
	}); err != nil {
		return err
	}
	sortCandidates(candidates)
	discovery.Candidates = candidates
	return nil
}
