package yumrepo

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

// ManagedPoolPathVersion identifies the canonical Repository Pool path
// function. Its inputs and output are unescaped ASCII path components; URI
// escaping belongs exclusively to the retrieval-reference layer below.
const ManagedPoolPathVersion = "sow-managed-pool-v1"

// ManagedPoolPath is one validated canonical Repository-relative Pool path.
type ManagedPoolPath struct {
	raw      string
	source   string
	filename string
}

// NewManagedPoolPath applies sow-managed-pool-v1 to an unescaped source and
// filename.
func NewManagedPoolPath(source, filename string) (ManagedPoolPath, error) {
	if !safeManagedPackageComponent(source) || !safeManagedPackageComponent(filename) {
		return ManagedPoolPath{}, fmt.Errorf("%w: invalid %s source or filename", ErrUnsafeLocation, ManagedPoolPathVersion)
	}
	prefix := source[:1]
	if strings.HasPrefix(source, "lib") {
		if len(source) < 4 {
			prefix = source
		} else {
			prefix = source[:4]
		}
	}
	prefix = strings.ToLower(prefix)
	if !safeManagedPackageComponent(prefix) {
		return ManagedPoolPath{}, fmt.Errorf("%w: invalid %s prefix", ErrUnsafeLocation, ManagedPoolPathVersion)
	}
	return ManagedPoolPath{raw: "pool/" + prefix + "/" + source + "/" + filename, source: source, filename: filename}, nil
}

// ParseManagedPoolPath accepts only the exact output language of
// sow-managed-pool-v1.
func ParseManagedPoolPath(raw string) (ManagedPoolPath, error) {
	if raw == "" || path.Clean(raw) != raw || strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "\\\x00\r\n\t") {
		return ManagedPoolPath{}, fmt.Errorf("%w: unsafe canonical Pool path %q", ErrUnsafeLocation, raw)
	}
	parts := strings.Split(raw, "/")
	if len(parts) != 4 || parts[0] != "pool" {
		return ManagedPoolPath{}, fmt.Errorf("%w: canonical Pool path %q must be pool/<prefix>/<source>/<filename>", ErrUnsafeLocation, raw)
	}
	canonical, err := NewManagedPoolPath(parts[2], parts[3])
	if err != nil || canonical.raw != raw {
		return ManagedPoolPath{}, fmt.Errorf("%w: non-canonical Pool path %q", ErrUnsafeLocation, raw)
	}
	return canonical, nil
}

func (value ManagedPoolPath) String() string   { return value.raw }
func (value ManagedPoolPath) Source() string   { return value.source }
func (value ManagedPoolPath) Filename() string { return value.filename }

// ManagedRPMViewPath is one Repository-relative RPM view root. Canonical SOW
// views have the exact dists/<dist>/<architecture> shape.
type ManagedRPMViewPath struct {
	raw string
}

func ParseManagedRPMViewPath(raw string) (ManagedRPMViewPath, error) {
	if raw == "" || path.Clean(raw) != raw || strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "\\\x00\r\n\t") {
		return ManagedRPMViewPath{}, fmt.Errorf("%w: unsafe RPM view path %q", ErrUnsafeLocation, raw)
	}
	parts := strings.Split(raw, "/")
	if len(parts) != 3 || parts[0] != "dists" || !safeManagedPackageComponent(parts[1]) || !safeManagedPackageComponent(parts[2]) {
		return ManagedRPMViewPath{}, fmt.Errorf("%w: RPM view path %q must be dists/<dist>/<architecture>", ErrUnsafeLocation, raw)
	}
	return ManagedRPMViewPath{raw: raw}, nil
}

func (value ManagedRPMViewPath) String() string { return value.raw }

// ManagedRPMHref is the canonical URI relative-reference from one RPM view
// directory to one canonical Pool object.
type ManagedRPMHref struct {
	raw string
}

func (value ManagedRPMHref) String() string { return value.raw }

// RPMParentRelativeHref computes a POSIX parent-relative reference from
// unescaped Repository path segments. Navigation segments remain literal;
// every target data segment is encoded exactly once using RFC 3986 unreserved
// bytes and uppercase percent escapes.
func RPMParentRelativeHref(view ManagedRPMViewPath, pool ManagedPoolPath) (ManagedRPMHref, error) {
	if view.raw == "" || pool.raw == "" {
		return ManagedRPMHref{}, fmt.Errorf("%w: empty managed RPM path", ErrUnsafeLocation)
	}
	from, target := strings.Split(view.raw, "/"), strings.Split(pool.raw, "/")
	common := 0
	for common < len(from) && common < len(target) && from[common] == target[common] {
		common++
	}
	parts := make([]string, 0, len(from)-common+len(target)-common)
	for range len(from) - common {
		parts = append(parts, "..")
	}
	for _, segment := range target[common:] {
		parts = append(parts, encodeURIDataSegment(segment))
	}
	if len(parts) == 0 {
		return ManagedRPMHref{}, fmt.Errorf("%w: RPM view and Pool path unexpectedly coincide", ErrUnsafeLocation)
	}
	href := strings.Join(parts, "/")
	parsed, parsedPool, err := ParseManagedRPMHref(href)
	if err != nil || parsedPool != pool {
		return ManagedRPMHref{}, fmt.Errorf("%w: generated RPM href %q does not round-trip to %q", ErrUnsafeLocation, href, pool.raw)
	}
	return parsed, nil
}

// ParseManagedRPMHref validates canonical encode-once spelling. It decodes
// data segments exactly once and returns the canonical Pool target, but does
// not infer a view depth; exact view binding is performed by
// ValidateRPMHrefRoundTrip.
func ParseManagedRPMHref(raw string) (ManagedRPMHref, ManagedPoolPath, error) {
	if raw == "" || strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "\\?#\x00\r\n\t") {
		return ManagedRPMHref{}, ManagedPoolPath{}, fmt.Errorf("%w: unsafe managed RPM href %q", ErrUnsafeLocation, raw)
	}
	parts := strings.Split(raw, "/")
	navigation := 0
	for navigation < len(parts) && parts[navigation] == ".." {
		navigation++
	}
	if navigation == 0 || len(parts)-navigation != 4 {
		return ManagedRPMHref{}, ManagedPoolPath{}, fmt.Errorf("%w: managed RPM href %q is not parent-relative to a Pool path", ErrUnsafeLocation, raw)
	}
	decoded := make([]string, 0, 4)
	for _, encoded := range parts[navigation:] {
		segment, err := decodeCanonicalURIDataSegment(encoded)
		if err != nil {
			return ManagedRPMHref{}, ManagedPoolPath{}, fmt.Errorf("%w: managed RPM href %q: %v", ErrUnsafeLocation, raw, err)
		}
		decoded = append(decoded, segment)
	}
	pool, err := ParseManagedPoolPath(strings.Join(decoded, "/"))
	if err != nil {
		return ManagedRPMHref{}, ManagedPoolPath{}, err
	}
	return ManagedRPMHref{raw: raw}, pool, nil
}

// ValidateRPMHrefRoundTrip binds one canonical href to an actual final
// Repository directory URI. It rejects a non-directory base, any spelling
// other than the shared resolver output, and any resolution outside or away
// from the expected canonical Pool target.
func ValidateRPMHrefRoundTrip(repositoryBase *url.URL, view ManagedRPMViewPath, pool ManagedPoolPath, rawHref string) error {
	if err := validateRepositoryBaseURI(repositoryBase); err != nil {
		return err
	}
	wantHref, err := RPMParentRelativeHref(view, pool)
	if err != nil {
		return err
	}
	if rawHref != wantHref.raw {
		return fmt.Errorf("%w: RPM href %q differs from canonical %q", ErrUnsafeLocation, rawHref, wantHref.raw)
	}
	viewReference, err := url.Parse(encodeRepositoryPath(view.raw) + "/")
	if err != nil {
		return fmt.Errorf("%w: encode RPM view URI: %v", ErrUnsafeLocation, err)
	}
	viewBase := repositoryBase.ResolveReference(viewReference)
	if !strings.HasSuffix(viewBase.EscapedPath(), "/") {
		return fmt.Errorf("%w: RPM view retrieval base is not a directory URI", ErrUnsafeLocation)
	}
	hrefReference, err := url.Parse(rawHref)
	if err != nil || hrefReference.IsAbs() || hrefReference.Host != "" || hrefReference.RawQuery != "" || hrefReference.Fragment != "" {
		return fmt.Errorf("%w: RPM href %q is not a relative path reference", ErrUnsafeLocation, rawHref)
	}
	resolved := viewBase.ResolveReference(hrefReference)
	targetReference, err := url.Parse(encodeRepositoryPath(pool.raw))
	if err != nil {
		return fmt.Errorf("%w: encode canonical Pool URI: %v", ErrUnsafeLocation, err)
	}
	wantTarget := repositoryBase.ResolveReference(targetReference)
	if !sameURLTarget(resolved, wantTarget) {
		return fmt.Errorf("%w: RPM href %q resolves to %q, want %q", ErrUnsafeLocation, rawHref, resolved.String(), wantTarget.String())
	}
	if !strings.HasPrefix(wantTarget.Path, repositoryBase.Path) || strings.TrimPrefix(wantTarget.Path, repositoryBase.Path) != pool.raw {
		return fmt.Errorf("%w: RPM href target is outside the Repository Pool", ErrUnsafeLocation)
	}
	return nil
}

func validateRepositoryBaseURI(base *url.URL) error {
	if base == nil || !base.IsAbs() || base.Opaque != "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" ||
		!strings.HasSuffix(base.Path, "/") || !strings.HasSuffix(base.EscapedPath(), "/") || strings.ContainsAny(base.Path, "\\\x00\r\n\t") {
		return fmt.Errorf("%w: Repository retrieval base must be an absolute directory URI", ErrUnsafeLocation)
	}
	return nil
}

func sameURLTarget(left, right *url.URL) bool {
	return left != nil && right != nil && left.Scheme == right.Scheme && left.Host == right.Host && left.Opaque == right.Opaque &&
		left.User == nil && right.User == nil && left.EscapedPath() == right.EscapedPath() && left.RawQuery == "" && right.RawQuery == "" &&
		left.Fragment == "" && right.Fragment == ""
}

func encodeRepositoryPath(raw string) string {
	parts := strings.Split(raw, "/")
	for index := range parts {
		parts[index] = encodeURIDataSegment(parts[index])
	}
	return strings.Join(parts, "/")
}

func encodeURIDataSegment(value string) string {
	const hex = "0123456789ABCDEF"
	var encoded strings.Builder
	encoded.Grow(len(value))
	for index := 0; index < len(value); index++ {
		valueByte := value[index]
		if isURIUnreserved(valueByte) {
			encoded.WriteByte(valueByte)
			continue
		}
		encoded.WriteByte('%')
		encoded.WriteByte(hex[valueByte>>4])
		encoded.WriteByte(hex[valueByte&15])
	}
	return encoded.String()
}

func decodeCanonicalURIDataSegment(encoded string) (string, error) {
	if encoded == "" {
		return "", errorsNewDataSegment("empty data segment")
	}
	decoded := make([]byte, 0, len(encoded))
	for index := 0; index < len(encoded); {
		valueByte := encoded[index]
		if isURIUnreserved(valueByte) {
			decoded = append(decoded, valueByte)
			index++
			continue
		}
		if valueByte != '%' || index+2 >= len(encoded) || !isUpperHex(encoded[index+1]) || !isUpperHex(encoded[index+2]) {
			return "", errorsNewDataSegment("non-canonical percent escape")
		}
		valueByte = fromHex(encoded[index+1])<<4 | fromHex(encoded[index+2])
		if isURIUnreserved(valueByte) {
			return "", errorsNewDataSegment("unreserved byte is percent-encoded")
		}
		decoded = append(decoded, valueByte)
		index += 3
	}
	value := string(decoded)
	if !safeManagedPackageComponent(value) {
		return "", errorsNewDataSegment("decoded byte is not a managed path component")
	}
	return value, nil
}

func errorsNewDataSegment(detail string) error {
	return fmt.Errorf("invalid URI data segment: %s", detail)
}

func isURIUnreserved(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' ||
		value == '-' || value == '.' || value == '_' || value == '~'
}

func isUpperHex(value byte) bool { return value >= '0' && value <= '9' || value >= 'A' && value <= 'F' }

func fromHex(value byte) byte {
	if value >= '0' && value <= '9' {
		return value - '0'
	}
	return value - 'A' + 10
}
