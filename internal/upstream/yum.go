package upstream

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/syncer"
)

const (
	yumRepoNamespace   = "http://linux.duke.edu/metadata/repo"
	yumCommonNamespace = "http://linux.duke.edu/metadata/common"
	maxXMLFieldBytes   = 1 << 20
)

// YUMSource identifies one RPM repository root. Keyring and repomd.xml.asc are
// mandatory: primary.xml checksums have no trust root when repomd is unsigned.
// Package bytes are pinned by primary.xml SHA-256/size and preserved verbatim,
// retaining their embedded RPM signature without Day-1 re-signing.
type YUMSource struct {
	BaseURL       string
	Architectures []string
	// ExcludeNoarch lets a caller select only base-architecture leaves from a
	// repository whose local noarch policy is separate. The zero value preserves
	// the long-standing YUM behavior of admitting noarch alongside any basearch.
	ExcludeNoarch bool
	Keyring       openpgp.KeyRing
	Client        *http.Client
	WorkDir       string
	Limits        Limits
}

type yumPrimaryReference struct {
	Location    string
	SHA256      string
	Size        int64
	OpenSHA256  string
	OpenSize    int64
	HasOpenSize bool
}

// DiscoverYUM is the compatibility, materializing wrapper. New production
// callers should use DiscoverYUMStreaming.
func DiscoverYUM(ctx context.Context, source YUMSource) (*Discovery, error) {
	discovery, err := DiscoverYUMStreaming(ctx, source)
	if err != nil {
		return nil, err
	}
	if err := materializeCandidates(discovery); err != nil {
		_ = discovery.Close()
		return nil, err
	}
	return discovery, nil
}

// DiscoverYUMStreaming downloads and verifies signed repomd/primary metadata,
// then spools selected RPM package/proof records to a bounded-memory cursor.
func DiscoverYUMStreaming(ctx context.Context, source YUMSource) (*Discovery, error) {
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
	if source.WorkDir == "" {
		return nil, fmt.Errorf("%w: YUM work directory is required", ErrInvalidMetadata)
	}
	if source.Keyring == nil {
		return nil, fmt.Errorf("%w: YUM trusted keyring is required", ErrSignature)
	}
	if len(source.Architectures) != 0 {
		if err := validateUniqueSegments("architecture", source.Architectures); err != nil {
			return nil, err
		}
	}
	repomdURL, err := resolveRelative(base, "repodata/repomd.xml")
	if err != nil {
		return nil, err
	}
	repomd, _, err := fetchBytes(ctx, source.Client, repomdURL, limits.RepomdBytes, false)
	if err != nil {
		return nil, err
	}
	signatureURL, err := resolveRelative(base, "repodata/repomd.xml.asc")
	if err != nil {
		return nil, err
	}
	signature, signatureFound, err := fetchBytes(ctx, source.Client, signatureURL, limits.SignatureBytes, true)
	if err != nil {
		return nil, err
	}
	if !signatureFound {
		return nil, fmt.Errorf("%w: repomd.xml.asc is absent", ErrSignature)
	}
	if err = verifyDetached(repomd, signature, source.Keyring); err != nil {
		return nil, fmt.Errorf("%w: repomd.xml.asc: %v", ErrSignature, err)
	}
	repomdEvidence, err := preserveBytes(source.WorkDir, "yum-repomd", repomdURL, repomd, true)
	if err != nil {
		return nil, err
	}
	discovery, err := newDiscovery("rpm", source.WorkDir)
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = discovery.Close()
		}
	}()
	discovery.Evidence = []Evidence{repomdEvidence}
	sigEvidence, err := preserveBytes(source.WorkDir, "yum-repomd-signature", signatureURL, signature, true)
	if err != nil {
		return nil, err
	}
	discovery.Evidence = append(discovery.Evidence, sigEvidence)

	primaryRef, err := parseRepomd(repomd, limits.XMLDepth, limits.XMLTokenBytes)
	if err != nil {
		return nil, err
	}
	primaryURL, err := resolveRelative(base, primaryRef.Location)
	if err != nil {
		return nil, err
	}
	metadataCandidate := syncer.Candidate{
		Format: "rpm", Name: "primary", Version: primaryRef.SHA256, Arch: "noarch",
		URL: primaryURL, Size: primaryRef.Size, SHA256: primaryRef.SHA256,
	}
	primaryEvidence, err := downloadEvidence(ctx, source.WorkDir, "yum-primary", metadataCandidate, source.Client, limits)
	if err != nil {
		return nil, err
	}
	discovery.Evidence = append(discovery.Evidence, primaryEvidence)
	stream, err := openIndex(primaryEvidence.Path, primaryURL, limits)
	if err != nil {
		return nil, err
	}
	proof := provenance.RPMProof{
		IndexURL: primaryURL, IndexSHA256: primaryRef.SHA256, IndexSize: primaryRef.Size,
		SignaturePolicy: "preserve-upstream",
	}
	err = parsePrimaryLimited(&interruptibleReader{ctx: ctx, r: newXMLTokenLimitReader(stream, limits.XMLTokenBytes)}, base, limits.XMLDepth, limits.PackageCount, func(candidate syncer.Candidate) error {
		if candidate.Arch == "noarch" && source.ExcludeNoarch {
			return nil
		}
		if len(source.Architectures) != 0 && candidate.Arch != "noarch" && !containsString(source.Architectures, candidate.Arch) {
			return nil
		}
		perPackage := proof
		perPackage.OriginalRPMSHA = candidate.SHA256
		return addDiscoveredCandidate(discovery, candidate, candidateProof{rpm: &perPackage})
	})
	openSHA, openSize := stream.digest()
	closeErr := stream.Close()
	if err != nil || closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}
	if primaryRef.OpenSHA256 != "" && primaryRef.OpenSHA256 != openSHA {
		return nil, fmt.Errorf("%w: primary open-checksum mismatch", ErrInvalidMetadata)
	}
	if primaryRef.HasOpenSize && primaryRef.OpenSize != openSize {
		return nil, fmt.Errorf("%w: primary open-size mismatch", ErrInvalidMetadata)
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

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

type repomdXML struct {
	XMLName xml.Name     `xml:"repomd"`
	Data    []repomdData `xml:"data"`
}

type repomdData struct {
	Type         string       `xml:"type,attr"`
	Checksum     checksumText `xml:"checksum"`
	OpenChecksum checksumText `xml:"open-checksum"`
	Location     locationHref `xml:"location"`
	Size         *int64       `xml:"size"`
	OpenSize     *int64       `xml:"open-size"`
}

type checksumText struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type locationHref struct {
	Href string `xml:"href,attr"`
}

func parseRepomd(data []byte, maxDepth, maxToken int) (yumPrimaryReference, error) {
	if err := validateXMLSecurity(newXMLTokenLimitReader(bytes.NewReader(data), maxToken), yumRepoNamespace, "repomd", maxDepth); err != nil {
		return yumPrimaryReference{}, err
	}
	decoder := xml.NewDecoder(newXMLTokenLimitReader(bytes.NewReader(data), maxToken))
	decoder.Strict = true
	var document repomdXML
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, ErrMetadataTooLarge) || errors.Is(err, ErrInvalidMetadata) {
			return yumPrimaryReference{}, err
		}
		return yumPrimaryReference{}, fmt.Errorf("%w: decode repomd.xml: %v", ErrInvalidMetadata, err)
	}
	if document.XMLName.Space != yumRepoNamespace || document.XMLName.Local != "repomd" {
		return yumPrimaryReference{}, fmt.Errorf("%w: unexpected repomd root", ErrInvalidMetadata)
	}
	var primary *repomdData
	for i := range document.Data {
		if document.Data[i].Type != "primary" {
			continue
		}
		if primary != nil {
			return yumPrimaryReference{}, fmt.Errorf("%w: duplicate primary record", ErrInvalidMetadata)
		}
		primary = &document.Data[i]
	}
	if primary == nil || primary.Size == nil || *primary.Size <= 0 {
		return yumPrimaryReference{}, fmt.Errorf("%w: missing/invalid primary record size", ErrInvalidMetadata)
	}
	primary.Checksum.Value = strings.TrimSpace(primary.Checksum.Value)
	if primary.Checksum.Type != "sha256" || !validSHA256(primary.Checksum.Value) {
		return yumPrimaryReference{}, fmt.Errorf("%w: primary checksum must be SHA-256", ErrInvalidMetadata)
	}
	if err := validateRelativePath(primary.Location.Href); err != nil || !strings.HasPrefix(primary.Location.Href, "repodata/") {
		return yumPrimaryReference{}, fmt.Errorf("%w: unsafe primary location %q", ErrInvalidMetadata, primary.Location.Href)
	}
	ref := yumPrimaryReference{Location: primary.Location.Href, SHA256: primary.Checksum.Value, Size: *primary.Size}
	if primary.OpenChecksum.Value != "" {
		primary.OpenChecksum.Value = strings.TrimSpace(primary.OpenChecksum.Value)
		if primary.OpenChecksum.Type != "sha256" || !validSHA256(primary.OpenChecksum.Value) {
			return yumPrimaryReference{}, fmt.Errorf("%w: invalid primary open-checksum", ErrInvalidMetadata)
		}
		ref.OpenSHA256 = primary.OpenChecksum.Value
	}
	if primary.OpenSize != nil {
		if *primary.OpenSize < 0 {
			return yumPrimaryReference{}, fmt.Errorf("%w: negative primary open-size", ErrInvalidMetadata)
		}
		ref.OpenSize, ref.HasOpenSize = *primary.OpenSize, true
	}
	return ref, nil
}

func validateXMLSecurity(reader io.Reader, namespace, root string, maxDepth int) error {
	decoder := xml.NewDecoder(reader)
	decoder.Strict = true
	depth := 0
	rootSeen := false
	rootClosed := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, ErrMetadataTooLarge) || errors.Is(err, ErrInvalidMetadata) {
				return err
			}
			return fmt.Errorf("%w: XML parse: %v", ErrInvalidMetadata, err)
		}
		switch value := token.(type) {
		case xml.Directive:
			return fmt.Errorf("%w: XML directives/DTD are forbidden", ErrInvalidMetadata)
		case xml.ProcInst:
			if !strings.EqualFold(value.Target, "xml") || rootSeen {
				return fmt.Errorf("%w: XML processing instructions are forbidden", ErrInvalidMetadata)
			}
		case xml.StartElement:
			if depth == 0 {
				if rootSeen || rootClosed || value.Name.Space != namespace || value.Name.Local != root {
					return fmt.Errorf("%w: unexpected XML root", ErrInvalidMetadata)
				}
				rootSeen = true
			} else if value.Name.Space != namespace {
				return fmt.Errorf("%w: foreign XML namespace %q in %s", ErrInvalidMetadata, value.Name.Space, root)
			}
			depth++
			if depth > maxDepth {
				return fmt.Errorf("%w: XML nesting exceeds %d", ErrMetadataTooLarge, maxDepth)
			}
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(value)) != 0 {
				return fmt.Errorf("%w: non-whitespace outside XML root", ErrInvalidMetadata)
			}
		case xml.EndElement:
			depth--
			if depth < 0 {
				return fmt.Errorf("%w: unbalanced XML", ErrInvalidMetadata)
			}
			if depth == 0 {
				rootClosed = true
			}
		}
	}
	if !rootSeen || !rootClosed || depth != 0 {
		return fmt.Errorf("%w: incomplete XML document", ErrInvalidMetadata)
	}
	return nil
}

type primaryPackage struct {
	Name, Arch, Epoch, Version, Release string
	Checksum, Location                  string
	Size                                int64
	checksumType                        string
	seenName, seenArch, seenChecksum    bool
	seenVersion, seenSize, seenLocation bool
}

func parsePrimaryLimited(reader io.Reader, base *url.URL, maxDepth, maxPackages int, accept func(syncer.Candidate) error) error {
	if maxPackages <= 0 {
		return fmt.Errorf("%w: invalid package count limit", ErrInvalidMetadata)
	}
	decoder := xml.NewDecoder(reader)
	decoder.Strict = true
	depth := 0
	rootSeen, rootClosed := false, false
	declared := int64(-1)
	actual := int64(0)
	inPackage, packageDepth := false, 0
	var pkg primaryPackage
	capture, captureValue, captureDepth := "", strings.Builder{}, 0

	setCaptured := func() error {
		value := strings.TrimSpace(captureValue.String())
		switch capture {
		case "name":
			if pkg.seenName {
				return fmt.Errorf("%w: duplicate primary package name", ErrInvalidMetadata)
			}
			pkg.Name, pkg.seenName = value, true
		case "arch":
			if pkg.seenArch {
				return fmt.Errorf("%w: duplicate primary package arch", ErrInvalidMetadata)
			}
			pkg.Arch, pkg.seenArch = value, true
		case "checksum":
			if pkg.seenChecksum {
				return fmt.Errorf("%w: duplicate primary package checksum", ErrInvalidMetadata)
			}
			pkg.Checksum, pkg.seenChecksum = value, true
		}
		capture = ""
		captureValue.Reset()
		captureDepth = 0
		return nil
	}

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, ErrMetadataTooLarge) || errors.Is(err, ErrInvalidMetadata) {
				return err
			}
			return fmt.Errorf("%w: decode primary XML: %v", ErrInvalidMetadata, err)
		}
		switch value := token.(type) {
		case xml.Directive:
			return fmt.Errorf("%w: XML directives/DTD are forbidden", ErrInvalidMetadata)
		case xml.ProcInst:
			if !strings.EqualFold(value.Target, "xml") || rootSeen {
				return fmt.Errorf("%w: XML processing instructions are forbidden", ErrInvalidMetadata)
			}
		case xml.StartElement:
			if capture != "" {
				return fmt.Errorf("%w: nested markup in primary scalar field", ErrInvalidMetadata)
			}
			if depth == 0 {
				if rootSeen || rootClosed || value.Name.Space != yumCommonNamespace || value.Name.Local != "metadata" {
					return fmt.Errorf("%w: unexpected primary XML root", ErrInvalidMetadata)
				}
				rootSeen = true
				packages, ok, attributeErr := xmlAttributeStrict(value.Attr, "packages")
				if attributeErr != nil {
					return attributeErr
				}
				if !ok {
					return fmt.Errorf("%w: primary metadata lacks package count", ErrInvalidMetadata)
				}
				declared, err = strconv.ParseInt(packages, 10, 64)
				if err != nil || declared < 0 || declared > int64(maxPackages) {
					return fmt.Errorf("%w: invalid primary package count", ErrInvalidMetadata)
				}
			} else if depth == 1 && value.Name.Space == yumCommonNamespace && value.Name.Local == "package" {
				if inPackage {
					return fmt.Errorf("%w: nested primary package", ErrInvalidMetadata)
				}
				packageType, ok, attributeErr := xmlAttributeStrict(value.Attr, "type")
				if attributeErr != nil {
					return attributeErr
				}
				if !ok || packageType != "rpm" {
					return fmt.Errorf("%w: primary package type is not rpm", ErrInvalidMetadata)
				}
				inPackage, packageDepth, pkg = true, depth+1, primaryPackage{}
			} else if inPackage && depth == packageDepth {
				if value.Name.Space != yumCommonNamespace {
					switch value.Name.Local {
					case "name", "arch", "checksum", "version", "size", "location":
						return fmt.Errorf("%w: foreign namespace on primary %s field", ErrInvalidMetadata, value.Name.Local)
					}
				}
				switch value.Name.Local {
				case "name", "arch", "checksum":
					capture, captureDepth = value.Name.Local, depth+1
					captureValue.Reset()
					if capture == "checksum" {
						var attributeErr error
						pkg.checksumType, _, attributeErr = xmlAttributeStrict(value.Attr, "type")
						if attributeErr != nil {
							return attributeErr
						}
						pkgID, found, attributeErr := xmlAttributeStrict(value.Attr, "pkgid")
						if attributeErr != nil {
							return attributeErr
						}
						if !found || !strings.EqualFold(pkgID, "yes") {
							return fmt.Errorf("%w: primary checksum must be the package id", ErrInvalidMetadata)
						}
					}
				case "version":
					if pkg.seenVersion {
						return fmt.Errorf("%w: duplicate primary version", ErrInvalidMetadata)
					}
					var attributeErr error
					if pkg.Epoch, _, attributeErr = xmlAttributeStrict(value.Attr, "epoch"); attributeErr != nil {
						return attributeErr
					}
					if pkg.Version, _, attributeErr = xmlAttributeStrict(value.Attr, "ver"); attributeErr != nil {
						return attributeErr
					}
					if pkg.Release, _, attributeErr = xmlAttributeStrict(value.Attr, "rel"); attributeErr != nil {
						return attributeErr
					}
					pkg.seenVersion = true
				case "size":
					if pkg.seenSize {
						return fmt.Errorf("%w: duplicate primary size", ErrInvalidMetadata)
					}
					rawSize, ok, attributeErr := xmlAttributeStrict(value.Attr, "package")
					if attributeErr != nil {
						return attributeErr
					}
					if !ok {
						return fmt.Errorf("%w: primary package lacks size", ErrInvalidMetadata)
					}
					pkg.Size, err = strconv.ParseInt(rawSize, 10, 64)
					if err != nil || pkg.Size < 0 {
						return fmt.Errorf("%w: invalid primary package size", ErrInvalidMetadata)
					}
					pkg.seenSize = true
				case "location":
					if pkg.seenLocation {
						return fmt.Errorf("%w: duplicate primary location", ErrInvalidMetadata)
					}
					var attributeErr error
					pkg.Location, _, attributeErr = xmlAttributeStrict(value.Attr, "href")
					if attributeErr != nil {
						return attributeErr
					}
					pkg.seenLocation = true
				}
			}
			depth++
			if depth > maxDepth {
				return fmt.Errorf("%w: primary XML nesting exceeds %d", ErrMetadataTooLarge, maxDepth)
			}
		case xml.CharData:
			if capture != "" {
				if captureValue.Len()+len(value) > maxXMLFieldBytes {
					return fmt.Errorf("%w: primary XML field too large", ErrMetadataTooLarge)
				}
				captureValue.Write([]byte(value))
			} else if depth == 0 && len(bytes.TrimSpace(value)) != 0 {
				return fmt.Errorf("%w: non-whitespace outside primary root", ErrInvalidMetadata)
			}
		case xml.EndElement:
			depth--
			if depth < 0 {
				return fmt.Errorf("%w: unbalanced primary XML", ErrInvalidMetadata)
			}
			if capture != "" && depth == captureDepth-1 {
				if err := setCaptured(); err != nil {
					return err
				}
			}
			if inPackage && depth == packageDepth-1 {
				candidate, err := primaryCandidate(pkg, base)
				if err != nil {
					return err
				}
				if err := accept(candidate); err != nil {
					return err
				}
				actual++
				if actual > int64(maxPackages) {
					return fmt.Errorf("%w: primary contains more than %d packages", ErrMetadataTooLarge, maxPackages)
				}
				inPackage = false
			}
			if depth == 0 {
				rootClosed = true
			}
		}
	}
	if !rootSeen || !rootClosed || inPackage || depth != 0 || declared != actual {
		return fmt.Errorf("%w: primary package count/document mismatch: declared=%d actual=%d", ErrInvalidMetadata, declared, actual)
	}
	return nil
}

func primaryCandidate(pkg primaryPackage, base *url.URL) (syncer.Candidate, error) {
	if !pkg.seenName || !pkg.seenArch || !pkg.seenVersion || !pkg.seenChecksum || !pkg.seenSize || !pkg.seenLocation ||
		pkg.Name == "" || pkg.Arch == "" || pkg.Version == "" || pkg.Release == "" ||
		pkg.Size <= 0 || pkg.checksumType != "sha256" || !validSHA256(pkg.Checksum) {
		return syncer.Candidate{}, fmt.Errorf("%w: incomplete or non-SHA256 primary package", ErrInvalidMetadata)
	}
	for kind, value := range map[string]string{"RPM name": pkg.Name, "RPM architecture": pkg.Arch, "RPM version": pkg.Version, "RPM release": pkg.Release} {
		if err := validateIdentity(kind, value); err != nil {
			return syncer.Candidate{}, err
		}
	}
	if err := validateRelativePath(pkg.Location); err != nil || !strings.HasSuffix(pkg.Location, ".rpm") {
		return syncer.Candidate{}, fmt.Errorf("%w: unsafe RPM location %q", ErrInvalidMetadata, pkg.Location)
	}
	packageURL, err := resolveRelative(base, pkg.Location)
	if err != nil {
		return syncer.Candidate{}, err
	}
	version := pkg.Version + "-" + pkg.Release
	if pkg.Epoch != "" && pkg.Epoch != "0" {
		if _, err := strconv.ParseUint(pkg.Epoch, 10, 64); err != nil {
			return syncer.Candidate{}, fmt.Errorf("%w: invalid RPM epoch", ErrInvalidMetadata)
		}
		version = pkg.Epoch + ":" + version
	}
	candidate := syncer.Candidate{
		Format: "rpm", Name: pkg.Name, Version: version, Arch: pkg.Arch,
		URL: packageURL, Size: pkg.Size, SHA256: pkg.Checksum,
		DebugInfo: isDebugPackage("rpm", pkg.Name),
	}
	if err := candidate.Validate(); err != nil {
		return syncer.Candidate{}, fmt.Errorf("%w: %v", ErrInvalidMetadata, err)
	}
	return candidate, nil
}

func xmlAttributeStrict(attributes []xml.Attr, local string) (string, bool, error) {
	var value string
	found := false
	for _, attribute := range attributes {
		if attribute.Name.Space != "" || attribute.Name.Local != local {
			continue
		}
		if found {
			return "", false, fmt.Errorf("%w: duplicate XML attribute %s", ErrInvalidMetadata, local)
		}
		value, found = attribute.Value, true
	}
	return value, found, nil
}
