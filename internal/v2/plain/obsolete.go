package plain

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pgsty/sow/internal/yumrepo"
	"pault.ag/go/debian/control"
)

func obsoleteMetadataActions(ctx context.Context, root string, journal operationJournal, staged stagedBuild) ([]fileAction, error) {
	var actions []fileAction
	if staged.rpmPresent {
		stale, err := staleRPMActions(ctx, root, journal, staged)
		if err != nil {
			return nil, err
		}
		actions = append(actions, stale...)
	} else {
		rpmActions, err := obsoleteRPMActions(ctx, root, journal)
		if err != nil {
			return nil, err
		}
		actions = append(actions, rpmActions...)
	}
	if !staged.debPresent {
		debActions, err := obsoleteDEBActions(ctx, root, journal)
		if err != nil {
			return nil, err
		}
		actions = append(actions, debActions...)
	}
	return actions, nil
}

func staleRPMActions(ctx context.Context, root string, journal operationJournal, staged stagedBuild) ([]fileAction, error) {
	liveDir := filepath.Join(root, "repodata")
	info, err := os.Lstat(liveDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, &Error{Kind: KindIntegrity, Op: "inspect prior rpm index", Path: liveDir, Err: errors.Join(err, errors.New("repodata is not a real directory"))}
	}
	ownedNames, owned, err := ownedRPMMetadata(ctx, filepath.Join(root, journal.Stage), liveDir)
	if err != nil {
		return nil, err
	}
	if !owned {
		return nil, nil
	}
	stagedDir := filepath.Join(staged.dir, "repodata")
	stagedEntries, err := os.ReadDir(stagedDir)
	if err != nil {
		return nil, &Error{Kind: KindRuntime, Op: "list staged rpm index", Path: stagedDir, Err: err}
	}
	keep := make(map[string]struct{}, len(stagedEntries))
	for _, entry := range stagedEntries {
		keep[entry.Name()] = struct{}{}
	}
	var actions []fileAction
	for _, name := range ownedNames {
		if name == "repomd.xml" {
			continue
		}
		if _, retained := keep[name]; retained {
			continue
		}
		source := filepath.Join("repodata", name)
		digest, err := hashFile(ctx, filepath.Join(root, source))
		if err != nil {
			return nil, err
		}
		actions = append(actions, fileAction{
			Kind: "move", Source: source,
			Target: filepath.Join(journal.Trash, "stale", source), SHA256: digest,
		})
	}
	return actions, nil
}

func obsoleteRPMActions(ctx context.Context, root string, journal operationJournal) ([]fileAction, error) {
	dir := filepath.Join(root, "repodata")
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		// With no RPM input, an unrelated/non-directory repodata path is an
		// unknown file. Plain Create does not inspect or mutate it.
		return nil, nil
	}
	names, owned, err := ownedRPMMetadata(ctx, filepath.Join(root, journal.Stage), dir)
	if err != nil {
		return nil, err
	}
	if !owned {
		return nil, nil
	}
	actions := make([]fileAction, 0, len(names))
	for _, name := range names {
		source := filepath.Join("repodata", name)
		digest, err := hashFile(ctx, filepath.Join(root, source))
		if err != nil {
			return nil, err
		}
		actions = append(actions, fileAction{
			Kind: "move", Source: source,
			Target: filepath.Join(journal.Trash, "obsolete", source), SHA256: digest,
			Before: FaultBeforeRPMRemoval, After: FaultAfterRPMRemoval,
		})
	}
	return actions, nil
}

type rpmOwnershipPointer struct {
	XMLName xml.Name             `xml:"repomd"`
	Data    []rpmOwnershipRecord `xml:"data"`
}

type rpmOwnershipRecord struct {
	Type     string `xml:"type,attr"`
	Checksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"checksum"`
	Location struct {
		Href string `xml:"href,attr"`
	} `xml:"location"`
}

// ownedRPMMetadata recognizes only the closed SOW plain pointer and its three
// content-addressed primary/filelists/other objects. Extra files are neither
// opened nor validated, so custom metadata and modulemd remain opaque.
func ownedRPMMetadata(ctx context.Context, proofParent, dir string) ([]string, bool, error) {
	pointerPath := filepath.Join(dir, "repomd.xml")
	info, err := os.Lstat(pointerPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, &Error{Kind: KindRuntime, Op: "inspect rpm pointer", Path: pointerPath, Err: err}
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 1<<20 {
		return nil, false, nil
	}
	body, err := os.ReadFile(pointerPath)
	if err != nil {
		return nil, false, &Error{Kind: KindRuntime, Op: "read rpm pointer", Path: pointerPath, Err: err}
	}
	var pointer rpmOwnershipPointer
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = true
	if err := decoder.Decode(&pointer); err != nil || len(pointer.Data) != 3 {
		return nil, false, nil
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, false, nil
	}
	names := []string{"repomd.xml"}
	seen := make(map[string]struct{}, 3)
	for _, record := range pointer.Data {
		if record.Type != "primary" && record.Type != "filelists" && record.Type != "other" {
			return nil, false, nil
		}
		if _, duplicate := seen[record.Type]; duplicate {
			return nil, false, nil
		}
		seen[record.Type] = struct{}{}
		checksum := strings.TrimSpace(record.Checksum.Value)
		name := strings.TrimPrefix(record.Location.Href, "repodata/")
		if record.Checksum.Type != "sha256" || !validSHA256(checksum) ||
			name == record.Location.Href || filepath.Base(name) != name ||
			name != checksum+"-"+record.Type+".xml.gz" {
			return nil, false, nil
		}
		artifactInfo, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !artifactInfo.Mode().IsRegular() || artifactInfo.Mode()&os.ModeSymlink != 0 {
			return nil, false, nil
		}
		names = append(names, name)
	}
	// Prove the recognized closure with the existing renderer validator, but
	// present only the four SOW-owned entries. Opaque extras are never opened.
	proof, err := os.MkdirTemp(proofParent, ".sow-plain-rpm-proof-")
	if err != nil {
		return nil, false, &Error{Kind: KindRuntime, Op: "create rpm ownership proof", Path: proofParent, Err: err}
	}
	defer os.RemoveAll(proof)
	for _, name := range names {
		if err := os.Link(filepath.Join(dir, name), filepath.Join(proof, name)); err != nil {
			return nil, false, &Error{Kind: KindRuntime, Op: "bind rpm ownership proof", Path: filepath.Join(dir, name), Err: err}
		}
	}
	if _, err := yumrepo.ValidateFlatUnsignedDirectory(ctx, proof, yumrepo.CompressionGzip); err != nil {
		return nil, false, nil
	}
	return names, true, nil
}

func obsoleteDEBActions(ctx context.Context, root string, journal operationJournal) ([]fileAction, error) {
	packagesPath := filepath.Join(root, "Packages")
	gzipPath := filepath.Join(root, "Packages.gz")
	packagesInfo, packagesErr := os.Lstat(packagesPath)
	gzipInfo, gzipErr := os.Lstat(gzipPath)
	packagesExists := packagesErr == nil
	gzipExists := gzipErr == nil
	if errors.Is(packagesErr, os.ErrNotExist) {
		packagesErr = nil
	}
	if errors.Is(gzipErr, os.ErrNotExist) {
		gzipErr = nil
	}
	if packagesErr != nil || gzipErr != nil {
		return nil, &Error{Kind: KindRuntime, Op: "inspect obsolete deb index", Path: root, Err: errors.Join(packagesErr, gzipErr)}
	}
	if !packagesExists && !gzipExists {
		return nil, nil
	}
	if !packagesExists || !gzipExists || !packagesInfo.Mode().IsRegular() || packagesInfo.Mode()&os.ModeSymlink != 0 || !gzipInfo.Mode().IsRegular() || gzipInfo.Mode()&os.ModeSymlink != 0 {
		return nil, &Error{Kind: KindIntegrity, Op: "prove obsolete deb index ownership", Path: root, Err: errors.New("Packages and Packages.gz are not a complete regular-file pair")}
	}
	if err := validateObsoleteDEBPair(packagesPath, gzipPath); err != nil {
		return nil, &Error{Kind: KindIntegrity, Op: "prove obsolete deb index ownership", Path: root, Err: err}
	}
	var actions []fileAction
	// Withdraw the compressed pointer first. A crash still leaves the complete
	// uncompressed index; after the second move no APT pointer remains.
	for _, name := range []string{"Packages.gz", "Packages"} {
		digest, err := hashFile(ctx, filepath.Join(root, name))
		if err != nil {
			return nil, err
		}
		actions = append(actions, fileAction{
			Kind: "move", Source: name,
			Target: filepath.Join(journal.Trash, "obsolete", name), SHA256: digest,
			Before: FaultBeforeDEBRemoval, After: FaultAfterDEBRemoval,
		})
	}
	return actions, nil
}

func validateObsoleteDEBPair(packagesPath, gzipPath string) (resultErr error) {
	packagesInfo, err := os.Lstat(packagesPath)
	if err != nil {
		return err
	}
	gzipInfo, err := os.Lstat(gzipPath)
	if err != nil {
		return err
	}
	packagesFile, err := os.Open(packagesPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, packagesFile.Close()) }()
	openedPackages, err := packagesFile.Stat()
	if err != nil || !openedPackages.Mode().IsRegular() || !os.SameFile(packagesInfo, openedPackages) {
		return errors.Join(err, errors.New("Packages changed while opening"))
	}
	gzipFile, err := os.Open(gzipPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, gzipFile.Close()) }()
	openedGzip, err := gzipFile.Stat()
	if err != nil || !openedGzip.Mode().IsRegular() || !os.SameFile(gzipInfo, openedGzip) {
		return errors.Join(err, errors.New("Packages.gz changed while opening"))
	}
	ctx := context.Background()
	rawDigest, rawSize, err := hashStream(ctx, &contextReader{ctx: ctx, reader: packagesFile})
	if err != nil {
		return err
	}
	if _, err := packagesFile.Seek(0, io.SeekStart); err != nil {
		return err
	}
	zr, err := gzip.NewReader(&contextReader{ctx: ctx, reader: gzipFile})
	if err != nil {
		return err
	}
	decodedDigest, decodedSize, readErr := hashStream(ctx, io.LimitReader(zr, packagesInfo.Size()+1))
	closeErr := zr.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	if rawSize != packagesInfo.Size() || decodedSize != rawSize || rawDigest != decodedDigest {
		return errors.New("Packages.gz does not expand exactly to Packages")
	}
	reader, err := control.NewParagraphReader(&contextReader{ctx: ctx, reader: packagesFile}, nil)
	if err != nil {
		return err
	}
	for position := 0; ; position++ {
		paragraph, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("parse Packages entry %d: %w", position, err)
		}
		values := paragraph.Values
		filename := values["Filename"]
		base := strings.TrimPrefix(filename, "./")
		if values["Package"] == "" || values["Version"] == "" || values["Architecture"] == "" ||
			!strings.HasPrefix(filename, "./") || filepath.Base(base) != base || !strings.HasSuffix(base, ".deb") ||
			!validSHA256(values["SHA256"]) {
			return fmt.Errorf("Packages entry %d is not a SOW flat package record", position)
		}
		if size, err := strconv.ParseInt(values["Size"], 10, 64); err != nil || size < 0 {
			return fmt.Errorf("Packages entry %d has an invalid Size", position)
		}
		seen := make(map[string]struct{}, len(paragraph.Order))
		for _, field := range paragraph.Order {
			folded := strings.ToLower(field)
			if _, duplicate := seen[folded]; duplicate {
				return fmt.Errorf("Packages entry %d repeats field %q", position, field)
			}
			seen[folded] = struct{}{}
		}
	}
	packagesOpenedAfter, packagesOpenErr := packagesFile.Stat()
	gzipOpenedAfter, gzipOpenErr := gzipFile.Stat()
	packagesAfter, packagesErr := os.Lstat(packagesPath)
	gzipAfter, gzipErr := os.Lstat(gzipPath)
	if packagesErr != nil || gzipErr != nil || !os.SameFile(packagesInfo, packagesAfter) || !os.SameFile(gzipInfo, gzipAfter) ||
		packagesOpenErr != nil || gzipOpenErr != nil || !os.SameFile(packagesInfo, packagesOpenedAfter) || !os.SameFile(gzipInfo, gzipOpenedAfter) ||
		packagesInfo.Size() != packagesAfter.Size() || gzipInfo.Size() != gzipAfter.Size() ||
		!packagesInfo.ModTime().Equal(packagesAfter.ModTime()) || !gzipInfo.ModTime().Equal(gzipAfter.ModTime()) {
		return errors.Join(packagesErr, gzipErr, errors.New("flat DEB index changed while proving ownership"))
	}
	return nil
}

func hashStream(ctx context.Context, reader io.Reader) ([sha256.Size]byte, int64, error) {
	hasher := sha256.New()
	buffer := make([]byte, 128*1024)
	size, err := io.CopyBuffer(hasher, &contextReader{ctx: ctx, reader: reader}, buffer)
	if err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, size, nil
}

func isRPMRemovalAction(journal operationJournal, action fileAction) bool {
	if action.Kind != "move" || action.Replace || action.Package != "" ||
		action.Before != FaultBeforeRPMRemoval || action.After != FaultAfterRPMRemoval ||
		filepath.Dir(action.Source) != "repodata" {
		return false
	}
	return action.Target == filepath.Join(journal.Trash, "obsolete", action.Source)
}

func isRPMStaleAction(journal operationJournal, action fileAction) bool {
	if action.Kind != "move" || action.Replace || action.Package != "" || action.Before != "" || action.After != "" ||
		filepath.Dir(action.Source) != "repodata" || filepath.Base(action.Source) == "repomd.xml" {
		return false
	}
	return action.Target == filepath.Join(journal.Trash, "stale", action.Source)
}

func isDEBRemovalAction(journal operationJournal, action fileAction, compressed bool) bool {
	name := "Packages"
	if compressed {
		name = "Packages.gz"
	}
	return action.Kind == "move" && !action.Replace && action.Package == "" && action.Source == name &&
		action.Target == filepath.Join(journal.Trash, "obsolete", name) &&
		action.Before == FaultBeforeDEBRemoval && action.After == FaultAfterDEBRemoval
}

func journalRemovesRPM(journal operationJournal) bool {
	for _, action := range journal.Actions {
		if isRPMRemovalAction(journal, action) {
			return true
		}
	}
	return false
}
