package plain

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/yumrepo"
)

func TestCreateDEBFlatRegularOnlyStable(t *testing.T) {
	dir := t.TempDir()
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1:1.2.3-1", "amd64"), "alpha")
	writeDEBFixture(t, filepath.Join(mustMkdir(t, filepath.Join(dir, "nested"))), "nested.deb", debControl("nested", "1.0-1", "amd64"), "nested")
	if err := os.Symlink(filepath.Join(dir, "alpha.deb"), filepath.Join(dir, "linked.deb")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unknown.txt"), []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}

	first, err := Create(context.Background(), Options{Dir: dir, Jobs: 4})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if first.RPM != 0 || first.DEB != 1 || strings.Join(first.Kept, ",") != "alpha.deb" || first.Marker {
		t.Fatalf("unexpected result: %+v", first)
	}
	packages := mustRead(t, filepath.Join(dir, "Packages"))
	if !bytes.Contains(packages, []byte("Package: alpha\n")) || !bytes.Contains(packages, []byte("Filename: ./alpha.deb\n")) {
		t.Fatalf("flat Packages missing expected fields:\n%s", packages)
	}
	if bytes.Contains(packages, []byte("nested")) || bytes.Contains(packages, []byte("linked")) {
		t.Fatalf("non-top-level package entered index:\n%s", packages)
	}
	if got := gunzip(t, mustRead(t, filepath.Join(dir, "Packages.gz"))); !bytes.Equal(got, packages) {
		t.Fatal("Packages.gz does not expand to Packages")
	}
	before := append([]byte(nil), packages...)
	beforeGzip := mustRead(t, filepath.Join(dir, "Packages.gz"))
	second, err := Create(context.Background(), Options{Dir: dir, Jobs: 1})
	if err != nil {
		t.Fatalf("repeat Create: %v", err)
	}
	if !second.Noop {
		t.Fatalf("repeat Create was not a no-op: %+v", second)
	}
	if !bytes.Equal(before, mustRead(t, filepath.Join(dir, "Packages"))) || !bytes.Equal(beforeGzip, mustRead(t, filepath.Join(dir, "Packages.gz"))) {
		t.Fatal("repeat Create changed deterministic DEB metadata")
	}
	for _, forbidden := range []string{"repo_complete", "sow.yml", ".sow"} {
		if _, err := os.Lstat(filepath.Join(dir, forbidden)); !os.IsNotExist(err) {
			t.Fatalf("default create unexpectedly produced %s", forbidden)
		}
	}
}

func TestCreateRPMFlatAndMixed(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "zeta.rpm"), rpmFixture{Name: "zeta", Version: "2.0", Release: "1", Arch: "x86_64", Payload: "zeta"})
	writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1.0", Release: "2", Arch: "noarch", Payload: "alpha"})
	writeDEBFixture(t, dir, "bravo.deb", debControl("bravo", "1.0-1", "arm64"), "bravo")

	result, err := Create(context.Background(), Options{Dir: dir, Jobs: 3})
	if err != nil {
		t.Fatalf("Create mixed: %v", err)
	}
	if result.RPM != 2 || result.DEB != 1 {
		t.Fatalf("unexpected mixed result: %+v", result)
	}
	if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), filepath.Join(dir, "repodata"), yumrepo.CompressionGzip); err != nil {
		t.Fatalf("validate flat RPM metadata: %v", err)
	}
	primary := readPrimaryXML(t, filepath.Join(dir, "repodata"))
	for _, location := range []string{`href="alpha.rpm"`, `href="zeta.rpm"`} {
		if !bytes.Contains(primary, []byte(location)) {
			t.Fatalf("primary metadata missing %s:\n%s", location, primary)
		}
	}
	if bytes.Contains(primary, []byte("Packages/")) {
		t.Fatal("flat RPM metadata used managed Packages/<bucket> location")
	}
	if _, err := os.Lstat(filepath.Join(dir, "repodata", "repomd.xml.asc")); !os.IsNotExist(err) {
		t.Fatal("plain RPM unexpectedly generated a signature")
	}
}

func TestCreateSignWithFillsOnlyUnsignedRPMs(t *testing.T) {
	const key = "E7935D8DB9BD8B20"
	dir := t.TempDir()
	unsigned := filepath.Join(dir, "alpha.rpm")
	signed := filepath.Join(dir, "zeta.rpm")
	writeRPMFixture(t, unsigned, rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "alpha"})
	writeRPMFixture(t, signed, rpmFixture{Name: "zeta", Version: "1", Release: "1", Arch: "noarch", Payload: "zeta"})
	if err := replaceTestRPMSignature(signed, "0123456789ABCDEF"); err != nil {
		t.Fatal(err)
	}
	unsignedBefore, signedBefore := fileSHA(unsigned), fileSHA(signed)
	var calls []string
	result, err := Create(context.Background(), Options{
		Dir: dir, SignWith: "0x" + strings.ToLower(key),
		SignRPM: func(ctx context.Context, path, gotKey string, overwrite bool) error {
			if gotKey != key || overwrite {
				return fmt.Errorf("unexpected signer request key=%s overwrite=%t", gotKey, overwrite)
			}
			calls = append(calls, filepath.Base(path))
			return replaceTestRPMSignature(path, gotKey)
		},
	})
	if err != nil {
		t.Fatalf("Create --sign-with: %v", err)
	}
	if strings.Join(calls, ",") != "alpha.rpm" || strings.Join(result.Signed, ",") != "alpha.rpm" || result.Signer != key {
		t.Fatalf("calls=%v result=%+v", calls, result)
	}
	if fileSHA(unsigned) == unsignedBefore {
		t.Fatal("unsigned RPM bytes did not change")
	}
	if fileSHA(signed) != signedBefore {
		t.Fatal("already-signed RPM was changed by fill mode")
	}
	for _, path := range []string{unsigned, signed} {
		if present, err := hasEmbeddedRPMSignature(context.Background(), path); err != nil || !present {
			t.Fatalf("signature %s: present=%t err=%v", path, present, err)
		}
	}
	primary := readPrimaryXML(t, filepath.Join(dir, "repodata"))
	if !bytes.Contains(primary, []byte(fileSHA(unsigned))) || !bytes.Contains(primary, []byte(fileSHA(signed))) {
		t.Fatal("rpm-md does not bind final signed package SHA-256 values")
	}
}

func TestCreateSignWithOverwriteResignsEveryRPM(t *testing.T) {
	const key = "E7935D8DB9BD8B20"
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "alpha.rpm"), filepath.Join(dir, "zeta.rpm")}
	writeRPMFixture(t, paths[0], rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "alpha"})
	writeRPMFixture(t, paths[1], rpmFixture{Name: "zeta", Version: "1", Release: "1", Arch: "noarch", Payload: "zeta"})
	for _, path := range paths {
		if err := replaceTestRPMSignature(path, "0123456789ABCDEF"); err != nil {
			t.Fatal(err)
		}
	}
	before := map[string]string{paths[0]: fileSHA(paths[0]), paths[1]: fileSHA(paths[1])}
	var calls []string
	result, err := Create(context.Background(), Options{
		Dir: dir, SignWith: key, Overwrite: true,
		SignRPM: func(_ context.Context, path, gotKey string, overwrite bool) error {
			if gotKey != key || !overwrite {
				return fmt.Errorf("unexpected signer request key=%s overwrite=%t", gotKey, overwrite)
			}
			calls = append(calls, filepath.Base(path))
			return replaceTestRPMSignature(path, gotKey)
		},
	})
	if err != nil {
		t.Fatalf("Create --overwrite: %v", err)
	}
	if strings.Join(calls, ",") != "alpha.rpm,zeta.rpm" || strings.Join(result.Signed, ",") != "alpha.rpm,zeta.rpm" {
		t.Fatalf("calls=%v result=%+v", calls, result)
	}
	for _, path := range paths {
		if fileSHA(path) == before[path] {
			t.Fatalf("overwrite did not replace %s", filepath.Base(path))
		}
		signatures, err := inspectTestRPMSignatures(path)
		if err != nil || len(signatures) != 1 || signatures[0].IssuerKeyID != strings.ToLower(key) {
			t.Fatalf("signature %s: %+v err=%v", path, signatures, err)
		}
	}
}

func TestCreateSignFailurePreservesPackagesAndExistingMetadata(t *testing.T) {
	dir := t.TempDir()
	rpmPath := filepath.Join(dir, "alpha.rpm")
	writeRPMFixture(t, rpmPath, rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "alpha"})
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	packageBefore := fileSHA(rpmPath)
	pointerBefore := append([]byte(nil), mustRead(t, filepath.Join(dir, "repodata", "repomd.xml"))...)
	want := errors.New("signer unavailable")
	_, err := Create(context.Background(), Options{
		Dir: dir, SignWith: "E7935D8DB9BD8B20",
		SignRPM: func(context.Context, string, string, bool) error { return want },
	})
	if !errors.Is(err, want) || KindOf(err) != KindRuntime {
		t.Fatalf("sign failure=%v kind=%s", err, KindOf(err))
	}
	if fileSHA(rpmPath) != packageBefore || !bytes.Equal(mustRead(t, filepath.Join(dir, "repodata", "repomd.xml")), pointerBefore) {
		t.Fatal("stage signing failure changed live package or metadata")
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stage signing failure persisted journal: %v", err)
	}
	for _, pattern := range []string{".sow-plain-stage-*", ".sow-plain-recovery-*"} {
		if matches, globErr := filepath.Glob(filepath.Join(dir, pattern)); globErr != nil || len(matches) != 0 {
			t.Fatalf("stage signing failure left %s: %v %v", pattern, matches, globErr)
		}
	}
}

func TestCreateSigningPreservesPackageMode(t *testing.T) {
	dir := t.TempDir()
	rpmPath := filepath.Join(dir, "alpha.rpm")
	writeRPMFixture(t, rpmPath, rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "alpha"})
	if err := os.Chmod(rpmPath, 0o664|os.ModeSetuid|os.ModeSetgid|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(rpmPath)
	if err != nil {
		t.Fatal(err)
	}
	wantMode := preservedFileMode(before.Mode())
	wantOwner, err := ownershipFromInfo(before)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Create(context.Background(), Options{
		Dir: dir, SignWith: "E7935D8DB9BD8B20",
		SignRPM: func(_ context.Context, path, key string, _ bool) error {
			if err := replaceTestRPMSignature(path, key); err != nil {
				return err
			}
			return os.Chmod(path, 0)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(rpmPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := preservedFileMode(info.Mode()); got != wantMode {
		t.Fatalf("signed RPM mode=%v want %v", got, wantMode)
	}
	gotOwner, err := ownershipFromInfo(info)
	if err != nil {
		t.Fatal(err)
	}
	if gotOwner != wantOwner {
		t.Fatalf("signed RPM owner=%+v want %+v", gotOwner, wantOwner)
	}
}

func TestCreateSigningOptionGuardsAndDuplicateBytes(t *testing.T) {
	if _, err := Create(context.Background(), Options{Dir: t.TempDir(), Overwrite: true}); err == nil || KindOf(err) != KindUsage {
		t.Fatalf("overwrite without key error=%v kind=%s", err, KindOf(err))
	}
	debOnly := t.TempDir()
	writeDEBFixture(t, debOnly, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "alpha")
	if _, err := Create(context.Background(), Options{Dir: debOnly, SignWith: "E7935D8DB9BD8B20"}); err == nil || KindOf(err) != KindRejected {
		t.Fatalf("DEB-only signing error=%v kind=%s", err, KindOf(err))
	}

	dir := t.TempDir()
	one := filepath.Join(dir, "one.rpm")
	two := filepath.Join(dir, "two.rpm")
	writeRPMFixture(t, one, rpmFixture{Name: "same", Version: "1", Release: "1", Arch: "x86_64", Payload: "same"})
	if err := os.WriteFile(two, mustRead(t, one), 0o444); err != nil {
		t.Fatal(err)
	}
	calls := 0
	result, err := Create(context.Background(), Options{
		Dir: dir, SignWith: "E7935D8DB9BD8B20",
		SignRPM: func(_ context.Context, path, key string, overwrite bool) error {
			calls++
			return replaceTestRPMSignature(path, key)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || strings.Join(result.Signed, ",") != "one.rpm,two.rpm" || fileSHA(filepath.Join(dir, "one.rpm")) != fileSHA(filepath.Join(dir, "two.rpm")) {
		t.Fatalf("calls=%d result=%+v duplicate SHA=%s/%s", calls, result, fileSHA(filepath.Join(dir, "one.rpm")), fileSHA(filepath.Join(dir, "two.rpm")))
	}
	for path, want := range map[string]os.FileMode{one: 0o644, two: 0o444} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s mode=%#o want %#o", filepath.Base(path), got, want)
		}
	}
}

func TestCreateRejectsMarkerBeforeMetadataChange(t *testing.T) {
	dir := t.TempDir()
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "alpha")
	old := []byte("old index\n")
	if err := os.WriteFile(filepath.Join(dir, "Packages"), old, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "repo_complete"), []byte("legacy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Create(context.Background(), Options{Dir: dir})
	if err == nil || KindOf(err) != KindRejected {
		t.Fatalf("marker gate error = %v, kind = %s", err, KindOf(err))
	}
	if got := mustRead(t, filepath.Join(dir, "Packages")); !bytes.Equal(got, old) {
		t.Fatalf("marker rejection changed old metadata: %q", got)
	}
}

func TestCreateRejectsCoordinateConflict(t *testing.T) {
	dir := t.TempDir()
	control := debControl("same", "1.0-1", "amd64")
	writeDEBFixture(t, dir, "one.deb", control, "one")
	writeDEBFixture(t, dir, "two.deb", control, "two")
	_, err := Create(context.Background(), Options{Dir: dir, Jobs: 2})
	if err == nil || KindOf(err) != KindRejected || !strings.Contains(err.Error(), "same logical coordinate") {
		t.Fatalf("coordinate conflict error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "Packages")); !os.IsNotExist(err) {
		t.Fatal("coordinate conflict wrote metadata")
	}
}

func TestCreateRejectsRPMCoordinateConflict(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "one.rpm"), rpmFixture{Name: "same", Version: "1", Release: "1", Arch: "x86_64", Payload: "one"})
	writeRPMFixture(t, filepath.Join(dir, "two.rpm"), rpmFixture{Name: "same", Version: "1", Release: "1", Arch: "x86_64", Payload: "two"})
	_, err := Create(context.Background(), Options{Dir: dir, Jobs: 2})
	if err == nil || KindOf(err) != KindRejected || !strings.Contains(err.Error(), "same logical coordinate") {
		t.Fatalf("RPM coordinate conflict error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "repodata")); !os.IsNotExist(err) {
		t.Fatal("RPM coordinate conflict wrote metadata")
	}
}

func TestCreateRejectsEmptyDirectory(t *testing.T) {
	_, err := Create(context.Background(), Options{Dir: t.TempDir()})
	if err == nil || KindOf(err) != KindRejected {
		t.Fatalf("empty directory error = %v, kind = %s", err, KindOf(err))
	}
}

func TestCreateJobsDeterministic(t *testing.T) {
	left, right := t.TempDir(), t.TempDir()
	for _, dir := range []string{left, right} {
		writeDEBFixture(t, dir, "zeta.deb", debControl("zeta", "2.0-1", "amd64"), "zeta")
		writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "all"), "alpha")
		writeRPMFixture(t, filepath.Join(dir, "zeta.rpm"), rpmFixture{Name: "zeta", Version: "2", Release: "1", Arch: "x86_64", Payload: "zeta"})
		writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "noarch", Payload: "alpha"})
	}
	if _, err := Create(context.Background(), Options{Dir: left, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), Options{Dir: right, Jobs: 8}); err != nil {
		t.Fatal(err)
	}
	for _, relative := range append([]string{"Packages", "Packages.gz"}, repodataFiles(t, left)...) {
		if !bytes.Equal(mustRead(t, filepath.Join(left, relative)), mustRead(t, filepath.Join(right, relative))) {
			t.Fatalf("jobs changed output %s", relative)
		}
	}
}

func TestCreateParseErrorSelectionDeterministic(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "z.deb"), []byte("bad z"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.deb"), []byte("bad a"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, one := Create(context.Background(), Options{Dir: dir, Jobs: 1})
	_, many := Create(context.Background(), Options{Dir: dir, Jobs: 8})
	if one == nil || many == nil || one.Error() != many.Error() || !strings.Contains(one.Error(), "a.deb") {
		t.Fatalf("parse errors differ by jobs:\n1: %v\n8: %v", one, many)
	}
}

func TestCreateParseFailurePreservesExistingMetadata(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.deb"), []byte("not a deb"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldPackages := []byte("Package: old\n\n")
	oldGzip := []byte("old gzip bytes")
	if err := os.WriteFile(filepath.Join(dir, "Packages"), oldPackages, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Packages.gz"), oldGzip, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), Options{Dir: dir}); err == nil {
		t.Fatal("invalid package unexpectedly succeeded")
	}
	if !bytes.Equal(mustRead(t, filepath.Join(dir, "Packages")), oldPackages) || !bytes.Equal(mustRead(t, filepath.Join(dir, "Packages.gz")), oldGzip) {
		t.Fatal("parse failure changed old metadata")
	}
}

func TestCreateDeduplicatesIdenticalCoordinateContent(t *testing.T) {
	dir := t.TempDir()
	one := writeDEBFixture(t, dir, "one.deb", debControl("same", "1.0-1", "amd64"), "same")
	body := mustRead(t, one)
	if err := os.WriteFile(filepath.Join(dir, "two.deb"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	if got := bytes.Count(mustRead(t, filepath.Join(dir, "Packages")), []byte("Package: same\n")); got != 1 {
		t.Fatalf("duplicate coordinate emitted %d paragraphs", got)
	}
}

func debControl(name, version, arch string) string {
	return fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: SOW Test <sow@example.invalid>\nDescription: fixture\n", name, version, arch)
}

func writeDEBFixture(t *testing.T, dir, filename, controlText, payload string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	controlTar := tarGzip(t, map[string][]byte{"control": []byte(controlText)})
	dataTar := tarGzip(t, map[string][]byte{"usr/share/sow/payload": []byte(payload)})
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	writeArMember(t, &archive, "debian-binary", []byte("2.0\n"))
	writeArMember(t, &archive, "control.tar.gz", controlTar)
	writeArMember(t, &archive, "data.tar.gz", dataTar)
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func tarGzip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func writeArMember(t *testing.T, out *bytes.Buffer, name string, data []byte) {
	t.Helper()
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name+"/", 0, 0, 0, 0o644, len(data))
	if len(header) != 60 {
		t.Fatalf("bad ar header length %d", len(header))
	}
	out.WriteString(header)
	out.Write(data)
	if len(data)%2 != 0 {
		out.WriteByte('\n')
	}
}

type rpmFixture struct {
	Name, Version, Release, Arch, Payload string
	Epoch                                 uint32
}

type rpmTag struct {
	id, typ uint32
	count   uint32
	data    []byte
}

func rpmStringTag(id uint32, values ...string) rpmTag {
	var data []byte
	for _, value := range values {
		data = append(data, value...)
		data = append(data, 0)
	}
	typ := uint32(8)
	if len(values) == 1 {
		typ = 6
	}
	return rpmTag{id: id, typ: typ, count: uint32(len(values)), data: data}
}

func rpmIntTag(id uint32, values ...uint32) rpmTag {
	data := make([]byte, 4*len(values))
	for i, value := range values {
		binary.BigEndian.PutUint32(data[i*4:], value)
	}
	return rpmTag{id: id, typ: 4, count: uint32(len(values)), data: data}
}

func writeRPMFixture(t *testing.T, filename string, fixture rpmFixture) {
	t.Helper()
	tags := []rpmTag{
		rpmStringTag(1000, fixture.Name), rpmStringTag(1001, fixture.Version), rpmStringTag(1002, fixture.Release), rpmIntTag(1003, fixture.Epoch),
		rpmStringTag(1004, "fixture summary"), rpmStringTag(1005, "fixture description"), rpmIntTag(1006, 1_600_000_000),
		rpmIntTag(1009, 1234), rpmStringTag(1014, "MIT"), rpmStringTag(1022, fixture.Arch),
		rpmIntTag(1030, 0100644), rpmIntTag(1037, 1), rpmStringTag(1044, fixture.Name+"-"+fixture.Version+"-"+fixture.Release+".src.rpm"),
		rpmStringTag(1047, fixture.Name), rpmIntTag(1112, 1<<3), rpmStringTag(1113, fmt.Sprintf("%d:%s-%s", fixture.Epoch, fixture.Version, fixture.Release)),
		rpmIntTag(1116, 0), rpmStringTag(1117, "fixture.conf"), rpmStringTag(1118, "/etc/"),
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i].id < tags[j].id })
	var store bytes.Buffer
	indexes := make([]byte, 16*len(tags))
	for i, tag := range tags {
		offset := uint32(store.Len())
		binary.BigEndian.PutUint32(indexes[i*16:], tag.id)
		binary.BigEndian.PutUint32(indexes[i*16+4:], tag.typ)
		binary.BigEndian.PutUint32(indexes[i*16+8:], offset)
		binary.BigEndian.PutUint32(indexes[i*16+12:], tag.count)
		store.Write(tag.data)
	}
	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	copy(lead[10:76], fixture.Name+"-"+fixture.Version+"-"+fixture.Release)
	binary.BigEndian.PutUint16(lead[78:80], 5)
	signatureHeader := make([]byte, 16)
	copy(signatureHeader, []byte{0x8e, 0xad, 0xe8, 1})
	header := make([]byte, 16)
	copy(header, []byte{0x8e, 0xad, 0xe8, 1})
	binary.BigEndian.PutUint32(header[8:12], uint32(len(tags)))
	binary.BigEndian.PutUint32(header[12:16], uint32(store.Len()))
	data := bytes.Join([][]byte{lead, signatureHeader, header, indexes, store.Bytes(), []byte(fixture.Payload)}, nil)
	if err := os.WriteFile(filename, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func replaceTestRPMSignature(filename, key string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	if len(data) < 112 || !bytes.Equal(data[96:100], []byte{0x8e, 0xad, 0xe8, 1}) {
		return errors.New("test RPM has no bounded signature header")
	}
	count := int(binary.BigEndian.Uint32(data[104:108]))
	storeSize := int(binary.BigEndian.Uint32(data[108:112]))
	oldSize := 16 + count*16 + storeSize
	oldSize += (8 - oldSize%8) % 8
	mainStart := 96 + oldSize
	if count < 0 || storeSize < 0 || mainStart > len(data) {
		return errors.New("test RPM signature header is truncated")
	}
	key = strings.TrimPrefix(strings.TrimPrefix(key, "0x"), "0X")
	if len(key) < 16 {
		return errors.New("test signing key is too short")
	}
	keyID, err := hex.DecodeString(key[len(key)-16:])
	if err != nil {
		return err
	}
	hashed := []byte{5, 2, 0, 0, 0, 1}
	unhashed := append([]byte{9, 16}, keyID...)
	body := []byte{4, 0, 1, 8, 0, byte(len(hashed))}
	body = append(body, hashed...)
	body = append(body, 0, byte(len(unhashed)))
	body = append(body, unhashed...)
	body = append(body, 0, 0, 0, 1, 1)
	if len(body) >= 192 {
		return errors.New("test signature packet is unexpectedly large")
	}
	packet := append([]byte{0xc2, byte(len(body))}, body...)
	descriptor := make([]byte, 16)
	copy(descriptor, []byte{0x8e, 0xad, 0xe8, 1})
	binary.BigEndian.PutUint32(descriptor[8:12], 1)
	binary.BigEndian.PutUint32(descriptor[12:16], uint32(len(packet)))
	index := make([]byte, 16)
	binary.BigEndian.PutUint32(index[0:4], 268)
	binary.BigEndian.PutUint32(index[4:8], 7)
	binary.BigEndian.PutUint32(index[12:16], uint32(len(packet)))
	padding := make([]byte, (8-len(packet)%8)%8)
	updated := bytes.Join([][]byte{data[:96], descriptor, index, packet, padding, data[mainStart:]}, nil)
	return os.WriteFile(filename, updated, 0o644)
}

func inspectTestRPMSignatures(path string) ([]yumrepo.EmbeddedRPMSignature, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	signatures, inspectErr := yumrepo.InspectEmbeddedRPMSignatures(context.Background(), file)
	return signatures, errors.Join(inspectErr, file.Close())
}

func readPrimaryXML(t *testing.T, repodata string) []byte {
	t.Helper()
	entries, err := os.ReadDir(repodata)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), "-primary.xml.gz") {
			return gunzip(t, mustRead(t, filepath.Join(repodata, entry.Name())))
		}
	}
	t.Fatal("primary metadata not found")
	return nil
}

func repodataFiles(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "repodata"))
	if err != nil {
		t.Fatal(err)
	}
	var result []string
	for _, entry := range entries {
		result = append(result, filepath.Join("repodata", entry.Name()))
	}
	sort.Strings(result)
	return result
}

func gunzip(t *testing.T, body []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	result, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if err := zr.Close(); err != nil {
		t.Fatal(err)
	}
	return result
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func mustMkdir(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func fileSHA(path string) string {
	body, _ := os.ReadFile(path)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
