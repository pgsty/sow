package aptrepo

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func FuzzCompareVersionsAntisymmetric(f *testing.F) {
	for _, seed := range [][2]string{{"1.0~rc1", "1.0"}, {"1:0.1-1", "9.9-9"}, {"0:1.0+really0.9", "1.0"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, left, right string) {
		if len(left) > 1024 || len(right) > 1024 {
			t.Skip()
		}
		forward, forwardErr := CompareVersions(left, right)
		reverse, reverseErr := CompareVersions(right, left)
		if (forwardErr == nil) != (reverseErr == nil) {
			t.Fatalf("reversing operands changed parse validity: forward=%v reverse=%v", forwardErr, reverseErr)
		}
		if forwardErr != nil {
			return
		}
		if comparisonSign(forward) != -comparisonSign(reverse) {
			t.Fatalf("Debian comparison is not antisymmetric: %q ? %q = %d, reverse=%d", left, right, forward, reverse)
		}
		self, err := CompareVersions(left, left)
		if err != nil || self != 0 {
			t.Fatalf("valid Debian version is not reflexive: %q => %d, %v", left, self, err)
		}
	})
}

func comparisonSign(value int) int {
	switch {
	case value < 0:
		return -1
	case value > 0:
		return 1
	default:
		return 0
	}
}

const fixtureControl = `Package: libfoo-bin
Source: libfoo (1.2.3-1)
Version: 1:1.2.3-1
Architecture: amd64
Maintainer: SOW Test <sow@example.invalid>
Installed-Size: 1
Depends: libc6 (>= 2.36)
Section: utils
Priority: optional
Description: minimal real deb fixture
 second description line
X-Sow-Test: preserved
`

func TestInspectPackageAndReadablePoolPath(t *testing.T) {
	debPath := writeMinimalDeb(t, t.TempDir(), "libfoo-bin_1.2.3-1_amd64.deb", fixtureControl)
	pkg, err := InspectPackage(context.Background(), debPath, "main")
	if err != nil {
		t.Fatalf("InspectPackage: %v", err)
	}
	if pkg.Name != "libfoo-bin" || pkg.Source != "libfoo" || pkg.Version != "1:1.2.3-1" || pkg.Architecture != "amd64" {
		t.Fatalf("unexpected package identity: %+v", pkg)
	}
	wantPool := "pool/main/libf/libfoo/libfoo-bin_1.2.3-1_amd64.deb"
	if pkg.PoolPath != wantPool {
		t.Fatalf("PoolPath = %q, want %q", pkg.PoolPath, wantPool)
	}
	if pkg.Size <= 0 || len(pkg.SHA256) != 64 {
		t.Fatalf("invalid payload metadata: size=%d sha256=%q", pkg.Size, pkg.SHA256)
	}
	if got, ok := pkg.ControlValue("X-Sow-Test"); !ok || got != "preserved" {
		t.Fatalf("unknown control field was not preserved: %q, %v", got, ok)
	}
}

func TestInspectPackageDoesNotOpenDataArchive(t *testing.T) {
	debPath := writeDebWithDataMember(
		t,
		t.TempDir(),
		"libfoo-bin_1.2.3-1_amd64.deb",
		fixtureControl,
		"data.tar.zst",
		[]byte("intentionally not a zstd stream"),
	)
	pkg, err := InspectPackage(context.Background(), debPath, "main")
	if err != nil {
		t.Fatalf("control-only package inspection opened the irrelevant data archive: %v", err)
	}
	if pkg.Name != "libfoo-bin" || pkg.Architecture != "amd64" {
		t.Fatalf("unexpected package identity: %+v", pkg)
	}
}

func TestLoadDebControlRequiresUniqueStructuralMembers(t *testing.T) {
	controlTar := tarGzip(t, map[string][]byte{"control": []byte(fixtureControl)})
	type arMember struct {
		name string
		data []byte
	}
	tests := []struct {
		name    string
		members []arMember
		want    string
	}{
		{
			name:    "missing data",
			members: []arMember{{"debian-binary", []byte("2.0\n")}, {"control.tar.gz", controlTar}},
			want:    "missing data archive member",
		},
		{
			name:    "duplicate data",
			members: []arMember{{"debian-binary", []byte("2.0\n")}, {"control.tar.gz", controlTar}, {"data.tar.xz", []byte("one")}, {"data.tar.zst", []byte("two")}},
			want:    "duplicate data archive member",
		},
		{
			name:    "duplicate control",
			members: []arMember{{"debian-binary", []byte("2.0\n")}, {"control.tar.gz", controlTar}, {"control.tar.xz", []byte("duplicate")}, {"data.tar.gz", []byte("data")}},
			want:    "duplicate control archive member",
		},
		{
			name:    "duplicate version",
			members: []arMember{{"debian-binary", []byte("2.0\n")}, {"debian-binary", []byte("2.0\n")}, {"control.tar.gz", controlTar}, {"data.tar.gz", []byte("data")}},
			want:    "duplicate debian-binary member",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var archive bytes.Buffer
			archive.WriteString("!<arch>\n")
			for _, member := range tt.members {
				writeArMember(t, &archive, member.name, member.data)
			}
			if _, err := loadDebControl(context.Background(), bytes.NewReader(archive.Bytes()), int64(archive.Len())); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadDebControl error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestBinaryControlRequiresOneStrictParagraph(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"duplicate", fixtureControl + "Package: duplicate\n", "repeats field"},
		{"case-insensitive duplicate", fixtureControl + "package: duplicate\n", "repeats field"},
		{"second paragraph", fixtureControl + "\nPackage: second\n", "more than one paragraph"},
		{"invalid field", "Bad Field: value\n", "invalid field name"},
		{"comment", "# comment\n", "invalid field name"},
		{"orphan continuation", " continuation\n", "orphan continuation"},
		{"nul", "Package: good\x00bad\n", "forbidden control byte"},
		{"control", "Package: good\x1bbad\n", "forbidden control byte"},
		{"leading empty paragraph", "\nPackage: good\n", "empty paragraph"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateBinaryControlDocument([]byte(tt.body)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateBinaryControlDocument error = %v, want %q", err, tt.want)
			}
		})
	}
	valid := strings.ReplaceAll(fixtureControl+"X_Custom: accepted\n", "\n", "\r\n")
	if err := validateBinaryControlDocument([]byte(valid)); err != nil {
		t.Fatalf("strict validator rejected a valid custom-field CRLF paragraph: %v", err)
	}

	duplicateDeb := writeMinimalDeb(t, t.TempDir(), "libfoo-bin_1.2.3-1_amd64.deb", fixtureControl+"Package: duplicate\n")
	if _, err := InspectPackage(context.Background(), duplicateDeb, "main"); err == nil || !strings.Contains(err.Error(), "repeats field") {
		t.Fatalf("InspectPackage duplicate-field error = %v", err)
	}
}

func TestLoadDebControlRejectsNonAdvancingNegativeArMember(t *testing.T) {
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	header := []byte(fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", "loop/", 0, 0, 0, 0o644, -60))
	if len(header) != 60 {
		t.Fatalf("malformed test header length = %d", len(header))
	}
	archive.Write(header)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := loadDebControl(ctx, bytes.NewReader(archive.Bytes()), int64(archive.Len())); err == nil || !strings.Contains(err.Error(), "invalid ar member size") {
		t.Fatalf("negative ar member size error = %v", err)
	}
}

func TestPoolPathRejectsUnsafeMetadata(t *testing.T) {
	tests := []struct {
		component string
		source    string
		filename  string
	}{
		{"../main", "foo", "foo_1_amd64.deb"},
		{"main", "../foo", "foo_1_amd64.deb"},
		{"main", "foo", "../foo_1_amd64.deb"},
		{"main", "foo", "foo_1_amd64.rpm"},
		{"main", "foo", "foo_1%2fescape_amd64.deb"},
	}
	for _, tt := range tests {
		if _, err := PoolPath(tt.component, tt.source, tt.filename); err == nil {
			t.Errorf("PoolPath(%q, %q, %q) unexpectedly succeeded", tt.component, tt.source, tt.filename)
		}
	}
}

func TestDebFilenamePercentEncodingPolicy(t *testing.T) {
	allowed := []string{
		"foo_1%3a2_amd64.deb",
		"foo_1%3A2_amd64.deb",
		"foo_1:2+build~1_amd64.deb",
	}
	for _, filename := range allowed {
		if _, err := PoolPath("main", "foo", filename); err != nil {
			t.Errorf("PoolPath rejected safe filename %q: %v", filename, err)
		}
	}

	rejected := []string{
		"foo_1%2fescape_amd64.deb",
		"foo_1%2Fescape_amd64.deb",
		"foo_1%5cescape_amd64.deb",
		"foo_1%5Cescape_amd64.deb",
		"foo_1%2e%2e_amd64.deb",
		"foo_1%2E%2E_amd64.deb",
		"foo_1%252fescape_amd64.deb",
		"foo_1%00_amd64.deb",
		"foo_1%_amd64.deb",
		"foo_1%3_amd64.deb",
		"foo_1%zz_amd64.deb",
	}
	for _, filename := range rejected {
		if _, err := PoolPath("main", "foo", filename); err == nil {
			t.Errorf("PoolPath accepted ambiguous filename %q", filename)
		}
	}
}

func TestInspectPackageRejectsUnsafeSource(t *testing.T) {
	control := strings.Replace(fixtureControl, "Source: libfoo (1.2.3-1)", "Source: ../libfoo", 1)
	debPath := writeMinimalDeb(t, t.TempDir(), "libfoo-bin_1.2.3-1_amd64.deb", control)
	if _, err := InspectPackage(context.Background(), debPath, "main"); err == nil {
		t.Fatal("InspectPackage accepted an unsafe source package name")
	}
}

func TestInspectPackageRejectsSymlinkInput(t *testing.T) {
	dir := t.TempDir()
	target := writeMinimalDeb(t, dir, "alpha_1.0-1_amd64.deb", fixtureControl)
	link := filepath.Join(t.TempDir(), "alpha_1.0-1_amd64.deb")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectPackage(context.Background(), link, "main"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("InspectPackage symlink error = %v", err)
	}
}

func TestInspectCheckedInExternallyBuiltDeb(t *testing.T) {
	encoded, err := os.ReadFile("testdata/libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64")
	if err != nil {
		t.Fatalf("read checked-in deb fixture: %v", err)
	}
	payload := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(payload, encoded)
	if err != nil {
		t.Fatalf("decode checked-in deb fixture: %v", err)
	}
	filePath := filepath.Join(t.TempDir(), "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb")
	if err := os.WriteFile(filePath, payload[:n], 0o444); err != nil {
		t.Fatalf("materialize checked-in deb fixture: %v", err)
	}
	pkg, err := InspectPackage(context.Background(), filePath, "main")
	if err != nil {
		t.Fatalf("inspect checked-in externally built deb: %v", err)
	}
	if pkg.Name != "libpqtypes0" || pkg.Architecture != "arm64" || pkg.Version != "1.5.1-9.pgdg22.04+1" {
		t.Fatalf("unexpected checked-in package identity: %+v", pkg)
	}
	if pkg.SHA256 != "61f344ab5a23007088706fab7264aea3eb0ce9650ffbbc5e6f1f76684af7373a" {
		t.Fatalf("checked-in external fixture digest = %s", pkg.SHA256)
	}
}
