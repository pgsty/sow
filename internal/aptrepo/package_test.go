package aptrepo

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
			if _, err := loadDebControl(bytes.NewReader(archive.Bytes())); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadDebControl error = %v, want %q", err, tt.want)
			}
		})
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

func TestInspectPackageRejectsUnsafeSource(t *testing.T) {
	control := strings.Replace(fixtureControl, "Source: libfoo (1.2.3-1)", "Source: ../libfoo", 1)
	debPath := writeMinimalDeb(t, t.TempDir(), "libfoo-bin_1.2.3-1_amd64.deb", control)
	if _, err := InspectPackage(context.Background(), debPath, "main"); err == nil {
		t.Fatal("InspectPackage accepted an unsafe source package name")
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
