package aptrepo

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"pault.ag/go/debian/control"
)

func TestWritePackagesDeterministicAndParseable(t *testing.T) {
	dir := t.TempDir()
	alphaControl := strings.ReplaceAll(fixtureControl, "libfoo-bin", "alpha")
	alphaControl = strings.Replace(alphaControl, "Source: libfoo (1.2.3-1)", "Source: alpha", 1)
	zetaControl := strings.ReplaceAll(fixtureControl, "libfoo-bin", "zeta")
	zetaControl = strings.Replace(zetaControl, "Source: libfoo (1.2.3-1)", "Source: zeta", 1)

	alpha, err := InspectPackage(context.Background(), writeMinimalDeb(t, dir, "alpha_1.2.3-1_amd64.deb", alphaControl), "main")
	if err != nil {
		t.Fatalf("inspect alpha: %v", err)
	}
	zeta, err := InspectPackage(context.Background(), writeMinimalDeb(t, dir, "zeta_1.2.3-1_amd64.deb", zetaControl), "main")
	if err != nil {
		t.Fatalf("inspect zeta: %v", err)
	}

	var first, second bytes.Buffer
	if err := WritePackages(&first, []Package{zeta, alpha}); err != nil {
		t.Fatalf("WritePackages first: %v", err)
	}
	if err := WritePackages(&second, []Package{alpha, zeta}); err != nil {
		t.Fatalf("WritePackages second: %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("Packages output depends on input ordering")
	}

	entries, err := control.ParseBinaryIndex(bufio.NewReader(bytes.NewReader(first.Bytes())))
	if err != nil {
		t.Fatalf("parse generated Packages: %v", err)
	}
	if len(entries) != 2 || entries[0].Package != "alpha" || entries[1].Package != "zeta" {
		t.Fatalf("unexpected Packages ordering: %+v", entries)
	}
	if entries[0].Filename != alpha.PoolPath || int64(entries[0].Size) != alpha.Size || entries[0].SHA256 != alpha.SHA256 {
		t.Fatalf("generated index metadata mismatch: %+v", entries[0])
	}
	if got := entries[0].Paragraph.Values["X-Sow-Test"]; got != "preserved" {
		t.Fatalf("unknown field = %q, want preserved", got)
	}
	if _, ok := entries[0].Paragraph.Values["MD5sum"]; ok {
		t.Fatal("Packages unexpectedly contains MD5sum")
	}
}

func TestPackagesWriterRejectsOutOfOrderStream(t *testing.T) {
	dir := t.TempDir()
	alphaControl := strings.ReplaceAll(fixtureControl, "libfoo-bin", "alpha")
	alphaControl = strings.Replace(alphaControl, "Source: libfoo (1.2.3-1)", "Source: alpha", 1)
	zetaControl := strings.ReplaceAll(fixtureControl, "libfoo-bin", "zeta")
	zetaControl = strings.Replace(zetaControl, "Source: libfoo (1.2.3-1)", "Source: zeta", 1)
	alpha, err := InspectPackage(context.Background(), writeMinimalDeb(t, dir, "alpha_1.2.3-1_amd64.deb", alphaControl), "main")
	if err != nil {
		t.Fatal(err)
	}
	zeta, err := InspectPackage(context.Background(), writeMinimalDeb(t, dir, "zeta_1.2.3-1_amd64.deb", zetaControl), "main")
	if err != nil {
		t.Fatal(err)
	}

	writer, err := NewPackagesWriter(&bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(zeta); err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(alpha); !errors.Is(err, ErrPackagesOutOfOrder) {
		t.Fatalf("out-of-order error = %v, want %v", err, ErrPackagesOutOfOrder)
	}
}

func TestPackagesWriterRejectsDuplicateIdentity(t *testing.T) {
	pkg, err := InspectPackage(context.Background(), writeMinimalDeb(t, t.TempDir(), "libfoo-bin_1.2.3-1_amd64.deb", fixtureControl), "main")
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewPackagesWriter(&bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(pkg); err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(pkg); !errors.Is(err, ErrDuplicatePackageIdentity) {
		t.Fatalf("duplicate identity error = %v, want %v", err, ErrDuplicatePackageIdentity)
	}
}

func TestWritePackagesCaseFoldsDerivedControlFields(t *testing.T) {
	debPath := writeMinimalDeb(t, t.TempDir(), "libfoo-bin_1.2.3-1_amd64.deb", fixtureControl)
	pkg, err := InspectPackage(context.Background(), debPath, "main")
	if err != nil {
		t.Fatal(err)
	}
	pkg.paragraph.Values["filename"] = "pool/main/evil.deb"
	pkg.paragraph.Values["sha256"] = strings.Repeat("0", 64)
	pkg.paragraph.Order = append(pkg.paragraph.Order, "filename", "sha256")
	var output bytes.Buffer
	if err := WritePackages(&output, []Package{pkg}); err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(output.String())
	if strings.Count(lower, "filename:") != 1 || strings.Count(lower, "sha256:") != 1 || strings.Contains(lower, "pool/main/evil.deb") {
		t.Fatalf("derived field collision survived case folding:\n%s", output.String())
	}
}

func TestWritePackagesRejectsCaseInsensitiveControlDuplicates(t *testing.T) {
	pkg, err := InspectPackage(context.Background(), writeMinimalDeb(t, t.TempDir(), "libfoo-bin_1.2.3-1_amd64.deb", fixtureControl), "main")
	if err != nil {
		t.Fatal(err)
	}
	pkg.paragraph.Values["package"] = pkg.Name
	if err := WritePackages(&bytes.Buffer{}, []Package{pkg}); err == nil || !strings.Contains(err.Error(), "case-insensitive") {
		t.Fatalf("case-insensitive duplicate error = %v", err)
	}
}
