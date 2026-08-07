package yumrepo

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestManagedPoolPathV1(t *testing.T) {
	tests := []struct {
		source   string
		filename string
		want     string
	}{
		{"PolarDB", "PolarDB-17.9.1.0-1.el10.aarch64.rpm", "pool/p/PolarDB/PolarDB-17.9.1.0-1.el10.aarch64.rpm"},
		{"libFoo", "libFoo-1.0-1.x86_64.rpm", "pool/libf/libFoo/libFoo-1.0-1.x86_64.rpm"},
		{"pkg%2Fdebug+1", "pkg%2Fdebug+1:2^3.rpm", "pool/p/pkg%2Fdebug+1/pkg%2Fdebug+1:2^3.rpm"},
	}
	for _, test := range tests {
		pool, err := NewManagedPoolPath(test.source, test.filename)
		if err != nil || pool.String() != test.want || pool.Source() != test.source || pool.Filename() != test.filename {
			t.Fatalf("NewManagedPoolPath(%q, %q) = %#v, %v; want %q", test.source, test.filename, pool, err, test.want)
		}
		parsed, err := ParseManagedPoolPath(test.want)
		if err != nil || parsed != pool {
			t.Fatalf("ParseManagedPoolPath(%q) = %#v, %v; want %#v", test.want, parsed, err, pool)
		}
	}
	for _, invalid := range []string{
		"pool/P/PolarDB/PolarDB.rpm", "pool/p/../pkg.rpm", "pool/p/pkg", "pool/p/pkg/pkg/name.rpm", "pool/p/pkg/pkg name.rpm",
	} {
		if _, err := ParseManagedPoolPath(invalid); err == nil {
			t.Errorf("ParseManagedPoolPath accepted %q", invalid)
		}
	}
}

func TestRPMParentRelativeHrefEncodeOnceAndRoundTrip(t *testing.T) {
	view, err := ParseManagedRPMViewPath("dists/el9/x86_64")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewManagedPoolPath("pkg%2Fdebug+1", "pkg%2Fdebug+1:2^3.rpm")
	if err != nil {
		t.Fatal(err)
	}
	href, err := RPMParentRelativeHref(view, pool)
	if err != nil {
		t.Fatal(err)
	}
	const want = "../../../pool/p/pkg%252Fdebug%2B1/pkg%252Fdebug%2B1%3A2%5E3.rpm"
	if href.String() != want {
		t.Fatalf("RPMParentRelativeHref = %q, want %q", href.String(), want)
	}
	parsedHref, parsedPool, err := ParseManagedRPMHref(want)
	if err != nil || parsedHref != href || parsedPool != pool {
		t.Fatalf("ParseManagedRPMHref = %#v %#v, %v", parsedHref, parsedPool, err)
	}
	for _, rawBase := range []string{
		"https://repo.example/publish/team/repo/",
		"file:///srv/mirror/non-root/repo/",
	} {
		base, err := url.Parse(rawBase)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateRPMHrefRoundTrip(base, view, pool, href.String()); err != nil {
			t.Fatalf("ValidateRPMHrefRoundTrip(%q): %v", rawBase, err)
		}
	}
	dotPool, err := NewManagedPoolPath("pkg", "%2E%2E%2F.rpm")
	if err != nil {
		t.Fatal(err)
	}
	dotHref, err := RPMParentRelativeHref(view, dotPool)
	if err != nil {
		t.Fatal(err)
	}
	if want := "../../../pool/p/pkg/%252E%252E%252F.rpm"; dotHref.String() != want {
		t.Fatalf("encoded dot/separator href = %q, want %q", dotHref.String(), want)
	}
	base, err := url.Parse("https://repo.example/non-root/repo/")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRPMHrefRoundTrip(base, view, dotPool, dotHref.String()); err != nil {
		t.Fatalf("encoded dot/separator round-trip: %v", err)
	}
}

func TestRPMLeafValidationRequiresEncodedLeafLocalHref(t *testing.T) {
	pool, err := NewManagedPoolPath("pkg%2Fdebug+1", "pkg%2Fdebug+1:2^3.rpm")
	if err != nil {
		t.Fatal(err)
	}
	const identity = "0000000000000000000000000000000000000000000000000000000000000000"
	validation, err := newRPMLeafValidation([]ManagedRPMPackageExpectation{{SHA256: identity, Size: 1, PoolPath: pool}})
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.check(identity, "pool/p/pkg%252Fdebug%2B1/pkg%252Fdebug%2B1%3A2%5E3.rpm", 1); err != nil {
		t.Fatal(err)
	}
	validation, err = newRPMLeafValidation([]ManagedRPMPackageExpectation{{SHA256: identity, Size: 1, PoolPath: pool}})
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.check(identity, pool.String(), 1); err == nil {
		t.Fatal("RPM leaf validator accepted an unescaped literal percent href")
	}
}

func TestGenerateRPMLeafAcceptsManagedPercentAndColonBasename(t *testing.T) {
	root := t.TempDir()
	const basename = "fixture%2Fdebug+1:2^3.x86_64.rpm"
	rpmPath := filepath.Join(root, basename)
	writeRPMFixture(t, rpmPath, "fixture")
	pool, err := NewManagedPoolPath("fixture", basename)
	if err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(root, "leaf")
	if err := os.Mkdir(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	generation, err := GenerateRPMLeaf(context.Background(), filepath.Join(leaf, "repodata"), 1, &SliceIterator{Inputs: []PackageInput{{Path: rpmPath, Basename: basename, PoolPath: pool.String()}}}, nil)
	if err != nil || generation.Packages != 1 {
		t.Fatalf("leaf generation=%#v err=%v", generation, err)
	}
}

func TestManagedRPMHrefRejectsAmbiguousOrNonCanonicalSpelling(t *testing.T) {
	view, err := ParseManagedRPMViewPath("dists/el9/x86_64")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewManagedPoolPath("pkg", "pkg+1.rpm")
	if err != nil {
		t.Fatal(err)
	}
	base, err := url.Parse("https://repo.example/prefix/repo/")
	if err != nil {
		t.Fatal(err)
	}
	for _, href := range []string{
		"/pool/p/pkg/pkg%2B1.rpm",
		"../../../pool/p/pkg/pkg+1.rpm",
		"../../../pool/p/pkg/pkg%2b1.rpm",
		"../../../pool/p/pkg/pkg%2F1.rpm",
		"../../../pool/p/pkg/%2E%2E",
		"../../pool/p/pkg/pkg%2B1.rpm",
		"../../../../pool/p/pkg/pkg%2B1.rpm",
	} {
		if err := ValidateRPMHrefRoundTrip(base, view, pool, href); err == nil {
			t.Errorf("ValidateRPMHrefRoundTrip accepted %q", href)
		}
	}
	withoutSlash, err := url.Parse("https://repo.example/prefix/repo")
	if err != nil {
		t.Fatal(err)
	}
	href, err := RPMParentRelativeHref(view, pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRPMHrefRoundTrip(withoutSlash, view, pool, href.String()); err == nil {
		t.Fatal("ValidateRPMHrefRoundTrip accepted a non-directory Repository base URI")
	}
}
