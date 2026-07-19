package yumrepo

import (
	"testing"

	crpm "github.com/cavaliergopher/rpm"
)

func TestValidatePackageSizeTagsRejectsSignedWraparound(t *testing.T) {
	negative := &crpm.Tag{Type: crpm.TagTypeInt64, Value: []int64{-1}}
	pkg := &crpm.Package{
		Header: crpm.Header{Tags: map[int]*crpm.Tag{5009: negative}},
	}
	if err := validatePackageSizeTags(pkg); err == nil {
		t.Fatal("negative RPM size tag was accepted")
	}
	if err := validatePackageSizeTags(&crpm.Package{}); err != nil {
		t.Fatalf("missing optional size tags were rejected: %v", err)
	}
}

func TestNormalizedRPMArchitectureRecognizesSourceBasename(t *testing.T) {
	stringValue := func(value string) *crpm.Tag {
		return &crpm.Tag{Type: crpm.TagTypeString, Value: []string{value}}
	}
	header := &crpm.Header{Tags: map[int]*crpm.Tag{tagArch: stringValue("aarch64")}}
	for _, basename := range []string{"pkg-1-1.src.rpm", "pkg-1-1.nosrc.rpm"} {
		if got, err := normalizedRPMArchitecture(header, basename); err != nil || got != "src" {
			t.Fatalf("basename=%s arch=%q err=%v", basename, got, err)
		}
	}
	if got, err := normalizedRPMArchitecture(header, "pkg-1-1.aarch64.rpm"); err != nil || got != "aarch64" {
		t.Fatalf("binary arch=%q err=%v", got, err)
	}
	header.Tags[tagSourceRPM] = stringValue("pkg-1-1.src.rpm")
	if _, err := normalizedRPMArchitecture(header, "renamed.src.rpm"); err == nil {
		t.Fatal("binary RPM renamed to a source basename was accepted")
	}
}
