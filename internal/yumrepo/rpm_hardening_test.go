package yumrepo

import (
	"testing"

	crpm "github.com/cavaliergopher/rpm"
)

func FuzzCompareEVRAntisymmetric(f *testing.F) {
	f.Add(int64(0), "1.0~rc1", "1", int64(0), "1.0", "1")
	f.Add(int64(1), "0.1", "2.el9", int64(0), "99", "9")
	f.Fuzz(func(t *testing.T, leftEpoch int64, leftVersion, leftRelease string, rightEpoch int64, rightVersion, rightRelease string) {
		if len(leftVersion) > 1024 || len(leftRelease) > 1024 || len(rightVersion) > 1024 || len(rightRelease) > 1024 {
			t.Skip()
		}
		leftEpoch &= 0x7fffffff
		rightEpoch &= 0x7fffffff
		forward := CompareEVR(leftEpoch, leftVersion, leftRelease, rightEpoch, rightVersion, rightRelease)
		reverse := CompareEVR(rightEpoch, rightVersion, rightRelease, leftEpoch, leftVersion, leftRelease)
		if rpmComparisonSign(forward) != -rpmComparisonSign(reverse) {
			t.Fatalf("RPM EVR comparison is not antisymmetric: forward=%d reverse=%d", forward, reverse)
		}
		if self := CompareEVR(leftEpoch, leftVersion, leftRelease, leftEpoch, leftVersion, leftRelease); self != 0 {
			t.Fatalf("RPM EVR comparison is not reflexive: %d", self)
		}
	})
}

func rpmComparisonSign(value int) int {
	switch {
	case value < 0:
		return -1
	case value > 0:
		return 1
	default:
		return 0
	}
}

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

func TestNormalizedRPMArchitectureUsesHeaderNotBasename(t *testing.T) {
	stringValue := func(value string) *crpm.Tag {
		return &crpm.Tag{Type: crpm.TagTypeString, Value: []string{value}}
	}
	header := &crpm.Header{Tags: map[int]*crpm.Tag{tagArch: stringValue("aarch64")}}
	for _, basename := range []string{"pkg-1-1.src.rpm", "pkg-1-1.nosrc.rpm"} {
		if got, err := normalizedRPMArchitecture(header, basename); err != nil || got != "aarch64" {
			t.Fatalf("basename=%s arch=%q err=%v", basename, got, err)
		}
	}
	if got, err := normalizedRPMArchitecture(header, "pkg-1-1.aarch64.rpm"); err != nil || got != "aarch64" {
		t.Fatalf("binary arch=%q err=%v", got, err)
	}
	header.Tags[tagArch] = stringValue("src")
	if got, err := normalizedRPMArchitecture(header, "looks-binary.rpm"); err != nil || got != "src" {
		t.Fatalf("source header arch=%q err=%v", got, err)
	}
}
