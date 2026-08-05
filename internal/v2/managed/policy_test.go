package managed

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func FuzzApplyPolicyInputOrderStable(f *testing.F) {
	f.Add("1.0,1.0~rc1,2:0.1,9.9", uint8(2), true)
	f.Add("1.9,1.10,2.0", uint8(1), false)
	f.Fuzz(func(t *testing.T, encoded string, rawLimit uint8, excludeDebug bool) {
		if len(encoded) > 4096 {
			t.Skip()
		}
		versions := strings.Split(encoded, ",")
		if len(versions) > 32 {
			versions = versions[:32]
		}
		objects := make([]state.PackageObject, 0, len(versions))
		for index, version := range versions {
			if version == "" {
				version = "0"
			}
			digest := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s", index, version)))
			name := "pkg"
			if excludeDebug && index%3 == 0 {
				name = "pkg-debuginfo"
			}
			objects = append(objects, state.PackageObject{
				SHA256: hex.EncodeToString(digest[:]), Format: "rpm", Name: name, Source: "pkg",
				Version: version, Release: "1", Epoch: "0", Architecture: "x86_64", CanonicalArch: "x86_64",
				Coordinate: fmt.Sprintf("%s-0:%s-1.x86_64-%d", name, version, index),
			})
		}
		dist := config.EffectiveDist{Format: "rpm", Architectures: []string{"x86_64"}, Limit: int(rawLimit % 8)}
		if excludeDebug {
			dist.Exclude = []config.ExcludeRule{{Kind: []string{"debuginfo"}}}
		}
		forward, err := ApplyPolicy(objects, dist)
		if err != nil {
			return
		}
		for left, right := 0, len(objects)-1; left < right; left, right = left+1, right-1 {
			objects[left], objects[right] = objects[right], objects[left]
		}
		reverse, err := ApplyPolicy(objects, dist)
		if err != nil || !reflect.DeepEqual(forward, reverse) {
			t.Fatalf("policy result depends on input order: forward=%#v reverse=%#v err=%v", forward, reverse, err)
		}
	})
}

func TestClassifyPackageKindUsesClosedSpecificSuffixes(t *testing.T) {
	tests := map[string]string{
		"rpm/pkg-debuginfo": "debuginfo", "rpm/pkg-debugsource": "debugsource",
		"rpm/pkg-llvmjit": "llvmjit", "rpm/pkg-dbgsym": "main",
		"deb/pkg-dbgsym": "dbgsym", "deb/pkg-dbg": "dbg", "deb/pkg-debuginfo": "main",
	}
	for input, want := range tests {
		parts := []byte(input)
		separator := 0
		for parts[separator] != '/' {
			separator++
		}
		if got := ClassifyPackageKind(string(parts[:separator]), string(parts[separator+1:])); got != want {
			t.Fatalf("ClassifyPackageKind(%q)=%q want=%q", input, got, want)
		}
	}
}

func TestApplyPolicyExcludeTruthTableBeforeNativeVersionLimit(t *testing.T) {
	objects := []state.PackageObject{
		policyRPM("1", "test-tool", "1.0", "1", "aarch64"),
		policyRPM("2", "test-tool", "2.0", "1", "x86_64"),
		policyRPM("3", "pkg-debuginfo", "9.0", "1", "x86_64"),
		policyRPM("4", "pkg", "1.9", "1", "x86_64"),
		policyRPM("5", "pkg", "1.10", "1", "x86_64"),
		policyRPM("6", "pkg", "2.0", "1", "aarch64"),
	}
	dist := config.EffectiveDist{Format: "rpm", Architectures: []string{"x86_64", "aarch64"}, Limit: 1, Exclude: []config.ExcludeRule{
		{Name: []string{"test-*", "other"}, Arch: []string{"aarch64"}},
		{Kind: []string{"debuginfo", "debugsource"}},
	}}
	result, err := ApplyPolicy(objects, dist)
	if err != nil {
		t.Fatal(err)
	}
	if got := objectCoordinates(result.Excluded); !reflect.DeepEqual(got, []string{"pkg-debuginfo-0:9.0-1.x86_64", "test-tool-0:1.0-1.aarch64"}) {
		t.Fatalf("excluded=%v", got)
	}
	if got := objectCoordinates(result.Kept); !reflect.DeepEqual(got, []string{"pkg-0:2.0-1.aarch64", "pkg-0:1.10-1.x86_64", "test-tool-0:2.0-1.x86_64"}) {
		t.Fatalf("kept=%v", got)
	}
	if got := objectCoordinates(result.Limited); !reflect.DeepEqual(got, []string{"pkg-0:1.9-1.x86_64"}) {
		t.Fatalf("limited=%v", got)
	}

	for left, right := 0, len(objects)-1; left < right; left, right = left+1, right-1 {
		objects[left], objects[right] = objects[right], objects[left]
	}
	reversed, err := ApplyPolicy(objects, dist)
	if err != nil || !reflect.DeepEqual(result, reversed) {
		t.Fatalf("input order changed policy result: result=%#v reversed=%#v err=%v", result, reversed, err)
	}
}

func TestApplyPolicyUsesDebianVersionOrderingAndNeutralCountsOnce(t *testing.T) {
	objects := []state.PackageObject{
		policyDEB("a", "pkg", "1.0~rc1", "all"),
		policyDEB("b", "pkg", "1.0", "all"),
		policyDEB("c", "pkg", "1:0.1", "amd64"),
		policyDEB("d", "pkg", "9.0", "amd64"),
	}
	result, err := ApplyPolicy(objects, config.EffectiveDist{Format: "deb", Architectures: []string{"x86_64", "aarch64"}, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := objectCoordinates(result.Kept); !reflect.DeepEqual(got, []string{"pkg=1.0:all", "pkg=1:0.1:amd64"}) {
		t.Fatalf("kept=%v", got)
	}
	if len(result.Limited) != 2 {
		t.Fatalf("limited=%#v", result.Limited)
	}
}

func policyRPM(digit, name, version, release, architecture string) state.PackageObject {
	canonical := architecture
	if architecture == "noarch" {
		canonical = "neutral"
	}
	return state.PackageObject{SHA256: repeatedHex(digit), Format: "rpm", Name: name, Source: name, Version: version, Release: release, Epoch: "0", Architecture: architecture, CanonicalArch: canonical, Coordinate: name + "-0:" + version + "-" + release + "." + architecture}
}

func policyDEB(digit, name, version, architecture string) state.PackageObject {
	canonical := map[string]string{"all": "neutral", "amd64": "x86_64", "arm64": "aarch64"}[architecture]
	return state.PackageObject{SHA256: repeatedHex(digit), Format: "deb", Name: name, Source: name, Version: version, Architecture: architecture, CanonicalArch: canonical, Coordinate: name + "=" + version + ":" + architecture}
}

func repeatedHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result[:64]
}

func objectCoordinates(objects []state.PackageObject) []string {
	result := make([]string, len(objects))
	for index := range objects {
		result[index] = objects[index].Coordinate
	}
	return result
}
