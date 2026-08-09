package state

import (
	"strings"
	"testing"
)

func localGCCaseObject() PackageObject {
	return PackageObject{
		SHA256: strings.Repeat("a", 64), Format: "deb", Coordinate: "deb:pgformatter=1:all",
		Architecture: "all", CanonicalArch: "neutral", PoolPath: "pool/p/pgformatter/package.deb",
		Filename: "package.deb", Size: 7, Name: "pgformatter", Source: "pgformatter", Version: "1",
		Kind: "main", Storage: "pool",
	}
}

func TestSubtractLocalGCObjectsMatchesUniqueCaseFoldedGenerationPath(t *testing.T) {
	object := localGCCaseObject()
	alias := GenerationFile{Path: "pool/p/pgFormatter/package.deb", Phase: "payload", Size: object.Size, SHA256: object.SHA256}
	metadata := GenerationFile{Path: "dists/jammy/Release", Phase: "pointer", Size: 1, SHA256: strings.Repeat("b", 64)}
	target, removals, err := SubtractLocalGCObjects([]GenerationFile{metadata, alias}, []PackageObject{object})
	if err != nil || len(target) != 1 || target[0] != metadata || len(removals) != 1 || removals[0].Object.PoolPath != object.PoolPath || removals[0].File != alias {
		t.Fatalf("target=%#v removals=%#v err=%v", target, removals, err)
	}
}

func TestSubtractLocalGCObjectsRejectsCaseFoldAmbiguityAndDrift(t *testing.T) {
	object := localGCCaseObject()
	exact := GenerationFile{Path: object.PoolPath, Phase: "payload", Size: object.Size, SHA256: object.SHA256}
	alias := exact
	alias.Path = "pool/p/pgFormatter/package.deb"
	if _, _, err := SubtractLocalGCObjects([]GenerationFile{exact, alias}, []PackageObject{object}); err == nil {
		t.Fatal("case-folded duplicate Generation paths were accepted")
	}
	drift := alias
	drift.SHA256 = strings.Repeat("c", 64)
	if _, _, err := SubtractLocalGCObjects([]GenerationFile{drift}, []PackageObject{object}); err == nil {
		t.Fatal("case-folded payload identity drift was accepted")
	}
}
