package managed

import (
	"errors"
	"testing"

	"github.com/pgsty/sow/internal/v2/state"
)

func TestMutationRecoveryArtifactMarshalBoundaries(t *testing.T) {
	manifest := mutationManifest{
		Version: mutationOperationVersion,
		Objects: []state.PackageObject{},
		Desired: map[string][]string{"dist": {}},
		Result:  map[string]int{},
	}
	wire, err := marshalMutationManifestLimit(manifest, maxMutationManifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if exact, err := marshalMutationManifestLimit(manifest, len(wire)); err != nil || len(exact) != len(wire) {
		t.Fatalf("exact manifest boundary: bytes=%d err=%v", len(exact), err)
	}
	if _, err := marshalMutationManifestLimit(manifest, len(wire)-1); !errors.Is(err, ErrRejected) || !errors.Is(err, errMutationRecoveryArtifactTooLarge) {
		t.Fatalf("manifest max+1 was not rejected with the bounded-artifact class: %v", err)
	}

	base := []state.GenerationFile{{Path: "dists/dist/repomd.xml", Size: 1, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	baseWire, err := marshalMutationBaseManifestLimit(base, maxMutationBaseManifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if exact, err := marshalMutationBaseManifestLimit(base, len(baseWire)); err != nil || len(exact) != len(baseWire) {
		t.Fatalf("exact base-manifest boundary: bytes=%d err=%v", len(exact), err)
	}
	if _, err := marshalMutationBaseManifestLimit(base, len(baseWire)-1); !errors.Is(err, ErrRejected) || !errors.Is(err, errMutationRecoveryArtifactTooLarge) {
		t.Fatalf("base manifest max+1 was not rejected with the bounded-artifact class: %v", err)
	}
}
