package managed

import "testing"

func TestDecodeRetainedEffectiveSigningAcceptsLegacyUnsignedDefault(t *testing.T) {
	snapshot, err := decodeRetainedEffectiveSigning("{}")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.RPM.Packages.Mode != "never" || snapshot.RPM.Packages.Key != "" || len(snapshot.RPM.Packages.TrustedKeys) != 0 {
		t.Fatalf("legacy unsigned snapshot expanded incorrectly: %#v", snapshot)
	}
}
