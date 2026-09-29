package v2cli

import "testing"

func TestParseCreateMetadataTimestamp(t *testing.T) {
	for _, value := range []string{"0", "1790049000", "253402300799"} {
		inv, err := Parse([]string{"create", "--metadata-timestamp=" + value})
		if err != nil || inv.MetadataTimestamp < 0 {
			t.Fatalf("%s: %+v %v", value, inv, err)
		}
	}
	for _, args := range [][]string{
		{"create", "--metadata-timestamp"},
		{"create", "--metadata-timestamp=-1"},
		{"create", "--metadata-timestamp=253402300800"},
		{"create", "--metadata-timestamp=1790049000000"},
		{"create", "--metadata-timestamp=9223372036854775807"},
		{"create", "--metadata-timestamp=1.5"},
		{"create", "--metadata-timestamp=tomorrow"},
		{"create", "--metadata-timestamp=9223372036854775808"},
		{"create", "--metadata-timestamp=1", "--metadata-timestamp=2"},
		{"build", "--metadata-timestamp=1"},
	} {
		if _, err := Parse(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
