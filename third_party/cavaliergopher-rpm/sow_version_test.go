package rpm

import "testing"

func TestCompareCaretSnapshots(t *testing.T) {
	// RPM's version contract places a caret snapshot after its base and before
	// the next ordinary segment: https://rpm.org/docs/6.0.x/man/rpm-version.7
	tests := []struct {
		a, b string
		want int
	}{
		{"2.0", "2.0^20250611", -1},
		{"2.0^20250611", "2.0.1", -1},
		{"2.0^20250611", "2.0.20250611", -1},
		{"2.0^git1", "2.0.1", -1},
		{"2.0^git1", "2.0git1", -1},
		{"2.0^git9", "2.0^git10", -1},
		{"2.0^git01", "2.0^git1", 0},
		{"2.0^git1", "2.0^git1", 0},
		{"2.0~rc1", "2.0^git1", -1},
		{"2.0^git1~rc1", "2.0^git1", -1},
		{"2.0^git1", "2.0^git1^git2", -1},
		{"2.0^git1^git2", "2.0^git1.1", -1},
		{"2.0^", "2.0", 1},
		{"2.0^", "2.0.1", -1},
		{"2.0^", "2.0^^", -1},
		{"2.0^", "2.0~", 1},
		{"2.0^", "2.0^~", 1},
		{"2.0^git1", "2.0+^git1", 0},
		{"^", "", 1},
	}
	for _, tt := range tests {
		t.Run(tt.a+"/"+tt.b, func(t *testing.T) {
			if got := CompareVersions(tt.a, tt.b); got != tt.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
			if got := CompareVersions(tt.b, tt.a); got != -tt.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
			}
			if got := Compare(&TestPkg{V: tt.a}, &TestPkg{V: tt.b}); got != tt.want {
				t.Errorf("Compare version = %d, want %d", got, tt.want)
			}
			if got := Compare(&TestPkg{R: tt.a}, &TestPkg{R: tt.b}); got != tt.want {
				t.Errorf("Compare release = %d, want %d", got, tt.want)
			}
		})
	}
}
