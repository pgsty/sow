package cli

import (
	"testing"

	"github.com/pgsty/sow/internal/config"
)

func TestSelectedLatestYUMCompatibilityForTargetUsesSourceOwnerAffinity(t *testing.T) {
	repos := []config.Repo{
		{ID: "infra-cf", Type: "yum", OS: config.OSConfig{Family: "el", Major: 9}, Arches: []string{"x86_64"}, PublishTargets: []string{"cf"}, YUM: &config.YUMConfig{}},
		{ID: "infra-cos", Type: "yum", OS: config.OSConfig{Family: "el", Major: 9}, Arches: []string{"x86_64"}, PublishTargets: []string{"cos"}, YUM: &config.YUMConfig{}},
	}
	cfg := &config.Config{CompatibilityProjections: []config.YUMCompatibilityProjection{
		{ID: "legacy-cf", Source: config.YUMCompatibilitySource{Repo: "infra-cf", View: "latest", OS: "el9", Arch: "x86_64"}},
		{ID: "legacy-cos", Source: config.YUMCompatibilitySource{Repo: "infra-cos", View: "latest", OS: "el9", Arch: "x86_64"}},
	}}

	for _, test := range []struct {
		target string
		want   string
	}{
		{target: "cf", want: "legacy-cf"},
		{target: "cos", want: "legacy-cos"},
	} {
		projections, err := selectedLatestYUMCompatibilityForTarget(cfg, repos, test.target, []string{"latest"}, commonFlags{})
		if err != nil {
			t.Fatal(err)
		}
		if len(projections) != 1 || projections[0].ID != test.want {
			t.Fatalf("target %s compatibility projections=%v want=%s", test.target, verificationCompatibilityIDs(projections), test.want)
		}
	}
}

func verificationCompatibilityIDs(projections []config.YUMCompatibilityProjection) []string {
	ids := make([]string, 0, len(projections))
	for _, projection := range projections {
		ids = append(ids, projection.ID)
	}
	return ids
}
