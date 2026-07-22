package cli

import (
	"reflect"
	"testing"

	"github.com/pgsty/sow/internal/state"
)

func TestProjectionExpectedStagesCloseManifestAndConfigVector(t *testing.T) {
	asset := assetProjectionIntent{
		ViewPath: "views/beta/asset/all/all.tsv", ManifestSize: 11, ManifestSHA256: "asset-sha",
		ConfigSize: 22, ConfigSHA256: "config-sha",
	}
	if got, want := assetProjectionExpectedStages(asset), map[string]state.FileIdentity{
		"views/beta/asset/all/all.tsv": {Size: 11, SHA256: "asset-sha"},
		"config/sow.yaml":              {Size: 22, SHA256: "config-sha"},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("asset expected stages=%+v want=%+v", got, want)
	}

	packages := packageProjectionIntent{
		ConfigSize: 33, ConfigSHA256: "package-config-sha",
		Units: []packageProjectionIntentUnit{
			{ViewPath: "views/beta/apt/jammy/arm64.tsv", ManifestSize: 44, ManifestSHA256: "apt-sha"},
			{ViewPath: "views/beta/yum/el9/x86_64.tsv", ManifestSize: 55, ManifestSHA256: "yum-sha"},
		},
	}
	if got, want := packageProjectionExpectedStages(packages), map[string]state.FileIdentity{
		"views/beta/apt/jammy/arm64.tsv": {Size: 44, SHA256: "apt-sha"},
		"views/beta/yum/el9/x86_64.tsv":  {Size: 55, SHA256: "yum-sha"},
		"config/sow.yaml":                {Size: 33, SHA256: "package-config-sha"},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("package expected stages=%+v want=%+v", got, want)
	}
}
