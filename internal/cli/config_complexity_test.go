package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
)

func TestInitRejectsConfigurationComplexityBeforeStateMutation(t *testing.T) {
	tests := []struct {
		name string
		body func() string
		want string
	}{
		{
			name: "default topology amplification",
			body: topologyAmplificationCLIConfig,
			want: "configuration topology exceeds 65536-work-unit safety limit",
		},
		{
			name: "long path derived bytes",
			body: longPathAmplificationCLIConfig,
			want: "configuration derived strings exceeds 67108864-byte safety limit",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "sow.yaml")
			original := []byte(test.body())
			if len(original) >= config.MaxConfigBytes {
				t.Fatalf("adversarial fixture is not sub-limit: %d bytes", len(original))
			}
			if err := os.WriteFile(configPath, original, 0o600); err != nil {
				t.Fatal(err)
			}

			var stdout, stderr bytes.Buffer
			code := Main([]string{"init", "--config", configPath}, &stdout, &stderr)
			if code != ExitConfig || !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("failed init emitted success output: %q", stdout.String())
			}
			for _, hidden := range []string{config.StateDirectory, config.PoolDirectory} {
				if _, err := os.Lstat(filepath.Join(root, hidden)); !os.IsNotExist(err) {
					t.Fatalf("failed init created %s: %v", hidden, err)
				}
			}
			after, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, original) {
				t.Fatal("failed init changed operator configuration bytes")
			}
		})
	}
}

func topologyAmplificationCLIConfig() string {
	arches := make([]string, 256)
	for index := range arches {
		arches[index] = fmt.Sprintf("arch%03d", index)
	}
	upstreams := make([]string, 130)
	for index := range upstreams {
		upstreams[index] = fmt.Sprintf("  - {id: upstream-%03d, type: apt, repo: apt-wide}\n", index)
	}
	return configComplexityCLIShell(fmt.Sprintf(`
  - id: apt-wide
    type: apt
    path: apt/wide
    default_pool: public
    arches: [%s]
    os: {family: debian, lifecycle: active}
    apt: {suites: [stable], components: [main]}
`, strings.Join(arches, ", ")), strings.Join(upstreams, ""))
}

func longPathAmplificationCLIConfig() string {
	arches := make([]string, 20)
	for index := range arches {
		arches[index] = fmt.Sprintf("arch%02d", index)
	}
	return configComplexityCLIShell(fmt.Sprintf(`
  - id: yum-wide
    type: yum
    path: yum/%s/{arch}
    default_pool: public
    arches: [%s]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: keys/packages.asc}
`, strings.Repeat("p", 2<<20), strings.Join(arches, ", ")), "")
}

func configComplexityCLIShell(repos, upstreams string) string {
	return `schema: sow/v1
state: {}
gpg: {public_key: keys/repository.asc}
pools: {public: {}, gated: {}}
repos:` + repos + `upstreams:
` + upstreams + `views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`
}
