package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/state"
)

func TestInitNeverAdvancesImmutableCompatibilityCarrierS0(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(yumCompatibilityInitConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		filepath.Join(root, "yum", "infra", "el9", "x86_64"),
		filepath.Join(root, "yum", "infra", "x86_64"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	legacy := filepath.Join(root, "yum", "infra", "x86_64", "legacy.rpm")
	if err := os.WriteFile(legacy, []byte("immutable legacy bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func() (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main([]string{"init", "--config", configPath, "--root", root, "--workers", "2"}, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run(); code != ExitOK {
		t.Fatalf("initial S0 init code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	carrierRef, _ := state.RepoRef("infra-carrier")
	s0, exists, err := canonical.Ref(carrierRef)
	if err != nil || !exists || s0.IsZero() {
		t.Fatalf("immutable S0 ref exists=%t commit=%s err=%v", exists, s0, err)
	}
	marker := filepath.Join(root, "after-s0.marker")
	if err := os.WriteFile(marker, []byte("later canonical state"), 0o600); err != nil {
		t.Fatal(err)
	}
	later, changed, err := canonical.InstallPaths(map[string]string{"tests/after-s0": marker}, "test: later adoption-like state")
	if err != nil || !changed || later == s0 {
		t.Fatalf("install later state changed=%t commit=%s err=%v", changed, later, err)
	}
	if code, stdout, stderr := run(); code != ExitOK || !strings.Contains(stdout, "baseline preserved repo=infra-carrier immutable_inventory=true") {
		t.Fatalf("replayed S0 init code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if current, exists, err := canonical.Ref(carrierRef); err != nil || !exists || current != s0 {
		t.Fatalf("exact replay advanced S0 ref: exists=%t current=%s want=%s err=%v", exists, current, s0, err)
	}
	beforeDrift, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "yum", "infra", "x86_64", "unexpected.rpm"), []byte("drift"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run(); code != ExitVerification || !strings.Contains(stderr, "inventory carrier infra-carrier differs from immutable baseline") {
		t.Fatalf("drifted S0 init code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if afterDrift, err := canonical.HeadHash(); err != nil || afterDrift != beforeDrift {
		t.Fatalf("rejected carrier drift advanced HEAD: before=%s after=%s err=%v", beforeDrift, afterDrift, err)
	}
	if current, exists, err := canonical.Ref(carrierRef); err != nil || !exists || current != s0 {
		t.Fatalf("rejected carrier drift advanced S0 ref: exists=%t current=%s want=%s err=%v", exists, current, s0, err)
	}
}

func TestFSCKFailsClosedBeforeScanningAnyPendingYUMCompatibilityCutoverJournal(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(yumCompatibilityInitConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		filepath.Join(root, "yum", "infra", "el9", "x86_64"),
		filepath.Join(root, "yum", "infra", "x86_64"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	// This deliberately belongs to another projection and uses the durable
	// atomic-write sidecar suffix. fsck must fail on every pending journal, not
	// merely one selected compatibility projection's primary journal.
	journal := filepath.Join(root, ".sow", "yum-compatibility-cutover-other.journal.json.next")
	if err := os.WriteFile(journal, []byte("pending local cutover"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code := Main([]string{"fsck", "--config", configPath, "--repo", "infra-el9", "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitConflict || !strings.Contains(stderr.String(), journal) || !strings.Contains(stderr.String(), "yum-cutover or yum-rollback") || !strings.Contains(stderr.String(), "--recover") {
		t.Fatalf("pending cutover fsck code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "fsck repo=") || strings.Contains(stdout.String(), "fsck clean") {
		t.Fatalf("fsck scanned repositories despite pending cutover journal: %s", stdout.String())
	}
	if headAfter, err := canonical.HeadHash(); err != nil || headAfter != headBefore {
		t.Fatalf("rejected fsck changed canonical HEAD: before=%s after=%s err=%v", headBefore, headAfter, err)
	}
}

func TestFSCKAuditsS0CompatibilityCarrierAgainstImmutableRef(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(yumCompatibilityInitConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		filepath.Join(root, "yum", "infra", "el9", "x86_64"),
		filepath.Join(root, "yum", "infra", "x86_64"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run := func(command string, extra ...string) (int, string, string) {
		arguments := []string{command, "--config", configPath, "--workers", "1", "--chunk-entries", "1"}
		arguments = append(arguments, extra...)
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("init"); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("fsck", "--repo", "infra-el9"); code != ExitOK || !strings.Contains(stdout, "fsck yum_compatibility=infra-legacy-x86-64 stage=S0-raw clean=true") {
		t.Fatalf("clean S0 fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if err := os.WriteFile(filepath.Join(root, "yum", "infra", "x86_64", "drift.rpm"), []byte("untracked carrier drift"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("fsck", "--repo", "infra-el9"); code != ExitVerification || !strings.Contains(stdout, "yum_compatibility=infra-legacy-x86-64 stage=S0-raw code=YUM_COMPATIBILITY_STAGE_CLOSURE_INVALID") || !strings.Contains(stdout, "served carrier differs from S0 baseline") {
		t.Fatalf("drifted S0 fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

const yumCompatibilityInitConfig = `schema: sow/v1
state: {}
gpg: {}
pools: {public: {}, gated: {}}
repos:
  - id: infra-el9
    type: yum
    path: yum/infra/el9/{arch}
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
  - id: infra-carrier
    type: yum
    path: yum/infra/{arch}
    active: false
    default_pool: public
    arches: [x86_64]
    os: {family: cross-el, major: 0, lifecycle: frozen}
    yum: {compression: gzip, compatibility_carrier: true, package_keyring: package-trust.asc}
compatibility_projections:
  - id: infra-legacy-x86-64
    root: yum/infra/x86_64
    mode: frozen-cross-el
    carrier: infra-carrier
    source: {repo: infra-el9, view: latest, os: cross-el, arch: x86_64, commit: pin-at-first-freeze}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false, repos: [infra-el9]}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`
