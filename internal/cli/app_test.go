package cli

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
)

func TestInitAndFSCKEndToEnd(t *testing.T) {
	root := t.TempDir()
	asset := filepath.Join(root, "asset", "hello.txt")
	if err := os.MkdirAll(filepath.Dir(asset), 0o755); err != nil {
		t.Fatal(err)
	}
	original := []byte("hello")
	if err := os.WriteFile(asset, original, 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"init", "--config", configPath, "--workers", "2", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "baseline committed=") {
		t.Fatalf("missing commit evidence: %s", stdout.String())
	}
	after, err := os.ReadFile(asset)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("init modified a published file")
	}

	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"init", "--config", configPath, "--workers", "2", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "baseline unchanged=") {
		t.Fatalf("idempotent init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"fsck", "--config", configPath, "--workers", "2", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "fsck clean") {
		t.Fatalf("clean fsck code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	if err := os.WriteFile(asset, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"fsck", "--config", configPath, "--workers", "2", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitVerification || !strings.Contains(stdout.String(), "kind=changed") || !strings.Contains(stderr.String(), "drift detected") {
		t.Fatalf("dirty fsck code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestLoadedConfigBaselineRejectsLaterDifferentCanonicalConfig(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "asset"), 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("initial config code=%d stderr=%s", code, stderr.String())
	}
	loaded, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := captureCanonicalConfigBaseline(loaded); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(testConfig, "state: {}", "state: {cas_history_commits: 33}", 1)
	changedPath := filepath.Join(root, "changed.yaml")
	if err := os.WriteFile(changedPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"init", "--config", changedPath}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("later config code=%d stderr=%s", code, stderr.String())
	}
	if err := requireCanonicalConfigBaseline(loaded, state.New(loaded.StatePath())); !errors.Is(err, state.ErrFileConflict) {
		t.Fatalf("stale loaded config baseline was accepted: %v", err)
	}
}

func TestPreDecodeConfigBaselineRejectsCompetingCommit(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "asset"), 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("initial config code=%d stderr=%s", code, stderr.String())
	}
	baselineA, err := readCanonicalConfigBaseline(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	staleA, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(testConfig, "state: {}", "state: {cas_history_commits: 33}", 1)
	configB := filepath.Join(root, "config-b.yaml")
	if err := os.WriteFile(configB, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"init", "--config", configB}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("competing config code=%d stderr=%s", code, stderr.String())
	}
	setCanonicalConfigBaseline(staleA, baselineA)
	txDir, err := newTransactionDir(staleA.StatePath(), "stale-config-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(txDir)
	stagedConfig, _, err := stageCanonicalConfig(staleA, txDir)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = applyCanonicalConfig(t.Context(), staleA, state.New(staleA.StatePath()), "test", "stale config A", map[string]string{
		"config/sow.yaml": stagedConfig,
	}, nil, state.ApplyOptions{})
	if !errors.Is(err, state.ErrFileConflict) {
		t.Fatalf("pre-decode baseline admitted competing commit: %v", err)
	}
}

func TestHelpAndUsageCodes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Main(nil, &stdout, &stderr); code != ExitOK || !strings.Contains(stdout.String(), "init       adopt") {
		t.Fatalf("help code/content mismatch: %d %s", code, stdout.String())
	}
	stdout.Reset()
	if code := Main([]string{"unknown"}, &stdout, &stderr); code != ExitUsage {
		t.Fatalf("unknown command code=%d", code)
	}
	for _, command := range []string{"init", "fsck", "add", "rm", "sync", "publish", "gc", "verify", "promote", "materialize"} {
		stdout.Reset()
		stderr.Reset()
		if code := Main([]string{command, "--help"}, &stdout, &stderr); code != ExitOK {
			t.Errorf("%s --help code=%d stdout=%q stderr=%q", command, code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stderr.String(), "Usage: sow "+command) {
			t.Errorf("%s --help omitted command usage: stdout=%q stderr=%q", command, stdout.String(), stderr.String())
		}
		if !strings.Contains(stderr.String(), "\nOptions:\n") {
			t.Errorf("%s --help omitted generated options: stdout=%q stderr=%q", command, stdout.String(), stderr.String())
		}
		if strings.Contains(stderr.String(), "sow: ") {
			t.Errorf("%s --help reported an error: %q", command, stderr.String())
		}
	}
}

func TestHelpPrinterIncludesEveryRegisteredFlag(t *testing.T) {
	fs := flag.NewFlagSet("fixture", flag.ContinueOnError)
	var output bytes.Buffer
	fs.SetOutput(&output)
	fs.Bool("recover", false, "recover interrupted work")
	fs.Int("workers", 4, "bounded worker count")
	fs.String("gpg-private-key-file", "", "protected key file")
	var selectors csvFlag
	fs.Var(&selectors, "repo", "repository selector")

	printSubcommandUsage(fs, "sow fixture [options]", "Fixture note.")
	help := output.String()
	if !strings.Contains(help, "Usage: sow fixture [options]") || !strings.Contains(help, "Fixture note.") || !strings.Contains(help, "\nOptions:\n") {
		t.Fatalf("help framing is incomplete: %q", help)
	}
	fs.VisitAll(func(item *flag.Flag) {
		found := false
		for _, line := range strings.Split(help, "\n") {
			if line == "  -"+item.Name || strings.HasPrefix(line, "  -"+item.Name+" ") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("registered flag %q is absent from generated help: %q", item.Name, help)
		}
	})
}

func TestHelpDoesNotEchoSensitiveFlagValues(t *testing.T) {
	const marker = "/protected/DO-NOT-ECHO-SECRET"
	tests := []struct {
		command string
		flags   []string
	}{
		{command: "add", flags: []string{"--gpg-private-key-file", marker, "--gpg-passphrase-file", marker}},
		{command: "rm", flags: []string{"--gpg-private-key-file", marker, "--gpg-passphrase-file", marker}},
		{command: "sync", flags: []string{"--gpg-private-key-file", marker, "--gpg-passphrase-file", marker}},
		{command: "publish", flags: []string{"--gpg-private-key-file", marker, "--gpg-passphrase-file", marker}},
		{command: "materialize", flags: []string{"--gpg-private-key-file", marker, "--gpg-passphrase-file", marker}},
		{command: "verify", flags: []string{"--gpg-public-key-file", marker, "--pro-token-file", marker}},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			arguments := append([]string{test.command}, test.flags...)
			arguments = append(arguments, "--help")
			var stdout, stderr bytes.Buffer
			if code := Main(arguments, &stdout, &stderr); code != ExitOK {
				t.Fatalf("help code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			combined := stdout.String() + stderr.String()
			if strings.Contains(combined, marker) {
				t.Fatalf("help echoed a supplied sensitive value: %q", combined)
			}
			if strings.Contains(combined, "sow: ") {
				t.Fatalf("help reported an error: %q", combined)
			}
		})
	}
}

func TestHelpAfterPositionalsShortCircuitsBeforeConfigurationOrMutation(t *testing.T) {
	missingConfig := filepath.Join(t.TempDir(), "must-not-be-read.yaml")
	tests := []struct {
		name string
		args []string
	}{
		{name: "add", args: []string{"add", "--config", missingConfig, "--repo", "assets", "payload.rpm", "--help"}},
		{name: "rm", args: []string{"rm", "--config", missingConfig, "--view", "beta", "real-selector", "--help"}},
		{name: "promote", args: []string{"promote", "--config", missingConfig, "beta", "latest", "--help"}},
		{name: "materialize", args: []string{"materialize", "--config", missingConfig, "latest", "-h"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Main(test.args, &stdout, &stderr); code != ExitOK {
				t.Fatalf("help code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			combined := stdout.String() + stderr.String()
			if !strings.Contains(combined, "Usage: sow "+test.name) || !strings.Contains(combined, "\nOptions:\n") {
				t.Fatalf("trailing help omitted generated usage: %q", combined)
			}
			if strings.Contains(combined, missingConfig) || strings.Contains(combined, "sow: ") {
				t.Fatalf("trailing help read configuration or reported business failure: %q", combined)
			}
			if _, err := os.Stat(missingConfig); !os.IsNotExist(err) {
				t.Fatalf("help path unexpectedly mutated config sentinel: %v", err)
			}
		})
	}
}

func TestHelpScannerHonorsEndOfOptionsDelimiter(t *testing.T) {
	fs := flag.NewFlagSet("fixture", flag.ContinueOnError)
	var output bytes.Buffer
	fs.SetOutput(&output)
	usageCalls := 0
	fs.Usage = func() { usageCalls++ }
	help, err := parseFlagSet(fs, []string{"--", "--help"})
	if err != nil || help || usageCalls != 0 {
		t.Fatalf("literal post-delimiter help parsed as control help=%v usage_calls=%d err=%v", help, usageCalls, err)
	}
	if got := fs.Args(); len(got) != 1 || got[0] != "--help" {
		t.Fatalf("post-delimiter positional=%q want [--help]", got)
	}
}

func TestHelpScannerDistinguishesDelimiterFromFlagValue(t *testing.T) {
	fs := flag.NewFlagSet("fixture", flag.ContinueOnError)
	var output bytes.Buffer
	fs.SetOutput(&output)
	fs.String("config", "sow.yaml", "configuration path")
	fs.String("view", "beta", "view selector")
	usageCalls := 0
	fs.Usage = func() { usageCalls++ }
	help, err := parseFlagSet(fs, []string{"--config", "--", "--view", "beta", "package", "--help"})
	if err != nil || !help || usageCalls != 1 {
		t.Fatalf("dash-dash flag value hid later help help=%v usage_calls=%d err=%v", help, usageCalls, err)
	}
}

func TestAddParsesOptionsAfterAnInputBeforeReadingConfiguration(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "intended.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig+"proof_marker: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "payload.bin")
	if err := os.WriteFile(input, []byte("must not be imported"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Main([]string{
		"add", "--type", "asset", input,
		"--config", configPath, "--repo", "asset", "--dest", "payload.bin",
	}, &stdout, &stderr)
	if code != ExitConfig || !strings.Contains(stderr.String(), "proof_marker") {
		t.Fatalf("interspersed --config was ignored code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".sow")); !os.IsNotExist(err) {
		t.Fatalf("invalid intended configuration mutated state: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".pool")); !os.IsNotExist(err) {
		t.Fatalf("invalid intended configuration mutated CAS: %v", err)
	}
}

func TestAddInterspersedArgumentPartitionHonorsFlagsAndDelimiter(t *testing.T) {
	fs := flag.NewFlagSet("add-partition", flag.ContinueOnError)
	inputType := fs.String("type", "auto", "input type")
	configPath := fs.String("config", "sow.yaml", "configuration")
	replace := fs.Bool("replace", false, "replace")

	flagArgs, positionals := partitionInterspersedFlagArgs(fs, []string{
		"--type", "asset", "first.bin", "--config", "intended.yaml",
		"second.bin", "--replace", "--", "--literal.bin", "third.bin",
	})
	if help, err := parseFlagSet(fs, flagArgs); err != nil || help {
		t.Fatalf("parse partitioned add flags help=%v err=%v flags=%q", help, err, flagArgs)
	}
	if *inputType != "asset" || *configPath != "intended.yaml" || !*replace {
		t.Fatalf("partitioned values type=%q config=%q replace=%v", *inputType, *configPath, *replace)
	}
	want := []string{"first.bin", "second.bin", "--literal.bin", "third.bin"}
	if strings.Join(positionals, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("partitioned add inputs=%q want=%q", positionals, want)
	}
}

func TestAddRejectsUnknownOptionAfterInputBeforeConfigurationRead(t *testing.T) {
	missingConfig := filepath.Join(t.TempDir(), "must-not-be-read.yaml")
	var stdout, stderr bytes.Buffer
	code := Main([]string{
		"add", "--type", "asset", "payload.bin", "--unknown-add-option",
		"--config", missingConfig,
	}, &stdout, &stderr)
	if code != ExitUsage || !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("unknown trailing add option code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), missingConfig) {
		t.Fatalf("unknown trailing add option read configuration: %q", stderr.String())
	}
}

func TestInitRejectsConfigurableSnapshotPolicyBeforeStateCreation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	configured := strings.Replace(testConfig,
		"  stable: {access: pro, allowed_pools: [public, gated], append_only: true}\n",
		"  stable: {access: pro, allowed_pools: [public, gated], append_only: true}\n  snapshot: {access: public, allowed_pools: [public], append_only: false}\n", 1)
	if err := os.WriteFile(configPath, []byte(configured), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"init", "--config", configPath}, &stdout, &stderr)
	if code != ExitConfig || !strings.Contains(stderr.String(), "views.snapshot is not configurable") {
		t.Fatalf("configurable snapshot policy code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".sow")); !os.IsNotExist(err) {
		t.Fatalf("rejected snapshot policy created canonical state: %v", err)
	}
}

func TestCLIRejectsUnboundedWorkersBeforeMutation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"init", "--config", configPath, "--workers", "65"}, &stdout, &stderr)
	if code != ExitUsage || !strings.Contains(stderr.String(), "--workers must not exceed 64") {
		t.Fatalf("oversized workers code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".sow")); !os.IsNotExist(err) {
		t.Fatalf("oversized worker request mutated state: %v", err)
	}
}

func TestInitAndFSCKExpandMultiArchitectureYUMPath(t *testing.T) {
	root := t.TempDir()
	for arch, contents := range map[string]string{"x86_64": "x86", "aarch64": "arm"} {
		filename := filepath.Join(root, "yum", "infra", arch, "Packages", "p", "probe.rpm")
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(multiarchInitConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath, "--workers", "2", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("multiarch init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	manifestBytes, err := os.ReadFile(filepath.Join(root, ".sow", "state", "manifests", "infra.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	manifestText := string(manifestBytes)
	if !strings.Contains(manifestText, "yum/infra/aarch64/") || !strings.Contains(manifestText, "yum/infra/x86_64/") {
		t.Fatalf("aggregate manifest omitted an expanded path:\n%s", manifestText)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"fsck", "--config", configPath, "--workers", "2", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitOK || !strings.Contains(stdout.String(), "fsck clean") {
		t.Fatalf("multiarch fsck code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestNarrowRepoSelectionDetachesAndIntersectsLeafDimensions(t *testing.T) {
	repo := config.Repo{
		ID: "apt", Type: "apt", Arches: []string{"amd64", "arm64"},
		APT: &config.APTConfig{Suites: []string{"bookworm", "trixie"}, Components: []string{"main"}},
	}
	values := commonFlags{
		arches: csvFlag{items: []string{"arm64"}},
		oses:   csvFlag{items: []string{"trixie"}},
	}
	selected := narrowRepoSelection(repo, values)
	if got := strings.Join(selected.Arches, ","); got != "arm64" {
		t.Fatalf("selected arches=%q", got)
	}
	if got := strings.Join(selected.APT.Suites, ","); got != "trixie" {
		t.Fatalf("selected suites=%q", got)
	}
	selected.Arches[0] = "mutated"
	selected.APT.Suites[0] = "mutated"
	if got := strings.Join(repo.Arches, ","); got != "amd64,arm64" {
		t.Fatalf("source arches were aliased: %q", got)
	}
	if got := strings.Join(repo.APT.Suites, ","); got != "bookworm,trixie" {
		t.Fatalf("source suites were aliased: %q", got)
	}
}

func TestRepoGroupCLIExpansionFreezesPhysicalRecoveryLeaves(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"apt/one/dists/jammy/main/binary-arm64/Packages": "selected",
		"apt/one/dists/jammy/main/binary-amd64/Packages": "wrong-arch",
		"apt/one/dists/noble/main/binary-arm64/Packages": "wrong-suite",
		"apt/two/dists/jammy/main/binary-amd64/Packages": "wrong-repo",
	}
	for name, body := range files {
		filename := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(repoGroupAPTInitConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{"init", "--config", configPath, "--repo", "apt-family", "--os", "jammy", "--arch", "arm64", "--workers", "1", "--chunk-entries", "1"}
	var stdout, stderr bytes.Buffer
	if code := Main(arguments, &stdout, &stderr); code != ExitOK {
		t.Fatalf("group-scoped init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "repos=1") || !strings.Contains(stdout.String(), "repo=apt-one") {
		t.Fatalf("group selector did not narrow to one physical repo: %s", stdout.String())
	}
	cfg, selected, err := loadAndSelect(commonFlags{
		configPath: configPath, workers: 1, chunk: 1,
		repos: csvFlag{items: []string{"apt-family"}}, oses: csvFlag{items: []string{"jammy"}}, arches: csvFlag{items: []string{"arm64"}},
	})
	if err != nil || len(selected) != 1 || selected[0].ID != "apt-one" || strings.Join(selected[0].APT.Suites, ",") != "jammy" || strings.Join(selected[0].Arches, ",") != "arm64" {
		t.Fatalf("physical selector expansion=%+v err=%v", selected, err)
	}
	canonical := state.New(cfg.StatePath())
	oneRef, _ := state.RepoRef("apt-one")
	if _, exists, err := canonical.Ref(oneRef); err != nil || !exists {
		t.Fatalf("physical apt-one baseline exists=%v err=%v", exists, err)
	}
	twoRef, _ := state.RepoRef("apt-two")
	if _, exists, err := canonical.Ref(twoRef); err != nil || exists {
		t.Fatalf("unmatched apt-two baseline exists=%v err=%v", exists, err)
	}
	manifestBytes, err := os.ReadFile(canonical.ManifestPath("apt-one"))
	if err != nil {
		t.Fatal(err)
	}
	manifestText := string(manifestBytes)
	if !strings.Contains(manifestText, "binary-arm64/Packages") || strings.Contains(manifestText, "binary-amd64/Packages") || strings.Contains(manifestText, "dists/noble/") || strings.Contains(manifestText, "apt/two/") {
		t.Fatalf("group+OS+arch selector widened physical baseline:\n%s", manifestText)
	}

	viewPath, err := state.ViewPath("latest", "apt-one", "jammy", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	emptyView := filepath.Join(root, "empty-view.tsv")
	if err := os.WriteFile(emptyView, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	viewCommit, _, err := canonical.InstallPaths(map[string]string{viewPath: emptyView}, "seed selected physical view")
	if err != nil {
		t.Fatal(err)
	}
	viewRef, _ := state.ViewRef("latest", "apt-one", "jammy", "arm64")
	if err := canonical.AdvanceRef(viewRef, plumbing.ZeroHash, viewCommit, false); err != nil {
		t.Fatal(err)
	}
	leaves := selectedLeaves(selected, commonFlags{oses: csvFlag{items: []string{"jammy"}}, arches: csvFlag{items: []string{"arm64"}}})
	units, err := planMaterializationSelectedUnits(cfg, canonical, []materializationSelectionRequest{{
		Source: materializeCanonicalSource{ID: "latest"}, Leaves: leaves, TargetRoot: filepath.Join(root, "export"), IncludeMetadata: true,
	}})
	if err != nil || len(units) != 1 || units[0].Repo != "apt-one" || units[0].OS != "jammy" || units[0].Arch != "" || strings.Contains(units[0].ID, "apt-family") {
		t.Fatalf("durable units did not freeze physical leaves: %+v err=%v", units, err)
	}
	configSHA, parentConfigSHA, head, err := currentMaterializationCanonicalIdentity(cfg, canonical)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &materializationTrustSnapshot{repositoryKeySHA256: strings.Repeat("a", 64), yum: make(map[string]materializationYUMTrust)}
	journal, err := newMaterializationSelectionJournal("materialize", configSHA, parentConfigSHA, head, snapshot, units)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMaterializationSelectionJournal(cfg.StatePath(), journal); err != nil {
		t.Fatal(err)
	}
	durable, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !exists || len(durable.Units) != 1 || durable.Units[0].Repo != "apt-one" {
		t.Fatalf("physical recovery journal exists=%v units=%+v err=%v", exists, durable.Units, err)
	}
	changed := *cfg
	changed.RepoGroups = map[string][]string{"apt-family": {"apt-two"}}
	if err := requireMaterializationJournalCanonicalIdentity(&changed, canonical, durable); err == nil || !strings.Contains(err.Error(), "config") {
		t.Fatalf("group membership drift did not invalidate recovery: %v", err)
	}
}

func TestPartialInitPreservesUnselectedYUMBaselineAndPartialFSCKScope(t *testing.T) {
	root := t.TempDir()
	for arch, contents := range map[string]string{"x86_64": "x86", "aarch64": "arm"} {
		filename := filepath.Join(root, "yum", "infra", arch, "Packages", "p", "probe.rpm")
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(multiarchInitConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"init", "--config", configPath, "--workers", "2", "--chunk-entries", "1"}
	if code := Main(args, &stdout, &stderr); code != ExitOK {
		t.Fatalf("full init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	args = append(args, "--arch", "aarch64")
	if code := Main(args, &stdout, &stderr); code != ExitOK {
		t.Fatalf("partial init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	manifestBytes, err := os.ReadFile(filepath.Join(root, ".sow", "state", "manifests", "infra.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifestBytes), "yum/infra/aarch64/") || !strings.Contains(string(manifestBytes), "yum/infra/x86_64/") {
		t.Fatalf("partial init discarded unselected baseline:\n%s", manifestBytes)
	}

	// Drift outside the selected arch must not poison the scoped audit, while a
	// full audit must still report it.
	if err := os.WriteFile(filepath.Join(root, "yum", "infra", "x86_64", "Packages", "p", "probe.rpm"), []byte("drift"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"fsck", "--config", configPath, "--arch", "aarch64", "--workers", "2", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("partial fsck widened scope code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"fsck", "--config", configPath, "--workers", "2", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitVerification {
		t.Fatalf("full fsck missed unselected drift code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestFirstPartialInitMakesUnselectedCoverageExplicit(t *testing.T) {
	root := t.TempDir()
	for arch, contents := range map[string]string{"x86_64": "x86", "aarch64": "arm"} {
		filename := filepath.Join(root, "yum", "infra", arch, "Packages", "p", "probe.rpm")
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(multiarchInitConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(arguments ...string) (int, string, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("init", "--config", configPath, "--arch", "aarch64", "--workers", "2", "--chunk-entries", "1"); code != ExitOK || !strings.Contains(stdout, "scope_full=false") {
		t.Fatalf("partial init code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("fsck", "--config", configPath, "--arch", "aarch64", "--workers", "2", "--chunk-entries", "1"); code != ExitOK || !strings.Contains(stdout, "fsck clean") {
		t.Fatalf("selected fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("fsck", "--config", configPath, "--workers", "2", "--chunk-entries", "1"); code != ExitVerification || !strings.Contains(stdout, "kind=added") || !strings.Contains(stdout, "yum/infra/x86_64/") {
		t.Fatalf("uncovered full fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("init", "--config", configPath, "--workers", "2", "--chunk-entries", "1"); code != ExitOK || !strings.Contains(stdout, "scope_full=true") {
		t.Fatalf("full coverage init code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("fsck", "--config", configPath, "--workers", "2", "--chunk-entries", "1"); code != ExitOK || !strings.Contains(stdout, "fsck clean") {
		t.Fatalf("full fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestPartialAPTFSCKNarrowsSuiteAndArchitectureButRetainsSharedPaths(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"apt/test/dists/bookworm/main/binary-amd64/Packages": "bookworm-amd64",
		"apt/test/dists/bookworm/main/binary-arm64/Packages": "bookworm-arm64",
		"apt/test/dists/trixie/main/binary-amd64/Packages":   "trixie-amd64",
		"apt/test/dists/trixie/main/binary-arm64/Packages":   "trixie-arm64",
		"apt/test/dists/bookworm/InRelease":                  "bookworm-release",
		"apt/test/dists/trixie/InRelease":                    "trixie-release",
		"apt/test/pool/main/p/probe.deb":                     "shared-pool",
	}
	for name, contents := range files {
		filename := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(multiSuiteAPTInitConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("full APT init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	// A different suite and architecture is outside trixie/arm64.
	outside := filepath.Join(root, "apt", "test", "dists", "bookworm", "main", "binary-amd64", "Packages")
	if err := os.WriteFile(outside, []byte("outside-drift"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"fsck", "--config", configPath, "--os", "trixie", "--arch", "arm64"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("APT partial fsck widened scope code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	// Pool is shared across APT leaves, so its drift must remain visible.
	shared := filepath.Join(root, "apt", "test", "pool", "main", "p", "probe.deb")
	if err := os.WriteFile(shared, []byte("shared-drift"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"fsck", "--config", configPath, "--os", "trixie", "--arch", "arm64"}, &stdout, &stderr); code != ExitVerification || !strings.Contains(stdout.String(), "probe.deb") {
		t.Fatalf("APT partial fsck ignored shared pool drift code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

const testConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: asset
    type: asset
    path: asset
    default_pool: public
    asset: {kind: test, mutable_paths: [tool.bin]}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`

const multiarchInitConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: infra
    type: yum
    path: yum/infra/{arch}
    default_pool: public
    arches: [x86_64, aarch64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`

const multiSuiteAPTInitConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: apt-test
    type: apt
    path: apt/test
    default_pool: public
    arches: [amd64, arm64]
    os: {family: debian, suite: trixie, lifecycle: active}
    apt: {suites: [bookworm, trixie], components: [main]}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`

const repoGroupAPTInitConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: apt-one
    type: apt
    path: apt/one
    default_pool: public
    arches: [amd64, arm64]
    os: {family: ubuntu, lifecycle: active}
    apt:
      suites: [jammy, noble]
      components: [main, "18"]
      suite_components: {jammy: [main], noble: [main, "18"]}
      suite_lifecycle: {jammy: active, noble: active}
  - id: apt-two
    type: apt
    path: apt/two
    default_pool: public
    arches: [amd64]
    os: {family: ubuntu, lifecycle: active}
    apt: {suites: [jammy], components: [main]}
repo_groups:
  apt-family: [apt-one, apt-two]
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
