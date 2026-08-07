package v2cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/managed"
	"github.com/pgsty/sow/internal/v2/state"
	"golang.org/x/sys/unix"
)

func TestMainManagedLifecycleAndJSONEnvelope(t *testing.T) {
	root := t.TempDir()
	assertCLISuccess(t, []string{"init", root, "--json"}, `"command":"init"`)
	assertCLISuccess(t, []string{"repo", "new", "pgsql", "-C", root, "--json"}, `"repository":"pgsql"`)
	assertCLISuccess(t, []string{"dist", "new", "el9", "--format", "rpm", "-C", root, "-r", "pgsql", "--json"}, `"format":"rpm"`)
	assertCLISuccess(t, []string{"dist", "new", "noble", "--format", "deb", "-C", root, "-r", "pgsql", "--json"}, `"format":"deb"`)

	stdout, stderr, code := runCLI([]string{
		"config", "show", "-C", root, "-r", "pgsql",
		"-d", "noble", "-d", "el9", "-d", "noble", "--json",
	})
	if code != ExitOK || stderr != "" {
		t.Fatalf("config show: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if strings.Contains(stdout, `"Repositories"`) || strings.Contains(stdout, `"Architectures"`) {
		t.Fatalf("config JSON leaked Go field names: %s", stdout)
	}
	var envelope struct {
		Schema     string `json:"schema"`
		Command    string `json:"command"`
		OK         bool   `json:"ok"`
		Repository string `json:"repository"`
		Result     struct {
			Repositories map[string]struct {
				Dists map[string]any `json:"dists"`
			} `json:"repos"`
		} `json:"result"`
		Errors []CLIError `json:"errors"`
	}
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != OutputSchema || envelope.Command != "config show" || !envelope.OK || envelope.Repository != "pgsql" || len(envelope.Errors) != 0 {
		t.Fatalf("envelope=%+v", envelope)
	}
	dists := envelope.Result.Repositories["pgsql"].Dists
	if len(dists) != 2 || dists["el9"] == nil || dists["noble"] == nil {
		t.Fatalf("repeatable --dist was not merged/deduplicated: %#v", dists)
	}

	stdout, stderr, code = runCLI([]string{"dist", "ls", "-C", root, "-r", "pgsql"})
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, "NAME\tFORMAT") || !strings.Contains(stdout, "el9\trpm") || !strings.Contains(stdout, "noble\tdeb") {
		t.Fatalf("dist ls: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	assertCLISuccess(t, []string{"dist", "show", "el9", "-C", root, "-r", "pgsql", "--json"}, `"name":"el9"`)
	assertCLISuccess(t, []string{"dist", "rm", "el9", "-C", root, "-r", "pgsql", "--json"}, `"removed":true`)
	assertCLISuccess(t, []string{"dist", "rm", "noble", "-C", root, "-r", "pgsql", "--json"}, `"removed":true`)
	assertCLISuccess(t, []string{"dist", "rm", "noble", "-C", root, "-r", "pgsql", "--json"}, `"noop":true`)
	assertCLISuccess(t, []string{"repo", "show", "pgsql", "-C", root, "--json"}, `"name":"pgsql"`)
	assertCLISuccess(t, []string{"repo", "rm", "pgsql", "-C", root, "--json"}, `"removed":true`)
	assertCLISuccess(t, []string{"repo", "rm", "pgsql", "-C", root, "--json"}, `"noop":true`)
}

func TestCLISummaryCheckAndChangesPreserveMaxUint64Generation(t *testing.T) {
	root := t.TempDir()
	assertCLISuccess(t, []string{"init", root, "--json"}, `"command":"init"`)
	assertCLISuccess(t, []string{"repo", "new", "repo", "-C", root, "--json"}, `"repository":"repo"`)
	ctx := context.Background()
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE repository_state SET built_generation = ? WHERE singleton = 1`, state.MaxGeneration); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.BootstrapLegacyGeneration(ctx, strings.Repeat("f", 64), state.MaxGeneration, nil); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := errors.Join(store.Check(ctx), store.ValidateGenerationLedger(ctx), store.Close()); err != nil {
		t.Fatal(err)
	}
	const maximum = `"18446744073709551615"`
	for _, command := range [][]string{
		{"status", "-C", root, "-r", "repo", "--json"},
		{"check", "-C", root, "-r", "repo", "--json"},
		{"changes", "-C", root, "-r", "repo", "--json"},
	} {
		stdout, stderr, code := runCLI(command)
		if code != ExitOK || stderr != "" || !strings.Contains(stdout, maximum) {
			t.Fatalf("%v lost MaxUint64 Generation: code=%d stdout=%q stderr=%q", command, code, stdout, stderr)
		}
	}
	stdout, stderr, code := runCLI([]string{"changes", "-C", root, "-r", "repo", "--json"})
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"base":"00000000000000000000"`) || !strings.Contains(stdout, `"generation":`+maximum) {
		t.Fatalf("changes MaxUint64 wire: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	stdout, stderr, code = runCLI([]string{"changes", "18446744073709551615", "-C", root, "-r", "repo", "--json"})
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"base":`+maximum) || !strings.Contains(stdout, `"generation":`+maximum) || !strings.Contains(stdout, `"changes":[]`) {
		t.Fatalf("explicit MaxUint64 changes base: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestMainP2P3PackageWorkflowEndToEnd(t *testing.T) {
	root := t.TempDir()
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeCLIFixture(t, filepath.Join("..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "pgdg-redhat-nonfree-repo.rpm"))
	deb := decodeCLIFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(inputs, "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb"))

	assertCLISuccess(t, []string{"init", root, "--json"}, `"command":"init"`)
	assertCLISuccess(t, []string{"repo", "new", "repo", "-C", root, "--json"}, `"name":"repo"`)
	assertCLISuccess(t, []string{"repo", "migrate", "repo", "-C", root, "--json"}, `"complete":true`)
	assertCLISuccess(t, []string{"dist", "new", "el9", "--format", "rpm", "-C", root, "-r", "repo", "--json"}, `"format":"rpm"`)
	assertCLISuccess(t, []string{"dist", "new", "noble", "--format", "deb", "-C", root, "-r", "repo", "--json"}, `"format":"deb"`)

	assertCLISuccess(t, []string{"add", rpm, "--skip", "-C", root, "-r", "repo", "-d", "el9", "--json"}, `"dirty":true`)
	assertCLISuccess(t, []string{"status", "-C", root, "-r", "repo", "--json"}, `"status":"dirty"`)
	assertCLISuccess(t, []string{"build", "-C", root, "-r", "repo", "--json"}, `"dirty":false`)
	assertCLISuccess(t, []string{"add", deb, "-C", root, "-r", "repo", "-d", "noble", "--json"}, `"accepted":1`)
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	summary, summaryErr := store.Summary(context.Background())
	if err := errors.Join(summaryErr, store.Close()); err != nil {
		t.Fatal(err)
	}
	generation := summary.BuiltGeneration.String()
	assertCLIActualRepository(t, []string{"retain", "add", generation, "-C", root, "--json"}, "repo")
	assertCLIActualRepository(t, []string{"retain", "ls", "-C", root, "--json"}, "repo")
	assertCLIActualRepository(t, []string{"retain", "rm", generation, "-C", root, "--json"}, "repo")
	assertCLISuccess(t, []string{"gc", "-C", root, "-r", "repo", "--json"}, `"noop":true`)
	assertCLISuccess(t, []string{"ls", "-C", root, "-r", "repo", "-d", "el9", "-d", "noble", "--json"}, `"packages"`)
	assertCLISuccess(t, []string{"show", "pgdg-redhat-nonfree-repo", "-C", root, "-r", "repo", "--json"}, `"coordinate"`)
	assertCLISuccess(t, []string{"where", "libpqtypes0", "-C", root, "--json"}, `"repository":"repo"`)
	assertCLISuccess(t, []string{"rm", "pgdg-redhat-nonfree-repo", "--check", "-C", root, "-r", "repo", "-d", "el9", "--json"}, `"check":true`)
	assertCLISuccess(t, []string{"check", "-C", root, "-r", "repo", "--json"}, `"ready_to_copy":true`)
	assertCLISuccess(t, []string{"changes", "0", "-C", root, "-r", "repo", "--json"}, `"base":"00000000000000000000"`)
	assertCLISuccess(t, []string{"log", "-C", root, "-r", "repo", "--json"}, `"operations"`)

	stdout, stderr, code := runCLI([]string{"log", "export", "-", "-C", root, "-r", "repo"})
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"kind":"add"`) || !strings.HasSuffix(stdout, "\n") {
		t.Fatalf("log export: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	// A repeated import must reuse the immutable object and leave the current
	// Built Generation unchanged rather than creating timestamp-dependent work.
	assertCLISuccess(t, []string{"add", rpm, "-C", root, "-r", "repo", "-d", "el9", "--json"}, `"memberships_added":0`)
	assertCLISuccess(t, []string{"status", "-C", root, "-r", "repo", "--json"}, `"ready_to_copy":true`)
}

func TestMainExportRPMLeafCopyDefault(t *testing.T) {
	root := t.TempDir()
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeCLIFixture(t, filepath.Join("..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	assertCLISuccess(t, []string{"init", root, "--json"}, `"command":"init"`)
	assertCLISuccess(t, []string{"repo", "new", "repo", "-C", root, "--json"}, `"repository":"repo"`)
	assertCLISuccess(t, []string{"dist", "new", "el9", "--format", "rpm", "-C", root, "-r", "repo", "--json"}, `"format":"rpm"`)
	assertCLISuccess(t, []string{"add", rpm, "-C", root, "-r", "repo", "-d", "el9", "--json"}, `"accepted":1`)
	target := filepath.Join(root, "leaf")
	stdout, stderr, code := runCLI([]string{"export", "rpm-leaf", "el9", "x86_64", target, "-C", root, "-r", "repo", "--json"})
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"command":"export rpm-leaf"`) || !strings.Contains(stdout, `"method":"copy"`) {
		t.Fatalf("export rpm-leaf code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if _, err := managed.VerifyRPMLeafExportStandalone(context.Background(), target, nil); err != nil {
		t.Fatal(err)
	}
}

func TestMainCheckNotReadyUsesIntegrityExit(t *testing.T) {
	root := t.TempDir()
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeCLIFixture(t, filepath.Join("..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	assertCLISuccess(t, []string{"init", root, "--json"}, `"command":"init"`)
	assertCLISuccess(t, []string{"repo", "new", "repo", "-C", root, "--json"}, `"name":"repo"`)
	assertCLISuccess(t, []string{"dist", "new", "el9", "--format", "rpm", "-C", root, "-r", "repo", "--json"}, `"format":"rpm"`)
	assertCLISuccess(t, []string{"add", rpm, "--skip", "-C", root, "-r", "repo", "-d", "el9", "--json"}, `"dirty":true`)
	assertCLIFailure(t, []string{"check", "-C", root, "-r", "repo", "--json"}, ExitIntegrity, "integrity")
}

func TestMainAddPartialSuccessReturnsExit3WithCommittedResult(t *testing.T) {
	root := t.TempDir()
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	valid := decodeCLIFixture(t, filepath.Join("..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "valid.rpm"))
	invalid := filepath.Join(inputs, "invalid.rpm")
	if err := os.WriteFile(invalid, []byte("not an rpm\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	assertCLISuccess(t, []string{"init", root, "--json"}, `"command":"init"`)
	assertCLISuccess(t, []string{"repo", "new", "repo", "-C", root, "--json"}, `"name":"repo"`)
	assertCLISuccess(t, []string{"dist", "new", "el9", "--format", "rpm", "-C", root, "-r", "repo", "--json"}, `"format":"rpm"`)

	stdout, stderr, code := runCLI([]string{"add", valid, invalid, "-C", root, "-r", "repo", "-d", "el9", "--json"})
	for _, fragment := range []string{`"class":"partial"`, `"accepted":1`, `"failed":1`, `"memberships_added":1`, `"dirty":false`} {
		if !strings.Contains(stdout, fragment) {
			t.Fatalf("partial JSON is missing %s: %s", fragment, stdout)
		}
	}
	if code != ExitPartial || stderr == "" {
		t.Fatalf("partial add code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	assertCLISuccess(t, []string{"check", "-C", root, "-r", "repo", "--json"}, `"ready_to_copy":true`)
	assertCLISuccess(t, []string{"show", "pgdg-redhat-nonfree-repo", "-C", root, "-r", "repo", "-d", "el9", "--json"}, `"coordinate"`)
}

func TestMainAddPartialSuccessHumanReportsCommittedAndFailedItems(t *testing.T) {
	root := t.TempDir()
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	valid := decodeCLIFixture(t, filepath.Join("..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "valid.rpm"))
	invalid := filepath.Join(inputs, "invalid.rpm")
	if err := os.WriteFile(invalid, []byte("not an rpm\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	assertCLISuccess(t, []string{"init", root}, "initialized ")
	assertCLISuccess(t, []string{"repo", "new", "repo", "-C", root}, "created repo")
	assertCLISuccess(t, []string{"dist", "new", "el9", "--format", "rpm", "-C", root, "-r", "repo"}, "created el9")

	stdout, stderr, code := runCLI([]string{"add", valid, invalid, "-C", root, "-r", "repo", "-d", "el9"})
	if code != ExitPartial || stderr == "" || strings.Contains(stdout, `"schema"`) {
		t.Fatalf("human partial add: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, fragment := range []string{
		"add repository=repo operation=",
		"accepted=1 failed=1 memberships=+1/-0",
		"dirty=false",
		"item input=" + strconv.Quote(valid) + " status=accepted",
		" sha256:",
		"dists=el9:accepted",
		"item input=" + strconv.Quote(invalid) + " status=failed",
		"error=",
	} {
		if !strings.Contains(stdout, fragment) {
			t.Fatalf("human partial output is missing %q:\n%s", fragment, stdout)
		}
	}
	assertCLISuccess(t, []string{"check", "-C", root, "-r", "repo", "--json"}, `"ready_to_copy":true`)
}

func decodeCLIFixture(t *testing.T, source, destination string) string {
	t.Helper()
	encoded, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, payload, 0o444); err != nil {
		t.Fatal(err)
	}
	return destination
}

func TestWorkdirControlsImplicitRepositorySelection(t *testing.T) {
	root := t.TempDir()
	configData := []byte("schema: sow/v3\nrepos:\n  alpha: {}\n  beta: {}\n")
	if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), configData, 0o644); err != nil {
		t.Fatal(err)
	}
	assertCLISuccess(t, []string{"init", root, "--json"}, `"repositories_initialized":2`)

	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
	if err := os.Chdir(filepath.Join(root, "beta")); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCLI([]string{
		"dist", "new", "selected-by-workdir", "--format", "rpm",
		"-C", filepath.Join(root, "alpha"), "--json",
	})
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"repository":"alpha"`) {
		t.Fatalf("workdir-selected dist new: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if _, stderr, code := runCLI([]string{"dist", "show", "selected-by-workdir", "-C", root, "-r", "alpha", "--json"}); code != ExitOK || stderr != "" {
		t.Fatalf("dist was not created in alpha: code=%d stderr=%q", code, stderr)
	}
	if stdout, _, code := runCLI([]string{"dist", "show", "selected-by-workdir", "-C", root, "-r", "beta", "--json"}); code != ExitRejected || !strings.Contains(stdout, `"ok":false`) {
		t.Fatalf("dist unexpectedly created in beta: code=%d stdout=%q", code, stdout)
	}
}

func TestMainConfigShowScopeAndAllIgnoresSelectors(t *testing.T) {
	root := t.TempDir()
	configData := []byte(`
schema: sow/v3
architectures: [amd64, arm64]
repos:
  alpha:
    dists:
      el9: {format: rpm}
      noble: {format: deb}
  beta:
    dists:
      noble: {format: deb, architectures: [amd64]}
`)
	if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), configData, 0o644); err != nil {
		t.Fatal(err)
	}
	assertCLISuccess(t, []string{"init", root, "--json"}, `"repositories_initialized":2`)

	stdout, stderr, code := runCLI([]string{"config", "show", "-C", root, "-r", "alpha", "--json"})
	if code != ExitOK || stderr != "" {
		t.Fatalf("scoped config show: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var scoped struct {
		Repository string `json:"repository"`
		Result     struct {
			Architectures []string `json:"architectures"`
			Repositories  map[string]struct {
				Dists map[string]any `json:"dists"`
			} `json:"repos"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(stdout), &scoped); err != nil {
		t.Fatal(err)
	}
	if scoped.Repository != "alpha" || len(scoped.Result.Repositories) != 1 || scoped.Result.Repositories["alpha"].Dists["el9"] == nil {
		t.Fatalf("scoped result = %#v", scoped)
	}
	if got := strings.Join(scoped.Result.Architectures, ","); got != "x86_64,aarch64" {
		t.Fatalf("scoped canonical architectures = %q", got)
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(filepath.Join(root, "alpha", "dists", "el9")); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runCLI([]string{"config", "show", "--json"})
	if err := os.Chdir(previous); err != nil {
		t.Fatal(err)
	}
	if code != ExitOK || stderr != "" {
		t.Fatalf("cwd-dist config show: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var cwdScoped struct {
		Repository string `json:"repository"`
		Result     struct {
			Repositories map[string]struct {
				Dists map[string]any `json:"dists"`
			} `json:"repos"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(stdout), &cwdScoped); err != nil {
		t.Fatal(err)
	}
	if cwdScoped.Repository != "alpha" || len(cwdScoped.Result.Repositories) != 1 ||
		len(cwdScoped.Result.Repositories["alpha"].Dists) != 1 ||
		cwdScoped.Result.Repositories["alpha"].Dists["el9"] == nil {
		t.Fatalf("cwd-dist scope was not preserved: %#v", cwdScoped)
	}

	stdout, stderr, code = runCLI([]string{
		"config", "show", "--all", "-C", root,
		"-r", "not-configured", "-d", "not-configured", "--json",
	})
	if code != ExitOK || stderr != "" {
		t.Fatalf("config show --all: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var all struct {
		Repository any `json:"repository"`
		Result     struct {
			Architectures []string `json:"architectures"`
			Repositories  map[string]struct {
				Dists map[string]struct {
					Architectures []string `json:"architectures"`
				} `json:"dists"`
			} `json:"repos"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(stdout), &all); err != nil {
		t.Fatal(err)
	}
	if all.Repository != nil || len(all.Result.Repositories) != 2 {
		t.Fatalf("--all did not ignore selectors and return the full workspace: %#v", all)
	}
	if len(all.Result.Repositories["alpha"].Dists) != 2 || len(all.Result.Repositories["beta"].Dists) != 1 {
		t.Fatalf("--all did not include every configured dist: %#v", all.Result.Repositories)
	}
	if got := strings.Join(all.Result.Architectures, ","); got != "x86_64,aarch64" {
		t.Fatalf("--all canonical architectures = %q", got)
	}
	for name, dist := range map[string]string{"alpha": "el9", "beta": "noble"} {
		repository := all.Result.Repositories[name]
		architectures := repository.Dists[dist].Architectures
		if name == "alpha" && strings.Join(architectures, ",") != "x86_64,aarch64" {
			t.Fatalf("inherited architectures were not expanded: %#v", architectures)
		}
		if name == "beta" && strings.Join(architectures, ",") != "x86_64" {
			t.Fatalf("explicit alias was not canonicalized: %#v", architectures)
		}
	}
	if strings.Contains(stdout, "amd64") || strings.Contains(stdout, "arm64") {
		t.Fatalf("--all leaked non-canonical aliases: %s", stdout)
	}
	for _, required := range []string{"signing", `"mode":"never"`, `"limit":0`, `"exclude":null`} {
		if !strings.Contains(stdout, required) {
			t.Fatalf("--all omitted active P2/P3 field %q: %s", required, stdout)
		}
	}
	for _, forbidden := range []string{"payload_json", "new_config", "PRIVATE KEY", "passphrase"} {
		if strings.Contains(stdout, forbidden) {
			t.Fatalf("--all exposed private field %q: %s", forbidden, stdout)
		}
	}
}

func TestMainHumanPackageListReportsScopedDirtyState(t *testing.T) {
	root := t.TempDir()
	configData := []byte(`
schema: sow/v3
repos:
  repo:
    dists:
      el9: {format: rpm}
      noble: {format: deb}
`)
	if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), configData, 0o644); err != nil {
		t.Fatal(err)
	}
	assertCLISuccess(t, []string{"init", root, "--json"}, `"dists_initialized":2`)
	cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	repository := cfg.Repositories["repo"]
	noble := repository.Dists["noble"]
	noble.Limit = 1
	repository.Dists["noble"] = noble
	cfg.Repositories["repo"] = repository
	data, err := config.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), data, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLI([]string{"ls", "-C", root, "-r", "repo", "-d", "noble"})
	if code != ExitOK || stderr != "" || !strings.HasPrefix(stdout, "repository=repo dists=noble dirty=true\n") || !strings.Contains(stdout, "SHA256\tCOORDINATE") {
		t.Fatalf("dirty noble human list: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	stdout, stderr, code = runCLI([]string{"ls", "-C", root, "-r", "repo", "-d", "el9"})
	if code != ExitOK || stderr != "" || !strings.HasPrefix(stdout, "repository=repo dists=el9 dirty=false\n") {
		t.Fatalf("clean el9 human list was polluted by noble: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestMainConfigShowRejectsWorkspaceRenameDuringAgentKeyExport(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "workspace")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	configData := []byte(`
schema: sow/v3
repos:
  repo:
    signing:
      rpm:
        metadata:
          key: agent://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
`)
	if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), configData, 0o644); err != nil {
		t.Fatal(err)
	}
	publicKey, err := filepath.Abs(filepath.Join("..", "..", "test", "compat", "testdata", "PGDG-RPM-GPG-KEY-RHEL-nonfree.asc"))
	if err != nil {
		t.Fatal(err)
	}
	control := t.TempDir()
	ready := filepath.Join(control, "ready")
	resume := filepath.Join(control, "resume")
	tools := t.TempDir()
	gpg := "#!/bin/sh\n" +
		": > \"$SOW_TEST_GPG_READY\"\n" +
		"while [ ! -e \"$SOW_TEST_GPG_RESUME\" ]; do sleep 0.01; done\n" +
		"exec /bin/cat \"$SOW_TEST_GPG_PUBLIC\"\n"
	if err := os.WriteFile(filepath.Join(tools, "gpg"), []byte(gpg), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SOW_TEST_GPG_READY", ready)
	t.Setenv("SOW_TEST_GPG_RESUME", resume)
	t.Setenv("SOW_TEST_GPG_PUBLIC", publicKey)

	type cliResult struct {
		stdout string
		stderr string
		code   int
	}
	result := make(chan cliResult, 1)
	go func() {
		stdout, stderr, code := runCLI([]string{"config", "show", "--all", "-C", root, "--json"})
		result <- cliResult{stdout: stdout, stderr: stderr, code: code}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("config show did not reach the blocked agent-key export")
		}
		time.Sleep(10 * time.Millisecond)
	}
	moved := root + ".moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resume, []byte("resume\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got.code != ExitIntegrity || !strings.Contains(got.stdout, `"ok":false`) ||
			!strings.Contains(got.stdout, `"class":"integrity"`) || !strings.Contains(got.stderr, "workspace root identity changed") {
			t.Fatalf("renamed config show: code=%d stdout=%q stderr=%q", got.code, got.stdout, got.stderr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("config show did not finish after the agent-key export resumed")
	}
}

func TestMainHumanShowIncludesConfigDirtyReasonsAndRecentOperation(t *testing.T) {
	root := t.TempDir()
	assertCLISuccess(t, []string{"init", root}, "initialized ")
	assertCLISuccess(t, []string{"repo", "new", "pgsql", "-C", root}, "created pgsql")
	assertCLISuccess(t, []string{"dist", "new", "el9", "--format", "rpm", "-C", root, "-r", "pgsql"}, "created el9")

	cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	repository := cfg.Repositories["pgsql"]
	dist := repository.Dists["el9"]
	dist.Architectures = []string{"x86_64"}
	repository.Dists["el9"] = dist
	cfg.Repositories["pgsql"] = repository
	data, err := config.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), data, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCLI([]string{"repo", "show", "pgsql", "-C", root})
	if code != ExitOK || stderr != "" {
		t.Fatalf("repo show: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, want := range []string{
		"config:", "dirty_reasons:",
		"dist el9 effective configuration differs from built state", "recent_operation:",
		"kind=dist.new", "state=done",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("repo show missing %q:\n%s", want, stdout)
		}
	}
	for _, args := range [][]string{
		{"repo", "show", "pgsql", "-C", root, "--json"},
		{"config", "show", "-C", root, "-r", "pgsql", "--json"},
		{"config", "show", "--all", "-C", root, "--json"},
		{"config", "show", "--all", "-C", root},
	} {
		stdout, stderr, code = runCLI(args)
		if code != ExitOK || stderr != "" {
			t.Fatalf("P1 show args=%q: code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
		for _, required := range []string{"signing", "limit", "exclude"} {
			if !strings.Contains(stdout, required) {
				t.Fatalf("show omitted active P2/P3 field %q args=%q: %s", required, args, stdout)
			}
		}
		for _, forbidden := range []string{"payload_json", "new_config", "PRIVATE KEY", "passphrase"} {
			if strings.Contains(stdout, forbidden) {
				t.Fatalf("show exposed private field %q args=%q: %s", forbidden, args, stdout)
			}
		}
	}

	stdout, stderr, code = runCLI([]string{"dist", "ls", "-C", root, "-r", "pgsql"})
	if code != ExitOK || stderr != "" {
		t.Fatalf("dist ls: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, want := range []string{"DESIRED", "BUILT", "DIRTY_REASONS", "effective configuration differs from built state"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("dist ls missing %q:\n%s", want, stdout)
		}
	}

	stdout, stderr, code = runCLI([]string{"dist", "show", "el9", "-C", root, "-r", "pgsql"})
	if code != ExitOK || stderr != "" {
		t.Fatalf("dist show: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, want := range []string{"dirty_reasons:", "effective configuration differs from built state"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("dist show missing %q:\n%s", want, stdout)
		}
	}

	cfg, err = config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	repository = cfg.Repositories["pgsql"]
	delete(repository.Dists, "el9")
	cfg.Repositories["pgsql"] = repository
	data, err = config.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), data, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runCLI([]string{"dist", "ls", "-C", root, "-r", "pgsql"})
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, "el9\trpm\t") || strings.Contains(strings.ToLower(stdout), "policy") {
		t.Fatalf("dist ls exposed deferred policy for state-only dist: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	stdout, stderr, code = runCLI([]string{"dist", "show", "el9", "-C", root, "-r", "pgsql"})
	if code != ExitOK || stderr != "" || strings.Contains(strings.ToLower(stdout), "policy") {
		t.Fatalf("dist show exposed deferred policy for state-only dist: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestMainExitCodeAndFailureEnvelopeMatrix(t *testing.T) {
	t.Run("unresolved active signing reference is rejected", func(t *testing.T) {
		root := t.TempDir()
		data := []byte("schema: sow/v3\nrepos:\n  pgsql:\n    signing:\n      rpm:\n        metadata:\n          key: env://KEY\n")
		if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), data, 0o644); err != nil {
			t.Fatal(err)
		}
		assertCLIFailure(t, []string{"config", "check", "-C", root, "--json"}, ExitRejected, "rejected")
		assertCLIFailure(t, []string{"config", "show", "--all", "-C", root, "--json"}, ExitRejected, "rejected")
	})
	t.Run("active policy schema is accepted", func(t *testing.T) {
		root := t.TempDir()
		data := []byte("schema: sow/v3\nrepos:\n  pgsql:\n    dists:\n      el9:\n        format: rpm\n        limit: 1\n")
		if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), data, 0o644); err != nil {
			t.Fatal(err)
		}
		assertCLISuccess(t, []string{"config", "check", "-C", root, "--json"}, `"dists":1`)
		assertCLISuccess(t, []string{"config", "show", "--all", "-C", root, "--json"}, `"limit":1`)
	})
	t.Run("repo show selector mismatch precedes discovery", func(t *testing.T) {
		assertCLIFailure(t, []string{
			"repo", "show", "pgsql", "-r", "infra", "-C", t.TempDir(), "--json",
		}, ExitRejected, "rejected")
	})
	t.Run("usage", func(t *testing.T) {
		assertCLIFailure(t, []string{"dist", "new", "el9", "--json"}, ExitUsage, "usage")
	})
	t.Run("discovery", func(t *testing.T) {
		root := t.TempDir()
		assertCLIFailure(t, []string{"repo", "ls", "-C", root, "--json"}, ExitUsage, "usage")
		assertCLIFailure(t, []string{"repo", "rm", "missing", "-C", root, "--json"}, ExitUsage, "usage")
	})
	t.Run("config", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), []byte("schema: sow/v3\nunknown: true\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		assertCLIFailure(t, []string{"config", "check", "-C", root, "--json"}, ExitUsage, "usage")
		assertCLIFailure(t, []string{"init", root, "--json"}, ExitUsage, "usage")
		assertCLIFailure(t, []string{"repo", "rm", "missing", "-C", root, "--json"}, ExitUsage, "usage")
	})
	t.Run("state architecture rejection", func(t *testing.T) {
		root := t.TempDir()
		assertCLISuccess(t, []string{"init", root}, "initialized ")
		assertCLISuccess(t, []string{"repo", "new", "arch", "-C", root}, "created arch")
		assertCLISuccess(t, []string{"dist", "new", "el9", "--format", "rpm", "-C", root, "-r", "arch"}, "created el9")
		cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Architectures = []string{"x86_64"}
		data, err := config.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), data, 0o644); err != nil {
			t.Fatal(err)
		}
		assertCLIFailure(t, []string{"config", "check", "-C", root, "--json"}, ExitRejected, "rejected")
	})
	t.Run("rejected", func(t *testing.T) {
		root := t.TempDir()
		assertCLISuccess(t, []string{"init", root}, "initialized ")
		assertCLISuccess(t, []string{"repo", "new", "prod", "-C", root}, "created prod")
		cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
		if err != nil {
			t.Fatal(err)
		}
		repo := cfg.Repositories["prod"]
		repo.Protected = true
		cfg.Repositories["prod"] = repo
		data, err := config.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), data, 0o644); err != nil {
			t.Fatal(err)
		}
		assertCLIFailure(t, []string{"repo", "rm", "prod", "-f", "-C", root, "--json"}, ExitRejected, "rejected")
	})
	t.Run("integrity", func(t *testing.T) {
		root := t.TempDir()
		assertCLISuccess(t, []string{"init", root}, "initialized ")
		assertCLISuccess(t, []string{"repo", "new", "broken", "-C", root}, "created broken")
		database := filepath.Join(root, ".sow", "broken.db")
		store, err := state.OpenExisting(database)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Checkpoint(context.Background()); err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(database, []byte("not sqlite"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertCLIFailure(t, []string{"repo", "show", "broken", "-C", root, "--json"}, ExitIntegrity, "integrity")
	})
	t.Run("lock", func(t *testing.T) {
		root := t.TempDir()
		assertCLISuccess(t, []string{"init", root}, "initialized ")
		lock, err := os.OpenFile(filepath.Join(root, ".sow", "workspace.lock"), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		defer unix.Flock(int(lock.Fd()), unix.LOCK_UN) //nolint:errcheck
		assertCLIFailure(t, []string{"repo", "new", "locked", "-C", root, "-N", "--json"}, ExitLock, "lock")
	})
}

func TestMainP1P3SelectionAndWorkspaceFailureMatrix(t *testing.T) {
	managedCommands := [][]string{
		{"add", "missing.rpm"},
		{"rm", "missing-package"},
		{"ls"},
		{"show", "missing-package"},
		{"where", "missing-package"},
		{"status"},
		{"build"},
		{"check"},
		{"changes", "0"},
		{"log"},
		{"log", "prune", "2000-01-01T00:00:00Z"},
	}
	t.Run("discovery and config are exit 2 for every managed surface", func(t *testing.T) {
		missing := t.TempDir()
		invalid := t.TempDir()
		if err := os.WriteFile(filepath.Join(invalid, config.ConfigFilename), []byte("schema: sow/v3\nunknown: true\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, command := range managedCommands {
			command := command
			t.Run(strings.Join(command, "-")+"-missing", func(t *testing.T) {
				args := append(append([]string(nil), command...), "-C", missing, "--json")
				assertCLIFailure(t, args, ExitUsage, "usage")
			})
			t.Run(strings.Join(command, "-")+"-invalid", func(t *testing.T) {
				args := append(append([]string(nil), command...), "-C", invalid, "--json")
				assertCLIFailure(t, args, ExitUsage, "usage")
			})
		}
	})

	root := t.TempDir()
	data := []byte("schema: sow/v3\nrepos:\n  alpha:\n    dists:\n      first: {format: rpm}\n      second: {format: rpm}\n  beta:\n    dists:\n      only: {format: rpm}\n")
	if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), data, 0o644); err != nil {
		t.Fatal(err)
	}
	assertCLISuccess(t, []string{"init", root, "--json"}, `"repositories_initialized":2`)

	t.Run("implicit repository ambiguity is discovery", func(t *testing.T) {
		for _, command := range [][]string{{"add", "missing.rpm"}, {"rm", "missing-package"}, {"ls"}, {"show", "missing-package"}, {"status"}, {"build"}, {"check"}, {"changes", "0"}, {"log"}, {"log", "prune", "2000-01-01T00:00:00Z"}} {
			args := append(append([]string(nil), command...), "-C", root, "--json")
			assertCLIFailure(t, args, ExitUsage, "usage")
		}
	})

	t.Run("explicit missing repository is rejected", func(t *testing.T) {
		for _, command := range [][]string{{"add", "missing.rpm"}, {"rm", "missing-package"}, {"ls"}, {"show", "missing-package"}, {"status"}, {"build"}, {"check"}, {"changes", "0"}, {"log"}, {"log", "prune", "2000-01-01T00:00:00Z"}} {
			args := append(append([]string(nil), command...), "-C", root, "-r", "missing", "--json")
			assertCLIFailure(t, args, ExitRejected, "rejected")
		}
	})

	t.Run("mutation dist ambiguity is discovery and explicit miss is rejected", func(t *testing.T) {
		for _, command := range [][]string{{"add", "missing.rpm"}, {"rm", "missing-package"}, {"ls"}} {
			implicit := append(append([]string(nil), command...), "-C", root, "-r", "alpha", "--json")
			assertCLIFailure(t, implicit, ExitUsage, "usage")
			explicit := append(append([]string(nil), command...), "-C", root, "-r", "alpha", "-d", "missing", "--json")
			assertCLIFailure(t, explicit, ExitRejected, "rejected")
		}
	})
}

func TestInitPartialExitPreservesCommittedResult(t *testing.T) {
	original := initWorkspace
	t.Cleanup(func() { initWorkspace = original })
	initWorkspace = func(context.Context, managed.InitOptions) (managed.InitResult, error) {
		return managed.InitResult{Workspace: "/workspace", ConfigCreated: true, RepositoriesInitialized: 1, DistsInitialized: 1}, errors.New("injected post-commit failure")
	}
	root := t.TempDir()

	t.Run("json", func(t *testing.T) {
		stdout, stderr, code := runCLI([]string{"init", root, "--json"})
		if code != ExitPartial || stderr == "" || !strings.Contains(stdout, `"class":"partial"`) || !strings.Contains(stdout, `"dists_initialized":1`) {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})

	t.Run("human", func(t *testing.T) {
		stdout, stderr, code := runCLI([]string{"init", root})
		if code != ExitPartial || stderr == "" || !strings.Contains(stdout, "dists_initialized=1") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
}

func TestMainWorkspaceFallbackAndRepositorySelection(t *testing.T) {
	root := t.TempDir()
	assertCLISuccess(t, []string{"init", root}, "initialized ")
	assertCLISuccess(t, []string{"repo", "new", "one", "-C", root}, "created one")
	assertCLISuccess(t, []string{"repo", "new", "two", "-C", root}, "created two")

	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "one", "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(nested); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})
	stdout, stderr, code := runCLI([]string{"dist", "ls", "--json"})
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"repository":"one"`) {
		t.Fatalf("cwd repository selection: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	if err := os.Chdir(previous); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_DIR", root)
	stdout, stderr, code = runCLI([]string{"repo", "ls", "--json"})
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"name":"one"`) || !strings.Contains(stdout, `"name":"two"`) {
		t.Fatalf("SOW_DIR fallback: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestMainHelpVersionAndClosedSurface(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"help"}, {"help", "dist", "new"}} {
		stdout, stderr, code := runCLI(args)
		if code != ExitOK || stderr != "" || !strings.Contains(stdout, "Usage:") {
			t.Fatalf("args=%q code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
	stdout, stderr, code := runCLI([]string{"version"})
	if code != ExitOK || stderr != "" || !strings.HasPrefix(stdout, "sow ") {
		t.Fatalf("version code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	assertCLISuccess(t, []string{"help", "add"}, "sow add PATH")
	assertCLIFailure(t, []string{"publish", "--json"}, ExitUsage, "usage")
}

func TestMainOutputFailureIsRuntime(t *testing.T) {
	var stderr bytes.Buffer
	code := Main([]string{"--help"}, failingWriter{err: errors.New("closed")}, &stderr)
	if code != ExitRuntime || !strings.Contains(stderr.String(), "closed") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func runCLI(args []string) (string, string, int) {
	var stdout, stderr bytes.Buffer
	code := Main(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func assertCLISuccess(t *testing.T, args []string, contains string) {
	t.Helper()
	stdout, stderr, code := runCLI(args)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, contains) {
		t.Fatalf("args=%q code=%d stdout=%q stderr=%q want output containing %q", args, code, stdout, stderr, contains)
	}
}

func assertCLIActualRepository(t *testing.T, args []string, want string) {
	t.Helper()
	stdout, stderr, code := runCLI(args)
	if code != ExitOK || stderr != "" {
		t.Fatalf("%v: code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
	}
	var envelope struct {
		Repository string `json:"repository"`
		Result     struct {
			Repository string `json:"repository"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Repository != want || envelope.Result.Repository != want {
		t.Fatalf("%v selected repository envelope=%q result=%q want=%q", args, envelope.Repository, envelope.Result.Repository, want)
	}
}

func assertCLIFailure(t *testing.T, args []string, code int, class string) {
	t.Helper()
	stdout, stderr, got := runCLI(args)
	if got != code || stderr == "" {
		t.Fatalf("args=%q code=%d want=%d stdout=%q stderr=%q", args, got, code, stdout, stderr)
	}
	if class != "" {
		if !strings.Contains(stdout, `"ok":false`) || !strings.Contains(stdout, `"code":`+strconv.Itoa(code)) || !strings.Contains(stdout, `"class":"`+class+`"`) {
			t.Fatalf("args=%q malformed failure envelope: %s", args, stdout)
		}
	}
}
