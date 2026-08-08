package compat_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestShippedExampleSupportsCleanRoomLocalMVP builds the production binary and
// exercises the public V2 P0-P3 surface in an isolated local filesystem.
// It deliberately supplies no provider credentials, signing material, remote
// endpoint, or network opt-in: P0-P3 are pure local operations.
func TestShippedExampleSupportsCleanRoomLocalMVP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	moduleRoot := findModuleRoot(t)
	work := hostableCompatTempDir(t)
	environment := cleanRoomV2Environment(t, work)
	cliPath := buildCleanRoomV2CLI(ctx, t, moduleRoot, work, environment)

	// P0: one mixed flat directory is sufficient to prove that the shipped
	// binary reaches both native renderers without discovering a Workspace.
	plainRoot := filepath.Join(work, "plain")
	if err := os.MkdirAll(plainRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	decodeBase64Fixture(t,
		filepath.Join(moduleRoot, "internal", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"),
		filepath.Join(plainRoot, "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm"),
	)
	decodeBase64Fixture(t,
		filepath.Join(moduleRoot, "internal", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"),
		filepath.Join(plainRoot, "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb"),
	)
	plainOutput := runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment,
		"create", plainRoot, "--json")
	assertCleanRoomV2JSONSuccess(t, plainOutput, "create")
	for _, path := range []string{
		filepath.Join(plainRoot, "repodata", "repomd.xml"),
		filepath.Join(plainRoot, "Packages"),
		filepath.Join(plainRoot, "Packages.gz"),
	} {
		assertCleanRoomV2RegularFile(t, path, true)
	}
	packages, err := os.ReadFile(filepath.Join(plainRoot, "Packages"))
	if err != nil {
		t.Fatal(err)
	}
	filename := "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb"
	if !strings.Contains(string(packages), "Filename: "+filename+"\n") &&
		!strings.Contains(string(packages), "Filename: ./"+filename+"\n") {
		t.Fatalf("plain Packages does not use basename or ./basename:\n%s", packages)
	}
	for _, forbidden := range []string{"sow.yml", ".sow", "repo_complete"} {
		if _, err := os.Lstat(filepath.Join(plainRoot, forbidden)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("plain create produced managed or Pigsty-only path %q: %v", forbidden, err)
		}
	}

	// P1: initialize the default V2 Workspace, then create one Repository and
	// one empty Dist of each supported format through the production CLI.
	workspace := filepath.Join(work, "workspace")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	initOutput := runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment,
		"init", workspace, "--json")
	assertCleanRoomV2JSONSuccess(t, initOutput, "init")
	configPath := filepath.Join(workspace, "sow.yml")
	initialConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"schema: sow/v3", "- x86_64", "- aarch64"} {
		if !strings.Contains(string(initialConfig), want) {
			t.Fatalf("default V2 config omitted %q:\n%s", want, initialConfig)
		}
	}
	assertCleanRoomV2Directory(t, filepath.Join(workspace, ".sow"))

	// The default initialization is idempotent and must not reset or rewrite a
	// valid configuration.
	secondInit := runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment,
		"init", workspace, "--json")
	assertCleanRoomV2JSONSuccess(t, secondInit, "init")
	afterInit, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterInit) != string(initialConfig) {
		t.Fatal("idempotent V2 init rewrote sow.yml")
	}

	repoOutput := runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment,
		"repo", "new", "pgsql", "-C", workspace, "--json")
	assertCleanRoomV2JSONSuccess(t, repoOutput, "repo new")
	rpmOutput := runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment,
		"dist", "new", "el9", "--format", "rpm", "-C", workspace, "-r", "pgsql", "--json")
	assertCleanRoomV2JSONSuccess(t, rpmOutput, "dist new")
	debOutput := runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment,
		"dist", "new", "noble", "--format", "deb", "-C", workspace, "-r", "pgsql", "--json")
	assertCleanRoomV2JSONSuccess(t, debOutput, "dist new")

	for _, path := range []string{
		filepath.Join(workspace, ".sow", "pgsql.db"),
		filepath.Join(workspace, "pgsql", "dists", "el9", "x86_64", "repodata", "repomd.xml"),
		filepath.Join(workspace, "pgsql", "dists", "el9", "aarch64", "repodata", "repomd.xml"),
		filepath.Join(workspace, "pgsql", "dists", "noble", "main", "binary-amd64", "Packages.gz"),
		filepath.Join(workspace, "pgsql", "dists", "noble", "main", "binary-arm64", "Packages.gz"),
		filepath.Join(workspace, "pgsql", "dists", "noble", "Release"),
	} {
		assertCleanRoomV2RegularFile(t, path, true)
	}
	for _, path := range []string{
		filepath.Join(workspace, ".sow", "repo-locks", "pgsql.lock"),
		filepath.Join(workspace, "pgsql", "dists", "noble", "main", "binary-amd64", "Packages"),
		filepath.Join(workspace, "pgsql", "dists", "noble", "main", "binary-arm64", "Packages"),
	} {
		assertCleanRoomV2RegularFile(t, path, false)
	}
	for _, path := range []string{
		filepath.Join(workspace, "pgsql", "pool"),
		filepath.Join(workspace, "pgsql", "dists"),
		filepath.Join(workspace, ".sow", "pgsql", "stage"),
		filepath.Join(workspace, ".sow", "pgsql", "recovery"),
	} {
		assertCleanRoomV2Directory(t, path)
	}

	// P2/P3: add one package of each format through the default build path,
	// then exercise the closed query, status, verification, changes and audit
	// surface against the resulting Built Generation.
	for _, mutation := range []struct {
		want string
		path string
		dist string
	}{
		{want: "add", path: filepath.Join(plainRoot, "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm"), dist: "el9"},
		{want: "add", path: filepath.Join(plainRoot, "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb"), dist: "noble"},
	} {
		output := runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment,
			"add", mutation.path, "-C", workspace, "-r", "pgsql", "-d", mutation.dist, "--json")
		assertCleanRoomV2JSONSuccess(t, output, mutation.want)
	}
	for _, command := range []struct {
		want string
		args []string
	}{
		{want: "ls", args: []string{"ls", "-C", workspace, "-r", "pgsql", "-d", "el9", "--json"}},
		{want: "show", args: []string{"show", "pgdg-redhat-nonfree-repo", "-C", workspace, "-r", "pgsql", "-d", "el9", "--json"}},
		{want: "where", args: []string{"where", "libpqtypes0", "-C", workspace, "--json"}},
		{want: "status", args: []string{"status", "-C", workspace, "-r", "pgsql", "--json"}},
		{want: "build", args: []string{"build", "-C", workspace, "-r", "pgsql", "--json"}},
		{want: "check", args: []string{"check", "-C", workspace, "-r", "pgsql", "--json"}},
		{want: "changes", args: []string{"changes", "0", "-C", workspace, "-r", "pgsql", "--json"}},
		{want: "log", args: []string{"log", "-C", workspace, "-r", "pgsql", "--json"}},
	} {
		output := runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment, command.args...)
		assertCleanRoomV2JSONSuccess(t, output, command.want)
	}

	for _, command := range []struct {
		want string
		args []string
	}{
		{want: "config check", args: []string{"config", "check", "-C", workspace, "--json"}},
		{want: "repo ls", args: []string{"repo", "ls", "-C", workspace, "--json"}},
		{want: "repo show", args: []string{"repo", "show", "pgsql", "-C", workspace, "--json"}},
		{want: "dist ls", args: []string{"dist", "ls", "-C", workspace, "-r", "pgsql", "--json"}},
		{want: "dist show", args: []string{"dist", "show", "el9", "-C", workspace, "-r", "pgsql", "--json"}},
	} {
		output := runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment, command.args...)
		assertCleanRoomV2JSONSuccess(t, output, command.want)
	}
	shown := runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment,
		"config", "show", "--all", "-C", workspace)
	for _, want := range []string{"schema: sow/v3", "pgsql:", "el9:", "format: rpm", "noble:", "format: deb"} {
		if !strings.Contains(shown, want) {
			t.Fatalf("config show --all omitted %q:\n%s", want, shown)
		}
	}

	// Root help is the closed v0.3 command surface. Retired V1 commands are not
	// merely undocumented: the binary must reject them as usage errors.
	help := runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment, "help")
	assertCleanRoomV2RootCommands(t, help)
	for _, args := range [][]string{
		{"sync"},
		{"snapshot"},
		{"serve"},
	} {
		output, code := runCleanRoomV2(ctx, t, moduleRoot, cliPath, environment, args...)
		if code != 2 || !strings.Contains(output, "usage") {
			t.Fatalf("inactive command %q: exit=%d output=%q, want usage exit 2", strings.Join(args, " "), code, output)
		}
	}
	version := runCleanRoomV2OK(ctx, t, moduleRoot, cliPath, environment, "version")
	if !strings.HasPrefix(version, "sow 0.2.0 ") {
		t.Fatalf("unexpected V2 version output: %q", version)
	}
}

func cleanRoomV2Environment(t *testing.T, work string) []string {
	t.Helper()
	directories := map[string]string{
		"HOME":    filepath.Join(work, "home"),
		"GOPATH":  filepath.Join(work, "gopath"),
		"GOCACHE": filepath.Join(work, "gocache"),
		"TMPDIR":  filepath.Join(work, "tmp"),
	}
	for _, path := range directories {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatalf("create clean-room directory %s: %v", path, err)
		}
	}
	moduleCache := strings.TrimSpace(os.Getenv("GOMODCACHE"))
	if moduleCache == "" {
		parentHome, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		moduleCache = filepath.Join(parentHome, "go", "pkg", "mod")
	}
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + directories["HOME"],
		"GOPATH=" + directories["GOPATH"],
		"GOMODCACHE=" + moduleCache,
		"GOCACHE=" + directories["GOCACHE"],
		"TMPDIR=" + directories["TMPDIR"],
		"GOENV=off",
		"GOWORK=off",
		"GOTOOLCHAIN=local",
		"GOFLAGS=-mod=readonly",
		"CGO_ENABLED=0",
		"LANG=C",
		"LC_ALL=C",
		"SOW_DIR=",
		"AWS_CONFIG_FILE=/dev/null",
		"AWS_SHARED_CREDENTIALS_FILE=/dev/null",
		"AWS_EC2_METADATA_DISABLED=true",
	}
}

func buildCleanRoomV2CLI(ctx context.Context, t *testing.T, moduleRoot, work string, environment []string) string {
	t.Helper()
	output := filepath.Join(work, "sow")
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", output, "./cmd/sow")
	command.Dir = moduleRoot
	command.Env = environment
	combined, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build V2 production CLI in clean room: %v\n%s", err, combined)
	}
	return output
}

func runCleanRoomV2OK(
	ctx context.Context,
	t *testing.T,
	moduleRoot string,
	executable string,
	environment []string,
	arguments ...string,
) string {
	t.Helper()
	output, code := runCleanRoomV2(ctx, t, moduleRoot, executable, environment, arguments...)
	if code != 0 {
		t.Fatalf("sow %s: exit=%d\n%s", strings.Join(arguments, " "), code, output)
	}
	return output
}

func runCleanRoomV2(
	ctx context.Context,
	t *testing.T,
	moduleRoot string,
	executable string,
	environment []string,
	arguments ...string,
) (string, int) {
	t.Helper()
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir = moduleRoot
	command.Env = environment
	started := time.Now()
	output, err := command.CombinedOutput()
	code := 0
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			t.Fatalf("start sow %s: %v\n%s", strings.Join(arguments, " "), err, output)
		}
		code = exitError.ExitCode()
	}
	t.Logf("sow %s exit=%d elapsed=%s\n%s", strings.Join(arguments, " "), code, time.Since(started), output)
	return string(output), code
}

func assertCleanRoomV2JSONSuccess(t *testing.T, output, command string) {
	t.Helper()
	var envelope struct {
		Schema  string `json:"schema"`
		Command string `json:"command"`
		OK      bool   `json:"ok"`
		Errors  []any  `json:"errors"`
	}
	if err := json.Unmarshal([]byte(output), &envelope); err != nil {
		t.Fatalf("decode %s JSON: %v\n%s", command, err, output)
	}
	if envelope.Schema != "sow.cli/v1" || envelope.Command != command || !envelope.OK || len(envelope.Errors) != 0 {
		t.Fatalf("unexpected %s envelope: %#v", command, envelope)
	}
}

func assertCleanRoomV2RootCommands(t *testing.T, output string) {
	t.Helper()
	commandSet := make(map[string]struct{}, 18)
	inCommands := false
	for _, line := range strings.Split(output, "\n") {
		if line == "Commands:" {
			inCommands = true
			continue
		}
		if !inCommands {
			continue
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		fields := strings.Fields(line)
		if len(fields) != 0 {
			commandSet[fields[0]] = struct{}{}
		}
	}
	commands := make([]string, 0, len(commandSet))
	for command := range commandSet {
		commands = append(commands, command)
	}
	sort.Strings(commands)
	want := []string{"add", "build", "changes", "check", "config", "create", "dist", "export", "gc", "help", "init", "log", "ls", "publish", "repo", "retain", "rm", "show", "status", "version", "where"}
	if fmt.Sprint(commands) != fmt.Sprint(want) {
		t.Fatalf("root help command surface=%v want=%v\n%s", commands, want, output)
	}
}

func assertCleanRoomV2RegularFile(t *testing.T, path string, nonEmpty bool) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (nonEmpty && info.Size() == 0) {
		t.Fatalf("required regular file %s is absent, unsafe, or empty: info=%v err=%v", path, info, err)
	}
}

func assertCleanRoomV2Directory(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("required directory %s is absent or unsafe: info=%v err=%v", path, info, err)
	}
}
