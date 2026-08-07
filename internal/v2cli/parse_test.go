package v2cli

import (
	"runtime"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/state"
)

func TestParseCreateDefaultsAndOptionsAnywhere(t *testing.T) {
	inv, err := Parse([]string{"--json", "create", "fixtures", "--pigsty", "-j", "3", "-T=2s", "-S", "0xe7935d8db9bd8b20", "--overwrite"})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Command != "create" || len(inv.Positionals) != 1 || inv.Positionals[0] != "fixtures" || !inv.Pigsty || inv.Jobs != 3 || inv.Global.Timeout != 2*time.Second || !inv.Global.JSON || inv.SignWith != "E7935D8DB9BD8B20" || !inv.Overwrite {
		t.Fatalf("unexpected invocation: %+v", inv)
	}
	defaults, err := Parse([]string{"create"})
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Jobs != runtime.NumCPU() {
		t.Fatalf("jobs=%d want=%d", defaults.Jobs, runtime.NumCPU())
	}
}

func TestParseClosedGlobalMatrix(t *testing.T) {
	tests := [][]string{
		{"create", "-C", "workspace"},
		{"init", "-T", "1s"},
		{"repo", "ls", "-r", "one"},
		{"dist", "show", "x", "-T", "1s"},
		{"config", "check", "-N"},
	}
	for _, args := range tests {
		if _, err := Parse(args); err == nil {
			t.Errorf("Parse(%q) accepted disallowed global option", args)
		}
	}
}

func TestParseLocalMatrixAndCardinality(t *testing.T) {
	valid := [][]string{
		{"init"}, {"init", "dir"}, {"config", "show", "--all", "-d", "el9", "-d", "noble"},
		{"repo", "show"}, {"repo", "show", "pgsql", "-r", "pgsql"},
		{"repo", "migrate"}, {"repo", "migrate", "pgsql", "-j", "2", "-N"}, {"repo", "migrate", "pgsql", "--abort"},
		{"repo", "rm", "pgsql", "-f"}, {"dist", "new", "el9", "--format", "rpm", "-r", "pgsql"},
		{"dist", "rm", "noble", "--force", "-r", "pgsql", "-N"},
		{"add", "one.rpm", "two.deb", "--recursive", "--skip", "-d", "el9"},
		{"rm", "sha256:abc", "--check", "-d", "el9"}, {"rm", "pkg", "--skip", "-N"},
		{"ls", "-d", "el9", "-d", "noble"}, {"show", "pkg"}, {"where", "pkg"}, {"status"},
		{"build", "-j", "2", "-d", "el9", "-N"}, {"check", "-j", "2"}, {"changes"}, {"changes", "0"},
		{"publish", "prod", "-N"}, {"publish", "prod", "--abort"},
		{"retain", "add", "1", "-N"}, {"retain", "ls", "-r", "pgsql"}, {"retain", "rm", "18446744073709551615"}, {"gc", "-N"}, {"gc", "prod", "-N"},
		{"export", "rpm-leaf", "el9", "x86_64", "/tmp/leaf"}, {"export", "rpm-leaf", "el9", "aarch64", "/tmp/leaf", "--hardlink", "--json"},
		{"log"}, {"log", "123456789"}, {"log", "export", "-"}, {"log", "prune", "2026-08-01T00:00:00Z", "-N"},
	}
	for _, args := range valid {
		if _, err := Parse(args); err != nil {
			t.Errorf("Parse(%q): %v", args, err)
		}
	}
	invalid := [][]string{
		{"create", "a", "b"}, {"create", "-j", "0"}, {"create", "--all"},
		{"create", "--overwrite"}, {"create", "--sign-with", "short"},
		{"repo", "new"}, {"repo", "new", "one", "two"}, {"repo", "ls", "--force"},
		{"repo", "migrate", "one", "two"}, {"repo", "migrate", "--force"}, {"repo", "migrate", "--abort", "--abort"},
		{"dist", "new", "el9"}, {"dist", "new", "el9", "--format", "apk"},
		{"dist", "show"}, {"config", "check", "extra"},
		{"add"}, {"rm"}, {"rm", "pkg", "--check", "--skip"}, {"rm", "pkg", "--check", "-T", "1s"},
		{"show"}, {"where"}, {"changes", "1", "2"}, {"publish"}, {"publish", "a", "b"}, {"publish", "prod", "-r", "repo"}, {"publish", "prod", "--abort=true"}, {"check", "-T", "1s"},
		{"retain"}, {"retain", "add", "0"}, {"retain", "add", "-1"}, {"retain", "rm"}, {"retain", "ls", "1"}, {"gc", "prod", "extra"}, {"gc", "prod", "-r", "repo"}, {"gc", "-d", "el9"},
		{"export"}, {"export", "unknown"}, {"export", "rpm-leaf", "el9", "x86_64"}, {"export", "rpm-leaf", "el9", "x86_64", "/tmp/leaf", "--hardlink", "--hardlink"},
		{"export", "rpm-leaf", "EL9", "x86_64", "/tmp/leaf"}, {"export", "rpm-leaf", "el9", "noarch", "/tmp/leaf"},
		{"log", "one", "two"}, {"log", "operation-id"}, {"log", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}, {"log", "export", "a", "b"}, {"log", "export", "--json"}, {"log", "prune", "date", "-d", "el9"},
	}
	for _, args := range invalid {
		if _, err := Parse(args); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", args)
		}
	}
}

func TestParseLockOptions(t *testing.T) {
	if _, err := Parse([]string{"repo", "new", "one", "-N", "-T", "1ms"}); err == nil {
		t.Fatal("no-wait with non-zero timeout succeeded")
	}
	if _, err := Parse([]string{"repo", "new", "one", "-N", "-T", "0"}); err != nil {
		t.Fatalf("no-wait with zero timeout: %v", err)
	}
	for _, value := range []string{"-1s", "forever", "1d", "1us", "1µs", "1ns", "0s", ""} {
		args := []string{"create", "--timeout=" + value}
		if _, err := Parse(args); err == nil {
			t.Errorf("timeout %q succeeded", value)
		}
	}
	for _, value := range []string{"1ms", "1.5s", ".5m", "1h30m", "+2s"} {
		if _, err := Parse([]string{"create", "--timeout=" + value}); err != nil {
			t.Errorf("timeout %q failed: %v", value, err)
		}
	}
}

func TestParseHelpBypassesRequiredOperands(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"create", "--help"}, {"dist", "new", "--help"}, {"repo", "--help"}, {"retain", "add", "--help"}, {"gc", "--help"}} {
		inv, err := Parse(args)
		if err != nil {
			t.Errorf("Parse(%q): %v", args, err)
			continue
		}
		if !inv.Help {
			t.Errorf("Parse(%q) did not set help", args)
		}
	}
}

func TestParseRejectsUnknownAndDuplicateOptions(t *testing.T) {
	for _, args := range [][]string{
		{"create", "--recursive"}, {"create", "--json", "--json"},
		{"create", "-S", "E7935D8DB9BD8B20", "--sign-with", "E7935D8DB9BD8B20"}, {"create", "-S", "E7935D8DB9BD8B20", "--overwrite", "--overwrite"},
		{"repo", "show", "-r", "one", "--repo", "two"},
		{"dist", "new", "x", "--format", "rpm", "--format", "deb"},
	} {
		if _, err := Parse(args); err == nil {
			t.Errorf("Parse(%q) succeeded", args)
		}
	}
}

func TestParseRepoShowPreservesNameAndExplicitRepository(t *testing.T) {
	inv, err := Parse([]string{"repo", "show", "pgsql", "-r", "infra"})
	if err != nil {
		t.Fatalf("mismatched repo selectors must reach pre-state semantic validation: %v", err)
	}
	if inv.Global.Repo != "infra" || len(inv.Positionals) != 1 || inv.Positionals[0] != "pgsql" {
		t.Fatalf("selectors were not preserved independently: %#v", inv)
	}
	if _, err := Parse([]string{"repo", "show", "pgsql", "-r", "pgsql"}); err != nil {
		t.Fatalf("matching repo selectors: %v", err)
	}
}

func TestParseHelpAndVersionRejectCommandOptions(t *testing.T) {
	for _, args := range [][]string{
		{"help", "--json"}, {"version", "--json"}, {"--help", "-C", "."},
		{"repo", "--help", "-r", "pgsql"}, {"create", "--version"},
	} {
		if _, err := Parse(args); err == nil {
			t.Errorf("Parse(%q) accepted options outside the closed help/version surface", args)
		}
	}
	for _, args := range [][]string{{"--help"}, {"--version"}, {"help", "create"}, {"version"}} {
		if _, err := Parse(args); err != nil {
			t.Errorf("Parse(%q): %v", args, err)
		}
	}
}

func TestParseScalarBoundariesAndPruneCutoff(t *testing.T) {
	for input, want := range map[string]int64{"0": 0, "0007": 7, "9223372036854775807": 9223372036854775807} {
		got, err := parseNonnegativeInt64(input, "generation")
		if err != nil || got != want {
			t.Fatalf("parseNonnegativeInt64(%q)=%d err=%v want=%d", input, got, err, want)
		}
	}
	for _, input := range []string{"", "+1", "-1", "1.0", " 1", "9223372036854775808"} {
		if _, err := parseNonnegativeInt64(input, "generation"); err == nil {
			t.Fatalf("parseNonnegativeInt64(%q) succeeded", input)
		}
	}
	for input, want := range map[string]state.GenerationID{
		"0":                    0,
		"0007":                 7,
		"9223372036854775808":  state.GenerationID(1 << 63),
		"18446744073709551615": state.MaxGeneration,
	} {
		got, err := parseGenerationIDArgument(input)
		if err != nil || got != want {
			t.Fatalf("parseGenerationIDArgument(%q)=%s err=%v want=%s", input, got, err, want)
		}
	}
	for _, input := range []string{"", "+1", "-1", "1.0", " 1", "18446744073709551616"} {
		if _, err := parseGenerationIDArgument(input); err == nil {
			t.Fatalf("parseGenerationIDArgument(%q) succeeded", input)
		}
	}
	location := time.FixedZone("acceptance", 8*60*60)
	date, err := parseBefore("2026-08-02", location)
	if err != nil || !date.Equal(time.Date(2026, 8, 2, 0, 0, 0, 0, location)) || date.Location() != location {
		t.Fatalf("date cutoff=%v location=%v err=%v", date, date.Location(), err)
	}
	rfc, err := parseBefore("2026-08-02T03:04:05.123456789+09:30", location)
	if err != nil || !rfc.Equal(time.Date(2026, 8, 1, 17, 34, 5, 123456789, time.UTC)) {
		t.Fatalf("RFC3339 cutoff=%v err=%v", rfc, err)
	}
	for _, input := range []string{"2026-02-30", "2026-08-02T03:04:05", "yesterday", ""} {
		if _, err := parseBefore(input, location); err == nil {
			t.Fatalf("parseBefore(%q) succeeded", input)
		}
	}
}

func TestFailureInvocationContextDoesNotReinterpretOptionValues(t *testing.T) {
	tests := []struct {
		args       []string
		command    string
		jsonOutput bool
	}{
		{args: []string{"--workdir", "build", "repo", "new", "name", "--json"}, command: "repo new", jsonOutput: true},
		{args: []string{"--repo", "--json", "build", "--unknown"}, command: "build", jsonOutput: false},
		{args: []string{"-C=build", "config", "show", "--json=false"}, command: "config show", jsonOutput: false},
		{args: []string{"-d", "log", "log", "prune", "bad", "--json"}, command: "log prune", jsonOutput: true},
		{args: []string{"--", "build", "--json"}, command: "unknown", jsonOutput: false},
	}
	for _, test := range tests {
		command, jsonOutput := failureInvocationContext(test.args)
		if command != test.command || jsonOutput != test.jsonOutput {
			t.Fatalf("failureInvocationContext(%v)=(%q,%t) want=(%q,%t)", test.args, command, jsonOutput, test.command, test.jsonOutput)
		}
	}
}
