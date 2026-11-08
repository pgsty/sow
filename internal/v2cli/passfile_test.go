package v2cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/v2/plain"
)

func TestPassfileRejectsURIForm(t *testing.T) {
	_, err := Parse([]string{"--passfile", "file:///run/secrets/gpg", "build"})
	if ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), "not a URI") {
		t.Fatalf("passfile URI error=%v", err)
	}
}

func TestPassfileCommandScopeAndRecoveryEntrypoints(t *testing.T) {
	for _, args := range [][]string{
		{"create", "-S", "0123456789ABCDEF"}, {"init"}, {"config", "check"},
		{"repo", "new", "demo"}, {"repo", "rm", "demo"}, {"repo", "migrate"},
		{"dist", "new", "stable", "--format", "rpm"}, {"dist", "rm", "stable"},
		{"add", "example.rpm"}, {"add", "example.rpm", "--skip"},
		{"rm", "package"}, {"rm", "package", "--check"}, {"build"},
		{"publish", "target"}, {"gc"}, {"gc", "target"},
		{"log", "prune", "2026-01-01"}, {"export", "rpm-leaf", "stable", "x86_64", "out"},
	} {
		for _, input := range [][]string{append([]string{"--passfile", "path with spaces"}, args...), append(append([]string{}, args...), "--passfile=path with spaces")} {
			inv, err := Parse(input)
			if err != nil || inv.Global.PassFile != "path with spaces" {
				t.Fatalf("%v: %v", input, err)
			}
			if help, _ := HelpTopic(strings.Fields(invocationCommand(inv))...); !strings.Contains(help, "SOW_GPG_PASSFILE") {
				t.Fatalf("missing signing help: %s", invocationCommand(inv))
			}
		}
	}
	for _, args := range [][]string{
		{"create"}, {"prune", "dir"}, {"check"}, {"status"}, {"config", "show"},
		{"ls"}, {"log"}, {"changes"}, {"retain", "add", "1"},
	} {
		if _, err := Parse(append(args, "--passfile", "password")); err == nil {
			t.Fatalf("unsupported passfile: %v", args)
		}
	}
	for _, args := range [][]string{
		{"build", "--passfile"}, {"build", "--passfile="}, {"build", "--passfile", "   "},
		{"build", "--passfile", "a\nb"}, {"build", "--passfile", "a", "--passfile", "b"},
		{"build", "--pass", "secret"}, {"build", "--pass-env", "SECRET"}, {"build", "--pass-file", "a"},
	} {
		if _, err := Parse(args); err == nil {
			t.Fatalf("invalid passfile options accepted: %v", args)
		}
	}
}

func TestPassfileCreateMappingAndFailureEnvelope(t *testing.T) {
	inv, err := Parse([]string{"create", "-S", "0123456789ABCDEF", "--passfile", "password"})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := ExecuteCreate(context.Background(), inv, &stdout, &stderr, func(_ context.Context, opts plain.Options) (plain.Result, error) {
		if opts.PassFile != "password" {
			t.Fatal("create dropped passfile")
		}
		return plain.Result{}, nil
	})
	if code != 0 {
		t.Fatalf("create: %d %s", code, stderr.String())
	}
	if command, jsonOutput := failureInvocationContext([]string{"--passfile", "--json", "build", "--bad"}); command != "build" || jsonOutput {
		t.Fatalf("passfile became output intent: %s %t", command, jsonOutput)
	}
	if command, jsonOutput := failureInvocationContext([]string{"--passfile", "build", "rm", "--json", "--bad"}); command != "rm" || !jsonOutput {
		t.Fatalf("passfile became command intent: %s %t", command, jsonOutput)
	}
}
