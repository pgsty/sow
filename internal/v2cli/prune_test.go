package v2cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/plain"
)

func TestParsePruneDefaultsAndOptions(t *testing.T) {
	inv, err := Parse([]string{"prune", "packages"})
	if err != nil || inv.Command != "prune" || inv.DryRun || len(inv.Protect) != 0 || !reflect.DeepEqual(inv.Positionals, []string{"packages"}) {
		t.Fatalf("default prune=%+v err=%v", inv, err)
	}
	inv, err = Parse([]string{"--json", "prune", "--dry-run", "--protect", "age_18", "packages", "--protect=age_18-llvmjit", "-j", "2", "-T", "1s"})
	if err != nil || !inv.DryRun || !inv.Global.JSON || inv.Jobs != 2 || inv.Global.Timeout != time.Second || !reflect.DeepEqual(inv.Protect, []string{"age_18", "age_18-llvmjit"}) {
		t.Fatalf("prune options=%+v err=%v", inv, err)
	}
	for _, args := range [][]string{
		{"prune"}, {"prune", "a", "b"},
		{"prune", "packages", "--dry-run=true"}, {"prune", "packages", "--dry-run", "--dry-run"},
		{"prune", "packages", "--protect"}, {"prune", "packages", "--protect="},
		{"prune", "packages", "--protect", "age_*"}, {"prune", "packages", "--protect", "path/name"},
		{"prune", "packages", "--apply"}, {"prune", "packages", "--keep", "2"},
		{"prune", "packages", "--pigsty"}, {"prune", "packages", "--recursive"},
		{"prune", "packages", "-C", "workspace"}, {"prune", "packages", "-r", "repo"},
		{"prune", "packages", "-d", "el9"}, {"prune", "packages", "-j", "0"},
		{"prune", "packages", "-N", "-T", "1s"},
		{"create", "packages", "--dry-run"}, {"create", "packages", "--protect", "pkg"},
	} {
		if _, err := Parse(args); ExitCode(err) != ExitUsage {
			t.Errorf("Parse(%q) error=%v", args, err)
		}
	}
}

func TestMainPrunePreviewThenDefaultExecution(t *testing.T) {
	dir := t.TempDir()
	path := decodeCLIFixture(t, filepath.Join("..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(dir, "package.rpm"))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, dry := range []bool{true, false} {
		args := []string{"prune", dir, "--json", "--protect", "pgdg-redhat-nonfree-repo"}
		if dry {
			args = append(args, "--dry-run")
		}
		stdout, stderr, code := runCLI(args)
		var envelope struct {
			Schema  string            `json:"schema"`
			Command string            `json:"command"`
			OK      bool              `json:"ok"`
			Result  plain.PruneResult `json:"result"`
			Errors  []CLIError        `json:"errors"`
		}
		if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
			t.Fatalf("invalid JSON: %v stdout=%s stderr=%s", err, stdout, stderr)
		}
		if code != ExitOK || stderr != "" || envelope.Schema != OutputSchema || envelope.Command != "prune" || !envelope.OK || len(envelope.Errors) != 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		result := envelope.Result
		if result.DryRun != dry || result.IndexUpdated == dry || len(result.Kept) != 1 || len(result.Candidates) != 0 || len(result.Removed) != 0 {
			t.Fatalf("result=%+v", result)
		}
		_, indexErr := os.Stat(filepath.Join(dir, "repodata", "repomd.xml"))
		if dry && !errors.Is(indexErr, os.ErrNotExist) || !dry && indexErr != nil {
			t.Fatalf("dry=%t index=%v", dry, indexErr)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("retained RPM changed: %v", err)
	}
	stdout, stderr, code := runCLI([]string{"prune", dir})
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, "pruned ") || !strings.Contains(stdout, "noop=true") {
		t.Fatalf("repeat prune: code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, name := range []string{".sow", "sow.yml", "repo_complete"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("prune unexpectedly created %s: %v", name, err)
		}
	}
}

func TestMainPruneFailureJSONAndCancellation(t *testing.T) {
	for _, tt := range []struct {
		args []string
		code int
	}{
		{[]string{"prune", "--json"}, ExitUsage},
		{[]string{"prune", t.TempDir(), "--json"}, ExitRejected},
	} {
		stdout, stderr, code := runCLI(tt.args)
		var envelope Envelope
		if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
			t.Fatal(err)
		}
		if code != tt.code || envelope.Command != "prune" || envelope.OK || len(envelope.Errors) != 1 || envelope.Errors[0].Code != tt.code || stderr == "" {
			t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if code := MainContext(ctx, []string{"prune", t.TempDir(), "--json"}, &stdout, &stderr); code != ExitInterrupted {
		t.Fatalf("cancelled prune: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}
