package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAssetRemoveProjectionIntentRecoversWithoutOriginalSelector(t *testing.T) {
	if os.Getenv("SOW_TEST_ASSET_REMOVE_PROJECTION_CRASH") == "1" {
		wanted := os.Getenv("SOW_TEST_ASSET_REMOVE_PROJECTION_PHASE")
		assetProjectionMutationHook = func(phase string) error {
			if phase == wanted {
				os.Exit(93)
			}
			return nil
		}
		view := os.Getenv("SOW_TEST_ASSET_REMOVE_PROJECTION_VIEW")
		if view == "" {
			view = "beta"
		}
		var stdout, stderr bytes.Buffer
		code := Main([]string{
			"rm", "remove.bin", "--config", os.Getenv("SOW_TEST_ASSET_REMOVE_PROJECTION_CONFIG"),
			"--repo", "asset", "--view", view, "--workers", "1", "--chunk-entries", "1",
		}, &stdout, &stderr)
		os.Exit(code)
	}

	for _, view := range []string{"beta", "latest"} {
		view := view
		t.Run(view, func(t *testing.T) {
			for _, phase := range []string{
				"after-fence-before-apply",
				"after-transaction-intent-before-commit",
				"after-canonical-commit-before-ref",
				"after-ref-before-materialize",
			} {
				phase := phase
				t.Run(phase, func(t *testing.T) {
					root, configPath := newAssetMaterializeHardeningFixture(t)
					input := addAssetMaterializeFixture(t, configPath, "remove.bin", "durable asset removal "+view+" "+phase+"\n", false)
					if view == "latest" {
						code, stdout, stderr := runAssetMaterializeHardeningCLI(t, "promote", "beta", "latest", "--config", configPath, "--repo", "asset")
						if code != ExitOK {
							t.Fatalf("promote asset latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
						}
						code, stdout, stderr = runAssetMaterializeHardeningCLI(t, "materialize", "latest", "--config", configPath, "--repo", "asset", "--workers", "1", "--chunk-entries", "1")
						if code != ExitOK {
							t.Fatalf("materialize asset latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
						}
					}
					poolObjects, err := filepath.Glob(filepath.Join(root, ".pool", "sha256", "*", strings.Repeat("?", 64)))
					if err != nil || len(poolObjects) != 1 {
						t.Fatalf("asset removal pool objects=%v err=%v", poolObjects, err)
					}
					treePath := filepath.Join(root, ".sow", "materialized", "beta", "asset", "remove.bin")
					if view == "latest" {
						treePath = filepath.Join(root, "asset", "remove.bin")
					}
					if _, err := os.Stat(treePath); err != nil {
						t.Fatal(err)
					}
					command := exec.Command(os.Args[0], "-test.run=^TestAssetRemoveProjectionIntentRecoversWithoutOriginalSelector$")
					command.Env = append(os.Environ(),
						"SOW_TEST_ASSET_REMOVE_PROJECTION_CRASH=1",
						"SOW_TEST_ASSET_REMOVE_PROJECTION_PHASE="+phase,
						"SOW_TEST_ASSET_REMOVE_PROJECTION_CONFIG="+configPath,
						"SOW_TEST_ASSET_REMOVE_PROJECTION_VIEW="+view,
					)
					output, err := command.CombinedOutput()
					var exitErr *exec.ExitError
					if !errors.As(err, &exitErr) || exitErr.ExitCode() != 93 {
						t.Fatalf("asset rm crash helper phase=%s err=%v output=%s", phase, err, output)
					}
					intent, exists, err := readAssetProjectionIntent(filepath.Join(root, ".sow"))
					if err != nil || !exists || intent.Operation != "rm" || intent.Repo != "asset" || intent.View != view {
						t.Fatalf("asset rm bridge phase=%s exists=%t intent=%+v err=%v", phase, exists, intent, err)
					}
					if err := os.Remove(input); err != nil {
						t.Fatal(err)
					}
					code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
						"rm", "--config", configPath, "--repo", "asset", "--view", view, "--recover", "--workers", "1", "--chunk-entries", "1",
					)
					if code != ExitOK || !strings.Contains(stdout, "recovered pending asset projection operation=rm repo=asset view="+view) {
						t.Fatalf("asset rm inputless recovery phase=%s code=%d stdout=%s stderr=%s", phase, code, stdout, stderr)
					}
					if entries := readAssetMaterializeView(t, root, view); len(entries) != 0 {
						t.Fatalf("asset rm recovery retained canonical entries phase=%s entries=%+v", phase, entries)
					}
					if _, err := os.Stat(treePath); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("asset rm recovery retained public tree path phase=%s err=%v", phase, err)
					}
					if _, err := os.Stat(poolObjects[0]); err != nil {
						t.Fatalf("asset rm recovery deleted CAS phase=%s err=%v", phase, err)
					}
					if _, exists, err := readAssetProjectionIntent(filepath.Join(root, ".sow")); err != nil || exists {
						t.Fatalf("asset rm recovery retained bridge phase=%s exists=%t err=%v", phase, exists, err)
					}
					if _, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
						t.Fatalf("asset rm recovery retained selected set phase=%s exists=%t err=%v", phase, exists, err)
					}
				})
			}
		})
	}
}

func TestAssetRemoveDropsMutableReachabilityButKeepsCAS(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "tool.bin")
	if err := os.WriteFile(input, []byte("preserved CAS bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := runAdd(context.Background(), []string{input, "--config", configPath, "--repo", "asset", "--dest", "tool.bin"}, &stdout, &stderr); err != nil {
		t.Fatalf("seed add: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	poolObjects, err := filepath.Glob(filepath.Join(root, ".pool", "sha256", "*", strings.Repeat("?", 64)))
	if err != nil || len(poolObjects) != 1 {
		t.Fatalf("pool objects=%v err=%v", poolObjects, err)
	}
	stdout.Reset()
	stderr.Reset()
	err = runRemove(context.Background(), []string{"tool.bin", "--config", configPath, "--repo", "asset", "--view", "beta"}, &stdout, &stderr)
	if err != nil || !strings.Contains(stdout.String(), "entries=1") {
		t.Fatalf("remove err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	materialized := filepath.Join(root, ".sow", "materialized", "beta", "asset", "tool.bin")
	if _, err := os.Stat(materialized); !os.IsNotExist(err) {
		t.Fatalf("removed path remains: %v", err)
	}
	if _, err := os.Stat(poolObjects[0]); err != nil {
		t.Fatalf("rm deleted CAS object: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	err = runRemove(context.Background(), []string{"tool.bin", "--config", configPath, "--repo", "asset", "--view", "beta"}, &stdout, &stderr)
	if err != nil || !strings.Contains(stdout.String(), "rm unchanged") {
		t.Fatalf("idempotent rm err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
}

func TestRemoveRejectsAppendOnlyStable(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := runRemove(context.Background(), []string{"anything", "--config", configPath, "--repo", "asset", "--view", "stable"}, &stdout, &stderr)
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("stable removal err=%v", err)
	}
}

func TestRemoveRejectsFlagLikeTailAfterInterspersedPositional(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := runRemove(context.Background(), []string{"--config", configPath, "tool.bin", "--view", "latest"}, &stdout, &stderr)
	if exitCode(err) != ExitUsage || !strings.Contains(err.Error(), "appears after a positional") || !strings.Contains(err.Error(), "--view") {
		t.Fatalf("interspersed rm flag tail was not rejected: err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
}

func TestRemoveDoubleDashAllowsLiteralFlagShapedSelector(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "tool.bin")
	if err := os.WriteFile(input, []byte("tool"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := runAdd(context.Background(), []string{input, "--config", configPath, "--repo", "asset", "--dest", "tool.bin"}, &stdout, &stderr); err != nil {
		t.Fatalf("seed add: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	err := runRemove(context.Background(), []string{"--config", configPath, "--repo", "asset", "--", "--view"}, &stdout, &stderr)
	if err != nil || !strings.Contains(stdout.String(), "rm unchanged") || !strings.Contains(stdout.String(), "selectors=1") {
		t.Fatalf("literal flag-shaped selector failed: err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
}
