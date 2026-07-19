package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestVerifyAndFSCKAuditLocalStrongServingClosure(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		_, configPath, _, keyPath, _ := setupServingYUMView(t)
		materialize := []string{"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
		if code, stdout, stderr := runServingCLI(t, materialize...); code != ExitOK {
			t.Fatalf("materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if code, stdout, stderr := runServingCLI(t, "verify", "--layer", "L1", "--view", "latest", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("verify healthy code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if code, stdout, stderr := runServingCLI(t, "fsck", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitOK || !strings.Contains(stdout, "fsck serving_checks=") {
			t.Fatalf("fsck healthy code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})

	t.Run("mirrorlist", func(t *testing.T) {
		root, configPath, _, keyPath, _ := setupServingYUMView(t)
		if code, stdout, stderr := runServingCLI(t, "materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		mirror := filepath.Join(root, "_sow", "v1", "mirrorlist", "latest", "rpm-test", "el10", "x86_64.txt")
		if err := os.Chmod(mirror, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(mirror, []byte("https://foreign.example.invalid/\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if code, stdout, stderr := runServingCLI(t, "verify", "--layer", "L1", "--view", "latest", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitVerification || !strings.Contains(stdout, "LOCAL_YUM_POINTER_DRIFT") {
			t.Fatalf("verify mirrorlist code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if code, stdout, stderr := runServingCLI(t, "fsck", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitVerification || !strings.Contains(stdout, "LOCAL_YUM_POINTER_DRIFT") {
			t.Fatalf("fsck mirrorlist code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})

	t.Run("retained-generation", func(t *testing.T) {
		root, configPath, rpmPath, keyPath, _ := setupServingYUMView(t)
		materialize := []string{"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
		if code, stdout, stderr := runServingCLI(t, materialize...); code != ExitOK {
			t.Fatalf("first materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		mirror := "_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt"
		firstGeneration := mirrorGenerationID(t, root, mirror)
		info, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: rpmPath})
		if err != nil {
			t.Fatal(err)
		}
		if code, stdout, stderr := runServingCLI(t, "rm", "--view", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, info.Name); code != ExitOK {
			t.Fatalf("rm code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if code, stdout, stderr := runServingCLI(t, materialize...); code != ExitOK {
			t.Fatalf("second materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if firstGeneration == mirrorGenerationID(t, root, mirror) {
			t.Fatal("serving generation did not advance")
		}
		retainedMetadata := filepath.Join(root, "_sow", "v1", "g", firstGeneration, "yum", "test", "x86_64", "repodata", "repomd.xml")
		if err := os.Remove(retainedMetadata); err != nil {
			t.Fatal(err)
		}
		if code, stdout, stderr := runServingCLI(t, "verify", "--layer", "L1", "--view", "latest", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitVerification || !strings.Contains(stdout, "LOCAL_YUM_GENERATION_DRIFT") {
			t.Fatalf("verify retained generation code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if code, stdout, stderr := runServingCLI(t, "fsck", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitVerification || !strings.Contains(stdout, "LOCAL_YUM_GENERATION_DRIFT") {
			t.Fatalf("fsck retained generation code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})

	t.Run("missing-canonical-channel", func(t *testing.T) {
		root, configPath, _, keyPath, _ := setupServingYUMView(t)
		if code, stdout, stderr := runServingCLI(t, "materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		target, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
		if err != nil {
			t.Fatal(err)
		}
		channelPath := serving.ChannelStatePath(serving.Channel{TargetID: target.ID, View: "latest", Repo: "rpm-test", OS: "el10", Arch: "x86_64"})
		canonical := state.New(filepath.Join(root, ".sow"))
		if _, changed, err := canonical.Apply(t.Context(), "test-delete-serving-channel", "test: delete serving channel", nil, nil, state.ApplyOptions{DeletePaths: []string{channelPath}}); err != nil || !changed {
			t.Fatalf("delete channel changed=%t err=%v", changed, err)
		}
		if code, stdout, stderr := runServingCLI(t, "verify", "--layer", "L1", "--view", "latest", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitVerification || !strings.Contains(stdout, "LOCAL_YUM_CHANNEL_MISSING") {
			t.Fatalf("verify missing channel code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if code, stdout, stderr := runServingCLI(t, "fsck", "--config", configPath, "--workers", "2", "--chunk-entries", "2"); code != ExitVerification || !strings.Contains(stdout, "LOCAL_YUM_CHANNEL_MISSING") {
			t.Fatalf("fsck missing channel code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})

	t.Run("desired-ref-advanced", func(t *testing.T) {
		_, configPath, rpmPath, keyPath, _ := setupServingYUMView(t)
		if code, stdout, stderr := runServingCLI(t, "materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		info, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: rpmPath})
		if err != nil {
			t.Fatal(err)
		}
		if code, stdout, stderr := runServingCLI(t, "rm", "--view", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, info.Name); code != ExitOK {
			t.Fatalf("rm code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if code, stdout, stderr := runServingCLI(t, "verify", "--layer", "L1", "--view", "latest", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitVerification || !strings.Contains(stdout, "LOCAL_YUM_DESIRED_DRIFT") {
			t.Fatalf("verify stale desired state code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if code, stdout, stderr := runServingCLI(t, "fsck", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitVerification || !strings.Contains(stdout, "LOCAL_YUM_DESIRED_DRIFT") {
			t.Fatalf("fsck stale desired state code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})

	t.Run("channel-outside-configured-topology", func(t *testing.T) {
		_, configPath, _, keyPath, _ := setupServingYUMView(t)
		if code, stdout, stderr := runServingCLI(t, "materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		body, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		updated := strings.Replace(string(body), "upstreams: []", "  - id: assets\n    type: asset\n    path: bin\n    default_pool: public\n    asset: {kind: bin}\nupstreams: []", 1)
		updated = strings.Replace(updated, "latest: {access: public, allowed_pools: [public], append_only: false}", "latest: {access: public, allowed_pools: [public], append_only: false, repos: [assets]}", 1)
		if updated == string(body) {
			t.Fatal("fixture topology was not replaced")
		}
		if err := os.WriteFile(configPath, []byte(updated), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, stdout, stderr := runServingCLI(t, "verify", "--layer", "L1", "--view", "latest", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitVerification || !strings.Contains(stdout, "LOCAL_YUM_TOPOLOGY_DRIFT") {
			t.Fatalf("verify stale topology code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})

	for _, phase := range []localServingPhase{localServingInstallIntent, localServingGenerationReady} {
		t.Run("incomplete-transaction-"+string(phase), func(t *testing.T) {
			configPath := interruptLocalServingForAudit(t, phase)
			if code, stdout, stderr := runServingCLI(t, "verify", "--layer", "L1", "--view", "latest", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitConflict || !strings.Contains(stderr, "incomplete local serving transaction") || strings.Contains(stdout, "outcome=passed") {
				t.Fatalf("verify incomplete %s code=%d stdout=%s stderr=%s", phase, code, stdout, stderr)
			}
			if code, stdout, stderr := runServingCLI(t, "fsck", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitConflict || !strings.Contains(stderr, "incomplete local serving transaction") || strings.Contains(stdout, "fsck clean") {
				t.Fatalf("fsck incomplete %s code=%d stdout=%s stderr=%s", phase, code, stdout, stderr)
			}
		})
	}
}

func interruptLocalServingForAudit(t *testing.T, phase localServingPhase) string {
	t.Helper()
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	cfg, repos, err := loadAndSelect(commonFlags{configPath: configPath, workers: 2, chunk: 2})
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, passphrase, keySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, selectedLeaves(repos, commonFlags{}), keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	txDir, err := newTransactionDir(cfg.StatePath(), "serving-audit-fault-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(txDir) })
	leaf := selectedLeaves(repos, commonFlags{})[0]
	if _, err := materializeYUMLeaf(t.Context(), cfg, canonical, pool, leaf.repo, leaf, "latest", txDir, commonFlags{workers: 2, chunk: 2}, privateKey, passphrase); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected audit boundary")
	_, err = activateLocalYUMServing(t.Context(), cfg, canonical, pool, materializeCanonicalSource{ID: "latest", Public: true}, root,
		"https://repo.example.invalid", keySHA, txDir, []localYUMServingLeaf{{repo: leaf.repo, os: leaf.os, arch: leaf.arch}},
		commonFlags{workers: 2, chunk: 2}, localServingActivationOptions{AfterPhase: func(current localServingPhase) error {
			if current == phase {
				return injected
			}
			return nil
		}}, io.Discard)
	if !errors.Is(err, injected) {
		t.Fatalf("interrupt phase=%s err=%v", phase, err)
	}
	return configPath
}
