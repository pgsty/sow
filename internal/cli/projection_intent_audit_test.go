package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/state"
)

func TestVerifyAndFSCKReportPendingProjectionBeforeCanonicalRecovery(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	input := filepath.Join(t.TempDir(), "pending.bin")
	if err := os.WriteFile(input, []byte("pending projection audit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := assetProjectionMutationHook
	assetProjectionMutationHook = func(phase string) error {
		if phase == "after-canonical-commit-before-ref" {
			return errors.New("leave canonical transaction behind projection fence")
		}
		return nil
	}
	t.Cleanup(func() { assetProjectionMutationHook = previous })
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
		"add", input, "--config", configPath, "--repo", "asset", "--dest", "pending.bin", "--workers", "1", "--chunk-entries", "1",
	)
	assetProjectionMutationHook = previous
	if code == ExitOK || !strings.Contains(stderr, "leave canonical transaction behind projection fence") {
		t.Fatalf("leave pending projection code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	pendingHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	viewRef, err := state.ViewRef("beta", "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	pendingRef, pendingRefExists, err := canonical.Ref(viewRef)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "verify", args: []string{"verify", "--layer", "L1", "--config", configPath, "--workers", "1"}, want: "ASSET_PROJECTION_RECOVERY_REQUIRED"},
		{name: "verify-recover", args: []string{"verify", "--layer", "L1", "--recover", "--config", configPath, "--workers", "1"}, want: "ASSET_PROJECTION_RECOVERY_REQUIRED"},
		{name: "fsck", args: []string{"fsck", "--config", configPath, "--workers", "1", "--limit", "0"}, want: "drift code=ASSET_PROJECTION_RECOVERY_REQUIRED"},
		{name: "fsck-recover", args: []string{"fsck", "--recover", "--config", configPath, "--workers", "1", "--limit", "0"}, want: "drift code=ASSET_PROJECTION_RECOVERY_REQUIRED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runAssetMaterializeHardeningCLI(t, test.args...)
			if code != ExitVerification || !strings.Contains(stdout, test.want) {
				t.Fatalf("projection audit code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			head, err := canonical.HeadHash()
			if err != nil || head != pendingHead {
				t.Fatalf("projection audit changed canonical HEAD before=%s after=%s err=%v", pendingHead, head, err)
			}
			ref, exists, err := canonical.Ref(viewRef)
			if err != nil || exists != pendingRefExists || ref != pendingRef {
				t.Fatalf("projection audit advanced ref before=%s/%t after=%s/%t err=%v", pendingRef, pendingRefExists, ref, exists, err)
			}
		})
	}
}

func TestVerifyAndFSCKReportPendingPackageProjectionBeforeCanonicalRecovery(t *testing.T) {
	root, configPath, packagePath, keyPath := preparePackageNoopDEB(t)
	previous := packageProjectionMutationHook
	packageProjectionMutationHook = func(phase string) error {
		if phase == "after-canonical-commit-before-ref" {
			return errors.New("leave package transaction behind projection fence")
		}
		return nil
	}
	t.Cleanup(func() { packageProjectionMutationHook = previous })
	var addOutput, addError bytes.Buffer
	err := runAdd(t.Context(), []string{
		packagePath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath,
		"--workers", "1", "--chunk-entries", "1",
	}, &addOutput, &addError)
	packageProjectionMutationHook = previous
	if err == nil || !strings.Contains(err.Error(), "leave package transaction behind projection fence") {
		t.Fatalf("leave pending package projection err=%v stdout=%s stderr=%s", err, addOutput.String(), addError.String())
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	pendingHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	viewRef, err := state.ViewRef("beta", "deb-test", "jammy", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	pendingRef, pendingRefExists, err := canonical.Ref(viewRef)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "verify", args: []string{"verify", "--layer", "L1", "--config", configPath, "--workers", "1"}, want: "PACKAGE_PROJECTION_RECOVERY_REQUIRED"},
		{name: "fsck", args: []string{"fsck", "--recover", "--config", configPath, "--workers", "1", "--limit", "0"}, want: "drift code=PACKAGE_PROJECTION_RECOVERY_REQUIRED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runAssetMaterializeHardeningCLI(t, test.args...)
			if code != ExitVerification || !strings.Contains(stdout, test.want) {
				t.Fatalf("package projection audit code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			head, err := canonical.HeadHash()
			if err != nil || head != pendingHead {
				t.Fatalf("package projection audit changed HEAD before=%s after=%s err=%v", pendingHead, head, err)
			}
			ref, exists, err := canonical.Ref(viewRef)
			if err != nil || exists != pendingRefExists || ref != pendingRef {
				t.Fatalf("package projection audit advanced ref before=%s/%t after=%s/%t err=%v", pendingRef, pendingRefExists, ref, exists, err)
			}
		})
	}
}
