package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyAndFSCKInventoryAndRetirePreservedProjectionAudits(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	stateRoot := filepath.Join(root, ".sow")
	assetName := assetProjectionStagePrefix + strings.Repeat("a", 32) + ".tsv.preserved-" + strings.Repeat("b", 32)
	packageName := packageProjectionStagePrefix + strings.Repeat("c", 32) + "-000.tsv.preserved-" + strings.Repeat("d", 32)
	assetPath := filepath.Join(stateRoot, assetName)
	packagePath := filepath.Join(stateRoot, packageName)
	if err := os.WriteFile(assetPath, []byte("preserved asset audit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packagePath, []byte("preserved package audit\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
		"verify", "--layer", "L1", "--config", configPath, "--workers", "1",
	)
	if code != ExitVerification ||
		strings.Count(stdout, "PRESERVED_PROJECTION_AUDIT_QUARANTINE") != 2 ||
		!strings.Contains(stdout, "retire_token") {
		t.Fatalf("verify inventory code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"fsck", "--recover", "--config", configPath, "--workers", "1", "--limit", "0",
	)
	if code != ExitVerification ||
		strings.Count(stdout, "code=PRESERVED_PROJECTION_AUDIT_QUARANTINE") != 2 {
		t.Fatalf("fsck inventory code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	assetToken := preservedProjectionTokenFromOutput(t, stdout, assetName)
	packageToken := preservedProjectionTokenFromOutput(t, stdout, packageName)
	for _, path := range []string{assetPath, packagePath} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("fsck --recover implicitly removed audit quarantine %s: %v", path, err)
		}
	}

	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"fsck", "--retire-preserved-projection", assetName, "--confirm", strings.Repeat("0", 64),
		"--config", configPath, "--workers", "1",
	)
	if code != ExitConflict || !strings.Contains(stderr, "confirmation conflict") {
		t.Fatalf("wrong retirement token code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Lstat(assetPath); err != nil {
		t.Fatalf("wrong retirement token changed audit quarantine: %v", err)
	}

	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"fsck", "--retire-preserved-projection", assetName, "--confirm", assetToken,
		"--config", configPath, "--workers", "1",
	)
	if code != ExitOK || !strings.Contains(stdout, "retired=true already_absent=false") {
		t.Fatalf("exact retirement code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Lstat(assetPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact retirement left asset audit quarantine: %v", err)
	}
	if _, err := os.Lstat(packagePath); err != nil {
		t.Fatalf("one-at-a-time retirement changed sibling audit quarantine: %v", err)
	}

	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"fsck", "--retire-preserved-projection", assetName, "--confirm", assetToken,
		"--config", configPath, "--workers", "1",
	)
	if code != ExitOK || !strings.Contains(stdout, "retired=false already_absent=true") {
		t.Fatalf("retirement replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"fsck", "--retire-preserved-projection", packageName, "--confirm", packageToken,
		"--config", configPath, "--workers", "1",
	)
	if code != ExitOK || !strings.Contains(stdout, "retired=true already_absent=false") {
		t.Fatalf("package retirement code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Lstat(packagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact retirement left package audit quarantine: %v", err)
	}
}

func TestPreservedProjectionRetirementRejectsStaleInodeAndUnlinkAlias(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	stateRoot := filepath.Join(root, ".sow")
	name := assetProjectionStagePrefix + strings.Repeat("1", 32) + ".tsv.preserved-" + strings.Repeat("2", 32)
	path := filepath.Join(stateRoot, name)
	body := []byte("same bytes do not preserve retirement authority\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	_, inventory, _ := runAssetMaterializeHardeningCLI(t,
		"fsck", "--config", configPath, "--workers", "1", "--limit", "0",
	)
	staleToken := preservedProjectionTokenFromOutput(t, inventory, name)
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(stateRoot, "replacement")
	if err := os.WriteFile(replacement, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(replacement, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
		"fsck", "--retire-preserved-projection", name, "--confirm", staleToken,
		"--config", configPath, "--workers", "1",
	)
	if code != ExitConflict || !strings.Contains(stderr, "confirmation conflict") {
		t.Fatalf("stale inode token code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(body) {
		t.Fatalf("stale inode retirement changed replacement body=%q err=%v", got, err)
	}

	_, inventory, _ = runAssetMaterializeHardeningCLI(t,
		"fsck", "--config", configPath, "--workers", "1", "--limit", "0",
	)
	freshToken := preservedProjectionTokenFromOutput(t, inventory, name)
	alias := filepath.Join(stateRoot, "retirement-alias")
	previous := projectionStateBeforeUnlinkHook
	projectionStateBeforeUnlinkHook = func(quarantine string) error {
		return os.Link(filepath.Join(stateRoot, quarantine), alias)
	}
	t.Cleanup(func() { projectionStateBeforeUnlinkHook = previous })
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"fsck", "--retire-preserved-projection", name, "--confirm", freshToken,
		"--config", configPath, "--workers", "1",
	)
	projectionStateBeforeUnlinkHook = previous
	if code != ExitConflict || !strings.Contains(stderr, "link count") {
		t.Fatalf("unlink alias boundary code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, current := range []string{path, alias} {
		if got, err := os.ReadFile(current); err != nil || string(got) != string(body) {
			t.Fatalf("unlink alias boundary changed %s body=%q err=%v", current, got, err)
		}
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"fsck", "--retire-preserved-projection", name, "--confirm", freshToken,
		"--config", configPath, "--workers", "1",
	)
	if code != ExitOK || !strings.Contains(stdout, "retired=true") {
		t.Fatalf("retirement retry after alias removal code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestPreservedProjectionAuditRejectsUnsafeEvidenceAndRetirementFlagMixes(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	stateRoot := filepath.Join(root, ".sow")
	name := packageProjectionStagePrefix + strings.Repeat("3", 32) + "-000.tsv.preserved-" + strings.Repeat("4", 32)
	path := filepath.Join(stateRoot, name)
	alias := filepath.Join(stateRoot, "foreign-alias")
	if err := os.WriteFile(path, []byte("aliased audit evidence\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectPreservedProjectionAudits(stateRoot); err == nil {
		t.Fatalf("aliased audit inventory was accepted directly: %v", err)
	}
	code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
		"fsck", "--recover", "--config", configPath, "--workers", "1", "--limit", "0",
	)
	if code != ExitConflict || !strings.Contains(stderr, "link count") {
		t.Fatalf("aliased audit inventory code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, current := range []string{path, alias} {
		if _, err := os.Lstat(current); err != nil {
			t.Fatalf("unsafe audit evidence was removed at %s: %v", current, err)
		}
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	_, inventory, _ := runAssetMaterializeHardeningCLI(t,
		"fsck", "--config", configPath, "--workers", "1", "--limit", "0",
	)
	token := preservedProjectionTokenFromOutput(t, inventory, name)

	for _, args := range [][]string{
		{"fsck", "--retire-preserved-projection", name, "--config", configPath},
		{"fsck", "--confirm", token, "--config", configPath},
		{"fsck", "--retire-preserved-projection", name, "--confirm", token, "--recover", "--config", configPath},
		{"fsck", "--retire-preserved-projection", name, "--confirm", token, "--repo", "asset", "--config", configPath},
		{"fsck", "--retire-preserved-projection", name, "--confirm", token, "--target", "cf", "--config", configPath},
	} {
		code, stdout, stderr := runAssetMaterializeHardeningCLI(t, args...)
		if code != ExitUsage {
			t.Fatalf("unsafe retirement flag mix args=%v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("usage error changed audit evidence args=%v err=%v", args, err)
		}
	}
}

func TestPreservedProjectionAuditRejectsMalformedAndUnboundedInventory(t *testing.T) {
	t.Run("malformed", func(t *testing.T) {
		stateRoot := t.TempDir()
		name := assetProjectionStagePrefix + strings.Repeat("5", 32) + ".tsv.preserved-not-hex"
		if err := os.WriteFile(filepath.Join(stateRoot, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectPreservedProjectionAudits(stateRoot); err == nil || !strings.Contains(err.Error(), "unsafe") {
			t.Fatalf("malformed preserved audit name was accepted: %v", err)
		}
	})
	t.Run("bounded", func(t *testing.T) {
		stateRoot := t.TempDir()
		for index := 0; index <= preservedProjectionAuditMaximum; index++ {
			transaction := strings.Repeat("0", 28) + formatProjectionAuditHex(index)
			nonce := strings.Repeat("f", 32)
			name := assetProjectionStagePrefix + transaction + ".tsv.preserved-" + nonce
			if err := os.WriteFile(filepath.Join(stateRoot, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := inspectPreservedProjectionAudits(stateRoot); err == nil || !strings.Contains(err.Error(), "exceeds 1024") {
			t.Fatalf("unbounded preserved audit inventory was accepted: %v", err)
		}
	})
}

func preservedProjectionTokenFromOutput(t *testing.T, output, name string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "subject=\"state/"+name+"\"") {
			continue
		}
		for _, field := range strings.Fields(line) {
			if token, ok := strings.CutPrefix(field, "retire_token="); ok && exactLowerHex(token, 64) {
				return token
			}
		}
	}
	t.Fatalf("output has no retirement token for %s: %s", name, output)
	return ""
}

func formatProjectionAuditHex(value int) string {
	const digits = "0123456789abcdef"
	result := []byte{'0', '0', '0', '0'}
	for index := len(result) - 1; index >= 0; index-- {
		result[index] = digits[value&15]
		value >>= 4
	}
	return string(result)
}
