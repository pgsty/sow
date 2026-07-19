package cli

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/state"
)

func TestBuilderHandoffExpectedObjectParsingIsExactAndOrdered(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first.bin")
	second := filepath.Join(t.TempDir(), "second.bin")
	digestA := strings.Repeat("a", 64)
	digestB := strings.Repeat("b", 64)
	expected, receipt, err := parseBuilderHandoffObjects(
		[]string{first, second},
		[]string{"sha256:" + digestA + ":0", "sha256:" + digestB + ":12"},
	)
	if err != nil || len(expected) != 2 || expected[first].HashString() != digestA || expected[first].Size != 0 || expected[second].HashString() != digestB || expected[second].Size != 12 || len(receipt) != 64 {
		t.Fatalf("expected=%v receipt=%q err=%v", expected, receipt, err)
	}

	for name, values := range map[string][]string{
		"count":        {"sha256:" + digestA + ":0"},
		"algorithm":    {"sha512:" + digestA + ":0", "sha256:" + digestB + ":12"},
		"uppercase":    {"sha256:" + strings.ToUpper(digestA) + ":0", "sha256:" + digestB + ":12"},
		"negative":     {"sha256:" + digestA + ":-1", "sha256:" + digestB + ":12"},
		"leading-zero": {"sha256:" + digestA + ":00", "sha256:" + digestB + ":12"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseBuilderHandoffObjects([]string{first, second}, values); err == nil {
				t.Fatalf("invalid builder handoff %v was accepted", values)
			}
		})
	}
	if _, _, err := parseBuilderHandoffObjects([]string{first, first}, []string{"sha256:" + digestA + ":0", "sha256:" + digestA + ":0"}); err == nil {
		t.Fatal("duplicate builder input was accepted")
	}
}

func TestBuilderHandoffAssetMismatchFailsBeforeCASOrCanonicalMutation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	input := filepath.Join(root, "builder-output.bin")
	if err := os.WriteFile(input, []byte("canonical builder output"), 0o600); err != nil {
		t.Fatal(err)
	}
	specification := expectedObjectSpecification(t, input)
	canonical := state.New(filepath.Join(root, ".sow"))
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	poolBefore := readMaterializationTree(t, filepath.Join(root, ".pool"))
	wrong := "sha256:" + strings.Repeat("0", 64) + ":24"
	var stdout, stderr bytes.Buffer
	code := Main([]string{
		"add", input, "--config", configPath, "--repo", "asset", "--dest", "builder-output.bin",
		"--expected-object", wrong,
	}, &stdout, &stderr)
	if code != ExitVerification || !strings.Contains(stderr.String(), "builder handoff input") {
		t.Fatalf("mismatch code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	headAfter, err := canonical.HeadHash()
	if err != nil || headAfter != headBefore {
		t.Fatalf("mismatch mutated canonical state before=%s after=%s err=%v", headBefore, headAfter, err)
	}
	if poolAfter := readMaterializationTree(t, filepath.Join(root, ".pool")); !reflect.DeepEqual(poolBefore, poolAfter) {
		t.Fatalf("mismatch mutated CAS before=%v after=%v", poolBefore, poolAfter)
	}

	stdout.Reset()
	stderr.Reset()
	code = Main([]string{
		"add", input, "--config", configPath, "--repo", "asset", "--dest", "builder-output.bin",
		"--expected-object", specification,
	}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "builder handoff verified inputs=1 receipt_sha256=") {
		t.Fatalf("verified handoff code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if body, err := os.ReadFile(filepath.Join(root, ".sow", "materialized", "beta", "asset", "builder-output.bin")); err != nil || string(body) != "canonical builder output" {
		t.Fatalf("materialized handoff body=%q err=%v", body, err)
	}
}

func TestBuilderHandoffFeedsRealDEBAndRPMAddPaths(t *testing.T) {
	t.Run("deb", func(t *testing.T) {
		root := t.TempDir()
		_, keyPath := writeMaterializeSigningKey(t, root)
		configPath := filepath.Join(root, "sow.yaml")
		if err := os.WriteFile(configPath, []byte(debTestConfig), 0o600); err != nil {
			t.Fatal(err)
		}
		initializeRepoBaselineForTest(t, root, configPath, "apt/test")
		input := decodeMaterializeFixture(t,
			filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"),
			filepath.Join(root, "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb"),
		)
		assertBuilderPackageAdd(t, input, configPath, "deb-test", keyPath)
	})

	t.Run("rpm", func(t *testing.T) {
		root := t.TempDir()
		_, keyPath := writeMaterializeSigningKey(t, root)
		configPath := filepath.Join(root, "sow.yaml")
		if err := os.WriteFile(configPath, []byte(rpmTestConfig), 0o600); err != nil {
			t.Fatal(err)
		}
		initializeRepoBaselineForTest(t, root, configPath, "yum/test/x86_64")
		input := decodeMaterializeFixture(t,
			filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"),
			filepath.Join(root, "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm"),
		)
		assertBuilderPackageAdd(t, input, configPath, "rpm-test", keyPath)
	})
}

func assertBuilderPackageAdd(t *testing.T, input, configPath, repo, keyPath string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Main([]string{
		"add", input, "--config", configPath, "--repo", repo,
		"--gpg-private-key-file", keyPath, "--expected-object", expectedObjectSpecification(t, input),
		"--workers", "1", "--chunk-entries", "1",
	}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "builder handoff verified inputs=1 receipt_sha256=") {
		t.Fatalf("package handoff code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func expectedObjectSpecification(t *testing.T, filename string) string {
	t.Helper()
	body, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	return fmt.Sprintf("sha256:%x:%d", digest, len(body))
}
