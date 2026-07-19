package cli

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

type packageNoopFileWitness struct {
	body []byte
	info os.FileInfo
}

func capturePackageNoopWitnesses(t *testing.T, names ...string) map[string]packageNoopFileWitness {
	t.Helper()
	result := make(map[string]packageNoopFileWitness, len(names))
	for _, name := range names {
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read no-op witness %s: %v", name, err)
		}
		info, err := os.Stat(name)
		if err != nil {
			t.Fatalf("stat no-op witness %s: %v", name, err)
		}
		result[name] = packageNoopFileWitness{body: body, info: info}
	}
	return result
}

func assertPackageNoopWitnessesUnchanged(t *testing.T, before map[string]packageNoopFileWitness) {
	t.Helper()
	for name, witness := range before {
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("re-read no-op witness %s: %v", name, err)
		}
		info, err := os.Stat(name)
		if err != nil {
			t.Fatalf("re-stat no-op witness %s: %v", name, err)
		}
		if !bytes.Equal(body, witness.body) {
			t.Errorf("no-op rewrote metadata bytes: %s", name)
		}
		if !os.SameFile(witness.info, info) {
			t.Errorf("no-op replaced metadata inode: %s", name)
		}
		if !info.ModTime().Equal(witness.info.ModTime()) {
			t.Errorf("no-op changed metadata mtime: %s before=%s after=%s", name, witness.info.ModTime(), info.ModTime())
		}
	}
}

func assertPackageNoopCanonicalUnchanged(t *testing.T, canonical *state.Store, beforeHead plumbing.Hash, ref plumbing.ReferenceName, beforeRef plumbing.Hash) {
	t.Helper()
	afterHead, err := canonical.HeadHash()
	if err != nil || afterHead != beforeHead {
		t.Fatalf("no-op changed canonical HEAD before=%s after=%s err=%v", beforeHead, afterHead, err)
	}
	afterRef, exists, err := canonical.Ref(ref)
	if err != nil || !exists || afterRef != beforeRef {
		t.Fatalf("no-op changed view ref %s before=%s after=%s exists=%t err=%v", ref, beforeRef, afterRef, exists, err)
	}
}

func onlyPackageMaterializationReceipt(t *testing.T, canonical *state.Store) string {
	t.Helper()
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	files, err := canonical.ListFilesAt(head, "materializations/packages/")
	if err != nil {
		t.Fatal(err)
	}
	var receipts []string
	for _, name := range files {
		if strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".trust.json") {
			receipts = append(receipts, name)
		}
	}
	if len(receipts) != 1 {
		t.Fatalf("package materialization receipts=%v", receipts)
	}
	return receipts[0]
}

func preparePackageNoopDEB(t *testing.T) (root, configPath, packagePath, keyPath string) {
	t.Helper()
	root = t.TempDir()
	configPath = filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(debTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "apt/test")
	encoded, err := os.ReadFile("../aptrepo/testdata/libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64")
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	packagePath = filepath.Join(root, "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb")
	if err := os.WriteFile(packagePath, body, 0o444); err != nil {
		t.Fatal(err)
	}
	_, keyPath = writeMaterializeSigningKey(t, root)
	return root, configPath, packagePath, keyPath
}

func preparePackageNoopRPM(t *testing.T) (root, configPath, packagePath, keyPath string) {
	t.Helper()
	root = t.TempDir()
	configPath = filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(rpmTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "yum/test/x86_64")
	packagePath = decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "pgdg-redhat-nonfree-repo.rpm"))
	_, keyPath = writeMaterializeSigningKey(t, root)
	return root, configPath, packagePath, keyPath
}

func preparePackageNoopMixed(t *testing.T) (root, configPath, debPath, rpmPath, keyPath string) {
	t.Helper()
	root = t.TempDir()
	configPath = filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(packageNoopMixedConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "apt/test", "yum/test/x86_64")
	encoded, err := os.ReadFile("../aptrepo/testdata/libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64")
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	debPath = filepath.Join(root, "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb")
	if err := os.WriteFile(debPath, body, 0o444); err != nil {
		t.Fatal(err)
	}
	rpmPath = decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "pgdg-redhat-nonfree-repo.rpm"))
	_, keyPath = writeMaterializeSigningKey(t, root)
	return root, configPath, debPath, rpmPath, keyPath
}

func TestPackageAddAndUnmatchedRemoveAreReceiptGuardedPhysicalNoops(t *testing.T) {
	t.Run("deb", func(t *testing.T) {
		root, configPath, packagePath, keyPath := preparePackageNoopDEB(t)
		args := []string{packagePath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
		var hooks atomic.Int64
		ctx := withPackageMaterializationHook(t.Context(), func(packageMaterializationInvocation) error {
			hooks.Add(1)
			return nil
		})
		var stdout, stderr bytes.Buffer
		if err := runAdd(ctx, args, &stdout, &stderr); err != nil || hooks.Load() == 0 {
			t.Fatalf("initial DEB materialization hooks=%d err=%v stdout=%s stderr=%s", hooks.Load(), err, stdout.String(), stderr.String())
		}
		loaded, err := config.Load(configPath, "")
		if err != nil {
			t.Fatal(err)
		}
		canonical := state.New(loaded.StatePath())
		ref, _ := state.ViewRef("beta", "deb-test", "jammy", "arm64")
		beforeRef, exists, err := canonical.Ref(ref)
		if err != nil || !exists {
			t.Fatalf("DEB ref exists=%t err=%v", exists, err)
		}
		beforeHead, err := canonical.HeadHash()
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, ".sow", "materialized", "beta", "apt", "test")
		witnesses := capturePackageNoopWitnesses(t,
			filepath.Join(target, "dists", "jammy", "main", "binary-arm64", "Packages"),
			filepath.Join(target, "dists", "jammy", "Release"),
			filepath.Join(target, "dists", "jammy", "InRelease"),
		)

		hooks.Store(0)
		stdout.Reset()
		stderr.Reset()
		if err := runAdd(ctx, args, &stdout, &stderr); err != nil || hooks.Load() != 0 || !strings.Contains(stdout.String(), "physical=no-op") {
			t.Fatalf("DEB no-op hooks=%d err=%v stdout=%s stderr=%s", hooks.Load(), err, stdout.String(), stderr.String())
		}
		assertPackageNoopCanonicalUnchanged(t, canonical, beforeHead, ref, beforeRef)
		assertPackageNoopWitnessesUnchanged(t, witnesses)

		hooks.Store(0)
		stdout.Reset()
		stderr.Reset()
		removeArgs := []string{"definitely-not-present", "--config", configPath, "--repo", "deb-test", "--os", "jammy", "--view", "beta", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
		if err := runRemove(ctx, removeArgs, &stdout, &stderr); err != nil || hooks.Load() != 0 || !strings.Contains(stdout.String(), "physical=no-op") {
			t.Fatalf("unmatched DEB rm hooks=%d err=%v stdout=%s stderr=%s", hooks.Load(), err, stdout.String(), stderr.String())
		}
		assertPackageNoopCanonicalUnchanged(t, canonical, beforeHead, ref, beforeRef)
		assertPackageNoopWitnessesUnchanged(t, witnesses)
	})

	t.Run("rpm", func(t *testing.T) {
		root, configPath, packagePath, keyPath := preparePackageNoopRPM(t)
		args := []string{packagePath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
		var hooks atomic.Int64
		ctx := withPackageMaterializationHook(t.Context(), func(packageMaterializationInvocation) error {
			hooks.Add(1)
			return nil
		})
		var stdout, stderr bytes.Buffer
		if err := runAdd(ctx, args, &stdout, &stderr); err != nil || hooks.Load() == 0 {
			t.Fatalf("initial RPM materialization hooks=%d err=%v stdout=%s stderr=%s", hooks.Load(), err, stdout.String(), stderr.String())
		}
		loaded, err := config.Load(configPath, "")
		if err != nil {
			t.Fatal(err)
		}
		canonical := state.New(loaded.StatePath())
		ref, _ := state.ViewRef("beta", "rpm-test", "el10", "x86_64")
		beforeRef, exists, err := canonical.Ref(ref)
		if err != nil || !exists {
			t.Fatalf("RPM ref exists=%t err=%v", exists, err)
		}
		beforeHead, err := canonical.HeadHash()
		if err != nil {
			t.Fatal(err)
		}
		repodata := filepath.Join(root, ".sow", "materialized", "beta", "yum", "test", "x86_64", "repodata")
		witnesses := capturePackageNoopWitnesses(t, filepath.Join(repodata, "repomd.xml"), filepath.Join(repodata, "repomd.xml.asc"))

		hooks.Store(0)
		stdout.Reset()
		stderr.Reset()
		if err := runAdd(ctx, args, &stdout, &stderr); err != nil || hooks.Load() != 0 || !strings.Contains(stdout.String(), "physical=no-op") {
			t.Fatalf("RPM no-op hooks=%d err=%v stdout=%s stderr=%s", hooks.Load(), err, stdout.String(), stderr.String())
		}
		assertPackageNoopCanonicalUnchanged(t, canonical, beforeHead, ref, beforeRef)
		assertPackageNoopWitnessesUnchanged(t, witnesses)
	})
}

func TestPackageNoopRepairsMissingCorruptAndDriftedReadinessEvidence(t *testing.T) {
	t.Run("corrupt-receipt-and-missing-metadata", func(t *testing.T) {
		root, configPath, packagePath, keyPath := preparePackageNoopDEB(t)
		args := []string{packagePath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
		var hooks atomic.Int64
		ctx := withPackageMaterializationHook(t.Context(), func(packageMaterializationInvocation) error {
			hooks.Add(1)
			return nil
		})
		var stdout, stderr bytes.Buffer
		if err := runAdd(ctx, args, &stdout, &stderr); err != nil {
			t.Fatalf("initial DEB add: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
		}
		loaded, err := config.Load(configPath, "")
		if err != nil {
			t.Fatal(err)
		}
		canonical := state.New(loaded.StatePath())
		receiptPath := onlyPackageMaterializationReceipt(t, canonical)
		corrupt := filepath.Join(t.TempDir(), "corrupt.json")
		if err := os.WriteFile(corrupt, []byte("{not-json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, changed, err := canonical.InstallPaths(map[string]string{receiptPath: corrupt}, "test: corrupt package readiness receipt"); err != nil || !changed {
			t.Fatalf("corrupt package receipt changed=%t err=%v", changed, err)
		}
		hooks.Store(0)
		stdout.Reset()
		stderr.Reset()
		if err := runAdd(ctx, args, &stdout, &stderr); err != nil || hooks.Load() == 0 || !strings.Contains(stdout.String(), "repair=materialization") {
			t.Fatalf("corrupt receipt repair hooks=%d err=%v stdout=%s stderr=%s", hooks.Load(), err, stdout.String(), stderr.String())
		}
		_ = onlyPackageMaterializationReceipt(t, canonical)

		packages := filepath.Join(root, ".sow", "materialized", "beta", "apt", "test", "dists", "jammy", "main", "binary-arm64", "Packages")
		if err := os.Remove(packages); err != nil {
			t.Fatal(err)
		}
		hooks.Store(0)
		stdout.Reset()
		stderr.Reset()
		if err := runAdd(ctx, args, &stdout, &stderr); err != nil || hooks.Load() == 0 || !strings.Contains(stdout.String(), "repair=materialization") {
			t.Fatalf("physical metadata repair hooks=%d err=%v stdout=%s stderr=%s", hooks.Load(), err, stdout.String(), stderr.String())
		}
		if _, err := os.Stat(packages); err != nil {
			t.Fatalf("missing Packages was not repaired: %v", err)
		}
	})

	t.Run("missing-receipt", func(t *testing.T) {
		_, configPath, packagePath, keyPath := preparePackageNoopRPM(t)
		args := []string{packagePath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
		var hooks atomic.Int64
		ctx := withPackageMaterializationHook(t.Context(), func(packageMaterializationInvocation) error {
			hooks.Add(1)
			return nil
		})
		var stdout, stderr bytes.Buffer
		if err := runAdd(ctx, args, &stdout, &stderr); err != nil {
			t.Fatalf("initial RPM add: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
		}
		loaded, err := config.Load(configPath, "")
		if err != nil {
			t.Fatal(err)
		}
		canonical := state.New(loaded.StatePath())
		receiptPath := onlyPackageMaterializationReceipt(t, canonical)
		if _, changed, err := canonical.Apply(t.Context(), "test-package-receipt-loss", "test: remove package readiness receipt", nil, nil, state.ApplyOptions{DeletePaths: []string{receiptPath}}); err != nil || !changed {
			t.Fatalf("delete package receipt changed=%t err=%v", changed, err)
		}
		hooks.Store(0)
		stdout.Reset()
		stderr.Reset()
		if err := runAdd(ctx, args, &stdout, &stderr); err != nil || hooks.Load() == 0 || !strings.Contains(stdout.String(), "repair=materialization") {
			t.Fatalf("missing receipt repair hooks=%d err=%v stdout=%s stderr=%s", hooks.Load(), err, stdout.String(), stderr.String())
		}
		_ = onlyPackageMaterializationReceipt(t, canonical)
	})
}

func TestRPMMaterializationGroupsOneCompletePhysicalOwnerPerRepoArch(t *testing.T) {
	repo := config.Repo{
		ID: "multi-alias", Type: "yum", Path: "yum/multi/{arch}", Arches: []string{"x86_64"},
		OS:  config.OSConfig{Family: "el", Major: 10, Suite: "vendor10", Lifecycle: "active"},
		YUM: &config.YUMConfig{Compression: "zstd"},
	}
	requests := []materializationSelectionRequest{{
		Source: materializeCanonicalSource{ID: "beta", Public: true},
		Leaves: []viewLeaf{
			{repo: repo, os: "el10", arch: "x86_64"},
			{repo: repo, os: "vendor10", arch: "x86_64"},
		},
	}}
	owners, err := rpmMaterializationOwners(requests)
	if err != nil || len(owners) != 1 {
		t.Fatalf("physical owner count=%d err=%v", len(owners), err)
	}
	if got := removalLeafOSList(owners[0].leaves); got != "el10,vendor10" {
		t.Fatalf("YUM physical owner aliases=%q", got)
	}
}

func TestPackageProjectionIntentRecoversInputlessAfterCommitBeforeMaterialization(t *testing.T) {
	if os.Getenv("SOW_TEST_PACKAGE_PROJECTION_CRASH") == "1" {
		crashPhase := os.Getenv("SOW_TEST_PACKAGE_PROJECTION_PHASE")
		if crashPhase == "" {
			crashPhase = "after-ref-before-materialize"
		}
		packageProjectionMutationHook = func(phase string) error {
			if phase == crashPhase {
				os.Exit(94)
			}
			return nil
		}
		operation := os.Getenv("SOW_TEST_PACKAGE_PROJECTION_OPERATION")
		family := os.Getenv("SOW_TEST_PACKAGE_PROJECTION_FAMILY")
		configPath := os.Getenv("SOW_TEST_PACKAGE_PROJECTION_CONFIG")
		keyPath := os.Getenv("SOW_TEST_PACKAGE_PROJECTION_KEY")
		var arguments []string
		if operation == "add" {
			arguments = []string{"add", os.Getenv("SOW_TEST_PACKAGE_PROJECTION_INPUT"), "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}
		} else {
			arguments = []string{"rm", os.Getenv("SOW_TEST_PACKAGE_PROJECTION_SELECTOR"), "--view", "beta", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}
		}
		if family == "apt" {
			arguments = append(arguments, "--repo", "deb-test")
		} else {
			arguments = append(arguments, "--repo", "rpm-test")
		}
		var stdout, stderr bytes.Buffer
		os.Exit(Main(arguments, &stdout, &stderr))
	}

	phases := []string{
		"after-fence-before-apply",
		"after-transaction-intent-before-commit",
		"after-canonical-commit-before-ref",
		"after-ref-before-materialize",
	}
	for _, test := range []struct {
		name      string
		family    string
		operation string
		selector  string
	}{
		{name: "apt-add", family: "apt", operation: "add"},
		{name: "yum-add", family: "yum", operation: "add"},
		{name: "apt-rm", family: "apt", operation: "rm", selector: "libpqtypes0"},
		{name: "yum-rm", family: "yum", operation: "rm", selector: "pgdg-redhat-nonfree-repo"},
	} {
		test := test
		for _, phase := range phases {
			phase := phase
			t.Run(test.name+"/"+phase, func(t *testing.T) {
				var root, configPath, packagePath, keyPath, repo string
				if test.family == "apt" {
					root, configPath, packagePath, keyPath = preparePackageNoopDEB(t)
					repo = "deb-test"
				} else {
					root, configPath, packagePath, keyPath = preparePackageNoopRPM(t)
					repo = "rpm-test"
				}
				addArguments := []string{packagePath, "--config", configPath, "--repo", repo, "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}
				if test.operation == "rm" {
					var stdout, stderr bytes.Buffer
					if err := runAdd(t.Context(), addArguments, &stdout, &stderr); err != nil {
						t.Fatalf("seed %s removal: %v stdout=%s stderr=%s", test.family, err, stdout.String(), stderr.String())
					}
				}
				command := exec.Command(os.Args[0], "-test.run=^TestPackageProjectionIntentRecoversInputlessAfterCommitBeforeMaterialization$")
				command.Env = append(os.Environ(),
					"SOW_TEST_PACKAGE_PROJECTION_CRASH=1",
					"SOW_TEST_PACKAGE_PROJECTION_PHASE="+phase,
					"SOW_TEST_PACKAGE_PROJECTION_OPERATION="+test.operation,
					"SOW_TEST_PACKAGE_PROJECTION_FAMILY="+test.family,
					"SOW_TEST_PACKAGE_PROJECTION_CONFIG="+configPath,
					"SOW_TEST_PACKAGE_PROJECTION_KEY="+keyPath,
					"SOW_TEST_PACKAGE_PROJECTION_INPUT="+packagePath,
					"SOW_TEST_PACKAGE_PROJECTION_SELECTOR="+test.selector,
				)
				output, err := command.CombinedOutput()
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 94 {
					t.Fatalf("package projection crash helper %s err=%v output=%s", test.name, err, output)
				}
				intent, exists, err := readPackageProjectionIntent(filepath.Join(root, ".sow"))
				if err != nil || !exists || intent.Operation != test.operation || intent.Family != test.family {
					t.Fatalf("package bridge %s exists=%t intent=%+v err=%v", test.name, exists, intent, err)
				}
				transaction, transactionExists, transactionErr := state.New(filepath.Join(root, ".sow")).Transaction(intent.TransactionID)
				switch phase {
				case "after-fence-before-apply":
					if transactionErr != nil || transactionExists {
						t.Fatalf("pre-Apply bridge unexpectedly has transaction exists=%t record=%+v err=%v", transactionExists, transaction, transactionErr)
					}
				case "after-transaction-intent-before-commit":
					if transactionErr != nil || !transactionExists || transaction.Phase != "intent" || !transaction.Commit.IsZero() {
						t.Fatalf("intent-window transaction exists=%t record=%+v err=%v", transactionExists, transaction, transactionErr)
					}
				case "after-canonical-commit-before-ref":
					if transactionErr != nil || !transactionExists || transaction.Phase != "committed" || transaction.Commit.IsZero() {
						t.Fatalf("committed-window transaction exists=%t record=%+v err=%v", transactionExists, transaction, transactionErr)
					}
				case "after-ref-before-materialize":
					if transactionErr != nil || !transactionExists || transaction.Phase != "complete" || transaction.Commit.IsZero() {
						t.Fatalf("post-ref transaction exists=%t record=%+v err=%v", transactionExists, transaction, transactionErr)
					}
				}
				if err := os.Remove(packagePath); err != nil {
					t.Fatal(err)
				}
				recovery := []string{test.operation, "--config", configPath, "--repo", repo, "--recover", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}
				if test.operation == "rm" {
					recovery = append(recovery, "--view", "beta")
				}
				var stdout, stderr bytes.Buffer
				if code := Main(recovery, &stdout, &stderr); code != ExitOK || !strings.Contains(stdout.String(), "recovered pending package projection operation="+test.operation+" family="+test.family) {
					t.Fatalf("inputless package recovery %s code=%d stdout=%s stderr=%s", test.name, code, stdout.String(), stderr.String())
				}
				wantPackages := 1
				if test.operation == "rm" {
					wantPackages = 0
				}
				if test.family == "apt" {
					packages, err := os.ReadFile(filepath.Join(root, ".sow", "materialized", "beta", "apt", "test", "dists", "jammy", "main", "binary-arm64", "Packages"))
					if err != nil || strings.Contains(string(packages), "Package: libpqtypes0\n") != (wantPackages == 1) {
						t.Fatalf("APT recovery %s Packages=%s err=%v", test.name, packages, err)
					}
				} else {
					privateKey, err := os.ReadFile(keyPath)
					if err != nil {
						t.Fatal(err)
					}
					verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(privateKey), time.Now().UTC().Add(time.Hour))
					if err != nil {
						t.Fatal(err)
					}
					generation, err := yumrepo.ValidateDirectory(t.Context(), filepath.Join(root, ".sow", "materialized", "beta", "yum", "test", "x86_64", "repodata"), yumrepo.CompressionZstd, verifier)
					if err != nil || generation.Packages != int64(wantPackages) {
						t.Fatalf("YUM recovery %s generation=%+v err=%v", test.name, generation, err)
					}
				}
				if _, exists, err := readPackageProjectionIntent(filepath.Join(root, ".sow")); err != nil || exists {
					t.Fatalf("package recovery retained bridge %s exists=%t err=%v", test.name, exists, err)
				}
				if _, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
					t.Fatalf("package recovery retained selected set %s exists=%t err=%v", test.name, exists, err)
				}
			})
		}
	}
}

func TestMixedPackageRemoveProjectionRecoversBothRepositoryFamilies(t *testing.T) {
	if os.Getenv("SOW_TEST_MIXED_PACKAGE_REMOVE_CRASH") == "1" {
		wanted := os.Getenv("SOW_TEST_MIXED_PACKAGE_REMOVE_PHASE")
		packageProjectionMutationHook = func(phase string) error {
			if phase == wanted {
				os.Exit(95)
			}
			return nil
		}
		var stdout, stderr bytes.Buffer
		os.Exit(Main([]string{
			"rm", "libpqtypes0", "pgdg-redhat-nonfree-repo", "--view", "beta",
			"--config", os.Getenv("SOW_TEST_MIXED_PACKAGE_REMOVE_CONFIG"),
			"--gpg-private-key-file", os.Getenv("SOW_TEST_MIXED_PACKAGE_REMOVE_KEY"),
			"--workers", "1", "--chunk-entries", "1",
		}, &stdout, &stderr))
	}

	for _, phase := range []string{"after-transaction-intent-before-commit", "after-ref-before-materialize"} {
		phase := phase
		t.Run(phase, func(t *testing.T) {
			root, configPath, debPath, rpmPath, keyPath := preparePackageNoopMixed(t)
			var stdout, stderr bytes.Buffer
			if err := runAdd(t.Context(), []string{debPath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); err != nil {
				t.Fatalf("seed mixed APT: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
			}
			stdout.Reset()
			stderr.Reset()
			if err := runAdd(t.Context(), []string{rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); err != nil {
				t.Fatalf("seed mixed YUM: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
			}
			command := exec.Command(os.Args[0], "-test.run=^TestMixedPackageRemoveProjectionRecoversBothRepositoryFamilies$")
			command.Env = append(os.Environ(),
				"SOW_TEST_MIXED_PACKAGE_REMOVE_CRASH=1",
				"SOW_TEST_MIXED_PACKAGE_REMOVE_PHASE="+phase,
				"SOW_TEST_MIXED_PACKAGE_REMOVE_CONFIG="+configPath,
				"SOW_TEST_MIXED_PACKAGE_REMOVE_KEY="+keyPath,
			)
			output, err := command.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 95 {
				t.Fatalf("mixed package rm crash phase=%s err=%v output=%s", phase, err, output)
			}
			intent, exists, err := readPackageProjectionIntent(filepath.Join(root, ".sow"))
			if err != nil || !exists || intent.Operation != "rm" || intent.Family != "mixed" || len(intent.Units) != 2 {
				t.Fatalf("mixed package bridge phase=%s exists=%t intent=%+v err=%v", phase, exists, intent, err)
			}
			refs := make(map[string]struct{}, len(intent.Units))
			for _, unit := range intent.Units {
				refs[unit.ViewRef] = struct{}{}
				if _, err := os.Stat(filepath.Join(root, ".sow", unit.StageRelative)); err != nil {
					t.Fatalf("mixed package bridge stage %s: %v", unit.StageRelative, err)
				}
			}
			if len(refs) != 2 {
				t.Fatalf("mixed package bridge refs=%v", refs)
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			record, exists, err := canonical.Transaction(intent.TransactionID)
			wantPhase := "intent"
			if phase == "after-ref-before-materialize" {
				wantPhase = "complete"
			}
			if err != nil || !exists || record.Phase != wantPhase {
				t.Fatalf("mixed package transaction phase=%s exists=%t record=%+v err=%v", phase, exists, record, err)
			}
			stdout.Reset()
			stderr.Reset()
			code := Main([]string{"rm", "--config", configPath, "--recover", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
			if code != ExitOK || !strings.Contains(stdout.String(), "recovered pending package projection operation=rm family=mixed units=2") {
				t.Fatalf("mixed package inputless recovery phase=%s code=%d stdout=%s stderr=%s", phase, code, stdout.String(), stderr.String())
			}
			packages, err := os.ReadFile(filepath.Join(root, ".sow", "materialized", "beta", "apt", "test", "dists", "jammy", "main", "binary-arm64", "Packages"))
			if err != nil || strings.Contains(string(packages), "Package: libpqtypes0\n") {
				t.Fatalf("mixed APT recovery retained package Packages=%s err=%v", packages, err)
			}
			privateKey, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(privateKey), time.Now().UTC().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			generation, err := yumrepo.ValidateDirectory(t.Context(), filepath.Join(root, ".sow", "materialized", "beta", "yum", "test", "x86_64", "repodata"), yumrepo.CompressionZstd, verifier)
			if err != nil || generation.Packages != 0 {
				t.Fatalf("mixed YUM recovery generation=%+v err=%v", generation, err)
			}
			record, exists, err = canonical.Transaction(intent.TransactionID)
			if err != nil || !exists || record.Phase != "complete" || record.Commit.IsZero() || len(record.Refs) != 2 {
				t.Fatalf("mixed recovered transaction exists=%t record=%+v err=%v", exists, record, err)
			}
			for _, ref := range record.Refs {
				current, refExists, refErr := canonical.Ref(ref.Name)
				if refErr != nil || !refExists || current != record.Commit {
					t.Fatalf("mixed recovered ref %s current=%s exists=%t commit=%s err=%v", ref.Name, current, refExists, record.Commit, refErr)
				}
			}
			if _, exists, err := readPackageProjectionIntent(filepath.Join(root, ".sow")); err != nil || exists {
				t.Fatalf("mixed recovery retained package bridge exists=%t err=%v", exists, err)
			}
			if _, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
				t.Fatalf("mixed recovery retained selected-set journal exists=%t err=%v", exists, err)
			}
		})
	}
}

func TestMixedPackageRecoveryAdoptsCompleteSelectedSetBeforeFirstOwner(t *testing.T) {
	root, configPath, debPath, rpmPath, keyPath := preparePackageNoopMixed(t)
	var stdout, stderr bytes.Buffer
	if err := runAdd(t.Context(), []string{debPath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); err != nil {
		t.Fatalf("seed mixed APT: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if err := runAdd(t.Context(), []string{rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); err != nil {
		t.Fatalf("seed mixed YUM: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	command := exec.Command(os.Args[0], "-test.run=^TestMixedPackageRemoveProjectionRecoversBothRepositoryFamilies$")
	command.Env = append(os.Environ(),
		"SOW_TEST_MIXED_PACKAGE_REMOVE_CRASH=1",
		"SOW_TEST_MIXED_PACKAGE_REMOVE_PHASE=after-ref-before-materialize",
		"SOW_TEST_MIXED_PACKAGE_REMOVE_CONFIG="+configPath,
		"SOW_TEST_MIXED_PACKAGE_REMOVE_KEY="+keyPath,
	)
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 95 {
		t.Fatalf("mixed package pre-materialization crash err=%v output=%s", err, output)
	}
	intent, exists, err := readPackageProjectionIntent(filepath.Join(root, ".sow"))
	if err != nil || !exists || intent.Family != "mixed" || len(intent.Units) != 2 {
		t.Fatalf("mixed package bridge exists=%t intent=%+v err=%v", exists, intent, err)
	}
	if _, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("selected set unexpectedly existed before first recovery exists=%t err=%v", exists, err)
	}
	aptTarget := filepath.Join(root, ".sow", "materialized", "beta", "apt", "test")
	aptBackup := aptTarget + ".first-owner-repair"
	if err := os.Rename(aptTarget, aptBackup); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aptTarget, []byte("first-owner-filesystem-fault"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code := Main([]string{"rm", "--config", configPath, "--recover", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code == ExitOK {
		t.Fatalf("first-owner filesystem fault unexpectedly recovered stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	journal, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow"))
	if err != nil || !exists || len(journal.Units) < 2 || journal.Phase != materializationSelectionMaterializing || len(journal.CompletedUnits) != 0 {
		t.Fatalf("full first-owner failure journal exists=%t journal=%+v err=%v stdout=%s stderr=%s", exists, journal, err, stdout.String(), stderr.String())
	}
	if err := os.Remove(aptTarget); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(aptBackup, aptTarget); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"rm", "--config", configPath, "--recover", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "recovered pending package projection operation=rm family=mixed units=2") {
		t.Fatalf("complete selected-set recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("complete selected-set recovery retained journal exists=%t err=%v", exists, err)
	}
}

func TestMultiRepoPackageRecoveryAdoptsCompleteSelectedSetBeforeFirstOwner(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(packageMultiAPTRecoveryConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "apt/one", "apt/two")
	arm64 := writeSyncMinimalDEB(t, root, "multi-one", "1.0", "arm64")
	amd64 := writeSyncMinimalDEB(t, root, "multi-two", "1.0", "amd64")
	_, keyPath := writeMaterializeSigningKey(t, root)
	previous := packageProjectionMutationHook
	packageProjectionMutationHook = func(phase string) error {
		if phase == "after-ref-before-materialize" {
			return errors.New("stop multi-repo add before first owner")
		}
		return nil
	}
	t.Cleanup(func() { packageProjectionMutationHook = previous })
	arguments := []string{arm64, amd64, "--config", configPath, "--repo", "apt-one", "--repo", "apt-two", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}
	var stdout, stderr bytes.Buffer
	if err := runAdd(t.Context(), arguments, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "stop multi-repo add") {
		t.Fatalf("multi-repo bridge seed err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	packageProjectionMutationHook = nil
	intent, exists, err := readPackageProjectionIntent(filepath.Join(root, ".sow"))
	if err != nil || !exists || intent.Family != "apt" || len(intent.Units) != 2 {
		t.Fatalf("multi-repo package bridge exists=%t intent=%+v err=%v", exists, intent, err)
	}
	firstTarget := filepath.Join(root, ".sow", "materialized", "beta", "apt", "one")
	if err := os.MkdirAll(filepath.Dir(firstTarget), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstTarget, []byte("multi-repo-first-owner-fault"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code := Main([]string{"add", "--config", configPath, "--recover", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code == ExitOK {
		t.Fatalf("multi-repo first-owner fault unexpectedly recovered stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	journal, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow"))
	if err != nil || !exists || len(journal.Units) != 2 || journal.Phase != materializationSelectionMaterializing || len(journal.CompletedUnits) != 0 {
		t.Fatalf("multi-repo full journal exists=%t journal=%+v err=%v stdout=%s stderr=%s", exists, journal, err, stdout.String(), stderr.String())
	}
	if err := os.Remove(firstTarget); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"add", "--config", configPath, "--recover", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "recovered pending package projection operation=add family=apt units=2") {
		t.Fatalf("multi-repo complete recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, packages := range []string{
		filepath.Join(root, ".sow", "materialized", "beta", "apt", "one", "dists", "jammy", "main", "binary-arm64", "Packages"),
		filepath.Join(root, ".sow", "materialized", "beta", "apt", "two", "dists", "jammy", "main", "binary-amd64", "Packages"),
	} {
		if info, err := os.Stat(packages); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("multi-repo recovered metadata %s info=%v err=%v", packages, info, err)
		}
	}
}

func TestPackageProjectionReturnedAfterIntentErrorRemainsInputlessRecoverable(t *testing.T) {
	root, configPath, packagePath, keyPath := preparePackageNoopDEB(t)
	previous := packageProjectionMutationHook
	packageProjectionMutationHook = func(phase string) error {
		if phase == "after-transaction-intent-before-commit" {
			return errors.New("injected returned after-intent failure")
		}
		return nil
	}
	t.Cleanup(func() { packageProjectionMutationHook = previous })
	var stdout, stderr bytes.Buffer
	err := runAdd(t.Context(), []string{packagePath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "injected returned after-intent failure") {
		t.Fatalf("package returned after-intent failure err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	intent, exists, err := readPackageProjectionIntent(filepath.Join(root, ".sow"))
	if err != nil || !exists {
		t.Fatalf("package returned failure bridge exists=%t err=%v", exists, err)
	}
	record, exists, err := state.New(filepath.Join(root, ".sow")).Transaction(intent.TransactionID)
	if err != nil || !exists || record.Phase != "intent" || !record.Commit.IsZero() {
		t.Fatalf("package returned failure transaction exists=%t record=%+v err=%v", exists, record, err)
	}
	for _, relative := range append([]string{intent.ConfigStage}, intent.Units[0].StageRelative) {
		if _, err := os.Stat(filepath.Join(root, ".sow", relative)); err != nil {
			t.Fatalf("package returned failure lost durable stage %s: %v", relative, err)
		}
	}
	packageProjectionMutationHook = nil
	if err := os.Remove(packagePath); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code := Main([]string{"add", "--config", configPath, "--repo", "deb-test", "--recover", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "recovered pending package projection operation=add family=apt") {
		t.Fatalf("package returned failure inputless recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, exists, err := readPackageProjectionIntent(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("package returned failure recovery retained bridge exists=%t err=%v", exists, err)
	}
}

func TestPackageProjectionAbortedCanonicalInstallRepairsAndRecoversInputless(t *testing.T) {
	root, configPath, packagePath, keyPath := preparePackageNoopDEB(t)
	var faultPath, backupPath string
	previous := packageProjectionMutationHook
	packageProjectionMutationHook = func(phase string) error {
		if phase != "after-transaction-intent-before-commit" {
			return nil
		}
		intent, exists, err := readPackageProjectionIntent(filepath.Join(root, ".sow"))
		if err != nil || !exists || len(intent.Units) != 1 {
			return errors.Join(err, errors.New("package intent unavailable at install fault boundary"))
		}
		faultPath = filepath.Join(root, ".sow", intent.Units[0].StageRelative)
		backupPath = faultPath + ".repair"
		if err := os.Rename(faultPath, backupPath); err != nil {
			return err
		}
		// A directory is a real filesystem fault for the exact regular stage.
		// Returning nil forces Apply to enter installPathChanges and persist its
		// aborted phase rather than stopping at the test seam itself.
		return os.Mkdir(faultPath, 0o700)
	}
	t.Cleanup(func() { packageProjectionMutationHook = previous })
	arguments := []string{packagePath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}
	var stdout, stderr bytes.Buffer
	err := runAdd(t.Context(), arguments, &stdout, &stderr)
	if err == nil || faultPath == "" || backupPath == "" {
		t.Fatalf("real package install fault err=%v fault=%q backup=%q stdout=%s stderr=%s", err, faultPath, backupPath, stdout.String(), stderr.String())
	}
	intent, exists, readErr := readPackageProjectionIntent(filepath.Join(root, ".sow"))
	if readErr != nil || !exists {
		t.Fatalf("aborted package bridge exists=%t err=%v", exists, readErr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	record, exists, readErr := canonical.Transaction(intent.TransactionID)
	if readErr != nil || !exists || record.Phase != "aborted" || !record.Commit.IsZero() {
		t.Fatalf("aborted package transaction exists=%t record=%+v err=%v", exists, record, readErr)
	}
	if err := os.Remove(faultPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backupPath, faultPath); err != nil {
		t.Fatal(err)
	}
	packageProjectionMutationHook = nil
	if err := os.Remove(packagePath); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code := Main([]string{"add", "--config", configPath, "--repo", "deb-test", "--recover", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "recovered pending package projection operation=add family=apt") {
		t.Fatalf("aborted package inputless recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	record, exists, readErr = canonical.Transaction(intent.TransactionID)
	if readErr != nil || !exists || record.Phase != "complete" || record.Commit.IsZero() {
		t.Fatalf("aborted package recovery transaction exists=%t record=%+v err=%v", exists, record, readErr)
	}
	if _, exists, err := readPackageProjectionIntent(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("aborted package recovery retained bridge exists=%t err=%v", exists, err)
	}
	if _, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("aborted package recovery retained selected set exists=%t err=%v", exists, err)
	}
}

func TestPackageProjectionRecoveryRereadsIntentAfterLockAdmission(t *testing.T) {
	_, configPath, packagePath, keyPath := preparePackageNoopDEB(t)
	previousMutation := packageProjectionMutationHook
	packageProjectionMutationHook = func(phase string) error {
		if phase == "after-fence-before-apply" {
			return errors.New("seed package bridge before lock-reread test")
		}
		return nil
	}
	t.Cleanup(func() { packageProjectionMutationHook = previousMutation })
	var stdout, stderr bytes.Buffer
	if err := runAdd(t.Context(), []string{packagePath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); err == nil {
		t.Fatal("package bridge seed unexpectedly succeeded")
	}
	packageProjectionMutationHook = nil
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, exists, err := readPackageProjectionIntent(cfg.StatePath()); err != nil || !exists {
		t.Fatalf("seed package bridge exists=%t err=%v", exists, err)
	}
	previousBeforeLock := packageProjectionBeforeLockHook
	packageProjectionBeforeLockHook = func() error {
		// Simulate the exact state transition made by a process that acquired
		// and released the lock while this caller was queued after its first
		// read. Disable the seam before entering the winning recovery.
		packageProjectionBeforeLockHook = nil
		recovered, err := recoverPendingPackageProjection(t.Context(), cfg, commonFlags{recover: true, workers: 1, chunk: 1}, "add", keyPath, "", &stdout, &stderr)
		if err != nil || !recovered {
			return errors.Join(err, errors.New("winning package recovery did not converge"))
		}
		return nil
	}
	t.Cleanup(func() { packageProjectionBeforeLockHook = previousBeforeLock })
	stdout.Reset()
	stderr.Reset()
	recovered, err := recoverPendingPackageProjection(t.Context(), cfg, commonFlags{recover: true, workers: 1, chunk: 1}, "add", keyPath, "", &stdout, &stderr)
	if err != nil || !recovered || !strings.Contains(stdout.String(), "already recovered while waiting for the state lock") {
		t.Fatalf("queued recovery recovered=%t err=%v stdout=%s stderr=%s", recovered, err, stdout.String(), stderr.String())
	}
	if _, exists, err := readPackageProjectionIntent(cfg.StatePath()); err != nil || exists {
		t.Fatalf("queued recovery retained package bridge exists=%t err=%v", exists, err)
	}
}

func TestPackageProjectionRecoveryRejectsIntentDisappearanceWithoutCompletionReceipt(t *testing.T) {
	_, configPath, packagePath, keyPath := preparePackageNoopDEB(t)
	previousMutation := packageProjectionMutationHook
	packageProjectionMutationHook = func(phase string) error {
		if phase == "after-fence-before-apply" {
			return errors.New("seed package bridge for disappearance proof")
		}
		return nil
	}
	t.Cleanup(func() { packageProjectionMutationHook = previousMutation })
	var stdout, stderr bytes.Buffer
	if err := runAdd(t.Context(), []string{packagePath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); err == nil {
		t.Fatal("package disappearance bridge seed unexpectedly succeeded")
	}
	packageProjectionMutationHook = nil
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	intent, exists, err := readPackageProjectionIntent(cfg.StatePath())
	if err != nil || !exists {
		t.Fatalf("seed package bridge exists=%t err=%v", exists, err)
	}
	previousBeforeLock := packageProjectionBeforeLockHook
	packageProjectionBeforeLockHook = func() error {
		packageProjectionBeforeLockHook = nil
		return os.Remove(filepath.Join(cfg.StatePath(), packageProjectionIntentRelative))
	}
	t.Cleanup(func() { packageProjectionBeforeLockHook = previousBeforeLock })
	stdout.Reset()
	stderr.Reset()
	recovered, err := recoverPendingPackageProjection(t.Context(), cfg, commonFlags{recover: true, workers: 1, chunk: 1}, "add", keyPath, "", &stdout, &stderr)
	if err == nil || !recovered || !strings.Contains(err.Error(), "without an exact durable completion receipt") {
		t.Fatalf("intent disappearance recovered=%t err=%v stdout=%s stderr=%s", recovered, err, stdout.String(), stderr.String())
	}
	if _, receiptExists, err := readPackageProjectionCompletionReceipt(cfg.StatePath(), intent.ID); err != nil || receiptExists {
		t.Fatalf("abnormal intent deletion produced completion receipt exists=%t err=%v", receiptExists, err)
	}
	if _, transactionExists, err := state.New(cfg.StatePath()).Transaction(intent.TransactionID); err != nil || transactionExists {
		t.Fatalf("abnormal intent deletion created canonical transaction exists=%t err=%v", transactionExists, err)
	}
}

func TestPackageProjectionCompletionIgnoresOrphanStageCleanupFailure(t *testing.T) {
	root, configPath, packagePath, keyPath := preparePackageNoopDEB(t)
	previousMutation := packageProjectionMutationHook
	packageProjectionMutationHook = func(phase string) error {
		if phase == "after-fence-before-apply" {
			return errors.New("seed package bridge for cleanup boundary")
		}
		return nil
	}
	t.Cleanup(func() { packageProjectionMutationHook = previousMutation })
	var stdout, stderr bytes.Buffer
	if err := runAdd(t.Context(), []string{packagePath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); err == nil {
		t.Fatal("package cleanup bridge seed unexpectedly succeeded")
	}
	packageProjectionMutationHook = nil
	stateRoot := filepath.Join(root, ".sow")
	intent, exists, err := readPackageProjectionIntent(stateRoot)
	if err != nil || !exists || len(intent.Units) != 1 {
		t.Fatalf("cleanup package bridge exists=%t intent=%+v err=%v", exists, intent, err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ensurePackageProjectionCanonical(t.Context(), cfg, state.New(stateRoot), intent); err != nil {
		t.Fatalf("complete cleanup-boundary canonical transaction: %v", err)
	}
	stage := filepath.Join(stateRoot, intent.Units[0].StageRelative)
	backup := stage + ".cleanup-backup"
	previousCleanup := packageProjectionCleanupHook
	packageProjectionCleanupHook = func(packageProjectionIntent) {
		if err := os.Rename(stage, backup); err != nil {
			t.Errorf("move cleanup stage: %v", err)
			return
		}
		if err := os.Mkdir(stage, 0o700); err != nil {
			t.Errorf("replace cleanup stage with directory: %v", err)
			return
		}
		if err := os.WriteFile(filepath.Join(stage, "busy"), []byte("busy"), 0o600); err != nil {
			t.Errorf("make cleanup directory non-empty: %v", err)
		}
	}
	t.Cleanup(func() { packageProjectionCleanupHook = previousCleanup })
	if err := removePackageProjectionIntent(stateRoot, intent); err != nil {
		t.Fatalf("post-completion orphan cleanup leaked an error: %v", err)
	}
	if _, exists, err := readPackageProjectionIntent(stateRoot); err != nil || exists {
		t.Fatalf("durably completed intent reappeared exists=%t err=%v", exists, err)
	}
	if _, err := os.Stat(filepath.Join(stage, "busy")); err != nil {
		t.Fatalf("test did not retain the injected orphan stage: %v", err)
	}
	packageProjectionCleanupHook = nil
	if err := os.RemoveAll(stage); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, stage); err != nil {
		t.Fatal(err)
	}
	if err := cleanupPackageProjectionIntentResidue(stateRoot, true); err != nil {
		t.Fatalf("later orphan cleanup did not converge: %v", err)
	}
	if _, err := os.Stat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan package stage remains after retry: %v", err)
	}
}

func writeExpiredPackageProjectionSigningKey(t *testing.T, root, keyPath string) ([]byte, time.Time, time.Time) {
	t.Helper()
	created := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	entity, err := openpgp.NewEntity("Expiring SOW package projection", "", "projection-expiry@example.invalid", &packet.Config{
		Time: func() time.Time { return created }, RSABits: 2048, KeyLifetimeSecs: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	armored, err := armor.Encode(&private, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(armored, &packet.Config{Time: func() time.Time { return created }}); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	var public bytes.Buffer
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, private.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "repository-public.pgp"), public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	validAt := created.Add(30 * time.Second)
	expiredAt := created.Add(2 * time.Minute)
	return append([]byte(nil), private.Bytes()...), validAt, expiredAt
}

func TestPackageProjectionFrozenSigningTimeCrossesKeyExpiryOnlyForExactRecovery(t *testing.T) {
	root, configPath, packagePath, keyPath := preparePackageNoopDEB(t)
	privateKey, validAt, expiredAt := writeExpiredPackageProjectionSigningKey(t, root, keyPath)
	previousNow := packageProjectionNow
	packageProjectionNow = func() time.Time { return validAt }
	t.Cleanup(func() { packageProjectionNow = previousNow })
	previousHook := packageProjectionMutationHook
	stopBeforeCommit := errors.New("controlled stop before canonical commit")
	packageProjectionMutationHook = func(phase string) error {
		if phase == "after-transaction-intent-before-commit" {
			return stopBeforeCommit
		}
		return nil
	}
	t.Cleanup(func() { packageProjectionMutationHook = previousHook })
	var stdout, stderr bytes.Buffer
	addErr := runAdd(t.Context(), []string{packagePath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if addErr == nil || !strings.Contains(addErr.Error(), stopBeforeCommit.Error()) {
		t.Fatalf("package projection did not stop at frozen pre-commit intent err=%v stdout=%s stderr=%s", addErr, stdout.String(), stderr.String())
	}
	packageProjectionMutationHook = nil
	stateRoot := filepath.Join(root, config.StateDirectory)
	intent, exists, err := readPackageProjectionIntent(stateRoot)
	if err != nil || !exists || intent.Schema != packageProjectionIntentSchema || intent.SigningTime != validAt.Format(time.RFC3339) {
		t.Fatalf("frozen package intent exists=%t intent=%+v err=%v", exists, intent, err)
	}
	canonical := state.New(stateRoot)
	record, exists, err := canonical.Transaction(intent.TransactionID)
	if err != nil || !exists || record.Phase != "intent" || !record.Commit.IsZero() {
		t.Fatalf("pre-expiry transaction exists=%t record=%+v err=%v", exists, record, err)
	}
	legacy := intent
	legacy.Schema = "sow-package-projection-intent/v1"
	legacy.ID, err = packageProjectionIntentID(legacy)
	if err != nil || legacy.validate() == nil {
		t.Fatalf("legacy package intent schema was accepted err=%v", err)
	}
	missingTime := intent
	missingTime.SigningTime = ""
	missingTime.Message = packageProjectionMessage(missingTime.Operation, missingTime.Family, missingTime.SigningTime, missingTime.TransactionID, len(missingTime.Units), missingTime.RepositoryKeySHA256, missingTime.YUMPackageKeyringSHA256)
	missingTime.ID, err = packageProjectionIntentID(missingTime)
	if err != nil || missingTime.validate() == nil {
		t.Fatalf("package intent without signing time was accepted err=%v", err)
	}
	missingAttestation := intent
	missingAttestation.Attestation = ""
	missingAttestation.ID, err = packageProjectionIntentID(missingAttestation)
	if err != nil || missingAttestation.validate() == nil {
		t.Fatalf("package intent without signed attestation was accepted err=%v", err)
	}
	if err := os.Remove(packagePath); err != nil {
		t.Fatal(err)
	}
	packageProjectionNow = func() time.Time { return expiredAt }
	if recoveredAt, err := requirePackageProjectionSigningSecret(intent, privateKey, nil); err != nil || !recoveredAt.Equal(validAt) {
		t.Fatalf("exact recovery did not use frozen valid time recovered_at=%s err=%v", recoveredAt, err)
	}
	stdout.Reset()
	stderr.Reset()
	code := Main([]string{"add", "--config", configPath, "--repo", "deb-test", "--recover", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("expired-key exact inputless recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, exists, err := readPackageProjectionIntent(stateRoot); err != nil || exists {
		t.Fatalf("recovered package intent remains exists=%t err=%v", exists, err)
	}
	record, exists, err = canonical.Transaction(intent.TransactionID)
	if err != nil || !exists || record.Phase != "complete" || record.Commit.IsZero() {
		t.Fatalf("recovered transaction exists=%t record=%+v err=%v", exists, record, err)
	}
	release, err := os.ReadFile(filepath.Join(root, ".sow", "materialized", "beta", "apt", "test", "dists", "jammy", "Release"))
	if err != nil {
		t.Fatal(err)
	}
	inRelease, err := os.ReadFile(filepath.Join(root, ".sow", "materialized", "beta", "apt", "test", "dists", "jammy", "InRelease"))
	if err != nil {
		t.Fatal(err)
	}
	detached, err := os.ReadFile(filepath.Join(root, ".sow", "materialized", "beta", "apt", "test", "dists", "jammy", "Release.gpg"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := aptrepo.NewSigner(bytes.NewReader(privateKey), nil)
	if err != nil || signer.Verify(release, inRelease, detached, validAt) != nil {
		t.Fatalf("recovered APT metadata was not signed at frozen time: %v", err)
	}
	if err := signer.Verify(release, inRelease, detached, expiredAt); err == nil {
		t.Fatal("recovered APT signatures were accepted at the expired key time")
	}
	beforeRejectedAdd, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	novel := writeSyncMinimalDEB(t, root, "expired-key-new-work", "2.0", "arm64")
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"add", novel, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code == ExitOK {
		t.Fatalf("expired key authorized a new CLI package transaction stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	if after, err := canonical.HeadHash(); err != nil || after != beforeRejectedAdd {
		t.Fatalf("rejected expired-key add changed canonical HEAD before=%s after=%s err=%v", beforeRejectedAdd, after, err)
	}
	if _, exists, err := readPackageProjectionIntent(stateRoot); err != nil || exists {
		t.Fatalf("rejected expired-key add created an intent exists=%t err=%v", exists, err)
	}
	newSnapshot := &materializationTrustSnapshot{repositoryKeySHA256: strings.Repeat("a", 64), yum: make(map[string]materializationYUMTrust)}
	if err := freezePackageProjectionSigningTime(newSnapshot, "apt", privateKey, nil); err == nil || !strings.Contains(err.Error(), "not valid at intent creation") {
		t.Fatalf("expired key authorized a new package projection: %v", err)
	}
	for _, invalid := range []string{"", validAt.Add(time.Nanosecond).Format(time.RFC3339Nano), validAt.Format("2006-01-02T15:04:05+00:00")} {
		if _, err := parsePackageProjectionSigningTime(invalid); err == nil {
			t.Fatalf("non-canonical signing time %q was accepted", invalid)
		}
	}
}

func TestPackageProjectionSignedIntentRejectsRehashedHistoricalTimeBeforeTransactionJournal(t *testing.T) {
	root, configPath, packagePath, keyPath := preparePackageNoopDEB(t)
	_, validAt, expiredAt := writeExpiredPackageProjectionSigningKey(t, root, keyPath)
	previousNow := packageProjectionNow
	packageProjectionNow = func() time.Time { return validAt }
	t.Cleanup(func() { packageProjectionNow = previousNow })
	previousHook := packageProjectionMutationHook
	packageProjectionMutationHook = func(phase string) error {
		if phase == "after-fence-before-apply" {
			return errors.New("controlled stop after signed package bridge")
		}
		return nil
	}
	t.Cleanup(func() { packageProjectionMutationHook = previousHook })
	var stdout, stderr bytes.Buffer
	if err := runAdd(t.Context(), []string{packagePath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); err == nil {
		t.Fatal("signed package bridge seed unexpectedly succeeded")
	}
	packageProjectionMutationHook = nil
	stateRoot := filepath.Join(root, config.StateDirectory)
	base, exists, err := readPackageProjectionIntent(stateRoot)
	if err != nil || !exists {
		t.Fatalf("signed package bridge exists=%t err=%v", exists, err)
	}
	canonical := state.New(stateRoot)
	if _, exists, err := canonical.Transaction(base.TransactionID); err != nil || exists {
		t.Fatalf("bridge-only crash unexpectedly has transaction journal exists=%t err=%v", exists, err)
	}
	candidate := base
	candidate.SigningTime = validAt.Add(-time.Second).Format(time.RFC3339)
	candidate.Message = packageProjectionMessage(candidate.Operation, candidate.Family, candidate.SigningTime, candidate.TransactionID, len(candidate.Units), candidate.RepositoryKeySHA256, candidate.YUMPackageKeyringSHA256)
	candidate.ID, err = packageProjectionIntentID(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePackageProjectionIntent(stateRoot, candidate); err != nil {
		t.Fatalf("write structurally valid rehashed signing-time candidate: %v", err)
	}
	packageProjectionNow = func() time.Time { return expiredAt }
	stdout.Reset()
	stderr.Reset()
	code := Main([]string{"add", "--config", configPath, "--repo", "deb-test", "--recover", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code == ExitOK || !strings.Contains(stderr.String(), "attestation verification failed") {
		t.Fatalf("rehashed historical signing time recovered code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, exists, err := canonical.Transaction(base.TransactionID); err != nil || exists {
		t.Fatalf("rejected signing-time tamper created transaction exists=%t err=%v", exists, err)
	}
	if err := writePackageProjectionIntent(stateRoot, base); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"add", "--config", configPath, "--repo", "deb-test", "--recover", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("exact signed bridge recovery after expiry code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestYUMPackageProjectionFrozenSigningTimeRecoversAfterKeyExpiry(t *testing.T) {
	root, configPath, packagePath, keyPath := preparePackageNoopRPM(t)
	privateKey, validAt, expiredAt := writeExpiredPackageProjectionSigningKey(t, root, keyPath)
	previousNow := packageProjectionNow
	packageProjectionNow = func() time.Time { return validAt }
	t.Cleanup(func() { packageProjectionNow = previousNow })
	previousHook := packageProjectionMutationHook
	packageProjectionMutationHook = func(phase string) error {
		if phase == "after-transaction-intent-before-commit" {
			return errors.New("controlled YUM stop before canonical commit")
		}
		return nil
	}
	t.Cleanup(func() { packageProjectionMutationHook = previousHook })
	var stdout, stderr bytes.Buffer
	addErr := runAdd(t.Context(), []string{packagePath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if addErr == nil || !strings.Contains(addErr.Error(), "controlled YUM stop") {
		t.Fatalf("YUM projection did not stop at frozen intent err=%v stdout=%s stderr=%s", addErr, stdout.String(), stderr.String())
	}
	packageProjectionMutationHook = nil
	stateRoot := filepath.Join(root, config.StateDirectory)
	intent, exists, err := readPackageProjectionIntent(stateRoot)
	if err != nil || !exists || intent.Family != "yum" || intent.SigningTime != validAt.Format(time.RFC3339) {
		t.Fatalf("frozen YUM package intent exists=%t intent=%+v err=%v", exists, intent, err)
	}
	if err := os.Remove(packagePath); err != nil {
		t.Fatal(err)
	}
	packageProjectionNow = func() time.Time { return expiredAt }
	stdout.Reset()
	stderr.Reset()
	code := Main([]string{"add", "--config", configPath, "--repo", "rpm-test", "--recover", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("expired-key YUM inputless recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, exists, err := readPackageProjectionIntent(stateRoot); err != nil || exists {
		t.Fatalf("recovered YUM package intent remains exists=%t err=%v", exists, err)
	}
	repomd, err := os.ReadFile(filepath.Join(root, ".sow", "materialized", "beta", "yum", "test", "x86_64", "repodata", "repomd.xml"))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := os.ReadFile(filepath.Join(root, ".sow", "materialized", "beta", "yum", "test", "x86_64", "repodata", "repomd.xml.asc"))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(privateKey), validAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(t.Context(), bytes.NewReader(repomd), bytes.NewReader(signature)); err != nil {
		t.Fatalf("recovered YUM metadata was not signed at the frozen valid time: %v", err)
	}
}

func TestPackageProjectionPreflightRejectsRehashedOldStateBeforeGenericRecovery(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*packageProjectionIntent)
	}{
		{name: "expected-head", mutate: func(intent *packageProjectionIntent) { intent.ExpectedHead = strings.Repeat("a", 40) }},
		{name: "expected-ref", mutate: func(intent *packageProjectionIntent) { intent.Units[0].ExpectedRef = strings.Repeat("b", 40) }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			root, configPath, packagePath, keyPath := preparePackageNoopDEB(t)
			command := exec.Command(os.Args[0], "-test.run=^TestPackageProjectionIntentRecoversInputlessAfterCommitBeforeMaterialization$")
			command.Env = append(os.Environ(),
				"SOW_TEST_PACKAGE_PROJECTION_CRASH=1",
				"SOW_TEST_PACKAGE_PROJECTION_PHASE=after-canonical-commit-before-ref",
				"SOW_TEST_PACKAGE_PROJECTION_OPERATION=add",
				"SOW_TEST_PACKAGE_PROJECTION_FAMILY=apt",
				"SOW_TEST_PACKAGE_PROJECTION_CONFIG="+configPath,
				"SOW_TEST_PACKAGE_PROJECTION_KEY="+keyPath,
				"SOW_TEST_PACKAGE_PROJECTION_INPUT="+packagePath,
			)
			output, err := command.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 94 {
				t.Fatalf("package preflight crash helper err=%v output=%s", err, output)
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			base, exists, err := readPackageProjectionIntent(filepath.Join(root, ".sow"))
			if err != nil || !exists {
				t.Fatalf("read package preflight bridge exists=%t err=%v", exists, err)
			}
			record, exists, err := canonical.Transaction(base.TransactionID)
			if err != nil || !exists || record.Phase != "committed" {
				t.Fatalf("package preflight transaction exists=%t record=%+v err=%v", exists, record, err)
			}
			headBefore, err := canonical.HeadHash()
			if err != nil {
				t.Fatal(err)
			}
			ref := plumbing.ReferenceName(base.Units[0].ViewRef)
			if _, exists, err := canonical.Ref(ref); err != nil || exists {
				t.Fatalf("pre-recovery ref unexpectedly advanced exists=%t err=%v", exists, err)
			}
			worktreePath := filepath.Join(root, ".sow", "state", filepath.FromSlash(base.Units[0].ViewPath))
			worktreeWitness := capturePackageNoopWitnesses(t, worktreePath)
			candidate := base
			candidate.Units = append([]packageProjectionIntentUnit(nil), base.Units...)
			test.mutate(&candidate)
			candidate.ID, err = packageProjectionIntentID(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := writePackageProjectionIntent(filepath.Join(root, ".sow"), candidate); err != nil {
				t.Fatalf("write rehashed package old-state tamper: %v", err)
			}
			var stdout, stderr bytes.Buffer
			code := Main([]string{"add", "--config", configPath, "--repo", "deb-test", "--recover", "--gpg-private-key-file", keyPath}, &stdout, &stderr)
			if code == ExitOK {
				t.Fatalf("rehashed package old-state tamper recovered stdout=%s stderr=%s", stdout.String(), stderr.String())
			}
			headAfter, err := canonical.HeadHash()
			if err != nil || headAfter != headBefore {
				t.Fatalf("rejected preflight moved HEAD before=%s after=%s err=%v", headBefore, headAfter, err)
			}
			if _, exists, err := canonical.Ref(ref); err != nil || exists {
				t.Fatalf("rejected preflight advanced ref exists=%t err=%v", exists, err)
			}
			assertPackageNoopWitnessesUnchanged(t, worktreeWitness)
			recordAfter, exists, err := canonical.Transaction(base.TransactionID)
			if err != nil || !exists || recordAfter.Phase != "committed" {
				t.Fatalf("rejected preflight mutated transaction exists=%t record=%+v err=%v", exists, recordAfter, err)
			}
			if err := writePackageProjectionIntent(filepath.Join(root, ".sow"), base); err != nil {
				t.Fatal(err)
			}
			stdout.Reset()
			stderr.Reset()
			if code := Main([]string{"add", "--config", configPath, "--repo", "deb-test", "--recover", "--gpg-private-key-file", keyPath}, &stdout, &stderr); code != ExitOK {
				t.Fatalf("exact package preflight recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestPackageProjectionPreflightRejectsStageAndTrustDriftBeforeGenericRecovery(t *testing.T) {
	tests := []struct {
		name   string
		family string
		mutate func(*testing.T, string, string, packageProjectionIntent) func()
	}{
		{
			name: "staged-manifest-tamper", family: "apt",
			mutate: func(t *testing.T, root, _ string, intent packageProjectionIntent) func() {
				stage := filepath.Join(root, ".sow", intent.Units[0].StageRelative)
				original, err := os.ReadFile(stage)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(stage, []byte("tampered staged manifest\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return func() {
					if err := os.WriteFile(stage, original, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			name: "missing-private-key", family: "apt",
			mutate: func(t *testing.T, _ string, keyPath string, _ packageProjectionIntent) func() {
				original, err := os.ReadFile(keyPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(keyPath); err != nil {
					t.Fatal(err)
				}
				return func() {
					if err := os.WriteFile(keyPath, original, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			name: "same-path-repository-key-rotation", family: "apt",
			mutate: func(t *testing.T, root, keyPath string, _ packageProjectionIntent) func() {
				originalPrivate, err := os.ReadFile(keyPath)
				if err != nil {
					t.Fatal(err)
				}
				publicPath := filepath.Join(root, "repository-public.pgp")
				originalPublic, err := os.ReadFile(publicPath)
				if err != nil {
					t.Fatal(err)
				}
				_, rotatedPath := writeMaterializeSigningKey(t, root)
				if rotatedPath != keyPath {
					t.Fatalf("same-path signing rotation changed path %s -> %s", keyPath, rotatedPath)
				}
				return func() {
					if err := os.WriteFile(keyPath, originalPrivate, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(publicPath, originalPublic, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			name: "same-path-rpm-keyring-rotation", family: "yum",
			mutate: func(t *testing.T, root, _ string, _ packageProjectionIntent) func() {
				keyringPath := filepath.Join(root, "package-trust.asc")
				original, err := os.ReadFile(keyringPath)
				if err != nil {
					t.Fatal(err)
				}
				rotated, err := os.ReadFile(filepath.Join(root, "repository-public.pgp"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(keyringPath, rotated, 0o644); err != nil {
					t.Fatal(err)
				}
				return func() {
					if err := os.WriteFile(keyringPath, original, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			var root, configPath, packagePath, keyPath, repo string
			if test.family == "apt" {
				root, configPath, packagePath, keyPath = preparePackageNoopDEB(t)
				repo = "deb-test"
			} else {
				root, configPath, packagePath, keyPath = preparePackageNoopRPM(t)
				repo = "rpm-test"
			}
			command := exec.Command(os.Args[0], "-test.run=^TestPackageProjectionIntentRecoversInputlessAfterCommitBeforeMaterialization$")
			command.Env = append(os.Environ(),
				"SOW_TEST_PACKAGE_PROJECTION_CRASH=1",
				"SOW_TEST_PACKAGE_PROJECTION_PHASE=after-canonical-commit-before-ref",
				"SOW_TEST_PACKAGE_PROJECTION_OPERATION=add",
				"SOW_TEST_PACKAGE_PROJECTION_FAMILY="+test.family,
				"SOW_TEST_PACKAGE_PROJECTION_CONFIG="+configPath,
				"SOW_TEST_PACKAGE_PROJECTION_KEY="+keyPath,
				"SOW_TEST_PACKAGE_PROJECTION_INPUT="+packagePath,
			)
			output, err := command.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 94 {
				t.Fatalf("package projection preflight crash err=%v output=%s", err, output)
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			intent, exists, err := readPackageProjectionIntent(filepath.Join(root, ".sow"))
			if err != nil || !exists {
				t.Fatalf("read package projection intent exists=%t err=%v", exists, err)
			}
			headBefore, err := canonical.HeadHash()
			if err != nil {
				t.Fatal(err)
			}
			ref := plumbing.ReferenceName(intent.Units[0].ViewRef)
			if _, exists, err := canonical.Ref(ref); err != nil || exists {
				t.Fatalf("package projection preflight ref already advanced exists=%t err=%v", exists, err)
			}
			recordBefore, exists, err := canonical.Transaction(intent.TransactionID)
			if err != nil || !exists || recordBefore.Phase != "committed" {
				t.Fatalf("package projection preflight transaction exists=%t record=%+v err=%v", exists, recordBefore, err)
			}
			restore := test.mutate(t, root, keyPath, intent)
			var stdout, stderr bytes.Buffer
			code := Main([]string{"add", "--config", configPath, "--repo", repo, "--recover", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
			if code == ExitOK {
				t.Fatalf("package projection drift recovered stdout=%s stderr=%s", stdout.String(), stderr.String())
			}
			headAfter, err := canonical.HeadHash()
			if err != nil || headAfter != headBefore {
				t.Fatalf("package projection drift moved HEAD before=%s after=%s err=%v", headBefore, headAfter, err)
			}
			if _, exists, err := canonical.Ref(ref); err != nil || exists {
				t.Fatalf("package projection drift advanced ref exists=%t err=%v", exists, err)
			}
			recordAfter, exists, err := canonical.Transaction(intent.TransactionID)
			if err != nil || !exists || recordAfter.Phase != "committed" || recordAfter.Commit != recordBefore.Commit {
				t.Fatalf("package projection drift changed transaction exists=%t before=%+v after=%+v err=%v", exists, recordBefore, recordAfter, err)
			}
			current, exists, err := readPackageProjectionIntent(filepath.Join(root, ".sow"))
			if err != nil || !exists || current.ID != intent.ID {
				t.Fatalf("package projection drift cleared bridge exists=%t current=%+v err=%v", exists, current, err)
			}
			restore()
			stdout.Reset()
			stderr.Reset()
			if code := Main([]string{"add", "--config", configPath, "--repo", repo, "--recover", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitOK {
				t.Fatalf("restored package projection recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}

const packageNoopMixedConfig = `schema: sow/v1
state: {}
gpg:
  public_key: repository-public.pgp
pools:
  public: {}
  gated: {}
repos:
  - id: deb-test
    type: apt
    path: apt/test
    default_pool: public
    arches: [arm64]
    os: {family: ubuntu, suite: jammy, lifecycle: active}
    apt: {suites: [jammy], components: [main]}
  - id: rpm-test
    type: yum
    path: yum/test/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`

const packageMultiAPTRecoveryConfig = `schema: sow/v1
state: {}
gpg:
  public_key: repository-public.pgp
pools:
  public: {}
  gated: {}
repos:
  - id: apt-one
    type: apt
    path: apt/one
    default_pool: public
    arches: [arm64]
    os: {family: ubuntu, suite: jammy, lifecycle: active}
    apt: {suites: [jammy], components: [main]}
  - id: apt-two
    type: apt
    path: apt/two
    default_pool: public
    arches: [amd64]
    os: {family: ubuntu, suite: jammy, lifecycle: active}
    apt: {suites: [jammy], components: [main]}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
