package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

func TestOfflineArchiveStableAndSnapshotCannotLaunderIntoPublicAssets(t *testing.T) {
	root, configPath := newOfflineArchiveTaintFixture(t)
	secret := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(secret, []byte("licensed payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "add", secret, "--config", configPath, "--repo", "source-gated", "--dest", "secret.bin")

	stableRejected := filepath.Join(root, "offline", "stable-public.tgz")
	code, stdout, stderr := runArchiveTaintCLI(t,
		"materialize", "stable", "--config", configPath, "--repo", "source-gated",
		"--tgz", stableRejected, "--asset-repo", "public-assets", "--asset-dest", "stable.tgz",
	)
	if code != ExitVerification || !strings.Contains(stderr, "confidentiality closure rejects") {
		t.Fatalf("stable public adoption was not rejected code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	assertArchiveTaintPathAbsent(t, stableRejected)

	snapshotID, err := views.SnapshotID("all", timeNowUTC())
	if err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "promote", "stable", snapshotID, "--config", configPath, "--repo", "source-gated")
	snapshotRejected := filepath.Join(root, "offline", "snapshot-public.tgz")
	code, stdout, stderr = runArchiveTaintCLI(t,
		"materialize", snapshotID, "--config", configPath, "--repo", "source-gated",
		"--tgz", snapshotRejected, "--asset-repo", "public-assets", "--asset-dest", "snapshot.tgz",
	)
	if code != ExitVerification || !strings.Contains(stderr, "confidentiality closure rejects") {
		t.Fatalf("snapshot public adoption was not rejected code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	assertArchiveTaintPathAbsent(t, snapshotRejected)

	for _, source := range []struct {
		name string
		ref  string
	}{
		{name: "stable", ref: "stable"},
		{name: "snapshot", ref: snapshotID},
	} {
		t.Run(source.name+"-archive-only-digest-taint", func(t *testing.T) {
			archive := filepath.Join(root, "offline", source.name+"-only.tgz")
			runArchiveTaintOK(t, "materialize", source.ref, "--config", configPath, "--repo", "source-gated", "--tgz", archive)
			inspected, err := inspectOfflineArchiveInput(archive)
			if err != nil || inspected.Marker == nil || inspected.Marker.Access != "pro" || inspected.Marker.Confidentiality != "gated" {
				t.Fatalf("archive marker=%+v err=%v", inspected.Marker, err)
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			receipt, exists, err := readOfflineArchiveTaintReceipt(canonical, inspected.Object.HashString())
			if err != nil || !exists || receipt.Confidentiality != "gated" {
				t.Fatalf("archive receipt exists=%t receipt=%+v err=%v", exists, receipt, err)
			}

			aliases := make(map[string]string)
			copied := filepath.Join(t.TempDir(), "renamed.bin")
			body, err := os.ReadFile(archive)
			if err != nil || os.WriteFile(copied, body, 0o600) != nil {
				t.Fatal(err)
			}
			aliases["copy-rename"] = copied
			hardlink := filepath.Join(t.TempDir(), "hardlink.bin")
			if err := os.Link(archive, hardlink); err != nil {
				t.Fatal(err)
			}
			aliases["hardlink"] = hardlink
			for alias, input := range aliases {
				code, stdout, stderr := runArchiveTaintCLI(t, "add", input, "--config", configPath, "--repo", "public-assets", "--dest", source.name+"-"+alias+".bin")
				if code != ExitVerification || !strings.Contains(stderr, "public") {
					t.Fatalf("%s public alias accepted code=%d stdout=%s stderr=%s", alias, code, stdout, stderr)
				}
			}
			runArchiveTaintOK(t, "add", copied, "--config", configPath, "--repo", "gated-assets", "--dest", source.name+"-allowed.bin")
		})
	}
}

func TestOfflineArchivePublicLatestControlAndPolicyMarkerDomainSeparation(t *testing.T) {
	root, configPath := newOfflineArchiveTaintFixture(t)
	public := filepath.Join(t.TempDir(), "public.bin")
	if err := os.WriteFile(public, []byte("public payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "add", public, "--config", configPath, "--repo", "public-assets", "--dest", "payload.bin")
	runArchiveTaintOK(t, "promote", "beta", "latest", "--config", configPath, "--repo", "public-assets")
	archive := filepath.Join(root, "offline", "latest.tgz")
	runArchiveTaintOK(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", archive,
		"--asset-repo", "public-assets", "--asset-dest", "bundles/latest.tgz",
	)
	inspected, err := inspectOfflineArchiveInput(archive)
	if err != nil || inspected.Marker == nil || inspected.Marker.Access != "public" || inspected.Marker.Confidentiality != "public" {
		t.Fatalf("public marker=%+v err=%v", inspected.Marker, err)
	}
	first, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "promote", "beta", "latest", "--config", configPath, "--repo", "public-assets")
	runArchiveTaintOK(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", archive,
		"--asset-repo", "public-assets", "--asset-dest", "bundles/latest.tgz",
	)
	second, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("self-excluded latest archive marker or bytes changed on replay")
	}

	// The marker is a standard gzip FCOMMENT; ordinary gzip/tar consumers still
	// see the unchanged tar stream.
	compressed, err := gzip.NewReader(bytes.NewReader(second))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(compressed.Header.Comment, offlineArchiveMarkerPrefix) {
		t.Fatalf("gzip comment=%q", compressed.Header.Comment)
	}
	if _, err := io.Copy(io.Discard, compressed); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineArchiveDestinationParentSymlinkSwapIsRootBound(t *testing.T) {
	for _, adoption := range []bool{false, true} {
		t.Run(map[bool]string{false: "archive-only", true: "asset-adoption"}[adoption], func(t *testing.T) {
			root, configPath := newOfflineArchiveTaintFixture(t)
			input := filepath.Join(t.TempDir(), "public.bin")
			if err := os.WriteFile(input, []byte("public\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runArchiveTaintOK(t, "add", input, "--config", configPath, "--repo", "public-assets", "--dest", "payload.bin")
			runArchiveTaintOK(t, "promote", "beta", "latest", "--config", configPath, "--repo", "public-assets")
			victim := t.TempDir()
			offline := filepath.Join(root, "offline")
			previous := archiveDestinationBeforeBindHook
			archiveDestinationBeforeBindHook = func(parent string) {
				if filepath.Clean(parent) != filepath.Clean(offline) {
					return
				}
				_ = os.RemoveAll(offline)
				_ = os.Symlink(victim, offline)
			}
			t.Cleanup(func() { archiveDestinationBeforeBindHook = previous })
			arguments := []string{"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", filepath.Join(offline, "bundle.tgz")}
			if adoption {
				arguments = append(arguments, "--asset-repo", "public-assets", "--asset-dest", "bundles/swap.tgz")
			}
			code, stdout, stderr := runArchiveTaintCLI(t, arguments...)
			if code == ExitOK || !strings.Contains(stderr, "directory segment") {
				t.Fatalf("symlink swap accepted code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			entries, err := os.ReadDir(victim)
			if err != nil || len(entries) != 0 {
				t.Fatalf("victim entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestOfflineArchiveMarkerParserLeavesOpaqueGzipUntouched(t *testing.T) {
	var body bytes.Buffer
	compressed := gzip.NewWriter(&body)
	compressed.Header.Comment = strings.Repeat("ordinary-", 100)
	if _, err := compressed.Write([]byte("opaque")); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "opaque.gz")
	if err := os.WriteFile(file, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	inspected, err := inspectOfflineArchiveInput(file)
	if err != nil || inspected.Marker != nil {
		t.Fatalf("ordinary gzip marker=%+v err=%v", inspected.Marker, err)
	}
	prefixed := filepath.Join(t.TempDir(), "prefixed-opaque.gz")
	if err := os.WriteFile(prefixed, append([]byte("ordinary-prefix\n"), body.Bytes()...), 0o600); err != nil {
		t.Fatal(err)
	}
	if inspected, err := inspectOfflineArchiveInput(prefixed); err != nil || inspected.Marker != nil {
		t.Fatalf("prefixed ordinary gzip marker=%+v err=%v", inspected.Marker, err)
	}
	if _, err := parseOfflineArchiveMarker("sow-offline-archive/v1;access=pro"); err == nil {
		t.Fatal("malformed SOW marker was accepted")
	}

	// Marker-looking bytes outside FNAME/FCOMMENT are opaque. In particular,
	// neither FEXTRA nor the bounded compressed payload may be searched as raw
	// bytes, because ordinary gzip data can contain this sequence by chance.
	prefix := []byte("sow-offline-archive/v1;not-a-header-field")
	base := []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255}
	payloadPrefix := append(append([]byte(nil), base...), prefix...)
	if marker, err := parseOfflineArchiveMarkerHeader(payloadPrefix); err != nil || marker != nil {
		t.Fatalf("compressed payload marker bytes were not opaque marker=%+v err=%v", marker, err)
	}
	extra := []byte{0x1f, 0x8b, 8, 0x04, 0, 0, 0, 0, 0, 255, byte(len(prefix)), 0}
	extra = append(extra, prefix...)
	if marker, err := parseOfflineArchiveMarkerHeader(extra); err != nil || marker != nil {
		t.Fatalf("FEXTRA marker bytes were not opaque marker=%+v err=%v", marker, err)
	}
	truncatedComment := []byte{0x1f, 0x8b, 8, 0x10, 0, 0, 0, 0, 0, 255}
	truncatedComment = append(truncatedComment, prefix...)
	if _, err := parseOfflineArchiveMarkerHeader(truncatedComment); err == nil {
		t.Fatal("confirmed truncated SOW FCOMMENT was accepted")
	}
}

func TestOfflineArchivePreReceiptFailureNeverExposesArchive(t *testing.T) {
	for _, adoption := range []bool{false, true} {
		t.Run(map[bool]string{false: "archive-only", true: "asset-adoption"}[adoption], func(t *testing.T) {
			root, configPath := newOfflineArchiveTaintFixture(t)
			input := filepath.Join(t.TempDir(), "public.bin")
			if err := os.WriteFile(input, []byte("pre-receipt public payload\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runArchiveTaintOK(t, "add", input, "--config", configPath, "--repo", "public-assets", "--dest", "payload.bin")
			runArchiveTaintOK(t, "promote", "beta", "latest", "--config", configPath, "--repo", "public-assets")
			destination := filepath.Join(root, "offline", "pre-receipt.tgz")
			canonical := state.New(filepath.Join(root, ".sow"))
			called := false
			previous := archiveBeforeTaintPrecommitHook
			archiveBeforeTaintPrecommitHook = func(result archiveResult) error {
				called = true
				if result.Path != destination || result.SHA256 == "" || result.Size == 0 {
					t.Errorf("incomplete private staged archive result=%+v", result)
				}
				if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("archive became visible before receipt: %v", err)
				}
				if _, exists, err := readOfflineArchiveTaintReceipt(canonical, result.SHA256); err != nil || exists {
					t.Errorf("receipt existed before precommit exists=%t err=%v", exists, err)
				}
				return errors.New("injected pre-receipt stop")
			}
			t.Cleanup(func() { archiveBeforeTaintPrecommitHook = previous })
			arguments := []string{"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", destination}
			if adoption {
				arguments = append(arguments, "--asset-repo", "public-assets", "--asset-dest", "bundles/pre-receipt.tgz")
			}
			code, stdout, stderr := runArchiveTaintCLI(t, arguments...)
			if code != ExitVerification || !called || !strings.Contains(stderr, "injected pre-receipt stop") {
				t.Fatalf("pre-receipt failure code=%d called=%t stdout=%s stderr=%s", code, called, stdout, stderr)
			}
			assertArchiveTaintPathAbsent(t, destination)
			if _, err := os.Lstat(filepath.Dir(destination)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("operator-visible destination parent was created before receipt: %v", err)
			}
		})
	}
}

func TestOfflineArchiveDurableStageSyncPrecedesReceipt(t *testing.T) {
	root, configPath := newOfflineArchiveTaintFixture(t)
	input := filepath.Join(t.TempDir(), "public.bin")
	if err := os.WriteFile(input, []byte("durable-stage-sync payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "add", input, "--config", configPath, "--repo", "public-assets", "--dest", "payload.bin")
	runArchiveTaintOK(t, "promote", "beta", "latest", "--config", configPath, "--repo", "public-assets")
	destination := filepath.Join(root, "offline", "stage-sync.tgz")
	canonical := state.New(filepath.Join(root, ".sow"))
	var staged archiveResult
	previousBefore := archiveBeforeTaintPrecommitHook
	previousSync := offlineArchiveProjectionStageSync
	archiveBeforeTaintPrecommitHook = func(result archiveResult) error {
		staged = result
		return nil
	}
	offlineArchiveProjectionStageSync = func(*os.Root) error { return errors.New("injected durable archive stage sync failure") }
	t.Cleanup(func() {
		archiveBeforeTaintPrecommitHook = previousBefore
		offlineArchiveProjectionStageSync = previousSync
	})
	code, stdout, stderr := runArchiveTaintCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", destination,
		"--workers", "1", "--chunk-entries", "1",
	)
	if code != ExitVerification || staged.SHA256 == "" || !strings.Contains(stderr, "injected durable archive stage sync failure") {
		t.Fatalf("stage sync fault code=%d staged=%+v stdout=%s stderr=%s", code, staged, stdout, stderr)
	}
	if _, exists, err := readOfflineArchiveTaintReceipt(canonical, staged.SHA256); err != nil || exists {
		t.Fatalf("receipt crossed failed durable stage boundary exists=%t err=%v", exists, err)
	}
	if _, exists, err := readOfflineArchiveProjectionIntent(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("intent crossed failed durable stage boundary exists=%t err=%v", exists, err)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".sow", offlineArchiveProjectionStageDir))
	if err != nil || len(entries) != 0 {
		t.Fatalf("durable stage sync failure retained unowned stage entries=%v err=%v", entries, err)
	}
	assertArchiveTaintPathAbsent(t, destination)
}

func TestOfflineArchiveStageSyncFailureReportsCleanupDrift(t *testing.T) {
	root, configPath := newOfflineArchiveTaintFixture(t)
	input := filepath.Join(t.TempDir(), "public.bin")
	if err := os.WriteFile(input, []byte("durable-stage cleanup drift\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "add", input, "--config", configPath, "--repo", "public-assets", "--dest", "payload.bin")
	runArchiveTaintOK(t, "promote", "beta", "latest", "--config", configPath, "--repo", "public-assets")
	destination := filepath.Join(root, "offline", "stage-sync-cleanup.tgz")
	stateRoot := filepath.Join(root, ".sow")
	stageDirectory := filepath.Join(stateRoot, offlineArchiveProjectionStageDir)
	canonical := state.New(stateRoot)

	var staged archiveResult
	previousBefore := archiveBeforeTaintPrecommitHook
	previousSync := offlineArchiveProjectionStageSync
	archiveBeforeTaintPrecommitHook = func(result archiveResult) error {
		staged = result
		return nil
	}
	offlineArchiveProjectionStageSync = func(*os.Root) error {
		if err := os.Chmod(stageDirectory, 0o000); err != nil {
			return err
		}
		return errors.New("injected durable archive stage sync failure")
	}
	t.Cleanup(func() {
		archiveBeforeTaintPrecommitHook = previousBefore
		offlineArchiveProjectionStageSync = previousSync
		_ = os.Chmod(stageDirectory, 0o700)
	})
	code, stdout, stderr := runArchiveTaintCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", destination,
		"--workers", "1", "--chunk-entries", "1",
	)
	archiveBeforeTaintPrecommitHook = previousBefore
	offlineArchiveProjectionStageSync = previousSync
	if code != ExitVerification || !strings.Contains(stderr, "injected durable archive stage sync failure") ||
		!strings.Contains(stderr, "offline archive projection stage cleanup failed") || !strings.Contains(stderr, "--recover") {
		t.Fatalf("stage sync cleanup drift code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if err := os.Chmod(stageDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(stageDirectory)
	if err != nil || len(entries) != 1 || !offlineArchiveProjectionStagePattern.MatchString(entries[0].Name()) {
		t.Fatalf("failed stage cleanup residue entries=%v err=%v", entries, err)
	}
	if _, exists, err := readOfflineArchiveProjectionIntent(stateRoot); err != nil || exists {
		t.Fatalf("stage sync failure installed intent exists=%t err=%v", exists, err)
	}
	if staged.SHA256 == "" {
		t.Fatal("stage sync fault did not capture archive identity")
	}
	if _, exists, err := readOfflineArchiveTaintReceipt(canonical, staged.SHA256); err != nil || exists {
		t.Fatalf("stage sync failure installed receipt exists=%t err=%v", exists, err)
	}
	assertArchiveTaintPathAbsent(t, destination)

	code, stdout, stderr = runArchiveTaintCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", destination,
		"--workers", "1", "--chunk-entries", "1", "--recover",
	)
	if code != ExitOK {
		t.Fatalf("stage sync cleanup recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	entries, err = os.ReadDir(stageDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("stage sync cleanup recovery retained stages=%v err=%v", entries, err)
	}
}

func TestOfflineArchivePreReceiptProcessCrashLeavesOnlyPrivateBytes(t *testing.T) {
	if os.Getenv("SOW_TEST_ARCHIVE_PRE_RECEIPT_CRASH") == "1" {
		archiveBeforeTaintPrecommitHook = func(archiveResult) error {
			os.Exit(91)
			return nil
		}
		var stdout, stderr bytes.Buffer
		code := Main([]string{
			"materialize", "latest", "--config", os.Getenv("SOW_TEST_ARCHIVE_CONFIG"), "--repo", "public-assets",
			"--tgz", os.Getenv("SOW_TEST_ARCHIVE_DESTINATION"), "--workers", "1", "--chunk-entries", "1",
		}, &stdout, &stderr)
		os.Exit(code)
	}

	root, configPath := newOfflineArchiveTaintFixture(t)
	input := filepath.Join(t.TempDir(), "public.bin")
	if err := os.WriteFile(input, []byte("process-crash public payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "add", input, "--config", configPath, "--repo", "public-assets", "--dest", "payload.bin")
	runArchiveTaintOK(t, "promote", "beta", "latest", "--config", configPath, "--repo", "public-assets")
	destination := filepath.Join(root, "offline", "process-crash.tgz")
	command := exec.Command(os.Args[0], "-test.run=^TestOfflineArchivePreReceiptProcessCrashLeavesOnlyPrivateBytes$")
	command.Env = append(os.Environ(),
		"SOW_TEST_ARCHIVE_PRE_RECEIPT_CRASH=1",
		"SOW_TEST_ARCHIVE_CONFIG="+configPath,
		"SOW_TEST_ARCHIVE_DESTINATION="+destination,
	)
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 91 {
		t.Fatalf("archive crash helper err=%v output=%s", err, output)
	}
	assertArchiveTaintPathAbsent(t, destination)
	if _, err := os.Lstat(filepath.Dir(destination)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("process crash created operator-visible archive parent: %v", err)
	}

	transactions := filepath.Join(root, ".sow", "transactions")
	var privateArchive string
	if err := filepath.WalkDir(transactions, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return err
		}
		inspected, err := inspectOfflineArchiveInput(name)
		if err == nil && inspected.Marker != nil {
			if privateArchive != "" {
				return errors.New("multiple private staged archives survived one crash")
			}
			privateArchive = name
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if privateArchive == "" {
		t.Fatal("process crash did not retain the completed private staged archive")
	}
	relative, err := filepath.Rel(filepath.Join(root, ".sow"), privateArchive)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("crash archive escaped private state path=%s relative=%s err=%v", privateArchive, relative, err)
	}
	code, stdout, stderr := runArchiveTaintCLI(t,
		"add", privateArchive, "--config", configPath, "--repo", "public-assets", "--dest", "must-not-import.tgz", "--recover",
	)
	if code != ExitConflict || !strings.Contains(stderr, "cannot be read from SOW private state") {
		t.Fatalf("ordinary add accepted private crash residue code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = runArchiveTaintCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", destination,
		"--workers", "1", "--chunk-entries", "1", "--recover",
	)
	if code != ExitOK {
		t.Fatalf("archive replay after process crash code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	inspected, err := inspectOfflineArchiveInput(destination)
	if err != nil || inspected.Marker == nil {
		t.Fatalf("replayed archive marker=%+v err=%v", inspected.Marker, err)
	}
	if entries, err := os.ReadDir(transactions); err != nil || len(entries) != 0 {
		t.Fatalf("archive recovery retained private transaction residue entries=%v err=%v", entries, err)
	}
}

func TestOfflineArchivePostReceiptCrashNeverStagesBytesInServedTree(t *testing.T) {
	if os.Getenv("SOW_TEST_ARCHIVE_POST_RECEIPT_CRASH") == "1" {
		archiveBeforeAtomicInstallHook = func(archiveResult) error {
			os.Exit(92)
			return nil
		}
		var stdout, stderr bytes.Buffer
		code := Main([]string{
			"materialize", "stable", "--config", os.Getenv("SOW_TEST_ARCHIVE_CONFIG"), "--repo", "source-gated",
			"--tgz", os.Getenv("SOW_TEST_ARCHIVE_DESTINATION"), "--workers", "1", "--chunk-entries", "1",
		}, &stdout, &stderr)
		os.Exit(code)
	}

	root, configPath := newOfflineArchiveTaintFixture(t)
	input := filepath.Join(t.TempDir(), "post-receipt-gated.bin")
	if err := os.WriteFile(input, []byte("post-receipt gated payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "add", input, "--config", configPath, "--repo", "source-gated", "--dest", "payload.bin")
	destination := filepath.Join(root, "offline", "post-receipt.tgz")
	command := exec.Command(os.Args[0], "-test.run=^TestOfflineArchivePostReceiptCrashNeverStagesBytesInServedTree$")
	command.Env = append(os.Environ(),
		"SOW_TEST_ARCHIVE_POST_RECEIPT_CRASH=1",
		"SOW_TEST_ARCHIVE_CONFIG="+configPath,
		"SOW_TEST_ARCHIVE_DESTINATION="+destination,
	)
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 92 {
		t.Fatalf("post-receipt crash helper err=%v output=%s", err, output)
	}
	assertArchiveTaintPathAbsent(t, destination)

	// Only the private 0700 transaction may retain the completed inode. No
	// random staging name or partial archive may appear under the tree a plain
	// static server exposes.
	if err := filepath.WalkDir(root, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		if relative == ".sow" || strings.HasPrefix(relative, ".sow"+string(filepath.Separator)) {
			if entry.IsDir() && relative == ".sow" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(entry.Name(), ".sow-archive-") {
			return fmt.Errorf("served tree retained archive staging path %s", relative)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.FileServer(http.Dir(root)))
	defer server.Close()
	for _, requestPath := range []string{"/offline/", "/offline/post-receipt.tgz"} {
		response, err := server.Client().Get(server.URL + requestPath)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal(errors.Join(readErr, closeErr))
		}
		if response.StatusCode != http.StatusNotFound || bytes.Contains(body, []byte(".sow-archive-")) {
			t.Fatalf("static server exposed post-receipt staging path=%s status=%d body=%s", requestPath, response.StatusCode, body)
		}
	}
	assertOfflineArchiveAbsentViaRealNginx(t, root)
	pending, exists, err := readOfflineArchiveProjectionIntent(filepath.Join(root, ".sow"))
	if err != nil || !exists {
		t.Fatalf("post-receipt crash lost durable archive intent exists=%t err=%v", exists, err)
	}
	stagePath := filepath.Join(root, ".sow", pending.StageRelative)
	stageBody, err := os.ReadFile(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	intentBody, err := os.ReadFile(filepath.Join(root, ".sow", offlineArchiveProjectionIntentRelative))
	if err != nil {
		t.Fatal(err)
	}
	blockedInput := filepath.Join(t.TempDir(), "must-block.bin")
	if err := os.WriteFile(blockedInput, []byte("must not advance while archive intent is pending\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runArchiveTaintCLI(t, "add", blockedInput, "--config", configPath, "--repo", "source-gated", "--dest", "must-block.bin", "--recover")
	if code != ExitConflict || !strings.Contains(stderr, "pending offline archive projection") {
		t.Fatalf("pending archive intent did not fence canonical mutation code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = runArchiveTaintCLI(t, "verify", "--layer", "L1", "--config", configPath, "--recover", "--workers", "1")
	if code != ExitVerification || !strings.Contains(stdout+stderr, "OFFLINE_ARCHIVE_PROJECTION_RECOVERY_REQUIRED") {
		t.Fatalf("L1 audit missed pending archive intent code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	// Simulate canonical state advanced by an older writer that did not know the
	// new fence: temporarily remove the exact durable bridge, commit a new asset,
	// then restore the original intent and stable inode bytes. Recovery must use
	// the frozen refs and digest, not rebuild from the now-current stable view.
	if err := os.Remove(filepath.Join(root, ".sow", offlineArchiveProjectionIntentRelative)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(stagePath); err != nil {
		t.Fatal(err)
	}
	advancedInput := filepath.Join(t.TempDir(), "advanced.bin")
	if err := os.WriteFile(advancedInput, []byte("advanced stable view after interrupted archive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "add", advancedInput, "--config", configPath, "--repo", "source-gated", "--dest", "advanced.bin")
	if err := os.WriteFile(stagePath, stageBody, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".sow", offlineArchiveProjectionIntentRelative), intentBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syncLocalDirectory(filepath.Dir(stagePath)); err != nil {
		t.Fatal(err)
	}
	if err := syncLocalDirectory(filepath.Join(root, ".sow")); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runArchiveTaintCLI(t,
		"materialize", "stable", "--config", configPath, "--repo", "source-gated", "--tgz", destination,
		"--workers", "1", "--chunk-entries", "1", "--recover",
	)
	if code != ExitOK {
		t.Fatalf("post-receipt replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	inspected, err := inspectOfflineArchiveInput(destination)
	if err != nil || inspected.Marker == nil || inspected.Marker.Confidentiality != "gated" {
		t.Fatalf("post-receipt replay marker=%+v err=%v", inspected.Marker, err)
	}
	if inspected.Object.HashString() != pending.ArchiveSHA256 {
		t.Fatalf("recovery rebound interrupted archive got=%s want=%s", inspected.Object.HashString(), pending.ArchiveSHA256)
	}
	currentDestination := filepath.Join(root, "offline", "post-receipt-current.tgz")
	runArchiveTaintOK(t,
		"materialize", "stable", "--config", configPath, "--repo", "source-gated", "--tgz", currentDestination,
		"--workers", "1", "--chunk-entries", "1",
	)
	current, err := inspectOfflineArchiveInput(currentDestination)
	if err != nil || current.Object.HashString() == pending.ArchiveSHA256 {
		t.Fatalf("subsequent invocation did not publish advanced view object=%s old=%s err=%v", current.Object.HashString(), pending.ArchiveSHA256, err)
	}
}

func TestOfflineArchivePostLinkCrashReplayConverges(t *testing.T) {
	if phase := os.Getenv("SOW_TEST_ARCHIVE_POST_LINK_PHASE"); phase != "" {
		switch phase {
		case "before-directory-sync":
			archiveAfterAtomicInstallHook = func(archiveResult) error { os.Exit(93); return nil }
		case "after-directory-sync":
			archiveAfterDestinationSyncHook = func(archiveResult) error { os.Exit(94); return nil }
		default:
			os.Exit(95)
		}
		var stdout, stderr bytes.Buffer
		code := Main([]string{
			"materialize", "stable", "--config", os.Getenv("SOW_TEST_ARCHIVE_CONFIG"), "--repo", "source-gated",
			"--tgz", os.Getenv("SOW_TEST_ARCHIVE_DESTINATION"), "--workers", "1", "--chunk-entries", "1",
		}, &stdout, &stderr)
		os.Exit(code)
	}

	for _, phase := range []struct {
		name string
		exit int
	}{
		{name: "before-directory-sync", exit: 93},
		{name: "after-directory-sync", exit: 94},
	} {
		phase := phase
		t.Run(phase.name, func(t *testing.T) {
			root, configPath := newOfflineArchiveTaintFixture(t)
			input := filepath.Join(t.TempDir(), "gated.bin")
			if err := os.WriteFile(input, []byte("post-link replay payload\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runArchiveTaintOK(t, "add", input, "--config", configPath, "--repo", "source-gated", "--dest", "payload.bin")
			destination := filepath.Join(root, "offline", phase.name+".tgz")
			command := exec.Command(os.Args[0], "-test.run=^TestOfflineArchivePostLinkCrashReplayConverges$")
			command.Env = append(os.Environ(),
				"SOW_TEST_ARCHIVE_POST_LINK_PHASE="+phase.name,
				"SOW_TEST_ARCHIVE_CONFIG="+configPath,
				"SOW_TEST_ARCHIVE_DESTINATION="+destination,
			)
			output, err := command.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != phase.exit {
				t.Fatalf("post-link crash phase=%s err=%v output=%s", phase.name, err, output)
			}
			if _, err := os.Stat(destination); err != nil {
				t.Fatalf("post-link crash lost visible final name phase=%s: %v", phase.name, err)
			}
			code, stdout, stderr := runArchiveTaintCLI(t,
				"materialize", "stable", "--config", configPath, "--repo", "source-gated", "--tgz", destination,
				"--workers", "1", "--chunk-entries", "1", "--recover",
			)
			if code != ExitOK {
				t.Fatalf("post-link replay phase=%s code=%d stdout=%s stderr=%s", phase.name, code, stdout, stderr)
			}
			inspected, err := inspectOfflineArchiveInput(destination)
			if err != nil || inspected.Marker == nil || inspected.Marker.Confidentiality != "gated" {
				t.Fatalf("post-link replay phase=%s marker=%+v err=%v", phase.name, inspected.Marker, err)
			}
			transactions := filepath.Join(root, ".sow", "transactions")
			if entries, err := os.ReadDir(transactions); err != nil || len(entries) != 0 {
				t.Fatalf("post-link replay retained transaction residue phase=%s entries=%v err=%v", phase.name, entries, err)
			}
		})
	}
}

func assertOfflineArchiveAbsentViaRealNginx(t *testing.T, root string) {
	t.Helper()
	if os.Getenv("SOW_COMPAT_NGINX") != "1" {
		return
	}
	nginx, err := exec.LookPath("nginx")
	if err != nil {
		t.Fatal("SOW_COMPAT_NGINX=1 requires nginx in PATH")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	prefix := t.TempDir()
	configPath := filepath.Join(prefix, "nginx.conf")
	configBody := fmt.Sprintf(`worker_processes 1;
daemon off;
master_process off;
pid %s;
error_log stderr notice;
events { worker_connections 32; }
http {
  access_log off;
  server {
    listen 127.0.0.1:%d;
    root %s;
    autoindex on;
  }
}
`, strconv.Quote(filepath.Join(prefix, "nginx.pid")), port, strconv.Quote(root))
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(nginx, "-p", prefix+string(filepath.Separator), "-c", configPath)
	var processOutput bytes.Buffer
	command.Stdout, command.Stderr = &processOutput, &processOutput
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	baseURL := "http://127.0.0.1:" + strconv.Itoa(port)
	client := &http.Client{Timeout: time.Second}
	ready := false
	for attempt := 0; attempt < 200; attempt++ {
		response, requestErr := client.Get(baseURL + "/")
		if requestErr == nil {
			_ = response.Body.Close()
			ready = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("real nginx did not start: %s", processOutput.String())
	}
	for _, requestPath := range []string{"/offline/", "/offline/post-receipt.tgz"} {
		response, err := client.Get(baseURL + requestPath)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal(errors.Join(readErr, closeErr))
		}
		if response.StatusCode != http.StatusNotFound || bytes.Contains(body, []byte(".sow-archive-")) {
			t.Fatalf("real nginx exposed post-receipt staging path=%s status=%d body=%s", requestPath, response.StatusCode, body)
		}
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("real nginx shutdown unexpectedly returned success after kill")
	}
	waited = true
}

func TestOfflineArchiveMarkerCarriesTaintAcrossIndependentRoots(t *testing.T) {
	_, _, archive, inspected := produceGatedOfflineArchive(t)

	ordinaryRoot, ordinaryConfig := newOfflineArchiveTaintFixture(t)
	copied := filepath.Join(t.TempDir(), "renamed-release.bin")
	copyOfflineArchiveFixture(t, archive, copied)
	ordinaryCanonical := state.New(filepath.Join(ordinaryRoot, ".sow"))
	if _, exists, err := readOfflineArchiveTaintReceipt(ordinaryCanonical, inspected.Object.HashString()); err != nil || exists {
		t.Fatalf("independent ordinary root unexpectedly had receipt exists=%t err=%v", exists, err)
	}
	code, stdout, stderr := runArchiveTaintCLI(t, "add", copied, "--config", ordinaryConfig, "--repo", "public-assets", "--dest", "renamed-release.bin")
	if code != ExitVerification || !strings.Contains(stderr, "gzip marker rejects") {
		t.Fatalf("independent public add accepted Pro marker code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	ordinaryPool, err := repository.NewStore(ordinaryRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := ordinaryPool.Verify(t.Context(), inspected.Object); err == nil {
		t.Fatal("rejected cross-root public add imported the archive into CAS")
	}
	runArchiveTaintOK(t, "add", copied, "--config", ordinaryConfig, "--repo", "gated-assets", "--dest", "renamed-release.bin")
	if err := ordinaryPool.Verify(t.Context(), inspected.Object); err != nil {
		t.Fatalf("gated cross-root add did not import admitted archive: %v", err)
	}

	for _, alias := range []string{"copy-rename", "hardlink"} {
		t.Run("legacy-public-"+alias, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "sow.yaml")
			if err := os.WriteFile(configPath, []byte(legacyAssetConfig("public")), 0o600); err != nil {
				t.Fatal(err)
			}
			candidate := filepath.Join(root, "pkg", alias+".tgz")
			if err := os.MkdirAll(filepath.Dir(candidate), 0o755); err != nil {
				t.Fatal(err)
			}
			if alias == "hardlink" {
				if err := os.Link(archive, candidate); err != nil {
					t.Fatal(err)
				}
			} else {
				copyOfflineArchiveFixture(t, archive, candidate)
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			if _, exists, err := readOfflineArchiveTaintReceipt(canonical, inspected.Object.HashString()); err != nil || exists {
				t.Fatalf("independent legacy root unexpectedly had receipt exists=%t err=%v", exists, err)
			}
			code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", configPath, "--repo", "assets")
			if code != ExitVerification || !strings.Contains(stderr, "gzip marker rejects") ||
				!strings.Contains(stderr, fmt.Sprintf("legacy asset %q", "pkg/"+alias+".tgz")) {
				t.Fatalf("independent public legacy adoption accepted Pro marker code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			pool, err := repository.NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := pool.Verify(t.Context(), inspected.Object); err == nil {
				t.Fatal("rejected legacy marker alias imported into CAS")
			}
		})
	}

	t.Run("legacy-gated-control", func(t *testing.T) {
		root := t.TempDir()
		configPath := filepath.Join(root, "sow.yaml")
		if err := os.WriteFile(configPath, []byte(legacyAssetConfig("gated")), 0o600); err != nil {
			t.Fatal(err)
		}
		candidate := filepath.Join(root, "pkg", "gated-hardlink.tgz")
		if err := os.MkdirAll(filepath.Dir(candidate), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(archive, candidate); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--view", "stable", "--config", configPath, "--repo", "assets")
		if code != ExitOK {
			t.Fatalf("gated legacy marker control code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		pool, err := repository.NewStore(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := pool.Verify(t.Context(), inspected.Object); err != nil {
			t.Fatalf("gated legacy marker control did not import archive: %v", err)
		}
	})
}

func TestOfflineArchivePayloadMarkerSurvivesGzipCommentRemovalAcrossIndependentRoots(t *testing.T) {
	_, _, archive, original := produceGatedOfflineArchive(t)
	stripped := filepath.Join(t.TempDir(), "licensed-header-stripped.tgz")
	stripOfflineArchiveGzipComment(t, archive, stripped)

	originalTar := readOfflineArchiveGzipPayload(t, archive)
	strippedTar := readOfflineArchiveGzipPayload(t, stripped)
	if !bytes.Equal(originalTar, strippedTar) {
		t.Fatal("removing FCOMMENT changed the decompressed tar payload")
	}
	strippedBytes, err := os.ReadFile(stripped)
	if err != nil {
		t.Fatal(err)
	}
	if strippedBytes[3]&0x10 != 0 {
		t.Fatal("FCOMMENT remained set after the header-only rewrite")
	}
	if marker, err := parseOfflineArchiveMarkerHeader(strippedBytes); err != nil || marker != nil {
		t.Fatalf("stripped gzip header marker=%+v err=%v", marker, err)
	}
	inspected, err := inspectOfflineArchiveInput(stripped)
	if err != nil || inspected.Marker == nil || inspected.Marker.Access != "pro" || inspected.Marker.Confidentiality != "gated" {
		t.Fatalf("payload-carried marker=%+v err=%v", inspected.Marker, err)
	}
	if inspected.Object.HashString() == original.Object.HashString() {
		t.Fatal("header stripping unexpectedly preserved the compressed archive digest")
	}

	ordinaryRoot, ordinaryConfig := newOfflineArchiveTaintFixture(t)
	ordinaryCanonical := state.New(filepath.Join(ordinaryRoot, ".sow"))
	if _, exists, err := readOfflineArchiveTaintReceipt(ordinaryCanonical, inspected.Object.HashString()); err != nil || exists {
		t.Fatalf("independent root unexpectedly had stripped digest receipt exists=%t err=%v", exists, err)
	}
	code, stdout, stderr := runArchiveTaintCLI(t, "add", stripped, "--config", ordinaryConfig, "--repo", "public-assets", "--dest", "header-stripped.tgz")
	if code != ExitVerification || !strings.Contains(stderr, "gzip marker rejects") {
		t.Fatalf("independent public add accepted payload-marked archive code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	ordinaryPool, err := repository.NewStore(ordinaryRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := ordinaryPool.Verify(t.Context(), inspected.Object); err == nil {
		t.Fatal("rejected header-stripped archive was imported into public-root CAS")
	}

	legacyRoot := t.TempDir()
	legacyConfig := filepath.Join(legacyRoot, "sow.yaml")
	if err := os.WriteFile(legacyConfig, []byte(legacyAssetConfig("public")), 0o600); err != nil {
		t.Fatal(err)
	}
	legacyArchive := filepath.Join(legacyRoot, "pkg", "header-stripped.tgz")
	if err := os.MkdirAll(filepath.Dir(legacyArchive), 0o755); err != nil {
		t.Fatal(err)
	}
	copyOfflineArchiveFixture(t, stripped, legacyArchive)
	code, stdout, stderr = legacyCLIRunner()("init", "--adopt-content", "--config", legacyConfig, "--repo", "assets")
	if code != ExitVerification || !strings.Contains(stderr, "gzip marker rejects") {
		t.Fatalf("independent public legacy adoption accepted payload-marked archive code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestOfflineArchiveMarkerCannotBeHiddenBehindConcatenatedGzipMember(t *testing.T) {
	_, _, archive, _ := produceGatedOfflineArchive(t)
	stripped := filepath.Join(t.TempDir(), "licensed-header-stripped.tgz")
	stripOfflineArchiveGzipComment(t, archive, stripped)

	for _, test := range []struct {
		name   string
		source string
	}{
		{name: "header-and-payload-marker", source: archive},
		{name: "payload-marker-only", source: stripped},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := filepath.Join(t.TempDir(), test.name+".tgz")
			prependIncompleteTarGzipMember(t, test.source, candidate)
			if _, err := inspectOfflineArchiveInput(candidate); err == nil || !strings.Contains(err.Error(), "exactly one gzip member") {
				t.Fatalf("concatenated SOW gzip member was not rejected err=%v", err)
			}

			root, configPath := newOfflineArchiveTaintFixture(t)
			code, stdout, stderr := runArchiveTaintCLI(t, "add", candidate, "--config", configPath, "--repo", "public-assets", "--dest", "concatenated.tgz")
			if code == ExitOK || !strings.Contains(stderr, "exactly one gzip member") {
				t.Fatalf("public add accepted concatenated SOW archive code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			pool, err := repository.NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			candidateBody, err := os.ReadFile(candidate)
			if err != nil {
				t.Fatal(err)
			}
			candidateDigest := sha256.Sum256(candidateBody)
			parsedDigest, err := repository.ParseDigest(fmt.Sprintf("%x", candidateDigest))
			if err != nil {
				t.Fatal(err)
			}
			candidateObject := repository.Object{SHA256: parsedDigest, Size: int64(len(candidateBody))}
			if err := pool.Verify(t.Context(), candidateObject); err == nil {
				t.Fatal("rejected concatenated archive was imported into public-root CAS")
			}
		})
	}
}

func TestOfflineArchiveMarkerCannotBeHiddenAfterTarEOFInSameGzipMember(t *testing.T) {
	_, _, archive, _ := produceGatedOfflineArchive(t)
	stripped := filepath.Join(t.TempDir(), "licensed-header-stripped.tgz")
	stripOfflineArchiveGzipComment(t, archive, stripped)

	var ordinary bytes.Buffer
	ordinaryTar := tar.NewWriter(&ordinary)
	body := []byte("ordinary prefix\n")
	if err := ordinaryTar.WriteHeader(&tar.Header{Name: "ordinary.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := ordinaryTar.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := ordinaryTar.Close(); err != nil {
		t.Fatal(err)
	}
	joined := append(append([]byte(nil), ordinary.Bytes()...), readOfflineArchiveGzipPayload(t, stripped)...)
	if marker, _, err := inspectOfflineArchiveTarMember(bytes.NewReader(joined)); err == nil || !errors.Is(err, errOfflineArchivePolicyEnvelope) || marker != nil {
		t.Fatalf("direct same-member tar tail concealed SOW marker marker=%+v err=%v", marker, err)
	}
	var encoded bytes.Buffer
	compressed := gzip.NewWriter(&encoded)
	if _, err := compressed.Write(joined); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(t.TempDir(), "same-member-two-tars.tgz")
	if err := os.WriteFile(candidate, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectOfflineArchiveInput(candidate); err == nil || !strings.Contains(err.Error(), "not the first tar entry") {
		t.Fatalf("same-member tar tail concealed SOW marker ordinary=%d joined=%d tail=%x err=%v", ordinary.Len(), len(joined), joined[ordinary.Len():ordinary.Len()+16], err)
	}
}

func TestOfflineArchiveMarkerCannotBeHiddenBehindOpaquePrefix(t *testing.T) {
	_, _, archive, _ := produceGatedOfflineArchive(t)
	stripped := filepath.Join(t.TempDir(), "licensed-header-stripped.tgz")
	stripOfflineArchiveGzipComment(t, archive, stripped)
	for _, source := range []string{archive, stripped} {
		body, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		candidate := filepath.Join(t.TempDir(), filepath.Base(source)+"-prefixed")
		if err := os.WriteFile(candidate, append([]byte("ordinary-prefix\n"), body...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectOfflineArchiveInput(candidate); err == nil || !strings.Contains(err.Error(), "opaque prefix") {
			t.Fatalf("opaque prefix concealed SOW marker source=%s err=%v", source, err)
		}
	}
}

func TestOfflineArchiveOpaqueAssetIgnoresIncidentalEmbeddedGzip(t *testing.T) {
	var embedded bytes.Buffer
	compressed, err := gzip.NewWriterLevel(&embedded, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	compressed.Header.ModTime = time.Unix(123, 0).UTC()
	compressed.Header.OS = 3
	if _, err := compressed.Write([]byte("ordinary nested gzip payload\n")); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	body := []byte{
		0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00,
		0x1f, 0x8b, 0x46, 0xa9, 0x99,
		0x1f, 0x8b, 0x08, 0x52, 0x36, 0x02, 0x7a, 0x9f, 0xf9, 0x38,
	}
	body = append(body, embedded.Bytes()...)
	body = append(body, []byte("opaque suffix after an embedded gzip member\n")...)
	candidate := filepath.Join(t.TempDir(), "ordinary-source.tar.xz")
	if err := os.WriteFile(candidate, body, 0o600); err != nil {
		t.Fatal(err)
	}
	inspected, err := inspectOfflineArchiveInput(candidate)
	if err != nil || inspected.Marker != nil {
		t.Fatalf("ordinary opaque asset marker=%+v err=%v", inspected.Marker, err)
	}
	digest := sha256.Sum256(body)
	if inspected.Object.HashString() != fmt.Sprintf("%x", digest) || inspected.Object.Size != int64(len(body)) {
		t.Fatalf("ordinary opaque asset identity=%+v", inspected.Object)
	}
}

func TestOfflineArchiveOpaqueAssetAllowsMarkerFreeDeterministicGzipMember(t *testing.T) {
	var embedded bytes.Buffer
	compressed, err := gzip.NewWriterLevel(&embedded, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	compressed.Header.ModTime = time.Unix(0, 0).UTC()
	compressed.Header.OS = 255
	archive := tar.NewWriter(compressed)
	body := []byte("ordinary package member\n")
	if err := archive.WriteHeader(&tar.Header{Name: "ordinary.txt", Mode: 0o644, Size: int64(len(body)), ModTime: time.Unix(0, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	candidateBody := append([]byte("ar-like opaque prefix\n"), embedded.Bytes()...)
	candidateBody = append(candidateBody, []byte{0x1f, 0x8b, 0x00, 'o', 'p', 'a', 'q', 'u', 'e'}...)
	candidate := filepath.Join(t.TempDir(), "ordinary-package.deb")
	if err := os.WriteFile(candidate, candidateBody, 0o600); err != nil {
		t.Fatal(err)
	}
	inspected, err := inspectOfflineArchiveInput(candidate)
	if err != nil || inspected.Marker != nil {
		t.Fatalf("marker-free deterministic gzip member marker=%+v err=%v", inspected.Marker, err)
	}

	_, _, sowArchive, _ := produceGatedOfflineArchive(t)
	sowBody, err := os.ReadFile(sowArchive)
	if err != nil {
		t.Fatal(err)
	}
	laundered := filepath.Join(t.TempDir(), "ordinary-then-sow.bin")
	combined := append(append(append([]byte("prefix\n"), embedded.Bytes()...), []byte("gap\n")...), sowBody...)
	if err := os.WriteFile(laundered, combined, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectOfflineArchiveInput(laundered); err == nil || !strings.Contains(err.Error(), "opaque prefix") {
		t.Fatalf("ordinary embedded gzip concealed a later SOW envelope err=%v", err)
	}
}

func TestOfflineArchiveEmbeddedEnvelopeAcrossScannerBufferBoundary(t *testing.T) {
	_, _, archive, _ := produceGatedOfflineArchive(t)
	body, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	// Put the ten-byte deterministic SOW envelope across the 64 KiB Peek
	// boundary. The scanner must retain a partial header between windows.
	prefix := bytes.Repeat([]byte{'x'}, 64*1024-5)
	candidate := filepath.Join(t.TempDir(), "buffer-split.tgz")
	if err := os.WriteFile(candidate, append(prefix, body...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectOfflineArchiveInput(candidate); err == nil || !strings.Contains(err.Error(), "opaque prefix") {
		t.Fatalf("buffer-split opaque prefix concealed SOW marker err=%v", err)
	}
}

func TestOfflineArchiveMarkerCannotBeHiddenBehindMalformedGzipBoundary(t *testing.T) {
	_, _, source, _ := produceGatedOfflineArchive(t)
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
		gap    []byte
		custom func(string)
	}{
		{name: "one-byte-separator", gap: []byte{0}},
		{name: "reserved-flag-in-second-header", mutate: func(body []byte) []byte {
			body = append([]byte(nil), body...)
			body[3] |= 0x20
			return body
		}},
		{name: "corrupt-prefix-trailer", custom: func(destination string) {
			prependCorruptGzipMember(t, source, destination)
		}},
		{name: "malformed-prefix-header", custom: func(destination string) {
			body, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(destination, append([]byte{0x1f, 0x8b, 0x00}, body...), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			candidate := filepath.Join(t.TempDir(), test.name+".tgz")
			if test.custom != nil {
				test.custom(candidate)
			} else {
				prependIncompleteTarGzipMemberWithGap(t, source, candidate, test.gap, test.mutate)
			}
			if _, err := inspectOfflineArchiveInput(candidate); err == nil {
				t.Fatalf("malformed gzip boundary concealed SOW member err=%v", err)
			}
			root, configPath := newOfflineArchiveTaintFixture(t)
			code, stdout, stderr := runArchiveTaintCLI(t, "add", candidate, "--config", configPath, "--repo", "public-assets", "--dest", "hidden.tgz")
			if code == ExitOK {
				t.Fatalf("public add accepted malformed boundary code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			body, err := os.ReadFile(candidate)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(body)
			parsed, err := repository.ParseDigest(fmt.Sprintf("%x", digest))
			if err != nil {
				t.Fatal(err)
			}
			pool, err := repository.NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := pool.Verify(t.Context(), repository.Object{SHA256: parsed, Size: int64(len(body))}); err == nil {
				t.Fatal("rejected malformed-boundary archive was imported into public CAS")
			}
		})
	}
}

func TestArchiveDirectoryCreationSyncsEachParentBeforeDescending(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "one", "two", "three")
	canonicalTarget, err := archiveAbsolutePath(target)
	if err != nil {
		t.Fatal(err)
	}
	previous := archiveDirectorySync
	calls := 0
	archiveDirectorySync = func(root *os.Root) error {
		calls++
		if calls == 2 {
			return errors.New("injected parent directory sync failure")
		}
		return previous(root)
	}
	t.Cleanup(func() { archiveDirectorySync = previous })
	bound, _, err := walkAbsoluteArchiveDirectory(canonicalTarget, true)
	if bound != nil {
		bound.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "injected parent directory sync failure") || calls != 2 {
		t.Fatalf("directory sync fault calls=%d err=%v", calls, err)
	}
	if _, err := os.Stat(filepath.Join(base, "one", "two")); err != nil {
		t.Fatalf("second created entry missing before its sync fault: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "one", "two", "three")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("walker descended after failed parent sync: %v", err)
	}
}

func TestOfflineArchiveFilesystemMismatchFailsBeforeCompressionOrReceipt(t *testing.T) {
	materialized := t.TempDir()
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "new", "bundle.tgz")
	previousIdentity := archiveFilesystemIdentity
	previousPrecommit := archiveBeforeTaintPrecommitHook
	precommitCalled := false
	archiveFilesystemIdentity = func(os.FileInfo, os.FileInfo) (bool, error) { return false, nil }
	archiveBeforeTaintPrecommitHook = func(archiveResult) error { precommitCalled = true; return nil }
	t.Cleanup(func() {
		archiveFilesystemIdentity = previousIdentity
		archiveBeforeTaintPrecommitHook = previousPrecommit
	})
	_, err := writeDeterministicTGZWithPrecommit(t.Context(), materialized, filepath.Join(materialized, "missing.manifest"), destination, false, private, "", func(archiveResult) error {
		precommitCalled = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "share a filesystem") || precommitCalled {
		t.Fatalf("filesystem mismatch err=%v precommit=%t", err, precommitCalled)
	}
	if _, err := os.Stat(filepath.Dir(destination)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("filesystem preflight created destination parent: %v", err)
	}
}

func TestOfflineArchiveDigestAndMarkerUseOneBoundByteStream(t *testing.T) {
	_, _, archive, _ := produceGatedOfflineArchive(t)
	original, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(original) >= 64*1024 {
		t.Fatalf("mutation fixture unexpectedly exceeds bounded header buffer: %d", len(original))
	}
	ordinary := ordinaryGzipWithExactSize(t, len(original))
	candidate := filepath.Join(t.TempDir(), "in-place-swap.tgz")
	if err := os.WriteFile(candidate, original, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(candidate)
	if err != nil {
		t.Fatal(err)
	}
	writeInPlace := func(body []byte) error {
		file, err := os.OpenFile(candidate, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(body)
		closeErr := file.Close()
		timeErr := os.Chtimes(candidate, info.ModTime(), info.ModTime())
		return errors.Join(writeErr, closeErr, timeErr)
	}
	peeked, restored := false, false
	previousPeek := offlineArchiveInputAfterHeaderPeekHook
	previousMarker := offlineArchiveInputAfterMarkerHook
	offlineArchiveInputAfterHeaderPeekHook = func(*os.File) error {
		peeked = true
		return writeInPlace(ordinary)
	}
	offlineArchiveInputAfterMarkerHook = func(*os.File) error {
		restored = true
		return writeInPlace(original)
	}
	t.Cleanup(func() {
		offlineArchiveInputAfterHeaderPeekHook = previousPeek
		offlineArchiveInputAfterMarkerHook = previousMarker
	})

	inspected, err := inspectOfflineArchiveInput(candidate)
	if err != nil {
		t.Fatal(err)
	}
	wanted := sha256.Sum256(original)
	if !peeked || !restored || inspected.Object.HashString() != fmt.Sprintf("%x", wanted) || inspected.Marker == nil || inspected.Marker.Confidentiality != "gated" {
		t.Fatalf("single-pass inspection did not bind original digest and marker peeked=%t restored=%t object=%s marker=%+v", peeked, restored, inspected.Object.HashString(), inspected.Marker)
	}

	// With the original bytes restored, the old two-pass implementation could
	// have imported the gated object after observing Marker=nil from the swapped
	// public bytes. The bound marker decision must still reject public admission.
	_, configPath := newOfflineArchiveTaintFixture(t)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	var publicRepo config.Repo
	for _, repo := range cfg.Repos {
		if repo.ID == "public-assets" {
			publicRepo = repo
			break
		}
	}
	if publicRepo.ID == "" {
		t.Fatal("public asset fixture repo is missing")
	}
	if err := requireOfflineArchiveMarkerAdmission(inspected.Marker, publicRepo, nil, nil); err == nil {
		t.Fatal("in-place swap laundered a gated archive into public admission")
	}
}

func TestOfflineArchivePayloadMarkerTamperMissingAndTarEnvelopeBypassesFailClosed(t *testing.T) {
	_, configPath, archive, _ := produceGatedOfflineArchive(t)
	for _, test := range []struct {
		name      string
		transform func(*tar.Header, []byte, int) (*tar.Header, []byte, bool)
		want      string
	}{
		{
			name: "tampered-policy",
			transform: func(header *tar.Header, body []byte, index int) (*tar.Header, []byte, bool) {
				if index != 0 {
					return header, body, true
				}
				var envelope offlineArchivePayloadMarker
				if err := json.Unmarshal(body, &envelope); err != nil {
					t.Fatal(err)
				}
				if envelope.SourceSHA256[0] == '0' {
					envelope.SourceSHA256 = "1" + envelope.SourceSHA256[1:]
				} else {
					envelope.SourceSHA256 = "0" + envelope.SourceSHA256[1:]
				}
				body, err := json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				body = append(body, '\n')
				header.Size = int64(len(body))
				return header, body, true
			},
			want: "gzip and payload markers differ",
		},
		{
			name: "missing",
			transform: func(header *tar.Header, body []byte, index int) (*tar.Header, []byte, bool) {
				return header, body, index != 0
			},
			want: "no first-entry payload marker",
		},
		{
			name: "non-first",
			transform: func(header *tar.Header, body []byte, index int) (*tar.Header, []byte, bool) {
				return header, body, true
			},
			want: "not the first tar entry",
		},
		{
			name: "symlink",
			transform: func(header *tar.Header, body []byte, index int) (*tar.Header, []byte, bool) {
				if index == 0 {
					header.Typeflag, header.Linkname, header.Size = tar.TypeSymlink, "payload", 0
					body = nil
				}
				return header, body, true
			},
			want: "unsafe tar envelope",
		},
		{
			name: "directory",
			transform: func(header *tar.Header, body []byte, index int) (*tar.Header, []byte, bool) {
				if index == 0 {
					header.Typeflag, header.Size = tar.TypeDir, 0
					body = nil
				}
				return header, body, true
			},
			want: "unsafe tar envelope",
		},
		{
			name: "pax-override",
			transform: func(header *tar.Header, body []byte, index int) (*tar.Header, []byte, bool) {
				if index == 0 {
					header.Format = tar.FormatPAX
					header.PAXRecords = map[string]string{"comment": "not-trusted"}
				}
				return header, body, true
			},
			want: "unsafe tar envelope",
		},
		{
			name: "non-canonical-mode",
			transform: func(header *tar.Header, body []byte, index int) (*tar.Header, []byte, bool) {
				if index == 0 {
					header.Mode = 0o644
				}
				return header, body, true
			},
			want: "unsafe tar envelope",
		},
		{
			name: "non-canonical-owner",
			transform: func(header *tar.Header, body []byte, index int) (*tar.Header, []byte, bool) {
				if index == 0 {
					header.Uid, header.Uname = 1, "operator"
				}
				return header, body, true
			},
			want: "unsafe tar envelope",
		},
		{
			name: "non-canonical-time",
			transform: func(header *tar.Header, body []byte, index int) (*tar.Header, []byte, bool) {
				if index == 0 {
					header.ModTime = time.Unix(1, 0).UTC()
				}
				return header, body, true
			},
			want: "unsafe tar envelope",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := filepath.Join(t.TempDir(), test.name+".tgz")
			if test.name == "non-first" {
				moveOfflineArchivePayloadMarkerAfterFirst(t, archive, candidate)
			} else {
				rewriteOfflineArchiveTar(t, archive, candidate, test.transform)
			}
			if _, err := inspectOfflineArchiveInput(candidate); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("inspect tampered archive err=%v", err)
			}
			code, stdout, stderr := runArchiveTaintCLI(t, "add", candidate, "--config", configPath, "--repo", "gated-assets", "--dest", test.name+".tgz")
			if code == ExitOK || !strings.Contains(stderr, test.want) {
				t.Fatalf("gated add accepted malformed envelope code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
		})
	}

	duplicate := filepath.Join(t.TempDir(), "duplicate.tgz")
	duplicateOfflineArchivePayloadMarker(t, archive, duplicate)
	if _, err := inspectOfflineArchiveInput(duplicate); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate payload marker err=%v", err)
	}
}

func TestOrdinaryThirdPartyTGZRemainsAdmissibleAsPublicAsset(t *testing.T) {
	_, configPath := newOfflineArchiveTaintFixture(t)
	ordinary := filepath.Join(t.TempDir(), "vendor.tgz")
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	body := []byte("ordinary vendor archive\n")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "vendor/readme.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(tarWriter.Close(), gzipWriter.Close()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ordinary, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	inspected, err := inspectOfflineArchiveInput(ordinary)
	if err != nil || inspected.Marker != nil {
		t.Fatalf("ordinary third-party tgz marker=%+v err=%v", inspected.Marker, err)
	}
	runArchiveTaintOK(t, "add", ordinary, "--config", configPath, "--repo", "public-assets", "--dest", "vendor.tgz")
}

func TestOfflineArchivePayloadEnvelopeIsNotProjectedAsRepositoryContent(t *testing.T) {
	root, configPath := newOfflineArchiveTaintFixture(t)
	secret := filepath.Join(t.TempDir(), "licensed.bin")
	if err := os.WriteFile(secret, []byte("licensed projection payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "add", secret, "--config", configPath, "--repo", "source-gated", "--dest", "licensed.bin")
	archive := filepath.Join(root, "offline", "licensed.tgz")
	output := runArchiveTaintOK(t,
		"materialize", "stable", "--config", configPath, "--repo", "source-gated", "--tgz", archive,
		"--asset-repo", "gated-assets", "--asset-dest", "bundles/licensed.tgz",
	)
	if !strings.Contains(output, " entries=1 ") {
		t.Fatalf("payload envelope changed source entry accounting: %s", output)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	refName, err := state.ViewRef("stable", "gated-assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	commit, exists, err := canonical.Ref(refName)
	if err != nil || !exists {
		t.Fatalf("adopted archive ref exists=%t err=%v", exists, err)
	}
	viewPath, err := state.ViewPath("stable", "gated-assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := canonical.OpenPathAt(commit, viewPath)
	if err != nil {
		t.Fatal(err)
	}
	entries := views.NewReader(reader)
	entry, err := entries.Next()
	if err != nil {
		reader.Close()
		t.Fatal(err)
	}
	if entry.Path != "gated/assets/bundles/licensed.tgz" {
		reader.Close()
		t.Fatalf("adopted manifest entry=%+v", entry)
	}
	if _, err := entries.Next(); !errors.Is(err, io.EOF) {
		reader.Close()
		t.Fatalf("payload envelope appeared as an extra adopted manifest entry: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	for _, unexpected := range []string{
		filepath.Join(root, offlineArchivePayloadMarkerPath),
		filepath.Join(root, "gated", "assets", offlineArchivePayloadMarkerPath),
		filepath.Join(root, ".sow", "origin", "gated", "gated", "assets", offlineArchivePayloadMarkerPath),
	} {
		if _, err := os.Lstat(unexpected); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("payload envelope escaped archive at %s: %v", unexpected, err)
		}
	}
}

func TestPublicViewWithCanonicalGatedDigestFailsEveryLocalReadGate(t *testing.T) {
	root, configPath, _, inspected := produceGatedOfflineArchive(t)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	repo, exists := cfg.RepoByName("public-assets")
	if !exists {
		t.Fatal("public asset repo is missing")
	}
	canonical := state.New(cfg.StatePath())
	viewPath, _ := state.ViewPath("latest", repo.ID, "all", "all")
	viewRef, _ := state.ViewRef("latest", repo.ID, "all", "all")
	transactionDir, err := newTransactionDir(cfg.StatePath(), "test-forged-public-view-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(transactionDir)
	stage, err := os.CreateTemp(transactionDir, "forged-public-view-*.tsv")
	if err != nil {
		t.Fatal(err)
	}
	entry := views.Entry{
		Repo: repo.ID, OS: "all", Arch: "all", Name: "leaked", Version: inspected.Object.HashString()[:16],
		Path: "public/assets/leaked.tgz", Size: inspected.Object.Size, SHA256: inspected.Object.HashString(), Pool: "public",
	}
	if err := views.WriteEntry(stage, entry); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(stage.Sync(), stage.Close()); err != nil {
		t.Fatal(err)
	}
	commit, _, err := canonical.Apply(t.Context(), "test-forged-public-archive-ref", "test: bypass write admission for negative closure fixture",
		map[string]string{viewPath: stage.Name()}, []state.RefUpdate{{Name: viewRef}}, state.ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateViewAt(canonical, commit, viewPath, viewLeaf{repo: repo, os: "all", arch: "all"}, true); err == nil || !strings.Contains(err.Error(), "canonical archive taint") {
		t.Fatalf("direct public view admission accepted gated digest: %v", err)
	}

	code, stdout, stderr := runArchiveTaintCLI(t, "fsck", "--config", configPath, "--repo", repo.ID, "--workers", "1", "--chunk-entries", "1")
	if code != ExitVerification || !strings.Contains(stdout+stderr, "canonical archive taint") {
		t.Fatalf("fsck accepted forged public ref code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = runArchiveTaintCLI(t, "verify", "--layer", "L1", "--view", "latest", "--config", configPath, "--repo", repo.ID, "--workers", "1", "--chunk-entries", "1")
	if code != ExitVerification || !strings.Contains(stdout+stderr, "canonical archive taint") {
		t.Fatalf("L1 accepted forged public ref code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	target := filepath.Join(root, "forged-public-export")
	code, stdout, stderr = runArchiveTaintCLI(t, "materialize", "latest", "--config", configPath, "--repo", repo.ID, "--target", target, "--workers", "1", "--chunk-entries", "1")
	if code != ExitVerification || !strings.Contains(stdout+stderr, "canonical archive taint") {
		t.Fatalf("materialize accepted forged public ref code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Lstat(filepath.Join(target, repo.Path, "leaked.tgz")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("forged gated public asset became visible: %v", err)
	}
}

func TestOfflineArchivePublicDebugEntryIsCanonicallyTainted(t *testing.T) {
	root, configPath := newOfflineArchiveTaintFixture(t)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	repo, exists := cfg.RepoByName("public-assets")
	if !exists {
		t.Fatal("public asset repo is missing")
	}
	canonical := state.New(cfg.StatePath())
	viewPath, _ := state.ViewPath("latest", repo.ID, "all", "all")
	viewRef, _ := state.ViewRef("latest", repo.ID, "all", "all")
	transactionDir, err := newTransactionDir(cfg.StatePath(), "test-debug-view-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(transactionDir)
	stage, err := os.CreateTemp(transactionDir, "debug-view-*.tsv")
	if err != nil {
		t.Fatal(err)
	}
	entry := views.Entry{
		Repo: repo.ID, OS: "all", Arch: "all", Name: "debug", Version: "1", Path: "public/assets/debug.bin",
		Size: 1, SHA256: strings.Repeat("a", 64), Pool: "public", DebugInfo: true,
	}
	if err := views.WriteEntry(stage, entry); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(stage.Sync(), stage.Close()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.Apply(t.Context(), "test-debug-archive-taint", "test: seed public debug archive source",
		map[string]string{viewPath: stage.Name()}, []state.RefUpdate{{Name: viewRef}}, state.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	proof, err := deriveOfflineArchiveSourceProof(cfg, canonical, materializeCanonicalSource{ID: "latest", Public: true}, []viewLeaf{{repo: repo, os: "all", arch: "all"}})
	if err != nil {
		t.Fatal(err)
	}
	if proof.DebugEntries != 1 || proof.Confidentiality != "gated" {
		t.Fatalf("debug proof=%+v", proof)
	}
	if _, err := prepareOfflineArchiveAdoptionFromProof(cfg, proof, repo, "debug.tgz"); err == nil || !strings.Contains(err.Error(), "confidentiality closure rejects") {
		t.Fatalf("public debug archive preflight err=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "debug.tgz")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected debug archive path err=%v", err)
	}
}

func TestPromoteCannotReturnCanonicalGatedDigestFromProToPublic(t *testing.T) {
	root, configPath, _, inspected := produceGatedOfflineArchive(t)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	repo, exists := cfg.RepoByName("public-assets")
	if !exists {
		t.Fatal("public asset repo is missing")
	}
	canonical := state.New(cfg.StatePath())
	stablePath, _ := state.ViewPath("stable", repo.ID, "all", "all")
	stableRef, _ := state.ViewRef("stable", repo.ID, "all", "all")
	transactionDir, err := newTransactionDir(cfg.StatePath(), "test-forged-pro-source-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(transactionDir)
	stage, err := os.CreateTemp(transactionDir, "forged-pro-source-*.tsv")
	if err != nil {
		t.Fatal(err)
	}
	entry := views.Entry{
		Repo: repo.ID, OS: "all", Arch: "all", Name: "pro-return", Version: inspected.Object.HashString()[:16],
		Path: "public/assets/pro-return.tgz", Size: inspected.Object.Size, SHA256: inspected.Object.HashString(), Pool: "public",
	}
	if err := views.WriteEntry(stage, entry); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(stage.Sync(), stage.Close()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.Apply(t.Context(), "test-forged-pro-source", "test: seed stable-only public-pool gated digest",
		map[string]string{stablePath: stage.Name()}, []state.RefUpdate{{Name: stableRef}}, state.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	betaRef, _ := state.ViewRef("beta", repo.ID, "all", "all")
	betaBefore, betaExistsBefore, err := canonical.Ref(betaRef)
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runArchiveTaintCLI(t, "promote", "stable", "beta", "--config", configPath, "--repo", repo.ID)
	if code != ExitVerification || !strings.Contains(stdout+stderr, "canonical archive taint") {
		t.Fatalf("Pro-to-public promote accepted gated digest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	headAfter, err := canonical.HeadHash()
	if err != nil || headAfter != headBefore {
		t.Fatalf("rejected Pro-to-public promote changed HEAD before=%s after=%s err=%v", headBefore, headAfter, err)
	}
	betaAfter, betaExistsAfter, err := canonical.Ref(betaRef)
	if err != nil || betaExistsAfter != betaExistsBefore || betaAfter != betaBefore {
		t.Fatalf("rejected Pro-to-public promote changed beta before=%s/%t after=%s/%t err=%v", betaBefore, betaExistsBefore, betaAfter, betaExistsAfter, err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".sow", "materialized", "beta", repo.Path, "pro-return.tgz")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected Pro archive became public: %v", err)
	}
}

func newOfflineArchiveTaintFixture(t *testing.T) (string, string) {
	t.Helper()
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(offlineArchiveTaintConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "gated/source", "public/assets", "gated/assets")
	return root, configPath
}

func runArchiveTaintCLI(t *testing.T, arguments ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Main(arguments, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func runArchiveTaintOK(t *testing.T, arguments ...string) string {
	t.Helper()
	code, stdout, stderr := runArchiveTaintCLI(t, arguments...)
	if code != ExitOK {
		t.Fatalf("command=%v code=%d stdout=%s stderr=%s", arguments, code, stdout, stderr)
	}
	return stdout
}

func assertArchiveTaintPathAbsent(t *testing.T, filename string) {
	t.Helper()
	if _, err := os.Lstat(filename); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("archive %s exists or has unexpected error: %v", filename, err)
	}
}

func produceGatedOfflineArchive(t *testing.T) (root, configPath, archive string, inspected inspectedOfflineArchiveInput) {
	t.Helper()
	root, configPath = newOfflineArchiveTaintFixture(t)
	secret := filepath.Join(t.TempDir(), "licensed.bin")
	if err := os.WriteFile(secret, []byte("cross-root licensed payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "add", secret, "--config", configPath, "--repo", "source-gated", "--dest", "licensed.bin")
	archive = filepath.Join(root, "offline", "licensed-stable.tgz")
	output := runArchiveTaintOK(t, "materialize", "stable", "--config", configPath, "--repo", "source-gated", "--tgz", archive)
	if !strings.Contains(output, " entries=1 ") {
		t.Fatalf("payload control envelope changed the archive entry count: %s", output)
	}
	var err error
	inspected, err = inspectOfflineArchiveInput(archive)
	if err != nil || inspected.Marker == nil || inspected.Marker.Access != "pro" || inspected.Marker.Confidentiality != "gated" {
		t.Fatalf("produce gated archive marker=%+v err=%v", inspected.Marker, err)
	}
	if _, err := os.Lstat(filepath.Join(root, offlineArchivePayloadMarkerPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("payload control envelope escaped into the directly hosted tree: %v", err)
	}
	comment := fmt.Sprintf("%ssource_sha256=%s;access=%s;confidentiality=%s", offlineArchiveMarkerPrefix, inspected.Marker.SourceSHA256, inspected.Marker.Access, inspected.Marker.Confidentiality)
	payload, err := offlineArchivePayloadMarkerForComment(comment)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(payload)
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Verify(t.Context(), repository.Object{SHA256: repository.Digest(payloadDigest), Size: int64(len(payload))}); err == nil {
		t.Fatal("payload control envelope was imported as a standalone CAS object")
	}
	return root, configPath, archive, inspected
}

func copyOfflineArchiveFixture(t *testing.T, source, destination string) {
	t.Helper()
	body, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

type offlineArchiveTarFixtureEntry struct {
	header tar.Header
	body   []byte
}

type offlineArchiveTarFixture struct {
	header  gzip.Header
	entries []offlineArchiveTarFixtureEntry
}

func readOfflineArchiveTarFixture(t *testing.T, filename string) offlineArchiveTarFixture {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	fixture := offlineArchiveTarFixture{header: compressed.Header}
	fixture.header.Extra = append([]byte(nil), compressed.Header.Extra...)
	archive := tar.NewReader(compressed)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		cloned := *header
		cloned.PAXRecords = cloneArchiveStringMap(header.PAXRecords)
		fixture.entries = append(fixture.entries, offlineArchiveTarFixtureEntry{header: cloned, body: body})
	}
	if _, err := io.Copy(io.Discard, compressed); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func writeOfflineArchiveTarFixture(t *testing.T, filename string, fixture offlineArchiveTarFixture) {
	t.Helper()
	var output bytes.Buffer
	compressed, err := gzip.NewWriterLevel(&output, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	compressed.Header = fixture.header
	compressed.Header.Extra = append([]byte(nil), fixture.header.Extra...)
	archive := tar.NewWriter(compressed)
	for index := range fixture.entries {
		entry := fixture.entries[index]
		entry.header.Size = int64(len(entry.body))
		if err := archive.WriteHeader(&entry.header); err != nil {
			t.Fatal(err)
		}
		if len(entry.body) != 0 {
			if _, err := archive.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := errors.Join(archive.Close(), compressed.Close()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, output.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func rewriteOfflineArchiveTar(t *testing.T, source, destination string, transform func(*tar.Header, []byte, int) (*tar.Header, []byte, bool)) {
	t.Helper()
	fixture := readOfflineArchiveTarFixture(t, source)
	transformed := make([]offlineArchiveTarFixtureEntry, 0, len(fixture.entries))
	for index := range fixture.entries {
		entry := fixture.entries[index]
		header := entry.header
		header.PAXRecords = cloneArchiveStringMap(entry.header.PAXRecords)
		body := append([]byte(nil), entry.body...)
		updated, body, keep := transform(&header, body, index)
		if !keep {
			continue
		}
		if updated == nil {
			t.Fatal("archive fixture transform returned a nil header")
		}
		transformed = append(transformed, offlineArchiveTarFixtureEntry{header: *updated, body: body})
	}
	fixture.entries = transformed
	writeOfflineArchiveTarFixture(t, destination, fixture)
}

func moveOfflineArchivePayloadMarkerAfterFirst(t *testing.T, source, destination string) {
	t.Helper()
	fixture := readOfflineArchiveTarFixture(t, source)
	if len(fixture.entries) < 2 || fixture.entries[0].header.Name != offlineArchivePayloadMarkerPath {
		t.Fatal("archive fixture has no leading payload marker and content entry")
	}
	fixture.entries[0], fixture.entries[1] = fixture.entries[1], fixture.entries[0]
	writeOfflineArchiveTarFixture(t, destination, fixture)
}

func duplicateOfflineArchivePayloadMarker(t *testing.T, source, destination string) {
	t.Helper()
	fixture := readOfflineArchiveTarFixture(t, source)
	if len(fixture.entries) == 0 || fixture.entries[0].header.Name != offlineArchivePayloadMarkerPath {
		t.Fatal("archive fixture has no leading payload marker")
	}
	duplicate := fixture.entries[0]
	duplicate.body = append([]byte(nil), duplicate.body...)
	fixture.entries = append(fixture.entries[:1], append([]offlineArchiveTarFixtureEntry{duplicate}, fixture.entries[1:]...)...)
	writeOfflineArchiveTarFixture(t, destination, fixture)
}

func cloneArchiveStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func stripOfflineArchiveGzipComment(t *testing.T, source, destination string) {
	t.Helper()
	body, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 10 || body[0] != 0x1f || body[1] != 0x8b || body[2] != 8 || body[3]&0x10 == 0 {
		t.Fatal("archive fixture has no gzip FCOMMENT")
	}
	if body[3]&0x02 != 0 {
		t.Fatal("generated archive unexpectedly uses FHCRC")
	}
	offset := 10
	if body[3]&0x04 != 0 {
		if offset+2 > len(body) {
			t.Fatal("truncated gzip FEXTRA length")
		}
		extraLength := int(body[offset]) | int(body[offset+1])<<8
		offset += 2 + extraLength
		if offset > len(body) {
			t.Fatal("truncated gzip FEXTRA")
		}
	}
	consumeTerminated := func() {
		if offset >= len(body) {
			t.Fatal("truncated gzip text field")
		}
		end := bytes.IndexByte(body[offset:], 0)
		if end < 0 {
			t.Fatal("unterminated gzip text field")
		}
		offset += end + 1
	}
	if body[3]&0x08 != 0 {
		consumeTerminated()
	}
	commentStart := offset
	consumeTerminated()
	commentEnd := offset
	stripped := make([]byte, 0, len(body)-(commentEnd-commentStart))
	stripped = append(stripped, body[:commentStart]...)
	stripped = append(stripped, body[commentEnd:]...)
	stripped[3] &^= 0x10
	if err := os.WriteFile(destination, stripped, 0o600); err != nil {
		t.Fatal(err)
	}
}

func prependIncompleteTarGzipMember(t *testing.T, source, destination string) {
	prependIncompleteTarGzipMemberWithGap(t, source, destination, nil, nil)
}

func prependIncompleteTarGzipMemberWithGap(t *testing.T, source, destination string, gap []byte, mutate func([]byte) []byte) {
	t.Helper()
	var prefix bytes.Buffer
	compressed := gzip.NewWriter(&prefix)
	archive := tar.NewWriter(compressed)
	body := []byte("ordinary prefix\n")
	if err := archive.WriteHeader(&tar.Header{Name: "ordinary-prefix.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(body); err != nil {
		t.Fatal(err)
	}
	// Flush the complete entry but deliberately omit tar's end-of-archive
	// blocks. A standard multistream gzip reader then exposes the following
	// member as a continuation of this tar stream.
	if err := archive.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	suffix, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		suffix = mutate(suffix)
	}
	joined := append(append(append([]byte(nil), prefix.Bytes()...), gap...), suffix...)
	if err := os.WriteFile(destination, joined, 0o600); err != nil {
		t.Fatal(err)
	}
}

func prependCorruptGzipMember(t *testing.T, source, destination string) {
	t.Helper()
	var prefix bytes.Buffer
	compressed := gzip.NewWriter(&prefix)
	if _, err := compressed.Write([]byte("ordinary corrupt prefix\n")); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	encoded := append([]byte(nil), prefix.Bytes()...)
	if len(encoded) < 8 {
		t.Fatal("ordinary gzip prefix has no trailer")
	}
	encoded[len(encoded)-8] ^= 0x01
	suffix, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, append(encoded, suffix...), 0o600); err != nil {
		t.Fatal(err)
	}
}

func ordinaryGzipWithExactSize(t *testing.T, size int) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	if _, err := compressed.Write([]byte("ordinary opaque asset\n")); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	base := output.Bytes()
	extraLength := size - len(base) - 2
	if extraLength < 0 || extraLength > 65535 || len(base) < 10 || base[3]&0x06 != 0 {
		t.Fatalf("cannot pad ordinary gzip from %d to %d bytes", len(base), size)
	}
	padded := make([]byte, 0, size)
	padded = append(padded, base[:10]...)
	padded[3] |= 0x04
	padded = append(padded, byte(extraLength), byte(extraLength>>8))
	padded = append(padded, make([]byte, extraLength)...)
	padded = append(padded, base[10:]...)
	if len(padded) != size {
		t.Fatalf("ordinary gzip padding size=%d want=%d", len(padded), size)
	}
	return padded
}

func readOfflineArchiveGzipPayload(t *testing.T, filename string) []byte {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(compressed)
	if err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return body
}

const offlineArchiveTaintConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: source-gated
    type: asset
    path: gated/source
    default_pool: gated
    asset: {kind: test}
  - id: public-assets
    type: asset
    path: public/assets
    default_pool: public
    asset: {kind: test}
  - id: gated-assets
    type: asset
    path: gated/assets
    default_pool: gated
    asset: {kind: test}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
