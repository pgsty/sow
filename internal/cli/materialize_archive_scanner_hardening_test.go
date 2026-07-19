package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/state"
)

func TestOfflineArchiveMalformedTarBarrierCannotHideLaterPolicyMarker(t *testing.T) {
	markerText := offlineArchiveMarkerPrefix + "source_sha256=" + strings.Repeat("a", 64) + ";access=pro;confidentiality=gated"
	policyTar := scannerPolicyTar(t, markerText)

	var ordinary bytes.Buffer
	ordinaryTar := tar.NewWriter(&ordinary)
	body := []byte("ordinary\n")
	if err := ordinaryTar.WriteHeader(&tar.Header{Name: "ordinary.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)), Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if _, err := ordinaryTar.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := ordinaryTar.Close(); err != nil {
		t.Fatal(err)
	}
	barrier := bytes.Repeat([]byte{0x7f}, 512)
	payload := append(append(append([]byte(nil), ordinary.Bytes()...), barrier...), policyTar...)

	for _, test := range []struct {
		name    string
		payload []byte
	}{
		{name: "after-valid-tar", payload: payload},
		{name: "at-start", payload: append(append([]byte(nil), barrier...), policyTar...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "barrier.tgz")
			writeScannerGzip(t, archive, gzip.Header{}, test.payload)
			if _, err := inspectOfflineArchiveInput(archive); err == nil ||
				(!strings.Contains(err.Error(), "tar stream is invalid") && !strings.Contains(err.Error(), "hidden behind malformed tar bytes")) {
				t.Fatalf("malformed tar barrier concealed later policy marker: %v", err)
			}
		})
	}
}

func TestOfflineArchiveLargeFEXTRAHeaderUsesStreamingMarkerDecision(t *testing.T) {
	markerText := offlineArchiveMarkerPrefix + "source_sha256=" + strings.Repeat("b", 64) + ";access=public;confidentiality=public"
	archive := filepath.Join(t.TempDir(), "large-extra.tgz")
	writeScannerGzip(t, archive, gzip.Header{Extra: make([]byte, 65535), Comment: markerText}, scannerPolicyTar(t, markerText))

	inspected, err := inspectOfflineArchiveInput(archive)
	if err != nil {
		t.Fatal(err)
	}
	want, err := parseOfflineArchiveMarker(markerText)
	if err != nil || !offlineArchiveMarkersEqual(inspected.Marker, want) {
		t.Fatalf("large FEXTRA marker=%+v want=%+v parseErr=%v", inspected.Marker, want, err)
	}
}

func TestOfflineArchiveInspectionStopsAtExpandedByteBudget(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "bomb.gz")
	writeScannerGzip(t, archive, gzip.Header{}, make([]byte, 2<<20))
	limits := offlineArchiveInspectionLimits{
		MaxExpandedBytes:  64 << 10,
		MaxMembers:        4,
		MaxExpansionRatio: 1 << 20,
		ExpansionSlack:    1 << 20,
	}
	if _, err := inspectOfflineArchiveInputWithLimits(t.Context(), archive, limits); !errors.Is(err, errOfflineArchiveInspectionBudget) {
		t.Fatalf("expanded-byte budget error=%v", err)
	}
}

func TestOfflineArchiveInspectionStopsAtExpansionRatioBudget(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "ratio-bomb.gz")
	writeScannerGzip(t, archive, gzip.Header{}, make([]byte, 2<<20))
	limits := offlineArchiveInspectionLimits{
		MaxExpandedBytes:  1 << 30,
		MaxMembers:        4,
		MaxExpansionRatio: 8,
		ExpansionSlack:    64 << 10,
	}
	if _, err := inspectOfflineArchiveInputWithLimits(t.Context(), archive, limits); !errors.Is(err, errOfflineArchiveInspectionBudget) {
		t.Fatalf("expansion-ratio budget error=%v", err)
	}
}

func TestOfflineArchiveInspectionHonorsCanceledContext(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "ordinary.bin")
	if err := os.WriteFile(filename, []byte("ordinary"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := inspectOfflineArchiveInputContext(ctx, filename); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled inspection error=%v", err)
	}
}

func TestOfflineArchiveResidueCleanupDoesNotFollowStageDirectorySymlink(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	victimRoot := t.TempDir()
	victimName := offlineArchiveProjectionStagePrefix + strings.Repeat("c", 32) + ".tgz"
	victim := filepath.Join(victimRoot, victimName)
	if err := os.WriteFile(victim, []byte("must survive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimRoot, filepath.Join(stateRoot, offlineArchiveProjectionStageDir)); err != nil {
		t.Fatal(err)
	}
	if err := cleanupOfflineArchiveProjectionResidue(stateRoot, true); err == nil || !strings.Contains(err.Error(), "stage directory is not private") {
		t.Fatalf("symlinked stage cleanup error=%v", err)
	}
	if body, err := os.ReadFile(victim); err != nil || string(body) != "must survive\n" {
		t.Fatalf("cleanup changed external victim body=%q err=%v", body, err)
	}
}

func TestOfflineArchiveIntentDirectorySyncFailureKeepsRecoverableStage(t *testing.T) {
	root, configPath := newOfflineArchiveTaintFixture(t)
	input := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(input, []byte("intent sync recovery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "add", input, "--config", configPath, "--repo", "public-assets", "--dest", "payload.bin")
	runArchiveTaintOK(t, "promote", "beta", "latest", "--config", configPath, "--repo", "public-assets")
	destination := filepath.Join(root, "offline", "intent-sync.tgz")

	previous := offlineArchiveProjectionIntentWrite
	offlineArchiveProjectionIntentWrite = func(stateRoot, relative string, body []byte) error {
		if err := writeDerivedStateFile(stateRoot, relative, body); err != nil {
			return err
		}
		return errors.New("injected offline archive intent directory sync failure")
	}
	code, stdout, stderr := runArchiveTaintCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", destination,
		"--workers", "1", "--chunk-entries", "1",
	)
	offlineArchiveProjectionIntentWrite = previous
	t.Cleanup(func() { offlineArchiveProjectionIntentWrite = previous })
	if code != ExitVerification || !strings.Contains(stderr, "injected offline archive intent directory sync failure") {
		t.Fatalf("intent sync fault code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	intent, exists, err := readOfflineArchiveProjectionIntent(filepath.Join(root, ".sow"))
	if err != nil || !exists {
		t.Fatalf("intent sync fault lost recoverable intent exists=%t err=%v", exists, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", intent.StageRelative)); err != nil {
		t.Fatalf("intent sync fault lost durable stage: %v", err)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed precommit installed visible destination: %v", err)
	}

	code, stdout, stderr = runArchiveTaintCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", destination,
		"--workers", "1", "--chunk-entries", "1", "--recover",
	)
	if code != ExitOK || !strings.Contains(stdout, "recovered offline archive path=") {
		t.Fatalf("intent sync recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, exists, err := readOfflineArchiveProjectionIntent(filepath.Join(root, ".sow")); err != nil || exists {
		t.Fatalf("intent sync recovery retained intent exists=%t err=%v", exists, err)
	}
	if inspected, err := inspectOfflineArchiveInput(destination); err != nil || inspected.Object.HashString() != intent.ArchiveSHA256 {
		t.Fatalf("intent sync recovery object=%+v want=%s err=%v", inspected.Object, intent.ArchiveSHA256, err)
	}
}

func TestOfflineArchiveRecoveryAcceptsSemanticallyEquivalentExistingReceipt(t *testing.T) {
	root, configPath := newOfflineArchiveTaintFixture(t)
	input := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(input, []byte("semantic receipt recovery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "add", input, "--config", configPath, "--repo", "public-assets", "--dest", "payload.bin")
	runArchiveTaintOK(t, "promote", "beta", "latest", "--config", configPath, "--repo", "public-assets")
	firstDestination := filepath.Join(root, "offline", "first.tgz")
	runArchiveTaintOK(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", firstDestination,
		"--workers", "1", "--chunk-entries", "1",
	)
	first, err := inspectOfflineArchiveInput(firstDestination)
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	receipt, exists, err := readOfflineArchiveTaintReceipt(canonical, first.Object.HashString())
	if err != nil || !exists {
		t.Fatalf("initial receipt exists=%t err=%v", exists, err)
	}
	latestRef, err := state.ViewRef("latest", "public-assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	oldCommit, exists, err := canonical.Ref(latestRef)
	if err != nil || !exists {
		t.Fatalf("initial latest ref exists=%t err=%v", exists, err)
	}
	txDir, err := newTransactionDir(filepath.Join(root, ".sow"), "test-semantic-archive-source-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(txDir)
	unrelated := filepath.Join(txDir, "unrelated.txt")
	if err := os.WriteFile(unrelated, []byte("new commit, same view bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	newCommit, changed, err := canonical.Apply(t.Context(), "test-semantic-archive-source", "advance ref without changing its view blob",
		map[string]string{"tests/semantic-archive-source.txt": unrelated}, []state.RefUpdate{{Name: latestRef, Expected: oldCommit}}, state.ApplyOptions{})
	if err != nil || !changed || newCommit == oldCommit {
		t.Fatalf("advance semantic source commit=%s old=%s changed=%t err=%v", newCommit, oldCommit, changed, err)
	}

	secondDestination := filepath.Join(root, "offline", "second.tgz")
	previous := archiveBeforeAtomicInstallHook
	injected := errors.New("injected semantic receipt recovery stop")
	archiveBeforeAtomicInstallHook = func(archiveResult) error { return injected }
	code, stdout, stderr := runArchiveTaintCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", secondDestination,
		"--workers", "1", "--chunk-entries", "1",
	)
	archiveBeforeAtomicInstallHook = previous
	t.Cleanup(func() { archiveBeforeAtomicInstallHook = previous })
	if code != ExitVerification || !strings.Contains(stderr, injected.Error()) {
		t.Fatalf("semantic receipt stop code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	intent, exists, err := readOfflineArchiveProjectionIntent(filepath.Join(root, ".sow"))
	if err != nil || !exists || intent.ArchiveSHA256 != first.Object.HashString() {
		t.Fatalf("semantic receipt intent exists=%t intent=%+v first=%s err=%v", exists, intent, first.Object.HashString(), err)
	}
	if len(intent.Source.Refs) == 0 || len(receipt.Source.Refs) == 0 || intent.Source.Refs[0].Commit == receipt.Source.Refs[0].Commit {
		t.Fatalf("fixture did not retain distinct commit witnesses intent=%+v receipt=%+v", intent.Source.Refs, receipt.Source.Refs)
	}
	code, stdout, stderr = runArchiveTaintCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", secondDestination,
		"--workers", "1", "--chunk-entries", "1", "--recover",
	)
	if code != ExitOK || !strings.Contains(stdout, "recovered offline archive path=") {
		t.Fatalf("semantic receipt recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if second, err := inspectOfflineArchiveInput(secondDestination); err != nil || second.Object.HashString() != first.Object.HashString() {
		t.Fatalf("semantic receipt recovered digest=%s want=%s err=%v", second.Object.HashString(), first.Object.HashString(), err)
	}
}

func scannerPolicyTar(t *testing.T, markerText string) []byte {
	t.Helper()
	body, err := offlineArchivePayloadMarkerForComment(markerText)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	header := &tar.Header{
		Name: offlineArchivePayloadMarkerPath, Typeflag: tar.TypeReg, Mode: 0o444,
		Size: int64(len(body)), ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR,
	}
	if err := writer.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func writeScannerGzip(t *testing.T, filename string, header gzip.Header, payload []byte) {
	t.Helper()
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := gzip.NewWriter(file)
	writer.Header = header
	_, writeErr := writer.Write(payload)
	closeErr := errors.Join(writer.Close(), file.Close())
	if writeErr != nil || closeErr != nil {
		t.Fatal(errors.Join(writeErr, closeErr))
	}
}
