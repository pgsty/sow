package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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

func TestOfflineArchiveIntentTempCleanupPreservesConcurrentReplacement(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name := offlineArchiveProjectionIntentRelative + ".tmp-" + strings.Repeat("a", 32)
	path := filepath.Join(stateRoot, name)
	displaced := filepath.Join(t.TempDir(), "admitted-intent-temp")
	if err := os.WriteFile(path, []byte("admitted temp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := projectionResidueCleanupHook
	projectionResidueCleanupHook = func(relative string) error {
		if relative != name {
			return errors.New("unexpected residue cleanup coordinate")
		}
		if err := os.Rename(path, displaced); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("replacement temp\n"), 0o600)
	}
	t.Cleanup(func() { projectionResidueCleanupHook = previous })
	err := cleanupOfflineArchiveProjectionResidue(stateRoot, true)
	projectionResidueCleanupHook = previous
	if err == nil {
		t.Fatal("intent temporary replacement was accepted as exact cleanup")
	}
	if body, readErr := os.ReadFile(path); readErr != nil || string(body) != "replacement temp\n" {
		t.Fatalf("intent temporary replacement body=%q err=%v cleanupErr=%v", body, readErr, err)
	}
	if body, readErr := os.ReadFile(displaced); readErr != nil || string(body) != "admitted temp\n" {
		t.Fatalf("admitted intent temporary body=%q err=%v", body, readErr)
	}
}

func TestOfflineArchiveStageResidueCleanupPreservesConcurrentReplacement(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	stageDirectory := filepath.Join(stateRoot, offlineArchiveProjectionStageDir)
	if err := os.MkdirAll(stageDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	name := offlineArchiveProjectionStagePrefix + strings.Repeat("b", 32) + ".tgz"
	path := filepath.Join(stageDirectory, name)
	displaced := filepath.Join(t.TempDir(), "admitted-stage.tgz")
	if err := os.WriteFile(path, []byte("admitted archive stage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	previous := projectionResidueCleanupHook
	projectionResidueCleanupHook = func(relative string) error {
		if relative != name {
			return errors.New("unexpected stage cleanup coordinate")
		}
		if err := os.Rename(path, displaced); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte("replacement archive stage\n"), 0o600); err != nil {
			return err
		}
		return os.Chmod(path, 0o444)
	}
	t.Cleanup(func() { projectionResidueCleanupHook = previous })
	err := cleanupOfflineArchiveProjectionResidue(stateRoot, true)
	projectionResidueCleanupHook = previous
	if err == nil {
		t.Fatal("archive stage replacement was accepted as exact cleanup")
	}
	if body, readErr := os.ReadFile(path); readErr != nil || string(body) != "replacement archive stage\n" {
		t.Fatalf("archive stage replacement body=%q err=%v cleanupErr=%v", body, readErr, err)
	}
	if body, readErr := os.ReadFile(displaced); readErr != nil || string(body) != "admitted archive stage\n" {
		t.Fatalf("admitted archive stage body=%q err=%v", body, readErr)
	}
}

func TestOfflineArchiveResidueCleanupRejectsMalformedNames(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage bool
	}{
		{name: offlineArchiveProjectionIntentRelative + ".tmp"},
		{name: offlineArchiveProjectionIntentRelative + ".tmp-not-hex"},
		{name: offlineArchiveProjectionStagePrefix + strings.Repeat("c", 32) + ".tgz.tmp-remove-not-hex", stage: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateRoot := filepath.Join(t.TempDir(), ".sow")
			directory := stateRoot
			mode := os.FileMode(0o600)
			if tc.stage {
				directory = filepath.Join(stateRoot, offlineArchiveProjectionStageDir)
				mode = 0o444
			}
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, tc.name)
			if err := os.WriteFile(path, []byte("malformed residue\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			err := cleanupOfflineArchiveProjectionResidue(stateRoot, true)
			if err == nil || !strings.Contains(err.Error(), "unsafe offline archive projection") {
				t.Fatalf("malformed residue error=%v", err)
			}
			if body, readErr := os.ReadFile(path); readErr != nil || string(body) != "malformed residue\n" {
				t.Fatalf("malformed residue body=%q err=%v", body, readErr)
			}
		})
	}
}

func TestOfflineArchiveResidueCleanupIsExactAndIdempotent(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	stageDirectory := filepath.Join(stateRoot, offlineArchiveProjectionStageDir)
	if err := os.MkdirAll(stageDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	temporaries := []string{
		filepath.Join(stateRoot, offlineArchiveProjectionIntentRelative+".tmp-"+strings.Repeat("d", 32)),
		filepath.Join(stateRoot, offlineArchiveProjectionIntentRelative+".tmp-remove-"+strings.Repeat("6", 32)),
		filepath.Join(stateRoot, offlineArchiveProjectionIntentRelative+".tmp-"+strings.Repeat("7", 32)+".tmp-remove-"+strings.Repeat("8", 32)+".tmp-remove-"+strings.Repeat("9", 32)),
	}
	stageBase := offlineArchiveProjectionStagePrefix + strings.Repeat("e", 32) + ".tgz"
	stages := []string{
		filepath.Join(stageDirectory, stageBase),
		filepath.Join(stageDirectory, stageBase+".tmp-remove-"+strings.Repeat("f", 32)),
		filepath.Join(stageDirectory, stageBase+".tmp-install-"+strings.Repeat("a", 32)+".tmp-remove-"+strings.Repeat("b", 32)+".tmp-remove-"+strings.Repeat("c", 32)),
	}
	for _, temporary := range temporaries {
		if err := os.WriteFile(temporary, []byte("intent temporary\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, stage := range stages {
		if err := os.WriteFile(stage, []byte("archive stage\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(stage, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	if err := cleanupOfflineArchiveProjectionResidue(stateRoot, false); err == nil || !strings.Contains(err.Error(), "requires --recover") {
		t.Fatalf("non-recovery residue error=%v", err)
	}
	for _, path := range append(append([]string(nil), temporaries...), stages...) {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("non-recovery changed %s: %v", path, err)
		}
	}
	if err := cleanupOfflineArchiveProjectionResidue(stateRoot, true); err != nil {
		t.Fatalf("recover exact residues: %v", err)
	}
	for _, path := range append(append([]string(nil), temporaries...), stages...) {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovery retained %s: %v", path, err)
		}
	}
	if err := cleanupOfflineArchiveProjectionResidue(stateRoot, true); err != nil {
		t.Fatalf("idempotent residue recovery: %v", err)
	}
}

func TestOfflineArchiveResidueCleanupRequarantinesWithoutNesting(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name := offlineArchiveProjectionIntentRelative + ".tmp-remove-" + strings.Repeat("d", 32)
	path := filepath.Join(stateRoot, name)
	if err := os.WriteFile(path, []byte("interrupted quarantine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("stop after stable requarantine")
	observed := ""
	previous := projectionStateBeforeUnlinkHook
	projectionStateBeforeUnlinkHook = func(quarantine string) error {
		observed = quarantine
		return injected
	}
	t.Cleanup(func() { projectionStateBeforeUnlinkHook = previous })
	err := cleanupOfflineArchiveProjectionResidue(stateRoot, true)
	projectionStateBeforeUnlinkHook = previous
	if !errors.Is(err, injected) {
		t.Fatalf("stable requarantine error=%v", err)
	}
	if strings.Count(observed, ".tmp-remove-") != 1 || !strings.HasPrefix(observed, offlineArchiveProjectionIntentRelative+".tmp-remove-") {
		t.Fatalf("requarantine nested its removal suffix: %q", observed)
	}
	if body, readErr := os.ReadFile(path); readErr != nil || string(body) != "interrupted quarantine\n" {
		t.Fatalf("failed requarantine did not restore original coordinate body=%q err=%v", body, readErr)
	}
	if err := cleanupOfflineArchiveProjectionResidue(stateRoot, true); err != nil {
		t.Fatalf("replay stable requarantine: %v", err)
	}
}

func TestOfflineArchiveIntentTempCleanupRejectsSpecialFilesWithoutBlocking(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			stateRoot := filepath.Join(t.TempDir(), ".sow")
			if err := os.Mkdir(stateRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			name := offlineArchiveProjectionIntentRelative + ".tmp-" + strings.Repeat("1", 32)
			path := filepath.Join(stateRoot, name)
			switch kind {
			case "fifo":
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				victim := filepath.Join(t.TempDir(), "victim")
				if err := os.WriteFile(victim, []byte("victim\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, path); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() { done <- cleanupOfflineArchiveProjectionResidue(stateRoot, true) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("%s residue was accepted", kind)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("%s residue cleanup blocked", kind)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("%s residue was removed: %v", kind, err)
			}
		})
	}
}

func TestOfflineArchiveResidueCleanupRequiresExactModes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  os.FileMode
		stage bool
	}{
		{name: "intent-read-only", mode: 0o400},
		{name: "intent-owner-executable", mode: 0o700},
		{name: "stage-owner-writable", mode: 0o644, stage: true},
		{name: "stage-owner-only", mode: 0o400, stage: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateRoot := filepath.Join(t.TempDir(), ".sow")
			directory := stateRoot
			name := offlineArchiveProjectionIntentRelative + ".tmp-" + strings.Repeat("e", 32)
			if tc.stage {
				directory = filepath.Join(stateRoot, offlineArchiveProjectionStageDir)
				name = offlineArchiveProjectionStagePrefix + strings.Repeat("e", 32) + ".tgz"
			}
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, name)
			if err := os.WriteFile(path, []byte("wrong mode\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			err := cleanupOfflineArchiveProjectionResidue(stateRoot, true)
			if err == nil || !strings.Contains(err.Error(), "not an exact regular file") {
				t.Fatalf("wrong mode %04o error=%v", tc.mode, err)
			}
			if _, statErr := os.Lstat(path); statErr != nil {
				t.Fatalf("wrong-mode residue was removed: %v", statErr)
			}
		})
	}

	stateRoot := t.TempDir()
	path := filepath.Join(stateRoot, "mode-source")
	if err := os.WriteFile(path, []byte("mode source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if exactOfflineArchiveIntentTemporary(offlineArchiveModeInfo{FileInfo: info, mode: 0o600 | os.ModeSetuid}) ||
		exactOfflineArchiveStageResidue(offlineArchiveModeInfo{FileInfo: info, mode: 0o444 | os.ModeSticky}) {
		t.Fatal("special mode bits were admitted by exact residue policies")
	}
}

func TestDerivedStateWriterRepairsRestrictiveUmaskToExactPrivateMode(t *testing.T) {
	stateRoot := t.TempDir()
	previousUmask := syscall.Umask(0o400)
	err := writeDerivedStateFile(stateRoot, "exact-private.json", []byte("{}\n"))
	syscall.Umask(previousUmask)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(stateRoot, "exact-private.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode() != 0o600 {
		t.Fatalf("derived state mode=%v want=0600", info.Mode())
	}
}

func TestSOWProcessInitNormalizesRestrictiveOwnerUmask(t *testing.T) {
	if output := os.Getenv("SOW_UMASK_HELPER_OUTPUT"); output != "" {
		if err := os.Mkdir(output, 0o700); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(filepath.Join(output, "state"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	output := filepath.Join(t.TempDir(), "init-mode-directory")
	previousUmask := syscall.Umask(0o500)
	command := exec.Command(os.Args[0], "-test.run=^TestSOWProcessInitNormalizesRestrictiveOwnerUmask$")
	command.Env = append(os.Environ(), "SOW_UMASK_HELPER_OUTPUT="+output)
	runErr := command.Run()
	syscall.Umask(previousUmask)
	if runErr != nil {
		t.Fatal(runErr)
	}
	info, err := os.Lstat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode() != os.ModeDir|0o700 {
		t.Fatalf("process-init directory mode=%v want=0700", info.Mode())
	}
	info, err = os.Lstat(filepath.Join(output, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode() != 0o600 {
		t.Fatalf("process-init state mode=%v want=0600", info.Mode())
	}
}

func TestDerivedStateWriterRejectsSameInodeModeMutation(t *testing.T) {
	stateRoot := t.TempDir()
	previous := derivedStateWriteHook
	derivedStateWriteHook = func(relative string) error {
		return os.Chmod(filepath.Join(stateRoot, filepath.Base(relative)), 0o400)
	}
	t.Cleanup(func() { derivedStateWriteHook = previous })
	err := writeDerivedStateFile(stateRoot, "mode-mutated.json", []byte("{}\n"))
	derivedStateWriteHook = previous
	if err == nil || !strings.Contains(err.Error(), "temporary changed while writing") {
		t.Fatalf("same-inode mode mutation error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(stateRoot, "mode-mutated.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("mode-mutated state was published: %v", statErr)
	}
	entries, readErr := os.ReadDir(stateRoot)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("mode-mutated temporary was not cleaned entries=%v err=%v", entries, readErr)
	}
}

func TestOfflineArchiveIntentTempBindRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name := offlineArchiveProjectionIntentRelative + ".tmp-" + strings.Repeat("4", 32)
	path := filepath.Join(stateRoot, name)
	displaced := filepath.Join(t.TempDir(), "admitted-bind-temp")
	if err := os.WriteFile(path, []byte("admitted bind temp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := projectionStateBeforeBindOpenHook
	projectionStateBeforeBindOpenHook = func(relative string) error {
		if relative != name {
			return errors.New("unexpected bind coordinate")
		}
		if err := os.Rename(path, displaced); err != nil {
			return err
		}
		return syscall.Mkfifo(path, 0o600)
	}
	t.Cleanup(func() { projectionStateBeforeBindOpenHook = previous })
	done := make(chan error, 1)
	go func() { done <- cleanupOfflineArchiveProjectionResidue(stateRoot, true) }()
	select {
	case err := <-done:
		projectionStateBeforeBindOpenHook = previous
		if err == nil || !strings.Contains(err.Error(), "changed while binding") {
			t.Fatalf("FIFO bind replacement error=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO replacement blocked residue binding")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("FIFO replacement info=%+v err=%v", info, err)
	}
	if body, err := os.ReadFile(displaced); err != nil || string(body) != "admitted bind temp\n" {
		t.Fatalf("admitted bind temp body=%q err=%v", body, err)
	}
}

func TestOfflineArchiveIntentTempCleanupRevalidatesFinalUnlinkBoundary(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name := offlineArchiveProjectionIntentRelative + ".tmp-" + strings.Repeat("5", 32)
	path := filepath.Join(stateRoot, name)
	displaced := filepath.Join(t.TempDir(), "admitted-quarantine-temp")
	if err := os.WriteFile(path, []byte("admitted quarantine temp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := projectionStateBeforeUnlinkHook
	projectionStateBeforeUnlinkHook = func(quarantine string) error {
		quarantinePath := filepath.Join(stateRoot, quarantine)
		if err := os.Rename(quarantinePath, displaced); err != nil {
			return err
		}
		return os.WriteFile(quarantinePath, []byte("final unlink replacement\n"), 0o600)
	}
	t.Cleanup(func() { projectionStateBeforeUnlinkHook = previous })
	err := cleanupOfflineArchiveProjectionResidue(stateRoot, true)
	projectionStateBeforeUnlinkHook = previous
	if err == nil || !strings.Contains(err.Error(), "quarantine changed before unlink") {
		t.Fatalf("final unlink replacement error=%v", err)
	}
	if body, readErr := os.ReadFile(path); readErr != nil || string(body) != "final unlink replacement\n" {
		t.Fatalf("final unlink replacement body=%q err=%v", body, readErr)
	}
	if body, readErr := os.ReadFile(displaced); readErr != nil || string(body) != "admitted quarantine temp\n" {
		t.Fatalf("admitted quarantine body=%q err=%v", body, readErr)
	}
}

func TestOfflineArchiveIntentTempCleanupRejectsReoccupiedCoordinate(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name := offlineArchiveProjectionIntentRelative + ".tmp-" + strings.Repeat("a", 32)
	path := filepath.Join(stateRoot, name)
	if err := os.WriteFile(path, []byte("admitted coordinate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := projectionStateBeforeUnlinkHook
	projectionStateBeforeUnlinkHook = func(string) error {
		return os.WriteFile(path, []byte("reoccupied coordinate\n"), 0o600)
	}
	t.Cleanup(func() { projectionStateBeforeUnlinkHook = previous })
	err := cleanupOfflineArchiveProjectionResidue(stateRoot, true)
	projectionStateBeforeUnlinkHook = previous
	if err == nil || !strings.Contains(err.Error(), "was reoccupied") {
		t.Fatalf("reoccupied coordinate error=%v", err)
	}
	if body, readErr := os.ReadFile(path); readErr != nil || string(body) != "reoccupied coordinate\n" {
		t.Fatalf("replacement coordinate body=%q err=%v", body, readErr)
	}
	entries, readErr := os.ReadDir(stateRoot)
	if readErr != nil {
		t.Fatal(readErr)
	}
	preserved := false
	for _, entry := range entries {
		if entry.Name() == name || !strings.HasPrefix(entry.Name(), name+".tmp-remove-") {
			continue
		}
		body, readErr := os.ReadFile(filepath.Join(stateRoot, entry.Name()))
		if readErr == nil && string(body) == "admitted coordinate\n" {
			preserved = true
		}
	}
	if !preserved {
		t.Fatal("admitted inode was not retained at its exact quarantine")
	}
}

func TestOfflineArchiveIntentTempCleanupRejectsStateRootReplacement(t *testing.T) {
	parent := t.TempDir()
	stateRoot := filepath.Join(parent, ".sow")
	displacedRoot := filepath.Join(parent, "admitted-state-root")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name := offlineArchiveProjectionIntentRelative + ".tmp-" + strings.Repeat("2", 32)
	if err := os.WriteFile(filepath.Join(stateRoot, name), []byte("admitted root\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := projectionResidueCleanupHook
	projectionResidueCleanupHook = func(string) error {
		if err := os.Rename(stateRoot, displacedRoot); err != nil {
			return err
		}
		if err := os.Mkdir(stateRoot, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(stateRoot, name), []byte("replacement root\n"), 0o600)
	}
	t.Cleanup(func() { projectionResidueCleanupHook = previous })
	err := cleanupOfflineArchiveProjectionResidue(stateRoot, true)
	projectionResidueCleanupHook = previous
	if err == nil || !strings.Contains(err.Error(), "root coordinate changed") {
		t.Fatalf("state-root replacement error=%v", err)
	}
	if body, readErr := os.ReadFile(filepath.Join(displacedRoot, name)); readErr != nil || string(body) != "admitted root\n" {
		t.Fatalf("admitted root residue body=%q err=%v", body, readErr)
	}
	if body, readErr := os.ReadFile(filepath.Join(stateRoot, name)); readErr != nil || string(body) != "replacement root\n" {
		t.Fatalf("replacement root residue body=%q err=%v", body, readErr)
	}
}

func TestOfflineArchiveStageCleanupRejectsNewOwningIntent(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	stageDirectory := filepath.Join(stateRoot, offlineArchiveProjectionStageDir)
	if err := os.MkdirAll(stageDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	transactionID := strings.Repeat("c", 32)
	name := offlineArchiveProjectionStagePrefix + transactionID + ".tgz"
	path := filepath.Join(stageDirectory, name)
	if err := os.WriteFile(path, []byte("newly owned stage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	intent := testOfflineArchiveProjectionIntent(t, transactionID)
	previous := projectionResidueCleanupHook
	wroteIntent := false
	projectionResidueCleanupHook = func(relative string) error {
		if relative != name || wroteIntent {
			return nil
		}
		wroteIntent = true
		return writeOfflineArchiveProjectionIntent(stateRoot, intent)
	}
	t.Cleanup(func() { projectionResidueCleanupHook = previous })
	err := cleanupOfflineArchiveProjectionResidue(stateRoot, true)
	projectionResidueCleanupHook = previous
	if err == nil || !strings.Contains(err.Error(), "intent changed during residue cleanup") {
		t.Fatalf("new owning intent error=%v", err)
	}
	if !wroteIntent {
		t.Fatal("ownership change seam did not run")
	}
	if body, readErr := os.ReadFile(path); readErr != nil || string(body) != "newly owned stage\n" {
		t.Fatalf("newly owned stage body=%q err=%v", body, readErr)
	}
	if current, exists, readErr := readOfflineArchiveProjectionIntent(stateRoot); readErr != nil || !exists || current.ID != intent.ID {
		t.Fatalf("new owner intent exists=%t current=%+v err=%v", exists, current, readErr)
	}
}

func TestOfflineArchiveResidueNoDeleteBranchRevalidatesStateRoot(t *testing.T) {
	parent := t.TempDir()
	stateRoot := filepath.Join(parent, ".sow")
	displaced := filepath.Join(parent, "admitted-state-root")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := offlineArchiveProjectionResidueBeforeReturnHook
	offlineArchiveProjectionResidueBeforeReturnHook = func() error {
		if err := os.Rename(stateRoot, displaced); err != nil {
			return err
		}
		return os.Mkdir(stateRoot, 0o700)
	}
	t.Cleanup(func() { offlineArchiveProjectionResidueBeforeReturnHook = previous })
	err := cleanupOfflineArchiveProjectionResidue(stateRoot, true)
	offlineArchiveProjectionResidueBeforeReturnHook = previous
	if err == nil || !strings.Contains(err.Error(), "root coordinate changed") {
		t.Fatalf("no-delete state-root replacement error=%v", err)
	}
	if info, statErr := os.Stat(displaced); statErr != nil || !info.IsDir() {
		t.Fatalf("bound state root was not preserved info=%+v err=%v", info, statErr)
	}
}

func TestOfflineArchiveResidueNoStageBranchRejectsAppearingStageCoordinate(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	stageDirectory := filepath.Join(stateRoot, offlineArchiveProjectionStageDir)
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := offlineArchiveProjectionResidueBeforeReturnHook
	offlineArchiveProjectionResidueBeforeReturnHook = func() error {
		return os.Mkdir(stageDirectory, 0o700)
	}
	t.Cleanup(func() { offlineArchiveProjectionResidueBeforeReturnHook = previous })
	err := cleanupOfflineArchiveProjectionResidue(stateRoot, true)
	offlineArchiveProjectionResidueBeforeReturnHook = previous
	if err == nil || !strings.Contains(err.Error(), "stage coordinate appeared") {
		t.Fatalf("appearing stage coordinate error=%v", err)
	}
	if info, statErr := os.Stat(stageDirectory); statErr != nil || !info.IsDir() {
		t.Fatalf("appearing stage coordinate info=%+v err=%v", info, statErr)
	}
}

func TestOfflineArchiveOwnedStageBranchRevalidatesStageRoot(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	stageDirectory := filepath.Join(stateRoot, offlineArchiveProjectionStageDir)
	displaced := filepath.Join(stateRoot, "admitted-stage-root")
	if err := os.MkdirAll(stageDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	transactionID := strings.Repeat("d", 32)
	name := offlineArchiveProjectionStagePrefix + transactionID + ".tgz"
	path := filepath.Join(stageDirectory, name)
	if err := os.WriteFile(path, []byte("owned final stage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := writeOfflineArchiveProjectionIntent(stateRoot, testOfflineArchiveProjectionIntent(t, transactionID)); err != nil {
		t.Fatal(err)
	}
	previous := offlineArchiveProjectionResidueBeforeReturnHook
	offlineArchiveProjectionResidueBeforeReturnHook = func() error {
		if err := os.Rename(stageDirectory, displaced); err != nil {
			return err
		}
		return os.Mkdir(stageDirectory, 0o700)
	}
	t.Cleanup(func() { offlineArchiveProjectionResidueBeforeReturnHook = previous })
	err := cleanupOfflineArchiveProjectionResidue(stateRoot, true)
	offlineArchiveProjectionResidueBeforeReturnHook = previous
	if err == nil || !strings.Contains(err.Error(), "root coordinate changed") {
		t.Fatalf("owned-stage root replacement error=%v", err)
	}
	if body, readErr := os.ReadFile(filepath.Join(displaced, name)); readErr != nil || string(body) != "owned final stage\n" {
		t.Fatalf("owned final stage body=%q err=%v", body, readErr)
	}
}

func TestOfflineArchiveStageCleanupRejectsDirectoryReplacement(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	stageDirectory := filepath.Join(stateRoot, offlineArchiveProjectionStageDir)
	displaced := filepath.Join(stateRoot, "admitted-stage-directory")
	if err := os.MkdirAll(stageDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	name := offlineArchiveProjectionStagePrefix + strings.Repeat("3", 32) + ".tgz"
	writeStage := func(directory, body string) error {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			return err
		}
		return os.Chmod(path, 0o444)
	}
	if err := writeStage(stageDirectory, "admitted stage root\n"); err != nil {
		t.Fatal(err)
	}
	previous := projectionResidueCleanupHook
	projectionResidueCleanupHook = func(string) error {
		if err := os.Rename(stageDirectory, displaced); err != nil {
			return err
		}
		if err := os.Mkdir(stageDirectory, 0o700); err != nil {
			return err
		}
		return writeStage(stageDirectory, "replacement stage root\n")
	}
	t.Cleanup(func() { projectionResidueCleanupHook = previous })
	err := cleanupOfflineArchiveProjectionResidue(stateRoot, true)
	projectionResidueCleanupHook = previous
	if err == nil || !strings.Contains(err.Error(), "root coordinate changed") {
		t.Fatalf("stage-directory replacement error=%v", err)
	}
	if body, readErr := os.ReadFile(filepath.Join(displaced, name)); readErr != nil || string(body) != "admitted stage root\n" {
		t.Fatalf("admitted stage-root residue body=%q err=%v", body, readErr)
	}
	if body, readErr := os.ReadFile(filepath.Join(stageDirectory, name)); readErr != nil || string(body) != "replacement stage root\n" {
		t.Fatalf("replacement stage-root residue body=%q err=%v", body, readErr)
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
	offlineArchiveProjectionIntentWrite = func(stateRoot, relative string, body []byte) (derivedStateReplacementResult, error) {
		result, err := writeDerivedStateFileOutcome(stateRoot, relative, body)
		if err != nil {
			return result, err
		}
		return result, errors.New("injected offline archive intent directory sync failure")
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

func TestOfflineArchiveIntentWriteFailureReportsStageCleanupDrift(t *testing.T) {
	root, configPath := newOfflineArchiveTaintFixture(t)
	input := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(input, []byte("intent cleanup drift\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "add", input, "--config", configPath, "--repo", "public-assets", "--dest", "payload.bin")
	runArchiveTaintOK(t, "promote", "beta", "latest", "--config", configPath, "--repo", "public-assets")
	destination := filepath.Join(root, "offline", "intent-cleanup.tgz")
	stateRoot := filepath.Join(root, ".sow")
	stageDirectory := filepath.Join(stateRoot, offlineArchiveProjectionStageDir)

	previous := offlineArchiveProjectionIntentWrite
	previousDiscard := offlineArchiveProjectionStageDiscard
	offlineArchiveProjectionIntentWrite = func(string, string, []byte) (derivedStateReplacementResult, error) {
		return derivedStateReplacementResult{Outcome: derivedStateReplacementNotCommitted}, errors.New("injected offline archive intent write failure")
	}
	offlineArchiveProjectionStageDiscard = func(string, string) error {
		return errors.New("injected offline archive projection stage cleanup failure")
	}
	t.Cleanup(func() {
		offlineArchiveProjectionIntentWrite = previous
		offlineArchiveProjectionStageDiscard = previousDiscard
	})
	code, stdout, stderr := runArchiveTaintCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", destination,
		"--workers", "1", "--chunk-entries", "1",
	)
	offlineArchiveProjectionIntentWrite = previous
	offlineArchiveProjectionStageDiscard = previousDiscard
	if code != ExitVerification || !strings.Contains(stderr, "injected offline archive intent write failure") ||
		!strings.Contains(stderr, "offline archive projection stage cleanup failed") || !strings.Contains(stderr, "--recover") {
		t.Fatalf("intent cleanup drift code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, exists, err := readOfflineArchiveProjectionIntent(stateRoot); err != nil || exists {
		t.Fatalf("failed intent write installed an intent exists=%t err=%v", exists, err)
	}
	entries, err := os.ReadDir(stageDirectory)
	if err != nil || len(entries) != 1 || !offlineArchiveProjectionStagePattern.MatchString(entries[0].Name()) {
		t.Fatalf("failed cleanup residue entries=%v err=%v", entries, err)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed pre-intent cleanup installed visible destination: %v", err)
	}

	code, stdout, stderr = runArchiveTaintCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", destination,
		"--workers", "1", "--chunk-entries", "1", "--recover",
	)
	if code != ExitOK {
		t.Fatalf("intent cleanup recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Stat(destination); err != nil {
		t.Fatalf("intent cleanup recovery omitted archive: %v", err)
	}
	entries, err = os.ReadDir(stageDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("intent cleanup recovery retained stages=%v err=%v", entries, err)
	}
}

func TestOfflineArchiveIntentWriteFailureRemovesUnownedStage(t *testing.T) {
	root, configPath := newOfflineArchiveTaintFixture(t)
	input := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(input, []byte("intent cleanup success\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runArchiveTaintOK(t, "add", input, "--config", configPath, "--repo", "public-assets", "--dest", "payload.bin")
	runArchiveTaintOK(t, "promote", "beta", "latest", "--config", configPath, "--repo", "public-assets")
	destination := filepath.Join(root, "offline", "intent-cleanup.tgz")
	stateRoot := filepath.Join(root, ".sow")
	stageDirectory := filepath.Join(stateRoot, offlineArchiveProjectionStageDir)

	previous := offlineArchiveProjectionIntentWrite
	offlineArchiveProjectionIntentWrite = func(string, string, []byte) (derivedStateReplacementResult, error) {
		return derivedStateReplacementResult{Outcome: derivedStateReplacementNotCommitted}, errors.New("injected offline archive intent write failure")
	}
	t.Cleanup(func() { offlineArchiveProjectionIntentWrite = previous })
	code, stdout, stderr := runArchiveTaintCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", destination,
		"--workers", "1", "--chunk-entries", "1",
	)
	offlineArchiveProjectionIntentWrite = previous
	if code != ExitVerification || !strings.Contains(stderr, "injected offline archive intent write failure") || strings.Contains(stderr, "stage cleanup failed") {
		t.Fatalf("intent write failure code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, exists, err := readOfflineArchiveProjectionIntent(stateRoot); err != nil || exists {
		t.Fatalf("failed intent write installed an intent exists=%t err=%v", exists, err)
	}
	entries, err := os.ReadDir(stageDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("successful cleanup retained stages=%v err=%v", entries, err)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed pre-intent write installed visible destination: %v", err)
	}

	code, stdout, stderr = runArchiveTaintCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "public-assets", "--tgz", destination,
		"--workers", "1", "--chunk-entries", "1",
	)
	if code != ExitOK {
		t.Fatalf("intent write retry code=%d stdout=%s stderr=%s", code, stdout, stderr)
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

func testOfflineArchiveProjectionIntent(t *testing.T, transactionID string) offlineArchiveProjectionIntent {
	t.Helper()
	intent := offlineArchiveProjectionIntent{
		Schema:        offlineArchiveProjectionIntentSchema,
		TransactionID: transactionID,
		ConfigSHA256:  strings.Repeat("1", 64),
		Source: offlineArchiveSourceProof{
			ID:              "test-offline-archive-source",
			Access:          "public",
			Refs:            []offlineArchiveSourceRef{{Name: "refs/sow/views/latest/public-assets/all/all", Commit: strings.Repeat("2", 40), Path: "views/latest/public-assets/all/all.json", Repo: "public-assets", OS: "all", Arch: "all"}},
			EntriesSHA256:   strings.Repeat("3", 64),
			Confidentiality: "public",
		},
		ArchiveSHA256:  strings.Repeat("4", 64),
		ArchiveSize:    1,
		StageRelative:  filepath.Join(offlineArchiveProjectionStageDir, offlineArchiveProjectionStagePrefix+transactionID+".tgz"),
		Destination:    filepath.Join(t.TempDir(), "destination.tgz"),
		ValidationRoot: t.TempDir(),
	}
	var err error
	intent.ID, err = offlineArchiveProjectionIntentID(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := intent.validate(); err != nil {
		t.Fatalf("invalid ownership fixture: %v", err)
	}
	return intent
}

func TestOfflineArchiveOversizeIntentIsProvenNotCommitted(t *testing.T) {
	intent := testOfflineArchiveProjectionIntent(t, strings.Repeat("b", 32))
	repo := strings.Repeat("r", 200)
	intent.Source.Refs = make([]offlineArchiveSourceRef, 0, 1800)
	for index := 0; index < cap(intent.Source.Refs); index++ {
		osName := fmt.Sprintf("%010d%s", index, strings.Repeat("o", 100))
		intent.Source.Refs = append(intent.Source.Refs, offlineArchiveSourceRef{
			Name:   "refs/sow/views/latest/" + repo + "/" + osName + "/all",
			Commit: strings.Repeat("2", 40),
			Path:   "views/latest/" + repo + "/" + osName + "/all.json",
			Repo:   repo,
			OS:     osName,
			Arch:   "all",
		})
	}
	var err error
	intent.ID, err = offlineArchiveProjectionIntentID(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := intent.validate(); err != nil {
		t.Fatalf("oversize fixture is not otherwise valid: %v", err)
	}
	body, err := json.Marshal(intent)
	if err != nil || len(body) <= offlineArchiveProjectionIntentMaxBytes {
		t.Fatalf("oversize fixture bytes=%d err=%v", len(body), err)
	}
	stateRoot := t.TempDir()
	result, err := writeOfflineArchiveProjectionIntentOutcome(stateRoot, intent)
	if result.Outcome != derivedStateReplacementNotCommitted ||
		err == nil || !strings.Contains(err.Error(), "exceeds size limit") {
		t.Fatalf("oversize outcome=%+v err=%v", result, err)
	}
	if _, err := os.Lstat(filepath.Join(stateRoot, offlineArchiveProjectionIntentRelative)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversize preflight installed an intent: %v", err)
	}
	assertNoDerivedStateReplacementResidue(t, stateRoot)
}

type offlineArchiveModeInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (info offlineArchiveModeInfo) Mode() os.FileMode { return info.mode }
