package plain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/yumrepo"
)

func TestCreatePigstyExactCleanupAndSHA256Marker(t *testing.T) {
	dir := t.TempDir()
	for _, arch := range []string{"i386", "i486", "i586", "i686"} {
		writeRPMFixture(t, filepath.Join(dir, "rpm-"+arch+".rpm"), rpmFixture{Name: "legacy", Version: "1", Release: "1", Arch: arch, Payload: arch})
	}
	writeRPMFixture(t, filepath.Join(dir, "rpm-patroni-bad.rpm"), rpmFixture{Name: "patroni", Version: "3.0.4", Release: "9", Arch: "x86_64", Epoch: 2, Payload: "bad"})
	writeRPMFixture(t, filepath.Join(dir, "rpm-patroni-plus.rpm"), rpmFixture{Name: "patroni", Version: "3.0.4+foo", Release: "1", Arch: "x86_64", Payload: "plus"})
	writeRPMFixture(t, filepath.Join(dir, "rpm-good.rpm"), rpmFixture{Name: "good", Version: "1", Release: "1", Arch: "aarch64", Payload: "good"})
	writeDEBFixture(t, dir, "deb-i386.deb", debControl("legacy", "1.0-1", "i386"), "legacy")
	writeDEBFixture(t, dir, "deb-patroni-bad.deb", debControl("patroni", "1:3.0.4-7", "amd64"), "bad")
	writeDEBFixture(t, dir, "deb-patroni-plus.deb", debControl("patroni", "1:3.0.4+foo-7", "amd64"), "plus")
	writeDEBFixture(t, dir, "deb-good.deb", debControl("good", "1.0-1", "arm64"), "good")
	if err := os.WriteFile(filepath.Join(dir, "patroni-3.0.4-not-a-package.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	wantRemoved := []string{"deb-i386.deb", "deb-patroni-bad.deb", "rpm-patroni-bad.rpm"}
	wantKept := []string{
		"deb-good.deb", "deb-patroni-plus.deb", "rpm-good.rpm",
		"rpm-i386.rpm", "rpm-i486.rpm", "rpm-i586.rpm", "rpm-i686.rpm", "rpm-patroni-plus.rpm",
	}
	result, err := Create(context.Background(), Options{Dir: dir, Jobs: 4, Pigsty: true})
	if err != nil {
		t.Fatalf("Create --pigsty: %v", err)
	}
	if !result.Marker || strings.Join(result.Removed, ",") != strings.Join(wantRemoved, ",") {
		t.Fatalf("unexpected pigsty result: %+v", result)
	}
	for _, name := range wantRemoved {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("selected package %s was not removed", name)
		}
	}
	for _, name := range wantKept {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("non-selected file %s was removed: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "patroni-3.0.4-not-a-package.txt")); err != nil {
		t.Fatalf("non-package file was removed: %v", err)
	}
	marker := string(mustRead(t, filepath.Join(dir, "repo_complete")))
	var wantLines []string
	for _, name := range wantKept {
		wantLines = append(wantLines, fmt.Sprintf("%s  %s", fileSHA(filepath.Join(dir, name)), name))
	}
	if marker != strings.Join(wantLines, "\n")+"\n" {
		t.Fatalf("marker =\n%s\nwant =\n%s", marker, strings.Join(wantLines, "\n")+"\n")
	}
	packages := mustRead(t, filepath.Join(dir, "Packages"))
	primary := readPrimaryXML(t, filepath.Join(dir, "repodata"))
	for _, removed := range wantRemoved {
		if bytes.Contains(packages, []byte(removed)) || bytes.Contains(primary, []byte(removed)) {
			t.Fatalf("metadata still references removed package %s", removed)
		}
	}
	for _, kept := range []string{"rpm-i386.rpm", "rpm-i486.rpm", "rpm-i586.rpm", "rpm-i686.rpm"} {
		if !bytes.Contains(primary, []byte(`href="`+kept+`"`)) {
			t.Fatalf("RPM metadata omitted retained package %s", kept)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFilename)); !os.IsNotExist(err) {
		t.Fatal("successful pigsty operation left journal")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".sow-plain-stage-") || strings.HasPrefix(entry.Name(), ".sow-plain-recovery-") {
			t.Fatalf("successful operation left temporary path %s", entry.Name())
		}
	}
}

func TestCreatePigstyIdenticalRepeatDoesNotWithdrawMarker(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "good.rpm"), rpmFixture{Name: "good", Version: "1", Release: "1", Arch: "x86_64", Payload: "good"})
	writeDEBFixture(t, dir, "good.deb", debControl("good", "1.0-1", "amd64"), "good")
	if _, err := Create(context.Background(), Options{Dir: dir, Pigsty: true}); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(dir, "repo_complete")
	before, err := os.Lstat(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	faults := 0
	result, err := Create(context.Background(), Options{Dir: dir, Pigsty: true, Fault: func(Fault) error {
		faults++
		return errors.New("an identical repeat must not enter journal execution")
	}})
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Noop || faults != 0 {
		t.Fatalf("identical repeat result=%+v faults=%d", result, faults)
	}
	if !os.SameFile(before, after) {
		t.Fatal("identical --pigsty repeat replaced repo_complete")
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identical repeat left journal: %v", err)
	}
}

func TestCreatePigstyFaultRecoveryMatrix(t *testing.T) {
	tests := []struct {
		point       FaultPoint
		packageName string
	}{
		{FaultAfterJournal, ""},
		{FaultAfterMarkerWithdrawn, ""},
		{FaultBeforeRPMPointer, ""},
		{FaultAfterRPMPointer, ""},
		{FaultBeforeDEBPackages, ""},
		{FaultAfterDEBPackages, ""},
		{FaultBeforeDEBGzip, ""},
		{FaultAfterDEBGzip, ""},
		{FaultAfterPackageRename, "bad.deb"},
		{FaultAfterPackageRename, "bad.rpm"},
		{FaultBeforeMarker, ""},
		{FaultAfterMarker, ""},
	}
	for _, tt := range tests {
		name := string(tt.point)
		if tt.packageName != "" {
			name += "-" + tt.packageName
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeCrashFixture(t, dir)
			injected := errors.New("injected stop")
			result, err := Create(context.Background(), Options{Dir: dir, Pigsty: true, Fault: func(fault Fault) error {
				if fault.Point == tt.point && (tt.packageName == "" || fault.Package == tt.packageName) {
					return injected
				}
				return nil
			}})
			if tt.point == FaultAfterJournal {
				if !errors.Is(err, injected) {
					t.Fatalf("after-journal fault did not return its error: %v", err)
				}
				assertOldIndexedFixture(t, dir)
				if _, err := os.Lstat(filepath.Join(dir, journalFilename)); err != nil {
					t.Fatalf("after-journal error lost durable recovery plan: %v", err)
				}
				if _, err := Create(context.Background(), Options{Dir: dir, Pigsty: true}); err != nil {
					t.Fatalf("recover after-journal fault: %v", err)
				}
				assertRecoveredFixture(t, dir)
				return
			}
			// A non-process-termination fault after the durable journal must
			// synchronously roll forward. Once the complete new state is durable,
			// the public operation reports success rather than a false failure.
			if err != nil {
				t.Fatalf("completed roll-forward returned an error: %v", err)
			}
			if result.Noop || !result.Marker || len(result.Removed) != 2 {
				t.Fatalf("completed roll-forward result=%+v", result)
			}
			assertRecoveredFixture(t, dir)
		})
	}
}

func TestCreatePigstyPersistentFailureRestoresPackagesMarkerAndIndexes(t *testing.T) {
	dir := t.TempDir()
	writeCrashFixture(t, dir)
	injected := errors.New("make final marker persistently unusable")
	mutated := false
	_, err := Create(context.Background(), Options{Dir: dir, Pigsty: true, Fault: func(fault Fault) error {
		if fault.Point != FaultAfterPackageRename || fault.Package != "bad.rpm" || mutated {
			return nil
		}
		mutated = true
		stages, globErr := filepath.Glob(filepath.Join(dir, ".sow-plain-stage-*"))
		if globErr != nil || len(stages) != 1 {
			t.Fatalf("locate stage: paths=%v err=%v", stages, globErr)
		}
		marker := filepath.Join(stages[0], "repo_complete")
		if removeErr := os.Remove(marker); removeErr != nil {
			t.Fatal(removeErr)
		}
		if mkdirErr := os.Mkdir(marker, 0o755); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
		return injected
	}})
	if !errors.Is(err, injected) {
		t.Fatalf("persistent Pigsty commit error=%v", err)
	}
	assertOldIndexedFixture(t, dir)
	if _, err := os.Lstat(filepath.Join(dir, journalFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rolled-back Pigsty operation left an active journal: %v", err)
	}
	if _, err := Create(context.Background(), Options{Dir: dir, Pigsty: true}); err != nil {
		t.Fatalf("fresh Pigsty retry: %v", err)
	}
	assertRecoveredFixture(t, dir)
}

func TestCompletedPigstyJournalCleansAfterPartialTrashRemoval(t *testing.T) {
	dir := t.TempDir()
	writeCrashFixture(t, dir)
	stopAfterJournal := errors.New("stop after journal")
	_, err := Create(context.Background(), Options{Dir: dir, Pigsty: true, Fault: func(fault Fault) error {
		if fault.Point == FaultAfterJournal {
			return stopAfterJournal
		}
		return nil
	}})
	if !errors.Is(err, stopAfterJournal) {
		t.Fatalf("prepare durable operation: %v", err)
	}
	journal, err := loadJournal(dir)
	if err != nil || journal == nil {
		t.Fatalf("load prepared operation: journal=%+v err=%v", journal, err)
	}
	stopAfterMarker := errors.New("stop after final marker")
	if _, err := executeJournalOnce(context.Background(), dir, journal, func(fault Fault) error {
		if fault.Point == FaultAfterMarker {
			return stopAfterMarker
		}
		return nil
	}); !errors.Is(err, stopAfterMarker) {
		t.Fatalf("install complete public generation: %v", err)
	}
	committed, err := confirmCommittedDurable(context.Background(), dir, journal)
	if err != nil || !committed {
		t.Fatalf("prove complete public generation: committed=%v err=%v", committed, err)
	}
	journal.Next = len(journal.Actions)
	if err := persistCommittedJournal(dir, *journal); err != nil {
		t.Fatalf("persist completed journal: %v", err)
	}

	var removedTarget string
	for _, action := range journal.Actions {
		if action.Package == "bad.rpm" {
			removedTarget = filepath.Join(dir, action.Target)
			break
		}
	}
	if removedTarget == "" {
		t.Fatal("prepared operation has no bad.rpm cleanup action")
	}
	if err := os.Remove(removedTarget); err != nil {
		t.Fatalf("simulate partial trash cleanup: %v", err)
	}
	if err := syncDir(filepath.Dir(removedTarget)); err != nil {
		t.Fatalf("sync partial trash cleanup: %v", err)
	}
	oldPointer := append([]byte(nil), mustRead(t, filepath.Join(dir, "repodata", "repomd.xml"))...)
	oldPackages := append([]byte(nil), mustRead(t, filepath.Join(dir, "Packages"))...)
	oldPackagesGzip := append([]byte(nil), mustRead(t, filepath.Join(dir, "Packages.gz"))...)
	oldMarker := append([]byte(nil), mustRead(t, filepath.Join(dir, "repo_complete"))...)

	result, err := Create(context.Background(), Options{Dir: dir, Pigsty: true})
	if err != nil || !result.Recovered || !result.Noop {
		t.Fatalf("cleanup completed operation: result=%+v err=%v", result, err)
	}
	for path, want := range map[string][]byte{
		filepath.Join(dir, "repodata", "repomd.xml"): oldPointer,
		filepath.Join(dir, "Packages"):               oldPackages,
		filepath.Join(dir, "Packages.gz"):            oldPackagesGzip,
		filepath.Join(dir, "repo_complete"):          oldMarker,
	} {
		if got := mustRead(t, path); !bytes.Equal(got, want) {
			t.Fatalf("cleanup-only recovery changed public bytes at %s", path)
		}
	}
	assertRecoveredFixture(t, dir)
}

func TestCreatePigstyAllPackagesRemovedProducesEmptyRepositories(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "legacy.rpm"), rpmFixture{Name: "patroni", Version: "3.0.4", Release: "1", Arch: "x86_64", Payload: "legacy"})
	writeDEBFixture(t, dir, "legacy.deb", debControl("legacy", "1.0-1", "i386"), "legacy")
	result, err := Create(context.Background(), Options{Dir: dir, Pigsty: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.RPM != 0 || result.DEB != 0 || len(result.Removed) != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if marker := mustRead(t, filepath.Join(dir, "repo_complete")); len(marker) != 0 {
		t.Fatalf("empty marker contains bytes: %q", marker)
	}
	if packages := mustRead(t, filepath.Join(dir, "Packages")); len(packages) != 0 {
		t.Fatalf("empty Packages contains bytes: %q", packages)
	}
	if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), filepath.Join(dir, "repodata"), yumrepo.CompressionGzip); err != nil {
		t.Fatalf("empty RPM repository invalid: %v", err)
	}
}

func TestCreatePigstyProcessTerminationRecoveryMatrix(t *testing.T) {
	tests := []struct {
		point       FaultPoint
		packageName string
	}{
		{FaultAfterJournal, ""},
		{FaultAfterMarkerWithdrawn, ""},
		{FaultBeforeRPMPointer, ""},
		{FaultAfterRPMPointer, ""},
		{FaultBeforeDEBPackages, ""},
		{FaultAfterDEBPackages, ""},
		{FaultBeforeDEBGzip, ""},
		{FaultAfterDEBGzip, ""},
		{FaultAfterPackageRename, "bad.deb"},
		{FaultAfterPackageRename, "bad.rpm"},
		{FaultBeforeMarker, ""},
		{FaultAfterMarker, ""},
	}
	for _, tt := range tests {
		name := string(tt.point)
		if tt.packageName != "" {
			name += "-" + tt.packageName
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeCrashFixture(t, dir)
			cmd := exec.Command(os.Args[0], "-test.run=^TestPlainCrashHelper$")
			cmd.Env = append(os.Environ(),
				"SOW_PLAIN_CRASH_HELPER=1",
				"SOW_PLAIN_CRASH_DIR="+dir,
				"SOW_PLAIN_CRASH_POINT="+string(tt.point),
				"SOW_PLAIN_CRASH_PACKAGE="+tt.packageName,
			)
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 91 {
				t.Fatalf("crash helper exit = %v", err)
			}
			if _, err := Create(context.Background(), Options{Dir: dir, Pigsty: true}); err != nil {
				t.Fatalf("recover process termination at %s/%s: %v", tt.point, tt.packageName, err)
			}
			assertRecoveredFixture(t, dir)
		})
	}
}

func TestCreatePigstyAllRemovedProcessTerminationRecoveryMatrix(t *testing.T) {
	tests := []struct {
		point       FaultPoint
		packageName string
	}{
		{FaultAfterJournal, ""},
		{FaultAfterMarkerWithdrawn, ""},
		{FaultBeforeRPMPointer, ""},
		{FaultAfterRPMPointer, ""},
		{FaultBeforeDEBPackages, ""},
		{FaultAfterDEBPackages, ""},
		{FaultBeforeDEBGzip, ""},
		{FaultAfterDEBGzip, ""},
		{FaultAfterPackageRename, "legacy.deb"},
		{FaultAfterPackageRename, "legacy.rpm"},
		{FaultBeforeMarker, ""},
		{FaultAfterMarker, ""},
	}
	for _, tt := range tests {
		name := string(tt.point)
		if tt.packageName != "" {
			name += "-" + tt.packageName
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeRPMFixture(t, filepath.Join(dir, "legacy.rpm"), rpmFixture{Name: "patroni", Version: "3.0.4", Release: "1", Arch: "x86_64", Payload: "legacy"})
			writeDEBFixture(t, dir, "legacy.deb", debControl("legacy", "1.0-1", "i386"), "legacy")
			if err := os.WriteFile(filepath.Join(dir, "repo_complete"), []byte("old marker\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestPlainCrashHelper$")
			cmd.Env = append(os.Environ(),
				"SOW_PLAIN_CRASH_HELPER=1",
				"SOW_PLAIN_CRASH_DIR="+dir,
				"SOW_PLAIN_CRASH_POINT="+string(tt.point),
				"SOW_PLAIN_CRASH_PACKAGE="+tt.packageName,
			)
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 91 {
				t.Fatalf("crash helper exit=%v", err)
			}
			result, err := Create(context.Background(), Options{Dir: dir, Pigsty: true})
			if err != nil {
				t.Fatalf("recover all-removed at %s/%s: %v", tt.point, tt.packageName, err)
			}
			if !result.Recovered || result.RPM != 0 || result.DEB != 0 || len(result.Kept) != 0 || len(result.Removed) != 2 {
				t.Fatalf("recovered result=%+v", result)
			}
			for _, removed := range []string{"legacy.rpm", "legacy.deb"} {
				if _, err := os.Lstat(filepath.Join(dir, removed)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("recovery retained %s: %v", removed, err)
				}
			}
			if marker := mustRead(t, filepath.Join(dir, "repo_complete")); len(marker) != 0 {
				t.Fatalf("empty marker=%q", marker)
			}
			if packages := mustRead(t, filepath.Join(dir, "Packages")); len(packages) != 0 {
				t.Fatalf("empty Packages=%q", packages)
			}
			if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), filepath.Join(dir, "repodata"), yumrepo.CompressionGzip); err != nil {
				t.Fatalf("empty RPM index invalid: %v", err)
			}
		})
	}
}

func TestCreatePigstyRepeatSkipsProcessTerminationFault(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "good.rpm"), rpmFixture{Name: "good", Version: "1", Release: "1", Arch: "x86_64", Payload: "good"})
	writeDEBFixture(t, dir, "good.deb", debControl("good", "1.0-1", "amd64"), "good")
	if _, err := Create(context.Background(), Options{Dir: dir, Pigsty: true}); err != nil {
		t.Fatal(err)
	}
	wantMarker := append([]byte(nil), mustRead(t, filepath.Join(dir, "repo_complete"))...)
	cmd := exec.Command(os.Args[0], "-test.run=^TestPlainCrashHelper$")
	cmd.Env = append(os.Environ(),
		"SOW_PLAIN_CRASH_HELPER=1",
		"SOW_PLAIN_CRASH_DIR="+dir,
		"SOW_PLAIN_CRASH_POINT="+string(FaultAfterMarker),
	)
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 92 {
		t.Fatalf("crash helper exit=%v", err)
	}
	result, err := Create(context.Background(), Options{Dir: dir, Pigsty: true})
	if err != nil || result.Recovered || !result.Noop {
		t.Fatalf("repeat recovery result=%+v err=%v", result, err)
	}
	if got := mustRead(t, filepath.Join(dir, "repo_complete")); !bytes.Equal(got, wantMarker) {
		t.Fatalf("marker changed after repeat recovery:\n%s\nwant:\n%s", got, wantMarker)
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("repeat recovery left journal: %v", err)
	}
}

func TestPlainCrashHelper(t *testing.T) {
	if os.Getenv("SOW_PLAIN_CRASH_HELPER") != "1" {
		return
	}
	dir := os.Getenv("SOW_PLAIN_CRASH_DIR")
	point := FaultPoint(os.Getenv("SOW_PLAIN_CRASH_POINT"))
	packageName := os.Getenv("SOW_PLAIN_CRASH_PACKAGE")
	pigsty := true
	if value, exists := os.LookupEnv("SOW_PLAIN_CRASH_PIGSTY"); exists {
		pigsty = value == "1"
	}
	signWith := os.Getenv("SOW_PLAIN_CRASH_SIGN_WITH")
	overwrite := os.Getenv("SOW_PLAIN_CRASH_OVERWRITE") == "1"
	var signer RPMSignFunc
	if signWith != "" {
		signer = func(_ context.Context, path, key string, _ bool) error {
			return replaceTestRPMSignature(path, key)
		}
	}
	_, err := Create(context.Background(), Options{Dir: dir, Pigsty: pigsty, SignWith: signWith, Overwrite: overwrite, SignRPM: signer, Fault: func(fault Fault) error {
		if fault.Point == point && (packageName == "" || fault.Package == packageName) {
			os.Exit(91)
		}
		return nil
	}})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(92)
}

func writeCrashFixture(t *testing.T, dir string) {
	t.Helper()
	writeRPMFixture(t, filepath.Join(dir, "good.rpm"), rpmFixture{Name: "good", Version: "1", Release: "1", Arch: "x86_64", Payload: "good"})
	writeRPMFixture(t, filepath.Join(dir, "bad.rpm"), rpmFixture{Name: "patroni", Version: "3.0.4", Release: "1", Arch: "x86_64", Payload: "bad"})
	writeDEBFixture(t, dir, "good.deb", debControl("good", "1.0-1", "amd64"), "good")
	writeDEBFixture(t, dir, "bad.deb", debControl("legacy", "1.0-1", "i386"), "bad")
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatalf("build old crash fixture index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "repo_complete"), []byte("old marker\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertOldIndexedFixture(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{"good.rpm", "bad.rpm", "good.deb", "bad.deb"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("old state lost package %s: %v", name, err)
		}
	}
	if marker := string(mustRead(t, filepath.Join(dir, "repo_complete"))); marker != "old marker\n" {
		t.Fatalf("old marker changed: %q", marker)
	}
	if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), filepath.Join(dir, "repodata"), yumrepo.CompressionGzip); err != nil {
		t.Fatalf("old RPM index invalid: %v", err)
	}
	primary := readPrimaryXML(t, filepath.Join(dir, "repodata"))
	for _, name := range []string{"good.rpm", "bad.rpm"} {
		if !bytes.Contains(primary, []byte(`href="`+name+`"`)) {
			t.Fatalf("old RPM index lost %s", name)
		}
	}
	packages := mustRead(t, filepath.Join(dir, "Packages"))
	for _, name := range []string{"good.deb", "bad.deb"} {
		if !bytes.Contains(packages, []byte("Filename: ./"+name+"\n")) {
			t.Fatalf("old DEB index lost %s", name)
		}
	}
	if expanded := gunzip(t, mustRead(t, filepath.Join(dir, "Packages.gz"))); !bytes.Equal(expanded, packages) {
		t.Fatal("old Packages.gz does not match Packages")
	}
}

func assertRecoveredFixture(t *testing.T, dir string) {
	t.Helper()
	for _, removed := range []string{"bad.rpm", "bad.deb"} {
		if _, err := os.Lstat(filepath.Join(dir, removed)); !os.IsNotExist(err) {
			t.Fatalf("recovery retained selected package %s", removed)
		}
	}
	marker := string(mustRead(t, filepath.Join(dir, "repo_complete")))
	for _, kept := range []string{"good.deb", "good.rpm"} {
		if !strings.Contains(marker, "  "+kept+"\n") {
			t.Fatalf("marker missing %s: %s", kept, marker)
		}
	}
	if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), filepath.Join(dir, "repodata"), yumrepo.CompressionGzip); err != nil {
		t.Fatalf("recovered RPM metadata is invalid: %v", err)
	}
	primary := readPrimaryXML(t, filepath.Join(dir, "repodata"))
	if !bytes.Contains(primary, []byte(`href="good.rpm"`)) || bytes.Contains(primary, []byte("bad.rpm")) {
		t.Fatalf("recovered RPM metadata has a dangling or missing location:\n%s", primary)
	}
	packages := mustRead(t, filepath.Join(dir, "Packages"))
	if !bytes.Contains(packages, []byte("Filename: ./good.deb\n")) || bytes.Contains(packages, []byte("bad.deb")) {
		t.Fatalf("recovered DEB metadata has a dangling or missing location:\n%s", packages)
	}
	if expanded := gunzip(t, mustRead(t, filepath.Join(dir, "Packages.gz"))); !bytes.Equal(expanded, packages) {
		t.Fatal("recovered Packages.gz does not match Packages")
	}
	for _, line := range strings.Split(strings.TrimSuffix(marker, "\n"), "\n") {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			t.Fatalf("invalid recovered marker line %q", line)
		}
		body := mustRead(t, filepath.Join(dir, parts[1]))
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != parts[0] {
			t.Fatalf("recovered marker hash for %s = %s, want %s", parts[1], parts[0], got)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFilename)); !os.IsNotExist(err) {
		t.Fatal("recovery left journal")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".sow-plain-stage-") || strings.HasPrefix(entry.Name(), ".sow-plain-recovery-") {
			t.Fatalf("recovery left transaction residue %s", entry.Name())
		}
	}
}
