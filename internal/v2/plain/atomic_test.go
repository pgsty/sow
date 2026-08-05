package plain

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/yumrepo"
)

func TestCreateRejectsDisguisedSourceRPMFromHeader(t *testing.T) {
	for _, arch := range []string{"src", "nosrc"} {
		t.Run(arch, func(t *testing.T) {
			dir := t.TempDir()
			// Deliberately avoid .src.rpm/.nosrc.rpm: acceptance must come from
			// the parsed RPM architecture header, never the filename.
			writeRPMFixture(t, filepath.Join(dir, "looks-binary.rpm"), rpmFixture{
				Name: "source-only", Version: "1", Release: "1", Arch: arch, Payload: "source",
			})
			_, err := Create(context.Background(), Options{Dir: dir})
			if err == nil || KindOf(err) != KindRejected || !strings.Contains(err.Error(), "source rpm") {
				t.Fatalf("Create error=%v kind=%s", err, KindOf(err))
			}
			if _, err := os.Lstat(filepath.Join(dir, "repodata")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("source RPM rejection created repodata: %v", err)
			}
		})
	}
}

func TestCreateAcceptsBinaryRPMWithSourceLookingBasename(t *testing.T) {
	dir := t.TempDir()
	name := "renamed.src.rpm"
	writeRPMFixture(t, filepath.Join(dir, name), rpmFixture{
		Name: "binary", Version: "1", Release: "1", Arch: "aarch64", Payload: "binary",
	})
	result, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatalf("Create rejected header-proven binary RPM: %v", err)
	}
	if result.RPM != 1 || result.DEB != 0 || len(result.Kept) != 1 || result.Kept[0] != name {
		t.Fatalf("unexpected binary RPM result: %#v", result)
	}
	primary := readPrimaryXML(t, filepath.Join(dir, "repodata"))
	if !bytes.Contains(primary, []byte(`<arch>aarch64</arch>`)) || !bytes.Contains(primary, []byte(`href="renamed.src.rpm"`)) {
		t.Fatalf("metadata does not retain header architecture and basename: %s", primary)
	}
}

func TestDefaultPendingJournalRejectsAppearedMarkerBeforeReplay(t *testing.T) {
	dir := t.TempDir()
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "alpha")
	stop := errors.New("stop after journal")
	_, err := Create(context.Background(), Options{Dir: dir, Fault: func(fault Fault) error {
		if fault.Point == FaultAfterJournal {
			return stop
		}
		return nil
	}})
	if !errors.Is(err, stop) {
		t.Fatalf("fault Create: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "repo_complete"), []byte("appeared\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Create(context.Background(), Options{Dir: dir})
	if err == nil || KindOf(err) != KindRejected || !strings.Contains(err.Error(), "refusing replay") {
		t.Fatalf("marker/pending error=%v kind=%s", err, KindOf(err))
	}
	if _, err := os.Lstat(filepath.Join(dir, "Packages")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker/pending rejection replayed metadata: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFilename)); err != nil {
		t.Fatalf("marker/pending rejection removed journal: %v", err)
	}
}

func TestRecoveryRejectsMutatedDeletedAndAddedInputsBeforePublish(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"mutated", func(t *testing.T, dir string) {
			writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "2.0-1", "amd64"), "changed")
		}},
		{"deleted", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "alpha.deb")); err != nil {
				t.Fatal(err)
			}
		}},
		{"added", func(t *testing.T, dir string) {
			writeDEBFixture(t, dir, "beta.deb", debControl("beta", "1.0-1", "amd64"), "beta")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "alpha")
			stop := errors.New("stop after journal")
			_, err := Create(context.Background(), Options{Dir: dir, Fault: func(fault Fault) error {
				if fault.Point == FaultAfterJournal {
					return stop
				}
				return nil
			}})
			if !errors.Is(err, stop) {
				t.Fatalf("fault Create: %v", err)
			}
			tt.mutate(t, dir)
			_, err = Create(context.Background(), Options{Dir: dir})
			if err == nil || KindOf(err) != KindIntegrity {
				t.Fatalf("recovery error=%v kind=%s", err, KindOf(err))
			}
			if _, err := os.Lstat(filepath.Join(dir, "Packages")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("input mutation published Packages: %v", err)
			}
		})
	}
}

func TestCommitRevalidatesInputAfterBeforePointerHook(t *testing.T) {
	dir := t.TempDir()
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "alpha")
	mutated := false
	_, err := Create(context.Background(), Options{Dir: dir, Fault: func(fault Fault) error {
		if fault.Point == FaultBeforeDEBPackages && !mutated {
			mutated = true
			writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "2.0-1", "amd64"), "changed")
		}
		return nil
	}})
	if err == nil || KindOf(err) != KindIntegrity {
		t.Fatalf("Create error=%v kind=%s", err, KindOf(err))
	}
	if _, err := os.Lstat(filepath.Join(dir, "Packages")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("changed input was published: %v", err)
	}
}

func TestCreateDefaultOrdinaryPointerFaultRollsForwardAsSuccess(t *testing.T) {
	for _, point := range []FaultPoint{
		FaultBeforeRPMPointer,
		FaultAfterRPMPointer,
		FaultBeforeDEBPackages,
		FaultAfterDEBPackages,
		FaultBeforeDEBGzip,
		FaultAfterDEBGzip,
	} {
		t.Run(string(point), func(t *testing.T) {
			dir := t.TempDir()
			writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "alpha"})
			writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "alpha")
			if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
				t.Fatal(err)
			}
			writeRPMFixture(t, filepath.Join(dir, "beta.rpm"), rpmFixture{Name: "beta", Version: "1", Release: "1", Arch: "aarch64", Payload: "beta"})
			writeDEBFixture(t, dir, "beta.deb", debControl("beta", "1.0-1", "arm64"), "beta")
			injected := errors.New("transient commit fault")
			result, err := Create(context.Background(), Options{Dir: dir, Fault: func(fault Fault) error {
				if fault.Point == point {
					return injected
				}
				return nil
			}})
			if err != nil {
				t.Fatalf("complete roll-forward returned error: %v", err)
			}
			if result.RPM != 2 || result.DEB != 2 || result.Noop {
				t.Fatalf("result=%+v", result)
			}
			primary := readPrimaryXML(t, filepath.Join(dir, "repodata"))
			packages := mustRead(t, filepath.Join(dir, "Packages"))
			for _, name := range []string{"alpha.rpm", "beta.rpm"} {
				if !bytes.Contains(primary, []byte(`href="`+name+`"`)) {
					t.Fatalf("RPM metadata missing %s", name)
				}
			}
			for _, name := range []string{"alpha.deb", "beta.deb"} {
				if !bytes.Contains(packages, []byte("Filename: ./"+name+"\n")) {
					t.Fatalf("DEB metadata missing %s", name)
				}
			}
			if expanded := gunzip(t, mustRead(t, filepath.Join(dir, "Packages.gz"))); !bytes.Equal(expanded, packages) {
				t.Fatal("Packages.gz differs after roll-forward")
			}
			if _, err := os.Lstat(filepath.Join(dir, journalFilename)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("successful roll-forward left journal: %v", err)
			}
		})
	}
}

func TestCreateDefaultMixedProcessTerminationRecoveryMatrix(t *testing.T) {
	for _, point := range []FaultPoint{
		FaultAfterJournal,
		FaultBeforeRPMPointer,
		FaultAfterRPMPointer,
		FaultBeforeDEBPackages,
		FaultAfterDEBPackages,
		FaultBeforeDEBGzip,
		FaultAfterDEBGzip,
	} {
		t.Run(string(point), func(t *testing.T) {
			dir := t.TempDir()
			writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "alpha"})
			writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "alpha")
			if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
				t.Fatal(err)
			}
			writeRPMFixture(t, filepath.Join(dir, "beta.rpm"), rpmFixture{Name: "beta", Version: "1", Release: "1", Arch: "aarch64", Payload: "beta"})
			writeDEBFixture(t, dir, "beta.deb", debControl("beta", "1.0-1", "arm64"), "beta")
			cmd := exec.Command(os.Args[0], "-test.run=^TestPlainCrashHelper$")
			cmd.Env = append(os.Environ(),
				"SOW_PLAIN_CRASH_HELPER=1",
				"SOW_PLAIN_CRASH_DIR="+dir,
				"SOW_PLAIN_CRASH_POINT="+string(point),
				"SOW_PLAIN_CRASH_PIGSTY=0",
			)
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 91 {
				t.Fatalf("crash helper exit=%v", err)
			}
			result, err := Create(context.Background(), Options{Dir: dir})
			if err != nil || !result.Recovered || result.RPM != 2 || result.DEB != 2 {
				t.Fatalf("recovery result=%+v err=%v", result, err)
			}
			primary := readPrimaryXML(t, filepath.Join(dir, "repodata"))
			packages := mustRead(t, filepath.Join(dir, "Packages"))
			for _, name := range []string{"alpha.rpm", "beta.rpm"} {
				if !bytes.Contains(primary, []byte(`href="`+name+`"`)) {
					t.Fatalf("recovered RPM metadata omits %s", name)
				}
			}
			for _, name := range []string{"alpha.deb", "beta.deb"} {
				if !bytes.Contains(packages, []byte("Filename: ./"+name+"\n")) {
					t.Fatalf("recovered DEB metadata omits %s", name)
				}
			}
			if _, err := os.Lstat(filepath.Join(dir, "repo_complete")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("default recovery created marker: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(dir, journalFilename)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("default recovery left journal: %v", err)
			}
		})
	}
}

func TestCreateSigningProcessTerminationRecoveryMatrix(t *testing.T) {
	const key = "E7935D8DB9BD8B20"
	for _, point := range []FaultPoint{
		FaultAfterJournal,
		FaultBeforeRPMPackage,
		FaultAfterRPMPackage,
		FaultBeforeRPMPointer,
		FaultAfterRPMPointer,
	} {
		t.Run(string(point), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "alpha.rpm")
			writeRPMFixture(t, path, rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "alpha"})
			if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
				t.Fatal(err)
			}
			unsignedSHA := fileSHA(path)
			cmd := exec.Command(os.Args[0], "-test.run=^TestPlainCrashHelper$")
			cmd.Env = append(os.Environ(),
				"SOW_PLAIN_CRASH_HELPER=1",
				"SOW_PLAIN_CRASH_DIR="+dir,
				"SOW_PLAIN_CRASH_POINT="+string(point),
				"SOW_PLAIN_CRASH_PIGSTY=0",
				"SOW_PLAIN_CRASH_SIGN_WITH="+key,
			)
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 91 {
				t.Fatalf("crash helper exit=%v", err)
			}
			result, err := Create(context.Background(), Options{Dir: dir, SignWith: key})
			if err != nil || !result.Recovered || strings.Join(result.Signed, ",") != "alpha.rpm" {
				t.Fatalf("recovery result=%+v err=%v", result, err)
			}
			if fileSHA(path) == unsignedSHA {
				t.Fatal("recovery did not install the staged signed RPM")
			}
			signatures, err := inspectTestRPMSignatures(path)
			if err != nil || len(signatures) != 1 || signatures[0].IssuerKeyID != strings.ToLower(key) {
				t.Fatalf("recovered signature=%+v err=%v", signatures, err)
			}
			primary := readPrimaryXML(t, filepath.Join(dir, "repodata"))
			if !bytes.Contains(primary, []byte(fileSHA(path))) {
				t.Fatal("recovered rpm-md does not bind the signed RPM")
			}
			if _, err := os.Lstat(filepath.Join(dir, journalFilename)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("recovery left journal: %v", err)
			}
		})
	}
}

func TestRestoreSnapshotPreservesOwnershipAndSpecialMode(t *testing.T) {
	dir := t.TempDir()
	backupRelative := filepath.Join(".sow-plain-recovery-test", "rollback", "000000")
	backup := filepath.Join(dir, backupRelative)
	if err := os.MkdirAll(filepath.Dir(backup), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("old rpm bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "alpha.rpm")
	if err := os.WriteFile(target, []byte("new rpm bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	desired := os.FileMode(0o640) | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	if err := os.Chmod(backup, desired); err != nil {
		t.Fatal(err)
	}
	backupInfo, err := os.Lstat(backup)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := ownershipFromInfo(backupInfo)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	prior := priorFileState{
		Exists: true,
		SHA256: fileSHA(backup),
		Backup: backupRelative,
		Mode:   encodePreservedFileMode(backupInfo.Mode()),
		UID:    uint32(owner.uid),
		GID:    uint32(owner.gid),
	}
	if err := restoreSnapshot(context.Background(), bound, dir, prior, "alpha.rpm"); err != nil {
		t.Fatal(err)
	}
	if got := string(mustRead(t, target)); got != "old rpm bytes" {
		t.Fatalf("restored bytes = %q", got)
	}
	restored, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := preservedFileMode(restored.Mode()), preservedFileMode(backupInfo.Mode()); got != want {
		t.Fatalf("restored mode = %v, want %v", got, want)
	}
	restoredOwner, err := ownershipFromInfo(restored)
	if err != nil {
		t.Fatal(err)
	}
	if restoredOwner != owner {
		t.Fatalf("restored owner = %+v, want %+v", restoredOwner, owner)
	}
}

func TestCreateSigningRecoveryRequiresOriginalAuthorization(t *testing.T) {
	const key = "E7935D8DB9BD8B20"
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "alpha"})
	cmd := exec.Command(os.Args[0], "-test.run=^TestPlainCrashHelper$")
	cmd.Env = append(os.Environ(),
		"SOW_PLAIN_CRASH_HELPER=1",
		"SOW_PLAIN_CRASH_DIR="+dir,
		"SOW_PLAIN_CRASH_POINT="+string(FaultAfterJournal),
		"SOW_PLAIN_CRASH_PIGSTY=0",
		"SOW_PLAIN_CRASH_SIGN_WITH="+key,
	)
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 91 {
		t.Fatalf("crash helper exit=%v", err)
	}
	for _, options := range []Options{
		{Dir: dir},
		{Dir: dir, SignWith: "0123456789ABCDEF"},
		{Dir: dir, SignWith: key, Overwrite: true},
	} {
		if _, err := Create(context.Background(), options); err == nil || KindOf(err) != KindRejected {
			t.Fatalf("mismatched recovery options=%+v error=%v kind=%s", options, err, KindOf(err))
		}
	}
	if _, err := Create(context.Background(), Options{Dir: dir, SignWith: key}); err != nil {
		t.Fatalf("authorized recovery: %v", err)
	}
}

func TestCreatePersistentFailureAfterRPMPointerRestoresOldMixedIndexes(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "alpha"})
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "alpha")
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	oldPointer := append([]byte(nil), mustRead(t, filepath.Join(dir, "repodata", "repomd.xml"))...)
	oldPackages := append([]byte(nil), mustRead(t, filepath.Join(dir, "Packages"))...)
	oldPackagesGzip := append([]byte(nil), mustRead(t, filepath.Join(dir, "Packages.gz"))...)

	writeRPMFixture(t, filepath.Join(dir, "beta.rpm"), rpmFixture{Name: "beta", Version: "1", Release: "1", Arch: "aarch64", Payload: "beta"})
	writeDEBFixture(t, dir, "beta.deb", debControl("beta", "1.0-1", "arm64"), "beta")
	injected := errors.New("make staged DEB pointer persistently unusable")
	mutated := false
	_, err := Create(context.Background(), Options{Dir: dir, Fault: func(fault Fault) error {
		if fault.Point != FaultAfterRPMPointer || mutated {
			return nil
		}
		mutated = true
		stages, globErr := filepath.Glob(filepath.Join(dir, ".sow-plain-stage-*"))
		if globErr != nil || len(stages) != 1 {
			t.Fatalf("locate stage: paths=%v err=%v", stages, globErr)
		}
		packages := filepath.Join(stages[0], "Packages")
		if removeErr := os.Remove(packages); removeErr != nil {
			t.Fatal(removeErr)
		}
		if mkdirErr := os.Mkdir(packages, 0o755); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
		return injected
	}})
	if !errors.Is(err, injected) {
		t.Fatalf("persistent commit error=%v", err)
	}
	if got := mustRead(t, filepath.Join(dir, "repodata", "repomd.xml")); !bytes.Equal(got, oldPointer) {
		t.Fatal("failed operation did not restore the old RPM pointer")
	}
	if got := mustRead(t, filepath.Join(dir, "Packages")); !bytes.Equal(got, oldPackages) {
		t.Fatal("failed operation changed the old Packages pointer")
	}
	if got := mustRead(t, filepath.Join(dir, "Packages.gz")); !bytes.Equal(got, oldPackagesGzip) {
		t.Fatal("failed operation changed the old Packages.gz pointer")
	}
	if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), filepath.Join(dir, "repodata"), yumrepo.CompressionGzip); err != nil {
		t.Fatalf("restored RPM repository is not consumable: %v", err)
	}
	if expanded := gunzip(t, oldPackagesGzip); !bytes.Equal(expanded, oldPackages) {
		t.Fatal("restored DEB index pair is inconsistent")
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rolled-back operation left an active journal: %v", err)
	}
	for _, pattern := range []string{".sow-plain-stage-*", ".sow-plain-recovery-*"} {
		if paths, err := filepath.Glob(filepath.Join(dir, pattern)); err != nil || len(paths) != 0 {
			t.Fatalf("rolled-back operation left %s: paths=%v err=%v", pattern, paths, err)
		}
	}

	result, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatalf("fresh retry after repairing the persistent conflict: %v", err)
	}
	if result.RPM != 2 || result.DEB != 2 || result.Noop {
		t.Fatalf("retry result=%+v", result)
	}
}

func TestCreatePersistentFailureRestoresRepodataDirectoryPreimage(t *testing.T) {
	for _, tt := range []struct {
		name              string
		preexisting       bool
		wantRepodataAfter bool
	}{
		{name: "created-by-failed-operation", preexisting: false, wantRepodataAfter: false},
		{name: "preexisting-empty-directory", preexisting: true, wantRepodataAfter: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "alpha")
			if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
				t.Fatal(err)
			}
			oldPackages := append([]byte(nil), mustRead(t, filepath.Join(dir, "Packages"))...)
			oldPackagesGzip := append([]byte(nil), mustRead(t, filepath.Join(dir, "Packages.gz"))...)
			if tt.preexisting {
				if err := os.Mkdir(filepath.Join(dir, "repodata"), 0o755); err != nil {
					t.Fatal(err)
				}
			}

			writeRPMFixture(t, filepath.Join(dir, "beta.rpm"), rpmFixture{Name: "beta", Version: "1", Release: "1", Arch: "x86_64", Payload: "beta"})
			writeDEBFixture(t, dir, "beta.deb", debControl("beta", "1.0-1", "amd64"), "beta")
			injected := errors.New("make staged Packages persistently unusable")
			mutated := false
			_, err := Create(context.Background(), Options{Dir: dir, Fault: func(fault Fault) error {
				if fault.Point != FaultAfterRPMPointer || mutated {
					return nil
				}
				mutated = true
				stages, globErr := filepath.Glob(filepath.Join(dir, ".sow-plain-stage-*"))
				if globErr != nil || len(stages) != 1 {
					t.Fatalf("locate stage: paths=%v err=%v", stages, globErr)
				}
				packages := filepath.Join(stages[0], "Packages")
				if removeErr := os.Remove(packages); removeErr != nil {
					t.Fatal(removeErr)
				}
				if mkdirErr := os.Mkdir(packages, 0o755); mkdirErr != nil {
					t.Fatal(mkdirErr)
				}
				return injected
			}})
			if !errors.Is(err, injected) {
				t.Fatalf("persistent commit error=%v", err)
			}
			if got := mustRead(t, filepath.Join(dir, "Packages")); !bytes.Equal(got, oldPackages) {
				t.Fatal("failed operation changed the old Packages pointer")
			}
			if got := mustRead(t, filepath.Join(dir, "Packages.gz")); !bytes.Equal(got, oldPackagesGzip) {
				t.Fatal("failed operation changed the old Packages.gz pointer")
			}
			repodata := filepath.Join(dir, "repodata")
			info, statErr := os.Lstat(repodata)
			if !tt.wantRepodataAfter {
				if !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("failed operation left newly-created repodata: info=%v err=%v", info, statErr)
				}
			} else {
				if statErr != nil || !info.IsDir() {
					t.Fatalf("failed operation removed pre-existing repodata: info=%v err=%v", info, statErr)
				}
				entries, readErr := os.ReadDir(repodata)
				if readErr != nil || len(entries) != 0 {
					t.Fatalf("restored pre-existing repodata is not empty: entries=%v err=%v", entries, readErr)
				}
			}
			if _, err := os.Lstat(filepath.Join(dir, journalFilename)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rolled-back operation left an active journal: %v", err)
			}
		})
	}
}

func TestCommittedStateCleanupFailureReportsSuccessAndRetryOnlyCleans(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "alpha"})
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "alpha")
	injected := errors.New("make private cleanup persistently unusable")
	mutated := false
	var blockedTrash string
	result, err := Create(context.Background(), Options{Dir: dir, Pigsty: true, Fault: func(fault Fault) error {
		if fault.Point != FaultAfterMarker || mutated {
			return nil
		}
		mutated = true
		stages, stageErr := filepath.Glob(filepath.Join(dir, ".sow-plain-stage-*"))
		recoveries, recoveryErr := filepath.Glob(filepath.Join(dir, ".sow-plain-recovery-*"))
		if stageErr != nil || recoveryErr != nil || len(stages) != 1 || len(recoveries) != 1 {
			t.Fatalf("locate private state: stages=%v recoveries=%v errors=%v/%v", stages, recoveries, stageErr, recoveryErr)
		}
		if removeErr := os.RemoveAll(stages[0]); removeErr != nil {
			t.Fatal(removeErr)
		}
		blockedTrash = recoveries[0]
		if removeErr := os.RemoveAll(blockedTrash); removeErr != nil {
			t.Fatal(removeErr)
		}
		if writeErr := os.WriteFile(blockedTrash, []byte("cleanup conflict"), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		return injected
	}})
	if err != nil || !result.Marker || result.Noop {
		t.Fatalf("committed public state was reported as failure: result=%+v err=%v", result, err)
	}
	journal, loadErr := loadJournal(dir)
	if loadErr != nil || journal == nil || journal.Next != len(journal.Actions) {
		t.Fatalf("cleanup failure did not retain a completed journal: journal=%+v err=%v", journal, loadErr)
	}
	if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), filepath.Join(dir, "repodata"), yumrepo.CompressionGzip); err != nil {
		t.Fatalf("committed RPM repository is invalid: %v", err)
	}
	oldPointer := append([]byte(nil), mustRead(t, filepath.Join(dir, "repodata", "repomd.xml"))...)
	oldPackages := append([]byte(nil), mustRead(t, filepath.Join(dir, "Packages"))...)
	oldPackagesGzip := append([]byte(nil), mustRead(t, filepath.Join(dir, "Packages.gz"))...)
	oldMarker := append([]byte(nil), mustRead(t, filepath.Join(dir, "repo_complete"))...)
	if expanded := gunzip(t, oldPackagesGzip); !bytes.Equal(expanded, oldPackages) {
		t.Fatal("committed DEB index pair is inconsistent")
	}
	if len(oldMarker) == 0 {
		t.Fatal("committed Pigsty marker is empty")
	}

	if err := os.Remove(blockedTrash); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(blockedTrash, 0o700); err != nil {
		t.Fatal(err)
	}
	result, err = Create(context.Background(), Options{Dir: dir, Pigsty: true})
	if err != nil || !result.Recovered || !result.Noop {
		t.Fatalf("retry completed cleanup: result=%+v err=%v", result, err)
	}
	for path, want := range map[string][]byte{
		filepath.Join(dir, "repodata", "repomd.xml"): oldPointer,
		filepath.Join(dir, "Packages"):               oldPackages,
		filepath.Join(dir, "Packages.gz"):            oldPackagesGzip,
		filepath.Join(dir, "repo_complete"):          oldMarker,
	} {
		if got := mustRead(t, path); !bytes.Equal(got, want) {
			t.Fatalf("cleanup-only retry changed public bytes at %s", path)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful retry left active journal: %v", err)
	}
	for _, pattern := range []string{".sow-plain-stage-*", ".sow-plain-recovery-*"} {
		if paths, err := filepath.Glob(filepath.Join(dir, pattern)); err != nil || len(paths) != 0 {
			t.Fatalf("successful retry left %s: paths=%v err=%v", pattern, paths, err)
		}
	}
}

func TestCreateMixedToSingleRemovesOwnedObsoleteIndex(t *testing.T) {
	tests := []struct {
		name       string
		remove     string
		wantRPM    int
		wantDEB    int
		wantAbsent []string
	}{
		{"deb-only", "alpha.rpm", 0, 1, []string{"repodata"}},
		{"rpm-only", "alpha.deb", 1, 0, []string{"Packages", "Packages.gz"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "rpm"})
			writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "deb")
			if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, tt.remove)); err != nil {
				t.Fatal(err)
			}
			result, err := Create(context.Background(), Options{Dir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if result.RPM != tt.wantRPM || result.DEB != tt.wantDEB {
				t.Fatalf("result=%+v", result)
			}
			for _, name := range tt.wantAbsent {
				if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("obsolete index %s remains: %v", name, err)
				}
			}
		})
	}
}

func TestCreateDEBDisappearanceFailsClosedOnUnprovenOldIndex(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "rpm"})
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "deb")
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	anchor := append([]byte(nil), mustRead(t, filepath.Join(dir, "repodata", "repomd.xml"))...)
	if err := os.WriteFile(filepath.Join(dir, "Packages.gz"), []byte("not a SOW index\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "alpha.deb")); err != nil {
		t.Fatal(err)
	}
	_, err := Create(context.Background(), Options{Dir: dir})
	if err == nil || KindOf(err) != KindIntegrity {
		t.Fatalf("Create error=%v kind=%s", err, KindOf(err))
	}
	if got := mustRead(t, filepath.Join(dir, "repodata", "repomd.xml")); !bytes.Equal(got, anchor) {
		t.Fatal("failed DEB ownership proof changed live RPM index")
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed ownership proof persisted a journal: %v", err)
	}
}

func TestCreateRPMDisappearancePreservesUnprovenRepodata(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "rpm"})
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "deb")
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("not a SOW pointer\n")
	if err := os.WriteFile(filepath.Join(dir, "repodata", "repomd.xml"), corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "alpha.rpm")); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, filepath.Join(dir, "repodata", "repomd.xml")); !bytes.Equal(got, corrupt) {
		t.Fatalf("unproven repomd.xml changed: %q", got)
	}
}

func TestCreateRPMPreservesOpaqueExtraAndModulemdFilesOnRebuild(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "alpha"})
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	extras := map[string][]byte{
		"custom.data":     []byte("opaque custom bytes\n"),
		"modules.yaml.gz": []byte("not parsed modulemd bytes\n"),
	}
	for name, body := range extras {
		if err := os.WriteFile(filepath.Join(dir, "repodata", name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeRPMFixture(t, filepath.Join(dir, "beta.rpm"), rpmFixture{Name: "beta", Version: "1", Release: "1", Arch: "aarch64", Payload: "beta"})
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	for name, want := range extras {
		if got := mustRead(t, filepath.Join(dir, "repodata", name)); !bytes.Equal(got, want) {
			t.Fatalf("opaque repodata file %s changed: %q", name, got)
		}
	}
	pointer := mustRead(t, filepath.Join(dir, "repodata", "repomd.xml"))
	for name := range extras {
		if bytes.Contains(pointer, []byte(name)) {
			t.Fatalf("new repomd.xml references opaque file %s", name)
		}
	}
	primary := readPrimaryXML(t, filepath.Join(dir, "repodata"))
	for _, name := range []string{"alpha.rpm", "beta.rpm"} {
		if !bytes.Contains(primary, []byte(`href="`+name+`"`)) {
			t.Fatalf("rebuilt RPM index missing %s", name)
		}
	}
}

func TestCreateRPMDoesNotValidateOrCarryForwardReferencedModulemd(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "alpha"})
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	modulePath := filepath.Join(dir, "repodata", "modules.yaml.gz")
	moduleBody := []byte("deliberately invalid and opaque modulemd\n")
	if err := os.WriteFile(modulePath, moduleBody, 0o644); err != nil {
		t.Fatal(err)
	}
	pointerPath := filepath.Join(dir, "repodata", "repomd.xml")
	pointer := mustRead(t, pointerPath)
	moduleRecord := []byte(`<data type="modules"><checksum type="sha256">` + strings.Repeat("a", 64) + `</checksum><location href="repodata/modules.yaml.gz"/></data></repomd>`)
	pointer = bytes.Replace(pointer, []byte("</repomd>"), moduleRecord, 1)
	if err := os.WriteFile(pointerPath, pointer, 0o644); err != nil {
		t.Fatal(err)
	}
	writeRPMFixture(t, filepath.Join(dir, "beta.rpm"), rpmFixture{Name: "beta", Version: "1", Release: "1", Arch: "aarch64", Payload: "beta"})
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, modulePath); !bytes.Equal(got, moduleBody) {
		t.Fatalf("modulemd bytes changed: %q", got)
	}
	newPointer := mustRead(t, pointerPath)
	if bytes.Contains(newPointer, []byte("modules")) || bytes.Contains(newPointer, []byte("modules.yaml.gz")) {
		t.Fatalf("new repomd.xml carried modulemd forward:\n%s", newPointer)
	}
	names, owned, err := ownedRPMMetadata(context.Background(), t.TempDir(), filepath.Join(dir, "repodata"))
	if err != nil || !owned {
		t.Fatalf("new SOW pointer ownership proof: owned=%t err=%v", owned, err)
	}
	var primaryPath string
	for _, name := range names {
		if strings.HasSuffix(name, "-primary.xml.gz") {
			primaryPath = filepath.Join(dir, "repodata", name)
		}
	}
	if primaryPath == "" {
		t.Fatal("new primary artifact not found")
	}
	primary := gunzip(t, mustRead(t, primaryPath))
	if !bytes.Contains(primary, []byte(`href="beta.rpm"`)) {
		t.Fatalf("new primary does not contain beta.rpm:\n%s", primary)
	}
}

func TestCreateRPMDisappearancePreservesOpaqueExtraAndModulemdFiles(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "alpha"})
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "alpha")
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	owned := repodataFiles(t, dir)
	extras := map[string][]byte{
		"custom.data":     []byte("opaque custom bytes\n"),
		"modules.yaml.gz": []byte("not parsed modulemd bytes\n"),
	}
	for name, body := range extras {
		if err := os.WriteFile(filepath.Join(dir, "repodata", name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(dir, "alpha.rpm")); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	for _, relative := range owned {
		if _, err := os.Lstat(filepath.Join(dir, relative)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned RPM metadata %s remains: %v", relative, err)
		}
	}
	for name, want := range extras {
		if got := mustRead(t, filepath.Join(dir, "repodata", name)); !bytes.Equal(got, want) {
			t.Fatalf("opaque repodata file %s changed: %q", name, got)
		}
	}
	if !bytes.Contains(mustRead(t, filepath.Join(dir, "Packages")), []byte("Filename: ./alpha.deb\n")) {
		t.Fatal("remaining DEB index is invalid")
	}
}

func TestCreateMixedToSingleProcessTerminationRecovery(t *testing.T) {
	tests := []struct {
		name       string
		remove     string
		point      FaultPoint
		wantAbsent []string
	}{
		{"deb-only-before", "alpha.rpm", FaultBeforeRPMRemoval, []string{"repodata"}},
		{"deb-only-after", "alpha.rpm", FaultAfterRPMRemoval, []string{"repodata"}},
		{"rpm-only-before", "alpha.deb", FaultBeforeDEBRemoval, []string{"Packages", "Packages.gz"}},
		{"rpm-only-after", "alpha.deb", FaultAfterDEBRemoval, []string{"Packages", "Packages.gz"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "rpm"})
			writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "deb")
			if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, tt.remove)); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestPlainCrashHelper$")
			cmd.Env = append(os.Environ(),
				"SOW_PLAIN_CRASH_HELPER=1",
				"SOW_PLAIN_CRASH_DIR="+dir,
				"SOW_PLAIN_CRASH_POINT="+string(tt.point),
				"SOW_PLAIN_CRASH_PIGSTY=0",
			)
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 91 {
				t.Fatalf("crash helper exit=%v", err)
			}
			result, err := Create(context.Background(), Options{Dir: dir})
			if err != nil || !result.Recovered {
				t.Fatalf("recover result=%+v err=%v", result, err)
			}
			for _, name := range tt.wantAbsent {
				if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("obsolete index %s remains after recovery: %v", name, err)
				}
			}
			if strings.HasPrefix(tt.name, "deb-only") {
				if !bytes.Contains(mustRead(t, filepath.Join(dir, "Packages")), []byte("Filename: ./alpha.deb\n")) {
					t.Fatal("recovered DEB index is not usable")
				}
			} else if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), filepath.Join(dir, "repodata"), yumrepo.CompressionGzip); err != nil {
				t.Fatalf("recovered RPM index invalid: %v", err)
			}
		})
	}
}

func TestCreatePersistentFormatRemovalFailureRestoresOldMixedIndexes(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "rpm"})
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "deb")
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	oldPointer := append([]byte(nil), mustRead(t, filepath.Join(dir, "repodata", "repomd.xml"))...)
	oldPackages := append([]byte(nil), mustRead(t, filepath.Join(dir, "Packages"))...)
	if err := os.Remove(filepath.Join(dir, "alpha.rpm")); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("persistent RPM recovery-target conflict")
	mutated := false
	_, err := Create(context.Background(), Options{Dir: dir, Fault: func(fault Fault) error {
		if fault.Point != FaultBeforeRPMRemoval || mutated {
			return nil
		}
		mutated = true
		recoveries, globErr := filepath.Glob(filepath.Join(dir, ".sow-plain-recovery-*"))
		if globErr != nil || len(recoveries) != 1 {
			t.Fatalf("locate recovery directory: paths=%v err=%v", recoveries, globErr)
		}
		if writeErr := os.WriteFile(filepath.Join(recoveries[0], "obsolete"), []byte("conflict"), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		return injected
	}})
	if !errors.Is(err, injected) {
		t.Fatalf("persistent format-removal error=%v", err)
	}
	if got := mustRead(t, filepath.Join(dir, "repodata", "repomd.xml")); !bytes.Equal(got, oldPointer) {
		t.Fatal("failed format removal changed the old RPM pointer")
	}
	if got := mustRead(t, filepath.Join(dir, "Packages")); !bytes.Equal(got, oldPackages) {
		t.Fatal("failed format removal changed the old DEB pointer")
	}
	if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), filepath.Join(dir, "repodata"), yumrepo.CompressionGzip); err != nil {
		t.Fatalf("restored RPM repository is invalid: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rolled-back format removal left an active journal: %v", err)
	}
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatalf("fresh format-removal retry: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "repodata")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retry retained obsolete RPM index: %v", err)
	}
}

func TestEnsureRealDirectorySyncsEveryCreatedParent(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var synced []string
	err = ensureRealDirectoryRootUsing(root, filepath.Join("one", "two", "three"), 0o755, func(_ *os.Root, parent string) error {
		synced = append(synced, parent)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".", "one", filepath.Join("one", "two")}
	if !reflect.DeepEqual(synced, want) {
		t.Fatalf("synced parents=%v want=%v", synced, want)
	}
	synced = nil
	if err := ensureRealDirectoryRootUsing(root, filepath.Join("one", "two", "three"), 0o755, func(_ *os.Root, parent string) error {
		synced = append(synced, parent)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(synced, want) {
		t.Fatalf("replay synced parents=%v want=%v", synced, want)
	}
}
