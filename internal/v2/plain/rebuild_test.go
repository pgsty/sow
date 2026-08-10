package plain

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/yumrepo"
)

func TestCreateRejectsDisguisedSourceRPMFromHeader(t *testing.T) {
	for _, arch := range []string{"src", "nosrc"} {
		t.Run(arch, func(t *testing.T) {
			dir := t.TempDir()
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

// Temporarily remove every package after the concurrent scan, then restore the
// same inodes immediately before final stat validation. Rendering can succeed
// only if neither RPM nor DEB payloads are reopened after the content pass.
func TestCreateRendersFromSingleContentPass(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "alpha.rpm"), filepath.Join(dir, "alpha.deb")}
	writeRPMFixture(t, paths[0], rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: strings.Repeat("rpm", 4096)})
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), strings.Repeat("deb", 4096))

	fault := func(event Fault) error {
		switch event.Point {
		case FaultAfterContentScan:
			for _, path := range paths {
				if err := os.Rename(path, path+".hold"); err != nil {
					return err
				}
			}
		case FaultBeforeStatValidation:
			for _, path := range paths {
				if err := os.Rename(path+".hold", path); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if _, err := Create(context.Background(), Options{Dir: dir, Jobs: 2, Fault: fault}); err != nil {
		t.Fatalf("single-pass Create: %v", err)
	}
	if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), filepath.Join(dir, "repodata"), yumrepo.CompressionGzip); err != nil {
		t.Fatalf("validate RPM output: %v", err)
	}
	if got, want := gunzip(t, mustRead(t, filepath.Join(dir, "Packages.gz"))), mustRead(t, filepath.Join(dir, "Packages")); !bytes.Equal(got, want) {
		t.Fatal("Packages.gz does not match Packages")
	}
}

func TestInspectPackageFactRejectsReplacementAfterEnumeration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alpha.rpm")
	writeRPMFixture(t, path, rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "old"})
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement.rpm")
	writeRPMFixture(t, replacement, rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "new"})
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}

	_, err = inspectPackageFact(context.Background(), path, "alpha.rpm", formatRPM, before)
	if err == nil || !strings.Contains(err.Error(), "changed after inspection") {
		t.Fatalf("inspectPackageFact error=%v", err)
	}
}

func TestCreateFinalStatRejectsChangedPackageWithoutPublishing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alpha.rpm")
	writeRPMFixture(t, path, rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "alpha"})
	mutated := false
	_, err := Create(context.Background(), Options{Dir: dir, Fault: func(event Fault) error {
		if event.Point == FaultBeforeStatValidation && !mutated {
			mutated = true
			file, openErr := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if openErr != nil {
				return openErr
			}
			_, writeErr := file.Write([]byte("changed"))
			return errors.Join(writeErr, file.Close())
		}
		return nil
	}})
	if err == nil || KindOf(err) != KindIntegrity || !strings.Contains(err.Error(), "stat changed") {
		t.Fatalf("Create error=%v kind=%s", err, KindOf(err))
	}
	if _, err := os.Lstat(filepath.Join(dir, "repodata")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat rejection published repodata: %v", err)
	}
}

func TestCreateFailureThenOverwriteRebuildConverges(t *testing.T) {
	dir := t.TempDir()
	rpm := filepath.Join(dir, "alpha.rpm")
	writeRPMFixture(t, rpm, rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "old-rpm"})
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "old-deb")
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	writeRPMFixture(t, rpm, rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "new-rpm"})
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "new-deb")
	want := errors.New("stop after RPM pointer")
	_, err := Create(context.Background(), Options{Dir: dir, Fault: func(event Fault) error {
		if event.Point == FaultAfterRPMPointer {
			return want
		}
		return nil
	}})
	if !errors.Is(err, want) {
		t.Fatalf("faulted Create error=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, legacyPlainJournal)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("faulted Create wrote a journal: %v", err)
	}

	result, err := Create(context.Background(), Options{Dir: dir, Jobs: 4})
	if err != nil {
		t.Fatalf("overwrite rebuild: %v", err)
	}
	if result.Recovered || result.Noop {
		t.Fatalf("rebuild result=%+v", result)
	}
	if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), filepath.Join(dir, "repodata"), yumrepo.CompressionGzip); err != nil {
		t.Fatalf("rebuilt RPM output: %v", err)
	}
	if !bytes.Contains(readPrimaryXML(t, filepath.Join(dir, "repodata")), []byte(fileSHA(rpm))) {
		t.Fatal("rebuilt RPM metadata does not bind current package bytes")
	}
	if !bytes.Contains(mustRead(t, filepath.Join(dir, "Packages")), []byte(fileSHA(filepath.Join(dir, "alpha.deb")))) {
		t.Fatal("rebuilt DEB metadata does not bind current package bytes")
	}
	repeat, err := Create(context.Background(), Options{Dir: dir})
	if err != nil || !repeat.Noop {
		t.Fatalf("stable repeat result=%+v err=%v", repeat, err)
	}
}

func TestCreateReplacesPartialDerivedOutputs(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "alpha.rpm"), rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "rpm"})
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "deb")
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "alpha.rpm")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "Packages.gz")); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatalf("rebuild partial outputs: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "repodata")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("obsolete RPM output remains: %v", err)
	}
	if got, want := gunzip(t, mustRead(t, filepath.Join(dir, "Packages.gz"))), mustRead(t, filepath.Join(dir, "Packages")); !bytes.Equal(got, want) {
		t.Fatal("rebuilt DEB pair differs")
	}
}

func TestCreateDiscardsLegacyPrivateState(t *testing.T) {
	dir := t.TempDir()
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "alpha")
	for _, name := range []string{".sow-plain-stage-old", ".sow-plain-recovery-old"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, legacyPlainJournal), []byte("obsolete\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".sow-plain-stage-old", ".sow-plain-recovery-old", legacyPlainJournal} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale state %s remains: %v", name, err)
		}
	}
}
