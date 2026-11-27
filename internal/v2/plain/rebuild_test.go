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

func TestCreateSkipsDisguisedSourceRPMByDefaultAndRejectsInStrictMode(t *testing.T) {
	for _, arch := range []string{"src", "nosrc"} {
		t.Run(arch, func(t *testing.T) {
			dir := t.TempDir()
			writeRPMFixture(t, filepath.Join(dir, "looks-binary.rpm"), rpmFixture{
				Name: "source-only", Version: "1", Release: "1", Arch: arch, Payload: "source",
			})
			_, err := Create(context.Background(), Options{Dir: dir, Strict: true})
			if err == nil || KindOf(err) != KindRejected || !strings.Contains(err.Error(), "source rpm") {
				t.Fatalf("strict Create error=%v kind=%s", err, KindOf(err))
			}
			if _, err := os.Lstat(filepath.Join(dir, "repodata")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("strict source RPM rejection created repodata: %v", err)
			}
			// Default mode skips source RPM with a warning.
			res, err := Create(context.Background(), Options{Dir: dir})
			if err != nil || res.RPM != 0 || len(res.Skipped) != 1 || res.Skipped[0].Path != "looks-binary.rpm" {
				t.Fatalf("default source RPM skip res=%+v err=%v", res, err)
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

func TestCreatePigstyIndexesRepeatedSourceRPM(t *testing.T) {
	dir := t.TempDir()
	const source = "pkg-1-1.src.rpm"
	writeRPMFixture(t, filepath.Join(dir, "pkg-1-1.aarch64.rpm"), rpmFixture{
		Name: "pkg", Version: "1", Release: "1", Arch: "aarch64",
		ExtraTags: []rpmTag{rpmStringTag(1044, source)},
	})
	result, err := Create(context.Background(), Options{Dir: dir, Pigsty: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.RPM != 1 || !result.Marker {
		t.Fatalf("created repository with rpm=%d marker=%t", result.RPM, result.Marker)
	}
	primary := readPrimaryXML(t, filepath.Join(dir, "repodata"))
	if got := bytes.Count(primary, []byte("<rpm:sourcerpm>"+source+"</rpm:sourcerpm>")); got != 1 {
		t.Fatalf("primary metadata contains %d copies of SOURCERPM, want 1", got)
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

func TestCreatePreservesSkippedFormatAndMarker(t *testing.T) {
	for _, bad := range []string{"alpha.rpm", "alpha.deb"} {
		t.Run(bad, func(t *testing.T) {
			dir := t.TempDir()
			opts := Options{Dir: dir, Pigsty: true}
			rpm := filepath.Join(dir, "alpha.rpm")
			writeRPMFixture(t, rpm, rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "old"})
			writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1", "amd64"), "old")
			if _, err := Create(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, bad)
			wantLine := fileSHA(path) + "  " + bad
			protected := []string{"Packages", "Packages.gz"}
			if bad == "alpha.rpm" {
				protected = []string{"repodata/repomd.xml", rpmHistoryName}
				writeDEBFixture(t, dir, "beta.deb", debControl("beta", "1", "amd64"), "new")
			} else {
				writeRPMFixture(t, filepath.Join(dir, "beta.rpm"), rpmFixture{Name: "beta", Version: "1", Release: "1", Arch: "noarch", Payload: "new"})
			}
			before := map[string]string{}
			for _, name := range protected {
				before[name] = fileSHA(filepath.Join(dir, name))
			}
			if err := os.WriteFile(path, []byte("incomplete transfer"), 0644); err != nil {
				t.Fatal(err)
			}
			stop := errors.New("interrupted")
			opts.Fault = func(event Fault) error {
				if event.Point == FaultAfterMarkerWithdrawn {
					return stop
				}
				return nil
			}
			if _, err := Create(context.Background(), opts); !errors.Is(err, stop) {
				t.Fatal(err)
			}
			opts.Fault = nil
			res, err := Create(context.Background(), opts)
			if err != nil || len(res.Skipped) != 1 || len(res.DroppedMetadata) != 0 {
				t.Fatalf("res=%+v err=%v", res, err)
			}
			for name, sum := range before {
				if fileSHA(filepath.Join(dir, name)) != sum {
					t.Fatalf("%s changed", name)
				}
			}
			marker := string(mustRead(t, filepath.Join(dir, "repo_complete")))
			if !strings.Contains(marker, wantLine) || !strings.Contains(marker, "  beta.") {
				t.Fatalf("marker=%s", marker)
			}
		})
	}
}

func TestCreateUsesDebianVersionIdentity(t *testing.T) {
	dir := t.TempDir()
	writeDEBFixture(t, dir, "a.deb", debControl("app", "1.0-1", "amd64"), "first")
	writeDEBFixture(t, dir, "b.deb", debControl("app", "1.00-1", "amd64"), "second")
	if _, err := Create(context.Background(), Options{Dir: dir, Strict: true}); KindOf(err) != KindRejected {
		t.Fatalf("strict conflict: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "Packages")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("strict published: %v", err)
	}
	res, err := Create(context.Background(), Options{Dir: dir})
	if err != nil || res.DEB != 1 || len(res.Skipped) != 1 || res.Skipped[0].Path != "b.deb" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestPigstyRemovalRechecksPackageAtDeletion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.rpm")
	rpm := rpmFixture{Name: "patroni", Version: "3.0.4", Release: "1", Arch: "noarch"}
	writeRPMFixture(t, path, rpm)
	writeRPMFixture(t, filepath.Join(dir, "keep.rpm"), rpmFixture{Name: "keep", Version: "1", Release: "1", Arch: "noarch"})
	_, err := Create(context.Background(), Options{Dir: dir, Pigsty: true, Fault: func(f Fault) error {
		if f.Point == FaultAfterRPMPointer {
			return os.WriteFile(path, []byte("new arrival"), 0644)
		}
		return nil
	}})
	if KindOf(err) != KindIntegrity || string(mustRead(t, path)) != "new arrival" {
		t.Fatalf("replacement lost: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "repo_complete")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("incomplete marker: %v", err)
	}
}

func TestCreatePigstyFreshDirectoryPublishesValidFormatWhenOtherFormatFails(t *testing.T) {
	t.Run("fresh directory with valid deb and corrupt rpm", func(t *testing.T) {
		dir := t.TempDir()
		debPath := writeDEBFixture(t, dir, "good.deb", debControl("good", "1.0-1", "amd64"), "payload")
		if err := os.WriteFile(filepath.Join(dir, "bad.rpm"), []byte("not an rpm"), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := Create(context.Background(), Options{Dir: dir, Pigsty: true})
		if err != nil || res.DEB != 1 || res.RPM != 0 || !res.Marker || res.Noop || len(res.Skipped) != 1 || res.Skipped[0].Path != "bad.rpm" {
			t.Fatalf("fresh pigsty create=%+v err=%v", res, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "Packages")); err != nil {
			t.Fatalf("Packages missing: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "Packages.gz")); err != nil {
			t.Fatalf("Packages.gz missing: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "repodata")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected repodata: %v", err)
		}
		marker := string(mustRead(t, filepath.Join(dir, "repo_complete")))
		want := fileSHA(debPath) + "  good.deb\n"
		if marker != want {
			t.Fatalf("repo_complete=%q want=%q", marker, want)
		}
	})

	t.Run("existing non-pigsty rpm index without marker skips cleanly", func(t *testing.T) {
		dir := t.TempDir()
		rpmPath := filepath.Join(dir, "old.rpm")
		writeRPMFixture(t, rpmPath, rpmFixture{Name: "old", Version: "1", Release: "1", Arch: "x86_64", Payload: "old"})
		if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
			t.Fatal(err)
		}
		beforeRepomd := fileSHA(filepath.Join(dir, "repodata", "repomd.xml"))
		if err := os.WriteFile(rpmPath, []byte("corrupt"), 0o644); err != nil {
			t.Fatal(err)
		}
		writeDEBFixture(t, dir, "good.deb", debControl("good", "1.0-1", "amd64"), "payload")
		res, err := Create(context.Background(), Options{Dir: dir, Pigsty: true})
		if err != nil || !res.Noop || res.Marker {
			t.Fatalf("unmarked prior index res=%+v err=%v", res, err)
		}
		if fileSHA(filepath.Join(dir, "repodata", "repomd.xml")) != beforeRepomd {
			t.Fatal("existing repomd.xml changed")
		}
		for _, w := range res.Warnings {
			if strings.Contains(w, pruneMarkerName) {
				t.Fatalf("warning leaked internal prune marker name: %q", w)
			}
		}
	})

	t.Run("mixed repo removes stale deb index when all debs deleted and rpm corrupt", func(t *testing.T) {
		dir := t.TempDir()
		rpmPath := filepath.Join(dir, "alpha.rpm")
		writeRPMFixture(t, rpmPath, rpmFixture{Name: "alpha", Version: "1", Release: "1", Arch: "x86_64", Payload: "old"})
		debPath := writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1", "amd64"), "old")
		if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
			t.Fatal(err)
		}
		beforeRepomd := fileSHA(filepath.Join(dir, "repodata", "repomd.xml"))
		if err := os.Remove(debPath); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rpmPath, []byte("corrupt"), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := Create(context.Background(), Options{Dir: dir})
		if err != nil || res.Noop {
			t.Fatalf("mixed cleanup res=%+v err=%v", res, err)
		}
		if fileSHA(filepath.Join(dir, "repodata", "repomd.xml")) != beforeRepomd {
			t.Fatal("existing repomd.xml changed")
		}
		for _, stale := range []string{"Packages", "Packages.gz"} {
			if _, err := os.Stat(filepath.Join(dir, stale)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("stale %s remained: %v", stale, err)
			}
		}
	})
}
