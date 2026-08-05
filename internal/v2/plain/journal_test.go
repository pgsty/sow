package plain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPigstyJournalRequiresExplicitPigstyRecovery(t *testing.T) {
	dir := t.TempDir()
	writeCrashFixture(t, dir)
	stop := errors.New("stop after journal")
	_, err := Create(context.Background(), Options{Dir: dir, Pigsty: true, Fault: func(fault Fault) error {
		if fault.Point == FaultAfterJournal {
			return stop
		}
		return nil
	}})
	if !errors.Is(err, stop) {
		t.Fatalf("fault Create: %v", err)
	}
	_, err = Create(context.Background(), Options{Dir: dir})
	if err == nil || KindOf(err) != KindRejected || !strings.Contains(err.Error(), "rerun create with --pigsty") {
		t.Fatalf("default recovery error = %v, kind = %s", err, KindOf(err))
	}
	for _, name := range []string{"bad.rpm", "bad.deb", journalFilename} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("default recovery changed %s: %v", name, err)
		}
	}
	if got := string(mustRead(t, filepath.Join(dir, "repo_complete"))); got != "old marker\n" {
		t.Fatalf("default recovery changed marker: %q", got)
	}
	if _, err := Create(context.Background(), Options{Dir: dir, Pigsty: true}); err != nil {
		t.Fatalf("explicit recovery: %v", err)
	}
	assertRecoveredFixture(t, dir)
}

func TestDefaultJournalCannotBeSilentlyRecoveredAsPigsty(t *testing.T) {
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
	_, err = Create(context.Background(), Options{Dir: dir, Pigsty: true})
	if err == nil || KindOf(err) != KindRejected || !strings.Contains(err.Error(), "without --pigsty") {
		t.Fatalf("mismatched recovery error=%v kind=%s", err, KindOf(err))
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFilename)); err != nil {
		t.Fatalf("mismatched recovery removed journal: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "repo_complete")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched recovery created marker: %v", err)
	}
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatalf("recover original mode: %v", err)
	}
}

func TestJournalNextIsOnlyAHint(t *testing.T) {
	dir := t.TempDir()
	writeCrashFixture(t, dir)
	stop := errors.New("stop after journal")
	_, err := Create(context.Background(), Options{Dir: dir, Pigsty: true, Fault: func(fault Fault) error {
		if fault.Point == FaultAfterJournal {
			return stop
		}
		return nil
	}})
	if !errors.Is(err, stop) {
		t.Fatalf("fault Create: %v", err)
	}
	journal, err := loadJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	journal.Next = len(journal.Actions)
	if err := persistJournal(dir, *journal); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), Options{Dir: dir, Pigsty: true}); err != nil {
		t.Fatalf("recover with untrusted next hint: %v", err)
	}
	assertRecoveredFixture(t, dir)
}

func TestWriteJournalRetainsInstalledStateWhenParentSyncFails(t *testing.T) {
	dir := t.TempDir()
	stop := errors.New("parent sync failed")
	err := writeJournalUsing(dir, operationJournal{Version: journalVersion}, func(path string) error {
		if path != dir {
			t.Fatalf("sync path = %q, want %q", path, dir)
		}
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("writeJournalUsing error = %v, want %v", err, stop)
	}
	if !journalWasInstalled(err) {
		t.Fatalf("writeJournalUsing did not report the completed rename: %v", err)
	}
	if info, statErr := os.Lstat(filepath.Join(dir, journalFilename)); statErr != nil || !info.Mode().IsRegular() {
		t.Fatalf("installed journal missing after sync failure: info=%v err=%v", info, statErr)
	}
}

func TestPackageProgressDoesNotRewriteWholeJournal(t *testing.T) {
	journal := operationJournal{Stage: ".sow-plain-stage-test", Trash: ".sow-plain-recovery-test"}
	signed := fileAction{Kind: "install", Source: filepath.Join(journal.Stage, "packages", "a.rpm"), Target: "a.rpm", Package: "a.rpm", Replace: true, Before: FaultBeforeRPMPackage, After: FaultAfterRPMPackage}
	removed := fileAction{Kind: "move", Source: "b.rpm", Target: filepath.Join(journal.Trash, "packages", "b.rpm"), Package: "b.rpm", After: FaultAfterPackageRename}
	pointer := fileAction{Kind: "install", Source: filepath.Join(journal.Stage, "repodata", "repomd.xml"), Target: filepath.Join("repodata", "repomd.xml"), Replace: true, Before: FaultBeforeRPMPointer, After: FaultAfterRPMPointer}
	if shouldPersistJournalProgress(journal, signed) || shouldPersistJournalProgress(journal, removed) {
		t.Fatal("per-package progress would rewrite the complete journal")
	}
	if !shouldPersistJournalProgress(journal, pointer) {
		t.Fatal("metadata publication boundary did not persist progress")
	}
}

func TestLoadJournalRejectsSymlinkAndOversizedFile(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		outside := filepath.Join(t.TempDir(), "journal")
		if err := os.WriteFile(outside, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, journalFilename)); err != nil {
			t.Fatal(err)
		}
		if _, err := loadJournal(dir); err == nil || KindOf(err) != KindIntegrity {
			t.Fatalf("symlink journal error = %v, kind = %s", err, KindOf(err))
		}
	})
	t.Run("oversized", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, journalFilename)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(maxJournalBytes + 1); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := loadJournal(dir); err == nil || KindOf(err) != KindIntegrity {
			t.Fatalf("oversized journal error = %v, kind = %s", err, KindOf(err))
		}
	})
}

func TestJournalRejectsForgedPackageCleanupAction(t *testing.T) {
	dir := t.TempDir()
	writeCrashFixture(t, dir)
	writeRPMFixture(t, filepath.Join(dir, "unknown.rpm"), rpmFixture{Name: "unknown", Version: "1", Release: "1", Arch: "x86_64", Payload: "keep"})
	stop := errors.New("stop after journal")
	_, err := Create(context.Background(), Options{Dir: dir, Pigsty: true, Fault: func(fault Fault) error {
		if fault.Point == FaultAfterJournal {
			return stop
		}
		return nil
	}})
	if !errors.Is(err, stop) {
		t.Fatalf("fault Create: %v", err)
	}
	journal, err := loadJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hashFile(context.Background(), filepath.Join(dir, "unknown.rpm"))
	if err != nil {
		t.Fatal(err)
	}
	for index := range journal.Actions {
		if journal.Actions[index].Package == "bad.rpm" {
			journal.Actions[index].Source = "unknown.rpm"
			journal.Actions[index].Target = filepath.Join(journal.Trash, "packages", "unknown.rpm")
			journal.Actions[index].Package = "unknown.rpm"
			journal.Actions[index].SHA256 = digest
			break
		}
	}
	body, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, journalFilename), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Create(context.Background(), Options{Dir: dir, Pigsty: true})
	if err == nil || KindOf(err) != KindIntegrity {
		t.Fatalf("forged package action error = %v, kind = %s", err, KindOf(err))
	}
	if _, err := os.Lstat(filepath.Join(dir, "unknown.rpm")); err != nil {
		t.Fatalf("forged cleanup touched unknown.rpm: %v", err)
	}
}

func TestJournalWireRejectsUnknownVersionFieldAndEscape(t *testing.T) {
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name string
		body string
	}{
		{"version", `{"version":4,"pigsty":false,"stage":".sow-plain-stage-x","trash":".sow-plain-recovery-x","inputs":[],"actions":[],"next":0}`},
		{"unknown-field", fmt.Sprintf(`{"version":%d,"pigsty":false,"stage":".sow-plain-stage-x","trash":".sow-plain-recovery-x","inputs":[],"actions":[],"next":0,"future":true}`, journalVersion)},
		{"escape", fmt.Sprintf(`{"version":%d,"pigsty":false,"stage":".sow-plain-stage-x","trash":".sow-plain-recovery-x","inputs":[],"actions":[{"kind":"install","source":"../outside","target":"Packages","sha256":"%s"}],"next":0}`, journalVersion, digest)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, journalFilename), []byte(tt.body+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadJournal(dir)
			if err == nil || KindOf(err) != KindIntegrity {
				t.Fatalf("loadJournal error = %v, kind = %s", err, KindOf(err))
			}
		})
	}
}

func TestJournalV3RejectsInstallWithoutBoundPreimage(t *testing.T) {
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
	journal, err := loadJournal(dir)
	if err != nil || journal == nil || journal.Version != journalVersion {
		t.Fatalf("load v3 journal: journal=%+v err=%v", journal, err)
	}
	for index := range journal.Actions {
		if journal.Actions[index].Kind == "install" {
			journal.Actions[index].Prior = nil
			break
		}
	}
	body, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, journalFilename), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadJournal(dir); err == nil || KindOf(err) != KindIntegrity || !strings.Contains(err.Error(), "pre-image") {
		t.Fatalf("unbound v3 pre-image error=%v kind=%s", err, KindOf(err))
	}
}

func TestRecoveryRejectsSymlinkedStageWithoutTouchingOutside(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	outsideSentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(outsideSentinel, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
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
	journal, err := loadJournal(dir)
	if err != nil || journal == nil {
		t.Fatalf("load retained journal: %v", err)
	}
	stage := filepath.Join(dir, journal.Stage)
	saved := stage + ".saved"
	if err := os.Rename(stage, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, stage); err != nil {
		t.Fatal(err)
	}
	_, err = Create(context.Background(), Options{Dir: dir})
	if err == nil || KindOf(err) != KindIntegrity {
		t.Fatalf("symlinked stage recovery error = %v, kind = %s", err, KindOf(err))
	}
	if got := string(mustRead(t, outsideSentinel)); got != "outside" {
		t.Fatalf("outside sentinel changed: %q", got)
	}
}

func TestCreatedRepodataDirectoryIsClientTraversable(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "good.rpm"), rpmFixture{Name: "good", Version: "1", Release: "1", Arch: "x86_64", Payload: "good"})
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "repodata"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("repodata mode = %o, want 755", got)
	}
}

func TestCommitRejectsSymlinkedRepodataWithoutTouchingOutside(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "repodata")); err != nil {
		t.Fatal(err)
	}
	writeRPMFixture(t, filepath.Join(dir, "good.rpm"), rpmFixture{Name: "good", Version: "1", Release: "1", Arch: "x86_64", Payload: "good"})
	_, err := Create(context.Background(), Options{Dir: dir})
	if err == nil || KindOf(err) != KindIntegrity {
		t.Fatalf("symlinked repodata error = %v, kind = %s", err, KindOf(err))
	}
	if got := string(mustRead(t, sentinel)); got != "outside" {
		t.Fatalf("outside sentinel changed: %q", got)
	}
}

func TestPlainJournalWireLimitIsCheckedBeforePersistence(t *testing.T) {
	journal := operationJournal{
		Version: journalVersion,
		Stage:   ".sow-plain-stage-fixture",
		Trash:   ".sow-plain-recovery-fixture",
		Inputs:  []inputFact{{Base: strings.Repeat("x", maxJournalBytes)}},
	}
	if err := validateJournalWireSize("/plain", journal, true); err == nil || KindOf(err) != KindRejected {
		t.Fatalf("oversized journal wire error=%v kind=%s", err, KindOf(err))
	}
	journal.Inputs[0].Base = "fixture.rpm"
	if err := validateJournalWireSize("/plain", journal, true); err != nil {
		t.Fatalf("small journal rejected: %v", err)
	}
}

func TestPlainJournalWireCapacityCoversDocumentedPackageScale(t *testing.T) {
	const packages = 34_184
	inputs := make([]inputFact, 0, packages)
	for index := 0; index < packages; index++ {
		name := fmt.Sprintf("package-%05d", index)
		base := name + "-12.34.56-7.el9.aarch64.rpm"
		inputs = append(inputs, inputFact{
			Format: formatRPM, Base: base,
			Coordinate: fmt.Sprintf("rpm:%s\x000\x0012.34.56\x007.el9\x00aarch64", name),
			SHA256:     fmt.Sprintf("%064x", index),
			Name:       name,
			Version:    "12.34.56",
			Arch:       "aarch64",
		})
	}
	journal := operationJournal{
		Version: journalVersion,
		Stage:   ".sow-plain-stage-scale",
		Trash:   ".sow-plain-recovery-scale",
		Inputs:  inputs,
	}
	body, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= 4<<20 {
		t.Fatalf("scale fixture no longer proves the former 4 MiB regression: bytes=%d", len(body))
	}
	if err := validateJournalWireSize("/plain", journal, true); err != nil {
		t.Fatalf("documented %d-package scale exceeds the bounded journal: bytes=%d err=%v", packages, len(body), err)
	}
}
