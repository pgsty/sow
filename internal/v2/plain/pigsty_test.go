package plain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/yumrepo"
)

func TestPigstyCleanupRules(t *testing.T) {
	tests := []struct {
		name string
		fact packageFact
		want bool
	}{
		{"rpm-i386-is-retained", packageFact{format: formatRPM, name: "legacy", version: "1", arch: "i386"}, false},
		{"rpm-patroni-exact", packageFact{format: formatRPM, name: "patroni", version: "3.0.4", arch: "x86_64"}, true},
		{"rpm-patroni-suffix", packageFact{format: formatRPM, name: "patroni", version: "3.0.4+foo", arch: "x86_64"}, false},
		{"deb-i386", packageFact{format: formatDEB, name: "legacy", version: "1.0-1", arch: "i386"}, true},
		{"deb-patroni-exact", packageFact{format: formatDEB, name: "patroni", version: "1:3.0.4-7", arch: "amd64"}, true},
		{"deb-patroni-suffix", packageFact{format: formatDEB, name: "patroni", version: "1:3.0.4+foo-7", arch: "amd64"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRemove(tt.fact); got != tt.want {
				t.Fatalf("shouldRemove(%+v)=%t want %t", tt.fact, got, tt.want)
			}
		})
	}
}

func TestCreatePigstyCleanupMarkerAndNoop(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "good.rpm"), rpmFixture{Name: "good", Version: "1", Release: "1", Arch: "x86_64", Payload: "good"})
	writeRPMFixture(t, filepath.Join(dir, "bad.rpm"), rpmFixture{Name: "patroni", Version: "3.0.4", Release: "1", Arch: "x86_64", Payload: "bad"})
	writeDEBFixture(t, dir, "good.deb", debControl("good", "1.0-1", "amd64"), "good")
	writeDEBFixture(t, dir, "bad.deb", debControl("legacy", "1.0-1", "i386"), "bad")

	result, err := Create(context.Background(), Options{Dir: dir, Jobs: 4, Pigsty: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.Removed, ",") != "bad.deb,bad.rpm" || strings.Join(result.Kept, ",") != "good.deb,good.rpm" {
		t.Fatalf("result=%+v", result)
	}
	for _, name := range result.Removed {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("removed package %s remains: %v", name, err)
		}
	}
	wantMarker := fmt.Sprintf("%s  good.deb\n%s  good.rpm\n", fileSHA(filepath.Join(dir, "good.deb")), fileSHA(filepath.Join(dir, "good.rpm")))
	markerPath := filepath.Join(dir, "repo_complete")
	if got := string(mustRead(t, markerPath)); got != wantMarker {
		t.Fatalf("marker=%q want=%q", got, wantMarker)
	}
	before, err := os.Lstat(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	repeat, err := Create(context.Background(), Options{Dir: dir, Pigsty: true})
	if err != nil || !repeat.Noop {
		t.Fatalf("repeat=%+v err=%v", repeat, err)
	}
	after, err := os.Lstat(markerPath)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("no-op replaced marker: %v", err)
	}
}

func TestCreatePigstyFailureWithdrawsMarkerAndRerunRebuilds(t *testing.T) {
	dir := t.TempDir()
	rpm := filepath.Join(dir, "good.rpm")
	writeRPMFixture(t, rpm, rpmFixture{Name: "good", Version: "1", Release: "1", Arch: "x86_64", Payload: "old"})
	writeDEBFixture(t, dir, "good.deb", debControl("good", "1.0-1", "amd64"), "old")
	if _, err := Create(context.Background(), Options{Dir: dir, Pigsty: true}); err != nil {
		t.Fatal(err)
	}
	writeRPMFixture(t, rpm, rpmFixture{Name: "good", Version: "1", Release: "1", Arch: "x86_64", Payload: "new"})
	writeRPMFixture(t, filepath.Join(dir, "bad.rpm"), rpmFixture{Name: "patroni", Version: "3.0.4", Release: "1", Arch: "x86_64", Payload: "bad"})
	writeDEBFixture(t, dir, "good.deb", debControl("good", "1.0-1", "amd64"), "new")
	writeDEBFixture(t, dir, "bad.deb", debControl("legacy", "1.0-1", "i386"), "bad")
	want := errors.New("interrupted")
	_, err := Create(context.Background(), Options{Dir: dir, Pigsty: true, Fault: func(event Fault) error {
		if event.Point == FaultAfterRPMPointer {
			return want
		}
		return nil
	}})
	if !errors.Is(err, want) {
		t.Fatalf("faulted Create error=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "repo_complete")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted Pigsty create left completion marker: %v", err)
	}

	result, err := Create(context.Background(), Options{Dir: dir, Pigsty: true})
	if err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if result.Recovered || strings.Join(result.Removed, ",") != "bad.deb,bad.rpm" {
		t.Fatalf("rerun result=%+v", result)
	}
	if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), filepath.Join(dir, "repodata"), yumrepo.CompressionGzip); err != nil {
		t.Fatalf("rebuilt RPM output: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "repo_complete")); err != nil {
		t.Fatalf("rerun did not publish marker last: %v", err)
	}
}

func TestCreatePigstyEmptyAuthorityConvergesAfterInterruption(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "legacy.rpm"), rpmFixture{Name: "patroni", Version: "3.0.4", Release: "1", Arch: "x86_64", Payload: "legacy"})
	writeDEBFixture(t, dir, "legacy.deb", debControl("legacy", "1.0-1", "i386"), "legacy")
	want := errors.New("stop after removals")
	_, err := Create(context.Background(), Options{Dir: dir, Pigsty: true, Fault: func(event Fault) error {
		if event.Point == FaultAfterPackageRename && event.Sequence == 1 {
			return want
		}
		return nil
	}})
	if !errors.Is(err, want) {
		t.Fatalf("faulted Create error=%v", err)
	}
	for _, name := range []string{"legacy.rpm", "legacy.deb", "repo_complete"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s unexpectedly exists: %v", name, err)
		}
	}
	result, err := Create(context.Background(), Options{Dir: dir, Pigsty: true})
	if err != nil {
		t.Fatalf("empty-authority rerun: %v", err)
	}
	if result.RPM != 0 || result.DEB != 0 || len(mustRead(t, filepath.Join(dir, "repo_complete"))) != 0 {
		t.Fatalf("empty-authority result=%+v", result)
	}
	for _, name := range []string{"repodata", "Packages", "Packages.gz", legacyPlainJournal} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("derived residue %s remains: %v", name, err)
		}
	}
}

func TestCreatePigstyAllRemovedPublishesNoEmptyIndexes(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "legacy.rpm"), rpmFixture{Name: "patroni", Version: "3.0.4", Release: "1", Arch: "x86_64", Payload: "legacy"})
	writeDEBFixture(t, dir, "legacy.deb", debControl("legacy", "1.0-1", "i386"), "legacy")

	result, err := Create(context.Background(), Options{Dir: dir, Pigsty: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.RPM != 0 || result.DEB != 0 || len(result.Kept) != 0 || strings.Join(result.Removed, ",") != "legacy.deb,legacy.rpm" {
		t.Fatalf("result=%+v", result)
	}
	if len(mustRead(t, filepath.Join(dir, "repo_complete"))) != 0 {
		t.Fatal("empty authoritative package set produced a non-empty marker")
	}
	for _, name := range []string{"legacy.rpm", "legacy.deb", "repodata", "Packages", "Packages.gz"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s unexpectedly exists: %v", name, err)
		}
	}
}
