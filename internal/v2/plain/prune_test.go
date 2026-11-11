package plain

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/yumrepo"
)

func TestPruneLatestRPMsAndProtectedNames(t *testing.T) {
	dir := t.TempDir()
	packages := []struct {
		file string
		pkg  rpmFixture
		keep bool
	}{
		{"snapshot.rpm", rpmFixture{Name: "alpha", Version: "2.0^20250611", Release: "1", Arch: "x86_64"}, false},
		{"release.rpm", rpmFixture{Name: "alpha", Version: "2.0.1", Release: "1", Arch: "x86_64"}, true},
		{"arm-old.rpm", rpmFixture{Name: "alpha", Version: "1.9", Release: "1", Arch: "aarch64"}, false},
		{"arm-new.rpm", rpmFixture{Name: "alpha", Version: "1.10", Release: "1", Arch: "aarch64"}, true},
		{"neutral.rpm", rpmFixture{Name: "alpha", Version: "1.0", Release: "1", Arch: "noarch"}, true},
		{"i386.rpm", rpmFixture{Name: "alpha", Version: "1.0", Release: "1", Arch: "i386"}, true},
		{"epoch-old.rpm", rpmFixture{Name: "epoch", Version: "9.9", Release: "1", Arch: "x86_64"}, false},
		{"epoch-new.rpm", rpmFixture{Name: "epoch", Version: "0.1", Release: "1", Epoch: 1, Arch: "x86_64"}, true},
		{"revision-old.rpm", rpmFixture{Name: "revision", Version: "1", Release: "1^20250611", Arch: "x86_64"}, false},
		{"revision-new.rpm", rpmFixture{Name: "revision", Version: "1", Release: "1.1", Arch: "x86_64"}, true},
		{"age-old.rpm", rpmFixture{Name: "age_18", Version: "1", Release: "1", Arch: "x86_64"}, true},
		{"age-new.rpm", rpmFixture{Name: "age_18", Version: "2", Release: "1", Arch: "x86_64"}, true},
		{"jit-old.rpm", rpmFixture{Name: "age_18-llvmjit", Version: "1", Release: "1", Arch: "x86_64"}, true},
		{"jit-new.rpm", rpmFixture{Name: "age_18-llvmjit", Version: "2", Release: "1", Arch: "x86_64"}, true},
		{"client-old.rpm", rpmFixture{Name: "age_18-client", Version: "1", Release: "1", Arch: "x86_64"}, false},
		{"client-new.rpm", rpmFixture{Name: "age_18-client", Version: "2", Release: "1", Arch: "x86_64"}, true},
		{"patroni.rpm", rpmFixture{Name: "patroni", Version: "3.0.4", Release: "1", Arch: "x86_64"}, true},
	}
	before := map[string]string{}
	for _, item := range packages {
		path := filepath.Join(dir, item.file)
		writePruneRPM(t, path, item.pkg)
		before[item.file] = fileSHA(path)
	}
	nested := mustMkdir(t, filepath.Join(dir, "nested"))
	writePruneRPM(t, filepath.Join(nested, "hidden.rpm"), rpmFixture{Name: "alpha", Version: "999", Release: "1", Arch: "x86_64"})
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "repo_complete"), []byte("old marker\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := PruneOptions{Dir: dir, Protect: []string{"age_18", "age_18-llvmjit"}}
	result, err := Prune(context.Background(), opts)
	if err != nil || len(result.Removed) != 5 || !result.IndexUpdated || !result.Marker || result.DryRun {
		t.Fatalf("Prune=%+v err=%v", result, err)
	}
	primary := readPrimaryXML(t, filepath.Join(dir, "repodata"))
	marker := mustRead(t, filepath.Join(dir, "repo_complete"))
	for _, item := range packages {
		path := filepath.Join(dir, item.file)
		if item.keep {
			if fileSHA(path) != before[item.file] || !bytes.Contains(primary, []byte(`href="`+item.file+`"`)) || !bytes.Contains(marker, []byte(before[item.file]+"  "+item.file+"\n")) {
				t.Errorf("retained package %s or its indexes changed incorrectly", item.file)
			}
		} else if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) || bytes.Contains(primary, []byte(`href="`+item.file+`"`)) || bytes.Contains(marker, []byte("  "+item.file+"\n")) {
			t.Errorf("old package %s remains or is still indexed: %v", item.file, err)
		}
	}
	if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), filepath.Join(dir, "repodata"), yumrepo.CompressionGzip); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(nested, "hidden.rpm")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, pruneMarkerName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending completion marker remains: %v", err)
	}
	again, err := Prune(context.Background(), opts)
	if err != nil || !again.Noop || len(again.Removed) != 0 {
		t.Fatalf("repeat prune=%+v err=%v", again, err)
	}
}

func TestPruneWithoutCompletionMarker(t *testing.T) {
	dir := pruneFixture(t, false)
	result, err := Prune(context.Background(), PruneOptions{Dir: dir})
	if err != nil || len(result.Removed) != 2 || !result.IndexUpdated || result.Marker {
		t.Fatalf("Prune=%+v err=%v", result, err)
	}
	for _, name := range []string{"old1.rpm", "old2.rpm", "repo_complete", pruneMarkerName} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected file %s: %v", name, err)
		}
	}
	primary := readPrimaryXML(t, filepath.Join(dir, "repodata"))
	if bytes.Contains(primary, []byte(`href="old`)) || !bytes.Contains(primary, []byte(`href="new.rpm"`)) {
		t.Fatalf("incorrect pruned index: %s", primary)
	}
}

func TestPruneDryRunNeverWrites(t *testing.T) {
	for _, indexed := range []bool{false, true} {
		t.Run(fmt.Sprint(indexed), func(t *testing.T) {
			dir := pruneFixture(t, indexed)
			stage := mustMkdir(t, filepath.Join(dir, ".sow-plain-stage-preserved"))
			if err := os.WriteFile(filepath.Join(stage, "evidence"), []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
			before := pruneTreeSnapshot(t, dir)
			result, err := Prune(context.Background(), PruneOptions{Dir: dir, DryRun: true})
			if err != nil || !result.DryRun || len(result.Candidates) != 2 || len(result.Removed) != 0 || result.IndexUpdated {
				t.Fatalf("preview=%+v err=%v", result, err)
			}
			if after := pruneTreeSnapshot(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("dry run changed directory:\nbefore=%v\nafter=%v", before, after)
			}
		})
	}
}

func TestPruneRejectsInvalidInputsBeforeChanges(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"damaged replacement", func(t *testing.T, dir string) {
			path := filepath.Join(dir, "new.rpm")
			data := mustRead(t, path)
			data[len(data)-1] ^= 0xff
			mustWritePruneFile(t, path, data)
		}},
		{"unparseable RPM", func(t *testing.T, dir string) { mustWritePruneFile(t, filepath.Join(dir, "bad.rpm"), []byte("broken")) }},
		{"duplicate bytes", func(t *testing.T, dir string) {
			mustWritePruneFile(t, filepath.Join(dir, "alias.rpm"), mustRead(t, filepath.Join(dir, "new.rpm")))
		}},
		{"equal EVR", func(t *testing.T, dir string) {
			writePruneRPM(t, filepath.Join(dir, "equal-a.rpm"), rpmFixture{Name: "equal", Version: "1.0", Release: "1", Arch: "x86_64"})
			writePruneRPM(t, filepath.Join(dir, "equal-b.rpm"), rpmFixture{Name: "equal", Version: "1+0", Release: "1", Arch: "x86_64"})
		}},
		{"DEB", func(t *testing.T, dir string) { mustWritePruneFile(t, filepath.Join(dir, "other.deb"), []byte("deb")) }},
		{"RPM symlink", func(t *testing.T, dir string) {
			if err := os.Symlink("new.rpm", filepath.Join(dir, "link.rpm")); err != nil {
				t.Fatal(err)
			}
		}},
		{"source RPM", func(t *testing.T, dir string) {
			writePruneRPM(t, filepath.Join(dir, "source.rpm"), rpmFixture{Name: "source", Version: "1", Release: "1", Arch: "src"})
		}},
		{"signed metadata", func(t *testing.T, dir string) {
			mustWritePruneFile(t, filepath.Join(dir, "repodata", "repomd.xml.asc"), []byte("signature"))
		}},
		{"group metadata", addRepomdGroupData},
		{"module metadata", addRepomdModulesData},
		{"managed state", func(t *testing.T, dir string) { mustMkdir(t, filepath.Join(dir, ".sow")) }},
		{"marker symlink", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "repo_complete")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("new.rpm", filepath.Join(dir, "repo_complete")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := pruneFixture(t, true)
			tt.mutate(t, dir)
			before := pruneTreeSnapshot(t, dir)
			for _, dry := range []bool{true, false} {
				if result, err := Prune(context.Background(), PruneOptions{Dir: dir, DryRun: dry}); err == nil || len(result.Removed) != 0 || result.IndexUpdated {
					t.Fatalf("unsafe prune accepted: result=%+v err=%v", result, err)
				}
				if after := pruneTreeSnapshot(t, dir); !reflect.DeepEqual(before, after) {
					t.Fatalf("rejected prune changed directory")
				}
			}
		})
	}
}

func TestPruneRejectsManagedAncestorThroughAlias(t *testing.T) {
	workspace := t.TempDir()
	mustMkdir(t, filepath.Join(workspace, ".sow"))
	pool := mustMkdir(t, filepath.Join(workspace, "pool"))
	leaf := mustMkdir(t, filepath.Join(pool, "pkg"))
	writePruneRPM(t, filepath.Join(leaf, "pkg.rpm"), rpmFixture{Name: "pkg", Version: "1", Release: "1", Arch: "x86_64"})
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(pool, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Prune(context.Background(), PruneOptions{Dir: filepath.Join(alias, "pkg")}); KindOf(err) != KindRejected {
		t.Fatalf("managed pool alias error=%v", err)
	}
}

func TestPruneInterruptedPublicationAndRemovalConverge(t *testing.T) {
	for _, point := range []FaultPoint{FaultBeforeRPMPointer, FaultAfterRPMPointer, FaultAfterPackageRename, FaultBeforeMarker, FaultAfterMarker} {
		t.Run(string(point), func(t *testing.T) {
			dir := pruneFixture(t, true)
			oldPointer := mustRead(t, filepath.Join(dir, "repodata", "repomd.xml"))
			latestSHA := fileSHA(filepath.Join(dir, "new.rpm"))
			injected := errors.New("interrupted prune")
			result, err := Prune(context.Background(), PruneOptions{Dir: dir, Fault: func(event Fault) error {
				if event.Point == point {
					return injected
				}
				return nil
			}})
			if !errors.Is(err, injected) {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if fileSHA(filepath.Join(dir, "new.rpm")) != latestSHA {
				t.Fatal("replacement changed")
			}
			if point == FaultBeforeRPMPointer {
				if result.IndexUpdated || len(result.Removed) != 0 || !bytes.Equal(oldPointer, mustRead(t, filepath.Join(dir, "repodata", "repomd.xml"))) {
					t.Fatalf("failed pre-publication prune changed repository: %+v", result)
				}
			} else {
				if !result.IndexUpdated {
					t.Fatalf("published result lost: %+v", result)
				}
				primary := readPrimaryXML(t, filepath.Join(dir, "repodata"))
				if bytes.Contains(primary, []byte(`href="old`)) {
					t.Fatal("new index still names removed candidates")
				}
			}
			if point == FaultAfterPackageRename && len(result.Removed) != 1 {
				t.Fatalf("partial deletion result=%+v", result)
			}
			if point != FaultAfterMarker {
				if _, err := os.Lstat(filepath.Join(dir, "repo_complete")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("incomplete prune left completion marker")
				}
			}
			if _, err := os.Stat(filepath.Join(dir, pruneMarkerName)); err != nil {
				t.Fatal("interrupted prune lost marker intent")
			}
			if _, err := Prune(context.Background(), PruneOptions{Dir: dir}); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"old1.rpm", "old2.rpm", pruneMarkerName} {
				if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("rerun left %s: %v", name, err)
				}
			}
			if !bytes.Contains(mustRead(t, filepath.Join(dir, "repo_complete")), []byte(latestSHA+"  new.rpm\n")) {
				t.Fatal("rerun did not restore completion marker")
			}
		})
	}
}

func TestPruneRejectsChangedInputsAndCancellationBeforeDeleting(t *testing.T) {
	for _, change := range []string{"new file", "new symlink", "replacement", "replacement after pointer", "cancel after pointer"} {
		t.Run(change, func(t *testing.T) {
			dir := pruneFixture(t, true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result, err := Prune(ctx, PruneOptions{Dir: dir, Fault: func(event Fault) error {
				if event.Point == FaultBeforeStatValidation {
					switch change {
					case "new file":
						writePruneRPM(t, filepath.Join(dir, "extra.rpm"), rpmFixture{Name: "extra", Version: "1", Release: "1", Arch: "x86_64"})
					case "new symlink":
						return os.Symlink("new.rpm", filepath.Join(dir, "extra.rpm"))
					case "replacement":
						writePruneRPM(t, filepath.Join(dir, "new.rpm"), rpmFixture{Name: "pkg", Version: "4", Release: "1", Arch: "x86_64"})
					}
				}
				if change == "cancel after pointer" && event.Point == FaultAfterRPMPointer {
					cancel()
				}
				if change == "replacement after pointer" && event.Point == FaultAfterRPMPointer {
					writePruneRPM(t, filepath.Join(dir, "new.rpm"), rpmFixture{Name: "pkg", Version: "4", Release: "1", Arch: "x86_64"})
				}
				return nil
			}})
			if err == nil || len(result.Removed) != 0 {
				t.Fatalf("changed prune=%+v err=%v", result, err)
			}
			for _, name := range []string{"old1.rpm", "old2.rpm"} {
				if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			if change == "cancel after pointer" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
}

// A same-size in-place rewrite that restores mtime passes stat checks. Prune
// must still refuse to delete old versions, and must not report success when
// the rewrite happens while old versions are being removed.
func TestPruneDetectsInPlaceReplacementRewrite(t *testing.T) {
	rewrite := func(t *testing.T, path string) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data[len(data)-1] ^= 0xff
		if err := os.WriteFile(path, data, info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("before removal", func(t *testing.T) {
		dir := pruneFixture(t, true)
		result, err := Prune(context.Background(), PruneOptions{Dir: dir, Fault: func(event Fault) error {
			if event.Point == FaultAfterRPMPointer {
				rewrite(t, filepath.Join(dir, "new.rpm"))
			}
			return nil
		}})
		if KindOf(err) != KindIntegrity || len(result.Removed) != 0 {
			t.Fatalf("prune=%+v err=%v", result, err)
		}
		for _, name := range []string{"old1.rpm", "old2.rpm"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("during removal", func(t *testing.T) {
		dir := pruneFixture(t, true)
		result, err := Prune(context.Background(), PruneOptions{Dir: dir, Fault: func(event Fault) error {
			if event.Point == FaultAfterPackageRename && event.Sequence == 0 {
				rewrite(t, filepath.Join(dir, "new.rpm"))
			}
			return nil
		}})
		if KindOf(err) != KindIntegrity || len(result.Removed) != 1 || result.Noop {
			t.Fatalf("prune=%+v err=%v", result, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "old2.rpm")); err != nil {
			t.Fatalf("last old package was not preserved: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "repo_complete")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("completion marker restored: %v", err)
		}
	})
	t.Run("before marker", func(t *testing.T) {
		dir := pruneFixture(t, true)
		result, err := Prune(context.Background(), PruneOptions{Dir: dir, Fault: func(event Fault) error {
			if event.Point == FaultBeforeMarker {
				rewrite(t, filepath.Join(dir, "new.rpm"))
			}
			return nil
		}})
		if KindOf(err) != KindIntegrity || len(result.Removed) != 2 {
			t.Fatalf("prune=%+v err=%v", result, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "repo_complete")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("completion marker restored: %v", err)
		}
	})
}

func TestPruneRejectsProtectionThatMatchesNoPackage(t *testing.T) {
	dir := pruneFixture(t, true)
	before := pruneTreeSnapshot(t, dir)
	for _, dry := range []bool{true, false} {
		result, err := Prune(context.Background(), PruneOptions{Dir: dir, DryRun: dry, Protect: []string{"pkg", "pgk"}})
		if KindOf(err) != KindUsage || !strings.Contains(err.Error(), "pgk") || len(result.Removed) != 0 {
			t.Fatalf("misspelled protection dry=%t result=%+v err=%v", dry, result, err)
		}
	}
	if after := pruneTreeSnapshot(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("rejected protection changed directory")
	}
}

func TestPruneKeepsExplicitMetadataTimestamp(t *testing.T) {
	dir := pruneFixture(t, false)
	const timestamp = 1790049000
	if _, err := Create(context.Background(), Options{Dir: dir, MetadataTimestamp: timestamp}); err != nil {
		t.Fatal(err)
	}
	if _, err := Prune(context.Background(), PruneOptions{Dir: dir, MetadataTimestamp: timestamp}); err != nil {
		t.Fatal(err)
	}
	repomd := mustRead(t, filepath.Join(dir, "repodata", "repomd.xml"))
	if !bytes.Contains(repomd, []byte("<timestamp>1790049000</timestamp>")) || bytes.Contains(repomd, []byte("<timestamp>0</timestamp>")) {
		t.Fatalf("prune changed metadata timestamps: %s", repomd)
	}
}

// addRepomdGroupData models an index produced by createrepo_c -g comps.xml.
func addRepomdGroupData(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "repodata", "repomd.xml")
	data := mustRead(t, path)
	group := []byte(`<data type="group"><location href="repodata/comps.xml"/></data></repomd>`)
	if !bytes.Contains(data, []byte("</repomd>")) {
		t.Fatalf("repomd.xml has no closing element: %s", data)
	}
	mustWritePruneFile(t, path, bytes.Replace(data, []byte("</repomd>"), group, 1))
	mustWritePruneFile(t, filepath.Join(dir, "repodata", "comps.xml"), []byte("<comps/>\n"))
}

// addRepomdModulesData models an EL8/9 repository built by Pigsty v4.4 or
// earlier with repo2module and modifyrepo_c --mdtype=modules.
func addRepomdModulesData(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "repodata", "repomd.xml")
	data := mustRead(t, path)
	modules := []byte(`<data type="modules"><location href="repodata/legacy-modules.yaml.gz"/></data></repomd>`)
	mustWritePruneFile(t, path, bytes.Replace(data, []byte("</repomd>"), modules, 1))
	mustWritePruneFile(t, filepath.Join(dir, "repodata", "legacy-modules.yaml.gz"), []byte("modules"))
}

// Create keeps replacing a foreign repomd.xml, as createrepo_c does, so that
// existing Pigsty repositories with legacy module metadata still rebuild. It
// reports the data types the rebuilt index no longer carries.
func TestCreateReplacesForeignIndexAndReportsDroppedMetadata(t *testing.T) {
	for name, test := range map[string]struct {
		add  func(*testing.T, string)
		want []string
	}{
		"Pigsty legacy modules": {addRepomdModulesData, []string{"modules"}},
		"groups and modules": {func(t *testing.T, dir string) {
			addRepomdGroupData(t, dir)
			addRepomdModulesData(t, dir)
		}, []string{"group", "modules"}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := pruneFixture(t, true)
			test.add(t, dir)
			result, err := Create(context.Background(), Options{Dir: dir, Pigsty: true})
			if err != nil || result.Noop || !reflect.DeepEqual(result.DroppedMetadata, test.want) {
				t.Fatalf("create over foreign index=%+v err=%v", result, err)
			}
			repomd := mustRead(t, filepath.Join(dir, "repodata", "repomd.xml"))
			if bytes.Contains(repomd, []byte(`type="modules"`)) || bytes.Contains(repomd, []byte(`type="group"`)) {
				t.Fatalf("rebuilt index kept foreign data: %s", repomd)
			}
			again, err := Create(context.Background(), Options{Dir: dir, Pigsty: true})
			if err != nil || !again.Noop || len(again.DroppedMetadata) != 0 {
				t.Fatalf("repeat create=%+v err=%v", again, err)
			}
		})
	}
}

func TestPlainRejectsOversizedPriorIndex(t *testing.T) {
	oversized := func(t *testing.T) string {
		t.Helper()
		dir := pruneFixture(t, true)
		path := filepath.Join(dir, "repodata", "repomd.xml")
		body := `<repomd><!--` + strings.Repeat("x", maxPriorRepomdBytes) + `--><data type="group"/></repomd>`
		mustWritePruneFile(t, path, []byte(body))
		return dir
	}
	for _, dry := range []bool{false, true} {
		t.Run(fmt.Sprintf("prune dry=%t", dry), func(t *testing.T) {
			dir := oversized(t)
			before := pruneTreeSnapshot(t, dir)
			if _, err := Prune(context.Background(), PruneOptions{Dir: dir, DryRun: dry}); KindOf(err) != KindRejected {
				t.Fatalf("oversized index accepted: %v", err)
			}
			if !reflect.DeepEqual(before, pruneTreeSnapshot(t, dir)) {
				t.Fatal("rejected command changed repository")
			}
		})
	}
	// Create cannot list the types of an index it cannot inspect, but keeps
	// its established behavior of replacing the old index.
	t.Run("create", func(t *testing.T) {
		dir := oversized(t)
		result, err := Create(context.Background(), Options{Dir: dir, Pigsty: true})
		if err != nil || len(result.DroppedMetadata) != 0 {
			t.Fatalf("create over oversized index=%+v err=%v", result, err)
		}
		if info, err := os.Stat(filepath.Join(dir, "repodata", "repomd.xml")); err != nil || info.Size() > maxPriorRepomdBytes {
			t.Fatalf("oversized index was not replaced: info=%v err=%v", info, err)
		}
	})
}

func TestPruneAndCreateRejectRPMv6AcrossAllRoles(t *testing.T) {
	v6Tags := []rpmTag{rpmStringTag(5092, strings.Repeat("a", 64))}
	for _, tc := range []struct {
		name    string
		protect []string
		setup   func(*testing.T, string)
	}{
		{
			name: "single-version",
			setup: func(t *testing.T, dir string) {
				writePruneRPM(t, filepath.Join(dir, "only.rpm"), rpmFixture{Name: "pkg", Version: "1", Release: "1", Arch: "x86_64", ExtraTags: v6Tags})
			},
		},
		{
			name:    "protected",
			protect: []string{"protected-pkg"},
			setup: func(t *testing.T, dir string) {
				writePruneRPM(t, filepath.Join(dir, "protected.rpm"), rpmFixture{Name: "protected-pkg", Version: "1", Release: "1", Arch: "x86_64", ExtraTags: v6Tags})
				writePruneRPM(t, filepath.Join(dir, "old.rpm"), rpmFixture{Name: "pkg", Version: "1", Release: "1", Arch: "x86_64"})
				writePruneRPM(t, filepath.Join(dir, "new.rpm"), rpmFixture{Name: "pkg", Version: "2", Release: "1", Arch: "x86_64"})
			},
		},
		{
			name: "superseded",
			setup: func(t *testing.T, dir string) {
				writePruneRPM(t, filepath.Join(dir, "old-v6.rpm"), rpmFixture{Name: "pkg", Version: "1", Release: "1", Arch: "x86_64", ExtraTags: v6Tags})
				writePruneRPM(t, filepath.Join(dir, "new.rpm"), rpmFixture{Name: "pkg", Version: "2", Release: "1", Arch: "x86_64"})
			},
		},
		{
			name: "latest-replacement",
			setup: func(t *testing.T, dir string) {
				writePruneRPM(t, filepath.Join(dir, "old.rpm"), rpmFixture{Name: "pkg", Version: "1", Release: "1", Arch: "x86_64"})
				writePruneRPM(t, filepath.Join(dir, "new-v6.rpm"), rpmFixture{Name: "pkg", Version: "2", Release: "1", Arch: "x86_64", ExtraTags: v6Tags})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			before := pruneTreeSnapshot(t, dir)
			for _, dry := range []bool{true, false} {
				if result, err := Prune(context.Background(), PruneOptions{Dir: dir, DryRun: dry, Protect: tc.protect}); err == nil || !strings.Contains(err.Error(), "RPM v6") || len(result.Removed) != 0 || result.IndexUpdated {
					t.Fatalf("Prune dry=%t accepted RPM v6 (%s): result=%+v err=%v", dry, tc.name, result, err)
				}
			}
			if _, err := Create(context.Background(), Options{Dir: dir}); err == nil || !strings.Contains(err.Error(), "RPM v6") {
				t.Fatalf("Create accepted RPM v6 (%s): %v", tc.name, err)
			}
			if !reflect.DeepEqual(before, pruneTreeSnapshot(t, dir)) {
				t.Fatalf("rejected RPM v6 (%s) mutated directory", tc.name)
			}
		})
	}
}

func pruneFixture(t *testing.T, indexed bool) string {
	t.Helper()
	dir := t.TempDir()
	for i, name := range []string{"old1.rpm", "old2.rpm", "new.rpm"} {
		writePruneRPM(t, filepath.Join(dir, name), rpmFixture{Name: "pkg", Version: fmt.Sprint(i + 1), Release: "1", Arch: "x86_64"})
	}
	if indexed {
		if _, err := Create(context.Background(), Options{Dir: dir, Pigsty: true}); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func writePruneRPM(t *testing.T, path string, pkg rpmFixture) {
	t.Helper()
	pkg.Payload = "payload for " + pkg.Name + " " + pkg.Version + " " + pkg.Release
	writeRPMFixture(t, path, pkg)
	data := mustRead(t, path)
	main := data[112:] // writeRPMFixture emits a 96-byte lead and empty signature header.
	digest := md5.Sum(main)
	signature := make([]byte, 16+2*16+4+md5.Size)
	copy(signature, []byte{0x8e, 0xad, 0xe8, 1})
	binary.BigEndian.PutUint32(signature[8:], 2)
	binary.BigEndian.PutUint32(signature[12:], 4+md5.Size)
	for i, tag := range []struct{ id, typ, offset, count uint32 }{{1000, 4, 0, 1}, {1004, 7, 4, md5.Size}} {
		start := 16 + i*16
		binary.BigEndian.PutUint32(signature[start:], tag.id)
		binary.BigEndian.PutUint32(signature[start+4:], tag.typ)
		binary.BigEndian.PutUint32(signature[start+8:], tag.offset)
		binary.BigEndian.PutUint32(signature[start+12:], tag.count)
	}
	binary.BigEndian.PutUint32(signature[48:], uint32(len(main)))
	copy(signature[52:], digest[:])
	for len(signature)%8 != 0 {
		signature = append(signature, 0)
	}
	mustWritePruneFile(t, path, bytes.Join([][]byte{data[:96], signature, main}, nil))
}

func mustWritePruneFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func pruneTreeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := map[string]string{}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		identity := fmt.Sprintf("%v %d %d", info.Mode(), info.Size(), info.ModTime().UnixNano())
		if info.Mode().IsRegular() {
			identity += " " + fileSHA(path)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			identity += " " + target
		}
		snapshot[strings.TrimPrefix(path, root)] = identity
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot
}
