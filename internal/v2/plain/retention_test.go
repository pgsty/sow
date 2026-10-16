package plain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/yumrepo"
)

type rpmReaderView struct {
	pointer []byte
	files   map[string]string
}

func TestCreateRPMRetainsPreviousMetadata(t *testing.T) {
	dir := t.TempDir()
	writeRPMFixture(t, filepath.Join(dir, "one.rpm"), rpmFixture{Name: "one", Version: "1", Release: "1", Arch: "x86_64", Payload: "first"})
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	old := readRPMReaderView(t, dir)
	writeRPMFixture(t, filepath.Join(dir, "two.rpm"), rpmFixture{Name: "two", Version: "1", Release: "1", Arch: "x86_64", Payload: "second"})
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	assertRPMReaderView(t, dir, old)
	assertRPMReaderView(t, dir, readRPMReaderView(t, dir))
}

func TestCreateRPMRetentionWindowAndNoop(t *testing.T) {
	dir := t.TempDir()
	var previous rpmReaderView
	for version := 1; version <= 6; version++ {
		current := createRPMVersion(t, dir, version)
		views := []rpmReaderView{current}
		if version > 1 {
			views = append(views, previous)
		}
		assertRPMMetadataWindow(t, dir, views...)
		assertRPMHistoryBounded(t, dir)
		assertRPMStableNoop(t, dir)
		assertRPMMetadataWindow(t, dir, views...)
		previous = current
	}
}

func TestCreateRPMRetentionAcrossInterruptedPublication(t *testing.T) {
	for _, point := range []FaultPoint{FaultBeforeRPMIndex, FaultAfterRPMIndex, FaultBeforeRPMPointer, FaultAfterRPMPointer} {
		sequences := []int{-1}
		if point == FaultBeforeRPMIndex || point == FaultAfterRPMIndex {
			sequences = []int{0, 1, 2}
		}
		for _, sequence := range sequences {
			t.Run(fmt.Sprintf("%s/%d", point, sequence), func(t *testing.T) {
				dir := t.TempDir()
				previous := createRPMVersion(t, dir, 1)
				current := createRPMVersion(t, dir, 2)
				writeRPMVersion(t, dir, 3)
				want := errors.New("interrupt publication")
				var candidate rpmReaderView
				_, err := Create(context.Background(), Options{Dir: dir, Fault: func(event Fault) error {
					if event.Point != point || event.Sequence != sequence {
						return nil
					}
					// Until the pointer moves, both existing reader generations
					// remain complete even while new indexes are installed.
					assertRPMReaderView(t, dir, previous)
					assertRPMReaderView(t, dir, current)
					if point == FaultBeforeRPMPointer {
						stages, err := filepath.Glob(filepath.Join(dir, ".sow-plain-stage-*"))
						if err != nil || len(stages) != 1 {
							t.Fatalf("staged candidate: %v %v", stages, err)
						}
						candidate = readRPMReaderView(t, stages[0])
						assertRPMReaderView(t, dir, candidate)
					}
					if point == FaultAfterRPMPointer {
						candidate = readRPMReaderView(t, dir)
						if bytes.Equal(candidate.pointer, current.pointer) {
							t.Fatal("new pointer was not published")
						}
						assertRPMReaderView(t, dir, candidate)
					} else if !bytes.Equal(readRPMReaderView(t, dir).pointer, current.pointer) {
						t.Fatal("pointer moved before all new indexes were ready")
					}
					return want
				}})
				if !errors.Is(err, want) {
					t.Fatalf("faulted create: %v", err)
				}
				assertRPMHistoryBounded(t, dir)
				if _, err := os.Lstat(filepath.Join(dir, legacyPlainJournal)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("retention created a publication journal: %v", err)
				}
				if result, err := Create(context.Background(), Options{Dir: dir}); err != nil || result.Recovered {
					t.Fatalf("rebuild result=%+v err=%v", result, err)
				}
				next := readRPMReaderView(t, dir)
				if candidate.pointer != nil && !bytes.Equal(next.pointer, candidate.pointer) {
					t.Fatal("rerun changed the interrupted candidate")
				}
				assertRPMMetadataWindow(t, dir, next, current)
				assertRPMStableNoop(t, dir)
			})
		}
	}
}

func TestCreateRPMUnpublishedCandidateDoesNotAdvanceRetention(t *testing.T) {
	dir := t.TempDir()
	previous := createRPMVersion(t, dir, 1)
	current := createRPMVersion(t, dir, 2)
	writeRPMVersion(t, dir, 3)
	want := errors.New("stop before pointer")
	_, err := Create(context.Background(), Options{Dir: dir, Fault: func(event Fault) error {
		if event.Point == FaultBeforeRPMPointer {
			return want
		}
		return nil
	}})
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
	// Returning to the current input must not confuse the unpublished candidate
	// with the real predecessor, even though its retention list was installed.
	writeRPMVersion(t, dir, 2)
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readRPMReaderView(t, dir).pointer, current.pointer) {
		t.Fatal("returning to current input changed the pointer")
	}
	assertRPMMetadataWindow(t, dir, current, previous)
	assertRPMStableNoop(t, dir)
}

func TestCreateRPMRetentionCleanupAfterRepeatedInterruptions(t *testing.T) {
	dir := t.TempDir()
	previous := createRPMVersion(t, dir, 1)
	current := createRPMVersion(t, dir, 2)
	for version := 3; version <= 10; version++ {
		writeRPMVersion(t, dir, version)
		point := FaultBeforeRPMPointer
		if version%2 == 0 {
			point = FaultAfterRPMPointer
		}
		want := errors.New("repeated interruption")
		_, err := Create(context.Background(), Options{Dir: dir, Fault: func(event Fault) error {
			if event.Point == point {
				return want
			}
			return nil
		}})
		if !errors.Is(err, want) {
			t.Fatalf("version %d: %v", version, err)
		}
		if point == FaultAfterRPMPointer {
			previous, current = current, readRPMReaderView(t, dir)
		}
		assertRPMReaderView(t, dir, previous)
		assertRPMReaderView(t, dir, current)
		assertRPMHistoryBounded(t, dir)
	}
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	assertRPMMetadataWindow(t, dir, current, previous)
	assertRPMStableNoop(t, dir)
}

func TestCreateRPMRetentionRepairsDamagedHistory(t *testing.T) {
	for _, damage := range []string{"previous-index", "current-index", "repomd", "missing-repomd", "missing-history", "malformed-history", "oversize-history", "unknown-field", "unsafe-reference", "too-many-snapshots"} {
		t.Run(damage, func(t *testing.T) {
			dir := t.TempDir()
			previous := createRPMVersion(t, dir, 1)
			current := createRPMVersion(t, dir, 2)
			historyPath := filepath.Join(dir, rpmHistoryName)
			write := func(path string, body []byte) {
				t.Helper()
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			remove := func(path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			wantViews := []rpmReaderView{current}
			switch damage {
			case "previous-index":
				for href := range previous.files {
					write(filepath.Join(dir, href), []byte("damaged historical bytes"))
					delete(previous.files, href)
					break
				}
				wantViews = append(wantViews, previous)
			case "current-index":
				for href := range current.files {
					write(filepath.Join(dir, href), []byte("damaged current bytes"))
					break
				}
				wantViews = append(wantViews, previous)
			case "repomd":
				write(filepath.Join(dir, "repodata", "repomd.xml"), []byte("broken XML"))
			case "missing-repomd":
				remove(filepath.Join(dir, "repodata", "repomd.xml"))
			case "missing-history":
				remove(historyPath)
			case "malformed-history":
				write(historyPath, []byte("broken JSON"))
			case "oversize-history":
				write(historyPath, bytes.Repeat([]byte(" "), 4097))
			default:
				var history map[string]json.RawMessage
				if err := json.Unmarshal(mustRead(t, historyPath), &history); err != nil {
					t.Fatal(err)
				}
				var snapshots []map[string]any
				if err := json.Unmarshal(history["snapshots"], &snapshots); err != nil {
					t.Fatal(err)
				}
				switch damage {
				case "unknown-field":
					history["foreign"] = json.RawMessage(`true`)
				case "unsafe-reference":
					snapshots[0]["metadata"] = []string{"../../unowned", "bad", "names"}
				case "too-many-snapshots":
					snapshots = append(snapshots, snapshots...)
				}
				body, err := json.Marshal(snapshots)
				if err != nil {
					t.Fatal(err)
				}
				history["snapshots"] = body
				body, err = json.Marshal(history)
				if err != nil {
					t.Fatal(err)
				}
				write(historyPath, body)
			}
			if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
				t.Fatalf("repair %s: %v", damage, err)
			}
			assertRPMMetadataWindow(t, dir, wantViews...)
			assertRPMHistoryBounded(t, dir)
			assertRPMStableNoop(t, dir)
		})
	}
}

func TestCreateRPMMissingHistoryRetainsReplacedPointer(t *testing.T) {
	dir := t.TempDir()
	createRPMVersion(t, dir, 1)
	current := createRPMVersion(t, dir, 2)
	if err := os.Remove(filepath.Join(dir, rpmHistoryName)); err != nil {
		t.Fatal(err)
	}
	next := createRPMVersion(t, dir, 3)
	assertRPMMetadataWindow(t, dir, next, current)
	assertRPMStableNoop(t, dir)
}

func TestCreateRPMRetentionRejectsOwnedSymlinks(t *testing.T) {
	for _, target := range []string{"repodata", "repomd", "previous-index", "current-index", "history", "history-without-rpm"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			previous := createRPMVersion(t, dir, 1)
			current := createRPMVersion(t, dir, 2)
			path := filepath.Join(dir, rpmHistoryName)
			switch target {
			case "repodata":
				path = filepath.Join(dir, "repodata")
			case "repomd":
				path = filepath.Join(dir, "repodata", "repomd.xml")
			case "previous-index", "current-index":
				view := previous
				if target == "current-index" {
					view = current
				}
				for href := range view.files {
					path = filepath.Join(dir, href)
					break
				}
			}
			if err := os.Rename(path, path+".hold"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".hold", path); err != nil {
				t.Fatal(err)
			}
			if target == "history-without-rpm" {
				if err := os.Remove(filepath.Join(dir, "package.rpm")); err != nil {
					t.Fatal(err)
				}
				writeDEBFixture(t, dir, "remaining.deb", debControl("remaining", "1", "amd64"), "remaining")
			}
			if _, err := Create(context.Background(), Options{Dir: dir}); KindOf(err) != KindIntegrity {
				t.Fatalf("owned symlink %s accepted: %v", target, err)
			}
			if !bytes.Equal(readRPMReaderView(t, dir).pointer, current.pointer) {
				t.Fatal("rejected symlink changed the published pointer")
			}
			assertRPMReaderView(t, dir, current)
			assertRPMReaderView(t, dir, previous)
			if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("rejected symlink was changed: %v", err)
			}
		})
	}
}

func TestCreateRPMRetentionPreservesForeignFilesAndClearsWithoutRPM(t *testing.T) {
	dir := t.TempDir()
	createRPMVersion(t, dir, 1)
	repodata := filepath.Join(dir, "repodata")
	foreign := []string{"repomd.xml.asc", "primary.xml.gz", strings.Repeat("A", 64) + "-primary.xml.gz", strings.Repeat("a", 64) + "-other.xml.zst", "notes.txt"}
	for _, name := range foreign {
		if err := os.WriteFile(filepath.Join(repodata, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(repodata, "foreign-directory"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("notes.txt", filepath.Join(repodata, "foreign-link")); err != nil {
		t.Fatal(err)
	}
	obsolete := filepath.Join(repodata, strings.Repeat("f", 64)+"-other.xml.gz")
	if err := os.WriteFile(obsolete, []byte("corrupt unreferenced SOW index"), 0o644); err != nil {
		t.Fatal(err)
	}
	for version := 2; version <= 4; version++ {
		createRPMVersion(t, dir, version)
	}
	if _, err := os.Lstat(obsolete); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("obsolete SOW index retained: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "package.rpm")); err != nil {
		t.Fatal(err)
	}
	writeDEBFixture(t, dir, "remaining.deb", debControl("remaining", "1", "amd64"), "remaining")
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, rpmHistoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retention list remains without RPM inputs: %v", err)
	}
	entries, err := os.ReadDir(repodata)
	if err != nil || len(entries) != len(foreign)+2 {
		t.Fatalf("unexpected foreign directory contents: %v %v", entries, err)
	}
	for _, name := range foreign {
		if got := string(mustRead(t, filepath.Join(repodata, name))); got != name {
			t.Fatalf("foreign file changed: %s", name)
		}
	}
	if target, err := os.Readlink(filepath.Join(repodata, "foreign-link")); err != nil || target != "notes.txt" {
		t.Fatalf("foreign symlink changed: %q %v", target, err)
	}
	if result, err := Create(context.Background(), Options{Dir: dir}); err != nil || !result.Noop {
		t.Fatalf("empty repeat: %+v %v", result, err)
	}
}

func TestFlatRPMValidationRejectsInvalidRetainedEntries(t *testing.T) {
	for _, damage := range []string{"checksum", "symlink", "unsafe-name", "signature"} {
		t.Run(damage, func(t *testing.T) {
			dir := t.TempDir()
			previous := createRPMVersion(t, dir, 1)
			createRPMVersion(t, dir, 2)
			repodata := filepath.Join(dir, "repodata")
			if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), repodata, yumrepo.CompressionGzip); err != nil {
				t.Fatalf("valid retained entries rejected: %v", err)
			}
			var retained string
			for href := range previous.files {
				retained = filepath.Join(dir, href)
				break
			}
			switch damage {
			case "checksum":
				if err := os.WriteFile(retained, []byte("bad hash"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				outside := filepath.Join(t.TempDir(), "retained.xml.gz")
				if err := os.Rename(retained, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, retained); err != nil {
					t.Fatal(err)
				}
			case "unsafe-name", "signature":
				name := "primary.xml.gz"
				if damage == "signature" {
					name = "repomd.xml.asc"
				}
				if err := os.WriteFile(filepath.Join(repodata, name), []byte("unaccepted by unsigned validator"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), repodata, yumrepo.CompressionGzip); !errors.Is(err, yumrepo.ErrInvalidRepodata) {
				t.Fatalf("invalid retained entry accepted: %v", err)
			}
		})
	}
}

func writeRPMVersion(t *testing.T, dir string, version int) {
	t.Helper()
	writeRPMFixture(t, filepath.Join(dir, "package.rpm"), rpmFixture{Name: "package", Version: fmt.Sprint(version), Release: "1", Arch: "x86_64", Payload: fmt.Sprintf("payload version %d", version)})
}

func createRPMVersion(t *testing.T, dir string, version int) rpmReaderView {
	t.Helper()
	writeRPMVersion(t, dir, version)
	if _, err := Create(context.Background(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	return readRPMReaderView(t, dir)
}

func assertRPMMetadataWindow(t *testing.T, dir string, views ...rpmReaderView) {
	t.Helper()
	wanted := map[string]bool{"repomd.xml": true}
	for _, view := range views {
		assertRPMReaderView(t, dir, view)
		for href := range view.files {
			wanted[filepath.Base(href)] = true
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "repodata"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(wanted) {
		t.Fatalf("retention has %d files, want %d", len(entries), len(wanted))
	}
	for _, entry := range entries {
		if !wanted[entry.Name()] {
			t.Fatalf("unexpected retained file: %s", entry.Name())
		}
	}
	if _, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), filepath.Join(dir, "repodata"), yumrepo.CompressionGzip); err != nil {
		t.Fatalf("validate published directory: %v", err)
	}
}

func assertRPMHistoryBounded(t *testing.T, dir string) {
	t.Helper()
	body := mustRead(t, filepath.Join(dir, rpmHistoryName))
	var history struct {
		Version   int `json:"version"`
		Snapshots []struct {
			RepomdSHA256 string   `json:"repomd_sha256"`
			Metadata     []string `json:"metadata"`
		} `json:"snapshots"`
	}
	if err := json.Unmarshal(body, &history); err != nil || len(body) > 4096 || history.Version != 1 || len(history.Snapshots) < 1 || len(history.Snapshots) > 3 {
		t.Fatalf("unbounded or invalid retention list: %s (%v)", body, err)
	}
	for _, snapshot := range history.Snapshots {
		if len(snapshot.RepomdSHA256) != 64 || len(snapshot.Metadata) != 3 {
			t.Fatalf("invalid retention identity: %+v", snapshot)
		}
	}
}

func assertRPMStableNoop(t *testing.T, dir string) {
	t.Helper()
	paths := []string{filepath.Join(dir, rpmHistoryName), filepath.Join(dir, "repodata", "repomd.xml")}
	var before []os.FileInfo
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		before = append(before, info)
	}
	for range 2 {
		result, err := Create(context.Background(), Options{Dir: dir, Jobs: 4})
		if err != nil || !result.Noop || result.Recovered {
			t.Fatalf("stable repeat: %+v %v", result, err)
		}
		for i, path := range paths {
			after, err := os.Stat(path)
			if err != nil || !os.SameFile(before[i], after) || !before[i].ModTime().Equal(after.ModTime()) {
				t.Fatalf("Noop rewrote %s: %v", path, err)
			}
		}
	}
}

// A client saves repomd first and retrieves exactly those hrefs later. This
// intentionally does not ask the publisher which files it considers retained.
func readRPMReaderView(t *testing.T, dir string) rpmReaderView {
	t.Helper()
	body := mustRead(t, filepath.Join(dir, "repodata", "repomd.xml"))
	var document struct {
		Data []struct {
			Location struct {
				Href string `xml:"href,attr"`
			} `xml:"location"`
			Checksum struct {
				Type  string `xml:"type,attr"`
				Value string `xml:",chardata"`
			} `xml:"checksum"`
		} `xml:"data"`
	}
	if err := xml.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	view := rpmReaderView{pointer: body, files: make(map[string]string)}
	for _, record := range document.Data {
		if record.Checksum.Type != "sha256" {
			t.Fatalf("unexpected checksum type: %s", record.Checksum.Type)
		}
		view.files[record.Location.Href] = record.Checksum.Value
	}
	if len(view.files) != 3 {
		t.Fatalf("client received %d references, want 3", len(view.files))
	}
	return view
}

func assertRPMReaderView(t *testing.T, dir string, view rpmReaderView) {
	t.Helper()
	for href, want := range view.files {
		body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(href)))
		if err != nil {
			t.Fatalf("saved repomd reference %s: %v", href, err)
		}
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("saved repomd reference %s SHA256=%s, want %s", href, got, want)
		}
	}
}
