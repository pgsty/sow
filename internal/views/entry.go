package views

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var snapshotPattern = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9+._-]*)-([0-9]{8})$`)

type Entry struct {
	Repo      string
	OS        string
	Arch      string
	Name      string
	Version   string
	Path      string
	Size      int64
	SHA256    string
	Pool      string
	DebugInfo bool
}

func (e Entry) Key() string {
	// A leaf ref already fixes repo/OS/arch. The physical path is therefore the
	// canonical identity and sort key: it makes each view directly projectable
	// into the three-field repository manifest without an in-memory re-sort.
	return e.Path
}

func (e Entry) Validate() error {
	for field, value := range map[string]string{
		"repo": e.Repo, "os": e.OS, "arch": e.Arch, "name": e.Name, "version": e.Version,
	} {
		if value == "" || strings.ContainsAny(value, "\x00\t\r\n") {
			return fmt.Errorf("view %s is empty or unsafe", field)
		}
	}
	if e.Path == "" || strings.HasPrefix(e.Path, "/") || strings.ContainsAny(e.Path, "%?#\x00\\\t\r\n") || path.Clean(e.Path) != e.Path || e.Path == ".." || strings.HasPrefix(e.Path, "../") {
		return fmt.Errorf("unsafe view path %q", e.Path)
	}
	for _, segment := range strings.Split(e.Path, "/") {
		if segment == ".sow" || segment == ".pool" || segment == ".git" {
			return fmt.Errorf("view path %q crosses a reserved shadow point", e.Path)
		}
	}
	if e.Size < 0 {
		return errors.New("view size cannot be negative")
	}
	digest, err := hex.DecodeString(e.SHA256)
	if err != nil || len(digest) != sha256.Size || strings.ToLower(e.SHA256) != e.SHA256 {
		return errors.New("view sha256 must be lowercase hex")
	}
	if e.Pool != "public" && e.Pool != "gated" {
		return errors.New("view pool must be public or gated")
	}
	return nil
}

func WriteEntry(w io.Writer, entry Entry) error {
	if err := entry.Validate(); err != nil {
		return err
	}
	debug := "0"
	if entry.DebugInfo {
		debug = "1"
	}
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
		entry.Repo, entry.OS, entry.Arch, entry.Name, entry.Version, entry.Path,
		entry.Size, entry.SHA256, entry.Pool, debug)
	return err
}

type Reader struct {
	scanner *bufio.Scanner
	line    int
	lastKey string
}

func NewReader(r io.Reader) *Reader {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	return &Reader{scanner: scanner}
}

func (r *Reader) Next() (Entry, error) {
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return Entry{}, err
		}
		return Entry{}, io.EOF
	}
	r.line++
	fields := strings.Split(r.scanner.Text(), "\t")
	if len(fields) != 10 {
		return Entry{}, fmt.Errorf("view line %d: want 10 fields", r.line)
	}
	size, err := strconv.ParseInt(fields[6], 10, 64)
	if err != nil {
		return Entry{}, fmt.Errorf("view line %d: invalid size", r.line)
	}
	if fields[9] != "0" && fields[9] != "1" {
		return Entry{}, fmt.Errorf("view line %d: debuginfo must be 0 or 1", r.line)
	}
	entry := Entry{Repo: fields[0], OS: fields[1], Arch: fields[2], Name: fields[3], Version: fields[4], Path: fields[5], Size: size, SHA256: fields[7], Pool: fields[8], DebugInfo: fields[9] == "1"}
	if err := entry.Validate(); err != nil {
		return Entry{}, fmt.Errorf("view line %d: %w", r.line, err)
	}
	key := entry.Key()
	if r.lastKey != "" && key <= r.lastKey {
		return Entry{}, fmt.Errorf("view line %d: entries are not strictly sorted", r.line)
	}
	r.lastKey = key
	return entry, nil
}

type Selector struct {
	Repos  []string
	OSes   []string
	Arches []string
	Names  []string
}

func (s Selector) Match(entry Entry) bool {
	return selected(entry.Repo, s.Repos) && selected(entry.OS, s.OSes) && selected(entry.Arch, s.Arches) && selected(entry.Name, s.Names)
}

func selected(value string, choices []string) bool {
	if len(choices) == 0 {
		return true
	}
	for _, choice := range choices {
		if choice == value {
			return true
		}
	}
	return false
}

func SnapshotID(suite string, commitTime time.Time) (string, error) {
	if suite == "" || strings.ContainsAny(suite, "\x00/\\\t\r\n") || suite == "." || suite == ".." || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*$`).MatchString(suite) {
		return "", fmt.Errorf("unsafe snapshot suite %q", suite)
	}
	return suite + "-" + commitTime.UTC().Format("20060102"), nil
}

func ValidateSnapshotID(value string) error {
	match := snapshotPattern.FindStringSubmatch(value)
	if match == nil {
		return fmt.Errorf("snapshot ID %q must be <suite>-YYYYMMDD", value)
	}
	if _, err := time.Parse("20060102", match[2]); err != nil {
		return fmt.Errorf("snapshot ID %q has an invalid UTC date", value)
	}
	return nil
}

func SnapshotSuite(value string) (string, error) {
	match := snapshotPattern.FindStringSubmatch(value)
	if match == nil {
		return "", fmt.Errorf("snapshot ID %q must be <suite>-YYYYMMDD", value)
	}
	if err := ValidateSnapshotID(value); err != nil {
		return "", err
	}
	return match[1], nil
}
