package manifest

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func testEntry(path string, body string) Entry {
	return Entry{Path: path, Size: int64(len(body)), SHA256: sha256.Sum256([]byte(body))}
}

func TestReaderRequiresStrictSortedCanonicalTSV(t *testing.T) {
	var content bytes.Buffer
	if err := WriteEntry(&content, testEntry("a/file", "a")); err != nil {
		t.Fatal(err)
	}
	if err := WriteEntry(&content, testEntry("b/file", "b")); err != nil {
		t.Fatal(err)
	}
	reader := NewReader(&content)
	if _, err := reader.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Next(); err != nil {
		t.Fatal(err)
	}

	bad := manifestText(t, testEntry("b/file", "b"), testEntry("a/file", "a"))
	reader = NewReader(strings.NewReader(bad))
	_, _ = reader.Next()
	if _, err := reader.Next(); err == nil || !strings.Contains(err.Error(), "strictly sorted") {
		t.Fatalf("wanted sorted error, got %v", err)
	}
	if err := testEntry("../escape", "x").Validate(); err == nil {
		t.Fatal("unsafe path accepted")
	}
}

func TestDiff(t *testing.T) {
	old := manifestText(t, testEntry("a", "old"), testEntry("b", "same"), testEntry("d", "gone"))
	newer := manifestText(t, testEntry("a", "new"), testEntry("b", "same"), testEntry("c", "added"))
	var changes []Change
	stats, err := Diff(strings.NewReader(old), strings.NewReader(newer), func(change Change) error {
		changes = append(changes, change)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Added != 1 || stats.Removed != 1 || stats.Changed != 1 || len(changes) != 3 {
		t.Fatalf("unexpected diff: %#v %#v", stats, changes)
	}
}

func manifestText(t *testing.T, entries ...Entry) string {
	t.Helper()
	var result bytes.Buffer
	for _, entry := range entries {
		if err := WriteEntry(&result, entry); err != nil {
			t.Fatal(err)
		}
	}
	return result.String()
}
