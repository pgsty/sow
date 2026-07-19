package cli

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"testing"
)

// Go's standard library intentionally exposes only a bzip2 reader. Keep one
// tiny, fixed bzip2 stream in the test corpus so the frozen sqlite input
// contract is exercised without adding a runtime or test dependency.
const legacyYUMCompatibilitySQLiteBZ2 = "QlpoOTFBWSZTWWmvfXUAAAURgEAAKqXuICAAIo2ptQw1CmAABSLjrljUTJFstpR8XckU4UJBpr311A=="

func legacyYUMCompatibilityFixtureArtifact(t *testing.T, index int, kind string) (filename string, compressed, open []byte) {
	t.Helper()
	switch kind {
	case "primary", "filelists", "other":
		filename = fmt.Sprintf("%02d-%s.xml.gz", index, kind)
		open = []byte(fmt.Sprintf("<metadata kind=%q/>", kind))
	case "modules":
		filename = fmt.Sprintf("%02d-modules.yaml.gz", index)
		open = []byte("document: modulemd\nversion: 2\n")
	case "primary_db", "filelists_db", "other_db":
		filename = fmt.Sprintf("%02d-%s.sqlite.bz2", index, kind)
		open = []byte("legacy sqlite input only")
		var err error
		compressed, err = base64.StdEncoding.DecodeString(legacyYUMCompatibilitySQLiteBZ2)
		if err != nil {
			t.Fatal(err)
		}
		return filename, compressed, open
	default:
		t.Fatalf("unsupported legacy fixture record %q", kind)
	}
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(open); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return filename, buffer.Bytes(), open
}
