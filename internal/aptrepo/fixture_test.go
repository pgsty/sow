package aptrepo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeMinimalDeb(t *testing.T, dir, filename, controlText string) string {
	t.Helper()
	dataTar := tarGzip(t, map[string][]byte{"usr/share/doc/sow-fixture/README": []byte("fixture\n")})
	return writeDebWithDataMember(t, dir, filename, controlText, "data.tar.gz", dataTar)
}

func writeDebWithDataMember(t *testing.T, dir, filename, controlText, dataMemberName string, data []byte) string {
	t.Helper()
	controlTar := tarGzip(t, map[string][]byte{"control": []byte(controlText)})
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	writeArMember(t, &archive, "debian-binary", []byte("2.0\n"))
	writeArMember(t, &archive, "control.tar.gz", controlTar)
	writeArMember(t, &archive, dataMemberName, data)

	filePath := filepath.Join(dir, filename)
	if err := os.WriteFile(filePath, archive.Bytes(), 0o644); err != nil {
		t.Fatalf("write real deb fixture: %v", err)
	}
	return filePath
}

func tarGzip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("write tar body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return out.Bytes()
}

func writeArMember(t *testing.T, out *bytes.Buffer, name string, data []byte) {
	t.Helper()
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name+"/", 0, 0, 0, 0o644, len(data))
	if len(header) != 60 {
		t.Fatalf("invalid ar header length %d", len(header))
	}
	out.WriteString(header)
	out.Write(data)
	if len(data)%2 != 0 {
		out.WriteByte('\n')
	}
}
