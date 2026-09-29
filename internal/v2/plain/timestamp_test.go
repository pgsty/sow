package plain

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateRPMExplicitPublicationTime(t *testing.T) {
	dir := t.TempDir()
	rpm := filepath.Join(dir, "test.rpm")
	writeRPMFixture(t, rpm, rpmFixture{Name: "test", Version: "1", Release: "1", Arch: "noarch", Payload: "unchanged"})
	packageBytes := mustRead(t, rpm)
	opts := Options{Dir: dir, Jobs: 1}
	if _, err := Create(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	xml := filepath.Join(dir, "repodata", "repomd.xml")
	original := mustRead(t, xml)
	if strings.Count(string(original), "<timestamp>0</timestamp>") != 3 {
		t.Fatal("default timestamp changed")
	}
	payloads := map[string][]byte{}
	paths, err := filepath.Glob(filepath.Join(dir, "repodata", "*.gz"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		payloads[p] = mustRead(t, p)
	}
	opts.MetadataTimestamp = 1790049000
	result, err := Create(context.Background(), opts)
	if err != nil || result.Noop {
		t.Fatalf("publish: %+v %v", result, err)
	}
	want := strings.ReplaceAll(string(original), "<timestamp>0</timestamp>", "<timestamp>1790049000</timestamp>")
	if string(mustRead(t, xml)) != want {
		t.Fatal("explicit time changed fields other than data timestamps")
	}
	info, err := os.Stat(xml)
	if err != nil {
		t.Fatal(err)
	}
	result, err = Create(context.Background(), opts)
	if err != nil || !result.Noop {
		t.Fatalf("repeat: %+v %v", result, err)
	}
	next, err := os.Stat(xml)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(info, next) || !info.ModTime().Equal(next.ModTime()) {
		t.Fatal("fixed-time repeat rewrote repomd")
	}
	opts.MetadataTimestamp++
	result, err = Create(context.Background(), opts)
	if err != nil || result.Noop {
		t.Fatalf("new time: %+v %v", result, err)
	}
	for p, before := range payloads {
		if !bytes.Equal(before, mustRead(t, p)) {
			t.Fatalf("index payload changed: %s", p)
		}
	}
	paths, err = filepath.Glob(filepath.Join(dir, "repodata", "*.gz"))
	if err != nil || len(paths) != len(payloads) {
		t.Fatal("new compressed index produced")
	}
	if !bytes.Equal(packageBytes, mustRead(t, rpm)) {
		t.Fatal("publication time modified RPM")
	}
}

func TestCreateRejectsNegativeMetadataTimestamp(t *testing.T) {
	_, err := Create(context.Background(), Options{Dir: t.TempDir(), MetadataTimestamp: -1})
	if err == nil || KindOf(err) != KindUsage {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateRejectsOutOfRangeMetadataTimestampBeforeWriting(t *testing.T) {
	for _, value := range []int64{253402300800, 1790049000000, 9223372036854775807} {
		root := t.TempDir()
		if _, err := Create(context.Background(), Options{Dir: root, MetadataTimestamp: value}); KindOf(err) != KindUsage {
			t.Fatalf("timestamp=%d err=%v", value, err)
		}
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			t.Fatalf("invalid timestamp wrote files: %v %v", entries, err)
		}
	}
}
