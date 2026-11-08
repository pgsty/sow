package yumrepo

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyPackageDigestsRealRPMs(t *testing.T) {
	pgdg := readPGDGRPMFixture(t)
	legacy, err := os.ReadFile("../../third_party/cavaliergopher-rpm/testdata/centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm")
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"PGDG":               pgdg,
		"legacy MD5":         legacy,
		"modern without MD5": withoutSignatureDigestTags(pgdg, 1004),
	} {
		t.Run(name, func(t *testing.T) {
			reader := bytes.NewReader(data)
			if _, err := reader.Seek(7, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			if err := VerifyPackageDigests(context.Background(), reader); err != nil {
				t.Fatal(err)
			}
			if offset, err := reader.Seek(0, io.SeekCurrent); err != nil || offset != 7 {
				t.Fatalf("reader position=%d err=%v", offset, err)
			}
		})
	}
}

// RPM v6 writes PAYLOADSHA256 without PAYLOADSHA256ALGO. Report the format
// rather than an opaque "algorithm 0" failure.
func TestVerifyPackageDigestsNamesUnsupportedRPMv6(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v6.rpm")
	writeRPMFixture(t, path, "v6", fixtureTag{id: rpmTagPayloadDigest, typ: 8, count: 1, data: append([]byte(strings.Repeat("0", 64)), 0)})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyPackageDigests(context.Background(), bytes.NewReader(data))
	if !errors.Is(err, ErrInvalidPackage) || !strings.Contains(err.Error(), "RPM v6 packages are not supported") {
		t.Fatalf("v6 digest error=%v", err)
	}
}

func TestVerifyPackageDigestsRejectsDamagedOrUncoveredBytes(t *testing.T) {
	data := withoutSignatureDigestTags(readPGDGRPMFixture(t), 1004)
	layout := testRPMVerificationLayout(t, data)
	headerDamaged := bytes.Clone(data)
	offset := bytes.Index(headerDamaged[layout.mainHeaderStart:layout.mainHeaderEnd], []byte(layout.payloadDigests[0]))
	if offset < 0 {
		t.Fatal("fixture payload digest not found")
	}
	headerDamaged[int(layout.mainHeaderStart)+offset] ^= 1
	payloadDamaged := bytes.Clone(data)
	payloadDamaged[len(payloadDamaged)-1] ^= 1
	unsignedPath := filepath.Join(t.TempDir(), "no-digests.rpm")
	writeRPMFixture(t, unsignedPath, "no-digests")
	unsigned, err := os.ReadFile(unsignedPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name    string
		data    []byte
		message string
	}{
		{"header damage", headerDamaged, "header digest"},
		{"payload damage", payloadDamaged, "payload digest"},
		{"payload truncation", data[:len(data)-1], "payload digest"},
		{"no digests", unsigned, "lacks supported"},
		{"payload only", withoutSignatureDigestTags(data, 269, 273), "lacks supported"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.data)
			_, _ = reader.Seek(7, io.SeekStart)
			err := VerifyPackageDigests(context.Background(), reader)
			if !errors.Is(err, ErrInvalidPackage) || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("verification error=%v, want %s", err, tt.message)
			}
			if offset, _ := reader.Seek(0, io.SeekCurrent); offset != 7 {
				t.Fatalf("failed verification left reader at %d", offset)
			}
		})
	}
}

func TestVerifyPackageDigestsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := VerifyPackageDigests(ctx, bytes.NewReader(readPGDGRPMFixture(t))); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}

// Rename selected signature-header tags to unknown IDs without changing the
// main header or payload, so coverage can be tested independently of MD5.
func withoutSignatureDigestTags(data []byte, tags ...uint32) []byte {
	result := bytes.Clone(data)
	count := int(binary.BigEndian.Uint32(result[104:108]))
	for i := 0; i < count; i++ {
		entry := result[112+i*16:]
		for _, tag := range tags {
			if binary.BigEndian.Uint32(entry) == tag {
				binary.BigEndian.PutUint32(entry, 65000+uint32(i))
			}
		}
	}
	return result
}
