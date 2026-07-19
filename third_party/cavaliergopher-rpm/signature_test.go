package rpm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
)

func TestReadSignatureHeaderStopsBeforeMainHeaderAndPayload(t *testing.T) {
	const filename = "testdata/centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm"
	data := getTestFiles()[filename]
	full, err := Read(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	mainHeaderStart, _ := full.HeaderRange()
	reader := bytes.NewReader(data)
	signature, err := ReadSignatureHeader(reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(data) - reader.Len(); got != mainHeaderStart || signature.Size != mainHeaderStart-96 {
		t.Fatalf("signature-only read consumed=%d signature_size=%d main_header_start=%d", got, signature.Size, mainHeaderStart)
	}
	if _, err := ReadSignatureHeader(bytes.NewReader(data[:mainHeaderStart])); err != nil {
		t.Fatalf("signature-only reader required main header or payload: %v", err)
	}
}

func TestReadSignatureHeaderEnforcesLowIndependentBudget(t *testing.T) {
	const filename = "testdata/centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm"
	lead := append([]byte(nil), getTestFiles()[filename][:96]...)
	header := make([]byte, 16)
	copy(header, []byte{0x8e, 0xad, 0xe8, 1})
	binary.BigEndian.PutUint32(header[12:16], uint32(r_MaxSignatureHeaderSize+1))
	if _, err := ReadSignatureHeader(bytes.NewReader(append(lead, header...))); err == nil || !strings.Contains(err.Error(), "header size exceeds") {
		t.Fatalf("oversized signature header error=%v", err)
	}
	binary.BigEndian.PutUint32(header[12:16], 1)
	binary.BigEndian.PutUint32(header[8:12], uint32(r_MaxSignatureHeaderIndexCount+1))
	if _, err := ReadSignatureHeader(bytes.NewReader(append(lead, header...))); err == nil || !strings.Contains(err.Error(), "index count exceeds") {
		t.Fatalf("oversized signature index count error=%v", err)
	}
	header[0] = 0
	if _, err := ReadSignatureHeader(bytes.NewReader(append(lead, header...))); err == nil || !strings.Contains(err.Error(), "invalid rpm header") {
		t.Fatalf("malformed signature header error=%v", err)
	}
}

func TestReadSignatureHeaderRejectsDuplicateTags(t *testing.T) {
	const filename = "testdata/centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm"
	lead := append([]byte(nil), getTestFiles()[filename][:96]...)
	header := make([]byte, 16)
	copy(header, []byte{0x8e, 0xad, 0xe8, 1})
	binary.BigEndian.PutUint32(header[8:12], 2)
	binary.BigEndian.PutUint32(header[12:16], 1)
	indexes := make([]byte, 32)
	for offset := 0; offset < len(indexes); offset += 16 {
		binary.BigEndian.PutUint32(indexes[offset:offset+4], 268)
		binary.BigEndian.PutUint32(indexes[offset+4:offset+8], 7)
		binary.BigEndian.PutUint32(indexes[offset+12:offset+16], 1)
	}
	data := bytes.Join([][]byte{lead, header, indexes, {0x01}, make([]byte, 7)}, nil)
	if _, err := ReadSignatureHeader(bytes.NewReader(data)); err == nil || !strings.Contains(err.Error(), "duplicate header tag") {
		t.Fatalf("duplicate signature tag error=%v", err)
	}
}

func TestMD5Check(t *testing.T) {
	files := getTestFiles()
	valid := 0
	for filename, b := range files {
		if err := MD5Check(bytes.NewReader(b)); err != nil {
			t.Errorf("Validation error for %s: %v", filename, err)
		} else {
			valid++
		}
	}
	t.Logf("Validated MD5 checksum for %d packages", valid)
}

func TestGPGSignatureString(t *testing.T) {
	const filename = "testdata/centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm"
	pkg, err := Read(bytes.NewReader(getTestFiles()[filename]))
	if err != nil {
		t.Fatalf("Read(%s): %v", filename, err)
	}
	display := pkg.GPGSignature().String()
	if !strings.HasPrefix(display, "RSA/SHA256, ") || !strings.Contains(display, "Key ID 24c6a8a7f4a80eb5") {
		t.Fatalf("GPGSignature(%s) = %q", filename, display)
	}
}

func TestOpenPGPSignaturePacketBodyRejectsMalformed(t *testing.T) {
	tests := [][]byte{
		nil,
		{0x00, 0x00},
		{0x88, 0xff},
		{0xc2, 224}, // partial body length
		{0xc1, 0},   // not a signature packet
		{0xc2, 10, 3},
	}
	for _, input := range tests {
		if _, ok := openPGPSignaturePacketBody(input); ok {
			t.Fatalf("malformed packet accepted: %x", input)
		}
	}
}

// ExampleMD5Check reads a local RPM and validates its legacy payload checksum.
func ExampleMD5Check() {
	f, err := os.Open("testdata/centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if err := MD5Check(f); err == nil {
		fmt.Println("Package passed MD5 checksum validation")
	} else if err == ErrMD5CheckFailed {
		fmt.Println("Package failed MD5 checksum validation")
	} else {
		log.Fatal(err)
	}

	// Output: Package passed MD5 checksum validation
}
