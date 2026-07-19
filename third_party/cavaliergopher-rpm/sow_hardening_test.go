package rpm

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

type syntheticHeaderIndex struct {
	tag, kind, offset, count uint32
}

func encodeSyntheticHeader(indexes []syntheticHeaderIndex, store []byte) []byte {
	header := make([]byte, 16+len(indexes)*16+len(store))
	copy(header[:4], []byte{0x8e, 0xad, 0xe8, 1})
	binary.BigEndian.PutUint32(header[8:12], uint32(len(indexes)))
	binary.BigEndian.PutUint32(header[12:16], uint32(len(store)))
	for i, index := range indexes {
		offset := 16 + i*16
		binary.BigEndian.PutUint32(header[offset:offset+4], index.tag)
		binary.BigEndian.PutUint32(header[offset+4:offset+8], index.kind)
		binary.BigEndian.PutUint32(header[offset+8:offset+12], index.offset)
		binary.BigEndian.PutUint32(header[offset+12:offset+16], index.count)
	}
	copy(header[16+len(indexes)*16:], store)
	return header
}

func TestReadHeaderRejectsAllocationAndIndexBombsBeforeMaterialization(t *testing.T) {
	hugeCount := encodeSyntheticHeader([]syntheticHeaderIndex{{tag: 1000, kind: uint32(TagTypeInt64), count: ^uint32(0)}}, make([]byte, 8))
	if _, err := readHeader(bytes.NewReader(hugeCount), false); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("huge int64 count was not rejected: %v", err)
	}

	indexes := make([]syntheticHeaderIndex, 65)
	for i := range indexes {
		indexes[i] = syntheticHeaderIndex{tag: uint32(2000 + i), kind: uint32(TagTypeString), count: 1}
	}
	store := bytes.Repeat([]byte{'x'}, 1<<20)
	store[len(store)-1] = 0
	aggregate := encodeSyntheticHeader(indexes, store)
	if _, err := readHeader(bytes.NewReader(aggregate), false); err == nil || !strings.Contains(err.Error(), "decoded value bytes") {
		t.Fatalf("aggregate decoded allocation was not rejected: %v", err)
	}

	tooMany := make([]byte, 17)
	copy(tooMany[:4], []byte{0x8e, 0xad, 0xe8, 1})
	binary.BigEndian.PutUint32(tooMany[8:12], uint32(r_MaxHeaderIndexCount+1))
	binary.BigEndian.PutUint32(tooMany[12:16], 1)
	if _, err := readHeader(bytes.NewReader(tooMany), false); err == nil || !strings.Contains(err.Error(), "index count") {
		t.Fatalf("excessive index count was not rejected: %v", err)
	}
}

func TestReadHeaderRejectsInvalidDescriptorAndUnterminatedStrings(t *testing.T) {
	valid := encodeSyntheticHeader([]syntheticHeaderIndex{{tag: 1000, kind: uint32(TagTypeString), offset: 1, count: 1}}, []byte{0, 'x'})
	for name, mutate := range map[string]func([]byte){
		"magic":   func(value []byte) { value[0] ^= 0xff },
		"version": func(value []byte) { value[3] = 2 },
		"reserved": func(value []byte) {
			value[4] = 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := append([]byte(nil), valid...)
			mutate(input)
			if _, err := readHeader(bytes.NewReader(input), false); err == nil || !strings.Contains(err.Error(), "descriptor") {
				t.Fatalf("invalid %s was not rejected: %v", name, err)
			}
		})
	}
	if _, err := readHeader(bytes.NewReader(valid), false); err == nil || !strings.Contains(err.Error(), "NUL terminated") {
		t.Fatalf("unterminated string was not rejected: %v", err)
	}
	two := encodeSyntheticHeader([]syntheticHeaderIndex{{tag: 1000, kind: uint32(TagTypeStringArray), offset: 1, count: 2}}, []byte{0, 'x', 0})
	// Remove the final terminator so the second string ends at the store edge.
	two[len(two)-1] = 'y'
	if _, err := readHeader(bytes.NewReader(two), false); err == nil || !strings.Contains(err.Error(), "NUL terminated") {
		t.Fatalf("unterminated second string was not rejected: %v", err)
	}
}

func TestNegativePackageSizesNeverWrapToUint64(t *testing.T) {
	negative := &Tag{Type: TagTypeInt64, Value: []int64{-1}}
	pkg := &Package{
		Header:    Header{Tags: map[int]*Tag{5009: negative, 1009: negative, 271: negative, 1046: negative}},
		Signature: Header{Tags: map[int]*Tag{271: negative, 1007: negative}},
	}
	if got := pkg.Size(); got != 0 {
		t.Fatalf("Size() = %d, want 0", got)
	}
	if got := pkg.ArchiveSize(); got != 0 {
		t.Fatalf("ArchiveSize() = %d, want 0", got)
	}
}

func FuzzReadHeaderDoesNotPanic(f *testing.F) {
	f.Add(encodeSyntheticHeader([]syntheticHeaderIndex{{tag: 1000, kind: uint32(TagTypeString), count: 1}}, []byte{'x', 0}))
	f.Add([]byte{0x8e, 0xad, 0xe8, 1})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = readHeader(bytes.NewReader(input), false)
	})
}
