package rpm

import (
	"bytes"
	"encoding/binary"
	"io"
)

const (
	r_MaxHeaderSize            = uint64(32 << 20)
	r_MaxHeaderIndexCount      = uint64(65_536)
	r_MaxDecodedHeaderBytes    = uint64(64 << 20)
	r_MaxDecodedHeaderElements = uint64(16 << 20)
	r_DecodedTagOverhead       = uint64(64)
	r_StringHeaderBytes        = uint64(16)
)

type headerLimits struct {
	maxHeaderSize       uint64
	maxHeaderIndexCount uint64
	maxDecodedBytes     uint64
	maxDecodedElements  uint64
	rejectDuplicateTags bool
}

var defaultHeaderLimits = headerLimits{
	maxHeaderSize:       r_MaxHeaderSize,
	maxHeaderIndexCount: r_MaxHeaderIndexCount,
	maxDecodedBytes:     r_MaxDecodedHeaderBytes,
	maxDecodedElements:  r_MaxDecodedHeaderElements,
}

// A Header stores metadata about an rpm package.
type Header struct {
	Version int
	Tags    map[int]*Tag
	Size    int
}

// GetTag returns the tag with the given identifier.
//
// Nil is returned if the specified tag does not exist or the header is nil.
func (c *Header) GetTag(id int) *Tag {
	if c == nil || len(c.Tags) == 0 {
		return nil
	}
	return c.Tags[id]
}

type rpmHeader [16]byte

func (b rpmHeader) Magic() []byte      { return b[:3] }
func (b rpmHeader) Version() int       { return int(b[3]) }
func (b rpmHeader) IndexCount() uint32 { return binary.BigEndian.Uint32(b[8:12]) }
func (b rpmHeader) Size() uint32       { return binary.BigEndian.Uint32(b[12:16]) }

type rpmIndex [16]byte

func (b rpmIndex) Tag() int           { return int(binary.BigEndian.Uint32(b[:4])) }
func (b rpmIndex) Type() TagType      { return TagType(binary.BigEndian.Uint32(b[4:8])) }
func (b rpmIndex) Offset() uint32     { return binary.BigEndian.Uint32(b[8:12]) }
func (b rpmIndex) ValueCount() uint32 { return binary.BigEndian.Uint32(b[12:16]) }

type headerDecodeBudget struct {
	bytes, elements       uint64
	maxBytes, maxElements uint64
}

func (b *headerDecodeBudget) reserve(index int, materializedBytes, elements uint64) error {
	if materializedBytes > b.maxBytes-b.bytes {
		return errorf("decoded value bytes exceed the maximum of %d at index %d", b.maxBytes, index+1)
	}
	if elements > b.maxElements-b.elements {
		return errorf("decoded value elements exceed the maximum of %d at index %d", b.maxElements, index+1)
	}
	b.bytes += materializedBytes
	b.elements += elements
	return nil
}

// readHeader reads an RPM package file header structure from r. The raw header,
// index count, per-value range, and aggregate decoded allocations are all
// bounded before any tag value is materialized.
func readHeader(r io.Reader, pad bool) (*Header, error) {
	return readHeaderWithLimits(r, pad, defaultHeaderLimits)
}

func readHeaderWithLimits(r io.Reader, pad bool, limits headerLimits) (*Header, error) {
	var hdrBytes rpmHeader
	if _, err := io.ReadFull(r, hdrBytes[:]); err != nil {
		return nil, err
	}
	if !bytes.Equal(hdrBytes.Magic(), []byte{0x8e, 0xad, 0xe8}) || hdrBytes.Version() != 1 || !allZero(hdrBytes[4:8]) {
		return nil, errorf("invalid rpm header descriptor")
	}
	headerSize := uint64(hdrBytes.Size())
	if headerSize > limits.maxHeaderSize {
		return nil, errorf("header size exceeds the maximum of %d: %d", limits.maxHeaderSize, headerSize)
	}
	indexCount := uint64(hdrBytes.IndexCount())
	if indexCount > limits.maxHeaderIndexCount || indexCount > limits.maxHeaderSize/uint64(len(rpmIndex{})) {
		return nil, errorf("header index count exceeds the maximum of %d: %d", limits.maxHeaderIndexCount, indexCount)
	}

	indexBytes := make([]rpmIndex, int(indexCount))
	for i := range indexBytes {
		if _, err := io.ReadFull(r, indexBytes[i][:]); err != nil {
			return nil, err
		}
		if uint64(indexBytes[i].Offset()) >= headerSize {
			return nil, errorf("offset of index %d is out of range: %d", i+1, indexBytes[i].Offset())
		}
	}

	buf := make([]byte, int(headerSize))
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	budget := headerDecodeBudget{maxBytes: limits.maxDecodedBytes, maxElements: limits.maxDecodedElements}
	for i, ix := range indexBytes {
		if err := validateHeaderIndex(i, ix, buf, &budget); err != nil {
			return nil, err
		}
	}

	tags := make(map[int]*Tag, len(indexBytes))
	for _, ix := range indexBytes {
		if _, duplicate := tags[ix.Tag()]; duplicate && limits.rejectDuplicateTags {
			return nil, errorf("duplicate header tag: %d", ix.Tag())
		}
		o := int(ix.Offset())
		count := int(ix.ValueCount())
		var value interface{}
		switch ix.Type() {
		case TagTypeBinary, TagTypeChar, TagTypeInt8:
			decoded := make([]byte, count)
			copy(decoded, buf[o:o+count])
			value = decoded
		case TagTypeInt16:
			decoded := make([]int64, count)
			for i := range decoded {
				decoded[i] = int64(binary.BigEndian.Uint16(buf[o : o+2]))
				o += 2
			}
			value = decoded
		case TagTypeInt32:
			decoded := make([]int64, count)
			for i := range decoded {
				decoded[i] = int64(binary.BigEndian.Uint32(buf[o : o+4]))
				o += 4
			}
			value = decoded
		case TagTypeInt64:
			decoded := make([]int64, count)
			for i := range decoded {
				decoded[i] = int64(binary.BigEndian.Uint64(buf[o : o+8]))
				o += 8
			}
			value = decoded
		case TagTypeString, TagTypeStringArray, TagTypeI18NString:
			decoded := make([]string, count)
			for i := range decoded {
				end := bytes.IndexByte(buf[o:], 0)
				// validateHeaderIndex proved this terminator exists.
				decoded[i] = string(buf[o : o+end])
				o += end + 1
			}
			value = decoded
		case TagTypeNull:
			// No materialized value.
		}
		tags[ix.Tag()] = &Tag{ID: ix.Tag(), Type: ix.Type(), Value: value}
	}

	var padding int64
	if pad {
		padding = int64(8-(headerSize%8)) % 8
		if padding != 0 {
			if _, err := io.CopyN(io.Discard, r, padding); err != nil {
				return nil, err
			}
		}
	}

	return &Header{
		Version: hdrBytes.Version(),
		Tags:    tags,
		Size:    16 + int(headerSize) + len(indexBytes)*16 + int(padding),
	}, nil
}

func validateHeaderIndex(index int, ix rpmIndex, store []byte, budget *headerDecodeBudget) error {
	count := uint64(ix.ValueCount())
	if count == 0 {
		return errorf("invalid value count for index %d: 0", index+1)
	}
	offset := uint64(ix.Offset())
	available := uint64(len(store)) - offset
	reserve := func(materialized uint64) error {
		if materialized > ^uint64(0)-r_DecodedTagOverhead {
			return errorf("decoded value size overflows at index %d", index+1)
		}
		return budget.reserve(index, materialized+r_DecodedTagOverhead, count)
	}
	switch ix.Type() {
	case TagTypeBinary, TagTypeChar, TagTypeInt8:
		if count > available {
			return errorf("byte value for index %d is out of range", index+1)
		}
		return reserve(count)
	case TagTypeInt16:
		if count > available/2 {
			return errorf("int16 value for index %d is out of range", index+1)
		}
		return reserve(count * 8)
	case TagTypeInt32:
		if count > available/4 {
			return errorf("int32 value for index %d is out of range", index+1)
		}
		return reserve(count * 8)
	case TagTypeInt64:
		if count > available/8 {
			return errorf("int64 value for index %d is out of range", index+1)
		}
		return reserve(count * 8)
	case TagTypeString, TagTypeStringArray, TagTypeI18NString:
		if count > available {
			return errorf("string values for index %d are out of range", index+1)
		}
		cursor := int(offset)
		var stringBytes uint64
		for n := uint64(0); n < count; n++ {
			if cursor >= len(store) {
				return errorf("string value for index %d is out of range", index+1)
			}
			end := bytes.IndexByte(store[cursor:], 0)
			if end < 0 {
				return errorf("string value for index %d is not NUL terminated", index+1)
			}
			stringBytes += uint64(end)
			cursor += end + 1
		}
		if count > (^uint64(0)-stringBytes)/r_StringHeaderBytes {
			return errorf("decoded string size overflows at index %d", index+1)
		}
		return reserve(stringBytes + count*r_StringHeaderBytes)
	case TagTypeNull:
		return reserve(0)
	default:
		return errorf("unknown index data type: %0X", ix.Type())
	}
}

func allZero(values []byte) bool {
	for _, value := range values {
		if value != 0 {
			return false
		}
	}
	return true
}
