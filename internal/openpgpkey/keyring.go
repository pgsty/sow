// Package openpgpkey reads complete OpenPGP key inputs without silently
// discarding subsequent armor blocks or malformed entities.
package openpgpkey

import (
	"bytes"
	"errors"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var errInvalidKeyring = errors.New("invalid or incomplete OpenPGP keyring")

// Read accepts a binary keyring or one or more complete public/private armor
// blocks. Unlike openpgp.ReadKeyRing it does not skip malformed entities.
func Read(data []byte) (openpgp.EntityList, error) {
	return read(data, false)
}

// ReadSingle accepts exactly one entity and, for armored input, exactly one
// armor block. A trust bundle must not silently become a single signing key.
func ReadSingle(data []byte) (openpgp.EntityList, error) {
	return read(data, true)
}

func read(data []byte, single bool) (openpgp.EntityList, error) {
	blocks := [][]byte{data}
	armored := bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN PGP"))
	if armored {
		var err error
		blocks, err = SplitArmor(data, openpgp.PublicKeyType, openpgp.PrivateKeyType)
		if err != nil || single && len(blocks) != 1 {
			return nil, errInvalidKeyring
		}
	}
	var entities openpgp.EntityList
	for _, block := range blocks {
		material := block
		if armored {
			decoded, err := armor.Decode(bytes.NewReader(block))
			if err != nil {
				return nil, errInvalidKeyring
			}
			material, err = io.ReadAll(decoded.Body)
			defer clear(material)
			if err != nil {
				return nil, errInvalidKeyring
			}
		}
		if err := validatePackets(material); err != nil {
			return nil, errInvalidKeyring
		}
		packets := packet.NewReader(bytes.NewReader(material))
		count := 0
		for {
			entity, err := openpgp.ReadEntity(packets)
			if err == io.EOF {
				break
			}
			if err != nil || entity == nil || entity.PrimaryKey == nil {
				return nil, errInvalidKeyring
			}
			entities = append(entities, entity)
			count++
		}
		if count == 0 {
			return nil, errInvalidKeyring
		}
	}
	if single && len(entities) != 1 {
		return nil, errInvalidKeyring
	}
	return entities, nil
}

func validatePackets(material []byte) error {
	// Reader.Next skips unsupported keys, so ReadEntity alone cannot prove
	// that every supplied key is usable. Validate the bounded key bytes before
	// parsing entities, retaining standard marker/non-critical compatibility.
	source := &packetSource{reader: bytes.NewReader(material)}
	for source.reader.Len() > 0 {
		header := material[len(material)-source.reader.Len()]
		indeterminate := header&0x40 == 0 && header&3 == 3
		source.reachedEOF = false
		_, err := packet.Read(source)
		// packet.Read ignores errors while draining unknown packet bodies.
		// A bounded or partial body must end at its declared boundary without
		// reading past the input. Only old indeterminate-length packets use
		// the actual stream EOF as their legitimate body boundary.
		if source.reachedEOF && !indeterminate {
			return errInvalidKeyring
		}
		if _, ignorable := err.(pgperrors.UnknownPacketTypeError); ignorable {
			continue // Preserve OpenPGP's non-critical packet compatibility.
		}
		if err != nil {
			return errInvalidKeyring
		}
	}
	return nil
}

type packetSource struct {
	reader     *bytes.Reader
	reachedEOF bool
}

func (source *packetSource) Read(data []byte) (int, error) {
	n, err := source.reader.Read(data)
	if err == io.EOF {
		source.reachedEOF = true
	}
	return n, err
}

// SplitArmor returns complete armor blocks of the permitted types, allowing
// whitespace only between them. The slices refer to data; callers retain the
// responsibility for bounding and clearing any private input bytes.
func SplitArmor(data []byte, types ...string) ([][]byte, error) {
	remaining := bytes.TrimSpace(data)
	var blocks [][]byte
	for len(remaining) > 0 {
		first, offset := armorLine(remaining)
		end := ""
		for _, kind := range types {
			if string(first) == "-----BEGIN "+kind+"-----" {
				end = "-----END " + kind + "-----"
				break
			}
		}
		if end == "" {
			return nil, errInvalidKeyring
		}
		found, checksum := false, false
		for offset < len(remaining) {
			line, size := armorLine(remaining[offset:])
			offset += size
			if string(line) == end {
				blocks = append(blocks, remaining[:offset])
				remaining = bytes.TrimSpace(remaining[offset:])
				found = true
				break
			}
			if bytes.HasPrefix(line, []byte("-----BEGIN ")) || bytes.HasPrefix(line, []byte("-----END ")) || checksum && len(line) != 0 {
				return nil, errInvalidKeyring
			}
			if len(line) == 5 && line[0] == '=' {
				checksum = true
			}
		}
		if !found {
			return nil, errInvalidKeyring
		}
	}
	if len(blocks) == 0 {
		return nil, errInvalidKeyring
	}
	return blocks, nil
}

func armorLine(data []byte) ([]byte, int) {
	if end := bytes.IndexByte(data, '\n'); end >= 0 {
		return bytes.TrimSpace(data[:end]), end + 1
	}
	return bytes.TrimSpace(data), len(data)
}
