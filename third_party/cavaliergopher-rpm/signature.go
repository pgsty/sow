package rpm

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// ErrMD5CheckFailed indicates that an RPM package failed MD5 checksum
// validation.
var ErrMD5CheckFailed = fmt.Errorf("MD5 checksum validation failed")

// In order of precedence.
var gpgTags = []int{
	1002, // RPMSIGTAG_PGP
	1006, // RPMSIGTAG_PGP5
	1005, // RPMSIGTAG_GPG
}

// OpenPGP algorithm identifiers used by RPM's signature display.
var gpgPubkeyTbl = map[byte]string{
	1:  "RSA",
	2:  "RSA(Encrypt-Only)",
	3:  "RSA(Sign-Only)",
	16: "Elgamal",
	17: "DSA",
	18: "Elliptic Curve",
	19: "ECDSA",
}

var gpgHashTbl = map[byte]string{
	1:  "MD5",
	2:  "SHA1",
	3:  "RIPEMD160",
	8:  "SHA256",
	9:  "SHA384",
	10: "SHA512",
	11: "SHA224",
	12: "SHA3_256",
	14: "SHA3_512",
}

const (
	r_MaxSignatureHeaderSize            = uint64(2 << 20)
	r_MaxSignatureHeaderIndexCount      = uint64(256)
	r_MaxSignatureDecodedHeaderBytes    = uint64(4 << 20)
	r_MaxSignatureDecodedHeaderElements = uint64(2 << 20)
)

var signatureHeaderLimits = headerLimits{
	maxHeaderSize:       r_MaxSignatureHeaderSize,
	maxHeaderIndexCount: r_MaxSignatureHeaderIndexCount,
	maxDecodedBytes:     r_MaxSignatureDecodedHeaderBytes,
	maxDecodedElements:  r_MaxSignatureDecodedHeaderElements,
	rejectDuplicateTags: true,
}

// GPGSignature is the raw byte representation of a package's embedded
// signature packet. SOW preserves these bytes; repository clients perform the
// package-level trust check. String decodes only the legacy v3 metadata that
// the upstream rpm package displayed, and does not claim cryptographic
// verification.
type GPGSignature []byte

func (b GPGSignature) String() string {
	body, ok := openPGPSignaturePacketBody(b)
	// A v3 signature body is fixed through the issuer/hash fields:
	// version(1), hashed-length(1), type(1), time(4), issuer(8),
	// public-key algorithm(1), hash algorithm(1), hash tag(2).
	if !ok || len(body) < 19 || body[0] != 3 || body[1] != 5 {
		return ""
	}
	algo, ok := gpgPubkeyTbl[body[15]]
	if !ok {
		algo = "Unknown public key algorithm"
	}
	hasher, ok := gpgHashTbl[body[16]]
	if !ok {
		hasher = "Unknown hash algorithm"
	}
	created := time.Unix(int64(binary.BigEndian.Uint32(body[3:7])), 0).UTC().Format(TimeFormat)
	issuer := binary.BigEndian.Uint64(body[7:15])
	return fmt.Sprintf("%v/%v, %v, Key ID %x", algo, hasher, created, issuer)
}

// openPGPSignaturePacketBody unwraps one bounded old- or new-format OpenPGP
// signature packet. Partial-body lengths are deliberately rejected: RPM
// signature tags contain one complete packet and never require packet
// concatenation.
func openPGPSignaturePacketBody(encoded []byte) ([]byte, bool) {
	if len(encoded) < 2 || encoded[0]&0x80 == 0 {
		return nil, false
	}
	header := encoded[0]
	offset := 1
	var length uint64
	if header&0x40 == 0 {
		if (header>>2)&0x0f != 2 {
			return nil, false
		}
		switch header & 0x03 {
		case 0:
			length = uint64(encoded[offset])
			offset++
		case 1:
			if len(encoded) < offset+2 {
				return nil, false
			}
			length = uint64(binary.BigEndian.Uint16(encoded[offset : offset+2]))
			offset += 2
		case 2:
			if len(encoded) < offset+4 {
				return nil, false
			}
			length = uint64(binary.BigEndian.Uint32(encoded[offset : offset+4]))
			offset += 4
		case 3:
			length = uint64(len(encoded) - offset)
		}
	} else {
		if header&0x3f != 2 || len(encoded) <= offset {
			return nil, false
		}
		first := encoded[offset]
		offset++
		switch {
		case first < 192:
			length = uint64(first)
		case first <= 223:
			if len(encoded) <= offset {
				return nil, false
			}
			length = uint64(first-192)<<8 + uint64(encoded[offset]) + 192
			offset++
		case first == 255:
			if len(encoded) < offset+4 {
				return nil, false
			}
			length = uint64(binary.BigEndian.Uint32(encoded[offset : offset+4]))
			offset += 4
		default:
			return nil, false
		}
	}
	if length > uint64(len(encoded)-offset) {
		return nil, false
	}
	return encoded[offset : offset+int(length)], true
}

// readSigHeader reads the lead and signature header of an RPM package and
// stops the reader at the beginning of the main header.
func readSigHeader(r io.Reader) (*Header, error) {
	return readSignatureHeaderWithLimits(r, defaultHeaderLimits)
}

// ReadSignatureHeader validates and reads only the RPM lead and bounded
// signature header. It stops before the main package header and payload, so
// callers inspecting embedded signature evidence do not materialize an
// attacker-selected main header for every concurrent package.
func ReadSignatureHeader(r io.Reader) (*Header, error) {
	return readSignatureHeaderWithLimits(r, signatureHeaderLimits)
}

func readSignatureHeaderWithLimits(r io.Reader, limits headerLimits) (*Header, error) {
	lead, err := readLead(r)
	if err != nil {
		return nil, err
	}
	if lead.SignatureType != 5 { // RPMSIGTYPE_HEADERSIG
		return nil, errorf("unknown signature type: %x", lead.SignatureType)
	}
	sig, err := readHeaderWithLimits(r, true, limits)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// MD5Check validates the legacy RPM payload checksum stored in the signature
// header. It is an integrity check, not a trust/signature check.
func MD5Check(r io.Reader) error {
	sigheader, err := readSigHeader(r)
	if err != nil {
		return err
	}
	payloadSize := sigheader.GetTag(270).Int64() // RPMSIGTAG_LONGSIGSIZE
	if payloadSize == 0 {
		payloadSize = sigheader.GetTag(1000).Int64() // RPMSIGTAG_SIGSIZE
		if payloadSize == 0 {
			return fmt.Errorf("tag not found: RPMSIGTAG_SIZE")
		}
	}
	expect := sigheader.GetTag(1004).Bytes() // RPMSIGTAG_MD5
	if expect == nil {
		return errorf("tag not found: RPMSIGTAG_MD5")
	}
	h := md5.New()
	if n, err := io.Copy(h, r); err != nil {
		return err
	} else if n != payloadSize {
		return ErrMD5CheckFailed
	}
	if !bytes.Equal(expect, h.Sum(nil)) {
		return ErrMD5CheckFailed
	}
	return nil
}
