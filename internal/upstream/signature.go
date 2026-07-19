package upstream

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var trustedMetadataHashes = []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}

func verifyClearSigned(data []byte, keyring openpgp.KeyRing) (*clearsign.Block, error) {
	if keyring == nil {
		return nil, fmt.Errorf("%w: trusted keyring is required", ErrSignature)
	}
	block, rest := clearsign.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.ArmoredSignature == nil {
		return nil, fmt.Errorf("%w: malformed clear-signed document", ErrSignature)
	}
	// VerifySignature additionally checks that the cleartext Hash header agrees
	// with the signature packet. Decode a second copy below because verification
	// consumes ArmoredSignature.Body.
	if _, err := block.VerifySignature(keyring, nil); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	checked, rest := clearsign.Decode(data)
	if checked == nil || len(bytes.TrimSpace(rest)) != 0 || checked.ArmoredSignature == nil {
		return nil, fmt.Errorf("%w: malformed clear-signed document", ErrSignature)
	}
	signaturePacket, err := io.ReadAll(io.LimitReader(checked.ArmoredSignature.Body, int64(len(data))+1))
	if err != nil || len(signaturePacket) > len(data) {
		return nil, fmt.Errorf("%w: malformed clear signature packet: %v", ErrSignature, err)
	}
	if err := validateSingleSignaturePacket(signaturePacket); err != nil {
		return nil, err
	}
	if _, _, err := openpgp.VerifyDetachedSignatureAndHash(
		keyring,
		bytes.NewReader(checked.Bytes),
		bytes.NewReader(signaturePacket),
		trustedMetadataHashes,
		nil,
	); err != nil {
		return nil, fmt.Errorf("%w: weak or invalid clear signature: %v", ErrSignature, err)
	}
	return checked, nil
}

func verifyDetached(signed, signature []byte, keyring openpgp.KeyRing) error {
	if keyring == nil {
		return fmt.Errorf("%w: trusted keyring is required", ErrSignature)
	}
	signaturePacket := signature
	if bytes.HasPrefix(bytes.TrimSpace(signature), []byte("-----BEGIN PGP SIGNATURE-----")) {
		decoded, err := decodeArmoredDetachedSignature(signature)
		if err != nil {
			return err
		}
		signaturePacket = decoded
	}
	if err := validateSingleSignaturePacket(signaturePacket); err != nil {
		return err
	}
	if _, _, err := openpgp.VerifyDetachedSignatureAndHash(
		keyring,
		bytes.NewReader(signed),
		bytes.NewReader(signaturePacket),
		trustedMetadataHashes,
		nil,
	); err != nil {
		return fmt.Errorf("%w: weak or invalid detached signature: %v", ErrSignature, err)
	}
	return nil
}

// validateSingleSignaturePacket closes a parser-differential gap in OpenPGP
// detached verification: some verifiers return after the first valid packet.
// Repository metadata evidence must contain exactly one signature packet and
// no ignored packet or trailing binary data.
func validateSingleSignaturePacket(encoded []byte) error {
	reader := packet.NewReader(bytes.NewReader(encoded))
	first, err := reader.Next()
	if err != nil {
		return fmt.Errorf("%w: malformed detached signature packet: %v", ErrSignature, err)
	}
	if _, ok := first.(*packet.Signature); !ok {
		return fmt.Errorf("%w: detached evidence begins with %T, not a signature", ErrSignature, first)
	}
	next, err := reader.Next()
	if err == nil {
		return fmt.Errorf("%w: detached evidence contains an extra %T packet", ErrSignature, next)
	}
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data after detached signature packet: %v", ErrSignature, err)
	}
	return nil
}

// decodeArmoredDetachedSignature decodes exactly one complete signature armor
// block. The upstream armor package intentionally reads ahead and stops at the
// CRC line, making its source reader unusable for a reliable trailing-data
// check. Parsing the small, already size-bounded detached signature envelope
// here keeps that check fail-closed and also validates the optional CRC-24.
func decodeArmoredDetachedSignature(signature []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(signature))
	if strings.Contains(trimmed, "\r") {
		trimmed = strings.ReplaceAll(trimmed, "\r\n", "\n")
		if strings.Contains(trimmed, "\r") {
			return nil, fmt.Errorf("%w: malformed armored detached signature", ErrSignature)
		}
	}
	lines := strings.Split(trimmed, "\n")
	if len(lines) < 4 || strings.TrimSpace(lines[0]) != "-----BEGIN PGP SIGNATURE-----" ||
		strings.TrimSpace(lines[len(lines)-1]) != "-----END PGP SIGNATURE-----" {
		return nil, fmt.Errorf("%w: malformed armored detached signature", ErrSignature)
	}
	separator := -1
	for i := 1; i < len(lines)-1; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			separator = i
			break
		}
		if colon := strings.IndexByte(line, ':'); colon <= 0 {
			return nil, fmt.Errorf("%w: malformed armored detached signature", ErrSignature)
		}
	}
	if separator < 0 || separator == len(lines)-2 {
		return nil, fmt.Errorf("%w: malformed armored detached signature", ErrSignature)
	}

	var encoded strings.Builder
	var checksum []byte
	for i := separator + 1; i < len(lines)-1; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || len(line) > 96 {
			return nil, fmt.Errorf("%w: malformed armored detached signature", ErrSignature)
		}
		if strings.HasPrefix(line, "=") {
			if i != len(lines)-2 || len(line) != 5 {
				return nil, fmt.Errorf("%w: malformed armored detached signature", ErrSignature)
			}
			var err error
			checksum, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "="))
			if err != nil || len(checksum) != 3 {
				return nil, fmt.Errorf("%w: malformed armored detached signature", ErrSignature)
			}
			continue
		}
		if checksum != nil {
			return nil, fmt.Errorf("%w: trailing data after armored signature", ErrSignature)
		}
		encoded.WriteString(line)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil || len(decoded) == 0 {
		return nil, fmt.Errorf("%w: malformed armored detached signature", ErrSignature)
	}
	if checksum != nil {
		crc := armorCRC24(decoded)
		if checksum[0] != byte(crc>>16) || checksum[1] != byte(crc>>8) || checksum[2] != byte(crc) {
			return nil, fmt.Errorf("%w: armored detached signature checksum mismatch", ErrSignature)
		}
	}
	return decoded, nil
}

func armorCRC24(body []byte) uint32 {
	crc := uint32(0xb704ce)
	for _, value := range body {
		crc ^= uint32(value) << 16
		for bit := 0; bit < 8; bit++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= 0x1864cfb
			}
		}
	}
	return crc & 0xffffff
}
