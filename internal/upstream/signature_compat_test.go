package upstream

import (
	"bytes"
	"crypto"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestVerifyDetachedConsumesAndValidatesCompleteArmor(t *testing.T) {
	created := time.Unix(1_700_000_000, 0).UTC()
	config := &packet.Config{
		Time:        func() time.Time { return created },
		RSABits:     2048,
		DefaultHash: crypto.SHA256,
	}
	entity, err := openpgp.NewEntity("SOW signature compatibility", "", "signature@example.invalid", config)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("signed repository metadata\n")
	var signature bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&signature, entity, bytes.NewReader(message), config); err != nil {
		t.Fatal(err)
	}
	keyring := openpgp.EntityList{entity}
	if err := verifyDetached(message, signature.Bytes(), keyring); err != nil {
		t.Fatalf("complete armored signature: %v", err)
	}

	withTrailing := append(append([]byte(nil), signature.Bytes()...), []byte("garbage\n")...)
	if err := verifyDetached(message, withTrailing, keyring); err == nil || !strings.Contains(err.Error(), "malformed armored detached signature") {
		t.Fatalf("trailing armor data was not rejected: %v", err)
	}

	corruptCRC := append([]byte(nil), signature.Bytes()...)
	checksum := bytes.LastIndex(corruptCRC, []byte("\n="))
	if checksum < 0 {
		t.Fatal("generated armor has no CRC line")
	}
	if corruptCRC[checksum+2] == 'A' {
		corruptCRC[checksum+2] = 'B'
	} else {
		corruptCRC[checksum+2] = 'A'
	}
	if err := verifyDetached(message, corruptCRC, keyring); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("corrupt armor CRC was not rejected: %v", err)
	}

	block, err := armor.Decode(bytes.NewReader(signature.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(block.Body)
	if err != nil {
		t.Fatal(err)
	}
	doubledBinary := append(append([]byte(nil), raw...), raw...)
	if err := verifyDetached(message, doubledBinary, keyring); err == nil || !strings.Contains(err.Error(), "extra") {
		t.Fatalf("second binary signature packet was not rejected: %v", err)
	}
	var doubledArmor bytes.Buffer
	armored, err := armor.Encode(&doubledArmor, openpgp.SignatureType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := armored.Write(doubledBinary); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyDetached(message, doubledArmor.Bytes(), keyring); err == nil || !strings.Contains(err.Error(), "extra") {
		t.Fatalf("second armored signature packet was not rejected: %v", err)
	}
}
