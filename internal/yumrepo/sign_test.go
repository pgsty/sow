package yumrepo

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestOpenPGPArmoredIOAndSingleKeyPolicy(t *testing.T) {
	created := time.Unix(1_500_000_000, 0).UTC()
	config := &packet.Config{Time: func() time.Time { return created }, RSABits: 2048}
	entity, err := openpgp.NewEntity("SOW", "", "sow@example.invalid", config)
	if err != nil {
		t.Fatal(err)
	}
	var armored bytes.Buffer
	block, err := armor.Encode(&armored, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(block, nil); err != nil {
		t.Fatal(err)
	}
	if err := block.Close(); err != nil {
		t.Fatal(err)
	}
	signer, err := NewOpenPGPSigner(bytes.NewReader(armored.Bytes()), nil, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("NewOpenPGPSigner armored: %v", err)
	}
	message := []byte("repomd")
	var signature bytes.Buffer
	if err := signer.Sign(context.Background(), bytes.NewReader(message), &signature); err != nil {
		t.Fatal(err)
	}
	var replay bytes.Buffer
	if err := signer.Sign(context.Background(), bytes.NewReader(message), &replay); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signature.Bytes(), replay.Bytes()) {
		t.Fatal("fixed-time YUM metadata signature is not deterministic")
	}
	armoredSignature, err := armor.Decode(bytes.NewReader(signature.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	parsedPacket, err := packet.Read(armoredSignature.Body)
	if err != nil {
		t.Fatal(err)
	}
	parsedSignature, ok := parsedPacket.(*packet.Signature)
	if !ok {
		t.Fatalf("armored signature packet type = %T", parsedPacket)
	}
	for _, notation := range parsedSignature.Notations {
		if notation.Name == packet.SaltNotationName {
			t.Fatal("YUM compatibility signature retained an unsupported randomized salt notation")
		}
	}
	if err := signer.Verify(context.Background(), bytes.NewReader(message), bytes.NewReader(signature.Bytes())); err != nil {
		t.Fatal(err)
	}
	if err := signer.Verify(context.Background(), bytes.NewReader([]byte("tampered")), bytes.NewReader(signature.Bytes())); err == nil {
		t.Fatal("tampered message unexpectedly verified")
	}

	second, err := openpgp.NewEntity("Other", "", "other@example.invalid", config)
	if err != nil {
		t.Fatal(err)
	}
	var keyring bytes.Buffer
	if err := entity.SerializePrivate(&keyring, nil); err != nil {
		t.Fatal(err)
	}
	if err := second.SerializePrivate(&keyring, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := NewOpenPGPSigner(bytes.NewReader(keyring.Bytes()), nil, time.Unix(1_700_000_000, 0)); err == nil {
		t.Fatal("multiple OpenPGP entities unexpectedly accepted")
	}
}

func TestOpenPGPVerifierSelectsExactAggregateCertificate(t *testing.T) {
	created := time.Unix(1_500_000_000, 0).UTC()
	at := time.Unix(1_700_000_000, 0).UTC()
	config := &packet.Config{Time: func() time.Time { return created }, RSABits: 2048}
	selected, err := openpgp.NewEntity("Selected", "", "selected@example.invalid", config)
	if err != nil {
		t.Fatal(err)
	}
	decoy, err := openpgp.NewEntity("Decoy", "", "decoy@example.invalid", config)
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	if err := selected.SerializePrivate(&private, nil); err != nil {
		t.Fatal(err)
	}
	signer, err := NewOpenPGPSigner(bytes.NewReader(private.Bytes()), nil, at)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("aggregate repomd")
	var signature bytes.Buffer
	if err := signer.Sign(context.Background(), bytes.NewReader(message), &signature); err != nil {
		t.Fatal(err)
	}
	var aggregate bytes.Buffer
	if err := decoy.Serialize(&aggregate); err != nil {
		t.Fatal(err)
	}
	if err := selected.Serialize(&aggregate); err != nil {
		t.Fatal(err)
	}
	fingerprint := hex.EncodeToString(selected.PrimaryKey.Fingerprint)
	verifier, err := NewOpenPGPVerifierForFingerprint(bytes.NewReader(aggregate.Bytes()), fingerprint, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), bytes.NewReader(message), bytes.NewReader(signature.Bytes())); err != nil {
		t.Fatalf("selected aggregate certificate rejected signature: %v", err)
	}
	if _, err := NewOpenPGPVerifierForFingerprint(bytes.NewReader(aggregate.Bytes()), strings.Repeat("0", len(fingerprint)), at); err == nil || !strings.Contains(err.Error(), "lacks primary fingerprint") {
		t.Fatalf("missing aggregate fingerprint error=%v", err)
	}
	if _, err := NewOpenPGPVerifierForFingerprint(bytes.NewReader(aggregate.Bytes()), "00", at); err == nil || !strings.Contains(err.Error(), "invalid lowercase") {
		t.Fatalf("short aggregate fingerprint error=%v", err)
	}
}
