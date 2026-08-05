package aptrepo

import (
	"bytes"
	"crypto"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestSignerProducesVerifiableInReleaseAndDetachedSignature(t *testing.T) {
	created := time.Date(2026, 7, 12, 1, 0, 0, 0, time.UTC)
	signer, keyring, _ := testSigningMaterial(t, created)
	message := []byte("Origin: Pigsty\nSuite: beta\nAcquire-By-Hash: yes\n")
	signedAt := created.Add(time.Hour)

	var inRelease bytes.Buffer
	if err := signer.ClearSign(&inRelease, bytes.NewReader(message), signedAt); err != nil {
		t.Fatalf("ClearSign: %v", err)
	}
	block, rest := clearsign.Decode(inRelease.Bytes())
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("generated InRelease is not a complete clear-signed document")
	}
	verifyConfig := &packet.Config{Time: func() time.Time { return signedAt }}
	if _, err := block.VerifySignature(keyring, verifyConfig); err != nil {
		t.Fatalf("verify InRelease: %v", err)
	}
	if !bytes.Equal(block.Plaintext, message) {
		t.Fatalf("InRelease plaintext mismatch:\n%s", block.Plaintext)
	}

	var detached bytes.Buffer
	if err := signer.DetachedSign(&detached, bytes.NewReader(message), signedAt); err != nil {
		t.Fatalf("DetachedSign: %v", err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(message), bytes.NewReader(detached.Bytes()), verifyConfig); err != nil {
		t.Fatalf("verify detached signature: %v", err)
	}
	if err := signer.Verify(message, inRelease.Bytes(), detached.Bytes(), signedAt); err != nil {
		t.Fatalf("Signer.Verify: %v", err)
	}
	var replayInRelease, replayDetached bytes.Buffer
	if err := signer.ClearSign(&replayInRelease, bytes.NewReader(message), signedAt); err != nil {
		t.Fatalf("replay ClearSign: %v", err)
	}
	if err := signer.DetachedSign(&replayDetached, bytes.NewReader(message), signedAt); err != nil {
		t.Fatalf("replay DetachedSign: %v", err)
	}
	if !bytes.Equal(inRelease.Bytes(), replayInRelease.Bytes()) || !bytes.Equal(detached.Bytes(), replayDetached.Bytes()) {
		t.Fatal("fixed-time APT metadata signatures are not retry-deterministic")
	}
	tampered := append([]byte(nil), message...)
	tampered[0] ^= 1
	if err := signer.Verify(tampered, inRelease.Bytes(), detached.Bytes(), signedAt); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("tampered self-check error = %v", err)
	}
}

func TestSignerUnlockErrorsDoNotExposeSecrets(t *testing.T) {
	created := time.Date(2026, 7, 12, 1, 0, 0, 0, time.UTC)
	entity := newTestEntity(t, "encrypted", created)
	correct := []byte("correct horse battery staple")
	if err := entity.EncryptPrivateKeys(correct, &packet.Config{DefaultHash: crypto.SHA256}); err != nil {
		t.Fatalf("encrypt private key: %v", err)
	}
	key := serializePrivateEntities(t, []*openpgp.Entity{entity}, false, created)
	wrong := []byte("super-secret-wrong")
	_, err := NewSignerBytes(key, wrong)
	if !errors.Is(err, ErrUnlockSigningKey) {
		t.Fatalf("NewSignerBytes error = %v, want %v", err, ErrUnlockSigningKey)
	}
	if strings.Contains(err.Error(), string(correct)) || strings.Contains(err.Error(), string(wrong)) {
		t.Fatalf("unlock error exposed a passphrase: %q", err)
	}
	if _, err := NewSignerBytes(key, nil); !errors.Is(err, ErrUnlockSigningKey) {
		t.Fatalf("missing-passphrase error = %v, want %v", err, ErrUnlockSigningKey)
	}
	if _, err := NewSignerBytes(key, correct); err != nil {
		t.Fatalf("unlock encrypted key: %v", err)
	}
}

func TestSignerRequiresExactlyOnePrivateEntity(t *testing.T) {
	created := time.Date(2026, 7, 12, 1, 0, 0, 0, time.UTC)
	first := newTestEntity(t, "first", created)
	second := newTestEntity(t, "second", created)
	twoKeys := serializePrivateEntities(t, []*openpgp.Entity{first, second}, true, created)
	if _, err := NewSignerBytes(twoKeys, nil); !errors.Is(err, ErrInvalidSigningKey) {
		t.Fatalf("two-entity keyring error = %v, want %v", err, ErrInvalidSigningKey)
	}
	if _, err := NewSignerBytes([]byte("not a private key"), nil); !errors.Is(err, ErrInvalidSigningKey) {
		t.Fatalf("invalid key error = %v, want %v", err, ErrInvalidSigningKey)
	}
}

func TestSignerRejectsMultipleUsableSigningKeys(t *testing.T) {
	created := time.Date(2026, 7, 12, 1, 0, 0, 0, time.UTC)
	entity := newTestEntity(t, "multiple-signers", created)
	config := &packet.Config{DefaultHash: crypto.SHA256, RSABits: 1024, Time: func() time.Time { return created }}
	if err := entity.AddSigningSubkey(config); err != nil {
		t.Fatalf("add signing subkey: %v", err)
	}
	key := serializePrivateEntities(t, []*openpgp.Entity{entity}, true, created)
	if _, err := NewSignerBytes(key, nil); !errors.Is(err, ErrInvalidSigningKey) {
		t.Fatalf("multiple signing key error = %v, want %v", err, ErrInvalidSigningKey)
	}
}

func testSigningMaterial(t *testing.T, created time.Time) (*Signer, openpgp.EntityList, []byte) {
	t.Helper()
	entity := newTestEntity(t, "repository", created)
	key := serializePrivateEntities(t, []*openpgp.Entity{entity}, true, created)
	signer, err := NewSignerBytes(key, nil)
	if err != nil {
		t.Fatalf("NewSignerBytes: %v", err)
	}
	return signer, openpgp.EntityList{entity}, key
}

func newTestEntity(t *testing.T, name string, created time.Time) *openpgp.Entity {
	t.Helper()
	config := &packet.Config{
		DefaultHash: crypto.SHA256,
		RSABits:     1024,
		Time:        func() time.Time { return created },
	}
	entity, err := openpgp.NewEntity(name, "SOW aptrepo test", name+"@example.invalid", config)
	if err != nil {
		t.Fatalf("create OpenPGP entity: %v", err)
	}
	return entity
}

func serializePrivateEntities(t *testing.T, entities []*openpgp.Entity, resign bool, created time.Time) []byte {
	t.Helper()
	var out bytes.Buffer
	armored, err := armor.Encode(&out, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatalf("create private-key armor: %v", err)
	}
	config := &packet.Config{DefaultHash: crypto.SHA256, Time: func() time.Time { return created }}
	for _, entity := range entities {
		if resign {
			err = entity.SerializePrivate(armored, config)
		} else {
			err = entity.SerializePrivateWithoutSigning(armored, config)
		}
		if err != nil {
			t.Fatalf("serialize private key: %v", err)
		}
	}
	if err := armored.Close(); err != nil {
		t.Fatalf("close private-key armor: %v", err)
	}
	return out.Bytes()
}
