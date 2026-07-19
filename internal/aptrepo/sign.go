package aptrepo

import (
	"bytes"
	"crypto"
	"errors"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const maxSigningKeyBytes = 16 << 20

var (
	ErrInvalidSigningKey = errors.New("aptrepo: invalid signing key")
	ErrUnlockSigningKey  = errors.New("aptrepo: unable to unlock signing key")
	ErrSigningFailed     = errors.New("aptrepo: signing failed")
)

// Signer is a single-key OpenPGP signer. Key material is read through an
// io.Reader, decrypted once in memory and never rendered in returned errors.
type Signer struct {
	entity *openpgp.Entity
}

// NewSigner accepts an armored or binary private key ring containing exactly
// one entity. passphrase is used only while unlocking encrypted private keys
// and is not retained.
func NewSigner(key io.Reader, passphrase []byte) (*Signer, error) {
	if key == nil {
		return nil, ErrInvalidSigningKey
	}
	data, err := io.ReadAll(io.LimitReader(key, maxSigningKeyBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxSigningKeyBytes {
		return nil, ErrInvalidSigningKey
	}
	defer clear(data)

	var entities openpgp.EntityList
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN PGP")) {
		entities, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
	} else {
		entities, err = openpgp.ReadKeyRing(bytes.NewReader(data))
	}
	if err != nil || len(entities) != 1 || entities[0] == nil {
		return nil, ErrInvalidSigningKey
	}
	entity := entities[0]
	if entity.PrivateKey == nil {
		return nil, ErrInvalidSigningKey
	}

	needsPassphrase := entity.PrivateKey.Encrypted
	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			needsPassphrase = true
		}
	}
	if needsPassphrase && len(passphrase) == 0 {
		return nil, ErrUnlockSigningKey
	}
	if entity.PrivateKey.Encrypted {
		if err := entity.PrivateKey.Decrypt(passphrase); err != nil {
			return nil, ErrUnlockSigningKey
		}
	}
	for i := range entity.Subkeys {
		privateKey := entity.Subkeys[i].PrivateKey
		if privateKey != nil && privateKey.Encrypted {
			if err := privateKey.Decrypt(passphrase); err != nil {
				return nil, ErrUnlockSigningKey
			}
		}
	}
	if countPrivateSigningKeys(entity) != 1 {
		return nil, ErrInvalidSigningKey
	}
	return &Signer{entity: entity}, nil
}

func countPrivateSigningKeys(entity *openpgp.Entity) int {
	count := 0
	primarySignature, _ := entity.PrimarySelfSignature()
	if primarySignature != nil && primarySignature.FlagsValid && primarySignature.FlagSign && entity.PrimaryKey.PubKeyAlgo.CanSign() && entity.PrivateKey != nil {
		count++
	}
	for _, subkey := range entity.Subkeys {
		if subkey.Sig != nil && subkey.Sig.FlagsValid && subkey.Sig.FlagSign && subkey.PublicKey.PubKeyAlgo.CanSign() && subkey.PrivateKey != nil {
			count++
		}
	}
	return count
}

func NewSignerBytes(key, passphrase []byte) (*Signer, error) {
	return NewSigner(bytes.NewReader(key), passphrase)
}

// Validate preflights the single entity's signing key for a publication time
// without writing any metadata.
func (s *Signer) Validate(at time.Time) error {
	if s == nil || s.entity == nil || at.IsZero() {
		return ErrSigningFailed
	}
	at = at.UTC()
	keyIDs := []uint64{s.entity.PrimaryKey.KeyId}
	for _, subkey := range s.entity.Subkeys {
		keyIDs = append(keyIDs, subkey.PublicKey.KeyId)
	}
	usable := 0
	for _, keyID := range keyIDs {
		key, ok := s.entity.SigningKeyById(at, keyID)
		if ok && key.PrivateKey != nil && !key.PrivateKey.Encrypted {
			usable++
		}
	}
	if usable != 1 {
		return ErrSigningFailed
	}
	return nil
}

// ClearSign writes an InRelease-compatible clear-signed representation of
// message using SHA-256 and the supplied deterministic signature time.
func (s *Signer) ClearSign(w io.Writer, message io.Reader, at time.Time) error {
	if w == nil || message == nil || s.Validate(at) != nil {
		return ErrSigningFailed
	}
	config := signingConfig(at)
	key, ok := s.entity.SigningKey(at)
	if !ok || key.PrivateKey == nil || key.PrivateKey.Encrypted {
		return ErrSigningFailed
	}
	plaintext, err := clearsign.Encode(w, key.PrivateKey, config)
	if err != nil {
		return ErrSigningFailed
	}
	if _, err := io.Copy(plaintext, message); err != nil {
		_ = plaintext.Close()
		return err
	}
	if err := plaintext.Close(); err != nil {
		return ErrSigningFailed
	}
	return nil
}

// DetachedSign writes an ASCII-armored Release.gpg detached signature.
func (s *Signer) DetachedSign(w io.Writer, message io.Reader, at time.Time) error {
	if w == nil || message == nil || s.Validate(at) != nil {
		return ErrSigningFailed
	}
	if err := openpgp.ArmoredDetachSign(w, s.entity, message, signingConfig(at)); err != nil {
		return ErrSigningFailed
	}
	return nil
}

// Verify checks both APT signature forms against the exact Release bytes and
// the signer's public entity. Errors are intentionally secret-free.
func (s *Signer) Verify(release, inRelease, detached []byte, at time.Time) error {
	if s.Validate(at) != nil {
		return ErrSigningFailed
	}
	block, rest := clearsign.Decode(inRelease)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(block.Plaintext, release) {
		return ErrSigningFailed
	}
	keyring := openpgp.EntityList{s.entity}
	config := signingConfig(at)
	if _, err := block.VerifySignature(keyring, config); err != nil {
		return ErrSigningFailed
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(release), bytes.NewReader(detached), config); err != nil {
		return ErrSigningFailed
	}
	return nil
}

func signingConfig(at time.Time) *packet.Config {
	at = at.UTC()
	return &packet.Config{
		DefaultHash: crypto.SHA256,
		Time:        func() time.Time { return at },
	}
}
