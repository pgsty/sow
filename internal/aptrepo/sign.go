package aptrepo

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
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

// Verifier is the public-only half used to authenticate a retained Built APT
// Generation after the Desired signing key has rotated.
type Verifier struct {
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

// NewVerifier accepts exactly one armored or binary public/private OpenPGP
// entity. No private material is required or retained by this verification
// path.
func NewVerifier(key io.Reader) (*Verifier, error) {
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
	if err != nil || len(entities) != 1 || entities[0] == nil || entities[0].PrimaryKey == nil {
		return nil, ErrInvalidSigningKey
	}
	return &Verifier{entity: entities[0]}, nil
}

func NewVerifierBytes(key []byte) (*Verifier, error) {
	return NewVerifier(bytes.NewReader(key))
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
			if !deterministicSignatureAlgorithm(key.PublicKey.PubKeyAlgo) {
				return ErrSigningFailed
			}
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
	if s == nil {
		return ErrSigningFailed
	}
	return verifyMetadataSignatures(s.entity, release, inRelease, detached, at, false)
}

func (v *Verifier) Verify(release, inRelease, detached []byte, at time.Time) error {
	if v == nil {
		return ErrSigningFailed
	}
	return verifyMetadataSignatures(v.entity, release, inRelease, detached, at, false)
}

// VerifyForPublication also checks the digest accepted for a new publication.
// Verify remains suitable for historical integrity and frozen recovery.
func (v *Verifier) VerifyForPublication(release, inRelease, detached []byte, at time.Time) error {
	if v == nil {
		return ErrSigningFailed
	}
	return verifyMetadataSignatures(v.entity, release, inRelease, detached, at, true)
}

func verifyMetadataSignatures(entity *openpgp.Entity, release, inRelease, detached []byte, at time.Time, publication bool) error {
	if entity == nil || at.IsZero() {
		return ErrSigningFailed
	}
	block, rest := clearsign.Decode(inRelease)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || !sameClearsignedRelease(block.Plaintext, release) {
		return ErrSigningFailed
	}
	keyring := openpgp.EntityList{entity}
	config := signingConfig(at)
	clearSignature, _, err := openpgp.VerifyDetachedSignature(keyring, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, config)
	if err != nil {
		return ErrSigningFailed
	}
	armored, err := armor.Decode(bytes.NewReader(detached))
	if err != nil || armored.Type != openpgp.SignatureType {
		return ErrSigningFailed
	}
	detachedSignature, _, err := openpgp.VerifyDetachedSignature(keyring, bytes.NewReader(release), armored.Body, config)
	if err != nil {
		return ErrSigningFailed
	}
	if publication && (!publicationSignatureHash(clearSignature.Hash) || !publicationSignatureHash(detachedSignature.Hash)) {
		return fmt.Errorf("%w: new APT publication requires SHA-256 or stronger metadata signatures; rebuild the Dist", ErrSigningFailed)
	}
	return nil
}

func publicationSignatureHash(hash crypto.Hash) bool {
	return hash == crypto.SHA256 || hash == crypto.SHA384 || hash == crypto.SHA512
}

func signingConfig(at time.Time) *packet.Config {
	at = at.UTC()
	randomizedNotation := false
	return &packet.Config{
		DefaultHash:                           crypto.SHA256,
		Time:                                  func() time.Time { return at },
		NonDeterministicSignaturesViaNotation: &randomizedNotation,
	}
}

func deterministicSignatureAlgorithm(algorithm packet.PublicKeyAlgorithm) bool {
	switch algorithm {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly, packet.PubKeyAlgoEdDSA, packet.PubKeyAlgoEd25519, packet.PubKeyAlgoEd448:
		return true
	default:
		return false
	}
}

// RFC 9580 excludes the final line ending before the signature delimiter.
// GnuPG omits it from decoded Plaintext; our encoder retains it. Accept only
// this single difference, never arbitrary whitespace normalization.
func sameClearsignedRelease(plaintext, release []byte) bool {
	return bytes.Equal(plaintext, release) || len(release) > 0 && release[len(release)-1] == '\n' && bytes.Equal(plaintext, release[:len(release)-1])
}
