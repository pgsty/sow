package verify

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

// ErrAPTSignatureValidation is intentionally secret-free.
var ErrAPTSignatureValidation = errors.New("APT signature validation failed")

// APTVerifier verifies InRelease and Release.gpg with one public OpenPGP
// entity. It lets sow verify/fsck remain read-only and avoids loading a private
// signing key merely to validate repository metadata.
type APTVerifier struct {
	keyring openpgp.EntityList
}

// NewAPTVerifier accepts one armored or binary public/private entity. Private
// material is tolerated for compatibility but never used.
func NewAPTVerifier(key io.Reader) (*APTVerifier, error) {
	if key == nil {
		return nil, ErrAPTSignatureValidation
	}
	data, err := io.ReadAll(io.LimitReader(key, aptSignatureLimit+1))
	if err != nil || int64(len(data)) > aptSignatureLimit {
		return nil, ErrAPTSignatureValidation
	}
	entities, armoredErr := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
	if armoredErr != nil {
		entities, err = openpgp.ReadKeyRing(bytes.NewReader(data))
		if err != nil {
			return nil, ErrAPTSignatureValidation
		}
	}
	if len(entities) != 1 || entities[0] == nil || entities[0].PrimaryKey == nil {
		return nil, ErrAPTSignatureValidation
	}
	return &APTVerifier{keyring: entities}, nil
}

// Verify checks that both signature forms authenticate the exact Release
// bytes at the caller-selected verification time.
func (v *APTVerifier) Verify(release, inRelease, detached []byte, at time.Time) error {
	if v == nil || len(v.keyring) != 1 || at.IsZero() {
		return ErrAPTSignatureValidation
	}
	plaintext, err := v.VerifyInRelease(inRelease, at)
	if err != nil || !bytes.Equal(plaintext, release) {
		return ErrAPTSignatureValidation
	}
	config := &packet.Config{DefaultHash: crypto.SHA256, Time: func() time.Time { return at.UTC() }}
	if _, err := openpgp.CheckArmoredDetachedSignature(v.keyring, bytes.NewReader(release), bytes.NewReader(detached), config); err != nil {
		return ErrAPTSignatureValidation
	}
	return nil
}

// VerifyInRelease authenticates the clear-signed metadata form fetched by an
// apt client and returns a private copy of the exact Release plaintext.
func (v *APTVerifier) VerifyInRelease(inRelease []byte, at time.Time) ([]byte, error) {
	if v == nil || len(v.keyring) != 1 || at.IsZero() {
		return nil, ErrAPTSignatureValidation
	}
	block, rest := clearsign.Decode(inRelease)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrAPTSignatureValidation
	}
	config := &packet.Config{DefaultHash: crypto.SHA256, Time: func() time.Time { return at.UTC() }}
	if _, err := block.VerifySignature(v.keyring, config); err != nil {
		return nil, ErrAPTSignatureValidation
	}
	return append([]byte(nil), block.Plaintext...), nil
}
