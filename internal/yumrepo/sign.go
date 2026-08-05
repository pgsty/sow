package yumrepo

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const maxOpenPGPKeyBytes = 16 << 20

// OpenPGPKey is an io-injected, single-key detached signer/verifier backed by
// ProtonMail/go-crypto. It never shells out to gpg and never writes key bytes.
type OpenPGPKey struct {
	entities openpgp.EntityList
	signer   *openpgp.Entity
	config   packet.Config
}

// NewOpenPGPSigner reads exactly one armored or binary private OpenPGP entity.
// Encrypted primary/subkeys are decrypted in memory with passphrase. at fixes
// the signature creation time; callers should use the generation's committed
// time to make retries reproducible.
func NewOpenPGPSigner(key io.Reader, passphrase []byte, at time.Time) (*OpenPGPKey, error) {
	entities, err := readSingleKey(key)
	if err != nil {
		return nil, err
	}
	entity := entities[0]
	if entity.PrivateKey == nil {
		return nil, errorsPrivateKeyRequired()
	}
	if entity.PrivateKey.Encrypted {
		if err := entity.PrivateKey.Decrypt(passphrase); err != nil {
			return nil, fmt.Errorf("yumrepo: decrypt OpenPGP primary key: %w", err)
		}
	}
	for i := range entity.Subkeys {
		private := entity.Subkeys[i].PrivateKey
		if private != nil && private.Encrypted {
			if err := private.Decrypt(passphrase); err != nil {
				return nil, fmt.Errorf("yumrepo: decrypt OpenPGP subkey: %w", err)
			}
		}
	}
	if at.IsZero() {
		return nil, errorsSigningTimeRequired()
	}
	signingKey, ok := entity.SigningKey(at)
	if !ok || signingKey.PrivateKey == nil || signingKey.PrivateKey.Encrypted {
		return nil, errorsPrivateKeyRequired()
	}
	if !DeterministicMetadataSignatureAlgorithm(signingKey.PublicKey.PubKeyAlgo) {
		return nil, fmt.Errorf("yumrepo: metadata signing key algorithm %d is not retry-deterministic", signingKey.PublicKey.PubKeyAlgo)
	}
	return &OpenPGPKey{
		entities: entities,
		signer:   entity,
		config:   yumSigningConfig(at),
	}, nil
}

// NewOpenPGPVerifier reads exactly one armored or binary public/private entity.
func NewOpenPGPVerifier(key io.Reader, at time.Time) (*OpenPGPKey, error) {
	entities, err := readSingleKey(key)
	if err != nil {
		return nil, err
	}
	if at.IsZero() {
		return nil, errorsSigningTimeRequired()
	}
	return &OpenPGPKey{
		entities: entities,
		config:   yumSigningConfig(at),
	}, nil
}

// NewOpenPGPVerifierForFingerprint selects one public certificate from a
// multi-identity trust bundle. This keeps the single-signer metadata policy
// while proving against the exact aggregate bundle imported by repository
// clients rather than a different repo-local copy of the same primary key.
func NewOpenPGPVerifierForFingerprint(key io.Reader, fingerprint string, at time.Time) (*OpenPGPKey, error) {
	if key == nil {
		return nil, fmt.Errorf("yumrepo: nil OpenPGP key reader")
	}
	decoded, err := hex.DecodeString(fingerprint)
	if err != nil || (len(decoded) != 20 && len(decoded) != 32) || fingerprint != strings.ToLower(fingerprint) {
		return nil, fmt.Errorf("yumrepo: invalid lowercase OpenPGP primary fingerprint")
	}
	data, err := io.ReadAll(io.LimitReader(key, maxOpenPGPKeyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("yumrepo: read OpenPGP trust bundle: %w", err)
	}
	if len(data) == 0 || len(data) > maxOpenPGPKeyBytes {
		return nil, fmt.Errorf("yumrepo: OpenPGP trust bundle is empty or exceeds %d bytes", maxOpenPGPKeyBytes)
	}
	entities, err := ParsePublicKeyring(data)
	if err != nil {
		return nil, err
	}
	var selected *openpgp.Entity
	for _, entity := range entities {
		if entity != nil && entity.PrimaryKey != nil && bytes.Equal(entity.PrimaryKey.Fingerprint, decoded) {
			if selected != nil {
				return nil, fmt.Errorf("yumrepo: aggregate trust bundle repeats primary fingerprint %s", fingerprint)
			}
			selected = entity
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("yumrepo: aggregate trust bundle lacks primary fingerprint %s", fingerprint)
	}
	if at.IsZero() {
		return nil, errorsSigningTimeRequired()
	}
	return &OpenPGPKey{entities: openpgp.EntityList{selected}, config: yumSigningConfig(at)}, nil
}

// yumSigningConfig keeps detached metadata signatures deterministic and
// consumable by the frozen yum 3.4.3 client. The compatibility switches only
// make standard creation-time and key-flag subpackets non-critical; SHA-256,
// the signer identity, and all cryptographic verification remain unchanged.
func yumSigningConfig(at time.Time) packet.Config {
	randomizedNotation := false
	return packet.Config{
		DefaultHash:                           crypto.SHA256,
		Time:                                  func() time.Time { return at.UTC() },
		NonDeterministicSignaturesViaNotation: &randomizedNotation,
		InsecureGenerateNonCriticalKeyFlags:   true,
		InsecureGenerateNonCriticalSignatureCreationTime: true,
	}
}

// DeterministicMetadataSignatureAlgorithm reports algorithms whose OpenPGP
// signature primitive is deterministic for fixed message bytes and creation
// time. DSA/ECDSA are intentionally excluded: retrying a preview/build with
// fresh entropy would change repository file identities.
func DeterministicMetadataSignatureAlgorithm(algorithm packet.PublicKeyAlgorithm) bool {
	switch algorithm {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly, packet.PubKeyAlgoEdDSA, packet.PubKeyAlgoEd25519, packet.PubKeyAlgoEd448:
		return true
	default:
		return false
	}
}

func errorsPrivateKeyRequired() error {
	return fmt.Errorf("yumrepo: OpenPGP key has no usable decrypted private signing key")
}

func errorsSigningTimeRequired() error {
	return fmt.Errorf("yumrepo: a non-zero OpenPGP signing/verification time is required")
}

func readSingleKey(reader io.Reader) (openpgp.EntityList, error) {
	if reader == nil {
		return nil, fmt.Errorf("yumrepo: nil OpenPGP key reader")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxOpenPGPKeyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("yumrepo: read OpenPGP key: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("yumrepo: empty OpenPGP key")
	}
	if len(data) > maxOpenPGPKeyBytes {
		return nil, fmt.Errorf("yumrepo: OpenPGP key exceeds %d bytes", maxOpenPGPKeyBytes)
	}
	var entities openpgp.EntityList
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN PGP")) {
		entities, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(trimmed))
	} else {
		entities, err = openpgp.ReadKeyRing(bytes.NewReader(data))
	}
	if err != nil {
		return nil, fmt.Errorf("yumrepo: parse OpenPGP key: %w", err)
	}
	if len(entities) != 1 {
		return nil, fmt.Errorf("yumrepo: single-key policy requires exactly one OpenPGP entity, got %d", len(entities))
	}
	return entities, nil
}

// Sign writes an ASCII-armored binary detached signature.
func (k *OpenPGPKey) Sign(ctx context.Context, message io.Reader, signature io.Writer) error {
	if k == nil || k.signer == nil {
		return errorsPrivateKeyRequired()
	}
	if ctx == nil {
		return fmt.Errorf("yumrepo: nil OpenPGP sign context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if message == nil || signature == nil {
		return fmt.Errorf("yumrepo: nil OpenPGP sign stream")
	}
	if err := openpgp.ArmoredDetachSign(signature, k.signer, &contextReader{ctx: ctx, r: message}, &k.config); err != nil {
		return fmt.Errorf("yumrepo: OpenPGP detached sign: %w", err)
	}
	return nil
}

// Verify verifies an ASCII-armored detached signature with the same single key.
func (k *OpenPGPKey) Verify(ctx context.Context, message io.Reader, signature io.Reader) error {
	if k == nil || len(k.entities) != 1 {
		return fmt.Errorf("yumrepo: no OpenPGP verification key")
	}
	if ctx == nil {
		return fmt.Errorf("yumrepo: nil OpenPGP verify context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if message == nil || signature == nil {
		return fmt.Errorf("yumrepo: nil OpenPGP verify stream")
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(k.entities, &contextReader{ctx: ctx, r: message}, signature, &k.config); err != nil {
		return fmt.Errorf("yumrepo: verify OpenPGP detached signature: %w", err)
	}
	return nil
}
