package yumrepo

//lint:file-ignore SA1019 RPM verification must accept legacy DSA signatures; SOW never generates them.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/dsa"
	"crypto/rsa"
	_ "crypto/sha1" // Legacy RPM DSA/RSA signatures commonly use OpenPGP SHA-1.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"math/bits"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	crpm "github.com/cavaliergopher/rpm"
	"github.com/pgsty/sow/internal/workmetrics"
)

const maxEmbeddedRPMSignatureBytes = 1 << 20

// MaxRPMSignatureClockSkew is the only future-time tolerance applied to an
// embedded package signature. The caller-supplied observation time is not used
// to re-evaluate historical key expiry: verification runs at the signature's
// authenticated creation time instead.
const MaxRPMSignatureClockSkew = 5 * time.Minute

const (
	rpmTagPayloadDigest     = 5092
	rpmTagPayloadDigestAlgo = 5093
	rpmHashSHA224           = 11
	rpmHashSHA256           = 8
	rpmHashSHA384           = 9
	rpmHashSHA512           = 10
)

var embeddedRPMSignatureTags = [...]struct {
	id   int
	name string
}{
	{267, "RPMSIGTAG_DSA"},
	{268, "RPMSIGTAG_RSA"},
	{1002, "RPMSIGTAG_PGP"},
	{1005, "RPMSIGTAG_GPG"},
	{1006, "RPMSIGTAG_PGP5"},
}

type embeddedRPMSignaturePacket struct {
	metadata EmbeddedRPMSignature
	packet   []byte
}

// InspectEmbeddedRPMSignatures parses the bounded RPM signature header and
// records the exact OpenPGP signature packet identities and public metadata.
// It does not verify a signature against a package-signing keyring. Callers
// must separately bind r to already size/SHA-256-verified artifact bytes.
func InspectEmbeddedRPMSignatures(ctx context.Context, r io.Reader) ([]EmbeddedRPMSignature, error) {
	packets, err := inspectEmbeddedRPMSignaturePackets(ctx, r)
	if err != nil {
		return nil, err
	}
	signatures := make([]EmbeddedRPMSignature, len(packets))
	for i := range packets {
		signatures[i] = packets[i].metadata
	}
	return signatures, nil
}

func inspectEmbeddedRPMSignaturePackets(ctx context.Context, r io.Reader) ([]embeddedRPMSignaturePacket, error) {
	if ctx == nil {
		return nil, errors.New("yumrepo: nil context")
	}
	if r == nil {
		return nil, fmt.Errorf("%w: nil RPM reader", ErrEmbeddedSignature)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	signatureHeader, err := crpm.ReadSignatureHeader(&contextReader{ctx: ctx, r: r})
	if err != nil {
		return nil, fmt.Errorf("%w: parse RPM signature header: %w", ErrEmbeddedSignature, err)
	}
	signatures := make([]embeddedRPMSignaturePacket, 0, len(embeddedRPMSignatureTags))
	for _, known := range embeddedRPMSignatureTags {
		tag := signatureHeader.GetTag(known.id)
		if tag == nil {
			continue
		}
		if tag.Type != crpm.TagTypeBinary {
			return nil, fmt.Errorf("%w: %s must be a binary tag", ErrEmbeddedSignature, known.name)
		}
		packet := tag.Bytes()
		if len(packet) == 0 || len(packet) > maxEmbeddedRPMSignatureBytes {
			return nil, fmt.Errorf("%w: %s packet size %d is outside 1..%d", ErrEmbeddedSignature, known.name, len(packet), maxEmbeddedRPMSignatureBytes)
		}
		version, publicKeyAlgorithm, hashAlgorithm, issuerKeyID, err := parseOpenPGPSignaturePacket(packet)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrEmbeddedSignature, known.name, err)
		}
		createdAt, err := parseOpenPGPSignatureCreationTime(packet)
		if err != nil {
			return nil, fmt.Errorf("%w: %s creation time: %v", ErrEmbeddedSignature, known.name, err)
		}
		if known.id == 267 && publicKeyAlgorithm != 17 {
			return nil, fmt.Errorf("%w: %s carries public-key algorithm %d, want DSA", ErrEmbeddedSignature, known.name, publicKeyAlgorithm)
		}
		if known.id == 268 && publicKeyAlgorithm != 1 && publicKeyAlgorithm != 3 {
			return nil, fmt.Errorf("%w: %s carries public-key algorithm %d, want RSA", ErrEmbeddedSignature, known.name, publicKeyAlgorithm)
		}
		digest := sha256.Sum256(packet)
		metadata := EmbeddedRPMSignature{
			HeaderTag: known.name, HeaderTagID: known.id, PacketSHA256: hex.EncodeToString(digest[:]),
			PacketSize: int64(len(packet)), PacketVersion: version,
			PublicKeyAlgorithm: publicKeyAlgorithm, HashAlgorithm: hashAlgorithm, IssuerKeyID: issuerKeyID,
			SignatureCreatedAt: createdAt,
		}
		signatures = append(signatures, embeddedRPMSignaturePacket{
			metadata: metadata,
			packet:   append([]byte(nil), packet...),
		})
	}
	if len(signatures) == 0 {
		return nil, fmt.Errorf("%w: %w: RPM signature header contains no PGP, GPG, RSA, or DSA signature tag", ErrEmbeddedSignature, ErrUnsignedRPMPackage)
	}
	return signatures, nil
}

// RPMSignatureNeutralDigest hashes the immutable main header and payload while
// excluding the mutable RPM signature header. It lets callers prove that an
// external signing helper changed only signature material.
func RPMSignatureNeutralOffset(ctx context.Context, r io.ReadSeeker) (_ int64, resultErr error) {
	if ctx == nil || r == nil {
		return 0, fmt.Errorf("%w: invalid RPM reader", ErrInvalidPackage)
	}
	original, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, fmt.Errorf("%w: read RPM offset: %v", ErrInvalidPackage, err)
	}
	defer func() {
		if _, err := r.Seek(original, io.SeekStart); err != nil && resultErr == nil {
			resultErr = fmt.Errorf("%w: restore RPM offset: %v", ErrInvalidPackage, err)
		}
	}()
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("%w: seek RPM start: %v", ErrInvalidPackage, err)
	}
	if _, err := crpm.ReadSignatureHeader(&contextReader{ctx: ctx, r: r}); err != nil {
		return 0, fmt.Errorf("%w: parse RPM signature header: %v", ErrInvalidPackage, err)
	}
	offset, err := r.Seek(0, io.SeekCurrent)
	if err != nil || offset <= 0 {
		return 0, fmt.Errorf("%w: locate RPM signature-neutral bytes: %v", ErrInvalidPackage, err)
	}
	return offset, nil
}

func RPMSignatureNeutralDigest(ctx context.Context, r io.ReadSeeker) (_ string, resultErr error) {
	if ctx == nil {
		return "", errors.New("yumrepo: nil context")
	}
	if r == nil {
		return "", fmt.Errorf("%w: nil RPM reader", ErrInvalidPackage)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	original, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", fmt.Errorf("%w: read RPM offset: %v", ErrInvalidPackage, err)
	}
	defer func() {
		if _, err := r.Seek(original, io.SeekStart); err != nil && resultErr == nil {
			resultErr = fmt.Errorf("%w: restore RPM offset: %v", ErrInvalidPackage, err)
		}
	}()
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("%w: seek RPM start: %v", ErrInvalidPackage, err)
	}
	if _, err := crpm.ReadSignatureHeader(&contextReader{ctx: ctx, r: r}); err != nil {
		return "", fmt.Errorf("%w: parse RPM signature header: %v", ErrInvalidPackage, err)
	}
	h := sha256.New()
	read, err := io.Copy(h, &contextReader{ctx: ctx, r: r})
	if err != nil {
		return "", fmt.Errorf("%w: hash RPM signature-neutral bytes: %v", ErrInvalidPackage, err)
	}
	workmetrics.RecordFullPackageRead(ctx, read)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyEmbeddedRPMSignatures verifies every recognized signature packet in a
// complete RPM against keyring without loading the package payload in memory.
// r is always addressed from offset zero and its original offset is restored.
// at is the caller's observation time. Every packet must carry a non-zero,
// hashed creation time no later than at+MaxRPMSignatureClockSkew. Historical
// key validity is evaluated at that authenticated creation time, not at at.
//
// RPM's modern RPMSIGTAG_RSA/RPMSIGTAG_DSA packets sign only the raw main
// header. For those packets this function also streams and checks the SHA-2
// payload digest stored in the signed header. Historical RPMs without that tag
// are accepted only when a separately verified legacy PGP/GPG/PGP5 packet
// authenticates the main header and payload directly. All present recognized
// packets must verify, and at least one trusted path must authenticate the
// payload; unsigned packages, unknown issuers, untrusted keys and altered bytes
// fail closed with ErrRPMPackageSignature.
func VerifyEmbeddedRPMSignatures(ctx context.Context, r io.ReadSeeker, keyring openpgp.KeyRing, at time.Time) (verified []VerifiedEmbeddedRPMSignature, err error) {
	if ctx == nil {
		return nil, errors.New("yumrepo: nil context")
	}
	if r == nil {
		return nil, fmt.Errorf("%w: nil RPM reader", ErrRPMPackageSignature)
	}
	if keyring == nil {
		return nil, fmt.Errorf("%w: nil OpenPGP trust ring", ErrRPMPackageSignature)
	}
	if at.IsZero() {
		return nil, fmt.Errorf("%w: a non-zero verification time is required", ErrRPMPackageSignature)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	originalOffset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("%w: read original RPM offset: %v", ErrRPMPackageSignature, err)
	}
	defer func() {
		if _, restoreErr := r.Seek(originalOffset, io.SeekStart); restoreErr != nil && err == nil {
			verified = nil
			err = fmt.Errorf("%w: restore RPM offset: %v", ErrRPMPackageSignature, restoreErr)
		}
	}()

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("%w: seek RPM start: %v", ErrRPMPackageSignature, err)
	}
	packets, err := inspectEmbeddedRPMSignaturePackets(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRPMPackageSignature, err)
	}
	mainHeaderStart, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("%w: locate RPM main header: %v", ErrRPMPackageSignature, err)
	}
	layout, err := inspectRPMVerificationLayout(ctx, r, mainHeaderStart)
	if err != nil {
		return nil, err
	}

	verified = make([]VerifiedEmbeddedRPMSignature, 0, len(packets))
	payloadChecked := false
	payloadAuthenticated := false
	var payloadAlgorithm, payloadDigest string
	for _, candidate := range packets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		createdAt := candidate.metadata.SignatureCreatedAt
		if createdAt.IsZero() {
			return nil, fmt.Errorf("%w: %s has no authenticated signature creation time", ErrRPMPackageSignature, candidate.metadata.HeaderTag)
		}
		latestAllowed := at.UTC().Add(MaxRPMSignatureClockSkew)
		if createdAt.After(latestAllowed) {
			return nil, fmt.Errorf("%w: %s creation time %s is later than observation %s plus %s clock skew", ErrRPMPackageSignature, candidate.metadata.HeaderTag, createdAt.Format(time.RFC3339), at.UTC().Format(time.RFC3339), MaxRPMSignatureClockSkew)
		}
		coverage, signedStart, signedBytes := signedRPMRange(candidate.metadata.HeaderTagID, layout)
		if _, err := r.Seek(signedStart, io.SeekStart); err != nil {
			return nil, fmt.Errorf("%w: seek %s signed bytes: %v", ErrRPMPackageSignature, candidate.metadata.HeaderTag, err)
		}
		signed := &exactLengthReader{r: &contextReader{ctx: ctx, r: r}, remaining: signedBytes}
		var signerKey openpgp.Key
		switch candidate.metadata.PacketVersion {
		case 3:
			signerKey, err = verifyOpenPGPV3DetachedSignature(signed, candidate.packet, keyring, createdAt)
			if err != nil {
				return nil, fmt.Errorf("%w: %s is not valid under the trusted keyring: %w", ErrRPMPackageSignature, candidate.metadata.HeaderTag, err)
			}
		case 4:
			signerKey, err = verifyOpenPGPV4DetachedSignature(signed, candidate.packet, keyring, createdAt)
			if err != nil {
				return nil, fmt.Errorf("%w: %s is not valid under the trusted keyring: %w", ErrRPMPackageSignature, candidate.metadata.HeaderTag, err)
			}
		default:
			return nil, fmt.Errorf("%w: unsupported OpenPGP signature version %d", ErrRPMPackageSignature, candidate.metadata.PacketVersion)
		}
		if signed.remaining != 0 {
			return nil, fmt.Errorf("%w: %s signed range is truncated by %d bytes", ErrRPMPackageSignature, candidate.metadata.HeaderTag, signed.remaining)
		}
		if coverage == RPMSignatureCoverageHeaderPayloadDigest {
			if len(layout.payloadDigests) == 0 && layout.payloadHashAlgo == 0 {
				coverage = RPMSignatureCoverageHeader
			} else if !payloadChecked {
				payloadAlgorithm, payloadDigest, err = verifySignedRPMPayloadDigest(ctx, r, layout)
				if err != nil {
					return nil, err
				}
				payloadChecked = true
				payloadAuthenticated = true
			}
		} else {
			payloadAuthenticated = true
		}
		proof := VerifiedEmbeddedRPMSignature{
			EmbeddedRPMSignature:   candidate.metadata,
			Coverage:               coverage,
			SignedBytes:            signedBytes,
			SignerKeyID:            fmt.Sprintf("%016x", signerKey.PublicKey.KeyId),
			SignerFingerprint:      hex.EncodeToString(signerKey.PublicKey.Fingerprint),
			PublicKeyAlgorithmName: openPGPPublicKeyAlgorithmName(candidate.metadata.PublicKeyAlgorithm),
			HashAlgorithmName:      openPGPHashAlgorithmName(candidate.metadata.HashAlgorithm),
		}
		if signerKey.Entity != nil && signerKey.Entity.PrimaryKey != nil {
			proof.SignerPrimaryFingerprint = hex.EncodeToString(signerKey.Entity.PrimaryKey.Fingerprint)
		}
		if coverage == RPMSignatureCoverageHeaderPayloadDigest {
			proof.PayloadDigestAlgorithm = payloadAlgorithm
			proof.PayloadDigest = payloadDigest
		}
		verified = append(verified, proof)
	}
	if !payloadAuthenticated {
		return nil, fmt.Errorf("%w: no trusted embedded signature authenticates the RPM payload", ErrRPMPackageSignature)
	}
	return verified, nil
}

func verifyOpenPGPV3DetachedSignature(signed io.Reader, encoded []byte, keyring openpgp.KeyRing, createdAt time.Time) (openpgp.Key, error) {
	body, err := unwrapOpenPGPSignaturePacket(encoded)
	if err != nil {
		return openpgp.Key{}, err
	}
	if len(body) < 22 || body[0] != 3 || body[1] != 5 || body[2] != 0x00 {
		return openpgp.Key{}, errors.New("malformed OpenPGP v3 binary signature")
	}
	if !time.Unix(int64(binary.BigEndian.Uint32(body[3:7])), 0).UTC().Equal(createdAt) {
		return openpgp.Key{}, errors.New("OpenPGP v3 signature creation time changed during verification")
	}
	issuerKeyID := binary.BigEndian.Uint64(body[7:15])
	publicKeyAlgorithm := int(body[15])
	hashAlgorithm := int(body[16])
	hashID, err := openPGPHash(hashAlgorithm)
	if err != nil {
		return openpgp.Key{}, err
	}
	hasher := hashID.New()
	if _, err := io.Copy(hasher, signed); err != nil {
		return openpgp.Key{}, err
	}
	if _, err := hasher.Write(body[2:7]); err != nil {
		return openpgp.Key{}, err
	}
	digest := hasher.Sum(nil)
	if len(digest) < 2 || subtle.ConstantTimeCompare(digest[:2], body[17:19]) != 1 {
		return openpgp.Key{}, errors.New("OpenPGP v3 signed-hash prefix mismatch")
	}
	material := body[19:]
	first, material, err := readOpenPGPMPI(material)
	if err != nil {
		return openpgp.Key{}, err
	}
	var second []byte
	if publicKeyAlgorithm == 17 {
		second, material, err = readOpenPGPMPI(material)
		if err != nil {
			return openpgp.Key{}, err
		}
	}
	if len(material) != 0 {
		return openpgp.Key{}, errors.New("trailing OpenPGP v3 signature material")
	}

	// KeysByIdUsage rejects historical OpenPGP keys whose self-signature
	// predates the Key Flags subpacket even though RFC 4880 treats absent key
	// flags as unrestricted. Enumerate the exact issuer here, then apply usage
	// and temporal policy explicitly at the authenticated signature time.
	keys := openPGPKeysByIDAt(keyring, issuerKeyID, createdAt)
	if len(keys) == 0 {
		return openpgp.Key{}, fmt.Errorf("OpenPGP v3 signature issuer %016x is not in the trusted keyring", issuerKeyID)
	}
	var lastErr error
	for _, key := range keys {
		if key.PublicKey == nil || int(key.PublicKey.PubKeyAlgo) != publicKeyAlgorithm {
			lastErr = errors.New("trusted key uses a different public-key algorithm")
			continue
		}
		if err := validateOpenPGPSigningKeyAt(key, createdAt); err != nil {
			lastErr = err
			continue
		}
		switch publicKeyAlgorithm {
		case 1, 3:
			publicKey, ok := key.PublicKey.PublicKey.(*rsa.PublicKey)
			if !ok {
				lastErr = errors.New("trusted RSA key has an incompatible implementation")
				continue
			}
			keyBytes := (publicKey.N.BitLen() + 7) / 8
			if len(first) > keyBytes {
				lastErr = errors.New("OpenPGP RSA signature is larger than the trusted key")
				continue
			}
			padded := make([]byte, keyBytes)
			copy(padded[keyBytes-len(first):], first)
			if err := rsa.VerifyPKCS1v15(publicKey, hashID, digest, padded); err != nil {
				lastErr = errors.New("OpenPGP RSA signature verification failed")
				continue
			}
		case 17:
			publicKey, ok := key.PublicKey.PublicKey.(*dsa.PublicKey)
			if !ok {
				lastErr = errors.New("trusted DSA key has an incompatible implementation")
				continue
			}
			truncated := digest
			subgroupBytes := (publicKey.Q.BitLen() + 7) / 8
			if len(truncated) > subgroupBytes {
				truncated = truncated[:subgroupBytes]
			}
			if !dsa.Verify(publicKey, truncated, new(big.Int).SetBytes(first), new(big.Int).SetBytes(second)) {
				lastErr = errors.New("OpenPGP DSA signature verification failed")
				continue
			}
		default:
			return openpgp.Key{}, fmt.Errorf("unsupported OpenPGP v3 public-key algorithm %d", publicKeyAlgorithm)
		}
		return key, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no trusted OpenPGP v3 signing key verified the packet")
	}
	return openpgp.Key{}, lastErr
}

// verifyOpenPGPV4DetachedSignature performs the cryptographic verification at
// the packet layer, then applies SOW's historical key policy. The legacy
// high-level OpenPGP verifier evaluates the parsed latest self-certification and
// revocations even when a package signature predates a normal renewal. That can
// make a newly exported public certificate strand retained stable RPMs.
func verifyOpenPGPV4DetachedSignature(signed io.Reader, encoded []byte, keyring openpgp.KeyRing, createdAt time.Time) (openpgp.Key, error) {
	packets := packet.NewReader(bytes.NewReader(encoded))
	value, err := packets.Next()
	if err != nil {
		return openpgp.Key{}, err
	}
	signature, ok := value.(*packet.Signature)
	if !ok || signature.Version != 4 || signature.SigType != packet.SigTypeBinary || signature.IssuerKeyId == nil {
		return openpgp.Key{}, errors.New("malformed OpenPGP v4 binary signature")
	}
	if trailing, nextErr := packets.Next(); nextErr != io.EOF || trailing != nil {
		return openpgp.Key{}, errors.New("trailing OpenPGP v4 signature material")
	}
	if !signature.CreationTime.UTC().Equal(createdAt) {
		return openpgp.Key{}, errors.New("OpenPGP v4 signature creation time changed during verification")
	}
	for _, notation := range signature.Notations {
		if notation.IsCritical {
			return openpgp.Key{}, fmt.Errorf("OpenPGP v4 signature has unsupported critical notation %q", notation.Name)
		}
	}

	var selected *openpgp.Key
	var fingerprint string
	var lastErr error
	for _, candidate := range openPGPKeysByIDAt(keyring, *signature.IssuerKeyId, createdAt) {
		if candidate.PublicKey == nil || candidate.PublicKey.PubKeyAlgo != signature.PubKeyAlgo {
			lastErr = errors.New("trusted key uses a different public-key algorithm")
			continue
		}
		if err := validateOpenPGPSigningKeyAt(candidate, createdAt); err != nil {
			lastErr = err
			continue
		}
		current := hex.EncodeToString(candidate.PublicKey.Fingerprint)
		if selected != nil && current != fingerprint {
			return openpgp.Key{}, fmt.Errorf("ambiguous trusted OpenPGP v4 issuer %016x", *signature.IssuerKeyId)
		}
		copyCandidate := candidate
		selected, fingerprint = &copyCandidate, current
	}
	if selected == nil {
		if lastErr != nil {
			return openpgp.Key{}, fmt.Errorf("OpenPGP v4 signature issuer %016x has no historically valid trusted signing key: %w", *signature.IssuerKeyId, lastErr)
		}
		return openpgp.Key{}, fmt.Errorf("OpenPGP v4 signature issuer %016x has no historically valid trusted signing key", *signature.IssuerKeyId)
	}
	hasher, err := signature.PrepareVerify()
	if err != nil {
		return openpgp.Key{}, err
	}
	if _, err := io.Copy(hasher, signed); err != nil {
		return openpgp.Key{}, err
	}
	if err := selected.PublicKey.VerifySignature(hasher, signature); err != nil {
		return openpgp.Key{}, err
	}
	return *selected, nil
}

func validateOpenPGPSigningKeyAt(key openpgp.Key, at time.Time) error {
	if key.Entity == nil || key.Entity.PrimaryKey == nil || key.PublicKey == nil {
		return errors.New("trusted OpenPGP signer evidence is incomplete")
	}
	if key.Entity.PrimaryKey.CreationTime.After(at) || key.PublicKey.CreationTime.After(at) {
		return errors.New("trusted OpenPGP signer did not exist at signature creation time")
	}
	primarySignature, primaryIdentity, err := primarySelfSignatureAt(key.Entity, at)
	if err != nil {
		return err
	}
	if !key.PublicKey.CanSign() {
		return errors.New("trusted OpenPGP key algorithm cannot sign")
	}
	bindingSignature := key.SelfSignature
	if key.PublicKey == key.Entity.PrimaryKey {
		bindingSignature = primarySignature
	}
	if bindingSignature == nil {
		return errors.New("trusted OpenPGP signer has no binding self-signature")
	}
	if bindingSignature.CreationTime.After(at) || primarySignature.CreationTime.After(at) {
		return errors.New("trusted OpenPGP signer binding did not exist at signature creation time")
	}
	if bindingSignature.FlagsValid && !bindingSignature.FlagSign {
		return errors.New("trusted OpenPGP key flags do not permit signing")
	}
	if revokedAt(key.Entity.Revocations, at) || (primaryIdentity != nil && revokedAt(primaryIdentity.Revocations, at)) {
		return errors.New("trusted OpenPGP signer was revoked at signature creation time")
	}
	if key.Entity.PrimaryKey.KeyExpired(primarySignature, at) || primarySignature.SigExpired(at) {
		return errors.New("trusted OpenPGP primary key was not valid at signature creation time")
	}
	if key.PublicKey != key.Entity.PrimaryKey {
		// Historical package keyrings may expose an older binding packet that
		// the legacy parser normally discards. Authenticate the binding here on
		// every API path; VerifyKeySignature also enforces the signing-subkey
		// embedded back-signature (cross-certification).
		if err := key.Entity.PrimaryKey.VerifyKeySignature(key.PublicKey, bindingSignature); err != nil {
			return fmt.Errorf("trusted OpenPGP signing subkey binding is invalid: %w", err)
		}
		if bindingSignature.FlagSign && (bindingSignature.EmbeddedSignature == nil ||
			bindingSignature.EmbeddedSignature.CreationTime.After(at) || bindingSignature.EmbeddedSignature.SigExpired(at)) {
			return errors.New("trusted OpenPGP signing subkey cross-certification was not valid at signature creation time")
		}
		if revokedAt(key.Revocations, at) || key.PublicKey.KeyExpired(bindingSignature, at) || bindingSignature.SigExpired(at) {
			return errors.New("trusted OpenPGP signing subkey was not valid at signature creation time")
		}
	}
	signatures := []*packet.Signature{primarySignature, bindingSignature}
	if bindingSignature != nil && bindingSignature.EmbeddedSignature != nil {
		signatures = append(signatures, bindingSignature.EmbeddedSignature)
	}
	for _, signature := range signatures {
		if signature == nil {
			continue
		}
		for _, notation := range signature.Notations {
			if notation.IsCritical {
				return fmt.Errorf("trusted OpenPGP key has unsupported critical notation %q", notation.Name)
			}
		}
	}
	return nil
}

type openPGPTemporalKeyRing interface {
	KeysByIdAt(id uint64, at time.Time) []openpgp.Key
}

func openPGPKeysByIDAt(keyring openpgp.KeyRing, id uint64, at time.Time) []openpgp.Key {
	if temporal, ok := keyring.(openPGPTemporalKeyRing); ok {
		return temporal.KeysByIdAt(id, at)
	}
	return keyring.KeysById(id)
}

func primarySelfSignatureAt(entity *openpgp.Entity, at time.Time) (*packet.Signature, *openpgp.Identity, error) {
	if entity == nil || entity.PrimaryKey == nil {
		return nil, nil, errors.New("trusted OpenPGP signer evidence is incomplete")
	}
	if entity.PrimaryKey.Version == 6 {
		var selected *packet.Signature
		ambiguous := false
		for _, signature := range entity.Signatures {
			if signature == nil || signature.SigType != packet.SigTypeDirectSignature || signature.CreationTime.After(at) {
				continue
			}
			if err := entity.PrimaryKey.VerifyDirectKeySignature(signature); err != nil {
				continue
			}
			if selected == nil || signature.CreationTime.After(selected.CreationTime) {
				selected = signature
				ambiguous = false
				continue
			}
			if signature.CreationTime.Equal(selected.CreationTime) && signature != selected {
				ambiguous = true
			}
		}
		if selected == nil {
			return nil, nil, errors.New("trusted OpenPGP signer has no primary self-signature valid at signature creation time")
		}
		if ambiguous {
			return nil, nil, errors.New("trusted OpenPGP signer has ambiguous direct-key self-signatures at signature creation time")
		}
		return selected, nil, nil
	}

	var selected *packet.Signature
	var selectedIdentity *openpgp.Identity
	selectedPrimary := false
	selectedAmbiguous := false
	for _, identity := range entity.Identities {
		if identity == nil || identity.UserId == nil || revokedAt(identity.Revocations, at) {
			continue
		}
		var current *packet.Signature
		ambiguous := false
		for _, signature := range identity.Signatures {
			if !isOpenPGPCertification(signature) || signature.CreationTime.After(at) ||
				!signature.CheckKeyIdOrFingerprint(entity.PrimaryKey) {
				continue
			}
			if err := entity.PrimaryKey.VerifyUserIdSignature(identity.UserId.Id, entity.PrimaryKey, signature); err != nil {
				continue
			}
			if current == nil || signature.CreationTime.After(current.CreationTime) {
				current = signature
				ambiguous = false
				continue
			}
			if signature.CreationTime.Equal(current.CreationTime) && signature != current {
				ambiguous = true
			}
		}
		if ambiguous {
			return nil, nil, errors.New("trusted OpenPGP signer has ambiguous primary self-signatures at signature creation time")
		}
		if current == nil {
			continue
		}
		isPrimary := current.IsPrimaryId != nil && *current.IsPrimaryId
		if selected == nil || (isPrimary && !selectedPrimary) || (isPrimary == selectedPrimary && current.CreationTime.After(selected.CreationTime)) {
			selected, selectedIdentity, selectedPrimary = current, identity, isPrimary
			selectedAmbiguous = false
			continue
		}
		if isPrimary == selectedPrimary && current.CreationTime.Equal(selected.CreationTime) && current != selected {
			selectedAmbiguous = true
		}
	}
	if selected == nil {
		return nil, nil, errors.New("trusted OpenPGP signer has no primary self-signature valid at signature creation time")
	}
	if selectedAmbiguous {
		return nil, nil, errors.New("trusted OpenPGP signer has ambiguous primary identities at signature creation time")
	}
	return selected, selectedIdentity, nil
}

func isOpenPGPCertification(signature *packet.Signature) bool {
	if signature == nil {
		return false
	}
	switch signature.SigType {
	case packet.SigTypeGenericCert, packet.SigTypePersonaCert, packet.SigTypeCasualCert, packet.SigTypePositiveCert:
		return true
	default:
		return false
	}
}

func revokedAt(revocations []*packet.Signature, at time.Time) bool {
	for _, revocation := range revocations {
		if revocation == nil {
			continue
		}
		if revocation.RevocationReason == nil ||
			*revocation.RevocationReason == packet.Unknown ||
			*revocation.RevocationReason == packet.NoReason ||
			*revocation.RevocationReason == packet.KeyCompromised {
			// A compromise or an unspecified reason invalidates historical
			// signatures retroactively. Superseded/retired keys remain valid for
			// signatures made before the authenticated revocation time.
			return true
		}
		if !revocation.CreationTime.After(at) && !revocation.SigExpired(at) {
			return true
		}
	}
	return false
}

func openPGPHash(algorithm int) (crypto.Hash, error) {
	var result crypto.Hash
	switch algorithm {
	case 2:
		result = crypto.SHA1
	case 8:
		result = crypto.SHA256
	case 9:
		result = crypto.SHA384
	case 10:
		result = crypto.SHA512
	case 11:
		result = crypto.SHA224
	default:
		return 0, fmt.Errorf("unsupported OpenPGP hash algorithm %d", algorithm)
	}
	if !result.Available() {
		return 0, fmt.Errorf("OpenPGP hash algorithm %d is unavailable", algorithm)
	}
	return result, nil
}

func readOpenPGPMPI(encoded []byte) ([]byte, []byte, error) {
	if len(encoded) < 3 {
		return nil, nil, errors.New("truncated OpenPGP signature MPI")
	}
	bitLength := int(binary.BigEndian.Uint16(encoded[:2]))
	byteLength := (bitLength + 7) / 8
	if bitLength == 0 || byteLength > len(encoded)-2 {
		return nil, nil, errors.New("invalid OpenPGP signature MPI length")
	}
	value := encoded[2 : 2+byteLength]
	actualBits := (len(value)-1)*8 + bits.Len8(value[0])
	if actualBits != bitLength {
		return nil, nil, errors.New("non-canonical OpenPGP signature MPI")
	}
	return value, encoded[2+byteLength:], nil
}

func parseOpenPGPSignatureCreationTime(encoded []byte) (time.Time, error) {
	body, err := unwrapOpenPGPSignaturePacket(encoded)
	if err != nil {
		return time.Time{}, err
	}
	if len(body) == 0 {
		return time.Time{}, errors.New("empty OpenPGP signature packet")
	}
	switch body[0] {
	case 3:
		if len(body) < 7 || body[1] != 5 || body[2] != 0x00 {
			return time.Time{}, errors.New("malformed OpenPGP v3 signature creation time")
		}
		seconds := binary.BigEndian.Uint32(body[3:7])
		if seconds == 0 {
			return time.Time{}, nil
		}
		return time.Unix(int64(seconds), 0).UTC(), nil
	case 4:
		if len(body) < 8 || body[1] != 0x00 {
			return time.Time{}, errors.New("malformed OpenPGP v4 signature creation time")
		}
		hashedSize := int(binary.BigEndian.Uint16(body[4:6]))
		if hashedSize > len(body)-6 {
			return time.Time{}, errors.New("truncated OpenPGP hashed subpackets")
		}
		hashed := body[6 : 6+hashedSize]
		cursor := 6 + hashedSize
		if len(body)-cursor < 2 {
			return time.Time{}, errors.New("missing OpenPGP unhashed subpacket length")
		}
		unhashedSize := int(binary.BigEndian.Uint16(body[cursor : cursor+2]))
		cursor += 2
		if unhashedSize > len(body)-cursor {
			return time.Time{}, errors.New("truncated OpenPGP unhashed subpackets")
		}
		createdAt, found, err := signatureCreationTimeSubpacket(hashed)
		if err != nil {
			return time.Time{}, fmt.Errorf("hashed subpackets: %w", err)
		}
		if _, unhashedFound, err := signatureCreationTimeSubpacket(body[cursor : cursor+unhashedSize]); err != nil {
			return time.Time{}, fmt.Errorf("unhashed subpackets: %w", err)
		} else if unhashedFound {
			return time.Time{}, errors.New("OpenPGP signature creation time must not appear in unhashed subpackets")
		}
		if !found {
			return time.Time{}, nil
		}
		return createdAt, nil
	default:
		return time.Time{}, fmt.Errorf("unsupported OpenPGP signature packet version %d", body[0])
	}
}

func signatureCreationTimeSubpacket(subpackets []byte) (time.Time, bool, error) {
	var createdAt time.Time
	found := false
	for len(subpackets) > 0 {
		length, lengthBytes, err := openPGPSubpacketLength(subpackets)
		if err != nil {
			return time.Time{}, false, err
		}
		if length < 1 || length > len(subpackets)-lengthBytes {
			return time.Time{}, false, errors.New("invalid OpenPGP signature subpacket length")
		}
		value := subpackets[lengthBytes : lengthBytes+length]
		if value[0]&0x7f == 2 {
			if found {
				return time.Time{}, false, errors.New("duplicate OpenPGP signature creation-time subpacket")
			}
			if len(value) != 5 {
				return time.Time{}, false, errors.New("invalid OpenPGP signature creation-time subpacket")
			}
			seconds := binary.BigEndian.Uint32(value[1:])
			if seconds != 0 {
				createdAt = time.Unix(int64(seconds), 0).UTC()
			}
			found = true
		}
		subpackets = subpackets[lengthBytes+length:]
	}
	return createdAt, found, nil
}

type rpmVerificationLayout struct {
	mainHeaderStart int64
	mainHeaderEnd   int64
	fileEnd         int64
	payloadDigests  []string
	payloadHashAlgo int
}

func inspectRPMVerificationLayout(ctx context.Context, r io.ReadSeeker, wantMainHeaderStart int64) (rpmVerificationLayout, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return rpmVerificationLayout{}, fmt.Errorf("%w: seek RPM for header layout: %v", ErrRPMPackageSignature, err)
	}
	pkg, err := crpm.Read(&contextReader{ctx: ctx, r: r})
	if err != nil {
		return rpmVerificationLayout{}, fmt.Errorf("%w: parse RPM header layout: %v", ErrRPMPackageSignature, err)
	}
	mainStart, mainEnd := pkg.HeaderRange()
	if int64(mainStart) != wantMainHeaderStart || mainEnd <= mainStart {
		return rpmVerificationLayout{}, fmt.Errorf("%w: inconsistent RPM main-header offsets", ErrRPMPackageSignature)
	}
	fileEnd, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return rpmVerificationLayout{}, fmt.Errorf("%w: locate RPM end: %v", ErrRPMPackageSignature, err)
	}
	if int64(mainEnd) > fileEnd {
		return rpmVerificationLayout{}, fmt.Errorf("%w: RPM main header extends past end of file", ErrRPMPackageSignature)
	}
	layout := rpmVerificationLayout{mainHeaderStart: int64(mainStart), mainHeaderEnd: int64(mainEnd), fileEnd: fileEnd}
	digestTag := pkg.Header.GetTag(rpmTagPayloadDigest)
	algorithmTag := pkg.Header.GetTag(rpmTagPayloadDigestAlgo)
	if digestTag != nil {
		layout.payloadDigests = append([]string(nil), digestTag.StringSlice()...)
	}
	if algorithmTag != nil {
		layout.payloadHashAlgo = int(algorithmTag.Int64())
	}
	return layout, nil
}

func signedRPMRange(tagID int, layout rpmVerificationLayout) (RPMSignatureCoverage, int64, int64) {
	switch tagID {
	case 267, 268:
		return RPMSignatureCoverageHeaderPayloadDigest, layout.mainHeaderStart, layout.mainHeaderEnd - layout.mainHeaderStart
	default:
		return RPMSignatureCoverageHeaderPayload, layout.mainHeaderStart, layout.fileEnd - layout.mainHeaderStart
	}
}

func verifySignedRPMPayloadDigest(ctx context.Context, r io.ReadSeeker, layout rpmVerificationLayout) (string, string, error) {
	if len(layout.payloadDigests) != 1 {
		return "", "", fmt.Errorf("%w: signed RPM header must contain exactly one payload digest, got %d", ErrRPMPackageSignature, len(layout.payloadDigests))
	}
	digest := strings.ToLower(layout.payloadDigests[0])
	hasher, algorithm, encodedBytes, err := rpmPayloadHasher(layout.payloadHashAlgo)
	if err != nil {
		return "", "", err
	}
	if len(digest) != encodedBytes*2 {
		return "", "", fmt.Errorf("%w: signed %s payload digest has length %d, want %d", ErrRPMPackageSignature, algorithm, len(digest), encodedBytes*2)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", "", fmt.Errorf("%w: signed %s payload digest is not hexadecimal", ErrRPMPackageSignature, algorithm)
	}
	if _, err := r.Seek(layout.mainHeaderEnd, io.SeekStart); err != nil {
		return "", "", fmt.Errorf("%w: seek RPM payload: %v", ErrRPMPackageSignature, err)
	}
	payloadBytes := layout.fileEnd - layout.mainHeaderEnd
	reader := &exactLengthReader{r: &contextReader{ctx: ctx, r: r}, remaining: payloadBytes}
	if _, err := io.Copy(hasher, reader); err != nil {
		return "", "", fmt.Errorf("%w: hash RPM payload: %w", ErrRPMPackageSignature, err)
	}
	if reader.remaining != 0 {
		return "", "", fmt.Errorf("%w: RPM payload is truncated by %d bytes", ErrRPMPackageSignature, reader.remaining)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if actual != digest {
		return "", "", fmt.Errorf("%w: signed %s payload digest mismatch", ErrRPMPackageSignature, algorithm)
	}
	return algorithm, digest, nil
}

func rpmPayloadHasher(algorithm int) (hash.Hash, string, int, error) {
	switch algorithm {
	case rpmHashSHA224:
		return sha256.New224(), "SHA-224", sha256.Size224, nil
	case rpmHashSHA256:
		return sha256.New(), "SHA-256", sha256.Size, nil
	case rpmHashSHA384:
		return sha512.New384(), "SHA-384", sha512.Size384, nil
	case rpmHashSHA512:
		return sha512.New(), "SHA-512", sha512.Size, nil
	default:
		return nil, "", 0, fmt.Errorf("%w: signed RPM header uses unsupported payload digest algorithm %d", ErrRPMPackageSignature, algorithm)
	}
}

type exactLengthReader struct {
	r         io.Reader
	remaining int64
}

func (r *exactLengthReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.r.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func openPGPPublicKeyAlgorithmName(algorithm int) string {
	switch algorithm {
	case 1:
		return "RSA"
	case 3:
		return "RSA-sign-only"
	case 17:
		return "DSA"
	case 19:
		return "ECDSA"
	case 22:
		return "EdDSA"
	default:
		return fmt.Sprintf("OpenPGP-%d", algorithm)
	}
}

func openPGPHashAlgorithmName(algorithm int) string {
	switch algorithm {
	case 2:
		return crypto.SHA1.String()
	case 8:
		return crypto.SHA256.String()
	case 9:
		return crypto.SHA384.String()
	case 10:
		return crypto.SHA512.String()
	case 11:
		return crypto.SHA224.String()
	default:
		return fmt.Sprintf("OpenPGP-%d", algorithm)
	}
}

func parseOpenPGPSignaturePacket(encoded []byte) (version, publicKeyAlgorithm, hashAlgorithm int, issuerKeyID string, err error) {
	body, err := unwrapOpenPGPSignaturePacket(encoded)
	if err != nil {
		return 0, 0, 0, "", err
	}
	if len(body) == 0 {
		return 0, 0, 0, "", errors.New("empty OpenPGP signature packet")
	}
	switch body[0] {
	case 3:
		if len(body) < 19 || body[1] != 5 || body[2] != 0x00 {
			return 0, 0, 0, "", errors.New("malformed OpenPGP v3 signature body")
		}
		publicKeyAlgorithm, hashAlgorithm = int(body[15]), int(body[16])
		issuerKeyID = hex.EncodeToString(body[7:15])
		if err := validateSignatureMaterial(publicKeyAlgorithm, body[19:]); err != nil {
			return 0, 0, 0, "", err
		}
		return 3, publicKeyAlgorithm, hashAlgorithm, issuerKeyID, nil
	case 4:
		if len(body) < 10 || body[1] != 0x00 {
			return 0, 0, 0, "", errors.New("malformed OpenPGP v4 signature body")
		}
		publicKeyAlgorithm, hashAlgorithm = int(body[2]), int(body[3])
		hashedSize := int(binary.BigEndian.Uint16(body[4:6]))
		if hashedSize > len(body)-6 {
			return 0, 0, 0, "", errors.New("truncated OpenPGP hashed subpackets")
		}
		hashed := body[6 : 6+hashedSize]
		cursor := 6 + hashedSize
		if len(body)-cursor < 2 {
			return 0, 0, 0, "", errors.New("missing OpenPGP unhashed subpacket length")
		}
		unhashedSize := int(binary.BigEndian.Uint16(body[cursor : cursor+2]))
		cursor += 2
		if unhashedSize > len(body)-cursor {
			return 0, 0, 0, "", errors.New("truncated OpenPGP unhashed subpackets")
		}
		unhashed := body[cursor : cursor+unhashedSize]
		cursor += unhashedSize
		if len(body)-cursor < 2 {
			return 0, 0, 0, "", errors.New("missing OpenPGP signed-hash prefix")
		}
		cursor += 2
		hashedIssuer, err := signatureIssuerKeyID(hashed)
		if err != nil {
			return 0, 0, 0, "", fmt.Errorf("hashed subpackets: %w", err)
		}
		unhashedIssuer, err := signatureIssuerKeyID(unhashed)
		if err != nil {
			return 0, 0, 0, "", fmt.Errorf("unhashed subpackets: %w", err)
		}
		if hashedIssuer != "" && unhashedIssuer != "" && hashedIssuer != unhashedIssuer {
			return 0, 0, 0, "", errors.New("conflicting OpenPGP issuer key IDs")
		}
		issuerKeyID = hashedIssuer
		if issuerKeyID == "" {
			issuerKeyID = unhashedIssuer
		}
		if err := validateSignatureMaterial(publicKeyAlgorithm, body[cursor:]); err != nil {
			return 0, 0, 0, "", err
		}
		return 4, publicKeyAlgorithm, hashAlgorithm, issuerKeyID, nil
	default:
		return 0, 0, 0, "", fmt.Errorf("unsupported OpenPGP signature packet version %d", body[0])
	}
}

func unwrapOpenPGPSignaturePacket(encoded []byte) ([]byte, error) {
	if len(encoded) < 2 || encoded[0]&0x80 == 0 {
		return nil, errors.New("invalid OpenPGP packet header")
	}
	header := encoded[0]
	offset := 1
	var length uint64
	if header&0x40 == 0 {
		if (header>>2)&0x0f != 2 {
			return nil, errors.New("OpenPGP packet is not a signature")
		}
		switch header & 0x03 {
		case 0:
			length = uint64(encoded[offset])
			offset++
		case 1:
			if len(encoded)-offset < 2 {
				return nil, errors.New("truncated OpenPGP packet length")
			}
			length = uint64(binary.BigEndian.Uint16(encoded[offset : offset+2]))
			offset += 2
		case 2:
			if len(encoded)-offset < 4 {
				return nil, errors.New("truncated OpenPGP packet length")
			}
			length = uint64(binary.BigEndian.Uint32(encoded[offset : offset+4]))
			offset += 4
		case 3:
			length = uint64(len(encoded) - offset)
		}
	} else {
		if header&0x3f != 2 {
			return nil, errors.New("OpenPGP packet is not a signature")
		}
		first := encoded[offset]
		offset++
		switch {
		case first < 192:
			length = uint64(first)
		case first <= 223:
			if len(encoded) <= offset {
				return nil, errors.New("truncated OpenPGP packet length")
			}
			length = uint64(first-192)<<8 + uint64(encoded[offset]) + 192
			offset++
		case first == 255:
			if len(encoded)-offset < 4 {
				return nil, errors.New("truncated OpenPGP packet length")
			}
			length = uint64(binary.BigEndian.Uint32(encoded[offset : offset+4]))
			offset += 4
		default:
			return nil, errors.New("partial-body OpenPGP signature packet is not canonical for RPM")
		}
	}
	if length != uint64(len(encoded)-offset) {
		return nil, errors.New("OpenPGP signature packet length does not consume the RPM tag")
	}
	return encoded[offset:], nil
}

func signatureIssuerKeyID(subpackets []byte) (string, error) {
	issuer := ""
	for len(subpackets) > 0 {
		length, lengthBytes, err := openPGPSubpacketLength(subpackets)
		if err != nil {
			return "", err
		}
		if length < 1 || length > len(subpackets)-lengthBytes {
			return "", errors.New("invalid OpenPGP signature subpacket length")
		}
		packet := subpackets[lengthBytes : lengthBytes+length]
		tag := packet[0] & 0x7f
		candidate := ""
		switch tag {
		case 16: // Issuer Key ID.
			if len(packet) != 9 {
				return "", errors.New("invalid OpenPGP issuer key ID subpacket")
			}
			candidate = hex.EncodeToString(packet[1:])
		case 33: // Issuer Fingerprint; the key ID is its low 64 bits.
			// A v4 signature can identify only a v4 issuer here: one type
			// octet, one key-version octet and the exact 20-byte v4
			// fingerprint defined by RFC 9580 section 5.2.3.35.
			if len(packet) != 22 || packet[1] != 4 {
				return "", errors.New("invalid OpenPGP issuer fingerprint subpacket")
			}
			candidate = hex.EncodeToString(packet[len(packet)-8:])
		}
		if candidate != "" {
			if issuer != "" && issuer != candidate {
				return "", errors.New("conflicting OpenPGP issuer subpackets")
			}
			issuer = candidate
		}
		subpackets = subpackets[lengthBytes+length:]
	}
	return issuer, nil
}

func openPGPSubpacketLength(encoded []byte) (length, consumed int, err error) {
	if len(encoded) == 0 {
		return 0, 0, errors.New("missing OpenPGP signature subpacket length")
	}
	first := encoded[0]
	switch {
	case first < 192:
		return int(first), 1, nil
	case first <= 223:
		if len(encoded) < 2 {
			return 0, 0, errors.New("truncated OpenPGP signature subpacket length")
		}
		return int(first-192)<<8 + int(encoded[1]) + 192, 2, nil
	case first == 255:
		if len(encoded) < 5 {
			return 0, 0, errors.New("truncated OpenPGP signature subpacket length")
		}
		value := binary.BigEndian.Uint32(encoded[1:5])
		if uint64(value) > uint64(^uint(0)>>1) {
			return 0, 0, errors.New("OpenPGP signature subpacket length overflows int")
		}
		return int(value), 5, nil
	default:
		return 0, 0, errors.New("partial-body length is invalid for an OpenPGP signature subpacket")
	}
}

func validateSignatureMaterial(publicKeyAlgorithm int, encoded []byte) error {
	want := 0
	switch publicKeyAlgorithm {
	case 1, 3: // RSA.
		want = 1
	case 17, 19, 22: // DSA, ECDSA, EdDSA.
		want = 2
	default:
		return fmt.Errorf("unsupported OpenPGP signature public-key algorithm %d", publicKeyAlgorithm)
	}
	for i := 0; i < want; i++ {
		if len(encoded) < 3 {
			return errors.New("truncated OpenPGP signature MPI")
		}
		bitLength := int(binary.BigEndian.Uint16(encoded[:2]))
		byteLength := (bitLength + 7) / 8
		if bitLength == 0 || byteLength > len(encoded)-2 {
			return errors.New("invalid OpenPGP signature MPI length")
		}
		value := encoded[2 : 2+byteLength]
		actualBits := (len(value)-1)*8 + bits.Len8(value[0])
		if actualBits != bitLength {
			return errors.New("non-canonical OpenPGP signature MPI")
		}
		encoded = encoded[2+byteLength:]
	}
	if len(encoded) != 0 {
		return errors.New("trailing bytes after OpenPGP signature material")
	}
	return nil
}
