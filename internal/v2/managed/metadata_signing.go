package managed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

type gpgSignerCore struct {
	identity    string
	fingerprint string
	at          time.Time
}

type gpgYUMMetadataSigner struct{ *gpgSignerCore }
type gpgAPTMetadataSigner struct{ *gpgSignerCore }
type inProcessAPTMetadataSigner struct{ signer *aptrepo.Signer }
type inProcessAPTMetadataVerifier struct{ verifier *aptrepo.Verifier }

type metadataSignerIdentity struct {
	Fingerprint string
	PublicKey   []byte
}

type metadataSignerSnapshot struct {
	RPMSigner yumrepo.DetachedSigner
	APTSigner APTMetadataSigner
	RPM       metadataSignerIdentity
	DEB       metadataSignerIdentity
}

const (
	distMetadataSignerSnapshotVersion = 1
	maxDistSignerSnapshotBytes        = 24 << 20
)

type distMetadataSignerSnapshotWire struct {
	Version     int    `json:"version"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   []byte `json:"public_key"`
}

func (signer *gpgSignerCore) Validate(ctx context.Context, _ time.Time) error {
	if signer == nil || signer.identity == "" || signer.fingerprint == "" {
		return errors.New("managed: metadata signing identity is unavailable")
	}
	if ctx == nil {
		return errors.New("managed: nil metadata signing context")
	}
	if err := validateGPGSecretIdentity(ctx, signer.fingerprint); err != nil {
		return errors.New("managed: configured metadata signing key is unavailable to gpg")
	}
	return nil
}

func newGPGSignerCoreWithPublic(ctx context.Context, identity string, at time.Time) (*gpgSignerCore, []byte, error) {
	if at.IsZero() {
		return nil, nil, errors.New("managed: gpg metadata signing time is required")
	}
	public, err := exportPublicKey(ctx, identity)
	if err != nil {
		return nil, nil, err
	}
	public, err = publicOpenPGPKeyMaterial(public)
	if err != nil {
		return nil, nil, err
	}
	entities, err := yumrepo.ParsePublicKeyring(public)
	if err != nil || len(entities) != 1 {
		return nil, nil, errors.New("managed: gpg identity must export exactly one valid OpenPGP entity")
	}
	signingKey, ok := entities[0].SigningKey(at.UTC())
	if !ok || !yumrepo.DeterministicMetadataSignatureAlgorithm(signingKey.PublicKey.PubKeyAlgo) {
		return nil, nil, errors.New("managed: gpg metadata signing key algorithm is not retry-deterministic")
	}
	fingerprints, err := yumrepo.RPMPackageKeyringPrimaryFingerprints(public)
	if err != nil || len(fingerprints) != 1 {
		return nil, nil, errors.New("managed: gpg identity must resolve to exactly one primary OpenPGP key")
	}
	core := &gpgSignerCore{identity: identity, fingerprint: strings.ToUpper(fingerprints[0]), at: at.UTC()}
	if err := core.Validate(ctx, time.Now().UTC()); err != nil {
		return nil, nil, err
	}
	return core, public, nil
}

func (signer *gpgYUMMetadataSigner) Sign(ctx context.Context, message io.Reader, signature io.Writer) error {
	return signer.runSign(ctx, []string{"--armor", "--detach-sign"}, message, signature, signer.at)
}

func (signer *gpgAPTMetadataSigner) ClearSign(ctx context.Context, output io.Writer, message io.Reader, at time.Time) error {
	return signer.runSign(ctx, []string{"--armor", "--clearsign"}, message, output, at)
}

func (signer *gpgAPTMetadataSigner) DetachedSign(ctx context.Context, output io.Writer, message io.Reader, at time.Time) error {
	return signer.runSign(ctx, []string{"--armor", "--detach-sign"}, message, output, at)
}

func (signer *gpgSignerCore) runSign(ctx context.Context, operation []string, message io.Reader, output io.Writer, at time.Time) error {
	if ctx == nil || message == nil || output == nil || at.IsZero() {
		return errors.New("managed: invalid gpg signing request")
	}
	if err := signer.Validate(ctx, time.Now()); err != nil {
		return err
	}
	gpg, _ := exec.LookPath("gpg")
	args := []string{"--batch", "--no-tty", "--yes", "--faked-system-time", strconv.FormatInt(at.UTC().Unix(), 10), "--local-user", signer.fingerprint, "--output", "-"}
	args = append(args, operation...)
	command := exec.CommandContext(ctx, gpg, args...)
	command.Stdin, command.Stdout, command.Stderr = message, output, io.Discard
	if err := command.Run(); err != nil {
		return fmt.Errorf("managed: gpg metadata signing failed: %w", err)
	}
	return nil
}

func (signer *gpgYUMMetadataSigner) Verify(ctx context.Context, message io.Reader, signature io.Reader) error {
	messageBytes, err := io.ReadAll(io.LimitReader(message, 64<<20))
	if err != nil {
		return err
	}
	signatureBytes, err := io.ReadAll(io.LimitReader(signature, maxManagedKeyBytes+1))
	if err != nil || len(signatureBytes) > maxManagedKeyBytes {
		return errors.New("managed: detached metadata signature is unbounded")
	}
	return verifyGPGDetached(ctx, messageBytes, signatureBytes, signer.fingerprint)
}

// Verify satisfies APTMetadataSigner. gpg --decrypt both authenticates the
// clear signature and returns the exact Release plaintext for byte comparison.
func (signer *gpgAPTMetadataSigner) Verify(ctx context.Context, release, inRelease, detached []byte, _ time.Time) error {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, gpg, "--batch", "--no-tty", "--status-fd", "2", "--decrypt")
	command.Stdin = bytes.NewReader(inRelease)
	var plaintext bytes.Buffer
	var status bytes.Buffer
	command.Stdout, command.Stderr = &plaintext, &status
	if err := command.Run(); err != nil || !bytes.Equal(plaintext.Bytes(), release) || !gpgStatusMatchesFingerprint(status.String(), signer.fingerprint) {
		return errors.New("managed: InRelease verification failed")
	}
	return verifyGPGDetached(ctx, release, detached, signer.fingerprint)
}

func (signer *inProcessAPTMetadataSigner) Validate(ctx context.Context, at time.Time) error {
	if ctx == nil || ctx.Err() != nil || signer == nil || signer.signer == nil {
		return context.Canceled
	}
	return signer.signer.Validate(at)
}

func (signer *inProcessAPTMetadataSigner) ClearSign(ctx context.Context, output io.Writer, message io.Reader, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return signer.signer.ClearSign(output, message, at)
}

func (signer *inProcessAPTMetadataSigner) DetachedSign(ctx context.Context, output io.Writer, message io.Reader, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return signer.signer.DetachedSign(output, message, at)
}

func (signer *inProcessAPTMetadataSigner) Verify(ctx context.Context, release, inRelease, detached []byte, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return signer.signer.Verify(release, inRelease, detached, at)
}

func (verifier *inProcessAPTMetadataVerifier) Verify(ctx context.Context, release, inRelease, detached []byte, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if verifier == nil || verifier.verifier == nil {
		return errors.New("managed: APT metadata verifier is unavailable")
	}
	return verifier.verifier.Verify(release, inRelease, detached, at)
}

func verifyGPGDetached(ctx context.Context, message, signature []byte, fingerprint string) error {
	root, err := os.MkdirTemp("", "sow-gpg-verify-")
	if err != nil {
		return err
	}
	defer func() { _ = removeOwnedDirectory(root, filepath.Dir(root)) }()
	messagePath := root + "/message"
	signaturePath := root + "/signature"
	if err := writeAtomic(messagePath, message, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(signaturePath, signature, 0o600); err != nil {
		return err
	}
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, gpg, "--batch", "--no-tty", "--status-fd", "2", "--verify", signaturePath, messagePath)
	var status bytes.Buffer
	command.Stdout, command.Stderr = io.Discard, &status
	if err := command.Run(); err != nil || !gpgStatusMatchesFingerprint(status.String(), fingerprint) {
		return errors.New("managed: detached metadata signature verification failed")
	}
	return nil
}

func gpgStatusMatchesFingerprint(status, fingerprint string) bool {
	want := strings.ToUpper(fingerprint)
	matches := 0
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "[GNUPG:]" || fields[1] != "VALIDSIG" {
			continue
		}
		matches++
		signing := strings.ToUpper(fields[2])
		primary := signing
		if candidate := strings.ToUpper(fields[len(fields)-1]); managedFingerprint.MatchString(candidate) {
			primary = candidate
		}
		if signing != want && primary != want {
			return false
		}
	}
	return matches == 1
}

// loadMetadataSignerSnapshotForFormats resolves only the signing identities
// needed by the target Dist set. A selective RPM build must not depend on a
// DEB key (and vice versa), including an unavailable env/agent reference.
func loadMetadataSignerSnapshotForFormats(ctx context.Context, root string, repository config.RepositoryConfig, at time.Time, wantRPM, wantDEB bool) (metadataSignerSnapshot, error) {
	var snapshot metadataSignerSnapshot
	if at.IsZero() {
		return snapshot, errors.New("managed: metadata publication time is required")
	}
	at = at.UTC()
	if reference := repository.Signing.RPM.Metadata.Key; wantRPM && reference != "" {
		passphrase, err := resolvePassphraseReference(root, repository.Signing.RPM.Metadata.Passphrase)
		if err != nil {
			return metadataSignerSnapshot{}, fmt.Errorf("managed: resolve RPM metadata passphrase: %w", err)
		}
		defer zeroSecret(passphrase)
		material, identity, err := resolveKeyReference(root, reference)
		if err != nil {
			return metadataSignerSnapshot{}, fmt.Errorf("managed: resolve RPM metadata signing key: %w", err)
		}
		if identity != "" {
			if len(passphrase) != 0 {
				return metadataSignerSnapshot{}, errors.New("managed: gpg-agent metadata key cannot use an explicit passphrase reference")
			}
			core, public, err := newGPGSignerCoreWithPublic(ctx, identity, at)
			if err != nil {
				return metadataSignerSnapshot{}, err
			}
			snapshot.RPMSigner = &gpgYUMMetadataSigner{gpgSignerCore: core}
			snapshot.RPM = metadataSignerIdentity{Fingerprint: core.fingerprint, PublicKey: public}
		} else {
			signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(material), passphrase, at)
			if err != nil {
				return metadataSignerSnapshot{}, fmt.Errorf("managed: load RPM metadata signing key: %w", err)
			}
			identity, err := metadataIdentityFromMaterial(material)
			if err != nil {
				return metadataSignerSnapshot{}, fmt.Errorf("managed: identify RPM metadata signing key: %w", err)
			}
			snapshot.RPMSigner, snapshot.RPM = signer, identity
		}
	}
	if reference := repository.Signing.DEB.Metadata.Key; wantDEB && reference != "" {
		passphrase, err := resolvePassphraseReference(root, repository.Signing.DEB.Metadata.Passphrase)
		if err != nil {
			return metadataSignerSnapshot{}, fmt.Errorf("managed: resolve DEB metadata passphrase: %w", err)
		}
		defer zeroSecret(passphrase)
		material, identity, err := resolveKeyReference(root, reference)
		if err != nil {
			return metadataSignerSnapshot{}, fmt.Errorf("managed: resolve DEB metadata signing key: %w", err)
		}
		if identity != "" {
			if len(passphrase) != 0 {
				return metadataSignerSnapshot{}, errors.New("managed: gpg-agent metadata key cannot use an explicit passphrase reference")
			}
			core, public, err := newGPGSignerCoreWithPublic(ctx, identity, at)
			if err != nil {
				return metadataSignerSnapshot{}, err
			}
			snapshot.APTSigner = &gpgAPTMetadataSigner{gpgSignerCore: core}
			snapshot.DEB = metadataSignerIdentity{Fingerprint: core.fingerprint, PublicKey: public}
		} else {
			signer, err := aptrepo.NewSignerBytes(material, passphrase)
			if err != nil {
				return metadataSignerSnapshot{}, fmt.Errorf("managed: load DEB metadata signing key: %w", err)
			}
			identity, err := metadataIdentityFromMaterial(material)
			if err != nil {
				return metadataSignerSnapshot{}, fmt.Errorf("managed: identify DEB metadata signing key: %w", err)
			}
			snapshot.APTSigner, snapshot.DEB = &inProcessAPTMetadataSigner{signer: signer}, identity
		}
	}
	return snapshot, nil
}

// nextMutationPublicationTime is derived only from committed repository state
// and the exact configured metadata certificates. Consequently rm --check and
// an immediately following rm render byte-identical timestamped metadata while
// a retry of the same journal remains reproducible. Key activation times raise
// the floor so a newly rotated certificate is never backdated before it exists.
func nextMutationPublicationTime(ctx context.Context, root string, repository config.RepositoryConfig, store *state.Store, generation int64, wantRPM, wantDEB bool) (time.Time, error) {
	floor := time.Unix(0, 0).UTC()
	if generation > 0 {
		info, err := store.GetGeneration(ctx, generation)
		if err != nil {
			return time.Time{}, err
		}
		detail, err := store.GetOperation(ctx, info.OperationID)
		if err != nil || detail.Operation.CreatedAt.IsZero() {
			return time.Time{}, errors.New("managed: current Generation has no publication identity")
		}
		floor = detail.Operation.CreatedAt.UTC()
	}
	references := []string{}
	if wantRPM {
		references = append(references, repository.Signing.RPM.Metadata.Key)
	}
	if wantDEB {
		references = append(references, repository.Signing.DEB.Metadata.Key)
	}
	for _, reference := range references {
		if reference == "" {
			continue
		}
		material, identity, err := resolveKeyReference(root, reference)
		if err != nil {
			return time.Time{}, err
		}
		if identity != "" {
			material, err = exportPublicKey(ctx, identity)
			if err != nil {
				return time.Time{}, err
			}
		}
		public, err := publicOpenPGPKeyMaterial(material)
		if err != nil {
			return time.Time{}, err
		}
		entities, err := yumrepo.ParsePublicKeyring(public)
		if err != nil || len(entities) != 1 || entities[0] == nil || entities[0].PrimaryKey == nil {
			return time.Time{}, errors.New("managed: metadata signing reference must contain exactly one public certificate")
		}
		entity := entities[0]
		activation := entity.PrimaryKey.CreationTime.UTC()
		for _, identity := range entity.Identities {
			if identity != nil && identity.SelfSignature != nil && identity.SelfSignature.CreationTime.After(activation) {
				activation = identity.SelfSignature.CreationTime.UTC()
			}
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PublicKey != nil && subkey.PublicKey.CreationTime.After(activation) {
				activation = subkey.PublicKey.CreationTime.UTC()
			}
			if subkey.Sig != nil && subkey.Sig.CreationTime.After(activation) {
				activation = subkey.Sig.CreationTime.UTC()
			}
		}
		if activation.After(floor) {
			floor = activation
		}
	}
	// APT Release and OpenPGP creation times have one-second resolution. Using
	// the containing second keeps the deterministic identity no later than the
	// actual operation that follows a preview, while still including a key whose
	// activation packet has that same whole-second timestamp.
	return floor.UTC().Truncate(time.Second), nil
}

func metadataIdentityFromMaterial(material []byte) (metadataSignerIdentity, error) {
	public, err := publicOpenPGPKeyMaterial(material)
	if err != nil {
		return metadataSignerIdentity{}, err
	}
	fingerprints, err := yumrepo.RPMPackageKeyringPrimaryFingerprints(public)
	if err != nil || len(fingerprints) != 1 {
		return metadataSignerIdentity{}, errors.New("metadata key must contain exactly one public primary key")
	}
	return metadataSignerIdentity{Fingerprint: strings.ToUpper(fingerprints[0]), PublicKey: public}, nil
}

func validateMetadataSignerIdentity(identity metadataSignerIdentity) error {
	if identity.Fingerprint == "" && len(identity.PublicKey) == 0 {
		return nil
	}
	if !managedFingerprint.MatchString(identity.Fingerprint) || identity.Fingerprint != strings.ToUpper(identity.Fingerprint) || len(identity.PublicKey) == 0 {
		return errors.New("metadata signer identity is incomplete")
	}
	canonical, err := metadataIdentityFromMaterial(identity.PublicKey)
	if err != nil || canonical.Fingerprint != identity.Fingerprint || !bytes.Equal(canonical.PublicKey, identity.PublicKey) {
		return errors.New("metadata signer public key does not match its fingerprint or canonical public encoding")
	}
	return nil
}

func distMetadataSignerSnapshotPath(root, repoName, operationID string) string {
	return filepath.Join(distStageRoot(root, repoName, operationID), "metadata-signer.json")
}

func persistDistMetadataSignerSnapshot(root, repoName, operationID string, identity metadataSignerIdentity) (string, error) {
	if err := validateMetadataSignerIdentity(identity); err != nil {
		return "", err
	}
	filename := distMetadataSignerSnapshotPath(root, repoName, operationID)
	if identity.Fingerprint == "" {
		if _, err := os.Lstat(filename); err == nil {
			return "", errors.New("unsigned Dist stage unexpectedly contains a signer snapshot")
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		return "", nil
	}
	wire := distMetadataSignerSnapshotWire{Version: distMetadataSignerSnapshotVersion, Fingerprint: identity.Fingerprint, PublicKey: identity.PublicKey}
	data, err := json.Marshal(wire)
	if err != nil || len(data) > maxDistSignerSnapshotBytes {
		return "", errors.New("metadata signer public snapshot exceeds its private journal limit")
	}
	if err := writeAtomic(filename, data, 0o600); err != nil {
		return "", err
	}
	return bytesSHA(data), nil
}

func loadDistMetadataSignerSnapshot(root, repoName, operationID, expectedSHA string) (metadataSignerIdentity, error) {
	stageOwner := filepath.Join(root, ".sow", repoName, "stage")
	relative := filepath.Join(operationID, "metadata-signer.json")
	if expectedSHA == "" {
		opened, err := openRootedPrivateRegular(stageOwner, relative)
		if errors.Is(err, os.ErrNotExist) {
			return metadataSignerIdentity{}, nil
		}
		if err != nil {
			return metadataSignerIdentity{}, err
		}
		if err := opened.CloseVerified(); err != nil {
			return metadataSignerIdentity{}, err
		}
		return metadataSignerIdentity{}, errors.New("unsigned Dist operation has an unexpected signer snapshot")
	}
	if !lowercaseSHA256.MatchString(expectedSHA) {
		return metadataSignerIdentity{}, errors.New("metadata signer snapshot digest is malformed")
	}
	data, err := readRootedPrivateRegular(stageOwner, relative, maxDistSignerSnapshotBytes, false)
	if err != nil || bytesSHA(data) != expectedSHA {
		return metadataSignerIdentity{}, errors.New("metadata signer snapshot is missing, unsafe, or differs from its journal digest")
	}
	var wire distMetadataSignerSnapshotWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return metadataSignerIdentity{}, errors.New("metadata signer snapshot is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || wire.Version != distMetadataSignerSnapshotVersion {
		return metadataSignerIdentity{}, errors.New("metadata signer snapshot has trailing content or an unsupported version")
	}
	identity := metadataSignerIdentity{Fingerprint: wire.Fingerprint, PublicKey: wire.PublicKey}
	if err := validateMetadataSignerIdentity(identity); err != nil {
		return metadataSignerIdentity{}, err
	}
	return identity, nil
}
