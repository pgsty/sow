package managed

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

type gpgSignerCore struct {
	identity           string
	fingerprint        string // retained primary certificate identity
	signingFingerprint string // actual GPG key, pinned for this in-memory signer
	public             []byte
	at                 time.Time
}

type gpgYUMMetadataSigner struct{ *gpgSignerCore }
type gpgAPTMetadataSigner struct{ *gpgSignerCore }
type inProcessAPTMetadataSigner struct{ signer *aptrepo.Signer }
type inProcessAPTMetadataVerifier struct{ verifier *aptrepo.Verifier }

type metadataSignerIdentity struct {
	Fingerprint string
	PublicKey   []byte
	// SelectedFingerprint is operation-local. Frozen trees retain the public
	// certificate and their bytes, and never need to select a signing key again.
	SelectedFingerprint string `json:"-"`
}

var errMetadataSigningPolicy = errors.New("metadata signing policy rejects new metadata")

func metadataSigningPolicyError(reason string) error {
	return fmt.Errorf("%w: %w: %s", ErrRejected, errMetadataSigningPolicy, reason)
}

type metadataSignerCacheKey struct{}
type metadataSignerCache struct {
	sync.Mutex
	cores map[string]*gpgSignerCore
}

// The cache belongs to one command, never the process or the repository. A
// shared certificate/time needs only one small GPG probe, regardless of Dists.
func withMetadataSignerCache(ctx context.Context) context.Context {
	if ctx.Value(metadataSignerCacheKey{}) != nil {
		return ctx
	}
	return context.WithValue(ctx, metadataSignerCacheKey{}, &metadataSignerCache{cores: map[string]*gpgSignerCore{}})
}

type metadataSignerSnapshot struct {
	RPMSigner yumrepo.DetachedSigner
	APTSigner APTMetadataSigner
	RPM       metadataSignerIdentity
	DEB       metadataSignerIdentity
}

func metadataSignerRecordIdentity(fingerprint string, publicKey []byte) string {
	if fingerprint == "" || len(publicKey) == 0 {
		return "none"
	}
	return bytesSHA(publicKey)
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

func (signer *gpgSignerCore) Validate(ctx context.Context, at time.Time) error {
	if signer == nil || signer.identity == "" || signer.fingerprint == "" || signer.signingFingerprint == "" {
		return errors.New("managed: metadata signing identity is unavailable")
	}
	if ctx == nil {
		return errors.New("managed: nil metadata signing context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := selectedMetadataSigningKey(metadataSignerIdentity{PublicKey: signer.public, SelectedFingerprint: signer.signingFingerprint}, at)
	return err
}

func newGPGSignerCoreWithPublic(ctx context.Context, identity string, at time.Time) (*gpgSignerCore, []byte, error) {
	if at.IsZero() {
		return nil, nil, errors.New("managed: gpg metadata signing time is required")
	}
	if ctx == nil {
		return nil, nil, errors.New("managed: nil metadata signing context")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	cache, _ := ctx.Value(metadataSignerCacheKey{}).(*metadataSignerCache)
	cacheKey := identity + "/" + strconv.FormatInt(at.Unix(), 10)
	if cache != nil {
		cache.Lock()
		defer cache.Unlock()
		if core := cache.cores[cacheKey]; core != nil {
			return core, core.public, nil
		}
	}
	public, err := exportPublicKey(ctx, identity)
	if err != nil {
		return nil, nil, err
	}
	public, err = publicOpenPGPKeyMaterial(public)
	if err != nil {
		return nil, nil, err
	}
	fingerprints, err := yumrepo.RPMPackageKeyringPrimaryFingerprints(public)
	if err != nil || len(fingerprints) != 1 {
		return nil, nil, metadataSigningPolicyError("gpg identity must resolve to exactly one primary OpenPGP key")
	}
	selected, err := probeGPGSigning(ctx, fingerprints[0], at)
	if err != nil {
		return nil, nil, err
	}
	core := &gpgSignerCore{identity: identity, fingerprint: strings.ToUpper(fingerprints[0]), signingFingerprint: selected, public: public, at: at.UTC()}
	if err := core.Validate(ctx, at); err != nil {
		return nil, nil, err
	}
	if cache != nil {
		cache.cores[cacheKey] = core
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
	if err := signer.Validate(ctx, at); err != nil {
		return err
	}
	if err := waitForFrozenGPGTime(ctx, at); err != nil {
		return err
	}
	gpg, _ := exec.LookPath("gpg")
	args := []string{"--batch", "--no-tty", "--yes", "--pinentry-mode", "error", "--digest-algo", "SHA256", "--faked-system-time", strconv.FormatInt(at.UTC().Unix(), 10) + "!", "--local-user", signer.signingFingerprint + "!", "--output", "-"}
	args = append(args, operation...)
	command := exec.CommandContext(ctx, gpg, args...)
	command.Stdin, command.Stdout, command.Stderr = message, output, io.Discard
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("managed: gpg metadata signing failed: %w", err)
	}
	return nil
}

// waitForFrozenGPGTime returns once GnuPG will freeze --faked-system-time at.
// GnuPG freezes the faked clock only when the requested second is already in the
// past; a value equal to the current second lets its clock keep running, so a
// slow signature can be stamped later than the published Date. Signing at an
// earlier Generation time never waits; init and dist new wait at most a second.
func waitForFrozenGPGTime(ctx context.Context, at time.Time) error {
	target, now := at.Unix(), time.Now()
	if now.Unix() > target || target-now.Unix() > 1 {
		return nil
	}
	timer := time.NewTimer(time.Until(time.Unix(target+1, 0).Add(10 * time.Millisecond)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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
	root, err := privateTemporaryDirectory("sow-gpg-verify-")
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
	if ctx == nil {
		return snapshot, errors.New("managed: nil metadata signing context")
	}
	ctx = withMetadataSignerCache(ctx)
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
			snapshot.RPM = metadataSignerIdentity{Fingerprint: core.fingerprint, PublicKey: public, SelectedFingerprint: core.signingFingerprint}
		} else {
			signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(material), passphrase, at)
			if err != nil {
				return metadataSignerSnapshot{}, metadataSigningPolicyError("RPM metadata key is unusable for signing at the publication time")
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
			snapshot.DEB = metadataSignerIdentity{Fingerprint: core.fingerprint, PublicKey: public, SelectedFingerprint: core.signingFingerprint}
		} else {
			signer, err := aptrepo.NewSignerBytes(material, passphrase)
			if err != nil {
				return metadataSignerSnapshot{}, fmt.Errorf("managed: load DEB metadata signing key: %w", err)
			}
			if err := signer.Validate(at); err != nil {
				return metadataSignerSnapshot{}, metadataSigningPolicyError("DEB metadata key is unusable for signing at the publication time")
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

// publicationTime is absent only in legacy journals. Its decoder rejects a
// present null or empty value, so malformed new journals cannot opt into the
// legacy rendering contract. The wire value is UTC with whole-second precision.
type publicationTime string

func (value *publicationTime) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil || encoded == "" {
		return fmt.Errorf("%w: publication_time must be a UTC whole-second string", ErrIntegrity)
	}
	at, err := time.Parse(time.RFC3339, encoded)
	if err != nil || at.IsZero() || at.Unix() < 0 || at.Unix() > yumrepo.MaxMetadataTimestamp || at.UTC().Format(time.RFC3339) != encoded {
		return fmt.Errorf("%w: invalid publication_time", ErrIntegrity)
	}
	*value = publicationTime(encoded)
	return nil
}

type publicationIdentity struct {
	Time    time.Time
	Current bool // present publication_time enables timestamped RPM metadata
}

func (value publicationTime) identity() publicationIdentity {
	if value == "" {
		return publicationIdentity{}
	}
	// Values come only from the strict JSON decoder or the validated chooser.
	at, _ := time.Parse(time.RFC3339, string(value))
	return publicationIdentity{Time: at, Current: true}
}

func (identity publicationIdentity) wire() publicationTime {
	if !identity.Current {
		return ""
	}
	return publicationTime(identity.Time.UTC().Format(time.RFC3339))
}

func (identity publicationIdentity) rpmTimestamp() int64 {
	if !identity.Current {
		return 0
	}
	return identity.Time.Unix()
}

func retainedPublicationIdentity(operation state.Operation) (publicationIdentity, error) {
	var payload struct {
		PublicationTime publicationTime `json:"publication_time,omitempty"`
	}
	if err := json.Unmarshal([]byte(operation.PayloadJSON), &payload); err != nil {
		return publicationIdentity{}, fmt.Errorf("%w: invalid retained publication identity: %v", ErrIntegrity, err)
	}
	return payload.PublicationTime.identity(), nil
}

// Selection happens only after the physical build scope is known. A preview
// chooses its own in-memory time; only the actual operation persists a value.
func selectMutationPublicationTime(ctx context.Context, root, repoName string, cfg config.Config, store *state.Store, distNames []string, candidate time.Time) (publicationIdentity, error) {
	if candidate.IsZero() {
		return publicationIdentity{}, fmt.Errorf("%w: operation publication time is unavailable", ErrIntegrity)
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return publicationIdentity{}, err
	}
	generations := map[state.GenerationID]struct{}{summary.BuiltGeneration: {}}
	dists, err := store.ListDists(ctx)
	if err != nil {
		return publicationIdentity{}, err
	}
	// A dist.rm or a partial build may leave live Dists from earlier
	// generations. Their retained publication times still bound a successor.
	for _, dist := range dists {
		generations[dist.BuiltGeneration] = struct{}{}
	}
	for generation := range generations {
		if generation == 0 {
			continue
		}
		at, err := builtGenerationPublicationTime(ctx, store, generation)
		if err != nil {
			return publicationIdentity{}, err
		}
		if at.After(candidate) {
			candidate = at
		}
	}
	formats := configuredSigningFormats(cfg, repoName, distNames)
	at, err := metadataPublicationFloor(ctx, root, cfg.Repositories[repoName], candidate, formats.rpm, formats.deb)
	if err != nil {
		return publicationIdentity{}, err
	}
	identity := publicationIdentity{Time: at, Current: true}
	var validated publicationTime
	if err := validated.UnmarshalJSON([]byte(strconv.Quote(string(identity.wire())))); err != nil {
		return publicationIdentity{}, err
	}
	return identity, nil
}

// validateDistPublicationTime compares payload identity with small metadata
// files in an already hash-bound tree. It does not reselect keys or timestamps.
func validateDistPublicationTime(distRoot, format string, architectures []state.Architecture, signed bool, publication publicationIdentity) error {
	if !publication.Current {
		return nil
	}
	read := func(relative string) ([]byte, error) {
		return readRootedRegular(distRoot, filepath.FromSlash(relative), 16<<20, false)
	}
	checkSignature := func(relative string) error {
		data, err := read(relative)
		if err != nil {
			return err
		}
		at, err := yumrepo.DetachedSignatureCreationTime(bytes.NewReader(data))
		if err != nil || !at.Equal(publication.Time) {
			return fmt.Errorf("%w: %s signature time differs from publication_time", ErrIntegrity, relative)
		}
		return nil
	}
	if format == "rpm" {
		for _, architecture := range architectures {
			prefix := architecture.Family + "/repodata/"
			data, err := read(prefix + "repomd.xml")
			if err != nil {
				return err
			}
			var document struct {
				Data []struct {
					Timestamp int64 `xml:"timestamp"`
				} `xml:"data"`
			}
			if err := xml.Unmarshal(data, &document); err != nil || len(document.Data) == 0 {
				return fmt.Errorf("%w: invalid timestamped repomd", ErrIntegrity)
			}
			for _, record := range document.Data {
				if record.Timestamp != publication.Time.Unix() {
					return fmt.Errorf("%w: repomd timestamp differs from publication_time", ErrIntegrity)
				}
			}
			if signed {
				if err := checkSignature(prefix + "repomd.xml.asc"); err != nil {
					return err
				}
			}
		}
		return nil
	}
	data, err := read("Release")
	if err != nil {
		return err
	}
	at, err := parseReleaseDate(data)
	if err != nil || !at.Equal(publication.Time) {
		return fmt.Errorf("%w: Release Date differs from publication_time", ErrIntegrity)
	}
	if !signed {
		return nil
	}
	if err := checkSignature("Release.gpg"); err != nil {
		return err
	}
	data, err = read("InRelease")
	if err != nil {
		return err
	}
	block, rest := clearsign.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("%w: invalid timestamped InRelease", ErrIntegrity)
	}
	reader := packet.NewReader(block.ArmoredSignature.Body)
	parsed, err := reader.Next()
	signature, ok := parsed.(*packet.Signature)
	if err != nil || !ok || !signature.CreationTime.Equal(publication.Time) {
		return fmt.Errorf("%w: InRelease signature time differs from publication_time", ErrIntegrity)
	}
	if _, err := reader.Next(); err != io.EOF {
		return fmt.Errorf("%w: trailing InRelease signature packets", ErrIntegrity)
	}
	return nil
}

// frozenPublicationTree selects the exact journaled tree before any promotion
// or pointer exchange. Legacy plans retain their original hash-only contract.
func frozenPublicationTree(ctx context.Context, live, staged, expected string) (string, error) {
	for _, candidate := range []string{live, staged} {
		sha, _, err := digestTree(ctx, candidate)
		if err == nil && sha == expected {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%w: neither live nor staged tree matches the publication journal", ErrIntegrity)
}

func validateMutationPublicationTime(ctx context.Context, root, repoName, operationID string, store *state.Store, publication publicationIdentity, manifest mutationManifest) error {
	if !publication.Current || manifest.Build == nil {
		return nil
	}
	for _, build := range manifest.Build.Dists {
		dist, err := store.GetDist(ctx, build.Name)
		if err != nil {
			return err
		}
		tree, err := frozenPublicationTree(ctx, filepath.Join(root, repoName, "dists", build.Name), filepath.Join(mutationStageRoot(root, repoName, operationID), "build", "dists", build.Name), build.TreeSHA256)
		if err != nil {
			return err
		}
		if err := validateDistPublicationTime(tree, dist.Format, build.Architectures, build.MetadataSignerFingerprint != "", publication); err != nil {
			return err
		}
	}
	return nil
}

// nextMutationPublicationTime preserves the deterministic chooser for journals
// without publication_time. Never use the current wall clock on this path.
func nextMutationPublicationTime(ctx context.Context, root string, repository config.RepositoryConfig, store *state.Store, generation state.GenerationID, wantRPM, wantDEB bool) (time.Time, error) {
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
	return metadataPublicationFloor(ctx, root, repository, floor, wantRPM, wantDEB)
}

func metadataPublicationFloor(ctx context.Context, root string, repository config.RepositoryConfig, floor time.Time, wantRPM, wantDEB bool) (time.Time, error) {
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
	// the containing second preserves the selected operation identity and key
	// activation packet precision.
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

// New publication must use a key usable now, even when the deterministic
// signing timestamp is historical. Historical Generation verification and
// recovery of a frozen build continue to use their bound signing material.
func validateNewMetadataSigningKeys(snapshot metadataSignerSnapshot, at, now time.Time) error {
	for _, identity := range []metadataSignerIdentity{snapshot.RPM, snapshot.DEB} {
		if identity.Fingerprint == "" {
			continue
		}
		// Validate the key selected at the deterministic signing time. Merely
		// finding any usable key now can fall back from an expired subkey to
		// the primary, while the historical signature still uses that subkey.
		key, err := selectedMetadataSigningKey(identity, at)
		if err != nil {
			return err
		}
		identity.SelectedFingerprint = fmt.Sprintf("%X", key.PublicKey.Fingerprint)
		if _, err := selectedMetadataSigningKey(identity, now); err != nil {
			return metadataSigningPolicyError("metadata signing key is expired, revoked, or not yet valid for a new publication")
		}
	}
	return nil
}

// Validate the exact key selected by the signer, not a different usable key
// from the same certificate. GPG can legitimately have only one of several
// signing subkeys available on this machine.
func selectedMetadataSigningKey(identity metadataSignerIdentity, at time.Time) (openpgp.Key, error) {
	entities, err := yumrepo.ParsePublicKeyring(identity.PublicKey)
	if err != nil || len(entities) != 1 || at.IsZero() {
		return openpgp.Key{}, metadataSigningPolicyError("metadata signing certificate or publication time is invalid")
	}
	entity := entities[0]
	var key openpgp.Key
	var usable bool
	if identity.SelectedFingerprint == "" {
		key, usable = entity.SigningKey(at)
	} else {
		candidates := []uint64{entity.PrimaryKey.KeyId}
		for _, subkey := range entity.Subkeys {
			candidates = append(candidates, subkey.PublicKey.KeyId)
		}
		for _, id := range candidates {
			candidate, ok := entity.SigningKeyById(at, id)
			if ok && fmt.Sprintf("%X", candidate.PublicKey.Fingerprint) == identity.SelectedFingerprint {
				key, usable = candidate, true
				break
			}
		}
	}
	if !usable || !yumrepo.DeterministicMetadataSignatureAlgorithm(key.PublicKey.PubKeyAlgo) {
		return openpgp.Key{}, metadataSigningPolicyError("metadata signing key is unavailable, invalid at the publication time, or not retry-deterministic")
	}
	return key, nil
}
