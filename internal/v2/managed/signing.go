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
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
	"golang.org/x/sys/unix"
)

const maxManagedKeyBytes = 16 << 20

const rpmSigningChildArg = "__sow_internal_rpm_sign_fd_v1__"

var managedFingerprint = regexp.MustCompile(`(?i)^(?:[0-9a-f]{16}|[0-9a-f]{40}|[0-9a-f]{64})$`)

// rpm rewrites a package beside its input, so a regular-file descriptor alone
// is insufficient: the child must retain the already-bound parent directory.
// Re-execing this binary gives the child a private cwd without ever changing
// the concurrent parent process cwd and works on Darwin, where /dev/fd does not
// permit directory traversal. The sentinel is intentionally strict; ordinary
// CLI invocations never enter this internal transport.
func init() {
	if len(os.Args) < 2 || os.Args[1] != rpmSigningChildArg {
		return
	}
	if err := runRPMSigningChild(os.Args[2:]); err != nil {
		os.Exit(126)
	}
	// unix.Exec only returns on failure, but retain an explicit terminal path if
	// a future platform implementation ever violates that contract.
	os.Exit(127)
}

func runRPMSigningChild(args []string) error {
	if len(args) != 4 {
		return errors.New("invalid RPM signing child arguments")
	}
	rpm, operation, keyID, name := args[0], args[1], args[2], args[3]
	if !filepath.IsAbs(rpm) || filepath.Base(rpm) != "rpm" {
		return errors.New("invalid RPM signing executable")
	}
	if operation != "--addsign" && operation != "--resign" {
		return errors.New("invalid RPM signing operation")
	}
	if !managedFingerprint.MatchString(keyID) {
		return errors.New("invalid RPM signing identity")
	}
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
		return errors.New("invalid RPM signing basename")
	}
	var directory unix.Stat_t
	if err := unix.Fstat(3, &directory); err != nil || uint32(directory.Mode)&unix.S_IFMT != unix.S_IFDIR {
		return errors.Join(errors.New("invalid RPM signing directory descriptor"), err)
	}
	if err := unix.Fchdir(3); err != nil {
		return errors.New("cannot enter RPM signing directory descriptor")
	}
	if err := unix.Close(3); err != nil {
		return errors.New("cannot close RPM signing directory descriptor")
	}
	return unix.Exec(rpm, []string{
		rpm,
		"--define", "_signature gpg",
		"--define", "_gpg_name " + strings.ToUpper(keyID),
		"--define", "_gpg_digest_algo sha256",
		operation, name,
	}, os.Environ())
}

type rpmSigningPolicy struct {
	mode             string
	keyID            string
	current          openpgp.KeyRing
	trusted          openpgp.KeyRing
	currentPrint     string
	trustedPrint     []string
	currentSnapshot  string
	trustedSnapshots []string
	retainedKeys     []state.RPMSigningKey
}

func loadRPMSigningPolicy(ctx context.Context, workspaceRoot string, cfg config.RPMPackageSigningConfig) (rpmSigningPolicy, error) {
	policy := rpmSigningPolicy{mode: cfg.Mode}
	if policy.mode == "" {
		policy.mode = "never"
	}
	if policy.mode == "never" {
		return policy, nil
	}
	currentBytes, keyID, err := resolveSigningPublicKey(ctx, workspaceRoot, cfg.Key)
	if err != nil {
		return rpmSigningPolicy{}, fmt.Errorf("managed: resolve configured RPM package signing key: %w", err)
	}
	current, err := yumrepo.ParseRPMPackageKeyring(currentBytes)
	if err != nil {
		return rpmSigningPolicy{}, fmt.Errorf("managed: configured RPM package key has no usable public half: %w", err)
	}
	policy.retainedKeys, err = retainedRPMSigningKeysFromMaterial(currentBytes)
	if err != nil {
		return rpmSigningPolicy{}, fmt.Errorf("managed: retain configured RPM package key: %w", err)
	}
	fingerprints, err := yumrepo.RPMPackageKeyringPrimaryFingerprints(currentBytes)
	if err != nil || len(fingerprints) != 1 {
		return rpmSigningPolicy{}, errors.New("managed: configured RPM package key must identify exactly one primary key")
	}
	currentPrint := strings.ToUpper(fingerprints[0])
	if len(policy.retainedKeys) != 1 || policy.retainedKeys[0].Fingerprint != currentPrint {
		identities := make([]string, 0, len(policy.retainedKeys))
		for _, key := range policy.retainedKeys {
			identities = append(identities, key.Fingerprint)
		}
		return rpmSigningPolicy{}, fmt.Errorf("managed: configured RPM package key has no unique certificate snapshot for %s (resolved %v)", currentPrint, identities)
	}
	policy.currentSnapshot = policy.retainedKeys[0].SnapshotSHA256
	trustedBytes := append([]byte(nil), currentBytes...)
	for _, reference := range cfg.TrustedKeys {
		data, err := resolvePublicKeyReference(ctx, workspaceRoot, reference)
		if err != nil {
			return rpmSigningPolicy{}, fmt.Errorf("managed: resolve RPM trusted key reference: %w", err)
		}
		trustedBytes = append(trustedBytes, '\n')
		trustedBytes = append(trustedBytes, data...)
		keys, err := retainedRPMSigningKeysFromMaterial(data)
		if err != nil {
			return rpmSigningPolicy{}, fmt.Errorf("managed: retain RPM trusted key reference: %w", err)
		}
		policy.retainedKeys = append(policy.retainedKeys, keys...)
	}
	trusted, err := yumrepo.ParseRPMPackageKeyring(trustedBytes)
	if err != nil {
		return rpmSigningPolicy{}, fmt.Errorf("managed: build RPM package trust ring: %w", err)
	}
	policy.keyID = keyID
	policy.current = current
	policy.trusted = trusted
	policy.currentPrint = currentPrint
	trustedFingerprints, err := yumrepo.RPMPackageKeyringPrimaryFingerprints(trustedBytes)
	if err != nil || len(trustedFingerprints) == 0 {
		return rpmSigningPolicy{}, errors.New("managed: RPM package trust ring has no primary fingerprint")
	}
	for index := range trustedFingerprints {
		trustedFingerprints[index] = strings.ToUpper(trustedFingerprints[index])
	}
	sort.Strings(trustedFingerprints)
	policy.trustedPrint = stableUniqueStrings(trustedFingerprints)
	policy.retainedKeys, err = normalizeRetainedRPMSigningKeys(policy.retainedKeys)
	if err != nil {
		return rpmSigningPolicy{}, err
	}
	for _, key := range policy.retainedKeys {
		policy.trustedSnapshots = append(policy.trustedSnapshots, key.SnapshotSHA256)
	}
	sort.Strings(policy.trustedSnapshots)
	policy.trustedSnapshots = stableUniqueStrings(policy.trustedSnapshots)
	return policy, nil
}

func retainedRPMSigningKeysFromMaterial(material []byte) ([]state.RPMSigningKey, error) {
	public, err := publicOpenPGPKeyMaterial(material)
	if err != nil {
		return nil, err
	}
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(public))
	if err != nil || len(entities) == 0 {
		return nil, errors.New("OpenPGP public material has no entity")
	}
	keys := make([]state.RPMSigningKey, 0, len(entities))
	for _, entity := range entities {
		if entity == nil || entity.PrimaryKey == nil {
			return nil, errors.New("OpenPGP public material has an invalid entity")
		}
		var output bytes.Buffer
		armored, err := armor.Encode(&output, openpgp.PublicKeyType, nil)
		if err != nil {
			return nil, err
		}
		if err := entity.Serialize(armored); err != nil {
			_ = armored.Close()
			return nil, err
		}
		if err := armored.Close(); err != nil {
			return nil, err
		}
		fingerprints, err := yumrepo.RPMPackageKeyringPrimaryFingerprints(output.Bytes())
		if err != nil || len(fingerprints) != 1 {
			return nil, errors.New("OpenPGP public entity has no unique primary fingerprint")
		}
		certificate := append([]byte(nil), output.Bytes()...)
		keys = append(keys, state.RPMSigningKey{Fingerprint: strings.ToUpper(fingerprints[0]), SnapshotSHA256: bytesSHA(certificate), PublicKey: certificate})
	}
	return normalizeRetainedRPMSigningKeys(keys)
}

func normalizeRetainedRPMSigningKeys(input []state.RPMSigningKey) ([]state.RPMSigningKey, error) {
	bySnapshot := make(map[string]state.RPMSigningKey, len(input))
	for _, key := range input {
		fingerprint := strings.ToUpper(key.Fingerprint)
		snapshot := bytesSHA(key.PublicKey)
		if !managedFingerprint.MatchString(fingerprint) || len(key.PublicKey) == 0 || key.SnapshotSHA256 != "" && key.SnapshotSHA256 != snapshot {
			return nil, errors.New("managed: retained RPM signing key is invalid")
		}
		key.Fingerprint = fingerprint
		key.SnapshotSHA256 = snapshot
		key.PublicKey = append([]byte(nil), key.PublicKey...)
		bySnapshot[fingerprint+":"+snapshot] = key
	}
	identities := make([]string, 0, len(bySnapshot))
	for identity := range bySnapshot {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	result := make([]state.RPMSigningKey, 0, len(identities))
	for _, identity := range identities {
		result = append(result, bySnapshot[identity])
	}
	return result, nil
}

type retainedRPMKeyrings map[string]map[string]openpgp.KeyRing

func loadRetainedRPMKeyrings(ctx context.Context, store *state.Store) (retainedRPMKeyrings, error) {
	keys, err := store.ListRPMSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	result := make(retainedRPMKeyrings, len(keys))
	for _, key := range keys {
		parsed, err := retainedRPMSigningKeysFromMaterial(key.PublicKey)
		if err != nil || len(parsed) != 1 || parsed[0].Fingerprint != key.Fingerprint || parsed[0].SnapshotSHA256 != key.SnapshotSHA256 {
			return nil, fmt.Errorf("%w: retained RPM signing certificate %s is invalid", ErrIntegrity, key.Fingerprint)
		}
		keyring, err := yumrepo.ParseRPMPackageKeyring(key.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: retained RPM signing certificate %s cannot form a verifier: %v", ErrIntegrity, key.Fingerprint, err)
		}
		if result[key.Fingerprint] == nil {
			result[key.Fingerprint] = map[string]openpgp.KeyRing{}
		}
		result[key.Fingerprint][key.SnapshotSHA256] = keyring
	}
	return result, nil
}

func validateStoredRPMIdentity(ctx context.Context, reader io.ReadSeeker, object state.PackageObject, retained retainedRPMKeyrings) error {
	identity := strings.ToUpper(object.SignatureKey)
	if len(identity) == 40 || len(identity) == 64 {
		keyrings := retained[identity]
		if len(keyrings) == 0 {
			return fmt.Errorf("no retained public certificate for stored signer %s", identity)
		}
		verified := false
		for _, keyring := range keyrings {
			fingerprint, ok := verifiedRPMSignerReader(ctx, reader, keyring)
			if ok && fingerprint == identity {
				verified = true
				break
			}
		}
		if !verified {
			return fmt.Errorf("package is not verified by its retained signer %s", identity)
		}
		return nil
	}
	structural, err := inspectStructuralRPMKeyIDReader(ctx, reader)
	if err != nil {
		return err
	}
	if strings.ToUpper(structural) != identity {
		return fmt.Errorf("structural signature identity %q differs from stored identity %q", structural, object.SignatureKey)
	}
	return nil
}

func validateBuiltRPMAuthorization(ctx context.Context, root, repoName string, object state.PackageObject, signing config.EffectiveRPMPackageSigningConfig, retained retainedRPMKeyrings) error {
	if signing.Mode == "" || signing.Mode == "never" {
		return validateStoredRPMIdentityFromSource(ctx, root, repoName, object, retained)
	}
	allowed := map[string]map[string]struct{}{}
	if signing.Mode == "always" {
		allowed[strings.ToUpper(signing.KeyFingerprint)] = map[string]struct{}{signing.KeySnapshotSHA256: {}}
	} else if signing.Mode == "fill" {
		for _, fingerprint := range signing.TrustedKeyFingerprints {
			allowed[strings.ToUpper(fingerprint)] = map[string]struct{}{}
		}
		for _, snapshot := range signing.TrustedKeySnapshotSHA256s {
			for fingerprint, keyrings := range retained {
				if _, authorizedFingerprint := allowed[fingerprint]; authorizedFingerprint {
					if _, exists := keyrings[snapshot]; exists {
						allowed[fingerprint][snapshot] = struct{}{}
					}
				}
			}
		}
	} else {
		return fmt.Errorf("unknown retained RPM package signing mode %q", signing.Mode)
	}
	source, err := availableManagedPackageSource(root, repoName, object)
	if err != nil {
		return err
	}
	opened, err := source.open()
	if err != nil {
		return err
	}
	var signer string
	for fingerprint, snapshots := range allowed {
		for snapshot := range snapshots {
			keyring := retained[fingerprint][snapshot]
			if verified, ok := verifiedRPMSignerReader(ctx, opened.file, keyring); ok {
				signer = verified
				break
			}
		}
		if signer != "" {
			break
		}
	}
	closeErr := opened.CloseVerified()
	if signer == "" {
		return errors.Join(fmt.Errorf("package is not verified by the retained %s authorization", signing.Mode), closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

// decodeRetainedEffectiveSigning is deliberately stricter than ordinary JSON
// decoding. Built signing evidence is an immutable authorization snapshot, so
// aliases, unsorted identities, duplicate identities, and dormant resolved
// fingerprints are integrity failures rather than inputs to normalize.
func decodeRetainedEffectiveSigning(value string) (config.EffectiveSigningConfig, error) {
	if value == "" {
		value = "{}"
	}
	// Schema v5 deliberately used {} as the unsigned default.  It is the one
	// legacy spelling accepted here and has exactly one semantic expansion:
	// RPM package signing mode never, with no key or trust references.
	if value == "{}" {
		return config.EffectiveSigningConfig{RPM: config.EffectiveRPMSigningConfig{
			Packages: config.EffectiveRPMPackageSigningConfig{Mode: "never"},
		}}, nil
	}
	var frozen config.EffectiveSigningConfig
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frozen); err != nil {
		return config.EffectiveSigningConfig{}, fmt.Errorf("%w: decode retained signing snapshot: %v", ErrIntegrity, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return config.EffectiveSigningConfig{}, fmt.Errorf("%w: retained signing snapshot has trailing content", ErrIntegrity)
	}
	packages := frozen.RPM.Packages
	canonical, err := canonicalEffectiveRPMPackages(config.RPMPackageSigningConfig{
		Mode: packages.Mode, Key: packages.Key, TrustedKeys: append([]string(nil), packages.TrustedKeys...),
	}, packages.KeyFingerprint, append([]string(nil), packages.TrustedKeyFingerprints...), packages.KeySnapshotSHA256, append([]string(nil), packages.TrustedKeySnapshotSHA256s...))
	if err != nil || !reflect.DeepEqual(canonical, packages) {
		return config.EffectiveSigningConfig{}, fmt.Errorf("%w: retained RPM package signing snapshot is not canonical", ErrIntegrity)
	}
	if frozen.RPM.Metadata != nil {
		if frozen.RPM.Metadata.Key == "" || !managedFingerprint.MatchString(frozen.RPM.Metadata.KeyFingerprint) || frozen.RPM.Metadata.KeyFingerprint != strings.ToUpper(frozen.RPM.Metadata.KeyFingerprint) {
			return config.EffectiveSigningConfig{}, fmt.Errorf("%w: retained RPM metadata signing snapshot is invalid", ErrIntegrity)
		}
	}
	if frozen.DEB != nil {
		metadata := frozen.DEB.Metadata
		if metadata.Key == "" || !managedFingerprint.MatchString(metadata.KeyFingerprint) || metadata.KeyFingerprint != strings.ToUpper(metadata.KeyFingerprint) {
			return config.EffectiveSigningConfig{}, fmt.Errorf("%w: retained DEB metadata signing snapshot is invalid", ErrIntegrity)
		}
	}
	return frozen, nil
}

func validateStoredRPMIdentityFromSource(ctx context.Context, root, repoName string, object state.PackageObject, retained retainedRPMKeyrings) error {
	source, err := availableManagedPackageSource(root, repoName, object)
	if err != nil {
		return err
	}
	opened, err := source.open()
	if err != nil {
		return err
	}
	return errors.Join(validateStoredRPMIdentity(ctx, opened.file, object, retained), opened.CloseVerified())
}

func (policy rpmSigningPolicy) prepare(ctx context.Context, snapshot, basename string, object state.PackageObject) (state.PackageObject, error) {
	if policy.mode == "never" {
		signatureKey, err := inspectStructuralRPMKeyID(ctx, snapshot)
		if err != nil {
			return state.PackageObject{}, err
		}
		object.SignatureKey = signatureKey
		return object, nil
	}
	wanted := policy.trusted
	if policy.mode == "always" {
		wanted = policy.current
	}
	if fingerprint, ok := verifiedRPMSigner(ctx, snapshot, wanted); ok {
		object.SignatureKey = fingerprint
		return object, nil
	}
	hadSignature, err := hasStructuralRPMSignature(ctx, snapshot)
	if err != nil {
		return state.PackageObject{}, err
	}
	neutralBefore := object.PayloadSHA256
	if err := signManagedRPM(ctx, snapshot, policy.keyID, hadSignature); err != nil {
		return state.PackageObject{}, err
	}
	final, err := inspectRPMSnapshot(ctx, snapshot, basename)
	if err != nil {
		return state.PackageObject{}, fmt.Errorf("managed: inspect signed RPM: %w", err)
	}
	if final.Coordinate != object.Coordinate || final.PayloadSHA256 != neutralBefore {
		return state.PackageObject{}, fmt.Errorf("%w: RPM signing changed logical identity or signature-neutral payload", ErrIntegrity)
	}
	fingerprint, ok := verifiedRPMSigner(ctx, snapshot, policy.current)
	if !ok {
		return state.PackageObject{}, errors.New("managed: RPM signing output is not verified by the configured key")
	}
	final.SignatureKey = fingerprint
	return final, nil
}

func (policy rpmSigningPolicy) permitsNeutralReuseReader(ctx context.Context, reader io.ReadSeeker) bool {
	switch policy.mode {
	case "fill":
		_, ok := verifiedRPMSignerReader(ctx, reader, policy.trusted)
		return ok
	case "always":
		_, ok := verifiedRPMSignerReader(ctx, reader, policy.current)
		return ok
	default:
		return false
	}
}

// authorizeDesiredReader answers only whether the current Desired policy
// authorizes these bytes. It intentionally does not compare PackageObject's
// historical identity representation: never records an issuer key ID whereas
// fill/always record a verified primary fingerprint, and a policy transition
// must remain legal when the immutable bytes already satisfy the new policy.
func (policy rpmSigningPolicy) authorizeDesiredReader(ctx context.Context, reader io.ReadSeeker) error {
	switch policy.mode {
	case "never":
		return nil
	case "fill":
		if _, ok := verifiedRPMSignerReader(ctx, reader, policy.trusted); !ok {
			return errors.New("package is not verified by the configured trusted keys")
		}
		return nil
	case "always":
		if _, ok := verifiedRPMSignerReader(ctx, reader, policy.current); !ok {
			return errors.New("package is not verified by the configured current key")
		}
		return nil
	default:
		return fmt.Errorf("unsupported package signing mode %q", policy.mode)
	}
}

func verifiedRPMSigner(ctx context.Context, filename string, keyring openpgp.KeyRing) (string, bool) {
	if keyring == nil {
		return "", false
	}
	opened, err := openRootedRegular(filepath.Dir(filename), filepath.Base(filename))
	if err != nil {
		return "", false
	}
	fingerprint, ok := verifiedRPMSignerReader(ctx, opened.file, keyring)
	closeErr := opened.CloseVerified()
	if !ok || closeErr != nil {
		return "", false
	}
	return fingerprint, true
}

func verifiedRPMSignerReader(ctx context.Context, reader io.ReadSeeker, keyring openpgp.KeyRing) (string, bool) {
	if keyring == nil || reader == nil {
		return "", false
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return "", false
	}
	proofs, err := yumrepo.VerifyEmbeddedRPMSignatures(ctx, reader, keyring, time.Now().UTC())
	if err != nil || len(proofs) == 0 {
		return "", false
	}
	return strings.ToUpper(proofs[0].SignerPrimaryFingerprint), true
}

func inspectStructuralRPMKeyID(ctx context.Context, filename string) (string, error) {
	opened, err := openRootedRegular(filepath.Dir(filename), filepath.Base(filename))
	if err != nil {
		return "", err
	}
	identity, inspectErr := inspectStructuralRPMKeyIDReader(ctx, opened.file)
	closeErr := opened.CloseVerified()
	if err := errors.Join(inspectErr, closeErr); err != nil {
		return "", fmt.Errorf("managed: inspect RPM signature identity: %w", err)
	}
	return identity, nil
}

func inspectStructuralRPMKeyIDReader(ctx context.Context, reader io.ReadSeeker) (string, error) {
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	signatures, err := yumrepo.InspectEmbeddedRPMSignatures(ctx, reader)
	if errors.Is(err, yumrepo.ErrUnsignedRPMPackage) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if len(signatures) == 0 {
		return "", nil
	}
	return strings.ToUpper(signatures[0].IssuerKeyID), nil
}

func hasStructuralRPMSignature(ctx context.Context, filename string) (bool, error) {
	opened, err := openRootedRegular(filepath.Dir(filename), filepath.Base(filename))
	if err != nil {
		return false, err
	}
	signatures, inspectErr := yumrepo.InspectEmbeddedRPMSignatures(ctx, opened.file)
	closeErr := opened.CloseVerified()
	if errors.Is(inspectErr, yumrepo.ErrUnsignedRPMPackage) {
		return false, closeErr
	}
	if err := errors.Join(inspectErr, closeErr); err != nil {
		return false, fmt.Errorf("managed: inspect RPM signature: %w", err)
	}
	return len(signatures) != 0, nil
}

func signManagedRPM(ctx context.Context, filename, keyID string, resign bool) error {
	rpm, err := exec.LookPath("rpm")
	if err != nil {
		return errors.New("managed: rpm executable is required by the configured package signing policy")
	}
	rpm, err = filepath.Abs(rpm)
	if err != nil || filepath.Base(rpm) != "rpm" {
		return errors.New("managed: resolved rpm executable is unsafe")
	}
	if !managedFingerprint.MatchString(keyID) {
		return errors.New("managed: RPM signing identity is invalid")
	}
	operation := "--addsign"
	if resign {
		operation = "--resign"
	}
	name := filepath.Base(filename)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return errors.New("managed: unsafe RPM signing target")
	}
	parent, err := openPhysicalDirectoryChain(filepath.Dir(filename))
	if err != nil {
		return fmt.Errorf("managed: bind RPM signing stage: %w", err)
	}
	finishParent := func(result error) error { return errors.Join(result, parent.close(true)) }
	var before unix.Stat_t
	if err := unix.Fstatat(int(parent.directory().Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil || uint32(before.Mode)&unix.S_IFMT != unix.S_IFREG {
		return finishParent(errors.Join(errors.New("managed: RPM signing target is not a regular file"), err))
	}
	fd, err := unix.Openat(int(parent.directory().Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return finishParent(err)
	}
	held := os.NewFile(uintptr(fd), name)
	finish := func(result error) error { return finishParent(errors.Join(result, held.Close())) }
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || opened.Dev != before.Dev || opened.Ino != before.Ino || uint32(opened.Mode)&unix.S_IFMT != unix.S_IFREG {
		return finish(errors.Join(errors.New("managed: RPM signing target changed while opening"), err))
	}
	executable, err := os.Executable()
	if err != nil {
		return finish(errors.New("managed: current executable is unavailable for RPM signing"))
	}
	command := exec.CommandContext(ctx, executable, rpmSigningChildArg, rpm, operation, strings.ToUpper(keyID), name)
	command.ExtraFiles = []*os.File{parent.directory()}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return finish(fmt.Errorf("managed: rpm signing command failed: %w", err))
	}
	var entry unix.Stat_t
	entryErr := unix.Fstatat(int(parent.directory().Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW)
	if entryErr != nil || uint32(entry.Mode)&unix.S_IFMT != unix.S_IFREG {
		return finish(errors.Join(errors.New("managed: RPM signing output is missing or unsafe"), entryErr))
	}
	signedFD, err := unix.Openat(int(parent.directory().Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return finish(err)
	}
	signed := os.NewFile(uintptr(signedFD), name)
	var signedRaw unix.Stat_t
	statErr := unix.Fstat(signedFD, &signedRaw)
	if statErr != nil || signedRaw.Dev != entry.Dev || signedRaw.Ino != entry.Ino || uint32(signedRaw.Mode)&unix.S_IFMT != unix.S_IFREG {
		return finish(errors.Join(errors.New("managed: RPM signing output changed while opening"), statErr, signed.Close()))
	}
	return finish(errors.Join(signed.Sync(), signed.Close(), parent.directory().Sync()))
}

func validateRPMPackageSigningKey(ctx context.Context, root, reference string) error {
	if _, err := exec.LookPath("rpm"); err != nil {
		return errors.New("rpm executable is required")
	}
	public, _, err := resolveSigningPublicKey(ctx, root, reference)
	if err != nil {
		return err
	}
	fingerprints, err := yumrepo.RPMPackageKeyringPrimaryFingerprints(public)
	if err != nil || len(fingerprints) != 1 {
		return errors.New("configured key must resolve to exactly one primary OpenPGP key")
	}
	fingerprint := strings.ToUpper(fingerprints[0])
	if err := validateGPGSecretIdentity(ctx, fingerprint); err != nil {
		return err
	}
	// RPM package signing is intentionally delegated to rpm(8). Its macros may
	// provide a non-interactive passphrase channel that is not equivalent to a
	// standalone gpg invocation (the Pigsty dnfupdate image does exactly this).
	// A direct gpg signing probe would reject a valid rpm configuration. The
	// actual private-stage rpm call and cryptographic post-verification remain
	// the authoritative capability check.
	return nil
}

func validateGPGSecretIdentity(ctx context.Context, fingerprint string) error {
	if ctx == nil {
		return errors.New("nil gpg context")
	}
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		return errors.New("gpg executable is required")
	}
	want := strings.ToUpper(fingerprint)
	command := exec.CommandContext(ctx, gpg, "--batch", "--no-tty", "--with-colons", "--fingerprint", "--list-secret-keys", want)
	var stdout bytes.Buffer
	command.Stdout, command.Stderr = &stdout, io.Discard
	if err := command.Run(); err != nil {
		return errors.New("configured OpenPGP secret key is unavailable")
	}
	waitingForPrimaryFingerprint := false
	primary := []string{}
	for _, line := range strings.Split(stdout.String(), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "sec":
			waitingForPrimaryFingerprint = true
		case "ssb":
			waitingForPrimaryFingerprint = false
		case "fpr":
			if waitingForPrimaryFingerprint && len(fields) > 9 {
				primary = append(primary, strings.ToUpper(fields[9]))
				waitingForPrimaryFingerprint = false
			}
		}
	}
	primary = stableUniqueStrings(primary)
	if len(primary) != 1 || primary[0] != want {
		return errors.New("configured OpenPGP secret identity is ambiguous or unavailable")
	}
	return nil
}

func probeGPGSigning(ctx context.Context, fingerprint string) error {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		return errors.New("gpg executable is required")
	}
	command := exec.CommandContext(ctx, gpg,
		"--batch", "--no-tty", "--pinentry-mode", "error", "--local-user", strings.ToUpper(fingerprint),
		"--armor", "--detach-sign", "--output", "-",
	)
	command.Stdin = strings.NewReader("sow signing preflight\n")
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Run(); err != nil {
		return errors.New("configured OpenPGP key cannot produce a non-interactive signature")
	}
	return nil
}

func resolveSigningPublicKey(ctx context.Context, root, reference string) ([]byte, string, error) {
	material, identity, err := resolveKeyReference(root, reference)
	if err != nil {
		return nil, "", err
	}
	if identity != "" {
		public, err := exportPublicKey(ctx, identity)
		return public, identity, err
	}
	public, err := publicOpenPGPKeyMaterial(material)
	if err != nil {
		return nil, "", err
	}
	fingerprints, err := yumrepo.RPMPackageKeyringPrimaryFingerprints(public)
	if err != nil || len(fingerprints) != 1 {
		return nil, "", errors.New("key material must contain exactly one public primary key")
	}
	return public, strings.ToUpper(fingerprints[0]), nil
}

func resolvePublicKeyReference(ctx context.Context, root, reference string) ([]byte, error) {
	material, identity, err := resolveKeyReference(root, reference)
	if err != nil {
		return nil, err
	}
	if identity != "" {
		return exportPublicKey(ctx, identity)
	}
	return material, nil
}

func publicOpenPGPKeyMaterial(data []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	var (
		entities openpgp.EntityList
		err      error
	)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN PGP")) {
		entities, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(trimmed))
	} else {
		entities, err = openpgp.ReadKeyRing(bytes.NewReader(data))
	}
	if err != nil || len(entities) == 0 {
		return nil, errors.New("key reference has no parseable OpenPGP key")
	}
	var output bytes.Buffer
	armored, err := armor.Encode(&output, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, errors.New("cannot encode OpenPGP public key")
	}
	for _, entity := range entities {
		if entity == nil || entity.PrimaryKey == nil {
			_ = armored.Close()
			return nil, errors.New("key reference has an invalid OpenPGP entity")
		}
		if err := entity.Serialize(armored); err != nil {
			_ = armored.Close()
			return nil, errors.New("cannot serialize OpenPGP public key")
		}
	}
	if err := armored.Close(); err != nil {
		return nil, errors.New("cannot finalize OpenPGP public key")
	}
	if _, err := yumrepo.RPMPackageKeyringPrimaryFingerprints(output.Bytes()); err != nil {
		return nil, errors.New("key reference has no usable OpenPGP public half")
	}
	return output.Bytes(), nil
}

func resolveKeyReference(root, reference string) ([]byte, string, error) {
	value := reference
	secretOrigin := false
	switch {
	case strings.HasPrefix(reference, "env://"):
		name := strings.TrimPrefix(reference, "env://")
		var ok bool
		value, ok = os.LookupEnv(name)
		if !ok || strings.TrimSpace(value) == "" {
			return nil, "", fmt.Errorf("environment key reference %s is unset", name)
		}
		secretOrigin = true
	case strings.HasPrefix(reference, "agent://"):
		value = strings.TrimPrefix(reference, "agent://")
	case strings.HasPrefix(reference, "file://"):
		value = strings.TrimPrefix(reference, "file://")
	}
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	if managedFingerprint.MatchString(value) {
		return nil, strings.ToUpper(value), nil
	}
	if strings.Contains(value, "-----BEGIN PGP ") {
		if len(value) > maxManagedKeyBytes {
			return nil, "", errors.New("inline public key exceeds 16 MiB")
		}
		return []byte(value), "", nil
	}
	filename := value
	if !filepath.IsAbs(filename) {
		filename = filepath.Join(root, filename)
	}
	data, err := readBoundedRegularNoFollow(filename, maxManagedKeyBytes)
	if err != nil {
		if secretOrigin {
			return nil, "", errors.New("environment key reference does not resolve to a bounded regular file or OpenPGP key")
		}
		return nil, "", errors.New("key reference does not resolve to a bounded regular file")
	}
	return data, "", nil
}

const maxManagedPassphraseBytes = 64 << 10

func resolvePassphraseReference(root, reference string) ([]byte, error) {
	if reference == "" {
		return nil, nil
	}
	var secret []byte
	switch {
	case strings.HasPrefix(reference, "env://"):
		value, ok := os.LookupEnv(strings.TrimPrefix(reference, "env://"))
		if !ok {
			return nil, errors.New("environment passphrase reference is unset")
		}
		if len(value) > maxManagedPassphraseBytes {
			return nil, errors.New("environment passphrase reference is unbounded")
		}
		secret = []byte(value)
	case strings.HasPrefix(reference, "file://"):
		filename := strings.TrimPrefix(reference, "file://")
		if !filepath.IsAbs(filename) {
			filename = filepath.Join(root, filename)
		}
		data, err := readBoundedRegularNoFollow(filename, maxManagedPassphraseBytes)
		if err != nil {
			return nil, errors.New("passphrase file reference is missing, unsafe, empty, or unbounded")
		}
		secret = data
	default:
		filename := reference
		if !filepath.IsAbs(filename) {
			filename = filepath.Join(root, filename)
		}
		data, err := readBoundedRegularNoFollow(filename, maxManagedPassphraseBytes)
		if err != nil {
			return nil, errors.New("passphrase file reference is missing, unsafe, empty, or unbounded")
		}
		secret = data
	}
	secret = bytes.TrimSuffix(secret, []byte("\n"))
	secret = bytes.TrimSuffix(secret, []byte("\r"))
	if len(secret) == 0 || len(secret) > maxManagedPassphraseBytes || bytes.IndexByte(secret, 0) >= 0 {
		zeroSecret(secret)
		return nil, errors.New("passphrase reference resolves to an empty, invalid, or unbounded secret")
	}
	return secret, nil
}

func zeroSecret(secret []byte) {
	for index := range secret {
		secret[index] = 0
	}
}

func exportPublicKey(ctx context.Context, identity string) ([]byte, error) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		return nil, errors.New("gpg executable is required to export a configured agent key")
	}
	command := exec.CommandContext(ctx, gpg, "--batch", "--no-tty", "--armor", "--export", identity)
	var stdout bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("gpg public-key export failed: %w", err)
	}
	if stdout.Len() == 0 || stdout.Len() > maxManagedKeyBytes {
		return nil, errors.New("gpg public-key export returned no bounded key material")
	}
	return stdout.Bytes(), nil
}
