package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
)

const maxSecretBytes = 16 << 20

func resolveSecret(reference, overrideFile string, optional bool) ([]byte, error) {
	if overrideFile != "" {
		return readSecretFile(overrideFile)
	}
	if reference == "" {
		if optional {
			return nil, nil
		}
		return nil, errors.New("required secret reference is not configured")
	}
	if !strings.HasPrefix(reference, "env://") {
		return nil, errors.New("selected CLI operation supports only env:// secret references or an explicit secret file")
	}
	name := strings.TrimPrefix(reference, "env://")
	value, exists := os.LookupEnv(name)
	if !exists || (!optional && value == "") {
		return nil, fmt.Errorf("required environment secret %s is not set", name)
	}
	if len(value) > maxSecretBytes {
		return nil, fmt.Errorf("environment secret %s exceeds the size limit", name)
	}
	return []byte(value), nil
}

func readSecretFile(path string) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New("resolve secret file")
	}
	info, err := os.Lstat(abs)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("secret file must be a regular non-symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("secret file permissions must not grant group or other access")
	}
	file, err := os.Open(abs)
	if err != nil {
		return nil, errors.New("open secret file")
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		file.Close()
		return nil, errors.New("secret file changed while opening")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxSecretBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		clearSecret(data)
		return nil, errors.New("read secret file")
	}
	if len(data) == 0 || len(data) > maxSecretBytes {
		clearSecret(data)
		return nil, errors.New("secret file is empty or exceeds the size limit")
	}
	after, err := os.Lstat(abs)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		clearSecret(data)
		return nil, errors.New("secret file changed while reading")
	}
	return data, nil
}

func clearSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// repositoryTrustAnchorSHA256ForRefs binds package generations to the exact
// OpenPGP packet stream trusted by clients. Armor framing is normalized away;
// the parsed Entity is never re-serialized because its identity map has no
// deterministic iteration order. Genuinely asset-only generations return an
// empty identity and do not acquire an unrelated key dependency.
func repositoryTrustAnchorSHA256ForRefs(cfg *config.Config, refs []pub.RefState) (string, error) {
	if cfg == nil {
		return "", errors.New("publication configuration is unavailable")
	}
	requiresTrust, err := publicationRefsRequireRepositoryTrust(cfg, refs)
	if err != nil {
		return "", err
	}
	if !requiresTrust {
		return "", nil
	}
	if cfg.GPG.PublicKey == "" {
		return "", errors.New("gpg.public_key is required for package repository publication")
	}
	_, packets, err := loadRepositoryPublicTrustAnchor(cfg.Path, cfg.GPG.PublicKey)
	if err != nil {
		return "", err
	}
	return repositoryTrustAnchorDigest(packets), nil
}

func repositoryTrustAnchorDigest(packets []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("sow-repository-public-key-v1\x00"))
	_, _ = digest.Write(packets)
	return hex.EncodeToString(digest.Sum(nil))
}

func publicationRefsRequireRepositoryTrust(cfg *config.Config, refs []pub.RefState) (bool, error) {
	configuredLeaves := make(map[string]config.Repo)
	for _, leaf := range selectedLeaves(cfg.Repos, commonFlags{}) {
		configuredLeaves[leaf.repo.ID+"\x00"+leaf.os+"\x00"+leaf.arch] = leaf.repo
	}
	requiresTrust := false
	for _, ref := range refs {
		name := ref.Name
		for _, prefix := range []string{"refs/sow/views/", "refs/sow/snapshots/"} {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			parts := strings.Split(strings.TrimPrefix(name, prefix), "/")
			if len(parts) != 4 {
				return false, fmt.Errorf("invalid desired publication ref %q", name)
			}
			repo, exists := configuredLeaves[parts[1]+"\x00"+parts[2]+"\x00"+parts[3]]
			if !exists {
				return false, fmt.Errorf("desired publication ref %q is not representable by the current repository type/leaf configuration", name)
			}
			if repo.Type == "apt" || repo.Type == "yum" {
				requiresTrust = true
			}
			name = ""
			break
		}
		if name != "" {
			return false, fmt.Errorf("unsupported desired publication ref %q", ref.Name)
		}
	}
	return requiresTrust, nil
}

func loadRepositoryPublicTrustAnchor(configPath, relative string) (*openpgp.Entity, []byte, error) {
	return loadRepositoryPublicTrustAnchorAt(configPath, relative, time.Now().UTC())
}

func loadRepositoryPublicTrustAnchorAt(configPath, relative string, at time.Time) (*openpgp.Entity, []byte, error) {
	if at.IsZero() {
		return nil, nil, errors.New("repository public-key validation time is required")
	}
	if relative == "" {
		return nil, nil, errors.New("gpg.public_key is required for package repository signing")
	}
	filename := relative
	if !filepath.IsAbs(filename) {
		filename = filepath.Join(filepath.Dir(configPath), filepath.FromSlash(relative))
	}
	abs, err := filepath.Abs(filename)
	if err != nil {
		return nil, nil, errors.New("resolve repository public key path")
	}
	before, err := os.Lstat(abs)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maxSecretBytes {
		return nil, nil, errors.New("repository public key must be a bounded regular non-symlink file")
	}
	file, err := os.Open(abs)
	if err != nil {
		return nil, nil, errors.New("open repository public key")
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		file.Close()
		return nil, nil, errors.New("repository public key changed while opening")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxSecretBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > maxSecretBytes {
		return nil, nil, errors.New("read repository public key")
	}
	after, err := os.Lstat(abs)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, nil, errors.New("repository public key changed while reading")
	}
	return parseRepositoryPublicTrustAnchorAt(data, at)
}

func parseRepositoryPublicTrustAnchor(data []byte) (*openpgp.Entity, []byte, error) {
	return parseRepositoryPublicTrustAnchorAt(data, time.Now().UTC())
}

func parseRepositoryPublicTrustAnchorAt(data []byte, at time.Time) (*openpgp.Entity, []byte, error) {
	if at.IsZero() {
		return nil, nil, errors.New("repository public-key validation time is required")
	}
	packets, err := decodeRepositoryPublicKeyPackets(data)
	if err != nil {
		return nil, nil, err
	}
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(packets))
	if err != nil || len(entities) != 1 || entities[0] == nil || entities[0].PrimaryKey == nil || entityHasPrivateMaterial(entities[0]) {
		return nil, nil, errors.New("gpg.public_key must contain exactly one public OpenPGP entity")
	}
	signingFingerprint, err := solePublicSigningFingerprint(entities[0])
	if err != nil {
		return nil, nil, errors.New("gpg.public_key must contain exactly one repository signing key")
	}
	usable, ok := entities[0].SigningKey(at.UTC())
	if !ok || usable.PublicKey == nil || !bytes.Equal(usable.PublicKey.Fingerprint, signingFingerprint) {
		return nil, nil, errors.New("gpg.public_key has no currently usable sole repository signing key")
	}
	return entities[0], packets, nil
}

func decodeRepositoryPublicKeyPackets(data []byte) ([]byte, error) {
	trimmedBytes := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmedBytes, []byte("-----BEGIN PGP")) {
		return append([]byte(nil), data...), nil
	}
	text := strings.TrimSpace(string(trimmedBytes))
	if strings.Contains(text, "\r") {
		text = strings.ReplaceAll(text, "\r\n", "\n")
		if strings.Contains(text, "\r") {
			return nil, errors.New("malformed armored repository public key")
		}
	}
	lines := strings.Split(text, "\n")
	const begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	const end = "-----END PGP PUBLIC KEY BLOCK-----"
	if len(lines) < 4 || strings.TrimSpace(lines[0]) != begin || strings.TrimSpace(lines[len(lines)-1]) != end {
		return nil, errors.New("malformed armored repository public key")
	}
	separator := -1
	for index := 1; index < len(lines)-1; index++ {
		line := strings.TrimSpace(lines[index])
		if line == "" {
			separator = index
			break
		}
		if colon := strings.IndexByte(line, ':'); colon <= 0 {
			return nil, errors.New("malformed armored repository public key")
		}
	}
	if separator < 0 || separator == len(lines)-2 {
		return nil, errors.New("malformed armored repository public key")
	}
	var encoded strings.Builder
	var checksum []byte
	for index := separator + 1; index < len(lines)-1; index++ {
		line := strings.TrimSpace(lines[index])
		if line == "" || len(line) > 96 {
			return nil, errors.New("malformed armored repository public key")
		}
		if strings.HasPrefix(line, "=") {
			if index != len(lines)-2 || len(line) != 5 {
				return nil, errors.New("malformed armored repository public key")
			}
			checksum, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "="))
			if err != nil || len(checksum) != 3 {
				return nil, errors.New("malformed armored repository public key")
			}
			continue
		}
		if checksum != nil {
			return nil, errors.New("trailing data after armored repository public key")
		}
		encoded.WriteString(line)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil || len(decoded) == 0 || len(decoded) > maxSecretBytes {
		return nil, errors.New("malformed armored repository public key")
	}
	if checksum != nil {
		crc := openPGPArmorCRC24(decoded)
		if checksum[0] != byte(crc>>16) || checksum[1] != byte(crc>>8) || checksum[2] != byte(crc) {
			return nil, errors.New("armored repository public key checksum mismatch")
		}
	}
	return decoded, nil
}

func openPGPArmorCRC24(body []byte) uint32 {
	crc := uint32(0xb704ce)
	for _, value := range body {
		crc ^= uint32(value) << 16
		for bit := 0; bit < 8; bit++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= 0x1864cfb
			}
		}
	}
	return crc & 0xffffff
}

// validateRepositorySigningKeyPair prevents a valid but unrelated private key
// override from producing metadata that SOW can self-verify while configured
// apt/dnf clients reject it. A configured repository public key is the trust
// anchor; its primary key and sole private signing key must match exactly.
func validateRepositorySigningKeyPair(cfg *config.Config, privateKey []byte) error {
	_, err := repositorySigningKeyIdentity(cfg, privateKey)
	return err
}

// requireRepositorySigningKeyIdentity re-reads the public trust anchor at an
// irreversible-operation boundary and compares it with the packet identity
// captured during preflight. This closes the ordinary add/rm window where a
// key can be atomically replaced at the same configured path while the command
// is acquiring the canonical-state lock.
func requireRepositorySigningKeyIdentity(cfg *config.Config, privateKey []byte, expected string) error {
	return requireRepositorySigningKeyIdentityAt(cfg, privateKey, expected, time.Now().UTC())
}

func requireRepositorySigningKeyIdentityAt(cfg *config.Config, privateKey []byte, expected string, at time.Time) error {
	if len(expected) != sha256.Size*2 {
		return errors.New("expected repository signing key identity is invalid")
	}
	current, err := repositorySigningKeyIdentityAt(cfg, privateKey, at)
	if err != nil {
		return err
	}
	if current != expected {
		return errors.New("repository signing key changed after operation preflight")
	}
	return nil
}

func repositorySigningKeyIdentity(cfg *config.Config, privateKey []byte) (string, error) {
	return repositorySigningKeyIdentityAt(cfg, privateKey, time.Now().UTC())
}

func repositorySigningKeyIdentityAt(cfg *config.Config, privateKey []byte, at time.Time) (string, error) {
	if at.IsZero() {
		return "", errors.New("repository signing-key validation time is required")
	}
	if cfg == nil || len(privateKey) == 0 {
		return "", errors.New("repository signing key pair is incomplete")
	}
	if cfg.GPG.PublicKey == "" {
		return "", errors.New("gpg.public_key is required for package repository signing")
	}
	privateEntities, err := parseSingleRepositoryKey(privateKey)
	if err != nil {
		return "", errors.New("repository private key is invalid")
	}
	publicEntity, packets, err := loadRepositoryPublicTrustAnchorAt(cfg.Path, cfg.GPG.PublicKey, at)
	if err != nil {
		return "", err
	}
	privateEntity := privateEntities[0]
	if privateEntity.PrimaryKey == nil || publicEntity.PrimaryKey == nil ||
		!bytes.Equal(privateEntity.PrimaryKey.Fingerprint, publicEntity.PrimaryKey.Fingerprint) {
		return "", errors.New("repository private key does not match gpg.public_key")
	}
	signingFingerprint, err := solePrivateSigningFingerprint(privateEntity)
	publicSigningFingerprint, publicErr := solePublicSigningFingerprint(publicEntity)
	if err != nil || publicErr != nil || !bytes.Equal(signingFingerprint, publicSigningFingerprint) {
		return "", errors.New("repository private signing key does not match gpg.public_key")
	}
	return repositoryTrustAnchorDigest(packets), nil
}

func parseSingleRepositoryKey(data []byte) (openpgp.EntityList, error) {
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
	if err != nil || len(entities) != 1 || entities[0] == nil {
		return nil, errors.New("expected exactly one OpenPGP entity")
	}
	return entities, nil
}

func entityHasPrivateMaterial(entity *openpgp.Entity) bool {
	if entity == nil {
		return false
	}
	if entity.PrivateKey != nil {
		return true
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil {
			return true
		}
	}
	return false
}

func solePrivateSigningFingerprint(entity *openpgp.Entity) ([]byte, error) {
	candidates := signingFingerprints(entity, true)
	if len(candidates) != 1 {
		return nil, errors.New("repository key must contain exactly one private signing key")
	}
	return candidates[0], nil
}

func solePublicSigningFingerprint(entity *openpgp.Entity) ([]byte, error) {
	candidates := signingFingerprints(entity, false)
	if len(candidates) != 1 {
		return nil, errors.New("repository public key must contain exactly one signing key")
	}
	return candidates[0], nil
}

func signingFingerprints(entity *openpgp.Entity, requirePrivate bool) [][]byte {
	if entity == nil || entity.PrimaryKey == nil {
		return nil
	}
	byFingerprint := make(map[string][]byte)
	primaryCanSign := entity.PrimaryKey.PubKeyAlgo.CanSign() && (!requirePrivate || entity.PrivateKey != nil)
	if primaryCanSign {
		if entity.PrimaryKey.Version == 6 {
			signature := entity.SelfSignature
			if signature != nil && signature.FlagsValid && signature.FlagSign {
				byFingerprint[hex.EncodeToString(entity.PrimaryKey.Fingerprint)] = entity.PrimaryKey.Fingerprint
			}
		} else {
			for _, identity := range entity.Identities {
				if identity != nil && identity.SelfSignature != nil && identity.SelfSignature.FlagsValid && identity.SelfSignature.FlagSign {
					byFingerprint[hex.EncodeToString(entity.PrimaryKey.Fingerprint)] = entity.PrimaryKey.Fingerprint
					break
				}
			}
		}
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PublicKey != nil && subkey.Sig != nil && subkey.Sig.FlagsValid && subkey.Sig.FlagSign && subkey.PublicKey.PubKeyAlgo.CanSign() && (!requirePrivate || subkey.PrivateKey != nil) {
			byFingerprint[hex.EncodeToString(subkey.PublicKey.Fingerprint)] = subkey.PublicKey.Fingerprint
		}
	}
	keys := make([]string, 0, len(byFingerprint))
	for fingerprint := range byFingerprint {
		keys = append(keys, fingerprint)
	}
	sort.Strings(keys)
	result := make([][]byte, 0, len(keys))
	for _, fingerprint := range keys {
		result = append(result, byFingerprint[fingerprint])
	}
	return result
}
