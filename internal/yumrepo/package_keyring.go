package yumrepo

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgpv2 "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// ParseRPMPackageKeyring parses a public-only package trust bundle while
// retaining every signing-subkey binding packet. The legacy openpgp Entity
// model keeps only the newest binding, which would make a harmless future
// expiry renewal strand RPMs signed under the prior, then-valid binding.
//
// The returned adapter still implements the legacy KeyRing interface used by
// the RPM packet verifier. Its time-aware lookup exposes only the latest
// cryptographically valid, signature-unexpired binding at the package
// signature time. Older bindings cannot override a newer usage or lifetime
// policy that was already in force.
func ParseRPMPackageKeyring(data []byte) (openpgp.KeyRing, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("yumrepo: RPM package keyring is empty")
	}
	legacy, historical, err := parsePackageKeyringModels(data)
	if err != nil {
		return nil, fmt.Errorf("yumrepo: parse RPM package keyring: %w", err)
	}
	if len(legacy) == 0 || len(historical) == 0 {
		return nil, errors.New("yumrepo: RPM package keyring contains no usable OpenPGP public keys")
	}
	legacyPrimaries := make(map[string]struct{}, len(legacy))
	for _, entity := range legacy {
		if entity == nil || entity.PrimaryKey == nil || entity.PrivateKey != nil {
			return nil, errors.New("yumrepo: RPM package keyring must contain public keys only")
		}
		primary := hex.EncodeToString(entity.PrimaryKey.Fingerprint)
		if _, exists := legacyPrimaries[primary]; exists {
			return nil, errors.New("yumrepo: RPM package keyring contains duplicate versions of one primary certificate")
		}
		legacyPrimaries[primary] = struct{}{}
		for _, subkey := range entity.Subkeys {
			if subkey.PrivateKey != nil {
				return nil, errors.New("yumrepo: RPM package keyring must contain public keys only")
			}
		}
	}

	bindings := make(map[string][]*packet.Signature)
	historicalPrimaries := make(map[string]struct{}, len(historical))
	for _, entity := range historical {
		if entity == nil || entity.PrimaryKey == nil || entity.PrivateKey != nil {
			return nil, errors.New("yumrepo: RPM package keyring historical model contains private or incomplete keys")
		}
		primary := hex.EncodeToString(entity.PrimaryKey.Fingerprint)
		if _, exists := historicalPrimaries[primary]; exists {
			return nil, errors.New("yumrepo: RPM package keyring historical model contains duplicate primary certificates")
		}
		historicalPrimaries[primary] = struct{}{}
		for index := range entity.Subkeys {
			subkey := &entity.Subkeys[index]
			if subkey.PublicKey == nil || subkey.PrivateKey != nil || len(subkey.Bindings) == 0 {
				return nil, errors.New("yumrepo: RPM package keyring contains an incomplete signing-subkey history")
			}
			key := packageSubkeyHistoryKey(primary, subkey.PublicKey.Fingerprint)
			for _, binding := range subkey.Bindings {
				if binding == nil || binding.Packet == nil {
					return nil, errors.New("yumrepo: RPM package keyring contains an incomplete subkey binding")
				}
				bindings[key] = append(bindings[key], binding.Packet)
			}
		}
	}
	for _, entity := range legacy {
		primary := hex.EncodeToString(entity.PrimaryKey.Fingerprint)
		if _, ok := historicalPrimaries[primary]; !ok {
			return nil, errors.New("yumrepo: RPM package keyring parser models disagree on primary keys")
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PublicKey == nil || len(bindings[packageSubkeyHistoryKey(primary, subkey.PublicKey.Fingerprint)]) == 0 {
				return nil, errors.New("yumrepo: RPM package keyring parser models disagree on subkeys")
			}
		}
	}
	return &historicalPackageKeyring{legacy: legacy, bindings: bindings}, nil
}

// RPMPackageKeyringPrimaryFingerprints returns the deduplicated primary
// fingerprints from a package trust bundle after applying the same
// public-only and historical signing-subkey validation as
// ParseRPMPackageKeyring. Callers that build an aggregate trust closure must
// not reparse package trust with the lossy legacy model merely to enumerate
// identities.
func RPMPackageKeyringPrimaryFingerprints(data []byte) ([]string, error) {
	keyring, err := ParseRPMPackageKeyring(data)
	if err != nil {
		return nil, err
	}
	historical, ok := keyring.(*historicalPackageKeyring)
	if !ok || historical == nil || len(historical.legacy) == 0 {
		return nil, errors.New("yumrepo: RPM package keyring parser returned no inspectable identities")
	}
	fingerprints := make([]string, 0, len(historical.legacy))
	seen := make(map[string]struct{}, len(historical.legacy))
	for _, entity := range historical.legacy {
		if entity == nil || entity.PrimaryKey == nil {
			return nil, errors.New("yumrepo: RPM package keyring contains an unusable primary identity")
		}
		fingerprint := hex.EncodeToString(entity.PrimaryKey.Fingerprint)
		if _, duplicate := seen[fingerprint]; duplicate {
			return nil, errors.New("yumrepo: RPM package keyring contains duplicate primary identities")
		}
		seen[fingerprint] = struct{}{}
		fingerprints = append(fingerprints, fingerprint)
	}
	sort.Strings(fingerprints)
	return fingerprints, nil
}

// ParsePublicKeyring parses every public key in a binary or ASCII-armored
// bundle. Armor is consumed block-by-block so trailing private material or
// garbage cannot hide behind the first valid public block.
func ParsePublicKeyring(data []byte) (openpgp.EntityList, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("yumrepo: OpenPGP public keyring is empty")
	}
	entities, err := parseLegacyKeyring(data)
	if err != nil {
		return nil, fmt.Errorf("yumrepo: parse OpenPGP public keyring: %w", err)
	}
	if len(entities) == 0 {
		return nil, errors.New("yumrepo: OpenPGP public keyring contains no usable keys")
	}
	seen := make(map[string]struct{}, len(entities))
	for _, entity := range entities {
		if entity == nil || entity.PrimaryKey == nil || entity.PrivateKey != nil {
			return nil, errors.New("yumrepo: OpenPGP public keyring must contain public keys only")
		}
		fingerprint := hex.EncodeToString(entity.PrimaryKey.Fingerprint)
		if _, exists := seen[fingerprint]; exists {
			return nil, errors.New("yumrepo: OpenPGP public keyring contains duplicate primary certificates")
		}
		seen[fingerprint] = struct{}{}
		for _, subkey := range entity.Subkeys {
			if subkey.PrivateKey != nil {
				return nil, errors.New("yumrepo: OpenPGP public keyring must contain public keys only")
			}
		}
	}
	return entities, nil
}

func parsePackageKeyringModels(data []byte) (openpgp.EntityList, openpgpv2.EntityList, error) {
	legacy, err := parseLegacyKeyring(data)
	if err != nil {
		return nil, nil, err
	}
	historical, err := parseHistoricalKeyring(data)
	return legacy, historical, err
}

func parseLegacyKeyring(data []byte) (openpgp.EntityList, error) {
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN PGP")) {
		// Binary OpenPGP packets are arbitrary octets. In particular, a valid
		// signature MPI can end in an ASCII whitespace byte. Trimming a binary
		// keyring would silently truncate that packet and make acceptance depend
		// on random key material.
		return openpgp.ReadKeyRing(bytes.NewReader(data))
	}
	blocks, err := splitPublicKeyArmorBlocks(trimmed)
	if err != nil {
		return nil, err
	}
	var entities openpgp.EntityList
	for _, block := range blocks {
		current, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(block))
		if err != nil {
			return nil, err
		}
		entities = append(entities, current...)
	}
	return entities, nil
}

func parseHistoricalKeyring(data []byte) (openpgpv2.EntityList, error) {
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN PGP")) {
		return openpgpv2.ReadKeyRing(bytes.NewReader(data))
	}
	blocks, err := splitPublicKeyArmorBlocks(trimmed)
	if err != nil {
		return nil, err
	}
	var entities openpgpv2.EntityList
	for _, block := range blocks {
		current, err := openpgpv2.ReadArmoredKeyRing(bytes.NewReader(block))
		if err != nil {
			return nil, err
		}
		entities = append(entities, current...)
	}
	return entities, nil
}

func splitPublicKeyArmorBlocks(data []byte) ([][]byte, error) {
	const (
		begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
		end   = "-----END PGP PUBLIC KEY BLOCK-----"
	)
	remaining := bytes.TrimSpace(data)
	var blocks [][]byte
	for len(remaining) > 0 {
		firstEnd := bytes.IndexByte(remaining, '\n')
		if firstEnd < 0 {
			firstEnd = len(remaining)
		}
		if string(bytes.TrimSpace(remaining[:firstEnd])) != begin {
			return nil, errors.New("yumrepo: armored RPM package keyring must contain public-key blocks only")
		}
		offset := 0
		found := false
		for offset < len(remaining) {
			lineEnd := bytes.IndexByte(remaining[offset:], '\n')
			blockEnd := len(remaining)
			lineLimit := len(remaining)
			if lineEnd >= 0 {
				lineLimit = offset + lineEnd
				blockEnd = lineLimit + 1
			}
			if string(bytes.TrimSpace(remaining[offset:lineLimit])) == end {
				block := append([]byte(nil), remaining[:blockEnd]...)
				blocks = append(blocks, block)
				remaining = bytes.TrimSpace(remaining[blockEnd:])
				found = true
				break
			}
			if lineEnd < 0 {
				break
			}
			offset = blockEnd
		}
		if !found {
			return nil, errors.New("yumrepo: unterminated armored RPM package public key block")
		}
	}
	if len(blocks) == 0 {
		return nil, errors.New("yumrepo: armored RPM package keyring is empty")
	}
	return blocks, nil
}

type historicalPackageKeyring struct {
	legacy   openpgp.EntityList
	bindings map[string][]*packet.Signature
}

func (keyring *historicalPackageKeyring) KeysById(id uint64) []openpgp.Key {
	if keyring == nil {
		return nil
	}
	// A timeless legacy lookup must never enumerate historical alternatives:
	// that would let a caller fall back around a newer restrictive binding.
	return keyring.legacy.KeysById(id)
}

func (keyring *historicalPackageKeyring) KeysByIdAt(id uint64, at time.Time) []openpgp.Key {
	if keyring == nil || at.IsZero() {
		return nil
	}
	base := keyring.legacy.KeysById(id)
	keys := make([]openpgp.Key, 0, len(base))
	for _, key := range base {
		if key.Entity == nil || key.Entity.PrimaryKey == nil || key.PublicKey == nil || key.PublicKey == key.Entity.PrimaryKey {
			keys = append(keys, key)
			continue
		}
		historyKey := packageSubkeyHistoryKey(hex.EncodeToString(key.Entity.PrimaryKey.Fingerprint), key.PublicKey.Fingerprint)
		var selected *packet.Signature
		ambiguous := false
		for _, binding := range keyring.bindings[historyKey] {
			if binding == nil || binding.CreationTime.After(at) ||
				key.Entity.PrimaryKey.VerifyKeySignature(key.PublicKey, binding) != nil {
				continue
			}
			if selected == nil || binding.CreationTime.After(selected.CreationTime) {
				selected = binding
				ambiguous = false
				continue
			}
			if binding.CreationTime.Equal(selected.CreationTime) && binding != selected {
				ambiguous = true
			}
		}
		if selected != nil && !ambiguous {
			candidate := key
			candidate.SelfSignature = selected
			keys = append(keys, candidate)
		}
	}
	return keys
}

func (keyring *historicalPackageKeyring) KeysByIdUsage(id uint64, requiredUsage byte) []openpgp.Key {
	keys := keyring.KeysById(id)
	result := keys[:0]
	for _, key := range keys {
		if requiredUsage != 0 {
			signature := key.SelfSignature
			if signature == nil || !signature.FlagsValid {
				continue
			}
			var usage byte
			if signature.FlagCertify {
				usage |= packet.KeyFlagCertify
			}
			if signature.FlagSign {
				usage |= packet.KeyFlagSign
			}
			if signature.FlagEncryptCommunications {
				usage |= packet.KeyFlagEncryptCommunications
			}
			if signature.FlagEncryptStorage {
				usage |= packet.KeyFlagEncryptStorage
			}
			if usage&requiredUsage != requiredUsage {
				continue
			}
		}
		result = append(result, key)
	}
	return result
}

func (keyring *historicalPackageKeyring) DecryptionKeys() []openpgp.Key {
	if keyring == nil {
		return nil
	}
	return keyring.legacy.DecryptionKeys()
}

func packageSubkeyHistoryKey(primary string, subkeyFingerprint []byte) string {
	return primary + ":" + hex.EncodeToString(subkeyFingerprint)
}
