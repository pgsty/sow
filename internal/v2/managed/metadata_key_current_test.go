package managed

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pgsty/sow/internal/v2/config"
)

func TestNewMetadataSigningRejectsExpiredCertificateWithoutChangingHistoricalValidation(t *testing.T) {
	created := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	cfg := &packet.Config{DefaultHash: crypto.SHA256, RSABits: 1024, KeyLifetimeSecs: 3600, Time: func() time.Time { return created }}
	entity, err := openpgp.NewEntity("expiry", "", "expiry@example.invalid", cfg)
	if err != nil {
		t.Fatal(err)
	}
	var public bytes.Buffer
	armored, err := armor.Encode(&public, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(armored); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := metadataIdentityFromMaterial(public.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := metadataSignerSnapshot{RPM: identity, DEB: identity}
	if err := validateNewMetadataSigningKeys(snapshot, created.Add(time.Minute), created.Add(time.Minute)); err != nil {
		t.Fatalf("historically valid key: %v", err)
	}
	if err := validateNewMetadataSigningKeys(snapshot, created.Add(time.Minute), time.Now()); !errors.Is(err, ErrRejected) {
		t.Fatalf("expired key accepted: %v", err)
	}
	if err := validateMetadataSignerIdentity(identity); err != nil {
		t.Fatalf("historical identity was invalidated: %v", err)
	}
}

func TestNewMetadataSigningRejectsExpiredSelectedSubkey(t *testing.T) {
	created := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	cfg := &packet.Config{DefaultHash: crypto.SHA256, RSABits: 1024, Time: func() time.Time { return created }}
	entity, err := openpgp.NewEntity("subkey expiry", "", "subkey@example.invalid", cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.KeyLifetimeSecs = 3600
	if err := entity.AddSigningSubkey(cfg); err != nil {
		t.Fatal(err)
	}
	// The historical publication time selects the now-expired signing subkey,
	// while checking any usable key now silently falls back to the primary.
	selected, ok := entity.SigningKey(created.Add(time.Minute))
	if !ok || selected.PublicKey == entity.PrimaryKey {
		t.Fatal("fixture did not select its signing subkey")
	}
	current, ok := entity.SigningKey(time.Now())
	if !ok || current.PublicKey != entity.PrimaryKey {
		t.Fatal("fixture did not retain a usable primary key")
	}
	var public bytes.Buffer
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	identity, err := metadataIdentityFromMaterial(public.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := metadataSignerSnapshot{RPM: identity, DEB: identity}
	if err := validateNewMetadataSigningKeys(snapshot, created.Add(time.Minute), time.Now()); !errors.Is(err, ErrRejected) {
		t.Fatalf("expired selected subkey accepted through primary fallback: %v", err)
	}
	if err := validateNewMetadataSigningKeys(snapshot, time.Now(), time.Now()); err != nil {
		t.Fatalf("currently selected primary key was rejected: %v", err)
	}
	// An agent holding only the primary may legitimately select it even at
	// the historical time; validation must follow the real signer selection.
	identity.SelectedFingerprint = identity.Fingerprint
	snapshot.RPM, snapshot.DEB = identity, identity
	if err := validateNewMetadataSigningKeys(snapshot, created.Add(time.Minute), time.Now()); err != nil {
		t.Fatalf("usable actual primary rejected because another subkey expired: %v", err)
	}
}

func TestDEBConfigCheckRejectsExpiredFileSigningKey(t *testing.T) {
	created := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	cfg := &packet.Config{DefaultHash: crypto.SHA256, RSABits: 1024, KeyLifetimeSecs: 3600, Time: func() time.Time { return created }}
	entity, err := openpgp.NewEntity("expired config", "", "expired@example.invalid", cfg)
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	armored, err := armor.Encode(&private, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivateWithoutSigning(armored, cfg); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_EXPIRED_DEB_METADATA_KEY", private.String())
	signing := config.SigningConfig{DEB: config.DEBSigningConfig{Metadata: config.MetadataSigningConfig{Key: "env://SOW_EXPIRED_DEB_METADATA_KEY"}}}
	if err := validateSigningApplicabilityForFormats(context.Background(), t.TempDir(), signing, false, true); !errors.Is(err, errMetadataSigningPolicy) {
		t.Fatalf("expired DEB metadata key not identified as a signing-policy rejection: %v", err)
	}
}
