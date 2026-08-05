package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
)

func TestSecretResolutionNeverEchoesValues(t *testing.T) {
	t.Setenv("SOW_TEST_SECRET", "super-secret-value")
	value, err := resolveSecret("env://SOW_TEST_SECRET", "", false)
	if err != nil || string(value) != "super-secret-value" {
		t.Fatalf("resolve value length=%d err=%v", len(value), err)
	}
	clearSecret(value)
	if strings.Contains(string(value), "super-secret") {
		t.Fatal("secret bytes were not cleared")
	}
	_, err = resolveSecret("env://MISSING_SOW_TEST_SECRET", "", false)
	if err == nil || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("missing secret error=%v", err)
	}
}

func TestSecretFileRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.WriteFile(real, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSecret("", link, false); err == nil || strings.Contains(err.Error(), "secret\"") {
		t.Fatalf("symlink secret accepted or leaked: %v", err)
	}
}

func TestRepositorySigningKeyPairMustMatchConfiguredTrustAnchor(t *testing.T) {
	root := t.TempDir()
	trustedPrivate, trustedPublic := generateRepositorySigningKey(t, "trusted")
	unrelatedPrivate, _ := generateRepositorySigningKey(t, "unrelated")
	if err := validateRepositorySigningKeyPair(&config.Config{}, trustedPrivate); err == nil || !strings.Contains(err.Error(), "gpg.public_key") {
		t.Fatalf("package signing without a configured trust anchor was accepted: %v", err)
	}
	publicPath := filepath.Join(root, "repository-public.pgp")
	if err := os.WriteFile(publicPath, trustedPublic, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Path: filepath.Join(root, "sow.yaml"),
		GPG:  config.GPGConfig{PublicKey: filepath.Base(publicPath)},
	}
	if err := validateRepositorySigningKeyPair(cfg, trustedPrivate); err != nil {
		t.Fatalf("matching signing key was rejected: %v", err)
	}
	if err := validateRepositorySigningKeyPair(cfg, unrelatedPrivate); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unrelated signing key was accepted: %v", err)
	}
}

func TestRepositoryPublicTrustAnchorRejectsPrivateMaterial(t *testing.T) {
	root := t.TempDir()
	private, _ := generateRepositorySigningKey(t, "private-anchor")
	anchorPath := filepath.Join(root, "repository-public.pgp")
	if err := os.WriteFile(anchorPath, private, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Path: filepath.Join(root, "sow.yaml"),
		GPG:  config.GPGConfig{PublicKey: filepath.Base(anchorPath)},
	}
	if err := validateRepositorySigningKeyPair(cfg, private); err == nil || !strings.Contains(err.Error(), "public") {
		t.Fatalf("private material in public trust anchor was accepted: %v", err)
	}
}

func TestRepositoryPublicTrustAnchorRejectsExpiredSigningKey(t *testing.T) {
	root := t.TempDir()
	created := time.Unix(1_500_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW expired", "", "expired@example.invalid", &packet.Config{
		Time:            func() time.Time { return created },
		RSABits:         testOpenPGPRSABits,
		KeyLifetimeSecs: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	var private, public bytes.Buffer
	if err := entity.SerializePrivate(&private, &packet.Config{Time: func() time.Time { return created }, KeyLifetimeSecs: 60}); err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(root, "expired-public.pgp")
	if err := os.WriteFile(publicPath, public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Path: filepath.Join(root, "sow.yaml"), GPG: config.GPGConfig{PublicKey: filepath.Base(publicPath)}}
	if _, err := repositorySigningKeyIdentity(cfg, private.Bytes()); err == nil || !strings.Contains(err.Error(), "currently usable") {
		t.Fatalf("expired repository signing key was accepted: %v", err)
	}
}

func TestRepositoryPublicTrustAnchorRejectsMultipleSigningFingerprints(t *testing.T) {
	root := t.TempDir()
	created := time.Now().UTC().Add(-time.Hour)
	entity, err := openpgp.NewEntity("SOW multi signer", "", "multi-signer@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: testOpenPGPRSABits})
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.AddSigningSubkey(&packet.Config{Time: func() time.Time { return created.Add(time.Second) }, RSABits: testOpenPGPRSABits}); err != nil {
		t.Fatal(err)
	}
	var public bytes.Buffer
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(root, "multiple-signers.pgp")
	if err := os.WriteFile(publicPath, public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadRepositoryPublicTrustAnchor(filepath.Join(root, "sow.yaml"), filepath.Base(publicPath)); err == nil || !strings.Contains(err.Error(), "exactly one repository signing key") {
		t.Fatalf("multiple public signing fingerprints were accepted: %v", err)
	}
}

func TestSigningSecretLoadersRejectUnrelatedOverride(t *testing.T) {
	root := t.TempDir()
	_, trustedPublic := generateRepositorySigningKey(t, "loader-trusted")
	unrelatedPrivate, _ := generateRepositorySigningKey(t, "loader-unrelated")
	publicPath := filepath.Join(root, "repository-public.pgp")
	privatePath := filepath.Join(root, "unrelated-private.pgp")
	if err := os.WriteFile(publicPath, trustedPublic, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privatePath, unrelatedPrivate, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Path: filepath.Join(root, "sow.yaml"),
		GPG:  config.GPGConfig{PublicKey: filepath.Base(publicPath)},
	}
	if private, passphrase, err := loadPublishSigningSecrets(cfg, []config.Repo{{Type: "apt"}}, privatePath, ""); err == nil || private != nil || passphrase != nil {
		t.Fatalf("publish accepted unrelated private override: private=%d passphrase=%d err=%v", len(private), len(passphrase), err)
	}
	leaf := viewLeaf{repo: config.Repo{Type: "yum"}}
	if private, passphrase, err := loadMaterializeSigningSecrets(cfg, []viewLeaf{leaf}, privatePath, ""); err == nil || private != nil || passphrase != nil {
		t.Fatalf("materialize accepted unrelated private override: private=%d passphrase=%d err=%v", len(private), len(passphrase), err)
	}
}

func TestRepositoryTrustAnchorDigestBindsPacketStreamOnlyForPackageRefs(t *testing.T) {
	root := t.TempDir()
	_, trustedPublic := generateRepositorySigningKey(t, "digest-trusted")
	_, rotatedPublic := generateRepositorySigningKey(t, "digest-rotated")
	publicPath := filepath.Join(root, "repository-public.pgp")
	if err := os.WriteFile(publicPath, trustedPublic, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Path: filepath.Join(root, "sow.yaml"),
		GPG:  config.GPGConfig{PublicKey: filepath.Base(publicPath)},
		Repos: []config.Repo{
			{ID: "packages", Type: "apt", Arches: []string{"amd64"}, APT: &config.APTConfig{Suites: []string{"bookworm"}}},
			{ID: "assets", Type: "asset"},
		},
	}
	assetRefs := []pub.RefState{{Name: "refs/sow/views/latest/assets/all/all"}}
	packageRefs := []pub.RefState{{Name: "refs/sow/views/latest/packages/bookworm/amd64"}}
	assetDigest, err := repositoryTrustAnchorSHA256ForRefs(cfg, assetRefs)
	if err != nil || assetDigest != "" {
		t.Fatalf("asset-only digest=%s err=%v", assetDigest, err)
	}
	trustedDigest, err := repositoryTrustAnchorSHA256ForRefs(cfg, packageRefs)
	if err != nil || len(trustedDigest) != 64 {
		t.Fatalf("package digest did not bind trust anchor: digest=%s err=%v", trustedDigest, err)
	}
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(trustedPublic))
	if err != nil || len(entities) != 1 {
		t.Fatalf("parse trusted key: entities=%d err=%v", len(entities), err)
	}
	var armored bytes.Buffer
	armorWriter, err := armor.Encode(&armored, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entities[0].Serialize(armorWriter); err != nil {
		t.Fatal(err)
	}
	if err := armorWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, armored.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	reserializedDigest, err := repositoryTrustAnchorSHA256ForRefs(cfg, packageRefs)
	if err != nil || reserializedDigest != trustedDigest {
		t.Fatalf("equivalent armor changed digest: binary=%s armor=%s err=%v", trustedDigest, reserializedDigest, err)
	}
	if err := os.WriteFile(publicPath, rotatedPublic, 0o644); err != nil {
		t.Fatal(err)
	}
	rotatedDigest, err := repositoryTrustAnchorSHA256ForRefs(cfg, packageRefs)
	if err != nil || rotatedDigest == trustedDigest {
		t.Fatalf("in-place key rotation was not bound: before=%s after=%s err=%v", trustedDigest, rotatedDigest, err)
	}
}

func TestRepositoryTrustAnchorDigestIsStableForMultiUIDKey(t *testing.T) {
	root := t.TempDir()
	created := time.Unix(1_700_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW multi uid", "", "first@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: testOpenPGPRSABits})
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.AddUserId("SOW second", "", "second@example.invalid", &packet.Config{Time: func() time.Time { return created.Add(time.Second) }}); err != nil {
		t.Fatal(err)
	}
	if err := entity.AddUserId("SOW third", "", "third@example.invalid", &packet.Config{Time: func() time.Time { return created.Add(2 * time.Second) }}); err != nil {
		t.Fatal(err)
	}
	var public bytes.Buffer
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(root, "repository-public.pgp")
	if err := os.WriteFile(publicPath, public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Path:  filepath.Join(root, "sow.yaml"),
		GPG:   config.GPGConfig{PublicKey: filepath.Base(publicPath)},
		Repos: []config.Repo{{ID: "packages", Type: "apt", Arches: []string{"amd64"}, APT: &config.APTConfig{Suites: []string{"bookworm"}}}},
	}
	refs := []pub.RefState{{Name: "refs/sow/views/latest/packages/bookworm/amd64"}}
	first, err := repositoryTrustAnchorSHA256ForRefs(cfg, refs)
	if err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 256; iteration++ {
		current, err := repositoryTrustAnchorSHA256ForRefs(cfg, refs)
		if err != nil || current != first {
			t.Fatalf("multi-UID digest drift at iteration %d: first=%s current=%s err=%v", iteration, first, current, err)
		}
	}
}

func TestPublicationTrustRejectsRemovedRetypedAndMissingLeaves(t *testing.T) {
	ref := func(repo, osName, arch string) []pub.RefState {
		return []pub.RefState{{Name: "refs/sow/views/beta/" + repo + "/" + osName + "/" + arch}}
	}
	for name, cfg := range map[string]*config.Config{
		"removed": {Repos: []config.Repo{{ID: "assets", Type: "asset"}}},
		"retyped": {Repos: []config.Repo{{ID: "packages", Type: "asset"}}},
		"leaf":    {Repos: []config.Repo{{ID: "packages", Type: "apt", Arches: []string{"amd64"}, APT: &config.APTConfig{Suites: []string{"bookworm"}}}}},
	} {
		name, cfg := name, cfg
		t.Run(name, func(t *testing.T) {
			repo, suite := "packages", "bookworm"
			if name == "removed" {
				repo = "removed-packages"
			}
			if name == "leaf" {
				suite = "trixie"
			}
			if _, err := publicationRefsRequireRepositoryTrust(cfg, ref(repo, suite, "amd64")); err == nil || !strings.Contains(err.Error(), "not representable") {
				t.Fatalf("stale publication ref was accepted: %v", err)
			}
		})
	}
}

func generateRepositorySigningKey(t *testing.T, identity string) ([]byte, []byte) {
	t.Helper()
	created := time.Unix(1_700_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW "+identity, "", identity+"@example.invalid", &packet.Config{
		Time:    func() time.Time { return created },
		RSABits: testOpenPGPRSABits,
	})
	if err != nil {
		t.Fatal(err)
	}
	var private, public bytes.Buffer
	if err := entity.SerializePrivate(&private, &packet.Config{Time: func() time.Time { return created }}); err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), private.Bytes()...), append([]byte(nil), public.Bytes()...)
}
