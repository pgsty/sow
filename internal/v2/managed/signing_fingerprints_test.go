package managed

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pgsty/sow/internal/v2/config"
)

func TestMetadataKeyFingerprintRotationMarksDirtyAndRebuilds(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	keyOne, fingerprintOne := managedTestPrivateKey(t, "one")
	keyTwo, fingerprintTwo := managedTestPrivateKey(t, "two")
	t.Setenv("SOW_TEST_METADATA_KEY", string(keyOne))

	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{
		Signing: config.SigningConfig{
			RPM: config.RPMSigningConfig{Metadata: config.MetadataSigningConfig{Key: "env://SOW_TEST_METADATA_KEY"}},
			DEB: config.DEBSigningConfig{Metadata: config.MetadataSigningConfig{Key: "env://SOW_TEST_METADATA_KEY"}},
		},
		Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}, "noble": {Format: "deb"}},
	}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	view, err := ShowConfig(ctx, ConfigShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, All: true})
	if err != nil {
		t.Fatal(err)
	}
	effective := view.Repositories["repo"].Signing
	if effective.RPM.Metadata == nil || effective.RPM.Metadata.KeyFingerprint != fingerprintOne || effective.DEB == nil || effective.DEB.Metadata.KeyFingerprint != fingerprintOne {
		t.Fatalf("resolved signing fingerprints=%#v want=%s", effective, fingerprintOne)
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, keyOne) || strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("effective config exposed private key material")
	}
	if _, err := os.Stat(filepath.Join(root, "repo", "dists", "el9", "x86_64", "repodata", "repomd.xml.asc")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"InRelease", "Release.gpg"} {
		if _, err := os.Stat(filepath.Join(root, "repo", "dists", "noble", name)); err != nil {
			t.Fatal(err)
		}
	}
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1}); err != nil || !checked.ReadyToCopy {
		t.Fatalf("initial signed check=%#v err=%v", checked, err)
	}
	repomdSignature := filepath.Join(root, "repo", "dists", "el9", "x86_64", "repodata", "repomd.xml.asc")
	originalSignature, err := os.ReadFile(repomdSignature)
	if err != nil {
		t.Fatal(err)
	}
	tamperedSignature := append([]byte(nil), originalSignature...)
	tamperedSignature[len(tamperedSignature)/2] ^= 1
	if err := os.WriteFile(repomdSignature, tamperedSignature, 0o644); err != nil {
		t.Fatal(err)
	}
	tampered, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Jobs: 1})
	layers := make(map[string]CheckLayer, len(tampered.Layers))
	for _, layer := range tampered.Layers {
		layers[layer.Name] = layer
	}
	if !errors.Is(err, ErrIntegrity) || layers["signature"].OK || !layers["index"].OK {
		t.Fatalf("tampered repomd signature was not isolated to signature layer: checked=%#v err=%v", tampered, err)
	}
	if err := os.WriteFile(repomdSignature, originalSignature, 0o644); err != nil {
		t.Fatal(err)
	}
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1}); err != nil || !checked.ReadyToCopy {
		t.Fatalf("restored signed check=%#v err=%v", checked, err)
	}
	// Delivery verification is bound to the retained Built public certificate,
	// not to the continued presence of a private signing capability.
	t.Setenv("SOW_TEST_METADATA_KEY", "")
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1}); err != nil || !checked.ReadyToCopy || checked.Status != "clean" {
		t.Fatalf("offline signed check=%#v err=%v", checked, err)
	}
	if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrRejected) {
		t.Fatalf("config check accepted unavailable private key: %v", err)
	}
	if _, err := Build(ctx, BuildOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1}); err == nil {
		t.Fatal("build accepted unavailable private key")
	}

	t.Setenv("SOW_TEST_METADATA_KEY", string(keyTwo))
	for _, distName := range []string{"el9", "noble"} {
		shown, err := ShowDist(ctx, DistShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: distName})
		if err != nil || !shown.Dirty || shown.Status != "dirty" {
			t.Fatalf("rotated Dist %s=%#v err=%v", distName, shown, err)
		}
	}
	rotated, err := ShowConfig(ctx, ConfigShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, All: true})
	if err != nil || rotated.Repositories["repo"].Signing.RPM.Metadata.KeyFingerprint != fingerprintTwo {
		t.Fatalf("rotated config=%#v err=%v", rotated, err)
	}
	build, err := Build(ctx, BuildOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if err != nil || build.Dirty || build.Noop {
		t.Fatalf("rotation build=%#v err=%v", build, err)
	}
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1}); err != nil || !checked.ReadyToCopy {
		t.Fatalf("rotated signed check=%#v err=%v", checked, err)
	}

	// Re-selecting the old key is another renderer-input transition. The exact
	// current Generation (signed by key two) remains structurally and
	// manifest-valid, but it is not ready-to-copy until rebuilt with key one.
	t.Setenv("SOW_TEST_METADATA_KEY", string(keyOne))
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrNotReady) || checked.Status != "dirty" || checked.ReadyToCopy {
		t.Fatalf("wrong-key check=%#v err=%v", checked, err)
	}
}

func TestGPGStatusVerificationBindsExactlyOnePrimaryFingerprint(t *testing.T) {
	primary := strings.Repeat("A", 40)
	subkey := strings.Repeat("B", 40)
	valid := "[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG " + subkey + " 2026-08-02 0 4 0 1 10 00 " + primary + "\n"
	if !gpgStatusMatchesFingerprint(valid, primary) {
		t.Fatal("valid signing-subkey status did not bind to its primary fingerprint")
	}
	if gpgStatusMatchesFingerprint(valid, strings.Repeat("C", 40)) {
		t.Fatal("signature from a different primary fingerprint was accepted")
	}
	if gpgStatusMatchesFingerprint(valid+valid, primary) {
		t.Fatal("multiple valid signatures were accepted as one identity")
	}
	if gpgStatusMatchesFingerprint("[GNUPG:] GOODSIG 0123 signer\n", primary) {
		t.Fatal("GOODSIG without VALIDSIG was accepted")
	}
}

func TestMalformedEnvironmentKeyNeverEntersErrorText(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	const secret = "SOW-SUPER-SECRET-CONTENT-THAT-IS-NOT-A-KEY"
	t.Setenv("SOW_TEST_BAD_KEY", secret)
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{
		Signing: config.SigningConfig{RPM: config.RPMSigningConfig{Metadata: config.MetadataSigningConfig{Key: "env://SOW_TEST_BAD_KEY"}}},
		Dists:   map[string]config.DistConfig{"el9": {Format: "rpm"}},
	}
	_, err := EffectiveConfigView(ctx, root, cfg, config.ViewOptions{Repository: "repo"})
	if err == nil {
		t.Fatal("malformed environment key unexpectedly resolved")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error exposed environment key content: %v", err)
	}
}

func TestRPMPackageSigningPreflightUsesRPMMacroChannelInsteadOfDirectGPGProbe(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	privateKey, fingerprint := managedTestPrivateKey(t, "rpm-macro-channel")
	t.Setenv("SOW_TEST_RPM_MACRO_KEY", string(privateKey))
	tools := t.TempDir()
	gpg := "#!/bin/sh\ncase \" $* \" in\n  *\" --list-secret-keys \"*) printf 'sec::::::::::\\nfpr:::::::::" + fingerprint + ":\\n'; exit 0;;\n  *) exit 41;;\nesac\n"
	if err := os.WriteFile(filepath.Join(tools, "gpg"), []byte(gpg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "rpm"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	signing := config.SigningConfig{RPM: config.RPMSigningConfig{Packages: config.RPMPackageSigningConfig{Mode: "fill", Key: "env://SOW_TEST_RPM_MACRO_KEY"}}}
	if err := validateSigningApplicability(ctx, root, signing); err != nil {
		t.Fatalf("RPM macro-capable signing environment was rejected: %v", err)
	}
}

func TestEffectiveRPMPackageSigningFingerprintParity(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	currentKey, currentFingerprint := managedTestPrivateKey(t, "package-current")
	trustedKey, trustedFingerprint := managedTestPrivateKey(t, "package-trusted")
	trustedPublic, err := publicOpenPGPKeyMaterial(trustedKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_PACKAGE_CURRENT", string(currentKey))
	t.Setenv("SOW_TEST_PACKAGE_TRUSTED", string(trustedPublic))
	signing := config.SigningConfig{RPM: config.RPMSigningConfig{Packages: config.RPMPackageSigningConfig{
		Mode: "fill", Key: "env://SOW_TEST_PACKAGE_CURRENT", TrustedKeys: []string{"env://SOW_TEST_PACKAGE_TRUSTED"},
	}}}
	readSide, err := resolveEffectiveSigningFingerprints(ctx, root, signing, config.EffectiveSigningConfig{})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := loadRPMSigningPolicy(ctx, root, signing.RPM.Packages)
	if err != nil {
		t.Fatal(err)
	}
	buildSide, err := frozenEffectiveSigning(signing, policy, metadataSignerSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(readSide.RPM.Packages, buildSide.RPM.Packages) {
		t.Fatalf("read/build package signing fingerprints differ:\nread=%#v\nbuild=%#v", readSide.RPM.Packages, buildSide.RPM.Packages)
	}
	wantTrusted := []string{currentFingerprint, trustedFingerprint}
	if strings.Compare(wantTrusted[0], wantTrusted[1]) > 0 {
		wantTrusted[0], wantTrusted[1] = wantTrusted[1], wantTrusted[0]
	}
	if !reflect.DeepEqual(readSide.RPM.Packages.TrustedKeyFingerprints, wantTrusted) {
		t.Fatalf("trusted fingerprints=%v want=%v", readSide.RPM.Packages.TrustedKeyFingerprints, wantTrusted)
	}

	dormant := config.SigningConfig{RPM: config.RPMSigningConfig{Packages: config.RPMPackageSigningConfig{
		Mode: "never", Key: "env://SOW_TEST_DORMANT_MISSING", TrustedKeys: []string{"env://SOW_TEST_DORMANT_TRUST_MISSING"},
	}}}
	dormantRead, err := resolveEffectiveSigningFingerprints(ctx, root, dormant, config.EffectiveSigningConfig{})
	if err != nil {
		t.Fatalf("dormant package keys were resolved: %v", err)
	}
	dormantBuild, err := frozenEffectiveSigning(dormant, rpmSigningPolicy{mode: "never"}, metadataSignerSnapshot{})
	if err != nil || !reflect.DeepEqual(dormantRead.RPM.Packages, dormantBuild.RPM.Packages) {
		t.Fatalf("dormant read/build parity: read=%#v build=%#v err=%v", dormantRead.RPM.Packages, dormantBuild.RPM.Packages, err)
	}
}

func TestRPMPackageSigningModeTransitionsSeparateHistoricalIdentityFromCurrentAuthorization(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	keysDir := filepath.Join(root, "keys")
	if err := os.Mkdir(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pgdgPublic, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "PGDG-RPM-GPG-KEY-RHEL-nonfree.asc"))
	if err != nil {
		t.Fatal(err)
	}
	pgdgReference := "file://keys/pgdg.asc"
	if err := os.WriteFile(filepath.Join(keysDir, "pgdg.asc"), pgdgPublic, 0o600); err != nil {
		t.Fatal(err)
	}
	pgdgFingerprints, err := resolveReferenceFingerprints(ctx, root, pgdgReference)
	if err != nil || len(pgdgFingerprints) != 1 {
		t.Fatalf("PGDG key fingerprints=%v err=%v", pgdgFingerprints, err)
	}

	tools := t.TempDir()
	gpg := "#!/bin/sh\nlast=\nfor arg in \"$@\"; do last=\"$arg\"; done\ncase \" $* \" in\n  *\" --list-secret-keys \"*) printf 'sec::::::::::\\nfpr:::::::::%s:\\n' \"$last\"; exit 0;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(tools, "gpg"), []byte(gpg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "rpm"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))

	setPolicy := func(mode, key string) {
		repository := cfg.Repositories["repo"]
		repository.Signing.RPM.Packages = config.RPMPackageSigningConfig{Mode: mode, Key: key}
		cfg.Repositories["repo"] = repository
		writeManagedConfig(t, root, cfg)
	}
	setPolicy("fill", pgdgReference)
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Jobs: 1}); err != nil || !checked.ReadyToCopy {
		t.Fatalf("initial fill check=%#v err=%v", checked, err)
	}

	for _, transition := range []struct{ mode, key string }{{"never", pgdgReference}, {"fill", pgdgReference}, {"always", pgdgReference}} {
		setPolicy(transition.mode, transition.key)
		checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Jobs: 1})
		if !errors.Is(err, ErrNotReady) || errors.Is(err, ErrIntegrity) || checked.Status != "dirty" {
			t.Fatalf("transition to %s check=%#v err=%v", transition.mode, checked, err)
		}
		built, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Jobs: 1})
		if err != nil || built.Noop || built.Dirty {
			t.Fatalf("transition to %s build=%#v err=%v", transition.mode, built, err)
		}
		if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Jobs: 1}); err != nil || !checked.ReadyToCopy {
			t.Fatalf("transition to %s final check=%#v err=%v", transition.mode, checked, err)
		}
	}

	otherPrivate, _ := managedTestPrivateKey(t, "package-rotation-other")
	otherPublic, err := publicOpenPGPKeyMaterial(otherPrivate)
	if err != nil {
		t.Fatal(err)
	}
	otherReference := "file://keys/other.asc"
	if err := os.WriteFile(filepath.Join(keysDir, "other.asc"), otherPublic, 0o600); err != nil {
		t.Fatal(err)
	}
	setPolicy("always", otherReference)
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Jobs: 1})
	if !errors.Is(err, ErrNotReady) || errors.Is(err, ErrIntegrity) || checked.Status != "dirty" {
		t.Fatalf("new-key rotation check=%#v err=%v", checked, err)
	}
	if _, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Jobs: 1}); !errors.Is(err, ErrRejected) {
		t.Fatalf("new-key rotation build error=%v, want ErrRejected", err)
	}
}

func TestFreshDistWithActivePackageSigningIsImmediatelyClean(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	privateKey, fingerprint := managedTestPrivateKey(t, "fresh-clean-package-signing")
	t.Setenv("SOW_TEST_FRESH_PACKAGE_KEY", string(privateKey))
	tools := t.TempDir()
	gpg := "#!/bin/sh\ncase \" $* \" in\n  *\" --list-secret-keys \"*) printf 'sec::::::::::\\nfpr:::::::::" + fingerprint + ":\\n'; exit 0;;\n  *) exit 41;;\nesac\n"
	if err := os.WriteFile(filepath.Join(tools, "gpg"), []byte(gpg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "rpm"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{
		Signing: config.SigningConfig{RPM: config.RPMSigningConfig{Packages: config.RPMPackageSigningConfig{Mode: "fill", Key: "env://SOW_TEST_FRESH_PACKAGE_KEY"}}},
		Dists:   map[string]config.DistConfig{"el9": {Format: "rpm"}},
	}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	options := WorkspaceOptions{Workdir: root, CWD: root}
	dist, err := ShowDist(ctx, DistShowOptions{WorkspaceOptions: options, Repository: "repo", Name: "el9"})
	if err != nil || dist.Dirty || dist.Status != "clean" {
		t.Fatalf("fresh signed-policy Dist=%#v err=%v", dist, err)
	}
	status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
	if err != nil || status.Status != "clean" || !status.ReadyToCopy {
		t.Fatalf("fresh signed-policy status=%#v err=%v", status, err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || !checked.ReadyToCopy || checked.Status != "clean" {
		t.Fatalf("fresh signed-policy check=%#v err=%v", checked, err)
	}
}

func TestEncryptedMetadataKeysUseReferencedPassphraseWithoutPersistence(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	const passphrase = "SOW-encrypted-key-secret-2026"
	key, fingerprint := managedTestEncryptedPrivateKey(t, "encrypted", []byte(passphrase))
	t.Setenv("SOW_TEST_ENCRYPTED_METADATA_KEY", string(key))
	t.Setenv("SOW_TEST_METADATA_PASSPHRASE", passphrase)
	cfg := config.Default()
	metadata := config.MetadataSigningConfig{Key: "env://SOW_TEST_ENCRYPTED_METADATA_KEY", Passphrase: "env://SOW_TEST_METADATA_PASSPHRASE"}
	cfg.Repositories["repo"] = config.RepositoryConfig{
		Signing: config.SigningConfig{RPM: config.RPMSigningConfig{Metadata: metadata}, DEB: config.DEBSigningConfig{Metadata: metadata}},
		Dists:   map[string]config.DistConfig{"el9": {Format: "rpm"}, "noble": {Format: "deb"}},
	}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	view, err := ShowConfig(ctx, ConfigShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, All: true})
	if err != nil {
		t.Fatal(err)
	}
	rpmMetadata := view.Repositories["repo"].Signing.RPM.Metadata
	if rpmMetadata == nil || rpmMetadata.KeyFingerprint != fingerprint || rpmMetadata.Passphrase != "env://SOW_TEST_METADATA_PASSPHRASE" {
		t.Fatalf("effective encrypted signing=%#v", rpmMetadata)
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(passphrase)) || bytes.Contains(encoded, key) || strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("effective config exposed encrypted key bytes or passphrase")
	}
	database, err := os.ReadFile(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(database, []byte(passphrase)) || bytes.Contains(database, key) {
		t.Fatal("SQLite persisted encrypted key bytes or passphrase")
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if err != nil || !checked.ReadyToCopy {
		t.Fatalf("encrypted signed check=%#v err=%v", checked, err)
	}

	const wrong = "SOW-wrong-passphrase-must-not-leak"
	t.Setenv("SOW_TEST_METADATA_PASSPHRASE", wrong)
	checked, err = Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if err != nil || !checked.ReadyToCopy {
		t.Fatalf("delivery check unnecessarily required metadata passphrase: checked=%#v err=%v", checked, err)
	}
	if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); err == nil || strings.Contains(err.Error(), wrong) || strings.Contains(err.Error(), passphrase) {
		t.Fatalf("config check accepted wrong passphrase or leaked a secret: %v", err)
	}
	if _, err := Build(ctx, BuildOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1}); err == nil || strings.Contains(err.Error(), wrong) || strings.Contains(err.Error(), passphrase) {
		t.Fatalf("build accepted wrong passphrase or leaked a secret: %v", err)
	}
}

func managedTestPrivateKey(t *testing.T, name string) ([]byte, string) {
	t.Helper()
	created := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	packetConfig := &packet.Config{
		DefaultHash: crypto.SHA256,
		RSABits:     1024,
		Time:        func() time.Time { return created },
	}
	entity, err := openpgp.NewEntity(name, "SOW managed test", name+"@example.invalid", packetConfig)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	armored, err := armor.Encode(&output, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(armored, packetConfig); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes(), strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint))
}

func managedTestEncryptedPrivateKey(t *testing.T, name string, passphrase []byte) ([]byte, string) {
	t.Helper()
	created := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	packetConfig := &packet.Config{DefaultHash: crypto.SHA256, RSABits: 1024, Time: func() time.Time { return created }}
	entity, err := openpgp.NewEntity(name, "SOW managed encrypted test", name+"@example.invalid", packetConfig)
	if err != nil {
		t.Fatal(err)
	}
	if entity.PrivateKey == nil {
		t.Fatal("test entity has no private key")
	}
	if err := entity.PrivateKey.Encrypt(passphrase); err != nil {
		t.Fatal(err)
	}
	for index := range entity.Subkeys {
		if entity.Subkeys[index].PrivateKey != nil {
			if err := entity.Subkeys[index].PrivateKey.Encrypt(passphrase); err != nil {
				t.Fatal(err)
			}
		}
	}
	var output bytes.Buffer
	armored, err := armor.Encode(&output, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivateWithoutSigning(armored, packetConfig); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes(), strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint))
}
