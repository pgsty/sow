package managed

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	crpm "github.com/cavaliergopher/rpm"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestRemoveCheckDoesNotTouchStageDirectory(t *testing.T) {
	ctx := context.Background()
	root, ws := newRejectionWorkspace(t)
	inputDir := t.TempDir()
	rpm := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(inputDir, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	stageDir := filepath.Join(root, ".sow", "repo", "stage")
	old := time.Unix(1, 0)
	if err := os.Chtimes(stageDir, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Check: true, Jobs: 1}); err != nil {
		t.Fatalf("rm --check failed: %v", err)
	}
	after, err := os.Stat(stageDir)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(old) {
		t.Fatalf("rm --check wrote to stage: mtime=%s", after.ModTime())
	}
}

func TestLocalGCRecoversLegacyV071EmptyManifest(t *testing.T) {
	ctx := context.Background()
	fixture := newLocalGCFixture(t, false)
	opts := LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}
	stop := errors.New("interrupted after detach")
	opts.Fault = func(point string) error {
		if point == "gc.applied" {
			return stop
		}
		return nil
	}
	if _, err := LocalGC(ctx, opts); !errors.Is(err, stop) {
		t.Fatalf("interrupt: %v", err)
	}

	// Recreate the persisted v0.7.1 plan and its matching journal checksum.
	plans, err := filepath.Glob(filepath.Join(fixture.root, ".sow", "repo", "recovery", "*", localGCPlanName))
	if err != nil || len(plans) != 1 {
		t.Fatalf("plans=%v err=%v", plans, err)
	}
	data, err := os.ReadFile(plans[0])
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]json.RawMessage
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	if _, ok := plan["manifest"]; ok {
		t.Fatal("expected compact GC plan")
	}
	plan["manifest"] = json.RawMessage("[]")
	data, err = json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plans[0], data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(fixture.root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := store.DB().ExecContext(ctx, "UPDATE operations SET payload_json=json_set(payload_json, '$.plan_sha256', ?) WHERE kind='local.gc' AND state='applied'", bytesSHA(data))
	if err := errors.Join(err, store.Close()); err != nil {
		t.Fatal(err)
	}
	if count, err := res.RowsAffected(); err != nil || count != 1 {
		t.Fatalf("journal rows=%d err=%v", count, err)
	}

	opts.Fault = nil
	for range 2 {
		res, err := LocalGC(ctx, opts)
		if err != nil || !res.Noop {
			t.Fatalf("replay=%+v err=%v", res, err)
		}
	}
	if _, err := os.Stat(plans[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plan remains: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fixture.root, "repo", fixture.object.PoolPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("payload remains: %v", err)
	}
	result, err := Check(ctx, CheckOptions{WorkspaceOptions: fixture.options, Repository: "repo", Jobs: 1})
	if err != nil || !result.ReadyToCopy {
		t.Fatalf("check=%+v err=%v", result, err)
	}
}

func TestCheckPolicyChangeIsDirtyNotIntegrity(t *testing.T) {
	ctx := context.Background()
	root, ws := newRejectionWorkspace(t)
	inputDir := t.TempDir()
	rpm := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(inputDir, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	repo := cfg.Repositories["repo"]
	dist := repo.Dists["el9"]
	dist.Exclude = []config.ExcludeRule{{Name: []string{"pgdg-redhat-nonfree-repo"}}}
	repo.Dists["el9"] = dist
	cfg.Repositories["repo"] = repo
	writeManagedConfig(t, root, cfg)

	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrNotReady) || errors.Is(err, ErrIntegrity) || checked.Status != "dirty" {
		t.Fatalf("policy change check: status=%q err=%v, want dirty + ErrNotReady (not ErrIntegrity)", checked.Status, err)
	}
	if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
		t.Fatalf("build after policy change failed: %v", err)
	}
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil || checked.Status != "clean" {
		t.Fatalf("check after policy rebuild: status=%q err=%v, want clean", checked.Status, err)
	}
}

func TestAPTByHashAcceptsCopiedNonHardlinkedIndex(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	ws := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"noble": {Format: "deb"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := t.TempDir()
	deb := decodeManagedFixture(t, "../../aptrepo/testdata/libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64", filepath.Join(inputs, "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"noble"}, Paths: []string{deb}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	// Simulate rsync -a / tar restore that breaks hardlinks between Packages and by-hash/.
	packagesPath := filepath.Join(root, "repo", "dists", "noble", "main", "binary-arm64", "Packages")
	data, err := os.ReadFile(packagesPath)
	if err != nil {
		t.Fatal(err)
	}
	tmpCopy := packagesPath + ".copy"
	if err := os.WriteFile(tmpCopy, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmpCopy, packagesPath); err != nil {
		t.Fatal(err)
	}
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil || checked.Status != "clean" {
		t.Fatalf("check after breaking by-hash hardlink: status=%q err=%v", checked.Status, err)
	}
}

func TestAddRecursiveIgnoresUnreadableNonPackageAndFollowsSymlink(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks require a non-root user")
	}
	ctx := context.Background()
	_, ws := newRejectionWorkspace(t)
	realDir := t.TempDir()
	realRPM := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(realDir, "package.rpm"))

	scanDir := t.TempDir()
	secretFile := filepath.Join(scanDir, "secret.key")
	if err := os.WriteFile(secretFile, []byte("private"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secretFile, 0o600) })
	if err := os.Symlink(realRPM, filepath.Join(scanDir, "linked.rpm")); err != nil {
		t.Fatal(err)
	}
	added, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{scanDir}, Recursive: true, Jobs: 1})
	if err != nil || added.Accepted != 1 || added.Failed != 0 {
		t.Fatalf("recursive add with unreadable non-package + symlinked RPM: %+v err=%v", added, err)
	}
}

func TestFilesystemPublicationIgnoresForeignFiles(t *testing.T) {
	ctx := context.Background()
	fixture, _, targetRoot := filesystemPublishFixture(t)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetRoot, "index.html"), []byte("<html>ok</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetRoot, "RPM-GPG-KEY"), []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(targetRoot, "RPM-GPG-KEY"), filepath.Join(targetRoot, "RPM-GPG-KEY.link")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(targetRoot, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if result, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"}); err != nil || !result.Noop {
		t.Fatalf("publish with harmless foreign files/symlinks/dirs failed: %+v err=%v", result, err)
	}
	// Forbidden files inside dists/ must still fail with ErrIntegrity.
	strayDistFile := filepath.Join(targetRoot, "dists", "el9", "stray.rpm")
	if err := os.WriteFile(strayDistFile, []byte("stray"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("forbidden file inside dists/ was not rejected with ErrIntegrity: %v", err)
	}
}

func TestManagedLifecycleWithSowYAML(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	ws := WorkspaceOptions{Workdir: root, CWD: root}
	data, err := config.Marshal(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, config.AltConfigFilename), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatalf("Init with sow.yaml: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, config.ConfigFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Init created duplicate sow.yml beside sow.yaml: err=%v", err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: ws, Name: "repo"}); err != nil {
		t.Fatalf("NewRepository with sow.yaml: %v", err)
	}
	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: ws, Repository: "repo", Name: "el9", Format: "rpm"}); err != nil {
		t.Fatalf("NewDist with sow.yaml: %v", err)
	}
	inputDir := t.TempDir()
	rpm := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(inputDir, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatalf("Add with sow.yaml: %v", err)
	}
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil || checked.Status != "clean" {
		t.Fatalf("Check with sow.yaml: status=%q err=%v", checked.Status, err)
	}
	if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1}); err != nil {
		t.Fatalf("Remove with sow.yaml: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, config.ConfigFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed operations created stray sow.yml beside sow.yaml: err=%v", err)
	}
}

func TestManagedFillDualSignedRPMv6PassesCheckAndDetectsTampering(t *testing.T) {
	ctx := context.Background()
	raw := decodeManagedFixtureBytes(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	parsed, err := crpm.Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mainStart, mainEnd := parsed.HeaderRange()
	mainHeader := raw[mainStart:mainEnd]

	created := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	makeKey := func(name string) (*openpgp.Entity, []byte, string) {
		cfg := &packet.Config{Algorithm: packet.PubKeyAlgoRSA, RSABits: 2048, Time: func() time.Time { return created }}
		entity, err := openpgp.NewEntity(name, "", name+"@example.invalid", cfg)
		if err != nil {
			t.Fatal(err)
		}
		var pub bytes.Buffer
		w, err := armor.Encode(&pub, openpgp.PublicKeyType, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := entity.Serialize(w); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return entity, pub.Bytes(), strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint))
	}
	keyA, pubA, fpA := makeKey("dual-signer-a")
	keyB, pubB, fpB := makeKey("dual-signer-b")
	_, pubC, fpC := makeKey("dual-signer-c")

	signCfg := &packet.Config{Time: func() time.Time { return created.Add(time.Minute) }}
	var sigA, sigB bytes.Buffer
	if err := openpgp.DetachSign(&sigA, keyA, bytes.NewReader(mainHeader), signCfg); err != nil {
		t.Fatal(err)
	}
	if err := openpgp.DetachSign(&sigB, keyB, bytes.NewReader(mainHeader), signCfg); err != nil {
		t.Fatal(err)
	}

	// Build an RPM signature header carrying RPMSIGTAG_OPENPGP (tag 278) with both signatures.
	storeData := append([]byte(base64.StdEncoding.EncodeToString(sigA.Bytes())), 0)
	storeData = append(storeData, []byte(base64.StdEncoding.EncodeToString(sigB.Bytes()))...)
	storeData = append(storeData, 0)
	var sigHeader bytes.Buffer
	sigHeader.Write([]byte{0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00})
	_ = binary.Write(&sigHeader, binary.BigEndian, uint32(1))
	_ = binary.Write(&sigHeader, binary.BigEndian, uint32(len(storeData)))
	_ = binary.Write(&sigHeader, binary.BigEndian, uint32(278))
	_ = binary.Write(&sigHeader, binary.BigEndian, uint32(crpm.TagTypeStringArray))
	_ = binary.Write(&sigHeader, binary.BigEndian, uint32(0))
	_ = binary.Write(&sigHeader, binary.BigEndian, uint32(2))
	sigHeader.Write(storeData)
	if pad := (8 - (len(storeData) % 8)) % 8; pad != 0 {
		sigHeader.Write(make([]byte, pad))
	}

	dualBytes := make([]byte, 0, 96+sigHeader.Len()+len(raw)-int(mainStart))
	dualBytes = append(dualBytes, raw[:96]...)
	dualBytes = append(dualBytes, sigHeader.Bytes()...)
	dualBytes = append(dualBytes, raw[mainStart:]...)
	dualSHA := bytesSHA(dualBytes)

	inputDir := t.TempDir()
	dualPath := filepath.Join(inputDir, "dual-v6.rpm")
	if err := os.WriteFile(dualPath, dualBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	tools := t.TempDir()
	if err := os.WriteFile(filepath.Join(tools, "gpg"), []byte("#!/bin/sh\nlast=\nfor arg in \"$@\"; do last=\"$arg\"; done\ncase \" $* \" in\n *\" --list-secret-keys \"*) printf 'sec::::::::::\\nfpr:::::::::%s:\\n' \"$last\";;\nesac\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))

	t.Setenv("SOW_TEST_DUAL_KEY_A", string(pubA))
	t.Setenv("SOW_TEST_DUAL_KEY_B", string(pubB))
	root := t.TempDir()
	ws := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{
		Signing: config.SigningConfig{
			RPM: config.RPMSigningConfig{
				Packages: config.RPMPackageSigningConfig{
					Mode:        "fill",
					Key:         "env://SOW_TEST_DUAL_KEY_A",
					TrustedKeys: []string{"env://SOW_TEST_DUAL_KEY_B"},
				},
			},
		},
		Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}},
	}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}

	added, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{dualPath}, Jobs: 1})
	if err != nil || added.Accepted != 1 || len(added.Items) != 1 || added.Items[0].SHA256 != dualSHA {
		t.Fatalf("add dual-signed RPM: added=%+v err=%v", added, err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1})
	if err != nil || checked.Status != "clean" || !checked.ReadyToCopy {
		t.Fatalf("check dual-signed RPM: checked=%+v err=%v", checked, err)
	}

	// Dropping Key B from live trusted_keys makes the Dist dirty (policy drift),
	// while the frozen Built Generation remains valid under its retained fill set.
	repoCfg := cfg.Repositories["repo"]
	repoCfg.Signing.RPM.Packages.TrustedKeys = nil
	cfg.Repositories["repo"] = repoCfg
	writeManagedConfig(t, root, cfg)
	checked, err = Check(ctx, CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrNotReady) || errors.Is(err, ErrIntegrity) || checked.Status != "dirty" {
		t.Fatalf("check after rotating off Key B: status=%q err=%v, want dirty + ErrNotReady", checked.Status, err)
	}

	// Restore live config and verify tampering signature_key to an unrelated retained key C fails closed.
	repoCfg.Signing.RPM.Packages.TrustedKeys = []string{"env://SOW_TEST_DUAL_KEY_B"}
	cfg.Repositories["repo"] = repoCfg
	writeManagedConfig(t, root, cfg)

	dbPath := filepath.Join(root, ".sow", "repo.db")
	store, err := state.OpenExisting(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO rpm_signing_keys(fingerprint, public_key) VALUES (?, ?)`, fpC, pubC); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE package_objects SET signature_key = ? WHERE sha256 = ?`, fpC, dualSHA); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); !errors.Is(err, ErrIntegrity) || checked.Status != "error" {
		t.Fatalf("check accepted tampered signature_key %s: status=%q err=%v", fpC, checked.Status, err)
	}

	// Restore signature_key to Key A, then delete Key B from rpm_signing_keys;
	// check must reject the missing co-signer certificate.
	store, err = state.OpenExisting(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE package_objects SET signature_key = ? WHERE sha256 = ?`, fpA, dualSHA); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `DELETE FROM rpm_signing_keys WHERE fingerprint = ?`, fpB); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); !errors.Is(err, ErrIntegrity) || checked.Status != "error" {
		t.Fatalf("check accepted missing retained co-signer %s: status=%q err=%v", fpB, checked.Status, err)
	}
}

func decodeManagedFixtureBytes(t *testing.T, path string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(encoded)), ""))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
