package managed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/plain"
	"github.com/pgsty/sow/internal/v2/signing"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestPassfileRejectedFromRetainedSigningIdentity(t *testing.T) {
	for _, format := range []string{"rpm", "deb"} {
		metadata := config.EffectiveMetadataSigningConfig{Key: "keys/repo.asc", KeyFingerprint: strings.Repeat("A", 40)}
		frozen := config.EffectiveSigningConfig{RPM: config.EffectiveRPMSigningConfig{Packages: config.EffectiveRPMPackageSigningConfig{Mode: "never"}}}
		var passfile *string
		if format == "rpm" {
			frozen.RPM.Metadata = &metadata
			passfile = &frozen.RPM.Metadata.PassFile
		} else {
			frozen.DEB = &config.EffectiveDEBSigningConfig{Metadata: metadata}
			passfile = &frozen.DEB.Metadata.PassFile
		}
		encoded, _ := json.Marshal(frozen)
		if _, err := decodeRetainedEffectiveSigning(string(encoded)); err != nil {
			t.Fatal(err)
		}
		*passfile = "/run/secrets/password"
		encoded, _ = json.Marshal(frozen)
		if _, err := decodeRetainedEffectiveSigning(string(encoded)); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s snapshot accepted runtime credential source: %v", format, err)
		}
	}
}

func TestPassfileDoesNotAffectRPMPublicVerification(t *testing.T) {
	key, _ := managedTestPrivateKey(t, "verification-without-password")
	t.Setenv("SOW_TEST_VERIFY_KEY", string(key))
	t.Setenv(signing.Environment, "")
	ctx := context.Background()
	policy, err := loadRPMSigningPolicy(ctx, t.TempDir(), config.RPMPackageSigningConfig{Mode: "fill", Key: "env://SOW_TEST_VERIFY_KEY"})
	if err != nil || policy.current == nil {
		t.Fatalf("verification resolved an unused password source: %v", err)
	}
	input := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(t.TempDir(), "package.rpm"))
	if _, err := policy.prepare(ctx, input, "package.rpm", state.PackageObject{}); err == nil {
		t.Fatal("actual signing ignored the invalid password source")
	}
}

func TestPassfileInProcessLifecycleAndPublishRecovery(t *testing.T) {
	ctx := context.Background()
	root, secrets := t.TempDir(), t.TempDir()
	ws := WorkspaceOptions{Workdir: root, CWD: root}
	const password = "  SOW-private-passfile-秘密  "
	key, _ := managedTestEncryptedPrivateKey(t, "passfile", []byte(password))
	t.Setenv("SOW_TEST_PASSFILE_KEY", string(key))
	passfile := filepath.Join(secrets, "password")
	if err := os.WriteFile(passfile, []byte(password+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(signing.Environment, passfile)
	cfg := config.Default()
	cfg.Architectures = []string{"x86_64"}
	metadata := config.MetadataSigningConfig{Key: "env://SOW_TEST_PASSFILE_KEY"}
	cfg.Repositories["repo"] = config.RepositoryConfig{
		Signing: config.SigningConfig{RPM: config.RPMSigningConfig{Metadata: metadata}, DEB: config.DEBSigningConfig{Metadata: metadata}},
		Dists:   map[string]config.DistConfig{"el9": {Format: "rpm"}, "noble": {Format: "deb"}},
	}
	targetRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.FileServer(http.Dir(targetRoot)))
	t.Cleanup(server.Close)
	cfg.Targets["local"] = config.TargetConfig{Repository: "repo", Provider: "filesystem", Endpoint: (&url.URL{Scheme: "file", Path: targetRoot}).String(), Prefix: "mirror/repo", PublicEndpoint: server.URL + "/mirror/repo/", MaxCacheTTL: "0s", AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckConfig(ctx, ws); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: ws, Name: "empty"}); err != nil {
		t.Fatal(err)
	}
	if err := RemoveRepository(ctx, RepositoryRemoveOptions{WorkspaceOptions: ws, Name: "empty"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: ws, Repository: "repo", Name: "extra", Format: "deb"}); err != nil {
		t.Fatal(err)
	}
	if err := RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: ws, Repository: "repo", Name: "extra"}); err != nil {
		t.Fatal(err)
	}
	input := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(t.TempDir(), "package.rpm"))
	stop := errors.New("passfile interrupted before rendering")
	_, err = Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1, Fault: func(point string) error {
		if point == "add.applied" {
			return stop
		}
		return nil
	}})
	if !errors.Is(err, stop) {
		t.Fatalf("did not interrupt build: %v", err)
	}
	// No credentials are journaled. Recovery obtains a new CLI override, which
	// must beat a now-invalid environment default inside Publish's recovery.
	t.Setenv(signing.Environment, filepath.Join(secrets, "missing"))
	ctx = signing.WithPassFile(ctx, passfile)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: ws, Target: "local"}); err != nil {
		t.Fatalf("publish recovery lost password override: %v", err)
	}
	if checked, err := Check(context.Background(), CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil || !checked.ReadyToCopy {
		t.Fatalf("verification required a password or rejected recovery: %v", err)
	}
	if _, err := ShowConfig(context.Background(), ConfigShowOptions{WorkspaceOptions: ws, All: true}); err != nil {
		t.Fatalf("config show read password: %v", err)
	}
	if _, err := ExportRPMLeaf(ctx, RPMLeafExportOptions{WorkspaceOptions: ws, Repository: "repo", Dist: "el9", Arch: "x86_64", Directory: filepath.Join(t.TempDir(), "leaf")}); err != nil {
		t.Fatalf("signed export: %v", err)
	}
	// Use the configured path, then move only that path. Credential rotation
	// must not change the rendered identity or make the Dist dirty.
	cfg, err = config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	repo := cfg.Repositories["repo"]
	repo.Signing.RPM.Metadata.PassFile, repo.Signing.DEB.Metadata.PassFile = passfile, passfile
	cfg.Repositories["repo"] = repo
	writeManagedConfig(t, root, cfg)
	if _, err := CheckConfig(context.Background(), ws); err != nil {
		t.Fatalf("per-key source did not beat env: %v", err)
	}
	if status, err := Status(context.Background(), StatusOptions{WorkspaceOptions: ws, Repository: "repo"}); err != nil || status.Status != "clean" {
		t.Fatalf("passfile changed rendered identity: %#v %v", status, err)
	}
	view, err := ShowConfig(context.Background(), ConfigShowOptions{WorkspaceOptions: ws, All: true})
	if err != nil || view.Repositories["repo"].Signing.RPM.Metadata.PassFile != passfile {
		t.Fatalf("config did not expose path: %v", err)
	}
	encoded, _ := json.Marshal(view)
	if bytes.Contains(encoded, []byte(password)) {
		t.Fatal("config show exposed password")
	}
	remove := RemoveOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1, Check: true}
	if _, err := Remove(context.Background(), remove); err != nil {
		t.Fatalf("signed removal preview: %v", err)
	}
	remove.Check = false
	if _, err := Remove(context.Background(), remove); err != nil {
		t.Fatalf("signed removal: %v", err)
	}
	if _, err := Build(context.Background(), BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
		t.Fatalf("signed build: %v", err)
	}
	for _, maintenance := range []struct {
		name string
		run  func() error
	}{
		{"gc", func() error {
			_, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: ws, Repository: "repo"})
			return err
		}},
		{"gc target", func() error {
			_, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: ws, Target: "local"})
			return err
		}},
		{"log prune", func() error {
			_, err := PruneLog(ctx, LogPruneOptions{WorkspaceOptions: ws, Repository: "repo", Before: time.Now().Add(-time.Hour)})
			return err
		}},
	} {
		// A committed membership update still needs metadata signatures when
		// the next maintenance command recovers it.
		_, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1, Fault: func(point string) error {
			if point == "add.applied" {
				return stop
			}
			return nil
		}})
		if !errors.Is(err, stop) {
			t.Fatalf("%s recovery fixture: %v", maintenance.name, err)
		}
		if err := maintenance.run(); err != nil {
			t.Fatalf("%s lost signing credentials during recovery: %v", maintenance.name, err)
		}
		if _, err := Remove(ctx, remove); err != nil {
			t.Fatal(err)
		}
	}
	// Password values must never enter journals, SQLite, or public artifacts.
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if bytes.Contains(data, []byte(password)) {
				t.Errorf("password persisted at %s", path)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPassfileProtectedGPGAndRPMSigning(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg unavailable")
	}
	gpgHome, err := os.MkdirTemp("/tmp", "sow-passfile-gpg-")
	if err != nil {
		t.Fatal(err)
	}
	killAgent := func() {
		if gpgconf, err := exec.LookPath("gpgconf"); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = exec.CommandContext(ctx, gpgconf, "--homedir", gpgHome, "--kill", "gpg-agent").Run()
		}
	}
	t.Cleanup(func() { killAgent(); _ = os.RemoveAll(gpgHome) })
	t.Setenv("GNUPGHOME", gpgHome)
	const password = "  SOW-GPG-passfile-secret  "
	passfile := filepath.Join(gpgHome, "password")
	if err := os.WriteFile(passfile, []byte(password+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pinentry := filepath.Join(gpgHome, "pinentry")
	if err := os.WriteFile(pinentry, []byte("#!/bin/sh\n: > \"$GNUPGHOME/pinentry-called\"\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gpgHome, "gpg-agent.conf"), []byte("pinentry-program "+pinentry+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	created := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	generate := exec.Command(gpg, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase-fd", "0", "--faked-system-time", strconv.FormatInt(created.Unix(), 10)+"!", "--quick-generate-key", "SOW passfile test <passfile@example.invalid>", "rsa2048", "sign", "0")
	generate.Stdin = strings.NewReader(password + "\n")
	if output, err := generate.CombinedOutput(); err != nil {
		t.Fatalf("generate isolated encrypted key: %v: %s", err, output)
	}
	listing, err := exec.Command(gpg, "--batch", "--with-colons", "--list-secret-keys").Output()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := ""
	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 9 && fields[0] == "fpr" {
			fingerprint = fields[9]
			break
		}
	}
	if fingerprint == "" {
		t.Fatal("fixture has no fingerprint")
	}
	t.Setenv(signing.Environment, passfile)
	metadata := config.MetadataSigningConfig{Key: "agent://" + fingerprint}
	repo := config.RepositoryConfig{Signing: config.SigningConfig{RPM: config.RPMSigningConfig{Metadata: metadata}, DEB: config.DEBSigningConfig{Metadata: metadata}}}
	at := created.Add(time.Hour)
	killAgent()
	snapshot, err := loadMetadataSignerSnapshotForFormats(context.Background(), t.TempDir(), repo, at, true, true)
	if err != nil {
		t.Fatalf("protected GPG probe: %v", err)
	}
	message := []byte("Origin: SOW\nSuite: passfile\n")
	var clear, detached, rpmSignature bytes.Buffer
	if err := snapshot.APTSigner.ClearSign(context.Background(), &clear, bytes.NewReader(message), at); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.APTSigner.DetachedSign(context.Background(), &detached, bytes.NewReader(message), at); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.APTSigner.Verify(context.Background(), message, clear.Bytes(), detached.Bytes(), at); err != nil {
		t.Fatalf("protected APT verification: %v", err)
	}
	if err := snapshot.RPMSigner.Sign(context.Background(), bytes.NewReader(message), &rpmSignature); err != nil {
		t.Fatal(err)
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(snapshot.RPM.PublicKey), at)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), bytes.NewReader(message), &rpmSignature); err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(gpgHome, "wrong")
	if err := os.WriteFile(wrong, []byte("wrong-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	killAgent()
	if _, err := loadMetadataSignerSnapshotForFormats(signing.WithPassFile(context.Background(), wrong), t.TempDir(), repo, at, true, false); err == nil || strings.Contains(err.Error(), "wrong-password") {
		t.Fatalf("wrong GPG password accepted or exposed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(gpgHome, "pinentry-called")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("GPG prompted instead of using the passfile")
	}
	t.Run("RPM", func(t *testing.T) {
		rpm, err := exec.LookPath("rpm")
		if err != nil {
			t.Skip("rpm unavailable")
		}
		// Host RPM macros may pin a different homedir. Override only that
		// location in this test, leaving SOW responsible for the passfile args.
		bin := t.TempDir()
		t.Setenv("SOW_TEST_RPM", rpm)
		rpmLog := filepath.Join(bin, "rpm.log")
		t.Setenv("SOW_TEST_RPM_LOG", rpmLog)
		wrapper := "#!/bin/sh\nif [ \"$SOW_TEST_RPM_V3\" = 1 ]; then set -- --rpmv3 \"$@\"; fi\nexec \"$SOW_TEST_RPM\" --define \"_gpg_path $GNUPGHOME\" \"$@\" > \"$SOW_TEST_RPM_LOG\" 2>&1\n"
		if err := os.WriteFile(filepath.Join(bin, "rpm"), []byte(wrapper), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		keyring, err := yumrepo.ParseRPMPackageKeyring(snapshot.RPM.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		verify := func(path string, signatures int) {
			t.Helper()
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if verified, err := yumrepo.VerifyEmbeddedRPMSignatures(context.Background(), file, keyring, time.Now()); err != nil || len(verified) < signatures {
				t.Fatalf("RPM did not get the configured signature: %v", err)
			}
		}
		for _, mode := range []string{"plain", "managed", "repeated"} {
			minimumSignatures := 1
			if mode == "repeated" {
				// rpmsign can request both header-only and header+payload
				// signatures; rpm's compatibility command lacks --rpmv3.
				rpmsign, err := exec.LookPath("rpmsign")
				if err != nil {
					t.Log("rpmsign unavailable; repeated invocation covered by password-file unit test")
					continue
				}
				t.Setenv("SOW_TEST_RPM", rpmsign)
				t.Setenv("SOW_TEST_RPM_V3", "1")
				minimumSignatures = 2
			}
			path := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(t.TempDir(), "package.rpm"))
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			killAgent()
			if mode == "managed" {
				policy, err := loadRPMSigningPolicy(context.Background(), "", config.RPMPackageSigningConfig{Mode: "always", Key: "agent://" + fingerprint, PassFile: passfile})
				if err != nil {
					t.Fatal(err)
				}
				credential, err := policy.credential(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				err = signManagedRPM(context.Background(), path, fingerprint, true, credential)
				if err != nil {
					output, _ := os.ReadFile(rpmLog)
					t.Fatalf("managed encrypted RPM signing: %v: %s", err, output)
				}
			} else {
				_, err := plain.Create(context.Background(), plain.Options{Dir: filepath.Dir(path), SignWith: fingerprint, PassFile: passfile, Overwrite: true, Jobs: 1})
				if err != nil {
					output, _ := os.ReadFile(rpmLog)
					t.Fatalf("plain encrypted RPM signing: %v: %s", err, output)
				}
			}
			verify(path, minimumSignatures)
			if mode == "managed" {
				root := t.TempDir()
				cfg := config.Default()
				cfg.Repositories["repo"] = config.RepositoryConfig{
					Signing: config.SigningConfig{RPM: config.RPMSigningConfig{Packages: config.RPMPackageSigningConfig{Mode: "always", Key: "agent://" + fingerprint}}},
					Dists:   map[string]config.DistConfig{"el9": {Format: "rpm", Architectures: []string{"x86_64"}}},
				}
				writeManagedConfig(t, root, cfg)
				ctx := signing.WithPassFile(context.Background(), passfile)
				if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
					t.Fatal(err)
				}
				ws := WorkspaceOptions{Workdir: root, CWD: root}
				if _, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{path}, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
				t.Setenv(signing.Environment, "")
				if result, err := Check(context.Background(), CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil || !result.ReadyToCopy {
					t.Fatalf("public RPM verification required a password: %+v %v", result, err)
				}
				t.Setenv(signing.Environment, passfile)
			}
		}
	})
}
