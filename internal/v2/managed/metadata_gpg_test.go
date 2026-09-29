package managed

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestWaitForFrozenGPGTimeLeavesOnlyTheCurrentSecond(t *testing.T) {
	start := time.Now()
	if err := waitForFrozenGPGTime(context.Background(), start.Add(-2*time.Second)); err != nil || time.Since(start) > 200*time.Millisecond {
		t.Fatalf("a past Generation time waited %v: %v", time.Since(start), err)
	}
	at := time.Now()
	if err := waitForFrozenGPGTime(context.Background(), at); err != nil || time.Now().Unix() <= at.Unix() {
		t.Fatalf("signing would start in the faked second: now=%d at=%d err=%v", time.Now().Unix(), at.Unix(), err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForFrozenGPGTime(cancelled, time.Now().Add(time.Second)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled wait=%v", err)
	}
}

// This is a real agent keyring, with two public signing subkeys but only the
// older one's secret key on this machine. Public-only selection prefers the
// newer key; GPG must be allowed to select the usable local key.
func TestGPGMetadataUsesActualAvailableSubkeyAndFrozenClock(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg is unavailable")
	}
	home, err := os.MkdirTemp("", "sow-gpg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if gpgconf, err := exec.LookPath("gpgconf"); err == nil {
			_ = exec.Command(gpgconf, "--homedir", home, "--kill", "gpg-agent").Run()
		}
		_ = os.RemoveAll(home)
	})
	t.Setenv("GNUPGHOME", home)
	// A user preference must not change the generated metadata digest.
	if err := os.WriteFile(filepath.Join(home, "gpg.conf"), []byte("digest-algo SHA1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	created := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	at := created.Add(2 * time.Hour)
	sourceHome := filepath.Join(home, "source")
	if err := os.Mkdir(sourceHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if gpgconf, err := exec.LookPath("gpgconf"); err == nil {
			_ = exec.Command(gpgconf, "--homedir", sourceHome, "--kill", "gpg-agent").Run()
		}
	})
	run := func(at time.Time, args ...string) []byte {
		t.Helper()
		options := []string{"--homedir", sourceHome, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", "", "--faked-system-time", strconv.FormatInt(at.Unix(), 10) + "!"}
		command := exec.Command(gpg, append(options, args...)...)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		output, err := command.Output()
		if err != nil {
			t.Fatalf("isolated GPG fixture: %v: %s", err, stderr.Bytes())
		}
		return output
	}
	parsePublic := func(material []byte) *openpgp.Entity {
		t.Helper()
		entities, err := yumrepo.ParsePublicKeyring(material)
		if err != nil || len(entities) != 1 {
			t.Fatalf("fixture public key: %v", err)
		}
		return entities[0]
	}
	run(created, "--quick-generate-key", "SOW agent <agent@example.invalid>", "ed25519", "cert", "0")
	entity := parsePublic(run(created, "--export", "agent@example.invalid"))
	fingerprint := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
	run(created, "--quick-add-key", fingerprint, "ed25519", "sign", "0")
	entity = parsePublic(run(created, "--export", fingerprint))
	want := fmt.Sprintf("%X", entity.Subkeys[len(entity.Subkeys)-1].PublicKey.Fingerprint)
	run(created.Add(time.Hour), "--quick-add-key", fingerprint, "ed25519", "sign", "0")
	public := run(at, "--export", fingerprint)
	entity = parsePublic(public)
	newer, usable := entity.SigningKey(at)
	if !usable || fmt.Sprintf("%X", newer.PublicKey.Fingerprint) == want {
		t.Fatal("fixture must select the newer public-only key in Go")
	}
	secret := run(at, "--export-secret-subkeys", want+"!")
	command := exec.Command(gpg, "--batch", "--no-tty", "--import")
	command.Stdin = bytes.NewReader(secret)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("import isolated local subkey: %v: %s", err, output)
	}
	ctx := withMetadataSignerCache(context.Background())
	repo := config.RepositoryConfig{Signing: config.SigningConfig{
		RPM: config.RPMSigningConfig{Metadata: config.MetadataSigningConfig{Key: "agent://" + fingerprint}},
		DEB: config.DEBSigningConfig{Metadata: config.MetadataSigningConfig{Key: "agent://" + fingerprint}},
	}}
	snapshot, err := loadMetadataSignerSnapshotForFormats(ctx, t.TempDir(), repo, at, true, true)
	if err != nil {
		command := exec.Command(gpg, "--batch", "--no-tty", "--pinentry-mode", "error", "--digest-algo", "SHA256", "--faked-system-time", strconv.FormatInt(at.Unix(), 10)+"!", "--local-user", fingerprint, "--armor", "--detach-sign", "--output", "-")
		command.Stdin = bytes.NewReader([]byte("probe\n"))
		output, _ := command.CombinedOutput()
		t.Fatalf("%v: %s", err, output)
	}
	if snapshot.RPM.SelectedFingerprint != want || snapshot.DEB.SelectedFingerprint != want {
		t.Fatalf("actual key RPM=%s DEB=%s want %s", snapshot.RPM.SelectedFingerprint, snapshot.DEB.SelectedFingerprint, want)
	}
	rpmCore := snapshot.RPMSigner.(*gpgYUMMetadataSigner).gpgSignerCore
	aptCore := snapshot.APTSigner.(*gpgAPTMetadataSigner).gpgSignerCore
	if rpmCore != aptCore {
		t.Fatal("shared certificate/time was probed separately for RPM and APT")
	}
	if reused, _, err := newGPGSignerCoreWithPublic(ctx, fingerprint, at); err != nil || reused != aptCore {
		t.Fatalf("operation signer cache was not reused: %v", err)
	}
	if err := validateNewMetadataSigningKeys(snapshot, at, time.Now()); err != nil {
		t.Fatalf("valid local key was rejected: %v", err)
	}
	release := []byte("Origin: SOW\nSuite: test\nDate: " + at.Format(time.RFC1123) + "\n")
	reader, writer := io.Pipe()
	written := make(chan error, 1)
	go func() {
		// GPG starts before input arrives: without T!, the signature is later
		// than Release.Date and SOW's own historical verifier rejects it.
		time.Sleep(1200 * time.Millisecond)
		_, err := writer.Write(release)
		_ = writer.Close()
		written <- err
	}()
	var inRelease, detached bytes.Buffer
	signErr := snapshot.APTSigner.ClearSign(ctx, &inRelease, reader, at)
	_ = reader.Close()
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if signErr != nil {
		t.Fatal(signErr)
	}
	if err := snapshot.APTSigner.DetachedSign(ctx, &detached, bytes.NewReader(release), at); err != nil {
		t.Fatal(err)
	}
	verifier, err := aptrepo.NewVerifierBytes(snapshot.DEB.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyForPublication(release, inRelease.Bytes(), detached.Bytes(), at); err != nil {
		t.Fatalf("real delayed GPG output rejected at its Release time: %v", err)
	}
	// Historical SHA-1 metadata is still authentic, but cannot start a new
	// publication. Use GPG because go-crypto deliberately cannot emit SHA-1.
	var weak [2][]byte
	for i, operation := range []string{"--clearsign", "--detach-sign"} {
		command := exec.Command(gpg, "--batch", "--no-tty", "--pinentry-mode", "error", "--armor", "--digest-algo", "SHA1", "--faked-system-time", strconv.FormatInt(at.Unix(), 10)+"!", "--local-user", want+"!", "--output", "-", operation)
		command.Stdin = bytes.NewReader(release)
		weak[i], err = command.Output()
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := verifier.Verify(release, weak[0], weak[1], at); err != nil {
		t.Fatalf("historical SHA-1 metadata rejected: %v", err)
	}
	for _, pair := range [][2][]byte{{weak[0], detached.Bytes()}, {inRelease.Bytes(), weak[1]}, {weak[0], weak[1]}} {
		if err := verifier.VerifyForPublication(release, pair[0], pair[1], at); err == nil {
			t.Fatal("new publication accepted a SHA-1 signature")
		}
	}
	armored, err := armor.Decode(bytes.NewReader(detached.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	signature, _, err := openpgp.VerifyDetachedSignature(openpgp.EntityList{entity}, bytes.NewReader(release), armored.Body, &packet.Config{Time: func() time.Time { return at }})
	if err != nil || signature.Hash != crypto.SHA256 || !signature.CreationTime.Equal(at) || !bytes.Equal(signature.IssuerFingerprint, rpmCoreKeyFingerprint(entity, want)) {
		t.Fatalf("wrong signature digest/time/key: %#v err=%v", signature, err)
	}
	var repeated bytes.Buffer
	if err := snapshot.APTSigner.DetachedSign(ctx, &repeated, bytes.NewReader(release), at); err != nil || !bytes.Equal(repeated.Bytes(), detached.Bytes()) {
		t.Fatalf("same-time GPG signature changed: %v", err)
	}
}

func rpmCoreKeyFingerprint(entity *openpgp.Entity, want string) []byte {
	for _, subkey := range entity.Subkeys {
		if fmt.Sprintf("%X", subkey.PublicKey.Fingerprint) == want {
			return subkey.PublicKey.Fingerprint
		}
	}
	return nil
}
