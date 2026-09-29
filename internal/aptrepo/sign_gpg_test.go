package aptrepo

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func TestVerifyGnuPGClearSignatureFinalNewline(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg unavailable")
	}
	home, err := os.MkdirTemp("", "sow-gpg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	run := func(input []byte, args ...string) []byte {
		t.Helper()
		args = append([]string{"--homedir", home, "--batch", "--no-tty"}, args...)
		cmd := exec.Command(gpg, args...)
		cmd.Stdin = bytes.NewReader(input)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("gpg: %v: %s", err, stderr.String())
		}
		return out
	}
	t.Cleanup(func() {
		if conf, e := exec.LookPath("gpgconf"); e == nil {
			_ = exec.Command(conf, "--homedir", home, "--kill", "gpg-agent").Run()
		}
	})
	run(nil, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", "SOW APT regression <sow-aptrepo@example.invalid>", "rsa2048", "sign", "0")
	private := run(nil, "--armor", "--export-secret-keys", "sow-aptrepo@example.invalid")
	signer, err := NewSignerBytes(private, nil)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(time.Minute).Truncate(time.Second)
	message := []byte("Origin: SOW\nSuite: stable\n")
	inRelease := run(message, "--armor", "--digest-algo", "SHA256", "--faked-system-time", strconv.FormatInt(at.Unix(), 10), "--clearsign")
	var detached bytes.Buffer
	if err := signer.DetachedSign(&detached, bytes.NewReader(message), at); err != nil {
		t.Fatal(err)
	}
	if err := signer.Verify(message, inRelease, detached.Bytes(), at); err != nil {
		t.Fatalf("valid GPG InRelease rejected: %v", err)
	}
	for _, altered := range [][]byte{[]byte("Origin: changed\nSuite: stable\n"), append(append([]byte{}, message...), '\n'), append(append([]byte{}, message...), ' ')} {
		var signature bytes.Buffer
		if err := signer.DetachedSign(&signature, bytes.NewReader(altered), at); err != nil {
			t.Fatal(err)
		}
		if err := signer.Verify(altered, inRelease, signature.Bytes(), at); err == nil {
			t.Fatalf("unbound Release accepted: %q", altered)
		}
	}
	if err := signer.Verify(message, append(append([]byte{}, inRelease...), []byte("garbage")...), detached.Bytes(), at); err == nil {
		t.Fatal("trailing garbage accepted")
	}
}
