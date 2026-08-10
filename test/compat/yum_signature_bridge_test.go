package compat_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/pgsty/sow/internal/yumrepo"
)

// TestYUMDetachedSignatureBridgeCompatibility is an opt-in protocol probe for
// the only plausible way to keep a legacy raw baseurl verifiable while its two
// mutable files are replaced serially. The bridge file concatenates detached
// signatures for the old and new repomd.xml. Every result comes from a real
// dnf client; accepting the bridge in a Go OpenPGP parser would not prove the
// client-observable publication contract.
func TestYUMDetachedSignatureBridgeCompatibility(t *testing.T) {
	if os.Getenv("SOW_RUN_DOCKER_COMPAT") != "1" {
		t.Skip("set SOW_RUN_DOCKER_COMPAT=1 to run the real dnf signature-bridge probe")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	moduleRoot := findModuleRoot(t)
	work := t.TempDir()
	privateKey, publicKey := writeSigningKey(t, work)
	rpmPath := decodeBase64Fixture(t,
		filepath.Join(moduleRoot, "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"),
		filepath.Join(work, "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm"),
	)
	base := filepath.Join(work, "base")
	packagePath := filepath.Join(base, "Packages", "p", filepath.Base(rpmPath))
	linkOrCopy(t, rpmPath, packagePath)
	keyReader, err := os.Open(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	signingTime := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	signer, signerErr := yumrepo.NewOpenPGPSigner(keyReader, nil, signingTime)
	closeErr := keyReader.Close()
	if signerErr != nil || closeErr != nil {
		t.Fatal(errors.Join(signerErr, closeErr))
	}
	if _, err := yumrepo.Generate(ctx, filepath.Join(base, "repodata"), yumrepo.Options{
		ELMajor: 8, Revision: signingTime.Unix(), Signer: signer,
	}, &yumrepo.SliceIterator{Inputs: []yumrepo.PackageInput{{Path: packagePath, FileTime: signingTime}}}); err != nil {
		t.Fatal(err)
	}

	oldXML := mustRead(t, filepath.Join(base, "repodata", "repomd.xml"))
	oldASC := mustRead(t, filepath.Join(base, "repodata", "repomd.xml.asc"))
	oldRevision := fmt.Sprintf("<revision>%d</revision>", signingTime.Unix())
	newRevision := fmt.Sprintf("<revision>%d</revision>", signingTime.Unix()+1)
	newXML := bytes.Replace(oldXML, []byte(oldRevision), []byte(newRevision), 1)
	if bytes.Equal(oldXML, newXML) {
		t.Fatal("could not create a distinct second repomd generation")
	}
	var newSignature bytes.Buffer
	if err := signer.Sign(ctx, bytes.NewReader(newXML), &newSignature); err != nil {
		t.Fatal(err)
	}
	newASC := newSignature.Bytes()
	oldFirst := append(append(bytes.TrimSpace(append([]byte(nil), oldASC...)), '\n'), bytes.TrimSpace(newASC)...)
	oldFirst = append(oldFirst, '\n')
	newFirst := append(append(bytes.TrimSpace(append([]byte(nil), newASC...)), '\n'), bytes.TrimSpace(oldASC)...)
	newFirst = append(newFirst, '\n')
	packetOldFirst := armorSignaturePackets(t, oldASC, newASC)
	packetNewFirst := armorSignaturePackets(t, newASC, oldASC)

	root := filepath.Join(work, "served")
	states := []signatureBridgeState{
		{name: "old-old", xml: oldXML, asc: oldASC},
		{name: "old-new", xml: oldXML, asc: newASC},
		{name: "new-old", xml: newXML, asc: oldASC},
		{name: "new-new", xml: newXML, asc: newASC},
		{name: "old-bridge-old-first", xml: oldXML, asc: oldFirst},
		{name: "new-bridge-old-first", xml: newXML, asc: oldFirst},
		{name: "old-bridge-new-first", xml: oldXML, asc: newFirst},
		{name: "new-bridge-new-first", xml: newXML, asc: newFirst},
		{name: "old-packet-bridge-old-first", xml: oldXML, asc: packetOldFirst},
		{name: "new-packet-bridge-old-first", xml: newXML, asc: packetOldFirst},
		{name: "old-packet-bridge-new-first", xml: oldXML, asc: packetNewFirst},
		{name: "new-packet-bridge-new-first", xml: newXML, asc: packetNewFirst},
		// For redirect probes, the raw .asc is deliberately the old signature.
		// Success is possible only if dnf derives the signature URL from the
		// redirected repomd URL instead of from the configured raw baseurl.
		{name: "redirect-302", xml: oldXML, asc: oldASC},
		{name: "redirect-307", xml: oldXML, asc: oldASC},
		{name: "redirect-308", xml: oldXML, asc: oldASC},
		{name: "generation-new", xml: newXML, asc: newASC},
	}
	for _, state := range states {
		materializeBridgeState(t, base, filepath.Join(root, state.name), state.xml, state.asc)
	}
	port, requests, stop := serveBridgeStates(t, root)
	defer stop()

	for _, image := range []struct {
		name string
		env  string
		def  string
	}{
		{name: "el8", env: "SOW_COMPAT_EL8_IMAGE", def: defaultEL8Image},
		{name: "el9", env: "SOW_COMPAT_EL9_IMAGE", def: defaultEL9Image},
		{name: "el10", env: "SOW_COMPAT_DNF_IMAGE", def: defaultDNFImage},
	} {
		image := image
		t.Run(image.name, func(t *testing.T) {
			runDocker(ctx, t, compatImage(image.env, image.def),
				[]string{"-v", publicKey + ":/etc/pki/rpm-gpg/SOW-COMPAT:ro"},
				dnfSignatureBridgeScript(port, states, image.name),
			)
		})
	}
	for name, code := range map[string]int{"redirect-302": http.StatusFound, "redirect-307": http.StatusTemporaryRedirect, "redirect-308": http.StatusPermanentRedirect} {
		if !requests.contains(fmt.Sprintf("GET /%s/repodata/repomd.xml %d", name, code)) ||
			!requests.contains(fmt.Sprintf("GET /%s/repodata/repomd.xml.asc 200", name)) {
			t.Fatalf("redirect probe %s did not fetch XML through the redirect and signature from the raw baseurl:\n%s", name, requests.String())
		}
	}
	t.Logf("signature bridge HTTP request assertions passed entries=%d", len(requests.snapshot()))
}

func armorSignaturePackets(t *testing.T, signatures ...[]byte) []byte {
	t.Helper()
	var packets bytes.Buffer
	for _, signature := range signatures {
		block, err := armor.Decode(bytes.NewReader(signature))
		if err != nil {
			t.Fatalf("decode detached signature armor: %v", err)
		}
		if block == nil || block.Type != openpgp.SignatureType {
			t.Fatalf("decode detached signature armor: unexpected block %#v", block)
		}
		if _, err := io.Copy(&packets, block.Body); err != nil {
			t.Fatal(err)
		}
	}
	var combined bytes.Buffer
	armored, err := armor.Encode(&combined, openpgp.SignatureType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := packets.WriteTo(armored); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	return combined.Bytes()
}

type signatureBridgeState struct {
	name string
	xml  []byte
	asc  []byte
}

func materializeBridgeState(t *testing.T, base, destination string, repomd, signature []byte) {
	t.Helper()
	err := filepath.WalkDir(base, func(source string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(base, source)
		if err != nil || relative == "." {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if relative == filepath.Join("repodata", "repomd.xml") || relative == filepath.Join("repodata", "repomd.xml.asc") {
			return nil
		}
		return linkOrCopyErr(source, target)
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(destination, "repodata", "repomd.xml"), repomd, 0o644)
	writeFile(t, filepath.Join(destination, "repodata", "repomd.xml.asc"), signature, 0o644)
}

func linkOrCopy(t *testing.T, source, destination string) {
	t.Helper()
	if err := linkOrCopyErr(source, destination); err != nil {
		t.Fatal(err)
	}
}

func linkOrCopyErr(source, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	if err := os.Link(source, destination); err == nil {
		return nil
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	return errors.Join(copyErr, output.Close())
}

func mustRead(t *testing.T, filename string) []byte {
	t.Helper()
	body, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func serveBridgeStates(t *testing.T, root string) (int, *requestLog, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	files := http.FileServer(http.Dir(root))
	requests := &requestLog{}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		status := &responseStatus{ResponseWriter: writer}
		redirected := false
		for name, code := range map[string]int{"redirect-302": http.StatusFound, "redirect-307": http.StatusTemporaryRedirect, "redirect-308": http.StatusPermanentRedirect} {
			if request.URL.Path == "/"+name+"/repodata/repomd.xml" {
				http.Redirect(status, request, "/generation-new/repodata/repomd.xml", code)
				redirected = true
				break
			}
		}
		if !redirected {
			files.ServeHTTP(status, request)
		}
		if status.status == 0 {
			status.status = http.StatusOK
		}
		requests.append(fmt.Sprintf("%s %s %d", request.Method, request.URL.EscapedPath(), status.status))
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}
	return listener.Addr().(*net.TCPAddr).Port, requests, stop
}

func dnfSignatureBridgeScript(port int, states []signatureBridgeState, image string) string {
	var script strings.Builder
	script.WriteString("dnf --version | head -1\n")
	for _, state := range states {
		expect := signatureBridgeExpectation(state.name, image)
		fmt.Fprintf(&script, `
name=%q
cat > /etc/yum.repos.d/sow-bridge.repo <<EOF
[sow-bridge]
name=SOW detached signature bridge probe
baseurl=http://host.docker.internal:%d/%s/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/SOW-COMPAT
metadata_expire=0
skip_if_unavailable=0
EOF
rm -rf /var/cache/dnf
set +e
dnf -y --disablerepo='*' --enablerepo=sow-bridge --setopt=install_weak_deps=False makecache --refresh >"/tmp/$name.log" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then result=success; else result=failure; fi
printf 'STATE %%s RESULT %%s STATUS %%s\n' "$name" "$result" "$status"
sed -n '1,120p' "/tmp/$name.log"
case %q in
  success) test "$result" = success ;;
  failure) test "$result" = failure ;;
  probe) : ;;
esac
`, state.name, port, state.name, expect)
	}
	return script.String()
}

func signatureBridgeExpectation(state, image string) string {
	switch state {
	case "old-old", "new-new", "generation-new", "old-bridge-old-first", "new-bridge-new-first":
		return "success"
	case "old-new", "new-old", "new-bridge-old-first", "old-bridge-new-first",
		"redirect-302", "redirect-307", "redirect-308":
		return "failure"
	case "old-packet-bridge-old-first":
		if image == "el10" {
			return "failure"
		}
		return "success"
	case "new-packet-bridge-new-first":
		if image == "el10" {
			return "failure"
		}
		return "success"
	case "new-packet-bridge-old-first", "old-packet-bridge-new-first":
		return "failure"
	default:
		panic("unclassified signature bridge state " + state)
	}
}
