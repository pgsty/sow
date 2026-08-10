package compat_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const (
	defaultAPTImage = "pgsty/u22:latest"
	defaultDNFImage = "pgsty/el10:latest"
	defaultEL9Image = "almalinux:9"
	defaultEL8Image = "almalinux:8"
	debPackage      = "sow-compat-deb"
	debVersion      = "1.2.3-1"
)

func compatImage(environment, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(environment)); value != "" {
		return value
	}
	return fallback
}

func findModuleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve compatibility test source path")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func writeSigningKey(t *testing.T, root string) (string, string) {
	t.Helper()
	created := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	randomizedNotation := false
	keyConfig := &packet.Config{
		Time:                                  func() time.Time { return created },
		RSABits:                               2048,
		DefaultHash:                           crypto.SHA256,
		NonDeterministicSignaturesViaNotation: &randomizedNotation,
		InsecureGenerateNonCriticalKeyFlags:   true,
		InsecureGenerateNonCriticalSignatureCreationTime: true,
	}
	entity, err := openpgp.NewEntity("SOW Docker compatibility", "", "compat@example.invalid", keyConfig)
	if err != nil {
		t.Fatal(err)
	}
	var private, public, armoredPublic bytes.Buffer
	if err := entity.SerializePrivate(&private, keyConfig); err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	armoredWriter, err := armor.Encode(&armoredPublic, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	serializeErr := entity.Serialize(armoredWriter)
	closeErr := armoredWriter.Close()
	if serializeErr != nil || closeErr != nil {
		t.Fatal(errors.Join(serializeErr, closeErr))
	}
	privatePath := filepath.Join(root, "signing-private.gpg")
	publicPath := filepath.Join(root, "signing-public.gpg")
	writeFile(t, privatePath, private.Bytes(), 0o600)
	writeFile(t, publicPath, public.Bytes(), 0o644)
	writeFile(t, filepath.Join(root, "signing-public.asc"), armoredPublic.Bytes(), 0o644)
	return privatePath, publicPath
}

func writeInstallableDEB(t *testing.T, root, version string) string {
	t.Helper()
	control := []byte("Package: " + debPackage + "\n" +
		"Version: " + version + "\n" +
		"Architecture: amd64\n" +
		"Maintainer: SOW Test <compat@example.invalid>\n" +
		"Installed-Size: 1\n" +
		"Section: misc\n" +
		"Priority: optional\n" +
		"Description: SOW apt client compatibility fixture\n")
	controlTar := tarGzip(t, map[string][]byte{"control": control})
	dataTar := tarGzip(t, map[string][]byte{"usr/share/doc/sow-compat/README": []byte("installed version " + version + " by sow compatibility test\n")})
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	writeArMember(t, &archive, "debian-binary", []byte("2.0\n"))
	writeArMember(t, &archive, "control.tar.gz", controlTar)
	writeArMember(t, &archive, "data.tar.gz", dataTar)
	filename := filepath.Join(root, "sow-compat-deb_"+version+"_amd64.deb")
	writeFile(t, filename, archive.Bytes(), 0o644)
	return filename
}

func tarGzip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tw := tar.NewWriter(gz)
	directories := make(map[string]struct{})
	var names []string
	for name := range files {
		names = append(names, name)
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			directories[parent] = struct{}{}
		}
	}
	var directoryNames []string
	for name := range directories {
		directoryNames = append(directoryNames, name)
	}
	sort.Strings(directoryNames)
	for _, name := range directoryNames {
		if err := tw.WriteHeader(&tar.Header{Name: name + "/", Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func writeArMember(t *testing.T, output *bytes.Buffer, name string, body []byte) {
	t.Helper()
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name+"/", 0, 0, 0, 0o644, len(body))
	if len(header) != 60 {
		t.Fatalf("invalid ar header length %d", len(header))
	}
	output.WriteString(header)
	output.Write(body)
	if len(body)%2 != 0 {
		output.WriteByte('\n')
	}
}

func decodeBase64Fixture(t *testing.T, source, destination string) string {
	t.Helper()
	encoded, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, destination, decoded, 0o644)
	return destination
}

type requestLog struct {
	mu      sync.Mutex
	entries []string
}

func (log *requestLog) append(entry string) {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.entries = append(log.entries, entry)
}

func (log *requestLog) contains(fragment string) bool {
	for _, entry := range log.snapshot() {
		if strings.Contains(entry, fragment) {
			return true
		}
	}
	return false
}

func (log *requestLog) String() string {
	return strings.Join(log.snapshot(), "\n") + "\n"
}

func (log *requestLog) snapshot() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]string(nil), log.entries...)
}

type responseStatus struct {
	http.ResponseWriter
	status int
}

func (writer *responseStatus) WriteHeader(status int) {
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *responseStatus) Write(body []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	return writer.ResponseWriter.Write(body)
}

func serveRepositoryHTTP(t *testing.T, root string) (*requestLog, int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	log := &requestLog{}
	files := http.FileServer(http.Dir(root))
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		status := &responseStatus{ResponseWriter: writer}
		files.ServeHTTP(status, request)
		if status.status == 0 {
			status.status = http.StatusOK
		}
		log.append(fmt.Sprintf("%s %s %d", request.Method, request.URL.EscapedPath(), status.status))
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}
	return log, listener.Addr().(*net.TCPAddr).Port, stop
}

func dockerCompatibilityCommand(ctx context.Context, image string, mounts []string, script string) *exec.Cmd {
	arguments := []string{"run", "--rm", "--platform", "linux/amd64", "--add-host", "host.docker.internal:host-gateway"}
	arguments = append(arguments, mounts...)
	arguments = append(arguments, image, "sh", "-ec", script)
	return exec.CommandContext(ctx, "docker", arguments...)
}

func runDocker(ctx context.Context, t *testing.T, image string, mounts []string, script string) string {
	t.Helper()
	output, err := dockerCompatibilityCommand(ctx, image, mounts, script).CombinedOutput()
	t.Logf("docker image=%s\n%s", image, output)
	if err != nil {
		t.Fatalf("docker compatibility client %s: %v\n%s", image, err, output)
	}
	return string(output)
}

func writeFile(t *testing.T, filename string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filename, body, mode); err != nil {
		t.Fatal(err)
	}
}
