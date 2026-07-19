package compat_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/repository"
)

const (
	realAPTBaseURL        = "https://apt.postgresql.org/pub/repos/apt/"
	realAPTKeyURL         = "https://www.postgresql.org/media/keys/ACCC4CF8.asc"
	realAPTKeyFingerprint = "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8"
	realYUMBaseURL        = "https://download.postgresql.org/pub/repos/yum/common/redhat/rhel-9-x86_64/"
	realYUMKeyURL         = "https://download.postgresql.org/pub/repos/yum/keys/PGDG-RPM-GPG-KEY-RHEL"
	realYUMKeyFingerprint = "D4BF08AE67A0B4C7A1DBCCD240BCA2B408B40D20"
	realSyncByteLimit     = int64(32 << 20)
)

// TestOfficialPGDGUpstreamSyncCompatibility is a deliberately opt-in public
// network gate. It exercises the production CLI against the official PGDG APT
// and YUM repositories, while pinning both trust anchors and allowing only one
// small package family per source. A CONNECT proxy caps response traffic and
// refuses host drift before any production sync process can follow it.
func TestOfficialPGDGUpstreamSyncCompatibility(t *testing.T) {
	if os.Getenv("SOW_RUN_REAL_UPSTREAM") != "1" {
		t.Skip("set SOW_RUN_REAL_UPSTREAM=1 to run the official PGDG upstream compatibility gate")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	moduleRoot := findModuleRoot(t)
	work := hostableCompatTempDir(t)
	repositoryRoot := filepath.Join(work, "repository")
	if err := os.MkdirAll(repositoryRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		filepath.Join(repositoryRoot, "apt", "pgdg"),
		filepath.Join(repositoryRoot, "yum", "pgdg", "9", "x86_64"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	aptKey := fetchPinnedPublicKey(ctx, t, realAPTKeyURL, realAPTKeyFingerprint)
	yumKey := fetchPinnedPublicKey(ctx, t, realYUMKeyURL, realYUMKeyFingerprint)
	yumKeySHA256 := sha256.Sum256(yumKey)
	writeFile(t, filepath.Join(repositoryRoot, "pgdg-apt.asc"), aptKey, 0o644)
	writeFile(t, filepath.Join(repositoryRoot, "pgdg-yum.asc"), yumKey, 0o644)

	privateKey, publicKey := writeSigningKey(t, work)
	publicKeyBody, err := os.ReadFile(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(repositoryRoot, "signing-public.gpg"), publicKeyBody, 0o644)
	configPath := filepath.Join(repositoryRoot, "sow.yaml")
	writeFile(t, configPath, []byte(realPGDGConfig), 0o600)
	cliPath := buildCLI(ctx, t, moduleRoot, work)

	runRealCLI(ctx, t, moduleRoot, cliPath, nil,
		"init", "--config", configPath, "--workers", "2", "--chunk-entries", "128")

	aptFirst, aptFirstBytes := runOfficialSync(ctx, t, moduleRoot, cliPath, configPath, privateKey,
		"pgdg-apt", "apt.postgresql.org:443")
	assertSyncChanged(t, aptFirst, "pgdg-apt", "deb")
	yumFirst, yumFirstBytes := runOfficialSync(ctx, t, moduleRoot, cliPath, configPath, privateKey,
		"pgdg-yum", "download.postgresql.org:443")
	assertSyncChanged(t, yumFirst, "pgdg-yum", "rpm")

	receiptsBefore := readCanonicalReceipts(t, repositoryRoot)
	debCount, rpmCount, casBytes := assertRealPGDGReceipts(t, repositoryRoot, receiptsBefore, hex.EncodeToString(yumKeySHA256[:]))
	metadataDigests := collectRealPGDGMetadataDigests(t, repositoryRoot, receiptsBefore)
	if debCount != 1 {
		t.Fatalf("PGDG pgbadger filter produced %d DEB receipts, want exactly one", debCount)
	}
	if rpmCount < 1 || rpmCount > 64 {
		t.Fatalf("PGDG pgdg-redhat-repo filter produced %d RPM receipts, want 1..64", rpmCount)
	}
	if casBytes > realSyncByteLimit {
		t.Fatalf("selected package CAS bytes=%d exceed opt-in gate budget=%d", casBytes, realSyncByteLimit)
	}
	casBefore := snapshotRegularFiles(t, filepath.Join(repositoryRoot, ".pool", "sha256"), ".tmp")

	aptReplay, aptReplayBytes := runOfficialSync(ctx, t, moduleRoot, cliPath, configPath, privateKey,
		"pgdg-apt", "apt.postgresql.org:443")
	assertSyncReplay(t, aptReplay, "pgdg-apt")
	yumReplay, yumReplayBytes := runOfficialSync(ctx, t, moduleRoot, cliPath, configPath, privateKey,
		"pgdg-yum", "download.postgresql.org:443")
	assertSyncReplay(t, yumReplay, "pgdg-yum")
	assertSameSnapshot(t, receiptsBefore, readCanonicalReceipts(t, repositoryRoot), "canonical provenance replay")
	assertSameSnapshot(t, casBefore, snapshotRegularFiles(t, filepath.Join(repositoryRoot, ".pool", "sha256"), ".tmp"), "CAS replay")

	verifyOutput := runRealCLI(ctx, t, moduleRoot, cliPath, nil,
		"verify", "--layer", "L1", "--view", "beta", "--config", configPath,
		"--gpg-public-key-file", publicKey, "--workers", "2", "--chunk-entries", "128")
	if !strings.Contains(verifyOutput, "verify outcome=passed") {
		t.Fatalf("L1 did not pass:\n%s", verifyOutput)
	}
	exportRoot := filepath.Join(repositoryRoot, "export")
	materializeOutput := runRealCLI(ctx, t, moduleRoot, cliPath, nil,
		"materialize", "beta", "--target", "export", "--config", configPath,
		"--serving-base-url", "https://export.example.invalid",
		"--gpg-private-key-file", privateKey, "--workers", "2", "--chunk-entries", "128")
	if !strings.Contains(materializeOutput, "materialized ref=beta") {
		t.Fatalf("materialize did not report beta projection:\n%s", materializeOutput)
	}
	assertMaterializedReceiptHardlinks(t, repositoryRoot, exportRoot, receiptsBefore)

	t.Logf("official PGDG gate passed: apt_receipts=%d rpm_receipts=%d cas_bytes=%d evidence=%d apt_wire_first=%d apt_wire_replay=%d yum_wire_first=%d yum_wire_replay=%d",
		debCount, rpmCount, casBytes, countEvidence(t, repositoryRoot), aptFirstBytes, aptReplayBytes, yumFirstBytes, yumReplayBytes)
	t.Logf("official PGDG metadata sha256: apt_release=%s apt_packages=%s yum_repomd=%s yum_repomd_asc=%s yum_primary=%s",
		metadataDigests.aptRelease, metadataDigests.aptPackages, metadataDigests.yumRepomd, metadataDigests.yumRepomdASC, metadataDigests.yumPrimary)
}

func runOfficialSync(ctx context.Context, t *testing.T, moduleRoot, cliPath, configPath, privateKey, upstreamID, host string) (string, int64) {
	t.Helper()
	proxy := newBoundedCONNECTProxy(t, host, realSyncByteLimit)
	defer proxy.Close()
	output := runRealCLI(ctx, t, moduleRoot, cliPath, map[string]string{
		"HTTPS_PROXY": proxy.URL(),
		"HTTP_PROXY":  proxy.URL(),
		"NO_PROXY":    "",
	}, "sync", "--upstream", upstreamID, "--config", configPath,
		"--gpg-private-key-file", privateKey, "--attempts", "2", "--workers", "2", "--chunk-entries", "128")
	if proxy.Exceeded() {
		t.Fatalf("official %s sync exceeded response budget %d bytes", upstreamID, realSyncByteLimit)
	}
	if proxy.Bytes() <= 0 {
		t.Fatalf("official %s sync did not traverse the bounded HTTPS proxy", upstreamID)
	}
	return output, proxy.Bytes()
}

func runRealCLI(ctx context.Context, t *testing.T, moduleRoot, executable string, overrides map[string]string, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir = moduleRoot
	command.Env = overriddenEnvironment(overrides)
	started := time.Now()
	output, err := command.CombinedOutput()
	t.Logf("sow %s elapsed=%s\n%s", strings.Join(arguments, " "), time.Since(started), output)
	if err != nil {
		t.Fatalf("sow %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
	return string(output)
}

func overriddenEnvironment(overrides map[string]string) []string {
	if len(overrides) == 0 {
		return os.Environ()
	}
	wanted := make(map[string]string, len(overrides)*2)
	for key, value := range overrides {
		wanted[strings.ToUpper(key)] = value
		wanted[strings.ToLower(key)] = value
	}
	result := make([]string, 0, len(os.Environ())+len(wanted))
	for _, entry := range os.Environ() {
		key, _, found := strings.Cut(entry, "=")
		if _, replaced := wanted[key]; found && replaced {
			continue
		}
		result = append(result, entry)
	}
	keys := make([]string, 0, len(wanted))
	for key := range wanted {
		keys = append(keys, key)
	}
	// Ordering makes subprocess evidence deterministic enough to diagnose.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	for _, key := range keys {
		result = append(result, key+"="+wanted[key])
	}
	return result
}

func fetchPinnedPublicKey(ctx context.Context, t *testing.T, rawURL, expectedFingerprint string) []byte {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 || request.URL.Scheme != "https" || request.URL.Host != parsed.Host {
				return fmt.Errorf("refuse public-key redirect to %s", request.URL.Redacted())
			}
			return nil
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("fetch official key %s: %v", parsed.Host, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > 1<<20 {
		t.Fatalf("fetch official key %s: status=%d length=%d", parsed.Host, response.StatusCode, response.ContentLength)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(body) == 0 || len(body) > 1<<20 {
		t.Fatalf("read official key %s: bytes=%d err=%v", parsed.Host, len(body), err)
	}
	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(string(body)))
	if err != nil || len(entities) != 1 || entities[0] == nil || entities[0].PrimaryKey == nil || entities[0].PrivateKey != nil {
		t.Fatalf("official key %s is not one public OpenPGP entity: entities=%d err=%v", parsed.Host, len(entities), err)
	}
	for _, subkey := range entities[0].Subkeys {
		if subkey.PrivateKey != nil {
			t.Fatalf("official key %s unexpectedly contains a private subkey", parsed.Host)
		}
	}
	fingerprint := strings.ToUpper(hex.EncodeToString(entities[0].PrimaryKey.Fingerprint[:]))
	if fingerprint != expectedFingerprint {
		t.Fatalf("official key %s fingerprint drifted: got=%s want=%s", parsed.Host, fingerprint, expectedFingerprint)
	}
	t.Logf("pinned official key host=%s fingerprint=%s bytes=%d", parsed.Host, fingerprint, len(body))
	return body
}

func assertSyncChanged(t *testing.T, output, upstreamID, format string) {
	t.Helper()
	line := syncSummaryLine(t, output, upstreamID)
	if !strings.Contains(line, "format="+format) || syncSummaryInteger(t, line, "download") < 1 || !strings.Contains(line, "provenance_changed=true") {
		t.Fatalf("first official sync lacks changed/download evidence: %s", line)
	}
	if syncSummaryInteger(t, line, "filtered") < 1 {
		t.Fatalf("official sync did not prove its allow-list filtered the upstream: %s", line)
	}
}

func assertSyncReplay(t *testing.T, output, upstreamID string) {
	t.Helper()
	line := syncSummaryLine(t, output, upstreamID)
	if syncSummaryInteger(t, line, "download") != 0 || !strings.Contains(line, "provenance_changed=false") {
		t.Fatalf("official sync replay was not additive/idempotent: %s", line)
	}
}

func syncSummaryLine(t *testing.T, output, upstreamID string) string {
	t.Helper()
	prefix := "sync upstream=" + upstreamID + " "
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("missing sync summary for %s:\n%s", upstreamID, output)
	return ""
}

func syncSummaryInteger(t *testing.T, line, field string) int64 {
	t.Helper()
	prefix := field + "="
	for _, token := range strings.Fields(line) {
		if strings.HasPrefix(token, prefix) {
			value, err := strconv.ParseInt(strings.TrimPrefix(token, prefix), 10, 64)
			if err != nil {
				t.Fatalf("invalid %s in sync summary %q", field, line)
			}
			return value
		}
	}
	t.Fatalf("missing %s in sync summary %q", field, line)
	return 0
}

func readCanonicalReceipts(t *testing.T, root string) map[string][]byte {
	t.Helper()
	return snapshotRegularFiles(t, filepath.Join(root, ".sow", "state", "provenance"), "evidence")
}

func snapshotRegularFiles(t *testing.T, root string, excludedTop ...string) map[string][]byte {
	t.Helper()
	excluded := make(map[string]bool, len(excludedTop))
	for _, name := range excludedTop {
		excluded[name] = true
	}
	result := make(map[string][]byte)
	err := filepath.WalkDir(root, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if relative != "." && excluded[strings.Split(filepath.ToSlash(relative), "/")[0]] {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || strings.Contains(filepath.ToSlash(relative), "/.tmp/") {
			return nil
		}
		body, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(relative)] = body
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertSameSnapshot(t *testing.T, before, after map[string][]byte, subject string) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("%s file count changed: before=%d after=%d", subject, len(before), len(after))
	}
	for name, body := range before {
		other, exists := after[name]
		if !exists || string(body) != string(other) {
			t.Fatalf("%s changed or deleted %s", subject, name)
		}
	}
}

func assertRealPGDGReceipts(t *testing.T, root string, files map[string][]byte, packageKeyringSHA256 string) (int, int, int64) {
	t.Helper()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	debCount, rpmCount := 0, 0
	var total int64
	for name, body := range files {
		receipt, err := provenance.Decode(body)
		if err != nil {
			t.Fatalf("decode canonical receipt %s: %v", name, err)
		}
		switch receipt.Format {
		case "deb":
			debCount++
			if !strings.HasPrefix(receipt.UpstreamURL, realAPTBaseURL+"pool/main/p/pgbadger/pgbadger_") || receipt.DEB == nil || receipt.DEB.SignedReleaseKind != "InRelease" {
				t.Fatalf("unexpected filtered DEB receipt %s: %#v", name, receipt)
			}
			assertCanonicalEvidence(t, root, receipt.DEB.SignedReleaseSHA256)
			assertCanonicalEvidence(t, root, receipt.DEB.PackagesEvidenceSHA256)
		case "rpm":
			rpmCount++
			if receipt.Schema != provenance.Schema || !strings.HasPrefix(receipt.UpstreamURL, realYUMBaseURL+"pgdg-redhat-repo-") ||
				receipt.RPM == nil || receipt.RPM.OriginalRPMSHA != receipt.ArtifactSHA256 ||
				receipt.RPM.SignaturePolicy != "preserve-upstream" || receipt.RPM.SignatureVerification != "verified" ||
				receipt.RPM.PackageKeyringSHA256 != packageKeyringSHA256 ||
				len(receipt.RPM.EmbeddedSignatures) == 0 {
				t.Fatalf("unexpected filtered RPM receipt %s: %#v", name, receipt)
			}
			for _, signature := range receipt.RPM.EmbeddedSignatures {
				if signature.SignatureCreatedAt == "" || signature.Coverage == "" || signature.SignedBytes <= 0 ||
					signature.SignerFingerprint == "" || signature.SignerKeyID == "" || signature.SignerPrimaryFingerprint == "" {
					t.Fatalf("incomplete RPM provenance v3 signature %s: %#v", name, signature)
				}
				t.Logf("official PGDG RPM provenance v3 artifact=%s keyring=%s signer=%s primary=%s created=%s coverage=%s signed_bytes=%d",
					receipt.ArtifactSHA256, receipt.RPM.PackageKeyringSHA256, signature.SignerFingerprint,
					signature.SignerPrimaryFingerprint, signature.SignatureCreatedAt, signature.Coverage, signature.SignedBytes)
			}
			assertCanonicalEvidence(t, root, receipt.RPM.IndexSHA256)
		default:
			t.Fatalf("unexpected provenance format %q", receipt.Format)
		}
		digest, err := repository.ParseDigest(receipt.ArtifactSHA256)
		if err != nil {
			t.Fatal(err)
		}
		file, err := pool.Open(digest)
		if err != nil {
			t.Fatalf("open receipt CAS %s: %v", receipt.ArtifactSHA256, err)
		}
		hash := sha256.New()
		written, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != receipt.ArtifactSize || hex.EncodeToString(hash.Sum(nil)) != receipt.ArtifactSHA256 {
			t.Fatalf("CAS bytes do not match receipt %s: bytes=%d copy=%v close=%v", name, written, copyErr, closeErr)
		}
		total += written
	}
	return debCount, rpmCount, total
}

type realPGDGMetadataDigests struct {
	aptRelease   string
	aptPackages  string
	yumRepomd    string
	yumRepomdASC string
	yumPrimary   string
}

// collectRealPGDGMetadataDigests turns the public-network observation into an
// exact, archiveable identity. Receipt fields bind APT Release/Packages and
// YUM primary; the remaining signed YUM root objects are identified from the
// content-addressed evidence store and rehashed before being reported.
func collectRealPGDGMetadataDigests(t *testing.T, root string, receipts map[string][]byte) realPGDGMetadataDigests {
	t.Helper()
	result := realPGDGMetadataDigests{}
	for name, body := range receipts {
		receipt, err := provenance.Decode(body)
		if err != nil {
			t.Fatalf("decode receipt %s while collecting metadata identity: %v", name, err)
		}
		switch receipt.Format {
		case "deb":
			if receipt.DEB == nil {
				t.Fatalf("DEB receipt %s omitted proof", name)
			}
			setSingleRealPGDGDigest(t, "APT signed Release", &result.aptRelease, receipt.DEB.SignedReleaseSHA256)
			setSingleRealPGDGDigest(t, "APT Packages", &result.aptPackages, receipt.DEB.PackagesEvidenceSHA256)
		case "rpm":
			if receipt.RPM == nil {
				t.Fatalf("RPM receipt %s omitted proof", name)
			}
			setSingleRealPGDGDigest(t, "YUM primary", &result.yumPrimary, receipt.RPM.IndexSHA256)
		}
	}

	evidenceRoot := filepath.Join(root, ".sow", "state", "provenance", "evidence", "sha256")
	evidence := snapshotRegularFiles(t, evidenceRoot)
	for filename, body := range evidence {
		digest := filepath.Base(filename)
		sum := sha256.Sum256(body)
		if digest != hex.EncodeToString(sum[:]) {
			t.Fatalf("canonical evidence filename/hash mismatch: %s", filename)
		}
		trimmed := bytes.TrimSpace(body)
		switch {
		case bytes.HasPrefix(trimmed, []byte("-----BEGIN PGP SIGNATURE-----")):
			setSingleRealPGDGDigest(t, "YUM repomd signature", &result.yumRepomdASC, digest)
		case bytes.Contains(firstRealPGDGBytes(trimmed, 4096), []byte("<repomd")):
			setSingleRealPGDGDigest(t, "YUM repomd", &result.yumRepomd, digest)
		}
	}
	for label, digest := range map[string]string{
		"APT signed Release": result.aptRelease,
		"APT Packages":       result.aptPackages,
		"YUM repomd":         result.yumRepomd,
		"YUM repomd.asc":     result.yumRepomdASC,
		"YUM primary":        result.yumPrimary,
	} {
		if digest == "" {
			t.Fatalf("official PGDG observation omitted %s digest", label)
		}
		assertCanonicalEvidence(t, root, digest)
	}
	return result
}

func setSingleRealPGDGDigest(t *testing.T, label string, destination *string, digest string) {
	t.Helper()
	if len(digest) != sha256.Size*2 {
		t.Fatalf("%s has invalid SHA-256 %q", label, digest)
	}
	if *destination != "" && *destination != digest {
		t.Fatalf("%s changed within one observation: %s != %s", label, *destination, digest)
	}
	*destination = digest
}

func firstRealPGDGBytes(body []byte, limit int) []byte {
	if len(body) <= limit {
		return body
	}
	return body[:limit]
}

func assertCanonicalEvidence(t *testing.T, root, digest string) {
	t.Helper()
	info, err := os.Stat(filepath.Join(root, ".sow", "state", "provenance", "evidence", "sha256", digest))
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		t.Fatalf("canonical upstream evidence %s is missing or empty: %v", digest, err)
	}
}

func countEvidence(t *testing.T, root string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, ".sow", "state", "provenance", "evidence", "sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 5 {
		t.Fatalf("canonical evidence objects=%d, want at least APT InRelease+Packages and YUM repomd+signature+primary", len(entries))
	}
	return len(entries)
}

func assertMaterializedReceiptHardlinks(t *testing.T, root, exportRoot string, receipts map[string][]byte) {
	t.Helper()
	materialized := make(map[string]string)
	err := filepath.WalkDir(exportRoot, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || (filepath.Ext(name) != ".deb" && filepath.Ext(name) != ".rpm") {
			return nil
		}
		file, err := os.Open(name)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return fmt.Errorf("hash materialized payload: copy=%v close=%v", copyErr, closeErr)
		}
		materialized[hex.EncodeToString(hash.Sum(nil))] = name
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(materialized) != len(receipts) {
		t.Fatalf("materialized payload count=%d canonical receipts=%d", len(materialized), len(receipts))
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range receipts {
		receipt, err := provenance.Decode(body)
		if err != nil {
			t.Fatal(err)
		}
		payload, exists := materialized[receipt.ArtifactSHA256]
		if !exists {
			t.Fatalf("receipt %s is absent from explicit materialization", receipt.ArtifactSHA256)
		}
		digest, _ := repository.ParseDigest(receipt.ArtifactSHA256)
		poolInfo, err := os.Stat(pool.ObjectPath(digest))
		if err != nil {
			t.Fatal(err)
		}
		materializedInfo, err := os.Stat(payload)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(poolInfo, materializedInfo) {
			t.Fatalf("materialized payload %s is not a hardlink to CAS %s", payload, receipt.ArtifactSHA256)
		}
	}
}

type boundedCONNECTProxy struct {
	t        *testing.T
	host     string
	budget   *responseBudget
	server   *httptest.Server
	exceeded bool
	mu       sync.Mutex
}

func newBoundedCONNECTProxy(t *testing.T, host string, limit int64) *boundedCONNECTProxy {
	t.Helper()
	proxy := &boundedCONNECTProxy{t: t, host: host, budget: &responseBudget{limit: limit}}
	proxy.server = httptest.NewServer(http.HandlerFunc(proxy.serveHTTP))
	return proxy
}

func (p *boundedCONNECTProxy) URL() string  { return p.server.URL }
func (p *boundedCONNECTProxy) Bytes() int64 { return p.budget.Bytes() }
func (p *boundedCONNECTProxy) Close()       { p.server.Close() }

func (p *boundedCONNECTProxy) Exceeded() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exceeded
}

func (p *boundedCONNECTProxy) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodConnect || request.Host != p.host {
		http.Error(writer, "CONNECT target refused", http.StatusForbidden)
		return
	}
	upstream, err := net.DialTimeout("tcp", request.Host, 10*time.Second)
	if err != nil {
		http.Error(writer, "upstream connect failed", http.StatusBadGateway)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(writer, "proxy hijacking unavailable", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, client)
		_ = upstream.Close()
		close(done)
	}()
	_, copyErr := io.Copy(&budgetedWriter{destination: client, budget: p.budget}, upstream)
	if copyErr != nil && p.budget.Exceeded() {
		p.mu.Lock()
		p.exceeded = true
		p.mu.Unlock()
	}
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

type responseBudget struct {
	mu       sync.Mutex
	limit    int64
	written  int64
	exceeded bool
}

func (b *responseBudget) WriteTo(destination io.Writer, body []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - b.written
	if remaining <= 0 {
		b.exceeded = true
		return 0, fmt.Errorf("official upstream response budget exceeded")
	}
	if int64(len(body)) > remaining {
		body = body[:remaining]
		b.exceeded = true
	}
	written, err := destination.Write(body)
	b.written += int64(written)
	if err == nil && b.exceeded {
		err = fmt.Errorf("official upstream response budget exceeded")
	}
	return written, err
}

func (b *responseBudget) Bytes() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.written
}

func (b *responseBudget) Exceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exceeded
}

type budgetedWriter struct {
	destination io.Writer
	budget      *responseBudget
}

func (w *budgetedWriter) Write(body []byte) (int, error) {
	return w.budget.WriteTo(w.destination, body)
}

const realPGDGConfig = `schema: sow/v1
state: {}
gpg:
  public_key: signing-public.gpg
pools:
  public: {}
  gated: {}
repos:
  - id: apt-pgdg
    type: apt
    path: apt/pgdg
    default_pool: public
    arches: [amd64]
    os: {family: debian, major: 12, suite: bookworm-pgdg, lifecycle: active}
    apt: {suites: [bookworm-pgdg], components: [main]}
  - id: yum-pgdg
    type: yum
    path: yum/pgdg/9/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: pgdg-yum.asc}
upstreams:
  - id: pgdg-apt
    type: apt
    repo: apt-pgdg
    url: https://apt.postgresql.org/pub/repos/apt/
    suite: bookworm-pgdg
    components: [main]
    arches: [amd64]
    allow: [pgbadger]
    debuginfo: drop
    keyring: pgdg-apt.asc
  - id: pgdg-yum
    type: yum
    repo: yum-pgdg
    url: https://download.postgresql.org/pub/repos/yum/common/redhat/rhel-9-x86_64/
    arches: [x86_64]
    allow: [pgdg-redhat-repo]
    debuginfo: drop
    keyring: pgdg-yum.asc
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://real-upstream-compat
`
