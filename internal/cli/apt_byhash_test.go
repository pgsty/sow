package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/state"
)

func TestCLIAPTByHashRetentionKeepsTwoGenerationsAndFailsClosed(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(aptByHashCLIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	_, keyPath := writeMaterializeSigningKey(t, root)
	packages := []string{
		writeRetentionDEB(t, root, "1.0.0"),
		writeRetentionDEB(t, root, "2.0.0"),
		writeRetentionDEB(t, root, "3.0.0"),
		writeRetentionDEB(t, root, "4.0.0"),
	}
	runAdd := func(packagePath string) (int, string, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := Main([]string{"add", packagePath, "--config", configPath, "--repo", "deb-retention", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	ledgerPath := filepath.Join(root, ".sow", "state", "retention", "apt-by-hash", "views", "beta", "deb-retention", "jammy.json")
	readLedger := func() aptrepo.ByHashLedger {
		t.Helper()
		file, err := os.Open(ledgerPath)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		ledger, err := aptrepo.DecodeByHashLedger(file)
		if err != nil {
			t.Fatal(err)
		}
		return ledger
	}

	var first aptrepo.ByHashGeneration
	for index := 0; index < 3; index++ {
		code, stdout, stderr := runAdd(packages[index])
		if code != ExitOK || !strings.Contains(stdout, "apt by-hash retained=2") {
			t.Fatalf("add generation %d code=%d stdout=%s stderr=%s", index+1, code, stdout, stderr)
		}
		ledger := readLedger()
		if ledger.LastSequence != uint64(index+1) || ledger.LiveGeneration == "" {
			t.Fatalf("generation %d ledger = %+v", index+1, ledger)
		}
		if index == 0 {
			first = ledger.Generations[0]
		}
		if index == 2 && len(ledger.Generations) != 2 {
			t.Fatalf("third generation retained %d ledgers, want 2", len(ledger.Generations))
		}
	}
	var commandOut, commandErr bytes.Buffer
	if code := Main([]string{"promote", "beta", "latest", "--config", configPath, "--repo", "deb-retention"}, &commandOut, &commandErr); code != ExitOK {
		t.Fatalf("promote latest code=%d stdout=%s stderr=%s", code, commandOut.String(), commandErr.String())
	}
	commandOut.Reset()
	commandErr.Reset()
	if code := Main([]string{"materialize", "latest", "--config", configPath, "--repo", "deb-retention", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}, &commandOut, &commandErr); code != ExitOK || !strings.Contains(commandOut.String(), "materialize apt-by-hash view=latest retained=2") {
		t.Fatalf("materialize latest code=%d stdout=%s stderr=%s", code, commandOut.String(), commandErr.String())
	}
	latestLedgerPath := filepath.Join(root, ".sow", "state", "retention", "apt-by-hash", "views", "latest", "deb-retention", "jammy.json")
	if file, err := os.Open(latestLedgerPath); err != nil {
		t.Fatalf("materialize did not persist latest ledger: %v", err)
	} else {
		if _, err := aptrepo.DecodeByHashLedger(file); err != nil {
			file.Close()
			t.Fatalf("materialize latest ledger is invalid: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}

	third := readLedger()
	canonical := state.New(filepath.Join(root, ".sow"))
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		t.Fatalf("canonical ledger head=%s err=%v", head, err)
	}
	canonicalPath, err := state.APTByHashLedgerPath("views", "beta", "deb-retention", "jammy")
	if err != nil {
		t.Fatal(err)
	}
	committedLedger, err := canonical.OpenPathAt(head, canonicalPath)
	if err != nil {
		t.Fatalf("ledger is not committed at canonical HEAD: %v", err)
	}
	if _, err := aptrepo.DecodeByHashLedger(committedLedger); err != nil {
		committedLedger.Close()
		t.Fatalf("committed ledger is invalid: %v", err)
	}
	if err := committedLedger.Close(); err != nil {
		t.Fatal(err)
	}
	retainedPaths := make(map[string]struct{})
	for _, generation := range third.Generations {
		for _, relative := range generation.Paths {
			retainedPaths[relative] = struct{}{}
			if _, err := os.Stat(filepath.Join(root, ".sow", "materialized", "beta", "apt", "retention", filepath.FromSlash(relative))); err != nil {
				t.Fatalf("retained by-hash path %s is missing: %v", relative, err)
			}
		}
	}
	firstOnly := ""
	for _, relative := range first.Paths {
		if _, shared := retainedPaths[relative]; !shared {
			firstOnly = relative
			if _, err := os.Stat(filepath.Join(root, ".sow", "materialized", "beta", "apt", "retention", filepath.FromSlash(relative))); !os.IsNotExist(err) {
				t.Fatalf("first-only by-hash path %s survived: %v", relative, err)
			}
		}
	}
	if firstOnly == "" {
		t.Fatal("fixture did not produce a first-generation-only by-hash path")
	}

	beforeReplay, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runAdd(packages[2])
	if code != ExitOK || !strings.Contains(stdout, "physical=no-op") {
		t.Fatalf("generation replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	afterReplay, err := os.ReadFile(ledgerPath)
	if err != nil || !bytes.Equal(beforeReplay, afterReplay) {
		t.Fatalf("generation replay changed ledger: err=%v", err)
	}

	// Commit a corrupt ledger while keeping the canonical Git worktree/index
	// clean. The fourth Release may be installed, but retention must reject the
	// ledger before deleting any second-generation immutable object.
	tampered := bytes.Replace(beforeReplay, []byte(`"repo": "deb-retention"`), []byte(`"repo": "deb-corrupted"`), 1)
	if bytes.Equal(tampered, beforeReplay) {
		t.Fatal("ledger tamper did not change bytes")
	}
	tamperDir, err := newTransactionDir(filepath.Join(root, ".sow"), "tamper-by-hash-ledger-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tamperDir)
	tamperStage := filepath.Join(tamperDir, "ledger.json")
	if err := os.WriteFile(tamperStage, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.Apply(t.Context(), "test-corrupt-by-hash-ledger", "commit corrupt by-hash ledger fixture", map[string]string{canonicalPath: tamperStage}, nil, state.ApplyOptions{}); err != nil || !changed {
		t.Fatalf("commit corrupt ledger changed=%v err=%v", changed, err)
	}
	secondOnly := generationUniquePath(third.Generations[0], third.Generations[1])
	if secondOnly == "" {
		t.Fatal("fixture did not produce a second-generation-only path")
	}
	code, stdout, stderr = runAdd(packages[3])
	if code == ExitOK || !strings.Contains(stderr, "by-hash ledger checksum mismatch") {
		t.Fatalf("corrupt-ledger add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", "materialized", "beta", "apt", "retention", filepath.FromSlash(secondOnly))); err != nil {
		t.Fatalf("fail-closed cleanup removed second generation %s: %v", secondOnly, err)
	}
}

func generationUniquePath(left, right aptrepo.ByHashGeneration) string {
	rightPaths := make(map[string]struct{}, len(right.Paths))
	for _, value := range right.Paths {
		rightPaths[value] = struct{}{}
	}
	for _, value := range left.Paths {
		if _, shared := rightPaths[value]; !shared {
			return value
		}
	}
	return ""
}

func writeRetentionDEB(t *testing.T, root, version string) string {
	t.Helper()
	control := []byte("Package: sow-retention\n" +
		"Version: " + version + "\n" +
		"Architecture: amd64\n" +
		"Maintainer: SOW Test <sow@example.invalid>\n" +
		"Section: misc\nPriority: optional\n" +
		"Description: SOW by-hash retention fixture\n")
	controlTar := retentionTarGzip(t, map[string][]byte{"control": control})
	dataTar := retentionTarGzip(t, map[string][]byte{"usr/share/doc/sow-retention/" + version: []byte(version + "\n")})
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	writeRetentionArMember(t, &archive, "debian-binary", []byte("2.0\n"))
	writeRetentionArMember(t, &archive, "control.tar.gz", controlTar)
	writeRetentionArMember(t, &archive, "data.tar.gz", dataTar)
	filename := filepath.Join(root, "sow-retention_"+version+"_amd64.deb")
	if err := os.WriteFile(filename, archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return filename
}

func retentionTarGzip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tw := tar.NewWriter(gz)
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body := files[name]
		header := &tar.Header{Name: path.Clean(name), Mode: 0o644, Size: int64(len(body))}
		if err := tw.WriteHeader(header); err != nil {
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

func writeRetentionArMember(t *testing.T, output *bytes.Buffer, name string, body []byte) {
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

const aptByHashCLIConfig = `schema: sow/v1
state: {apt_by_hash_retention: 2}
gpg:
  public_key: repository-public.pgp
pools:
  public: {}
  gated: {}
repos:
  - id: deb-retention
    type: apt
    path: apt/retention
    default_pool: public
    arches: [amd64]
    os: {family: ubuntu, suite: jammy, lifecycle: active}
    apt: {suites: [jammy], components: [main]}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
