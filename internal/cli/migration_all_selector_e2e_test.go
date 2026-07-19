package cli

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/klauspost/compress/zstd"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/catalog"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

const (
	allSelectorRepoCount      = 33
	allSelectorAssetRepoCount = 12
	allSelectorAPTRepoCount   = 11
	allSelectorYUMRepoCount   = 10
	allSelectorPhysicalLeaves = 73
	allSelectorPayloads       = 53
	// Each YUM leaf carries one real RPM plus complete primary/filelists/other,
	// repomd.xml, and its detached signature: 12 + 64 + (19 * 6) = 190.
	allSelectorSourceFiles = 190
	allSelectorViewEntries = allSelectorPhysicalLeaves * 2
	// Asset entries remain in canonical views but are not package memberships
	// in the rebuildable SQLite catalog.
	allSelectorCatalogMemberships = (allSelectorPhysicalLeaves - allSelectorAssetRepoCount) * 2
)

type allSelectorPhysicalFixture struct {
	assetRelative map[string]string
	aptPackages   map[string]map[string]aptrepo.Package
	yumCanonical  map[string]map[string]string
}

type allSelectorTreeSnapshot struct {
	body        []byte
	files       int64
	filesByRepo map[string]int64
	bytesByRepo map[string]int64
}

// TestInitAdoptContentSynthetic33RepoGeneralization proves the
// complete selector universe through the real CLI and parsers. Everything is
// synthetic and local: this is deliberately not evidence about the existing
// Pigsty production tree, buckets, CDN zones, or credentials.
func TestInitAdoptContentSynthetic33RepoGeneralization(t *testing.T) {
	forceAllSelectorLocalOnlyEnvironment(t)
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	selectorPath := filepath.Join("..", "..", "docs", "migration", "fixtures", "selector-matrix.yaml")
	selectorBody, err := os.ReadFile(selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(selectorBody, []byte(".invalid")) {
		t.Fatal("selector fixture lost its local-only .invalid endpoint boundary")
	}
	if err := os.WriteFile(configPath, selectorBody, 0o600); err != nil {
		t.Fatal(err)
	}

	privateKey, generatedPublicKey := writeLegacySigningKey(t, root)
	publicKey := filepath.Join(root, "keys", "pigsty.asc")
	if err := copyAllSelectorFile(generatedPublicKey, publicKey, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	assertAllSelectorFixtureShape(t, cfg)
	rpmInput := decodeLegacyFixture(t,
		filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"),
		filepath.Join(t.TempDir(), "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm"),
	)
	physical := buildAllSelectorPhysicalTree(t, cfg, privateKey, rpmInput)
	before := snapshotAllSelectorTree(t, cfg)
	if before.files != allSelectorSourceFiles {
		t.Fatalf("all-selector source files=%d want=%d", before.files, allSelectorSourceFiles)
	}

	// Multi-path YUM manifest scanning may create its bounded scratch path in
	// .sow/tmp. Remove every derived SOW path so the acceptance starts from the
	// exact pre-SOW, zero-rewrite migration shape.
	removeAllSelectorDerivedState(t, root)
	run := legacyCLIRunner()
	code, stdout, stderr := run("init", "--adopt-content", "--view", "latest,stable", "--config", configPath, "--workers", "4", "--chunk-entries", "3")
	if code != ExitOK || !strings.Contains(stdout, "repos=33") ||
		!strings.Contains(stdout, "payloads=53") || !strings.Contains(stdout, "leaves=146") ||
		!strings.Contains(stdout, "receipts=53") || !strings.Contains(stdout, "serving_tree_rewritten=false") {
		t.Fatalf("all-selector adoption code=%d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	after := snapshotAllSelectorTree(t, cfg)
	assertAllSelectorSourceUnchanged(t, before, after, "adoption")

	wantStats := catalog.Stats{Files: allSelectorSourceFiles, Packages: 23, Memberships: allSelectorCatalogMemberships, Relations: 8, Provenance: allSelectorPayloads}
	head, stats := assertAllSelectorCanonicalClosure(t, cfg, before, wantStats)
	if code, fsckOut, fsckErr := run("fsck", "--config", configPath, "--workers", "4", "--chunk-entries", "3"); code != ExitOK || strings.Count(fsckOut, "fsck repo=") != allSelectorRepoCount {
		t.Fatalf("all-selector fsck code=%d repo_lines=%d\nstdout:\n%s\nstderr:\n%s", code, strings.Count(fsckOut, "fsck repo="), fsckOut, fsckErr)
	}

	code, replayOut, replayErr := run("init", "--adopt-content", "--view", "latest,stable", "--config", configPath, "--workers", "3", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(replayOut, "changed=false") || !strings.Contains(replayOut, "payloads=53") {
		t.Fatalf("all-selector replay code=%d\nstdout:\n%s\nstderr:\n%s", code, replayOut, replayErr)
	}
	canonical := state.New(cfg.StatePath())
	replayedHead, err := canonical.HeadHash()
	if err != nil || replayedHead != head {
		t.Fatalf("idempotent all-selector replay head=%s want=%s err=%v", replayedHead, head, err)
	}
	replayedStats, err := catalog.Statistics(t.Context(), cfg.StatePath())
	if err != nil || replayedStats != stats {
		t.Fatalf("idempotent all-selector replay stats=%+v want=%+v err=%v", replayedStats, stats, err)
	}
	assertAllSelectorSourceUnchanged(t, before, snapshotAllSelectorTree(t, cfg), "idempotent replay")

	// SQLite is only a projection. Delete it, rebuild from canonical Git, and
	// require byte-independent row counts plus the exact canonical HEAD.
	if err := os.Remove(catalog.Path(cfg.StatePath())); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Rebuild(cfg.StatePath()); err != nil {
		t.Fatal(err)
	}
	rebuiltStats, err := catalog.Statistics(t.Context(), cfg.StatePath())
	if err != nil || rebuiltStats != stats {
		t.Fatalf("rebuilt all-selector catalog=%+v want=%+v err=%v", rebuiltStats, stats, err)
	}
	rebuiltHead, err := catalog.CanonicalHead(t.Context(), cfg.StatePath())
	if err != nil || rebuiltHead != head {
		t.Fatalf("rebuilt all-selector catalog head=%s want=%s err=%v", rebuiltHead, head, err)
	}

	candidateName := "all-selector-migration-candidate"
	code, materializeOut, materializeErr := run("materialize", "latest", "--config", configPath,
		"--target", candidateName, "--serving-base-url", "https://migration.example.invalid",
		"--gpg-private-key-file", privateKey, "--workers", "4", "--chunk-entries", "3")
	if code != ExitOK {
		t.Fatalf("all-selector materialize code=%d\nstdout:\n%s\nstderr:\n%s", code, materializeOut, materializeErr)
	}
	candidateRoot := filepath.Join(root, candidateName)
	assertAllSelectorCandidate(t, cfg, physical, candidateRoot, publicKey)
	assertAllSelectorSourceUnchanged(t, before, snapshotAllSelectorTree(t, cfg), "candidate materialization")

	// Exercise the cutover/rollback shape without touching a real origin. A
	// candidate payload is removed, product fsck must detect the drift, the
	// synthetic serving symlink is atomically returned to the untouched legacy
	// root, and the same rollback is safely replayed.
	candidateConfig := filepath.Join(candidateRoot, "sow.yaml")
	if err := os.WriteFile(candidateConfig, selectorBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, baselineOut, baselineErr := run("init", "--config", candidateConfig, "--repo", "asset-bin", "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("candidate product baseline code=%d\nstdout:\n%s\nstderr:\n%s", code, baselineOut, baselineErr)
	}
	switchRoot := t.TempDir()
	serving := filepath.Join(switchRoot, "serving")
	if err := replaceAllSelectorServingLink(serving, candidateRoot); err != nil {
		t.Fatal(err)
	}
	probeRepo, _ := cfg.RepoByName("asset-bin")
	probe := filepath.Join(serving, filepath.FromSlash(probeRepo.Path), physical.assetRelative[probeRepo.ID])
	if _, err := os.Stat(probe); err != nil {
		t.Fatalf("synthetic cutover asset probe: %v", err)
	}
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}
	if code, driftOut, driftErr := run("fsck", "--config", candidateConfig, "--repo", "asset-bin", "--limit", "10"); code != ExitVerification || !strings.Contains(driftOut, "removed=1") {
		t.Fatalf("candidate product drift detection code=%d\nstdout:\n%s\nstderr:\n%s", code, driftOut, driftErr)
	}
	if err := replaceAllSelectorServingLink(serving, root); err != nil {
		t.Fatal(err)
	}
	failedCandidate := filepath.Join(switchRoot, "failed-candidate")
	if err := os.Rename(candidateRoot, failedCandidate); err != nil {
		t.Fatal(err)
	}
	if err := replaceAllSelectorServingLink(serving, root); err != nil {
		t.Fatalf("idempotent synthetic rollback: %v", err)
	}
	resolvedServing, err := filepath.EvalSymlinks(serving)
	resolvedRoot, rootErr := filepath.EvalSymlinks(root)
	if err != nil || rootErr != nil || resolvedServing != resolvedRoot {
		t.Fatalf("synthetic rollback target=%q want=%q err=%v root_err=%v", resolvedServing, resolvedRoot, err, rootErr)
	}
	assertAllSelectorSourceUnchanged(t, before, snapshotAllSelectorTree(t, cfg), "rollback")
}

func TestLegacyEL7CLIPolicyRejectsUnsafeConfigurations(t *testing.T) {
	forceAllSelectorLocalOnlyEnvironment(t)
	for _, test := range []struct {
		name        string
		major       int
		lifecycle   string
		compression string
		yumExtra    string
		want        string
	}{
		{name: "active EL7", major: 7, lifecycle: "active", compression: "gzip", want: "legacy EL7"},
		{name: "EL7 zstd", major: 7, lifecycle: "frozen", compression: "zstd", want: "legacy EL7"},
		{name: "EL6", major: 6, lifecycle: "frozen", compression: "gzip", want: "only legacy frozen EL7"},
		{name: "modulemd field", major: 7, lifecycle: "frozen", compression: "gzip", yumExtra: ", modulemd: true", want: "field modulemd not found"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "sow.yaml")
			body := fmt.Sprintf(`schema: sow/v1
state: {}
gpg: {}
pools: {public: {}, gated: {}}
repos:
  - id: legacy-el
    type: yum
    path: yum/legacy-el
    os: {family: el, major: %d, lifecycle: %s}
    arches: [x86_64]
    default_pool: public
    yum: {compression: %s, package_keyring: package-trust.asc%s}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://synthetic-local-only}
`, test.major, test.lifecycle, test.compression, test.yumExtra)
			if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := legacyCLIRunner()("init", "--config", configPath)
			if code != ExitConfig || !strings.Contains(stderr, test.want) {
				t.Fatalf("unsafe EL CLI policy code=%d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			for _, derived := range []string{config.StateDirectory, config.PoolDirectory} {
				if _, err := os.Lstat(filepath.Join(root, derived)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("rejected configuration created %s: %v", derived, err)
				}
			}
		})
	}
}

func forceAllSelectorLocalOnlyEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, "http://127.0.0.1:1")
	}
	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		t.Setenv(name, "")
	}
	for _, name := range []string{
		"SOW_RUN_REAL_CLOUD", "SOW_RUN_REAL_EDGE_EVIDENCE", "SOW_RUN_REAL_UPSTREAM",
		"SOW_REAL_CLOUD_PURGE_WATCHER_HELPER", "SOW_LOCAL_PURGE_WATCHER_HELPER",
	} {
		t.Setenv(name, "0")
	}
	// A developer shell may contain live provider credentials. Clear every
	// provider, raw-log, verifier, and legacy compatibility credential even
	// though this synthetic test has no publish or remote command.
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"CLOUDFLARE_API_TOKEN", "TENCENT_SECRET_ID", "TENCENT_SECRET_KEY",
		"SOW_COS_SECRET_ID", "SOW_COS_SECRET_KEY", "SOW_TOKEN_VERIFIER_BEARER",
		"SOW_REAL_CF_CDN_JSON", "SOW_REAL_CF_STORAGE_JSON", "SOW_REAL_CF_LOG_STORAGE_JSON", "SOW_REAL_CF_LOG_WRITER_JSON",
		"SOW_REAL_COS_CDN_JSON", "SOW_REAL_COS_STORAGE_JSON", "SOW_REAL_COS_LOG_STORAGE_JSON", "SOW_REAL_COS_LOG_WRITER_JSON",
		"SOW_REAL_CLOUD_PROVIDER_ATTESTATION_JSON", "SOW_REAL_CLOUD_TEST_RESOURCE_ALLOWLIST_JSON",
		"SOW_REAL_EDGE_ACTIVE_OBSERVATIONS_JSONL", "SOW_REAL_EDGE_OBSERVERS_JSON", "SOW_REAL_EDGE_PROVIDER_LOG_JSONL",
		"SOW_REAL_EDGE_PRO_TOKEN_A", "SOW_REAL_EDGE_PRO_TOKEN_B", "SOW_ORIGIN_BEARER",
	} {
		t.Setenv(name, "")
	}
}

func assertAllSelectorFixtureShape(t *testing.T, cfg *config.Config) {
	t.Helper()
	counts := map[string]int{"asset": 0, "apt": 0, "yum": 0}
	leaves := 0
	for _, repo := range cfg.Repos {
		counts[repo.Type]++
		leaves += len(legacyRepoLeaves(repo))
		if repo.Type == "yum" && (repo.YUM == nil || repo.YUM.PackageKeyring != "package-trust.asc") {
			t.Fatalf("selector YUM repo %s package trust=%q", repo.ID, repo.YUM.PackageKeyring)
		}
	}
	if len(cfg.Repos) != allSelectorRepoCount || counts["asset"] != allSelectorAssetRepoCount ||
		counts["apt"] != allSelectorAPTRepoCount || counts["yum"] != allSelectorYUMRepoCount || leaves != allSelectorPhysicalLeaves {
		t.Fatalf("selector shape repos=%d types=%v leaves=%d", len(cfg.Repos), counts, leaves)
	}
}

func buildAllSelectorPhysicalTree(t *testing.T, cfg *config.Config, privateKey, rpmInput string) allSelectorPhysicalFixture {
	t.Helper()
	fixture := allSelectorPhysicalFixture{
		assetRelative: make(map[string]string, allSelectorAssetRepoCount),
		aptPackages:   make(map[string]map[string]aptrepo.Package, allSelectorAPTRepoCount),
		yumCanonical:  make(map[string]map[string]string, allSelectorYUMRepoCount),
	}
	for _, repo := range sortedAllSelectorRepos(cfg.Repos) {
		switch repo.Type {
		case "asset":
			relative := "fixture-" + repo.ID + ".txt"
			body := []byte("sow all-selector synthetic asset " + repo.ID + "\n")
			path := filepath.Join(cfg.Root, filepath.FromSlash(repo.Path), relative)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0o644); err != nil {
				t.Fatal(err)
			}
			fixture.assetRelative[repo.ID] = relative
		case "apt":
			packages := make(map[string]aptrepo.Package, len(repo.Arches))
			for _, arch := range repo.Arches {
				input := writeSyncMinimalDEB(t, t.TempDir(), "sow-selector-"+repo.ID, "1.0-1", arch)
				pkg, err := aptrepo.InspectPackage(t.Context(), input, "main")
				if err != nil {
					t.Fatal(err)
				}
				destination := filepath.Join(cfg.Root, filepath.FromSlash(repo.Path), filepath.FromSlash(pkg.PoolPath))
				if err := copyAllSelectorFile(input, destination, 0o644); err != nil {
					t.Fatal(err)
				}
				packages[arch] = pkg
			}
			for _, suite := range repo.APT.Suites {
				for _, arch := range repo.Arches {
					indexPath := filepath.Join(cfg.Root, filepath.FromSlash(repo.Path), "dists", suite, "main", "binary-"+arch, "Packages")
					if err := os.MkdirAll(filepath.Dir(indexPath), 0o755); err != nil {
						t.Fatal(err)
					}
					index, err := os.OpenFile(indexPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
					if err != nil {
						t.Fatal(err)
					}
					writeErr := aptrepo.WritePackages(index, []aptrepo.Package{packages[arch]})
					closeErr := index.Close()
					if writeErr != nil || closeErr != nil {
						t.Fatal(errors.Join(writeErr, closeErr))
					}
				}
			}
			fixture.aptPackages[repo.ID] = packages
		case "yum":
			canonical := make(map[string]string, len(repo.Arches))
			for _, arch := range repo.Arches {
				effective, err := repo.PathForArch(arch)
				if err != nil {
					t.Fatal(err)
				}
				flat, destination := writeAllSelectorFlatYUM(t, repo,
					filepath.Join(cfg.Root, filepath.FromSlash(effective)), rpmInput, privateKey)
				if filepath.Base(flat) != flat || !strings.HasPrefix(destination, "Packages/p/") {
					t.Fatalf("selector YUM %s/%s flat=%q canonical=%q", repo.ID, arch, flat, destination)
				}
				canonical[arch] = destination
			}
			fixture.yumCanonical[repo.ID] = canonical
		default:
			t.Fatalf("unsupported selector repo type %q", repo.Type)
		}
	}
	return fixture
}

// writeAllSelectorFlatYUM models the legacy flat-RPM layout while generating
// complete, compression-correct primary/filelists/other metadata with the
// production generator. Only primary's package href is rewritten to the flat
// source path; repomd checksums and its detached signature are then rebuilt.
func writeAllSelectorFlatYUM(t *testing.T, repo config.Repo, root, rpmInput, privateKey string) (string, string) {
	t.Helper()
	const flat = "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm"
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(root, flat)
	if err := copyAllSelectorFile(rpmInput, packagePath, 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: packagePath, Basename: flat})
	if err != nil {
		t.Fatal(err)
	}
	keyBody, err := os.ReadFile(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(keyBody), nil, time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	options := yumrepo.Options{
		ELMajor:     repo.OS.Major,
		Frozen:      repo.OS.Lifecycle == "frozen",
		Compression: yumrepo.Compression(repo.YUM.Compression),
		Revision:    1_752_448_000,
		Signer:      signer,
	}
	compression, err := yumrepo.CompressionForOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	repodata := filepath.Join(root, "repodata")
	generation, err := yumrepo.Generate(t.Context(), repodata, options, &yumrepo.SliceIterator{Inputs: []yumrepo.PackageInput{{
		Path: packagePath, Basename: flat, FileTime: time.Unix(options.Revision, 0).UTC(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	patchAllSelectorFlatPrimary(t, generation, compression, info.Location, flat)
	writeAllSelectorRepomd(t, generation, signer)
	return flat, info.Location
}

func patchAllSelectorFlatPrimary(t *testing.T, generation *yumrepo.Generation, compression yumrepo.Compression, canonical, flat string) {
	t.Helper()
	for index := range generation.Artifacts {
		artifact := &generation.Artifacts[index]
		if artifact.Type != "primary" {
			continue
		}
		oldPath := filepath.Join(generation.Dir, filepath.Base(artifact.Path))
		compressed, err := os.ReadFile(oldPath)
		if err != nil {
			t.Fatal(err)
		}
		raw := decompressAllSelectorMetadata(t, compressed, compression)
		old := []byte(`location href="` + canonical + `"`)
		replacement := []byte(`location href="` + flat + `"`)
		if bytes.Count(raw, old) != 1 {
			t.Fatalf("primary canonical href count=%d want=1", bytes.Count(raw, old))
		}
		raw = bytes.Replace(raw, old, replacement, 1)
		compressed = compressAllSelectorMetadata(t, raw, compression)
		compressedSHA, openSHA := sha256.Sum256(compressed), sha256.Sum256(raw)
		extension := ".gz"
		if compression == yumrepo.CompressionZstd {
			extension = ".zst"
		}
		name := hex.EncodeToString(compressedSHA[:]) + "-primary.xml" + extension
		newPath := filepath.Join(generation.Dir, name)
		if err := os.WriteFile(newPath, compressed, 0o644); err != nil {
			t.Fatal(err)
		}
		if newPath != oldPath {
			if err := os.Remove(oldPath); err != nil {
				t.Fatal(err)
			}
		}
		artifact.Path = "repodata/" + name
		artifact.SHA256 = hex.EncodeToString(compressedSHA[:])
		artifact.OpenSHA256 = hex.EncodeToString(openSHA[:])
		artifact.Size = int64(len(compressed))
		artifact.OpenSize = int64(len(raw))
		return
	}
	t.Fatal("generated repodata lacks primary artifact")
}

func decompressAllSelectorMetadata(t *testing.T, body []byte, compression yumrepo.Compression) []byte {
	t.Helper()
	var reader io.ReadCloser
	switch compression {
	case yumrepo.CompressionGzip:
		value, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		reader = value
	case yumrepo.CompressionZstd:
		value, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		reader = value.IOReadCloser()
	default:
		t.Fatalf("unsupported synthetic YUM compression %q", compression)
	}
	result, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	return result
}

func compressAllSelectorMetadata(t *testing.T, body []byte, compression yumrepo.Compression) []byte {
	t.Helper()
	var result bytes.Buffer
	switch compression {
	case yumrepo.CompressionGzip:
		writer, err := gzip.NewWriterLevel(&result, gzip.DefaultCompression)
		if err != nil {
			t.Fatal(err)
		}
		writer.Header.ModTime = time.Unix(0, 0).UTC()
		writer.Header.OS = 255
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	case yumrepo.CompressionZstd:
		writer, err := zstd.NewWriter(&result, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderCRC(true), zstd.WithWindowSize(8<<20))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported synthetic YUM compression %q", compression)
	}
	return result.Bytes()
}

func writeAllSelectorRepomd(t *testing.T, generation *yumrepo.Generation, signer yumrepo.DetachedSigner) {
	t.Helper()
	var body bytes.Buffer
	fmt.Fprintf(&body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<repomd xmlns=\"http://linux.duke.edu/metadata/repo\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\">\n  <revision>%d</revision>\n", generation.Revision)
	for _, artifact := range generation.Artifacts {
		fmt.Fprintf(&body, "  <data type=\"%s\">\n    <checksum type=\"sha256\">%s</checksum>\n    <open-checksum type=\"sha256\">%s</open-checksum>\n    <location href=\"%s\"/>\n    <timestamp>%d</timestamp>\n    <size>%d</size>\n    <open-size>%d</open-size>\n  </data>\n", artifact.Type, artifact.SHA256, artifact.OpenSHA256, artifact.Path, artifact.Timestamp, artifact.Size, artifact.OpenSize)
	}
	body.WriteString("</repomd>\n")
	repomd := filepath.Join(generation.Dir, "repomd.xml")
	if err := os.WriteFile(repomd, body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	var signature bytes.Buffer
	if err := signer.Sign(t.Context(), bytes.NewReader(body.Bytes()), &signature); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(repomd+".asc", signature.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := signer.Verify(t.Context(), bytes.NewReader(body.Bytes()), bytes.NewReader(signature.Bytes())); err != nil {
		t.Fatal(err)
	}
}

func sortedAllSelectorRepos(repos []config.Repo) []config.Repo {
	result := append([]config.Repo(nil), repos...)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func snapshotAllSelectorTree(t *testing.T, cfg *config.Config) allSelectorTreeSnapshot {
	t.Helper()
	result := allSelectorTreeSnapshot{filesByRepo: make(map[string]int64, len(cfg.Repos)), bytesByRepo: make(map[string]int64, len(cfg.Repos))}
	work := t.TempDir()
	var output bytes.Buffer
	for _, repo := range sortedAllSelectorRepos(cfg.Repos) {
		destination := filepath.Join(work, repo.ID+".tsv")
		stats, err := scanRepoManifest(t.Context(), cfg, repo, destination, manifest.ScanOptions{Workers: 3, ChunkEntries: 3, TempDir: work})
		if err != nil {
			t.Fatalf("scan all-selector repo %s: %v", repo.ID, err)
		}
		body, err := os.ReadFile(destination)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&output, "[%s files=%d bytes=%d]\n", repo.ID, stats.Files, stats.Bytes)
		output.Write(body)
		result.files += stats.Files
		result.filesByRepo[repo.ID] = stats.Files
		result.bytesByRepo[repo.ID] = stats.Bytes
	}
	result.body = output.Bytes()
	return result
}

func removeAllSelectorDerivedState(t *testing.T, root string) {
	t.Helper()
	for _, relative := range []string{".sow", ".pool", "_sow"} {
		path := filepath.Join(root, relative)
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("derived selector path %s survived reset: %v", relative, err)
		}
	}
}

func assertAllSelectorSourceUnchanged(t *testing.T, before, after allSelectorTreeSnapshot, phase string) {
	t.Helper()
	if before.files != after.files || !bytes.Equal(before.body, after.body) {
		t.Fatalf("all-selector source tree changed during %s files=%d/%d\nbefore:\n%s\nafter:\n%s", phase, before.files, after.files, before.body, after.body)
	}
}

func assertAllSelectorCanonicalClosure(t *testing.T, cfg *config.Config, source allSelectorTreeSnapshot, wantStats catalog.Stats) (plumbing.Hash, catalog.Stats) {
	t.Helper()
	canonical := state.New(cfg.StatePath())
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		t.Fatalf("all-selector canonical head=%s err=%v", head, err)
	}
	viewMemberships := int64(0)
	for _, repo := range sortedAllSelectorRepos(cfg.Repos) {
		repoRef, err := state.RepoRef(repo.ID)
		if err != nil {
			t.Fatal(err)
		}
		repoCommit, exists, err := canonical.Ref(repoRef)
		if err != nil || !exists {
			t.Fatalf("all-selector repo ref %s exists=%t err=%v", repoRef, exists, err)
		}
		manifestPath := filepath.ToSlash(filepath.Join("manifests", repo.ID+".tsv"))
		baseline, err := canonical.OpenPathAt(repoCommit, manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		count, countErr := countAllSelectorManifest(baseline)
		closeErr := baseline.Close()
		if countErr != nil || closeErr != nil || count != source.filesByRepo[repo.ID] {
			t.Fatalf("all-selector manifest %s entries=%d want=%d err=%v", repo.ID, count, source.filesByRepo[repo.ID], errors.Join(countErr, closeErr))
		}
		for _, viewName := range []string{"latest", "stable"} {
			for _, leaf := range legacyRepoLeaves(repo) {
				ref, _ := state.ViewRef(viewName, repo.ID, leaf.os, leaf.arch)
				commit, exists, err := canonical.Ref(ref)
				if err != nil || !exists || commit != head {
					t.Fatalf("all-selector view ref %s exists=%t commit=%s head=%s err=%v", ref, exists, commit, head, err)
				}
				viewPath, _ := state.ViewPath(viewName, repo.ID, leaf.os, leaf.arch)
				body, err := canonical.OpenPathAt(commit, viewPath)
				if err != nil {
					t.Fatal(err)
				}
				reader := views.NewReader(body)
				entry, firstErr := reader.Next()
				_, secondErr := reader.Next()
				closeErr := body.Close()
				if firstErr != nil || !errors.Is(secondErr, io.EOF) || closeErr != nil || entry.Repo != repo.ID || entry.OS != leaf.os || entry.Arch != leaf.arch {
					t.Fatalf("all-selector view %s/%s/%s/%s entry=%+v first=%v second=%v close=%v", viewName, repo.ID, leaf.os, leaf.arch, entry, firstErr, secondErr, closeErr)
				}
				viewMemberships++
			}
		}
	}
	if viewMemberships != allSelectorViewEntries {
		t.Fatalf("all-selector view entries=%d want=%d", viewMemberships, allSelectorViewEntries)
	}

	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		t.Fatal(err)
	}
	receipts, remapped := int64(0), int64(0)
	for _, repo := range sortedAllSelectorRepos(cfg.Repos) {
		ledger, err := canonical.OpenPath(filepath.ToSlash(filepath.Join("provenance", "legacy", repo.ID+".jsonl")))
		if err != nil {
			t.Fatal(err)
		}
		reader := provenance.NewLegacyAdoptionReader(ledger)
		for {
			receipt, err := reader.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil || receipt.Repo != repo.ID {
				t.Fatalf("all-selector receipt repo=%s receipt=%+v err=%v", repo.ID, receipt, err)
			}
			digest, err := repository.ParseDigest(receipt.ArtifactSHA256)
			if err != nil {
				t.Fatal(err)
			}
			if err := pool.Verify(t.Context(), repository.Object{SHA256: digest, Size: receipt.ArtifactSize}); err != nil {
				t.Fatalf("all-selector CAS %s: %v", receipt.SourcePath, err)
			}
			if receipt.SourcePath != receipt.CanonicalPath {
				if receipt.Format != "rpm" {
					t.Fatalf("non-RPM selector receipt remapped %s -> %s", receipt.SourcePath, receipt.CanonicalPath)
				}
				remapped++
			}
			receipts++
		}
		if err := ledger.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if receipts != allSelectorPayloads || remapped != 19 {
		t.Fatalf("all-selector receipts=%d remapped-yum=%d", receipts, remapped)
	}
	stats, err := catalog.Statistics(t.Context(), cfg.StatePath())
	if err != nil || stats != wantStats {
		t.Fatalf("all-selector catalog=%+v want=%+v err=%v", stats, wantStats, err)
	}
	cacheHead, err := catalog.CanonicalHead(t.Context(), cfg.StatePath())
	if err != nil || cacheHead != head {
		t.Fatalf("all-selector catalog head=%s want=%s err=%v", cacheHead, head, err)
	}
	return head, stats
}

func countAllSelectorManifest(reader io.Reader) (int64, error) {
	stream := manifest.NewReader(reader)
	var count int64
	for {
		_, err := stream.Next()
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		count++
	}
}

func assertAllSelectorCandidate(t *testing.T, cfg *config.Config, physical allSelectorPhysicalFixture, candidateRoot, publicKey string) {
	t.Helper()
	publicBody, err := os.ReadFile(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := openpgp.ReadKeyRing(bytes.NewReader(publicBody))
	if err != nil {
		t.Fatal(err)
	}
	yumVerifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(publicBody), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, repo := range sortedAllSelectorRepos(cfg.Repos) {
		switch repo.Type {
		case "asset":
			path := filepath.Join(candidateRoot, filepath.FromSlash(repo.Path), physical.assetRelative[repo.ID])
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("all-selector candidate asset %s: %v", repo.ID, err)
			}
		case "apt":
			for _, suite := range repo.APT.Suites {
				suiteRoot := filepath.Join(candidateRoot, filepath.FromSlash(repo.Path), "dists", suite)
				assertAllSelectorAPTSignatures(t, suiteRoot, keyring)
				for _, arch := range repo.Arches {
					indexRoot := filepath.Join(suiteRoot, "main", "binary-"+arch)
					packages, err := os.ReadFile(filepath.Join(indexRoot, "Packages"))
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Contains(packages, []byte("Package: "+physical.aptPackages[repo.ID][arch].Name+"\n")) {
						t.Fatalf("all-selector candidate APT %s/%s/%s lacks real package", repo.ID, suite, arch)
					}
					digest := sha256.Sum256(packages)
					byHash := filepath.Join(indexRoot, "by-hash", "SHA256", hex.EncodeToString(digest[:]))
					byHashBody, err := os.ReadFile(byHash)
					if err != nil || !bytes.Equal(byHashBody, packages) {
						t.Fatalf("all-selector candidate APT by-hash %s/%s/%s err=%v", repo.ID, suite, arch, err)
					}
				}
			}
			for _, pkg := range physical.aptPackages[repo.ID] {
				if _, err := os.Stat(filepath.Join(candidateRoot, filepath.FromSlash(repo.Path), filepath.FromSlash(pkg.PoolPath))); err != nil {
					t.Fatalf("all-selector candidate APT pool %s/%s: %v", repo.ID, pkg.PoolPath, err)
				}
			}
		case "yum":
			compression := yumrepo.CompressionZstd
			if repo.YUM.Compression == string(yumrepo.CompressionGzip) {
				compression = yumrepo.CompressionGzip
			}
			for _, arch := range repo.Arches {
				effective, _ := repo.PathForArch(arch)
				root := filepath.Join(candidateRoot, filepath.FromSlash(effective))
				generation, err := yumrepo.ValidateDirectory(t.Context(), filepath.Join(root, "repodata"), compression, yumVerifier)
				if err != nil || generation.Packages != 1 {
					t.Fatalf("all-selector candidate YUM %s/%s generation=%+v err=%v", repo.ID, arch, generation, err)
				}
				if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(physical.yumCanonical[repo.ID][arch]))); err != nil {
					t.Fatalf("all-selector candidate canonical RPM %s/%s: %v", repo.ID, arch, err)
				}
				flat := filepath.Join(root, "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm")
				if _, err := os.Stat(flat); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("all-selector flat RPM leaked into candidate %s/%s: %v", repo.ID, arch, err)
				}
			}
		}
	}
}

func assertAllSelectorAPTSignatures(t *testing.T, suiteRoot string, keyring openpgp.EntityList) {
	t.Helper()
	release, err := os.ReadFile(filepath.Join(suiteRoot, "Release"))
	if err != nil {
		t.Fatal(err)
	}
	inRelease, err := os.ReadFile(filepath.Join(suiteRoot, "InRelease"))
	if err != nil {
		t.Fatal(err)
	}
	detached, err := os.ReadFile(filepath.Join(suiteRoot, "Release.gpg"))
	if err != nil {
		t.Fatal(err)
	}
	block, rest := clearsign.Decode(inRelease)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(block.Plaintext, release) {
		t.Fatalf("all-selector candidate InRelease is malformed at %s", suiteRoot)
	}
	verifyAt := time.Now().UTC().Add(time.Minute)
	verifyConfig := &packet.Config{Time: func() time.Time { return verifyAt }}
	if _, err := block.VerifySignature(keyring, verifyConfig); err != nil {
		t.Fatalf("all-selector candidate InRelease signature %s: %v", suiteRoot, err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(release), bytes.NewReader(detached), verifyConfig); err != nil {
		t.Fatalf("all-selector candidate Release.gpg %s: %v", suiteRoot, err)
	}
}

func copyAllSelectorFile(source, destination string, mode os.FileMode) error {
	body, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	return os.WriteFile(destination, body, mode)
}

func replaceAllSelectorServingLink(link, target string) error {
	directory := filepath.Dir(link)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(link)+".next-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return err
	}
	installed := false
	defer func() {
		if !installed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := os.Symlink(target, temporaryPath); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, link); err != nil {
		return err
	}
	installed = true
	return syncLocalDirectory(directory)
}
