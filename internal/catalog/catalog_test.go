package catalog

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

func TestRebuildIsDisposableAndEquivalent(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	stageDir := t.TempDir()
	data := "asset/a\t1\tca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\nasset/b\t1\t3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d\n"
	manifestPath := filepath.Join(stageDir, "asset.tsv")
	if err := os.WriteFile(manifestPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(stateDir)
	commit, changed, err := canonical.InstallPaths(map[string]string{
		"manifests/asset.tsv": manifestPath,
		"config/sow.yaml":     filepath.Join("..", "..", "sow.example.yaml"),
	}, "catalog fixture")
	if err != nil || !changed {
		t.Fatalf("install canonical fixture changed=%v err=%v", changed, err)
	}
	ref, err := state.RepoRef("asset")
	if err != nil {
		t.Fatal(err)
	}
	if err := canonical.AdvanceRef(ref, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}
	if err := Rebuild(stateDir); err != nil {
		t.Fatal(err)
	}
	cacheHead, err := CanonicalHead(t.Context(), stateDir)
	if err != nil || cacheHead != commit {
		t.Fatalf("cache canonical head=%s want=%s err=%v", cacheHead, commit, err)
	}
	count, err := Count(stateDir)
	if err != nil || count != 2 {
		t.Fatalf("first cache count=%d err=%v", count, err)
	}
	if err := os.Remove(Path(stateDir)); err != nil {
		t.Fatal(err)
	}
	if err := Rebuild(stateDir); err != nil {
		t.Fatal(err)
	}
	count, err = Count(stateDir)
	if err != nil || count != 2 {
		t.Fatalf("rebuilt cache count=%d err=%v", count, err)
	}
}

func TestLegacyProvenanceProjectionStreamsExactCanonicalRows(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	stageDir := t.TempDir()
	observed := time.Date(2026, 7, 18, 12, 0, 0, 123, time.UTC)
	receipts := []provenance.LegacyAdoptionReceipt{
		{Schema: provenance.LegacyAdoptionSchema, Format: "asset", Repo: "assets-bin", SourcePath: "pkg/a.bin", CanonicalPath: "pkg/a.bin", ArtifactSize: 1, ArtifactSHA256: strings.Repeat("a", 64), Pool: "public", AdoptedAt: observed, ConfigCommit: strings.Repeat("1", 40)},
		{Schema: provenance.LegacyAdoptionSchema, Format: "asset", Repo: "assets-bin", SourcePath: "pkg/b.bin", CanonicalPath: "pkg/b.bin", ArtifactSize: 2, ArtifactSHA256: strings.Repeat("b", 64), Pool: "public", AdoptedAt: observed.Add(time.Second), ConfigCommit: strings.Repeat("2", 40)},
	}
	var ledger bytes.Buffer
	for _, receipt := range receipts {
		if err := provenance.WriteLegacyAdoption(&ledger, receipt); err != nil {
			t.Fatal(err)
		}
	}
	ledgerPath := filepath.Join(stageDir, "legacy.jsonl")
	if err := os.WriteFile(ledgerPath, ledger.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(stateDir)
	if _, changed, err := canonical.InstallPaths(map[string]string{
		"provenance/legacy/assets-bin.jsonl": ledgerPath,
		"config/sow.yaml":                    filepath.Join("..", "..", "sow.example.yaml"),
	}, "legacy provenance projection fixture"); err != nil || !changed {
		t.Fatalf("install legacy provenance fixture changed=%t err=%v", changed, err)
	}
	if err := Rebuild(stateDir); err != nil {
		t.Fatal(err)
	}
	stream, err := OpenLegacyProvenanceProjection(t.Context(), stateDir, "assets-bin")
	if err != nil {
		t.Fatal(err)
	}
	for index, receipt := range receipts {
		record, err := stream.Next()
		if err != nil {
			t.Fatalf("read projected receipt %d: %v", index, err)
		}
		body, err := receipt.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		identity := sha256.Sum256(body)
		if record.ReceiptID != fmt.Sprintf("%x", identity[:]) || record.ArtifactSHA256 != receipt.ArtifactSHA256 ||
			record.Format != receipt.Format || record.Kind != "legacy" || record.Repo != receipt.Repo ||
			record.SourcePath != receipt.SourcePath || record.Pool != receipt.Pool || record.UpstreamURL != "" ||
			record.ObservedAt != receipt.AdoptedAt.Format("2006-01-02T15:04:05.999999999Z") {
			t.Fatalf("projected receipt %d differs: %+v", index, record)
		}
	}
	if _, err := stream.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("projected receipt stream did not end: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLegacyProvenanceProjection(t.Context(), stateDir, "unsafe\nrepo"); err == nil {
		t.Fatal("legacy provenance projection accepted an unsafe repository")
	}
}

func TestAdvanceCanonicalHeadIsExactReadOnlyAndProjectionNeutral(t *testing.T) {
	stateDir, _ := installDependencyFixture(t)
	if err := Rebuild(stateDir); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(stateDir)
	baseline, err := canonical.HeadHash()
	if err != nil || baseline.IsZero() {
		t.Fatalf("baseline head=%s err=%v", baseline, err)
	}
	before, err := Statistics(t.Context(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	stageDir, err := os.MkdirTemp(stateDir, "catalog-head-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stageDir)
	stage := filepath.Join(stageDir, "neutral.json")
	if err := os.WriteFile(stage, []byte("{\"serving\":\"ledger\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	next, changed, err := canonical.Apply(t.Context(), "catalog-head-test", "test: projection-neutral canonical state", map[string]string{
		"serving/test/ledger.json": stage,
	}, nil, state.ApplyOptions{})
	if err != nil || !changed {
		t.Fatalf("neutral commit=%s changed=%t err=%v", next, changed, err)
	}
	if err := AdvanceCanonicalHead(t.Context(), stateDir, baseline, next); err != nil {
		t.Fatal(err)
	}
	cacheHead, err := CanonicalHead(t.Context(), stateDir)
	if err != nil || cacheHead != next {
		t.Fatalf("advanced cache head=%s want=%s err=%v", cacheHead, next, err)
	}
	after, err := Statistics(t.Context(), stateDir)
	if err != nil || after != before {
		t.Fatalf("projection changed during head-only advance before=%+v after=%+v err=%v", before, after, err)
	}
	info, err := os.Stat(Path(stateDir))
	if err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("advanced cache mode=%v err=%v", info.Mode().Perm(), err)
	}

	if err := os.WriteFile(stage, []byte("{\"serving\":\"ledger-2\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	third, changed, err := canonical.Apply(t.Context(), "catalog-head-test", "test: second projection-neutral canonical state", map[string]string{
		"serving/test/ledger.json": stage,
	}, nil, state.ApplyOptions{})
	if err != nil || !changed {
		t.Fatalf("second neutral commit=%s changed=%t err=%v", third, changed, err)
	}
	wrong := plumbing.NewHash(strings.Repeat("f", 40))
	if err := AdvanceCanonicalHead(t.Context(), stateDir, wrong, third); err == nil {
		t.Fatal("head advance accepted a mismatched expected cache identity")
	}
	cacheHead, err = CanonicalHead(t.Context(), stateDir)
	if err != nil || cacheHead != next {
		t.Fatalf("failed compare-and-set changed cache head=%s want=%s err=%v", cacheHead, next, err)
	}
	if err := AdvanceCanonicalHead(t.Context(), stateDir, next, third); err != nil {
		t.Fatal(err)
	}
	if err := AdvanceCanonicalHead(t.Context(), stateDir, next, third); err != nil {
		t.Fatalf("idempotent head advance: %v", err)
	}
}

func TestAdvanceCanonicalHeadFailsClosedAndRestoresReadOnlyMode(t *testing.T) {
	stateDir, _ := installDependencyFixture(t)
	if err := Rebuild(stateDir); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(stateDir)
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		t.Fatalf("canonical head=%s err=%v", head, err)
	}
	wrong := plumbing.NewHash(strings.Repeat("f", 40))
	if err := AdvanceCanonicalHead(t.Context(), stateDir, wrong, head); err != nil {
		t.Fatalf("idempotent current head must remain accepted: %v", err)
	}
	if info, err := os.Stat(Path(stateDir)); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("idempotent cache mode=%v err=%v", info.Mode().Perm(), err)
	}

	if err := os.Chmod(Path(stateDir), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", Path(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	_, updateErr := db.Exec(`UPDATE meta SET value='999' WHERE key='schema_version'`)
	closeErr := db.Close()
	if updateErr != nil || closeErr != nil {
		t.Fatalf("inject schema mismatch: %v / %v", updateErr, closeErr)
	}
	if err := AdvanceCanonicalHead(t.Context(), stateDir, head, wrong); err == nil || !strings.Contains(err.Error(), "cache schema") {
		t.Fatalf("schema mismatch accepted: %v", err)
	}
	if info, err := os.Stat(Path(stateDir)); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("failed advance cache mode=%v err=%v", info.Mode().Perm(), err)
	}

	cachePath := Path(stateDir)
	backup := cachePath + ".real"
	if err := os.Rename(cachePath, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backup, cachePath); err != nil {
		t.Fatal(err)
	}
	if err := AdvanceCanonicalHead(t.Context(), stateDir, head, wrong); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink cache accepted: %v", err)
	}
	if info, err := os.Stat(backup); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("symlink rejection changed target mode=%v err=%v", info.Mode().Perm(), err)
	}
}

func TestDependencyClosureUsesCanonicalBodiesHandlesCyclesAndVersions(t *testing.T) {
	stateDir, scope := installDependencyFixture(t)
	if err := Rebuild(stateDir); err != nil {
		t.Fatal(err)
	}
	stats, err := Statistics(t.Context(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Files != 6 || stats.Packages != 6 || stats.Memberships != 6 || stats.Relations != 6 || stats.Provenance != 1 {
		t.Fatalf("unexpected catalog stats: %+v", stats)
	}
	memberships, err := MembershipCount(t.Context(), stateDir, scope)
	if err != nil || memberships != 6 {
		t.Fatalf("scope memberships=%d err=%v", memberships, err)
	}

	v1, err := DependencyClosure(t.Context(), stateDir, ClosureQuery{Scope: scope, Roots: []PackageSelector{{Name: "app", Version: "1"}}})
	if err != nil {
		t.Fatal(err)
	}
	assertClosurePackages(t, v1, map[string]string{"app": "1", "libfixture": "1", "cycle-a": "1", "cycle-b": "1"})
	if len(v1.Unresolved) != 0 {
		t.Fatalf("v1 unresolved dependencies: %+v", v1.Unresolved)
	}

	latest, err := DependencyClosure(t.Context(), stateDir, ClosureQuery{Scope: scope, Roots: []PackageSelector{{Name: "app"}}})
	if err != nil {
		t.Fatal(err)
	}
	assertClosurePackages(t, latest, map[string]string{"app": "2", "libfixture": "2", "cycle-a": "1", "cycle-b": "1"})
	if len(latest.Provenance) != 1 || latest.Provenance[0].Kind != "upstream" || latest.Provenance[0].ArtifactSHA256 == "" {
		t.Fatalf("latest provenance projection: %+v", latest.Provenance)
	}
	for _, pkg := range latest.Packages {
		if pkg.Name == "app" && pkg.Source != "app-source" {
			t.Fatalf("app source projection = %q", pkg.Source)
		}
	}
	both, err := DependencyClosure(t.Context(), stateDir, ClosureQuery{Scope: scope, Roots: []PackageSelector{{Name: "app", Version: "1"}, {Name: "app", Version: "2"}}})
	if err != nil {
		t.Fatal(err)
	}
	versions := make(map[string]bool)
	for _, pkg := range both.Packages {
		if pkg.Name == "app" || pkg.Name == "libfixture" {
			versions[pkg.Name+"@"+pkg.Version] = true
		}
	}
	for _, wanted := range []string{"app@1", "app@2", "libfixture@1", "libfixture@2"} {
		if !versions[wanted] {
			t.Fatalf("two-root closure lost version boundary %s: %#v", wanted, versions)
		}
	}

	before := latest
	if err := os.Chmod(Path(stateDir), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(stateDir), []byte("corrupt sqlite cache"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Version(t.Context(), stateDir); err == nil {
		t.Fatal("corrupt cache unexpectedly remained queryable")
	}
	if err := Rebuild(stateDir); err != nil {
		t.Fatalf("rebuild corrupt cache: %v", err)
	}
	after, err := DependencyClosure(t.Context(), stateDir, ClosureQuery{Scope: scope, Roots: []PackageSelector{{Name: "app"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("query changed after disposable cache rebuild:\nbefore=%+v\nafter=%+v", before, after)
	}
	info, err := os.Stat(Path(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o444 {
		t.Fatalf("derived cache mode = %o, want 444", info.Mode().Perm())
	}
}

func assertClosurePackages(t *testing.T, result ClosureResult, want map[string]string) {
	t.Helper()
	got := make(map[string]string)
	for _, pkg := range result.Packages {
		if previous, exists := got[pkg.Name]; exists {
			t.Fatalf("closure selected multiple versions of %s: %s and %s", pkg.Name, previous, pkg.Version)
		}
		got[pkg.Name] = pkg.Version
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("closure packages = %#v, want %#v", got, want)
	}
}

func installDependencyFixture(t *testing.T) (string, Scope) {
	t.Helper()
	root := t.TempDir()
	stateDir := filepath.Join(root, ".sow")
	inputDir := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	type fixture struct {
		name, source, version, depends string
	}
	fixtures := []fixture{
		{name: "app", source: "app-source", version: "1", depends: "libfixture (= 1), cycle-a"},
		{name: "app", source: "app-source", version: "2", depends: "libfixture (>= 2), cycle-a"},
		{name: "libfixture", source: "libfixture", version: "1"},
		{name: "libfixture", source: "libfixture", version: "2"},
		{name: "cycle-a", source: "cycle-a", version: "1", depends: "cycle-b"},
		{name: "cycle-b", source: "cycle-b", version: "1", depends: "cycle-a"},
	}
	var entries []views.Entry
	objects := make(map[string]repository.Object)
	for _, value := range fixtures {
		control := fmt.Sprintf("Package: %s\nSource: %s\nVersion: %s\nArchitecture: amd64\nMaintainer: SOW Test <sow@example.invalid>\nSection: utils\nPriority: optional\nDescription: catalog fixture\n", value.name, value.source, value.version)
		if value.depends != "" {
			control += "Depends: " + value.depends + "\n"
		}
		filename := fmt.Sprintf("%s_%s_amd64.deb", value.name, value.version)
		filePath := writeCatalogDEB(t, inputDir, filename, control)
		pkg, err := aptrepo.InspectPackage(t.Context(), filePath, "main")
		if err != nil {
			t.Fatalf("inspect %s: %v", filename, err)
		}
		object, err := pool.Import(t.Context(), filePath)
		if err != nil {
			t.Fatal(err)
		}
		logical := filepath.ToSlash(filepath.Join("apt/pgsql/trixie", pkg.PoolPath))
		entries = append(entries, views.Entry{Repo: "pgsql-trixie-amd64", OS: "trixie", Arch: "amd64", Name: pkg.Name, Version: pkg.Version, Path: logical, Size: object.Size, SHA256: object.HashString(), Pool: "public"})
		objects[pkg.Name+"\x00"+pkg.Version] = object
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	stageDir := t.TempDir()
	viewPath := filepath.Join(stageDir, "latest.tsv")
	viewFile, err := os.Create(viewPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := views.WriteEntry(viewFile, entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := viewFile.Close(); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(stageDir, "repo.tsv")
	manifestFile, err := os.Create(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		digest, err := repository.ParseDigest(entry.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		var hash [32]byte
		copy(hash[:], digest[:])
		if err := manifest.WriteEntry(manifestFile, manifest.Entry{Path: entry.Path, Size: entry.Size, SHA256: hash}); err != nil {
			t.Fatal(err)
		}
	}
	if err := manifestFile.Close(); err != nil {
		t.Fatal(err)
	}
	app2 := objects["app\x002"]
	receipt := provenance.NewDEB(app2.HashString(), app2.Size, "https://upstream.example.invalid/pool/app_2_amd64.deb", time.Unix(1_700_000_000, 0).UTC(), provenance.DEBProof{
		PackagesEntrySHA256: strings.Repeat("a", 64), PackagesEvidenceSHA256: strings.Repeat("b", 64),
		SignedReleaseSHA256: strings.Repeat("c", 64), SignedReleaseKind: "InRelease",
	})
	receiptData, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(stageDir, "receipt.json")
	if err := os.WriteFile(receiptPath, receiptData, 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(stateDir)
	commit, changed, err := canonical.InstallPaths(map[string]string{
		"manifests/pgsql-trixie-amd64.tsv":                 manifestPath,
		"views/latest/pgsql-trixie-amd64/trixie/amd64.tsv": viewPath,
		"provenance/deb/" + app2.HashString() + ".json":    receiptPath,
		"config/sow.yaml": filepath.Join("..", "..", "sow.example.yaml"),
	}, "dependency catalog fixture")
	if err != nil || !changed {
		t.Fatalf("install dependency fixture changed=%v err=%v", changed, err)
	}
	repoRef, _ := state.RepoRef("pgsql-trixie-amd64")
	viewRef, _ := state.ViewRef("latest", "pgsql-trixie-amd64", "trixie", "amd64")
	if err := canonical.AdvanceRef(repoRef, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}
	if err := canonical.AdvanceRef(viewRef, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}
	return stateDir, Scope{Name: "latest", Repo: "pgsql-trixie-amd64", OS: "trixie", Arch: "amd64"}
}

func writeCatalogDEB(t *testing.T, dir, filename, controlText string) string {
	t.Helper()
	controlTar := catalogTarGzip(t, map[string][]byte{"control": []byte(controlText)})
	dataTar := catalogTarGzip(t, map[string][]byte{"usr/share/doc/sow-catalog/README": []byte("fixture\n")})
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	writeCatalogArMember(t, &archive, "debian-binary", []byte("2.0\n"))
	writeCatalogArMember(t, &archive, "control.tar.gz", controlTar)
	writeCatalogArMember(t, &archive, "data.tar.gz", dataTar)
	filePath := filepath.Join(dir, filename)
	if err := os.WriteFile(filePath, archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func catalogTarGzip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, data := range files {
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func writeCatalogArMember(t *testing.T, output *bytes.Buffer, name string, data []byte) {
	t.Helper()
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name+"/", 0, 0, 0, 0o644, len(data))
	if len(header) != 60 {
		t.Fatalf("invalid ar header length %d", len(header))
	}
	output.WriteString(header)
	output.Write(data)
	if len(data)%2 != 0 {
		output.WriteByte('\n')
	}
}
