package cli

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
)

func TestPublicationSelectionScopesRollbackExactReplacesRawBridgeWithS0(t *testing.T) {
	id := "infra-legacy-x86-64"
	rawRoot := "yum/infra/x86_64"
	trustRoot := path.Dir(config.YUMCompatibilityPackageTrustRoute(id))
	prepared := preparedPublication{
		projections: []publicationProjection{{
			repo: config.Repo{ID: "owner", Type: "yum"}, sourceRoot: rawRoot,
			compatibilityID: id, compatibilityRollback: true,
		}},
		compatibilityRollbacks: map[string]pub.CompatibilityState{id: {ID: id, RouteRoot: rawRoot}},
	}
	scopes, err := publicationSelectionScopes(&config.Config{}, prepared, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(scopes.Replace, []string{trustRoot, rawRoot}) || len(scopes.Upsert) != 0 {
		t.Fatalf("rollback scopes=%#v, want exact raw+trust replacement", scopes)
	}

	directory := t.TempDir()
	oldPath := filepath.Join(directory, "old.tsv")
	selectedPath := filepath.Join(directory, "selected.tsv")
	destinationPath := filepath.Join(directory, "desired.tsv")
	candidatePackage := publishManifestEntry(path.Join(rawRoot, "Packages/p/pkg.rpm"), "candidate-package")
	candidateMetadata := publishManifestEntry(path.Join(rawRoot, "repodata/candidate-primary.xml.gz"), "candidate-metadata")
	s0Package := publishManifestEntry(path.Join(rawRoot, "pkg.rpm"), "s0-package")
	s0Metadata := publishManifestEntry(path.Join(rawRoot, "repodata/legacy-primary.xml.gz"), "s0-metadata")
	s0Repomd := publishManifestEntry(path.Join(rawRoot, "repodata/repomd.xml"), "s0-repomd")
	writePublishManifest(t, oldPath,
		publishManifestEntry(config.YUMCompatibilityPackageTrustRoute(id), "package-trust"),
		publishManifestEntry(config.YUMCompatibilityRepositoryTrustRoute(id), "repository-trust"),
		candidatePackage,
		candidateMetadata,
		publishManifestEntry(path.Join(rawRoot, "repodata/repomd.xml"), "candidate-repomd"),
	)
	writePublishManifest(t, selectedPath, s0Package, s0Metadata, s0Repomd)
	if err := ReplaceManifestSelection(oldPath, selectedPath, destinationPath, scopes); err != nil {
		t.Fatal(err)
	}
	if got, want := readPublishManifest(t, destinationPath), []manifest.Entry{s0Package, s0Metadata, s0Repomd}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rollback desired manifest=%#v, want exact S0 %#v", got, want)
	}

	// A later ordinary publication starts from the cumulative rollback
	// manifest. Replacing an unrelated selected YUM leaf must carry the raw
	// S0 bridge forward instead of reclassifying it as stale compatibility data.
	nextSelected := filepath.Join(directory, "next-selected.tsv")
	nextDesired := filepath.Join(directory, "next-desired.tsv")
	ordinaryRoot := "yum/infra/el9/x86_64"
	ordinaryRepomd := publishManifestEntry(path.Join(ordinaryRoot, "repodata/repomd.xml"), "ordinary-repomd")
	writePublishManifest(t, nextSelected, ordinaryRepomd)
	nextPrepared := preparedPublication{projections: []publicationProjection{{
		repo: config.Repo{ID: "infra-el9", Type: "yum"}, sourceRoot: ordinaryRoot,
	}}}
	nextScopes, err := publicationSelectionScopes(&config.Config{}, nextPrepared, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ReplaceManifestSelection(destinationPath, nextSelected, nextDesired, nextScopes); err != nil {
		t.Fatal(err)
	}
	if got, want := readPublishManifest(t, nextDesired), []manifest.Entry{ordinaryRepomd, s0Package, s0Metadata, s0Repomd}; !reflect.DeepEqual(got, want) {
		t.Fatalf("post-rollback cumulative manifest=%#v, want %#v", got, want)
	}
	changed, err := DiffChangedPaths(destinationPath, nextDesired)
	if err != nil {
		t.Fatal(err)
	}
	for _, changedPath := range changed {
		if changedPath == s0Package.Path || changedPath == s0Metadata.Path || changedPath == s0Repomd.Path {
			t.Fatalf("follow-up ordinary diff re-deletes preserved raw route %s", changedPath)
		}
	}
}

func TestFilterAPTPublicationManifestHonorsSuiteWideMetadataAndExactPayloadScope(t *testing.T) {
	directory := t.TempDir()
	scanned := filepath.Join(directory, "scanned.tsv")
	payloads := filepath.Join(directory, "payloads.tsv")
	filtered := filepath.Join(directory, "filtered.tsv")
	prefix := ".sow/materialized/beta/apt/test/"
	writePublishManifest(t, scanned,
		publishManifestEntry(prefix+"dists/bookworm/InRelease", "bookworm-release"),
		publishManifestEntry(prefix+"dists/bookworm/main/binary-arm64/Packages", "bookworm-index"),
		publishManifestEntry(prefix+"dists/jammy/InRelease", "jammy-release"),
		publishManifestEntry(prefix+"dists/jammy/main/binary-amd64/Packages", "jammy-amd64"),
		publishManifestEntry(prefix+"dists/jammy/main/binary-arm64/Packages", "jammy-arm64"),
		publishManifestEntry(prefix+"pool/main/p/selected.deb", "selected"),
		publishManifestEntry(prefix+"pool/main/u/unselected.deb", "unselected"),
	)
	writePublishManifest(t, payloads, publishManifestEntry("apt/test/pool/main/p/selected.deb", "selected"))
	original := config.Repo{ID: "apt", Type: "apt", Path: "apt/test", Arches: []string{"amd64", "arm64"}, APT: &config.APTConfig{Suites: []string{"bookworm", "jammy"}, Components: []string{"main"}}}
	selected := original
	selected.Arches = append([]string(nil), original.Arches...)
	apt := *original.APT
	apt.Suites = []string{"jammy"}
	selected.APT = &apt
	projection := publicationProjection{repo: selected, sourceRoot: ".sow/materialized/beta/apt/test", legacyRoot: "apt/test", selectedPayloadManifest: payloads, aptMetadataSuites: []string{"jammy"}}
	if err := filterAPTPublicationManifest(scanned, payloads, projection, original, filtered); err != nil {
		t.Fatal(err)
	}
	got := readPublishManifest(t, filtered)
	wantPaths := []string{
		prefix + "dists/jammy/InRelease",
		prefix + "dists/jammy/main/binary-amd64/Packages",
		prefix + "dists/jammy/main/binary-arm64/Packages",
		prefix + "pool/main/p/selected.deb",
	}
	if len(got) != len(wantPaths) {
		t.Fatalf("filtered entries=%v", got)
	}
	for index, want := range wantPaths {
		if got[index].Path != want {
			t.Fatalf("filtered[%d]=%s want %s", index, got[index].Path, want)
		}
	}
}

func TestPublishManifestReplaceScopes(t *testing.T) {
	directory := t.TempDir()
	oldPath := filepath.Join(directory, "old.tsv")
	selectedPath := filepath.Join(directory, "selected.tsv")
	destinationPath := filepath.Join(directory, "target.tsv")
	writePublishManifest(t, oldPath,
		publishManifestEntry("apt/dists/bookworm/InRelease", "old-release"),
		publishManifestEntry("asset/tool.tar.gz", "keep-asset"),
		publishManifestEntry("yum/Packages/a.rpm", "keep-package"),
		publishManifestEntry("yum/repodata/old.xml.gz", "old-metadata"),
	)
	writePublishManifest(t, selectedPath,
		publishManifestEntry("apt/dists/bookworm/InRelease", "new-release"),
		publishManifestEntry("apt/dists/bookworm/main/binary-amd64/Packages", "new-index"),
		publishManifestEntry("yum/repodata/new.xml.zst", "new-metadata"),
		publishManifestEntry("yum/repodata/repomd.xml", "new-repomd"),
	)

	if err := ReplaceManifestScopes(oldPath, selectedPath, destinationPath, []string{"yum/repodata", "apt/dists"}); err != nil {
		t.Fatal(err)
	}
	got := readPublishManifest(t, destinationPath)
	want := []manifest.Entry{
		publishManifestEntry("apt/dists/bookworm/InRelease", "new-release"),
		publishManifestEntry("apt/dists/bookworm/main/binary-amd64/Packages", "new-index"),
		publishManifestEntry("asset/tool.tar.gz", "keep-asset"),
		publishManifestEntry("yum/Packages/a.rpm", "keep-package"),
		publishManifestEntry("yum/repodata/new.xml.zst", "new-metadata"),
		publishManifestEntry("yum/repodata/repomd.xml", "new-repomd"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected replacement:\n got: %#v\nwant: %#v", got, want)
	}
	if info, err := os.Stat(destinationPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode: info=%v err=%v", info, err)
	}
}

func TestPublishManifestScopePrefixIsSegmentAware(t *testing.T) {
	directory := t.TempDir()
	oldPath := filepath.Join(directory, "old.tsv")
	selectedPath := filepath.Join(directory, "selected.tsv")
	destinationPath := filepath.Join(directory, "target.tsv")
	writePublishManifest(t, oldPath,
		publishManifestEntry("a-b/keep", "keep"),
		publishManifestEntry("a/old", "old"),
	)
	writePublishManifest(t, selectedPath, publishManifestEntry("a/new", "new"))
	if err := ReplaceManifestScopes(oldPath, selectedPath, destinationPath, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	want := []manifest.Entry{
		publishManifestEntry("a-b/keep", "keep"),
		publishManifestEntry("a/new", "new"),
	}
	if got := readPublishManifest(t, destinationPath); !reflect.DeepEqual(got, want) {
		t.Fatalf("segment-aware replacement = %#v, want %#v", got, want)
	}
}

func TestPublishManifestReplaceSupportsEmptyInputsAndRootScope(t *testing.T) {
	tests := []struct {
		name     string
		old      []manifest.Entry
		selected []manifest.Entry
		scopes   []string
		want     []manifest.Entry
	}{
		{name: "empty selected removes scope", old: []manifest.Entry{publishManifestEntry("a/old", "old"), publishManifestEntry("z/keep", "keep")}, scopes: []string{"a"}, want: []manifest.Entry{publishManifestEntry("z/keep", "keep")}},
		{name: "empty old accepts selection", selected: []manifest.Entry{publishManifestEntry("a/new", "new")}, scopes: []string{"a"}, want: []manifest.Entry{publishManifestEntry("a/new", "new")}},
		{name: "both empty", scopes: nil, want: nil},
		{name: "root replaces all", old: []manifest.Entry{publishManifestEntry("a/old", "old")}, selected: []manifest.Entry{publishManifestEntry("z/new", "new")}, scopes: []string{"."}, want: []manifest.Entry{publishManifestEntry("z/new", "new")}},
		{name: "no scopes preserves old", old: []manifest.Entry{publishManifestEntry("a/old", "old")}, scopes: nil, want: []manifest.Entry{publishManifestEntry("a/old", "old")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			oldPath := filepath.Join(directory, "old.tsv")
			selectedPath := filepath.Join(directory, "selected.tsv")
			destinationPath := filepath.Join(directory, "target.tsv")
			writePublishManifest(t, oldPath, test.old...)
			writePublishManifest(t, selectedPath, test.selected...)
			if err := ReplaceManifestScopes(oldPath, selectedPath, destinationPath, test.scopes); err != nil {
				t.Fatal(err)
			}
			got := readPublishManifest(t, destinationPath)
			if !reflect.DeepEqual(got, test.want) && !(len(got) == 0 && len(test.want) == 0) {
				t.Fatalf("got %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestPublishManifestRejectsUnsafeScopesAndOutsideEntries(t *testing.T) {
	invalidScopes := [][]string{
		{"a//b"}, {"/absolute"}, {"../escape"}, {"a/../escape"}, {"a/"}, {"a\\b"}, {string([]byte{'a', 0, 'b'})},
		{"a", "a"}, {"a", "a/b"}, {"a/b", "a"}, {".", "a"},
	}
	for _, scopes := range invalidScopes {
		t.Run(fmt.Sprintf("scopes=%q", scopes), func(t *testing.T) {
			directory := t.TempDir()
			oldPath := filepath.Join(directory, "old.tsv")
			selectedPath := filepath.Join(directory, "selected.tsv")
			destinationPath := filepath.Join(directory, "target.tsv")
			writePublishManifest(t, oldPath)
			writePublishManifest(t, selectedPath)
			if err := ReplaceManifestScopes(oldPath, selectedPath, destinationPath, scopes); err == nil {
				t.Fatalf("unsafe scopes accepted: %q", scopes)
			}
			if _, err := os.Lstat(destinationPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed replacement left output behind: %v", err)
			}
		})
	}

	directory := t.TempDir()
	oldPath := filepath.Join(directory, "old.tsv")
	selectedPath := filepath.Join(directory, "selected.tsv")
	destinationPath := filepath.Join(directory, "target.tsv")
	writePublishManifest(t, oldPath)
	writePublishManifest(t, selectedPath,
		publishManifestEntry("selected/valid", "valid"),
		publishManifestEntry("unselected/outside", "outside"),
	)
	if err := ReplaceManifestScopes(oldPath, selectedPath, destinationPath, []string{"selected"}); err == nil || !strings.Contains(err.Error(), "outside selected scopes") {
		t.Fatalf("wanted selected-scope error, got %v", err)
	}
	if _, err := os.Lstat(destinationPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed replacement left output behind: %v", err)
	}
}

func TestPublishManifestRejectsMalformedInputsAndExistingDestination(t *testing.T) {
	directory := t.TempDir()
	oldPath := filepath.Join(directory, "old.tsv")
	selectedPath := filepath.Join(directory, "selected.tsv")
	writePublishManifest(t, selectedPath)
	if err := os.WriteFile(oldPath, []byte("b\t1\t"+strings.Repeat("0", 64)+"\na\t1\t"+strings.Repeat("1", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	destinationPath := filepath.Join(directory, "target.tsv")
	if err := ReplaceManifestScopes(oldPath, selectedPath, destinationPath, nil); err == nil || !strings.Contains(err.Error(), "strictly sorted") {
		t.Fatalf("wanted sorted-input error, got %v", err)
	}
	if _, err := os.Lstat(destinationPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("malformed input left output behind: %v", err)
	}

	duplicatePath := filepath.Join(directory, "duplicate.tsv")
	duplicateLine := "a/file\t1\t" + strings.Repeat("0", 64) + "\n"
	if err := os.WriteFile(duplicatePath, []byte(duplicateLine+duplicateLine), 0o600); err != nil {
		t.Fatal(err)
	}
	duplicateOutput := filepath.Join(directory, "duplicate-out.tsv")
	if err := ReplaceManifestScopes(selectedPath, duplicatePath, duplicateOutput, []string{"a"}); err == nil || !strings.Contains(err.Error(), "strictly sorted") {
		t.Fatalf("wanted duplicate-input error, got %v", err)
	}
	if _, err := os.Lstat(duplicateOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("duplicate input left output behind: %v", err)
	}

	goodOldPath := filepath.Join(directory, "good-old.tsv")
	writePublishManifest(t, goodOldPath)
	if err := os.WriteFile(destinationPath, []byte("do-not-replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceManifestScopes(goodOldPath, selectedPath, destinationPath, nil); err == nil {
		t.Fatal("existing destination was replaced")
	}
	content, err := os.ReadFile(destinationPath)
	if err != nil || string(content) != "do-not-replace" {
		t.Fatalf("existing destination changed: %q err=%v", content, err)
	}

	symlinkPath := filepath.Join(directory, "old-link.tsv")
	if err := os.Symlink(goodOldPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceManifestScopes(symlinkPath, selectedPath, filepath.Join(directory, "symlink-out.tsv"), nil); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("wanted symlink rejection, got %v", err)
	}
}

func TestPublishManifestDropScopesAndDiffChangedPaths(t *testing.T) {
	directory := t.TempDir()
	oldPath := filepath.Join(directory, "old.tsv")
	droppedPath := filepath.Join(directory, "dropped.tsv")
	newPath := filepath.Join(directory, "new.tsv")
	writePublishManifest(t, oldPath,
		publishManifestEntry("a/changed", "old"),
		publishManifestEntry("b/same", "same"),
		publishManifestEntry("gone/removed", "removed"),
		publishManifestEntry("yum/repodata/filelists.xml.gz", "metadata"),
	)
	if err := DropManifestScopes(oldPath, droppedPath, []string{"yum/repodata"}); err != nil {
		t.Fatal(err)
	}
	wantDropped := []manifest.Entry{
		publishManifestEntry("a/changed", "old"),
		publishManifestEntry("b/same", "same"),
		publishManifestEntry("gone/removed", "removed"),
	}
	if got := readPublishManifest(t, droppedPath); !reflect.DeepEqual(got, wantDropped) {
		t.Fatalf("dropped manifest = %#v, want %#v", got, wantDropped)
	}
	writePublishManifest(t, newPath,
		publishManifestEntry("a/changed", "new"),
		publishManifestEntry("b/same", "same"),
		publishManifestEntry("c/added", "added"),
		publishManifestEntry("yum/repodata/filelists.xml.gz", "metadata"),
	)
	paths, err := DiffChangedPaths(oldPath, newPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a/changed", "c/added"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("changed paths = %q, want %q", paths, want)
	}
}

func TestPublishManifestSelectionReplacesSuiteAndUpsertsSharedPool(t *testing.T) {
	directory := t.TempDir()
	oldPath := filepath.Join(directory, "old.tsv")
	selectedPath := filepath.Join(directory, "selected.tsv")
	desiredPath := filepath.Join(directory, "desired.tsv")
	baselinePath := filepath.Join(directory, "baseline.tsv")
	writePublishManifest(t, oldPath,
		publishManifestEntry("apt/dists/bookworm/InRelease", "bookworm-stable"),
		publishManifestEntry("apt/dists/jammy/InRelease", "jammy-old"),
		publishManifestEntry("apt/dists/jammy/main/binary-amd64/Packages", "packages-old"),
		publishManifestEntry("apt/pool/main/b/bookworm.deb", "bookworm-payload"),
		publishManifestEntry("apt/pool/main/j/jammy.deb", "jammy-old"),
	)
	writePublishManifest(t, selectedPath,
		publishManifestEntry("apt/dists/jammy/InRelease", "jammy-new"),
		publishManifestEntry("apt/dists/jammy/main/binary-amd64/Packages", "packages-new"),
		publishManifestEntry("apt/dists/jammy/main/binary-arm64/Packages", "arm64-closure"),
		publishManifestEntry("apt/pool/main/j/jammy-arm64.deb", "arm64-payload"),
		publishManifestEntry("apt/pool/main/j/jammy.deb", "jammy-new"),
	)
	selection := manifestSelectionScopes{Replace: []string{"apt/dists/jammy"}, Upsert: []string{"apt/pool"}}
	if err := ReplaceManifestSelection(oldPath, selectedPath, desiredPath, selection); err != nil {
		t.Fatal(err)
	}
	wantDesired := []manifest.Entry{
		publishManifestEntry("apt/dists/bookworm/InRelease", "bookworm-stable"),
		publishManifestEntry("apt/dists/jammy/InRelease", "jammy-new"),
		publishManifestEntry("apt/dists/jammy/main/binary-amd64/Packages", "packages-new"),
		publishManifestEntry("apt/dists/jammy/main/binary-arm64/Packages", "arm64-closure"),
		publishManifestEntry("apt/pool/main/b/bookworm.deb", "bookworm-payload"),
		publishManifestEntry("apt/pool/main/j/jammy-arm64.deb", "arm64-payload"),
		publishManifestEntry("apt/pool/main/j/jammy.deb", "jammy-new"),
	}
	if got := readPublishManifest(t, desiredPath); !reflect.DeepEqual(got, wantDesired) {
		t.Fatalf("selector merge = %#v, want %#v", got, wantDesired)
	}
	if err := DropManifestSelection(oldPath, selectedPath, baselinePath, selection); err != nil {
		t.Fatal(err)
	}
	wantBaseline := []manifest.Entry{
		publishManifestEntry("apt/dists/bookworm/InRelease", "bookworm-stable"),
		publishManifestEntry("apt/pool/main/b/bookworm.deb", "bookworm-payload"),
	}
	if got := readPublishManifest(t, baselinePath); !reflect.DeepEqual(got, wantBaseline) {
		t.Fatalf("selector plan baseline = %#v, want %#v", got, wantBaseline)
	}
	changed, err := DiffChangedPaths(baselinePath, desiredPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range changed {
		if strings.Contains(path, "bookworm") {
			t.Fatalf("selector baseline forced sibling addition %q", path)
		}
	}
}

func TestPublishManifestStreamsTenThousandEntries(t *testing.T) {
	directory := t.TempDir()
	oldPath := filepath.Join(directory, "old.tsv")
	selectedPath := filepath.Join(directory, "selected.tsv")
	destinationPath := filepath.Join(directory, "target.tsv")

	oldEntries := make([]manifest.Entry, 0, 10_000)
	selectedEntries := make([]manifest.Entry, 0, 5_000)
	for index := 0; index < 5_000; index++ {
		oldEntries = append(oldEntries, publishManifestEntry(fmt.Sprintf("keep/%05d.bin", index), fmt.Sprintf("keep-%d", index)))
	}
	for index := 0; index < 5_000; index++ {
		oldEntries = append(oldEntries, publishManifestEntry(fmt.Sprintf("yum/repodata/%05d.xml.zst", index), fmt.Sprintf("old-%d", index)))
		selectedEntries = append(selectedEntries, publishManifestEntry(fmt.Sprintf("yum/repodata/%05d.xml.zst", index), fmt.Sprintf("new-%d", index)))
	}
	writePublishManifest(t, oldPath, oldEntries...)
	writePublishManifest(t, selectedPath, selectedEntries...)
	if err := ReplaceManifestScopes(oldPath, selectedPath, destinationPath, []string{"yum/repodata"}); err != nil {
		t.Fatal(err)
	}
	entries := readPublishManifest(t, destinationPath)
	if len(entries) != 10_000 {
		t.Fatalf("got %d output entries, want 10000", len(entries))
	}
	if entries[0] != oldEntries[0] || entries[4_999] != oldEntries[4_999] || entries[5_000] != selectedEntries[0] || entries[9_999] != selectedEntries[4_999] {
		t.Fatal("streaming replacement did not preserve exact keep/selected boundaries")
	}
	paths, err := DiffChangedPaths(oldPath, destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 5_000 || paths[0] != "yum/repodata/00000.xml.zst" || paths[len(paths)-1] != "yum/repodata/04999.xml.zst" {
		t.Fatalf("unexpected 10k diff boundary: count=%d first=%q last=%q", len(paths), paths[0], paths[len(paths)-1])
	}
}

func publishManifestEntry(entryPath, body string) manifest.Entry {
	return manifest.Entry{Path: entryPath, Size: int64(len(body)), SHA256: sha256.Sum256([]byte(body))}
}

func writePublishManifest(t *testing.T, filename string, entries ...manifest.Entry) {
	t.Helper()
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := manifest.WriteEntry(file, entry); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		t.Fatal(err)
	}
}

func readPublishManifest(t *testing.T, filename string) []manifest.Entry {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	var entries []manifest.Entry
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return entries
		}
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
}
