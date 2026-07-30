package serving

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
)

type materializedRouteValidationFixture struct {
	root            string
	routeRoot       string
	relative        string
	payloadPath     string
	metadataPath    string
	exactManifest   string
	payloadManifest string
	route           MaterializedRoute
	pool            *repository.Store
	options         InstallOptions
}

func TestValidateMaterializedRouteRootAcceptsExactMetadataAndCanonicalPayload(t *testing.T) {
	fixture := newMaterializedRouteValidationFixture(t)
	validateMaterializedRouteFixture(t, context.Background(), fixture)
	// Validation has no durable side effects and is safe at both the initial
	// admission and final output-commit barrier.
	validateMaterializedRouteFixture(t, context.Background(), fixture)

	metadataInfo, err := os.Stat(fixture.metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	objectInfo, err := os.Stat(fixture.pool.ObjectPath(repository.Digest(sha256.Sum256([]byte("payload\n")))))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(metadataInfo, objectInfo) {
		t.Fatal("metadata unexpectedly required a CAS hardlink")
	}
}

func TestValidateMaterializedRouteRootAcceptsMissingPrefixOnlyForEmptyRoute(t *testing.T) {
	fixture := newMaterializedRouteValidationFixture(t)
	if err := os.RemoveAll(fixture.routeRoot); err != nil {
		t.Fatal(err)
	}
	writeManifestEntries(t, fixture.exactManifest, nil)
	writeManifestEntries(t, fixture.payloadManifest, nil)
	fixture.route = deriveMaterializedRouteFixtureReceipt(t, fixture, []MaterializedRouteClaim{{
		Kind: MaterializedRouteClaimPrefix, RelativeRoot: fixture.relative,
	}})
	validateMaterializedRouteFixture(t, context.Background(), fixture)

	if err := os.MkdirAll(fixture.routeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	writeModeFile(t, filepath.Join(fixture.routeRoot, "unexpected"), []byte("leak\n"), 0o444)
	if err := validateMaterializedRouteFixtureError(t, context.Background(), fixture); err == nil ||
		!strings.Contains(err.Error(), "manifest drift") {
		t.Fatalf("empty route receipt accepted a newly visible file: %v", err)
	}
}

func TestValidateMaterializedRouteRootRejectsAddedChangedAndUnhostableFiles(t *testing.T) {
	tests := map[string]func(*testing.T, materializedRouteValidationFixture){
		"added": func(t *testing.T, fixture materializedRouteValidationFixture) {
			writeModeFile(t, filepath.Join(fixture.routeRoot, "Packages", "p", "gated-secret.rpm"), []byte("secret\n"), 0o444)
		},
		"changed-metadata": func(t *testing.T, fixture materializedRouteValidationFixture) {
			if err := os.Chmod(fixture.metadataPath, 0o644); err != nil {
				t.Fatal(err)
			}
			writeModeFile(t, fixture.metadataPath, []byte("changed!\n"), 0o444)
		},
		"unhostable-file": func(t *testing.T, fixture materializedRouteValidationFixture) {
			if err := os.Chmod(fixture.metadataPath, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"unhostable-directory": func(t *testing.T, fixture materializedRouteValidationFixture) {
			if err := os.Chmod(filepath.Dir(fixture.metadataPath), 0o700); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newMaterializedRouteValidationFixture(t)
			mutate(t, fixture)
			if err := validateMaterializedRouteFixtureError(t, context.Background(), fixture); err == nil {
				t.Fatal("unsafe route was accepted")
			}
		})
	}
}

func TestValidateMaterializedRouteRootRejectsCopiedPayloadAndPayloadOutsideExact(t *testing.T) {
	t.Run("copied-non-CAS", func(t *testing.T) {
		fixture := newMaterializedRouteValidationFixture(t)
		body, err := os.ReadFile(fixture.payloadPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(fixture.payloadPath); err != nil {
			t.Fatal(err)
		}
		writeModeFile(t, fixture.payloadPath, body, 0o444)
		if err := validateMaterializedRouteFixtureError(t, context.Background(), fixture); err == nil || !strings.Contains(err.Error(), "canonical CAS hardlink") {
			t.Fatalf("copied payload error=%v", err)
		}
	})

	t.Run("payload-not-in-exact", func(t *testing.T) {
		fixture := newMaterializedRouteValidationFixture(t)
		unknown := manifest.Entry{Path: fixture.relative + "/Packages/z/unknown.rpm", Size: 1, SHA256: sha256.Sum256([]byte("x"))}
		writeManifestEntries(t, fixture.payloadManifest, []manifest.Entry{unknown})
		payloadReader, err := os.Open(fixture.payloadManifest)
		if err != nil {
			t.Fatal(err)
		}
		exactReader, err := os.Open(fixture.exactManifest)
		if err != nil {
			t.Fatal(err)
		}
		identity := MaterializedRouteIdentity{
			Kind: "yum", View: "latest", Source: "latest", TargetSHA256: strings.Repeat("a", 64),
			Claims: []MaterializedRouteClaim{{Kind: MaterializedRouteClaimPrefix, RelativeRoot: fixture.relative}}, ConfigSHA256: strings.Repeat("b", 64), ConfigCommit: strings.Repeat("e", 40), ServingTargetID: strings.Repeat("9", 64), Repo: "infra", OS: "all", Arch: "x86_64",
			Refs: []MaterializedRouteRef{{Name: "refs/sow/views/latest/infra/el8/x86_64", Commit: strings.Repeat("c", 40), ManifestBlob: strings.Repeat("f", 40), ManifestSize: 1}},
		}
		fixture.route, err = NewMaterializedRoute(identity, exactReader, payloadReader)
		closeErr := errors.Join(exactReader.Close(), payloadReader.Close())
		if err != nil || closeErr != nil {
			t.Fatal(errors.Join(err, closeErr))
		}
		if err := validateMaterializedRouteFixtureError(t, context.Background(), fixture); err == nil || !strings.Contains(err.Error(), "absent or differs") {
			t.Fatalf("payload subset error=%v", err)
		}
	})
}

func TestValidateMaterializedRouteRootFinalRechecksMetadataAndRetainedCASBytes(t *testing.T) {
	t.Run("metadata-after-scan", func(t *testing.T) {
		fixture := newMaterializedRouteValidationFixture(t)
		mutated := false
		ctx := withMaterializedRouteValidationHook(context.Background(), func(phase, _ string) error {
			if phase != materializedRouteValidationAfterInitialScan || mutated {
				return nil
			}
			mutated = true
			if err := os.Chmod(fixture.metadataPath, 0o644); err != nil {
				return err
			}
			if err := os.WriteFile(fixture.metadataPath, []byte("changed!\n"), 0o644); err != nil {
				return err
			}
			return os.Chmod(fixture.metadataPath, 0o444)
		})
		if err := validateMaterializedRouteFixtureError(t, ctx, fixture); err == nil || !strings.Contains(err.Error(), "final materialized route scan") {
			t.Fatalf("post-scan metadata mutation error=%v", err)
		}
	})

	t.Run("payload-after-CAS-verify", func(t *testing.T) {
		fixture := newMaterializedRouteValidationFixture(t)
		mutated := false
		ctx := withMaterializedRouteValidationHook(context.Background(), func(phase, relative string) error {
			if phase != materializedRouteValidationAfterCASVerified || mutated {
				return nil
			}
			mutated = true
			if relative != fixture.relative+"/Packages/p/pkg.rpm" {
				t.Fatalf("unexpected hook path %q", relative)
			}
			if err := os.Chmod(fixture.payloadPath, 0o644); err != nil {
				return err
			}
			if err := os.WriteFile(fixture.payloadPath, []byte("PAYLOAD\n"), 0o644); err != nil {
				return err
			}
			return os.Chmod(fixture.payloadPath, 0o444)
		})
		if err := validateMaterializedRouteFixtureError(t, ctx, fixture); err == nil || !strings.Contains(err.Error(), "retained rehash") {
			t.Fatalf("post-CAS payload mutation error=%v", err)
		}
	})
}

func TestValidateMaterializedRouteRootClaimsExactFileAndGenerationRegexSet(t *testing.T) {
	fixture := newMaterializedRouteValidationFixture(t)
	const generation = "00000000000000000001"
	generationLeaf := filepath.Join(fixture.root, "_sow", "v1", "g", generation, filepath.FromSlash(fixture.relative))
	for _, directory := range []string{
		filepath.Join(fixture.root, "_sow"), filepath.Join(fixture.root, "_sow", "v1"), filepath.Join(fixture.root, "_sow", "v1", "g"),
		filepath.Join(fixture.root, "_sow", "v1", "g", generation), generationLeaf,
		filepath.Join(generationLeaf, "Packages"), filepath.Join(generationLeaf, "Packages", "p"), filepath.Join(generationLeaf, "repodata"),
		filepath.Join(fixture.root, "_sow", "v1", "mirrorlists"), filepath.Join(fixture.root, "_sow", "v1", "mirrorlists", "latest"),
		filepath.Join(fixture.root, "_sow", "v1", "mirrorlists", "latest", "infra"), filepath.Join(fixture.root, "_sow", "v1", "mirrorlists", "latest", "infra", "el8"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	objectDigest := repository.Digest(sha256.Sum256([]byte("payload\n")))
	generationPayload := filepath.Join(generationLeaf, "Packages", "p", "pkg.rpm")
	if err := os.Link(fixture.pool.ObjectPath(objectDigest), generationPayload); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(generationPayload, 0o444); err != nil {
		t.Fatal(err)
	}
	generationMetadata := filepath.Join(generationLeaf, "repodata", "repomd.xml")
	writeModeFile(t, generationMetadata, []byte("generation-metadata\n"), 0o444)
	mirrorlistRelative := "_sow/v1/mirrorlists/latest/infra/el8/x86_64"
	mirrorlist := filepath.Join(fixture.root, filepath.FromSlash(mirrorlistRelative))
	writeModeFile(t, mirrorlist, []byte("https://repo.example/yum/infra/x86_64\n"), 0o444)
	// A sibling exact file and another repository leaf are not exposed by this
	// receipt and therefore must not be absorbed into its expected manifest.
	writeModeFile(t, filepath.Join(filepath.Dir(mirrorlist), "aarch64"), []byte("unrelated\n"), 0o444)
	unrelatedLeaf := filepath.Join(fixture.root, "_sow", "v1", "g", generation, "yum", "other", "x86_64", "Packages", "p")
	if err := os.MkdirAll(unrelatedLeaf, 0o755); err != nil {
		t.Fatal(err)
	}
	for current := unrelatedLeaf; current != filepath.Join(fixture.root, "_sow", "v1", "g", generation); current = filepath.Dir(current) {
		if err := os.Chmod(current, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(fixture.pool.ObjectPath(objectDigest), filepath.Join(unrelatedLeaf, "other.rpm")); err != nil {
		t.Fatal(err)
	}

	payloadBody := []byte("payload\n")
	metadataBody := []byte("metadata\n")
	generationMetadataBody := []byte("generation-metadata\n")
	mirrorlistBody := []byte("https://repo.example/yum/infra/x86_64\n")
	exactEntries := []manifest.Entry{
		{Path: fixture.relative + "/Packages/p/pkg.rpm", Size: int64(len(payloadBody)), SHA256: sha256.Sum256(payloadBody)},
		{Path: fixture.relative + "/repodata/repomd.xml", Size: int64(len(metadataBody)), SHA256: sha256.Sum256(metadataBody)},
		{Path: "_sow/v1/g/" + generation + "/" + fixture.relative + "/Packages/p/pkg.rpm", Size: int64(len(payloadBody)), SHA256: sha256.Sum256(payloadBody)},
		{Path: "_sow/v1/g/" + generation + "/" + fixture.relative + "/repodata/repomd.xml", Size: int64(len(generationMetadataBody)), SHA256: sha256.Sum256(generationMetadataBody)},
		{Path: mirrorlistRelative, Size: int64(len(mirrorlistBody)), SHA256: sha256.Sum256(mirrorlistBody)},
	}
	sort.Slice(exactEntries, func(i, j int) bool { return exactEntries[i].Path < exactEntries[j].Path })
	var payloadEntries []manifest.Entry
	for _, entry := range exactEntries {
		if strings.HasSuffix(entry.Path, ".rpm") {
			payloadEntries = append(payloadEntries, entry)
		}
	}
	writeManifestEntries(t, fixture.exactManifest, exactEntries)
	writeManifestEntries(t, fixture.payloadManifest, payloadEntries)
	fixture.route = deriveMaterializedRouteFixtureReceipt(t, fixture, []MaterializedRouteClaim{
		{Kind: MaterializedRouteClaimPrefix, RelativeRoot: fixture.relative},
		{Kind: MaterializedRouteClaimGeneration, RelativeRoot: "_sow/v1/g", Leaf: fixture.relative},
		{Kind: MaterializedRouteClaimExactFile, RelativeRoot: mirrorlistRelative},
	})
	validateMaterializedRouteFixture(t, context.Background(), fixture)

	const strayGeneration = "00000000000000000002"
	stray := filepath.Join(fixture.root, "_sow", "v1", "g", strayGeneration, filepath.FromSlash(fixture.relative), "Packages", "p")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
	}
	for current := stray; current != filepath.Join(fixture.root, "_sow", "v1", "g"); current = filepath.Dir(current) {
		if err := os.Chmod(current, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(fixture.pool.ObjectPath(objectDigest), filepath.Join(stray, "stray.rpm")); err != nil {
		t.Fatal(err)
	}
	strayMetadata := filepath.Join(filepath.Dir(filepath.Dir(stray)), "repodata")
	if err := os.MkdirAll(strayMetadata, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(strayMetadata, 0o755); err != nil {
		t.Fatal(err)
	}
	writeModeFile(t, filepath.Join(strayMetadata, "repomd.xml"), []byte("stray-metadata\n"), 0o444)
	if err := validateMaterializedRouteFixtureError(t, context.Background(), fixture); err == nil || !strings.Contains(err.Error(), "added=2") {
		t.Fatalf("regex-reachable stray generation error=%v", err)
	}
}

func newMaterializedRouteValidationFixture(t *testing.T) materializedRouteValidationFixture {
	t.Helper()
	root := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	payloadBody := []byte("payload\n")
	object, err := pool.Put(t.Context(), strings.NewReader(string(payloadBody)))
	if err != nil {
		t.Fatal(err)
	}
	relative := "yum/infra/x86_64"
	routeRoot := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Join(routeRoot, "Packages", "p"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(routeRoot, "repodata"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		filepath.Join(root, "yum"), filepath.Join(root, "yum", "infra"), routeRoot,
		filepath.Join(routeRoot, "Packages"), filepath.Join(routeRoot, "Packages", "p"), filepath.Join(routeRoot, "repodata"),
	} {
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	payloadPath := filepath.Join(routeRoot, "Packages", "p", "pkg.rpm")
	if err := os.Link(pool.ObjectPath(object.SHA256), payloadPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(payloadPath, 0o444); err != nil {
		t.Fatal(err)
	}
	metadataBody := []byte("metadata\n")
	metadataPath := filepath.Join(routeRoot, "repodata", "repomd.xml")
	writeModeFile(t, metadataPath, metadataBody, 0o444)
	exactEntries := []manifest.Entry{
		{Path: relative + "/Packages/p/pkg.rpm", Size: int64(len(payloadBody)), SHA256: sha256.Sum256(payloadBody)},
		{Path: relative + "/repodata/repomd.xml", Size: int64(len(metadataBody)), SHA256: sha256.Sum256(metadataBody)},
	}
	payloadEntries := exactEntries[:1]
	manifestDir := t.TempDir()
	exactManifest := filepath.Join(manifestDir, "exact.tsv")
	payloadManifest := filepath.Join(manifestDir, "payload.tsv")
	writeManifestEntries(t, exactManifest, exactEntries)
	writeManifestEntries(t, payloadManifest, payloadEntries)
	exactReader, err := os.Open(exactManifest)
	if err != nil {
		t.Fatal(err)
	}
	payloadReader, err := os.Open(payloadManifest)
	if err != nil {
		t.Fatal(err)
	}
	route, deriveErr := NewMaterializedRoute(MaterializedRouteIdentity{
		Kind: "yum", View: "latest", Source: "latest", TargetSHA256: strings.Repeat("a", 64),
		Claims: []MaterializedRouteClaim{{Kind: MaterializedRouteClaimPrefix, RelativeRoot: relative}}, ConfigSHA256: strings.Repeat("b", 64), ConfigCommit: strings.Repeat("e", 40), ServingTargetID: strings.Repeat("9", 64), Repo: "infra", OS: "all", Arch: "x86_64",
		Refs: []MaterializedRouteRef{{Name: "refs/sow/views/latest/infra/el8/x86_64", Commit: strings.Repeat("c", 40), ManifestBlob: strings.Repeat("f", 40), ManifestSize: 1}},
	}, exactReader, payloadReader)
	closeErr := errors.Join(exactReader.Close(), payloadReader.Close())
	if deriveErr != nil || closeErr != nil {
		t.Fatal(errors.Join(deriveErr, closeErr))
	}
	return materializedRouteValidationFixture{
		root: root, routeRoot: routeRoot, relative: relative,
		payloadPath: payloadPath, metadataPath: metadataPath,
		exactManifest: exactManifest, payloadManifest: payloadManifest,
		route: route, pool: pool,
		options: InstallOptions{Workers: 2, ChunkEntries: 2, TempDir: t.TempDir()},
	}
}

func validateMaterializedRouteFixture(t *testing.T, ctx context.Context, fixture materializedRouteValidationFixture) {
	t.Helper()
	if err := validateMaterializedRouteFixtureError(t, ctx, fixture); err != nil {
		t.Fatal(err)
	}
}

func validateMaterializedRouteFixtureError(t *testing.T, ctx context.Context, fixture materializedRouteValidationFixture) error {
	t.Helper()
	root, err := os.OpenRoot(fixture.root)
	if err != nil {
		return err
	}
	validateErr := ValidateMaterializedRouteRoot(ctx, fixture.pool, root, fixture.route, fixture.exactManifest, fixture.payloadManifest, fixture.options)
	return errors.Join(validateErr, root.Close())
}

func deriveMaterializedRouteFixtureReceipt(t *testing.T, fixture materializedRouteValidationFixture, claims []MaterializedRouteClaim) MaterializedRoute {
	t.Helper()
	exact, err := os.Open(fixture.exactManifest)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.Open(fixture.payloadManifest)
	if err != nil {
		t.Fatal(err)
	}
	route, deriveErr := NewMaterializedRoute(MaterializedRouteIdentity{
		Kind: "yum", View: "latest", Source: "latest", TargetSHA256: strings.Repeat("a", 64), Claims: claims,
		ConfigSHA256: strings.Repeat("b", 64), ConfigCommit: strings.Repeat("e", 40), ServingTargetID: strings.Repeat("9", 64), Repo: "infra", OS: "all", Arch: "x86_64",
		Refs: []MaterializedRouteRef{{Name: "refs/sow/views/latest/infra/el8/x86_64", Commit: strings.Repeat("c", 40), ManifestBlob: strings.Repeat("f", 40), ManifestSize: 1}},
	}, exact, payload)
	closeErr := errors.Join(exact.Close(), payload.Close())
	if deriveErr != nil || closeErr != nil {
		t.Fatal(errors.Join(deriveErr, closeErr))
	}
	return route
}

func writeManifestEntries(t *testing.T, name string, entries []manifest.Entry) {
	t.Helper()
	file, err := os.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := manifest.WriteEntry(file, entry); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeModeFile(t *testing.T, name string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(name, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}
