package managed

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestRetainedRecordAndManifestExactWire(t *testing.T) {
	record := RetainedRecord{
		Schema:               retainedSchema,
		RepositoryID:         "12345678-1234-4123-8123-123456789abc",
		Generation:           42,
		ManifestSHA256:       strings.Repeat("1", 64),
		PayloadRefsetSHA256:  strings.Repeat("2", 64),
		MetadataRefsetSHA256: strings.Repeat("3", 64),
		RendererIdentity:     strings.Repeat("4", 64),
		SignerIdentity:       "none",
	}
	canonical, err := canonicalRetainedRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"generation":"00000000000000000042","manifest_sha256":"` + strings.Repeat("1", 64) +
		`","metadata_refset_sha256":"` + strings.Repeat("3", 64) + `","payload_refset_sha256":"` + strings.Repeat("2", 64) +
		`","renderer_identity":"` + strings.Repeat("4", 64) + `","repository_id":"12345678-1234-4123-8123-123456789abc","schema":"sow/retained/v1","signer_identity":"none"}`
	if string(canonical) != want {
		t.Fatalf("record wire:\n%s\nwant:\n%s", canonical, want)
	}
	parsed, exact, err := parseRetainedRecord(canonical)
	if err != nil || parsed != record || !bytes.Equal(exact, canonical) {
		t.Fatalf("parsed=%#v exact=%s err=%v", parsed, exact, err)
	}
	duplicate := bytes.Replace(canonical, []byte(`"generation":`), []byte(`"generation":"00000000000000000042","generation":`), 1)
	unknown := append(append([]byte(nil), canonical[:len(canonical)-1]...), []byte(`,"unknown":"x"}`)...)
	for name, invalid := range map[string][]byte{
		"duplicate":    duplicate,
		"unknown":      unknown,
		"trailing-lf":  append(append([]byte(nil), canonical...), '\n'),
		"noncanonical": []byte(`{"schema":"sow/retained/v1","repository_id":"12345678-1234-4123-8123-123456789abc","generation":"00000000000000000042","manifest_sha256":"` + strings.Repeat("1", 64) + `","payload_refset_sha256":"` + strings.Repeat("2", 64) + `","metadata_refset_sha256":"` + strings.Repeat("3", 64) + `","renderer_identity":"` + strings.Repeat("4", 64) + `","signer_identity":"none"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRetainedRecord(invalid); err == nil {
				t.Fatalf("accepted invalid retained record %s", invalid)
			}
		})
	}

	manifest := []state.GenerationFile{
		{Path: "dists/el9/x86_64/repodata/repomd.xml", Phase: "pointer", Size: 2, SHA256: strings.Repeat("5", 64)},
		{Path: "pool/p/pkg/pkg.rpm", Phase: "payload", Size: 0, SHA256: strings.Repeat("6", 64)},
	}
	manifestBytes, _, err := state.ManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := parseRetainedManifest(manifestBytes); err != nil || len(parsed) != 2 || parsed[1].Path != "pool/p/pkg/pkg.rpm" {
		t.Fatalf("manifest=%#v err=%v", parsed, err)
	}
	for _, invalid := range [][]byte{
		bytes.TrimSuffix(manifestBytes, []byte{'\n'}),
		bytes.Replace(manifestBytes, []byte(" 0 payload "), []byte(" 00 payload "), 1),
		append(append([]byte(nil), manifestBytes...), manifestBytes...),
	} {
		if _, err := parseRetainedManifest(invalid); err == nil {
			t.Fatalf("accepted invalid retained manifest %q", invalid)
		}
	}
}

func TestRetainedGenerationVerifierAcceptsEmptyManifest(t *testing.T) {
	root := t.TempDir()
	const repositoryID = "12345678-1234-4123-8123-123456789abc"
	generation := state.GenerationID(1)
	directory := filepath.Join(root, ".sow", "repo", "retained", generation.String())
	if err := os.MkdirAll(filepath.Join(directory, "metadata"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest, manifestSHA, err := state.ManifestBytes([]state.GenerationFile{})
	if err != nil || len(manifest) != 0 {
		t.Fatalf("manifest=%q err=%v", manifest, err)
	}
	payloadRefset, metadataRefset := retainedRefsets(nil)
	record := RetainedRecord{
		Schema: retainedSchema, RepositoryID: repositoryID, Generation: generation,
		ManifestSHA256: manifestSHA, PayloadRefsetSHA256: payloadRefset, MetadataRefsetSHA256: metadataRefset,
		RendererIdentity: strings.Repeat("a", 64), SignerIdentity: "none",
	}
	recordBytes, err := canonicalRetainedRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.tsv"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "record.json"), recordBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	verified, err := verifyRetainedGenerationDirectory(context.Background(), root, "repo", generation, repositoryID, directory)
	if err != nil || verified.Record != record {
		t.Fatalf("verified=%#v err=%v", verified, err)
	}
}

func TestRetainedGenerationCopiesMetadataButReferencesPayload(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	summary, summaryErr := store.Summary(ctx)
	manifest, manifestErr := store.GenerationManifest(ctx, summary.BuiltGeneration)
	if err := errors.Join(summaryErr, manifestErr, store.Close()); err != nil {
		t.Fatal(err)
	}
	options := WorkspaceOptions{Workdir: root, CWD: root}
	injected := errors.New("injected retain failure")
	if _, err := AddRetainedGeneration(ctx, RetainAddOptions{WorkspaceOptions: options, Repository: "repo", Generation: summary.BuiltGeneration, Fault: func(point string) error {
		if point == "retain.staged" {
			return injected
		}
		return nil
	}}); !errors.Is(err, injected) {
		t.Fatalf("staged fault=%v", err)
	}
	retainedRoot := filepath.Join(root, ".sow", "repo", "retained", summary.BuiltGeneration.String())
	if _, err := os.Lstat(retainedRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed retain published target: %v", err)
	}

	retained, err := RetainAdd(ctx, RetainAddOptions{WorkspaceOptions: options, Repository: "repo", Generation: summary.BuiltGeneration})
	if err != nil || retained.Repository != "repo" || retained.Record.Generation != summary.BuiltGeneration || filepath.Base(retained.Path) != summary.BuiltGeneration.String() || !lowercaseSHA256.MatchString(retained.RecordIdentity) {
		t.Fatalf("retained=%#v err=%v", retained, err)
	}
	retainedRoot = retained.Path
	for _, file := range manifest {
		copyPath := filepath.Join(retainedRoot, "metadata", filepath.FromSlash(file.Path))
		if file.Phase == "payload" {
			if _, err := os.Lstat(copyPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("payload was copied into retained metadata: %s err=%v", file.Path, err)
			}
			if _, err := os.Stat(filepath.Join(root, "repo", filepath.FromSlash(file.Path))); err != nil {
				t.Fatalf("referenced payload missing: %s err=%v", file.Path, err)
			}
		} else if _, err := os.Stat(copyPath); err != nil {
			t.Fatalf("metadata was not copied: %s err=%v", file.Path, err)
		}
	}
	listed, err := RetainList(ctx, RetainListOptions{WorkspaceOptions: options, Repository: "repo"})
	if err != nil || listed.Repository != "repo" || len(listed.Generations) != 1 || listed.Generations[0].RecordIdentity != retained.RecordIdentity {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
	if _, err := VerifyRetainedGeneration(ctx, RetainVerifyOptions{WorkspaceOptions: options, Repository: "repo", Generation: summary.BuiltGeneration}); err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(retainedRoot, "record.json")
	recordBytes, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append(append([]byte(nil), recordBytes[:len(recordBytes)-1]...), []byte(`,"unknown":"x"}`)...)
	if err := os.WriteFile(recordPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRetainedGeneration(ctx, RetainVerifyOptions{WorkspaceOptions: options, Repository: "repo", Generation: summary.BuiltGeneration}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered retained verification error=%v", err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrIntegrity) || checked.ReadyToCopy {
		t.Fatalf("ordinary check accepted tampered retained Generation: result=%#v err=%v", checked, err)
	}
	retainedLayerFailed := false
	for _, layer := range checked.Layers {
		if layer.Name == "retained" {
			retainedLayerFailed = !layer.OK
		}
	}
	if !retainedLayerFailed {
		t.Fatalf("ordinary check did not attribute retained corruption: %#v", checked.Layers)
	}
	if err := os.WriteFile(recordPath, recordBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	tombstone := filepath.Join(root, ".sow", "repo", "stage", "retain-remove-"+summary.BuiltGeneration.String())
	planPath := tombstone + ".plan.json"
	planCrash := errors.New("crash after retained removal plan")
	if _, err := RetainRemove(ctx, RetainRemoveOptions{WorkspaceOptions: options, Repository: "repo", Generation: summary.BuiltGeneration, Fault: func(point string) error {
		if point == "retain.remove.planned" {
			return planCrash
		}
		return nil
	}}); !errors.Is(err, planCrash) {
		t.Fatalf("retained removal plan fault=%v", err)
	}
	if info, err := os.Lstat(retainedRoot); err != nil || !info.IsDir() {
		t.Fatalf("planned removal changed retained target: info=%#v err=%v", info, err)
	}
	if info, err := os.Lstat(planPath); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("planned removal sibling plan=%#v err=%v", info, err)
	}
	removeCrash := errors.New("crash after retained tombstone")
	if _, err := RetainRemove(ctx, RetainRemoveOptions{WorkspaceOptions: options, Repository: "repo", Generation: summary.BuiltGeneration, Fault: func(point string) error {
		if point == "retain.remove.tombstoned" {
			return removeCrash
		}
		return nil
	}}); !errors.Is(err, removeCrash) {
		t.Fatalf("retained tombstone fault=%v", err)
	}
	if _, err := os.Lstat(retainedRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tombstoned retained target remains: %v", err)
	}
	if info, err := os.Lstat(tombstone); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("removal tombstone=%#v err=%v", info, err)
	}
	if info, err := os.Lstat(planPath); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("removal sibling plan=%#v err=%v", info, err)
	}
	planData, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, canonical, err := parseRetainedRemovalPlan(planData)
	inventory, inventoryErr := retainedRemovalInventory(ctx, tombstone)
	if err != nil || inventoryErr != nil || !bytes.Equal(planData, canonical) || plan.RecordIdentity != retained.RecordIdentity || !sameRetainedRemovalInventory(plan.Entries, inventory) {
		t.Fatalf("sibling plan does not exactly bind tombstone: plan=%#v err=%v inventoryErr=%v", plan, err, inventoryErr)
	}
	partialCrash := errors.New("crash after one retained entry deletion")
	if _, err := RetainRemove(ctx, RetainRemoveOptions{WorkspaceOptions: options, Repository: "repo", Generation: summary.BuiltGeneration, Fault: func(point string) error {
		if strings.HasPrefix(point, "retain.remove.entry.") {
			return partialCrash
		}
		return nil
	}}); !errors.Is(err, partialCrash) {
		t.Fatalf("partial retained deletion fault=%v", err)
	}
	foreign := filepath.Join(tombstone, "foreign")
	if err := os.WriteFile(foreign, []byte("not in the frozen removal plan"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RetainRemove(ctx, RetainRemoveOptions{WorkspaceOptions: options, Repository: "repo", Generation: summary.BuiltGeneration}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("foreign retained tombstone entry was not rejected: %v", err)
	}
	if body, err := os.ReadFile(foreign); err != nil || string(body) != "not in the frozen removal plan" {
		t.Fatalf("foreign retained tombstone entry was changed: body=%q err=%v", body, err)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	cleanupCrash := errors.New("crash after retained tombstone cleanup")
	if _, err := RetainRemove(ctx, RetainRemoveOptions{WorkspaceOptions: options, Repository: "repo", Generation: summary.BuiltGeneration, Fault: func(point string) error {
		if point == "retain.remove.cleaned" {
			return cleanupCrash
		}
		return nil
	}}); !errors.Is(err, cleanupCrash) {
		t.Fatalf("retained cleanup fault=%v", err)
	}
	if _, err := os.Lstat(tombstone); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleaned retained tombstone survived: %v", err)
	}
	if info, err := os.Lstat(planPath); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("cleanup retry lost sibling plan: info=%#v err=%v", info, err)
	}
	removed, err := RetainRemove(ctx, RetainRemoveOptions{WorkspaceOptions: options, Repository: "repo", Generation: summary.BuiltGeneration})
	if err != nil || removed.Repository != "repo" || removed.RecordIdentity != retained.RecordIdentity {
		t.Fatalf("removed=%#v err=%v", removed, err)
	}
	if _, err := os.Lstat(retainedRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retained target survived remove: %v", err)
	}
	if _, err := os.Lstat(tombstone); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retained tombstone survived replay: %v", err)
	}
	if _, err := os.Lstat(planPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retained removal plan survived replay: %v", err)
	}
	noop, err := RetainRemove(ctx, RetainRemoveOptions{WorkspaceOptions: options, Repository: "repo", Generation: summary.BuiltGeneration})
	if err != nil || noop.Repository != "repo" || noop.Record.Generation != summary.BuiltGeneration || noop.RecordIdentity != "" {
		t.Fatalf("idempotent retained removal=%#v err=%v", noop, err)
	}
}
