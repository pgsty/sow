package serving

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/repository"
)

func deriveGenerationAtCommit(t *testing.T, manifestPath, commitDigit string) Generation {
	t.Helper()
	file, err := os.Open(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := testIdentity()
	identity.RefCommit = strings.Repeat(commitDigit, 40)
	generation, deriveErr := DeriveGeneration(identity, file)
	closeErr := file.Close()
	if deriveErr != nil || closeErr != nil {
		t.Fatal(errors.Join(deriveErr, closeErr))
	}
	return generation
}

func TestTargetPartitionAndBoundedGenerationLineage(t *testing.T) {
	root := t.TempDir()
	manifestPath := writeServingFixture(t, root)
	generationA := deriveGenerationAtCommit(t, manifestPath, "1")
	generationB := deriveGenerationAtCommit(t, manifestPath, "2")

	defaultTarget, err := NewTargetIdentity("latest", ".", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	explicitA, err := NewTargetIdentity("latest", "exports/a", "https://a.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	explicitB, err := NewTargetIdentity("latest", "exports/b", "https://b.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if defaultTarget.ID == explicitA.ID || explicitA.ID == explicitB.ID {
		t.Fatalf("distinct serving exports share target identity: default=%s a=%s b=%s", defaultTarget.ID, explicitA.ID, explicitB.ID)
	}
	replayedA, err := NewTargetIdentity("latest", "exports/a", "https://a.example.invalid/")
	if err != nil || replayedA != explicitA {
		t.Fatalf("target identity is not deterministic: replay=%#v err=%v", replayedA, err)
	}
	targetBody, err := explicitA.Canonical("latest")
	if err != nil {
		t.Fatal(err)
	}
	decodedTarget, err := DecodeTargetIdentity("latest", targetBody)
	if err != nil || decodedTarget != explicitA {
		t.Fatalf("target identity round trip=%#v err=%v", decodedTarget, err)
	}

	channelA1, err := NewChannelForTarget(generationA, explicitA, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	channelB, err := NewChannelForTarget(generationB, explicitA, &channelA1, 2)
	if err != nil {
		t.Fatal(err)
	}
	channelA2, err := NewChannelForTarget(generationA, explicitA, &channelB, 2)
	if err != nil {
		t.Fatal(err)
	}
	if channelA2.Generation != generationA.ID || channelA2.ParentGeneration != generationB.ID || len(channelA2.Previous) != 1 || channelA2.Previous[0].ID != generationB.ID {
		t.Fatalf("A -> B -> A lineage is not bounded/deduplicated: %#v", channelA2)
	}
	paths, err := RetainedGenerationManifestPaths(channelA2)
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		GenerationManifestStatePath(generationA),
		GenerationManifestStatePath(generationB),
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("retained manifest paths=%v want=%v", paths, wantPaths)
	}

	otherTargetChannel, err := NewChannelForTarget(generationA, explicitB, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if ChannelStatePath(channelA2) == ChannelStatePath(otherTargetChannel) {
		t.Fatalf("target partitions share canonical channel path %s", ChannelStatePath(channelA2))
	}
	if _, err := NewChannelForTarget(generationB, explicitB, &channelA1, 2); err == nil || !strings.Contains(err.Error(), "target differs") {
		t.Fatalf("cross-target parent lineage accepted: %v", err)
	}
	movedURL, err := NewTargetIdentity("latest", "exports/a", "https://new-a.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := NewChannelForTargetMigration(generationB, movedURL, &channelA1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.ParentTargetID != explicitA.ID || migrated.TargetID != movedURL.ID || migrated.ParentMirrorlistSHA256 != channelA1.MirrorlistSHA256 {
		t.Fatalf("base-URL migration lost target-bound parent: %#v", migrated)
	}
	otherRoot, err := NewTargetIdentity("latest", "exports/other", "https://new-a.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewChannelForTargetMigration(generationB, otherRoot, &channelA1, 2); err == nil {
		t.Fatal("cross-root target migration accepted")
	}
	if _, err := NewChannelForTarget(generationB, explicitA, &channelA1, 0); err == nil {
		t.Fatal("zero previous-generation retention accepted")
	}
}

func TestGlobalRetainedGenerationKeepSetDeduplicatesSharedTargetsAndPinsJournal(t *testing.T) {
	root := t.TempDir()
	manifestPath := writeServingFixture(t, root)
	current := deriveGenerationAtCommit(t, manifestPath, "3")
	previous := deriveGenerationAtCommit(t, manifestPath, "4")
	desired := deriveGenerationAtCommit(t, manifestPath, "5")
	targetA, err := NewTargetIdentity("latest", "exports/a", "https://a.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	targetB, err := NewTargetIdentity("latest", "exports/b", "https://b.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	parentA, err := NewChannelForTarget(previous, targetA, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	channelA, err := NewChannelForTarget(current, targetA, &parentA, 2)
	if err != nil {
		t.Fatal(err)
	}
	channelB, err := NewChannelForTarget(current, targetB, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	journalPin := GenerationCoordinate{ID: desired.ID, View: desired.View, Repo: desired.Repo, OS: desired.OS, Arch: desired.Arch}
	keep, err := RetainedGenerationKeepSet([]Channel{channelA, channelB}, []GenerationCoordinate{journalPin})
	if err != nil {
		t.Fatal(err)
	}
	for _, generation := range []Generation{current, previous, desired} {
		if _, exists := keep[GenerationManifestStatePath(generation)]; !exists {
			t.Fatalf("keep set omitted generation %s: %#v", generation.ID, keep)
		}
	}
	if len(keep) != 3 {
		t.Fatalf("shared generation was not deduplicated: %#v", keep)
	}
	for path := range keep {
		if !IsGenerationManifestStatePath(path) {
			t.Fatalf("keep set emitted unrecognized path %q", path)
		}
	}
	if IsGenerationManifestStatePath("serving/yum/generations/not-an-id/latest/repo/el10/x86_64.tsv") {
		t.Fatal("invalid generation manifest path accepted")
	}
}

func TestMirrorlistTopologyRemovalIsParentBoundAndIdempotent(t *testing.T) {
	root := t.TempDir()
	manifestPath := writeServingFixture(t, root)
	generation := deriveGenerationAtCommit(t, manifestPath, "6")
	target, err := NewTargetIdentity("latest", ".", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	channel, err := NewChannelForTarget(generation, target, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := ReconcileMirrorlist(root, channel); err != nil || !changed {
		t.Fatalf("install mirrorlist changed=%v err=%v", changed, err)
	}
	pointer := filepath.Join(root, filepath.FromSlash(channel.MirrorlistPath))
	if err := os.Chmod(pointer, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pointer, []byte("https://foreign.invalid/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if removed, err := RemoveMirrorlist(root, channel); err == nil || removed || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("foreign mirrorlist removed=%v err=%v", removed, err)
	}
	wanted, err := channel.MirrorlistBody()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pointer, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pointer, wanted, 0o644); err != nil {
		t.Fatal(err)
	}
	if removed, err := RemoveMirrorlist(root, channel); err != nil || !removed {
		t.Fatalf("canonical mirrorlist removed=%v err=%v", removed, err)
	}
	if removed, err := RemoveMirrorlist(root, channel); err != nil || removed {
		t.Fatalf("idempotent mirrorlist removal=%v err=%v", removed, err)
	}
}

func TestRetiredGenerationDirectoryRemovalIsValidatedAndRetryable(t *testing.T) {
	root := t.TempDir()
	manifestPath := writeServingFixture(t, root)
	generation := deriveGenerationAtCommit(t, manifestPath, "7")
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	options := InstallOptions{Workers: 2, ChunkEntries: 2, TempDir: filepath.Join(root, ".sow")}
	if _, err := InstallGeneration(t.Context(), pool, root, generation, manifestPath, options); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected directory removal stop")
	err = RemoveRetiredGeneration(t.Context(), pool, root, generation, RemoveGenerationOptions{
		InstallOptions: options,
		BeforeRemove:   func() error { return injected },
	})
	if !errors.Is(err, injected) {
		t.Fatalf("directory removal injection err=%v", err)
	}
	generationRoot := filepath.Join(root, "_sow", "v1", "g", generation.ID)
	if _, err := os.Stat(generationRoot); err != nil {
		t.Fatalf("injected removal changed directory: %v", err)
	}
	if err := RemoveRetiredGeneration(t.Context(), pool, root, generation, RemoveGenerationOptions{InstallOptions: options}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(generationRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retried removal left directory: %v", err)
	}
}
