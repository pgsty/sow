package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"

	"github.com/pgsty/sow/internal/yumrepo"
)

func TestRenderEmptyRPMDistViews(t *testing.T) {
	root := t.TempDir()
	result, err := RenderManagedDist(context.Background(), root, ManagedDistSpec{
		Name: "el9", Format: "rpm", Generation: 1, Jobs: 1,
		Architectures: []state.Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}, {Family: "aarch64", EcosystemArch: "aarch64"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Files != 8 || len(result.TreeSHA256) != 64 {
		t.Fatalf("result=%#v", result)
	}
	for _, family := range []string{"x86_64", "aarch64"} {
		view := filepath.Join(root, "dists", "el9", family, "repodata")
		validated, err := yumrepo.ValidateManagedUnsignedDirectory(context.Background(), view, yumrepo.CompressionGzip)
		if err != nil {
			t.Fatalf("validate %s: %v", family, err)
		}
		if validated.Packages != 0 || validated.Revision != 1 {
			t.Fatalf("empty %s view=%#v", family, validated)
		}
	}
}

func TestRenderEmptyDEBDistViews(t *testing.T) {
	root := t.TempDir()
	result, err := RenderManagedDist(context.Background(), root, ManagedDistSpec{
		Name: "noble", Format: "deb", Generation: 1, Jobs: 1,
		Architectures: []state.Architecture{{Family: "x86_64", EcosystemArch: "amd64"}, {Family: "aarch64", EcosystemArch: "arm64"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Files != 9 || len(result.TreeSHA256) != 64 {
		t.Fatalf("result=%#v", result)
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		for _, name := range []string{"Packages", "Packages.gz"} {
			path := filepath.Join(root, "dists", "noble", "main", "binary-"+architecture, name)
			if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
				t.Fatalf("missing %s/%s: info=%v err=%v", architecture, name, info, err)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(root, "dists", "noble", "Release")); err != nil {
		t.Fatal(err)
	}
	release, err := os.ReadFile(filepath.Join(root, "dists", "noble", "Release"))
	if err != nil {
		t.Fatal(err)
	}
	if generation, present, err := parseReleaseGeneration(release); err != nil || !present || generation != 1 {
		t.Fatalf("Release generation=%d present=%t err=%v", generation, present, err)
	}
}

func TestRenderManagedDistRejectsUnknownNeutralAndDuplicateFamilies(t *testing.T) {
	for _, architectures := range [][]state.Architecture{
		{{Family: "all"}},
		{{Family: "noarch"}},
		{{Family: "riscv64"}},
		{{Family: "x86_64", EcosystemArch: "x86_64"}, {Family: "x86_64", EcosystemArch: "x86_64"}},
	} {
		if _, err := RenderManagedDist(context.Background(), t.TempDir(), ManagedDistSpec{Name: "test", Format: "rpm", Architectures: architectures, Generation: 1, Jobs: 1}); err == nil {
			t.Fatalf("architectures %v succeeded", architectures)
		}
	}
}

func TestManagedRendererRequiresExplicitRPMTimestamp(t *testing.T) {
	ctx := context.Background()
	at := time.Unix(1792152000, 0).UTC()
	for _, timestamp := range []int64{0, at.Unix()} {
		root := t.TempDir()
		rendered, err := RenderManagedDist(ctx, root, ManagedDistSpec{Name: "el9", Format: "rpm", Architectures: []state.Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}}, Generation: 1, PublishedAt: at, RPMMetadataTimestamp: timestamp})
		if err != nil {
			t.Fatal(err)
		}
		generation, err := yumrepo.ValidateManagedUnsignedDirectory(ctx, filepath.Join(rendered.Path, "x86_64", "repodata"), yumrepo.CompressionGzip)
		if err != nil {
			t.Fatal(err)
		}
		for _, artifact := range generation.Artifacts {
			if artifact.Timestamp != timestamp {
				t.Fatalf("PublishedAt implicitly changed timestamp: %+v", artifact)
			}
		}
	}
}

func TestAPTGenerationsRemainDistinctWithinOnePublicationSecond(t *testing.T) {
	ctx := context.Background()
	at := time.Unix(1792152000, 0).UTC()
	var previous []byte
	for _, generation := range []state.GenerationID{1, 2} {
		root := t.TempDir()
		_, err := RenderManagedDist(ctx, root, ManagedDistSpec{Name: "noble", Format: "deb", Architectures: []state.Architecture{{Family: "aarch64", EcosystemArch: "arm64"}}, Generation: generation, PublishedAt: at})
		if err != nil {
			t.Fatal(err)
		}
		release, err := os.ReadFile(filepath.Join(root, "dists", "noble", "Release"))
		if err != nil {
			t.Fatal(err)
		}
		got, present, err := parseReleaseGeneration(release)
		if err != nil || !present || got != generation {
			t.Fatalf("generation=%d present=%t err=%v", got, present, err)
		}
		date, err := parseReleaseDate(release)
		if err != nil || !date.Equal(at) {
			t.Fatalf("Date=%s want=%s err=%v", date, at, err)
		}
		if previous != nil && string(previous) == string(release) {
			t.Fatal("same-second Generation did not change Release")
		}
		previous = release
	}
}

func TestRenderManagedDistReturnsCompleteIdentity(t *testing.T) {
	for _, format := range []string{"rpm", "deb"} {
		t.Run(format, func(t *testing.T) {
			ctx := context.Background()
			rendered, err := RenderManagedDist(ctx, t.TempDir(), ManagedDistSpec{
				Name: "test", Format: format, Generation: 7, Jobs: 4,
				Architectures: []state.Architecture{{Family: "aarch64", EcosystemArch: map[string]string{"rpm": "aarch64", "deb": "arm64"}[format]}},
				PublishedAt:   time.Unix(1792152000, 0).UTC(), RPMMetadataTimestamp: 1792152000,
			})
			if err != nil {
				t.Fatal(err)
			}
			digest, files, err := digestTree(ctx, rendered.Path)
			if err != nil || files == 0 || rendered.TreeSHA256 != digest || rendered.Files != files {
				t.Fatalf("renderer identity=%#v; tree digest=%s files=%d error=%v", rendered, digest, files, err)
			}
		})
	}
}

func TestBuildJournalBindsRetainedIndexes(t *testing.T) {
	for _, fixture := range []struct{ format, dist, name, path string }{
		{"rpm", "el9", "pgdg-redhat-nonfree-repo", "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64"},
		{"deb", "noble", "libpqtypes0", "../../aptrepo/testdata/libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"},
	} {
		t.Run(fixture.format, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			options := WorkspaceOptions{Workdir: root, CWD: root}
			cfg := config.Default()
			cfg.Architectures = []string{"aarch64"}
			cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{fixture.dist: {Format: fixture.format}}}
			writeManagedConfig(t, root, cfg)
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			input := decodeManagedFixture(t, fixture.path, filepath.Join(root, "package."+fixture.format))
			if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{fixture.dist}, Paths: []string{input}, Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			live := filepath.Join(root, "repo", "dists", fixture.dist)
			var prior []string
			if fixture.format == "rpm" {
				previous, err := yumrepo.ValidateManagedUnsignedDirectory(ctx, filepath.Join(live, "aarch64", "repodata"), yumrepo.CompressionGzip)
				if err != nil {
					t.Fatal(err)
				}
				for _, artifact := range previous.Artifacts {
					prior = append(prior, filepath.Join("aarch64", artifact.Path))
				}
			} else {
				objects, err := priorAPTByHashObjects(ctx, live, []state.Architecture{{Family: "aarch64", EcosystemArch: "arm64"}})
				if err != nil {
					t.Fatal(err)
				}
				for _, object := range objects {
					prior = append(prior, object.targetRelative)
				}
			}
			if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{fixture.dist}, Packages: []string{fixture.name}, Skip: true, Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("stop after durable build plan")
			if _, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, Fault: func(point string) error {
				if point == "build.staged" {
					return injected
				}
				return nil
			}}); !errors.Is(err, injected) {
				t.Fatalf("staged build error=%v", err)
			}
			store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			operation, err := store.LastOperation(ctx)
			if err != nil || operation == nil {
				store.Close()
				t.Fatalf("operation=%v err=%v", operation, err)
			}
			_, _, manifest, err := loadMutationOperation(ctx, store, root, "repo", operation.ID)
			if closeErr := store.Close(); err != nil || closeErr != nil {
				t.Fatalf("load build plan: %v; close: %v", err, closeErr)
			}
			if manifest.Build == nil || len(manifest.Build.Dists) != 1 {
				t.Fatalf("build plan=%#v", manifest.Build)
			}
			staged := filepath.Join(mutationStageRoot(root, "repo", operation.ID), "build", "dists", fixture.dist)
			digest, _, err := digestTree(ctx, staged)
			if err != nil || digest != manifest.Build.Dists[0].TreeSHA256 {
				t.Fatalf("journal does not bind final staged tree: %s, %v", digest, err)
			}
			var retained string
			for _, rel := range prior {
				path := filepath.Join(staged, rel)
				if info, err := os.Stat(path); err == nil && info.Size() > 0 {
					retained = path
					break
				}
			}
			if retained == "" {
				t.Fatal("nonempty predecessor index was not retained")
			}
			// Replace the stage pathname instead of writing through a retained
			// hardlink, so the public predecessor remains intact.
			if err := os.Remove(retained); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(retained, []byte("corrupt retained index"), 0o644); err != nil {
				t.Fatal(err)
			}
			before, err := publicTreeSnapshot(root, "repo")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1}); err == nil {
				t.Fatal("recovery accepted altered retained index")
			}
			after, err := publicTreeSnapshot(root, "repo")
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("failed recovery changed public tree: %v", err)
			}
		})
	}
}
