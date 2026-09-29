package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
)

func TestCompletedDistRemovalPreservesReaddedPayload(t *testing.T) {
	for _, crash := range []string{"", "dist.rm.finalized", "add.applied"} {
		t.Run(crash, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			opts := WorkspaceOptions{Workdir: root, CWD: root}
			cfg := config.Default()
			cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}, "el8": {Format: "rpm"}}}
			writeManagedConfig(t, root, cfg)
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			input := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(root, "package.rpm"))
			if _, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Skip: true, Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("crash before historical cleanup")
			fault := func(point string) error {
				if point == crash {
					return injected
				}
				return nil
			}
			_, err := RemoveDistResult(ctx, DistRemoveOptions{WorkspaceOptions: opts, Repository: "repo", Name: "el9", Force: true, Fault: fault})
			if crash == "dist.rm.finalized" {
				if !errors.Is(err, injected) {
					t.Fatalf("remove fault: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			_, err = Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el8"}, Paths: []string{input}, Skip: true, Jobs: 1, Fault: fault})
			if crash == "add.applied" {
				if !errors.Is(err, injected) {
					t.Fatalf("add fault: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			// Repeat after promotion too: the old deletion receipt remains in
			// history while the current object has moved from pending to pool.
			for range 2 {
				if _, err := Build(ctx, BuildOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1}); err != nil {
					t.Fatal(err)
				}
				checked, err := Check(ctx, CheckOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1})
				if err != nil || !checked.ReadyToCopy {
					t.Fatalf("check=%+v err=%v", checked, err)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "repo/pool/p/pgdg-redhat-nonfree-repo/package.rpm")); err != nil {
				t.Fatal(err)
			}
		})
	}
}
