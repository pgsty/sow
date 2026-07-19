package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/catalog"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

type lifecycleGenerationFixture struct {
	Generation serving.Generation
	Manifest   string
	Object     repository.Object
}

func TestLoadCanonicalServingLifecycleRejectsChannelPinGenerationMismatch(t *testing.T) {
	root := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	fixture := makeLifecycleGeneration(t, root, pool, "pin-mismatch", "c")
	target, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	channel, err := serving.NewChannelForTarget(fixture.Generation, target, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	seedServingLifecycle(t, canonical, root, []serving.TargetIdentity{target}, []serving.Channel{channel}, []lifecycleGenerationFixture{fixture})
	channel.ManifestSHA256 = strings.Repeat("f", 64)
	if channel.ManifestSHA256 == fixture.Generation.ManifestSHA256 {
		channel.ManifestSHA256 = strings.Repeat("e", 64)
	}
	body, err := channel.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	stage := stageLifecycleBytes(t, t.TempDir(), "forged-channel.json", body)
	if _, changed, err := canonical.InstallPaths(map[string]string{serving.ChannelStatePath(channel): stage}, "test: forge channel generation pin"); err != nil || !changed {
		t.Fatalf("forge channel pin changed=%t err=%v", changed, err)
	}
	if _, err := loadCanonicalServingLifecycle(canonical); err == nil || !strings.Contains(err.Error(), "retained pin differs") {
		t.Fatalf("channel/generation pin mismatch was accepted: %v", err)
	}
}

func makeLifecycleGeneration(t *testing.T, root string, pool *repository.Store, label, commitDigit string) lifecycleGenerationFixture {
	t.Helper()
	object, err := pool.Put(t.Context(), strings.NewReader(label))
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], object.SHA256[:])
	var encoded bytes.Buffer
	if err := manifest.WriteEntry(&encoded, manifest.Entry{Path: "yum/test/x86_64/Packages/p/" + label + ".rpm", Size: object.Size, SHA256: digest}); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, label+".tsv")
	if err := os.WriteFile(manifestPath, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	generation, deriveErr := serving.DeriveGeneration(serving.Identity{
		View: "latest", Repo: "rpm-test", OS: "el10", Arch: "x86_64", LegacyRoot: "yum/test/x86_64",
		RefCommit: strings.Repeat(commitDigit, 40), ConfigSHA256: strings.Repeat("a", 64), RepositoryKeySHA256: strings.Repeat("b", 64),
	}, file)
	closeErr := file.Close()
	if deriveErr != nil || closeErr != nil {
		t.Fatal(errors.Join(deriveErr, closeErr))
	}
	return lifecycleGenerationFixture{Generation: generation, Manifest: manifestPath, Object: object}
}

func stageLifecycleBytes(t *testing.T, root, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func seedServingLifecycle(t *testing.T, canonical *state.Store, root string, targets []serving.TargetIdentity, channels []serving.Channel, generations []lifecycleGenerationFixture) {
	t.Helper()
	staged := make(map[string]string)
	stageRoot := filepath.Join(root, ".sow", "lifecycle-stages")
	configBody := []byte(testConfig)
	if body, err := os.ReadFile(filepath.Join(root, "sow.yaml")); err == nil {
		configBody = body
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	staged["config/sow.yaml"] = stageLifecycleBytes(t, stageRoot, "sow.yaml", configBody)
	for index, target := range targets {
		body, err := target.Canonical("latest")
		if err != nil {
			t.Fatal(err)
		}
		staged[serving.TargetStatePath(target)] = stageLifecycleBytes(t, stageRoot, "target-"+string(rune('a'+index))+".json", body)
	}
	for index, channel := range channels {
		body, err := channel.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		staged[serving.ChannelStatePath(channel)] = stageLifecycleBytes(t, stageRoot, "channel-"+string(rune('a'+index))+".json", body)
	}
	for index, fixture := range generations {
		body, err := fixture.Generation.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		staged[serving.GenerationStatePath(fixture.Generation)] = stageLifecycleBytes(t, stageRoot, "generation-"+string(rune('a'+index))+".json", body)
		manifestBody, err := os.ReadFile(fixture.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		staged[serving.GenerationManifestStatePath(fixture.Generation)] = stageLifecycleBytes(t, stageRoot, "generation-"+string(rune('a'+index))+".tsv", manifestBody)
	}
	if _, _, err := canonical.Apply(t.Context(), "test-serving-lifecycle", "seed serving lifecycle", staged, nil, state.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := catalog.RebuildContext(t.Context(), canonical.StateDir()); err != nil {
		t.Fatalf("seed serving lifecycle catalog: %v", err)
	}
}

func TestCanonicalServingRetentionPinsCurrentPreviousJournalAndSharedTargets(t *testing.T) {
	root := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	first := makeLifecycleGeneration(t, root, pool, "first", "1")
	second := makeLifecycleGeneration(t, root, pool, "second", "2")
	orphan := makeLifecycleGeneration(t, root, pool, "journal", "3")
	targetA, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	targetB, err := serving.NewTargetIdentity("latest", "exports/b", "https://b.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	firstA, err := serving.NewChannelForTarget(first.Generation, targetA, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	currentA, err := serving.NewChannelForTarget(second.Generation, targetA, &firstA, 2)
	if err != nil {
		t.Fatal(err)
	}
	sharedB, err := serving.NewChannelForTarget(first.Generation, targetB, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	seedServingLifecycle(t, canonical, root, []serving.TargetIdentity{targetA, targetB}, []serving.Channel{currentA, sharedB}, []lifecycleGenerationFixture{first, second, orphan})

	paths, err := retainedLocalServingManifestPaths(canonical, targetA, "latest", "rpm-test", "el10", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{serving.GenerationManifestStatePath(first.Generation): true, serving.GenerationManifestStatePath(second.Generation): true}
	for _, path := range paths {
		delete(wanted, path)
	}
	if len(paths) != 2 || len(wanted) != 0 {
		t.Fatalf("retained assembly manifests=%v missing=%v", paths, wanted)
	}

	desired, err := serving.NewChannelForTarget(orphan.Generation, targetA, &currentA, 2)
	if err != nil {
		t.Fatal(err)
	}
	journal := localServingJournal{Generation: orphan.Generation, Channel: desired}
	if expired, err := pruneCanonicalServingGenerationLedgers(t.Context(), canonical, []localServingJournal{journal}); err != nil || len(expired) != 0 {
		t.Fatalf("journal-pinned prune expired=%v err=%v", expired, err)
	}
	expired, err := pruneCanonicalServingGenerationLedgers(t.Context(), canonical, nil)
	if err != nil || len(expired) != 1 || expired[0].Generation.ID != orphan.Generation.ID {
		t.Fatalf("unreferenced prune expired=%v err=%v", expired, err)
	}
	for _, path := range []string{serving.GenerationManifestStatePath(orphan.Generation), serving.GenerationStatePath(orphan.Generation)} {
		if reader, err := canonical.OpenPath(path); err == nil {
			_ = reader.Close()
			t.Fatalf("expired generation ledger remains at %s", path)
		}
	}

	roots, _, err := collectCanonicalRoots(t.Context(), canonical, pool, config.DefaultCASHistory)
	if err != nil {
		t.Fatal(err)
	}
	report, err := pool.Audit(t.Context(), roots)
	if err != nil {
		t.Fatal(err)
	}
	if roots.Count(first.Object.SHA256) != 1 || roots.Count(second.Object.SHA256) != 1 || roots.Count(orphan.Object.SHA256) != 0 || report.Stats.OrphanObjects != 1 {
		t.Fatalf("serving GC roots first=%d second=%d orphan=%d stats=%+v", roots.Count(first.Object.SHA256), roots.Count(second.Object.SHA256), roots.Count(orphan.Object.SHA256), report.Stats)
	}
}

func TestCanonicalServingLifecycleStreamsManifestLargerThanJSONLimit(t *testing.T) {
	root := t.TempDir()
	var encoded bytes.Buffer
	var zeroDigest [32]byte
	for index := 0; index < 170_000; index++ {
		entry := manifest.Entry{
			Path:   fmt.Sprintf("yum/test/x86_64/Packages/p/pkg-%06d.rpm", index),
			Size:   0,
			SHA256: zeroDigest,
		}
		if err := manifest.WriteEntry(&encoded, entry); err != nil {
			t.Fatal(err)
		}
	}
	if encoded.Len() <= maxSecretBytes {
		t.Fatalf("large manifest fixture=%d want>%d", encoded.Len(), maxSecretBytes)
	}
	manifestPath := filepath.Join(root, "large.tsv")
	if err := os.WriteFile(manifestPath, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	generation, err := serving.DeriveGeneration(serving.Identity{
		View: "latest", Repo: "rpm-test", OS: "el10", Arch: "x86_64", LegacyRoot: "yum/test/x86_64",
		RefCommit: strings.Repeat("6", 40), ConfigSHA256: strings.Repeat("a", 64), RepositoryKeySHA256: strings.Repeat("b", 64),
	}, bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	target, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	channel, err := serving.NewChannelForTarget(generation, target, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	seedServingLifecycle(t, canonical, root, []serving.TargetIdentity{target}, []serving.Channel{channel}, []lifecycleGenerationFixture{{Generation: generation, Manifest: manifestPath}})
	lifecycle, err := loadCanonicalServingLifecycle(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if len(lifecycle.Generations) != 1 || len(lifecycle.Channels) != 1 {
		t.Fatalf("large streaming lifecycle=%+v", lifecycle)
	}
}

func TestFullAuthorityServingTopologyRemovesObsoleteLeafButPartialDoesNot(t *testing.T) {
	for _, test := range []struct {
		name          string
		fullAuthority bool
		wantRemoved   bool
	}{
		{name: "partial", fullAuthority: false, wantRemoved: false},
		{name: "full", fullAuthority: true, wantRemoved: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			pool, err := repository.NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			fixture := makeLifecycleGeneration(t, root, pool, "obsolete", "7")
			target, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
			if err != nil {
				t.Fatal(err)
			}
			channel, err := serving.NewChannelForTarget(fixture.Generation, target, nil, 2)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := serving.ReconcileMirrorlist(root, channel); err != nil {
				t.Fatal(err)
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			seedServingLifecycle(t, canonical, root, []serving.TargetIdentity{target}, []serving.Channel{channel}, []lifecycleGenerationFixture{fixture})
			cfg := &config.Config{Root: root}
			result, err := reconcileLocalServingTopology(t.Context(), cfg, canonical, root, "latest", nil, nil, test.fullAuthority, false)
			if err != nil {
				t.Fatal(err)
			}
			_, pointerExists, err := serving.ReadMirrorlist(root, channel.MirrorlistPath)
			if err != nil {
				t.Fatal(err)
			}
			reader, channelErr := canonical.OpenPath(serving.ChannelStatePath(channel))
			if channelErr == nil {
				_ = reader.Close()
			}
			if test.wantRemoved {
				if result.ChannelsRemoved != 1 || result.PointersRemoved != 1 || result.LedgersExpired != 1 || pointerExists || channelErr == nil {
					t.Fatalf("full topology result=%+v pointer=%v channelErr=%v", result, pointerExists, channelErr)
				}
			} else if result != (localServingTopologyResult{}) || !pointerExists || channelErr != nil {
				t.Fatalf("partial topology mutated result=%+v pointer=%v channelErr=%v", result, pointerExists, channelErr)
			}
		})
	}
}

func TestServingTopologyRemovalJournalRecoversAfterCanonicalCommit(t *testing.T) {
	root := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	fixture := makeLifecycleGeneration(t, root, pool, "recover-remove", "8")
	target, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	channel, err := serving.NewChannelForTarget(fixture.Generation, target, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serving.ReconcileMirrorlist(root, channel); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	seedServingLifecycle(t, canonical, root, []serving.TargetIdentity{target}, []serving.Channel{channel}, []lifecycleGenerationFixture{fixture})
	journal := localServingRemovalJournal{Schema: localServingRemovalSchema, Phase: localServingRemovalIntent, TargetRoot: ".", Channel: channel}
	journal.ID = localServingRemovalJournalID(journal)
	if err := createLocalServingRemovalJournal(filepath.Join(root, ".sow"), journal); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.Apply(t.Context(), "test-topology-stop", "commit channel removal before injected stop", nil, nil, state.ApplyOptions{DeletePaths: []string{serving.ChannelStatePath(channel)}}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Root: root}
	if err := prepareLocalServingTopologyRemovals(t.Context(), cfg, canonical, false); err == nil {
		t.Fatal("topology removal journal was ignored without --recover")
	}
	if err := prepareLocalServingTopologyRemovals(t.Context(), cfg, canonical, true); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := serving.ReadMirrorlist(root, channel.MirrorlistPath); err != nil || exists {
		t.Fatalf("recovered topology pointer exists=%v err=%v", exists, err)
	}
	if journals, err := listLocalServingRemovalJournals(filepath.Join(root, ".sow")); err != nil || len(journals) != 0 {
		t.Fatalf("recovered topology journals=%v err=%v", journals, err)
	}
}

func TestCompatibilityTrustRemovalJournalRecoversMidPairWithoutBroadDeletion(t *testing.T) {
	root := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	fixture := makeLifecycleGeneration(t, root, pool, "compat-remove", "9")
	manifestFile, err := os.Open(fixture.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Generation, err = serving.DeriveGeneration(serving.Identity{
		View: "latest", Repo: "infra-legacy-x86-64", OS: "cross-el", Arch: "x86_64", LegacyRoot: "yum/infra/x86_64",
		RefCommit: strings.Repeat("9", 40), ConfigSHA256: strings.Repeat("a", 64), RepositoryKeySHA256: strings.Repeat("b", 64),
	}, manifestFile)
	if closeErr := manifestFile.Close(); err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	target, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	channel, err := serving.NewChannelForTarget(fixture.Generation, target, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serving.ReconcileMirrorlist(root, channel); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	seedServingLifecycle(t, canonical, root, []serving.TargetIdentity{target}, []serving.Channel{channel}, []lifecycleGenerationFixture{fixture})

	type trustFixture struct {
		path   string
		body   []byte
		object repository.Object
	}
	trust := []trustFixture{
		{path: config.YUMCompatibilityPackageTrustRoute(channel.Repo), body: []byte("frozen package trust\n")},
		{path: config.YUMCompatibilityRepositoryTrustRoute(channel.Repo), body: []byte("frozen repository trust\n")},
	}
	journal := localServingRemovalJournal{Schema: localServingRemovalSchema, Phase: localServingRemovalIntent, TargetRoot: ".", Channel: channel}
	for index := range trust {
		trust[index].object, err = pool.Put(t.Context(), bytes.NewReader(trust[index].body))
		if err != nil {
			t.Fatal(err)
		}
		route := filepath.Join(root, filepath.FromSlash(trust[index].path))
		if err := os.MkdirAll(filepath.Dir(route), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(pool.ObjectPath(trust[index].object.SHA256), route); err != nil {
			t.Fatal(err)
		}
		journal.Trust = append(journal.Trust, localServingRemovalTrust{
			Path: trust[index].path, SHA256: trust[index].object.HashString(), Size: trust[index].object.Size,
			Quarantine: localServingTrustQuarantine(trust[index].path, trust[index].object.HashString()),
		})
	}
	sort.Slice(journal.Trust, func(i, j int) bool { return journal.Trust[i].Path < journal.Trust[j].Path })
	journal.ID = localServingRemovalJournalID(journal)
	if err := createLocalServingRemovalJournal(filepath.Join(root, ".sow"), journal); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.Apply(t.Context(), "test-compat-topology-stop", "commit compatibility channel removal before injected stop", nil, nil, state.ApplyOptions{DeletePaths: []string{serving.ChannelStatePath(channel)}}); err != nil {
		t.Fatal(err)
	}
	rawSentinel := stageLifecycleBytes(t, root, "yum/infra/x86_64/raw-rpm", []byte("raw survives\n"))
	generationSentinel := stageLifecycleBytes(t, root, "_sow/v1/g/00000000000000000001/yum/infra/x86_64/repodata/repomd.xml", []byte("generation survives\n"))
	if removed, err := removeLocalServingCompatibilityTrust(t.Context(), pool, root, journal, func(index int) error {
		if index == 0 {
			return errors.New("injected crash between exact trust removals")
		}
		return nil
	}); err == nil || removed != 1 || !strings.Contains(err.Error(), "injected crash") {
		t.Fatalf("mid-pair crash removed=%d err=%v", removed, err)
	}
	first := filepath.Join(root, filepath.FromSlash(journal.Trust[0].Path))
	second := filepath.Join(root, filepath.FromSlash(journal.Trust[1].Path))
	if _, err := os.Lstat(first); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first trust route survived injected crash: %v", err)
	}
	if _, err := os.Lstat(second); err != nil {
		t.Fatalf("second trust route disappeared before recovery: %v", err)
	}
	cfg := &config.Config{Root: root}
	if err := prepareLocalServingTopologyRemovals(t.Context(), cfg, canonical, true); err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{first, second} {
		if _, err := os.Lstat(filename); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovered trust route remains %s: %v", filename, err)
		}
	}
	for _, item := range trust {
		if err := pool.Verify(t.Context(), item.object); err != nil {
			t.Fatalf("CAS object was deleted with public trust route: %v", err)
		}
	}
	for _, filename := range []string{rawSentinel, generationSentinel} {
		if body, err := os.ReadFile(filename); err != nil || len(body) == 0 {
			t.Fatalf("out-of-scope rollback byte %s changed: body=%q err=%v", filename, body, err)
		}
	}
	if journals, err := listLocalServingRemovalJournals(filepath.Join(root, ".sow")); err != nil || len(journals) != 0 {
		t.Fatalf("recovered compatibility removal journals=%v err=%v", journals, err)
	}
}

func TestCompatibilityTrustRemovalBindsRootAndExactParent(t *testing.T) {
	for _, replacement := range []string{"root", "parent"} {
		t.Run(replacement, func(t *testing.T) {
			root := t.TempDir()
			pool, err := repository.NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			fixture := makeLifecycleGeneration(t, root, pool, "compat-bound-"+replacement, "a")
			manifestFile, err := os.Open(fixture.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			fixture.Generation, err = serving.DeriveGeneration(serving.Identity{
				View: "latest", Repo: "infra-legacy-x86-64", OS: "cross-el", Arch: "x86_64", LegacyRoot: "yum/infra/x86_64",
				RefCommit: strings.Repeat("a", 40), ConfigSHA256: strings.Repeat("b", 64), RepositoryKeySHA256: strings.Repeat("c", 64),
			}, manifestFile)
			if closeErr := manifestFile.Close(); err != nil || closeErr != nil {
				t.Fatal(errors.Join(err, closeErr))
			}
			target, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
			if err != nil {
				t.Fatal(err)
			}
			channel, err := serving.NewChannelForTarget(fixture.Generation, target, nil, 2)
			if err != nil {
				t.Fatal(err)
			}
			journal := localServingRemovalJournal{Schema: localServingRemovalSchema, Phase: localServingRemovalPointerRemoved, TargetRoot: ".", Channel: channel}
			objects := make(map[string]repository.Object)
			for route, body := range map[string][]byte{
				config.YUMCompatibilityPackageTrustRoute(channel.Repo):    []byte("bound package trust\n"),
				config.YUMCompatibilityRepositoryTrustRoute(channel.Repo): []byte("bound repository trust\n"),
			} {
				object, err := pool.Put(t.Context(), bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				objects[route] = object
				physical := filepath.Join(root, filepath.FromSlash(route))
				if err := os.MkdirAll(filepath.Dir(physical), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(pool.ObjectPath(object.SHA256), physical); err != nil {
					t.Fatal(err)
				}
				journal.Trust = append(journal.Trust, localServingRemovalTrust{
					Path: route, SHA256: object.HashString(), Size: object.Size,
					Quarantine: localServingTrustQuarantine(route, object.HashString()),
				})
			}
			sort.Slice(journal.Trust, func(i, j int) bool { return journal.Trust[i].Path < journal.Trust[j].Path })
			journal.ID = localServingRemovalJournalID(journal)
			trustParentRelative := filepath.Dir(filepath.FromSlash(journal.Trust[0].Path))
			originalParent := filepath.Join(root, trustParentRelative)
			displaced := originalParent + "-bound"
			if replacement == "root" {
				displaced = root + "-bound"
			}
			var replacementCanary string
			afterBind := func() error {
				if replacement == "root" {
					if err := os.Rename(root, displaced); err != nil {
						return err
					}
					if err := os.Mkdir(root, 0o755); err != nil {
						return err
					}
				} else {
					if err := os.Rename(originalParent, displaced); err != nil {
						return err
					}
				}
				newParent := filepath.Join(root, trustParentRelative)
				if err := os.MkdirAll(newParent, 0o755); err != nil {
					return err
				}
				for route, object := range objects {
					relativeObject, err := filepath.Rel(pool.Root(), pool.ObjectPath(object.SHA256))
					if err != nil {
						return err
					}
					source := pool.ObjectPath(object.SHA256)
					if replacement == "root" {
						source = filepath.Join(displaced, relativeObject)
					}
					if err := os.Link(source, filepath.Join(root, filepath.FromSlash(route))); err != nil {
						return err
					}
				}
				replacementCanary = filepath.Join(newParent, "out-of-scope-canary")
				return os.WriteFile(replacementCanary, []byte("must survive\n"), 0o644)
			}
			removed, removeErr := removeLocalServingCompatibilityTrustWithHooks(t.Context(), pool, root, journal, afterBind, nil)
			if removeErr == nil || !errors.Is(removeErr, repository.ErrUnsafePath) || removed != 2 {
				t.Fatalf("%s replacement removed=%d err=%v", replacement, removed, removeErr)
			}
			if body, err := os.ReadFile(replacementCanary); err != nil || string(body) != "must survive\n" {
				t.Fatalf("replacement canary body=%q err=%v", body, err)
			}
			for route := range objects {
				if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(route))); err != nil {
					t.Fatalf("replacement route %s was touched: %v", route, err)
				}
				oldRoute := filepath.Join(displaced, filepath.FromSlash(route))
				if replacement == "parent" {
					oldRoute = filepath.Join(displaced, filepath.Base(filepath.FromSlash(route)))
				}
				if _, err := os.Lstat(oldRoute); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("bound old route %s survived exact removal: %v", oldRoute, err)
				}
			}
			if replacement == "root" {
				if err := os.RemoveAll(root); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(displaced, root); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.RemoveAll(originalParent); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(displaced, originalParent); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestCompatibilityTrustRemovalRejectsInitiallySymlinkedParent(t *testing.T) {
	root := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	fixture := makeLifecycleGeneration(t, root, pool, "compat-initial-parent-symlink", "a")
	manifestFile, err := os.Open(fixture.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Generation, err = serving.DeriveGeneration(serving.Identity{
		View: "latest", Repo: "infra-legacy-x86-64", OS: "cross-el", Arch: "x86_64", LegacyRoot: "yum/infra/x86_64",
		RefCommit: strings.Repeat("a", 40), ConfigSHA256: strings.Repeat("b", 64), RepositoryKeySHA256: strings.Repeat("c", 64),
	}, manifestFile)
	if closeErr := manifestFile.Close(); err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	target, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	channel, err := serving.NewChannelForTarget(fixture.Generation, target, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	journal := localServingRemovalJournal{Schema: localServingRemovalSchema, Phase: localServingRemovalPointerRemoved, TargetRoot: ".", Channel: channel}
	for route, body := range map[string][]byte{
		config.YUMCompatibilityPackageTrustRoute(channel.Repo):    []byte("symlinked package trust\n"),
		config.YUMCompatibilityRepositoryTrustRoute(channel.Repo): []byte("symlinked repository trust\n"),
	} {
		object, err := pool.Put(t.Context(), bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		physical := filepath.Join(root, filepath.FromSlash(route))
		if err := os.MkdirAll(filepath.Dir(physical), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(pool.ObjectPath(object.SHA256), physical); err != nil {
			t.Fatal(err)
		}
		journal.Trust = append(journal.Trust, localServingRemovalTrust{
			Path: route, SHA256: object.HashString(), Size: object.Size,
			Quarantine: localServingTrustQuarantine(route, object.HashString()),
		})
	}
	sort.Slice(journal.Trust, func(i, j int) bool { return journal.Trust[i].Path < journal.Trust[j].Path })
	journal.ID = localServingRemovalJournalID(journal)
	parentRelative := filepath.Dir(filepath.FromSlash(journal.Trust[0].Path))
	parent := filepath.Join(root, parentRelative)
	realParent := parent + "-real"
	if err := os.Rename(parent, realParent); err != nil {
		t.Fatal(err)
	}
	relativeTarget, err := filepath.Rel(filepath.Dir(parent), realParent)
	if err != nil || filepath.IsAbs(relativeTarget) {
		t.Fatalf("relative symlink target=%q err=%v", relativeTarget, err)
	}
	if err := os.Symlink(relativeTarget, parent); err != nil {
		t.Fatal(err)
	}
	removed, err := removeLocalServingCompatibilityTrust(t.Context(), pool, root, journal, nil)
	if err == nil || !errors.Is(err, repository.ErrUnsafePath) || removed != 0 {
		t.Fatalf("initially symlinked trust parent removed=%d err=%v", removed, err)
	}
	if info, err := os.Lstat(parent); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("initial trust parent symlink changed: info=%v err=%v", info, err)
	}
	for _, trust := range journal.Trust {
		if _, err := os.Lstat(filepath.Join(realParent, filepath.Base(filepath.FromSlash(trust.Path)))); err != nil {
			t.Fatalf("trust route behind rejected symlink was touched: %v", err)
		}
	}
}

func TestServingTopologyRecoveryCleansOnlyExactBoundedJournalTemps(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, ".sow")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, _, err := localServingRemovalDirectory(stateRoot, true)
	if err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(directory, strings.Repeat("a", 32)+".json.tmp-"+strings.Repeat("b", 16))
	if err := os.WriteFile(temporary, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Root: root}
	canonical := state.New(stateRoot)
	if err := prepareLocalServingTopologyRemovals(t.Context(), cfg, canonical, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact topology journal temp remains: %v", err)
	}

	unsafe := filepath.Join(directory, strings.Repeat("c", 32)+".json.tmp-"+strings.Repeat("d", 16))
	if err := os.Symlink(t.TempDir(), unsafe); err != nil {
		t.Fatal(err)
	}
	if err := prepareLocalServingTopologyRemovals(t.Context(), cfg, canonical, true); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("unsafe topology journal temp accepted: %v", err)
	}
}

func TestExplicitServingBaseURLMigrationIsParentBoundAcrossAToBToA(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	targetRelative := "export-switch"
	baseA := "https://a.example.invalid"
	baseB := "https://b.example.invalid"
	materialize := func(baseURL string) {
		t.Helper()
		code, stdout, stderr := runServingCLI(t,
			"materialize", "latest", "--config", configPath, "--repo", "rpm-test",
			"--target", targetRelative, "--serving-base-url", baseURL,
			"--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2",
		)
		if code != ExitOK {
			t.Fatalf("materialize base=%s code=%d stdout=%s stderr=%s", baseURL, code, stdout, stderr)
		}
		body, err := os.ReadFile(filepath.Join(root, targetRelative, "_sow", "v1", "mirrorlist", "latest", "rpm-test", "el10", "x86_64.txt"))
		if err != nil || !strings.HasPrefix(string(body), baseURL+"/_sow/v1/g/") {
			t.Fatalf("base=%s mirrorlist=%q err=%v", baseURL, body, err)
		}
	}
	materialize(baseA)
	materialize(baseB)
	materialize(baseA)

	canonical := state.New(filepath.Join(root, ".sow"))
	targetA, err := serving.NewTargetIdentity("latest", targetRelative, baseA)
	if err != nil {
		t.Fatal(err)
	}
	targetB, err := serving.NewTargetIdentity("latest", targetRelative, baseB)
	if err != nil {
		t.Fatal(err)
	}
	channelAPath := serving.ChannelStatePath(serving.Channel{TargetID: targetA.ID, View: "latest", Repo: "rpm-test", OS: "el10", Arch: "x86_64"})
	reader, err := canonical.OpenPath(channelAPath)
	if err != nil {
		t.Fatalf("final A channel missing: %v", err)
	}
	_ = reader.Close()
	channelBPath := serving.ChannelStatePath(serving.Channel{TargetID: targetB.ID, View: "latest", Repo: "rpm-test", OS: "el10", Arch: "x86_64"})
	if reader, err := canonical.OpenPath(channelBPath); err == nil {
		_ = reader.Close()
		t.Fatalf("retired B channel remains at %s", channelBPath)
	}
}

func TestFullMaterializeRemovesYUMTopologyWhenViewHasZeroYUMLeaves(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	withAsset := strings.Replace(servingYUMConfig(), "upstreams: []", `  - id: assets
    type: asset
    path: pkg
    default_pool: public
    asset: {kind: tools}
upstreams: []`, 1)
	if err := os.WriteFile(configPath, []byte(withAsset), 0o600); err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "package.rpm"))
	_, keyPath := writeMaterializeSigningKey(t, root)
	assetPath := filepath.Join(root, "tool.bin")
	if err := os.WriteFile(assetPath, []byte("tool\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{
		{"add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"},
		{"add", assetPath, "--config", configPath, "--repo", "assets", "--workers", "2", "--chunk-entries", "2"},
		{"promote", "beta", "latest", "--config", configPath},
		{"materialize", "latest", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"},
	} {
		if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
			t.Fatalf("setup %v code=%d stdout=%s stderr=%s", arguments, code, stdout, stderr)
		}
	}
	pointer := filepath.Join(root, "_sow", "v1", "mirrorlist", "latest", "rpm-test", "el10", "x86_64.txt")
	if _, err := os.Stat(pointer); err != nil {
		t.Fatal(err)
	}
	assetOnly := strings.Replace(withAsset,
		"latest: {access: public, allowed_pools: [public], append_only: false}",
		"latest: {access: public, allowed_pools: [public], append_only: false, repos: [assets]}", 1)
	if err := os.WriteFile(configPath, []byte(assetOnly), 0o600); err != nil {
		t.Fatal(err)
	}
	// A view-membership change is a canonical publication input. Commit it
	// through the supported operator workflow before asking materialize to
	// remove the no-longer-owned YUM topology.
	if code, stdout, stderr := runServingCLI(t, "init", "--config", configPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("commit asset-only config code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr := runServingCLI(t, "materialize", "latest", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(stdout, "serving_channels_removed=1") {
		t.Fatalf("asset-only full materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Stat(pointer); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("obsolete YUM mirrorlist remains: %v", err)
	}
}
