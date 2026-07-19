//go:build perf

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

const (
	strongYUMPerfEntries      = 50_000
	strongYUMPerfLeaves       = 4
	strongYUMPerfEntriesLeaf  = strongYUMPerfEntries / strongYUMPerfLeaves
	strongYUMPerfPayloadsLeaf = strongYUMPerfEntriesLeaf - 2
	strongYUMPerfWorkers      = 8
)

type strongYUMPerfObject struct {
	object repository.Object
	path   string
}

type strongYUMPerfPhase struct {
	Wall              time.Duration
	BaselineHeapBytes uint64
	PeakHeapBytes     uint64
	RetainedHeapBytes uint64
	TotalAllocBytes   uint64
	MaxRSSBytes       uint64
}

// TestStrongYUMServingFiftyThousand exercises the actual strong-serving
// production path, not only metadata generation or the generic CAS linker. It
// installs two generations for four repo/OS/arch leaves, replays exact
// current+Previous pins, runs the local strong L1 verifier, and validates the
// serving portion of the GC plan. The raw fixture contains exactly 50,000
// manifest coordinates while 256 immutable CAS objects keep hardlink counts
// below common filesystem limits.
func TestStrongYUMServingFiftyThousand(t *testing.T) {
	if strongYUMPerfEntries%strongYUMPerfLeaves != 0 {
		t.Fatal("performance fixture entries must divide evenly across leaves")
	}
	root := t.TempDir()
	_, keyPath := writeMaterializeSigningKey(t, root)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(strongYUMPerfConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	values := commonFlags{configPath: configPath, workers: strongYUMPerfWorkers, chunk: 1024}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	signedRPMPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "signed-package.rpm"))
	baseRPM, err := os.ReadFile(signedRPMPath)
	if err != nil {
		t.Fatal(err)
	}
	successorRPM := bytes.ReplaceAll(baseRPM, []byte("42.0"), []byte("42.1"))
	if bytes.Equal(successorRPM, baseRPM) {
		t.Fatal("performance RPM fixture does not contain its expected version")
	}
	successorRPMPath := filepath.Join(root, "successor-package.rpm")
	if err := os.WriteFile(successorRPMPath, successorRPM, 0o600); err != nil {
		t.Fatal(err)
	}
	packagePaths := []string{signedRPMPath, successorRPMPath}
	packageObjects := make([]strongYUMPerfObject, len(packagePaths))
	packageInfos := make([]yumrepo.CatalogPackage, len(packagePaths))
	for index, packagePath := range packagePaths {
		input, err := os.Open(packagePath)
		if err != nil {
			t.Fatal(err)
		}
		object, putErr := pool.Put(t.Context(), input)
		closeErr := input.Close()
		if putErr != nil || closeErr != nil {
			t.Fatal(errors.Join(putErr, closeErr))
		}
		info, err := yumrepo.InspectCatalogPackage(t.Context(), yumrepo.PackageInput{Path: packagePath, Basename: fmt.Sprintf("perf-probe-%d.rpm", index)})
		if err != nil {
			t.Fatal(err)
		}
		packageObjects[index] = strongYUMPerfObject{object: object, path: pool.ObjectPath(object.SHA256)}
		packageInfos[index] = info
	}
	if packageInfos[0].Name != packageInfos[1].Name || packageInfos[0].DisplayVersion == packageInfos[1].DisplayVersion {
		t.Fatalf("performance RPM successor identity did not advance: first=%+v second=%+v", packageInfos[0], packageInfos[1])
	}
	objects := make([]strongYUMPerfObject, 256)
	for index := range objects {
		object, err := pool.Put(t.Context(), bytes.NewReader([]byte(fmt.Sprintf("sow-strong-yum-perf-object-%03d\n", index))))
		if err != nil {
			t.Fatal(err)
		}
		objects[index] = strongYUMPerfObject{object: object, path: pool.ObjectPath(object.SHA256)}
	}
	leaves := localServingLeavesFromViewLeaves(selectedLeaves(repos, commonFlags{}))
	if len(leaves) != strongYUMPerfLeaves {
		t.Fatalf("fixture leaves=%d want=%d", len(leaves), strongYUMPerfLeaves)
	}
	viewEntries := make(map[string][]views.Entry, len(leaves))
	globalEntry := 0
	for leafIndex, leaf := range leaves {
		legacyRoot, err := leaf.repo.PathForArch(leaf.arch)
		if err != nil {
			t.Fatal(err)
		}
		packageRoot := filepath.Join(root, filepath.FromSlash(legacyRoot), "Packages", "p")
		metadataRoot := filepath.Join(root, filepath.FromSlash(legacyRoot), "repodata")
		if err := os.MkdirAll(packageRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(metadataRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		for packageIndex := 0; packageIndex < strongYUMPerfPayloadsLeaf; packageIndex++ {
			fixtureObject := objects[globalEntry%len(objects)]
			if packageIndex < 2 {
				fixtureObject = packageObjects[packageIndex]
			}
			basename := fmt.Sprintf("perf-%d-%05d-1.0-1.%s.rpm", leafIndex, packageIndex, leaf.arch)
			relative := filepath.ToSlash(filepath.Join(legacyRoot, "Packages", "p", basename))
			if err := os.Link(fixtureObject.path, filepath.Join(root, filepath.FromSlash(relative))); err != nil {
				t.Fatal(err)
			}
			if packageIndex < 2 {
				packageInfo := packageInfos[packageIndex]
				viewEntries[servingLeafKey(leaf.repo.ID, leaf.os, leaf.arch)] = append(viewEntries[servingLeafKey(leaf.repo.ID, leaf.os, leaf.arch)], views.Entry{
					Repo: leaf.repo.ID, OS: leaf.os, Arch: leaf.arch,
					Name: packageInfo.Name, Version: packageInfo.DisplayVersion,
					Path: relative, Size: fixtureObject.object.Size, SHA256: fixtureObject.object.HashString(), Pool: "public",
				})
			}
			globalEntry++
		}
		for metadataIndex, basename := range []string{"repomd.xml", "repomd.xml.asc"} {
			fixtureObject := objects[(globalEntry+metadataIndex)%len(objects)]
			if err := os.Link(fixtureObject.path, filepath.Join(metadataRoot, basename)); err != nil {
				t.Fatal(err)
			}
		}
		globalEntry += 2
	}
	if globalEntry != strongYUMPerfEntries {
		t.Fatalf("fixture entries=%d want=%d", globalEntry, strongYUMPerfEntries)
	}
	firstCommit := seedStrongYUMPerfView(t, canonical, cfg, leaves, viewEntries, 1, plumbing.ZeroHash)
	privateKey, passphrase, repositoryKeySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, selectedLeaves(repos, commonFlags{}), keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	source := materializeCanonicalSource{ID: "latest", Public: true}
	activate := func(label string) (localServingActivationResult, strongYUMPerfPhase) {
		t.Helper()
		txDir, err := newTransactionDir(cfg.StatePath(), "strong-yum-perf-"+label+"-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(txDir)
		var result localServingActivationResult
		phase, err := measureStrongYUMPerfPhase(func() error {
			var activationErr error
			result, activationErr = activateLocalYUMServing(t.Context(), cfg, canonical, pool, source, root,
				"https://repo.example.invalid", repositoryKeySHA, txDir, leaves, values, localServingActivationOptions{}, os.Stdout)
			return activationErr
		})
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		logStrongYUMPerfPhase(t, label, phase)
		if result.Generations != len(leaves) || result.PeakLeafWorkers < 2 || result.PeakLeafWorkers > min(values.workers, len(leaves)) {
			t.Fatalf("%s activation result=%+v", label, result)
		}
		if result.PeakInstallWorkers < 1 || result.PeakInstallWorkers > int64(values.workers/result.PeakLeafWorkers) {
			t.Fatalf("%s inner install worker peak escaped divided budget: %+v", label, result)
		}
		t.Logf("strong-yum50k activation=%s peak_leaf_workers=%d peak_install_workers_per_leaf=%d combined_peak_worker_bound=%d",
			label, result.PeakLeafWorkers, result.PeakInstallWorkers, int64(result.PeakLeafWorkers)*result.PeakInstallWorkers)
		return result, phase
	}
	first, firstPhase := activate("generation-1")
	if first.Created != len(leaves) {
		t.Fatalf("first activation did not create every generation: %+v", first)
	}
	secondCommit := seedStrongYUMPerfView(t, canonical, cfg, leaves, viewEntries, 2, firstCommit)
	if secondCommit == firstCommit {
		t.Fatal("successor view ref did not advance")
	}
	second, secondPhase := activate("generation-2-current-plus-previous")
	if second.Created != len(leaves) {
		t.Fatalf("successor activation did not create every generation: %+v", second)
	}
	replay, replayPhase := activate("replay-current-plus-previous")
	if replay.Created != 0 {
		t.Fatalf("idempotent replay unexpectedly created generation directories: %+v", replay)
	}

	verifyDir, err := newTransactionDir(cfg.StatePath(), "strong-yum-perf-verify-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(verifyDir)
	checks, err := buildLocalServingL1Checks(cfg, canonical, pool, repos, []string{"latest"}, values, verifyDir)
	if err != nil {
		t.Fatal(err)
	}
	var verification verify.Report
	verifyPhase, err := measureStrongYUMPerfPhase(func() error {
		verification = verify.Run(t.Context(), verify.Request{
			Layers: []verify.Layer{verify.LayerL1}, Checks: checks, Workers: values.workers, MaxFindings: 100,
		})
		if verification.Outcome != verify.OutcomePassed {
			return fmt.Errorf("strong local serving verification outcome=%s findings=%+v", verification.Outcome, verification.Findings)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	logStrongYUMPerfPhase(t, "verify-current-plus-previous", verifyPhase)

	gcDir, err := newTransactionDir(cfg.StatePath(), "strong-yum-perf-gc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(gcDir)
	var gcPlan servingGenerationGCPlan
	gcPhase, err := measureStrongYUMPerfPhase(func() error {
		var collectErr error
		gcPlan, collectErr = collectServingGenerationGCPlan(cfg, canonical, pool)
		if collectErr != nil {
			return collectErr
		}
		if len(gcPlan.Protected) != strongYUMPerfLeaves*2 || len(gcPlan.Directories) != 0 || len(gcPlan.Tombstones) != 0 {
			return fmt.Errorf("unexpected current+Previous GC plan: protected=%d directories=%d tombstones=%d", len(gcPlan.Protected), len(gcPlan.Directories), len(gcPlan.Tombstones))
		}
		return validateServingGenerationGCPlan(t.Context(), cfg, canonical, pool, gcPlan, values, gcDir)
	})
	if err != nil {
		t.Fatal(err)
	}
	logStrongYUMPerfPhase(t, "gc-preflight-current-plus-previous", gcPhase)

	for name, phase := range map[string]strongYUMPerfPhase{
		"generation-1": firstPhase, "generation-2": secondPhase, "replay": replayPhase,
		"verify": verifyPhase, "gc": gcPhase,
	} {
		if phase.Wall > 5*time.Minute {
			t.Fatalf("%s exceeded bounded 5 minute phase budget: %s", name, phase.Wall)
		}
		if phase.PeakHeapBytes > phase.BaselineHeapBytes+512<<20 {
			t.Fatalf("%s heap grew beyond streaming bound: baseline=%d peak=%d", name, phase.BaselineHeapBytes, phase.PeakHeapBytes)
		}
	}
}

func seedStrongYUMPerfView(
	t *testing.T,
	canonical *state.Store,
	cfg *config.Config,
	leaves []localYUMServingLeaf,
	entries map[string][]views.Entry,
	entryCount int,
	expected plumbing.Hash,
) plumbing.Hash {
	t.Helper()
	if entryCount < 1 || entryCount > 2 {
		t.Fatalf("unsupported view fixture entry count %d", entryCount)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "strong-yum-perf-view-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(txDir)
	staged := make(map[string]string, len(leaves))
	updates := make([]state.RefUpdate, 0, len(leaves))
	if expected.IsZero() {
		configStage := filepath.Join(txDir, "sow.yaml")
		if err := os.WriteFile(configStage, []byte(strongYUMPerfConfig), 0o600); err != nil {
			t.Fatal(err)
		}
		staged["config/sow.yaml"] = configStage
	}
	for index, leaf := range leaves {
		key := servingLeafKey(leaf.repo.ID, leaf.os, leaf.arch)
		leafEntries := entries[key]
		if len(leafEntries) < entryCount {
			t.Fatalf("leaf %s has %d view entries, need %d", key, len(leafEntries), entryCount)
		}
		stage := filepath.Join(txDir, fmt.Sprintf("view-%02d.tsv", index))
		file, err := os.OpenFile(stage, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range leafEntries[:entryCount] {
			if err := views.WriteEntry(file, entry); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		canonicalPath, err := state.ViewPath("latest", leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := state.ViewRef("latest", leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			t.Fatal(err)
		}
		staged[canonicalPath] = stage
		updates = append(updates, state.RefUpdate{Name: ref, Expected: expected})
	}
	commit, changed, err := applyCanonicalState(t.Context(), canonical, "strong-yum-perf-view", "test: advance strong YUM performance view", staged, updates, state.ApplyOptions{})
	if err != nil || !changed {
		t.Fatalf("seed performance view changed=%t commit=%s err=%v", changed, commit, err)
	}
	return commit
}

func measureStrongYUMPerfPhase(run func() error) (strongYUMPerfPhase, error) {
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	stop := make(chan struct{})
	peakResult := make(chan uint64, 1)
	go func() {
		peak := baseline.HeapAlloc
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				var sample runtime.MemStats
				runtime.ReadMemStats(&sample)
				if sample.HeapAlloc > peak {
					peak = sample.HeapAlloc
				}
			case <-stop:
				var sample runtime.MemStats
				runtime.ReadMemStats(&sample)
				if sample.HeapAlloc > peak {
					peak = sample.HeapAlloc
				}
				peakResult <- peak
				return
			}
		}
	}()
	started := time.Now()
	err := run()
	elapsed := time.Since(started)
	close(stop)
	peak := <-peakResult
	runtime.GC()
	var retained runtime.MemStats
	runtime.ReadMemStats(&retained)
	totalAlloc := uint64(0)
	if retained.TotalAlloc > baseline.TotalAlloc {
		totalAlloc = retained.TotalAlloc - baseline.TotalAlloc
	}
	return strongYUMPerfPhase{
		Wall: elapsed, BaselineHeapBytes: baseline.HeapAlloc, PeakHeapBytes: peak,
		RetainedHeapBytes: retained.HeapAlloc, TotalAllocBytes: totalAlloc, MaxRSSBytes: strongYUMMaxRSSBytes(),
	}, err
}

func strongYUMMaxRSSBytes() uint64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil || usage.Maxrss < 0 {
		return 0
	}
	value := uint64(usage.Maxrss)
	if runtime.GOOS != "darwin" {
		value *= 1024
	}
	return value
}

func logStrongYUMPerfPhase(t *testing.T, name string, phase strongYUMPerfPhase) {
	t.Helper()
	t.Logf("strong-yum50k phase=%s entries=%d leaves=%d workers=%d wall=%s baseline_heap_bytes=%d peak_heap_bytes=%d retained_heap_bytes=%d total_alloc_bytes=%d max_rss_bytes=%d",
		name, strongYUMPerfEntries, strongYUMPerfLeaves, strongYUMPerfWorkers, phase.Wall,
		phase.BaselineHeapBytes, phase.PeakHeapBytes, phase.RetainedHeapBytes, phase.TotalAllocBytes, phase.MaxRSSBytes)
}

const strongYUMPerfConfig = `schema: sow/v1
state: {snapshot_materialization_months: 6, yum_generation_retention: 1}
gpg:
  public_key: repository-public.pgp
pools:
  public: {}
  gated: {}
repos:
  - id: perf-el8-x86
    type: yum
    path: yum/perf-el8/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 8, lifecycle: frozen}
    yum: {compression: gzip, package_keyring: package-trust.asc}
  - id: perf-el9-arm
    type: yum
    path: yum/perf-el9/aarch64
    default_pool: public
    arches: [aarch64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
  - id: perf-el10-x86
    type: yum
    path: yum/perf-el10/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
  - id: perf-el10-arm
    type: yum
    path: yum/perf-el10/aarch64
    default_pool: public
    arches: [aarch64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: "https://repo.example.invalid"}
  beta: {base_url: "https://beta.example.invalid"}
  stable: {base_url: "https://repo.example.invalid/pro/v1/basic"}
targets: {}
edge:
  token_verifier: provider://test
`
