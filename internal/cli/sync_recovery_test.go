package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

type syncAPTRecoveryFixture struct {
	root         string
	configPath   string
	privatePath  string
	args         []string
	factory      syncClientFactory
	packages     map[string]aptrepo.Package
	upstreamRoot string
	requests     *atomic.Int64
}

func TestSyncRecoveryAfterProvenanceApplyBeforeProgressWriteIsOffline(t *testing.T) {
	fixture := newSyncAPTRecoveryFixture(t, []string{"main"})
	var stdout, stderr bytes.Buffer
	err := runSyncWithClientFactoryAndHooks(context.Background(), fixture.args, &stdout, &stderr, fixture.factory, syncExecutionHooks{
		AfterProvenanceApply: func(config.Upstream, string) error { return errors.New("injected commit-to-progress interruption") },
	})
	assertDurableSyncPartialError(t, err, syncPhaseProvenanceCommitting, "")
	progress := readSyncProgressForTest(t, fixture.root, "pgdg")
	if progress.Phase != syncPhaseProvenanceCommitting || progress.ProvenanceCommit != "" || !syncProgressTxPattern.MatchString(progress.ProvenanceTransaction) {
		t.Fatalf("commit bridge progress=%#v", progress)
	}
	requestsBefore := fixture.requests.Load()
	if err := os.RemoveAll(fixture.upstreamRoot); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if err := runSyncWithClientFactory(context.Background(), fixture.args, &stdout, &stderr, fixture.factory); err != nil {
		t.Fatalf("offline commit-bridge replay: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if fixture.requests.Load() != requestsBefore || !strings.Contains(stdout.String(), "sync recovery upstream=pgdg phase=provenance-committed") || strings.Contains(stdout.String(), "sync upstream=pgdg format=") {
		t.Fatalf("commit bridge rebound upstream: before=%d after=%d stdout=%s", requestsBefore, fixture.requests.Load(), stdout.String())
	}
	assertAPTRecoveryProjection(t, fixture, "main")
	assertSyncProgressRemoved(t, fixture.root, "pgdg")
}

func TestSyncRecoveryAfterProvenanceCommitIsOfflineAndDoesNotDuplicateReceipt(t *testing.T) {
	fixture := newSyncAPTRecoveryFixture(t, []string{"main"})
	var stdout, stderr bytes.Buffer
	err := runSyncWithClientFactoryAndHooks(context.Background(), fixture.args, &stdout, &stderr, fixture.factory, syncExecutionHooks{
		AfterProvenanceCommit: func(config.Upstream, string) error { return errors.New("injected post-provenance interruption") },
	})
	assertDurableSyncPartialError(t, err, syncPhaseProvenanceCommitted, "")
	progress := readSyncProgressForTest(t, fixture.root, "pgdg")
	if progress.ProvenanceCommit == "" || progress.Phase != syncPhaseProvenanceCommitted {
		t.Fatalf("progress=%#v", progress)
	}
	pkg := fixture.packages["main"]
	completedDownload := filepath.Join(fixture.root, ".sow", "sync", "pgdg", "downloads", pkg.SHA256+".download")
	if _, err := os.Stat(completedDownload); err != nil {
		t.Fatalf("interrupted sync did not retain recovery download: %v", err)
	}
	receiptPath := filepath.Join(fixture.root, ".sow", "state", "provenance", "deb", pkg.SHA256+".json")
	before, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(fixture.root, ".sow", "transactions", "sync-pgdg-sigkill-orphan")
	if err := os.Mkdir(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphan, "download-stage"), []byte("abandoned"), 0o600); err != nil {
		t.Fatal(err)
	}
	requestsBefore := fixture.requests.Load()
	if err := os.RemoveAll(fixture.upstreamRoot); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	if err := runSyncWithClientFactory(context.Background(), fixture.args, &stdout, &stderr, fixture.factory); err != nil {
		t.Fatalf("ordinary replay: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "sync recovery upstream=pgdg") || strings.Contains(stdout.String(), "sync upstream=pgdg format=") {
		t.Fatalf("missing replay evidence: %s", stdout.String())
	}
	if fixture.requests.Load() != requestsBefore {
		t.Fatalf("committed retry consulted mutated upstream: before=%d after=%d", requestsBefore, fixture.requests.Load())
	}
	after, err := os.ReadFile(receiptPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("provenance receipt duplicated or changed err=%v", err)
	}
	assertSyncProgressRemoved(t, fixture.root, "pgdg")
	if _, err := os.Lstat(completedDownload); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed recovery retained duplicate transport body: %v", err)
	}
	if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("SIGKILL transaction residue was not cleaned: %v", err)
	}
	assertAPTRecoveryProjection(t, fixture, "main")
}

func TestSyncRecoveryPreservesLaterUnrelatedCanonicalConfig(t *testing.T) {
	fixture := newSyncAPTRecoveryFixture(t, []string{"main"})
	var stdout, stderr bytes.Buffer
	err := runSyncWithClientFactoryAndHooks(context.Background(), fixture.args, &stdout, &stderr, fixture.factory, syncExecutionHooks{
		AfterProvenanceCommit: func(config.Upstream, string) error { return context.Canceled },
	})
	if err == nil {
		t.Fatal("fixture did not stop after provenance commit")
	}
	original, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(original), "state: {}", "state: {cas_history_commits: 33}", 1)
	changedPath := filepath.Join(fixture.root, "changed.yaml")
	if err := os.WriteFile(changedPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(fixture.root, "apt", "test"), 0o755); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if err := runInit(context.Background(), []string{"--config", changedPath, "--repo", "apt-test", "--workers", "1", "--chunk-entries", "2"}, &stdout, &stderr); err != nil {
		t.Fatalf("later unrelated config commit: %v stderr=%s", err, stderr.String())
	}
	canonicalPath := filepath.Join(fixture.root, ".sow", "state", "config", "sow.yaml")
	later, err := os.ReadFile(canonicalPath)
	if err != nil || !strings.Contains(string(later), "cas_history_commits: 33") {
		t.Fatalf("later config was not canonicalized: %v %s", err, later)
	}
	requestsBefore := fixture.requests.Load()
	if err := os.RemoveAll(fixture.upstreamRoot); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if err := runSyncWithClientFactory(context.Background(), fixture.args, &stdout, &stderr, fixture.factory); err != nil {
		t.Fatalf("offline recovery: %v stderr=%s", err, stderr.String())
	}
	after, err := os.ReadFile(canonicalPath)
	if err != nil || !bytes.Equal(after, later) || fixture.requests.Load() != requestsBefore {
		t.Fatalf("offline recovery changed newer config or upstream: same=%t requests=%d/%d err=%v", bytes.Equal(after, later), requestsBefore, fixture.requests.Load(), err)
	}
	wantConfigSHA := fmt.Sprintf("config_sha256=%x", sha256.Sum256(later))
	if !strings.Contains(stdout.String(), wantConfigSHA) {
		t.Fatalf("sync recovery log did not bind preserved canonical config %s: %s", wantConfigSHA, stdout.String())
	}
}

func TestSyncRecoveryRejectsImplicitCanonicalDimensionMigrationWithoutResurrection(t *testing.T) {
	fixture := newSyncAPTRecoveryFixture(t, []string{"main"})
	original, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	wide := strings.Replace(string(original), "    arches: [arm64]\n    os:", "    arches: [amd64, arm64]\n    os:", 1)
	wide = strings.Replace(wide, "apt: {suites: [jammy],", "apt: {suites: [jammy, noble],", 1)
	if wide == string(original) || !strings.Contains(wide, "suites: [jammy, noble]") || !strings.Contains(wide, "arches: [amd64, arm64]") {
		t.Fatal("failed to widen recovery fixture repository dimensions")
	}
	if err := os.WriteFile(fixture.configPath, []byte(wide), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(fixture.root, "apt", "test"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := runInit(context.Background(), []string{"--config", fixture.configPath, "--repo", "apt-test", "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr); err != nil {
		t.Fatalf("initialize wide sync config: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	input := filepath.Join(fixture.upstreamRoot, filepath.FromSlash(fixture.packages["main"].PoolPath))
	stdout.Reset()
	stderr.Reset()
	if err := runAdd(context.Background(), []string{input, "--config", fixture.configPath, "--repo", "apt-test", "--os", "noble", "--arch", "arm64", "--component", "main", "--gpg-private-key-file", fixture.privatePath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr); err != nil {
		t.Fatalf("seed old unrelated suite: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	err = runSyncWithClientFactoryAndHooks(context.Background(), fixture.args, &stdout, &stderr, fixture.factory, syncExecutionHooks{
		AfterProvenanceCommit: func(config.Upstream, string) error { return context.Canceled },
	})
	assertDurableSyncPartialError(t, err, syncPhaseProvenanceCommitted, "")

	current := strings.Replace(wide, "arches: [amd64, arm64]", "arches: [arm64, ppc64le]", 1)
	current = strings.Replace(current, "suites: [jammy, noble]", "suites: [jammy, focal]", 1)
	currentPath := filepath.Join(fixture.root, "current.yaml")
	if err := os.WriteFile(currentPath, []byte(current), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if err := runInit(context.Background(), []string{"--config", currentPath, "--repo", "apt-test", "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "explicit physical migration is required") {
		t.Fatalf("implicit canonical dimension migration was not rejected: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	target := filepath.Join(fixture.root, ".sow", "materialized", "beta", "apt", "test", "dists")
	noblePackages := filepath.Join(target, "noble", "main", "binary-arm64", "Packages")
	if body, err := os.ReadFile(noblePackages); err != nil || !strings.Contains(string(body), fixture.packages["main"].SHA256) {
		t.Fatalf("accepted canonical noble suite was not preserved after rejected migration: err=%v body=%s", err, body)
	}
	if _, err := os.Lstat(filepath.Join(target, "focal")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected focal suite reached the materialized tree: %v", err)
	}

	requestsBefore := fixture.requests.Load()
	if err := os.RemoveAll(fixture.upstreamRoot); err != nil {
		t.Fatal(err)
	}
	hookObserved := false
	stdout.Reset()
	stderr.Reset()
	err = runSyncWithClientFactoryAndHooks(context.Background(), fixture.args, &stdout, &stderr, fixture.factory, syncExecutionHooks{
		AfterAPTComponent: func(_ config.Upstream, _ string) error {
			hookObserved = true
			if _, statErr := os.Lstat(filepath.Join(target, "focal")); !errors.Is(statErr, os.ErrNotExist) {
				return fmt.Errorf("recovery resurrected rejected focal suite: %v", statErr)
			}
			if body, readErr := os.ReadFile(noblePackages); readErr != nil || !strings.Contains(string(body), fixture.packages["main"].SHA256) {
				return fmt.Errorf("recovery pruned accepted noble suite: %v", readErr)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("offline current-dimension recovery: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if !hookObserved {
		t.Fatal("offline replay did not exercise the APT ingestion boundary")
	}
	if fixture.requests.Load() != requestsBefore {
		t.Fatalf("dimension recovery rebound unavailable upstream: before=%d after=%d", requestsBefore, fixture.requests.Load())
	}
	if _, err := os.Lstat(filepath.Join(target, "focal")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected suite was resurrected after final projection: %v", err)
	}
	for _, suite := range []string{"jammy", "noble"} {
		packagesPath := filepath.Join(target, suite, "main", "binary-arm64", "Packages")
		if body, err := os.ReadFile(packagesPath); err != nil || !strings.Contains(string(body), fixture.packages["main"].SHA256) {
			t.Fatalf("configured suite %s was not preserved: err=%v body=%s", suite, err, body)
		}
	}
	assertSyncProgressRemoved(t, fixture.root, "pgdg")
}

func TestSyncRecoveryRejectsChangedFrozenRepositoryContracts(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, syncAPTRecoveryFixture, string) string
	}{
		{
			name: "apt-by-hash-retention",
			mutate: func(t *testing.T, _ syncAPTRecoveryFixture, original string) string {
				t.Helper()
				changed := strings.Replace(original, "state: {}", "state: {apt_by_hash_retention: 17}", 1)
				if changed == original {
					t.Fatal("fixture state stanza not found")
				}
				return changed
			},
		},
		{
			name: "repository-signing-key",
			mutate: func(t *testing.T, fixture syncAPTRecoveryFixture, original string) string {
				t.Helper()
				created := time.Unix(1_600_000_000, 0).UTC()
				rotated, err := openpgp.NewEntity("Rotated SOW Repository Key", "", "rotated@example.invalid", &packet.Config{
					Time: func() time.Time { return created }, RSABits: testOpenPGPRSABits,
				})
				if err != nil {
					t.Fatal(err)
				}
				var public bytes.Buffer
				armored, err := armor.Encode(&public, openpgp.PublicKeyType, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := rotated.Serialize(armored); err != nil {
					t.Fatal(err)
				}
				if err := armored.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(fixture.root, "rotated.asc"), public.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				changed := strings.Replace(original, "public_key: upstream.asc", "public_key: rotated.asc", 1)
				if changed == original {
					t.Fatal("fixture GPG stanza not found")
				}
				return changed
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSyncAPTRecoveryFixture(t, []string{"main"})
			var stdout, stderr bytes.Buffer
			err := runSyncWithClientFactoryAndHooks(context.Background(), fixture.args, &stdout, &stderr, fixture.factory, syncExecutionHooks{
				AfterProvenanceCommit: func(config.Upstream, string) error { return context.Canceled },
			})
			if err == nil {
				t.Fatal("fixture did not stop after provenance commit")
			}
			original, err := os.ReadFile(fixture.configPath)
			if err != nil {
				t.Fatal(err)
			}
			changedPath := filepath.Join(fixture.root, "changed-"+test.name+".yaml")
			if err := os.WriteFile(changedPath, []byte(test.mutate(t, fixture, string(original))), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(fixture.root, "apt", "test"), 0o755); err != nil {
				t.Fatal(err)
			}
			stdout.Reset()
			stderr.Reset()
			if err := runInit(context.Background(), []string{"--config", changedPath, "--repo", "apt-test", "--workers", "1", "--chunk-entries", "2"}, &stdout, &stderr); err != nil {
				t.Fatalf("install changed canonical contract: %v stderr=%s", err, stderr.String())
			}

			for _, recover := range []bool{false, true} {
				stdout.Reset()
				stderr.Reset()
				args := append([]string(nil), fixture.args...)
				if recover {
					args = append(args, "--recover")
				}
				err = runSyncWithClientFactory(context.Background(), args, &stdout, &stderr, fixture.factory)
				if err == nil || !strings.Contains(err.Error(), "canonical DEB sync contract changed") || !strings.Contains(err.Error(), "durable_partial_commit=true") {
					t.Fatalf("recovery recover=%t did not fail closed: err=%v stdout=%s stderr=%s", recover, err, stdout.String(), stderr.String())
				}
			}
			viewPath := filepath.Join(fixture.root, ".sow", "state", "views", "beta", "apt-test", "jammy", "arm64", "main.tsv")
			if body, readErr := os.ReadFile(viewPath); readErr == nil && strings.Contains(string(body), fixture.packages["main"].SHA256) {
				t.Fatal("changed frozen contract was detected only after package projection")
			} else if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
				t.Fatal(readErr)
			}
		})
	}
}

func TestSyncRecoveryRejectsInPlaceRepositoryKeyRotation(t *testing.T) {
	fixture := newSyncAPTRecoveryFixture(t, []string{"main"})
	var stdout, stderr bytes.Buffer
	err := runSyncWithClientFactoryAndHooks(context.Background(), fixture.args, &stdout, &stderr, fixture.factory, syncExecutionHooks{
		AfterProvenanceCommit: func(config.Upstream, string) error { return context.Canceled },
	})
	if err == nil {
		t.Fatal("fixture did not stop after provenance commit")
	}

	created := time.Unix(1_600_000_000, 0).UTC()
	rotated, err := openpgp.NewEntity("Rotated In Place", "", "rotated-in-place@example.invalid", &packet.Config{
		Time: func() time.Time { return created }, RSABits: testOpenPGPRSABits,
	})
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	if err := rotated.SerializePrivate(&private, &packet.Config{Time: func() time.Time { return created }}); err != nil {
		t.Fatal(err)
	}
	var public bytes.Buffer
	armored, err := armor.Encode(&public, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotated.Serialize(armored); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.root, "upstream.asc"), public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.privatePath, private.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	requestsBefore := fixture.requests.Load()
	if err := os.RemoveAll(fixture.upstreamRoot); err != nil {
		t.Fatal(err)
	}
	for _, recover := range []bool{false, true} {
		stdout.Reset()
		stderr.Reset()
		args := append([]string(nil), fixture.args...)
		if recover {
			args = append(args, "--recover")
		}
		err = runSyncWithClientFactory(context.Background(), args, &stdout, &stderr, fixture.factory)
		if err == nil || !strings.Contains(err.Error(), "durable_partial_commit=true") {
			t.Fatalf("same-path repository key rotation recover=%t was not frozen: err=%v stdout=%s stderr=%s", recover, err, stdout.String(), stderr.String())
		}
	}
	if fixture.requests.Load() != requestsBefore {
		t.Fatalf("key-rotation rejection rebound unavailable upstream: before=%d after=%d", requestsBefore, fixture.requests.Load())
	}
	viewPath := filepath.Join(fixture.root, ".sow", "state", "views", "beta", "apt-test", "jammy", "arm64", "main.tsv")
	if body, readErr := os.ReadFile(viewPath); readErr == nil && strings.Contains(string(body), fixture.packages["main"].SHA256) {
		t.Fatal("same-path key rotation was detected only after package projection")
	} else if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		t.Fatal(readErr)
	}
	readSyncProgressForTest(t, fixture.root, "pgdg")
}

func TestRecoverDiscardsOnlyUnstartedSyncIntents(t *testing.T) {
	for _, phase := range []syncProgressPhase{syncPhasePrepared, syncPhaseProvenanceCommitting} {
		t.Run(string(phase), func(t *testing.T) {
			fixture := newSyncAPTRecoveryFixture(t, []string{"main"})
			cfg, err := config.Load(fixture.configPath, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(cfg.StatePath(), 0o700); err != nil {
				t.Fatal(err)
			}
			repo, ok := cfg.RepoByName("apt-test")
			if !ok {
				t.Fatal("fixture repo missing")
			}
			source := cfg.Upstreams[0]
			progress, err := newSyncProgress(cfg, repo, source)
			if err != nil {
				t.Fatal(err)
			}
			operation, err := acquireSyncOperation(context.Background(), cfg.StatePath(), source.ID)
			if err != nil {
				t.Fatal(err)
			}
			pkg := fixture.packages["main"]
			replay := syncReplayRecord{
				Format: "deb", SHA256: pkg.SHA256, Size: pkg.Size, Name: pkg.Name,
				Version: pkg.Version, Arch: pkg.Architecture, Basename: filepath.Base(pkg.PoolPath), Component: "main",
			}
			progress.ReplaySHA256, progress.ReplayCount, err = operation.WriteReplay([]syncReplayRecord{replay}, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			progress.ProvenanceInputSHA256 = strings.Repeat("a", 64)
			progress.Phase = phase
			if phase == syncPhaseProvenanceCommitting {
				progress.ProvenanceTransaction, err = state.NewTransactionID()
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := operation.Write(progress); err != nil {
				t.Fatal(err)
			}
			if err := operation.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(fixture.upstreamRoot); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string(nil), fixture.args...), "--recover")
			_ = runSyncWithClientFactory(context.Background(), args, io.Discard, io.Discard, fixture.factory)
			if _, err := os.Lstat(filepath.Join(cfg.StatePath(), "sync", source.ID, syncProgressFilename)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("recover retained unstarted %s intent: %v", phase, err)
			}
		})
	}
}

func TestRecoverDiscardsUncommittedPreparedIntentAfterContractChange(t *testing.T) {
	fixture := newSyncAPTRecoveryFixture(t, []string{"main"})
	cfg, err := config.Load(fixture.configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.StatePath(), 0o700); err != nil {
		t.Fatal(err)
	}
	repo, ok := cfg.RepoByName("apt-test")
	if !ok {
		t.Fatal("fixture repo missing")
	}
	source := cfg.Upstreams[0]
	progress, err := newSyncProgress(cfg, repo, source)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := acquireSyncOperation(context.Background(), cfg.StatePath(), source.ID)
	if err != nil {
		t.Fatal(err)
	}
	pkg := fixture.packages["main"]
	replay := syncReplayRecord{
		Format: "deb", SHA256: pkg.SHA256, Size: pkg.Size, Name: pkg.Name,
		Version: pkg.Version, Arch: pkg.Architecture, Basename: filepath.Base(pkg.PoolPath), Component: "main",
	}
	progress.ReplaySHA256, progress.ReplayCount, err = operation.WriteReplay([]syncReplayRecord{replay}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	progress.ProvenanceInputSHA256 = strings.Repeat("a", 64)
	if err := operation.Write(progress); err != nil {
		t.Fatal(err)
	}
	if err := operation.Close(); err != nil {
		t.Fatal(err)
	}

	original, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(original), "state: {}", "state: {apt_by_hash_retention: 17}", 1)
	changedPath := filepath.Join(fixture.root, "changed-recovery.yaml")
	if err := os.WriteFile(changedPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string(nil), fixture.args...)
	for index := range args {
		if args[index] == fixture.configPath {
			args[index] = changedPath
		}
	}
	args = append(args, "--recover")
	if err := os.RemoveAll(fixture.upstreamRoot); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	_ = runSyncWithClientFactory(context.Background(), args, &stdout, io.Discard, fixture.factory)
	if !strings.Contains(stdout.String(), "discarded_uncommitted_intent=true phase=prepared") {
		t.Fatalf("recovery did not report safe prepared-intent discard: %s", stdout.String())
	}
	if _, err := os.Lstat(filepath.Join(cfg.StatePath(), "sync", source.ID, syncProgressFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recover retained pre-commit intent after contract change: %v", err)
	}
}

func TestSyncRecoveryBetweenAPTComponentsConvergesAllIndexes(t *testing.T) {
	fixture := newSyncAPTRecoveryFixture(t, []string{"contrib", "main"})
	var calls int
	var stdout, stderr bytes.Buffer
	err := runSyncWithClientFactoryAndHooks(context.Background(), fixture.args, &stdout, &stderr, fixture.factory, syncExecutionHooks{
		AfterAPTComponent: func(_ config.Upstream, component string) error {
			calls++
			if calls == 1 {
				return fmt.Errorf("injected interruption after %s", component)
			}
			return nil
		},
	})
	assertDurableSyncPartialError(t, err, syncPhaseProvenanceCommitted, "apt:contrib")
	progress := readSyncProgressForTest(t, fixture.root, "pgdg")
	if strings.Join(progress.CompletedUnits, ",") != "apt:contrib" {
		t.Fatalf("completed units=%v", progress.CompletedUnits)
	}
	requestsBefore := fixture.requests.Load()

	stdout.Reset()
	stderr.Reset()
	if err := runSyncWithClientFactory(context.Background(), fixture.args, &stdout, &stderr, fixture.factory); err != nil {
		t.Fatalf("component replay: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if strings.Count(stdout.String(), "added format=deb packages=1") != 1 {
		t.Fatalf("replay did not ingest exactly the missing component: %s", stdout.String())
	}
	if fixture.requests.Load() != requestsBefore {
		t.Fatalf("component replay rebound upstream snapshot: before=%d after=%d", requestsBefore, fixture.requests.Load())
	}
	for _, component := range []string{"contrib", "main"} {
		assertAPTRecoveryProjection(t, fixture, component)
	}
	receipts, err := filepath.Glob(filepath.Join(fixture.root, ".sow", "state", "provenance", "deb", "*.json"))
	if err != nil || len(receipts) != 2 {
		t.Fatalf("receipt count=%d receipts=%v err=%v", len(receipts), receipts, err)
	}
	assertSyncProgressRemoved(t, fixture.root, "pgdg")

	stdout.Reset()
	stderr.Reset()
	if err := runSyncWithClientFactory(context.Background(), fixture.args, &stdout, &stderr, fixture.factory); err != nil {
		t.Fatalf("idempotent component replay: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "added format=deb") || strings.Contains(stdout.String(), "sync recovery upstream=pgdg phase=") {
		t.Fatalf("completed replay repeated ingestion/recovery: %s", stdout.String())
	}
}

func TestSyncRecoveryRepairsViewCommittedBeforeRealFilesystemFailure(t *testing.T) {
	fixture := newSyncAPTRecoveryFixture(t, []string{"main"})
	blockedTarget := filepath.Join(fixture.root, ".sow", "materialized", "beta", "apt", "test")
	if err := os.MkdirAll(filepath.Dir(blockedTarget), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blockedTarget, []byte("real filesystem obstruction"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := runSyncWithClientFactory(context.Background(), fixture.args, &stdout, &stderr, fixture.factory)
	assertDurableSyncPartialError(t, err, syncPhaseIngesting, "apt:main")
	if _, err := os.Stat(filepath.Join(fixture.root, ".sow", "state", "views", "beta", "apt-test", "jammy", "arm64.tsv")); err != nil {
		t.Fatalf("view was not durably committed before materialization failure: %v", err)
	}
	initialProgress := readSyncProgressForTest(t, fixture.root, "pgdg")

	stdout.Reset()
	stderr.Reset()
	err = runSyncWithClientFactory(context.Background(), fixture.args, &stdout, &stderr, fixture.factory)
	assertDurableSyncPartialError(t, err, syncPhaseProjectionRepair, "canonical-view-projection")
	if progress := readSyncProgressForTest(t, fixture.root, "pgdg"); progress.Phase != syncPhaseProjectionRepair || progress.ProvenanceCommit != initialProgress.ProvenanceCommit {
		t.Fatalf("failed projection repair progress=%#v initial_commit=%s", progress, initialProgress.ProvenanceCommit)
	}
	requestsBefore := fixture.requests.Load()
	if err := os.RemoveAll(fixture.upstreamRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(blockedTarget); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if err := runSyncWithClientFactory(context.Background(), fixture.args, &stdout, &stderr, fixture.factory); err != nil {
		t.Fatalf("offline projection repair replay: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "added format=deb") {
		t.Fatalf("view-present package was reinspected/imported instead of projection repair: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "format=apt") || strings.Contains(stdout.String(), "sync upstream=pgdg format=") {
		t.Fatalf("missing projection repair evidence: %s", stdout.String())
	}
	if fixture.requests.Load() != requestsBefore {
		t.Fatalf("projection-repair phase consulted removed upstream: before=%d after=%d", requestsBefore, fixture.requests.Load())
	}
	assertAPTRecoveryProjection(t, fixture, "main")
	assertSyncProgressRemoved(t, fixture.root, "pgdg")

	pkg := fixture.packages["main"]
	pool, err := repository.NewStore(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := repository.ParseDigest(pkg.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	casInfo, err := os.Stat(pool.ObjectPath(digest))
	if err != nil {
		t.Fatal(err)
	}
	payloadInfo, err := os.Stat(filepath.Join(fixture.root, ".sow", "materialized", "beta", "apt", "test", filepath.FromSlash(pkg.PoolPath)))
	if err != nil || !os.SameFile(casInfo, payloadInfo) {
		t.Fatalf("repaired payload is not a CAS hardlink err=%v", err)
	}
}

func TestSyncRecoveryRepairsYUMViewCommittedBeforeRealFilesystemFailure(t *testing.T) {
	ctx := context.Background()
	created := time.Unix(1_500_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW YUM Recovery", "", "yum-recovery@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: testOpenPGPRSABits})
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	if err := entity.SerializePrivate(&private, &packet.Config{Time: func() time.Time { return created }}); err != nil {
		t.Fatal(err)
	}
	var public bytes.Buffer
	armored, err := armor.Encode(&public, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(armored); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(private.Bytes()), nil, created)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile("testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	upstreamRoot := t.TempDir()
	basename := "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm"
	staged := filepath.Join(upstreamRoot, basename)
	if err := os.WriteFile(staged, payload, 0o444); err != nil {
		t.Fatal(err)
	}
	info, err := yumrepo.InspectPackage(ctx, yumrepo.PackageInput{Path: staged})
	if err != nil {
		t.Fatal(err)
	}
	rpmPath := filepath.Join(upstreamRoot, filepath.FromSlash(info.Location))
	if err := os.MkdirAll(filepath.Dir(rpmPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, rpmPath); err != nil {
		t.Fatal(err)
	}
	if _, err := yumrepo.Generate(ctx, filepath.Join(upstreamRoot, "repodata"), yumrepo.Options{ELMajor: 10, Revision: 1, Signer: signer}, &yumrepo.SliceIterator{Inputs: []yumrepo.PackageInput{{Path: rpmPath, Basename: basename, FileTime: created}}}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.FileServer(http.Dir(upstreamRoot)))
	defer server.Close()
	root := t.TempDir()
	writeRPMPackageTrustFixture(t, root)
	if err := os.WriteFile(filepath.Join(root, "upstream.asc"), public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, "repository.key")
	if err := os.WriteFile(privatePath, private.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(syncYUMSeparateTestConfig(server.URL+"/")), 0o600); err != nil {
		t.Fatal(err)
	}
	factory := func(config.Upstream, []byte) (*http.Client, error) { return server.Client(), nil }
	args := []string{"--config", configPath, "--upstream", "el", "--arch", "noarch", "--gpg-private-key-file", privatePath, "--workers", "2", "--chunk-entries", "2"}
	blockedTarget := filepath.Join(root, ".sow", "materialized", "beta", "yum", "test", "noarch")
	if err := os.MkdirAll(filepath.Dir(blockedTarget), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blockedTarget, []byte("real filesystem obstruction"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err = runSyncWithClientFactory(ctx, args, &stdout, &stderr, factory)
	assertDurableSyncPartialErrorForUpstream(t, err, "el", syncPhaseIngesting, "yum:yum-test")
	if _, err := os.Stat(filepath.Join(root, ".sow", "state", "views", "beta", "yum-test", "el10", "noarch.tsv")); err != nil {
		t.Fatalf("YUM view was not committed before obstruction: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", "state", "views", "beta", "yum-test", "el10", "x86_64.tsv")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("separate noarch sync leaked into x86_64 canonical leaf: %v", err)
	}
	readSyncProgressForTest(t, root, "el")
	receiptPath := filepath.Join(root, ".sow", "state", "provenance", "rpm", info.SHA256+".json")
	receiptBefore, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(blockedTarget); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	if err := runSyncWithClientFactory(ctx, args, &stdout, &stderr, factory); err != nil {
		t.Fatalf("YUM projection replay: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "added format=rpm") || !strings.Contains(stdout.String(), "format=yum") || strings.Contains(stdout.String(), "sync upstream=el format=") {
		t.Fatalf("YUM replay did not use canonical projection repair: %s", stdout.String())
	}
	for _, relative := range []string{info.Location, "repodata/repomd.xml", "repodata/repomd.xml.asc"} {
		if _, err := os.Stat(filepath.Join(root, ".sow", "materialized", "beta", "yum", "test", "noarch", filepath.FromSlash(relative))); err != nil {
			t.Fatalf("missing recovered YUM artifact %s: %v", relative, err)
		}
	}
	receiptAfter, err := os.ReadFile(receiptPath)
	if err != nil || !bytes.Equal(receiptBefore, receiptAfter) {
		t.Fatalf("YUM provenance changed on replay err=%v", err)
	}
	assertSyncProgressRemoved(t, root, "el")
	stdout.Reset()
	stderr.Reset()
	if err := runSyncWithClientFactory(ctx, args, &stdout, &stderr, factory); err != nil {
		t.Fatalf("idempotent YUM replay: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "sync recovery upstream=el phase=") || strings.Contains(stdout.String(), "added format=rpm") ||
		!strings.Contains(stdout.String(), "download=0") || !strings.Contains(stdout.String(), "present=1") {
		t.Fatalf("completed YUM replay repeated recovery: %s", stdout.String())
	}
}

func newSyncAPTRecoveryFixture(t *testing.T, components []string) syncAPTRecoveryFixture {
	t.Helper()
	ctx := context.Background()
	created := time.Unix(1_500_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW Sync Recovery", "", "sync-recovery@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: testOpenPGPRSABits})
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	if err := entity.SerializePrivate(&private, &packet.Config{Time: func() time.Time { return created }}); err != nil {
		t.Fatal(err)
	}
	var public bytes.Buffer
	armored, err := armor.Encode(&public, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(armored); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	signer, err := aptrepo.NewSigner(bytes.NewReader(private.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile("../aptrepo/testdata/libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64")
	if err != nil {
		t.Fatal(err)
	}
	basePayload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	upstreamRoot := t.TempDir()
	packages := make(map[string]aptrepo.Package, len(components))
	indexes := make([]aptrepo.Index, 0, len(components))
	for index, component := range components {
		payload := append([]byte(nil), basePayload...)
		if index > 0 {
			// Vary an ar header timestamp byte. Package control/data payloads stay
			// valid and identical, while the upstream package SHA is distinct.
			if len(payload) < 36 || string(payload[:8]) != "!<arch>\n" {
				t.Fatal("unexpected DEB ar fixture")
			}
			payload[33] = byte('0' + index)
		}
		staged := filepath.Join(upstreamRoot, fmt.Sprintf("fixture-%s.deb", component))
		if err := os.WriteFile(staged, payload, 0o444); err != nil {
			t.Fatal(err)
		}
		pkg, err := aptrepo.InspectPackage(ctx, staged, component)
		if err != nil {
			t.Fatalf("inspect %s fixture: %v", component, err)
		}
		poolPath := filepath.Join(upstreamRoot, filepath.FromSlash(pkg.PoolPath))
		if err := os.MkdirAll(filepath.Dir(poolPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(staged, poolPath); err != nil {
			t.Fatal(err)
		}
		pkg, err = aptrepo.InspectPackage(ctx, poolPath, component)
		if err != nil {
			t.Fatal(err)
		}
		packages[component] = pkg
		indexes = append(indexes, aptrepo.Index{Component: component, Architecture: "arm64", Packages: []aptrepo.Package{pkg}})
	}
	sort.Strings(components)
	if _, err := aptrepo.Generate(ctx, upstreamRoot, aptrepo.RepositoryConfig{
		Origin: "Recovery Test", Label: "Recovery Test", Suite: "jammy", Codename: "jammy",
		Components: components, Architectures: []string{"arm64"}, Date: created,
	}, indexes, signer); err != nil {
		t.Fatalf("generate recovery upstream: %v", err)
	}
	requests := &atomic.Int64{}
	fileHandler := http.StripPrefix("/repo/", http.FileServer(http.Dir(upstreamRoot)))
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		fileHandler.ServeHTTP(response, request)
	}))
	t.Cleanup(server.Close)

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "upstream.asc"), public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, "repository.key")
	if err := os.WriteFile(privatePath, private.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	componentYAML := strings.Join(components, ", ")
	configuration := fmt.Sprintf(syncAPTRecoveryConfig, componentYAML, server.URL+"/repo/", componentYAML)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	factory := func(config.Upstream, []byte) (*http.Client, error) { return server.Client(), nil }
	args := []string{"--config", configPath, "--upstream", "pgdg", "--arch", "arm64", "--gpg-private-key-file", privatePath, "--workers", "2", "--chunk-entries", "2"}
	return syncAPTRecoveryFixture{root: root, configPath: configPath, privatePath: privatePath, args: args, factory: factory, packages: packages, upstreamRoot: upstreamRoot, requests: requests}
}

func readSyncProgressForTest(t *testing.T, root, upstreamID string) syncProgress {
	t.Helper()
	path := filepath.Join(root, ".sow", "sync", upstreamID, syncProgressFilename)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	progress, err := decodeSyncProgress(body)
	if err != nil {
		t.Fatal(err)
	}
	return progress
}

func assertSyncProgressRemoved(t *testing.T, root, upstreamID string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(root, ".sow", "sync", upstreamID, syncProgressFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sync progress was not cleaned: %v", err)
	}
}

func assertDurableSyncPartialError(t *testing.T, err error, phase syncProgressPhase, unit string) {
	assertDurableSyncPartialErrorForUpstream(t, err, "pgdg", phase, unit)
}

func assertDurableSyncPartialErrorForUpstream(t *testing.T, err error, upstreamID string, phase syncProgressPhase, unit string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected durable partial sync error")
	}
	for _, wanted := range []string{"durable_partial_commit=true", "provenance_commit=", "phase=" + string(phase), "retry_action=", "rerun the same sow sync command", "--upstream=" + upstreamID, "add --recover only if"} {
		if !strings.Contains(err.Error(), wanted) {
			t.Fatalf("partial error missing %q: %v", wanted, err)
		}
	}
	if unit != "" && !strings.Contains(err.Error(), "unit="+unit) {
		t.Fatalf("partial error missing unit=%s: %v", unit, err)
	}
}

func assertAPTRecoveryProjection(t *testing.T, fixture syncAPTRecoveryFixture, component string) {
	t.Helper()
	pkg := fixture.packages[component]
	root := filepath.Join(fixture.root, ".sow", "materialized", "beta", "apt", "test")
	packagesPath := filepath.Join(root, "dists", "jammy", component, "binary-arm64", "Packages")
	body, err := os.ReadFile(packagesPath)
	if err != nil || !strings.Contains(string(body), "SHA256: "+pkg.SHA256) {
		t.Fatalf("component=%s Packages err=%v body=%s", component, err, body)
	}
	for _, relative := range []string{"dists/jammy/Release", "dists/jammy/InRelease", pkg.PoolPath} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("component=%s missing %s: %v", component, relative, err)
		}
	}
	receiptBody, err := os.ReadFile(filepath.Join(fixture.root, ".sow", "state", "provenance", "deb", pkg.SHA256+".json"))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := provenance.Decode(receiptBody)
	if err != nil || receipt.DEB == nil || receipt.DEB.SignedReleaseSHA256 == "" {
		t.Fatalf("component=%s receipt=%#v err=%v", component, receipt, err)
	}
}

const syncAPTRecoveryConfig = `schema: sow/v1
state: {}
gpg:
  public_key: upstream.asc
pools:
  public: {}
  gated: {}
repos:
  - id: apt-test
    type: apt
    path: apt/test
    default_pool: public
    arches: [arm64]
    os: {family: ubuntu, major: 22, suite: jammy, lifecycle: active}
    apt: {suites: [jammy], components: [%s]}
upstreams:
  - id: pgdg
    type: apt
    repo: apt-test
    url: %s
    suite: jammy
    components: [%s]
    arches: [arm64]
    keyring: upstream.asc
    debuginfo: drop
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
