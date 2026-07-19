package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/syncer"
	"github.com/pgsty/sow/internal/upstream"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestSyncFailureExitCodeSeparatesIntegrityFromTransport(t *testing.T) {
	for _, integrityErr := range []error{
		upstream.ErrMetadataTooLarge, upstream.ErrInvalidMetadata, upstream.ErrSignature,
		upstream.ErrConflictingPackage, upstream.ErrEvidence,
	} {
		if got := syncFailureExitCode(fmt.Errorf("wrapped: %w", integrityErr)); got != ExitVerification {
			t.Fatalf("integrity error %v mapped to %d", integrityErr, got)
		}
	}
	if got := syncFailureExitCode(upstream.ErrUnsafeURL); got != ExitConfig {
		t.Fatalf("unsafe URL mapped to %d", got)
	}
	if got := syncFailureExitCode(errors.New("dial tcp: refused")); got != ExitNetworkAuth {
		t.Fatalf("transport error mapped to %d", got)
	}
}

func TestPresentCASArtifactCloseRejectsCoordinateReplacement(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("signed-rpm-coordinate"), 4096)
	object, err := pool.Put(ctx, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	handle, err := (casInventory{ctx: ctx, pool: pool}).OpenArtifact(object.HashString(), object.Size)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(root, "replacement")
	if err := os.WriteFile(replacement, bytes.Repeat([]byte("x"), len(body)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, pool.ObjectPath(object.SHA256)); err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err == nil || !strings.Contains(err.Error(), "changed during digest/signature verification") {
		t.Fatalf("replaced CAS coordinate passed close stability check: %v", err)
	}
}

func TestMissingPresentChangeSetRehashesCASBeforeViewMutation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("verified-deb-body"), 1024)
	object, err := pool.Put(ctx, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	coordinate := pool.ObjectPath(object.SHA256)
	if err := os.Chmod(coordinate, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(coordinate, bytes.Repeat([]byte("x"), len(body)), 0o444); err != nil {
		t.Fatal(err)
	}
	txDir := t.TempDir()
	journal, err := newSyncJournal(txDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Seal(); err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	candidate := syncer.Candidate{
		Format: "deb", Name: "example", Version: "1", Arch: "amd64",
		URL: "https://example.invalid/pool/e/example_1_amd64.deb", SHA256: object.HashString(), Size: object.Size,
	}
	_, err = stageSyncInputs(ctx, txDir, pool, config.Repo{ID: "apt", Type: "apt"}, config.Upstream{URL: "https://example.invalid/"}, journal, []syncer.Candidate{candidate})
	if err == nil || !strings.Contains(err.Error(), "verify present CAS object") {
		t.Fatalf("same-size corrupt CAS object reached view staging: %v", err)
	}
}

func TestDownloadedJournalBodyIsBoundBeforeViewStaging(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	wantedBody := []byte("authenticated-deb-body")
	wantedSum := sha256.Sum256(wantedBody)
	candidate := syncer.Candidate{
		Format: "deb", Name: "example", Version: "1", Arch: "amd64",
		URL:    "https://example.invalid/repo/pool/main/e/example_1_amd64.deb",
		SHA256: fmt.Sprintf("%x", wantedSum), Size: int64(len(wantedBody)),
	}
	substituted := filepath.Join(root, "download.deb")
	if err := os.WriteFile(substituted, bytes.Repeat([]byte("x"), len(wantedBody)), 0o600); err != nil {
		t.Fatal(err)
	}
	journal, err := newSyncJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	if err := journal.PutDownloaded(upstream.Downloaded{Candidate: candidate, Path: substituted}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Seal(); err != nil {
		t.Fatal(err)
	}
	repo := config.Repo{ID: "apt", Type: "apt", APT: &config.APTConfig{Components: []string{"main"}}}
	source := config.Upstream{URL: "https://example.invalid/repo/"}
	if _, err := stageSyncInputs(ctx, t.TempDir(), pool, repo, source, journal, nil); !errors.Is(err, repository.ErrObjectCorrupt) {
		t.Fatalf("substituted downloaded body reached view staging: %v", err)
	}
	if _, err := pool.Open(repository.Digest(wantedSum)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected download installed authenticated coordinate: %v", err)
	}
}

func TestSyncCandidateComponentIsRelativeToUpstreamBase(t *testing.T) {
	repo := config.Repo{ID: "apt", Type: "apt", APT: &config.APTConfig{Components: []string{"main", "contrib"}}}
	source := config.Upstream{URL: "https://example.invalid/pool/main/"}
	candidate := syncer.Candidate{
		Format: "deb", Name: "example", Version: "1", Arch: "amd64", Size: 1,
		SHA256: strings.Repeat("a", 64),
		URL:    "https://example.invalid/pool/main/pool/contrib/e/example_1_amd64.deb",
	}
	component, err := syncCandidateComponent(candidate, repo, source)
	if err != nil || component != "contrib" {
		t.Fatalf("component=%q err=%v, want signed relative component contrib", component, err)
	}
}

func TestOfflineSyncReplayDoesNotHideAPTComponentMove(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, ".sow")
	if err := os.MkdirAll(stateDir, 0o711); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(stateDir)
	digest := strings.Repeat("a", 64)
	entry := views.Entry{
		Repo: "apt", OS: "jammy", Arch: "amd64", Name: "example", Version: "1",
		Path: "apt/pool/main/e/example_1_amd64.deb", Size: 42, SHA256: digest, Pool: "public",
	}
	var view bytes.Buffer
	if err := views.WriteEntry(&view, entry); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "main.tsv")
	if err := os.WriteFile(stage, view.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	viewPath, _ := state.ViewPath("beta", "apt", "jammy", "amd64")
	commit, _, err := canonical.InstallPaths(map[string]string{viewPath: stage}, "seed main placement")
	if err != nil {
		t.Fatal(err)
	}
	viewRef, _ := state.ViewRef("beta", "apt", "jammy", "amd64")
	if err := canonical.AdvanceRef(viewRef, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}
	operation, err := acquireSyncOperation(t.Context(), stateDir, "pgdg")
	if err != nil {
		t.Fatal(err)
	}
	defer operation.Close()
	record := syncReplayRecord{
		Format: "deb", SHA256: digest, Size: 42, Name: "example", Version: "1", Arch: "amd64",
		Basename: "example_1_amd64.deb", Component: "contrib",
	}
	replaySHA, replayCount, err := operation.WriteReplay([]syncReplayRecord{record}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	progress := &syncProgress{ReplaySHA256: replaySHA, ReplayCount: replayCount}
	repo := config.Repo{
		ID: "apt", Type: "apt", Path: "apt", APT: &config.APTConfig{Components: []string{"main", "contrib"}},
	}
	source := config.Upstream{Suite: "jammy", Arches: []string{"amd64"}}
	missing, err := missingSyncReplayRecords(canonical, repo, source, operation, progress)
	if err != nil || len(missing) != 1 || missing[0] != record {
		t.Fatalf("contrib replay was hidden by main placement: missing=%+v err=%v", missing, err)
	}
}

func TestNarrowRepoToUpstreamFreezesOnlyRepresentableOperationDimensions(t *testing.T) {
	repo := config.Repo{
		ID: "apt", Type: "apt", Path: "apt", Arches: []string{"amd64", "arm64"},
		APT: &config.APTConfig{Suites: []string{"jammy", "noble"}, Components: []string{"main", "contrib"}},
	}
	source := config.Upstream{ID: "pgdg-noble", Repo: "apt", Type: "apt", Suite: "noble", Arches: []string{"arm64"}}

	operation, ok := narrowRepoToUpstream(repo, source)
	if !ok {
		t.Fatal("representable upstream scope was rejected")
	}
	if got := strings.Join(operation.Arches, ","); got != "arm64" {
		t.Fatalf("operation arches widened beyond upstream: %s", got)
	}
	if operation.APT == nil || strings.Join(operation.APT.Suites, ",") != "noble" {
		t.Fatalf("operation suites widened beyond upstream: %#v", operation.APT)
	}
	if got := strings.Join(operation.APT.Components, ","); got != "main,contrib" {
		t.Fatalf("APT component contract was narrowed: %s", got)
	}
	operation.APT.Components[0] = "mutated"
	if repo.APT.Components[0] != "main" {
		t.Fatal("operation repository aliases configured APT components")
	}

	missingArch := source
	missingArch.Arches = []string{"ppc64le"}
	if _, ok := narrowRepoToUpstream(repo, missingArch); ok {
		t.Fatal("upstream architecture outside the selected repo was accepted")
	}
	missingSuite := source
	missingSuite.Suite = "bookworm"
	if _, ok := narrowRepoToUpstream(repo, missingSuite); ok {
		t.Fatal("upstream suite outside the selected repo was accepted")
	}
}

func TestYUMNoarchModeControlsFreshPresentAndOfflineReplayLeafClosure(t *testing.T) {
	for _, test := range []struct {
		name        string
		mode        string
		repoArches  []string
		packageArch string
		seededLeaf  string
		wantMissing bool
	}{
		{name: "replicate requires every selected basearch", mode: config.YUMNoarchReplicate, repoArches: []string{"x86_64", "aarch64"}, packageArch: "noarch", seededLeaf: "x86_64", wantMissing: true},
		{name: "separate noarch leaf is complete alone", mode: config.YUMNoarchSeparate, repoArches: []string{"x86_64", "aarch64", "noarch"}, packageArch: "noarch", seededLeaf: "noarch"},
		{name: "separate rejects old replicated placement", mode: config.YUMNoarchSeparate, repoArches: []string{"x86_64", "aarch64", "noarch"}, packageArch: "noarch", seededLeaf: "x86_64", wantMissing: true},
		{name: "separate basearch does not require noarch", mode: config.YUMNoarchSeparate, repoArches: []string{"x86_64", "aarch64", "noarch"}, packageArch: "x86_64", seededLeaf: "x86_64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			stateDir := filepath.Join(root, ".sow")
			canonical := state.New(stateDir)
			digest := strings.Repeat("e", 64)
			basename := "percona-release-1-1." + test.packageArch + ".rpm"
			entry := views.Entry{
				Repo: "yum-percona", OS: "el10", Arch: test.seededLeaf, Name: "percona-release", Version: "1-1",
				Path: "yum/percona/el10." + test.seededLeaf + "/Packages/p/" + basename,
				Size: 42, SHA256: digest, Pool: "public",
			}
			var body bytes.Buffer
			if err := views.WriteEntry(&body, entry); err != nil {
				t.Fatal(err)
			}
			stage := filepath.Join(root, "view.tsv")
			if err := os.WriteFile(stage, body.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			viewPath, _ := state.ViewPath("beta", "yum-percona", "el10", test.seededLeaf)
			commit, _, err := canonical.InstallPaths(map[string]string{viewPath: stage}, "seed YUM noarch placement")
			if err != nil {
				t.Fatal(err)
			}
			viewRef, _ := state.ViewRef("beta", "yum-percona", "el10", test.seededLeaf)
			if err := canonical.AdvanceRef(viewRef, plumbing.ZeroHash, commit, false); err != nil {
				t.Fatal(err)
			}
			repo := config.Repo{
				ID: "yum-percona", Type: "yum", Path: "yum/percona/el10.{arch}", DefaultPool: "public",
				OS: config.OSConfig{Family: "el", Major: 10}, Arches: append([]string(nil), test.repoArches...),
				YUM: &config.YUMConfig{NoarchMode: test.mode},
			}
			source := config.Upstream{ID: "percona", Repo: repo.ID, Type: "yum", Arches: append([]string(nil), test.repoArches...)}
			candidate := syncer.Candidate{
				Format: "rpm", Name: entry.Name, Version: entry.Version, Arch: test.packageArch,
				URL: "https://example.invalid/Packages/p/" + basename, Size: entry.Size, SHA256: entry.SHA256,
			}

			journalDir := filepath.Join(root, "fresh-journal")
			if err := os.MkdirAll(journalDir, 0o700); err != nil {
				t.Fatal(err)
			}
			journal, err := newSyncJournal(journalDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := journal.PutPresent(upstream.ReceiptCommit{Candidate: candidate}); err != nil {
				journal.Close()
				t.Fatal(err)
			}
			if err := journal.Seal(); err != nil {
				journal.Close()
				t.Fatal(err)
			}
			freshMissing, freshErr := missingPresentCandidates(canonical, repo, source, journal)
			if closeErr := journal.Close(); freshErr == nil {
				freshErr = closeErr
			}
			if freshErr != nil || (len(freshMissing) != 0) != test.wantMissing {
				t.Fatalf("fresh missing=%+v want_missing=%t err=%v", freshMissing, test.wantMissing, freshErr)
			}

			operation, err := acquireSyncOperation(t.Context(), stateDir, "percona")
			if err != nil {
				t.Fatal(err)
			}
			defer operation.Close()
			record := syncReplayRecord{
				Format: "rpm", SHA256: candidate.SHA256, Size: candidate.Size, Name: candidate.Name,
				Version: candidate.Version, Arch: candidate.Arch, Basename: basename,
			}
			replaySHA, replayCount, err := operation.WriteReplay([]syncReplayRecord{record}, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			replayMissing, replayErr := missingSyncReplayRecords(canonical, repo, source, operation, &syncProgress{ReplaySHA256: replaySHA, ReplayCount: replayCount})
			if replayErr != nil || (len(replayMissing) != 0) != test.wantMissing {
				t.Fatalf("replay missing=%+v want_missing=%t err=%v", replayMissing, test.wantMissing, replayErr)
			}
		})
	}
}

func TestOfflineSyncReplayDoesNotAcceptWrongConfidentialityPool(t *testing.T) {
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	digest := strings.Repeat("c", 64)
	entry := views.Entry{
		Repo: "deb-test", OS: "jammy", Arch: "amd64", Name: "pkg", Version: "1",
		Path: "apt/pool/main/p/pkg/pkg_1_amd64.deb", Size: 7, SHA256: digest, Pool: "public",
	}
	var body bytes.Buffer
	if err := views.WriteEntry(&body, entry); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "view.tsv")
	if err := os.WriteFile(stage, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	viewPath, _ := state.ViewPath("stable", "deb-test", "jammy", "amd64")
	commit, _, err := canonical.InstallPaths(map[string]string{viewPath: stage}, "seed public stable")
	if err != nil {
		t.Fatal(err)
	}
	viewRef, _ := state.ViewRef("stable", "deb-test", "jammy", "amd64")
	if err := canonical.AdvanceRef(viewRef, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}

	operation, err := acquireSyncOperation(context.Background(), filepath.Join(root, ".sow"), "pool-audit")
	if err != nil {
		t.Fatal(err)
	}
	defer operation.Close()
	record := syncReplayRecord{
		Format: "deb", SHA256: digest, Size: 7, Name: "pkg", Version: "1", Arch: "amd64",
		Basename: "pkg_1_amd64.deb", Component: "main",
	}
	replaySHA, replayCount, err := operation.WriteReplay([]syncReplayRecord{record}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	progress := &syncProgress{ReplaySHA256: replaySHA, ReplayCount: replayCount}
	repo := config.Repo{
		ID: "deb-test", Type: "apt", Path: "apt", DefaultPool: "gated",
		APT: &config.APTConfig{Components: []string{"main"}},
	}
	source := config.Upstream{Type: "apt", Suite: "jammy", Arches: []string{"amd64"}}
	missing, err := missingSyncReplayRecords(canonical, repo, source, operation, progress)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 {
		t.Fatalf("public stable entry suppressed required gated replay: %+v", missing)
	}
}

func TestFreshSyncDoesNotAcceptWrongConfidentialityPool(t *testing.T) {
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	digest := strings.Repeat("d", 64)
	entry := views.Entry{
		Repo: "deb-test", OS: "jammy", Arch: "amd64", Name: "pkg", Version: "1",
		Path: "apt/pool/main/p/pkg/pkg_1_amd64.deb", Size: 7, SHA256: digest, Pool: "public",
	}
	var body bytes.Buffer
	if err := views.WriteEntry(&body, entry); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "view.tsv")
	if err := os.WriteFile(stage, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	viewPath, _ := state.ViewPath("stable", "deb-test", "jammy", "amd64")
	commit, _, err := canonical.InstallPaths(map[string]string{viewPath: stage}, "seed public stable")
	if err != nil {
		t.Fatal(err)
	}
	viewRef, _ := state.ViewRef("stable", "deb-test", "jammy", "amd64")
	if err := canonical.AdvanceRef(viewRef, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}

	journalDir := filepath.Join(root, ".sow", "transactions", "pool-audit-fresh")
	if err := os.MkdirAll(journalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := newSyncJournal(journalDir)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	candidate := syncer.Candidate{
		Format: "deb", Name: "pkg", Version: "1", Arch: "amd64",
		URL: "https://example.invalid/pool/main/p/pkg/pkg_1_amd64.deb", Size: 7, SHA256: digest,
	}
	if err := journal.PutPresent(upstream.ReceiptCommit{Candidate: candidate}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Seal(); err != nil {
		t.Fatal(err)
	}
	repo := config.Repo{
		ID: "deb-test", Type: "apt", Path: "apt", DefaultPool: "gated",
		APT: &config.APTConfig{Components: []string{"main"}},
	}
	source := config.Upstream{
		Type: "apt", URL: "https://example.invalid", Suite: "jammy", Arches: []string{"amd64"},
	}
	missing, err := missingPresentCandidates(canonical, repo, source, journal)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 {
		t.Fatalf("fresh sync hid gated placement behind public stable entry: %+v", missing)
	}
}

func TestExpectedSyncInputRejectsLateSubstitution(t *testing.T) {
	wantedSum := sha256.Sum256([]byte("wanted"))
	path := "/private/sync/input.deb"
	expected := map[string]repository.Object{path: {SHA256: repository.Digest(wantedSum), Size: 6}}
	if err := verifyExpectedSyncInput(path, strings.Repeat("b", 64), 6, expected); err == nil {
		t.Fatal("late same-size sync input substitution was accepted")
	}
	if err := verifyExpectedSyncInput(path, fmt.Sprintf("%x", wantedSum), 6, expected); err != nil {
		t.Fatalf("authenticated sync input rejected: %v", err)
	}
}

func TestPresentDEBInNewComponentIsNotHiddenBySameDigest(t *testing.T) {
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	digest := strings.Repeat("a", 64)
	entry := views.Entry{
		Repo: "deb-test", OS: "jammy", Arch: "amd64", Name: "example", Version: "1",
		Path: "apt/pool/main/e/example/example_1_amd64.deb", Size: 7, SHA256: digest, Pool: "public",
	}
	var body bytes.Buffer
	if err := views.WriteEntry(&body, entry); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "view.tsv")
	if err := os.WriteFile(stage, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	viewPath, _ := state.ViewPath("beta", "deb-test", "jammy", "amd64")
	commit, _, err := canonical.InstallPaths(map[string]string{viewPath: stage}, "seed main")
	if err != nil {
		t.Fatal(err)
	}
	viewRef, _ := state.ViewRef("beta", "deb-test", "jammy", "amd64")
	if err := canonical.AdvanceRef(viewRef, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}

	journal, err := newSyncJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	candidate := syncer.Candidate{
		Format: "deb", Name: "example", Version: "1", Arch: "amd64", Size: 7, SHA256: digest,
		URL: "https://example.invalid/pool/contrib/e/example/example_1_amd64.deb",
	}
	if err := journal.PutPresent(upstream.ReceiptCommit{Candidate: candidate}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Seal(); err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	repo := config.Repo{
		ID: "deb-test", Type: "apt", Path: "apt", DefaultPool: "public",
		APT: &config.APTConfig{Components: []string{"main", "contrib"}},
	}
	source := config.Upstream{Type: "apt", URL: "https://example.invalid/", Suite: "jammy", Arches: []string{"amd64"}}
	missing, err := missingPresentCandidates(canonical, repo, source, journal)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0].URL != candidate.URL {
		t.Fatalf("new contrib placement was suppressed by old main digest: missing=%+v", missing)
	}
}

func TestRepoPathPoolSegmentCannotSpoofAPTComponent(t *testing.T) {
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	digest := strings.Repeat("b", 64)
	entry := views.Entry{
		Repo: "deb-test", OS: "jammy", Arch: "amd64", Name: "example", Version: "1",
		Path: "archive/pool/main/pool/contrib/e/example/example_1_amd64.deb", Size: 7, SHA256: digest, Pool: "public",
	}
	var body bytes.Buffer
	if err := views.WriteEntry(&body, entry); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "view.tsv")
	if err := os.WriteFile(stage, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	viewPath, _ := state.ViewPath("beta", "deb-test", "jammy", "amd64")
	commit, _, err := canonical.InstallPaths(map[string]string{viewPath: stage}, "seed contrib")
	if err != nil {
		t.Fatal(err)
	}
	viewRef, _ := state.ViewRef("beta", "deb-test", "jammy", "amd64")
	if err := canonical.AdvanceRef(viewRef, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}

	journal, err := newSyncJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	candidate := syncer.Candidate{
		Format: "deb", Name: "example", Version: "1", Arch: "amd64", Size: 7, SHA256: digest,
		URL: "https://example.invalid/pool/main/e/example/example_1_amd64.deb",
	}
	if err := journal.PutPresent(upstream.ReceiptCommit{Candidate: candidate}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Seal(); err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	repo := config.Repo{
		ID: "deb-test", Type: "apt", Path: "archive/pool/main", DefaultPool: "public",
		APT: &config.APTConfig{Components: []string{"main", "contrib"}},
	}
	source := config.Upstream{Type: "apt", URL: "https://example.invalid/", Suite: "jammy", Arches: []string{"amd64"}}
	missing, err := missingPresentCandidates(canonical, repo, source, journal)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 {
		t.Fatalf("repo path component spoof suppressed new main placement: missing=%+v", missing)
	}
}

func TestSyncAPTEndToEndPreservesCanonicalProvenanceAndNeverDeletes(t *testing.T) {
	ctx := context.Background()
	created := time.Unix(1_500_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW Sync Test", "", "sync@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: 2048})
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
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	upstreamRoot := t.TempDir()
	fixturePath := filepath.Join(upstreamRoot, "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb")
	if err := os.WriteFile(fixturePath, payload, 0o444); err != nil {
		t.Fatal(err)
	}
	pkg, err := aptrepo.InspectPackage(ctx, fixturePath, "main")
	if err != nil {
		t.Fatal(err)
	}
	poolPath := filepath.Join(upstreamRoot, filepath.FromSlash(pkg.PoolPath))
	if err := os.MkdirAll(filepath.Dir(poolPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(fixturePath, poolPath); err != nil {
		t.Fatal(err)
	}
	pkg, err = aptrepo.InspectPackage(ctx, poolPath, "main")
	if err != nil {
		t.Fatal(err)
	}
	buildUpstream := func(packages []aptrepo.Package, at time.Time) {
		t.Helper()
		_, err := aptrepo.Generate(ctx, upstreamRoot, aptrepo.RepositoryConfig{
			Origin: "PGDG Test", Label: "PGDG Test", Suite: "jammy", Codename: "jammy",
			Components: []string{"main"}, Architectures: []string{"arm64"}, Date: at,
		}, []aptrepo.Index{{Component: "main", Architecture: "arm64", Packages: packages}}, signer)
		if err != nil {
			t.Fatalf("generate upstream: %v", err)
		}
	}
	buildUpstream([]aptrepo.Package{pkg}, created.Add(time.Hour))
	server := httptest.NewTLSServer(http.StripPrefix("/repo/", http.FileServer(http.Dir(upstreamRoot))))
	defer server.Close()

	root := t.TempDir()
	writeRPMPackageTrustFixture(t, root)
	keyringPath := filepath.Join(root, "upstream.asc")
	if err := os.WriteFile(keyringPath, public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, "repository.key")
	if err := os.WriteFile(privatePath, private.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "sow.yaml")
	configuration := fmt.Sprintf(syncAPTTestConfig, server.URL+"/repo/")
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	factory := func(config.Upstream, []byte) (*http.Client, error) { return server.Client(), nil }
	var stdout, stderr bytes.Buffer
	err = runSyncWithClientFactory(ctx, []string{"--config", configPath, "--upstream", "pgdg", "--arch", "arm64", "--gpg-private-key-file", privatePath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr, factory)
	if err != nil {
		t.Fatalf("first sync: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "download=1") || !strings.Contains(stdout.String(), "added format=deb") {
		t.Fatalf("missing sync/add evidence: %s", stdout.String())
	}
	completedDownload := filepath.Join(root, ".sow", "sync", "pgdg", "downloads", pkg.SHA256+".download")
	if _, err := os.Lstat(completedDownload); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed transport copy was retained beside canonical CAS: path=%s err=%v", completedDownload, err)
	}
	spools, err := os.ReadDir(filepath.Join(root, ".sow", "sync", "pgdg", "candidates"))
	if err != nil || len(spools) != 0 {
		t.Fatalf("streaming discovery spool was not released: entries=%v err=%v", spools, err)
	}
	localPackage := filepath.Join(root, ".sow", "materialized", "beta", "apt", "test", filepath.FromSlash(pkg.PoolPath))
	if _, err := os.Stat(localPackage); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", "state", "views", "beta", "apt-test", "jammy", "amd64.tsv")); !os.IsNotExist(err) {
		t.Fatalf("--arch arm64 created an unselected amd64 leaf: %v", err)
	}
	receiptPath := filepath.Join(root, ".sow", "state", "provenance", "deb", pkg.SHA256+".json")
	receiptBytes, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("canonical provenance missing: %v", err)
	}
	receipt, err := provenance.Decode(receiptBytes)
	if err != nil || receipt.DEB == nil || receipt.DEB.SignedReleaseSHA256 == "" {
		t.Fatalf("canonical receipt=%#v err=%v", receipt, err)
	}
	evidence, err := filepath.Glob(filepath.Join(root, ".sow", "state", "provenance", "evidence", "sha256", "*"))
	if err != nil || len(evidence) < 2 {
		t.Fatalf("canonical evidence=%v err=%v", evidence, err)
	}

	stdout.Reset()
	stderr.Reset()
	err = runSyncWithClientFactory(ctx, []string{"--config", configPath, "--upstream", "pgdg", "--arch", "arm64", "--gpg-private-key-file", privatePath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr, factory)
	if err != nil || !strings.Contains(stdout.String(), "download=0") || !strings.Contains(stdout.String(), "provenance_changed=false") {
		t.Fatalf("idempotent sync err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}

	newFixture := writeSyncMinimalDEB(t, upstreamRoot, "librotation", "2.0-1", "arm64")
	newPackage, err := aptrepo.InspectPackage(ctx, newFixture, "main")
	if err != nil {
		t.Fatal(err)
	}
	newPoolPath := filepath.Join(upstreamRoot, filepath.FromSlash(newPackage.PoolPath))
	if err := os.MkdirAll(filepath.Dir(newPoolPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(newFixture, newPoolPath); err != nil {
		t.Fatal(err)
	}
	newPackage, err = aptrepo.InspectPackage(ctx, newPoolPath, "main")
	if err != nil {
		t.Fatal(err)
	}
	buildUpstream([]aptrepo.Package{pkg, newPackage}, created.Add(2*time.Hour))
	stdout.Reset()
	stderr.Reset()
	err = runSyncWithClientFactory(ctx, []string{"--config", configPath, "--upstream", "pgdg", "--arch", "arm64", "--gpg-private-key-file", privatePath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr, factory)
	if err != nil || !strings.Contains(stdout.String(), "download=1") || !strings.Contains(stdout.String(), "present=1") || !strings.Contains(stdout.String(), "provenance_changed=true") {
		t.Fatalf("APT signed-index rotation err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if retained, err := os.ReadFile(receiptPath); err != nil || !bytes.Equal(retained, receiptBytes) {
		t.Fatalf("APT rotation rewrote first receipt err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", "state", "provenance", "deb", newPackage.SHA256+".json")); err != nil {
		t.Fatalf("APT rotation omitted new receipt: %v", err)
	}
	rotatedEvidence, err := filepath.Glob(filepath.Join(root, ".sow", "state", "provenance", "evidence", "sha256", "*"))
	if err != nil || len(rotatedEvidence) <= len(evidence) {
		t.Fatalf("APT rotation did not commit new signed evidence: before=%d after=%d err=%v", len(evidence), len(rotatedEvidence), err)
	}
	stdout.Reset()
	stderr.Reset()
	err = runSyncWithClientFactory(ctx, []string{"--config", configPath, "--upstream", "pgdg", "--arch", "arm64", "--gpg-private-key-file", privatePath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr, factory)
	if err != nil || !strings.Contains(stdout.String(), "download=0") || !strings.Contains(stdout.String(), "present=2") || !strings.Contains(stdout.String(), "provenance_changed=false") {
		t.Fatalf("APT rotated replay err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}

	if err := os.Remove(poolPath); err != nil {
		t.Fatal(err)
	}
	buildUpstream(nil, created.Add(3*time.Hour))
	stdout.Reset()
	stderr.Reset()
	err = runSyncWithClientFactory(ctx, []string{"--config", configPath, "--upstream", "pgdg", "--arch", "arm64", "--gpg-private-key-file", privatePath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr, factory)
	if err != nil {
		t.Fatalf("sync after upstream deletion: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(localPackage); err != nil {
		t.Fatalf("additive sync deleted historical package: %v", err)
	}
	localPackages, err := os.ReadFile(filepath.Join(root, ".sow", "materialized", "beta", "apt", "test", "dists", "jammy", "main", "binary-arm64", "Packages"))
	if err != nil || !strings.Contains(string(localPackages), "Package: libpqtypes0\n") {
		t.Fatalf("additive sync removed package index entry err=%v Packages=%s", err, localPackages)
	}
}

func TestSyncYUMEndToEndPreservesCanonicalProvenanceAndNeverDeletes(t *testing.T) {
	ctx := context.Background()
	created := time.Unix(1_500_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW YUM Sync Test", "", "yum-sync@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: 2048})
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
	stagedRPM := filepath.Join(upstreamRoot, basename)
	if err := os.WriteFile(stagedRPM, payload, 0o444); err != nil {
		t.Fatal(err)
	}
	info, err := yumrepo.InspectPackage(ctx, yumrepo.PackageInput{Path: stagedRPM})
	if err != nil {
		t.Fatal(err)
	}
	rpmPath := filepath.Join(upstreamRoot, filepath.FromSlash(info.Location))
	if err := os.MkdirAll(filepath.Dir(rpmPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(stagedRPM, rpmPath); err != nil {
		t.Fatal(err)
	}
	buildUpstream := func(inputs []yumrepo.PackageInput, revision int64) {
		t.Helper()
		if err := os.RemoveAll(filepath.Join(upstreamRoot, "repodata")); err != nil {
			t.Fatal(err)
		}
		if _, err := yumrepo.Generate(ctx, filepath.Join(upstreamRoot, "repodata"), yumrepo.Options{ELMajor: 10, Revision: revision, Signer: signer}, &yumrepo.SliceIterator{Inputs: inputs}); err != nil {
			t.Fatalf("generate signed upstream YUM repo: %v", err)
		}
	}
	buildUpstream([]yumrepo.PackageInput{{Path: rpmPath, Basename: basename, FileTime: created}}, 1)
	server := httptest.NewTLSServer(http.FileServer(http.Dir(upstreamRoot)))
	defer server.Close()

	root := t.TempDir()
	packageTrustPath := writeRPMPackageTrustFixture(t, root)
	correctPackageTrust, err := os.ReadFile(packageTrustPath)
	if err != nil {
		t.Fatal(err)
	}
	keyringPath := filepath.Join(root, "upstream.asc")
	if err := os.WriteFile(keyringPath, public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, "repository.key")
	if err := os.WriteFile(privatePath, private.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(syncYUMTestConfig, server.URL+"/")), 0o600); err != nil {
		t.Fatal(err)
	}
	factory := func(config.Upstream, []byte) (*http.Client, error) { return server.Client(), nil }
	args := []string{"--config", configPath, "--upstream", "el", "--arch", "x86_64", "--gpg-private-key-file", privatePath, "--workers", "2", "--chunk-entries", "2"}
	var stdout, stderr bytes.Buffer
	if err := os.WriteFile(packageTrustPath, public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runSyncWithClientFactory(ctx, args, &stdout, &stderr, factory); err == nil || !strings.Contains(err.Error(), "verify embedded RPM signature") {
		t.Fatalf("untrusted YUM sync accepted: err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if matches, globErr := filepath.Glob(filepath.Join(root, ".sow", "state", "provenance", "rpm", "*.json")); globErr != nil || len(matches) != 0 {
		t.Fatalf("untrusted sync committed provenance=%v err=%v", matches, globErr)
	}
	if err := os.WriteFile(packageTrustPath, correctPackageTrust, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if err := runSyncWithClientFactory(ctx, args, &stdout, &stderr, factory); err != nil {
		t.Fatalf("first YUM sync: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "format=rpm") || !strings.Contains(stdout.String(), "download=1") || !strings.Contains(stdout.String(), "repomd_sha256=") {
		t.Fatalf("missing YUM sync evidence: %s", stdout.String())
	}
	localPackage := filepath.Join(root, ".sow", "materialized", "beta", "yum", "test", "x86_64", filepath.FromSlash(info.Location))
	if _, err := os.Stat(localPackage); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, ".sow", "state", "provenance", "rpm", info.SHA256+".json")
	receiptBody, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := provenance.Decode(receiptBody)
	if err != nil || receipt.Schema != provenance.Schema || receipt.RPM == nil || receipt.RPM.IndexSHA256 == "" ||
		receipt.RPM.OriginalRPMSHA != info.SHA256 || receipt.RPM.SignatureVerification != "verified" ||
		receipt.RPM.PackageKeyringSHA256 == "" || len(receipt.RPM.EmbeddedSignatures) == 0 ||
		receipt.RPM.EmbeddedSignatures[0].SignerFingerprint == "" {
		t.Fatalf("YUM provenance receipt=%#v err=%v", receipt, err)
	}
	yumEvidenceBefore, err := filepath.Glob(filepath.Join(root, ".sow", "state", "provenance", "evidence", "sha256", "*"))
	if err != nil || len(yumEvidenceBefore) < 3 {
		t.Fatalf("initial YUM canonical evidence=%v err=%v", yumEvidenceBefore, err)
	}
	stdout.Reset()
	stderr.Reset()
	if err := runSyncWithClientFactory(ctx, args, &stdout, &stderr, factory); err != nil || !strings.Contains(stdout.String(), "download=0") || !strings.Contains(stdout.String(), "provenance_changed=false") {
		t.Fatalf("idempotent YUM sync err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	newSource := filepath.Join("..", "..", "third_party", "cavaliergopher-rpm", "testdata", "centos-release-4-0.1.x86_64.rpm")
	newPayload, err := os.ReadFile(newSource)
	if err != nil {
		t.Fatal(err)
	}
	newBasename := filepath.Base(newSource)
	newStaged := filepath.Join(upstreamRoot, newBasename)
	if err := os.WriteFile(newStaged, newPayload, 0o444); err != nil {
		t.Fatal(err)
	}
	newInfo, err := yumrepo.InspectPackage(ctx, yumrepo.PackageInput{Path: newStaged})
	if err != nil {
		t.Fatal(err)
	}
	newRPMPath := filepath.Join(upstreamRoot, filepath.FromSlash(newInfo.Location))
	if err := os.MkdirAll(filepath.Dir(newRPMPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(newStaged, newRPMPath); err != nil {
		t.Fatal(err)
	}
	buildUpstream([]yumrepo.PackageInput{
		{Path: newRPMPath, Basename: newBasename, FileTime: created},
		{Path: rpmPath, Basename: basename, FileTime: created},
	}, 2)
	stdout.Reset()
	stderr.Reset()
	if err := runSyncWithClientFactory(ctx, args, &stdout, &stderr, factory); err != nil || !strings.Contains(stdout.String(), "download=1") ||
		!strings.Contains(stdout.String(), "present=1") || !strings.Contains(stdout.String(), "provenance_changed=true") {
		t.Fatalf("YUM signed-index rotation err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if retained, err := os.ReadFile(receiptPath); err != nil || !bytes.Equal(retained, receiptBody) {
		t.Fatalf("YUM rotation rewrote first receipt err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", "state", "provenance", "rpm", newInfo.SHA256+".json")); err != nil {
		t.Fatalf("YUM rotation omitted new receipt: %v", err)
	}
	yumEvidenceAfter, err := filepath.Glob(filepath.Join(root, ".sow", "state", "provenance", "evidence", "sha256", "*"))
	if err != nil || len(yumEvidenceAfter) <= len(yumEvidenceBefore) {
		t.Fatalf("YUM rotation did not commit new signed evidence: before=%d after=%d err=%v", len(yumEvidenceBefore), len(yumEvidenceAfter), err)
	}
	stdout.Reset()
	stderr.Reset()
	if err := runSyncWithClientFactory(ctx, args, &stdout, &stderr, factory); err != nil || !strings.Contains(stdout.String(), "download=0") ||
		!strings.Contains(stdout.String(), "present=2") || !strings.Contains(stdout.String(), "provenance_changed=false") {
		t.Fatalf("YUM rotated replay err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if err := os.Remove(rpmPath); err != nil {
		t.Fatal(err)
	}
	buildUpstream(nil, 3)
	stdout.Reset()
	stderr.Reset()
	if err := runSyncWithClientFactory(ctx, args, &stdout, &stderr, factory); err != nil {
		t.Fatalf("YUM sync after upstream deletion: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(localPackage); err != nil {
		t.Fatalf("additive YUM sync deleted historical RPM: %v", err)
	}
}

func TestBearerTransportNeverForwardsCredentialToAnotherHost(t *testing.T) {
	var firstAuth, secondAuth string
	second := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		secondAuth = request.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer second.Close()
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		firstAuth = request.Header.Get("Authorization")
		http.Redirect(w, request, second.URL, http.StatusTemporaryRedirect)
	}))
	defer first.Close()
	parsed, _ := url.Parse(first.URL)
	base := first.Client().Transport
	client := &http.Client{Transport: bearerTransport{base: base, host: parsed.Host, token: []byte("opaque-secret")}}
	response, err := client.Get(first.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if firstAuth != "Bearer opaque-secret" || secondAuth != "" {
		t.Fatalf("authorization first=%q second=%q", firstAuth, secondAuth)
	}
}

const syncAPTTestConfig = `schema: sow/v1
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
    arches: [amd64, arm64]
    os: {family: ubuntu, major: 22, suite: jammy, lifecycle: active}
    apt: {suites: [jammy], components: [main]}
upstreams:
  - id: pgdg
    type: apt
    repo: apt-test
    url: %s
    suite: jammy
    components: [main]
    arches: [amd64, arm64]
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

const syncYUMTestConfig = `schema: sow/v1
state: {}
gpg:
  public_key: upstream.asc
pools:
  public: {}
  gated: {}
repos:
  - id: yum-test
    type: yum
    path: yum/test/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
upstreams:
  - id: el
    type: yum
    repo: yum-test
    url: %s
    arches: [x86_64]
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

func syncYUMSeparateTestConfig(baseURL string) string {
	value := fmt.Sprintf(syncYUMTestConfig, baseURL)
	value = strings.Replace(value, "path: yum/test/x86_64", "path: yum/test/{arch}", 1)
	value = strings.ReplaceAll(value, "arches: [x86_64]", "arches: [x86_64, noarch]")
	value = strings.Replace(value,
		"yum: {compression: zstd, package_keyring: package-trust.asc}",
		"yum: {compression: zstd, package_keyring: package-trust.asc, noarch_mode: separate}", 1)
	return value
}

func writeSyncMinimalDEB(t *testing.T, dir, packageName, version, architecture string) string {
	t.Helper()
	control := fmt.Sprintf("Package: %s\nSource: %s\nVersion: %s\nArchitecture: %s\nMaintainer: SOW Test <sow@example.invalid>\nInstalled-Size: 1\nSection: utils\nPriority: optional\nDescription: sync rotation fixture\n", packageName, packageName, version, architecture)
	controlTar := writeSyncTarGzip(t, "control", []byte(control))
	dataTar := writeSyncTarGzip(t, "usr/share/doc/"+packageName+"/README", []byte(packageName+"\n"))
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	writeSyncArMember(t, &archive, "debian-binary", []byte("2.0\n"))
	writeSyncArMember(t, &archive, "control.tar.gz", controlTar)
	writeSyncArMember(t, &archive, "data.tar.gz", dataTar)
	filename := filepath.Join(dir, fmt.Sprintf("%s_%s_%s.deb", packageName, version, architecture))
	if err := os.WriteFile(filename, archive.Bytes(), 0o444); err != nil {
		t.Fatal(err)
	}
	return filename
}

func writeSyncTarGzip(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func writeSyncArMember(t *testing.T, output *bytes.Buffer, name string, data []byte) {
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
