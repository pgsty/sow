package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"golang.org/x/sys/unix"
)

func TestProjectionStageInstallPreservesLegacyTemporaryCanary(t *testing.T) {
	stateRoot := t.TempDir()
	relative := assetProjectionStagePrefix + strings.Repeat("1", 32) + ".tsv"
	source := writeProjectionStageSource(t, []byte("admitted source"))
	legacy := filepath.Join(stateRoot, relative+".tmp")
	canary := []byte("legacy canary")
	if err := os.WriteFile(legacy, canary, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := installPendingAssetProjectionStage(stateRoot, relative, source); err != nil {
		t.Fatalf("install projection stage: %v", err)
	}
	if body, err := os.ReadFile(legacy); err != nil || !bytes.Equal(body, canary) {
		t.Fatalf("legacy temporary was deleted or changed body=%q err=%v", body, err)
	}
}

func TestProjectionStageInstallDoesNotOverwriteConcurrentDestination(t *testing.T) {
	stateRoot := t.TempDir()
	relative := assetProjectionStagePrefix + strings.Repeat("2", 32) + ".tsv"
	source := writeProjectionStageSource(t, []byte("admitted source"))
	canary := []byte("concurrent destination")
	previous := projectionStageInstallHook
	projectionStageInstallHook = func(phase, _ string) error {
		if phase == "before-install" {
			return os.WriteFile(filepath.Join(stateRoot, relative), canary, 0o600)
		}
		return nil
	}
	t.Cleanup(func() { projectionStageInstallHook = previous })
	if _, err := installPendingAssetProjectionStage(stateRoot, relative, source); err == nil {
		t.Fatal("projection stage overwrote a concurrent destination")
	}
	if body, err := os.ReadFile(filepath.Join(stateRoot, relative)); err != nil || !bytes.Equal(body, canary) {
		t.Fatalf("concurrent destination was deleted or changed body=%q err=%v", body, err)
	}
	projectionStageInstallHook = previous
}

func TestProjectionStageInstallRejectsCandidateReplacement(t *testing.T) {
	stateRoot := t.TempDir()
	relative := assetProjectionStagePrefix + strings.Repeat("3", 32) + ".tsv"
	source := writeProjectionStageSource(t, []byte("admitted source"))
	canary := []byte("candidate replacement")
	var replacement string
	previous := projectionStageInstallHook
	projectionStageInstallHook = func(phase, candidate string) error {
		if phase != "before-install" {
			return nil
		}
		replacement = candidate
		if err := os.Rename(candidate, candidate+".test-original"); err != nil {
			return err
		}
		return os.WriteFile(candidate, canary, 0o600)
	}
	t.Cleanup(func() { projectionStageInstallHook = previous })
	if _, err := installPendingAssetProjectionStage(stateRoot, relative, source); err == nil {
		t.Fatal("projection stage published a replacement candidate")
	}
	if _, err := os.Lstat(filepath.Join(stateRoot, relative)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement candidate reached destination: %v", err)
	}
	if body, err := os.ReadFile(replacement); err != nil || !bytes.Equal(body, canary) {
		t.Fatalf("replacement candidate was deleted or changed body=%q err=%v", body, err)
	}
	projectionStageInstallHook = previous
}

func TestProjectionStageInstallRejectsSourceCoordinateReplacement(t *testing.T) {
	stateRoot := t.TempDir()
	relative := assetProjectionStagePrefix + strings.Repeat("4", 32) + ".tsv"
	body := []byte("same bytes, unrelated inode")
	source := writeProjectionStageSource(t, body)
	previous := projectionStageInstallHook
	projectionStageInstallHook = func(phase, path string) error {
		if phase != "after-source-inspection" {
			return nil
		}
		if err := os.Rename(path, path+".test-original"); err != nil {
			return err
		}
		return os.WriteFile(path, body, 0o600)
	}
	t.Cleanup(func() { projectionStageInstallHook = previous })
	if _, err := installPendingAssetProjectionStage(stateRoot, relative, source); err == nil {
		t.Fatal("projection stage accepted a source-coordinate replacement")
	}
	if _, err := os.Lstat(filepath.Join(stateRoot, relative)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source replacement produced a stage: %v", err)
	}
	projectionStageInstallHook = previous
}

func TestProjectionStageInstallRejectsSpecialSourceReplacementWithoutBlocking(t *testing.T) {
	stateRoot := t.TempDir()
	relative := assetProjectionStagePrefix + strings.Repeat("5", 32) + ".tsv"
	source := writeProjectionStageSource(t, []byte("ordinary admitted source"))
	previous := projectionStageInstallHook
	projectionStageInstallHook = func(phase, path string) error {
		if phase != "after-source-inspection" {
			return nil
		}
		if err := os.Rename(path, path+".test-original"); err != nil {
			return err
		}
		return unix.Mkfifo(path, 0o600)
	}
	t.Cleanup(func() { projectionStageInstallHook = previous })
	if _, err := installPendingAssetProjectionStage(stateRoot, relative, source); err == nil {
		t.Fatal("projection stage accepted a FIFO source replacement")
	}
	if _, err := os.Lstat(filepath.Join(stateRoot, relative)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("FIFO replacement produced a stage: %v", err)
	}
	projectionStageInstallHook = previous
}

func TestProjectionStageInstallRejectsPostVerifyDestinationReplacement(t *testing.T) {
	stateRoot := t.TempDir()
	relative := assetProjectionStagePrefix + strings.Repeat("6", 32) + ".tsv"
	source := writeProjectionStageSource(t, []byte("admitted source"))
	canary := []byte("post-verify destination replacement")
	destination := filepath.Join(stateRoot, relative)
	previous := projectionStageInstallHook
	projectionStageInstallHook = func(phase, _ string) error {
		if phase != "after-destination-verify" {
			return nil
		}
		if err := os.Rename(destination, destination+".test-original"); err != nil {
			return err
		}
		return os.WriteFile(destination, canary, 0o600)
	}
	t.Cleanup(func() { projectionStageInstallHook = previous })
	if _, err := installPendingAssetProjectionStage(stateRoot, relative, source); err == nil {
		t.Fatal("projection stage accepted a post-verify destination replacement")
	}
	if body, err := os.ReadFile(destination); err != nil || !bytes.Equal(body, canary) {
		t.Fatalf("post-verify destination replacement was deleted or changed body=%q err=%v", body, err)
	}
	projectionStageInstallHook = previous
}

func TestProjectionStageInstallBoundsOversizedReader(t *testing.T) {
	stateRoot := t.TempDir()
	relative := assetProjectionStagePrefix + strings.Repeat("7", 32) + ".tsv"
	want := bytes.Repeat([]byte("a"), 32)
	digest := sha256.Sum256(want)
	parsed, err := repository.ParseDigest(hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	reader := &projectionStageCountingReader{remaining: 1 << 20}
	if _, _, err := installProjectionStageReader(stateRoot, relative, repository.Object{SHA256: parsed, Size: int64(len(want))}, reader, nil, nil); err == nil {
		t.Fatal("projection stage accepted an oversized source")
	}
	if reader.read != int64(len(want)+1) {
		t.Fatalf("oversized source read=%d want=%d", reader.read, len(want)+1)
	}
	if entries, err := os.ReadDir(stateRoot); err != nil || len(entries) != 0 {
		t.Fatalf("oversized source left projection residue entries=%v err=%v", entries, err)
	}
}

func TestProjectionStageInstallRepairsRestrictiveUmask(t *testing.T) {
	stateRoot := t.TempDir()
	relative := assetProjectionStagePrefix + strings.Repeat("d", 32) + ".tsv"
	source := writeProjectionStageSource(t, []byte("umask-bound source"))
	previous := unix.Umask(0o400)
	defer unix.Umask(previous)
	if _, err := installPendingAssetProjectionStage(stateRoot, relative, source); err != nil {
		t.Fatalf("install projection stage under restrictive umask: %v", err)
	}
	info, err := os.Stat(filepath.Join(stateRoot, relative))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("projection stage mode=%v err=%v want=0600", info, err)
	}
}

func TestOfflineArchiveExactOpenRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	source := writeProjectionStageSource(t, []byte("ordinary source"))
	previous := offlineArchiveInputBeforeOpenHook
	offlineArchiveInputBeforeOpenHook = func(path string) error {
		if err := os.Rename(path, path+".test-original"); err != nil {
			return err
		}
		return unix.Mkfifo(path, 0o600)
	}
	t.Cleanup(func() { offlineArchiveInputBeforeOpenHook = previous })
	done := make(chan error, 1)
	go func() {
		file, _, err := openExactOfflineArchiveInput(source)
		if file != nil {
			err = errors.Join(err, file.Close())
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("offline archive exact open accepted a FIFO replacement")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("offline archive exact open blocked on a FIFO replacement")
	}
	offlineArchiveInputBeforeOpenHook = previous
}

func TestProjectionStageBindRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	stateRoot := t.TempDir()
	relative := assetProjectionStagePrefix + strings.Repeat("e", 32) + ".tsv"
	path := filepath.Join(stateRoot, relative)
	if err := os.WriteFile(path, []byte("bound stage"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	previous := projectionStateBeforeBindOpenHook
	projectionStateBeforeBindOpenHook = func(name string) error {
		if name != relative {
			return nil
		}
		if err := os.Rename(path, path+".test-original"); err != nil {
			return err
		}
		return unix.Mkfifo(path, 0o600)
	}
	t.Cleanup(func() { projectionStateBeforeBindOpenHook = previous })
	done := make(chan error, 1)
	go func() {
		file, _, err := bindExactProjectionStage(root, relative, int64(len("bound stage")))
		if file != nil {
			err = errors.Join(err, file.Close())
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("projection stage binder accepted a FIFO replacement")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("projection stage binder blocked on a FIFO replacement")
	}
	projectionStateBeforeBindOpenHook = previous
}

func TestProjectionIntentInstallDoesNotOverwriteConcurrentDestination(t *testing.T) {
	stateRoot := t.TempDir()
	relative := assetProjectionIntentRelative
	canary := []byte("concurrent projection intent")
	previous := projectionStageInstallHook
	projectionStageInstallHook = func(phase, _ string) error {
		if phase == "before-install" {
			return os.WriteFile(filepath.Join(stateRoot, relative), canary, 0o600)
		}
		return nil
	}
	t.Cleanup(func() { projectionStageInstallHook = previous })
	if err := installProjectionIntentBytes(stateRoot, relative, []byte("writer intent"), nil); err == nil {
		t.Fatal("projection intent installer overwrote a concurrent destination")
	}
	if body, err := os.ReadFile(filepath.Join(stateRoot, relative)); err != nil || !bytes.Equal(body, canary) {
		t.Fatalf("concurrent projection intent was deleted or changed body=%q err=%v", body, err)
	}
	projectionStageInstallHook = previous
}

func TestProjectionStageInstallRejectsPreparedRootReplacement(t *testing.T) {
	parent := t.TempDir()
	stateRoot := filepath.Join(parent, "state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	first := assetProjectionStagePrefix + strings.Repeat("9", 32) + ".tsv"
	_, identity, err := installProjectionStageBytes(stateRoot, first, []byte("first stage"))
	if err != nil {
		t.Fatal(err)
	}
	detached := filepath.Join(parent, "detached-state")
	if err := os.Rename(stateRoot, detached); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	second := assetProjectionStagePrefix + strings.Repeat("a", 32) + "-config.yaml"
	if _, _, err := installProjectionStageBytesBound(stateRoot, second, []byte("second stage"), identity.root); err == nil {
		t.Fatal("projection stage installer accepted a replacement transaction root")
	}
	if _, err := os.Lstat(filepath.Join(stateRoot, second)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement root received a stage: %v", err)
	}
	if body, err := os.ReadFile(filepath.Join(detached, first)); err != nil || string(body) != "first stage" {
		t.Fatalf("original prepared stage changed body=%q err=%v", body, err)
	}
}

func TestProjectionStageRollbackRemovesOnlyInstalledIdentity(t *testing.T) {
	stateRoot := t.TempDir()
	relative := assetProjectionStagePrefix + strings.Repeat("8", 32) + ".tsv"
	source := writeProjectionStageSource(t, []byte("owned rollback source"))
	_, identity, err := installPendingProjectionStage(stateRoot, relative, source)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := removeInstalledProjectionStage(identity)
	if err != nil || !removed {
		t.Fatalf("remove installed identity removed=%t err=%v", removed, err)
	}
	if _, err := os.Lstat(filepath.Join(stateRoot, relative)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("installed identity remains after rollback: %v", err)
	}
}

func TestProjectionStageRollbackContinuesAfterReplacementConflict(t *testing.T) {
	stateRoot := t.TempDir()
	identities := make([]projectionStageIdentity, 0, 3)
	for index, suffix := range []string{"-config.yaml", "-000.tsv", "-001.tsv"} {
		relative := packageProjectionStagePrefix + strings.Repeat("b", 32) + suffix
		_, identity, err := installProjectionStageBytes(stateRoot, relative, []byte{byte('0' + index)})
		if err != nil {
			t.Fatal(err)
		}
		identities = append(identities, identity)
	}
	replaced := filepath.Join(stateRoot, identities[1].relative)
	if err := os.Rename(replaced, replaced+".test-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replaced, []byte{'1'}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rollbackInstalledProjectionStages(identities); err == nil || !strings.Contains(err.Error(), "--recover") {
		t.Fatalf("rollback replacement conflict err=%v", err)
	}
	if body, err := os.ReadFile(replaced); err != nil || !bytes.Equal(body, []byte{'1'}) {
		t.Fatalf("rollback changed same-byte replacement body=%q err=%v", body, err)
	}
	for _, identity := range []projectionStageIdentity{identities[0], identities[2]} {
		if _, err := os.Lstat(filepath.Join(stateRoot, identity.relative)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rollback stopped before cleaning exact stage %s: %v", identity.relative, err)
		}
	}
}

type projectionStageCountingReader struct {
	remaining int64
	read      int64
}

func (reader *projectionStageCountingReader) Read(body []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, nil
	}
	if int64(len(body)) > reader.remaining {
		body = body[:reader.remaining]
	}
	for index := range body {
		body[index] = 'a'
	}
	reader.remaining -= int64(len(body))
	reader.read += int64(len(body))
	return len(body), nil
}

func TestAssetProjectionPrepareRetainsStagesWhenIntentCommitIsAmbiguous(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	repo := cfg.Repos[0]
	viewPath, _ := state.ViewPath("beta", repo.ID, "all", "all")
	viewRef, _ := state.ViewRef("beta", repo.ID, "all", "all")
	stage := writeProjectionStageSource(t, []byte("asset manifest\n"))
	previous := assetProjectionIntentInstall
	assetProjectionIntentInstall = func(stateRoot, relative string, body []byte, _ os.FileInfo) error {
		if err := writeDerivedStateFile(stateRoot, relative, body); err != nil {
			return err
		}
		return errors.New("injected post-commit durability error")
	}
	t.Cleanup(func() { assetProjectionIntentInstall = previous })
	intent, _, err := prepareAssetProjectionIntent(cfg, state.New(cfg.StatePath()), "add", "", repo, "beta", viewPath, viewRef, plumbing.ZeroHash, stage, nil)
	if err == nil || !strings.Contains(err.Error(), "--recover") {
		t.Fatalf("ambiguous asset commit err=%v", err)
	}
	current, exists, readErr := readAssetProjectionIntent(cfg.StatePath())
	if readErr != nil || !exists || current.ID != intent.ID {
		t.Fatalf("durable asset intent missing current=%+v exists=%t err=%v", current, exists, readErr)
	}
	for _, relative := range []string{current.StageRelative, current.ConfigStage} {
		if _, err := os.Stat(filepath.Join(root, ".sow", relative)); err != nil {
			t.Fatalf("ambiguous asset commit removed stage %s: %v", relative, err)
		}
	}
	assetProjectionIntentInstall = previous
}

func TestAssetProjectionPreparePreservesCompetingIntentAndRollsBackOwnedStages(t *testing.T) {
	_, configPath := newAssetMaterializeHardeningFixture(t)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	repo := cfg.Repos[0]
	viewPath, _ := state.ViewPath("beta", repo.ID, "all", "all")
	viewRef, _ := state.ViewRef("beta", repo.ID, "all", "all")
	stage := writeProjectionStageSource(t, []byte("asset competing intent manifest\n"))
	var desired assetProjectionIntent
	var foreign assetProjectionIntent
	previous := assetProjectionIntentInstall
	assetProjectionIntentInstall = func(stateRoot, relative string, body []byte, _ os.FileInfo) error {
		var decodeErr error
		desired, decodeErr = decodeAssetProjectionIntent(body)
		if decodeErr != nil {
			return decodeErr
		}
		foreign = desired
		foreign.TransactionID = strings.Repeat("f", 32)
		foreign.StageRelative = assetProjectionStagePrefix + foreign.TransactionID + ".tsv"
		foreign.ConfigStage = assetProjectionStagePrefix + foreign.TransactionID + "-config.yaml"
		foreign.Message = assetProjectionIntentMessage(foreign.Operation, foreign.OperationScope, foreign.Repo, foreign.TransactionID, foreign.ArchiveAdoption)
		foreign.ID, decodeErr = assetProjectionIntentID(foreign)
		if decodeErr != nil {
			return decodeErr
		}
		foreignBody, marshalErr := json.Marshal(foreign)
		if marshalErr != nil {
			return marshalErr
		}
		if writeErr := writeDerivedStateFile(stateRoot, relative, foreignBody); writeErr != nil {
			return writeErr
		}
		return errors.New("injected competing asset intent")
	}
	t.Cleanup(func() { assetProjectionIntentInstall = previous })
	if _, _, err := prepareAssetProjectionIntent(cfg, state.New(cfg.StatePath()), "add", "", repo, "beta", viewPath, viewRef, plumbing.ZeroHash, stage, nil); err == nil {
		t.Fatal("asset prepare accepted a competing intent")
	}
	current, exists, readErr := readAssetProjectionIntent(cfg.StatePath())
	if readErr != nil || !exists || current.ID != foreign.ID {
		t.Fatalf("competing intent was changed current=%+v exists=%t err=%v", current, exists, readErr)
	}
	for _, relative := range []string{desired.StageRelative, desired.ConfigStage} {
		if _, statErr := os.Lstat(filepath.Join(cfg.StatePath(), relative)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("owned stage %s survived competing-intent rollback: %v", relative, statErr)
		}
	}
	assetProjectionIntentInstall = previous
}

func TestPackageProjectionPrepareRetainsStagesWhenIntentCommitIsAmbiguous(t *testing.T) {
	fixture := setupMaterializationSelectionFixture(t)
	repo := fixture.cfg.Repos[0]
	viewPath, _ := state.ViewPath("beta", repo.ID, "jammy", "amd64")
	viewRef, _ := state.ViewRef("beta", repo.ID, "jammy", "amd64")
	stage := writeProjectionStageSource(t, []byte("package manifest\n"))
	fixture.snapshot.verificationTime = time.Now().UTC().Truncate(time.Second)
	previous := packageProjectionIntentInstall
	packageProjectionIntentInstall = func(stateRoot, relative string, body []byte, _ os.FileInfo) error {
		if err := writeDerivedStateFile(stateRoot, relative, body); err != nil {
			return err
		}
		return errors.New("injected post-commit durability error")
	}
	t.Cleanup(func() { packageProjectionIntentInstall = previous })
	intent, _, err := preparePackageProjectionIntent(fixture.cfg, fixture.canonical, "add", "apt", []packageProjectionMutation{{
		leaf: viewLeaf{repo: repo, os: "jammy", arch: "amd64"}, view: "beta", viewPath: viewPath,
		viewRef: viewRef.String(), expected: plumbing.ZeroHash.String(),
	}}, map[string]string{viewPath: stage}, fixture.snapshot, fixture.private, nil)
	if err == nil || !strings.Contains(err.Error(), "--recover") {
		t.Fatalf("ambiguous package commit err=%v", err)
	}
	current, exists, readErr := readPackageProjectionIntent(fixture.cfg.StatePath())
	if readErr != nil || !exists || current.ID != intent.ID {
		t.Fatalf("durable package intent missing current=%+v exists=%t err=%v", current, exists, readErr)
	}
	for _, relative := range []string{current.ConfigStage, current.Units[0].StageRelative} {
		if _, err := os.Stat(filepath.Join(fixture.cfg.StatePath(), relative)); err != nil {
			t.Fatalf("ambiguous package commit removed stage %s: %v", relative, err)
		}
	}
	packageProjectionIntentInstall = previous
}

func TestAssetProjectionPrepareRollbackPreservesStageReplacement(t *testing.T) {
	_, configPath := newAssetMaterializeHardeningFixture(t)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	repo := cfg.Repos[0]
	viewPath, _ := state.ViewPath("beta", repo.ID, "all", "all")
	viewRef, _ := state.ViewRef("beta", repo.ID, "all", "all")
	stage := writeProjectionStageSource(t, []byte("asset rollback manifest\n"))
	var replacementPath string
	var configStagePath string
	var replacementBody []byte
	previous := assetProjectionIntentInstall
	assetProjectionIntentInstall = func(stateRoot, _ string, body []byte, _ os.FileInfo) error {
		intent, decodeErr := decodeAssetProjectionIntent(body)
		if decodeErr != nil {
			return decodeErr
		}
		replacementPath = filepath.Join(stateRoot, intent.StageRelative)
		configStagePath = filepath.Join(stateRoot, intent.ConfigStage)
		replacementBody, decodeErr = os.ReadFile(replacementPath)
		if decodeErr != nil {
			return decodeErr
		}
		if decodeErr = os.Rename(replacementPath, replacementPath+".test-original"); decodeErr != nil {
			return decodeErr
		}
		if decodeErr = os.WriteFile(replacementPath, replacementBody, 0o600); decodeErr != nil {
			return decodeErr
		}
		return errors.New("injected asset intent failure")
	}
	t.Cleanup(func() { assetProjectionIntentInstall = previous })
	_, _, err = prepareAssetProjectionIntent(cfg, state.New(cfg.StatePath()), "add", "", repo, "beta", viewPath, viewRef, plumbing.ZeroHash, stage, nil)
	if err == nil || !strings.Contains(err.Error(), "--recover") {
		t.Fatalf("asset rollback replacement err=%v", err)
	}
	if body, readErr := os.ReadFile(replacementPath); readErr != nil || !bytes.Equal(body, replacementBody) {
		t.Fatalf("asset rollback deleted or changed replacement body=%q err=%v", body, readErr)
	}
	if _, statErr := os.Lstat(configStagePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("asset rollback stopped before removing exact config stage: %v", statErr)
	}
	assetProjectionIntentInstall = previous
}

func TestAssetProjectionPrepareRejectsStageReplacementDuringIntentInstall(t *testing.T) {
	_, configPath := newAssetMaterializeHardeningFixture(t)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	repo := cfg.Repos[0]
	viewPath, _ := state.ViewPath("beta", repo.ID, "all", "all")
	viewRef, _ := state.ViewRef("beta", repo.ID, "all", "all")
	stage := writeProjectionStageSource(t, []byte("asset post-verification manifest\n"))
	retained := t.TempDir()
	previous := assetProjectionIntentInstall
	assetProjectionIntentInstall = func(stateRoot, relative string, body []byte, boundRoot os.FileInfo) error {
		intent, err := decodeAssetProjectionIntent(body)
		if err != nil {
			return err
		}
		path := filepath.Join(stateRoot, intent.StageRelative)
		current, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.Rename(path, filepath.Join(retained, intent.StageRelative)); err != nil {
			return err
		}
		if err := os.WriteFile(path, current, 0o600); err != nil {
			return err
		}
		return installProjectionIntentBytes(stateRoot, relative, body, boundRoot)
	}
	t.Cleanup(func() { assetProjectionIntentInstall = previous })
	intent, _, err := prepareAssetProjectionIntent(cfg, state.New(cfg.StatePath()), "add", "", repo, "beta", viewPath, viewRef, plumbing.ZeroHash, stage, nil)
	if err == nil || !strings.Contains(err.Error(), "committed with changed stages") {
		t.Fatalf("asset prepare accepted a stage replacement during intent install: %v", err)
	}
	current, exists, readErr := readAssetProjectionIntent(cfg.StatePath())
	if readErr != nil || !exists || current.ID != intent.ID {
		t.Fatalf("asset replacement failure lost committed recovery intent current=%+v exists=%t err=%v", current, exists, readErr)
	}
	assetProjectionIntentInstall = previous
}

func TestPackageProjectionPrepareRollbackPreservesStageReplacement(t *testing.T) {
	fixture := setupMaterializationSelectionFixture(t)
	repo := fixture.cfg.Repos[0]
	viewPath, _ := state.ViewPath("beta", repo.ID, "jammy", "amd64")
	viewRef, _ := state.ViewRef("beta", repo.ID, "jammy", "amd64")
	stage := writeProjectionStageSource(t, []byte("package rollback manifest\n"))
	fixture.snapshot.verificationTime = time.Now().UTC().Truncate(time.Second)
	var replacementPath string
	var configStagePath string
	var replacementBody []byte
	previous := packageProjectionIntentInstall
	packageProjectionIntentInstall = func(stateRoot, _ string, body []byte, _ os.FileInfo) error {
		intent, decodeErr := decodePackageProjectionIntent(body)
		if decodeErr != nil {
			return decodeErr
		}
		replacementPath = filepath.Join(stateRoot, intent.Units[0].StageRelative)
		configStagePath = filepath.Join(stateRoot, intent.ConfigStage)
		replacementBody, decodeErr = os.ReadFile(replacementPath)
		if decodeErr != nil {
			return decodeErr
		}
		if decodeErr = os.Rename(replacementPath, replacementPath+".test-original"); decodeErr != nil {
			return decodeErr
		}
		if decodeErr = os.WriteFile(replacementPath, replacementBody, 0o600); decodeErr != nil {
			return decodeErr
		}
		return errors.New("injected package intent failure")
	}
	t.Cleanup(func() { packageProjectionIntentInstall = previous })
	_, _, err := preparePackageProjectionIntent(fixture.cfg, fixture.canonical, "add", "apt", []packageProjectionMutation{{
		leaf: viewLeaf{repo: repo, os: "jammy", arch: "amd64"}, view: "beta", viewPath: viewPath,
		viewRef: viewRef.String(), expected: plumbing.ZeroHash.String(),
	}}, map[string]string{viewPath: stage}, fixture.snapshot, fixture.private, nil)
	if err == nil || !strings.Contains(err.Error(), "--recover") {
		t.Fatalf("package rollback replacement err=%v", err)
	}
	if body, readErr := os.ReadFile(replacementPath); readErr != nil || !bytes.Equal(body, replacementBody) {
		t.Fatalf("package rollback deleted or changed replacement body=%q err=%v", body, readErr)
	}
	if _, statErr := os.Lstat(configStagePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("package rollback stopped before removing exact config stage: %v", statErr)
	}
	packageProjectionIntentInstall = previous
}

func TestPackageProjectionPrepareRejectsStageReplacementDuringIntentInstall(t *testing.T) {
	fixture := setupMaterializationSelectionFixture(t)
	repo := fixture.cfg.Repos[0]
	viewPath, _ := state.ViewPath("beta", repo.ID, "jammy", "amd64")
	viewRef, _ := state.ViewRef("beta", repo.ID, "jammy", "amd64")
	stage := writeProjectionStageSource(t, []byte("package post-verification manifest\n"))
	fixture.snapshot.verificationTime = time.Now().UTC().Truncate(time.Second)
	retained := t.TempDir()
	previous := packageProjectionIntentInstall
	packageProjectionIntentInstall = func(stateRoot, relative string, body []byte, boundRoot os.FileInfo) error {
		intent, err := decodePackageProjectionIntent(body)
		if err != nil {
			return err
		}
		path := filepath.Join(stateRoot, intent.Units[0].StageRelative)
		current, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.Rename(path, filepath.Join(retained, intent.Units[0].StageRelative)); err != nil {
			return err
		}
		if err := os.WriteFile(path, current, 0o600); err != nil {
			return err
		}
		return installProjectionIntentBytes(stateRoot, relative, body, boundRoot)
	}
	t.Cleanup(func() { packageProjectionIntentInstall = previous })
	intent, _, err := preparePackageProjectionIntent(fixture.cfg, fixture.canonical, "add", "apt", []packageProjectionMutation{{
		leaf: viewLeaf{repo: repo, os: "jammy", arch: "amd64"}, view: "beta", viewPath: viewPath,
		viewRef: viewRef.String(), expected: plumbing.ZeroHash.String(),
	}}, map[string]string{viewPath: stage}, fixture.snapshot, fixture.private, nil)
	if err == nil || !strings.Contains(err.Error(), "committed with changed stages") {
		t.Fatalf("package prepare accepted a stage replacement during intent install: %v", err)
	}
	current, exists, readErr := readPackageProjectionIntent(fixture.cfg.StatePath())
	if readErr != nil || !exists || current.ID != intent.ID {
		t.Fatalf("package replacement failure lost committed recovery intent current=%+v exists=%t err=%v", current, exists, readErr)
	}
	packageProjectionIntentInstall = previous
}

func writeProjectionStageSource(t *testing.T, body []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stage.tsv")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
