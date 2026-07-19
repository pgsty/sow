package cli

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
)

type publicationTrustFixture struct {
	root             string
	configPath       string
	repositoryPublic string
	rpmKeyring       string
	cfg              *config.Config
	canonical        *state.Store
	txDir            string
	values           commonFlags
	publication      targetPublication
	transport        *cloudProtocolTransport
}

func newPublicationTrustFixture(t *testing.T) publicationTrustFixture {
	t.Helper()
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishPackageConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := writePublishTestPrivateKey(t, root)
	encoded, err := os.ReadFile("testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	if err != nil {
		t.Fatal(err)
	}
	rpmBody, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	rpmPath := filepath.Join(root, "package.rpm")
	if err := os.WriteFile(rpmPath, rpmBody, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("add RPM code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	repo, exists := cfg.RepoByName("rpm-test")
	if !exists {
		t.Fatal("rpm-test repository is not configured")
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "publish-trust-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(txDir) })
	privateKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	values := commonFlags{configPath: configPath, repos: csvFlag{items: []string{"rpm-test"}}, workers: 2, chunk: 2}
	repositoryKeySHA, err := repositorySigningKeyIdentity(cfg, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	values.materializeTrust, err = captureMaterializationTrust(cfg, selectedLeaves([]config.Repo{repo}, values), privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := preparePublicationView(t.Context(), cfg, canonical, pool, []config.Repo{repo}, "beta", txDir, values, privateKey, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	prepared.repositoryKeySHA256 = repositoryKeySHA
	desiredHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	publication, err := buildTargetPublication(t.Context(), cfg, canonical, []config.Repo{repo}, prepared, "cf", desiredHead, txDir, values)
	if err != nil {
		t.Fatal(err)
	}
	if publication.trust == nil {
		t.Fatal("publication plan did not capture an immutable trust snapshot")
	}
	return publicationTrustFixture{
		root: root, configPath: configPath,
		repositoryPublic: filepath.Join(root, "signing.key.pub"),
		rpmKeyring:       filepath.Join(root, "package-trust.asc"),
		cfg:              cfg, canonical: canonical, txDir: txDir, values: values,
		publication: publication, transport: transport,
	}
}

func (fixture publicationTrustFixture) publisher(t *testing.T, hooks pub.Hooks) *pub.Publisher {
	t.Helper()
	journalDir := filepath.Join(fixture.cfg.StatePath(), "publish-journal")
	publisher := pub.NewR2CloudflarePublisher(fixture.publication.client.r2, pub.DirectorySource{Root: fixture.root}, journalDir, hooks)
	return publisher.WithRequiredPurgeEvidence().WithWorkers(fixture.values.workers).WithTrustGuard(fixture.publication.trustGuard(fixture.cfg))
}

func TestPublicationTrustRejectsRepositoryKeyAtomicReplacementBeforeRemoteMutation(t *testing.T) {
	fixture := newPublicationTrustFixture(t)
	_, rotatedPublic := generateRepositorySigningKey(t, "publish-plan-rotation")
	atomicReplaceTestFile(t, fixture.repositoryPublic, rotatedPublic, 0o644)

	result, err := fixture.publisher(t, pub.Hooks{}).Run(t.Context(), fixture.publication.request)
	if err == nil || !errors.Is(err, pub.ErrDrift) || !strings.Contains(err.Error(), "repository public key changed") || !strings.Contains(err.Error(), string(pub.TrustBeforeRemoteMutation)) {
		t.Fatalf("repository key replacement result=%+v err=%v", result, err)
	}
	if result.Phase != pub.PhasePlanned || result.RemoteRefReady {
		t.Fatalf("rejected publication crossed a remote boundary: %+v", result)
	}
	fixture.transport.mutex.Lock()
	puts, purges := fixture.transport.puts, fixture.transport.purges
	_, checkpointExists := fixture.transport.objects[pub.CheckpointKey]
	fixture.transport.mutex.Unlock()
	if puts != 0 || purges != 0 || checkpointExists {
		t.Fatalf("pre-boundary rejection mutated remote state puts=%d purges=%d checkpoint=%t", puts, purges, checkpointExists)
	}
	if _, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf"); err != nil || exists {
		t.Fatalf("pre-boundary rejection persisted a local generation exists=%t err=%v", exists, err)
	}
}

func TestPublicationTrustRejectsRPMKeyringAtomicReplacementDuringSagaAndRecovers(t *testing.T) {
	fixture := newPublicationTrustFixture(t)
	originalKeyring, err := os.ReadFile(fixture.rpmKeyring)
	if err != nil {
		t.Fatal(err)
	}
	_, rotatedKeyring := generateRepositorySigningKey(t, "publish-rpm-trust-rotation")
	var rotateOnce sync.Once
	publisher := fixture.publisher(t, pub.Hooks{AfterPhase: func(_ pub.TargetName, phase pub.Phase) error {
		if phase == pub.PhaseGenerationReady {
			rotateOnce.Do(func() { atomicReplaceTestFile(t, fixture.rpmKeyring, rotatedKeyring, 0o644) })
		}
		return nil
	}})
	result, err := publisher.Run(t.Context(), fixture.publication.request)
	if err == nil || !errors.Is(err, pub.ErrDrift) || !strings.Contains(err.Error(), "RPM package trust-derived config identity changed") || !strings.Contains(err.Error(), string(pub.TrustBeforePointerFlip)) {
		t.Fatalf("RPM keyring replacement result=%+v err=%v", result, err)
	}
	if result.Phase != pub.PhaseGenerationReady || result.RemoteRefReady {
		t.Fatalf("rotated keyring crossed the pointer boundary: %+v", result)
	}
	fixture.transport.mutex.Lock()
	checkpointObject, checkpointExists := fixture.transport.objects[pub.CheckpointKey]
	for _, object := range fixture.publication.request.Plan.Objects {
		switch object.Class {
		case pub.ObjectLegacyMetadata, pub.ObjectYUMAliasMetadata, pub.ObjectYUMAliasPointer, pub.ObjectPointer:
			if _, exists := fixture.transport.objects[object.RemoteKey]; exists {
				fixture.transport.mutex.Unlock()
				t.Fatalf("rejected trust rotation exposed mutable object %s class=%s", object.RemoteKey, object.Class)
			}
		}
	}
	fixture.transport.mutex.Unlock()
	if !checkpointExists {
		t.Fatal("interrupted saga did not retain its recoverable remote lock")
	}
	checkpoint, err := pub.DecodeCheckpoint(checkpointObject.body)
	if err != nil || checkpoint.Phase != pub.PhaseLocked {
		t.Fatalf("interrupted checkpoint=%+v err=%v", checkpoint, err)
	}
	if _, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf"); err != nil || exists {
		t.Fatalf("failed saga persisted local target exists=%t err=%v", exists, err)
	}

	atomicReplaceTestFile(t, fixture.rpmKeyring, originalKeyring, 0o644)
	recovered, err := fixture.publisher(t, pub.Hooks{}).Run(t.Context(), fixture.publication.request)
	if err != nil || !recovered.RemoteRefReady || recovered.Phase != pub.PhaseRemoteRefReady {
		t.Fatalf("trust-restored saga did not recover result=%+v err=%v", recovered, err)
	}
}

func TestPublicationTrustPostPointerRotationIsForwardRecoverableInterruption(t *testing.T) {
	fixture := newPublicationTrustFixture(t)
	originalKeyring, err := os.ReadFile(fixture.rpmKeyring)
	if err != nil {
		t.Fatal(err)
	}
	_, rotatedKeyring := generateRepositorySigningKey(t, "publish-post-pointer-rotation")
	var rotateOnce sync.Once
	fixture.publication.trust.beforeCheck = func(boundary pub.TrustBoundary) {
		if boundary == pub.TrustAfterPointerFlip {
			rotateOnce.Do(func() { atomicReplaceTestFile(t, fixture.rpmKeyring, rotatedKeyring, 0o644) })
		}
	}
	result, err := fixture.publisher(t, pub.Hooks{}).Run(t.Context(), fixture.publication.request)
	if err == nil || !errors.Is(err, pub.ErrDrift) || !strings.Contains(err.Error(), string(pub.TrustAfterPointerFlip)) || result.RemoteRefReady {
		t.Fatalf("post-pointer trust rotation result=%+v err=%v", result, err)
	}
	if result.Phase != pub.PhaseGenerationReady {
		t.Fatalf("post-pointer trust failure advanced its durable journal: %+v", result)
	}
	fixture.transport.mutex.Lock()
	mutableObjects := 0
	for _, object := range fixture.publication.request.Plan.Objects {
		switch object.Class {
		case pub.ObjectLegacyMetadata, pub.ObjectYUMAliasMetadata, pub.ObjectYUMAliasPointer, pub.ObjectPointer:
			if _, exists := fixture.transport.objects[object.RemoteKey]; !exists {
				fixture.transport.mutex.Unlock()
				t.Fatalf("post-pointer interruption lost replayable mutable object %s class=%s", object.RemoteKey, object.Class)
			}
			mutableObjects++
		}
	}
	checkpointObject, checkpointExists := fixture.transport.objects[pub.CheckpointKey]
	fixture.transport.mutex.Unlock()
	if mutableObjects == 0 || !checkpointExists {
		t.Fatalf("test did not cross the mutable boundary objects=%d checkpoint=%t", mutableObjects, checkpointExists)
	}
	checkpoint, err := pub.DecodeCheckpoint(checkpointObject.body)
	if err != nil || checkpoint.Phase != pub.PhaseLocked {
		t.Fatalf("post-pointer interruption checkpoint=%+v err=%v", checkpoint, err)
	}
	if _, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf"); err != nil || exists {
		t.Fatalf("post-pointer interruption persisted local success exists=%t err=%v", exists, err)
	}

	atomicReplaceTestFile(t, fixture.rpmKeyring, originalKeyring, 0o644)
	recovered, err := fixture.publisher(t, pub.Hooks{}).Run(t.Context(), fixture.publication.request)
	if err != nil || !recovered.RemoteRefReady || recovered.Phase != pub.PhaseRemoteRefReady {
		t.Fatalf("post-pointer interruption did not recover forward result=%+v err=%v", recovered, err)
	}
	commit, err := persistPublishedTarget(t.Context(), fixture.cfg, fixture.canonical, fixture.publication, recovered, fixture.txDir)
	if err != nil || commit.IsZero() {
		t.Fatalf("forward recovery did not persist local remote refs commit=%s err=%v", commit, err)
	}
	fixture.transport.mutex.Lock()
	committedObject := fixture.transport.objects[pub.CheckpointKey]
	purges := fixture.transport.purges
	fixture.transport.mutex.Unlock()
	committedCheckpoint, err := pub.DecodeCheckpoint(committedObject.body)
	if err != nil || committedCheckpoint.Phase != pub.PhaseCheckpointCommitted || purges == 0 {
		t.Fatalf("forward recovery checkpoint=%+v purges=%d err=%v", committedCheckpoint, purges, err)
	}
	local, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf")
	if err != nil || !exists || local.Generation != recovered.Generation {
		t.Fatalf("forward recovery local target=%+v exists=%t err=%v", local, exists, err)
	}
}

func TestPublicationTrustPostCheckpointAndLocalPersistFailuresRemainRecoverable(t *testing.T) {
	fixture := newPublicationTrustFixture(t)
	originalRepositoryKey, err := os.ReadFile(fixture.repositoryPublic)
	if err != nil {
		t.Fatal(err)
	}
	originalKeyring, err := os.ReadFile(fixture.rpmKeyring)
	if err != nil {
		t.Fatal(err)
	}
	_, rotatedRepositoryKey := generateRepositorySigningKey(t, "publish-post-checkpoint-rotation")
	var rotateCheckpointOnce sync.Once
	fixture.publication.trust.beforeCheck = func(boundary pub.TrustBoundary) {
		if boundary == pub.TrustAfterCheckpoint {
			rotateCheckpointOnce.Do(func() { atomicReplaceTestFile(t, fixture.repositoryPublic, rotatedRepositoryKey, 0o644) })
		}
	}
	result, err := fixture.publisher(t, pub.Hooks{}).Run(t.Context(), fixture.publication.request)
	if err == nil || !errors.Is(err, pub.ErrDrift) || !strings.Contains(err.Error(), string(pub.TrustAfterCheckpoint)) || result.RemoteRefReady {
		t.Fatalf("post-checkpoint trust rotation result=%+v err=%v", result, err)
	}
	fixture.transport.mutex.Lock()
	committedObject, checkpointExists := fixture.transport.objects[pub.CheckpointKey]
	fixture.transport.mutex.Unlock()
	if !checkpointExists {
		t.Fatal("post-checkpoint rejection lost remote recovery evidence")
	}
	committedCheckpoint, err := pub.DecodeCheckpoint(committedObject.body)
	if err != nil || committedCheckpoint.Phase != pub.PhaseCheckpointCommitted {
		t.Fatalf("post-boundary checkpoint=%+v err=%v", committedCheckpoint, err)
	}
	if _, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf"); err != nil || exists {
		t.Fatalf("post-checkpoint failure was reported as local success exists=%t err=%v", exists, err)
	}

	atomicReplaceTestFile(t, fixture.repositoryPublic, originalRepositoryKey, 0o644)
	recovered, err := fixture.publisher(t, pub.Hooks{}).Run(t.Context(), fixture.publication.request)
	if err != nil || !recovered.RemoteRefReady {
		t.Fatalf("committed checkpoint was not recoverable after restoring trust result=%+v err=%v", recovered, err)
	}

	// A committed replay still re-issues its exact deletion/purge closure and
	// repairs the immutable generation before returning the local ref vector.
	// Rotate trust after that mutable replay boundary and prove the existing
	// checkpoint is recovery evidence, never permission to report success.
	_, replayRotatedKeyring := generateRepositorySigningKey(t, "publish-committed-replay-rotation")
	var rotateReplayOnce sync.Once
	fixture.publication.trust.beforeCheck = func(boundary pub.TrustBoundary) {
		if boundary == pub.TrustAfterPointerFlip {
			rotateReplayOnce.Do(func() { atomicReplaceTestFile(t, fixture.rpmKeyring, replayRotatedKeyring, 0o644) })
		}
	}
	replayResult, err := fixture.publisher(t, pub.Hooks{}).Run(t.Context(), fixture.publication.request)
	if err == nil || !errors.Is(err, pub.ErrDrift) || !strings.Contains(err.Error(), string(pub.TrustAfterPointerFlip)) || replayResult.RemoteRefReady {
		t.Fatalf("committed replay accepted trust rotation result=%+v err=%v", replayResult, err)
	}
	if _, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf"); err != nil || exists {
		t.Fatalf("failed committed replay persisted local success exists=%t err=%v", exists, err)
	}
	atomicReplaceTestFile(t, fixture.rpmKeyring, originalKeyring, 0o644)
	fixture.publication.trust.beforeCheck = nil
	recovered, err = fixture.publisher(t, pub.Hooks{}).Run(t.Context(), fixture.publication.request)
	if err != nil || !recovered.RemoteRefReady {
		t.Fatalf("committed replay did not recover after restoring trust result=%+v err=%v", recovered, err)
	}

	_, rotatedKeyring := generateRepositorySigningKey(t, "publish-local-persist-rotation")
	var rotatePersistOnce sync.Once
	fixture.publication.trust.beforeCheck = func(boundary pub.TrustBoundary) {
		if boundary == pub.TrustBeforeLocalPersist {
			rotatePersistOnce.Do(func() { atomicReplaceTestFile(t, fixture.rpmKeyring, rotatedKeyring, 0o644) })
		}
	}
	commit, err := persistPublishedTarget(t.Context(), fixture.cfg, fixture.canonical, fixture.publication, recovered, fixture.txDir)
	if err == nil || !errors.Is(err, pub.ErrDrift) || !commit.IsZero() || !strings.Contains(err.Error(), string(pub.TrustBeforeLocalPersist)) {
		t.Fatalf("local persist accepted rotated trust commit=%s err=%v", commit, err)
	}
	if _, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf"); err != nil || exists {
		t.Fatalf("rejected local persist advanced canonical target exists=%t err=%v", exists, err)
	}

	atomicReplaceTestFile(t, fixture.rpmKeyring, originalKeyring, 0o644)
	fixture.publication.trust.beforeCheck = nil
	recoveryDir, err := newTransactionDir(fixture.cfg.StatePath(), "publish-trust-persist-recovery-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(recoveryDir)
	commit, err = persistPublishedTarget(t.Context(), fixture.cfg, fixture.canonical, fixture.publication, recovered, recoveryDir)
	if err != nil || commit.IsZero() {
		t.Fatalf("local persist did not recover after trust restoration commit=%s err=%v", commit, err)
	}
	local, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf")
	if err != nil || !exists || local.Generation != recovered.Generation {
		t.Fatalf("recovered local target=%+v exists=%t err=%v", local, exists, err)
	}
}
