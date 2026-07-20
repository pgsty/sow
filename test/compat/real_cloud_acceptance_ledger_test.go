package compat_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	sowconfig "github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/views"
	"golang.org/x/sys/unix"
)

const (
	realCloudAcceptanceLedgerFilename = ".sow-real-cloud-acceptance.json"
	realCloudAcceptanceLockFilename   = ".sow-real-cloud-acceptance.lock"
	realCloudAcceptanceLedgerSchema   = "sow-real-cloud-acceptance/v1"
	realCloudAcceptanceHarnessVersion = "real-cloud-acceptance-20260720-v8"
	realCloudAcceptanceLedgerLimit    = 256 << 10
)

// realCloudAcceptanceStepIDs is the frozen destructive-acceptance program.
// Its digest is part of every persistent run binding: changing the order or
// meaning of a step requires an explicit harness-version migration instead of
// silently resuming an old workspace under different test code.
var realCloudAcceptanceStepIDs = []string{
	"edge-reservation-connectivity-preflight",
	"bootstrap-files-init",
	"prove-both-buckets-empty",
	"seed-local-generation-1",
	"publish-latest-cf-g1",
	"publish-latest-cos-g1",
	"seed-local-generation-2",
	"publish-latest-cf-g2",
	"verify-cos-lag-g1",
	"publish-latest-cos-g2",
	"seed-local-generation-3",
	"publish-latest-cf-g3",
	"verify-cos-lag-g2",
	"publish-latest-cos-g3",
	"verify-latest-l2-l4",
	"latest-noop-replay-and-cas",
	"promote-stable",
	"publish-stable-both-g4",
	"edge-stage-g4",
	"verify-stable-g4",
	"seed-gated-generation-2",
	"capture-pre-purge-g4",
	"interrupt-cf-g5",
	"recover-cf-g5",
	"publish-cos-g5",
	"edge-stage-g5",
	"seal-active-evidence",
	"verify-stable-g5",
	"seed-gated-generation-3",
	"interrupt-cos-g6",
	"recover-cos-g6",
	"publish-cf-g6",
	"verify-stable-g6",
	"allocate-snapshot-ids",
	"prepare-current-and-historical-snapshots",
	"publish-expired-cf-g7",
	"copy-probe-expired-cf",
	"publish-expired-cos-g7",
	"copy-probe-expired-cos",
	"publish-current-cf-g8",
	"publish-current-cos-g8",
	"verify-current-snapshot",
	"snapshot-noop-replay",
	"restore-cf-g9",
	"restore-cos-g9",
	"restore-noop-replays",
	"publish-current-stable-cf-g10",
	"publish-current-stable-cos-g10",
	"verify-g10-cache",
	"final-fsck",
}

type realCloudAcceptanceBinding struct {
	RunID                    string `json:"run_id"`
	ConfirmationSHA256       string `json:"confirmation_sha256"`
	ConfigSHA256             string `json:"config_sha256"`
	TokenVerifier            string `json:"token_verifier"`
	PublicKeySHA256          string `json:"public_key_sha256"`
	HarnessRevision          string `json:"harness_revision"`
	ImplementationSHA256     string `json:"implementation_sha256"`
	StepTableSHA256          string `json:"step_table_sha256"`
	ActiveArtifactPathSHA256 string `json:"active_artifact_path_sha256"`
	ProviderLogPathSHA256    string `json:"provider_log_path_sha256"`
	ObserverTopologySHA256   string `json:"observer_topology_sha256"`
}

type realCloudAcceptanceLedger struct {
	Schema           string                     `json:"schema"`
	Binding          realCloudAcceptanceBinding `json:"binding"`
	Revision         uint64                     `json:"revision"`
	Status           string                     `json:"status"`
	Current          *realCloudStepAttempt      `json:"current,omitempty"`
	Receipts         []realCloudStepReceipt     `json:"receipts"`
	Facts            realCloudResumeFacts       `json:"facts"`
	FinalProofSHA256 string                     `json:"final_proof_sha256,omitempty"`
	CompletedAt      string                     `json:"completed_at,omitempty"`
}

type realCloudStepAttempt struct {
	Index                int                          `json:"index"`
	ID                   string                       `json:"id"`
	Attempt              uint32                       `json:"attempt"`
	DescriptorSHA256     string                       `json:"descriptor_sha256"`
	ImplementationSHA256 string                       `json:"implementation_sha256"`
	IntentSHA256         string                       `json:"intent_sha256"`
	StartedAt            string                       `json:"started_at"`
	Baselines            []realCloudBaseline          `json:"baselines,omitempty"`
	CLIInFlight          *realCloudCLISubstepAttempt  `json:"cli_in_flight,omitempty"`
	CLIReceipts          []realCloudCLISubstepReceipt `json:"cli_receipts,omitempty"`
}

type realCloudCLISubstepAttempt struct {
	Index        int      `json:"index"`
	IntentSHA256 string   `json:"intent_sha256"`
	Arguments    []string `json:"arguments"`
	ExpectedExit int      `json:"expected_exit"`
	StartedAt    string   `json:"started_at"`
}

type realCloudCLISubstepReceipt struct {
	Index        int      `json:"index"`
	IntentSHA256 string   `json:"intent_sha256"`
	Arguments    []string `json:"arguments"`
	ExpectedExit int      `json:"expected_exit"`
	ActualExit   int      `json:"actual_exit"`
	OutputSHA256 string   `json:"output_sha256"`
	Output       string   `json:"output"`
	CompletedAt  string   `json:"completed_at"`
}

type realCloudCLIAuditReceipt struct {
	Index        int      `json:"index"`
	Arguments    []string `json:"arguments"`
	ExpectedExit int      `json:"expected_exit"`
	ActualExit   int      `json:"actual_exit"`
	OutputSHA256 string   `json:"output_sha256"`
	CompletedAt  string   `json:"completed_at"`
}

type realCloudBaseline struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type realCloudStepReceipt struct {
	Index                int                        `json:"index"`
	ID                   string                     `json:"id"`
	DescriptorSHA256     string                     `json:"descriptor_sha256"`
	ImplementationSHA256 string                     `json:"implementation_sha256"`
	IntentSHA256         string                     `json:"intent_sha256"`
	ResultSHA256         string                     `json:"result_sha256"`
	CLITranscriptSHA256  string                     `json:"cli_transcript_sha256"`
	CLISubsteps          int                        `json:"cli_substeps"`
	CLIAudit             []realCloudCLIAuditReceipt `json:"cli_audit,omitempty"`
	CompletedAt          string                     `json:"completed_at"`
}

type realCloudAcceptanceStepDescriptor struct {
	ID                   string `json:"id"`
	SemanticVersion      uint32 `json:"semantic_version"`
	IntentTemplate       string `json:"intent_template"`
	ExpectedExit         int    `json:"expected_exit"`
	PostconditionVersion uint32 `json:"postcondition_version"`
}

type realCloudInterruptedFact struct {
	Target                 string `json:"target"`
	Generation             uint64 `json:"generation"`
	ParentGeneration       uint64 `json:"parent_generation"`
	TransactionID          string `json:"transaction_id"`
	LockedCheckpointSHA256 string `json:"locked_checkpoint_sha256"`
}

type realCloudProviderClosureFact struct {
	ProviderLogPathSHA256  string                          `json:"provider_log_path_sha256"`
	ProviderLogSHA256      string                          `json:"provider_log_sha256"`
	ProviderSealSHA256     string                          `json:"provider_seal_sha256"`
	ActiveArtifactSHA256   string                          `json:"active_artifact_sha256"`
	ActiveSealSHA256       string                          `json:"active_seal_sha256"`
	CFPurgeEvidenceSHA256  string                          `json:"cf_purge_evidence_sha256"`
	COSPurgeEvidenceSHA256 string                          `json:"cos_purge_evidence_sha256"`
	ProviderRecords        int                             `json:"provider_records"`
	ProviderAttestation    realCloudProviderRawAttestation `json:"provider_attestation"`
}

type realCloudResumeFacts struct {
	RecentSnapshotID  string `json:"recent_snapshot_id,omitempty"`
	ExpiredSnapshotID string `json:"expired_snapshot_id,omitempty"`

	CFInterrupted   *realCloudInterruptedFact     `json:"cf_interrupted,omitempty"`
	COSInterrupted  *realCloudInterruptedFact     `json:"cos_interrupted,omitempty"`
	ProviderClosure *realCloudProviderClosureFact `json:"provider_closure,omitempty"`

	// PrePurge is secret-free causal evidence. It is persisted before the
	// generation-five publish so a recovery process never has to fabricate the
	// old-generation freshness observation from new wall-clock state.
	PrePurge map[string]realEdgePrePurgeVendorEvidence `json:"pre_purge,omitempty"`
}

type realCloudAcceptanceLedgerStore struct {
	root     string
	path     string
	lockPath string
	lock     *os.File
	ledger   realCloudAcceptanceLedger
}

func realCloudAcceptanceStepTableSHA256() string {
	body, err := json.Marshal(realCloudAcceptanceStepDescriptors())
	if err != nil {
		panic("encode frozen real-cloud acceptance step table")
	}
	return realCloudLowerSHA256(body)
}

func realCloudAcceptanceStepDescriptors() []realCloudAcceptanceStepDescriptor {
	descriptors := make([]realCloudAcceptanceStepDescriptor, 0, len(realCloudAcceptanceStepIDs))
	for _, id := range realCloudAcceptanceStepIDs {
		expectedExit := 0
		semanticVersion := uint32(1)
		postconditionVersion := uint32(1)
		if id == "edge-reservation-connectivity-preflight" {
			semanticVersion = 2
			postconditionVersion = 2
		}
		if id == "interrupt-cf-g5" || id == "interrupt-cos-g6" {
			expectedExit = 5 // cli.ExitNetworkAuth; kept numeric to avoid a package-level initialization cycle.
		} else if id == "verify-cos-lag-g1" || id == "verify-cos-lag-g2" {
			expectedExit = 4 // cli.ExitVerification.
		}
		descriptors = append(descriptors, realCloudAcceptanceStepDescriptor{
			ID: id, SemanticVersion: semanticVersion, IntentTemplate: realCloudAcceptanceIntentTemplate(id),
			ExpectedExit: expectedExit, PostconditionVersion: postconditionVersion,
		})
	}
	return descriptors
}

func realCloudAcceptanceIntentTemplate(id string) string {
	templates := map[string]string{
		"edge-reservation-connectivity-preflight":  "under durable ledger+reservation: anonymous GET every observer x cf,cos; idempotently bind both provider raw-log sinks to @run",
		"bootstrap-files-init":                     "mkdir fixtures; write @public-key,@config; sow init --config @config --workers 2 --chunk-entries 64",
		"prove-both-buckets-empty":                 "sow fsck --adopt-remote-inventory --limit 0 target=cf,cos",
		"seed-local-generation-1":                  "write deb,rpm,public-asset,gated-asset-v1; sow add x4; promote beta latest public repos",
		"publish-latest-cf-g1":                     "sow publish --view latest --target cf",
		"publish-latest-cos-g1":                    "sow publish --view latest --target cos",
		"seed-local-generation-2":                  "write deb-v2; sow add apt; promote beta latest apt",
		"publish-latest-cf-g2":                     "sow publish --view latest --target cf --repo apt",
		"verify-cos-lag-g1":                        "sow verify --layer L2 --view latest --target cos --repo apt => verification exit",
		"publish-latest-cos-g2":                    "sow publish --view latest --target cos --repo apt",
		"seed-local-generation-3":                  "sow rm yum package; replace public asset-v2; promote beta latest asset",
		"publish-latest-cf-g3":                     "sow publish --view latest --target cf",
		"verify-cos-lag-g2":                        "sow verify --layer L2 --view latest --target cos => verification exit",
		"publish-latest-cos-g3":                    "sow publish --view latest --target cos",
		"verify-latest-l2-l4":                      "sow verify --layer L2,L3,L4 --view latest --target cf,cos",
		"latest-noop-replay-and-cas":               "baseline cf,cos; sow publish latest cf,cos unchanged; competing CAS probes",
		"promote-stable":                           "sow promote beta stable public repos",
		"publish-stable-both-g4":                   "sow publish --view stable --target cf,cos",
		"edge-stage-g4":                            "multi-PoP stage generation=4 body=@gated-v1 artifact=@artifact",
		"verify-stable-g4":                         "edge cache+mirrorlist; sow verify stable token=@token-a L2,L3,L4; token=@token-b L3",
		"seed-gated-generation-2":                  "write gated-v2; sow add --replace gated asset",
		"capture-pre-purge-g4":                     "multi-PoP pre-purge HIT generation=4 persist secret-free facts",
		"interrupt-cf-g5":                          "durably arm independent TTL post-probe watcher; sow publish stable cf gated repo with intentional invalid purge credential => network-auth",
		"recover-cf-g5":                            "require live independent TTL post-probe watcher; sow publish stable cf gated repo; require interrupted transaction ID",
		"publish-cos-g5":                           "require live independent TTL post-probe watcher; sow publish stable cos gated repo",
		"edge-stage-g5":                            "multi-PoP stage generation=5 body=@gated-v2 with persisted pre-purge",
		"seal-active-evidence":                     "seal exact generation 4/5 x cf,edgeone active artifact",
		"verify-stable-g5":                         "edge gated cache v2; sow verify stable gated L2,L3 cf,cos",
		"seed-gated-generation-3":                  "write gated-v3; sow add --replace gated asset",
		"interrupt-cos-g6":                         "sow publish stable cos gated repo with intentional invalid purge credential => network-auth",
		"recover-cos-g6":                           "sow publish stable cos gated repo; require interrupted transaction ID",
		"publish-cf-g6":                            "sow publish stable cf gated repo",
		"verify-stable-g6":                         "edge gated cache v3 and independent target closure",
		"allocate-snapshot-ids":                    "persist seven-month-old snapshot policy ID; do not freeze a current UTC date before mutation",
		"prepare-current-and-historical-snapshots": "recover canonical state; discover exact run snapshot or promote stable to current UTC snapshot; atomically persist @recent; seed exact historical immutable ref",
		"publish-expired-cf-g7":                    "sow publish --snapshot @expired --target cf --repo yum",
		"copy-probe-expired-cf":                    "real R2 same-bucket copy probe exact plan object then identity-bound checkpoint-fenced delete",
		"publish-expired-cos-g7":                   "sow publish --snapshot @expired --target cos --repo yum",
		"copy-probe-expired-cos":                   "real COS same-bucket copy probe exact plan object then identity-bound checkpoint-fenced delete",
		"publish-current-cf-g8":                    "sow publish --snapshot @recent --target cf --repo yum; expire old snapshot",
		"publish-current-cos-g8":                   "sow publish --snapshot @recent --target cos --repo yum; expire old snapshot",
		"verify-current-snapshot":                  "sow verify @recent token=@token-a L2,L3,L4 cf,cos yum",
		"snapshot-noop-replay":                     "baseline cf,cos; sow publish @recent cf,cos unchanged",
		"restore-cf-g9":                            "sow publish --restore-generation 4 --target cf",
		"restore-cos-g9":                           "sow publish --restore-generation 4 --target cos",
		"restore-noop-replays":                     "baseline each target; restore generation 4 unchanged",
		"publish-current-stable-cf-g10":            "sow publish stable cf gated repo current content",
		"publish-current-stable-cos-g10":           "sow publish stable cos gated repo current content",
		"verify-g10-cache":                         "edge gated cache current v3",
		"final-fsck":                               "sow fsck --target cf,cos --limit 20; require clean repos=4 targets=2; require exact sealed provider-log v3 closure for active request set",
	}
	template, exists := templates[id]
	if !exists {
		panic("missing frozen real-cloud acceptance intent template for " + id)
	}
	return template
}

func realCloudAcceptanceStepDescriptorAt(index int) (realCloudAcceptanceStepDescriptor, error) {
	descriptors := realCloudAcceptanceStepDescriptors()
	if index < 0 || index >= len(descriptors) {
		return realCloudAcceptanceStepDescriptor{}, errors.New("real-cloud acceptance step index is out of range")
	}
	return descriptors[index], nil
}

func realCloudAcceptanceDescriptorSHA256(descriptor realCloudAcceptanceStepDescriptor) string {
	body, err := json.Marshal(descriptor)
	if err != nil {
		panic("encode real-cloud acceptance step descriptor")
	}
	return realCloudLowerSHA256(body)
}

func realCloudAcceptanceBindingFor(identity realCloudRunIdentity, configBody []byte, artifactPath, providerLogPath string, observerTopology []byte) (realCloudAcceptanceBinding, error) {
	if identity.Schema != "sow-real-cloud-run/v1" || !validRealCloudRunID(identity.RunID) ||
		!validRealCloudLowerSHA256(identity.ConfirmationSHA256) || !validRealCloudLowerSHA256(identity.ConfigSHA256) ||
		!validRealCloudLowerSHA256(identity.PublicKeySHA256) {
		return realCloudAcceptanceBinding{}, errors.New("real-cloud run identity is invalid")
	}
	tokenVerifier, err := realCloudAcceptanceTokenVerifier(configBody, identity.ConfigSHA256)
	if err != nil {
		return realCloudAcceptanceBinding{}, err
	}
	if artifactPath == "" || !filepath.IsAbs(artifactPath) || filepath.Clean(artifactPath) != artifactPath || strings.ContainsRune(artifactPath, '\x00') {
		return realCloudAcceptanceBinding{}, errors.New("real-cloud active artifact path is not one absolute clean path")
	}
	if providerLogPath == "" || !filepath.IsAbs(providerLogPath) || filepath.Clean(providerLogPath) != providerLogPath || strings.ContainsRune(providerLogPath, '\x00') {
		return realCloudAcceptanceBinding{}, errors.New("real-cloud provider log path is not one absolute clean path")
	}
	implementationSHA, err := realCloudAcceptanceImplementationSHA256()
	if err != nil {
		return realCloudAcceptanceBinding{}, err
	}
	return realCloudAcceptanceBinding{
		RunID: identity.RunID, ConfirmationSHA256: identity.ConfirmationSHA256,
		ConfigSHA256: identity.ConfigSHA256, TokenVerifier: tokenVerifier, PublicKeySHA256: identity.PublicKeySHA256,
		HarnessRevision: realCloudAcceptanceHarnessVersion, ImplementationSHA256: implementationSHA, StepTableSHA256: realCloudAcceptanceStepTableSHA256(),
		ActiveArtifactPathSHA256: realCloudLowerSHA256([]byte(artifactPath)), ProviderLogPathSHA256: realCloudLowerSHA256([]byte(providerLogPath)),
		ObserverTopologySHA256: realCloudLowerSHA256(observerTopology),
	}, nil
}

func realCloudAcceptanceTokenVerifier(configBody []byte, configSHA256 string) (string, error) {
	if len(configBody) == 0 || len(configBody) > sowconfig.MaxConfigBytes || !validRealCloudLowerSHA256(configSHA256) ||
		realCloudLowerSHA256(configBody) != configSHA256 {
		return "", errors.New("real-cloud acceptance product config bytes differ from the run identity")
	}
	product, err := sowconfig.Decode(bytes.NewReader(configBody))
	if err != nil {
		return "", fmt.Errorf("decode real-cloud acceptance product config: %w", err)
	}
	verifier, err := sowconfig.ParseTokenVerifierReference(product.Edge.TokenVerifier)
	if err != nil {
		return "", errors.New("real-cloud acceptance product token verifier is invalid")
	}
	reference := verifier.Kind + "://" + verifier.Name
	if product.Edge.TokenVerifier != reference {
		return "", errors.New("real-cloud acceptance product token verifier is not canonical")
	}
	return reference, nil
}

// realCloudAcceptanceImplementationSHA256 prevents receipts produced by
// different test executables, dirty trees, fixtures, local replacements, or Go
// toolchains from being spliced into one proof. The executable digest is the
// primary machine-code identity: reading the source tree alone is insufficient
// because go test keeps executing already-compiled code after a source edit.
// The twice-read source manifest remains bound for fixtures and for a useful
// explanation of exactly which checkout the executable exercised.
func realCloudAcceptanceImplementationSHA256() (string, error) {
	root, err := realEdgeRepositoryRoot()
	if err != nil {
		return "", err
	}
	executable, err := os.Executable()
	if err != nil {
		return "", errors.New("locate real-cloud acceptance executable")
	}
	executableSHA, executableSize, err := digestRealCloudStableRegularFile(executable)
	if err != nil {
		return "", fmt.Errorf("digest real-cloud acceptance executable: %w", err)
	}
	firstManifest, err := realCloudAcceptanceSourceManifest(root)
	if err != nil {
		return "", err
	}
	secondManifest, err := realCloudAcceptanceSourceManifest(root)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(firstManifest, secondManifest) {
		return "", errors.New("real-cloud implementation source tree changed while it was being bound")
	}
	hash := sha256.New()
	_, _ = io.WriteString(hash, "sow-real-cloud-implementation/v2\x00")
	_, _ = fmt.Fprintf(hash, "executable-size=%d\x00executable-sha256=%s\x00", executableSize, executableSHA)
	_, _ = fmt.Fprintf(hash, "runtime=%s\x00goos=%s\x00goarch=%s\x00compiler=%s\x00", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.Compiler)
	_, _ = hash.Write(realCloudAcceptanceBuildIdentity())
	_, _ = hash.Write(firstManifest)
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func realCloudAcceptanceSourceManifest(root string) ([]byte, error) {
	paths := []string{filepath.Join(root, "go.mod"), filepath.Join(root, "go.sum")}
	for _, directory := range []string{"cmd", "internal", "third_party", filepath.Join("test", "compat"), "edge"} {
		base := filepath.Join(root, directory)
		if err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("implementation digest refuses symlink %s", path)
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("implementation digest refuses non-regular file %s", path)
			}
			paths = append(paths, path)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	sort.Strings(paths)
	manifest := bytes.NewBufferString("sow-real-cloud-source-manifest/v2\x00")
	for _, path := range paths {
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}
		digest, size, err := digestRealCloudStableRegularFile(path)
		if err != nil {
			return nil, fmt.Errorf("digest implementation source %s: %w", filepath.ToSlash(relative), err)
		}
		relative = filepath.ToSlash(relative)
		_, _ = fmt.Fprintf(manifest, "%d:%s\x00%d:%s\x00", len(relative), relative, size, digest)
	}
	return manifest.Bytes(), nil
}

func realCloudAcceptanceBuildIdentity() []byte {
	buffer := bytes.NewBufferString("sow-real-cloud-build-identity/v1\x00")
	info, ok := debug.ReadBuildInfo()
	if !ok {
		buffer.WriteString("build-info=unavailable\x00")
		return buffer.Bytes()
	}
	_, _ = fmt.Fprintf(buffer, "go-version=%s\x00main=%s@%s\x00", info.GoVersion, info.Main.Path, info.Main.Version)
	settings := slices.Clone(info.Settings)
	sort.Slice(settings, func(i, j int) bool {
		if settings[i].Key == settings[j].Key {
			return settings[i].Value < settings[j].Value
		}
		return settings[i].Key < settings[j].Key
	})
	for _, setting := range settings {
		_, _ = fmt.Fprintf(buffer, "%d:%s\x00%d:%s\x00", len(setting.Key), setting.Key, len(setting.Value), setting.Value)
	}
	return buffer.Bytes()
}

func digestRealCloudStableRegularFile(path string) (string, int64, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", 0, errors.New("open stable regular file")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return "", 0, errors.New("stable digest input is not a regular file")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, file)
	if err != nil || n != before.Size() {
		return "", 0, errors.New("read stable digest input")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return "", 0, errors.New("stable digest input changed while reading")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !os.SameFile(after, pathInfo) {
		return "", 0, errors.New("stable digest input path changed while reading")
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), n, nil
}

func acquireRealCloudAcceptanceLedger(root, mode string, binding realCloudAcceptanceBinding) (*realCloudAcceptanceLedgerStore, error) {
	if mode != "fresh" && mode != "recover" {
		return nil, errors.New("real-cloud acceptance ledger mode must be fresh or recover")
	}
	if err := validateRealCloudAcceptanceBinding(binding); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("real-cloud acceptance ledger root is not one private non-symlink directory")
	}
	store := &realCloudAcceptanceLedgerStore{
		root: root, path: filepath.Join(root, realCloudAcceptanceLedgerFilename),
		lockPath: filepath.Join(root, realCloudAcceptanceLockFilename),
	}
	lockFD, err := unix.Open(store.lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("open real-cloud acceptance workspace lock")
	}
	store.lock = os.NewFile(uintptr(lockFD), store.lockPath)
	cleanup := func() {
		_ = unix.Flock(lockFD, unix.LOCK_UN)
		_ = store.lock.Close()
	}
	lockInfo, err := store.lock.Stat()
	if err != nil || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm()&0o077 != 0 {
		cleanup()
		return nil, errors.New("real-cloud acceptance workspace lock is unsafe")
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		cleanup()
		return nil, errors.New("another real-cloud acceptance process owns this workspace")
	}

	switch mode {
	case "fresh":
		ledger := realCloudAcceptanceLedger{
			Schema: realCloudAcceptanceLedgerSchema, Binding: binding, Revision: 1, Status: "running",
			Receipts: []realCloudStepReceipt{}, Facts: realCloudResumeFacts{},
		}
		if err := writeRealCloudAcceptanceLedgerExclusive(store.path, ledger); err != nil {
			cleanup()
			return nil, err
		}
		if err := syncRealCloudDirectoryError(root); err != nil {
			cleanup()
			return nil, err
		}
		store.ledger = ledger
	case "recover":
		ledger, err := readRealCloudAcceptanceLedger(store.path)
		if err != nil {
			cleanup()
			return nil, err
		}
		if ledger.Binding != binding {
			cleanup()
			return nil, errors.New("real-cloud acceptance ledger is not bound to this run, harness, observer topology, and artifact destination")
		}
		store.ledger = ledger
	}
	return store, nil
}

func (store *realCloudAcceptanceLedgerStore) Close() error {
	if store == nil || store.lock == nil {
		return nil
	}
	fd := int(store.lock.Fd())
	err := errors.Join(unix.Flock(fd, unix.LOCK_UN), store.lock.Close())
	store.lock = nil
	return err
}

func (store *realCloudAcceptanceLedgerStore) Snapshot() realCloudAcceptanceLedger {
	return cloneRealCloudAcceptanceLedger(store.ledger)
}

func (store *realCloudAcceptanceLedgerStore) StepCompleted(id string) bool {
	index := len(store.ledger.Receipts)
	for receiptIndex, receipt := range store.ledger.Receipts {
		if receipt.ID == id {
			return receiptIndex < index
		}
	}
	return false
}

func (store *realCloudAcceptanceLedgerStore) BeginStep(id string, intent any, baselines []realCloudBaseline, now time.Time) (bool, error) {
	if store == nil || store.lock == nil {
		return false, errors.New("real-cloud acceptance ledger is not locked")
	}
	if store.ledger.Status == "complete" {
		return false, errors.New("real-cloud acceptance ledger is already complete")
	}
	index := len(store.ledger.Receipts)
	if index >= len(realCloudAcceptanceStepIDs) || realCloudAcceptanceStepIDs[index] != id {
		return false, fmt.Errorf("real-cloud acceptance next step=%d/%q, cannot begin %q", index, realCloudAcceptanceNextStepID(index), id)
	}
	descriptor, err := realCloudAcceptanceStepDescriptorAt(index)
	if err != nil || descriptor.ID != id {
		return false, errors.New("real-cloud acceptance step descriptor does not match the frozen program")
	}
	descriptorSHA := realCloudAcceptanceDescriptorSHA256(descriptor)
	intentSHA, err := realCloudCanonicalValueSHA256(intent)
	if err != nil {
		return false, fmt.Errorf("encode real-cloud step intent: %w", err)
	}
	if err := validateRealCloudBaselines(baselines); err != nil {
		return false, err
	}
	if current := store.ledger.Current; current != nil {
		if current.Index != index || current.ID != id || current.DescriptorSHA256 != descriptorSHA || current.IntentSHA256 != intentSHA || !slices.Equal(current.Baselines, baselines) {
			return false, errors.New("real-cloud acceptance contains a conflicting in-flight step")
		}
		return true, nil
	}
	if now.IsZero() {
		return false, errors.New("real-cloud acceptance step start time is zero")
	}
	updated := cloneRealCloudAcceptanceLedger(store.ledger)
	updated.Revision++
	updated.Current = &realCloudStepAttempt{
		Index: index, ID: id, Attempt: 1, DescriptorSHA256: descriptorSHA, ImplementationSHA256: store.ledger.Binding.ImplementationSHA256, IntentSHA256: intentSHA,
		StartedAt: now.UTC().Format(time.RFC3339Nano), Baselines: append([]realCloudBaseline(nil), baselines...),
	}
	if err := store.replace(updated); err != nil {
		return false, err
	}
	return false, nil
}

func (store *realCloudAcceptanceLedgerStore) BeginCLISubstep(stepID string, index, expectedExit int, arguments []string, now time.Time) (completed bool, resumed bool, output string, err error) {
	if store == nil || store.lock == nil || store.ledger.Current == nil || store.ledger.Current.ID != stepID {
		return false, false, "", errors.New("real-cloud CLI substep has no matching in-flight phase")
	}
	if index < 0 || expectedExit < 0 || expectedExit > 255 {
		return false, false, "", errors.New("real-cloud CLI substep index or exit is invalid")
	}
	if len(arguments) == 0 {
		return false, false, "", errors.New("real-cloud CLI substep arguments are empty")
	}
	intentSHA, err := realCloudCanonicalValueSHA256(arguments)
	if err != nil {
		return false, false, "", err
	}
	current := store.ledger.Current
	if index < len(current.CLIReceipts) {
		receipt := current.CLIReceipts[index]
		if receipt.Index != index || receipt.IntentSHA256 != intentSHA || receipt.ExpectedExit != expectedExit || !slices.Equal(receipt.Arguments, arguments) {
			return false, false, "", errors.New("real-cloud CLI substep replay conflicts with its durable receipt")
		}
		return true, false, receipt.Output, nil
	}
	if index != len(current.CLIReceipts) {
		return false, false, "", errors.New("real-cloud CLI substep is not the exact next operation")
	}
	if current.CLIInFlight != nil {
		inFlight := current.CLIInFlight
		if inFlight.Index != index || inFlight.IntentSHA256 != intentSHA || inFlight.ExpectedExit != expectedExit || !slices.Equal(inFlight.Arguments, arguments) {
			return false, false, "", errors.New("real-cloud CLI substep conflicts with the interrupted operation")
		}
		return false, true, "", nil
	}
	if now.IsZero() {
		return false, false, "", errors.New("real-cloud CLI substep start time is zero")
	}
	updated := cloneRealCloudAcceptanceLedger(store.ledger)
	updated.Revision++
	updated.Current.CLIInFlight = &realCloudCLISubstepAttempt{
		Index: index, IntentSHA256: intentSHA, Arguments: append([]string(nil), arguments...), ExpectedExit: expectedExit, StartedAt: now.UTC().Format(time.RFC3339Nano),
	}
	if err := store.replace(updated); err != nil {
		return false, false, "", err
	}
	return false, false, "", nil
}

func (store *realCloudAcceptanceLedgerStore) CompleteCLISubstep(stepID string, index, actualExit int, output string, now time.Time) error {
	if store == nil || store.lock == nil || store.ledger.Current == nil || store.ledger.Current.ID != stepID || store.ledger.Current.CLIInFlight == nil {
		return errors.New("real-cloud CLI substep has no matching interrupted operation")
	}
	if len(output) > 64<<10 || !utf8.ValidString(output) || strings.ContainsRune(output, '\x00') {
		return errors.New("real-cloud CLI substep output is not bounded UTF-8 text")
	}
	inFlight := *store.ledger.Current.CLIInFlight
	if inFlight.Index != index || index != len(store.ledger.Current.CLIReceipts) || actualExit != inFlight.ExpectedExit || now.IsZero() {
		return errors.New("real-cloud CLI substep completion is out of order")
	}
	started, _ := parseRealCloudLedgerUTC(inFlight.StartedAt)
	if now.UTC().Before(started) {
		return errors.New("real-cloud CLI substep completed before it started")
	}
	updated := cloneRealCloudAcceptanceLedger(store.ledger)
	updated.Revision++
	updated.Current.CLIReceipts = append(updated.Current.CLIReceipts, realCloudCLISubstepReceipt{
		Index: index, IntentSHA256: inFlight.IntentSHA256, Arguments: append([]string(nil), inFlight.Arguments...), ExpectedExit: inFlight.ExpectedExit, ActualExit: actualExit,
		OutputSHA256: realCloudLowerSHA256([]byte(output)), Output: output, CompletedAt: now.UTC().Format(time.RFC3339Nano),
	})
	updated.Current.CLIInFlight = nil
	if err := validateRealCloudAcceptanceLedger(updated); err != nil {
		return err
	}
	return store.replace(updated)
}

func (store *realCloudAcceptanceLedgerStore) RequireCLISubstepsConsumed(stepID string, count int) error {
	if store == nil || store.ledger.Current == nil || store.ledger.Current.ID != stepID || store.ledger.Current.CLIInFlight != nil || len(store.ledger.Current.CLIReceipts) != count {
		return errors.New("real-cloud phase did not consume its exact durable CLI substep prefix")
	}
	return nil
}

func (store *realCloudAcceptanceLedgerStore) CLISubstepArguments(stepID string, index int) ([]string, bool, bool) {
	if store == nil || store.ledger.Current == nil || store.ledger.Current.ID != stepID || index < 0 {
		return nil, false, false
	}
	if index < len(store.ledger.Current.CLIReceipts) {
		return append([]string(nil), store.ledger.Current.CLIReceipts[index].Arguments...), true, false
	}
	if inFlight := store.ledger.Current.CLIInFlight; inFlight != nil && inFlight.Index == index {
		return append([]string(nil), inFlight.Arguments...), true, true
	}
	return nil, false, false
}

func (store *realCloudAcceptanceLedgerStore) ReplaceInFlightCLIArguments(stepID string, index, expectedExit int, oldArguments, newArguments []string, now time.Time) error {
	if store == nil || store.lock == nil || store.ledger.Current == nil || store.ledger.Current.ID != stepID || store.ledger.Current.CLIInFlight == nil {
		return errors.New("real-cloud CLI intent replacement has no in-flight operation")
	}
	inFlight := store.ledger.Current.CLIInFlight
	oldSHA, oldErr := realCloudCanonicalValueSHA256(oldArguments)
	newSHA, newErr := realCloudCanonicalValueSHA256(newArguments)
	if oldErr != nil || newErr != nil || validateRealCloudCLIArguments(newArguments) != nil || now.IsZero() || inFlight.Index != index ||
		inFlight.ExpectedExit != expectedExit || inFlight.IntentSHA256 != oldSHA || !slices.Equal(inFlight.Arguments, oldArguments) {
		return errors.New("real-cloud CLI intent replacement does not match the interrupted operation")
	}
	updated := cloneRealCloudAcceptanceLedger(store.ledger)
	updated.Revision++
	updated.Current.CLIInFlight.IntentSHA256 = newSHA
	updated.Current.CLIInFlight.Arguments = append([]string(nil), newArguments...)
	updated.Current.CLIInFlight.StartedAt = now.UTC().Format(time.RFC3339Nano)
	if err := validateRealCloudAcceptanceLedger(updated); err != nil {
		return err
	}
	return store.replace(updated)
}

func (store *realCloudAcceptanceLedgerStore) CompleteStep(id string, result any, updateFacts func(*realCloudResumeFacts) error, now time.Time) error {
	if store == nil || store.lock == nil || store.ledger.Current == nil {
		return errors.New("real-cloud acceptance has no locked in-flight step")
	}
	current := *store.ledger.Current
	if current.ID != id || current.Index != len(store.ledger.Receipts) {
		return errors.New("real-cloud acceptance completion does not match its in-flight step")
	}
	if current.CLIInFlight != nil {
		return errors.New("real-cloud acceptance cannot complete with an interrupted CLI substep")
	}
	resultSHA, err := realCloudCanonicalValueSHA256(result)
	if err != nil {
		return fmt.Errorf("encode real-cloud step result: %w", err)
	}
	if now.IsZero() {
		return errors.New("real-cloud acceptance step completion time is zero")
	}
	startedAt, _ := parseRealCloudLedgerUTC(current.StartedAt)
	if now.UTC().Before(startedAt) {
		return errors.New("real-cloud acceptance step completed before it started")
	}
	if count := len(store.ledger.Receipts); count > 0 {
		prior, _ := parseRealCloudLedgerUTC(store.ledger.Receipts[count-1].CompletedAt)
		if now.UTC().Before(prior) {
			return errors.New("real-cloud acceptance receipt time moved backwards")
		}
	}
	updated := cloneRealCloudAcceptanceLedger(store.ledger)
	if updateFacts != nil {
		if err := updateFacts(&updated.Facts); err != nil {
			return err
		}
	}
	updated.Revision++
	// Keep the zero-substep representation nil so omitempty round-trips through
	// disk without changing the canonical transcript from [] to null.
	var audit []realCloudCLIAuditReceipt
	if len(current.CLIReceipts) > 0 {
		audit = make([]realCloudCLIAuditReceipt, 0, len(current.CLIReceipts))
	}
	for _, cliReceipt := range current.CLIReceipts {
		audit = append(audit, realCloudCLIAuditReceipt{
			Index: cliReceipt.Index, Arguments: append([]string(nil), cliReceipt.Arguments...), ExpectedExit: cliReceipt.ExpectedExit,
			ActualExit: cliReceipt.ActualExit, OutputSHA256: cliReceipt.OutputSHA256, CompletedAt: cliReceipt.CompletedAt,
		})
	}
	transcriptSHA, err := realCloudCanonicalValueSHA256(audit)
	if err != nil {
		return errors.New("encode real-cloud CLI substep transcript")
	}
	updated.Receipts = append(updated.Receipts, realCloudStepReceipt{
		Index: current.Index, ID: current.ID, DescriptorSHA256: current.DescriptorSHA256, ImplementationSHA256: current.ImplementationSHA256, IntentSHA256: current.IntentSHA256,
		ResultSHA256: resultSHA, CLITranscriptSHA256: transcriptSHA, CLISubsteps: len(audit), CLIAudit: audit, CompletedAt: now.UTC().Format(time.RFC3339Nano),
	})
	updated.Current = nil
	if err := validateRealCloudAcceptanceLedger(updated); err != nil {
		return err
	}
	return store.replace(updated)
}

func (store *realCloudAcceptanceLedgerStore) MarkComplete(now time.Time) error {
	if store == nil || store.lock == nil || store.ledger.Current != nil || len(store.ledger.Receipts) != len(realCloudAcceptanceStepIDs) {
		return errors.New("real-cloud acceptance cannot complete before every step receipt exists")
	}
	if now.IsZero() {
		return errors.New("real-cloud acceptance completion time is zero")
	}
	updated := cloneRealCloudAcceptanceLedger(store.ledger)
	updated.Revision++
	updated.Status = "complete"
	proof, err := realCloudCanonicalValueSHA256(struct {
		Binding  realCloudAcceptanceBinding `json:"binding"`
		Receipts []realCloudStepReceipt     `json:"receipts"`
		Facts    realCloudResumeFacts       `json:"facts"`
	}{Binding: updated.Binding, Receipts: updated.Receipts, Facts: updated.Facts})
	if err != nil {
		return errors.New("encode final real-cloud acceptance proof")
	}
	updated.FinalProofSHA256 = proof
	updated.CompletedAt = now.UTC().Format(time.RFC3339Nano)
	return store.replace(updated)
}

// finalizeRealCloudAcceptanceLedger closes the deliberate crash window after
// the final receipt but before status=complete. Recovery must re-run the
// caller's external provider/file closure, not merely trust the persisted
// digest, immediately before MarkComplete.
func finalizeRealCloudAcceptanceLedger(store *realCloudAcceptanceLedgerStore, revalidate func() error, now time.Time) error {
	if revalidate == nil {
		return errors.New("real-cloud acceptance final revalidation is required")
	}
	if err := revalidate(); err != nil {
		return fmt.Errorf("real-cloud acceptance final revalidation: %w", err)
	}
	return store.MarkComplete(now)
}

func (store *realCloudAcceptanceLedgerStore) replace(updated realCloudAcceptanceLedger) error {
	if err := validateRealCloudAcceptanceLedger(updated); err != nil {
		return err
	}
	if updated.Revision != store.ledger.Revision+1 {
		return errors.New("real-cloud acceptance ledger revision is not the next monotonic value")
	}
	body, err := json.Marshal(updated)
	if err != nil {
		return errors.New("encode real-cloud acceptance ledger")
	}
	body = append(body, '\n')
	if len(body) > realCloudAcceptanceLedgerLimit {
		return errors.New("real-cloud acceptance ledger exceeds its safe size limit")
	}
	temporary, err := os.CreateTemp(store.root, ".sow-real-cloud-acceptance-*.tmp")
	if err != nil {
		return errors.New("create real-cloud acceptance ledger temporary file")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errors.New("secure real-cloud acceptance ledger temporary file")
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return errors.New("write real-cloud acceptance ledger temporary file")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errors.New("sync real-cloud acceptance ledger temporary file")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close real-cloud acceptance ledger temporary file")
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return errors.New("atomically install real-cloud acceptance ledger")
	}
	if err := syncRealCloudDirectoryError(store.root); err != nil {
		return err
	}
	store.ledger = updated
	return nil
}

func writeRealCloudAcceptanceLedgerExclusive(path string, ledger realCloudAcceptanceLedger) error {
	if err := validateRealCloudAcceptanceLedger(ledger); err != nil {
		return err
	}
	body, err := json.Marshal(ledger)
	if err != nil {
		return errors.New("encode initial real-cloud acceptance ledger")
	}
	body = append(body, '\n')
	if len(body) > realCloudAcceptanceLedgerLimit {
		return errors.New("initial real-cloud acceptance ledger exceeds its safe size limit")
	}
	installed, err := installRealCloudPrivateFileExclusive(path, body)
	if err != nil {
		return errors.New("create initial real-cloud acceptance ledger")
	}
	if !installed {
		return errors.New("initial real-cloud acceptance ledger already exists")
	}
	return nil
}

// installRealCloudPrivateFileExclusive installs a fully-written private inode
// with no-replace semantics. A kill before link(2) leaves only an ignorable
// temporary inode; a kill after link(2) leaves a complete final file. Thus a
// recover run never has to interpret a zero-byte or partially-written final
// bootstrap artifact.
func installRealCloudPrivateFileExclusive(path string, body []byte) (bool, error) {
	return installRealCloudPrivateFileExclusiveWithPattern(path, body, ".sow-private-bootstrap-*")
}

func installRealCloudPrivateFileExclusiveWithPattern(path string, body []byte, pattern string) (bool, error) {
	directory := filepath.Dir(path)
	if pattern == "" || filepath.Base(pattern) != pattern || !strings.Contains(pattern, "*") {
		return false, errors.New("private bootstrap temporary pattern is invalid")
	}
	temporary, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return false, errors.New("create private bootstrap temporary file")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return false, errors.New("secure private bootstrap temporary file")
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return false, errors.New("write private bootstrap temporary file")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, errors.New("sync private bootstrap temporary file")
	}
	if err := temporary.Close(); err != nil {
		return false, errors.New("close private bootstrap temporary file")
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, errors.New("link private bootstrap file")
	}
	if err := syncRealCloudDirectoryError(directory); err != nil {
		return false, err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return false, errors.New("remove linked private bootstrap temporary file")
	}
	if err := syncRealCloudDirectoryError(directory); err != nil {
		return false, err
	}
	return true, nil
}

func readRealCloudAcceptanceLedger(path string) (realCloudAcceptanceLedger, error) {
	var ledger realCloudAcceptanceLedger
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > realCloudAcceptanceLedgerLimit {
		return ledger, errors.New("real-cloud acceptance ledger is absent or unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return ledger, errors.New("open real-cloud acceptance ledger")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return ledger, errors.New("real-cloud acceptance ledger changed during open")
	}
	body, err := io.ReadAll(io.LimitReader(file, realCloudAcceptanceLedgerLimit+1))
	if err != nil || len(body) > realCloudAcceptanceLedgerLimit {
		return ledger, errors.New("read real-cloud acceptance ledger")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(body)) || !after.ModTime().Equal(opened.ModTime()) {
		return ledger, errors.New("real-cloud acceptance ledger changed while being read")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ledger); err != nil {
		return ledger, errors.New("decode real-cloud acceptance ledger")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ledger, errors.New("real-cloud acceptance ledger contains trailing values")
	}
	if err := validateRealCloudAcceptanceLedger(ledger); err != nil {
		return ledger, err
	}
	canonical, err := json.Marshal(ledger)
	if err != nil {
		return ledger, errors.New("re-encode real-cloud acceptance ledger")
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(body, canonical) {
		return ledger, errors.New("real-cloud acceptance ledger is not canonical JSON or contains duplicate keys")
	}
	return ledger, nil
}

func validateRealCloudAcceptanceLedger(ledger realCloudAcceptanceLedger) error {
	if ledger.Schema != realCloudAcceptanceLedgerSchema || ledger.Revision == 0 {
		return errors.New("real-cloud acceptance ledger schema or revision is invalid")
	}
	if err := validateRealCloudAcceptanceBinding(ledger.Binding); err != nil {
		return err
	}
	if ledger.Status != "running" && ledger.Status != "complete" {
		return errors.New("real-cloud acceptance ledger status is invalid")
	}
	if len(ledger.Receipts) > len(realCloudAcceptanceStepIDs) {
		return errors.New("real-cloud acceptance ledger has too many receipts")
	}
	var priorReceiptTime time.Time
	for index, receipt := range ledger.Receipts {
		descriptor, descriptorErr := realCloudAcceptanceStepDescriptorAt(index)
		if descriptorErr != nil || receipt.Index != index || receipt.ID != descriptor.ID || receipt.DescriptorSHA256 != realCloudAcceptanceDescriptorSHA256(descriptor) ||
			receipt.ImplementationSHA256 != ledger.Binding.ImplementationSHA256 ||
			!validRealCloudLowerSHA256(receipt.IntentSHA256) || !validRealCloudLowerSHA256(receipt.ResultSHA256) ||
			validateRealCloudCLIAudit(receipt) != nil {
			return errors.New("real-cloud acceptance receipts are not the exact step-table prefix")
		}
		completedAt, err := parseRealCloudLedgerUTC(receipt.CompletedAt)
		if err != nil {
			return errors.New("real-cloud acceptance receipt time is invalid")
		}
		if !priorReceiptTime.IsZero() && completedAt.Before(priorReceiptTime) {
			return errors.New("real-cloud acceptance receipt times are not monotonic")
		}
		priorReceiptTime = completedAt
	}
	if ledger.Current != nil {
		current := ledger.Current
		descriptor, descriptorErr := realCloudAcceptanceStepDescriptorAt(current.Index)
		if ledger.Status != "running" || current.Index != len(ledger.Receipts) || current.Index >= len(realCloudAcceptanceStepIDs) ||
			descriptorErr != nil || current.ID != descriptor.ID || current.DescriptorSHA256 != realCloudAcceptanceDescriptorSHA256(descriptor) ||
			current.ImplementationSHA256 != ledger.Binding.ImplementationSHA256 || current.Attempt == 0 || !validRealCloudLowerSHA256(current.IntentSHA256) {
			return errors.New("real-cloud acceptance in-flight step is invalid")
		}
		if _, err := parseRealCloudLedgerUTC(current.StartedAt); err != nil {
			return errors.New("real-cloud acceptance in-flight start time is invalid")
		}
		startedAt, _ := parseRealCloudLedgerUTC(current.StartedAt)
		if !priorReceiptTime.IsZero() && startedAt.Before(priorReceiptTime) {
			return errors.New("real-cloud acceptance in-flight step started before the prior receipt")
		}
		if err := validateRealCloudBaselines(current.Baselines); err != nil {
			return err
		}
		if err := validateRealCloudCLISubsteps(*current); err != nil {
			return err
		}
	}
	if err := validateRealCloudFactReceiptPrefix(ledger); err != nil {
		return err
	}
	if ledger.Status == "complete" {
		if ledger.Current != nil || len(ledger.Receipts) != len(realCloudAcceptanceStepIDs) || !validRealCloudLowerSHA256(ledger.FinalProofSHA256) {
			return errors.New("completed real-cloud acceptance ledger lacks the exact closed receipt set")
		}
		completedAt, err := parseRealCloudLedgerUTC(ledger.CompletedAt)
		if err != nil || !priorReceiptTime.IsZero() && completedAt.Before(priorReceiptTime) {
			return errors.New("completed real-cloud acceptance ledger has an invalid completion time")
		}
		proof, err := realCloudCanonicalValueSHA256(struct {
			Binding  realCloudAcceptanceBinding `json:"binding"`
			Receipts []realCloudStepReceipt     `json:"receipts"`
			Facts    realCloudResumeFacts       `json:"facts"`
		}{Binding: ledger.Binding, Receipts: ledger.Receipts, Facts: ledger.Facts})
		if err != nil || proof != ledger.FinalProofSHA256 {
			return errors.New("completed real-cloud acceptance ledger final proof digest is invalid")
		}
	} else if ledger.FinalProofSHA256 != "" || ledger.CompletedAt != "" {
		return errors.New("running real-cloud acceptance ledger contains premature final proof fields")
	}
	if err := validateRealCloudResumeFacts(ledger.Facts); err != nil {
		return err
	}
	if ledger.Facts.ProviderClosure != nil {
		attestation := ledger.Facts.ProviderClosure.ProviderAttestation
		if attestation.ProductConfigSHA256 != ledger.Binding.ConfigSHA256 {
			return errors.New("real-cloud acceptance provider attestation belongs to another product config")
		}
		if attestation.TokenVerifierKind+"://"+attestation.TokenVerifierName != ledger.Binding.TokenVerifier {
			return errors.New("real-cloud acceptance provider attestation belongs to another product token verifier")
		}
	}
	return nil
}

func validateRealCloudCLIAudit(receipt realCloudStepReceipt) error {
	if receipt.CLISubsteps != len(receipt.CLIAudit) || receipt.CLISubsteps < 0 || receipt.CLISubsteps > 128 || !validRealCloudLowerSHA256(receipt.CLITranscriptSHA256) {
		return errors.New("real-cloud CLI audit count or digest is invalid")
	}
	var prior time.Time
	for index, cliReceipt := range receipt.CLIAudit {
		completed, err := parseRealCloudLedgerUTC(cliReceipt.CompletedAt)
		if cliReceipt.Index != index || validateRealCloudCLIArguments(cliReceipt.Arguments) != nil || cliReceipt.ExpectedExit < 0 || cliReceipt.ExpectedExit > 255 ||
			cliReceipt.ActualExit != cliReceipt.ExpectedExit || !validRealCloudLowerSHA256(cliReceipt.OutputSHA256) || err != nil || !prior.IsZero() && completed.Before(prior) {
			return errors.New("real-cloud compact CLI audit receipt is invalid")
		}
		prior = completed
	}
	digest, err := realCloudCanonicalValueSHA256(receipt.CLIAudit)
	if err != nil || digest != receipt.CLITranscriptSHA256 {
		return errors.New("real-cloud compact CLI audit transcript digest changed")
	}
	return nil
}

func validateRealCloudCLISubsteps(current realCloudStepAttempt) error {
	started, err := parseRealCloudLedgerUTC(current.StartedAt)
	if err != nil {
		return err
	}
	prior := started
	for index, receipt := range current.CLIReceipts {
		completed, timeErr := parseRealCloudLedgerUTC(receipt.CompletedAt)
		argumentsSHA, argumentsErr := realCloudCanonicalValueSHA256(receipt.Arguments)
		if receipt.Index != index || validateRealCloudCLIArguments(receipt.Arguments) != nil || argumentsErr != nil || argumentsSHA != receipt.IntentSHA256 ||
			!validRealCloudLowerSHA256(receipt.IntentSHA256) || receipt.ExpectedExit < 0 || receipt.ExpectedExit > 255 || receipt.ActualExit != receipt.ExpectedExit ||
			!validRealCloudLowerSHA256(receipt.OutputSHA256) || receipt.OutputSHA256 != realCloudLowerSHA256([]byte(receipt.Output)) ||
			len(receipt.Output) > 64<<10 || !utf8.ValidString(receipt.Output) || strings.ContainsRune(receipt.Output, '\x00') || timeErr != nil || completed.Before(prior) {
			return errors.New("real-cloud CLI substep receipts are invalid or non-monotonic")
		}
		prior = completed
	}
	if current.CLIInFlight != nil {
		attempt := current.CLIInFlight
		attemptStarted, timeErr := parseRealCloudLedgerUTC(attempt.StartedAt)
		argumentsSHA, argumentsErr := realCloudCanonicalValueSHA256(attempt.Arguments)
		if attempt.Index != len(current.CLIReceipts) || validateRealCloudCLIArguments(attempt.Arguments) != nil || argumentsErr != nil || argumentsSHA != attempt.IntentSHA256 ||
			!validRealCloudLowerSHA256(attempt.IntentSHA256) || attempt.ExpectedExit < 0 || attempt.ExpectedExit > 255 ||
			timeErr != nil || attemptStarted.Before(prior) {
			return errors.New("real-cloud CLI in-flight substep is invalid")
		}
	}
	return nil
}

func validateRealCloudCLIArguments(arguments []string) error {
	if len(arguments) == 0 || len(arguments) > 128 {
		return errors.New("real-cloud CLI argument count is invalid")
	}
	for _, argument := range arguments {
		if len(argument) > 16<<10 || !utf8.ValidString(argument) || strings.ContainsAny(argument, "\x00\r\n") {
			return errors.New("real-cloud CLI argument is unsafe")
		}
	}
	return nil
}

func validateRealCloudFactReceiptPrefix(ledger realCloudAcceptanceLedger) error {
	completed := func(id string) bool {
		index := slices.Index(realCloudAcceptanceStepIDs, id)
		return index >= 0 && len(ledger.Receipts) > index
	}
	rules := []struct {
		step    string
		present bool
	}{
		{step: "allocate-snapshot-ids", present: ledger.Facts.ExpiredSnapshotID != ""},
		{step: "prepare-current-and-historical-snapshots", present: ledger.Facts.RecentSnapshotID != ""},
		{step: "capture-pre-purge-g4", present: len(ledger.Facts.PrePurge) != 0},
		{step: "interrupt-cf-g5", present: ledger.Facts.CFInterrupted != nil},
		{step: "interrupt-cos-g6", present: ledger.Facts.COSInterrupted != nil},
		{step: "final-fsck", present: ledger.Facts.ProviderClosure != nil},
	}
	for _, rule := range rules {
		if completed(rule.step) != rule.present {
			return fmt.Errorf("real-cloud acceptance fact for %s does not match its receipt prefix", rule.step)
		}
	}
	if ledger.Facts.ProviderClosure != nil && ledger.Facts.ProviderClosure.ProviderLogPathSHA256 != ledger.Binding.ProviderLogPathSHA256 {
		return errors.New("real-cloud acceptance provider closure is not bound to the provider path")
	}
	return nil
}

func validateRealCloudAcceptanceBinding(binding realCloudAcceptanceBinding) error {
	verifier, verifierErr := sowconfig.ParseTokenVerifierReference(binding.TokenVerifier)
	if !validRealCloudRunID(binding.RunID) || !validRealCloudLowerSHA256(binding.ConfirmationSHA256) ||
		!validRealCloudLowerSHA256(binding.ConfigSHA256) || !validRealCloudLowerSHA256(binding.PublicKeySHA256) ||
		verifierErr != nil || binding.TokenVerifier != verifier.Kind+"://"+verifier.Name ||
		binding.HarnessRevision != realCloudAcceptanceHarnessVersion || !validRealCloudLowerSHA256(binding.ImplementationSHA256) || binding.StepTableSHA256 != realCloudAcceptanceStepTableSHA256() ||
		!validRealCloudLowerSHA256(binding.ActiveArtifactPathSHA256) || !validRealCloudLowerSHA256(binding.ProviderLogPathSHA256) ||
		!validRealCloudLowerSHA256(binding.ObserverTopologySHA256) {
		return errors.New("real-cloud acceptance binding is invalid or belongs to another harness revision")
	}
	return nil
}

func validateRealCloudBaselines(baselines []realCloudBaseline) error {
	prior := ""
	for _, baseline := range baselines {
		if baseline.Name == "" || baseline.Name <= prior || strings.ContainsAny(baseline.Name, "\x00\r\n") || !validRealCloudLowerSHA256(baseline.SHA256) {
			return errors.New("real-cloud acceptance baselines are invalid, duplicate, or unsorted")
		}
		prior = baseline.Name
	}
	return nil
}

func validateRealCloudResumeFacts(facts realCloudResumeFacts) error {
	// The old-policy ID is frozen one step earlier. The current snapshot ID is
	// deliberately absent until the promote/discover step completes, so a
	// recovery delayed across UTC midnight may choose the then-current date.
	if facts.RecentSnapshotID != "" && facts.ExpiredSnapshotID == "" {
		return errors.New("real-cloud acceptance current snapshot fact has no frozen expiry policy")
	}
	if facts.ExpiredSnapshotID != "" {
		if err := views.ValidateSnapshotID(facts.ExpiredSnapshotID); err != nil {
			return errors.New("real-cloud acceptance expired snapshot fact is invalid")
		}
	}
	if facts.RecentSnapshotID != "" {
		if err := views.ValidateSnapshotID(facts.RecentSnapshotID); err != nil || facts.RecentSnapshotID == facts.ExpiredSnapshotID {
			return errors.New("real-cloud acceptance current snapshot fact is invalid")
		}
	}
	for name, fact := range map[string]*realCloudInterruptedFact{"cf": facts.CFInterrupted, "cos": facts.COSInterrupted} {
		if fact == nil {
			continue
		}
		if fact.Target != name || fact.Generation == 0 || fact.ParentGeneration+1 != fact.Generation ||
			!validRealEdgeTransactionID(fact.TransactionID) || !validRealCloudLowerSHA256(fact.LockedCheckpointSHA256) {
			return errors.New("real-cloud acceptance interrupted-publication fact is invalid")
		}
	}
	if len(facts.PrePurge) != 0 {
		if len(facts.PrePurge) != 2 {
			return errors.New("real-cloud acceptance pre-purge facts must contain both vendors")
		}
		for _, vendor := range []string{"cloudflare", "edgeone"} {
			fact, exists := facts.PrePurge[vendor]
			if !exists || fact.Generation == 0 || !validRealEdgeTransactionID(fact.TransactionID) ||
				!validRealCloudLowerSHA256(fact.CleanURLSHA256) || !validRealCloudLowerSHA256(fact.BodySHA256) || len(fact.Observations) < 2 {
				return errors.New("real-cloud acceptance pre-purge vendor fact is invalid")
			}
		}
	}
	if facts.ProviderClosure != nil {
		closure := facts.ProviderClosure
		for _, digest := range []string{closure.ProviderLogPathSHA256, closure.ProviderLogSHA256, closure.ProviderSealSHA256, closure.ActiveArtifactSHA256, closure.ActiveSealSHA256, closure.CFPurgeEvidenceSHA256, closure.COSPurgeEvidenceSHA256} {
			if !validRealCloudLowerSHA256(digest) {
				return errors.New("real-cloud acceptance provider closure digest is invalid")
			}
		}
		if closure.ProviderRecords < 8 || closure.ProviderRecords > realEdgeMaxProviderLogRecords {
			return errors.New("real-cloud acceptance provider closure record count is invalid")
		}
		attestation := closure.ProviderAttestation
		if attestation.Schema != realCloudProviderCollectorSchema || attestation.RawRecords != closure.ProviderRecords {
			return errors.New("real-cloud acceptance provider API attestation schema or record count is invalid")
		}
		for _, digest := range []string{
			attestation.CollectorSourceSHA256, attestation.CollectorBuildSHA256, attestation.CollectorConfigSHA256, attestation.ProductConfigSHA256, attestation.ProviderDeploymentSHA256,
			attestation.RawJoinedSHA256, attestation.RedactedClosureSHA256, attestation.CFLogpushJobSHA256,
			attestation.CFZoneIdentitySHA256, attestation.CFLogReaderIdentitySHA256, attestation.CFLogWriterIdentitySHA256,
			attestation.CFLogControlIdentitySHA256, attestation.CFRawObjectIdentitySHA256, attestation.CFRawObjectSHA256, attestation.CFWorkerContentSHA256,
			attestation.CFWorkerBindingsSHA256, attestation.CFWorkerRuntimeSHA256, attestation.CFWorkerSecuritySHA256,
			attestation.CFWorkerRoutesSHA256, attestation.CFWorkerInventorySHA256, attestation.CFOriginContentSHA256,
			attestation.CFOriginBindingsSHA256, attestation.CFOriginSecuritySHA256, attestation.CFOriginExposureSHA256,
			attestation.EdgeOneZoneIdentitySHA256, attestation.EdgeOneDomainsSHA256, attestation.EdgeOneLogTaskSHA256, attestation.EdgeOneLogReaderIdentitySHA256, attestation.EdgeOneLogWriterIdentitySHA256, attestation.EdgeOneRawObjectIdentitySHA256, attestation.EdgeOneRawObjectSHA256,
			attestation.EdgeOneFunctionDomainSHA256, attestation.EdgeOneFunctionDomainBehaviorSHA256, attestation.EdgeOneFunctionContentSHA256,
			attestation.EdgeOneFunctionComponentsSHA256, attestation.EdgeOneFunctionReplicasSHA256, attestation.EdgeOneFunctionRuntimeSHA256,
			attestation.EdgeOneFunctionRulesSHA256,
		} {
			if !validRealCloudLowerSHA256(digest) {
				return errors.New("real-cloud acceptance provider API attestation digest is invalid")
			}
		}
		for _, identity := range []string{
			attestation.CFAccountID, attestation.CFZoneID, attestation.CFWorkerScript, attestation.CFWorkerDeploymentID,
			attestation.CFWorkerVersionID, attestation.CFOriginWorkerScript, attestation.CFOriginDeploymentID,
			attestation.CFOriginVersionID,
			attestation.EdgeOneZoneID, attestation.EdgeOneLogTaskID, attestation.EdgeOneFunctionID,
		} {
			if !validRealCloudProviderIdentifier(identity, 128) {
				return errors.New("real-cloud acceptance provider API attestation identity is invalid")
			}
		}
		if !validRealCloudEdgeOneLogArea(attestation.EdgeOneLogArea) {
			return errors.New("real-cloud acceptance provider API attestation EdgeOne log area is invalid")
		}
		if attestation.CFLogpushJobID <= 0 || attestation.CFRawObjects <= 0 || attestation.CFRawObjects > realCloudProviderMaxInventoryItems ||
			attestation.EdgeOneRawObjects <= 0 || attestation.EdgeOneRawObjects > realCloudProviderMaxInventoryItems || !validRealCloudProviderETag(attestation.CFRawObjectETag) ||
			!validRealCloudProviderETag(attestation.CFWorkerVersionETag) || !validRealCloudProviderETag(attestation.CFOriginVersionETag) ||
			!validRealCloudProviderETag(attestation.EdgeOneRawObjectETag) {
			return errors.New("real-cloud acceptance provider API attestation job or ETag is invalid")
		}
		verifier, verifierErr := sowconfig.ParseTokenVerifierReference(attestation.TokenVerifierKind + "://" + attestation.TokenVerifierName)
		if verifierErr != nil || verifier.Kind != attestation.TokenVerifierKind || verifier.Name != attestation.TokenVerifierName {
			return errors.New("real-cloud acceptance provider API attestation verifier reference is invalid")
		}
		switch verifier.Kind {
		case "provider":
			if attestation.CFTokenVerifierService != verifier.Name ||
				!validRealCloudProviderIdentifier(attestation.CFTokenVerifierVersionID, 128) ||
				!validRealCloudProviderETag(attestation.CFTokenVerifierVersionETag) ||
				!validRealCloudLowerSHA256(attestation.CFTokenVerifierContentSHA256) ||
				!validRealCloudLowerSHA256(attestation.CFTokenVerifierBindingsSHA256) ||
				!validRealCloudLowerSHA256(attestation.CFTokenVerifierSecuritySHA256) ||
				!validRealCloudLowerSHA256(attestation.EdgeOneTokenVerifierDeploymentSHA256) {
				return errors.New("real-cloud acceptance provider verifier attestation is incomplete")
			}
		case "env":
			if !validRealCloudProviderSecretName(attestation.TokenVerifierName) || attestation.CFTokenVerifierService != "" ||
				attestation.CFTokenVerifierVersionID != "" || attestation.CFTokenVerifierVersionETag != "" ||
				attestation.CFTokenVerifierContentSHA256 != "" || attestation.CFTokenVerifierBindingsSHA256 != "" ||
				attestation.CFTokenVerifierSecuritySHA256 != "" || attestation.EdgeOneTokenVerifierDeploymentSHA256 != "" {
				return errors.New("real-cloud acceptance static verifier attestation retains provider-only evidence")
			}
		default:
			return errors.New("real-cloud acceptance provider API attestation verifier kind is invalid")
		}
	}
	return nil
}

func TestRealCloudAcceptanceLedgerValidatesVerifierEvidenceUnion(t *testing.T) {
	closureFor := func(attestation realCloudProviderRawAttestation) realCloudResumeFacts {
		return realCloudResumeFacts{ProviderClosure: &realCloudProviderClosureFact{
			ProviderLogPathSHA256: strings.Repeat("1", 64), ProviderLogSHA256: strings.Repeat("2", 64),
			ProviderSealSHA256: strings.Repeat("3", 64), ActiveArtifactSHA256: strings.Repeat("4", 64),
			ActiveSealSHA256: strings.Repeat("5", 64), CFPurgeEvidenceSHA256: strings.Repeat("6", 64),
			COSPurgeEvidenceSHA256: strings.Repeat("7", 64), ProviderRecords: 12, ProviderAttestation: attestation,
		}}
	}
	provider := realCloudProviderRawAttestationForTest(12)
	static := realCloudStaticProviderRawAttestationForTest(12)
	for name, attestation := range map[string]realCloudProviderRawAttestation{"provider": provider, "static": static} {
		t.Run(name, func(t *testing.T) {
			if err := validateRealCloudResumeFacts(closureFor(attestation)); err != nil {
				t.Fatalf("valid %s verifier evidence rejected: %v", name, err)
			}
		})
	}
	for _, test := range []struct {
		name   string
		value  realCloudProviderRawAttestation
		mutate func(*realCloudProviderRawAttestation)
	}{
		{"provider-missing-worker", provider, func(value *realCloudProviderRawAttestation) { value.CFTokenVerifierVersionID = "" }},
		{"provider-name-drift", provider, func(value *realCloudProviderRawAttestation) { value.TokenVerifierName = "other-verifier" }},
		{"static-retains-worker", static, func(value *realCloudProviderRawAttestation) { value.CFTokenVerifierService = "cf-verifier" }},
		{"static-retains-edgeone-deployment", static, func(value *realCloudProviderRawAttestation) {
			value.EdgeOneTokenVerifierDeploymentSHA256 = strings.Repeat("a", 64)
		}},
		{"static-invalid-secret-name", static, func(value *realCloudProviderRawAttestation) { value.TokenVerifierName = "lowercase" }},
		{"static-secret-name-too-long", static, func(value *realCloudProviderRawAttestation) { value.TokenVerifierName = "S" + strings.Repeat("A", 128) }},
		{"provider-uppercase-name", provider, func(value *realCloudProviderRawAttestation) {
			value.TokenVerifierName, value.CFTokenVerifierService = "CF-Verifier", "CF-Verifier"
		}},
		{"unknown-kind", static, func(value *realCloudProviderRawAttestation) { value.TokenVerifierKind = "remote" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := test.value
			test.mutate(&candidate)
			if err := validateRealCloudResumeFacts(closureFor(candidate)); err == nil {
				t.Fatal("mixed verifier evidence union was accepted")
			}
		})
	}
}

func realCloudCanonicalValueSHA256(value any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return realCloudLowerSHA256(body), nil
}

func realCloudLowerSHA256(body []byte) string {
	digest := sha256.Sum256(body)
	return fmt.Sprintf("%x", digest)
}

func parseRealCloudLedgerUTC(raw string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || parsed.IsZero() || !strings.HasSuffix(raw, "Z") {
		return time.Time{}, errors.New("time must be non-zero RFC3339 UTC")
	}
	return parsed.UTC(), nil
}

func realCloudAcceptanceNextStepID(index int) string {
	if index < 0 || index >= len(realCloudAcceptanceStepIDs) {
		return ""
	}
	return realCloudAcceptanceStepIDs[index]
}

func cloneRealCloudAcceptanceLedger(ledger realCloudAcceptanceLedger) realCloudAcceptanceLedger {
	cloned := ledger
	cloned.Receipts = append([]realCloudStepReceipt(nil), ledger.Receipts...)
	for index := range cloned.Receipts {
		if ledger.Receipts[index].CLIAudit != nil {
			cloned.Receipts[index].CLIAudit = append(make([]realCloudCLIAuditReceipt, 0, len(ledger.Receipts[index].CLIAudit)), ledger.Receipts[index].CLIAudit...)
		}
		for cliIndex := range cloned.Receipts[index].CLIAudit {
			cloned.Receipts[index].CLIAudit[cliIndex].Arguments = append([]string(nil), cloned.Receipts[index].CLIAudit[cliIndex].Arguments...)
		}
	}
	if ledger.Current != nil {
		current := *ledger.Current
		current.Baselines = append([]realCloudBaseline(nil), ledger.Current.Baselines...)
		current.CLIReceipts = append([]realCloudCLISubstepReceipt(nil), ledger.Current.CLIReceipts...)
		for index := range current.CLIReceipts {
			current.CLIReceipts[index].Arguments = append([]string(nil), current.CLIReceipts[index].Arguments...)
		}
		if ledger.Current.CLIInFlight != nil {
			value := *ledger.Current.CLIInFlight
			value.Arguments = append([]string(nil), value.Arguments...)
			current.CLIInFlight = &value
		}
		cloned.Current = &current
	}
	if ledger.Facts.CFInterrupted != nil {
		value := *ledger.Facts.CFInterrupted
		cloned.Facts.CFInterrupted = &value
	}
	if ledger.Facts.COSInterrupted != nil {
		value := *ledger.Facts.COSInterrupted
		cloned.Facts.COSInterrupted = &value
	}
	if ledger.Facts.ProviderClosure != nil {
		value := *ledger.Facts.ProviderClosure
		cloned.Facts.ProviderClosure = &value
	}
	if ledger.Facts.PrePurge != nil {
		cloned.Facts.PrePurge = make(map[string]realEdgePrePurgeVendorEvidence, len(ledger.Facts.PrePurge))
		for key, value := range ledger.Facts.PrePurge {
			value.Observations = append([]realEdgeMultiPoPObservation(nil), value.Observations...)
			cloned.Facts.PrePurge[key] = value
		}
	}
	return cloned
}

func syncRealCloudDirectoryError(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return errors.New("open real-cloud acceptance directory for sync")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("sync real-cloud acceptance directory")
	}
	return nil
}

func TestRealCloudAcceptanceLedgerRecoversExactInFlightStep(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	binding := realCloudAcceptanceLedgerTestBinding(t, root, "run-real-cloud-ledger-recovery-01")
	store, err := acquireRealCloudAcceptanceLedger(root, "fresh", binding)
	if err != nil {
		t.Fatal(err)
	}
	intent := struct {
		Command []string `json:"command"`
		Token   string   `json:"token"`
	}{Command: []string{"init", "--config", filepath.Join(root, "sow.yaml")}, Token: "@none"}
	baseline := []realCloudBaseline{{Name: "config", SHA256: strings.Repeat("a", 64)}}
	resumed, err := store.BeginStep(realCloudAcceptanceStepIDs[0], intent, baseline, time.Date(2026, 7, 14, 1, 2, 3, 0, time.UTC))
	if err != nil || resumed {
		t.Fatalf("initial begin resumed=%v err=%v", resumed, err)
	}
	first := store.Snapshot()
	if first.Current == nil || first.Current.ID != realCloudAcceptanceStepIDs[0] || first.Revision != 2 {
		t.Fatalf("initial in-flight ledger=%#v", first)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	recovered, err := acquireRealCloudAcceptanceLedger(root, "recover", binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recovered.Close() })
	resumed, err = recovered.BeginStep(realCloudAcceptanceStepIDs[0], intent, baseline, time.Date(2026, 7, 14, 1, 3, 0, 0, time.UTC))
	if err != nil || !resumed {
		t.Fatalf("recover exact in-flight step resumed=%v err=%v", resumed, err)
	}
	if err := recovered.CompleteStep(realCloudAcceptanceStepIDs[0], map[string]string{"config_sha256": strings.Repeat("b", 64)}, nil,
		time.Date(2026, 7, 14, 1, 4, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	after := recovered.Snapshot()
	if after.Current != nil || len(after.Receipts) != 1 || after.Receipts[0].ID != realCloudAcceptanceStepIDs[0] || after.Revision != 3 {
		t.Fatalf("completed recovered step ledger=%#v", after)
	}
	if _, err := recovered.BeginStep(realCloudAcceptanceStepIDs[2], struct{}{}, nil, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "next step") {
		t.Fatalf("out-of-order begin err=%v", err)
	}
}

func TestRealCloudAcceptanceLedgerRejectsConcurrentOrForeignRecovery(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	binding := realCloudAcceptanceLedgerTestBinding(t, root, "run-real-cloud-ledger-locking-01")
	store, err := acquireRealCloudAcceptanceLedger(root, "fresh", binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireRealCloudAcceptanceLedger(root, "recover", binding); err == nil || !strings.Contains(err.Error(), "another") {
		t.Fatalf("concurrent recovery err=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	foreign := binding
	foreign.RunID = "run-real-cloud-ledger-foreign-01"
	if _, err := acquireRealCloudAcceptanceLedger(root, "recover", foreign); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("foreign recovery err=%v", err)
	}
	recovered, err := acquireRealCloudAcceptanceLedger(root, "recover", binding)
	if err != nil {
		t.Fatalf("same-run recovery after owner exit: %v", err)
	}
	_ = recovered.Close()
}

func TestRealCloudAcceptanceLedgerStrictDecodeAndReceiptClosure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	binding := realCloudAcceptanceLedgerTestBinding(t, root, "run-real-cloud-ledger-closure-01")
	ledger := realCloudAcceptanceLedger{
		Schema: realCloudAcceptanceLedgerSchema, Binding: binding, Revision: 1, Status: "running",
		Receipts: []realCloudStepReceipt{}, Facts: realCloudResumeFacts{},
	}
	path := filepath.Join(root, realCloudAcceptanceLedgerFilename)
	if err := writeRealCloudAcceptanceLedgerExclusive(path, ledger); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Replace(body, []byte(`"revision":1`), []byte(`"unknown":true,"revision":1`), 1)
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRealCloudAcceptanceLedger(path); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("unknown ledger field err=%v", err)
	}
	canonical, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	canonical = append(canonical, '\n')
	nonCanonical := append([]byte(" \n"), canonical...)
	if err := os.WriteFile(path, nonCanonical, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRealCloudAcceptanceLedger(path); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("non-canonical ledger err=%v", err)
	}
	duplicate := bytes.Replace(canonical, []byte(`"revision":1`), []byte(`"revision":1,"revision":1`), 1)
	if err := os.WriteFile(path, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRealCloudAcceptanceLedger(path); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate-key ledger err=%v", err)
	}
	ledger.Receipts = []realCloudStepReceipt{{
		Index: 1, ID: realCloudAcceptanceStepIDs[1], IntentSHA256: strings.Repeat("a", 64), ResultSHA256: strings.Repeat("b", 64),
		CompletedAt: time.Date(2026, 7, 14, 2, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}}
	if err := validateRealCloudAcceptanceLedger(ledger); err == nil || !strings.Contains(err.Error(), "prefix") {
		t.Fatalf("non-prefix receipt err=%v", err)
	}
	ledger.Receipts = nil
	ledger.Status = "complete"
	if err := validateRealCloudAcceptanceLedger(ledger); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("premature complete err=%v", err)
	}
}

func TestRealCloudAcceptanceLedgerCompletesOnlyExactStepTable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	binding := realCloudAcceptanceLedgerTestBinding(t, root, "run-real-cloud-ledger-complete-01")
	store, err := acquireRealCloudAcceptanceLedger(root, "fresh", binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.MarkComplete(time.Now().UTC()); err == nil {
		t.Fatal("ledger completed without the exact receipt set")
	}
	for index, id := range realCloudAcceptanceStepIDs {
		instant := time.Date(2026, 7, 14, 3, 0, index, 0, time.UTC)
		if _, err := store.BeginStep(id, map[string]any{"id": id, "logical_token": "@none"}, nil, instant); err != nil {
			t.Fatalf("begin %s: %v", id, err)
		}
		var updateFacts func(*realCloudResumeFacts) error
		switch id {
		case "capture-pre-purge-g4":
			updateFacts = func(facts *realCloudResumeFacts) error {
				facts.PrePurge = map[string]realEdgePrePurgeVendorEvidence{}
				for _, vendor := range []string{"cloudflare", "edgeone"} {
					facts.PrePurge[vendor] = realEdgePrePurgeVendorEvidence{
						Generation: 4, TransactionID: "tx-ledger-pre-purge-" + vendor,
						CleanURLSHA256: strings.Repeat("4", 64), BodySHA256: strings.Repeat("5", 64),
						Observations: []realEdgeMultiPoPObservation{{ObserverID: "a"}, {ObserverID: "b"}},
					}
				}
				return nil
			}
		case "interrupt-cf-g5":
			updateFacts = func(facts *realCloudResumeFacts) error {
				facts.CFInterrupted = &realCloudInterruptedFact{Target: "cf", Generation: 5, ParentGeneration: 4, TransactionID: "tx-ledger-cf-g5", LockedCheckpointSHA256: strings.Repeat("6", 64)}
				return nil
			}
		case "interrupt-cos-g6":
			updateFacts = func(facts *realCloudResumeFacts) error {
				facts.COSInterrupted = &realCloudInterruptedFact{Target: "cos", Generation: 6, ParentGeneration: 5, TransactionID: "tx-ledger-cos-g6", LockedCheckpointSHA256: strings.Repeat("7", 64)}
				return nil
			}
		case "allocate-snapshot-ids":
			updateFacts = func(facts *realCloudResumeFacts) error {
				facts.ExpiredSnapshotID = "el10-20260114"
				return nil
			}
		case "prepare-current-and-historical-snapshots":
			updateFacts = func(facts *realCloudResumeFacts) error {
				facts.RecentSnapshotID = "el10-20260714"
				return nil
			}
		case "final-fsck":
			updateFacts = func(facts *realCloudResumeFacts) error {
				attestation := realCloudStaticProviderRawAttestationForTest(12)
				attestation.ProductConfigSHA256 = binding.ConfigSHA256
				facts.ProviderClosure = &realCloudProviderClosureFact{
					ProviderLogPathSHA256: binding.ProviderLogPathSHA256,
					ProviderLogSHA256:     strings.Repeat("d", 64), ProviderSealSHA256: strings.Repeat("e", 64),
					ActiveArtifactSHA256: strings.Repeat("f", 64), ActiveSealSHA256: strings.Repeat("1", 64),
					CFPurgeEvidenceSHA256: strings.Repeat("2", 64), COSPurgeEvidenceSHA256: strings.Repeat("3", 64), ProviderRecords: 12,
					ProviderAttestation: attestation,
				}
				return nil
			}
		}
		if err := store.CompleteStep(id, map[string]any{"status": "verified", "step": id}, updateFacts, instant.Add(time.Second)); err != nil {
			t.Fatalf("complete %s: %v", id, err)
		}
	}
	spliced := store.Snapshot()
	spliced.Facts.ProviderClosure.ProviderAttestation.ProductConfigSHA256 = strings.Repeat("9", 64)
	if err := validateRealCloudAcceptanceLedger(spliced); err == nil || !strings.Contains(err.Error(), "another product config") {
		t.Fatalf("cross-config provider attestation replay err=%v", err)
	}
	spliced = store.Snapshot()
	spliced.Facts.ProviderClosure.ProviderAttestation.TokenVerifierName = "SOW_OTHER_ENTITLEMENTS"
	if err := validateRealCloudAcceptanceLedger(spliced); err == nil || !strings.Contains(err.Error(), "another product token verifier") {
		t.Fatalf("cross-verifier provider attestation replay err=%v", err)
	}
	if err := store.MarkComplete(time.Date(2026, 7, 14, 4, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	final := store.Snapshot()
	if final.Status != "complete" || final.Current != nil || len(final.Receipts) != len(realCloudAcceptanceStepIDs) {
		t.Fatalf("final ledger=%#v", final)
	}
	if _, err := store.BeginStep(realCloudAcceptanceStepIDs[0], struct{}{}, nil, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "already complete") {
		t.Fatalf("completed ledger accepted another step err=%v", err)
	}
}

func realCloudAcceptanceLedgerTestBinding(t *testing.T, root, runID string) realCloudAcceptanceBinding {
	t.Helper()
	configBody, err := realCloudConfigBodyForEnvironment(realCloudSafetyFixtureEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	identity := realCloudRunIdentity{
		Schema: "sow-real-cloud-run/v1", RunID: runID,
		ConfirmationSHA256: strings.Repeat("a", 64), ConfigSHA256: realCloudLowerSHA256(configBody), PublicKeySHA256: strings.Repeat("c", 64),
	}
	binding, err := realCloudAcceptanceBindingFor(identity, configBody, filepath.Join(filepath.Dir(root), "active.jsonl"), filepath.Join(filepath.Dir(root), "provider.jsonl"), []byte("observer-a\x00observer-b\n"))
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestRealCloudAcceptanceFrozenProgramAndFactPrefix(t *testing.T) {
	if len(realCloudAcceptanceStepIDs) != 50 {
		t.Fatalf("frozen program steps=%d want=50", len(realCloudAcceptanceStepIDs))
	}
	seen := make(map[string]struct{}, len(realCloudAcceptanceStepIDs))
	for index, descriptor := range realCloudAcceptanceStepDescriptors() {
		if descriptor.ID != realCloudAcceptanceStepIDs[index] || descriptor.SemanticVersion == 0 || descriptor.PostconditionVersion == 0 || descriptor.IntentTemplate == "" {
			t.Fatalf("invalid frozen descriptor %d: %#v", index, descriptor)
		}
		if _, duplicate := seen[descriptor.ID]; duplicate {
			t.Fatalf("duplicate frozen step %q", descriptor.ID)
		}
		seen[descriptor.ID] = struct{}{}
	}
	binding := realCloudAcceptanceBinding{ProviderLogPathSHA256: strings.Repeat("a", 64)}
	rules := []struct {
		step   string
		mutate func(*realCloudResumeFacts, bool)
	}{
		{step: "allocate-snapshot-ids", mutate: func(f *realCloudResumeFacts, present bool) {
			if present {
				f.ExpiredSnapshotID = "el10-20260114"
			} else {
				f.ExpiredSnapshotID = ""
			}
		}},
		{step: "prepare-current-and-historical-snapshots", mutate: func(f *realCloudResumeFacts, present bool) {
			if present {
				f.RecentSnapshotID = "el10-20260714"
			} else {
				f.RecentSnapshotID = ""
			}
		}},
		{step: "capture-pre-purge-g4", mutate: func(f *realCloudResumeFacts, present bool) {
			if present {
				f.PrePurge = map[string]realEdgePrePurgeVendorEvidence{"cloudflare": {Generation: 4}}
			} else {
				f.PrePurge = nil
			}
		}},
		{step: "interrupt-cf-g5", mutate: func(f *realCloudResumeFacts, present bool) {
			if present {
				f.CFInterrupted = &realCloudInterruptedFact{}
			} else {
				f.CFInterrupted = nil
			}
		}},
		{step: "interrupt-cos-g6", mutate: func(f *realCloudResumeFacts, present bool) {
			if present {
				f.COSInterrupted = &realCloudInterruptedFact{}
			} else {
				f.COSInterrupted = nil
			}
		}},
		{step: "final-fsck", mutate: func(f *realCloudResumeFacts, present bool) {
			if present {
				f.ProviderClosure = &realCloudProviderClosureFact{ProviderLogPathSHA256: binding.ProviderLogPathSHA256}
			} else {
				f.ProviderClosure = nil
			}
		}},
	}
	for _, rule := range rules {
		t.Run(rule.step, func(t *testing.T) {
			index := slices.Index(realCloudAcceptanceStepIDs, rule.step)
			before := realCloudAcceptanceLedger{Binding: binding, Receipts: make([]realCloudStepReceipt, index), Facts: realCloudFactsForReceiptPrefix(index, binding)}
			if err := validateRealCloudFactReceiptPrefix(before); err != nil {
				t.Fatalf("valid before-prefix: %v", err)
			}
			rule.mutate(&before.Facts, true)
			if err := validateRealCloudFactReceiptPrefix(before); err == nil {
				t.Fatal("fact was accepted before its atomic receipt")
			}

			afterCount := index + 1
			after := realCloudAcceptanceLedger{Binding: binding, Receipts: make([]realCloudStepReceipt, afterCount), Facts: realCloudFactsForReceiptPrefix(afterCount, binding)}
			if err := validateRealCloudFactReceiptPrefix(after); err != nil {
				t.Fatalf("valid after-prefix: %v", err)
			}
			rule.mutate(&after.Facts, false)
			if err := validateRealCloudFactReceiptPrefix(after); err == nil {
				t.Fatal("receipt was accepted without its atomic fact")
			}
		})
	}
}

func realCloudFactsForReceiptPrefix(count int, binding realCloudAcceptanceBinding) realCloudResumeFacts {
	completed := func(id string) bool { return count > slices.Index(realCloudAcceptanceStepIDs, id) }
	facts := realCloudResumeFacts{}
	if completed("capture-pre-purge-g4") {
		facts.PrePurge = map[string]realEdgePrePurgeVendorEvidence{"cloudflare": {Generation: 4}}
	}
	if completed("interrupt-cf-g5") {
		facts.CFInterrupted = &realCloudInterruptedFact{}
	}
	if completed("interrupt-cos-g6") {
		facts.COSInterrupted = &realCloudInterruptedFact{}
	}
	if completed("allocate-snapshot-ids") {
		facts.ExpiredSnapshotID = "el10-20260114"
	}
	if completed("prepare-current-and-historical-snapshots") {
		facts.RecentSnapshotID = "el10-20260714"
	}
	if completed("final-fsck") {
		facts.ProviderClosure = &realCloudProviderClosureFact{ProviderLogPathSHA256: binding.ProviderLogPathSHA256}
	}
	return facts
}

func completeRealCloudAcceptanceReceiptsForTest(t *testing.T, store *realCloudAcceptanceLedgerStore, binding realCloudAcceptanceBinding, base time.Time) {
	t.Helper()
	advanceRealCloudAcceptanceReceiptsForTest(t, store, binding, base, len(realCloudAcceptanceStepIDs))
}

func advanceRealCloudAcceptanceReceiptsForTest(t *testing.T, store *realCloudAcceptanceLedgerStore, binding realCloudAcceptanceBinding, base time.Time, count int) {
	t.Helper()
	if count < 0 || count > len(realCloudAcceptanceStepIDs) {
		t.Fatalf("invalid test receipt count %d", count)
	}
	for index, id := range realCloudAcceptanceStepIDs[:count] {
		instant := base.Add(time.Duration(index*2) * time.Second)
		if _, err := store.BeginStep(id, map[string]string{"step": id}, nil, instant); err != nil {
			t.Fatalf("begin %s: %v", id, err)
		}
		var update func(*realCloudResumeFacts) error
		switch id {
		case "capture-pre-purge-g4":
			update = func(facts *realCloudResumeFacts) error {
				facts.PrePurge = map[string]realEdgePrePurgeVendorEvidence{}
				for _, vendor := range []string{"cloudflare", "edgeone"} {
					facts.PrePurge[vendor] = realEdgePrePurgeVendorEvidence{
						Generation: 4, TransactionID: "tx-finalize-pre-purge-" + vendor,
						CleanURLSHA256: strings.Repeat("4", 64), BodySHA256: strings.Repeat("5", 64),
						Observations: []realEdgeMultiPoPObservation{{ObserverID: "a"}, {ObserverID: "b"}},
					}
				}
				return nil
			}
		case "interrupt-cf-g5":
			update = func(facts *realCloudResumeFacts) error {
				facts.CFInterrupted = &realCloudInterruptedFact{Target: "cf", Generation: 5, ParentGeneration: 4, TransactionID: "tx-finalize-cf-g5", LockedCheckpointSHA256: strings.Repeat("6", 64)}
				return nil
			}
		case "interrupt-cos-g6":
			update = func(facts *realCloudResumeFacts) error {
				facts.COSInterrupted = &realCloudInterruptedFact{Target: "cos", Generation: 6, ParentGeneration: 5, TransactionID: "tx-finalize-cos-g6", LockedCheckpointSHA256: strings.Repeat("7", 64)}
				return nil
			}
		case "allocate-snapshot-ids":
			update = func(facts *realCloudResumeFacts) error { facts.ExpiredSnapshotID = "el10-20260114"; return nil }
		case "prepare-current-and-historical-snapshots":
			update = func(facts *realCloudResumeFacts) error { facts.RecentSnapshotID = "el10-20260714"; return nil }
		case "final-fsck":
			update = func(facts *realCloudResumeFacts) error {
				attestation := realCloudStaticProviderRawAttestationForTest(12)
				attestation.ProductConfigSHA256 = binding.ConfigSHA256
				facts.ProviderClosure = &realCloudProviderClosureFact{
					ProviderLogPathSHA256: binding.ProviderLogPathSHA256, ProviderLogSHA256: strings.Repeat("d", 64), ProviderSealSHA256: strings.Repeat("e", 64),
					ActiveArtifactSHA256: strings.Repeat("f", 64), ActiveSealSHA256: strings.Repeat("1", 64),
					CFPurgeEvidenceSHA256: strings.Repeat("2", 64), COSPurgeEvidenceSHA256: strings.Repeat("3", 64), ProviderRecords: 12,
					ProviderAttestation: attestation,
				}
				return nil
			}
		}
		if err := store.CompleteStep(id, map[string]string{"status": "verified"}, update, instant.Add(time.Second)); err != nil {
			t.Fatalf("complete %s: %v", id, err)
		}
	}
}

func TestFinalizeRealCloudAcceptanceRevalidatesCrashWindowAndReservation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	runID := "run-real-cloud-finalize-crash-20260714"
	binding := realCloudAcceptanceLedgerTestBinding(t, root, runID)
	store, err := acquireRealCloudAcceptanceLedger(root, "fresh", binding)
	if err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(filepath.Dir(root), "active.jsonl")
	reservation, err := acquireRealEdgePersistentRunReservation(artifactPath, runID, "fresh")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 14, 6, 0, 0, 0, time.UTC)
	completeRealCloudAcceptanceReceiptsForTest(t, store, binding, base)
	revalidations := 0
	if err := finalizeRealCloudAcceptanceLedger(store, func() error {
		revalidations++
		return errors.New("provider closure changed in final crash window")
	}, base.Add(2*time.Hour)); err == nil {
		t.Fatal("failed immediate revalidation still marked the ledger complete")
	}
	if snapshot := store.Snapshot(); snapshot.Status != "running" || snapshot.FinalProofSHA256 != "" || snapshot.Current != nil || len(snapshot.Receipts) != 50 {
		t.Fatalf("failed finalization mutated ledger=%#v", snapshot)
	}
	if err := reservation.CloseIncomplete(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = acquireRealCloudAcceptanceLedger(root, "recover", binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	reservation, err = acquireRealEdgePersistentRunReservation(artifactPath, runID, "recover")
	if err != nil {
		t.Fatal(err)
	}
	if err := finalizeRealCloudAcceptanceLedger(store, func() error {
		revalidations++
		snapshot := store.Snapshot()
		if snapshot.Status != "running" || snapshot.Facts.ProviderClosure == nil {
			return errors.New("final receipt closure is absent")
		}
		return nil
	}, base.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if revalidations != 2 || store.Snapshot().Status != "complete" {
		t.Fatalf("revalidations=%d status=%s", revalidations, store.Snapshot().Status)
	}
	if _, err := os.Lstat(artifactPath + realEdgeRunLockSuffix); err != nil {
		t.Fatalf("mark complete removed reservation before explicit closure: %v", err)
	}
	if err := reservation.Complete(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(artifactPath + realEdgeRunLockSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed reservation remains: %v", err)
	}
}

func TestRealCloudAcceptanceCLISubstepCrashRecovery(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	binding := realCloudAcceptanceLedgerTestBinding(t, root, "run-real-cloud-cli-journal-20260714")
	store, err := acquireRealCloudAcceptanceLedger(root, "fresh", binding)
	if err != nil {
		t.Fatal(err)
	}
	step := realCloudAcceptanceStepIDs[0]
	start := time.Date(2026, 7, 14, 5, 0, 0, 0, time.UTC)
	if _, err := store.BeginStep(step, []string{"compound", "two-cli-operations"}, nil, start); err != nil {
		t.Fatal(err)
	}
	firstArgs := []string{"init", "--config", "/private/sow.yaml"}
	completed, resumed, _, err := store.BeginCLISubstep(step, 0, 0, firstArgs, start.Add(time.Second))
	if err != nil || completed || resumed {
		t.Fatalf("first CLI begin completed=%v resumed=%v err=%v", completed, resumed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = acquireRealCloudAcceptanceLedger(root, "recover", binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.BeginCLISubstep(step, 0, 0, []string{"init", "--config", "/private/other.yaml"}, start.Add(2*time.Second)); err == nil {
		t.Fatal("different CLI arguments resumed an interrupted operation")
	}
	completed, resumed, _, err = store.BeginCLISubstep(step, 0, 0, firstArgs, start.Add(2*time.Second))
	if err != nil || completed || !resumed {
		t.Fatalf("exact first CLI resume completed=%v resumed=%v err=%v", completed, resumed, err)
	}
	if got := injectRealCloudRecoverFlag(firstArgs); !slices.Equal(got, []string{"init", "--config", "/private/sow.yaml", "--recover"}) {
		t.Fatalf("first CLI recovery arguments=%v", got)
	}
	if err := store.CompleteCLISubstep(step, 0, 0, "first durable output\n", start.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	completed, resumed, output, err := store.BeginCLISubstep(step, 0, 0, firstArgs, start.Add(4*time.Second))
	if err != nil || !completed || resumed || output != "first durable output\n" {
		t.Fatalf("completed prefix replay completed=%v resumed=%v output=%q err=%v", completed, resumed, output, err)
	}
	secondArgs := []string{"publish", "--view", "latest", "--target", "cf"}
	if completed, resumed, _, err = store.BeginCLISubstep(step, 1, 0, secondArgs, start.Add(4*time.Second)); err != nil || completed || resumed {
		t.Fatalf("second CLI begin completed=%v resumed=%v err=%v", completed, resumed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = acquireRealCloudAcceptanceLedger(root, "recover", binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	completed, _, output, err = store.BeginCLISubstep(step, 0, 0, firstArgs, start.Add(5*time.Second))
	if err != nil || !completed || output != "first durable output\n" {
		t.Fatalf("middle-crash lost completed prefix output=%q err=%v", output, err)
	}
	completed, resumed, _, err = store.BeginCLISubstep(step, 1, 0, secondArgs, start.Add(5*time.Second))
	if err != nil || completed || !resumed {
		t.Fatalf("middle CLI did not resume exactly completed=%v resumed=%v err=%v", completed, resumed, err)
	}
	if err := store.CompleteCLISubstep(step, 1, 0, "second durable output\n", start.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.RequireCLISubstepsConsumed(step, 2); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteStep(step, map[string]string{"status": "closed"}, nil, start.Add(7*time.Second)); err != nil {
		t.Fatal(err)
	}
	receipt := store.Snapshot().Receipts[0]
	if receipt.CLISubsteps != 2 || len(receipt.CLIAudit) != 2 || receipt.CLIAudit[0].OutputSHA256 != realCloudLowerSHA256([]byte("first durable output\n")) {
		t.Fatalf("compact top-level CLI audit=%#v", receipt)
	}
	body, err := json.Marshal(receipt)
	if err != nil || bytes.Contains(body, []byte("durable output")) {
		t.Fatalf("top-level receipt retained unbounded CLI output body=%s err=%v", body, err)
	}
}

func TestInjectRealCloudRecoverFlagCommandGrammar(t *testing.T) {
	tests := []struct {
		arguments []string
		want      []string
	}{
		{[]string{"init", "--config", "sow.yaml"}, []string{"init", "--config", "sow.yaml", "--recover"}},
		{[]string{"add", "a.deb", "b.rpm", "--repo", "x"}, []string{"add", "a.deb", "b.rpm", "--recover", "--repo", "x"}},
		{[]string{"rm", "pkg", "--repo", "x"}, []string{"rm", "--recover", "pkg", "--repo", "x"}},
		{[]string{"promote", "stable", "el10-20260714", "--repo", "x"}, []string{"promote", "stable", "el10-20260714", "--recover", "--repo", "x"}},
		{[]string{"publish", "--view", "latest"}, []string{"publish", "--view", "latest", "--recover"}},
		{[]string{"verify", "--layer", "L4"}, []string{"verify", "--layer", "L4", "--recover"}},
		{[]string{"fsck", "--limit", "0"}, []string{"fsck", "--limit", "0", "--recover"}},
		{[]string{"publish", "--recover", "--view", "latest"}, []string{"publish", "--recover", "--view", "latest"}},
	}
	for _, test := range tests {
		if got := injectRealCloudRecoverFlag(test.arguments); !slices.Equal(got, test.want) {
			t.Errorf("inject %v = %v want %v", test.arguments, got, test.want)
		}
	}
}

func TestRealCloudSnapshotPromoteJournalCrossesUTCMidnightSafely(t *testing.T) {
	for _, committed := range []bool{true, false} {
		name := "unmutated-roll-forward"
		if committed {
			name = "committed-old-date-consumed"
		}
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "workspace")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			runSuffix := "rolled"
			if committed {
				runSuffix = "committed"
			}
			binding := realCloudAcceptanceLedgerTestBinding(t, root, "run-rc-snapshot-20260714-"+runSuffix)
			store, err := acquireRealCloudAcceptanceLedger(root, "fresh", binding)
			if err != nil {
				t.Fatal(err)
			}
			base := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC)
			prepareIndex := slices.Index(realCloudAcceptanceStepIDs, "prepare-current-and-historical-snapshots")
			advanceRealCloudAcceptanceReceiptsForTest(t, store, binding, base, prepareIndex)
			step := "prepare-current-and-historical-snapshots"
			started := time.Date(2026, 7, 13, 23, 59, 55, 0, time.UTC)
			if _, err := store.BeginStep(step, []string{"cross-utc-midnight"}, nil, started); err != nil {
				t.Fatal(err)
			}
			fsck := []string{"fsck", "--recover", "--limit", "0"}
			if _, _, _, err := store.BeginCLISubstep(step, 0, 0, fsck, started.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := store.CompleteCLISubstep(step, 0, 0, "fsck recovered\n", started.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			oldPromote := []string{"promote", "stable", "el10-20260713", "--repo", realCloudYUMRepositoryID}
			if _, _, _, err := store.BeginCLISubstep(step, 1, 0, oldPromote, started.Add(3*time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = acquireRealCloudAcceptanceLedger(root, "recover", binding)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if committed {
				program := &realCloudAcceptanceProgram{t: t, ledger: store, activeStepID: step, cliCursor: 1}
				output := program.consumeRecoveredCLIFromPostcondition(0, "promote recovered from exact immutable snapshot ref\n", oldPromote...)
				if output == "" || store.Snapshot().Current.CLIInFlight != nil || len(store.Snapshot().Current.CLIReceipts) != 2 || store.Snapshot().Current.CLIReceipts[1].Arguments[2] != "el10-20260713" {
					t.Fatalf("committed cross-day promote was not consumed from exact old ref: %#v", store.Snapshot().Current)
				}
				return
			}
			newPromote := []string{"promote", "stable", "el10-20260714", "--repo", realCloudYUMRepositoryID}
			if err := store.ReplaceInFlightCLIArguments(step, 1, 0, oldPromote, newPromote, time.Date(2026, 7, 14, 0, 0, 5, 0, time.UTC)); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := store.BeginCLISubstep(step, 1, 0, oldPromote, time.Date(2026, 7, 14, 0, 0, 6, 0, time.UTC)); err == nil {
				t.Fatal("rolled snapshot intent still accepted the stale date")
			}
			completed, resumed, _, err := store.BeginCLISubstep(step, 1, 0, newPromote, time.Date(2026, 7, 14, 0, 0, 6, 0, time.UTC))
			if err != nil || completed || !resumed {
				t.Fatalf("new UTC snapshot intent completed=%v resumed=%v err=%v", completed, resumed, err)
			}
		})
	}
}

func TestRealCloudPrivateBootstrapAtomicWindows(t *testing.T) {
	directory := t.TempDir()
	wanted := []byte("complete-bootstrap-body\n")
	for index, orphan := range [][]byte{nil, []byte("partial"), wanted} {
		orphanPath := filepath.Join(directory, fmt.Sprintf(".sow-private-bootstrap-crash-%d", index))
		if err := os.WriteFile(orphanPath, orphan, 0o600); err != nil {
			t.Fatal(err)
		}
		finalPath := filepath.Join(directory, fmt.Sprintf("final-%d", index))
		installed, err := installRealCloudPrivateFileExclusive(finalPath, wanted)
		body, readErr := os.ReadFile(finalPath)
		if err != nil || !installed || readErr != nil || !bytes.Equal(body, wanted) {
			t.Fatalf("orphan window %d installed=%v body=%q err=%v read=%v", index, installed, body, err, readErr)
		}
	}

	linkedTemporary := filepath.Join(directory, ".sow-private-bootstrap-linked")
	linkedFinal := filepath.Join(directory, "linked-final")
	if err := os.WriteFile(linkedTemporary, wanted, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(linkedTemporary, linkedFinal); err != nil {
		t.Fatal(err)
	}
	installed, err := installRealCloudPrivateFileExclusive(linkedFinal, []byte("replacement"))
	body, readErr := os.ReadFile(linkedFinal)
	if err != nil || installed || readErr != nil || !bytes.Equal(body, wanted) {
		t.Fatalf("post-link window installed=%v body=%q err=%v read=%v", installed, body, err, readErr)
	}

	partialFinal := filepath.Join(directory, "partial-final")
	if err := os.WriteFile(partialFinal, []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	installed, err = installRealCloudPrivateFileExclusive(partialFinal, wanted)
	body, readErr = os.ReadFile(partialFinal)
	if err != nil || installed || readErr != nil || string(body) != "half" {
		t.Fatalf("legacy partial final was overwritten installed=%v body=%q err=%v read=%v", installed, body, err, readErr)
	}
}

func TestRealCloudInitialLedgerRejectsLegacyPartialFinal(t *testing.T) {
	for _, body := range [][]byte{nil, []byte(`{"schema":"sow-real-cloud-acceptance/v1"`)} {
		t.Run(fmt.Sprintf("bytes-%d", len(body)), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "workspace")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, realCloudAcceptanceLedgerFilename)
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readRealCloudAcceptanceLedger(path); err == nil {
				t.Fatal("partial initial ledger was decoded")
			}
			binding := realCloudAcceptanceLedgerTestBinding(t, root, "run-real-cloud-partial-ledger-20260714")
			ledger := realCloudAcceptanceLedger{Schema: realCloudAcceptanceLedgerSchema, Binding: binding, Revision: 1, Status: "running", Receipts: []realCloudStepReceipt{}, Facts: realCloudResumeFacts{}}
			if err := writeRealCloudAcceptanceLedgerExclusive(path, ledger); err == nil {
				t.Fatal("exclusive initial ledger overwrote a partial final")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, body) {
				t.Fatalf("partial initial ledger was not preserved body=%q err=%v", after, err)
			}
		})
	}
}

func TestRealCloudImplementationIdentityBindsExecutableAndAllFiles(t *testing.T) {
	digest, err := realCloudAcceptanceImplementationSHA256()
	if err != nil || !validRealCloudLowerSHA256(digest) {
		t.Fatalf("implementation digest=%q err=%v", digest, err)
	}
	root := t.TempDir()
	for _, directory := range []string{"cmd", "internal", "third_party", filepath.Join("test", "compat"), "edge"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, body := range map[string][]byte{
		"go.mod": []byte("module example.invalid/test\n"), "go.sum": nil,
		filepath.Join("third_party", "replace.go"):     []byte("package replace\n"),
		filepath.Join("test", "compat", "fixture.b64"): []byte("YWJj\n"),
	} {
		if err := os.WriteFile(filepath.Join(root, path), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	first, err := realCloudAcceptanceSourceManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "test", "compat", "fixture.b64"), []byte("ZGVm\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := realCloudAcceptanceSourceManifest(root)
	if err != nil || bytes.Equal(first, second) {
		t.Fatalf("non-Go fixture mutation was not bound err=%v", err)
	}
	file := filepath.Join(root, "binary")
	if err := os.WriteFile(file, []byte("machine-code-a"), 0o700); err != nil {
		t.Fatal(err)
	}
	firstExecutable, _, err := digestRealCloudStableRegularFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("machine-code-b"), 0o700); err != nil {
		t.Fatal(err)
	}
	secondExecutable, _, err := digestRealCloudStableRegularFile(file)
	if err != nil || firstExecutable == secondExecutable {
		t.Fatalf("executable byte mutation was not bound err=%v", err)
	}
}
