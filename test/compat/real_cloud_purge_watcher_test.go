package compat_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/publish"
	"golang.org/x/sys/unix"
)

const (
	realCloudPurgeWatcherSpecSchema     = "sow-real-cloud-purge-watcher-spec/v1"
	realCloudPurgeWatcherArmedSchema    = "sow-real-cloud-purge-watcher-armed/v1"
	realCloudPurgeWatcherEvidenceSchema = "sow-real-cloud-purge-watcher-evidence/v1"
	realCloudPurgeWatcherCompleteSchema = "sow-real-cloud-purge-watcher-complete/v1"
	realCloudPurgeWatcherDirectoryName  = ".sow-real-cloud-purge-watcher"
	realCloudPurgeWatcherHelperEnv      = "SOW_REAL_CLOUD_PURGE_WATCHER_HELPER"
	realCloudPurgeWatcherRootEnv        = "SOW_REAL_CLOUD_PURGE_WATCHER_ROOT"
	realCloudPurgeWatcherSpecSHAEnv     = "SOW_REAL_CLOUD_PURGE_WATCHER_SPEC_SHA256"
	realCloudPurgeWatcherFileLimit      = 256 << 10
	realCloudPurgeWatcherPollInterval   = 250 * time.Millisecond
)

var (
	errRealCloudPurgeWatcherPending = errors.New("purge watcher publication is not committed yet")
	errRealCloudPurgeWatcherActive  = errors.New("purge watcher is already active")

	// Kept injectable only so crash-window tests can prove that a matching
	// pre-existing link is not mistaken for durable state after a parent
	// directory sync failure. Production always uses the real directory fsync.
	realCloudPurgeWatcherSyncDirectory = syncRealCloudDirectoryError
)

// realCloudPurgeWatcherSpec is secret-free. Its MAC is keyed by the two
// run-bound entitlement tokens, but neither token nor any proxy URL/userinfo is
// written to disk. The spec is installed and the child is armed before the
// generation-five publication is allowed to start.
type realCloudPurgeWatcherSpec struct {
	Schema                  string                            `json:"schema"`
	RunID                   string                            `json:"run_id"`
	ConfirmationSHA256      string                            `json:"confirmation_sha256"`
	ConfigSHA256            string                            `json:"config_sha256"`
	AcceptanceBindingSHA256 string                            `json:"acceptance_binding_sha256"`
	ResourceSHA256          string                            `json:"resource_sha256"`
	ObserverTopologySHA256  string                            `json:"observer_topology_sha256"`
	WorkspaceSHA256         string                            `json:"workspace_sha256"`
	Generation              uint64                            `json:"generation"`
	ExpectedBodySHA256      string                            `json:"expected_body_sha256"`
	EntitlementSHA256       []string                          `json:"entitlement_sha256"`
	Nonce                   string                            `json:"nonce"`
	IssuedAt                string                            `json:"issued_at"`
	EvidenceDeadline        string                            `json:"evidence_deadline"`
	Vendors                 []realCloudPurgeWatcherVendorSpec `json:"vendors"`
	MACSHA256               string                            `json:"mac_sha256"`
}

type realCloudPurgeWatcherVendorSpec struct {
	Vendor              string                              `json:"vendor"`
	Target              string                              `json:"target"`
	ParentGeneration    uint64                              `json:"parent_generation"`
	ParentTransactionID string                              `json:"parent_transaction_id"`
	CleanURLSHA256      string                              `json:"clean_url_sha256"`
	PriorBodySHA256     string                              `json:"prior_body_sha256"`
	ExpectedBodySHA256  string                              `json:"expected_body_sha256"`
	Observers           []realCloudPurgeWatcherObserverSpec `json:"observers"`
}

type realCloudPurgeWatcherObserverSpec struct {
	ID         string `json:"id"`
	Role       string `json:"role"`
	FreshUntil string `json:"fresh_until"`
}

type realCloudPurgeWatcherArmed struct {
	Schema           string `json:"schema"`
	SpecSHA256       string `json:"spec_sha256"`
	RunID            string `json:"run_id"`
	ResourceSHA256   string `json:"resource_sha256"`
	Generation       uint64 `json:"generation"`
	Nonce            string `json:"nonce"`
	EvidenceDeadline string `json:"evidence_deadline"`
	MACSHA256        string `json:"mac_sha256"`
}

type realCloudPurgeWatcherEvidence struct {
	Schema                string                              `json:"schema"`
	SpecSHA256            string                              `json:"spec_sha256"`
	RunID                 string                              `json:"run_id"`
	ResourceSHA256        string                              `json:"resource_sha256"`
	Vendor                string                              `json:"vendor"`
	Target                string                              `json:"target"`
	Generation            uint64                              `json:"generation"`
	TransactionID         string                              `json:"transaction_id"`
	GenerationSHA256      string                              `json:"generation_sha256"`
	CheckpointSHA256      string                              `json:"checkpoint_sha256"`
	PurgeEvidenceSHA256   string                              `json:"purge_evidence_sha256"`
	PurgeCompletedAt      string                              `json:"purge_completed_at"`
	PublicationObservedAt string                              `json:"publication_observed_at"`
	CleanURLSHA256        string                              `json:"clean_url_sha256"`
	BodySHA256            string                              `json:"body_sha256"`
	Observations          []realEdgeActiveArtifactObservation `json:"observations"`
	CompletedAt           string                              `json:"completed_at"`
	MACSHA256             string                              `json:"mac_sha256"`
}

type realCloudPurgeWatcherComplete struct {
	Schema         string `json:"schema"`
	SpecSHA256     string `json:"spec_sha256"`
	RunID          string `json:"run_id"`
	ResourceSHA256 string `json:"resource_sha256"`
	Vendor         string `json:"vendor"`
	Generation     uint64 `json:"generation"`
	TransactionID  string `json:"transaction_id"`
	EvidenceSHA256 string `json:"evidence_sha256"`
	DurableAt      string `json:"durable_at"`
	MACSHA256      string `json:"mac_sha256"`
}

type realCloudPurgeWatcherProcessIdentity struct {
	Schema    string `json:"schema"`
	PID       int    `json:"pid"`
	ParentPID int    `json:"parent_pid"`
	SessionID int    `json:"session_id"`
	GroupID   int    `json:"process_group_id"`
}

type realCloudPurgeWatcherPublication struct {
	Target              string
	Generation          uint64
	TransactionID       string
	GatedBodySHA256     string
	GenerationSHA256    string
	CheckpointSHA256    string
	PurgeEvidenceSHA256 string
	PurgeCompletedAt    time.Time
}

type realCloudPurgeWatcherPaths struct {
	directory string
	spec      string
	body      string
	armed     string
	lock      string
	evidence  map[string]string
	complete  map[string]string
}

type realCloudPurgeWatcherClock struct {
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

type realCloudPurgeWatcherRuntime struct {
	clock             realCloudPurgeWatcherClock
	validateResources func() error
	loadPublication   func(string, uint64) (realCloudPurgeWatcherPublication, error)
	observe           func(context.Context, realCloudPurgeWatcherVendorSpec, realCloudPurgeWatcherObserverSpec, time.Time) (realEdgeMultiPoPObservation, error)
	beforeNetwork     func()
}

func realCloudPurgeWatcherPathsFor(root string, generation uint64) (realCloudPurgeWatcherPaths, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || generation == 0 {
		return realCloudPurgeWatcherPaths{}, errors.New("purge watcher root or generation is invalid")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&0o077 != 0 {
		return realCloudPurgeWatcherPaths{}, errors.New("purge watcher root must be a private non-symlink directory")
	}
	base := filepath.Join(root, realCloudPurgeWatcherDirectoryName)
	if err := os.Mkdir(base, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return realCloudPurgeWatcherPaths{}, errors.New("create purge watcher directory")
	}
	baseInfo, err := os.Lstat(base)
	if err != nil || !baseInfo.IsDir() || baseInfo.Mode()&os.ModeSymlink != 0 || baseInfo.Mode().Perm()&0o077 != 0 {
		return realCloudPurgeWatcherPaths{}, errors.New("purge watcher directory is unsafe")
	}
	// Sync even when the directory already existed. A prior attempt can have
	// created the entry and then failed its parent sync; retry must close that
	// exact crash window instead of adopting an only-page-cache-visible path.
	if err := realCloudPurgeWatcherSyncDirectory(root); err != nil {
		return realCloudPurgeWatcherPaths{}, errors.New("sync purge watcher root directory")
	}
	directory := filepath.Join(base, fmt.Sprintf("generation-%020d", generation))
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return realCloudPurgeWatcherPaths{}, errors.New("create generation purge watcher directory")
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || directoryInfo.Mode().Perm()&0o077 != 0 {
		return realCloudPurgeWatcherPaths{}, errors.New("generation purge watcher directory is unsafe")
	}
	if err := realCloudPurgeWatcherSyncDirectory(base); err != nil {
		return realCloudPurgeWatcherPaths{}, errors.New("sync generation purge watcher parent directory")
	}
	return realCloudPurgeWatcherPaths{
		directory: directory,
		spec:      filepath.Join(directory, "spec.json"),
		body:      filepath.Join(directory, "expected-body.bin"),
		armed:     filepath.Join(directory, "armed.json"),
		lock:      filepath.Join(directory, "watcher.lock"),
		evidence: map[string]string{
			"cloudflare": filepath.Join(directory, "cloudflare.json"),
			"edgeone":    filepath.Join(directory, "edgeone.json"),
		},
		complete: map[string]string{
			"cloudflare": filepath.Join(directory, "cloudflare.complete.json"),
			"edgeone":    filepath.Join(directory, "edgeone.complete.json"),
		},
	}, nil
}

func realCloudPurgeWatcherMACKey(tokenA, tokenB string) ([]byte, error) {
	if !validRealCloudEdgeToken(tokenA) || !validRealCloudEdgeToken(tokenB) || tokenA == tokenB {
		return nil, errors.New("purge watcher requires two distinct valid entitlements")
	}
	digest := sha256.Sum256([]byte("sow-real-cloud-purge-watcher-mac/v1\x00" + tokenA + "\x00" + tokenB))
	return digest[:], nil
}

func realCloudPurgeWatcherResourceSHA256(environment realCloudEnvironment) (string, error) {
	body, err := json.Marshal(realCloudTestResourceForEnvironment(environment))
	if err != nil {
		return "", errors.New("encode purge watcher resource binding")
	}
	return realCloudLowerSHA256(body), nil
}

func realCloudPurgeWatcherAcceptanceBindingSHA256(binding realCloudAcceptanceBinding) (string, error) {
	return realCloudCanonicalValueSHA256(binding)
}

func realCloudPurgeWatcherWorkspaceSHA256(root string) (string, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errors.New("purge watcher workspace path is invalid")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return "", errors.New("purge watcher workspace path is not canonical")
	}
	return realCloudLowerSHA256([]byte(root)), nil
}

// validateRealCloudPurgeWatcherRuntimeBinding makes the detached child a
// self-contained trust boundary. The parent checks the same bindings before
// spawn, but a recovered or manually re-invoked helper must not be able to use
// a signed spec from one pinned non-production resource/topology/workspace
// while issuing probes against another.
func validateRealCloudPurgeWatcherRuntimeBinding(
	root string,
	environment realCloudEnvironment,
	spec realCloudPurgeWatcherSpec,
	getenv func(string) string,
) error {
	confirmationSHA := realCloudLowerSHA256([]byte(realCloudConfirmation(environment)))
	if confirmationSHA != spec.ConfirmationSHA256 {
		return errors.New("purge watcher runtime confirmation differs from its signed spec")
	}
	resourceSHA, err := realCloudPurgeWatcherResourceSHA256(environment)
	if err != nil || resourceSHA != spec.ResourceSHA256 {
		return errors.New("purge watcher runtime resource differs from its signed spec")
	}
	workspaceSHA, err := realCloudPurgeWatcherWorkspaceSHA256(root)
	if err != nil || workspaceSHA != spec.WorkspaceSHA256 {
		return errors.New("purge watcher runtime workspace differs from its signed spec")
	}
	topology, err := realCloudObserverTopologyBindingFrom(getenv)
	topologySHA := realCloudLowerSHA256(topology)
	if err != nil || topologySHA != spec.ObserverTopologySHA256 {
		return errors.New("purge watcher runtime observer topology differs from its signed spec")
	}
	if !slices.Equal(realEdgeEntitlementDigests(environment.EdgeProTokenA, environment.EdgeProTokenB), spec.EntitlementSHA256) {
		return errors.New("purge watcher runtime entitlements differ from its signed spec")
	}
	var identity realCloudRunIdentity
	if _, err := readRealCloudPurgeWatcherJSON(filepath.Join(root, realCloudRunIdentityFilename), &identity); err != nil {
		return errors.New("purge watcher runtime run identity is absent or unsafe")
	}
	if identity.Schema != "sow-real-cloud-run/v1" || identity.RunID != spec.RunID ||
		identity.ConfirmationSHA256 != confirmationSHA || identity.ConfirmationSHA256 != spec.ConfirmationSHA256 ||
		identity.ConfigSHA256 != spec.ConfigSHA256 || !validRealCloudLowerSHA256(identity.PublicKeySHA256) {
		return errors.New("purge watcher runtime run identity differs from its signed spec and current confirmation")
	}
	configPath := filepath.Join(root, "sow.yaml")
	configInfo, err := os.Lstat(configPath)
	if err != nil || configInfo.Mode()&os.ModeSymlink != 0 || !configInfo.Mode().IsRegular() || configInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("purge watcher runtime config is absent or unsafe")
	}
	configSHA, _, err := digestRealCloudStableRegularFile(configPath)
	if err != nil || configSHA != spec.ConfigSHA256 || configSHA != identity.ConfigSHA256 {
		return errors.New("purge watcher runtime config differs from its signed spec")
	}
	configBody, err := readRealCloudPurgeWatcherPrivateFile(configPath, config.MaxConfigBytes)
	if err != nil || realCloudLowerSHA256(configBody) != configSHA {
		return errors.New("purge watcher runtime config changed while being read")
	}
	configAfter, err := os.Lstat(configPath)
	if err != nil || configAfter.Mode()&os.ModeSymlink != 0 || !configAfter.Mode().IsRegular() ||
		configAfter.Mode().Perm()&0o077 != 0 || !os.SameFile(configInfo, configAfter) {
		return errors.New("purge watcher runtime config changed while being bound")
	}
	var ledger realCloudAcceptanceLedger
	if _, err := readRealCloudPurgeWatcherJSON(filepath.Join(root, realCloudAcceptanceLedgerFilename), &ledger); err != nil || validateRealCloudAcceptanceLedger(ledger) != nil {
		return errors.New("purge watcher runtime acceptance ledger is absent or invalid")
	}
	currentBinding, err := realCloudAcceptanceBindingFor(identity, configBody,
		strings.TrimSpace(getenv(realEdgeActiveArtifactEnv)), strings.TrimSpace(getenv(realEdgeProviderLogEnv)), topology)
	if err != nil || ledger.Binding != currentBinding || ledger.Binding.RunID != spec.RunID ||
		ledger.Binding.ConfirmationSHA256 != confirmationSHA || ledger.Binding.ConfigSHA256 != configSHA ||
		ledger.Binding.ObserverTopologySHA256 != topologySHA {
		return errors.New("purge watcher runtime acceptance binding differs from the current run, harness, paths, or topology")
	}
	bindingSHA, err := realCloudPurgeWatcherAcceptanceBindingSHA256(ledger.Binding)
	if err != nil || bindingSHA != spec.AcceptanceBindingSHA256 {
		return errors.New("purge watcher runtime acceptance binding differs from its signed spec")
	}
	return nil
}

func validateRealCloudPurgeWatcherDetachedProcess() error {
	pid := os.Getpid()
	sid, err := unix.Getsid(0)
	if err != nil || sid != pid || unix.Getpgrp() != pid {
		return errors.New("purge watcher helper is not an independent session and process-group leader")
	}
	return nil
}

func realCloudPurgeWatcherSign(value any, key []byte) (string, error) {
	body, err := realCloudPurgeWatcherUnsignedBody(value)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func realCloudPurgeWatcherUnsignedBody(value any) ([]byte, error) {
	switch typed := value.(type) {
	case realCloudPurgeWatcherSpec:
		typed.MACSHA256 = ""
		return json.Marshal(typed)
	case realCloudPurgeWatcherArmed:
		typed.MACSHA256 = ""
		return json.Marshal(typed)
	case realCloudPurgeWatcherEvidence:
		typed.MACSHA256 = ""
		return json.Marshal(typed)
	case realCloudPurgeWatcherComplete:
		typed.MACSHA256 = ""
		return json.Marshal(typed)
	default:
		return nil, errors.New("unsupported purge watcher signed value")
	}
}

func realCloudPurgeWatcherVerifyMAC(value any, actual string, key []byte) error {
	if !validRealCloudLowerSHA256(actual) {
		return errors.New("purge watcher MAC is invalid")
	}
	wanted, err := realCloudPurgeWatcherSign(value, key)
	if err != nil || !hmac.Equal([]byte(wanted), []byte(actual)) {
		return errors.New("purge watcher evidence was changed or belongs to different entitlements")
	}
	return nil
}

func realCloudPurgeWatcherMarshalSigned(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("encode purge watcher record")
	}
	body = append(body, '\n')
	if len(body) > realCloudPurgeWatcherFileLimit {
		return nil, errors.New("purge watcher record exceeds its safe size limit")
	}
	return body, nil
}

func readRealCloudPurgeWatcherPrivateFile(path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("purge watcher private-file limit is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("purge watcher private file is absent or unsafe")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open purge watcher private file")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 || !os.SameFile(info, opened) {
		return nil, errors.New("purge watcher private-file identity changed during open")
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("read purge watcher private file")
	}
	after, statErr := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || pathAfter.Mode()&os.ModeSymlink != 0 || !pathAfter.Mode().IsRegular() ||
		after.Mode().Perm()&0o077 != 0 || pathAfter.Mode().Perm()&0o077 != 0 ||
		!os.SameFile(opened, after) || !os.SameFile(after, pathAfter) || after.Size() != int64(len(body)) ||
		!after.ModTime().Equal(opened.ModTime()) {
		return nil, errors.New("purge watcher private file changed while being read")
	}
	return body, nil
}

func readRealCloudPurgeWatcherJSON(path string, value any) ([]byte, error) {
	body, err := readRealCloudPurgeWatcherPrivateFile(path, realCloudPurgeWatcherFileLimit)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return nil, errors.New("decode purge watcher record")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("purge watcher record contains trailing values")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(body, append(canonical, '\n')) {
		return nil, errors.New("purge watcher record is not canonical JSON")
	}
	return body, nil
}

func installRealCloudPurgeWatcherRecord(path string, body []byte) error {
	installed, err := installRealCloudPrivateFileExclusiveWithPattern(path, body, ".sow-purge-watcher-*")
	if err != nil {
		return err
	}
	if installed {
		return realCloudPurgeWatcherSyncDirectory(filepath.Dir(path))
	}
	existing, err := readRealCloudPurgeWatcherPrivateFile(path, int64(len(body)))
	if err != nil || !bytes.Equal(existing, body) {
		return errors.New("purge watcher record conflicts with existing durable evidence")
	}
	// The exclusive helper can leave the final hardlink behind when link(2)
	// succeeds but fsync(parent) fails. A matching EEXIST retry is successful
	// only after it establishes the missing durability barrier itself.
	return realCloudPurgeWatcherSyncDirectory(filepath.Dir(path))
}

func buildRealCloudPurgeWatcherSpec(
	root string,
	environment realCloudEnvironment,
	identity realCloudRunIdentity,
	binding realCloudAcceptanceBinding,
	prePurge map[string]realEdgePrePurgeVendorEvidence,
	wanted []byte,
	now time.Time,
	nonce []byte,
) (realCloudPurgeWatcherSpec, error) {
	var spec realCloudPurgeWatcherSpec
	if len(prePurge) != 2 || len(wanted) == 0 || now.IsZero() || now.Location() != time.UTC || len(nonce) != 16 {
		return spec, errors.New("purge watcher inputs are incomplete")
	}
	resourceSHA, err := realCloudPurgeWatcherResourceSHA256(environment)
	if err != nil {
		return spec, err
	}
	topology, err := realCloudObserverTopologyBindingFrom(os.Getenv)
	if err != nil {
		return spec, err
	}
	workspaceSHA, err := realCloudPurgeWatcherWorkspaceSHA256(root)
	if err != nil {
		return spec, err
	}
	bindingSHA, err := realCloudPurgeWatcherAcceptanceBindingSHA256(binding)
	if err != nil {
		return spec, err
	}
	expectedBodySHA := realCloudLowerSHA256(wanted)
	observers, err := loadRealEdgeObservers(os.Getenv)
	if err != nil {
		return spec, err
	}
	deadline := time.Time{}
	vendors := make([]realCloudPurgeWatcherVendorSpec, 0, 2)
	for _, input := range []struct {
		vendor  string
		target  string
		baseURL string
	}{{"cloudflare", "cf", environment.CFCDNBase}, {"edgeone", "cos", environment.COSCDNBase}} {
		prior, exists := prePurge[input.vendor]
		if !exists || prior.Generation+1 != 5 || !validRealEdgeTransactionID(prior.TransactionID) || prior.BodySHA256 == expectedBodySHA {
			return spec, fmt.Errorf("%s purge watcher prior generation is invalid", input.vendor)
		}
		cleanSHA, cleanErr := realEdgeCleanURLDigest(input.baseURL)
		if cleanErr != nil || prior.CleanURLSHA256 != cleanSHA || len(prior.Observations) != len(observers) {
			return spec, fmt.Errorf("%s purge watcher clean URL or observer closure changed", input.vendor)
		}
		vendorSpec := realCloudPurgeWatcherVendorSpec{
			Vendor: input.vendor, Target: input.target, ParentGeneration: prior.Generation,
			ParentTransactionID: prior.TransactionID, CleanURLSHA256: cleanSHA,
			PriorBodySHA256: prior.BodySHA256, ExpectedBodySHA256: expectedBodySHA,
			Observers: make([]realCloudPurgeWatcherObserverSpec, 0, len(observers)),
		}
		for index, observer := range observers {
			observation := prior.Observations[index]
			if observation.ObserverID != observer.ID || observation.Role != "prime" && observation.Role != "cross-pop" ||
				index == 0 && observation.Role != "prime" || index > 0 && observation.Role != "cross-pop" ||
				observation.CacheStatus != "HIT" || observation.CacheAgeSeconds < 0 || observation.CacheMaxAge <= observation.CacheAgeSeconds ||
				observation.CleanURLSHA256 != cleanSHA || observation.BodySHA256 != prior.BodySHA256 || observation.ResponseObserved.IsZero() || now.Before(observation.ResponseObserved) {
				return spec, fmt.Errorf("%s purge watcher pre-purge observer %d is invalid", input.vendor, index)
			}
			freshUntil := observation.ResponseObserved.Add(time.Duration(observation.CacheMaxAge-observation.CacheAgeSeconds)*time.Second - realEdgeCacheFreshnessMargin)
			if !now.Before(freshUntil) {
				return spec, fmt.Errorf("%s purge watcher pre-purge TTL already expired", input.vendor)
			}
			if deadline.IsZero() || freshUntil.Before(deadline) {
				deadline = freshUntil
			}
			vendorSpec.Observers = append(vendorSpec.Observers, realCloudPurgeWatcherObserverSpec{
				ID: observer.ID, Role: observation.Role, FreshUntil: freshUntil.UTC().Format(time.RFC3339Nano),
			})
		}
		vendors = append(vendors, vendorSpec)
	}
	spec = realCloudPurgeWatcherSpec{
		Schema: realCloudPurgeWatcherSpecSchema, RunID: identity.RunID,
		ConfirmationSHA256: identity.ConfirmationSHA256, ConfigSHA256: identity.ConfigSHA256,
		AcceptanceBindingSHA256: bindingSHA, ResourceSHA256: resourceSHA,
		ObserverTopologySHA256: realCloudLowerSHA256(topology), WorkspaceSHA256: workspaceSHA,
		Generation: 5, ExpectedBodySHA256: expectedBodySHA,
		EntitlementSHA256: realEdgeEntitlementDigests(environment.EdgeProTokenA, environment.EdgeProTokenB),
		Nonce:             hex.EncodeToString(nonce), IssuedAt: now.Format(time.RFC3339Nano),
		EvidenceDeadline: deadline.UTC().Format(time.RFC3339Nano), Vendors: vendors,
	}
	key, err := realCloudPurgeWatcherMACKey(environment.EdgeProTokenA, environment.EdgeProTokenB)
	if err != nil {
		return realCloudPurgeWatcherSpec{}, err
	}
	spec.MACSHA256, err = realCloudPurgeWatcherSign(spec, key)
	if err != nil {
		return realCloudPurgeWatcherSpec{}, err
	}
	if err := validateRealCloudPurgeWatcherSpec(spec, key); err != nil {
		return realCloudPurgeWatcherSpec{}, err
	}
	return spec, nil
}

func validateRealCloudPurgeWatcherSpec(spec realCloudPurgeWatcherSpec, key []byte) error {
	if spec.Schema != realCloudPurgeWatcherSpecSchema || !validRealCloudRunID(spec.RunID) ||
		!validRealCloudLowerSHA256(spec.ConfirmationSHA256) || !validRealCloudLowerSHA256(spec.ConfigSHA256) ||
		!validRealCloudLowerSHA256(spec.AcceptanceBindingSHA256) || !validRealCloudLowerSHA256(spec.ResourceSHA256) ||
		!validRealCloudLowerSHA256(spec.ObserverTopologySHA256) || !validRealCloudLowerSHA256(spec.WorkspaceSHA256) ||
		spec.Generation != 5 || !validRealCloudLowerSHA256(spec.ExpectedBodySHA256) ||
		len(spec.Nonce) != 32 || len(spec.Vendors) != 2 {
		return errors.New("purge watcher spec identity is invalid")
	}
	if _, err := hex.DecodeString(spec.Nonce); err != nil {
		return errors.New("purge watcher nonce is invalid")
	}
	if err := validateRealEdgeEntitlementDigests(spec.EntitlementSHA256); err != nil {
		return err
	}
	issued, err := parseRealEdgeUTC(spec.IssuedAt)
	if err != nil {
		return errors.New("purge watcher issued time is invalid")
	}
	deadline, err := parseRealEdgeUTC(spec.EvidenceDeadline)
	if err != nil || !issued.Before(deadline) {
		return errors.New("purge watcher evidence deadline is invalid")
	}
	minimumFreshUntil := time.Time{}
	for index, vendor := range spec.Vendors {
		wantedVendor, wantedTarget := "cloudflare", "cf"
		if index == 1 {
			wantedVendor, wantedTarget = "edgeone", "cos"
		}
		if vendor.Vendor != wantedVendor || vendor.Target != wantedTarget || vendor.ParentGeneration != 4 ||
			!validRealEdgeTransactionID(vendor.ParentTransactionID) || !validRealCloudLowerSHA256(vendor.CleanURLSHA256) ||
			!validRealCloudLowerSHA256(vendor.PriorBodySHA256) || vendor.PriorBodySHA256 == vendor.ExpectedBodySHA256 ||
			vendor.ExpectedBodySHA256 != spec.ExpectedBodySHA256 || len(vendor.Observers) < 2 || len(vendor.Observers) > realEdgeMaxObservers {
			return errors.New("purge watcher vendor binding is invalid")
		}
		seen := make(map[string]struct{}, len(vendor.Observers))
		for observerIndex, observer := range vendor.Observers {
			freshUntil, timeErr := parseRealEdgeUTC(observer.FreshUntil)
			if !validRealEdgeIdentifier(observer.ID, 64) || observerIndex == 0 && observer.Role != "prime" || observerIndex > 0 && observer.Role != "cross-pop" ||
				timeErr != nil || freshUntil.Before(deadline) || issued.After(freshUntil) {
				return errors.New("purge watcher observer binding is invalid")
			}
			if _, duplicate := seen[observer.ID]; duplicate {
				return errors.New("purge watcher observer binding is duplicated")
			}
			seen[observer.ID] = struct{}{}
			if minimumFreshUntil.IsZero() || freshUntil.Before(minimumFreshUntil) {
				minimumFreshUntil = freshUntil
			}
		}
	}
	if !minimumFreshUntil.Equal(deadline) {
		return errors.New("purge watcher deadline is not the minimum observer freshness bound")
	}
	return realCloudPurgeWatcherVerifyMAC(spec, spec.MACSHA256, key)
}

func realCloudPurgeWatcherSpecSHA256(spec realCloudPurgeWatcherSpec) (string, error) {
	body, err := realCloudPurgeWatcherMarshalSigned(spec)
	if err != nil {
		return "", err
	}
	return realCloudLowerSHA256(body), nil
}

func loadRealCloudPurgeWatcherSpec(path string, key []byte) (realCloudPurgeWatcherSpec, []byte, error) {
	var spec realCloudPurgeWatcherSpec
	body, err := readRealCloudPurgeWatcherJSON(path, &spec)
	if err != nil {
		return spec, nil, err
	}
	if err := validateRealCloudPurgeWatcherSpec(spec, key); err != nil {
		return spec, nil, err
	}
	return spec, body, nil
}

func realCloudPurgeWatcherBindingEqual(left, right realCloudPurgeWatcherSpec) bool {
	left.Nonce, right.Nonce = "", ""
	left.IssuedAt, right.IssuedAt = "", ""
	left.MACSHA256, right.MACSHA256 = "", ""
	return left.Schema == right.Schema && left.RunID == right.RunID && left.ConfirmationSHA256 == right.ConfirmationSHA256 &&
		left.ConfigSHA256 == right.ConfigSHA256 && left.AcceptanceBindingSHA256 == right.AcceptanceBindingSHA256 &&
		left.ResourceSHA256 == right.ResourceSHA256 && left.ObserverTopologySHA256 == right.ObserverTopologySHA256 &&
		left.WorkspaceSHA256 == right.WorkspaceSHA256 && left.Generation == right.Generation &&
		left.ExpectedBodySHA256 == right.ExpectedBodySHA256 && slices.Equal(left.EntitlementSHA256, right.EntitlementSHA256) &&
		left.EvidenceDeadline == right.EvidenceDeadline && slices.EqualFunc(left.Vendors, right.Vendors, func(a, b realCloudPurgeWatcherVendorSpec) bool {
		return a.Vendor == b.Vendor && a.Target == b.Target && a.ParentGeneration == b.ParentGeneration &&
			a.ParentTransactionID == b.ParentTransactionID && a.CleanURLSHA256 == b.CleanURLSHA256 &&
			a.PriorBodySHA256 == b.PriorBodySHA256 && a.ExpectedBodySHA256 == b.ExpectedBodySHA256 && slices.Equal(a.Observers, b.Observers)
	})
}

func writeRealCloudPurgeWatcherArmed(paths realCloudPurgeWatcherPaths, spec realCloudPurgeWatcherSpec, key []byte) error {
	specSHA, err := realCloudPurgeWatcherSpecSHA256(spec)
	if err != nil {
		return err
	}
	record := realCloudPurgeWatcherArmed{
		Schema: realCloudPurgeWatcherArmedSchema, SpecSHA256: specSHA, RunID: spec.RunID,
		ResourceSHA256: spec.ResourceSHA256, Generation: spec.Generation, Nonce: spec.Nonce,
		EvidenceDeadline: spec.EvidenceDeadline,
	}
	record.MACSHA256, err = realCloudPurgeWatcherSign(record, key)
	if err != nil {
		return err
	}
	body, err := realCloudPurgeWatcherMarshalSigned(record)
	if err != nil {
		return err
	}
	return installRealCloudPurgeWatcherRecord(paths.armed, body)
}

func loadRealCloudPurgeWatcherArmed(paths realCloudPurgeWatcherPaths, spec realCloudPurgeWatcherSpec, key []byte) error {
	specSHA, err := realCloudPurgeWatcherSpecSHA256(spec)
	if err != nil {
		return err
	}
	load := func() error {
		var record realCloudPurgeWatcherArmed
		if _, err := readRealCloudPurgeWatcherJSON(paths.armed, &record); err != nil {
			return err
		}
		if record.Schema != realCloudPurgeWatcherArmedSchema || record.SpecSHA256 != specSHA || record.RunID != spec.RunID ||
			record.ResourceSHA256 != spec.ResourceSHA256 || record.Generation != spec.Generation || record.Nonce != spec.Nonce ||
			record.EvidenceDeadline != spec.EvidenceDeadline {
			return errors.New("purge watcher armed receipt does not match the exact run and spec")
		}
		return realCloudPurgeWatcherVerifyMAC(record, record.MACSHA256, key)
	}
	if err := load(); err != nil {
		return err
	}
	// A hardlink is visible before its writer's parent-directory fsync returns.
	// The reader establishes and verifies its own durability barrier before an
	// armed receipt is allowed to release the publication step.
	if err := realCloudPurgeWatcherSyncDirectory(paths.directory); err != nil {
		return err
	}
	return load()
}

func runRealCloudPurgeWatcher(
	ctx context.Context,
	paths realCloudPurgeWatcherPaths,
	spec realCloudPurgeWatcherSpec,
	key []byte,
	runtime realCloudPurgeWatcherRuntime,
) (resultErr error) {
	if runtime.clock.now == nil || runtime.clock.sleep == nil || runtime.validateResources == nil || runtime.loadPublication == nil || runtime.observe == nil {
		return errors.New("purge watcher runtime is incomplete")
	}
	if err := runtime.validateResources(); err != nil {
		return fmt.Errorf("resource-preflight: %w", err)
	}
	if err := validateRealCloudPurgeWatcherSpec(spec, key); err != nil {
		return fmt.Errorf("spec-validation: %w", err)
	}
	deadline, _ := parseRealEdgeUTC(spec.EvidenceDeadline)
	if !runtime.clock.now().Before(deadline) {
		return errors.New("expired: purge watcher was not armed inside the old-cache TTL")
	}
	lock, err := openRealCloudPurgeWatcherLock(paths.lock)
	if err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	lockHeld := false
	defer func() {
		resultErr = errors.Join(resultErr, closeRealCloudPurgeWatcherLock(lock, lockHeld))
	}()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return errRealCloudPurgeWatcherActive
		}
		return errors.New("lock: acquire purge watcher lock")
	}
	lockHeld = true
	if err := writeRealCloudPurgeWatcherArmed(paths, spec, key); err != nil {
		return fmt.Errorf("armed-persist: %w", err)
	}
	for _, vendorSpec := range spec.Vendors {
		evidencePath := paths.evidence[vendorSpec.Vendor]
		if _, statErr := os.Lstat(evidencePath); statErr == nil {
			record, err := loadRealCloudPurgeWatcherEvidence(evidencePath, spec, vendorSpec, key)
			if err != nil {
				return fmt.Errorf("existing-evidence: %w", err)
			}
			if _, completeErr := loadRealCloudPurgeWatcherComplete(paths.complete[vendorSpec.Vendor], evidencePath, spec, vendorSpec, record, key); completeErr == nil {
				continue
			} else if _, completeStatErr := os.Lstat(paths.complete[vendorSpec.Vendor]); completeStatErr == nil {
				return fmt.Errorf("existing-evidence-completion: %w", completeErr)
			} else if !errors.Is(completeStatErr, os.ErrNotExist) {
				return errors.New("existing-evidence-completion: completion path is unsafe")
			}
			if !runtime.clock.now().Before(deadline) {
				return fmt.Errorf("expired: %s evidence was durable but not completed inside the old-cache TTL", vendorSpec.Vendor)
			}
			if err := completeRealCloudPurgeWatcherEvidence(paths.complete[vendorSpec.Vendor], evidencePath, spec, vendorSpec, record, runtime.clock.now().UTC(), key); err != nil {
				return fmt.Errorf("evidence-completion: %s: %w", vendorSpec.Vendor, err)
			}
			continue
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return errors.New("existing-evidence: purge watcher evidence path is unsafe")
		}
		for {
			if !runtime.clock.now().Before(deadline) {
				return fmt.Errorf("expired: %s publication was not observed inside the old-cache TTL", vendorSpec.Vendor)
			}
			publication, loadErr := runtime.loadPublication(vendorSpec.Target, spec.Generation)
			if errors.Is(loadErr, errRealCloudPurgeWatcherPending) {
				if err := runtime.clock.sleep(ctx, realCloudPurgeWatcherPollInterval); err != nil {
					return err
				}
				continue
			}
			if loadErr != nil {
				return fmt.Errorf("publication: %s: %w", vendorSpec.Vendor, loadErr)
			}
			observedAt := runtime.clock.now().UTC()
			if observedAt.Before(publication.PurgeCompletedAt) {
				return fmt.Errorf("publication: %s purge completion moved backwards", vendorSpec.Vendor)
			}
			observations := make([]realEdgeMultiPoPObservation, 0, len(vendorSpec.Observers))
			for _, observerSpec := range vendorSpec.Observers {
				freshUntil, _ := parseRealEdgeUTC(observerSpec.FreshUntil)
				if !runtime.clock.now().Before(freshUntil) {
					return fmt.Errorf("expired: %s observer %s old-cache TTL elapsed before post-probe", vendorSpec.Vendor, observerSpec.ID)
				}
				if runtime.beforeNetwork != nil {
					runtime.beforeNetwork()
				}
				observation, observeErr := runtime.observe(ctx, vendorSpec, observerSpec, observedAt)
				if observeErr != nil {
					return fmt.Errorf("observation: %s/%s failed", vendorSpec.Vendor, observerSpec.ID)
				}
				if err := validateRealCloudPurgeWatcherObservation(vendorSpec, observerSpec, publication, observedAt, observation); err != nil {
					return fmt.Errorf("observation: %s/%s: %w", vendorSpec.Vendor, observerSpec.ID, err)
				}
				observations = append(observations, observation)
			}
			if err := validateRealCloudPurgeWatcherObservationSequence(vendorSpec, publication, observedAt, observations); err != nil {
				return fmt.Errorf("observation: %s sequence: %w", vendorSpec.Vendor, err)
			}
			if err := persistRealCloudPurgeWatcherEvidence(paths.evidence[vendorSpec.Vendor], spec, vendorSpec, publication, observedAt, observations, runtime.clock.now().UTC(), key); err != nil {
				return fmt.Errorf("evidence-persist: %s: %w", vendorSpec.Vendor, err)
			}
			record, err := loadRealCloudPurgeWatcherEvidence(paths.evidence[vendorSpec.Vendor], spec, vendorSpec, key)
			if err != nil {
				return fmt.Errorf("evidence-readback: %s: %w", vendorSpec.Vendor, err)
			}
			if !runtime.clock.now().Before(deadline) {
				return fmt.Errorf("expired: %s evidence missed durable completion inside the old-cache TTL", vendorSpec.Vendor)
			}
			if err := completeRealCloudPurgeWatcherEvidence(paths.complete[vendorSpec.Vendor], paths.evidence[vendorSpec.Vendor], spec, vendorSpec, record, runtime.clock.now().UTC(), key); err != nil {
				return fmt.Errorf("evidence-completion: %s: %w", vendorSpec.Vendor, err)
			}
			break
		}
	}
	return nil
}

func validateRealCloudPurgeWatcherObservationSequence(
	vendor realCloudPurgeWatcherVendorSpec,
	publication realCloudPurgeWatcherPublication,
	publicationObservedAt time.Time,
	observations []realEdgeMultiPoPObservation,
) error {
	if len(observations) != len(vendor.Observers) {
		return errors.New("post-probe observation count is incomplete")
	}
	seenRequests := make(map[string]struct{}, len(observations))
	primeObserved := time.Time{}
	for index, observation := range observations {
		if err := validateRealCloudPurgeWatcherObservation(vendor, vendor.Observers[index], publication, publicationObservedAt, observation); err != nil {
			return err
		}
		if _, duplicate := seenRequests[observation.RequestID]; duplicate {
			return errors.New("post-probe request ID was reused")
		}
		seenRequests[observation.RequestID] = struct{}{}
		if index == 0 {
			primeObserved = observation.ResponseObserved
		} else if observation.RequestStarted.Before(primeObserved) {
			return errors.New("cross-PoP post-probe started before the prime response completed")
		}
	}
	return nil
}

func validateRealCloudPurgeWatcherObservation(
	vendor realCloudPurgeWatcherVendorSpec,
	observer realCloudPurgeWatcherObserverSpec,
	publication realCloudPurgeWatcherPublication,
	publicationObservedAt time.Time,
	observation realEdgeMultiPoPObservation,
) error {
	freshUntil, err := parseRealEdgeUTC(observer.FreshUntil)
	if err != nil || publication.Target != vendor.Target || publication.Generation != 5 || !validRealEdgeTransactionID(publication.TransactionID) ||
		!validRealCloudLowerSHA256(publication.GenerationSHA256) || !validRealCloudLowerSHA256(publication.CheckpointSHA256) ||
		!validRealCloudLowerSHA256(publication.PurgeEvidenceSHA256) || publication.PurgeCompletedAt.IsZero() {
		return errors.New("publication identity is invalid")
	}
	if publication.GatedBodySHA256 != vendor.ExpectedBodySHA256 || observation.Vendor != vendor.Vendor || observation.ObserverID != observer.ID || observation.Role != observer.Role ||
		!validRealEdgeRequestID(observation.RequestID) || !validRealCloudSharedCacheStatus(observation.CacheStatus) ||
		observation.Role == "cross-pop" && observation.CacheStatus != "HIT" || observation.Transport != "https-bearer" ||
		observation.CleanURLSHA256 != vendor.CleanURLSHA256 || observation.BodySHA256 != vendor.ExpectedBodySHA256 ||
		observation.CacheAgeSeconds < 0 || observation.CacheMaxAge <= observation.CacheAgeSeconds ||
		observation.RequestStarted.Before(publicationObservedAt) || observation.ResponseObserved.Before(observation.RequestStarted) ||
		!observation.ResponseObserved.Before(freshUntil) {
		return errors.New("post-probe identity, cache, body, clean URL, or time is outside the watcher contract")
	}
	if vendor.Vendor == "cloudflare" && (len(observation.CloudflareColo) != 3 || observation.CloudflareColo != strings.ToUpper(observation.CloudflareColo)) {
		return errors.New("Cloudflare watcher observation has no valid colo")
	}
	if vendor.Vendor == "edgeone" && observation.CloudflareColo != "" {
		return errors.New("EdgeOne watcher observation claimed a response-derived PoP")
	}
	return nil
}

func persistRealCloudPurgeWatcherEvidence(
	path string,
	spec realCloudPurgeWatcherSpec,
	vendor realCloudPurgeWatcherVendorSpec,
	publication realCloudPurgeWatcherPublication,
	publicationObservedAt time.Time,
	observations []realEdgeMultiPoPObservation,
	completedAt time.Time,
	key []byte,
) error {
	specSHA, err := realCloudPurgeWatcherSpecSHA256(spec)
	if err != nil {
		return err
	}
	record := realCloudPurgeWatcherEvidence{
		Schema: realCloudPurgeWatcherEvidenceSchema, SpecSHA256: specSHA,
		RunID: spec.RunID, ResourceSHA256: spec.ResourceSHA256,
		Vendor: vendor.Vendor, Target: vendor.Target, Generation: publication.Generation,
		TransactionID: publication.TransactionID, GenerationSHA256: publication.GenerationSHA256,
		CheckpointSHA256: publication.CheckpointSHA256, PurgeEvidenceSHA256: publication.PurgeEvidenceSHA256,
		PurgeCompletedAt:      publication.PurgeCompletedAt.UTC().Format(time.RFC3339Nano),
		PublicationObservedAt: publicationObservedAt.UTC().Format(time.RFC3339Nano),
		CleanURLSHA256:        vendor.CleanURLSHA256, BodySHA256: vendor.ExpectedBodySHA256,
		Observations: encodeRealEdgeArtifactObservations(observations),
		CompletedAt:  completedAt.UTC().Format(time.RFC3339Nano),
	}
	record.MACSHA256, err = realCloudPurgeWatcherSign(record, key)
	if err != nil {
		return err
	}
	body, err := realCloudPurgeWatcherMarshalSigned(record)
	if err != nil {
		return err
	}
	return installRealCloudPurgeWatcherRecord(path, body)
}

func loadRealCloudPurgeWatcherEvidence(
	path string,
	spec realCloudPurgeWatcherSpec,
	vendor realCloudPurgeWatcherVendorSpec,
	key []byte,
) (realCloudPurgeWatcherEvidence, error) {
	var record realCloudPurgeWatcherEvidence
	if _, err := readRealCloudPurgeWatcherJSON(path, &record); err != nil {
		return record, err
	}
	specSHA, err := realCloudPurgeWatcherSpecSHA256(spec)
	if err != nil {
		return record, err
	}
	if record.Schema != realCloudPurgeWatcherEvidenceSchema || record.SpecSHA256 != specSHA || record.RunID != spec.RunID ||
		record.ResourceSHA256 != spec.ResourceSHA256 || record.Vendor != vendor.Vendor || record.Target != vendor.Target ||
		record.Generation != spec.Generation || !validRealEdgeTransactionID(record.TransactionID) ||
		!validRealCloudLowerSHA256(record.GenerationSHA256) || !validRealCloudLowerSHA256(record.CheckpointSHA256) ||
		!validRealCloudLowerSHA256(record.PurgeEvidenceSHA256) || record.CleanURLSHA256 != vendor.CleanURLSHA256 ||
		record.BodySHA256 != vendor.ExpectedBodySHA256 || len(record.Observations) != len(vendor.Observers) {
		return record, errors.New("purge watcher evidence does not match the exact run, resource, generation, and body")
	}
	purgeCompleted, purgeErr := parseRealEdgeUTC(record.PurgeCompletedAt)
	publicationObserved, publicationErr := parseRealEdgeUTC(record.PublicationObservedAt)
	completed, completedErr := parseRealEdgeUTC(record.CompletedAt)
	if purgeErr != nil || publicationErr != nil || completedErr != nil || publicationObserved.Before(purgeCompleted) || completed.Before(publicationObserved) {
		return record, errors.New("purge watcher evidence time chain is invalid")
	}
	decoded, err := decodeRealEdgeArtifactObservations(vendor.Vendor, record.Observations)
	if err != nil {
		return record, err
	}
	publication := realCloudPurgeWatcherPublication{
		Target: record.Target, Generation: record.Generation, TransactionID: record.TransactionID,
		GatedBodySHA256:  vendor.ExpectedBodySHA256,
		GenerationSHA256: record.GenerationSHA256, CheckpointSHA256: record.CheckpointSHA256,
		PurgeEvidenceSHA256: record.PurgeEvidenceSHA256, PurgeCompletedAt: purgeCompleted,
	}
	if err := validateRealCloudPurgeWatcherObservationSequence(vendor, publication, publicationObserved, decoded); err != nil {
		return record, err
	}
	if err := realCloudPurgeWatcherVerifyMAC(record, record.MACSHA256, key); err != nil {
		return record, err
	}
	return record, nil
}

func completeRealCloudPurgeWatcherEvidence(
	completePath, evidencePath string,
	spec realCloudPurgeWatcherSpec,
	vendor realCloudPurgeWatcherVendorSpec,
	evidence realCloudPurgeWatcherEvidence,
	durableAt time.Time,
	key []byte,
) error {
	if durableAt.IsZero() || durableAt.Location() != time.UTC {
		return errors.New("purge watcher durable completion time is invalid")
	}
	deadline, _ := parseRealEdgeUTC(spec.EvidenceDeadline)
	if !durableAt.Before(deadline) {
		return errors.New("purge watcher evidence completion missed the old-cache TTL")
	}
	evidenceBody, err := readRealCloudPurgeWatcherJSON(evidencePath, &realCloudPurgeWatcherEvidence{})
	if err != nil {
		return err
	}
	specSHA, err := realCloudPurgeWatcherSpecSHA256(spec)
	if err != nil {
		return err
	}
	record := realCloudPurgeWatcherComplete{
		Schema: realCloudPurgeWatcherCompleteSchema, SpecSHA256: specSHA,
		RunID: spec.RunID, ResourceSHA256: spec.ResourceSHA256,
		Vendor: vendor.Vendor, Generation: spec.Generation, TransactionID: evidence.TransactionID,
		EvidenceSHA256: realCloudLowerSHA256(evidenceBody), DurableAt: durableAt.Format(time.RFC3339Nano),
	}
	record.MACSHA256, err = realCloudPurgeWatcherSign(record, key)
	if err != nil {
		return err
	}
	body, err := realCloudPurgeWatcherMarshalSigned(record)
	if err != nil {
		return err
	}
	return installRealCloudPurgeWatcherRecord(completePath, body)
}

func loadRealCloudPurgeWatcherComplete(
	completePath, evidencePath string,
	spec realCloudPurgeWatcherSpec,
	vendor realCloudPurgeWatcherVendorSpec,
	evidence realCloudPurgeWatcherEvidence,
	key []byte,
) (realCloudPurgeWatcherComplete, error) {
	var record realCloudPurgeWatcherComplete
	if _, err := readRealCloudPurgeWatcherJSON(completePath, &record); err != nil {
		return record, err
	}
	evidenceBody, err := readRealCloudPurgeWatcherJSON(evidencePath, &realCloudPurgeWatcherEvidence{})
	if err != nil {
		return record, err
	}
	specSHA, err := realCloudPurgeWatcherSpecSHA256(spec)
	if err != nil {
		return record, err
	}
	durableAt, timeErr := parseRealEdgeUTC(record.DurableAt)
	evidenceCompletedAt, evidenceTimeErr := parseRealEdgeUTC(evidence.CompletedAt)
	deadline, deadlineErr := parseRealEdgeUTC(spec.EvidenceDeadline)
	if record.Schema != realCloudPurgeWatcherCompleteSchema || record.SpecSHA256 != specSHA || record.RunID != spec.RunID ||
		record.ResourceSHA256 != spec.ResourceSHA256 || record.Vendor != vendor.Vendor || record.Generation != spec.Generation ||
		record.TransactionID != evidence.TransactionID || record.EvidenceSHA256 != realCloudLowerSHA256(evidenceBody) ||
		timeErr != nil || evidenceTimeErr != nil || deadlineErr != nil || durableAt.Before(evidenceCompletedAt) || !durableAt.Before(deadline) {
		return record, errors.New("purge watcher completion does not bind timely durable evidence for this run")
	}
	if err := realCloudPurgeWatcherVerifyMAC(record, record.MACSHA256, key); err != nil {
		return record, err
	}
	return record, nil
}

func loadRealCloudPurgeWatcherEvidenceClosure(
	paths realCloudPurgeWatcherPaths,
	spec realCloudPurgeWatcherSpec,
	vendor realCloudPurgeWatcherVendorSpec,
	key []byte,
) (realCloudPurgeWatcherEvidence, error) {
	evidence, err := loadRealCloudPurgeWatcherEvidence(paths.evidence[vendor.Vendor], spec, vendor, key)
	if err != nil {
		return evidence, err
	}
	if _, err := loadRealCloudPurgeWatcherComplete(paths.complete[vendor.Vendor], paths.evidence[vendor.Vendor], spec, vendor, evidence, key); err != nil {
		return evidence, err
	}
	// Close the visibility-before-fsync window from a concurrent watcher, then
	// reload both immutable records from their exact inodes.
	if err := realCloudPurgeWatcherSyncDirectory(paths.directory); err != nil {
		return evidence, err
	}
	evidence, err = loadRealCloudPurgeWatcherEvidence(paths.evidence[vendor.Vendor], spec, vendor, key)
	if err != nil {
		return evidence, err
	}
	if _, err := loadRealCloudPurgeWatcherComplete(paths.complete[vendor.Vendor], paths.evidence[vendor.Vendor], spec, vendor, evidence, key); err != nil {
		return evidence, err
	}
	return evidence, nil
}

func realCloudPurgeWatcherLockHeld(paths realCloudPurgeWatcherPaths) (held bool, resultErr error) {
	lock, err := openRealCloudPurgeWatcherLock(paths.lock)
	if err != nil {
		return false, err
	}
	lockHeld := false
	defer func() {
		resultErr = errors.Join(resultErr, closeRealCloudPurgeWatcherLock(lock, lockHeld))
	}()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return true, nil
		}
		return false, errors.New("inspect purge watcher liveness lock")
	}
	lockHeld = true
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		return false, errors.New("release purge watcher liveness probe")
	}
	lockHeld = false
	return false, nil
}

func closeRealCloudPurgeWatcherLock(lock *os.File, held bool) error {
	if lock == nil {
		return nil
	}
	var unlockErr error
	if held {
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
			unlockErr = fmt.Errorf("release purge watcher lock: %w", err)
		}
	}
	var closeErr error
	if err := lock.Close(); err != nil {
		closeErr = fmt.Errorf("close purge watcher lock: %w", err)
	}
	return errors.Join(unlockErr, closeErr)
}

func openRealCloudPurgeWatcherLock(path string) (*os.File, error) {
	for attempts := 0; attempts < 2; attempts++ {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
			if createErr == nil {
				if syncErr := syncRealCloudDirectoryError(filepath.Dir(path)); syncErr != nil {
					return nil, errors.Join(syncErr, closeRealCloudPurgeWatcherLock(file, false))
				}
				return file, nil
			}
			if errors.Is(createErr, fs.ErrExist) {
				continue
			}
			return nil, errors.New("create purge watcher liveness lock")
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("purge watcher liveness lock is unsafe")
		}
		file, openErr := os.OpenFile(path, os.O_RDWR, 0)
		if openErr != nil {
			return nil, errors.New("open purge watcher liveness lock")
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil || !os.SameFile(info, openedInfo) {
			return nil, errors.Join(errors.New("purge watcher liveness lock identity changed"), closeRealCloudPurgeWatcherLock(file, false))
		}
		return file, nil
	}
	return nil, errors.New("purge watcher liveness lock raced with another creator")
}

func defaultRealCloudPurgeWatcherClock() realCloudPurgeWatcherClock {
	return realCloudPurgeWatcherClock{
		now: func() time.Time { return time.Now().UTC() },
		sleep: func(ctx context.Context, duration time.Duration) error {
			timer := time.NewTimer(duration)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	}
}

func loadRealCloudPurgeWatcherPublication(root, target string, generation uint64, environment realCloudEnvironment) (realCloudPurgeWatcherPublication, error) {
	wantedTarget := publish.TargetCloudflare
	wantedZone := environment.CFZoneID
	if target == "cos" {
		wantedTarget = publish.TargetTencent
		wantedZone = environment.EdgeOneZoneID
	} else if target != "cf" {
		return realCloudPurgeWatcherPublication{}, errors.New("unsupported purge watcher target")
	}
	directory := filepath.Join(root, config.StateDirectory, "state", "remotes", target)
	read := func(name string) ([]byte, error) {
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, errRealCloudPurgeWatcherPending
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4<<20 {
			return nil, errors.New("canonical purge watcher publication file is unsafe")
		}
		return os.ReadFile(path)
	}
	generationBody, err := read("generation.json")
	if err != nil {
		return realCloudPurgeWatcherPublication{}, err
	}
	checkpointBody, err := read("checkpoint.json")
	if err != nil {
		return realCloudPurgeWatcherPublication{}, err
	}
	planBody, err := read("plan.json")
	if err != nil {
		return realCloudPurgeWatcherPublication{}, err
	}
	targetGeneration, err := publish.DecodeTargetGeneration(generationBody)
	if err != nil {
		return realCloudPurgeWatcherPublication{}, errors.New("decode purge watcher generation")
	}
	checkpoint, err := publish.DecodeCheckpoint(checkpointBody)
	if err != nil {
		return realCloudPurgeWatcherPublication{}, errors.New("decode purge watcher checkpoint")
	}
	plan, err := publish.DecodePlan(planBody)
	if err != nil {
		return realCloudPurgeWatcherPublication{}, errors.New("decode purge watcher plan")
	}
	if checkpoint.Generation < generation || checkpoint.Generation == generation && checkpoint.Phase != publish.PhaseCheckpointCommitted {
		return realCloudPurgeWatcherPublication{}, errRealCloudPurgeWatcherPending
	}
	if checkpoint.Generation != generation || targetGeneration.Generation != generation || checkpoint.Target != wantedTarget || targetGeneration.Target != wantedTarget ||
		checkpoint.IntentView != "stable" || targetGeneration.IntentView != "stable" {
		return realCloudPurgeWatcherPublication{}, errors.New("purge watcher publication advanced past or conflicts with generation five")
	}
	gatedBodySHA := ""
	for _, object := range plan.Objects {
		if object.RemoteKey == realCloudGatedAssetPath && object.SHA256 != "" {
			gatedBodySHA = object.SHA256
			break
		}
	}
	if !validRealCloudLowerSHA256(gatedBodySHA) {
		return realCloudPurgeWatcherPublication{}, errors.New("purge watcher plan lacks the gated mutable object")
	}
	purgeName := filepath.Join("purges", fmt.Sprintf("%020d-%s.json", generation, checkpoint.TransactionID))
	purgeBody, err := read(purgeName)
	if err != nil {
		return realCloudPurgeWatcherPublication{}, err
	}
	purgeEvidence, err := publish.DecodePurgeEvidence(purgeBody)
	if err != nil {
		return realCloudPurgeWatcherPublication{}, errors.New("decode purge watcher purge evidence")
	}
	publication := realCloudPublication{
		generation: targetGeneration, checkpoint: checkpoint, plan: plan, purgeEvidence: purgeEvidence,
		generationBody: generationBody, checkpointBody: checkpointBody, planBody: planBody, purgeEvidenceBody: purgeBody,
	}
	if err := validateRealCloudPurgeEvidenceBinding(target, wantedZone, publication); err != nil {
		return realCloudPurgeWatcherPublication{}, err
	}
	purgeCompleted := time.Time{}
	latestFull := -1
	for index, attempt := range purgeEvidence.Attempts {
		if attempt.Purpose == publish.PurgeAttemptFull {
			latestFull = index
		}
	}
	if latestFull >= 0 {
		for _, receipt := range purgeEvidence.Attempts[latestFull].Batches {
			completed, parseErr := parseRealEdgeUTC(receipt.CompletedObservedAt)
			if parseErr != nil {
				return realCloudPurgeWatcherPublication{}, errors.New("purge watcher completion receipt time is invalid")
			}
			if completed.After(purgeCompleted) {
				purgeCompleted = completed
			}
		}
	}
	if purgeCompleted.IsZero() {
		return realCloudPurgeWatcherPublication{}, errors.New("purge watcher publication has no completed full purge receipt")
	}
	return realCloudPurgeWatcherPublication{
		Target: target, Generation: generation, TransactionID: checkpoint.TransactionID,
		GatedBodySHA256:  gatedBodySHA,
		GenerationSHA256: realCloudLowerSHA256(generationBody), CheckpointSHA256: realCloudLowerSHA256(checkpointBody),
		PurgeEvidenceSHA256: realCloudLowerSHA256(purgeBody), PurgeCompletedAt: purgeCompleted,
	}, nil
}

func newOptInDetachedRealCloudPurgeWatcherRuntime(root string, environment realCloudEnvironment, wantedBody []byte, secretFragments []string) (realCloudPurgeWatcherRuntime, error) {
	if len(wantedBody) == 0 {
		return realCloudPurgeWatcherRuntime{}, errors.New("purge watcher expected body is empty")
	}
	observers, err := loadRealEdgeObservers(os.Getenv)
	if err != nil {
		return realCloudPurgeWatcherRuntime{}, err
	}
	byID := make(map[string]realEdgeObserver, len(observers))
	for _, observer := range observers {
		byID[observer.ID] = observer
	}
	allSecrets := append([]string(nil), secretFragments...)
	allSecrets = append(allSecrets, environment.EdgeProTokenA, environment.EdgeProTokenB)
	for _, observer := range observers {
		allSecrets = append(allSecrets, realEdgeObserverSecretFragments(observer)...)
	}
	return realCloudPurgeWatcherRuntime{
		clock: defaultRealCloudPurgeWatcherClock(),
		validateResources: func() error {
			return validateRealCloudDedicatedTestResources(environment, os.Getenv)
		},
		loadPublication: func(target string, generation uint64) (realCloudPurgeWatcherPublication, error) {
			return loadRealCloudPurgeWatcherPublication(root, target, generation, environment)
		},
		observe: func(ctx context.Context, vendor realCloudPurgeWatcherVendorSpec, wanted realCloudPurgeWatcherObserverSpec, committedAt time.Time) (realEdgeMultiPoPObservation, error) {
			observer, exists := byID[wanted.ID]
			if !exists {
				return realEdgeMultiPoPObservation{}, errors.New("observer is absent")
			}
			baseURL, token := environment.CFCDNBase, environment.EdgeProTokenB
			if vendor.Vendor == "edgeone" {
				baseURL = environment.COSCDNBase
			}
			if wanted.Role == "prime" {
				token = environment.EdgeProTokenA
			}
			return requestRealEdgeMultiPoP(ctx, observer, vendor.Vendor, baseURL, token, wanted.Role,
				wantedBody, allSecrets)
		},
	}, nil
}

func startOptInDetachedRealCloudPurgeWatcher(root string, spec realCloudPurgeWatcherSpec) error {
	specSHA, err := realCloudPurgeWatcherSpecSHA256(spec)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return errors.New("locate purge watcher helper executable")
	}
	command := exec.Command(executable, "-test.run=^TestRealCloudPurgeWatcherProcess$", "-test.count=1")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	command.Env = append(os.Environ(),
		realCloudPurgeWatcherHelperEnv+"=1",
		realCloudPurgeWatcherRootEnv+"="+root,
		realCloudPurgeWatcherSpecSHAEnv+"="+specSHA,
	)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return errors.New("start independent purge watcher process")
	}
	return command.Process.Release()
}

func TestRealCloudPurgeWatcherProcess(t *testing.T) {
	if os.Getenv(realCloudPurgeWatcherHelperEnv) != "1" {
		t.Skip("internal real-cloud purge watcher helper")
	}
	if err := validateRealCloudPurgeWatcherDetachedProcess(); err != nil {
		t.Fatal(err)
	}
	root := strings.TrimSpace(os.Getenv(realCloudPurgeWatcherRootEnv))
	expectedSpecSHA := strings.TrimSpace(os.Getenv(realCloudPurgeWatcherSpecSHAEnv))
	if !validRealCloudLowerSHA256(expectedSpecSHA) {
		t.Fatal("purge watcher helper spec digest is invalid")
	}
	environment, err := realCloudEnvironmentFromLookup(os.Getenv)
	if err != nil {
		t.Fatal("purge watcher helper environment is incomplete")
	}
	// This exact administrator-pinned resource validation is deliberately
	// before observer loading or any HTTP client/request construction. Only an
	// exact reviewed non-production registry entry can reach a network path.
	if err := validateRealCloudDedicatedTestResources(environment, os.Getenv); err != nil {
		t.Fatal("purge watcher helper rejected non-dedicated resources")
	}
	paths, err := realCloudPurgeWatcherPathsFor(root, 5)
	if err != nil {
		t.Fatal(err)
	}
	key, err := realCloudPurgeWatcherMACKey(environment.EdgeProTokenA, environment.EdgeProTokenB)
	if err != nil {
		t.Fatal(err)
	}
	spec, body, err := loadRealCloudPurgeWatcherSpec(paths.spec, key)
	if err != nil || realCloudLowerSHA256(body) != expectedSpecSHA {
		t.Fatal("purge watcher helper spec differs from the parent-bound digest")
	}
	if err := validateRealCloudPurgeWatcherRuntimeBinding(root, environment, spec, os.Getenv); err != nil {
		t.Fatal(err)
	}
	wantedBody, err := readRealCloudPurgeWatcherPrivateFile(paths.body, realEdgeResponseLimit)
	if err != nil || realCloudLowerSHA256(wantedBody) != spec.ExpectedBodySHA256 {
		t.Fatal("purge watcher expected body is absent or changed")
	}
	secretFragments := loadRealCloudSecretFragments(t)
	runtime, err := newOptInDetachedRealCloudPurgeWatcherRuntime(root, environment, wantedBody, secretFragments)
	if err != nil {
		t.Fatal(err)
	}
	err = runRealCloudPurgeWatcher(t.Context(), paths, spec, key, runtime)
	if errors.Is(err, errRealCloudPurgeWatcherActive) {
		return
	}
	if err != nil {
		t.Fatal("independent purge watcher failed closed")
	}
}

func realCloudPurgeWatcherRandomNonce() ([]byte, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("generate purge watcher nonce")
	}
	return nonce, nil
}

func ensureRealCloudPurgeWatcherBody(path string, wanted []byte) error {
	if len(wanted) == 0 || len(wanted) > realEdgeResponseLimit {
		return errors.New("purge watcher expected body is empty or oversized")
	}
	installed, err := installRealCloudPrivateFileExclusiveWithPattern(path, wanted, ".sow-purge-watcher-body-*")
	if err != nil {
		return err
	}
	if installed {
		return realCloudPurgeWatcherSyncDirectory(filepath.Dir(path))
	}
	existing, err := readRealCloudPurgeWatcherPrivateFile(path, int64(len(wanted)))
	if err != nil || !bytes.Equal(existing, wanted) {
		return errors.New("purge watcher expected body conflicts with the durable run")
	}
	return realCloudPurgeWatcherSyncDirectory(filepath.Dir(path))
}

func (program *realCloudAcceptanceProgram) prepareGenerationFivePurgeWatcher() (realCloudPurgeWatcherPaths, realCloudPurgeWatcherSpec, []byte, error) {
	if err := validateRealCloudDedicatedTestResources(program.environment, os.Getenv); err != nil {
		return realCloudPurgeWatcherPaths{}, realCloudPurgeWatcherSpec{}, nil, err
	}
	prePurge := program.ledger.Snapshot().Facts.PrePurge
	if len(prePurge) != 2 {
		return realCloudPurgeWatcherPaths{}, realCloudPurgeWatcherSpec{}, nil, errors.New("purge watcher requires the durable generation-four pre-purge closure")
	}
	paths, err := realCloudPurgeWatcherPathsFor(program.root, 5)
	if err != nil {
		return paths, realCloudPurgeWatcherSpec{}, nil, err
	}
	key, err := realCloudPurgeWatcherMACKey(program.environment.EdgeProTokenA, program.environment.EdgeProTokenB)
	if err != nil {
		return paths, realCloudPurgeWatcherSpec{}, nil, err
	}
	if err := ensureRealCloudPurgeWatcherBody(paths.body, program.gatedBodies[1]); err != nil {
		return paths, realCloudPurgeWatcherSpec{}, nil, err
	}
	var spec realCloudPurgeWatcherSpec
	if _, statErr := os.Lstat(paths.spec); statErr == nil {
		persisted, _, loadErr := loadRealCloudPurgeWatcherSpec(paths.spec, key)
		if loadErr != nil {
			return paths, spec, nil, loadErr
		}
		nonce, decodeErr := hex.DecodeString(persisted.Nonce)
		issuedAt, timeErr := parseRealEdgeUTC(persisted.IssuedAt)
		if decodeErr != nil || timeErr != nil {
			return paths, spec, nil, errors.New("persisted purge watcher nonce or issued time is invalid")
		}
		candidate, buildErr := buildRealCloudPurgeWatcherSpec(program.root, program.environment, program.identity,
			program.ledger.Snapshot().Binding, prePurge, program.gatedBodies[1], issuedAt, nonce)
		if buildErr != nil || !realCloudPurgeWatcherBindingEqual(candidate, persisted) {
			return paths, spec, nil, errors.New("persisted purge watcher spec conflicts with this run, resource, observer topology, or expected body")
		}
		spec = persisted
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return paths, spec, nil, errors.New("inspect purge watcher spec")
	} else {
		nonce, nonceErr := realCloudPurgeWatcherRandomNonce()
		if nonceErr != nil {
			return paths, spec, nil, nonceErr
		}
		spec, err = buildRealCloudPurgeWatcherSpec(program.root, program.environment, program.identity,
			program.ledger.Snapshot().Binding, prePurge, program.gatedBodies[1], time.Now().UTC(), nonce)
		if err != nil {
			return paths, spec, nil, err
		}
		body, marshalErr := realCloudPurgeWatcherMarshalSigned(spec)
		if marshalErr != nil {
			return paths, spec, nil, marshalErr
		}
		if err := installRealCloudPurgeWatcherRecord(paths.spec, body); err != nil {
			return paths, spec, nil, err
		}
	}
	return paths, spec, key, nil
}

// validatePersistedGenerationFivePurgeWatcherClosure is the no-network
// recovery gate used once a derived generation-five active stage already
// exists. It must not recreate, re-arm, or re-probe missing evidence: recovery
// accepts that stage only while the original signed spec, armed receipt, body,
// and both vendor evidence/completion pairs remain exact and current-bound.
func (program *realCloudAcceptanceProgram) validatePersistedGenerationFivePurgeWatcherClosure() error {
	if err := validateRealCloudDedicatedTestResources(program.environment, os.Getenv); err != nil {
		return err
	}
	base := filepath.Join(program.root, realCloudPurgeWatcherDirectoryName)
	directory := filepath.Join(base, fmt.Sprintf("generation-%020d", 5))
	for _, path := range []string{base, directory} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.New("persisted purge watcher directory closure is absent or unsafe")
		}
	}
	paths, err := realCloudPurgeWatcherPathsFor(program.root, 5)
	if err != nil {
		return err
	}
	key, err := realCloudPurgeWatcherMACKey(program.environment.EdgeProTokenA, program.environment.EdgeProTokenB)
	if err != nil {
		return err
	}
	spec, _, err := loadRealCloudPurgeWatcherSpec(paths.spec, key)
	if err != nil {
		return err
	}
	if err := validateRealCloudPurgeWatcherRuntimeBinding(program.root, program.environment, spec, os.Getenv); err != nil {
		return err
	}
	prePurge := program.ledger.Snapshot().Facts.PrePurge
	nonce, nonceErr := hex.DecodeString(spec.Nonce)
	issuedAt, timeErr := parseRealEdgeUTC(spec.IssuedAt)
	if len(prePurge) != 2 || nonceErr != nil || timeErr != nil {
		return errors.New("persisted purge watcher spec has no exact ledger pre-purge binding")
	}
	candidate, err := buildRealCloudPurgeWatcherSpec(program.root, program.environment, program.identity,
		program.ledger.Snapshot().Binding, prePurge, program.gatedBodies[1], issuedAt, nonce)
	if err != nil || !realCloudPurgeWatcherBindingEqual(candidate, spec) {
		return errors.New("persisted purge watcher spec differs from the current run and pre-purge binding")
	}
	wantedBody, err := readRealCloudPurgeWatcherPrivateFile(paths.body, realEdgeResponseLimit)
	if err != nil || !bytes.Equal(wantedBody, program.gatedBodies[1]) || realCloudLowerSHA256(wantedBody) != spec.ExpectedBodySHA256 {
		return errors.New("persisted purge watcher body differs from the generation-five run body")
	}
	if err := loadRealCloudPurgeWatcherArmed(paths, spec, key); err != nil {
		return err
	}
	complete, err := realCloudPurgeWatcherAllVendorClosuresComplete(paths, spec, key)
	if err != nil {
		return err
	}
	if !complete {
		return errors.New("persisted purge watcher vendor evidence closure is incomplete")
	}
	return nil
}

func realCloudPurgeWatcherAllVendorClosuresComplete(
	paths realCloudPurgeWatcherPaths,
	spec realCloudPurgeWatcherSpec,
	key []byte,
) (bool, error) {
	complete := true
	for _, vendor := range spec.Vendors {
		if _, statErr := os.Lstat(paths.evidence[vendor.Vendor]); errors.Is(statErr, os.ErrNotExist) {
			complete = false
			if _, completeErr := os.Lstat(paths.complete[vendor.Vendor]); completeErr == nil {
				return false, fmt.Errorf("%s has completion without evidence", vendor.Vendor)
			} else if !errors.Is(completeErr, os.ErrNotExist) {
				return false, fmt.Errorf("inspect %s orphan completion: %w", vendor.Vendor, completeErr)
			}
			continue
		} else if statErr != nil {
			return false, fmt.Errorf("inspect %s evidence: %w", vendor.Vendor, statErr)
		}
		if _, evidenceErr := loadRealCloudPurgeWatcherEvidence(paths.evidence[vendor.Vendor], spec, vendor, key); evidenceErr != nil {
			return false, fmt.Errorf("%s evidence was changed: %w", vendor.Vendor, evidenceErr)
		}
		if _, statErr := os.Lstat(paths.complete[vendor.Vendor]); errors.Is(statErr, os.ErrNotExist) {
			complete = false
			continue
		} else if statErr != nil {
			return false, fmt.Errorf("inspect %s completion: %w", vendor.Vendor, statErr)
		}
		if _, evidenceErr := loadRealCloudPurgeWatcherEvidenceClosure(paths, spec, vendor, key); evidenceErr != nil {
			return false, fmt.Errorf("%s completion was changed: %w", vendor.Vendor, evidenceErr)
		}
	}
	return complete, nil
}

func (program *realCloudAcceptanceProgram) armGenerationFivePurgeWatcher() {
	program.t.Helper()
	paths, spec, key, err := program.prepareGenerationFivePurgeWatcher()
	if err != nil {
		program.t.Fatalf("prepare generation-five independent purge watcher: %v", err)
	}
	complete, err := realCloudPurgeWatcherAllVendorClosuresComplete(paths, spec, key)
	if err != nil {
		program.t.Fatalf("inspect generation-five purge watcher closure: %v", err)
	}
	if !complete {
		deadline, _ := parseRealEdgeUTC(spec.EvidenceDeadline)
		if !time.Now().UTC().Before(deadline) {
			program.t.Fatal("generation-five purge watcher evidence is missing after the old-cache TTL")
		}
		if err := startOptInDetachedRealCloudPurgeWatcher(program.root, spec); err != nil {
			program.t.Fatalf("start generation-five independent purge watcher: %v", err)
		}
	} else {
		if err := loadRealCloudPurgeWatcherArmed(paths, spec, key); err != nil {
			program.t.Fatalf("completed generation-five purge watcher has no exact armed receipt: %v", err)
		}
		return
	}
	waitUntil := time.Now().UTC().Add(15 * time.Second)
	deadline, _ := parseRealEdgeUTC(spec.EvidenceDeadline)
	if deadline.Before(waitUntil) {
		waitUntil = deadline
	}
	for {
		// A ready publication can let the helper finish and release its lock
		// before this parent performs its first liveness probe. Exact durable
		// closure is success; a live lock is required only while work remains.
		complete, closureErr := realCloudPurgeWatcherAllVendorClosuresComplete(paths, spec, key)
		if closureErr != nil {
			program.t.Fatalf("inspect generation-five purge watcher closure after spawn: %v", closureErr)
		}
		if complete {
			if err := loadRealCloudPurgeWatcherArmed(paths, spec, key); err != nil {
				program.t.Fatalf("completed generation-five purge watcher has no exact armed receipt: %v", err)
			}
			return
		}
		if err := loadRealCloudPurgeWatcherArmed(paths, spec, key); err == nil {
			held, lockErr := realCloudPurgeWatcherLockHeld(paths)
			if lockErr != nil {
				program.t.Fatalf("inspect generation-five purge watcher liveness: %v", lockErr)
			}
			if held {
				return
			}
		}
		if !time.Now().UTC().Before(waitUntil) {
			program.t.Fatal("generation-five purge watcher did not durably arm before publication")
		}
		select {
		case <-program.t.Context().Done():
			program.t.Fatal("generation-five purge watcher arming was interrupted")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (program *realCloudAcceptanceProgram) consumeGenerationFivePurgeWatcher() realEdgeMultiPoPStageEvidence {
	program.t.Helper()
	// The watcher can be killed after linking an evidence record but before
	// linking its durable completion seal, or after one vendor completes while
	// the other is still pending. Re-arm on entry so recovery of the ledger's
	// edge-stage step actively resumes that exact spec/evidence closure instead
	// of merely waiting for a process that may no longer exist.
	program.armGenerationFivePurgeWatcher()
	paths, spec, key, err := program.prepareGenerationFivePurgeWatcher()
	if err != nil {
		program.t.Fatalf("load generation-five purge watcher: %v", err)
	}
	if err := loadRealCloudPurgeWatcherArmed(paths, spec, key); err != nil {
		program.t.Fatalf("generation-five purge watcher was not armed before publication: %v", err)
	}
	records := make(map[string]realCloudPurgeWatcherEvidence, 2)
	deadline, _ := parseRealEdgeUTC(spec.EvidenceDeadline)
	for _, vendor := range spec.Vendors {
		for {
			_, evidenceErr := loadRealCloudPurgeWatcherEvidence(paths.evidence[vendor.Vendor], spec, vendor, key)
			if evidenceErr == nil {
				if _, statErr := os.Lstat(paths.complete[vendor.Vendor]); statErr == nil {
					closedRecord, completeErr := loadRealCloudPurgeWatcherEvidenceClosure(paths, spec, vendor, key)
					if completeErr != nil {
						program.t.Fatalf("generation-five purge watcher %s completion was changed: %v", vendor.Vendor, completeErr)
					}
					records[vendor.Vendor] = closedRecord
					break
				} else if !errors.Is(statErr, os.ErrNotExist) {
					program.t.Fatalf("inspect generation-five purge watcher %s completion: %v", vendor.Vendor, statErr)
				}
			} else if _, statErr := os.Lstat(paths.evidence[vendor.Vendor]); statErr == nil {
				program.t.Fatalf("generation-five purge watcher %s evidence was changed: %v", vendor.Vendor, evidenceErr)
			} else if !errors.Is(statErr, os.ErrNotExist) {
				program.t.Fatalf("inspect generation-five purge watcher %s evidence: %v", vendor.Vendor, statErr)
			}
			if !time.Now().UTC().Before(deadline) {
				program.t.Fatalf("generation-five purge watcher %s evidence is missing after the old-cache TTL", vendor.Vendor)
			}
			select {
			case <-program.t.Context().Done():
				program.t.Fatal("generation-five purge watcher evidence wait was interrupted")
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	evidence := realEdgeMultiPoPStageEvidence{
		Vendors:           make(map[string]realEdgeMultiPoPVendorStage, 2),
		EntitlementSHA256: append([]string(nil), spec.EntitlementSHA256...),
	}
	for _, vendorSpec := range spec.Vendors {
		record := records[vendorSpec.Vendor]
		publication := readRealCloudPublication(program.t, program.root, vendorSpec.Target)
		observedAt, timeErr := parseRealEdgeUTC(record.PublicationObservedAt)
		if timeErr != nil {
			program.t.Fatalf("generation-five purge watcher %s publication time: %v", vendorSpec.Vendor, timeErr)
		}
		baseURL := program.environment.CFCDNBase
		if vendorSpec.Vendor == "edgeone" {
			baseURL = program.environment.COSCDNBase
		}
		stage, stageErr := realEdgeStageFromPublication(vendorSpec.Vendor, baseURL, program.gatedBodies[1], publication, observedAt, program.identity)
		if stageErr != nil || stage.GenerationSHA256 != record.GenerationSHA256 || stage.CheckpointSHA256 != record.CheckpointSHA256 ||
			stage.TransactionID != record.TransactionID || realCloudLowerSHA256(publication.purgeEvidenceBody) != record.PurgeEvidenceSHA256 {
			program.t.Fatalf("generation-five purge watcher %s evidence disagrees with canonical publication: %v", vendorSpec.Vendor, stageErr)
		}
		stage.Observations, stageErr = decodeRealEdgeArtifactObservations(vendorSpec.Vendor, record.Observations)
		if stageErr != nil {
			program.t.Fatalf("decode generation-five purge watcher %s observations: %v", vendorSpec.Vendor, stageErr)
		}
		prior := program.ledger.Snapshot().Facts.PrePurge[vendorSpec.Vendor]
		prior.Observations = append([]realEdgeMultiPoPObservation(nil), prior.Observations...)
		stage.PrePurge = &prior
		if stageErr := validateRealEdgeActiveStage(stage); stageErr != nil {
			program.t.Fatalf("generation-five purge watcher %s active stage: %v", vendorSpec.Vendor, stageErr)
		}
		evidence.Vendors[vendorSpec.Vendor] = stage
	}
	allSecrets := append([]string(nil), program.secretFragments...)
	observers, observerErr := loadRealEdgeObservers(os.Getenv)
	if observerErr != nil {
		program.t.Fatalf("load generation-five purge watcher observers: %v", observerErr)
	}
	for _, observer := range observers {
		allSecrets = append(allSecrets, realEdgeObserverSecretFragments(observer)...)
	}
	if err := appendRealEdgeActiveArtifact(program.artifactPath, evidence, allSecrets); err != nil {
		program.t.Fatalf("append generation-five watcher evidence to active artifact: %v", err)
	}
	return evidence
}

const (
	realCloudPurgeWatcherLocalHelperEnv = "SOW_LOCAL_PURGE_WATCHER_HELPER"
	realCloudPurgeWatcherLocalParentEnv = "SOW_LOCAL_PURGE_WATCHER_PARENT"
	realCloudPurgeWatcherLocalServerEnv = "SOW_LOCAL_PURGE_WATCHER_SERVER"
	realCloudPurgeWatcherTestTokenA     = "purge-watcher-token-a-0001"
	realCloudPurgeWatcherTestTokenB     = "purge-watcher-token-b-0002"
)

func realCloudPurgeWatcherTestSpec(t *testing.T, root string, issuedAt time.Time, lifetime time.Duration) (realCloudPurgeWatcherSpec, []byte, []byte) {
	t.Helper()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	wantedBody := []byte("independent purge watcher new body\n")
	deadline := issuedAt.Add(lifetime).UTC()
	key, err := realCloudPurgeWatcherMACKey(realCloudPurgeWatcherTestTokenA, realCloudPurgeWatcherTestTokenB)
	if err != nil {
		t.Fatal(err)
	}
	spec := realCloudPurgeWatcherSpec{
		Schema: realCloudPurgeWatcherSpecSchema, RunID: "run-purge-watcher-local-0001",
		ConfirmationSHA256: strings.Repeat("1", 64), ConfigSHA256: strings.Repeat("2", 64),
		AcceptanceBindingSHA256: strings.Repeat("3", 64), ResourceSHA256: strings.Repeat("4", 64),
		ObserverTopologySHA256: strings.Repeat("5", 64), WorkspaceSHA256: realCloudLowerSHA256([]byte(root)),
		Generation: 5, ExpectedBodySHA256: realCloudLowerSHA256(wantedBody),
		EntitlementSHA256: realEdgeEntitlementDigests(realCloudPurgeWatcherTestTokenA, realCloudPurgeWatcherTestTokenB),
		Nonce:             strings.Repeat("ab", 16), IssuedAt: issuedAt.UTC().Format(time.RFC3339Nano),
		EvidenceDeadline: deadline.Format(time.RFC3339Nano),
	}
	for _, input := range []struct {
		vendor string
		target string
		clean  string
		prior  string
	}{{"cloudflare", "cf", strings.Repeat("6", 64), strings.Repeat("7", 64)}, {"edgeone", "cos", strings.Repeat("8", 64), strings.Repeat("9", 64)}} {
		vendor := realCloudPurgeWatcherVendorSpec{
			Vendor: input.vendor, Target: input.target, ParentGeneration: 4,
			ParentTransactionID: "tx-purge-watcher-parent-" + input.vendor,
			CleanURLSHA256:      input.clean, PriorBodySHA256: input.prior,
			ExpectedBodySHA256: spec.ExpectedBodySHA256,
		}
		for index, id := range []string{"observer-a", "observer-b"} {
			role := "cross-pop"
			if index == 0 {
				role = "prime"
			}
			vendor.Observers = append(vendor.Observers, realCloudPurgeWatcherObserverSpec{ID: id, Role: role, FreshUntil: deadline.Format(time.RFC3339Nano)})
		}
		spec.Vendors = append(spec.Vendors, vendor)
	}
	spec.MACSHA256, err = realCloudPurgeWatcherSign(spec, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRealCloudPurgeWatcherSpec(spec, key); err != nil {
		t.Fatal(err)
	}
	return spec, key, wantedBody
}

func TestRealCloudPurgeWatcherLocalHTTPContractAndTamperRejection(t *testing.T) {
	root := t.TempDir()
	issuedAt := time.Date(2026, 7, 14, 3, 0, 0, 0, time.UTC)
	spec, key, wantedBody := realCloudPurgeWatcherTestSpec(t, root, issuedAt, 30*time.Second)
	paths, err := realCloudPurgeWatcherPathsFor(root, 5)
	if err != nil {
		t.Fatal(err)
	}
	validated := false
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !validated {
			t.Error("fake HTTP request escaped before dedicated-resource validation")
			writer.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		requests.Add(1)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(wantedBody)
	}))
	defer server.Close()
	current := issuedAt.Add(time.Second)
	runtime := realCloudPurgeWatcherRuntime{
		clock: realCloudPurgeWatcherClock{
			now: func() time.Time { return current },
			sleep: func(_ context.Context, duration time.Duration) error {
				current = current.Add(duration)
				return nil
			},
		},
		validateResources: func() error {
			validated = true
			return nil
		},
		loadPublication: func(target string, generation uint64) (realCloudPurgeWatcherPublication, error) {
			return realCloudPurgeWatcherPublication{
				Target: target, Generation: generation, TransactionID: "tx-purge-watcher-g5-" + target,
				GatedBodySHA256: realCloudLowerSHA256(wantedBody), GenerationSHA256: strings.Repeat("a", 64),
				CheckpointSHA256: strings.Repeat("b", 64), PurgeEvidenceSHA256: strings.Repeat("c", 64),
				PurgeCompletedAt: current.Add(-time.Millisecond),
			}, nil
		},
		observe: func(ctx context.Context, vendor realCloudPurgeWatcherVendorSpec, observer realCloudPurgeWatcherObserverSpec, _ time.Time) (realEdgeMultiPoPObservation, error) {
			started := current.Add(time.Millisecond)
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/"+vendor.Vendor+"/"+observer.ID, nil)
			if err != nil {
				return realEdgeMultiPoPObservation{}, err
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				return realEdgeMultiPoPObservation{}, err
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, wantedBody) {
				return realEdgeMultiPoPObservation{}, errors.New("fake observer response mismatch")
			}
			current = started.Add(time.Millisecond)
			cacheStatus := "HIT"
			if observer.Role == "prime" {
				cacheStatus = "MISS"
			}
			colo := ""
			if vendor.Vendor == "cloudflare" {
				colo = "SJC"
			}
			return realEdgeMultiPoPObservation{
				Vendor: vendor.Vendor, Role: observer.Role, ObserverID: observer.ID,
				RequestID: "request-" + vendor.Vendor + "-" + observer.ID, CloudflareColo: colo,
				CacheStatus: cacheStatus, Transport: "https-bearer", CleanURLSHA256: vendor.CleanURLSHA256,
				BodySHA256: realCloudLowerSHA256(body), CacheAgeSeconds: 1, CacheMaxAge: 60,
				RequestStarted: started, ResponseObserved: current,
			}, nil
		},
	}
	if err := runRealCloudPurgeWatcher(t.Context(), paths, spec, key, runtime); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 4 {
		t.Fatalf("fake HTTP requests=%d want=4", requests.Load())
	}
	if err := loadRealCloudPurgeWatcherArmed(paths, spec, key); err != nil {
		t.Fatal(err)
	}
	for _, vendor := range spec.Vendors {
		record, err := loadRealCloudPurgeWatcherEvidenceClosure(paths, spec, vendor, key)
		if err != nil || record.Generation != 5 || record.BodySHA256 != spec.ExpectedBodySHA256 || len(record.Observations) != 2 {
			t.Fatalf("load %s watcher evidence: %#v err=%v", vendor.Vendor, record, err)
		}
	}
	if err := os.Remove(paths.complete["edgeone"]); err != nil {
		t.Fatal(err)
	}
	if err := syncRealCloudDirectoryError(paths.directory); err != nil {
		t.Fatal(err)
	}
	requestCount := requests.Load()
	if err := runRealCloudPurgeWatcher(t.Context(), paths, spec, key, runtime); err != nil {
		t.Fatalf("recover evidence-to-completion crash window: %v", err)
	}
	if requests.Load() != requestCount {
		t.Fatal("completion recovery repeated an already durable observer request")
	}
	if _, err := loadRealCloudPurgeWatcherEvidenceClosure(paths, spec, spec.Vendors[1], key); err != nil {
		t.Fatalf("recovered evidence completion closure: %v", err)
	}
	// A crash/recovery can leave one vendor fully complete while the other has
	// no evidence yet. Replaying must preserve the complete side and issue only
	// the missing vendor's two loopback observer requests.
	if err := os.Remove(paths.complete["edgeone"]); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths.evidence["edgeone"]); err != nil {
		t.Fatal(err)
	}
	if err := syncRealCloudDirectoryError(paths.directory); err != nil {
		t.Fatal(err)
	}
	requestCount = requests.Load()
	if err := runRealCloudPurgeWatcher(t.Context(), paths, spec, key, runtime); err != nil {
		t.Fatalf("recover partial vendor closure: %v", err)
	}
	if requests.Load() != requestCount+2 {
		t.Fatalf("partial replay requests=%d want=%d", requests.Load(), requestCount+2)
	}
	complete, err := realCloudPurgeWatcherAllVendorClosuresComplete(paths, spec, key)
	if err != nil || !complete {
		t.Fatalf("fast completed helper closure was not accepted without a live lock: complete=%v err=%v", complete, err)
	}
	held, err := realCloudPurgeWatcherLockHeld(paths)
	if err != nil || held {
		t.Fatalf("completed local helper unexpectedly retained its lock: held=%v err=%v", held, err)
	}
	if err := os.Remove(paths.armed); err != nil {
		t.Fatal(err)
	}
	if err := syncRealCloudDirectoryError(paths.directory); err != nil {
		t.Fatal(err)
	}
	complete, err = realCloudPurgeWatcherAllVendorClosuresComplete(paths, spec, key)
	if err != nil || !complete {
		t.Fatalf("completed vendor closure changed while testing the armed prerequisite: complete=%v err=%v", complete, err)
	}
	if err := loadRealCloudPurgeWatcherArmed(paths, spec, key); err == nil {
		t.Fatal("complete vendor evidence was accepted without the exact pre-publication armed receipt")
	}
	if err := writeRealCloudPurgeWatcherArmed(paths, spec, key); err != nil {
		t.Fatalf("restore exact armed receipt after negative test: %v", err)
	}
	cloudflare := spec.Vendors[0]
	record, err := loadRealCloudPurgeWatcherEvidence(paths.evidence[cloudflare.Vendor], spec, cloudflare, key)
	if err != nil {
		t.Fatal(err)
	}
	wrongSpecs := []struct {
		name   string
		mutate func(*realCloudPurgeWatcherSpec)
	}{
		{name: "run", mutate: func(value *realCloudPurgeWatcherSpec) { value.RunID = "run-purge-watcher-other-0002" }},
		{name: "resource", mutate: func(value *realCloudPurgeWatcherSpec) { value.ResourceSHA256 = strings.Repeat("d", 64) }},
		{name: "body", mutate: func(value *realCloudPurgeWatcherSpec) {
			value.ExpectedBodySHA256 = strings.Repeat("e", 64)
			value.Vendors = append([]realCloudPurgeWatcherVendorSpec(nil), value.Vendors...)
			for index := range value.Vendors {
				value.Vendors[index].ExpectedBodySHA256 = value.ExpectedBodySHA256
			}
		}},
	}
	for _, test := range wrongSpecs {
		wrong := spec
		test.mutate(&wrong)
		wrong.MACSHA256, err = realCloudPurgeWatcherSign(wrong, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := loadRealCloudPurgeWatcherEvidence(paths.evidence[cloudflare.Vendor], wrong, wrong.Vendors[0], key); err == nil {
			t.Fatalf("watcher evidence was accepted for a different %s binding", test.name)
		}
	}
	record.Observations[0].RequestID = "request-tampered-observer"
	tampered, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.evidence[cloudflare.Vendor], append(tampered, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRealCloudPurgeWatcherEvidence(paths.evidence[cloudflare.Vendor], spec, cloudflare, key); err == nil {
		t.Fatal("tampered watcher evidence passed its entitlement-keyed integrity check")
	}
}

func TestRealCloudPurgeWatcherFailsBeforeNetworkAndAtTTLBoundary(t *testing.T) {
	root := t.TempDir()
	issuedAt := time.Date(2026, 7, 14, 4, 0, 0, 0, time.UTC)
	spec, key, _ := realCloudPurgeWatcherTestSpec(t, root, issuedAt, 10*time.Second)
	paths, err := realCloudPurgeWatcherPathsFor(root, 5)
	if err != nil {
		t.Fatal(err)
	}
	loads, networks := 0, 0
	runtime := realCloudPurgeWatcherRuntime{
		clock: defaultRealCloudPurgeWatcherClock(),
		validateResources: func() error {
			return errors.New("not one administrator-pinned dedicated resource")
		},
		loadPublication: func(string, uint64) (realCloudPurgeWatcherPublication, error) {
			loads++
			return realCloudPurgeWatcherPublication{}, nil
		},
		observe: func(context.Context, realCloudPurgeWatcherVendorSpec, realCloudPurgeWatcherObserverSpec, time.Time) (realEdgeMultiPoPObservation, error) {
			networks++
			return realEdgeMultiPoPObservation{}, nil
		},
	}
	if err := runRealCloudPurgeWatcher(t.Context(), paths, spec, key, runtime); err == nil || !strings.Contains(err.Error(), "resource-preflight") {
		t.Fatalf("resource preflight did not fail closed: %v", err)
	}
	if loads != 0 || networks != 0 {
		t.Fatalf("resource rejection allowed local publication loads=%d or network calls=%d", loads, networks)
	}
	expiredLoads, expiredNetworks := 0, 0
	deadline, _ := parseRealEdgeUTC(spec.EvidenceDeadline)
	expiredRuntime := realCloudPurgeWatcherRuntime{
		clock: realCloudPurgeWatcherClock{
			now:   func() time.Time { return deadline },
			sleep: func(context.Context, time.Duration) error { return nil },
		},
		validateResources: func() error { return nil },
		loadPublication: func(string, uint64) (realCloudPurgeWatcherPublication, error) {
			expiredLoads++
			return realCloudPurgeWatcherPublication{}, nil
		},
		observe: func(context.Context, realCloudPurgeWatcherVendorSpec, realCloudPurgeWatcherObserverSpec, time.Time) (realEdgeMultiPoPObservation, error) {
			expiredNetworks++
			return realEdgeMultiPoPObservation{}, nil
		},
	}
	if err := runRealCloudPurgeWatcher(t.Context(), paths, spec, key, expiredRuntime); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("watcher armed exactly at the old-cache deadline: %v", err)
	}
	if expiredLoads != 0 || expiredNetworks != 0 {
		t.Fatalf("expired watcher reached publication loads=%d or network calls=%d", expiredLoads, expiredNetworks)
	}
	vendor := spec.Vendors[0]
	publicationObserved := issuedAt.Add(time.Second)
	freshUntil, _ := parseRealEdgeUTC(vendor.Observers[0].FreshUntil)
	observation := realEdgeMultiPoPObservation{
		Vendor: vendor.Vendor, Role: "prime", ObserverID: "observer-a", RequestID: "request-boundary-01",
		CloudflareColo: "SJC", CacheStatus: "MISS", Transport: "https-bearer",
		CleanURLSHA256: vendor.CleanURLSHA256, BodySHA256: vendor.ExpectedBodySHA256,
		CacheAgeSeconds: 1, CacheMaxAge: 60, RequestStarted: freshUntil.Add(-time.Millisecond), ResponseObserved: freshUntil,
	}
	publication := realCloudPurgeWatcherPublication{
		Target: "cf", Generation: 5, TransactionID: "tx-boundary-generation-five", GatedBodySHA256: vendor.ExpectedBodySHA256,
		GenerationSHA256: strings.Repeat("a", 64), CheckpointSHA256: strings.Repeat("b", 64), PurgeEvidenceSHA256: strings.Repeat("c", 64),
		PurgeCompletedAt: publicationObserved.Add(-time.Second),
	}
	if err := validateRealCloudPurgeWatcherObservation(vendor, vendor.Observers[0], publication, publicationObserved, observation); err == nil {
		t.Fatal("post-probe observed exactly at natural expiry was accepted")
	}
}

func TestRealCloudPurgeWatcherDuplicateProcessFailsBeforePublicationOrNetwork(t *testing.T) {
	root := t.TempDir()
	issuedAt := time.Date(2026, 7, 14, 4, 30, 0, 0, time.UTC)
	spec, key, _ := realCloudPurgeWatcherTestSpec(t, root, issuedAt, 30*time.Second)
	paths, err := realCloudPurgeWatcherPathsFor(root, 5)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := openRealCloudPurgeWatcherLock(paths.lock)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	loads, networks := 0, 0
	runtime := realCloudPurgeWatcherRuntime{
		clock: realCloudPurgeWatcherClock{
			now:   func() time.Time { return issuedAt.Add(time.Second) },
			sleep: func(context.Context, time.Duration) error { return nil },
		},
		validateResources: func() error { return nil },
		loadPublication: func(string, uint64) (realCloudPurgeWatcherPublication, error) {
			loads++
			return realCloudPurgeWatcherPublication{}, nil
		},
		observe: func(context.Context, realCloudPurgeWatcherVendorSpec, realCloudPurgeWatcherObserverSpec, time.Time) (realEdgeMultiPoPObservation, error) {
			networks++
			return realEdgeMultiPoPObservation{}, nil
		},
	}
	if err := runRealCloudPurgeWatcher(t.Context(), paths, spec, key, runtime); !errors.Is(err, errRealCloudPurgeWatcherActive) {
		t.Fatalf("duplicate watcher did not fail at its exclusive lock: %v", err)
	}
	if loads != 0 || networks != 0 {
		t.Fatalf("duplicate watcher reached publication loads=%d or network calls=%d", loads, networks)
	}
}

func TestRealCloudPurgeWatcherLockTeardownFailureIsReturned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watcher.lock")
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := closeRealCloudPurgeWatcherLock(lock, true); err != nil {
		t.Fatalf("valid purge watcher lock teardown failed: %v", err)
	}

	closed, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := closeRealCloudPurgeWatcherLock(closed, true); err == nil || !strings.Contains(err.Error(), "purge watcher lock") {
		t.Fatalf("closed descriptor teardown failure was discarded: %v", err)
	}
}

func TestRealCloudPurgeWatcherDurabilityBarriersAndPathSafety(t *testing.T) {
	originalSync := realCloudPurgeWatcherSyncDirectory
	t.Cleanup(func() { realCloudPurgeWatcherSyncDirectory = originalSync })
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	forced := errors.New("forced watcher directory sync failure")
	realCloudPurgeWatcherSyncDirectory = func(string) error { return forced }
	if _, err := realCloudPurgeWatcherPathsFor(root, 5); err == nil {
		t.Fatal("new watcher directory was accepted without a durable parent entry")
	}
	realCloudPurgeWatcherSyncDirectory = originalSync
	paths, err := realCloudPurgeWatcherPathsFor(root, 5)
	if err != nil {
		t.Fatalf("retry did not resync the pre-existing watcher directory: %v", err)
	}
	spec, key, wantedBody := realCloudPurgeWatcherTestSpec(t, root, time.Date(2026, 7, 14, 5, 0, 0, 0, time.UTC), 30*time.Second)
	specBody, err := realCloudPurgeWatcherMarshalSigned(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.spec, specBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeRealCloudPurgeWatcherArmed(paths, spec, key); err != nil {
		t.Fatal(err)
	}
	realCloudPurgeWatcherSyncDirectory = func(string) error { return forced }
	if err := installRealCloudPurgeWatcherRecord(paths.spec, specBody); !errors.Is(err, forced) {
		t.Fatalf("matching record bypassed its EEXIST durability retry: %v", err)
	}
	if err := ensureRealCloudPurgeWatcherBody(paths.body, wantedBody); !errors.Is(err, forced) {
		t.Fatalf("new body bypassed its reader-side durability barrier: %v", err)
	}
	if err := ensureRealCloudPurgeWatcherBody(paths.body, wantedBody); !errors.Is(err, forced) {
		t.Fatalf("matching body bypassed its EEXIST durability retry: %v", err)
	}
	if err := loadRealCloudPurgeWatcherArmed(paths, spec, key); !errors.Is(err, forced) {
		t.Fatalf("armed receipt bypassed its reader-side durability barrier: %v", err)
	}
	realCloudPurgeWatcherSyncDirectory = originalSync

	unsafe := filepath.Join(paths.directory, "unsafe.json")
	if err := os.WriteFile(unsafe, specBody, 0o644); err != nil {
		t.Fatal(err)
	}
	var decoded realCloudPurgeWatcherSpec
	if _, err := readRealCloudPurgeWatcherJSON(unsafe, &decoded); err == nil {
		t.Fatal("group/world-readable watcher record was accepted")
	}
	if err := os.Chmod(unsafe, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(paths.directory, "unsafe-link.json")
	if err := os.Symlink(unsafe, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readRealCloudPurgeWatcherJSON(symlink, &decoded); err == nil {
		t.Fatal("symlink watcher record was accepted")
	}
}

func TestRealCloudPurgeWatcherDetachedRuntimeBinding(t *testing.T) {
	temporary := t.TempDir()
	root, err := filepath.EvalSymlinks(temporary)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Date(2026, 7, 14, 5, 30, 0, 0, time.UTC)
	spec, key, _ := realCloudPurgeWatcherTestSpec(t, root, issuedAt, 30*time.Second)
	environment := realCloudEnvironment{
		CFR2Endpoint: "https://account.example.invalid", CFR2Bucket: "sow-test-r2-watcher",
		CFCDNBase: "https://cf-test.example.invalid", CFBetaCDNBase: "https://cf-beta-test.example.invalid", CFZoneID: "zone-cf-test",
		COSEndpoint: "https://cos.ap-test.myqcloud.com", COSBucket: "sow-test-cos-watcher-1234567890", COSRegion: "ap-test",
		COSCDNBase: "https://eo-test.example.invalid", COSBetaBase: "https://eo-beta-test.example.invalid", EdgeOneZoneID: "zone-eo-test",
		EdgeProTokenA: realCloudPurgeWatcherTestTokenA, EdgeProTokenB: realCloudPurgeWatcherTestTokenB,
	}
	values := map[string]string{
		realEdgeObserversEnv:         `[{"id":"observer-a","proxy_env":"SOW_REAL_EDGE_PROXY_TEST_A"},{"id":"observer-b","proxy_env":"SOW_REAL_EDGE_PROXY_TEST_B"}]`,
		"SOW_REAL_EDGE_PROXY_TEST_A": "https://observer:user-a@proxy-a.example.invalid:8443",
		"SOW_REAL_EDGE_PROXY_TEST_B": "socks5h://observer:user-b@proxy-b.example.invalid:1080",
		realEdgeActiveArtifactEnv:    filepath.Join(root, "active-evidence.jsonl"),
		realEdgeProviderLogEnv:       filepath.Join(root, "provider-evidence.jsonl"),
	}
	lookup := func(name string) string { return values[name] }
	resourceSHA, err := realCloudPurgeWatcherResourceSHA256(environment)
	if err != nil {
		t.Fatal(err)
	}
	workspaceSHA, err := realCloudPurgeWatcherWorkspaceSHA256(root)
	if err != nil {
		t.Fatal(err)
	}
	topology, err := realCloudObserverTopologyBindingFrom(lookup)
	if err != nil {
		t.Fatal(err)
	}
	confirmationSHA := realCloudLowerSHA256([]byte(realCloudConfirmation(environment)))
	configBody, err := realCloudConfigBodyForEnvironment(environment)
	if err != nil {
		t.Fatal(err)
	}
	configSHA := realCloudLowerSHA256(configBody)
	if err := os.WriteFile(filepath.Join(root, "sow.yaml"), configBody, 0o600); err != nil {
		t.Fatal(err)
	}
	identity := realCloudRunIdentity{
		Schema: "sow-real-cloud-run/v1", RunID: spec.RunID,
		ConfirmationSHA256: confirmationSHA, ConfigSHA256: configSHA, PublicKeySHA256: strings.Repeat("f", 64),
	}
	identityBody, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if installed, err := installRealCloudPrivateFileExclusive(filepath.Join(root, realCloudRunIdentityFilename), append(identityBody, '\n')); err != nil || !installed {
		t.Fatalf("install detached runtime identity: installed=%v err=%v", installed, err)
	}
	binding, err := realCloudAcceptanceBindingFor(identity, configBody, values[realEdgeActiveArtifactEnv], values[realEdgeProviderLogEnv], topology)
	if err != nil {
		t.Fatal(err)
	}
	ledger := realCloudAcceptanceLedger{
		Schema: realCloudAcceptanceLedgerSchema, Binding: binding, Revision: 1, Status: "running",
		Receipts: []realCloudStepReceipt{}, Facts: realCloudResumeFacts{},
	}
	if err := writeRealCloudAcceptanceLedgerExclusive(filepath.Join(root, realCloudAcceptanceLedgerFilename), ledger); err != nil {
		t.Fatal(err)
	}
	bindingSHA, err := realCloudPurgeWatcherAcceptanceBindingSHA256(binding)
	if err != nil {
		t.Fatal(err)
	}
	spec.ConfirmationSHA256 = confirmationSHA
	spec.ConfigSHA256 = configSHA
	spec.AcceptanceBindingSHA256 = bindingSHA
	spec.ResourceSHA256 = resourceSHA
	spec.WorkspaceSHA256 = workspaceSHA
	spec.ObserverTopologySHA256 = realCloudLowerSHA256(topology)
	spec.EntitlementSHA256 = realEdgeEntitlementDigests(environment.EdgeProTokenA, environment.EdgeProTokenB)
	spec.MACSHA256, err = realCloudPurgeWatcherSign(spec, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRealCloudPurgeWatcherRuntimeBinding(root, environment, spec, lookup); err != nil {
		t.Fatalf("exact detached runtime binding was rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "sow.yaml"), []byte("changed config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateRealCloudPurgeWatcherRuntimeBinding(root, environment, spec, lookup); err == nil {
		t.Fatal("changed current config was accepted by detached helper binding")
	}
	if err := os.WriteFile(filepath.Join(root, "sow.yaml"), configBody, 0o600); err != nil {
		t.Fatal(err)
	}
	changedIdentity := identity
	changedIdentity.ConfigSHA256 = strings.Repeat("e", 64)
	changedIdentityBody, err := json.Marshal(changedIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, realCloudRunIdentityFilename), append(changedIdentityBody, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateRealCloudPurgeWatcherRuntimeBinding(root, environment, spec, lookup); err == nil {
		t.Fatal("changed current run identity was accepted by detached helper binding")
	}
	if err := os.WriteFile(filepath.Join(root, realCloudRunIdentityFilename), append(identityBody, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	changedLedger := ledger
	changedLedger.Binding.ActiveArtifactPathSHA256 = strings.Repeat("d", 64)
	changedLedgerBody, err := json.Marshal(changedLedger)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, realCloudAcceptanceLedgerFilename), append(changedLedgerBody, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateRealCloudPurgeWatcherRuntimeBinding(root, environment, spec, lookup); err == nil {
		t.Fatal("changed acceptance ledger binding was accepted by detached helper")
	}
	ledgerBody, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, realCloudAcceptanceLedgerFilename), append(ledgerBody, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongBindingSpec := spec
	wrongBindingSpec.AcceptanceBindingSHA256 = strings.Repeat("c", 64)
	wrongBindingSpec.MACSHA256, err = realCloudPurgeWatcherSign(wrongBindingSpec, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRealCloudPurgeWatcherRuntimeBinding(root, environment, wrongBindingSpec, lookup); err == nil {
		t.Fatal("signed-spec acceptance binding mismatch was accepted by detached helper")
	}
	wrongResource := environment
	wrongResource.COSBucket += "-other"
	if err := validateRealCloudPurgeWatcherRuntimeBinding(root, wrongResource, spec, lookup); err == nil {
		t.Fatal("signed spec from another pinned resource was accepted")
	}
	values["SOW_REAL_EDGE_PROXY_TEST_B"] = "socks5h://observer:user-b@proxy-other.example.invalid:1080"
	if err := validateRealCloudPurgeWatcherRuntimeBinding(root, environment, spec, lookup); err == nil {
		t.Fatal("changed observer topology was accepted by detached helper binding")
	}
	values["SOW_REAL_EDGE_PROXY_TEST_B"] = "http://127.0.0.1:1"
	if err := validateRealCloudPurgeWatcherRuntimeBinding(root, environment, spec, lookup); err == nil {
		t.Fatal("invalid/private observer proxy was accepted by detached helper binding")
	}
	values["SOW_REAL_EDGE_PROXY_TEST_B"] = "socks5h://observer:user-b@proxy-b.example.invalid:1080"
	otherTemporary := t.TempDir()
	otherRoot, err := filepath.EvalSymlinks(otherTemporary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(otherRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateRealCloudPurgeWatcherRuntimeBinding(otherRoot, environment, spec, lookup); err == nil {
		t.Fatal("signed spec from another workspace was accepted")
	}
}

func TestRealCloudPurgeWatcherSurvivesParentSIGKILL(t *testing.T) {
	if os.Getenv(realCloudPurgeWatcherLocalParentEnv) == "1" || os.Getenv(realCloudPurgeWatcherLocalHelperEnv) == "1" {
		t.Skip("outer purge watcher SIGKILL contract only")
	}
	root := t.TempDir()
	spec, key, wantedBody := realCloudPurgeWatcherTestSpec(t, root, time.Now().UTC(), 20*time.Second)
	paths, err := realCloudPurgeWatcherPathsFor(root, 5)
	if err != nil {
		t.Fatal(err)
	}
	specBody, err := realCloudPurgeWatcherMarshalSigned(spec)
	if err != nil || installRealCloudPurgeWatcherRecord(paths.spec, specBody) != nil || ensureRealCloudPurgeWatcherBody(paths.body, wantedBody) != nil {
		t.Fatal("install local SIGKILL watcher fixture")
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if _, err := os.Lstat(filepath.Join(paths.directory, "resource-validated")); err != nil {
			writer.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		requests.Add(1)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(wantedBody)
	}))
	defer server.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	specSHA := realCloudLowerSHA256(specBody)
	parent := exec.Command(executable, "-test.run=^TestRealCloudPurgeWatcherKilledParentProcess$", "-test.count=1")
	parent.Env = append(os.Environ(),
		realCloudPurgeWatcherLocalParentEnv+"=1",
		realCloudPurgeWatcherRootEnv+"="+root,
		realCloudPurgeWatcherSpecSHAEnv+"="+specSHA,
		realCloudPurgeWatcherLocalServerEnv+"="+server.URL,
	)
	parent.Stdout, parent.Stderr = io.Discard, io.Discard
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	parentSession, err := unix.Getsid(parent.Process.Pid)
	if err != nil {
		_ = parent.Process.Kill()
		_ = parent.Wait()
		t.Fatal(err)
	}
	parentGroup, err := unix.Getpgid(parent.Process.Pid)
	if err != nil {
		_ = parent.Process.Kill()
		_ = parent.Wait()
		t.Fatal(err)
	}
	if err := waitForRealCloudPurgeWatcherPath(filepath.Join(paths.directory, "parent-ready"), 5*time.Second); err != nil {
		_ = parent.Process.Kill()
		_ = parent.Wait()
		t.Fatal(err)
	}
	if err := loadRealCloudPurgeWatcherArmed(paths, spec, key); err != nil {
		_ = parent.Process.Kill()
		_ = parent.Wait()
		t.Fatalf("child was not durably armed before parent kill: %v", err)
	}
	var processIdentity realCloudPurgeWatcherProcessIdentity
	if _, err := readRealCloudPurgeWatcherJSON(filepath.Join(paths.directory, "process-identity.json"), &processIdentity); err != nil {
		_ = parent.Process.Kill()
		_ = parent.Wait()
		t.Fatalf("read detached child process identity: %v", err)
	}
	if processIdentity.Schema != "sow-local-purge-watcher-process/v1" || processIdentity.ParentPID != parent.Process.Pid ||
		processIdentity.PID <= 0 || processIdentity.SessionID != processIdentity.PID || processIdentity.GroupID != processIdentity.PID ||
		processIdentity.SessionID == parentSession || processIdentity.GroupID == parentGroup {
		_ = parent.Process.Kill()
		_ = parent.Wait()
		t.Fatalf("child was not isolated from parent session/group: child=%+v parent_sid=%d parent_pgid=%d", processIdentity, parentSession, parentGroup)
	}
	killedAt := time.Now().UTC()
	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = parent.Wait()
	if _, err := installRealCloudPrivateFileExclusive(filepath.Join(paths.directory, "publication-ready"), []byte("committed\n")); err != nil {
		t.Fatal(err)
	}
	for _, vendor := range spec.Vendors {
		if err := waitForRealCloudPurgeWatcherPath(paths.complete[vendor.Vendor], 8*time.Second); err != nil {
			t.Fatal(err)
		}
		record, err := loadRealCloudPurgeWatcherEvidenceClosure(paths, spec, vendor, key)
		if err != nil {
			t.Fatal(err)
		}
		observedAt, _ := parseRealEdgeUTC(record.PublicationObservedAt)
		if observedAt.Before(killedAt) {
			t.Fatalf("%s watcher evidence predates parent SIGKILL", vendor.Vendor)
		}
	}
	if requests.Load() != 4 {
		t.Fatalf("orphaned watcher fake HTTP requests=%d want=4", requests.Load())
	}
}

func TestRealCloudPurgeWatcherKilledParentProcess(t *testing.T) {
	if os.Getenv(realCloudPurgeWatcherLocalParentEnv) != "1" {
		t.Skip("internal killed-parent helper")
	}
	root := os.Getenv(realCloudPurgeWatcherRootEnv)
	paths, err := realCloudPurgeWatcherPathsFor(root, 5)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestRealCloudPurgeWatcherLocalProcess$", "-test.count=1")
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	child.Env = append(os.Environ(), realCloudPurgeWatcherLocalHelperEnv+"=1")
	child.Stdout, child.Stderr = io.Discard, io.Discard
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if err := child.Process.Release(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		if err := waitForRealCloudPurgeWatcherPath(paths.armed, 100*time.Millisecond); err == nil {
			held, lockErr := realCloudPurgeWatcherLockHeld(paths)
			if lockErr != nil {
				t.Fatal(lockErr)
			}
			if held {
				break
			}
		}
		if !time.Now().Before(deadline) {
			t.Fatal("local purge watcher child did not retain its liveness lock")
		}
	}
	if _, err := installRealCloudPrivateFileExclusive(filepath.Join(paths.directory, "parent-ready"), []byte("ready\n")); err != nil {
		t.Fatal(err)
	}
	select {}
}

func TestRealCloudPurgeWatcherLocalProcess(t *testing.T) {
	if os.Getenv(realCloudPurgeWatcherLocalHelperEnv) != "1" {
		t.Skip("internal local purge watcher helper")
	}
	if err := validateRealCloudPurgeWatcherDetachedProcess(); err != nil {
		t.Fatal(err)
	}
	root := os.Getenv(realCloudPurgeWatcherRootEnv)
	serverRaw := os.Getenv(realCloudPurgeWatcherLocalServerEnv)
	parsed, err := url.Parse(serverRaw)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		t.Fatal("local watcher server URL is invalid")
	}
	serverIP := parsed.Hostname()
	if serverIP != "127.0.0.1" && serverIP != "::1" {
		t.Fatal("local watcher helper refuses non-loopback HTTP")
	}
	paths, err := realCloudPurgeWatcherPathsFor(root, 5)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := unix.Getsid(0)
	if err != nil {
		t.Fatal(err)
	}
	processIdentity := realCloudPurgeWatcherProcessIdentity{
		Schema: "sow-local-purge-watcher-process/v1", PID: os.Getpid(), ParentPID: os.Getppid(),
		SessionID: sessionID, GroupID: unix.Getpgrp(),
	}
	processBody, err := json.Marshal(processIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if installed, err := installRealCloudPrivateFileExclusive(filepath.Join(paths.directory, "process-identity.json"), append(processBody, '\n')); err != nil || !installed {
		t.Fatalf("install local detached process identity: installed=%v err=%v", installed, err)
	}
	key, _ := realCloudPurgeWatcherMACKey(realCloudPurgeWatcherTestTokenA, realCloudPurgeWatcherTestTokenB)
	spec, body, err := loadRealCloudPurgeWatcherSpec(paths.spec, key)
	if err != nil || realCloudLowerSHA256(body) != os.Getenv(realCloudPurgeWatcherSpecSHAEnv) {
		t.Fatal("local watcher spec changed")
	}
	wantedBody, err := readRealCloudPurgeWatcherPrivateFile(paths.body, realEdgeResponseLimit)
	if err != nil || realCloudLowerSHA256(wantedBody) != spec.ExpectedBodySHA256 {
		t.Fatal("local watcher expected body changed")
	}
	runtime := realCloudPurgeWatcherRuntime{
		clock: defaultRealCloudPurgeWatcherClock(),
		validateResources: func() error {
			installed, err := installRealCloudPrivateFileExclusive(filepath.Join(paths.directory, "resource-validated"), []byte("loopback-only\n"))
			if err != nil {
				return err
			}
			if !installed {
				return nil
			}
			return nil
		},
		loadPublication: func(target string, generation uint64) (realCloudPurgeWatcherPublication, error) {
			if _, err := os.Lstat(filepath.Join(paths.directory, "publication-ready")); errors.Is(err, os.ErrNotExist) {
				return realCloudPurgeWatcherPublication{}, errRealCloudPurgeWatcherPending
			} else if err != nil {
				return realCloudPurgeWatcherPublication{}, err
			}
			now := time.Now().UTC()
			return realCloudPurgeWatcherPublication{
				Target: target, Generation: generation, TransactionID: "tx-purge-watcher-g5-" + target,
				GatedBodySHA256: spec.ExpectedBodySHA256, GenerationSHA256: strings.Repeat("a", 64),
				CheckpointSHA256: strings.Repeat("b", 64), PurgeEvidenceSHA256: strings.Repeat("c", 64),
				PurgeCompletedAt: now.Add(-time.Millisecond),
			}, nil
		},
		observe: func(ctx context.Context, vendor realCloudPurgeWatcherVendorSpec, observer realCloudPurgeWatcherObserverSpec, _ time.Time) (realEdgeMultiPoPObservation, error) {
			started := time.Now().UTC()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, serverRaw+"/"+vendor.Vendor+"/"+observer.ID, nil)
			if err != nil {
				return realEdgeMultiPoPObservation{}, err
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				return realEdgeMultiPoPObservation{}, err
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, wantedBody) {
				return realEdgeMultiPoPObservation{}, errors.New("local watcher fake HTTP response mismatch")
			}
			observed := time.Now().UTC()
			cacheStatus, colo := "HIT", ""
			if observer.Role == "prime" {
				cacheStatus = "MISS"
			}
			if vendor.Vendor == "cloudflare" {
				colo = "SJC"
			}
			return realEdgeMultiPoPObservation{
				Vendor: vendor.Vendor, Role: observer.Role, ObserverID: observer.ID,
				RequestID: fmt.Sprintf("request-%s-%s-%d", vendor.Vendor, observer.ID, observed.UnixNano()), CloudflareColo: colo,
				CacheStatus: cacheStatus, Transport: "https-bearer", CleanURLSHA256: vendor.CleanURLSHA256,
				BodySHA256: realCloudLowerSHA256(body), CacheAgeSeconds: 1, CacheMaxAge: 60,
				RequestStarted: started, ResponseObserved: observed,
			}, nil
		},
	}
	if err := runRealCloudPurgeWatcher(t.Context(), paths, spec, key, runtime); err != nil {
		t.Fatal(err)
	}
}

func waitForRealCloudPurgeWatcherPath(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			return nil
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for purge watcher path %s", filepath.Base(path))
}
