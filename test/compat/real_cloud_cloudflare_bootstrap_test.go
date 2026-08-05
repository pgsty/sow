package compat_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	cloudflareapi "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/cloudflare-go/v7/workers"
	"github.com/pgsty/sow/internal/publish"
)

const (
	realCloudCloudflareBootstrapReceiptSchema      = "sow-real-cloud-cloudflare-bootstrap-receipt/v2"
	realCloudCloudflareBootstrapEnvelopeSchema     = "sow-real-cloud-cloudflare-bootstrap-receipt-envelope/v2"
	realCloudCloudflareBootstrapLeaseSchema        = "sow-real-cloud-cloudflare-bootstrap-lease/v3"
	realCloudCloudflareBootstrapIdleLeaseSchema    = "sow-real-cloud-cloudflare-bootstrap-idle-lease/v3"
	realCloudCloudflareLeaseRecoveryPendingSchema  = "sow-real-cloud-cloudflare-bootstrap-lease-recovery-pending/v1"
	realCloudCloudflareLeaseRecoverySchema         = "sow-real-cloud-cloudflare-bootstrap-lease-recovery/v3"
	realCloudCloudflareBootstrapRetirementRelease  = "release"
	realCloudCloudflareBootstrapRetirementRecovery = "recovery"
	realCloudCloudflareBootstrapMaxRecoveryLineage = 1024
	realCloudCloudflareBootstrapRecoveryReceiptMax = 1 << 20
	realCloudCloudflareBootstrapLeaseTTL           = 5 * time.Minute
	realCloudCloudflareMutationTimeout             = realCloudCloudflareBootstrapLeaseTTL / 3
)

type realCloudCloudflareBootstrapInventory struct {
	Workers            []string
	Routes             []realCloudCloudflareBootstrapInventoryRoute
	DomainServices     []string
	ManagedAttachments []string
}

type realCloudCloudflareBootstrapInventoryRoute struct {
	ID      string
	Pattern string
	Script  string
}

type realCloudCloudflareBootstrapWorkerState struct {
	Script             string
	DeploymentID       string
	VersionID          string
	VersionETag        string
	ContentSHA256      string
	BindingsSHA256     string
	OwnershipMessage   string
	OwnershipTag       string
	CompatibilityDate  string
	CompatibilityFlags []string
	ExposureDisabled   bool
}

type realCloudCloudflareBootstrapSecurityObservation struct {
	OwnershipMessage   string
	OwnershipTag       string
	CompatibilityDate  string
	CompatibilityFlags []string
	LogpushEnabled     bool
	ExposureDisabled   bool
	Digest             string
}

type realCloudCloudflareBootstrapControl interface {
	Inventory(context.Context, realCloudCloudflareBootstrapPlan) (realCloudCloudflareBootstrapInventory, error)
	Inspect(context.Context, realCloudCloudflareBootstrapPlan, string) (realCloudCloudflareBootstrapWorkerState, error)
	Upload(context.Context, realCloudCloudflareBootstrapPlan, string, string, string) error
	DisableExposure(context.Context, realCloudCloudflareBootstrapPlan, string) error
	CreateRoute(context.Context, realCloudCloudflareBootstrapPlan, realCloudCloudflareBootstrapRoute) (string, error)
	DeleteRouteIfMatch(context.Context, realCloudCloudflareBootstrapPlan, realCloudCloudflareBootstrapInventoryRoute) error
	DeleteScriptIfMatch(context.Context, realCloudCloudflareBootstrapPlan, string, string, realCloudCloudflareBootstrapReceiptWorker) error
}

type realCloudCloudflareBootstrapReceipt struct {
	Schema                  string                                     `json:"schema"`
	RunID                   string                                     `json:"run_id"`
	Mode                    string                                     `json:"mode"`
	ReadinessResourceSHA256 string                                     `json:"readiness_resource_sha256"`
	PlanSHA256              string                                     `json:"plan_sha256"`
	AccountID               string                                     `json:"account_id"`
	ZoneID                  string                                     `json:"zone_id"`
	Auth                    realCloudCloudflareBootstrapReceiptWorker  `json:"auth"`
	Origin                  realCloudCloudflareBootstrapReceiptWorker  `json:"origin"`
	Verifier                realCloudCloudflareBootstrapReceiptWorker  `json:"verifier"`
	Routes                  []realCloudCloudflareBootstrapReceiptRoute `json:"routes"`
	ClosureSHA256           string                                     `json:"closure_sha256"`
	ObservedAt              string                                     `json:"observed_at"`
}

type realCloudCloudflareBootstrapReceiptWorker struct {
	Script           string `json:"script"`
	DeploymentID     string `json:"deployment_id"`
	VersionID        string `json:"version_id"`
	VersionETag      string `json:"version_etag"`
	ContentSHA256    string `json:"content_sha256"`
	BindingsSHA256   string `json:"bindings_sha256"`
	OwnershipMessage string `json:"ownership_message"`
	OwnershipTag     string `json:"ownership_tag"`
}

type realCloudCloudflareBootstrapReceiptRoute struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	Script  string `json:"script"`
}

type realCloudCloudflareBootstrapEnvelope struct {
	Schema        string                              `json:"schema"`
	Receipt       realCloudCloudflareBootstrapReceipt `json:"receipt"`
	ReceiptSHA256 string                              `json:"receipt_sha256"`
	ReceiptSize   int                                 `json:"receipt_size"`
}

type realCloudCloudflareBootstrapLease struct {
	Schema                  string                                        `json:"schema"`
	RunID                   string                                        `json:"run_id"`
	Mode                    string                                        `json:"mode"`
	ReadinessResourceSHA256 string                                        `json:"readiness_resource_sha256"`
	PlanSHA256              string                                        `json:"plan_sha256"`
	AccountID               string                                        `json:"account_id"`
	ZoneID                  string                                        `json:"zone_id"`
	Holder                  string                                        `json:"holder"`
	RecoveryLineage         []realCloudCloudflareBootstrapRecoveryLineage `json:"recovery_lineage"`
	AcquiredAt              string                                        `json:"acquired_at"`
	ExpiresAt               string                                        `json:"expires_at"`
}

type realCloudCloudflareBootstrapRecoveryLineage struct {
	PendingSHA256 string `json:"pending_sha256"`
	ReceiptSHA256 string `json:"receipt_sha256"`
}

// realCloudCloudflareBootstrapIdleLease is the durable, non-owning state of
// the bootstrap serialization key. R2 does not implement conditional DELETE,
// so a holder releases ownership by compare-and-setting its exact live lease
// to this marker. No SOW path deletes or renews an idle marker; the next holder
// may only replace it with another compare-and-set PUT.
type realCloudCloudflareBootstrapIdleLease struct {
	Schema                  string                            `json:"schema"`
	ReadinessResourceSHA256 string                            `json:"readiness_resource_sha256"`
	PlanSHA256              string                            `json:"plan_sha256"`
	AccountID               string                            `json:"account_id"`
	ZoneID                  string                            `json:"zone_id"`
	Retirement              string                            `json:"retirement"`
	RecoveryPendingSHA256   string                            `json:"recovery_pending_sha256"`
	RecoveryReceiptSHA256   string                            `json:"recovery_receipt_sha256"`
	PreviousLease           realCloudCloudflareBootstrapLease `json:"previous_lease"`
	PreviousLeaseSHA256     string                            `json:"previous_lease_sha256"`
}

// realCloudCloudflareBootstrapLeaseRecoveryPending is an owning fencing
// record. It deliberately has no takeover timeout: only the exact recovery
// run and plan may resume it, persist its local receipt, and CAS it to idle.
type realCloudCloudflareBootstrapLeaseRecoveryPending struct {
	Schema                  string                            `json:"schema"`
	RecoveryRunID           string                            `json:"recovery_run_id"`
	RecoveryPlanSHA256      string                            `json:"recovery_plan_sha256"`
	ReadinessResourceSHA256 string                            `json:"readiness_resource_sha256"`
	AccountID               string                            `json:"account_id"`
	ZoneID                  string                            `json:"zone_id"`
	RecoveredLease          realCloudCloudflareBootstrapLease `json:"recovered_lease"`
	RecoveredLeaseSHA256    string                            `json:"recovered_lease_sha256"`
	StartedAt               string                            `json:"started_at"`
}

type realCloudCloudflareBootstrapLeaseStore interface {
	R2GetControl(context.Context, string) (publish.ControlObject, error)
	R2ListObjectsV2(context.Context, string) (publish.ObjectListPage, error)
	R2Put(context.Context, string, io.Reader, int64, string, publish.R2PutCondition) (string, error)
}

type realCloudCloudflareBootstrapHeldLease struct {
	store realCloudCloudflareBootstrapLeaseStore
	key   string
	lease realCloudCloudflareBootstrapLease
	etag  string
}

type realCloudCloudflareBootstrapLeaseRecoveryReceipt struct {
	Schema                   string                            `json:"schema"`
	RunID                    string                            `json:"run_id"`
	PlanSHA256               string                            `json:"plan_sha256"`
	AccountID                string                            `json:"account_id"`
	ZoneID                   string                            `json:"zone_id"`
	RecoveryPendingSHA256    string                            `json:"recovery_pending_sha256"`
	RecoveredLease           realCloudCloudflareBootstrapLease `json:"recovered_lease"`
	RecoveredLeaseRun        string                            `json:"recovered_lease_run"`
	RecoveredLeasePlanSHA256 string                            `json:"recovered_lease_plan_sha256"`
	RecoveredLeaseSHA256     string                            `json:"recovered_lease_sha256"`
	RecoveredMode            string                            `json:"recovered_mode"`
	LeaseHolderSHA256        string                            `json:"lease_holder_sha256"`
	LeaseExpiredAt           string                            `json:"lease_expired_at"`
	RecoveryStartedAt        string                            `json:"recovery_started_at"`
}

type realCloudCloudflareSDKBootstrapControl struct {
	client         *cloudflareapi.Client
	secretBindings map[string]string
}

type realCloudCloudflareStaticEntitlement struct {
	SHA256       string   `json:"sha256"`
	ExpiresAt    string   `json:"expires_at"`
	Audiences    []string `json:"audiences"`
	PathPrefixes []string `json:"path_prefixes"`
}

const (
	// Cloudflare Workers limits every environment variable, including
	// secret_text, to 5 KB. Use the decimal interpretation so the local gate is
	// never more permissive than the provider's published boundary.
	realCloudCloudflareStaticSecretMaxBytes = 5000
	// Leave enough lifetime for bounded upload, exposure, route, and repeated
	// closure observations instead of sealing an already-expiring deployment.
	realCloudCloudflareStaticEntitlementMinTTL = 15 * time.Minute
)

var realCloudCloudflareStaticAudiencePattern = regexp.MustCompile(`^[a-z0-9.-]+$`)
var realCloudCloudflareStaticPathPattern = regexp.MustCompile(`^/(?:[A-Za-z0-9+._~^:-]+(?:/[A-Za-z0-9+._~^:-]+)*)?$`)

type realCloudCloudflareLeasedBootstrapControl struct {
	inner           realCloudCloudflareBootstrapControl
	lease           *realCloudCloudflareBootstrapHeldLease
	now             func() time.Time
	providerClosure func(context.Context) error
}

func newRealCloudCloudflareLeasedBootstrapControl(ctx context.Context, inner realCloudCloudflareBootstrapControl, lease *realCloudCloudflareBootstrapHeldLease, now func() time.Time, providerClosure func(context.Context) error) (*realCloudCloudflareLeasedBootstrapControl, error) {
	if inner == nil || lease == nil || now == nil {
		return nil, errors.New("Cloudflare bootstrap leased control is invalid")
	}
	if err := validateRealCloudCloudflareBootstrapLeasedBucketClosure(ctx, lease); err != nil {
		return nil, err
	}
	if providerClosure != nil {
		if err := providerClosure(ctx); err != nil {
			return nil, fmt.Errorf("Cloudflare bootstrap provider closure changed after readiness: %w", err)
		}
	}
	return &realCloudCloudflareLeasedBootstrapControl{inner: inner, lease: lease, now: now, providerClosure: providerClosure}, nil
}

func (control *realCloudCloudflareLeasedBootstrapControl) Inventory(ctx context.Context, plan realCloudCloudflareBootstrapPlan) (realCloudCloudflareBootstrapInventory, error) {
	return control.inner.Inventory(ctx, plan)
}

func (control *realCloudCloudflareLeasedBootstrapControl) Inspect(ctx context.Context, plan realCloudCloudflareBootstrapPlan, role string) (realCloudCloudflareBootstrapWorkerState, error) {
	return control.inner.Inspect(ctx, plan, role)
}

func (control *realCloudCloudflareLeasedBootstrapControl) renew(ctx context.Context) error {
	if control == nil || control.inner == nil || control.lease == nil || control.now == nil {
		return errors.New("Cloudflare bootstrap leased control is invalid")
	}
	if err := control.lease.renew(ctx, control.now()); err != nil {
		return err
	}
	if err := validateRealCloudCloudflareBootstrapLeasedBucketClosure(ctx, control.lease); err != nil {
		return err
	}
	if control.providerClosure != nil {
		if err := control.providerClosure(ctx); err != nil {
			return fmt.Errorf("Cloudflare bootstrap provider closure changed before mutation: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.New("Cloudflare bootstrap pre-mutation closure exceeded the lease-safe deadline")
	}
	if err := control.lease.requireMutationBudget(control.now(), realCloudCloudflareMutationTimeout); err != nil {
		return err
	}
	return nil
}

func (control *realCloudCloudflareLeasedBootstrapControl) Upload(ctx context.Context, plan realCloudCloudflareBootstrapPlan, role, planSHA, runID string) error {
	ctx, cancel := context.WithTimeout(ctx, realCloudCloudflareMutationTimeout)
	defer cancel()
	if err := control.renew(ctx); err != nil {
		return err
	}
	return control.inner.Upload(ctx, plan, role, planSHA, runID)
}

func (control *realCloudCloudflareLeasedBootstrapControl) DisableExposure(ctx context.Context, plan realCloudCloudflareBootstrapPlan, script string) error {
	ctx, cancel := context.WithTimeout(ctx, realCloudCloudflareMutationTimeout)
	defer cancel()
	if err := control.renew(ctx); err != nil {
		return err
	}
	return control.inner.DisableExposure(ctx, plan, script)
}

func (control *realCloudCloudflareLeasedBootstrapControl) CreateRoute(ctx context.Context, plan realCloudCloudflareBootstrapPlan, route realCloudCloudflareBootstrapRoute) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, realCloudCloudflareMutationTimeout)
	defer cancel()
	if err := control.renew(ctx); err != nil {
		return "", err
	}
	return control.inner.CreateRoute(ctx, plan, route)
}

func (control *realCloudCloudflareLeasedBootstrapControl) DeleteRouteIfMatch(ctx context.Context, plan realCloudCloudflareBootstrapPlan, expected realCloudCloudflareBootstrapInventoryRoute) error {
	ctx, cancel := context.WithTimeout(ctx, realCloudCloudflareMutationTimeout)
	defer cancel()
	if err := control.renew(ctx); err != nil {
		return err
	}
	return control.inner.DeleteRouteIfMatch(ctx, plan, expected)
}

func (control *realCloudCloudflareLeasedBootstrapControl) DeleteScriptIfMatch(ctx context.Context, plan realCloudCloudflareBootstrapPlan, role, runID string, expected realCloudCloudflareBootstrapReceiptWorker) error {
	ctx, cancel := context.WithTimeout(ctx, realCloudCloudflareMutationTimeout)
	defer cancel()
	if err := control.renew(ctx); err != nil {
		return err
	}
	return control.inner.DeleteScriptIfMatch(ctx, plan, role, runID, expected)
}

type realCloudCloudflareBootstrapFile struct {
	*bytes.Reader
	filename    string
	contentType string
}

func (file *realCloudCloudflareBootstrapFile) Filename() string    { return file.filename }
func (file *realCloudCloudflareBootstrapFile) ContentType() string { return file.contentType }

func newRealCloudCloudflareSDKBootstrapControl(apiToken, baseURL string, client *http.Client, secretSets ...map[string]string) (*realCloudCloudflareSDKBootstrapControl, error) {
	if strings.TrimSpace(apiToken) == "" || apiToken != strings.TrimSpace(apiToken) {
		return nil, errors.New("Cloudflare bootstrap API token is empty or non-canonical")
	}
	if len(secretSets) > 1 {
		return nil, errors.New("Cloudflare bootstrap accepts at most one secret binding set")
	}
	if baseURL == "" {
		baseURL = "https://api.cloudflare.com/client/v4"
	}
	canonical, err := canonicalRealCloudProviderAPIBase(baseURL, strings.HasPrefix(baseURL, "http://127.0.0.1:") || strings.HasPrefix(baseURL, "http://localhost:"))
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = realCloudProviderHTTPClient()
	}
	secrets := make(map[string]string)
	if len(secretSets) == 1 {
		for name, value := range secretSets[0] {
			if !validRealCloudCloudflareStaticSecretName(name) || value == "" {
				return nil, errors.New("Cloudflare bootstrap secret binding set is invalid")
			}
			secrets[name] = value
		}
	}
	return &realCloudCloudflareSDKBootstrapControl{client: cloudflareapi.NewClient(
		option.WithBaseURL(strings.TrimSuffix(canonical, "/")+"/"), option.WithAPIToken(apiToken),
		option.WithHTTPClient(client), option.WithMaxRetries(0),
	), secretBindings: secrets}, nil
}

func realCloudCloudflareBootstrapUsesProvider(plan realCloudCloudflareBootstrapPlan) bool {
	return plan.TokenVerifierKind == "provider"
}

func realCloudCloudflareBootstrapManagedWorkers(plan realCloudCloudflareBootstrapPlan) map[string]bool {
	workers := map[string]bool{plan.AuthScript: false, plan.OriginScript: false}
	if realCloudCloudflareBootstrapUsesProvider(plan) {
		workers[plan.TokenVerifierService] = false
	}
	return workers
}

func validateRealCloudCloudflareStaticEntitlements(raw string, plan realCloudCloudflareBootstrapPlan, now time.Time) error {
	if plan.TokenVerifierKind != "env" || !validRealCloudCloudflareStaticSecretName(plan.TokenVerifierSecret) ||
		raw == "" || len(raw) > realCloudCloudflareStaticSecretMaxBytes || raw != strings.TrimSpace(raw) {
		return errors.New("Cloudflare bootstrap static entitlement secret is absent, oversized, or non-canonical")
	}
	var entries []realCloudCloudflareStaticEntitlement
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entries); err != nil {
		return errors.New("Cloudflare bootstrap static entitlement secret is not strict JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || len(entries) == 0 || len(entries) > 10000 {
		return errors.New("Cloudflare bootstrap static entitlement secret has an invalid document closure")
	}
	mainAudience := strings.TrimPrefix(plan.MainBase, "https://")
	betaAudience := strings.TrimPrefix(plan.BetaBase, "https://")
	previousSHA := ""
	for _, entry := range entries {
		if !validRealCloudLowerSHA256(entry.SHA256) || entry.SHA256 <= previousSHA {
			return errors.New("Cloudflare bootstrap static entitlements are not strictly sorted and unique")
		}
		previousSHA = entry.SHA256
		expires, err := time.Parse("2006-01-02T15:04:05Z", entry.ExpiresAt)
		if err != nil || expires.Format("2006-01-02T15:04:05Z") != entry.ExpiresAt || expires.Before(now.UTC().Add(realCloudCloudflareStaticEntitlementMinTTL)) {
			return errors.New("Cloudflare bootstrap static entitlement expiry is invalid or not live")
		}
		if len(entry.Audiences) == 0 || len(entry.PathPrefixes) == 0 {
			return errors.New("Cloudflare bootstrap static entitlement scope is empty")
		}
		for index, audience := range entry.Audiences {
			if !realCloudCloudflareStaticAudiencePattern.MatchString(audience) || audience != mainAudience && audience != betaAudience ||
				index > 0 && audience <= entry.Audiences[index-1] {
				return errors.New("Cloudflare bootstrap static entitlement audience is outside the exact test hosts or non-canonical")
			}
		}
		for index, prefix := range entry.PathPrefixes {
			if !realCloudCloudflareStaticPathPattern.MatchString(prefix) || index > 0 && prefix <= entry.PathPrefixes[index-1] {
				return errors.New("Cloudflare bootstrap static entitlement path scope is invalid or non-canonical")
			}
		}
	}
	canonical, err := json.Marshal(entries)
	if err != nil || raw != string(canonical) {
		return errors.New("Cloudflare bootstrap static entitlement secret must be canonical compact JSON")
	}
	return nil
}

func realCloudCloudflareStaticSecretFragments(raw string) []string {
	fragments := realCloudScopedSecretFragments(raw)
	for index := 0; index+64 <= len(raw); index++ {
		candidate := raw[index : index+64]
		if validRealCloudLowerSHA256(candidate) {
			fragments = append(fragments, candidate)
			index += 63
		}
	}
	return fragments
}

func bindRealCloudCloudflareStaticEntitlement(control *realCloudCloudflareSDKBootstrapControl, plan realCloudCloudflareBootstrapPlan, raw string, now time.Time) error {
	if control == nil || control.client == nil || plan.TokenVerifierKind != "env" || len(control.secretBindings) != 0 {
		return errors.New("Cloudflare bootstrap static entitlement binding state is invalid")
	}
	if err := validateRealCloudCloudflareStaticEntitlements(raw, plan, now); err != nil {
		return err
	}
	control.secretBindings[plan.TokenVerifierSecret] = raw
	return nil
}

func newRealCloudCloudflareBootstrapLeaseStore(resource realCloudProviderReadinessResource, plan realCloudCloudflareBootstrapPlan, storage realCloudStorageSecret, client *http.Client) (*publish.R2CloudflareControlHTTP, error) {
	if resource.Provider != "cloudflare" || resource.Cloudflare == nil || resource.EdgeOne != nil ||
		resource.Cloudflare.R2Bucket != plan.R2Bucket || resource.Cloudflare.AccountID != plan.AccountID || resource.Cloudflare.ZoneID != plan.ZoneID ||
		strings.TrimSpace(storage.AccessKeyID) == "" || strings.TrimSpace(storage.SecretAccessKey) == "" {
		return nil, errors.New("Cloudflare bootstrap lease store identity or credentials are invalid")
	}
	return publish.NewR2CloudflareControlHTTP(publish.R2CloudflareControlHTTPConfig{
		Bucket: plan.R2Bucket, ObjectBaseURL: realCloudProviderBucketBaseURL(resource.Cloudflare.R2Endpoint, plan.R2Bucket),
		Credentials: publish.S3Credentials{
			AccessKeyID: storage.AccessKeyID, SecretAccessKey: storage.SecretAccessKey, SessionToken: storage.SessionToken, Region: "auto",
		},
		Client: client,
	})
}

type realCloudCloudflareBootstrapRuntime struct {
	leaseStore      realCloudCloudflareBootstrapLeaseStore
	control         *realCloudCloudflareSDKBootstrapControl
	secretFragments []string
}

func newRealCloudCloudflareBootstrapRuntime(
	mode string,
	resource realCloudProviderReadinessResource,
	plan realCloudCloudflareBootstrapPlan,
	getenv func(string) string,
	apiBase string,
	client *http.Client,
) (realCloudCloudflareBootstrapRuntime, error) {
	var runtime realCloudCloudflareBootstrapRuntime
	if mode != "apply" && mode != "rollback" && mode != "recover-lease" || getenv == nil {
		return runtime, errors.New("Cloudflare bootstrap runtime mode or environment is invalid")
	}
	storageRaw := getenv(realCloudStorageCredentialCF)
	storage, err := decodeRealCloudProviderSecret[realCloudStorageSecret](storageRaw)
	if err != nil || strings.TrimSpace(storage.AccessKeyID) == "" || strings.TrimSpace(storage.SecretAccessKey) == "" {
		return runtime, errors.New("Cloudflare bootstrap storage credential is absent or invalid")
	}
	runtime.secretFragments = realCloudScopedSecretFragments(storageRaw)
	runtime.leaseStore, err = newRealCloudCloudflareBootstrapLeaseStore(resource, plan, storage, client)
	if err != nil {
		return runtime, errors.New("construct Cloudflare bootstrap R2 lease client")
	}
	if mode == "recover-lease" {
		return runtime, nil
	}
	apiRaw := getenv(realCloudCDNCredentialCF)
	api, err := decodeRealCloudProviderSecret[realCloudCloudflareSecret](apiRaw)
	if err != nil || strings.TrimSpace(api.APIToken) == "" {
		return runtime, errors.New("Cloudflare bootstrap API credential is absent or invalid")
	}
	runtime.secretFragments = realCloudScopedSecretFragments(storageRaw, apiRaw)
	runtime.control, err = newRealCloudCloudflareSDKBootstrapControl(api.APIToken, apiBase, client)
	if err != nil {
		return runtime, errors.New("construct Cloudflare bootstrap Worker client")
	}
	return runtime, nil
}

func (control *realCloudCloudflareSDKBootstrapControl) Inventory(ctx context.Context, plan realCloudCloudflareBootstrapPlan) (realCloudCloudflareBootstrapInventory, error) {
	var inventory realCloudCloudflareBootstrapInventory
	if control == nil || control.client == nil {
		return inventory, errors.New("Cloudflare bootstrap client is absent")
	}
	managedWorkers := realCloudCloudflareBootstrapManagedWorkers(plan)
	workerPager := control.client.Workers.Scripts.ListAutoPaging(ctx, workers.ScriptListParams{AccountID: cloudflareapi.F(plan.AccountID)})
	for workerPager.Next() {
		if workerPager.Index() > realCloudProviderMaxInventoryItems {
			return inventory, errors.New("Cloudflare Worker inventory exceeds the safety bound")
		}
		worker := workerPager.Current()
		inventory.Workers = append(inventory.Workers, worker.ID)
		if _, managed := managedWorkers[worker.ID]; managed {
			if len(worker.TailConsumers) != 0 {
				inventory.ManagedAttachments = append(inventory.ManagedAttachments, worker.ID+"\x00tail-consumer")
			}
			schedules, err := control.client.Workers.Scripts.Schedules.Get(ctx, worker.ID, workers.ScriptScheduleGetParams{AccountID: cloudflareapi.F(plan.AccountID)})
			if err != nil || schedules == nil {
				return inventory, errors.New("query Cloudflare bootstrap Worker schedule inventory")
			}
			if len(schedules.Schedules) != 0 {
				inventory.ManagedAttachments = append(inventory.ManagedAttachments, worker.ID+"\x00schedule")
			}
		}
	}
	if err := workerPager.Err(); err != nil {
		return inventory, errors.New("list Cloudflare bootstrap Worker inventory")
	}
	routePager := control.client.Workers.Routes.ListAutoPaging(ctx, workers.RouteListParams{ZoneID: cloudflareapi.F(plan.ZoneID)})
	for routePager.Next() {
		if routePager.Index() > realCloudProviderMaxInventoryItems {
			return inventory, errors.New("Cloudflare route inventory exceeds the safety bound")
		}
		route := routePager.Current()
		inventory.Routes = append(inventory.Routes, realCloudCloudflareBootstrapInventoryRoute{ID: route.ID, Pattern: route.Pattern, Script: route.Script})
	}
	if err := routePager.Err(); err != nil {
		return inventory, errors.New("list Cloudflare bootstrap route inventory")
	}
	domainPager := control.client.Workers.Domains.ListAutoPaging(ctx, workers.DomainListParams{AccountID: cloudflareapi.F(plan.AccountID)})
	for domainPager.Next() {
		if domainPager.Index() > realCloudProviderMaxInventoryItems {
			return inventory, errors.New("Cloudflare Worker custom-domain inventory exceeds the safety bound")
		}
		domain := domainPager.Current()
		if !validRealCloudProviderIdentifier(domain.ID, 128) || !validRealCloudProviderIdentifier(domain.Service, 128) ||
			!validRealCloudProviderIdentifier(domain.ZoneID, 128) || strings.TrimSpace(domain.Hostname) == "" ||
			strings.HasSuffix(domain.Hostname, ".") || strings.TrimSpace(domain.ZoneName) == "" {
			return inventory, errors.New("Cloudflare Worker custom-domain inventory contains an incomplete identity")
		}
		inventory.DomainServices = append(inventory.DomainServices, domain.Service)
	}
	if err := domainPager.Err(); err != nil {
		return inventory, errors.New("list Cloudflare bootstrap custom-domain inventory")
	}
	sort.Strings(inventory.Workers)
	sort.Slice(inventory.Routes, func(i, j int) bool {
		left := inventory.Routes[i].Pattern + "\x00" + inventory.Routes[i].ID
		right := inventory.Routes[j].Pattern + "\x00" + inventory.Routes[j].ID
		return left < right
	})
	sort.Strings(inventory.DomainServices)
	sort.Strings(inventory.ManagedAttachments)
	return inventory, nil
}

func (control *realCloudCloudflareSDKBootstrapControl) Inspect(ctx context.Context, plan realCloudCloudflareBootstrapPlan, role string) (realCloudCloudflareBootstrapWorkerState, error) {
	var state realCloudCloudflareBootstrapWorkerState
	if control == nil || control.client == nil {
		return state, errors.New("Cloudflare bootstrap client is absent")
	}
	var script, repositoryBundle, expectedSHA string
	var runtimeContract realCloudCloudflareWorkerRuntimeContract
	switch role {
	case "auth":
		script, repositoryBundle = plan.AuthScript, plan.AuthBundle.Path
		runtimeContract = realCloudCloudflareWorkerRuntimeContract{CompatibilityDate: plan.CompatibilityDate, CompatibilityFlags: append([]string(nil), plan.CompatibilityFlags...)}
	case "origin":
		script, repositoryBundle = plan.OriginScript, plan.OriginBundle.Path
		runtimeContract = realCloudCloudflareWorkerRuntimeContract{CompatibilityDate: plan.CompatibilityDate, CompatibilityFlags: append([]string(nil), plan.CompatibilityFlags...)}
	case "verifier":
		if !realCloudCloudflareBootstrapUsesProvider(plan) {
			return state, errors.New("static Cloudflare bootstrap has no token-verifier Worker")
		}
		script, expectedSHA = plan.TokenVerifierService, plan.TokenVerifierContentSHA256
		runtimeContract = realCloudCloudflareWorkerRuntimeContract{CompatibilityDate: plan.TokenVerifierCompatibilityDate, CompatibilityFlags: append([]string(nil), plan.TokenVerifierCompatibilityFlags...)}
	default:
		return state, errors.New("unknown Cloudflare bootstrap Worker role")
	}
	evidence, err := collectRealCloudCloudflareActiveWorker(ctx, control.client, plan.AccountID, script, repositoryBundle, expectedSHA, runtimeContract, false, false)
	if err != nil {
		return state, err
	}
	var bindingsSHA string
	switch role {
	case "auth":
		bindingsSHA, err = validateRealCloudCloudflareBootstrapAuthBindings(evidence.bindings, plan)
	case "origin":
		bindingsSHA, err = validateRealCloudCloudflareOriginBindings(evidence.bindings, plan.R2Bucket)
	case "verifier":
		bindingsSHA, err = validateRealCloudCloudflareVerifierBindings(evidence.bindings)
		if err == nil && bindingsSHA != plan.TokenVerifierBindingsSHA256 {
			err = errors.New("Cloudflare token verifier bindings differ from the bootstrap plan")
		}
	}
	if err != nil {
		return state, err
	}
	security, err := control.inspectSecurityObservation(ctx, plan, role, script)
	if err != nil {
		return state, err
	}
	stableSecurity, err := control.inspectSecurityObservation(ctx, plan, role, script)
	if err != nil || stableSecurity.Digest != security.Digest {
		return state, errors.New("Cloudflare bootstrap Worker settings or exposure changed while inspected")
	}
	recheck, err := control.client.Workers.Scripts.Deployments.List(ctx, script, workers.ScriptDeploymentListParams{AccountID: cloudflareapi.F(plan.AccountID)})
	if err != nil {
		return state, errors.New("recheck Cloudflare bootstrap Worker after settings and exposure inspection")
	}
	deploymentID, versionID, err := exactRealCloudCloudflareDeployment(recheck)
	if err != nil || deploymentID != evidence.deploymentID || versionID != evidence.versionID {
		return state, errors.New("Cloudflare bootstrap Worker changed while settings and exposure were inspected")
	}
	state = realCloudCloudflareBootstrapWorkerState{
		Script: script, DeploymentID: evidence.deploymentID, VersionID: evidence.versionID, VersionETag: evidence.versionETag,
		ContentSHA256: evidence.contentSHA, BindingsSHA256: bindingsSHA, CompatibilityDate: evidence.compatibilityDate,
		CompatibilityFlags: append([]string(nil), evidence.compatibilityFlags...), ExposureDisabled: security.ExposureDisabled,
	}
	if role != "verifier" {
		state.OwnershipMessage, state.OwnershipTag = security.OwnershipMessage, security.OwnershipTag
	}
	return state, nil
}

func (control *realCloudCloudflareSDKBootstrapControl) inspectSecurityObservation(ctx context.Context, plan realCloudCloudflareBootstrapPlan, role, script string) (realCloudCloudflareBootstrapSecurityObservation, error) {
	var observation realCloudCloudflareBootstrapSecurityObservation
	settings, err := control.client.Workers.Scripts.ScriptAndVersionSettings.Get(ctx, script, workers.ScriptScriptAndVersionSettingGetParams{
		AccountID: cloudflareapi.F(plan.AccountID),
	})
	if err != nil || settings == nil {
		return observation, errors.New("query Cloudflare bootstrap Worker security settings")
	}
	expectedDate, expectedFlags := plan.CompatibilityDate, plan.CompatibilityFlags
	if role == "verifier" {
		if !realCloudCloudflareBootstrapUsesProvider(plan) {
			return observation, errors.New("static Cloudflare bootstrap has no token-verifier Worker settings")
		}
		expectedDate, expectedFlags = plan.TokenVerifierCompatibilityDate, plan.TokenVerifierCompatibilityFlags
	}
	expectedLogpush := false
	if settings.CompatibilityDate != expectedDate || !equalRealCloudStrings(settings.CompatibilityFlags, expectedFlags) ||
		settings.Logpush != expectedLogpush || settings.CacheOptions.Enabled || settings.CacheOptions.CrossVersionCache ||
		settings.Limits.CPUMs != 0 || settings.Limits.Subrequests != 0 ||
		settings.Placement.Mode != "" || settings.Placement.Host != "" || settings.Placement.Hostname != "" || settings.Placement.Region != "" || settings.Placement.Target != nil ||
		settings.UsageModel != workers.ScriptScriptAndVersionSettingGetResponseUsageModelStandard ||
		settings.Observability.Enabled || settings.Observability.Logs.Enabled || settings.Observability.Logs.InvocationLogs ||
		settings.Observability.Logs.Persist || len(settings.Observability.Logs.Destinations) != 0 ||
		settings.Observability.Traces.Enabled || settings.Observability.Traces.Persist || len(settings.Observability.Traces.Destinations) != 0 ||
		len(settings.Tags) != 0 || len(settings.TailConsumers) != 0 {
		return observation, errors.New("Cloudflare bootstrap Worker settings differ from the closed runtime and telemetry policy")
	}
	exposure, err := control.client.Workers.Scripts.Subdomain.Get(ctx, script, workers.ScriptSubdomainGetParams{AccountID: cloudflareapi.F(plan.AccountID)})
	if err != nil || exposure == nil {
		return observation, errors.New("query Cloudflare Worker public exposure")
	}
	observation = realCloudCloudflareBootstrapSecurityObservation{
		OwnershipMessage: settings.Annotations.WorkersMessage, OwnershipTag: settings.Annotations.WorkersTag,
		CompatibilityDate: settings.CompatibilityDate, CompatibilityFlags: append([]string(nil), settings.CompatibilityFlags...),
		LogpushEnabled: settings.Logpush, ExposureDisabled: !exposure.Enabled && !exposure.PreviewsEnabled,
	}
	body, _ := json.Marshal(observation)
	observation.Digest = realCloudLowerSHA256(body)
	return observation, nil
}

func equalRealCloudStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func realCloudCloudflareBootstrapOwnershipAnnotations(plan realCloudCloudflareBootstrapPlan, runID string) (string, string) {
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	runSHA := realCloudLowerSHA256([]byte(runID))
	return "SOW non-production bootstrap run " + runID + " plan " + planSHA, planSHA[:16] + "-" + runSHA[:15]
}

func realCloudCloudflareBootstrapPlanSHA(plan realCloudCloudflareBootstrapPlan) string {
	body, _ := json.Marshal(plan)
	return realCloudLowerSHA256(body)
}

func realCloudCloudflareBootstrapLeaseKey(readinessResourceSHA string) (string, error) {
	if !validRealCloudLowerSHA256(readinessResourceSHA) {
		return "", errors.New("Cloudflare bootstrap lease readiness-resource digest is invalid")
	}
	return ".sow/bootstrap/leases/" + readinessResourceSHA + ".json", nil
}

func validateRealCloudCloudflareBootstrapReadinessMarkerResource(receipt realCloudProviderReadinessReceipt, plan realCloudCloudflareBootstrapPlan) error {
	key, err := realCloudCloudflareBootstrapLeaseKey(plan.ReadinessResourceSHA256)
	if err != nil {
		return err
	}
	if receipt.BucketControlObjectCount == 0 && receipt.BucketControlObjectKey == "" {
		return nil
	}
	if receipt.BucketControlObjectCount == 1 && receipt.BucketControlObjectKey == key {
		return nil
	}
	return errors.New("Cloudflare bootstrap readiness idle marker belongs to another readiness resource")
}

func newRealCloudCloudflareBootstrapLeaseHolder() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", errors.New("generate Cloudflare bootstrap lease holder")
	}
	return fmt.Sprintf("%x", nonce[:]), nil
}

func validateRealCloudCloudflareBootstrapRecoveryLineage(lineage []realCloudCloudflareBootstrapRecoveryLineage) error {
	if lineage == nil || len(lineage) > realCloudCloudflareBootstrapMaxRecoveryLineage {
		return errors.New("Cloudflare bootstrap lease recovery lineage is invalid")
	}
	seen := make(map[realCloudCloudflareBootstrapRecoveryLineage]struct{}, len(lineage))
	for _, entry := range lineage {
		if !validRealCloudLowerSHA256(entry.PendingSHA256) || !validRealCloudLowerSHA256(entry.ReceiptSHA256) {
			return errors.New("Cloudflare bootstrap lease recovery lineage is invalid")
		}
		if _, duplicate := seen[entry]; duplicate {
			return errors.New("Cloudflare bootstrap lease recovery lineage repeats an entry")
		}
		seen[entry] = struct{}{}
	}
	return nil
}

func appendRealCloudCloudflareBootstrapRecoveryLineage(
	lineage []realCloudCloudflareBootstrapRecoveryLineage,
	pendingSHA, receiptSHA string,
) ([]realCloudCloudflareBootstrapRecoveryLineage, error) {
	if err := validateRealCloudCloudflareBootstrapRecoveryLineage(lineage); err != nil ||
		!validRealCloudLowerSHA256(pendingSHA) || !validRealCloudLowerSHA256(receiptSHA) ||
		len(lineage) >= realCloudCloudflareBootstrapMaxRecoveryLineage {
		return nil, errors.New("Cloudflare bootstrap lease recovery lineage cannot append another entry")
	}
	next := make([]realCloudCloudflareBootstrapRecoveryLineage, len(lineage), len(lineage)+1)
	copy(next, lineage)
	entry := realCloudCloudflareBootstrapRecoveryLineage{PendingSHA256: pendingSHA, ReceiptSHA256: receiptSHA}
	for _, existing := range next {
		if existing == entry {
			return nil, errors.New("Cloudflare bootstrap lease recovery lineage already contains this entry")
		}
	}
	return append(next, entry), nil
}

func realCloudCloudflareBootstrapRecoveryLineageContains(
	lineage []realCloudCloudflareBootstrapRecoveryLineage,
	pendingSHA, receiptSHA string,
) bool {
	if validateRealCloudCloudflareBootstrapRecoveryLineage(lineage) != nil {
		return false
	}
	wanted := realCloudCloudflareBootstrapRecoveryLineage{PendingSHA256: pendingSHA, ReceiptSHA256: receiptSHA}
	for _, entry := range lineage {
		if entry == wanted {
			return true
		}
	}
	return false
}

func encodeRealCloudCloudflareBootstrapLease(lease realCloudCloudflareBootstrapLease) ([]byte, error) {
	if lease.Schema != realCloudCloudflareBootstrapLeaseSchema || !validRealCloudRunID(lease.RunID) ||
		lease.Mode != "apply" && lease.Mode != "rollback" || !validRealCloudLowerSHA256(lease.ReadinessResourceSHA256) ||
		!validRealCloudLowerSHA256(lease.PlanSHA256) ||
		!validRealCloudProviderIdentifier(lease.AccountID, 128) || !validRealCloudProviderIdentifier(lease.ZoneID, 128) ||
		!validRealCloudLowerSHA256(lease.Holder) {
		return nil, errors.New("Cloudflare bootstrap lease identity is invalid")
	}
	if err := validateRealCloudCloudflareBootstrapRecoveryLineage(lease.RecoveryLineage); err != nil {
		return nil, err
	}
	acquired, err := time.Parse(time.RFC3339Nano, lease.AcquiredAt)
	if err != nil {
		return nil, errors.New("Cloudflare bootstrap lease acquisition time is invalid")
	}
	expires, err := time.Parse(time.RFC3339Nano, lease.ExpiresAt)
	if err != nil || !expires.After(acquired) || expires.Sub(acquired) > 24*time.Hour {
		return nil, errors.New("Cloudflare bootstrap lease expiry is invalid")
	}
	body, err := json.Marshal(lease)
	if err != nil {
		return nil, errors.New("encode Cloudflare bootstrap lease")
	}
	return append(body, '\n'), nil
}

func realCloudCloudflareBootstrapLeaseSHA(lease realCloudCloudflareBootstrapLease) (string, error) {
	body, err := encodeRealCloudCloudflareBootstrapLease(lease)
	if err != nil {
		return "", err
	}
	defer clearRealCloudBytes(body)
	return realCloudLowerSHA256(body), nil
}

func realCloudCloudflareBootstrapLeasesEqual(left, right realCloudCloudflareBootstrapLease) bool {
	leftBody, leftErr := encodeRealCloudCloudflareBootstrapLease(left)
	rightBody, rightErr := encodeRealCloudCloudflareBootstrapLease(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBody, rightBody)
}

func decodeRealCloudCloudflareBootstrapLease(body []byte) (realCloudCloudflareBootstrapLease, error) {
	var lease realCloudCloudflareBootstrapLease
	if err := decodeRealCloudCanonicalJSONFile(body, &lease); err != nil {
		return lease, err
	}
	canonical, err := encodeRealCloudCloudflareBootstrapLease(lease)
	if err != nil || !bytes.Equal(canonical, body) {
		return lease, errors.New("Cloudflare bootstrap lease is invalid or non-canonical")
	}
	return lease, nil
}

func newRealCloudCloudflareBootstrapIdleLease(lease realCloudCloudflareBootstrapLease) (realCloudCloudflareBootstrapIdleLease, error) {
	body, err := encodeRealCloudCloudflareBootstrapLease(lease)
	if err != nil {
		return realCloudCloudflareBootstrapIdleLease{}, err
	}
	return realCloudCloudflareBootstrapIdleLease{
		Schema:                  realCloudCloudflareBootstrapIdleLeaseSchema,
		ReadinessResourceSHA256: lease.ReadinessResourceSHA256,
		PlanSHA256:              lease.PlanSHA256,
		AccountID:               lease.AccountID,
		ZoneID:                  lease.ZoneID,
		Retirement:              realCloudCloudflareBootstrapRetirementRelease,
		PreviousLease:           lease,
		PreviousLeaseSHA256:     realCloudLowerSHA256(body),
	}, nil
}

func newRealCloudCloudflareBootstrapRecoveredIdleLease(
	pending realCloudCloudflareBootstrapLeaseRecoveryPending,
	receiptBody []byte,
) (realCloudCloudflareBootstrapIdleLease, error) {
	pendingBody, err := encodeRealCloudCloudflareBootstrapLeaseRecoveryPending(pending)
	if err != nil || len(receiptBody) == 0 {
		return realCloudCloudflareBootstrapIdleLease{}, errors.New("Cloudflare bootstrap recovery idle source is invalid")
	}
	leaseBody, err := encodeRealCloudCloudflareBootstrapLease(pending.RecoveredLease)
	if err != nil {
		return realCloudCloudflareBootstrapIdleLease{}, err
	}
	pendingSHA := realCloudLowerSHA256(pendingBody)
	receiptSHA := realCloudLowerSHA256(receiptBody)
	if _, err := appendRealCloudCloudflareBootstrapRecoveryLineage(pending.RecoveredLease.RecoveryLineage, pendingSHA, receiptSHA); err != nil {
		return realCloudCloudflareBootstrapIdleLease{}, err
	}
	return realCloudCloudflareBootstrapIdleLease{
		Schema:                  realCloudCloudflareBootstrapIdleLeaseSchema,
		ReadinessResourceSHA256: pending.ReadinessResourceSHA256,
		PlanSHA256:              pending.RecoveredLease.PlanSHA256,
		AccountID:               pending.AccountID,
		ZoneID:                  pending.ZoneID,
		Retirement:              realCloudCloudflareBootstrapRetirementRecovery,
		RecoveryPendingSHA256:   pendingSHA,
		RecoveryReceiptSHA256:   receiptSHA,
		PreviousLease:           pending.RecoveredLease,
		PreviousLeaseSHA256:     realCloudLowerSHA256(leaseBody),
	}, nil
}

func encodeRealCloudCloudflareBootstrapIdleLease(idle realCloudCloudflareBootstrapIdleLease) ([]byte, error) {
	previousBody, err := encodeRealCloudCloudflareBootstrapLease(idle.PreviousLease)
	if err != nil || idle.Schema != realCloudCloudflareBootstrapIdleLeaseSchema ||
		idle.ReadinessResourceSHA256 != idle.PreviousLease.ReadinessResourceSHA256 ||
		idle.PlanSHA256 != idle.PreviousLease.PlanSHA256 || idle.AccountID != idle.PreviousLease.AccountID ||
		idle.ZoneID != idle.PreviousLease.ZoneID || idle.PreviousLeaseSHA256 != realCloudLowerSHA256(previousBody) {
		return nil, errors.New("Cloudflare bootstrap idle lease identity is invalid")
	}
	switch idle.Retirement {
	case realCloudCloudflareBootstrapRetirementRelease:
		if idle.RecoveryPendingSHA256 != "" || idle.RecoveryReceiptSHA256 != "" {
			return nil, errors.New("Cloudflare bootstrap released idle lease carries recovery identity")
		}
	case realCloudCloudflareBootstrapRetirementRecovery:
		if _, err := appendRealCloudCloudflareBootstrapRecoveryLineage(
			idle.PreviousLease.RecoveryLineage, idle.RecoveryPendingSHA256, idle.RecoveryReceiptSHA256,
		); err != nil {
			return nil, errors.New("Cloudflare bootstrap recovered idle lease identity is invalid")
		}
	default:
		return nil, errors.New("Cloudflare bootstrap idle lease retirement is invalid")
	}
	body, err := json.Marshal(idle)
	if err != nil {
		return nil, errors.New("encode Cloudflare bootstrap idle lease")
	}
	return append(body, '\n'), nil
}

func decodeRealCloudCloudflareBootstrapIdleLease(body []byte) (realCloudCloudflareBootstrapIdleLease, error) {
	var idle realCloudCloudflareBootstrapIdleLease
	if err := decodeRealCloudCanonicalJSONFile(body, &idle); err != nil {
		return idle, err
	}
	canonical, err := encodeRealCloudCloudflareBootstrapIdleLease(idle)
	if err != nil || !bytes.Equal(canonical, body) {
		return idle, errors.New("Cloudflare bootstrap idle lease is invalid or non-canonical")
	}
	return idle, nil
}

func validateRealCloudCloudflareBootstrapIdleLease(idle realCloudCloudflareBootstrapIdleLease, plan realCloudCloudflareBootstrapPlan) error {
	if idle.ReadinessResourceSHA256 != plan.ReadinessResourceSHA256 || idle.AccountID != plan.AccountID || idle.ZoneID != plan.ZoneID {
		return errors.New("Cloudflare bootstrap idle lease belongs to a foreign provider resource")
	}
	return nil
}

func realCloudCloudflareBootstrapIdleRecoveryLineage(idle realCloudCloudflareBootstrapIdleLease) ([]realCloudCloudflareBootstrapRecoveryLineage, error) {
	if idle.Retirement == realCloudCloudflareBootstrapRetirementRecovery {
		return appendRealCloudCloudflareBootstrapRecoveryLineage(
			idle.PreviousLease.RecoveryLineage, idle.RecoveryPendingSHA256, idle.RecoveryReceiptSHA256,
		)
	}
	if err := validateRealCloudCloudflareBootstrapRecoveryLineage(idle.PreviousLease.RecoveryLineage); err != nil {
		return nil, err
	}
	lineage := make([]realCloudCloudflareBootstrapRecoveryLineage, len(idle.PreviousLease.RecoveryLineage))
	copy(lineage, idle.PreviousLease.RecoveryLineage)
	return lineage, nil
}

func encodeRealCloudCloudflareBootstrapLeaseRecoveryPending(pending realCloudCloudflareBootstrapLeaseRecoveryPending) ([]byte, error) {
	leaseBody, err := encodeRealCloudCloudflareBootstrapLease(pending.RecoveredLease)
	if err != nil || pending.Schema != realCloudCloudflareLeaseRecoveryPendingSchema || !validRealCloudRunID(pending.RecoveryRunID) ||
		!validRealCloudLowerSHA256(pending.RecoveryPlanSHA256) || !validRealCloudLowerSHA256(pending.ReadinessResourceSHA256) ||
		!validRealCloudProviderIdentifier(pending.AccountID, 128) || !validRealCloudProviderIdentifier(pending.ZoneID, 128) ||
		pending.ReadinessResourceSHA256 != pending.RecoveredLease.ReadinessResourceSHA256 ||
		pending.AccountID != pending.RecoveredLease.AccountID || pending.ZoneID != pending.RecoveredLease.ZoneID ||
		len(pending.RecoveredLease.RecoveryLineage) >= realCloudCloudflareBootstrapMaxRecoveryLineage ||
		pending.RecoveredLeaseSHA256 != realCloudLowerSHA256(leaseBody) {
		return nil, errors.New("Cloudflare bootstrap recovery pending identity is invalid")
	}
	expires, expiresErr := time.Parse(time.RFC3339Nano, pending.RecoveredLease.ExpiresAt)
	started, startedErr := time.Parse(time.RFC3339Nano, pending.StartedAt)
	if expiresErr != nil || startedErr != nil || !started.After(expires) || started.Location() != time.UTC ||
		pending.StartedAt != started.Format(time.RFC3339Nano) {
		return nil, errors.New("Cloudflare bootstrap recovery pending time is invalid")
	}
	body, err := json.Marshal(pending)
	if err != nil {
		return nil, errors.New("encode Cloudflare bootstrap recovery pending marker")
	}
	return append(body, '\n'), nil
}

func decodeRealCloudCloudflareBootstrapLeaseRecoveryPending(body []byte) (realCloudCloudflareBootstrapLeaseRecoveryPending, error) {
	var pending realCloudCloudflareBootstrapLeaseRecoveryPending
	if err := decodeRealCloudCanonicalJSONFile(body, &pending); err != nil {
		return pending, err
	}
	canonical, err := encodeRealCloudCloudflareBootstrapLeaseRecoveryPending(pending)
	if err != nil || !bytes.Equal(canonical, body) {
		return pending, errors.New("Cloudflare bootstrap recovery pending marker is invalid or non-canonical")
	}
	return pending, nil
}

func realCloudCloudflareBootstrapRecoveryPendingsEqual(left, right realCloudCloudflareBootstrapLeaseRecoveryPending) bool {
	leftBody, leftErr := encodeRealCloudCloudflareBootstrapLeaseRecoveryPending(left)
	rightBody, rightErr := encodeRealCloudCloudflareBootstrapLeaseRecoveryPending(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBody, rightBody)
}

func validateRealCloudCloudflareBootstrapLeaseRecoveryPending(
	pending realCloudCloudflareBootstrapLeaseRecoveryPending,
	plan realCloudCloudflareBootstrapPlan,
	planSHA, runID string,
) error {
	if _, err := encodeRealCloudCloudflareBootstrapLeaseRecoveryPending(pending); err != nil {
		return err
	}
	if pending.RecoveryRunID != runID || pending.RecoveryPlanSHA256 != planSHA ||
		pending.ReadinessResourceSHA256 != plan.ReadinessResourceSHA256 ||
		pending.AccountID != plan.AccountID || pending.ZoneID != plan.ZoneID {
		return errors.New("Cloudflare bootstrap recovery pending marker belongs to another execution or resource")
	}
	return nil
}

func acquireRealCloudCloudflareBootstrapLease(ctx context.Context, store realCloudCloudflareBootstrapLeaseStore, plan realCloudCloudflareBootstrapPlan, planSHA, runID, mode, holder string, now time.Time) (*realCloudCloudflareBootstrapHeldLease, error) {
	if store == nil || planSHA != realCloudCloudflareBootstrapPlanSHA(plan) || !validRealCloudRunID(runID) ||
		mode != "apply" && mode != "rollback" || !validRealCloudLowerSHA256(holder) {
		return nil, errors.New("Cloudflare bootstrap lease acquisition identity is invalid")
	}
	key, err := realCloudCloudflareBootstrapLeaseKey(plan.ReadinessResourceSHA256)
	if err != nil {
		return nil, err
	}
	now = now.UTC()
	lease := realCloudCloudflareBootstrapLease{
		Schema: realCloudCloudflareBootstrapLeaseSchema, RunID: runID, Mode: mode, PlanSHA256: planSHA,
		ReadinessResourceSHA256: plan.ReadinessResourceSHA256,
		AccountID:               plan.AccountID, ZoneID: plan.ZoneID, Holder: holder, RecoveryLineage: []realCloudCloudflareBootstrapRecoveryLineage{},
		AcquiredAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(realCloudCloudflareBootstrapLeaseTTL).Format(time.RFC3339Nano),
	}
	body, err := encodeRealCloudCloudflareBootstrapLease(lease)
	if err != nil {
		return nil, err
	}
	etag, err := store.R2Put(ctx, key, bytes.NewReader(body), int64(len(body)), realCloudLowerSHA256(body), publish.R2PutCondition{IfNoneMatch: true})
	if err == nil {
		if !validRealCloudProviderETag(etag) {
			return nil, errors.New("Cloudflare bootstrap lease create returned an invalid ETag")
		}
		return &realCloudCloudflareBootstrapHeldLease{store: store, key: key, lease: lease, etag: etag}, nil
	}
	if !errors.Is(err, publish.ErrAlreadyExists) && !errors.Is(err, publish.ErrConflict) {
		return nil, fmt.Errorf("create Cloudflare bootstrap lease: %w", err)
	}
	observed, err := store.R2GetControl(ctx, key)
	if err != nil || !observed.Exists || !validRealCloudProviderETag(observed.ETag) {
		return nil, errors.New("inspect conflicting Cloudflare bootstrap lease")
	}
	existing, activeErr := decodeRealCloudCloudflareBootstrapLease(observed.Body)
	idle, idleErr := decodeRealCloudCloudflareBootstrapIdleLease(observed.Body)
	pending, pendingErr := decodeRealCloudCloudflareBootstrapLeaseRecoveryPending(observed.Body)
	clearRealCloudBytes(observed.Body)
	switch {
	case activeErr == nil:
		if existing.ReadinessResourceSHA256 != plan.ReadinessResourceSHA256 || existing.AccountID != plan.AccountID || existing.ZoneID != plan.ZoneID {
			return nil, errors.New("Cloudflare bootstrap refuses an invalid or foreign lease")
		}
		expires, _ := time.Parse(time.RFC3339Nano, existing.ExpiresAt)
		if !now.After(expires) {
			return nil, errors.New("Cloudflare bootstrap is leased by another live execution")
		}
		return nil, errors.New("Cloudflare bootstrap found an expired live lease; run recover-lease before acquisition")
	case idleErr == nil:
		if err := validateRealCloudCloudflareBootstrapIdleLease(idle, plan); err != nil {
			return nil, err
		}
		lease.RecoveryLineage, err = realCloudCloudflareBootstrapIdleRecoveryLineage(idle)
		if err != nil {
			return nil, err
		}
		body, err = encodeRealCloudCloudflareBootstrapLease(lease)
		if err != nil {
			return nil, err
		}
	case pendingErr == nil:
		if pending.ReadinessResourceSHA256 != plan.ReadinessResourceSHA256 || pending.AccountID != plan.AccountID || pending.ZoneID != plan.ZoneID {
			return nil, errors.New("Cloudflare bootstrap refuses a foreign recovery pending marker")
		}
		return nil, errors.New("Cloudflare bootstrap recovery is pending; resume the exact recover-lease run")
	default:
		return nil, errors.New("Cloudflare bootstrap refuses an invalid or foreign lease")
	}
	etag, err = store.R2Put(ctx, key, bytes.NewReader(body), int64(len(body)), realCloudLowerSHA256(body), publish.R2PutCondition{IfMatch: observed.ETag})
	if err != nil || !validRealCloudProviderETag(etag) {
		return nil, errors.New("replace expired Cloudflare bootstrap lease by compare-and-set")
	}
	return &realCloudCloudflareBootstrapHeldLease{store: store, key: key, lease: lease, etag: etag}, nil
}

// validateRealCloudCloudflareBootstrapLeasedBucketClosure closes the gap
// between the read-only empty-bucket readiness receipt and the first provider
// mutation. Once the conditional lease exists, it must be the bucket's one and
// only object, and both ListObjectsV2 and GET must bind to its exact entity.
func validateRealCloudCloudflareBootstrapLeasedBucketClosure(ctx context.Context, held *realCloudCloudflareBootstrapHeldLease) error {
	if held == nil || held.store == nil || held.key == "" || !validRealCloudProviderETag(held.etag) {
		return errors.New("Cloudflare bootstrap held lease is invalid")
	}
	expectedBody, err := encodeRealCloudCloudflareBootstrapLease(held.lease)
	if err != nil {
		return err
	}
	continuation := ""
	seenContinuations := map[string]struct{}{"": {}}
	objects := 0
	pages := 0
	for {
		pages++
		if pages > realCloudProviderMaxInventoryItems {
			return errors.New("Cloudflare bootstrap leased bucket inventory exceeds the safety bound")
		}
		page, err := held.store.R2ListObjectsV2(ctx, continuation)
		if err != nil {
			return fmt.Errorf("list Cloudflare bootstrap leased bucket closure: %w", err)
		}
		for _, object := range page.Objects {
			objects++
			if objects > realCloudProviderMaxInventoryItems {
				return errors.New("Cloudflare bootstrap leased bucket inventory exceeds the safety bound")
			}
			if object.Key != held.key {
				return errors.New("Cloudflare bootstrap leased bucket contains an object other than the exact lease")
			}
			if objects != 1 || object.Size != int64(len(expectedBody)) || object.ETag != held.etag {
				return errors.New("Cloudflare bootstrap leased bucket list identity differs from the held lease")
			}
		}
		next := page.NextContinuationToken
		if next == "" {
			break
		}
		if len(next) > 16<<10 || strings.ContainsAny(next, "\x00\r\n") {
			return errors.New("Cloudflare bootstrap leased bucket returned an unsafe continuation token")
		}
		if _, exists := seenContinuations[next]; exists {
			return errors.New("Cloudflare bootstrap leased bucket repeated a continuation token")
		}
		seenContinuations[next] = struct{}{}
		continuation = next
	}
	if objects != 1 {
		return errors.New("Cloudflare bootstrap leased bucket does not contain exactly one lease object")
	}
	observed, err := held.store.R2GetControl(ctx, held.key)
	if err != nil || !observed.Exists || observed.ETag != held.etag {
		clearRealCloudBytes(observed.Body)
		return errors.New("Cloudflare bootstrap leased bucket GET identity differs from the held lease")
	}
	defer clearRealCloudBytes(observed.Body)
	decoded, decodeErr := decodeRealCloudCloudflareBootstrapLease(observed.Body)
	if decodeErr != nil || !realCloudCloudflareBootstrapLeasesEqual(decoded, held.lease) || !bytes.Equal(observed.Body, expectedBody) {
		return errors.New("Cloudflare bootstrap leased bucket GET bytes differ from the held lease")
	}
	return nil
}

func (held *realCloudCloudflareBootstrapHeldLease) renew(ctx context.Context, now time.Time) error {
	if held == nil || held.store == nil || held.key == "" || !validRealCloudProviderETag(held.etag) {
		return errors.New("Cloudflare bootstrap held lease is invalid")
	}
	observed, err := held.store.R2GetControl(ctx, held.key)
	if err != nil || !observed.Exists || observed.ETag != held.etag {
		return errors.New("Cloudflare bootstrap lease ownership changed")
	}
	existing, err := decodeRealCloudCloudflareBootstrapLease(observed.Body)
	clearRealCloudBytes(observed.Body)
	if err != nil || !realCloudCloudflareBootstrapLeasesEqual(existing, held.lease) {
		return errors.New("Cloudflare bootstrap lease bytes changed")
	}
	expires, _ := time.Parse(time.RFC3339Nano, held.lease.ExpiresAt)
	now = now.UTC()
	if !now.Before(expires) {
		return errors.New("Cloudflare bootstrap lease expired before renewal")
	}
	next := held.lease
	next.ExpiresAt = now.Add(realCloudCloudflareBootstrapLeaseTTL).Format(time.RFC3339Nano)
	body, err := encodeRealCloudCloudflareBootstrapLease(next)
	if err != nil {
		return err
	}
	etag, err := held.store.R2Put(ctx, held.key, bytes.NewReader(body), int64(len(body)), realCloudLowerSHA256(body), publish.R2PutCondition{IfMatch: held.etag})
	if err != nil || !validRealCloudProviderETag(etag) {
		return errors.New("renew Cloudflare bootstrap lease by compare-and-set")
	}
	held.lease, held.etag = next, etag
	return nil
}

func (held *realCloudCloudflareBootstrapHeldLease) requireMutationBudget(now time.Time, minimum time.Duration) error {
	if held == nil || minimum <= 0 || minimum >= realCloudCloudflareBootstrapLeaseTTL || !validRealCloudProviderETag(held.etag) {
		return errors.New("Cloudflare bootstrap held lease mutation budget is invalid")
	}
	expires, err := time.Parse(time.RFC3339Nano, held.lease.ExpiresAt)
	if err != nil || expires.Sub(now.UTC()) < minimum {
		return errors.New("Cloudflare bootstrap lease lacks enough lifetime for a bounded mutation")
	}
	return nil
}

func (held *realCloudCloudflareBootstrapHeldLease) release(ctx context.Context) error {
	if held == nil || held.store == nil || !validRealCloudProviderETag(held.etag) {
		return errors.New("Cloudflare bootstrap held lease is invalid")
	}
	observed, err := held.store.R2GetControl(ctx, held.key)
	if err != nil || !observed.Exists || observed.ETag != held.etag {
		return errors.New("Cloudflare bootstrap lease changed before release")
	}
	existing, err := decodeRealCloudCloudflareBootstrapLease(observed.Body)
	clearRealCloudBytes(observed.Body)
	if err != nil || !realCloudCloudflareBootstrapLeasesEqual(existing, held.lease) {
		return errors.New("Cloudflare bootstrap lease bytes changed before release")
	}
	idle, err := newRealCloudCloudflareBootstrapIdleLease(held.lease)
	if err != nil {
		return err
	}
	body, err := encodeRealCloudCloudflareBootstrapIdleLease(idle)
	if err != nil {
		return err
	}
	etag, err := held.store.R2Put(ctx, held.key, bytes.NewReader(body), int64(len(body)), realCloudLowerSHA256(body), publish.R2PutCondition{IfMatch: held.etag})
	if err != nil || !validRealCloudProviderETag(etag) {
		return errors.New("release Cloudflare bootstrap lease by compare-and-set")
	}
	after, err := held.store.R2GetControl(ctx, held.key)
	if err != nil || !after.Exists || after.ETag != etag || !bytes.Equal(after.Body, body) {
		clearRealCloudBytes(after.Body)
		return errors.New("Cloudflare bootstrap idle lease was not durably observed after release")
	}
	clearRealCloudBytes(after.Body)
	held.etag = ""
	return nil
}

func beginRealCloudCloudflareBootstrapLeaseRecovery(
	ctx context.Context,
	store realCloudCloudflareBootstrapLeaseStore,
	plan realCloudCloudflareBootstrapPlan,
	planSHA, runID string,
	now time.Time,
) (realCloudCloudflareBootstrapLeaseRecoveryPending, error) {
	var pending realCloudCloudflareBootstrapLeaseRecoveryPending
	if store == nil || planSHA != realCloudCloudflareBootstrapPlanSHA(plan) || !validRealCloudRunID(runID) {
		return pending, errors.New("Cloudflare bootstrap lease recovery identity is invalid")
	}
	key, err := realCloudCloudflareBootstrapLeaseKey(plan.ReadinessResourceSHA256)
	if err != nil {
		return pending, err
	}
	observed, err := store.R2GetControl(ctx, key)
	if err != nil || !observed.Exists || !validRealCloudProviderETag(observed.ETag) {
		clearRealCloudBytes(observed.Body)
		return pending, errors.New("Cloudflare bootstrap recovery found no exact lease entity")
	}
	defer clearRealCloudBytes(observed.Body)
	if existing, pendingErr := decodeRealCloudCloudflareBootstrapLeaseRecoveryPending(observed.Body); pendingErr == nil {
		if err := validateRealCloudCloudflareBootstrapLeaseRecoveryPending(existing, plan, planSHA, runID); err != nil {
			return pending, err
		}
		return existing, nil
	}
	if _, idleErr := decodeRealCloudCloudflareBootstrapIdleLease(observed.Body); idleErr == nil {
		return pending, errors.New("Cloudflare bootstrap recovery found an idle marker without its exact pending transaction")
	}
	recovered, err := decodeRealCloudCloudflareBootstrapLease(observed.Body)
	if err != nil || recovered.ReadinessResourceSHA256 != plan.ReadinessResourceSHA256 ||
		recovered.AccountID != plan.AccountID || recovered.ZoneID != plan.ZoneID {
		return pending, errors.New("Cloudflare bootstrap recovery refuses an invalid or foreign lease")
	}
	now = now.UTC()
	expires, _ := time.Parse(time.RFC3339Nano, recovered.ExpiresAt)
	if !now.After(expires) {
		return pending, errors.New("Cloudflare bootstrap recovery refuses a live lease")
	}
	recoveredBody, err := encodeRealCloudCloudflareBootstrapLease(recovered)
	if err != nil {
		return pending, err
	}
	pending = realCloudCloudflareBootstrapLeaseRecoveryPending{
		Schema: realCloudCloudflareLeaseRecoveryPendingSchema, RecoveryRunID: runID, RecoveryPlanSHA256: planSHA,
		ReadinessResourceSHA256: plan.ReadinessResourceSHA256, AccountID: plan.AccountID, ZoneID: plan.ZoneID,
		RecoveredLease: recovered, RecoveredLeaseSHA256: realCloudLowerSHA256(recoveredBody), StartedAt: now.Format(time.RFC3339Nano),
	}
	body, err := encodeRealCloudCloudflareBootstrapLeaseRecoveryPending(pending)
	if err != nil {
		return realCloudCloudflareBootstrapLeaseRecoveryPending{}, err
	}
	etag, putErr := store.R2Put(ctx, key, bytes.NewReader(body), int64(len(body)), realCloudLowerSHA256(body), publish.R2PutCondition{IfMatch: observed.ETag})
	after, getErr := store.R2GetControl(ctx, key)
	if getErr != nil || !after.Exists || !validRealCloudProviderETag(after.ETag) || !bytes.Equal(after.Body, body) ||
		putErr == nil && (!validRealCloudProviderETag(etag) || after.ETag != etag) {
		clearRealCloudBytes(after.Body)
		return realCloudCloudflareBootstrapLeaseRecoveryPending{}, errors.New("begin expired Cloudflare bootstrap lease recovery by compare-and-set")
	}
	clearRealCloudBytes(after.Body)
	return pending, nil
}

func newRealCloudCloudflareBootstrapLeaseRecoveryReceipt(
	pending realCloudCloudflareBootstrapLeaseRecoveryPending,
	plan realCloudCloudflareBootstrapPlan,
	planSHA, runID string,
) (realCloudCloudflareBootstrapLeaseRecoveryReceipt, error) {
	if err := validateRealCloudCloudflareBootstrapLeaseRecoveryPending(pending, plan, planSHA, runID); err != nil {
		return realCloudCloudflareBootstrapLeaseRecoveryReceipt{}, err
	}
	pendingBody, err := encodeRealCloudCloudflareBootstrapLeaseRecoveryPending(pending)
	if err != nil {
		return realCloudCloudflareBootstrapLeaseRecoveryReceipt{}, err
	}
	recovered := pending.RecoveredLease
	return realCloudCloudflareBootstrapLeaseRecoveryReceipt{
		Schema: realCloudCloudflareLeaseRecoverySchema, RunID: runID, PlanSHA256: planSHA, AccountID: plan.AccountID, ZoneID: plan.ZoneID,
		RecoveryPendingSHA256: realCloudLowerSHA256(pendingBody), RecoveredLease: recovered, RecoveredLeaseRun: recovered.RunID,
		RecoveredLeasePlanSHA256: recovered.PlanSHA256, RecoveredLeaseSHA256: pending.RecoveredLeaseSHA256,
		RecoveredMode: recovered.Mode, LeaseHolderSHA256: realCloudLowerSHA256([]byte(recovered.Holder)),
		LeaseExpiredAt: recovered.ExpiresAt, RecoveryStartedAt: pending.StartedAt,
	}, nil
}

func validateRealCloudCloudflareBootstrapLeaseRecoveryReceipt(receipt realCloudCloudflareBootstrapLeaseRecoveryReceipt, plan realCloudCloudflareBootstrapPlan, planSHA, runID string) error {
	recoveredBody, recoveredErr := encodeRealCloudCloudflareBootstrapLease(receipt.RecoveredLease)
	if receipt.Schema != realCloudCloudflareLeaseRecoverySchema || receipt.RunID != runID || receipt.PlanSHA256 != planSHA ||
		receipt.AccountID != plan.AccountID || receipt.ZoneID != plan.ZoneID || !validRealCloudLowerSHA256(receipt.RecoveryPendingSHA256) ||
		recoveredErr != nil || receipt.RecoveredLease.ReadinessResourceSHA256 != plan.ReadinessResourceSHA256 ||
		receipt.RecoveredLease.AccountID != plan.AccountID || receipt.RecoveredLease.ZoneID != plan.ZoneID ||
		receipt.RecoveredLeaseRun != receipt.RecoveredLease.RunID ||
		!validRealCloudLowerSHA256(receipt.RecoveredLeasePlanSHA256) || !validRealCloudLowerSHA256(receipt.RecoveredLeaseSHA256) ||
		receipt.RecoveredLeasePlanSHA256 != receipt.RecoveredLease.PlanSHA256 ||
		receipt.RecoveredLeaseSHA256 != realCloudLowerSHA256(recoveredBody) || receipt.RecoveredMode != receipt.RecoveredLease.Mode ||
		receipt.LeaseHolderSHA256 != realCloudLowerSHA256([]byte(receipt.RecoveredLease.Holder)) ||
		receipt.LeaseExpiredAt != receipt.RecoveredLease.ExpiresAt {
		return errors.New("Cloudflare bootstrap lease recovery receipt identity is invalid")
	}
	expired, err := time.Parse(time.RFC3339Nano, receipt.LeaseExpiredAt)
	if err != nil {
		return errors.New("Cloudflare bootstrap lease recovery expiry is invalid")
	}
	started, err := time.Parse(time.RFC3339Nano, receipt.RecoveryStartedAt)
	if err != nil || !started.After(expired) || started.Location() != time.UTC ||
		receipt.RecoveryStartedAt != started.Format(time.RFC3339Nano) {
		return errors.New("Cloudflare bootstrap lease recovery time is invalid")
	}
	return nil
}

func encodeRealCloudCloudflareBootstrapLeaseRecoveryReceipt(
	receipt realCloudCloudflareBootstrapLeaseRecoveryReceipt,
	plan realCloudCloudflareBootstrapPlan,
	planSHA, runID string,
) ([]byte, error) {
	if err := validateRealCloudCloudflareBootstrapLeaseRecoveryReceipt(receipt, plan, planSHA, runID); err != nil {
		return nil, err
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		return nil, errors.New("encode Cloudflare bootstrap lease recovery receipt")
	}
	return append(body, '\n'), nil
}

func validateRealCloudCloudflareBootstrapLeaseRecoveryReceiptAgainstPending(
	receipt realCloudCloudflareBootstrapLeaseRecoveryReceipt,
	pending realCloudCloudflareBootstrapLeaseRecoveryPending,
	plan realCloudCloudflareBootstrapPlan,
	planSHA, runID string,
) error {
	if err := validateRealCloudCloudflareBootstrapLeaseRecoveryReceipt(receipt, plan, planSHA, runID); err != nil {
		return err
	}
	if err := validateRealCloudCloudflareBootstrapLeaseRecoveryPending(pending, plan, planSHA, runID); err != nil {
		return err
	}
	pendingBody, err := encodeRealCloudCloudflareBootstrapLeaseRecoveryPending(pending)
	if err != nil {
		return err
	}
	recovered := pending.RecoveredLease
	if receipt.RecoveryPendingSHA256 != realCloudLowerSHA256(pendingBody) ||
		!realCloudCloudflareBootstrapLeasesEqual(receipt.RecoveredLease, recovered) || receipt.RecoveredLeaseRun != recovered.RunID || receipt.RecoveredLeasePlanSHA256 != recovered.PlanSHA256 ||
		receipt.RecoveredLeaseSHA256 != pending.RecoveredLeaseSHA256 || receipt.RecoveredMode != recovered.Mode ||
		receipt.LeaseHolderSHA256 != realCloudLowerSHA256([]byte(recovered.Holder)) ||
		receipt.LeaseExpiredAt != recovered.ExpiresAt || receipt.RecoveryStartedAt != pending.StartedAt {
		return errors.New("Cloudflare bootstrap recovery receipt differs from the exact pending marker")
	}
	return nil
}

func persistRealCloudCloudflareBootstrapLeaseRecoveryReceipt(
	path string,
	receipt realCloudCloudflareBootstrapLeaseRecoveryReceipt,
	plan realCloudCloudflareBootstrapPlan,
	planSHA, runID string,
) error {
	body, err := encodeRealCloudCloudflareBootstrapLeaseRecoveryReceipt(receipt, plan, planSHA, runID)
	if err != nil {
		return err
	}
	installed, err := installRealCloudPrivateFileExclusiveWithPattern(path, body, ".sow-bootstrap-lease-recovery-*")
	if err != nil {
		return fmt.Errorf("persist Cloudflare bootstrap lease recovery receipt: %w", err)
	}
	if installed {
		return nil
	}
	existing, err := readRealCloudPrivateCanonicalFile(path, realCloudCloudflareBootstrapRecoveryReceiptMax)
	if err != nil {
		return fmt.Errorf("read concurrent Cloudflare bootstrap lease recovery receipt: %w", err)
	}
	defer clearRealCloudBytes(existing)
	if !bytes.Equal(existing, body) {
		return errors.New("existing Cloudflare bootstrap lease recovery receipt differs from this recovery")
	}
	return nil
}

func loadRealCloudCloudflareBootstrapLeaseRecoveryReceipt(
	path string,
	plan realCloudCloudflareBootstrapPlan,
	planSHA, runID string,
) (realCloudCloudflareBootstrapLeaseRecoveryReceipt, []byte, error) {
	var receipt realCloudCloudflareBootstrapLeaseRecoveryReceipt
	body, err := readRealCloudPrivateCanonicalFile(path, realCloudCloudflareBootstrapRecoveryReceiptMax)
	if err != nil {
		return receipt, nil, err
	}
	if err := decodeRealCloudCanonicalJSONFile(body, &receipt); err != nil {
		clearRealCloudBytes(body)
		return receipt, nil, errors.New("decode Cloudflare bootstrap lease recovery receipt")
	}
	canonical, err := encodeRealCloudCloudflareBootstrapLeaseRecoveryReceipt(receipt, plan, planSHA, runID)
	if err != nil || !bytes.Equal(canonical, body) {
		clearRealCloudBytes(body)
		return receipt, nil, errors.New("Cloudflare bootstrap lease recovery receipt is invalid or non-canonical")
	}
	return receipt, body, nil
}

func validateRealCloudCloudflareBootstrapLeaseRecoveryDescendant(
	receipt realCloudCloudflareBootstrapLeaseRecoveryReceipt,
	receiptBody []byte,
	lease realCloudCloudflareBootstrapLease,
	plan realCloudCloudflareBootstrapPlan,
) error {
	if _, err := encodeRealCloudCloudflareBootstrapLease(lease); err != nil || realCloudCloudflareBootstrapLeasesEqual(lease, receipt.RecoveredLease) ||
		lease.ReadinessResourceSHA256 != plan.ReadinessResourceSHA256 || lease.AccountID != plan.AccountID || lease.ZoneID != plan.ZoneID ||
		!realCloudCloudflareBootstrapRecoveryLineageContains(
			lease.RecoveryLineage, receipt.RecoveryPendingSHA256, realCloudLowerSHA256(receiptBody),
		) {
		return errors.New("Cloudflare bootstrap marker is not a proven descendant of the completed recovery")
	}
	return nil
}

func completeRealCloudCloudflareBootstrapLeaseRecovery(
	ctx context.Context,
	store realCloudCloudflareBootstrapLeaseStore,
	plan realCloudCloudflareBootstrapPlan,
	planSHA, runID, receiptPath string,
) (realCloudCloudflareBootstrapLease, error) {
	var recovered realCloudCloudflareBootstrapLease
	if store == nil || planSHA != realCloudCloudflareBootstrapPlanSHA(plan) || !validRealCloudRunID(runID) {
		return recovered, errors.New("Cloudflare bootstrap lease recovery completion identity is invalid")
	}
	receipt, receiptBody, err := loadRealCloudCloudflareBootstrapLeaseRecoveryReceipt(receiptPath, plan, planSHA, runID)
	if err != nil {
		return recovered, err
	}
	defer clearRealCloudBytes(receiptBody)
	key, err := realCloudCloudflareBootstrapLeaseKey(plan.ReadinessResourceSHA256)
	if err != nil {
		return recovered, err
	}
	observed, err := store.R2GetControl(ctx, key)
	if err != nil || !observed.Exists || !validRealCloudProviderETag(observed.ETag) {
		clearRealCloudBytes(observed.Body)
		return recovered, errors.New("Cloudflare bootstrap recovery completion found no exact marker entity")
	}
	defer clearRealCloudBytes(observed.Body)
	if idle, idleErr := decodeRealCloudCloudflareBootstrapIdleLease(observed.Body); idleErr == nil {
		if err := validateRealCloudCloudflareBootstrapLeaseRecoveryMarker(receipt, idle, plan, planSHA, runID); err == nil {
			return idle.PreviousLease, nil
		}
		if err := validateRealCloudCloudflareBootstrapIdleLease(idle, plan); err == nil &&
			validateRealCloudCloudflareBootstrapLeaseRecoveryDescendant(receipt, receiptBody, idle.PreviousLease, plan) == nil {
			return receipt.RecoveredLease, nil
		}
		return recovered, errors.New("Cloudflare bootstrap idle marker does not descend from the durable recovery receipt")
	}
	pending, pendingErr := decodeRealCloudCloudflareBootstrapLeaseRecoveryPending(observed.Body)
	if pendingErr != nil {
		active, activeErr := decodeRealCloudCloudflareBootstrapLease(observed.Body)
		if activeErr == nil && validateRealCloudCloudflareBootstrapLeaseRecoveryDescendant(receipt, receiptBody, active, plan) == nil {
			return receipt.RecoveredLease, nil
		}
		return recovered, errors.New("Cloudflare bootstrap recovery completion refuses an unrelated live, invalid, or foreign marker")
	}
	if err := validateRealCloudCloudflareBootstrapLeaseRecoveryReceiptAgainstPending(receipt, pending, plan, planSHA, runID); err != nil {
		if validateRealCloudCloudflareBootstrapLeaseRecoveryDescendant(receipt, receiptBody, pending.RecoveredLease, plan) == nil {
			return receipt.RecoveredLease, nil
		}
		return recovered, err
	}
	idle, err := newRealCloudCloudflareBootstrapRecoveredIdleLease(pending, receiptBody)
	if err != nil {
		return recovered, err
	}
	idleBody, err := encodeRealCloudCloudflareBootstrapIdleLease(idle)
	if err != nil {
		return recovered, err
	}
	etag, putErr := store.R2Put(ctx, key, bytes.NewReader(idleBody), int64(len(idleBody)), realCloudLowerSHA256(idleBody), publish.R2PutCondition{IfMatch: observed.ETag})
	after, getErr := store.R2GetControl(ctx, key)
	if getErr != nil || !after.Exists || !validRealCloudProviderETag(after.ETag) ||
		putErr == nil && !validRealCloudProviderETag(etag) {
		clearRealCloudBytes(after.Body)
		return recovered, errors.New("complete Cloudflare bootstrap lease recovery by compare-and-set")
	}
	if bytes.Equal(after.Body, idleBody) {
		if putErr == nil && after.ETag != etag {
			clearRealCloudBytes(after.Body)
			return recovered, errors.New("complete Cloudflare bootstrap lease recovery by compare-and-set")
		}
		clearRealCloudBytes(after.Body)
		return pending.RecoveredLease, nil
	}
	descendant := false
	if active, activeErr := decodeRealCloudCloudflareBootstrapLease(after.Body); activeErr == nil {
		descendant = validateRealCloudCloudflareBootstrapLeaseRecoveryDescendant(receipt, receiptBody, active, plan) == nil
	} else if advancedIdle, idleErr := decodeRealCloudCloudflareBootstrapIdleLease(after.Body); idleErr == nil {
		descendant = validateRealCloudCloudflareBootstrapIdleLease(advancedIdle, plan) == nil &&
			validateRealCloudCloudflareBootstrapLeaseRecoveryDescendant(receipt, receiptBody, advancedIdle.PreviousLease, plan) == nil
	} else if advancedPending, pendingErr := decodeRealCloudCloudflareBootstrapLeaseRecoveryPending(after.Body); pendingErr == nil {
		descendant = validateRealCloudCloudflareBootstrapLeaseRecoveryDescendant(receipt, receiptBody, advancedPending.RecoveredLease, plan) == nil
	}
	clearRealCloudBytes(after.Body)
	if !descendant {
		return recovered, errors.New("completed Cloudflare bootstrap recovery is not followed by its exact marker or a proven descendant")
	}
	return pending.RecoveredLease, nil
}

func validateRealCloudCloudflareBootstrapLeaseRecoveryMarker(
	receipt realCloudCloudflareBootstrapLeaseRecoveryReceipt,
	idle realCloudCloudflareBootstrapIdleLease,
	plan realCloudCloudflareBootstrapPlan,
	planSHA, runID string,
) error {
	if err := validateRealCloudCloudflareBootstrapLeaseRecoveryReceipt(receipt, plan, planSHA, runID); err != nil {
		return err
	}
	if err := validateRealCloudCloudflareBootstrapIdleLease(idle, plan); err != nil {
		return err
	}
	receiptBody, err := encodeRealCloudCloudflareBootstrapLeaseRecoveryReceipt(receipt, plan, planSHA, runID)
	if err != nil {
		return err
	}
	previous := idle.PreviousLease
	previousSHA, err := realCloudCloudflareBootstrapLeaseSHA(previous)
	if err != nil {
		return err
	}
	reconstructedPending := realCloudCloudflareBootstrapLeaseRecoveryPending{
		Schema: realCloudCloudflareLeaseRecoveryPendingSchema, RecoveryRunID: receipt.RunID, RecoveryPlanSHA256: receipt.PlanSHA256,
		ReadinessResourceSHA256: plan.ReadinessResourceSHA256, AccountID: receipt.AccountID, ZoneID: receipt.ZoneID,
		RecoveredLease: previous, RecoveredLeaseSHA256: previousSHA, StartedAt: receipt.RecoveryStartedAt,
	}
	pendingBody, err := encodeRealCloudCloudflareBootstrapLeaseRecoveryPending(reconstructedPending)
	if err != nil {
		return err
	}
	if idle.Retirement != realCloudCloudflareBootstrapRetirementRecovery ||
		idle.RecoveryPendingSHA256 != receipt.RecoveryPendingSHA256 || receipt.RecoveryPendingSHA256 != realCloudLowerSHA256(pendingBody) ||
		idle.RecoveryReceiptSHA256 != realCloudLowerSHA256(receiptBody) || !realCloudCloudflareBootstrapLeasesEqual(previous, receipt.RecoveredLease) ||
		previous.RunID != receipt.RecoveredLeaseRun || previous.PlanSHA256 != receipt.RecoveredLeasePlanSHA256 ||
		previousSHA != receipt.RecoveredLeaseSHA256 ||
		previous.Mode != receipt.RecoveredMode || realCloudLowerSHA256([]byte(previous.Holder)) != receipt.LeaseHolderSHA256 ||
		previous.ExpiresAt != receipt.LeaseExpiredAt {
		return errors.New("Cloudflare bootstrap recovered idle marker differs from the durable recovery receipt")
	}
	return nil
}

func validateRealCloudCloudflareBootstrapAuthBindings(bindings []workers.ScriptVersionGetResponseResourcesBinding, plan realCloudCloudflareBootstrapPlan) (string, error) {
	wantedVariables := make(map[string]string, len(plan.EdgeContract.Variables))
	for name, value := range plan.EdgeContract.Variables {
		wantedVariables[name] = value
	}
	wantedServices := map[string]string{"ORIGIN": plan.OriginScript}
	wantedSecrets := make(map[string]struct{})
	if realCloudCloudflareBootstrapUsesProvider(plan) {
		wantedServices["TOKEN_VERIFIER"] = plan.TokenVerifierService
	} else {
		wantedSecrets[plan.TokenVerifierSecret] = struct{}{}
	}
	seen := make(map[string]struct{}, len(bindings))
	rows := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		if _, duplicate := seen[binding.Name]; duplicate || !validRealCloudCloudflareRuntimeBindingName(binding.Name) {
			return "", errors.New("Cloudflare bootstrap auth Worker repeats or has an invalid binding")
		}
		seen[binding.Name] = struct{}{}
		switch binding.Type {
		case workers.ScriptVersionGetResponseResourcesBindingsTypePlainText:
			wanted, found := wantedVariables[binding.Name]
			if !found || binding.Text != wanted {
				return "", errors.New("Cloudflare bootstrap auth Worker runtime binding differs from the plan")
			}
			delete(wantedVariables, binding.Name)
			rows = append(rows, strings.Join([]string{binding.Name, string(binding.Type), binding.Text}, "\x00"))
		case workers.ScriptVersionGetResponseResourcesBindingsTypeService:
			wanted, found := wantedServices[binding.Name]
			wantedEnvironment := realCloudCloudflareBootstrapServiceEnvironment("")
			if binding.Name == "TOKEN_VERIFIER" {
				wantedEnvironment = realCloudCloudflareBootstrapServiceEnvironment(plan.TokenVerifierEnvironment)
			}
			if !found || binding.Service != wanted || binding.Environment != wantedEnvironment || binding.Entrypoint != "" {
				return "", errors.New("Cloudflare bootstrap auth Worker service binding differs from the plan")
			}
			delete(wantedServices, binding.Name)
			rows = append(rows, strings.Join([]string{binding.Name, string(binding.Type), binding.Service, binding.Environment}, "\x00"))
		case workers.ScriptVersionGetResponseResourcesBindingsTypeSecretText:
			if _, found := wantedSecrets[binding.Name]; !found {
				return "", errors.New("Cloudflare bootstrap auth Worker secret binding differs from the plan")
			}
			delete(wantedSecrets, binding.Name)
			rows = append(rows, strings.Join([]string{binding.Name, string(binding.Type)}, "\x00"))
		default:
			return "", errors.New("Cloudflare bootstrap auth Worker has an excessive capability binding")
		}
	}
	if len(wantedVariables) != 0 || len(wantedServices) != 0 || len(wantedSecrets) != 0 {
		return "", errors.New("Cloudflare bootstrap auth Worker lacks a planned binding")
	}
	sort.Strings(rows)
	body, _ := json.Marshal(rows)
	return realCloudLowerSHA256(body), nil
}

func realCloudCloudflareBootstrapServiceEnvironment(environment string) string {
	if environment == "" {
		return "production"
	}
	return environment
}

func (control *realCloudCloudflareSDKBootstrapControl) Upload(ctx context.Context, plan realCloudCloudflareBootstrapPlan, role, planSHA, runID string) error {
	if planSHA != realCloudCloudflareBootstrapPlanSHA(plan) || !validRealCloudRunID(runID) {
		return errors.New("Cloudflare bootstrap upload plan digest differs from the canonical plan")
	}
	if control == nil || control.client == nil {
		return errors.New("Cloudflare bootstrap client is absent")
	}
	var script string
	var bundle realCloudCloudflareBootstrapBundle
	var bindings []workers.ScriptUpdateParamsMetadataBindingUnion
	switch role {
	case "origin":
		script, bundle = plan.OriginScript, plan.OriginBundle
		bindings = append(bindings, workers.ScriptUpdateParamsMetadataBindingsWorkersBindingKindR2Bucket{
			Name: cloudflareapi.F("REPOSITORY"), BucketName: cloudflareapi.F(plan.R2Bucket),
			Type: cloudflareapi.F(workers.ScriptUpdateParamsMetadataBindingsWorkersBindingKindR2BucketTypeR2Bucket),
		})
	case "auth":
		script, bundle = plan.AuthScript, plan.AuthBundle
		names := make([]string, 0, len(plan.EdgeContract.Variables))
		for name := range plan.EdgeContract.Variables {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			bindings = append(bindings, workers.ScriptUpdateParamsMetadataBindingsWorkersBindingKindPlainText{
				Name: cloudflareapi.F(name), Text: cloudflareapi.F(plan.EdgeContract.Variables[name]),
				Type: cloudflareapi.F(workers.ScriptUpdateParamsMetadataBindingsWorkersBindingKindPlainTextTypePlainText),
			})
		}
		bindings = append(bindings, workers.ScriptUpdateParamsMetadataBindingsWorkersBindingKindService{
			Name: cloudflareapi.F("ORIGIN"), Service: cloudflareapi.F(plan.OriginScript),
			Environment: cloudflareapi.F(realCloudCloudflareBootstrapServiceEnvironment("")),
			Type:        cloudflareapi.F(workers.ScriptUpdateParamsMetadataBindingsWorkersBindingKindServiceTypeService),
		})
		if realCloudCloudflareBootstrapUsesProvider(plan) {
			if len(control.secretBindings) != 0 {
				return errors.New("Cloudflare bootstrap provider upload received an unexpected static secret")
			}
			bindings = append(bindings, workers.ScriptUpdateParamsMetadataBindingsWorkersBindingKindService{
				Name: cloudflareapi.F("TOKEN_VERIFIER"), Service: cloudflareapi.F(plan.TokenVerifierService),
				Environment: cloudflareapi.F(realCloudCloudflareBootstrapServiceEnvironment(plan.TokenVerifierEnvironment)),
				Type:        cloudflareapi.F(workers.ScriptUpdateParamsMetadataBindingsWorkersBindingKindServiceTypeService),
			})
		} else {
			secret, found := control.secretBindings[plan.TokenVerifierSecret]
			if !found || len(control.secretBindings) != 1 || validateRealCloudCloudflareStaticEntitlements(secret, plan, time.Now().UTC()) != nil {
				return errors.New("Cloudflare bootstrap static entitlement secret is absent or invalid before upload")
			}
			bindings = append(bindings, workers.ScriptUpdateParamsMetadataBindingsWorkersBindingKindSecretText{
				Name: cloudflareapi.F(plan.TokenVerifierSecret), Text: cloudflareapi.F(secret),
				Type: cloudflareapi.F(workers.ScriptUpdateParamsMetadataBindingsWorkersBindingKindSecretTextTypeSecretText),
			})
		}
	default:
		return errors.New("Cloudflare bootstrap may upload only auth or origin Workers")
	}
	body, err := readRealCloudProviderRepositoryFile(bundle.Path, realCloudProviderMaxContentBytes)
	if err != nil || realCloudLowerSHA256(body) != bundle.SHA256 {
		return errors.New("Cloudflare bootstrap bundle changed before upload")
	}
	defer clearRealCloudBytes(body)
	file := &realCloudCloudflareBootstrapFile{Reader: bytes.NewReader(body), filename: "worker.mjs", contentType: "application/javascript+module"}
	message, tag := realCloudCloudflareBootstrapOwnershipAnnotations(plan, runID)
	response, err := control.client.Workers.Scripts.Update(ctx, script, workers.ScriptUpdateParams{
		AccountID:       cloudflareapi.F(plan.AccountID),
		BindingsInherit: cloudflareapi.F(workers.ScriptUpdateParamsBindingsInheritStrict),
		Metadata: cloudflareapi.F(workers.ScriptUpdateParamsMetadata{
			Annotations: cloudflareapi.F(workers.ScriptUpdateParamsMetadataAnnotations{
				WorkersMessage: cloudflareapi.F(message),
				WorkersTag:     cloudflareapi.F(tag),
			}),
			Bindings: cloudflareapi.F(bindings), CompatibilityDate: cloudflareapi.F(plan.CompatibilityDate),
			CompatibilityFlags: cloudflareapi.F(append([]string(nil), plan.CompatibilityFlags...)),
			CacheOptions: cloudflareapi.F(workers.ScriptUpdateParamsMetadataCacheOptions{
				Enabled: cloudflareapi.F(false), CrossVersionCache: cloudflareapi.F(false),
			}),
			Logpush: cloudflareapi.F(false), MainModule: cloudflareapi.F("worker.mjs"),
			Observability: cloudflareapi.F(workers.ScriptUpdateParamsMetadataObservability{
				Enabled: cloudflareapi.F(false),
			}),
			Tags: cloudflareapi.F([]string{}), TailConsumers: cloudflareapi.F([]workers.ConsumerScriptParam{}),
			UsageModel: cloudflareapi.F(workers.ScriptUpdateParamsMetadataUsageModelStandard),
		}),
		Files: cloudflareapi.F([]io.Reader{file}),
	}, option.WithHeader("If-None-Match", "*"))
	if err != nil {
		return fmt.Errorf("upload exact Cloudflare bootstrap Worker: %w", err)
	}
	if response == nil || response.ID != "" && response.ID != script {
		return errors.New("upload exact Cloudflare bootstrap Worker")
	}
	return nil
}

func (control *realCloudCloudflareSDKBootstrapControl) DisableExposure(ctx context.Context, plan realCloudCloudflareBootstrapPlan, script string) error {
	response, err := control.client.Workers.Scripts.Subdomain.New(ctx, script, workers.ScriptSubdomainNewParams{
		AccountID: cloudflareapi.F(plan.AccountID), Enabled: cloudflareapi.F(false), PreviewsEnabled: cloudflareapi.F(false),
	})
	if err != nil || response == nil || response.Enabled || response.PreviewsEnabled {
		return errors.New("disable Cloudflare Worker workers.dev and preview exposure")
	}
	return nil
}

func (control *realCloudCloudflareSDKBootstrapControl) CreateRoute(ctx context.Context, plan realCloudCloudflareBootstrapPlan, route realCloudCloudflareBootstrapRoute) (string, error) {
	response, err := control.client.Workers.Routes.New(ctx, workers.RouteNewParams{
		ZoneID: cloudflareapi.F(plan.ZoneID), Pattern: cloudflareapi.F(route.Pattern), Script: cloudflareapi.F(route.Script),
	})
	if err != nil || response == nil || !validRealCloudProviderIdentifier(response.ID, 128) || response.Pattern != route.Pattern || response.Script != route.Script {
		return "", errors.New("create exact Cloudflare bootstrap route")
	}
	return response.ID, nil
}

func (control *realCloudCloudflareSDKBootstrapControl) GetRoute(ctx context.Context, plan realCloudCloudflareBootstrapPlan, routeID string) (realCloudCloudflareBootstrapInventoryRoute, error) {
	route, exists, err := control.getRouteIfExists(ctx, plan, routeID)
	if err != nil {
		return route, err
	}
	if !exists {
		return route, errors.New("exact Cloudflare bootstrap route is absent")
	}
	return route, nil
}

func (control *realCloudCloudflareSDKBootstrapControl) getRouteIfExists(ctx context.Context, plan realCloudCloudflareBootstrapPlan, routeID string) (realCloudCloudflareBootstrapInventoryRoute, bool, error) {
	var route realCloudCloudflareBootstrapInventoryRoute
	if !validRealCloudProviderIdentifier(routeID, 128) {
		return route, false, errors.New("Cloudflare bootstrap route ID is invalid")
	}
	response, err := control.client.Workers.Routes.Get(ctx, routeID, workers.RouteGetParams{ZoneID: cloudflareapi.F(plan.ZoneID)})
	if realCloudCloudflareAPINotFound(err) {
		return route, false, nil
	}
	if err != nil || response == nil || response.ID != routeID || !validRealCloudProviderIdentifier(response.Script, 128) || strings.TrimSpace(response.Pattern) == "" {
		return route, false, errors.New("inspect exact Cloudflare bootstrap route")
	}
	return realCloudCloudflareBootstrapInventoryRoute{ID: response.ID, Pattern: response.Pattern, Script: response.Script}, true, nil
}

func (control *realCloudCloudflareSDKBootstrapControl) DeleteRouteIfMatch(ctx context.Context, plan realCloudCloudflareBootstrapPlan, expected realCloudCloudflareBootstrapInventoryRoute) error {
	if !validRealCloudProviderIdentifier(expected.ID, 128) {
		return errors.New("Cloudflare bootstrap route ID is invalid")
	}
	planned := false
	for _, route := range plan.Routes {
		if expected.Pattern == route.Pattern && expected.Script == route.Script {
			planned = true
			break
		}
	}
	if !planned {
		return errors.New("Cloudflare bootstrap route deletion identity differs from the exact plan")
	}
	current, exists, err := control.getRouteIfExists(ctx, plan, expected.ID)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if current != expected {
		return errors.New("Cloudflare bootstrap route changed immediately before deletion")
	}
	response, err := control.client.Workers.Routes.Delete(ctx, expected.ID, workers.RouteDeleteParams{ZoneID: cloudflareapi.F(plan.ZoneID)})
	if err != nil || response == nil || response.ID != "" && response.ID != expected.ID {
		return errors.New("delete exact Cloudflare bootstrap route")
	}
	return nil
}

func (control *realCloudCloudflareSDKBootstrapControl) DeleteScriptIfMatch(ctx context.Context, plan realCloudCloudflareBootstrapPlan, role, runID string, expected realCloudCloudflareBootstrapReceiptWorker) error {
	script := plan.AuthScript
	if role == "origin" {
		script = plan.OriginScript
	} else if role != "auth" {
		return errors.New("Cloudflare bootstrap may delete only its exact auth or origin Worker")
	}
	if expected.Script != script {
		return errors.New("Cloudflare bootstrap Worker deletion identity differs from the exact plan")
	}
	_, err := control.client.Workers.Scripts.Deployments.List(ctx, script, workers.ScriptDeploymentListParams{AccountID: cloudflareapi.F(plan.AccountID)})
	if realCloudCloudflareAPINotFound(err) {
		return nil
	}
	if err != nil {
		return errors.New("probe exact Cloudflare bootstrap Worker before deletion")
	}
	inventory, err := control.Inventory(ctx, plan)
	if err != nil {
		return errors.New("inspect Cloudflare bootstrap Worker deletion attachment closure")
	}
	_, routesFound, err := validateRealCloudCloudflareBootstrapInventory(plan, inventory, false)
	if err != nil || len(routesFound) != 0 {
		return errors.New("Cloudflare bootstrap Worker deletion attachment closure changed")
	}
	schedules, err := control.client.Workers.Scripts.Schedules.Get(ctx, script, workers.ScriptScheduleGetParams{AccountID: cloudflareapi.F(plan.AccountID)})
	if err != nil || schedules == nil || len(schedules.Schedules) != 0 {
		return errors.New("Cloudflare bootstrap Worker deletion schedule closure changed")
	}
	current, err := control.Inspect(ctx, plan, role)
	if err != nil || validateRealCloudCloudflareBootstrapWorkerState(role, current, plan, runID, true) != nil ||
		!realCloudCloudflareBootstrapStateMatchesReceipt(current, expected) {
		return fmt.Errorf("Cloudflare bootstrap %s Worker changed immediately before deletion", role)
	}
	versionCount := 0
	versionPager := control.client.Workers.Scripts.Versions.ListAutoPaging(ctx, script, workers.ScriptVersionListParams{AccountID: cloudflareapi.F(plan.AccountID)})
	for versionPager.Next() {
		versionCount++
		if versionCount > realCloudProviderMaxInventoryItems || versionPager.Current().ID != expected.VersionID {
			return fmt.Errorf("Cloudflare bootstrap %s Worker version closure changed before deletion", role)
		}
	}
	if err := versionPager.Err(); err != nil || versionCount != 1 {
		return fmt.Errorf("Cloudflare bootstrap %s Worker version closure is incomplete before deletion", role)
	}
	if _, err := control.client.Workers.Scripts.Delete(ctx, script, workers.ScriptDeleteParams{AccountID: cloudflareapi.F(plan.AccountID), Force: cloudflareapi.F(false)}); err != nil {
		return errors.New("delete exact Cloudflare bootstrap Worker")
	}
	return nil
}

func realCloudCloudflareAPINotFound(err error) bool {
	var apiErr *cloudflareapi.Error
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

func validateRealCloudCloudflareBootstrapInventory(plan realCloudCloudflareBootstrapPlan, inventory realCloudCloudflareBootstrapInventory, complete bool) (map[string]bool, map[string]realCloudCloudflareBootstrapInventoryRoute, error) {
	wantedWorkers := realCloudCloudflareBootstrapManagedWorkers(plan)
	seenWorkers := make(map[string]struct{}, len(inventory.Workers))
	for _, script := range inventory.Workers {
		if !validRealCloudProviderIdentifier(script, 128) {
			return nil, nil, errors.New("Cloudflare bootstrap Worker inventory contains an invalid identity")
		}
		if _, duplicate := seenWorkers[script]; duplicate {
			return nil, nil, errors.New("Cloudflare bootstrap Worker inventory repeats an identity")
		}
		seenWorkers[script] = struct{}{}
		if _, relevant := wantedWorkers[script]; relevant {
			wantedWorkers[script] = true
		}
	}
	if realCloudCloudflareBootstrapUsesProvider(plan) && !wantedWorkers[plan.TokenVerifierService] {
		return nil, nil, errors.New("Cloudflare bootstrap token verifier service is absent")
	}
	if complete && (!wantedWorkers[plan.AuthScript] || !wantedWorkers[plan.OriginScript]) {
		return nil, nil, errors.New("Cloudflare bootstrap auth or origin Worker is absent")
	}
	for _, service := range inventory.DomainServices {
		if _, relevant := wantedWorkers[service]; relevant {
			return nil, nil, errors.New("Cloudflare bootstrap security-sensitive Worker has a public custom domain")
		}
	}
	if len(inventory.ManagedAttachments) != 0 {
		return nil, nil, errors.New("Cloudflare bootstrap auth or origin Worker has an unmanaged schedule or tail consumer")
	}
	wantedRoutes := make(map[string]realCloudCloudflareBootstrapRoute, len(plan.Routes))
	for _, route := range plan.Routes {
		wantedRoutes[route.Pattern] = route
	}
	foundRoutes := make(map[string]realCloudCloudflareBootstrapInventoryRoute, len(plan.Routes))
	mainHost := strings.TrimPrefix(plan.MainBase, "https://")
	betaHost := strings.TrimPrefix(plan.BetaBase, "https://")
	for _, route := range inventory.Routes {
		if !validRealCloudProviderIdentifier(route.ID, 128) || route.Pattern == "" || route.Pattern != strings.TrimSpace(route.Pattern) || strings.ContainsAny(route.Pattern, "\x00\r\n\t") {
			return nil, nil, errors.New("Cloudflare route inventory contains an incomplete or unsafe identity")
		}
		wanted, exact := wantedRoutes[route.Pattern]
		_, relevantScript := wantedWorkers[route.Script]
		overlaps := realCloudCloudflareRouteMayMatchHost(route.Pattern, mainHost) || realCloudCloudflareRouteMayMatchHost(route.Pattern, betaHost)
		if !exact && !relevantScript && !overlaps {
			continue
		}
		if !validRealCloudProviderIdentifier(route.Script, 128) {
			return nil, nil, errors.New("Cloudflare bootstrap relevant route has an invalid identity")
		}
		if !exact || route.Script != wanted.Script {
			return nil, nil, errors.New("Cloudflare shared zone contains a foreign, overlapping, or excessive bootstrap route")
		}
		if _, duplicate := foundRoutes[route.Pattern]; duplicate {
			return nil, nil, errors.New("Cloudflare bootstrap route inventory repeats a planned route")
		}
		foundRoutes[route.Pattern] = route
	}
	if complete && len(foundRoutes) != len(plan.Routes) {
		return nil, nil, errors.New("Cloudflare bootstrap main and beta route closure is incomplete")
	}
	return wantedWorkers, foundRoutes, nil
}

func realCloudCloudflareBootstrapExpectedAuthBindingsSHA(plan realCloudCloudflareBootstrapPlan) string {
	rows := make([]string, 0, len(plan.EdgeContract.Variables)+2)
	for name, value := range plan.EdgeContract.Variables {
		rows = append(rows, strings.Join([]string{name, string(workers.ScriptVersionGetResponseResourcesBindingsTypePlainText), value}, "\x00"))
	}
	rows = append(rows,
		strings.Join([]string{"ORIGIN", string(workers.ScriptVersionGetResponseResourcesBindingsTypeService), plan.OriginScript, realCloudCloudflareBootstrapServiceEnvironment("")}, "\x00"),
	)
	if realCloudCloudflareBootstrapUsesProvider(plan) {
		rows = append(rows, strings.Join([]string{"TOKEN_VERIFIER", string(workers.ScriptVersionGetResponseResourcesBindingsTypeService), plan.TokenVerifierService, realCloudCloudflareBootstrapServiceEnvironment(plan.TokenVerifierEnvironment)}, "\x00"))
	} else {
		rows = append(rows, strings.Join([]string{plan.TokenVerifierSecret, string(workers.ScriptVersionGetResponseResourcesBindingsTypeSecretText)}, "\x00"))
	}
	sort.Strings(rows)
	body, _ := json.Marshal(rows)
	return realCloudLowerSHA256(body)
}

func realCloudCloudflareBootstrapExpectedOriginBindingsSHA(plan realCloudCloudflareBootstrapPlan) string {
	body, _ := json.Marshal([]string{"REPOSITORY", string(workers.ScriptVersionGetResponseResourcesBindingsTypeR2Bucket), plan.R2Bucket})
	return realCloudLowerSHA256(body)
}

func validateRealCloudCloudflareBootstrapWorkerState(role string, state realCloudCloudflareBootstrapWorkerState, plan realCloudCloudflareBootstrapPlan, runID string, requireExposureDisabled bool) error {
	if !validRealCloudRunID(runID) {
		return errors.New("Cloudflare bootstrap Worker validation run ID is invalid")
	}
	var script, contentSHA, bindingsSHA string
	switch role {
	case "auth":
		script, contentSHA, bindingsSHA = plan.AuthScript, plan.AuthBundle.SHA256, realCloudCloudflareBootstrapExpectedAuthBindingsSHA(plan)
	case "origin":
		script, contentSHA, bindingsSHA = plan.OriginScript, plan.OriginBundle.SHA256, realCloudCloudflareBootstrapExpectedOriginBindingsSHA(plan)
	case "verifier":
		if !realCloudCloudflareBootstrapUsesProvider(plan) {
			return errors.New("static Cloudflare bootstrap has no token-verifier Worker state")
		}
		script, contentSHA, bindingsSHA = plan.TokenVerifierService, plan.TokenVerifierContentSHA256, plan.TokenVerifierBindingsSHA256
	default:
		return errors.New("unknown Cloudflare bootstrap Worker role")
	}
	if state.Script != script || state.ContentSHA256 != contentSHA || state.BindingsSHA256 != bindingsSHA ||
		!validRealCloudProviderIdentifier(state.DeploymentID, 128) || !validRealCloudProviderIdentifier(state.VersionID, 128) ||
		!validRealCloudProviderETag(state.VersionETag) {
		return fmt.Errorf("Cloudflare bootstrap %s Worker active identity differs from the exact plan", role)
	}
	if role != "verifier" {
		message, tag := realCloudCloudflareBootstrapOwnershipAnnotations(plan, runID)
		if state.OwnershipMessage != message || state.OwnershipTag != tag {
			return fmt.Errorf("Cloudflare bootstrap %s Worker is not owned by the exact reviewed plan", role)
		}
		if state.CompatibilityDate != plan.CompatibilityDate || len(state.CompatibilityFlags) != len(plan.CompatibilityFlags) {
			return fmt.Errorf("Cloudflare bootstrap %s Worker runtime differs from the exact plan", role)
		}
		for index := range state.CompatibilityFlags {
			if state.CompatibilityFlags[index] != plan.CompatibilityFlags[index] {
				return fmt.Errorf("Cloudflare bootstrap %s Worker compatibility flags differ from the exact plan", role)
			}
		}
	} else if state.CompatibilityDate != plan.TokenVerifierCompatibilityDate || !equalRealCloudStrings(state.CompatibilityFlags, plan.TokenVerifierCompatibilityFlags) {
		return errors.New("Cloudflare bootstrap verifier runtime differs from the exact plan")
	}
	if requireExposureDisabled && !state.ExposureDisabled {
		return fmt.Errorf("Cloudflare bootstrap %s Worker workers.dev or preview exposure is enabled", role)
	}
	return nil
}

func inspectRealCloudCloudflareBootstrapExisting(ctx context.Context, control realCloudCloudflareBootstrapControl, plan realCloudCloudflareBootstrapPlan, runID string, workersFound map[string]bool, requireExposureDisabled bool) (map[string]realCloudCloudflareBootstrapWorkerState, error) {
	roles := []string{"origin", "auth"}
	if realCloudCloudflareBootstrapUsesProvider(plan) {
		roles = append([]string{"verifier"}, roles...)
	}
	states := make(map[string]realCloudCloudflareBootstrapWorkerState, len(roles))
	for _, role := range roles {
		var script string
		switch role {
		case "verifier":
			script = plan.TokenVerifierService
		case "origin":
			script = plan.OriginScript
		case "auth":
			script = plan.AuthScript
		}
		if !workersFound[script] {
			continue
		}
		state, err := control.Inspect(ctx, plan, role)
		if err != nil {
			return nil, fmt.Errorf("inspect Cloudflare bootstrap %s Worker: %w", role, err)
		}
		requireExposure := requireExposureDisabled || role == "verifier"
		if err := validateRealCloudCloudflareBootstrapWorkerState(role, state, plan, runID, requireExposure); err != nil {
			return nil, err
		}
		states[role] = state
	}
	return states, nil
}

// Cloudflare never returns a secret_text value. An unsealed static apply
// therefore cannot prove that a same-run auth Worker contains the entitlement
// supplied by the recovering process. Remove only the exact run-owned routes
// and auth Worker under the provider-visible lease, then create them again.
// A sealed receipt is handled by the caller's read-only replay path and never
// reaches this reset.
func resetRealCloudCloudflareUnsealedStaticAuth(
	ctx context.Context,
	control realCloudCloudflareBootstrapControl,
	plan realCloudCloudflareBootstrapPlan,
	runID string,
	states map[string]realCloudCloudflareBootstrapWorkerState,
	routesFound map[string]realCloudCloudflareBootstrapInventoryRoute,
) error {
	if plan.TokenVerifierKind != "env" {
		return nil
	}
	auth, exists := states["auth"]
	if !exists {
		if len(routesFound) != 0 {
			return errors.New("Cloudflare static bootstrap found planned routes without the run-owned auth Worker")
		}
		return nil
	}
	if !auth.ExposureDisabled {
		if len(routesFound) != 0 {
			return errors.New("Cloudflare static bootstrap found routes attached to an exposed partial auth Worker")
		}
		if err := control.DisableExposure(ctx, plan, plan.AuthScript); err != nil {
			return fmt.Errorf("disable unsealed Cloudflare static auth Worker before reset: %w", err)
		}
		var err error
		auth, err = control.Inspect(ctx, plan, "auth")
		if err != nil || validateRealCloudCloudflareBootstrapWorkerState("auth", auth, plan, runID, true) != nil {
			return errors.New("verify unsealed Cloudflare static auth Worker before reset")
		}
	}
	for _, planned := range plan.Routes {
		route, found := routesFound[planned.Pattern]
		if !found {
			continue
		}
		if err := control.DeleteRouteIfMatch(ctx, plan, route); err != nil {
			return fmt.Errorf("reset unsealed Cloudflare static route %s: %w", planned.Pattern, err)
		}
		delete(routesFound, planned.Pattern)
	}
	if err := control.DeleteScriptIfMatch(ctx, plan, "auth", runID, realCloudCloudflareBootstrapReceiptWorkerFromState(auth)); err != nil {
		return fmt.Errorf("reset unsealed Cloudflare static auth Worker: %w", err)
	}
	delete(states, "auth")
	return nil
}

func applyRealCloudCloudflareBootstrap(ctx context.Context, control realCloudCloudflareBootstrapControl, resource realCloudProviderReadinessResource, plan realCloudCloudflareBootstrapPlan, planSHA, runID string) (realCloudCloudflareBootstrapReceipt, error) {
	var receipt realCloudCloudflareBootstrapReceipt
	if control == nil || planSHA != realCloudCloudflareBootstrapPlanSHA(plan) || !validRealCloudRunID(runID) {
		return receipt, errors.New("Cloudflare bootstrap apply dependencies are invalid")
	}
	inventory, err := control.Inventory(ctx, plan)
	if err != nil {
		return receipt, err
	}
	workersFound, routesFound, err := validateRealCloudCloudflareBootstrapInventory(plan, inventory, false)
	if err != nil {
		return receipt, err
	}
	states, err := inspectRealCloudCloudflareBootstrapExisting(ctx, control, plan, runID, workersFound, false)
	if err != nil {
		return receipt, err
	}
	if len(routesFound) != 0 {
		if _, owned := states["auth"]; !owned {
			return receipt, errors.New("Cloudflare bootstrap planned route exists without the run-owned auth Worker")
		}
	}
	if err := resetRealCloudCloudflareUnsealedStaticAuth(ctx, control, plan, runID, states, routesFound); err != nil {
		return receipt, err
	}
	for _, role := range []string{"origin", "auth"} {
		var script string
		if role == "origin" {
			script = plan.OriginScript
		} else {
			script = plan.AuthScript
		}
		state, exists := states[role]
		if !exists {
			if err := control.Upload(ctx, plan, role, planSHA, runID); err != nil {
				return receipt, fmt.Errorf("upload Cloudflare bootstrap %s Worker: %w", role, err)
			}
		}
		if !exists || !state.ExposureDisabled {
			if err := control.DisableExposure(ctx, plan, script); err != nil {
				return receipt, fmt.Errorf("disable Cloudflare bootstrap %s exposure: %w", role, err)
			}
		}
		state, err = control.Inspect(ctx, plan, role)
		if err != nil {
			return receipt, fmt.Errorf("inspect Cloudflare bootstrap %s Worker after reconciliation: %w", role, err)
		}
		if err := validateRealCloudCloudflareBootstrapWorkerState(role, state, plan, runID, true); err != nil {
			return receipt, fmt.Errorf("verify Cloudflare bootstrap %s Worker after reconciliation: %w", role, err)
		}
		states[role] = state
	}
	for _, route := range plan.Routes {
		if _, exists := routesFound[route.Pattern]; exists {
			continue
		}
		auth, inspectErr := control.Inspect(ctx, plan, "auth")
		if inspectErr != nil || validateRealCloudCloudflareBootstrapWorkerState("auth", auth, plan, runID, true) != nil {
			return receipt, fmt.Errorf("recheck run-owned Cloudflare bootstrap auth Worker before route %s", route.Pattern)
		}
		if _, err := control.CreateRoute(ctx, plan, route); err != nil {
			return receipt, fmt.Errorf("create Cloudflare bootstrap route %s: %w", route.Pattern, err)
		}
	}
	return observeRealCloudCloudflareBootstrapClosure(ctx, control, resource, plan, planSHA, runID, "apply")
}

func observeRealCloudCloudflareBootstrapClosure(ctx context.Context, control realCloudCloudflareBootstrapControl, resource realCloudProviderReadinessResource, plan realCloudCloudflareBootstrapPlan, planSHA, runID, mode string) (realCloudCloudflareBootstrapReceipt, error) {
	first, err := collectRealCloudCloudflareBootstrapClosure(ctx, control, resource, plan, planSHA, runID, mode)
	if err != nil {
		return realCloudCloudflareBootstrapReceipt{}, err
	}
	second, err := collectRealCloudCloudflareBootstrapClosure(ctx, control, resource, plan, planSHA, runID, mode)
	if err != nil {
		return realCloudCloudflareBootstrapReceipt{}, err
	}
	if first.ClosureSHA256 != second.ClosureSHA256 {
		return realCloudCloudflareBootstrapReceipt{}, errors.New("Cloudflare bootstrap closure changed between consecutive complete observations")
	}
	return second, nil
}

func collectRealCloudCloudflareBootstrapClosure(ctx context.Context, control realCloudCloudflareBootstrapControl, resource realCloudProviderReadinessResource, plan realCloudCloudflareBootstrapPlan, planSHA, runID, mode string) (realCloudCloudflareBootstrapReceipt, error) {
	var receipt realCloudCloudflareBootstrapReceipt
	inventory, err := control.Inventory(ctx, plan)
	if err != nil {
		return receipt, err
	}
	workersFound, routesFound, err := validateRealCloudCloudflareBootstrapInventory(plan, inventory, true)
	if err != nil {
		return receipt, err
	}
	states, err := inspectRealCloudCloudflareBootstrapExisting(ctx, control, plan, runID, workersFound, true)
	if err != nil {
		return receipt, err
	}
	routes := make([]realCloudCloudflareBootstrapReceiptRoute, 0, len(routesFound))
	for _, planned := range plan.Routes {
		route := routesFound[planned.Pattern]
		routes = append(routes, realCloudCloudflareBootstrapReceiptRoute(route))
	}
	receipt = realCloudCloudflareBootstrapReceipt{
		Schema: realCloudCloudflareBootstrapReceiptSchema, RunID: runID, Mode: mode,
		ReadinessResourceSHA256: realCloudProviderReadinessResourceSHA(resource), PlanSHA256: planSHA,
		AccountID: plan.AccountID, ZoneID: plan.ZoneID, Auth: realCloudCloudflareBootstrapReceiptWorkerFromState(states["auth"]), Origin: realCloudCloudflareBootstrapReceiptWorkerFromState(states["origin"]),
		Verifier: realCloudCloudflareBootstrapReceiptWorkerFromState(states["verifier"]), Routes: routes, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	receipt.ClosureSHA256 = realCloudCloudflareBootstrapReceiptClosureSHA(receipt)
	return receipt, nil
}

func realCloudCloudflareBootstrapReceiptClosureSHA(receipt realCloudCloudflareBootstrapReceipt) string {
	closureBody, _ := json.Marshal(struct {
		Resource string                                     `json:"resource"`
		Plan     string                                     `json:"plan"`
		Auth     realCloudCloudflareBootstrapReceiptWorker  `json:"auth"`
		Origin   realCloudCloudflareBootstrapReceiptWorker  `json:"origin"`
		Verifier realCloudCloudflareBootstrapReceiptWorker  `json:"verifier"`
		Routes   []realCloudCloudflareBootstrapReceiptRoute `json:"routes"`
	}{receipt.ReadinessResourceSHA256, receipt.PlanSHA256, receipt.Auth, receipt.Origin, receipt.Verifier, receipt.Routes})
	return realCloudLowerSHA256(closureBody)
}

func validateRealCloudCloudflareBootstrapReceipt(receipt realCloudCloudflareBootstrapReceipt, resource realCloudProviderReadinessResource, plan realCloudCloudflareBootstrapPlan, planSHA, mode, runID string) error {
	if receipt.Schema != realCloudCloudflareBootstrapReceiptSchema || receipt.Mode != mode || receipt.RunID != runID ||
		receipt.ReadinessResourceSHA256 != realCloudProviderReadinessResourceSHA(resource) || receipt.PlanSHA256 != planSHA ||
		receipt.AccountID != plan.AccountID || receipt.ZoneID != plan.ZoneID || !validRealCloudLowerSHA256(receipt.ClosureSHA256) {
		return errors.New("Cloudflare bootstrap receipt identity differs from the selected run")
	}
	if _, err := time.Parse(time.RFC3339Nano, receipt.ObservedAt); err != nil {
		return errors.New("Cloudflare bootstrap receipt observation time is invalid")
	}
	wantedWorkers := []realCloudCloudflareBootstrapReceiptWorker{receipt.Auth, receipt.Origin}
	if realCloudCloudflareBootstrapUsesProvider(plan) {
		wantedWorkers = append(wantedWorkers, receipt.Verifier)
	} else if receipt.Verifier != (realCloudCloudflareBootstrapReceiptWorker{}) {
		return errors.New("static Cloudflare bootstrap receipt contains a token-verifier Worker")
	}
	for _, worker := range wantedWorkers {
		if !validRealCloudProviderIdentifier(worker.Script, 128) || !validRealCloudProviderIdentifier(worker.DeploymentID, 128) ||
			!validRealCloudProviderIdentifier(worker.VersionID, 128) || !validRealCloudProviderETag(worker.VersionETag) ||
			!validRealCloudLowerSHA256(worker.ContentSHA256) || !validRealCloudLowerSHA256(worker.BindingsSHA256) {
			return errors.New("Cloudflare bootstrap receipt Worker evidence is invalid")
		}
	}
	if receipt.Auth.Script != plan.AuthScript || receipt.Origin.Script != plan.OriginScript ||
		receipt.Auth.ContentSHA256 != plan.AuthBundle.SHA256 || receipt.Origin.ContentSHA256 != plan.OriginBundle.SHA256 ||
		receipt.Auth.BindingsSHA256 != realCloudCloudflareBootstrapExpectedAuthBindingsSHA(plan) ||
		receipt.Origin.BindingsSHA256 != realCloudCloudflareBootstrapExpectedOriginBindingsSHA(plan) {
		return errors.New("Cloudflare bootstrap receipt Worker closure differs from the plan")
	}
	if realCloudCloudflareBootstrapUsesProvider(plan) && (receipt.Verifier.Script != plan.TokenVerifierService ||
		receipt.Verifier.ContentSHA256 != plan.TokenVerifierContentSHA256 || receipt.Verifier.BindingsSHA256 != plan.TokenVerifierBindingsSHA256) {
		return errors.New("Cloudflare bootstrap receipt token-verifier closure differs from the plan")
	}
	message, tag := realCloudCloudflareBootstrapOwnershipAnnotations(plan, runID)
	if receipt.Auth.OwnershipMessage != message || receipt.Auth.OwnershipTag != tag ||
		receipt.Origin.OwnershipMessage != message || receipt.Origin.OwnershipTag != tag ||
		receipt.Verifier.OwnershipMessage != "" || receipt.Verifier.OwnershipTag != "" {
		return errors.New("Cloudflare bootstrap receipt ownership closure differs from the plan")
	}
	if len(receipt.Routes) != len(plan.Routes) {
		return errors.New("Cloudflare bootstrap receipt route closure is incomplete")
	}
	for index, route := range receipt.Routes {
		if !validRealCloudProviderIdentifier(route.ID, 128) || route.Pattern != plan.Routes[index].Pattern || route.Script != plan.Routes[index].Script {
			return errors.New("Cloudflare bootstrap receipt route closure differs from the plan")
		}
	}
	if realCloudCloudflareBootstrapReceiptClosureSHA(receipt) != receipt.ClosureSHA256 {
		return errors.New("Cloudflare bootstrap receipt closure digest is invalid")
	}
	return nil
}

func rollbackRealCloudCloudflareBootstrap(ctx context.Context, control realCloudCloudflareBootstrapControl, resource realCloudProviderReadinessResource, plan realCloudCloudflareBootstrapPlan, planSHA, runID string, applyReceipt realCloudCloudflareBootstrapReceipt) (realCloudCloudflareBootstrapReceipt, error) {
	var rollback realCloudCloudflareBootstrapReceipt
	if control == nil || planSHA != realCloudCloudflareBootstrapPlanSHA(plan) || !validRealCloudRunID(runID) {
		return rollback, errors.New("Cloudflare bootstrap rollback dependencies are invalid")
	}
	if err := validateRealCloudCloudflareBootstrapReceipt(applyReceipt, resource, plan, planSHA, "apply", runID); err != nil {
		return rollback, err
	}
	inventory, err := control.Inventory(ctx, plan)
	if err != nil {
		return rollback, err
	}
	workersFound, routesFound, err := validateRealCloudCloudflareBootstrapInventory(plan, inventory, false)
	if err != nil {
		return rollback, err
	}
	states, err := inspectRealCloudCloudflareBootstrapExisting(ctx, control, plan, runID, workersFound, true)
	if err != nil {
		return rollback, err
	}
	if realCloudCloudflareBootstrapUsesProvider(plan) {
		if _, exists := states["verifier"]; !exists {
			return rollback, errors.New("Cloudflare bootstrap rollback refuses an absent token verifier")
		}
		if !realCloudCloudflareBootstrapStateMatchesReceipt(states["verifier"], applyReceipt.Verifier) {
			return rollback, errors.New("Cloudflare bootstrap rollback token verifier differs from the sealed apply receipt")
		}
	}
	for role, workerReceipt := range map[string]realCloudCloudflareBootstrapReceiptWorker{"auth": applyReceipt.Auth, "origin": applyReceipt.Origin} {
		if state, exists := states[role]; exists && !realCloudCloudflareBootstrapStateMatchesReceipt(state, workerReceipt) {
			return rollback, fmt.Errorf("Cloudflare bootstrap rollback %s Worker differs from the sealed apply receipt", role)
		}
	}
	receiptRouteIDs := make(map[string]string, len(applyReceipt.Routes))
	for _, route := range applyReceipt.Routes {
		receiptRouteIDs[route.Pattern] = route.ID
	}
	for _, planned := range plan.Routes {
		expected := realCloudCloudflareBootstrapInventoryRoute{
			ID: receiptRouteIDs[planned.Pattern], Pattern: planned.Pattern, Script: planned.Script,
		}
		if route, listed := routesFound[planned.Pattern]; listed && route != expected {
			return rollback, errors.New("Cloudflare bootstrap rollback route ID differs from the sealed apply receipt")
		}
		if err := control.DeleteRouteIfMatch(ctx, plan, expected); err != nil {
			return rollback, fmt.Errorf("delete Cloudflare bootstrap route %s: %w", expected.Pattern, err)
		}
	}
	for _, role := range []string{"auth", "origin"} {
		workerReceipt := applyReceipt.Auth
		if role == "origin" {
			workerReceipt = applyReceipt.Origin
		}
		if err := control.DeleteScriptIfMatch(ctx, plan, role, runID, workerReceipt); err != nil {
			return rollback, fmt.Errorf("delete Cloudflare bootstrap %s Worker: %w", role, err)
		}
	}
	finalInventory, err := control.Inventory(ctx, plan)
	if err != nil {
		return rollback, err
	}
	finalWorkers, finalRoutes, err := validateRealCloudCloudflareBootstrapInventory(plan, finalInventory, false)
	if err != nil {
		return rollback, err
	}
	if finalWorkers[plan.AuthScript] || finalWorkers[plan.OriginScript] || len(finalRoutes) != 0 {
		return rollback, errors.New("Cloudflare bootstrap rollback left an auth/origin Worker or planned route")
	}
	var verifier realCloudCloudflareBootstrapWorkerState
	if realCloudCloudflareBootstrapUsesProvider(plan) {
		verifier, err = control.Inspect(ctx, plan, "verifier")
		if err != nil || validateRealCloudCloudflareBootstrapWorkerState("verifier", verifier, plan, runID, true) != nil ||
			!realCloudCloudflareBootstrapStateMatchesReceipt(verifier, applyReceipt.Verifier) {
			return rollback, errors.New("Cloudflare bootstrap rollback changed or exposed the token verifier")
		}
	}
	rollback = applyReceipt
	rollback.Mode = "rollback"
	rollback.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	body, _ := json.Marshal([]any{applyReceipt.ClosureSHA256, "auth-origin-and-routes-absent", workerReceiptIdentity(verifier)})
	rollback.ClosureSHA256 = realCloudLowerSHA256(body)
	return rollback, nil
}

func realCloudCloudflareBootstrapStateMatchesReceipt(state realCloudCloudflareBootstrapWorkerState, receipt realCloudCloudflareBootstrapReceiptWorker) bool {
	return state.Script == receipt.Script && state.DeploymentID == receipt.DeploymentID && state.VersionID == receipt.VersionID &&
		state.VersionETag == receipt.VersionETag && state.ContentSHA256 == receipt.ContentSHA256 && state.BindingsSHA256 == receipt.BindingsSHA256 &&
		state.OwnershipMessage == receipt.OwnershipMessage && state.OwnershipTag == receipt.OwnershipTag
}

func realCloudCloudflareBootstrapReceiptWorkerFromState(state realCloudCloudflareBootstrapWorkerState) realCloudCloudflareBootstrapReceiptWorker {
	return realCloudCloudflareBootstrapReceiptWorker{
		Script: state.Script, DeploymentID: state.DeploymentID, VersionID: state.VersionID, VersionETag: state.VersionETag,
		ContentSHA256: state.ContentSHA256, BindingsSHA256: state.BindingsSHA256,
		OwnershipMessage: state.OwnershipMessage, OwnershipTag: state.OwnershipTag,
	}
}

func workerReceiptIdentity(state realCloudCloudflareBootstrapWorkerState) []string {
	return []string{state.Script, state.DeploymentID, state.VersionID, state.VersionETag, state.ContentSHA256, state.BindingsSHA256, state.OwnershipMessage, state.OwnershipTag}
}

func writeRealCloudCloudflareBootstrapReceipt(t *testing.T, path string, receipt realCloudCloudflareBootstrapReceipt) {
	t.Helper()
	receiptBody, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal("encode Cloudflare bootstrap receipt")
	}
	envelope := realCloudCloudflareBootstrapEnvelope{
		Schema: realCloudCloudflareBootstrapEnvelopeSchema, Receipt: receipt,
		ReceiptSHA256: realCloudLowerSHA256(receiptBody), ReceiptSize: len(receiptBody),
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal("encode Cloudflare bootstrap receipt envelope")
	}
	body = append(body, '\n')
	if containsRealEdgeURLLeak(body) {
		t.Fatal("Cloudflare bootstrap receipt exposed a URL")
	}
	writeRealCloudRegistryCandidate(t, path, body)
}

func readRealCloudCloudflareBootstrapReceipt(t *testing.T, path string) realCloudCloudflareBootstrapReceipt {
	t.Helper()
	body, err := readRealCloudPrivateCanonicalFile(path, 64<<10)
	if err != nil {
		t.Fatalf("read Cloudflare bootstrap receipt envelope: %v", err)
	}
	defer clearRealCloudBytes(body)
	var envelope realCloudCloudflareBootstrapEnvelope
	if err := decodeRealCloudCanonicalJSONFile(body, &envelope); err != nil {
		t.Fatalf("decode Cloudflare bootstrap receipt envelope: %v", err)
	}
	receiptBody, err := json.Marshal(envelope.Receipt)
	if err != nil || envelope.Schema != realCloudCloudflareBootstrapEnvelopeSchema ||
		envelope.ReceiptSize != len(receiptBody) || envelope.ReceiptSHA256 != realCloudLowerSHA256(receiptBody) {
		t.Fatal("Cloudflare bootstrap receipt envelope digest is invalid")
	}
	return envelope.Receipt
}

func validateRealCloudCloudflareBootstrapRollbackReceipt(rollback, apply realCloudCloudflareBootstrapReceipt) error {
	if rollback.Mode != "rollback" || apply.Mode != "apply" || rollback.Schema != apply.Schema || rollback.RunID != apply.RunID ||
		rollback.ReadinessResourceSHA256 != apply.ReadinessResourceSHA256 || rollback.PlanSHA256 != apply.PlanSHA256 ||
		rollback.AccountID != apply.AccountID || rollback.ZoneID != apply.ZoneID || rollback.Auth != apply.Auth || rollback.Origin != apply.Origin ||
		rollback.Verifier != apply.Verifier || len(rollback.Routes) != len(apply.Routes) || !validRealCloudLowerSHA256(rollback.ClosureSHA256) {
		return errors.New("Cloudflare bootstrap rollback receipt differs from its sealed apply receipt")
	}
	for index := range rollback.Routes {
		if rollback.Routes[index] != apply.Routes[index] {
			return errors.New("Cloudflare bootstrap rollback receipt route evidence changed")
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, rollback.ObservedAt); err != nil {
		return errors.New("Cloudflare bootstrap rollback observation time is invalid")
	}
	verifier := []string{apply.Verifier.Script, apply.Verifier.DeploymentID, apply.Verifier.VersionID, apply.Verifier.VersionETag, apply.Verifier.ContentSHA256, apply.Verifier.BindingsSHA256, apply.Verifier.OwnershipMessage, apply.Verifier.OwnershipTag}
	body, _ := json.Marshal([]any{apply.ClosureSHA256, "auth-origin-and-routes-absent", verifier})
	if rollback.ClosureSHA256 != realCloudLowerSHA256(body) {
		return errors.New("Cloudflare bootstrap rollback absence closure digest is invalid")
	}
	return nil
}

func validateRealCloudCloudflareBootstrapRollbackClosure(ctx context.Context, control realCloudCloudflareBootstrapControl, plan realCloudCloudflareBootstrapPlan, runID string, applyReceipt realCloudCloudflareBootstrapReceipt) error {
	inventory, err := control.Inventory(ctx, plan)
	if err != nil {
		return err
	}
	workers, routes, err := validateRealCloudCloudflareBootstrapInventory(plan, inventory, false)
	if err != nil {
		return err
	}
	if workers[plan.AuthScript] || workers[plan.OriginScript] || len(routes) != 0 {
		return errors.New("Cloudflare bootstrap rollback closure still contains an auth/origin Worker or planned route")
	}
	if realCloudCloudflareBootstrapUsesProvider(plan) {
		verifier, inspectErr := control.Inspect(ctx, plan, "verifier")
		if inspectErr != nil || validateRealCloudCloudflareBootstrapWorkerState("verifier", verifier, plan, runID, true) != nil ||
			!realCloudCloudflareBootstrapStateMatchesReceipt(verifier, applyReceipt.Verifier) {
			return errors.New("Cloudflare bootstrap rollback closure changed or exposed the token verifier")
		}
	}
	return nil
}

// TestRealCloudCloudflareBootstrap is the only live mutation entrypoint for
// first deployment of the reviewed Cloudflare auth/origin bundles. TestMain
// admits it only after the independent readiness and bootstrap registries plus
// the exact mutation phrase pass. Apply and rollback use one conditional R2
// lease object under .sow/bootstrap/leases and retire it by compare-and-set
// only after a durable receipt. They never alter repository payload objects, DNS, custom domains,
// any provider token-verifier deployment, or unrelated Worker routes. Static
// plans inject one secret binding into the run-owned auth Worker only.
func TestRealCloudCloudflareBootstrap(t *testing.T) {
	mode := strings.TrimSpace(os.Getenv(realCloudCloudflareBootstrapOptInEnv))
	if mode == "" || mode == "0" {
		t.Skip("set SOW_RUN_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP=apply, rollback, or recover-lease after registry review and explicit authorization")
	}
	if err := validateRealCloudCloudflareBootstrapSelection(mode, os.Getenv); err != nil {
		t.Fatalf("Cloudflare bootstrap selection gate failed: %v", err)
	}
	resource, _, err := decodeRealCloudProviderReadinessResource(os.Getenv(realCloudProviderReadinessResourceEnv))
	if err != nil {
		t.Fatal(err)
	}
	plan, planBody, err := decodeRealCloudCloudflareBootstrapPlan(os.Getenv(realCloudCloudflareBootstrapPlanEnv), resource)
	if err != nil {
		t.Fatal(err)
	}
	planSHA := realCloudLowerSHA256(planBody)
	runID := strings.TrimSpace(os.Getenv(realCloudRunIDEnv))
	if !validRealCloudRunID(runID) {
		t.Fatalf("%s must identify this Cloudflare bootstrap run", realCloudRunIDEnv)
	}
	client := realCloudProviderHTTPClient()
	runtime, err := newRealCloudCloudflareBootstrapRuntime(
		mode, resource, plan, os.Getenv, "https://api.cloudflare.com/client/v4", client,
	)
	if err != nil {
		assertNoRealCloudSecret(t, "Cloudflare bootstrap runtime error", []byte(err.Error()), runtime.secretFragments)
		t.Fatal(err)
	}
	leaseStore := runtime.leaseStore
	secretFragments := runtime.secretFragments
	receiptPath := validateRealCloudPrivateReceiptPath(t, realCloudCloudflareBootstrapReceiptEnv, os.Getenv(realCloudCloudflareBootstrapReceiptEnv))
	if mode == "recover-lease" {
		recoveryPath := strings.TrimSuffix(receiptPath, ".json") + ".lease-recovery.json"
		if _, statErr := os.Lstat(recoveryPath); statErr == nil {
			recovered, completeErr := completeRealCloudCloudflareBootstrapLeaseRecovery(
				t.Context(), leaseStore, plan, planSHA, runID, recoveryPath,
			)
			if completeErr != nil {
				assertNoRealCloudSecret(t, "Cloudflare bootstrap lease recovery replay error", []byte(completeErr.Error()), secretFragments)
				t.Fatalf("resume Cloudflare bootstrap expired lease recovery: %v", completeErr)
			}
			t.Logf("Cloudflare bootstrap expired lease recovery is already durable receipt=%s recovered_run=%s", recoveryPath, recovered.RunID)
			return
		} else if !os.IsNotExist(statErr) {
			t.Fatalf("inspect Cloudflare bootstrap lease recovery receipt: %v", statErr)
		}
		pending, beginErr := beginRealCloudCloudflareBootstrapLeaseRecovery(t.Context(), leaseStore, plan, planSHA, runID, time.Now())
		if beginErr != nil {
			assertNoRealCloudSecret(t, "Cloudflare bootstrap lease recovery begin error", []byte(beginErr.Error()), secretFragments)
			t.Fatalf("begin Cloudflare bootstrap expired lease recovery: %v", beginErr)
		}
		recoveryReceipt, err := newRealCloudCloudflareBootstrapLeaseRecoveryReceipt(pending, plan, planSHA, runID)
		if err != nil {
			t.Fatal(err)
		}
		if err := persistRealCloudCloudflareBootstrapLeaseRecoveryReceipt(recoveryPath, recoveryReceipt, plan, planSHA, runID); err != nil {
			t.Fatalf("persist Cloudflare bootstrap lease recovery receipt: %v", err)
		}
		recovered, completeErr := completeRealCloudCloudflareBootstrapLeaseRecovery(
			t.Context(), leaseStore, plan, planSHA, runID, recoveryPath,
		)
		if completeErr != nil {
			assertNoRealCloudSecret(t, "Cloudflare bootstrap lease recovery completion error", []byte(completeErr.Error()), secretFragments)
			t.Fatalf("complete Cloudflare bootstrap expired lease recovery: %v", completeErr)
		}
		t.Logf("Cloudflare bootstrap expired lease recovered receipt=%s recovered_run=%s", recoveryPath, recovered.RunID)
		return
	}
	control := runtime.control
	if control == nil {
		t.Fatal("Cloudflare bootstrap Worker client is absent outside recover-lease mode")
	}
	readinessReceipt, err := loadValidatedRealCloudCloudflareBootstrapReadinessReceipt(
		strings.TrimSpace(os.Getenv(realCloudCloudflareBootstrapReadinessReceiptEnv)), resource, runID,
		plan.ReadinessSealPublicKey, time.Now(),
	)
	if err != nil {
		t.Fatalf("load Cloudflare bootstrap readiness receipt for post-lease revalidation: %v", err)
	}
	if err := validateRealCloudCloudflareBootstrapReadinessMarkerResource(readinessReceipt, plan); err != nil {
		t.Fatal(err)
	}
	environment := realCloudProviderReadinessEnvironment(resource)
	providerClosure := func(ctx context.Context) error {
		observedSHA, err := collectRealCloudCloudflareReadinessControl(ctx, environment, *resource.Cloudflare, control.client)
		if err != nil {
			return err
		}
		if observedSHA != readinessReceipt.ProviderControlSHA256 {
			return errors.New("Cloudflare exact zone or main-and-beta R2 custom-domain closure differs from the readiness receipt")
		}
		return nil
	}
	switch mode {
	case "apply":
		if _, statErr := os.Lstat(receiptPath); statErr == nil {
			existing := readRealCloudCloudflareBootstrapReceipt(t, receiptPath)
			if err := validateRealCloudCloudflareBootstrapReceipt(existing, resource, plan, planSHA, "apply", runID); err != nil {
				t.Fatalf("existing Cloudflare bootstrap receipt is invalid: %v", err)
			}
			observed, observeErr := observeRealCloudCloudflareBootstrapClosure(t.Context(), control, resource, plan, planSHA, runID, "apply")
			if observeErr != nil || observed.ClosureSHA256 != existing.ClosureSHA256 {
				t.Fatalf("existing Cloudflare bootstrap receipt differs from the current read-only closure: %v", observeErr)
			}
			t.Logf("Cloudflare bootstrap apply replay is already sealed receipt=%s closure_sha256=%s", receiptPath, existing.ClosureSHA256)
			return
		} else if !os.IsNotExist(statErr) {
			t.Fatalf("inspect Cloudflare bootstrap receipt: %v", statErr)
		}
		holder, err := newRealCloudCloudflareBootstrapLeaseHolder()
		if err != nil {
			t.Fatal(err)
		}
		held, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), leaseStore, plan, planSHA, runID, mode, holder, time.Now())
		if err != nil {
			assertNoRealCloudSecret(t, "Cloudflare bootstrap lease acquisition error", []byte(err.Error()), secretFragments)
			t.Fatalf("Cloudflare bootstrap lease acquisition failed: %v", err)
		}
		leasedControl, err := newRealCloudCloudflareLeasedBootstrapControl(t.Context(), control, held, time.Now, providerClosure)
		if err != nil {
			releaseErr := held.release(t.Context())
			combined := errors.Join(err, releaseErr)
			assertNoRealCloudSecret(t, "Cloudflare bootstrap post-lease closure error", []byte(combined.Error()), secretFragments)
			t.Fatalf("Cloudflare bootstrap post-lease closure failed before any Worker or route mutation: %v", combined)
		}
		if plan.TokenVerifierKind == "env" {
			staticRaw := os.Getenv(plan.TokenVerifierSecret)
			secretFragments = append(secretFragments, realCloudCloudflareStaticSecretFragments(staticRaw)...)
			if err := bindRealCloudCloudflareStaticEntitlement(control, plan, staticRaw, time.Now().UTC()); err != nil {
				releaseErr := held.release(t.Context())
				combined := errors.Join(err, releaseErr)
				assertNoRealCloudSecret(t, "Cloudflare static entitlement mutation-gate error", []byte(combined.Error()), secretFragments)
				t.Fatalf("Cloudflare static entitlement failed after the leased readiness gate and before Worker mutation: %v", combined)
			}
		}
		receipt, applyErr := applyRealCloudCloudflareBootstrap(t.Context(), leasedControl, resource, plan, planSHA, runID)
		if applyErr != nil {
			assertNoRealCloudSecret(t, "Cloudflare bootstrap apply error", []byte(applyErr.Error()), secretFragments)
			t.Fatalf("Cloudflare bootstrap apply failed: %v", applyErr)
		}
		if err := validateRealCloudCloudflareBootstrapReceipt(receipt, resource, plan, planSHA, "apply", runID); err != nil {
			t.Fatal(err)
		}
		if plan.TokenVerifierKind == "env" {
			if err := validateRealCloudCloudflareStaticEntitlements(control.secretBindings[plan.TokenVerifierSecret], plan, time.Now().UTC()); err != nil {
				assertNoRealCloudSecret(t, "Cloudflare static entitlement post-closure error", []byte(err.Error()), secretFragments)
				t.Fatalf("Cloudflare static entitlement lost its minimum lifetime before durable receipt: %v", err)
			}
		}
		if err := held.renew(t.Context(), time.Now()); err != nil {
			t.Fatalf("renew Cloudflare bootstrap lease before durable receipt: %v", err)
		}
		writeRealCloudCloudflareBootstrapReceipt(t, receiptPath, receipt)
		if err := held.release(t.Context()); err != nil {
			t.Fatalf("release Cloudflare bootstrap lease after durable receipt: %v", err)
		}
		t.Logf("Cloudflare bootstrap apply receipt=%s closure_sha256=%s", receiptPath, receipt.ClosureSHA256)
	case "rollback":
		applyReceipt := readRealCloudCloudflareBootstrapReceipt(t, receiptPath)
		if err := validateRealCloudCloudflareBootstrapReceipt(applyReceipt, resource, plan, planSHA, "apply", runID); err != nil {
			t.Fatal(err)
		}
		rollbackPath := strings.TrimSuffix(receiptPath, ".json") + ".rollback.json"
		if _, statErr := os.Lstat(rollbackPath); statErr == nil {
			existing := readRealCloudCloudflareBootstrapReceipt(t, rollbackPath)
			if err := validateRealCloudCloudflareBootstrapRollbackReceipt(existing, applyReceipt); err != nil {
				t.Fatalf("existing Cloudflare bootstrap rollback receipt is invalid: %v", err)
			}
			if err := validateRealCloudCloudflareBootstrapRollbackClosure(t.Context(), control, plan, runID, applyReceipt); err != nil {
				t.Fatalf("existing Cloudflare bootstrap rollback receipt differs from the current read-only absence closure: %v", err)
			}
			t.Logf("Cloudflare bootstrap rollback replay is already sealed receipt=%s closure_sha256=%s", rollbackPath, existing.ClosureSHA256)
			return
		} else if !os.IsNotExist(statErr) {
			t.Fatalf("inspect Cloudflare bootstrap rollback receipt: %v", statErr)
		}
		holder, err := newRealCloudCloudflareBootstrapLeaseHolder()
		if err != nil {
			t.Fatal(err)
		}
		held, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), leaseStore, plan, planSHA, runID, mode, holder, time.Now())
		if err != nil {
			assertNoRealCloudSecret(t, "Cloudflare bootstrap lease acquisition error", []byte(err.Error()), secretFragments)
			t.Fatalf("Cloudflare bootstrap lease acquisition failed: %v", err)
		}
		leasedControl, err := newRealCloudCloudflareLeasedBootstrapControl(t.Context(), control, held, time.Now, providerClosure)
		if err != nil {
			releaseErr := held.release(t.Context())
			combined := errors.Join(err, releaseErr)
			assertNoRealCloudSecret(t, "Cloudflare bootstrap post-lease closure error", []byte(combined.Error()), secretFragments)
			t.Fatalf("Cloudflare bootstrap post-lease closure failed before any Worker or route mutation: %v", combined)
		}
		rollback, rollbackErr := rollbackRealCloudCloudflareBootstrap(t.Context(), leasedControl, resource, plan, planSHA, runID, applyReceipt)
		if rollbackErr != nil {
			assertNoRealCloudSecret(t, "Cloudflare bootstrap rollback error", []byte(rollbackErr.Error()), secretFragments)
			t.Fatalf("Cloudflare bootstrap rollback failed: %v", rollbackErr)
		}
		if err := validateRealCloudCloudflareBootstrapRollbackReceipt(rollback, applyReceipt); err != nil {
			t.Fatal(err)
		}
		if err := held.renew(t.Context(), time.Now()); err != nil {
			t.Fatalf("renew Cloudflare bootstrap lease before durable rollback receipt: %v", err)
		}
		writeRealCloudCloudflareBootstrapReceipt(t, rollbackPath, rollback)
		if err := held.release(t.Context()); err != nil {
			t.Fatalf("release Cloudflare bootstrap lease after durable rollback receipt: %v", err)
		}
		t.Logf("Cloudflare bootstrap rollback receipt=%s closure_sha256=%s", rollbackPath, rollback.ClosureSHA256)
	}
}

type fakeRealCloudCloudflareBootstrapControl struct {
	workers                map[string]realCloudCloudflareBootstrapWorkerState
	routes                 map[string]realCloudCloudflareBootstrapInventoryRoute
	domains                []string
	attachments            []string
	fail                   map[string]int
	calls                  map[string]int
	nextID                 int
	omitWorkerInventory    map[string]bool
	omitRouteInventory     map[string]bool
	errorAfterRouteDelete  map[string]int
	errorAfterScriptDelete map[string]int
	beforeDeleteRoute      func(*fakeRealCloudCloudflareBootstrapControl, realCloudCloudflareBootstrapInventoryRoute)
	beforeDeleteScript     func(*fakeRealCloudCloudflareBootstrapControl, string, realCloudCloudflareBootstrapReceiptWorker)
}

type fakeRealCloudCloudflareBootstrapLeaseStore struct {
	key                  string
	body                 []byte
	etag                 string
	version              int
	putCalls             int
	deleteCalls          int
	responseLossAfterPut int
	beforePut            func(*fakeRealCloudCloudflareBootstrapLeaseStore, publish.R2PutCondition)
	afterPut             func(*fakeRealCloudCloudflareBootstrapLeaseStore, []byte)
	extraObjects         []publish.ListedObject
	listPages            map[string]publish.ObjectListPage
}

func (store *fakeRealCloudCloudflareBootstrapLeaseStore) R2GetControl(_ context.Context, key string) (publish.ControlObject, error) {
	if store.key == "" {
		return publish.ControlObject{}, nil
	}
	if key != store.key {
		return publish.ControlObject{}, publish.ErrNotFound
	}
	return publish.ControlObject{Exists: true, Body: append([]byte(nil), store.body...), ETag: store.etag}, nil
}

func (store *fakeRealCloudCloudflareBootstrapLeaseStore) R2ListObjectsV2(_ context.Context, continuation string) (publish.ObjectListPage, error) {
	if store.listPages != nil {
		page, exists := store.listPages[continuation]
		if !exists {
			return publish.ObjectListPage{}, errors.New("unexpected fake lease continuation token")
		}
		return page, nil
	}
	if continuation != "" {
		return publish.ObjectListPage{}, errors.New("unexpected fake lease continuation token")
	}
	objects := append([]publish.ListedObject(nil), store.extraObjects...)
	if store.key != "" {
		objects = append(objects, publish.ListedObject{Key: store.key, Size: int64(len(store.body)), ETag: store.etag})
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Key < objects[j].Key })
	return publish.ObjectListPage{Objects: objects}, nil
}

func (store *fakeRealCloudCloudflareBootstrapLeaseStore) R2Put(_ context.Context, key string, reader io.Reader, size int64, sha string, condition publish.R2PutCondition) (string, error) {
	body, err := io.ReadAll(reader)
	if err != nil || int64(len(body)) != size || realCloudLowerSHA256(body) != sha || condition.IfMatch != "" && condition.IfNoneMatch {
		return "", errors.New("invalid fake lease put")
	}
	store.putCalls++
	if hook := store.beforePut; hook != nil {
		store.beforePut = nil
		hook(store, condition)
	}
	if condition.IfNoneMatch && store.key != "" {
		return "", publish.ErrAlreadyExists
	}
	if condition.IfMatch != "" && (store.key != key || store.etag != condition.IfMatch) {
		return "", publish.ErrConflict
	}
	store.version++
	store.key, store.body, store.etag = key, append([]byte(nil), body...), fmt.Sprintf("\"lease-%d\"", store.version)
	if hook := store.afterPut; hook != nil {
		store.afterPut = nil
		hook(store, append([]byte(nil), body...))
	}
	if store.responseLossAfterPut > 0 {
		store.responseLossAfterPut--
		return "", errors.New("injected lease Put response loss after commit")
	}
	return store.etag, nil
}

func (store *fakeRealCloudCloudflareBootstrapLeaseStore) R2Delete(_ context.Context, key, ifMatch string) error {
	store.deleteCalls++
	if store.key != key {
		return publish.ErrNotFound
	}
	if store.etag != ifMatch {
		return publish.ErrConflict
	}
	store.key, store.body, store.etag = "", nil, ""
	return nil
}

func recoverRealCloudCloudflareBootstrapLeaseForTest(
	t *testing.T,
	store *fakeRealCloudCloudflareBootstrapLeaseStore,
	plan realCloudCloudflareBootstrapPlan,
	planSHA, runID string,
	now time.Time,
) (realCloudCloudflareBootstrapLeaseRecoveryPending, realCloudCloudflareBootstrapLeaseRecoveryReceipt, realCloudCloudflareBootstrapLease, string) {
	t.Helper()
	pending, err := beginRealCloudCloudflareBootstrapLeaseRecovery(t.Context(), store, plan, planSHA, runID, now)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := newRealCloudCloudflareBootstrapLeaseRecoveryReceipt(pending, plan, planSHA, runID)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "bootstrap.lease-recovery.json")
	if err := persistRealCloudCloudflareBootstrapLeaseRecoveryReceipt(path, receipt, plan, planSHA, runID); err != nil {
		t.Fatal(err)
	}
	recovered, err := completeRealCloudCloudflareBootstrapLeaseRecovery(t.Context(), store, plan, planSHA, runID, path)
	if err != nil {
		t.Fatal(err)
	}
	return pending, receipt, recovered, path
}

func newFakeRealCloudCloudflareBootstrapControl(plan realCloudCloudflareBootstrapPlan) *fakeRealCloudCloudflareBootstrapControl {
	fake := &fakeRealCloudCloudflareBootstrapControl{
		workers: make(map[string]realCloudCloudflareBootstrapWorkerState), routes: make(map[string]realCloudCloudflareBootstrapInventoryRoute),
		fail: make(map[string]int), calls: make(map[string]int), nextID: 1,
		omitWorkerInventory: make(map[string]bool), omitRouteInventory: make(map[string]bool),
		errorAfterRouteDelete: make(map[string]int), errorAfterScriptDelete: make(map[string]int),
	}
	if realCloudCloudflareBootstrapUsesProvider(plan) {
		fake.workers[plan.TokenVerifierService] = fakeRealCloudCloudflareBootstrapWorkerState(plan, "verifier", "20260717T000000Z-fixture", true)
	}
	return fake
}

func fakeRealCloudCloudflareBootstrapWorkerState(plan realCloudCloudflareBootstrapPlan, role, runID string, exposureDisabled bool) realCloudCloudflareBootstrapWorkerState {
	var script, content, bindings string
	switch role {
	case "auth":
		script, content, bindings = plan.AuthScript, plan.AuthBundle.SHA256, realCloudCloudflareBootstrapExpectedAuthBindingsSHA(plan)
	case "origin":
		script, content, bindings = plan.OriginScript, plan.OriginBundle.SHA256, realCloudCloudflareBootstrapExpectedOriginBindingsSHA(plan)
	case "verifier":
		script, content, bindings = plan.TokenVerifierService, plan.TokenVerifierContentSHA256, plan.TokenVerifierBindingsSHA256
	}
	state := realCloudCloudflareBootstrapWorkerState{
		Script: script, DeploymentID: "deployment-" + script, VersionID: "version-" + script, VersionETag: "etag-" + script,
		ContentSHA256: content, BindingsSHA256: bindings, ExposureDisabled: exposureDisabled,
	}
	if role != "verifier" {
		state.OwnershipMessage, state.OwnershipTag = realCloudCloudflareBootstrapOwnershipAnnotations(plan, runID)
		state.CompatibilityDate = plan.CompatibilityDate
		state.CompatibilityFlags = append([]string(nil), plan.CompatibilityFlags...)
	} else {
		state.CompatibilityDate = plan.TokenVerifierCompatibilityDate
		state.CompatibilityFlags = append([]string(nil), plan.TokenVerifierCompatibilityFlags...)
	}
	return state
}

func (fake *fakeRealCloudCloudflareBootstrapControl) failNow(operation string) error {
	fake.calls[operation]++
	if fake.fail[operation] > 0 {
		fake.fail[operation]--
		return errors.New("injected " + operation + " failure")
	}
	return nil
}

func (fake *fakeRealCloudCloudflareBootstrapControl) Inventory(_ context.Context, _ realCloudCloudflareBootstrapPlan) (realCloudCloudflareBootstrapInventory, error) {
	if err := fake.failNow("inventory"); err != nil {
		return realCloudCloudflareBootstrapInventory{}, err
	}
	inventory := realCloudCloudflareBootstrapInventory{
		DomainServices: append([]string(nil), fake.domains...), ManagedAttachments: append([]string(nil), fake.attachments...),
	}
	for script := range fake.workers {
		if !fake.omitWorkerInventory[script] {
			inventory.Workers = append(inventory.Workers, script)
		}
	}
	for _, route := range fake.routes {
		if !fake.omitRouteInventory[route.Pattern] {
			inventory.Routes = append(inventory.Routes, route)
		}
	}
	sort.Strings(inventory.Workers)
	sort.Slice(inventory.Routes, func(i, j int) bool { return inventory.Routes[i].Pattern < inventory.Routes[j].Pattern })
	return inventory, nil
}

func (fake *fakeRealCloudCloudflareBootstrapControl) Inspect(_ context.Context, plan realCloudCloudflareBootstrapPlan, role string) (realCloudCloudflareBootstrapWorkerState, error) {
	if err := fake.failNow("inspect-" + role); err != nil {
		return realCloudCloudflareBootstrapWorkerState{}, err
	}
	script := plan.AuthScript
	if role == "origin" {
		script = plan.OriginScript
	} else if role == "verifier" {
		script = plan.TokenVerifierService
	}
	state, exists := fake.workers[script]
	if !exists {
		return state, errors.New("fake Worker is absent")
	}
	return state, nil
}

func (fake *fakeRealCloudCloudflareBootstrapControl) Upload(_ context.Context, plan realCloudCloudflareBootstrapPlan, role, planSHA, runID string) error {
	if err := fake.failNow("upload-" + role); err != nil {
		return err
	}
	if planSHA != realCloudCloudflareBootstrapPlanSHA(plan) || !validRealCloudRunID(runID) {
		return errors.New("fake upload identity is invalid")
	}
	state := fakeRealCloudCloudflareBootstrapWorkerState(plan, role, runID, false)
	if _, exists := fake.workers[state.Script]; exists {
		return errors.New("fake conditional Worker create found an existing script")
	}
	fake.workers[state.Script] = state
	return nil
}

func (fake *fakeRealCloudCloudflareBootstrapControl) DisableExposure(_ context.Context, plan realCloudCloudflareBootstrapPlan, script string) error {
	if err := fake.failNow("disable-" + script); err != nil {
		return err
	}
	state, exists := fake.workers[script]
	if !exists || script != plan.AuthScript && script != plan.OriginScript {
		return errors.New("fake exposure target is absent or foreign")
	}
	state.ExposureDisabled = true
	fake.workers[script] = state
	return nil
}

func (fake *fakeRealCloudCloudflareBootstrapControl) CreateRoute(_ context.Context, _ realCloudCloudflareBootstrapPlan, route realCloudCloudflareBootstrapRoute) (string, error) {
	if err := fake.failNow("create-route-" + route.Pattern); err != nil {
		return "", err
	}
	id := fmt.Sprintf("route-%d", fake.nextID)
	fake.nextID++
	fake.routes[route.Pattern] = realCloudCloudflareBootstrapInventoryRoute{ID: id, Pattern: route.Pattern, Script: route.Script}
	return id, nil
}

func (fake *fakeRealCloudCloudflareBootstrapControl) GetRoute(_ context.Context, _ realCloudCloudflareBootstrapPlan, routeID string) (realCloudCloudflareBootstrapInventoryRoute, error) {
	if err := fake.failNow("get-route-" + routeID); err != nil {
		return realCloudCloudflareBootstrapInventoryRoute{}, err
	}
	for _, route := range fake.routes {
		if route.ID == routeID {
			return route, nil
		}
	}
	return realCloudCloudflareBootstrapInventoryRoute{}, errors.New("fake route is absent")
}

func (fake *fakeRealCloudCloudflareBootstrapControl) DeleteRouteIfMatch(_ context.Context, plan realCloudCloudflareBootstrapPlan, expected realCloudCloudflareBootstrapInventoryRoute) error {
	fake.calls["check-delete-route-"+expected.ID]++
	if hook := fake.beforeDeleteRoute; hook != nil {
		fake.beforeDeleteRoute = nil
		hook(fake, expected)
	}
	planned := false
	for _, route := range plan.Routes {
		if expected.Pattern == route.Pattern && expected.Script == route.Script {
			planned = true
			break
		}
	}
	current, exists := fake.routes[expected.Pattern]
	if !exists {
		for _, route := range fake.routes {
			if route.ID == expected.ID {
				current, exists = route, true
				break
			}
		}
	}
	if !planned {
		return errors.New("fake route deletion identity differs from the exact plan")
	}
	if !exists {
		return nil
	}
	if current != expected {
		return errors.New("fake route changed immediately before deletion")
	}
	if err := fake.failNow("delete-route-" + expected.ID); err != nil {
		return err
	}
	delete(fake.routes, expected.Pattern)
	if fake.errorAfterRouteDelete[expected.ID] > 0 {
		fake.errorAfterRouteDelete[expected.ID]--
		return errors.New("injected route response loss after provider delete")
	}
	return nil
}

func (fake *fakeRealCloudCloudflareBootstrapControl) DeleteScriptIfMatch(ctx context.Context, plan realCloudCloudflareBootstrapPlan, role, runID string, expected realCloudCloudflareBootstrapReceiptWorker) error {
	fake.calls["check-delete-script-"+expected.Script]++
	if hook := fake.beforeDeleteScript; hook != nil {
		fake.beforeDeleteScript = nil
		hook(fake, role, expected)
	}
	script := plan.AuthScript
	if role == "origin" {
		script = plan.OriginScript
	} else if role != "auth" {
		return errors.New("fake Worker deletion role is invalid")
	}
	if _, exists := fake.workers[script]; !exists {
		return nil
	}
	inventory, err := fake.Inventory(ctx, plan)
	if err != nil {
		return err
	}
	_, routesFound, err := validateRealCloudCloudflareBootstrapInventory(plan, inventory, false)
	if err != nil || len(routesFound) != 0 {
		return errors.New("fake Worker deletion attachment closure changed")
	}
	current, exists := fake.workers[script]
	if !exists || expected.Script != script || validateRealCloudCloudflareBootstrapWorkerState(role, current, plan, runID, true) != nil ||
		!realCloudCloudflareBootstrapStateMatchesReceipt(current, expected) {
		return errors.New("fake Worker changed immediately before deletion")
	}
	if err := fake.failNow("delete-script-" + script); err != nil {
		return err
	}
	delete(fake.workers, script)
	if fake.errorAfterScriptDelete[script] > 0 {
		fake.errorAfterScriptDelete[script]--
		return errors.New("injected Worker response loss after provider delete")
	}
	return nil
}

func TestRealCloudCloudflareBootstrapRecoverLeaseRuntimeUsesOnlyR2Authority(t *testing.T) {
	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	reads := make(map[string]int)
	getenv := func(name string) string {
		reads[name]++
		if name == realCloudCDNCredentialCF {
			t.Fatal("recover-lease read the unrelated Cloudflare API credential")
		}
		if name == realCloudStorageCredentialCF {
			return `{"access_key_id":"bootstrap-recovery-access","secret_access_key":"bootstrap-recovery-fixture-secret"}`
		}
		return ""
	}
	runtime, err := newRealCloudCloudflareBootstrapRuntime(
		"recover-lease", resource, plan, getenv, "https://api.cloudflare.com/client/v4", &http.Client{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.leaseStore == nil || runtime.control != nil {
		t.Fatalf("recover-lease runtime authority lease=%T worker_control=%v", runtime.leaseStore, runtime.control)
	}
	if reads[realCloudStorageCredentialCF] != 1 || reads[realCloudCDNCredentialCF] != 0 || len(reads) != 1 {
		t.Fatalf("recover-lease credential surface=%v", reads)
	}
}

func realCloudCloudflareStaticEntitlementsFixture(t *testing.T, plan realCloudCloudflareBootstrapPlan) string {
	t.Helper()
	audiences := []string{strings.TrimPrefix(plan.BetaBase, "https://"), strings.TrimPrefix(plan.MainBase, "https://")}
	sort.Strings(audiences)
	entries := []realCloudCloudflareStaticEntitlement{
		{SHA256: strings.Repeat("a", 64), ExpiresAt: "2099-01-01T00:00:00Z", Audiences: audiences, PathPrefixes: []string{"/"}},
		{SHA256: strings.Repeat("b", 64), ExpiresAt: "2099-01-01T00:00:00Z", Audiences: audiences, PathPrefixes: []string{"/apt", "/yum"}},
	}
	body, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestRealCloudCloudflareStaticBootstrapRuntimeDefersSecretUntilUnsealedMutation(t *testing.T) {
	resource, plan := realCloudCloudflareStaticBootstrapPlanFixture(t)
	secret := realCloudCloudflareStaticEntitlementsFixture(t, plan)
	values := map[string]string{
		realCloudStorageCredentialCF: `{"access_key_id":"static-bootstrap-access","secret_access_key":"fixture-secret-access-key-value"}`,
		realCloudCDNCredentialCF:     `{"api_token":"replace-with-cloudflare-token-value"}`,
		plan.TokenVerifierSecret:     secret,
	}
	reads := make(map[string]int)
	getenv := func(name string) string {
		reads[name]++
		return values[name]
	}
	runtime, err := newRealCloudCloudflareBootstrapRuntime("apply", resource, plan, getenv, "https://api.cloudflare.com/client/v4", &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.control == nil || len(runtime.control.secretBindings) != 0 || reads[plan.TokenVerifierSecret] != 0 {
		t.Fatalf("static bootstrap runtime read a secret before the unsealed mutation branch reads=%v bindings=%d", reads, len(runtime.control.secretBindings))
	}
	if err := bindRealCloudCloudflareStaticEntitlement(runtime.control, plan, secret, time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	runtime.secretFragments = append(runtime.secretFragments, realCloudCloudflareStaticSecretFragments(secret)...)
	if len(runtime.control.secretBindings) != 1 || runtime.control.secretBindings[plan.TokenVerifierSecret] != secret {
		t.Fatal("unsealed static mutation branch did not inject exactly one secret")
	}
	if !containsRealCloudSecret([]byte(secret), runtime.secretFragments) {
		t.Fatal("static entitlement was not included in the runtime leak detector")
	}
	if !containsRealCloudSecret([]byte(strings.Repeat("a", 64)), runtime.secretFragments) {
		t.Fatal("individual static entitlement token digest was not included in the runtime leak detector")
	}
	delete(values, plan.TokenVerifierSecret)
	reads = make(map[string]int)
	rollback, err := newRealCloudCloudflareBootstrapRuntime("rollback", resource, plan, getenv, "https://api.cloudflare.com/client/v4", &http.Client{})
	if err != nil || rollback.control == nil || len(rollback.control.secretBindings) != 0 || reads[plan.TokenVerifierSecret] != 0 {
		t.Fatalf("static rollback unnecessarily required entitlement material err=%v reads=%v", err, reads)
	}
}

func TestRealCloudCloudflareStaticBootstrapEntitlementValidationFailsClosed(t *testing.T) {
	_, plan := realCloudCloudflareStaticBootstrapPlanFixture(t)
	valid := realCloudCloudflareStaticEntitlementsFixture(t, plan)
	if err := validateRealCloudCloudflareStaticEntitlements(valid, plan, time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	var entries []realCloudCloudflareStaticEntitlement
	if err := json.Unmarshal([]byte(valid), &entries); err != nil {
		t.Fatal(err)
	}
	encode := func(mutate func([]realCloudCloudflareStaticEntitlement)) string {
		copyEntries := append([]realCloudCloudflareStaticEntitlement(nil), entries...)
		for index := range copyEntries {
			copyEntries[index].Audiences = append([]string(nil), entries[index].Audiences...)
			copyEntries[index].PathPrefixes = append([]string(nil), entries[index].PathPrefixes...)
		}
		mutate(copyEntries)
		body, _ := json.Marshal(copyEntries)
		return string(body)
	}
	tests := map[string]string{
		"missing":        "",
		"non-canonical":  valid + " ",
		"unknown-field":  strings.Replace(valid, `"expires_at"`, `"raw_token":"forbidden","expires_at"`, 1),
		"wrong-audience": encode(func(value []realCloudCloudflareStaticEntitlement) { value[0].Audiences = []string{"repo.pigsty.io"} }),
		"expired":        encode(func(value []realCloudCloudflareStaticEntitlement) { value[0].ExpiresAt = "2020-01-01T00:00:00Z" }),
		"expires-during-bootstrap": encode(func(value []realCloudCloudflareStaticEntitlement) {
			value[0].ExpiresAt = "2026-07-20T00:00:01Z"
		}),
		"duplicate":     encode(func(value []realCloudCloudflareStaticEntitlement) { value[1].SHA256 = value[0].SHA256 }),
		"unsorted-path": encode(func(value []realCloudCloudflareStaticEntitlement) { value[1].PathPrefixes = []string{"/yum", "/apt"} }),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateRealCloudCloudflareStaticEntitlements(raw, plan, time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC))
			if err == nil || raw != "" && strings.Contains(err.Error(), raw) {
				t.Fatalf("unsafe entitlement validation result err=%v", err)
			}
		})
	}
	boundaryNow := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	atHorizon := encode(func(value []realCloudCloudflareStaticEntitlement) {
		value[0].ExpiresAt = boundaryNow.Add(realCloudCloudflareStaticEntitlementMinTTL).Format("2006-01-02T15:04:05Z")
	})
	if err := validateRealCloudCloudflareStaticEntitlements(atHorizon, plan, boundaryNow); err != nil {
		t.Fatalf("exact 15-minute static entitlement horizon rejected: %v", err)
	}
	belowHorizon := encode(func(value []realCloudCloudflareStaticEntitlement) {
		value[0].ExpiresAt = boundaryNow.Add(realCloudCloudflareStaticEntitlementMinTTL - time.Second).Format("2006-01-02T15:04:05Z")
	})
	if err := validateRealCloudCloudflareStaticEntitlements(belowHorizon, plan, boundaryNow); err == nil {
		t.Fatal("static entitlement below the 15-minute deployment horizon was accepted")
	}
	boundary := []realCloudCloudflareStaticEntitlement{{
		SHA256: strings.Repeat("c", 64), ExpiresAt: "2099-01-01T00:00:00Z",
		Audiences: entries[0].Audiences, PathPrefixes: []string{"/"},
	}}
	base, err := json.Marshal(boundary)
	if err != nil || len(base) >= realCloudCloudflareStaticSecretMaxBytes {
		t.Fatalf("construct static entitlement boundary: len=%d err=%v", len(base), err)
	}
	boundary[0].PathPrefixes[0] = "/" + strings.Repeat("a", realCloudCloudflareStaticSecretMaxBytes-len(base))
	exact, err := json.Marshal(boundary)
	if err != nil || len(exact) != realCloudCloudflareStaticSecretMaxBytes {
		t.Fatalf("construct exact 5 KB static entitlement: len=%d err=%v", len(exact), err)
	}
	if err := validateRealCloudCloudflareStaticEntitlements(string(exact), plan, time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("exact 5 KB static entitlement rejected: %v", err)
	}
	overBoundary := append([]realCloudCloudflareStaticEntitlement(nil), boundary...)
	overBoundary[0].Audiences = append([]string(nil), boundary[0].Audiences...)
	overBoundary[0].PathPrefixes = []string{boundary[0].PathPrefixes[0] + "a"}
	over, err := json.Marshal(overBoundary)
	if err != nil || len(over) != realCloudCloudflareStaticSecretMaxBytes+1 {
		t.Fatalf("construct over-limit static entitlement: len=%d err=%v", len(over), err)
	}
	if err := validateRealCloudCloudflareStaticEntitlements(string(over), plan, time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("static entitlement over the Cloudflare 5 KB limit was accepted")
	}
}

func TestRealCloudCloudflareBootstrapLeaseSerializesAndRecoversByCAS(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
	first, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, "20260717T120000Z-first-lease", "apply", strings.Repeat("a", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, "20260717T120000Z-conflict-lease", "apply", strings.Repeat("b", 64), now.Add(time.Minute)); err == nil {
		t.Fatal("concurrent live Cloudflare bootstrap lease was accepted")
	}
	oldETag := first.etag
	if err := first.renew(t.Context(), now.Add(2*time.Minute)); err != nil || first.etag == oldETag {
		t.Fatalf("lease renewal did not compare-and-set a new entity etag=%q err=%v", first.etag, err)
	}
	if err := first.release(t.Context()); err != nil || store.key == "" || store.deleteCalls != 0 {
		t.Fatalf("lease release did not CAS the exact entity to an idle marker err=%v delete_calls=%d", err, store.deleteCalls)
	}
	if idle, err := decodeRealCloudCloudflareBootstrapIdleLease(store.body); err != nil || !realCloudCloudflareBootstrapLeasesEqual(idle.PreviousLease, first.lease) {
		t.Fatalf("lease release idle marker is invalid idle=%+v err=%v", idle, err)
	}

	expired, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, "20260717T120000Z-expired-lease", "apply", strings.Repeat("c", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	recoveryTime := now.Add(realCloudCloudflareBootstrapLeaseTTL + time.Second)
	if _, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, "20260717T121000Z-bypass-recovery", "rollback", strings.Repeat("d", 64), recoveryTime); err == nil || !strings.Contains(err.Error(), "recover-lease") {
		t.Fatalf("ordinary acquisition bypassed durable expired-lease recovery: %v", err)
	}
	_, _, recovered, _ := recoverRealCloudCloudflareBootstrapLeaseForTest(
		t, store, plan, planSHA, "20260717T121000Z-recovery", recoveryTime,
	)
	if !realCloudCloudflareBootstrapLeasesEqual(recovered, expired.lease) {
		t.Fatalf("expired Cloudflare bootstrap lease was not explicitly recovered recovered=%+v", recovered)
	}
	replacement, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, "20260717T121000Z-recovery-lease", "rollback", strings.Repeat("d", 64), recoveryTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if replacement.etag == expired.etag || replacement.lease.Holder == expired.lease.Holder {
		t.Fatal("expired Cloudflare bootstrap lease was not replaced by a new compare-and-set entity")
	}
	if err := expired.release(t.Context()); err == nil {
		t.Fatal("stale lease holder released the replacement lease")
	}
	if err := replacement.release(t.Context()); err != nil || store.deleteCalls != 0 {
		t.Fatal(err)
	}
}

func TestRealCloudCloudflareBootstrapLeaseSurvivesPlanRotationOnOneResourceKey(t *testing.T) {
	resource, firstPlan := realCloudCloudflareBootstrapPlanFixture(t)
	rotatedPlan := firstPlan
	rotatedPlan.CompatibilityDate = "2026-07-18"
	if err := validateRealCloudCloudflareBootstrapPlan(rotatedPlan, resource); err != nil {
		t.Fatalf("rotated bootstrap plan fixture is invalid: %v", err)
	}
	firstPlanSHA := realCloudCloudflareBootstrapPlanSHA(firstPlan)
	rotatedPlanSHA := realCloudCloudflareBootstrapPlanSHA(rotatedPlan)
	if firstPlanSHA == rotatedPlanSHA {
		t.Fatal("bootstrap plan rotation did not change the plan digest")
	}
	wantedKey, err := realCloudCloudflareBootstrapLeaseKey(firstPlan.ReadinessResourceSHA256)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
	first, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, firstPlan, firstPlanSHA,
		"20260719T120000Z-plan-one", "apply", strings.Repeat("1", 64), base)
	if err != nil {
		t.Fatal(err)
	}
	if first.key != wantedKey || store.key != wantedKey {
		t.Fatalf("bootstrap lease key is not readiness-resource stable held=%q stored=%q want=%q", first.key, store.key, wantedKey)
	}
	if err := first.release(t.Context()); err != nil {
		t.Fatal(err)
	}
	rotated, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, rotatedPlan, rotatedPlanSHA,
		"20260719T120100Z-plan-two", "apply", strings.Repeat("2", 64), base.Add(time.Minute))
	if err != nil {
		t.Fatalf("rotated plan did not CAS-take the prior idle marker: %v", err)
	}
	if rotated.key != wantedKey || store.key != wantedKey || rotated.lease.PlanSHA256 != rotatedPlanSHA {
		t.Fatalf("rotated plan forked the serialization key held=%q stored=%q lease=%+v", rotated.key, store.key, rotated.lease)
	}
	if _, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, firstPlan, firstPlanSHA,
		"20260719T120200Z-plan-one-live", "rollback", strings.Repeat("3", 64), base.Add(2*time.Minute)); err == nil || !strings.Contains(err.Error(), "live execution") {
		t.Fatalf("plan rotation took over a live same-resource lease: %v", err)
	}
	if err := rotated.release(t.Context()); err != nil {
		t.Fatal(err)
	}
	foreignPlan := rotatedPlan
	foreignPlan.ZoneID = strings.Repeat("f", 32)
	foreignPlanSHA := realCloudCloudflareBootstrapPlanSHA(foreignPlan)
	if _, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, foreignPlan, foreignPlanSHA,
		"20260719T120300Z-foreign-zone", "apply", strings.Repeat("4", 64), base.Add(3*time.Minute)); err == nil {
		t.Fatal("foreign provider resource took over the stable bootstrap marker")
	}
	crashed, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, firstPlan, firstPlanSHA,
		"20260719T120400Z-old-plan-crash", "rollback", strings.Repeat("5", 64), base.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	pending, recoveryReceipt, recovered, _ := recoverRealCloudCloudflareBootstrapLeaseForTest(
		t, store, rotatedPlan, rotatedPlanSHA, "20260719T121000Z-rotation-recovery",
		base.Add(4*time.Minute+realCloudCloudflareBootstrapLeaseTTL+time.Second),
	)
	if !realCloudCloudflareBootstrapLeasesEqual(recovered, crashed.lease) || recovered.PlanSHA256 != firstPlanSHA {
		t.Fatalf("rotated plan did not recover the expired prior-plan lease recovered=%+v", recovered)
	}
	if err := validateRealCloudCloudflareBootstrapLeaseRecoveryReceipt(
		recoveryReceipt, rotatedPlan, rotatedPlanSHA, recoveryReceipt.RunID,
	); err != nil {
		t.Fatalf("cross-plan recovery receipt was rejected: %v", err)
	}
	recoveredIdle, err := decodeRealCloudCloudflareBootstrapIdleLease(store.body)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRealCloudCloudflareBootstrapLeaseRecoveryMarker(
		recoveryReceipt, recoveredIdle, rotatedPlan, rotatedPlanSHA, recoveryReceipt.RunID,
	); err != nil {
		t.Fatalf("cross-plan recovery marker did not match its durable receipt: %v", err)
	}
	forgedReceipt := recoveryReceipt
	forgedReceipt.RecoveredLeasePlanSHA256 = rotatedPlanSHA
	if err := validateRealCloudCloudflareBootstrapLeaseRecoveryMarker(
		forgedReceipt, recoveredIdle, rotatedPlan, rotatedPlanSHA, forgedReceipt.RunID,
	); err == nil {
		t.Fatal("recovery receipt accepted a forged recovered-plan digest")
	}
	forgedChainReceipt := recoveryReceipt
	forgedChainReceipt.RecoveryPendingSHA256 = strings.Repeat("9", 64)
	forgedChainBody, err := encodeRealCloudCloudflareBootstrapLeaseRecoveryReceipt(
		forgedChainReceipt, rotatedPlan, rotatedPlanSHA, forgedChainReceipt.RunID,
	)
	if err != nil {
		t.Fatal(err)
	}
	forgedChainIdle := recoveredIdle
	forgedChainIdle.RecoveryPendingSHA256 = forgedChainReceipt.RecoveryPendingSHA256
	forgedChainIdle.RecoveryReceiptSHA256 = realCloudLowerSHA256(forgedChainBody)
	if _, err := encodeRealCloudCloudflareBootstrapIdleLease(forgedChainIdle); err != nil {
		t.Fatal(err)
	}
	if err := validateRealCloudCloudflareBootstrapLeaseRecoveryMarker(
		forgedChainReceipt, forgedChainIdle, rotatedPlan, rotatedPlanSHA, forgedChainReceipt.RunID,
	); err == nil {
		t.Fatal("recovery replay accepted mutually forged pending and receipt digests")
	}
	forgedLease := recovered
	forgedLease.AcquiredAt = base.Add(3 * time.Minute).Format(time.RFC3339Nano)
	forgedPending := pending
	forgedPending.RecoveredLease = forgedLease
	forgedLeaseBody, err := encodeRealCloudCloudflareBootstrapLease(forgedLease)
	if err != nil {
		t.Fatal(err)
	}
	forgedPending.RecoveredLeaseSHA256 = realCloudLowerSHA256(forgedLeaseBody)
	recoveryReceiptBody, err := encodeRealCloudCloudflareBootstrapLeaseRecoveryReceipt(
		recoveryReceipt, rotatedPlan, rotatedPlanSHA, recoveryReceipt.RunID,
	)
	if err != nil {
		t.Fatal(err)
	}
	forgedIdle, err := newRealCloudCloudflareBootstrapRecoveredIdleLease(forgedPending, recoveryReceiptBody)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRealCloudCloudflareBootstrapLeaseRecoveryMarker(
		recoveryReceipt, forgedIdle, rotatedPlan, rotatedPlanSHA, recoveryReceipt.RunID,
	); err == nil {
		t.Fatal("recovery receipt accepted a marker with forged recovered-lease bytes")
	}
	if err := crashed.release(t.Context()); err == nil {
		t.Fatal("stale prior-plan holder changed the recovered idle marker")
	}
	idle, err := decodeRealCloudCloudflareBootstrapIdleLease(store.body)
	if err != nil || !realCloudCloudflareBootstrapLeasesEqual(idle.PreviousLease, crashed.lease) || store.key != wantedKey || store.deleteCalls != 0 {
		t.Fatalf("plan-rotation recovery did not retain one exact idle marker idle=%+v err=%v key=%q deletes=%d", idle, err, store.key, store.deleteCalls)
	}
	observation, err := collectRealCloudCloudflareReadinessBucketClosure(t.Context(), store, *resource.Cloudflare)
	if err != nil || observation.ControlObjectCount != 1 || observation.ControlObjectKey != wantedKey {
		t.Fatalf("readiness rejected the rotated resource-stable idle marker observation=%+v err=%v", observation, err)
	}
}

func TestRealCloudCloudflareBootstrapLeaseRejectsForeignBytesAndLostOwnership(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
	held, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, "20260717T120000Z-lost-lease", "apply", strings.Repeat("e", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	store.body = []byte("{\"foreign\":true}\n")
	if err := held.renew(t.Context(), now.Add(time.Minute)); err == nil {
		t.Fatal("lease renewal accepted foreign bytes under the same ETag")
	}
	store.body, _ = encodeRealCloudCloudflareBootstrapLease(held.lease)
	store.etag = "\"foreign-replacement\""
	if err := held.release(t.Context()); err == nil {
		t.Fatal("stale lease holder deleted a replacement entity")
	}
}

func TestRealCloudCloudflareBootstrapPostLeaseClosureRejectsForeignMissingAndCyclicInventory(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	newHeld := func(t *testing.T) (*fakeRealCloudCloudflareBootstrapLeaseStore, *realCloudCloudflareBootstrapHeldLease) {
		t.Helper()
		store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
		held, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, "20260717T120000Z-closure", "apply", strings.Repeat("9", 64), now)
		if err != nil {
			t.Fatal(err)
		}
		return store, held
	}

	t.Run("exact", func(t *testing.T) {
		store, held := newHeld(t)
		if err := validateRealCloudCloudflareBootstrapLeasedBucketClosure(t.Context(), held); err != nil {
			t.Fatalf("exact lease-only closure was rejected: %v", err)
		}
		if err := held.release(t.Context()); err != nil || store.key == "" || store.deleteCalls != 0 {
			t.Fatalf("release exact closure: %v", err)
		}
	})
	t.Run("foreign", func(t *testing.T) {
		store, held := newHeld(t)
		store.extraObjects = []publish.ListedObject{{Key: "foreign/object", Size: 1, ETag: "\"foreign\""}}
		if err := validateRealCloudCloudflareBootstrapLeasedBucketClosure(t.Context(), held); err == nil {
			t.Fatal("post-lease closure accepted a foreign object")
		}
	})
	t.Run("missing", func(t *testing.T) {
		store, held := newHeld(t)
		store.listPages = map[string]publish.ObjectListPage{"": {}}
		if err := validateRealCloudCloudflareBootstrapLeasedBucketClosure(t.Context(), held); err == nil {
			t.Fatal("post-lease closure accepted a missing lease object")
		}
	})
	t.Run("replaced-list-identity", func(t *testing.T) {
		store, held := newHeld(t)
		store.listPages = map[string]publish.ObjectListPage{"": {Objects: []publish.ListedObject{{Key: held.key, Size: int64(len(store.body)), ETag: "\"replacement\""}}}}
		if err := validateRealCloudCloudflareBootstrapLeasedBucketClosure(t.Context(), held); err == nil {
			t.Fatal("post-lease closure accepted a replacement list identity")
		}
	})
	t.Run("continuation-cycle", func(t *testing.T) {
		store, held := newHeld(t)
		store.listPages = map[string]publish.ObjectListPage{
			"":      {Objects: []publish.ListedObject{{Key: held.key, Size: int64(len(store.body)), ETag: held.etag}}, NextContinuationToken: "cycle"},
			"cycle": {NextContinuationToken: "cycle"},
		}
		if err := validateRealCloudCloudflareBootstrapLeasedBucketClosure(t.Context(), held); err == nil {
			t.Fatal("post-lease closure accepted a continuation-token cycle")
		}
	})
}

func TestRealCloudCloudflareBootstrapRechecksLeaseOnlyClosureBeforeMutation(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
	held, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, "20260717T120000Z-before-mutation", "apply", strings.Repeat("8", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeRealCloudCloudflareBootstrapControl(plan)
	clock := now.Add(time.Minute)
	leased, err := newRealCloudCloudflareLeasedBootstrapControl(t.Context(), fake, held, func() time.Time { return clock }, nil)
	if err != nil {
		t.Fatal(err)
	}
	store.extraObjects = []publish.ListedObject{{Key: "arrived/after-readiness", Size: 1, ETag: "\"foreign\""}}
	if err := leased.Upload(t.Context(), plan, "origin", planSHA, held.lease.RunID); err == nil {
		t.Fatal("leased bootstrap mutation accepted an object that arrived after admission")
	}
	if fake.calls["upload-origin"] != 0 {
		t.Fatalf("inner Worker mutation ran before post-lease closure rejection: calls=%d", fake.calls["upload-origin"])
	}
	if _, exists := fake.workers[plan.OriginScript]; exists {
		t.Fatal("origin Worker was created despite post-lease closure drift")
	}
}

func TestRealCloudCloudflareBootstrapRechecksProviderClosureBeforeMutation(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
	held, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, "20260717T120000Z-provider-drift", "apply", strings.Repeat("7", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeRealCloudCloudflareBootstrapControl(plan)
	closureCalls := 0
	providerClosure := func(context.Context) error {
		closureCalls++
		if closureCalls > 1 {
			return errors.New("injected main-and-beta domain drift")
		}
		return nil
	}
	leased, err := newRealCloudCloudflareLeasedBootstrapControl(t.Context(), fake, held, func() time.Time { return now.Add(time.Minute) }, providerClosure)
	if err != nil || closureCalls != 1 {
		t.Fatalf("initial provider closure admission failed calls=%d err=%v", closureCalls, err)
	}
	expected := realCloudCloudflareBootstrapInventoryRoute{ID: "provider-drift-route", Pattern: plan.Routes[0].Pattern, Script: plan.Routes[0].Script}
	fake.routes[expected.Pattern] = expected
	if err := leased.DeleteRouteIfMatch(t.Context(), plan, expected); err == nil {
		t.Fatal("leased bootstrap mutation accepted provider-control drift")
	}
	if closureCalls != 2 || fake.calls["check-delete-route-"+expected.ID] != 0 || fake.calls["delete-route-"+expected.ID] != 0 {
		t.Fatalf("provider closure was not enforced before inner checked delete closure_calls=%d calls=%v", closureCalls, fake.calls)
	}
	if fake.routes[expected.Pattern] != expected {
		t.Fatal("provider drift changed the exact route before the inner checked delete")
	}
}

func TestRealCloudCloudflareBootstrapRejectsExhaustedLeaseBudgetBeforeCheckedDelete(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	clock := now
	store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
	held, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, "20260717T120000Z-slow-closure", "rollback", strings.Repeat("6", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeRealCloudCloudflareBootstrapControl(plan)
	expected := realCloudCloudflareBootstrapInventoryRoute{ID: "lease-budget-route", Pattern: plan.Routes[0].Pattern, Script: plan.Routes[0].Script}
	fake.routes[expected.Pattern] = expected
	closureCalls := 0
	providerClosure := func(context.Context) error {
		closureCalls++
		if closureCalls == 2 {
			clock = clock.Add(realCloudCloudflareBootstrapLeaseTTL)
		}
		return nil
	}
	leased, err := newRealCloudCloudflareLeasedBootstrapControl(t.Context(), fake, held, func() time.Time { return clock }, providerClosure)
	if err != nil {
		t.Fatal(err)
	}
	if err := leased.DeleteRouteIfMatch(t.Context(), plan, expected); err == nil {
		t.Fatal("checked delete entered its inner adapter after exhausting the lease lifetime")
	}
	if fake.calls["check-delete-route-"+expected.ID] != 0 || fake.calls["delete-route-"+expected.ID] != 0 || fake.routes[expected.Pattern] != expected {
		t.Fatalf("exhausted lease budget reached inner checked delete calls=%v route=%+v", fake.calls, fake.routes[expected.Pattern])
	}
}

func TestRealCloudCloudflareBootstrapExpiredLeaseRecoveryIsExactAndConditional(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	recoveryRunID := "20260717T121000Z-exact-recovery"
	store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
	held, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, "20260717T120000Z-crashed-lease", "apply", strings.Repeat("f", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := beginRealCloudCloudflareBootstrapLeaseRecovery(t.Context(), store, plan, planSHA, recoveryRunID, now.Add(time.Minute)); err == nil {
		t.Fatal("lease recovery fenced a live lease")
	}
	pending, err := beginRealCloudCloudflareBootstrapLeaseRecovery(
		t.Context(), store, plan, planSHA, recoveryRunID, now.Add(realCloudCloudflareBootstrapLeaseTTL+time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !realCloudCloudflareBootstrapLeasesEqual(pending.RecoveredLease, held.lease) {
		t.Fatalf("pending marker lost the expired lease: %+v", pending)
	}
	if _, err := acquireRealCloudCloudflareBootstrapLease(
		t.Context(), store, plan, planSHA, "20260717T121001Z-pending-block", "rollback", strings.Repeat("e", 64), now.Add(realCloudCloudflareBootstrapLeaseTTL+2*time.Second),
	); err == nil || !strings.Contains(err.Error(), "recovery is pending") {
		t.Fatalf("ordinary acquisition bypassed the recovery pending marker: %v", err)
	}
	receipt, err := newRealCloudCloudflareBootstrapLeaseRecoveryReceipt(pending, plan, planSHA, recoveryRunID)
	if err != nil {
		t.Fatal(err)
	}
	recoveryDirectory := t.TempDir()
	if err := os.Chmod(recoveryDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	recoveryPath := filepath.Join(recoveryDirectory, "bootstrap.lease-recovery.json")
	if err := persistRealCloudCloudflareBootstrapLeaseRecoveryReceipt(recoveryPath, receipt, plan, planSHA, recoveryRunID); err != nil {
		t.Fatal(err)
	}
	recovered, err := completeRealCloudCloudflareBootstrapLeaseRecovery(t.Context(), store, plan, planSHA, recoveryRunID, recoveryPath)
	if err != nil {
		t.Fatal(err)
	}
	idle, idleErr := decodeRealCloudCloudflareBootstrapIdleLease(store.body)
	if !realCloudCloudflareBootstrapLeasesEqual(recovered, held.lease) || idleErr != nil || !realCloudCloudflareBootstrapLeasesEqual(idle.PreviousLease, held.lease) ||
		idle.Retirement != realCloudCloudflareBootstrapRetirementRecovery || store.deleteCalls != 0 {
		t.Fatalf("expired lease recovery did not CAS exactly to recovery idle idle=%+v decode=%v delete_calls=%d", idle, idleErr, store.deleteCalls)
	}
	putCalls := store.putCalls
	if replayed, err := completeRealCloudCloudflareBootstrapLeaseRecovery(t.Context(), store, plan, planSHA, recoveryRunID, recoveryPath); err != nil || !realCloudCloudflareBootstrapLeasesEqual(replayed, held.lease) || store.putCalls != putCalls {
		t.Fatalf("idle recovery replay was not read-only recovered=%+v puts=%d/%d err=%v", replayed, putCalls, store.putCalls, err)
	}
}

func TestRealCloudCloudflareBootstrapLeaseRecoveryResumesEveryCommittedPhase(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	base := time.Date(2026, 7, 19, 14, 0, 0, 0, time.UTC)
	runID := "20260719T141000Z-phase-recovery"
	store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
	crashed, err := acquireRealCloudCloudflareBootstrapLease(
		t.Context(), store, plan, planSHA, "20260719T140000Z-phase-crash", "apply", strings.Repeat("1", 64), base,
	)
	if err != nil {
		t.Fatal(err)
	}
	store.responseLossAfterPut = 1
	pending, err := beginRealCloudCloudflareBootstrapLeaseRecovery(
		t.Context(), store, plan, planSHA, runID, base.Add(realCloudCloudflareBootstrapLeaseTTL+time.Second),
	)
	if err != nil {
		t.Fatalf("begin did not recover a committed pending marker after response loss: %v", err)
	}
	pendingPuts := store.putCalls
	replayedPending, err := beginRealCloudCloudflareBootstrapLeaseRecovery(
		t.Context(), store, plan, planSHA, runID, base.Add(24*time.Hour),
	)
	if err != nil || !realCloudCloudflareBootstrapRecoveryPendingsEqual(replayedPending, pending) || store.putCalls != pendingPuts {
		t.Fatalf("pending-only interruption was not read-only replayable pending=%+v puts=%d/%d err=%v", replayedPending, pendingPuts, store.putCalls, err)
	}
	receipt, err := newRealCloudCloudflareBootstrapLeaseRecoveryReceipt(pending, plan, planSHA, runID)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "bootstrap.lease-recovery.json")
	if err := persistRealCloudCloudflareBootstrapLeaseRecoveryReceipt(path, receipt, plan, planSHA, runID); err != nil {
		t.Fatal(err)
	}
	if err := persistRealCloudCloudflareBootstrapLeaseRecoveryReceipt(path, receipt, plan, planSHA, runID); err != nil {
		t.Fatalf("receipt-only interruption was not idempotently persisted: %v", err)
	}
	store.responseLossAfterPut = 1
	recovered, err := completeRealCloudCloudflareBootstrapLeaseRecovery(t.Context(), store, plan, planSHA, runID, path)
	if err != nil || !realCloudCloudflareBootstrapLeasesEqual(recovered, crashed.lease) {
		t.Fatalf("completion did not recover a committed idle marker after response loss recovered=%+v err=%v", recovered, err)
	}
	idlePuts := store.putCalls
	if replayed, err := completeRealCloudCloudflareBootstrapLeaseRecovery(t.Context(), store, plan, planSHA, runID, path); err != nil || !realCloudCloudflareBootstrapLeasesEqual(replayed, crashed.lease) || store.putCalls != idlePuts {
		t.Fatalf("post-idle interruption was not read-only replayable recovered=%+v puts=%d/%d err=%v", replayed, idlePuts, store.putCalls, err)
	}
	if err := crashed.release(t.Context()); err == nil || store.deleteCalls != 0 {
		t.Fatalf("stale holder changed two-phase recovery state err=%v deletes=%d", err, store.deleteCalls)
	}

	t.Run("completion-response-loss-with-immediate-contender", func(t *testing.T) {
		store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
		crashed, err := acquireRealCloudCloudflareBootstrapLease(
			t.Context(), store, plan, planSHA, "20260719T142000Z-raced-crash", "rollback", strings.Repeat("4", 64), base,
		)
		if err != nil {
			t.Fatal(err)
		}
		recoveryRunID := "20260719T143000Z-raced-recovery"
		pending, err := beginRealCloudCloudflareBootstrapLeaseRecovery(
			t.Context(), store, plan, planSHA, recoveryRunID, base.Add(realCloudCloudflareBootstrapLeaseTTL+time.Second),
		)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := newRealCloudCloudflareBootstrapLeaseRecoveryReceipt(pending, plan, planSHA, recoveryRunID)
		if err != nil || !realCloudCloudflareBootstrapLeasesEqual(receipt.RecoveredLease, crashed.lease) {
			t.Fatalf("recovery receipt did not preserve the full expired lease receipt=%+v err=%v", receipt, err)
		}
		receiptBody, err := encodeRealCloudCloudflareBootstrapLeaseRecoveryReceipt(receipt, plan, planSHA, recoveryRunID)
		if err != nil {
			t.Fatal(err)
		}
		receiptSHA := realCloudLowerSHA256(receiptBody)
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "raced.lease-recovery.json")
		if err := persistRealCloudCloudflareBootstrapLeaseRecoveryReceipt(path, receipt, plan, planSHA, recoveryRunID); err != nil {
			t.Fatal(err)
		}

		var contender *realCloudCloudflareBootstrapHeldLease
		store.responseLossAfterPut = 1
		store.afterPut = func(store *fakeRealCloudCloudflareBootstrapLeaseStore, committed []byte) {
			idle, err := decodeRealCloudCloudflareBootstrapIdleLease(committed)
			if err != nil || idle.Retirement != realCloudCloudflareBootstrapRetirementRecovery {
				t.Fatalf("completion did not commit the recovery idle marker before the contender err=%v idle=%+v", err, idle)
			}
			store.responseLossAfterPut = 0
			contender, err = acquireRealCloudCloudflareBootstrapLease(
				t.Context(), store, plan, planSHA, "20260719T143001Z-immediate-contender", "apply", strings.Repeat("5", 64),
				base.Add(realCloudCloudflareBootstrapLeaseTTL+2*time.Second),
			)
			if err != nil {
				t.Fatalf("immediate contender did not acquire the committed recovery idle marker: %v", err)
			}
			store.responseLossAfterPut = 1
		}
		recovered, err := completeRealCloudCloudflareBootstrapLeaseRecovery(
			t.Context(), store, plan, planSHA, recoveryRunID, path,
		)
		if err != nil || !realCloudCloudflareBootstrapLeasesEqual(recovered, crashed.lease) || contender == nil {
			t.Fatalf("completion response loss did not recognize the immediate descendant recovered=%+v contender=%+v err=%v", recovered, contender, err)
		}
		if !realCloudCloudflareBootstrapRecoveryLineageContains(
			contender.lease.RecoveryLineage, receipt.RecoveryPendingSHA256, receiptSHA,
		) {
			t.Fatalf("immediate contender lost recovery lineage: %+v", contender.lease)
		}
		puts := store.putCalls
		if replayed, err := completeRealCloudCloudflareBootstrapLeaseRecovery(
			t.Context(), store, plan, planSHA, recoveryRunID, path,
		); err != nil || !realCloudCloudflareBootstrapLeasesEqual(replayed, crashed.lease) || store.putCalls != puts {
			t.Fatalf("live-descendant replay was not read-only recovered=%+v puts=%d/%d err=%v", replayed, puts, store.putCalls, err)
		}
		if err := contender.release(t.Context()); err != nil {
			t.Fatal(err)
		}
		puts = store.putCalls
		if replayed, err := completeRealCloudCloudflareBootstrapLeaseRecovery(
			t.Context(), store, plan, planSHA, recoveryRunID, path,
		); err != nil || !realCloudCloudflareBootstrapLeasesEqual(replayed, crashed.lease) || store.putCalls != puts {
			t.Fatalf("released-descendant replay was not read-only recovered=%+v puts=%d/%d err=%v", replayed, puts, store.putCalls, err)
		}

		secondCrashed, err := acquireRealCloudCloudflareBootstrapLease(
			t.Context(), store, plan, planSHA, "20260719T144000Z-second-crash", "rollback", strings.Repeat("7", 64), base.Add(6*time.Minute),
		)
		if err != nil {
			t.Fatal(err)
		}
		_, secondReceipt, _, secondPath := recoverRealCloudCloudflareBootstrapLeaseForTest(
			t, store, plan, planSHA, "20260719T145000Z-second-recovery",
			base.Add(6*time.Minute+realCloudCloudflareBootstrapLeaseTTL+time.Second),
		)
		secondReceiptBody, err := encodeRealCloudCloudflareBootstrapLeaseRecoveryReceipt(
			secondReceipt, plan, planSHA, secondReceipt.RunID,
		)
		if err != nil {
			t.Fatal(err)
		}
		puts = store.putCalls
		if replayed, err := completeRealCloudCloudflareBootstrapLeaseRecovery(
			t.Context(), store, plan, planSHA, recoveryRunID, path,
		); err != nil || !realCloudCloudflareBootstrapLeasesEqual(replayed, crashed.lease) || store.putCalls != puts {
			t.Fatalf("older recovery receipt did not survive a later completed recovery recovered=%+v puts=%d/%d err=%v", replayed, puts, store.putCalls, err)
		}
		third, err := acquireRealCloudCloudflareBootstrapLease(
			t.Context(), store, plan, planSHA, "20260719T145001Z-post-second-holder", "apply", strings.Repeat("8", 64),
			base.Add(6*time.Minute+realCloudCloudflareBootstrapLeaseTTL+2*time.Second),
		)
		if err != nil {
			t.Fatal(err)
		}
		if !realCloudCloudflareBootstrapRecoveryLineageContains(third.lease.RecoveryLineage, receipt.RecoveryPendingSHA256, receiptSHA) ||
			!realCloudCloudflareBootstrapRecoveryLineageContains(
				third.lease.RecoveryLineage, secondReceipt.RecoveryPendingSHA256, realCloudLowerSHA256(secondReceiptBody),
			) {
			t.Fatalf("later lease did not preserve both recovery generations: %+v", third.lease.RecoveryLineage)
		}
		puts = store.putCalls
		if replayed, err := completeRealCloudCloudflareBootstrapLeaseRecovery(
			t.Context(), store, plan, planSHA, recoveryRunID, path,
		); err != nil || !realCloudCloudflareBootstrapLeasesEqual(replayed, crashed.lease) || store.putCalls != puts {
			t.Fatalf("older recovery receipt did not survive a later live holder recovered=%+v puts=%d/%d err=%v", replayed, puts, store.putCalls, err)
		}
		if replayed, err := completeRealCloudCloudflareBootstrapLeaseRecovery(
			t.Context(), store, plan, planSHA, secondReceipt.RunID, secondPath,
		); err != nil || !realCloudCloudflareBootstrapLeasesEqual(replayed, secondCrashed.lease) || store.putCalls != puts {
			t.Fatalf("newer recovery receipt did not match its live descendant recovered=%+v puts=%d/%d err=%v", replayed, puts, store.putCalls, err)
		}
		if err := third.release(t.Context()); err != nil {
			t.Fatal(err)
		}

		unrelated := third.lease
		unrelated.RunID = "20260719T143100Z-unrelated-live"
		unrelated.Holder = strings.Repeat("6", 64)
		unrelated.RecoveryLineage = []realCloudCloudflareBootstrapRecoveryLineage{}
		unrelatedBody, err := encodeRealCloudCloudflareBootstrapLease(unrelated)
		if err != nil {
			t.Fatal(err)
		}
		store.version++
		store.body, store.etag = unrelatedBody, fmt.Sprintf("\"lease-%d\"", store.version)
		if _, err := completeRealCloudCloudflareBootstrapLeaseRecovery(
			t.Context(), store, plan, planSHA, recoveryRunID, path,
		); err == nil {
			t.Fatal("recovery completion accepted an unrelated live marker without exact lineage")
		}
		if store.deleteCalls != 0 {
			t.Fatalf("response-loss recovery path called DeleteObject %d times", store.deleteCalls)
		}
	})
}

func TestRealCloudCloudflareBootstrapRecoveryPendingRejectsTakeoverAndReadiness(t *testing.T) {
	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	base := time.Date(2026, 7, 19, 15, 0, 0, 0, time.UTC)
	runID := "20260719T151000Z-owner-recovery"
	store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
	if _, err := acquireRealCloudCloudflareBootstrapLease(
		t.Context(), store, plan, planSHA, "20260719T150000Z-owner-crash", "rollback", strings.Repeat("2", 64), base,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := beginRealCloudCloudflareBootstrapLeaseRecovery(
		t.Context(), store, plan, planSHA, runID, base.Add(realCloudCloudflareBootstrapLeaseTTL+time.Second),
	); err != nil {
		t.Fatal(err)
	}
	puts := store.putCalls
	if _, err := beginRealCloudCloudflareBootstrapLeaseRecovery(
		t.Context(), store, plan, planSHA, "20260719T151100Z-foreign-recovery", base.Add(48*time.Hour),
	); err == nil || store.putCalls != puts {
		t.Fatalf("another recovery run took over an existing pending marker err=%v puts=%d/%d", err, puts, store.putCalls)
	}
	rotated := plan
	rotated.CompatibilityDate = "2026-07-20"
	rotatedSHA := realCloudCloudflareBootstrapPlanSHA(rotated)
	if _, err := beginRealCloudCloudflareBootstrapLeaseRecovery(
		t.Context(), store, rotated, rotatedSHA, runID, base.Add(72*time.Hour),
	); err == nil || store.putCalls != puts {
		t.Fatalf("another recovery plan took over an existing pending marker err=%v puts=%d/%d", err, puts, store.putCalls)
	}
	foreign := plan
	foreign.ZoneID = strings.Repeat("f", 32)
	foreignSHA := realCloudCloudflareBootstrapPlanSHA(foreign)
	if _, err := beginRealCloudCloudflareBootstrapLeaseRecovery(
		t.Context(), store, foreign, foreignSHA, runID, base.Add(80*time.Hour),
	); err == nil || store.putCalls != puts {
		t.Fatalf("another provider resource took over an existing pending marker err=%v puts=%d/%d", err, puts, store.putCalls)
	}
	pendingBody := append([]byte(nil), store.body...)
	pendingETag := store.etag
	if _, err := acquireRealCloudCloudflareBootstrapLease(
		t.Context(), store, plan, planSHA, "20260719T151200Z-ordinary-run", "apply", strings.Repeat("3", 64), base.Add(96*time.Hour),
	); err == nil || !strings.Contains(err.Error(), "recovery is pending") || store.etag != pendingETag || !bytes.Equal(store.body, pendingBody) {
		t.Fatalf("ordinary execution took over an existing pending marker err=%v etag=%q/%q", err, pendingETag, store.etag)
	}
	if observation, err := collectRealCloudCloudflareReadinessBucketClosure(t.Context(), store, *resource.Cloudflare); err == nil {
		t.Fatalf("readiness admitted an owning recovery pending marker: %+v", observation)
	}
	if store.deleteCalls != 0 {
		t.Fatalf("pending takeover rejection called DeleteObject %d times", store.deleteCalls)
	}
}

func TestRealCloudCloudflareBootstrapLeaseRecoveryRejectsCASAndReceiptDrift(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	base := time.Date(2026, 7, 19, 16, 0, 0, 0, time.UTC)

	t.Run("stale-live-etag", func(t *testing.T) {
		store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
		if _, err := acquireRealCloudCloudflareBootstrapLease(
			t.Context(), store, plan, planSHA, "20260719T160000Z-stale-crash", "apply", strings.Repeat("4", 64), base,
		); err != nil {
			t.Fatal(err)
		}
		store.beforePut = func(store *fakeRealCloudCloudflareBootstrapLeaseStore, condition publish.R2PutCondition) {
			if condition.IfMatch == "" {
				t.Fatal("recovery attempted an unconditional pending write")
			}
			store.etag = "\"external-rewrite\""
		}
		if _, err := beginRealCloudCloudflareBootstrapLeaseRecovery(
			t.Context(), store, plan, planSHA, "20260719T161000Z-stale-recovery", base.Add(realCloudCloudflareBootstrapLeaseTTL+time.Second),
		); err == nil {
			t.Fatal("recovery accepted a stale live-lease ETag")
		}
		if _, err := decodeRealCloudCloudflareBootstrapLease(store.body); err != nil || store.deleteCalls != 0 {
			t.Fatalf("stale ETag changed the live marker err=%v deletes=%d", err, store.deleteCalls)
		}
	})

	t.Run("forged-receipt", func(t *testing.T) {
		store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
		if _, err := acquireRealCloudCloudflareBootstrapLease(
			t.Context(), store, plan, planSHA, "20260719T160100Z-receipt-crash", "rollback", strings.Repeat("5", 64), base,
		); err != nil {
			t.Fatal(err)
		}
		runID := "20260719T161100Z-receipt-recovery"
		pending, err := beginRealCloudCloudflareBootstrapLeaseRecovery(
			t.Context(), store, plan, planSHA, runID, base.Add(realCloudCloudflareBootstrapLeaseTTL+time.Second),
		)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := newRealCloudCloudflareBootstrapLeaseRecoveryReceipt(pending, plan, planSHA, runID)
		if err != nil {
			t.Fatal(err)
		}
		receipt.RecoveredLease.RunID = "20260719T160200Z-forged-lease"
		receipt.RecoveredLeaseRun = receipt.RecoveredLease.RunID
		forgedLeaseBody, err := encodeRealCloudCloudflareBootstrapLease(receipt.RecoveredLease)
		if err != nil {
			t.Fatal(err)
		}
		receipt.RecoveredLeaseSHA256 = realCloudLowerSHA256(forgedLeaseBody)
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "forged.lease-recovery.json")
		if err := persistRealCloudCloudflareBootstrapLeaseRecoveryReceipt(path, receipt, plan, planSHA, runID); err != nil {
			t.Fatal(err)
		}
		if _, err := completeRealCloudCloudflareBootstrapLeaseRecovery(t.Context(), store, plan, planSHA, runID, path); err == nil {
			t.Fatal("recovery accepted a receipt that did not bind its pending marker")
		}
		if _, err := decodeRealCloudCloudflareBootstrapLeaseRecoveryPending(store.body); err != nil || store.deleteCalls != 0 {
			t.Fatalf("forged receipt changed the pending marker err=%v deletes=%d", err, store.deleteCalls)
		}
	})

	t.Run("lineage-capacity-before-pending", func(t *testing.T) {
		store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
		held, err := acquireRealCloudCloudflareBootstrapLease(
			t.Context(), store, plan, planSHA, "20260719T160250Z-lineage-crash", "apply", strings.Repeat("9", 64), base,
		)
		if err != nil {
			t.Fatal(err)
		}
		saturated := held.lease
		saturated.RecoveryLineage = make([]realCloudCloudflareBootstrapRecoveryLineage, realCloudCloudflareBootstrapMaxRecoveryLineage)
		for index := range saturated.RecoveryLineage {
			saturated.RecoveryLineage[index] = realCloudCloudflareBootstrapRecoveryLineage{
				PendingSHA256: fmt.Sprintf("%064x", index+1),
				ReceiptSHA256: fmt.Sprintf("%064x", index+1+realCloudCloudflareBootstrapMaxRecoveryLineage),
			}
		}
		saturatedBody, err := encodeRealCloudCloudflareBootstrapLease(saturated)
		if err != nil {
			t.Fatal(err)
		}
		store.version++
		store.body, store.etag = saturatedBody, fmt.Sprintf("\"lease-%d\"", store.version)
		puts := store.putCalls
		if _, err := beginRealCloudCloudflareBootstrapLeaseRecovery(
			t.Context(), store, plan, planSHA, "20260719T161250Z-lineage-recovery",
			base.Add(realCloudCloudflareBootstrapLeaseTTL+time.Second),
		); err == nil || store.putCalls != puts || !bytes.Equal(store.body, saturatedBody) {
			t.Fatalf("lineage capacity did not fail before pending CAS err=%v puts=%d/%d", err, puts, store.putCalls)
		}
		duplicate := saturated
		duplicate.RecoveryLineage = append([]realCloudCloudflareBootstrapRecoveryLineage(nil), saturated.RecoveryLineage...)
		duplicate.RecoveryLineage[1] = duplicate.RecoveryLineage[0]
		if _, err := encodeRealCloudCloudflareBootstrapLease(duplicate); err == nil {
			t.Fatal("lease encoder accepted duplicate recovery lineage")
		}
	})

	t.Run("ordinary-idle", func(t *testing.T) {
		store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
		if _, err := acquireRealCloudCloudflareBootstrapLease(
			t.Context(), store, plan, planSHA, "20260719T160300Z-idle-crash", "apply", strings.Repeat("6", 64), base,
		); err != nil {
			t.Fatal(err)
		}
		runID := "20260719T161300Z-idle-recovery"
		pending, err := beginRealCloudCloudflareBootstrapLeaseRecovery(
			t.Context(), store, plan, planSHA, runID, base.Add(realCloudCloudflareBootstrapLeaseTTL+time.Second),
		)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := newRealCloudCloudflareBootstrapLeaseRecoveryReceipt(pending, plan, planSHA, runID)
		if err != nil {
			t.Fatal(err)
		}
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "ordinary-idle.lease-recovery.json")
		if err := persistRealCloudCloudflareBootstrapLeaseRecoveryReceipt(path, receipt, plan, planSHA, runID); err != nil {
			t.Fatal(err)
		}
		ordinaryIdle, err := newRealCloudCloudflareBootstrapIdleLease(pending.RecoveredLease)
		if err != nil {
			t.Fatal(err)
		}
		store.body, err = encodeRealCloudCloudflareBootstrapIdleLease(ordinaryIdle)
		if err != nil {
			t.Fatal(err)
		}
		store.etag = "\"ordinary-idle\""
		if _, err := completeRealCloudCloudflareBootstrapLeaseRecovery(t.Context(), store, plan, planSHA, runID, path); err == nil {
			t.Fatal("recovery accepted an idle marker that did not bind the durable receipt")
		}
		if store.deleteCalls != 0 {
			t.Fatalf("ordinary idle rejection called DeleteObject %d times", store.deleteCalls)
		}
	})
}

func TestRealCloudCloudflareBootstrapApplyRollbackIsReplayable(t *testing.T) {
	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planBody, _ := json.Marshal(plan)
	planSHA := realCloudLowerSHA256(planBody)
	runID := "20260717T120000Z-bootstrap"
	fake := newFakeRealCloudCloudflareBootstrapControl(plan)
	fake.fail["upload-auth"] = 1
	if _, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID); err == nil {
		t.Fatal("injected auth upload failure was ignored")
	}
	if _, exists := fake.workers[plan.OriginScript]; !exists || len(fake.routes) != 0 {
		t.Fatal("partial apply did not leave only the exact disabled origin Worker for replay")
	}
	receipt, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRealCloudCloudflareBootstrapReceipt(receipt, resource, plan, planSHA, "apply", runID); err != nil {
		t.Fatal(err)
	}
	uploadOriginCalls := fake.calls["upload-origin"]
	uploadAuthCalls := fake.calls["upload-auth"]
	createCalls := 0
	for operation, calls := range fake.calls {
		if strings.HasPrefix(operation, "create-route-") {
			createCalls += calls
		}
	}
	replayed, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID)
	if err != nil || replayed.ClosureSHA256 != receipt.ClosureSHA256 || fake.calls["upload-origin"] != uploadOriginCalls ||
		fake.calls["upload-auth"] != uploadAuthCalls {
		t.Fatalf("idempotent apply replay changed deployment err=%v", err)
	}
	replayedCreateCalls := 0
	for operation, calls := range fake.calls {
		if strings.HasPrefix(operation, "create-route-") {
			replayedCreateCalls += calls
		}
	}
	if replayedCreateCalls != createCalls {
		t.Fatal("idempotent apply replay recreated routes")
	}
	secondRouteID := receipt.Routes[1].ID
	fake.fail["delete-route-"+secondRouteID] = 1
	if _, err := rollbackRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID, receipt); err == nil {
		t.Fatal("injected rollback route failure was ignored")
	}
	rollback, err := rollbackRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRealCloudCloudflareBootstrapRollbackReceipt(rollback, receipt); err != nil {
		t.Fatal(err)
	}
	if _, exists := fake.workers[plan.AuthScript]; exists {
		t.Fatal("rollback retained auth Worker")
	}
	if _, exists := fake.workers[plan.OriginScript]; exists {
		t.Fatal("rollback retained origin Worker")
	}
	if _, exists := fake.workers[plan.TokenVerifierService]; !exists || len(fake.routes) != 0 {
		t.Fatal("rollback changed verifier or retained a route")
	}
	replayedRollback, err := rollbackRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID, receipt)
	if err != nil || replayedRollback.ClosureSHA256 != rollback.ClosureSHA256 {
		t.Fatalf("idempotent rollback replay failed err=%v", err)
	}
}

func TestRealCloudCloudflareStaticBootstrapApplyRollbackIsReplayable(t *testing.T) {
	resource, plan := realCloudCloudflareStaticBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	runID := "20260720T120000Z-static-bootstrap"
	fake := newFakeRealCloudCloudflareBootstrapControl(plan)
	receipt, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Verifier != (realCloudCloudflareBootstrapReceiptWorker{}) {
		t.Fatal("static bootstrap persisted a token-verifier Worker receipt")
	}
	if err := validateRealCloudCloudflareBootstrapReceipt(receipt, resource, plan, planSHA, "apply", runID); err != nil {
		t.Fatal(err)
	}
	receiptBody, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	assertNoRealCloudSecret(t, "static bootstrap receipt", receiptBody, realCloudCloudflareStaticSecretFragments(realCloudCloudflareStaticEntitlementsFixture(t, plan)))
	mutations := fake.calls["upload-origin"] + fake.calls["upload-auth"]
	for operation, calls := range fake.calls {
		if strings.HasPrefix(operation, "create-route-") {
			mutations += calls
		}
	}
	replayed, err := observeRealCloudCloudflareBootstrapClosure(t.Context(), fake, resource, plan, planSHA, runID, "apply")
	if err != nil || replayed.ClosureSHA256 != receipt.ClosureSHA256 {
		t.Fatalf("sealed static bootstrap replay changed closure err=%v", err)
	}
	mutationsAfter := fake.calls["upload-origin"] + fake.calls["upload-auth"]
	for operation, calls := range fake.calls {
		if strings.HasPrefix(operation, "create-route-") {
			mutationsAfter += calls
		}
	}
	if mutationsAfter != mutations {
		t.Fatalf("sealed static bootstrap replay performed mutations before=%d after=%d", mutations, mutationsAfter)
	}
	rollback, err := rollbackRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRealCloudCloudflareBootstrapRollbackReceipt(rollback, receipt); err != nil {
		t.Fatal(err)
	}
	if len(fake.workers) != 0 || len(fake.routes) != 0 {
		t.Fatalf("static rollback left managed state workers=%v routes=%v", fake.workers, fake.routes)
	}
}

func TestRealCloudCloudflareStaticBootstrapUnsealedRecoveryResetsOpaqueSecret(t *testing.T) {
	resource, plan := realCloudCloudflareStaticBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	runID := "20260720T120000Z-static-unsealed-recovery"
	fake := newFakeRealCloudCloudflareBootstrapControl(plan)
	first, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID)
	if err != nil {
		t.Fatal(err)
	}
	fake.errorAfterRouteDelete[first.Routes[0].ID] = 1
	if _, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID); err == nil {
		t.Fatal("unsealed static recovery ignored route-delete response loss")
	}
	fake.errorAfterScriptDelete[plan.AuthScript] = 1
	if _, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID); err == nil {
		t.Fatal("unsealed static recovery ignored auth-delete response loss")
	}
	recovered, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID)
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls["upload-origin"] != 1 || fake.calls["upload-auth"] != 2 || fake.calls["check-delete-script-"+plan.AuthScript] != 1 {
		t.Fatalf("unsealed static recovery did not preserve origin and recreate auth calls=%v", fake.calls)
	}
	for _, route := range plan.Routes {
		if fake.calls["create-route-"+route.Pattern] != 2 {
			t.Fatalf("unsealed static recovery did not recreate exact route %s calls=%v", route.Pattern, fake.calls)
		}
	}
	if recovered.ClosureSHA256 == first.ClosureSHA256 {
		t.Fatal("unsealed static recovery retained the opaque pre-crash auth/route closure")
	}
	if _, err := rollbackRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID, recovered); err != nil {
		t.Fatal(err)
	}
}

func TestRealCloudCloudflareBootstrapRollbackReplaysProviderSuccessAfterClientError(t *testing.T) {
	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	runID := "20260717T120000Z-response-loss"

	t.Run("route", func(t *testing.T) {
		fake := newFakeRealCloudCloudflareBootstrapControl(plan)
		receipt, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID)
		if err != nil {
			t.Fatal(err)
		}
		target := receipt.Routes[0]
		fake.errorAfterRouteDelete[target.ID] = 1
		if _, err := rollbackRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID, receipt); err == nil {
			t.Fatal("route response loss after provider delete was ignored")
		}
		if _, exists := fake.routes[target.Pattern]; exists {
			t.Fatal("route response-loss fixture did not model provider-side success")
		}
		rollback, err := rollbackRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID, receipt)
		if err != nil || validateRealCloudCloudflareBootstrapRollbackReceipt(rollback, receipt) != nil {
			t.Fatalf("route response-loss replay did not converge err=%v", err)
		}
		if fake.calls["delete-route-"+target.ID] != 1 {
			t.Fatalf("route replay repeated provider delete calls=%v", fake.calls)
		}
	})

	t.Run("worker", func(t *testing.T) {
		fake := newFakeRealCloudCloudflareBootstrapControl(plan)
		receipt, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID)
		if err != nil {
			t.Fatal(err)
		}
		fake.errorAfterScriptDelete[plan.AuthScript] = 1
		if _, err := rollbackRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID, receipt); err == nil {
			t.Fatal("Worker response loss after provider delete was ignored")
		}
		if _, exists := fake.workers[plan.AuthScript]; exists {
			t.Fatal("Worker response-loss fixture did not model provider-side success")
		}
		rollback, err := rollbackRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID, receipt)
		if err != nil || validateRealCloudCloudflareBootstrapRollbackReceipt(rollback, receipt) != nil {
			t.Fatalf("Worker response-loss replay did not converge err=%v", err)
		}
		if fake.calls["delete-script-"+plan.AuthScript] != 1 || fake.calls["delete-script-"+plan.OriginScript] != 1 {
			t.Fatalf("Worker response-loss replay repeated or omitted provider delete calls=%v", fake.calls)
		}
	})
}

func TestRealCloudCloudflareBootstrapRollbackRejectsRecreatedIdentitiesBeforeMutation(t *testing.T) {
	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planBody, _ := json.Marshal(plan)
	planSHA := realCloudLowerSHA256(planBody)
	runID := "20260717T120000Z-recreated"
	for _, test := range []struct {
		name   string
		mutate func(*fakeRealCloudCloudflareBootstrapControl)
	}{
		{"auth deployment", func(fake *fakeRealCloudCloudflareBootstrapControl) {
			state := fake.workers[plan.AuthScript]
			state.DeploymentID = "replacement-auth-deployment"
			fake.workers[plan.AuthScript] = state
		}},
		{"origin version", func(fake *fakeRealCloudCloudflareBootstrapControl) {
			state := fake.workers[plan.OriginScript]
			state.VersionID = "replacement-origin-version"
			fake.workers[plan.OriginScript] = state
		}},
		{"verifier etag", func(fake *fakeRealCloudCloudflareBootstrapControl) {
			state := fake.workers[plan.TokenVerifierService]
			state.VersionETag = "replacement-verifier-etag"
			fake.workers[plan.TokenVerifierService] = state
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeRealCloudCloudflareBootstrapControl(plan)
			receipt, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(fake)
			if _, err := rollbackRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID, receipt); err == nil {
				t.Fatal("rollback accepted a recreated security-sensitive Worker")
			}
			for operation, calls := range fake.calls {
				if calls > 0 && (strings.HasPrefix(operation, "delete-route-") || strings.HasPrefix(operation, "delete-script-")) {
					t.Fatalf("identity drift reached mutation operation=%s calls=%d", operation, calls)
				}
			}
		})
	}
}

func TestRealCloudCloudflareBootstrapRollbackRejectsDriftAtCheckedDeleteBoundary(t *testing.T) {
	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	runID := "20260717T120000Z-delete-boundary"

	t.Run("route", func(t *testing.T) {
		fake := newFakeRealCloudCloudflareBootstrapControl(plan)
		receipt, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID)
		if err != nil {
			t.Fatal(err)
		}
		target := receipt.Routes[0]
		fake.beforeDeleteRoute = func(fake *fakeRealCloudCloudflareBootstrapControl, expected realCloudCloudflareBootstrapInventoryRoute) {
			replacement := fake.routes[expected.Pattern]
			replacement.Script = "replacement-worker"
			fake.routes[expected.Pattern] = replacement
		}
		if _, err := rollbackRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID, receipt); err == nil {
			t.Fatal("rollback deleted a route changed at the checked-delete boundary")
		}
		replacement, exists := fake.routes[target.Pattern]
		if !exists || replacement.ID != target.ID || replacement.Script != "replacement-worker" {
			t.Fatal("route replacement did not survive the checked-delete rejection")
		}
		if fake.calls["check-delete-route-"+target.ID] != 1 || fake.calls["delete-route-"+target.ID] != 0 {
			t.Fatalf("route drift reached provider delete calls=%v", fake.calls)
		}
	})

	t.Run("worker", func(t *testing.T) {
		fake := newFakeRealCloudCloudflareBootstrapControl(plan)
		receipt, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID)
		if err != nil {
			t.Fatal(err)
		}
		fake.beforeDeleteScript = func(fake *fakeRealCloudCloudflareBootstrapControl, role string, _ realCloudCloudflareBootstrapReceiptWorker) {
			if role != "auth" {
				t.Fatalf("first checked Worker delete role=%s want=auth", role)
			}
			replacement := fake.workers[plan.AuthScript]
			replacement.DeploymentID = "replacement-auth-deployment"
			fake.workers[plan.AuthScript] = replacement
		}
		if _, err := rollbackRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID, receipt); err == nil {
			t.Fatal("rollback deleted a Worker changed at the checked-delete boundary")
		}
		replacement, exists := fake.workers[plan.AuthScript]
		if !exists || replacement.DeploymentID != "replacement-auth-deployment" {
			t.Fatal("Worker replacement did not survive the checked-delete rejection")
		}
		if fake.calls["check-delete-script-"+plan.AuthScript] != 1 || fake.calls["delete-script-"+plan.AuthScript] != 0 ||
			fake.calls["delete-script-"+plan.OriginScript] != 0 {
			t.Fatalf("Worker drift reached provider delete calls=%v", fake.calls)
		}
	})

	t.Run("worker attachment", func(t *testing.T) {
		fake := newFakeRealCloudCloudflareBootstrapControl(plan)
		receipt, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID)
		if err != nil {
			t.Fatal(err)
		}
		fake.beforeDeleteScript = func(fake *fakeRealCloudCloudflareBootstrapControl, role string, _ realCloudCloudflareBootstrapReceiptWorker) {
			fake.attachments = []string{role + "\x00schedule"}
		}
		if _, err := rollbackRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID, receipt); err == nil {
			t.Fatal("rollback deleted a Worker with a new attachment at the checked-delete boundary")
		}
		if _, exists := fake.workers[plan.AuthScript]; !exists || fake.calls["delete-script-"+plan.AuthScript] != 0 {
			t.Fatalf("Worker attachment drift reached provider delete calls=%v", fake.calls)
		}
	})
}

func TestRealCloudCloudflareBootstrapRollbackProbesReceiptIdentitiesWhenInventoryOmitsThem(t *testing.T) {
	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	runID := "20260717T120000Z-inventory-omission"
	fake := newFakeRealCloudCloudflareBootstrapControl(plan)
	receipt, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range receipt.Routes {
		fake.omitRouteInventory[route.Pattern] = true
	}
	fake.omitWorkerInventory[plan.AuthScript] = true
	fake.omitWorkerInventory[plan.OriginScript] = true
	rollback, err := rollbackRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, runID, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRealCloudCloudflareBootstrapRollbackReceipt(rollback, receipt); err != nil {
		t.Fatal(err)
	}
	if len(fake.routes) != 0 {
		t.Fatalf("receipt routes survived inventory omission: %+v", fake.routes)
	}
	if _, exists := fake.workers[plan.AuthScript]; exists {
		t.Fatal("receipt auth Worker survived inventory omission")
	}
	if _, exists := fake.workers[plan.OriginScript]; exists {
		t.Fatal("receipt origin Worker survived inventory omission")
	}
	for _, route := range receipt.Routes {
		if fake.calls["delete-route-"+route.ID] != 1 {
			t.Fatalf("omitted receipt route was not exactly probed and deleted calls=%v", fake.calls)
		}
	}
}

func TestRealCloudCloudflareBootstrapRejectsSharedZoneConflictsBeforeMutation(t *testing.T) {
	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planBody, _ := json.Marshal(plan)
	planSHA := realCloudLowerSHA256(planBody)
	for _, test := range []struct {
		name   string
		mutate func(*fakeRealCloudCloudflareBootstrapControl)
	}{
		{"overlapping wildcard route", func(fake *fakeRealCloudCloudflareBootstrapControl) {
			fake.routes["*.pigsty.io/*"] = realCloudCloudflareBootstrapInventoryRoute{ID: "foreign-route", Pattern: "*.pigsty.io/*", Script: "foreign-worker"}
		}},
		{"foreign exact route", func(fake *fakeRealCloudCloudflareBootstrapControl) {
			pattern := plan.Routes[0].Pattern
			fake.routes[pattern] = realCloudCloudflareBootstrapInventoryRoute{ID: "foreign-route", Pattern: pattern, Script: "foreign-worker"}
		}},
		{"verifier custom domain", func(fake *fakeRealCloudCloudflareBootstrapControl) {
			fake.domains = []string{plan.TokenVerifierService}
		}},
		{"existing origin schedule", func(fake *fakeRealCloudCloudflareBootstrapControl) {
			fake.workers[plan.OriginScript] = fakeRealCloudCloudflareBootstrapWorkerState(plan, "origin", "20260717T120000Z-conflict", true)
			fake.attachments = []string{plan.OriginScript + "\x00schedule"}
		}},
		{"drifted existing origin", func(fake *fakeRealCloudCloudflareBootstrapControl) {
			state := fakeRealCloudCloudflareBootstrapWorkerState(plan, "origin", "20260717T120000Z-conflict", true)
			state.ContentSHA256 = strings.Repeat("f", 64)
			fake.workers[plan.OriginScript] = state
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeRealCloudCloudflareBootstrapControl(plan)
			test.mutate(fake)
			if _, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, "20260717T120000Z-conflict"); err == nil {
				t.Fatal("unsafe shared-zone bootstrap state was accepted")
			}
			if fake.calls["upload-origin"] != 0 || fake.calls["upload-auth"] != 0 {
				t.Fatal("shared-zone conflict reached a Worker upload")
			}
		})
	}
}

func TestRealCloudCloudflareBootstrapRejectsDifferentRunTakeoverBeforeMutation(t *testing.T) {
	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	fake := newFakeRealCloudCloudflareBootstrapControl(plan)
	if _, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, "20260717T120000Z-first-run"); err != nil {
		t.Fatal(err)
	}
	mutationsBefore := fake.calls["upload-origin"] + fake.calls["upload-auth"] + fake.calls["disable-"+plan.OriginScript] + fake.calls["disable-"+plan.AuthScript]
	for operation, calls := range fake.calls {
		if strings.HasPrefix(operation, "create-route-") {
			mutationsBefore += calls
		}
	}
	if _, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, "20260717T120000Z-second-run"); err == nil {
		t.Fatal("a different bootstrap run adopted existing Worker ownership")
	}
	mutationsAfter := fake.calls["upload-origin"] + fake.calls["upload-auth"] + fake.calls["disable-"+plan.OriginScript] + fake.calls["disable-"+plan.AuthScript]
	for operation, calls := range fake.calls {
		if strings.HasPrefix(operation, "create-route-") {
			mutationsAfter += calls
		}
	}
	if mutationsAfter != mutationsBefore {
		t.Fatalf("different-run takeover reached mutation before=%d after=%d", mutationsBefore, mutationsAfter)
	}
}

func TestRealCloudCloudflareBootstrapOfficialSDKMutationContract(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	runID := "20260717T120000Z-sdk-mutation"
	wantedOriginBundle, err := readRealCloudProviderRepositoryFile(plan.OriginBundle.Path, realCloudProviderMaxContentBytes)
	if err != nil {
		t.Fatal(err)
	}
	wantedAuthBundle, err := readRealCloudProviderRepositoryFile(plan.AuthBundle.Path, realCloudProviderMaxContentBytes)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	sequence := make([]string, 0, 8)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		sequence = append(sequence, request.Method+" "+request.URL.Path)
		if request.Header.Get("Authorization") != "Bearer bootstrap-test-token" {
			t.Errorf("request %d omitted exact bearer authorization", requests)
		}
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodPut && (request.URL.Path == "/client/v4/accounts/"+plan.AccountID+"/workers/scripts/"+plan.OriginScript || request.URL.Path == "/client/v4/accounts/"+plan.AccountID+"/workers/scripts/"+plan.AuthScript):
			script, wantedBundle := plan.OriginScript, wantedOriginBundle
			if strings.HasSuffix(request.URL.Path, "/"+plan.AuthScript) {
				script, wantedBundle = plan.AuthScript, wantedAuthBundle
			}
			if request.Header.Get("If-None-Match") != "*" {
				t.Error("Worker create omitted If-None-Match: * ownership precondition")
			}
			if request.URL.Query().Get("bindings_inherit") != "strict" {
				t.Error("Worker upload omitted strict binding inheritance policy")
			}
			mediaType, parameters, parseErr := mime.ParseMediaType(request.Header.Get("Content-Type"))
			if parseErr != nil || mediaType != "multipart/form-data" {
				t.Errorf("Worker upload content type=%q err=%v", request.Header.Get("Content-Type"), parseErr)
				break
			}
			reader := multipart.NewReader(request.Body, parameters["boundary"])
			seenMetadata, seenFile := false, false
			for {
				part, partErr := reader.NextPart()
				if errors.Is(partErr, io.EOF) {
					break
				}
				if partErr != nil {
					t.Errorf("read upload multipart: %v", partErr)
					break
				}
				partBody, _ := io.ReadAll(part)
				switch part.FormName() {
				case "metadata":
					var metadata struct {
						Annotations struct {
							Message string `json:"workers/message"`
							Tag     string `json:"workers/tag"`
						} `json:"annotations"`
						CacheOptions struct {
							Enabled           bool `json:"enabled"`
							CrossVersionCache bool `json:"cross_version_cache"`
						} `json:"cache_options"`
						Observability struct {
							Enabled bool `json:"enabled"`
						} `json:"observability"`
						Limits struct {
							CPUMs       int64 `json:"cpu_ms"`
							Subrequests int64 `json:"subrequests"`
						} `json:"limits"`
						Bindings []struct {
							Name        string `json:"name"`
							Type        string `json:"type"`
							Text        string `json:"text"`
							Service     string `json:"service"`
							Environment string `json:"environment"`
							BucketName  string `json:"bucket_name"`
						} `json:"bindings"`
						Tags          []string `json:"tags"`
						TailConsumers []any    `json:"tail_consumers"`
						Logpush       bool     `json:"logpush"`
						MainModule    string   `json:"main_module"`
						UsageModel    string   `json:"usage_model"`
					}
					message, tag := realCloudCloudflareBootstrapOwnershipAnnotations(plan, runID)
					metadataOK := json.Unmarshal(partBody, &metadata) == nil
					bindingsExact := metadataOK
					if script == plan.OriginScript {
						bindingsExact = len(metadata.Bindings) == 1 && metadata.Bindings[0].Name == "REPOSITORY" && metadata.Bindings[0].Type == "r2_bucket" && metadata.Bindings[0].BucketName == plan.R2Bucket
					} else {
						wanted := make(map[string]string, len(plan.EdgeContract.Variables)+2)
						for name, value := range plan.EdgeContract.Variables {
							wanted[name] = "plain_text\x00" + value
						}
						wanted["ORIGIN"] = "service\x00" + plan.OriginScript + "\x00" + realCloudCloudflareBootstrapServiceEnvironment("")
						wanted["TOKEN_VERIFIER"] = "service\x00" + plan.TokenVerifierService + "\x00" + realCloudCloudflareBootstrapServiceEnvironment(plan.TokenVerifierEnvironment)
						for _, binding := range metadata.Bindings {
							observed := binding.Type + "\x00" + binding.Text
							if binding.Type == "service" {
								observed = binding.Type + "\x00" + binding.Service + "\x00" + binding.Environment
							}
							if wanted[binding.Name] != observed {
								wanted["invalid"] = "present"
								break
							}
							delete(wanted, binding.Name)
						}
						bindingsExact = len(wanted) == 0
					}
					seenMetadata = metadataOK && metadata.MainModule == "worker.mjs" && bindingsExact &&
						metadata.Annotations.Message == message && metadata.Annotations.Tag == tag &&
						!metadata.CacheOptions.Enabled && !metadata.CacheOptions.CrossVersionCache && !metadata.Observability.Enabled &&
						metadata.Limits.CPUMs == 0 && metadata.Limits.Subrequests == 0 && metadata.UsageModel == "standard" &&
						!metadata.Logpush && metadata.Tags != nil && len(metadata.Tags) == 0 && metadata.TailConsumers != nil && len(metadata.TailConsumers) == 0 &&
						!bytes.Contains(partBody, []byte(`"limits"`)) && bytes.Contains(partBody, []byte(`"logpush":false`)) &&
						!bytes.Contains(partBody, []byte("secret"))
				case "files":
					seenFile = part.FileName() == "worker.mjs" && part.Header.Get("Content-Type") == "application/javascript+module" && bytes.Equal(partBody, wantedBundle)
				}
			}
			if !seenMetadata || !seenFile {
				t.Errorf("Worker upload missing exact metadata or bundle metadata=%t file=%t", seenMetadata, seenFile)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": map[string]any{"startup_time_ms": 1, "id": script, "compatibility_date": plan.CompatibilityDate, "compatibility_flags": []any{}}})
		case request.Method == http.MethodPost && request.URL.Path == "/client/v4/accounts/"+plan.AccountID+"/workers/scripts/"+plan.OriginScript+"/subdomain":
			body, _ := io.ReadAll(request.Body)
			if string(body) != `{"enabled":false,"previews_enabled":false}` {
				t.Errorf("unexpected exposure body %s", body)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": map[string]any{"enabled": false, "previews_enabled": false}})
		case request.Method == http.MethodPost && request.URL.Path == "/client/v4/zones/"+plan.ZoneID+"/workers/routes":
			var routeRequest struct {
				Pattern string `json:"pattern"`
				Script  string `json:"script"`
			}
			if err := json.NewDecoder(request.Body).Decode(&routeRequest); err != nil || routeRequest.Pattern != plan.Routes[0].Pattern || routeRequest.Script != plan.Routes[0].Script {
				t.Errorf("route create body differs from plan body=%+v err=%v", routeRequest, err)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": map[string]any{"id": "route-sdk-1", "pattern": plan.Routes[0].Pattern, "script": plan.Routes[0].Script}})
		case request.Method == http.MethodGet && request.URL.Path == "/client/v4/zones/"+plan.ZoneID+"/workers/routes/route-sdk-1":
			_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": map[string]any{"id": "route-sdk-1", "pattern": plan.Routes[0].Pattern, "script": plan.Routes[0].Script}})
		case request.Method == http.MethodDelete && request.URL.Path == "/client/v4/zones/"+plan.ZoneID+"/workers/routes/route-sdk-1":
			_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": map[string]any{"id": "route-sdk-1"}})
		default:
			t.Errorf("unexpected Cloudflare bootstrap request method=%s path=%s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
			_, _ = writer.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"unexpected"}],"messages":[],"result":null}`))
		}
	}))
	defer server.Close()
	control, err := newRealCloudCloudflareSDKBootstrapControl("bootstrap-test-token", server.URL+"/client/v4", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	if err := control.Upload(t.Context(), plan, "origin", planSHA, runID); err != nil {
		t.Fatal(err)
	}
	if err := control.Upload(t.Context(), plan, "auth", planSHA, runID); err != nil {
		t.Fatal(err)
	}
	if err := control.DisableExposure(t.Context(), plan, plan.OriginScript); err != nil {
		t.Fatal(err)
	}
	routeID, err := control.CreateRoute(t.Context(), plan, plan.Routes[0])
	if err != nil || routeID != "route-sdk-1" {
		t.Fatalf("route id=%q err=%v", routeID, err)
	}
	inspectedRoute, err := control.GetRoute(t.Context(), plan, routeID)
	if err != nil || inspectedRoute.ID != routeID || inspectedRoute.Pattern != plan.Routes[0].Pattern || inspectedRoute.Script != plan.Routes[0].Script {
		t.Fatalf("inspected route=%+v err=%v", inspectedRoute, err)
	}
	if err := control.DeleteRouteIfMatch(t.Context(), plan, inspectedRoute); err != nil {
		t.Fatal(err)
	}
	if requests != 7 {
		t.Fatalf("official SDK mutation request count=%d want=7", requests)
	}
	routePath := "/client/v4/zones/" + plan.ZoneID + "/workers/routes/" + routeID
	if len(sequence) < 2 || sequence[len(sequence)-2] != "GET "+routePath || sequence[len(sequence)-1] != "DELETE "+routePath {
		t.Fatalf("checked route delete was not adjacent to its final identity recheck: %v", sequence)
	}
}

func TestRealCloudCloudflareStaticBootstrapOfficialSDKSecretBindingContract(t *testing.T) {
	_, plan := realCloudCloudflareStaticBootstrapPlanFixture(t)
	secret := realCloudCloudflareStaticEntitlementsFixture(t, plan)
	wantedBundle, err := readRealCloudProviderRepositoryFile(plan.AuthBundle.Path, realCloudProviderMaxContentBytes)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		if request.Method != http.MethodPut || request.URL.Path != "/client/v4/accounts/"+plan.AccountID+"/workers/scripts/"+plan.AuthScript {
			t.Error("static bootstrap sent an unexpected provider request")
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		mediaType, parameters, parseErr := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if parseErr != nil || mediaType != "multipart/form-data" {
			t.Error("static Worker upload is not multipart")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		reader := multipart.NewReader(request.Body, parameters["boundary"])
		seenMetadata, seenFile := false, false
		for {
			part, partErr := reader.NextPart()
			if errors.Is(partErr, io.EOF) {
				break
			}
			if partErr != nil {
				t.Error("read static Worker multipart")
				break
			}
			partBody, _ := io.ReadAll(part)
			switch part.FormName() {
			case "metadata":
				var metadata struct {
					Bindings []struct {
						Name        string `json:"name"`
						Type        string `json:"type"`
						Text        string `json:"text"`
						Service     string `json:"service"`
						Environment string `json:"environment"`
					} `json:"bindings"`
				}
				if json.Unmarshal(partBody, &metadata) != nil {
					break
				}
				wanted := make(map[string]string, len(plan.EdgeContract.Variables)+2)
				for name, value := range plan.EdgeContract.Variables {
					wanted[name] = "plain_text\x00" + value
				}
				wanted["ORIGIN"] = "service\x00" + plan.OriginScript + "\x00" + realCloudCloudflareBootstrapServiceEnvironment("")
				wanted[plan.TokenVerifierSecret] = "secret_text\x00" + secret
				for _, binding := range metadata.Bindings {
					observed := binding.Type + "\x00" + binding.Text
					if binding.Type == "service" {
						observed = binding.Type + "\x00" + binding.Service + "\x00" + binding.Environment
					}
					if wanted[binding.Name] != observed {
						wanted["invalid"] = "present"
						break
					}
					delete(wanted, binding.Name)
				}
				seenMetadata = len(wanted) == 0
			case "files":
				seenFile = part.FileName() == "worker.mjs" && bytes.Equal(partBody, wantedBundle)
			}
		}
		if !seenMetadata || !seenFile {
			t.Error("static Worker upload omitted the exact secret binding or bundle")
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": map[string]any{"startup_time_ms": 1, "id": plan.AuthScript, "compatibility_date": plan.CompatibilityDate, "compatibility_flags": []any{}}})
	}))
	defer server.Close()
	control, err := newRealCloudCloudflareSDKBootstrapControl("static-bootstrap-test-token", server.URL+"/client/v4", server.Client(), map[string]string{plan.TokenVerifierSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Upload(t.Context(), plan, "auth", realCloudCloudflareBootstrapPlanSHA(plan), "20260720T120000Z-static-sdk"); err != nil {
		t.Fatal(err)
	}
	withoutSecret, err := newRealCloudCloudflareSDKBootstrapControl("static-bootstrap-test-token", server.URL+"/client/v4", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := withoutSecret.Upload(t.Context(), plan, "auth", realCloudCloudflareBootstrapPlanSHA(plan), "20260720T120000Z-static-sdk"); err == nil || requests != 1 {
		t.Fatalf("missing static secret reached provider requests=%d err=%v", requests, err)
	}
	_, providerPlan := realCloudCloudflareBootstrapPlanFixture(t)
	withUnexpectedSecret, err := newRealCloudCloudflareSDKBootstrapControl("static-bootstrap-test-token", server.URL+"/client/v4", server.Client(), map[string]string{plan.TokenVerifierSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	if err := withUnexpectedSecret.Upload(t.Context(), providerPlan, "auth", realCloudCloudflareBootstrapPlanSHA(providerPlan), "20260720T120000Z-static-sdk"); err == nil || requests != 1 {
		t.Fatalf("provider plan accepted a static secret requests=%d err=%v", requests, err)
	}
}

func TestRealCloudCloudflareStaticBootstrapBindingInspectionIsExact(t *testing.T) {
	_, plan := realCloudCloudflareStaticBootstrapPlanFixture(t)
	bindings := make([]workers.ScriptVersionGetResponseResourcesBinding, 0, len(plan.EdgeContract.Variables)+2)
	for name, value := range plan.EdgeContract.Variables {
		bindings = append(bindings, workers.ScriptVersionGetResponseResourcesBinding{
			Name: name, Type: workers.ScriptVersionGetResponseResourcesBindingsTypePlainText, Text: value,
		})
	}
	bindings = append(bindings,
		workers.ScriptVersionGetResponseResourcesBinding{Name: "ORIGIN", Type: workers.ScriptVersionGetResponseResourcesBindingsTypeService, Service: plan.OriginScript, Environment: realCloudCloudflareBootstrapServiceEnvironment("")},
		workers.ScriptVersionGetResponseResourcesBinding{Name: plan.TokenVerifierSecret, Type: workers.ScriptVersionGetResponseResourcesBindingsTypeSecretText},
	)
	got, err := validateRealCloudCloudflareBootstrapAuthBindings(bindings, plan)
	if err != nil || got != realCloudCloudflareBootstrapExpectedAuthBindingsSHA(plan) {
		t.Fatalf("static binding inspection digest=%q err=%v", got, err)
	}
	drifted := append([]workers.ScriptVersionGetResponseResourcesBinding(nil), bindings...)
	drifted[len(drifted)-1] = workers.ScriptVersionGetResponseResourcesBinding{
		Name: "TOKEN_VERIFIER", Type: workers.ScriptVersionGetResponseResourcesBindingsTypeService, Service: "pigsty-entitlements",
	}
	if _, err := validateRealCloudCloudflareBootstrapAuthBindings(drifted, plan); err == nil {
		t.Fatal("static binding inspection accepted a provider service substitution")
	}
}

func TestRealCloudCloudflareBootstrapOfficialSDKCheckedRouteDeleteRejectsDrift(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	expected := realCloudCloudflareBootstrapInventoryRoute{ID: "route-sdk-drift", Pattern: plan.Routes[0].Pattern, Script: plan.Routes[0].Script}
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		key := request.Method + " " + request.URL.Path
		requests[key]++
		writer.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && request.URL.Path == "/client/v4/zones/"+plan.ZoneID+"/workers/routes/"+expected.ID {
			_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": map[string]any{
				"id": expected.ID, "pattern": expected.Pattern, "script": "replacement-worker",
			}})
			return
		}
		t.Errorf("checked route drift reached unexpected request %s", key)
		writer.WriteHeader(http.StatusConflict)
		_, _ = writer.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"unexpected"}],"messages":[],"result":null}`))
	}))
	defer server.Close()
	control, err := newRealCloudCloudflareSDKBootstrapControl("bootstrap-route-drift-token", server.URL+"/client/v4", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := control.DeleteRouteIfMatch(t.Context(), plan, expected); err == nil {
		t.Fatal("checked route delete accepted a replacement route body")
	}
	path := "/client/v4/zones/" + plan.ZoneID + "/workers/routes/" + expected.ID
	if requests["GET "+path] != 1 || requests["DELETE "+path] != 0 || len(requests) != 1 {
		t.Fatalf("route drift request surface=%v", requests)
	}
}

func TestRealCloudCloudflareBootstrapOfficialSDKCheckedDeleteTreatsExactAbsenceAsReplaySuccess(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	writeNotFound := func(writer http.ResponseWriter) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusNotFound)
		_, _ = writer.Write([]byte(`{"success":false,"errors":[{"code":10090,"message":"not found"}],"messages":[],"result":null}`))
	}
	t.Run("route", func(t *testing.T) {
		expected := realCloudCloudflareBootstrapInventoryRoute{ID: "route-sdk-absent", Pattern: plan.Routes[0].Pattern, Script: plan.Routes[0].Script}
		requests := make(map[string]int)
		path := "/client/v4/zones/" + plan.ZoneID + "/workers/routes/" + expected.ID
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			requests[request.Method+" "+request.URL.Path]++
			if request.Method != http.MethodGet || request.URL.Path != path {
				t.Errorf("absent checked route reached unexpected request method=%s path=%s", request.Method, request.URL.Path)
			}
			writeNotFound(writer)
		}))
		defer server.Close()
		control, err := newRealCloudCloudflareSDKBootstrapControl("bootstrap-absent-route-token", server.URL+"/client/v4", server.Client())
		if err != nil {
			t.Fatal(err)
		}
		if err := control.DeleteRouteIfMatch(t.Context(), plan, expected); err != nil {
			t.Fatalf("replaying an already-deleted exact route failed: %v", err)
		}
		if requests["GET "+path] != 1 || requests["DELETE "+path] != 0 || len(requests) != 1 {
			t.Fatalf("absent route replay request surface=%v", requests)
		}
	})
	t.Run("worker", func(t *testing.T) {
		requests := make(map[string]int)
		path := "/client/v4/accounts/" + plan.AccountID + "/workers/scripts/" + plan.AuthScript + "/deployments"
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			requests[request.Method+" "+request.URL.Path]++
			if request.Method != http.MethodGet || request.URL.Path != path {
				t.Errorf("absent checked Worker reached unexpected request method=%s path=%s", request.Method, request.URL.Path)
			}
			writeNotFound(writer)
		}))
		defer server.Close()
		control, err := newRealCloudCloudflareSDKBootstrapControl("bootstrap-absent-worker-token", server.URL+"/client/v4", server.Client())
		if err != nil {
			t.Fatal(err)
		}
		expected := realCloudCloudflareBootstrapReceiptWorker{Script: plan.AuthScript}
		if err := control.DeleteScriptIfMatch(t.Context(), plan, "auth", "20260717T120000Z-absent-worker", expected); err != nil {
			t.Fatalf("replaying an already-deleted exact Worker failed: %v", err)
		}
		base := strings.TrimSuffix(path, "/deployments")
		if requests["GET "+path] != 1 || requests["DELETE "+base] != 0 || len(requests) != 1 {
			t.Fatalf("absent Worker replay request surface=%v", requests)
		}
	})
}

func TestRealCloudCloudflareBootstrapOfficialSDKInventoryContract(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		key := request.Method + " " + request.URL.Path
		requests[key]++
		if request.Header.Get("Authorization") != "Bearer bootstrap-inventory-token" {
			t.Errorf("inventory request omitted exact bearer authorization path=%s", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		var result any
		switch request.URL.Path {
		case "/client/v4/accounts/" + plan.AccountID + "/workers/scripts":
			result = []map[string]any{
				{"id": plan.AuthScript, "routes": []any{}, "tail_consumers": []any{}},
				{"id": plan.OriginScript, "routes": []any{}, "tail_consumers": []any{}},
				{"id": plan.TokenVerifierService, "routes": []any{}, "tail_consumers": []any{}},
			}
		case "/client/v4/accounts/" + plan.AccountID + "/workers/scripts/" + plan.AuthScript + "/schedules",
			"/client/v4/accounts/" + plan.AccountID + "/workers/scripts/" + plan.OriginScript + "/schedules",
			"/client/v4/accounts/" + plan.AccountID + "/workers/scripts/" + plan.TokenVerifierService + "/schedules":
			result = map[string]any{"schedules": []any{}}
		case "/client/v4/zones/" + plan.ZoneID + "/workers/routes":
			result = []map[string]any{
				{"id": "inventory-main-route", "pattern": plan.Routes[0].Pattern, "script": plan.AuthScript},
				{"id": "inventory-beta-route", "pattern": plan.Routes[1].Pattern, "script": plan.AuthScript},
			}
		case "/client/v4/accounts/" + plan.AccountID + "/workers/domains":
			result = []any{}
		default:
			t.Errorf("unexpected inventory request %s", key)
			writer.WriteHeader(http.StatusNotFound)
			_, _ = writer.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"unexpected"}],"messages":[],"result":null}`))
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result})
	}))
	defer server.Close()
	control, err := newRealCloudCloudflareSDKBootstrapControl("bootstrap-inventory-token", server.URL+"/client/v4", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := control.Inventory(t.Context(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateRealCloudCloudflareBootstrapInventory(plan, inventory, true); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 6 {
		t.Fatalf("official SDK inventory endpoint count=%d want=6 requests=%v", len(requests), requests)
	}
	for path, count := range requests {
		if count != 1 {
			t.Fatalf("official SDK inventory request %s count=%d", path, count)
		}
	}
}

func TestRealCloudCloudflareBootstrapOfficialSDKInspectContract(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	runID := "20260717T120000Z-sdk-inspect"
	bundle, err := readRealCloudProviderRepositoryFile(plan.AuthBundle.Path, realCloudProviderMaxContentBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer clearRealCloudBytes(bundle)
	bindings := make([]map[string]any, 0, len(plan.EdgeContract.Variables)+2)
	for name, value := range plan.EdgeContract.Variables {
		bindings = append(bindings, map[string]any{"name": name, "type": "plain_text", "text": value})
	}
	bindings = append(bindings,
		map[string]any{"name": "ORIGIN", "type": "service", "service": plan.OriginScript, "environment": realCloudCloudflareBootstrapServiceEnvironment("")},
		map[string]any{"name": "TOKEN_VERIFIER", "type": "service", "service": plan.TokenVerifierService, "environment": realCloudCloudflareBootstrapServiceEnvironment(plan.TokenVerifierEnvironment)},
	)
	message, tag := realCloudCloudflareBootstrapOwnershipAnnotations(plan, runID)
	for _, test := range []struct {
		name                 string
		observabilityEnabled bool
		extraVersion         bool
		deploymentDrift      bool
		wantInspectError     bool
		wantDeleteError      bool
	}{
		{name: "closed settings"},
		{name: "observability rejected", observabilityEnabled: true, wantInspectError: true},
		{name: "inactive version rejected", extraVersion: true, wantDeleteError: true},
		{name: "final deployment drift rejected", deploymentDrift: true, wantDeleteError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := make(map[string]int)
			sequence := make([]string, 0, 32)
			accountScripts := "/client/v4/accounts/" + plan.AccountID + "/workers/scripts"
			base := "/client/v4/accounts/" + plan.AccountID + "/workers/scripts/" + plan.AuthScript
			routeList := "/client/v4/zones/" + plan.ZoneID + "/workers/routes"
			domainList := "/client/v4/accounts/" + plan.AccountID + "/workers/domains"
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				key := request.Method + " " + request.URL.Path
				requests[key]++
				sequence = append(sequence, key)
				if request.Header.Get("Authorization") != "Bearer bootstrap-inspect-token" {
					t.Errorf("inspect request omitted exact bearer authorization path=%s", request.URL.Path)
				}
				writer.Header().Set("Content-Type", "application/json")
				writeEnvelope := func(result any) {
					_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result})
				}
				switch request.URL.Path {
				case accountScripts:
					writeEnvelope([]map[string]any{
						{"id": plan.AuthScript, "routes": []any{}, "tail_consumers": []any{}},
						{"id": plan.OriginScript, "routes": []any{}, "tail_consumers": []any{}},
						{"id": plan.TokenVerifierService, "routes": []any{}, "tail_consumers": []any{}},
					})
				case accountScripts + "/" + plan.AuthScript + "/schedules",
					accountScripts + "/" + plan.OriginScript + "/schedules",
					accountScripts + "/" + plan.TokenVerifierService + "/schedules":
					writeEnvelope(map[string]any{"schedules": []any{}})
				case routeList:
					writeEnvelope([]any{})
				case domainList:
					writeEnvelope([]any{})
				case base + "/deployments":
					deploymentID, versionID := "bootstrap-auth-deployment", "bootstrap-auth-version"
					if test.deploymentDrift && requests[key] >= 7 {
						deploymentID, versionID = "replacement-auth-deployment", "replacement-auth-version"
					}
					writeEnvelope(map[string]any{"deployments": []map[string]any{{
						"id": deploymentID, "created_on": "2026-07-17T00:00:00Z", "source": "api", "strategy": "percentage",
						"versions": []map[string]any{{"percentage": 100, "version_id": versionID}},
					}}})
				case base + "/versions":
					items := []map[string]any{}
					if request.URL.Query().Get("page") != "2" {
						items = append(items, map[string]any{"id": "bootstrap-auth-version", "number": 1, "metadata": map[string]any{}})
						if test.extraVersion {
							items = append(items, map[string]any{"id": "unsealed-draft-version", "number": 2, "metadata": map[string]any{}})
						}
					}
					_ = json.NewEncoder(writer).Encode(map[string]any{
						"result": map[string]any{"items": items}, "result_info": map[string]any{"page": 1, "per_page": 100},
					})
				case base + "/versions/bootstrap-auth-version":
					writeEnvelope(map[string]any{"id": "bootstrap-auth-version", "resources": map[string]any{
						"script": map[string]any{"etag": "bootstrap-auth-etag"}, "bindings": bindings,
						"script_runtime": map[string]any{
							"compatibility_date": plan.CompatibilityDate, "compatibility_flags": plan.CompatibilityFlags,
							"limits": map[string]any{"cpu_ms": 0}, "migration_tag": "", "usage_model": "standard",
						},
					}})
				case base + "/content/v2":
					writer.Header().Set("Content-Type", "application/javascript")
					_, _ = writer.Write(bundle)
				case base + "/settings":
					writeEnvelope(map[string]any{
						"annotations": map[string]any{"workers/message": message, "workers/tag": tag},
						"bindings":    bindings, "cache_options": map[string]any{"enabled": false, "cross_version_cache": false},
						"compatibility_date": plan.CompatibilityDate, "compatibility_flags": plan.CompatibilityFlags,
						"limits": map[string]any{"cpu_ms": 0, "subrequests": 0}, "placement": map[string]any{}, "usage_model": "standard",
						"logpush": false, "observability": map[string]any{"enabled": test.observabilityEnabled,
							"logs":   map[string]any{"enabled": false, "invocation_logs": false, "destinations": []any{}, "persist": false},
							"traces": map[string]any{"enabled": false, "destinations": []any{}, "persist": false}},
						"tags": []any{}, "tail_consumers": []any{},
					})
				case base + "/subdomain":
					writeEnvelope(map[string]any{"enabled": false, "previews_enabled": false})
				case base:
					if request.Method != http.MethodDelete || request.URL.Query().Get("force") != "false" {
						t.Errorf("checked Worker delete method=%s query=%s", request.Method, request.URL.RawQuery)
					}
					writeEnvelope(nil)
				default:
					t.Errorf("unexpected inspect request %s", key)
					writer.WriteHeader(http.StatusNotFound)
					_, _ = writer.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"unexpected"}],"messages":[],"result":null}`))
				}
			}))
			defer server.Close()
			control, err := newRealCloudCloudflareSDKBootstrapControl("bootstrap-inspect-token", server.URL+"/client/v4", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			state, inspectErr := control.Inspect(t.Context(), plan, "auth")
			if test.wantInspectError {
				if inspectErr == nil {
					t.Fatal("security-sensitive Worker observability was accepted")
				}
				return
			}
			if inspectErr != nil {
				t.Fatal(inspectErr)
			}
			if err := validateRealCloudCloudflareBootstrapWorkerState("auth", state, plan, runID, true); err != nil {
				t.Fatal(err)
			}
			deleteErr := control.DeleteScriptIfMatch(t.Context(), plan, "auth", runID, realCloudCloudflareBootstrapReceiptWorkerFromState(state))
			if test.wantDeleteError {
				if deleteErr == nil {
					t.Fatal("checked Worker delete accepted a changed provider identity or version closure")
				}
				if requests["DELETE "+base] != 0 {
					t.Fatalf("checked Worker delete reached DELETE after drift: %v", requests)
				}
				return
			}
			if deleteErr != nil {
				t.Fatal(deleteErr)
			}
			deployPath := "GET " + base + "/deployments"
			versionsPath := "GET " + base + "/versions"
			if requests[deployPath] != 7 || requests[versionsPath] != 2 || requests["DELETE "+base] != 1 || len(requests) != 13 {
				t.Fatalf("official SDK inspect request surface=%v", requests)
			}
			if len(sequence) < 2 || sequence[len(sequence)-2] != versionsPath || sequence[len(sequence)-1] != "DELETE "+base {
				t.Fatalf("checked Worker delete was not adjacent to its final version-closure recheck: %v", sequence)
			}
		})
	}
}

func TestRealCloudCloudflareBootstrapOfficialSDKVerifierRuntimeAndSettingsContract(t *testing.T) {
	_, plan := realCloudCloudflareBootstrapPlanFixture(t)
	runID := "20260717T120000Z-sdk-verifier"
	content := []byte("export default { async fetch() { return new Response('ok') } };\n")
	plan.TokenVerifierContentSHA256 = realCloudLowerSHA256(content)
	bindingsSHA, err := validateRealCloudCloudflareVerifierBindings(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan.TokenVerifierBindingsSHA256 = bindingsSHA
	for _, test := range []struct {
		name, usageModel string
		wantError        bool
	}{
		{name: "closed verifier settings", usageModel: "standard"},
		{name: "unbound verifier rejected", usageModel: "unbound", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := make(map[string]int)
			base := "/client/v4/accounts/" + plan.AccountID + "/workers/scripts/" + plan.TokenVerifierService
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests[request.Method+" "+request.URL.Path]++
				writer.Header().Set("Content-Type", "application/json")
				writeEnvelope := func(result any) {
					_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result})
				}
				switch request.URL.Path {
				case base + "/deployments":
					writeEnvelope(map[string]any{"deployments": []map[string]any{{
						"id": "bootstrap-verifier-deployment", "created_on": "2026-07-17T00:00:00Z", "source": "api", "strategy": "percentage",
						"versions": []map[string]any{{"percentage": 100, "version_id": "bootstrap-verifier-version"}},
					}}})
				case base + "/versions/bootstrap-verifier-version":
					writeEnvelope(map[string]any{"id": "bootstrap-verifier-version", "resources": map[string]any{
						"script": map[string]any{"etag": "bootstrap-verifier-etag"}, "bindings": []any{},
						"script_runtime": map[string]any{
							"compatibility_date": plan.TokenVerifierCompatibilityDate, "compatibility_flags": plan.TokenVerifierCompatibilityFlags,
							"limits": map[string]any{"cpu_ms": 0}, "migration_tag": "", "usage_model": "standard",
						},
					}})
				case base + "/content/v2":
					writer.Header().Set("Content-Type", "application/javascript")
					_, _ = writer.Write(content)
				case base + "/settings":
					writeEnvelope(map[string]any{
						"annotations": map[string]any{}, "bindings": []any{}, "cache_options": map[string]any{"enabled": false, "cross_version_cache": false},
						"compatibility_date": plan.TokenVerifierCompatibilityDate, "compatibility_flags": plan.TokenVerifierCompatibilityFlags,
						"limits": map[string]any{"cpu_ms": 0, "subrequests": 0}, "placement": map[string]any{}, "usage_model": test.usageModel,
						"logpush": false, "observability": map[string]any{"enabled": false,
							"logs":   map[string]any{"enabled": false, "invocation_logs": false, "destinations": []any{}, "persist": false},
							"traces": map[string]any{"enabled": false, "destinations": []any{}, "persist": false}},
						"tags": []any{}, "tail_consumers": []any{},
					})
				case base + "/subdomain":
					writeEnvelope(map[string]any{"enabled": false, "previews_enabled": false})
				default:
					t.Errorf("unexpected verifier inspect request %s", request.URL.Path)
					writer.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			control, err := newRealCloudCloudflareSDKBootstrapControl("bootstrap-verifier-token", server.URL+"/client/v4", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			state, inspectErr := control.Inspect(t.Context(), plan, "verifier")
			if test.wantError {
				if inspectErr == nil {
					t.Fatal("unsafe verifier runtime settings were accepted")
				}
				return
			}
			if inspectErr != nil {
				t.Fatal(inspectErr)
			}
			if err := validateRealCloudCloudflareBootstrapWorkerState("verifier", state, plan, runID, true); err != nil {
				t.Fatal(err)
			}
			if requests["GET "+base+"/settings"] != 2 || requests["GET "+base+"/subdomain"] != 2 || requests["GET "+base+"/deployments"] != 3 {
				t.Fatalf("verifier inspect did not repeat security observations: %v", requests)
			}
		})
	}
}

func TestRealCloudCloudflareBootstrapReceiptIsPrivateAndSealed(t *testing.T) {
	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	planBody, _ := json.Marshal(plan)
	planSHA := realCloudLowerSHA256(planBody)
	fake := newFakeRealCloudCloudflareBootstrapControl(plan)
	receipt, err := applyRealCloudCloudflareBootstrap(t.Context(), fake, resource, plan, planSHA, "20260717T120000Z-receipt")
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "bootstrap.json")
	writeRealCloudCloudflareBootstrapReceipt(t, path, receipt)
	loaded := readRealCloudCloudflareBootstrapReceipt(t, path)
	if err := validateRealCloudCloudflareBootstrapReceipt(loaded, resource, plan, planSHA, "apply", receipt.RunID); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("Cloudflare bootstrap receipt artifact is unsafe path=%s mode=%v err=%v", path, info, err)
	}
	if _, err := os.Lstat(path + ".seal"); !os.IsNotExist(err) {
		t.Fatal("Cloudflare bootstrap receipt unexpectedly used a crash-prone second seal file")
	}
}
