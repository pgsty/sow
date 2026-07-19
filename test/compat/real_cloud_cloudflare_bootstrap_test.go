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
	realCloudCloudflareBootstrapReceiptSchema  = "sow-real-cloud-cloudflare-bootstrap-receipt/v1"
	realCloudCloudflareBootstrapEnvelopeSchema = "sow-real-cloud-cloudflare-bootstrap-receipt-envelope/v1"
	realCloudCloudflareBootstrapLeaseSchema    = "sow-real-cloud-cloudflare-bootstrap-lease/v1"
	realCloudCloudflareLeaseRecoverySchema     = "sow-real-cloud-cloudflare-bootstrap-lease-recovery/v1"
	realCloudCloudflareBootstrapLeaseTTL       = 5 * time.Minute
	realCloudCloudflareMutationTimeout         = realCloudCloudflareBootstrapLeaseTTL / 3
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
	Schema     string `json:"schema"`
	RunID      string `json:"run_id"`
	Mode       string `json:"mode"`
	PlanSHA256 string `json:"plan_sha256"`
	AccountID  string `json:"account_id"`
	ZoneID     string `json:"zone_id"`
	Holder     string `json:"holder"`
	AcquiredAt string `json:"acquired_at"`
	ExpiresAt  string `json:"expires_at"`
}

type realCloudCloudflareBootstrapLeaseStore interface {
	R2GetControl(context.Context, string) (publish.ControlObject, error)
	R2ListObjectsV2(context.Context, string) (publish.ObjectListPage, error)
	R2Put(context.Context, string, io.Reader, int64, string, publish.R2PutCondition) (string, error)
	R2Delete(context.Context, string, string) error
}

type realCloudCloudflareBootstrapHeldLease struct {
	store realCloudCloudflareBootstrapLeaseStore
	key   string
	lease realCloudCloudflareBootstrapLease
	etag  string
}

type realCloudCloudflareBootstrapLeaseRecoveryReceipt struct {
	Schema            string `json:"schema"`
	RunID             string `json:"run_id"`
	PlanSHA256        string `json:"plan_sha256"`
	AccountID         string `json:"account_id"`
	ZoneID            string `json:"zone_id"`
	RecoveredLeaseRun string `json:"recovered_lease_run"`
	RecoveredMode     string `json:"recovered_mode"`
	LeaseHolderSHA256 string `json:"lease_holder_sha256"`
	LeaseExpiredAt    string `json:"lease_expired_at"`
	RecoveredAt       string `json:"recovered_at"`
}

type realCloudCloudflareSDKBootstrapControl struct {
	client *cloudflareapi.Client
}

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

func newRealCloudCloudflareSDKBootstrapControl(apiToken, baseURL string, client *http.Client) (*realCloudCloudflareSDKBootstrapControl, error) {
	if strings.TrimSpace(apiToken) == "" || apiToken != strings.TrimSpace(apiToken) {
		return nil, errors.New("Cloudflare bootstrap API token is empty or non-canonical")
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
	return &realCloudCloudflareSDKBootstrapControl{client: cloudflareapi.NewClient(
		option.WithBaseURL(strings.TrimSuffix(canonical, "/")+"/"), option.WithAPIToken(apiToken),
		option.WithHTTPClient(client), option.WithMaxRetries(0),
	)}, nil
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
	workerPager := control.client.Workers.Scripts.ListAutoPaging(ctx, workers.ScriptListParams{AccountID: cloudflareapi.F(plan.AccountID)})
	for workerPager.Next() {
		if workerPager.Index() > realCloudProviderMaxInventoryItems {
			return inventory, errors.New("Cloudflare Worker inventory exceeds the safety bound")
		}
		worker := workerPager.Current()
		inventory.Workers = append(inventory.Workers, worker.ID)
		if worker.ID == plan.AuthScript || worker.ID == plan.OriginScript || worker.ID == plan.TokenVerifierService {
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
		script, expectedSHA = plan.TokenVerifierService, plan.TokenVerifierContentSHA256
		runtimeContract = realCloudCloudflareWorkerRuntimeContract{CompatibilityDate: plan.TokenVerifierCompatibilityDate, CompatibilityFlags: append([]string(nil), plan.TokenVerifierCompatibilityFlags...)}
	default:
		return state, errors.New("unknown Cloudflare bootstrap Worker role")
	}
	evidence, err := collectRealCloudCloudflareActiveWorker(ctx, control.client, plan.AccountID, script, repositoryBundle, expectedSHA, runtimeContract, false)
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
		expectedDate, expectedFlags = plan.TokenVerifierCompatibilityDate, plan.TokenVerifierCompatibilityFlags
	}
	if settings.CompatibilityDate != expectedDate || !equalRealCloudStrings(settings.CompatibilityFlags, expectedFlags) ||
		settings.Logpush || settings.CacheOptions.Enabled || settings.CacheOptions.CrossVersionCache ||
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
		ExposureDisabled: !exposure.Enabled && !exposure.PreviewsEnabled,
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

func realCloudCloudflareBootstrapLeaseKey(planSHA string) (string, error) {
	if !validRealCloudLowerSHA256(planSHA) {
		return "", errors.New("Cloudflare bootstrap lease plan digest is invalid")
	}
	return ".sow/bootstrap/leases/" + planSHA + ".json", nil
}

func newRealCloudCloudflareBootstrapLeaseHolder() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", errors.New("generate Cloudflare bootstrap lease holder")
	}
	return fmt.Sprintf("%x", nonce[:]), nil
}

func encodeRealCloudCloudflareBootstrapLease(lease realCloudCloudflareBootstrapLease) ([]byte, error) {
	if lease.Schema != realCloudCloudflareBootstrapLeaseSchema || !validRealCloudRunID(lease.RunID) ||
		lease.Mode != "apply" && lease.Mode != "rollback" || !validRealCloudLowerSHA256(lease.PlanSHA256) ||
		!validRealCloudProviderIdentifier(lease.AccountID, 128) || !validRealCloudProviderIdentifier(lease.ZoneID, 128) ||
		!validRealCloudLowerSHA256(lease.Holder) {
		return nil, errors.New("Cloudflare bootstrap lease identity is invalid")
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

func acquireRealCloudCloudflareBootstrapLease(ctx context.Context, store realCloudCloudflareBootstrapLeaseStore, plan realCloudCloudflareBootstrapPlan, planSHA, runID, mode, holder string, now time.Time) (*realCloudCloudflareBootstrapHeldLease, error) {
	if store == nil || planSHA != realCloudCloudflareBootstrapPlanSHA(plan) || !validRealCloudRunID(runID) ||
		mode != "apply" && mode != "rollback" || !validRealCloudLowerSHA256(holder) {
		return nil, errors.New("Cloudflare bootstrap lease acquisition identity is invalid")
	}
	key, err := realCloudCloudflareBootstrapLeaseKey(planSHA)
	if err != nil {
		return nil, err
	}
	now = now.UTC()
	lease := realCloudCloudflareBootstrapLease{
		Schema: realCloudCloudflareBootstrapLeaseSchema, RunID: runID, Mode: mode, PlanSHA256: planSHA,
		AccountID: plan.AccountID, ZoneID: plan.ZoneID, Holder: holder,
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
	existing, err := decodeRealCloudCloudflareBootstrapLease(observed.Body)
	clearRealCloudBytes(observed.Body)
	if err != nil || existing.PlanSHA256 != planSHA || existing.AccountID != plan.AccountID || existing.ZoneID != plan.ZoneID {
		return nil, errors.New("Cloudflare bootstrap refuses an invalid or foreign lease")
	}
	expires, _ := time.Parse(time.RFC3339Nano, existing.ExpiresAt)
	if !now.After(expires) {
		return nil, errors.New("Cloudflare bootstrap is leased by another live execution")
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
	if decodeErr != nil || decoded != held.lease || !bytes.Equal(observed.Body, expectedBody) {
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
	if err != nil || existing != held.lease {
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
	if err != nil || existing != held.lease {
		return errors.New("Cloudflare bootstrap lease bytes changed before release")
	}
	if err := held.store.R2Delete(ctx, held.key, held.etag); err != nil {
		return fmt.Errorf("release Cloudflare bootstrap lease: %w", err)
	}
	held.etag = ""
	return nil
}

func recoverExpiredRealCloudCloudflareBootstrapLease(ctx context.Context, store realCloudCloudflareBootstrapLeaseStore, plan realCloudCloudflareBootstrapPlan, planSHA string, now time.Time) (realCloudCloudflareBootstrapLease, error) {
	var recovered realCloudCloudflareBootstrapLease
	if store == nil || planSHA != realCloudCloudflareBootstrapPlanSHA(plan) {
		return recovered, errors.New("Cloudflare bootstrap lease recovery identity is invalid")
	}
	key, err := realCloudCloudflareBootstrapLeaseKey(planSHA)
	if err != nil {
		return recovered, err
	}
	observed, err := store.R2GetControl(ctx, key)
	if err != nil || !observed.Exists || !validRealCloudProviderETag(observed.ETag) {
		return recovered, errors.New("Cloudflare bootstrap recovery found no exact lease entity")
	}
	recovered, err = decodeRealCloudCloudflareBootstrapLease(observed.Body)
	clearRealCloudBytes(observed.Body)
	if err != nil || recovered.PlanSHA256 != planSHA || recovered.AccountID != plan.AccountID || recovered.ZoneID != plan.ZoneID {
		return realCloudCloudflareBootstrapLease{}, errors.New("Cloudflare bootstrap recovery refuses an invalid or foreign lease")
	}
	expires, _ := time.Parse(time.RFC3339Nano, recovered.ExpiresAt)
	if !now.UTC().After(expires) {
		return realCloudCloudflareBootstrapLease{}, errors.New("Cloudflare bootstrap recovery refuses a live lease")
	}
	if err := store.R2Delete(ctx, key, observed.ETag); err != nil {
		return realCloudCloudflareBootstrapLease{}, fmt.Errorf("delete expired Cloudflare bootstrap lease by compare-and-delete: %w", err)
	}
	after, err := store.R2GetControl(ctx, key)
	if err != nil && !errors.Is(err, publish.ErrNotFound) || err == nil && after.Exists {
		clearRealCloudBytes(after.Body)
		return realCloudCloudflareBootstrapLease{}, errors.New("expired Cloudflare bootstrap lease remains after recovery")
	}
	clearRealCloudBytes(after.Body)
	return recovered, nil
}

func validateRealCloudCloudflareBootstrapLeaseRecoveryReceipt(receipt realCloudCloudflareBootstrapLeaseRecoveryReceipt, plan realCloudCloudflareBootstrapPlan, planSHA, runID string) error {
	if receipt.Schema != realCloudCloudflareLeaseRecoverySchema || receipt.RunID != runID || receipt.PlanSHA256 != planSHA ||
		receipt.AccountID != plan.AccountID || receipt.ZoneID != plan.ZoneID || !validRealCloudRunID(receipt.RecoveredLeaseRun) ||
		receipt.RecoveredMode != "apply" && receipt.RecoveredMode != "rollback" || !validRealCloudLowerSHA256(receipt.LeaseHolderSHA256) {
		return errors.New("Cloudflare bootstrap lease recovery receipt identity is invalid")
	}
	expired, err := time.Parse(time.RFC3339Nano, receipt.LeaseExpiredAt)
	if err != nil {
		return errors.New("Cloudflare bootstrap lease recovery expiry is invalid")
	}
	recovered, err := time.Parse(time.RFC3339Nano, receipt.RecoveredAt)
	if err != nil || recovered.Before(expired) {
		return errors.New("Cloudflare bootstrap lease recovery time is invalid")
	}
	return nil
}

func validateRealCloudCloudflareBootstrapAuthBindings(bindings []workers.ScriptVersionGetResponseResourcesBinding, plan realCloudCloudflareBootstrapPlan) (string, error) {
	wantedVariables := make(map[string]string, len(plan.EdgeContract.Variables))
	for name, value := range plan.EdgeContract.Variables {
		wantedVariables[name] = value
	}
	wantedServices := map[string]string{"ORIGIN": plan.OriginScript, "TOKEN_VERIFIER": plan.TokenVerifierService}
	seen := make(map[string]struct{}, len(bindings))
	rows := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		if _, duplicate := seen[binding.Name]; duplicate || !validRealCloudProviderSecretName(binding.Name) {
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
			if !found || binding.Service != wanted || binding.Environment != plan.TokenVerifierEnvironment && binding.Name == "TOKEN_VERIFIER" ||
				binding.Environment != "" && binding.Name == "ORIGIN" || binding.Entrypoint != "" {
				return "", errors.New("Cloudflare bootstrap auth Worker service binding differs from the plan")
			}
			delete(wantedServices, binding.Name)
			rows = append(rows, strings.Join([]string{binding.Name, string(binding.Type), binding.Service, binding.Environment}, "\x00"))
		default:
			return "", errors.New("Cloudflare bootstrap auth Worker has an excessive capability binding")
		}
	}
	if len(wantedVariables) != 0 || len(wantedServices) != 0 {
		return "", errors.New("Cloudflare bootstrap auth Worker lacks a planned binding")
	}
	sort.Strings(rows)
	body, _ := json.Marshal(rows)
	return realCloudLowerSHA256(body), nil
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
		bindings = append(bindings,
			workers.ScriptUpdateParamsMetadataBindingsWorkersBindingKindService{
				Name: cloudflareapi.F("ORIGIN"), Service: cloudflareapi.F(plan.OriginScript),
				Type: cloudflareapi.F(workers.ScriptUpdateParamsMetadataBindingsWorkersBindingKindServiceTypeService),
			},
			workers.ScriptUpdateParamsMetadataBindingsWorkersBindingKindService{
				Name: cloudflareapi.F("TOKEN_VERIFIER"), Service: cloudflareapi.F(plan.TokenVerifierService),
				Environment: cloudflareapi.F(plan.TokenVerifierEnvironment),
				Type:        cloudflareapi.F(workers.ScriptUpdateParamsMetadataBindingsWorkersBindingKindServiceTypeService),
			},
		)
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
			Limits: cloudflareapi.F(workers.ScriptUpdateParamsMetadataLimits{
				CPUMs: cloudflareapi.F(int64(0)), Subrequests: cloudflareapi.F(int64(0)),
			}),
			Observability: cloudflareapi.F(workers.ScriptUpdateParamsMetadataObservability{
				Enabled: cloudflareapi.F(false),
			}),
			Tags: cloudflareapi.F([]string{}), TailConsumers: cloudflareapi.F([]workers.ConsumerScriptParam{}),
			UsageModel: cloudflareapi.F(workers.ScriptUpdateParamsMetadataUsageModelStandard),
		}),
		Files: cloudflareapi.F([]io.Reader{file}),
	}, option.WithHeader("If-None-Match", "*"))
	if err != nil || response == nil || response.ID != "" && response.ID != script {
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
	wantedWorkers := map[string]bool{plan.AuthScript: false, plan.OriginScript: false, plan.TokenVerifierService: false}
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
	if !wantedWorkers[plan.TokenVerifierService] {
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
		relevantScript := route.Script == plan.AuthScript || route.Script == plan.OriginScript || route.Script == plan.TokenVerifierService
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
		strings.Join([]string{"ORIGIN", string(workers.ScriptVersionGetResponseResourcesBindingsTypeService), plan.OriginScript, ""}, "\x00"),
		strings.Join([]string{"TOKEN_VERIFIER", string(workers.ScriptVersionGetResponseResourcesBindingsTypeService), plan.TokenVerifierService, plan.TokenVerifierEnvironment}, "\x00"),
	)
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
	states := make(map[string]realCloudCloudflareBootstrapWorkerState, 3)
	for _, role := range []string{"verifier", "origin", "auth"} {
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
		if err != nil || validateRealCloudCloudflareBootstrapWorkerState(role, state, plan, runID, true) != nil {
			return receipt, fmt.Errorf("verify Cloudflare bootstrap %s Worker after reconciliation", role)
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
	wantedWorkers := []realCloudCloudflareBootstrapReceiptWorker{receipt.Auth, receipt.Origin, receipt.Verifier}
	for _, worker := range wantedWorkers {
		if !validRealCloudProviderIdentifier(worker.Script, 128) || !validRealCloudProviderIdentifier(worker.DeploymentID, 128) ||
			!validRealCloudProviderIdentifier(worker.VersionID, 128) || !validRealCloudProviderETag(worker.VersionETag) ||
			!validRealCloudLowerSHA256(worker.ContentSHA256) || !validRealCloudLowerSHA256(worker.BindingsSHA256) {
			return errors.New("Cloudflare bootstrap receipt Worker evidence is invalid")
		}
	}
	if receipt.Auth.Script != plan.AuthScript || receipt.Origin.Script != plan.OriginScript || receipt.Verifier.Script != plan.TokenVerifierService ||
		receipt.Auth.ContentSHA256 != plan.AuthBundle.SHA256 || receipt.Origin.ContentSHA256 != plan.OriginBundle.SHA256 ||
		receipt.Verifier.ContentSHA256 != plan.TokenVerifierContentSHA256 || receipt.Verifier.BindingsSHA256 != plan.TokenVerifierBindingsSHA256 ||
		receipt.Auth.BindingsSHA256 != realCloudCloudflareBootstrapExpectedAuthBindingsSHA(plan) ||
		receipt.Origin.BindingsSHA256 != realCloudCloudflareBootstrapExpectedOriginBindingsSHA(plan) {
		return errors.New("Cloudflare bootstrap receipt Worker closure differs from the plan")
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
	if _, exists := states["verifier"]; !exists {
		return rollback, errors.New("Cloudflare bootstrap rollback refuses an absent token verifier")
	}
	if !realCloudCloudflareBootstrapStateMatchesReceipt(states["verifier"], applyReceipt.Verifier) {
		return rollback, errors.New("Cloudflare bootstrap rollback token verifier differs from the sealed apply receipt")
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
	verifier, err := control.Inspect(ctx, plan, "verifier")
	if err != nil || validateRealCloudCloudflareBootstrapWorkerState("verifier", verifier, plan, runID, true) != nil ||
		!realCloudCloudflareBootstrapStateMatchesReceipt(verifier, applyReceipt.Verifier) {
		return rollback, errors.New("Cloudflare bootstrap rollback changed or exposed the token verifier")
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
	verifier, err := control.Inspect(ctx, plan, "verifier")
	if err != nil || validateRealCloudCloudflareBootstrapWorkerState("verifier", verifier, plan, runID, true) != nil ||
		!realCloudCloudflareBootstrapStateMatchesReceipt(verifier, applyReceipt.Verifier) {
		return errors.New("Cloudflare bootstrap rollback closure changed or exposed the token verifier")
	}
	return nil
}

// TestRealCloudCloudflareBootstrap is the only live mutation entrypoint for
// first deployment of the reviewed Cloudflare auth/origin bundles. TestMain
// admits it only after the independent readiness and bootstrap registries plus
// the exact mutation phrase pass. Apply and rollback use one conditional R2
// lease object under .sow/bootstrap/leases and remove it only after a durable
// receipt. They never alter repository payload objects, DNS, custom domains,
// the token-verifier deployment, or unrelated Worker routes.
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
			body, readErr := readRealCloudPrivateCanonicalFile(recoveryPath, 16<<10)
			if readErr != nil {
				t.Fatal(readErr)
			}
			defer clearRealCloudBytes(body)
			var existing realCloudCloudflareBootstrapLeaseRecoveryReceipt
			if err := decodeRealCloudCanonicalJSONFile(body, &existing); err != nil || validateRealCloudCloudflareBootstrapLeaseRecoveryReceipt(existing, plan, planSHA, runID) != nil {
				t.Fatalf("existing Cloudflare bootstrap lease recovery receipt is invalid: %v", err)
			}
			key, _ := realCloudCloudflareBootstrapLeaseKey(planSHA)
			observed, getErr := leaseStore.R2GetControl(t.Context(), key)
			if getErr != nil && !errors.Is(getErr, publish.ErrNotFound) || getErr == nil && observed.Exists {
				clearRealCloudBytes(observed.Body)
				t.Fatalf("recovered Cloudflare bootstrap lease reappeared: %v", getErr)
			}
			clearRealCloudBytes(observed.Body)
			t.Logf("Cloudflare bootstrap expired lease recovery is already durable receipt=%s", recoveryPath)
			return
		} else if !os.IsNotExist(statErr) {
			t.Fatalf("inspect Cloudflare bootstrap lease recovery receipt: %v", statErr)
		}
		recovered, recoverErr := recoverExpiredRealCloudCloudflareBootstrapLease(t.Context(), leaseStore, plan, planSHA, time.Now())
		if recoverErr != nil {
			assertNoRealCloudSecret(t, "Cloudflare bootstrap lease recovery error", []byte(recoverErr.Error()), secretFragments)
			t.Fatalf("Cloudflare bootstrap expired lease recovery failed: %v", recoverErr)
		}
		recoveryReceipt := realCloudCloudflareBootstrapLeaseRecoveryReceipt{
			Schema: realCloudCloudflareLeaseRecoverySchema, RunID: runID, PlanSHA256: planSHA, AccountID: plan.AccountID, ZoneID: plan.ZoneID,
			RecoveredLeaseRun: recovered.RunID, RecoveredMode: recovered.Mode, LeaseHolderSHA256: realCloudLowerSHA256([]byte(recovered.Holder)),
			LeaseExpiredAt: recovered.ExpiresAt, RecoveredAt: time.Now().UTC().Format(time.RFC3339Nano),
		}
		if err := validateRealCloudCloudflareBootstrapLeaseRecoveryReceipt(recoveryReceipt, plan, planSHA, runID); err != nil {
			t.Fatal(err)
		}
		writeRealCloudExclusiveJSON(t, recoveryPath, recoveryReceipt)
		t.Logf("Cloudflare bootstrap expired lease recovered receipt=%s", recoveryPath)
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
		receipt, applyErr := applyRealCloudCloudflareBootstrap(t.Context(), leasedControl, resource, plan, planSHA, runID)
		if applyErr != nil {
			assertNoRealCloudSecret(t, "Cloudflare bootstrap apply error", []byte(applyErr.Error()), secretFragments)
			t.Fatalf("Cloudflare bootstrap apply failed: %v", applyErr)
		}
		if err := validateRealCloudCloudflareBootstrapReceipt(receipt, resource, plan, planSHA, "apply", runID); err != nil {
			t.Fatal(err)
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
	key          string
	body         []byte
	etag         string
	version      int
	extraObjects []publish.ListedObject
	listPages    map[string]publish.ObjectListPage
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
	if condition.IfNoneMatch && store.key != "" {
		return "", publish.ErrAlreadyExists
	}
	if condition.IfMatch != "" && (store.key != key || store.etag != condition.IfMatch) {
		return "", publish.ErrConflict
	}
	store.version++
	store.key, store.body, store.etag = key, append([]byte(nil), body...), fmt.Sprintf("\"lease-%d\"", store.version)
	return store.etag, nil
}

func (store *fakeRealCloudCloudflareBootstrapLeaseStore) R2Delete(_ context.Context, key, ifMatch string) error {
	if store.key != key {
		return publish.ErrNotFound
	}
	if store.etag != ifMatch {
		return publish.ErrConflict
	}
	store.key, store.body, store.etag = "", nil, ""
	return nil
}

func newFakeRealCloudCloudflareBootstrapControl(plan realCloudCloudflareBootstrapPlan) *fakeRealCloudCloudflareBootstrapControl {
	fake := &fakeRealCloudCloudflareBootstrapControl{
		workers: make(map[string]realCloudCloudflareBootstrapWorkerState), routes: make(map[string]realCloudCloudflareBootstrapInventoryRoute),
		fail: make(map[string]int), calls: make(map[string]int), nextID: 1,
		omitWorkerInventory: make(map[string]bool), omitRouteInventory: make(map[string]bool),
		errorAfterRouteDelete: make(map[string]int), errorAfterScriptDelete: make(map[string]int),
	}
	fake.workers[plan.TokenVerifierService] = fakeRealCloudCloudflareBootstrapWorkerState(plan, "verifier", "20260717T000000Z-fixture", true)
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
	if err := first.release(t.Context()); err != nil || store.key != "" {
		t.Fatalf("lease release did not conditionally remove the exact entity err=%v", err)
	}

	expired, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, "20260717T120000Z-expired-lease", "apply", strings.Repeat("c", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, "20260717T121000Z-recovery-lease", "rollback", strings.Repeat("d", 64), now.Add(realCloudCloudflareBootstrapLeaseTTL+time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if replacement.etag == expired.etag || replacement.lease.Holder == expired.lease.Holder {
		t.Fatal("expired Cloudflare bootstrap lease was not replaced by a new compare-and-set entity")
	}
	if err := expired.release(t.Context()); err == nil {
		t.Fatal("stale lease holder released the replacement lease")
	}
	if err := replacement.release(t.Context()); err != nil {
		t.Fatal(err)
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
		if err := held.release(t.Context()); err != nil || store.key != "" {
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
	store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
	held, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, "20260717T120000Z-crashed-lease", "apply", strings.Repeat("f", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recoverExpiredRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, now.Add(time.Minute)); err == nil {
		t.Fatal("lease recovery deleted a live lease")
	}
	recovered, err := recoverExpiredRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA, now.Add(realCloudCloudflareBootstrapLeaseTTL+time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if recovered != held.lease || store.key != "" {
		t.Fatal("expired lease recovery did not remove exactly the observed lease")
	}
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
						wanted["ORIGIN"] = "service\x00" + plan.OriginScript + "\x00"
						wanted["TOKEN_VERIFIER"] = "service\x00" + plan.TokenVerifierService + "\x00" + plan.TokenVerifierEnvironment
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
		map[string]any{"name": "ORIGIN", "type": "service", "service": plan.OriginScript, "environment": ""},
		map[string]any{"name": "TOKEN_VERIFIER", "type": "service", "service": plan.TokenVerifierService, "environment": plan.TokenVerifierEnvironment},
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
						"script_runtime": map[string]any{"compatibility_date": plan.CompatibilityDate, "compatibility_flags": plan.CompatibilityFlags},
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
						"script_runtime": map[string]any{"compatibility_date": plan.TokenVerifierCompatibilityDate, "compatibility_flags": plan.TokenVerifierCompatibilityFlags},
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
