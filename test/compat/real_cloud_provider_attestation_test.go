package compat_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cloudflareapi "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/logpush"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/cloudflare-go/v7/packages/pagination"
	"github.com/cloudflare/cloudflare-go/v7/workers"
	"github.com/cloudflare/cloudflare-go/v7/zones"
	sowconfig "github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/publish"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	teo "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/teo/v20220901"
)

const (
	realCloudProviderAttestationEnv           = "SOW_REAL_CLOUD_PROVIDER_ATTESTATION_JSON"
	realCloudProviderLogStorageCredentialCF   = "SOW_REAL_CF_LOG_STORAGE_JSON"
	realCloudProviderLogStorageCredentialCOS  = "SOW_REAL_COS_LOG_STORAGE_JSON"
	realCloudProviderLogWriterCredentialCF    = "SOW_REAL_CF_LOG_WRITER_JSON"
	realCloudProviderLogWriterCredentialCOS   = "SOW_REAL_COS_LOG_WRITER_JSON"
	realCloudProviderLogControlCredentialCF   = "SOW_REAL_CF_LOG_CONTROL_JSON"
	realCloudProviderAttestationSchema        = "sow-real-cloud-provider-attestation-config/v3"
	realCloudProviderCollectorSchema          = "sow-real-cloud-provider-raw-attestation/v3"
	realCloudProviderCollectorSource          = "test/compat/real_cloud_provider_attestation_test.go"
	realCloudProviderDeploymentRegistryPath   = "test/compat/testdata/real_cloud_nonproduction_provider_deployment_registry.json"
	realCloudProviderDeploymentRegistrySchema = "sow-real-cloud-pinned-provider-deployment-registry/v1"
	realCloudProviderDeploymentEntrySchema    = "sow-real-cloud-pinned-provider-deployment/v1"
	realCloudProviderDeploymentIdentitySchema = "sow-real-cloud-provider-deployment-identity/v3"
	realCloudProviderDeploymentRegistrySHA256 = "3eac7304de5472c532fbfcd93f93cc69a5baa778c9c851280e692e0f9d633e52"
	realCloudProviderMaxRawBytes              = 8 << 20
	realCloudProviderMaxContentBytes          = 2 << 20
	realCloudProviderMaxInventoryItems        = 10_000
	realCloudProviderLogSinkLeaseSchema       = "sow-real-cloud-provider-log-sink-lease/v1"
	realCloudProviderLogSinkLeaseTTL          = 5 * time.Minute
)

var (
	realCloudCloudflareRawFields = []string{
		"CacheCacheStatus", "ClientRequestURI", "EdgeColoCode", "EdgeColoID", "EdgeStartTimestamp", "ParentRayID", "RayID",
	}
	realCloudEdgeOneRawFields = []string{
		"EdgeCacheStatus", "EdgeFunctionSubrequest", "EdgeServerID", "EdgeServerIP", "EdgeSeverRegion", "ParentRequestID",
		"RequestHost", "RequestID", "RequestScheme", "RequestTime", "RequestUrl", "RequestUrlQueryString",
	}
)

// realCloudProviderAttestationConfig contains resource identities only. Every
// credential remains in the existing secret-only env JSON. The exact zone,
// buckets, endpoints, and CDN hosts are independently bound by the compiled
// SHA-pinned non-production registry before this value is decoded.
type realCloudProviderAttestationConfig struct {
	Schema              string                                `json:"schema"`
	ProductConfigSHA256 string                                `json:"product_config_sha256"`
	Cloudflare          realCloudCloudflareAttestationConfig  `json:"cloudflare"`
	EdgeOne             realCloudEdgeOneAttestationConfig     `json:"edgeone"`
	Runtime             realCloudEdgeRuntimeAttestationConfig `json:"runtime"`
}

type realCloudEdgeRuntimeAttestationConfig struct {
	TokenVerifier                        string   `json:"token_verifier"`
	PublicPrefixes                       []string `json:"public_prefixes"`
	PublicKeys                           []string `json:"public_keys"`
	EdgeOneTokenVerifierURL              string   `json:"edgeone_token_verifier_url"`
	EdgeOneTokenVerifierDeploymentSHA256 string   `json:"edgeone_token_verifier_deployment_sha256"`
	CloudflareSecretNames                []string `json:"cloudflare_secret_names"`
	EdgeOneSecretNames                   []string `json:"edgeone_secret_names"`
}

type realCloudCloudflareAttestationConfig struct {
	AccountID                   string                                   `json:"account_id"`
	ZoneID                      string                                   `json:"zone_id"`
	LogpushJobID                int64                                    `json:"logpush_job_id"`
	WorkerScript                string                                   `json:"worker_script"`
	WorkerRuntime               realCloudCloudflareWorkerRuntimeContract `json:"worker_runtime"`
	OriginWorkerScript          string                                   `json:"origin_worker_script"`
	OriginWorkerEnvironment     string                                   `json:"origin_worker_environment"`
	OriginWorkerRuntime         realCloudCloudflareWorkerRuntimeContract `json:"origin_worker_runtime"`
	TokenVerifierService        string                                   `json:"token_verifier_service"`
	TokenVerifierEnvironment    string                                   `json:"token_verifier_environment"`
	TokenVerifierRuntime        realCloudCloudflareWorkerRuntimeContract `json:"token_verifier_runtime"`
	TokenVerifierContentSHA256  string                                   `json:"token_verifier_content_sha256"`
	TokenVerifierBindingsSHA256 string                                   `json:"token_verifier_bindings_sha256"`
	RawReaderAccessKeySHA256    string                                   `json:"raw_reader_access_key_sha256"`
	RawWriterAccessKeySHA256    string                                   `json:"raw_writer_access_key_sha256"`
	LogControlAccessKeySHA256   string                                   `json:"log_control_access_key_sha256"`
	RawBucket                   string                                   `json:"raw_bucket"`
	RawRoot                     string                                   `json:"raw_root"`
}

type realCloudCloudflareWorkerRuntimeContract struct {
	CompatibilityDate  string   `json:"compatibility_date"`
	CompatibilityFlags []string `json:"compatibility_flags"`
}

type realCloudEdgeOneAttestationConfig struct {
	ZoneID                   string `json:"zone_id"`
	RealtimeLogTaskID        string `json:"realtime_log_task_id"`
	RealtimeLogArea          string `json:"realtime_log_area"`
	FunctionID               string `json:"function_id"`
	FunctionDomainSHA256     string `json:"function_domain_sha256"`
	RawReaderAccessKeySHA256 string `json:"raw_reader_access_key_sha256"`
	RawWriterAccessKeySHA256 string `json:"raw_writer_access_key_sha256"`
	RawBucket                string `json:"raw_bucket"`
	RawRoot                  string `json:"raw_root"`
}

type realCloudPinnedProviderDeploymentRegistry struct {
	Schema      string                                           `json:"schema"`
	Deployments []realCloudPinnedProviderDeploymentRegistryEntry `json:"deployments"`
}

type realCloudPinnedProviderDeploymentRegistryEntry struct {
	Schema           string `json:"schema"`
	Purpose          string `json:"purpose"`
	ResourceSHA256   string `json:"resource_sha256"`
	DeploymentSHA256 string `json:"deployment_sha256"`
}

// realCloudProviderRawAttestation is deliberately URL- and secret-free. It is
// folded into the durable ProviderClosure after the raw provider bytes have
// been reconstructed into the joined-v3 request set. Raw API responses and raw
// log object bytes are never written by the collector.
type realCloudProviderRawAttestation struct {
	Schema                   string `json:"schema"`
	CollectorSourceSHA256    string `json:"collector_source_sha256"`
	CollectorBuildSHA256     string `json:"collector_build_sha256"`
	CollectorConfigSHA256    string `json:"collector_config_sha256"`
	ProductConfigSHA256      string `json:"product_config_sha256"`
	ProviderDeploymentSHA256 string `json:"provider_deployment_sha256"`
	RawJoinedSHA256          string `json:"raw_joined_sha256"`
	RedactedClosureSHA256    string `json:"redacted_closure_sha256"`
	RawRecords               int    `json:"raw_records"`

	CFAccountID                   string `json:"cf_account_id"`
	CFZoneID                      string `json:"cf_zone_id"`
	CFZoneIdentitySHA256          string `json:"cf_zone_identity_sha256"`
	CFLogpushJobID                int64  `json:"cf_logpush_job_id"`
	CFLogpushJobSHA256            string `json:"cf_logpush_job_sha256"`
	CFLogReaderIdentitySHA256     string `json:"cf_log_reader_identity_sha256"`
	CFLogWriterIdentitySHA256     string `json:"cf_log_writer_identity_sha256"`
	CFLogControlIdentitySHA256    string `json:"cf_log_control_identity_sha256"`
	CFRawObjectIdentitySHA256     string `json:"cf_raw_object_identity_sha256"`
	CFRawObjectETag               string `json:"cf_raw_object_etag"`
	CFRawObjectSHA256             string `json:"cf_raw_object_sha256"`
	CFRawObjects                  int    `json:"cf_raw_objects"`
	CFWorkerScript                string `json:"cf_worker_script"`
	CFWorkerDeploymentID          string `json:"cf_worker_deployment_id"`
	CFWorkerVersionID             string `json:"cf_worker_version_id"`
	CFWorkerVersionETag           string `json:"cf_worker_version_etag"`
	CFWorkerContentSHA256         string `json:"cf_worker_content_sha256"`
	CFWorkerBindingsSHA256        string `json:"cf_worker_bindings_sha256"`
	CFWorkerRuntimeSHA256         string `json:"cf_worker_runtime_sha256"`
	CFWorkerSecuritySHA256        string `json:"cf_worker_security_sha256"`
	CFWorkerRoutesSHA256          string `json:"cf_worker_routes_sha256"`
	CFWorkerInventorySHA256       string `json:"cf_worker_inventory_sha256"`
	CFOriginWorkerScript          string `json:"cf_origin_worker_script"`
	CFOriginDeploymentID          string `json:"cf_origin_deployment_id"`
	CFOriginVersionID             string `json:"cf_origin_version_id"`
	CFOriginVersionETag           string `json:"cf_origin_version_etag"`
	CFOriginContentSHA256         string `json:"cf_origin_content_sha256"`
	CFOriginBindingsSHA256        string `json:"cf_origin_bindings_sha256"`
	CFOriginSecuritySHA256        string `json:"cf_origin_security_sha256"`
	CFOriginExposureSHA256        string `json:"cf_origin_exposure_sha256"`
	CFTokenVerifierService        string `json:"cf_token_verifier_service"`
	CFTokenVerifierVersionID      string `json:"cf_token_verifier_version_id"`
	CFTokenVerifierVersionETag    string `json:"cf_token_verifier_version_etag"`
	CFTokenVerifierContentSHA256  string `json:"cf_token_verifier_content_sha256"`
	CFTokenVerifierBindingsSHA256 string `json:"cf_token_verifier_bindings_sha256"`
	CFTokenVerifierSecuritySHA256 string `json:"cf_token_verifier_security_sha256"`

	EdgeOneZoneID                        string `json:"edgeone_zone_id"`
	EdgeOneZoneIdentitySHA256            string `json:"edgeone_zone_identity_sha256"`
	EdgeOneDomainsSHA256                 string `json:"edgeone_domains_sha256"`
	EdgeOneLogTaskID                     string `json:"edgeone_log_task_id"`
	EdgeOneLogArea                       string `json:"edgeone_log_area"`
	EdgeOneLogTaskSHA256                 string `json:"edgeone_log_task_sha256"`
	EdgeOneLogReaderIdentitySHA256       string `json:"edgeone_log_reader_identity_sha256"`
	EdgeOneLogWriterIdentitySHA256       string `json:"edgeone_log_writer_identity_sha256"`
	EdgeOneRawObjectIdentitySHA256       string `json:"edgeone_raw_object_identity_sha256"`
	EdgeOneRawObjectETag                 string `json:"edgeone_raw_object_etag"`
	EdgeOneRawObjectSHA256               string `json:"edgeone_raw_object_sha256"`
	EdgeOneRawObjects                    int    `json:"edgeone_raw_objects"`
	EdgeOneFunctionID                    string `json:"edgeone_function_id"`
	EdgeOneFunctionDomainSHA256          string `json:"edgeone_function_domain_sha256"`
	EdgeOneFunctionDomainBehaviorSHA256  string `json:"edgeone_function_domain_behavior_sha256"`
	EdgeOneFunctionContentSHA256         string `json:"edgeone_function_content_sha256"`
	EdgeOneFunctionComponentsSHA256      string `json:"edgeone_function_components_sha256"`
	EdgeOneFunctionReplicasSHA256        string `json:"edgeone_function_replicas_sha256"`
	EdgeOneFunctionRuntimeSHA256         string `json:"edgeone_function_runtime_sha256"`
	EdgeOneFunctionRulesSHA256           string `json:"edgeone_function_rules_sha256"`
	EdgeOneTokenVerifierDeploymentSHA256 string `json:"edgeone_token_verifier_deployment_sha256"`
}

type realCloudProviderCollectorEndpoints struct {
	CloudflareAPIURL        string
	EdgeOneAPIURL           string
	CFObjectBaseURL         string
	EOObjectBaseURL         string
	EOFunctionDomainBaseURL string
	HTTPClient              *http.Client
	AllowInsecure           bool
}

type realCloudProviderCollectorClients struct {
	cloudflare            *cloudflareapi.Client
	edgeOne               *teo.Client
	logSinkLeaseStore     realCloudCloudflareBootstrapLeaseStore
	openCF                func(context.Context, string) (publish.ObjectContent, error)
	openEO                func(context.Context, string) (publish.ObjectContent, error)
	listCF                func(context.Context, string, string) (publish.ObjectListPage, error)
	listEO                func(context.Context, string, string) (publish.ObjectListPage, error)
	probeEOFunctionDomain func(context.Context, string) (string, error)
}

type realCloudProviderLogSinkLease struct {
	Schema                   string `json:"schema"`
	RunID                    string `json:"run_id"`
	ProviderDeploymentSHA256 string `json:"provider_deployment_sha256"`
	AccountID                string `json:"account_id"`
	ZoneID                   string `json:"zone_id"`
	Holder                   string `json:"holder"`
	AcquiredAt               string `json:"acquired_at"`
	ExpiresAt                string `json:"expires_at"`
}

type realCloudProviderHeldLogSinkLease struct {
	store realCloudCloudflareBootstrapLeaseStore
	key   string
	lease realCloudProviderLogSinkLease
	etag  string
}

// validateRealCloudProviderAPIAttestedRawClosure is the only opt-in
// provider-facing entry point, and it accepts dedicated non-production
// resources only. Its ordering is a safety contract: exact environment parsing,
// vendor-family validation, and the repository SHA-pinned non-production gate
// all complete before provider config/credentials are parsed and before any
// SDK, client, transport, or request is constructed.
func validateRealCloudProviderAPIAttestedRawClosure(
	ctx context.Context,
	stages []realEdgeMultiPoPStageEvidence,
	operatorLogs []realEdgeProviderLog,
	forbidden []string,
) (realCloudProviderRawAttestation, error) {
	environment, err := realCloudEnvironmentFromLookup(os.Getenv)
	if err != nil {
		return realCloudProviderRawAttestation{}, fmt.Errorf("%w: provider environment is incomplete", errRealCloudProviderAPIAttestationRequired)
	}
	if err := validateRealCloudVendorEndpoints(environment); err != nil {
		return realCloudProviderRawAttestation{}, fmt.Errorf("%w: provider endpoint family is invalid", errRealCloudProviderAPIAttestationRequired)
	}
	if err := validateRealCloudDedicatedTestResources(environment, os.Getenv); err != nil {
		return realCloudProviderRawAttestation{}, fmt.Errorf("%w: exact pinned non-production registry gate rejected the resources", errRealCloudProviderAPIAttestationRequired)
	}

	configuration, configurationBody, err := decodeAndValidateRealCloudPinnedProviderDeployment(environment, os.Getenv)
	if err != nil {
		return realCloudProviderRawAttestation{}, fmt.Errorf("%w: administrator-pinned provider deployment gate rejected the config", errRealCloudProviderAPIAttestationRequired)
	}
	cfStorage, err := decodeRealCloudProviderSecret[realCloudStorageSecret](os.Getenv(realCloudProviderLogStorageCredentialCF))
	if err != nil {
		return realCloudProviderRawAttestation{}, fmt.Errorf("%w: Cloudflare raw-log read credential schema is invalid", errRealCloudProviderAPIAttestationRequired)
	}
	cfCDN, err := decodeRealCloudProviderSecret[realCloudCloudflareSecret](os.Getenv(realCloudCDNCredentialCF))
	if err != nil {
		return realCloudProviderRawAttestation{}, fmt.Errorf("%w: Cloudflare API credential schema is invalid", errRealCloudProviderAPIAttestationRequired)
	}
	eoStorage, err := decodeRealCloudProviderSecret[realCloudStorageSecret](os.Getenv(realCloudProviderLogStorageCredentialCOS))
	if err != nil {
		return realCloudProviderRawAttestation{}, fmt.Errorf("%w: EdgeOne raw-log read credential schema is invalid", errRealCloudProviderAPIAttestationRequired)
	}
	eoCDN, err := decodeRealCloudProviderSecret[realCloudTencentSecret](os.Getenv(realCloudCDNCredentialCOS))
	if err != nil {
		return realCloudProviderRawAttestation{}, fmt.Errorf("%w: EdgeOne API credential schema is invalid", errRealCloudProviderAPIAttestationRequired)
	}
	cfPublisherStorage, err := decodeRealCloudProviderSecret[realCloudStorageSecret](os.Getenv(realCloudStorageCredentialCF))
	if err != nil {
		return realCloudProviderRawAttestation{}, fmt.Errorf("%w: Cloudflare publisher storage credential schema is invalid", errRealCloudProviderAPIAttestationRequired)
	}
	teoPublisherStorage, err := decodeRealCloudProviderSecret[realCloudStorageSecret](os.Getenv(realCloudStorageCredentialCOS))
	if err != nil {
		return realCloudProviderRawAttestation{}, fmt.Errorf("%w: EdgeOne publisher storage credential schema is invalid", errRealCloudProviderAPIAttestationRequired)
	}
	if err := validateRealCloudProviderLogReaderIdentities(configuration, cfStorage, eoStorage, cfPublisherStorage, teoPublisherStorage); err != nil {
		return realCloudProviderRawAttestation{}, fmt.Errorf("%w: provider raw-log reader identity is not isolated", errRealCloudProviderAPIAttestationRequired)
	}

	endpoints := realCloudProviderCollectorEndpoints{
		CloudflareAPIURL: "https://api.cloudflare.com/client/v4",
		EdgeOneAPIURL:    "https://teo.tencentcloudapi.com",
		CFObjectBaseURL:  realCloudProviderBucketBaseURL(environment.CFR2Endpoint, configuration.Cloudflare.RawBucket),
		EOObjectBaseURL:  realCloudProviderBucketBaseURL(environment.COSEndpoint, configuration.EdgeOne.RawBucket),
		HTTPClient:       realCloudProviderHTTPClient(),
	}
	clients, err := newRealCloudProviderCollectorClients(environment, configuration, cfStorage, cfCDN, eoStorage, eoCDN, endpoints)
	if err != nil {
		return realCloudProviderRawAttestation{}, fmt.Errorf("%w: construct read-only provider collectors", errRealCloudProviderAPIAttestationRequired)
	}
	attestation, err := collectRealCloudProviderRawAttestationAfterGate(ctx, environment, configuration, configurationBody, stages, operatorLogs, forbidden, clients)
	if err != nil {
		return realCloudProviderRawAttestation{}, fmt.Errorf("%w: %v", errRealCloudProviderAPIAttestationRequired, err)
	}
	return attestation, nil
}

// prepareRealCloudProviderPerRunRawSinks is the executable setup path that
// moves both provider-owned exporters from the stable administrator-pinned
// raw_root to raw_root/<run-id>/. It is called only by the already destructive,
// explicitly opted-in non-production acceptance before any edge probe. A
// partial cross-provider failure is safe and replayable: probes do not start,
// and the next invocation writes the same exact per-run configuration.
func prepareRealCloudProviderPerRunRawSinks(ctx context.Context, environment realCloudEnvironment, runID string, getenv func(string) string) error {
	if !validRealCloudRunID(runID) {
		return errors.New("provider log setup requires the exact bound run ID")
	}
	if err := validateRealCloudVendorEndpoints(environment); err != nil {
		return err
	}
	if err := validateRealCloudDedicatedTestResources(environment, getenv); err != nil {
		return errors.New("exact pinned non-production resource gate rejected provider log setup")
	}
	configuration, _, err := decodeAndValidateRealCloudPinnedProviderDeployment(environment, getenv)
	if err != nil {
		return err
	}
	cfLog, err := decodeRealCloudProviderSecret[realCloudStorageSecret](getenv(realCloudProviderLogStorageCredentialCF))
	if err != nil {
		return err
	}
	eoLog, err := decodeRealCloudProviderSecret[realCloudStorageSecret](getenv(realCloudProviderLogStorageCredentialCOS))
	if err != nil {
		return err
	}
	cfWriter, err := decodeRealCloudProviderSecret[realCloudStorageSecret](getenv(realCloudProviderLogWriterCredentialCF))
	if err != nil {
		return errors.New("decode Cloudflare raw-log writer credential")
	}
	eoWriter, err := decodeRealCloudProviderSecret[realCloudStorageSecret](getenv(realCloudProviderLogWriterCredentialCOS))
	if err != nil {
		return errors.New("decode EdgeOne raw-log writer credential")
	}
	cfLogControl, err := decodeRealCloudProviderSecret[realCloudStorageSecret](getenv(realCloudProviderLogControlCredentialCF))
	if err != nil {
		return errors.New("decode Cloudflare raw-log control credential")
	}
	cfPublisher, err := decodeRealCloudProviderSecret[realCloudStorageSecret](getenv(realCloudStorageCredentialCF))
	if err != nil {
		return err
	}
	eoPublisher, err := decodeRealCloudProviderSecret[realCloudStorageSecret](getenv(realCloudStorageCredentialCOS))
	if err != nil {
		return err
	}
	if err := validateRealCloudProviderLogReaderIdentities(configuration, cfLog, eoLog, cfPublisher, eoPublisher); err != nil {
		return err
	}
	if err := validateRealCloudProviderLogWriterCredentials(configuration, cfWriter, eoWriter); err != nil {
		return err
	}
	if err := validateRealCloudProviderLogControlCredential(configuration, cfLogControl); err != nil {
		return err
	}
	cfCDN, err := decodeRealCloudProviderSecret[realCloudCloudflareSecret](getenv(realCloudCDNCredentialCF))
	if err != nil {
		return err
	}
	eoCDN, err := decodeRealCloudProviderSecret[realCloudTencentSecret](getenv(realCloudCDNCredentialCOS))
	if err != nil {
		return err
	}
	clients, err := newRealCloudProviderCollectorClients(environment, configuration, cfLog, cfCDN, eoLog, eoCDN, realCloudProviderCollectorEndpoints{
		CloudflareAPIURL: "https://api.cloudflare.com/client/v4", EdgeOneAPIURL: "https://teo.tencentcloudapi.com",
		CFObjectBaseURL: realCloudProviderBucketBaseURL(environment.CFR2Endpoint, configuration.Cloudflare.RawBucket),
		EOObjectBaseURL: realCloudProviderBucketBaseURL(environment.COSEndpoint, configuration.EdgeOne.RawBucket), HTTPClient: realCloudProviderHTTPClient(),
	})
	if err != nil {
		return err
	}
	clients.logSinkLeaseStore, err = newRealCloudProviderLogSinkLeaseStore(environment, configuration, cfLogControl, cfCDN, realCloudProviderHTTPClient())
	if err != nil {
		return err
	}
	return prepareRealCloudProviderPerRunRawSinksAfterGate(ctx, environment, runID, configuration, cfWriter, eoWriter, clients)
}

func validateRealCloudProviderLogWriterCredentials(
	configuration realCloudProviderAttestationConfig,
	cfWriter, eoWriter realCloudStorageSecret,
) error {
	if strings.TrimSpace(cfWriter.SecretAccessKey) == "" || strings.TrimSpace(eoWriter.SecretAccessKey) == "" ||
		cfWriter.SessionToken != "" || eoWriter.SessionToken != "" ||
		realCloudLowerSHA256([]byte(cfWriter.AccessKeyID)) != configuration.Cloudflare.RawWriterAccessKeySHA256 ||
		realCloudLowerSHA256([]byte(eoWriter.AccessKeyID)) != configuration.EdgeOne.RawWriterAccessKeySHA256 {
		return errors.New("provider log writer credentials must be pinned isolated non-session identities")
	}
	return nil
}

func validateRealCloudProviderLogControlCredential(configuration realCloudProviderAttestationConfig, control realCloudStorageSecret) error {
	if strings.TrimSpace(control.AccessKeyID) == "" || strings.TrimSpace(control.SecretAccessKey) == "" || control.SessionToken != "" ||
		realCloudLowerSHA256([]byte(control.AccessKeyID)) != configuration.Cloudflare.LogControlAccessKeySHA256 {
		return errors.New("provider log control credential must be a pinned isolated non-session identity")
	}
	return nil
}

func realCloudProviderLogSinkLeaseKey(configuration realCloudProviderAttestationConfig) (string, error) {
	key := configuration.Cloudflare.RawRoot + ".sow/provider-log-sink-lease.json"
	if !validRealCloudProviderObjectKey(key) {
		return "", errors.New("provider log-sink lease key is invalid")
	}
	return key, nil
}

func encodeRealCloudProviderLogSinkLease(lease realCloudProviderLogSinkLease) ([]byte, error) {
	if lease.Schema != realCloudProviderLogSinkLeaseSchema || !validRealCloudRunID(lease.RunID) ||
		!validRealCloudLowerSHA256(lease.ProviderDeploymentSHA256) || !validRealCloudProviderIdentifier(lease.AccountID, 128) ||
		!validRealCloudProviderIdentifier(lease.ZoneID, 128) || !validRealCloudLowerSHA256(lease.Holder) {
		return nil, errors.New("provider log-sink lease identity is invalid")
	}
	acquired, err := time.Parse(time.RFC3339Nano, lease.AcquiredAt)
	if err != nil {
		return nil, errors.New("provider log-sink lease acquisition time is invalid")
	}
	expires, err := time.Parse(time.RFC3339Nano, lease.ExpiresAt)
	if err != nil || !expires.After(acquired) || expires.Sub(acquired) > 24*time.Hour {
		return nil, errors.New("provider log-sink lease expiry is invalid")
	}
	body, err := json.Marshal(lease)
	if err != nil {
		return nil, errors.New("encode provider log-sink lease")
	}
	return append(body, '\n'), nil
}

func decodeRealCloudProviderLogSinkLease(body []byte) (realCloudProviderLogSinkLease, error) {
	var lease realCloudProviderLogSinkLease
	if err := decodeRealCloudCanonicalJSONFile(body, &lease); err != nil {
		return lease, err
	}
	canonical, err := encodeRealCloudProviderLogSinkLease(lease)
	if err != nil || !bytes.Equal(canonical, body) {
		return lease, errors.New("provider log-sink lease is invalid or non-canonical")
	}
	return lease, nil
}

func acquireRealCloudProviderLogSinkLease(
	ctx context.Context,
	store realCloudCloudflareBootstrapLeaseStore,
	environment realCloudEnvironment,
	configuration realCloudProviderAttestationConfig,
	runID, holder string,
	now time.Time,
) (*realCloudProviderHeldLogSinkLease, error) {
	deploymentSHA, err := realCloudProviderDeploymentIdentity(environment, configuration)
	if err != nil || store == nil || !validRealCloudRunID(runID) || !validRealCloudLowerSHA256(holder) {
		return nil, errors.New("provider log-sink lease acquisition identity is invalid")
	}
	key, err := realCloudProviderLogSinkLeaseKey(configuration)
	if err != nil {
		return nil, err
	}
	now = now.UTC()
	lease := realCloudProviderLogSinkLease{
		Schema: realCloudProviderLogSinkLeaseSchema, RunID: runID, ProviderDeploymentSHA256: deploymentSHA,
		AccountID: configuration.Cloudflare.AccountID, ZoneID: configuration.Cloudflare.ZoneID, Holder: holder,
		AcquiredAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(realCloudProviderLogSinkLeaseTTL).Format(time.RFC3339Nano),
	}
	body, err := encodeRealCloudProviderLogSinkLease(lease)
	if err != nil {
		return nil, err
	}
	etag, err := store.R2Put(ctx, key, bytes.NewReader(body), int64(len(body)), realCloudLowerSHA256(body), publish.R2PutCondition{IfNoneMatch: true})
	if err == nil {
		if !validRealCloudProviderETag(etag) {
			return nil, errors.New("provider log-sink lease create returned an invalid ETag")
		}
		return &realCloudProviderHeldLogSinkLease{store: store, key: key, lease: lease, etag: etag}, nil
	}
	if !errors.Is(err, publish.ErrAlreadyExists) && !errors.Is(err, publish.ErrConflict) {
		return nil, fmt.Errorf("create provider log-sink lease: %w", err)
	}
	observed, err := store.R2GetControl(ctx, key)
	if err != nil || !observed.Exists || !validRealCloudProviderETag(observed.ETag) {
		return nil, errors.New("inspect conflicting provider log-sink lease")
	}
	existing, err := decodeRealCloudProviderLogSinkLease(observed.Body)
	clearRealCloudBytes(observed.Body)
	if err != nil || existing.ProviderDeploymentSHA256 != deploymentSHA || existing.AccountID != configuration.Cloudflare.AccountID || existing.ZoneID != configuration.Cloudflare.ZoneID {
		return nil, errors.New("provider log-sink setup refuses an invalid or foreign lease")
	}
	expires, _ := time.Parse(time.RFC3339Nano, existing.ExpiresAt)
	if !now.After(expires) {
		return nil, errors.New("provider log-sink setup is leased by another live execution")
	}
	etag, err = store.R2Put(ctx, key, bytes.NewReader(body), int64(len(body)), realCloudLowerSHA256(body), publish.R2PutCondition{IfMatch: observed.ETag})
	if err != nil || !validRealCloudProviderETag(etag) {
		return nil, errors.New("replace expired provider log-sink lease by compare-and-set")
	}
	return &realCloudProviderHeldLogSinkLease{store: store, key: key, lease: lease, etag: etag}, nil
}

func (held *realCloudProviderHeldLogSinkLease) renew(ctx context.Context, now time.Time) error {
	if held == nil || held.store == nil || held.key == "" || !validRealCloudProviderETag(held.etag) {
		return errors.New("provider log-sink held lease is invalid")
	}
	observed, err := held.store.R2GetControl(ctx, held.key)
	if err != nil || !observed.Exists || observed.ETag != held.etag {
		return errors.New("provider log-sink lease ownership changed")
	}
	existing, err := decodeRealCloudProviderLogSinkLease(observed.Body)
	clearRealCloudBytes(observed.Body)
	if err != nil || existing != held.lease {
		return errors.New("provider log-sink lease bytes changed")
	}
	expires, _ := time.Parse(time.RFC3339Nano, held.lease.ExpiresAt)
	now = now.UTC()
	if !now.Before(expires) {
		return errors.New("provider log-sink lease expired before renewal")
	}
	next := held.lease
	next.ExpiresAt = now.Add(realCloudProviderLogSinkLeaseTTL).Format(time.RFC3339Nano)
	body, err := encodeRealCloudProviderLogSinkLease(next)
	if err != nil {
		return err
	}
	etag, err := held.store.R2Put(ctx, held.key, bytes.NewReader(body), int64(len(body)), realCloudLowerSHA256(body), publish.R2PutCondition{IfMatch: held.etag})
	if err != nil || !validRealCloudProviderETag(etag) {
		return errors.New("renew provider log-sink lease by compare-and-set")
	}
	held.lease, held.etag = next, etag
	return nil
}

func (held *realCloudProviderHeldLogSinkLease) release(ctx context.Context) error {
	if held == nil || held.store == nil || !validRealCloudProviderETag(held.etag) {
		return errors.New("provider log-sink held lease is invalid")
	}
	observed, err := held.store.R2GetControl(ctx, held.key)
	if err != nil || !observed.Exists || observed.ETag != held.etag {
		return errors.New("provider log-sink lease changed before release")
	}
	existing, err := decodeRealCloudProviderLogSinkLease(observed.Body)
	clearRealCloudBytes(observed.Body)
	if err != nil || existing != held.lease {
		return errors.New("provider log-sink lease bytes changed before release")
	}
	if err := held.store.R2Delete(ctx, held.key, held.etag); err != nil {
		return fmt.Errorf("release provider log-sink lease: %w", err)
	}
	held.etag = ""
	return nil
}

func prepareRealCloudProviderPerRunRawSinksAfterGate(
	ctx context.Context,
	environment realCloudEnvironment,
	runID string,
	configuration realCloudProviderAttestationConfig,
	cfWriter, eoWriter realCloudStorageSecret,
	clients realCloudProviderCollectorClients,
) error {
	// Resolve both opaque provider zone IDs back to their exact dedicated
	// non-production identities before either provider is mutated. In
	// particular, a registry entry that accidentally pins a production EdgeOne
	// ZoneID must fail before the first Cloudflare Logpush update.
	if _, _, err := collectRealCloudEdgeOneZoneClosure(ctx, environment, configuration.EdgeOne, "", clients.edgeOne); err != nil {
		return fmt.Errorf("EdgeOne non-production zone safety gate rejected provider log setup: %w", err)
	}
	cfZone, err := clients.cloudflare.Zones.Get(ctx, zones.ZoneGetParams{ZoneID: cloudflareapi.F(configuration.Cloudflare.ZoneID)})
	if err != nil || cfZone == nil {
		return errors.New("Cloudflare non-production zone safety gate query failed before provider log setup")
	}
	_, zoneErr := validateRealCloudCloudflareZone(cfZone, environment, configuration.Cloudflare)
	*cfZone = zones.Zone{}
	if zoneErr != nil {
		return fmt.Errorf("Cloudflare non-production zone safety gate rejected provider log setup: %w", zoneErr)
	}
	holder, err := newRealCloudCloudflareBootstrapLeaseHolder()
	if err != nil {
		return err
	}
	heldLease, err := acquireRealCloudProviderLogSinkLease(ctx, clients.logSinkLeaseStore, environment, configuration, runID, holder, time.Now())
	if err != nil {
		return err
	}
	cfFilter := realCloudCloudflareHostFilter(environment)
	cfDestination := realCloudCloudflareDestinationURL(configuration.Cloudflare, runID, cfWriter)
	if err := heldLease.renew(ctx, time.Now()); err != nil {
		return err
	}
	updated, err := clients.cloudflare.Logpush.Jobs.Update(ctx, configuration.Cloudflare.LogpushJobID, logpush.JobUpdateParams{
		ZoneID: cloudflareapi.F(configuration.Cloudflare.ZoneID), DestinationConf: cloudflareapi.F(cfDestination), Enabled: cloudflareapi.F(true), Filter: cloudflareapi.F(cfFilter),
		OutputOptions: cloudflareapi.F(logpush.OutputOptionsParam{
			FieldNames: cloudflareapi.F(append([]string(nil), realCloudCloudflareRawFields...)), MergeSubrequests: cloudflareapi.F(false),
			OutputType: cloudflareapi.F(logpush.OutputOptionsOutputTypeNdjson), SampleRate: cloudflareapi.F(1.0), TimestampFormat: cloudflareapi.F(logpush.OutputOptionsTimestampFormatRfc3339ns),
		}),
	})
	cfDestination = ""
	if err != nil || updated == nil {
		return errors.New("configure Cloudflare per-run Logpush sink")
	}
	*updated = logpush.LogpushJob{}
	if err := heldLease.renew(ctx, time.Now()); err != nil {
		return err
	}
	eoRequest := teo.NewModifyRealtimeLogDeliveryTaskRequest()
	eoRequest.ZoneId = stringPointer(configuration.EdgeOne.ZoneID)
	eoRequest.TaskId = stringPointer(configuration.EdgeOne.RealtimeLogTaskID)
	eoRequest.DeliveryStatus = stringPointer("enabled")
	eoRequest.EntityList = stringValuesPointers([]string{hostOnly(environment.COSCDNBase), hostOnly(environment.COSBetaBase)})
	eoRequest.Fields = stringValuesPointers(realCloudEdgeOneRawFields)
	eoRequest.CustomFields = []*teo.CustomField{}
	eoRequest.DeliveryConditions = []*teo.DeliveryCondition{}
	eoRequest.Sample = uint64Pointer(1000)
	eoRequest.LogFormat = &teo.LogFormat{FormatType: stringPointer("json")}
	eoRequest.S3 = &teo.S3{
		Endpoint: stringPointer(strings.TrimSuffix(environment.COSEndpoint, "/")), Region: stringPointer(environment.COSRegion),
		Bucket:   stringPointer(configuration.EdgeOne.RawBucket + "/" + realCloudProviderRunSinkPrefix(configuration.EdgeOne.RawRoot, runID)),
		AccessId: stringPointer(eoWriter.AccessKeyID), AccessKey: stringPointer(eoWriter.SecretAccessKey), CompressType: stringPointer(""),
	}
	_, err = clients.edgeOne.ModifyRealtimeLogDeliveryTaskWithContext(ctx, eoRequest)
	if eoRequest.S3.AccessKey != nil {
		*eoRequest.S3.AccessKey = ""
	}
	*eoRequest = *teo.NewModifyRealtimeLogDeliveryTaskRequest()
	if err != nil {
		return errors.New("configure EdgeOne per-run realtime-log sink")
	}
	jobs, err := clients.cloudflare.Logpush.Jobs.List(ctx, logpush.JobListParams{ZoneID: cloudflareapi.F(configuration.Cloudflare.ZoneID)})
	if err != nil || jobs == nil {
		return errors.New("verify Cloudflare per-run Logpush sink")
	}
	defer func() {
		for index := range jobs.Result {
			jobs.Result[index] = logpush.LogpushJob{}
		}
		*jobs = *newCloudflareLogpushPage()
	}()
	configuredJob, err := selectRealCloudCloudflareLogpushJob(jobs.Result, environment, configuration.Cloudflare)
	if err != nil {
		return err
	}
	if _, _, err := validateRealCloudCloudflareLogpushJob(&jobs.Result[configuredJob], environment, configuration.Cloudflare); err != nil {
		return err
	}
	taskRequest := teo.NewDescribeRealtimeLogDeliveryTasksRequest()
	taskRequest.ZoneId = stringPointer(configuration.EdgeOne.ZoneID)
	taskRequest.Offset = int64Pointer(0)
	taskRequest.Limit = uint64Pointer(1000)
	taskResponse, err := clients.edgeOne.DescribeRealtimeLogDeliveryTasksWithContext(ctx, taskRequest)
	if err != nil || taskResponse == nil || taskResponse.Response == nil || taskResponse.Response.TotalCount == nil ||
		*taskResponse.Response.TotalCount != 1 || len(taskResponse.Response.RealtimeLogDeliveryTasks) != 1 {
		return errors.New("verify EdgeOne per-run realtime-log sink")
	}
	if _, _, err := validateRealCloudEdgeOneLogTask(taskResponse.Response.RealtimeLogDeliveryTasks[0], environment, configuration.EdgeOne); err != nil {
		return err
	}
	if err := heldLease.release(ctx); err != nil {
		return err
	}
	return nil
}

func validateRealCloudProviderLogReaderIdentities(
	configuration realCloudProviderAttestationConfig,
	cfLog, eoLog, cfPublisher, eoPublisher realCloudStorageSecret,
) error {
	identities := make(map[string]struct{}, 4)
	digests := make(map[string]struct{}, 7)
	for _, credential := range []realCloudStorageSecret{cfLog, eoLog, cfPublisher, eoPublisher} {
		if strings.TrimSpace(credential.AccessKeyID) == "" || credential.AccessKeyID != strings.TrimSpace(credential.AccessKeyID) {
			return errors.New("storage access-key identity is empty or non-canonical")
		}
		if _, duplicate := identities[credential.AccessKeyID]; duplicate {
			return errors.New("raw-log reader and publisher access-key identities must be pairwise distinct")
		}
		identities[credential.AccessKeyID] = struct{}{}
		digests[realCloudLowerSHA256([]byte(credential.AccessKeyID))] = struct{}{}
	}
	if realCloudLowerSHA256([]byte(cfLog.AccessKeyID)) != configuration.Cloudflare.RawReaderAccessKeySHA256 ||
		realCloudLowerSHA256([]byte(eoLog.AccessKeyID)) != configuration.EdgeOne.RawReaderAccessKeySHA256 {
		return errors.New("raw-log reader access-key identity differs from the administrator-pinned digest")
	}
	for _, isolated := range []string{configuration.Cloudflare.RawWriterAccessKeySHA256, configuration.EdgeOne.RawWriterAccessKeySHA256, configuration.Cloudflare.LogControlAccessKeySHA256} {
		if !validRealCloudLowerSHA256(isolated) {
			return errors.New("raw-log writer or control access-key identity digest is invalid")
		}
		if _, duplicate := digests[isolated]; duplicate {
			return errors.New("raw-log writer, control, reader, and publisher access-key identities must be pairwise distinct")
		}
		digests[isolated] = struct{}{}
	}
	return nil
}

func decodeAndValidateRealCloudPinnedProviderDeployment(environment realCloudEnvironment, getenv func(string) string) (realCloudProviderAttestationConfig, []byte, error) {
	configuration, body, err := decodeRealCloudProviderAttestationConfig(getenv(realCloudProviderAttestationEnv), environment, getenv(realCloudRunIDEnv))
	if err != nil {
		return realCloudProviderAttestationConfig{}, nil, err
	}
	if _, err := validateRealCloudPinnedProviderDeployment(environment, configuration); err != nil {
		return realCloudProviderAttestationConfig{}, nil, err
	}
	return configuration, body, nil
}

func decodeRealCloudProviderAttestationConfig(raw string, environment realCloudEnvironment, runID string) (realCloudProviderAttestationConfig, []byte, error) {
	var configuration realCloudProviderAttestationConfig
	if raw == "" || raw != strings.TrimSpace(raw) {
		return configuration, nil, errors.New("missing or non-canonical provider attestation config")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&configuration); err != nil {
		return configuration, nil, errors.New("decode provider attestation config")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return configuration, nil, errors.New("provider attestation config contains trailing data")
	}
	body, err := json.Marshal(configuration)
	if err != nil || raw != string(body) || configuration.Schema != realCloudProviderAttestationSchema {
		return configuration, nil, errors.New("provider attestation config is not canonical")
	}
	accountID := strings.TrimSuffix(strings.ToLower(strings.TrimSuffix(environment.CFR2Endpoint, "/")), ".r2.cloudflarestorage.com")
	accountID = strings.TrimPrefix(accountID, "https://")
	if configuration.Cloudflare.AccountID != accountID || configuration.Cloudflare.ZoneID != environment.CFZoneID ||
		configuration.EdgeOne.ZoneID != environment.EdgeOneZoneID {
		return configuration, nil, errors.New("provider attestation identities do not match the pinned resource environment")
	}
	productBody, _, _, err := realCloudProviderProductContracts(environment)
	if err != nil || !validRealCloudLowerSHA256(configuration.ProductConfigSHA256) || realCloudLowerSHA256(productBody) != configuration.ProductConfigSHA256 {
		return configuration, nil, errors.New("provider deployment is not bound to the deterministic SOW product config")
	}
	if configuration.Cloudflare.LogpushJobID <= 0 || !validRealCloudProviderIdentifier(configuration.Cloudflare.WorkerScript, 128) ||
		!validRealCloudProviderIdentifier(configuration.Cloudflare.OriginWorkerScript, 128) ||
		configuration.Cloudflare.OriginWorkerScript == configuration.Cloudflare.WorkerScript ||
		!validRealCloudProviderOptionalIdentifier(configuration.Cloudflare.OriginWorkerEnvironment, 128) ||
		!validRealCloudProviderIdentifier(configuration.Cloudflare.TokenVerifierService, 128) ||
		!validRealCloudProviderOptionalIdentifier(configuration.Cloudflare.TokenVerifierEnvironment, 128) ||
		configuration.Cloudflare.TokenVerifierService == configuration.Cloudflare.WorkerScript ||
		configuration.Cloudflare.TokenVerifierService == configuration.Cloudflare.OriginWorkerScript ||
		!validRealCloudLowerSHA256(configuration.Cloudflare.TokenVerifierContentSHA256) ||
		!validRealCloudLowerSHA256(configuration.Cloudflare.TokenVerifierBindingsSHA256) ||
		!validRealCloudLowerSHA256(configuration.Cloudflare.RawReaderAccessKeySHA256) ||
		!validRealCloudLowerSHA256(configuration.Cloudflare.RawWriterAccessKeySHA256) ||
		!validRealCloudLowerSHA256(configuration.Cloudflare.LogControlAccessKeySHA256) ||
		!validRealCloudLowerSHA256(configuration.EdgeOne.RawReaderAccessKeySHA256) ||
		!validRealCloudLowerSHA256(configuration.EdgeOne.RawWriterAccessKeySHA256) ||
		!validRealCloudLowerSHA256(configuration.EdgeOne.FunctionDomainSHA256) ||
		!validRealCloudProviderIdentifier(configuration.EdgeOne.RealtimeLogTaskID, 128) ||
		!validRealCloudEdgeOneLogArea(configuration.EdgeOne.RealtimeLogArea) ||
		!validRealCloudProviderIdentifier(configuration.EdgeOne.FunctionID, 128) {
		return configuration, nil, errors.New("provider attestation job, task, or function identity is invalid")
	}
	logIdentities := make(map[string]struct{}, 5)
	for _, identity := range []string{
		configuration.Cloudflare.RawReaderAccessKeySHA256, configuration.Cloudflare.RawWriterAccessKeySHA256,
		configuration.Cloudflare.LogControlAccessKeySHA256, configuration.EdgeOne.RawReaderAccessKeySHA256,
		configuration.EdgeOne.RawWriterAccessKeySHA256,
	} {
		if _, duplicate := logIdentities[identity]; duplicate {
			return configuration, nil, errors.New("provider raw-log reader, writer, and control identities must be pairwise distinct")
		}
		logIdentities[identity] = struct{}{}
	}
	for _, worker := range []struct {
		role     string
		contract realCloudCloudflareWorkerRuntimeContract
	}{
		{"auth", configuration.Cloudflare.WorkerRuntime},
		{"origin", configuration.Cloudflare.OriginWorkerRuntime},
		{"token-verifier", configuration.Cloudflare.TokenVerifierRuntime},
	} {
		if err := validateRealCloudCloudflareWorkerRuntimeContract(worker.contract); err != nil {
			return configuration, nil, fmt.Errorf("provider attestation %s Worker runtime contract is invalid: %w", worker.role, err)
		}
	}
	if !validDedicatedRealCloudBucket(configuration.Cloudflare.RawBucket) || !validDedicatedRealCloudBucket(configuration.EdgeOne.RawBucket) ||
		!validRealCloudProviderCOSBucket(configuration.EdgeOne.RawBucket) || hasRealCloudProductionMarker(configuration.Cloudflare.RawBucket) || hasRealCloudProductionMarker(configuration.EdgeOne.RawBucket) ||
		configuration.Cloudflare.RawBucket == environment.CFR2Bucket || configuration.EdgeOne.RawBucket == environment.COSBucket ||
		configuration.Cloudflare.RawBucket == configuration.EdgeOne.RawBucket ||
		!validRealCloudProviderRawPrefix(configuration.Cloudflare.RawRoot) || !validRealCloudProviderRawPrefix(configuration.EdgeOne.RawRoot) {
		return configuration, nil, errors.New("provider raw exports must use distinct dedicated non-production log buckets and safe prefixes")
	}
	if err := validateRealCloudProviderRuntimeConfig(environment, configuration.Runtime, configuration.Cloudflare.TokenVerifierService); err != nil {
		return configuration, nil, err
	}
	runID = strings.TrimSpace(runID)
	if !validRealCloudRunID(runID) {
		return configuration, nil, errors.New("provider raw export inventory is not bound to one valid destructive run")
	}
	return configuration, body, nil
}

func validateRealCloudCloudflareWorkerRuntimeContract(contract realCloudCloudflareWorkerRuntimeContract) error {
	parsed, err := time.Parse("2006-01-02", contract.CompatibilityDate)
	if err != nil || parsed.Format("2006-01-02") != contract.CompatibilityDate || contract.CompatibilityFlags == nil || len(contract.CompatibilityFlags) > 32 {
		return errors.New("compatibility date or flag inventory is absent or non-canonical")
	}
	previous := ""
	for _, flag := range contract.CompatibilityFlags {
		if !validRealCloudProviderIdentifier(flag, 128) || flag <= previous {
			return errors.New("compatibility flags are invalid, duplicate, or unsorted")
		}
		previous = flag
	}
	return nil
}

func realCloudProviderProductContracts(environment realCloudEnvironment) ([]byte, sowconfig.EdgeDeploymentContract, sowconfig.EdgeDeploymentContract, error) {
	product := realCloudConfigForEnvironment(environment)
	body, err := realCloudConfigBodyForEnvironment(environment)
	if err != nil {
		return nil, sowconfig.EdgeDeploymentContract{}, sowconfig.EdgeDeploymentContract{}, errors.New("encode deterministic SOW product config")
	}
	cloudflare, err := product.EdgeDeployment("cf")
	if err != nil {
		return nil, sowconfig.EdgeDeploymentContract{}, sowconfig.EdgeDeploymentContract{}, fmt.Errorf("derive Cloudflare product edge contract: %w", err)
	}
	edgeOne, err := product.EdgeDeployment("cos")
	if err != nil {
		return nil, sowconfig.EdgeDeploymentContract{}, sowconfig.EdgeDeploymentContract{}, fmt.Errorf("derive EdgeOne product edge contract: %w", err)
	}
	return body, cloudflare, edgeOne, nil
}

func validateRealCloudProviderRuntimeConfig(environment realCloudEnvironment, runtime realCloudEdgeRuntimeAttestationConfig, tokenVerifierService string) error {
	_, cloudflare, edgeOne, err := realCloudProviderProductContracts(environment)
	if err != nil {
		return err
	}
	verifier, err := sowconfig.ParseTokenVerifierReference(runtime.TokenVerifier)
	if err != nil || verifier.Kind != "provider" || verifier.Name != tokenVerifierService ||
		cloudflare.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable] != runtime.TokenVerifier ||
		edgeOne.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable] != runtime.TokenVerifier {
		return errors.New("runtime token verifier reference does not bind the exact Cloudflare service")
	}
	if !validRealCloudProviderHTTPSURL(runtime.EdgeOneTokenVerifierURL, true) || !validRealCloudLowerSHA256(runtime.EdgeOneTokenVerifierDeploymentSHA256) {
		return errors.New("EdgeOne runtime token verifier URL is not one canonical HTTPS endpoint")
	}
	if !validRealCloudProviderRouteList(runtime.PublicPrefixes) || !validRealCloudProviderRouteList(runtime.PublicKeys) {
		return errors.New("runtime public prefix or key allowlist is non-canonical")
	}
	prefixes, _ := json.Marshal(runtime.PublicPrefixes)
	keys, _ := json.Marshal(runtime.PublicKeys)
	if cloudflare.Variables[sowconfig.EdgeRuntimePublicPrefixesVariable] != string(prefixes) ||
		cloudflare.Variables[sowconfig.EdgeRuntimePublicKeysVariable] != string(keys) ||
		edgeOne.Variables[sowconfig.EdgeRuntimePublicPrefixesVariable] != string(prefixes) ||
		edgeOne.Variables[sowconfig.EdgeRuntimePublicKeysVariable] != string(keys) {
		return errors.New("runtime public route allowlists differ from the deterministic SOW product config")
	}
	if !validRealCloudProviderSecretNameList(runtime.CloudflareSecretNames, []string{"SOW_ORIGIN_BEARER"}) ||
		!validRealCloudProviderSecretNameList(runtime.EdgeOneSecretNames, []string{"SOW_ORIGIN_BEARER", "SOW_TOKEN_VERIFIER_BEARER"}) {
		return errors.New("runtime secret-name inventory is non-canonical or incomplete")
	}
	return nil
}

func realCloudProviderExpectedRuntimeVariables(
	environment realCloudEnvironment,
	runtime realCloudEdgeRuntimeAttestationConfig,
	vendor string,
) (map[string]string, error) {
	_, cloudflare, edgeOne, err := realCloudProviderProductContracts(environment)
	if err != nil {
		return nil, err
	}
	var contract sowconfig.EdgeDeploymentContract
	var publicBase, betaBase string
	switch vendor {
	case "cloudflare":
		contract = cloudflare
		publicBase, betaBase = environment.CFCDNBase, environment.CFBetaCDNBase
	case "edgeone":
		contract = edgeOne
		publicBase, betaBase = environment.COSCDNBase, environment.COSBetaBase
	default:
		return nil, errors.New("unknown provider runtime vendor")
	}
	publicBase, err = canonicalRealCloudProviderRuntimeOrigin(publicBase)
	if err != nil {
		return nil, fmt.Errorf("%s public runtime base: %w", vendor, err)
	}
	betaBase, err = canonicalRealCloudProviderRuntimeOrigin(betaBase)
	if err != nil || publicBase == betaBase {
		return nil, fmt.Errorf("%s beta runtime base is invalid or not distinct", vendor)
	}
	variables := make(map[string]string, len(contract.Variables)+2)
	for name, value := range contract.Variables {
		variables[name] = value
	}
	variables[sowconfig.EdgeRuntimePublicBaseURLVariable] = publicBase
	variables[sowconfig.EdgeRuntimeBetaBaseURLVariable] = betaBase
	variables[sowconfig.EdgeRuntimeOriginModeVariable] = "https-bearer"
	variables["SOW_ORIGIN_BASE_URL"] = publicBase
	variables["SOW_BETA_ORIGIN_BASE_URL"] = betaBase
	delete(variables, "SOW_COS_REGION")
	delete(variables, "SOW_COS_BUCKET")
	if vendor == "edgeone" {
		variables["SOW_TOKEN_VERIFIER_URL"] = runtime.EdgeOneTokenVerifierURL
	}
	return variables, nil
}

func canonicalRealCloudProviderRuntimeOrigin(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.Port() != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("must be one clean credential-free HTTPS origin")
	}
	host := strings.ToLower(parsed.Hostname())
	if parsed.Hostname() != host {
		return "", errors.New("host must be lowercase")
	}
	return "https://" + host, nil
}

func validateRealCloudPinnedProviderDeployment(environment realCloudEnvironment, configuration realCloudProviderAttestationConfig) (string, error) {
	registry, err := loadRealCloudPinnedProviderDeploymentRegistry()
	if err != nil {
		return "", err
	}
	return validateRealCloudProviderDeploymentAgainstRegistry(environment, configuration, registry)
}

func loadRealCloudPinnedProviderDeploymentRegistry() (realCloudPinnedProviderDeploymentRegistry, error) {
	body, err := readRealCloudProviderRepositoryFile(realCloudProviderDeploymentRegistryPath, 256<<10)
	if err != nil {
		return realCloudPinnedProviderDeploymentRegistry{}, errors.New("repository-pinned provider deployment registry is absent or unsafe")
	}
	defer clearRealCloudBytes(body)
	return decodeRealCloudPinnedProviderDeploymentRegistry(body, realCloudProviderDeploymentRegistrySHA256)
}

func decodeRealCloudPinnedProviderDeploymentRegistry(body []byte, expectedSHA256 string) (realCloudPinnedProviderDeploymentRegistry, error) {
	var registry realCloudPinnedProviderDeploymentRegistry
	if !validRealCloudLowerSHA256(expectedSHA256) || realCloudLowerSHA256(body) != expectedSHA256 {
		return registry, errors.New("repository-pinned provider deployment registry digest differs from the reviewed build constant")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return registry, errors.New("decode repository-pinned provider deployment registry")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return registry, errors.New("repository-pinned provider deployment registry contains trailing values")
	}
	canonical, err := json.Marshal(registry)
	if err != nil || !bytes.Equal(body, append(canonical, '\n')) || registry.Schema != realCloudProviderDeploymentRegistrySchema || registry.Deployments == nil {
		return registry, errors.New("repository-pinned provider deployment registry is non-canonical or invalid")
	}
	previous := ""
	for _, deployment := range registry.Deployments {
		key := deployment.ResourceSHA256 + "\x00" + deployment.DeploymentSHA256
		if deployment.Schema != realCloudProviderDeploymentEntrySchema || deployment.Purpose != "dedicated-disposable-non-production-test" ||
			!validRealCloudLowerSHA256(deployment.ResourceSHA256) || !validRealCloudLowerSHA256(deployment.DeploymentSHA256) || key <= previous {
			return registry, errors.New("repository-pinned provider deployments are invalid, duplicate, or unsorted")
		}
		previous = key
	}
	return registry, nil
}

func validateRealCloudProviderDeploymentAgainstRegistry(
	environment realCloudEnvironment,
	configuration realCloudProviderAttestationConfig,
	registry realCloudPinnedProviderDeploymentRegistry,
) (string, error) {
	resourceBody, err := json.Marshal(realCloudTestResourceForEnvironment(environment))
	if err != nil {
		return "", errors.New("encode provider deployment resource identity")
	}
	resourceSHA := realCloudLowerSHA256(resourceBody)
	deploymentSHA, err := realCloudProviderDeploymentIdentity(environment, configuration)
	if err != nil {
		return "", err
	}
	for _, approved := range registry.Deployments {
		if approved.ResourceSHA256 == resourceSHA && approved.DeploymentSHA256 == deploymentSHA {
			return deploymentSHA, nil
		}
	}
	return "", errors.New("provider deployment is not present in the repository-pinned administrator-reviewed non-production registry")
}

func realCloudProviderDeploymentIdentity(environment realCloudEnvironment, configuration realCloudProviderAttestationConfig) (string, error) {
	resourceBody, err := json.Marshal(realCloudTestResourceForEnvironment(environment))
	if err != nil {
		return "", errors.New("encode provider deployment resource identity")
	}
	stable := struct {
		Schema              string                                `json:"schema"`
		ResourceSHA256      string                                `json:"resource_sha256"`
		ProductConfigSHA256 string                                `json:"product_config_sha256"`
		Cloudflare          realCloudCloudflareAttestationConfig  `json:"cloudflare"`
		EdgeOne             realCloudEdgeOneAttestationConfig     `json:"edgeone"`
		Runtime             realCloudEdgeRuntimeAttestationConfig `json:"runtime"`
	}{
		Schema: realCloudProviderDeploymentIdentitySchema, ResourceSHA256: realCloudLowerSHA256(resourceBody),
		ProductConfigSHA256: configuration.ProductConfigSHA256,
		Cloudflare:          configuration.Cloudflare, EdgeOne: configuration.EdgeOne, Runtime: configuration.Runtime,
	}
	body, err := json.Marshal(stable)
	if err != nil {
		return "", errors.New("encode stable provider deployment identity")
	}
	return realCloudLowerSHA256(body), nil
}

func decodeRealCloudProviderSecret[T any](raw string) (T, error) {
	var result T
	if strings.TrimSpace(raw) == "" {
		return result, errors.New("missing credential")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, errors.New("decode credential")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return result, errors.New("credential contains trailing data")
	}
	return result, nil
}

func newRealCloudProviderCollectorClients(
	environment realCloudEnvironment,
	providerConfiguration realCloudProviderAttestationConfig,
	cfStorage realCloudStorageSecret,
	cfCDN realCloudCloudflareSecret,
	eoStorage realCloudStorageSecret,
	eoCDN realCloudTencentSecret,
	endpoints realCloudProviderCollectorEndpoints,
) (realCloudProviderCollectorClients, error) {
	var result realCloudProviderCollectorClients
	client := endpoints.HTTPClient
	if client == nil {
		client = realCloudProviderHTTPClient()
	}
	cfAPI, err := canonicalRealCloudProviderAPIBase(endpoints.CloudflareAPIURL, endpoints.AllowInsecure)
	if err != nil {
		return result, err
	}
	eoAPI, err := canonicalRealCloudProviderAPIBase(endpoints.EdgeOneAPIURL, endpoints.AllowInsecure)
	if err != nil {
		return result, err
	}
	if strings.TrimSpace(cfCDN.APIToken) == "" || strings.TrimSpace(eoCDN.SecretID) == "" || strings.TrimSpace(eoCDN.SecretKey) == "" {
		return result, errors.New("provider API credentials are empty")
	}
	result.cloudflare = cloudflareapi.NewClient(
		option.WithBaseURL(strings.TrimSuffix(cfAPI, "/")+"/"),
		option.WithAPIToken(cfCDN.APIToken),
		option.WithHTTPClient(client),
		option.WithMaxRetries(0),
	)

	parsedTEO, _ := url.Parse(eoAPI)
	clientProfile := profile.NewClientProfile()
	clientProfile.DisableRegionBreaker = true
	clientProfile.NetworkFailureMaxRetries = 0
	clientProfile.RateLimitExceededMaxRetries = 0
	clientProfile.HttpProfile.Scheme = strings.ToUpper(parsedTEO.Scheme)
	clientProfile.HttpProfile.Endpoint = parsedTEO.Host
	clientProfile.HttpProfile.ReqTimeout = 30
	credential := common.NewTokenCredential(eoCDN.SecretID, eoCDN.SecretKey, eoCDN.SessionToken)
	result.edgeOne, err = teo.NewClient(credential, "", clientProfile)
	if err != nil {
		return realCloudProviderCollectorClients{}, errors.New("construct EdgeOne SDK")
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	result.edgeOne.WithHttpTransport(transport)

	cfObjects, err := publish.NewR2CloudflareHTTP(publish.R2CloudflareHTTPConfig{
		Bucket: providerConfiguration.Cloudflare.RawBucket, ObjectBaseURL: endpoints.CFObjectBaseURL, CDNBaseURL: environment.CFCDNBase,
		Credentials: publish.S3Credentials{AccessKeyID: cfStorage.AccessKeyID, SecretAccessKey: cfStorage.SecretAccessKey, SessionToken: cfStorage.SessionToken, Region: "auto"},
		ZoneID:      environment.CFZoneID, APIToken: cfCDN.APIToken, CloudflareAPIURL: cfAPI,
		Client: client, AllowInsecure: endpoints.AllowInsecure,
	})
	if err != nil {
		return realCloudProviderCollectorClients{}, errors.New("construct read-only R2 protocol client")
	}
	eoObjects, err := publish.NewCOSEdgeOneHTTP(publish.COSEdgeOneHTTPConfig{
		Bucket: providerConfiguration.EdgeOne.RawBucket, ObjectBaseURL: endpoints.EOObjectBaseURL, CDNBaseURL: environment.COSCDNBase,
		ObjectCredentials:  publish.S3Credentials{AccessKeyID: eoStorage.AccessKeyID, SecretAccessKey: eoStorage.SecretAccessKey, SessionToken: eoStorage.SessionToken, Region: environment.COSRegion},
		TencentCredentials: publish.TencentCredentials{SecretID: eoCDN.SecretID, SecretKey: eoCDN.SecretKey, Token: eoCDN.SessionToken},
		ZoneID:             environment.EdgeOneZoneID, EdgeOneAPIURL: eoAPI,
		Client: client, AllowInsecure: endpoints.AllowInsecure, UnversionedBucketConfirmed: true,
	})
	if err != nil {
		return realCloudProviderCollectorClients{}, errors.New("construct read-only COS protocol client")
	}
	result.openCF = cfObjects.R2OpenObject
	result.openEO = eoObjects.COSOpenObject
	result.listCF = cfObjects.R2ListObjectsV2Prefix
	result.listEO = eoObjects.COSListObjectsV2Prefix
	result.probeEOFunctionDomain = func(ctx context.Context, domain string) (string, error) {
		base := "https://" + domain
		if endpoints.EOFunctionDomainBaseURL != "" {
			if !endpoints.AllowInsecure {
				return "", errors.New("EdgeOne default-domain probe override is test-only")
			}
			base = strings.TrimSuffix(endpoints.EOFunctionDomainBaseURL, "/")
		}
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, base+"/.sow/provider-attestation-deny", nil)
		if requestErr != nil {
			return "", errors.New("construct EdgeOne default-domain fail-closed probe")
		}
		request.Host = domain
		response, requestErr := client.Do(request)
		if requestErr != nil || response == nil || response.Body == nil {
			return "", errors.New("EdgeOne default-domain fail-closed probe failed")
		}
		defer response.Body.Close()
		probeBody, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
		defer clearRealCloudBytes(probeBody)
		if readErr != nil || len(probeBody) > 4096 || response.StatusCode != http.StatusForbidden && response.StatusCode != http.StatusNotFound ||
			response.Header.Get("X-SOW-Edge-Contract") != "" || response.Header.Get("X-SOW-Origin-Transport") != "" {
			return "", errors.New("EdgeOne default public function domain did not fail closed")
		}
		body, _ := json.Marshal([]any{realCloudLowerSHA256([]byte(domain)), response.StatusCode, realCloudLowerSHA256(probeBody)})
		return realCloudLowerSHA256(body), nil
	}
	return result, nil
}

func newRealCloudProviderLogSinkLeaseStore(
	environment realCloudEnvironment,
	configuration realCloudProviderAttestationConfig,
	control realCloudStorageSecret,
	api realCloudCloudflareSecret,
	client *http.Client,
) (*publish.R2CloudflareHTTP, error) {
	if strings.TrimSpace(control.AccessKeyID) == "" || strings.TrimSpace(control.SecretAccessKey) == "" || control.SessionToken != "" ||
		realCloudLowerSHA256([]byte(control.AccessKeyID)) != configuration.Cloudflare.LogControlAccessKeySHA256 || strings.TrimSpace(api.APIToken) == "" {
		return nil, errors.New("Cloudflare provider log-sink lease control identity is invalid")
	}
	store, err := publish.NewR2CloudflareHTTP(publish.R2CloudflareHTTPConfig{
		Bucket:        configuration.Cloudflare.RawBucket,
		ObjectBaseURL: realCloudProviderBucketBaseURL(environment.CFR2Endpoint, configuration.Cloudflare.RawBucket),
		CDNBaseURL:    environment.CFCDNBase, ZoneID: configuration.Cloudflare.ZoneID, APIToken: api.APIToken,
		Credentials:      publish.S3Credentials{AccessKeyID: control.AccessKeyID, SecretAccessKey: control.SecretAccessKey, Region: "auto"},
		CloudflareAPIURL: "https://api.cloudflare.com/client/v4", Client: client,
	})
	if err != nil {
		return nil, errors.New("construct Cloudflare provider log-sink lease store")
	}
	return store, nil
}

func collectRealCloudProviderRawAttestationAfterGate(
	ctx context.Context,
	environment realCloudEnvironment,
	configuration realCloudProviderAttestationConfig,
	configurationBody []byte,
	stages []realEdgeMultiPoPStageEvidence,
	operatorLogs []realEdgeProviderLog,
	forbidden []string,
	clients realCloudProviderCollectorClients,
) (realCloudProviderRawAttestation, error) {
	if clients.cloudflare == nil || clients.edgeOne == nil || clients.openCF == nil || clients.openEO == nil || clients.listCF == nil || clients.listEO == nil || clients.probeEOFunctionDomain == nil {
		return realCloudProviderRawAttestation{}, errors.New("provider collector clients are incomplete")
	}
	sourceSHA, buildSHA, err := realCloudProviderCollectorIdentity()
	if err != nil {
		return realCloudProviderRawAttestation{}, err
	}
	productBody, _, _, err := realCloudProviderProductContracts(environment)
	if err != nil || realCloudLowerSHA256(productBody) != configuration.ProductConfigSHA256 {
		return realCloudProviderRawAttestation{}, errors.New("provider collector product config binding is invalid")
	}
	for _, stage := range stages {
		for _, vendor := range []string{"cloudflare", "edgeone"} {
			if stage.Vendors[vendor].ConfigSHA256 != configuration.ProductConfigSHA256 {
				return realCloudProviderRawAttestation{}, errors.New("active edge evidence was not produced from the attested SOW product config")
			}
		}
	}

	cfControl, err := collectRealCloudCloudflareControl(ctx, environment, configuration, clients.cloudflare)
	if err != nil {
		return realCloudProviderRawAttestation{}, err
	}
	eoControl, err := collectRealCloudEdgeOneControl(ctx, environment, configuration, clients.edgeOne, clients.probeEOFunctionDomain)
	if err != nil {
		return realCloudProviderRawAttestation{}, err
	}
	cfSinkPrefix := realCloudProviderRunSinkPrefix(configuration.Cloudflare.RawRoot, strings.TrimSpace(os.Getenv(realCloudRunIDEnv)))
	eoSinkPrefix := realCloudProviderRunSinkPrefix(configuration.EdgeOne.RawRoot, strings.TrimSpace(os.Getenv(realCloudRunIDEnv)))
	cfRaw, cfObject, err := readRealCloudProviderRawObjects(ctx, "cloudflare", configuration.Cloudflare.RawBucket, cfSinkPrefix, clients.listCF, clients.openCF)
	if err != nil {
		return realCloudProviderRawAttestation{}, err
	}
	defer clearRealCloudBytes(cfRaw)
	eoRaw, eoObject, err := readRealCloudProviderRawObjects(ctx, "edgeone", configuration.EdgeOne.RawBucket, eoSinkPrefix, clients.listEO, clients.openEO)
	if err != nil {
		return realCloudProviderRawAttestation{}, err
	}
	defer clearRealCloudBytes(eoRaw)
	if containsRealEdgeForbidden(cfRaw, forbidden) || containsRealEdgeForbidden(eoRaw, forbidden) {
		return realCloudProviderRawAttestation{}, errors.New("raw provider export contains forbidden secret or entitlement material")
	}

	reconstructed, redactedSHA, err := reconstructRealCloudProviderLogs(environment, stages, cfRaw, eoRaw)
	if err != nil {
		return realCloudProviderRawAttestation{}, err
	}
	joinedSHA, err := compareRealCloudRawAndOperatorLogs(reconstructed, operatorLogs)
	if err != nil {
		return realCloudProviderRawAttestation{}, err
	}
	cfControlAfter, err := collectRealCloudCloudflareControl(ctx, environment, configuration, clients.cloudflare)
	if err != nil || realCloudCloudflareControlSHA(cfControlAfter) != realCloudCloudflareControlSHA(cfControl) {
		return realCloudProviderRawAttestation{}, errors.New("Cloudflare control plane changed across the provider attestation bracket")
	}
	eoControlAfter, err := collectRealCloudEdgeOneControl(ctx, environment, configuration, clients.edgeOne, clients.probeEOFunctionDomain)
	if err != nil || realCloudEdgeOneControlSHA(eoControlAfter) != realCloudEdgeOneControlSHA(eoControl) {
		return realCloudProviderRawAttestation{}, errors.New("EdgeOne control plane changed across the provider attestation bracket")
	}
	cfRawAfter, cfObjectAfter, err := readRealCloudProviderRawObjects(ctx, "cloudflare", configuration.Cloudflare.RawBucket, cfSinkPrefix, clients.listCF, clients.openCF)
	if err != nil {
		return realCloudProviderRawAttestation{}, err
	}
	defer clearRealCloudBytes(cfRawAfter)
	eoRawAfter, eoObjectAfter, err := readRealCloudProviderRawObjects(ctx, "edgeone", configuration.EdgeOne.RawBucket, eoSinkPrefix, clients.listEO, clients.openEO)
	if err != nil {
		return realCloudProviderRawAttestation{}, err
	}
	defer clearRealCloudBytes(eoRawAfter)
	if cfObjectAfter != cfObject || eoObjectAfter != eoObject || !bytes.Equal(cfRawAfter, cfRaw) || !bytes.Equal(eoRawAfter, eoRaw) {
		return realCloudProviderRawAttestation{}, errors.New("provider raw exports changed across the final attestation bracket")
	}
	providerDeploymentSHA, err := realCloudProviderDeploymentIdentity(environment, configuration)
	if err != nil {
		return realCloudProviderRawAttestation{}, err
	}
	attestation := realCloudProviderRawAttestation{
		Schema:                realCloudProviderCollectorSchema,
		CollectorSourceSHA256: sourceSHA, CollectorBuildSHA256: buildSHA,
		CollectorConfigSHA256: realCloudLowerSHA256(configurationBody), RawJoinedSHA256: joinedSHA,
		ProductConfigSHA256:      configuration.ProductConfigSHA256,
		ProviderDeploymentSHA256: providerDeploymentSHA,
		RedactedClosureSHA256:    redactedSHA, RawRecords: len(reconstructed),
		CFAccountID: configuration.Cloudflare.AccountID, CFZoneID: configuration.Cloudflare.ZoneID, CFZoneIdentitySHA256: cfControl.zoneSHA,
		CFLogpushJobID: configuration.Cloudflare.LogpushJobID, CFLogpushJobSHA256: cfControl.jobSHA,
		CFLogReaderIdentitySHA256:  configuration.Cloudflare.RawReaderAccessKeySHA256,
		CFLogWriterIdentitySHA256:  cfControl.writerSHA,
		CFLogControlIdentitySHA256: configuration.Cloudflare.LogControlAccessKeySHA256,
		CFRawObjectIdentitySHA256:  cfObject.identitySHA, CFRawObjectETag: cfObject.etag, CFRawObjectSHA256: cfObject.bodySHA, CFRawObjects: cfObject.objects,
		CFWorkerScript: configuration.Cloudflare.WorkerScript, CFWorkerDeploymentID: cfControl.auth.deploymentID,
		CFWorkerVersionID: cfControl.auth.versionID, CFWorkerVersionETag: cfControl.auth.versionETag, CFWorkerContentSHA256: cfControl.auth.contentSHA,
		CFWorkerBindingsSHA256: cfControl.authBindingsSHA, CFWorkerRuntimeSHA256: cfControl.authRuntimeSHA,
		CFWorkerSecuritySHA256: cfControl.auth.securitySHA, CFWorkerRoutesSHA256: cfControl.routeSHA, CFWorkerInventorySHA256: cfControl.inventorySHA,
		CFOriginWorkerScript: configuration.Cloudflare.OriginWorkerScript, CFOriginDeploymentID: cfControl.origin.deploymentID,
		CFOriginVersionID: cfControl.origin.versionID, CFOriginVersionETag: cfControl.origin.versionETag,
		CFOriginContentSHA256: cfControl.origin.contentSHA, CFOriginBindingsSHA256: cfControl.originBindingsSHA,
		CFOriginSecuritySHA256: cfControl.origin.securitySHA,
		CFOriginExposureSHA256: cfControl.originExposureSHA,
		CFTokenVerifierService: configuration.Cloudflare.TokenVerifierService, CFTokenVerifierVersionID: cfControl.verifier.versionID,
		CFTokenVerifierVersionETag: cfControl.verifier.versionETag, CFTokenVerifierContentSHA256: cfControl.verifier.contentSHA,
		CFTokenVerifierBindingsSHA256:  cfControl.verifierBindingsSHA,
		CFTokenVerifierSecuritySHA256:  cfControl.verifier.securitySHA,
		EdgeOneZoneID:                  configuration.EdgeOne.ZoneID,
		EdgeOneZoneIdentitySHA256:      eoControl.zoneSHA,
		EdgeOneDomainsSHA256:           eoControl.domainsSHA,
		EdgeOneLogTaskID:               configuration.EdgeOne.RealtimeLogTaskID,
		EdgeOneLogArea:                 configuration.EdgeOne.RealtimeLogArea,
		EdgeOneLogTaskSHA256:           eoControl.taskSHA,
		EdgeOneLogReaderIdentitySHA256: configuration.EdgeOne.RawReaderAccessKeySHA256,
		EdgeOneLogWriterIdentitySHA256: eoControl.writerSHA,
		EdgeOneRawObjectIdentitySHA256: eoObject.identitySHA, EdgeOneRawObjectETag: eoObject.etag, EdgeOneRawObjectSHA256: eoObject.bodySHA, EdgeOneRawObjects: eoObject.objects,
		EdgeOneFunctionID: configuration.EdgeOne.FunctionID, EdgeOneFunctionDomainSHA256: eoControl.domainSHA,
		EdgeOneFunctionDomainBehaviorSHA256:  eoControl.domainBehaviorSHA,
		EdgeOneFunctionContentSHA256:         eoControl.contentSHA,
		EdgeOneFunctionComponentsSHA256:      eoControl.componentsSHA,
		EdgeOneFunctionReplicasSHA256:        eoControl.replicasSHA,
		EdgeOneFunctionRuntimeSHA256:         eoControl.runtimeSHA,
		EdgeOneFunctionRulesSHA256:           eoControl.rulesSHA,
		EdgeOneTokenVerifierDeploymentSHA256: configuration.Runtime.EdgeOneTokenVerifierDeploymentSHA256,
	}
	encoded, err := json.Marshal(attestation)
	if err != nil || containsRealEdgeForbidden(encoded, forbidden) || containsRealEdgeURLLeak(encoded) {
		return realCloudProviderRawAttestation{}, errors.New("provider attestation is not safely redacted")
	}
	return attestation, nil
}

func realCloudCloudflareControlSHA(control realCloudCloudflareControlEvidence) string {
	body, _ := json.Marshal([]string{
		control.zoneSHA, control.jobSHA, control.writerSHA, control.routeSHA, control.inventorySHA, control.originExposureSHA,
		control.authBindingsSHA, control.authRuntimeSHA, control.originBindingsSHA, control.verifierBindingsSHA,
		control.auth.script, control.auth.deploymentID, control.auth.versionID, control.auth.versionETag, control.auth.contentSHA, control.auth.securitySHA,
		control.auth.compatibilityDate, strings.Join(control.auth.compatibilityFlags, "\x00"),
		control.origin.script, control.origin.deploymentID, control.origin.versionID, control.origin.versionETag, control.origin.contentSHA, control.origin.securitySHA,
		control.origin.compatibilityDate, strings.Join(control.origin.compatibilityFlags, "\x00"),
		control.verifier.script, control.verifier.deploymentID, control.verifier.versionID, control.verifier.versionETag, control.verifier.contentSHA, control.verifier.securitySHA,
		control.verifier.compatibilityDate, strings.Join(control.verifier.compatibilityFlags, "\x00"),
	})
	return realCloudLowerSHA256(body)
}

func realCloudEdgeOneControlSHA(control realCloudEdgeOneControlEvidence) string {
	body, _ := json.Marshal([]string{
		control.zoneSHA, control.domainsSHA, control.taskSHA, control.writerSHA, control.domainSHA, control.domainBehaviorSHA, control.contentSHA,
		control.componentsSHA, control.replicasSHA, control.runtimeSHA, control.rulesSHA,
	})
	return realCloudLowerSHA256(body)
}

type realCloudCloudflareControlEvidence struct {
	zoneSHA, jobSHA, writerSHA, routeSHA, inventorySHA, originExposureSHA, authBindingsSHA, authRuntimeSHA, originBindingsSHA, verifierBindingsSHA string
	auth, origin, verifier                                                                                                                         realCloudCloudflareWorkerEvidence
}

type realCloudCloudflareWorkerEvidence struct {
	script, deploymentID, versionID, versionETag, contentSHA, securitySHA, compatibilityDate string
	compatibilityFlags                                                                       []string
	bindings                                                                                 []workers.ScriptVersionGetResponseResourcesBinding
}

func collectRealCloudCloudflareControl(ctx context.Context, environment realCloudEnvironment, providerConfiguration realCloudProviderAttestationConfig, client *cloudflareapi.Client) (realCloudCloudflareControlEvidence, error) {
	var result realCloudCloudflareControlEvidence
	configuration := providerConfiguration.Cloudflare
	zone, err := client.Zones.Get(ctx, zones.ZoneGetParams{ZoneID: cloudflareapi.F(configuration.ZoneID)})
	if err != nil || zone == nil {
		return result, errors.New("Cloudflare zone query failed")
	}
	result.zoneSHA, err = validateRealCloudCloudflareZone(zone, environment, configuration)
	*zone = zones.Zone{}
	if err != nil {
		return result, err
	}
	jobs, err := client.Logpush.Jobs.List(ctx, logpush.JobListParams{ZoneID: cloudflareapi.F(configuration.ZoneID)})
	if err != nil || jobs == nil {
		return result, errors.New("Cloudflare dedicated zone Logpush inventory query failed")
	}
	defer func() {
		for index := range jobs.Result {
			jobs.Result[index] = logpush.LogpushJob{}
		}
		*jobs = *newCloudflareLogpushPage()
	}()
	configuredJob, err := selectRealCloudCloudflareLogpushJob(jobs.Result, environment, configuration)
	if err != nil {
		return result, err
	}
	result.jobSHA, result.writerSHA, err = validateRealCloudCloudflareLogpushJob(&jobs.Result[configuredJob], environment, configuration)
	if err != nil {
		return result, err
	}
	result.auth, err = collectRealCloudCloudflareActiveWorker(ctx, client, configuration.AccountID, configuration.WorkerScript,
		"edge/dist/cloudflare-worker.mjs", "", configuration.WorkerRuntime, true)
	if err != nil {
		return result, fmt.Errorf("Cloudflare auth Worker attestation: %w", err)
	}
	result.origin, err = collectRealCloudCloudflareActiveWorker(ctx, client, configuration.AccountID, configuration.OriginWorkerScript,
		"edge/dist/cloudflare-origin-worker.mjs", "", configuration.OriginWorkerRuntime, true)
	if err != nil {
		return result, fmt.Errorf("Cloudflare origin Worker attestation: %w", err)
	}
	result.verifier, err = collectRealCloudCloudflareActiveWorker(ctx, client, configuration.AccountID, configuration.TokenVerifierService,
		"", configuration.TokenVerifierContentSHA256, configuration.TokenVerifierRuntime, true)
	if err != nil {
		return result, fmt.Errorf("Cloudflare token verifier Worker attestation: %w", err)
	}
	result.verifierBindingsSHA, err = validateRealCloudCloudflareVerifierBindings(result.verifier.bindings)
	if err != nil || result.verifierBindingsSHA != configuration.TokenVerifierBindingsSHA256 {
		return result, errors.New("Cloudflare token verifier binding inventory differs from the administrator-pinned digest")
	}
	result.authBindingsSHA, result.authRuntimeSHA, err = validateRealCloudCloudflareAuthBindings(result.auth.bindings, environment, providerConfiguration)
	if err != nil {
		return result, err
	}
	result.originBindingsSHA, err = validateRealCloudCloudflareOriginBindings(result.origin.bindings, environment.CFR2Bucket)
	if err != nil {
		return result, err
	}
	result.routeSHA, result.originExposureSHA, err = collectRealCloudCloudflareRoutingClosure(ctx, client, environment, configuration)
	if err != nil {
		return result, err
	}
	stableRouteSHA, stableExposureSHA, err := collectRealCloudCloudflareRoutingClosure(ctx, client, environment, configuration)
	if err != nil || stableRouteSHA != result.routeSHA || stableExposureSHA != result.originExposureSHA {
		return result, errors.New("Cloudflare complete Worker, route, domain, and exposure inventory changed while attested")
	}
	result.inventorySHA = result.routeSHA
	return result, nil
}

func selectRealCloudCloudflareLogpushJob(jobs []logpush.LogpushJob, environment realCloudEnvironment, configuration realCloudCloudflareAttestationConfig) (int, error) {
	configuredJob := -1
	for index := range jobs {
		job := &jobs[index]
		if job.ID == configuration.LogpushJobID {
			if configuredJob >= 0 {
				return -1, errors.New("Cloudflare shared zone repeats the configured SOW Logpush job")
			}
			configuredJob = index
			continue
		}
		if !job.Enabled {
			continue
		}
		if strings.Contains(job.DestinationConf, configuration.RawBucket) {
			return -1, errors.New("Cloudflare unrelated enabled Logpush job can write the SOW raw bucket")
		}
		if job.Dataset == logpush.LogpushJobDatasetHTTPRequests && realCloudCloudflareLogpushJobMayIncludeHosts(job, hostOnly(environment.CFCDNBase), hostOnly(environment.CFBetaCDNBase)) {
			return -1, errors.New("Cloudflare unrelated enabled HTTP Logpush job can include a reviewed host")
		}
	}
	if configuredJob < 0 {
		return -1, errors.New("Cloudflare shared zone omits the configured SOW Logpush job")
	}
	return configuredJob, nil
}

// newCloudflareLogpushPage exists so the SDK page, including its private raw
// response cache, can be overwritten immediately after destination credentials
// have been validated and redacted.
func newCloudflareLogpushPage() *pagination.SinglePage[logpush.LogpushJob] {
	return &pagination.SinglePage[logpush.LogpushJob]{}
}

func collectRealCloudCloudflareActiveWorker(
	ctx context.Context,
	client *cloudflareapi.Client,
	accountID, script, repositoryBundle, expectedSHA string,
	runtimeContract realCloudCloudflareWorkerRuntimeContract,
	attestSecurity bool,
) (realCloudCloudflareWorkerEvidence, error) {
	var result realCloudCloudflareWorkerEvidence
	first, err := client.Workers.Scripts.Deployments.List(ctx, script, workers.ScriptDeploymentListParams{AccountID: cloudflareapi.F(accountID)})
	if err != nil {
		return result, errors.New("active deployment query failed")
	}
	deploymentID, versionID, err := exactRealCloudCloudflareDeployment(first)
	if err != nil {
		return result, err
	}
	version, err := client.Workers.Scripts.Versions.Get(ctx, script, versionID, workers.ScriptVersionGetParams{AccountID: cloudflareapi.F(accountID)})
	if err != nil || version == nil || version.ID != versionID || !validRealCloudProviderETag(version.Resources.Script.Etag) {
		return result, errors.New("active version is absent or inconsistent")
	}
	if attestSecurity && (validateRealCloudCloudflareWorkerRuntimeContract(runtimeContract) != nil ||
		version.Resources.ScriptRuntime.CompatibilityDate != runtimeContract.CompatibilityDate ||
		!equalRealCloudStrings(version.Resources.ScriptRuntime.CompatibilityFlags, runtimeContract.CompatibilityFlags) ||
		version.Resources.ScriptRuntime.UsageModel != workers.ScriptVersionGetResponseResourcesScriptRuntimeUsageModelStandard ||
		version.Resources.ScriptRuntime.Limits.CPUMs != 0 || version.Resources.ScriptRuntime.MigrationTag != "" ||
		version.Resources.ScriptRuntime.JSON.CompatibilityDate.IsMissing() || version.Resources.ScriptRuntime.JSON.CompatibilityFlags.IsMissing() ||
		version.Resources.ScriptRuntime.JSON.UsageModel.IsMissing() || len(version.Resources.ScriptRuntime.JSON.ExtraFields) != 0 ||
		len(version.Resources.ScriptRuntime.Limits.JSON.ExtraFields) != 0) {
		return result, errors.New("active version runtime differs from the administrator-pinned closed runtime contract")
	}
	response, err := client.Workers.Scripts.Content.Get(ctx, script, workers.ScriptContentGetParams{AccountID: cloudflareapi.F(accountID)})
	if err != nil || response == nil {
		return result, errors.New("active content query failed")
	}
	content, err := readRealCloudCloudflareWorkerContent(response)
	if err != nil {
		return result, err
	}
	defer clearRealCloudBytes(content)
	contentSHA := realCloudLowerSHA256(content)
	if repositoryBundle != "" {
		wanted, readErr := readRealCloudProviderRepositoryFile(repositoryBundle, realCloudProviderMaxContentBytes)
		if readErr != nil {
			return result, readErr
		}
		defer clearRealCloudBytes(wanted)
		if !bytes.Equal(content, wanted) {
			return result, errors.New("active content differs from the reviewed in-repo bundle")
		}
	} else if !validRealCloudLowerSHA256(expectedSHA) || contentSHA != expectedSHA {
		return result, errors.New("active external content differs from the independently reviewed digest")
	}
	securitySHA := ""
	if attestSecurity {
		securitySHA, err = collectRealCloudCloudflareWorkerSecurityObservation(ctx, client, accountID, script, runtimeContract)
		if err != nil {
			return result, err
		}
		stableSecuritySHA, stableErr := collectRealCloudCloudflareWorkerSecurityObservation(ctx, client, accountID, script, runtimeContract)
		if stableErr != nil || stableSecuritySHA != securitySHA {
			return result, errors.New("active Worker runtime, trigger, telemetry, or public exposure changed while attested")
		}
	}
	second, err := client.Workers.Scripts.Deployments.List(ctx, script, workers.ScriptDeploymentListParams{AccountID: cloudflareapi.F(accountID)})
	if err != nil {
		return result, errors.New("active deployment recheck failed")
	}
	secondDeployment, secondVersion, err := exactRealCloudCloudflareDeployment(second)
	if err != nil || secondDeployment != deploymentID || secondVersion != versionID {
		return result, errors.New("active deployment changed while its content was attested")
	}
	result = realCloudCloudflareWorkerEvidence{
		script: script, deploymentID: deploymentID, versionID: versionID, versionETag: version.Resources.Script.Etag,
		contentSHA: contentSHA, securitySHA: securitySHA, compatibilityDate: version.Resources.ScriptRuntime.CompatibilityDate,
		compatibilityFlags: append([]string(nil), version.Resources.ScriptRuntime.CompatibilityFlags...),
		bindings:           append([]workers.ScriptVersionGetResponseResourcesBinding(nil), version.Resources.Bindings...),
	}
	return result, nil
}

func collectRealCloudCloudflareWorkerSecurityObservation(
	ctx context.Context,
	client *cloudflareapi.Client,
	accountID, script string,
	runtimeContract realCloudCloudflareWorkerRuntimeContract,
) (string, error) {
	settings, err := client.Workers.Scripts.ScriptAndVersionSettings.Get(ctx, script, workers.ScriptScriptAndVersionSettingGetParams{
		AccountID: cloudflareapi.F(accountID),
	})
	if err != nil || settings == nil {
		return "", errors.New("Cloudflare Worker settings query failed")
	}
	if settings.JSON.CompatibilityDate.IsMissing() || settings.JSON.CompatibilityFlags.IsMissing() || settings.JSON.CacheOptions.IsMissing() ||
		settings.JSON.Limits.IsMissing() || settings.JSON.Logpush.IsMissing() || settings.JSON.Observability.IsMissing() ||
		settings.JSON.Placement.IsMissing() || settings.JSON.Tags.IsMissing() || settings.JSON.TailConsumers.IsMissing() || settings.JSON.UsageModel.IsMissing() ||
		len(settings.JSON.ExtraFields) != 0 || len(settings.CacheOptions.JSON.ExtraFields) != 0 || len(settings.Limits.JSON.ExtraFields) != 0 ||
		len(settings.Observability.JSON.ExtraFields) != 0 || len(settings.Observability.Logs.JSON.ExtraFields) != 0 ||
		len(settings.Observability.Traces.JSON.ExtraFields) != 0 || len(settings.Placement.JSON.ExtraFields) != 0 {
		return "", errors.New("Cloudflare Worker settings response is incomplete or contains unreviewed fields")
	}
	if settings.CompatibilityDate != runtimeContract.CompatibilityDate || !equalRealCloudStrings(settings.CompatibilityFlags, runtimeContract.CompatibilityFlags) ||
		settings.Logpush || settings.CacheOptions.Enabled || settings.CacheOptions.CrossVersionCache ||
		settings.Limits.CPUMs != 0 || settings.Limits.Subrequests != 0 ||
		settings.Placement.Mode != "" || settings.Placement.Host != "" || settings.Placement.Hostname != "" || settings.Placement.Region != "" || settings.Placement.Target != nil ||
		settings.UsageModel != workers.ScriptScriptAndVersionSettingGetResponseUsageModelStandard ||
		settings.Observability.Enabled || settings.Observability.HeadSamplingRate != 0 ||
		settings.Observability.Logs.Enabled || settings.Observability.Logs.InvocationLogs || settings.Observability.Logs.Persist ||
		settings.Observability.Logs.HeadSamplingRate != 0 || len(settings.Observability.Logs.Destinations) != 0 ||
		settings.Observability.Traces.Enabled || settings.Observability.Traces.Persist || settings.Observability.Traces.HeadSamplingRate != 0 ||
		settings.Observability.Traces.PropagationPolicy != "" || len(settings.Observability.Traces.Destinations) != 0 ||
		len(settings.Tags) != 0 || len(settings.TailConsumers) != 0 {
		return "", errors.New("Cloudflare Worker settings differ from the closed runtime and telemetry policy")
	}
	schedules, err := client.Workers.Scripts.Schedules.Get(ctx, script, workers.ScriptScheduleGetParams{AccountID: cloudflareapi.F(accountID)})
	if err != nil || schedules == nil || schedules.JSON.Schedules.IsMissing() || len(schedules.JSON.ExtraFields) != 0 || len(schedules.Schedules) != 0 {
		return "", errors.New("Cloudflare Worker has an incomplete or non-empty schedule inventory")
	}
	exposure, err := client.Workers.Scripts.Subdomain.Get(ctx, script, workers.ScriptSubdomainGetParams{AccountID: cloudflareapi.F(accountID)})
	if err != nil || exposure == nil || exposure.JSON.Enabled.IsMissing() || exposure.JSON.PreviewsEnabled.IsMissing() ||
		len(exposure.JSON.ExtraFields) != 0 || exposure.Enabled || exposure.PreviewsEnabled {
		return "", errors.New("Cloudflare Worker workers.dev or preview URL exposure is not closed")
	}
	body, _ := json.Marshal(struct {
		Script             string   `json:"script"`
		CompatibilityDate  string   `json:"compatibility_date"`
		CompatibilityFlags []string `json:"compatibility_flags"`
		UsageModel         string   `json:"usage_model"`
		Closed             bool     `json:"closed"`
	}{script, settings.CompatibilityDate, append([]string(nil), settings.CompatibilityFlags...), string(settings.UsageModel), true})
	return realCloudLowerSHA256(body), nil
}

func validateRealCloudCloudflareAuthBindings(
	bindings []workers.ScriptVersionGetResponseResourcesBinding,
	environment realCloudEnvironment,
	providerConfiguration realCloudProviderAttestationConfig,
) (string, string, error) {
	configuration := providerConfiguration.Cloudflare
	wantedServices := map[string]struct {
		service, environment string
	}{
		"ORIGIN":         {configuration.OriginWorkerScript, configuration.OriginWorkerEnvironment},
		"TOKEN_VERIFIER": {configuration.TokenVerifierService, configuration.TokenVerifierEnvironment},
	}
	wantedVariables, err := realCloudProviderExpectedRuntimeVariables(environment, providerConfiguration.Runtime, "cloudflare")
	if err != nil {
		return "", "", err
	}
	wantedSecrets := make(map[string]bool, len(providerConfiguration.Runtime.CloudflareSecretNames))
	for _, name := range providerConfiguration.Runtime.CloudflareSecretNames {
		wantedSecrets[name] = false
	}
	seen := make(map[string]struct{}, len(bindings))
	serviceRows := make([]string, 0, len(wantedServices))
	runtimeRows := make([]string, 0, len(wantedVariables)+len(wantedSecrets))
	for _, binding := range bindings {
		if _, duplicate := seen[binding.Name]; duplicate || !validRealCloudProviderSecretName(binding.Name) {
			return "", "", errors.New("Cloudflare auth Worker repeats or has an invalid binding name")
		}
		seen[binding.Name] = struct{}{}
		switch binding.Type {
		case workers.ScriptVersionGetResponseResourcesBindingsTypeService:
			expected, found := wantedServices[binding.Name]
			if !found || binding.Service != expected.service || binding.Environment != expected.environment || binding.Entrypoint != "" {
				return "", "", errors.New("Cloudflare auth Worker service binding differs from the exact origin or token verifier service")
			}
			delete(wantedServices, binding.Name)
			serviceRows = append(serviceRows, strings.Join([]string{binding.Name, string(binding.Type), binding.Service, binding.Environment}, "\x00"))
		case workers.ScriptVersionGetResponseResourcesBindingsTypePlainText:
			expected, found := wantedVariables[binding.Name]
			if !found || binding.Text != expected {
				return "", "", errors.New("Cloudflare auth Worker runtime variable differs from the exact clean-URL deployment contract")
			}
			delete(wantedVariables, binding.Name)
			runtimeRows = append(runtimeRows, strings.Join([]string{binding.Name, string(binding.Type), binding.Text}, "\x00"))
		case workers.ScriptVersionGetResponseResourcesBindingsTypeSecretText:
			if _, found := wantedSecrets[binding.Name]; !found {
				return "", "", errors.New("Cloudflare auth Worker has an unexpected or mode-inapplicable secret")
			}
			delete(wantedSecrets, binding.Name)
			runtimeRows = append(runtimeRows, strings.Join([]string{binding.Name, string(binding.Type), "secret-present"}, "\x00"))
		default:
			return "", "", errors.New("Cloudflare auth Worker has an unexpected capability binding")
		}
	}
	if len(wantedServices) != 0 || len(wantedVariables) != 0 || len(wantedSecrets) != 0 {
		return "", "", errors.New("Cloudflare auth Worker lacks an exact service, runtime variable, or secret binding")
	}
	sort.Strings(serviceRows)
	sort.Strings(runtimeRows)
	serviceBody, _ := json.Marshal(serviceRows)
	runtimeBody, _ := json.Marshal(runtimeRows)
	return realCloudLowerSHA256(serviceBody), realCloudLowerSHA256(runtimeBody), nil
}

func validateRealCloudCloudflareVerifierBindings(bindings []workers.ScriptVersionGetResponseResourcesBinding) (string, error) {
	seen := make(map[string]struct{}, len(bindings))
	rows := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		if _, duplicate := seen[binding.Name]; duplicate || !validRealCloudProviderSecretName(binding.Name) {
			return "", errors.New("Cloudflare token verifier repeats or has an invalid binding name")
		}
		seen[binding.Name] = struct{}{}
		var target string
		switch binding.Type {
		case workers.ScriptVersionGetResponseResourcesBindingsTypeSecretText:
			target = "secret-present"
		case workers.ScriptVersionGetResponseResourcesBindingsTypePlainText:
			target = "text-sha256:" + realCloudLowerSHA256([]byte(binding.Text))
		case workers.ScriptVersionGetResponseResourcesBindingsTypeService:
			if !validRealCloudProviderIdentifier(binding.Service, 128) || !validRealCloudProviderOptionalIdentifier(binding.Environment, 128) || binding.Entrypoint != "" {
				return "", errors.New("Cloudflare token verifier service target is invalid")
			}
			target = strings.Join([]string{binding.Service, binding.Environment}, "\x00")
		case workers.ScriptVersionGetResponseResourcesBindingsTypeKVNamespace:
			if !validRealCloudProviderIdentifier(binding.NamespaceID, 256) {
				return "", errors.New("Cloudflare token verifier KV target is invalid")
			}
			target = binding.NamespaceID
		case workers.ScriptVersionGetResponseResourcesBindingsTypeD1:
			if !validRealCloudProviderIdentifier(binding.DatabaseID, 256) {
				return "", errors.New("Cloudflare token verifier D1 target is invalid")
			}
			target = binding.DatabaseID
		default:
			return "", errors.New("Cloudflare token verifier has an unreviewable or excessive capability binding")
		}
		rows = append(rows, strings.Join([]string{binding.Name, string(binding.Type), target}, "\x00"))
	}
	sort.Strings(rows)
	body, _ := json.Marshal(rows)
	return realCloudLowerSHA256(body), nil
}

func validateRealCloudCloudflareOriginBindings(bindings []workers.ScriptVersionGetResponseResourcesBinding, bucket string) (string, error) {
	if len(bindings) != 1 || bindings[0].Name != "REPOSITORY" || bindings[0].Type != workers.ScriptVersionGetResponseResourcesBindingsTypeR2Bucket || bindings[0].BucketName != bucket {
		return "", errors.New("Cloudflare origin Worker is not capability-limited to the exact REPOSITORY R2 binding")
	}
	body, _ := json.Marshal([]string{bindings[0].Name, string(bindings[0].Type), bindings[0].BucketName})
	return realCloudLowerSHA256(body), nil
}

func collectRealCloudCloudflareRoutingClosure(ctx context.Context, client *cloudflareapi.Client, environment realCloudEnvironment, configuration realCloudCloudflareAttestationConfig) (string, string, error) {
	mainHost := hostOnly(environment.CFCDNBase)
	betaHost := hostOnly(environment.CFBetaCDNBase)
	wantedPatterns := map[string]bool{
		mainHost + "/*": false,
		betaHost + "/*": false,
	}
	wantedScripts := map[string]bool{configuration.WorkerScript: false, configuration.OriginWorkerScript: false, configuration.TokenVerifierService: false}
	accountRoutes := make([]string, 0, 2)
	inventoryRows := make([]string, 0, 32)
	scriptIDs := make(map[string]struct{})
	scriptPager := client.Workers.Scripts.ListAutoPaging(ctx, workers.ScriptListParams{AccountID: cloudflareapi.F(configuration.AccountID)})
	for scriptPager.Next() {
		script := scriptPager.Current()
		if scriptPager.Index() > realCloudProviderMaxInventoryItems || !validRealCloudProviderIdentifier(script.ID, 128) ||
			script.JSON.ID.IsMissing() || script.JSON.Routes.IsMissing() || script.JSON.TailConsumers.IsMissing() || len(script.JSON.ExtraFields) != 0 {
			return "", "", errors.New("Cloudflare account Worker inventory is oversized or contains an invalid identity")
		}
		if _, duplicate := scriptIDs[script.ID]; duplicate {
			return "", "", errors.New("Cloudflare account Worker inventory repeats a script")
		}
		scriptIDs[script.ID] = struct{}{}
		scriptRouteRows := make([]string, 0, len(script.Routes))
		for _, route := range script.Routes {
			if !validRealCloudProviderIdentifier(route.ID, 128) || strings.TrimSpace(route.Pattern) == "" ||
				route.JSON.ID.IsMissing() || route.JSON.Pattern.IsMissing() || route.JSON.Script.IsMissing() || len(route.JSON.ExtraFields) != 0 {
				return "", "", errors.New("Cloudflare account Worker inventory contains an incomplete route identity")
			}
			scriptRouteRows = append(scriptRouteRows, strings.Join([]string{route.ID, route.Pattern, route.Script}, "\x00"))
		}
		tailRows := make([]string, 0, len(script.TailConsumers))
		for _, consumer := range script.TailConsumers {
			if !validRealCloudProviderIdentifier(consumer.Service, 128) || !validRealCloudProviderOptionalIdentifier(consumer.Environment, 128) ||
				!validRealCloudProviderOptionalIdentifier(consumer.Namespace, 128) || consumer.JSON.Service.IsMissing() || len(consumer.JSON.ExtraFields) != 0 {
				return "", "", errors.New("Cloudflare account Worker inventory contains an incomplete tail-consumer identity")
			}
			tailRows = append(tailRows, strings.Join([]string{consumer.Service, consumer.Environment, consumer.Namespace}, "\x00"))
		}
		sort.Strings(scriptRouteRows)
		sort.Strings(tailRows)
		scriptBody, _ := json.Marshal(struct {
			ID            string   `json:"id"`
			Routes        []string `json:"routes"`
			TailConsumers []string `json:"tail_consumers"`
		}{script.ID, scriptRouteRows, tailRows})
		inventoryRows = append(inventoryRows, "script\x00"+string(scriptBody))
		if _, relevant := wantedScripts[script.ID]; !relevant {
			continue
		}
		if wantedScripts[script.ID] {
			return "", "", errors.New("Cloudflare account Worker inventory repeats a security-sensitive script")
		}
		wantedScripts[script.ID] = true
		if len(script.TailConsumers) != 0 {
			return "", "", errors.New("Cloudflare attested Worker has a tail consumer")
		}
		if script.ID != configuration.WorkerScript && len(script.Routes) != 0 {
			return "", "", errors.New("Cloudflare service-only origin or token verifier Worker has a public account route")
		}
		for _, route := range script.Routes {
			if route.Script != "" && route.Script != configuration.WorkerScript {
				return "", "", errors.New("Cloudflare account route does not bind the exact auth Worker")
			}
			if _, expected := wantedPatterns[route.Pattern]; !expected || wantedPatterns[route.Pattern] {
				return "", "", errors.New("Cloudflare account auth Worker route set contains an extra or duplicate route")
			}
			wantedPatterns[route.Pattern] = true
			accountRoutes = append(accountRoutes, route.Pattern+"\x00"+configuration.WorkerScript)
		}
	}
	if err := scriptPager.Err(); err != nil {
		return "", "", errors.New("Cloudflare account Worker inventory query failed")
	}
	for _, found := range wantedScripts {
		if !found {
			return "", "", errors.New("Cloudflare account Worker inventory omits an attested script")
		}
	}
	for _, found := range wantedPatterns {
		if !found {
			return "", "", errors.New("Cloudflare account inventory does not bind both main and beta routes to the auth Worker")
		}
	}
	for pattern := range wantedPatterns {
		wantedPatterns[pattern] = false
	}
	sanitizedRoutes := make([]string, 0, 2)
	routeIDs := make(map[string]struct{})
	relevantRouteIDs := make(map[string]struct{}, 2)
	routePager := client.Workers.Routes.ListAutoPaging(ctx, workers.RouteListParams{ZoneID: cloudflareapi.F(configuration.ZoneID)})
	for routePager.Next() {
		route := routePager.Current()
		if routePager.Index() > realCloudProviderMaxInventoryItems || !validRealCloudProviderIdentifier(route.ID, 128) ||
			strings.TrimSpace(route.Pattern) == "" || route.JSON.ID.IsMissing() || route.JSON.Pattern.IsMissing() || route.JSON.Script.IsMissing() || len(route.JSON.ExtraFields) != 0 {
			return "", "", errors.New("Cloudflare zone route inventory is oversized or contains an invalid identity")
		}
		if _, duplicate := routeIDs[route.ID]; duplicate {
			return "", "", errors.New("Cloudflare zone route inventory repeats a route")
		}
		routeIDs[route.ID] = struct{}{}
		inventoryRows = append(inventoryRows, strings.Join([]string{"route", route.ID, route.Pattern, route.Script}, "\x00"))
		if _, expected := wantedPatterns[route.Pattern]; !expected {
			if route.Script == configuration.WorkerScript || realCloudCloudflareRouteMayMatchHost(route.Pattern, mainHost) || realCloudCloudflareRouteMayMatchHost(route.Pattern, betaHost) {
				return "", "", errors.New("Cloudflare shared zone has a route outside the exact auth Worker closure that can expose or overlap a reviewed host")
			}
			continue
		}
		if route.Script != configuration.WorkerScript {
			return "", "", errors.New("Cloudflare reviewed host route does not bind the exact auth Worker")
		}
		if wantedPatterns[route.Pattern] {
			return "", "", errors.New("Cloudflare auth Worker route set contains a duplicate route")
		}
		wantedPatterns[route.Pattern] = true
		relevantRouteIDs[route.ID] = struct{}{}
		sanitizedRoutes = append(sanitizedRoutes, route.Pattern+"\x00"+route.Script)
	}
	if err := routePager.Err(); err != nil {
		return "", "", errors.New("Cloudflare Worker route query failed")
	}
	if len(relevantRouteIDs) != 2 {
		return "", "", errors.New("Cloudflare zone must contain exactly the main and beta auth routes within the reviewed host closure")
	}
	for _, found := range wantedPatterns {
		if !found {
			return "", "", errors.New("Cloudflare main and beta hosts are not both routed to the exact auth Worker")
		}
	}
	domainIDs := make(map[string]struct{})
	domainPager := client.Workers.Domains.ListAutoPaging(ctx, workers.DomainListParams{AccountID: cloudflareapi.F(configuration.AccountID)})
	for domainPager.Next() {
		domain := domainPager.Current()
		//lint:ignore SA1019 The pinned Cloudflare SDK still exposes Environment in the inventory wire contract.
		domainEnvironment := domain.Environment
		if domainPager.Index() > realCloudProviderMaxInventoryItems || !validRealCloudProviderIdentifier(domain.ID, 128) ||
			!validRealCloudProviderIdentifier(domain.CERTID, 128) || !validRealCloudProviderIdentifier(domain.Service, 128) ||
			!validRealCloudProviderIdentifier(domain.ZoneID, 128) || !validRealCloudProviderIdentifier(domain.ZoneName, 253) ||
			!validRealCloudProviderOptionalIdentifier(domainEnvironment, 128) || strings.TrimSpace(domain.Hostname) == "" ||
			domain.Hostname != strings.ToLower(domain.Hostname) || strings.HasSuffix(domain.Hostname, ".") ||
			domain.JSON.ID.IsMissing() || domain.JSON.CERTID.IsMissing() || domain.JSON.Hostname.IsMissing() || domain.JSON.Service.IsMissing() ||
			domain.JSON.ZoneID.IsMissing() || domain.JSON.ZoneName.IsMissing() || len(domain.JSON.ExtraFields) != 0 {
			return "", "", errors.New("Cloudflare Worker custom-domain inventory is oversized or contains an invalid identity")
		}
		if _, duplicate := domainIDs[domain.ID]; duplicate {
			return "", "", errors.New("Cloudflare Worker custom-domain inventory repeats a domain")
		}
		domainIDs[domain.ID] = struct{}{}
		inventoryRows = append(inventoryRows, strings.Join([]string{"domain", domain.ID, domain.CERTID, domain.Hostname, domain.Service, domainEnvironment, domain.ZoneID, domain.ZoneName}, "\x00"))
		if _, relevant := wantedScripts[domain.Service]; relevant {
			return "", "", errors.New("Cloudflare attested Workers must not have a public custom domain outside exact zone routes")
		}
	}
	if err := domainPager.Err(); err != nil {
		return "", "", errors.New("Cloudflare Worker custom-domain query failed")
	}
	exposure := make([]string, 0, 3)
	for _, script := range []string{configuration.WorkerScript, configuration.OriginWorkerScript, configuration.TokenVerifierService} {
		subdomain, subdomainErr := client.Workers.Scripts.Subdomain.Get(ctx, script, workers.ScriptSubdomainGetParams{AccountID: cloudflareapi.F(configuration.AccountID)})
		if subdomainErr != nil || subdomain == nil || subdomain.Enabled || subdomain.PreviewsEnabled {
			return "", "", errors.New("Cloudflare Worker workers.dev or preview URL exposure is not disabled")
		}
		exposure = append(exposure, script+"\x00disabled")
	}
	sort.Strings(accountRoutes)
	sort.Strings(sanitizedRoutes)
	sort.Strings(exposure)
	sort.Strings(inventoryRows)
	routeBody, _ := json.Marshal(struct {
		Account   []string `json:"account"`
		Zone      []string `json:"zone"`
		Inventory []string `json:"inventory"`
	}{accountRoutes, sanitizedRoutes, inventoryRows})
	exposureBody, _ := json.Marshal(exposure)
	return realCloudLowerSHA256(routeBody), realCloudLowerSHA256(exposureBody), nil
}

// Cloudflare route patterns use a single leading host wildcard and an optional
// trailing path wildcard rather than regular expressions. This predicate is
// deliberately conservative: malformed or unrecognized patterns are treated
// as overlapping so a shared production zone cannot hide a bypass behind a
// syntax the acceptance harness failed to model.
func realCloudCloudflareRouteMayMatchHost(pattern, host string) bool {
	if pattern == "" || pattern != strings.TrimSpace(pattern) || host == "" || host != strings.ToLower(host) ||
		strings.ContainsAny(pattern, "?#\t\r\n") || strings.Contains(pattern, "%") {
		return true
	}
	remaining := pattern
	lower := strings.ToLower(remaining)
	switch {
	case strings.HasPrefix(lower, "https://"):
		remaining = remaining[len("https://"):]
	case strings.HasPrefix(lower, "http://"):
		remaining = remaining[len("http://"):]
	case strings.Contains(lower, "://"):
		return true
	}
	hostPattern, pathPattern, found := strings.Cut(remaining, "/")
	if !found {
		pathPattern = ""
	}
	hostPattern = strings.ToLower(hostPattern)
	if hostPattern == "" || strings.ContainsAny(hostPattern, " :@[]") ||
		strings.Count(hostPattern, "*") > 1 || strings.Contains(pathPattern, "*") && !strings.HasSuffix(pathPattern, "*") ||
		strings.Count(pathPattern, "*") > 1 {
		return true
	}
	hostSuffix := hostPattern
	if strings.HasPrefix(hostSuffix, "*.") {
		hostSuffix = strings.TrimPrefix(hostSuffix, "*.")
	} else if strings.HasPrefix(hostSuffix, "*") {
		hostSuffix = strings.TrimPrefix(hostSuffix, "*")
	}
	if !validRealCloudCloudflareRouteHostSuffix(hostSuffix) {
		return true
	}
	switch {
	case strings.HasPrefix(hostPattern, "*."):
		suffix := strings.TrimPrefix(hostPattern, "*.")
		return suffix == "" || host != suffix && strings.HasSuffix(host, "."+suffix)
	case strings.HasPrefix(hostPattern, "*"):
		suffix := strings.TrimPrefix(hostPattern, "*")
		return suffix == "" || strings.HasSuffix(host, suffix)
	case strings.Contains(hostPattern, "*"):
		return true
	default:
		return hostPattern == host
	}
}

func validRealCloudCloudflareRouteHostSuffix(value string) bool {
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func TestRealCloudCloudflareRouteHostOverlapIsConservative(t *testing.T) {
	host := "pro.pigsty.io"
	for _, test := range []struct {
		pattern string
		match   bool
	}{
		{"pro.pigsty.io/*", true},
		{"https://pro.pigsty.io/private/*", true},
		{"*.pigsty.io/*", true},
		{"*pigsty.io/*", true},
		{"other.pigsty.io/*", false},
		{"https://other.pigsty.io/*", false},
		{"example.com/*", false},
		{"pro.pigsty.io/*.jpg", true},
		{"pro.pigsty.io/*?query", true},
		{"unrelated_bad_host/*", true},
		{"", true},
	} {
		if got := realCloudCloudflareRouteMayMatchHost(test.pattern, host); got != test.match {
			t.Fatalf("pattern %q overlap=%t want=%t", test.pattern, got, test.match)
		}
	}
}

func validateRealCloudCloudflareZone(zone *zones.Zone, environment realCloudEnvironment, configuration realCloudCloudflareAttestationConfig) (string, error) {
	if zone == nil || zone.ID != configuration.ZoneID || zone.Account.ID != configuration.AccountID || zone.Status != zones.ZoneStatusActive || zone.Paused || zone.Type != zones.TypeFull {
		return "", errors.New("Cloudflare zone is not the exact active full-zone contract")
	}
	name := strings.ToLower(strings.TrimSuffix(zone.Name, "."))
	ownerDesignated := isRealCloudOwnerDesignatedCloudflareTest(environment)
	if zone.Name != name {
		return "", errors.New("Cloudflare zone name is not canonical")
	}
	mode := "dedicated-non-production-zone"
	if ownerDesignated {
		if name != realCloudOwnerDesignatedCFZoneName {
			return "", errors.New("owner-designated Cloudflare hosts are outside the exact reviewed shared zone")
		}
		mode = "owner-designated-exact-hosts-in-shared-zone"
	} else if !hasRealCloudNonProductionHostMarker(name) || isRealCloudProductionDomain(name) || hasRealCloudProductionMarker(name) {
		return "", errors.New("Cloudflare zone name is not an explicit dedicated non-production identity")
	}
	for _, raw := range []string{environment.CFCDNBase, environment.CFBetaCDNBase} {
		host := hostOnly(raw)
		if host == name || !strings.HasSuffix(host, "."+name) {
			return "", errors.New("Cloudflare main or beta host is outside the attested dedicated zone")
		}
	}
	body, _ := json.Marshal([]any{zone.ID, zone.Account.ID, name, string(zone.Status), zone.Paused, string(zone.Type), mode})
	return realCloudLowerSHA256(body), nil
}

func TestRealCloudOwnerDesignatedCloudflareSharedZoneIsExact(t *testing.T) {
	environment := realCloudSafetyFixtureEnvironment()
	environment.CFR2Bucket = realCloudOwnerDesignatedCFR2Bucket
	environment.CFCDNBase = realCloudOwnerDesignatedCFCDNBase
	environment.CFBetaCDNBase = realCloudOwnerDesignatedCFBetaBase
	configuration := realCloudProviderConfigurationFixture(environment, strings.Repeat("a", 64)).Cloudflare
	zoneBody, err := json.Marshal(map[string]any{
		"id": configuration.ZoneID, "name": realCloudOwnerDesignatedCFZoneName,
		"account": map[string]string{"id": configuration.AccountID},
		"status":  "active", "paused": false, "type": "full",
	})
	if err != nil {
		t.Fatal(err)
	}
	var zone zones.Zone
	if err := json.Unmarshal(zoneBody, &zone); err != nil {
		t.Fatal(err)
	}
	if digest, err := validateRealCloudCloudflareZone(&zone, environment, configuration); err != nil || !validRealCloudLowerSHA256(digest) {
		t.Fatalf("exact owner-designated shared zone rejected digest=%q err=%v", digest, err)
	}
	zone.Name = "pigsty.cc"
	if _, err := validateRealCloudCloudflareZone(&zone, environment, configuration); err == nil {
		t.Fatal("owner-designated host tuple was reused for another Pigsty zone")
	}
	zone.Name = realCloudOwnerDesignatedCFZoneName
	mutated := environment
	mutated.CFBetaCDNBase = "https://other.pro.pigsty.io"
	if _, err := validateRealCloudCloudflareZone(&zone, mutated, configuration); err == nil {
		t.Fatal("unreviewed beta host reused the shared-zone exception")
	}
}

func realCloudCloudflareHostFilter(environment realCloudEnvironment) string {
	body, _ := json.Marshal(map[string]any{"where": map[string]any{"or": []map[string]string{
		{"key": "ClientRequestHost", "operator": "eq", "value": hostOnly(environment.CFCDNBase)},
		{"key": "ClientRequestHost", "operator": "eq", "value": hostOnly(environment.CFBetaCDNBase)},
	}}})
	return string(body)
}

type realCloudFilterTruth uint8

const (
	realCloudFilterFalse realCloudFilterTruth = iota
	realCloudFilterUnknown
	realCloudFilterTrue
)

func realCloudCloudflareLogpushJobMayIncludeHosts(job *logpush.LogpushJob, hosts ...string) bool {
	if job == nil {
		return true
	}
	var raw struct {
		Filter string `json:"filter"`
	}
	if err := json.Unmarshal([]byte(job.JSON.RawJSON()), &raw); err != nil || raw.Filter == "" {
		return true
	}
	for _, host := range hosts {
		if realCloudCloudflareFilterMayIncludeHost(raw.Filter, host) {
			return true
		}
	}
	return false
}

func realCloudCloudflareFilterMayIncludeHost(raw, host string) bool {
	if raw == "" || raw != strings.TrimSpace(raw) || host == "" || host != strings.ToLower(host) {
		return true
	}
	var expression any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&expression); err != nil {
		return true
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return true
	}
	return evaluateRealCloudCloudflareHostFilter(expression, host) != realCloudFilterFalse
}

func evaluateRealCloudCloudflareHostFilter(value any, host string) realCloudFilterTruth {
	object, ok := value.(map[string]any)
	if !ok || len(object) == 0 {
		return realCloudFilterUnknown
	}
	if where, found := object["where"]; found && len(object) == 1 {
		return evaluateRealCloudCloudflareHostFilter(where, host)
	}
	for _, operator := range []string{"and", "or"} {
		raw, found := object[operator]
		if !found || len(object) != 1 {
			continue
		}
		items, ok := raw.([]any)
		if !ok || len(items) == 0 {
			return realCloudFilterUnknown
		}
		if operator == "and" {
			result := realCloudFilterTrue
			for _, item := range items {
				current := evaluateRealCloudCloudflareHostFilter(item, host)
				if current == realCloudFilterFalse {
					return realCloudFilterFalse
				}
				if current == realCloudFilterUnknown {
					result = realCloudFilterUnknown
				}
			}
			return result
		}
		result := realCloudFilterFalse
		for _, item := range items {
			current := evaluateRealCloudCloudflareHostFilter(item, host)
			if current == realCloudFilterTrue {
				return realCloudFilterTrue
			}
			if current == realCloudFilterUnknown {
				result = realCloudFilterUnknown
			}
		}
		return result
	}
	key, keyOK := object["key"].(string)
	operator, operatorOK := object["operator"].(string)
	operand, operandOK := object["value"].(string)
	if len(object) != 3 || !keyOK || !operatorOK || !operandOK || key != "ClientRequestHost" {
		return realCloudFilterUnknown
	}
	switch operator {
	case "eq":
		if strings.EqualFold(operand, host) {
			return realCloudFilterTrue
		}
		return realCloudFilterFalse
	case "neq":
		if strings.EqualFold(operand, host) {
			return realCloudFilterFalse
		}
		return realCloudFilterTrue
	default:
		return realCloudFilterUnknown
	}
}

func TestRealCloudCloudflareLogpushHostOverlapIsConservative(t *testing.T) {
	host := "pro.pigsty.io"
	for _, test := range []struct {
		filter string
		match  bool
	}{
		{`{"where":{"key":"ClientRequestHost","operator":"eq","value":"other.pigsty.io"}}`, false},
		{`{"where":{"key":"ClientRequestHost","operator":"eq","value":"pro.pigsty.io"}}`, true},
		{`{"where":{"or":[{"key":"ClientRequestHost","operator":"eq","value":"other.pigsty.io"},{"key":"ClientRequestHost","operator":"eq","value":"pro.pigsty.io"}]}}`, true},
		{`{"where":{"and":[{"key":"ClientRequestHost","operator":"eq","value":"other.pigsty.io"},{"key":"EdgeResponseStatus","operator":"eq","value":"200"}]}}`, false},
		{`{"where":{"and":[{"key":"ClientRequestHost","operator":"eq","value":"pro.pigsty.io"},{"key":"EdgeResponseStatus","operator":"eq","value":"200"}]}}`, true},
		{`{"where":{"key":"ClientRequestHost","operator":"contains","value":"pigsty.io"}}`, true},
		{`not-json`, true},
	} {
		if got := realCloudCloudflareFilterMayIncludeHost(test.filter, host); got != test.match {
			t.Fatalf("filter %q overlap=%t want=%t", test.filter, got, test.match)
		}
	}
}

func realCloudCloudflareDestinationURL(configuration realCloudCloudflareAttestationConfig, runID string, writer realCloudStorageSecret) string {
	return (&url.URL{
		Scheme: "r2", Host: configuration.RawBucket, Path: "/" + realCloudProviderRunSinkPrefix(configuration.RawRoot, runID),
		RawQuery: url.Values{"access-key-id": {writer.AccessKeyID}, "account-id": {configuration.AccountID}, "secret-access-key": {writer.SecretAccessKey}}.Encode(),
	}).String()
}

func validateRealCloudCloudflareLogpushJob(job *logpush.LogpushJob, environment realCloudEnvironment, configuration realCloudCloudflareAttestationConfig) (string, string, error) {
	defer func() { *job = logpush.LogpushJob{} }()
	wantedFilterBody := []byte(realCloudCloudflareHostFilter(environment))
	var rawJob struct {
		Filter string `json:"filter"`
	}
	if err := json.Unmarshal([]byte(job.JSON.RawJSON()), &rawJob); err != nil || rawJob.Filter != string(wantedFilterBody) {
		return "", "", errors.New("Cloudflare Logpush job lacks the exact main-and-beta host filter")
	}
	//lint:ignore SA1019 LogpullOptions remains part of the pinned provider wire closure and must be asserted empty.
	logpullOptions := job.LogpullOptions
	if job.ID != configuration.LogpushJobID || job.Dataset != logpush.LogpushJobDatasetHTTPRequests || !job.Enabled || strings.TrimSpace(job.ErrorMessage) != "" ||
		job.OutputOptions.OutputType != logpush.OutputOptionsOutputTypeNdjson || job.OutputOptions.MergeSubrequests ||
		job.OutputOptions.SampleRate != 1 || logpullOptions != "" ||
		job.OutputOptions.BatchPrefix != "" || job.OutputOptions.BatchSuffix != "" || job.OutputOptions.Cve2021_44228 ||
		job.OutputOptions.FieldDelimiter != "" || job.OutputOptions.RecordDelimiter != "" || job.OutputOptions.RecordPrefix != "" ||
		job.OutputOptions.RecordSuffix != "" || job.OutputOptions.RecordTemplate != "" ||
		job.OutputOptions.TimestampFormat != logpush.OutputOptionsTimestampFormatRfc3339 && job.OutputOptions.TimestampFormat != logpush.OutputOptionsTimestampFormatRfc3339ns ||
		!sameRealCloudProviderStringSet(job.OutputOptions.FieldNames, realCloudCloudflareRawFields) {
		return "", "", errors.New("Cloudflare Logpush job is not the enabled full-sample uncustomized http_requests raw NDJSON contract")
	}
	sinkPrefix := realCloudProviderRunSinkPrefix(configuration.RawRoot, strings.TrimSpace(os.Getenv(realCloudRunIDEnv)))
	destination, err := realCloudCloudflareDestination(job.DestinationConf)
	job.DestinationConf = ""
	if err != nil || destination.bucket != configuration.RawBucket || destination.prefix != sinkPrefix || destination.accountID != configuration.AccountID {
		return "", "", errors.New("Cloudflare Logpush destination does not bind the pinned R2 bucket and per-run raw sink")
	}
	writerSHA := realCloudLowerSHA256([]byte(destination.accessKeyID))
	if writerSHA != configuration.RawWriterAccessKeySHA256 {
		return "", "", errors.New("Cloudflare Logpush writer identity differs from the administrator-pinned isolated identity")
	}
	sanitized := struct {
		ID        int64    `json:"id"`
		Dataset   string   `json:"dataset"`
		Enabled   bool     `json:"enabled"`
		Bucket    string   `json:"bucket"`
		Prefix    string   `json:"prefix"`
		Fields    []string `json:"fields"`
		Output    string   `json:"output"`
		Timestamp string   `json:"timestamp"`
		FilterSHA string   `json:"filter_sha256"`
	}{job.ID, string(job.Dataset), job.Enabled, destination.bucket, destination.prefix, sortedRealCloudProviderStrings(job.OutputOptions.FieldNames), string(job.OutputOptions.OutputType), string(job.OutputOptions.TimestampFormat), realCloudLowerSHA256(wantedFilterBody)}
	body, _ := json.Marshal(sanitized)
	return realCloudLowerSHA256(body), writerSHA, nil
}

type realCloudCloudflareLogDestination struct {
	bucket, prefix, accountID, accessKeyID string
}

func realCloudCloudflareDestination(raw string) (realCloudCloudflareLogDestination, error) {
	var result realCloudCloudflareLogDestination
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Host == "" || parsed.Scheme != "r2" {
		return result, errors.New("invalid Logpush destination")
	}
	query := parsed.Query()
	if len(query) != 3 || len(query["account-id"]) != 1 || len(query["access-key-id"]) != 1 || len(query["secret-access-key"]) != 1 ||
		strings.TrimSpace(query.Get("account-id")) == "" || strings.TrimSpace(query.Get("access-key-id")) == "" ||
		strings.TrimSpace(query.Get("secret-access-key")) == "" || parsed.RawQuery != query.Encode() {
		return result, errors.New("Logpush destination credential query is absent or non-canonical")
	}
	prefix := strings.TrimPrefix(parsed.EscapedPath(), "/")
	decoded, err := url.PathUnescape(prefix)
	if err != nil || decoded == "" || path.Clean(decoded) != strings.TrimSuffix(decoded, "/") {
		return result, errors.New("invalid Logpush destination prefix")
	}
	result = realCloudCloudflareLogDestination{
		bucket: parsed.Host, prefix: strings.TrimSuffix(decoded, "/") + "/",
		accountID: query.Get("account-id"), accessKeyID: query.Get("access-key-id"),
	}
	query.Set("secret-access-key", "")
	parsed.RawQuery = ""
	raw = ""
	return result, nil
}

func exactRealCloudCloudflareDeployment(response *workers.ScriptDeploymentListResponse) (string, string, error) {
	if response == nil || len(response.Deployments) != 1 {
		return "", "", errors.New("Cloudflare Worker must expose exactly one active deployment")
	}
	deployment := response.Deployments[0]
	if !validRealCloudProviderIdentifier(deployment.ID, 128) || deployment.Strategy != workers.DeploymentStrategyPercentage || len(deployment.Versions) != 1 ||
		deployment.Versions[0].Percentage != 100 || !validRealCloudProviderIdentifier(deployment.Versions[0].VersionID, 128) {
		return "", "", errors.New("Cloudflare Worker active deployment is not one exact 100-percent version")
	}
	return deployment.ID, deployment.Versions[0].VersionID, nil
}

func readRealCloudCloudflareWorkerContent(response *http.Response) ([]byte, error) {
	if response.Body == nil {
		return nil, errors.New("Cloudflare Worker content response has no body")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, realCloudProviderMaxContentBytes+1))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || len(body) == 0 || len(body) > realCloudProviderMaxContentBytes {
		return nil, errors.New("Cloudflare Worker content response is unreadable or oversized")
	}
	mediaType, parameters, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if parseErr == nil && strings.HasPrefix(mediaType, "multipart/") {
		reader := multipart.NewReader(bytes.NewReader(body), parameters["boundary"])
		var selected []byte
		for {
			part, nextErr := reader.NextPart()
			if errors.Is(nextErr, io.EOF) {
				break
			}
			if nextErr != nil {
				return nil, errors.New("Cloudflare Worker multipart content is invalid")
			}
			partBody, readErr := io.ReadAll(io.LimitReader(part, realCloudProviderMaxContentBytes+1))
			_ = part.Close()
			if readErr != nil || len(partBody) > realCloudProviderMaxContentBytes {
				return nil, errors.New("Cloudflare Worker multipart part is invalid")
			}
			partType := strings.ToLower(part.Header.Get("Content-Type"))
			if strings.Contains(partType, "javascript") {
				if selected != nil {
					return nil, errors.New("Cloudflare Worker content has multiple JavaScript bundle parts")
				}
				selected = partBody
			}
		}
		clearRealCloudBytes(body)
		if len(selected) == 0 {
			return nil, errors.New("Cloudflare Worker content has no JavaScript bundle part")
		}
		return selected, nil
	}
	return body, nil
}

type realCloudEdgeOneControlEvidence struct {
	zoneSHA, domainsSHA, taskSHA, writerSHA, domainSHA, domainBehaviorSHA, contentSHA, componentsSHA, replicasSHA, runtimeSHA, rulesSHA string
}

func collectRealCloudEdgeOneControl(ctx context.Context, environment realCloudEnvironment, providerConfiguration realCloudProviderAttestationConfig, client *teo.Client, probeFunctionDomain func(context.Context, string) (string, error)) (realCloudEdgeOneControlEvidence, error) {
	var result realCloudEdgeOneControlEvidence
	configuration := providerConfiguration.EdgeOne
	zoneSHA, domainsSHA, err := collectRealCloudEdgeOneZoneClosure(ctx, environment, configuration, "", client)
	if err != nil {
		return result, err
	}
	result.zoneSHA = zoneSHA
	result.domainsSHA = domainsSHA
	taskRequest := teo.NewDescribeRealtimeLogDeliveryTasksRequest()
	taskRequest.ZoneId = stringPointer(configuration.ZoneID)
	taskRequest.Offset = int64Pointer(0)
	taskRequest.Limit = uint64Pointer(1000)
	taskResponse, err := client.DescribeRealtimeLogDeliveryTasksWithContext(ctx, taskRequest)
	if err != nil || taskResponse == nil || taskResponse.Response == nil {
		return result, errors.New("EdgeOne realtime log delivery task query failed")
	}
	defer func() {
		for _, task := range taskResponse.Response.RealtimeLogDeliveryTasks {
			if task != nil {
				if task.S3 != nil && task.S3.AccessKey != nil {
					*task.S3.AccessKey = ""
				}
				*task = teo.RealtimeLogDeliveryTask{}
			}
		}
	}()
	if taskResponse.Response.TotalCount == nil || *taskResponse.Response.TotalCount != 1 || len(taskResponse.Response.RealtimeLogDeliveryTasks) != 1 {
		return result, errors.New("EdgeOne realtime log delivery task query failed or was non-exact")
	}
	taskSHA, writerSHA, err := validateRealCloudEdgeOneLogTask(taskResponse.Response.RealtimeLogDeliveryTasks[0], environment, configuration)
	if err != nil {
		return result, err
	}
	functionRequest := teo.NewDescribeFunctionsRequest()
	functionRequest.ZoneId = stringPointer(configuration.ZoneID)
	functionRequest.FunctionIds = []*string{stringPointer(configuration.FunctionID)}
	functionRequest.Offset = int64Pointer(0)
	functionRequest.Limit = int64Pointer(200)
	functionResponse, err := client.DescribeFunctionsWithContext(ctx, functionRequest)
	if err != nil || functionResponse == nil || functionResponse.Response == nil || functionResponse.Response.TotalCount == nil || *functionResponse.Response.TotalCount != 1 || len(functionResponse.Response.Functions) != 1 {
		return result, errors.New("EdgeOne deployed function query failed or was non-exact")
	}
	function := functionResponse.Response.Functions[0]
	if function == nil || stringValue(function.FunctionId) != configuration.FunctionID || stringValue(function.ZoneId) != configuration.ZoneID || function.Content == nil {
		return result, errors.New("EdgeOne deployed function identity or content is incomplete")
	}
	domainSHA, domain, err := validateRealCloudEdgeOneFunctionDomain(function.Domain, environment, configuration)
	if err != nil {
		return result, err
	}
	domainBehaviorSHA, err := probeFunctionDomain(ctx, domain)
	if err != nil {
		return result, err
	}
	wanted, err := readRealCloudProviderRepositoryFile("edge/dist/edgeone.js", realCloudProviderMaxContentBytes)
	if err != nil {
		return result, err
	}
	defer clearRealCloudBytes(wanted)
	content := []byte(*function.Content)
	defer clearRealCloudBytes(content)
	if !bytes.Equal(content, wanted) {
		return result, errors.New("EdgeOne deployed function content differs from the reviewed in-repo bundle")
	}
	componentRequest := teo.NewDescribeFunctionComponentBindingsRequest()
	componentRequest.ZoneId = stringPointer(configuration.ZoneID)
	componentRequest.FunctionId = stringPointer(configuration.FunctionID)
	componentRequest.Offset = int64Pointer(0)
	componentRequest.Limit = int64Pointer(1000)
	componentResponse, err := client.DescribeFunctionComponentBindingsWithContext(ctx, componentRequest)
	if err != nil || componentResponse == nil || componentResponse.Response == nil || componentResponse.Response.TotalCount == nil ||
		*componentResponse.Response.TotalCount != 0 || len(componentResponse.Response.FunctionComponentBindings) != 0 {
		return result, errors.New("EdgeOne function has an unreviewed component binding")
	}
	componentsBody, _ := json.Marshal([]any{})
	componentsSHA := realCloudLowerSHA256(componentsBody)
	replicaRequest := teo.NewDescribeFunctionReplicasRequest()
	replicaRequest.ZoneId = stringPointer(configuration.ZoneID)
	replicaRequest.FunctionId = stringPointer(configuration.FunctionID)
	replicaRequest.Offset = int64Pointer(0)
	replicaRequest.Limit = int64Pointer(200)
	replicaResponse, err := client.DescribeFunctionReplicasWithContext(ctx, replicaRequest)
	if err != nil || replicaResponse == nil || replicaResponse.Response == nil || replicaResponse.Response.TotalCount == nil ||
		*replicaResponse.Response.TotalCount != 0 || len(replicaResponse.Response.FunctionReplicas) != 0 {
		return result, errors.New("EdgeOne function has an unreviewed executable replica")
	}
	replicasBody, _ := json.Marshal([]any{})
	replicasSHA := realCloudLowerSHA256(replicasBody)
	runtimeRequest := teo.NewDescribeFunctionRuntimeEnvironmentRequest()
	runtimeRequest.ZoneId = stringPointer(configuration.ZoneID)
	runtimeRequest.FunctionId = stringPointer(configuration.FunctionID)
	runtimeResponse, err := client.DescribeFunctionRuntimeEnvironmentWithContext(ctx, runtimeRequest)
	if err != nil || runtimeResponse == nil || runtimeResponse.Response == nil {
		return result, errors.New("EdgeOne function runtime-environment query failed")
	}
	runtimeSHA, err := validateRealCloudEdgeOneRuntimeEnvironment(runtimeResponse.Response.EnvironmentVariables, environment, providerConfiguration.Runtime)
	if err != nil {
		return result, err
	}
	rulesRequest := teo.NewDescribeFunctionRulesRequest()
	rulesRequest.ZoneId = stringPointer(configuration.ZoneID)
	rulesResponse, err := client.DescribeFunctionRulesWithContext(ctx, rulesRequest)
	if err != nil || rulesResponse == nil || rulesResponse.Response == nil {
		return result, errors.New("EdgeOne function trigger-rule query failed")
	}
	rulesSHA, err := validateRealCloudEdgeOneFunctionRules(rulesResponse.Response.FunctionRules, environment, configuration)
	if err != nil {
		return result, err
	}
	result.taskSHA = taskSHA
	result.writerSHA = writerSHA
	result.domainSHA = domainSHA
	result.domainBehaviorSHA = domainBehaviorSHA
	result.contentSHA = realCloudLowerSHA256(content)
	result.componentsSHA = componentsSHA
	result.replicasSHA = replicasSHA
	result.runtimeSHA = runtimeSHA
	result.rulesSHA = rulesSHA
	return result, nil
}

func collectRealCloudEdgeOneZoneClosure(
	ctx context.Context,
	environment realCloudEnvironment,
	configuration realCloudEdgeOneAttestationConfig,
	expectedZoneName string,
	client *teo.Client,
) (string, string, error) {
	if client == nil {
		return "", "", errors.New("EdgeOne zone safety client is absent")
	}
	zoneRequest := teo.NewDescribeZonesRequest()
	zoneRequest.Offset = int64Pointer(0)
	zoneRequest.Limit = int64Pointer(100)
	zoneRequest.Filters = []*teo.AdvancedFilter{{
		Name: stringPointer("zone-id"), Values: []*string{stringPointer(configuration.ZoneID)},
	}}
	zoneResponse, err := client.DescribeZonesWithContext(ctx, zoneRequest)
	if err != nil || zoneResponse == nil || zoneResponse.Response == nil || zoneResponse.Response.TotalCount == nil ||
		*zoneResponse.Response.TotalCount != 1 || len(zoneResponse.Response.Zones) != 1 {
		return "", "", errors.New("EdgeOne exact zone identity query failed or was non-exact")
	}
	zone := zoneResponse.Response.Zones[0]
	zoneSHA, zoneName, err := validateRealCloudEdgeOneZone(zone, environment, configuration)
	if zone != nil {
		*zone = teo.Zone{}
	}
	if err != nil {
		return "", "", err
	}
	if expectedZoneName != "" && zoneName != expectedZoneName {
		return "", "", errors.New("EdgeOne readiness zone name differs from the pinned identity")
	}
	domainsSHA, err := collectRealCloudEdgeOneAccelerationDomains(ctx, client, environment, configuration, zoneName)
	if err != nil {
		return "", "", err
	}
	return zoneSHA, domainsSHA, nil
}

func validateRealCloudEdgeOneZone(
	zone *teo.Zone,
	environment realCloudEnvironment,
	configuration realCloudEdgeOneAttestationConfig,
) (string, string, error) {
	if zone == nil || stringValue(zone.ZoneId) != configuration.ZoneID || stringValue(zone.Status) != "active" ||
		stringValue(zone.ActiveStatus) != "active" || zone.Paused == nil || *zone.Paused {
		return "", "", errors.New("EdgeOne zone is not the exact active unpaused contract")
	}
	zoneType := stringValue(zone.Type)
	if zoneType != "full" && zoneType != "partial" {
		return "", "", errors.New("EdgeOne zone has an unsupported acceleration type")
	}
	zoneName := strings.ToLower(strings.TrimSuffix(stringValue(zone.ZoneName), "."))
	if zoneName == "" || stringValue(zone.ZoneName) != zoneName || !hasRealCloudNonProductionHostMarker(zoneName) ||
		isRealCloudProductionDomain(zoneName) || hasRealCloudProductionMarker(zoneName) {
		return "", "", errors.New("EdgeOne zone name is not an explicit dedicated non-production identity")
	}
	mainHost := hostOnly(environment.COSCDNBase)
	betaHost := hostOnly(environment.COSBetaBase)
	if mainHost == betaHost || mainHost == zoneName || betaHost == zoneName ||
		!strings.HasSuffix(mainHost, "."+zoneName) || !strings.HasSuffix(betaHost, "."+zoneName) {
		return "", "", errors.New("EdgeOne main or beta host is outside the attested dedicated zone")
	}
	body, _ := json.Marshal([]any{configuration.ZoneID, zoneName, zoneType, "active", "active", false})
	return realCloudLowerSHA256(body), zoneName, nil
}

func collectRealCloudEdgeOneAccelerationDomains(
	ctx context.Context,
	client *teo.Client,
	environment realCloudEnvironment,
	configuration realCloudEdgeOneAttestationConfig,
	zoneName string,
) (string, error) {
	const (
		pageLimit  int64 = 200
		maxDomains int64 = 1000
	)
	var (
		offset        int64
		expectedTotal int64 = -1
		domains             = make([]*teo.AccelerationDomain, 0, 2)
	)
	for {
		request := teo.NewDescribeAccelerationDomainsRequest()
		request.ZoneId = stringPointer(configuration.ZoneID)
		request.Offset = int64Pointer(offset)
		request.Limit = int64Pointer(pageLimit)
		response, err := client.DescribeAccelerationDomainsWithContext(ctx, request)
		if err != nil || response == nil || response.Response == nil || response.Response.TotalCount == nil {
			return "", errors.New("EdgeOne acceleration-domain inventory query failed")
		}
		total := *response.Response.TotalCount
		if total < 0 || total > maxDomains || expectedTotal >= 0 && total != expectedTotal {
			return "", errors.New("EdgeOne acceleration-domain inventory count changed or exceeded its bound")
		}
		if expectedTotal < 0 {
			expectedTotal = total
		}
		page := response.Response.AccelerationDomains
		if int64(len(page)) > pageLimit || offset+int64(len(page)) > total || len(page) == 0 && offset < total {
			return "", errors.New("EdgeOne acceleration-domain inventory pagination is inconsistent")
		}
		domains = append(domains, page...)
		offset += int64(len(page))
		if offset == total {
			break
		}
	}
	if expectedTotal != 2 || len(domains) != 2 {
		return "", errors.New("EdgeOne acceleration-domain inventory is not the exact main-and-beta closure")
	}
	wanted := map[string]struct{}{
		hostOnly(environment.COSCDNBase):  {},
		hostOnly(environment.COSBetaBase): {},
	}
	rows := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		if domain == nil || stringValue(domain.ZoneId) != configuration.ZoneID || stringValue(domain.DomainStatus) != "online" {
			return "", errors.New("EdgeOne acceleration domain is incomplete, foreign, or offline")
		}
		name := strings.ToLower(strings.TrimSuffix(stringValue(domain.DomainName), "."))
		if name == "" || stringValue(domain.DomainName) != name || name == zoneName || !strings.HasSuffix(name, "."+zoneName) {
			return "", errors.New("EdgeOne acceleration domain is non-canonical or outside the dedicated zone")
		}
		if _, ok := wanted[name]; !ok {
			return "", errors.New("EdgeOne acceleration-domain inventory contains a third or unexpected domain")
		}
		if _, duplicate := seen[name]; duplicate {
			return "", errors.New("EdgeOne acceleration-domain inventory repeats a domain")
		}
		seen[name] = struct{}{}
		rows = append(rows, strings.Join([]string{configuration.ZoneID, name, "online"}, "\x00"))
		*domain = teo.AccelerationDomain{}
	}
	if len(seen) != len(wanted) {
		return "", errors.New("EdgeOne acceleration-domain inventory lacks main or beta")
	}
	sort.Strings(rows)
	body, _ := json.Marshal(rows)
	return realCloudLowerSHA256(body), nil
}

func validateRealCloudEdgeOneFunctionDomain(domainValue *string, environment realCloudEnvironment, configuration realCloudEdgeOneAttestationConfig) (string, string, error) {
	domain := strings.ToLower(strings.TrimSuffix(stringValue(domainValue), "."))
	if domain == "" || stringValue(domainValue) != domain || !hasRealCloudNonProductionHostMarker(domain) || isRealCloudProductionDomain(domain) ||
		hasRealCloudProductionMarker(domain) || domain == hostOnly(environment.COSCDNBase) || domain == hostOnly(environment.COSBetaBase) {
		return "", "", errors.New("EdgeOne default function domain is not a dedicated non-production identity")
	}
	digest := realCloudLowerSHA256([]byte(domain))
	if digest != configuration.FunctionDomainSHA256 {
		return "", "", errors.New("EdgeOne default function domain differs from the administrator-pinned identity")
	}
	return digest, domain, nil
}

func validateRealCloudEdgeOneRuntimeEnvironment(
	variables []*teo.FunctionEnvironmentVariable,
	environment realCloudEnvironment,
	runtime realCloudEdgeRuntimeAttestationConfig,
) (string, error) {
	defer func() {
		for _, variable := range variables {
			if variable != nil && variable.Value != nil {
				*variable.Value = ""
			}
		}
	}()
	wantedVariables, err := realCloudProviderExpectedRuntimeVariables(environment, runtime, "edgeone")
	if err != nil {
		return "", err
	}
	wantedSecrets := make(map[string]bool, len(runtime.EdgeOneSecretNames))
	for _, name := range runtime.EdgeOneSecretNames {
		wantedSecrets[name] = false
	}
	seen := make(map[string]struct{}, len(variables))
	redactedRows := make([]string, 0, len(variables))
	for _, variable := range variables {
		if variable == nil || variable.Key == nil || variable.Value == nil || variable.Type == nil || stringValue(variable.Type) != "string" ||
			!validRealCloudProviderSecretName(stringValue(variable.Key)) {
			return "", errors.New("EdgeOne function runtime variable is incomplete or has the wrong type")
		}
		name := stringValue(variable.Key)
		if _, duplicate := seen[name]; duplicate {
			return "", errors.New("EdgeOne function repeats a runtime variable")
		}
		seen[name] = struct{}{}
		if expected, found := wantedVariables[name]; found {
			if stringValue(variable.Value) != expected {
				return "", errors.New("EdgeOne function runtime variable differs from the exact clean-URL deployment contract")
			}
			delete(wantedVariables, name)
			redactedRows = append(redactedRows, strings.Join([]string{name, "string", expected}, "\x00"))
			continue
		}
		if _, found := wantedSecrets[name]; !found || stringValue(variable.Value) == "" {
			return "", errors.New("EdgeOne function has an unexpected, missing, or mode-inapplicable secret")
		}
		delete(wantedSecrets, name)
		redactedRows = append(redactedRows, strings.Join([]string{name, "string", "secret-present"}, "\x00"))
	}
	if len(wantedVariables) != 0 || len(wantedSecrets) != 0 {
		return "", errors.New("EdgeOne function lacks an exact runtime variable or secret")
	}
	sort.Strings(redactedRows)
	body, _ := json.Marshal(redactedRows)
	return realCloudLowerSHA256(body), nil
}

func validateRealCloudEdgeOneFunctionRules(rules []*teo.FunctionRule, environment realCloudEnvironment, configuration realCloudEdgeOneAttestationConfig) (string, error) {
	wantedHosts := map[string]bool{hostOnly(environment.COSCDNBase): false, hostOnly(environment.COSBetaBase): false}
	if len(rules) == 0 || len(rules) > 2 || len(wantedHosts) != 2 {
		return "", errors.New("EdgeOne main and beta function trigger rules are absent or ambiguous")
	}
	sanitized := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule == nil || !validRealCloudProviderIdentifier(stringValue(rule.RuleId), 128) || stringValue(rule.TriggerType) != "direct" ||
			stringValue(rule.FunctionId) != configuration.FunctionID || len(rule.FunctionRuleConditions) == 0 ||
			len(rule.WeightedSelections) != 0 || len(rule.RegionMappingSelections) != 0 {
			return "", errors.New("EdgeOne function trigger rule is not an exact direct binding")
		}
		matched := make([]string, 0, 2)
		for _, group := range rule.FunctionRuleConditions {
			if group == nil || len(group.RuleConditions) != 1 || group.RuleConditions[0] == nil {
				return "", errors.New("EdgeOne function trigger rule contains a non-host or compound condition")
			}
			condition := group.RuleConditions[0]
			if stringValue(condition.Target) != "host" || stringValue(condition.Operator) != "equal" || len(condition.Values) == 0 || condition.IgnoreCase == nil || !*condition.IgnoreCase {
				return "", errors.New("EdgeOne function trigger rule is not a case-insensitive exact host condition")
			}
			for _, value := range stringPointerValues(condition.Values) {
				host := strings.ToLower(value)
				if _, expected := wantedHosts[host]; !expected || wantedHosts[host] {
					return "", errors.New("EdgeOne function trigger rule contains an extra or duplicate host")
				}
				wantedHosts[host] = true
				matched = append(matched, host)
			}
		}
		sort.Strings(matched)
		sanitized = append(sanitized, strings.Join([]string{stringValue(rule.RuleId), configuration.FunctionID, strings.Join(matched, ",")}, "\x00"))
	}
	for _, found := range wantedHosts {
		if !found {
			return "", errors.New("EdgeOne main and beta hosts are not both bound to the exact function")
		}
	}
	sort.Strings(sanitized)
	body, _ := json.Marshal(sanitized)
	return realCloudLowerSHA256(body), nil
}

func validateRealCloudEdgeOneLogTask(task *teo.RealtimeLogDeliveryTask, environment realCloudEnvironment, configuration realCloudEdgeOneAttestationConfig) (string, string, error) {
	defer func() {
		if task != nil {
			if task.S3 != nil && task.S3.AccessKey != nil {
				*task.S3.AccessKey = ""
			}
			*task = teo.RealtimeLogDeliveryTask{}
		}
	}()
	if task == nil || stringValue(task.TaskId) != configuration.RealtimeLogTaskID || stringValue(task.DeliveryStatus) != "enabled" ||
		strings.ToLower(stringValue(task.TaskType)) != "s3" || stringValue(task.LogType) != "l7-access-logs" ||
		stringValue(task.Area) != configuration.RealtimeLogArea || !validRealCloudEdgeOneLogArea(configuration.RealtimeLogArea) ||
		task.Sample == nil || *task.Sample != 1000 || !sameRealCloudProviderStringSet(stringPointerValues(task.Fields), realCloudEdgeOneRawFields) || task.S3 == nil ||
		len(task.CustomFields) != 0 || len(task.DeliveryConditions) != 0 || !validRealCloudEdgeOneDefaultJSONL(task.LogFormat) {
		return "", "", errors.New("EdgeOne realtime log task is not the enabled exact-area full-sample default-JSONL l7 S3 raw contract")
	}
	if stringValue(task.S3.Endpoint) != strings.TrimSuffix(environment.COSEndpoint, "/") || stringValue(task.S3.Region) != environment.COSRegion ||
		stringValue(task.S3.CompressType) != "" && stringValue(task.S3.CompressType) != "gzip" {
		return "", "", errors.New("EdgeOne realtime log S3 sink endpoint, region, or compression differs")
	}
	accessID := strings.TrimSpace(stringValue(task.S3.AccessId))
	if accessID == "" || accessID != stringValue(task.S3.AccessId) || strings.TrimSpace(stringValue(task.S3.AccessKey)) == "" {
		return "", "", errors.New("EdgeOne realtime log S3 writer credential is absent or non-canonical")
	}
	writerSHA := realCloudLowerSHA256([]byte(accessID))
	if writerSHA != configuration.RawWriterAccessKeySHA256 {
		return "", "", errors.New("EdgeOne realtime log writer identity differs from the administrator-pinned isolated identity")
	}
	bucketPath := strings.TrimPrefix(stringValue(task.S3.Bucket), "/")
	wantedPrefix := configuration.RawBucket + "/"
	if !strings.HasPrefix(bucketPath, wantedPrefix) {
		return "", "", errors.New("EdgeOne realtime log task does not target the pinned COS bucket")
	}
	prefix := strings.TrimPrefix(bucketPath, wantedPrefix)
	sinkPrefix := realCloudProviderRunSinkPrefix(configuration.RawRoot, strings.TrimSpace(os.Getenv(realCloudRunIDEnv)))
	if prefix == "" || prefix != sinkPrefix {
		return "", "", errors.New("EdgeOne realtime log raw object is outside the configured per-run S3 sink prefix")
	}
	wantedEntities := []string{hostOnly(environment.COSCDNBase), hostOnly(environment.COSBetaBase)}
	if !sameRealCloudProviderStringSet(stringPointerValues(task.EntityList), wantedEntities) {
		return "", "", errors.New("EdgeOne realtime log task does not bind both pinned CDN hosts")
	}
	sanitized := struct {
		TaskID, Status, Type, LogType, Area, Endpoint, Region, BucketPrefix, Compression string
		Fields, Entities                                                                 []string
		Sample                                                                           uint64
	}{configuration.RealtimeLogTaskID, stringValue(task.DeliveryStatus), strings.ToLower(stringValue(task.TaskType)), stringValue(task.LogType),
		configuration.RealtimeLogArea, strings.TrimSuffix(environment.COSEndpoint, "/"), environment.COSRegion, prefix, stringValue(task.S3.CompressType),
		sortedRealCloudProviderStrings(stringPointerValues(task.Fields)), sortedRealCloudProviderStrings(stringPointerValues(task.EntityList)), *task.Sample}
	body, _ := json.Marshal(sanitized)
	return realCloudLowerSHA256(body), writerSHA, nil
}

func validRealCloudEdgeOneDefaultJSONL(format *teo.LogFormat) bool {
	if format == nil {
		return true
	}
	return stringValue(format.FormatType) == "json" && stringValue(format.BatchPrefix) == "" && stringValue(format.BatchSuffix) == "" &&
		stringValue(format.RecordPrefix) == "" && stringValue(format.RecordSuffix) == "" && stringValue(format.RecordDelimiter) == "" &&
		stringValue(format.FieldDelimiter) == ""
}

type realCloudProviderRawObjectEvidence struct {
	identitySHA, etag, bodySHA string
	objects                    int
	size                       int64
}

func readRealCloudProviderRawObjects(
	ctx context.Context,
	vendor, bucket, prefix string,
	list func(context.Context, string, string) (publish.ObjectListPage, error),
	open func(context.Context, string) (publish.ObjectContent, error),
) ([]byte, realCloudProviderRawObjectEvidence, error) {
	var aggregate realCloudProviderRawObjectEvidence
	if list == nil || open == nil || !validRealCloudProviderRawPrefix(prefix) {
		return nil, aggregate, errors.New("provider raw object inventory client or prefix is invalid")
	}
	var objects []publish.ListedObject
	seenTokens := map[string]struct{}{"": {}}
	token := ""
	lastKey := ""
	for {
		page, err := list(ctx, prefix, token)
		if err != nil {
			return nil, aggregate, fmt.Errorf("%s raw export inventory query failed", vendor)
		}
		for _, object := range page.Objects {
			if len(objects) >= realCloudProviderMaxInventoryItems || object.Key <= lastKey || !strings.HasPrefix(object.Key, prefix) ||
				object.Size <= 0 || !validRealCloudProviderETag(object.ETag) || aggregate.size > realCloudProviderMaxRawBytes-object.Size {
				return nil, aggregate, fmt.Errorf("%s dedicated raw bucket inventory is unsafe, unsorted, outside the per-run prefix, or oversized", vendor)
			}
			lastKey = object.Key
			aggregate.size += object.Size
			objects = append(objects, object)
		}
		if page.NextContinuationToken == "" {
			break
		}
		if _, duplicate := seenTokens[page.NextContinuationToken]; duplicate {
			return nil, aggregate, fmt.Errorf("%s raw export inventory repeats a continuation token", vendor)
		}
		seenTokens[page.NextContinuationToken] = struct{}{}
		token = page.NextContinuationToken
	}
	if len(objects) == 0 {
		return nil, aggregate, fmt.Errorf("%s per-run raw export inventory is empty", vendor)
	}
	identityRows := make([]string, 0, len(objects))
	etagRows := make([]string, 0, len(objects))
	bodyRows := make([]string, 0, len(objects))
	var joined bytes.Buffer
	for _, listed := range objects {
		decoded, evidence, err := readRealCloudProviderRawObject(ctx, vendor, bucket, listed.Key, open)
		if err != nil {
			clearRealCloudBytes(joined.Bytes())
			return nil, aggregate, err
		}
		if evidence.size != listed.Size || evidence.etag != listed.ETag || len(decoded) == 0 || decoded[len(decoded)-1] != '\n' {
			clearRealCloudBytes(decoded)
			clearRealCloudBytes(joined.Bytes())
			return nil, aggregate, fmt.Errorf("%s raw export changed between LIST and GET or is not complete JSONL", vendor)
		}
		if len(decoded) > realCloudProviderMaxRawBytes-joined.Len() {
			clearRealCloudBytes(decoded)
			clearRealCloudBytes(joined.Bytes())
			return nil, aggregate, fmt.Errorf("%s decoded raw export inventory exceeds the aggregate byte bound", vendor)
		}
		identityRows = append(identityRows, strings.Join([]string{vendor, bucket, listed.Key, strconv.FormatInt(listed.Size, 10)}, "\x00"))
		etagRows = append(etagRows, listed.ETag)
		bodyRows = append(bodyRows, evidence.bodySHA)
		_, _ = joined.Write(decoded)
		clearRealCloudBytes(decoded)
	}
	identityBody, _ := json.Marshal(identityRows)
	etagBody, _ := json.Marshal(etagRows)
	bodyBody, _ := json.Marshal(bodyRows)
	aggregate.identitySHA = realCloudLowerSHA256(identityBody)
	aggregate.etag = realCloudLowerSHA256(etagBody)
	aggregate.bodySHA = realCloudLowerSHA256(bodyBody)
	aggregate.objects = len(objects)
	return joined.Bytes(), aggregate, nil
}

func readRealCloudProviderRawObject(ctx context.Context, vendor, bucket, key string, open func(context.Context, string) (publish.ObjectContent, error)) ([]byte, realCloudProviderRawObjectEvidence, error) {
	var evidence realCloudProviderRawObjectEvidence
	object, err := open(ctx, key)
	if err != nil || object.Body == nil || !object.Info.Exists || object.Info.Size < 0 || object.Info.Size > realCloudProviderMaxRawBytes || !validRealCloudProviderETag(object.Info.ETag) {
		return nil, evidence, fmt.Errorf("%s raw export object is absent, unsafe, or oversized", vendor)
	}
	raw, readErr := io.ReadAll(io.LimitReader(object.Body, realCloudProviderMaxRawBytes+1))
	closeErr := object.Body.Close()
	if readErr != nil || closeErr != nil || len(raw) == 0 || len(raw) > realCloudProviderMaxRawBytes || object.Info.Size != int64(len(raw)) {
		clearRealCloudBytes(raw)
		return nil, evidence, fmt.Errorf("%s raw export object could not be read exactly", vendor)
	}
	evidence.identitySHA = realCloudLowerSHA256([]byte(vendor + "\x00" + bucket + "\x00" + key))
	evidence.etag = object.Info.ETag
	evidence.bodySHA = realCloudLowerSHA256(raw)
	evidence.size = object.Info.Size
	evidence.objects = 1
	decoded, err := decodeRealCloudProviderRawBytes(raw)
	if err != nil {
		clearRealCloudBytes(raw)
		return nil, evidence, fmt.Errorf("%s raw export object compression is invalid", vendor)
	}
	clearRealCloudBytes(raw)
	return decoded, evidence, nil
}

func decodeRealCloudProviderRawBytes(raw []byte) ([]byte, error) {
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		return append([]byte(nil), raw...), nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	decoded, readErr := io.ReadAll(io.LimitReader(reader, realCloudProviderMaxRawBytes+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || len(decoded) == 0 || len(decoded) > realCloudProviderMaxRawBytes {
		clearRealCloudBytes(decoded)
		return nil, errors.New("gzip raw export is invalid")
	}
	return decoded, nil
}

type realCloudExpectedProviderRecord struct {
	phase, vendor, parent, transaction, cleanSHA, bodySHA string
	generation                                            uint64
	started, observed                                     time.Time
}

func reconstructRealCloudProviderLogs(environment realCloudEnvironment, stages []realEdgeMultiPoPStageEvidence, cfRaw, teoRaw []byte) ([]realEdgeProviderLog, string, error) {
	expected, err := expectedRealCloudProviderRecords(stages)
	if err != nil {
		return nil, "", err
	}
	cfLogs, cfRedacted, err := decodeRealCloudCloudflareRawLogs(cfRaw, environment.CFCDNBase, expected["cloudflare"])
	if err != nil {
		return nil, "", err
	}
	if len(expected["cloudflare"]) != 0 {
		return nil, "", errors.New("Cloudflare raw export omits one or more active provider requests")
	}
	teoLogs, teoRedacted, err := decodeRealCloudEdgeOneRawLogs(teoRaw, environment.COSCDNBase, expected["edgeone"])
	if err != nil {
		return nil, "", err
	}
	if len(expected["edgeone"]) != 0 {
		return nil, "", errors.New("EdgeOne raw export omits one or more active provider requests")
	}
	logs := append(cfLogs, teoLogs...)
	redacted := append(cfRedacted, teoRedacted...)
	sort.Strings(redacted)
	body, _ := json.Marshal(redacted)
	return logs, realCloudLowerSHA256(body), nil
}

func expectedRealCloudProviderRecords(stages []realEdgeMultiPoPStageEvidence) (map[string]map[string]realCloudExpectedProviderRecord, error) {
	result := map[string]map[string]realCloudExpectedProviderRecord{"cloudflare": {}, "edgeone": {}}
	if len(stages) != 2 {
		return nil, errors.New("raw provider reconstruction requires exactly two active stages")
	}
	add := func(vendor, phase string, generation uint64, transaction, cleanSHA, bodySHA string, observations []realEdgeMultiPoPObservation) error {
		for _, observation := range observations {
			if observation.Vendor != vendor || result[vendor][observation.RequestID].parent != "" {
				return errors.New("active provider request identity is invalid or duplicated")
			}
			result[vendor][observation.RequestID] = realCloudExpectedProviderRecord{
				phase: phase, vendor: vendor, parent: observation.RequestID, transaction: transaction,
				cleanSHA: cleanSHA, bodySHA: bodySHA, generation: generation,
				started: observation.RequestStarted, observed: observation.ResponseObserved,
			}
		}
		return nil
	}
	for _, stageEvidence := range stages {
		for _, vendor := range []string{"cloudflare", "edgeone"} {
			stage, exists := stageEvidence.Vendors[vendor]
			if !exists || add(vendor, "stage", stage.Generation, stage.TransactionID, stage.CleanURLSHA256, stage.BodySHA256, stage.Observations) != nil {
				return nil, errors.New("active stage cannot seed raw provider reconstruction")
			}
			if stage.PrePurge != nil {
				pre := stage.PrePurge
				if err := add(vendor, "pre-purge", pre.Generation, pre.TransactionID, pre.CleanURLSHA256, pre.BodySHA256, pre.Observations); err != nil {
					return nil, err
				}
			}
		}
	}
	return result, nil
}

type realCloudCloudflareRawLog struct {
	CacheCacheStatus   string          `json:"CacheCacheStatus"`
	ClientRequestURI   string          `json:"ClientRequestURI"`
	EdgeColoCode       string          `json:"EdgeColoCode"`
	EdgeColoID         json.Number     `json:"EdgeColoID"`
	EdgeStartTimestamp json.RawMessage `json:"EdgeStartTimestamp"`
	ParentRayID        string          `json:"ParentRayID"`
	RayID              string          `json:"RayID"`
}

func decodeRealCloudCloudflareRawLogs(raw []byte, baseURL string, expected map[string]realCloudExpectedProviderRecord) ([]realEdgeProviderLog, []string, error) {
	return decodeRealCloudProviderJSONL(raw, len(realCloudCloudflareRawFields), func(line []byte) (realEdgeProviderLog, string, error) {
		var record realCloudCloudflareRawLog
		if err := decodeRealCloudProviderExactObject(line, len(realCloudCloudflareRawFields), &record); err != nil {
			return realEdgeProviderLog{}, "", err
		}
		wanted, exists := expected[record.ParentRayID]
		if !exists {
			return realEdgeProviderLog{}, "", errors.New("Cloudflare raw export contains an extra or unknown parent request")
		}
		if record.ClientRequestURI != realCloudProviderCleanPath() {
			return realEdgeProviderLog{}, "", errors.New("Cloudflare raw export contains a token-bearing, queried, or unexpected URL")
		}
		cleanSHA, err := realCloudProviderCleanURLSHA(baseURL, record.ClientRequestURI)
		if err != nil || cleanSHA != wanted.cleanSHA {
			return realEdgeProviderLog{}, "", errors.New("Cloudflare raw clean URL does not match active evidence")
		}
		timestamp, err := parseRealCloudProviderTimestamp(record.EdgeStartTimestamp)
		if err != nil {
			return realEdgeProviderLog{}, "", errors.New("Cloudflare raw timestamp is invalid")
		}
		nodeID, err := record.EdgeColoID.Int64()
		if err != nil || nodeID <= 0 {
			return realEdgeProviderLog{}, "", errors.New("Cloudflare raw edge colo ID is invalid")
		}
		normalized := realEdgeProviderLog{
			Schema: "sow-real-edge-provider-joined/v3", RunID: strings.TrimSpace(os.Getenv(realCloudRunIDEnv)), ProbePhase: wanted.phase, Vendor: "cloudflare",
			RequestID: record.RayID, ParentRequestID: record.ParentRayID, NodeID: strconv.FormatInt(nodeID, 10), Region: strings.ToUpper(record.EdgeColoCode),
			CacheStatus: strings.ToUpper(record.CacheCacheStatus), CleanURLSHA256: wanted.cleanSHA, BodySHA256: wanted.bodySHA,
			Generation: wanted.generation, TransactionID: wanted.transaction, ObservedAt: timestamp.Format(time.RFC3339Nano), observedTime: timestamp,
		}
		if timestamp.Before(wanted.started.Add(-realEdgeProviderClockSkew)) || timestamp.After(wanted.observed.Add(realEdgeProviderExportLag)) || validateRealEdgeProviderLogShape(normalized) != nil {
			return realEdgeProviderLog{}, "", errors.New("Cloudflare raw log does not fit the active request window or joined-v3 shape")
		}
		delete(expected, record.ParentRayID)
		return normalized, strings.Join([]string{"cloudflare", normalized.RequestID, normalized.ParentRequestID, normalized.CleanURLSHA256}, "\x00"), nil
	})
}

type realCloudEdgeOneRawLog struct {
	EdgeCacheStatus        string `json:"EdgeCacheStatus"`
	EdgeFunctionSubrequest int64  `json:"EdgeFunctionSubrequest"`
	EdgeServerID           string `json:"EdgeServerID"`
	EdgeServerIP           string `json:"EdgeServerIP"`
	EdgeSeverRegion        string `json:"EdgeSeverRegion"`
	ParentRequestID        string `json:"ParentRequestID"`
	RequestHost            string `json:"RequestHost"`
	RequestID              string `json:"RequestID"`
	RequestScheme          string `json:"RequestScheme"`
	RequestTime            string `json:"RequestTime"`
	RequestUrl             string `json:"RequestUrl"`
	RequestUrlQueryString  string `json:"RequestUrlQueryString"`
}

func decodeRealCloudEdgeOneRawLogs(raw []byte, baseURL string, expected map[string]realCloudExpectedProviderRecord) ([]realEdgeProviderLog, []string, error) {
	return decodeRealCloudProviderJSONL(raw, len(realCloudEdgeOneRawFields), func(line []byte) (realEdgeProviderLog, string, error) {
		var record realCloudEdgeOneRawLog
		if err := decodeRealCloudProviderExactObject(line, len(realCloudEdgeOneRawFields), &record); err != nil {
			return realEdgeProviderLog{}, "", err
		}
		wanted, exists := expected[record.ParentRequestID]
		if !exists {
			return realEdgeProviderLog{}, "", errors.New("EdgeOne raw export contains an extra or unknown parent request")
		}
		parsedBase, _ := url.Parse(baseURL)
		if record.EdgeFunctionSubrequest != 1 || !strings.EqualFold(record.RequestScheme, "HTTPS") || record.RequestHost != parsedBase.Host ||
			record.RequestUrl != realCloudProviderCleanPath() || record.RequestUrlQueryString != "" {
			return realEdgeProviderLog{}, "", errors.New("EdgeOne raw export contains a token-bearing, queried, or non-function URL")
		}
		cleanSHA, err := realCloudProviderCleanURLSHA(baseURL, record.RequestUrl)
		if err != nil || cleanSHA != wanted.cleanSHA {
			return realEdgeProviderLog{}, "", errors.New("EdgeOne raw clean URL does not match active evidence")
		}
		timestamp, err := time.Parse(time.RFC3339Nano, record.RequestTime)
		if err != nil || timestamp.Location() != time.UTC {
			return realEdgeProviderLog{}, "", errors.New("EdgeOne raw timestamp is invalid")
		}
		normalized := realEdgeProviderLog{
			Schema: "sow-real-edge-provider-joined/v3", RunID: strings.TrimSpace(os.Getenv(realCloudRunIDEnv)), ProbePhase: wanted.phase, Vendor: "edgeone",
			RequestID: record.RequestID, ParentRequestID: record.ParentRequestID, NodeID: record.EdgeServerID, NodeIP: record.EdgeServerIP, Region: strings.ToUpper(record.EdgeSeverRegion),
			CacheStatus: strings.ToUpper(record.EdgeCacheStatus), CleanURLSHA256: wanted.cleanSHA, BodySHA256: wanted.bodySHA,
			Generation: wanted.generation, TransactionID: wanted.transaction, ObservedAt: timestamp.UTC().Format(time.RFC3339Nano), observedTime: timestamp.UTC(),
		}
		if timestamp.Before(wanted.started.Add(-realEdgeProviderClockSkew)) || timestamp.After(wanted.observed.Add(realEdgeProviderExportLag)) || validateRealEdgeProviderLogShape(normalized) != nil {
			return realEdgeProviderLog{}, "", errors.New("EdgeOne raw log does not fit the active request window or joined-v3 shape")
		}
		delete(expected, record.ParentRequestID)
		return normalized, strings.Join([]string{"edgeone", normalized.RequestID, normalized.ParentRequestID, normalized.CleanURLSHA256}, "\x00"), nil
	})
}

func decodeRealCloudProviderJSONL(raw []byte, fieldCount int, decode func([]byte) (realEdgeProviderLog, string, error)) ([]realEdgeProviderLog, []string, error) {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return nil, nil, errors.New("raw provider JSONL must end with one complete newline-delimited record")
	}
	logs := make([]realEdgeProviderLog, 0, 16)
	redacted := make([]string, 0, 16)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), realEdgeMaxProviderLogLine)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if len(bytes.TrimSpace(line)) == 0 || len(logs) >= realEdgeMaxProviderLogRecords {
			return nil, nil, errors.New("raw provider JSONL has a blank or excessive record set")
		}
		log, safe, err := decode(line)
		clearRealCloudBytes(line)
		if err != nil {
			return nil, nil, err
		}
		logs = append(logs, log)
		redacted = append(redacted, safe)
	}
	if scanner.Err() != nil || len(logs) == 0 || fieldCount <= 0 {
		return nil, nil, errors.New("raw provider JSONL is empty or exceeds its line limit")
	}
	return logs, redacted, nil
}

func decodeRealCloudProviderExactObject(line []byte, fieldCount int, destination any) error {
	keyDecoder := json.NewDecoder(bytes.NewReader(line))
	keyDecoder.UseNumber()
	opening, err := keyDecoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("raw provider record has missing or unknown fields")
	}
	keys := make(map[string]struct{}, fieldCount)
	for keyDecoder.More() {
		keyToken, tokenErr := keyDecoder.Token()
		key, ok := keyToken.(string)
		if tokenErr != nil || !ok {
			return errors.New("raw provider record has missing or unknown fields")
		}
		if _, duplicate := keys[key]; duplicate {
			return errors.New("raw provider record repeats a JSON field")
		}
		keys[key] = struct{}{}
		var value json.RawMessage
		if err := keyDecoder.Decode(&value); err != nil {
			return errors.New("raw provider record values are invalid")
		}
	}
	closing, err := keyDecoder.Token()
	if err != nil || closing != json.Delim('}') || len(keys) != fieldCount {
		return errors.New("raw provider record has missing or unknown fields")
	}
	var keyTrailing any
	if err := keyDecoder.Decode(&keyTrailing); !errors.Is(err, io.EOF) {
		return errors.New("raw provider record contains trailing data")
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("raw provider record values are invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("raw provider record contains trailing data")
	}
	return nil
}

func compareRealCloudRawAndOperatorLogs(reconstructed, operator []realEdgeProviderLog) (string, error) {
	left := append([]realEdgeProviderLog(nil), reconstructed...)
	right := append([]realEdgeProviderLog(nil), operator...)
	sortRealCloudProviderLogs(left)
	sortRealCloudProviderLogs(right)
	leftBody, _ := json.Marshal(left)
	rightBody, _ := json.Marshal(right)
	if !bytes.Equal(leftBody, rightBody) {
		return "", errors.New("provider raw bytes reconstruct a different joined-v3 request closure than the operator JSONL")
	}
	return realCloudLowerSHA256(leftBody), nil
}

func applyRealCloudProviderRawAttestation(candidate realCloudProviderClosureFact, attestation realCloudProviderRawAttestation) realCloudProviderClosureFact {
	candidate.ProviderAttestation = attestation
	return candidate
}

func realCloudProviderRawAttestationForTest(records int) realCloudProviderRawAttestation {
	sha := func(value byte) string { return strings.Repeat(string(value), 64) }
	return realCloudProviderRawAttestation{
		Schema: realCloudProviderCollectorSchema, CollectorSourceSHA256: sha('a'), CollectorBuildSHA256: sha('b'),
		CollectorConfigSHA256: sha('c'), ProductConfigSHA256: sha('f'), ProviderDeploymentSHA256: sha('0'), RawJoinedSHA256: sha('d'), RedactedClosureSHA256: sha('e'), RawRecords: records,
		CFAccountID: "cf-account", CFZoneID: "cf-zone", CFZoneIdentitySHA256: sha('e'), CFLogpushJobID: 1, CFLogpushJobSHA256: sha('f'),
		CFLogReaderIdentitySHA256: sha('f'), CFLogWriterIdentitySHA256: sha('d'), CFLogControlIdentitySHA256: sha('e'),
		CFRawObjectIdentitySHA256: sha('1'), CFRawObjectETag: "cf-raw-etag", CFRawObjectSHA256: sha('2'),
		CFWorkerScript: "cf-auth", CFWorkerDeploymentID: "cf-auth-deploy", CFWorkerVersionID: "cf-auth-version",
		CFWorkerVersionETag: "cf-auth-etag", CFWorkerContentSHA256: sha('3'), CFWorkerBindingsSHA256: sha('4'), CFWorkerRuntimeSHA256: sha('a'),
		CFWorkerSecuritySHA256: sha('b'), CFWorkerRoutesSHA256: sha('5'), CFWorkerInventorySHA256: sha('6'),
		CFOriginWorkerScript: "cf-origin", CFOriginDeploymentID: "cf-origin-deploy", CFOriginVersionID: "cf-origin-version",
		CFOriginVersionETag: "cf-origin-etag", CFOriginContentSHA256: sha('6'), CFOriginBindingsSHA256: sha('7'), CFOriginSecuritySHA256: sha('9'), CFOriginExposureSHA256: sha('8'),
		CFTokenVerifierService: "cf-verifier", CFTokenVerifierVersionID: "cf-verifier-version", CFTokenVerifierVersionETag: "cf-verifier-etag",
		CFTokenVerifierContentSHA256: sha('9'), CFTokenVerifierBindingsSHA256: sha('b'), CFTokenVerifierSecuritySHA256: sha('c'),
		EdgeOneZoneID: "eo-zone", EdgeOneZoneIdentitySHA256: sha('8'), EdgeOneDomainsSHA256: sha('9'), EdgeOneLogTaskID: "eo-task", EdgeOneLogArea: "overseas", EdgeOneLogTaskSHA256: sha('a'),
		EdgeOneLogReaderIdentitySHA256: sha('a'), EdgeOneLogWriterIdentitySHA256: sha('f'), EdgeOneRawObjectIdentitySHA256: sha('b'), EdgeOneRawObjectETag: "eo-raw-etag", EdgeOneRawObjectSHA256: sha('c'),
		EdgeOneFunctionID: "eo-function", EdgeOneFunctionDomainSHA256: sha('a'), EdgeOneFunctionDomainBehaviorSHA256: sha('b'),
		EdgeOneFunctionContentSHA256: sha('d'), EdgeOneFunctionComponentsSHA256: sha('e'), EdgeOneFunctionReplicasSHA256: sha('f'),
		EdgeOneFunctionRuntimeSHA256: sha('c'), EdgeOneFunctionRulesSHA256: sha('e'), EdgeOneTokenVerifierDeploymentSHA256: sha('d'), CFRawObjects: 1, EdgeOneRawObjects: 1,
	}
}

func sortRealCloudProviderLogs(logs []realEdgeProviderLog) {
	sort.Slice(logs, func(i, j int) bool {
		left := realEdgeProviderClosureKey(logs[i].ProbePhase, logs[i].Vendor, logs[i].Generation, logs[i].TransactionID, logs[i].ParentRequestID)
		right := realEdgeProviderClosureKey(logs[j].ProbePhase, logs[j].Vendor, logs[j].Generation, logs[j].TransactionID, logs[j].ParentRequestID)
		return left < right
	})
}

func realCloudProviderCollectorIdentity() (string, string, error) {
	body, err := readRealCloudProviderRepositoryFile(realCloudProviderCollectorSource, realCloudProviderMaxContentBytes)
	if err != nil {
		return "", "", err
	}
	sourceSHA := realCloudLowerSHA256(body)
	clearRealCloudBytes(body)
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok || buildInfo == nil {
		return "", "", errors.New("collector Go build identity is unavailable")
	}
	type moduleIdentity struct{ Path, Version, Sum string }
	modules := make([]moduleIdentity, 0, len(buildInfo.Deps))
	for _, dependency := range buildInfo.Deps {
		if dependency == nil {
			continue
		}
		value := dependency
		if dependency.Replace != nil {
			value = dependency.Replace
		}
		modules = append(modules, moduleIdentity{value.Path, value.Version, value.Sum})
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	settings := append([]debug.BuildSetting(nil), buildInfo.Settings...)
	sort.Slice(settings, func(i, j int) bool { return settings[i].Key < settings[j].Key })
	identity := struct {
		GoVersion, Path, Version, SourceSHA string
		Settings                            []debug.BuildSetting
		Modules                             []moduleIdentity
	}{buildInfo.GoVersion, buildInfo.Path, buildInfo.Main.Version, sourceSHA, settings, modules}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", "", errors.New("encode collector build identity")
	}
	return sourceSHA, realCloudLowerSHA256(encoded), nil
}

func readRealCloudProviderRepositoryFile(relative string, maximum int64) ([]byte, error) {
	root, err := realEdgeRepositoryRoot()
	if err != nil {
		return nil, err
	}
	filename := filepath.Join(root, filepath.FromSlash(relative))
	return readRealCloudProviderStableRegularFile(filename, maximum, nil)
}

func readRealCloudProviderStableRegularFile(filename string, maximum int64, afterFirstRead func()) ([]byte, error) {
	before, err := os.Lstat(filename)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximum {
		return nil, errors.New("reviewed in-repo collector or edge bundle is absent or unsafe")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("open reviewed in-repo collector or edge bundle")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() || !opened.ModTime().Equal(before.ModTime()) {
		return nil, errors.New("reviewed in-repo collector or edge bundle changed before it was opened")
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(body)) != opened.Size() || int64(len(body)) > maximum {
		clearRealCloudBytes(body)
		return nil, errors.New("read reviewed in-repo collector or edge bundle exactly")
	}
	if afterFirstRead != nil {
		afterFirstRead()
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		clearRealCloudBytes(body)
		return nil, errors.New("recheck reviewed in-repo collector or edge bundle")
	}
	second, err := io.ReadAll(io.LimitReader(file, maximum+1))
	openedAfter, statErr := file.Stat()
	pathAfter, pathErr := os.Lstat(filename)
	stable := err == nil && statErr == nil && pathErr == nil && bytes.Equal(body, second) &&
		openedAfter.Size() == opened.Size() && openedAfter.ModTime().Equal(opened.ModTime()) && os.SameFile(opened, openedAfter) &&
		pathAfter.Mode()&os.ModeSymlink == 0 && pathAfter.Mode().IsRegular() && os.SameFile(opened, pathAfter) &&
		pathAfter.Size() == opened.Size() && pathAfter.ModTime().Equal(opened.ModTime())
	clearRealCloudBytes(second)
	if !stable {
		clearRealCloudBytes(body)
		return nil, errors.New("reviewed in-repo collector or edge bundle changed while it was read")
	}
	return body, nil
}

func realCloudProviderHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

func realCloudProviderBucketBaseURL(endpoint, bucket string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	parsed.Host = bucket + "." + parsed.Hostname()
	parsed.Path, parsed.RawPath, parsed.RawQuery, parsed.Fragment = "", "", "", ""
	return parsed.String()
}

func canonicalRealCloudProviderAPIBase(raw string, allowInsecure bool) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" ||
		parsed.Scheme != "https" && !(allowInsecure && parsed.Scheme == "http") {
		return "", errors.New("provider API base is invalid")
	}
	clean := strings.TrimSuffix(parsed.Path, "/")
	if parsed.Path != "" && parsed.Path != "/" && path.Clean(parsed.Path) != clean {
		return "", errors.New("provider API base path is not canonical")
	}
	return strings.TrimSuffix(raw, "/"), nil
}

func realCloudProviderCleanPath() string { return "/.sow/gated/" + realCloudGatedAssetPath }

func realCloudProviderCleanURLSHA(baseURL, cleanPath string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("provider CDN base is invalid")
	}
	parsed.Path = cleanPath
	parsed.RawPath = ""
	return realCloudLowerSHA256([]byte(parsed.String())), nil
}

func parseRealCloudProviderTimestamp(raw json.RawMessage) (time.Time, error) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		parsed, err := time.Parse(time.RFC3339Nano, text)
		if err == nil && parsed.Location() == time.UTC && !parsed.IsZero() {
			return parsed.UTC(), nil
		}
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		nanos, err := strconv.ParseInt(number.String(), 10, 64)
		if err == nil && nanos > 0 {
			return time.Unix(0, nanos).UTC(), nil
		}
	}
	return time.Time{}, errors.New("invalid timestamp")
}

func validRealCloudProviderIdentifier(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t /?#")
}

func validRealCloudProviderHTTPSURL(raw string, allowPath bool) bool {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if parsed.Host != strings.ToLower(parsed.Host) || parsed.Hostname() == "" || parsed.Port() != "" {
		return false
	}
	if parsed.RawPath != "" || strings.Contains(parsed.Path, "//") || path.Clean(parsed.Path) != parsed.Path {
		return false
	}
	if allowPath {
		return parsed.Path != "" && parsed.Path != "/" && !strings.HasSuffix(parsed.Path, "/") && parsed.String() == raw
	}
	return (parsed.Path == "" || parsed.Path == "/") && parsed.String() == raw
}

func validRealCloudProviderRouteList(values []string) bool {
	if len(values) == 0 {
		return false
	}
	previous := ""
	for _, value := range values {
		if value == "" || value != strings.TrimSpace(value) || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") ||
			strings.ContainsAny(value, "\\:?#[]@") || strings.Contains(value, "//") || path.Clean(value) != value || value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func validRealCloudProviderSecretNameList(actual, required []string) bool {
	if len(actual) != len(required) || len(actual) == 0 {
		return false
	}
	for index, name := range actual {
		if name != required[index] || !validRealCloudProviderSecretName(name) {
			return false
		}
	}
	return true
}

func validRealCloudProviderSecretName(value string) bool {
	if value == "" || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range value[1:] {
		if character != '_' && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validRealCloudProviderOptionalIdentifier(value string, maximum int) bool {
	return value == "" || validRealCloudProviderIdentifier(value, maximum)
}

func validRealCloudProviderObjectKey(value string) bool {
	return value != "" && len(value) <= 1024 && strings.TrimSpace(value) == value && !strings.HasPrefix(value, "/") &&
		path.Clean(value) == value && !strings.ContainsAny(value, "\x00\r\n\\?#")
}

func validRealCloudProviderRawPrefix(value string) bool {
	if value == "" || len(value) > 512 || value != strings.TrimSpace(value) || strings.HasPrefix(value, "/") || !strings.HasSuffix(value, "/") ||
		strings.ContainsAny(value, "\x00\r\n\\?#") {
		return false
	}
	clean := strings.TrimSuffix(value, "/")
	return clean != "" && path.Clean(clean) == clean && strings.HasPrefix(clean, "sow-provider-logs/")
}

func realCloudProviderRunSinkPrefix(root, runID string) string {
	return root + strings.TrimSpace(runID) + "/"
}

func validRealCloudProviderCOSBucket(value string) bool {
	separator := strings.LastIndexByte(value, '-')
	if separator <= 0 {
		return false
	}
	appID := value[separator+1:]
	if len(appID) < 5 || len(appID) > 20 || appID[0] == '0' {
		return false
	}
	for _, character := range appID {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validRealCloudEdgeOneLogArea(value string) bool {
	return value == "mainland" || value == "overseas"
}

func validRealCloudProviderETag(value string) bool {
	return value != "" && len(value) <= 512 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func sameRealCloudProviderStringSet(left, right []string) bool {
	left = sortedRealCloudProviderStrings(left)
	right = sortedRealCloudProviderStrings(right)
	return strings.Join(left, "\x00") == strings.Join(right, "\x00")
}

func sortedRealCloudProviderStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func stringPointerValues(values []*string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, stringValue(value))
	}
	return result
}

func int64Pointer(value int64) *int64    { return &value }
func uint64Pointer(value uint64) *uint64 { return &value }
func stringPointer(value string) *string { return &value }

func stringValuesPointers(values []string) []*string {
	result := make([]*string, 0, len(values))
	for _, value := range values {
		result = append(result, stringPointer(value))
	}
	return result
}

func hostOnly(raw string) string {
	parsed, _ := url.Parse(raw)
	return parsed.Host
}

func TestRealCloudProviderLogIdentitiesArePairwiseIsolated(t *testing.T) {
	environment := realCloudSafetyFixtureEnvironment()
	configuration := realCloudProviderConfigurationFixture(environment, realCloudLowerSHA256([]byte("verifier")))
	cfReader := realCloudStorageSecret{AccessKeyID: "loopback-cf-log-reader"}
	eoReader := realCloudStorageSecret{AccessKeyID: "loopback-eo-log-reader"}
	cfPublisher := realCloudStorageSecret{AccessKeyID: "loopback-cf-publisher"}
	eoPublisher := realCloudStorageSecret{AccessKeyID: "loopback-eo-publisher"}
	if err := validateRealCloudProviderLogReaderIdentities(configuration, cfReader, eoReader, cfPublisher, eoPublisher); err != nil {
		t.Fatalf("isolated provider identities were rejected: %v", err)
	}

	configuration.Cloudflare.RawWriterAccessKeySHA256 = configuration.Cloudflare.RawReaderAccessKeySHA256
	if err := validateRealCloudProviderLogReaderIdentities(configuration, cfReader, eoReader, cfPublisher, eoPublisher); err == nil || !strings.Contains(err.Error(), "pairwise distinct") {
		t.Fatalf("reader/writer credential collision was accepted: %v", err)
	}
	configuration.Cloudflare.RawWriterAccessKeySHA256 = realCloudLowerSHA256([]byte("loopback-cf-log-writer"))
	if err := validateRealCloudProviderLogReaderIdentities(configuration, cfReader, cfReader, cfPublisher, eoPublisher); err == nil || !strings.Contains(err.Error(), "pairwise distinct") {
		t.Fatalf("cross-provider reader credential collision was accepted: %v", err)
	}
	cfWriter := realCloudStorageSecret{AccessKeyID: "loopback-cf-log-writer", SecretAccessKey: "cf-writer-secret"}
	eoWriter := realCloudStorageSecret{AccessKeyID: "loopback-eo-log-writer", SecretAccessKey: "eo-writer-secret"}
	if err := validateRealCloudProviderLogWriterCredentials(configuration, cfWriter, eoWriter); err != nil {
		t.Fatalf("exact non-session writer credentials were rejected: %v", err)
	}
	cfWriter.SessionToken = "unsupported-temporary-token"
	if err := validateRealCloudProviderLogWriterCredentials(configuration, cfWriter, eoWriter); err == nil || !strings.Contains(err.Error(), "non-session") {
		t.Fatalf("writer session token was silently ignored: %v", err)
	}
}

func TestRealCloudProviderRawExportsReconstructExactOperatorClosure(t *testing.T) {
	environment, stages, operatorLogs, cfRaw, eoRaw := realCloudProviderRawParserFixture(t)
	reconstructed, redactedSHA, err := reconstructRealCloudProviderLogs(environment, stages, cfRaw, eoRaw)
	if err != nil {
		t.Fatalf("reconstruct exact provider raw exports: %v", err)
	}
	if !validRealCloudLowerSHA256(redactedSHA) || len(reconstructed) != len(operatorLogs) {
		t.Fatalf("raw reconstruction records=%d digest=%q", len(reconstructed), redactedSHA)
	}
	if _, err := compareRealCloudRawAndOperatorLogs(reconstructed, operatorLogs); err != nil {
		t.Fatalf("raw and operator closures differ: %v", err)
	}

	t.Run("missing-record", func(t *testing.T) {
		lines := bytes.Split(bytes.TrimSpace(cfRaw), []byte{'\n'})
		mutated := append(bytes.Join(lines[:len(lines)-1], []byte{'\n'}), '\n')
		if _, _, err := reconstructRealCloudProviderLogs(environment, stages, mutated, eoRaw); err == nil || !strings.Contains(err.Error(), "omits") {
			t.Fatalf("missing raw record err=%v", err)
		}
	})
	t.Run("query-leak", func(t *testing.T) {
		mutated := bytes.Replace(cfRaw, []byte(`"ClientRequestURI":"`+realCloudProviderCleanPath()+`"`), []byte(`"ClientRequestURI":"`+realCloudProviderCleanPath()+`?token=forbidden"`), 1)
		if _, _, err := reconstructRealCloudProviderLogs(environment, stages, mutated, eoRaw); err == nil || !strings.Contains(err.Error(), "token-bearing") {
			t.Fatalf("queried Cloudflare raw URL err=%v", err)
		}
	})
	t.Run("unknown-field", func(t *testing.T) {
		mutated := bytes.Replace(eoRaw, []byte(`{"EdgeCacheStatus"`), []byte(`{"Unexpected":true,"EdgeCacheStatus"`), 1)
		if _, _, err := reconstructRealCloudProviderLogs(environment, stages, cfRaw, mutated); err == nil || !strings.Contains(err.Error(), "unknown fields") {
			t.Fatalf("unknown EdgeOne field err=%v", err)
		}
	})
	t.Run("duplicate-cloudflare-field", func(t *testing.T) {
		mutated := bytes.Replace(cfRaw, []byte(`{"CacheCacheStatus":`), []byte(`{"CacheCacheStatus":"HIT","CacheCacheStatus":`), 1)
		if _, _, err := reconstructRealCloudProviderLogs(environment, stages, mutated, eoRaw); err == nil || !strings.Contains(err.Error(), "repeats a JSON field") {
			t.Fatalf("duplicate Cloudflare JSON key err=%v", err)
		}
	})
	t.Run("duplicate-edgeone-field", func(t *testing.T) {
		mutated := bytes.Replace(eoRaw, []byte(`{"EdgeCacheStatus":`), []byte(`{"EdgeCacheStatus":"HIT","EdgeCacheStatus":`), 1)
		if _, _, err := reconstructRealCloudProviderLogs(environment, stages, cfRaw, mutated); err == nil || !strings.Contains(err.Error(), "repeats a JSON field") {
			t.Fatalf("duplicate EdgeOne JSON key err=%v", err)
		}
	})
	t.Run("incomplete-final-line", func(t *testing.T) {
		mutated := append([]byte(nil), cfRaw[:len(cfRaw)-1]...)
		if _, _, err := reconstructRealCloudProviderLogs(environment, stages, mutated, eoRaw); err == nil || !strings.Contains(err.Error(), "newline-delimited") {
			t.Fatalf("unterminated provider JSONL err=%v", err)
		}
	})
	t.Run("operator-self-assertion", func(t *testing.T) {
		mutated := append([]realEdgeProviderLog(nil), operatorLogs...)
		mutated[0].CacheStatus = "BYPASS"
		if _, err := compareRealCloudRawAndOperatorLogs(reconstructed, mutated); err == nil {
			t.Fatal("operator-authored normalized closure overrode raw provider truth")
		}
	})
}

func TestRealCloudProviderRepositoryIdentityRejectsSymlinkAndInodeSwap(t *testing.T) {
	directory := t.TempDir()
	reviewed := filepath.Join(directory, "reviewed.js")
	other := filepath.Join(directory, "other.js")
	if err := os.WriteFile(reviewed, []byte("export default 1;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("export default 2;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink.js")
	if err := os.Symlink(reviewed, symlink); err != nil {
		t.Fatal(err)
	}
	if body, err := readRealCloudProviderStableRegularFile(symlink, 1024, nil); err == nil {
		clearRealCloudBytes(body)
		t.Fatal("symlink was accepted as reviewed repository identity")
	}
	if body, err := readRealCloudProviderStableRegularFile(reviewed, 1024, func() {
		if renameErr := os.Rename(other, reviewed); renameErr != nil {
			t.Fatalf("replace reviewed path: %v", renameErr)
		}
	}); err == nil {
		clearRealCloudBytes(body)
		t.Fatal("inode replacement during reviewed read was accepted")
	}
}

func TestRealCloudProviderCollectorStopsAtPinnedResourceGateBeforeCredentials(t *testing.T) {
	environment := realCloudSafetyFixtureEnvironment()
	values := realCloudSafetyEnvironmentMap(environment)
	for name, value := range values {
		t.Setenv(name, value)
	}
	// These are deliberately malformed. The compiled empty non-production
	// registry must reject the exact resources before config/credential decode,
	// SDK construction, transport construction, or any provider request.
	t.Setenv(realCloudProviderAttestationEnv, "not-json")
	t.Setenv(realCloudStorageCredentialCF, "not-json")
	t.Setenv(realCloudProviderLogStorageCredentialCF, "not-json")
	t.Setenv(realCloudCDNCredentialCF, "not-json")
	t.Setenv(realCloudStorageCredentialCOS, "not-json")
	t.Setenv(realCloudProviderLogStorageCredentialCOS, "not-json")
	t.Setenv(realCloudCDNCredentialCOS, "not-json")
	_, err := validateRealCloudProviderAPIAttestedRawClosure(t.Context(), nil, nil, nil)
	if !errors.Is(err, errRealCloudProviderAPIAttestationRequired) || !strings.Contains(err.Error(), "pinned non-production registry gate") {
		t.Fatalf("provider collector did not stop at the pre-credential resource gate: %v", err)
	}
}

func TestRealCloudProviderDeploymentRegistryIsIndependentAndStable(t *testing.T) {
	loaded, err := loadRealCloudPinnedProviderDeploymentRegistry()
	if err != nil {
		t.Fatalf("load reviewed provider deployment registry: %v", err)
	}
	if loaded.Schema != realCloudProviderDeploymentRegistrySchema || loaded.Deployments == nil {
		t.Fatal("reviewed provider deployment registry decoded without its frozen schema")
	}
	root, err := realEdgeRepositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	body, err := readRealCloudProviderStableRegularFile(filepath.Join(root, filepath.FromSlash(realCloudProviderDeploymentRegistryPath)), 256<<10, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clearRealCloudBytes(body)
	if _, err := decodeRealCloudPinnedProviderDeploymentRegistry(append(append([]byte(nil), body...), ' '), realCloudProviderDeploymentRegistrySHA256); err == nil {
		t.Fatal("mutated provider deployment registry bypassed the compiled reviewed digest")
	}

	environment := realCloudSafetyFixtureEnvironment()
	configuration := realCloudProviderConfigurationFixture(environment, strings.Repeat("a", 64))
	resourceBody, err := json.Marshal(realCloudTestResourceForEnvironment(environment))
	if err != nil {
		t.Fatal(err)
	}
	deploymentSHA, err := realCloudProviderDeploymentIdentity(environment, configuration)
	if err != nil {
		t.Fatal(err)
	}
	registry := realCloudPinnedProviderDeploymentRegistry{
		Schema: realCloudProviderDeploymentRegistrySchema,
		Deployments: []realCloudPinnedProviderDeploymentRegistryEntry{{
			Schema: realCloudProviderDeploymentEntrySchema, Purpose: "dedicated-disposable-non-production-test",
			ResourceSHA256: realCloudLowerSHA256(resourceBody), DeploymentSHA256: deploymentSHA,
		}},
	}
	if got, err := validateRealCloudProviderDeploymentAgainstRegistry(environment, configuration, registry); err != nil || got != deploymentSHA {
		t.Fatalf("exact administrator-pinned provider deployment rejected digest=%q err=%v", got, err)
	}
	mutatedRoot := configuration
	mutatedRoot.Cloudflare.RawRoot = "sow-provider-logs/unreviewed/"
	if got, err := realCloudProviderDeploymentIdentity(environment, mutatedRoot); err != nil || got == deploymentSHA {
		t.Fatalf("unreviewed stable raw root did not change deployment identity digest=%q err=%v", got, err)
	}
	mutated := configuration
	mutated.Cloudflare.TokenVerifierContentSHA256 = strings.Repeat("b", 64)
	if _, err := validateRealCloudProviderDeploymentAgainstRegistry(environment, mutated, registry); err == nil {
		t.Fatal("same-run provider config self-asserted an unreviewed token-verifier deployment")
	}
	mutated = configuration
	mutated.Runtime.PublicPrefixes = []string{"apt", "pkg", "unreviewed", "yum"}
	if _, err := validateRealCloudProviderDeploymentAgainstRegistry(environment, mutated, registry); err == nil {
		t.Fatal("unreviewed provider runtime allowlist bypassed deployment pin")
	}
	mutated = configuration
	mutated.Cloudflare.WorkerRuntime.CompatibilityDate = "2026-07-18"
	if _, err := validateRealCloudProviderDeploymentAgainstRegistry(environment, mutated, registry); err == nil {
		t.Fatal("unreviewed Cloudflare compatibility date bypassed deployment pin")
	}
	mutated = configuration
	mutated.EdgeOne.RealtimeLogArea = "mainland"
	if _, err := validateRealCloudProviderDeploymentAgainstRegistry(environment, mutated, registry); err == nil {
		t.Fatal("unreviewed EdgeOne realtime-log area bypassed deployment pin")
	}
	foreignEnvironment := environment
	foreignEnvironment.EdgeOneZoneID = "another-non-production-zone"
	if _, err := validateRealCloudProviderDeploymentAgainstRegistry(foreignEnvironment, configuration, registry); err == nil {
		t.Fatal("provider deployment pin was reused for a different resource topology")
	}
}

func TestRealCloudProviderAttestationConfigRequiresHTTPSBearerAndSeparateRawSinks(t *testing.T) {
	environment := realCloudSafetyFixtureEnvironment()
	configuration := realCloudProviderConfigurationFixture(environment, strings.Repeat("a", 64))
	encode := func(value realCloudProviderAttestationConfig) string {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	if _, _, err := decodeRealCloudProviderAttestationConfig(encode(configuration), environment, "real-edge-test-run-20260714"); err != nil {
		t.Fatalf("exact https-bearer provider config rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*realCloudProviderAttestationConfig)
	}{
		{"publisher-bucket-reuse", func(value *realCloudProviderAttestationConfig) { value.Cloudflare.RawBucket = environment.CFR2Bucket }},
		{"mode-inapplicable-cos-secret", func(value *realCloudProviderAttestationConfig) {
			value.Runtime.EdgeOneSecretNames = []string{"SOW_COS_SECRET_ID", "SOW_ORIGIN_BEARER", "SOW_TOKEN_VERIFIER_BEARER"}
		}},
		{"unsafe-raw-root", func(value *realCloudProviderAttestationConfig) {
			value.EdgeOne.RawRoot = "raw/edgeone/"
		}},
		{"unreviewed-token-verifier-binding-digest", func(value *realCloudProviderAttestationConfig) { value.Cloudflare.TokenVerifierBindingsSHA256 = "" }},
		{"missing-log-control-identity", func(value *realCloudProviderAttestationConfig) { value.Cloudflare.LogControlAccessKeySHA256 = "" }},
		{"writer-control-identity-reuse", func(value *realCloudProviderAttestationConfig) {
			value.Cloudflare.LogControlAccessKeySHA256 = value.Cloudflare.RawWriterAccessKeySHA256
		}},
		{"missing-auth-runtime-date", func(value *realCloudProviderAttestationConfig) { value.Cloudflare.WorkerRuntime.CompatibilityDate = "" }},
		{"unsorted-origin-runtime-flags", func(value *realCloudProviderAttestationConfig) {
			value.Cloudflare.OriginWorkerRuntime.CompatibilityFlags = []string{"z", "a"}
		}},
		{"nil-verifier-runtime-flags", func(value *realCloudProviderAttestationConfig) {
			value.Cloudflare.TokenVerifierRuntime.CompatibilityFlags = nil
		}},
		{"missing-edgeone-log-area", func(value *realCloudProviderAttestationConfig) {
			value.EdgeOne.RealtimeLogArea = ""
		}},
		{"invalid-edgeone-log-area", func(value *realCloudProviderAttestationConfig) {
			value.EdgeOne.RealtimeLogArea = "global"
		}},
		{"missing-edgeone-verifier-deployment-digest", func(value *realCloudProviderAttestationConfig) {
			value.Runtime.EdgeOneTokenVerifierDeploymentSHA256 = ""
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := configuration
			test.mutate(&candidate)
			if _, _, err := decodeRealCloudProviderAttestationConfig(encode(candidate), environment, "real-edge-test-run-20260714"); err == nil {
				t.Fatal("unsafe provider attestation config was accepted")
			}
		})
	}
}

func TestRealCloudProviderLogSinkLeaseSerializesRunsAndRecoversExpiredHolder(t *testing.T) {
	environment := realCloudSafetyFixtureEnvironment()
	configuration := realCloudProviderConfigurationFixture(environment, strings.Repeat("a", 64))
	store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
	base := time.Date(2026, 7, 17, 8, 0, 0, 0, time.UTC)
	first, err := acquireRealCloudProviderLogSinkLease(t.Context(), store, environment, configuration,
		"real-edge-test-run-20260717-a", strings.Repeat("1", 64), base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireRealCloudProviderLogSinkLease(t.Context(), store, environment, configuration,
		"real-edge-test-run-20260717-b", strings.Repeat("2", 64), base.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "another live execution") {
		t.Fatalf("live provider log-sink lease was taken over: %v", err)
	}
	if err := first.renew(t.Context(), base.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	replacement, err := acquireRealCloudProviderLogSinkLease(t.Context(), store, environment, configuration,
		"real-edge-test-run-20260717-b", strings.Repeat("2", 64), base.Add(8*time.Minute))
	if err != nil {
		t.Fatalf("expired provider log-sink lease was not replaced by CAS: %v", err)
	}
	if err := first.release(t.Context()); err == nil {
		t.Fatal("stale provider log-sink holder released its replacement")
	}
	if err := replacement.release(t.Context()); err != nil || store.key != "" {
		t.Fatalf("replacement provider log-sink lease did not release exactly err=%v", err)
	}
}

func TestRealCloudProviderRuntimeInventoriesAreExactAndSecretFree(t *testing.T) {
	environment := realCloudSafetyFixtureEnvironment()
	configuration := realCloudProviderConfigurationFixture(environment, strings.Repeat("a", 64))
	fakeBindings, err := realCloudProviderFakeCloudflareAuthBindings(environment, configuration)
	if err != nil {
		t.Fatal(err)
	}
	bindingBody, _ := json.Marshal(fakeBindings)
	var bindings []workers.ScriptVersionGetResponseResourcesBinding
	if err := json.Unmarshal(bindingBody, &bindings); err != nil {
		t.Fatal(err)
	}
	serviceSHA, runtimeSHA, err := validateRealCloudCloudflareAuthBindings(bindings, environment, configuration)
	if err != nil || !validRealCloudLowerSHA256(serviceSHA) || !validRealCloudLowerSHA256(runtimeSHA) {
		t.Fatalf("exact Cloudflare runtime inventory rejected service=%q runtime=%q err=%v", serviceSHA, runtimeSHA, err)
	}
	bindings = append(bindings, workers.ScriptVersionGetResponseResourcesBinding{
		Name: "SOW_COS_SECRET_ID", Type: workers.ScriptVersionGetResponseResourcesBindingsTypeSecretText,
	})
	if _, _, err := validateRealCloudCloudflareAuthBindings(bindings, environment, configuration); err == nil || !strings.Contains(err.Error(), "mode-inapplicable") {
		t.Fatalf("Cloudflare accepted a mode-inapplicable COS secret: %v", err)
	}
	verifierSHA, err := validateRealCloudCloudflareVerifierBindings(nil)
	if err != nil || verifierSHA != configuration.Cloudflare.TokenVerifierBindingsSHA256 {
		t.Fatalf("empty reviewed verifier binding inventory mismatch digest=%q err=%v", verifierSHA, err)
	}
	if _, err := validateRealCloudCloudflareVerifierBindings([]workers.ScriptVersionGetResponseResourcesBinding{{
		Name: "REPOSITORY", Type: workers.ScriptVersionGetResponseResourcesBindingsTypeR2Bucket, BucketName: environment.CFR2Bucket,
	}}); err == nil {
		t.Fatal("token verifier received an unreviewed repository-bucket capability")
	}

	variables, err := realCloudProviderFakeEdgeOneRuntimeVariables(environment, configuration.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	variableBody, _ := json.Marshal(variables)
	var edgeVariables []*teo.FunctionEnvironmentVariable
	if err := json.Unmarshal(variableBody, &edgeVariables); err != nil {
		t.Fatal(err)
	}
	if digest, err := validateRealCloudEdgeOneRuntimeEnvironment(edgeVariables, environment, configuration.Runtime); err != nil || !validRealCloudLowerSHA256(digest) {
		t.Fatalf("exact EdgeOne runtime inventory rejected digest=%q err=%v", digest, err)
	}
	for _, variable := range edgeVariables {
		if variable != nil && stringValue(variable.Value) != "" {
			t.Fatal("EdgeOne runtime value remained in memory after redacted comparison")
		}
	}
	variables = append(variables, map[string]any{"Key": "SOW_COS_SECRET_KEY", "Value": "not-used-in-https-bearer", "Type": "string"})
	variableBody, _ = json.Marshal(variables)
	edgeVariables = nil
	if err := json.Unmarshal(variableBody, &edgeVariables); err != nil {
		t.Fatal(err)
	}
	if _, err := validateRealCloudEdgeOneRuntimeEnvironment(edgeVariables, environment, configuration.Runtime); err == nil || !strings.Contains(err.Error(), "mode-inapplicable") {
		t.Fatalf("EdgeOne accepted a mode-inapplicable COS secret: %v", err)
	}
	encoded, _ := json.Marshal(realCloudProviderRawAttestationForTest(12))
	if bytes.Contains(encoded, []byte("loopback-secret")) || containsRealEdgeURLLeak(encoded) {
		t.Fatal("redacted provider attestation persisted runtime secret material or URLs")
	}
}

func realCloudProviderRawParserFixture(t *testing.T) (realCloudEnvironment, []realEdgeMultiPoPStageEvidence, []realEdgeProviderLog, []byte, []byte) {
	t.Helper()
	environment := realCloudSafetyFixtureEnvironment()
	environment.CFCDNBase = "https://sow-test-cf.test.invalid"
	environment.CFBetaCDNBase = "https://sow-test-cf-beta.test.invalid"
	environment.COSCDNBase = "https://sow-test-eo.test.invalid"
	environment.COSBetaBase = "https://sow-ci-eo-beta.test.invalid"
	runID := "real-edge-test-run-20260714"
	t.Setenv(realCloudRunIDEnv, runID)
	baseTime := time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)
	before := realEdgeTestEvidence(4, "generation-four", baseTime)
	after := attachRealEdgeTestPrePurge(before, realEdgeTestEvidence(5, "generation-five", baseTime.Add(10*time.Minute)))
	stages := []realEdgeMultiPoPStageEvidence{before, after}
	productBody, _, _, err := realCloudProviderProductContracts(environment)
	if err != nil {
		t.Fatal(err)
	}
	productConfigSHA := realCloudLowerSHA256(productBody)
	bases := map[string]string{"cloudflare": environment.CFCDNBase, "edgeone": environment.COSCDNBase}
	for stageIndex := range stages {
		for vendor, base := range bases {
			cleanSHA, err := realCloudProviderCleanURLSHA(base, realCloudProviderCleanPath())
			if err != nil {
				t.Fatal(err)
			}
			stage := stages[stageIndex].Vendors[vendor]
			stage.ConfigSHA256 = productConfigSHA
			stage.CleanURLSHA256 = cleanSHA
			for index := range stage.Observations {
				stage.Observations[index].CleanURLSHA256 = cleanSHA
			}
			if stage.PrePurge != nil {
				stage.PrePurge.CleanURLSHA256 = cleanSHA
				for index := range stage.PrePurge.Observations {
					stage.PrePurge.Observations[index].CleanURLSHA256 = cleanSHA
				}
			}
			stages[stageIndex].Vendors[vendor] = stage
		}
	}
	operatorLogs := append(append([]realEdgeProviderLog(nil), before.ProviderLogs...), after.ProviderLogs...)
	for index := range operatorLogs {
		cleanSHA, err := realCloudProviderCleanURLSHA(bases[operatorLogs[index].Vendor], realCloudProviderCleanPath())
		if err != nil {
			t.Fatal(err)
		}
		operatorLogs[index].CleanURLSHA256 = cleanSHA
	}
	var cfBody, eoBody bytes.Buffer
	cfEncoder, eoEncoder := json.NewEncoder(&cfBody), json.NewEncoder(&eoBody)
	for _, record := range operatorLogs {
		switch record.Vendor {
		case "cloudflare":
			if err := cfEncoder.Encode(realCloudCloudflareRawLog{
				CacheCacheStatus: record.CacheStatus, ClientRequestURI: realCloudProviderCleanPath(), EdgeColoCode: record.Region,
				EdgeColoID: json.Number(record.NodeID), EdgeStartTimestamp: json.RawMessage(strconv.Quote(record.ObservedAt)),
				ParentRayID: record.ParentRequestID, RayID: record.RequestID,
			}); err != nil {
				t.Fatal(err)
			}
		case "edgeone":
			if err := eoEncoder.Encode(realCloudEdgeOneRawLog{
				EdgeCacheStatus: record.CacheStatus, EdgeFunctionSubrequest: 1, EdgeServerID: record.NodeID, EdgeServerIP: record.NodeIP,
				EdgeSeverRegion: record.Region, ParentRequestID: record.ParentRequestID, RequestHost: hostOnly(environment.COSCDNBase),
				RequestID: record.RequestID, RequestScheme: "HTTPS", RequestTime: record.ObservedAt, RequestUrl: realCloudProviderCleanPath(),
				RequestUrlQueryString: "",
			}); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unexpected provider fixture vendor %q", record.Vendor)
		}
	}
	return environment, stages, operatorLogs, cfBody.Bytes(), eoBody.Bytes()
}

func TestRealCloudProviderCollectorUsesExactSDKAndSignedObjectContracts(t *testing.T) {
	environment, stages, operatorLogs, cfRaw, eoRaw := realCloudProviderRawParserFixture(t)
	authBundle, err := readRealCloudProviderRepositoryFile("edge/dist/cloudflare-worker.mjs", realCloudProviderMaxContentBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer clearRealCloudBytes(authBundle)
	originBundle, err := readRealCloudProviderRepositoryFile("edge/dist/cloudflare-origin-worker.mjs", realCloudProviderMaxContentBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer clearRealCloudBytes(originBundle)
	edgeOneBundle, err := readRealCloudProviderRepositoryFile("edge/dist/edgeone.js", realCloudProviderMaxContentBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer clearRealCloudBytes(edgeOneBundle)
	verifierBundle := []byte("export default {async fetch(){return new Response('{}')}};\n")
	configuration := realCloudProviderConfigurationFixture(environment, realCloudLowerSHA256(verifierBundle))
	configurationBody, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	fake := &realCloudProviderFakeAPI{
		t: t, environment: environment, configuration: configuration, authBundle: authBundle, originBundle: originBundle,
		verifierBundle: verifierBundle, edgeOneBundle: edgeOneBundle, cfRaw: cfRaw, eoRaw: eoRaw, requests: make(map[string]int),
	}
	server := httptest.NewServer(fake)
	defer server.Close()
	storageSecret := realCloudStorageSecret{AccessKeyID: "test-access", SecretAccessKey: "test-secret-access"}
	cfSecret := realCloudCloudflareSecret{APIToken: "test-cloudflare-token"}
	eoSecret := realCloudTencentSecret{SecretID: "test-tencent-id", SecretKey: "test-tencent-secret"}
	clients, err := newRealCloudProviderCollectorClients(environment, configuration, storageSecret, cfSecret, storageSecret, eoSecret, realCloudProviderCollectorEndpoints{
		CloudflareAPIURL: server.URL + "/client/v4", EdgeOneAPIURL: server.URL,
		CFObjectBaseURL: server.URL + "/" + configuration.Cloudflare.RawBucket, EOObjectBaseURL: server.URL + "/" + configuration.EdgeOne.RawBucket,
		EOFunctionDomainBaseURL: server.URL,
		HTTPClient:              server.Client(), AllowInsecure: true,
	})
	if err != nil {
		t.Fatalf("construct loopback provider clients: %v", err)
	}
	providerLeaseStore := &fakeRealCloudCloudflareBootstrapLeaseStore{}
	clients.logSinkLeaseStore = providerLeaseStore
	runID := strings.TrimSpace(os.Getenv(realCloudRunIDEnv))
	if err := prepareRealCloudProviderPerRunRawSinksAfterGate(t.Context(), environment, runID, configuration,
		realCloudStorageSecret{AccessKeyID: "loopback-cf-log-writer", SecretAccessKey: "loopback-cf-log-writer-secret"},
		realCloudStorageSecret{AccessKeyID: "loopback-eo-log-writer", SecretAccessKey: "loopback-eo-log-writer-secret"}, clients); err != nil {
		t.Fatalf("prepare loopback per-run provider raw sinks: %v", err)
	}
	forbidden := []string{storageSecret.SecretAccessKey, cfSecret.APIToken, eoSecret.SecretKey, "loopback-cf-log-writer-secret", "loopback-eo-log-writer-secret"}
	attestation, err := collectRealCloudProviderRawAttestationAfterGate(t.Context(), environment, configuration, configurationBody, stages, operatorLogs, forbidden, clients)
	if err != nil {
		t.Fatalf("collect loopback provider attestation: %v", err)
	}
	if attestation.Schema != realCloudProviderCollectorSchema || attestation.RawRecords != len(operatorLogs) ||
		attestation.CFOriginWorkerScript != configuration.Cloudflare.OriginWorkerScript ||
		attestation.CFTokenVerifierService != configuration.Cloudflare.TokenVerifierService ||
		attestation.EdgeOneLogArea != configuration.EdgeOne.RealtimeLogArea ||
		!validRealCloudLowerSHA256(attestation.CFWorkerSecuritySHA256) || !validRealCloudLowerSHA256(attestation.CFOriginSecuritySHA256) ||
		!validRealCloudLowerSHA256(attestation.CFTokenVerifierSecuritySHA256) || !validRealCloudLowerSHA256(attestation.CFWorkerInventorySHA256) ||
		!validRealCloudLowerSHA256(attestation.CFWorkerRoutesSHA256) || !validRealCloudLowerSHA256(attestation.EdgeOneFunctionRulesSHA256) {
		t.Fatalf("incomplete provider attestation: %#v", attestation)
	}
	encoded, err := json.Marshal(attestation)
	if err != nil || containsRealEdgeForbidden(encoded, forbidden) || containsRealEdgeURLLeak(encoded) {
		t.Fatalf("attestation leaked a URL or credential err=%v body=%s", err, encoded)
	}
	fake.assertRequests(t)
	beforeCFUpdates, beforeEOUpdates := fake.mutationCounts()
	if beforeCFUpdates != 1 || beforeEOUpdates != 1 {
		t.Fatalf("loopback exporter setup mutations cf=%d eo=%d want=1,1", beforeCFUpdates, beforeEOUpdates)
	}
	if providerLeaseStore.key != "" {
		t.Fatal("successful provider log-sink setup did not conditionally release its R2 lease")
	}
	fake.unsafeEdgeZone = true
	if err := prepareRealCloudProviderPerRunRawSinksAfterGate(t.Context(), environment, runID, configuration,
		realCloudStorageSecret{AccessKeyID: "loopback-cf-log-writer", SecretAccessKey: "loopback-cf-log-writer-secret"},
		realCloudStorageSecret{AccessKeyID: "loopback-eo-log-writer", SecretAccessKey: "loopback-eo-log-writer-secret"}, clients); err == nil || !strings.Contains(err.Error(), "non-production") {
		t.Fatalf("provider setup did not reject production-like EdgeOne zone before mutation: %v", err)
	}
	fake.unsafeEdgeZone = false
	if afterCF, afterEO := fake.mutationCounts(); afterCF != beforeCFUpdates || afterEO != beforeEOUpdates {
		t.Fatalf("unsafe EdgeOne zone reached provider mutation: before=%d,%d after=%d,%d", beforeCFUpdates, beforeEOUpdates, afterCF, afterEO)
	}
	fake.unsafeCFZone = true
	if err := prepareRealCloudProviderPerRunRawSinksAfterGate(t.Context(), environment, runID, configuration,
		realCloudStorageSecret{AccessKeyID: "loopback-cf-log-writer", SecretAccessKey: "loopback-cf-log-writer-secret"},
		realCloudStorageSecret{AccessKeyID: "loopback-eo-log-writer", SecretAccessKey: "loopback-eo-log-writer-secret"}, clients); err == nil || !strings.Contains(err.Error(), "non-production") {
		t.Fatalf("provider setup did not reject production-like Cloudflare zone before mutation: %v", err)
	}
	fake.unsafeCFZone = false
	if afterCF, afterEO := fake.mutationCounts(); afterCF != beforeCFUpdates || afterEO != beforeEOUpdates {
		t.Fatalf("unsafe Cloudflare zone reached provider mutation: before=%d,%d after=%d,%d", beforeCFUpdates, beforeEOUpdates, afterCF, afterEO)
	}
	fake.mu.Lock()
	cfObjectRequest := "GET /" + configuration.Cloudflare.RawBucket + "/" + fake.cfRawObjectKey()
	fake.mutateCFRawAtRequest = fake.requests[cfObjectRequest] + 2
	fake.mu.Unlock()
	if _, err := collectRealCloudProviderRawAttestationAfterGate(t.Context(), environment, configuration, configurationBody, stages, operatorLogs, forbidden, clients); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("loopback raw-object mutation bypassed the final TOCTOU bracket: %v", err)
	}
	fake.mutateCFRawAtRequest = 0

	fake.extraZoneRoute = true
	if _, _, err := collectRealCloudCloudflareRoutingClosure(t.Context(), clients.cloudflare, environment, configuration.Cloudflare); err == nil || !strings.Contains(err.Error(), "outside the exact auth Worker closure") {
		t.Fatalf("extra Cloudflare zone route bypass was accepted: %v", err)
	}
	fake.extraZoneRoute = false
	fake.unrelatedZoneRoute = true
	if _, _, err := collectRealCloudCloudflareRoutingClosure(t.Context(), clients.cloudflare, environment, configuration.Cloudflare); err != nil {
		t.Fatalf("unrelated shared-zone route was treated as part of the reviewed host closure: %v", err)
	}
	fake.unrelatedZoneRoute = false
	fake.extraCFCustomDomain = true
	if _, _, err := collectRealCloudCloudflareRoutingClosure(t.Context(), clients.cloudflare, environment, configuration.Cloudflare); err != nil {
		t.Fatalf("complete unrelated Cloudflare custom domain was treated as managed exposure: %v", err)
	}
	fake.extraCFCustomDomain = false
	fake.incompleteCFCustomDomain = true
	if _, _, err := collectRealCloudCloudflareRoutingClosure(t.Context(), clients.cloudflare, environment, configuration.Cloudflare); err == nil || !strings.Contains(err.Error(), "invalid identity") {
		t.Fatalf("incomplete Cloudflare custom-domain identity was accepted: %v", err)
	}
	fake.incompleteCFCustomDomain = false
	fake.extraCFLogpushJob = true
	if _, err := collectRealCloudCloudflareControl(t.Context(), environment, configuration, clients.cloudflare); err == nil || !strings.Contains(err.Error(), "can include a reviewed host") {
		t.Fatalf("overlapping Cloudflare Logpush job was accepted: %v", err)
	}
	fake.extraCFLogpushJob = false
	fake.unrelatedCFLogpushJob = true
	if _, err := collectRealCloudCloudflareControl(t.Context(), environment, configuration, clients.cloudflare); err != nil {
		t.Fatalf("unrelated shared-zone Cloudflare Logpush job was rejected: %v", err)
	}
	fake.unrelatedCFLogpushJob = false
	fake.conflictingCFLogpushDestination = true
	if _, err := collectRealCloudCloudflareControl(t.Context(), environment, configuration, clients.cloudflare); err == nil || !strings.Contains(err.Error(), "can write the SOW raw bucket") {
		t.Fatalf("unrelated Cloudflare Logpush job could reuse the SOW raw bucket: %v", err)
	}
	fake.conflictingCFLogpushDestination = false
	fake.badCFLogpushFilter = true
	if _, err := collectRealCloudCloudflareControl(t.Context(), environment, configuration, clients.cloudflare); err == nil || !strings.Contains(err.Error(), "exact main-and-beta host filter") {
		t.Fatalf("non-exact Cloudflare Logpush host filter was accepted: %v", err)
	}
	fake.badCFLogpushFilter = false
	fake.extraCFSchedule = true
	if _, err := collectRealCloudCloudflareControl(t.Context(), environment, configuration, clients.cloudflare); err == nil || !strings.Contains(err.Error(), "schedule") {
		t.Fatalf("Cloudflare Worker schedule bypass was accepted: %v", err)
	}
	fake.extraCFSchedule = false
	fake.extraCFTailConsumer = true
	if _, err := collectRealCloudCloudflareControl(t.Context(), environment, configuration, clients.cloudflare); err == nil || !strings.Contains(err.Error(), "tail consumer") {
		t.Fatalf("Cloudflare Worker tail consumer bypass was accepted: %v", err)
	}
	fake.extraCFTailConsumer = false
	fake.unsafeCFSettings = true
	if _, err := collectRealCloudCloudflareControl(t.Context(), environment, configuration, clients.cloudflare); err == nil || !strings.Contains(err.Error(), "closed runtime") {
		t.Fatalf("Cloudflare Worker unbound runtime setting was accepted: %v", err)
	}
	fake.unsafeCFSettings = false
	fake.mu.Lock()
	workerInventoryRequest := "GET /client/v4/accounts/" + configuration.Cloudflare.AccountID + "/workers/scripts"
	fake.mutateCFWorkerInventoryAtRequest = fake.requests[workerInventoryRequest] + 2
	fake.mu.Unlock()
	if _, err := collectRealCloudCloudflareControl(t.Context(), environment, configuration, clients.cloudflare); err == nil || !strings.Contains(err.Error(), "complete Worker") {
		t.Fatalf("Cloudflare cross-time Worker inventory was accepted: %v", err)
	}
	fake.mutateCFWorkerInventoryAtRequest = 0
	fake.extraEdgeTask = true
	if _, err := collectRealCloudEdgeOneControl(t.Context(), environment, configuration, clients.edgeOne, clients.probeEOFunctionDomain); err == nil || !strings.Contains(err.Error(), "non-exact") {
		t.Fatalf("second EdgeOne log task was accepted: %v", err)
	}
	fake.extraEdgeTask = false
	fake.badEdgeLogArea = true
	if _, err := collectRealCloudEdgeOneControl(t.Context(), environment, configuration, clients.edgeOne, clients.probeEOFunctionDomain); err == nil || !strings.Contains(err.Error(), "exact-area") {
		t.Fatalf("wrong immutable EdgeOne log-task area was accepted: %v", err)
	}
	fake.badEdgeLogArea = false
	fake.taskTotalCountOverride = 2
	if _, err := collectRealCloudEdgeOneControl(t.Context(), environment, configuration, clients.edgeOne, clients.probeEOFunctionDomain); err == nil || !strings.Contains(err.Error(), "non-exact") {
		t.Fatalf("truncated EdgeOne log-task query was accepted: %v", err)
	}
	fake.taskTotalCountOverride = 0
	fake.functionTotalCountOverride = 2
	if _, err := collectRealCloudEdgeOneControl(t.Context(), environment, configuration, clients.edgeOne, clients.probeEOFunctionDomain); err == nil || !strings.Contains(err.Error(), "non-exact") {
		t.Fatalf("truncated EdgeOne function query was accepted: %v", err)
	}
	fake.functionTotalCountOverride = 0
	fake.unsafeEdgeZone = true
	if _, _, err := collectRealCloudEdgeOneZoneClosure(t.Context(), environment, configuration.EdgeOne, "", clients.edgeOne); err == nil || !strings.Contains(err.Error(), "non-production") {
		t.Fatalf("production-like EdgeOne zone identity was accepted: %v", err)
	}
	fake.unsafeEdgeZone = false
	fake.extraEdgeDomain = true
	if _, _, err := collectRealCloudEdgeOneZoneClosure(t.Context(), environment, configuration.EdgeOne, "", clients.edgeOne); err == nil || !strings.Contains(err.Error(), "exact main-and-beta closure") {
		t.Fatalf("third EdgeOne acceleration domain was accepted: %v", err)
	}
	fake.extraEdgeDomain = false
	if _, _, err := collectRealCloudEdgeOneZoneClosure(t.Context(), environment, configuration.EdgeOne, "other.sow-test.example.invalid", clients.edgeOne); err == nil || !strings.Contains(err.Error(), "pinned identity") {
		t.Fatalf("EdgeOne readiness accepted a live zone name that differs from the pinned identity: %v", err)
	}
	fake.paginateEdgeDomains = true
	fake.edgeDomainPageCalls = 0
	if _, domainsSHA, err := collectRealCloudEdgeOneZoneClosure(t.Context(), environment, configuration.EdgeOne, "", clients.edgeOne); err != nil || !validRealCloudLowerSHA256(domainsSHA) || fake.edgeDomainPageCalls != 2 {
		t.Fatalf("full EdgeOne acceleration-domain pagination was not consumed: pages=%d digest=%q err=%v", fake.edgeDomainPageCalls, domainsSHA, err)
	}
	fake.paginateEdgeDomains = false
	fake.edgeDomainPageCalls = 0
	fake.badEdgeFunctionDomain = true
	if _, err := collectRealCloudEdgeOneControl(t.Context(), environment, configuration, clients.edgeOne, clients.probeEOFunctionDomain); err == nil || !strings.Contains(err.Error(), "non-production") {
		t.Fatalf("production-like EdgeOne default function domain was accepted: %v", err)
	}
	fake.badEdgeFunctionDomain = false
	fake.extraEdgeComponent = true
	if _, err := collectRealCloudEdgeOneControl(t.Context(), environment, configuration, clients.edgeOne, clients.probeEOFunctionDomain); err == nil || !strings.Contains(err.Error(), "component binding") {
		t.Fatalf("unreviewed EdgeOne function component was accepted: %v", err)
	}
	fake.extraEdgeComponent = false
	fake.extraEdgeReplica = true
	if _, err := collectRealCloudEdgeOneControl(t.Context(), environment, configuration, clients.edgeOne, clients.probeEOFunctionDomain); err == nil || !strings.Contains(err.Error(), "executable replica") {
		t.Fatalf("unreviewed EdgeOne function replica was accepted: %v", err)
	}
	fake.extraEdgeReplica = false
	fake.extraEdgeRule = true
	if _, err := collectRealCloudEdgeOneControl(t.Context(), environment, configuration, clients.edgeOne, clients.probeEOFunctionDomain); err == nil || !strings.Contains(err.Error(), "extra or duplicate host") {
		t.Fatalf("competing EdgeOne function rule was accepted: %v", err)
	}
	fake.extraEdgeRule = false
	fake.extraEdgeRuntimeSecret = true
	if _, err := collectRealCloudEdgeOneControl(t.Context(), environment, configuration, clients.edgeOne, clients.probeEOFunctionDomain); err == nil || !strings.Contains(err.Error(), "mode-inapplicable") {
		t.Fatalf("mode-inapplicable EdgeOne COS secret was accepted: %v", err)
	}
	fake.extraEdgeRuntimeSecret = false
	beforeFailedCF, beforeFailedEO := fake.mutationCounts()
	fake.failEOLogTaskUpdate = true
	if err := prepareRealCloudProviderPerRunRawSinksAfterGate(t.Context(), environment, runID, configuration,
		realCloudStorageSecret{AccessKeyID: "loopback-cf-log-writer", SecretAccessKey: "loopback-cf-log-writer-secret"},
		realCloudStorageSecret{AccessKeyID: "loopback-eo-log-writer", SecretAccessKey: "loopback-eo-log-writer-secret"}, clients); err == nil || !strings.Contains(err.Error(), "configure EdgeOne") {
		t.Fatalf("injected cross-provider sink failure was not reported: %v", err)
	}
	fake.failEOLogTaskUpdate = false
	afterFailedCF, afterFailedEO := fake.mutationCounts()
	if afterFailedCF != beforeFailedCF+1 || afterFailedEO != beforeFailedEO || providerLeaseStore.key == "" {
		t.Fatalf("partial provider setup did not retain the serialization lease cf=%d/%d eo=%d/%d lease=%q", beforeFailedCF, afterFailedCF, beforeFailedEO, afterFailedEO, providerLeaseStore.key)
	}
	retained, err := decodeRealCloudProviderLogSinkLease(providerLeaseStore.body)
	if err != nil || retained.RunID != runID {
		t.Fatalf("retained provider setup lease is invalid: %#v err=%v", retained, err)
	}
	providerLeaseStore.key, providerLeaseStore.body, providerLeaseStore.etag = "", nil, ""
	fake.unrelatedCFLogpushJob = true
	if err := prepareRealCloudProviderPerRunRawSinksAfterGate(t.Context(), environment, runID, configuration,
		realCloudStorageSecret{AccessKeyID: "loopback-cf-log-writer", SecretAccessKey: "loopback-cf-log-writer-secret"},
		realCloudStorageSecret{AccessKeyID: "loopback-eo-log-writer", SecretAccessKey: "loopback-eo-log-writer-secret"}, clients); err != nil {
		t.Fatalf("safe unrelated Cloudflare Logpush job broke id-selected provider setup: %v", err)
	}
	fake.unrelatedCFLogpushJob = false
	if providerLeaseStore.key != "" {
		t.Fatal("id-selected provider setup did not release its exact lease")
	}
}

func realCloudProviderConfigurationFixture(environment realCloudEnvironment, verifierContentSHA string) realCloudProviderAttestationConfig {
	productBody, cloudflareContract, _, err := realCloudProviderProductContracts(environment)
	if err != nil {
		panic(err)
	}
	var publicPrefixes, publicKeys []string
	if err := json.Unmarshal([]byte(cloudflareContract.Variables[sowconfig.EdgeRuntimePublicPrefixesVariable]), &publicPrefixes); err != nil {
		panic(err)
	}
	if err := json.Unmarshal([]byte(cloudflareContract.Variables[sowconfig.EdgeRuntimePublicKeysVariable]), &publicKeys); err != nil {
		panic(err)
	}
	functionDomain := "sow-test-function.edge.test.invalid"
	return realCloudProviderAttestationConfig{
		Schema: realCloudProviderAttestationSchema, ProductConfigSHA256: realCloudLowerSHA256(productBody),
		Cloudflare: realCloudCloudflareAttestationConfig{
			AccountID: "test-account", ZoneID: environment.CFZoneID, LogpushJobID: 17,
			WorkerScript: "sow-test-auth", WorkerRuntime: realCloudCloudflareWorkerRuntimeContract{CompatibilityDate: "2026-07-17", CompatibilityFlags: []string{}},
			OriginWorkerScript: "sow-test-origin", OriginWorkerRuntime: realCloudCloudflareWorkerRuntimeContract{CompatibilityDate: "2026-07-17", CompatibilityFlags: []string{}},
			TokenVerifierService: "pigsty-entitlements", TokenVerifierRuntime: realCloudCloudflareWorkerRuntimeContract{CompatibilityDate: "2026-07-17", CompatibilityFlags: []string{}},
			TokenVerifierContentSHA256: verifierContentSHA, TokenVerifierBindingsSHA256: realCloudLowerSHA256([]byte("[]")),
			RawReaderAccessKeySHA256:  realCloudLowerSHA256([]byte("loopback-cf-log-reader")),
			RawWriterAccessKeySHA256:  realCloudLowerSHA256([]byte("loopback-cf-log-writer")),
			LogControlAccessKeySHA256: realCloudLowerSHA256([]byte("loopback-cf-log-control")),
			RawBucket:                 "sow-test-cf-provider-logs", RawRoot: "sow-provider-logs/cloudflare/",
		},
		EdgeOne: realCloudEdgeOneAttestationConfig{
			ZoneID: environment.EdgeOneZoneID, RealtimeLogTaskID: "sow-test-log-task", RealtimeLogArea: "overseas", FunctionID: "sow-test-function", FunctionDomainSHA256: realCloudLowerSHA256([]byte(functionDomain)),
			RawReaderAccessKeySHA256: realCloudLowerSHA256([]byte("loopback-eo-log-reader")),
			RawWriterAccessKeySHA256: realCloudLowerSHA256([]byte("loopback-eo-log-writer")),
			RawBucket:                "sow-test-eo-provider-logs-1250000000", RawRoot: "sow-provider-logs/edgeone/",
		},
		Runtime: realCloudEdgeRuntimeAttestationConfig{
			TokenVerifier: cloudflareContract.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable], PublicPrefixes: publicPrefixes,
			PublicKeys: publicKeys, EdgeOneTokenVerifierURL: "https://verifier.test.invalid/v1/verify",
			EdgeOneTokenVerifierDeploymentSHA256: realCloudLowerSHA256([]byte("loopback-edgeone-verifier-deployment")),
			CloudflareSecretNames:                []string{"SOW_ORIGIN_BEARER"},
			EdgeOneSecretNames:                   []string{"SOW_ORIGIN_BEARER", "SOW_TOKEN_VERIFIER_BEARER"},
		},
	}
}

type realCloudProviderFakeAPI struct {
	t                                                       *testing.T
	environment                                             realCloudEnvironment
	configuration                                           realCloudProviderAttestationConfig
	authBundle, originBundle, verifierBundle, edgeOneBundle []byte
	cfRaw, eoRaw                                            []byte
	extraZoneRoute, unrelatedZoneRoute                      bool
	extraCFCustomDomain, incompleteCFCustomDomain           bool
	extraCFTailConsumer, extraCFSchedule, unsafeCFSettings  bool
	extraCFLogpushJob, unrelatedCFLogpushJob                bool
	conflictingCFLogpushDestination, badCFLogpushFilter     bool
	unsafeCFZone                                            bool
	extraEdgeRuntimeSecret, unsafeEdgeZone, extraEdgeDomain bool
	failEOLogTaskUpdate                                     bool
	extraEdgeTask, badEdgeLogArea, extraEdgeRule            bool
	extraEdgeComponent, extraEdgeReplica                    bool
	badEdgeFunctionDomain                                   bool
	taskTotalCountOverride, functionTotalCountOverride      int
	paginateEdgeDomains                                     bool
	edgeDomainPageCalls                                     int
	mutateCFRawAtRequest                                    int
	mutateCFWorkerInventoryAtRequest                        int
	cfLogpushUpdates, eoLogTaskUpdates                      int
	mu                                                      sync.Mutex
	requests                                                map[string]int
}

func (fake *realCloudProviderFakeAPI) mutationCounts() (int, int) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.cfLogpushUpdates, fake.eoLogTaskUpdates
}

func (fake *realCloudProviderFakeAPI) cfRawObjectKey() string {
	return realCloudProviderRunSinkPrefix(fake.configuration.Cloudflare.RawRoot, strings.TrimSpace(os.Getenv(realCloudRunIDEnv))) + "cloudflare-part-0001.jsonl"
}

func (fake *realCloudProviderFakeAPI) eoRawObjectKey() string {
	return realCloudProviderRunSinkPrefix(fake.configuration.EdgeOne.RawRoot, strings.TrimSpace(os.Getenv(realCloudRunIDEnv))) + "edgeone-part-0001.jsonl"
}

func (fake *realCloudProviderFakeAPI) cloudflareLogJob() map[string]any {
	configuration := fake.configuration.Cloudflare
	destination := realCloudCloudflareDestinationURL(configuration, strings.TrimSpace(os.Getenv(realCloudRunIDEnv)), realCloudStorageSecret{
		AccessKeyID: "loopback-cf-log-writer", SecretAccessKey: "loopback-cf-log-writer-secret",
	})
	filter := realCloudCloudflareHostFilter(fake.environment)
	if fake.badCFLogpushFilter {
		body, _ := json.Marshal(map[string]any{"where": map[string]any{"key": "ClientRequestHost", "operator": "eq", "value": hostOnly(fake.environment.CFCDNBase)}})
		filter = string(body)
	}
	return map[string]any{
		"id": configuration.LogpushJobID, "dataset": "http_requests", "destination_conf": destination, "filter": filter,
		"enabled": true, "error_message": "", "output_options": map[string]any{
			"field_names": realCloudCloudflareRawFields, "merge_subrequests": false, "output_type": "ndjson", "sample_rate": 1, "timestamp_format": "rfc3339ns",
		},
	}
}

func (fake *realCloudProviderFakeAPI) cloudflareUnrelatedLogJob() map[string]any {
	destination := "https://logs.example.invalid/unrelated"
	if fake.conflictingCFLogpushDestination {
		destination = "r2://" + fake.configuration.Cloudflare.RawBucket + "/unrelated"
	}
	filterBody, _ := json.Marshal(map[string]any{
		"where": map[string]any{
			"key": "ClientRequestHost", "operator": "eq", "value": "unrelated.test.invalid",
		},
	})
	return map[string]any{
		"id": fake.configuration.Cloudflare.LogpushJobID + 2, "dataset": "http_requests",
		"destination_conf": destination, "filter": string(filterBody),
		"enabled": true, "error_message": "", "output_options": map[string]any{
			"field_names": realCloudCloudflareRawFields, "merge_subrequests": false, "output_type": "ndjson", "sample_rate": 1, "timestamp_format": "rfc3339ns",
		},
	}
}

func (fake *realCloudProviderFakeAPI) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	fake.mu.Lock()
	requestKey := request.Method + " " + request.URL.Path
	fake.requests[requestKey]++
	requestCount := fake.requests[requestKey]
	fake.mu.Unlock()
	if request.URL.Path == "/.sow/provider-attestation-deny" {
		if request.Method != http.MethodGet || request.Host != "sow-test-function.edge.test.invalid" {
			http.Error(writer, "invalid default-domain probe", http.StatusBadRequest)
			return
		}
		http.Error(writer, "not found", http.StatusNotFound)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/client/v4/") {
		if request.Method != http.MethodGet && request.Method != http.MethodPut || request.Header.Get("Authorization") != "Bearer test-cloudflare-token" {
			http.Error(writer, "invalid Cloudflare provider request", http.StatusForbidden)
			return
		}
		fake.serveCloudflare(writer, request, requestCount)
		return
	}
	for bucket, entry := range map[string]struct {
		key  string
		body []byte
	}{
		fake.configuration.Cloudflare.RawBucket: {fake.cfRawObjectKey(), fake.cfRaw},
		fake.configuration.EdgeOne.RawBucket:    {fake.eoRawObjectKey(), fake.eoRaw},
	} {
		if request.URL.Path == "/"+bucket && request.Method == http.MethodGet && request.URL.Query().Get("list-type") == "2" {
			if !strings.Contains(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
				http.Error(writer, "invalid signed object inventory", http.StatusForbidden)
				return
			}
			wantedPrefix := strings.TrimSuffix(entry.key, path.Base(entry.key))
			if request.URL.Query().Get("prefix") != wantedPrefix {
				http.Error(writer, "missing exact signed per-run prefix", http.StatusBadRequest)
				return
			}
			writer.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(writer, fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>%s</Name><Prefix>%s</Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><EncodingType>url</EncodingType><Contents><Key>%s</Key><LastModified>2026-07-14T00:00:00.000Z</LastModified><ETag>&#34;loopback-object-etag&#34;</ETag><Size>%d</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>`, bucket, url.PathEscape(wantedPrefix), url.PathEscape(entry.key), len(entry.body)))
			return
		}
		objectPath := "/" + bucket + "/" + entry.key
		if request.URL.Path != objectPath {
			continue
		}
		if request.Method != http.MethodGet || !strings.Contains(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			http.Error(writer, "invalid signed object read", http.StatusForbidden)
			return
		}
		object := entry.body
		if request.URL.Path == "/"+fake.configuration.Cloudflare.RawBucket+"/"+fake.cfRawObjectKey() && fake.mutateCFRawAtRequest == requestCount {
			object = append(append([]byte(nil), object...), '\n')
		}
		writer.Header().Set("ETag", `"loopback-object-etag"`)
		writer.Header().Set("Content-Length", strconv.Itoa(len(object)))
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(object)
		return
	}
	if request.URL.Path == "/" && request.Method == http.MethodPost && request.Header.Get("X-TC-Action") != "" {
		if !strings.Contains(request.Header.Get("Authorization"), "TC3-HMAC-SHA256") {
			http.Error(writer, "invalid Tencent provider request", http.StatusForbidden)
			return
		}
		fake.serveEdgeOne(writer, request)
		return
	}
	http.Error(writer, "unexpected loopback provider request", http.StatusNotFound)
}

func (fake *realCloudProviderFakeAPI) serveCloudflare(writer http.ResponseWriter, request *http.Request, requestCount int) {
	configuration := fake.configuration.Cloudflare
	prefix := "/client/v4"
	pathValue := strings.TrimPrefix(request.URL.Path, prefix)
	writeEnvelope := func(result any) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result})
	}
	switch pathValue {
	case fmt.Sprintf("/zones/%s", configuration.ZoneID):
		zoneName := "test.invalid"
		if fake.unsafeCFZone {
			zoneName = "production.example.invalid"
		}
		writeEnvelope(map[string]any{"id": configuration.ZoneID, "name": zoneName, "status": "active", "paused": false, "type": "full", "account": map[string]any{"id": configuration.AccountID, "name": "sow test"}})
	case fmt.Sprintf("/zones/%s/logpush/jobs", configuration.ZoneID):
		jobs := []map[string]any{fake.cloudflareLogJob()}
		if fake.extraCFLogpushJob {
			extra := fake.cloudflareLogJob()
			extra["id"] = configuration.LogpushJobID + 1
			extra["destination_conf"] = "https://logs.example.invalid/overlapping"
			jobs = append(jobs, extra)
		}
		if fake.unrelatedCFLogpushJob || fake.conflictingCFLogpushDestination {
			jobs = append(jobs, fake.cloudflareUnrelatedLogJob())
		}
		writeEnvelope(jobs)
	case fmt.Sprintf("/zones/%s/logpush/jobs/%d", configuration.ZoneID, configuration.LogpushJobID):
		if request.Method != http.MethodPut || validateRealCloudProviderFakeJSONRequest(request, map[string]any{
			"destination_conf": realCloudCloudflareDestinationURL(configuration, strings.TrimSpace(os.Getenv(realCloudRunIDEnv)), realCloudStorageSecret{AccessKeyID: "loopback-cf-log-writer", SecretAccessKey: "loopback-cf-log-writer-secret"}),
			"enabled":          true, "filter": realCloudCloudflareHostFilter(fake.environment),
			"output_options": map[string]any{"field_names": realCloudCloudflareRawFields, "merge_subrequests": false, "output_type": "ndjson", "sample_rate": 1, "timestamp_format": "rfc3339ns"},
		}) != nil {
			http.Error(writer, "invalid Cloudflare per-run Logpush setup", http.StatusBadRequest)
			return
		}
		fake.mu.Lock()
		fake.cfLogpushUpdates++
		fake.mu.Unlock()
		writeEnvelope(fake.cloudflareLogJob())
	case fmt.Sprintf("/zones/%s/workers/routes", configuration.ZoneID):
		routes := []map[string]any{
			{"id": "main-route", "pattern": hostOnly(fake.environment.CFCDNBase) + "/*", "script": configuration.WorkerScript},
			{"id": "beta-route", "pattern": hostOnly(fake.environment.CFBetaCDNBase) + "/*", "script": configuration.WorkerScript},
		}
		if fake.extraZoneRoute {
			routes = append(routes, map[string]any{"id": "bypass-route", "pattern": hostOnly(fake.environment.CFCDNBase) + "/.sow/*", "script": "unexpected-bypass-worker"})
		}
		if fake.unrelatedZoneRoute {
			routes = append(routes, map[string]any{"id": "unrelated-route", "pattern": "unrelated.test.invalid/*", "script": "unrelated-worker"})
		}
		writeEnvelope(routes)
	case fmt.Sprintf("/accounts/%s/workers/domains", configuration.AccountID):
		domains := []map[string]any{}
		if fake.extraCFCustomDomain || fake.incompleteCFCustomDomain {
			domain := map[string]any{"id": "unrelated-domain", "cert_id": "unrelated-cert", "environment": "", "hostname": "unrelated.test.invalid",
				"service": "unrelated-worker", "zone_id": configuration.ZoneID, "zone_name": "test.invalid"}
			if fake.incompleteCFCustomDomain {
				delete(domain, "service")
			}
			domains = append(domains, domain)
		}
		writeEnvelope(domains)
	case fmt.Sprintf("/accounts/%s/workers/scripts", configuration.AccountID):
		authTailConsumers := []any{}
		if fake.extraCFTailConsumer {
			authTailConsumers = append(authTailConsumers, map[string]any{"service": "unreviewed-tail"})
		}
		scripts := []map[string]any{
			{"id": configuration.WorkerScript, "routes": []map[string]any{
				{"id": "main-route", "pattern": hostOnly(fake.environment.CFCDNBase) + "/*", "script": configuration.WorkerScript},
				{"id": "beta-route", "pattern": hostOnly(fake.environment.CFBetaCDNBase) + "/*", "script": configuration.WorkerScript},
			}, "tail_consumers": authTailConsumers},
			{"id": configuration.OriginWorkerScript, "routes": []any{}, "tail_consumers": []any{}},
			{"id": configuration.TokenVerifierService, "routes": []any{}, "tail_consumers": []any{}},
		}
		if fake.unrelatedZoneRoute {
			scripts = append(scripts, map[string]any{"id": "unrelated-worker", "routes": []map[string]any{{"id": "unrelated-route", "pattern": "unrelated.test.invalid/*", "script": "unrelated-worker"}}, "tail_consumers": []any{}})
		}
		if fake.mutateCFWorkerInventoryAtRequest == requestCount {
			scripts = append(scripts, map[string]any{"id": "concurrent-unrelated-worker", "routes": []any{}, "tail_consumers": []any{}})
		}
		writeEnvelope(scripts)
	default:
		for script, content := range map[string][]byte{
			configuration.WorkerScript:         fake.authBundle,
			configuration.OriginWorkerScript:   fake.originBundle,
			configuration.TokenVerifierService: fake.verifierBundle,
		} {
			base := fmt.Sprintf("/accounts/%s/workers/scripts/%s", configuration.AccountID, script)
			runtimeContract := configuration.WorkerRuntime
			if script == configuration.OriginWorkerScript {
				runtimeContract = configuration.OriginWorkerRuntime
			} else if script == configuration.TokenVerifierService {
				runtimeContract = configuration.TokenVerifierRuntime
			}
			switch pathValue {
			case base + "/deployments":
				writeEnvelope(map[string]any{"deployments": []map[string]any{{
					"id": script + "-deployment", "created_on": "2026-07-14T00:00:00Z", "source": "api", "strategy": "percentage",
					"versions": []map[string]any{{"percentage": 100, "version_id": script + "-version"}},
				}}})
				return
			case base + "/versions/" + script + "-version":
				bindings := []map[string]any{}
				switch script {
				case configuration.WorkerScript:
					var bindingErr error
					bindings, bindingErr = realCloudProviderFakeCloudflareAuthBindings(fake.environment, fake.configuration)
					if bindingErr != nil {
						http.Error(writer, "invalid fake Cloudflare runtime", http.StatusInternalServerError)
						return
					}
				case configuration.OriginWorkerScript:
					bindings = []map[string]any{{"name": "REPOSITORY", "type": "r2_bucket", "bucket_name": fake.environment.CFR2Bucket}}
				}
				writeEnvelope(map[string]any{"id": script + "-version", "resources": map[string]any{
					"script": map[string]any{"etag": script + "-etag"}, "bindings": bindings,
					"script_runtime": map[string]any{"compatibility_date": runtimeContract.CompatibilityDate, "compatibility_flags": runtimeContract.CompatibilityFlags,
						"limits": map[string]any{"cpu_ms": 0}, "migration_tag": "", "usage_model": "standard"},
				}})
				return
			case base + "/content/v2":
				writer.Header().Set("Content-Type", "application/javascript")
				_, _ = writer.Write(content)
				return
			case base + "/subdomain":
				writeEnvelope(map[string]any{"enabled": false, "previews_enabled": false})
				return
			case base + "/settings":
				usageModel := "standard"
				if fake.unsafeCFSettings && script == configuration.WorkerScript {
					usageModel = "unbound"
				}
				writeEnvelope(map[string]any{
					"annotations": map[string]any{}, "bindings": []any{}, "cache_options": map[string]any{"enabled": false, "cross_version_cache": false},
					"compatibility_date": runtimeContract.CompatibilityDate, "compatibility_flags": runtimeContract.CompatibilityFlags,
					"limits": map[string]any{"cpu_ms": 0, "subrequests": 0}, "logpush": false,
					"observability": map[string]any{"enabled": false, "head_sampling_rate": 0,
						"logs":   map[string]any{"enabled": false, "invocation_logs": false, "destinations": []any{}, "head_sampling_rate": 0, "persist": false},
						"traces": map[string]any{"enabled": false, "destinations": []any{}, "head_sampling_rate": 0, "persist": false, "propagation_policy": ""}},
					"placement": map[string]any{}, "tags": []any{}, "tail_consumers": []any{}, "usage_model": usageModel,
				})
				return
			case base + "/schedules":
				schedules := []any{}
				if fake.extraCFSchedule && script == configuration.WorkerScript {
					schedules = append(schedules, map[string]any{"cron": "0 * * * *"})
				}
				writeEnvelope(map[string]any{"schedules": schedules})
				return
			}
		}
		http.Error(writer, "unexpected Cloudflare SDK path", http.StatusNotFound)
	}
}

func realCloudProviderFakeCloudflareAuthBindings(environment realCloudEnvironment, configuration realCloudProviderAttestationConfig) ([]map[string]any, error) {
	bindings := []map[string]any{
		{"name": "ORIGIN", "type": "service", "service": configuration.Cloudflare.OriginWorkerScript, "environment": configuration.Cloudflare.OriginWorkerEnvironment},
		{"name": "TOKEN_VERIFIER", "type": "service", "service": configuration.Cloudflare.TokenVerifierService, "environment": configuration.Cloudflare.TokenVerifierEnvironment},
	}
	variables, err := realCloudProviderExpectedRuntimeVariables(environment, configuration.Runtime, "cloudflare")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(variables))
	for name := range variables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		bindings = append(bindings, map[string]any{"name": name, "type": "plain_text", "text": variables[name]})
	}
	for _, name := range configuration.Runtime.CloudflareSecretNames {
		bindings = append(bindings, map[string]any{"name": name, "type": "secret_text"})
	}
	return bindings, nil
}

func realCloudProviderFakeEdgeOneRuntimeVariables(environment realCloudEnvironment, runtime realCloudEdgeRuntimeAttestationConfig) ([]map[string]any, error) {
	variables, err := realCloudProviderExpectedRuntimeVariables(environment, runtime, "edgeone")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(variables))
	for name := range variables {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]map[string]any, 0, len(names)+len(runtime.EdgeOneSecretNames))
	for _, name := range names {
		result = append(result, map[string]any{"Key": name, "Value": variables[name], "Type": "string"})
	}
	for _, name := range runtime.EdgeOneSecretNames {
		result = append(result, map[string]any{"Key": name, "Value": "loopback-secret-value-never-persisted", "Type": "string"})
	}
	return result, nil
}

func (fake *realCloudProviderFakeAPI) serveEdgeOne(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	action := request.Header.Get("X-TC-Action")
	configuration := fake.configuration.EdgeOne
	var response any
	switch action {
	case "DescribeZones":
		if err := validateRealCloudProviderFakeTencentRequest(request, map[string]any{
			"Offset": 0, "Limit": 100, "Filters": []map[string]any{{"Name": "zone-id", "Values": []string{configuration.ZoneID}}},
		}); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		zoneName := "test.invalid"
		if fake.unsafeEdgeZone {
			zoneName = "production.example.invalid"
		}
		response = map[string]any{"TotalCount": 1, "Zones": []map[string]any{{
			"ZoneId": configuration.ZoneID, "ZoneName": zoneName, "Type": "partial", "Status": "active", "ActiveStatus": "active", "Paused": false,
		}}}
	case "DescribeAccelerationDomains":
		domainOffset := 0
		if fake.paginateEdgeDomains {
			domainOffset = fake.edgeDomainPageCalls
			fake.edgeDomainPageCalls++
		}
		if err := validateRealCloudProviderFakeTencentRequest(request, map[string]any{
			"ZoneId": configuration.ZoneID, "Offset": domainOffset, "Limit": 200,
		}); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		domains := []map[string]any{
			{"ZoneId": configuration.ZoneID, "DomainName": hostOnly(fake.environment.COSCDNBase), "DomainStatus": "online"},
			{"ZoneId": configuration.ZoneID, "DomainName": hostOnly(fake.environment.COSBetaBase), "DomainStatus": "online"},
		}
		if fake.extraEdgeDomain {
			domains = append(domains, map[string]any{"ZoneId": configuration.ZoneID, "DomainName": "sow-test-extra.test.invalid", "DomainStatus": "online"})
		}
		totalCount := len(domains)
		if fake.paginateEdgeDomains {
			domains = domains[domainOffset : domainOffset+1]
		}
		response = map[string]any{"TotalCount": totalCount, "AccelerationDomains": domains}
	case "ModifyRealtimeLogDeliveryTask":
		if err := validateRealCloudProviderFakeTencentRequest(request, map[string]any{
			"ZoneId": configuration.ZoneID, "TaskId": configuration.RealtimeLogTaskID, "DeliveryStatus": "enabled",
			"EntityList": []string{hostOnly(fake.environment.COSCDNBase), hostOnly(fake.environment.COSBetaBase)}, "Fields": realCloudEdgeOneRawFields,
			"CustomFields": []any{}, "DeliveryConditions": []any{}, "Sample": 1000, "LogFormat": map[string]any{"FormatType": "json"},
			"S3": map[string]any{
				"Endpoint": strings.TrimSuffix(fake.environment.COSEndpoint, "/"), "Region": fake.environment.COSRegion,
				"Bucket":   configuration.RawBucket + "/" + realCloudProviderRunSinkPrefix(configuration.RawRoot, strings.TrimSpace(os.Getenv(realCloudRunIDEnv))),
				"AccessId": "loopback-eo-log-writer", "AccessKey": "loopback-eo-log-writer-secret", "CompressType": "",
			},
		}); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		if fake.failEOLogTaskUpdate {
			http.Error(writer, "injected EdgeOne log-task failure", http.StatusServiceUnavailable)
			return
		}
		fake.mu.Lock()
		fake.eoLogTaskUpdates++
		fake.mu.Unlock()
		response = map[string]any{}
	case "DescribeRealtimeLogDeliveryTasks":
		if err := validateRealCloudProviderFakeTencentRequest(request, map[string]any{
			"ZoneId": configuration.ZoneID, "Offset": 0, "Limit": 1000,
		}); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		tasks := []map[string]any{{
			"TaskId": configuration.RealtimeLogTaskID, "DeliveryStatus": "enabled", "TaskType": "s3",
			"EntityList": []string{hostOnly(fake.environment.COSCDNBase), hostOnly(fake.environment.COSBetaBase)},
			"LogType":    "l7-access-logs", "Area": configuration.RealtimeLogArea, "Fields": realCloudEdgeOneRawFields, "Sample": 1000,
			"S3": map[string]any{
				"Endpoint": fake.environment.COSEndpoint, "Region": fake.environment.COSRegion,
				"Bucket":   configuration.RawBucket + "/" + realCloudProviderRunSinkPrefix(configuration.RawRoot, strings.TrimSpace(os.Getenv(realCloudRunIDEnv))),
				"AccessId": "loopback-eo-log-writer", "AccessKey": "loopback-eo-log-writer-secret", "CompressType": "",
			},
		}}
		if fake.badEdgeLogArea {
			tasks[0]["Area"] = "mainland"
		}
		if fake.extraEdgeTask {
			extra := make(map[string]any, len(tasks[0]))
			for key, value := range tasks[0] {
				extra[key] = value
			}
			extra["TaskId"] = "sow-test-unreviewed-log-task"
			tasks = append(tasks, extra)
		}
		totalCount := len(tasks)
		if fake.taskTotalCountOverride != 0 {
			totalCount = fake.taskTotalCountOverride
		}
		response = map[string]any{"TotalCount": totalCount, "RealtimeLogDeliveryTasks": tasks}
	case "DescribeFunctions":
		if err := validateRealCloudProviderFakeTencentRequest(request, map[string]any{
			"ZoneId": configuration.ZoneID, "FunctionIds": []string{configuration.FunctionID}, "Offset": 0, "Limit": 200,
		}); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		totalCount := 1
		if fake.functionTotalCountOverride != 0 {
			totalCount = fake.functionTotalCountOverride
		}
		functionDomain := "sow-test-function.edge.test.invalid"
		if fake.badEdgeFunctionDomain {
			functionDomain = "production-function.example.invalid"
		}
		response = map[string]any{"TotalCount": totalCount, "Functions": []map[string]any{{
			"FunctionId": configuration.FunctionID, "ZoneId": configuration.ZoneID, "Domain": functionDomain, "Content": string(fake.edgeOneBundle),
		}}}
	case "DescribeFunctionComponentBindings":
		if err := validateRealCloudProviderFakeTencentRequest(request, map[string]any{
			"ZoneId": configuration.ZoneID, "FunctionId": configuration.FunctionID, "Offset": 0, "Limit": 1000,
		}); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		bindings := []any{}
		if fake.extraEdgeComponent {
			bindings = append(bindings, map[string]any{"ComponentId": "sow-test-unreviewed-component"})
		}
		response = map[string]any{"TotalCount": len(bindings), "FunctionComponentBindings": bindings}
	case "DescribeFunctionReplicas":
		if err := validateRealCloudProviderFakeTencentRequest(request, map[string]any{
			"ZoneId": configuration.ZoneID, "FunctionId": configuration.FunctionID, "Offset": 0, "Limit": 200,
		}); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		replicas := []any{}
		if fake.extraEdgeReplica {
			replicas = append(replicas, map[string]any{"FunctionId": "sow-test-unreviewed-replica"})
		}
		response = map[string]any{"TotalCount": len(replicas), "FunctionReplicas": replicas}
	case "DescribeFunctionRuntimeEnvironment":
		if err := validateRealCloudProviderFakeTencentRequest(request, map[string]any{
			"ZoneId": configuration.ZoneID, "FunctionId": configuration.FunctionID,
		}); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		variables, err := realCloudProviderFakeEdgeOneRuntimeVariables(fake.environment, fake.configuration.Runtime)
		if err != nil {
			http.Error(writer, "invalid fake EdgeOne runtime", http.StatusInternalServerError)
			return
		}
		if fake.extraEdgeRuntimeSecret {
			variables = append(variables, map[string]any{"Key": "SOW_COS_SECRET_ID", "Value": "mode-inapplicable-secret", "Type": "string"})
		}
		response = map[string]any{"EnvironmentVariables": variables}
	case "DescribeFunctionRules":
		if err := validateRealCloudProviderFakeTencentRequest(request, map[string]any{
			"ZoneId": configuration.ZoneID,
		}); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		rules := []map[string]any{{
			"RuleId": "sow-main-beta-rule", "TriggerType": "direct", "FunctionId": configuration.FunctionID,
			"FunctionRuleConditions": []map[string]any{
				{"RuleConditions": []map[string]any{{"Operator": "equal", "Target": "host", "Values": []string{hostOnly(fake.environment.COSCDNBase)}, "IgnoreCase": true}}},
				{"RuleConditions": []map[string]any{{"Operator": "equal", "Target": "host", "Values": []string{hostOnly(fake.environment.COSBetaBase)}, "IgnoreCase": true}}},
			},
		}}
		if fake.extraEdgeRule {
			rules = append(rules, map[string]any{
				"RuleId": "sow-unreviewed-competing-rule", "TriggerType": "direct", "FunctionId": configuration.FunctionID,
				"FunctionRuleConditions": []map[string]any{{"RuleConditions": []map[string]any{{
					"Operator": "equal", "Target": "host", "Values": []string{hostOnly(fake.environment.COSCDNBase)}, "IgnoreCase": true,
				}}}},
			})
		}
		response = map[string]any{"FunctionRules": rules}
	default:
		http.Error(writer, "unexpected EdgeOne SDK action", http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(writer).Encode(map[string]any{"Response": mergeRealCloudProviderFakeResponse(response, map[string]any{"RequestId": "loopback-request"})})
}

func validateRealCloudProviderFakeJSONRequest(request *http.Request, wanted any) error {
	body, err := io.ReadAll(io.LimitReader(request.Body, (64<<10)+1))
	if err != nil || len(body) == 0 || len(body) > 64<<10 {
		return errors.New("provider SDK request body is absent or oversized")
	}
	defer clearRealCloudBytes(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var actual any
	if err := decoder.Decode(&actual); err != nil {
		return errors.New("provider SDK request body is invalid JSON")
	}
	wantedBody, _ := json.Marshal(wanted)
	wantedDecoder := json.NewDecoder(bytes.NewReader(wantedBody))
	wantedDecoder.UseNumber()
	var normalizedWanted any
	_ = wantedDecoder.Decode(&normalizedWanted)
	actualBody, _ := json.Marshal(actual)
	wantedBody, _ = json.Marshal(normalizedWanted)
	if !bytes.Equal(actualBody, wantedBody) {
		return errors.New("provider SDK request body differs from the exact setup contract")
	}
	return nil
}

func validateRealCloudProviderFakeTencentRequest(request *http.Request, wanted any) error {
	body, err := io.ReadAll(io.LimitReader(request.Body, (64<<10)+1))
	if err != nil || len(body) == 0 || len(body) > 64<<10 {
		return errors.New("Tencent SDK request body is absent or oversized")
	}
	defer clearRealCloudBytes(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var actual any
	if err := decoder.Decode(&actual); err != nil {
		return errors.New("Tencent SDK request body is invalid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Tencent SDK request body contains trailing data")
	}
	wantedBody, err := json.Marshal(wanted)
	if err != nil {
		return errors.New("encode expected Tencent SDK request")
	}
	wantedDecoder := json.NewDecoder(bytes.NewReader(wantedBody))
	wantedDecoder.UseNumber()
	var normalizedWanted any
	if err := wantedDecoder.Decode(&normalizedWanted); err != nil {
		return errors.New("decode expected Tencent SDK request")
	}
	actualBody, _ := json.Marshal(actual)
	wantedBody, _ = json.Marshal(normalizedWanted)
	if !bytes.Equal(actualBody, wantedBody) {
		return errors.New("Tencent SDK request does not exactly bind the expected zone, function, task, filter, and page bounds")
	}
	return nil
}

func mergeRealCloudProviderFakeResponse(left, right any) map[string]any {
	result := make(map[string]any)
	for key, value := range left.(map[string]any) {
		result[key] = value
	}
	for key, value := range right.(map[string]any) {
		result[key] = value
	}
	return result
}

func (fake *realCloudProviderFakeAPI) assertRequests(t *testing.T) {
	t.Helper()
	fake.mu.Lock()
	defer fake.mu.Unlock()
	want := map[string]int{
		"GET /client/v4/zones/" + fake.configuration.Cloudflare.ZoneID:                            3,
		"GET /client/v4/zones/" + fake.configuration.Cloudflare.ZoneID + "/logpush/jobs":          3,
		"PUT /client/v4/zones/" + fake.configuration.Cloudflare.ZoneID + "/logpush/jobs/17":       1,
		"GET /client/v4/accounts/" + fake.configuration.Cloudflare.AccountID + "/workers/scripts": 4,
		"GET /client/v4/zones/" + fake.configuration.Cloudflare.ZoneID + "/workers/routes":        4,
		"GET /client/v4/accounts/" + fake.configuration.Cloudflare.AccountID + "/workers/domains": 4,
		"GET /" + fake.configuration.Cloudflare.RawBucket:                                         2,
		"GET /" + fake.configuration.EdgeOne.RawBucket:                                            2,
		"GET /" + fake.configuration.Cloudflare.RawBucket + "/" + fake.cfRawObjectKey():           2,
		"GET /" + fake.configuration.EdgeOne.RawBucket + "/" + fake.eoRawObjectKey():              2,
		"GET /.sow/provider-attestation-deny":                                                     2,
		"POST /":                                                                                  20,
	}
	for _, script := range []string{fake.configuration.Cloudflare.WorkerScript, fake.configuration.Cloudflare.OriginWorkerScript, fake.configuration.Cloudflare.TokenVerifierService} {
		base := "GET /client/v4/accounts/" + fake.configuration.Cloudflare.AccountID + "/workers/scripts/" + script
		want[base+"/deployments"] = 4
		want[base+"/versions/"+script+"-version"] = 2
		want[base+"/content/v2"] = 2
		want[base+"/settings"] = 4
		want[base+"/schedules"] = 4
		want[base+"/subdomain"] = 8
	}
	if len(fake.requests) != len(want) {
		t.Fatalf("loopback provider request surface=%v want=%v", fake.requests, want)
	}
	for request, count := range want {
		if fake.requests[request] != count {
			t.Fatalf("loopback provider request %s count=%d want=%d all=%v", request, fake.requests[request], count, fake.requests)
		}
	}
}
