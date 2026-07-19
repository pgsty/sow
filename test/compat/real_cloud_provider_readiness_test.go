package compat_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	cloudflareapi "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/option"
	cloudflarer2 "github.com/cloudflare/cloudflare-go/v7/r2"
	"github.com/cloudflare/cloudflare-go/v7/zones"
	"github.com/pgsty/sow/internal/publish"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	teo "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/teo/v20220901"
)

const (
	realCloudProviderReadinessOptInEnv      = "SOW_RUN_REAL_CLOUD_PROVIDER_READINESS"
	realCloudProviderReadinessReceiptEnv    = "SOW_REAL_CLOUD_PROVIDER_READINESS_RECEIPT"
	realCloudProviderReadinessSignerEnv     = "SOW_REAL_CLOUD_PROVIDER_READINESS_SIGNER_JSON"
	realCloudProviderReadinessReceiptSchema = "sow-real-cloud-provider-readiness/v3"
	realCloudProviderReadinessSealSchema    = "sow-real-cloud-provider-readiness-seal/v3"
	realCloudProviderReadinessMaxAge        = 15 * time.Minute
)

var realCloudCloudflareModernTLS12Ciphers = []string{
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-CHACHA20-POLY1305",
	"ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-RSA-CHACHA20-POLY1305",
}

type realCloudProviderReadinessReceipt struct {
	Schema                     string `json:"schema"`
	RunID                      string `json:"run_id"`
	Provider                   string `json:"provider"`
	ReadinessResourceSHA256    string `json:"readiness_resource_sha256"`
	BucketIdentitySHA256       string `json:"bucket_identity_sha256"`
	ProviderControlSHA256      string `json:"provider_control_sha256"`
	BucketObservedEmpty        bool   `json:"bucket_observed_empty"`
	BucketControlObjectCount   int    `json:"bucket_control_object_count"`
	BucketControlObjectKey     string `json:"bucket_control_object_key"`
	BucketControlClosureSHA256 string `json:"bucket_control_closure_sha256"`
	ProviderOperations         string `json:"provider_operations"`
	ObservedAt                 string `json:"observed_at"`
}

type realCloudProviderReadinessBucketObservation struct {
	ObservedEmpty        bool
	ControlObjectCount   int
	ControlObjectKey     string
	ControlClosureSHA256 string
	Operations           string
}

type realCloudProviderReadinessControlObject struct {
	Key    string `json:"key"`
	Size   int64  `json:"size"`
	ETag   string `json:"etag"`
	SHA256 string `json:"sha256"`
}

type realCloudProviderReadinessSeal struct {
	Schema                string `json:"schema"`
	RunID                 string `json:"run_id"`
	Provider              string `json:"provider"`
	ReceiptSHA256         string `json:"receipt_sha256"`
	ReceiptSize           int    `json:"receipt_size"`
	SignerPublicKeySHA256 string `json:"signer_public_key_sha256"`
	Signature             string `json:"signature"`
}

type realCloudProviderReadinessSignerSecret struct {
	PrivateKeySeed string `json:"private_key_seed"`
}

// TestRealCloudProviderScopedReadiness checks exactly one administrator-pinned
// provider without needing credentials for the other provider. It is strictly
// read-only: a signed bucket-closure ListObjectsV2 and provider control-plane
// identity reads. Cloudflare may also contain one exact CAS-retired bootstrap
// lease marker. It never purges, uploads, reconfigures, or deletes.
func TestRealCloudProviderScopedReadiness(t *testing.T) {
	provider := strings.TrimSpace(os.Getenv(realCloudProviderReadinessOptInEnv))
	if provider == "" || provider == "0" {
		t.Skip("set SOW_RUN_REAL_CLOUD_PROVIDER_READINESS=cloudflare or edgeone to run one read-only provider preflight")
	}
	resource, environment, err := loadRealCloudProviderReadinessSelection(provider, os.Getenv)
	if err != nil {
		t.Fatalf("provider-scoped readiness resource gate failed: %v", err)
	}
	runID := strings.TrimSpace(os.Getenv(realCloudRunIDEnv))
	if !validRealCloudRunID(runID) {
		t.Fatalf("%s must identify this readiness observation", realCloudRunIDEnv)
	}
	signerRaw := os.Getenv(realCloudProviderReadinessSignerEnv)
	signer, err := decodeRealCloudProviderReadinessSigner(signerRaw)
	if err != nil {
		t.Fatalf("%s is absent or invalid", realCloudProviderReadinessSignerEnv)
	}
	defer clearRealCloudBytes(signer)
	storageName, apiName, err := realCloudProviderReadinessCredentialNames(provider)
	if err != nil {
		t.Fatal(err)
	}
	secretFragments := realCloudScopedSecretFragments(signerRaw, os.Getenv(storageName), os.Getenv(apiName))
	var bucketSHA, controlSHA string
	var bucketObservation realCloudProviderReadinessBucketObservation
	switch provider {
	case "cloudflare":
		identity := resource.Cloudflare
		bucketSHA, controlSHA, bucketObservation, err = checkRealCloudCloudflareReadiness(t.Context(), environment, *identity, os.Getenv)
	case "edgeone":
		identity := resource.EdgeOne
		bucketSHA, controlSHA, bucketObservation, err = checkRealCloudEdgeOneReadiness(t.Context(), environment, *identity, os.Getenv)
	}
	if err != nil {
		assertNoRealCloudSecret(t, "provider-scoped readiness error", []byte(err.Error()), secretFragments)
		t.Fatalf("%s read-only readiness failed: %v", provider, err)
	}
	receipt := realCloudProviderReadinessReceipt{
		Schema: realCloudProviderReadinessReceiptSchema, RunID: runID, Provider: provider,
		ReadinessResourceSHA256: realCloudProviderReadinessResourceSHA(resource), BucketIdentitySHA256: bucketSHA,
		ProviderControlSHA256: controlSHA, BucketObservedEmpty: bucketObservation.ObservedEmpty,
		BucketControlObjectCount: bucketObservation.ControlObjectCount, BucketControlObjectKey: bucketObservation.ControlObjectKey,
		BucketControlClosureSHA256: bucketObservation.ControlClosureSHA256,
		ProviderOperations:         bucketObservation.Operations,
		ObservedAt:                 time.Now().UTC().Format(time.RFC3339Nano),
	}
	writeRealCloudProviderReadinessReceipt(t, strings.TrimSpace(os.Getenv(realCloudProviderReadinessReceiptEnv)), receipt, signer)
}

func realCloudProviderReadinessCredentialNames(provider string) (string, string, error) {
	switch provider {
	case "cloudflare":
		return realCloudStorageCredentialCF, realCloudCDNCredentialCF, nil
	case "edgeone":
		return realCloudStorageCredentialCOS, realCloudCDNCredentialCOS, nil
	default:
		return "", "", errors.New("provider-scoped readiness provider must be cloudflare or edgeone")
	}
}

func realCloudCloudflareReadinessDomainFixture(identity realCloudCloudflareReadinessResource) *cloudflarer2.BucketDomainCustomListResponse {
	status := cloudflarer2.BucketDomainCustomListResponseDomainsStatus{
		Ownership: cloudflarer2.BucketDomainCustomListResponseDomainsStatusOwnershipActive,
		SSL:       cloudflarer2.BucketDomainCustomListResponseDomainsStatusSSLActive,
	}
	return &cloudflarer2.BucketDomainCustomListResponse{Domains: []cloudflarer2.BucketDomainCustomListResponseDomain{
		{Domain: strings.TrimPrefix(identity.CDNBase, "https://"), Enabled: true, Status: status, ZoneID: identity.ZoneID, ZoneName: identity.ZoneName,
			MinTLS: cloudflarer2.BucketDomainCustomListResponseDomainsMinTLS1_2, Ciphers: append([]string(nil), realCloudCloudflareModernTLS12Ciphers...)},
		{Domain: strings.TrimPrefix(identity.BetaBase, "https://"), Enabled: true, Status: status, ZoneID: identity.ZoneID, ZoneName: identity.ZoneName,
			MinTLS: cloudflarer2.BucketDomainCustomListResponseDomainsMinTLS1_2, Ciphers: append([]string(nil), realCloudCloudflareModernTLS12Ciphers...)},
	}}
}

type realCloudProviderReadinessBucketReader interface {
	R2GetControl(context.Context, string) (publish.ControlObject, error)
	R2ListObjectsV2(context.Context, string) (publish.ObjectListPage, error)
}

func realCloudProviderEmptyReadinessBucketObservation() realCloudProviderReadinessBucketObservation {
	body, _ := json.Marshal([]realCloudProviderReadinessControlObject{})
	return realCloudProviderReadinessBucketObservation{
		ObservedEmpty:        true,
		ControlClosureSHA256: realCloudLowerSHA256(body),
		Operations:           "read-only:list-objects-v2+zone-and-domain-identity",
	}
}

// collectRealCloudCloudflareReadinessBucketClosure admits either the pristine
// empty bootstrap bucket or one exact CAS-retired bootstrap lease marker. The
// marker is non-owning and cannot authorize a Worker mutation; acquisition
// must replace it by ETag CAS and the post-acquisition closure must then contain
// only the new live lease. Any payload, foreign control object, or second marker
// still fails readiness.
func collectRealCloudCloudflareReadinessBucketClosure(ctx context.Context, reader realCloudProviderReadinessBucketReader, identity realCloudCloudflareReadinessResource) (realCloudProviderReadinessBucketObservation, error) {
	if reader == nil {
		return realCloudProviderReadinessBucketObservation{}, errors.New("Cloudflare readiness bucket reader is absent")
	}
	continuation := ""
	seen := map[string]struct{}{"": {}}
	var objects []publish.ListedObject
	for pages := 0; ; pages++ {
		if pages >= realCloudProviderMaxInventoryItems {
			return realCloudProviderReadinessBucketObservation{}, errors.New("Cloudflare readiness bucket inventory exceeds the safety bound")
		}
		page, err := reader.R2ListObjectsV2(ctx, continuation)
		if err != nil {
			return realCloudProviderReadinessBucketObservation{}, fmt.Errorf("Cloudflare R2 signed bucket-closure query failed: %w", err)
		}
		objects = append(objects, page.Objects...)
		if len(objects) > 1 {
			return realCloudProviderReadinessBucketObservation{}, errors.New("Cloudflare readiness bucket contains payload or multiple control objects")
		}
		next := page.NextContinuationToken
		if next == "" {
			break
		}
		if len(next) > 16<<10 || strings.ContainsAny(next, "\x00\r\n") {
			return realCloudProviderReadinessBucketObservation{}, errors.New("Cloudflare readiness bucket returned an unsafe continuation token")
		}
		if _, duplicate := seen[next]; duplicate {
			return realCloudProviderReadinessBucketObservation{}, errors.New("Cloudflare readiness bucket repeated a continuation token")
		}
		seen[next] = struct{}{}
		continuation = next
	}
	if len(objects) == 0 {
		return realCloudProviderEmptyReadinessBucketObservation(), nil
	}
	listed := objects[0]
	const prefix = ".sow/bootstrap/leases/"
	planSHA := strings.TrimSuffix(strings.TrimPrefix(listed.Key, prefix), ".json")
	if !strings.HasPrefix(listed.Key, prefix) || listed.Key != prefix+planSHA+".json" || !validRealCloudLowerSHA256(planSHA) ||
		listed.Size <= 0 || listed.Size > 64<<10 || !validRealCloudProviderETag(listed.ETag) {
		return realCloudProviderReadinessBucketObservation{}, errors.New("Cloudflare readiness bucket contains a foreign object")
	}
	observed, err := reader.R2GetControl(ctx, listed.Key)
	if err != nil || !observed.Exists || observed.ETag != listed.ETag || int64(len(observed.Body)) != listed.Size {
		clearRealCloudBytes(observed.Body)
		return realCloudProviderReadinessBucketObservation{}, errors.New("Cloudflare readiness idle marker identity changed between list and GET")
	}
	defer clearRealCloudBytes(observed.Body)
	idle, err := decodeRealCloudCloudflareBootstrapIdleLease(observed.Body)
	if err != nil || idle.PlanSHA256 != planSHA || idle.AccountID != identity.AccountID || idle.ZoneID != identity.ZoneID {
		return realCloudProviderReadinessBucketObservation{}, errors.New("Cloudflare readiness bucket contains an invalid or foreign idle marker")
	}
	closure := []realCloudProviderReadinessControlObject{{
		Key: listed.Key, Size: listed.Size, ETag: listed.ETag, SHA256: realCloudLowerSHA256(observed.Body),
	}}
	body, _ := json.Marshal(closure)
	return realCloudProviderReadinessBucketObservation{
		ControlObjectCount:   1,
		ControlObjectKey:     listed.Key,
		ControlClosureSHA256: realCloudLowerSHA256(body),
		Operations:           "read-only:list-objects-v2+get-idle-bootstrap-lease+zone-and-domain-identity",
	}, nil
}

func checkRealCloudCloudflareReadiness(
	ctx context.Context,
	environment realCloudEnvironment,
	identity realCloudCloudflareReadinessResource,
	getenv func(string) string,
) (string, string, realCloudProviderReadinessBucketObservation, error) {
	storage, err := decodeRealCloudProviderSecret[realCloudStorageSecret](getenv(realCloudStorageCredentialCF))
	if err != nil || strings.TrimSpace(storage.AccessKeyID) == "" || strings.TrimSpace(storage.SecretAccessKey) == "" {
		return "", "", realCloudProviderReadinessBucketObservation{}, errors.New("Cloudflare storage credential is absent or invalid")
	}
	api, err := decodeRealCloudProviderSecret[realCloudCloudflareSecret](getenv(realCloudCDNCredentialCF))
	if err != nil || strings.TrimSpace(api.APIToken) == "" {
		return "", "", realCloudProviderReadinessBucketObservation{}, errors.New("Cloudflare API credential is absent or invalid")
	}
	client := realCloudProviderHTTPClient()
	objects, err := publish.NewR2CloudflareHTTP(publish.R2CloudflareHTTPConfig{
		Bucket: environment.CFR2Bucket, ObjectBaseURL: realCloudProviderBucketBaseURL(environment.CFR2Endpoint, environment.CFR2Bucket),
		CDNBaseURL: environment.CFCDNBase, ZoneID: environment.CFZoneID, APIToken: api.APIToken,
		Credentials:      publish.S3Credentials{AccessKeyID: storage.AccessKeyID, SecretAccessKey: storage.SecretAccessKey, SessionToken: storage.SessionToken, Region: "auto"},
		CloudflareAPIURL: "https://api.cloudflare.com/client/v4", Client: client,
	})
	if err != nil {
		return "", "", realCloudProviderReadinessBucketObservation{}, errors.New("construct read-only Cloudflare clients")
	}
	bucketObservation, err := collectRealCloudCloudflareReadinessBucketClosure(ctx, objects, identity)
	if err != nil {
		return "", "", realCloudProviderReadinessBucketObservation{}, err
	}
	cf := cloudflareapi.NewClient(
		option.WithBaseURL("https://api.cloudflare.com/client/v4/"), option.WithAPIToken(api.APIToken),
		option.WithHTTPClient(client), option.WithMaxRetries(0),
	)
	controlSHA, err := collectRealCloudCloudflareReadinessControl(ctx, environment, identity, cf)
	if err != nil {
		return "", "", realCloudProviderReadinessBucketObservation{}, err
	}
	bucketIdentity, _ := json.Marshal([]string{"cloudflare", environment.CFR2Endpoint, environment.CFR2Bucket, environment.CFZoneID})
	return realCloudLowerSHA256(bucketIdentity), controlSHA, bucketObservation, nil
}

func collectRealCloudCloudflareReadinessControl(ctx context.Context, environment realCloudEnvironment, identity realCloudCloudflareReadinessResource, cf *cloudflareapi.Client) (string, error) {
	if cf == nil {
		return "", errors.New("Cloudflare readiness control client is absent")
	}
	zone, err := cf.Zones.Get(ctx, zones.ZoneGetParams{ZoneID: cloudflareapi.F(identity.ZoneID)})
	if err != nil || zone == nil {
		return "", errors.New("Cloudflare exact zone identity query failed")
	}
	zoneName := strings.ToLower(strings.TrimSuffix(zone.Name, "."))
	if zone.Name != identity.ZoneName || zoneName != identity.ZoneName {
		*zone = zones.Zone{}
		return "", errors.New("Cloudflare readiness zone name differs from the pinned identity")
	}
	zoneSHA, err := validateRealCloudCloudflareZone(zone, environment, realCloudCloudflareAttestationConfig{AccountID: identity.AccountID, ZoneID: identity.ZoneID})
	*zone = zones.Zone{}
	if err != nil {
		return "", err
	}
	domainsSHA, err := collectRealCloudCloudflareR2CustomDomainClosure(ctx, identity, cf)
	if err != nil {
		return "", err
	}
	controlIdentity, _ := json.Marshal([]string{zoneSHA, domainsSHA})
	return realCloudLowerSHA256(controlIdentity), nil
}

func collectRealCloudCloudflareR2CustomDomainClosure(
	ctx context.Context,
	identity realCloudCloudflareReadinessResource,
	client *cloudflareapi.Client,
) (string, error) {
	if client == nil {
		return "", errors.New("Cloudflare R2 custom-domain safety client is absent")
	}
	response, err := client.R2.Buckets.Domains.Custom.List(ctx, identity.R2Bucket, cloudflarer2.BucketDomainCustomListParams{
		AccountID: cloudflareapi.F(identity.AccountID),
	})
	if err != nil || response == nil {
		return "", errors.New("Cloudflare exact R2 custom-domain inventory query failed")
	}
	return validateRealCloudCloudflareR2CustomDomainClosure(response, identity)
}

func validateRealCloudCloudflareR2CustomDomainClosure(
	response *cloudflarer2.BucketDomainCustomListResponse,
	identity realCloudCloudflareReadinessResource,
) (string, error) {
	if response == nil || len(response.Domains) != 2 {
		return "", errors.New("Cloudflare R2 custom-domain inventory is not the exact main-and-beta closure")
	}
	mainHost, err := canonicalRealCloudReadinessCDNBase(identity.CDNBase)
	if err != nil {
		return "", err
	}
	betaHost, err := canonicalRealCloudReadinessCDNBase(identity.BetaBase)
	if err != nil {
		return "", err
	}
	expected := []string{mainHost, betaHost}
	sort.Strings(expected)
	domains := append([]cloudflarer2.BucketDomainCustomListResponseDomain(nil), response.Domains...)
	sort.Slice(domains, func(i, j int) bool { return domains[i].Domain < domains[j].Domain })
	rows := make([]any, 0, len(domains))
	for index, domain := range domains {
		if domain.Domain != expected[index] || !domain.Enabled ||
			domain.Status.Ownership != cloudflarer2.BucketDomainCustomListResponseDomainsStatusOwnershipActive ||
			domain.Status.SSL != cloudflarer2.BucketDomainCustomListResponseDomainsStatusSSLActive ||
			domain.ZoneID != identity.ZoneID || domain.ZoneName != identity.ZoneName {
			return "", errors.New("Cloudflare R2 custom domain is not the exact active pinned bucket binding")
		}
		if domain.MinTLS != cloudflarer2.BucketDomainCustomListResponseDomainsMinTLS1_2 &&
			domain.MinTLS != cloudflarer2.BucketDomainCustomListResponseDomainsMinTLS1_3 {
			return "", errors.New("Cloudflare R2 custom domain minimum TLS policy is below 1.2 or absent")
		}
		ciphers := append([]string(nil), domain.Ciphers...)
		sort.Strings(ciphers)
		if len(ciphers) != len(realCloudCloudflareModernTLS12Ciphers) {
			return "", errors.New("Cloudflare R2 custom domain does not use the exact reviewed modern TLS 1.2 cipher set")
		}
		for cipherIndex, cipher := range ciphers {
			if cipher != realCloudCloudflareModernTLS12Ciphers[cipherIndex] {
				return "", errors.New("Cloudflare R2 custom domain does not use the exact reviewed modern TLS 1.2 cipher set")
			}
		}
		rows = append(rows, []any{
			domain.Domain, domain.Enabled, string(domain.Status.Ownership), string(domain.Status.SSL),
			domain.ZoneID, domain.ZoneName, string(domain.MinTLS), ciphers,
		})
	}
	body, _ := json.Marshal(rows)
	return realCloudLowerSHA256(body), nil
}

func TestRealCloudCloudflareReadinessUsesExactR2CustomDomainListAPI(t *testing.T) {
	identity := *realCloudCloudflareReadinessFixture().Cloudflare
	response := realCloudCloudflareReadinessDomainFixture(identity)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.URL.Path != "/client/v4/accounts/"+identity.AccountID+"/r2/buckets/"+identity.R2Bucket+"/domains/custom" ||
			request.Header.Get("Authorization") != "Bearer readiness-test-token" {
			t.Errorf("unexpected R2 custom-domain request method=%s path=%s authorization=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"success": true, "errors": []any{}, "messages": []any{}, "result": response,
		})
	}))
	defer server.Close()
	client := cloudflareapi.NewClient(
		option.WithBaseURL(server.URL+"/client/v4/"), option.WithAPIToken("readiness-test-token"),
		option.WithHTTPClient(server.Client()), option.WithMaxRetries(0),
	)
	digest, err := collectRealCloudCloudflareR2CustomDomainClosure(t.Context(), identity, client)
	if err != nil || !validRealCloudLowerSHA256(digest) || requests != 1 {
		t.Fatalf("Cloudflare readiness did not use the exact read-only custom-domain list API: requests=%d digest=%q err=%v", requests, digest, err)
	}
}

func TestRealCloudCloudflareReadinessRequiresExactActiveR2CustomDomains(t *testing.T) {
	identity := *realCloudCloudflareReadinessFixture().Cloudflare
	valid := realCloudCloudflareReadinessDomainFixture(identity)
	digest, err := validateRealCloudCloudflareR2CustomDomainClosure(valid, identity)
	if err != nil || !validRealCloudLowerSHA256(digest) {
		t.Fatalf("exact active R2 main/beta closure rejected: digest=%q err=%v", digest, err)
	}
	reordered := &cloudflarer2.BucketDomainCustomListResponse{Domains: []cloudflarer2.BucketDomainCustomListResponseDomain{valid.Domains[1], valid.Domains[0]}}
	for index := range reordered.Domains {
		reordered.Domains[index].Ciphers = append([]string(nil), realCloudCloudflareModernTLS12Ciphers...)
		sort.Sort(sort.Reverse(sort.StringSlice(reordered.Domains[index].Ciphers)))
	}
	canonical := &cloudflarer2.BucketDomainCustomListResponse{Domains: []cloudflarer2.BucketDomainCustomListResponseDomain{valid.Domains[0], valid.Domains[1]}}
	canonical.Domains[0].Ciphers = append([]string(nil), realCloudCloudflareModernTLS12Ciphers...)
	canonical.Domains[1].Ciphers = append([]string(nil), realCloudCloudflareModernTLS12Ciphers...)
	canonicalDigest, canonicalErr := validateRealCloudCloudflareR2CustomDomainClosure(canonical, identity)
	reorderedDigest, reorderedErr := validateRealCloudCloudflareR2CustomDomainClosure(reordered, identity)
	if canonicalErr != nil || reorderedErr != nil || canonicalDigest != reorderedDigest {
		t.Fatalf("R2 custom-domain identity was order-dependent: canonical=%q/%v reordered=%q/%v", canonicalDigest, canonicalErr, reorderedDigest, reorderedErr)
	}

	for _, test := range []struct {
		name   string
		mutate func(*cloudflarer2.BucketDomainCustomListResponse)
	}{
		{"missing beta", func(response *cloudflarer2.BucketDomainCustomListResponse) { response.Domains = response.Domains[:1] }},
		{"extra domain", func(response *cloudflarer2.BucketDomainCustomListResponse) {
			response.Domains = append(response.Domains, response.Domains[0])
		}},
		{"wrong domain", func(response *cloudflarer2.BucketDomainCustomListResponse) {
			response.Domains[1].Domain = "other.pro.pigsty.io"
		}},
		{"disabled", func(response *cloudflarer2.BucketDomainCustomListResponse) { response.Domains[1].Enabled = false }},
		{"ownership pending", func(response *cloudflarer2.BucketDomainCustomListResponse) {
			response.Domains[1].Status.Ownership = cloudflarer2.BucketDomainCustomListResponseDomainsStatusOwnershipPending
		}},
		{"ssl pending", func(response *cloudflarer2.BucketDomainCustomListResponse) {
			response.Domains[1].Status.SSL = cloudflarer2.BucketDomainCustomListResponseDomainsStatusSSLPending
		}},
		{"zone id drift", func(response *cloudflarer2.BucketDomainCustomListResponse) { response.Domains[1].ZoneID = "other-zone" }},
		{"zone name drift", func(response *cloudflarer2.BucketDomainCustomListResponse) {
			response.Domains[1].ZoneName = "other.example.invalid"
		}},
		{"unknown TLS", func(response *cloudflarer2.BucketDomainCustomListResponse) { response.Domains[1].MinTLS = "future" }},
		{"missing TLS", func(response *cloudflarer2.BucketDomainCustomListResponse) { response.Domains[1].MinTLS = "" }},
		{"TLS 1.0", func(response *cloudflarer2.BucketDomainCustomListResponse) {
			response.Domains[1].MinTLS = cloudflarer2.BucketDomainCustomListResponseDomainsMinTLS1_0
		}},
		{"TLS 1.1", func(response *cloudflarer2.BucketDomainCustomListResponse) {
			response.Domains[1].MinTLS = cloudflarer2.BucketDomainCustomListResponseDomainsMinTLS1_1
		}},
		{"empty ciphers", func(response *cloudflarer2.BucketDomainCustomListResponse) { response.Domains[1].Ciphers = nil }},
		{"unknown cipher", func(response *cloudflarer2.BucketDomainCustomListResponse) {
			response.Domains[1].Ciphers[0] = "AES256-SHA"
		}},
		{"duplicate cipher", func(response *cloudflarer2.BucketDomainCustomListResponse) {
			response.Domains[1].Ciphers[0] = response.Domains[1].Ciphers[1]
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := realCloudCloudflareReadinessDomainFixture(identity)
			test.mutate(candidate)
			if _, err := validateRealCloudCloudflareR2CustomDomainClosure(candidate, identity); err == nil {
				t.Fatal("unsafe R2 custom-domain closure was accepted")
			}
		})
	}
}

func checkRealCloudEdgeOneReadiness(
	ctx context.Context,
	environment realCloudEnvironment,
	identity realCloudEdgeOneReadinessResource,
	getenv func(string) string,
) (string, string, realCloudProviderReadinessBucketObservation, error) {
	storage, err := decodeRealCloudProviderSecret[realCloudStorageSecret](getenv(realCloudStorageCredentialCOS))
	if err != nil || strings.TrimSpace(storage.AccessKeyID) == "" || strings.TrimSpace(storage.SecretAccessKey) == "" {
		return "", "", realCloudProviderReadinessBucketObservation{}, errors.New("Tencent COS storage credential is absent or invalid")
	}
	api, err := decodeRealCloudProviderSecret[realCloudTencentSecret](getenv(realCloudCDNCredentialCOS))
	if err != nil || strings.TrimSpace(api.SecretID) == "" || strings.TrimSpace(api.SecretKey) == "" {
		return "", "", realCloudProviderReadinessBucketObservation{}, errors.New("EdgeOne API credential is absent or invalid")
	}
	client := realCloudProviderHTTPClient()
	objects, err := publish.NewCOSEdgeOneHTTP(publish.COSEdgeOneHTTPConfig{
		Bucket: environment.COSBucket, ObjectBaseURL: realCloudProviderBucketBaseURL(environment.COSEndpoint, environment.COSBucket),
		CDNBaseURL:         environment.COSCDNBase,
		ObjectCredentials:  publish.S3Credentials{AccessKeyID: storage.AccessKeyID, SecretAccessKey: storage.SecretAccessKey, SessionToken: storage.SessionToken, Region: environment.COSRegion},
		TencentCredentials: publish.TencentCredentials{SecretID: api.SecretID, SecretKey: api.SecretKey, Token: api.SessionToken},
		ZoneID:             environment.EdgeOneZoneID, EdgeOneAPIURL: "https://teo.tencentcloudapi.com", Client: client, UnversionedBucketConfirmed: true,
	})
	if err != nil {
		return "", "", realCloudProviderReadinessBucketObservation{}, errors.New("construct read-only Tencent clients")
	}
	page, err := objects.COSListObjectsV2(ctx, "")
	if err != nil {
		return "", "", realCloudProviderReadinessBucketObservation{}, fmt.Errorf("Tencent COS signed empty-bucket query failed: %w", err)
	}
	if len(page.Objects) != 0 || page.NextContinuationToken != "" {
		return "", "", realCloudProviderReadinessBucketObservation{}, errors.New("Tencent readiness bucket is not empty")
	}
	parsed, _ := url.Parse("https://teo.tencentcloudapi.com")
	clientProfile := profile.NewClientProfile()
	clientProfile.DisableRegionBreaker = true
	clientProfile.NetworkFailureMaxRetries = 0
	clientProfile.RateLimitExceededMaxRetries = 0
	clientProfile.HttpProfile.Scheme = strings.ToUpper(parsed.Scheme)
	clientProfile.HttpProfile.Endpoint = parsed.Host
	clientProfile.HttpProfile.ReqTimeout = 30
	credential := common.NewTokenCredential(api.SecretID, api.SecretKey, api.SessionToken)
	edgeOne, err := teo.NewClient(credential, "", clientProfile)
	if err != nil {
		return "", "", realCloudProviderReadinessBucketObservation{}, errors.New("construct read-only EdgeOne SDK")
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	edgeOne.WithHttpTransport(transport)
	configuration := realCloudEdgeOneAttestationConfig{ZoneID: identity.ZoneID}
	zoneSHA, domainsSHA, err := collectRealCloudEdgeOneZoneClosure(ctx, environment, configuration, identity.ZoneName, edgeOne)
	if err != nil {
		return "", "", realCloudProviderReadinessBucketObservation{}, err
	}
	controlBody, _ := json.Marshal([]string{zoneSHA, domainsSHA})
	bucketIdentity, _ := json.Marshal([]string{"edgeone", environment.COSEndpoint, environment.COSBucket, environment.COSRegion, environment.EdgeOneZoneID})
	return realCloudLowerSHA256(bucketIdentity), realCloudLowerSHA256(controlBody), realCloudProviderEmptyReadinessBucketObservation(), nil
}

func realCloudScopedSecretFragments(raw ...string) []string {
	fragments := make([]string, 0, len(raw)*4)
	for _, document := range raw {
		if document == "" {
			continue
		}
		fragments = append(fragments, document)
		var fields map[string]any
		if json.Unmarshal([]byte(document), &fields) != nil {
			continue
		}
		for _, name := range []string{"access_key_id", "secret_access_key", "session_token", "api_token", "secret_id", "secret_key", "basic_username", "basic_password", "private_key_seed"} {
			if value, ok := fields[name].(string); ok && value != "" {
				fragments = append(fragments, value)
			}
		}
	}
	return fragments
}

func decodeRealCloudProviderReadinessSigner(raw string) (ed25519.PrivateKey, error) {
	secret, err := decodeRealCloudProviderSecret[realCloudProviderReadinessSignerSecret](raw)
	if err != nil || !validRealCloudLowerSHA256(secret.PrivateKeySeed) {
		return nil, errors.New("decode readiness receipt signer")
	}
	seed, err := hex.DecodeString(secret.PrivateKeySeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		clearRealCloudBytes(seed)
		return nil, errors.New("decode readiness receipt signer seed")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	clearRealCloudBytes(seed)
	return privateKey, nil
}

func realCloudProviderReadinessSignerPublicKey(privateKey ed25519.PrivateKey) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("readiness receipt signer private key is invalid")
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("derive readiness receipt signer public key")
	}
	return hex.EncodeToString(publicKey), nil
}

func decodeRealCloudProviderReadinessPublicKey(raw string) (ed25519.PublicKey, error) {
	if !validRealCloudLowerSHA256(raw) {
		return nil, errors.New("readiness receipt signer public key is invalid")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("decode readiness receipt signer public key")
	}
	allZero := true
	for _, value := range decoded {
		allZero = allZero && value == 0
	}
	if allZero {
		clearRealCloudBytes(decoded)
		return nil, errors.New("readiness receipt signer public key is invalid")
	}
	return ed25519.PublicKey(decoded), nil
}

func realCloudProviderReadinessSealMessage(receiptBody []byte) []byte {
	message := make([]byte, 0, len(realCloudProviderReadinessSealSchema)+1+len(receiptBody))
	message = append(message, realCloudProviderReadinessSealSchema...)
	message = append(message, '\n')
	return append(message, receiptBody...)
}

func newRealCloudProviderReadinessTestSigner(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, hex.EncodeToString(publicKey)
}

func writeRealCloudProviderReadinessReceipt(t *testing.T, rawPath string, receipt realCloudProviderReadinessReceipt, signer ed25519.PrivateKey) {
	t.Helper()
	path := validateRealCloudProviderReadinessReceiptPath(t, rawPath)
	publicKeyHex, err := realCloudProviderReadinessSignerPublicKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := decodeRealCloudProviderReadinessPublicKey(publicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	defer clearRealCloudBytes(publicKey)
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal("encode provider-scoped readiness receipt")
	}
	body = append(body, '\n')
	if containsRealEdgeURLLeak(body) {
		t.Fatal("provider-scoped readiness receipt exposed a URL")
	}
	writeRealCloudRegistryCandidate(t, path, body)
	message := realCloudProviderReadinessSealMessage(body)
	signature := ed25519.Sign(signer, message)
	clearRealCloudBytes(message)
	seal := realCloudProviderReadinessSeal{
		Schema: realCloudProviderReadinessSealSchema, RunID: receipt.RunID, Provider: receipt.Provider,
		ReceiptSHA256: realCloudLowerSHA256(body), ReceiptSize: len(body),
		SignerPublicKeySHA256: realCloudLowerSHA256(publicKey), Signature: base64.RawStdEncoding.EncodeToString(signature),
	}
	clearRealCloudBytes(signature)
	writeRealCloudExclusiveJSON(t, path+".seal", seal)
	t.Logf("%s readiness receipt=%s seal_sha256=%s", receipt.Provider, path, seal.ReceiptSHA256)
}

func validateRealCloudProviderReadinessReceiptPath(t *testing.T, raw string) string {
	return validateRealCloudPrivateReceiptPath(t, realCloudProviderReadinessReceiptEnv, raw)
}

func validateRealCloudPrivateReceiptPath(t *testing.T, envName, raw string) string {
	t.Helper()
	if raw == "" || raw != strings.TrimSpace(raw) || !filepath.IsAbs(raw) || filepath.Clean(raw) != raw || filepath.Ext(raw) != ".json" {
		t.Fatalf("%s must be one clean absolute .json path", envName)
	}
	parentInfo, err := os.Lstat(filepath.Dir(raw))
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("%s parent must be an existing private non-symlink directory", envName)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(raw))
	if err != nil {
		t.Fatal("resolve provider-scoped receipt parent")
	}
	path := filepath.Join(parent, filepath.Base(raw))
	root, err := filepath.EvalSymlinks(findModuleRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("%s must resolve outside the repository", envName)
	}
	return path
}

func validateRealCloudCloudflareBootstrapReadinessReceipt(rawPath string, resource realCloudProviderReadinessResource, runID, signerPublicKey string, now time.Time) error {
	_, err := loadAndValidateRealCloudCloudflareBootstrapReadinessReceipt(rawPath, resource, runID, signerPublicKey, now)
	return err
}

// loadAndValidateRealCloudCloudflareBootstrapReadinessReceipt returns the
// receipt decoded from the same bytes whose Ed25519 seal was verified. The
// caller must never validate one pathname read and then reopen that pathname
// to obtain mutation authority: an attacker could replace the file between
// those two reads while leaving the already-validated seal untouched.
func loadAndValidateRealCloudCloudflareBootstrapReadinessReceipt(rawPath string, resource realCloudProviderReadinessResource, runID, signerPublicKey string, now time.Time) (realCloudProviderReadinessReceipt, error) {
	return loadAndValidateRealCloudCloudflareBootstrapReadinessReceiptWithHook(rawPath, resource, runID, signerPublicKey, now, nil)
}

func loadAndValidateRealCloudCloudflareBootstrapReadinessReceiptWithHook(rawPath string, resource realCloudProviderReadinessResource, runID, signerPublicKey string, now time.Time, afterValidation func()) (realCloudProviderReadinessReceipt, error) {
	var receipt realCloudProviderReadinessReceipt
	if rawPath == "" || rawPath != strings.TrimSpace(rawPath) || !filepath.IsAbs(rawPath) || filepath.Clean(rawPath) != rawPath || filepath.Ext(rawPath) != ".json" {
		return receipt, fmt.Errorf("%s must be one clean absolute .json path", realCloudCloudflareBootstrapReadinessReceiptEnv)
	}
	if resource.Provider != "cloudflare" || resource.Cloudflare == nil || resource.EdgeOne != nil || !validRealCloudRunID(runID) {
		return receipt, errors.New("Cloudflare bootstrap readiness receipt selection is invalid")
	}
	publicKey, err := decodeRealCloudProviderReadinessPublicKey(signerPublicKey)
	if err != nil {
		return receipt, err
	}
	defer clearRealCloudBytes(publicKey)
	receiptBody, err := readRealCloudPrivateCanonicalFile(rawPath, 64<<10)
	if err != nil {
		return receipt, fmt.Errorf("read readiness receipt: %w", err)
	}
	defer clearRealCloudBytes(receiptBody)
	if err := decodeRealCloudCanonicalJSONFile(receiptBody, &receipt); err != nil {
		return realCloudProviderReadinessReceipt{}, fmt.Errorf("decode readiness receipt: %w", err)
	}
	sealBody, err := readRealCloudPrivateCanonicalFile(rawPath+".seal", 16<<10)
	if err != nil {
		return realCloudProviderReadinessReceipt{}, fmt.Errorf("read readiness receipt seal: %w", err)
	}
	defer clearRealCloudBytes(sealBody)
	var seal realCloudProviderReadinessSeal
	if err := decodeRealCloudCanonicalJSONFile(sealBody, &seal); err != nil {
		return realCloudProviderReadinessReceipt{}, fmt.Errorf("decode readiness receipt seal: %w", err)
	}
	empty := realCloudProviderEmptyReadinessBucketObservation()
	markerPlanSHA := strings.TrimSuffix(strings.TrimPrefix(receipt.BucketControlObjectKey, ".sow/bootstrap/leases/"), ".json")
	markerKeyValid := validRealCloudLowerSHA256(markerPlanSHA) && receipt.BucketControlObjectKey == ".sow/bootstrap/leases/"+markerPlanSHA+".json"
	bucketClosureValid := validRealCloudLowerSHA256(receipt.BucketControlClosureSHA256) && (receipt.BucketObservedEmpty && receipt.BucketControlObjectCount == 0 && receipt.BucketControlObjectKey == "" && receipt.BucketControlClosureSHA256 == empty.ControlClosureSHA256 && receipt.ProviderOperations == empty.Operations ||
		!receipt.BucketObservedEmpty && receipt.BucketControlObjectCount == 1 && markerKeyValid && receipt.ProviderOperations == "read-only:list-objects-v2+get-idle-bootstrap-lease+zone-and-domain-identity")
	if receipt.Schema != realCloudProviderReadinessReceiptSchema || receipt.RunID != runID || receipt.Provider != "cloudflare" ||
		receipt.ReadinessResourceSHA256 != realCloudProviderReadinessResourceSHA(resource) || !validRealCloudLowerSHA256(receipt.BucketIdentitySHA256) ||
		!validRealCloudLowerSHA256(receipt.ProviderControlSHA256) || !bucketClosureValid {
		return realCloudProviderReadinessReceipt{}, errors.New("readiness receipt does not prove the exact empty-or-idle Cloudflare resource closure")
	}
	observed, err := time.Parse(time.RFC3339Nano, receipt.ObservedAt)
	if err != nil || observed.After(now.Add(time.Minute)) || now.Sub(observed) < 0 || now.Sub(observed) > realCloudProviderReadinessMaxAge {
		return realCloudProviderReadinessReceipt{}, errors.New("readiness receipt is invalid, from the future, or stale")
	}
	signature, err := base64.RawStdEncoding.DecodeString(seal.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(signature) != seal.Signature {
		clearRealCloudBytes(signature)
		return realCloudProviderReadinessReceipt{}, errors.New("readiness receipt seal signature is invalid")
	}
	defer clearRealCloudBytes(signature)
	message := realCloudProviderReadinessSealMessage(receiptBody)
	defer clearRealCloudBytes(message)
	if seal.Schema != realCloudProviderReadinessSealSchema || seal.RunID != runID || seal.Provider != "cloudflare" ||
		seal.ReceiptSize != len(receiptBody) || seal.ReceiptSHA256 != realCloudLowerSHA256(receiptBody) ||
		seal.SignerPublicKeySHA256 != realCloudLowerSHA256(publicKey) || !ed25519.Verify(publicKey, message, signature) {
		return realCloudProviderReadinessReceipt{}, errors.New("readiness receipt seal is invalid")
	}
	if afterValidation != nil {
		afterValidation()
	}
	return receipt, nil
}

func loadValidatedRealCloudCloudflareBootstrapReadinessReceipt(rawPath string, resource realCloudProviderReadinessResource, runID, signerPublicKey string, now time.Time) (realCloudProviderReadinessReceipt, error) {
	return loadAndValidateRealCloudCloudflareBootstrapReadinessReceipt(rawPath, resource, runID, signerPublicKey, now)
}

func decodeRealCloudCanonicalJSONFile(body []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("contains trailing JSON values")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(body, append(canonical, '\n')) {
		return errors.New("is not canonical JSON")
	}
	return nil
}

func readRealCloudPrivateCanonicalFile(rawPath string, maxBytes int64) ([]byte, error) {
	if rawPath == "" || rawPath != strings.TrimSpace(rawPath) || !filepath.IsAbs(rawPath) || filepath.Clean(rawPath) != rawPath || maxBytes <= 0 {
		return nil, errors.New("private evidence path is invalid")
	}
	parentInfo, err := os.Lstat(filepath.Dir(rawPath))
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private evidence parent is absent or unsafe")
	}
	root, err := realEdgeRepositoryRoot()
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, errors.New("resolve repository root")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(rawPath))
	if err != nil {
		return nil, errors.New("resolve private evidence parent")
	}
	path := filepath.Join(parent, filepath.Base(rawPath))
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("private evidence must resolve outside the repository")
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 || before.Size() <= 0 || before.Size() > maxBytes {
		return nil, errors.New("private evidence file is absent or unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open private evidence file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() || opened.Size() != before.Size() {
		return nil, errors.New("private evidence file changed while it was opened")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(body)) != opened.Size() || int64(len(body)) > maxBytes {
		clearRealCloudBytes(body)
		return nil, errors.New("read private evidence file")
	}
	return body, nil
}

func TestRealCloudProviderReadinessContractIsScopedAndRedacted(t *testing.T) {
	for _, test := range []struct {
		provider, storage, api string
	}{
		{"cloudflare", realCloudStorageCredentialCF, realCloudCDNCredentialCF},
		{"edgeone", realCloudStorageCredentialCOS, realCloudCDNCredentialCOS},
	} {
		storage, api, err := realCloudProviderReadinessCredentialNames(test.provider)
		if err != nil || storage != test.storage || api != test.api {
			t.Fatalf("%s credential scope storage=%q api=%q err=%v", test.provider, storage, api, err)
		}
	}
	if _, _, err := realCloudProviderReadinessCredentialNames("both"); err == nil {
		t.Fatal("provider-scoped readiness accepted a dual-provider selector")
	}
	receipt := realCloudProviderReadinessReceipt{
		Schema: realCloudProviderReadinessReceiptSchema, RunID: realCloudRegistryCandidateRunID, Provider: "cloudflare",
		ReadinessResourceSHA256: strings.Repeat("a", 64),
		BucketIdentitySHA256:    strings.Repeat("d", 64), ProviderControlSHA256: strings.Repeat("e", 64), BucketObservedEmpty: true,
		BucketControlClosureSHA256: realCloudProviderEmptyReadinessBucketObservation().ControlClosureSHA256,
		ProviderOperations:         "read-only:list-objects-v2+zone-and-domain-identity", ObservedAt: "2026-07-17T00:00:00Z",
	}
	body, err := json.Marshal(receipt)
	if err != nil || containsRealEdgeURLLeak(body) || strings.Contains(string(body), "access_key") || strings.Contains(string(body), "token") {
		t.Fatalf("provider-scoped receipt is not redacted: err=%v", err)
	}
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	signer, signerPublicKey := newRealCloudProviderReadinessTestSigner(t)
	defer clearRealCloudBytes(signer)
	seed := signer.Seed()
	signerSecret, err := json.Marshal(realCloudProviderReadinessSignerSecret{PrivateKeySeed: hex.EncodeToString(seed)})
	clearRealCloudBytes(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer clearRealCloudBytes(signerSecret)
	decodedSigner, err := decodeRealCloudProviderReadinessSigner(string(signerSecret))
	if err != nil {
		t.Fatal(err)
	}
	decodedPublicKey, err := realCloudProviderReadinessSignerPublicKey(decodedSigner)
	clearRealCloudBytes(decodedSigner)
	if err != nil || decodedPublicKey != signerPublicKey {
		t.Fatalf("readiness signer secret did not derive the expected public key: %v", err)
	}
	if _, err := decodeRealCloudProviderReadinessSigner(`{"private_key_seed":"00"}`); err == nil {
		t.Fatal("malformed readiness signer secret was accepted")
	}
	path := filepath.Join(private, "readiness.json")
	writeRealCloudProviderReadinessReceipt(t, path, receipt, signer)
	written, err := os.ReadFile(path)
	if err != nil || realCloudLowerSHA256(written) == "" {
		t.Fatalf("read provider-scoped receipt: %v", err)
	}
	var seal realCloudProviderReadinessSeal
	readRealCloudStrictJSON(t, path+".seal", &seal)
	publicKey, err := decodeRealCloudProviderReadinessPublicKey(signerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clearRealCloudBytes(publicKey)
	signature, err := base64.RawStdEncoding.DecodeString(seal.Signature)
	message := realCloudProviderReadinessSealMessage(written)
	defer clearRealCloudBytes(signature)
	defer clearRealCloudBytes(message)
	if seal.Schema != realCloudProviderReadinessSealSchema || seal.Provider != receipt.Provider ||
		seal.RunID != receipt.RunID || seal.ReceiptSHA256 != realCloudLowerSHA256(written) || seal.ReceiptSize != len(written) ||
		seal.SignerPublicKeySHA256 != realCloudLowerSHA256(publicKey) || err != nil || !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("provider-scoped readiness seal does not bind the exact receipt")
	}
}

func TestRealCloudCloudflareReadinessAdmitsOnlyOneExactIdleBootstrapLease(t *testing.T) {
	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	identity := *resource.Cloudflare
	planSHA := realCloudCloudflareBootstrapPlanSHA(plan)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	store := &fakeRealCloudCloudflareBootstrapLeaseStore{}
	held, err := acquireRealCloudCloudflareBootstrapLease(t.Context(), store, plan, planSHA,
		"20260719T120000Z-readiness-idle", "apply", strings.Repeat("1", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collectRealCloudCloudflareReadinessBucketClosure(t.Context(), store, identity); err == nil {
		t.Fatal("Cloudflare readiness admitted a live bootstrap lease")
	}
	if err := held.release(t.Context()); err != nil {
		t.Fatal(err)
	}
	observation, err := collectRealCloudCloudflareReadinessBucketClosure(t.Context(), store, identity)
	if err != nil || observation.ObservedEmpty || observation.ControlObjectCount != 1 ||
		observation.ControlObjectKey != held.key || !validRealCloudLowerSHA256(observation.ControlClosureSHA256) || !strings.Contains(observation.Operations, "get-idle-bootstrap-lease") {
		t.Fatalf("exact idle bootstrap marker was not admitted observation=%+v err=%v", observation, err)
	}
	receipt := realCloudProviderReadinessReceipt{BucketControlObjectCount: 1, BucketControlObjectKey: observation.ControlObjectKey}
	if err := validateRealCloudCloudflareBootstrapReadinessMarkerPlan(receipt, planSHA); err != nil {
		t.Fatalf("same-plan readiness marker was rejected: %v", err)
	}
	if err := validateRealCloudCloudflareBootstrapReadinessMarkerPlan(receipt, strings.Repeat("2", 64)); err == nil {
		t.Fatal("foreign-plan readiness marker was admitted before lease acquisition")
	}
	runID := "20260719T120000Z-readiness-idle"
	receipt = realCloudProviderReadinessReceipt{
		Schema: realCloudProviderReadinessReceiptSchema, RunID: runID, Provider: "cloudflare",
		ReadinessResourceSHA256: realCloudProviderReadinessResourceSHA(resource),
		BucketIdentitySHA256:    strings.Repeat("a", 64), ProviderControlSHA256: strings.Repeat("b", 64),
		BucketControlObjectCount: 1, BucketControlObjectKey: observation.ControlObjectKey,
		BucketControlClosureSHA256: observation.ControlClosureSHA256, ProviderOperations: observation.Operations,
		ObservedAt: now.Format(time.RFC3339Nano),
	}
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	signer, publicKey := newRealCloudProviderReadinessTestSigner(t)
	defer clearRealCloudBytes(signer)
	path := filepath.Join(private, "idle-readiness.json")
	writeRealCloudProviderReadinessReceipt(t, path, receipt, signer)
	if err := validateRealCloudCloudflareBootstrapReadinessReceipt(path, resource, runID, publicKey, now); err != nil {
		t.Fatalf("signed idle-marker readiness receipt was rejected: %v", err)
	}
	store.extraObjects = []publish.ListedObject{{Key: "payload/foreign", Size: 1, ETag: `"foreign"`}}
	if _, err := collectRealCloudCloudflareReadinessBucketClosure(t.Context(), store, identity); err == nil {
		t.Fatal("Cloudflare readiness admitted an idle marker alongside a foreign payload")
	}
}

func TestRealCloudCloudflareBootstrapReadinessSealRejectsLocalForgery(t *testing.T) {
	resource := realCloudCloudflareReadinessFixture()
	now := time.Now().UTC()
	runID := "20260719T000000Z-readiness-seal"
	receipt := realCloudProviderReadinessReceipt{
		Schema: realCloudProviderReadinessReceiptSchema, RunID: runID, Provider: "cloudflare",
		ReadinessResourceSHA256: realCloudProviderReadinessResourceSHA(resource),
		BucketIdentitySHA256:    strings.Repeat("b", 64), ProviderControlSHA256: strings.Repeat("c", 64),
		BucketObservedEmpty: true, ProviderOperations: "read-only:list-objects-v2+zone-and-domain-identity",
		BucketControlClosureSHA256: realCloudProviderEmptyReadinessBucketObservation().ControlClosureSHA256,
		ObservedAt:                 now.Format(time.RFC3339Nano),
	}
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	signer, signerPublicKey := newRealCloudProviderReadinessTestSigner(t)
	defer clearRealCloudBytes(signer)
	attacker, attackerPublicKey := newRealCloudProviderReadinessTestSigner(t)
	defer clearRealCloudBytes(attacker)
	path := filepath.Join(private, "readiness.json")
	writeRealCloudProviderReadinessReceipt(t, path, receipt, signer)
	if err := validateRealCloudCloudflareBootstrapReadinessReceipt(path, resource, runID, signerPublicKey, now); err != nil {
		t.Fatalf("valid plan-pinned readiness signature rejected: %v", err)
	}
	if err := validateRealCloudCloudflareBootstrapReadinessReceipt(path, resource, runID, attackerPublicKey, now); err == nil {
		t.Fatal("readiness receipt was accepted under an unpinned signer key")
	}

	var seal realCloudProviderReadinessSeal
	readRealCloudStrictJSON(t, path+".seal", &seal)
	receipt.ProviderControlSHA256 = strings.Repeat("d", 64)
	receiptBody, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptBody = append(receiptBody, '\n')
	seal.ReceiptSHA256 = realCloudLowerSHA256(receiptBody)
	seal.ReceiptSize = len(receiptBody)
	writeCanonical := func(name string, value any) {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, '\n')
		if err := os.WriteFile(name, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, receiptBody, 0o600); err != nil {
		t.Fatal(err)
	}
	writeCanonical(path+".seal", seal)
	if err := validateRealCloudCloudflareBootstrapReadinessReceipt(path, resource, runID, signerPublicKey, now); err == nil {
		t.Fatal("attacker-rehashed receipt bypassed its Ed25519 signature")
	}

	attackerKey, err := decodeRealCloudProviderReadinessPublicKey(attackerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	seal.SignerPublicKeySHA256 = realCloudLowerSHA256(attackerKey)
	clearRealCloudBytes(attackerKey)
	message := realCloudProviderReadinessSealMessage(receiptBody)
	seal.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(attacker, message))
	clearRealCloudBytes(message)
	writeCanonical(path+".seal", seal)
	if err := validateRealCloudCloudflareBootstrapReadinessReceipt(path, resource, runID, signerPublicKey, now); err == nil {
		t.Fatal("attacker-signed receipt bypassed the bootstrap plan public-key pin")
	}
}

func TestRealCloudCloudflareBootstrapReadinessReturnsTheValidatedPathRead(t *testing.T) {
	resource := realCloudCloudflareReadinessFixture()
	now := time.Now().UTC()
	runID := "20260719T000000Z-readiness-path-swap"
	receipt := realCloudProviderReadinessReceipt{
		Schema: realCloudProviderReadinessReceiptSchema, RunID: runID, Provider: "cloudflare",
		ReadinessResourceSHA256: realCloudProviderReadinessResourceSHA(resource),
		BucketIdentitySHA256:    strings.Repeat("b", 64), ProviderControlSHA256: strings.Repeat("c", 64),
		BucketObservedEmpty: true, ProviderOperations: "read-only:list-objects-v2+zone-and-domain-identity",
		BucketControlClosureSHA256: realCloudProviderEmptyReadinessBucketObservation().ControlClosureSHA256,
		ObservedAt:                 now.Format(time.RFC3339Nano),
	}
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	signer, signerPublicKey := newRealCloudProviderReadinessTestSigner(t)
	defer clearRealCloudBytes(signer)
	path := filepath.Join(private, "readiness.json")
	writeRealCloudProviderReadinessReceipt(t, path, receipt, signer)

	replacement := receipt
	replacement.ProviderControlSHA256 = strings.Repeat("d", 64)
	loaded, err := loadAndValidateRealCloudCloudflareBootstrapReadinessReceiptWithHook(
		path, resource, runID, signerPublicKey, now,
		func() {
			body, marshalErr := json.Marshal(replacement)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			body = append(body, '\n')
			if writeErr := os.WriteFile(path, body, 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
		},
	)
	if err != nil {
		t.Fatalf("load one signed readiness read: %v", err)
	}
	if loaded != receipt {
		t.Fatalf("loader returned pathname replacement instead of signed bytes: got=%+v want=%+v", loaded, receipt)
	}
	var disk realCloudProviderReadinessReceipt
	readRealCloudStrictJSON(t, path, &disk)
	if disk != replacement {
		t.Fatalf("path swap did not install the regression control: got=%+v want=%+v", disk, replacement)
	}
}
