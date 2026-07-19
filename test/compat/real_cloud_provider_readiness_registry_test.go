package compat_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	realCloudProviderReadinessResourceEnv           = "SOW_REAL_CLOUD_PROVIDER_READINESS_RESOURCE_JSON"
	realCloudProviderReadinessRegistryOnboardingEnv = "SOW_RUN_REAL_CLOUD_PROVIDER_READINESS_REGISTRY_ONBOARDING"
	realCloudProviderReadinessRegistryPath          = "test/compat/testdata/real_cloud_nonproduction_provider_readiness_registry.json"
	realCloudProviderReadinessRegistrySchema        = "sow-real-cloud-pinned-provider-readiness-registry/v1"
	realCloudProviderReadinessResourceSchema        = "sow-real-cloud-provider-readiness-resource/v1"
	realCloudProviderReadinessRegistrySHA256        = "ed06605a86cb84ece865a6ea2eb7280d3094392d144a5841ac257268bc8f3f63"
)

type realCloudProviderReadinessResource struct {
	Schema     string                                `json:"schema"`
	Purpose    string                                `json:"purpose"`
	Provider   string                                `json:"provider"`
	Cloudflare *realCloudCloudflareReadinessResource `json:"cloudflare,omitempty"`
	EdgeOne    *realCloudEdgeOneReadinessResource    `json:"edgeone,omitempty"`
}

type realCloudCloudflareReadinessResource struct {
	AccountID  string `json:"account_id"`
	R2Endpoint string `json:"r2_endpoint"`
	R2Bucket   string `json:"r2_bucket"`
	ZoneID     string `json:"zone_id"`
	ZoneName   string `json:"zone_name"`
	CDNBase    string `json:"cdn_base"`
	BetaBase   string `json:"beta_base"`
}

type realCloudEdgeOneReadinessResource struct {
	COSEndpoint string `json:"cos_endpoint"`
	COSBucket   string `json:"cos_bucket"`
	COSRegion   string `json:"cos_region"`
	ZoneID      string `json:"zone_id"`
	ZoneName    string `json:"zone_name"`
	CDNBase     string `json:"cdn_base"`
	BetaBase    string `json:"beta_base"`
}

type realCloudPinnedProviderReadinessRegistry struct {
	Schema    string                               `json:"schema"`
	Resources []realCloudProviderReadinessResource `json:"resources"`
}

type realCloudProviderReadinessRegistryCandidateReceipt struct {
	Schema         string `json:"schema"`
	Provider       string `json:"provider"`
	ResourceSHA256 string `json:"resource_sha256"`
	RegistrySHA256 string `json:"registry_sha256"`
}

func loadRealCloudPinnedProviderReadinessRegistry() (realCloudPinnedProviderReadinessRegistry, error) {
	body, err := readRealCloudProviderRepositoryFile(realCloudProviderReadinessRegistryPath, 256<<10)
	if err != nil {
		return realCloudPinnedProviderReadinessRegistry{}, errors.New("repository-pinned provider readiness registry is absent or unsafe")
	}
	defer clearRealCloudBytes(body)
	return decodeRealCloudPinnedProviderReadinessRegistry(body, realCloudProviderReadinessRegistrySHA256)
}

func decodeRealCloudPinnedProviderReadinessRegistry(body []byte, expectedSHA256 string) (realCloudPinnedProviderReadinessRegistry, error) {
	var registry realCloudPinnedProviderReadinessRegistry
	if !validRealCloudLowerSHA256(expectedSHA256) || realCloudLowerSHA256(body) != expectedSHA256 {
		return registry, errors.New("repository-pinned provider readiness registry digest differs from the reviewed build constant")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return registry, errors.New("decode repository-pinned provider readiness registry")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return registry, errors.New("repository-pinned provider readiness registry contains trailing values")
	}
	canonical, err := json.Marshal(registry)
	if err != nil || !bytes.Equal(body, append(canonical, '\n')) || registry.Schema != realCloudProviderReadinessRegistrySchema || registry.Resources == nil {
		return registry, errors.New("repository-pinned provider readiness registry is non-canonical or invalid")
	}
	previous := ""
	for _, resource := range registry.Resources {
		if err := validateRealCloudProviderReadinessResource(resource); err != nil {
			return registry, fmt.Errorf("repository-pinned provider readiness resource is unsafe: %w", err)
		}
		key := realCloudProviderReadinessResourceKey(resource)
		if key <= previous {
			return registry, errors.New("repository-pinned provider readiness resources are duplicate or unsorted")
		}
		previous = key
	}
	return registry, nil
}

func decodeRealCloudProviderReadinessResource(raw string) (realCloudProviderReadinessResource, realCloudEnvironment, error) {
	var resource realCloudProviderReadinessResource
	if raw == "" || raw != strings.TrimSpace(raw) {
		return resource, realCloudEnvironment{}, errors.New("missing or non-canonical provider readiness resource")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&resource); err != nil {
		return resource, realCloudEnvironment{}, errors.New("decode provider readiness resource")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return resource, realCloudEnvironment{}, errors.New("provider readiness resource contains trailing values")
	}
	canonical, err := json.Marshal(resource)
	if err != nil || raw != string(canonical) {
		return resource, realCloudEnvironment{}, errors.New("provider readiness resource must be canonical JSON")
	}
	if err := validateRealCloudProviderReadinessResource(resource); err != nil {
		return resource, realCloudEnvironment{}, err
	}
	return resource, realCloudProviderReadinessEnvironment(resource), nil
}

func validateRealCloudProviderReadinessResource(resource realCloudProviderReadinessResource) error {
	if resource.Schema != realCloudProviderReadinessResourceSchema || resource.Purpose != "dedicated-disposable-non-production-test" {
		return errors.New("provider readiness resource schema or purpose is invalid")
	}
	switch resource.Provider {
	case "cloudflare":
		if resource.Cloudflare == nil || resource.EdgeOne != nil {
			return errors.New("Cloudflare readiness resource must contain only the Cloudflare identity")
		}
		return validateRealCloudCloudflareReadinessResource(*resource.Cloudflare)
	case "edgeone":
		if resource.EdgeOne == nil || resource.Cloudflare != nil {
			return errors.New("EdgeOne readiness resource must contain only the EdgeOne identity")
		}
		return validateRealCloudEdgeOneReadinessResource(*resource.EdgeOne)
	default:
		return errors.New("provider readiness resource provider must be cloudflare or edgeone")
	}
}

func validateRealCloudCloudflareReadinessResource(resource realCloudCloudflareReadinessResource) error {
	for name, value := range map[string]string{
		"account_id": resource.AccountID, "r2_endpoint": resource.R2Endpoint, "r2_bucket": resource.R2Bucket,
		"zone_id": resource.ZoneID, "zone_name": resource.ZoneName, "cdn_base": resource.CDNBase, "beta_base": resource.BetaBase,
	} {
		if value == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("Cloudflare readiness %s is empty or non-canonical", name)
		}
	}
	if !validRealCloudProviderIdentifier(resource.AccountID, 64) || !validRealCloudProviderIdentifier(resource.ZoneID, 64) ||
		hasRealCloudProductionMarker(resource.AccountID) || hasRealCloudProductionMarker(resource.ZoneID) {
		return errors.New("Cloudflare readiness account or zone identity is invalid")
	}
	parsed, err := url.Parse(resource.R2Endpoint)
	wantedHost := strings.ToLower(resource.AccountID) + ".r2.cloudflarestorage.com"
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Host != wantedHost || parsed.Path != "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || resource.R2Endpoint != "https://"+wantedHost {
		return errors.New("Cloudflare readiness R2 endpoint is not the exact account service root")
	}
	mainHost, err := canonicalRealCloudReadinessCDNBase(resource.CDNBase)
	if err != nil {
		return fmt.Errorf("Cloudflare readiness main host: %w", err)
	}
	betaHost, err := canonicalRealCloudReadinessCDNBase(resource.BetaBase)
	if err != nil || mainHost == betaHost {
		return errors.New("Cloudflare readiness beta host is invalid or not distinct")
	}
	zoneName := strings.ToLower(strings.TrimSuffix(resource.ZoneName, "."))
	if resource.ZoneName != zoneName || zoneName == "" {
		return errors.New("Cloudflare readiness zone name is non-canonical")
	}
	ownerTuple := resource.R2Bucket == realCloudOwnerDesignatedCFR2Bucket &&
		resource.CDNBase == realCloudOwnerDesignatedCFCDNBase && resource.BetaBase == realCloudOwnerDesignatedCFBetaBase &&
		zoneName == realCloudOwnerDesignatedCFZoneName
	ownerFragment := resource.R2Bucket == realCloudOwnerDesignatedCFR2Bucket || resource.CDNBase == realCloudOwnerDesignatedCFCDNBase ||
		resource.BetaBase == realCloudOwnerDesignatedCFBetaBase || zoneName == realCloudOwnerDesignatedCFZoneName
	if ownerFragment && !ownerTuple {
		return errors.New("owner-designated Cloudflare readiness identity must use the exact bucket/main/beta/zone tuple")
	}
	if !ownerTuple {
		if !validDedicatedRealCloudBucket(resource.R2Bucket) || hasRealCloudProductionMarker(resource.R2Bucket) ||
			!hasRealCloudNonProductionHostMarker(zoneName) || isRealCloudProductionDomain(zoneName) || hasRealCloudProductionMarker(zoneName) ||
			!hasRealCloudNonProductionHostMarker(mainHost) || !hasRealCloudNonProductionHostMarker(betaHost) {
			return errors.New("Cloudflare readiness resource is not an explicit dedicated non-production identity")
		}
	}
	if mainHost == zoneName || betaHost == zoneName || !strings.HasSuffix(mainHost, "."+zoneName) || !strings.HasSuffix(betaHost, "."+zoneName) {
		return errors.New("Cloudflare readiness hosts are outside the exact zone")
	}
	return nil
}

func validateRealCloudEdgeOneReadinessResource(resource realCloudEdgeOneReadinessResource) error {
	for name, value := range map[string]string{
		"cos_endpoint": resource.COSEndpoint, "cos_bucket": resource.COSBucket, "cos_region": resource.COSRegion,
		"zone_id": resource.ZoneID, "zone_name": resource.ZoneName, "cdn_base": resource.CDNBase, "beta_base": resource.BetaBase,
	} {
		if value == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("EdgeOne readiness %s is empty or non-canonical", name)
		}
		if hasRealCloudProductionMarker(value) {
			return fmt.Errorf("EdgeOne readiness %s contains a forbidden production marker", name)
		}
	}
	if !validRealCloudProviderIdentifier(resource.COSRegion, 64) || !validRealCloudProviderIdentifier(resource.ZoneID, 128) ||
		!validDedicatedRealCloudBucket(resource.COSBucket) || !validRealCloudProviderCOSBucket(resource.COSBucket) {
		return errors.New("EdgeOne readiness region, bucket, or zone identity is invalid")
	}
	parsed, err := url.Parse(resource.COSEndpoint)
	wantedHost := "cos." + strings.ToLower(resource.COSRegion) + ".myqcloud.com"
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || strings.ToLower(parsed.Host) != wantedHost || parsed.Path != "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || resource.COSEndpoint != "https://"+wantedHost {
		return errors.New("EdgeOne readiness COS endpoint is not the exact regional service root")
	}
	mainHost, err := canonicalRealCloudReadinessCDNBase(resource.CDNBase)
	if err != nil {
		return fmt.Errorf("EdgeOne readiness main host: %w", err)
	}
	betaHost, err := canonicalRealCloudReadinessCDNBase(resource.BetaBase)
	if err != nil || mainHost == betaHost {
		return errors.New("EdgeOne readiness beta host is invalid or not distinct")
	}
	zoneName := strings.ToLower(strings.TrimSuffix(resource.ZoneName, "."))
	if resource.ZoneName != zoneName || zoneName == "" || !hasRealCloudNonProductionHostMarker(zoneName) ||
		isRealCloudProductionDomain(zoneName) || !hasRealCloudNonProductionHostMarker(mainHost) || !hasRealCloudNonProductionHostMarker(betaHost) {
		return errors.New("EdgeOne readiness zone or host is not an explicit dedicated non-production identity")
	}
	if mainHost == zoneName || betaHost == zoneName || !strings.HasSuffix(mainHost, "."+zoneName) || !strings.HasSuffix(betaHost, "."+zoneName) {
		return errors.New("EdgeOne readiness hosts are outside the exact zone")
	}
	return nil
}

func canonicalRealCloudReadinessCDNBase(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.Port() != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("must be one credential-free canonical HTTPS origin")
	}
	host := strings.ToLower(parsed.Hostname())
	if parsed.Hostname() != host || raw != "https://"+host {
		return "", errors.New("must use one lowercase host without a trailing slash")
	}
	return host, nil
}

func realCloudProviderReadinessEnvironment(resource realCloudProviderReadinessResource) realCloudEnvironment {
	if resource.Cloudflare != nil {
		identity := resource.Cloudflare
		return realCloudEnvironment{
			CFR2Endpoint: identity.R2Endpoint, CFR2Bucket: identity.R2Bucket, CFZoneID: identity.ZoneID,
			CFCDNBase: identity.CDNBase, CFBetaCDNBase: identity.BetaBase,
		}
	}
	identity := resource.EdgeOne
	return realCloudEnvironment{
		COSEndpoint: identity.COSEndpoint, COSBucket: identity.COSBucket, COSRegion: identity.COSRegion,
		EdgeOneZoneID: identity.ZoneID, COSCDNBase: identity.CDNBase, COSBetaBase: identity.BetaBase,
	}
}

func realCloudProviderReadinessResourceKey(resource realCloudProviderReadinessResource) string {
	body, _ := json.Marshal(resource)
	return resource.Provider + "\x00" + string(body)
}

func realCloudProviderReadinessResourceSHA(resource realCloudProviderReadinessResource) string {
	body, _ := json.Marshal(resource)
	return realCloudLowerSHA256(body)
}

func validateRealCloudProviderReadinessSelection(provider string, getenv func(string) string) error {
	registry, err := loadRealCloudPinnedProviderReadinessRegistry()
	if err != nil {
		return err
	}
	return validateRealCloudProviderReadinessSelectionAgainstRegistry(provider, getenv, registry)
}

func validateRealCloudProviderReadinessSelectionAgainstRegistry(
	provider string,
	getenv func(string) string,
	registry realCloudPinnedProviderReadinessRegistry,
) error {
	if provider != "cloudflare" && provider != "edgeone" {
		return errors.New("provider readiness selector must be cloudflare or edgeone")
	}
	if getenv(realCloudNonProductionEnv) != realCloudNonProductionPhrase {
		return fmt.Errorf("%s must explicitly confirm dedicated disposable non-production resources", realCloudNonProductionEnv)
	}
	resource, _, err := decodeRealCloudProviderReadinessResource(getenv(realCloudProviderReadinessResourceEnv))
	if err != nil {
		return err
	}
	if resource.Provider != provider {
		return errors.New("provider readiness selector differs from the exact resource provider")
	}
	wantedKey := realCloudProviderReadinessResourceKey(resource)
	for _, approved := range registry.Resources {
		if realCloudProviderReadinessResourceKey(approved) == wantedKey {
			return nil
		}
	}
	return errors.New("provider readiness resource is not present in the repository-pinned administrator-reviewed registry")
}

func loadRealCloudProviderReadinessSelection(provider string, getenv func(string) string) (realCloudProviderReadinessResource, realCloudEnvironment, error) {
	if err := validateRealCloudProviderReadinessSelection(provider, getenv); err != nil {
		return realCloudProviderReadinessResource{}, realCloudEnvironment{}, err
	}
	return decodeRealCloudProviderReadinessResource(getenv(realCloudProviderReadinessResourceEnv))
}

func buildRealCloudProviderReadinessRegistryCandidate(
	registry realCloudPinnedProviderReadinessRegistry,
	resource realCloudProviderReadinessResource,
) ([]byte, realCloudProviderReadinessRegistryCandidateReceipt, error) {
	if registry.Schema != realCloudProviderReadinessRegistrySchema || registry.Resources == nil {
		return nil, realCloudProviderReadinessRegistryCandidateReceipt{}, errors.New("existing provider readiness registry is invalid")
	}
	if err := validateRealCloudProviderReadinessResource(resource); err != nil {
		return nil, realCloudProviderReadinessRegistryCandidateReceipt{}, err
	}
	wantedKey := realCloudProviderReadinessResourceKey(resource)
	found := false
	for _, existing := range registry.Resources {
		found = found || realCloudProviderReadinessResourceKey(existing) == wantedKey
	}
	if !found {
		registry.Resources = append(registry.Resources, resource)
	}
	sort.Slice(registry.Resources, func(i, j int) bool {
		return realCloudProviderReadinessResourceKey(registry.Resources[i]) < realCloudProviderReadinessResourceKey(registry.Resources[j])
	})
	body, err := json.Marshal(registry)
	if err != nil {
		return nil, realCloudProviderReadinessRegistryCandidateReceipt{}, errors.New("encode provider readiness registry candidate")
	}
	body = append(body, '\n')
	if _, err := decodeRealCloudPinnedProviderReadinessRegistry(body, realCloudLowerSHA256(body)); err != nil {
		return nil, realCloudProviderReadinessRegistryCandidateReceipt{}, fmt.Errorf("self-validate provider readiness registry candidate: %w", err)
	}
	return body, realCloudProviderReadinessRegistryCandidateReceipt{
		Schema: "sow-real-cloud-provider-readiness-registry-candidate-receipt/v1", Provider: resource.Provider,
		ResourceSHA256: realCloudProviderReadinessResourceSHA(resource), RegistrySHA256: realCloudLowerSHA256(body),
	}, nil
}

// TestRealCloudProviderReadinessRegistryOnboardingCandidate is offline. It
// writes a canonical review candidate outside the repository and never reads a
// credential, constructs a client, or sends a request.
func TestRealCloudProviderReadinessRegistryOnboardingCandidate(t *testing.T) {
	if os.Getenv(realCloudProviderReadinessRegistryOnboardingEnv) != "1" {
		t.Skip("set SOW_RUN_REAL_CLOUD_PROVIDER_READINESS_REGISTRY_ONBOARDING=1 to emit an offline provider readiness registry candidate")
	}
	resource, _, err := decodeRealCloudProviderReadinessResource(os.Getenv(realCloudProviderReadinessResourceEnv))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := loadRealCloudPinnedProviderReadinessRegistry()
	if err != nil {
		t.Fatal(err)
	}
	body, receipt, err := buildRealCloudProviderReadinessRegistryCandidate(registry, resource)
	if err != nil {
		t.Fatal(err)
	}
	output := strings.TrimSpace(os.Getenv(realCloudRegistryOutputDirEnv))
	if output == "" || output != os.Getenv(realCloudRegistryOutputDirEnv) {
		t.Fatalf("%s must be one absolute path without surrounding whitespace", realCloudRegistryOutputDirEnv)
	}
	output = prepareRealCloudRegistryCandidateDirectory(t, output)
	writeRealCloudRegistryCandidate(t, filepath.Join(output, "real_cloud_nonproduction_provider_readiness_registry.candidate.json"), body)
	writeRealCloudExclusiveJSON(t, filepath.Join(output, "real_cloud_provider_readiness_registry_candidate_receipt.json"), receipt)
	t.Logf("offline %s provider readiness registry candidate written under %s resource_sha256=%s registry_sha256=%s", resource.Provider, output, receipt.ResourceSHA256, receipt.RegistrySHA256)
}

func realCloudCloudflareReadinessFixture() realCloudProviderReadinessResource {
	return realCloudProviderReadinessResource{
		Schema: realCloudProviderReadinessResourceSchema, Purpose: "dedicated-disposable-non-production-test", Provider: "cloudflare",
		Cloudflare: &realCloudCloudflareReadinessResource{
			AccountID: "72cdbd1b54f7add44ecbd3d986399481", R2Endpoint: "https://72cdbd1b54f7add44ecbd3d986399481.r2.cloudflarestorage.com",
			R2Bucket: realCloudOwnerDesignatedCFR2Bucket, ZoneID: "da7b5a27e4f9ef6eaa1b00a89c2c77c2", ZoneName: realCloudOwnerDesignatedCFZoneName,
			CDNBase: realCloudOwnerDesignatedCFCDNBase, BetaBase: realCloudOwnerDesignatedCFBetaBase,
		},
	}
}

func realCloudEdgeOneReadinessFixture() realCloudProviderReadinessResource {
	return realCloudProviderReadinessResource{
		Schema: realCloudProviderReadinessResourceSchema, Purpose: "dedicated-disposable-non-production-test", Provider: "edgeone",
		EdgeOne: &realCloudEdgeOneReadinessResource{
			COSEndpoint: "https://cos.ap-shanghai.myqcloud.com", COSBucket: "sow-test-readiness-1250000000", COSRegion: "ap-shanghai",
			ZoneID: "zone-sow-test-readiness", ZoneName: "sow-test-eo.example.invalid",
			CDNBase: "https://repo.sow-test-eo.example.invalid", BetaBase: "https://beta.sow-test-eo.example.invalid",
		},
	}
}

func TestRealCloudProviderReadinessRegistryIsIndependentAndPinned(t *testing.T) {
	registry, err := loadRealCloudPinnedProviderReadinessRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Resources) != 1 ||
		realCloudProviderReadinessResourceKey(registry.Resources[0]) != realCloudProviderReadinessResourceKey(realCloudCloudflareReadinessFixture()) {
		t.Fatalf("shipped provider readiness registry does not contain only the reviewed Cloudflare pro tuple: %+v", registry.Resources)
	}
	root, err := realEdgeRepositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(realCloudProviderReadinessRegistryPath)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRealCloudPinnedProviderReadinessRegistry(append(append([]byte(nil), body...), ' '), realCloudProviderReadinessRegistrySHA256); err == nil {
		t.Fatal("mutated provider readiness registry bypassed its compiled digest")
	}
}

func TestRealCloudProviderReadinessRegistryCandidateIsDeterministicAndProviderScoped(t *testing.T) {
	empty := realCloudPinnedProviderReadinessRegistry{Schema: realCloudProviderReadinessRegistrySchema, Resources: []realCloudProviderReadinessResource{}}
	cloudflare := realCloudCloudflareReadinessFixture()
	body, receipt, err := buildRealCloudProviderReadinessRegistryCandidate(empty, cloudflare)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeRealCloudPinnedProviderReadinessRegistry(body, receipt.RegistrySHA256)
	if err != nil {
		t.Fatal(err)
	}
	replayed, replayedReceipt, err := buildRealCloudProviderReadinessRegistryCandidate(decoded, cloudflare)
	if err != nil || !bytes.Equal(body, replayed) || receipt != replayedReceipt {
		t.Fatalf("provider readiness candidate is not idempotent: err=%v", err)
	}
	edgeOne := realCloudEdgeOneReadinessFixture()
	combined, _, err := buildRealCloudProviderReadinessRegistryCandidate(decoded, edgeOne)
	if err != nil {
		t.Fatal(err)
	}
	combinedRegistry, err := decodeRealCloudPinnedProviderReadinessRegistry(combined, realCloudLowerSHA256(combined))
	if err != nil || len(combinedRegistry.Resources) != 2 || combinedRegistry.Resources[0].Provider != "cloudflare" || combinedRegistry.Resources[1].Provider != "edgeone" {
		t.Fatalf("provider readiness registry did not preserve independent sorted identities: err=%v resources=%+v", err, combinedRegistry.Resources)
	}
}

func TestRealCloudProviderReadinessResourceRejectsPartialOwnerTupleAndCrossProviderFields(t *testing.T) {
	resource := realCloudCloudflareReadinessFixture()
	if err := validateRealCloudProviderReadinessResource(resource); err != nil {
		t.Fatalf("exact owner-designated Cloudflare readiness resource rejected: %v", err)
	}
	mutated := resource
	copyIdentity := *resource.Cloudflare
	mutated.Cloudflare = &copyIdentity
	mutated.Cloudflare.BetaBase = "https://other.pro.pigsty.io"
	if err := validateRealCloudProviderReadinessResource(mutated); err == nil {
		t.Fatal("partial owner-designated Cloudflare readiness tuple was accepted")
	}
	mutated = resource
	mutated.EdgeOne = realCloudEdgeOneReadinessFixture().EdgeOne
	if err := validateRealCloudProviderReadinessResource(mutated); err == nil {
		t.Fatal("provider-scoped Cloudflare readiness resource smuggled an EdgeOne identity")
	}
	if err := validateRealCloudProviderReadinessResource(realCloudEdgeOneReadinessFixture()); err != nil {
		t.Fatalf("dedicated EdgeOne readiness fixture rejected: %v", err)
	}
}

func TestRealCloudProviderReadinessSelectionDoesNotRequireOtherProviderOrDeployment(t *testing.T) {
	resource := realCloudCloudflareReadinessFixture()
	registry := realCloudPinnedProviderReadinessRegistry{Schema: realCloudProviderReadinessRegistrySchema, Resources: []realCloudProviderReadinessResource{resource}}
	raw, _ := json.Marshal(resource)
	values := map[string]string{
		realCloudNonProductionEnv:             realCloudNonProductionPhrase,
		realCloudProviderReadinessResourceEnv: string(raw),
	}
	lookup := func(name string) string { return values[name] }
	if err := validateRealCloudProviderReadinessSelectionAgainstRegistry("cloudflare", lookup, registry); err != nil {
		t.Fatalf("Cloudflare-only readiness selection required unrelated provider state: %v", err)
	}
	if err := validateRealCloudProviderReadinessSelectionAgainstRegistry("edgeone", lookup, registry); err == nil {
		t.Fatal("Cloudflare resource was selected as EdgeOne")
	}
	values[realCloudProviderReadinessResourceEnv] = string(append(raw, ' '))
	if err := validateRealCloudProviderReadinessSelectionAgainstRegistry("cloudflare", lookup, registry); err == nil {
		t.Fatal("non-canonical provider readiness resource was accepted")
	}
}
