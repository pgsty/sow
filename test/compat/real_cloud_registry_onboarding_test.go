package compat_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	realCloudRegistryOnboardingOptInEnv = "SOW_RUN_REAL_CLOUD_REGISTRY_ONBOARDING"
	realCloudRegistryOutputDirEnv       = "SOW_REAL_CLOUD_REGISTRY_OUTPUT_DIR"
	realCloudRegistryCandidateRunID     = "sow-real-cloud-registry-onboarding"
)

type realCloudRegistryCandidateReceipt struct {
	Schema                           string `json:"schema"`
	ResourceSHA256                   string `json:"resource_sha256"`
	DeploymentSHA256                 string `json:"deployment_sha256"`
	ResourceRegistrySHA256           string `json:"resource_registry_sha256"`
	ProviderDeploymentRegistrySHA256 string `json:"provider_deployment_registry_sha256"`
}

// TestRealCloudRegistryOnboardingCandidate is an intentionally offline
// administrator helper. It never loads credentials or constructs an HTTP
// client. It emits review candidates outside the repository; a human review
// must still copy the exact canonical bytes and update the compiled digest
// constants before any network-capable test can use the resources.
func TestRealCloudRegistryOnboardingCandidate(t *testing.T) {
	if os.Getenv(realCloudRegistryOnboardingOptInEnv) != "1" {
		t.Skip("set SOW_RUN_REAL_CLOUD_REGISTRY_ONBOARDING=1 to emit offline registry review candidates")
	}
	resource, environment, err := decodeRealCloudRegistryCandidateResource(os.Getenv(realCloudAllowlistEnv))
	if err != nil {
		t.Fatal(err)
	}
	configuration, _, err := decodeRealCloudProviderAttestationConfig(
		os.Getenv(realCloudProviderAttestationEnv), environment, realCloudRegistryCandidateRunID,
	)
	if err != nil {
		t.Fatalf("provider deployment candidate is invalid: %v", err)
	}
	resourceRegistry, err := loadRealCloudPinnedTestResourceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	providerRegistry, err := loadRealCloudPinnedProviderDeploymentRegistry()
	if err != nil {
		t.Fatal(err)
	}
	resourceBody, providerBody, receipt, err := buildRealCloudRegistryCandidates(resourceRegistry, providerRegistry, resource, environment, configuration)
	if err != nil {
		t.Fatal(err)
	}
	output := strings.TrimSpace(os.Getenv(realCloudRegistryOutputDirEnv))
	if output == "" || output != os.Getenv(realCloudRegistryOutputDirEnv) {
		t.Fatalf("%s must be one absolute path without surrounding whitespace", realCloudRegistryOutputDirEnv)
	}
	output = prepareRealCloudRegistryCandidateDirectory(t, output)
	writeRealCloudRegistryCandidate(t, filepath.Join(output, "real_cloud_nonproduction_resource_registry.candidate.json"), resourceBody)
	writeRealCloudRegistryCandidate(t, filepath.Join(output, "real_cloud_nonproduction_provider_deployment_registry.candidate.json"), providerBody)
	writeRealCloudExclusiveJSON(t, filepath.Join(output, "real_cloud_registry_candidate_receipt.json"), receipt)
	t.Logf("offline registry candidates written under %s resource_sha256=%s deployment_sha256=%s", output, receipt.ResourceSHA256, receipt.DeploymentSHA256)
}

func decodeRealCloudRegistryCandidateResource(raw string) (realCloudTestResourceAllowlist, realCloudEnvironment, error) {
	var resource realCloudTestResourceAllowlist
	if raw == "" || raw != strings.TrimSpace(raw) {
		return resource, realCloudEnvironment{}, errors.New("missing or non-canonical non-production resource candidate")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&resource); err != nil {
		return resource, realCloudEnvironment{}, errors.New("decode non-production resource candidate")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return resource, realCloudEnvironment{}, errors.New("non-production resource candidate contains trailing values")
	}
	canonical, err := json.Marshal(resource)
	if err != nil || raw != string(canonical) || resource.Schema != "sow-real-cloud-test-resource-allowlist/v1" || resource.Purpose != "dedicated-disposable-non-production-test" {
		return resource, realCloudEnvironment{}, errors.New("non-production resource candidate is non-canonical or invalid")
	}
	environment := realCloudEnvironment{
		CFR2Endpoint: resource.CFR2Endpoint, CFR2Bucket: resource.CFR2Bucket,
		CFZoneID: resource.CFZoneID, CFCDNBase: resource.CFCDNBase, CFBetaCDNBase: resource.CFBetaCDNBase,
		COSEndpoint: resource.COSEndpoint, COSBucket: resource.COSBucket, COSRegion: resource.COSRegion,
		EdgeOneZoneID: resource.EdgeOneZoneID, COSCDNBase: resource.COSCDNBase, COSBetaBase: resource.COSBetaCDNBase,
	}
	if err := validateRealCloudProductionIsolation(environment); err != nil {
		return resource, realCloudEnvironment{}, fmt.Errorf("resource candidate is not production-isolated: %w", err)
	}
	return resource, environment, nil
}

func buildRealCloudRegistryCandidates(
	resources realCloudPinnedTestResourceRegistry,
	providers realCloudPinnedProviderDeploymentRegistry,
	resource realCloudTestResourceAllowlist,
	environment realCloudEnvironment,
	configuration realCloudProviderAttestationConfig,
) ([]byte, []byte, realCloudRegistryCandidateReceipt, error) {
	if resource != realCloudTestResourceForEnvironment(environment) {
		return nil, nil, realCloudRegistryCandidateReceipt{}, errors.New("resource candidate differs from its environment identity")
	}
	if err := validateRealCloudPinnedNonProductionResource(resource); err != nil {
		return nil, nil, realCloudRegistryCandidateReceipt{}, err
	}
	if resources.Schema != "sow-real-cloud-pinned-test-resource-registry/v1" || resources.Resources == nil ||
		providers.Schema != realCloudProviderDeploymentRegistrySchema || providers.Deployments == nil {
		return nil, nil, realCloudRegistryCandidateReceipt{}, errors.New("existing pinned registry is invalid")
	}
	resources.Resources = appendUniqueRealCloudResource(resources.Resources, resource)
	sort.Slice(resources.Resources, func(i, j int) bool {
		return realCloudPinnedResourceKey(resources.Resources[i]) < realCloudPinnedResourceKey(resources.Resources[j])
	})
	resourceIdentity, err := json.Marshal(resource)
	if err != nil {
		return nil, nil, realCloudRegistryCandidateReceipt{}, errors.New("encode resource candidate identity")
	}
	resourceSHA := realCloudLowerSHA256(resourceIdentity)
	deploymentSHA, err := realCloudProviderDeploymentIdentity(environment, configuration)
	if err != nil {
		return nil, nil, realCloudRegistryCandidateReceipt{}, err
	}
	providers.Deployments = appendUniqueRealCloudProviderDeployment(providers.Deployments, realCloudPinnedProviderDeploymentRegistryEntry{
		Schema: realCloudProviderDeploymentEntrySchema, Purpose: "dedicated-disposable-non-production-test",
		ResourceSHA256: resourceSHA, DeploymentSHA256: deploymentSHA,
	})
	sort.Slice(providers.Deployments, func(i, j int) bool {
		left := providers.Deployments[i].ResourceSHA256 + "\x00" + providers.Deployments[i].DeploymentSHA256
		right := providers.Deployments[j].ResourceSHA256 + "\x00" + providers.Deployments[j].DeploymentSHA256
		return left < right
	})
	resourceBody, err := json.Marshal(resources)
	if err != nil {
		return nil, nil, realCloudRegistryCandidateReceipt{}, errors.New("encode resource registry candidate")
	}
	resourceBody = append(resourceBody, '\n')
	providerBody, err := json.Marshal(providers)
	if err != nil {
		return nil, nil, realCloudRegistryCandidateReceipt{}, errors.New("encode provider deployment registry candidate")
	}
	providerBody = append(providerBody, '\n')
	if _, err := decodeRealCloudPinnedTestResourceRegistry(resourceBody, realCloudLowerSHA256(resourceBody)); err != nil {
		return nil, nil, realCloudRegistryCandidateReceipt{}, fmt.Errorf("self-validate resource registry candidate: %w", err)
	}
	if _, err := decodeRealCloudPinnedProviderDeploymentRegistry(providerBody, realCloudLowerSHA256(providerBody)); err != nil {
		return nil, nil, realCloudRegistryCandidateReceipt{}, fmt.Errorf("self-validate provider registry candidate: %w", err)
	}
	receipt := realCloudRegistryCandidateReceipt{
		Schema: "sow-real-cloud-registry-candidate-receipt/v1", ResourceSHA256: resourceSHA, DeploymentSHA256: deploymentSHA,
		ResourceRegistrySHA256: realCloudLowerSHA256(resourceBody), ProviderDeploymentRegistrySHA256: realCloudLowerSHA256(providerBody),
	}
	return resourceBody, providerBody, receipt, nil
}

func appendUniqueRealCloudResource(resources []realCloudTestResourceAllowlist, candidate realCloudTestResourceAllowlist) []realCloudTestResourceAllowlist {
	for _, resource := range resources {
		if resource == candidate {
			return resources
		}
	}
	return append(resources, candidate)
}

func appendUniqueRealCloudProviderDeployment(
	deployments []realCloudPinnedProviderDeploymentRegistryEntry,
	candidate realCloudPinnedProviderDeploymentRegistryEntry,
) []realCloudPinnedProviderDeploymentRegistryEntry {
	for _, deployment := range deployments {
		if deployment == candidate {
			return deployments
		}
	}
	return append(deployments, candidate)
}

func prepareRealCloudRegistryCandidateDirectory(t *testing.T, raw string) string {
	t.Helper()
	if !filepath.IsAbs(raw) || filepath.Clean(raw) != raw {
		t.Fatalf("%s must be one clean absolute path", realCloudRegistryOutputDirEnv)
	}
	root, err := filepath.EvalSymlinks(findModuleRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(raw))
	if err != nil {
		t.Fatalf("resolve registry candidate parent: %v", err)
	}
	output := filepath.Join(parent, filepath.Base(raw))
	relative, err := filepath.Rel(root, output)
	if err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("%s must resolve outside the repository", realCloudRegistryOutputDirEnv)
	}
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatalf("create private registry candidate directory: %v", err)
	}
	return output
}

func writeRealCloudRegistryCandidate(t *testing.T, path string, body []byte) {
	t.Helper()
	if len(body) == 0 || !bytes.HasSuffix(body, []byte("\n")) {
		t.Fatal("registry candidate body is empty or non-canonical")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("create registry candidate: %v", err)
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		t.Fatalf("write registry candidate: %v", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatalf("sync registry candidate: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close registry candidate: %v", err)
	}
	syncRealCloudDirectory(t, filepath.Dir(path))
}

func TestRealCloudRegistryCandidateBuilderIsDeterministicAndProductionSafe(t *testing.T) {
	environment := realCloudSafetyFixtureEnvironment()
	resource := realCloudTestResourceForEnvironment(environment)
	configuration := realCloudProviderConfigurationFixture(environment, strings.Repeat("a", 64))
	emptyResources := realCloudPinnedTestResourceRegistry{Schema: "sow-real-cloud-pinned-test-resource-registry/v1", Resources: []realCloudTestResourceAllowlist{}}
	emptyProviders := realCloudPinnedProviderDeploymentRegistry{Schema: realCloudProviderDeploymentRegistrySchema, Deployments: []realCloudPinnedProviderDeploymentRegistryEntry{}}
	resourceBody, providerBody, receipt, err := buildRealCloudRegistryCandidates(emptyResources, emptyProviders, resource, environment, configuration)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ResourceRegistrySHA256 != realCloudLowerSHA256(resourceBody) || receipt.ProviderDeploymentRegistrySHA256 != realCloudLowerSHA256(providerBody) {
		t.Fatal("candidate receipt does not bind exact canonical registry bytes")
	}
	decodedResources, err := decodeRealCloudPinnedTestResourceRegistry(resourceBody, receipt.ResourceRegistrySHA256)
	if err != nil {
		t.Fatal(err)
	}
	decodedProviders, err := decodeRealCloudPinnedProviderDeploymentRegistry(providerBody, receipt.ProviderDeploymentRegistrySHA256)
	if err != nil {
		t.Fatal(err)
	}
	replayedResourceBody, replayedProviderBody, replayedReceipt, err := buildRealCloudRegistryCandidates(decodedResources, decodedProviders, resource, environment, configuration)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resourceBody, replayedResourceBody) || !bytes.Equal(providerBody, replayedProviderBody) || receipt != replayedReceipt {
		t.Fatal("registry onboarding candidate is not idempotent")
	}
	production := resource
	production.CFCDNBase = "https://pro.pigsty.io"
	if _, _, err := decodeRealCloudRegistryCandidateResource(mustRealCloudCanonicalJSON(t, production)); err == nil {
		t.Fatal("Pigsty production DNS candidate was accepted")
	}
	ownerDesignated := resource
	ownerDesignated.CFR2Bucket = realCloudOwnerDesignatedCFR2Bucket
	ownerDesignated.CFCDNBase = realCloudOwnerDesignatedCFCDNBase
	ownerDesignated.CFBetaCDNBase = realCloudOwnerDesignatedCFBetaBase
	if _, _, err := decodeRealCloudRegistryCandidateResource(mustRealCloudCanonicalJSON(t, ownerDesignated)); err != nil {
		t.Fatalf("exact owner-designated Cloudflare tuple was not accepted for offline review: %v", err)
	}
}

func TestRealCloudRegistryCandidateWriterUsesPrivateExternalDirectory(t *testing.T) {
	parent := t.TempDir()
	output := prepareRealCloudRegistryCandidateDirectory(t, filepath.Join(parent, "candidate"))
	body := []byte("{\"schema\":\"test-only\"}\n")
	path := filepath.Join(output, "candidate.json")
	writeRealCloudRegistryCandidate(t, path, body)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("registry candidate file is absent or not private: mode=%v err=%v", info, err)
	}
	written, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(written, body) {
		t.Fatalf("registry candidate bytes changed: err=%v", err)
	}
}

func mustRealCloudCanonicalJSON(t *testing.T, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
