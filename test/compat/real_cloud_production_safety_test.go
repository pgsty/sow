package compat_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"unicode"

	"github.com/pgsty/sow/internal/config"
)

// TestMain is the process-wide, pre-test safety boundary for every opt-in
// cloud/edge path in this package. It deliberately runs before testing can
// select an individual destructive, evidence, or detached-watcher test. A
// future helper cannot become network-capable merely by forgetting its own
// local preflight. Destructive/evidence paths require the complete resource and
// deployment registries; provider-scoped read-only readiness requires its
// separate exact-provider registry before any credential or client is touched.
func TestMain(m *testing.M) {
	if err := validateRealCloudProviderOptInProcess(
		os.Getenv,
		validateRealCloudDedicatedTestResources,
		func(environment realCloudEnvironment, getenv func(string) string) error {
			_, _, err := decodeAndValidateRealCloudPinnedProviderDeployment(environment, getenv)
			return err
		},
		validateRealCloudProviderReadinessSelection,
		validateRealCloudCloudflareBootstrapSelection,
	); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "test/compat production-cloud safety gate: %v\n", err)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

func validateRealCloudProviderOptInProcess(
	getenv func(string) string,
	validateResources func(realCloudEnvironment, func(string) string) error,
	validateDeployment func(realCloudEnvironment, func(string) string) error,
	validateReadiness func(string, func(string) string) error,
	validateCloudflareBootstrap func(string, func(string) string) error,
) error {
	if err := validateRealCloudOptInProcess(getenv, validateResources); err != nil {
		return err
	}
	readinessRaw := getenv(realCloudProviderReadinessOptInEnv)
	readiness := strings.TrimSpace(readinessRaw)
	if readinessRaw != readiness {
		return fmt.Errorf("%s must not contain surrounding whitespace", realCloudProviderReadinessOptInEnv)
	}
	bootstrapRaw := getenv(realCloudCloudflareBootstrapOptInEnv)
	bootstrap := strings.TrimSpace(bootstrapRaw)
	if bootstrapRaw != bootstrap {
		return fmt.Errorf("%s must not contain surrounding whitespace", realCloudCloudflareBootstrapOptInEnv)
	}
	if bootstrap != "" && bootstrap != "0" {
		if bootstrap != "apply" && bootstrap != "rollback" && bootstrap != "recover-lease" {
			return fmt.Errorf("%s must be exactly apply, rollback, recover-lease, 0, or unset", realCloudCloudflareBootstrapOptInEnv)
		}
		if readiness != "" && readiness != "0" || getenv(realCloudOptInEnv) == "1" || getenv(realEdgeEvidenceOptInEnv) == "1" || getenv(realCloudPurgeWatcherHelperEnv) == "1" {
			return errors.New("Cloudflare bootstrap cannot share a process with readiness, destructive, evidence, or detached-watcher opt-ins")
		}
		if validateCloudflareBootstrap == nil {
			return errors.New("Cloudflare bootstrap safety validator is absent")
		}
		if err := validateCloudflareBootstrap(bootstrap, getenv); err != nil {
			return fmt.Errorf("refuse Cloudflare bootstrap before any request: %w", err)
		}
		return nil
	}
	switch readiness {
	case "", "0":
	case "cloudflare", "edgeone":
		if getenv(realCloudOptInEnv) == "1" || getenv(realEdgeEvidenceOptInEnv) == "1" || getenv(realCloudPurgeWatcherHelperEnv) == "1" {
			return errors.New("provider-scoped readiness cannot share a process with destructive, evidence, or detached-watcher opt-ins")
		}
		if validateReadiness == nil {
			return errors.New("provider-scoped readiness safety validator is absent")
		}
		if err := validateReadiness(readiness, getenv); err != nil {
			return fmt.Errorf("refuse provider-scoped readiness before any request: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("%s must be exactly cloudflare, edgeone, 0, or unset", realCloudProviderReadinessOptInEnv)
	}
	if getenv(realCloudOptInEnv) != "1" && getenv(realEdgeEvidenceOptInEnv) != "1" && getenv(realCloudPurgeWatcherHelperEnv) != "1" {
		return nil
	}
	environment, err := realCloudEnvironmentFromLookup(getenv)
	if err != nil {
		return fmt.Errorf("reload provider resource identity before tests: %w", err)
	}
	if validateDeployment == nil {
		return errors.New("provider deployment safety validator is absent")
	}
	if err := validateDeployment(environment, getenv); err != nil {
		return fmt.Errorf("refuse opt-in before any cloud or edge request: provider deployment gate: %w", err)
	}
	return nil
}

func validateRealCloudOptInProcess(
	getenv func(string) string,
	validate func(realCloudEnvironment, func(string) string) error,
) error {
	active := false
	for _, name := range []string{
		realCloudOptInEnv,
		realEdgeEvidenceOptInEnv,
		realCloudPurgeWatcherHelperEnv,
	} {
		raw := getenv(name)
		value := strings.TrimSpace(raw)
		if raw != value {
			return fmt.Errorf("%s must not contain surrounding whitespace", name)
		}
		switch value {
		case "", "0":
		case "1":
			active = true
		default:
			return fmt.Errorf("%s must be exactly 0, 1, or unset", name)
		}
	}
	if !active {
		return nil
	}
	environment, err := realCloudEnvironmentFromLookup(getenv)
	if err != nil {
		return fmt.Errorf("load opt-in resource identity before tests: %w", err)
	}
	if err := validate(environment, getenv); err != nil {
		return fmt.Errorf("refuse opt-in before any cloud or edge request: %w", err)
	}
	return nil
}

// validateRealCloudProductionIsolation is intentionally stricter than the
// provider SDKs. Provider endpoints prove only protocol family; this gate
// proves that the identities selected for a test cannot look like production.
// The sole exception is the exact owner-designated Cloudflare bucket/main/beta tuple;
// no subset is accepted and every opaque account/zone/deployment value
// still has to be accepted by the separately SHA-pinned registries. Obvious
// prod/production/live identities remain forbidden everywhere.
func validateRealCloudProductionIsolation(environment realCloudEnvironment) error {
	if err := validateRealCloudVendorEndpoints(environment); err != nil {
		return err
	}
	validated := environment
	if isRealCloudOwnerDesignatedCloudflareTest(environment) {
		// Reuse the complete generic isolation validator below after replacing
		// only the two explicitly designated identifiers with inert structural
		// equivalents. All other identities retain the strict generic policy.
		validated.CFR2Bucket = "sow-test-owner-designated-r2"
		validated.CFCDNBase = "https://sow-test-owner-designated-cf.example.invalid"
		validated.CFBetaCDNBase = "https://sow-test-owner-designated-cf-beta.example.invalid"
	}
	identities := []struct {
		name  string
		value string
	}{
		{"Cloudflare R2 endpoint", environment.CFR2Endpoint},
		{"Cloudflare R2 bucket", environment.CFR2Bucket},
		{"Cloudflare zone", environment.CFZoneID},
		{"Cloudflare main CDN", environment.CFCDNBase},
		{"Cloudflare beta CDN", environment.CFBetaCDNBase},
		{"Tencent COS endpoint", environment.COSEndpoint},
		{"Tencent COS bucket", environment.COSBucket},
		{"Tencent COS region", environment.COSRegion},
		{"EdgeOne zone", environment.EdgeOneZoneID},
		{"EdgeOne main CDN", environment.COSCDNBase},
		{"EdgeOne beta CDN", environment.COSBetaBase},
	}
	for _, identity := range identities {
		if identity.value == "" || identity.value != strings.TrimSpace(identity.value) {
			return fmt.Errorf("%s is empty or has surrounding whitespace", identity.name)
		}
		if hasRealCloudProductionMarker(identity.value) {
			return fmt.Errorf("%s contains a forbidden production/prod/live marker", identity.name)
		}
	}
	for name, bucket := range map[string]string{
		"Cloudflare R2": validated.CFR2Bucket,
		"Tencent COS":   validated.COSBucket,
	} {
		if !validDedicatedRealCloudBucket(bucket) {
			return fmt.Errorf("%s bucket must be a lowercase, dedicated sow-test/sow-ci/sow-sandbox name", name)
		}
	}
	if validated.CFR2Bucket == validated.COSBucket {
		return errors.New("Cloudflare R2 and Tencent COS test buckets must have distinct names")
	}

	r2, _ := url.Parse(environment.CFR2Endpoint)
	r2Account := strings.TrimSuffix(strings.ToLower(r2.Hostname()), ".r2.cloudflarestorage.com")
	if r2Account == "" || strings.Contains(r2Account, ".") {
		return errors.New("Cloudflare R2 test endpoint must identify exactly one reviewed account label")
	}

	cdnHosts := make(map[string]string, 4)
	for _, candidate := range []struct {
		name string
		raw  string
	}{
		{"Cloudflare main", validated.CFCDNBase},
		{"Cloudflare beta", validated.CFBetaCDNBase},
		{"EdgeOne main", validated.COSCDNBase},
		{"EdgeOne beta", validated.COSBetaBase},
	} {
		host, err := validateRealCloudNonProductionCDNBase(candidate.name, candidate.raw)
		if err != nil {
			return err
		}
		if prior, exists := cdnHosts[host]; exists {
			return fmt.Errorf("%s and %s reuse CDN host %q", prior, candidate.name, host)
		}
		cdnHosts[host] = candidate.name
	}
	return nil
}

func isRealCloudOwnerDesignatedCloudflareTest(environment realCloudEnvironment) bool {
	return environment.CFR2Bucket == realCloudOwnerDesignatedCFR2Bucket &&
		environment.CFCDNBase == realCloudOwnerDesignatedCFCDNBase &&
		environment.CFBetaCDNBase == realCloudOwnerDesignatedCFBetaBase
}

func validateRealCloudPinnedNonProductionResource(resource realCloudTestResourceAllowlist) error {
	return validateRealCloudProductionIsolation(realCloudEnvironment{
		CFR2Endpoint: resource.CFR2Endpoint, CFR2Bucket: resource.CFR2Bucket,
		CFZoneID: resource.CFZoneID, CFCDNBase: resource.CFCDNBase, CFBetaCDNBase: resource.CFBetaCDNBase,
		COSEndpoint: resource.COSEndpoint, COSBucket: resource.COSBucket, COSRegion: resource.COSRegion,
		EdgeOneZoneID: resource.EdgeOneZoneID, COSCDNBase: resource.COSCDNBase, COSBetaBase: resource.COSBetaCDNBase,
	})
}

func hasRealCloudProductionMarker(value string) bool {
	for _, token := range strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if strings.Contains(token, "production") || strings.HasPrefix(token, "prod") || token == "prd" || token == "live" {
			return true
		}
	}
	return false
}

func validDedicatedRealCloudBucket(value string) bool {
	if len(value) < 3 || len(value) > 63 || !hasRealCloudDedicatedTestPrefix(value) {
		return false
	}
	for index, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' && index > 0 && index < len(value)-1 {
			continue
		}
		return false
	}
	return !strings.Contains(value, "--")
}

func validateRealCloudNonProductionCDNBase(name, raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.Port() != "" ||
		strings.HasSuffix(parsed.Hostname(), ".") || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("%s CDN base must be one credential-free HTTPS origin root", name)
	}
	host := strings.ToLower(parsed.Hostname())
	if !hasRealCloudNonProductionHostMarker(host) {
		return "", fmt.Errorf("%s CDN host lacks an explicit test/ci/sandbox/staging/dev marker", name)
	}
	if isRealCloudProductionDomain(host) {
		return "", fmt.Errorf("%s CDN host belongs to a forbidden production or storage-service domain", name)
	}
	return host, nil
}

func isRealCloudProductionDomain(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, suffix := range []string{
		"pigsty.cc", "pigsty.io", "pigsty.com", "pigsty.net", "pigsty.pro",
		"cloudflarestorage.com", "myqcloud.com",
	} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return isKnownRealCloudProductionHost(host)
}

func TestRealCloudProductionIsolationGate(t *testing.T) {
	valid := realCloudSafetyFixtureEnvironment()
	if err := validateRealCloudProductionIsolation(valid); err != nil {
		t.Fatalf("dedicated non-production fixture rejected: %v", err)
	}
	ownerDesignated := valid
	ownerDesignated.CFR2Bucket = realCloudOwnerDesignatedCFR2Bucket
	ownerDesignated.CFCDNBase = realCloudOwnerDesignatedCFCDNBase
	ownerDesignated.CFBetaCDNBase = realCloudOwnerDesignatedCFBetaBase
	if err := validateRealCloudProductionIsolation(ownerDesignated); err != nil {
		t.Fatalf("exact owner-designated Cloudflare tuple rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*realCloudEnvironment)
	}{
		{"r2-account-prod", func(value *realCloudEnvironment) {
			value.CFR2Endpoint = "https://prod-account.r2.cloudflarestorage.com"
		}},
		{"offered-r2-bucket-pro", func(value *realCloudEnvironment) { value.CFR2Bucket = "pro" }},
		{"owner-main-and-bucket-without-beta", func(value *realCloudEnvironment) {
			value.CFR2Bucket = realCloudOwnerDesignatedCFR2Bucket
			value.CFCDNBase = realCloudOwnerDesignatedCFCDNBase
		}},
		{"r2-bucket-prod", func(value *realCloudEnvironment) { value.CFR2Bucket = "sow-test-prod-repository" }},
		{"cos-bucket-production", func(value *realCloudEnvironment) { value.COSBucket = "sow-test-production-cos-1250000000" }},
		{"cloudflare-prod-zone", func(value *realCloudEnvironment) { value.CFZoneID = "prod-zone" }},
		{"edgeone-live-zone", func(value *realCloudEnvironment) { value.EdgeOneZoneID = "live-zone" }},
		{"offered-production-zone-pro-pigsty-io", func(value *realCloudEnvironment) { value.CFCDNBase = "https://pro.pigsty.io" }},
		{"owner-beta-only", func(value *realCloudEnvironment) { value.CFBetaCDNBase = realCloudOwnerDesignatedCFBetaBase }},
		{"owner-beta-path-variant", func(value *realCloudEnvironment) {
			value.CFR2Bucket = realCloudOwnerDesignatedCFR2Bucket
			value.CFCDNBase = realCloudOwnerDesignatedCFCDNBase
			value.CFBetaCDNBase = realCloudOwnerDesignatedCFBetaBase + "/"
		}},
		{"pigsty-production-zone", func(value *realCloudEnvironment) { value.CFCDNBase = "https://sow-test-cf.pigsty.io" }},
		{"cos-production-zone", func(value *realCloudEnvironment) { value.COSCDNBase = "https://sow-test-cn.pigsty.cc" }},
		{"storage-service-as-cdn", func(value *realCloudEnvironment) { value.COSCDNBase = "https://sow-test.cos.ap-shanghai.myqcloud.com" }},
		{"cdn-path", func(value *realCloudEnvironment) { value.CFBetaCDNBase += "/repository" }},
		{"cdn-query", func(value *realCloudEnvironment) { value.COSBetaBase += "?test=1" }},
		{"unmarked-cdn", func(value *realCloudEnvironment) { value.CFCDNBase = "https://repository.example.invalid" }},
		{"shared-cdn-host", func(value *realCloudEnvironment) { value.COSBetaBase = value.CFCDNBase }},
		{"shared-bucket-name", func(value *realCloudEnvironment) { value.COSBucket = value.CFR2Bucket }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if err := validateRealCloudProductionIsolation(candidate); err == nil {
				t.Fatal("production-like or non-isolated resource identity was accepted")
			}
		})
	}
}

func TestRealCloudPinnedRegistryCannotApproveProductionResource(t *testing.T) {
	resource := realCloudTestResourceForEnvironment(realCloudSafetyFixtureEnvironment())
	resource.CFCDNBase = "https://sow-test-cf.pigsty.io"
	registry := realCloudPinnedTestResourceRegistry{
		Schema:    "sow-real-cloud-pinned-test-resource-registry/v1",
		Resources: []realCloudTestResourceAllowlist{resource},
	}
	body, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	if _, err := decodeRealCloudPinnedTestResourceRegistry(body, realCloudLowerSHA256(body)); err == nil {
		t.Fatal("production Pigsty DNS resource was accepted even with a matching registry SHA-256")
	}

	ownerDesignated := realCloudTestResourceForEnvironment(realCloudSafetyFixtureEnvironment())
	ownerDesignated.CFR2Bucket = realCloudOwnerDesignatedCFR2Bucket
	ownerDesignated.CFCDNBase = realCloudOwnerDesignatedCFCDNBase
	ownerDesignated.CFBetaCDNBase = realCloudOwnerDesignatedCFBetaBase
	registry.Resources = []realCloudTestResourceAllowlist{ownerDesignated}
	body, err = json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	if _, err := decodeRealCloudPinnedTestResourceRegistry(body, realCloudLowerSHA256(body)); err != nil {
		t.Fatalf("exact owner-designated tuple was not reviewable by the pinned registry: %v", err)
	}
}

func TestRealCloudOwnerDesignatedCloudflarePairStillRequiresExactRegistry(t *testing.T) {
	environment := realCloudSafetyFixtureEnvironment()
	environment.CFR2Bucket = realCloudOwnerDesignatedCFR2Bucket
	environment.CFCDNBase = realCloudOwnerDesignatedCFCDNBase
	environment.CFBetaCDNBase = realCloudOwnerDesignatedCFBetaBase
	resource := realCloudTestResourceForEnvironment(environment)
	registry := realCloudPinnedTestResourceRegistry{
		Schema:    "sow-real-cloud-pinned-test-resource-registry/v1",
		Resources: []realCloudTestResourceAllowlist{resource},
	}
	values := realCloudSafetyEnvironmentMap(environment)
	lookup := func(name string) string { return values[name] }
	if err := validateRealCloudDedicatedTestResourcesAgainstRegistry(environment, lookup, registry); err != nil {
		t.Fatalf("exact owner-designated topology rejected after registry review: %v", err)
	}
	if err := validateRealCloudDedicatedTestResources(environment, lookup); err == nil || !strings.Contains(err.Error(), "repository-pinned") {
		t.Fatalf("shipped empty registry did not reject owner-designated topology: %v", err)
	}
	mutated := environment
	mutated.CFZoneID = "another-reviewed-zone"
	if err := validateRealCloudDedicatedTestResourcesAgainstRegistry(mutated, lookup, registry); err == nil {
		t.Fatal("owner designation or registry entry was reused for a different Cloudflare zone")
	}
}

func TestRealCloudNonProductionConfirmationIsExact(t *testing.T) {
	environment := realCloudSafetyFixtureEnvironment()
	values := realCloudSafetyEnvironmentMap(environment)
	values[realCloudNonProductionEnv] = " " + realCloudNonProductionPhrase
	registry := realCloudPinnedTestResourceRegistry{
		Schema:    "sow-real-cloud-pinned-test-resource-registry/v1",
		Resources: []realCloudTestResourceAllowlist{realCloudTestResourceForEnvironment(environment)},
	}
	if err := validateRealCloudDedicatedTestResourcesAgainstRegistry(environment, func(name string) string { return values[name] }, registry); err == nil {
		t.Fatal("whitespace-bearing non-production confirmation was accepted")
	}
}

func TestRealCloudProcessGateRunsForEveryNetworkCapableOptIn(t *testing.T) {
	base := realCloudSafetyEnvironmentMap(realCloudSafetyFixtureEnvironment())
	for _, activeName := range []string{realCloudOptInEnv, realEdgeEvidenceOptInEnv, realCloudPurgeWatcherHelperEnv} {
		t.Run(activeName, func(t *testing.T) {
			values := cloneRealCloudSafetyMap(base)
			values[activeName] = "1"
			calls := 0
			want := errors.New("registry rejected before request")
			err := validateRealCloudOptInProcess(func(name string) string { return values[name] }, func(realCloudEnvironment, func(string) string) error {
				calls++
				return want
			})
			if !errors.Is(err, want) || calls != 1 {
				t.Fatalf("process gate err=%v calls=%d", err, calls)
			}
		})
	}
	values := cloneRealCloudSafetyMap(base)
	values[realCloudOptInEnv] = "true"
	if err := validateRealCloudOptInProcess(func(name string) string { return values[name] }, nil); err == nil {
		t.Fatal("ambiguous real-cloud opt-in value was accepted")
	}
	values[realCloudOptInEnv] = " 1 "
	if err := validateRealCloudOptInProcess(func(name string) string { return values[name] }, nil); err == nil {
		t.Fatal("whitespace-bearing real-cloud opt-in value was accepted")
	}
	values = cloneRealCloudSafetyMap(base)
	values[realCloudProviderLogStorageCredentialCF] = "deliberately-malformed-and-must-not-be-parsed"
	values[realCloudProviderLogStorageCredentialCOS] = "deliberately-malformed-and-must-not-be-parsed"
	values[realCloudProviderLogWriterCredentialCF] = "deliberately-malformed-and-must-not-be-parsed"
	values[realCloudProviderLogWriterCredentialCOS] = "deliberately-malformed-and-must-not-be-parsed"
	validationCalls := 0
	if err := validateRealCloudOptInProcess(func(name string) string { return values[name] }, func(realCloudEnvironment, func(string) string) error {
		validationCalls++
		return errors.New("disabled opt-in unexpectedly reached resource or credential validation")
	}); err != nil || validationCalls != 0 {
		t.Fatalf("disabled opt-in parsed provider-log credentials or entered validation err=%v calls=%d", err, validationCalls)
	}
	values = cloneRealCloudSafetyMap(base)
	values[realCloudOptInEnv] = "1"
	resourceCalls, deploymentCalls := 0, 0
	wantDeployment := errors.New("empty administrator deployment registry")
	err := validateRealCloudProviderOptInProcess(
		func(name string) string { return values[name] },
		func(realCloudEnvironment, func(string) string) error { resourceCalls++; return nil },
		func(realCloudEnvironment, func(string) string) error { deploymentCalls++; return wantDeployment },
		nil,
		nil,
	)
	if !errors.Is(err, wantDeployment) || resourceCalls != 1 || deploymentCalls != 1 {
		t.Fatalf("provider deployment gate did not fail before opt-in execution err=%v resource=%d deployment=%d", err, resourceCalls, deploymentCalls)
	}
	values = cloneRealCloudSafetyMap(base)
	values[realCloudPurgeWatcherHelperEnv] = "1"
	resourceCalls, deploymentCalls = 0, 0
	err = validateRealCloudProviderOptInProcess(
		func(name string) string { return values[name] },
		func(realCloudEnvironment, func(string) string) error { resourceCalls++; return nil },
		func(realCloudEnvironment, func(string) string) error { deploymentCalls++; return wantDeployment },
		nil,
		nil,
	)
	if !errors.Is(err, wantDeployment) || resourceCalls != 1 || deploymentCalls != 1 {
		t.Fatalf("detached watcher bypassed provider deployment gate err=%v resource=%d deployment=%d", err, resourceCalls, deploymentCalls)
	}
	values = cloneRealCloudSafetyMap(base)
	values[realCloudProviderReadinessOptInEnv] = "cloudflare"
	resourceCalls, deploymentCalls, readinessCalls := 0, 0, 0
	wantReadiness := errors.New("empty provider readiness registry")
	err = validateRealCloudProviderOptInProcess(
		func(name string) string { return values[name] },
		func(realCloudEnvironment, func(string) string) error { resourceCalls++; return nil },
		func(realCloudEnvironment, func(string) string) error { deploymentCalls++; return nil },
		func(provider string, _ func(string) string) error {
			readinessCalls++
			if provider != "cloudflare" {
				t.Fatalf("readiness provider=%q", provider)
			}
			return wantReadiness
		},
		nil,
	)
	if !errors.Is(err, wantReadiness) || resourceCalls != 0 || deploymentCalls != 0 || readinessCalls != 1 {
		t.Fatalf("provider-scoped readiness did not use its independent pinned gate err=%v resource=%d deployment=%d readiness=%d", err, resourceCalls, deploymentCalls, readinessCalls)
	}
	values[realCloudProviderReadinessOptInEnv] = " cloudflare"
	if err := validateRealCloudProviderOptInProcess(func(name string) string { return values[name] }, nil, nil, nil, nil); err == nil {
		t.Fatal("whitespace-bearing provider-scoped readiness opt-in was accepted")
	}
	values[realCloudProviderReadinessOptInEnv] = "cloudflare"
	values[realCloudOptInEnv] = "1"
	if err := validateRealCloudProviderOptInProcess(func(name string) string { return values[name] }, func(realCloudEnvironment, func(string) string) error { return nil }, func(realCloudEnvironment, func(string) string) error { return nil }, func(string, func(string) string) error { return nil }, nil); err == nil {
		t.Fatal("provider-scoped readiness was combined with destructive acceptance")
	}
	values = cloneRealCloudSafetyMap(base)
	values[realCloudCloudflareBootstrapOptInEnv] = "apply"
	resourceCalls, deploymentCalls, readinessCalls = 0, 0, 0
	bootstrapCalls := 0
	wantBootstrap := errors.New("empty Cloudflare bootstrap registry")
	err = validateRealCloudProviderOptInProcess(
		func(name string) string { return values[name] },
		func(realCloudEnvironment, func(string) string) error { resourceCalls++; return nil },
		func(realCloudEnvironment, func(string) string) error { deploymentCalls++; return nil },
		func(string, func(string) string) error { readinessCalls++; return nil },
		func(mode string, _ func(string) string) error {
			bootstrapCalls++
			if mode != "apply" {
				t.Fatalf("bootstrap mode=%q", mode)
			}
			return wantBootstrap
		},
	)
	if !errors.Is(err, wantBootstrap) || resourceCalls != 0 || deploymentCalls != 0 || readinessCalls != 0 || bootstrapCalls != 1 {
		t.Fatalf("Cloudflare bootstrap did not use its independent pinned gate err=%v resource=%d deployment=%d readiness=%d bootstrap=%d", err, resourceCalls, deploymentCalls, readinessCalls, bootstrapCalls)
	}
	values[realCloudCloudflareBootstrapOptInEnv] = "recover-lease"
	if err := validateRealCloudProviderOptInProcess(func(name string) string { return values[name] }, nil, nil, nil, func(mode string, _ func(string) string) error {
		if mode != "recover-lease" {
			t.Fatalf("bootstrap recovery mode=%q", mode)
		}
		return nil
	}); err != nil {
		t.Fatalf("isolated Cloudflare lease recovery opt-in rejected: %v", err)
	}
	values[realCloudCloudflareBootstrapOptInEnv] = " apply"
	if err := validateRealCloudProviderOptInProcess(func(name string) string { return values[name] }, nil, nil, nil, nil); err == nil {
		t.Fatal("whitespace-bearing Cloudflare bootstrap opt-in was accepted")
	}
	values[realCloudCloudflareBootstrapOptInEnv] = "apply"
	values[realCloudProviderReadinessOptInEnv] = "cloudflare"
	if err := validateRealCloudProviderOptInProcess(func(name string) string { return values[name] }, nil, nil, nil, func(string, func(string) string) error { return nil }); err == nil {
		t.Fatal("Cloudflare bootstrap was combined with readiness")
	}
}

func TestShippedLocalFixturesCannotSelectCloudTargets(t *testing.T) {
	root, err := realEdgeRepositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{
		"sow.example.yaml",
		"docs/examples/sow-pgdg.yaml",
		"docs/migration/fixtures/pigsty-v1-synthetic.yaml",
		"docs/migration/fixtures/pigsty-v1.yaml",
	} {
		t.Run(relative, func(t *testing.T) {
			file, err := os.Open(filepath.Join(root, filepath.FromSlash(relative)))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			cfg, err := config.Decode(file)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.Targets) != 0 {
				t.Fatalf("shipped local fixture has %d cloud targets", len(cfg.Targets))
			}
		})
	}
}

func TestRealCloudAcceptanceRejectsUnsafeOrUnregisteredResourcesBeforeNetwork(t *testing.T) {
	var proxyRequests atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		proxyRequests.Add(1)
	}))
	defer proxy.Close()

	for _, test := range []struct {
		name     string
		mutate   func(*realCloudEnvironment)
		fragment string
	}{
		{name: "safe-looking-but-unregistered", mutate: func(*realCloudEnvironment) {}, fragment: "repository-pinned"},
		{name: "production-like", mutate: func(environment *realCloudEnvironment) {
			environment.CFR2Endpoint = "https://prod-account.r2.cloudflarestorage.com"
			environment.CFR2Bucket = "sow-test-prod-repository"
			environment.CFZoneID = "production-zone"
			environment.CFCDNBase = "https://sow-test-cf.pigsty.io"
		}, fragment: "production-cloud safety gate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			environment := realCloudSafetyFixtureEnvironment()
			test.mutate(&environment)
			values := realCloudSafetyEnvironmentMap(environment)
			values[realCloudOptInEnv] = "1"
			for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
				values[name] = proxy.URL
			}
			values["NO_PROXY"] = ""
			values["no_proxy"] = ""

			command := exec.Command(os.Args[0], "-test.run=^TestRealCloudAcceptance$", "-test.count=1")
			command.Env = replaceRealCloudSafetyEnvironment(os.Environ(), values)
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), test.fragment) {
				t.Fatalf("unsafe subprocess did not fail at the process gate: err=%v output=%s", err, output)
			}
			if proxyRequests.Load() != 0 {
				t.Fatalf("resource rejection reached proxy/network requests=%d", proxyRequests.Load())
			}
		})
	}
}

func TestRealCloudCloudflareBootstrapRejectsUnregisteredPlanBeforeCredentialsOrNetwork(t *testing.T) {
	var proxyRequests atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		proxyRequests.Add(1)
	}))
	defer proxy.Close()

	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	resourceBody, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	planBody, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	runID := "20260717T120000Z-process-gate"
	planSHA := realCloudLowerSHA256(planBody)
	values := realCloudSafetyEnvironmentMap(realCloudSafetyFixtureEnvironment())
	values[realCloudCloudflareBootstrapOptInEnv] = "apply"
	values[realCloudNonProductionEnv] = realCloudNonProductionPhrase
	values[realCloudRunIDEnv] = runID
	values[realCloudCloudflareBootstrapConfirmationEnv] = realCloudCloudflareBootstrapConfirmation("apply", runID, planSHA, plan.AccountID, plan.ZoneID)
	values[realCloudProviderReadinessResourceEnv] = string(resourceBody)
	values[realCloudCloudflareBootstrapPlanEnv] = string(planBody)
	values[realCloudCDNCredentialCF] = ""
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		values[name] = proxy.URL
	}
	values["NO_PROXY"] = ""
	values["no_proxy"] = ""

	command := exec.Command(os.Args[0], "-test.run=^TestRealCloudCloudflareBootstrap$", "-test.count=1")
	command.Env = replaceRealCloudSafetyEnvironment(os.Environ(), values)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "Cloudflare bootstrap plan is not present in the repository-pinned") {
		t.Fatalf("unregistered Cloudflare bootstrap did not fail at the process gate: err=%v output=%s", err, output)
	}
	if proxyRequests.Load() != 0 {
		t.Fatalf("unregistered Cloudflare bootstrap reached proxy/network requests=%d", proxyRequests.Load())
	}
}

func realCloudSafetyFixtureEnvironment() realCloudEnvironment {
	return realCloudEnvironment{
		CFR2Endpoint: "https://test-account.r2.cloudflarestorage.com", CFR2Bucket: "sow-test-r2-20260714",
		CFZoneID: "opaque-cloudflare-zone", CFCDNBase: "https://sow-test-cf.example.invalid", CFBetaCDNBase: "https://sow-test-cf-beta.example.invalid",
		COSEndpoint: "https://cos.ap-shanghai.myqcloud.com", COSBucket: "sow-sandbox-cos-20260714", COSRegion: "ap-shanghai",
		EdgeOneZoneID: "opaque-edgeone-zone", COSCDNBase: "https://sow-test-eo.example.invalid", COSBetaBase: "https://sow-ci-eo-beta.example.invalid",
		EdgeProTokenA: strings.Repeat("A", 24), EdgeProTokenB: strings.Repeat("B", 24),
	}
}

func realCloudSafetyEnvironmentMap(environment realCloudEnvironment) map[string]string {
	result := map[string]string{
		realCloudOptInEnv: "0", realEdgeEvidenceOptInEnv: "0", realCloudPurgeWatcherHelperEnv: "0",
		realCloudProviderReadinessOptInEnv:   "0",
		realCloudCloudflareBootstrapOptInEnv: "0",
		realCloudNonProductionEnv:            realCloudNonProductionPhrase,
		realCloudEdgeProTokenAEnv:            environment.EdgeProTokenA, realCloudEdgeProTokenBEnv: environment.EdgeProTokenB,
	}
	for field, name := range realCloudEnvironmentNames {
		switch field {
		case "CFR2Endpoint":
			result[name] = environment.CFR2Endpoint
		case "CFR2Bucket":
			result[name] = environment.CFR2Bucket
		case "CFCDNBase":
			result[name] = environment.CFCDNBase
		case "CFBetaCDNBase":
			result[name] = environment.CFBetaCDNBase
		case "CFZoneID":
			result[name] = environment.CFZoneID
		case "COSEndpoint":
			result[name] = environment.COSEndpoint
		case "COSBucket":
			result[name] = environment.COSBucket
		case "COSRegion":
			result[name] = environment.COSRegion
		case "COSCDNBase":
			result[name] = environment.COSCDNBase
		case "COSBetaBase":
			result[name] = environment.COSBetaBase
		case "EdgeOneZoneID":
			result[name] = environment.EdgeOneZoneID
		}
	}
	allowlist, _ := json.Marshal(realCloudTestResourceForEnvironment(environment))
	result[realCloudAllowlistEnv] = string(allowlist)
	result[realCloudConfirmationEnv] = realCloudConfirmation(environment)
	storage, _ := json.Marshal(realCloudStorageSecret{AccessKeyID: "test", SecretAccessKey: strings.Repeat("s", 24)})
	cloudflare, _ := json.Marshal(realCloudCloudflareSecret{APIToken: strings.Repeat("c", 24)})
	tencent, _ := json.Marshal(realCloudTencentSecret{SecretID: "test", SecretKey: strings.Repeat("t", 24)})
	result[realCloudStorageCredentialCF] = string(storage)
	result[realCloudCDNCredentialCF] = string(cloudflare)
	result[realCloudStorageCredentialCOS] = string(storage)
	result[realCloudCDNCredentialCOS] = string(tencent)
	return result
}

func cloneRealCloudSafetyMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func replaceRealCloudSafetyEnvironment(base []string, replacements map[string]string) []string {
	result := make([]string, 0, len(base)+len(replacements))
	for _, entry := range base {
		name, _, found := strings.Cut(entry, "=")
		if found {
			if _, replaced := replacements[name]; replaced {
				continue
			}
		}
		result = append(result, entry)
	}
	for name, value := range replacements {
		result = append(result, name+"="+value)
	}
	return result
}
