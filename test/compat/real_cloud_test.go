package compat_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	gitobject "github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pgsty/sow/internal/catalog"
	"github.com/pgsty/sow/internal/cli"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
	"gopkg.in/yaml.v3"
)

const (
	realCloudOptInEnv             = "SOW_RUN_REAL_CLOUD"
	realCloudConfirmationEnv      = "SOW_REAL_CLOUD_DESTRUCTIVE_CONFIRM"
	realCloudPrivateSigningKeyEnv = "SOW_REAL_CLOUD_GPG_PRIVATE"
	realCloudConfirmationPrefix   = "I-CONFIRM-DESTRUCTIVE-SOW-TEST-ON-EMPTY-R2-AND-NEVER-VERSIONED-COS"
	realCloudFirstPackageVersion  = "10.0.0-1"
	realCloudSecondPackageVersion = "10.0.1-1"
	realCloudRepositoryID         = "apt-real-cloud"
	realCloudYUMRepositoryID      = "yum-real-cloud"
	realCloudAssetRepositoryID    = "asset-real-cloud"
	realCloudGatedAssetRepoID     = "asset-real-cloud-gated"
	realCloudGatedAssetPath       = "assets/real-cloud-gated/secret.txt"
	realCloudRepositoryPublicKey  = "repository-public.gpg"
	realCloudStorageCredentialCF  = "SOW_REAL_CF_STORAGE_JSON"
	realCloudCDNCredentialCF      = "SOW_REAL_CF_CDN_JSON"
	realCloudStorageCredentialCOS = "SOW_REAL_COS_STORAGE_JSON"
	realCloudCDNCredentialCOS     = "SOW_REAL_COS_CDN_JSON"
	realCloudEdgeProTokenAEnv     = "SOW_REAL_EDGE_PRO_TOKEN_A"
	realCloudEdgeProTokenBEnv     = "SOW_REAL_EDGE_PRO_TOKEN_B"
	realCloudWorkspaceEnv         = "SOW_REAL_CLOUD_WORKSPACE"
	realCloudRunIDEnv             = "SOW_REAL_CLOUD_RUN_ID"
	realCloudModeEnv              = "SOW_REAL_CLOUD_MODE"
	realCloudNonProductionEnv     = "SOW_REAL_CLOUD_NONPRODUCTION_CONFIRM"
	realCloudAllowlistEnv         = "SOW_REAL_CLOUD_TEST_RESOURCE_ALLOWLIST_JSON"
	realCloudRunIdentityFilename  = ".sow-real-cloud-run.json"
	realCloudInvalidCFToken       = "sow-real-cloud-intentional-invalid-purge-token"
	realCloudInvalidTencentID     = "sow-real-cloud-intentional-invalid-edgeone-id"
	realCloudInvalidTencentKey    = "sow-real-cloud-intentional-invalid-edgeone-key"
	realCloudNonProductionPhrase  = "I-CONFIRM-DEDICATED-DISPOSABLE-NON-PRODUCTION-SOW-TEST-RESOURCES"
	realCloudPinnedRegistryPath   = "test/compat/testdata/real_cloud_nonproduction_resource_registry.json"
	realCloudPinnedRegistrySHA256 = "bd52ba1da663739b3a5b5a3c8f9d58290d710753d691fcd05c1eb25216ea9cea"

	// The owner explicitly designated this exact R2 bucket/CDN namespace for SOW
	// testing on 2026-07-17. The main/beta/bucket tuple is intentionally
	// inseparable: no identifier is accepted alone, and the account endpoint,
	// zone, second provider and deployment still require SHA-pinned review.
	realCloudOwnerDesignatedCFR2Bucket = "pro"
	realCloudOwnerDesignatedCFCDNBase  = "https://pro.pigsty.io"
	realCloudOwnerDesignatedCFBetaBase = "https://beta.pro.pigsty.io"
	realCloudOwnerDesignatedCFZoneName = "pigsty.io"
)

var errRealCloudOutputSecret = errors.New("CLI output exposed real-cloud secret material")

// TestRealCloudAcceptance is an intentionally destructive, single-use,
// opt-in acceptance test for dedicated disposable non-production
// R2/Cloudflare and COS/EdgeOne resources. Production resources are rejected
// even when the generic destructive confirmation is present.
// It uses cli.Main for every product mutation. Direct provider calls are
// limited to read-only evidence, non-mutating competing-CAS probes that rewrite
// identical control bytes under failing conditions, and one exact SOW-owned
// copy probe that is conditionally deleted immediately after read-back.
// The only direct canonical-state mutation is the documented historical-aging
// fixture: it copies today's CLI-created immutable YUM leaf to an older immutable
// ref because production promote correctly forbids backdating.
//
// Safety properties:
//   - the default test run skips before resolving credentials or networking;
//   - the confirmation phrase binds every storage/CDN resource identity;
//   - both buckets must prove empty before the first remote mutation;
//   - COS publication additionally performs the production never-versioned
//     probe before using create-only generation locks;
//   - cloud secrets and the persistent signing private key originate only in
//     env; runtime token files live outside the repository and are scrubbed;
//     captured CLI output is checked for secret fragments before it is logged.
//   - provider raw-log exporters are rebound to the exact run prefix only
//     after the durable acceptance ledger and provider-scoped run reservation
//     exist and both provider zone identities have been proved non-production.
func TestRealCloudAcceptance(t *testing.T) {
	if os.Getenv(realCloudOptInEnv) != "1" {
		t.Skip("set SOW_RUN_REAL_CLOUD=1 and the documented real-cloud environment contract to run")
	}

	environment := loadRealCloudEnvironment(t)
	if err := validateRealCloudVendorEndpoints(environment); err != nil {
		t.Fatalf("real-cloud vendor endpoint validation failed: %v", err)
	}
	if err := validateRealCloudDedicatedTestResources(environment, os.Getenv); err != nil {
		t.Fatalf("refuse production or non-allowlisted cloud resources: %v", err)
	}
	wantConfirmation := realCloudConfirmation(environment)
	if os.Getenv(realCloudConfirmationEnv) != wantConfirmation {
		t.Fatalf("%s must exactly equal %q", realCloudConfirmationEnv, wantConfirmation)
	}
	secretFragments := loadRealCloudSecretFragments(t)
	privateKey := []byte(os.Getenv(realCloudPrivateSigningKeyEnv))
	if len(privateKey) == 0 {
		t.Fatalf("required persistent signing key environment variable %s is empty", realCloudPrivateSigningKeyEnv)
	}
	publicKey := realCloudPublicSigningMaterial(t, privateKey)
	secretFragments = append(secretFragments, realCloudPrivateKeySecretFragments(privateKey)...)
	defer clearRealCloudBytes(privateKey)

	configBody := marshalRealCloudConfig(t, environment)
	assertNoRealCloudSecret(t, "generated config", configBody, secretFragments)
	runIdentity := realCloudRunIdentityFor(t, environment, configBody, publicKey)
	mode := strings.TrimSpace(os.Getenv(realCloudModeEnv))
	if mode == "" {
		mode = "fresh"
	}
	root := prepareRealCloudPersistentWorkspace(t, mode, runIdentity)
	executeRealCloudAcceptanceProgram(t, mode, root, environment, runIdentity, secretFragments, publicKey, configBody)
}

type realCloudTestResourceAllowlist struct {
	Schema         string `json:"schema"`
	Purpose        string `json:"purpose"`
	CFR2Endpoint   string `json:"cf_r2_endpoint"`
	CFR2Bucket     string `json:"cf_r2_bucket"`
	CFZoneID       string `json:"cf_zone_id"`
	CFCDNBase      string `json:"cf_cdn_base"`
	CFBetaCDNBase  string `json:"cf_beta_cdn_base"`
	COSEndpoint    string `json:"cos_endpoint"`
	COSBucket      string `json:"cos_bucket"`
	COSRegion      string `json:"cos_region"`
	EdgeOneZoneID  string `json:"edgeone_zone_id"`
	COSCDNBase     string `json:"cos_cdn_base"`
	COSBetaCDNBase string `json:"cos_beta_cdn_base"`
}

type realCloudPinnedTestResourceRegistry struct {
	Schema    string                           `json:"schema"`
	Resources []realCloudTestResourceAllowlist `json:"resources"`
}

func validateRealCloudDedicatedTestResources(environment realCloudEnvironment, getenv func(string) string) error {
	registry, err := loadRealCloudPinnedTestResourceRegistry()
	if err != nil {
		return err
	}
	return validateRealCloudDedicatedTestResourcesAgainstRegistry(environment, getenv, registry)
}

func loadRealCloudPinnedTestResourceRegistry() (realCloudPinnedTestResourceRegistry, error) {
	var registry realCloudPinnedTestResourceRegistry
	root, err := realEdgeRepositoryRoot()
	if err != nil {
		return registry, err
	}
	path := filepath.Join(root, filepath.FromSlash(realCloudPinnedRegistryPath))
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256<<10 {
		return registry, errors.New("repository-pinned non-production resource registry is absent or unsafe")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return registry, errors.New("read repository-pinned non-production resource registry")
	}
	return decodeRealCloudPinnedTestResourceRegistry(body, realCloudPinnedRegistrySHA256)
}

func decodeRealCloudPinnedTestResourceRegistry(body []byte, expectedSHA256 string) (realCloudPinnedTestResourceRegistry, error) {
	var registry realCloudPinnedTestResourceRegistry
	if !validRealCloudLowerSHA256(expectedSHA256) || realCloudLowerSHA256(body) != expectedSHA256 {
		return registry, errors.New("repository-pinned non-production resource registry digest differs from the reviewed build constant")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return registry, errors.New("decode repository-pinned non-production resource registry")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return registry, errors.New("repository-pinned non-production resource registry contains trailing values")
	}
	canonical, err := json.Marshal(registry)
	if err != nil || !bytes.Equal(body, append(canonical, '\n')) || registry.Schema != "sow-real-cloud-pinned-test-resource-registry/v1" || registry.Resources == nil {
		return registry, errors.New("repository-pinned non-production resource registry is non-canonical or invalid")
	}
	prior := ""
	for _, resource := range registry.Resources {
		key := realCloudPinnedResourceKey(resource)
		if resource.Schema != "sow-real-cloud-test-resource-allowlist/v1" || resource.Purpose != "dedicated-disposable-non-production-test" || key <= prior {
			return registry, errors.New("repository-pinned non-production resources are invalid, duplicate, or unsorted")
		}
		if err := validateRealCloudPinnedNonProductionResource(resource); err != nil {
			return registry, fmt.Errorf("repository-pinned resource is not production-isolated: %w", err)
		}
		prior = key
	}
	return registry, nil
}

func validateRealCloudDedicatedTestResourcesAgainstRegistry(environment realCloudEnvironment, getenv func(string) string, registry realCloudPinnedTestResourceRegistry) error {
	if err := validateRealCloudProductionIsolation(environment); err != nil {
		return fmt.Errorf("configured test resources are not production-isolated: %w", err)
	}
	ownerDesignatedCloudflare := isRealCloudOwnerDesignatedCloudflareTest(environment)
	if getenv(realCloudNonProductionEnv) != realCloudNonProductionPhrase {
		return fmt.Errorf("%s must explicitly confirm dedicated disposable non-production resources", realCloudNonProductionEnv)
	}
	raw := getenv(realCloudAllowlistEnv)
	if raw == "" {
		return fmt.Errorf("%s is required", realCloudAllowlistEnv)
	}
	if raw != strings.TrimSpace(raw) {
		return errors.New("non-production resource allowlist must not contain surrounding whitespace")
	}
	var actual realCloudTestResourceAllowlist
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&actual); err != nil {
		return errors.New("decode non-production resource allowlist")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("non-production resource allowlist contains trailing values")
	}
	canonical, err := json.Marshal(actual)
	if err != nil || raw != string(canonical) {
		return errors.New("non-production resource allowlist must be canonical JSON")
	}
	wanted := realCloudTestResourceForEnvironment(environment)
	if actual != wanted {
		return errors.New("non-production resource allowlist does not exactly match every configured account endpoint, bucket, region, zone, and CDN base")
	}
	approved := false
	for _, resource := range registry.Resources {
		if resource == wanted {
			approved = true
			break
		}
	}
	if !approved {
		return errors.New("configured resources are not present in the repository-pinned administrator-reviewed non-production registry")
	}
	for name, bucket := range map[string]string{"Cloudflare R2": environment.CFR2Bucket, "Tencent COS": environment.COSBucket} {
		if !hasRealCloudDedicatedTestPrefix(bucket) && !(name == "Cloudflare R2" && ownerDesignatedCloudflare && bucket == realCloudOwnerDesignatedCFR2Bucket) {
			return fmt.Errorf("%s bucket %q lacks the mandatory sow-test/sow-ci/sow-sandbox prefix", name, bucket)
		}
	}
	for name, rawURL := range map[string]string{
		"Cloudflare main": environment.CFCDNBase, "Cloudflare beta": environment.CFBetaCDNBase,
		"EdgeOne main": environment.COSCDNBase, "EdgeOne beta": environment.COSBetaBase,
	} {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" {
			return fmt.Errorf("%s CDN base is not one credential-free HTTPS URL", name)
		}
		host := strings.ToLower(parsed.Hostname())
		ownerDesignatedHost := ownerDesignatedCloudflare &&
			(name == "Cloudflare main" && rawURL == realCloudOwnerDesignatedCFCDNBase ||
				name == "Cloudflare beta" && rawURL == realCloudOwnerDesignatedCFBetaBase)
		if !ownerDesignatedHost && (isKnownRealCloudProductionHost(host) || !hasRealCloudNonProductionHostMarker(host)) {
			return fmt.Errorf("%s CDN host %q is production-like and is forbidden", name, host)
		}
	}
	return nil
}

func realCloudTestResourceForEnvironment(environment realCloudEnvironment) realCloudTestResourceAllowlist {
	return realCloudTestResourceAllowlist{
		Schema: "sow-real-cloud-test-resource-allowlist/v1", Purpose: "dedicated-disposable-non-production-test",
		CFR2Endpoint: environment.CFR2Endpoint, CFR2Bucket: environment.CFR2Bucket,
		CFZoneID: environment.CFZoneID, CFCDNBase: environment.CFCDNBase, CFBetaCDNBase: environment.CFBetaCDNBase,
		COSEndpoint: environment.COSEndpoint, COSBucket: environment.COSBucket, COSRegion: environment.COSRegion,
		EdgeOneZoneID: environment.EdgeOneZoneID, COSCDNBase: environment.COSCDNBase, COSBetaCDNBase: environment.COSBetaBase,
	}
}

func realCloudPinnedResourceKey(resource realCloudTestResourceAllowlist) string {
	return strings.Join([]string{resource.CFR2Endpoint, resource.CFR2Bucket, resource.CFZoneID, resource.CFCDNBase, resource.CFBetaCDNBase,
		resource.COSEndpoint, resource.COSBucket, resource.COSRegion, resource.EdgeOneZoneID, resource.COSCDNBase, resource.COSBetaCDNBase}, "\x00")
}

func hasRealCloudDedicatedTestPrefix(value string) bool {
	lower := strings.ToLower(value)
	return strings.HasPrefix(lower, "sow-test-") || strings.HasPrefix(lower, "sow-ci-") || strings.HasPrefix(lower, "sow-sandbox-")
}

func hasRealCloudNonProductionHostMarker(host string) bool {
	for _, token := range strings.FieldsFunc(host, func(r rune) bool { return r == '.' || r == '-' }) {
		if token == "test" || token == "ci" || token == "sandbox" || token == "staging" || token == "dev" {
			return true
		}
	}
	return false
}

func isKnownRealCloudProductionHost(host string) bool {
	for _, forbidden := range []string{
		"repo.pigsty.cc", "repo.pigsty.io", "repo.pigsty.com", "repo.pigsty.net", "repo.pigsty.pro",
		"apt.pigsty.cc", "yum.pigsty.cc", "get.pigsty.cc",
	} {
		if host == forbidden {
			return true
		}
	}
	return false
}

func TestRealCloudVendorEndpointValidation(t *testing.T) {
	valid := realCloudEnvironment{
		CFR2Endpoint: "https://0123456789abcdef.r2.cloudflarestorage.com",
		COSEndpoint:  "https://cos.ap-shanghai.myqcloud.com",
		COSRegion:    "ap-shanghai",
	}
	if err := validateRealCloudVendorEndpoints(valid); err != nil {
		t.Fatalf("valid vendor endpoints rejected: %v", err)
	}
	for _, test := range []struct {
		name     string
		mutate   func(*realCloudEnvironment)
		fragment string
	}{
		{name: "r2-compatible-impostor", mutate: func(value *realCloudEnvironment) { value.CFR2Endpoint = "https://minio.example.invalid" }, fragment: "Cloudflare R2"},
		{name: "r2-path", mutate: func(value *realCloudEnvironment) { value.CFR2Endpoint += "/bucket" }, fragment: "service root"},
		{name: "cos-compatible-impostor", mutate: func(value *realCloudEnvironment) { value.COSEndpoint = "https://cos.example.invalid" }, fragment: "Tencent COS"},
		{name: "cos-wrong-region", mutate: func(value *realCloudEnvironment) { value.COSEndpoint = "https://cos.ap-beijing.myqcloud.com" }, fragment: "Tencent COS"},
		{name: "insecure", mutate: func(value *realCloudEnvironment) {
			value.CFR2Endpoint = "http://0123456789abcdef.r2.cloudflarestorage.com"
		}, fragment: "HTTPS"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if err := validateRealCloudVendorEndpoints(candidate); err == nil || !strings.Contains(err.Error(), test.fragment) {
				t.Fatalf("endpoint validation err=%v want fragment %q", err, test.fragment)
			}
		})
	}
}

func TestRealCloudDedicatedTestResourceGate(t *testing.T) {
	pinned, err := loadRealCloudPinnedTestResourceRegistry()
	if err != nil {
		t.Fatalf("load reviewed non-production registry: %v", err)
	}
	root, err := realEdgeRepositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	pinnedBody, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(realCloudPinnedRegistryPath)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRealCloudPinnedTestResourceRegistry(append(append([]byte(nil), pinnedBody...), ' '), realCloudPinnedRegistrySHA256); err == nil {
		t.Fatal("mutated administrator-reviewed registry bypassed its compiled SHA-256 pin")
	}
	environment := realCloudEnvironment{
		CFR2Endpoint: "https://test-account.r2.cloudflarestorage.com", CFR2Bucket: "sow-test-r2-20260714", CFZoneID: "opaque-cloudflare-zone",
		CFCDNBase: "https://sow-test-cf.example.invalid", CFBetaCDNBase: "https://sow-test-cf-beta.example.invalid",
		COSEndpoint: "https://cos.ap-shanghai.myqcloud.com", COSBucket: "sow-sandbox-cos-20260714", COSRegion: "ap-shanghai", EdgeOneZoneID: "opaque-edgeone-zone",
		COSCDNBase: "https://sow-test-eo.example.invalid", COSBetaBase: "https://sow-ci-eo-beta.example.invalid",
	}
	allowlistFor := func(value realCloudEnvironment) string {
		body, err := json.Marshal(realCloudTestResourceForEnvironment(value))
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	registryFor := func(value realCloudEnvironment) realCloudPinnedTestResourceRegistry {
		return realCloudPinnedTestResourceRegistry{Schema: "sow-real-cloud-pinned-test-resource-registry/v1", Resources: []realCloudTestResourceAllowlist{realCloudTestResourceForEnvironment(value)}}
	}
	getenvFor := func(value realCloudEnvironment, confirmation, allowlist string) func(string) string {
		return func(name string) string {
			switch name {
			case realCloudNonProductionEnv:
				return confirmation
			case realCloudAllowlistEnv:
				return allowlist
			default:
				return ""
			}
		}
	}
	if err := validateRealCloudDedicatedTestResourcesAgainstRegistry(environment, getenvFor(environment, realCloudNonProductionPhrase, allowlistFor(environment)), registryFor(environment)); err != nil {
		t.Fatalf("dedicated test resources rejected: %v", err)
	}
	approvedByPinned := false
	for _, resource := range pinned.Resources {
		if resource == realCloudTestResourceForEnvironment(environment) {
			approvedByPinned = true
			break
		}
	}
	if err := validateRealCloudDedicatedTestResources(environment, getenvFor(environment, realCloudNonProductionPhrase, allowlistFor(environment))); approvedByPinned && err != nil || !approvedByPinned && (err == nil || !strings.Contains(err.Error(), "repository-pinned")) {
		t.Fatalf("repository-pinned membership gate mismatch approved=%t err=%v", approvedByPinned, err)
	}
	if err := validateRealCloudDedicatedTestResourcesAgainstRegistry(environment, getenvFor(environment, "", allowlistFor(environment)), registryFor(environment)); err == nil {
		t.Fatal("missing explicit non-production confirmation was accepted")
	}
	if err := validateRealCloudDedicatedTestResourcesAgainstRegistry(environment, getenvFor(environment, realCloudNonProductionPhrase, " "+allowlistFor(environment)), registryFor(environment)); err == nil {
		t.Fatal("non-canonical allowlist was accepted")
	}
	productionBucket := environment
	productionBucket.CFR2Bucket = "pigsty-production-repository"
	if err := validateRealCloudDedicatedTestResourcesAgainstRegistry(productionBucket, getenvFor(productionBucket, realCloudNonProductionPhrase, allowlistFor(productionBucket)), registryFor(productionBucket)); err == nil {
		t.Fatal("production-like bucket was accepted")
	}
	productionHost := environment
	productionHost.CFCDNBase = "https://repo.pigsty.cc"
	if err := validateRealCloudDedicatedTestResourcesAgainstRegistry(productionHost, getenvFor(productionHost, realCloudNonProductionPhrase, allowlistFor(productionHost)), registryFor(productionHost)); err == nil {
		t.Fatal("known production CDN host was accepted")
	}
	trailingDotProductionHost := environment
	trailingDotProductionHost.CFBetaCDNBase = "https://beta.pro.pigsty.io."
	if err := validateRealCloudDedicatedTestResourcesAgainstRegistry(trailingDotProductionHost, getenvFor(trailingDotProductionHost, realCloudNonProductionPhrase, allowlistFor(trailingDotProductionHost)), registryFor(trailingDotProductionHost)); err == nil {
		t.Fatal("trailing-dot production CDN host was accepted")
	}
	unmarkedHost := environment
	unmarkedHost.COSCDNBase = "https://repo-edge.example.invalid"
	if err := validateRealCloudDedicatedTestResourcesAgainstRegistry(unmarkedHost, getenvFor(unmarkedHost, realCloudNonProductionPhrase, allowlistFor(unmarkedHost)), registryFor(unmarkedHost)); err == nil {
		t.Fatal("CDN host without a non-production marker was accepted")
	}
	wrongAllowlist := environment
	wrongAllowlist.EdgeOneZoneID = "another-zone"
	if err := validateRealCloudDedicatedTestResourcesAgainstRegistry(environment, getenvFor(environment, realCloudNonProductionPhrase, allowlistFor(wrongAllowlist)), registryFor(environment)); err == nil {
		t.Fatal("allowlist for a different zone was accepted")
	}
}

func TestRealCloudEdgeTokenValidation(t *testing.T) {
	for _, valid := range []string{strings.Repeat("A", 22), strings.Repeat("z", 256), "route_safe-token-1234567890"} {
		if !validRealCloudEdgeToken(valid) {
			t.Fatalf("valid token shape rejected length=%d", len(valid))
		}
	}
	for _, invalid := range []string{"short", strings.Repeat("x", 257), "unsafe/token-1234567890123456", "unsafe.token-1234567890123456", "unsafe%token-123456789012345"} {
		if validRealCloudEdgeToken(invalid) {
			t.Fatalf("unsafe token shape accepted length=%d", len(invalid))
		}
	}
}

func TestRealCloudEnvironmentRejectsUnsafeTokensBeforeEndpointParsing(t *testing.T) {
	values := map[string]string{
		realCloudEnvironmentNames["CFR2Endpoint"]:  "://malformed-r2-endpoint",
		realCloudEnvironmentNames["CFR2Bucket"]:    "dedicated-empty-r2",
		realCloudEnvironmentNames["CFCDNBase"]:     "://malformed-cf-cdn",
		realCloudEnvironmentNames["CFBetaCDNBase"]: "://malformed-cf-beta",
		realCloudEnvironmentNames["CFZoneID"]:      "cf-zone",
		realCloudEnvironmentNames["COSEndpoint"]:   "://malformed-cos-endpoint",
		realCloudEnvironmentNames["COSBucket"]:     "dedicated-empty-cos",
		realCloudEnvironmentNames["COSRegion"]:     "ap-shanghai",
		realCloudEnvironmentNames["COSCDNBase"]:    "://malformed-cos-cdn",
		realCloudEnvironmentNames["COSBetaBase"]:   "://malformed-cos-beta",
		realCloudEnvironmentNames["EdgeOneZoneID"]: "edgeone-zone",
		realCloudEdgeProTokenAEnv:                  strings.Repeat("A", 22),
		realCloudEdgeProTokenBEnv:                  strings.Repeat("B", 22),
	}
	for _, test := range []struct {
		name        string
		environment string
		value       string
	}{
		{name: "token-a", environment: realCloudEdgeProTokenAEnv, value: "unsafe/token-a-123456789012345"},
		{name: "token-b", environment: realCloudEdgeProTokenBEnv, value: "unsafe.token-b-123456789012345"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := make(map[string]string, len(values))
			for name, value := range values {
				candidate[name] = value
			}
			candidate[test.environment] = test.value
			_, err := realCloudEnvironmentFromLookup(func(name string) string { return candidate[name] })
			if err == nil || !strings.Contains(err.Error(), test.environment) || strings.Contains(strings.ToLower(err.Error()), "endpoint") {
				t.Fatalf("unsafe token was not rejected by the pre-endpoint environment loader: %v", err)
			}
		})
	}
}

func TestRealCloudGatedCacheEvidenceContract(t *testing.T) {
	wantedDigest := fmt.Sprintf("%x", sha256.Sum256([]byte("https://repo.example/.sow/gated/"+realCloudGatedAssetPath)))
	for _, status := range []string{"HIT", "MISS", "EXPIRED", "STALE", "UPDATING", "REVALIDATED"} {
		if err := validateRealCloudGatedCacheEvidence(realCloudEdgeResponse{cleanURLSHA256: wantedDigest, cacheStatus: status}, wantedDigest, status == "HIT"); err != nil {
			t.Fatalf("valid cache evidence status=%s rejected: %v", status, err)
		}
	}
	for _, test := range []struct {
		name       string
		digest     string
		status     string
		requireHit bool
	}{
		{name: "empty-digest", status: "MISS"},
		{name: "uppercase-digest", digest: strings.ToUpper(wantedDigest), status: "MISS"},
		{name: "wrong-digest", digest: strings.Repeat("f", sha256.Size*2), status: "MISS"},
		{name: "empty-status", digest: wantedDigest},
		{name: "unknown-status", digest: wantedDigest, status: "UNKNOWN"},
		{name: "bypass-status", digest: wantedDigest, status: "BYPASS"},
		{name: "dynamic-status", digest: wantedDigest, status: "DYNAMIC"},
		{name: "second-token-miss", digest: wantedDigest, status: "MISS", requireHit: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateRealCloudGatedCacheEvidence(realCloudEdgeResponse{cleanURLSHA256: test.digest, cacheStatus: test.status}, wantedDigest, test.requireHit); err == nil {
				t.Fatal("invalid gated cache evidence was accepted")
			}
		})
	}
}

func TestRealCloudAnonymousGatedResponseContract(t *testing.T) {
	wanted := []byte("gated payload must remain confidential")
	valid := realCloudEdgeResponse{
		status: http.StatusNotFound, edgeContract: "sow-edge-runtime/v1", body: []byte("not_found\n"),
		headers: http.Header{
			"Content-Type":           {"text/plain; charset=utf-8"},
			"Cache-Control":          {"private, no-store, max-age=0"},
			"X-Content-Type-Options": {"nosniff"},
			"X-Sow-Edge-Contract":    {"sow-edge-runtime/v1"},
		},
	}
	if err := validateRealCloudAnonymousGatedResponse(valid, wanted); err != nil {
		t.Fatalf("valid anonymous denial rejected: %v", err)
	}
	wantedDigest := fmt.Sprintf("%x", sha256.Sum256(wanted))
	for _, test := range []struct {
		name     string
		response realCloudEdgeResponse
	}{
		{name: "wrong-status", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) { response.status = http.StatusOK })},
		{name: "missing-edge-contract", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) { response.edgeContract = "" })},
		{name: "wrong-body", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) { response.body = []byte("not found\n") })},
		{name: "body-leak", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) { response.body = append([]byte("denied: "), wanted...) })},
		{name: "partial-body-leak", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) { response.body = append([]byte("not_found\n"), wanted[:8]...) })},
		{name: "digest-body-leak", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) { response.body = []byte(wantedDigest) })},
		{name: "wrong-content-type", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) {
			response.headers.Set("Content-Type", "application/octet-stream")
		})},
		{name: "wrong-cache-control", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) { response.headers.Set("Cache-Control", "public, max-age=300") })},
		{name: "missing-nosniff", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) { response.headers.Del("X-Content-Type-Options") })},
		{name: "etag-leak", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) { response.headers.Set("ETag", `"`+wantedDigest+`"`) })},
		{name: "content-range-leak", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) { response.headers.Set("Content-Range", "bytes 0-7/37") })},
		{name: "last-modified-leak", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) {
			response.headers.Set("Last-Modified", "Tue, 14 Jul 2026 00:00:00 GMT")
		})},
		{name: "digest-header-leak", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) {
			response.headers.Set("Content-Digest", "sha-256=:"+wantedDigest+":")
		})},
		{name: "origin-path-leak", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) { response.headers.Set("X-SOW-Clean-URL-SHA256", wantedDigest) })},
		{name: "origin-cache-leak", response: mutateRealCloudEdgeResponse(valid, func(response *realCloudEdgeResponse) { response.headers.Set("X-SOW-Origin-Cache-Status", "HIT") })},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateRealCloudAnonymousGatedResponse(test.response, wanted); err == nil {
				t.Fatal("invalid anonymous gated response was accepted")
			}
		})
	}
}

func TestRealCloudGatedRangeEvidenceContract(t *testing.T) {
	wantedDigest := fmt.Sprintf("%x", sha256.Sum256([]byte("https://repo.example/.sow/gated/"+realCloudGatedAssetPath)))
	valid := realCloudEdgeResponse{
		status: http.StatusPartialContent, transport: "https-bearer", cleanURLSHA256: wantedDigest,
		cacheStatus: "HIT", contentRange: "bytes 0-2/37",
	}
	if err := validateRealCloudGatedRangeEvidence(valid, wantedDigest, 37); err != nil {
		t.Fatalf("valid gated range evidence rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*realCloudEdgeResponse)
	}{
		{name: "wrong-status", mutate: func(response *realCloudEdgeResponse) { response.status = http.StatusOK }},
		{name: "wrong-transport", mutate: func(response *realCloudEdgeResponse) { response.transport = "r2-binding" }},
		{name: "wrong-content-range", mutate: func(response *realCloudEdgeResponse) { response.contentRange = "bytes 0-2/36" }},
		{name: "wrong-clean-url", mutate: func(response *realCloudEdgeResponse) { response.cleanURLSHA256 = strings.Repeat("f", 64) }},
		{name: "unobservable-cache", mutate: func(response *realCloudEdgeResponse) { response.cacheStatus = "BYPASS" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if err := validateRealCloudGatedRangeEvidence(candidate, wantedDigest, 37); err == nil {
				t.Fatal("invalid gated range evidence was accepted")
			}
		})
	}
}

func TestRealCloudInterruptedPointerValidationContract(t *testing.T) {
	for _, target := range []publish.TargetName{publish.TargetCloudflare, publish.TargetTencent} {
		t.Run(string(target), func(t *testing.T) {
			generation := publish.TargetGeneration{
				Target:                target,
				Generation:            2,
				ParentGeneration:      1,
				DesiredCommit:         strings.Repeat("a", 40),
				IntentView:            "latest",
				ConfigSHA256:          strings.Repeat("b", 64),
				ContentManifestSHA256: strings.Repeat("c", 64),
				Refs: []publish.RefState{{
					Name:           "refs/sow/views/latest/repo/el10/x86_64",
					Commit:         strings.Repeat("d", 40),
					ManifestSHA256: strings.Repeat("e", 64),
				}},
			}
			body, err := generation.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			locked, err := publish.NewCheckpoint(generation, "tx-interrupted-pointer", strings.Repeat("f", 64), publish.PhaseLocked, time.Date(2026, 7, 14, 1, 2, 3, 0, time.UTC))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateRealCloudInterruptedRemotePointer(locked, body, target); err != nil {
				t.Fatalf("valid %s interrupted pointer rejected: %v", target, err)
			}

			otherTarget := publish.TargetCloudflare
			if target == publish.TargetCloudflare {
				otherTarget = publish.TargetTencent
			}
			if err := validateRealCloudInterruptedRemotePointer(locked, body, otherTarget); err == nil {
				t.Fatal("interrupted pointer accepted the wrong provider target")
			}
			if err := validateRealCloudInterruptedRemotePointer(locked, append(append([]byte(nil), body...), '\n'), target); err == nil {
				t.Fatal("interrupted pointer accepted non-canonical generation bytes")
			}
			wrongDigest := locked
			wrongDigest.GenerationSHA256 = strings.Repeat("f", 64)
			if err := validateRealCloudInterruptedRemotePointer(wrongDigest, body, target); err == nil {
				t.Fatal("interrupted pointer accepted bytes outside the locked checkpoint digest")
			}
			wrongIntent := locked
			wrongIntent.IntentView = "beta"
			if err := validateRealCloudInterruptedRemotePointer(wrongIntent, body, target); err == nil {
				t.Fatal("interrupted pointer accepted a generation outside the locked publication intent")
			}
		})
	}
}

func TestRealCloudInvalidTencentCredentialPreservesNonSigningContract(t *testing.T) {
	raw := `{"secret_id":"original-id","secret_key":"original-key","session_token":"session","basic_username":"basic-user","basic_password":"basic-password"}`
	rewritten := realCloudInvalidTencentCDNCredential(t, raw)
	var credential realCloudTencentSecret
	decoder := json.NewDecoder(strings.NewReader(rewritten))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credential); err != nil {
		t.Fatal("intentional EdgeOne failure credential is not valid provider JSON")
	}
	if credential.SecretID != realCloudInvalidTencentID || credential.SecretKey != realCloudInvalidTencentKey {
		t.Fatal("intentional EdgeOne failure credential retained a valid signing identity")
	}
	if credential.SessionToken != "session" || credential.BasicUsername != "basic-user" || credential.BasicPassword != "basic-password" {
		t.Fatal("intentional EdgeOne failure credential changed unrelated transport or Basic fallback fields")
	}
	if strings.Contains(rewritten, "original-id") || strings.Contains(rewritten, "original-key") {
		t.Fatal("intentional EdgeOne failure credential retained original signing material")
	}
}

func TestRealCloudDestructiveConfirmationBindsExactBuckets(t *testing.T) {
	environment := realCloudEnvironment{
		CFR2Endpoint: "https://account.r2.cloudflarestorage.com", CFR2Bucket: "sow-r2-empty",
		CFCDNBase: "https://repo-cf.example.invalid", CFBetaCDNBase: "https://beta-cf.example.invalid", CFZoneID: "cf-zone",
		COSEndpoint: "https://cos.ap-shanghai.myqcloud.com", COSBucket: "sow-cos-empty-1250000000", COSRegion: "ap-shanghai",
		COSCDNBase: "https://repo-cos.example.invalid", COSBetaBase: "https://beta-cos.example.invalid", EdgeOneZoneID: "eo-zone",
	}
	want := realCloudConfirmation(environment)
	if want != realCloudConfirmationPrefix+":R2=https://account.r2.cloudflarestorage.com/sow-r2-empty;CF=cf-zone@https://repo-cf.example.invalid,https://beta-cf.example.invalid;COS=https://cos.ap-shanghai.myqcloud.com/sow-cos-empty-1250000000@ap-shanghai;EO=eo-zone@https://repo-cos.example.invalid,https://beta-cos.example.invalid" {
		t.Fatalf("confirmation=%q", want)
	}
	changed := environment
	changed.CFR2Endpoint = "https://other.r2.cloudflarestorage.com"
	if want == realCloudConfirmation(changed) {
		t.Fatal("destructive confirmation is not bound to the R2 account endpoint")
	}
	changed = environment
	changed.COSBucket = "sow-cos-other-1250000000"
	if want == realCloudConfirmation(changed) {
		t.Fatal("destructive confirmation is not bound to the exact COS bucket")
	}
	changed = environment
	changed.EdgeOneZoneID = "eo-other"
	if want == realCloudConfirmation(changed) {
		t.Fatal("destructive confirmation is not bound to the EdgeOne zone")
	}
	changed = environment
	changed.CFCDNBase = "https://production-cf.example.invalid"
	if want == realCloudConfirmation(changed) {
		t.Fatal("destructive confirmation is not bound to the Cloudflare main CDN URL")
	}
	changed = environment
	changed.COSBetaBase = "https://production-beta-cos.example.invalid"
	if want == realCloudConfirmation(changed) {
		t.Fatal("destructive confirmation is not bound to the EdgeOne beta CDN URL")
	}
}

func TestRealCloudGeneratedConfigUsesOnlyEnvironmentSecretReferences(t *testing.T) {
	environment := realCloudEnvironment{
		CFR2Endpoint: "https://account.r2.cloudflarestorage.com", CFR2Bucket: "sow-r2-empty",
		CFCDNBase: "https://repo-cf.example.invalid", CFBetaCDNBase: "https://beta-cf.example.invalid", CFZoneID: "cf-zone",
		COSEndpoint: "https://cos.ap-shanghai.myqcloud.com", COSBucket: "sow-cos-empty-1250000000", COSRegion: "ap-shanghai",
		COSCDNBase: "https://repo-cos.example.invalid", COSBetaBase: "https://beta-cos.example.invalid", EdgeOneZoneID: "eo-zone",
	}
	body := marshalRealCloudConfig(t, environment)
	for _, reference := range []string{
		"env://" + realCloudPrivateSigningKeyEnv,
		"env://" + realCloudStorageCredentialCF,
		"env://" + realCloudCDNCredentialCF,
		"env://" + realCloudStorageCredentialCOS,
		"env://" + realCloudCDNCredentialCOS,
	} {
		if !bytes.Contains(body, []byte(reference)) {
			t.Fatalf("generated config omitted secret reference %s", reference)
		}
	}
	assertNoRealCloudSecret(t, "generated config", body, []string{
		"offline-access-key", "offline-secret-key", "offline-cdn-token", "offline-private-key",
	})
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	writeFile(t, configPath, body, 0o600)
	if _, err := config.Load(configPath, ""); err != nil {
		t.Fatalf("generated config does not satisfy the production schema: %v", err)
	}
}

func TestRealCloudGatedAssetMutatesStableWithoutPromotion(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{
		filepath.Join(root, "apt", "real-cloud"),
		filepath.Join(root, "yum", "real-cloud", "x86_64"),
		filepath.Join(root, "assets", "real-cloud"),
		filepath.Join(root, "assets", "real-cloud-gated"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	environment := realCloudEnvironment{
		CFR2Endpoint: "https://account.r2.cloudflarestorage.com", CFR2Bucket: "sow-r2-empty",
		CFCDNBase: "https://repo-cf.example.invalid", CFBetaCDNBase: "https://beta-cf.example.invalid", CFZoneID: "cf-zone",
		COSEndpoint: "https://cos.ap-shanghai.myqcloud.com", COSBucket: "sow-cos-empty-1250000000", COSRegion: "ap-shanghai",
		COSCDNBase: "https://repo-cos.example.invalid", COSBetaBase: "https://beta-cos.example.invalid", EdgeOneZoneID: "eo-zone",
	}
	privateKey, publicKey := realCloudSigningMaterial(t)
	defer clearRealCloudBytes(privateKey)
	writeFile(t, filepath.Join(root, realCloudRepositoryPublicKey), publicKey, 0o644)
	configPath := filepath.Join(root, "sow.yaml")
	writeFile(t, configPath, marshalRealCloudConfig(t, environment), 0o600)
	run := func(expected int, arguments ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := cli.Main(arguments, &stdout, &stderr)
		if code != expected {
			t.Fatalf("offline sow %s exit=%d want=%d stdout=%s stderr=%s", strings.Join(arguments, " "), code, expected, stdout.String(), stderr.String())
		}
		return stdout.String() + stderr.String()
	}
	run(cli.ExitOK, "init", "--config", configPath, "--workers", "2", "--chunk-entries", "16")
	input := filepath.Join(root, "gated-input.txt")
	writeFile(t, input, []byte("gated-state-one\n"), 0o600)
	firstOutput := run(cli.ExitOK, "add", input, "--config", configPath, "--repo", realCloudGatedAssetRepoID, "--dest", "secret.txt", "--workers", "2", "--chunk-entries", "16")
	if !strings.Contains(firstOutput, "repo="+realCloudGatedAssetRepoID+" view=stable") || strings.Contains(firstOutput, "view=beta") {
		t.Fatalf("gated asset did not mutate stable directly: %s", firstOutput)
	}
	canonical := state.New(filepath.Join(root, config.StateDirectory))
	stableRef, _ := state.ViewRef("stable", realCloudGatedAssetRepoID, "all", "all")
	betaRef, _ := state.ViewRef("beta", realCloudGatedAssetRepoID, "all", "all")
	stablePath, _ := state.ViewPath("stable", realCloudGatedAssetRepoID, "all", "all")
	firstCommit, exists, err := canonical.Ref(stableRef)
	if err != nil || !exists {
		t.Fatalf("gated stable ref exists=%v err=%v", exists, err)
	}
	if _, exists, err := canonical.Ref(betaRef); err != nil || exists {
		t.Fatalf("gated asset unexpectedly created a public beta ref exists=%v err=%v", exists, err)
	}
	readHash := func(commit plumbing.Hash) string {
		reader, err := canonical.OpenPathAt(commit, stablePath)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		entries := views.NewReader(reader)
		for {
			entry, err := entries.Next()
			if errors.Is(err, io.EOF) {
				t.Fatal("stable gated manifest omitted secret.txt")
			}
			if err != nil {
				t.Fatal(err)
			}
			if entry.Path == realCloudGatedAssetPath {
				return entry.SHA256
			}
		}
	}
	firstHash := readHash(firstCommit)
	writeFile(t, input, []byte("gated-state-two\n"), 0o600)
	secondOutput := run(cli.ExitOK, "add", input, "--config", configPath, "--repo", realCloudGatedAssetRepoID, "--dest", "secret.txt", "--replace", "--workers", "2", "--chunk-entries", "16")
	if !strings.Contains(secondOutput, "view=stable") || !strings.Contains(secondOutput, "replaced=1") {
		t.Fatalf("gated mutable replacement did not advance stable: %s", secondOutput)
	}
	secondCommit, exists, err := canonical.Ref(stableRef)
	if err != nil || !exists || secondCommit == firstCommit || readHash(secondCommit) == firstHash {
		t.Fatalf("gated stable replacement commit/hash did not advance exists=%v err=%v", exists, err)
	}
	if _, exists, err := canonical.Ref(betaRef); err != nil || exists {
		t.Fatalf("gated replacement unexpectedly created a public beta ref exists=%v err=%v", exists, err)
	}
}

func TestRealCloudStablePlanAssertionContract(t *testing.T) {
	environment := realCloudEnvironment{CFCDNBase: "https://repo.example.invalid"}
	base := environment.CFCDNBase
	evidence := realCloudPublication{
		generation: publish.TargetGeneration{
			Target: publish.TargetCloudflare, Generation: 4, IntentView: "stable",
			Channels: []publish.ChannelState{{View: "stable", Repo: realCloudYUMRepositoryID, OS: "el10", Arch: "x86_64", Generation: 4}},
		},
		checkpoint: publish.Checkpoint{Target: publish.TargetCloudflare, Generation: 4, IntentView: "stable", Phase: publish.PhaseCheckpointCommitted},
		plan: publish.Plan{
			Objects: []publish.PlannedObject{
				{RemoteKey: ".sow/gated/apt/real-cloud/dists/jammy/InRelease"},
				{RemoteKey: ".sow/gated/generations/00000000000000000004/yum/yum/real-cloud/x86_64/repodata/repomd.xml"},
				{RemoteKey: ".sow/channels/stable/" + realCloudYUMRepositoryID + "/el10/x86_64.json"},
				{RemoteKey: ".sow/gated/assets/real-cloud/latest.txt", SHA256: strings.Repeat("c", 64)},
				{RemoteKey: ".sow/gated/" + realCloudGatedAssetPath, SHA256: strings.Repeat("a", 64)},
			},
			Verify: make([]publish.VerifyObject, 5),
			PurgeURLs: []string{
				base + "/pro/v1/basic/apt/real-cloud/dists/jammy/InRelease",
				base + "/pro/v1/basic/_sow/v1/mirrorlist/stable/" + realCloudYUMRepositoryID + "/el10/x86_64.txt",
				base + "/pro/v1/basic/yum/real-cloud/x86_64/repodata/repomd.xml",
				base + "/pro/v1/basic/yum/real-cloud/x86_64/repodata/repomd.xml.asc",
				base + "/pro/v1/basic/assets/real-cloud/latest.txt",
				base + "/pro/v1/basic/" + realCloudGatedAssetPath,
				base + "/.sow/gated/apt/real-cloud/dists/jammy/InRelease",
				base + "/.sow/channels/stable/" + realCloudYUMRepositoryID + "/el10/x86_64.json",
				base + "/.sow/gated/yum/real-cloud/x86_64/repodata/repomd.xml",
				base + "/.sow/gated/yum/real-cloud/x86_64/repodata/repomd.xml.asc",
				base + "/.sow/gated/assets/real-cloud/latest.txt",
				base + "/.sow/gated/" + realCloudGatedAssetPath,
			},
		},
	}
	if _, err := validateRealCloudStablePublication(environment, "cf", evidence, publish.TargetCloudflare, 4); err != nil {
		t.Fatalf("valid stable assertion fixture rejected: %v", err)
	}
	allPurges := append([]string(nil), evidence.plan.PurgeURLs...)
	evidence.plan.PurgeURLs = nil
	for _, rawURL := range allPurges {
		if rawURL != base+"/pro/v1/basic/assets/real-cloud/latest.txt" {
			evidence.plan.PurgeURLs = append(evidence.plan.PurgeURLs, rawURL)
		}
	}
	if _, err := validateRealCloudStablePublication(environment, "cf", evidence, publish.TargetCloudflare, 4); err == nil || !strings.Contains(err.Error(), "public-asset client") {
		t.Fatalf("stable assertion accepted missing public asset purge closure: %v", err)
	}
	evidence.plan.PurgeURLs = nil
	for _, rawURL := range allPurges {
		if rawURL != base+"/.sow/gated/"+realCloudGatedAssetPath {
			evidence.plan.PurgeURLs = append(evidence.plan.PurgeURLs, rawURL)
		}
	}
	if _, err := validateRealCloudStablePublication(environment, "cf", evidence, publish.TargetCloudflare, 4); err == nil || !strings.Contains(err.Error(), "gated-asset clean") {
		t.Fatalf("stable assertion accepted incomplete purge closure: %v", err)
	}
	evidence.plan.PurgeURLs = append([]string(nil), allPurges...)
	evidence.plan.PurgeURLs[len(evidence.plan.PurgeURLs)-1] = "https://other.example.invalid/.sow/gated/" + realCloudGatedAssetPath
	if _, err := validateRealCloudStablePublication(environment, "cf", evidence, publish.TargetCloudflare, 4); err == nil || !strings.Contains(err.Error(), "unplanned purge URL") {
		t.Fatalf("stable assertion accepted wrong-target purge URL: %v", err)
	}
}

func TestRealCloudExactPurgeURLContract(t *testing.T) {
	wanted := map[string]string{
		"https://repo.example.invalid/apt/real-cloud/dists/jammy/InRelease":      "apt",
		"https://repo.example.invalid/yum/real-cloud/x86_64/repodata/repomd.xml": "yum repomd",
	}
	valid := []string{
		"https://repo.example.invalid/apt/real-cloud/dists/jammy/InRelease",
		"https://repo.example.invalid/yum/real-cloud/x86_64/repodata/repomd.xml",
	}
	if err := validateRealCloudExactPurgeURLs(valid, wanted); err != nil {
		t.Fatalf("valid exact purge set rejected: %v", err)
	}
	for _, test := range []struct {
		name string
		urls []string
	}{
		{name: "missing", urls: valid[:1]},
		{name: "duplicate", urls: []string{valid[0], valid[0]}},
		{name: "wrong-target", urls: []string{valid[0], "https://other.example.invalid/yum/real-cloud/x86_64/repodata/repomd.xml"}},
		{name: "extra", urls: append(append([]string(nil), valid...), "https://repo.example.invalid/unplanned")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateRealCloudExactPurgeURLs(test.urls, wanted); err == nil {
				t.Fatal("invalid exact purge set was accepted")
			}
		})
	}
	if err := validateRealCloudPurgeURLBase("https://other.example.invalid/path", "https://repo.example.invalid"); err == nil {
		t.Fatal("purge URL base validator accepted another target host")
	}
	if err := validateRealCloudPurgeURLBase("https://repo.example.invalid/path?secret=1", "https://repo.example.invalid"); err == nil {
		t.Fatal("purge URL base validator accepted a query-bearing URL")
	}
}

func TestRealCloudSnapshotRetentionAssertionContract(t *testing.T) {
	const recent = "el10-20260712"
	const expired = "el10-20251212"
	environment := realCloudEnvironment{CFCDNBase: "https://repo.example.invalid"}
	base := environment.CFCDNBase
	evidence := realCloudPublication{
		generation: publish.TargetGeneration{Target: publish.TargetCloudflare, Generation: 7, IntentView: "snapshot", IntentSnapshot: recent},
		checkpoint: publish.Checkpoint{Target: publish.TargetCloudflare, Generation: 7, IntentView: "snapshot", IntentSnapshot: recent, Phase: publish.PhaseCheckpointCommitted},
		plan: publish.Plan{
			Objects: []publish.PlannedObject{
				{RemoteKey: ".sow/snapshots/" + recent + ".json", Class: publish.ObjectPointer},
				{RemoteKey: ".sow/gated/snapshots/" + recent + "/yum/yum/real-cloud/x86_64/Packages/p/pkg.rpm", Class: publish.ObjectCopyImmutable, CopySource: "yum/real-cloud/x86_64/Packages/p/pkg.rpm"},
			},
			Verify: []publish.VerifyObject{{}, {}},
			Deletes: []publish.PlannedDelete{
				{Class: publish.DeleteSnapshotOwned, SourcePath: ".sow/snapshots/" + expired + ".json", RemoteKey: ".sow/snapshots/" + expired + ".json", Size: 1, SHA256: strings.Repeat("a", 64)},
				{Class: publish.DeleteSnapshotOwned, SourcePath: ".sow/gated/snapshots/" + expired + "/yum/yum/real-cloud/x86_64/Packages/p/pkg.rpm", RemoteKey: ".sow/gated/snapshots/" + expired + "/yum/yum/real-cloud/x86_64/Packages/p/pkg.rpm", Size: 1, SHA256: strings.Repeat("b", 64)},
			},
			Probes:       []publish.VerifyObject{{URL: base + "/retained"}},
			VerifyAbsent: []publish.VerifyAbsentObject{{URL: base + "/pro/v1/basic/_sow/v1/snapshots/" + expired + "/_route.json"}},
			PurgeURLs: []string{
				base + "/pro/v1/basic/_sow/v1/snapshots/" + recent + "/_route.json",
				base + "/.sow/snapshots/" + recent + ".json",
				base + "/pro/v1/basic/_sow/v1/snapshots/" + expired + "/_route.json",
				base + "/.sow/snapshots/" + expired + ".json",
			},
		},
	}
	if err := validateRealCloudSnapshotPublication(environment, evidence, publish.TargetCloudflare, 7, recent, expired); err != nil {
		t.Fatalf("valid snapshot retention assertion fixture rejected: %v", err)
	}
	firstSnapshot := evidence
	firstSnapshot.plan.Deletes = nil
	firstSnapshot.plan.VerifyAbsent = nil
	firstSnapshot.plan.PurgeURLs = append([]string(nil), evidence.plan.PurgeURLs[:2]...)
	if err := validateRealCloudSnapshotPublication(environment, firstSnapshot, publish.TargetCloudflare, 7, recent, ""); err != nil {
		t.Fatalf("valid first-snapshot exact current route pair rejected: %v", err)
	}
	firstSnapshot.plan.PurgeURLs = firstSnapshot.plan.PurgeURLs[:1]
	if err := validateRealCloudSnapshotPublication(environment, firstSnapshot, publish.TargetCloudflare, 7, recent, ""); err == nil || !strings.Contains(err.Error(), "purge") {
		t.Fatalf("first snapshot assertion accepted missing current clean purge: %v", err)
	}
	evidence.plan.Objects[1].CopySource = ""
	if err := validateRealCloudSnapshotPublication(environment, evidence, publish.TargetCloudflare, 7, recent, expired); err == nil || !strings.Contains(err.Error(), "copy") {
		t.Fatalf("snapshot assertion accepted uploaded package fallback: %v", err)
	}
	evidence.plan.Objects[1].CopySource = "yum/real-cloud/x86_64/Packages/p/pkg.rpm"
	evidence.plan.VerifyAbsent[0].URL = "https://other.example.invalid/pro/v1/basic/_sow/v1/snapshots/" + expired + "/_route.json"
	if err := validateRealCloudSnapshotPublication(environment, evidence, publish.TargetCloudflare, 7, recent, expired); err == nil || !strings.Contains(err.Error(), "absence") {
		t.Fatalf("snapshot assertion accepted wrong-target absence URL: %v", err)
	}
	evidence.plan.VerifyAbsent[0].URL = base + "/pro/v1/basic/_sow/v1/snapshots/" + expired + "/_route.json"
	validPurges := append([]string(nil), evidence.plan.PurgeURLs...)
	for _, test := range []struct {
		name   string
		purges []string
	}{
		{name: "missing-current-client", purges: append([]string(nil), validPurges[1:]...)},
		{name: "missing-current-clean", purges: append(append([]string(nil), validPurges[:1]...), validPurges[2:]...)},
		{name: "missing-expired-client", purges: append(append([]string(nil), validPurges[:2]...), validPurges[3:]...)},
		{name: "missing-expired-clean", purges: append([]string(nil), validPurges[:3]...)},
		{name: "extra", purges: append(append([]string(nil), validPurges...), base+"/.sow/snapshots/unplanned.json")},
		{name: "wrong-target", purges: []string{
			validPurges[0],
			validPurges[1],
			validPurges[2],
			"https://other.example.invalid/.sow/snapshots/" + expired + ".json",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence.plan.PurgeURLs = test.purges
			if err := validateRealCloudSnapshotPublication(environment, evidence, publish.TargetCloudflare, 7, recent, expired); err == nil || !strings.Contains(err.Error(), "purge") {
				t.Fatalf("snapshot assertion accepted invalid purge closure: %v", err)
			}
		})
	}
}

func TestRealCloudHistoricalSnapshotFixturePreservesCurrentRef(t *testing.T) {
	root := t.TempDir()
	current, err := views.SnapshotID("el10", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	historical, err := views.SnapshotID("el10", time.Now().UTC().AddDate(0, -7, 0))
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, config.StateDirectory))
	currentPath, _ := state.SnapshotPath(current, realCloudYUMRepositoryID, "el10", "x86_64")
	currentRef, _ := state.SnapshotRef(current, realCloudYUMRepositoryID, "el10", "x86_64")
	stage := filepath.Join(root, "current-snapshot.tsv")
	rpmPath := decodeBase64Fixture(t, filepath.Join(findModuleRoot(t), "internal", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "fixture.rpm"))
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	object, err := pool.Import(t.Context(), rpmPath)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := yumrepo.InspectCatalogPackage(t.Context(), yumrepo.PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	entry := views.Entry{
		Repo: realCloudYUMRepositoryID, OS: "el10", Arch: "x86_64", Name: pkg.Name,
		Version: pkg.DisplayVersion, Path: "yum/real-cloud/x86_64/" + pkg.Location,
		Size: object.Size, SHA256: object.HashString(), Pool: "public",
	}
	var body bytes.Buffer
	if err := views.WriteEntry(&body, entry); err != nil {
		t.Fatal(err)
	}
	writeFile(t, stage, body.Bytes(), 0o600)
	configPath := filepath.Join(root, "fixture-sow.yaml")
	writeFile(t, configPath, marshalRealCloudConfig(t, realCloudEnvironment{
		CFR2Endpoint: "https://test-account.r2.cloudflarestorage.com", CFR2Bucket: "sow-test-r2-fixture",
		CFCDNBase: "https://cf.test.example.invalid", CFBetaCDNBase: "https://cf-beta.test.example.invalid", CFZoneID: "test-zone",
		COSEndpoint: "https://cos.ap-shanghai.myqcloud.com", COSBucket: "sow-test-cos-fixture-1000000000", COSRegion: "ap-shanghai",
		COSCDNBase: "https://eo.test.example.invalid", COSBetaBase: "https://eo-beta.test.example.invalid", EdgeOneZoneID: "test-zone",
	}), 0o600)
	commit, changed, err := canonical.InstallPaths(map[string]string{currentPath: stage, "config/sow.yaml": configPath}, "test: current snapshot fixture")
	if err != nil || !changed {
		t.Fatalf("install current snapshot fixture changed=%v err=%v", changed, err)
	}
	if err := canonical.AdvanceRef(currentRef, plumbing.ZeroHash, commit, true); err != nil {
		t.Fatal(err)
	}
	if err := catalog.RebuildContext(t.Context(), filepath.Join(root, config.StateDirectory)); err != nil {
		t.Fatal(err)
	}
	seedRealCloudHistoricalSnapshot(t, root, current, historical)
	stillCurrent, exists, err := canonical.Ref(currentRef)
	if err != nil || !exists || stillCurrent != commit {
		t.Fatalf("historical fixture moved current ref got=%s want=%s exists=%v err=%v", stillCurrent, commit, exists, err)
	}
	historicalRef, _ := state.SnapshotRef(historical, realCloudYUMRepositoryID, "el10", "x86_64")
	historicalPath, _ := state.SnapshotPath(historical, realCloudYUMRepositoryID, "el10", "x86_64")
	historicalCommit, exists, err := canonical.Ref(historicalRef)
	if err != nil || !exists || historicalCommit == commit {
		t.Fatalf("historical fixture ref did not advance independently got=%s current=%s exists=%v err=%v", historicalCommit, commit, exists, err)
	}
	reader, err := canonical.OpenPathAt(historicalCommit, historicalPath)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, body.Bytes()) {
		t.Fatalf("historical fixture bytes=%q read_err=%v close_err=%v", got, readErr, closeErr)
	}
	for _, snapshotID := range []string{current, historical} {
		count, err := catalog.MembershipCount(t.Context(), filepath.Join(root, config.StateDirectory), catalog.Scope{Kind: "snapshot", Name: snapshotID, Repo: realCloudYUMRepositoryID, OS: "el10", Arch: "x86_64"})
		if err != nil || count != 1 {
			t.Fatalf("snapshot %s catalog memberships=%d err=%v", snapshotID, count, err)
		}
	}

	// Model SIGKILL after the immutable canonical ref commit but before the
	// promote command's catalog rebuild. The acceptance recovery path must not
	// synthesize a successful CLI receipt until this ref-only cache projection
	// has been rebuilt and bound to the new canonical HEAD.
	crashSnapshot, err := views.SnapshotID("el10", time.Now().UTC().AddDate(0, -8, 0))
	if err != nil {
		t.Fatal(err)
	}
	crashPath, _ := state.SnapshotPath(crashSnapshot, realCloudYUMRepositoryID, "el10", "x86_64")
	crashRef, _ := state.SnapshotRef(crashSnapshot, realCloudYUMRepositoryID, "el10", "x86_64")
	crashStage := filepath.Join(root, config.StateDirectory, "tmp", "crash-snapshot.tsv")
	if err := os.MkdirAll(filepath.Dir(crashStage), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, crashStage, body.Bytes(), 0o600)
	crashCommit, changed, err := canonical.Apply(t.Context(), "test-crash", "test: snapshot committed before catalog rebuild",
		map[string]string{crashPath: crashStage}, []state.RefUpdate{{Name: crashRef, Immutable: true}}, state.ApplyOptions{})
	if err != nil || !changed {
		t.Fatalf("commit simulated crash snapshot changed=%v err=%v", changed, err)
	}
	cacheHead, err := catalog.CanonicalHead(t.Context(), filepath.Join(root, config.StateDirectory))
	if err != nil || cacheHead == crashCommit {
		t.Fatalf("simulated crash did not leave an observably stale cache head=%s commit=%s err=%v", cacheHead, crashCommit, err)
	}
	count, err := catalog.MembershipCount(t.Context(), filepath.Join(root, config.StateDirectory), catalog.Scope{Kind: "snapshot", Name: crashSnapshot, Repo: realCloudYUMRepositoryID, OS: "el10", Arch: "x86_64"})
	if err != nil || count != 0 {
		t.Fatalf("simulated crash snapshot unexpectedly reached cache memberships=%d err=%v", count, err)
	}
	if err := recoverRealCloudSnapshotCanonicalMutation(t.Context(), root); err != nil {
		t.Fatalf("recover committed snapshot catalog window: %v", err)
	}
	cacheHead, err = catalog.CanonicalHead(t.Context(), filepath.Join(root, config.StateDirectory))
	if err != nil || cacheHead != crashCommit {
		t.Fatalf("recovered cache head=%s want=%s err=%v", cacheHead, crashCommit, err)
	}
	count, err = catalog.MembershipCount(t.Context(), filepath.Join(root, config.StateDirectory), catalog.Scope{Kind: "snapshot", Name: crashSnapshot, Repo: realCloudYUMRepositoryID, OS: "el10", Arch: "x86_64"})
	if err != nil || count != 1 {
		t.Fatalf("recovered crash snapshot memberships=%d err=%v", count, err)
	}
}

func TestRealCloudArtifactSecretScanIncludesHistoricalGitBlobs(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, config.StateDirectory, "state")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	repository, err := git.PlainInit(stateRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(stateRoot, "transient-secret.txt")
	const secret = "real-cloud-historical-secret-fixture"
	if err := os.WriteFile(secretPath, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add("transient-secret.txt"); err != nil {
		t.Fatal(err)
	}
	author := &gitobject.Signature{Name: "sow-test", Email: "sow-test@example.invalid", When: time.Unix(1, 0).UTC()}
	if _, err := worktree.Commit("transient secret regression fixture", &git.CommitOptions{Author: author}); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Remove("transient-secret.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Commit("remove transient fixture from HEAD", &git.CommitOptions{Author: author}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(secretPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("secret fixture remains in the worktree: %v", err)
	}
	if err := scanRealCloudSecretArtifacts(root, []string{secret}); err == nil || !strings.Contains(err.Error(), "canonical Git blob") {
		t.Fatalf("historical Git secret was not detected: %v", err)
	}
}

func TestRealCloudArtifactSecretScanCoversGitObjectSidecars(t *testing.T) {
	const secret = "real-cloud-git-object-sidecar-secret"
	t.Run("canonical-objects-info", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, config.StateDirectory, "state", ".git", "objects", "info", "leak")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := scanRealCloudSecretArtifacts(root, []string{secret}); err == nil || !strings.Contains(err.Error(), "exposed real-cloud secret material") {
			t.Fatalf("canonical objects/info sidecar secret was not rejected: %v", err)
		}
	})
	t.Run("nested-object-database", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "nested", ".git", "objects", "info", "leak")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := scanRealCloudSecretArtifacts(root, []string{secret}); err == nil || !strings.Contains(err.Error(), "nested Git object database") {
			t.Fatalf("nested Git object database was not rejected: %v", err)
		}
	})
}

func TestScanRealCloudRegularFileFindsBoundarySplitSecret(t *testing.T) {
	const secret = "boundary-split-secret-value"
	path := filepath.Join(t.TempDir(), "large-artifact")
	prefix := bytes.Repeat([]byte{'x'}, 64<<10-len(secret)/2)
	body := append(prefix, []byte(secret)...)
	body = append(body, bytes.Repeat([]byte{'y'}, 64<<10)...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	exposed, err := scanRealCloudRegularFile(path, []string{secret})
	if err != nil || !exposed {
		t.Fatalf("streaming scan missed a read-boundary secret exposed=%v err=%v", exposed, err)
	}
}

func TestRealCloudUnexpectedCLIExitStillScansPersistentArtifacts(t *testing.T) {
	root := t.TempDir()
	const secret = "real-cloud-unexpected-exit-secret-fixture"
	entry := func(_ []string, _, _ io.Writer) int {
		journal := filepath.Join(root, config.StateDirectory, "journal", "failed-command.json")
		if err := os.MkdirAll(filepath.Dir(journal), 0o700); err != nil {
			return cli.ExitInternal
		}
		if err := os.WriteFile(journal, []byte(secret), 0o600); err != nil {
			return cli.ExitInternal
		}
		return cli.ExitInternal
	}
	result, err := executeCheckedRealCloudCLI(entry, root, cli.ExitOK, []string{secret}, "publish", "--config", filepath.Join(root, "sow.yaml"))
	if result.code != cli.ExitInternal {
		t.Fatalf("unexpected fixture code=%d", result.code)
	}
	if err == nil || !strings.Contains(err.Error(), "artifact") || strings.Contains(err.Error(), secret) {
		t.Fatalf("persistent secret scan did not take precedence over exit mismatch: %v", err)
	}
}

func TestRealCloudSecretOutputIsNeverReturnedForLogging(t *testing.T) {
	root := t.TempDir()
	const secret = "real-cloud-output-secret-fixture"
	entry := func(_ []string, stdout, _ io.Writer) int {
		_, _ = io.WriteString(stdout, "prefix "+secret+" suffix")
		return cli.ExitInternal
	}
	result, err := executeCheckedRealCloudCLI(entry, root, cli.ExitOK, []string{secret}, "publish")
	if !errors.Is(err, errRealCloudOutputSecret) {
		t.Fatalf("secret output produced the wrong guard error: %v", err)
	}
	if len(result.output) != 0 || strings.Contains(err.Error(), secret) {
		t.Fatalf("secret-bearing output remained available to the logging path: output_bytes=%d err=%v", len(result.output), err)
	}
}

func TestRealCloudBasicUsernameIsSecretMaterial(t *testing.T) {
	t.Setenv(realCloudStorageCredentialCF, `{"access_key_id":"cf-access","secret_access_key":"cf-secret"}`)
	t.Setenv(realCloudCDNCredentialCF, `{"api_token":"cf-token","basic_username":"cf-private-user","basic_password":"cf-private-password"}`)
	t.Setenv(realCloudProviderLogStorageCredentialCF, `{"access_key_id":"cf-log-access","secret_access_key":"cf-log-secret"}`)
	t.Setenv(realCloudProviderLogWriterCredentialCF, `{"access_key_id":"cf-log-writer-access","secret_access_key":"`+strings.Join([]string{"cf", "log", "writer", "secret"}, "-")+`"}`)
	t.Setenv(realCloudStorageCredentialCOS, `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv(realCloudCDNCredentialCOS, `{"secret_id":"cos-id","secret_key":"cos-key","basic_username":"cos-private-user","basic_password":"cos-private-password"}`)
	t.Setenv(realCloudProviderLogStorageCredentialCOS, `{"access_key_id":"cos-log-access","secret_access_key":"cos-log-secret"}`)
	t.Setenv(realCloudProviderLogWriterCredentialCOS, `{"access_key_id":"cos-log-writer-access","secret_access_key":"`+strings.Join([]string{"cos", "log", "writer", "secret"}, "-")+`"}`)
	t.Setenv(realCloudEdgeProTokenAEnv, strings.Repeat("A", 22))
	t.Setenv(realCloudEdgeProTokenBEnv, strings.Repeat("B", 22))
	fragments := loadRealCloudSecretFragments(t)
	for _, username := range []string{"cf-private-user", "cos-private-user"} {
		found := false
		for _, fragment := range fragments {
			found = found || fragment == username
		}
		if !found {
			t.Fatalf("basic username was omitted from the secret-fragment set")
		}
		result, err := executeCheckedRealCloudCLI(func(_ []string, stdout, _ io.Writer) int {
			_, _ = io.WriteString(stdout, username)
			return cli.ExitOK
		}, t.TempDir(), cli.ExitOK, fragments, "verify")
		if !errors.Is(err, errRealCloudOutputSecret) || len(result.output) != 0 {
			t.Fatalf("basic username output did not fail closed: err=%v bytes=%d", err, len(result.output))
		}
	}
	for _, pair := range [][2]string{{"cf-private-user", "cf-private-password"}, {"cos-private-user", "cos-private-password"}} {
		encoded := base64.StdEncoding.EncodeToString([]byte(pair[0] + ":" + pair[1]))
		for _, exposed := range []string{encoded, "Basic " + encoded} {
			found := false
			for _, fragment := range fragments {
				found = found || fragment == exposed
			}
			if !found {
				t.Fatal("HTTP Basic credential encoding was omitted from the secret-fragment set")
			}
			result, err := executeCheckedRealCloudCLI(func(_ []string, stdout, _ io.Writer) int {
				_, _ = io.WriteString(stdout, exposed)
				return cli.ExitOK
			}, t.TempDir(), cli.ExitOK, fragments, "verify")
			if !errors.Is(err, errRealCloudOutputSecret) || len(result.output) != 0 {
				t.Fatalf("HTTP Basic credential output did not fail closed: err=%v bytes=%d", err, len(result.output))
			}
		}
	}
	for _, secret := range []string{"cf-log-access", "cf-log-secret", "cos-log-access", "cos-log-secret"} {
		found := false
		for _, fragment := range fragments {
			found = found || fragment == secret
		}
		if !found {
			t.Fatal("provider raw-log reader secret fragment was omitted")
		}
	}
}

type realCloudEnvironment struct {
	CFR2Endpoint  string
	CFR2Bucket    string
	CFCDNBase     string
	CFBetaCDNBase string
	CFZoneID      string
	COSEndpoint   string
	COSBucket     string
	COSRegion     string
	COSCDNBase    string
	COSBetaBase   string
	EdgeOneZoneID string
	EdgeProTokenA string
	EdgeProTokenB string
}

var realCloudEnvironmentNames = map[string]string{
	"CFR2Endpoint":  "SOW_REAL_CF_R2_ENDPOINT",
	"CFR2Bucket":    "SOW_REAL_CF_R2_BUCKET",
	"CFCDNBase":     "SOW_REAL_CF_CDN_BASE_URL",
	"CFBetaCDNBase": "SOW_REAL_CF_BETA_CDN_BASE_URL",
	"CFZoneID":      "SOW_REAL_CF_ZONE_ID",
	"COSEndpoint":   "SOW_REAL_COS_ENDPOINT",
	"COSBucket":     "SOW_REAL_COS_BUCKET",
	"COSRegion":     "SOW_REAL_COS_REGION",
	"COSCDNBase":    "SOW_REAL_COS_CDN_BASE_URL",
	"COSBetaBase":   "SOW_REAL_COS_BETA_CDN_BASE_URL",
	"EdgeOneZoneID": "SOW_REAL_EDGEONE_ZONE_ID",
}

func loadRealCloudEnvironment(t *testing.T) realCloudEnvironment {
	t.Helper()
	result, err := realCloudEnvironmentFromLookup(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	// Credential values are decoded later, after endpoint and destructive
	// confirmation validation. Their presence is nevertheless part of the
	// pre-network environment contract.
	for _, name := range []string{
		realCloudStorageCredentialCF, realCloudCDNCredentialCF, realCloudStorageCredentialCOS, realCloudCDNCredentialCOS,
		realCloudProviderLogStorageCredentialCF, realCloudProviderLogStorageCredentialCOS,
		realCloudProviderLogWriterCredentialCF, realCloudProviderLogWriterCredentialCOS,
	} {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			t.Fatalf("required real-cloud environment variable %s is empty", name)
		}
	}
	return result
}

func realCloudEnvironmentFromLookup(getenv func(string) string) (realCloudEnvironment, error) {
	get := func(name string) (string, error) {
		value := strings.TrimSpace(getenv(name))
		if value == "" {
			return "", fmt.Errorf("required real-cloud environment variable %s is empty", name)
		}
		return value, nil
	}
	values := make(map[string]string, len(realCloudEnvironmentNames)+2)
	for _, name := range []string{
		realCloudEnvironmentNames["CFR2Endpoint"], realCloudEnvironmentNames["CFR2Bucket"],
		realCloudEnvironmentNames["CFCDNBase"], realCloudEnvironmentNames["CFBetaCDNBase"], realCloudEnvironmentNames["CFZoneID"],
		realCloudEnvironmentNames["COSEndpoint"], realCloudEnvironmentNames["COSBucket"], realCloudEnvironmentNames["COSRegion"],
		realCloudEnvironmentNames["COSCDNBase"], realCloudEnvironmentNames["COSBetaBase"], realCloudEnvironmentNames["EdgeOneZoneID"],
		realCloudEdgeProTokenAEnv, realCloudEdgeProTokenBEnv,
	} {
		value, err := get(name)
		if err != nil {
			return realCloudEnvironment{}, err
		}
		values[name] = value
	}
	result := realCloudEnvironment{
		CFR2Endpoint:  values[realCloudEnvironmentNames["CFR2Endpoint"]],
		CFR2Bucket:    values[realCloudEnvironmentNames["CFR2Bucket"]],
		CFCDNBase:     values[realCloudEnvironmentNames["CFCDNBase"]],
		CFBetaCDNBase: values[realCloudEnvironmentNames["CFBetaCDNBase"]],
		CFZoneID:      values[realCloudEnvironmentNames["CFZoneID"]],
		COSEndpoint:   values[realCloudEnvironmentNames["COSEndpoint"]],
		COSBucket:     values[realCloudEnvironmentNames["COSBucket"]],
		COSRegion:     values[realCloudEnvironmentNames["COSRegion"]],
		COSCDNBase:    values[realCloudEnvironmentNames["COSCDNBase"]],
		COSBetaBase:   values[realCloudEnvironmentNames["COSBetaBase"]],
		EdgeOneZoneID: values[realCloudEnvironmentNames["EdgeOneZoneID"]],
		EdgeProTokenA: values[realCloudEdgeProTokenAEnv],
		EdgeProTokenB: values[realCloudEdgeProTokenBEnv],
	}
	for _, entitlement := range []struct {
		name  string
		value string
	}{{realCloudEdgeProTokenAEnv, result.EdgeProTokenA}, {realCloudEdgeProTokenBEnv, result.EdgeProTokenB}} {
		if !validRealCloudEdgeToken(entitlement.value) {
			return realCloudEnvironment{}, fmt.Errorf("%s must be a 22-256 character route-safe edge token", entitlement.name)
		}
	}
	if result.EdgeProTokenA == result.EdgeProTokenB {
		return realCloudEnvironment{}, fmt.Errorf("%s and %s must be distinct entitlements", realCloudEdgeProTokenAEnv, realCloudEdgeProTokenBEnv)
	}
	return result, nil
}

func realCloudConfirmation(environment realCloudEnvironment) string {
	return realCloudConfirmationPrefix +
		":R2=" + environment.CFR2Endpoint + "/" + environment.CFR2Bucket +
		";CF=" + environment.CFZoneID + "@" + environment.CFCDNBase + "," + environment.CFBetaCDNBase +
		";COS=" + environment.COSEndpoint + "/" + environment.COSBucket + "@" + environment.COSRegion +
		";EO=" + environment.EdgeOneZoneID + "@" + environment.COSCDNBase + "," + environment.COSBetaBase
}

func validateRealCloudVendorEndpoints(environment realCloudEnvironment) error {
	r2, err := url.Parse(environment.CFR2Endpoint)
	if err != nil {
		return fmt.Errorf("parse Cloudflare R2 endpoint: %w", err)
	}
	if r2.Scheme != "https" {
		return errors.New("Cloudflare R2 endpoint must use HTTPS")
	}
	r2Host := strings.ToLower(r2.Hostname())
	const r2Suffix = ".r2.cloudflarestorage.com"
	if !strings.HasSuffix(r2Host, r2Suffix) || strings.TrimSuffix(r2Host, r2Suffix) == "" {
		return fmt.Errorf("Cloudflare R2 endpoint host %q is outside the vendor service family", r2Host)
	}
	if r2.User != nil || r2.Port() != "" || r2.RawQuery != "" || r2.Fragment != "" || r2.Path != "" && r2.Path != "/" {
		return errors.New("Cloudflare R2 endpoint must be a credential-free service root")
	}
	cos, err := url.Parse(environment.COSEndpoint)
	if err != nil {
		return fmt.Errorf("parse Tencent COS endpoint: %w", err)
	}
	if cos.Scheme != "https" {
		return errors.New("Tencent COS endpoint must use HTTPS")
	}
	wantedCOSHost := "cos." + strings.ToLower(environment.COSRegion) + ".myqcloud.com"
	if strings.ToLower(cos.Hostname()) != wantedCOSHost {
		return fmt.Errorf("Tencent COS endpoint host must be %q for region %s", wantedCOSHost, environment.COSRegion)
	}
	if cos.User != nil || cos.Port() != "" || cos.RawQuery != "" || cos.Fragment != "" || cos.Path != "" && cos.Path != "/" {
		return errors.New("Tencent COS endpoint must be a credential-free service root")
	}
	return nil
}

type realCloudStorageSecret struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

type realCloudCloudflareSecret struct {
	APIToken      string `json:"api_token"`
	BasicUsername string `json:"basic_username,omitempty"`
	BasicPassword string `json:"basic_password,omitempty"`
}

type realCloudTencentSecret struct {
	SecretID      string `json:"secret_id"`
	SecretKey     string `json:"secret_key"`
	SessionToken  string `json:"session_token,omitempty"`
	BasicUsername string `json:"basic_username,omitempty"`
	BasicPassword string `json:"basic_password,omitempty"`
}

func decodeRealCloudSecret[T any](t *testing.T, name string) T {
	t.Helper()
	var result T
	decoder := json.NewDecoder(strings.NewReader(os.Getenv(name)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("%s does not satisfy the documented JSON schema", name)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("%s contains trailing JSON data", name)
	}
	return result
}

func realCloudBucketBaseURL(t *testing.T, endpoint, bucket string) string {
	t.Helper()
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" && parsed.Path != "/" {
		t.Fatal("real-cloud bucket endpoint is not a clean HTTPS service root")
	}
	parsed.Host = bucket + "." + parsed.Hostname()
	parsed.Path = ""
	return parsed.String()
}

func newRealCloudProviders(t *testing.T, environment realCloudEnvironment) (*publish.R2CloudflareHTTP, *publish.COSEdgeOneHTTP) {
	t.Helper()
	cfStorage := decodeRealCloudSecret[realCloudStorageSecret](t, realCloudStorageCredentialCF)
	cfCDN := decodeRealCloudSecret[realCloudCloudflareSecret](t, realCloudCDNCredentialCF)
	cosStorage := decodeRealCloudSecret[realCloudStorageSecret](t, realCloudStorageCredentialCOS)
	cosCDN := decodeRealCloudSecret[realCloudTencentSecret](t, realCloudCDNCredentialCOS)
	r2, err := publish.NewR2CloudflareHTTP(publish.R2CloudflareHTTPConfig{
		Bucket: environment.CFR2Bucket, ObjectBaseURL: realCloudBucketBaseURL(t, environment.CFR2Endpoint, environment.CFR2Bucket),
		CDNBaseURL: environment.CFCDNBase, ZoneID: environment.CFZoneID, APIToken: cfCDN.APIToken,
		Credentials: publish.S3Credentials{
			AccessKeyID: cfStorage.AccessKeyID, SecretAccessKey: cfStorage.SecretAccessKey, SessionToken: cfStorage.SessionToken, Region: "auto",
		},
	})
	if err != nil {
		t.Fatal("construct real R2 provider")
	}
	cos, err := publish.NewCOSEdgeOneHTTP(publish.COSEdgeOneHTTPConfig{
		Bucket: environment.COSBucket, ObjectBaseURL: realCloudBucketBaseURL(t, environment.COSEndpoint, environment.COSBucket), CDNBaseURL: environment.COSCDNBase,
		ObjectCredentials: publish.S3Credentials{
			AccessKeyID: cosStorage.AccessKeyID, SecretAccessKey: cosStorage.SecretAccessKey, SessionToken: cosStorage.SessionToken, Region: environment.COSRegion,
		},
		TencentCredentials: publish.TencentCredentials{SecretID: cosCDN.SecretID, SecretKey: cosCDN.SecretKey, Token: cosCDN.SessionToken},
		ZoneID:             environment.EdgeOneZoneID, UnversionedBucketConfirmed: true,
	})
	if err != nil {
		t.Fatal("construct real COS provider")
	}
	return r2, cos
}

func assertRealCloudProviderErrorSafe(t *testing.T, label string, err error, secretFragments []string) {
	t.Helper()
	if err == nil {
		return
	}
	assertNoRealCloudSecret(t, label, []byte(err.Error()), secretFragments)
}

// assertRealCloudCompetingCAS performs only non-mutating conflicting writes:
// R2 receives the currently committed checkpoint bytes with a deliberately
// wrong If-Match, while COS receives the existing generation-lock bytes under
// create-only semantics. Even a broken endpoint can at worst rewrite identical
// bytes; the assertions still require a conflict and byte/ETag stability.
func assertRealCloudCompetingCAS(t *testing.T, environment realCloudEnvironment, secretFragments []string, cf, cos realCloudPublication) {
	t.Helper()
	r2Provider, cosProvider := newRealCloudProviders(t, environment)
	cfBefore, err := r2Provider.R2GetControl(t.Context(), publish.CheckpointKey)
	assertRealCloudProviderErrorSafe(t, "R2 checkpoint CAS read", err, secretFragments)
	if err != nil || !cfBefore.Exists || !bytes.Equal(cfBefore.Body, cf.checkpointBody) || cfBefore.ETag == "" {
		t.Fatal("R2 checkpoint was unavailable for the competing CAS probe")
	}
	cfSHA := fmt.Sprintf("%x", sha256.Sum256(cfBefore.Body))
	_, err = r2Provider.R2Put(t.Context(), publish.CheckpointKey, bytes.NewReader(cfBefore.Body), int64(len(cfBefore.Body)), cfSHA,
		publish.R2PutCondition{IfMatch: `"sow-real-cloud-competing-checkpoint-etag"`})
	assertRealCloudProviderErrorSafe(t, "R2 checkpoint CAS conflict", err, secretFragments)
	if !errors.Is(err, publish.ErrConflict) {
		t.Fatalf("R2 competing checkpoint write returned %T, want publish.ErrConflict", err)
	}
	cfAfter, err := r2Provider.R2GetControl(t.Context(), publish.CheckpointKey)
	assertRealCloudProviderErrorSafe(t, "R2 checkpoint CAS read-back", err, secretFragments)
	if err != nil || !bytes.Equal(cfAfter.Body, cfBefore.Body) || cfAfter.ETag != cfBefore.ETag {
		t.Fatal("R2 competing checkpoint write changed the committed checkpoint")
	}

	if err := cosProvider.COSProbeUnversioned(t.Context()); err != nil {
		assertRealCloudProviderErrorSafe(t, "COS never-versioned CAS probe", err, secretFragments)
		t.Fatal("COS bucket no longer satisfies the never-versioned contract")
	}
	lockKey, err := publish.GenerationLockKey(cos.generation.Generation)
	if err != nil {
		t.Fatal(err)
	}
	cosBefore, err := cosProvider.COSGetControl(t.Context(), lockKey)
	assertRealCloudProviderErrorSafe(t, "COS generation-lock CAS read", err, secretFragments)
	if err != nil || !cosBefore.Exists || cosBefore.ETag == "" {
		t.Fatal("COS generation lock was unavailable for the competing CAS probe")
	}
	lock, err := publish.DecodeGenerationLock(cosBefore.Body)
	if err != nil || lock.Target != publish.TargetTencent || lock.Generation != cos.generation.Generation || lock.TransactionID != cos.checkpoint.TransactionID {
		t.Fatal("COS competing CAS probe did not bind the committed generation lock")
	}
	cosSHA := fmt.Sprintf("%x", sha256.Sum256(cosBefore.Body))
	_, err = cosProvider.COSCreate(t.Context(), lockKey, bytes.NewReader(cosBefore.Body), int64(len(cosBefore.Body)), cosSHA)
	assertRealCloudProviderErrorSafe(t, "COS generation-lock CAS conflict", err, secretFragments)
	if !errors.Is(err, publish.ErrConflict) && !errors.Is(err, publish.ErrAlreadyExists) {
		t.Fatalf("COS competing generation-lock create returned %T, want conflict", err)
	}
	cosAfter, err := cosProvider.COSGetControl(t.Context(), lockKey)
	assertRealCloudProviderErrorSafe(t, "COS generation-lock CAS read-back", err, secretFragments)
	if err != nil || !bytes.Equal(cosAfter.Body, cosBefore.Body) || cosAfter.ETag != cosBefore.ETag {
		t.Fatal("COS competing generation-lock create changed the existing lock")
	}
}

// assertRealCloudSnapshotCopyProvider closes the only ambiguity left by a
// snapshot plan's CopySource field: the real provider must accept an actual
// same-bucket server-side copy with the exact source ETag/size/digest. The
// destination is one run-bound deterministic SOW-owned probe key and is
// removed only after two complete HEAD-to-streamed-GET identity proofs. The
// provider primitive is unconditional because R2 does not provide conditional
// DeleteObject; this storage cleanup must not be confused with a Publisher
// checkpoint-fenced transaction.
func readRealCloudObjectIdentity(
	ctx context.Context,
	key string,
	maximumSize int64,
	head func(context.Context, string) (publish.ObjectInfo, error),
	open func(context.Context, string) (publish.ObjectContent, error),
) (publish.ObjectInfo, string, bool, error) {
	observed, err := head(ctx, key)
	if err != nil {
		return publish.ObjectInfo{}, "", false, err
	}
	if !observed.Exists {
		return publish.ObjectInfo{}, "", false, nil
	}
	if maximumSize < 0 || maximumSize > 1<<40 || observed.Size < 0 || observed.Size > maximumSize || observed.ETag == "" {
		return publish.ObjectInfo{}, "", false, errors.New("object HEAD exceeds the cleanup identity boundary")
	}
	content, err := open(ctx, key)
	if err != nil {
		return publish.ObjectInfo{}, "", false, err
	}
	if content.Body == nil {
		return publish.ObjectInfo{}, "", false, errors.New("object GET returned no body")
	}
	hasher := sha256.New()
	written, readErr := io.Copy(hasher, io.LimitReader(content.Body, maximumSize+1))
	closeErr := content.Body.Close()
	if readErr != nil || closeErr != nil {
		return publish.ObjectInfo{}, "", false, errors.Join(readErr, closeErr)
	}
	digest := fmt.Sprintf("%x", hasher.Sum(nil))
	if written != observed.Size || content.Info != observed || content.Info.ETag == "" ||
		observed.SHA256 != "" && observed.SHA256 != digest {
		return publish.ObjectInfo{}, "", false, errors.New("object changed between HEAD and streamed GET")
	}
	return observed, digest, true, nil
}

func cleanupRealCloudCopyProbe(
	ctx context.Context,
	key string,
	size int64,
	sha, copyETag string,
	head func(context.Context, string) (publish.ObjectInfo, error),
	open func(context.Context, string) (publish.ObjectContent, error),
	remove func(context.Context, string) error,
) error {
	first, firstSHA, exists, err := readRealCloudObjectIdentity(ctx, key, size, head, open)
	if err != nil {
		return fmt.Errorf("inspect copy probe before cleanup: %w", err)
	}
	if !exists {
		return nil
	}
	if first.Size != size || firstSHA != sha || first.SHA256 != "" && first.SHA256 != sha || copyETag != "" && first.ETag != copyETag {
		return errors.New("refuse to remove copy probe whose observed identity does not match the planned SOW object")
	}
	second, secondSHA, exists, err := readRealCloudObjectIdentity(ctx, key, size, head, open)
	if err != nil || !exists || second != first || secondSHA != firstSHA {
		return errors.Join(err, errors.New("refuse to remove copy probe that changed between consecutive identity proofs"))
	}
	removeErr := remove(ctx, key)
	after, headErr := head(ctx, key)
	if headErr != nil || after.Exists {
		return errors.Join(removeErr, headErr, errors.New("identity-bound copy-probe cleanup did not prove origin absence"))
	}
	return nil
}

func TestCleanupRealCloudCopyProbeUnknownResult(t *testing.T) {
	const key = ".sow/probes/server-side-copy/cf/accepted-response-lost"
	body := bytes.Repeat([]byte("a"), 42)
	sha := realCloudLowerSHA256(body)
	present := true
	deleted := false
	err := cleanupRealCloudCopyProbe(
		context.Background(), key, 42, sha, "",
		func(context.Context, string) (publish.ObjectInfo, error) {
			return publish.ObjectInfo{Exists: present, Size: 42, SHA256: sha, ETag: `"accepted-copy"`}, nil
		},
		func(context.Context, string) (publish.ObjectContent, error) {
			return publish.ObjectContent{Info: publish.ObjectInfo{Exists: present, Size: 42, SHA256: sha, ETag: `"accepted-copy"`}, Body: io.NopCloser(bytes.NewReader(body))}, nil
		},
		func(_ context.Context, gotKey string) error {
			if gotKey != key {
				t.Fatalf("cleanup key=%q want=%q", gotKey, key)
			}
			deleted = true
			present = false
			return nil
		},
	)
	if err != nil || !deleted {
		t.Fatalf("accepted-then-response-lost copy was not identity-bound cleaned deleted=%t err=%v", deleted, err)
	}
	deleted = false
	present = true
	err = cleanupRealCloudCopyProbe(
		context.Background(), key, 42, sha, "",
		func(context.Context, string) (publish.ObjectInfo, error) {
			return publish.ObjectInfo{Exists: true, Size: 43, SHA256: sha, ETag: `"foreign"`}, nil
		},
		func(context.Context, string) (publish.ObjectContent, error) {
			return publish.ObjectContent{}, errors.New("mismatched HEAD must reject before GET")
		},
		func(_ context.Context, _ string) error {
			deleted = true
			return nil
		},
	)
	if err == nil || deleted {
		t.Fatalf("mismatched unknown copy result was deleted=%t err=%v", deleted, err)
	}

	// Matching provider metadata is not deletion authority. A foreign writer
	// can preserve size/custom metadata while replacing the bytes, so cleanup
	// must stream and hash the body before invoking the unconditional primitive.
	deleted = false
	foreignBody := bytes.Repeat([]byte("b"), 42)
	err = cleanupRealCloudCopyProbe(
		context.Background(), key, 42, sha, "",
		func(context.Context, string) (publish.ObjectInfo, error) {
			return publish.ObjectInfo{Exists: true, Size: 42, SHA256: sha, ETag: `"forged-metadata"`}, nil
		},
		func(context.Context, string) (publish.ObjectContent, error) {
			return publish.ObjectContent{
				Info: publish.ObjectInfo{Exists: true, Size: 42, SHA256: sha, ETag: `"forged-metadata"`},
				Body: io.NopCloser(bytes.NewReader(foreignBody)),
			}, nil
		},
		func(_ context.Context, _ string) error {
			deleted = true
			return nil
		},
	)
	if err == nil || deleted {
		t.Fatalf("forged metadata with foreign body was deleted=%t err=%v", deleted, err)
	}

	// A provider may apply DELETE and lose the response. Proven origin absence
	// is the only safe success signal; the transport error alone is not.
	deleted = false
	present = true
	err = cleanupRealCloudCopyProbe(
		context.Background(), key, 42, sha, "",
		func(context.Context, string) (publish.ObjectInfo, error) {
			return publish.ObjectInfo{Exists: present, Size: 42, SHA256: sha, ETag: `"response-lost"`}, nil
		},
		func(context.Context, string) (publish.ObjectContent, error) {
			return publish.ObjectContent{
				Info: publish.ObjectInfo{Exists: present, Size: 42, SHA256: sha, ETag: `"response-lost"`},
				Body: io.NopCloser(bytes.NewReader(body)),
			}, nil
		},
		func(_ context.Context, _ string) error {
			deleted = true
			present = false
			return errors.New("simulated response loss after accepted DELETE")
		},
	)
	if err != nil || !deleted || present {
		t.Fatalf("response-lost cleanup did not converge deleted=%t present=%t err=%v", deleted, present, err)
	}
}

func assertRealCloudSnapshotCopyProvider(t *testing.T, environment realCloudEnvironment, secretFragments []string, target string, evidence realCloudPublication) {
	t.Helper()
	var planned publish.PlannedObject
	for _, object := range evidence.plan.Objects {
		if object.Class == publish.ObjectCopyImmutable && object.CopySource != "" {
			planned = object
			break
		}
	}
	if planned.RemoteKey == "" {
		t.Fatalf("target %s snapshot plan has no server-side copy candidate", target)
	}
	probeDigest := sha256.Sum256([]byte(target + "\x00" + evidence.checkpoint.TransactionID + "\x00" + evidence.generation.IntentSnapshot + "\x00" + planned.RemoteKey))
	probeKey := fmt.Sprintf(".sow/probes/server-side-copy/%s/%x", target, probeDigest)
	r2Provider, cosProvider := newRealCloudProviders(t, environment)
	if target == "cf" {
		source, err := r2Provider.R2Head(t.Context(), planned.CopySource)
		assertRealCloudProviderErrorSafe(t, "R2 snapshot copy source HEAD", err, secretFragments)
		if err != nil || !source.Exists || source.ETag == "" || source.Size != planned.Size || source.SHA256 != planned.SHA256 {
			t.Fatal("R2 snapshot copy source does not match the plan")
		}
		copyETag := ""
		cleanupPending := true
		t.Cleanup(func() {
			if !cleanupPending {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cleanupErr := cleanupRealCloudCopyProbe(ctx, probeKey, planned.Size, planned.SHA256, copyETag, r2Provider.R2Head, r2Provider.R2OpenObject, r2Provider.R2DeleteCheckpointFenced)
			assertRealCloudProviderErrorSafe(t, "R2 snapshot copy probe fail-safe cleanup", cleanupErr, secretFragments)
			if cleanupErr != nil {
				t.Errorf("R2 could not fail-safe remove its copied probe")
			}
		})
		copyETag, err = r2Provider.R2Copy(t.Context(), probeKey, planned.CopySource, planned.Size, planned.SHA256, source.ETag)
		assertRealCloudProviderErrorSafe(t, "R2 snapshot server-side copy", err, secretFragments)
		if err != nil || copyETag == "" {
			t.Fatal("R2 rejected the snapshot server-side copy contract")
		}
		copied, err := r2Provider.R2Head(t.Context(), probeKey)
		assertRealCloudProviderErrorSafe(t, "R2 snapshot copy destination HEAD", err, secretFragments)
		if err != nil || !copied.Exists || copied.ETag != copyETag || copied.Size != planned.Size || copied.SHA256 != planned.SHA256 {
			t.Fatal("R2 snapshot server-side copy failed integrity read-back")
		}
		if err := cleanupRealCloudCopyProbe(t.Context(), probeKey, planned.Size, planned.SHA256, copyETag, r2Provider.R2Head, r2Provider.R2OpenObject, r2Provider.R2DeleteCheckpointFenced); err != nil {
			assertRealCloudProviderErrorSafe(t, "R2 snapshot copy probe cleanup", err, secretFragments)
			t.Fatal("R2 could not checkpoint-fenced remove its SOW-owned copy probe")
		}
		cleanupPending = false
		removed, err := r2Provider.R2Head(t.Context(), probeKey)
		assertRealCloudProviderErrorSafe(t, "R2 snapshot copy probe absence HEAD", err, secretFragments)
		if err != nil || removed.Exists {
			t.Fatal("R2 snapshot copy probe remained after identity-bound cleanup")
		}
		return
	}
	if target != "cos" {
		t.Fatalf("unknown real-cloud snapshot copy target %q", target)
	}
	if err := cosProvider.COSProbeUnversioned(t.Context()); err != nil {
		assertRealCloudProviderErrorSafe(t, "COS snapshot copy never-versioned probe", err, secretFragments)
		t.Fatal("COS bucket no longer satisfies the never-versioned contract")
	}
	source, err := cosProvider.COSHead(t.Context(), planned.CopySource)
	assertRealCloudProviderErrorSafe(t, "COS snapshot copy source HEAD", err, secretFragments)
	if err != nil || !source.Exists || source.ETag == "" || source.Size != planned.Size || source.SHA256 != planned.SHA256 {
		t.Fatal("COS snapshot copy source does not match the plan")
	}
	copyETag := ""
	cleanupPending := true
	t.Cleanup(func() {
		if !cleanupPending {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cleanupErr := cleanupRealCloudCopyProbe(ctx, probeKey, planned.Size, planned.SHA256, copyETag, cosProvider.COSHead, cosProvider.COSOpenObject, cosProvider.COSDeleteCheckpointFenced)
		assertRealCloudProviderErrorSafe(t, "COS snapshot copy probe fail-safe cleanup", cleanupErr, secretFragments)
		if cleanupErr != nil {
			t.Errorf("COS could not fail-safe remove its copied probe")
		}
	})
	copyETag, err = cosProvider.COSCopy(t.Context(), probeKey, planned.CopySource, planned.Size, planned.SHA256, source.ETag)
	assertRealCloudProviderErrorSafe(t, "COS snapshot server-side copy", err, secretFragments)
	if err != nil || copyETag == "" {
		t.Fatal("COS rejected the snapshot server-side copy contract")
	}
	copied, err := cosProvider.COSHead(t.Context(), probeKey)
	assertRealCloudProviderErrorSafe(t, "COS snapshot copy destination HEAD", err, secretFragments)
	if err != nil || !copied.Exists || copied.ETag != copyETag || copied.Size != planned.Size || copied.SHA256 != planned.SHA256 {
		t.Fatal("COS snapshot server-side copy failed integrity read-back")
	}
	if err := cleanupRealCloudCopyProbe(t.Context(), probeKey, planned.Size, planned.SHA256, copyETag, cosProvider.COSHead, cosProvider.COSOpenObject, cosProvider.COSDeleteCheckpointFenced); err != nil {
		assertRealCloudProviderErrorSafe(t, "COS snapshot copy probe cleanup", err, secretFragments)
		t.Fatal("COS could not checkpoint-fenced remove its SOW-owned copy probe")
	}
	cleanupPending = false
	removed, err := cosProvider.COSHead(t.Context(), probeKey)
	assertRealCloudProviderErrorSafe(t, "COS snapshot copy probe absence HEAD", err, secretFragments)
	if err != nil || removed.Exists {
		t.Fatal("COS snapshot copy probe remained after identity-bound cleanup")
	}
}

func assertRealCloudDeletedObjectsAbsent(t *testing.T, environment realCloudEnvironment, secretFragments []string, target string, evidence realCloudPublication) {
	t.Helper()
	if len(evidence.plan.Deletes) == 0 {
		t.Fatalf("target %s has no deletion plan to verify", target)
	}
	probeID := sha256.Sum256([]byte(evidence.checkpoint.TransactionID))
	keys := make([]string, 0, len(evidence.plan.Deletes)+1)
	for _, deletion := range evidence.plan.Deletes {
		keys = append(keys, deletion.RemoteKey)
	}
	keys = append(keys, fmt.Sprintf(".sow/probes/conditional-delete/%x", probeID))
	r2Provider, cosProvider := newRealCloudProviders(t, environment)
	for _, key := range keys {
		var (
			info publish.ObjectInfo
			err  error
		)
		if target == "cf" {
			info, err = r2Provider.R2Head(t.Context(), key)
		} else if target == "cos" {
			info, err = cosProvider.COSHead(t.Context(), key)
		} else {
			t.Fatalf("unknown real-cloud deletion target %q", target)
		}
		assertRealCloudProviderErrorSafe(t, target+" deletion absence HEAD", err, secretFragments)
		if err != nil || info.Exists {
			t.Fatalf("target %s deletion/probe key remained after committed transaction: %s", target, key)
		}
	}
}

func readRealCloudCheckpoint(t *testing.T, environment realCloudEnvironment, secretFragments []string, target string) publish.Checkpoint {
	t.Helper()
	r2Provider, cosProvider := newRealCloudProviders(t, environment)
	var (
		control publish.ControlObject
		err     error
	)
	switch target {
	case "cf":
		control, err = r2Provider.R2GetControl(t.Context(), publish.CheckpointKey)
	case "cos":
		control, err = cosProvider.COSGetControl(t.Context(), publish.CheckpointKey)
	default:
		t.Fatalf("unknown interrupted real-cloud target %q", target)
	}
	assertRealCloudProviderErrorSafe(t, "read interrupted "+target+" checkpoint", err, secretFragments)
	if err != nil || !control.Exists {
		t.Fatalf("interrupted %s checkpoint is absent", target)
	}
	checkpoint, err := publish.DecodeCheckpoint(control.Body)
	if err != nil {
		t.Fatalf("interrupted %s checkpoint is not canonical", target)
	}
	return checkpoint
}

func assertRealCloudInterruptedRemotePointer(t *testing.T, environment realCloudEnvironment, secretFragments []string, target string, locked publish.Checkpoint, wantedPointerBody []byte) {
	t.Helper()
	generationKey, err := publish.GenerationKey(locked.Generation)
	if err != nil {
		t.Fatal(err)
	}
	r2Provider, cosProvider := newRealCloudProviders(t, environment)
	get := r2Provider.R2GetControl
	wantedTarget := publish.TargetCloudflare
	if target == "cos" {
		get = cosProvider.COSGetControl
		wantedTarget = publish.TargetTencent
	} else if target != "cf" {
		t.Fatalf("unknown interrupted real-cloud target %q", target)
	}
	control, err := get(t.Context(), generationKey)
	assertRealCloudProviderErrorSafe(t, "read interrupted "+target+" generation pointer", err, secretFragments)
	if err != nil || !control.Exists {
		t.Fatalf("interrupted %s generation pointer %s is absent", target, generationKey)
	}
	if err := validateRealCloudInterruptedRemotePointer(locked, control.Body, wantedTarget); err != nil {
		t.Fatalf("interrupted %s generation pointer is not bound to locked transaction %s: %v", target, locked.TransactionID, err)
	}
	pointerKey := ".sow/gated/" + realCloudGatedAssetPath
	pointer, err := get(t.Context(), pointerKey)
	assertRealCloudProviderErrorSafe(t, "read interrupted "+target+" flipped object", err, secretFragments)
	if err != nil || !pointer.Exists || pointer.ETag == "" {
		t.Fatalf("interrupted %s flipped object %s is absent or lacks an ETag", target, pointerKey)
	}
	if !bytes.Equal(pointer.Body, wantedPointerBody) {
		t.Fatalf("interrupted %s flipped object %s has digest=%x, want digest=%x", target, pointerKey, sha256.Sum256(pointer.Body), sha256.Sum256(wantedPointerBody))
	}
}

func validateRealCloudInterruptedRemotePointer(locked publish.Checkpoint, body []byte, target publish.TargetName) error {
	if locked.Target != target || locked.Phase != publish.PhaseLocked || locked.TransactionID == "" {
		return fmt.Errorf("interrupted checkpoint is not one locked %s transaction", target)
	}
	generation, err := publish.DecodeTargetGeneration(body)
	if err != nil {
		return fmt.Errorf("decode interrupted target generation: %w", err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(body))
	if digest != locked.GenerationSHA256 {
		return errors.New("remote generation bytes do not match the locked checkpoint digest")
	}
	if generation.Target != locked.Target || generation.Generation != locked.Generation || generation.ParentGeneration != locked.ParentGeneration ||
		generation.DesiredCommit != locked.DesiredCommit || generation.IntentView != locked.IntentView || generation.IntentSnapshot != locked.IntentSnapshot ||
		generation.ContentManifestSHA256 != locked.ContentManifestSHA256 {
		return errors.New("remote generation identity does not match the locked checkpoint")
	}
	return nil
}

type realCloudPublishJournalEvidence struct {
	Schema                   string             `json:"schema"`
	Target                   publish.TargetName `json:"target"`
	TransactionID            string             `json:"transaction_id"`
	Generation               uint64             `json:"generation"`
	PlanSHA256               string             `json:"plan_sha256"`
	CheckpointSHA256         string             `json:"checkpoint_sha256"`
	ExpectedGeneration       uint64             `json:"expected_generation"`
	ExpectedCheckpointSHA256 string             `json:"expected_checkpoint_sha256"`
	Phase                    publish.Phase      `json:"phase"`
	LockToken                string             `json:"lock_token"`
}

func assertRealCloudInterruptedJournal(t *testing.T, root, target string, locked publish.Checkpoint, committedParent realCloudPublication) {
	t.Helper()
	wantedTarget := publish.TargetCloudflare
	if target == "cos" {
		wantedTarget = publish.TargetTencent
	} else if target != "cf" {
		t.Fatalf("unknown interrupted real-cloud target %q", target)
	}
	filename := filepath.Join(root, config.StateDirectory, "publish-journal", target+"-"+locked.TransactionID+".json")
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("interrupted publish journal is absent or unsafe: %v", err)
	}
	body, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var journal realCloudPublishJournalEvidence
	if err := json.Unmarshal(body, &journal); err != nil {
		t.Fatal("interrupted publish journal is not valid JSON")
	}
	parentSHA := fmt.Sprintf("%x", sha256.Sum256(committedParent.checkpointBody))
	if journal.Schema != "sow-publish-journal/v1" || journal.Target != wantedTarget ||
		journal.TransactionID != locked.TransactionID || journal.Generation != locked.Generation ||
		journal.ExpectedGeneration != committedParent.generation.Generation || journal.ExpectedCheckpointSHA256 != parentSHA ||
		journal.Phase != publish.PhasePointerFlipped || journal.LockToken == "" ||
		len(journal.PlanSHA256) != 64 || len(journal.CheckpointSHA256) != 64 {
		t.Fatalf("interrupted journal does not bind pointer-flipped generation=%d transaction=%s to committed parent=%d",
			locked.Generation, locked.TransactionID, committedParent.generation.Generation)
	}
	purgePath := filepath.Join(root, config.StateDirectory, "publish-journal", target+"-"+locked.TransactionID+".purge.json")
	purgeEvidence, _, err := publish.LoadPurgeEvidenceFile(purgePath)
	if err != nil {
		t.Fatalf("interrupted purge evidence is absent or invalid: %v", err)
	}
	if purgeEvidence.Schema != publish.PurgeEvidenceSchema || purgeEvidence.Target != wantedTarget ||
		purgeEvidence.TransactionID != locked.TransactionID || purgeEvidence.Generation != locked.Generation ||
		purgeEvidence.GenerationSHA256 != locked.GenerationSHA256 || purgeEvidence.PlanSHA256 != journal.PlanSHA256 ||
		purgeEvidence.CheckpointSHA256 != journal.CheckpointSHA256 || purgeEvidence.URLCount == 0 ||
		len(purgeEvidence.Attempts) != 1 || len(purgeEvidence.Attempts[0].Batches) != 0 {
		t.Fatalf("interrupted purge sidecar does not retain one incomplete exact attempt: %#v", purgeEvidence)
	}
}

func realCloudInvalidCloudflareCDNCredential(t *testing.T, raw string) string {
	t.Helper()
	var credential realCloudCloudflareSecret
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credential); err != nil {
		t.Fatalf("%s does not satisfy the documented JSON schema", realCloudCDNCredentialCF)
	}
	credential.APIToken = realCloudInvalidCFToken
	body, err := json.Marshal(credential)
	if err != nil {
		t.Fatal("encode intentional Cloudflare failure credential")
	}
	return string(body)
}

func realCloudInvalidTencentCDNCredential(t *testing.T, raw string) string {
	t.Helper()
	var credential realCloudTencentSecret
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credential); err != nil {
		t.Fatalf("%s does not satisfy the documented JSON schema", realCloudCDNCredentialCOS)
	}
	credential.SecretID = realCloudInvalidTencentID
	credential.SecretKey = realCloudInvalidTencentKey
	body, err := json.Marshal(credential)
	if err != nil {
		t.Fatal("encode intentional EdgeOne failure credential")
	}
	return string(body)
}

type realCloudRuntimeSecretFile interface {
	io.Writer
	Name() string
	Chmod(fs.FileMode) error
	Stat() (fs.FileInfo, error)
	Seek(int64, int) (int64, error)
	Truncate(int64) error
	Sync() error
	Close() error
}

type realCloudRuntimeSecretIdentity struct {
	name string
	size int
	file realCloudRuntimeSecretFile
	info fs.FileInfo
}

// prepareRealCloudRuntimeSecretFile registers fail-closed cleanup immediately
// after CreateTemp has yielded a stable inode identity, before chmod or any
// secret bytes are written. The original descriptor remains open through the
// CLI run so cleanup can scrub that inode even if its path is replaced. Every
// subsequent setup failure runs cleanup eagerly and joins cleanup failures into
// the returned error. A failed eager cleanup remains armed for one testing.T
// teardown retry, so a transient remove failure cannot silently strand bytes.
func prepareRealCloudRuntimeSecretFile(
	value string,
	create func() (realCloudRuntimeSecretFile, error),
	registerCleanup func(func()),
	cleanup func(realCloudRuntimeSecretIdentity) error,
	reportCleanup func(error),
) (string, error) {
	file, err := create()
	if err != nil {
		return "", fmt.Errorf("create runtime Pro token file: %w", err)
	}
	name := file.Name()
	size := len(value) + 1
	info, err := file.Stat()
	if err != nil {
		closeErr := file.Close()
		return "", errors.Join(fmt.Errorf("stat runtime Pro token file: %w", err), closeErr)
	}
	identity := realCloudRuntimeSecretIdentity{name: name, size: size, file: file, info: info}
	cleanupComplete := false
	runCleanup := func() error {
		if cleanupComplete {
			return nil
		}
		cleanupErr := cleanup(identity)
		if cleanupErr == nil {
			cleanupComplete = true
		}
		return cleanupErr
	}
	registerCleanup(func() {
		if cleanupErr := runCleanup(); cleanupErr != nil {
			reportCleanup(cleanupErr)
		}
	})
	fail := func(stage string, operationErr error) (string, error) {
		cleanupErr := runCleanup()
		if cleanupErr != nil {
			cleanupErr = fmt.Errorf("cleanup after %s failure: %w", stage, cleanupErr)
		}
		return "", errors.Join(fmt.Errorf("%s runtime Pro token file: %w", stage, operationErr), cleanupErr)
	}
	if err := file.Chmod(0o600); err != nil {
		return fail("secure", err)
	}
	written, err := io.WriteString(file, value+"\n")
	if err == nil && written != size {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fail("write", err)
	}
	if err := file.Sync(); err != nil {
		return fail("sync", err)
	}
	return name, nil
}

func cleanupRealCloudRuntimeSecretFile(name string, size int) error {
	info, err := os.Lstat(name)
	if err != nil {
		return errors.Join(fmt.Errorf("open token file for scrub: %w", err), errors.New("remove token file: token path was not removed"))
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.Join(errors.New("open token file for scrub: unsafe token path"), errors.New("remove token file: unsafe token path was preserved"))
	}
	file, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		return errors.Join(fmt.Errorf("open token file for scrub: %w", err), fmt.Errorf("remove token file: token path was not removed"))
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return errors.Join(errors.New("open token file for scrub: token identity changed"), errors.New("remove token file: token path was not removed"))
	}
	return cleanupRealCloudRuntimeSecretHandle(realCloudRuntimeSecretIdentity{name: name, size: size, file: file, info: info})
}

// cleanupRealCloudRuntimeSecretHandle scrubs through the descriptor retained
// from CreateTemp. Even if the pathname is renamed or replaced, the original
// token inode is zeroed and truncated. Removal is attempted only when the
// pathname still names that exact inode, so a replacement symlink or regular
// file is never followed or deleted.
func cleanupRealCloudRuntimeSecretHandle(identity realCloudRuntimeSecretIdentity) error {
	var cleanupErr error
	if identity.file == nil || identity.info == nil || identity.name == "" || identity.size < 0 {
		return errors.New("runtime token cleanup identity is incomplete")
	}
	if _, err := identity.file.Seek(0, io.SeekStart); err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("seek token file for scrub: %w", err))
	} else {
		written, writeErr := identity.file.Write(make([]byte, identity.size))
		if writeErr != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("scrub token file: %w", writeErr))
		}
		if written != identity.size {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("short token scrub: wrote %d of %d bytes", written, identity.size))
		}
		if truncateErr := identity.file.Truncate(0); truncateErr != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("truncate token file after scrub: %w", truncateErr))
		}
		if syncErr := identity.file.Sync(); syncErr != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("sync token scrub: %w", syncErr))
		}
	}
	if closeErr := identity.file.Close(); closeErr != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("close token scrub: %w", closeErr))
	}
	current, statErr := os.Lstat(identity.name)
	pathRemoved := false
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		pathRemoved = true
	case statErr != nil:
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("inspect token path before remove: %w", statErr))
	case current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(identity.info, current):
		cleanupErr = errors.Join(cleanupErr, errors.New("token path identity changed before remove"))
	default:
		if removeErr := os.Remove(identity.name); removeErr != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove token file: %w", removeErr))
		} else {
			pathRemoved = true
		}
	}
	if pathRemoved {
		return cleanupErr
	}
	if _, statErr := os.Lstat(identity.name); !os.IsNotExist(statErr) {
		if statErr == nil {
			cleanupErr = errors.Join(cleanupErr, errors.New("token path remains after cleanup"))
		} else {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("verify token file absence: %w", statErr))
		}
	}
	return cleanupErr
}

func TestCleanupRealCloudRuntimeSecretFile(t *testing.T) {
	name := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(name, []byte("sensitive-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupRealCloudRuntimeSecretFile(name, len("sensitive-token\n")); err != nil {
		t.Fatalf("valid token cleanup failed: %v", err)
	}
	if _, err := os.Lstat(name); !os.IsNotExist(err) {
		t.Fatalf("token remains after successful cleanup: %v", err)
	}
}

func TestCleanupRealCloudRuntimeSecretFileReportsFailures(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-token")
	if err := cleanupRealCloudRuntimeSecretFile(missing, 16); err == nil || !strings.Contains(err.Error(), "open token file for scrub") || !strings.Contains(err.Error(), "remove token file") {
		t.Fatalf("missing token cleanup did not report scrub and removal failures: %v", err)
	}
	directory := filepath.Join(t.TempDir(), "token-directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cleanupRealCloudRuntimeSecretFile(directory, 16); err == nil || !strings.Contains(err.Error(), "open token file for scrub") {
		t.Fatalf("directory token cleanup did not report scrub failure: %v", err)
	}
	if info, err := os.Lstat(directory); err != nil || !info.IsDir() {
		t.Fatalf("directory cleanup did not preserve the unrelated unsafe path: %v", err)
	}
}

func TestCleanupRealCloudRuntimeSecretHandleRejectsPathReplacement(t *testing.T) {
	directory := t.TempDir()
	file, err := os.CreateTemp(directory, "token-*")
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("runtime-token-that-must-be-scrubbed\n")
	if _, err := file.Write(secret); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	name := file.Name()
	moved := name + ".moved"
	if err := os.Rename(name, moved); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(directory, "victim")
	wantedVictim := []byte("unrelated-victim-bytes\n")
	if err := os.WriteFile(victim, wantedVictim, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, name); err != nil {
		t.Fatal(err)
	}
	err = cleanupRealCloudRuntimeSecretHandle(realCloudRuntimeSecretIdentity{name: name, size: len(secret), file: file, info: info})
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("replacement token path was not reported: %v", err)
	}
	victimBody, readErr := os.ReadFile(victim)
	if readErr != nil || !bytes.Equal(victimBody, wantedVictim) {
		t.Fatalf("cleanup modified replacement symlink victim body=%q err=%v", victimBody, readErr)
	}
	movedInfo, statErr := os.Stat(moved)
	if statErr != nil {
		t.Fatalf("stat scrubbed original token: %v", statErr)
	}
	if movedInfo.Size() != 0 {
		t.Fatalf("retained descriptor did not scrub and truncate original token size=%d", movedInfo.Size())
	}
	if linkInfo, statErr := os.Lstat(name); statErr != nil || linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("cleanup removed or replaced the attacker-controlled path: %v", statErr)
	}
}

type faultRealCloudRuntimeSecretFile struct {
	name      string
	operation string
	events    *[]string
}

type faultRealCloudFileInfo struct{ name string }

func (info faultRealCloudFileInfo) Name() string  { return info.name }
func (faultRealCloudFileInfo) Size() int64        { return 0 }
func (faultRealCloudFileInfo) Mode() fs.FileMode  { return 0o600 }
func (faultRealCloudFileInfo) ModTime() time.Time { return time.Unix(1, 0).UTC() }
func (faultRealCloudFileInfo) IsDir() bool        { return false }
func (faultRealCloudFileInfo) Sys() any           { return nil }

func (file *faultRealCloudRuntimeSecretFile) Name() string {
	return file.name
}

func (file *faultRealCloudRuntimeSecretFile) Chmod(fs.FileMode) error {
	*file.events = append(*file.events, "chmod")
	if file.operation == "chmod" {
		return errors.New("chmod fault")
	}
	return nil
}

func (file *faultRealCloudRuntimeSecretFile) Stat() (fs.FileInfo, error) {
	*file.events = append(*file.events, "stat")
	return faultRealCloudFileInfo{name: filepath.Base(file.name)}, nil
}

func (file *faultRealCloudRuntimeSecretFile) Seek(offset int64, _ int) (int64, error) {
	*file.events = append(*file.events, "seek")
	return offset, nil
}

func (file *faultRealCloudRuntimeSecretFile) Truncate(int64) error {
	*file.events = append(*file.events, "truncate")
	return nil
}

func (file *faultRealCloudRuntimeSecretFile) Write(body []byte) (int, error) {
	*file.events = append(*file.events, "write")
	switch file.operation {
	case "write":
		return 0, errors.New("write fault")
	case "short-write":
		return len(body) - 1, nil
	default:
		return len(body), nil
	}
}

func (file *faultRealCloudRuntimeSecretFile) Sync() error {
	*file.events = append(*file.events, "sync")
	if file.operation == "sync" {
		return errors.New("sync fault")
	}
	return nil
}

func (file *faultRealCloudRuntimeSecretFile) Close() error {
	*file.events = append(*file.events, "close")
	if file.operation == "close" {
		return errors.New("close fault")
	}
	return nil
}

func TestPrepareRealCloudRuntimeSecretFileFailureCleanup(t *testing.T) {
	for _, test := range []struct {
		operation string
		wantError string
	}{
		{operation: "chmod", wantError: "chmod fault"},
		{operation: "write", wantError: "write fault"},
		{operation: "short-write", wantError: "short write"},
		{operation: "sync", wantError: "sync fault"},
	} {
		t.Run(test.operation, func(t *testing.T) {
			var events []string
			var registered func()
			var reported []error
			cleanupCalls := 0
			_, err := prepareRealCloudRuntimeSecretFile(
				"route-safe-token-value",
				func() (realCloudRuntimeSecretFile, error) {
					events = append(events, "create")
					return &faultRealCloudRuntimeSecretFile{name: "/outside/repository/token", operation: test.operation, events: &events}, nil
				},
				func(callback func()) {
					events = append(events, "register")
					registered = callback
				},
				func(identity realCloudRuntimeSecretIdentity) error {
					cleanupCalls++
					events = append(events, "cleanup")
					if identity.name != "/outside/repository/token" || identity.size != len("route-safe-token-value")+1 || identity.file == nil || identity.info == nil {
						t.Fatalf("cleanup identity name=%q size=%d", identity.name, identity.size)
					}
					return errors.New("cleanup fault")
				},
				func(err error) { reported = append(reported, err) },
			)
			if err == nil || !strings.Contains(err.Error(), test.wantError) || !strings.Contains(err.Error(), "cleanup fault") {
				t.Fatalf("operation and cleanup failures were not joined: %v", err)
			}
			if len(events) < 4 || strings.Join(events[:4], ",") != "create,stat,register,chmod" {
				t.Fatalf("cleanup was not registered immediately after creation: %v", events)
			}
			if registered == nil || cleanupCalls != 1 {
				t.Fatalf("registered=%v cleanup_calls=%d events=%v", registered != nil, cleanupCalls, events)
			}
			registered()
			if cleanupCalls != 2 || len(reported) != 1 || !strings.Contains(reported[0].Error(), "cleanup fault") {
				t.Fatalf("failed eager cleanup was not retried and reported calls=%d reports=%v", cleanupCalls, reported)
			}
		})
	}
}

func TestPrepareRealCloudRuntimeSecretFileTeardownCleanupFailure(t *testing.T) {
	var events []string
	var registered func()
	var reported []error
	cleanupCalls := 0
	name, err := prepareRealCloudRuntimeSecretFile(
		"route-safe-token-value",
		func() (realCloudRuntimeSecretFile, error) {
			events = append(events, "create")
			return &faultRealCloudRuntimeSecretFile{name: "/outside/repository/token", events: &events}, nil
		},
		func(callback func()) {
			events = append(events, "register")
			registered = callback
		},
		func(realCloudRuntimeSecretIdentity) error {
			cleanupCalls++
			return errors.New("teardown cleanup fault")
		},
		func(err error) { reported = append(reported, err) },
	)
	if err != nil || name != "/outside/repository/token" {
		t.Fatalf("valid runtime secret preparation failed name=%q err=%v", name, err)
	}
	if registered == nil || cleanupCalls != 0 || strings.Join(events[:4], ",") != "create,stat,register,chmod" {
		t.Fatalf("cleanup registration/setup events=%v calls=%d", events, cleanupCalls)
	}
	registered()
	if cleanupCalls != 1 || len(reported) != 1 || !strings.Contains(reported[0].Error(), "teardown cleanup fault") {
		t.Fatalf("teardown cleanup failure was not surfaced calls=%d reports=%v", cleanupCalls, reported)
	}
}

func assertRealCloudDynamicMirrorlists(t *testing.T, environment realCloudEnvironment, secretFragments []string, generation uint64) {
	t.Helper()
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, vendor := range []struct {
		name string
		base string
	}{{name: "cloudflare", base: environment.CFCDNBase}, {name: "edgeone", base: environment.COSCDNBase}} {
		mirrorPath := "_sow/v1/mirrorlist/stable/" + realCloudYUMRepositoryID + "/el10/x86_64.txt"
		anonymous := requestRealCloudEdge(t, client, vendor.name, strings.TrimSuffix(vendor.base, "/")+"/"+mirrorPath, http.MethodGet, "", nil, secretFragments)
		if anonymous.status != http.StatusNotFound || anonymous.edgeContract != "sow-edge-runtime/v1" {
			t.Fatalf("%s anonymous stable mirrorlist status=%d contract=%q, want edge 404", vendor.name, anonymous.status, anonymous.edgeContract)
		}
		for _, token := range []string{environment.EdgeProTokenA, environment.EdgeProTokenB} {
			rawURL := strings.TrimSuffix(vendor.base, "/") + "/pro/v1/" + token + "/" + mirrorPath
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
			if err != nil {
				t.Fatalf("%s dynamic mirrorlist request construction failed", vendor.name)
			}
			request.Header.Set("Accept-Encoding", "identity")
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("%s dynamic mirrorlist request failed", vendor.name)
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || len(body) > 64<<10 {
				t.Fatalf("%s dynamic mirrorlist response was not safely readable", vendor.name)
			}
			var headerEvidence strings.Builder
			for name, values := range response.Header {
				headerEvidence.WriteString(name)
				headerEvidence.WriteByte(':')
				headerEvidence.WriteString(strings.Join(values, ","))
				headerEvidence.WriteByte('\n')
			}
			assertNoRealCloudSecret(t, vendor.name+" dynamic mirrorlist headers", []byte(headerEvidence.String()), secretFragments)
			wanted := fmt.Sprintf("%s/pro/v1/%s/_sow/v1/g/%020d/yum/yum/real-cloud/x86_64/\n", strings.TrimSuffix(vendor.base, "/"), token, generation)
			if response.StatusCode != http.StatusOK || string(body) != wanted || response.Header.Get("X-SOW-Edge-Contract") != "sow-edge-runtime/v1" {
				t.Fatalf("%s dynamic mirrorlist contract status=%d body_bytes=%d", vendor.name, response.StatusCode, len(body))
			}
			cacheControl := strings.ToLower(response.Header.Get("Cache-Control"))
			if !strings.Contains(cacheControl, "private") || !strings.Contains(cacheControl, "no-store") || bytes.Count(body, []byte(token)) != 1 {
				t.Fatalf("%s dynamic mirrorlist did not preserve private one-token rendering", vendor.name)
			}
			scrubbed := bytes.ReplaceAll(append([]byte(nil), body...), []byte(token), []byte("<runtime-token>"))
			assertNoRealCloudSecret(t, vendor.name+" dynamic mirrorlist sanitized body", scrubbed, secretFragments)
		}
		t.Logf("%s dynamic stable mirrorlist generation=%020d entitlements=2", vendor.name, generation)
	}
}

// assertRealCloudGatedCachePhase is the live POC-06 cache gate. Unlike the
// public fallback exercised by local contract tests, this path exists only in
// .sow/gated. It requires a cache-transiting https-bearer deployment: direct R2
// binding and direct COS SigV4 transports intentionally report BYPASS and fail.
func assertRealCloudGatedCachePhase(t *testing.T, environment realCloudEnvironment, secretFragments []string, wanted []byte) {
	t.Helper()
	if !validRealCloudEdgeToken(environment.EdgeProTokenA) {
		t.Fatalf("%s must be a 22-256 character route-safe edge token", realCloudEdgeProTokenAEnv)
	}
	if !validRealCloudEdgeToken(environment.EdgeProTokenB) {
		t.Fatalf("%s must be a 22-256 character route-safe edge token", realCloudEdgeProTokenBEnv)
	}
	if environment.EdgeProTokenA == environment.EdgeProTokenB {
		t.Fatalf("%s and %s must be distinct", realCloudEdgeProTokenAEnv, realCloudEdgeProTokenBEnv)
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, vendor := range []struct {
		name string
		base string
	}{{name: "cloudflare", base: environment.CFCDNBase}, {name: "edgeone", base: environment.COSCDNBase}} {
		base, err := url.Parse(vendor.base)
		if err != nil || base.Scheme != "https" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Path != "" && base.Path != "/" {
			t.Fatalf("%s edge probe base URL is not a clean HTTPS origin", vendor.name)
		}
		canonicalCleanURL := *base
		canonicalCleanURL.Path = "/.sow/gated/" + realCloudGatedAssetPath
		canonicalCleanURL.RawPath = ""
		wantedCleanURLSHA256 := fmt.Sprintf("%x", sha256.Sum256([]byte(canonicalCleanURL.String())))
		for label, rawURL := range map[string]string{
			"public": strings.TrimSuffix(vendor.base, "/") + "/" + realCloudGatedAssetPath,
			"clean":  strings.TrimSuffix(vendor.base, "/") + "/.sow/gated/" + realCloudGatedAssetPath,
		} {
			anonymous := requestRealCloudEdge(t, client, vendor.name, rawURL, http.MethodGet, "", nil, secretFragments)
			if err := validateRealCloudAnonymousGatedResponse(anonymous, wanted); err != nil {
				t.Fatalf("%s anonymous %s gated path: %v", vendor.name, label, err)
			}
		}

		first := requestRealCloudEdge(t, client, vendor.name, realCloudTokenURL(vendor.base, environment.EdgeProTokenA), http.MethodGet, "", wanted, secretFragments)
		second := requestRealCloudEdge(t, client, vendor.name, realCloudTokenURL(vendor.base, environment.EdgeProTokenB), http.MethodGet, "", wanted, secretFragments)
		if first.transport != "https-bearer" || second.transport != "https-bearer" {
			t.Fatalf("%s cache POC used non-cache transport first=%q second=%q", vendor.name, first.transport, second.transport)
		}
		if err := validateRealCloudGatedCacheEvidence(first, wantedCleanURLSHA256, false); err != nil {
			t.Fatalf("%s first entitlement cache evidence: %v", vendor.name, err)
		}
		if err := validateRealCloudGatedCacheEvidence(second, wantedCleanURLSHA256, true); err != nil {
			t.Fatalf("%s second entitlement cache evidence: %v", vendor.name, err)
		}
		if first.etag != "" && second.etag != "" && first.etag != second.etag {
			t.Fatalf("%s distinct tokens returned different ETags", vendor.name)
		}

		head := requestRealCloudEdge(t, client, vendor.name, realCloudTokenURL(vendor.base, environment.EdgeProTokenA), http.MethodHead, "", []byte{}, secretFragments)
		ranged := requestRealCloudEdge(t, client, vendor.name, realCloudTokenURL(vendor.base, environment.EdgeProTokenB), http.MethodGet, "bytes=0-2", wanted[:3], secretFragments)
		if head.cleanURLSHA256 != first.cleanURLSHA256 {
			t.Fatalf("%s GET/HEAD/Range did not retain one clean URL identity", vendor.name)
		}
		if err := validateRealCloudGatedRangeEvidence(ranged, wantedCleanURLSHA256, len(wanted)); err != nil {
			t.Fatalf("%s gated Range evidence: %v", vendor.name, err)
		}
		// Re-check both anonymous aliases after the authenticated requests have
		// populated the shared clean cache.  This is the confidentiality-closure
		// assertion: cache warming must never make either the public path or the
		// internal clean path anonymously readable.
		for label, rawURL := range map[string]string{
			"public": strings.TrimSuffix(vendor.base, "/") + "/" + realCloudGatedAssetPath,
			"clean":  strings.TrimSuffix(vendor.base, "/") + "/.sow/gated/" + realCloudGatedAssetPath,
		} {
			anonymous := requestRealCloudEdge(t, client, vendor.name, rawURL, http.MethodGet, "", nil, secretFragments)
			if err := validateRealCloudAnonymousGatedResponse(anonymous, wanted); err != nil {
				t.Fatalf("%s post-warm anonymous %s gated path: %v", vendor.name, label, err)
			}
		}
		t.Logf("%s gated cache proof first=%s second=%s clean_url_sha256=%s etag=%s", vendor.name, first.cacheStatus, second.cacheStatus, first.cleanURLSHA256, first.etag)
	}
}

// assertRealCloudGatedVendorBody is the target-independent cache/read-back
// probe used while a staggered restore intentionally leaves the two vendors on
// different generations. Token B must hit the same clean cache identity that
// token A populated, so a stale purge or token-fragmented cache fails here.
func assertRealCloudGatedVendorBody(t *testing.T, vendor, baseURL string, environment realCloudEnvironment, secretFragments []string, wanted []byte) {
	t.Helper()
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		t.Fatalf("%s edge probe base URL is not a clean HTTPS origin", vendor)
	}
	cleanURL := *parsed
	cleanURL.Path = "/.sow/gated/" + realCloudGatedAssetPath
	wantedDigest := fmt.Sprintf("%x", sha256.Sum256([]byte(cleanURL.String())))
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	first := requestRealCloudEdge(t, client, vendor, realCloudTokenURL(baseURL, environment.EdgeProTokenA), http.MethodGet, "", wanted, secretFragments)
	second := requestRealCloudEdge(t, client, vendor, realCloudTokenURL(baseURL, environment.EdgeProTokenB), http.MethodGet, "", wanted, secretFragments)
	if first.transport != "https-bearer" || second.transport != "https-bearer" {
		t.Fatalf("%s staggered generation probe did not traverse the shared cache transport", vendor)
	}
	if err := validateRealCloudGatedCacheEvidence(first, wantedDigest, false); err != nil {
		t.Fatalf("%s staggered generation first-token cache evidence: %v", vendor, err)
	}
	if err := validateRealCloudGatedCacheEvidence(second, wantedDigest, true); err != nil {
		t.Fatalf("%s staggered generation second-token cache evidence: %v", vendor, err)
	}
	if first.etag != "" && second.etag != "" && first.etag != second.etag {
		t.Fatalf("%s staggered generation tokens returned different ETags", vendor)
	}
	t.Logf("%s staggered gated generation body_sha256=%x first=%s second=%s clean_url_sha256=%s", vendor, sha256.Sum256(wanted), first.cacheStatus, second.cacheStatus, wantedDigest)
}

type realCloudEdgeResponse struct {
	status         int
	edgeContract   string
	cacheStatus    string
	transport      string
	cleanURLSHA256 string
	etag           string
	contentRange   string
	body           []byte
	headers        http.Header
}

func mutateRealCloudEdgeResponse(source realCloudEdgeResponse, mutate func(*realCloudEdgeResponse)) realCloudEdgeResponse {
	result := source
	result.body = append([]byte(nil), source.body...)
	result.headers = source.headers.Clone()
	mutate(&result)
	return result
}

func realCloudTokenURL(base, token string) string {
	return strings.TrimSuffix(base, "/") + "/pro/v1/" + token + "/" + realCloudGatedAssetPath
}

func requestRealCloudEdge(t *testing.T, client *http.Client, vendor, rawURL, method, rangeHeader string, wanted []byte, secretFragments []string) realCloudEdgeResponse {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, rawURL, nil)
	if err != nil {
		t.Fatalf("%s edge probe request construction failed", vendor)
	}
	request.Header.Set("Accept-Encoding", "identity")
	if rangeHeader != "" {
		request.Header.Set("Range", rangeHeader)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s edge probe transport failed", vendor)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > 1<<20 {
		t.Fatalf("%s edge probe response was not safely readable", vendor)
	}
	var headerEvidence strings.Builder
	for name, values := range response.Header {
		headerEvidence.WriteString(name)
		headerEvidence.WriteByte(':')
		headerEvidence.WriteString(strings.Join(values, ","))
		headerEvidence.WriteByte('\n')
	}
	assertNoRealCloudSecret(t, vendor+" edge response headers", []byte(headerEvidence.String()), secretFragments)
	assertNoRealCloudSecret(t, vendor+" edge response body", body, secretFragments)
	if wanted != nil {
		wantStatus := http.StatusOK
		if rangeHeader != "" {
			wantStatus = http.StatusPartialContent
		}
		if response.StatusCode != wantStatus || !bytes.Equal(body, wanted) {
			t.Fatalf("%s edge probe method=%s range=%t status=%d body_bytes=%d", vendor, method, rangeHeader != "", response.StatusCode, len(body))
		}
		if response.Header.Get("X-SOW-Edge-Contract") != "sow-edge-runtime/v1" {
			t.Fatalf("%s edge probe did not traverse the versioned edge contract", vendor)
		}
		cacheControl := strings.ToLower(response.Header.Get("Cache-Control"))
		if !strings.Contains(cacheControl, "private") || !strings.Contains(cacheControl, "no-store") {
			t.Fatalf("%s edge probe did not preserve the private no-store client contract", vendor)
		}
		if response.Header.Get("Authorization") != "" || response.Header.Get("Proxy-Authorization") != "" {
			t.Fatalf("%s edge probe exposed origin authorization", vendor)
		}
	}
	return realCloudEdgeResponse{
		status: response.StatusCode, edgeContract: response.Header.Get("X-SOW-Edge-Contract"), cacheStatus: response.Header.Get("X-SOW-Origin-Cache-Status"),
		transport: response.Header.Get("X-SOW-Origin-Transport"), cleanURLSHA256: response.Header.Get("X-SOW-Clean-URL-SHA256"),
		etag: response.Header.Get("ETag"), contentRange: response.Header.Get("Content-Range"), body: append([]byte(nil), body...), headers: response.Header.Clone(),
	}
}

func validRealCloudEdgeToken(value string) bool {
	if len(value) < 22 || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validateRealCloudGatedCacheEvidence(response realCloudEdgeResponse, wantedCleanURLSHA256 string, requireHit bool) error {
	if !validRealCloudLowerSHA256(response.cleanURLSHA256) {
		return fmt.Errorf("clean URL digest %q is not 64 lowercase hexadecimal characters", response.cleanURLSHA256)
	}
	if response.cleanURLSHA256 != wantedCleanURLSHA256 {
		return errors.New("clean URL digest does not match the canonical gated origin URL")
	}
	if !validRealCloudSharedCacheStatus(response.cacheStatus) {
		return fmt.Errorf("cache status %q is not observable shared-cache evidence", response.cacheStatus)
	}
	if requireHit && response.cacheStatus != "HIT" {
		return fmt.Errorf("cache status=%s, want HIT", response.cacheStatus)
	}
	return nil
}

func validateRealCloudAnonymousGatedResponse(response realCloudEdgeResponse, wanted []byte) error {
	if response.status != http.StatusNotFound {
		return fmt.Errorf("anonymous gated response status=%d, want 404", response.status)
	}
	if response.edgeContract != "sow-edge-runtime/v1" {
		return fmt.Errorf("anonymous gated response edge contract=%q, want sow-edge-runtime/v1", response.edgeContract)
	}
	if !bytes.Equal(response.body, []byte("not_found\n")) {
		return errors.New("anonymous gated response body is not the constant denial envelope")
	}
	if response.headers.Get("Content-Type") != "text/plain; charset=utf-8" {
		return errors.New("anonymous gated response content type is not the constant denial envelope")
	}
	if response.headers.Get("Cache-Control") != "private, no-store, max-age=0" {
		return errors.New("anonymous gated response cache control is not the constant denial envelope")
	}
	if response.headers.Get("X-Content-Type-Options") != "nosniff" {
		return errors.New("anonymous gated response omitted nosniff")
	}
	if response.headers.Get("X-SOW-Edge-Contract") != "sow-edge-runtime/v1" {
		return errors.New("anonymous gated response header contract does not match the parsed contract")
	}
	for _, name := range []string{"Age", "Accept-Ranges", "Content-Digest", "Content-Location", "Content-MD5", "Content-Range", "Digest", "ETag", "Last-Modified", "X-Cache", "X-Cache-Hits", "X-Served-By"} {
		if response.headers.Get(name) != "" {
			return fmt.Errorf("anonymous gated response exposed forbidden metadata header %s", name)
		}
	}
	for name := range response.headers {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-sow-origin-") || lower == "x-sow-clean-url-sha256" || strings.HasPrefix(lower, "x-amz-") || strings.HasPrefix(lower, "x-cos-") {
			return fmt.Errorf("anonymous gated response exposed origin evidence header %s", name)
		}
	}
	if len(wanted) != 0 {
		wantedDigest := fmt.Sprintf("%x", sha256.Sum256(wanted))
		for name, values := range response.headers {
			joined := strings.Join(values, ",")
			if bytes.Contains(response.body, wanted) || strings.Contains(joined, string(wanted)) || strings.Contains(strings.ToLower(joined), wantedDigest) {
				return fmt.Errorf("anonymous gated response exposed protected bytes or digest in %s", name)
			}
		}
	}
	return nil
}

func validateRealCloudGatedRangeEvidence(response realCloudEdgeResponse, wantedCleanURLSHA256 string, total int) error {
	if response.status != http.StatusPartialContent {
		return fmt.Errorf("gated Range response status=%d, want 206", response.status)
	}
	if response.transport != "https-bearer" {
		return fmt.Errorf("gated Range transport=%q, want https-bearer", response.transport)
	}
	if err := validateRealCloudGatedCacheEvidence(response, wantedCleanURLSHA256, false); err != nil {
		return err
	}
	wantedContentRange := fmt.Sprintf("bytes 0-2/%d", total)
	if response.contentRange != wantedContentRange {
		return fmt.Errorf("gated Range Content-Range=%q, want %q", response.contentRange, wantedContentRange)
	}
	return nil
}

func validRealCloudLowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}

func validRealCloudSharedCacheStatus(value string) bool {
	switch value {
	case "HIT", "MISS", "EXPIRED", "STALE", "UPDATING", "REVALIDATED":
		return true
	default:
		return false
	}
}

func marshalRealCloudConfig(t *testing.T, environment realCloudEnvironment) []byte {
	t.Helper()
	body, err := realCloudConfigBodyForEnvironment(environment)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func realCloudConfigBodyForEnvironment(environment realCloudEnvironment) ([]byte, error) {
	return yaml.Marshal(realCloudConfigForEnvironment(environment))
}

func realCloudConfigForEnvironment(environment realCloudEnvironment) config.Config {
	return config.Config{
		Schema: config.Schema,
		// A deliberately wide APT by-hash window prevents unrelated index
		// cleanup. Snapshot retention remains six months so the harness can
		// deliberately exercise evidence-bound DELETE only inside one expired,
		// SOW-owned snapshot namespace.
		State: config.StateConfig{SnapshotMaterializationMonths: 6, APTByHashRetention: 100, CASHistoryCommits: 32},
		GPG: config.GPGConfig{
			PublicKey:  realCloudRepositoryPublicKey,
			PrivateKey: "env://" + realCloudPrivateSigningKeyEnv,
		},
		Pools: map[string]config.Pool{"public": {}, "gated": {}},
		Repos: []config.Repo{
			{
				ID: realCloudRepositoryID, Type: "apt", Path: "apt/real-cloud", DefaultPool: "public",
				Arches: []string{"amd64"},
				OS:     config.OSConfig{Family: "ubuntu", Major: 22, Suite: "jammy", Lifecycle: "active"},
				APT:    &config.APTConfig{Suites: []string{"jammy"}, Components: []string{"main"}},
			},
			{
				ID: realCloudYUMRepositoryID, Type: "yum", Path: "yum/real-cloud/x86_64", DefaultPool: "public",
				Arches: []string{"x86_64"},
				OS:     config.OSConfig{Family: "el", Major: 10, Lifecycle: "active"},
				YUM:    &config.YUMConfig{Compression: "zstd"},
			},
			{
				ID: realCloudAssetRepositoryID, Type: "asset", Path: "assets/real-cloud", DefaultPool: "public",
				Asset: &config.AssetConfig{Kind: "acceptance", MutablePaths: []string{"latest.txt"}},
			},
			{
				ID: realCloudGatedAssetRepoID, Type: "asset", Path: "assets/real-cloud-gated", DefaultPool: "gated",
				Asset: &config.AssetConfig{Kind: "acceptance-gated", MutablePaths: []string{"secret.txt"}},
			},
		},
		Upstreams: []config.Upstream{},
		Views: map[string]config.View{
			"beta":   {Access: "public", AllowedPools: []string{"public"}, Repos: []string{realCloudRepositoryID, realCloudYUMRepositoryID, realCloudAssetRepositoryID}},
			"latest": {Access: "public", AllowedPools: []string{"public"}, Repos: []string{realCloudRepositoryID, realCloudYUMRepositoryID, realCloudAssetRepositoryID}},
			"stable": {Access: "pro", AllowedPools: []string{"public", "gated"}, AppendOnly: true, Repos: []string{realCloudRepositoryID, realCloudYUMRepositoryID, realCloudAssetRepositoryID, realCloudGatedAssetRepoID}},
		},
		Serving: config.ServingConfig{
			Latest: config.ServingView{BaseURL: strings.TrimSuffix(environment.CFCDNBase, "/")},
			Beta:   config.ServingView{BaseURL: strings.TrimSuffix(environment.CFBetaCDNBase, "/")},
			Stable: config.ServingView{BaseURL: strings.TrimSuffix(environment.CFCDNBase, "/") + "/pro/v1/basic"},
		},
		Targets: map[string]config.Target{
			"cf": {
				Storage: config.Storage{Kind: "r2", Endpoint: environment.CFR2Endpoint, Bucket: environment.CFR2Bucket, Region: "auto", Credential: "env://" + realCloudStorageCredentialCF, DeleteMode: config.StorageDeleteCheckpointFenced},
				CDN:     config.CDN{Kind: "cloudflare", BaseURL: environment.CFCDNBase, BetaBaseURL: environment.CFBetaCDNBase, ZoneID: environment.CFZoneID, Credential: "env://" + realCloudCDNCredentialCF},
			},
			"cos": {
				Storage: config.Storage{Kind: "cos", Endpoint: environment.COSEndpoint, Bucket: environment.COSBucket, Region: environment.COSRegion, Credential: "env://" + realCloudStorageCredentialCOS, DeleteMode: config.StorageDeleteCheckpointFenced, UnversionedBucketConfirmed: true},
				CDN:     config.CDN{Kind: "edgeone", BaseURL: environment.COSCDNBase, BetaBaseURL: environment.COSBetaBase, Distribution: environment.EdgeOneZoneID, Credential: "env://" + realCloudCDNCredentialCOS},
			},
		},
		Edge: config.EdgeConfig{ProPrefix: config.DefaultProPrefix, TokenVerifier: "provider://pigsty-entitlements"},
	}
}

func realCloudSigningMaterial(t *testing.T) (private, public []byte) {
	t.Helper()
	created := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	keyConfig := &packet.Config{Time: func() time.Time { return created }, RSABits: 2048, DefaultHash: crypto.SHA256}
	entity, err := openpgp.NewEntity("SOW real-cloud acceptance", "", "real-cloud@example.invalid", keyConfig)
	if err != nil {
		t.Fatal(err)
	}
	var privateBuffer bytes.Buffer
	armored, err := armor.Encode(&privateBuffer, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(armored, keyConfig); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	var publicBuffer bytes.Buffer
	if err := entity.Serialize(&publicBuffer); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), privateBuffer.Bytes()...), append([]byte(nil), publicBuffer.Bytes()...)
}

type realCloudRunIdentity struct {
	Schema             string `json:"schema"`
	RunID              string `json:"run_id"`
	ConfirmationSHA256 string `json:"confirmation_sha256"`
	ConfigSHA256       string `json:"config_sha256"`
	PublicKeySHA256    string `json:"public_key_sha256"`
}

func realCloudRunIdentityFor(t *testing.T, environment realCloudEnvironment, configBody, publicKey []byte) realCloudRunIdentity {
	t.Helper()
	runID := strings.TrimSpace(os.Getenv(realCloudRunIDEnv))
	if !validRealCloudRunID(runID) {
		t.Fatalf("%s must be a 22-64 character route-safe nonsecret identifier", realCloudRunIDEnv)
	}
	confirmationDigest := sha256.Sum256([]byte(realCloudConfirmation(environment)))
	configDigest := sha256.Sum256(configBody)
	publicKeyDigest := sha256.Sum256(publicKey)
	return realCloudRunIdentity{
		Schema: "sow-real-cloud-run/v1", RunID: runID,
		ConfirmationSHA256: fmt.Sprintf("%x", confirmationDigest),
		ConfigSHA256:       fmt.Sprintf("%x", configDigest),
		PublicKeySHA256:    fmt.Sprintf("%x", publicKeyDigest),
	}
}

func validRealCloudRunID(value string) bool {
	if len(value) < 22 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func realCloudPublicSigningMaterial(t *testing.T, private []byte) []byte {
	t.Helper()
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(private))
	if err != nil || len(entities) != 1 || entities[0] == nil || entities[0].PrivateKey == nil || entities[0].PrivateKey.Encrypted {
		t.Fatal("persistent real-cloud signing key must be one unencrypted armored OpenPGP private identity")
	}
	for _, subkey := range entities[0].Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			t.Fatal("persistent real-cloud signing key contains an encrypted private subkey")
		}
	}
	var public bytes.Buffer
	if err := entities[0].Serialize(&public); err != nil {
		t.Fatal("serialize persistent real-cloud signing public identity")
	}
	return append([]byte(nil), public.Bytes()...)
}

func prepareRealCloudPersistentWorkspace(t *testing.T, mode string, identity realCloudRunIdentity) string {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv(realCloudWorkspaceEnv))
	if raw == "" || !filepath.IsAbs(raw) || filepath.Clean(raw) != raw || strings.ContainsRune(raw, '\x00') {
		t.Fatalf("%s must be an absolute clean path", realCloudWorkspaceEnv)
	}
	rawParent := filepath.Dir(raw)
	parentInfo, err := os.Lstat(rawParent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("%s parent must be an existing non-symlink directory", realCloudWorkspaceEnv)
	}
	canonicalParent, err := filepath.EvalSymlinks(rawParent)
	if err != nil {
		t.Fatalf("resolve %s parent: %v", realCloudWorkspaceEnv, err)
	}
	canonicalRoot := filepath.Join(canonicalParent, filepath.Base(raw))
	repositoryRoot, err := filepath.EvalSymlinks(findModuleRoot(t))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	relative, err := filepath.Rel(repositoryRoot, canonicalRoot)
	if err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("%s must resolve outside the repository", realCloudWorkspaceEnv)
	}
	identityPath := filepath.Join(canonicalRoot, realCloudRunIdentityFilename)
	switch mode {
	case "fresh":
		if _, err := os.Lstat(canonicalRoot); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("fresh %s must not already exist: %v", realCloudWorkspaceEnv, err)
		}
		if err := os.Mkdir(canonicalRoot, 0o700); err != nil {
			t.Fatalf("create persistent real-cloud workspace: %v", err)
		}
		writeRealCloudExclusiveJSON(t, identityPath, identity)
	case "recover":
		info, err := os.Lstat(canonicalRoot)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("recover %s must be a private non-symlink directory: %v", realCloudWorkspaceEnv, err)
		}
		var persisted realCloudRunIdentity
		readRealCloudStrictJSON(t, identityPath, &persisted)
		if persisted != identity {
			t.Fatal("persistent real-cloud workspace identity does not match run/resources/config/signing key")
		}
	default:
		t.Fatalf("%s must be fresh or recover", realCloudModeEnv)
	}
	return canonicalRoot
}

func writeRealCloudExclusiveJSON(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("encode persistent real-cloud metadata")
	}
	body = append(body, '\n')
	installed, err := installRealCloudPrivateFileExclusiveWithPattern(path, body, ".sow-real-cloud-metadata-*")
	if err != nil {
		t.Fatalf("atomically install persistent real-cloud metadata: %v", err)
	}
	if !installed {
		t.Fatal("persistent real-cloud metadata already exists")
	}
}

func readRealCloudStrictJSON(t *testing.T, path string, value any) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 64<<10 {
		t.Fatalf("persistent real-cloud metadata is absent or unsafe: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persistent real-cloud metadata: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		t.Fatalf("decode persistent real-cloud metadata: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatal("persistent real-cloud metadata contains trailing values")
	}
}

func syncRealCloudDirectory(t *testing.T, path string) {
	t.Helper()
	directory, err := os.Open(path)
	if err != nil {
		t.Fatalf("open persistent real-cloud directory for sync: %v", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		t.Fatalf("sync persistent real-cloud directory: %v", err)
	}
}

func loadRealCloudSecretFragments(t *testing.T) []string {
	t.Helper()
	var fragments []string
	for _, name := range []string{
		realCloudStorageCredentialCF, realCloudCDNCredentialCF, realCloudProviderLogStorageCredentialCF, realCloudProviderLogWriterCredentialCF,
		realCloudStorageCredentialCOS, realCloudCDNCredentialCOS, realCloudProviderLogStorageCredentialCOS, realCloudProviderLogWriterCredentialCOS,
	} {
		raw := os.Getenv(name)
		var document map[string]any
		if err := json.Unmarshal([]byte(raw), &document); err != nil {
			t.Fatalf("%s must contain valid JSON", name)
		}
		fragments = append(fragments, raw)
		for _, field := range []string{"access_key_id", "secret_access_key", "session_token", "api_token", "secret_id", "secret_key", "basic_username", "basic_password"} {
			if value, ok := document[field].(string); ok && value != "" {
				fragments = append(fragments, value)
			}
		}
		username, usernameOK := document["basic_username"].(string)
		password, passwordOK := document["basic_password"].(string)
		if usernameOK && passwordOK && username != "" && password != "" {
			encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
			fragments = append(fragments, encoded, "Basic "+encoded)
		}
	}
	for _, name := range []string{realCloudEdgeProTokenAEnv, realCloudEdgeProTokenBEnv} {
		if token := os.Getenv(name); token != "" {
			fragments = append(fragments, token)
		}
	}
	sort.Strings(fragments)
	return fragments
}

func realCloudPrivateKeySecretFragments(privateKey []byte) []string {
	fragments := []string{string(privateKey), "-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----"}
	for _, line := range strings.Split(string(privateKey), "\n") {
		line = strings.TrimSpace(line)
		// Armor headers are caught above. Retaining every substantial base64
		// body line catches partial private-key logging without ever printing
		// the matched fragment in a failure message.
		if len(line) >= 16 && !strings.Contains(line, ":") && !strings.HasPrefix(line, "-----") {
			fragments = append(fragments, line)
		}
	}
	return fragments
}

func assertNoRealCloudSecret(t *testing.T, label string, body []byte, fragments []string) {
	t.Helper()
	if containsRealCloudSecret(body, fragments) {
		t.Fatalf("%s exposed real-cloud secret material", label)
	}
}

func containsRealCloudSecret(body []byte, fragments []string) bool {
	for _, fragment := range fragments {
		if fragment != "" && bytes.Contains(body, []byte(fragment)) {
			return true
		}
	}
	return false
}

func scanRealCloudSecretArtifacts(root string, fragments []string) error {
	const maximumArtifactSize = 16 << 20
	canonicalObjectDirectory := filepath.Clean(filepath.Join(root, config.StateDirectory, "state", ".git", "objects"))
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if containsRealCloudSecret([]byte(relative), fragments) {
			return fmt.Errorf("artifact path exposed real-cloud secret material")
		}
		if entry.IsDir() {
			if filepath.Base(current) == "objects" && filepath.Base(filepath.Dir(current)) == ".git" && filepath.Clean(current) != canonicalObjectDirectory {
				return fmt.Errorf("refuse unverified nested Git object database %s", relative)
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refuse secret scan through symlink artifact %s", relative)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refuse unscannable non-regular artifact %s", relative)
		}
		exposed, err := scanRealCloudRegularFile(current, fragments)
		if err != nil {
			return err
		}
		if exposed {
			return fmt.Errorf("artifact %s exposed real-cloud secret material", relative)
		}
		return nil
	})
	if err != nil {
		return err
	}
	stateRepository := filepath.Join(root, config.StateDirectory, "state")
	repository, err := git.PlainOpen(stateRepository)
	if errors.Is(err, git.ErrRepositoryNotExists) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open canonical Git state for secret scan: %w", err)
	}
	blobs, err := repository.BlobObjects()
	if err != nil {
		return fmt.Errorf("enumerate canonical Git blobs for secret scan: %w", err)
	}
	defer blobs.Close()
	if err := blobs.ForEach(func(blob *gitobject.Blob) error {
		if blob.Size > maximumArtifactSize {
			return fmt.Errorf("canonical Git blob %s is %d bytes, above bounded secret-scan limit %d", blob.Hash, blob.Size, maximumArtifactSize)
		}
		reader, err := blob.Reader()
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(reader, maximumArtifactSize+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		for _, fragment := range fragments {
			if fragment != "" && bytes.Contains(body, []byte(fragment)) {
				return fmt.Errorf("canonical Git blob %s exposed real-cloud secret material", blob.Hash)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	references, err := repository.References()
	if err != nil {
		return fmt.Errorf("enumerate canonical Git refs for secret scan: %w", err)
	}
	defer references.Close()
	if err := references.ForEach(func(reference *plumbing.Reference) error {
		if containsRealCloudSecret([]byte(reference.Name().String()), fragments) {
			return errors.New("canonical Git ref name exposed real-cloud secret material")
		}
		return nil
	}); err != nil {
		return err
	}
	commits, err := repository.CommitObjects()
	if err != nil {
		return fmt.Errorf("enumerate canonical Git commits for secret scan: %w", err)
	}
	defer commits.Close()
	if err := commits.ForEach(func(commit *gitobject.Commit) error {
		identity := commit.Message + "\x00" + commit.Author.Name + "\x00" + commit.Author.Email + "\x00" + commit.Committer.Name + "\x00" + commit.Committer.Email
		if containsRealCloudSecret([]byte(identity), fragments) {
			return fmt.Errorf("canonical Git commit %s metadata exposed real-cloud secret material", commit.Hash)
		}
		return nil
	}); err != nil {
		return err
	}
	trees, err := repository.TreeObjects()
	if err != nil {
		return fmt.Errorf("enumerate canonical Git trees for secret scan: %w", err)
	}
	defer trees.Close()
	if err := trees.ForEach(func(tree *gitobject.Tree) error {
		for _, entry := range tree.Entries {
			if containsRealCloudSecret([]byte(entry.Name), fragments) {
				return fmt.Errorf("canonical Git tree %s entry name exposed real-cloud secret material", tree.Hash)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	tags, err := repository.TagObjects()
	if err != nil {
		return fmt.Errorf("enumerate canonical Git tags for secret scan: %w", err)
	}
	defer tags.Close()
	if err := tags.ForEach(func(tag *gitobject.Tag) error {
		identity := tag.Name + "\x00" + tag.Message + "\x00" + tag.Tagger.Name + "\x00" + tag.Tagger.Email
		if containsRealCloudSecret([]byte(identity), fragments) {
			return fmt.Errorf("canonical Git tag %s metadata exposed real-cloud secret material", tag.Hash)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// scanRealCloudRegularFile keeps the persistent-artifact scan streaming, so
// large package payloads and Git packs do not create either a memory spike or
// a size-based blind spot. The overlap preserves matches split across reads.
func scanRealCloudRegularFile(path string, fragments []string) (bool, error) {
	maximumFragment := 0
	for _, fragment := range fragments {
		if len(fragment) > maximumFragment {
			maximumFragment = len(fragment)
		}
	}
	if maximumFragment == 0 {
		return false, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	buffer := make([]byte, 64<<10)
	tail := make([]byte, 0, maximumFragment-1)
	for {
		read, readErr := file.Read(buffer)
		if read > 0 {
			window := make([]byte, 0, len(tail)+read)
			window = append(window, tail...)
			window = append(window, buffer[:read]...)
			if containsRealCloudSecret(window, fragments) {
				return true, nil
			}
			keep := maximumFragment - 1
			if keep > len(window) {
				keep = len(window)
			}
			tail = append(tail[:0], window[len(window)-keep:]...)
		}
		if errors.Is(readErr, io.EOF) {
			return false, nil
		}
		if readErr != nil {
			return false, readErr
		}
	}
}

type realCloudCLIResult struct {
	code    int
	output  []byte
	elapsed time.Duration
}

func executeCheckedRealCloudCLI(entry func([]string, io.Writer, io.Writer) int, root string, expectedCode int, fragments []string, arguments ...string) (realCloudCLIResult, error) {
	var stdout, stderr bytes.Buffer
	started := time.Now()
	code := entry(arguments, &stdout, &stderr)
	combined := append(append([]byte(nil), stdout.Bytes()...), stderr.Bytes()...)
	result := realCloudCLIResult{code: code, output: combined, elapsed: time.Since(started)}
	artifactErr := scanRealCloudSecretArtifacts(root, fragments)
	if containsRealCloudSecret(combined, fragments) {
		for index := range combined {
			combined[index] = 0
		}
		stdout.Reset()
		stderr.Reset()
		result.output = nil
		return result, errRealCloudOutputSecret
	}
	if artifactErr != nil {
		return result, fmt.Errorf("persistent artifact acceptance scan: %w", artifactErr)
	}
	if code != expectedCode {
		return result, fmt.Errorf("exit=%d want=%d", code, expectedCode)
	}
	return result, nil
}

type realCloudPublication struct {
	generation        publish.TargetGeneration
	checkpoint        publish.Checkpoint
	plan              publish.Plan
	purgeEvidence     publish.PurgeEvidence
	generationBody    []byte
	checkpointBody    []byte
	planBody          []byte
	purgeEvidenceBody []byte
}

func readRealCloudPublication(t *testing.T, root, target string) realCloudPublication {
	t.Helper()
	directory := filepath.Join(root, config.StateDirectory, "state", "remotes", target)
	read := func(name string) []byte {
		body, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatalf("read canonical %s/%s: %v", target, name, err)
		}
		return body
	}
	result := realCloudPublication{
		generationBody: read("generation.json"),
		checkpointBody: read("checkpoint.json"),
		planBody:       read("plan.json"),
	}
	var err error
	if result.generation, err = publish.DecodeTargetGeneration(result.generationBody); err != nil {
		t.Fatalf("decode canonical %s generation: %v", target, err)
	}
	if result.checkpoint, err = publish.DecodeCheckpoint(result.checkpointBody); err != nil {
		t.Fatalf("decode canonical %s checkpoint: %v", target, err)
	}
	if result.plan, err = publish.DecodePlan(result.planBody); err != nil {
		t.Fatalf("decode canonical %s plan: %v", target, err)
	}
	purgeName := filepath.Join("purges", fmt.Sprintf("%020d-%s.json", result.checkpoint.Generation, result.checkpoint.TransactionID))
	result.purgeEvidenceBody = read(purgeName)
	if result.purgeEvidence, err = publish.DecodePurgeEvidence(result.purgeEvidenceBody); err != nil {
		t.Fatalf("decode canonical %s purge evidence: %v", target, err)
	}
	expectedZone := strings.TrimSpace(os.Getenv(realCloudEnvironmentNames["CFZoneID"]))
	if target == string(publish.TargetTencent) {
		expectedZone = strings.TrimSpace(os.Getenv(realCloudEnvironmentNames["EdgeOneZoneID"]))
	}
	if expectedZone == "" {
		t.Fatalf("canonical %s purge evidence has no confirmation-bound expected zone", target)
	}
	assertRealCloudPurgeEvidenceBinding(t, target, expectedZone, result)
	return result
}

func assertRealCloudPurgeEvidenceBinding(t *testing.T, target, expectedZone string, evidence realCloudPublication) {
	t.Helper()
	if err := validateRealCloudPurgeEvidenceBinding(target, expectedZone, evidence); err != nil {
		t.Fatalf("canonical %s purge evidence is not bound to this publication: %v", target, err)
	}
}

func validateRealCloudPurgeEvidenceBinding(target, expectedZone string, evidence realCloudPublication) error {
	if expectedZone == "" || strings.TrimSpace(expectedZone) != expectedZone {
		return errors.New("expected purge zone is empty or non-canonical")
	}
	planSHA, err := evidence.plan.Digest()
	if err != nil {
		return err
	}
	urlsSHA, err := publish.PurgeURLsDigest(evidence.plan.PurgeURLs)
	if err != nil {
		return err
	}
	wantVendor := publish.PurgeVendorCloudflare
	if target == string(publish.TargetTencent) {
		wantVendor = publish.PurgeVendorEdgeOne
	} else if target != string(publish.TargetCloudflare) {
		return fmt.Errorf("unsupported purge target %q", target)
	}
	if evidence.purgeEvidence.Target != publish.TargetName(target) ||
		evidence.purgeEvidence.TransactionID != evidence.checkpoint.TransactionID ||
		evidence.purgeEvidence.Generation != evidence.generation.Generation ||
		evidence.purgeEvidence.GenerationSHA256 != fmt.Sprintf("%x", sha256.Sum256(evidence.generationBody)) ||
		evidence.purgeEvidence.PlanSHA256 != planSHA ||
		evidence.purgeEvidence.CheckpointSHA256 != fmt.Sprintf("%x", sha256.Sum256(evidence.checkpointBody)) ||
		evidence.purgeEvidence.URLCount != len(evidence.plan.PurgeURLs) || evidence.purgeEvidence.URLsSHA256 != urlsSHA {
		return errors.New("purge evidence disagrees with generation, plan, or checkpoint")
	}
	latestFull := uint64(0)
	for _, attempt := range evidence.purgeEvidence.Attempts {
		if attempt.Purpose == publish.PurgeAttemptFull {
			latestFull = attempt.ID
		}
	}
	if latestFull == 0 {
		return errors.New("purge evidence has no full attempt")
	}
	if err := evidence.purgeEvidence.ValidateFullClosure(latestFull, evidence.plan.PurgeURLs); err != nil {
		return fmt.Errorf("purge evidence has no completed exact full closure: %w", err)
	}
	for _, receipt := range evidence.purgeEvidence.Attempts[latestFull-1].Batches {
		if receipt.Vendor != wantVendor || receipt.ZoneID != expectedZone || receipt.AcceptedRequestID == "" || receipt.CompletedRequestID == "" ||
			wantVendor == publish.PurgeVendorCloudflare && receipt.VendorResultID == "" ||
			wantVendor == publish.PurgeVendorEdgeOne && receipt.JobID == "" {
			return fmt.Errorf("purge receipt lacks the confirmation-bound provider identity: %#v", receipt)
		}
	}
	return nil
}

func TestRealCloudPurgeEvidenceRequiresExactConfirmedZone(t *testing.T) {
	plan, err := (publish.Plan{Objects: []publish.PlannedObject{{
		SourcePath: "assets/release.txt", RemoteKey: "assets/release.txt", Size: 1,
		SHA256: strings.Repeat("a", 64), Class: publish.ObjectPointer,
	}}}).WithCDN("https://cdn.example.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	planSHA, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	urlsSHA, err := publish.PurgeURLsDigest(plan.PurgeURLs)
	if err != nil {
		t.Fatal(err)
	}
	stamp := "2026-07-14T00:00:00Z"
	generationBody := []byte(`{"generation":1}`)
	checkpointBody := []byte(`{"generation":1,"transaction_id":"tx-zone-binding"}`)
	evidence := realCloudPublication{
		generation:     publish.TargetGeneration{Generation: 1},
		checkpoint:     publish.Checkpoint{TransactionID: "tx-zone-binding"},
		plan:           plan,
		generationBody: generationBody, checkpointBody: checkpointBody,
		purgeEvidence: publish.PurgeEvidence{
			Schema: publish.PurgeEvidenceSchema, Target: publish.TargetCloudflare,
			TransactionID: "tx-zone-binding", Generation: 1,
			GenerationSHA256: fmt.Sprintf("%x", sha256.Sum256(generationBody)), PlanSHA256: planSHA,
			CheckpointSHA256: fmt.Sprintf("%x", sha256.Sum256(checkpointBody)),
			URLCount:         len(plan.PurgeURLs), URLsSHA256: urlsSHA,
			Attempts: []publish.PurgeAttempt{{
				ID: 1, Purpose: publish.PurgeAttemptFull, URLCount: len(plan.PurgeURLs), URLsSHA256: urlsSHA,
				StartedAt: stamp, UpdatedAt: stamp,
				Batches: []publish.PurgeReceipt{{
					BatchIndex: 0, URLCount: len(plan.PurgeURLs), URLsSHA256: urlsSHA,
					Vendor: publish.PurgeVendorCloudflare, ZoneID: "zone-confirmed", Status: publish.PurgeReceiptCompleted,
					AcceptedRequestID: "cf-ray-accepted", AcceptedObservedAt: stamp,
					CompletedRequestID: "cf-ray-completed", CompletedObservedAt: stamp, VendorResultID: "purge-result",
				}},
			}},
			CreatedAt: stamp, UpdatedAt: stamp,
		},
	}
	if err := validateRealCloudPurgeEvidenceBinding("cf", "zone-confirmed", evidence); err != nil {
		t.Fatalf("exact confirmation-bound zone rejected: %v", err)
	}
	evidence.purgeEvidence.Attempts[0].Batches[0].ZoneID = "zone-wrong-but-nonempty"
	if err := validateRealCloudPurgeEvidenceBinding("cf", "zone-confirmed", evidence); err == nil {
		t.Fatal("non-empty purge receipt zone not present in the confirmation/config was accepted")
	}
}

func assertRealCloudPublicationAbsent(t *testing.T, root, target string) {
	t.Helper()
	for _, name := range []string{"generation.json", "checkpoint.json", "plan.json"} {
		_, err := os.Stat(filepath.Join(root, config.StateDirectory, "state", "remotes", target, name))
		if !os.IsNotExist(err) {
			t.Fatalf("unpublished target %s unexpectedly has %s: %v", target, name, err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, config.StateDirectory, "state", "remotes", target, "purges"))
	if err == nil && len(entries) != 0 || err != nil && !os.IsNotExist(err) {
		t.Fatalf("unpublished target %s unexpectedly has purge evidence: entries=%d err=%v", target, len(entries), err)
	}
}

func assertRealCloudPublication(t *testing.T, environment realCloudEnvironment, evidence realCloudPublication, target publish.TargetName, generation uint64) {
	t.Helper()
	assertRealCloudLatestPublicationEnvelope(t, environment, evidence, target, generation)
	base, err := realCloudTargetBase(environment, target)
	if err != nil {
		t.Fatal(err)
	}
	wantedInRelease := base + "/apt/real-cloud/dists/jammy/InRelease"
	if !containsExactString(evidence.plan.PurgeURLs, wantedInRelease) {
		t.Fatalf("target %s plan did not include the APT InRelease flip in minimal purge", target)
	}
}

// assertRealCloudLatestPublicationEnvelope intentionally accepts only latest.
// Stable, snapshot, and restore plans have different object/delete closure and
// must use their intent-specific assertions instead of this convenience gate.
func assertRealCloudLatestPublicationEnvelope(t *testing.T, environment realCloudEnvironment, evidence realCloudPublication, target publish.TargetName, generation uint64) {
	t.Helper()
	if evidence.generation.Target != target || evidence.checkpoint.Target != target || evidence.generation.Generation != generation || evidence.checkpoint.Generation != generation {
		t.Fatalf("target %s generation/checkpoint identity mismatch: generation=%s/%d checkpoint=%s/%d", target, evidence.generation.Target, evidence.generation.Generation, evidence.checkpoint.Target, evidence.checkpoint.Generation)
	}
	if evidence.generation.IntentView != "latest" || evidence.checkpoint.IntentView != "latest" || evidence.checkpoint.Phase != publish.PhaseCheckpointCommitted {
		t.Fatalf("target %s did not commit one latest publication: intent=%s/%s phase=%s", target, evidence.generation.IntentView, evidence.checkpoint.IntentView, evidence.checkpoint.Phase)
	}
	if len(evidence.plan.Objects) == 0 || len(evidence.plan.Verify) != len(evidence.plan.Objects) || len(evidence.plan.PurgeURLs) == 0 {
		t.Fatalf("target %s plan lacks object/read-back/purge closure: objects=%d verify=%d purge=%d", target, len(evidence.plan.Objects), len(evidence.plan.Verify), len(evidence.plan.PurgeURLs))
	}
	if len(evidence.plan.Deletes) != 0 {
		t.Fatalf("target %s real-cloud harness plan unexpectedly authorized %d object deletes", target, len(evidence.plan.Deletes))
	}
	base, err := realCloudTargetBase(environment, target)
	if err != nil {
		t.Fatal(err)
	}
	for _, rawURL := range evidence.plan.PurgeURLs {
		if err := validateRealCloudPurgeURLBase(rawURL, base); err != nil {
			t.Fatalf("target %s plan contains purge outside its canonical CDN base: %v", target, err)
		}
	}
}

func realCloudTargetBase(environment realCloudEnvironment, target publish.TargetName) (string, error) {
	rawBase := ""
	switch target {
	case publish.TargetCloudflare:
		rawBase = environment.CFCDNBase
	case publish.TargetTencent:
		rawBase = environment.COSCDNBase
	default:
		return "", fmt.Errorf("unknown real-cloud target %q", target)
	}
	parsed, err := url.Parse(rawBase)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("target %s CDN base is not one clean HTTPS origin: %q", target, rawBase)
	}
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func validateRealCloudPurgeURLBase(rawURL, base string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path == "" || !strings.HasPrefix(parsed.Path, "/") {
		return fmt.Errorf("purge URL is not one clean absolute HTTPS URL: %q", rawURL)
	}
	parsedBase, err := url.Parse(base)
	if err != nil || parsed.Scheme != parsedBase.Scheme || parsed.Host != parsedBase.Host {
		return fmt.Errorf("purge URL %q is outside target base %q", rawURL, base)
	}
	return nil
}

func validateRealCloudExactPurgeURLs(actual []string, wanted map[string]string) error {
	seen := make(map[string]bool, len(actual))
	for _, rawURL := range actual {
		label, exists := wanted[rawURL]
		if !exists {
			return fmt.Errorf("unplanned purge URL %q", rawURL)
		}
		if seen[rawURL] {
			return fmt.Errorf("duplicate %s purge URL %q", label, rawURL)
		}
		seen[rawURL] = true
	}
	if len(actual) != len(wanted) {
		for rawURL, label := range wanted {
			if !seen[rawURL] {
				return fmt.Errorf("missing %s purge URL %q", label, rawURL)
			}
		}
		return fmt.Errorf("purge URL count=%d, want %d", len(actual), len(wanted))
	}
	return nil
}

func containsExactString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func assertRealCloudStablePublication(t *testing.T, environment realCloudEnvironment, targetName string, evidence realCloudPublication, target publish.TargetName, generation uint64) publish.PlannedObject {
	t.Helper()
	asset, err := validateRealCloudStablePublication(environment, targetName, evidence, target, generation)
	if err != nil {
		t.Fatal(err)
	}
	return asset
}

func validateRealCloudStablePublication(environment realCloudEnvironment, targetName string, evidence realCloudPublication, target publish.TargetName, generation uint64) (publish.PlannedObject, error) {
	if evidence.generation.Target != target || evidence.checkpoint.Target != target || evidence.generation.Generation != generation || evidence.checkpoint.Generation != generation {
		return publish.PlannedObject{}, fmt.Errorf("target %s stable generation/checkpoint identity mismatch", targetName)
	}
	if evidence.generation.IntentView != "stable" || evidence.checkpoint.IntentView != "stable" || evidence.checkpoint.Phase != publish.PhaseCheckpointCommitted {
		return publish.PlannedObject{}, fmt.Errorf("target %s did not commit one stable publication", targetName)
	}
	if len(evidence.plan.Objects) == 0 || len(evidence.plan.Verify) != len(evidence.plan.Objects) || len(evidence.plan.Deletes) != 0 {
		return publish.PlannedObject{}, fmt.Errorf("target %s stable plan closure objects=%d verify=%d deletes=%d", targetName, len(evidence.plan.Objects), len(evidence.plan.Verify), len(evidence.plan.Deletes))
	}
	generationText := fmt.Sprintf("%020d", generation)
	wantedObjects := map[string]bool{"apt": false, "yum-generation": false, "yum-channel": false, "public-asset": false, "gated-asset": false}
	var gatedAsset publish.PlannedObject
	for _, object := range evidence.plan.Objects {
		switch {
		case object.RemoteKey == ".sow/gated/apt/real-cloud/dists/jammy/InRelease":
			wantedObjects["apt"] = true
		case object.RemoteKey == ".sow/gated/generations/"+generationText+"/yum/yum/real-cloud/x86_64/repodata/repomd.xml":
			wantedObjects["yum-generation"] = true
		case object.RemoteKey == ".sow/channels/stable/"+realCloudYUMRepositoryID+"/el10/x86_64.json":
			wantedObjects["yum-channel"] = true
		case object.RemoteKey == ".sow/gated/assets/real-cloud/latest.txt":
			wantedObjects["public-asset"] = true
		case object.RemoteKey == ".sow/gated/"+realCloudGatedAssetPath:
			wantedObjects["gated-asset"] = true
			gatedAsset = object
		}
	}
	for class, found := range wantedObjects {
		if !found {
			return publish.PlannedObject{}, fmt.Errorf("target %s stable plan omitted %s", targetName, class)
		}
	}
	channelFound := false
	for _, channel := range evidence.generation.Channels {
		if channel.View == "stable" && channel.Repo == realCloudYUMRepositoryID && channel.OS == "el10" && channel.Arch == "x86_64" && channel.Generation == generation {
			channelFound = true
		}
	}
	if !channelFound {
		return publish.PlannedObject{}, fmt.Errorf("target %s stable generation omitted the YUM channel", targetName)
	}
	base, err := realCloudTargetBase(environment, target)
	if err != nil {
		return publish.PlannedObject{}, err
	}
	wantedPurges := map[string]string{
		base + "/pro/v1/basic/apt/real-cloud/dists/jammy/InRelease":                                       "apt client",
		base + "/pro/v1/basic/_sow/v1/mirrorlist/stable/" + realCloudYUMRepositoryID + "/el10/x86_64.txt": "yum mirrorlist client",
		base + "/pro/v1/basic/yum/real-cloud/x86_64/repodata/repomd.xml":                                  "yum repomd client",
		base + "/pro/v1/basic/yum/real-cloud/x86_64/repodata/repomd.xml.asc":                              "yum signature client",
		base + "/pro/v1/basic/assets/real-cloud/latest.txt":                                               "public-asset client",
		base + "/pro/v1/basic/" + realCloudGatedAssetPath:                                                 "gated-asset client",
		base + "/.sow/gated/apt/real-cloud/dists/jammy/InRelease":                                         "apt clean",
		base + "/.sow/channels/stable/" + realCloudYUMRepositoryID + "/el10/x86_64.json":                  "yum mirrorlist clean",
		base + "/.sow/gated/yum/real-cloud/x86_64/repodata/repomd.xml":                                    "yum repomd clean",
		base + "/.sow/gated/yum/real-cloud/x86_64/repodata/repomd.xml.asc":                                "yum signature clean",
		base + "/.sow/gated/assets/real-cloud/latest.txt":                                                 "public-asset clean",
		base + "/.sow/gated/" + realCloudGatedAssetPath:                                                   "gated-asset clean",
	}
	if err := validateRealCloudExactPurgeURLs(evidence.plan.PurgeURLs, wantedPurges); err != nil {
		return publish.PlannedObject{}, fmt.Errorf("target %s stable purge closure: %w", targetName, err)
	}
	return gatedAsset, nil
}

func assertRealCloudGatedPublication(t *testing.T, environment realCloudEnvironment, targetName string, evidence realCloudPublication, target publish.TargetName, generation uint64) publish.PlannedObject {
	t.Helper()
	if evidence.generation.Target != target || evidence.checkpoint.Target != target || evidence.generation.Generation != generation || evidence.checkpoint.Generation != generation {
		t.Fatalf("target %s gated generation/checkpoint identity mismatch", targetName)
	}
	if evidence.generation.IntentView != "stable" || evidence.checkpoint.IntentView != "stable" || evidence.checkpoint.Phase != publish.PhaseCheckpointCommitted {
		t.Fatalf("target %s did not commit one stable publication: intent=%s/%s phase=%s", targetName, evidence.generation.IntentView, evidence.checkpoint.IntentView, evidence.checkpoint.Phase)
	}
	if len(evidence.plan.Objects) == 0 || len(evidence.plan.Verify) != len(evidence.plan.Objects) || len(evidence.plan.Deletes) != 0 {
		t.Fatalf("target %s gated plan closure objects=%d verify=%d deletes=%d", targetName, len(evidence.plan.Objects), len(evidence.plan.Verify), len(evidence.plan.Deletes))
	}
	wantedRemoteKey := ".sow/gated/" + realCloudGatedAssetPath
	var asset publish.PlannedObject
	for _, object := range evidence.plan.Objects {
		if object.RemoteKey == wantedRemoteKey {
			asset = object
			break
		}
	}
	if asset.RemoteKey == "" || asset.SHA256 == "" {
		t.Fatalf("target %s stable plan omitted gated asset pointer %s", targetName, wantedRemoteKey)
	}
	base := environment.CFCDNBase
	if target == publish.TargetTencent {
		base = environment.COSCDNBase
	}
	wantedPurges := map[string]bool{
		strings.TrimSuffix(base, "/") + "/pro/v1/basic/" + realCloudGatedAssetPath: false,
		strings.TrimSuffix(base, "/") + "/.sow/gated/" + realCloudGatedAssetPath:   false,
	}
	for _, rawURL := range evidence.plan.PurgeURLs {
		if _, exists := wantedPurges[rawURL]; !exists || strings.ContainsAny(rawURL, "*?#") {
			t.Fatalf("target %s gated purge contains a non-exact or unplanned URL: %s", targetName, rawURL)
		}
		wantedPurges[rawURL] = true
	}
	if len(evidence.plan.PurgeURLs) != len(wantedPurges) {
		t.Fatalf("target %s gated mutable publication purge=%v, want paired client and clean-cache URLs", targetName, evidence.plan.PurgeURLs)
	}
	for rawURL, found := range wantedPurges {
		if !found {
			t.Fatalf("target %s gated publication omitted purge %s", targetName, rawURL)
		}
	}
	return asset
}

func assertRealCloudSnapshotPublication(t *testing.T, environment realCloudEnvironment, evidence realCloudPublication, target publish.TargetName, generation uint64, snapshotID, expiredSnapshotID string) {
	t.Helper()
	if err := validateRealCloudSnapshotPublication(environment, evidence, target, generation, snapshotID, expiredSnapshotID); err != nil {
		t.Fatal(err)
	}
}

func validateRealCloudSnapshotPublication(environment realCloudEnvironment, evidence realCloudPublication, target publish.TargetName, generation uint64, snapshotID, expiredSnapshotID string) error {
	if evidence.generation.Target != target || evidence.checkpoint.Target != target || evidence.generation.Generation != generation || evidence.checkpoint.Generation != generation {
		return errors.New("snapshot generation/checkpoint identity mismatch")
	}
	if evidence.generation.IntentView != "snapshot" || evidence.generation.IntentSnapshot != snapshotID ||
		evidence.checkpoint.IntentView != "snapshot" || evidence.checkpoint.IntentSnapshot != snapshotID || evidence.checkpoint.Phase != publish.PhaseCheckpointCommitted {
		return errors.New("snapshot intent did not commit")
	}
	if len(evidence.plan.Objects) == 0 || len(evidence.plan.Verify) != len(evidence.plan.Objects) {
		return errors.New("snapshot object/read-back closure is incomplete")
	}
	wantedRoute := ".sow/snapshots/" + snapshotID + ".json"
	destinationPrefix := ".sow/gated/snapshots/" + snapshotID + "/yum/yum/real-cloud/x86_64/Packages/"
	sourcePrefix := "yum/real-cloud/x86_64/Packages/"
	routeFound, copyFound := false, false
	for _, object := range evidence.plan.Objects {
		if object.RemoteKey == wantedRoute && object.Class == publish.ObjectPointer {
			routeFound = true
		}
		if strings.HasPrefix(object.RemoteKey, destinationPrefix) && object.Class == publish.ObjectCopyImmutable && strings.HasPrefix(object.CopySource, sourcePrefix) {
			copyFound = true
		}
	}
	if !routeFound || !copyFound {
		return fmt.Errorf("snapshot route/copy closure route=%v copy=%v", routeFound, copyFound)
	}
	base, err := realCloudTargetBase(environment, target)
	if err != nil {
		return err
	}
	wantedPurges := map[string]string{
		base + "/pro/v1/basic/_sow/v1/snapshots/" + snapshotID + "/_route.json": "current snapshot client route",
		base + "/.sow/snapshots/" + snapshotID + ".json":                        "current snapshot clean route",
	}
	if expiredSnapshotID != "" {
		wantedPurges[base+"/pro/v1/basic/_sow/v1/snapshots/"+expiredSnapshotID+"/_route.json"] = "expired snapshot client route"
		wantedPurges[base+"/.sow/snapshots/"+expiredSnapshotID+".json"] = "expired snapshot clean route"
	}
	if err := validateRealCloudExactPurgeURLs(evidence.plan.PurgeURLs, wantedPurges); err != nil {
		return fmt.Errorf("snapshot purge closure: %w", err)
	}
	if expiredSnapshotID == "" {
		if len(evidence.plan.Deletes) != 0 || len(evidence.plan.VerifyAbsent) != 0 {
			return errors.New("first snapshot unexpectedly authorized retention deletion")
		}
		return nil
	}
	expiredRoute := ".sow/snapshots/" + expiredSnapshotID + ".json"
	expiredPayloadPrefix := ".sow/gated/snapshots/" + expiredSnapshotID + "/yum/yum/real-cloud/x86_64/Packages/"
	routeDelete, payloadDelete := false, false
	for _, deletion := range evidence.plan.Deletes {
		if deletion.Class != publish.DeleteSnapshotOwned {
			return fmt.Errorf("snapshot retention used unsafe delete class %s", deletion.Class)
		}
		if deletion.Size <= 0 || len(deletion.SHA256) != 64 {
			return fmt.Errorf("snapshot retention deletion %s lacks size/digest evidence", deletion.RemoteKey)
		}
		if deletion.SourcePath != deletion.RemoteKey {
			return fmt.Errorf("snapshot retention deletion %s is not source-bound", deletion.RemoteKey)
		}
		switch {
		case deletion.RemoteKey == expiredRoute:
			routeDelete = true
		case strings.HasPrefix(deletion.RemoteKey, expiredPayloadPrefix):
			payloadDelete = true
		case !strings.HasPrefix(deletion.RemoteKey, ".sow/gated/snapshots/"+expiredSnapshotID+"/"):
			return fmt.Errorf("snapshot retention escaped expired namespace: %s", deletion.RemoteKey)
		}
	}
	wantedClientRoute := base + "/pro/v1/basic/_sow/v1/snapshots/" + expiredSnapshotID + "/_route.json"
	absenceFound := len(evidence.plan.VerifyAbsent) == 1 && evidence.plan.VerifyAbsent[0].URL == wantedClientRoute
	if !routeDelete || !payloadDelete || !absenceFound || len(evidence.plan.Probes) == 0 {
		return fmt.Errorf("snapshot retention closure route=%v payload=%v absence=%v probes=%d", routeDelete, payloadDelete, absenceFound, len(evidence.plan.Probes))
	}
	return nil
}

// seedRealCloudHistoricalSnapshot models the only state an acceptance run
// cannot create honestly today: an immutable snapshot ref captured months ago.
// Production `sow promote stable <snapshot>` deliberately rejects backdating,
// so the fixture first creates today's snapshot through the CLI, then copies
// that exact canonical YUM leaf into an older immutable ref in one recoverable
// local state transaction. Every remote publish/delete remains production CLI.
func seedRealCloudHistoricalSnapshot(t *testing.T, root, currentSnapshotID, historicalSnapshotID string) {
	t.Helper()
	canonical := state.New(filepath.Join(root, config.StateDirectory))
	currentRef, err := state.SnapshotRef(currentSnapshotID, realCloudYUMRepositoryID, "el10", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	currentPath, err := state.SnapshotPath(currentSnapshotID, realCloudYUMRepositoryID, "el10", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	currentCommit, exists, err := canonical.Ref(currentRef)
	if err != nil || !exists {
		t.Fatalf("current snapshot fixture ref exists=%v err=%v", exists, err)
	}
	reader, err := canonical.OpenPathAt(currentCommit, currentPath)
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := filepath.Join(root, config.StateDirectory, "tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		_ = reader.Close()
		t.Fatal(err)
	}
	stage, err := os.CreateTemp(tmpDir, "historical-snapshot-*.tsv")
	if err != nil {
		_ = reader.Close()
		t.Fatal(err)
	}
	stageName := stage.Name()
	t.Cleanup(func() { _ = os.Remove(stageName) })
	_, copyErr := io.Copy(stage, reader)
	closeErr := errors.Join(reader.Close(), stage.Sync(), stage.Close())
	if copyErr != nil || closeErr != nil {
		t.Fatal(errors.Join(copyErr, closeErr))
	}
	historicalPath, err := state.SnapshotPath(historicalSnapshotID, realCloudYUMRepositoryID, "el10", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	historicalRef, err := state.SnapshotRef(historicalSnapshotID, realCloudYUMRepositoryID, "el10", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	if _, exists, err := canonical.Ref(historicalRef); err != nil || exists {
		t.Fatalf("historical snapshot fixture ref already exists=%v err=%v", exists, err)
	}
	commit, changed, err := canonical.Apply(t.Context(), "real-cloud-fixture", "sow real-cloud fixture: seed historical snapshot ref",
		map[string]string{historicalPath: stageName}, []state.RefUpdate{{Name: historicalRef, Immutable: true}}, state.ApplyOptions{})
	if err != nil || !changed {
		t.Fatalf("seed historical snapshot fixture changed=%v err=%v", changed, err)
	}
	installed, exists, err := canonical.Ref(historicalRef)
	if err != nil || !exists || installed != commit {
		t.Fatalf("historical snapshot fixture ref=%s commit=%s exists=%v err=%v", installed, commit, exists, err)
	}
	stillCurrent, exists, err := canonical.Ref(currentRef)
	if err != nil || !exists || stillCurrent != currentCommit {
		t.Fatalf("historical fixture moved current immutable ref got=%s want=%s exists=%v err=%v", stillCurrent, currentCommit, exists, err)
	}
	if err := rebuildAndValidateRealCloudSnapshotCatalog(t.Context(), root, currentSnapshotID, historicalSnapshotID); err != nil {
		t.Fatalf("rebuild historical snapshot catalog closure: %v", err)
	}
}

func rebuildAndValidateRealCloudCatalogHead(ctx context.Context, root string) (catalog.Stats, error) {
	statePath := filepath.Join(root, config.StateDirectory)
	if err := catalog.RebuildContext(ctx, statePath); err != nil {
		return catalog.Stats{}, fmt.Errorf("rebuild SQLite catalog: %w", err)
	}
	stats, err := catalog.Statistics(ctx, statePath)
	if err != nil {
		return catalog.Stats{}, fmt.Errorf("read rebuilt SQLite catalog statistics: %w", err)
	}
	canonicalHead, err := state.New(statePath).HeadHash()
	if err != nil {
		return catalog.Stats{}, fmt.Errorf("read canonical head after catalog rebuild: %w", err)
	}
	cacheHead, err := catalog.CanonicalHead(ctx, statePath)
	if err != nil {
		return catalog.Stats{}, fmt.Errorf("read SQLite catalog canonical head: %w", err)
	}
	if cacheHead != canonicalHead {
		return catalog.Stats{}, fmt.Errorf("SQLite catalog head=%s differs from canonical=%s", cacheHead, canonicalHead)
	}
	return stats, nil
}

func rebuildAndValidateRealCloudSnapshotCatalog(ctx context.Context, root string, snapshotIDs ...string) error {
	if _, err := rebuildAndValidateRealCloudCatalogHead(ctx, root); err != nil {
		return err
	}
	canonical := state.New(filepath.Join(root, config.StateDirectory))
	for _, snapshotID := range snapshotIDs {
		if views.ValidateSnapshotID(snapshotID) != nil {
			return fmt.Errorf("invalid snapshot identity %q in catalog closure", snapshotID)
		}
		ref, err := state.SnapshotRef(snapshotID, realCloudYUMRepositoryID, "el10", "x86_64")
		if err != nil {
			return err
		}
		commit, exists, err := canonical.Ref(ref)
		if err != nil || !exists {
			return errors.Join(err, fmt.Errorf("snapshot %s canonical ref is absent", snapshotID))
		}
		canonicalPath, err := state.SnapshotPath(snapshotID, realCloudYUMRepositoryID, "el10", "x86_64")
		if err != nil {
			return err
		}
		reader, err := canonical.OpenPathAt(commit, canonicalPath)
		if err != nil {
			return err
		}
		viewReader := views.NewReader(reader)
		var expected int64
		for {
			_, readErr := viewReader.Next()
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = reader.Close()
				return readErr
			}
			expected++
		}
		if err := reader.Close(); err != nil {
			return err
		}
		actual, err := catalog.MembershipCount(ctx, filepath.Join(root, config.StateDirectory), catalog.Scope{Kind: "snapshot", Name: snapshotID, Repo: realCloudYUMRepositoryID, OS: "el10", Arch: "x86_64"})
		if err != nil {
			return fmt.Errorf("read snapshot %s SQLite memberships: %w", snapshotID, err)
		}
		if actual != expected {
			return fmt.Errorf("snapshot %s SQLite memberships=%d canonical=%d", snapshotID, actual, expected)
		}
	}
	return nil
}

func assertRealCloudFirstPublicationProtocols(t *testing.T, environment realCloudEnvironment, targetName string, evidence realCloudPublication, target publish.TargetName) {
	t.Helper()
	objects := map[string]bool{
		"apt": false, "yum-generation": false, "yum-mirrorlist": false, "asset": false,
	}
	for _, object := range evidence.plan.Objects {
		switch {
		case strings.HasSuffix(object.RemoteKey, "/apt/apt/real-cloud/dists/jammy/InRelease") && strings.HasPrefix(object.RemoteKey, ".sow/generations/"):
			objects["apt"] = true
		case strings.Contains(object.RemoteKey, "/yum/yum/real-cloud/x86_64/repodata/repomd.xml") && strings.HasPrefix(object.RemoteKey, ".sow/generations/"):
			objects["yum-generation"] = true
		case object.RemoteKey == "_sow/v1/mirrorlist/latest/"+realCloudYUMRepositoryID+"/el10/x86_64.txt":
			objects["yum-mirrorlist"] = true
		case object.RemoteKey == "assets/real-cloud/latest.txt":
			objects["asset"] = true
		}
	}
	for protocol, found := range objects {
		if !found {
			t.Fatalf("target %s first publication omitted %s object closure", targetName, protocol)
		}
	}
	base, err := realCloudTargetBase(environment, target)
	if err != nil {
		t.Fatal(err)
	}
	wantedPurges := map[string]string{
		base + "/apt/real-cloud/dists/jammy/InRelease":                                       "apt",
		base + "/_sow/v1/mirrorlist/latest/" + realCloudYUMRepositoryID + "/el10/x86_64.txt": "yum mirrorlist",
		base + "/yum/real-cloud/x86_64/repodata/repomd.xml":                                  "yum repomd",
		base + "/yum/real-cloud/x86_64/repodata/repomd.xml.asc":                              "yum signature",
		base + "/assets/real-cloud/latest.txt":                                               "asset",
	}
	if err := validateRealCloudExactPurgeURLs(evidence.plan.PurgeURLs, wantedPurges); err != nil {
		t.Fatalf("target %s first publication mandatory minimal purge: %v", targetName, err)
	}
}

func assertRealCloudYUMAssetUpdate(t *testing.T, environment realCloudEnvironment, targetName string, first, updated realCloudPublication, target publish.TargetName, generation uint64) {
	t.Helper()
	generationText := fmt.Sprintf("%020d", generation)
	generationPrefix := ".sow/generations/" + generationText + "/yum/yum/real-cloud/x86_64/repodata/"
	rawPrefix := "yum/real-cloud/x86_64/repodata/"
	objects := make(map[string]publish.PlannedObject, len(updated.plan.Objects))
	for _, object := range updated.plan.Objects {
		objects[object.RemoteKey] = object
	}
	for _, filename := range []string{"repomd.xml", "repomd.xml.asc"} {
		immutable, immutableOK := objects[generationPrefix+filename]
		raw, rawOK := objects[rawPrefix+filename]
		if !immutableOK || !rawOK || immutable.Size != raw.Size || immutable.SHA256 != raw.SHA256 {
			t.Fatalf("target %s generation %d YUM %s immutable/raw closure differs: immutable=%#v raw=%#v", targetName, generation, filename, immutable, raw)
		}
	}
	mirrorKey := "_sow/v1/mirrorlist/latest/" + realCloudYUMRepositoryID + "/el10/x86_64.txt"
	if _, exists := objects[mirrorKey]; !exists {
		t.Fatalf("target %s generation %d omitted updated YUM mirrorlist %s", targetName, generation, mirrorKey)
	}
	assetKey := "assets/real-cloud/latest.txt"
	updatedAsset, exists := objects[assetKey]
	if !exists {
		t.Fatalf("target %s generation %d omitted mutable asset update %s", targetName, generation, assetKey)
	}
	firstAsset := publish.PlannedObject{}
	for _, object := range first.plan.Objects {
		if object.RemoteKey == assetKey {
			firstAsset = object
			break
		}
	}
	if firstAsset.SHA256 == "" || firstAsset.SHA256 == updatedAsset.SHA256 {
		t.Fatalf("target %s mutable asset did not change first=%s updated=%s", targetName, firstAsset.SHA256, updatedAsset.SHA256)
	}
	foundChannel := false
	for _, channel := range updated.generation.Channels {
		if channel.View == "latest" && channel.Repo == realCloudYUMRepositoryID && channel.OS == "el10" && channel.Arch == "x86_64" {
			foundChannel = channel.Generation == generation
		}
	}
	if !foundChannel {
		t.Fatalf("target %s generation %d did not advance the YUM channel", targetName, generation)
	}
	base, err := realCloudTargetBase(environment, target)
	if err != nil {
		t.Fatal(err)
	}
	wantedPurges := map[string]string{
		base + "/" + mirrorKey:                    "mirrorlist",
		base + "/" + rawPrefix + "repomd.xml":     "repomd",
		base + "/" + rawPrefix + "repomd.xml.asc": "signature",
		base + "/" + assetKey:                     "asset",
	}
	if err := validateRealCloudExactPurgeURLs(updated.plan.PurgeURLs, wantedPurges); err != nil {
		t.Fatalf("target %s generation %d YUM/asset purge closure: %v", targetName, generation, err)
	}
}

func assertRealCloudYUMGenerationInventory(t *testing.T, root, target string, generations ...uint64) {
	t.Helper()
	file, err := os.Open(filepath.Join(root, config.StateDirectory, "state", "remotes", target, "inventory.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	wanted := make(map[string]bool, len(generations))
	for _, generation := range generations {
		prefix := fmt.Sprintf(".sow/generations/%020d/yum/yum/real-cloud/x86_64/repodata/", generation)
		wanted[prefix] = false
	}
	reader := manifest.NewReader(file)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		for prefix := range wanted {
			if strings.HasPrefix(entry.Path, prefix) {
				wanted[prefix] = true
			}
		}
	}
	for prefix, found := range wanted {
		if !found {
			t.Fatalf("target %s remote inventory did not retain YUM generation prefix %s", target, prefix)
		}
	}
}

func assertRealCloudSnapshotInventory(t *testing.T, root, target string, present, absent []string) {
	t.Helper()
	file, err := os.Open(filepath.Join(root, config.StateDirectory, "state", "remotes", target, "inventory.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	type coverage struct {
		route   bool
		payload bool
	}
	wantedPresent := make(map[string]coverage, len(present))
	wantedAbsent := make(map[string]struct{}, len(absent))
	for _, snapshotID := range present {
		wantedPresent[snapshotID] = coverage{}
	}
	for _, snapshotID := range absent {
		wantedAbsent[snapshotID] = struct{}{}
	}
	reader := manifest.NewReader(file)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		for snapshotID, state := range wantedPresent {
			state.route = state.route || entry.Path == ".sow/snapshots/"+snapshotID+".json"
			state.payload = state.payload || strings.HasPrefix(entry.Path, ".sow/gated/snapshots/"+snapshotID+"/")
			wantedPresent[snapshotID] = state
		}
		for snapshotID := range wantedAbsent {
			if entry.Path == ".sow/snapshots/"+snapshotID+".json" || strings.HasPrefix(entry.Path, ".sow/gated/snapshots/"+snapshotID+"/") {
				t.Fatalf("target %s inventory retained expired snapshot key %s", target, entry.Path)
			}
		}
		if strings.HasPrefix(entry.Path, ".sow/probes/conditional-delete/") {
			t.Fatalf("target %s inventory retained conditional-delete capability probe %s", target, entry.Path)
		}
	}
	for snapshotID, state := range wantedPresent {
		if !state.route || !state.payload {
			t.Fatalf("target %s inventory snapshot %s route=%v payload=%v", target, snapshotID, state.route, state.payload)
		}
	}
}

func assertRealCloudReplayUnchanged(t *testing.T, target string, before, after realCloudPublication) {
	t.Helper()
	if !bytes.Equal(before.generationBody, after.generationBody) || !bytes.Equal(before.checkpointBody, after.checkpointBody) ||
		!bytes.Equal(before.planBody, after.planBody) || !bytes.Equal(before.purgeEvidenceBody, after.purgeEvidenceBody) {
		t.Fatalf("target %s no-op replay rewrote canonical generation/checkpoint/plan/purge evidence", target)
	}
}

func clearRealCloudBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
