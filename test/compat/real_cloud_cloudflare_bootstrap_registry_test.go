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
	"time"

	sowconfig "github.com/pgsty/sow/internal/config"
)

const (
	realCloudCloudflareBootstrapOptInEnv            = "SOW_RUN_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP"
	realCloudCloudflareBootstrapPlanEnv             = "SOW_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP_PLAN_JSON"
	realCloudCloudflareBootstrapConfirmationEnv     = "SOW_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP_CONFIRM"
	realCloudCloudflareBootstrapReceiptEnv          = "SOW_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP_RECEIPT"
	realCloudCloudflareBootstrapReadinessReceiptEnv = "SOW_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP_READINESS_RECEIPT"
	realCloudCloudflareBootstrapRegistryOnboardEnv  = "SOW_RUN_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP_REGISTRY_ONBOARDING"
	realCloudCloudflareBootstrapPlanOnboardEnv      = "SOW_RUN_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP_PLAN_ONBOARDING"
	realCloudCloudflareBootstrapDescriptorEnv       = "SOW_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP_DESCRIPTOR_JSON"
	realCloudCloudflareBootstrapEdgeContractFileEnv = "SOW_REAL_CLOUD_CLOUDFLARE_EDGE_CONTRACT_FILE"
	realCloudCloudflareBootstrapRegistryPath        = "test/compat/testdata/real_cloud_nonproduction_cloudflare_bootstrap_registry.json"
	realCloudCloudflareBootstrapRegistrySchema      = "sow-real-cloud-pinned-cloudflare-bootstrap-registry/v1"
	realCloudCloudflareBootstrapRegistryEntrySchema = "sow-real-cloud-pinned-cloudflare-bootstrap/v1"
	realCloudCloudflareBootstrapPlanSchema          = "sow-real-cloud-cloudflare-bootstrap-plan/v3"
	realCloudCloudflareBootstrapDescriptorSchema    = "sow-real-cloud-cloudflare-bootstrap-descriptor/v3"
	realCloudCloudflareBootstrapRegistrySHA256      = "054a6df1bc74a60ff39c202b4f3342e88bbb3c0892374ed9ac5251a8619570ca"
	realCloudCloudflareAuthBundlePath               = "edge/dist/cloudflare-worker.mjs"
	realCloudCloudflareOriginBundlePath             = "edge/dist/cloudflare-origin-worker.mjs"
	realCloudCloudflareBootstrapOwnership           = "manage-exact-auth-origin-workers-and-main-beta-routes-only"
)

type realCloudCloudflareBootstrapRegistry struct {
	Schema string                                      `json:"schema"`
	Plans  []realCloudCloudflareBootstrapRegistryEntry `json:"plans"`
}

type realCloudCloudflareBootstrapRegistryEntry struct {
	Schema                  string `json:"schema"`
	Purpose                 string `json:"purpose"`
	ReadinessResourceSHA256 string `json:"readiness_resource_sha256"`
	PlanSHA256              string `json:"plan_sha256"`
}

type realCloudCloudflareBootstrapPlan struct {
	Schema                          string                              `json:"schema"`
	Purpose                         string                              `json:"purpose"`
	Ownership                       string                              `json:"ownership"`
	ReadinessResourceSHA256         string                              `json:"readiness_resource_sha256"`
	ReadinessSealPublicKey          string                              `json:"readiness_seal_public_key"`
	AccountID                       string                              `json:"account_id"`
	ZoneID                          string                              `json:"zone_id"`
	R2Bucket                        string                              `json:"r2_bucket"`
	MainBase                        string                              `json:"main_base"`
	BetaBase                        string                              `json:"beta_base"`
	AuthScript                      string                              `json:"auth_script"`
	OriginScript                    string                              `json:"origin_script"`
	TokenVerifierKind               string                              `json:"token_verifier_kind"`
	TokenVerifierService            string                              `json:"token_verifier_service"`
	TokenVerifierEnvironment        string                              `json:"token_verifier_environment"`
	TokenVerifierSecret             string                              `json:"token_verifier_secret"`
	TokenVerifierContentSHA256      string                              `json:"token_verifier_content_sha256"`
	TokenVerifierBindingsSHA256     string                              `json:"token_verifier_bindings_sha256"`
	TokenVerifierCompatibilityDate  string                              `json:"token_verifier_compatibility_date"`
	TokenVerifierCompatibilityFlags []string                            `json:"token_verifier_compatibility_flags"`
	CompatibilityDate               string                              `json:"compatibility_date"`
	CompatibilityFlags              []string                            `json:"compatibility_flags"`
	AuthBundle                      realCloudCloudflareBootstrapBundle  `json:"auth_bundle"`
	OriginBundle                    realCloudCloudflareBootstrapBundle  `json:"origin_bundle"`
	EdgeContract                    sowconfig.EdgeDeploymentContract    `json:"edge_contract"`
	Routes                          []realCloudCloudflareBootstrapRoute `json:"routes"`
}

type realCloudCloudflareBootstrapBundle struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type realCloudCloudflareBootstrapRoute struct {
	Pattern string `json:"pattern"`
	Script  string `json:"script"`
}

type realCloudCloudflareBootstrapRegistryCandidateReceipt struct {
	Schema                  string `json:"schema"`
	ReadinessResourceSHA256 string `json:"readiness_resource_sha256"`
	PlanSHA256              string `json:"plan_sha256"`
	RegistrySHA256          string `json:"registry_sha256"`
}

type realCloudCloudflareBootstrapDescriptor struct {
	Schema                          string   `json:"schema"`
	ReadinessSealPublicKey          string   `json:"readiness_seal_public_key"`
	AuthScript                      string   `json:"auth_script"`
	OriginScript                    string   `json:"origin_script"`
	TokenVerifierKind               string   `json:"token_verifier_kind"`
	TokenVerifierService            string   `json:"token_verifier_service"`
	TokenVerifierEnvironment        string   `json:"token_verifier_environment"`
	TokenVerifierSecret             string   `json:"token_verifier_secret"`
	TokenVerifierContentSHA256      string   `json:"token_verifier_content_sha256"`
	TokenVerifierBindingsSHA256     string   `json:"token_verifier_bindings_sha256"`
	TokenVerifierCompatibilityDate  string   `json:"token_verifier_compatibility_date"`
	TokenVerifierCompatibilityFlags []string `json:"token_verifier_compatibility_flags"`
	CompatibilityDate               string   `json:"compatibility_date"`
	CompatibilityFlags              []string `json:"compatibility_flags"`
}

type realCloudCloudflareBootstrapPlanCandidateReceipt struct {
	Schema                  string `json:"schema"`
	ReadinessResourceSHA256 string `json:"readiness_resource_sha256"`
	PlanSHA256              string `json:"plan_sha256"`
	AuthBundleSHA256        string `json:"auth_bundle_sha256"`
	OriginBundleSHA256      string `json:"origin_bundle_sha256"`
}

func loadRealCloudCloudflareBootstrapRegistry() (realCloudCloudflareBootstrapRegistry, error) {
	body, err := readRealCloudProviderRepositoryFile(realCloudCloudflareBootstrapRegistryPath, 256<<10)
	if err != nil {
		return realCloudCloudflareBootstrapRegistry{}, errors.New("repository-pinned Cloudflare bootstrap registry is absent or unsafe")
	}
	defer clearRealCloudBytes(body)
	return decodeRealCloudCloudflareBootstrapRegistry(body, realCloudCloudflareBootstrapRegistrySHA256)
}

func decodeRealCloudCloudflareBootstrapRegistry(body []byte, expectedSHA256 string) (realCloudCloudflareBootstrapRegistry, error) {
	var registry realCloudCloudflareBootstrapRegistry
	if !validRealCloudLowerSHA256(expectedSHA256) || realCloudLowerSHA256(body) != expectedSHA256 {
		return registry, errors.New("repository-pinned Cloudflare bootstrap registry digest differs from the reviewed build constant")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return registry, errors.New("decode repository-pinned Cloudflare bootstrap registry")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return registry, errors.New("repository-pinned Cloudflare bootstrap registry contains trailing values")
	}
	canonical, err := json.Marshal(registry)
	if err != nil || !bytes.Equal(body, append(canonical, '\n')) || registry.Schema != realCloudCloudflareBootstrapRegistrySchema || registry.Plans == nil {
		return registry, errors.New("repository-pinned Cloudflare bootstrap registry is non-canonical or invalid")
	}
	previous := ""
	for _, plan := range registry.Plans {
		key := plan.ReadinessResourceSHA256 + "\x00" + plan.PlanSHA256
		if plan.Schema != realCloudCloudflareBootstrapRegistryEntrySchema || plan.Purpose != "dedicated-disposable-non-production-test" ||
			!validRealCloudLowerSHA256(plan.ReadinessResourceSHA256) || !validRealCloudLowerSHA256(plan.PlanSHA256) || key <= previous {
			return registry, errors.New("repository-pinned Cloudflare bootstrap plans are invalid, duplicate, or unsorted")
		}
		previous = key
	}
	return registry, nil
}

func decodeRealCloudCloudflareBootstrapPlan(raw string, resource realCloudProviderReadinessResource) (realCloudCloudflareBootstrapPlan, []byte, error) {
	var plan realCloudCloudflareBootstrapPlan
	if raw == "" || raw != strings.TrimSpace(raw) {
		return plan, nil, errors.New("missing or non-canonical Cloudflare bootstrap plan")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return plan, nil, errors.New("decode Cloudflare bootstrap plan")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return plan, nil, errors.New("Cloudflare bootstrap plan contains trailing values")
	}
	body, err := json.Marshal(plan)
	if err != nil || raw != string(body) {
		return plan, nil, errors.New("Cloudflare bootstrap plan must be canonical JSON")
	}
	if err := validateRealCloudCloudflareBootstrapPlan(plan, resource); err != nil {
		return plan, nil, err
	}
	return plan, body, nil
}

func validateRealCloudCloudflareBootstrapPlan(plan realCloudCloudflareBootstrapPlan, resource realCloudProviderReadinessResource) error {
	if resource.Provider != "cloudflare" || resource.Cloudflare == nil || resource.EdgeOne != nil {
		return errors.New("Cloudflare bootstrap requires one exact Cloudflare readiness resource")
	}
	identity := resource.Cloudflare
	if plan.Schema != realCloudCloudflareBootstrapPlanSchema || plan.Purpose != "dedicated-disposable-non-production-test" || plan.Ownership != realCloudCloudflareBootstrapOwnership {
		return errors.New("Cloudflare bootstrap plan schema, purpose, or ownership is invalid")
	}
	if plan.ReadinessResourceSHA256 != realCloudProviderReadinessResourceSHA(resource) ||
		plan.AccountID != identity.AccountID || plan.ZoneID != identity.ZoneID || plan.R2Bucket != identity.R2Bucket ||
		plan.MainBase != identity.CDNBase || plan.BetaBase != identity.BetaBase {
		return errors.New("Cloudflare bootstrap plan differs from the exact provider readiness identity")
	}
	publicKey, err := decodeRealCloudProviderReadinessPublicKey(plan.ReadinessSealPublicKey)
	if err != nil {
		return fmt.Errorf("Cloudflare bootstrap readiness seal key: %w", err)
	}
	clearRealCloudBytes(publicKey)
	if !validRealCloudProviderIdentifier(plan.AuthScript, 128) || !validRealCloudProviderIdentifier(plan.OriginScript, 128) ||
		plan.AuthScript == plan.OriginScript {
		return errors.New("Cloudflare bootstrap Worker identities are invalid or overlap")
	}
	if err := validateRealCloudCloudflareBootstrapVerifierShape(plan); err != nil {
		return err
	}
	parsedDate, err := time.Parse("2006-01-02", plan.CompatibilityDate)
	if err != nil || parsedDate.Format("2006-01-02") != plan.CompatibilityDate || len(plan.CompatibilityFlags) != 0 {
		return errors.New("Cloudflare bootstrap compatibility contract must use one canonical date and no unreviewed flags")
	}
	if err := validateRealCloudCloudflareBootstrapBundle(plan.AuthBundle, realCloudCloudflareAuthBundlePath); err != nil {
		return fmt.Errorf("Cloudflare auth bundle: %w", err)
	}
	if err := validateRealCloudCloudflareBootstrapBundle(plan.OriginBundle, realCloudCloudflareOriginBundlePath); err != nil {
		return fmt.Errorf("Cloudflare origin bundle: %w", err)
	}
	if err := validateRealCloudCloudflareBootstrapEdgeContract(plan.EdgeContract, *identity, plan); err != nil {
		return err
	}
	wantedRoutes := []realCloudCloudflareBootstrapRoute{
		{Pattern: strings.TrimPrefix(identity.BetaBase, "https://") + "/*", Script: plan.AuthScript},
		{Pattern: strings.TrimPrefix(identity.CDNBase, "https://") + "/*", Script: plan.AuthScript},
	}
	sort.Slice(wantedRoutes, func(i, j int) bool { return wantedRoutes[i].Pattern < wantedRoutes[j].Pattern })
	if len(plan.Routes) != len(wantedRoutes) {
		return errors.New("Cloudflare bootstrap plan must contain exactly main and beta auth routes")
	}
	for index := range wantedRoutes {
		if plan.Routes[index] != wantedRoutes[index] {
			return errors.New("Cloudflare bootstrap route closure differs from the exact main and beta hosts")
		}
	}
	return nil
}

func validateRealCloudCloudflareBootstrapVerifierShape(plan realCloudCloudflareBootstrapPlan) error {
	verifier, err := sowconfig.ParseTokenVerifierReference(plan.EdgeContract.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable])
	if err != nil || plan.TokenVerifierKind != verifier.Kind {
		return errors.New("Cloudflare bootstrap token-verifier kind differs from the edge contract")
	}
	switch verifier.Kind {
	case "provider":
		if plan.TokenVerifierService != verifier.Name || !validRealCloudProviderIdentifier(plan.TokenVerifierService, 128) ||
			!validRealCloudProviderOptionalIdentifier(plan.TokenVerifierEnvironment, 128) || plan.TokenVerifierSecret != "" ||
			plan.AuthScript == plan.TokenVerifierService || plan.OriginScript == plan.TokenVerifierService ||
			!validRealCloudLowerSHA256(plan.TokenVerifierContentSHA256) || !validRealCloudLowerSHA256(plan.TokenVerifierBindingsSHA256) {
			return errors.New("Cloudflare bootstrap provider token-verifier shape or evidence is invalid")
		}
		verifierDate, dateErr := time.Parse("2006-01-02", plan.TokenVerifierCompatibilityDate)
		if dateErr != nil || verifierDate.Format("2006-01-02") != plan.TokenVerifierCompatibilityDate || len(plan.TokenVerifierCompatibilityFlags) != 0 {
			return errors.New("Cloudflare bootstrap token-verifier runtime must use one canonical date and no unreviewed flags")
		}
	case "env":
		if plan.TokenVerifierSecret != verifier.Name || !validRealCloudCloudflareStaticSecretName(plan.TokenVerifierSecret) ||
			plan.TokenVerifierService != "" || plan.TokenVerifierEnvironment != "" || plan.TokenVerifierContentSHA256 != "" ||
			plan.TokenVerifierBindingsSHA256 != "" || plan.TokenVerifierCompatibilityDate != "" || len(plan.TokenVerifierCompatibilityFlags) != 0 {
			return errors.New("Cloudflare bootstrap static token-verifier shape contains missing or provider-only fields")
		}
	default:
		return errors.New("Cloudflare bootstrap token-verifier kind is unsupported")
	}
	return nil
}

func validRealCloudCloudflareRuntimeBindingName(name string) bool {
	reference, err := sowconfig.ParseTokenVerifierReference("env://" + name)
	return err == nil && reference.Kind == "env" && reference.Name == name
}

func validRealCloudCloudflareStaticSecretName(name string) bool {
	if !validRealCloudCloudflareRuntimeBindingName(name) {
		return false
	}
	for _, reserved := range []string{
		realCloudOptInEnv,
		realCloudProviderReadinessOptInEnv,
		realEdgeEvidenceOptInEnv,
		realCloudPurgeWatcherHelperEnv,
		realCloudConfirmationEnv,
		realCloudNonProductionEnv,
		realCloudRunIDEnv,
		realCloudStorageCredentialCF,
		realCloudCDNCredentialCF,
		realCloudProviderReadinessResourceEnv,
		realCloudRegistryOutputDirEnv,
		realCloudCloudflareBootstrapOptInEnv,
		realCloudCloudflareBootstrapPlanEnv,
		realCloudCloudflareBootstrapConfirmationEnv,
		realCloudCloudflareBootstrapReceiptEnv,
		realCloudCloudflareBootstrapReadinessReceiptEnv,
		realCloudCloudflareBootstrapRegistryOnboardEnv,
		realCloudCloudflareBootstrapPlanOnboardEnv,
		realCloudCloudflareBootstrapDescriptorEnv,
		realCloudCloudflareBootstrapEdgeContractFileEnv,
		sowconfig.EdgeRuntimeBasicEntitlementsVariable,
	} {
		if name == reserved {
			return false
		}
	}
	return true
}

func validateRealCloudCloudflareBootstrapBundle(bundle realCloudCloudflareBootstrapBundle, wantedPath string) error {
	if bundle.Path != wantedPath || !validRealCloudLowerSHA256(bundle.SHA256) {
		return errors.New("bundle path or SHA-256 is invalid")
	}
	body, err := readRealCloudProviderRepositoryFile(wantedPath, realCloudProviderMaxContentBytes)
	if err != nil {
		return errors.New("reviewed in-repository bundle is absent")
	}
	defer clearRealCloudBytes(body)
	if realCloudLowerSHA256(body) != bundle.SHA256 {
		return errors.New("bundle SHA-256 differs from the reviewed repository bytes")
	}
	return nil
}

func decodeRealCloudCloudflareBootstrapDescriptor(raw string) (realCloudCloudflareBootstrapDescriptor, error) {
	var descriptor realCloudCloudflareBootstrapDescriptor
	if raw == "" || raw != strings.TrimSpace(raw) {
		return descriptor, errors.New("missing or non-canonical Cloudflare bootstrap descriptor")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&descriptor); err != nil {
		return descriptor, errors.New("decode Cloudflare bootstrap descriptor")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return descriptor, errors.New("Cloudflare bootstrap descriptor contains trailing values")
	}
	canonical, err := json.Marshal(descriptor)
	if err != nil || raw != string(canonical) || descriptor.Schema != realCloudCloudflareBootstrapDescriptorSchema {
		return descriptor, errors.New("Cloudflare bootstrap descriptor must be canonical JSON with the exact schema")
	}
	return descriptor, nil
}

func readRealCloudCloudflareBootstrapEdgeContract(path string) (sowconfig.EdgeDeploymentContract, error) {
	var contract sowconfig.EdgeDeploymentContract
	if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return contract, errors.New("Cloudflare bootstrap edge contract path must be one clean absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 2<<20 {
		return contract, errors.New("Cloudflare bootstrap edge contract file is absent or unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return contract, errors.New("open Cloudflare bootstrap edge contract")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Size() != info.Size() {
		return contract, errors.New("Cloudflare bootstrap edge contract changed while opened")
	}
	body, err := io.ReadAll(io.LimitReader(file, 2<<20+1))
	if err != nil || int64(len(body)) != opened.Size() || len(body) > 2<<20 {
		return contract, errors.New("read exact Cloudflare bootstrap edge contract")
	}
	defer clearRealCloudBytes(body)
	after, err := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(opened, after) || !os.SameFile(opened, pathAfter) ||
		after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return contract, errors.New("Cloudflare bootstrap edge contract changed while read")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return contract, errors.New("decode Cloudflare bootstrap edge contract")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return contract, errors.New("Cloudflare bootstrap edge contract contains trailing values")
	}
	return contract, nil
}

func buildRealCloudCloudflareBootstrapPlan(
	resource realCloudProviderReadinessResource,
	descriptor realCloudCloudflareBootstrapDescriptor,
	contract sowconfig.EdgeDeploymentContract,
) (realCloudCloudflareBootstrapPlan, []byte, error) {
	var plan realCloudCloudflareBootstrapPlan
	if resource.Provider != "cloudflare" || resource.Cloudflare == nil || resource.EdgeOne != nil {
		return plan, nil, errors.New("Cloudflare bootstrap plan builder requires one Cloudflare readiness resource")
	}
	auth, err := readRealCloudProviderRepositoryFile(realCloudCloudflareAuthBundlePath, realCloudProviderMaxContentBytes)
	if err != nil {
		return plan, nil, err
	}
	defer clearRealCloudBytes(auth)
	origin, err := readRealCloudProviderRepositoryFile(realCloudCloudflareOriginBundlePath, realCloudProviderMaxContentBytes)
	if err != nil {
		return plan, nil, err
	}
	defer clearRealCloudBytes(origin)
	identity := resource.Cloudflare
	plan = realCloudCloudflareBootstrapPlan{
		Schema: realCloudCloudflareBootstrapPlanSchema, Purpose: "dedicated-disposable-non-production-test", Ownership: realCloudCloudflareBootstrapOwnership,
		ReadinessResourceSHA256: realCloudProviderReadinessResourceSHA(resource), ReadinessSealPublicKey: descriptor.ReadinessSealPublicKey,
		AccountID: identity.AccountID, ZoneID: identity.ZoneID,
		R2Bucket: identity.R2Bucket, MainBase: identity.CDNBase, BetaBase: identity.BetaBase,
		AuthScript: descriptor.AuthScript, OriginScript: descriptor.OriginScript,
		TokenVerifierKind:    descriptor.TokenVerifierKind,
		TokenVerifierService: descriptor.TokenVerifierService, TokenVerifierEnvironment: descriptor.TokenVerifierEnvironment,
		TokenVerifierSecret:        descriptor.TokenVerifierSecret,
		TokenVerifierContentSHA256: descriptor.TokenVerifierContentSHA256, TokenVerifierBindingsSHA256: descriptor.TokenVerifierBindingsSHA256,
		TokenVerifierCompatibilityDate:  descriptor.TokenVerifierCompatibilityDate,
		TokenVerifierCompatibilityFlags: append([]string(nil), descriptor.TokenVerifierCompatibilityFlags...),
		CompatibilityDate:               descriptor.CompatibilityDate, CompatibilityFlags: append([]string(nil), descriptor.CompatibilityFlags...),
		AuthBundle:   realCloudCloudflareBootstrapBundle{Path: realCloudCloudflareAuthBundlePath, SHA256: realCloudLowerSHA256(auth)},
		OriginBundle: realCloudCloudflareBootstrapBundle{Path: realCloudCloudflareOriginBundlePath, SHA256: realCloudLowerSHA256(origin)},
		EdgeContract: contract,
		Routes: []realCloudCloudflareBootstrapRoute{
			{Pattern: strings.TrimPrefix(identity.CDNBase, "https://") + "/*", Script: descriptor.AuthScript},
			{Pattern: strings.TrimPrefix(identity.BetaBase, "https://") + "/*", Script: descriptor.AuthScript},
		},
	}
	sort.Slice(plan.Routes, func(i, j int) bool { return plan.Routes[i].Pattern < plan.Routes[j].Pattern })
	if err := validateRealCloudCloudflareBootstrapPlan(plan, resource); err != nil {
		return realCloudCloudflareBootstrapPlan{}, nil, err
	}
	body, err := json.Marshal(plan)
	if err != nil {
		return realCloudCloudflareBootstrapPlan{}, nil, errors.New("encode canonical Cloudflare bootstrap plan")
	}
	return plan, body, nil
}

func validateRealCloudCloudflareBootstrapEdgeContract(contract sowconfig.EdgeDeploymentContract, identity realCloudCloudflareReadinessResource, plan realCloudCloudflareBootstrapPlan) error {
	if contract.Schema != sowconfig.EdgeRuntimeSchema || contract.Target != "cf" || contract.Runtime != "cloudflare" || len(contract.RequiredVariables) != 0 {
		return errors.New("Cloudflare bootstrap edge contract has an invalid runtime identity or external variable")
	}
	if err := sowconfig.ValidateEdgeDeploymentBindingNamespaces(contract); err != nil {
		return fmt.Errorf("Cloudflare bootstrap edge contract binding namespace: %w", err)
	}
	verifier, err := sowconfig.ParseTokenVerifierReference(contract.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable])
	if err != nil || verifier.Kind != plan.TokenVerifierKind {
		return errors.New("Cloudflare bootstrap edge contract has an invalid token-verifier reference")
	}
	switch verifier.Kind {
	case "provider":
		if verifier.Name != plan.TokenVerifierService || len(contract.RequiredSecrets) != 0 ||
			len(contract.ServiceBindings) != 2 || contract.ServiceBindings[0] != "ORIGIN" || contract.ServiceBindings[1] != "TOKEN_VERIFIER" {
			return errors.New("Cloudflare bootstrap edge contract is not the exact provider-service deployment shape")
		}
	case "env":
		if verifier.Name != plan.TokenVerifierSecret || len(contract.RequiredSecrets) != 1 || contract.RequiredSecrets[0] != verifier.Name ||
			len(contract.ServiceBindings) != 1 || contract.ServiceBindings[0] != "ORIGIN" {
			return errors.New("Cloudflare bootstrap edge contract is not the exact static-secret deployment shape")
		}
	default:
		return errors.New("Cloudflare bootstrap edge contract token-verifier kind is unsupported")
	}
	wantedKeys := []string{
		sowconfig.EdgeRuntimeBetaBaseURLVariable,
		sowconfig.EdgeRuntimeCompatibilityVariable,
		sowconfig.EdgeRuntimeOriginModeVariable,
		sowconfig.EdgeRuntimeProPrefixVariable,
		sowconfig.EdgeRuntimePublicBaseURLVariable,
		sowconfig.EdgeRuntimePublicKeysVariable,
		sowconfig.EdgeRuntimePublicPrefixesVariable,
		sowconfig.EdgeRuntimeSchemaVariable,
		sowconfig.EdgeRuntimeTokenVerifierVariable,
	}
	sort.Strings(wantedKeys)
	keys := make([]string, 0, len(contract.Variables))
	for key := range contract.Variables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) != len(wantedKeys) {
		return errors.New("Cloudflare bootstrap edge contract has an incomplete or excessive runtime variable set")
	}
	for index := range wantedKeys {
		if keys[index] != wantedKeys[index] {
			return errors.New("Cloudflare bootstrap edge contract has an unknown runtime variable")
		}
	}
	if contract.Variables[sowconfig.EdgeRuntimeSchemaVariable] != sowconfig.EdgeRuntimeSchema ||
		contract.Variables[sowconfig.EdgeRuntimeProPrefixVariable] != sowconfig.DefaultProPrefix ||
		contract.Variables[sowconfig.EdgeRuntimePublicBaseURLVariable] != identity.CDNBase ||
		contract.Variables[sowconfig.EdgeRuntimeBetaBaseURLVariable] != identity.BetaBase ||
		contract.Variables[sowconfig.EdgeRuntimeOriginModeVariable] != "r2-service" {
		return errors.New("Cloudflare bootstrap runtime variables differ from the exact R2-service topology")
	}
	for _, name := range []string{sowconfig.EdgeRuntimePublicPrefixesVariable, sowconfig.EdgeRuntimePublicKeysVariable} {
		var values []string
		raw := contract.Variables[name]
		if err := json.Unmarshal([]byte(raw), &values); err != nil || !validRealCloudProviderRouteList(values) {
			return errors.New("Cloudflare bootstrap public route allowlist is invalid")
		}
		canonical, _ := json.Marshal(values)
		if raw != string(canonical) {
			return errors.New("Cloudflare bootstrap public route allowlist is non-canonical")
		}
	}
	compatibility := contract.Variables[sowconfig.EdgeRuntimeCompatibilityVariable]
	if err := sowconfig.ValidateEdgeCompatibilityAdmissionJSON(compatibility); err != nil {
		return fmt.Errorf("Cloudflare bootstrap compatibility admission: %w", err)
	}
	return nil
}

func validateRealCloudCloudflareBootstrapSelection(mode string, getenv func(string) string) error {
	readinessRegistry, err := loadRealCloudPinnedProviderReadinessRegistry()
	if err != nil {
		return err
	}
	bootstrapRegistry, err := loadRealCloudCloudflareBootstrapRegistry()
	if err != nil {
		return err
	}
	return validateRealCloudCloudflareBootstrapSelectionAgainstRegistriesAt(
		mode, getenv, readinessRegistry, bootstrapRegistry, time.Now().UTC(),
	)
}

func validateRealCloudCloudflareBootstrapSelectionAgainstRegistries(
	mode string,
	getenv func(string) string,
	readinessRegistry realCloudPinnedProviderReadinessRegistry,
	bootstrapRegistry realCloudCloudflareBootstrapRegistry,
) error {
	return validateRealCloudCloudflareBootstrapSelectionAgainstRegistriesAt(
		mode, getenv, readinessRegistry, bootstrapRegistry, time.Now().UTC(),
	)
}

func validateRealCloudCloudflareBootstrapSelectionAgainstRegistriesAt(
	mode string,
	getenv func(string) string,
	readinessRegistry realCloudPinnedProviderReadinessRegistry,
	bootstrapRegistry realCloudCloudflareBootstrapRegistry,
	now time.Time,
) error {
	if mode != "apply" && mode != "rollback" && mode != "recover-lease" {
		return errors.New("Cloudflare bootstrap mode must be apply, rollback, or recover-lease")
	}
	if getenv(realCloudNonProductionEnv) != realCloudNonProductionPhrase {
		return fmt.Errorf("%s must explicitly confirm dedicated disposable non-production resources", realCloudNonProductionEnv)
	}
	if err := validateRealCloudProviderReadinessSelectionAgainstRegistry("cloudflare", getenv, readinessRegistry); err != nil {
		return fmt.Errorf("Cloudflare bootstrap readiness gate: %w", err)
	}
	resource, _, err := decodeRealCloudProviderReadinessResource(getenv(realCloudProviderReadinessResourceEnv))
	if err != nil {
		return err
	}
	plan, body, err := decodeRealCloudCloudflareBootstrapPlan(getenv(realCloudCloudflareBootstrapPlanEnv), resource)
	if err != nil {
		return err
	}
	planSHA := realCloudLowerSHA256(body)
	runID := getenv(realCloudRunIDEnv)
	if !validRealCloudRunID(runID) {
		return fmt.Errorf("%s must identify this exact Cloudflare bootstrap", realCloudRunIDEnv)
	}
	wantedConfirmation := realCloudCloudflareBootstrapConfirmation(mode, runID, planSHA, plan.AccountID, plan.ZoneID)
	if getenv(realCloudCloudflareBootstrapConfirmationEnv) != wantedConfirmation {
		return fmt.Errorf("%s must bind the exact mode, run, plan, account, and zone", realCloudCloudflareBootstrapConfirmationEnv)
	}
	approvedPlan := false
	for _, approved := range bootstrapRegistry.Plans {
		if approved.ReadinessResourceSHA256 == plan.ReadinessResourceSHA256 && approved.PlanSHA256 == planSHA {
			approvedPlan = true
			break
		}
	}
	if !approvedPlan {
		return errors.New("Cloudflare bootstrap plan is not present in the repository-pinned administrator-reviewed registry")
	}
	if mode == "apply" || mode == "rollback" {
		if err := validateRealCloudCloudflareBootstrapReadinessReceipt(
			getenv(realCloudCloudflareBootstrapReadinessReceiptEnv), resource, runID, plan.ReadinessSealPublicKey, now,
		); err != nil {
			return fmt.Errorf("Cloudflare bootstrap live readiness receipt: %w", err)
		}
	}
	return nil
}

func realCloudCloudflareBootstrapConfirmation(mode, runID, planSHA, accountID, zoneID string) string {
	return strings.Join([]string{
		"I AUTHORIZE SOW CLOUDFLARE NON-PRODUCTION BOOTSTRAP", strings.ToUpper(mode),
		"RUN", runID, "PLAN", planSHA, "ACCOUNT", accountID, "ZONE", zoneID,
	}, " ")
}

func buildRealCloudCloudflareBootstrapRegistryCandidate(
	registry realCloudCloudflareBootstrapRegistry,
	resource realCloudProviderReadinessResource,
	plan realCloudCloudflareBootstrapPlan,
) ([]byte, realCloudCloudflareBootstrapRegistryCandidateReceipt, error) {
	if registry.Schema != realCloudCloudflareBootstrapRegistrySchema || registry.Plans == nil {
		return nil, realCloudCloudflareBootstrapRegistryCandidateReceipt{}, errors.New("existing Cloudflare bootstrap registry is invalid")
	}
	if err := validateRealCloudCloudflareBootstrapPlan(plan, resource); err != nil {
		return nil, realCloudCloudflareBootstrapRegistryCandidateReceipt{}, err
	}
	planBody, err := json.Marshal(plan)
	if err != nil {
		return nil, realCloudCloudflareBootstrapRegistryCandidateReceipt{}, errors.New("encode Cloudflare bootstrap plan")
	}
	entry := realCloudCloudflareBootstrapRegistryEntry{
		Schema: realCloudCloudflareBootstrapRegistryEntrySchema, Purpose: "dedicated-disposable-non-production-test",
		ReadinessResourceSHA256: plan.ReadinessResourceSHA256, PlanSHA256: realCloudLowerSHA256(planBody),
	}
	found := false
	for _, existing := range registry.Plans {
		found = found || existing == entry
	}
	if !found {
		registry.Plans = append(registry.Plans, entry)
	}
	sort.Slice(registry.Plans, func(i, j int) bool {
		left := registry.Plans[i].ReadinessResourceSHA256 + "\x00" + registry.Plans[i].PlanSHA256
		right := registry.Plans[j].ReadinessResourceSHA256 + "\x00" + registry.Plans[j].PlanSHA256
		return left < right
	})
	body, err := json.Marshal(registry)
	if err != nil {
		return nil, realCloudCloudflareBootstrapRegistryCandidateReceipt{}, errors.New("encode Cloudflare bootstrap registry candidate")
	}
	body = append(body, '\n')
	if _, err := decodeRealCloudCloudflareBootstrapRegistry(body, realCloudLowerSHA256(body)); err != nil {
		return nil, realCloudCloudflareBootstrapRegistryCandidateReceipt{}, fmt.Errorf("self-validate Cloudflare bootstrap registry candidate: %w", err)
	}
	return body, realCloudCloudflareBootstrapRegistryCandidateReceipt{
		Schema:                  "sow-real-cloud-cloudflare-bootstrap-registry-candidate-receipt/v1",
		ReadinessResourceSHA256: entry.ReadinessResourceSHA256, PlanSHA256: entry.PlanSHA256, RegistrySHA256: realCloudLowerSHA256(body),
	}, nil
}

// TestRealCloudCloudflareBootstrapPlanOnboardingCandidate converts one
// state-admitted `sow materialize latest --edge-contract cf` document plus a
// secret-free verifier descriptor into the canonical bootstrap plan. It is
// offline and writes only to a private directory outside the repository.
func TestRealCloudCloudflareBootstrapPlanOnboardingCandidate(t *testing.T) {
	if os.Getenv(realCloudCloudflareBootstrapPlanOnboardEnv) != "1" {
		t.Skip("set SOW_RUN_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP_PLAN_ONBOARDING=1 to emit an offline Cloudflare bootstrap plan")
	}
	resource, _, err := decodeRealCloudProviderReadinessResource(os.Getenv(realCloudProviderReadinessResourceEnv))
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := decodeRealCloudCloudflareBootstrapDescriptor(os.Getenv(realCloudCloudflareBootstrapDescriptorEnv))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := readRealCloudCloudflareBootstrapEdgeContract(os.Getenv(realCloudCloudflareBootstrapEdgeContractFileEnv))
	if err != nil {
		t.Fatal(err)
	}
	plan, body, err := buildRealCloudCloudflareBootstrapPlan(resource, descriptor, contract)
	if err != nil {
		t.Fatal(err)
	}
	output := strings.TrimSpace(os.Getenv(realCloudRegistryOutputDirEnv))
	if output == "" || output != os.Getenv(realCloudRegistryOutputDirEnv) {
		t.Fatalf("%s must be one absolute path without surrounding whitespace", realCloudRegistryOutputDirEnv)
	}
	output = prepareRealCloudRegistryCandidateDirectory(t, output)
	writeRealCloudRegistryCandidate(t, filepath.Join(output, "real_cloud_cloudflare_bootstrap_plan.candidate.json"), append(body, '\n'))
	writeRealCloudExclusiveJSON(t, filepath.Join(output, "real_cloud_cloudflare_bootstrap_plan_candidate_receipt.json"), realCloudCloudflareBootstrapPlanCandidateReceipt{
		Schema: "sow-real-cloud-cloudflare-bootstrap-plan-candidate-receipt/v1", ReadinessResourceSHA256: plan.ReadinessResourceSHA256,
		PlanSHA256: realCloudLowerSHA256(body), AuthBundleSHA256: plan.AuthBundle.SHA256, OriginBundleSHA256: plan.OriginBundle.SHA256,
	})
	t.Logf("offline Cloudflare bootstrap plan written under %s plan_sha256=%s", output, realCloudLowerSHA256(body))
}

// TestRealCloudCloudflareBootstrapRegistryOnboardingCandidate is offline. It
// emits a private canonical review candidate outside the repository and never
// reads credentials, constructs a provider client, or sends a request.
func TestRealCloudCloudflareBootstrapRegistryOnboardingCandidate(t *testing.T) {
	if os.Getenv(realCloudCloudflareBootstrapRegistryOnboardEnv) != "1" {
		t.Skip("set SOW_RUN_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP_REGISTRY_ONBOARDING=1 to emit an offline Cloudflare bootstrap registry candidate")
	}
	resource, _, err := decodeRealCloudProviderReadinessResource(os.Getenv(realCloudProviderReadinessResourceEnv))
	if err != nil {
		t.Fatal(err)
	}
	plan, _, err := decodeRealCloudCloudflareBootstrapPlan(os.Getenv(realCloudCloudflareBootstrapPlanEnv), resource)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := loadRealCloudCloudflareBootstrapRegistry()
	if err != nil {
		t.Fatal(err)
	}
	body, receipt, err := buildRealCloudCloudflareBootstrapRegistryCandidate(registry, resource, plan)
	if err != nil {
		t.Fatal(err)
	}
	output := strings.TrimSpace(os.Getenv(realCloudRegistryOutputDirEnv))
	if output == "" || output != os.Getenv(realCloudRegistryOutputDirEnv) {
		t.Fatalf("%s must be one absolute path without surrounding whitespace", realCloudRegistryOutputDirEnv)
	}
	output = prepareRealCloudRegistryCandidateDirectory(t, output)
	writeRealCloudRegistryCandidate(t, filepath.Join(output, "real_cloud_nonproduction_cloudflare_bootstrap_registry.candidate.json"), body)
	writeRealCloudExclusiveJSON(t, filepath.Join(output, "real_cloud_cloudflare_bootstrap_registry_candidate_receipt.json"), receipt)
	t.Logf("offline Cloudflare bootstrap registry candidate written under %s plan_sha256=%s registry_sha256=%s", output, receipt.PlanSHA256, receipt.RegistrySHA256)
}

func realCloudCloudflareBootstrapPlanFixture(t *testing.T) (realCloudProviderReadinessResource, realCloudCloudflareBootstrapPlan) {
	t.Helper()
	resource := realCloudCloudflareReadinessFixture()
	signer, readinessSealPublicKey := newRealCloudProviderReadinessTestSigner(t)
	clearRealCloudBytes(signer)
	auth, err := readRealCloudProviderRepositoryFile(realCloudCloudflareAuthBundlePath, realCloudProviderMaxContentBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer clearRealCloudBytes(auth)
	origin, err := readRealCloudProviderRepositoryFile(realCloudCloudflareOriginBundlePath, realCloudProviderMaxContentBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer clearRealCloudBytes(origin)
	identity := resource.Cloudflare
	contract := sowconfig.EdgeDeploymentContract{
		Schema: sowconfig.EdgeRuntimeSchema, Target: "cf", Runtime: "cloudflare",
		Variables: map[string]string{
			sowconfig.EdgeRuntimeSchemaVariable:         sowconfig.EdgeRuntimeSchema,
			sowconfig.EdgeRuntimeProPrefixVariable:      sowconfig.DefaultProPrefix,
			sowconfig.EdgeRuntimePublicBaseURLVariable:  identity.CDNBase,
			sowconfig.EdgeRuntimeBetaBaseURLVariable:    identity.BetaBase,
			sowconfig.EdgeRuntimeTokenVerifierVariable:  "provider://pigsty-entitlements",
			sowconfig.EdgeRuntimePublicPrefixesVariable: `["apt","yum"]`,
			sowconfig.EdgeRuntimePublicKeysVariable:     `["keys/pigsty.asc"]`,
			sowconfig.EdgeRuntimeCompatibilityVariable:  `{"apt_roots":[],"yum_repos":[],"yum_roots":[],"yum_channels":[],"asset_roots":[],"asset_keys":[],"projections":[],"snapshots":[],"raw":[],"active":[]}`,
			sowconfig.EdgeRuntimeOriginModeVariable:     "r2-service",
		},
		ServiceBindings: []string{"ORIGIN", "TOKEN_VERIFIER"},
	}
	plan := realCloudCloudflareBootstrapPlan{
		Schema: realCloudCloudflareBootstrapPlanSchema, Purpose: "dedicated-disposable-non-production-test", Ownership: realCloudCloudflareBootstrapOwnership,
		ReadinessResourceSHA256: realCloudProviderReadinessResourceSHA(resource), ReadinessSealPublicKey: readinessSealPublicKey,
		AccountID: identity.AccountID, ZoneID: identity.ZoneID,
		R2Bucket: identity.R2Bucket, MainBase: identity.CDNBase, BetaBase: identity.BetaBase,
		AuthScript: "sow-test-pro-auth", OriginScript: "sow-test-pro-origin", TokenVerifierKind: "provider", TokenVerifierService: "pigsty-entitlements",
		TokenVerifierContentSHA256: strings.Repeat("a", 64), TokenVerifierBindingsSHA256: strings.Repeat("b", 64),
		TokenVerifierCompatibilityDate: "2026-07-17", TokenVerifierCompatibilityFlags: []string{},
		CompatibilityDate: "2026-07-17", CompatibilityFlags: []string{},
		AuthBundle:   realCloudCloudflareBootstrapBundle{Path: realCloudCloudflareAuthBundlePath, SHA256: realCloudLowerSHA256(auth)},
		OriginBundle: realCloudCloudflareBootstrapBundle{Path: realCloudCloudflareOriginBundlePath, SHA256: realCloudLowerSHA256(origin)},
		EdgeContract: contract,
		Routes: []realCloudCloudflareBootstrapRoute{
			{Pattern: strings.TrimPrefix(identity.BetaBase, "https://") + "/*", Script: "sow-test-pro-auth"},
			{Pattern: strings.TrimPrefix(identity.CDNBase, "https://") + "/*", Script: "sow-test-pro-auth"},
		},
	}
	sort.Slice(plan.Routes, func(i, j int) bool { return plan.Routes[i].Pattern < plan.Routes[j].Pattern })
	return resource, plan
}

func realCloudCloudflareStaticBootstrapPlanFixture(t *testing.T) (realCloudProviderReadinessResource, realCloudCloudflareBootstrapPlan) {
	t.Helper()
	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	const secret = "SOW_TOKEN_ENTITLEMENTS"
	plan.TokenVerifierKind = "env"
	plan.TokenVerifierService = ""
	plan.TokenVerifierEnvironment = ""
	plan.TokenVerifierSecret = secret
	plan.TokenVerifierContentSHA256 = ""
	plan.TokenVerifierBindingsSHA256 = ""
	plan.TokenVerifierCompatibilityDate = ""
	plan.TokenVerifierCompatibilityFlags = []string{}
	plan.EdgeContract.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable] = "env://" + secret
	plan.EdgeContract.RequiredSecrets = []string{secret}
	plan.EdgeContract.ServiceBindings = []string{"ORIGIN"}
	if err := validateRealCloudCloudflareBootstrapPlan(plan, resource); err != nil {
		t.Fatalf("static Cloudflare bootstrap fixture: %v", err)
	}
	return resource, plan
}

func TestRealCloudCloudflareBootstrapRegistryIsIndependentAndPinned(t *testing.T) {
	registry, err := loadRealCloudCloudflareBootstrapRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if registry.Schema != realCloudCloudflareBootstrapRegistrySchema || registry.Plans == nil {
		t.Fatalf("unexpected shipped Cloudflare bootstrap registry: %+v", registry)
	}
	body, err := readRealCloudProviderRepositoryFile(realCloudCloudflareBootstrapRegistryPath, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRealCloudCloudflareBootstrapRegistry(append(append([]byte(nil), body...), ' '), realCloudCloudflareBootstrapRegistrySHA256); err == nil {
		t.Fatal("mutated Cloudflare bootstrap registry bypassed the compiled SHA-256 pin")
	}
}

func TestRealCloudCloudflareBootstrapPlanIsClosedAndDeterministic(t *testing.T) {
	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	if err := validateRealCloudCloudflareBootstrapPlan(plan, resource); err != nil {
		t.Fatal(err)
	}
	empty := realCloudCloudflareBootstrapRegistry{Schema: realCloudCloudflareBootstrapRegistrySchema, Plans: []realCloudCloudflareBootstrapRegistryEntry{}}
	firstBody, firstReceipt, err := buildRealCloudCloudflareBootstrapRegistryCandidate(empty, resource, plan)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeRealCloudCloudflareBootstrapRegistry(firstBody, firstReceipt.RegistrySHA256)
	if err != nil {
		t.Fatal(err)
	}
	secondBody, secondReceipt, err := buildRealCloudCloudflareBootstrapRegistryCandidate(decoded, resource, plan)
	if err != nil || !bytes.Equal(firstBody, secondBody) || firstReceipt != secondReceipt {
		t.Fatalf("Cloudflare bootstrap registry candidate is not deterministic err=%v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*realCloudCloudflareBootstrapPlan)
	}{
		{"bucket drift", func(value *realCloudCloudflareBootstrapPlan) { value.R2Bucket = "other" }},
		{"invalid readiness seal key", func(value *realCloudCloudflareBootstrapPlan) { value.ReadinessSealPublicKey = strings.Repeat("0", 64) }},
		{"production route", func(value *realCloudCloudflareBootstrapPlan) { value.Routes[0].Pattern = "repo.pigsty.io/*" }},
		{"origin public route", func(value *realCloudCloudflareBootstrapPlan) { value.Routes[0].Script = value.OriginScript }},
		{"bundle drift", func(value *realCloudCloudflareBootstrapPlan) { value.AuthBundle.SHA256 = strings.Repeat("f", 64) }},
		{"secret variable", func(value *realCloudCloudflareBootstrapPlan) {
			value.EdgeContract.Variables["SOW_SECRET"] = "forbidden"
		}},
		{"cache flag", func(value *realCloudCloudflareBootstrapPlan) {
			value.CompatibilityFlags = []string{"global_fetch_private_origin"}
		}},
		{"verifier overlap", func(value *realCloudCloudflareBootstrapPlan) { value.TokenVerifierService = value.AuthScript }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidateBody, _ := json.Marshal(plan)
			var candidate realCloudCloudflareBootstrapPlan
			if err := json.Unmarshal(candidateBody, &candidate); err != nil {
				t.Fatal(err)
			}
			test.mutate(&candidate)
			if err := validateRealCloudCloudflareBootstrapPlan(candidate, resource); err == nil {
				t.Fatal("unsafe Cloudflare bootstrap plan was accepted")
			}
		})
	}
}

func TestRealCloudCloudflareStaticBootstrapPlanIsClosedAndDeterministic(t *testing.T) {
	resource, plan := realCloudCloudflareStaticBootstrapPlanFixture(t)
	body, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	decoded, decodedBody, err := decodeRealCloudCloudflareBootstrapPlan(string(body), resource)
	if err != nil || !bytes.Equal(body, decodedBody) || decoded.TokenVerifierKind != "env" || decoded.TokenVerifierSecret != "SOW_TOKEN_ENTITLEMENTS" {
		t.Fatalf("static Cloudflare bootstrap plan did not round-trip exactly err=%v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*realCloudCloudflareBootstrapPlan)
	}{
		{"provider service retained", func(value *realCloudCloudflareBootstrapPlan) { value.TokenVerifierService = "pigsty-entitlements" }},
		{"service name collision", func(value *realCloudCloudflareBootstrapPlan) {
			value.TokenVerifierSecret = "ORIGIN"
			value.EdgeContract.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable] = "env://ORIGIN"
			value.EdgeContract.RequiredSecrets = []string{"ORIGIN"}
		}},
		{"plain variable name collision", func(value *realCloudCloudflareBootstrapPlan) {
			value.TokenVerifierSecret = sowconfig.EdgeRuntimePublicBaseURLVariable
			value.EdgeContract.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable] = "env://" + sowconfig.EdgeRuntimePublicBaseURLVariable
			value.EdgeContract.RequiredSecrets = []string{sowconfig.EdgeRuntimePublicBaseURLVariable}
		}},
		{"bootstrap control env collision", func(value *realCloudCloudflareBootstrapPlan) {
			value.TokenVerifierSecret = realCloudCDNCredentialCF
			value.EdgeContract.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable] = "env://" + realCloudCDNCredentialCF
			value.EdgeContract.RequiredSecrets = []string{realCloudCDNCredentialCF}
		}},
		{"readiness process env collision", func(value *realCloudCloudflareBootstrapPlan) {
			value.TokenVerifierSecret = realCloudProviderReadinessOptInEnv
			value.EdgeContract.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable] = "env://" + realCloudProviderReadinessOptInEnv
			value.EdgeContract.RequiredSecrets = []string{realCloudProviderReadinessOptInEnv}
		}},
		{"edge evidence process env collision", func(value *realCloudCloudflareBootstrapPlan) {
			value.TokenVerifierSecret = realEdgeEvidenceOptInEnv
			value.EdgeContract.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable] = "env://" + realEdgeEvidenceOptInEnv
			value.EdgeContract.RequiredSecrets = []string{realEdgeEvidenceOptInEnv}
		}},
		{"purge watcher process env collision", func(value *realCloudCloudflareBootstrapPlan) {
			value.TokenVerifierSecret = realCloudPurgeWatcherHelperEnv
			value.EdgeContract.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable] = "env://" + realCloudPurgeWatcherHelperEnv
			value.EdgeContract.RequiredSecrets = []string{realCloudPurgeWatcherHelperEnv}
		}},
		{"basic entitlement authority collision", func(value *realCloudCloudflareBootstrapPlan) {
			value.TokenVerifierSecret = sowconfig.EdgeRuntimeBasicEntitlementsVariable
			value.EdgeContract.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable] = "env://" + sowconfig.EdgeRuntimeBasicEntitlementsVariable
			value.EdgeContract.RequiredSecrets = []string{sowconfig.EdgeRuntimeBasicEntitlementsVariable}
		}},
		{"provider digest retained", func(value *realCloudCloudflareBootstrapPlan) {
			value.TokenVerifierContentSHA256 = strings.Repeat("a", 64)
		}},
		{"secret name drift", func(value *realCloudCloudflareBootstrapPlan) { value.TokenVerifierSecret = "OTHER_SECRET" }},
		{"service binding added", func(value *realCloudCloudflareBootstrapPlan) {
			value.EdgeContract.ServiceBindings = []string{"ORIGIN", "TOKEN_VERIFIER"}
		}},
		{"secret binding omitted", func(value *realCloudCloudflareBootstrapPlan) { value.EdgeContract.RequiredSecrets = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidateBody, _ := json.Marshal(plan)
			var candidate realCloudCloudflareBootstrapPlan
			if err := json.Unmarshal(candidateBody, &candidate); err != nil {
				t.Fatal(err)
			}
			test.mutate(&candidate)
			if err := validateRealCloudCloudflareBootstrapPlan(candidate, resource); err == nil {
				t.Fatal("mixed static/provider bootstrap plan was accepted")
			}
		})
	}
	leadingUnderscore := plan
	leadingUnderscore.TokenVerifierSecret = "_SOW_TOKEN_ENTITLEMENTS"
	leadingUnderscore.EdgeContract.Variables = make(map[string]string, len(plan.EdgeContract.Variables))
	for name, value := range plan.EdgeContract.Variables {
		leadingUnderscore.EdgeContract.Variables[name] = value
	}
	leadingUnderscore.EdgeContract.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable] = "env://_SOW_TOKEN_ENTITLEMENTS"
	leadingUnderscore.EdgeContract.RequiredSecrets = []string{"_SOW_TOKEN_ENTITLEMENTS"}
	if err := validateRealCloudCloudflareBootstrapPlan(leadingUnderscore, resource); err != nil {
		t.Fatalf("product-valid leading-underscore secret binding was rejected: %v", err)
	}
}

func TestRealCloudCloudflareBootstrapPlanBuilderConsumesExactEdgeContract(t *testing.T) {
	resource, fixture := realCloudCloudflareBootstrapPlanFixture(t)
	descriptor := realCloudCloudflareBootstrapDescriptor{
		Schema: realCloudCloudflareBootstrapDescriptorSchema, ReadinessSealPublicKey: fixture.ReadinessSealPublicKey,
		AuthScript: fixture.AuthScript, OriginScript: fixture.OriginScript, TokenVerifierKind: fixture.TokenVerifierKind,
		TokenVerifierService: fixture.TokenVerifierService, TokenVerifierEnvironment: fixture.TokenVerifierEnvironment,
		TokenVerifierSecret:        fixture.TokenVerifierSecret,
		TokenVerifierContentSHA256: fixture.TokenVerifierContentSHA256, TokenVerifierBindingsSHA256: fixture.TokenVerifierBindingsSHA256,
		TokenVerifierCompatibilityDate:  fixture.TokenVerifierCompatibilityDate,
		TokenVerifierCompatibilityFlags: append([]string(nil), fixture.TokenVerifierCompatibilityFlags...),
		CompatibilityDate:               fixture.CompatibilityDate, CompatibilityFlags: []string{},
	}
	first, firstBody, err := buildRealCloudCloudflareBootstrapPlan(resource, descriptor, fixture.EdgeContract)
	if err != nil {
		t.Fatal(err)
	}
	_, secondBody, err := buildRealCloudCloudflareBootstrapPlan(resource, descriptor, fixture.EdgeContract)
	if err != nil || !bytes.Equal(firstBody, secondBody) || first.ReadinessResourceSHA256 != fixture.ReadinessResourceSHA256 ||
		first.AuthBundle != fixture.AuthBundle || first.OriginBundle != fixture.OriginBundle {
		t.Fatalf("Cloudflare bootstrap plan builder is not deterministic or repository-bound err=%v", err)
	}
	bad := descriptor
	bad.TokenVerifierContentSHA256 = strings.Repeat("f", 63)
	if _, _, err := buildRealCloudCloudflareBootstrapPlan(resource, bad, fixture.EdgeContract); err == nil {
		t.Fatal("Cloudflare bootstrap plan builder accepted an invalid verifier digest")
	}
	contract := fixture.EdgeContract
	contract.Variables[sowconfig.EdgeRuntimePublicBaseURLVariable] = "https://repo.pigsty.io"
	if _, _, err := buildRealCloudCloudflareBootstrapPlan(resource, descriptor, contract); err == nil {
		t.Fatal("Cloudflare bootstrap plan builder accepted a production/drifted edge contract")
	}
}

func TestRealCloudCloudflareBootstrapPlanBuilderConsumesStaticEdgeContract(t *testing.T) {
	resource, fixture := realCloudCloudflareStaticBootstrapPlanFixture(t)
	descriptor := realCloudCloudflareBootstrapDescriptor{
		Schema: realCloudCloudflareBootstrapDescriptorSchema, ReadinessSealPublicKey: fixture.ReadinessSealPublicKey,
		AuthScript: fixture.AuthScript, OriginScript: fixture.OriginScript, TokenVerifierKind: fixture.TokenVerifierKind,
		TokenVerifierSecret: fixture.TokenVerifierSecret, TokenVerifierCompatibilityFlags: []string{},
		CompatibilityDate: fixture.CompatibilityDate, CompatibilityFlags: []string{},
	}
	first, firstBody, err := buildRealCloudCloudflareBootstrapPlan(resource, descriptor, fixture.EdgeContract)
	if err != nil {
		t.Fatal(err)
	}
	_, secondBody, err := buildRealCloudCloudflareBootstrapPlan(resource, descriptor, fixture.EdgeContract)
	if err != nil || !bytes.Equal(firstBody, secondBody) || first.TokenVerifierSecret != fixture.TokenVerifierSecret || first.TokenVerifierService != "" {
		t.Fatalf("static Cloudflare bootstrap plan builder is not deterministic or closed err=%v", err)
	}
	bad := descriptor
	bad.TokenVerifierService = "pigsty-entitlements"
	if _, _, err := buildRealCloudCloudflareBootstrapPlan(resource, bad, fixture.EdgeContract); err == nil {
		t.Fatal("static Cloudflare bootstrap descriptor retained provider-only fields")
	}
}

func TestRealCloudCloudflareBootstrapPlanBuilderConsumesGeneratedStaticProductContract(t *testing.T) {
	resource, fixture := realCloudCloudflareStaticBootstrapPlanFixture(t)
	environment := realCloudProviderReadinessEnvironment(resource)
	product := realCloudConfigForEnvironment(environment)
	product.Edge.TokenVerifier = "env://" + fixture.TokenVerifierSecret
	contract, err := product.EdgeDeployment("cf")
	if err != nil {
		t.Fatal(err)
	}
	descriptor := realCloudCloudflareBootstrapDescriptor{
		Schema: realCloudCloudflareBootstrapDescriptorSchema, ReadinessSealPublicKey: fixture.ReadinessSealPublicKey,
		AuthScript: fixture.AuthScript, OriginScript: fixture.OriginScript, TokenVerifierKind: "env",
		TokenVerifierSecret: fixture.TokenVerifierSecret, TokenVerifierCompatibilityFlags: []string{},
		CompatibilityDate: fixture.CompatibilityDate, CompatibilityFlags: []string{},
	}
	plan, _, err := buildRealCloudCloudflareBootstrapPlan(resource, descriptor, contract)
	if err != nil {
		t.Fatal(err)
	}
	if plan.EdgeContract.Variables[sowconfig.EdgeRuntimeTokenVerifierVariable] != "env://"+fixture.TokenVerifierSecret ||
		len(plan.EdgeContract.RequiredSecrets) != 1 || plan.EdgeContract.RequiredSecrets[0] != fixture.TokenVerifierSecret ||
		len(plan.EdgeContract.ServiceBindings) != 1 || plan.EdgeContract.ServiceBindings[0] != "ORIGIN" {
		t.Fatalf("generated product contract lost the static verifier shape: %+v", plan.EdgeContract)
	}
}

func TestRealCloudCloudflareBootstrapSelectionFailsBeforeCredentials(t *testing.T) {
	resource, plan := realCloudCloudflareBootstrapPlanFixture(t)
	signer, signerPublicKey := newRealCloudProviderReadinessTestSigner(t)
	defer clearRealCloudBytes(signer)
	plan.ReadinessSealPublicKey = signerPublicKey
	planBody, _ := json.Marshal(plan)
	entry := realCloudCloudflareBootstrapRegistryEntry{
		Schema: realCloudCloudflareBootstrapRegistryEntrySchema, Purpose: "dedicated-disposable-non-production-test",
		ReadinessResourceSHA256: plan.ReadinessResourceSHA256, PlanSHA256: realCloudLowerSHA256(planBody),
	}
	readiness := realCloudPinnedProviderReadinessRegistry{Schema: realCloudProviderReadinessRegistrySchema, Resources: []realCloudProviderReadinessResource{resource}}
	bootstrap := realCloudCloudflareBootstrapRegistry{Schema: realCloudCloudflareBootstrapRegistrySchema, Plans: []realCloudCloudflareBootstrapRegistryEntry{entry}}
	resourceBody, _ := json.Marshal(resource)
	runID := "20260717T120000Z-selection"
	planSHA := realCloudLowerSHA256(planBody)
	now := time.Now().UTC()
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	readinessPath := filepath.Join(private, "bootstrap-readiness.json")
	readinessReceipt := realCloudProviderReadinessReceipt{
		Schema: realCloudProviderReadinessReceiptSchema, RunID: runID, Provider: "cloudflare",
		ReadinessResourceSHA256: realCloudProviderReadinessResourceSHA(resource),
		BucketIdentitySHA256:    strings.Repeat("b", 64), ProviderControlSHA256: strings.Repeat("c", 64),
		BucketObservedEmpty: true, ProviderOperations: "read-only:list-objects-v2+zone-and-domain-identity",
		BucketControlClosureSHA256: realCloudProviderEmptyReadinessBucketObservation().ControlClosureSHA256,
		ObservedAt:                 now.Format(time.RFC3339Nano),
	}
	writeRealCloudProviderReadinessReceipt(t, readinessPath, readinessReceipt, signer)
	values := map[string]string{
		realCloudNonProductionEnv:                       realCloudNonProductionPhrase,
		realCloudProviderReadinessResourceEnv:           string(resourceBody),
		realCloudCloudflareBootstrapPlanEnv:             string(planBody),
		realCloudRunIDEnv:                               runID,
		realCloudCloudflareBootstrapConfirmationEnv:     realCloudCloudflareBootstrapConfirmation("apply", runID, planSHA, plan.AccountID, plan.ZoneID),
		realCloudCloudflareBootstrapReadinessReceiptEnv: readinessPath,
		realCloudStorageCredentialCF:                    "deliberately-invalid-and-must-not-be-read-by-selection",
		realCloudCDNCredentialCF:                        "deliberately-invalid-and-must-not-be-read-by-selection",
	}
	credentialReads := 0
	getenv := func(name string) string {
		if name == realCloudStorageCredentialCF || name == realCloudCDNCredentialCF {
			credentialReads++
		}
		return values[name]
	}
	if err := validateRealCloudCloudflareBootstrapSelectionAgainstRegistriesAt("apply", getenv, readiness, bootstrap, now); err != nil {
		t.Fatalf("exact registered bootstrap selection rejected before credential parsing: %v", err)
	}
	if credentialReads != 0 {
		t.Fatalf("apply selection read credentials before all safety gates reads=%d", credentialReads)
	}
	values[realCloudCloudflareBootstrapConfirmationEnv] = realCloudCloudflareBootstrapConfirmation("rollback", runID, planSHA, plan.AccountID, plan.ZoneID)
	if err := validateRealCloudCloudflareBootstrapSelectionAgainstRegistriesAt("rollback", getenv, readiness, bootstrap, now); err != nil {
		t.Fatalf("exact registered rollback selection rejected before credential parsing: %v", err)
	}
	if credentialReads != 0 {
		t.Fatalf("rollback selection read credentials before all safety gates reads=%d", credentialReads)
	}
	legacyMarkerReceipt := readinessReceipt
	legacyMarkerReceipt.BucketObservedEmpty = false
	legacyMarkerReceipt.BucketControlObjectCount = 1
	legacyMarkerReceipt.BucketControlObjectKey = ".sow/bootstrap/leases/" + planSHA + ".json"
	legacyMarkerReceipt.BucketControlClosureSHA256 = strings.Repeat("d", 64)
	legacyMarkerReceipt.ProviderOperations = "read-only:list-objects-v2+get-idle-bootstrap-lease+zone-and-domain-identity"
	legacyReadinessPath := filepath.Join(private, "legacy-plan-key-readiness.json")
	writeRealCloudProviderReadinessReceipt(t, legacyReadinessPath, legacyMarkerReceipt, signer)
	values[realCloudCloudflareBootstrapReadinessReceiptEnv] = legacyReadinessPath
	if err := validateRealCloudCloudflareBootstrapSelectionAgainstRegistriesAt("rollback", getenv, readiness, bootstrap, now); err == nil || !strings.Contains(err.Error(), "resource closure") {
		t.Fatalf("bootstrap selection accepted a signed legacy plan-key marker before credentials: %v", err)
	}
	if credentialReads != 0 {
		t.Fatalf("legacy marker rejection read credentials reads=%d", credentialReads)
	}
	values[realCloudCloudflareBootstrapReadinessReceiptEnv] = readinessPath
	delete(values, realCloudCloudflareBootstrapReadinessReceiptEnv)
	if err := validateRealCloudCloudflareBootstrapSelectionAgainstRegistriesAt("rollback", getenv, readiness, bootstrap, now); err == nil || !strings.Contains(err.Error(), "live readiness receipt") {
		t.Fatalf("rollback accepted a missing pre-credential readiness receipt: %v", err)
	}
	if credentialReads != 0 {
		t.Fatalf("failed rollback readiness gate read credentials reads=%d", credentialReads)
	}
	values[realCloudCloudflareBootstrapReadinessReceiptEnv] = readinessPath
	values[realCloudCloudflareBootstrapConfirmationEnv] = realCloudCloudflareBootstrapConfirmation("recover-lease", runID, planSHA, plan.AccountID, plan.ZoneID)
	if err := validateRealCloudCloudflareBootstrapSelectionAgainstRegistries("recover-lease", getenv, readiness, bootstrap); err != nil {
		t.Fatalf("exact registered expired-lease recovery selection rejected: %v", err)
	}
	values[realCloudCloudflareBootstrapConfirmationEnv] = realCloudCloudflareBootstrapConfirmation("apply", runID, planSHA, plan.AccountID, plan.ZoneID)
	delete(values, realCloudCloudflareBootstrapConfirmationEnv)
	if err := validateRealCloudCloudflareBootstrapSelectionAgainstRegistries("apply", getenv, readiness, bootstrap); err == nil {
		t.Fatal("missing exact mutation authorization was accepted")
	}
	values[realCloudCloudflareBootstrapConfirmationEnv] = realCloudCloudflareBootstrapConfirmation("apply", runID, planSHA, plan.AccountID, plan.ZoneID)
	bootstrap.Plans = []realCloudCloudflareBootstrapRegistryEntry{}
	if err := validateRealCloudCloudflareBootstrapSelectionAgainstRegistries("apply", getenv, readiness, bootstrap); err == nil || !strings.Contains(err.Error(), "repository-pinned") {
		t.Fatalf("unregistered Cloudflare bootstrap plan was accepted: %v", err)
	}
}
