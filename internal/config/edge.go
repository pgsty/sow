package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	// EdgeRuntimeSchema versions the non-secret environment contract consumed by
	// both deployable edge adapters. It is deliberately separate from Schema so
	// an edge-only rollout cannot silently reinterpret the repository config.
	EdgeRuntimeSchema = "sow-edge-runtime/v2"

	EdgeRuntimeSchemaVariable         = "SOW_EDGE_SCHEMA"
	EdgeRuntimeProPrefixVariable      = "SOW_PRO_PREFIX"
	EdgeRuntimePublicBaseURLVariable  = "SOW_PUBLIC_BASE_URL"
	EdgeRuntimeBetaBaseURLVariable    = "SOW_BETA_BASE_URL"
	EdgeRuntimeTokenVerifierVariable  = "SOW_TOKEN_VERIFIER"
	EdgeRuntimePublicPrefixesVariable = "SOW_PUBLIC_PREFIXES"
	EdgeRuntimePublicKeysVariable     = "SOW_PUBLIC_KEYS"
	EdgeRuntimeCompatibilityVariable  = "SOW_COMPATIBILITY_ADMISSION"
	EdgeRuntimeOriginModeVariable     = "SOW_ORIGIN_MODE"
	// EdgeRuntimeBasicEntitlementsVariable is an optional independent fallback
	// authority consumed by both edge adapters. A token verifier must never
	// alias it or one entitlement document would authorize two credential forms.
	EdgeRuntimeBasicEntitlementsVariable = "SOW_BASIC_ENTITLEMENTS"
)

var tokenVerifierProviderPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
var environmentNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
var edgeOneCOSBucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]+-[1-9][0-9]{4,19}$`)

type TokenVerifierReference struct {
	Kind string
	Name string
}

// ParseTokenVerifierReference accepts the two closed deployment transports in
// schema v1. The URI is a reference, never a secret value:
//
//   - env://NAME reads a strict entitlement document from a platform secret.
//   - provider://ID calls the target-specific production verifier transport.
//
// Provider IDs are included in verifier requests, so they are not decorative
// labels and cannot be changed without changing the authorization contract.
func ParseTokenVerifierReference(value string) (TokenVerifierReference, error) {
	if len(value) > 256 {
		return TokenVerifierReference{}, errors.New("reference is longer than 256 bytes")
	}
	if strings.HasPrefix(value, "env://") {
		name := strings.TrimPrefix(value, "env://")
		if len(name) > 128 || !environmentNamePattern.MatchString(name) {
			return TokenVerifierReference{}, errors.New("must use env:// followed by an uppercase environment binding name")
		}
		return TokenVerifierReference{Kind: "env", Name: name}, nil
	}
	if strings.HasPrefix(value, "provider://") {
		name := strings.TrimPrefix(value, "provider://")
		if len(name) > 128 || !tokenVerifierProviderPattern.MatchString(name) {
			return TokenVerifierReference{}, errors.New("must use provider:// followed by a lowercase provider ID")
		}
		return TokenVerifierReference{Kind: "provider", Name: name}, nil
	}
	return TokenVerifierReference{}, errors.New("must be an env://NAME secret binding or provider://id verifier reference")
}

// EdgeDeploymentContract is the secret-free bridge from sow.yaml to a vendor
// deployment. Variables are safe to render into deployment configuration;
// RequiredSecrets and ServiceBindings contain names only, never their values.
type EdgeDeploymentContract struct {
	Schema            string            `json:"schema"`
	Target            string            `json:"target"`
	Runtime           string            `json:"runtime"`
	Variables         map[string]string `json:"variables"`
	RequiredVariables []string          `json:"required_variables,omitempty"`
	RequiredSecrets   []string          `json:"required_secrets,omitempty"`
	ServiceBindings   []string          `json:"service_bindings,omitempty"`
}

// ValidateEdgeDeploymentBindingNamespaces rejects a deployment that assigns
// one runtime name to more than one binding kind. Workers and EdgeOne expose
// these collections in one environment namespace; accepting a plain value,
// service, or secret collision would make provider behavior ambiguous.
func ValidateEdgeDeploymentBindingNamespaces(contract EdgeDeploymentContract) error {
	type namedBinding struct {
		name string
		kind string
	}
	bindings := make([]namedBinding, 0, len(contract.Variables)+len(contract.RequiredVariables)+len(contract.RequiredSecrets)+len(contract.ServiceBindings))
	variableNames := make([]string, 0, len(contract.Variables))
	for name := range contract.Variables {
		variableNames = append(variableNames, name)
	}
	sort.Strings(variableNames)
	for _, name := range variableNames {
		bindings = append(bindings, namedBinding{name: name, kind: "plain variable"})
	}
	for _, group := range []struct {
		kind  string
		names []string
	}{
		{kind: "required variable", names: contract.RequiredVariables},
		{kind: "secret", names: contract.RequiredSecrets},
		{kind: "service", names: contract.ServiceBindings},
	} {
		names := append([]string(nil), group.names...)
		sort.Strings(names)
		for _, name := range names {
			bindings = append(bindings, namedBinding{name: name, kind: group.kind})
		}
	}
	seen := make(map[string]string, len(bindings))
	for _, binding := range bindings {
		if !environmentNamePattern.MatchString(binding.name) || len(binding.name) > 128 {
			return fmt.Errorf("edge deployment %s binding %q is not a valid runtime name", binding.kind, binding.name)
		}
		if previous, exists := seen[binding.name]; exists {
			return fmt.Errorf("edge deployment binding %q collides between %s and %s", binding.name, previous, binding.kind)
		}
		seen[binding.name] = binding.kind
	}
	return nil
}

// EdgeCompatibilityAdmission is a caller-proven projection of canonical
// migration state. Raw IDs own an exact S0/S1/rollback or active physical
// bridge. Active IDs are the raw subset whose append-only cutover ledger is
// currently active. Configuration membership alone grants neither capability.
type EdgeCompatibilityAdmission struct {
	RawIDs    []string
	ActiveIDs []string
	Snapshots []EdgeSnapshotAdmission
}

// EdgeSnapshotAdmission is the immutable ownership closure for one canonical
// snapshot ref set. It is deliberately separate from current active/view
// routes so EOL snapshots remain addressable after their repositories leave
// the mutable configuration, without granting a sibling snapshot access to
// those historical roots.
type EdgeSnapshotAdmission struct {
	ID         string   `json:"id"`
	APTRoots   []string `json:"apt_roots"`
	YUMRoots   []string `json:"yum_roots"`
	AssetRoots []string `json:"asset_roots"`
	AssetKeys  []string `json:"asset_keys"`
}

type edgeCompatibilityProjection struct {
	ID   string `json:"id"`
	Root string `json:"root"`
	View string `json:"view"`
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type edgeYUMChannel struct {
	View string `json:"view"`
	Repo string `json:"repo"`
	OS   string `json:"os"`
	Arch string `json:"arch"`
	Root string `json:"root"`
}

type edgeCompatibilityRuntime struct {
	APTRoots    []string                      `json:"apt_roots"`
	YUMRepos    []string                      `json:"yum_repos"`
	YUMRoots    []string                      `json:"yum_roots"`
	YUMChannels []edgeYUMChannel              `json:"yum_channels"`
	AssetRoots  []string                      `json:"asset_roots"`
	AssetKeys   []string                      `json:"asset_keys"`
	Projections []edgeCompatibilityProjection `json:"projections"`
	Snapshots   []EdgeSnapshotAdmission       `json:"snapshots"`
	Raw         []string                      `json:"raw"`
	Active      []string                      `json:"active"`
}

// ValidateEdgeCompatibilityAdmissionJSON validates the complete serialized
// compatibility contract consumed by both edge runtimes. It is intentionally
// exported so deployment/bootstrap admission can reuse the same semantic
// checks instead of treating nested projection, channel, and snapshot records
// as opaque JSON.
func ValidateEdgeCompatibilityAdmissionJSON(raw string) error {
	if raw == "" || len(raw) > 1<<20 {
		return errors.New("edge compatibility admission is empty or exceeds 1 MiB")
	}
	var runtime edgeCompatibilityRuntime
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&runtime); err != nil {
		return fmt.Errorf("decode edge compatibility admission: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("edge compatibility admission contains trailing values")
	}
	if runtime.APTRoots == nil || runtime.YUMRepos == nil || runtime.YUMRoots == nil || runtime.YUMChannels == nil ||
		runtime.AssetRoots == nil || runtime.AssetKeys == nil || runtime.Projections == nil || runtime.Snapshots == nil ||
		runtime.Raw == nil || runtime.Active == nil {
		return errors.New("edge compatibility admission omits a required array")
	}
	for field, routes := range map[string][]string{
		"apt_roots": runtime.APTRoots, "yum_roots": runtime.YUMRoots, "asset_roots": runtime.AssetRoots, "asset_keys": runtime.AssetKeys,
	} {
		if err := validateSortedUniqueEdgeRoutes(field, routes); err != nil {
			return err
		}
	}
	if err := validateSortedUniqueEdgeNames("yum_repos", runtime.YUMRepos); err != nil {
		return err
	}
	yumRepos := make(map[string]struct{}, len(runtime.YUMRepos))
	for _, id := range runtime.YUMRepos {
		yumRepos[id] = struct{}{}
	}
	yumRoots := make(map[string]struct{}, len(runtime.YUMRoots))
	for _, root := range runtime.YUMRoots {
		yumRoots[root] = struct{}{}
	}
	previousChannel := ""
	for index, channel := range runtime.YUMChannels {
		identity := strings.Join([]string{channel.View, channel.Repo, channel.OS, channel.Arch, channel.Root}, "\x00")
		if index > 0 && identity <= previousChannel {
			return errors.New("edge compatibility yum_channels are not strictly sorted and unique")
		}
		previousChannel = identity
		if channel.View != "beta" && channel.View != "latest" && channel.View != "stable" {
			return fmt.Errorf("edge compatibility YUM channel %d has an invalid view", index)
		}
		if _, exists := yumRepos[channel.Repo]; !exists {
			return fmt.Errorf("edge compatibility YUM channel %d references an unknown repo", index)
		}
		if err := validateName("edge compatibility YUM OS", channel.OS); err != nil {
			return err
		}
		if err := validateName("edge compatibility YUM architecture", channel.Arch); err != nil {
			return err
		}
		if err := validateRoutePath(channel.Root); err != nil {
			return fmt.Errorf("edge compatibility YUM channel %d root: %w", index, err)
		}
		if _, exists := yumRoots[channel.Root]; !exists {
			return fmt.Errorf("edge compatibility YUM channel %d root is not admitted by yum_roots", index)
		}
	}
	projectionIDs := make(map[string]struct{}, len(runtime.Projections))
	previousProjection := ""
	for index, projection := range runtime.Projections {
		if err := validateName("edge compatibility projection", projection.ID); err != nil {
			return err
		}
		if index > 0 && projection.ID <= previousProjection {
			return errors.New("edge compatibility projections are not strictly sorted and unique")
		}
		previousProjection = projection.ID
		if err := validateRoutePath(projection.Root); err != nil || !hasPathNamespace(projection.Root, "yum") {
			return fmt.Errorf("edge compatibility projection %s has an invalid YUM root", projection.ID)
		}
		if projection.View != "beta" && projection.View != "latest" && projection.View != "stable" {
			return fmt.Errorf("edge compatibility projection %s has an invalid view", projection.ID)
		}
		if err := validateName("edge compatibility projection OS", projection.OS); err != nil {
			return err
		}
		if err := validateName("edge compatibility projection architecture", projection.Arch); err != nil {
			return err
		}
		if path.Base(projection.Root) != projection.Arch {
			return fmt.Errorf("edge compatibility projection %s root does not end in its architecture", projection.ID)
		}
		projectionIDs[projection.ID] = struct{}{}
	}
	if err := validateSortedUniqueEdgeNames("raw", runtime.Raw); err != nil {
		return err
	}
	if err := validateSortedUniqueEdgeNames("active", runtime.Active); err != nil {
		return err
	}
	rawIDs := make(map[string]struct{}, len(runtime.Raw))
	for _, id := range runtime.Raw {
		if _, exists := projectionIDs[id]; !exists {
			return fmt.Errorf("edge compatibility raw projection %q is not declared", id)
		}
		rawIDs[id] = struct{}{}
	}
	for _, id := range runtime.Active {
		if _, exists := rawIDs[id]; !exists {
			return fmt.Errorf("edge compatibility active projection %q lacks a raw bridge", id)
		}
	}
	normalizedSnapshots, err := validateEdgeSnapshotAdmissions(runtime.Snapshots)
	if err != nil {
		return err
	}
	writtenSnapshots, _ := json.Marshal(runtime.Snapshots)
	normalizedSnapshotBody, _ := json.Marshal(normalizedSnapshots)
	if string(writtenSnapshots) != string(normalizedSnapshotBody) {
		return errors.New("edge compatibility snapshots are not canonically sorted and unique")
	}
	canonical, err := json.Marshal(runtime)
	if err != nil || raw != string(canonical) {
		return errors.New("edge compatibility admission is not canonical JSON")
	}
	return nil
}

func validateSortedUniqueEdgeRoutes(field string, values []string) error {
	for index, value := range values {
		if index > 0 && value <= values[index-1] {
			return fmt.Errorf("edge compatibility %s is not strictly sorted and unique", field)
		}
		if err := validateRoutePath(value); err != nil {
			return fmt.Errorf("edge compatibility %s route %q: %w", field, value, err)
		}
	}
	return nil
}

func validateSortedUniqueEdgeNames(field string, values []string) error {
	for index, value := range values {
		if index > 0 && value <= values[index-1] {
			return fmt.Errorf("edge compatibility %s is not strictly sorted and unique", field)
		}
		if err := validateName("edge compatibility "+field, value); err != nil {
			return err
		}
	}
	return nil
}

// EdgeDeployment maps one validated target to the exact runtime contract its
// executable adapter consumes. Cloudflare provider verification uses a service
// binding; EdgeOne uses an HTTPS endpoint plus a bearer secret. env:// uses the
// named secret directly on either runtime.
func (c *Config) EdgeDeployment(targetName string, admissions ...EdgeCompatibilityAdmission) (EdgeDeploymentContract, error) {
	if len(admissions) > 1 {
		return EdgeDeploymentContract{}, errors.New("edge deployment accepts at most one compatibility admission")
	}
	admission := EdgeCompatibilityAdmission{}
	if len(admissions) == 1 {
		admission = admissions[0]
	}
	target, ok := c.Targets[targetName]
	if !ok {
		return EdgeDeploymentContract{}, fmt.Errorf("edge deployment target %q is not configured", targetName)
	}
	verifier, err := ParseTokenVerifierReference(c.Edge.TokenVerifier)
	if err != nil {
		return EdgeDeploymentContract{}, fmt.Errorf("edge.token_verifier: %w", err)
	}
	if verifier.Kind == "env" && verifier.Name == EdgeRuntimeBasicEntitlementsVariable {
		return EdgeDeploymentContract{}, errors.New("edge.token_verifier must not alias the independent Basic entitlement binding")
	}
	publicPrefixes, publicKeys, compatibility, err := c.edgePublicRouteAllowlists(targetName, admission)
	if err != nil {
		return EdgeDeploymentContract{}, err
	}
	contract := EdgeDeploymentContract{
		Schema:  EdgeRuntimeSchema,
		Target:  targetName,
		Runtime: target.CDN.Kind,
		Variables: map[string]string{
			EdgeRuntimeSchemaVariable:         EdgeRuntimeSchema,
			EdgeRuntimeProPrefixVariable:      c.Edge.ProPrefix,
			EdgeRuntimePublicBaseURLVariable:  target.CDN.BaseURL,
			EdgeRuntimeBetaBaseURLVariable:    target.CDN.BetaBaseURL,
			EdgeRuntimeTokenVerifierVariable:  c.Edge.TokenVerifier,
			EdgeRuntimePublicPrefixesVariable: publicPrefixes,
			EdgeRuntimePublicKeysVariable:     publicKeys,
			EdgeRuntimeCompatibilityVariable:  compatibility,
		},
	}
	switch target.CDN.Kind {
	case "cloudflare":
		contract.Variables[EdgeRuntimeOriginModeVariable] = "r2-service"
		contract.ServiceBindings = append(contract.ServiceBindings, "ORIGIN")
		if verifier.Kind == "provider" {
			contract.ServiceBindings = append(contract.ServiceBindings, "TOKEN_VERIFIER")
		} else {
			contract.RequiredSecrets = append(contract.RequiredSecrets, verifier.Name)
		}
	case "edgeone":
		if !edgeOneCOSBucketPattern.MatchString(target.Storage.Bucket) {
			return EdgeDeploymentContract{}, fmt.Errorf("target %s storage.bucket must include the numeric COS app ID suffix", targetName)
		}
		contract.Variables[EdgeRuntimeOriginModeVariable] = "cos-sigv4"
		contract.Variables["SOW_COS_REGION"] = target.Storage.Region
		contract.Variables["SOW_COS_BUCKET"] = target.Storage.Bucket
		contract.RequiredSecrets = append(contract.RequiredSecrets, "SOW_COS_SECRET_ID", "SOW_COS_SECRET_KEY")
		if verifier.Kind == "provider" {
			contract.RequiredVariables = append(contract.RequiredVariables, "SOW_TOKEN_VERIFIER_URL")
			contract.RequiredSecrets = append(contract.RequiredSecrets, "SOW_TOKEN_VERIFIER_BEARER")
		} else {
			contract.RequiredSecrets = append(contract.RequiredSecrets, verifier.Name)
		}
	default:
		return EdgeDeploymentContract{}, fmt.Errorf("target %s has unsupported edge runtime %q", targetName, target.CDN.Kind)
	}
	sort.Strings(contract.RequiredVariables)
	sort.Strings(contract.RequiredSecrets)
	sort.Strings(contract.ServiceBindings)
	if err := ValidateEdgeDeploymentBindingNamespaces(contract); err != nil {
		return EdgeDeploymentContract{}, err
	}
	return contract, nil
}

// edgePublicRouteAllowlists serializes the target-specific public projection
// understood by shared/contract.mjs. APT/YUM and bounded asset roots are
// boundary-aware prefixes; root-mapped assets and the public trust anchor are
// exact object keys. Compact, sorted JSON is part of the runtime contract so a
// vendor configuration cannot reinterpret a delimiter, widen an exact key, or
// expose a repository assigned only to the sibling target.
func (c *Config) edgePublicRouteAllowlists(targetName string, admission EdgeCompatibilityAdmission) (string, string, string, error) {
	prefixes, keys := []string{}, []string{}
	runtime := edgeCompatibilityRuntime{
		APTRoots: []string{}, YUMRepos: []string{}, YUMRoots: []string{}, YUMChannels: []edgeYUMChannel{},
		AssetRoots: []string{}, AssetKeys: []string{}, Projections: []edgeCompatibilityProjection{}, Snapshots: []EdgeSnapshotAdmission{}, Raw: []string{}, Active: []string{},
	}
	keyClaims := make(map[string]string)
	repoByID := make(map[string]Repo, len(c.Repos))
	for _, repo := range c.Repos {
		repoByID[repo.ID] = repo
	}
	viewRepos := make(map[string]map[string]struct{}, len(c.Views))
	for name, view := range c.Views {
		members := make(map[string]struct{}, len(view.Repos))
		for _, repoID := range view.Repos {
			members[repoID] = struct{}{}
		}
		viewRepos[name] = members
	}
	repoInView := func(viewName, repoID string) bool {
		view, exists := c.Views[viewName]
		if !exists {
			return false
		}
		if len(view.Repos) == 0 {
			return true
		}
		_, exists = viewRepos[viewName][repoID]
		return exists
	}
	repoInAnyView := func(repoID string) bool {
		for _, viewName := range []string{"beta", "latest", "stable"} {
			if repoInView(viewName, repoID) {
				return true
			}
		}
		return false
	}
	appendExactKey := func(key, claim string, sharedMutableTrust bool) error {
		if previous, exists := keyClaims[key]; exists {
			if sharedMutableTrust && previous == "mutable-trust" {
				return nil
			}
			return fmt.Errorf("edge public exact key %q is claimed by both %s and %s for target %s", key, previous, claim, targetName)
		}
		if sharedMutableTrust {
			keyClaims[key] = "mutable-trust"
		} else {
			keyClaims[key] = claim
		}
		keys = append(keys, key)
		return nil
	}
	for _, repo := range c.Repos {
		if !repo.IsActive() || !repo.PublishesToTarget(targetName) || !repoInAnyView(repo.ID) ||
			repo.Type == "yum" && repo.YUM != nil && repo.YUM.CompatibilityCarrier {
			continue
		}
		if repo.Type == "asset" {
			if repo.Asset == nil {
				return "", "", "", fmt.Errorf("edge public routes for repo %s: asset contract is missing", repo.ID)
			}
			if publicRoot := repo.AssetPublicRoot(); publicRoot == "." {
				for _, key := range repo.Asset.RootKeys {
					if err := appendExactKey(key, "asset repo "+repo.ID, false); err != nil {
						return "", "", "", err
					}
					runtime.AssetKeys = append(runtime.AssetKeys, key)
				}
			} else {
				prefixes = append(prefixes, publicRoot)
				runtime.AssetRoots = append(runtime.AssetRoots, publicRoot)
			}
			continue
		}
		if repo.Type == "yum" && repo.YUM != nil && repo.YUM.PackageKeyring != "" {
			if err := validateRoutePath(repo.YUM.PackageKeyring); err != nil {
				return "", "", "", fmt.Errorf("repo %s yum.package_keyring is not edge-routable: %w", repo.ID, err)
			}
			if err := appendExactKey(repo.YUM.PackageKeyring, "YUM package trust for repo "+repo.ID, true); err != nil {
				return "", "", "", err
			}
		}
		expanded, err := repo.ExpandedPaths()
		if err != nil {
			return "", "", "", fmt.Errorf("edge public routes for repo %s: %w", repo.ID, err)
		}
		prefixes = append(prefixes, expanded...)
		switch repo.Type {
		case "apt":
			runtime.APTRoots = append(runtime.APTRoots, expanded...)
		case "yum":
			runtime.YUMRepos = append(runtime.YUMRepos, repo.ID)
			runtime.YUMRoots = append(runtime.YUMRoots, expanded...)
			for _, viewName := range []string{"beta", "latest", "stable"} {
				if !repoInView(viewName, repo.ID) {
					continue
				}
				for _, osName := range repo.OSSelectorValues() {
					for archIndex, arch := range repo.Arches {
						root := expanded[archIndex]
						runtime.YUMChannels = append(runtime.YUMChannels, edgeYUMChannel{View: viewName, Repo: repo.ID, OS: osName, Arch: arch, Root: root})
					}
				}
			}
		}
	}

	configured := make(map[string]YUMCompatibilityProjection)
	for _, projection := range c.CompatibilityProjections {
		owner, exists := repoByID[projection.Source.Repo]
		if !exists || owner.Type != "yum" {
			return "", "", "", fmt.Errorf("edge public routes for compatibility projection %s: source owner %s is unavailable", projection.ID, projection.Source.Repo)
		}
		if owner.PublishesToTarget(targetName) {
			configured[projection.ID] = projection
			runtime.Projections = append(runtime.Projections, edgeCompatibilityProjection{
				ID: projection.ID, Root: projection.Root, View: projection.Source.View, OS: projection.Source.OS, Arch: projection.Source.Arch,
			})
		}
	}
	raw, err := validateEdgeCompatibilityIDs("raw", admission.RawIDs, configured, nil)
	if err != nil {
		return "", "", "", err
	}
	active, err := validateEdgeCompatibilityIDs("active", admission.ActiveIDs, configured, raw)
	if err != nil {
		return "", "", "", err
	}
	for _, id := range sortedEdgeCompatibilityIDs(raw) {
		prefixes = append(prefixes, configured[id].Root)
		runtime.Raw = append(runtime.Raw, id)
	}
	for _, id := range sortedEdgeCompatibilityIDs(active) {
		runtime.Active = append(runtime.Active, id)
		if err := appendExactKey(YUMCompatibilityRepositoryTrustRoute(id), "compatibility repository trust "+id, false); err != nil {
			return "", "", "", err
		}
		if err := appendExactKey(YUMCompatibilityPackageTrustRoute(id), "compatibility package trust "+id, false); err != nil {
			return "", "", "", err
		}
	}
	runtime.Snapshots, err = validateEdgeSnapshotAdmissions(admission.Snapshots)
	if err != nil {
		return "", "", "", err
	}
	sort.Slice(runtime.Projections, func(i, j int) bool { return runtime.Projections[i].ID < runtime.Projections[j].ID })
	sort.Slice(runtime.YUMChannels, func(i, j int) bool {
		left := runtime.YUMChannels[i]
		right := runtime.YUMChannels[j]
		if left.View != right.View {
			return left.View < right.View
		}
		if left.Repo != right.Repo {
			return left.Repo < right.Repo
		}
		if left.OS != right.OS {
			return left.OS < right.OS
		}
		return left.Arch < right.Arch
	})
	sort.Strings(runtime.APTRoots)
	sort.Strings(runtime.YUMRepos)
	sort.Strings(runtime.YUMRoots)
	sort.Strings(runtime.AssetRoots)
	sort.Strings(runtime.AssetKeys)
	sort.Strings(prefixes)
	if c.GPG.PublicKey != "" {
		if err := validateRoutePath(c.GPG.PublicKey); err != nil {
			return "", "", "", fmt.Errorf("gpg.public_key is not edge-routable: %w", err)
		}
		if err := appendExactKey(c.GPG.PublicKey, "repository metadata trust", true); err != nil {
			return "", "", "", err
		}
	}
	sort.Strings(keys)
	if duplicate := firstSortedDuplicate(prefixes); duplicate != "" {
		return "", "", "", fmt.Errorf("edge public prefix %q is duplicated for target %s", duplicate, targetName)
	}
	prefixJSON, err := json.Marshal(prefixes)
	if err != nil {
		return "", "", "", fmt.Errorf("encode edge public prefixes: %w", err)
	}
	keyJSON, err := json.Marshal(keys)
	if err != nil {
		return "", "", "", fmt.Errorf("encode edge public keys: %w", err)
	}
	compatibilityJSON, err := json.Marshal(runtime)
	if err != nil {
		return "", "", "", fmt.Errorf("encode edge compatibility admission: %w", err)
	}
	if err := ValidateEdgeCompatibilityAdmissionJSON(string(compatibilityJSON)); err != nil {
		return "", "", "", fmt.Errorf("validate encoded edge compatibility admission: %w", err)
	}
	return string(prefixJSON), string(keyJSON), string(compatibilityJSON), nil
}

var edgeSnapshotIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*-[0-9]{8}$`)

func validateEdgeSnapshotAdmissions(values []EdgeSnapshotAdmission) ([]EdgeSnapshotAdmission, error) {
	result := make([]EdgeSnapshotAdmission, len(values))
	copy(result, values)
	for index := range result {
		value := &result[index]
		if !edgeSnapshotIDPattern.MatchString(value.ID) {
			return nil, fmt.Errorf("edge snapshot admission %q has an invalid snapshot ID", value.ID)
		}
		for name, routes := range map[string]*[]string{
			"APT roots": &value.APTRoots, "YUM roots": &value.YUMRoots, "asset roots": &value.AssetRoots, "asset keys": &value.AssetKeys,
		} {
			*routes = append([]string{}, (*routes)...)
			sort.Strings(*routes)
			if duplicate := firstSortedDuplicate(*routes); duplicate != "" {
				return nil, fmt.Errorf("edge snapshot %s %s contain duplicate route %q", value.ID, name, duplicate)
			}
			for _, route := range *routes {
				if err := validateRoutePath(route); err != nil {
					return nil, fmt.Errorf("edge snapshot %s %s route %q: %w", value.ID, name, route, err)
				}
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	for index := 1; index < len(result); index++ {
		if result[index-1].ID == result[index].ID {
			return nil, fmt.Errorf("edge snapshot admission %q is duplicated", result[index].ID)
		}
	}
	return result, nil
}

func validateEdgeCompatibilityIDs(kind string, ids []string, configured map[string]YUMCompatibilityProjection, required map[string]struct{}) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, duplicate := result[id]; duplicate {
			return nil, fmt.Errorf("edge %s compatibility projection %q is admitted more than once", kind, id)
		}
		if _, exists := configured[id]; !exists {
			return nil, fmt.Errorf("edge %s compatibility projection %q is not configured for this target", kind, id)
		}
		if required != nil {
			if _, exists := required[id]; !exists {
				return nil, fmt.Errorf("edge active compatibility projection %q lacks a proven raw bridge", id)
			}
		}
		result[id] = struct{}{}
	}
	return result, nil
}

func sortedEdgeCompatibilityIDs(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for id := range values {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func firstSortedDuplicate(values []string) string {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return values[index]
		}
	}
	return ""
}
