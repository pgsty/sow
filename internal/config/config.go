package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

const (
	Schema                        = "sow/v1"
	StateDirectory                = ".sow"
	PoolDirectory                 = ".pool"
	SnapshotIDFormat              = "<suite>-YYYYMMDD"
	DefaultProPrefix              = "/pro/v1/{token}/"
	DefaultSnapshotAge            = 6
	DefaultAPTByHashRetention     = 2
	DefaultYUMGenerationRetention = 2
	DefaultCASHistory             = 32
	MaxServingBaseURLBytes        = 2048
	EL8FrozenSincePigstyVersion   = "v5.0.0"
	YUMNoarchReplicate            = "replicate"
	YUMNoarchSeparate             = "separate"
	StorageDeleteConditional      = "conditional"
	StorageDeleteCheckpointFenced = "checkpoint-fenced"
	MaxConfigBytes                = 8 << 20
)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$`)
var bucketPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$`)
var providerIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,256}$`)
var regionPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

type Config struct {
	Schema                   string                       `yaml:"schema"`
	State                    StateConfig                  `yaml:"state"`
	GPG                      GPGConfig                    `yaml:"gpg"`
	Pools                    map[string]Pool              `yaml:"pools"`
	Repos                    []Repo                       `yaml:"repos"`
	RepoGroups               map[string][]string          `yaml:"repo_groups,omitempty"`
	CompatibilityProjections []YUMCompatibilityProjection `yaml:"compatibility_projections,omitempty"`
	Upstreams                []Upstream                   `yaml:"upstreams"`
	Views                    map[string]View              `yaml:"views"`
	Serving                  ServingConfig                `yaml:"serving,omitempty"`
	Targets                  map[string]Target            `yaml:"targets"`
	Edge                     EdgeConfig                   `yaml:"edge"`

	Path string `yaml:"-"`
	Root string `yaml:"-"`

	// CanonicalBaseline* is populated by the CLI at command load time and is
	// deliberately excluded from the schema. It supplies stale-writer CAS
	// evidence to local state transactions without changing canonical YAML.
	CanonicalBaselineKnown  bool   `yaml:"-"`
	CanonicalBaselineExists bool   `yaml:"-"`
	CanonicalBaselineSHA256 string `yaml:"-"`
	CanonicalBaselineSize   int64  `yaml:"-"`
}

type StateConfig struct {
	SnapshotMaterializationMonths int `yaml:"snapshot_materialization_months,omitempty"`
	APTByHashRetention            int `yaml:"apt_by_hash_retention,omitempty"`
	YUMGenerationRetention        int `yaml:"yum_generation_retention,omitempty"`
	CASHistoryCommits             int `yaml:"cas_history_commits,omitempty"`
}

type GPGConfig struct {
	PublicKey  string `yaml:"public_key,omitempty"`
	PrivateKey string `yaml:"private_key,omitempty"`
	Passphrase string `yaml:"passphrase,omitempty"`
}

type Pool struct{}

type Repo struct {
	ID             string       `yaml:"id"`
	Type           string       `yaml:"type"`
	Path           string       `yaml:"path"`
	OS             OSConfig     `yaml:"os,omitempty"`
	Arches         []string     `yaml:"arches,omitempty"`
	DefaultPool    string       `yaml:"default_pool"`
	Active         *bool        `yaml:"active,omitempty"`
	Include        []string     `yaml:"include,omitempty"`
	Exclude        []string     `yaml:"exclude,omitempty"`
	PublishTargets []string     `yaml:"publish_targets,omitempty"`
	APT            *APTConfig   `yaml:"apt,omitempty"`
	YUM            *YUMConfig   `yaml:"yum,omitempty"`
	Asset          *AssetConfig `yaml:"asset,omitempty"`

	// yaml.v3 maps an absent sequence and an explicit null to the same nil
	// slice. Keep source presence so publish_targets: null cannot silently mean
	// the intentionally different "all configured targets" default.
	publishTargetsPresent bool `yaml:"-"`
}

func (r Repo) IsActive() bool { return r.Active == nil || *r.Active }

// PublishesToTarget applies the target-affinity default without copying the
// Config target map into every Repo. Callers iterate configured targets; an
// omitted publish_targets list therefore means all of them, including targets
// added by a later canonical configuration revision.
func (r Repo) PublishesToTarget(target string) bool {
	return len(r.PublishTargets) == 0 || containsString(r.PublishTargets, target)
}

// AssetPublicRoot returns the normalized public ownership root. Decode stores
// the default explicitly, while the Path fallback keeps manually constructed
// Repo values and older serialized test fixtures backward compatible.
func (r Repo) AssetPublicRoot() string {
	if r.Type == "asset" && r.Asset != nil && r.Asset.PublicPath != "" {
		return r.Asset.PublicPath
	}
	return r.Path
}

type OSConfig struct {
	Family    string `yaml:"family,omitempty"`
	Major     int    `yaml:"major,omitempty"`
	Suite     string `yaml:"suite,omitempty"`
	Lifecycle string `yaml:"lifecycle,omitempty"`
}

type APTConfig struct {
	Suites          []string            `yaml:"suites"`
	Components      []string            `yaml:"components"`
	SuiteComponents map[string][]string `yaml:"suite_components,omitempty"`
	SuiteLifecycle  map[string]string   `yaml:"suite_lifecycle,omitempty"`

	// yaml.v3 decodes both an absent optional mapping and an explicit null to a
	// nil Go map. Preserve source-key presence separately so `{}` and `null`
	// cannot bypass the exact-coverage contract and silently fall back to the
	// legacy rectangular schema.
	suiteComponentsPresent bool `yaml:"-"`
	suiteLifecyclePresent  bool `yaml:"-"`
}

func (a *APTConfig) hasSuiteComponents() bool {
	return a != nil && (a.suiteComponentsPresent || a.SuiteComponents != nil)
}

func (a *APTConfig) hasSuiteLifecycle() bool {
	return a != nil && (a.suiteLifecyclePresent || a.SuiteLifecycle != nil)
}

// ComponentsForSuite returns the exact component contract for one suite. The
// legacy rectangular schema remains the default when suite_components is not
// declared. The returned slice is detached so selector and recovery code can
// narrow it without mutating the canonical configuration.
func (a *APTConfig) ComponentsForSuite(suite string) []string {
	return append([]string(nil), a.componentsForSuite(suite)...)
}

// componentsForSuite is the allocation-free internal form. Validation and
// topology preflight only inspect canonical configuration and must not create
// one detached slice per membership check.
func (a *APTConfig) componentsForSuite(suite string) []string {
	if a == nil {
		return nil
	}
	if a.hasSuiteComponents() {
		return a.SuiteComponents[suite]
	}
	return a.Components
}

func (a *APTConfig) HasComponent(suite, component string) bool {
	return containsString(a.componentsForSuite(suite), component)
}

// NarrowSuites makes a deep, self-contained APT selection. In particular, a
// one-suite selection carries only that suite's component union and lifecycle
// map, so durable recovery hashes cannot silently widen back to a rectangular
// repository contract.
func (a *APTConfig) NarrowSuites(suites []string) *APTConfig {
	if a == nil {
		return nil
	}
	selected := make(map[string]struct{}, len(suites))
	for _, suite := range suites {
		selected[suite] = struct{}{}
	}
	result := &APTConfig{Suites: append([]string(nil), suites...)}
	if !a.hasSuiteComponents() {
		result.Components = append([]string(nil), a.Components...)
	} else {
		result.suiteComponentsPresent = true
		result.SuiteComponents = make(map[string][]string, len(suites))
		used := make(map[string]struct{})
		for _, suite := range suites {
			values := append([]string(nil), a.SuiteComponents[suite]...)
			result.SuiteComponents[suite] = values
			for _, component := range values {
				used[component] = struct{}{}
			}
		}
		for _, component := range a.Components {
			if _, exists := used[component]; exists {
				result.Components = append(result.Components, component)
			}
		}
	}
	if a.hasSuiteLifecycle() {
		result.suiteLifecyclePresent = true
		result.SuiteLifecycle = make(map[string]string, len(suites))
		for suite, lifecycle := range a.SuiteLifecycle {
			if _, exists := selected[suite]; exists {
				result.SuiteLifecycle[suite] = lifecycle
			}
		}
	}
	return result
}

type YUMConfig struct {
	Compression          string `yaml:"compression"`
	PackageKeyring       string `yaml:"package_keyring,omitempty"`
	NoarchMode           string `yaml:"noarch_mode,omitempty"`
	CompatibilityCarrier bool   `yaml:"compatibility_carrier,omitempty"`

	// An omitted noarch_mode preserves the schema-v1 replication contract.
	// Explicit empty/null values are invalid rather than silently selecting a
	// package-routing policy the operator did not actually declare.
	noarchModePresent       bool `yaml:"-"`
	packageKeyringDefaulted bool `yaml:"-"`
}

type AssetConfig struct {
	Kind             string   `yaml:"kind,omitempty"`
	MutablePaths     []string `yaml:"mutable_paths,omitempty"`
	PublicPath       string   `yaml:"public_path,omitempty"`
	RootKeys         []string `yaml:"root_keys,omitempty"`
	InventoryCarrier bool     `yaml:"inventory_carrier,omitempty"`

	// Presence is part of validation even though it is not part of canonical
	// YAML: explicit empty/null declarations are invalid contracts, whereas an
	// absent public_path selects the repo.path compatibility default.
	publicPathPresent bool `yaml:"-"`
	rootKeysPresent   bool `yaml:"-"`
}

type Upstream struct {
	ID         string   `yaml:"id"`
	Type       string   `yaml:"type"`
	Repo       string   `yaml:"repo"`
	URL        string   `yaml:"url"`
	Suite      string   `yaml:"suite,omitempty"`
	Components []string `yaml:"components,omitempty"`
	Arches     []string `yaml:"arches,omitempty"`
	Allow      []string `yaml:"allow,omitempty"`
	Deny       []string `yaml:"deny,omitempty"`
	DebugInfo  string   `yaml:"debuginfo,omitempty"`
	Keyring    string   `yaml:"keyring,omitempty"`
	Credential string   `yaml:"credential,omitempty"`
}

type View struct {
	Access       string   `yaml:"access"`
	AllowedPools []string `yaml:"allowed_pools"`
	AppendOnly   bool     `yaml:"append_only"`
	DebugInfo    string   `yaml:"debuginfo,omitempty"`
	Repos        []string `yaml:"repos,omitempty"`
}

// ServingConfig freezes the externally visible base URL for each mutable
// local view. The block is optional for configurations that never materialize
// YUM, but once enabled it is an all-or-nothing contract: a mutable YUM view
// cannot safely emit a relative or guessed mirrorlist URL.
type ServingConfig struct {
	Latest ServingView `yaml:"latest,omitempty"`
	Beta   ServingView `yaml:"beta,omitempty"`
	Stable ServingView `yaml:"stable,omitempty"`
}

type ServingView struct {
	BaseURL string `yaml:"base_url,omitempty"`
}

type Target struct {
	Storage Storage `yaml:"storage"`
	CDN     CDN     `yaml:"cdn"`
}

type Storage struct {
	Kind                       string `yaml:"kind"`
	Endpoint                   string `yaml:"endpoint"`
	Bucket                     string `yaml:"bucket"`
	Region                     string `yaml:"region,omitempty"`
	Credential                 string `yaml:"credential"`
	DeleteMode                 string `yaml:"delete_mode,omitempty"`
	UnversionedBucketConfirmed bool   `yaml:"unversioned_bucket_confirmed,omitempty"`
}

type CDN struct {
	Kind         string `yaml:"kind"`
	BaseURL      string `yaml:"base_url"`
	BetaBaseURL  string `yaml:"beta_base_url"`
	ZoneID       string `yaml:"zone_id,omitempty"`
	Distribution string `yaml:"distribution,omitempty"`
	Credential   string `yaml:"credential"`
}

type EdgeConfig struct {
	ProPrefix     string `yaml:"pro_prefix,omitempty"`
	TokenVerifier string `yaml:"token_verifier"`
}

func Load(path, rootOverride string) (*Config, error) {
	absConfig, root, err := ResolvePaths(path, rootOverride)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	cfg, err := Decode(f)
	if err != nil {
		return nil, err
	}
	cfg.Path = absConfig
	cfg.Root = root
	info, err := os.Stat(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("stat root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("root is not a directory: %s", cfg.Root)
	}
	return cfg, nil
}

// ResolvePaths applies the same config-path and repository-root rules as Load
// without opening or decoding the external YAML. CLI callers use this narrow
// operation to snapshot canonical Git state before they trust a potentially
// stale configuration file.
func ResolvePaths(configPath, rootOverride string) (string, string, error) {
	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		return "", "", fmt.Errorf("resolve config path: %w", err)
	}
	root := rootOverride
	if root == "" {
		root = filepath.Dir(absConfig)
	}
	if !filepath.IsAbs(root) {
		root = filepath.Join(filepath.Dir(absConfig), root)
	}
	absRoot, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", "", fmt.Errorf("resolve root: %w", err)
	}
	return absConfig, absRoot, nil
}

func Decode(r io.Reader) (*Config, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxConfigBytes+1))
	if len(data) > MaxConfigBytes {
		return nil, fmt.Errorf("config exceeds %d-byte safety limit", MaxConfigBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := rejectYAMLAliasesAndMergeKeys(&document); err != nil {
		return nil, err
	}
	if err := validateYUMCompatibilityProjectionNode(&document); err != nil {
		return nil, err
	}
	if err := requireTopLevelKeys(&document, "schema", "state", "gpg", "pools", "repos", "upstreams", "views", "targets", "edge"); err != nil {
		return nil, err
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	markRepoOptionalFieldPresence(&document, &cfg)
	if cfg.State.APTByHashRetention == 0 && hasNestedMappingKey(&document, "state", "apt_by_hash_retention") {
		return nil, errors.New("state.apt_by_hash_retention must be positive")
	}
	if cfg.State.YUMGenerationRetention == 0 && hasNestedMappingKey(&document, "state", "yum_generation_retention") {
		return nil, errors.New("state.yum_generation_retention must be positive")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("config must contain exactly one YAML document")
		}
		return nil, fmt.Errorf("decode trailing YAML: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if _, err := cfg.Canonical(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// rejectYAMLAliasesAndMergeKeys keeps source presence and strict-field checks
// authoritative. yaml.v3 resolves aliases and merge keys while decoding into
// Go values, which would otherwise let a field supplied through << bypass the
// source-node presence ledger and silently select an absent-field default.
func rejectYAMLAliasesAndMergeKeys(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("YAML aliases are not allowed at line %d", node.Line)
	}
	if node.Kind == yaml.MappingNode {
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Value == "<<" || key.Tag == "!!merge" || key.Tag == "tag:yaml.org,2002:merge" {
				return fmt.Errorf("YAML merge keys (<<) are not allowed at line %d", key.Line)
			}
		}
	}
	for _, child := range node.Content {
		if err := rejectYAMLAliasesAndMergeKeys(child); err != nil {
			return err
		}
	}
	return nil
}

// markRepoOptionalFieldPresence keeps strict KnownFields decoding intact while
// recovering the distinction ordinary Go values lose: absent versus explicit
// empty/null optional fields. Repository order is preserved by YAML sequence
// decoding, so each source node maps exactly to cfg.Repos[i].
func markRepoOptionalFieldPresence(document *yaml.Node, cfg *Config) {
	if cfg == nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return
	}
	root := document.Content[0]
	for index := 0; index+1 < len(root.Content); index += 2 {
		if root.Content[index].Value != "repos" || root.Content[index+1].Kind != yaml.SequenceNode {
			continue
		}
		for repoIndex, repoNode := range root.Content[index+1].Content {
			if repoIndex >= len(cfg.Repos) || repoNode.Kind != yaml.MappingNode {
				continue
			}
			for field := 0; field+1 < len(repoNode.Content); field += 2 {
				switch repoNode.Content[field].Value {
				case "publish_targets":
					cfg.Repos[repoIndex].publishTargetsPresent = true
				case "apt":
					if cfg.Repos[repoIndex].APT == nil || repoNode.Content[field+1].Kind != yaml.MappingNode {
						continue
					}
					aptNode := repoNode.Content[field+1]
					for aptField := 0; aptField+1 < len(aptNode.Content); aptField += 2 {
						switch aptNode.Content[aptField].Value {
						case "suite_components":
							cfg.Repos[repoIndex].APT.suiteComponentsPresent = true
						case "suite_lifecycle":
							cfg.Repos[repoIndex].APT.suiteLifecyclePresent = true
						}
					}
				case "yum":
					if cfg.Repos[repoIndex].YUM == nil || repoNode.Content[field+1].Kind != yaml.MappingNode {
						continue
					}
					yumNode := repoNode.Content[field+1]
					for yumField := 0; yumField+1 < len(yumNode.Content); yumField += 2 {
						switch yumNode.Content[yumField].Value {
						case "noarch_mode":
							cfg.Repos[repoIndex].YUM.noarchModePresent = true
						}
					}
				case "asset":
					if cfg.Repos[repoIndex].Asset == nil || repoNode.Content[field+1].Kind != yaml.MappingNode {
						continue
					}
					assetNode := repoNode.Content[field+1]
					for assetField := 0; assetField+1 < len(assetNode.Content); assetField += 2 {
						switch assetNode.Content[assetField].Value {
						case "public_path":
							cfg.Repos[repoIndex].Asset.publicPathPresent = true
						case "root_keys":
							cfg.Repos[repoIndex].Asset.rootKeysPresent = true
						}
					}
				}
			}
		}
		return
	}
}

func hasNestedMappingKey(document *yaml.Node, parent, child string) bool {
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return false
	}
	root := document.Content[0]
	for index := 0; index+1 < len(root.Content); index += 2 {
		if root.Content[index].Value != parent || root.Content[index+1].Kind != yaml.MappingNode {
			continue
		}
		mapping := root.Content[index+1]
		for nested := 0; nested+1 < len(mapping.Content); nested += 2 {
			if mapping.Content[nested].Value == child {
				return true
			}
		}
	}
	return false
}

func requireTopLevelKeys(document *yaml.Node, required ...string) error {
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return errors.New("config root must be a YAML mapping")
	}
	present := make(map[string]bool)
	node := document.Content[0]
	for i := 0; i+1 < len(node.Content); i += 2 {
		present[node.Content[i].Value] = true
	}
	var missing []string
	for _, key := range required {
		if !present[key] {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("config must declare top-level blocks: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.State.SnapshotMaterializationMonths == 0 {
		c.State.SnapshotMaterializationMonths = DefaultSnapshotAge
	}
	if c.State.APTByHashRetention == 0 {
		c.State.APTByHashRetention = DefaultAPTByHashRetention
	}
	if c.State.YUMGenerationRetention == 0 {
		c.State.YUMGenerationRetention = DefaultYUMGenerationRetention
	}
	if c.State.CASHistoryCommits == 0 {
		c.State.CASHistoryCommits = DefaultCASHistory
	}
	if c.Edge.ProPrefix == "" {
		c.Edge.ProPrefix = DefaultProPrefix
	}
	for name, view := range c.Views {
		if view.DebugInfo == "" {
			if view.Access == "public" {
				view.DebugInfo = "drop"
			} else {
				view.DebugInfo = "keep"
			}
			c.Views[name] = view
		}
	}
	for name, target := range c.Targets {
		if name == "cf" && target.Storage.Region == "" {
			target.Storage.Region = "auto"
		}
		if target.Storage.DeleteMode == "" {
			target.Storage.DeleteMode = StorageDeleteConditional
		}
		target.Storage.Endpoint = strings.TrimSuffix(target.Storage.Endpoint, "/")
		target.CDN.BaseURL = strings.TrimSuffix(target.CDN.BaseURL, "/")
		target.CDN.BetaBaseURL = strings.TrimSuffix(target.CDN.BetaBaseURL, "/")
		c.Targets[name] = target
	}
	c.Serving.Latest.BaseURL = strings.TrimSuffix(c.Serving.Latest.BaseURL, "/")
	c.Serving.Beta.BaseURL = strings.TrimSuffix(c.Serving.Beta.BaseURL, "/")
	c.Serving.Stable.BaseURL = strings.TrimSuffix(c.Serving.Stable.BaseURL, "/")
	for index := range c.Repos {
		if c.Repos[index].Asset != nil && !c.Repos[index].Asset.publicPathPresent {
			c.Repos[index].Asset.PublicPath = c.Repos[index].Path
		}
		// The repository metadata signing key is also the backward-compatible
		// trust source for locally built RPMs. Operators mirroring third-party
		// RPMs should declare an explicit bundle containing every package signer
		// retained by this append-only repository.
		if c.Repos[index].YUM != nil && c.Repos[index].YUM.PackageKeyring == "" {
			c.Repos[index].YUM.PackageKeyring = c.GPG.PublicKey
			c.Repos[index].YUM.packageKeyringDefaulted = true
		}
		if c.Repos[index].YUM != nil && !c.Repos[index].YUM.noarchModePresent && c.Repos[index].YUM.NoarchMode == "" {
			c.Repos[index].YUM.NoarchMode = YUMNoarchReplicate
		}
	}
}

func (c *Config) Validate() error {
	if c.Schema != Schema {
		return fmt.Errorf("unsupported schema %q (want %s)", c.Schema, Schema)
	}
	// This preflight is deliberately the first schema-v1 validation. In
	// particular it runs before validateUpstreams copies omitted arches or
	// components and before path/suite validation allocates derived topology.
	if _, err := configComplexityUsageFor(c); err != nil {
		return err
	}
	if c.State.SnapshotMaterializationMonths < 1 {
		return errors.New("state.snapshot_materialization_months must be positive")
	}
	if c.State.APTByHashRetention < 1 {
		return errors.New("state.apt_by_hash_retention must be positive")
	}
	if c.State.YUMGenerationRetention < 1 {
		return errors.New("state.yum_generation_retention must be positive")
	}
	if c.State.CASHistoryCommits < 1 || c.State.CASHistoryCommits > 10_000 {
		return errors.New("state.cas_history_commits must be between 1 and 10000")
	}
	if c.Edge.ProPrefix != DefaultProPrefix {
		return fmt.Errorf("edge.pro_prefix is frozen at %s", DefaultProPrefix)
	}
	if c.Edge.TokenVerifier == "" {
		return errors.New("edge.token_verifier is required")
	}
	if _, err := ParseTokenVerifierReference(c.Edge.TokenVerifier); err != nil {
		return fmt.Errorf("edge.token_verifier: %w", err)
	}
	if c.GPG.PublicKey != "" {
		if err := validateRoutePath(c.GPG.PublicKey); err != nil {
			return fmt.Errorf("gpg.public_key: %w", err)
		}
		c.GPG.PublicKey = path.Clean(c.GPG.PublicKey)
	}
	if c.GPG.PrivateKey != "" {
		if err := validateSecretReference("gpg.private_key", c.GPG.PrivateKey, false); err != nil {
			return err
		}
	}
	if c.GPG.Passphrase != "" {
		if err := validateSecretReference("gpg.passphrase", c.GPG.Passphrase, false); err != nil {
			return err
		}
	}
	if err := c.validatePools(); err != nil {
		return err
	}
	repoIDs, err := c.validateRepos()
	if err != nil {
		return err
	}
	if err := c.validateRepoGroups(repoIDs); err != nil {
		return err
	}
	if err := c.validateUpstreams(repoIDs); err != nil {
		return err
	}
	if err := c.validateViews(repoIDs); err != nil {
		return err
	}
	if err := ValidateYUMCompatibilityProjections(c.CompatibilityProjections, c.Repos, c.RepoGroups, c.Views); err != nil {
		return err
	}
	if err := c.validateServing(); err != nil {
		return err
	}
	if err := c.validateTargets(); err != nil {
		return err
	}
	// Build every deployment contract during config preflight. This prevents a
	// repository target from validating while its executable edge adapter would
	// receive an unrepresentable or silently ignored verifier reference.
	for target := range c.Targets {
		if _, err := c.EdgeDeployment(target); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) validateRepoGroups(repoIDs map[string]struct{}) error {
	groupIDs := make(map[string]struct{}, len(c.RepoGroups))
	for name := range c.RepoGroups {
		if err := validateName("repo group", name); err != nil {
			return err
		}
		if _, exists := repoIDs[name]; exists {
			return fmt.Errorf("repo group %q collides with a physical repo ID", name)
		}
		groupIDs[name] = struct{}{}
	}
	for name, members := range c.RepoGroups {
		if len(members) == 0 {
			return fmt.Errorf("repo group %q must contain at least one physical repo ID", name)
		}
		seen := make(map[string]struct{}, len(members))
		for _, member := range members {
			if _, duplicate := seen[member]; duplicate {
				return fmt.Errorf("repo group %q contains duplicate member %q", name, member)
			}
			seen[member] = struct{}{}
			if _, nested := groupIDs[member]; nested {
				return fmt.Errorf("repo group %q may not contain nested group %q", name, member)
			}
			if _, exists := repoIDs[member]; !exists {
				return fmt.Errorf("repo group %q contains unknown physical repo %q", name, member)
			}
		}
		// Group membership is a set. Normalize it before canonical YAML hashing so
		// equivalent declarations have one identity while every member remains
		// bound by CanonicalSHA256.
		sort.Strings(members)
		c.RepoGroups[name] = members
	}
	return nil
}

func (c *Config) validateServing() error {
	endpoints := []struct {
		view     string
		baseURL  string
		wantPath string
	}{
		{view: "latest", baseURL: c.Serving.Latest.BaseURL},
		{view: "beta", baseURL: c.Serving.Beta.BaseURL},
		{view: "stable", baseURL: c.Serving.Stable.BaseURL, wantPath: "/pro/v1/basic"},
	}
	configured := 0
	for _, endpoint := range endpoints {
		if endpoint.baseURL != "" {
			configured++
		}
	}
	if configured == 0 {
		return nil
	}
	if configured != len(endpoints) {
		return errors.New("serving must configure latest, beta, and stable base_url together")
	}
	for _, endpoint := range endpoints {
		if err := ValidateServingBaseURL(endpoint.baseURL, endpoint.wantPath); err != nil {
			return fmt.Errorf("serving.%s.base_url: %w", endpoint.view, err)
		}
	}
	return nil
}

// ValidateServingBaseURL rejects credentials and alternate cache-key forms.
// Production serving is HTTPS. Plain HTTP is accepted only for loopback test
// origins and the exact host.docker.internal bridge used by containerized
// real-client tests, where a dynamic port is unavoidable.
func ValidateServingBaseURL(rawURL, wantPath string) error {
	if len(rawURL) > MaxServingBaseURLBytes {
		return fmt.Errorf("exceeds %d-byte limit", MaxServingBaseURLBytes)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" {
		return errors.New("must be a clean absolute URL without userinfo, query, fragment, or alternate encoding")
	}
	if parsed.Path != wantPath {
		if wantPath == "" {
			return errors.New("must be a clean origin URL without a path")
		}
		return fmt.Errorf("path must be exactly %s", wantPath)
	}
	hostname := parsed.Hostname()
	if hostname == "" || strings.ContainsAny(parsed.Host, "\x00\t\r\n ") {
		return errors.New("has an invalid host")
	}
	loopback := strings.EqualFold(hostname, "localhost") || strings.EqualFold(hostname, "host.docker.internal")
	if address := net.ParseIP(hostname); address != nil && address.IsLoopback() {
		loopback = true
	}
	switch parsed.Scheme {
	case "https":
		if parsed.Port() != "" && !loopback {
			return errors.New("production HTTPS URL must not use a custom port")
		}
	case "http":
		if !loopback {
			return errors.New("plain HTTP is restricted to loopback serving")
		}
	default:
		return errors.New("scheme must be HTTPS, or HTTP on loopback")
	}
	return nil
}

func (c *Config) validatePools() error {
	if len(c.Pools) != 2 {
		return errors.New("schema v1 requires exactly the public and gated pools")
	}
	for _, required := range []string{"public", "gated"} {
		if _, ok := c.Pools[required]; !ok {
			return fmt.Errorf("pools must declare %s", required)
		}
	}
	return nil
}

func (c *Config) validateRepos() (map[string]struct{}, error) {
	if len(c.Repos) == 0 {
		return nil, errors.New("at least one repo is required")
	}
	IDs := make(map[string]struct{})
	paths := make([]string, 0, len(c.Repos))
	publicPrefixes := make([]publicPrefixOwner, 0, len(c.Repos))
	rootKeyOwners := make(map[string]string)
	for i := range c.Repos {
		repo := &c.Repos[i]
		if err := validateName("repo", repo.ID); err != nil {
			return nil, fmt.Errorf("repos[%d]: %w", i, err)
		}
		if _, exists := IDs[repo.ID]; exists {
			return nil, fmt.Errorf("duplicate repo %q", repo.ID)
		}
		IDs[repo.ID] = struct{}{}
		if repo.Type != "apt" && repo.Type != "yum" && repo.Type != "asset" {
			return nil, fmt.Errorf("repos[%d]: type must be apt, yum, or asset", i)
		}
		if err := validateRelativePath(repo.Path); err != nil {
			return nil, fmt.Errorf("repos[%d].path: %w", i, err)
		}
		repo.Path = filepath.ToSlash(filepath.Clean(repo.Path))
		if containsReservedComponent(repo.Path) {
			return nil, fmt.Errorf("repos[%d].path uses a reserved .sow/.pool/.git/_sow component", i)
		}
		if _, exists := c.Pools[repo.DefaultPool]; !exists {
			return nil, fmt.Errorf("repos[%d]: unknown default_pool %q", i, repo.DefaultPool)
		}
		if repo.publishTargetsPresent && len(repo.PublishTargets) == 0 {
			return nil, fmt.Errorf("repos[%d].publish_targets must contain at least one configured target when declared", i)
		}
		if err := validateStringList(fmt.Sprintf("repos[%d].publish_targets", i), repo.PublishTargets); err != nil {
			return nil, err
		}
		for _, target := range repo.PublishTargets {
			if target != "cf" && target != "cos" {
				return nil, fmt.Errorf("repos[%d].publish_targets entries must be cf or cos; got %q", i, target)
			}
		}
		// Affinity is a set. A canonical order prevents YAML list order from
		// producing distinct recovery identities for equivalent contracts.
		sort.Strings(repo.PublishTargets)
		if len(repo.Arches) == 0 && repo.Type != "asset" {
			return nil, fmt.Errorf("repos[%d]: arches are required for %s", i, repo.Type)
		}
		if err := validateRouteStringList(fmt.Sprintf("repos[%d].arches", i), repo.Arches); err != nil {
			return nil, err
		}
		if err := validateRepoUnion(*repo); err != nil {
			return nil, fmt.Errorf("repos[%d]: %w", i, err)
		}
		if repo.APT != nil {
			if err := validateRouteStringList(fmt.Sprintf("repos[%d].apt.suites", i), repo.APT.Suites); err != nil {
				return nil, err
			}
			if err := validateRouteStringList(fmt.Sprintf("repos[%d].apt.components", i), repo.APT.Components); err != nil {
				return nil, err
			}
			if err := validateAPTSuiteContracts(i, repo.APT); err != nil {
				return nil, err
			}
		}
		if repo.Type == "yum" {
			if err := validateRouteStringList(fmt.Sprintf("repos[%d].os", i), repo.OSSelectorValues()); err != nil {
				return nil, err
			}
			if repo.YUM.PackageKeyring == "" {
				return nil, fmt.Errorf("repos[%d].yum.package_keyring is required (or set gpg.public_key as the Pigsty package trust key)", i)
			}
			if err := validateRoutePath(repo.YUM.PackageKeyring); err != nil {
				return nil, fmt.Errorf("repos[%d].yum.package_keyring: %w", i, err)
			}
			repo.YUM.PackageKeyring = path.Clean(repo.YUM.PackageKeyring)
			if repo.YUM.NoarchMode != YUMNoarchReplicate && repo.YUM.NoarchMode != YUMNoarchSeparate {
				return nil, fmt.Errorf("repos[%d].yum.noarch_mode must be %s or %s", i, YUMNoarchReplicate, YUMNoarchSeparate)
			}
			if repo.YUM.NoarchMode == YUMNoarchSeparate && !containsString(repo.Arches, "noarch") {
				return nil, fmt.Errorf("repos[%d].yum.noarch_mode=%s requires repos[%d].arches to contain noarch", i, YUMNoarchSeparate, i)
			}
		}
		for _, pattern := range append(append([]string{}, repo.Include...), repo.Exclude...) {
			if !doublestar.ValidatePattern(pattern) || strings.HasPrefix(pattern, "/") || strings.ContainsAny(pattern, "\\\t\r\n") {
				return nil, fmt.Errorf("repos[%d]: invalid include/exclude pattern %q", i, pattern)
			}
		}
		if repo.Asset != nil {
			for _, pattern := range repo.Asset.MutablePaths {
				if !doublestar.ValidatePattern(pattern) || strings.HasPrefix(pattern, "/") || strings.ContainsAny(pattern, "\\\t\r\n") {
					return nil, fmt.Errorf("repos[%d].asset.mutable_paths: invalid pattern %q", i, pattern)
				}
			}
			if err := validateStringList(fmt.Sprintf("repos[%d].asset.mutable_paths", i), repo.Asset.MutablePaths); err != nil {
				return nil, err
			}
			if !repo.Asset.publicPathPresent {
				// repo.Path has now been normalized; keep an omitted public_path
				// exactly aligned with that backward-compatible physical root.
				repo.Asset.PublicPath = repo.Path
			}
		}
		if err := validateLifecycle(*repo); err != nil {
			return nil, fmt.Errorf("repos[%d]: %w", i, err)
		}
		expandedPaths, err := repo.ExpandedPaths()
		if err != nil {
			return nil, fmt.Errorf("repos[%d]: %w", i, err)
		}
		for _, expanded := range expandedPaths {
			if err := validateRoutePath(expanded); err != nil {
				return nil, fmt.Errorf("repos[%d].path: expanded path %q is not edge-routable: %w", i, expanded, err)
			}
			switch {
			case repo.Type == "apt" && !hasPathNamespace(expanded, "apt"):
				return nil, fmt.Errorf("repos[%d].path: APT repositories must use the apt/ namespace", i)
			case repo.Type == "yum" && !hasPathNamespace(expanded, "yum"):
				return nil, fmt.Errorf("repos[%d].path: YUM repositories must use the yum/ namespace", i)
			case repo.Type == "asset" && (hasPathNamespace(expanded, "apt") || hasPathNamespace(expanded, "yum")):
				return nil, fmt.Errorf("repos[%d].path: asset repositories may not use the reserved apt/ or yum/ package namespace", i)
			}
		}
		if repo.Type == "asset" {
			if err := validateAssetProjection(i, repo, rootKeyOwners); err != nil {
				return nil, err
			}
			if repo.Asset.InventoryCarrier {
				if repo.IsActive() {
					return nil, fmt.Errorf("repos[%d].asset.inventory_carrier requires active=false", i)
				}
				if repo.Asset.Kind != "inventory" {
					return nil, fmt.Errorf("repos[%d].asset.inventory_carrier requires kind=inventory", i)
				}
				if repo.AssetPublicRoot() == "." || len(repo.Asset.RootKeys) != 0 || len(repo.Asset.MutablePaths) != 0 {
					return nil, fmt.Errorf("repos[%d].asset.inventory_carrier must use a non-root public_path and may not declare root_keys or mutable_paths", i)
				}
			}
		}
		paths = append(paths, expandedPaths...)
		if repo.Type == "asset" {
			if publicRoot := repo.AssetPublicRoot(); publicRoot != "." {
				publicPrefixes = append(publicPrefixes, publicPrefixOwner{path: publicRoot, repo: repo.ID})
			}
		} else {
			for _, expanded := range expandedPaths {
				publicPrefixes = append(publicPrefixes, publicPrefixOwner{path: expanded, repo: repo.ID})
			}
		}
	}
	if err := validateNonOverlapping(paths); err != nil {
		return nil, err
	}
	if err := validatePublicOwnership(publicPrefixes, rootKeyOwners); err != nil {
		return nil, err
	}
	return IDs, nil
}

type publicPrefixOwner struct {
	path string
	repo string
}

func validateAssetProjection(repoIndex int, repo *Repo, rootKeyOwners map[string]string) error {
	asset := repo.Asset
	field := fmt.Sprintf("repos[%d].asset.public_path", repoIndex)
	if asset.PublicPath == "" {
		return fmt.Errorf("%s must be a normalized public prefix or the exact root sentinel .", field)
	}
	if asset.PublicPath == "." {
		if len(asset.RootKeys) == 0 {
			return fmt.Errorf("repos[%d].asset.root_keys must contain at least one exact key when public_path is .", repoIndex)
		}
		rootKeysField := fmt.Sprintf("repos[%d].asset.root_keys", repoIndex)
		if err := validateRouteStringList(rootKeysField, asset.RootKeys); err != nil {
			return err
		}
		for _, key := range asset.RootKeys {
			if isReservedPublicRootKey(key) {
				return fmt.Errorf("%s contains reserved public namespace %q", rootKeysField, key)
			}
			if owner, duplicate := rootKeyOwners[key]; duplicate {
				return fmt.Errorf("public root exact key %q is owned by both repo %q and repo %q", key, owner, repo.ID)
			}
			rootKeyOwners[key] = repo.ID
		}
		sort.Strings(asset.RootKeys)
		rootKeys := make(map[string]struct{}, len(asset.RootKeys))
		for _, key := range asset.RootKeys {
			rootKeys[key] = struct{}{}
		}
		for _, mutable := range asset.MutablePaths {
			if err := ValidateRouteSegment(mutable); err != nil {
				return fmt.Errorf("repos[%d].asset.mutable_paths root mapping %q must be one exact route-safe key without glob syntax: %w", repoIndex, mutable, err)
			}
			if _, allowed := rootKeys[mutable]; !allowed {
				return fmt.Errorf("repos[%d].asset.mutable_paths root mapping %q is not declared in asset.root_keys", repoIndex, mutable)
			}
		}
		sort.Strings(asset.MutablePaths)
		return nil
	}

	if asset.rootKeysPresent || len(asset.RootKeys) != 0 {
		return fmt.Errorf("repos[%d].asset.root_keys is allowed only when public_path is .", repoIndex)
	}
	if err := validateRoutePath(asset.PublicPath); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if containsReservedComponent(asset.PublicPath) || isReservedPublicRootKey(strings.Split(asset.PublicPath, "/")[0]) {
		return fmt.Errorf("%s uses a reserved public namespace", field)
	}
	if hasPathNamespace(asset.PublicPath, "apt") || hasPathNamespace(asset.PublicPath, "yum") {
		return fmt.Errorf("%s: asset repositories may not own the reserved apt/ or yum/ package namespace", field)
	}
	// validateRoutePath already proved this is canonical, but assign through
	// path.Clean to make the normalization guarantee explicit to helper callers.
	asset.PublicPath = path.Clean(asset.PublicPath)
	return nil
}

func isReservedPublicRootKey(value string) bool {
	switch value {
	case StateDirectory, PoolDirectory, ".git", "_sow", "apt", "yum", "pro", "sow.yaml":
		return true
	default:
		return false
	}
}

func validatePublicOwnership(prefixes []publicPrefixOwner, rootKeyOwners map[string]string) error {
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].path == prefixes[j].path {
			return prefixes[i].repo < prefixes[j].repo
		}
		return prefixes[i].path < prefixes[j].path
	})
	paths := make([]string, len(prefixes))
	for index := range prefixes {
		paths[index] = prefixes[index].path
	}
	for i := range prefixes {
		if conflict, exists := firstSortedPathConflict(paths, i); exists {
			left, right := prefixes[i], prefixes[conflict]
			return fmt.Errorf("public repo prefixes overlap: repo %q owns %q and repo %q owns %q", left.repo, left.path, right.repo, right.path)
		}
	}
	prefixByPath := make(map[string]publicPrefixOwner, len(prefixes))
	for _, prefix := range prefixes {
		if _, exists := prefixByPath[prefix.path]; !exists {
			prefixByPath[prefix.path] = prefix
		}
	}
	for _, key := range sortedStringMapKeys(rootKeyOwners) {
		exactOwner := rootKeyOwners[key]
		// An exact object `pkg` and a strict child prefix `pkg/pig` are
		// representable together in object storage and by exact Nginx alias.
		// A same-name prefix (or a prefix ancestor of a future multi-segment
		// exact key) is ambiguous and therefore rejected globally.
		for end := strings.IndexByte(key, '/'); ; end = nextPathSeparator(key, end) {
			candidate := key
			if end >= 0 {
				candidate = key[:end]
			}
			if prefix, exists := prefixByPath[candidate]; exists {
				return fmt.Errorf("public root exact key %q from repo %q conflicts with prefix %q from repo %q", key, exactOwner, prefix.path, prefix.repo)
			}
			if end < 0 {
				break
			}
		}
	}
	return nil
}

func nextPathSeparator(value string, current int) int {
	if current < 0 || current+1 >= len(value) {
		return -1
	}
	next := strings.IndexByte(value[current+1:], '/')
	if next < 0 {
		return -1
	}
	return current + 1 + next
}

func validateAPTSuiteContracts(repoIndex int, apt *APTConfig) error {
	if apt == nil {
		return nil
	}
	suites := make(map[string]struct{}, len(apt.Suites))
	for _, suite := range apt.Suites {
		suites[suite] = struct{}{}
	}
	if apt.hasSuiteComponents() {
		if len(apt.SuiteComponents) != len(apt.Suites) {
			return fmt.Errorf("repos[%d].apt.suite_components must cover every configured suite exactly", repoIndex)
		}
		componentOrder := make(map[string]int, len(apt.Components))
		for order, component := range apt.Components {
			componentOrder[component] = order
		}
		componentUnion := make(map[string]struct{}, len(apt.Components))
		for _, suite := range sortedStringMapKeys(apt.SuiteComponents) {
			components := apt.SuiteComponents[suite]
			if _, exists := suites[suite]; !exists {
				return fmt.Errorf("repos[%d].apt.suite_components contains unknown suite %q", repoIndex, suite)
			}
			field := fmt.Sprintf("repos[%d].apt.suite_components.%s", repoIndex, suite)
			if len(components) == 0 {
				return fmt.Errorf("%s must contain at least one component", field)
			}
			if err := validateRouteStringList(field, components); err != nil {
				return err
			}
			for _, component := range components {
				if _, exists := componentOrder[component]; !exists {
					return fmt.Errorf("%s contains component %q outside apt.components", field, component)
				}
				componentUnion[component] = struct{}{}
			}
			// Preserve the declared global order without scanning every global
			// component for every sparse suite. The precomputed order index turns
			// this into O(total suite members log max-suite-members).
			normalized := append([]string(nil), components...)
			sort.Slice(normalized, func(left, right int) bool {
				return componentOrder[normalized[left]] < componentOrder[normalized[right]]
			})
			apt.SuiteComponents[suite] = normalized
		}
		for _, suite := range apt.Suites {
			if _, exists := apt.SuiteComponents[suite]; !exists {
				return fmt.Errorf("repos[%d].apt.suite_components is missing suite %q", repoIndex, suite)
			}
		}
		if len(componentUnion) != len(apt.Components) {
			return fmt.Errorf("repos[%d].apt.suite_components union must equal apt.components exactly", repoIndex)
		}
	}
	if apt.hasSuiteLifecycle() {
		if len(apt.SuiteLifecycle) != len(apt.Suites) {
			return fmt.Errorf("repos[%d].apt.suite_lifecycle must cover every configured suite exactly", repoIndex)
		}
		for suite, lifecycle := range apt.SuiteLifecycle {
			if _, exists := suites[suite]; !exists {
				return fmt.Errorf("repos[%d].apt.suite_lifecycle contains unknown suite %q", repoIndex, suite)
			}
			if lifecycle != "active" && lifecycle != "frozen" {
				return fmt.Errorf("repos[%d].apt.suite_lifecycle.%s must be active or frozen", repoIndex, suite)
			}
		}
		for _, suite := range apt.Suites {
			if _, exists := apt.SuiteLifecycle[suite]; !exists {
				return fmt.Errorf("repos[%d].apt.suite_lifecycle is missing suite %q", repoIndex, suite)
			}
		}
	}
	return nil
}

func validateRepoUnion(repo Repo) error {
	blocks := 0
	if repo.APT != nil {
		blocks++
	}
	if repo.YUM != nil {
		blocks++
	}
	if repo.Asset != nil {
		blocks++
	}
	if blocks != 1 {
		return errors.New("exactly one apt, yum, or asset block is required")
	}
	if (repo.Type == "apt") != (repo.APT != nil) || (repo.Type == "yum") != (repo.YUM != nil) || (repo.Type == "asset") != (repo.Asset != nil) {
		return errors.New("type must match its apt/yum/asset block")
	}
	if repo.APT != nil && (len(repo.APT.Suites) == 0 || len(repo.APT.Components) == 0) {
		return errors.New("apt suites and components are required")
	}
	return nil
}

func validateLifecycle(repo Repo) error {
	if repo.Type == "asset" {
		return nil
	}
	if repo.Type == "yum" && repo.YUM != nil && repo.YUM.CompatibilityCarrier {
		if repo.Active == nil || *repo.Active {
			return errors.New("YUM compatibility carrier must declare active: false")
		}
		if repo.OS.Family != "cross-el" || repo.OS.Major != 0 || repo.OS.Lifecycle != "frozen" || repo.YUM.Compression != "gzip" {
			return errors.New("YUM compatibility carrier requires os.family=cross-el, os.major=0, frozen lifecycle, and gzip input metadata")
		}
		return nil
	}
	if repo.OS.Lifecycle != "active" && repo.OS.Lifecycle != "frozen" {
		return errors.New("os.lifecycle must be active or frozen")
	}
	if repo.Type == "yum" {
		if repo.OS.Family != "el" || repo.OS.Major <= 0 {
			return errors.New("yum repos require os.family=el and a positive major")
		}
		switch repo.OS.Major {
		case 7:
			if repo.OS.Lifecycle != "frozen" || repo.YUM.Compression != "gzip" {
				return errors.New("legacy EL7 is supported only as frozen gzip repodata")
			}
		case 8:
			if repo.OS.Lifecycle != "frozen" || repo.YUM.Compression != "gzip" {
				return fmt.Errorf("EL8 is frozen since Pigsty %s and requires gzip repodata", EL8FrozenSincePigstyVersion)
			}
		case 9, 10:
			if repo.YUM.Compression != "zstd" {
				return errors.New("EL9/10 require zstd repodata")
			}
		default:
			return errors.New("YUM metadata policy supports only legacy frozen EL7 and EL8-EL10")
		}
	}
	return nil
}

func (c *Config) validateUpstreams(repoIDs map[string]struct{}) error {
	type repoIndex struct {
		repo            *Repo
		arches          map[string]struct{}
		suiteComponents map[string]map[string]struct{}
	}
	indexedRepos := make(map[string]repoIndex, len(c.Repos))
	for index := range c.Repos {
		repo := &c.Repos[index]
		arches := make(map[string]struct{}, len(repo.Arches))
		for _, arch := range repo.Arches {
			arches[arch] = struct{}{}
		}
		suiteComponents := make(map[string]map[string]struct{})
		if repo.APT != nil {
			suiteComponents = make(map[string]map[string]struct{}, len(repo.APT.Suites))
			for _, suite := range repo.APT.Suites {
				components := repo.APT.componentsForSuite(suite)
				componentSet := make(map[string]struct{}, len(components))
				for _, component := range components {
					componentSet[component] = struct{}{}
				}
				suiteComponents[suite] = componentSet
			}
		}
		indexedRepos[repo.ID] = repoIndex{repo: repo, arches: arches, suiteComponents: suiteComponents}
	}
	seen := make(map[string]struct{})
	for i := range c.Upstreams {
		upstream := &c.Upstreams[i]
		if err := validateName("upstream", upstream.ID); err != nil {
			return fmt.Errorf("upstreams[%d]: %w", i, err)
		}
		if _, exists := seen[upstream.ID]; exists {
			return fmt.Errorf("duplicate upstream %q", upstream.ID)
		}
		seen[upstream.ID] = struct{}{}
		if upstream.Type != "apt" && upstream.Type != "yum" {
			return fmt.Errorf("upstreams[%d]: type must be apt or yum", i)
		}
		if _, exists := repoIDs[upstream.Repo]; !exists {
			return fmt.Errorf("upstreams[%d]: unknown repo %q", i, upstream.Repo)
		}
		indexed := indexedRepos[upstream.Repo]
		repo := indexed.repo
		if repo.Type != upstream.Type {
			return fmt.Errorf("upstreams[%d]: type %s does not match target repo %s type %s", i, upstream.Type, repo.ID, repo.Type)
		}
		if err := validateUpstreamURL(upstream.URL); err != nil {
			return fmt.Errorf("upstreams[%d].url: %w", i, err)
		}
		if upstream.DebugInfo == "" {
			upstream.DebugInfo = "drop"
		}
		if upstream.DebugInfo != "drop" {
			return fmt.Errorf("upstreams[%d]: debuginfo is a view policy frozen at drop for public ingestion; stable retains debug packages", i)
		}
		if len(upstream.Arches) == 0 {
			upstream.Arches = append([]string(nil), repo.Arches...)
		}
		if err := validateStringList(fmt.Sprintf("upstreams[%d].arches", i), upstream.Arches); err != nil {
			return err
		}
		for _, arch := range upstream.Arches {
			if _, exists := indexed.arches[arch]; !exists {
				return fmt.Errorf("upstreams[%d]: arch %q is not configured by repo %s", i, arch, repo.ID)
			}
		}
		if upstream.Type == "apt" {
			if upstream.Suite == "" && len(repo.APT.Suites) == 1 {
				upstream.Suite = repo.APT.Suites[0]
			}
			componentSet, suiteExists := indexed.suiteComponents[upstream.Suite]
			if !suiteExists {
				return fmt.Errorf("upstreams[%d]: suite %q is not configured by repo %s", i, upstream.Suite, repo.ID)
			}
			if len(upstream.Components) == 0 {
				upstream.Components = append([]string(nil), repo.APT.componentsForSuite(upstream.Suite)...)
			}
			if err := validateStringList(fmt.Sprintf("upstreams[%d].components", i), upstream.Components); err != nil {
				return err
			}
			for _, component := range upstream.Components {
				if _, exists := componentSet[component]; !exists {
					return fmt.Errorf("upstreams[%d]: component %q is not configured by repo %s suite %s", i, component, repo.ID, upstream.Suite)
				}
			}
			if upstream.Keyring == "" {
				return fmt.Errorf("upstreams[%d]: APT keyring is required", i)
			}
		} else if upstream.Suite != "" || len(upstream.Components) != 0 {
			return fmt.Errorf("upstreams[%d]: suite/components apply only to APT", i)
		}
		if upstream.Keyring == "" {
			return fmt.Errorf("upstreams[%d]: signed metadata keyring is required", i)
		}
		if upstream.Keyring != "" {
			if err := validateRelativePath(upstream.Keyring); err != nil {
				return fmt.Errorf("upstreams[%d].keyring: %w", i, err)
			}
			upstream.Keyring = filepath.ToSlash(filepath.Clean(upstream.Keyring))
		}
		if upstream.Credential != "" {
			if err := validateSecretReference(fmt.Sprintf("upstreams[%d].credential", i), upstream.Credential, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateUpstreamURL runs before any canonical config snapshot is staged.
// Credentials belong in the separate secret reference; accepting userinfo,
// query, or fragment material here would persist it verbatim into embedded Git
// even though the HTTP client later rejects the request.
func validateUpstreamURL(rawURL string) error {
	if len(rawURL) == 0 || len(rawURL) > MaxServingBaseURLBytes {
		return fmt.Errorf("must be 1..%d bytes", MaxServingBaseURLBytes)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.RawFragment != "" || parsed.RawPath != "" || strings.Contains(rawURL, "#") ||
		strings.ContainsAny(parsed.Host, "\x00\t\r\n ") {
		return errors.New("must be a clean absolute HTTPS URL without userinfo, query, fragment, opaque form, or alternate path encoding")
	}
	return nil
}

func (c *Config) validateViews(repoIDs map[string]struct{}) error {
	for _, required := range []string{"beta", "latest", "stable"} {
		if _, exists := c.Views[required]; !exists {
			return fmt.Errorf("views must declare %s", required)
		}
	}
	for name, view := range c.Views {
		if name == "snapshot" {
			return errors.New("views.snapshot is not configurable in sow/v1; immutable snapshots derive the fixed Pro policy from stable")
		}
		if name != "beta" && name != "latest" && name != "stable" {
			return fmt.Errorf("unknown view %q", name)
		}
		if view.Access != "public" && view.Access != "pro" {
			return fmt.Errorf("view %s access must be public or pro", name)
		}
		if view.DebugInfo != "drop" && view.DebugInfo != "keep" {
			return fmt.Errorf("view %s debuginfo must be drop or keep", name)
		}
		if len(view.AllowedPools) == 0 {
			return fmt.Errorf("view %s must allow at least one pool", name)
		}
		for _, pool := range view.AllowedPools {
			if _, exists := c.Pools[pool]; !exists {
				return fmt.Errorf("view %s references unknown pool %q", name, pool)
			}
		}
		if err := validateStringList("view "+name+" allowed_pools", view.AllowedPools); err != nil {
			return err
		}
		if (name == "beta" || name == "latest") && (view.Access != "public" || view.DebugInfo != "drop" || !sameStrings(view.AllowedPools, []string{"public"})) {
			return fmt.Errorf("view %s must be public, drop debuginfo, and allow only public", name)
		}
		if name == "stable" && (!view.AppendOnly || view.Access != "pro" || view.DebugInfo != "keep" || !sameStringSet(view.AllowedPools, []string{"public", "gated"})) {
			return errors.New("stable must be append-only pro, keep debuginfo, and allow public+gated")
		}
		for _, repo := range view.Repos {
			if _, exists := repoIDs[repo]; !exists {
				return fmt.Errorf("view %s references unknown repo %q", name, repo)
			}
		}
	}
	return nil
}

func (c *Config) validateTargets() error {
	for name, target := range c.Targets {
		if name != "cf" && name != "cos" {
			return fmt.Errorf("target %q is not part of schema v1", name)
		}
		wantStorage, wantCDN := "r2", "cloudflare"
		if name == "cos" {
			wantStorage, wantCDN = "cos", "edgeone"
		}
		if target.Storage.Kind != wantStorage || target.CDN.Kind != wantCDN {
			return fmt.Errorf("target %s requires storage=%s and cdn=%s", name, wantStorage, wantCDN)
		}
		if target.Storage.DeleteMode != StorageDeleteConditional && target.Storage.DeleteMode != StorageDeleteCheckpointFenced {
			return fmt.Errorf("target %s storage.delete_mode must be %s or %s", name, StorageDeleteConditional, StorageDeleteCheckpointFenced)
		}
		if name == "cos" && !target.Storage.UnversionedBucketConfirmed {
			return errors.New("target cos requires storage.unversioned_bucket_confirmed=true for create-only generation locks")
		}
		if name == "cf" && target.Storage.UnversionedBucketConfirmed {
			return errors.New("target cf does not use storage.unversioned_bucket_confirmed")
		}
		if target.Storage.Endpoint == "" || target.Storage.Bucket == "" || target.CDN.BaseURL == "" || target.CDN.BetaBaseURL == "" {
			return fmt.Errorf("target %s endpoint, bucket, CDN base_url, and beta_base_url are required", name)
		}
		if !bucketPattern.MatchString(target.Storage.Bucket) {
			return fmt.Errorf("target %s storage.bucket must be one DNS-safe bucket label", name)
		}
		if !regionPattern.MatchString(target.Storage.Region) || name == "cf" && target.Storage.Region != "auto" {
			return fmt.Errorf("target %s has an invalid storage.region", name)
		}
		var origins = make(map[string]string, 2)
		for field, rawURL := range map[string]string{"storage.endpoint": target.Storage.Endpoint, "cdn.base_url": target.CDN.BaseURL, "cdn.beta_base_url": target.CDN.BetaBaseURL} {
			parsed, err := url.Parse(rawURL)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || parsed.Path != "" || parsed.Port() != "" {
				return fmt.Errorf("target %s %s must be a clean bucket-root HTTPS URL", name, field)
			}
			origins[field] = strings.ToLower(parsed.Host)
		}
		if origins["cdn.base_url"] == origins["cdn.beta_base_url"] {
			return fmt.Errorf("target %s beta_base_url must preserve the distinct beta host", name)
		}
		if name == "cf" && (!providerIDPattern.MatchString(target.CDN.ZoneID) || target.CDN.Distribution != "") {
			return errors.New("target cf requires cdn.zone_id and forbids cdn.distribution")
		}
		if name == "cos" && (!providerIDPattern.MatchString(target.CDN.Distribution) || target.CDN.ZoneID != "") {
			return errors.New("target cos requires cdn.distribution and forbids cdn.zone_id")
		}
		for field, value := range map[string]string{"storage.credential": target.Storage.Credential, "cdn.credential": target.CDN.Credential} {
			if err := validateSecretReference("targets."+name+"."+field, value, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSecretReference(field, value string, allowProvider bool) error {
	if strings.HasPrefix(value, "env://") {
		name := strings.TrimPrefix(value, "env://")
		if name == "" || !regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`).MatchString(name) {
			return fmt.Errorf("%s has an invalid env reference", field)
		}
		return nil
	}
	if allowProvider && strings.HasPrefix(value, "provider://") && len(strings.TrimPrefix(value, "provider://")) > 0 {
		return nil
	}
	return fmt.Errorf("%s must be an env://%s secret reference%s", field, strings.ToUpper(strings.ReplaceAll(field, ".", "_")), map[bool]string{true: " or provider:// reference", false: ""}[allowProvider])
}

func validateName(kind, value string) error {
	if !namePattern.MatchString(value) {
		return fmt.Errorf("%s name %q must match %s", kind, value, namePattern)
	}
	return nil
}

func validateStringList(field string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || strings.ContainsAny(value, "\x00\t\r\n") {
			return fmt.Errorf("%s contains an empty or unsafe value", field)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains duplicate %q", field, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateRouteStringList(field string, values []string) error {
	if err := validateStringList(field, values); err != nil {
		return err
	}
	for _, value := range values {
		if err := ValidateRouteSegment(value); err != nil {
			return fmt.Errorf("%s contains non-routable value %q: %w", field, value, err)
		}
	}
	return nil
}

// ValidateRouteSegment enforces the literal object-key alphabet shared with
// edge/shared/contract.mjs. Every admitted byte is preserved in manifests and
// origin keys. Standard URL serializers encode only caret from this alphabet;
// the edge accepts its exact uppercase %5E wire form and recovers the literal
// byte before applying route and entitlement gates.
func ValidateRouteSegment(value string) error {
	if value == "" || value == "." || value == ".." {
		return errors.New("must be a non-empty, non-dot URL segment")
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("+._~^:-", rune(character)) {
			continue
		}
		return fmt.Errorf("contains byte 0x%02x outside [A-Za-z0-9+._~^:-]", character)
	}
	return nil
}

// EncodeRouteWirePath converts a canonical literal object-key path into the
// sole client-visible URL spelling shared with the edge contract. The frozen
// route alphabet is preserved byte-for-byte except for caret, which WHATWG URL
// serializers represent as uppercase %5E. This is deliberately not a general
// URI encoder and never accepts an already escaped input.
func EncodeRouteWirePath(value string) (string, error) {
	if err := validateRoutePath(value); err != nil {
		return "", err
	}
	return strings.ReplaceAll(value, "^", "%5E"), nil
}

// DecodeRouteWirePath is the exact inverse accepted at a raw URL-string
// boundary. Decode-and-reencode equality rejects lowercase escapes, encoded
// unreserved bytes, separators, double encoding, and raw caret aliases.
func DecodeRouteWirePath(value string) (string, error) {
	decoded := strings.ReplaceAll(value, "%5E", "^")
	if strings.Contains(decoded, "%") {
		return "", errors.New("contains a non-canonical percent escape")
	}
	encoded, err := EncodeRouteWirePath(decoded)
	if err != nil {
		return "", err
	}
	if encoded != value {
		return "", errors.New("is not the canonical route wire spelling")
	}
	return decoded, nil
}

// CanonicalRouteURL appends one canonical literal route path to a clean HTTP(S)
// base URL and returns its exact client-visible spelling. Callers use it for
// generated mirrorlists and verification expectations so the URL body, purge
// plan, and edge decoder cannot disagree about caret-bearing object keys.
func CanonicalRouteURL(baseURL, literalPath string, trailingSlash bool) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Opaque != "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("base URL must be a clean absolute HTTP(S) URL")
	}
	basePath := strings.TrimSuffix(strings.TrimPrefix(parsed.Path, "/"), "/")
	if parsed.Path != "" && parsed.Path != "/" && parsed.Path != "/"+basePath && parsed.Path != "/"+basePath+"/" {
		return "", errors.New("base URL path is not canonical")
	}
	if basePath != "" {
		if err := validateRoutePath(basePath); err != nil {
			return "", fmt.Errorf("base URL path: %w", err)
		}
	}
	wirePath, err := EncodeRouteWirePath(literalPath)
	if err != nil {
		return "", fmt.Errorf("route path: %w", err)
	}
	parsed.Path = "/" + basePath
	if basePath == "" {
		parsed.Path = ""
	}
	parsed.RawPath = ""
	canonicalBase := strings.TrimSuffix(parsed.String(), "/")
	result := canonicalBase + "/" + wirePath
	if trailingSlash {
		result += "/"
	}
	return result, nil
}

func validateRoutePath(value string) error {
	if err := validateRelativePath(value); err != nil {
		return err
	}
	clean := path.Clean(value)
	if clean != value {
		return errors.New("must be a normalized POSIX path")
	}
	for _, segment := range strings.Split(clean, "/") {
		if err := ValidateRouteSegment(segment); err != nil {
			return fmt.Errorf("segment %q: %w", segment, err)
		}
	}
	return nil
}

func validateRelativePath(value string) error {
	if value == "" || path.IsAbs(value) {
		return errors.New("must be a non-empty relative path")
	}
	if strings.ContainsRune(value, '\\') {
		return errors.New("must be a relative POSIX path without backslashes")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New("contains an unsafe control character")
		}
	}
	clean := path.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return errors.New("must name a non-root path inside root")
	}
	return nil
}

func hasPathNamespace(value, namespace string) bool {
	return value == namespace || strings.HasPrefix(value, namespace+"/")
}

func validateNonOverlapping(paths []string) error {
	sort.Strings(paths)
	for i := range paths {
		if conflict, exists := firstSortedPathConflict(paths, i); exists {
			return fmt.Errorf("repo paths overlap: %q and %q", paths[i], paths[conflict])
		}
	}
	return nil
}

// firstSortedPathConflict preserves the old nested-loop choice (lowest left
// index, then lowest conflicting right index) while using the lexical prefix
// interval of a normalized path. Callers sort once before querying.
func firstSortedPathConflict(paths []string, leftIndex int) (int, bool) {
	if leftIndex < 0 || leftIndex+1 >= len(paths) {
		return 0, false
	}
	left := strings.TrimSuffix(paths[leftIndex], "/")
	if strings.TrimSuffix(paths[leftIndex+1], "/") == left {
		return leftIndex + 1, true
	}
	prefix := left + "/"
	offset := sort.Search(len(paths)-leftIndex-1, func(relative int) bool {
		candidate := strings.TrimSuffix(paths[leftIndex+1+relative], "/")
		return candidate >= prefix
	})
	if offset == len(paths)-leftIndex-1 {
		return 0, false
	}
	candidateIndex := leftIndex + 1 + offset
	if strings.HasPrefix(strings.TrimSuffix(paths[candidateIndex], "/"), prefix) {
		return candidateIndex, true
	}
	return 0, false
}

func containsReservedComponent(value string) bool {
	for _, component := range strings.Split(filepath.ToSlash(value), "/") {
		if component == StateDirectory || component == PoolDirectory || component == ".git" || component == "_sow" {
			return true
		}
	}
	return false
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func sameStringSet(left, right []string) bool {
	left = append([]string{}, left...)
	right = append([]string{}, right...)
	sort.Strings(left)
	sort.Strings(right)
	return sameStrings(left, right)
}

func (c *Config) StatePath() string { return filepath.Join(c.Root, StateDirectory) }
func (c *Config) PoolPath() string  { return filepath.Join(c.Root, PoolDirectory) }

// ServingBaseURL returns the frozen public base for a mutable local view. An
// empty serving block remains valid for APT/asset-only configurations, but a
// caller selecting YUM must treat the returned error as a pre-mutation config
// failure rather than guessing one of the cloud target origins.
func (c *Config) ServingBaseURL(view string) (string, error) {
	var value string
	switch view {
	case "latest":
		value = c.Serving.Latest.BaseURL
	case "beta":
		value = c.Serving.Beta.BaseURL
	case "stable":
		value = c.Serving.Stable.BaseURL
	default:
		return "", fmt.Errorf("view %q has no mutable serving base URL", view)
	}
	if value == "" {
		return "", fmt.Errorf("serving.%s.base_url is required for mutable YUM materialization", view)
	}
	return value, nil
}

// Canonical serializes only the validated declarative schema. Runtime-resolved
// paths and secret values are never included; secret references remain intact.
func (c *Config) Canonical() ([]byte, error) {
	clone := *c
	clone.Path = ""
	clone.Root = ""
	encoded, err := yaml.Marshal(&clone)
	if err != nil {
		return nil, fmt.Errorf("encode canonical config: %w", err)
	}
	if len(encoded) > MaxConfigBytes {
		return nil, fmt.Errorf("canonical config exceeds %d-byte safety limit", MaxConfigBytes)
	}
	return encoded, nil
}

func (c *Config) CanonicalSHA256() (string, error) {
	encoded, err := c.Canonical()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (c *Config) RepoByName(name string) (Repo, bool) {
	for _, repo := range c.Repos {
		if repo.ID == name {
			return repo, true
		}
	}
	return Repo{}, false
}

func (c *Config) RepoSelectorNames() []string {
	result := make([]string, 0, len(c.Repos)+len(c.RepoGroups))
	for _, repo := range c.Repos {
		result = append(result, repo.ID)
	}
	for group := range c.RepoGroups {
		result = append(result, group)
	}
	sort.Strings(result)
	return result
}

// ExpandRepoSelectors resolves explicit IDs and configured groups to physical
// repositories only. There is deliberately no glob or prefix matching: an
// operation's selected set changes only when the canonical group membership
// changes, which also changes CanonicalSHA256 and invalidates stale recovery.
func (c *Config) ExpandRepoSelectors(selectors []string) ([]string, error) {
	if len(selectors) == 0 {
		return nil, nil
	}
	physical := make(map[string]struct{}, len(c.Repos))
	for _, repo := range c.Repos {
		physical[repo.ID] = struct{}{}
	}
	result := make(map[string]struct{})
	for _, selector := range selectors {
		if _, exists := physical[selector]; exists {
			result[selector] = struct{}{}
			continue
		}
		members, exists := c.RepoGroups[selector]
		if !exists {
			return nil, fmt.Errorf("unknown repo selector %q", selector)
		}
		for _, member := range members {
			if _, exists := physical[member]; !exists {
				return nil, fmt.Errorf("repo group %q contains unavailable physical repo %q", selector, member)
			}
			result[member] = struct{}{}
		}
	}
	expanded := make([]string, 0, len(result))
	for repo := range result {
		expanded = append(expanded, repo)
	}
	sort.Strings(expanded)
	return expanded, nil
}

func (r Repo) LifecycleForSuite(suite string) string {
	if r.Type == "apt" && r.APT != nil && r.APT.hasSuiteLifecycle() {
		if lifecycle, exists := r.APT.SuiteLifecycle[suite]; exists {
			return lifecycle
		}
		// A validated config always has complete coverage. Keeping an invalid or
		// manually narrowed value fail-closed is safer than silently inheriting
		// the repository-wide active lifecycle.
		return "frozen"
	}
	return r.OS.Lifecycle
}

func (r Repo) OSSelectorValues() []string {
	if r.Type == "asset" {
		return []string{"all"}
	}
	if r.Type == "yum" && r.YUM != nil && r.YUM.CompatibilityCarrier {
		return []string{"cross-el"}
	}
	if r.Type == "apt" && r.APT != nil {
		return append([]string(nil), r.APT.Suites...)
	}
	var values []string
	if r.OS.Suite != "" {
		values = append(values, r.OS.Suite)
	}
	if r.OS.Family != "" && r.OS.Major > 0 {
		values = append(values, r.OS.Family+strconv.Itoa(r.OS.Major))
	}
	return values
}

func (r Repo) ArchSelectorValues() []string {
	if r.Type == "asset" {
		return []string{"all"}
	}
	return append([]string(nil), r.Arches...)
}

// PathForArch resolves the only path template supported by schema v1. A
// multi-architecture YUM family must state the legacy URL shape explicitly via
// {arch}; single-leaf and all non-YUM repositories use their exact path.
func (r Repo) PathForArch(arch string) (string, error) {
	placeholder, err := r.validatePathTemplate()
	if err != nil {
		return "", err
	}
	if placeholder == 0 {
		return r.Path, nil
	}
	if !containsString(r.Arches, arch) {
		return "", fmt.Errorf("arch %q is not configured for repo %s", arch, r.ID)
	}
	return r.pathForConfiguredArch(arch)
}

func (r Repo) validatePathTemplate() (int, error) {
	placeholder := strings.Count(r.Path, "{arch}")
	if placeholder > 1 || (placeholder == 1 && r.Type != "yum") || (placeholder == 0 && strings.ContainsAny(r.Path, "{}")) {
		return 0, errors.New("only YUM paths may contain one {arch} placeholder")
	}
	if r.Type == "yum" && len(r.Arches) > 1 && placeholder != 1 {
		return 0, errors.New("multi-architecture YUM repo path must contain {arch}")
	}
	return placeholder, nil
}

// pathForConfiguredArch expands an architecture already proven to belong to
// the repository. ExpandedPaths uses it after one list validation so it never
// re-scans the same arches slice once per member.
func (r Repo) pathForConfiguredArch(arch string) (string, error) {
	value := strings.Replace(r.Path, "{arch}", arch, 1)
	if err := validateRelativePath(value); err != nil {
		return "", err
	}
	return filepath.ToSlash(filepath.Clean(value)), nil
}

func (r Repo) ExpandedPaths() ([]string, error) {
	placeholder, err := r.validatePathTemplate()
	if err != nil {
		return nil, err
	}
	if placeholder == 1 {
		if len(r.Arches) == 0 {
			return nil, errors.New("only YUM paths may contain one {arch} placeholder")
		}
		paths := make([]string, 0, len(r.Arches))
		for _, arch := range r.Arches {
			value, err := r.pathForConfiguredArch(arch)
			if err != nil {
				return nil, err
			}
			paths = append(paths, value)
		}
		return paths, nil
	}
	return []string{r.Path}, nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
