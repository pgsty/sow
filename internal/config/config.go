package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

const (
	Schema             = "sow/v1"
	StateDirectory     = ".sow"
	PoolDirectory      = ".pool"
	SnapshotIDFormat   = "<suite>-YYYYMMDD"
	DefaultProPrefix   = "/pro/v1/{token}/"
	DefaultSnapshotAge = 6
)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$`)

type Config struct {
	Schema    string            `yaml:"schema"`
	State     StateConfig       `yaml:"state"`
	GPG       GPGConfig         `yaml:"gpg"`
	Pools     map[string]Pool   `yaml:"pools"`
	Repos     []Repo            `yaml:"repos"`
	Upstreams []Upstream        `yaml:"upstreams"`
	Views     map[string]View   `yaml:"views"`
	Targets   map[string]Target `yaml:"targets"`
	Edge      EdgeConfig        `yaml:"edge"`

	Path string `yaml:"-"`
	Root string `yaml:"-"`
}

type StateConfig struct {
	SnapshotMaterializationMonths int `yaml:"snapshot_materialization_months,omitempty"`
}

type GPGConfig struct {
	PublicKey  string `yaml:"public_key,omitempty"`
	PrivateKey string `yaml:"private_key,omitempty"`
	Passphrase string `yaml:"passphrase,omitempty"`
}

type Pool struct{}

type Repo struct {
	ID          string       `yaml:"id"`
	Type        string       `yaml:"type"`
	Path        string       `yaml:"path"`
	OS          OSConfig     `yaml:"os,omitempty"`
	Arches      []string     `yaml:"arches,omitempty"`
	DefaultPool string       `yaml:"default_pool"`
	Active      *bool        `yaml:"active,omitempty"`
	Include     []string     `yaml:"include,omitempty"`
	Exclude     []string     `yaml:"exclude,omitempty"`
	APT         *APTConfig   `yaml:"apt,omitempty"`
	YUM         *YUMConfig   `yaml:"yum,omitempty"`
	Asset       *AssetConfig `yaml:"asset,omitempty"`
}

func (r Repo) IsActive() bool { return r.Active == nil || *r.Active }

type OSConfig struct {
	Family    string `yaml:"family,omitempty"`
	Major     int    `yaml:"major,omitempty"`
	Suite     string `yaml:"suite,omitempty"`
	Lifecycle string `yaml:"lifecycle,omitempty"`
}

type APTConfig struct {
	Suites     []string `yaml:"suites"`
	Components []string `yaml:"components"`
}

type YUMConfig struct {
	Compression string `yaml:"compression"`
}

type AssetConfig struct {
	Kind string `yaml:"kind,omitempty"`
}

type Upstream struct {
	ID         string   `yaml:"id"`
	Type       string   `yaml:"type"`
	Repo       string   `yaml:"repo"`
	URL        string   `yaml:"url"`
	Arches     []string `yaml:"arches,omitempty"`
	Allow      []string `yaml:"allow,omitempty"`
	Deny       []string `yaml:"deny,omitempty"`
	DebugInfo  string   `yaml:"debuginfo,omitempty"`
	Credential string   `yaml:"credential,omitempty"`
}

type View struct {
	Access       string   `yaml:"access"`
	AllowedPools []string `yaml:"allowed_pools"`
	AppendOnly   bool     `yaml:"append_only"`
	Repos        []string `yaml:"repos,omitempty"`
}

type Target struct {
	Storage Storage `yaml:"storage"`
	CDN     CDN     `yaml:"cdn"`
}

type Storage struct {
	Kind       string `yaml:"kind"`
	Endpoint   string `yaml:"endpoint"`
	Bucket     string `yaml:"bucket"`
	Region     string `yaml:"region,omitempty"`
	Credential string `yaml:"credential"`
}

type CDN struct {
	Kind         string `yaml:"kind"`
	BaseURL      string `yaml:"base_url"`
	ZoneID       string `yaml:"zone_id,omitempty"`
	Distribution string `yaml:"distribution,omitempty"`
	Credential   string `yaml:"credential"`
}

type EdgeConfig struct {
	ProPrefix     string `yaml:"pro_prefix,omitempty"`
	TokenVerifier string `yaml:"token_verifier"`
}

func Load(path, rootOverride string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	cfg, err := Decode(f)
	if err != nil {
		return nil, err
	}
	absConfig, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}
	cfg.Path = absConfig
	root := rootOverride
	if root == "" {
		root = filepath.Dir(absConfig)
	}
	if !filepath.IsAbs(root) {
		root = filepath.Join(filepath.Dir(absConfig), root)
	}
	cfg.Root, err = filepath.Abs(filepath.Clean(root))
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}
	info, err := os.Stat(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("stat root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("root is not a directory: %s", cfg.Root)
	}
	return cfg, nil
}

func Decode(r io.Reader) (*Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
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
	return &cfg, nil
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
	if c.Edge.ProPrefix == "" {
		c.Edge.ProPrefix = DefaultProPrefix
	}
}

func (c *Config) Validate() error {
	if c.Schema != Schema {
		return fmt.Errorf("unsupported schema %q (want %s)", c.Schema, Schema)
	}
	if c.State.SnapshotMaterializationMonths < 1 {
		return errors.New("state.snapshot_materialization_months must be positive")
	}
	if c.Edge.ProPrefix != DefaultProPrefix {
		return fmt.Errorf("edge.pro_prefix is frozen at %s", DefaultProPrefix)
	}
	if c.Edge.TokenVerifier == "" {
		return errors.New("edge.token_verifier is required")
	}
	if err := validateSecretReference("edge.token_verifier", c.Edge.TokenVerifier, true); err != nil {
		return err
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
	if err := c.validateUpstreams(repoIDs); err != nil {
		return err
	}
	if err := c.validateViews(repoIDs); err != nil {
		return err
	}
	return c.validateTargets()
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
			return nil, fmt.Errorf("repos[%d].path uses a reserved .sow/.pool/.git component", i)
		}
		if _, exists := c.Pools[repo.DefaultPool]; !exists {
			return nil, fmt.Errorf("repos[%d]: unknown default_pool %q", i, repo.DefaultPool)
		}
		if len(repo.Arches) == 0 && repo.Type != "asset" {
			return nil, fmt.Errorf("repos[%d]: arches are required for %s", i, repo.Type)
		}
		if err := validateStringList(fmt.Sprintf("repos[%d].arches", i), repo.Arches); err != nil {
			return nil, err
		}
		if err := validateRepoUnion(*repo); err != nil {
			return nil, fmt.Errorf("repos[%d]: %w", i, err)
		}
		for _, pattern := range append(append([]string{}, repo.Include...), repo.Exclude...) {
			if !doublestar.ValidatePattern(pattern) || strings.HasPrefix(pattern, "/") || strings.ContainsAny(pattern, "\\\t\r\n") {
				return nil, fmt.Errorf("repos[%d]: invalid include/exclude pattern %q", i, pattern)
			}
		}
		if err := validateLifecycle(*repo); err != nil {
			return nil, fmt.Errorf("repos[%d]: %w", i, err)
		}
		paths = append(paths, repo.Path)
	}
	if err := validateNonOverlapping(paths); err != nil {
		return nil, err
	}
	return IDs, nil
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
	if repo.OS.Lifecycle != "active" && repo.OS.Lifecycle != "frozen" {
		return errors.New("os.lifecycle must be active or frozen")
	}
	if repo.Type == "yum" {
		if repo.OS.Family != "el" || repo.OS.Major <= 0 {
			return errors.New("yum repos require os.family=el and a positive major")
		}
		if repo.OS.Major == 8 && (repo.OS.Lifecycle != "frozen" || repo.YUM.Compression != "gzip") {
			return errors.New("EL8 is frozen and requires gzip repodata")
		}
		if repo.OS.Major >= 9 && repo.YUM.Compression != "zstd" {
			return errors.New("EL9/10 require zstd repodata")
		}
	}
	return nil
}

func (c *Config) validateUpstreams(repoIDs map[string]struct{}) error {
	seen := make(map[string]struct{})
	for i, upstream := range c.Upstreams {
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
		parsed, err := url.Parse(upstream.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return fmt.Errorf("upstreams[%d]: url must be absolute HTTPS", i)
		}
		if upstream.DebugInfo != "" && upstream.DebugInfo != "keep" && upstream.DebugInfo != "drop" {
			return fmt.Errorf("upstreams[%d]: debuginfo must be keep or drop", i)
		}
		if upstream.Credential != "" {
			if err := validateSecretReference(fmt.Sprintf("upstreams[%d].credential", i), upstream.Credential, false); err != nil {
				return err
			}
		}
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
		if name != "beta" && name != "latest" && name != "stable" && name != "snapshot" {
			return fmt.Errorf("unknown view %q", name)
		}
		if view.Access != "public" && view.Access != "pro" {
			return fmt.Errorf("view %s access must be public or pro", name)
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
		if (name == "beta" || name == "latest") && (view.Access != "public" || !sameStrings(view.AllowedPools, []string{"public"})) {
			return fmt.Errorf("view %s must be public and allow only public", name)
		}
		if name == "stable" && (!view.AppendOnly || view.Access != "pro" || !sameStringSet(view.AllowedPools, []string{"public", "gated"})) {
			return errors.New("stable must be append-only pro and allow public+gated")
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
		if target.Storage.Endpoint == "" || target.Storage.Bucket == "" || target.CDN.BaseURL == "" {
			return fmt.Errorf("target %s endpoint, bucket, and CDN base_url are required", name)
		}
		for field, rawURL := range map[string]string{"storage.endpoint": target.Storage.Endpoint, "cdn.base_url": target.CDN.BaseURL} {
			parsed, err := url.Parse(rawURL)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
				return fmt.Errorf("target %s %s must be absolute HTTPS", name, field)
			}
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

func validateRelativePath(value string) error {
	if value == "" || filepath.IsAbs(value) {
		return errors.New("must be a non-empty relative path")
	}
	clean := filepath.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("must name a non-root path inside root")
	}
	if strings.ContainsAny(value, "\t\r\n") {
		return errors.New("contains a tab or newline")
	}
	return nil
}

func validateNonOverlapping(paths []string) error {
	sort.Strings(paths)
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			left, right := strings.TrimSuffix(paths[i], "/"), strings.TrimSuffix(paths[j], "/")
			if left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/") {
				return fmt.Errorf("repo paths overlap: %q and %q", paths[i], paths[j])
			}
		}
	}
	return nil
}

func containsReservedComponent(value string) bool {
	for _, component := range strings.Split(filepath.ToSlash(value), "/") {
		if component == StateDirectory || component == PoolDirectory || component == ".git" {
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

func (c *Config) RepoByName(name string) (Repo, bool) {
	for _, repo := range c.Repos {
		if repo.ID == name {
			return repo, true
		}
	}
	return Repo{}, false
}

func (r Repo) OSSelectorValues() []string {
	var values []string
	if r.OS.Suite != "" {
		values = append(values, r.OS.Suite)
	}
	if r.OS.Family != "" && r.OS.Major > 0 {
		values = append(values, r.OS.Family+strconv.Itoa(r.OS.Major))
	}
	return values
}
