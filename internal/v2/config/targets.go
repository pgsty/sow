package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v4"
)

var (
	r2BucketPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$`)
	r2RegionPattern = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
)

const maximumPublicationCacheTTL = time.Duration(1<<63-1) - 24*time.Hour

// TargetConfig is a private publication binding. Credential is a reference,
// never credential material; the public prefix itself remains pool/ + dists/.
type TargetConfig struct {
	Repository              string `yaml:"repository" json:"repository"`
	Provider                string `yaml:"provider" json:"provider"`
	Endpoint                string `yaml:"endpoint" json:"endpoint"`
	Region                  string `yaml:"region,omitempty" json:"region,omitempty"`
	Bucket                  string `yaml:"bucket,omitempty" json:"bucket,omitempty"`
	Prefix                  string `yaml:"prefix" json:"prefix"`
	Credential              string `yaml:"credential,omitempty" json:"credential,omitempty"`
	PublicEndpoint          string `yaml:"public_endpoint" json:"public_endpoint"`
	MaxCacheTTL             string `yaml:"max_cache_ttl" json:"max_cache_ttl"`
	AuthoritativeWorkspace  bool   `yaml:"authoritative_workspace" json:"authoritative_workspace"`
	SingleWriter            bool   `yaml:"single_writer" json:"single_writer"`
	ExclusiveWriteAuthority bool   `yaml:"exclusive_write_authority" json:"exclusive_write_authority"`
}

// UnmarshalYAML defaults the workspace-authority flags to true when omitted so
// operators do not need to repeat boilerplate booleans in every target block,
// while preserving strict KnownFields checking and rejecting explicit null values.
func (t *TargetConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(value.Content); i += 2 {
			k, v := value.Content[i].Value, value.Content[i+1]
			switch k {
			case "authoritative_workspace", "single_writer", "exclusive_write_authority":
				if v.Tag == "!!null" {
					return fmt.Errorf("target field %q must be a boolean, not null", k)
				}
			}
		}
	}
	type rawTargetConfig struct {
		Repository              string `yaml:"repository"`
		Provider                string `yaml:"provider"`
		Endpoint                string `yaml:"endpoint"`
		Region                  string `yaml:"region,omitempty"`
		Bucket                  string `yaml:"bucket,omitempty"`
		Prefix                  string `yaml:"prefix"`
		Credential              string `yaml:"credential,omitempty"`
		PublicEndpoint          string `yaml:"public_endpoint"`
		MaxCacheTTL             string `yaml:"max_cache_ttl"`
		AuthoritativeWorkspace  *bool  `yaml:"authoritative_workspace"`
		SingleWriter            *bool  `yaml:"single_writer"`
		ExclusiveWriteAuthority *bool  `yaml:"exclusive_write_authority"`
	}
	var raw rawTargetConfig
	if err := value.Load(&raw, yaml.WithKnownFields()); err != nil {
		return err
	}
	defaultTrue := func(v *bool) bool {
		if v == nil {
			return true
		}
		return *v
	}
	*t = TargetConfig{
		Repository:              raw.Repository,
		Provider:                raw.Provider,
		Endpoint:                raw.Endpoint,
		Region:                  raw.Region,
		Bucket:                  raw.Bucket,
		Prefix:                  raw.Prefix,
		Credential:              raw.Credential,
		PublicEndpoint:          raw.PublicEndpoint,
		MaxCacheTTL:             raw.MaxCacheTTL,
		AuthoritativeWorkspace:  defaultTrue(raw.AuthoritativeWorkspace),
		SingleWriter:            defaultTrue(raw.SingleWriter),
		ExclusiveWriteAuthority: defaultTrue(raw.ExclusiveWriteAuthority),
	}
	return nil
}

// TargetBinding is the canonical, name-independent identity persisted by the
// publication state layer. StorageIdentity deliberately excludes Prefix.
type TargetBinding struct {
	Name            string `json:"name"`
	Repository      string `json:"repository"`
	Provider        string `json:"provider"`
	Endpoint        string `json:"endpoint"`
	Region          string `json:"region,omitempty"`
	Bucket          string `json:"bucket,omitempty"`
	Prefix          string `json:"prefix"`
	StorageIdentity string `json:"target_storage_id"`
	TargetIdentity  string `json:"target_identity"`
}

func normalizeAndValidateTargets(cfg *Config) error {
	bindings := make([]TargetBinding, 0, len(cfg.Targets))
	names := make([]string, 0, len(cfg.Targets))
	for name := range cfg.Targets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ValidateName(name); err != nil {
			return fmt.Errorf("target name %q: %w", name, err)
		}
		target := cfg.Targets[name]
		binding, err := validateTarget(name, &target, cfg.Repositories)
		if err != nil {
			return fmt.Errorf("target %q: %w", name, err)
		}
		cfg.Targets[name] = target
		bindings = append(bindings, binding)
	}
	for index, left := range bindings {
		for _, right := range bindings[index+1:] {
			sameBucket := left.Provider == "r2" && right.Provider == "r2" && left.Endpoint == right.Endpoint && left.Bucket == right.Bucket
			if (left.StorageIdentity == right.StorageIdentity || sameBucket) && prefixesOverlap(left.Prefix, right.Prefix) {
				return fmt.Errorf("targets %q and %q overlap on storage %s at prefixes %q and %q", left.Name, right.Name, left.StorageIdentity, left.Prefix, right.Prefix)
			}
			// file:// endpoints name the storage namespace themselves. Two
			// differently-spelled endpoint/prefix pairs may therefore resolve to
			// nested effective directories even though their storage identities
			// differ. Reject that aliasing at configuration time.
			if left.Provider == "filesystem" && right.Provider == "filesystem" {
				leftPath, leftErr := filesystemTargetPath(left)
				rightPath, rightErr := filesystemTargetPath(right)
				if leftErr != nil || rightErr != nil {
					return errors.Join(leftErr, rightErr)
				}
				if canonicalPathsOverlap(leftPath, rightPath) {
					return fmt.Errorf("filesystem targets %q and %q overlap at effective paths %q and %q", left.Name, right.Name, leftPath, rightPath)
				}
			}
		}
	}
	return nil
}

func validateTarget(name string, target *TargetConfig, repositories map[string]RepositoryConfig) (TargetBinding, error) {
	if _, ok := repositories[target.Repository]; !ok || target.Repository == "" {
		return TargetBinding{}, fmt.Errorf("repository %q is not configured", target.Repository)
	}
	if target.Provider != "filesystem" && target.Provider != "r2" {
		return TargetBinding{}, fmt.Errorf("provider must be filesystem or r2, got %q", target.Provider)
	}
	normalizedEndpoint, err := normalizeAndValidateTargetEndpoint(target.Provider, target.Endpoint)
	if err != nil {
		return TargetBinding{}, err
	}
	target.Endpoint = normalizedEndpoint
	if err := validateCanonicalPrefix(target.Prefix); err != nil {
		return TargetBinding{}, fmt.Errorf("prefix: %w", err)
	}
	normalizedPublic, err := normalizeAndValidatePublicEndpoint(target.PublicEndpoint)
	if err != nil {
		return TargetBinding{}, fmt.Errorf("public endpoint: %w", err)
	}
	target.PublicEndpoint = normalizedPublic
	if target.Provider == "r2" {
		public, _ := url.Parse(target.PublicEndpoint)
		if public.Scheme != "https" && public.Scheme != "http" {
			return TargetBinding{}, errors.New("r2 public endpoint scheme must be https or http")
		}
	}
	if target.MaxCacheTTL == "" {
		return TargetBinding{}, errors.New("max_cache_ttl is required, including explicit 0s")
	}
	rawTTL := strings.TrimSpace(target.MaxCacheTTL)
	if rawTTL == "0" {
		rawTTL = "0s"
	}
	ttl, err := time.ParseDuration(rawTTL)
	if err != nil || ttl < 0 || ttl > maximumPublicationCacheTTL {
		return TargetBinding{}, fmt.Errorf("max_cache_ttl %q must be a Go duration between 0s and %s", target.MaxCacheTTL, maximumPublicationCacheTTL)
	}
	target.MaxCacheTTL = ttl.String()
	if !target.AuthoritativeWorkspace || !target.SingleWriter || !target.ExclusiveWriteAuthority {
		return TargetBinding{}, errors.New("authoritative_workspace, single_writer, and exclusive_write_authority must all be true")
	}
	switch target.Provider {
	case "filesystem":
		if target.Region != "" || target.Bucket != "" || target.Credential != "" {
			return TargetBinding{}, errors.New("filesystem target forbids region, bucket, and credential")
		}
	case "r2":
		target.Region = strings.ToLower(strings.TrimSpace(target.Region))
		if target.Region == "" {
			target.Region = "auto"
		}
		if !r2RegionPattern.MatchString(target.Region) {
			return TargetBinding{}, fmt.Errorf("r2 region %q is invalid", target.Region)
		}
		if err := validateTargetComponent("bucket", target.Bucket); err != nil {
			return TargetBinding{}, err
		}
		if !r2BucketPattern.MatchString(target.Bucket) || strings.Contains(target.Bucket, "..") {
			return TargetBinding{}, fmt.Errorf("bucket %q is not a DNS-safe R2 bucket label", target.Bucket)
		}
		if err := validateCredentialReference(target.Credential); err != nil {
			return TargetBinding{}, err
		}
	}
	storage := targetIdentity("sow/target-storage/v1", target.Provider, target.Endpoint, target.Region, target.Bucket)
	identity := targetIdentity("sow/target/v1", storage, target.Prefix)
	return TargetBinding{Name: name, Repository: target.Repository, Provider: target.Provider, Endpoint: target.Endpoint, Region: target.Region, Bucket: target.Bucket, Prefix: target.Prefix, StorageIdentity: storage, TargetIdentity: identity}, nil
}

// TargetBindings returns canonical bindings in target-name order.
func (cfg Config) TargetBindings() ([]TargetBinding, error) {
	copyCfg := cloneConfig(cfg)
	if err := normalizeAndValidate(&copyCfg); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(copyCfg.Targets))
	for name := range copyCfg.Targets {
		names = append(names, name)
	}
	sort.Strings(names)
	bindings := make([]TargetBinding, 0, len(names))
	for _, name := range names {
		target := copyCfg.Targets[name]
		binding, err := validateTarget(name, &target, copyCfg.Repositories)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, nil
}

func normalizeAndValidateTargetEndpoint(provider, raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("endpoint %q is not a valid URL without userinfo, query, or fragment", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if provider == "filesystem" {
		if u.Scheme != "file" || u.Host != "" || !strings.HasPrefix(u.Path, "/") || u.RawPath != "" {
			return "", fmt.Errorf("filesystem endpoint %q must be canonical file:///absolute/path", raw)
		}
		cleaned := path.Clean(u.Path)
		if cleaned == "/" {
			return "", fmt.Errorf("filesystem endpoint %q must not be /", raw)
		}
		u.Path = cleaned
		return u.String(), nil
	}
	if u.Host == "" || u.RawPath != "" {
		return "", fmt.Errorf("r2 endpoint %q must be https://host (or http://localhost)", raw)
	}
	u.Host = normalizeHostPort(u.Scheme, u.Host)
	if !canonicalHost(u.Host) {
		return "", fmt.Errorf("r2 endpoint %q host is not valid", raw)
	}
	host := u.Hostname()
	isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && !(isLocal && u.Scheme == "http") {
		return "", fmt.Errorf("r2 endpoint %q must use https (or http for localhost)", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("r2 endpoint %q must not include a path", raw)
	}
	u.Path = ""
	return u.String(), nil
}

func normalizeAndValidatePublicEndpoint(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return "", errors.New("must be a valid URL without userinfo, query, or fragment")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "file" {
		return "", errors.New("scheme must be https, http, or file")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	withoutSlash := strings.TrimSuffix(u.Path, "/")
	if withoutSlash == "" {
		withoutSlash = "/"
	}
	if path.Clean(withoutSlash) != withoutSlash {
		return "", errors.New("path contains non-canonical dot or empty segments")
	}
	if u.Scheme == "file" {
		if u.Host != "" || !strings.HasPrefix(u.Path, "/") {
			return "", errors.New("file endpoint must be canonical and absolute")
		}
	} else {
		u.Host = normalizeHostPort(u.Scheme, u.Host)
		if u.Host == "" || !canonicalHost(u.Host) {
			return "", errors.New("HTTP endpoint host is not valid ASCII")
		}
	}
	return u.String(), nil
}

func normalizeHostPort(scheme, hostport string) string {
	hostport = strings.ToLower(hostport)
	host, port, err := net.SplitHostPort(hostport)
	if err == nil {
		if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
			if strings.Contains(host, ":") {
				return "[" + host + "]"
			}
			return host
		}
	}
	return hostport
}

func canonicalHost(hostport string) bool {
	if strings.ToLower(hostport) != hostport || strings.ContainsAny(hostport, "\t\r\n ") {
		return false
	}
	for _, r := range hostport {
		if r > 0x7f {
			return false // IDNs must already use their lower-case ASCII spelling.
		}
	}
	host, port, err := net.SplitHostPort(hostport)
	if err == nil {
		return host != "" && port != "80" && port != "443"
	}
	return !strings.Contains(hostport, ":") || strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]")
}

func validateCanonicalPrefix(prefix string) error {
	if prefix == "" { // Empty means the entire storage namespace and conflicts with all siblings.
		return nil
	}
	if strings.TrimSpace(prefix) != prefix || strings.HasPrefix(prefix, "/") || strings.HasSuffix(prefix, "/") || strings.ContainsAny(prefix, "\\?#") {
		return errors.New("must be trimmed, relative, and contain no trailing slash, backslash, query, or fragment")
	}
	lower := strings.ToLower(prefix)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return errors.New("must not contain a percent-encoded separator")
	}
	for _, segment := range strings.Split(prefix, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("contains an empty or dot segment")
		}
		for _, r := range segment {
			if r < 0x21 || r > 0x7e {
				return errors.New("must use canonical visible ASCII spelling")
			}
		}
	}
	return nil
}

func validateTargetComponent(label, value string) error {
	if value == "" || strings.TrimSpace(value) != value || strings.ToLower(value) != value || strings.ContainsAny(value, "/\\?#") {
		return fmt.Errorf("%s %q is not canonical", label, value)
	}
	return nil
}

func validateCredentialReference(reference string) error {
	if reference == "" || strings.TrimSpace(reference) != reference {
		return errors.New("credential must be a non-empty reference")
	}
	if strings.HasPrefix(reference, "env://") && environmentName.MatchString(strings.TrimPrefix(reference, "env://")) {
		return nil
	}
	if strings.HasPrefix(reference, "file://") && strings.HasPrefix(strings.TrimPrefix(reference, "file://"), "/") {
		return nil
	}
	return errors.New("credential must use env://NAME or file:///absolute/path; inline secrets are forbidden")
}

func prefixesOverlap(left, right string) bool {
	return left == "" || right == "" || left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func filesystemTargetPath(binding TargetBinding) (string, error) {
	endpoint, err := url.Parse(binding.Endpoint)
	if err != nil || endpoint.Scheme != "file" || endpoint.Host != "" {
		return "", fmt.Errorf("filesystem target %q has invalid endpoint", binding.Name)
	}
	return path.Clean(path.Join(endpoint.Path, binding.Prefix)), nil
}

func canonicalPathsOverlap(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func targetIdentity(domain string, fields ...string) string {
	hash := sha256.New()
	hash.Write([]byte(domain))
	for _, field := range fields {
		hash.Write([]byte{0})
		hash.Write([]byte(field))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
