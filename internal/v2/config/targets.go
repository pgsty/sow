package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

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
		binding, err := validateTarget(name, target, cfg.Repositories)
		if err != nil {
			return fmt.Errorf("target %q: %w", name, err)
		}
		bindings = append(bindings, binding)
	}
	for index, left := range bindings {
		for _, right := range bindings[index+1:] {
			if left.StorageIdentity == right.StorageIdentity && prefixesOverlap(left.Prefix, right.Prefix) {
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

func validateTarget(name string, target TargetConfig, repositories map[string]RepositoryConfig) (TargetBinding, error) {
	if _, ok := repositories[target.Repository]; !ok || target.Repository == "" {
		return TargetBinding{}, fmt.Errorf("repository %q is not configured", target.Repository)
	}
	if target.Provider != "filesystem" && target.Provider != "r2" {
		return TargetBinding{}, fmt.Errorf("provider must be filesystem or r2, got %q", target.Provider)
	}
	if err := validateCanonicalTargetEndpoint(target.Provider, target.Endpoint); err != nil {
		return TargetBinding{}, err
	}
	if err := validateCanonicalPrefix(target.Prefix); err != nil {
		return TargetBinding{}, fmt.Errorf("prefix: %w", err)
	}
	if err := validateCanonicalPublicEndpoint(target.PublicEndpoint); err != nil {
		return TargetBinding{}, fmt.Errorf("public endpoint: %w", err)
	}
	if target.MaxCacheTTL == "" {
		return TargetBinding{}, errors.New("max_cache_ttl is required, including explicit 0s")
	}
	ttl, err := time.ParseDuration(target.MaxCacheTTL)
	if err != nil || ttl < 0 || target.MaxCacheTTL != ttl.String() {
		return TargetBinding{}, fmt.Errorf("max_cache_ttl %q is not a canonical non-negative Go duration", target.MaxCacheTTL)
	}
	if !target.AuthoritativeWorkspace || !target.SingleWriter || !target.ExclusiveWriteAuthority {
		return TargetBinding{}, errors.New("authoritative_workspace, single_writer, and exclusive_write_authority must all be true")
	}
	switch target.Provider {
	case "filesystem":
		if target.Region != "" || target.Bucket != "" || target.Credential != "" {
			return TargetBinding{}, errors.New("filesystem target forbids region, bucket, and credential")
		}
	case "r2":
		if target.Region != "auto" {
			return TargetBinding{}, errors.New("r2 region must be the canonical value auto")
		}
		if err := validateTargetComponent("bucket", target.Bucket); err != nil {
			return TargetBinding{}, err
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
		binding, err := validateTarget(name, copyCfg.Targets[name], copyCfg.Repositories)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, nil
}

func validateCanonicalTargetEndpoint(provider, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("endpoint %q is not a canonical URL without userinfo, query, or fragment", raw)
	}
	if provider == "filesystem" {
		if u.Scheme != "file" || u.Host != "" || !strings.HasPrefix(u.Path, "/") || u.RawPath != "" || path.Clean(u.Path) != u.Path || u.Path == "/" || strings.HasSuffix(u.Path, "/") || u.String() != raw {
			return fmt.Errorf("filesystem endpoint %q must be canonical file:///absolute/path without a trailing slash", raw)
		}
		return nil
	}
	if u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawPath != "" || u.String() != raw || !canonicalHost(u.Host) {
		return fmt.Errorf("r2 endpoint %q must be canonical https://host with no path or default port", raw)
	}
	return nil
}

func validateCanonicalPublicEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.String() != raw || !strings.HasSuffix(u.Path, "/") {
		return errors.New("must be a canonical URL ending in /")
	}
	if u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "file" {
		return errors.New("scheme must be https, http, or file")
	}
	withoutSlash := strings.TrimSuffix(u.Path, "/")
	if withoutSlash == "" {
		withoutSlash = "/"
	}
	if path.Clean(withoutSlash) != withoutSlash {
		return errors.New("path contains non-canonical dot or empty segments")
	}
	if u.Scheme == "file" {
		if u.Host != "" || !strings.HasPrefix(u.Path, "/") || path.Clean(strings.TrimSuffix(u.Path, "/")) != strings.TrimSuffix(u.Path, "/") {
			return errors.New("file endpoint must be canonical and absolute")
		}
	} else if u.Host == "" || !canonicalHost(u.Host) {
		return errors.New("HTTP endpoint host is not canonical")
	}
	return nil
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
