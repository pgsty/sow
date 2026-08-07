// Package config implements the strict, local SOW V2 P1 workspace
// configuration boundary.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const (
	ConfigFilename = "sow.yml"
	Schema         = "sow/v3"
	LegacySchema   = "sow/v2"
	maxConfigBytes = 16 << 20
)

var (
	defaultArchitectures = []string{"x86_64", "aarch64"}
	namePattern          = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	environmentName      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	gpgFingerprint       = regexp.MustCompile(`(?i)^(?:[0-9a-f]{16}|[0-9a-f]{40}|[0-9a-f]{64})$`)
	reservedNames        = map[string]struct{}{
		".": {}, "..": {}, ".sow": {}, "pool": {}, "dists": {}, ConfigFilename: {},
		"workspace-ops": {}, "repo-locks": {}, "workspace.lock": {},
	}
)

// Config is the canonical in-memory form of sow.yml. Parse normalizes the two
// ecosystem aliases and fills workspace defaults.
type Config struct {
	Schema        string                      `yaml:"schema" json:"schema"`
	Architectures []string                    `yaml:"architectures" json:"architectures"`
	Repositories  map[string]RepositoryConfig `yaml:"repos,omitempty" json:"repos,omitempty"`
	Targets       map[string]TargetConfig     `yaml:"targets,omitempty" json:"targets,omitempty"`
}

type RepositoryConfig struct {
	Protected bool                  `yaml:"protected,omitempty" json:"protected,omitempty"`
	Signing   SigningConfig         `yaml:"signing,omitempty" json:"signing,omitempty"`
	Dists     map[string]DistConfig `yaml:"dists,omitempty" json:"dists,omitempty"`
}

type DistConfig struct {
	Format        string        `yaml:"format" json:"format"`
	Architectures []string      `yaml:"architectures,omitempty" json:"architectures,omitempty"`
	Limit         int           `yaml:"limit,omitempty" json:"limit"`
	Exclude       []ExcludeRule `yaml:"exclude,omitempty" json:"exclude"`
}

type ExcludeRule struct {
	Name   []string `yaml:"name,omitempty" json:"name,omitempty"`
	Source []string `yaml:"source,omitempty" json:"source,omitempty"`
	Arch   []string `yaml:"arch,omitempty" json:"arch,omitempty"`
	Kind   []string `yaml:"kind,omitempty" json:"kind,omitempty"`
	Format []string `yaml:"format,omitempty" json:"format,omitempty"`
}

type SigningConfig struct {
	RPM RPMSigningConfig `yaml:"rpm,omitempty" json:"rpm,omitempty"`
	DEB DEBSigningConfig `yaml:"deb,omitempty" json:"deb,omitempty"`
}

type RPMSigningConfig struct {
	Packages RPMPackageSigningConfig `yaml:"packages,omitempty" json:"packages,omitempty"`
	Metadata MetadataSigningConfig   `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

type DEBSigningConfig struct {
	Metadata MetadataSigningConfig `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

type RPMPackageSigningConfig struct {
	Mode        string   `yaml:"mode,omitempty" json:"mode"`
	Key         string   `yaml:"key,omitempty" json:"key,omitempty"`
	TrustedKeys []string `yaml:"trusted_keys,omitempty" json:"trusted_keys,omitempty"`
}

type MetadataSigningConfig struct {
	Key        string `yaml:"key,omitempty" json:"key,omitempty"`
	Passphrase string `yaml:"passphrase,omitempty" json:"passphrase,omitempty"`
}

// Default returns a fresh current workspace config.
func Default() Config {
	return Config{
		Schema:        Schema,
		Architectures: append([]string(nil), defaultArchitectures...),
		Repositories:  make(map[string]RepositoryConfig),
		Targets:       make(map[string]TargetConfig),
	}
}

// Parse strictly decodes exactly one YAML document and validates the complete
// P1 configuration grammar.
func Parse(data []byte) (Config, error) {
	return parse(data, false)
}

// ParseForMigration is the compatibility decoder for a frozen v0.2 workspace.
// It returns a current in-memory projection plus an explicit legacy bit: read
// surfaces can operate under the old physical contract, while mutations still
// use the strict decoder and fail before the explicit layout transition.
func ParseForMigration(data []byte) (Config, bool, error) {
	cfg, err := parse(data, true)
	if err != nil {
		return Config{}, false, err
	}
	legacy := cfg.Schema == LegacySchema
	if legacy {
		cfg.Schema = Schema
	}
	return cfg, legacy, nil
}

func parse(data []byte, allowLegacy bool) (Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		if err == io.EOF {
			return Config{}, fmt.Errorf("config schema must be %q, got empty document", Schema)
		}
		return Config{}, fmt.Errorf("parse %s: %w", ConfigFilename, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, fmt.Errorf("parse %s: multiple YAML documents are not allowed", ConfigFilename)
		}
		return Config{}, fmt.Errorf("parse %s: %w", ConfigFilename, err)
	}
	if err := normalizeAndValidateSchema(&cfg, allowLegacy); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// LoadDocumentForMigration preserves the descriptor-bound source bytes while
// allowing only the one frozen predecessor schema. It is shared by explicit
// migration and mutation-free compatibility reads; callers must use the
// returned legacy bit to keep those authority domains separate.
func LoadDocumentForMigration(filename string) (Config, []byte, string, bool, error) {
	data, digest, err := readConfigFile(filename)
	if err != nil {
		return Config{}, nil, "", false, err
	}
	cfg, legacy, err := ParseForMigration(data)
	if err != nil {
		return Config{}, nil, "", false, fmt.Errorf("load config %q: %w", filename, err)
	}
	return cfg, data, digest, legacy, nil
}

// LoadWorkspaceDocumentForMigration is the root-bound compatibility/migration
// counterpart of LoadWorkspaceDocument. Ordinary writers continue to use the
// strict loader and therefore cannot cross the schema boundary implicitly.
func LoadWorkspaceDocumentForMigration(workspace Workspace) (Config, []byte, string, bool, error) {
	if workspace.rootDevice == 0 || workspace.rootInode == 0 || filepath.Clean(workspace.ConfigPath) != filepath.Join(filepath.Clean(workspace.Root), ConfigFilename) {
		return Config{}, nil, "", false, errors.New("load workspace config: invalid discovery root binding")
	}
	data, digest, err := readConfigFileBound(workspace.ConfigPath, workspace.rootDevice, workspace.rootInode, nil)
	if err != nil {
		return Config{}, nil, "", false, err
	}
	cfg, legacy, err := ParseForMigration(data)
	if err != nil {
		return Config{}, nil, "", false, fmt.Errorf("load config %q: %w", workspace.ConfigPath, err)
	}
	return cfg, data, digest, legacy, nil
}

// Load reads and strictly parses one sow.yml. It rejects symlinks and anything
// other than a regular file.
func Load(filename string) (Config, error) {
	cfg, _, _, err := LoadDocument(filename)
	return cfg, err
}

// LoadWithSHA parses and hashes the exact same bounded, descriptor-bound
// config bytes. Mutation journals use the returned digest so a concurrent
// pathname replacement cannot bind a different config from the one applied.
func LoadWithSHA(filename string) (Config, string, error) {
	cfg, _, digest, err := LoadDocument(filename)
	return cfg, digest, err
}

// LoadDocument returns the parsed config, exact source document, and digest
// from one descriptor-bound read. Lifecycle journals must preserve the source
// bytes from this call instead of reopening the pathname after validation.
func LoadDocument(filename string) (Config, []byte, string, error) {
	data, digest, err := readConfigFile(filename)
	if err != nil {
		return Config{}, nil, "", err
	}
	cfg, err := Parse(data)
	if err != nil {
		return Config{}, nil, "", fmt.Errorf("load config %q: %w", filename, err)
	}
	return cfg, data, digest, nil
}

// LoadWorkspace parses a config only when its descriptor-bound parent is the
// exact Workspace root inode captured by Discover. This closes the
// Discover-to-Load gap in which an ancestor could otherwise be replaced by a
// symlink or another same-shaped directory tree.
func LoadWorkspace(workspace Workspace) (Config, error) {
	cfg, _, _, err := LoadWorkspaceDocument(workspace)
	return cfg, err
}

// LoadWorkspaceWithSHA is the workspace-root-bound counterpart of LoadWithSHA.
func LoadWorkspaceWithSHA(workspace Workspace) (Config, string, error) {
	cfg, _, digest, err := LoadWorkspaceDocument(workspace)
	return cfg, digest, err
}

// LoadWorkspaceDocument returns one root-bound config snapshot and its digest.
func LoadWorkspaceDocument(workspace Workspace) (Config, []byte, string, error) {
	if workspace.rootDevice == 0 || workspace.rootInode == 0 || filepath.Clean(workspace.ConfigPath) != filepath.Join(filepath.Clean(workspace.Root), ConfigFilename) {
		return Config{}, nil, "", errors.New("load workspace config: invalid discovery root binding")
	}
	data, digest, err := readConfigFileBound(workspace.ConfigPath, workspace.rootDevice, workspace.rootInode, nil)
	if err != nil {
		return Config{}, nil, "", err
	}
	cfg, err := Parse(data)
	if err != nil {
		return Config{}, nil, "", fmt.Errorf("load config %q: %w", workspace.ConfigPath, err)
	}
	return cfg, data, digest, nil
}

// FileSHA returns the digest of one safe, bounded sow.yml without parsing it.
// Recovery uses it to compare the current decision state with a closed journal.
func FileSHA(filename string) (string, error) {
	_, digest, err := readConfigFile(filename)
	return digest, err
}

func readConfigFile(filename string) ([]byte, string, error) {
	return readConfigFileBound(filename, 0, 0, nil)
}

type configDirectoryBinding struct {
	directories []*os.File
	components  []string
	stats       []unix.Stat_t
}

func openConfigParent(parent string) (*configDirectoryBinding, error) {
	physical, err := filepath.Abs(parent)
	if err != nil {
		return nil, err
	}
	physical, err = normalizeTrustedRootAlias(filepath.Clean(physical))
	if err != nil {
		return nil, err
	}
	components := strings.Split(strings.TrimPrefix(physical, string(filepath.Separator)), string(filepath.Separator))
	if physical == string(filepath.Separator) {
		components = nil
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." || filepath.Base(component) != component {
			return nil, errors.New("config parent has an unsafe path component")
		}
	}
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	binding := &configDirectoryBinding{directories: []*os.File{os.NewFile(uintptr(rootFD), string(filepath.Separator))}, components: components}
	closeError := func(result error) (*configDirectoryBinding, error) {
		return nil, errors.Join(result, binding.close(false))
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil || uint32(rootStat.Mode)&unix.S_IFMT != unix.S_IFDIR {
		return closeError(errors.Join(errors.New("config filesystem root is unsafe"), err))
	}
	binding.stats = append(binding.stats, rootStat)
	for index, component := range components {
		parentHandle := binding.directories[len(binding.directories)-1]
		fd, openErr := unix.Openat(int(parentHandle.Fd()), component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if openErr != nil {
			return closeError(openErr)
		}
		child := os.NewFile(uintptr(fd), filepath.Join(components[:index+1]...))
		var opened, entry unix.Stat_t
		statErr := unix.Fstat(fd, &opened)
		entryErr := unix.Fstatat(int(parentHandle.Fd()), component, &entry, unix.AT_SYMLINK_NOFOLLOW)
		if statErr != nil || entryErr != nil || opened.Dev != entry.Dev || opened.Ino != entry.Ino || uint32(opened.Mode)&unix.S_IFMT != unix.S_IFDIR {
			_ = child.Close()
			return closeError(errors.Join(errors.New("config parent changed while opening"), statErr, entryErr))
		}
		binding.directories = append(binding.directories, child)
		binding.stats = append(binding.stats, opened)
	}
	return binding, nil
}

// normalizeTrustedRootAlias resolves only a root-level platform alias such as
// macOS /var -> /private/var. Deeper symlink components remain forbidden by
// the descriptor walk, so a user-writable Workspace ancestor cannot redirect
// a config load. Creating or replacing a root-level entry requires system
// authority and is outside the Workspace writer threat boundary.
func normalizeTrustedRootAlias(absolute string) (string, error) {
	components := strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 0 || components[0] == "" {
		return absolute, nil
	}
	top := filepath.Join(string(filepath.Separator), components[0])
	info, err := os.Lstat(top)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return absolute, nil
	}
	target, err := filepath.EvalSymlinks(top)
	if err != nil {
		return "", err
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if len(components) == 1 {
		return filepath.Clean(target), nil
	}
	return filepath.Join(append([]string{filepath.Clean(target)}, components[1:]...)...), nil
}

func (binding *configDirectoryBinding) directory() *os.File {
	if binding == nil || len(binding.directories) == 0 {
		return nil
	}
	return binding.directories[len(binding.directories)-1]
}

func (binding *configDirectoryBinding) verify() error {
	if binding == nil || len(binding.directories) == 0 || len(binding.directories) != len(binding.stats) || len(binding.components)+1 != len(binding.directories) {
		return errors.New("invalid config parent binding")
	}
	var result error
	for index, directory := range binding.directories {
		var opened unix.Stat_t
		statErr := unix.Fstat(int(directory.Fd()), &opened)
		expected := binding.stats[index]
		if statErr != nil || opened.Dev != expected.Dev || opened.Ino != expected.Ino || uint32(opened.Mode)&unix.S_IFMT != unix.S_IFDIR {
			result = errors.Join(result, errors.New("config parent descriptor changed during read"), statErr)
		}
		if index == 0 {
			continue
		}
		var entry unix.Stat_t
		entryErr := unix.Fstatat(int(binding.directories[index-1].Fd()), binding.components[index-1], &entry, unix.AT_SYMLINK_NOFOLLOW)
		if entryErr != nil || entry.Dev != expected.Dev || entry.Ino != expected.Ino || uint32(entry.Mode)&unix.S_IFMT != unix.S_IFDIR {
			result = errors.Join(result, errors.New("config parent pathname changed during read"), entryErr)
		}
	}
	return result
}

func (binding *configDirectoryBinding) close(verify bool) error {
	if binding == nil {
		return nil
	}
	var result error
	if verify {
		result = binding.verify()
	}
	for index := len(binding.directories) - 1; index >= 0; index-- {
		result = errors.Join(result, binding.directories[index].Close())
	}
	binding.directories = nil
	return result
}

func readConfigFileBound(filename string, expectedDevice, expectedInode uint64, afterParentBound func() error) ([]byte, string, error) {
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return nil, "", fmt.Errorf("load config %q: %w", filename, err)
	}
	parent := filepath.Dir(absolute)
	base := filepath.Base(absolute)
	if base == "" || base == "." || base == ".." || filepath.Base(base) != base {
		return nil, "", fmt.Errorf("load config %q: unsafe filename", filename)
	}
	parentBinding, err := openConfigParent(parent)
	if err != nil {
		return nil, "", fmt.Errorf("load config %q parent: %w", filename, err)
	}
	finish := func(data []byte, digest string, result error) ([]byte, string, error) {
		return data, digest, errors.Join(result, parentBinding.close(true))
	}
	parentFD := int(parentBinding.directory().Fd())
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return finish(nil, "", fmt.Errorf("load config %q parent: %w", filename, err))
	}
	if expectedDevice != 0 && (uint64(parentStat.Dev) != expectedDevice || uint64(parentStat.Ino) != expectedInode) {
		return finish(nil, "", fmt.Errorf("load config %q: workspace root identity changed after discovery", filename))
	}
	if afterParentBound != nil {
		if err := afterParentBound(); err != nil {
			return finish(nil, "", err)
		}
	}
	var entry unix.Stat_t
	if err := unix.Fstatat(parentFD, base, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return finish(nil, "", fmt.Errorf("load config %q: %w", filename, err))
	}
	if uint32(entry.Mode)&unix.S_IFMT == unix.S_IFLNK {
		return finish(nil, "", fmt.Errorf("load config %q: symlink is not allowed", filename))
	}
	if uint32(entry.Mode)&unix.S_IFMT != unix.S_IFREG || entry.Nlink != 1 || entry.Size > maxConfigBytes {
		return finish(nil, "", fmt.Errorf("load config %q: not a bounded regular file", filename))
	}
	fd, err := unix.Openat(parentFD, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return finish(nil, "", fmt.Errorf("load config %q: %w", filename, err))
	}
	file := os.NewFile(uintptr(fd), filename)
	opened, statErr := file.Stat()
	var openedRaw unix.Stat_t
	rawErr := unix.Fstat(fd, &openedRaw)
	if statErr != nil || rawErr != nil || !opened.Mode().IsRegular() || openedRaw.Nlink != 1 || openedRaw.Dev != entry.Dev || openedRaw.Ino != entry.Ino || opened.Size() > maxConfigBytes {
		_ = file.Close()
		return finish(nil, "", fmt.Errorf("load config %q: changed while opening: %w", filename, errors.Join(statErr, rawErr)))
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	afterFD, descriptorErr := file.Stat()
	var afterRaw, afterEntry unix.Stat_t
	afterRawErr := unix.Fstat(fd, &afterRaw)
	entryErr := unix.Fstatat(parentFD, base, &afterEntry, unix.AT_SYMLINK_NOFOLLOW)
	parentErr := parentBinding.verify()
	closeErr := file.Close()
	if err := errors.Join(readErr, descriptorErr, afterRawErr, entryErr, parentErr, closeErr); err != nil {
		return finish(nil, "", fmt.Errorf("load config %q: %w", filename, err))
	}
	if int64(len(data)) != opened.Size() || int64(len(data)) > maxConfigBytes || !afterFD.Mode().IsRegular() ||
		!os.SameFile(opened, afterFD) || afterFD.Size() != opened.Size() || !afterFD.ModTime().Equal(opened.ModTime()) ||
		afterRaw.Dev != openedRaw.Dev || afterRaw.Ino != openedRaw.Ino || afterRaw.Nlink != 1 || afterRaw.Size != openedRaw.Size ||
		afterEntry.Dev != openedRaw.Dev || afterEntry.Ino != openedRaw.Ino || afterEntry.Nlink != 1 || afterEntry.Size != openedRaw.Size ||
		uint32(afterEntry.Mode)&unix.S_IFMT != unix.S_IFREG {
		return finish(nil, "", fmt.Errorf("load config %q: changed while reading or exceeds %d bytes", filename, maxConfigBytes))
	}
	sum := sha256.Sum256(data)
	return finish(data, hex.EncodeToString(sum[:]), nil)
}

// Marshal emits a stable canonical sow.yml. The input is cloned before
// validation so normalization never mutates caller-owned maps or slices.
func Marshal(input Config) ([]byte, error) {
	cfg := cloneConfig(input)
	if err := normalizeAndValidate(&cfg); err != nil {
		return nil, err
	}
	data, err := marshalYAML(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", ConfigFilename, err)
	}
	return data, nil
}

func normalizeAndValidate(cfg *Config) error {
	return normalizeAndValidateSchema(cfg, false)
}

func normalizeAndValidateSchema(cfg *Config, allowLegacy bool) error {
	if cfg.Schema != Schema && (!allowLegacy || cfg.Schema != LegacySchema) {
		return fmt.Errorf("config schema must be %q, got %q", Schema, cfg.Schema)
	}
	if cfg.Architectures == nil {
		cfg.Architectures = append([]string(nil), defaultArchitectures...)
	} else if len(cfg.Architectures) == 0 {
		return errors.New("workspace architectures must not be empty")
	}
	normalized, err := normalizeArchitectureList(cfg.Architectures, false)
	if err != nil {
		return fmt.Errorf("workspace architectures: %w", err)
	}
	cfg.Architectures = normalized
	allowed := make(map[string]struct{}, len(normalized))
	for _, arch := range normalized {
		allowed[arch] = struct{}{}
	}
	if cfg.Repositories == nil {
		cfg.Repositories = make(map[string]RepositoryConfig)
	}
	if cfg.Targets == nil {
		cfg.Targets = make(map[string]TargetConfig)
	}

	repositoryNames := sortedRepositoryNames(cfg.Repositories)
	for _, repoName := range repositoryNames {
		if err := ValidateName(repoName); err != nil {
			return fmt.Errorf("repository name %q: %w", repoName, err)
		}
	}
	if err := validateRepositoryOwnedNames(repositoryNames); err != nil {
		return err
	}

	for _, repoName := range repositoryNames {
		repo := cfg.Repositories[repoName]
		if err := normalizeAndValidateSigning(&repo.Signing); err != nil {
			return fmt.Errorf("repository %q signing: %w", repoName, err)
		}
		if repo.Dists == nil {
			repo.Dists = make(map[string]DistConfig)
		}
		for _, distName := range sortedDistNames(repo.Dists) {
			if err := ValidateName(distName); err != nil {
				return fmt.Errorf("repository %q dist name %q: %w", repoName, distName, err)
			}
			dist := repo.Dists[distName]
			if dist.Format != "rpm" && dist.Format != "deb" {
				return fmt.Errorf("repository %q dist %q format must be rpm or deb, got %q", repoName, distName, dist.Format)
			}
			if dist.Architectures != nil {
				if len(dist.Architectures) == 0 {
					return fmt.Errorf("repository %q dist %q architectures must not be empty", repoName, distName)
				}
				dist.Architectures, err = normalizeArchitectureList(dist.Architectures, false)
				if err != nil {
					return fmt.Errorf("repository %q dist %q architectures: %w", repoName, distName, err)
				}
				for _, arch := range dist.Architectures {
					if _, ok := allowed[arch]; !ok {
						return fmt.Errorf("repository %q dist %q architecture %q is not allowed by workspace", repoName, distName, arch)
					}
				}
			}
			if err := validatePolicy(dist); err != nil {
				return fmt.Errorf("repository %q dist %q policy: %w", repoName, distName, err)
			}
			repo.Dists[distName] = dist
		}
		cfg.Repositories[repoName] = repo
	}
	if err := normalizeAndValidateTargets(cfg); err != nil {
		return err
	}
	return nil
}

func normalizeAndValidateSigning(signing *SigningConfig) error {
	packages := &signing.RPM.Packages
	if packages.Mode == "" {
		if packages.Key == "" {
			packages.Mode = "never"
		} else {
			packages.Mode = "fill"
		}
	}
	switch packages.Mode {
	case "never", "fill", "always":
	default:
		return fmt.Errorf("rpm packages mode must be never, fill, or always, got %q", packages.Mode)
	}
	if packages.Mode != "never" && packages.Key == "" {
		return fmt.Errorf("rpm packages mode %q requires key", packages.Mode)
	}
	for label, reference := range map[string]string{
		"rpm packages key": packages.Key,
		"rpm metadata key": signing.RPM.Metadata.Key,
		"deb metadata key": signing.DEB.Metadata.Key,
	} {
		if reference != "" {
			if err := validateKeyReference(reference); err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
		}
	}
	for label, metadata := range map[string]MetadataSigningConfig{
		"rpm metadata": signing.RPM.Metadata,
		"deb metadata": signing.DEB.Metadata,
	} {
		if metadata.Passphrase == "" {
			continue
		}
		if metadata.Key == "" {
			return fmt.Errorf("%s passphrase requires key", label)
		}
		if strings.HasPrefix(metadata.Key, "agent://") {
			return fmt.Errorf("%s agent key uses its ambient gpg-agent and cannot accept a passphrase reference", label)
		}
		if err := validatePassphraseReference(metadata.Passphrase); err != nil {
			return fmt.Errorf("%s passphrase: %w", label, err)
		}
	}
	seen := make(map[string]struct{}, len(packages.TrustedKeys))
	for _, reference := range packages.TrustedKeys {
		if err := validateKeyReference(reference); err != nil {
			return fmt.Errorf("rpm trusted key: %w", err)
		}
		if _, exists := seen[reference]; exists {
			return fmt.Errorf("duplicate rpm trusted key reference %q", reference)
		}
		seen[reference] = struct{}{}
	}
	return nil
}

func validateKeyReference(reference string) error {
	if reference == "" || strings.TrimSpace(reference) != reference || strings.IndexFunc(reference, func(r rune) bool { return r == 0 || r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("key reference must be non-empty, trimmed, and contain no control bytes")
	}
	switch {
	case strings.HasPrefix(reference, "env://"):
		name := strings.TrimPrefix(reference, "env://")
		if !environmentName.MatchString(name) {
			return fmt.Errorf("invalid env key reference %q", reference)
		}
	case strings.HasPrefix(reference, "agent://"):
		fingerprint := strings.TrimPrefix(reference, "agent://")
		if !gpgFingerprint.MatchString(fingerprint) {
			return fmt.Errorf("invalid agent key fingerprint %q", fingerprint)
		}
	case strings.HasPrefix(reference, "file://"):
		if strings.TrimPrefix(reference, "file://") == "" {
			return errors.New("file key reference has an empty path")
		}
	case strings.Contains(reference, "://"):
		return fmt.Errorf("unsupported key reference scheme in %q", reference)
	}
	return nil
}

func validatePassphraseReference(reference string) error {
	if reference == "" || strings.TrimSpace(reference) != reference || strings.IndexFunc(reference, func(r rune) bool { return r == 0 || r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("passphrase reference must be non-empty, trimmed, and contain no control bytes")
	}
	switch {
	case strings.HasPrefix(reference, "env://"):
		if name := strings.TrimPrefix(reference, "env://"); !environmentName.MatchString(name) {
			return fmt.Errorf("invalid env passphrase reference %q", reference)
		}
	case strings.HasPrefix(reference, "file://"):
		if strings.TrimPrefix(reference, "file://") == "" {
			return errors.New("file passphrase reference has an empty path")
		}
	case strings.Contains(reference, "://"):
		return fmt.Errorf("unsupported passphrase reference scheme in %q", reference)
	}
	return nil
}

func validatePolicy(dist DistConfig) error {
	if dist.Limit < 0 {
		return fmt.Errorf("limit must be zero or positive, got %d", dist.Limit)
	}
	for index, rule := range dist.Exclude {
		fields := map[string][]string{
			"name": rule.Name, "source": rule.Source, "arch": rule.Arch,
			"kind": rule.Kind, "format": rule.Format,
		}
		nonempty := false
		for field, patterns := range fields {
			if len(patterns) == 0 {
				continue
			}
			nonempty = true
			seen := make(map[string]struct{}, len(patterns))
			for _, pattern := range patterns {
				if pattern == "" || strings.TrimSpace(pattern) != pattern || strings.ContainsRune(pattern, 0) {
					return fmt.Errorf("exclude rule %d field %s has an empty or untrimmed pattern", index, field)
				}
				if _, err := path.Match(pattern, "candidate"); err != nil {
					return fmt.Errorf("exclude rule %d field %s has invalid glob %q: %w", index, field, pattern, err)
				}
				if _, duplicate := seen[pattern]; duplicate {
					return fmt.Errorf("exclude rule %d field %s repeats pattern %q", index, field, pattern)
				}
				seen[pattern] = struct{}{}
			}
		}
		if !nonempty {
			return fmt.Errorf("exclude rule %d is empty", index)
		}
	}
	return nil
}

func validateRepositoryOwnedNames(names []string) error {
	owners := make(map[string]string, len(names)*5)
	for _, name := range names {
		for _, entry := range []string{name, name + ".db", name + ".db-wal", name + ".db-shm", name + ".db-journal"} {
			if previous, exists := owners[entry]; exists && previous != name {
				return fmt.Errorf("repository names %q and %q collide at reserved state path %q", previous, name, entry)
			}
			owners[entry] = name
		}
	}
	return nil
}

// CanonicalArchitecture normalizes supported ecosystem aliases. Neutral
// package architectures are intentionally not valid CPU families here.
func CanonicalArchitecture(input string) (string, error) {
	switch input {
	case "x86_64", "amd64":
		return "x86_64", nil
	case "aarch64", "arm64":
		return "aarch64", nil
	case "neutral", "noarch", "all":
		return "", fmt.Errorf("%q is a neutral package architecture, not a canonical CPU family", input)
	default:
		return "", fmt.Errorf("unsupported architecture %q; supported canonical families are x86_64 and aarch64", input)
	}
}

func normalizeArchitectureList(input []string, allowNeutral bool) ([]string, error) {
	result := make([]string, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, raw := range input {
		if allowNeutral && (raw == "neutral" || raw == "noarch" || raw == "all") {
			raw = "neutral"
		} else {
			var err error
			raw, err = CanonicalArchitecture(raw)
			if err != nil {
				return nil, err
			}
		}
		if _, ok := seen[raw]; ok {
			return nil, fmt.Errorf("duplicate architecture %q after normalization", raw)
		}
		seen[raw] = struct{}{}
		result = append(result, raw)
	}
	return result, nil
}

// ValidateName enforces the closed Repository/Dist name grammar and reserved
// workspace names.
func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("name %q must match [a-z0-9][a-z0-9._-]*", name)
	}
	if _, reserved := reservedNames[name]; reserved {
		return fmt.Errorf("name %q is reserved", name)
	}
	return nil
}

func sortedRepositoryNames(repos map[string]RepositoryConfig) []string {
	names := make([]string, 0, len(repos))
	for name := range repos {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedDistNames(dists map[string]DistConfig) []string {
	names := make([]string, 0, len(dists))
	for name := range dists {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func cloneConfig(input Config) Config {
	output := Config{
		Schema:        input.Schema,
		Architectures: append([]string(nil), input.Architectures...),
		Repositories:  make(map[string]RepositoryConfig, len(input.Repositories)),
		Targets:       make(map[string]TargetConfig, len(input.Targets)),
	}
	if input.Architectures == nil {
		output.Architectures = nil
	}
	for repoName, repo := range input.Repositories {
		copyRepo := repo
		copyRepo.Signing.RPM.Packages.TrustedKeys = append([]string(nil), repo.Signing.RPM.Packages.TrustedKeys...)
		copyRepo.Dists = make(map[string]DistConfig, len(repo.Dists))
		for distName, dist := range repo.Dists {
			copyDist := dist
			copyDist.Architectures = append([]string(nil), dist.Architectures...)
			copyDist.Exclude = cloneExcludeRules(dist.Exclude)
			if dist.Architectures == nil {
				copyDist.Architectures = nil
			}
			copyRepo.Dists[distName] = copyDist
		}
		output.Repositories[repoName] = copyRepo
	}
	for targetName, target := range input.Targets {
		output.Targets[targetName] = target
	}
	return output
}

func cloneExcludeRules(input []ExcludeRule) []ExcludeRule {
	if input == nil {
		return nil
	}
	output := make([]ExcludeRule, len(input))
	for index, rule := range input {
		output[index] = ExcludeRule{
			Name: append([]string(nil), rule.Name...), Source: append([]string(nil), rule.Source...),
			Arch: append([]string(nil), rule.Arch...), Kind: append([]string(nil), rule.Kind...),
			Format: append([]string(nil), rule.Format...),
		}
	}
	return output
}

// ViewOptions scopes a fully effective P1 config view.
type ViewOptions struct {
	Repository string
	Dist       string
}

type EffectiveConfig struct {
	Schema        string                         `yaml:"schema" json:"schema"`
	Architectures []string                       `yaml:"architectures" json:"architectures"`
	Repositories  map[string]EffectiveRepository `yaml:"repos" json:"repos"`
	Targets       map[string]TargetConfig        `yaml:"targets,omitempty" json:"targets,omitempty"`
}

type EffectiveRepository struct {
	Protected bool                     `yaml:"protected" json:"protected"`
	Signing   EffectiveSigningConfig   `yaml:"signing" json:"signing"`
	Dists     map[string]EffectiveDist `yaml:"dists" json:"dists"`
}

// EffectiveSigningConfig intentionally separates public references from
// their resolved public-key fingerprints. Fingerprints are filled by the
// Managed workspace layer, which has the workspace root and runtime context
// needed to resolve file://, env://, and agent:// references. Secret key
// material is never represented by these public view types.
type EffectiveSigningConfig struct {
	RPM EffectiveRPMSigningConfig  `yaml:"rpm" json:"rpm"`
	DEB *EffectiveDEBSigningConfig `yaml:"deb,omitempty" json:"deb,omitempty"`
}

type EffectiveRPMSigningConfig struct {
	Packages EffectiveRPMPackageSigningConfig `yaml:"packages" json:"packages"`
	Metadata *EffectiveMetadataSigningConfig  `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

type EffectiveDEBSigningConfig struct {
	Metadata EffectiveMetadataSigningConfig `yaml:"metadata" json:"metadata"`
}

type EffectiveRPMPackageSigningConfig struct {
	Mode                      string   `yaml:"mode" json:"mode"`
	Key                       string   `yaml:"key,omitempty" json:"key,omitempty"`
	KeyFingerprint            string   `yaml:"key_fingerprint,omitempty" json:"key_fingerprint,omitempty"`
	KeySnapshotSHA256         string   `yaml:"key_snapshot_sha256,omitempty" json:"key_snapshot_sha256,omitempty"`
	TrustedKeys               []string `yaml:"trusted_keys,omitempty" json:"trusted_keys,omitempty"`
	TrustedKeyFingerprints    []string `yaml:"trusted_key_fingerprints,omitempty" json:"trusted_key_fingerprints,omitempty"`
	TrustedKeySnapshotSHA256s []string `yaml:"trusted_key_snapshot_sha256s,omitempty" json:"trusted_key_snapshot_sha256s,omitempty"`
}

type EffectiveMetadataSigningConfig struct {
	Key            string `yaml:"key,omitempty" json:"key,omitempty"`
	Passphrase     string `yaml:"passphrase,omitempty" json:"passphrase,omitempty"`
	KeyFingerprint string `yaml:"key_fingerprint,omitempty" json:"key_fingerprint,omitempty"`
}

type EffectiveDist struct {
	Format        string        `yaml:"format" json:"format"`
	Architectures []string      `yaml:"architectures" json:"architectures"`
	Limit         int           `yaml:"limit" json:"limit"`
	Exclude       []ExcludeRule `yaml:"exclude" json:"exclude"`
}

// EffectiveView expands P1 defaults and inherited architecture lists.
func EffectiveView(input Config, opts ViewOptions) (EffectiveConfig, error) {
	cfg := cloneConfig(input)
	if err := normalizeAndValidate(&cfg); err != nil {
		return EffectiveConfig{}, err
	}
	if opts.Dist != "" && opts.Repository == "" {
		return EffectiveConfig{}, errors.New("effective dist view requires repository")
	}
	if opts.Repository != "" {
		if err := ValidateName(opts.Repository); err != nil {
			return EffectiveConfig{}, fmt.Errorf("effective repository: %w", err)
		}
		if _, ok := cfg.Repositories[opts.Repository]; !ok {
			return EffectiveConfig{}, fmt.Errorf("repository %q is not configured", opts.Repository)
		}
	}
	if opts.Dist != "" {
		if err := ValidateName(opts.Dist); err != nil {
			return EffectiveConfig{}, fmt.Errorf("effective dist: %w", err)
		}
		if _, ok := cfg.Repositories[opts.Repository].Dists[opts.Dist]; !ok {
			return EffectiveConfig{}, fmt.Errorf("dist %q is not configured in repository %q", opts.Dist, opts.Repository)
		}
	}
	view := EffectiveConfig{
		Schema:        Schema,
		Architectures: append([]string(nil), cfg.Architectures...),
		Repositories:  make(map[string]EffectiveRepository),
		Targets:       make(map[string]TargetConfig),
	}
	for _, repoName := range sortedRepositoryNames(cfg.Repositories) {
		if opts.Repository != "" && repoName != opts.Repository {
			continue
		}
		repo := cfg.Repositories[repoName]
		effectiveRepo := EffectiveRepository{
			Protected: repo.Protected,
			Signing: EffectiveSigningConfig{
				RPM: EffectiveRPMSigningConfig{
					Packages: EffectiveRPMPackageSigningConfig{
						Mode:        repo.Signing.RPM.Packages.Mode,
						Key:         repo.Signing.RPM.Packages.Key,
						TrustedKeys: append([]string(nil), repo.Signing.RPM.Packages.TrustedKeys...),
					},
				},
			},
			Dists: make(map[string]EffectiveDist),
		}
		if repo.Signing.RPM.Metadata.Key != "" {
			effectiveRepo.Signing.RPM.Metadata = &EffectiveMetadataSigningConfig{Key: repo.Signing.RPM.Metadata.Key, Passphrase: repo.Signing.RPM.Metadata.Passphrase}
		}
		if repo.Signing.DEB.Metadata.Key != "" {
			effectiveRepo.Signing.DEB = &EffectiveDEBSigningConfig{Metadata: EffectiveMetadataSigningConfig{Key: repo.Signing.DEB.Metadata.Key, Passphrase: repo.Signing.DEB.Metadata.Passphrase}}
		}
		for _, distName := range sortedDistNames(repo.Dists) {
			if opts.Dist != "" && distName != opts.Dist {
				continue
			}
			dist := repo.Dists[distName]
			architectures := dist.Architectures
			if architectures == nil {
				architectures = cfg.Architectures
			}
			effectiveRepo.Dists[distName] = EffectiveDist{
				Format: dist.Format, Architectures: append([]string(nil), architectures...),
				Limit: dist.Limit, Exclude: cloneExcludeRules(dist.Exclude),
			}
		}
		view.Repositories[repoName] = effectiveRepo
	}
	for targetName, target := range cfg.Targets {
		if opts.Repository == "" || target.Repository == opts.Repository {
			view.Targets[targetName] = target
		}
	}
	return view, nil
}

// MarshalEffective emits the stable P1 representation used by config show
// --all and structured output adapters.
func MarshalEffective(view EffectiveConfig) ([]byte, error) {
	data, err := marshalYAML(view)
	if err != nil {
		return nil, fmt.Errorf("marshal effective config: %w", err)
	}
	return data, nil
}

func marshalYAML(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// EffectiveArchitectures returns the canonical architecture families for a
// configured Dist, expanding inheritance from the Workspace.
func EffectiveArchitectures(cfg Config, repository, dist string) ([]string, error) {
	view, err := EffectiveView(cfg, ViewOptions{Repository: repository, Dist: dist})
	if err != nil {
		return nil, err
	}
	return append([]string(nil), view.Repositories[repository].Dists[dist].Architectures...), nil
}

// StateArchitectureReference is the narrow read-only projection config check
// needs from Repository state. Source is diagnostic context such as
// "membership" or "built generation"; it never affects validation.
type StateArchitectureReference struct {
	Repository   string
	Dist         string
	Architecture string
	Source       string
}

// ValidateStateArchitectureReferences rejects a candidate config that removed
// a Repository, Dist, or canonical family still referenced by durable state.
// Callers obtain the references from SQLite without allowing config to import
// or depend on the state package.
func ValidateStateArchitectureReferences(cfg Config, refs []StateArchitectureReference) error {
	copyCfg := cloneConfig(cfg)
	if err := normalizeAndValidate(&copyCfg); err != nil {
		return err
	}
	ordered := append([]StateArchitectureReference(nil), refs...)
	sort.Slice(ordered, func(i, j int) bool {
		left, right := ordered[i], ordered[j]
		if left.Repository != right.Repository {
			return left.Repository < right.Repository
		}
		if left.Dist != right.Dist {
			return left.Dist < right.Dist
		}
		if left.Architecture != right.Architecture {
			return left.Architecture < right.Architecture
		}
		return left.Source < right.Source
	})
	for _, ref := range ordered {
		repo, ok := copyCfg.Repositories[ref.Repository]
		if !ok {
			return fmt.Errorf("state %s references removed repository %q", referenceSource(ref.Source), ref.Repository)
		}
		dist, ok := repo.Dists[ref.Dist]
		if !ok {
			return fmt.Errorf("state %s references removed dist %q in repository %q", referenceSource(ref.Source), ref.Dist, ref.Repository)
		}
		architecture, err := CanonicalArchitecture(ref.Architecture)
		if err != nil {
			return fmt.Errorf("state %s has invalid architecture %q for repository %q dist %q: %w", referenceSource(ref.Source), ref.Architecture, ref.Repository, ref.Dist, err)
		}
		allowed := dist.Architectures
		if allowed == nil {
			allowed = copyCfg.Architectures
		}
		if !containsString(allowed, architecture) {
			return fmt.Errorf("state %s references architecture %q removed from repository %q dist %q", referenceSource(ref.Source), architecture, ref.Repository, ref.Dist)
		}
	}
	return nil
}

func referenceSource(source string) string {
	if strings.TrimSpace(source) == "" {
		return "entry"
	}
	return source
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
