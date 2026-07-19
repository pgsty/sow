package config

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// YUMCompatibility*TrustRoute are immutable public trust coordinates for a
// frozen projection. They are exact object keys, never prefixes: edge and
// Nginx policy can expose the two required trust anchors without widening the
// reserved _sow namespace or following a mutable owner keyring path.
func YUMCompatibilityRepositoryTrustRoute(id string) string {
	return path.Join("_sow/v1/trust/yum-compat", id, "repository.pgp")
}

func YUMCompatibilityPackageTrustRoute(id string) string {
	return path.Join("_sow/v1/trust/yum-compat", id, "packages.pgp")
}

const (
	YUMCompatibilityModeFrozenCrossEL = "frozen-cross-el"
	// YUMCompatibilityPinAtFirstFreeze is the only non-commit value accepted
	// by schema v1. It is resolved exactly once from the explicit immutable
	// cross-EL adoption ref, then the witness/ref become authoritative.
	YUMCompatibilityPinAtFirstFreeze = "pin-at-first-freeze"
)

var yumCompatibilityCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func validateYUMCompatibilityProjectionNode(document *yaml.Node) error {
	if document == nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	root := document.Content[0]
	for index := 0; index+1 < len(root.Content); index += 2 {
		if root.Content[index].Value != "compatibility_projections" {
			continue
		}
		value := root.Content[index+1]
		if value.Kind != yaml.SequenceNode || len(value.Content) == 0 {
			return errors.New("compatibility_projections must be a non-empty sequence when declared")
		}
		return nil
	}
	return nil
}

// YUMCompatibilityProjection owns one exact legacy YUM leaf. The projection
// is deliberately not a repository. Source.Repo is only the active owner from
// which target affinity and publication policy are inherited; package bytes
// come from a dedicated immutable cross-EL adoption ref. Ordinary add/rm/sync
// therefore cannot relabel a mixed-EL byte set as that owner's per-EL leaf.
//
// One record per architecture avoids an implicit cartesian product and makes
// the legacy physical owner, source ref and recovery identity reviewable in
// canonical configuration.
type YUMCompatibilityProjection struct {
	ID      string                 `yaml:"id"`
	Root    string                 `yaml:"root"`
	Mode    string                 `yaml:"mode"`
	Carrier string                 `yaml:"carrier"`
	Source  YUMCompatibilitySource `yaml:"source"`
}

type YUMCompatibilitySource struct {
	Repo   string `yaml:"repo"`
	View   string `yaml:"view"`
	OS     string `yaml:"os"`
	Arch   string `yaml:"arch"`
	Commit string `yaml:"commit"`
}

// ValidateYUMCompatibilityProjections validates and normalizes the schema-v1
// compatibility contract without observing Git. Runtime admission separately
// proves that Source.Commit is the exact immutable adoption ref, is reachable
// from canonical HEAD, and contains a valid Packages manifest before any
// witness or serving bytes can be written.
func ValidateYUMCompatibilityProjections(projections []YUMCompatibilityProjection, repos []Repo, groups map[string][]string, views map[string]View) error {
	repoByID := make(map[string]Repo, len(repos))
	paths := make([]string, 0, len(repos)+len(projections))
	for _, repo := range repos {
		repoByID[repo.ID] = repo
		expanded, err := repo.ExpandedPaths()
		if err != nil {
			return fmt.Errorf("expand repo %s while validating compatibility projections: %w", repo.ID, err)
		}
		paths = append(paths, expanded...)
	}
	seenIDs := make(map[string]struct{}, len(projections))
	seenSources := make(map[string]string, len(projections))
	for index := range projections {
		projection := &projections[index]
		if err := validateName("compatibility projection", projection.ID); err != nil {
			return fmt.Errorf("compatibility_projections[%d]: %w", index, err)
		}
		if _, collision := repoByID[projection.ID]; collision {
			return fmt.Errorf("compatibility projection %q collides with a physical repo ID", projection.ID)
		}
		if _, collision := groups[projection.ID]; collision {
			return fmt.Errorf("compatibility projection %q collides with a repo group", projection.ID)
		}
		if _, duplicate := seenIDs[projection.ID]; duplicate {
			return fmt.Errorf("duplicate compatibility projection %q", projection.ID)
		}
		seenIDs[projection.ID] = struct{}{}
		if err := validateRelativePath(projection.Root); err != nil {
			return fmt.Errorf("compatibility_projections[%d].root: %w", index, err)
		}
		projection.Root = filepath.ToSlash(filepath.Clean(projection.Root))
		if strings.ContainsAny(projection.Root, "{}") {
			return fmt.Errorf("compatibility_projections[%d].root must be one exact architecture leaf", index)
		}
		if containsReservedComponent(projection.Root) {
			return fmt.Errorf("compatibility_projections[%d].root uses a reserved .sow/.pool/.git/_sow component", index)
		}
		if err := validateRoutePath(projection.Root); err != nil {
			return fmt.Errorf("compatibility_projections[%d].root is not edge-routable: %w", index, err)
		}
		if !hasPathNamespace(projection.Root, "yum") {
			return fmt.Errorf("compatibility_projections[%d].root must use the yum/ namespace", index)
		}
		if projection.Mode != YUMCompatibilityModeFrozenCrossEL {
			return fmt.Errorf("compatibility_projections[%d].mode must be %s", index, YUMCompatibilityModeFrozenCrossEL)
		}
		if err := validateYUMCompatibilitySource(index, projection.Source, repoByID, views); err != nil {
			return err
		}
		carrier, carrierExists := repoByID[projection.Carrier]
		if !carrierExists || carrier.Type != "yum" || carrier.YUM == nil || !carrier.YUM.CompatibilityCarrier || carrier.IsActive() {
			return fmt.Errorf("compatibility_projections[%d].carrier must reference an explicit inactive YUM compatibility carrier", index)
		}
		// The raw Nginx/edge route owns the complete carrier leaf. A filtered
		// baseline would prove only a subset while the prefix route exposed the
		// excluded remainder, and a gated pool would violate the public-only
		// confidentiality closure.
		if carrier.DefaultPool != "public" {
			return fmt.Errorf("compatibility_projections[%d].carrier must use default_pool public", index)
		}
		if len(carrier.Include) != 0 || len(carrier.Exclude) != 0 {
			return fmt.Errorf("compatibility_projections[%d].carrier must scan the complete raw tree without include/exclude filters", index)
		}
		if projection.Carrier == projection.Source.Repo {
			return fmt.Errorf("compatibility_projections[%d].carrier and active policy owner must be distinct", index)
		}
		if filepath.Base(projection.Root) != projection.Source.Arch {
			return fmt.Errorf("compatibility_projections[%d].root architecture leaf %q must equal source.arch %q", index, filepath.Base(projection.Root), projection.Source.Arch)
		}
		carrierRoot, err := carrier.PathForArch(projection.Source.Arch)
		if err != nil || carrierRoot != projection.Root {
			return fmt.Errorf("compatibility_projections[%d].root must exactly equal carrier leaf %q", index, carrierRoot)
		}
		sourceKey := strings.Join([]string{projection.Carrier, projection.Source.View, projection.Source.Arch}, "\x00")
		if owner, duplicate := seenSources[sourceKey]; duplicate {
			return fmt.Errorf("compatibility projections %s and %s claim the same pinned source leaf", owner, projection.ID)
		}
		seenSources[sourceKey] = projection.ID
		// The inactive carrier is the physical owner of this exact root. The
		// projection deliberately overlaps that one leaf and no other: validateRepos
		// has already proved the carrier does not overlap any sibling repository.
	}
	if err := validateNonOverlapping(paths); err != nil {
		return fmt.Errorf("compatibility projection ownership: %w", err)
	}
	// Compatibility leaves are a set. Canonical order prevents YAML list order
	// from changing config SHA or recovery identities for an equivalent frozen
	// contract.
	sort.Slice(projections, func(i, j int) bool { return projections[i].ID < projections[j].ID })
	return nil
}

func validateYUMCompatibilitySource(index int, source YUMCompatibilitySource, repos map[string]Repo, views map[string]View) error {
	field := fmt.Sprintf("compatibility_projections[%d].source", index)
	repo, exists := repos[source.Repo]
	if !exists {
		return fmt.Errorf("%s.repo references unknown repo %q", field, source.Repo)
	}
	if repo.Type != "yum" || repo.YUM == nil || repo.YUM.CompatibilityCarrier || !repo.IsActive() {
		return fmt.Errorf("%s.repo must reference an active non-carrier YUM policy owner", field)
	}
	// Once S1 has pinned the cross-EL bytes, the owner supplies only policy and
	// target affinity.  An explicit EOL transition from active to frozen must
	// not invalidate that history; the physical repo itself remains selected
	// (active != false), public, and constrained to the EL9/10 zstd contract.
	if repo.OS.Family != "el" || (repo.OS.Major != 9 && repo.OS.Major != 10) ||
		(repo.OS.Lifecycle != "active" && repo.OS.Lifecycle != "frozen") || repo.YUM.Compression != "zstd" {
		return fmt.Errorf("%s.repo must reference an enabled EL9/10 zstd policy owner with active or frozen lifecycle", field)
	}
	if repo.DefaultPool != "public" {
		return fmt.Errorf("%s.repo must use default_pool public", field)
	}
	if source.View != "latest" {
		return fmt.Errorf("%s.view must be latest in schema v1", field)
	}
	view, exists := views[source.View]
	if !exists || view.Access != "public" {
		return fmt.Errorf("%s.view must reference the configured public latest view", field)
	}
	if len(view.Repos) != 0 && !containsString(view.Repos, source.Repo) {
		return fmt.Errorf("%s.repo must be included by the configured public latest view", field)
	}
	if source.OS != "cross-el" {
		return fmt.Errorf("%s.os must be cross-el; compatibility bytes are not an EL9/10 source leaf", field)
	}
	if source.Arch == "noarch" || !containsString(repo.Arches, source.Arch) {
		return fmt.Errorf("%s.arch must be one configured non-noarch source architecture", field)
	}
	if source.Commit != YUMCompatibilityPinAtFirstFreeze &&
		(!yumCompatibilityCommitPattern.MatchString(source.Commit) || source.Commit == strings.Repeat("0", 40)) {
		return fmt.Errorf("%s.commit must be %q or a non-zero lowercase 40-hex Git commit", field, YUMCompatibilityPinAtFirstFreeze)
	}
	return nil
}

// SortedYUMCompatibilityProjections returns a detached deterministic copy for
// planning, recovery and canonical witness generation.
func SortedYUMCompatibilityProjections(projections []YUMCompatibilityProjection) []YUMCompatibilityProjection {
	result := append([]YUMCompatibilityProjection(nil), projections...)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

// YUMCompatibilityProjectionForSource returns the unique projection owned by
// an exact repo/view/arch selection. osName is the selected ordinary owner
// leaf and is intentionally not compared with Source.OS, which is frozen to
// cross-el: ownership must not relabel mixed-release compatibility bytes.
func YUMCompatibilityProjectionForSource(projections []YUMCompatibilityProjection, repo, view, osName, arch string) (YUMCompatibilityProjection, bool, error) {
	_ = osName
	var result YUMCompatibilityProjection
	found := false
	for _, projection := range projections {
		source := projection.Source
		if source.Repo != repo || source.View != view || source.Arch != arch {
			continue
		}
		if found {
			return YUMCompatibilityProjection{}, false, errors.New("multiple YUM compatibility projections match one source leaf")
		}
		result, found = projection, true
	}
	return result, found, nil
}

// YUMCompatibilityProjectionByID resolves the independent compatibility
// channel identity without making it a repository selector. Runtime channel
// ownership, audit and recovery all use this exact lookup and fail closed on
// duplicate IDs even if an unvalidated Config was assembled by a test/tool.
func YUMCompatibilityProjectionByID(projections []YUMCompatibilityProjection, id string) (YUMCompatibilityProjection, bool, error) {
	var result YUMCompatibilityProjection
	found := false
	for _, projection := range projections {
		if projection.ID != id {
			continue
		}
		if found {
			return YUMCompatibilityProjection{}, false, fmt.Errorf("duplicate YUM compatibility projection ID %q", id)
		}
		result, found = projection, true
	}
	return result, found, nil
}
