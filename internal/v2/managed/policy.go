package managed

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

type PolicyResult struct {
	Kept     []state.PackageObject `json:"kept"`
	Excluded []state.PackageObject `json:"excluded"`
	Limited  []state.PackageObject `json:"limited"`
}

func ClassifyPackageKind(format, name string) string {
	switch format {
	case "rpm":
		for _, candidate := range []struct{ suffix, kind string }{
			{"-debugsource", "debugsource"}, {"-debuginfo", "debuginfo"}, {"-llvmjit", "llvmjit"},
		} {
			if strings.HasSuffix(name, candidate.suffix) {
				return candidate.kind
			}
		}
	case "deb":
		for _, candidate := range []struct{ suffix, kind string }{{"-dbgsym", "dbgsym"}, {"-dbg", "dbg"}} {
			if strings.HasSuffix(name, candidate.suffix) {
				return candidate.kind
			}
		}
	}
	return "main"
}

// ApplyPolicy evaluates exclude before Limit over a complete candidate set.
// The result is stable regardless of input order.
func ApplyPolicy(packages []state.PackageObject, dist config.EffectiveDist) (PolicyResult, error) {
	allowedArch := make(map[string]struct{}, len(dist.Architectures))
	for _, architecture := range dist.Architectures {
		allowedArch[architecture] = struct{}{}
	}
	unique := make(map[string]state.PackageObject, len(packages))
	for _, object := range packages {
		if object.Format != dist.Format {
			continue
		}
		if object.CanonicalArch != "neutral" {
			if _, ok := allowedArch[object.CanonicalArch]; !ok {
				continue
			}
		}
		if previous, duplicate := unique[object.SHA256]; duplicate {
			if !samePolicyObject(previous, object) {
				return PolicyResult{}, fmt.Errorf("managed: sha256 %s has conflicting policy facts", object.SHA256)
			}
			continue
		}
		object.Kind = ClassifyPackageKind(object.Format, object.Name)
		unique[object.SHA256] = object
	}
	ordered := make([]state.PackageObject, 0, len(unique))
	for _, object := range unique {
		ordered = append(ordered, object)
	}
	sortPolicyObjects(ordered)

	result := PolicyResult{}
	eligible := make([]state.PackageObject, 0, len(ordered))
	for _, object := range ordered {
		matched, err := excludedByPolicy(object, dist.Exclude)
		if err != nil {
			return PolicyResult{}, err
		}
		if matched {
			result.Excluded = append(result.Excluded, object)
			continue
		}
		eligible = append(eligible, object)
	}
	if dist.Limit == 0 {
		result.Kept = eligible
		return result, nil
	}

	groups := make(map[string][]state.PackageObject)
	groupNames := []string{}
	for _, object := range eligible {
		key := object.Name + "\x00" + object.CanonicalArch
		if _, exists := groups[key]; !exists {
			groupNames = append(groupNames, key)
		}
		groups[key] = append(groups[key], object)
	}
	sort.Strings(groupNames)
	for _, key := range groupNames {
		group := groups[key]
		for _, object := range group {
			if _, err := comparePolicyVersion(object, object); err != nil {
				return PolicyResult{}, err
			}
		}
		sort.SliceStable(group, func(i, j int) bool {
			comparison, _ := comparePolicyVersion(group[i], group[j])
			if comparison != 0 {
				return comparison > 0
			}
			return group[i].SHA256 < group[j].SHA256
		})
		cut := dist.Limit
		if cut > len(group) {
			cut = len(group)
		}
		result.Kept = append(result.Kept, group[:cut]...)
		result.Limited = append(result.Limited, group[cut:]...)
	}
	sortPolicyObjects(result.Kept)
	sortPolicyObjects(result.Limited)
	return result, nil
}

func excludedByPolicy(object state.PackageObject, rules []config.ExcludeRule) (bool, error) {
	values := map[string]string{
		"name": object.Name, "source": object.Source, "arch": object.CanonicalArch,
		"kind": object.Kind, "format": object.Format,
	}
	for index, rule := range rules {
		fields := map[string][]string{
			"name": rule.Name, "source": rule.Source, "arch": rule.Arch,
			"kind": rule.Kind, "format": rule.Format,
		}
		ruleMatches := true
		for field, patterns := range fields {
			if len(patterns) == 0 {
				continue
			}
			fieldMatches := false
			for _, pattern := range patterns {
				matched, err := path.Match(pattern, values[field])
				if err != nil {
					return false, fmt.Errorf("managed: exclude rule %d field %s pattern %q: %w", index, field, pattern, err)
				}
				fieldMatches = fieldMatches || matched
			}
			if !fieldMatches {
				ruleMatches = false
				break
			}
		}
		if ruleMatches {
			return true, nil
		}
	}
	return false, nil
}

func comparePolicyVersion(left, right state.PackageObject) (int, error) {
	if left.Format != right.Format {
		return strings.Compare(left.Format, right.Format), nil
	}
	switch left.Format {
	case "rpm":
		leftEpoch, err := strconv.ParseInt(left.Epoch, 10, 64)
		if err != nil || leftEpoch < 0 {
			return 0, fmt.Errorf("managed: invalid RPM epoch %q for %s", left.Epoch, left.Coordinate)
		}
		rightEpoch, err := strconv.ParseInt(right.Epoch, 10, 64)
		if err != nil || rightEpoch < 0 {
			return 0, fmt.Errorf("managed: invalid RPM epoch %q for %s", right.Epoch, right.Coordinate)
		}
		return yumrepo.CompareEVR(leftEpoch, left.Version, left.Release, rightEpoch, right.Version, right.Release), nil
	case "deb":
		return aptrepo.CompareVersions(left.Version, right.Version)
	default:
		return 0, fmt.Errorf("managed: unsupported package format %q", left.Format)
	}
}

func sortPolicyObjects(objects []state.PackageObject) {
	sort.SliceStable(objects, func(i, j int) bool {
		if objects[i].Format != objects[j].Format {
			return objects[i].Format < objects[j].Format
		}
		if objects[i].Name != objects[j].Name {
			return objects[i].Name < objects[j].Name
		}
		if objects[i].CanonicalArch != objects[j].CanonicalArch {
			return objects[i].CanonicalArch < objects[j].CanonicalArch
		}
		if objects[i].Coordinate != objects[j].Coordinate {
			return objects[i].Coordinate < objects[j].Coordinate
		}
		return objects[i].SHA256 < objects[j].SHA256
	})
}

func samePolicyObject(left, right state.PackageObject) bool {
	return left.Format == right.Format && left.Name == right.Name && left.Source == right.Source &&
		left.Version == right.Version && left.Epoch == right.Epoch && left.Release == right.Release &&
		left.Architecture == right.Architecture && left.CanonicalArch == right.CanonicalArch &&
		left.Coordinate == right.Coordinate
}
