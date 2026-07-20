package config

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

const (
	// MaxConfigTopologyUnits bounds decoded collection members, sequence
	// defaults, and logical selector/metadata leaves before validation expands
	// any of them. Package inventory rows are intentionally outside this
	// configuration-only budget.
	MaxConfigTopologyUnits = 1 << 16

	// MaxConfigDerivedStringBytes independently bounds string bytes that
	// validation/defaulting would materialize or repeat. The input-size limit
	// alone cannot protect a short configuration from repeatedly embedding one
	// very long path, architecture, suite, or component in derived values.
	MaxConfigDerivedStringBytes = 64 << 20
)

type configComplexityUsage struct {
	StructuralUnits    uint64
	DerivedStringBytes uint64
}

type configComplexityBudget struct {
	used  uint64
	limit uint64
	kind  string
	unit  string
}

func newConfigStructuralBudget() configComplexityBudget {
	return configComplexityBudget{limit: MaxConfigTopologyUnits, kind: "configuration topology", unit: "work-unit"}
}

func newConfigDerivedStringBudget() configComplexityBudget {
	return configComplexityBudget{limit: MaxConfigDerivedStringBytes, kind: "configuration derived strings", unit: "byte"}
}

func (b *configComplexityBudget) add(value uint64, field string) error {
	if b.used > b.limit || value > b.limit-b.used {
		return fmt.Errorf("%s exceeds %d-%s safety limit while accounting for %s", b.kind, b.limit, b.unit, field)
	}
	b.used += value
	return nil
}

func (b *configComplexityBudget) addProduct(field string, factors ...uint64) error {
	for _, factor := range factors {
		if factor == 0 {
			return nil
		}
	}
	product := uint64(1)
	for _, factor := range factors {
		if factor > math.MaxUint64/product {
			return fmt.Errorf("%s exceeds %d-%s safety limit while accounting for %s", b.kind, b.limit, b.unit, field)
		}
		product *= factor
	}
	return b.add(product, field)
}

func configComplexityUsageFor(cfg *Config) (configComplexityUsage, error) {
	if cfg == nil {
		return configComplexityUsage{}, nil
	}
	structural := newConfigStructuralBudget()
	if err := accountConfigStructuralUnits(cfg, &structural); err != nil {
		return configComplexityUsage{}, err
	}
	derived := newConfigDerivedStringBudget()
	if err := accountConfigDerivedStringBytes(cfg, &derived); err != nil {
		return configComplexityUsage{}, err
	}
	return configComplexityUsage{StructuralUnits: structural.used, DerivedStringBytes: derived.used}, nil
}

func accountConfigStructuralUnits(cfg *Config, budget *configComplexityBudget) error {
	base := []struct {
		field string
		count int
	}{
		{field: "pools", count: len(cfg.Pools)},
		{field: "repos", count: len(cfg.Repos)},
		{field: "repo_groups", count: len(cfg.RepoGroups)},
		{field: "compatibility_projections", count: len(cfg.CompatibilityProjections)},
		{field: "upstreams", count: len(cfg.Upstreams)},
		{field: "views", count: len(cfg.Views)},
		{field: "targets", count: len(cfg.Targets)},
	}
	for _, item := range base {
		if err := budget.add(uint64(item.count), item.field); err != nil {
			return err
		}
	}

	repos := make(map[string]*Repo, len(cfg.Repos))
	for index := range cfg.Repos {
		repo := &cfg.Repos[index]
		if _, exists := repos[repo.ID]; !exists {
			repos[repo.ID] = repo
		}
		fields := []struct {
			name  string
			count int
		}{
			{name: "arches", count: len(repo.Arches)},
			{name: "include", count: len(repo.Include)},
			{name: "exclude", count: len(repo.Exclude)},
		}
		for _, field := range fields {
			if err := budget.add(uint64(field.count), fmt.Sprintf("repos[%d].%s", index, field.name)); err != nil {
				return err
			}
		}
		if err := budget.add(uint64(len(repo.PublishTargets)), fmt.Sprintf("repos[%d].publish_targets", index)); err != nil {
			return err
		}
		targetCount := len(repo.PublishTargets)
		targetField := fmt.Sprintf("repos[%d].publish target selector leaves", index)
		if targetCount == 0 {
			targetCount = len(cfg.Targets)
			targetField += " default expansion"
		}
		if err := budget.add(uint64(targetCount), targetField); err != nil {
			return err
		}

		switch {
		case repo.APT != nil:
			apt := repo.APT
			aptFields := []struct {
				name  string
				count int
			}{
				{name: "suites", count: len(apt.Suites)},
				{name: "components", count: len(apt.Components)},
				{name: "suite_components", count: len(apt.SuiteComponents)},
				{name: "suite_lifecycle", count: len(apt.SuiteLifecycle)},
			}
			for _, field := range aptFields {
				if err := budget.add(uint64(field.count), fmt.Sprintf("repos[%d].apt.%s", index, field.name)); err != nil {
					return err
				}
			}
			for _, suite := range sortedStringMapKeys(apt.SuiteComponents) {
				if err := budget.add(uint64(len(apt.SuiteComponents[suite])), fmt.Sprintf("repos[%d].apt.suite_components.%s", index, suite)); err != nil {
					return err
				}
			}
			for _, suite := range apt.Suites {
				if err := budget.addProduct(fmt.Sprintf("repos[%d].apt selector leaves", index), uint64(len(repo.Arches))); err != nil {
					return err
				}
				components := apt.componentsForSuite(suite)
				if err := budget.addProduct(fmt.Sprintf("repos[%d].apt metadata leaves", index), uint64(len(components)), uint64(len(repo.Arches))); err != nil {
					return err
				}
			}
		case repo.YUM != nil:
			if err := budget.addProduct(fmt.Sprintf("repos[%d].yum selector leaves", index), uint64(len(repo.OSSelectorValues())), uint64(len(repo.Arches))); err != nil {
				return err
			}
		case repo.Asset != nil:
			if err := budget.add(uint64(len(repo.Asset.MutablePaths)), fmt.Sprintf("repos[%d].asset.mutable_paths", index)); err != nil {
				return err
			}
			if err := budget.add(uint64(len(repo.Asset.RootKeys)), fmt.Sprintf("repos[%d].asset.root_keys", index)); err != nil {
				return err
			}
			if err := budget.add(1, fmt.Sprintf("repos[%d].asset selector leaf", index)); err != nil {
				return err
			}
		}
	}

	for _, group := range sortedStringMapKeys(cfg.RepoGroups) {
		if err := budget.add(uint64(len(cfg.RepoGroups[group])), "repo_groups."+group); err != nil {
			return err
		}
	}

	for index := range cfg.Upstreams {
		upstream := &cfg.Upstreams[index]
		if err := budget.add(uint64(len(upstream.Arches)), fmt.Sprintf("upstreams[%d].arches", index)); err != nil {
			return err
		}
		if err := budget.add(uint64(len(upstream.Components)), fmt.Sprintf("upstreams[%d].components", index)); err != nil {
			return err
		}
		if err := budget.add(uint64(len(upstream.Allow)), fmt.Sprintf("upstreams[%d].allow", index)); err != nil {
			return err
		}
		if err := budget.add(uint64(len(upstream.Deny)), fmt.Sprintf("upstreams[%d].deny", index)); err != nil {
			return err
		}
		repo := repos[upstream.Repo]
		arches := upstream.Arches
		if len(arches) == 0 && repo != nil {
			arches = repo.Arches
			if err := budget.add(uint64(len(arches)), fmt.Sprintf("upstreams[%d].arches default expansion", index)); err != nil {
				return err
			}
		}
		components := upstream.Components
		if upstream.Type == "apt" && len(components) == 0 && repo != nil && repo.APT != nil {
			suite := upstream.Suite
			if suite == "" && len(repo.APT.Suites) == 1 {
				suite = repo.APT.Suites[0]
			}
			components = repo.APT.componentsForSuite(suite)
			if err := budget.add(uint64(len(components)), fmt.Sprintf("upstreams[%d].components default expansion", index)); err != nil {
				return err
			}
		}
		if upstream.Type == "apt" {
			if err := budget.addProduct(fmt.Sprintf("upstreams[%d].apt selector leaves", index), uint64(len(components)), uint64(len(arches))); err != nil {
				return err
			}
		} else if upstream.Type == "yum" {
			if err := budget.add(uint64(len(arches)), fmt.Sprintf("upstreams[%d].yum selector leaves", index)); err != nil {
				return err
			}
		}
	}

	for _, viewName := range sortedStringMapKeys(cfg.Views) {
		view := cfg.Views[viewName]
		if err := budget.add(uint64(len(view.AllowedPools)), "views."+viewName+".allowed_pools"); err != nil {
			return err
		}
		if err := budget.add(uint64(len(view.Repos)), "views."+viewName+".repos"); err != nil {
			return err
		}
		field := "views." + viewName + ".repo selector leaves"
		selected := view.Repos
		if len(selected) == 0 {
			field += " default expansion"
			for index := range cfg.Repos {
				if err := addRepoSelectorLeaves(budget, field, &cfg.Repos[index]); err != nil {
					return err
				}
			}
			continue
		}
		for _, repoID := range selected {
			repo := repos[repoID]
			if repo == nil {
				if err := budget.add(1, field); err != nil {
					return err
				}
				continue
			}
			if err := addRepoSelectorLeaves(budget, field, repo); err != nil {
				return err
			}
		}
	}
	return nil
}

func addRepoSelectorLeaves(budget *configComplexityBudget, field string, repo *Repo) error {
	switch {
	case repo == nil:
		return budget.add(1, field)
	case repo.APT != nil:
		return budget.add(maxOneProduct(uint64(len(repo.APT.Suites)), uint64(len(repo.Arches))), field)
	case repo.YUM != nil:
		return budget.add(maxOneProduct(uint64(len(repo.OSSelectorValues())), uint64(len(repo.Arches))), field)
	default:
		return budget.add(1, field)
	}
}

// maxOneProduct makes the preflight itself bounded for invalid zero-dimension
// repositories. A hostile config with many empty default views and many
// incomplete repos must still spend one unit per visited view/repo pair rather
// than reaching the ordinary schema error through an uncharged cross-product.
func maxOneProduct(factors ...uint64) uint64 {
	product := uint64(1)
	for _, factor := range factors {
		if factor == 0 {
			return 1
		}
		if factor > math.MaxUint64/product {
			return math.MaxUint64
		}
		product *= factor
	}
	return product
}

func accountConfigDerivedStringBytes(cfg *Config, budget *configComplexityBudget) error {
	repos := make(map[string]*Repo, len(cfg.Repos))
	viewShapes := make([]viewRepoCoordinateShape, len(cfg.Repos))
	viewShapesByRepo := make(map[string]viewRepoCoordinateShape, len(cfg.Repos))
	targetNames := sortedStringMapKeys(cfg.Targets)
	for index := range cfg.Repos {
		repo := &cfg.Repos[index]
		archBytes := stringListBytes(repo.Arches)
		common := uint64(len(repo.ID) + len(repo.Path))
		shape := viewRepoCoordinateShape{
			commonBytes: common,
			archCount:   uint64(len(repo.Arches)),
			archBytes:   archBytes,
		}
		switch {
		case repo.APT != nil:
			shape.packageRepo = true
			shape.axisCount = uint64(len(repo.APT.Suites))
			shape.axisBytes = stringListBytes(repo.APT.Suites)
		case repo.YUM != nil:
			shape.packageRepo = true
			osValues := repo.OSSelectorValues()
			shape.axisCount = uint64(len(osValues))
			shape.axisBytes = stringListBytes(osValues)
		default:
			shape.assetPublicRootBytes = uint64(len(repo.AssetPublicRoot()))
		}
		viewShapes[index] = shape
		if _, exists := repos[repo.ID]; !exists {
			repos[repo.ID] = repo
			viewShapesByRepo[repo.ID] = shape
		}

		if strings.Count(repo.Path, "{arch}") == 1 && repo.Type == "yum" && len(repo.Arches) != 0 {
			baseLength := uint64(len(repo.Path) - len("{arch}"))
			if err := budget.addProduct(fmt.Sprintf("repos[%d].expanded_paths", index), uint64(len(repo.Arches)), baseLength); err != nil {
				return err
			}
			if err := budget.add(archBytes, fmt.Sprintf("repos[%d].expanded_paths", index)); err != nil {
				return err
			}
		}

		repoTargetNames := repo.PublishTargets
		if len(repoTargetNames) == 0 {
			repoTargetNames = targetNames
		}
		if err := budget.addProduct(fmt.Sprintf("repos[%d].publish target coordinates", index), uint64(len(repoTargetNames)), uint64(len(repo.ID))); err != nil {
			return err
		}
		if err := budget.add(stringListBytes(repoTargetNames), fmt.Sprintf("repos[%d].publish target coordinates", index)); err != nil {
			return err
		}

		switch {
		case repo.APT != nil:
			apt := repo.APT
			rectangularComponentBytes := uint64(0)
			if apt.hasSuiteComponents() {
				for _, suite := range sortedStringMapKeys(apt.SuiteComponents) {
					if err := budget.add(stringListBytes(apt.SuiteComponents[suite]), fmt.Sprintf("repos[%d].apt.suite_components.%s normalization", index, suite)); err != nil {
						return err
					}
				}
			} else {
				rectangularComponentBytes = stringListBytes(apt.Components)
			}
			for _, suite := range apt.Suites {
				selectorBase := common + uint64(len(suite))
				if err := budget.addProduct(fmt.Sprintf("repos[%d].apt selector coordinates", index), uint64(len(repo.Arches)), selectorBase); err != nil {
					return err
				}
				if err := budget.add(archBytes, fmt.Sprintf("repos[%d].apt selector coordinates", index)); err != nil {
					return err
				}
				components := apt.componentsForSuite(suite)
				componentBytes := rectangularComponentBytes
				if apt.hasSuiteComponents() {
					componentBytes = stringListBytes(components)
				}
				if err := budget.addProduct(fmt.Sprintf("repos[%d].apt metadata coordinates", index), uint64(len(components)), uint64(len(repo.Arches)), selectorBase); err != nil {
					return err
				}
				if err := budget.addProduct(fmt.Sprintf("repos[%d].apt metadata coordinates", index), uint64(len(repo.Arches)), componentBytes); err != nil {
					return err
				}
				if err := budget.addProduct(fmt.Sprintf("repos[%d].apt metadata coordinates", index), uint64(len(components)), archBytes); err != nil {
					return err
				}
			}
		case repo.YUM != nil:
			if err := budget.addProduct(fmt.Sprintf("repos[%d].yum selector coordinates", index), shape.archCount, shape.axisCount, common); err != nil {
				return err
			}
			if err := budget.addProduct(fmt.Sprintf("repos[%d].yum selector coordinates", index), shape.archCount, shape.axisBytes); err != nil {
				return err
			}
			if err := budget.addProduct(fmt.Sprintf("repos[%d].yum selector coordinates", index), shape.axisCount, shape.archBytes); err != nil {
				return err
			}
			if repo.YUM.packageKeyringDefaulted {
				if err := budget.add(uint64(len(repo.YUM.PackageKeyring)), fmt.Sprintf("repos[%d].yum.package_keyring default", index)); err != nil {
					return err
				}
			}
			if !repo.YUM.noarchModePresent {
				if err := budget.add(uint64(len(repo.YUM.NoarchMode)), fmt.Sprintf("repos[%d].yum.noarch_mode default", index)); err != nil {
					return err
				}
			}
		case repo.Asset != nil:
			if err := budget.add(common+uint64(len(repo.AssetPublicRoot())), fmt.Sprintf("repos[%d].asset selector coordinates", index)); err != nil {
				return err
			}
			if !repo.Asset.publicPathPresent {
				// Decode applies this default before Validate, while direct
				// Config.Validate callers reach the same assignment in
				// validateRepos. Charge the declared source path in both cases.
				if err := budget.add(uint64(len(repo.Path)), fmt.Sprintf("repos[%d].asset.public_path default", index)); err != nil {
					return err
				}
			}
		}
	}

	for index, projection := range cfg.CompatibilityProjections {
		bytes := len(projection.ID) + len(projection.Root) + len(projection.Mode) + len(projection.Carrier) +
			len(projection.Source.Repo) + len(projection.Source.View) + len(projection.Source.OS) +
			len(projection.Source.Arch) + len(projection.Source.Commit)
		if err := budget.add(uint64(bytes), fmt.Sprintf("compatibility_projections[%d] coordinates", index)); err != nil {
			return err
		}
	}

	for index := range cfg.Upstreams {
		upstream := &cfg.Upstreams[index]
		repo := repos[upstream.Repo]
		arches := upstream.Arches
		if len(arches) == 0 && repo != nil {
			arches = repo.Arches
			if err := budget.add(stringListBytes(arches), fmt.Sprintf("upstreams[%d].arches default", index)); err != nil {
				return err
			}
		}
		suite := upstream.Suite
		if suite == "" && upstream.Type == "apt" && repo != nil && repo.APT != nil && len(repo.APT.Suites) == 1 {
			suite = repo.APT.Suites[0]
			if err := budget.add(uint64(len(suite)), fmt.Sprintf("upstreams[%d].suite default", index)); err != nil {
				return err
			}
		}
		components := upstream.Components
		if upstream.Type == "apt" && len(components) == 0 && repo != nil && repo.APT != nil {
			components = repo.APT.componentsForSuite(suite)
			if err := budget.add(stringListBytes(components), fmt.Sprintf("upstreams[%d].components default", index)); err != nil {
				return err
			}
		}
		if upstream.DebugInfo == "" {
			if err := budget.add(uint64(len("drop")), fmt.Sprintf("upstreams[%d].debuginfo default", index)); err != nil {
				return err
			}
		}
		archBytes := stringListBytes(arches)
		base := uint64(len(upstream.ID) + len(upstream.Repo) + len(suite))
		if upstream.Type == "apt" {
			componentBytes := stringListBytes(components)
			if err := budget.addProduct(fmt.Sprintf("upstreams[%d].apt selector coordinates", index), uint64(len(components)), uint64(len(arches)), base); err != nil {
				return err
			}
			if err := budget.addProduct(fmt.Sprintf("upstreams[%d].apt selector coordinates", index), uint64(len(arches)), componentBytes); err != nil {
				return err
			}
			if err := budget.addProduct(fmt.Sprintf("upstreams[%d].apt selector coordinates", index), uint64(len(components)), archBytes); err != nil {
				return err
			}
		} else if upstream.Type == "yum" {
			if err := budget.addProduct(fmt.Sprintf("upstreams[%d].yum selector coordinates", index), uint64(len(arches)), base); err != nil {
				return err
			}
			if err := budget.add(archBytes, fmt.Sprintf("upstreams[%d].yum selector coordinates", index)); err != nil {
				return err
			}
		}
	}

	for _, viewName := range sortedStringMapKeys(cfg.Views) {
		view := cfg.Views[viewName]
		field := "views." + viewName + " repo selector coordinates"
		if len(view.Repos) == 0 {
			for index := range viewShapes {
				if err := viewShapes[index].add(budget, field, viewName); err != nil {
					return err
				}
			}
		} else {
			for _, repoID := range view.Repos {
				shape, exists := viewShapesByRepo[repoID]
				if !exists {
					if err := budget.add(uint64(len(viewName)+len(repoID)), field); err != nil {
						return err
					}
					continue
				}
				if err := shape.add(budget, field, viewName); err != nil {
					return err
				}
			}
		}
		if err := budget.add(uint64(len(view.DebugInfo)), "views."+viewName+".debuginfo canonical value"); err != nil {
			return err
		}
	}

	for _, targetName := range sortedStringMapKeys(cfg.Targets) {
		target := cfg.Targets[targetName]
		if err := budget.add(uint64(len(target.Storage.Region)+len(target.Storage.DeleteMode)), "targets."+targetName+" canonical defaults"); err != nil {
			return err
		}
	}
	if err := budget.add(uint64(len(cfg.Edge.ProPrefix)), "edge.pro_prefix canonical value"); err != nil {
		return err
	}
	return nil
}

type viewRepoCoordinateShape struct {
	commonBytes          uint64
	axisCount            uint64
	axisBytes            uint64
	archCount            uint64
	archBytes            uint64
	assetPublicRootBytes uint64
	packageRepo          bool
}

func (shape viewRepoCoordinateShape) add(budget *configComplexityBudget, field, viewName string) error {
	common := shape.commonBytes + uint64(len(viewName))
	if !shape.packageRepo {
		return budget.add(common+shape.assetPublicRootBytes, field)
	}
	if err := budget.addProduct(field, shape.axisCount, shape.archCount, common); err != nil {
		return err
	}
	if err := budget.addProduct(field, shape.archCount, shape.axisBytes); err != nil {
		return err
	}
	return budget.addProduct(field, shape.axisCount, shape.archBytes)
}

func stringListBytes(values []string) uint64 {
	var total uint64
	for _, value := range values {
		total += uint64(len(value))
	}
	return total
}

func sortedStringMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
