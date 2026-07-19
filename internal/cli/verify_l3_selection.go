package cli

import (
	"net/url"
	"path"
	"strings"

	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
)

type l3SelectorGap struct {
	code    string
	subject string
	message string
}

type l3ScopedExpectations struct {
	positive []pub.VerifyObject
	absent   []pub.VerifyAbsentObject
	gaps     []l3SelectorGap
}

func hasExplicitVerificationLeafSelector(values commonFlags) bool {
	return len(values.repos.values()) != 0 || len(values.oses.values()) != 0 || len(values.arches.values()) != 0
}

// scopeL3Expectations binds an explicitly selected repo/OS/arch set to the
// exact change-set URLs carried by the committed publication plan. L3 is a
// change-set audit rather than a full repository walk: when the most recent
// intent plan has no expectation for a selected leaf, the honest result is a
// coverage finding, never success based on an unrelated repo's probe.
func scopeL3Expectations(
	cfg *config.Config,
	target, viewName, snapshotID string,
	generation pub.TargetGeneration,
	positive []pub.VerifyObject,
	absent []pub.VerifyAbsentObject,
	repos []config.Repo,
	values commonFlags,
) l3ScopedExpectations {
	result := l3ScopedExpectations{
		positive: append([]pub.VerifyObject(nil), positive...),
		absent:   append([]pub.VerifyAbsentObject(nil), absent...),
	}
	if !hasExplicitVerificationLeafSelector(values) {
		return result
	}
	result.positive = nil
	// Negative expectations are transaction-wide safety closure, not optional
	// content sampling. In particular, selecting one retained repo must not hide
	// a stale gated snapshot route that the same committed plan deleted. Keep
	// every authenticated absence while using leaf matching below only to decide
	// whether an absence also closes explicit selector coverage.
	result.absent = append([]pub.VerifyAbsentObject(nil), absent...)

	var leaves []viewLeaf
	view, viewExists := cfg.Views[viewName]
	for _, leaf := range selectedLeaves(repos, values) {
		if !leaf.repo.PublishesToTarget(target) || snapshotID == "" && (!viewExists || !viewIncludesRepo(view, leaf.repo.ID)) {
			continue
		}
		leaves = append(leaves, leaf)
	}
	if len(leaves) == 0 {
		result.gaps = append(result.gaps, l3SelectorGap{
			code: "REMOTE_SELECTOR_TARGET_COVERAGE_MISSING", subject: target + "/" + viewName,
			message: "the explicit repository selectors match no leaf owned by this target and intent",
		})
		return result
	}

	covered := make(map[string]bool, len(leaves))
	eligible := make(map[string]bool, len(leaves))
	for _, leaf := range leaves {
		key := l3LeafKey(leaf)
		present := generationHasLeaf(generation, viewName, leaf)
		if snapshotID != "" {
			present = generationHasSnapshotLeaf(generation, snapshotID, leaf)
		}
		if !present {
			result.gaps = append(result.gaps, l3SelectorGap{
				code: "REMOTE_REF_COVERAGE_MISSING", subject: l3LeafSubject(target, viewName, snapshotID, leaf),
				message: "the committed generation does not contain the explicitly selected repository leaf",
			})
			continue
		}
		eligible[key] = true
	}

	for _, expectation := range positive {
		matched, closes := l3ExpectationSelection(expectation.URL, leaves, viewName, snapshotID)
		if len(matched) == 0 {
			continue
		}
		result.positive = append(result.positive, expectation)
		for _, key := range closes {
			if eligible[key] {
				covered[key] = true
			}
		}
	}
	for _, expectation := range absent {
		matched, closes := l3ExpectationSelection(expectation.URL, leaves, viewName, snapshotID)
		if len(matched) == 0 {
			continue
		}
		for _, key := range closes {
			if eligible[key] {
				covered[key] = true
			}
		}
	}
	for _, leaf := range leaves {
		key := l3LeafKey(leaf)
		if eligible[key] && !covered[key] {
			result.gaps = append(result.gaps, l3SelectorGap{
				code: "REMOTE_PLAN_SELECTOR_COVERAGE_MISSING", subject: l3LeafSubject(target, viewName, snapshotID, leaf),
				message: "the selected leaf has no positive or negative expectation in the committed change-set plan",
			})
		}
	}
	return result
}

func l3LeafKey(leaf viewLeaf) string {
	return strings.Join([]string{leaf.repo.ID, leaf.os, leaf.arch}, "\x00")
}

func l3LeafSubject(target, viewName, snapshotID string, leaf viewLeaf) string {
	intent := viewName
	if snapshotID != "" {
		intent = "snapshot/" + snapshotID
	}
	return strings.Join([]string{target, intent, leaf.repo.ID, leaf.os, leaf.arch}, "/")
}

// l3ExpectationSelection returns every selected leaf whose route owns the URL
// and, separately, the leaves for which that URL is meaningful change-set
// coverage. Shared package pools are retained in a scoped probe but do not by
// themselves prove one APT architecture or YUM OS channel was selected.
func l3ExpectationSelection(rawURL string, leaves []viewLeaf, viewName, snapshotID string) (matched, closes []string) {
	route, channelRepo, channelOS, channelArch, ok := normalizeL3ExpectationRoute(rawURL, viewName, snapshotID)
	if !ok {
		return nil, nil
	}
	matchedSet := make(map[string]struct{})
	closedSet := make(map[string]struct{})
	for _, leaf := range leaves {
		key := l3LeafKey(leaf)
		if channelRepo != "" {
			if leaf.repo.Type == "yum" && leaf.repo.ID == channelRepo && leaf.os == channelOS && leaf.arch == channelArch {
				matchedSet[key] = struct{}{}
				closedSet[key] = struct{}{}
			}
			continue
		}
		switch leaf.repo.Type {
		case "asset":
			if leaf.repo.AssetPublicRoot() == "." && leaf.repo.Asset != nil {
				for _, rootKey := range leaf.repo.Asset.RootKeys {
					if route == rootKey {
						matchedSet[key] = struct{}{}
						closedSet[key] = struct{}{}
						break
					}
				}
				continue
			}
			roots := []string{leaf.repo.Path, leaf.repo.AssetPublicRoot()}
			for _, root := range roots {
				if routeBelowL3Root(route, root) {
					matchedSet[key] = struct{}{}
					closedSet[key] = struct{}{}
					break
				}
			}
		case "apt":
			relative, under := relativeL3Route(route, leaf.repo.Path)
			if !under {
				continue
			}
			if strings.HasPrefix(relative, "pool/") {
				matchedSet[key] = struct{}{}
				continue
			}
			metadataSuite := leaf.os
			if snapshotID != "" {
				metadataSuite = snapshotID
			}
			if strings.HasPrefix(relative, "dists/"+metadataSuite+"/") {
				matchedSet[key] = struct{}{}
				// Release/InRelease is shared by every architecture in a
				// suite. It is useful to probe once the suite is selected, but
				// it cannot prove that the committed change-set covers this
				// exact architecture. A direct or by-hash Packages route retains
				// its binary-<arch> segment and therefore closes the leaf.
				if strings.Contains(relative, "/binary-"+leaf.arch+"/") {
					closedSet[key] = struct{}{}
				}
			}
		case "yum":
			root, err := leaf.repo.PathForArch(leaf.arch)
			if err == nil && routeBelowL3Root(route, root) {
				matchedSet[key] = struct{}{}
				// One physical YUM repo+arch can own several logical OS aliases;
				// only the exact mirrorlist/channel route closes an ordinary OS
				// selector. An immutable snapshot intent itself names one frozen
				// suite, so its exact repo+arch route is sufficient.
				if snapshotID != "" {
					closedSet[key] = struct{}{}
				}
			}
		}
	}
	for _, leaf := range leaves {
		key := l3LeafKey(leaf)
		if _, exists := matchedSet[key]; exists {
			matched = append(matched, key)
		}
		if _, exists := closedSet[key]; exists {
			closes = append(closes, key)
		}
	}
	return matched, closes
}

func normalizeL3ExpectationRoute(rawURL, viewName, snapshotID string) (route, channelRepo, channelOS, channelArch string, ok bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || path.Clean(parsed.Path) != parsed.Path {
		return "", "", "", "", false
	}
	segments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if (viewName == "stable" || snapshotID != "") && len(segments) >= 3 && segments[0] == "pro" && segments[1] == "v1" {
		segments = segments[3:]
	}
	if len(segments) >= 7 && segments[0] == "_sow" && segments[1] == "v1" && segments[2] == "mirrorlist" {
		arch := strings.TrimSuffix(segments[6], ".txt")
		if len(segments) == 7 && segments[3] == viewName && arch != "" && arch != segments[6] {
			return "", segments[4], segments[5], arch, true
		}
		return "", "", "", "", false
	}
	if len(segments) >= 5 && segments[0] == "_sow" && segments[1] == "v1" && (segments[2] == "a" || segments[2] == "g") && len(segments[3]) == 20 {
		segments = segments[4:]
	} else if len(segments) >= 6 && segments[0] == "_sow" && segments[1] == "v1" && segments[2] == "snapshots" {
		if snapshotID == "" || segments[3] != snapshotID || (segments[4] != "apt" && segments[4] != "yum" && segments[4] != "asset") {
			return "", "", "", "", false
		}
		segments = segments[5:]
	}
	if len(segments) == 0 {
		return "", "", "", "", false
	}
	return strings.Join(segments, "/"), "", "", "", true
}

func routeBelowL3Root(route, root string) bool {
	_, ok := relativeL3Route(route, root)
	return ok
}

func relativeL3Route(route, root string) (string, bool) {
	root = strings.Trim(strings.TrimSpace(root), "/")
	if root == "" || route == root || !strings.HasPrefix(route, root+"/") {
		return "", false
	}
	return strings.TrimPrefix(route, root+"/"), true
}
