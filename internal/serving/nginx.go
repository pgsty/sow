package serving

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/config"
)

const basicNginxURLPrefix = "/pro/v1/basic"

// An immutable YUM generation exposes only signed repodata and canonical
// Packages/<bucket>/<safe RPM basename> payloads. In particular it must never
// expose root-flat compatibility aliases: those belong exclusively to the raw
// legacy route. Capture 1 remains the generation ID; this outer non-nesting
// group is capture 2.
const nginxGenerationTailPattern = `((?:repodata/(?!\.{1,2}$)[A-Za-z0-9._+~^@-]+|Packages/[a-z0-9_]/[A-Za-z0-9][A-Za-z0-9._+~^-]*\.rpm))`

// NginxIncludeOptions describes one immutable projection from a validated
// sow.yaml into an Nginx server-context include. Root is the exact materialized
// tree served by the enclosing server. BasicAuthUserFile is required only for
// the pro stable view and contains a path, never credential material.
type NginxIncludeOptions struct {
	View              string
	Root              string
	BasicAuthUserFile string
	// RawCompatibilityIDs is the exact set whose current legacy raw tree has
	// been proven by the caller. It remains routable before cutover and after
	// rollback so existing consumers do not lose the migration bridge.
	RawCompatibilityIDs []string
	// ActiveCompatibilityIDs is the exact subset whose completed S3 cutover is
	// currently active. Only this set receives generation, mirrorlist and
	// frozen-trust routes. Configuration or a frozen S2 candidate alone is not
	// sufficient, and rollback must remove an ID from this set.
	ActiveCompatibilityIDs []string
}

type nginxRouteKind uint8

const (
	nginxExactRoute nginxRouteKind = iota
	nginxPrefixRoute
	nginxGenerationRoute
)

type nginxRoute struct {
	kind   nginxRouteKind
	url    string
	source string
}

// RenderNginxInclude emits a complete default-deny set of location blocks for
// one mutable view. Every successful route is derived from an exact configured
// repository leaf, asset projection, YUM pointer/generation coordinate, frozen
// compatibility leaf, or the configured public trust anchor. It intentionally
// has no generic root/try_files fallback and never emits /apt/, /yum/, or
// /_sow/ parent aliases.
func RenderNginxInclude(cfg *config.Config, repos []config.Repo, options NginxIncludeOptions) ([]byte, error) {
	if cfg == nil {
		return nil, errors.New("Nginx include requires a validated configuration")
	}
	view, exists := cfg.Views[options.View]
	if !exists || options.View != "latest" && options.View != "beta" && options.View != "stable" {
		return nil, fmt.Errorf("Nginx include view %q is not a configured mutable view", options.View)
	}
	root, err := cleanNginxPathResolvingExistingPrefix("Nginx serving root", options.Root)
	if err != nil {
		return nil, err
	}
	urlPrefix := ""
	switch view.Access {
	case "public":
		if options.BasicAuthUserFile != "" {
			return nil, fmt.Errorf("public view %s must not configure Basic Auth", options.View)
		}
	case "pro":
		if options.View != "stable" {
			return nil, fmt.Errorf("pro Nginx fallback is supported only for stable, got %s", options.View)
		}
		urlPrefix = basicNginxURLPrefix
		authFile, authErr := resolveNginxRegularFile("Nginx Basic Auth user file", options.BasicAuthUserFile)
		if authErr != nil {
			return nil, authErr
		}
		repositoryRoot := ""
		if cfg.Root != "" {
			repositoryRoot, authErr = cleanNginxPathResolvingExistingPrefix("repository root", cfg.Root)
			if authErr != nil {
				return nil, authErr
			}
		}
		if pathContains(root, authFile) || repositoryRoot != "" && pathContains(repositoryRoot, authFile) {
			return nil, errors.New("Nginx Basic Auth user file must be outside the repository and served tree")
		}
		options.BasicAuthUserFile = authFile
	default:
		return nil, fmt.Errorf("view %s has unsupported access %q", options.View, view.Access)
	}

	selected := make(map[string]config.Repo, len(repos))
	for _, repo := range repos {
		if !repo.IsActive() || !nginxViewIncludesRepo(view, repo.ID) {
			continue
		}
		if _, duplicate := selected[repo.ID]; duplicate {
			return nil, fmt.Errorf("Nginx include repository %q is selected more than once", repo.ID)
		}
		selected[repo.ID] = repo
	}
	rawCompatibility := make(map[string]config.YUMCompatibilityProjection, len(options.RawCompatibilityIDs))
	for _, id := range options.RawCompatibilityIDs {
		if _, duplicate := rawCompatibility[id]; duplicate {
			return nil, fmt.Errorf("Nginx include raw compatibility projection %q is enabled more than once", id)
		}
		projection, found, lookupErr := config.YUMCompatibilityProjectionByID(cfg.CompatibilityProjections, id)
		if lookupErr != nil {
			return nil, fmt.Errorf("Nginx include compatibility projection %q: %w", id, lookupErr)
		}
		if !found {
			return nil, fmt.Errorf("Nginx include compatibility projection %q is not configured", id)
		}
		if projection.Source.View != options.View {
			return nil, fmt.Errorf("Nginx include compatibility projection %q belongs to view %s, not %s", id, projection.Source.View, options.View)
		}
		// A compatibility projection inherits selector/view/target affinity from
		// its active owner. An explicit cutover authorization must still fail
		// closed if a narrowed selector omitted that owner.
		if _, ownerSelected := selected[projection.Source.Repo]; !ownerSelected {
			return nil, fmt.Errorf("Nginx include compatibility projection %q requires selected affinity owner %s", id, projection.Source.Repo)
		}
		rawCompatibility[id] = projection
	}
	activeCompatibility := make(map[string]config.YUMCompatibilityProjection, len(options.ActiveCompatibilityIDs))
	for _, id := range options.ActiveCompatibilityIDs {
		if _, duplicate := activeCompatibility[id]; duplicate {
			return nil, fmt.Errorf("Nginx include active compatibility projection %q is enabled more than once", id)
		}
		projection, raw := rawCompatibility[id]
		if !raw {
			return nil, fmt.Errorf("Nginx include active compatibility projection %q lacks a proven raw bridge", id)
		}
		activeCompatibility[id] = projection
	}
	if len(selected) == 0 && len(rawCompatibility) == 0 {
		return nil, fmt.Errorf("Nginx include selectors matched no active repositories in view %s", options.View)
	}

	var routes []nginxRoute
	add := func(kind nginxRouteKind, urlPath, source string) error {
		if err := validateNginxRoutePath(urlPath); err != nil {
			return err
		}
		sourcePath := source
		if !filepath.IsAbs(sourcePath) {
			sourcePath = filepath.Join(root, filepath.FromSlash(sourcePath))
		}
		sourcePath, err = cleanAbsoluteNginxPath("Nginx route source", sourcePath)
		if err != nil {
			return err
		}
		routes = append(routes, nginxRoute{kind: kind, url: urlPath, source: sourcePath})
		return nil
	}

	packageSelected := false
	trustPaths := make(map[string]struct{})
	ids := make([]string, 0, len(selected))
	for id := range selected {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		repo := selected[id]
		switch repo.Type {
		case "asset":
			if repo.Asset == nil {
				return nil, fmt.Errorf("Nginx include repo %s has no asset projection", repo.ID)
			}
			publicRoot := repo.AssetPublicRoot()
			if publicRoot == "." {
				for _, key := range repo.Asset.RootKeys {
					if err := add(nginxExactRoute, key, path.Join(repo.Path, key)); err != nil {
						return nil, fmt.Errorf("Nginx include repo %s: %w", repo.ID, err)
					}
				}
			} else if err := add(nginxPrefixRoute, publicRoot, repo.Path); err != nil {
				return nil, fmt.Errorf("Nginx include repo %s: %w", repo.ID, err)
			}
		case "apt":
			packageSelected = true
			expanded, expandErr := repo.ExpandedPaths()
			if expandErr != nil {
				return nil, fmt.Errorf("Nginx include repo %s: %w", repo.ID, expandErr)
			}
			for _, leaf := range expanded {
				if err := add(nginxPrefixRoute, leaf, leaf); err != nil {
					return nil, fmt.Errorf("Nginx include repo %s: %w", repo.ID, err)
				}
			}
		case "yum":
			packageSelected = true
			if repo.YUM == nil {
				return nil, fmt.Errorf("Nginx include repo %s has no YUM contract", repo.ID)
			}
			if repo.YUM.PackageKeyring != "" {
				trustPaths[repo.YUM.PackageKeyring] = struct{}{}
			}
			if _, servingErr := cfg.ServingBaseURL(options.View); servingErr != nil {
				return nil, fmt.Errorf("Nginx include repo %s: %w", repo.ID, servingErr)
			}
			for _, arch := range repo.Arches {
				leaf, leafErr := repo.PathForArch(arch)
				if leafErr != nil {
					return nil, fmt.Errorf("Nginx include repo %s: %w", repo.ID, leafErr)
				}
				if err := add(nginxPrefixRoute, leaf, leaf); err != nil {
					return nil, fmt.Errorf("Nginx include repo %s: %w", repo.ID, err)
				}
				if err := add(nginxGenerationRoute, leaf, leaf); err != nil {
					return nil, fmt.Errorf("Nginx include repo %s: %w", repo.ID, err)
				}
				for _, osName := range repo.OSSelectorValues() {
					mirrorlist := MirrorlistPath(options.View, repo.ID, osName, arch)
					if err := add(nginxExactRoute, mirrorlist, mirrorlist); err != nil {
						return nil, fmt.Errorf("Nginx include repo %s: %w", repo.ID, err)
					}
				}
			}
		default:
			return nil, fmt.Errorf("Nginx include repo %s has unsupported type %q", repo.ID, repo.Type)
		}
	}

	for _, projection := range cfg.CompatibilityProjections {
		if _, enabled := rawCompatibility[projection.ID]; !enabled {
			continue
		}
		if projection.Source.View != options.View {
			continue
		}
		owner, exists := cfg.RepoByName(projection.Source.Repo)
		if !exists || owner.Type != "yum" || owner.YUM == nil {
			return nil, fmt.Errorf("Nginx include compatibility projection %s has no configured YUM affinity owner", projection.ID)
		}
		if _, ownerSelected := selected[owner.ID]; !ownerSelected {
			continue
		}
		packageSelected = true
		if owner.YUM.PackageKeyring != "" {
			trustPaths[owner.YUM.PackageKeyring] = struct{}{}
		}
		if err := add(nginxPrefixRoute, projection.Root, projection.Root); err != nil {
			return nil, fmt.Errorf("Nginx include compatibility projection %s: %w", projection.ID, err)
		}
		if _, active := activeCompatibility[projection.ID]; !active {
			continue
		}
		if err := add(nginxGenerationRoute, projection.Root, projection.Root); err != nil {
			return nil, fmt.Errorf("Nginx include compatibility projection %s generation: %w", projection.ID, err)
		}
		mirrorlist := MirrorlistPath(options.View, projection.ID, "cross-el", projection.Source.Arch)
		if err := add(nginxExactRoute, mirrorlist, mirrorlist); err != nil {
			return nil, fmt.Errorf("Nginx include compatibility projection %s mirrorlist: %w", projection.ID, err)
		}
		for _, trustRoute := range []string{
			config.YUMCompatibilityPackageTrustRoute(projection.ID),
			config.YUMCompatibilityRepositoryTrustRoute(projection.ID),
		} {
			if err := add(nginxExactRoute, trustRoute, trustRoute); err != nil {
				return nil, fmt.Errorf("Nginx include compatibility projection %s frozen trust: %w", projection.ID, err)
			}
		}
	}

	if packageSelected && cfg.GPG.PublicKey != "" {
		trustPaths[cfg.GPG.PublicKey] = struct{}{}
	}
	orderedTrustPaths := make([]string, 0, len(trustPaths))
	for trustPath := range trustPaths {
		orderedTrustPaths = append(orderedTrustPaths, trustPath)
	}
	sort.Strings(orderedTrustPaths)
	for _, trustPath := range orderedTrustPaths {
		keySource := trustPath
		if cfg.Path != "" {
			configDir, dirErr := cleanNginxPathResolvingExistingPrefix("Nginx configuration directory", filepath.Dir(cfg.Path))
			if dirErr != nil {
				return nil, dirErr
			}
			keySource = filepath.Join(configDir, filepath.FromSlash(trustPath))
		}
		if err := add(nginxExactRoute, trustPath, keySource); err != nil {
			return nil, fmt.Errorf("Nginx include public trust anchor: %w", err)
		}
	}

	if err := validateNginxRouteSet(routes); err != nil {
		return nil, err
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].kind != routes[j].kind {
			return routes[i].kind < routes[j].kind
		}
		if routes[i].url != routes[j].url {
			return routes[i].url < routes[j].url
		}
		return routes[i].source < routes[j].source
	})

	var output bytes.Buffer
	fmt.Fprintln(&output, "# Generated by sow from validated schema sow/v1; DO NOT EDIT.")
	fmt.Fprintf(&output, "# view=%s access=%s; include inside exactly one Nginx server block.\n", options.View, view.Access)
	fmt.Fprintln(&output, "# The enclosing server must not define a broader repository location or root fallback.")
	for _, route := range routes {
		renderNginxRoute(&output, route, root, urlPrefix, options.BasicAuthUserFile)
	}
	fmt.Fprintln(&output, "location / { return 404; }")
	return output.Bytes(), nil
}

func renderNginxRoute(output *bytes.Buffer, route nginxRoute, root, urlPrefix, authFile string) {
	writePolicy := func() {
		output.WriteString("    limit_except GET { deny all; }\n")
		output.WriteString("    autoindex off;\n")
		output.WriteString("    disable_symlinks on;\n")
		if authFile != "" {
			output.WriteString("    auth_basic \"Pigsty Pro repository\";\n")
			fmt.Fprintf(output, "    auth_basic_user_file %s;\n", nginxQuote(authFile))
			output.WriteString("    add_header Cache-Control \"private, no-store\" always;\n")
		}
	}
	switch route.kind {
	case nginxExactRoute:
		fmt.Fprintf(output, "location = %s/%s {\n", urlPrefix, route.url)
		writePolicy()
		fmt.Fprintf(output, "    alias %s;\n", nginxQuote(route.source))
		output.WriteString("}\n")
	case nginxPrefixRoute:
		fmt.Fprintf(output, "location ^~ %s/%s/ {\n", urlPrefix, route.url)
		writePolicy()
		fmt.Fprintf(output, "    alias %s;\n", nginxQuote(route.source+string(filepath.Separator)))
		output.WriteString("}\n")
	case nginxGenerationRoute:
		literal := regexp.QuoteMeta(route.url)
		fmt.Fprintf(output, "location ~ \"^%s/_sow/v1/g/([0-9]{20})/%s/%s$\" {\n", urlPrefix, literal, nginxGenerationTailPattern)
		writePolicy()
		generationRoot := filepath.Join(root, "_sow", "v1", "g") + string(filepath.Separator)
		generationMiddle := string(filepath.Separator) + filepath.FromSlash(route.url) + string(filepath.Separator)
		fmt.Fprintf(output, "    alias \"%s$1%s$2\";\n", nginxEscape(generationRoot), nginxEscape(generationMiddle))
		output.WriteString("}\n")
	}
}

func validateNginxRouteSet(routes []nginxRoute) error {
	claims := make(map[string]nginxRouteKind, len(routes))
	for _, route := range routes {
		key := fmt.Sprintf("%d\x00%s", route.kind, route.url)
		if _, duplicate := claims[key]; duplicate {
			return fmt.Errorf("Nginx include route %q is duplicated", route.url)
		}
		claims[key] = route.kind
	}
	return nil
}

func validateNginxRoutePath(value string) error {
	if value == "" || strings.HasPrefix(value, "/") || path.Clean(value) != value || strings.Contains(value, "//") {
		return fmt.Errorf("unsafe Nginx route %q", value)
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._-/", character) {
			continue
		}
		return fmt.Errorf("unsafe character %q in Nginx route %q", character, value)
	}
	return nil
}

func cleanAbsoluteNginxPath(label, value string) (string, error) {
	if value == "" || !filepath.IsAbs(value) || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("%s must be a non-empty absolute path without control characters", label)
	}
	return filepath.Clean(value), nil
}

func cleanNginxPathResolvingExistingPrefix(label, value string) (string, error) {
	cleaned, err := cleanAbsoluteNginxPath(label, value)
	if err != nil {
		return "", err
	}
	candidate := cleaned
	missing := make([]string, 0, 4)
	for {
		resolved, resolveErr := filepath.EvalSymlinks(candidate)
		if resolveErr == nil {
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return resolved, nil
		}
		if !errors.Is(resolveErr, os.ErrNotExist) {
			return "", fmt.Errorf("%s has an unresolvable existing path prefix: %w", label, resolveErr)
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return "", fmt.Errorf("%s has no resolvable path prefix", label)
		}
		missing = append(missing, filepath.Base(candidate))
		candidate = parent
	}
}

func resolveNginxRegularFile(label, value string) (string, error) {
	cleaned, err := cleanAbsoluteNginxPath(label, value)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(cleaned)
	if err != nil {
		return "", fmt.Errorf("%s must be an existing exact regular file: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s must be an existing exact regular non-symlink file", label)
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", fmt.Errorf("%s has an unresolvable path ancestor: %w", label, err)
	}
	return resolved, nil
}

func pathContains(root, candidate string) bool {
	root, rootErr := filepath.Abs(filepath.Clean(root))
	candidate, candidateErr := filepath.Abs(filepath.Clean(candidate))
	if rootErr != nil || candidateErr != nil {
		return false
	}
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func nginxQuote(value string) string {
	return `"` + nginxEscape(value) + `"`
}

func nginxEscape(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`)
	return replacer.Replace(value)
}

func nginxViewIncludesRepo(view config.View, repo string) bool {
	return len(view.Repos) == 0 || containsNginxValue(view.Repos, repo)
}

func containsNginxValue(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
