// Command cleandelivery builds and verifies the deterministic SOW operator
// source archive. It deliberately uses only the Go standard library so the
// same gate runs on Linux and macOS without GNU tar/find extensions.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

//go:embed product-files.txt delivery-extra-files.txt
var policyFiles embed.FS

const (
	productListName  = "product-files.txt"
	deliveryListName = "delivery-extra-files.txt"
	productManifest  = "PRODUCT-SOURCE.sha256"
	deliveryManifest = "DELIVERY-CONTENT.sha256"
)

var (
	productRoots          = []string{".github", "cmd", "edge", "internal", "test", "third_party"}
	deliveryRoots         = append(append([]string{}, productRoots...), "docs")
	markdownInlineLink    = regexp.MustCompile(`!?\[[^\]]*\]\(([^)]+)\)`)
	markdownReference     = regexp.MustCompile(`(?m)^\s*\[[^\]]+\]:\s*(\S+)`)
	highConfidenceSecrets = []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{name: "private key block", pattern: regexp.MustCompile(`^\s*-----BEGIN (?:PGP |RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----\r?\n?$`)},
		{name: "AWS long-lived access key ID", pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{name: "AWS temporary access key ID", pattern: regexp.MustCompile(`ASIA[0-9A-Z]{16}`)},
		{name: "Tencent Cloud secret ID", pattern: regexp.MustCompile(`AKID[0-9A-Za-z]{32}`)},
		{name: "GitHub classic token", pattern: regexp.MustCompile(`ghp_[0-9A-Za-z]{36}`)},
		{name: "GitHub fine-grained token", pattern: regexp.MustCompile(`github_pat_[0-9A-Za-z_]{20,}`)},
		{name: "Slack token", pattern: regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{20,}`)},
		{name: "Stripe live secret key", pattern: regexp.MustCompile(`sk_live_[0-9A-Za-z]{16,}`)},
	}
	providerSecretAssignment = regexp.MustCompile(`(?i)["']?(?:aws_secret_access_key|aws_session_token|r2_secret_access_key|cloudflare_api_token|cloudflare_api_key|cf_api_token|tencentcloud_secret_key|tencent_secret_key|cos_secret_key|sow_cos_secret_key|sow_cos_session_token|sow_origin_bearer|sow_token_verifier_bearer|sow_real_edge_pro_token_[ab]|basic_password|secret_access_key|api_token|session_token|secret_key)["']?\s*[:=]\s*["']?([0-9A-Za-z+/=_:.-]{16,})`)
)

type policy struct {
	product  []string
	delivery []string
}

type buildResult struct {
	productDigest  string
	productFiles   int
	deliveryDigest string
	deliveryFiles  int
	archiveDigest  string
	archivePath    string
}

func main() {
	rootFlag := flag.String("root", ".", "repository root")
	outFlag := flag.String("out", "", "archive output directory")
	flag.Parse()

	root, err := filepath.Abs(*rootFlag)
	if err != nil {
		fatal(err)
	}
	out := *outFlag
	if out == "" {
		out = filepath.Join(os.TempDir(), "sow-clean-delivery")
	}
	out, err = filepath.Abs(out)
	if err != nil {
		fatal(err)
	}

	result, err := build(root, out)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("PRODUCT_SOURCE_SHA256=%s\n", result.productDigest)
	fmt.Printf("PRODUCT_SOURCE_FILES=%d\n", result.productFiles)
	fmt.Printf("DELIVERY_CONTENT_SHA256=%s\n", result.deliveryDigest)
	fmt.Printf("DELIVERY_FILES=%d\n", result.deliveryFiles)
	fmt.Printf("ARCHIVE_SHA256=%s\n", result.archiveDigest)
	fmt.Printf("ARCHIVE=%s\n", result.archivePath)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "clean delivery: %v\n", err)
	os.Exit(1)
}

func loadPolicy() (policy, error) {
	productRaw, err := policyFiles.ReadFile(productListName)
	if err != nil {
		return policy{}, err
	}
	extraRaw, err := policyFiles.ReadFile(deliveryListName)
	if err != nil {
		return policy{}, err
	}
	product, err := parsePathList(productListName, productRaw)
	if err != nil {
		return policy{}, err
	}
	extra, err := parsePathList(deliveryListName, extraRaw)
	if err != nil {
		return policy{}, err
	}
	delivery, err := sortedUnion(product, extra)
	if err != nil {
		return policy{}, fmt.Errorf("delivery allowlist: %w", err)
	}
	return policy{product: product, delivery: delivery}, nil
}

func parsePathList(name string, raw []byte) ([]string, error) {
	var result []string
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	line := 0
	previous := ""
	for scanner.Scan() {
		line++
		item := scanner.Text()
		if err := validateReleasePath(item); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, line, err)
		}
		if previous != "" && item <= previous {
			return nil, fmt.Errorf("%s:%d: paths must be unique and bytewise sorted", name, line)
		}
		previous = item
		result = append(result, item)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("%s is empty", name)
	}
	return result, nil
}

func sortedUnion(first, second []string) ([]string, error) {
	seen := make(map[string]struct{}, len(first)+len(second))
	result := make([]string, 0, len(first)+len(second))
	for _, list := range [][]string{first, second} {
		for _, item := range list {
			if _, exists := seen[item]; exists {
				return nil, fmt.Errorf("path appears in both allowlists: %s", item)
			}
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result, nil
}

func validateReleasePath(item string) error {
	if item == "" || item != filepath.ToSlash(item) || path.Clean(item) != item || strings.HasPrefix(item, "/") || item == "." || item == ".." || strings.HasPrefix(item, "../") {
		return fmt.Errorf("unsafe release path %q", item)
	}
	for _, r := range item {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("control character in release path %q", item)
		}
	}
	if suspiciousReleaseName(item) {
		return fmt.Errorf("secret/cache-like path is forbidden: %s", item)
	}
	return nil
}

func suspiciousReleaseName(item string) bool {
	components := strings.Split(strings.ToLower(item), "/")
	for _, component := range components {
		switch component {
		case ".git", ".hg", ".svn", ".cache", "__pycache__", "node_modules", ".idea", ".vscode":
			return true
		}
		if component == ".env" || strings.HasPrefix(component, ".env.") ||
			component == ".netrc" || component == ".npmrc" ||
			component == "credentials" || strings.HasPrefix(component, "credentials.") ||
			component == "secret" || strings.HasPrefix(component, "secret.") ||
			component == "token" || strings.HasPrefix(component, "token.") ||
			strings.HasSuffix(component, ".pem") || strings.HasSuffix(component, ".key") ||
			strings.HasSuffix(component, ".p12") || strings.HasSuffix(component, ".pfx") ||
			strings.HasSuffix(component, ".jks") || strings.HasSuffix(component, ".swp") ||
			strings.HasSuffix(component, ".swo") || strings.HasSuffix(component, "~") ||
			component == ".ds_store" {
			return true
		}
	}
	return false
}

func build(root, out string) (buildResult, error) {
	if err := validateOutputLocation(root, out); err != nil {
		return buildResult{}, err
	}
	p, err := loadPolicy()
	if err != nil {
		return buildResult{}, err
	}
	if err := auditSource(root, productRoots, p.product); err != nil {
		return buildResult{}, fmt.Errorf("product allowlist: %w", err)
	}
	if err := auditSource(root, deliveryRoots, p.delivery); err != nil {
		return buildResult{}, fmt.Errorf("delivery allowlist: %w", err)
	}
	if err := auditAllowedContent(root, p.delivery); err != nil {
		return buildResult{}, fmt.Errorf("delivery content: %w", err)
	}

	work, err := os.MkdirTemp("", "sow-clean-delivery-")
	if err != nil {
		return buildResult{}, err
	}
	defer os.RemoveAll(work)
	env, err := isolatedGoEnvironment(work)
	if err != nil {
		return buildResult{}, err
	}

	before, err := hashAllowedFiles(root, p.delivery)
	if err != nil {
		return buildResult{}, err
	}
	if err := runCheckedCommand(root, env, func() error {
		return auditAndCompare(root, deliveryRoots, p.delivery, before)
	}, "go", "mod", "tidy", "-diff"); err != nil {
		return buildResult{}, err
	}

	productBytes, err := manifestBytes(root, p.product)
	if err != nil {
		return buildResult{}, err
	}
	deliveryBytes, err := manifestBytes(root, p.delivery)
	if err != nil {
		return buildResult{}, err
	}
	productDigest := digestBytes(productBytes)
	deliveryDigest := digestBytes(deliveryBytes)

	virtual := map[string][]byte{
		productManifest:  productBytes,
		deliveryManifest: deliveryBytes,
	}
	first := filepath.Join(work, "delivery-1.tgz")
	second := filepath.Join(work, "delivery-2.tgz")
	if err := writeDeterministicArchive(first, root, p.delivery, virtual); err != nil {
		return buildResult{}, err
	}
	if err := writeDeterministicArchive(second, root, p.delivery, virtual); err != nil {
		return buildResult{}, err
	}
	archiveDigest, err := compareFilesExact(first, second)
	if err != nil {
		return buildResult{}, fmt.Errorf("archive reproducibility: %w", err)
	}

	for index, archive := range []string{first, second} {
		extract := filepath.Join(work, fmt.Sprintf("extract-%d", index+1))
		if err := extractAndValidate(archive, extract, p.delivery, virtual); err != nil {
			return buildResult{}, fmt.Errorf("extract delivery %d: %w", index+1, err)
		}
		verifyExtract := func() error {
			if err := auditExtracted(extract, p.delivery, virtual); err != nil {
				return err
			}
			if err := auditAllowedContent(extract, p.delivery); err != nil {
				return fmt.Errorf("extracted delivery content: %w", err)
			}
			if err := verifyManifest(extract, productBytes); err != nil {
				return fmt.Errorf("product manifest: %w", err)
			}
			if err := verifyManifest(extract, deliveryBytes); err != nil {
				return fmt.Errorf("delivery manifest: %w", err)
			}
			return checkMarkdownLinks(extract, p.delivery)
		}
		if err := verifyExtract(); err != nil {
			return buildResult{}, fmt.Errorf("verify delivery %d: %w", index+1, err)
		}

		binary := filepath.Join(work, fmt.Sprintf("sow-%d", index+1))
		commands := [][]string{
			{"go", "mod", "tidy", "-diff"},
			{"go", "mod", "download"},
			{"go", "mod", "verify"},
			{"bash", "third_party/cavaliergopher-rpm/verify-upstream.sh"},
			{"go", "test", "-count=1", "./test/compat/cleandelivery"},
			{"go", "test", "-count=1", "./internal/config", "-run", "TestExampleConfigMatchesSchema|TestShippedPGDGUpstreamExampleMatchesSchema"},
			{"go", "test", "-timeout", "15m", "-count=1", "./test/compat", "-run", "^TestShippedExampleSupportsCleanRoomLocalMVP$"},
			{"go", "build", "-trimpath", "-o", binary, "./cmd/sow"},
		}
		for _, command := range commands {
			if err := runCheckedCommand(extract, env, verifyExtract, command[0], command[1:]...); err != nil {
				return buildResult{}, fmt.Errorf("delivery %d: %w", index+1, err)
			}
		}
		for _, arguments := range [][]string{{"--help"}, {"version"}} {
			if err := runCheckedCommand(extract, env, verifyExtract, binary, arguments...); err != nil {
				return buildResult{}, fmt.Errorf("delivery %d: %w", index+1, err)
			}
		}
		if err := verifyExtract(); err != nil {
			return buildResult{}, err
		}
	}

	if err := auditAndCompare(root, deliveryRoots, p.delivery, before); err != nil {
		return buildResult{}, fmt.Errorf("source changed during clean build: %w", err)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return buildResult{}, err
	}
	// Re-resolve after creation so a pre-existing or concurrently introduced
	// symlinked ancestor cannot redirect the final archive into the source tree.
	if err := validateOutputLocation(root, out); err != nil {
		return buildResult{}, err
	}
	finalArchive := filepath.Join(out, fmt.Sprintf("sow-delivery-%s.tgz", deliveryDigest[:16]))
	if err := copyFileAtomic(first, finalArchive, 0o644); err != nil {
		return buildResult{}, err
	}
	finalDigest, err := digestFile(finalArchive)
	if err != nil {
		return buildResult{}, err
	}
	if finalDigest != archiveDigest {
		return buildResult{}, errors.New("installed archive differs from verified archive")
	}
	return buildResult{
		productDigest: productDigest, productFiles: len(p.product),
		deliveryDigest: deliveryDigest, deliveryFiles: len(p.delivery),
		archiveDigest: archiveDigest, archivePath: finalArchive,
	}, nil
}

func auditSource(root string, managedRoots, allowed []string) error {
	resolvedRoot, err := validateRepositoryRoot(root)
	if err != nil {
		return err
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, item := range allowed {
		allowedSet[item] = struct{}{}
	}
	for _, managed := range managedRoots {
		if err := validateRepositoryPath(root, resolvedRoot, managed, true); err != nil {
			return fmt.Errorf("managed root %s: %w", managed, err)
		}
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(managed)), func(full string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(root, full)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if rel == managed {
				return nil
			}
			// The edge dependency tree is a managed build input, never a release
			// input. This is the only ignored directory; every other cache-like
			// name remains a hard failure below.
			if entry.IsDir() && rel == "edge/node_modules" {
				return filepath.SkipDir
			}
			if suspiciousReleaseName(rel) {
				return fmt.Errorf("secret/cache-like path found: %s", rel)
			}
			info, err := os.Lstat(full)
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("symlink is forbidden: %s", rel)
			}
			if info.IsDir() {
				if !hasAllowedDescendant(rel, allowedSet) {
					return fmt.Errorf("unexpected directory: %s", rel)
				}
				return nil
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("non-regular path is forbidden: %s", rel)
			}
			if _, ok := allowedSet[rel]; !ok {
				return fmt.Errorf("unexpected regular file: %s", rel)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	for _, item := range allowed {
		if err := validateRepositoryPath(root, resolvedRoot, item, false); err != nil {
			return fmt.Errorf("allowlisted path %s: %w", item, err)
		}
	}
	return nil
}

func validateRepositoryRoot(root string) (string, error) {
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("repository root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("repository root is a symlink")
	}
	if !info.IsDir() {
		return "", errors.New("repository root is not a directory")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve repository root: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve repository root: %w", err)
	}
	return filepath.Clean(resolved), nil
}

func validateRepositoryPath(root, resolvedRoot, item string, wantDirectory bool) error {
	if err := validateReleasePath(item); err != nil {
		return err
	}
	components := strings.Split(item, "/")
	current := filepath.Clean(root)
	for index, component := range components {
		current = filepath.Join(current, filepath.FromSlash(component))
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink component is forbidden: %s", strings.Join(components[:index+1], "/"))
		}
		isLeaf := index == len(components)-1
		if !isLeaf || wantDirectory {
			if !info.IsDir() {
				return fmt.Errorf("path component is not a directory: %s", strings.Join(components[:index+1], "/"))
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return errors.New("allowlisted path is not a regular file")
		}
	}
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	if !pathWithin(resolvedRoot, resolved) {
		return fmt.Errorf("resolved path escapes repository: %s", item)
	}
	return nil
}

func auditAllowedContent(root string, allowed []string) error {
	for _, item := range allowed {
		file, err := os.Open(filepath.Join(root, filepath.FromSlash(item)))
		if err != nil {
			return fmt.Errorf("scan %s: %w", item, err)
		}
		reader := bufio.NewReader(file)
		lineNumber := 0
		for {
			line, readErr := reader.ReadBytes('\n')
			if len(line) > 0 {
				lineNumber++
				for _, secret := range highConfidenceSecrets {
					for _, match := range secret.pattern.FindAll(line, -1) {
						if explicitSecretPlaceholder(string(match)) {
							continue
						}
						_ = file.Close()
						return fmt.Errorf("%s:%d: high-confidence %s detected", item, lineNumber, secret.name)
					}
				}
				for _, match := range providerSecretAssignment.FindAllSubmatch(line, -1) {
					if len(match) == 2 && !explicitSecretPlaceholder(string(match[1])) {
						_ = file.Close()
						return fmt.Errorf("%s:%d: high-confidence provider secret assignment detected", item, lineNumber)
					}
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = file.Close()
				return fmt.Errorf("scan %s: %w", item, readErr)
			}
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("scan %s: %w", item, err)
		}
	}
	return nil
}

func explicitSecretPlaceholder(value string) bool {
	value = strings.ToLower(value)
	for _, marker := range []string{
		"example", "placeholder", "replace-with", "contract-test", "contract-secret",
		"test-only", "tests-only", "fixture", "dummy", "redacted", "changeme", "not-a-secret", "verifier-secret", "private-password",
	} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func hasAllowedDescendant(directory string, allowed map[string]struct{}) bool {
	prefix := directory + "/"
	for item := range allowed {
		if strings.HasPrefix(item, prefix) {
			return true
		}
	}
	return false
}

func hashAllowedFiles(root string, allowed []string) (map[string]string, error) {
	result := make(map[string]string, len(allowed))
	for _, item := range allowed {
		digest, err := digestFile(filepath.Join(root, filepath.FromSlash(item)))
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", item, err)
		}
		result[item] = digest
	}
	return result, nil
}

func auditAndCompare(root string, roots, allowed []string, expected map[string]string) error {
	if err := auditSource(root, roots, allowed); err != nil {
		return err
	}
	actual, err := hashAllowedFiles(root, allowed)
	if err != nil {
		return err
	}
	for item, digest := range expected {
		if actual[item] != digest {
			return fmt.Errorf("file changed: %s", item)
		}
	}
	return nil
}

func manifestBytes(root string, allowed []string) ([]byte, error) {
	var result bytes.Buffer
	for _, item := range allowed {
		digest, err := digestFile(filepath.Join(root, filepath.FromSlash(item)))
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", item, err)
		}
		fmt.Fprintf(&result, "%s  %s\n", digest, item)
	}
	return result.Bytes(), nil
}

func verifyManifest(root string, raw []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 67 || line[64:66] != "  " {
			return fmt.Errorf("malformed manifest line")
		}
		expected := line[:64]
		if _, err := hex.DecodeString(expected); err != nil {
			return fmt.Errorf("malformed digest: %w", err)
		}
		item := line[66:]
		if err := validateReleasePath(item); err != nil {
			return err
		}
		actual, err := digestFile(filepath.Join(root, filepath.FromSlash(item)))
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("checksum mismatch: %s", item)
		}
	}
	return scanner.Err()
}

func writeDeterministicArchive(destination, root string, allowed []string, virtual map[string][]byte) (returnErr error) {
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); returnErr == nil && err != nil {
			returnErr = err
		}
	}()
	gz, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return err
	}
	gz.Header.ModTime = time.Unix(0, 0).UTC()
	gz.Header.OS = 255
	tw := tar.NewWriter(gz)
	items := append([]string{}, allowed...)
	for item := range virtual {
		items = append(items, item)
	}
	sort.Strings(items)
	for _, item := range items {
		var size int64
		var reader io.Reader
		var closer io.Closer
		if raw, ok := virtual[item]; ok {
			size = int64(len(raw))
			reader = bytes.NewReader(raw)
		} else {
			input, err := os.Open(filepath.Join(root, filepath.FromSlash(item)))
			if err != nil {
				return err
			}
			info, err := input.Stat()
			if err != nil {
				_ = input.Close()
				return err
			}
			size = info.Size()
			reader = input
			closer = input
		}
		header := &tar.Header{
			Name: item, Mode: canonicalMode(item), Size: size,
			Uid: 0, Gid: 0, ModTime: time.Unix(0, 0).UTC(),
			Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(header); err != nil {
			if closer != nil {
				_ = closer.Close()
			}
			return fmt.Errorf("archive %s: %w", item, err)
		}
		if _, err := io.Copy(tw, reader); err != nil {
			if closer != nil {
				_ = closer.Close()
			}
			return fmt.Errorf("archive %s: %w", item, err)
		}
		if closer != nil {
			if err := closer.Close(); err != nil {
				return err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return file.Sync()
}

func canonicalMode(item string) int64 {
	if strings.HasSuffix(item, ".sh") {
		return 0o755
	}
	return 0o644
}

func extractAndValidate(archive, destination string, allowed []string, virtual map[string][]byte) error {
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return err
	}
	input, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer input.Close()
	gz, err := gzip.NewReader(input)
	if err != nil {
		return err
	}
	defer gz.Close()
	// RFC 1952 encodes an mtime of zero as the canonical "not available"
	// value, which Go exposes as the zero time when reading it back.
	if (!gz.Header.ModTime.IsZero() && !gz.Header.ModTime.Equal(time.Unix(0, 0).UTC())) || gz.Header.Name != "" || gz.Header.Comment != "" {
		return errors.New("non-canonical gzip header")
	}
	expected := append([]string{}, allowed...)
	for item := range virtual {
		expected = append(expected, item)
	}
	sort.Strings(expected)
	tr := tar.NewReader(gz)
	index := 0
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if index >= len(expected) || header.Name != expected[index] {
			return fmt.Errorf("archive path/order mismatch at %q", header.Name)
		}
		index++
		if header.Typeflag != tar.TypeReg || header.Mode != canonicalMode(header.Name) || header.Uid != 0 || header.Gid != 0 || !header.ModTime.Equal(time.Unix(0, 0).UTC()) {
			return fmt.Errorf("non-canonical tar metadata: %s", header.Name)
		}
		destinationPath := filepath.Join(destination, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(destinationPath), 0o755); err != nil {
			return err
		}
		output, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fs.FileMode(header.Mode))
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, tr)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if index != len(expected) {
		return fmt.Errorf("archive contains %d paths; expected %d", index, len(expected))
	}
	return auditExtracted(destination, allowed, virtual)
}

func auditExtracted(root string, allowed []string, virtual map[string][]byte) error {
	expected := make(map[string]struct{}, len(allowed)+len(virtual))
	for _, item := range allowed {
		expected[item] = struct{}{}
	}
	for item, raw := range virtual {
		expected[item] = struct{}{}
		actual, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(item)))
		if err != nil || !bytes.Equal(actual, raw) {
			return fmt.Errorf("generated manifest changed: %s", item)
		}
	}
	seen := make(map[string]struct{}, len(expected))
	err := filepath.WalkDir(root, func(full string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if full == root {
			return nil
		}
		rel, err := filepath.Rel(root, full)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		info, err := os.Lstat(full)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("non-regular extracted path: %s", rel)
		}
		if info.IsDir() {
			if !hasAllowedDescendant(rel, expected) {
				return fmt.Errorf("unexpected extracted directory: %s", rel)
			}
			return nil
		}
		if _, ok := expected[rel]; !ok {
			return fmt.Errorf("unexpected extracted file: %s", rel)
		}
		seen[rel] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("extracted path set has %d files; expected %d", len(seen), len(expected))
	}
	return nil
}

func checkMarkdownLinks(root string, allowed []string) error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, item := range allowed {
		allowedSet[item] = struct{}{}
	}
	for _, item := range allowed {
		if strings.ToLower(path.Ext(item)) != ".md" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(item)))
		if err != nil {
			return err
		}
		matches := append(markdownInlineLink.FindAllSubmatch(raw, -1), markdownReference.FindAllSubmatch(raw, -1)...)
		for _, match := range matches {
			target := strings.TrimSpace(string(match[1]))
			if strings.HasPrefix(target, "<") {
				if end := strings.Index(target, ">"); end >= 0 {
					target = target[1:end]
				}
			} else if fields := strings.Fields(target); len(fields) > 0 {
				target = fields[0]
			}
			if target == "" || strings.HasPrefix(target, "#") || strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
				continue
			}
			parsed, err := url.Parse(target)
			if err != nil {
				return fmt.Errorf("%s: invalid Markdown link %q", item, target)
			}
			if parsed.Scheme != "" || parsed.Host != "" || parsed.Path == "" {
				continue
			}
			decoded, err := url.PathUnescape(parsed.Path)
			if err != nil {
				return fmt.Errorf("%s: invalid escaped Markdown link %q", item, target)
			}
			resolved := path.Clean(path.Join(path.Dir(item), decoded))
			if resolved == ".." || strings.HasPrefix(resolved, "../") {
				return fmt.Errorf("%s: Markdown link escapes delivery: %s", item, target)
			}
			if _, ok := allowedSet[resolved]; !ok && !hasAllowedDescendant(resolved, allowedSet) {
				return fmt.Errorf("%s: relative Markdown link is absent from delivery: %s", item, resolved)
			}
		}
	}
	return nil
}

func isolatedGoEnvironment(work string) ([]string, error) {
	directories := map[string]string{
		"HOME":           filepath.Join(work, "home"),
		"XDG_CACHE_HOME": filepath.Join(work, "xdg-cache"),
		"GOPATH":         filepath.Join(work, "gopath"),
		"GOMODCACHE":     filepath.Join(work, "gomodcache"),
		"GOCACHE":        filepath.Join(work, "gocache"),
		"TMPDIR":         filepath.Join(work, "tmp"),
	}
	for _, directory := range directories {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, err
		}
	}
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly",
		"CGO_ENABLED=0", "GOPRIVATE=", "GONOPROXY=", "GONOSUMDB=",
	}
	goProxy := strings.TrimSpace(os.Getenv("SOW_CLEAN_GOPROXY"))
	if goProxy == "" {
		goProxy = "https://proxy.golang.org,direct"
	}
	if strings.ContainsAny(goProxy, "\x00\r\n") {
		return nil, errors.New("SOW_CLEAN_GOPROXY contains a control character")
	}
	env = append(env, "GOPROXY="+goProxy)
	goSumDB := strings.TrimSpace(os.Getenv("SOW_CLEAN_GOSUMDB"))
	if goSumDB == "" {
		goSumDB = "sum.golang.org"
	}
	if strings.ContainsAny(goSumDB, "\x00\r\n") {
		return nil, errors.New("SOW_CLEAN_GOSUMDB contains a control character")
	}
	if strings.EqualFold(goSumDB, "off") {
		return nil, errors.New("SOW_CLEAN_GOSUMDB cannot disable checksum verification")
	}
	env = append(env, "GOSUMDB="+goSumDB)
	keys := make([]string, 0, len(directories))
	for key := range directories {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, key+"="+directories[key])
	}
	return env, nil
}

func runCheckedCommand(directory string, env []string, verify func() error, name string, arguments ...string) error {
	command := exec.Command(name, arguments...)
	command.Dir = directory
	command.Env = env
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(arguments, " "), err, bytes.TrimSpace(output))
	}
	if err := verify(); err != nil {
		return fmt.Errorf("after %s %s: %w", name, strings.Join(arguments, " "), err)
	}
	return nil
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func digestFile(name string) (string, error) {
	file, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func compareFilesExact(first, second string) (string, error) {
	firstRaw, err := os.ReadFile(first)
	if err != nil {
		return "", err
	}
	secondRaw, err := os.ReadFile(second)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(firstRaw, secondRaw) {
		return "", errors.New("two consecutive archives differ byte-for-byte")
	}
	return digestBytes(firstRaw), nil
}

func validateOutputLocation(root, out string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	out, err = filepath.Abs(out)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}
	root = filepath.Clean(root)
	out = filepath.Clean(out)
	if pathWithin(root, out) {
		return fmt.Errorf("output directory must be outside repository: %s", out)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	resolvedOut, err := resolveWithExistingAncestor(out)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}
	if pathWithin(resolvedRoot, resolvedOut) {
		return fmt.Errorf("resolved output directory must be outside repository: %s", resolvedOut)
	}
	return nil
}

func resolveWithExistingAncestor(name string) (string, error) {
	current := filepath.Clean(name)
	var missing []string
	for {
		_, err := os.Lstat(current)
		if err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			resolved, err = filepath.Abs(resolved)
			if err != nil {
				return "", err
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing ancestor for %s", name)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func pathWithin(parent, child string) bool {
	parent, err := filepath.Abs(parent)
	if err != nil {
		return false
	}
	child, err = filepath.Abs(child)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(child))
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func copyFileAtomic(source, destination string, mode fs.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	directory := filepath.Dir(destination)
	output, err := os.CreateTemp(directory, "."+filepath.Base(destination)+".tmp-*")
	if err != nil {
		return err
	}
	temporary := output.Name()
	installed := false
	defer func() {
		if !installed {
			_ = os.Remove(temporary)
		}
	}()
	if err := output.Chmod(mode); err != nil {
		_ = output.Close()
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return err
	}
	installed = true
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	syncErr := directoryHandle.Sync()
	closeErr := directoryHandle.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
