package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
	"github.com/pgsty/sow/internal/yumrepo"
	"gopkg.in/yaml.v3"
)

const (
	yumConsumerPreflightReceiptSchema = "sow-yum-consumer-preflight-receipt/v1"
	yumConsumerMapSchema              = "sow-pigsty-yum-consumer-map/v2"
	yumConsumerFilesSchema            = "sow-pigsty-yum-consumer-files/v1"
	yumConsumerTrustRoute             = "pkg/keys/rpm-trust.asc"
	yumConsumerMaximumInputBytes      = int64(16 << 20)
	yumConsumerMaximumReceiptBytes    = int64(16 << 20)
	yumConsumerMaximumValidity        = time.Hour
	yumConsumerDefaultValidity        = 15 * time.Minute
	yumConsumerMinimumValidity        = time.Second
	yumConsumerMaximumPointerBytes    = int64(4096)
	yumConsumerMaximumDefinitions     = 4096
	yumConsumerMaximumBindings        = 65536
	yumConsumerMaximumRegions         = 64
)

// Tests replace the client without weakening URL, redirect, byte, signature,
// package, or canonical-publication checks. Production leaves it nil.
var yumConsumerPreflightHTTPClient *http.Client
var yumConsumerPreflightNow = func() time.Time { return time.Now().UTC() }

type yumConsumerPreflightOptions struct {
	values      commonFlags
	staged      string
	mapFile     string
	inventory   string
	trustBundle string
	receipt     string
	confirm     string
	validFor    time.Duration
}

type yumConsumerMapEntry struct {
	Name                string
	ExpectedModule      string
	X8664Route          string
	AArch64Route        string
	ExpectedDefinitions int
}

type yumConsumerInventoryEntry struct {
	Path                string
	ExpectedDefinitions int
	Kind                string
}

type yumConsumerManifestEntry struct {
	Path   string
	Before string
	After  string
}

type yumConsumerBinding struct {
	File          string `json:"file"`
	Name          string `json:"name"`
	Region        string `json:"region"`
	Release       int    `json:"release"`
	Arch          string `json:"arch"`
	MirrorlistURL string `json:"mirrorlist_url"`
	TrustURL      string `json:"trust_url"`
}

type yumConsumerPublicationState struct {
	Target                    string `json:"target"`
	View                      string `json:"view"`
	Generation                uint64 `json:"generation"`
	GenerationSHA256          string `json:"generation_sha256"`
	CheckpointSHA256          string `json:"checkpoint_sha256"`
	PlanSHA256                string `json:"plan_sha256"`
	AggregateGeneration       uint64 `json:"aggregate_generation"`
	AggregateGenerationSHA256 string `json:"aggregate_generation_sha256"`
	AggregateCheckpointSHA256 string `json:"aggregate_checkpoint_sha256"`
	AggregatePlanSHA256       string `json:"aggregate_plan_sha256"`
}

type yumConsumerEndpointEvidence struct {
	Target            string `json:"target"`
	View              string `json:"view"`
	Repo              string `json:"repo"`
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	Compression       string `json:"compression"`
	MirrorlistURL     string `json:"mirrorlist_url"`
	GenerationURL     string `json:"generation_url"`
	TrustURL          string `json:"trust_url"`
	TranscriptSHA256  string `json:"transcript_sha256"`
	TranscriptSummary string `json:"transcript_summary"`
	MetadataObjects   int64  `json:"metadata_objects"`
	InstalledObjects  int64  `json:"installed_objects"`
	PackageName       string `json:"package_name"`
	PackageVersion    string `json:"package_version"`
	PackageSHA256     string `json:"package_sha256"`
}

type yumConsumerPreflightReceipt struct {
	Schema                 string                        `json:"schema"`
	PlanSHA256             string                        `json:"plan_sha256"`
	StagedManifestSHA256   string                        `json:"staged_manifest_sha256"`
	MapSHA256              string                        `json:"map_sha256"`
	InventorySHA256        string                        `json:"inventory_sha256"`
	ConfigSHA256           string                        `json:"config_sha256"`
	TrustBundleSHA256      string                        `json:"trust_bundle_sha256"`
	ConsumerDefinitions    int                           `json:"consumer_definitions"`
	ConsumerBindings       int                           `json:"consumer_bindings"`
	ConsumerBindingsSHA256 string                        `json:"consumer_bindings_sha256"`
	VerifiedAt             string                        `json:"verified_at"`
	ExpiresAt              string                        `json:"expires_at"`
	PublicationStates      []yumConsumerPublicationState `json:"publication_states"`
	Endpoints              []yumConsumerEndpointEvidence `json:"endpoints"`
}

type yumConsumerEndpointSpec struct {
	Target              string
	View                string
	Repo                string
	OS                  string
	Arch                string
	Compression         yumrepo.Compression
	BaseURL             string
	MirrorlistURL       string
	MirrorlistKey       string
	GenerationURL       string
	TrustURL            string
	MetadataFingerprint string
	Verifier            yumrepo.DetachedVerifier
	PackageKeyring      openpgp.KeyRing
}

type yumConsumerPrepared struct {
	cfg                   *config.Config
	canonical             *state.Store
	stagedRoot            string
	repositoryRoot        string
	repositoryIdentity    os.FileInfo
	receiptParent         string
	receiptParentIdentity os.FileInfo
	stagedIdentity        os.FileInfo
	manifest              []yumConsumerManifestEntry
	planSHA256            string
	stagedManifestSHA256  string
	mapSHA256             string
	inventorySHA256       string
	configSHA256          string
	trustBundleSHA256     string
	trustBundle           []byte
	repositoryTrustSHA256 string
	packageTrustSHA256    map[string]string
	definitions           int
	bindings              []yumConsumerBinding
	bindingsSHA256        string
	states                []yumConsumerPublicationState
	endpoints             []yumConsumerEndpointSpec
	verifiedAt            time.Time
}

func addYUMConsumerPreflightFlags(fs *flag.FlagSet, options *yumConsumerPreflightOptions, includeValidity bool) {
	fs.StringVar(&options.values.configPath, "config", "sow.yaml", "path to strict schema-v1 SOW configuration")
	fs.StringVar(&options.values.root, "root", "", "override repository root from config")
	fs.IntVar(&options.values.workers, "workers", min(runtime.NumCPU(), maxCLIWorkers), "bounded endpoint worker count (1-64)")
	fs.IntVar(&options.values.chunk, "chunk-entries", 4096, "entries per in-memory protocol-validation run")
	fs.BoolVar(&options.values.recover, "recover", false, "recover local canonical state before preflight")
	fs.StringVar(&options.staged, "staged", "", "reviewed Pigsty consumer stage directory outside the repository")
	fs.StringVar(&options.mapFile, "map", "", "reviewed Pigsty consumer map TSV")
	fs.StringVar(&options.inventory, "inventory", "", "reviewed Pigsty consumer file inventory TSV")
	fs.StringVar(&options.trustBundle, "trust-bundle", "", "public-only aggregate RPM/repository trust bundle")
	fs.StringVar(&options.receipt, "receipt", "", "durable preflight receipt outside the repository")
	fs.StringVar(&options.confirm, "confirm", "", "exact SHA-256 printed by consumer stage")
	if includeValidity {
		fs.DurationVar(&options.validFor, "valid-for", yumConsumerDefaultValidity, "receipt validity window (1s to 1h)")
	}
}

func validateYUMConsumerPreflightOptions(options yumConsumerPreflightOptions, includeValidity bool) error {
	if options.staged == "" || options.mapFile == "" || options.inventory == "" || options.trustBundle == "" || options.receipt == "" || options.confirm == "" {
		return errors.New("--staged, --map, --inventory, --trust-bundle, --receipt, and --confirm are required")
	}
	if !validLowerSHA256(options.confirm) {
		return errors.New("--confirm must be one lowercase SHA-256")
	}
	if includeValidity && (options.validFor < yumConsumerMinimumValidity || options.validFor > yumConsumerMaximumValidity) {
		return fmt.Errorf("--valid-for must be at least %s and no greater than %s", yumConsumerMinimumValidity, yumConsumerMaximumValidity)
	}
	return nil
}

func runYUMConsumerPreflight(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	fs := flag.NewFlagSet("compatibility yum-consumer-preflight", flag.ContinueOnError)
	fs.SetOutput(stderr)
	options := yumConsumerPreflightOptions{}
	addYUMConsumerPreflightFlags(fs, &options, true)
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow compatibility yum-consumer-preflight --staged DIR --map FILE --inventory FILE --trust-bundle FILE --receipt FILE --confirm SHA256 [--config sow.yaml]")
	}
	if help, err := parseFlagSet(fs, args); err != nil || help {
		return err
	}
	if fs.NArg() != 0 {
		return withExitCode(ExitUsage, "yum-consumer-preflight accepts no positional arguments")
	}
	if err := validateYUMConsumerPreflightOptions(options, true); err != nil {
		return withExitCode(ExitUsage, "%v", err)
	}
	prepared, lock, err := prepareYUMConsumerPreflight(ctx, options, stdout, stderr)
	if err != nil {
		return err
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	evidence, err := executeYUMConsumerEndpointPreflight(ctx, prepared, options.values.workers, options.values.chunk)
	if err != nil {
		if errors.Is(err, verify.ErrClientNetwork) {
			return withExitCode(ExitNetworkAuth, "YUM consumer endpoint preflight could not complete a public endpoint request")
		}
		return withExitCode(ExitVerification, "YUM consumer endpoint preflight rejected the staged route contract: %v", err)
	}
	if err := revalidateYUMConsumerRemoteClosure(ctx, prepared, options.values.workers); err != nil {
		if errors.Is(err, verify.ErrClientNetwork) {
			return withExitCode(ExitNetworkAuth, "YUM consumer endpoint closure could not be revalidated after protocol proof")
		}
		return withExitCode(ExitVerification, "YUM consumer remote endpoint changed after protocol proof: %v", err)
	}
	if err := prepared.validateLocalInputs(options); err != nil {
		return withExitCode(ExitConflict, "YUM consumer local inputs changed during endpoint preflight: %v", err)
	}
	// Receipt timestamps are canonical whole-second UTC. Use that exact expiry
	// for the completion gate as well; otherwise a fractional duration could
	// pass against 1.5s and then be serialized as an already-expired 1s token.
	expiresAt := prepared.verifiedAt.Add(options.validFor).UTC().Truncate(time.Second)
	completionTime := yumConsumerPreflightNow().UTC()
	if completionTime.Before(prepared.verifiedAt) || !completionTime.Before(expiresAt) {
		return withExitCode(ExitConflict, "YUM consumer endpoint proof outlived its receipt validity window")
	}
	receipt := prepared.receipt(prepared.verifiedAt, expiresAt, evidence)
	body, err := canonicalYUMConsumerReceipt(receipt)
	if err != nil {
		return withExitCode(ExitInternal, "encode YUM consumer preflight receipt: %v", err)
	}
	if err := requireCanonicalConfigBaseline(prepared.cfg, prepared.canonical); err != nil {
		return withExitCode(ExitConflict, "canonical config changed during YUM consumer endpoint preflight: %v", err)
	}
	if err := lock.Validate(); err != nil {
		return withExitCode(ExitConflict, "YUM consumer state lock changed during endpoint preflight: %v", err)
	}
	if err := installYUMConsumerReceipt(options.receipt, body, prepared.receiptParentIdentity); err != nil {
		return withExitCode(ExitConflict, "install YUM consumer preflight receipt: %v", err)
	}
	digest := sha256.Sum256(body)
	fmt.Fprintf(stdout, "preflight=pass endpoints=%d consumer_definitions=%d consumer_bindings=%d plan_sha256=%s receipt_sha256=%s expires_at=%s\n",
		len(evidence), prepared.definitions, len(prepared.bindings), prepared.planSHA256, hex.EncodeToString(digest[:]), receipt.ExpiresAt)
	return nil
}

func runYUMConsumerReceiptCheck(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	fs := flag.NewFlagSet("compatibility yum-consumer-receipt-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	options := yumConsumerPreflightOptions{}
	addYUMConsumerPreflightFlags(fs, &options, false)
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow compatibility yum-consumer-receipt-check --staged DIR --map FILE --inventory FILE --trust-bundle FILE --receipt FILE --confirm SHA256 [--config sow.yaml]")
	}
	if help, err := parseFlagSet(fs, args); err != nil || help {
		return err
	}
	if fs.NArg() != 0 {
		return withExitCode(ExitUsage, "yum-consumer-receipt-check accepts no positional arguments")
	}
	if err := validateYUMConsumerPreflightOptions(options, false); err != nil {
		return withExitCode(ExitUsage, "%v", err)
	}
	prepared, lock, err := prepareYUMConsumerPreflight(ctx, options, stdout, stderr)
	if err != nil {
		return err
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	body, err := readStableRegularLimited(options.receipt, yumConsumerMaximumReceiptBytes)
	if err != nil {
		return withExitCode(ExitConflict, "read YUM consumer preflight receipt: %v", err)
	}
	receipt, err := decodeYUMConsumerReceipt(body)
	if err != nil {
		return withExitCode(ExitConflict, "decode YUM consumer preflight receipt: %v", err)
	}
	if err := prepared.validateReceipt(receipt, yumConsumerPreflightNow().UTC()); err != nil {
		return withExitCode(ExitConflict, "YUM consumer preflight receipt is not current authority: %v", err)
	}
	if err := prepared.validateLocalInputs(options); err != nil {
		return withExitCode(ExitConflict, "YUM consumer local inputs changed during receipt validation: %v", err)
	}
	if err := lock.Validate(); err != nil {
		return withExitCode(ExitConflict, "YUM consumer state lock changed during receipt validation: %v", err)
	}
	digest := sha256.Sum256(body)
	fmt.Fprintf(stdout, "receipt=valid endpoints=%d consumer_definitions=%d consumer_bindings=%d plan_sha256=%s receipt_sha256=%s expires_at=%s\n",
		len(receipt.Endpoints), receipt.ConsumerDefinitions, receipt.ConsumerBindings, receipt.PlanSHA256, hex.EncodeToString(digest[:]), receipt.ExpiresAt)
	return nil
}

func canonicalYUMConsumerDirectory(filename string) (string, error) {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.Join(err, fmt.Errorf("%s is not a real directory", filename))
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func canonicalYUMConsumerDirectoryIdentity(filename string) (string, os.FileInfo, error) {
	canonical, err := canonicalYUMConsumerDirectory(filename)
	if err != nil {
		return "", nil, err
	}
	identity, err := os.Lstat(canonical)
	if err != nil || identity.Mode()&os.ModeSymlink != 0 || !identity.IsDir() {
		return "", nil, errors.Join(err, fmt.Errorf("%s has no stable directory identity", filename))
	}
	return canonical, identity, nil
}

func yumConsumerPathInside(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func safeYUMConsumerRelativePath(value string) bool {
	if value == "" || filepath.IsAbs(value) || strings.ContainsAny(value, "\\\x00\r\n\t") || filepath.ToSlash(filepath.Clean(value)) != value {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func readYUMConsumerStageFile(root, relative string) ([]byte, error) {
	if !safeYUMConsumerRelativePath(relative) {
		return nil, fmt.Errorf("unsafe staged path %q", relative)
	}
	current := root
	parts := strings.Split(relative, "/")
	for index, segment := range parts {
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.Join(err, fmt.Errorf("staged path %s contains a symlink or missing component", relative))
		}
		if index+1 < len(parts) && !info.IsDir() {
			return nil, fmt.Errorf("staged parent for %s is not a directory", relative)
		}
	}
	return readStableRegularLimited(current, yumConsumerMaximumInputBytes)
}

func splitYUMConsumerTSV(body []byte, schema string, columns int) ([][]string, error) {
	if len(body) == 0 || bytes.ContainsAny(body, "\x00\r") {
		return nil, errors.New("TSV is empty or contains forbidden bytes")
	}
	lines := strings.Split(string(body), "\n")
	schemaSeen := false
	var records [][]string
	for lineNumber, line := range lines {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if line == "# schema="+schema {
				if schemaSeen {
					return nil, errors.New("TSV repeats its schema marker")
				}
				schemaSeen = true
			}
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != columns {
			return nil, fmt.Errorf("TSV line %d has %d fields, want %d", lineNumber+1, len(fields), columns)
		}
		for _, field := range fields {
			if field == "" || strings.TrimSpace(field) != field {
				return nil, fmt.Errorf("TSV line %d contains an empty or non-canonical field", lineNumber+1)
			}
		}
		records = append(records, fields)
	}
	if !schemaSeen || len(records) == 0 {
		return nil, fmt.Errorf("TSV lacks schema %s or records", schema)
	}
	return records, nil
}

func validYUMConsumerSegment(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' || character == '$' {
			continue
		}
		return false
	}
	return true
}

func validateYUMConsumerRouteTemplate(value, arch string) error {
	if strings.Count(value, "$releasever") > 2 || strings.ReplaceAll(value, "$releasever", "") != strings.ReplaceAll(strings.ReplaceAll(value, "$releasever", ""), "$", "") {
		return fmt.Errorf("route %q has an unsupported placeholder", value)
	}
	parts := strings.Split(value, "/")
	if len(parts) != 3 || parts[2] != arch {
		return fmt.Errorf("route %q must be repo/os/%s", value, arch)
	}
	for _, part := range parts {
		if !validYUMConsumerSegment(part) {
			return fmt.Errorf("route %q has an invalid segment", value)
		}
	}
	return nil
}

func canonicalYUMConsumerModule(name string) string {
	switch name {
	case "pigsty-infra":
		return "infra"
	case "pigsty-pgsql":
		return "pgsql"
	case "percona":
		return "percona"
	case "wiltondb":
		return "mssql"
	default:
		return ""
	}
}

func parseYUMConsumerMap(body []byte) (map[string]yumConsumerMapEntry, int, error) {
	records, err := splitYUMConsumerTSV(body, yumConsumerMapSchema, 4)
	if err != nil {
		return nil, 0, err
	}
	result := make(map[string]yumConsumerMapEntry, len(records))
	total := 0
	for _, fields := range records {
		if !validYUMConsumerSegment(fields[0]) || strings.Contains(fields[0], "$") {
			return nil, 0, fmt.Errorf("invalid Pigsty consumer name %q", fields[0])
		}
		if strings.HasPrefix(fields[0], "epel") || strings.HasPrefix(fields[0], "pgdg") {
			return nil, 0, fmt.Errorf("consumer %s uses renderer-specific target_version semantics that map v2 cannot freeze", fields[0])
		}
		if err := validateYUMConsumerRouteTemplate(fields[1], "x86_64"); err != nil {
			return nil, 0, err
		}
		if err := validateYUMConsumerRouteTemplate(fields[2], "aarch64"); err != nil {
			return nil, 0, err
		}
		x86Releases := strings.Count(fields[1], "$releasever")
		armReleases := strings.Count(fields[2], "$releasever")
		if fields[0] == "pigsty-infra" {
			if x86Releases != 0 || armReleases != 0 {
				return nil, 0, errors.New("pigsty-infra must use release-independent frozen compatibility routes")
			}
		} else if x86Releases == 0 || armReleases == 0 || x86Releases != armReleases {
			return nil, 0, fmt.Errorf("ordinary consumer %s must use matching release-aware routes", fields[0])
		}
		expected, err := strconv.Atoi(fields[3])
		if err != nil || expected < 1 || expected > 1000 {
			return nil, 0, fmt.Errorf("invalid definition count for %s", fields[0])
		}
		if total > yumConsumerMaximumDefinitions-expected {
			return nil, 0, fmt.Errorf("consumer map exceeds %d reviewed definitions", yumConsumerMaximumDefinitions)
		}
		if _, duplicate := result[fields[0]]; duplicate {
			return nil, 0, fmt.Errorf("duplicate consumer map name %s", fields[0])
		}
		result[fields[0]] = yumConsumerMapEntry{Name: fields[0], ExpectedModule: canonicalYUMConsumerModule(fields[0]), X8664Route: fields[1], AArch64Route: fields[2], ExpectedDefinitions: expected}
		total += expected
	}
	return result, total, nil
}

func parseYUMConsumerInventory(body []byte) (map[string]yumConsumerInventoryEntry, error) {
	records, err := splitYUMConsumerTSV(body, yumConsumerFilesSchema, 3)
	if err != nil {
		return nil, err
	}
	result := make(map[string]yumConsumerInventoryEntry, len(records))
	for _, fields := range records {
		if !safeYUMConsumerRelativePath(fields[0]) || fields[2] != "consumer" && fields[2] != "renderer" {
			return nil, fmt.Errorf("invalid consumer inventory record %q", strings.Join(fields, "\t"))
		}
		expected, err := strconv.Atoi(fields[1])
		if err != nil || expected < 0 || expected > 1000 || fields[2] == "renderer" && expected != 0 || fields[2] == "consumer" && expected == 0 {
			return nil, fmt.Errorf("invalid inventory definition count for %s", fields[0])
		}
		if _, duplicate := result[fields[0]]; duplicate {
			return nil, fmt.Errorf("duplicate inventory path %s", fields[0])
		}
		result[fields[0]] = yumConsumerInventoryEntry{Path: fields[0], ExpectedDefinitions: expected, Kind: fields[2]}
	}
	return result, nil
}

func parseYUMConsumerManifest(body []byte, inventory map[string]yumConsumerInventoryEntry) ([]yumConsumerManifestEntry, error) {
	if len(body) == 0 || bytes.ContainsAny(body, "\x00\r") {
		return nil, errors.New("staged manifest is empty or contains forbidden bytes")
	}
	seen := make(map[string]struct{}, len(inventory))
	var result []yumConsumerManifestEntry
	for lineNumber, line := range strings.Split(string(body), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || !safeYUMConsumerRelativePath(fields[0]) || !validLowerSHA256(fields[1]) || !validLowerSHA256(fields[2]) {
			return nil, fmt.Errorf("invalid staged manifest line %d", lineNumber+1)
		}
		if _, allowed := inventory[fields[0]]; !allowed {
			return nil, fmt.Errorf("staged manifest contains unreviewed path %s", fields[0])
		}
		if _, duplicate := seen[fields[0]]; duplicate {
			return nil, fmt.Errorf("staged manifest repeats %s", fields[0])
		}
		seen[fields[0]] = struct{}{}
		result = append(result, yumConsumerManifestEntry{Path: fields[0], Before: fields[1], After: fields[2]})
	}
	if len(result) != len(inventory) {
		return nil, fmt.Errorf("staged manifest covers %d files, inventory requires %d", len(result), len(inventory))
	}
	return result, nil
}

func yumConsumerMappingValue(node *yaml.Node, key string) (*yaml.Node, error) {
	if node == nil || node.Kind != yaml.MappingNode || node.Tag != "!!map" || len(node.Content)%2 != 0 {
		return nil, errors.New("consumer definition is not a YAML mapping")
	}
	seen := make(map[string]struct{}, len(node.Content)/2)
	var result *yaml.Node
	for index := 0; index < len(node.Content); index += 2 {
		name := node.Content[index]
		if name.Kind != yaml.ScalarNode || name.Tag != "!!str" || name.Value == "" {
			return nil, errors.New("consumer definition has a non-string key")
		}
		if _, duplicate := seen[name.Value]; duplicate {
			return nil, fmt.Errorf("consumer definition repeats YAML key %s", name.Value)
		}
		seen[name.Value] = struct{}{}
		if name.Value == key {
			result = node.Content[index+1]
		}
	}
	return result, nil
}

func yumConsumerScalar(node *yaml.Node, subject string) (string, error) {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag != "!!str" || node.Value == "" || strings.TrimSpace(node.Value) != node.Value {
		return "", fmt.Errorf("%s must be one non-empty YAML string", subject)
	}
	return node.Value, nil
}

func yumConsumerDescription(node *yaml.Node) error {
	description, err := yumConsumerScalar(node, "description")
	if err != nil {
		return err
	}
	if len(description) > 256 {
		return errors.New("description exceeds 256 bytes")
	}
	for _, character := range description {
		if character < 0x20 || character == 0x7f {
			return errors.New("description contains a control character")
		}
	}
	return nil
}

func yumConsumerStringSequence(node *yaml.Node, subject string) ([]string, error) {
	if node == nil || node.Kind != yaml.SequenceNode || node.Tag != "!!seq" || len(node.Content) == 0 {
		return nil, fmt.Errorf("%s must be a non-empty YAML sequence", subject)
	}
	seen := make(map[string]struct{}, len(node.Content))
	result := make([]string, 0, len(node.Content))
	for _, child := range node.Content {
		value, err := yumConsumerScalar(child, subject)
		if err != nil || value != "x86_64" && value != "aarch64" {
			return nil, errors.Join(err, fmt.Errorf("%s contains unsupported architecture", subject))
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, fmt.Errorf("%s contains duplicate %s", subject, value)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func yumConsumerReleaseSequence(node *yaml.Node) ([]int, error) {
	if node == nil || node.Kind != yaml.SequenceNode || node.Tag != "!!seq" || len(node.Content) == 0 {
		return nil, errors.New("releases must be a non-empty YAML sequence")
	}
	seen := make(map[int]struct{}, len(node.Content))
	result := make([]int, 0, len(node.Content))
	for _, child := range node.Content {
		if child.Kind != yaml.ScalarNode || child.Tag != "!!int" {
			return nil, errors.New("releases must contain integers")
		}
		value, err := strconv.Atoi(child.Value)
		if err != nil || value < 7 || value > 10 {
			return nil, errors.New("releases contains an unsupported EL major")
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, fmt.Errorf("releases contains duplicate EL%d", value)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func yumConsumerStringMap(node *yaml.Node, subject string) (map[string]string, error) {
	if node == nil || node.Kind != yaml.MappingNode || node.Tag != "!!map" || len(node.Content) == 0 || len(node.Content)%2 != 0 {
		return nil, fmt.Errorf("%s must be a non-empty YAML mapping", subject)
	}
	if len(node.Content)/2 > yumConsumerMaximumRegions {
		return nil, fmt.Errorf("%s exceeds %d entries", subject, yumConsumerMaximumRegions)
	}
	result := make(map[string]string, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		key, err := yumConsumerScalar(node.Content[index], subject+" key")
		if err != nil || !validYUMConsumerSegment(key) || strings.Contains(key, "$") {
			return nil, errors.Join(err, fmt.Errorf("%s contains an invalid key", subject))
		}
		value, err := yumConsumerScalar(node.Content[index+1], subject+" value")
		if err != nil {
			return nil, err
		}
		if _, duplicate := result[key]; duplicate {
			return nil, fmt.Errorf("%s repeats region %s", subject, key)
		}
		result[key] = value
	}
	return result, nil
}

func yumConsumerMirrorlistMap(node *yaml.Node) (map[string]map[string]string, error) {
	if node == nil || node.Kind != yaml.MappingNode || node.Tag != "!!map" || len(node.Content) == 0 || len(node.Content)%2 != 0 {
		return nil, errors.New("mirrorlist must be a non-empty region mapping")
	}
	if len(node.Content)/2 > yumConsumerMaximumRegions {
		return nil, fmt.Errorf("mirrorlist exceeds %d regions", yumConsumerMaximumRegions)
	}
	result := make(map[string]map[string]string, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		region, err := yumConsumerScalar(node.Content[index], "mirrorlist region")
		if err != nil || !validYUMConsumerSegment(region) || strings.Contains(region, "$") {
			return nil, errors.Join(err, errors.New("mirrorlist has an invalid region"))
		}
		arches, err := yumConsumerStringMap(node.Content[index+1], "mirrorlist "+region)
		if err != nil {
			return nil, err
		}
		for arch := range arches {
			if arch != "x86_64" && arch != "aarch64" {
				return nil, fmt.Errorf("mirrorlist region %s contains unsupported architecture %s", region, arch)
			}
		}
		if _, duplicate := result[region]; duplicate {
			return nil, fmt.Errorf("mirrorlist repeats region %s", region)
		}
		result[region] = arches
	}
	return result, nil
}

func yumConsumerMetaIsStrict(node *yaml.Node) error {
	if node == nil || node.Kind != yaml.MappingNode || node.Tag != "!!map" || len(node.Content)%2 != 0 {
		return errors.New("meta must be a YAML mapping")
	}
	wanted := map[string]bool{"gpgcheck": false, "repo_gpgcheck": false}
	forbidden := map[string]struct{}{
		"baseurl": {}, "mirrorlist": {}, "metalink": {}, "gpgkey": {}, "enabled": {}, "sslverify": {},
	}
	seen := make(map[string]struct{}, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index]
		value := node.Content[index+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return errors.New("meta contains a non-string key")
		}
		if _, duplicate := seen[key.Value]; duplicate {
			return fmt.Errorf("meta repeats YAML key %s", key.Value)
		}
		seen[key.Value] = struct{}{}
		if _, unsafe := forbidden[key.Value]; unsafe {
			return fmt.Errorf("meta.%s cannot override the reviewed route or trust policy", key.Value)
		}
		if _, required := wanted[key.Value]; !required {
			continue
		}
		if wanted[key.Value] || value.Kind != yaml.ScalarNode || value.Tag != "!!int" || value.Value != "1" {
			return fmt.Errorf("meta.%s must be integer 1 exactly once", key.Value)
		}
		wanted[key.Value] = true
	}
	for key, present := range wanted {
		if !present {
			return fmt.Errorf("meta.%s is required", key)
		}
	}
	return nil
}

func yumConsumerNodeContainsManagedRawURL(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		if yumConsumerManagedRawURL(node.Value) {
			return true
		}
	}
	for _, child := range node.Content {
		if yumConsumerNodeContainsManagedRawURL(child) {
			return true
		}
	}
	return false
}

func yumConsumerManagedRawURL(value string) bool {
	trimmed := strings.TrimSpace(value)
	parsed, err := url.Parse(trimmed)
	if err == nil && (strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https")) {
		host := strings.ToLower(parsed.Hostname())
		managedHost := strings.HasPrefix(host, "repo.pigsty.") || strings.HasPrefix(host, "beta.pigsty.")
		if managedHost && (parsed.Path == "/yum" || strings.HasPrefix(parsed.Path, "/yum/")) {
			return true
		}
	}
	// Retain fail-closed detection for templated/non-canonical YAML strings
	// that are not standalone parseable URLs. Percent-encoded path separators
	// are included because URL parsers expose them as /yum/... to clients.
	lower := strings.ToLower(trimmed)
	managedHost := strings.Contains(lower, "repo.pigsty.") || strings.Contains(lower, "beta.pigsty.")
	return managedHost && (strings.Contains(lower, "/yum/") || strings.HasSuffix(lower, "/yum") || strings.Contains(lower, "/yum%"))
}

func strictYUMConsumerHTTPSURL(raw string) (*url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.Contains(raw, "%") {
		return nil, errors.New("URL is empty, non-canonical, or percent encoded")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || parsed.Opaque != "" || parsed.Path == "" || path.Clean(parsed.Path) != parsed.Path {
		return nil, errors.Join(err, fmt.Errorf("URL %q is not strict credential-free HTTPS", raw))
	}
	if parsed.String() != raw {
		return nil, fmt.Errorf("URL %q is not canonical", raw)
	}
	return parsed, nil
}

func yumConsumerRouteTemplate(entry yumConsumerMapEntry, arch string) (string, error) {
	switch arch {
	case "x86_64":
		return entry.X8664Route, nil
	case "aarch64":
		return entry.AArch64Route, nil
	default:
		return "", fmt.Errorf("unsupported architecture %s", arch)
	}
}

func validateYUMConsumerMappedRoute(raw string, entry yumConsumerMapEntry, release int, arch string) error {
	parsed, err := strictYUMConsumerHTTPSURL(raw)
	if err != nil {
		return err
	}
	const marker = "/_sow/v1/mirrorlist/"
	if strings.Count(parsed.Path, marker) != 1 {
		return errors.New("mirrorlist URL has no unique SOW route marker")
	}
	remainder := strings.SplitN(parsed.Path, marker, 2)[1]
	viewName, coordinate, found := strings.Cut(remainder, "/")
	if !found || viewName != "latest" && viewName != "beta" {
		return errors.New("mirrorlist URL must select latest or beta")
	}
	template, err := yumConsumerRouteTemplate(entry, arch)
	if err != nil {
		return err
	}
	wanted := strings.ReplaceAll(template, "$releasever", strconv.Itoa(release)) + ".txt"
	if coordinate != wanted {
		return fmt.Errorf("mirrorlist route %s does not match reviewed route %s", coordinate, wanted)
	}
	return nil
}

func bindingsFromYUMConsumerDefinition(file string, node *yaml.Node, entry yumConsumerMapEntry) ([]yumConsumerBinding, error) {
	minorNode, err := yumConsumerMappingValue(node, "minor")
	if err != nil {
		return nil, err
	}
	if minorNode != nil {
		return nil, errors.New("mapped v2 consumer cannot use renderer-specific minor target_version semantics")
	}
	releasesNode, err := yumConsumerMappingValue(node, "releases")
	if err != nil {
		return nil, err
	}
	archesNode, err := yumConsumerMappingValue(node, "arch")
	if err != nil {
		return nil, err
	}
	mirrorlistNode, err := yumConsumerMappingValue(node, "mirrorlist")
	if err != nil {
		return nil, err
	}
	trustNode, err := yumConsumerMappingValue(node, "gpgkey")
	if err != nil {
		return nil, err
	}
	metaNode, err := yumConsumerMappingValue(node, "meta")
	if err != nil {
		return nil, err
	}
	releases, err := yumConsumerReleaseSequence(releasesNode)
	if err != nil {
		return nil, err
	}
	arches, err := yumConsumerStringSequence(archesNode, "arch")
	if err != nil {
		return nil, err
	}
	mirrorlists, err := yumConsumerMirrorlistMap(mirrorlistNode)
	if err != nil {
		return nil, err
	}
	trust, err := yumConsumerStringMap(trustNode, "gpgkey")
	if err != nil {
		return nil, err
	}
	if err := yumConsumerMetaIsStrict(metaNode); err != nil {
		return nil, err
	}
	if len(mirrorlists) != len(trust) {
		return nil, errors.New("mirrorlist and gpgkey region sets differ")
	}
	if _, exists := mirrorlists["default"]; !exists {
		return nil, errors.New("mirrorlist and gpgkey must include the default fallback region")
	}
	moduleNode, err := yumConsumerMappingValue(node, "module")
	if err != nil {
		return nil, err
	}
	module, err := yumConsumerScalar(moduleNode, "module")
	if err != nil || !validYUMConsumerSegment(module) || strings.Contains(module, "$") {
		return nil, errors.Join(err, errors.New("module must be one literal Pigsty module segment"))
	}
	if entry.ExpectedModule != "" && module != entry.ExpectedModule {
		return nil, fmt.Errorf("module %s differs from frozen %s module %s", module, entry.Name, entry.ExpectedModule)
	}
	descriptionNode, err := yumConsumerMappingValue(node, "description")
	if err != nil {
		return nil, err
	}
	if err := yumConsumerDescription(descriptionNode); err != nil {
		return nil, err
	}
	var result []yumConsumerBinding
	for region, byArch := range mirrorlists {
		trustURL, exists := trust[region]
		if !exists {
			return nil, fmt.Errorf("gpgkey lacks region %s", region)
		}
		if _, err := strictYUMConsumerHTTPSURL(trustURL); err != nil {
			return nil, fmt.Errorf("gpgkey region %s: %w", region, err)
		}
		for _, arch := range arches {
			templateURL, exists := byArch[arch]
			if !exists {
				return nil, fmt.Errorf("mirrorlist region %s lacks architecture %s", region, arch)
			}
			for _, release := range releases {
				if len(result) >= yumConsumerMaximumBindings {
					return nil, fmt.Errorf("definition expands beyond %d bindings", yumConsumerMaximumBindings)
				}
				mirrorlistURL := strings.ReplaceAll(strings.ReplaceAll(templateURL, "$releasever", strconv.Itoa(release)), "$basearch", arch)
				if strings.Contains(mirrorlistURL, "$") {
					return nil, fmt.Errorf("mirrorlist region %s leaves an unresolved placeholder", region)
				}
				if err := validateYUMConsumerMappedRoute(mirrorlistURL, entry, release, arch); err != nil {
					return nil, fmt.Errorf("%s %s EL%d %s: %w", file, entry.Name, release, arch, err)
				}
				result = append(result, yumConsumerBinding{File: file, Name: entry.Name, Region: region, Release: release, Arch: arch, MirrorlistURL: mirrorlistURL, TrustURL: trustURL})
			}
		}
	}
	return result, nil
}

func walkYUMConsumerDefinitions(file string, node *yaml.Node, entries map[string]yumConsumerMapEntry, counts map[string]int, bindings *[]yumConsumerBinding) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("%s uses a YAML alias in the reviewed consumer surface", file)
	}
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" && yumConsumerNodeContainsManagedRawURL(node) {
		return fmt.Errorf("%s contains an unmapped SOW-hosted YUM URL", file)
	}
	if node.Kind == yaml.MappingNode {
		nameNode, err := yumConsumerMappingValue(node, "name")
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		if nameNode != nil {
			name, scalarErr := yumConsumerScalar(nameNode, "name")
			if scalarErr == nil {
				if entry, matched := entries[name]; matched {
					definitionBindings, bindingErr := bindingsFromYUMConsumerDefinition(file, node, entry)
					if bindingErr != nil {
						return fmt.Errorf("%s definition %s: %w", file, name, bindingErr)
					}
					if len(*bindings) > yumConsumerMaximumBindings-len(definitionBindings) {
						return fmt.Errorf("%s expands beyond %d reviewed consumer bindings", file, yumConsumerMaximumBindings)
					}
					counts[name]++
					*bindings = append(*bindings, definitionBindings...)
					return nil
				}
				if yumConsumerNodeContainsManagedRawURL(node) {
					return fmt.Errorf("%s contains unmapped SOW-hosted YUM definition %s", file, name)
				}
			}
		}
	}
	for _, child := range node.Content {
		if err := walkYUMConsumerDefinitions(file, child, entries, counts, bindings); err != nil {
			return err
		}
	}
	return nil
}

func rejectYUMConsumerAliases(file string, node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("%s uses a YAML alias in the reviewed consumer surface", file)
	}
	for _, child := range node.Content {
		if err := rejectYUMConsumerAliases(file, child); err != nil {
			return err
		}
	}
	return nil
}

func parseYUMConsumerYAML(file string, body []byte, entries map[string]yumConsumerMapEntry, counts map[string]int, bindings *[]yumConsumerBinding) error {
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 {
		return errors.Join(err, fmt.Errorf("%s is not one YAML document", file))
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s contains multiple YAML documents", file)
	}
	if err := rejectYUMConsumerAliases(file, document.Content[0]); err != nil {
		return err
	}
	return walkYUMConsumerDefinitions(file, document.Content[0], entries, counts, bindings)
}

func yumConsumerTrimmedSequenceCount(body []byte, sequence []string) int {
	if len(sequence) == 0 {
		return 0
	}
	lines := strings.Split(string(body), "\n")
	count := 0
	for start := 0; start+len(sequence) <= len(lines); start++ {
		matched := true
		for offset := range sequence {
			if strings.TrimSpace(lines[start+offset]) != sequence[offset] {
				matched = false
				break
			}
		}
		if matched {
			count++
		}
	}
	return count
}

func validateYUMConsumerRenderer(file string, body []byte) error {
	if bytes.ContainsAny(body, "\x00\r") || strings.Count(string(body), "sow-yum-mirrorlist/v2") != 1 {
		return fmt.Errorf("renderer %s lacks one reviewed v2 marker", file)
	}
	routeBlock := []string{
		"# sow-yum-mirrorlist/v2",
		`{% if repo.mirrorlist is defined and region in repo.mirrorlist and repo.mirrorlist[region] is mapping and os_arch in repo.mirrorlist[region] %}`,
		`mirrorlist = {{ repo.mirrorlist[region][os_arch] | replace("${admin_ip}", admin_ip) | replace("$releasever", target_version|string) }}`,
		`{% elif repo.mirrorlist is defined and region in repo.mirrorlist and repo.mirrorlist[region] is string and repo.mirrorlist[region] != "" %}`,
		`mirrorlist = {{ repo.mirrorlist[region] | replace("${admin_ip}", admin_ip) | replace("$releasever", target_version|string) }}`,
		`{% elif repo.baseurl is defined and region in repo.baseurl and repo.baseurl[region] != "" %}`,
		`baseurl = {{ repo.baseurl[region] | replace("${admin_ip}", admin_ip) | replace("$releasever", target_version|string) }}`,
		`{% elif repo.mirrorlist is defined and "default" in repo.mirrorlist and repo.mirrorlist.default is mapping and os_arch in repo.mirrorlist.default %}`,
		`mirrorlist = {{ repo.mirrorlist.default[os_arch] | replace("${admin_ip}", admin_ip) | replace("$releasever", target_version|string) }}`,
		`{% elif repo.mirrorlist is defined and "default" in repo.mirrorlist and repo.mirrorlist.default is string and repo.mirrorlist.default != "" %}`,
		`mirrorlist = {{ repo.mirrorlist.default | replace("${admin_ip}", admin_ip) | replace("$releasever", target_version|string) }}`,
		`{% else %}`,
		`baseurl = {{ repo.baseurl.default | replace("${admin_ip}", admin_ip) | replace("$releasever", target_version|string) }}`,
		`{% endif %}`,
	}
	trustBlock := []string{
		`{% if repo.gpgkey is defined %}`,
		`{% if region in repo.gpgkey and repo.gpgkey[region] != "" %}`,
		`{% set repo_opts = repo_opts | combine({"gpgkey": repo.gpgkey[region]}) %}`,
		`{% else %}`,
		`{% set repo_opts = repo_opts | combine({"gpgkey": repo.gpgkey.default}) %}`,
		`{% endif %}`,
		`{% endif %}`,
	}
	rpmBlock := []string{
		`{% for repo in repo_upstream %}`,
		`{% if os_version|int in repo.releases and repo.module == module_name and os_arch in repo.arch %}`,
		`{% if os_package == 'rpm' %}`,
		`{% set target_version = '$releasever' %}`,
		`{% if (os_version|int >= 10) and (repo.name | lower | regex_search('^epel')) %}{% set target_version = os_version|string ~ 'z' %}{% endif %}`,
		`{% if (repo.name | lower | regex_search('^pgdg')) and ((os_version|int >= 10) or ((os_version|int == 9) and (os_version_full|string | regex_search('^9\.([6-9]|[1-9][0-9]+)(\..*)?$')))) %}{% set target_version = os_version_full|string | regex_replace('^(9\.([6-9]|[1-9][0-9]+)).*$', '\1') %}{% endif %}`,
		`{% if repo.minor is defined and repo.minor|bool %}{% set target_version = os_version_full|string %}{% endif %}`,
		`[{{ repo.name }}]`,
		`name = {{ repo.description }} $releasever - $basearch`,
	}
	rpmBlock = append(rpmBlock, routeBlock...)
	rpmBlock = append(rpmBlock,
		`{% set repo_opts = {'gpgcheck': 0, 'enabled': 1} %}`,
		`{% if os_version|int >= 8 %}{% set repo_opts = repo_opts | combine({'module_hotfixes': 1}) %}{% endif %}`,
		`{% if repo.meta is defined %}{% set repo_opts = repo_opts | combine(repo.meta) %}{% endif %}`,
	)
	rpmBlock = append(rpmBlock, trustBlock...)
	rpmBlock = append(rpmBlock,
		`{% for key, value in repo_opts.items() %}`,
		`{{ key }} = {{ value }}`,
		`{% endfor %}`,
		`{% else %}`,
	)
	if yumConsumerTrimmedSequenceCount(body, rpmBlock) != 1 {
		return fmt.Errorf("renderer %s differs from the reviewed architecture/trust control flow", file)
	}
	return nil
}

func parseYUMConsumerRoute(raw string) (viewName, repo, osName, arch string, err error) {
	parsed, err := strictYUMConsumerHTTPSURL(raw)
	if err != nil {
		return "", "", "", "", err
	}
	const marker = "/_sow/v1/mirrorlist/"
	if strings.Count(parsed.Path, marker) != 1 {
		return "", "", "", "", errors.New("mirrorlist URL has no unique route marker")
	}
	parts := strings.Split(strings.SplitN(parsed.Path, marker, 2)[1], "/")
	if len(parts) != 4 || parts[0] != "latest" && parts[0] != "beta" || !strings.HasSuffix(parts[3], ".txt") {
		return "", "", "", "", errors.New("mirrorlist URL is not view/repo/os/arch.txt")
	}
	arch = strings.TrimSuffix(parts[3], ".txt")
	for _, segment := range []string{parts[1], parts[2], arch} {
		if !validYUMConsumerSegment(segment) || strings.Contains(segment, "$") {
			return "", "", "", "", errors.New("mirrorlist URL contains an invalid coordinate")
		}
	}
	return parts[0], parts[1], parts[2], arch, nil
}

func yumConsumerTargetBase(cfg *config.Config, viewName, mirrorlistURL string) (string, string, error) {
	if cfg == nil {
		return "", "", errors.New("configuration is unavailable")
	}
	names := make([]string, 0, len(cfg.Targets))
	for name := range cfg.Targets {
		names = append(names, name)
	}
	sort.Strings(names)
	var targetName, baseURL string
	for _, name := range names {
		target := cfg.Targets[name]
		candidate := target.CDN.BaseURL
		if viewName == "beta" {
			candidate = target.CDN.BetaBaseURL
		}
		prefix := strings.TrimSuffix(candidate, "/") + "/_sow/v1/mirrorlist/" + viewName + "/"
		if strings.HasPrefix(mirrorlistURL, prefix) {
			if targetName != "" {
				return "", "", fmt.Errorf("mirrorlist origin matches multiple targets %s and %s", targetName, name)
			}
			targetName, baseURL = name, candidate
		}
	}
	if targetName == "" {
		return "", "", fmt.Errorf("mirrorlist URL %s is outside configured target origins", mirrorlistURL)
	}
	return targetName, baseURL, nil
}

func containsYUMConsumerString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func yumConsumerTrustRemoteKey(viewName string) string {
	if viewName == "beta" {
		return path.Join(".sow/beta", yumConsumerTrustRoute)
	}
	return yumConsumerTrustRoute
}

func yumConsumerCompatibilityTrustCacheKey(publicationKey, repoID string) string {
	return "compatibility:\x00" + publicationKey + "\x00" + repoID
}

func yumConsumerTrustFingerprints(body []byte, subject string, required map[string]struct{}) ([]string, error) {
	entities, err := yumrepo.ParsePublicKeyring(body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", subject, err)
	}
	fingerprints := make([]string, 0, len(entities))
	for _, entity := range entities {
		if entity == nil || entity.PrimaryKey == nil {
			return nil, fmt.Errorf("%s contains an unusable primary key", subject)
		}
		fingerprint := hex.EncodeToString(entity.PrimaryKey.Fingerprint)
		required[fingerprint] = struct{}{}
		fingerprints = append(fingerprints, fingerprint)
	}
	sort.Strings(fingerprints)
	return fingerprints, nil
}

func yumConsumerPackageTrustFingerprints(body []byte, subject string, required map[string]struct{}) error {
	fingerprints, err := yumrepo.RPMPackageKeyringPrimaryFingerprints(body)
	if err != nil {
		return fmt.Errorf("%s: %w", subject, err)
	}
	for _, fingerprint := range fingerprints {
		required[fingerprint] = struct{}{}
	}
	return nil
}

func ensureYUMConsumerAggregateTrust(bundle []byte, required map[string]struct{}) error {
	entities, err := yumrepo.ParsePublicKeyring(bundle)
	if err != nil {
		return fmt.Errorf("aggregate RPM trust bundle: %w", err)
	}
	present := make(map[string]struct{}, len(entities))
	for _, entity := range entities {
		present[hex.EncodeToString(entity.PrimaryKey.Fingerprint)] = struct{}{}
	}
	var missing []string
	for fingerprint := range required {
		if _, exists := present[fingerprint]; !exists {
			missing = append(missing, fingerprint)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return fmt.Errorf("aggregate RPM trust bundle lacks required primary fingerprints %s", strings.Join(missing, ","))
	}
	return nil
}

func yumConsumerPublicationIdentity(publication committedVerificationState, aggregate aggregateVerificationState, canonical *state.Store, target, viewName string) (yumConsumerPublicationState, error) {
	var result yumConsumerPublicationState
	generationBody, err := publication.generation.Canonical()
	if err != nil {
		return result, err
	}
	checkpointBody, err := publication.checkpoint.Canonical()
	if err != nil {
		return result, err
	}
	planBody, err := publication.plan.Canonical()
	if err != nil {
		return result, err
	}
	aggregateGenerationBody, err := aggregate.generation.Canonical()
	if err != nil {
		return result, err
	}
	aggregateCheckpointBody, checkpointExists, err := readOptionalCanonical(canonical, remoteStatePath(target, "checkpoint.json"))
	if err != nil || !checkpointExists {
		return result, errors.Join(err, errors.New("aggregate checkpoint disappeared during preflight"))
	}
	aggregatePlanBody, planExists, err := readOptionalCanonical(canonical, remoteStatePath(target, "plan.json"))
	if err != nil || !planExists {
		return result, errors.Join(err, errors.New("aggregate plan disappeared during preflight"))
	}
	return yumConsumerPublicationState{
		Target: target, View: viewName, Generation: publication.generation.Generation,
		GenerationSHA256: digestBytesCLI(generationBody), CheckpointSHA256: digestBytesCLI(checkpointBody), PlanSHA256: digestBytesCLI(planBody),
		AggregateGeneration: aggregate.generation.Generation, AggregateGenerationSHA256: digestBytesCLI(aggregateGenerationBody),
		AggregateCheckpointSHA256: digestBytesCLI(aggregateCheckpointBody), AggregatePlanSHA256: digestBytesCLI(aggregatePlanBody),
	}, nil
}

func readYUMConsumerCompatibilityPackageTrust(canonical *state.Store, frozen yumCompatibilityFrozenState) ([]byte, error) {
	trustPath, err := state.YUMCompatibilityPackageTrustPath(frozen.Receipt.ID)
	if err != nil {
		return nil, err
	}
	body, exists, err := readCanonicalBytesAt(canonical, frozen.Commit, trustPath, maxSecretBytes)
	if err != nil || !exists || int64(len(body)) != frozen.Receipt.PackageTrustSize || digestBytesCLI(body) != frozen.Receipt.PackageTrustSHA256 {
		return nil, errors.Join(err, fmt.Errorf("compatibility %s frozen package trust differs from its witness", frozen.Receipt.ID))
	}
	return body, nil
}

func prepareYUMConsumerPreflight(ctx context.Context, options yumConsumerPreflightOptions, stdout, stderr io.Writer) (*yumConsumerPrepared, *state.Lock, error) {
	cfg, _, err := loadAndSelect(options.values)
	if err != nil {
		return nil, nil, err
	}
	stagedRoot, stagedIdentity, err := canonicalYUMConsumerDirectoryIdentity(options.staged)
	if err != nil {
		return nil, nil, withExitCode(ExitVerification, "open reviewed YUM consumer stage: %v", err)
	}
	repositoryRoot, repositoryIdentity, err := canonicalYUMConsumerDirectoryIdentity(cfg.Root)
	if err != nil {
		return nil, nil, withExitCode(ExitVerification, "resolve repository root: %v", err)
	}
	if yumConsumerPathInside(repositoryRoot, stagedRoot) || yumConsumerPathInside(stagedRoot, repositoryRoot) {
		return nil, nil, withExitCode(ExitUsage, "--staged must be disjoint from the SOW repository")
	}
	receiptParent, receiptParentIdentity, err := canonicalYUMConsumerDirectoryIdentity(filepath.Dir(options.receipt))
	if err != nil {
		return nil, nil, withExitCode(ExitUsage, "receipt parent: %v", err)
	}
	if yumConsumerPathInside(repositoryRoot, receiptParent) {
		return nil, nil, withExitCode(ExitUsage, "--receipt must be outside the SOW repository")
	}

	mapBody, err := readStableRegularLimited(options.mapFile, yumConsumerMaximumInputBytes)
	if err != nil {
		return nil, nil, withExitCode(ExitVerification, "read consumer map: %v", err)
	}
	inventoryBody, err := readStableRegularLimited(options.inventory, yumConsumerMaximumInputBytes)
	if err != nil {
		return nil, nil, withExitCode(ExitVerification, "read consumer inventory: %v", err)
	}
	trustBundle, err := readStableRegularLimited(options.trustBundle, maxSecretBytes)
	if err != nil {
		return nil, nil, withExitCode(ExitVerification, "read aggregate RPM trust bundle: %v", err)
	}
	entries, mappedDefinitions, err := parseYUMConsumerMap(mapBody)
	if err != nil {
		return nil, nil, withExitCode(ExitVerification, "consumer map: %v", err)
	}
	inventory, err := parseYUMConsumerInventory(inventoryBody)
	if err != nil {
		return nil, nil, withExitCode(ExitVerification, "consumer inventory: %v", err)
	}
	inventoryDefinitions := 0
	for _, item := range inventory {
		inventoryDefinitions += item.ExpectedDefinitions
	}
	if inventoryDefinitions != mappedDefinitions {
		return nil, nil, withExitCode(ExitVerification, "consumer map covers %d definitions but inventory covers %d", mappedDefinitions, inventoryDefinitions)
	}
	manifestBody, err := readYUMConsumerStageFile(stagedRoot, "manifest.tsv")
	if err != nil {
		return nil, nil, withExitCode(ExitVerification, "read staged manifest: %v", err)
	}
	manifestDigest := digestBytesCLI(manifestBody)
	planBody, err := readYUMConsumerStageFile(stagedRoot, "plan.sha256")
	if err != nil || string(planBody) != manifestDigest+"\n" || options.confirm != manifestDigest {
		return nil, nil, withExitCode(ExitConflict, "stage plan digest is not the confirmed manifest identity %s", manifestDigest)
	}
	manifest, err := parseYUMConsumerManifest(manifestBody, inventory)
	if err != nil {
		return nil, nil, withExitCode(ExitVerification, "staged manifest: %v", err)
	}
	counts := make(map[string]int, len(entries))
	var bindings []yumConsumerBinding
	definitions := 0
	for _, item := range manifest {
		body, readErr := readYUMConsumerStageFile(stagedRoot, item.Path)
		if readErr != nil || digestBytesCLI(body) != item.After {
			return nil, nil, withExitCode(ExitConflict, "staged file %s differs from its manifest: %v", item.Path, readErr)
		}
		inventoryItem := inventory[item.Path]
		if inventoryItem.Kind == "renderer" {
			if err := validateYUMConsumerRenderer(item.Path, body); err != nil {
				return nil, nil, withExitCode(ExitVerification, "%v", err)
			}
			continue
		}
		before := len(bindings)
		beforeDefinitions := 0
		for _, count := range counts {
			beforeDefinitions += count
		}
		if err := parseYUMConsumerYAML(item.Path, body, entries, counts, &bindings); err != nil {
			return nil, nil, withExitCode(ExitVerification, "%v", err)
		}
		afterDefinitions := 0
		for _, count := range counts {
			afterDefinitions += count
		}
		if afterDefinitions-beforeDefinitions != inventoryItem.ExpectedDefinitions || len(bindings) == before {
			return nil, nil, withExitCode(ExitVerification, "consumer file %s contains %d reviewed definitions, want %d", item.Path, afterDefinitions-beforeDefinitions, inventoryItem.ExpectedDefinitions)
		}
		if len(bindings) > yumConsumerMaximumBindings {
			return nil, nil, withExitCode(ExitVerification, "staged consumers exceed %d expanded bindings", yumConsumerMaximumBindings)
		}
		definitions = afterDefinitions
	}
	for name, entry := range entries {
		if counts[name] != entry.ExpectedDefinitions {
			return nil, nil, withExitCode(ExitVerification, "consumer %s occurs %d times, want %d", name, counts[name], entry.ExpectedDefinitions)
		}
	}
	if definitions != mappedDefinitions || len(bindings) == 0 {
		return nil, nil, withExitCode(ExitVerification, "staged consumers lack complete expanded bindings")
	}
	sort.Slice(bindings, func(i, j int) bool {
		left, right := bindings[i], bindings[j]
		return left.File+"\x00"+left.Name+"\x00"+left.Region+fmt.Sprintf("\x00%02d\x00", left.Release)+left.Arch < right.File+"\x00"+right.Name+"\x00"+right.Region+fmt.Sprintf("\x00%02d\x00", right.Release)+right.Arch
	})
	bindingBody, err := json.Marshal(bindings)
	if err != nil {
		return nil, nil, withExitCode(ExitInternal, "encode consumer bindings: %v", err)
	}

	lock, err := state.AcquireLock(cfg.StatePath(), "yum-consumer-preflight", options.values.recover)
	if err != nil {
		return nil, nil, withExitCode(ExitConflict, "%v", err)
	}
	fail := func(err error) (*yumConsumerPrepared, *state.Lock, error) {
		return nil, nil, releaseYUMConsumerPreparationLock(lock, err, stderr)
	}
	canonical := state.New(cfg.StatePath())
	if err := prepareCanonicalState(ctx, canonical, options.values.recover, stdout); err != nil {
		return fail(err)
	}
	if err := requireCanonicalConfigBaseline(cfg, canonical); err != nil {
		return fail(withExitCode(ExitConflict, "canonical config changed while consumer preflight waited for the state lock: %v", err))
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return fail(withExitCode(ExitVerification, "canonical config identity: %v", err))
	}
	requiredFingerprints := make(map[string]struct{})
	publicationCache := make(map[string]committedVerificationState)
	aggregateCache := make(map[string]aggregateVerificationState)
	stateCache := make(map[string]yumConsumerPublicationState)
	endpointCache := make(map[string]yumConsumerEndpointSpec)
	verifierCache := make(map[string]yumrepo.DetachedVerifier)
	packageCache := make(map[string]openpgp.KeyRing)
	metadataFingerprintCache := make(map[string]string)
	packageTrustSHA256 := make(map[string]string)
	repositoryTrustSHA256 := ""
	verifyAt := yumConsumerPreflightNow().UTC().Truncate(time.Second)

	for _, binding := range bindings {
		viewName, repoID, osName, arch, routeErr := parseYUMConsumerRoute(binding.MirrorlistURL)
		if routeErr != nil || arch != binding.Arch {
			return fail(withExitCode(ExitVerification, "binding %s/%s: %v", binding.File, binding.Name, errors.Join(routeErr, errors.New("route architecture differs from consumer architecture"))))
		}
		targetName, baseURL, targetErr := yumConsumerTargetBase(cfg, viewName, binding.MirrorlistURL)
		if targetErr != nil {
			return fail(withExitCode(ExitVerification, "binding %s/%s: %v", binding.File, binding.Name, targetErr))
		}
		wantedTrustURL := strings.TrimSuffix(baseURL, "/") + "/" + yumConsumerTrustRoute
		if binding.TrustURL != wantedTrustURL {
			return fail(withExitCode(ExitVerification, "binding %s/%s trust URL %s is not target-owned %s", binding.File, binding.Name, binding.TrustURL, wantedTrustURL))
		}
		publicationKey := targetName + "\x00" + viewName
		publication, exists := publicationCache[publicationKey]
		if !exists {
			publication, err = loadCommittedVerificationStateForConfig(cfg, canonical, targetName, viewName, "")
			if err != nil {
				return fail(withExitCode(ExitConflict, "load committed %s/%s publication: %v", targetName, viewName, err))
			}
			committedConfigSHA, configErr := publicationConfigSHA256ForGeneration(cfg, publication.generation)
			keyMatches, keyErr := generationRepositoryTrustMatches(cfg, publication.generation)
			var publicationDrift []string
			if configErr != nil {
				publicationDrift = append(publicationDrift, "config identity could not be derived")
			} else if publication.generation.ConfigSHA256 != committedConfigSHA {
				publicationDrift = append(publicationDrift, "config identity changed")
			}
			if keyErr != nil {
				publicationDrift = append(publicationDrift, "repository trust identity could not be derived")
			} else if !keyMatches {
				publicationDrift = append(publicationDrift, "repository trust changed")
			}
			if strings.TrimSuffix(publication.plan.CDNBaseURL, "/") != strings.TrimSuffix(baseURL, "/") {
				publicationDrift = append(publicationDrift, "CDN origin differs")
			}
			if len(publicationDrift) > 0 {
				return fail(withExitCode(ExitConflict, "committed %s/%s publication differs from current authority (%s): %v", targetName, viewName, strings.Join(publicationDrift, ", "), errors.Join(configErr, keyErr)))
			}
			publicationCache[publicationKey] = publication
		}
		aggregate, exists := aggregateCache[targetName]
		if !exists {
			aggregate, err = loadCurrentAggregateVerificationStateForConfig(cfg, canonical, targetName, map[string]struct{}{
				yumConsumerTrustRoute: {}, path.Join(".sow/beta", yumConsumerTrustRoute): {},
			})
			if err != nil {
				return fail(withExitCode(ExitConflict, "load current %s aggregate publication: %v", targetName, err))
			}
			aggregateCache[targetName] = aggregate
		}
		trustRemoteKey := yumConsumerTrustRemoteKey(viewName)
		trustInventoryEntry, present := aggregate.inventoryEntries[trustRemoteKey]
		if !present {
			return fail(withExitCode(ExitConflict, "current %s aggregate inventory does not own %s", targetName, trustRemoteKey))
		}
		if trustInventoryEntry.Size != int64(len(trustBundle)) || trustInventoryEntry.HashString() != digestBytesCLI(trustBundle) {
			return fail(withExitCode(ExitConflict, "current %s aggregate inventory identity for %s differs from the reviewed trust bundle", targetName, trustRemoteKey))
		}
		if _, exists := stateCache[publicationKey]; !exists {
			identity, identityErr := yumConsumerPublicationIdentity(publication, aggregate, canonical, targetName, viewName)
			if identityErr != nil {
				return fail(withExitCode(ExitConflict, "bind %s/%s publication identity: %v", targetName, viewName, identityErr))
			}
			stateCache[publicationKey] = identity
		}

		var channel pub.ChannelState
		var compression yumrepo.Compression
		metadataFingerprint := ""
		trustKey := repoID
		if repo, ordinary := cfg.RepoByName(repoID); ordinary {
			if repo.Type != "yum" || repo.YUM == nil || !repo.IsActive() || !repo.PublishesToTarget(targetName) || !containsYUMConsumerString(repo.OSSelectorValues(), osName) || !containsYUMConsumerString(repo.ArchSelectorValues(), arch) {
				return fail(withExitCode(ExitVerification, "route %s/%s/%s is not an active target-owned YUM leaf", repoID, osName, arch))
			}
			leaf := viewLeaf{repo: repo, os: osName, arch: arch}
			var channelExists bool
			channel, channelExists = generationChannel(publication.generation, viewName, leaf)
			if !channelExists {
				return fail(withExitCode(ExitConflict, "committed %s/%s publication has no channel for %s/%s/%s", targetName, viewName, repoID, osName, arch))
			}
			compression = yumrepo.Compression(repo.YUM.Compression)
			if compression != yumrepo.CompressionGzip && compression != yumrepo.CompressionZstd {
				return fail(withExitCode(ExitVerification, "repo %s has unsupported compression", repoID))
			}
			if _, cached := verifierCache[trustKey]; !cached {
				metadataTrust, trustErr := loadRepositoryPublicKey(cfg, "")
				verifier, verifierErr := yumrepo.NewOpenPGPVerifier(bytes.NewReader(metadataTrust), verifyAt)
				packageTrust, packageDigest, packageErr := readStableKeyringBytes(cfg.Path, repo.YUM.PackageKeyring)
				packageKeyring, keyringErr := yumrepo.ParseRPMPackageKeyring(packageTrust)
				if trustErr != nil || verifierErr != nil || packageErr != nil || keyringErr != nil {
					return fail(withExitCode(ExitVerification, "load trust for repo %s: %v", repoID, errors.Join(trustErr, verifierErr, packageErr, keyringErr)))
				}
				metadataFingerprints, fingerprintErr := yumConsumerTrustFingerprints(metadataTrust, "repository metadata trust", requiredFingerprints)
				if fingerprintErr != nil || len(metadataFingerprints) != 1 {
					return fail(withExitCode(ExitVerification, "repository metadata trust must contain exactly one primary identity: %v", fingerprintErr))
				}
				metadataFingerprintCache[trustKey] = metadataFingerprints[0]
				if trustErr = yumConsumerPackageTrustFingerprints(packageTrust, "repo "+repoID+" package trust", requiredFingerprints); trustErr != nil {
					return fail(withExitCode(ExitVerification, "%v", trustErr))
				}
				metadataDigest := digestBytesCLI(metadataTrust)
				if repositoryTrustSHA256 != "" && repositoryTrustSHA256 != metadataDigest {
					return fail(withExitCode(ExitConflict, "repository metadata trust changed while preparing consumer endpoints"))
				}
				repositoryTrustSHA256 = metadataDigest
				packageTrustSHA256[repoID] = packageDigest
				verifierCache[trustKey], packageCache[trustKey] = verifier, packageKeyring
			}
			metadataFingerprint = metadataFingerprintCache[trustKey]
		} else {
			projection, projectionExists, projectionErr := config.YUMCompatibilityProjectionByID(cfg.CompatibilityProjections, repoID)
			if projectionErr != nil || !projectionExists || viewName != "latest" || osName != "cross-el" || projection.Source.Arch != arch {
				return fail(withExitCode(ExitVerification, "route %s/%s/%s is not a configured frozen compatibility projection: %v", repoID, osName, arch, projectionErr))
			}
			owner, ownerExists := cfg.RepoByName(projection.Source.Repo)
			if !ownerExists || !owner.PublishesToTarget(targetName) {
				return fail(withExitCode(ExitVerification, "compatibility projection %s is not owned by target %s", repoID, targetName))
			}
			identity, identityExists := compatibilityStateAtGeneration(publication.generation, repoID)
			if !identityExists {
				return fail(withExitCode(ExitConflict, "committed %s/latest publication lacks compatibility identity %s", targetName, repoID))
			}
			var channelExists bool
			channel, channelExists = compatibilityChannel(publication.generation, identity.ChannelRemoteKey)
			if !channelExists {
				return fail(withExitCode(ExitConflict, "committed compatibility projection %s lacks its channel", repoID))
			}
			compression = yumrepo.CompressionGzip
			// Each target/view can legitimately lag on a different committed
			// generation. Frozen compatibility trust belongs to that exact
			// publication commit, so it must never be reused by projection ID
			// alone across independently tracked targets.
			trustKey = yumConsumerCompatibilityTrustCacheKey(publicationKey, repoID)
			if _, cached := verifierCache[trustKey]; !cached {
				frozen, frozenErr := loadYUMCompatibilityFrozenStateAt(canonical, plumbing.NewHash(publication.generation.DesiredCommit), repoID)
				packageKeyring, keyringErr := loadFrozenCompatibilityPackageKeyring(canonical, identity)
				packageTrust, packageErr := readYUMConsumerCompatibilityPackageTrust(canonical, frozen)
				verifier, verifierErr := yumrepo.NewOpenPGPVerifier(bytes.NewReader(frozen.RepositoryTrust), verifyAt)
				if frozenErr != nil || keyringErr != nil || packageErr != nil || verifierErr != nil {
					return fail(withExitCode(ExitVerification, "load frozen trust for compatibility %s: %v", repoID, errors.Join(frozenErr, keyringErr, packageErr, verifierErr)))
				}
				metadataFingerprints, fingerprintErr := yumConsumerTrustFingerprints(frozen.RepositoryTrust, "compatibility "+repoID+" metadata trust", requiredFingerprints)
				if fingerprintErr != nil || len(metadataFingerprints) != 1 {
					return fail(withExitCode(ExitVerification, "compatibility %s metadata trust must contain exactly one primary identity: %v", repoID, fingerprintErr))
				}
				metadataFingerprintCache[trustKey] = metadataFingerprints[0]
				if err := yumConsumerPackageTrustFingerprints(packageTrust, "compatibility "+repoID+" package trust", requiredFingerprints); err != nil {
					return fail(withExitCode(ExitVerification, "%v", err))
				}
				verifierCache[trustKey], packageCache[trustKey] = verifier, packageKeyring
			}
			metadataFingerprint = metadataFingerprintCache[trustKey]
		}
		pointerKey, pointerBody, pointerErr := pub.YUMChannelPointer(baseURL, channel)
		if pointerErr != nil || binding.MirrorlistURL != strings.TrimSuffix(baseURL, "/")+"/"+pointerKey {
			return fail(withExitCode(ExitConflict, "binding %s/%s is not the exact committed channel pointer: %v", binding.File, binding.Name, pointerErr))
		}
		generationURL := strings.TrimSpace(string(pointerBody))
		if _, err := strictYUMConsumerHTTPSURL(strings.TrimSuffix(generationURL, "/")); err != nil || !strings.HasSuffix(generationURL, "/") {
			return fail(withExitCode(ExitConflict, "committed channel for %s/%s/%s has an invalid generation URL", repoID, osName, arch))
		}
		endpoint := yumConsumerEndpointSpec{Target: targetName, View: viewName, Repo: repoID, OS: osName, Arch: arch, Compression: compression, BaseURL: baseURL, MirrorlistURL: binding.MirrorlistURL, MirrorlistKey: pointerKey, GenerationURL: generationURL, TrustURL: wantedTrustURL, MetadataFingerprint: metadataFingerprint, Verifier: verifierCache[trustKey], PackageKeyring: packageCache[trustKey]}
		endpointKey := targetName + "\x00" + viewName + "\x00" + repoID + "\x00" + osName + "\x00" + arch + "\x00" + binding.MirrorlistURL
		endpointCache[endpointKey] = endpoint
	}
	if err := ensureYUMConsumerAggregateTrust(trustBundle, requiredFingerprints); err != nil {
		return fail(withExitCode(ExitVerification, "%v", err))
	}
	aggregatePackageKeyring, keyringErr := yumrepo.ParseRPMPackageKeyring(trustBundle)
	if keyringErr != nil {
		return fail(withExitCode(ExitVerification, "aggregate RPM trust bundle is not usable for package verification: %v", keyringErr))
	}
	// The client imports exactly pkg/keys/rpm-trust.asc. Fingerprint closure is
	// necessary but not sufficient: a same-primary certificate can omit the
	// historical signing-subkey binding needed by a retained RPM. Probe with
	// the exact aggregate bytes the client will import, not repo-local trust.
	aggregateVerifierCache := make(map[string]yumrepo.DetachedVerifier)
	for key, endpoint := range endpointCache {
		aggregateVerifier := aggregateVerifierCache[endpoint.MetadataFingerprint]
		if aggregateVerifier == nil {
			verifier, verifierErr := yumrepo.NewOpenPGPVerifierForFingerprint(bytes.NewReader(trustBundle), endpoint.MetadataFingerprint, verifyAt)
			if verifierErr != nil {
				return fail(withExitCode(ExitVerification, "aggregate RPM trust bundle cannot verify metadata identity %s: %v", endpoint.MetadataFingerprint, verifierErr))
			}
			aggregateVerifier = verifier
			aggregateVerifierCache[endpoint.MetadataFingerprint] = verifier
		}
		endpoint.Verifier = aggregateVerifier
		endpoint.PackageKeyring = aggregatePackageKeyring
		endpointCache[key] = endpoint
	}
	states := make([]yumConsumerPublicationState, 0, len(stateCache))
	for _, item := range stateCache {
		states = append(states, item)
	}
	sort.Slice(states, func(i, j int) bool {
		return states[i].Target+"\x00"+states[i].View < states[j].Target+"\x00"+states[j].View
	})
	endpoints := make([]yumConsumerEndpointSpec, 0, len(endpointCache))
	for _, endpoint := range endpointCache {
		endpoints = append(endpoints, endpoint)
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].MirrorlistURL < endpoints[j].MirrorlistURL })
	if len(endpoints) == 0 {
		return fail(withExitCode(ExitVerification, "staged consumer plan expands to no unique endpoints"))
	}
	prepared := &yumConsumerPrepared{
		cfg: cfg, canonical: canonical, stagedRoot: stagedRoot, repositoryRoot: repositoryRoot, receiptParent: receiptParent,
		stagedIdentity: stagedIdentity, repositoryIdentity: repositoryIdentity, receiptParentIdentity: receiptParentIdentity,
		manifest: append([]yumConsumerManifestEntry(nil), manifest...), planSHA256: manifestDigest, stagedManifestSHA256: manifestDigest,
		mapSHA256: digestBytesCLI(mapBody), inventorySHA256: digestBytesCLI(inventoryBody), configSHA256: configSHA,
		trustBundleSHA256: digestBytesCLI(trustBundle), trustBundle: append([]byte(nil), trustBundle...), definitions: definitions,
		repositoryTrustSHA256: repositoryTrustSHA256, packageTrustSHA256: packageTrustSHA256,
		bindings: bindings, bindingsSHA256: digestBytesCLI(bindingBody), states: states, endpoints: endpoints, verifiedAt: verifyAt,
	}
	return prepared, lock, nil
}

// releaseYUMConsumerPreparationLock preserves the preparation error and its
// exit class while making a failed durable-lock teardown visible. Without the
// diagnostic, the next invocation can encounter a residual state.lock without
// knowing that explicit recovery may be required.
func releaseYUMConsumerPreparationLock(lock stateLockReleaser, primary error, stderr io.Writer) error {
	resultErr := primary
	propagateStateLockRelease(lock, &resultErr, stderr)
	return resultErr
}

func (prepared *yumConsumerPrepared) validateLocalInputs(options yumConsumerPreflightOptions) error {
	if prepared == nil || prepared.cfg == nil || prepared.canonical == nil || prepared.stagedRoot == "" || prepared.repositoryRoot == "" || prepared.receiptParent == "" ||
		prepared.stagedIdentity == nil || prepared.repositoryIdentity == nil || prepared.receiptParentIdentity == nil || prepared.verifiedAt.IsZero() || len(prepared.manifest) == 0 {
		return errors.New("prepared consumer input identity is incomplete")
	}
	reloaded, _, err := loadAndSelect(options.values)
	if err != nil {
		return fmt.Errorf("reload configuration: %w", err)
	}
	configSHA, err := reloaded.CanonicalSHA256()
	if err != nil || configSHA != prepared.configSHA256 {
		return errors.Join(err, errors.New("canonical configuration digest differs"))
	}
	repositoryRoot, repositoryIdentity, err := canonicalYUMConsumerDirectoryIdentity(reloaded.Root)
	if err != nil || repositoryRoot != prepared.repositoryRoot || !os.SameFile(prepared.repositoryIdentity, repositoryIdentity) {
		return errors.Join(err, errors.New("repository root identity differs"))
	}
	stagedRoot, stagedIdentity, err := canonicalYUMConsumerDirectoryIdentity(options.staged)
	if err != nil || stagedRoot != prepared.stagedRoot || !os.SameFile(prepared.stagedIdentity, stagedIdentity) {
		return errors.Join(err, errors.New("reviewed stage directory identity differs"))
	}
	receiptParent, receiptParentIdentity, err := canonicalYUMConsumerDirectoryIdentity(filepath.Dir(options.receipt))
	if err != nil || receiptParent != prepared.receiptParent || !os.SameFile(prepared.receiptParentIdentity, receiptParentIdentity) || yumConsumerPathInside(repositoryRoot, receiptParent) {
		return errors.Join(err, errors.New("receipt parent identity or safety boundary differs"))
	}
	mapBody, err := readStableRegularLimited(options.mapFile, yumConsumerMaximumInputBytes)
	if err != nil || digestBytesCLI(mapBody) != prepared.mapSHA256 {
		return errors.Join(err, errors.New("reviewed consumer map digest differs"))
	}
	inventoryBody, err := readStableRegularLimited(options.inventory, yumConsumerMaximumInputBytes)
	if err != nil || digestBytesCLI(inventoryBody) != prepared.inventorySHA256 {
		return errors.Join(err, errors.New("reviewed consumer inventory digest differs"))
	}
	trustBundle, err := readStableRegularLimited(options.trustBundle, maxSecretBytes)
	if err != nil || digestBytesCLI(trustBundle) != prepared.trustBundleSHA256 {
		return errors.Join(err, errors.New("reviewed aggregate trust digest differs"))
	}
	if prepared.repositoryTrustSHA256 != "" {
		repositoryTrust, trustErr := loadRepositoryPublicKey(reloaded, "")
		if trustErr != nil || digestBytesCLI(repositoryTrust) != prepared.repositoryTrustSHA256 {
			return errors.Join(trustErr, errors.New("repository metadata trust digest differs"))
		}
	}
	repoIDs := make([]string, 0, len(prepared.packageTrustSHA256))
	for repoID := range prepared.packageTrustSHA256 {
		repoIDs = append(repoIDs, repoID)
	}
	sort.Strings(repoIDs)
	for _, repoID := range repoIDs {
		repo, exists := reloaded.RepoByName(repoID)
		if !exists || repo.YUM == nil {
			return fmt.Errorf("repo %s package trust authority disappeared", repoID)
		}
		_, digest, trustErr := readStableKeyringBytes(reloaded.Path, repo.YUM.PackageKeyring)
		if trustErr != nil || digest != prepared.packageTrustSHA256[repoID] {
			return errors.Join(trustErr, fmt.Errorf("repo %s package trust digest differs", repoID))
		}
	}
	manifestBody, err := readYUMConsumerStageFile(stagedRoot, "manifest.tsv")
	if err != nil || digestBytesCLI(manifestBody) != prepared.stagedManifestSHA256 || options.confirm != prepared.planSHA256 {
		return errors.Join(err, errors.New("staged manifest or confirmation identity differs"))
	}
	planBody, err := readYUMConsumerStageFile(stagedRoot, "plan.sha256")
	if err != nil || string(planBody) != prepared.planSHA256+"\n" {
		return errors.Join(err, errors.New("staged plan identity differs"))
	}
	for _, item := range prepared.manifest {
		body, readErr := readYUMConsumerStageFile(stagedRoot, item.Path)
		if readErr != nil || digestBytesCLI(body) != item.After {
			return errors.Join(readErr, fmt.Errorf("staged file %s digest differs", item.Path))
		}
	}
	return nil
}

func yumConsumerHTTPClient() *http.Client {
	result := &http.Client{Timeout: 2 * time.Minute}
	if yumConsumerPreflightHTTPClient != nil {
		copy := *yumConsumerPreflightHTTPClient
		result = &copy
		if result.Timeout <= 0 || result.Timeout > 2*time.Minute {
			result.Timeout = 2 * time.Minute
		}
	}
	result.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("YUM consumer preflight refuses redirects")
	}
	return result
}

func readYUMConsumerRemoteTrust(ctx context.Context, client *http.Client, raw string, wanted []byte) error {
	if _, err := strictYUMConsumerHTTPSURL(raw); err != nil {
		return fmt.Errorf("%w: invalid trust URL", verify.ErrClientCoverage)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return fmt.Errorf("%w: create trust request", verify.ErrClientCoverage)
	}
	request.Header.Set("Accept", "application/pgp-keys, application/octet-stream;q=0.9")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: trust endpoint request failed", verify.ErrClientNetwork)
	}
	if response.StatusCode != http.StatusOK {
		closeErr := response.Body.Close()
		return errors.Join(fmt.Errorf("%w: trust endpoint returned HTTP %d", verify.ErrClientNetwork, response.StatusCode), closeErr)
	}
	if response.ContentLength > maxSecretBytes {
		closeErr := response.Body.Close()
		return errors.Join(fmt.Errorf("%w: trust endpoint body exceeds limit", verify.ErrClientIntegrity), closeErr)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxSecretBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(fmt.Errorf("%w: trust endpoint body could not be read or closed", verify.ErrClientNetwork), readErr, closeErr)
	}
	if int64(len(body)) > maxSecretBytes || !bytes.Equal(body, wanted) {
		return fmt.Errorf("%w: trust endpoint bytes differ from the reviewed aggregate bundle", verify.ErrClientIntegrity)
	}
	return nil
}

func readYUMConsumerRemotePointer(ctx context.Context, client *http.Client, raw, generationURL string) error {
	if _, err := strictYUMConsumerHTTPSURL(raw); err != nil {
		return fmt.Errorf("%w: invalid mirrorlist URL", verify.ErrClientCoverage)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return fmt.Errorf("%w: create mirrorlist request", verify.ErrClientCoverage)
	}
	request.Header.Set("Accept", "text/plain")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: mirrorlist request failed", verify.ErrClientNetwork)
	}
	if response.StatusCode != http.StatusOK {
		closeErr := response.Body.Close()
		return errors.Join(fmt.Errorf("%w: mirrorlist returned HTTP %d", verify.ErrClientNetwork, response.StatusCode), closeErr)
	}
	if response.ContentLength > yumConsumerMaximumPointerBytes {
		closeErr := response.Body.Close()
		return errors.Join(fmt.Errorf("%w: mirrorlist body exceeds limit", verify.ErrClientIntegrity), closeErr)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, yumConsumerMaximumPointerBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(fmt.Errorf("%w: mirrorlist body could not be read or closed", verify.ErrClientNetwork), readErr, closeErr)
	}
	wanted := []byte(generationURL + "\n")
	if int64(len(body)) > yumConsumerMaximumPointerBytes || !bytes.Equal(body, wanted) {
		return fmt.Errorf("%w: mirrorlist no longer names the committed immutable generation", verify.ErrClientIntegrity)
	}
	return nil
}

type yumConsumerRemoteClosureCheck struct {
	kind          string
	url           string
	generationURL string
}

func revalidateYUMConsumerRemoteClosure(ctx context.Context, prepared *yumConsumerPrepared, workers int) error {
	if prepared == nil || len(prepared.endpoints) == 0 || len(prepared.trustBundle) == 0 || workers < 1 {
		return fmt.Errorf("%w: invalid remote closure configuration", verify.ErrClientCoverage)
	}
	checksByKey := make(map[string]yumConsumerRemoteClosureCheck, len(prepared.endpoints)*2)
	for _, endpoint := range prepared.endpoints {
		checksByKey["mirrorlist\x00"+endpoint.MirrorlistURL] = yumConsumerRemoteClosureCheck{kind: "mirrorlist", url: endpoint.MirrorlistURL, generationURL: endpoint.GenerationURL}
		checksByKey["trust\x00"+endpoint.TrustURL] = yumConsumerRemoteClosureCheck{kind: "trust", url: endpoint.TrustURL}
	}
	keys := make([]string, 0, len(checksByKey))
	for key := range checksByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	checks := make([]yumConsumerRemoteClosureCheck, 0, len(keys))
	for _, key := range keys {
		checks = append(checks, checksByKey[key])
	}
	if workers > len(checks) {
		workers = len(checks)
	}
	client := yumConsumerHTTPClient()
	errorsByIndex := make([]error, len(checks))
	jobs := make(chan int)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := range jobs {
				check := checks[index]
				if err := ctx.Err(); err != nil {
					errorsByIndex[index] = err
					continue
				}
				if check.kind == "trust" {
					errorsByIndex[index] = readYUMConsumerRemoteTrust(ctx, client, check.url, prepared.trustBundle)
				} else {
					errorsByIndex[index] = readYUMConsumerRemotePointer(ctx, client, check.url, check.generationURL)
				}
			}
		}()
	}
	for index := range checks {
		jobs <- index
	}
	close(jobs)
	wait.Wait()
	for index, err := range errorsByIndex {
		if err != nil {
			return fmt.Errorf("%s %s: %w", checks[index].kind, checks[index].url, err)
		}
	}
	return nil
}

func executeYUMConsumerEndpointPreflight(ctx context.Context, prepared *yumConsumerPrepared, workers, chunkEntries int) ([]yumConsumerEndpointEvidence, error) {
	if prepared == nil || len(prepared.endpoints) == 0 || len(prepared.trustBundle) == 0 || workers < 1 || chunkEntries < 1 {
		return nil, fmt.Errorf("%w: invalid endpoint preflight configuration", verify.ErrClientCoverage)
	}
	if workers > len(prepared.endpoints) {
		workers = len(prepared.endpoints)
	}
	client := yumConsumerHTTPClient()
	results := make([]yumConsumerEndpointEvidence, len(prepared.endpoints))
	errorsByIndex := make([]error, len(prepared.endpoints))
	jobs := make(chan int)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := range jobs {
				endpoint := prepared.endpoints[index]
				if err := ctx.Err(); err != nil {
					errorsByIndex[index] = err
					continue
				}
				if err := readYUMConsumerRemoteTrust(ctx, client, endpoint.TrustURL, prepared.trustBundle); err != nil {
					errorsByIndex[index] = fmt.Errorf("%s %s/%s/%s trust: %w", endpoint.Target, endpoint.Repo, endpoint.OS, endpoint.Arch, err)
					continue
				}
				probe := verify.YUMProtocolProbe{
					Client: client, CDNBaseURL: endpoint.BaseURL, MirrorlistPath: endpoint.MirrorlistKey,
					ExpectedGenerationURL: endpoint.GenerationURL, Architecture: endpoint.Arch,
					Compression: endpoint.Compression, Verifier: endpoint.Verifier, PackageKeyring: endpoint.PackageKeyring,
					VerifyAt: prepared.verifiedAt, ChunkEntries: chunkEntries,
				}
				evidence, err := probe.Run(ctx)
				if err != nil {
					errorsByIndex[index] = fmt.Errorf("%s %s/%s/%s protocol: %w", endpoint.Target, endpoint.Repo, endpoint.OS, endpoint.Arch, err)
					continue
				}
				results[index] = yumConsumerEndpointEvidence{
					Target: endpoint.Target, View: endpoint.View, Repo: endpoint.Repo, OS: endpoint.OS, Arch: endpoint.Arch,
					Compression: string(endpoint.Compression), MirrorlistURL: endpoint.MirrorlistURL, GenerationURL: endpoint.GenerationURL,
					TrustURL: endpoint.TrustURL, TranscriptSHA256: evidence.TranscriptSHA256, TranscriptSummary: evidence.TranscriptSummary,
					MetadataObjects: evidence.MetadataObjects, InstalledObjects: evidence.InstalledObjects,
					PackageName: evidence.PackageName, PackageVersion: evidence.PackageVersion, PackageSHA256: evidence.PackageSHA256,
				}
			}
		}()
	}
	for index := range prepared.endpoints {
		jobs <- index
	}
	close(jobs)
	wait.Wait()
	for _, err := range errorsByIndex {
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}

func (prepared *yumConsumerPrepared) receipt(verifiedAt, expiresAt time.Time, endpoints []yumConsumerEndpointEvidence) yumConsumerPreflightReceipt {
	return yumConsumerPreflightReceipt{
		Schema: yumConsumerPreflightReceiptSchema, PlanSHA256: prepared.planSHA256,
		StagedManifestSHA256: prepared.stagedManifestSHA256, MapSHA256: prepared.mapSHA256,
		InventorySHA256: prepared.inventorySHA256, ConfigSHA256: prepared.configSHA256,
		TrustBundleSHA256: prepared.trustBundleSHA256, ConsumerDefinitions: prepared.definitions,
		ConsumerBindings: len(prepared.bindings), ConsumerBindingsSHA256: prepared.bindingsSHA256,
		VerifiedAt:        verifiedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		ExpiresAt:         expiresAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		PublicationStates: append([]yumConsumerPublicationState(nil), prepared.states...),
		Endpoints:         append([]yumConsumerEndpointEvidence(nil), endpoints...),
	}
}

func validateYUMConsumerReceiptShape(receipt yumConsumerPreflightReceipt) error {
	if receipt.Schema != yumConsumerPreflightReceiptSchema || !validLowerSHA256(receipt.PlanSHA256) || !validLowerSHA256(receipt.StagedManifestSHA256) ||
		!validLowerSHA256(receipt.MapSHA256) || !validLowerSHA256(receipt.InventorySHA256) || !validLowerSHA256(receipt.ConfigSHA256) ||
		!validLowerSHA256(receipt.TrustBundleSHA256) || !validLowerSHA256(receipt.ConsumerBindingsSHA256) || receipt.PlanSHA256 != receipt.StagedManifestSHA256 ||
		receipt.ConsumerDefinitions < 1 || receipt.ConsumerBindings < receipt.ConsumerDefinitions || len(receipt.PublicationStates) == 0 || len(receipt.Endpoints) == 0 {
		return errors.New("receipt has invalid schema, digests, counts, or evidence coverage")
	}
	verifiedAt, err := time.Parse(time.RFC3339, receipt.VerifiedAt)
	if err != nil || verifiedAt.UTC().Format(time.RFC3339) != receipt.VerifiedAt {
		return errors.New("receipt verified_at is not canonical UTC RFC3339")
	}
	expiresAt, err := time.Parse(time.RFC3339, receipt.ExpiresAt)
	if err != nil || expiresAt.UTC().Format(time.RFC3339) != receipt.ExpiresAt || !expiresAt.After(verifiedAt) || expiresAt.Sub(verifiedAt) < yumConsumerMinimumValidity || expiresAt.Sub(verifiedAt) > yumConsumerMaximumValidity {
		return errors.New("receipt expiry is invalid")
	}
	seenStates := make(map[string]struct{}, len(receipt.PublicationStates))
	for _, state := range receipt.PublicationStates {
		key := state.Target + "\x00" + state.View
		if state.Target == "" || state.View != "latest" && state.View != "beta" || state.Generation == 0 || state.AggregateGeneration == 0 ||
			!validLowerSHA256(state.GenerationSHA256) || !validLowerSHA256(state.CheckpointSHA256) || !validLowerSHA256(state.PlanSHA256) ||
			!validLowerSHA256(state.AggregateGenerationSHA256) || !validLowerSHA256(state.AggregateCheckpointSHA256) || !validLowerSHA256(state.AggregatePlanSHA256) {
			return errors.New("receipt contains an invalid publication identity")
		}
		if _, duplicate := seenStates[key]; duplicate {
			return errors.New("receipt repeats a publication identity")
		}
		seenStates[key] = struct{}{}
	}
	seenEndpoints := make(map[string]struct{}, len(receipt.Endpoints))
	for _, endpoint := range receipt.Endpoints {
		if endpoint.Target == "" || endpoint.View != "latest" && endpoint.View != "beta" || endpoint.Repo == "" || endpoint.OS == "" ||
			(endpoint.Arch != "x86_64" && endpoint.Arch != "aarch64") || (endpoint.Compression != string(yumrepo.CompressionGzip) && endpoint.Compression != string(yumrepo.CompressionZstd)) ||
			!validLowerSHA256(endpoint.TranscriptSHA256) || !validLowerSHA256(endpoint.PackageSHA256) || endpoint.TranscriptSummary != "mirrorlist->repomd+asc->primary+filelists+other->RPM" ||
			endpoint.MetadataObjects != 6 || endpoint.InstalledObjects != 1 || endpoint.PackageName == "" || endpoint.PackageVersion == "" {
			return errors.New("receipt contains incomplete endpoint protocol evidence")
		}
		if _, err := strictYUMConsumerHTTPSURL(endpoint.MirrorlistURL); err != nil {
			return errors.New("receipt contains an invalid mirrorlist URL")
		}
		if _, err := strictYUMConsumerHTTPSURL(strings.TrimSuffix(endpoint.GenerationURL, "/")); err != nil || !strings.HasSuffix(endpoint.GenerationURL, "/") {
			return errors.New("receipt contains an invalid generation URL")
		}
		if _, err := strictYUMConsumerHTTPSURL(endpoint.TrustURL); err != nil {
			return errors.New("receipt contains an invalid trust URL")
		}
		if _, duplicate := seenEndpoints[endpoint.MirrorlistURL]; duplicate {
			return errors.New("receipt repeats an endpoint")
		}
		seenEndpoints[endpoint.MirrorlistURL] = struct{}{}
	}
	return nil
}

func canonicalYUMConsumerReceipt(receipt yumConsumerPreflightReceipt) ([]byte, error) {
	if err := validateYUMConsumerReceiptShape(receipt); err != nil {
		return nil, err
	}
	receipt.PublicationStates = append([]yumConsumerPublicationState(nil), receipt.PublicationStates...)
	sort.Slice(receipt.PublicationStates, func(i, j int) bool {
		return receipt.PublicationStates[i].Target+"\x00"+receipt.PublicationStates[i].View < receipt.PublicationStates[j].Target+"\x00"+receipt.PublicationStates[j].View
	})
	receipt.Endpoints = append([]yumConsumerEndpointEvidence(nil), receipt.Endpoints...)
	sort.Slice(receipt.Endpoints, func(i, j int) bool { return receipt.Endpoints[i].MirrorlistURL < receipt.Endpoints[j].MirrorlistURL })
	body, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func decodeYUMConsumerReceipt(body []byte) (yumConsumerPreflightReceipt, error) {
	var receipt yumConsumerPreflightReceipt
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return receipt, errors.New("receipt contains trailing JSON")
	}
	canonical, err := canonicalYUMConsumerReceipt(receipt)
	if err != nil {
		return receipt, err
	}
	if !bytes.Equal(body, canonical) {
		return receipt, errors.New("receipt is not canonical JSON")
	}
	return receipt, nil
}

func (prepared *yumConsumerPrepared) validateReceipt(receipt yumConsumerPreflightReceipt, now time.Time) error {
	if prepared == nil {
		return errors.New("prepared consumer state is unavailable")
	}
	verifiedAt, verifiedErr := time.Parse(time.RFC3339, receipt.VerifiedAt)
	expiresAt, expiryErr := time.Parse(time.RFC3339, receipt.ExpiresAt)
	if verifiedErr != nil || expiryErr != nil || now.Before(verifiedAt) || !now.Before(expiresAt) {
		return errors.New("receipt is expired or not yet valid")
	}
	if receipt.PlanSHA256 != prepared.planSHA256 || receipt.StagedManifestSHA256 != prepared.stagedManifestSHA256 ||
		receipt.MapSHA256 != prepared.mapSHA256 || receipt.InventorySHA256 != prepared.inventorySHA256 || receipt.ConfigSHA256 != prepared.configSHA256 ||
		receipt.TrustBundleSHA256 != prepared.trustBundleSHA256 || receipt.ConsumerDefinitions != prepared.definitions || receipt.ConsumerBindings != len(prepared.bindings) ||
		receipt.ConsumerBindingsSHA256 != prepared.bindingsSHA256 || !reflect.DeepEqual(receipt.PublicationStates, prepared.states) {
		return errors.New("receipt local plan, config, trust, or canonical publication identity has drifted")
	}
	if len(receipt.Endpoints) != len(prepared.endpoints) {
		return errors.New("receipt endpoint coverage differs from the current plan")
	}
	for index, expected := range prepared.endpoints {
		observed := receipt.Endpoints[index]
		if observed.Target != expected.Target || observed.View != expected.View || observed.Repo != expected.Repo || observed.OS != expected.OS || observed.Arch != expected.Arch ||
			observed.Compression != string(expected.Compression) || observed.MirrorlistURL != expected.MirrorlistURL || observed.GenerationURL != expected.GenerationURL || observed.TrustURL != expected.TrustURL {
			return fmt.Errorf("receipt endpoint %d differs from the current committed route", index)
		}
	}
	if err := requireCanonicalConfigBaseline(prepared.cfg, prepared.canonical); err != nil {
		return fmt.Errorf("canonical config changed during receipt validation: %w", err)
	}
	return nil
}

func installYUMConsumerReceipt(destination string, body []byte, expectedParent os.FileInfo) error {
	if expectedParent == nil || !expectedParent.IsDir() || expectedParent.Mode()&os.ModeSymlink != 0 {
		return errors.New("receipt parent has no bound directory identity")
	}
	abs, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	parent := filepath.Dir(abs)
	_, parentIdentity, err := canonicalYUMConsumerDirectoryIdentity(parent)
	if err != nil || !os.SameFile(expectedParent, parentIdentity) {
		return errors.Join(err, errors.New("receipt parent directory identity changed"))
	}
	if info, err := os.Lstat(abs); err == nil {
		return fmt.Errorf("receipt destination already exists with mode %s", info.Mode())
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".sow-yum-consumer-receipt-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	_, parentIdentity, err = canonicalYUMConsumerDirectoryIdentity(parent)
	if err != nil || !os.SameFile(expectedParent, parentIdentity) {
		return errors.Join(err, errors.New("receipt parent directory identity changed while staging"))
	}
	if err := os.Link(temporaryName, abs); err != nil {
		return err
	}
	_, parentIdentity, err = canonicalYUMConsumerDirectoryIdentity(parent)
	if err != nil || !os.SameFile(expectedParent, parentIdentity) {
		_ = os.Remove(abs)
		return errors.Join(err, errors.New("receipt parent directory identity changed while installing"))
	}
	if err := syncDirectoryPath(parent); err != nil {
		_ = os.Remove(abs)
		return err
	}
	installed, err := readStableRegularLimited(abs, yumConsumerMaximumReceiptBytes)
	if err != nil || !bytes.Equal(installed, body) {
		_ = os.Remove(abs)
		return errors.Join(err, errors.New("installed receipt differs from staged bytes"))
	}
	if err := os.Remove(temporaryName); err != nil {
		_ = os.Remove(abs)
		return err
	}
	removeTemporary = false
	return syncDirectoryPath(parent)
}
