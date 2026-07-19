package serving

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
)

const MaterializedRouteSchema = "sow-local-materialized-route/v2"

// MaterializedRouteTargetSHA256 is the single namespace identity used by
// materialization and read admission. It deliberately hashes only the clean
// lexical absolute coordinate: retained-root binding and component-level
// no-symlink checks prove filesystem authority separately, so neither caller
// may silently substitute EvalSymlinks semantics.
func MaterializedRouteTargetSHA256(target string) (string, error) {
	if target == "" || strings.ContainsRune(target, '\x00') {
		return "", errors.New("materialized route target is empty or contains NUL")
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	digest := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(digest[:]), nil
}

// MaterializedRouteRef freezes one member of the complete canonical ref
// vector used to build a directly hosted route. The vector is strictly sorted
// so omission, duplication, and order-dependent identities fail closed.
type MaterializedRouteRef struct {
	Name         string `json:"name"`
	Commit       string `json:"commit"`
	ManifestBlob string `json:"manifest_blob"`
	ManifestSize int64  `json:"manifest_size"`
}

const (
	MaterializedRouteClaimPrefix     = "prefix"
	MaterializedRouteClaimExactFile  = "exact-file"
	MaterializedRouteClaimGeneration = "generation"
)

// MaterializedRouteClaim describes the physical source set of one emitted
// Nginx route. Prefix owns a complete directory tree, exact-file owns one
// coordinate (used by root-key assets and mirrorlists), and generation owns
// exactly the Nginx generation regex projection for Leaf below RelativeRoot.
// A generation claim scans all generation IDs for that leaf, so an unledgered
// but regex-reachable generation is reported as an added file.
type MaterializedRouteClaim struct {
	Kind         string `json:"kind"`
	RelativeRoot string `json:"relative_root"`
	Leaf         string `json:"leaf,omitempty"`
}

// MaterializedRouteIdentity is the caller-supplied identity for one ordinary
// APT, YUM, or asset route. TargetSHA256 binds the operator-specific absolute
// target without persisting that path. Claims are the complete set of
// capability-relative physical coordinates that Nginx will expose.
type MaterializedRouteIdentity struct {
	Kind         string
	View         string
	Source       string
	TargetSHA256 string
	Claims       []MaterializedRouteClaim
	ConfigSHA256 string
	ConfigCommit string
	// ServingTargetID binds YUM mirrorlist and retained-generation lineage to
	// one canonical local-serving target. APT and asset routes have no such
	// lifecycle and must leave it empty.
	ServingTargetID string
	Repo            string
	OS              string
	Arch            string
	Refs            []MaterializedRouteRef
}

// MaterializedRoute is the canonical admission receipt for one ordinary
// static route. ID is a stable coordinate digest, allowing a later
// materialization of the same route to replace the earlier ledger in place.
// ContentSHA256 binds every frozen input and both manifest byte streams.
type MaterializedRoute struct {
	Schema                string                   `json:"schema"`
	ID                    string                   `json:"id"`
	ContentSHA256         string                   `json:"content_sha256"`
	Kind                  string                   `json:"kind"`
	View                  string                   `json:"view"`
	Source                string                   `json:"source"`
	TargetSHA256          string                   `json:"target_sha256"`
	Claims                []MaterializedRouteClaim `json:"claims"`
	ConfigSHA256          string                   `json:"config_sha256"`
	ConfigCommit          string                   `json:"config_commit"`
	ServingTargetID       string                   `json:"serving_target_id,omitempty"`
	Repo                  string                   `json:"repo"`
	OS                    string                   `json:"os"`
	Arch                  string                   `json:"arch"`
	Refs                  []MaterializedRouteRef   `json:"refs"`
	ExactManifestSHA256   string                   `json:"exact_manifest_sha256"`
	PayloadManifestSHA256 string                   `json:"payload_manifest_sha256"`
}

// NewMaterializedRoute derives a receipt from canonical manifest byte
// streams. Both streams are parsed while hashing, so malformed, unsorted, or
// duplicate manifest entries can never acquire a valid receipt.
func NewMaterializedRoute(identity MaterializedRouteIdentity, exactManifest, payloadManifest io.Reader) (MaterializedRoute, error) {
	var result MaterializedRoute
	if exactManifest == nil || payloadManifest == nil {
		return result, errors.New("materialized route manifests are unavailable")
	}
	exactSHA, err := hashMaterializedRouteManifest(exactManifest)
	if err != nil {
		return result, fmt.Errorf("hash exact route manifest: %w", err)
	}
	payloadSHA, err := hashMaterializedRouteManifest(payloadManifest)
	if err != nil {
		return result, fmt.Errorf("hash payload route manifest: %w", err)
	}
	refs := append([]MaterializedRouteRef(nil), identity.Refs...)
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	claims := append([]MaterializedRouteClaim(nil), identity.Claims...)
	sort.Slice(claims, func(i, j int) bool {
		return materializedRouteClaimKey(claims[i]) < materializedRouteClaimKey(claims[j])
	})
	result = MaterializedRoute{
		Schema: MaterializedRouteSchema, Kind: identity.Kind, View: identity.View,
		Source: identity.Source, TargetSHA256: identity.TargetSHA256,
		Claims: claims, ConfigSHA256: identity.ConfigSHA256, ConfigCommit: identity.ConfigCommit, ServingTargetID: identity.ServingTargetID,
		Repo: identity.Repo, OS: identity.OS, Arch: identity.Arch, Refs: refs,
		ExactManifestSHA256: exactSHA, PayloadManifestSHA256: payloadSHA,
	}
	result.ID, err = materializedRouteCoordinateSHA256(result)
	if err != nil {
		return MaterializedRoute{}, err
	}
	result.ContentSHA256, err = materializedRouteContentSHA256(result)
	if err != nil {
		return MaterializedRoute{}, err
	}
	return result, result.Validate()
}

func hashMaterializedRouteManifest(source io.Reader) (string, error) {
	hasher := sha256.New()
	reader := manifest.NewReader(io.TeeReader(source, hasher))
	for {
		_, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return hex.EncodeToString(hasher.Sum(nil)), nil
		}
		if err != nil {
			return "", err
		}
	}
}

// VerifyMaterializedRouteManifest parses and hashes one manifest stream against
// the digest frozen in a route receipt. It is shared by canonical staging and
// loading; physical-tree validation additionally proves exact scope and CAS
// hardlink identity.
func VerifyMaterializedRouteManifest(source io.Reader, want string) error {
	if source == nil || !hexSHA256Pattern.MatchString(want) {
		return errors.New("invalid materialized route manifest verification input")
	}
	actual, err := hashMaterializedRouteManifest(source)
	if err != nil {
		return err
	}
	if actual != want {
		return fmt.Errorf("materialized route manifest SHA-256=%s want=%s", actual, want)
	}
	return nil
}

func (route MaterializedRoute) Validate() error {
	if route.Schema != MaterializedRouteSchema {
		return errors.New("invalid materialized route schema")
	}
	if route.Kind != "apt" && route.Kind != "yum" && route.Kind != "asset" {
		return fmt.Errorf("invalid materialized route kind %q", route.Kind)
	}
	if route.View != "latest" && route.View != "beta" && route.View != "stable" && route.View != "snapshot" {
		return fmt.Errorf("invalid materialized route view %q", route.View)
	}
	for field, value := range map[string]string{
		"source": route.Source, "repo": route.Repo, "os": route.OS, "arch": route.Arch,
	} {
		if err := config.ValidateRouteSegment(value); err != nil {
			return fmt.Errorf("invalid materialized route %s: %w", field, err)
		}
	}
	if len(route.Claims) == 0 {
		return errors.New("materialized route claims are empty")
	}
	lastClaim := ""
	for index, claim := range route.Claims {
		if err := claim.Validate(); err != nil {
			return fmt.Errorf("invalid materialized route claim at index %d: %w", index, err)
		}
		key := materializedRouteClaimKey(claim)
		if lastClaim != "" && key <= lastClaim {
			return errors.New("materialized route claims are not strictly sorted")
		}
		lastClaim = key
	}
	for field, value := range map[string]string{
		"id": route.ID, "content": route.ContentSHA256, "target": route.TargetSHA256,
		"config": route.ConfigSHA256, "exact manifest": route.ExactManifestSHA256,
		"payload manifest": route.PayloadManifestSHA256,
	} {
		if !hexSHA256Pattern.MatchString(value) {
			return fmt.Errorf("invalid materialized route %s SHA-256", field)
		}
	}
	if len(route.Refs) == 0 {
		return errors.New("materialized route ref vector is empty")
	}
	if !isMaterializedRouteGitHash(route.ConfigCommit) {
		return errors.New("invalid materialized route config commit")
	}
	if route.Kind == "yum" {
		if !hexSHA256Pattern.MatchString(route.ServingTargetID) {
			return errors.New("invalid materialized YUM route serving target ID")
		}
	} else if route.ServingTargetID != "" {
		return errors.New("non-YUM materialized route must not set serving target ID")
	}
	last := ""
	for index, ref := range route.Refs {
		name := plumbing.ReferenceName(ref.Name)
		if !strings.HasPrefix(ref.Name, "refs/sow/") || name.Validate() != nil || !isMaterializedRouteGitHash(ref.Commit) ||
			!isMaterializedRouteGitHash(ref.ManifestBlob) || ref.ManifestSize < 0 {
			return fmt.Errorf("invalid materialized route ref at index %d", index)
		}
		if last != "" && ref.Name <= last {
			return errors.New("materialized route refs are not strictly sorted")
		}
		last = ref.Name
	}
	wantID, err := materializedRouteCoordinateSHA256(route)
	if err != nil || route.ID != wantID {
		return errors.Join(err, errors.New("materialized route ID does not match its coordinate"))
	}
	wantContent, err := materializedRouteContentSHA256(route)
	if err != nil || route.ContentSHA256 != wantContent {
		return errors.Join(err, errors.New("materialized route content digest does not match its frozen inputs"))
	}
	return nil
}

func isMaterializedRouteGitHash(value string) bool {
	// The embedded go-git object model used by SOW is SHA-1 only. Accepting a
	// 64-hex envelope here would be unsafe because plumbing.NewHash truncates it
	// while later route consumers require the exact object identity.
	return len(value) == 40 && gitHashPattern.MatchString(value)
}

func validateMaterializedRouteRelativeRoot(value string) error {
	if value == "" || value == "." || path.IsAbs(value) || path.Clean(value) != value ||
		value == ".." || strings.HasPrefix(value, "../") || strings.ContainsAny(value, "\\\x00\t\r\n") {
		return errors.New("invalid materialized route relative root")
	}
	for _, component := range strings.Split(value, "/") {
		if err := config.ValidateRouteSegment(component); err != nil {
			return fmt.Errorf("invalid materialized route root component %q: %w", component, err)
		}
	}
	return nil
}

func (claim MaterializedRouteClaim) Validate() error {
	if err := validateMaterializedRouteRelativeRoot(claim.RelativeRoot); err != nil {
		return err
	}
	switch claim.Kind {
	case MaterializedRouteClaimPrefix, MaterializedRouteClaimExactFile:
		if claim.Leaf != "" {
			return errors.New("prefix/exact-file materialized route claim must not set leaf")
		}
	case MaterializedRouteClaimGeneration:
		if claim.RelativeRoot != "_sow/v1/g" {
			return errors.New("generation materialized route claim must use _sow/v1/g")
		}
		if err := validateMaterializedRouteRelativeRoot(claim.Leaf); err != nil {
			return fmt.Errorf("invalid generation leaf: %w", err)
		}
	default:
		return fmt.Errorf("invalid materialized route claim kind %q", claim.Kind)
	}
	return nil
}

func materializedRouteClaimKey(claim MaterializedRouteClaim) string {
	return claim.Kind + "\x00" + claim.RelativeRoot + "\x00" + claim.Leaf
}

func materializedRouteCoordinateSHA256(route MaterializedRoute) (string, error) {
	body, err := json.Marshal(struct {
		Schema       string                   `json:"schema"`
		Kind         string                   `json:"kind"`
		View         string                   `json:"view"`
		Source       string                   `json:"source"`
		TargetSHA256 string                   `json:"target_sha256"`
		Claims       []MaterializedRouteClaim `json:"claims"`
		Repo         string                   `json:"repo"`
		OS           string                   `json:"os"`
		Arch         string                   `json:"arch"`
	}{route.Schema, route.Kind, route.View, route.Source, route.TargetSHA256, route.Claims, route.Repo, route.OS, route.Arch})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func materializedRouteContentSHA256(route MaterializedRoute) (string, error) {
	body, err := json.Marshal(struct {
		Schema                string                   `json:"schema"`
		ID                    string                   `json:"id"`
		Kind                  string                   `json:"kind"`
		View                  string                   `json:"view"`
		Source                string                   `json:"source"`
		TargetSHA256          string                   `json:"target_sha256"`
		Claims                []MaterializedRouteClaim `json:"claims"`
		ConfigSHA256          string                   `json:"config_sha256"`
		ConfigCommit          string                   `json:"config_commit"`
		ServingTargetID       string                   `json:"serving_target_id,omitempty"`
		Repo                  string                   `json:"repo"`
		OS                    string                   `json:"os"`
		Arch                  string                   `json:"arch"`
		Refs                  []MaterializedRouteRef   `json:"refs"`
		ExactManifestSHA256   string                   `json:"exact_manifest_sha256"`
		PayloadManifestSHA256 string                   `json:"payload_manifest_sha256"`
	}{
		route.Schema, route.ID, route.Kind, route.View, route.Source, route.TargetSHA256,
		route.Claims, route.ConfigSHA256, route.ConfigCommit, route.ServingTargetID, route.Repo, route.OS, route.Arch,
		route.Refs, route.ExactManifestSHA256, route.PayloadManifestSHA256,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func (route MaterializedRoute) Canonical() ([]byte, error) {
	if err := route.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(route)
}

func DecodeMaterializedRoute(data []byte) (MaterializedRoute, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var route MaterializedRoute
	if err := decoder.Decode(&route); err != nil {
		return route, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return route, errors.New("materialized route JSON has trailing data")
	}
	canonical, err := route.Canonical()
	if err != nil {
		return route, err
	}
	if !bytes.Equal(data, canonical) {
		return route, errors.New("materialized route JSON is not canonical")
	}
	return route, nil
}

func MaterializedRouteReceiptStatePath(route MaterializedRoute) (string, error) {
	if err := route.Validate(); err != nil {
		return "", err
	}
	return path.Join("serving", "materializations", route.TargetSHA256, route.View, "routes", route.ID+".json"), nil
}

func MaterializedRouteTargetStatePrefix(targetSHA256 string) (string, error) {
	if !hexSHA256Pattern.MatchString(targetSHA256) {
		return "", errors.New("invalid materialized route target SHA-256")
	}
	return path.Join("serving", "materializations", targetSHA256) + "/", nil
}

func MaterializedRouteStatePrefix(targetSHA256, view string) (string, error) {
	target, err := MaterializedRouteTargetStatePrefix(targetSHA256)
	if err != nil {
		return "", err
	}
	if view != "latest" && view != "beta" && view != "stable" && view != "snapshot" {
		return "", fmt.Errorf("invalid materialized route view %q", view)
	}
	return path.Join(strings.TrimSuffix(target, "/"), view, "routes") + "/", nil
}

func IsMaterializedRouteReceiptStatePath(value string) bool {
	if !IsMaterializedRouteLedgerStatePath(value) {
		return false
	}
	return strings.HasSuffix(value, ".json")
}

// IsMaterializedRouteLedgerStatePath recognizes only the three files in one
// route receipt triple. Cleanup code uses it to fail closed on unknown state
// rather than deleting future or unrelated canonical records by prefix.
func IsMaterializedRouteLedgerStatePath(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 6 || parts[0] != "serving" || parts[1] != "materializations" ||
		parts[4] != "routes" || !hexSHA256Pattern.MatchString(parts[2]) {
		return false
	}
	if parts[3] != "latest" && parts[3] != "beta" && parts[3] != "stable" && parts[3] != "snapshot" {
		return false
	}
	name := parts[5]
	for _, suffix := range []string{".exact.tsv", ".payload.tsv", ".json"} {
		if strings.HasSuffix(name, suffix) {
			return hexSHA256Pattern.MatchString(strings.TrimSuffix(name, suffix))
		}
	}
	return false
}

func MaterializedRouteExactManifestStatePath(route MaterializedRoute) (string, error) {
	receipt, err := MaterializedRouteReceiptStatePath(route)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(receipt, ".json") + ".exact.tsv", nil
}

func MaterializedRoutePayloadManifestStatePath(route MaterializedRoute) (string, error) {
	receipt, err := MaterializedRouteReceiptStatePath(route)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(receipt, ".json") + ".payload.tsv", nil
}
