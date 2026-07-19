package publish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
)

type ObjectClass string

const (
	ObjectImmutable        ObjectClass = "immutable"
	ObjectAdoptedImmutable ObjectClass = "adopted-immutable"
	ObjectCopyImmutable    ObjectClass = "copy-immutable"
	ObjectReuseImmutable   ObjectClass = "reuse-immutable"
	ObjectLegacyMetadata   ObjectClass = "legacy-metadata"
	ObjectMetadata         ObjectClass = "metadata"
	ObjectPointer          ObjectClass = "pointer"
	ObjectYUMAliasMetadata ObjectClass = "yum-alias-metadata"
	ObjectYUMAliasPointer  ObjectClass = "yum-alias-pointer"
	// ObjectCompatibilityRollbackMetadata and
	// ObjectCompatibilityRollbackPointer are reserved for restoring one frozen
	// cross-EL raw route to its byte-exact S0 carrier baseline. S0 intentionally
	// predates SOW's signed repomd pair, so its non-pointer repodata must be
	// installed before the sole legacy repomd.xml commit point. These classes are
	// mutable/replayable and must never be used for immutable generation history.
	ObjectCompatibilityRollbackMetadata ObjectClass = "compatibility-rollback-metadata"
	ObjectCompatibilityRollbackPointer  ObjectClass = "compatibility-rollback-pointer"
)

type PlannedObject struct {
	SourcePath         string      `json:"source_path"`
	RemoteKey          string      `json:"remote_key"`
	Size               int64       `json:"size"`
	SHA256             string      `json:"sha256"`
	Class              ObjectClass `json:"class"`
	CDNPath            string      `json:"cdn_path,omitempty"`
	VerificationSize   int64       `json:"verification_size,omitempty"`
	VerificationSHA256 string      `json:"verification_sha256,omitempty"`
	CopySource         string      `json:"copy_source,omitempty"`
}

type VerifyObject struct {
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// VerifyAbsentObject is a plan-bound negative CDN expectation. The saga
// accepts only HTTP 404 or 410 for this exact URL after the corresponding
// snapshot-owned object has been deleted and its route purged.
type VerifyAbsentObject struct {
	URL string `json:"url"`
}

type DeleteClass string

const (
	// DeleteSnapshotOwned is the only delete class whose legacy encoding may
	// omit class/source/digest fields. That preserves replay of v1 snapshot
	// retention journals created before delete classes were introduced.
	DeleteSnapshotOwned DeleteClass = "snapshot-owned"
	// DeleteAssetServing removes only the directly served projection of an
	// asset removed from the selected view. Its content-addressed archive and
	// Git/CAS history deliberately remain available for forward-only restore.
	DeleteAssetServing DeleteClass = "asset-serving"
	// DeleteAPTByHash removes an immutable APT by-hash object whose sealed
	// canonical retention ledger no longer retains the generation.
	DeleteAPTByHash DeleteClass = "apt-by-hash"
	// DeleteRestoreIndexServing is limited to beta/latest repository entry
	// metadata (APT dists, YUM repodata, or a public YUM mirrorlist) removed by a
	// forward historical restore. Package payloads and immutable generation
	// archives are deliberately outside this class.
	DeleteRestoreIndexServing DeleteClass = "restore-index-serving"
	// DeleteCompatibilityServing is the rollback-only authority for an active
	// latest cross-EL bridge. It can remove its public mirrorlist, two frozen
	// trust URLs, and S3-only raw candidate extras under one compatibility YUM
	// route. Immutable generation archives remain deliberately outside it.
	DeleteCompatibilityServing DeleteClass = "compatibility-serving"
)

// PlannedDelete is an evidence-bound, closed-union remote mutation. Removed
// manifest paths never become deletions implicitly: a caller must prove one
// of the three authorized ownership classes and bind the old source path,
// remote key, size, and digest where that class has content evidence.
type PlannedDelete struct {
	Class      DeleteClass `json:"class,omitempty"`
	SourcePath string      `json:"source_path,omitempty"`
	RemoteKey  string      `json:"remote_key"`
	Size       int64       `json:"size,omitempty"`
	SHA256     string      `json:"sha256,omitempty"`
	CDNPath    string      `json:"cdn_path,omitempty"`
}

// Classifier maps one changed manifest entry to its remote key and publish
// class. APT by-hash and YUM generation metadata should map to immutable or
// metadata keys; only the coherent mutable entry point maps to ObjectPointer.
type Classifier func(manifest.Entry) (remoteKey string, class ObjectClass, err error)

// IdentityClassifier is safe for asset repositories whose keys are already
// immutable. Indexed repositories must supply an explicit classifier.
func IdentityClassifier(entry manifest.Entry) (string, ObjectClass, error) {
	return entry.Path, ObjectImmutable, nil
}

type Plan struct {
	Schema       string               `json:"schema"`
	CDNBaseURL   string               `json:"cdn_base_url,omitempty"`
	Objects      []PlannedObject      `json:"objects"`
	Deletes      []PlannedDelete      `json:"deletes,omitempty"`
	Removed      []string             `json:"removed"`
	PurgeURLs    []string             `json:"purge_urls"`
	Verify       []VerifyObject       `json:"verify"`
	Probes       []VerifyObject       `json:"probes,omitempty"`
	VerifyAbsent []VerifyAbsentObject `json:"verify_absent,omitempty"`
	Stats        manifest.DiffStats   `json:"stats"`
}

const planSchema = "sow-publish-plan/v1"

// BuildPlan performs one streaming merge-diff. Its memory is proportional to
// changed entries only; unchanged repository entries are never retained.
// Removed keys remain remotely reachable for rollback and are recorded but
// never translated into delete operations.
func BuildPlan(oldManifest, desiredManifest io.Reader, classify Classifier) (Plan, error) {
	if oldManifest == nil || desiredManifest == nil {
		return Plan{}, errors.New("publish plan requires both manifest readers")
	}
	if classify == nil {
		return Plan{}, errors.New("publish plan requires an explicit classifier")
	}
	plan := Plan{Schema: planSchema}
	stats, err := manifest.Diff(oldManifest, desiredManifest, func(change manifest.Change) error {
		if change.Kind == manifest.Removed {
			plan.Removed = append(plan.Removed, change.Path())
			return nil
		}
		entry := *change.New
		remoteKey, class, err := classify(entry)
		if err != nil {
			return fmt.Errorf("classify %s: %w", entry.Path, err)
		}
		if err := validateRoutableRemoteKey(remoteKey); err != nil {
			return fmt.Errorf("classify %s: %w", entry.Path, err)
		}
		if err := validateObjectClass(class); err != nil {
			return fmt.Errorf("classify %s: unknown object class %q", entry.Path, class)
		}
		if change.Kind == manifest.Changed && remoteKey == entry.Path && class != ObjectPointer && class != ObjectLegacyMetadata && class != ObjectYUMAliasMetadata && class != ObjectYUMAliasPointer && class != ObjectCompatibilityRollbackMetadata && class != ObjectCompatibilityRollbackPointer {
			return fmt.Errorf("classify %s: an occupied mutable path requires an explicit pointer or a new content-addressed remote key", entry.Path)
		}
		plan.Objects = append(plan.Objects, PlannedObject{
			SourcePath: entry.Path, RemoteKey: remoteKey, Size: entry.Size,
			SHA256: entry.HashString(), Class: class,
		})
		return nil
	})
	if err != nil {
		return Plan{}, err
	}
	plan.Stats = stats
	if err := plan.sortAndValidate(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// WithCDN closes the mandatory minimal purge and L3 verification sets. Purge
// is derived only from the closed pointer-class union; immutable and metadata
// objects can never accidentally expand it. Verification covers every changed
// object.
func (p Plan) WithCDN(baseURL string) (Plan, error) {
	base, canonicalBase, err := parseCDNBaseURL(baseURL, false)
	if err != nil {
		return Plan{}, err
	}
	// A Plan is a value. Detach every caller-owned slice before normalization
	// sorts it so repeated or concurrent closure derivation cannot mutate the
	// original plan through a shared backing array.
	p.Objects = append([]PlannedObject(nil), p.Objects...)
	p.Deletes = append([]PlannedDelete(nil), p.Deletes...)
	p.Removed = append([]string(nil), p.Removed...)
	p.Probes = append([]VerifyObject(nil), p.Probes...)
	p.CDNBaseURL = canonicalBase
	p.PurgeURLs = nil
	p.Verify = nil
	p.VerifyAbsent = nil
	for _, object := range p.Objects {
		cdnPath, verifySize, verifySHA, err := object.cdnExpectation()
		if err != nil {
			return Plan{}, fmt.Errorf("derive CDN expectation for %s class=%s explicit_path=%q: %w", object.RemoteKey, object.Class, object.CDNPath, err)
		}
		u := joinCDNURL(base, cdnPath)
		if isPointerClass(object.Class) {
			for _, purgePath := range requiredObjectPurgePaths(object, cdnPath) {
				p.PurgeURLs = append(p.PurgeURLs, joinCDNURL(base, purgePath))
			}
		}
		p.Verify = append(p.Verify, VerifyObject{URL: u, Size: verifySize, SHA256: verifySHA})
	}
	for _, deletion := range p.Deletes {
		if deletion.CDNPath != "" {
			for _, purgePath := range requiredDeletePurgePaths(deletion) {
				p.PurgeURLs = append(p.PurgeURLs, joinCDNURL(base, purgePath))
			}
			p.VerifyAbsent = append(p.VerifyAbsent, VerifyAbsentObject{URL: joinCDNURL(base, deletion.CDNPath)})
		}
	}
	if err := p.sortAndValidate(); err != nil {
		return Plan{}, err
	}
	return p, nil
}

func (p *Plan) sortAndValidate() error {
	if p.Schema == "" {
		p.Schema = planSchema
	}
	if p.Schema != planSchema {
		return fmt.Errorf("publish plan schema %q is not %q", p.Schema, planSchema)
	}
	sort.Slice(p.Objects, func(i, j int) bool {
		if p.Objects[i].Class != p.Objects[j].Class {
			return p.Objects[i].Class < p.Objects[j].Class
		}
		return p.Objects[i].RemoteKey < p.Objects[j].RemoteKey
	})
	remoteKeys := make(map[string]struct{}, len(p.Objects))
	objectsByRemoteKey := make(map[string]PlannedObject, len(p.Objects))
	pointers := make(map[string]struct{})
	for _, object := range p.Objects {
		if err := validateObjectClass(object.Class); err != nil {
			return fmt.Errorf("invalid planned object %s: %w", object.RemoteKey, err)
		}
		if err := validateRoutableRemoteKey(object.SourcePath); err != nil {
			return fmt.Errorf("invalid source path: %w", err)
		}
		if err := validateRoutableRemoteKey(object.RemoteKey); err != nil {
			return err
		}
		if err := validatePlannedRemoteKey(object.RemoteKey, object.Class); err != nil {
			return err
		}
		if object.Size < 0 || !hexSHA256Pattern.MatchString(object.SHA256) {
			return fmt.Errorf("invalid planned object %s", object.RemoteKey)
		}
		if object.Class == ObjectCopyImmutable {
			if err := validateSnapshotCopy(object.RemoteKey, object.CopySource); err != nil {
				return err
			}
		} else if object.CopySource != "" {
			return fmt.Errorf("non-copy object %s carries a copy source", object.RemoteKey)
		}
		if object.CDNPath != "" {
			if err := validateRoutableRemoteKey(object.CDNPath); err != nil {
				return fmt.Errorf("invalid CDN path for %s: %w", object.RemoteKey, err)
			}
			if containsBearerCredential("/" + object.CDNPath) {
				return fmt.Errorf("CDN path for %s must not contain a bearer credential", object.RemoteKey)
			}
		}
		if object.VerificationSHA256 != "" {
			if !hexSHA256Pattern.MatchString(object.VerificationSHA256) || object.VerificationSize < 0 || object.CDNPath == "" {
				return fmt.Errorf("invalid transformed CDN verification for %s", object.RemoteKey)
			}
			if object.Class != ObjectPointer || !strings.HasPrefix(object.RemoteKey, ".sow/channels/") {
				return fmt.Errorf("transformed CDN verification is reserved for a canonical channel pointer: %s", object.RemoteKey)
			}
		} else if object.VerificationSize != 0 {
			return fmt.Errorf("verification size override for %s requires a verification digest", object.RemoteKey)
		}
		if strings.HasPrefix(object.RemoteKey, ".sow/channels/") && (object.CDNPath == "" || object.VerificationSHA256 == "") {
			return fmt.Errorf("channel pointer %s requires an explicit transformed CDN path and verification digest", object.RemoteKey)
		}
		if match := aptByHashPattern.FindStringSubmatch(object.RemoteKey); len(match) != 0 {
			if object.Class != ObjectImmutable && object.Class != ObjectAdoptedImmutable && object.Class != ObjectMetadata {
				return fmt.Errorf("APT by-hash object %s must be create-only", object.RemoteKey)
			}
			if match[1] != object.SHA256 {
				return fmt.Errorf("APT by-hash key %s does not match its content digest", object.RemoteKey)
			}
		}
		if _, duplicate := remoteKeys[object.RemoteKey]; duplicate {
			return fmt.Errorf("duplicate remote key %s", object.RemoteKey)
		}
		remoteKeys[object.RemoteKey] = struct{}{}
		objectsByRemoteKey[object.RemoteKey] = object
		if isPointerClass(object.Class) {
			pointers[object.RemoteKey] = struct{}{}
		}
	}
	sort.Slice(p.Deletes, func(i, j int) bool { return p.Deletes[i].RemoteKey < p.Deletes[j].RemoteKey })
	deletePaths := make(map[string]string, len(p.Deletes))
	for index, deletion := range p.Deletes {
		if err := validatePlannedDelete(deletion); err != nil {
			return err
		}
		if index != 0 && p.Deletes[index-1].RemoteKey == deletion.RemoteKey {
			return fmt.Errorf("duplicate planned deletion %s", deletion.RemoteKey)
		}
		if _, collision := remoteKeys[deletion.RemoteKey]; collision {
			return fmt.Errorf("remote key %s is both written and deleted", deletion.RemoteKey)
		}
		if deletion.CDNPath != "" {
			if existing, collision := deletePaths[deletion.CDNPath]; collision {
				return fmt.Errorf("deletions %s and %s collide at CDN path %s", existing, deletion.RemoteKey, deletion.CDNPath)
			}
			deletePaths[deletion.CDNPath] = deletion.RemoteKey
		}
	}
	aptPointers := make(map[string]struct{})
	for _, object := range p.Objects {
		if object.Class == ObjectPointer && aptInReleasePattern.MatchString(object.RemoteKey) {
			root, _ := aptDistributionRoot(object.RemoteKey)
			aptPointers[root] = struct{}{}
		}
	}
	for _, object := range p.Objects {
		if object.Class != ObjectLegacyMetadata {
			continue
		}
		root, ok := aptDistributionRoot(object.RemoteKey)
		if !ok {
			return fmt.Errorf("legacy APT metadata key %s has no distribution root", object.RemoteKey)
		}
		if _, exists := aptPointers[root]; !exists {
			return fmt.Errorf("legacy APT metadata %s requires %sInRelease as the final pointer", object.RemoteKey, root)
		}
	}
	for _, object := range p.Objects {
		if object.Class == ObjectYUMAliasMetadata {
			index := strings.LastIndex(object.RemoteKey, "/repodata/")
			if index < 0 {
				return fmt.Errorf("YUM alias metadata %s has no repodata root", object.RemoteKey)
			}
			root := object.RemoteKey[:index] + "/repodata/repomd.xml"
			xml, xmlExists := objectsByRemoteKey[root]
			asc, ascExists := objectsByRemoteKey[root+".asc"]
			if !xmlExists || !ascExists || xml.Class != ObjectYUMAliasPointer || asc.Class != ObjectYUMAliasPointer {
				return fmt.Errorf("YUM alias metadata %s requires a complete repomd.xml+asc commit pair", object.RemoteKey)
			}
		}
		if object.Class == ObjectCompatibilityRollbackMetadata {
			index := strings.LastIndex(object.RemoteKey, "/repodata/")
			if index < 0 {
				return fmt.Errorf("compatibility rollback metadata %s has no repodata root", object.RemoteKey)
			}
			root := object.RemoteKey[:index] + "/repodata/repomd.xml"
			pointer, exists := objectsByRemoteKey[root]
			if !exists || pointer.Class != ObjectCompatibilityRollbackPointer {
				return fmt.Errorf("compatibility rollback metadata %s requires the exact S0 repomd.xml commit point", object.RemoteKey)
			}
		}
		var counterpart string
		switch {
		case strings.HasSuffix(object.RemoteKey, "/repodata/repomd.xml"):
			counterpart = object.RemoteKey + ".asc"
		case strings.HasSuffix(object.RemoteKey, "/repodata/repomd.xml.asc"):
			counterpart = strings.TrimSuffix(object.RemoteKey, ".asc")
		default:
			continue
		}
		if object.Class == ObjectCompatibilityRollbackPointer {
			if strings.HasSuffix(object.RemoteKey, ".asc") {
				return fmt.Errorf("compatibility rollback pointer %s must be the unsigned S0 repomd.xml", object.RemoteKey)
			}
			continue
		}
		generationPair := object.Class == ObjectMetadata && yumGenerationKeyPattern.MatchString(object.RemoteKey)
		legacyPair := object.Class == ObjectYUMAliasPointer && !yumGenerationKeyPattern.MatchString(object.RemoteKey)
		if !generationPair && !legacyPair {
			return fmt.Errorf("YUM repomd pair member %s must use immutable generation metadata or the explicit alias pair, never a mutable pointer", object.RemoteKey)
		}
		paired, exists := objectsByRemoteKey[counterpart]
		if !exists || paired.Class != object.Class {
			return fmt.Errorf("YUM repomd publish requires complete xml+asc pair: missing %s", counterpart)
		}
	}
	sort.Strings(p.Removed)
	for i, value := range p.Removed {
		if err := validateRoutableRemoteKey(value); err != nil {
			return fmt.Errorf("invalid removed key: %w", err)
		}
		if i != 0 && p.Removed[i-1] == value {
			return fmt.Errorf("duplicate removed key %s", value)
		}
	}
	var cdnBase *url.URL
	if p.CDNBaseURL != "" {
		var canonical string
		var err error
		cdnBase, canonical, err = parseCDNBaseURL(p.CDNBaseURL, false)
		if err != nil {
			return err
		}
		if canonical != p.CDNBaseURL {
			return errors.New("CDN base URL is not canonical")
		}
	} else if len(p.PurgeURLs) != 0 || len(p.Verify) != 0 || len(p.Probes) != 0 || len(p.VerifyAbsent) != 0 {
		return errors.New("purge and verification URLs require an explicit CDN base URL")
	}
	type verificationBinding struct {
		remoteKey string
		size      int64
		sha256    string
	}
	cdnPaths := make(map[string]string, len(p.Objects))
	expectedVerificationByURL := make(map[string]verificationBinding, len(p.Objects))
	if cdnBase != nil {
		for _, object := range p.Objects {
			cdnPath, verifySize, verifySHA, err := object.cdnExpectation()
			if err != nil {
				return fmt.Errorf("validate CDN expectation for %s class=%s explicit_path=%q: %w", object.RemoteKey, object.Class, object.CDNPath, err)
			}
			if isPointerClass(object.Class) {
				if err := validatePointerCDNBinding(cdnBase, object, cdnPath); err != nil {
					return err
				}
			}
			if existing, duplicate := cdnPaths[cdnPath]; duplicate {
				return fmt.Errorf("remote keys %s and %s collide at CDN path %s", existing, object.RemoteKey, cdnPath)
			}
			cdnPaths[cdnPath] = object.RemoteKey
			expectedVerificationByURL[joinCDNURL(cdnBase, cdnPath)] = verificationBinding{
				remoteKey: object.RemoteKey, size: verifySize, sha256: verifySHA,
			}
		}
		for deletePath, deleteKey := range deletePaths {
			if objectKey, collision := cdnPaths[deletePath]; collision {
				return fmt.Errorf("CDN path %s is both written by %s and deleted by %s", deletePath, objectKey, deleteKey)
			}
		}
	}
	sort.Strings(p.PurgeURLs)
	mandatoryPurgeURLs := make(map[string]string, len(pointers)*2+len(deletePaths)*2)
	if cdnBase != nil {
		for pointer := range pointers {
			object := objectsByRemoteKey[pointer]
			cdnPath, _, _, err := object.cdnExpectation()
			if err != nil {
				return err
			}
			for _, purgePath := range requiredObjectPurgePaths(object, cdnPath) {
				identity := "pointer:" + pointer + "@" + purgePath
				purgeURL := joinCDNURL(cdnBase, purgePath)
				if existing, collision := mandatoryPurgeURLs[purgeURL]; collision {
					return fmt.Errorf("%s collides with %s at purge path %s", identity, existing, purgePath)
				}
				mandatoryPurgeURLs[purgeURL] = identity
			}
		}
		for _, deletion := range p.Deletes {
			if deletion.CDNPath == "" {
				continue
			}
			for _, purgePath := range requiredDeletePurgePaths(deletion) {
				identity := "delete:" + deletion.RemoteKey + "@" + purgePath
				purgeURL := joinCDNURL(cdnBase, purgePath)
				if existing, collision := mandatoryPurgeURLs[purgeURL]; collision {
					return fmt.Errorf("%s collides with %s at purge path %s", identity, existing, purgePath)
				}
				mandatoryPurgeURLs[purgeURL] = identity
			}
		}
	}
	matchedPurge := make(map[string]struct{}, len(mandatoryPurgeURLs))
	for i, value := range p.PurgeURLs {
		if i != 0 && p.PurgeURLs[i-1] == value {
			return fmt.Errorf("duplicate purge URL %s", value)
		}
		matched, exists := mandatoryPurgeURLs[value]
		if !exists {
			return fmt.Errorf("purge URL %q is not a planned pointer or routed deletion", value)
		}
		if _, duplicate := matchedPurge[matched]; duplicate {
			return fmt.Errorf("multiple purge URLs map to %s", matched)
		}
		matchedPurge[matched] = struct{}{}
	}
	if cdnBase != nil && len(matchedPurge) != len(mandatoryPurgeURLs) {
		return errors.New("purge set does not cover every planned pointer and routed deletion")
	}
	sort.Slice(p.Verify, func(i, j int) bool { return p.Verify[i].URL < p.Verify[j].URL })
	verifiedObjects := make(map[string]struct{}, len(p.Objects))
	for i, verify := range p.Verify {
		if verify.Size < 0 || !hexSHA256Pattern.MatchString(verify.SHA256) {
			return fmt.Errorf("invalid verification expectation %q", verify.URL)
		}
		if i != 0 && p.Verify[i-1].URL == verify.URL {
			return fmt.Errorf("duplicate verification URL %s", verify.URL)
		}
		binding, matched := expectedVerificationByURL[verify.URL]
		if !matched || verify.Size != binding.size || verify.SHA256 != binding.sha256 {
			return fmt.Errorf("verification URL %q does not match a planned object", verify.URL)
		}
		if _, duplicate := verifiedObjects[binding.remoteKey]; duplicate {
			return fmt.Errorf("multiple verification URLs map to %s", binding.remoteKey)
		}
		verifiedObjects[binding.remoteKey] = struct{}{}
	}
	if cdnBase != nil && len(verifiedObjects) != len(p.Objects) {
		return errors.New("verification set does not cover every planned object")
	}
	if len(p.Probes) > 1 {
		return errors.New("a publication plan may carry at most one unchanged CDN probe")
	}
	sort.Slice(p.Probes, func(i, j int) bool { return p.Probes[i].URL < p.Probes[j].URL })
	for index, probe := range p.Probes {
		if probe.Size < 0 || !hexSHA256Pattern.MatchString(probe.SHA256) {
			return fmt.Errorf("invalid unchanged verification probe %q", probe.URL)
		}
		if _, err := validateCDNTarget(cdnBase, probe.URL); err != nil {
			return fmt.Errorf("unchanged verification probe %q is outside the CDN base", probe.URL)
		}
		if index != 0 && p.Probes[index-1].URL == probe.URL {
			return fmt.Errorf("duplicate unchanged verification probe %s", probe.URL)
		}
		if _, changed := expectedVerificationByURL[probe.URL]; changed {
			return fmt.Errorf("unchanged verification probe %s duplicates a changed object expectation", probe.URL)
		}
	}
	sort.Slice(p.VerifyAbsent, func(i, j int) bool { return p.VerifyAbsent[i].URL < p.VerifyAbsent[j].URL })
	verifiedDeletions := make(map[string]struct{}, len(deletePaths))
	deletionsByURL := make(map[string]string, len(deletePaths))
	if cdnBase != nil {
		for cdnPath, remoteKey := range deletePaths {
			deletionsByURL[joinCDNURL(cdnBase, cdnPath)] = remoteKey
		}
	}
	for index, expectation := range p.VerifyAbsent {
		if index != 0 && p.VerifyAbsent[index-1].URL == expectation.URL {
			return fmt.Errorf("duplicate absence verification URL %s", expectation.URL)
		}
		for _, probe := range p.Probes {
			if probe.URL == expectation.URL {
				return fmt.Errorf("CDN URL %s cannot require both presence and absence", expectation.URL)
			}
		}
		if _, present := expectedVerificationByURL[expectation.URL]; present {
			return fmt.Errorf("CDN URL %s cannot require both presence and absence", expectation.URL)
		}
		matched, exists := deletionsByURL[expectation.URL]
		if !exists {
			return fmt.Errorf("absence verification URL %q does not match a routed deletion", expectation.URL)
		}
		if _, duplicate := verifiedDeletions[matched]; duplicate {
			return fmt.Errorf("multiple absence verification URLs map to %s", matched)
		}
		verifiedDeletions[matched] = struct{}{}
	}
	if cdnBase != nil && len(verifiedDeletions) != len(deletePaths) {
		return errors.New("absence verification set does not cover every routed deletion")
	}
	return nil
}

func isPointerClass(class ObjectClass) bool {
	return class == ObjectPointer || class == ObjectYUMAliasPointer || class == ObjectCompatibilityRollbackPointer
}

func isCreateOnlyClass(class ObjectClass) bool {
	switch class {
	case ObjectImmutable, ObjectAdoptedImmutable, ObjectCopyImmutable, ObjectReuseImmutable:
		return true
	default:
		return false
	}
}

func validateObjectClass(class ObjectClass) error {
	switch class {
	case ObjectImmutable, ObjectAdoptedImmutable, ObjectCopyImmutable, ObjectReuseImmutable,
		ObjectLegacyMetadata, ObjectMetadata, ObjectPointer, ObjectYUMAliasMetadata, ObjectYUMAliasPointer,
		ObjectCompatibilityRollbackMetadata, ObjectCompatibilityRollbackPointer:
		return nil
	default:
		return fmt.Errorf("unknown object class %q", class)
	}
}

// validatePointerCDNBinding closes the mutable route union before a plan can
// be persisted. Immutable snapshot objects may legitimately have an
// intent-specific alternate read route, but every pointer namespace has a
// mechanically derivable client entry point. Internal clean-cache keys always
// live at the CDN origin root; a path-prefixed base could only purge the wrong
// `/<prefix>/.sow/...` URL and is therefore rejected for routed pointers.
func validatePointerCDNBinding(base *url.URL, object PlannedObject, cdnPath string) error {
	remoteKey := object.RemoteKey
	if strings.HasPrefix(remoteKey, ".sow/") && base.Path != "/" {
		return fmt.Errorf("routed pointer %s requires an origin-root CDN base for its clean cache key", remoteKey)
	}
	want := ""
	switch {
	case strings.HasPrefix(remoteKey, ".sow/beta/"):
		want = strings.TrimPrefix(remoteKey, ".sow/beta/")
	case strings.HasPrefix(remoteKey, ".sow/channels/"):
		var err error
		want, err = channelPointerCDNPath(remoteKey)
		if err != nil {
			return err
		}
	case strings.HasPrefix(remoteKey, ".sow/snapshots/"):
		var err error
		want, err = snapshotRouteCDNPath(remoteKey)
		if err != nil {
			return err
		}
	case strings.HasPrefix(remoteKey, ".sow/gated/snapshots/"):
		var err error
		want, err = directSnapshotObjectCDNPath(remoteKey)
		if err != nil {
			return err
		}
	case strings.HasPrefix(remoteKey, ".sow/gated/generations/"):
		strong, err := generationStrongCDNPath(remoteKey)
		if err != nil {
			return err
		}
		if cdnPath == strong || validGenerationSnapshotCDNPath(remoteKey, cdnPath) {
			return nil
		}
		return fmt.Errorf("pointer %s has CDN path %q, want %q or its exact snapshot route", remoteKey, cdnPath, strong)
	case strings.HasPrefix(remoteKey, ".sow/gated/"):
		logical := strings.TrimPrefix(remoteKey, ".sow/gated/")
		if logical == "" || strings.HasPrefix(logical, ".sow/") || strings.HasPrefix(logical, ".pool/") {
			return fmt.Errorf("gated pointer %s has no safe client route", remoteKey)
		}
		want = path.Join("pro/v1/basic", logical)
	case strings.HasPrefix(remoteKey, ".sow/generations/"):
		var err error
		want, err = generationStrongCDNPath(remoteKey)
		if err != nil {
			return err
		}
	case strings.HasPrefix(remoteKey, ".sow/"):
		return fmt.Errorf("pointer control key %s has no canonical client route", remoteKey)
	default:
		want = remoteKey
	}
	if cdnPath != want {
		return fmt.Errorf("pointer %s has CDN path %q, want %q", remoteKey, cdnPath, want)
	}
	return nil
}

func generationRemoteParts(remoteKey string) (gated bool, generation, kind, tail string, err error) {
	prefix := ".sow/generations/"
	if strings.HasPrefix(remoteKey, ".sow/gated/generations/") {
		gated = true
		prefix = ".sow/gated/generations/"
	} else if !strings.HasPrefix(remoteKey, prefix) {
		return false, "", "", "", fmt.Errorf("remote key %s is not a generation object", remoteKey)
	}
	parts := strings.SplitN(strings.TrimPrefix(remoteKey, prefix), "/", 3)
	if len(parts) != 3 || len(parts[0]) != 20 || !allASCIIDigits(parts[0]) ||
		(parts[1] != "apt" && parts[1] != "yum") || parts[2] == "" {
		return false, "", "", "", fmt.Errorf("generation remote key %s is not canonical", remoteKey)
	}
	return gated, parts[0], parts[1], parts[2], nil
}

func generationStrongCDNPath(remoteKey string) (string, error) {
	gated, generation, kind, tail, err := generationRemoteParts(remoteKey)
	if err != nil {
		return "", err
	}
	routeKind := map[string]string{"apt": "a", "yum": "g"}[kind]
	prefix := ""
	if gated {
		prefix = "pro/v1/basic"
	}
	return path.Join(prefix, "_sow/v1", routeKind, generation, tail), nil
}

func validGenerationSnapshotCDNPath(remoteKey, cdnPath string) bool {
	gated, _, kind, tail, err := generationRemoteParts(remoteKey)
	if err != nil || !gated {
		return false
	}
	const prefix = "pro/v1/basic/_sow/v1/snapshots/"
	if !strings.HasPrefix(cdnPath, prefix) {
		return false
	}
	parts := strings.SplitN(strings.TrimPrefix(cdnPath, prefix), "/", 3)
	return len(parts) == 3 && ValidatePublicationIntent("snapshot", parts[0]) == nil && parts[1] == kind && parts[2] == tail
}

func channelPointerCDNPath(remoteKey string) (string, error) {
	parts := strings.Split(remoteKey, "/")
	if len(parts) != 6 || parts[0] != ".sow" || parts[1] != "channels" || parts[2] != "stable" ||
		parts[3] == "" || parts[4] == "" || !strings.HasSuffix(parts[5], ".json") || strings.TrimSuffix(parts[5], ".json") == "" {
		return "", fmt.Errorf("channel pointer %s is not a canonical stable channel", remoteKey)
	}
	return path.Join("pro/v1/basic/_sow/v1/mirrorlist", parts[2], parts[3], parts[4], strings.TrimSuffix(parts[5], ".json")+".txt"), nil
}

func snapshotRouteCDNPath(remoteKey string) (string, error) {
	if !strings.HasPrefix(remoteKey, ".sow/snapshots/") || !strings.HasSuffix(remoteKey, ".json") {
		return "", fmt.Errorf("snapshot route key %s is not canonical", remoteKey)
	}
	id := strings.TrimSuffix(strings.TrimPrefix(remoteKey, ".sow/snapshots/"), ".json")
	if strings.Contains(id, "/") || ValidatePublicationIntent("snapshot", id) != nil {
		return "", fmt.Errorf("snapshot route key %s has an invalid snapshot ID", remoteKey)
	}
	return path.Join("pro/v1/basic/_sow/v1/snapshots", id, "_route.json"), nil
}

func directSnapshotObjectCDNPath(remoteKey string) (string, error) {
	const prefix = ".sow/gated/snapshots/"
	parts := strings.SplitN(strings.TrimPrefix(remoteKey, prefix), "/", 3)
	if len(parts) != 3 || ValidatePublicationIntent("snapshot", parts[0]) != nil || parts[2] == "" {
		return "", fmt.Errorf("snapshot object key %s is not canonical", remoteKey)
	}
	kind := parts[1]
	if kind == "asset" {
		kind = "assets"
	} else if kind != "yum" {
		return "", fmt.Errorf("snapshot object key %s has unsupported kind %s", remoteKey, parts[1])
	}
	return path.Join("pro/v1/basic/_sow/v1/snapshots", parts[0], kind, parts[2]), nil
}

// requiredObjectPurgePaths returns the complete cache invalidation closure for
// one mutable publication entry point. CDNPath is the client-facing URL that
// must remain the post-publish verification surface. Private and beta edge
// routes deliberately fetch the object again through a credential-free
// internal URL whose path is the exact .sow remote key; that clean URL is a
// distinct CDN cache key and must be purged in the same publish transaction.
// Public latest pointers already use their remote key as CDNPath, so they keep
// the historical one-URL purge contract.
func requiredObjectPurgePaths(object PlannedObject, cdnPath string) []string {
	paths := []string{cdnPath}
	if strings.HasPrefix(object.RemoteKey, ".sow/") && object.RemoteKey != cdnPath {
		paths = append(paths, object.RemoteKey)
	}
	return paths
}

// requiredDeletePurgePaths mirrors requiredObjectPurgePaths for a routed
// deletion. Absence is still verified only at the client-facing CDNPath; the
// extra internal URL is invalidation work, not a public API or verification
// route.
func requiredDeletePurgePaths(deletion PlannedDelete) []string {
	paths := []string{deletion.CDNPath}
	if strings.HasPrefix(deletion.RemoteKey, ".sow/") && deletion.RemoteKey != deletion.CDNPath {
		paths = append(paths, deletion.RemoteKey)
	}
	return paths
}

func (p Plan) Canonical() ([]byte, error) {
	copyPlan, err := p.normalized()
	if err != nil {
		return nil, err
	}
	return json.Marshal(copyPlan)
}

func (p Plan) normalized() (Plan, error) {
	copyPlan := p
	copyPlan.Objects = append([]PlannedObject(nil), p.Objects...)
	copyPlan.Deletes = append([]PlannedDelete(nil), p.Deletes...)
	copyPlan.Removed = append([]string(nil), p.Removed...)
	copyPlan.PurgeURLs = append([]string(nil), p.PurgeURLs...)
	copyPlan.Verify = append([]VerifyObject(nil), p.Verify...)
	copyPlan.Probes = append([]VerifyObject(nil), p.Probes...)
	copyPlan.VerifyAbsent = append([]VerifyAbsentObject(nil), p.VerifyAbsent...)
	if err := copyPlan.sortAndValidate(); err != nil {
		return Plan{}, err
	}
	return copyPlan, nil
}

func validatePlannedDelete(deletion PlannedDelete) error {
	if err := validateRoutableRemoteKey(deletion.RemoteKey); err != nil {
		return fmt.Errorf("invalid planned deletion: %w", err)
	}
	class := deletion.Class
	if class == "" {
		class = DeleteSnapshotOwned
	}
	switch class {
	case DeleteSnapshotOwned:
		return validateSnapshotDelete(deletion)
	case DeleteAssetServing:
		return validateAssetServingDelete(deletion)
	case DeleteAPTByHash:
		return validateAPTByHashDelete(deletion)
	case DeleteRestoreIndexServing:
		return validateRestoreIndexServingDelete(deletion)
	case DeleteCompatibilityServing:
		return validateCompatibilityServingDelete(deletion)
	default:
		return fmt.Errorf("unsupported deletion class %q", deletion.Class)
	}
}

func validateCompatibilityServingDelete(deletion PlannedDelete) error {
	if deletion.Size < 0 || !hexSHA256Pattern.MatchString(deletion.SHA256) ||
		deletion.SourcePath != deletion.RemoteKey || deletion.CDNPath != deletion.RemoteKey {
		return fmt.Errorf("compatibility serving deletion %s lacks exact content and route identity", deletion.RemoteKey)
	}
	if strings.HasPrefix(deletion.RemoteKey, "_sow/v1/mirrorlist/latest/") {
		parts := strings.Split(deletion.RemoteKey, "/")
		if len(parts) == 7 && parts[0] == "_sow" && parts[1] == "v1" && parts[2] == "mirrorlist" && parts[3] == "latest" &&
			parts[4] != "" && parts[5] == "cross-el" && strings.HasSuffix(parts[6], ".txt") && strings.TrimSuffix(parts[6], ".txt") != "" {
			return nil
		}
		return fmt.Errorf("compatibility mirrorlist deletion %s is not canonical", deletion.RemoteKey)
	}
	if strings.HasPrefix(deletion.RemoteKey, "_sow/v1/trust/yum-compat/") {
		parts := strings.Split(deletion.RemoteKey, "/")
		if len(parts) == 6 && parts[0] == "_sow" && parts[1] == "v1" && parts[2] == "trust" && parts[3] == "yum-compat" &&
			parts[4] != "" && (parts[5] == "packages.pgp" || parts[5] == "repository.pgp") {
			return nil
		}
		return fmt.Errorf("compatibility trust deletion %s is not canonical", deletion.RemoteKey)
	}
	// Candidate-only raw paths are admitted only inside a public YUM route and
	// only for the two S3 layouts that can differ from S0. The CLI additionally
	// binds the exact route root and old manifest bytes to canonical parent
	// history before such a plan can be persisted.
	if strings.HasPrefix(deletion.RemoteKey, "yum/") &&
		(strings.Contains(deletion.RemoteKey, "/Packages/") || strings.Contains(deletion.RemoteKey, "/repodata/")) &&
		!strings.HasPrefix(deletion.RemoteKey, ".sow/") && !strings.Contains(deletion.RemoteKey, "/../") {
		return nil
	}
	return fmt.Errorf("compatibility serving deletion %s is outside the rollback route set", deletion.RemoteKey)
}

func validateRestoreIndexServingDelete(deletion PlannedDelete) error {
	if deletion.Size < 0 || !hexSHA256Pattern.MatchString(deletion.SHA256) {
		return fmt.Errorf("restore index deletion %s has invalid content evidence", deletion.RemoteKey)
	}
	if strings.HasPrefix(deletion.RemoteKey, "_sow/v1/mirrorlist/") {
		parts := strings.Split(deletion.RemoteKey, "/")
		if len(parts) != 7 || parts[0] != "_sow" || parts[1] != "v1" || parts[2] != "mirrorlist" ||
			(parts[3] != "beta" && parts[3] != "latest") || parts[4] == "" || parts[5] == "" ||
			!strings.HasSuffix(parts[6], ".txt") || strings.TrimSuffix(parts[6], ".txt") == "" ||
			deletion.SourcePath != deletion.RemoteKey || deletion.CDNPath != deletion.RemoteKey {
			return fmt.Errorf("restore mirrorlist deletion %s is not an exact public channel path", deletion.RemoteKey)
		}
		return nil
	}
	logical, view, err := deleteLogicalPath(deletion.SourcePath, deletion.RemoteKey)
	if err != nil {
		return fmt.Errorf("invalid restore index deletion %s: %w", deletion.RemoteKey, err)
	}
	if view != "beta" && view != "latest" {
		return fmt.Errorf("restore index deletion %s targets immutable or gated view %s", deletion.RemoteKey, view)
	}
	wrapped := "/" + logical + "/"
	aptIndex := strings.Contains(wrapped, "/dists/")
	yumIndex := strings.Contains(wrapped, "/repodata/")
	indexPath := aptIndex || yumIndex
	payloadPath := strings.Contains(wrapped, "/pool/") || !aptIndex && strings.Contains(wrapped, "/Packages/") ||
		strings.Contains(logical, "/objects/sha256/")
	if !indexPath || payloadPath || strings.HasPrefix(logical, ".sow/") {
		return fmt.Errorf("restore index deletion %s is outside APT/YUM serving metadata", deletion.RemoteKey)
	}
	if deletion.CDNPath != logical {
		return fmt.Errorf("restore index deletion %s has CDN path %q, want %q", deletion.RemoteKey, deletion.CDNPath, logical)
	}
	return nil
}

func validateSnapshotDelete(deletion PlannedDelete) error {
	valid := false
	routeKey := false
	snapshotID := ""
	if strings.HasPrefix(deletion.RemoteKey, ".sow/snapshots/") && strings.HasSuffix(deletion.RemoteKey, ".json") {
		snapshotID = strings.TrimSuffix(strings.TrimPrefix(deletion.RemoteKey, ".sow/snapshots/"), ".json")
		valid = !strings.Contains(snapshotID, "/") && ValidatePublicationIntent("snapshot", snapshotID) == nil
		routeKey = valid
	} else if strings.HasPrefix(deletion.RemoteKey, ".sow/gated/snapshots/") {
		remainder := strings.TrimPrefix(deletion.RemoteKey, ".sow/gated/snapshots/")
		id, tail, found := strings.Cut(remainder, "/")
		valid = found && tail != "" && ValidatePublicationIntent("snapshot", id) == nil
	}
	if !valid {
		return fmt.Errorf("deletion %s is outside an exact snapshot-owned prefix", deletion.RemoteKey)
	}
	if deletion.SourcePath != "" {
		if err := validateRoutableRemoteKey(deletion.SourcePath); err != nil {
			return fmt.Errorf("invalid snapshot deletion source: %w", err)
		}
		if deletion.Size < 0 || !hexSHA256Pattern.MatchString(deletion.SHA256) {
			return fmt.Errorf("snapshot deletion %s has invalid content evidence", deletion.RemoteKey)
		}
	} else if deletion.Size != 0 || deletion.SHA256 != "" {
		return fmt.Errorf("snapshot deletion %s has incomplete content evidence", deletion.RemoteKey)
	}
	if routeKey {
		want := path.Join("pro/v1/basic/_sow/v1/snapshots", snapshotID, "_route.json")
		if deletion.CDNPath != want {
			return fmt.Errorf("snapshot route deletion %s has CDN path %q, want %q", deletion.RemoteKey, deletion.CDNPath, want)
		}
	} else if deletion.CDNPath != "" {
		return fmt.Errorf("snapshot payload deletion %s must not claim a direct CDN route", deletion.RemoteKey)
	}
	return nil
}

func validateAssetServingDelete(deletion PlannedDelete) error {
	logical, view, err := deleteLogicalPath(deletion.SourcePath, deletion.RemoteKey)
	if err != nil {
		return fmt.Errorf("invalid asset-serving deletion %s: %w", deletion.RemoteKey, err)
	}
	if deletion.Size < 0 || !hexSHA256Pattern.MatchString(deletion.SHA256) {
		return fmt.Errorf("asset-serving deletion %s has invalid content evidence", deletion.RemoteKey)
	}
	if forbiddenServingDeletePath(logical) {
		return fmt.Errorf("asset-serving deletion %s targets a reserved repository or archive path", deletion.RemoteKey)
	}
	wantCDN := logical
	if view == "stable" {
		wantCDN = path.Join("pro/v1/basic", logical)
	}
	if deletion.CDNPath != wantCDN {
		return fmt.Errorf("asset-serving deletion %s has CDN path %q, want %q", deletion.RemoteKey, deletion.CDNPath, wantCDN)
	}
	return nil
}

func validateAPTByHashDelete(deletion PlannedDelete) error {
	logical, _, err := deleteLogicalPath(deletion.SourcePath, deletion.RemoteKey)
	if err != nil {
		return fmt.Errorf("invalid APT by-hash deletion %s: %w", deletion.RemoteKey, err)
	}
	match := aptByHashPattern.FindStringSubmatch(logical)
	if len(match) == 0 || match[1] != deletion.SHA256 || deletion.Size < 0 || !hexSHA256Pattern.MatchString(deletion.SHA256) {
		return fmt.Errorf("APT by-hash deletion %s is not bound to its immutable digest", deletion.RemoteKey)
	}
	if deletion.CDNPath != "" {
		return fmt.Errorf("APT by-hash deletion %s must not request CDN purge", deletion.RemoteKey)
	}
	return nil
}

// deleteLogicalPath accepts only the three publication source/remote mappings
// produced by the latest, beta, and stable classifiers. This makes it
// impossible to relabel an arbitrary control object as an asset or by-hash
// deletion inside a persisted plan.
func deleteLogicalPath(sourcePath, remoteKey string) (logical, view string, err error) {
	if err := validateRoutableRemoteKey(sourcePath); err != nil {
		return "", "", err
	}
	switch {
	case strings.HasPrefix(sourcePath, ".sow/materialized/beta/"):
		logical = strings.TrimPrefix(sourcePath, ".sow/materialized/beta/")
		view = "beta"
		if remoteKey != path.Join(".sow/beta", logical) {
			return "", "", errors.New("beta source and remote key do not match")
		}
	case strings.HasPrefix(sourcePath, ".sow/origin/gated/"):
		logical = strings.TrimPrefix(sourcePath, ".sow/origin/gated/")
		view = "stable"
		if remoteKey != path.Join(".sow/gated", logical) {
			return "", "", errors.New("stable source and remote key do not match")
		}
	default:
		logical = sourcePath
		view = "latest"
		if strings.HasPrefix(logical, ".sow/") || remoteKey != logical {
			return "", "", errors.New("latest source and remote key do not match")
		}
	}
	if err := validateRoutableRemoteKey(logical); err != nil {
		return "", "", err
	}
	return logical, view, nil
}

func forbiddenServingDeletePath(logical string) bool {
	if logical == "objects/sha256" || strings.HasPrefix(logical, "objects/sha256/") ||
		strings.HasPrefix(logical, ".sow/") || strings.HasPrefix(logical, ".pool/") {
		return true
	}
	wrapped := "/" + logical + "/"
	return strings.Contains(wrapped, "/dists/") || strings.Contains(wrapped, "/repodata/") ||
		strings.Contains(wrapped, "/Packages/") || strings.Contains(wrapped, "/pool/")
}

func (p Plan) Digest() (string, error) {
	canonical, err := p.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (p Plan) objects(class ObjectClass) []PlannedObject {
	var result []PlannedObject
	for _, object := range p.Objects {
		if object.Class == class {
			result = append(result, object)
		}
	}
	return result
}

func (object PlannedObject) cdnExpectation() (string, int64, string, error) {
	cdnPath := object.CDNPath
	if cdnPath == "" {
		var err error
		cdnPath, err = defaultCDNPath(object.RemoteKey)
		if err != nil {
			return "", 0, "", err
		}
	}
	if err := validateRoutableRemoteKey(cdnPath); err != nil {
		return "", 0, "", err
	}
	if object.VerificationSHA256 != "" {
		return cdnPath, object.VerificationSize, object.VerificationSHA256, nil
	}
	return cdnPath, object.Size, object.SHA256, nil
}

func defaultCDNPath(remoteKey string) (string, error) {
	if strings.HasPrefix(remoteKey, ".sow/gated/") {
		return "", fmt.Errorf("gated object %s requires an explicit authenticated CDN path", remoteKey)
	}
	if match := yumGenerationPublicPathPattern.FindStringSubmatch(remoteKey); len(match) != 0 {
		return "_sow/v1/g/" + match[2] + "/" + match[3], nil
	}
	if strings.HasPrefix(remoteKey, ".sow/channels/") {
		return "", fmt.Errorf("channel pointer %s requires an explicit transformed CDN path and verification digest", remoteKey)
	}
	if strings.HasPrefix(remoteKey, ".sow/") {
		return "", fmt.Errorf("remote control key %s has no public CDN route", remoteKey)
	}
	return remoteKey, nil
}

func validateRemoteKey(value string) error {
	if value == "" || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\\x00\r\n\t") {
		return fmt.Errorf("unsafe remote key %q", value)
	}
	if path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return fmt.Errorf("non-canonical remote key %q", value)
	}
	return nil
}

func validateRoutableRemoteKey(value string) error {
	if err := validateRemoteKey(value); err != nil {
		return err
	}
	for _, segment := range strings.Split(value, "/") {
		if err := config.ValidateRouteSegment(segment); err != nil {
			return fmt.Errorf("remote key %q is not edge-routable: segment %q: %w", value, segment, err)
		}
	}
	return nil
}

func validatePlannedRemoteKey(key string, class ObjectClass) error {
	if err := validateObjectClass(class); err != nil {
		return err
	}
	if key == CheckpointKey || strings.HasPrefix(key, ".sow/locks/") {
		return fmt.Errorf("remote control key %q is reserved for the publish protocol", key)
	}
	if generationDocumentKeyPattern.MatchString(key) {
		return fmt.Errorf("target generation document key %q is reserved for the publish protocol", key)
	}
	if strings.HasPrefix(key, ".sow/channels/") && class != ObjectPointer {
		return fmt.Errorf("channel key %q must be a mutable pointer", key)
	}
	if strings.HasPrefix(key, ".sow/snapshots/") && class != ObjectPointer {
		return fmt.Errorf("snapshot route key %q must be a mutable pointer", key)
	}
	if strings.HasPrefix(key, ".sow/gated/snapshots/") && !isCreateOnlyClass(class) {
		return fmt.Errorf("snapshot payload key %q must be create-only", key)
	}
	if (strings.HasPrefix(key, ".sow/generations/") || strings.HasPrefix(key, ".sow/gated/generations/")) && class != ObjectMetadata {
		return fmt.Errorf("generation key %q must be immutable metadata", key)
	}
	aptArchive := isAPTGenerationArchive(key)
	if aptArchive && class != ObjectMetadata {
		return fmt.Errorf("APT generation archive %q must be immutable metadata", key)
	}
	if !aptArchive && aptInReleasePattern.MatchString(key) && class != ObjectPointer {
		return fmt.Errorf("APT InRelease %q must be the final mutable pointer", key)
	}
	if !aptArchive && aptLegacyMetadataPattern.MatchString(key) && class != ObjectLegacyMetadata {
		return fmt.Errorf("legacy APT metadata %q must use the ordered pre-pointer class", key)
	}
	if class == ObjectLegacyMetadata && !aptLegacyMetadataPattern.MatchString(key) {
		return fmt.Errorf("legacy-metadata class is reserved for APT Packages/Release artifacts: %q", key)
	}
	if class == ObjectYUMAliasPointer {
		if !strings.HasSuffix(key, "/repodata/repomd.xml") && !strings.HasSuffix(key, "/repodata/repomd.xml.asc") {
			return fmt.Errorf("YUM alias pointer class is reserved for the repomd pair: %q", key)
		}
		if yumGenerationKeyPattern.MatchString(key) {
			return fmt.Errorf("YUM generation metadata cannot use a mutable alias class: %q", key)
		}
	}
	if class == ObjectYUMAliasMetadata {
		if !strings.Contains(key, "/repodata/") || strings.HasSuffix(key, "/repodata/repomd.xml") || strings.HasSuffix(key, "/repodata/repomd.xml.asc") || yumGenerationKeyPattern.MatchString(key) {
			return fmt.Errorf("YUM alias metadata class is reserved for non-pointer repodata: %q", key)
		}
	}
	if class == ObjectCompatibilityRollbackPointer {
		if !strings.HasPrefix(key, "yum/") || !strings.HasSuffix(key, "/repodata/repomd.xml") || yumGenerationKeyPattern.MatchString(key) || strings.HasPrefix(key, ".sow/") {
			return fmt.Errorf("compatibility rollback pointer is reserved for an exact raw S0 repomd.xml: %q", key)
		}
	}
	if class == ObjectCompatibilityRollbackMetadata {
		if !strings.HasPrefix(key, "yum/") || !strings.Contains(key, "/repodata/") || strings.HasSuffix(key, "/repodata/repomd.xml") || strings.HasSuffix(key, "/repodata/repomd.xml.asc") || yumGenerationKeyPattern.MatchString(key) || strings.HasPrefix(key, ".sow/") {
			return fmt.Errorf("compatibility rollback metadata is reserved for non-pointer raw S0 repodata: %q", key)
		}
	}
	return nil
}

func validateSnapshotCopy(destination, source string) error {
	if err := validateRoutableRemoteKey(source); err != nil {
		return fmt.Errorf("invalid server-side copy source: %w", err)
	}
	if destination == source || strings.HasPrefix(source, ".sow/locks/") || source == CheckpointKey || generationDocumentKeyPattern.MatchString(source) {
		return errors.New("server-side copy source is a reserved control object or equals its destination")
	}
	const prefix = ".sow/gated/snapshots/"
	if !strings.HasPrefix(destination, prefix) {
		return fmt.Errorf("server-side copy destination %s is outside the gated snapshot tree", destination)
	}
	remainder := strings.TrimPrefix(destination, prefix)
	parts := strings.SplitN(remainder, "/", 3)
	if len(parts) != 3 || ValidatePublicationIntent("snapshot", parts[0]) != nil || parts[1] != "yum" || !strings.Contains(parts[2], "/Packages/") {
		return fmt.Errorf("server-side copy destination %s is not a canonical YUM snapshot package key", destination)
	}
	return nil
}

func isAPTGenerationArchive(key string) bool {
	if !strings.HasPrefix(key, ".sow/generations/") && !strings.HasPrefix(key, ".sow/gated/generations/") {
		return false
	}
	parts := strings.Split(key, "/")
	for index := 0; index+1 < len(parts); index++ {
		if len(parts[index]) == 20 && allASCIIDigits(parts[index]) && parts[index+1] == "apt" {
			return true
		}
	}
	return false
}

func allASCIIDigits(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func aptDistributionRoot(key string) (string, bool) {
	index := strings.Index(key, "dists/")
	if index < 0 || index != 0 && key[index-1] != '/' {
		return "", false
	}
	after := key[index+len("dists/"):]
	slash := strings.IndexByte(after, '/')
	if slash <= 0 {
		return "", false
	}
	return key[:index+len("dists/")+slash+1], true
}

func parseCDNBaseURL(raw string, allowInsecure bool) (*url.URL, string, error) {
	base, err := url.Parse(raw)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.RawPath != "" ||
		(base.Scheme != "https" && !(allowInsecure && base.Scheme == "http")) {
		return nil, "", errors.New("CDN base URL must be an absolute clean HTTPS URL")
	}
	if base.Path == "" {
		base.Path = "/"
	}
	if strings.Contains(base.Path, "//") || path.Clean(base.Path) != strings.TrimSuffix(base.Path, "/") && base.Path != "/" {
		return nil, "", errors.New("CDN base URL path is not canonical")
	}
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	if containsBearerCredential(base.Path) {
		return nil, "", errors.New("CDN base URL must not contain a bearer credential; use the Basic verification route")
	}
	base.ForceQuery = false
	return base, base.String(), nil
}

func joinCDNURL(base *url.URL, remoteKey string) string {
	joined := *base
	joined.Path = path.Join(base.Path, remoteKey)
	joined.RawPath = ""
	return joined.String()
}

func containsBearerCredential(value string) bool {
	parts := strings.Split(value, "/")
	for index := 0; index+2 < len(parts); index++ {
		if parts[index] == "pro" && parts[index+1] == "v1" && parts[index+2] != "" && parts[index+2] != "basic" {
			return true
		}
	}
	return false
}

// DecodePlan is intentionally strict so persisted journals cannot be resumed
// against a differently interpreted plan document.
func DecodePlan(data []byte) (Plan, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Plan{}, err
	}
	canonical, err := plan.Canonical()
	if err != nil {
		return Plan{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Plan{}, errors.New("publish plan is not canonical JSON")
	}
	return plan, nil
}
