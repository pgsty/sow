package publish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
)

const (
	TargetGenerationSchema = "sow-target-generation/v1"
	// CheckpointSchemaV1 is retained only for strict decoding of repositories
	// published before the publication plan became part of the remote
	// checkpoint closure. New checkpoints are always v2 and bind PlanSHA256.
	CheckpointSchemaV1   = "sow-checkpoint/v1"
	CheckpointSchema     = "sow-checkpoint/v2"
	GenerationLockSchema = "sow-generation-lock/v1"
	SnapshotRouteSchema  = "sow-snapshot-route/v1"

	CheckpointKey = ".sow/manifest.json"
)

// SnapshotRouteBody is the single canonical encoding shared by the CLI plan
// builder and the publish recovery validator. A persisted plan cannot choose
// its own snapshot target or generation and then self-verify that forgery.
func SnapshotRouteBody(snapshotID string, generation uint64) ([]byte, error) {
	if generation == 0 || ValidatePublicationIntent("snapshot", snapshotID) != nil {
		return nil, errors.New("invalid snapshot route identity")
	}
	body := struct {
		Schema     string `json:"schema"`
		Snapshot   string `json:"snapshot"`
		Generation string `json:"generation"`
	}{Schema: SnapshotRouteSchema, Snapshot: snapshotID, Generation: fmt.Sprintf("%020d", generation)}
	return json.Marshal(body)
}

type TargetName string

const (
	TargetCloudflare TargetName = "cf"
	TargetTencent    TargetName = "cos"
)

var (
	hexSHA256Pattern               = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gitHashPattern                 = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	transactionIDPat               = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	channelSegmentPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*$`)
	snapshotIDPattern              = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9+._-]*)-([0-9]{8})$`)
	generationDocumentKeyPattern   = regexp.MustCompile(`^\.sow/generations/[0-9]{20}/generation\.json$`)
	aptGenerationKeyPattern        = regexp.MustCompile(`^\.sow/(gated/)?generations/([0-9]{20})/apt/(.+)$`)
	yumGenerationKeyPattern        = regexp.MustCompile(`^\.sow/(gated/)?generations/([0-9]{20})/yum/(.+)$`)
	yumGenerationPublicPathPattern = yumGenerationKeyPattern
	aptInReleasePattern            = regexp.MustCompile(`(?:^|/)dists/[^/]+/InRelease$`)
	aptLegacyMetadataPattern       = regexp.MustCompile(`(?:^|/)dists/[^/]+/(?:Release(?:\.gpg)?|.+/Packages(?:\.(?:gz|xz))?)$`)
	aptByHashPattern               = regexp.MustCompile(`(?:^|/)by-hash/SHA256/([0-9a-f]{64})$`)
)

var (
	ErrConflict        = errors.New("publish compare-and-set conflict")
	ErrDrift           = errors.New("remote checkpoint drift")
	ErrAlreadyExists   = errors.New("remote object already exists")
	ErrNotFound        = errors.New("remote object not found")
	ErrVerification    = errors.New("post-publish verification failed")
	ErrJournalConflict = errors.New("publish journal does not match requested transaction")
	ErrCapability      = errors.New("remote provider lacks required safety capability")
)

func (t TargetName) Validate() error {
	switch t {
	case TargetCloudflare, TargetTencent:
		return nil
	default:
		return fmt.Errorf("unsupported publish target %q", t)
	}
}

// RefState is one leaf in a target generation. The vector, rather than one
// arbitrary view ref, is the unit advanced by a remote publication.
type RefState struct {
	Name           string `json:"name"`
	Commit         string `json:"commit"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

// ChannelState is the canonical YUM indirection vector carried by every
// target generation. A target can legitimately have different leaves pinned
// to different immutable generations after a selector-scoped publish, so the
// checkpoint must preserve this mapping independently of the source manifest.
type ChannelState struct {
	View       string `json:"view"`
	Repo       string `json:"repo"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Generation uint64 `json:"generation"`
	RemoteKey  string `json:"remote_key"`
	LegacyRoot string `json:"legacy_root"`
	BodySHA256 string `json:"body_sha256"`
}

// CompatibilityState binds an independently published frozen cross-EL tree to
// the exact immutable source/witness/trust identities that produced its bytes.
// It is separate from ordinary mutable view refs: source advancement or key
// rotation can therefore never reinterpret an already-published generation.
type CompatibilityState struct {
	ID                      string `json:"id"`
	Root                    string `json:"root"`
	Carrier                 string `json:"carrier"`
	OwnerRepo               string `json:"owner_repo"`
	SourceRef               string `json:"source_ref"`
	SourceCommit            string `json:"source_commit"`
	FreezeRef               string `json:"freeze_ref"`
	FreezeCommit            string `json:"freeze_commit"`
	SourceRoot              string `json:"source_root"`
	SourceManifestSHA256    string `json:"source_manifest_sha256"`
	SourceManifestGit       string `json:"source_manifest_git_blob"`
	SourceManifestSize      int64  `json:"source_manifest_size"`
	AdoptionSHA256          string `json:"adoption_sha256"`
	AdoptionGit             string `json:"adoption_git_blob"`
	AdoptionSize            int64  `json:"adoption_size"`
	WitnessSHA256           string `json:"witness_sha256"`
	WitnessGit              string `json:"witness_git_blob"`
	WitnessSize             int64  `json:"witness_size"`
	PayloadManifestSHA256   string `json:"payload_manifest_sha256"`
	PayloadManifestGit      string `json:"payload_manifest_git_blob"`
	PayloadManifestSize     int64  `json:"payload_manifest_size"`
	PackageTrustSHA256      string `json:"package_trust_sha256"`
	PackageTrustGit         string `json:"package_trust_git_blob"`
	PackageTrustSize        int64  `json:"package_trust_size"`
	CandidateManifestSHA256 string `json:"candidate_manifest_sha256"`
	CandidateManifestGit    string `json:"candidate_manifest_git_blob"`
	CandidateManifestSize   int64  `json:"candidate_manifest_size"`
	CandidateReceiptSHA256  string `json:"candidate_receipt_sha256"`
	CandidateReceiptGit     string `json:"candidate_receipt_git_blob"`
	CandidateReceiptSize    int64  `json:"candidate_receipt_size"`
	RepomdSHA256            string `json:"repomd_sha256"`
	RepositoryKeySHA256     string `json:"repository_key_sha256"`
	CutoverSHA256           string `json:"cutover_sha256,omitempty"`
	CutoverGit              string `json:"cutover_git_blob,omitempty"`
	CutoverSize             int64  `json:"cutover_size,omitempty"`
	RouteTarget             string `json:"route_target"`
	RouteRoot               string `json:"route_root"`
	ChannelRemoteKey        string `json:"channel_remote_key"`
}

func (c ChannelState) CanonicalBody() ([]byte, error) {
	if c.Generation == 0 || c.LegacyRoot == "" || path.Clean(c.LegacyRoot) != c.LegacyRoot || strings.HasPrefix(c.LegacyRoot, "/") || strings.HasPrefix(c.LegacyRoot, "../") || strings.ContainsAny(c.LegacyRoot, "\\\x00\r\n\t") {
		return nil, errors.New("invalid channel generation or legacy root")
	}
	for _, segment := range strings.Split(c.LegacyRoot, "/") {
		if err := config.ValidateRouteSegment(segment); err != nil {
			return nil, fmt.Errorf("invalid channel legacy root segment %q: %w", segment, err)
		}
	}
	body := struct {
		Generation string `json:"generation"`
		LegacyRoot string `json:"legacy_root"`
	}{Generation: fmt.Sprintf("%020d", c.Generation), LegacyRoot: c.LegacyRoot}
	return json.Marshal(body)
}

// YUMChannelPointer returns the exact mutable remote object that exposes a
// canonical YUM channel. Stable stores the canonical channel document for the
// edge renderer; beta/latest store a static generation-pinned mirrorlist.
// Keeping this derivation beside ChannelState prevents publish, audit, and
// remote-inventory adoption from disagreeing about the public object.
func YUMChannelPointer(cdnBaseURL string, c ChannelState) (string, []byte, error) {
	canonical, err := c.CanonicalBody()
	if err != nil {
		return "", nil, err
	}
	switch c.View {
	case "stable":
		return c.RemoteKey, canonical, nil
	case "beta", "latest":
		for field, value := range map[string]string{"repo": c.Repo, "os": c.OS, "arch": c.Arch} {
			if !channelSegmentPattern.MatchString(value) {
				return "", nil, fmt.Errorf("invalid channel %s %q", field, value)
			}
		}
		key := path.Join("_sow/v1/mirrorlist", c.View, c.Repo, c.OS, c.Arch+".txt")
		route := "_sow/v1/g/" + fmt.Sprintf("%020d", c.Generation) + "/" + c.LegacyRoot
		clientURL, err := config.CanonicalRouteURL(cdnBaseURL, route, true)
		if err != nil {
			return "", nil, fmt.Errorf("render channel mirrorlist: %w", err)
		}
		body := []byte(clientURL + "\n")
		return key, body, nil
	default:
		return "", nil, fmt.Errorf("invalid channel view %q", c.View)
	}
}

// TargetGeneration is immutable. Canonical returns a deterministic JSON
// representation with refs sorted by name and no wall-clock fields.
type TargetGeneration struct {
	Schema                string               `json:"schema"`
	Target                TargetName           `json:"target"`
	Generation            uint64               `json:"generation"`
	ParentGeneration      uint64               `json:"parent_generation"`
	DesiredCommit         string               `json:"desired_commit"`
	IntentView            string               `json:"intent_view"`
	IntentSnapshot        string               `json:"intent_snapshot,omitempty"`
	ConfigSHA256          string               `json:"config_sha256"`
	RepositoryKeySHA256   string               `json:"repository_key_sha256,omitempty"`
	Refs                  []RefState           `json:"refs"`
	Compatibility         []CompatibilityState `json:"compatibility,omitempty"`
	Channels              []ChannelState       `json:"channels"`
	ContentManifestSHA256 string               `json:"content_manifest_sha256"`
}

func (g TargetGeneration) normalized() (TargetGeneration, error) {
	if g.Schema == "" {
		g.Schema = TargetGenerationSchema
	}
	if g.Schema != TargetGenerationSchema {
		return g, fmt.Errorf("target generation schema %q is not %q", g.Schema, TargetGenerationSchema)
	}
	if err := g.Target.Validate(); err != nil {
		return g, err
	}
	if g.Generation == 0 || g.ParentGeneration+1 != g.Generation {
		return g, fmt.Errorf("generation %d must immediately follow parent %d", g.Generation, g.ParentGeneration)
	}
	if !gitHashPattern.MatchString(g.DesiredCommit) {
		return g, fmt.Errorf("invalid desired commit %q", g.DesiredCommit)
	}
	if err := ValidatePublicationIntent(g.IntentView, g.IntentSnapshot); err != nil {
		return g, err
	}
	if !hexSHA256Pattern.MatchString(g.ConfigSHA256) {
		return g, errors.New("invalid config sha256")
	}
	if g.RepositoryKeySHA256 != "" && !hexSHA256Pattern.MatchString(g.RepositoryKeySHA256) {
		return g, errors.New("invalid repository key sha256")
	}
	if !hexSHA256Pattern.MatchString(g.ContentManifestSHA256) {
		return g, errors.New("invalid content manifest sha256")
	}
	if len(g.Refs) == 0 {
		return g, errors.New("target generation has no refs")
	}
	g.Refs = append([]RefState(nil), g.Refs...)
	sort.Slice(g.Refs, func(i, j int) bool { return g.Refs[i].Name < g.Refs[j].Name })
	for i := range g.Refs {
		ref := &g.Refs[i]
		name := plumbing.ReferenceName(ref.Name)
		parts := strings.Split(ref.Name, "/")
		allowedNamespace := len(parts) == 4 && len(parts) > 2 && parts[0] == "refs" && parts[1] == "sow" && parts[2] == "repos" ||
			len(parts) == 7 && len(parts) > 2 && parts[0] == "refs" && parts[1] == "sow" && (parts[2] == "views" || parts[2] == "snapshots")
		if !allowedNamespace || name.Validate() != nil || strings.ContainsAny(ref.Name, "\x00\r\n\t ") {
			return g, fmt.Errorf("invalid SOW ref name %q", ref.Name)
		}
		if !gitHashPattern.MatchString(ref.Commit) {
			return g, fmt.Errorf("invalid commit for %s", ref.Name)
		}
		if !hexSHA256Pattern.MatchString(ref.ManifestSHA256) {
			return g, fmt.Errorf("invalid manifest sha256 for %s", ref.Name)
		}
		if i != 0 && g.Refs[i-1].Name == ref.Name {
			return g, fmt.Errorf("duplicate target ref %s", ref.Name)
		}
	}
	g.Compatibility = append([]CompatibilityState(nil), g.Compatibility...)
	sort.Slice(g.Compatibility, func(i, j int) bool { return g.Compatibility[i].ID < g.Compatibility[j].ID })
	compatByChannel := make(map[string]CompatibilityState, len(g.Compatibility))
	for i, compatibility := range g.Compatibility {
		cutoverAbsent := compatibility.CutoverSHA256 == "" && compatibility.CutoverGit == "" && compatibility.CutoverSize == 0
		cutoverComplete := hexSHA256Pattern.MatchString(compatibility.CutoverSHA256) && gitHashPattern.MatchString(compatibility.CutoverGit) && compatibility.CutoverSize > 0
		if !channelSegmentPattern.MatchString(compatibility.ID) || !channelSegmentPattern.MatchString(compatibility.Carrier) || !channelSegmentPattern.MatchString(compatibility.OwnerRepo) || compatibility.Root == "" || path.Clean(compatibility.Root) != compatibility.Root || strings.HasPrefix(compatibility.Root, "/") || strings.HasPrefix(compatibility.Root, "../") || strings.ContainsAny(compatibility.Root, "\\\x00\r\n\t") {
			return g, fmt.Errorf("invalid compatibility projection %q", compatibility.ID)
		}
		if compatibility.SourceRoot != path.Join("compatibility", "yum", compatibility.ID, "source.tsv") ||
			plumbing.ReferenceName(compatibility.SourceRef).Validate() != nil || compatibility.SourceRef != path.Join("refs/sow/compatibility/yum-source", compatibility.ID) ||
			!gitHashPattern.MatchString(compatibility.SourceCommit) || plumbing.ReferenceName(compatibility.FreezeRef).Validate() != nil || compatibility.FreezeRef != path.Join("refs/sow/compatibility/yum", compatibility.ID) || !gitHashPattern.MatchString(compatibility.FreezeCommit) ||
			!hexSHA256Pattern.MatchString(compatibility.WitnessSHA256) || !gitHashPattern.MatchString(compatibility.WitnessGit) || compatibility.WitnessSize < 1 ||
			!hexSHA256Pattern.MatchString(compatibility.PayloadManifestSHA256) || compatibility.PayloadManifestSize < 0 ||
			!hexSHA256Pattern.MatchString(compatibility.SourceManifestSHA256) || !gitHashPattern.MatchString(compatibility.SourceManifestGit) ||
			compatibility.SourceManifestSize < 0 || !hexSHA256Pattern.MatchString(compatibility.AdoptionSHA256) || !gitHashPattern.MatchString(compatibility.AdoptionGit) || compatibility.AdoptionSize < 1 ||
			!gitHashPattern.MatchString(compatibility.PayloadManifestGit) || !hexSHA256Pattern.MatchString(compatibility.PackageTrustSHA256) || !gitHashPattern.MatchString(compatibility.PackageTrustGit) || compatibility.PackageTrustSize < 1 ||
			!hexSHA256Pattern.MatchString(compatibility.CandidateManifestSHA256) || !gitHashPattern.MatchString(compatibility.CandidateManifestGit) || compatibility.CandidateManifestSize < 1 ||
			!hexSHA256Pattern.MatchString(compatibility.CandidateReceiptSHA256) || !gitHashPattern.MatchString(compatibility.CandidateReceiptGit) || compatibility.CandidateReceiptSize < 1 ||
			!hexSHA256Pattern.MatchString(compatibility.RepomdSHA256) || !hexSHA256Pattern.MatchString(compatibility.RepositoryKeySHA256) ||
			(!cutoverAbsent && !cutoverComplete) {
			return g, fmt.Errorf("compatibility projection %s has invalid frozen source or trust identity", compatibility.ID)
		}
		if compatibility.RouteTarget != "compatibility" {
			return g, fmt.Errorf("compatibility projection %s has invalid route target %q", compatibility.ID, compatibility.RouteTarget)
		}
		if compatibility.RouteRoot == "" || path.Clean(compatibility.RouteRoot) != compatibility.RouteRoot || strings.HasPrefix(compatibility.RouteRoot, "/") || strings.HasPrefix(compatibility.RouteRoot, "../") || strings.ContainsAny(compatibility.RouteRoot, "\\\x00\r\n\t") {
			return g, fmt.Errorf("compatibility projection %s has invalid route root", compatibility.ID)
		}
		if compatibility.RouteRoot != compatibility.Root {
			return g, fmt.Errorf("compatibility projection %s route root does not match route target", compatibility.ID)
		}
		expectedChannel := path.Join(".sow/channels", "latest", compatibility.ID, "cross-el", path.Base(compatibility.Root)+".json")
		if compatibility.ChannelRemoteKey != expectedChannel {
			return g, fmt.Errorf("compatibility projection %s has non-canonical channel key", compatibility.ID)
		}
		if i != 0 && g.Compatibility[i-1].ID == compatibility.ID {
			return g, fmt.Errorf("duplicate compatibility projection %s", compatibility.ID)
		}
		compatByChannel[compatibility.ChannelRemoteKey] = compatibility
	}
	g.Channels = append([]ChannelState{}, g.Channels...)
	sort.Slice(g.Channels, func(i, j int) bool { return g.Channels[i].RemoteKey < g.Channels[j].RemoteKey })
	for i := range g.Channels {
		channel := &g.Channels[i]
		for field, value := range map[string]string{"view": channel.View, "repo": channel.Repo, "os": channel.OS, "arch": channel.Arch} {
			if !channelSegmentPattern.MatchString(value) {
				return g, fmt.Errorf("invalid channel %s %q", field, value)
			}
		}
		if channel.View != "beta" && channel.View != "latest" && channel.View != "stable" {
			return g, fmt.Errorf("invalid channel view %q", channel.View)
		}
		expectedKey := fmt.Sprintf(".sow/channels/%s/%s/%s/%s.json", channel.View, channel.Repo, channel.OS, channel.Arch)
		if channel.RemoteKey != expectedKey {
			return g, fmt.Errorf("channel remote key %q is not canonical", channel.RemoteKey)
		}
		if channel.Generation == 0 || channel.Generation > g.Generation {
			return g, fmt.Errorf("channel %s names invalid generation %d", channel.RemoteKey, channel.Generation)
		}
		body, err := channel.CanonicalBody()
		if err != nil {
			return g, fmt.Errorf("channel %s: %w", channel.RemoteKey, err)
		}
		digest := sha256.Sum256(body)
		if !hexSHA256Pattern.MatchString(channel.BodySHA256) || channel.BodySHA256 != hex.EncodeToString(digest[:]) {
			return g, fmt.Errorf("channel %s body digest is invalid", channel.RemoteKey)
		}
		if i != 0 && g.Channels[i-1].RemoteKey == channel.RemoteKey {
			return g, fmt.Errorf("duplicate channel %s", channel.RemoteKey)
		}
		compatibility, isCompatibility := compatByChannel[channel.RemoteKey]
		if channel.OS == "cross-el" {
			if !isCompatibility || channel.Repo != compatibility.ID || channel.LegacyRoot != compatibility.RouteRoot {
				return g, fmt.Errorf("cross-el channel %s has no matching frozen compatibility identity", channel.RemoteKey)
			}
		} else if isCompatibility {
			return g, fmt.Errorf("compatibility identity %s is bound to a non-cross-el channel", compatibility.ID)
		}
	}
	for remoteKey := range compatByChannel {
		found := false
		for _, channel := range g.Channels {
			found = found || channel.RemoteKey == remoteKey
		}
		if !found {
			return g, fmt.Errorf("compatibility identity for channel %s has no channel", remoteKey)
		}
	}
	return g, nil
}

func (g TargetGeneration) Canonical() ([]byte, error) {
	normalized, err := g.normalized()
	if err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

func (g TargetGeneration) Digest() (string, error) {
	canonical, err := g.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// DecodeTargetGeneration is the strict inverse of Canonical. A checkpoint
// stores only this document's digest, so recovery must GET generation.json,
// decode it with this function, and compare both the digest and the complete
// ref/content vector before deriving the next publication baseline.
func DecodeTargetGeneration(data []byte) (TargetGeneration, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var generation TargetGeneration
	if err := decoder.Decode(&generation); err != nil {
		return TargetGeneration{}, fmt.Errorf("decode target generation: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return TargetGeneration{}, err
	}
	canonical, err := generation.Canonical()
	if err != nil {
		return TargetGeneration{}, err
	}
	if !bytes.Equal(data, canonical) {
		return TargetGeneration{}, errors.New("target generation is not canonical JSON")
	}
	return generation, nil
}

func GenerationKey(generation uint64) (string, error) {
	if generation == 0 {
		return "", errors.New("zero generation has no remote object")
	}
	return fmt.Sprintf(".sow/generations/%020d/generation.json", generation), nil
}

func GenerationLockKey(generation uint64) (string, error) {
	if generation == 0 {
		return "", errors.New("zero generation has no lock")
	}
	return fmt.Sprintf(".sow/locks/%020d.json", generation), nil
}

type Phase string

const (
	PhasePlanned             Phase = "planned"
	PhaseLocked              Phase = "locked"
	PhaseImmutableUploaded   Phase = "immutable-uploaded"
	PhaseGenerationReady     Phase = "generation-ready"
	PhasePointerFlipped      Phase = "pointer-flipped"
	PhasePurged              Phase = "purged"
	PhaseVerified            Phase = "verified"
	PhaseCheckpointCommitted Phase = "checkpoint-committed"
	PhaseRemoteRefReady      Phase = "remote-ref-ready"
)

var phaseOrder = map[Phase]int{
	PhasePlanned: 0, PhaseLocked: 1, PhaseImmutableUploaded: 2,
	PhaseGenerationReady: 3, PhasePointerFlipped: 4, PhasePurged: 5,
	PhaseVerified: 6, PhaseCheckpointCommitted: 7, PhaseRemoteRefReady: 8,
}

func (p Phase) Validate() error {
	if _, ok := phaseOrder[p]; !ok {
		return fmt.Errorf("unknown publish phase %q", p)
	}
	return nil
}

func phaseAtLeast(current, wanted Phase) bool { return phaseOrder[current] >= phaseOrder[wanted] }

// Checkpoint is the single bounded remote read used to detect drift. The
// UpdatedAt value is selected once by the caller and therefore remains stable
// across retries; Canonical itself never consults the clock.
type Checkpoint struct {
	Schema                string     `json:"schema"`
	Target                TargetName `json:"target"`
	Generation            uint64     `json:"generation"`
	ParentGeneration      uint64     `json:"parent_generation"`
	DesiredCommit         string     `json:"desired_commit"`
	IntentView            string     `json:"intent_view"`
	IntentSnapshot        string     `json:"intent_snapshot,omitempty"`
	GenerationSHA256      string     `json:"generation_sha256"`
	PlanSHA256            string     `json:"plan_sha256,omitempty"`
	ContentManifestSHA256 string     `json:"content_manifest_sha256"`
	TransactionID         string     `json:"transaction_id"`
	Phase                 Phase      `json:"phase"`
	UpdatedAt             string     `json:"updated_at"`
}

func NewCheckpoint(g TargetGeneration, transactionID, planSHA256 string, phase Phase, updatedAt time.Time) (Checkpoint, error) {
	normalized, err := g.normalized()
	if err != nil {
		return Checkpoint{}, err
	}
	digest, err := normalized.Digest()
	if err != nil {
		return Checkpoint{}, err
	}
	checkpoint := Checkpoint{
		Schema: CheckpointSchema, Target: normalized.Target,
		Generation: normalized.Generation, ParentGeneration: normalized.ParentGeneration,
		DesiredCommit: normalized.DesiredCommit, GenerationSHA256: digest,
		PlanSHA256:            planSHA256,
		IntentView:            normalized.IntentView,
		IntentSnapshot:        normalized.IntentSnapshot,
		ContentManifestSHA256: normalized.ContentManifestSHA256,
		TransactionID:         transactionID, Phase: phase,
		UpdatedAt: updatedAt.UTC().Format(time.RFC3339Nano),
	}
	if _, err := checkpoint.Canonical(); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

func (c Checkpoint) Canonical() ([]byte, error) {
	if c.Schema == "" {
		c.Schema = CheckpointSchema
	}
	switch c.Schema {
	case CheckpointSchemaV1:
		if c.PlanSHA256 != "" {
			return nil, errors.New("v1 checkpoint cannot carry a plan sha256")
		}
	case CheckpointSchema:
		if !hexSHA256Pattern.MatchString(c.PlanSHA256) {
			return nil, errors.New("v2 checkpoint has no valid plan sha256")
		}
	default:
		return nil, fmt.Errorf("unsupported checkpoint schema %q", c.Schema)
	}
	if err := c.Target.Validate(); err != nil {
		return nil, err
	}
	if c.Generation == 0 || c.ParentGeneration+1 != c.Generation {
		return nil, errors.New("checkpoint generation does not immediately follow parent")
	}
	if !gitHashPattern.MatchString(c.DesiredCommit) || !hexSHA256Pattern.MatchString(c.GenerationSHA256) || !hexSHA256Pattern.MatchString(c.ContentManifestSHA256) {
		return nil, errors.New("checkpoint contains an invalid digest or commit")
	}
	if err := ValidatePublicationIntent(c.IntentView, c.IntentSnapshot); err != nil {
		return nil, fmt.Errorf("invalid checkpoint intent: %w", err)
	}
	if !transactionIDPat.MatchString(c.TransactionID) {
		return nil, errors.New("checkpoint has an invalid transaction ID")
	}
	if err := c.Phase.Validate(); err != nil {
		return nil, err
	}
	if c.Phase != PhaseLocked && c.Phase != PhaseCheckpointCommitted {
		return nil, fmt.Errorf("remote checkpoint cannot persist phase %s", c.Phase)
	}
	parsed, err := time.Parse(time.RFC3339Nano, c.UpdatedAt)
	if err != nil || parsed.Location() != time.UTC {
		return nil, errors.New("checkpoint updated_at must be RFC3339 UTC")
	}
	return json.Marshal(c)
}

func (c Checkpoint) Digest() (string, error) {
	canonical, err := c.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func DecodeCheckpoint(data []byte) (Checkpoint, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var checkpoint Checkpoint
	if err := decoder.Decode(&checkpoint); err != nil {
		return Checkpoint{}, fmt.Errorf("decode remote checkpoint: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Checkpoint{}, err
	}
	canonical, err := checkpoint.Canonical()
	if err != nil {
		return Checkpoint{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Checkpoint{}, errors.New("remote checkpoint is not canonical JSON")
	}
	return checkpoint, nil
}

// GenerationLock is used only for Tencent COS. COS's proprietary
// x-cos-forbid-overwrite create operation is the lock primitive; this type is
// deliberately not an If-Match emulation.
type GenerationLock struct {
	Schema                 string     `json:"schema"`
	Target                 TargetName `json:"target"`
	Generation             uint64     `json:"generation"`
	ParentGeneration       uint64     `json:"parent_generation"`
	ParentCheckpointSHA256 string     `json:"parent_checkpoint_sha256,omitempty"`
	GenerationSHA256       string     `json:"generation_sha256"`
	TransactionID          string     `json:"transaction_id"`
	IntentView             string     `json:"intent_view"`
	IntentSnapshot         string     `json:"intent_snapshot,omitempty"`
	UpdatedAt              string     `json:"updated_at"`
}

func (l GenerationLock) Canonical() ([]byte, error) {
	if l.Schema == "" {
		l.Schema = GenerationLockSchema
	}
	if l.Schema != GenerationLockSchema || l.Target != TargetTencent {
		return nil, errors.New("invalid COS generation lock schema or target")
	}
	if l.Generation == 0 || l.ParentGeneration+1 != l.Generation {
		return nil, errors.New("invalid COS generation lock parent")
	}
	if l.ParentGeneration != 0 && !hexSHA256Pattern.MatchString(l.ParentCheckpointSHA256) {
		return nil, errors.New("COS generation lock requires the parent checkpoint digest")
	}
	if l.ParentGeneration == 0 && l.ParentCheckpointSHA256 != "" {
		return nil, errors.New("initial COS generation lock cannot name a parent checkpoint")
	}
	if !hexSHA256Pattern.MatchString(l.GenerationSHA256) || !transactionIDPat.MatchString(l.TransactionID) {
		return nil, errors.New("invalid COS generation lock identity")
	}
	if err := ValidatePublicationIntent(l.IntentView, l.IntentSnapshot); err != nil {
		return nil, fmt.Errorf("invalid COS generation lock intent: %w", err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, l.UpdatedAt)
	if err != nil || parsed.Location() != time.UTC {
		return nil, errors.New("COS generation lock updated_at must be RFC3339 UTC")
	}
	return json.Marshal(l)
}

// ValidatePublicationIntent keeps the original view-only wire contract while
// giving immutable snapshots an exact recovery identity. Snapshot IDs are
// validated here, independently of local configuration, because generation,
// checkpoint, and COS lock documents are remote trust boundaries.
func ValidatePublicationIntent(view, snapshot string) error {
	switch view {
	case "beta", "latest", "stable":
		if snapshot != "" {
			return fmt.Errorf("view %s cannot name snapshot %q", view, snapshot)
		}
		return nil
	case "snapshot":
		match := snapshotIDPattern.FindStringSubmatch(snapshot)
		if match == nil {
			return fmt.Errorf("snapshot publication requires <suite>-YYYYMMDD, got %q", snapshot)
		}
		if _, err := time.Parse("20060102", match[2]); err != nil {
			return fmt.Errorf("snapshot publication has invalid UTC date: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("invalid publication intent view %q", view)
	}
}

// SamePublicationIntent is the exact comparison required during replay.
func SamePublicationIntent(leftView, leftSnapshot, rightView, rightSnapshot string) bool {
	return leftView == rightView && leftSnapshot == rightSnapshot
}

func DecodeGenerationLock(data []byte) (GenerationLock, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var lock GenerationLock
	if err := decoder.Decode(&lock); err != nil {
		return GenerationLock{}, fmt.Errorf("decode COS generation lock: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return GenerationLock{}, err
	}
	canonical, err := lock.Canonical()
	if err != nil {
		return GenerationLock{}, err
	}
	if !bytes.Equal(data, canonical) {
		return GenerationLock{}, errors.New("COS generation lock is not canonical JSON")
	}
	return lock, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains trailing data")
		}
		return err
	}
	return nil
}
