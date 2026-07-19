package serving

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
)

const (
	GenerationSchema = "sow-local-yum-generation/v1"
	ChannelSchema    = "sow-local-yum-channel/v1"
	TargetSchema     = "sow-local-yum-target/v1"
)

var (
	generationIDPattern = regexp.MustCompile(`^[0-9]{20}$`)
	hexSHA256Pattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gitHashPattern      = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

// TargetIdentity partitions mutable local-serving lineage by the exact
// serving tree and URL that an operator exports. The target ID is safe to use
// as a canonical-state path segment, while Root and BaseURL keep the digest
// auditable and prevent an ID from being replayed for a different export.
type TargetIdentity struct {
	Schema  string `json:"schema"`
	ID      string `json:"id"`
	Root    string `json:"root"`
	BaseURL string `json:"base_url"`
}

// NewTargetIdentity derives a stable target identity from a repository-root
// relative target and the clean externally visible URL for one mutable view.
func NewTargetIdentity(view, targetRoot, baseURL string) (TargetIdentity, error) {
	targetRoot, err := validateTargetIdentityRoot(targetRoot)
	if err != nil {
		return TargetIdentity{}, err
	}
	baseURL = strings.TrimSuffix(baseURL, "/")
	wantPath := ""
	if view == "stable" {
		wantPath = "/pro/v1/basic"
	}
	if err := config.ValidateServingBaseURL(baseURL, wantPath); err != nil {
		return TargetIdentity{}, fmt.Errorf("invalid serving target base URL: %w", err)
	}
	target := TargetIdentity{Schema: TargetSchema, Root: targetRoot, BaseURL: baseURL}
	target.ID = targetIdentityID(target.Root, target.BaseURL)
	return target, target.Validate(view)
}

func targetIdentityID(targetRoot, baseURL string) string {
	digest := sha256.New()
	_, _ = io.WriteString(digest, TargetSchema+"\x00")
	for _, field := range []string{targetRoot, baseURL} {
		_, _ = io.WriteString(digest, strconv.Itoa(len(field))+":"+field+"\x00")
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func validateTargetIdentityRoot(value string) (string, error) {
	if value == "" || path.IsAbs(value) || path.Clean(value) != value || strings.HasPrefix(value, "../") || strings.ContainsAny(value, "\\\x00\t\r\n") {
		return "", errors.New("invalid serving target root")
	}
	return value, nil
}

func (target TargetIdentity) Validate(view string) error {
	root, err := validateTargetIdentityRoot(target.Root)
	if err != nil {
		return err
	}
	if target.Schema != TargetSchema || target.Root != root || !hexSHA256Pattern.MatchString(target.ID) || target.ID != targetIdentityID(target.Root, target.BaseURL) {
		return errors.New("invalid serving target identity")
	}
	wantPath := ""
	if view == "stable" {
		wantPath = "/pro/v1/basic"
	}
	if err := config.ValidateServingBaseURL(target.BaseURL, wantPath); err != nil {
		return fmt.Errorf("invalid serving target base URL: %w", err)
	}
	return nil
}

func (target TargetIdentity) Canonical(view string) ([]byte, error) {
	if err := target.Validate(view); err != nil {
		return nil, err
	}
	return json.Marshal(target)
}

func DecodeTargetIdentity(view string, data []byte) (TargetIdentity, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var target TargetIdentity
	if err := decoder.Decode(&target); err != nil {
		return target, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return target, errors.New("serving target JSON has trailing data")
	}
	canonical, err := target.Canonical(view)
	if err != nil {
		return target, err
	}
	if !bytes.Equal(data, canonical) {
		return target, errors.New("serving target JSON is not canonical")
	}
	return target, nil
}

type Identity struct {
	View                string
	Repo                string
	OS                  string
	Arch                string
	LegacyRoot          string
	RefCommit           string
	ConfigSHA256        string
	RepositoryKeySHA256 string
}

// Generation is the immutable, content-addressed local serving record. ID is
// a 20-digit uint64 projection of ContentSHA256; the full digest remains in the
// record and every occupied directory is verified, so a projection collision
// fails closed rather than selecting a different identifier.
type Generation struct {
	Schema              string `json:"schema"`
	ID                  string `json:"id"`
	ContentSHA256       string `json:"content_sha256"`
	ManifestSHA256      string `json:"manifest_sha256"`
	View                string `json:"view"`
	Repo                string `json:"repo"`
	OS                  string `json:"os"`
	Arch                string `json:"arch"`
	LegacyRoot          string `json:"legacy_root"`
	RefCommit           string `json:"ref_commit"`
	ConfigSHA256        string `json:"config_sha256"`
	RepositoryKeySHA256 string `json:"repository_key_sha256"`
}

// GenerationPin is the collision-resistant identity retained by a channel.
// The full digests make a projected 20-digit ID insufficient on its own.
type GenerationPin struct {
	ID             string `json:"id"`
	ContentSHA256  string `json:"content_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

func PinGeneration(generation Generation) (GenerationPin, error) {
	if err := generation.Validate(); err != nil {
		return GenerationPin{}, err
	}
	return GenerationPin{ID: generation.ID, ContentSHA256: generation.ContentSHA256, ManifestSHA256: generation.ManifestSHA256}, nil
}

func (pin GenerationPin) Validate() error {
	if !generationIDPattern.MatchString(pin.ID) || !hexSHA256Pattern.MatchString(pin.ContentSHA256) || !hexSHA256Pattern.MatchString(pin.ManifestSHA256) {
		return errors.New("invalid retained generation pin")
	}
	digest, err := hex.DecodeString(pin.ContentSHA256)
	if err != nil || projectedGenerationID(digest) != pin.ID {
		return errors.New("retained generation pin ID does not match its content digest")
	}
	return nil
}

func DeriveGeneration(identity Identity, source io.Reader) (Generation, error) {
	var result Generation
	if source == nil {
		return result, errors.New("nil generation manifest")
	}
	if err := validateIdentity(identity); err != nil {
		return result, err
	}
	contentHash := sha256.New()
	manifestHash := sha256.New()
	_, _ = io.WriteString(contentHash, GenerationSchema+"\x00")
	for _, field := range []string{identity.View, identity.Repo, identity.OS, identity.Arch, identity.LegacyRoot, identity.RefCommit, identity.ConfigSHA256, identity.RepositoryKeySHA256} {
		_, _ = io.WriteString(contentHash, strconv.Itoa(len(field))+":"+field+"\x00")
	}
	stream := manifest.NewReader(io.TeeReader(source, io.MultiWriter(contentHash, manifestHash)))
	entries := 0
	for {
		_, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, fmt.Errorf("validate generation manifest: %w", err)
		}
		entries++
	}
	if entries == 0 {
		return result, errors.New("generation manifest is empty")
	}
	contentDigest := contentHash.Sum(nil)
	manifestDigest := manifestHash.Sum(nil)
	result = Generation{
		Schema: GenerationSchema, ID: projectedGenerationID(contentDigest),
		ContentSHA256: hex.EncodeToString(contentDigest), ManifestSHA256: hex.EncodeToString(manifestDigest),
		View: identity.View, Repo: identity.Repo, OS: identity.OS, Arch: identity.Arch,
		LegacyRoot: identity.LegacyRoot, RefCommit: identity.RefCommit,
		ConfigSHA256: identity.ConfigSHA256, RepositoryKeySHA256: identity.RepositoryKeySHA256,
	}
	return result, result.Validate()
}

func projectedGenerationID(digest []byte) string {
	value := binary.BigEndian.Uint64(digest[:8])
	if value == 0 && len(digest) >= 16 {
		value = binary.BigEndian.Uint64(digest[8:16])
	}
	if value == 0 {
		value = 1
	}
	return fmt.Sprintf("%020d", value)
}

func validateIdentity(identity Identity) error {
	for field, value := range map[string]string{"view": identity.View, "repo": identity.Repo, "os": identity.OS, "arch": identity.Arch} {
		if err := config.ValidateRouteSegment(value); err != nil {
			return fmt.Errorf("invalid generation %s: %w", field, err)
		}
	}
	if identity.View != "latest" && identity.View != "beta" && identity.View != "stable" {
		return fmt.Errorf("invalid mutable generation view %q", identity.View)
	}
	if err := validateLegacyRoot(identity.LegacyRoot); err != nil {
		return err
	}
	if !gitHashPattern.MatchString(identity.RefCommit) {
		return errors.New("invalid generation ref commit")
	}
	if !hexSHA256Pattern.MatchString(identity.ConfigSHA256) || !hexSHA256Pattern.MatchString(identity.RepositoryKeySHA256) {
		return errors.New("invalid generation config or repository-key digest")
	}
	return nil
}

func validateLegacyRoot(value string) error {
	if value == "" || path.IsAbs(value) || path.Clean(value) != value || strings.HasPrefix(value, "../") || strings.ContainsAny(value, "\\\x00\t\r\n") {
		return errors.New("invalid generation legacy root")
	}
	for _, segment := range strings.Split(value, "/") {
		if err := config.ValidateRouteSegment(segment); err != nil {
			return fmt.Errorf("invalid generation legacy root segment %q: %w", segment, err)
		}
	}
	return nil
}

func (generation Generation) Validate() error {
	if generation.Schema != GenerationSchema || !generationIDPattern.MatchString(generation.ID) || !hexSHA256Pattern.MatchString(generation.ContentSHA256) || !hexSHA256Pattern.MatchString(generation.ManifestSHA256) {
		return errors.New("invalid local YUM generation envelope")
	}
	digest, err := hex.DecodeString(generation.ContentSHA256)
	if err != nil || projectedGenerationID(digest) != generation.ID {
		return errors.New("generation ID does not match its full content digest")
	}
	return validateIdentity(Identity{
		View: generation.View, Repo: generation.Repo, OS: generation.OS, Arch: generation.Arch,
		LegacyRoot: generation.LegacyRoot, RefCommit: generation.RefCommit,
		ConfigSHA256: generation.ConfigSHA256, RepositoryKeySHA256: generation.RepositoryKeySHA256,
	})
}

func (generation Generation) Canonical() ([]byte, error) {
	if err := generation.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(generation)
}

func DecodeGeneration(data []byte) (Generation, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var generation Generation
	if err := decoder.Decode(&generation); err != nil {
		return generation, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return generation, errors.New("generation JSON has trailing data")
	}
	canonical, err := generation.Canonical()
	if err != nil {
		return generation, err
	}
	if !bytes.Equal(data, canonical) {
		return generation, errors.New("generation JSON is not canonical")
	}
	return generation, nil
}

// Channel is the canonical desired pointer state. ParentMirrorlistSHA256 binds
// a legal flip to the exact previous body; recovery accepts only parent,
// desired, or first-install absence and therefore never overwrites foreign
// local state.
type Channel struct {
	Schema                 string          `json:"schema"`
	View                   string          `json:"view"`
	Repo                   string          `json:"repo"`
	OS                     string          `json:"os"`
	Arch                   string          `json:"arch"`
	Generation             string          `json:"generation"`
	ContentSHA256          string          `json:"content_sha256"`
	ManifestSHA256         string          `json:"manifest_sha256"`
	LegacyRoot             string          `json:"legacy_root"`
	RefCommit              string          `json:"ref_commit"`
	ConfigSHA256           string          `json:"config_sha256"`
	RepositoryKeySHA256    string          `json:"repository_key_sha256"`
	BaseURL                string          `json:"base_url"`
	MirrorlistPath         string          `json:"mirrorlist_path"`
	MirrorlistSHA256       string          `json:"mirrorlist_sha256"`
	TargetID               string          `json:"target_id,omitempty"`
	TargetRoot             string          `json:"target_root,omitempty"`
	Previous               []GenerationPin `json:"previous,omitempty"`
	ParentGeneration       string          `json:"parent_generation,omitempty"`
	ParentMirrorlistSHA256 string          `json:"parent_mirrorlist_sha256,omitempty"`
	ParentTargetID         string          `json:"parent_target_id,omitempty"`
}

func NewChannel(generation Generation, baseURL string, parent *Channel) (Channel, error) {
	return newChannel(generation, TargetIdentity{}, baseURL, parent, 0)
}

// NewChannelForTarget advances one target-partitioned leaf and retains at
// most previousRetention prior generations, newest first. The current
// generation is never duplicated in Previous, so A -> B -> A remains bounded
// and produces current A with B as its direct retained predecessor.
func NewChannelForTarget(generation Generation, target TargetIdentity, parent *Channel, previousRetention int) (Channel, error) {
	if previousRetention < 1 {
		return Channel{}, errors.New("YUM generation previous retention must be positive")
	}
	if err := target.Validate(generation.View); err != nil {
		return Channel{}, err
	}
	return newChannel(generation, target, target.BaseURL, parent, previousRetention, false)
}

// NewChannelForTargetMigration safely rebinds the same physical target root
// to a changed base URL. The previous target channel remains the exact pointer
// parent and is named in ParentTargetID so the canonical transaction can
// delete that old channel while installing the new partition.
func NewChannelForTargetMigration(generation Generation, target TargetIdentity, parent *Channel, previousRetention int) (Channel, error) {
	if previousRetention < 1 {
		return Channel{}, errors.New("YUM generation previous retention must be positive")
	}
	if parent == nil {
		return Channel{}, errors.New("serving target migration requires a parent channel")
	}
	if err := target.Validate(generation.View); err != nil {
		return Channel{}, err
	}
	return newChannel(generation, target, target.BaseURL, parent, previousRetention, true)
}

func newChannel(generation Generation, target TargetIdentity, baseURL string, parent *Channel, previousRetention int, allowTargetMigration ...bool) (Channel, error) {
	if err := generation.Validate(); err != nil {
		return Channel{}, err
	}
	channel := Channel{
		Schema: ChannelSchema, View: generation.View, Repo: generation.Repo, OS: generation.OS, Arch: generation.Arch,
		Generation: generation.ID, ContentSHA256: generation.ContentSHA256, ManifestSHA256: generation.ManifestSHA256, LegacyRoot: generation.LegacyRoot,
		RefCommit: generation.RefCommit, ConfigSHA256: generation.ConfigSHA256, RepositoryKeySHA256: generation.RepositoryKeySHA256,
		BaseURL: baseURL, MirrorlistPath: MirrorlistPath(generation.View, generation.Repo, generation.OS, generation.Arch),
	}
	if target.ID != "" {
		channel.TargetID = target.ID
		channel.TargetRoot = target.Root
	}
	if parent != nil {
		if err := parent.Validate(); err != nil {
			return Channel{}, fmt.Errorf("invalid parent channel: %w", err)
		}
		if parent.View != channel.View || parent.Repo != channel.Repo || parent.OS != channel.OS || parent.Arch != channel.Arch {
			return Channel{}, errors.New("parent channel identity differs")
		}
		if target.ID != "" && (parent.TargetID != target.ID || parent.TargetRoot != target.Root || parent.BaseURL != target.BaseURL) {
			migration := len(allowTargetMigration) != 0 && allowTargetMigration[0]
			if !migration || parent.TargetID == "" || parent.TargetRoot != target.Root || parent.View != generation.View {
				return Channel{}, errors.New("parent channel serving target differs")
			}
			channel.ParentTargetID = parent.TargetID
		}
		channel.ParentGeneration = parent.Generation
		channel.ParentMirrorlistSHA256 = parent.MirrorlistSHA256
		if previousRetention > 0 {
			parentPin := GenerationPin{ID: parent.Generation, ContentSHA256: parent.ContentSHA256, ManifestSHA256: parent.ManifestSHA256}
			candidates := append([]GenerationPin{parentPin}, parent.Previous...)
			currentPin := GenerationPin{ID: generation.ID, ContentSHA256: generation.ContentSHA256, ManifestSHA256: generation.ManifestSHA256}
			seen := map[string]GenerationPin{currentPin.ID: currentPin}
			for _, pin := range candidates {
				if existing, exists := seen[pin.ID]; exists {
					if existing != pin {
						return Channel{}, errors.New("retained generation ID collision")
					}
					continue
				}
				seen[pin.ID] = pin
				channel.Previous = append(channel.Previous, pin)
				if len(channel.Previous) == previousRetention {
					break
				}
			}
		}
	}
	body, err := channel.MirrorlistBody()
	if err != nil {
		return Channel{}, err
	}
	digest := sha256.Sum256(body)
	channel.MirrorlistSHA256 = hex.EncodeToString(digest[:])
	return channel, channel.Validate()
}

func MirrorlistPath(view, repo, osName, arch string) string {
	return path.Join("_sow/v1/mirrorlist", view, repo, osName, arch+".txt")
}

func GenerationPath(generation, legacyRoot string) string {
	return path.Join("_sow/v1/g", generation, legacyRoot) + "/"
}

func (channel Channel) MirrorlistBody() ([]byte, error) {
	wantPath := ""
	if channel.View == "stable" {
		wantPath = "/pro/v1/basic"
	}
	if err := config.ValidateServingBaseURL(channel.BaseURL, wantPath); err != nil {
		return nil, err
	}
	if !generationIDPattern.MatchString(channel.Generation) {
		return nil, errors.New("invalid mirrorlist generation")
	}
	if err := validateLegacyRoot(channel.LegacyRoot); err != nil {
		return nil, err
	}
	route := "_sow/v1/g/" + channel.Generation + "/" + channel.LegacyRoot
	clientURL, err := config.CanonicalRouteURL(channel.BaseURL, route, true)
	if err != nil {
		return nil, fmt.Errorf("render mirrorlist URL: %w", err)
	}
	body := []byte(clientURL + "\n")
	if len(body) > mirrorlistMaxBytes {
		return nil, fmt.Errorf("mirrorlist body exceeds %d-byte limit", mirrorlistMaxBytes)
	}
	return body, nil
}

func (channel Channel) Validate() error {
	if channel.Schema != ChannelSchema || !generationIDPattern.MatchString(channel.Generation) || !hexSHA256Pattern.MatchString(channel.ContentSHA256) || !hexSHA256Pattern.MatchString(channel.ManifestSHA256) || !hexSHA256Pattern.MatchString(channel.MirrorlistSHA256) {
		return errors.New("invalid local YUM channel envelope")
	}
	currentPin := GenerationPin{ID: channel.Generation, ContentSHA256: channel.ContentSHA256, ManifestSHA256: channel.ManifestSHA256}
	if err := currentPin.Validate(); err != nil {
		return err
	}
	if channel.TargetID == "" != (channel.TargetRoot == "") {
		return errors.New("channel target ID and root must be present together")
	}
	if channel.TargetID != "" {
		if err := (TargetIdentity{Schema: TargetSchema, ID: channel.TargetID, Root: channel.TargetRoot, BaseURL: channel.BaseURL}).Validate(channel.View); err != nil {
			return err
		}
	}
	if channel.ParentGeneration == "" != (channel.ParentMirrorlistSHA256 == "") {
		return errors.New("channel parent generation and mirrorlist digest must be present together")
	}
	if channel.ParentGeneration != "" && (!generationIDPattern.MatchString(channel.ParentGeneration) || !hexSHA256Pattern.MatchString(channel.ParentMirrorlistSHA256)) {
		return errors.New("invalid channel parent state")
	}
	if channel.ParentTargetID != "" {
		if channel.ParentGeneration == "" || !hexSHA256Pattern.MatchString(channel.ParentTargetID) || channel.TargetID == "" || channel.ParentTargetID == channel.TargetID {
			return errors.New("invalid migrated channel parent target")
		}
	}
	seen := map[string]GenerationPin{currentPin.ID: currentPin}
	for _, pin := range channel.Previous {
		if err := pin.Validate(); err != nil {
			return err
		}
		if existing, exists := seen[pin.ID]; exists {
			if existing != pin {
				return errors.New("retained generation ID collision")
			}
			return errors.New("duplicate retained generation pin")
		}
		seen[pin.ID] = pin
	}
	if err := validateIdentity(Identity{
		View: channel.View, Repo: channel.Repo, OS: channel.OS, Arch: channel.Arch,
		LegacyRoot: channel.LegacyRoot, RefCommit: channel.RefCommit,
		ConfigSHA256: channel.ConfigSHA256, RepositoryKeySHA256: channel.RepositoryKeySHA256,
	}); err != nil {
		return err
	}
	if channel.MirrorlistPath != MirrorlistPath(channel.View, channel.Repo, channel.OS, channel.Arch) {
		return errors.New("channel mirrorlist path is not canonical")
	}
	body, err := channel.MirrorlistBody()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != channel.MirrorlistSHA256 {
		return errors.New("channel mirrorlist digest does not match rendered body")
	}
	return nil
}

func (channel Channel) Canonical() ([]byte, error) {
	if err := channel.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(channel)
}

func DecodeChannel(data []byte) (Channel, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var channel Channel
	if err := decoder.Decode(&channel); err != nil {
		return channel, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return channel, errors.New("channel JSON has trailing data")
	}
	canonical, err := channel.Canonical()
	if err != nil {
		return channel, err
	}
	if !bytes.Equal(data, canonical) {
		return channel, errors.New("channel JSON is not canonical")
	}
	return channel, nil
}

func GenerationManifestStatePath(generation Generation) string {
	return GenerationManifestStatePathFor(generation.ID, generation.View, generation.Repo, generation.OS, generation.Arch)
}

func GenerationManifestStatePathFor(generationID, view, repo, osName, arch string) string {
	return path.Join("serving/yum/generations", generationID, view, repo, osName, arch+".tsv")
}

func GenerationStatePath(generation Generation) string {
	return GenerationStatePathFor(generation.ID, generation.View, generation.Repo, generation.OS, generation.Arch)
}

func GenerationStatePathFor(generationID, view, repo, osName, arch string) string {
	return strings.TrimSuffix(GenerationManifestStatePathFor(generationID, view, repo, osName, arch), ".tsv") + ".json"
}

func ChannelStatePath(channel Channel) string {
	if channel.TargetID != "" {
		return path.Join("serving/yum/targets", channel.TargetID, "channels", channel.View, channel.Repo, channel.OS, channel.Arch+".json")
	}
	// Compatibility read path for ledgers written before target partitioning.
	// Production activation always supplies TargetID after the migration.
	return path.Join("serving/yum/channels", channel.View, channel.Repo, channel.OS, channel.Arch+".json")
}

func TargetStatePath(target TargetIdentity) string {
	return path.Join("serving/yum/targets", target.ID, "target.json")
}

// RetainedGenerationPins returns current plus Previous in serving order.
func (channel Channel) RetainedGenerationPins() ([]GenerationPin, error) {
	if err := channel.Validate(); err != nil {
		return nil, err
	}
	result := make([]GenerationPin, 0, 1+len(channel.Previous))
	result = append(result, GenerationPin{ID: channel.Generation, ContentSHA256: channel.ContentSHA256, ManifestSHA256: channel.ManifestSHA256})
	result = append(result, channel.Previous...)
	return result, nil
}

// RetainedGenerationManifestPaths is the canonical keep-set surface used by
// generation assembly and GC. Callers additionally union incomplete journal
// desired/parent pins before deleting any ledger or derived directory.
func RetainedGenerationManifestPaths(channel Channel) ([]string, error) {
	pins, err := channel.RetainedGenerationPins()
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(pins))
	for _, pin := range pins {
		result = append(result, GenerationManifestStatePathFor(pin.ID, channel.View, channel.Repo, channel.OS, channel.Arch))
	}
	return result, nil
}
