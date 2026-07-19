package serving

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
)

const RetiredGenerationSchema = "sow-local-yum-retired-generation/v1"

// RetiredGeneration preserves the collision-resistant identity needed to
// validate and explicitly remove derived generation directories. Its paired
// retired manifest is deletion evidence only: GC deliberately does not treat
// that path as a CAS root, so retirement still releases payload reachability.
type RetiredGeneration struct {
	Schema     string     `json:"schema"`
	Generation Generation `json:"generation"`
}

func NewRetiredGeneration(generation Generation) (RetiredGeneration, error) {
	result := RetiredGeneration{Schema: RetiredGenerationSchema, Generation: generation}
	return result, result.Validate()
}

func (retired RetiredGeneration) Validate() error {
	if retired.Schema != RetiredGenerationSchema {
		return errors.New("invalid retired YUM generation schema")
	}
	return retired.Generation.Validate()
}

func (retired RetiredGeneration) Canonical() ([]byte, error) {
	if err := retired.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(retired)
}

func DecodeRetiredGeneration(data []byte) (RetiredGeneration, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var retired RetiredGeneration
	if err := decoder.Decode(&retired); err != nil {
		return retired, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return retired, errors.New("retired YUM generation JSON has trailing data")
	}
	canonical, err := retired.Canonical()
	if err != nil {
		return retired, err
	}
	if !bytes.Equal(data, canonical) {
		return retired, errors.New("retired YUM generation JSON is not canonical")
	}
	return retired, nil
}

func RetiredGenerationStatePath(generation Generation) string {
	return path.Join("serving/yum/retired", generation.ID, generation.View, generation.Repo, generation.OS, generation.Arch+".json")
}

// RetiredGenerationManifestStatePath is the exact deletion witness paired
// with a retired generation. Keeping the manifest after removing the active
// ledger makes a partially interrupted directory removal recoverable: every
// remaining entry can still be proven to belong to the original generation.
// This path is intentionally distinct from GenerationManifestStatePath and is
// never added to the CAS root set.
func RetiredGenerationManifestStatePath(generation Generation) string {
	return path.Join("serving/yum/retired", generation.ID, generation.View, generation.Repo, generation.OS, generation.Arch+".tsv")
}

func IsRetiredGenerationStatePath(value string) bool {
	if path.Clean(value) != value || !strings.HasSuffix(value, ".json") {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) != 8 || parts[0] != "serving" || parts[1] != "yum" || parts[2] != "retired" || !generationIDPattern.MatchString(parts[3]) {
		return false
	}
	coordinate := GenerationCoordinate{ID: parts[3], View: parts[4], Repo: parts[5], OS: parts[6], Arch: strings.TrimSuffix(parts[7], ".json")}
	return coordinate.validate() == nil
}

func IsRetiredGenerationManifestStatePath(value string) bool {
	if path.Clean(value) != value || !strings.HasSuffix(value, ".tsv") {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) != 8 || parts[0] != "serving" || parts[1] != "yum" || parts[2] != "retired" || !generationIDPattern.MatchString(parts[3]) {
		return false
	}
	coordinate := GenerationCoordinate{ID: parts[3], View: parts[4], Repo: parts[5], OS: parts[6], Arch: strings.TrimSuffix(parts[7], ".tsv")}
	return coordinate.validate() == nil
}

// GenerationCoordinate names one immutable serving ledger independently of
// the target channels that retain it. Identical coordinates may be shared by
// several targets; deletion is legal only after the global keep set drops it.
type GenerationCoordinate struct {
	ID   string
	View string
	Repo string
	OS   string
	Arch string
}

func (coordinate GenerationCoordinate) validate() error {
	if !generationIDPattern.MatchString(coordinate.ID) {
		return errors.New("invalid retained generation coordinate")
	}
	return validateIdentity(Identity{
		View: coordinate.View, Repo: coordinate.Repo, OS: coordinate.OS, Arch: coordinate.Arch,
		LegacyRoot: "placeholder", RefCommit: "0000000000000000000000000000000000000000",
		ConfigSHA256:        "0000000000000000000000000000000000000000000000000000000000000000",
		RepositoryKeySHA256: "0000000000000000000000000000000000000000000000000000000000000000",
	})
}

func (coordinate GenerationCoordinate) ManifestPath() (string, error) {
	if err := coordinate.validate(); err != nil {
		return "", err
	}
	return GenerationManifestStatePathFor(coordinate.ID, coordinate.View, coordinate.Repo, coordinate.OS, coordinate.Arch), nil
}

func (coordinate GenerationCoordinate) JSONPath() (string, error) {
	if err := coordinate.validate(); err != nil {
		return "", err
	}
	return GenerationStatePathFor(coordinate.ID, coordinate.View, coordinate.Repo, coordinate.OS, coordinate.Arch), nil
}

func (channel Channel) RetainedGenerationCoordinates() ([]GenerationCoordinate, error) {
	pins, err := channel.RetainedGenerationPins()
	if err != nil {
		return nil, err
	}
	result := make([]GenerationCoordinate, 0, len(pins))
	for _, pin := range pins {
		result = append(result, GenerationCoordinate{ID: pin.ID, View: channel.View, Repo: channel.Repo, OS: channel.OS, Arch: channel.Arch})
	}
	return result, nil
}

// RetainedGenerationKeepSet returns canonical manifest paths for every
// current/previous channel pin plus every incomplete journal desired/parent
// coordinate supplied by the caller. This pure helper is also the assembly
// surface for retained Packages compatibility hardlinks.
func RetainedGenerationKeepSet(channels []Channel, journalPins []GenerationCoordinate) (map[string]struct{}, error) {
	keep := make(map[string]struct{})
	for _, channel := range channels {
		coordinates, err := channel.RetainedGenerationCoordinates()
		if err != nil {
			return nil, err
		}
		for _, coordinate := range coordinates {
			manifestPath, err := coordinate.ManifestPath()
			if err != nil {
				return nil, err
			}
			keep[manifestPath] = struct{}{}
		}
	}
	for _, coordinate := range journalPins {
		manifestPath, err := coordinate.ManifestPath()
		if err != nil {
			return nil, err
		}
		keep[manifestPath] = struct{}{}
	}
	return keep, nil
}

// IsGenerationManifestStatePath identifies only a complete canonical serving
// generation manifest, not arbitrary files beneath the serving namespace.
func IsGenerationManifestStatePath(value string) bool {
	if path.Clean(value) != value || path.Ext(value) != ".tsv" {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) != 8 || parts[0] != "serving" || parts[1] != "yum" || parts[2] != "generations" || !generationIDPattern.MatchString(parts[3]) {
		return false
	}
	coordinate := GenerationCoordinate{ID: parts[3], View: parts[4], Repo: parts[5], OS: parts[6], Arch: parts[7][:len(parts[7])-len(".tsv")]}
	return coordinate.validate() == nil
}
