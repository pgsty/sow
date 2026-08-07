package managed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/v2/state"
)

const (
	transitionSchema      = "sow/transition/c2-to-single/v1"
	transitionJournalName = "c2-to-single-v1.json"
	maxTransitionBytes    = 64 << 20
)

var transitionPhaseRank = map[string]int{
	"planned": 0, "staged": 1, "commit_intent": 2, "pointer_rollforward": 3,
	"grace": 4, "alias_delete": 5, "final_manifest": 6, "done": 7,
}

type TransitionSize int64

func (size TransitionSize) MarshalJSON() ([]byte, error) {
	if size < 0 {
		return nil, errors.New("negative transition size")
	}
	return json.Marshal(strconv.FormatInt(int64(size), 10))
}

func (size *TransitionSize) UnmarshalJSON(data []byte) error {
	if size == nil {
		return errors.New("nil transition size receiver")
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("transition alias size must be a JSON string")
	}
	if value == "" || len(value) > 1 && value[0] == '0' {
		return errors.New("transition alias size is not canonical decimal")
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 || strconv.FormatInt(parsed, 10) != value {
		return errors.New("transition alias size is outside 0..MaxInt64")
	}
	*size = TransitionSize(parsed)
	return nil
}

type TransitionPointer struct {
	ViewID    string `json:"view_id"`
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	OldSHA256 string `json:"old_sha256"`
	NewSHA256 string `json:"new_sha256"`
	State     string `json:"state"`
}

type TransitionLegacyAlias struct {
	Path          string         `json:"path"`
	Size          TransitionSize `json:"size"`
	SHA256        string         `json:"sha256"`
	State         string         `json:"state"`
	ReceiptSHA256 *string        `json:"receipt_sha256"`
}

type C2ToSingleTransition struct {
	Schema               string                  `json:"schema"`
	RepositoryID         string                  `json:"repository_id"`
	FromLayout           string                  `json:"from_layout"`
	ToLayout             string                  `json:"to_layout"`
	BaseGeneration       state.GenerationID      `json:"base_generation"`
	BaseManifestSHA256   string                  `json:"base_manifest_sha256"`
	TargetManifestSHA256 string                  `json:"target_manifest_sha256"`
	Phase                string                  `json:"phase"`
	CommitIntent         bool                    `json:"commit_intent"`
	GraceNotBefore       *string                 `json:"grace_not_before"`
	Pointers             []TransitionPointer     `json:"pointers"`
	LegacyAliases        []TransitionLegacyAlias `json:"legacy_aliases"`
}

func CanonicalAliasDeletionReceipt(repositoryID, aliasPath string, size int64, digest string) (string, error) {
	if !state.IsCanonicalRepositoryID(repositoryID) || !canonicalLegacyAliasPath(aliasPath) || size < 0 || !lowercaseSHA256.MatchString(digest) {
		return "", errors.New("invalid C2 alias deletion receipt input")
	}
	hash := sha256.New()
	for index, component := range []string{"sow/c2-alias-delete/v1", repositoryID, aliasPath, strconv.FormatInt(size, 10), digest} {
		if index != 0 {
			hash.Write([]byte{0})
		}
		io.WriteString(hash, component)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func canonicalTransitionJournal(journal C2ToSingleTransition) ([]byte, error) {
	if err := validateTransitionJournal(journal); err != nil {
		return nil, err
	}
	var output strings.Builder
	output.WriteByte('{')
	writeName := func(name string, first bool) {
		if !first {
			output.WriteByte(',')
		}
		output.WriteString(canonicalJSONString(name))
		output.WriteByte(':')
	}
	writeName("base_generation", true)
	output.WriteString(canonicalJSONString(journal.BaseGeneration.String()))
	writeName("base_manifest_sha256", false)
	output.WriteString(canonicalJSONString(journal.BaseManifestSHA256))
	writeName("commit_intent", false)
	if journal.CommitIntent {
		output.WriteString("true")
	} else {
		output.WriteString("false")
	}
	writeName("from_layout", false)
	output.WriteString(canonicalJSONString(journal.FromLayout))
	writeName("grace_not_before", false)
	if journal.GraceNotBefore == nil {
		output.WriteString("null")
	} else {
		output.WriteString(canonicalJSONString(*journal.GraceNotBefore))
	}
	writeName("legacy_aliases", false)
	output.WriteByte('[')
	for index, alias := range journal.LegacyAliases {
		if index != 0 {
			output.WriteByte(',')
		}
		output.WriteByte('{')
		output.WriteString(`"path":` + canonicalJSONString(alias.Path))
		output.WriteString(`,"receipt_sha256":`)
		if alias.ReceiptSHA256 == nil {
			output.WriteString("null")
		} else {
			output.WriteString(canonicalJSONString(*alias.ReceiptSHA256))
		}
		output.WriteString(`,"sha256":` + canonicalJSONString(alias.SHA256))
		output.WriteString(`,"size":` + canonicalJSONString(strconv.FormatInt(int64(alias.Size), 10)))
		output.WriteString(`,"state":` + canonicalJSONString(alias.State))
		output.WriteByte('}')
	}
	output.WriteByte(']')
	writeName("phase", false)
	output.WriteString(canonicalJSONString(journal.Phase))
	writeName("pointers", false)
	output.WriteByte('[')
	for index, pointer := range journal.Pointers {
		if index != 0 {
			output.WriteByte(',')
		}
		output.WriteByte('{')
		output.WriteString(`"kind":` + canonicalJSONString(pointer.Kind))
		output.WriteString(`,"new_sha256":` + canonicalJSONString(pointer.NewSHA256))
		output.WriteString(`,"old_sha256":` + canonicalJSONString(pointer.OldSHA256))
		output.WriteString(`,"path":` + canonicalJSONString(pointer.Path))
		output.WriteString(`,"state":` + canonicalJSONString(pointer.State))
		output.WriteString(`,"view_id":` + canonicalJSONString(pointer.ViewID))
		output.WriteByte('}')
	}
	output.WriteByte(']')
	writeName("repository_id", false)
	output.WriteString(canonicalJSONString(journal.RepositoryID))
	writeName("schema", false)
	output.WriteString(canonicalJSONString(journal.Schema))
	writeName("target_manifest_sha256", false)
	output.WriteString(canonicalJSONString(journal.TargetManifestSHA256))
	writeName("to_layout", false)
	output.WriteString(canonicalJSONString(journal.ToLayout))
	output.WriteByte('}')
	return []byte(output.String()), nil
}

func ParseC2ToSingleTransition(data []byte) (C2ToSingleTransition, string, error) {
	if len(data) == 0 || len(data) > maxTransitionBytes {
		return C2ToSingleTransition{}, "", errors.New("transition journal is empty or unbounded")
	}
	if err := rejectDuplicateJSONMembers(data); err != nil {
		return C2ToSingleTransition{}, "", err
	}
	var journal C2ToSingleTransition
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return C2ToSingleTransition{}, "", err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return C2ToSingleTransition{}, "", errors.New("transition journal has trailing content")
	}
	canonical, err := canonicalTransitionJournal(journal)
	if err != nil {
		return C2ToSingleTransition{}, "", err
	}
	if !bytes.Equal(data, canonical) {
		return C2ToSingleTransition{}, "", errors.New("transition journal is not RFC 8785 canonical JSON")
	}
	return journal, domainDigest(transitionSchema, canonical), nil
}

func validateTransitionJournal(journal C2ToSingleTransition) error {
	rank, validPhase := transitionPhaseRank[journal.Phase]
	if journal.Schema != transitionSchema || !state.IsCanonicalRepositoryID(journal.RepositoryID) ||
		journal.FromLayout != state.LayoutC2V1 || journal.ToLayout != state.LayoutSinglePayloadV1 || !validPhase ||
		!lowercaseSHA256.MatchString(journal.BaseManifestSHA256) || !lowercaseSHA256.MatchString(journal.TargetManifestSHA256) ||
		journal.CommitIntent != (rank >= transitionPhaseRank["commit_intent"]) {
		return errors.New("invalid transition journal header")
	}
	if rank < transitionPhaseRank["grace"] {
		if journal.GraceNotBefore != nil {
			return errors.New("transition grace deadline appears before grace phase")
		}
	} else {
		if journal.GraceNotBefore == nil {
			return errors.New("transition grace deadline is absent")
		}
		parsed, err := time.Parse(time.RFC3339, *journal.GraceNotBefore)
		if err != nil || parsed.Location() != time.UTC || parsed.Format("2006-01-02T15:04:05Z") != *journal.GraceNotBefore {
			return errors.New("transition grace deadline is not canonical UTC RFC3339 seconds")
		}
	}
	kindRank := map[string]int{"signature_companion": 0, "commit_pointer": 1}
	pointerPaths := map[string]struct{}{}
	commitPointers := map[string]int{}
	signaturePointers := map[string]int{}
	for index, pointer := range journal.Pointers {
		viewParts := strings.Split(pointer.ViewID, "/")
		if _, ok := kindRank[pointer.Kind]; !ok || pointer.State != "old" && pointer.State != "new" ||
			!canonicalRepositoryPath(pointer.ViewID) || len(viewParts) != 3 || viewParts[0] != "dists" ||
			!canonicalRepositoryPath(pointer.Path) ||
			!lowercaseSHA256.MatchString(pointer.OldSHA256) || !lowercaseSHA256.MatchString(pointer.NewSHA256) {
			return fmt.Errorf("invalid transition pointer at index %d", index)
		}
		if pointer.Kind == "signature_companion" && pointer.Path != pointer.ViewID+"/repodata/repomd.xml.asc" ||
			pointer.Kind == "commit_pointer" && pointer.Path != pointer.ViewID+"/repodata/repomd.xml" {
			return fmt.Errorf("transition pointer kind/path mismatch at index %d", index)
		}
		if pointer.Kind == "commit_pointer" {
			commitPointers[pointer.ViewID]++
		} else {
			signaturePointers[pointer.ViewID]++
		}
		key := pointer.ViewID + "\x00" + pointer.Kind + "\x00" + pointer.Path
		if _, duplicate := pointerPaths[key]; duplicate {
			return errors.New("duplicate transition pointer")
		}
		pointerPaths[key] = struct{}{}
		if index > 0 {
			previous := journal.Pointers[index-1]
			if previous.ViewID > pointer.ViewID || previous.ViewID == pointer.ViewID && (kindRank[previous.Kind] > kindRank[pointer.Kind] || kindRank[previous.Kind] == kindRank[pointer.Kind] && previous.Path >= pointer.Path) {
				return errors.New("transition pointers are not in canonical order")
			}
		}
	}
	for viewID, count := range commitPointers {
		if count != 1 || signaturePointers[viewID] > 1 {
			return fmt.Errorf("transition view %q does not have exactly one canonical commit pointer", viewID)
		}
	}
	for viewID := range signaturePointers {
		if commitPointers[viewID] != 1 {
			return fmt.Errorf("transition signature view %q lacks its canonical commit pointer", viewID)
		}
	}
	for index, alias := range journal.LegacyAliases {
		if !canonicalLegacyAliasPath(alias.Path) || alias.Size < 0 || !lowercaseSHA256.MatchString(alias.SHA256) || alias.State != "present" && alias.State != "deleted" {
			return fmt.Errorf("invalid legacy alias at index %d", index)
		}
		if index > 0 && journal.LegacyAliases[index-1].Path >= alias.Path {
			return errors.New("transition aliases are duplicate or not bytewise sorted")
		}
		if alias.State == "present" {
			if alias.ReceiptSHA256 != nil {
				return errors.New("present transition alias has a deletion receipt")
			}
		} else {
			if alias.ReceiptSHA256 == nil || !lowercaseSHA256.MatchString(*alias.ReceiptSHA256) {
				return errors.New("deleted transition alias lacks a canonical receipt")
			}
			want, _ := CanonicalAliasDeletionReceipt(journal.RepositoryID, alias.Path, int64(alias.Size), alias.SHA256)
			if *alias.ReceiptSHA256 != want {
				return errors.New("transition alias deletion receipt differs")
			}
		}
	}
	return nil
}

func canonicalRepositoryPath(value string) bool {
	if value == "" || value == "." || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "../") ||
		path.Clean(value) != value || strings.ContainsAny(value, "\\\x00\r\n\t?#") {
		return false
	}
	// Transition v1 intentionally accepts an ASCII path language.  Besides
	// making receipt bytes unambiguous, this prevents an implementation from
	// mistaking encoding/json's HTML escaping for RFC 8785 serialization.
	for index := 0; index < len(value); index++ {
		c := value[index]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '/', '.', '-', '_', '+', '~', '^', ':', '%':
			continue
		default:
			return false
		}
	}
	return true
}

func canonicalLegacyAliasPath(value string) bool {
	if !canonicalRepositoryPath(value) {
		return false
	}
	parts := strings.Split(value, "/")
	return len(parts) >= 6 && parts[0] == "dists" && parts[1] != "" && parts[2] != "" && parts[3] == "pool"
}

func sortTransitionPointers(pointers []TransitionPointer) {
	kindRank := map[string]int{"signature_companion": 0, "commit_pointer": 1}
	sort.Slice(pointers, func(i, j int) bool {
		if pointers[i].ViewID != pointers[j].ViewID {
			return pointers[i].ViewID < pointers[j].ViewID
		}
		if kindRank[pointers[i].Kind] != kindRank[pointers[j].Kind] {
			return kindRank[pointers[i].Kind] < kindRank[pointers[j].Kind]
		}
		return pointers[i].Path < pointers[j].Path
	})
}
