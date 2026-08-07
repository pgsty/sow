package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const PublicationPlanSchemaV1 = "sow/publication-plan/v1"

type PublicationPlanInput struct {
	RepositoryID     string
	TargetIdentity   string
	BaseCheckpoint   string
	TargetGeneration GenerationID
	BaseManifest     []GenerationFile
	TargetManifest   []GenerationFile
	Changes          []FileChange
}

type PublicationPlanOperation struct {
	Operation         string `json:"op"`
	Path              string `json:"path"`
	Phase             string `json:"phase"`
	Size              int64  `json:"size"`
	SHA256            string `json:"sha256,omitempty"`
	ExpectedOldSHA256 string `json:"expected_old_sha256,omitempty"`
}

type PublicationCommitUnit struct {
	ViewID   string                     `json:"view_id"`
	Protocol string                     `json:"protocol"`
	Pointers []PublicationPlanOperation `json:"pointers"`
}

type PublicationPlan struct {
	Schema            string                     `json:"schema"`
	RepositoryID      string                     `json:"repository_id"`
	TargetIdentity    string                     `json:"target_identity"`
	BaseCheckpoint    string                     `json:"base_checkpoint,omitempty"`
	TargetGeneration  GenerationID               `json:"target_generation"`
	ManifestSHA256    string                     `json:"manifest_sha256"`
	Payload           []PublicationPlanOperation `json:"payload"`
	ImmutableMetadata []PublicationPlanOperation `json:"immutable_metadata"`
	StableAliases     []PublicationPlanOperation `json:"stable_aliases"`
	CommitUnits       []PublicationCommitUnit    `json:"commit_units"`
	DeleteCandidates  []PublicationPlanOperation `json:"delete_candidates"`
	PlanSHA256        string                     `json:"plan_sha256"`
}

// BuildPublicationPlan is target-neutral and side-effect free. It verifies
// that Changes is the exact canonical delta between two already canonical
// Generation manifests, then derives target-scoped commit units.
func BuildPublicationPlan(input PublicationPlanInput) (PublicationPlan, error) {
	if !IsCanonicalRepositoryID(input.RepositoryID) || !validSHA256Text(input.TargetIdentity) || input.BaseCheckpoint != "" && !validSHA256Text(input.BaseCheckpoint) || input.TargetGeneration == 0 {
		return PublicationPlan{}, errors.New("invalid publication plan identity")
	}
	if input.BaseCheckpoint == "" && len(input.BaseManifest) != 0 {
		return PublicationPlan{}, errors.New("empty base checkpoint requires an empty base manifest")
	}
	if !canonicalManifestArray(input.BaseManifest) || !canonicalManifestArray(input.TargetManifest) {
		return PublicationPlan{}, errors.New("publication plan manifests must be sorted and duplicate-free")
	}
	_, manifestSHA, err := ManifestBytes(input.TargetManifest)
	if err != nil {
		return PublicationPlan{}, err
	}
	expected := DiffManifests(input.BaseManifest, input.TargetManifest)
	if !canonicalChangeArray(input.Changes) || !equalFileChanges(input.Changes, expected) {
		return PublicationPlan{}, errors.New("publication Changeset is not the exact canonical Generation delta")
	}
	plan := PublicationPlan{
		Schema: PublicationPlanSchemaV1, RepositoryID: input.RepositoryID, TargetIdentity: input.TargetIdentity,
		BaseCheckpoint: input.BaseCheckpoint, TargetGeneration: input.TargetGeneration, ManifestSHA256: manifestSHA,
		Payload: []PublicationPlanOperation{}, ImmutableMetadata: []PublicationPlanOperation{}, StableAliases: []PublicationPlanOperation{}, CommitUnits: []PublicationCommitUnit{}, DeleteCandidates: []PublicationPlanOperation{},
	}
	pointerChanges := make(map[string][]PublicationPlanOperation)
	protocols := make(map[string]string)
	baseByPath := make(map[string]GenerationFile, len(input.BaseManifest))
	for _, file := range input.BaseManifest {
		baseByPath[file.Path] = file
	}
	for _, change := range input.Changes {
		op := PublicationPlanOperation{Operation: change.Operation, Path: change.Path, Phase: change.Phase, Size: change.Size, SHA256: change.SHA256}
		if change.Operation == "update" {
			op.ExpectedOldSHA256 = baseByPath[change.Path].SHA256
		}
		switch change.Phase {
		case "payload":
			plan.Payload = append(plan.Payload, op)
		case "metadata":
			if isAPTStableAlias(change.Path) {
				plan.StableAliases = append(plan.StableAliases, op)
			} else {
				plan.ImmutableMetadata = append(plan.ImmutableMetadata, op)
			}
		case "pointer":
			viewID, protocol, ok := publicationPointerView(change.Path)
			if !ok {
				return PublicationPlan{}, fmt.Errorf("unknown publication commit pointer %q", change.Path)
			}
			if previous := protocols[viewID]; previous != "" && previous != protocol {
				return PublicationPlan{}, fmt.Errorf("publication view %q mixes protocols", viewID)
			}
			protocols[viewID] = protocol
			pointerChanges[viewID] = append(pointerChanges[viewID], op)
		case "delete":
			prior, ok := baseByPath[change.Path]
			if !ok {
				return PublicationPlan{}, fmt.Errorf("publication deletion %q lacks base identity", change.Path)
			}
			if prior.Phase == "pointer" {
				return PublicationPlan{}, fmt.Errorf("publication pointer removal %q is unsupported; signing-mode and view withdrawal transitions require an explicit safe protocol", change.Path)
			}
			op.Size, op.SHA256, op.ExpectedOldSHA256 = prior.Size, prior.SHA256, prior.SHA256
			plan.DeleteCandidates = append(plan.DeleteCandidates, op)
		default:
			return PublicationPlan{}, fmt.Errorf("unknown publication phase %q", change.Phase)
		}
	}
	viewIDs := make([]string, 0, len(pointerChanges))
	for viewID := range pointerChanges {
		viewIDs = append(viewIDs, viewID)
	}
	sort.Strings(viewIDs)
	targetByPath := make(map[string]GenerationFile, len(input.TargetManifest))
	for _, file := range input.TargetManifest {
		targetByPath[file.Path] = file
	}
	for _, viewID := range viewIDs {
		ordered, err := orderPublicationPointers(viewID, protocols[viewID], pointerChanges[viewID], targetByPath)
		if err != nil {
			return PublicationPlan{}, err
		}
		plan.CommitUnits = append(plan.CommitUnits, PublicationCommitUnit{ViewID: viewID, Protocol: protocols[viewID], Pointers: ordered})
	}
	plan.PlanSHA256, err = publicationPlanDigest(plan)
	if err != nil {
		return PublicationPlan{}, err
	}
	return plan, nil
}

func PublicationPlanBytes(plan PublicationPlan) ([]byte, error) {
	want, err := publicationPlanDigest(plan)
	if err != nil {
		return nil, err
	}
	if plan.PlanSHA256 != want {
		return nil, errors.New("publication plan digest mismatch")
	}
	return json.Marshal(plan)
}

func publicationPlanDigest(plan PublicationPlan) (string, error) {
	copyPlan := plan
	copyPlan.PlanSHA256 = ""
	data, err := json.Marshal(copyPlan)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func publicationPointerView(value string) (string, string, bool) {
	if strings.HasSuffix(value, "/repodata/repomd.xml") || strings.HasSuffix(value, "/repodata/repomd.xml.asc") {
		view := strings.TrimSuffix(strings.TrimSuffix(value, "/repomd.xml.asc"), "/repomd.xml")
		view = strings.TrimSuffix(view, "/repodata")
		return view, "rpm", strings.HasPrefix(view, "dists/")
	}
	parts := strings.Split(value, "/")
	if len(parts) == 3 && parts[0] == "dists" && (parts[2] == "Release.gpg" || parts[2] == "Release" || parts[2] == "InRelease") {
		return strings.Join(parts[:2], "/"), "apt", true
	}
	return "", "", false
}

func orderPublicationPointers(viewID, protocol string, changes []PublicationPlanOperation, target map[string]GenerationFile) ([]PublicationPlanOperation, error) {
	byPath := make(map[string]PublicationPlanOperation, len(changes))
	for _, change := range changes {
		if _, duplicate := byPath[change.Path]; duplicate {
			return nil, fmt.Errorf("publication view %q repeats pointer %q", viewID, change.Path)
		}
		byPath[change.Path] = change
	}
	var names []string
	switch protocol {
	case "rpm":
		names = []string{"repodata/repomd.xml.asc", "repodata/repomd.xml"}
	case "apt":
		names = []string{"Release.gpg", "Release", "InRelease"}
		_, hasDetached := target[viewID+"/Release.gpg"]
		_, hasInline := target[viewID+"/InRelease"]
		if hasDetached != hasInline {
			return nil, fmt.Errorf("publication view %q has an incomplete APT signature pair", viewID)
		}
	default:
		return nil, fmt.Errorf("unknown publication protocol %q", protocol)
	}
	commitName := "repodata/repomd.xml"
	if protocol == "apt" {
		commitName = "Release"
	}
	if _, ok := byPath[viewID+"/"+commitName]; !ok {
		return nil, fmt.Errorf("publication view %q changes companions without its commit pointer", viewID)
	}
	ordered := make([]PublicationPlanOperation, 0, len(changes))
	for _, name := range names {
		pointerPath := viewID + "/" + name
		if _, exists := target[pointerPath]; exists {
			operation, changed := byPath[pointerPath]
			if !changed {
				return nil, fmt.Errorf("publication view %q changed its commit pointer without changed companion %q", viewID, pointerPath)
			}
			ordered = append(ordered, operation)
			delete(byPath, pointerPath)
		}
	}
	if len(byPath) != 0 || len(ordered) == 0 {
		return nil, fmt.Errorf("publication view %q has an incomplete or unknown pointer unit", viewID)
	}
	return ordered, nil
}

func canonicalManifestArray(files []GenerationFile) bool {
	normalized, _, err := normalizeManifestForLayout(files, LayoutSinglePayloadV1)
	if err != nil || !sameGenerationFiles(normalized, files) {
		return false
	}
	previous := ""
	for _, file := range files {
		if file.Path <= previous || !validPublicationPath(file.Path) || file.Size < 0 || !validSHA256Text(file.SHA256) || file.Phase != "payload" && file.Phase != "metadata" && file.Phase != "pointer" {
			return false
		}
		previous = file.Path
	}
	return true
}

func isAPTStableAlias(value string) bool {
	if !strings.HasPrefix(value, "dists/") || strings.Contains(value, "/repodata/") || strings.Contains(value, "/by-hash/") {
		return false
	}
	_, _, pointer := publicationPointerView(value)
	return !pointer
}

func canonicalChangeArray(changes []FileChange) bool {
	expected := append([]FileChange(nil), changes...)
	sort.Slice(expected, func(i, j int) bool {
		rank := map[string]int{"payload": 0, "metadata": 1, "pointer": 2, "delete": 3}
		if rank[expected[i].Phase] != rank[expected[j].Phase] {
			return rank[expected[i].Phase] < rank[expected[j].Phase]
		}
		return expected[i].Path < expected[j].Path
	})
	seen := make(map[string]struct{}, len(changes))
	for index, change := range changes {
		if change != expected[index] {
			return false
		}
		if _, duplicate := seen[change.Path]; duplicate {
			return false
		}
		seen[change.Path] = struct{}{}
	}
	return true
}
