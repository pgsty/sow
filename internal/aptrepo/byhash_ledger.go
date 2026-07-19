package aptrepo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	byHashLedgerSchema  = "sow-apt-by-hash-ledger/v1"
	maxByHashLedgerSize = 16 << 20
)

// ByHashLedger is canonical, Git-tracked retention state for one materialized
// APT suite. Git history is the audit trail for generations removed from the
// current ledger after their immutable objects have been collected.
type ByHashLedger struct {
	Schema         string             `json:"schema"`
	Scope          string             `json:"scope"`
	Repo           string             `json:"repo"`
	Suite          string             `json:"suite"`
	LiveGeneration string             `json:"live_generation,omitempty"`
	LastSequence   uint64             `json:"last_sequence"`
	Generations    []ByHashGeneration `json:"generations"`
	LedgerSHA256   string             `json:"ledger_sha256"`
}

func NewByHashLedger(scope, repo, suite string) (ByHashLedger, error) {
	ledger := ByHashLedger{Schema: byHashLedgerSchema, Scope: scope, Repo: repo, Suite: suite, Generations: []ByHashGeneration{}}
	if err := ledger.validateIdentity(); err != nil {
		return ByHashLedger{}, err
	}
	ledger.LedgerSHA256 = sealByHashLedger(ledger)
	return ledger, nil
}

// DecodeByHashLedger uses a bounded strict decoder and verifies the ledger
// seal plus every complete generation before any cleanup decision is possible.
func DecodeByHashLedger(r io.Reader) (ByHashLedger, error) {
	if r == nil {
		return ByHashLedger{}, errors.New("aptrepo: nil by-hash ledger reader")
	}
	limited := &io.LimitedReader{R: r, N: maxByHashLedgerSize + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return ByHashLedger{}, fmt.Errorf("aptrepo: read by-hash ledger: %w", err)
	}
	if len(data) > maxByHashLedgerSize {
		return ByHashLedger{}, errors.New("aptrepo: by-hash ledger exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var ledger ByHashLedger
	if err := decoder.Decode(&ledger); err != nil {
		return ByHashLedger{}, fmt.Errorf("aptrepo: decode by-hash ledger: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return ByHashLedger{}, errors.New("aptrepo: by-hash ledger contains multiple JSON values")
		}
		return ByHashLedger{}, fmt.Errorf("aptrepo: decode trailing by-hash ledger data: %w", err)
	}
	if err := ledger.Validate(); err != nil {
		return ByHashLedger{}, err
	}
	return ledger, nil
}

func (ledger ByHashLedger) Validate() error {
	if ledger.Schema != byHashLedgerSchema {
		return fmt.Errorf("aptrepo: unsupported by-hash ledger schema %q", ledger.Schema)
	}
	if err := ledger.validateIdentity(); err != nil {
		return err
	}
	if !isLowerHex(ledger.LedgerSHA256, 64) || ledger.LedgerSHA256 != sealByHashLedger(ledger) {
		return errors.New("aptrepo: by-hash ledger checksum mismatch")
	}
	if len(ledger.Generations) == 0 {
		if ledger.LiveGeneration != "" || ledger.LastSequence != 0 {
			return errors.New("aptrepo: empty by-hash ledger has live or sequence state")
		}
		return nil
	}
	if ledger.LastSequence == 0 {
		return errors.New("aptrepo: populated by-hash ledger has no last sequence")
	}
	maxSequence := uint64(0)
	for _, generation := range ledger.Generations {
		if generation.Sequence > maxSequence {
			maxSequence = generation.Sequence
		}
	}
	if maxSequence > ledger.LastSequence {
		return errors.New("aptrepo: by-hash ledger generation exceeds last sequence")
	}
	if _, err := PlanByHashCleanup(ledger.Generations, len(ledger.Generations), ledger.LiveGeneration); err != nil {
		return fmt.Errorf("aptrepo: invalid by-hash ledger: %w", err)
	}
	return nil
}

func (ledger ByHashLedger) validateIdentity() error {
	for field, value := range map[string]string{"scope": ledger.Scope, "repo": ledger.Repo, "suite": ledger.Suite} {
		if value == "" || value == "." || value == ".." || strings.ContainsAny(value, "\\\x00\t\r\n") || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
			return fmt.Errorf("aptrepo: unsafe by-hash ledger %s %q", field, value)
		}
	}
	return nil
}

// Advance plans one post-InRelease cleanup and returns the canonical ledger
// that may be committed only after ApplyByHashCleanup succeeds. Replaying an
// already-recorded generation is byte-idempotent.
func (ledger ByHashLedger) Advance(generation ByHashGeneration, retain int) (ByHashLedger, CleanupPlan, error) {
	if err := ledger.Validate(); err != nil {
		return ByHashLedger{}, CleanupPlan{}, err
	}
	if generation.Sequence != 0 {
		return ByHashLedger{}, CleanupPlan{}, errors.New("aptrepo: new by-hash generation sequence must be assigned by its ledger")
	}
	paths := append([]string(nil), generation.Paths...)
	sort.Strings(paths)
	if hasDuplicate(paths) {
		return ByHashLedger{}, CleanupPlan{}, errors.New("aptrepo: new by-hash generation contains duplicate paths")
	}
	generation.Paths = paths
	if generation.PathsSHA256 != sealByHashPaths(generation.Paths) {
		return ByHashLedger{}, CleanupPlan{}, errors.New("aptrepo: new by-hash generation path-set checksum mismatch")
	}

	next := ledger
	next.Generations = append([]ByHashGeneration(nil), ledger.Generations...)
	found := -1
	for index := range next.Generations {
		if next.Generations[index].ID == generation.ID {
			found = index
			break
		}
	}
	if found >= 0 {
		existing := next.Generations[found]
		generation.Sequence = existing.Sequence
		if !sameByHashGeneration(existing, generation) {
			return ByHashLedger{}, CleanupPlan{}, fmt.Errorf("aptrepo: by-hash generation %q conflicts with canonical ledger", generation.ID)
		}
	} else {
		if next.LastSequence == ^uint64(0) {
			return ByHashLedger{}, CleanupPlan{}, errors.New("aptrepo: by-hash generation sequence exhausted")
		}
		next.LastSequence++
		generation.Sequence = next.LastSequence
		next.Generations = append(next.Generations, generation)
	}
	next.LiveGeneration = generation.ID
	// Two byte-distinct InRelease checkpoints can legitimately reference the
	// exact same immutable Packages index set (for example, a recoverable add
	// signing time followed by a deterministic ref-based materialization time).
	// Such checkpoints still advance LastSequence and the live ID, but must not
	// consume two retention slots: doing so can collect the previous genuinely
	// distinct index set one publication too early. Keep the live checkpoint for
	// its path set and the newest checkpoint for every other equivalent set.
	next.Generations = coalesceEquivalentByHashPathSets(next.Generations, generation.ID)
	plan, err := PlanByHashCleanup(next.Generations, retain, generation.ID)
	if err != nil {
		return ByHashLedger{}, CleanupPlan{}, err
	}
	retained := make(map[string]struct{}, len(plan.RetainedGenerationIDs))
	for _, id := range plan.RetainedGenerationIDs {
		retained[id] = struct{}{}
	}
	candidates := append([]ByHashGeneration(nil), next.Generations...)
	next.Generations = next.Generations[:0]
	for _, item := range candidates {
		if _, keep := retained[item.ID]; keep {
			next.Generations = append(next.Generations, item)
		}
	}
	sort.Slice(next.Generations, func(i, j int) bool { return next.Generations[i].Sequence < next.Generations[j].Sequence })
	next.LedgerSHA256 = sealByHashLedger(next)
	if err := next.Validate(); err != nil {
		return ByHashLedger{}, CleanupPlan{}, err
	}
	return next, plan, nil
}

func coalesceEquivalentByHashPathSets(generations []ByHashGeneration, liveGenerationID string) []ByHashGeneration {
	result := make([]ByHashGeneration, 0, len(generations))
	for _, candidate := range generations {
		equivalent := -1
		for index := range result {
			if sameByHashPathSet(result[index], candidate) {
				equivalent = index
				break
			}
		}
		if equivalent < 0 {
			result = append(result, candidate)
			continue
		}
		current := result[equivalent]
		if candidate.ID == liveGenerationID || (current.ID != liveGenerationID && newerByHashGeneration(candidate, current)) {
			result[equivalent] = candidate
		}
	}
	return result
}

func sameByHashPathSet(left, right ByHashGeneration) bool {
	if left.PathsSHA256 != right.PathsSHA256 || len(left.Paths) != len(right.Paths) {
		return false
	}
	leftPaths := append([]string(nil), left.Paths...)
	rightPaths := append([]string(nil), right.Paths...)
	sort.Strings(leftPaths)
	sort.Strings(rightPaths)
	for index := range leftPaths {
		if leftPaths[index] != rightPaths[index] {
			return false
		}
	}
	return true
}

func newerByHashGeneration(left, right ByHashGeneration) bool {
	if left.Sequence != right.Sequence {
		return left.Sequence > right.Sequence
	}
	if !left.CreatedAt.Equal(right.CreatedAt) {
		return left.CreatedAt.After(right.CreatedAt)
	}
	return left.ID > right.ID
}

func sameByHashGeneration(left, right ByHashGeneration) bool {
	if left.Sequence != right.Sequence || left.ID != right.ID || !left.CreatedAt.Equal(right.CreatedAt) || left.PathsSHA256 != right.PathsSHA256 || len(left.Paths) != len(right.Paths) {
		return false
	}
	for index := range left.Paths {
		if left.Paths[index] != right.Paths[index] {
			return false
		}
	}
	return true
}

func MarshalByHashLedger(ledger ByHashLedger) ([]byte, error) {
	if err := ledger.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("aptrepo: encode by-hash ledger: %w", err)
	}
	return append(data, '\n'), nil
}

func sealByHashLedger(ledger ByHashLedger) string {
	ledger.LedgerSHA256 = ""
	data, _ := json.Marshal(ledger)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
