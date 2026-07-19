package cli

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

const (
	yumCompatibilityCutoverEventSchema  = "sow-yum-compatibility-cutover/v1"
	maximumYUMCompatibilityLedgerBytes  = 1 << 20
	maximumYUMCompatibilityLedgerEvents = 1024
)

type yumCompatibilityStage string

const (
	yumCompatibilityStageS0         yumCompatibilityStage = "S0-raw"
	yumCompatibilityStageS1         yumCompatibilityStage = "S1-adopted"
	yumCompatibilityStageS2         yumCompatibilityStage = "S2-frozen-precutover"
	yumCompatibilityStageS3         yumCompatibilityStage = "S3-active"
	yumCompatibilityStageRolledBack yumCompatibilityStage = "S3-rolled-back"
)

type yumCompatibilityCutoverEvent struct {
	Schema                  string `json:"schema"`
	Sequence                int64  `json:"sequence"`
	ID                      string `json:"id"`
	Action                  string `json:"action"`
	ServingLink             string `json:"serving_link"`
	FromTarget              string `json:"from_target"`
	ToTarget                string `json:"to_target"`
	FreezeCommit            string `json:"freeze_commit"`
	CandidateManifestSHA256 string `json:"candidate_manifest_sha256"`
	PreviousEventSHA256     string `json:"previous_event_sha256"`
	EventSHA256             string `json:"event_sha256"`
}

func decodeYUMCompatibilityCutoverLedger(body []byte) ([]yumCompatibilityCutoverEvent, error) {
	if len(body) == 0 || len(body) > maximumYUMCompatibilityLedgerBytes {
		return nil, errors.New("YUM compatibility cutover ledger is empty or exceeds its bound")
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), maximumYUMCompatibilityLedgerBytes)
	var events []yumCompatibilityCutoverEvent
	for scanner.Scan() {
		if len(events) == maximumYUMCompatibilityLedgerEvents {
			return nil, errors.New("YUM compatibility cutover ledger has too many events")
		}
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return nil, errors.New("YUM compatibility cutover ledger contains an empty line")
		}
		var event yumCompatibilityCutoverEvent
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return nil, fmt.Errorf("decode YUM compatibility cutover event %d: %w", len(events)+1, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("YUM compatibility cutover event %d has trailing JSON", len(events)+1)
		}
		if err := validateYUMCompatibilityCutoverEvent(event, events); err != nil {
			return nil, fmt.Errorf("YUM compatibility cutover event %d: %w", len(events)+1, err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(events) == 0 || body[len(body)-1] != '\n' {
		return nil, errors.New("YUM compatibility cutover ledger must be non-empty canonical JSONL")
	}
	return events, nil
}

func validateYUMCompatibilityCutoverEvent(event yumCompatibilityCutoverEvent, prior []yumCompatibilityCutoverEvent) error {
	if event.Schema != yumCompatibilityCutoverEventSchema || !validYUMCompatibilityEventID(event.ID) || event.Sequence != int64(len(prior)+1) ||
		(event.Action != "cutover" && event.Action != "rollback") || !validLowerSHA256(event.CandidateManifestSHA256) ||
		!validLowerSHA256(event.PreviousEventSHA256) || !validLowerSHA256(event.EventSHA256) ||
		!validNonZeroGitHash(event.FreezeCommit) {
		return errors.New("event schema, sequence, action, freeze, or digest is invalid")
	}
	for name, value := range map[string]string{"serving_link": event.ServingLink, "from_target": event.FromTarget, "to_target": event.ToTarget} {
		if !validYUMCompatibilityLogicalPath(value) {
			return fmt.Errorf("%s must be one clean repository-root-relative logical path", name)
		}
	}
	wantLink := path.Join(".sow", "serving", "compatibility", "yum", event.ID, "current")
	wantCandidate := path.Join(".sow", "materialized", "compatibility", event.ID, event.CandidateManifestSHA256)
	if event.ServingLink != wantLink {
		return fmt.Errorf("serving_link must be the controlled logical path %s", wantLink)
	}
	if event.ServingLink == event.FromTarget || event.ServingLink == event.ToTarget || event.FromTarget == event.ToTarget {
		return errors.New("serving link and targets must be distinct")
	}
	copy := event
	copy.EventSHA256 = ""
	body, err := json.Marshal(copy)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("sow-yum-compatibility-cutover-event-v1\x00"))
	_, _ = hasher.Write(body)
	if hex.EncodeToString(hasher.Sum(nil)) != event.EventSHA256 {
		return errors.New("event SHA-256 is not content-bound")
	}
	zero := strings.Repeat("0", 64)
	if len(prior) == 0 {
		if event.Action != "cutover" || event.PreviousEventSHA256 != zero || event.ToTarget != wantCandidate || strings.HasPrefix(event.FromTarget, ".sow/") {
			return errors.New("first event must be a cutover from the zero predecessor")
		}
		return nil
	}
	previous := prior[len(prior)-1]
	if event.PreviousEventSHA256 != previous.EventSHA256 || event.ID != previous.ID || event.ServingLink != previous.ServingLink ||
		event.FreezeCommit != previous.FreezeCommit || event.CandidateManifestSHA256 != previous.CandidateManifestSHA256 ||
		event.FromTarget != previous.ToTarget || event.ToTarget != previous.FromTarget {
		return errors.New("event does not extend the exact prior cutover state")
	}
	if event.Action == previous.Action {
		return errors.New("cutover and rollback events must alternate")
	}
	return nil
}

func validYUMCompatibilityEventID(value string) bool {
	return value != "" && value != "." && value != ".." && path.Base(value) == value && !strings.ContainsAny(value, "/\\\x00\t\r\n")
}

func validYUMCompatibilityLogicalPath(value string) bool {
	if value == "" || value == "." || strings.ContainsAny(value, "\\\x00\t\r\n") || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "../") || path.Clean(value) != value {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func yumCompatibilityLedgerStage(events []yumCompatibilityCutoverEvent) yumCompatibilityStage {
	if len(events) == 0 {
		return yumCompatibilityStageS2
	}
	if events[len(events)-1].Action == "cutover" {
		return yumCompatibilityStageS3
	}
	return yumCompatibilityStageRolledBack
}

func requireYUMCompatibilityLedgerPrefix(ancestor, descendant []yumCompatibilityCutoverEvent) error {
	if len(descendant) < len(ancestor) {
		return errors.New("YUM compatibility cutover ledger was truncated")
	}
	for index := range ancestor {
		if ancestor[index].EventSHA256 != descendant[index].EventSHA256 {
			return fmt.Errorf("YUM compatibility cutover event %d was rewritten", index+1)
		}
	}
	return nil
}

func buildYUMCompatibilityCutoverEventHash(event yumCompatibilityCutoverEvent) (string, error) {
	if event.EventSHA256 != "" {
		return "", errors.New("event hash must be empty while sealing")
	}
	body, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("sow-yum-compatibility-cutover-event-v1\x00"))
	_, _ = hasher.Write(body)
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
