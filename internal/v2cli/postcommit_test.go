package v2cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/pgsty/sow/internal/v2/managed"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestCommittedMaintenanceFailurePreservesEnvelopeResult(t *testing.T) {
	result := managed.BuildResult{Operation: "123", Repository: "repo", Generation: 9, Revision: 3, Noop: true, Dists: []string{"el9"}}
	err := &state.CommittedMaintenanceError{Err: syscall.EIO}
	var stdout, stderr bytes.Buffer
	code := writeFailure("build", true, err, "repo", result.Operation, result, &stdout, &stderr)
	if code != ExitRuntime || !errors.Is(err, syscall.EIO) || !strings.Contains(stderr.String(), "transaction committed") {
		t.Fatalf("code=%d stderr=%s", code, &stderr)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(envelope))
	for key := range envelope {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, []string{"command", "errors", "ok", "operation", "repository", "result", "schema"}) {
		t.Fatalf("keys=%v", keys)
	}
	var got managed.BuildResult
	if err := json.Unmarshal(envelope["result"], &got); err != nil || !reflect.DeepEqual(got, result) || string(envelope["ok"]) != "false" {
		t.Fatalf("result=%+v envelope=%s err=%v", got, &stdout, err)
	}
}
