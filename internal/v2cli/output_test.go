package v2cli

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestWriteJSONStableSuccessEnvelope(t *testing.T) {
	envelope := NewEnvelope("repo ls", nil, nil, map[string]any{"repositories": []string{}})
	var output bytes.Buffer
	if err := WriteJSON(&output, envelope); err != nil {
		t.Fatal(err)
	}
	want := "{\"schema\":\"sow.cli/v1\",\"command\":\"repo ls\",\"ok\":true,\"repository\":null,\"operation\":null,\"result\":{\"repositories\":[]},\"errors\":[]}\n"
	if got := output.String(); got != want {
		t.Fatalf("JSON envelope changed:\n got: %s want: %s", got, want)
	}
}

func TestFailureEnvelopeRetainsCommittedResult(t *testing.T) {
	result := map[string]any{"committed": []string{"one.rpm"}}
	envelope := NewEnvelope(
		"create",
		nil,
		int64(17),
		result,
		Errorf(ErrRejected, "coordinate conflict"),
		Errorf(ErrLock, "second lock"),
	)
	if envelope.OK {
		t.Fatal("failure envelope reported ok")
	}
	if !reflect.DeepEqual(envelope.Result, result) {
		t.Fatalf("committed result lost: %#v", envelope.Result)
	}
	want := []CLIError{
		{Code: ExitRejected, Class: "rejected", Message: "operation rejected: coordinate conflict"},
		{Code: ExitLock, Class: "lock", Message: "lock unavailable: second lock"},
	}
	if !reflect.DeepEqual(envelope.Errors, want) {
		t.Fatalf("errors=%#v want=%#v", envelope.Errors, want)
	}
}

func TestWriteJSONNormalizesRequiredWireFields(t *testing.T) {
	envelope := Envelope{Schema: "wrong", Command: "version", OK: true, Errors: nil}
	var output bytes.Buffer
	if err := WriteJSON(&output, envelope); err != nil {
		t.Fatal(err)
	}
	want := "{\"schema\":\"sow.cli/v1\",\"command\":\"version\",\"ok\":true,\"repository\":null,\"operation\":null,\"result\":null,\"errors\":[]}\n"
	if got := output.String(); got != want {
		t.Fatalf("normalized envelope=%q want=%q", got, want)
	}
}

func TestWriteJSONForcesFailureWhenErrorsExist(t *testing.T) {
	envelope := Envelope{
		Command: "init",
		OK:      true,
		Errors:  []CLIError{{Code: ExitUsage, Class: "usage", Message: "bad config"}},
	}
	var output bytes.Buffer
	if err := WriteJSON(&output, envelope); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte(`"ok":true`)) {
		t.Fatalf("error envelope remained successful: %s", output.Bytes())
	}
}

func TestWriteJSONRejectsUndocumentedErrorCode(t *testing.T) {
	envelope := Envelope{
		Command: "create",
		Errors:  []CLIError{{Code: 7, Class: "future", Message: "unsupported class"}},
	}
	var output bytes.Buffer
	if err := WriteJSON(&output, envelope); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"errors":[{"code":1,"class":"runtime","message":"unsupported class"}]`)) {
		t.Fatalf("undocumented error code escaped normalization: %s", output.Bytes())
	}
}

func TestWriteJSONPreservesDocumentedPartialSuccess(t *testing.T) {
	envelope := Envelope{
		Command: "create",
		Errors:  []CLIError{{Code: ExitPartial, Message: "one item failed"}},
	}
	var output bytes.Buffer
	if err := WriteJSON(&output, envelope); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"errors":[{"code":3,"class":"partial","message":"one item failed"}]`)) {
		t.Fatalf("partial success was not preserved: %s", output.Bytes())
	}
}

func TestClassifyError(t *testing.T) {
	want := CLIError{Code: ExitIntegrity, Class: "integrity", Message: "integrity or recovery error: journal mismatch"}
	if got := ClassifyError(Errorf(ErrIntegrity, "journal mismatch")); got != want {
		t.Fatalf("ClassifyError()=%#v want=%#v", got, want)
	}
	if got := ClassifyError(nil); got != (CLIError{}) {
		t.Fatalf("ClassifyError(nil)=%#v", got)
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWriteJSONReturnsWriterFailure(t *testing.T) {
	want := errors.New("closed output")
	if err := WriteJSON(failingWriter{err: want}, NewEnvelope("repo ls", nil, nil, nil)); !errors.Is(err, want) {
		t.Fatalf("WriteJSON error=%v want=%v", err, want)
	}
}
