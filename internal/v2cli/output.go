package v2cli

import (
	"encoding/json"
	"io"
)

const OutputSchema = "sow.cli/v1"

// Envelope is the stable top-level JSON shape for every V2 command. Result is
// intentionally retained on failures so committed work is never hidden.
type Envelope struct {
	Schema     string     `json:"schema"`
	Command    string     `json:"command"`
	OK         bool       `json:"ok"`
	Repository any        `json:"repository"`
	Operation  any        `json:"operation"`
	Result     any        `json:"result"`
	Errors     []CLIError `json:"errors"`
}

type CLIError struct {
	Code    int    `json:"code"`
	Class   string `json:"class"`
	Message string `json:"message"`
}

// NewEnvelope creates either a successful envelope or a failure envelope from
// the non-nil errors supplied by the caller.
func NewEnvelope(command string, repository, operation, result any, errs ...error) Envelope {
	details := make([]CLIError, 0, len(errs))
	for _, err := range errs {
		if err == nil {
			continue
		}
		details = append(details, ClassifyError(err))
	}
	return Envelope{
		Schema:     OutputSchema,
		Command:    command,
		OK:         len(details) == 0,
		Repository: repository,
		Operation:  operation,
		Result:     result,
		Errors:     details,
	}
}

// WriteJSON emits exactly one newline-terminated JSON document. It repairs a
// zero-value schema and nil error slice so all required top-level members have
// the stable wire representation promised by the API contract.
func WriteJSON(writer io.Writer, envelope Envelope) error {
	envelope.Schema = OutputSchema
	if envelope.Errors == nil {
		envelope.Errors = []CLIError{}
	}
	for index := range envelope.Errors {
		if envelope.Errors[index].Code == ExitOK || !validExitCode(envelope.Errors[index].Code) {
			envelope.Errors[index].Code = ExitRuntime
		}
		envelope.Errors[index].Class = errorClass(envelope.Errors[index].Code)
	}
	if len(envelope.Errors) != 0 {
		envelope.OK = false
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(envelope)
}

// ClassifyError converts an error to its stable machine-readable form.
func ClassifyError(err error) CLIError {
	if err == nil {
		return CLIError{}
	}
	code := ExitCode(err)
	return CLIError{Code: code, Class: errorClass(code), Message: err.Error()}
}
