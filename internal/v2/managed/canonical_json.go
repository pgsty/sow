package managed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// rejectDuplicateJSONMembers recursively rejects duplicate names before a Go
// struct decode can overwrite them.  RFC 8785 identity would otherwise be
// ambiguous even when DisallowUnknownFields is enabled.
func rejectDuplicateJSONMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, container := token.(json.Delim)
		if !container {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := nameToken.(string)
				if !ok {
					return errors.New("JSON object member name is not a string")
				}
				if _, duplicate := seen[name]; duplicate {
					return fmt.Errorf("duplicate JSON member %q", name)
				}
				seen[name] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closeToken, err := decoder.Token()
			if err != nil || closeToken != json.Delim('}') {
				return errors.Join(errors.New("malformed JSON object"), err)
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closeToken, err := decoder.Token()
			if err != nil || closeToken != json.Delim(']') {
				return errors.Join(errors.New("malformed JSON array"), err)
			}
		default:
			return errors.New("unexpected closing JSON delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("JSON document has trailing content")
		}
		return err
	}
	return nil
}

func canonicalJSONString(value string) string {
	// Disable encoding/json's HTML substitutions: RFC 8785 uses ordinary JSON
	// string escaping and all accepted control-wire values are valid UTF-8.
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		panic(err) // encoding a Go string cannot fail
	}
	return strings.TrimSuffix(output.String(), "\n")
}
