package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pgsty/sow/internal/repository"
)

const builderHandoffReceiptDomain = "sow-builder-handoff-v1\x00"

// orderedValueFlag retains order and duplicates. Builder expectations bind
// one-for-one to positional inputs, so selector-style de-duplication would
// silently attach a digest to the wrong artifact.
type orderedValueFlag struct {
	items []string
}

func (f *orderedValueFlag) String() string { return strings.Join(f.items, ",") }

func (f *orderedValueFlag) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return errors.New("expected object values cannot be empty")
		}
		f.items = append(f.items, item)
	}
	return nil
}

func (f *orderedValueFlag) values() []string { return append([]string(nil), f.items...) }

// parseBuilderHandoffObjects turns ordered sha256:<digest>:<size> assertions
// into the same immutable object identities used by sync. The receipt binds
// the ordered basenames and identities without exposing builder directories.
func parseBuilderHandoffObjects(inputs, specifications []string) (map[string]repository.Object, string, error) {
	if len(specifications) == 0 {
		return nil, "", nil
	}
	if len(inputs) != len(specifications) {
		return nil, "", fmt.Errorf("--expected-object must be repeated exactly once for each of the %d input files", len(inputs))
	}
	expected := make(map[string]repository.Object, len(inputs))
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(builderHandoffReceiptDomain))
	for index, input := range inputs {
		if _, duplicate := expected[input]; duplicate {
			return nil, "", fmt.Errorf("builder handoff input %q is duplicated", input)
		}
		parts := strings.Split(specifications[index], ":")
		if len(parts) != 3 || parts[0] != "sha256" {
			return nil, "", fmt.Errorf("--expected-object %d must use sha256:<lowercase-64-hex>:<size>", index+1)
		}
		digest, err := repository.ParseDigest(parts[1])
		if err != nil {
			return nil, "", fmt.Errorf("--expected-object %d: %w", index+1, err)
		}
		size, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil || size < 0 || strconv.FormatInt(size, 10) != parts[2] {
			return nil, "", fmt.Errorf("--expected-object %d size must be a canonical non-negative decimal integer", index+1)
		}
		object := repository.Object{SHA256: digest, Size: size}
		expected[input] = object
		_, _ = fmt.Fprintf(hasher, "%d\x00%s\x00%s\x00%d\n", index, filepath.Base(input), object.HashString(), object.Size)
	}
	return expected, hex.EncodeToString(hasher.Sum(nil)), nil
}

func verifyExpectedBuilderInput(input, digest string, size int64, expected map[string]repository.Object) error {
	if expected == nil {
		return nil
	}
	object, exists := expected[input]
	if !exists {
		return fmt.Errorf("builder handoff input %s has no expected object identity", filepath.Base(input))
	}
	if object.HashString() != digest || object.Size != size {
		return fmt.Errorf("builder handoff input %s is %s/%d, expected %s/%d",
			filepath.Base(input), digest, size, object.HashString(), object.Size)
	}
	return nil
}

func verifyExpectedPackageInput(values commonFlags, input, digest string, size int64, expected map[string]repository.Object) error {
	if values.syncInternal {
		return verifyExpectedSyncInput(input, digest, size, expected)
	}
	return verifyExpectedBuilderInput(input, digest, size, expected)
}

func emitBuilderHandoffReceipt(stdout io.Writer, receipt string, inputs int) {
	if receipt == "" {
		return
	}
	_, _ = fmt.Fprintf(stdout, "builder handoff verified inputs=%d receipt_sha256=%s\n", inputs, receipt)
}
