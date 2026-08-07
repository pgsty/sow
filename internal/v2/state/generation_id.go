package state

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

const generationIDWidth = 20

// GenerationID is the complete unsigned 64-bit repository generation domain.
// Its durable and cross-file spelling is always exactly twenty zero-padded
// decimal digits.  Keeping the SQLite value in that spelling also preserves
// numeric order under ordinary bytewise TEXT comparison.
type GenerationID uint64

const (
	ZeroGeneration GenerationID = 0
	MaxGeneration  GenerationID = ^GenerationID(0)
)

func ParseGenerationID(value string) (GenerationID, error) {
	if len(value) != generationIDWidth {
		return 0, fmt.Errorf("generation ID must be exactly %d decimal digits", generationIDWidth)
	}
	for _, digit := range []byte(value) {
		if digit < '0' || digit > '9' {
			return 0, errors.New("generation ID contains a non-decimal byte")
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("generation ID is outside uint64: %w", err)
	}
	return GenerationID(parsed), nil
}

func (generation GenerationID) String() string {
	return fmt.Sprintf("%020d", uint64(generation))
}

func (generation GenerationID) Next() (GenerationID, error) {
	if generation == MaxGeneration {
		return 0, errors.New("repository generation exhausted uint64")
	}
	return generation + 1, nil
}

func (generation GenerationID) MarshalJSON() ([]byte, error) {
	return json.Marshal(generation.String())
}

func (generation *GenerationID) UnmarshalJSON(data []byte) error {
	if generation == nil {
		return errors.New("nil GenerationID receiver")
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("generation ID must be a JSON string")
	}
	parsed, err := ParseGenerationID(value)
	if err != nil {
		return err
	}
	*generation = parsed
	return nil
}

func (generation GenerationID) MarshalText() ([]byte, error) {
	return []byte(generation.String()), nil
}

func (generation *GenerationID) UnmarshalText(data []byte) error {
	if generation == nil {
		return errors.New("nil GenerationID receiver")
	}
	parsed, err := ParseGenerationID(string(data))
	if err != nil {
		return err
	}
	*generation = parsed
	return nil
}

// Value stores the canonical fixed-width spelling rather than SQLite INTEGER,
// whose signed domain would truncate the upper half of GenerationID.
func (generation GenerationID) Value() (driver.Value, error) {
	return generation.String(), nil
}

// Scan accepts the canonical v7+ TEXT domain and the non-negative SQLite
// INTEGER domain of the frozen v0.2 (schema v6) read-only compatibility
// surface. All current writes still use Value's fixed-width TEXT spelling.
func (generation *GenerationID) Scan(source any) error {
	if generation == nil {
		return errors.New("nil GenerationID receiver")
	}
	var value string
	switch typed := source.(type) {
	case string:
		value = typed
	case []byte:
		value = string(typed)
	case int64:
		if typed < 0 {
			return errors.New("generation ID has negative legacy INTEGER value")
		}
		*generation = GenerationID(typed)
		return nil
	default:
		return fmt.Errorf("generation ID has non-TEXT SQLite type %T", source)
	}
	parsed, err := ParseGenerationID(value)
	if err != nil {
		return err
	}
	*generation = parsed
	return nil
}
