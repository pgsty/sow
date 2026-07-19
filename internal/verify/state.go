package verify

import (
	"context"
	"errors"
)

// CacheCheck proves that a disposable cache projection is derived from the
// canonical manifest and uses the expected schema. Projection must emit the
// same sorted path/size/SHA256 TSV as Canonical.
type CacheCheck struct {
	CheckID               string
	Canonical             Stream
	Projection            Stream
	ExpectedSchema        int
	ActualSchema          int
	ExpectedCanonicalHead string
	ActualCanonicalHead   string
}

func (c CacheCheck) ID() string   { return c.CheckID }
func (c CacheCheck) Layer() Layer { return LayerL1 }

func (c CacheCheck) Verify(ctx context.Context, recorder *Recorder) error {
	if c.Canonical == nil || c.Projection == nil {
		return errors.New("cache check requires canonical and projection streams")
	}
	if c.ExpectedSchema <= 0 || c.ActualSchema != c.ExpectedSchema {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityError, Category: CategoryDrift, Code: "CACHE_SCHEMA_DRIFT", Subject: c.CheckID, Message: "SQLite cache schema differs from the rebuild contract"})
	}
	if c.ExpectedCanonicalHead != "" && c.ActualCanonicalHead != c.ExpectedCanonicalHead {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityError, Category: CategoryDrift, Code: "CACHE_HEAD_DRIFT", Subject: c.CheckID, Message: "SQLite cache was rebuilt from a different canonical Git HEAD"})
	}
	comparison := ManifestComparisonCheck{CheckID: c.CheckID + "/rows", AtLayer: LayerL1, Subject: c.CheckID, Desired: c.Canonical, Actual: c.Projection, CodePrefix: "CACHE"}
	return comparison.Verify(ctx, recorder)
}
