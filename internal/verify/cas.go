package verify

import (
	"context"
	"errors"
	"fmt"

	"github.com/pgsty/sow/internal/repository"
)

// NamedManifest identifies one canonical preservation root for CAS auditing.
type NamedManifest struct {
	Name string
	Open Stream
}

// CASCheck delegates byte/coordinate verification to the production CAS
// engine, then emits the complete missing/orphan partition as structured L1
// findings. It is read-only.
type CASCheck struct {
	CheckID string
	Store   *repository.Store
	Roots   []NamedManifest
}

func (c CASCheck) ID() string   { return c.CheckID }
func (c CASCheck) Layer() Layer { return LayerL1 }

func (c CASCheck) Verify(ctx context.Context, recorder *Recorder) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.Store == nil {
		return errors.New("CAS check requires a repository store")
	}
	if len(c.Roots) == 0 {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryCoverage, Code: "CAS_ROOTS_UNCONFIGURED", Subject: c.CheckID, Message: "CAS audit has no canonical preservation roots"})
		return nil
	}
	set := &repository.ReferenceSet{}
	invalidRoots := false
	for _, root := range c.Roots {
		if err := ctx.Err(); err != nil {
			return err
		}
		if root.Open == nil {
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryCoverage, Code: "CAS_ROOT_UNAVAILABLE", Subject: root.Name, Message: "canonical CAS root has no evidence stream"})
			invalidRoots = true
			continue
		}
		stream, err := root.Open()
		if err != nil {
			return fmt.Errorf("open CAS root %q: %w", root.Name, err)
		}
		addErr := set.AddManifest(stream)
		closeErr := stream.Close()
		if addErr != nil {
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "CAS_ROOT_INVALID", Subject: root.Name, Message: "canonical CAS root manifest is malformed"})
			invalidRoots = true
			continue
		}
		if closeErr != nil {
			return fmt.Errorf("close CAS root %q", root.Name)
		}
	}
	if invalidRoots {
		return nil
	}
	report, err := c.Store.Audit(ctx, set)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "CAS_AUDIT_FAILED", Subject: c.CheckID, Message: "CAS contains an unsafe coordinate or corrupt object"})
		return nil
	}
	for _, object := range report.Missing {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "CAS_OBJECT_MISSING", Subject: object.HashString(), Message: "canonical state references an object absent from CAS", Fields: []Field{{Key: "size", Value: fmt.Sprintf("%d", object.Size)}}})
	}
	for _, object := range report.Orphans {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityWarning, Category: CategoryDrift, Code: "CAS_OBJECT_ORPHAN", Subject: object.HashString(), Message: "CAS object is not reachable from any supplied preservation root", Fields: []Field{{Key: "orphan_set_sha256", Value: report.OrphanSetSHA256}, {Key: "size", Value: fmt.Sprintf("%d", object.Size)}}})
	}
	return nil
}
