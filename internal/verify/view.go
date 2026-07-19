package verify

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/pgsty/sow/internal/views"
)

// ViewCheck validates one canonical leaf. Public is a security property, not
// a mode flag: when true every gated reference is an unconditional critical
// finding and there is no force/skip path.
type ViewCheck struct {
	CheckID string
	Open    Stream
	Repo    string
	OS      string
	Arch    string
	Public  bool
	// ValidateEntry carries product-specific canonical invariants without
	// weakening the generic leaf/confidentiality checks above it.
	ValidateEntry func(views.Entry) error
}

func (c ViewCheck) ID() string   { return c.CheckID }
func (c ViewCheck) Layer() Layer { return LayerL1 }

func (c ViewCheck) Verify(ctx context.Context, recorder *Recorder) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.Open == nil {
		return errors.New("view check requires a canonical leaf stream")
	}
	stream, err := c.Open()
	if err != nil {
		return fmt.Errorf("open view evidence: %w", err)
	}
	reader := views.NewReader(stream)
	for {
		if err := ctx.Err(); err != nil {
			_ = stream.Close()
			return err
		}
		entry, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "VIEW_MANIFEST_INVALID", Subject: c.CheckID, Message: "view leaf is malformed, unsorted, or contains an unsafe entry"})
			break
		}
		if entry.Repo != c.Repo || entry.OS != c.OS || entry.Arch != c.Arch {
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityError, Category: CategoryIntegrity, Code: "VIEW_LEAF_MEMBERSHIP", Subject: entry.Path, Message: "view entry belongs to a different repo, OS, or architecture", Fields: []Field{{Key: "actual", Value: entry.Repo + "/" + entry.OS + "/" + entry.Arch}, {Key: "expected", Value: c.Repo + "/" + c.OS + "/" + c.Arch}}})
		}
		if c.Public && entry.Pool != "public" {
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryConfidentiality, Code: "CONFIDENTIALITY_GATED_REFERENCE", Subject: entry.Path, Message: "public view references a gated object", Fields: []Field{{Key: "pool", Value: entry.Pool}, {Key: "sha256", Value: entry.SHA256}}})
		}
		if c.Public && entry.DebugInfo {
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityError, Category: CategoryIntegrity, Code: "PUBLIC_DEBUGINFO_REFERENCE", Subject: entry.Path, Message: "public OSS view references a debuginfo package"})
		}
		if c.ValidateEntry != nil {
			if err := c.ValidateEntry(entry); err != nil {
				recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "VIEW_ASSET_PROJECTION_INVALID", Subject: entry.Path, Message: err.Error()})
			}
		}
	}
	if err := stream.Close(); err != nil {
		return errors.New("close view evidence")
	}
	return nil
}
