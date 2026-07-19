package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/pgsty/sow/internal/verify"
)

// projectionIntentAudit is captured before ordinary canonical admission. A
// projection bridge deliberately survives the canonical commit until the
// directly hostable tree and its receipts are complete, so an incomplete Git
// transaction must not hide the more useful recovery finding behind the
// generic transaction gate.
type projectionIntentAudit struct {
	findings []verify.Finding
}

func inspectProjectionIntentsForAudit(stateRoot string) projectionIntentAudit {
	var result projectionIntentAudit
	assetIntent, assetPending, assetErr := readAssetProjectionIntent(stateRoot)
	if assetErr != nil {
		result.findings = append(result.findings, verify.Finding{
			Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
			Code: "ASSET_PROJECTION_INTENT_INVALID", Subject: "state/asset-projection-intent",
			Message: "asset projection recovery intent is unreadable, unsafe, or internally inconsistent",
		})
	} else if assetPending {
		result.findings = append(result.findings, verify.Finding{
			Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
			Code: "ASSET_PROJECTION_RECOVERY_REQUIRED", Subject: assetIntent.Repo + "/" + assetIntent.View,
			Message: "an asset canonical mutation or directly hostable projection is incomplete; run the matching command with --recover",
			Fields: []verify.Field{
				{Key: "expected_head", Value: assetIntent.ExpectedHead},
				{Key: "expected_ref", Value: assetIntent.ExpectedRef},
				{Key: "intent_id", Value: assetIntent.ID},
				{Key: "manifest_sha256", Value: assetIntent.ManifestSHA256},
				{Key: "manifest_size", Value: fmt.Sprint(assetIntent.ManifestSize)},
				{Key: "operation", Value: assetIntent.Operation},
				{Key: "scope", Value: assetIntent.OperationScope},
				{Key: "transaction_id", Value: assetIntent.TransactionID},
				{Key: "view_ref", Value: assetIntent.ViewRef},
			},
		})
	}

	packageIntent, packagePending, packageErr := readPackageProjectionIntent(stateRoot)
	if packageErr != nil {
		result.findings = append(result.findings, verify.Finding{
			Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
			Code: "PACKAGE_PROJECTION_INTENT_INVALID", Subject: "state/package-projection-intent",
			Message: "package projection recovery intent is unreadable, unsafe, or internally inconsistent",
		})
	} else if packagePending {
		result.findings = append(result.findings, verify.Finding{
			Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
			Code: "PACKAGE_PROJECTION_RECOVERY_REQUIRED", Subject: packageIntent.Family + "/" + packageIntent.Operation,
			Message: "a package canonical mutation or directly hostable repository projection is incomplete; run the matching command with --recover",
			Fields: []verify.Field{
				{Key: "expected_head", Value: packageIntent.ExpectedHead},
				{Key: "family", Value: packageIntent.Family},
				{Key: "intent_id", Value: packageIntent.ID},
				{Key: "operation", Value: packageIntent.Operation},
				{Key: "transaction_id", Value: packageIntent.TransactionID},
				{Key: "units", Value: fmt.Sprint(len(packageIntent.Units))},
			},
		})
	}

	archiveIntent, archivePending, archiveErr := readOfflineArchiveProjectionIntent(stateRoot)
	if archiveErr != nil {
		result.findings = append(result.findings, verify.Finding{
			Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
			Code: "OFFLINE_ARCHIVE_PROJECTION_INTENT_INVALID", Subject: "state/offline-archive-projection-intent",
			Message: "offline archive projection recovery intent is unreadable, unsafe, or internally inconsistent",
		})
	} else if archivePending {
		result.findings = append(result.findings, verify.Finding{
			Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
			Code: "OFFLINE_ARCHIVE_PROJECTION_RECOVERY_REQUIRED", Subject: archiveIntent.Destination,
			Message: "an offline archive visibility transaction is incomplete; run materialize with --recover",
			Fields: []verify.Field{
				{Key: "archive_sha256", Value: archiveIntent.ArchiveSHA256},
				{Key: "archive_size", Value: fmt.Sprint(archiveIntent.ArchiveSize)},
				{Key: "intent_id", Value: archiveIntent.ID},
				{Key: "transaction_id", Value: archiveIntent.TransactionID},
			},
		})
	}
	return result
}

func (audit projectionIntentAudit) pending() bool { return len(audit.findings) != 0 }

func (audit projectionIntentAudit) verifyCheck() verify.Check {
	findings := append([]verify.Finding(nil), audit.findings...)
	return verify.CheckFunc{
		CheckID: "state/projection-intent", CheckLayer: verify.LayerL1,
		Run: func(_ context.Context, recorder *verify.Recorder) error {
			for _, finding := range findings {
				recorder.Add(finding)
			}
			return nil
		},
	}
}

func (audit projectionIntentAudit) writeFSCKDrift(output io.Writer) {
	for _, finding := range audit.findings {
		fmt.Fprintf(output, "drift code=%s subject=%q recovery_required=true\n", finding.Code, finding.Subject)
	}
}
