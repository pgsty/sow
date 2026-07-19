package verify

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

var (
	// ErrClientNetwork classifies transport/auth failures. Callers map it to
	// the CLI's network/auth exit without exposing the underlying URL/header.
	ErrClientNetwork = errors.New("client probe network failure")
	// ErrClientCoverage means the selected repository has no installable object
	// from which complete L4 evidence can be produced.
	ErrClientCoverage = errors.New("client probe coverage failure")
	// ErrClientIntegrity means signed metadata or a referenced object was
	// malformed, missing, or disagreed with its authenticated digest.
	ErrClientIntegrity = errors.New("client probe repository integrity failure")
)

// ClientEvidence is the minimum durable evidence returned by a real apt/dnf
// harness. TranscriptSHA256 is the hash of a redacted transcript retained by
// the integration test; it prevents a bare boolean from masquerading as L4.
type ClientEvidence struct {
	Client            string
	Protocol          string
	Version           string
	TranscriptSHA256  string
	TranscriptSummary string
	MetadataObjects   int64
	InstalledObjects  int64
	PackageName       string
	PackageVersion    string
	PackageSHA256     string
}

// ClientProbe runs an evidence-producing client path. SOW production probes
// implement the apt and rpm-md wire contracts in pure Go; disposable real
// apt/dnf compatibility tests remain a separate proof surface.
type ClientProbe interface {
	Run(context.Context) (ClientEvidence, error)
}

// ClientCheck validates L4 evidence and refuses boolean-only success.
type ClientCheck struct {
	CheckID            string
	Probe              ClientProbe
	MarkNetworkFailure func()
}

func (c ClientCheck) ID() string   { return c.CheckID }
func (c ClientCheck) Layer() Layer { return LayerL4 }

func (c ClientCheck) Verify(ctx context.Context, recorder *Recorder) error {
	if c.Probe == nil {
		recorder.Add(Finding{Layer: LayerL4, Severity: SeverityCritical, Category: CategoryCoverage, Code: "CLIENT_PROBE_UNCONFIGURED", Subject: c.CheckID, Message: "L4 requires a real apt or dnf client harness"})
		return nil
	}
	evidence, err := c.Probe.Run(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		switch {
		case errors.Is(err, ErrClientNetwork):
			if c.MarkNetworkFailure != nil {
				c.MarkNetworkFailure()
			}
			recorder.Add(Finding{Layer: LayerL4, Severity: SeverityCritical, Category: CategoryOperational, Code: "CLIENT_NETWORK_FAILED", Subject: c.CheckID, Message: "package client probe could not complete its CDN request"})
		case errors.Is(err, ErrClientCoverage):
			recorder.Add(Finding{Layer: LayerL4, Severity: SeverityCritical, Category: CategoryCoverage, Code: "CLIENT_PACKAGE_COVERAGE_MISSING", Subject: c.CheckID, Message: "selected package repository exposes no installable object for L4 evidence"})
		default:
			recorder.Add(Finding{Layer: LayerL4, Severity: SeverityError, Category: CategoryIntegrity, Code: "CLIENT_REPOSITORY_REJECTED", Subject: c.CheckID, Message: "package protocol probe rejected signed metadata or a referenced object"})
		}
		return nil
	}
	client := strings.ToLower(strings.TrimSpace(evidence.Client))
	if client != "apt" && client != "dnf" || !safeEvidenceValue(evidence.Protocol, 128) || !safeEvidenceValue(evidence.Version, 256) ||
		!lowerSHA256(evidence.TranscriptSHA256) || !safeEvidenceValue(evidence.TranscriptSummary, 512) || evidence.MetadataObjects <= 0 || evidence.InstalledObjects <= 0 ||
		!safeEvidenceValue(evidence.PackageName, 256) || !safeEvidenceValue(evidence.PackageVersion, 512) || !lowerSHA256(evidence.PackageSHA256) {
		recorder.Add(Finding{Layer: LayerL4, Severity: SeverityCritical, Category: CategoryCoverage, Code: "CLIENT_EVIDENCE_INCOMPLETE", Subject: c.CheckID, Message: "L4 probe did not return versioned, transcript-backed metadata and install evidence"})
		return nil
	}
	recorder.Add(Finding{Layer: LayerL4, Severity: SeverityInfo, Category: CategoryEvidence, Code: "CLIENT_EVIDENCE_ACCEPTED", Subject: c.CheckID, Message: "package protocol probe authenticated metadata and parsed an installable package object", Fields: []Field{
		{Key: "client", Value: client}, {Key: "installed_objects", Value: strconv.FormatInt(evidence.InstalledObjects, 10)},
		{Key: "metadata_objects", Value: strconv.FormatInt(evidence.MetadataObjects, 10)}, {Key: "package", Value: evidence.PackageName},
		{Key: "package_sha256", Value: evidence.PackageSHA256}, {Key: "package_version", Value: evidence.PackageVersion},
		{Key: "protocol", Value: evidence.Protocol}, {Key: "transcript_sha256", Value: evidence.TranscriptSHA256},
		{Key: "transcript_summary", Value: evidence.TranscriptSummary}, {Key: "version", Value: evidence.Version},
	}})
	return nil
}

func safeEvidenceValue(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
