package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

// HTTPObject is one immutable byte expectation fetched through the configured
// CDN URL. Label, never URL, is emitted in findings so bearer tokens in paths
// cannot leak through reports.
type HTTPObject struct {
	Label                   string
	URL                     string
	Headers                 http.Header
	ExpectedResponseHeaders map[string]string
	Status                  int
	Size                    int64
	SHA256                  string
	AllowHTTP               bool
}

// HTTPCheck is a real L3 origin/CDN probe. It streams response bytes, restricts
// redirects to the same origin, and never includes request URLs or header
// values in findings.
type HTTPCheck struct {
	CheckID            string
	Client             *http.Client
	Objects            []HTTPObject
	MarkNetworkFailure func()
}

// HTTPAbsentObject is one plan-bound CDN route that must no longer exist.
// 404 and 410 are the only successful outcomes; redirects and a stale 2xx are
// drift, while authentication/service failures remain operational errors.
type HTTPAbsentObject struct {
	Label     string
	URL       string
	Headers   http.Header
	AllowHTTP bool
}

type HTTPAbsenceCheck struct {
	CheckID            string
	Client             *http.Client
	Objects            []HTTPAbsentObject
	MarkNetworkFailure func()
}

func (c HTTPAbsenceCheck) ID() string   { return c.CheckID }
func (c HTTPAbsenceCheck) Layer() Layer { return LayerL3 }

func (c HTTPAbsenceCheck) Verify(ctx context.Context, recorder *Recorder) error {
	if len(c.Objects) == 0 {
		recorder.Add(Finding{Layer: LayerL3, Severity: SeverityCritical, Category: CategoryCoverage, Code: "CDN_ABSENCE_PROBE_UNCONFIGURED", Subject: c.CheckID, Message: "L3 absence check has no expected routes"})
		return nil
	}
	base := c.Client
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	if client.Timeout == 0 {
		client.Timeout = 2 * time.Minute
	}
	// A redirect is not proof that the deleted route itself is absent. Preserve
	// the first 3xx response so it is classified as drift below; following even
	// a same-origin redirect to a 404 would create a false negative.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, object := range c.Objects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validateHTTPAbsentObject(object); err != nil {
			recorder.Add(Finding{Layer: LayerL3, Severity: SeverityCritical, Category: CategoryCoverage, Code: "CDN_ABSENCE_EXPECTATION_INVALID", Subject: object.Label, Message: "L3 absence expectation is malformed"})
			continue
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, object.URL, nil)
		if err != nil {
			recorder.Add(Finding{Layer: LayerL3, Severity: SeverityCritical, Category: CategoryCoverage, Code: "CDN_ABSENCE_REQUEST_INVALID", Subject: object.Label, Message: "L3 absence request could not be constructed"})
			continue
		}
		request.Header = object.Headers.Clone()
		if request.Header == nil {
			request.Header = make(http.Header)
		}
		request.Header.Set("Accept-Encoding", "identity")
		response, err := client.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if c.MarkNetworkFailure != nil {
				c.MarkNetworkFailure()
			}
			recorder.Add(Finding{Layer: LayerL3, Severity: SeverityCritical, Category: CategoryOperational, Code: "CDN_ABSENCE_REQUEST_FAILED", Subject: object.Label, Message: "CDN absence request failed before a response was verified"})
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		closeErr := response.Body.Close()
		if closeErr != nil {
			if c.MarkNetworkFailure != nil {
				c.MarkNetworkFailure()
			}
			recorder.Add(Finding{Layer: LayerL3, Severity: SeverityCritical, Category: CategoryOperational, Code: "CDN_ABSENCE_BODY_CLOSE_FAILED", Subject: object.Label, Message: "CDN absence response could not be closed"})
			continue
		}
		if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone {
			continue
		}
		if networkHTTPStatus(response.StatusCode) {
			if c.MarkNetworkFailure != nil {
				c.MarkNetworkFailure()
			}
			recorder.Add(Finding{Layer: LayerL3, Severity: SeverityCritical, Category: CategoryOperational, Code: "CDN_NETWORK_STATUS", Subject: object.Label, Message: "CDN authentication or service availability prevented absence verification", Fields: []Field{{Key: "actual", Value: fmt.Sprintf("%d", response.StatusCode)}}})
			continue
		}
		recorder.Add(Finding{Layer: LayerL3, Severity: SeverityError, Category: CategoryDrift, Code: "CDN_ABSENCE_DRIFT", Subject: object.Label, Message: "deleted CDN route still returns a non-terminal response", Fields: []Field{{Key: "actual", Value: fmt.Sprintf("%d", response.StatusCode)}}})
	}
	return nil
}

func (c HTTPCheck) ID() string   { return c.CheckID }
func (c HTTPCheck) Layer() Layer { return LayerL3 }

func (c HTTPCheck) Verify(ctx context.Context, recorder *Recorder) error {
	if len(c.Objects) == 0 {
		recorder.Add(Finding{Layer: LayerL3, Severity: SeverityCritical, Category: CategoryCoverage, Code: "CDN_PROBE_UNCONFIGURED", Subject: c.CheckID, Message: "L3 HTTP check has no expected objects"})
		return nil
	}
	base := c.Client
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	if client.Timeout == 0 {
		client.Timeout = 2 * time.Minute
	}
	// A redirect is not evidence for the plan-bound URL itself. In particular,
	// following a same-origin redirect would forward Basic credentials to a
	// different path and could make a public object masquerade as a successful
	// Pro-route verification. Preserve the first 3xx response without issuing a
	// second request, then classify it as integrity drift below.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, object := range c.Objects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validateHTTPObject(object); err != nil {
			recorder.Add(Finding{Layer: LayerL3, Severity: SeverityCritical, Category: CategoryCoverage, Code: "CDN_EXPECTATION_INVALID", Subject: object.Label, Message: "L3 object expectation is malformed"})
			continue
		}
		expectedHeaders, err := canonicalExpectedHeaders(object.ExpectedResponseHeaders)
		if err != nil {
			recorder.Add(Finding{Layer: LayerL3, Severity: SeverityCritical, Category: CategoryCoverage, Code: "CDN_EXPECTATION_INVALID", Subject: object.Label, Message: "L3 response-header expectation is malformed"})
			continue
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, object.URL, nil)
		if err != nil {
			recorder.Add(Finding{Layer: LayerL3, Severity: SeverityCritical, Category: CategoryCoverage, Code: "CDN_REQUEST_INVALID", Subject: object.Label, Message: "L3 request could not be constructed"})
			continue
		}
		request.Header = object.Headers.Clone()
		if request.Header == nil {
			request.Header = make(http.Header)
		}
		request.Header.Set("Accept-Encoding", "identity")
		response, err := client.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			c.markNetworkFailure()
			recorder.Add(Finding{Layer: LayerL3, Severity: SeverityCritical, Category: CategoryOperational, Code: "CDN_REQUEST_FAILED", Subject: object.Label, Message: "CDN object request failed before a response was verified"})
			continue
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			_ = response.Body.Close()
			recorder.Add(Finding{Layer: LayerL3, Severity: SeverityError, Category: CategoryIntegrity, Code: "CDN_REDIRECT_POLICY", Subject: object.Label, Message: "CDN verification URL returned a redirect"})
			continue
		}
		wantedStatus := object.Status
		if wantedStatus == 0 {
			wantedStatus = http.StatusOK
		}
		if response.StatusCode != wantedStatus {
			_ = response.Body.Close()
			if networkHTTPStatus(response.StatusCode) {
				c.markNetworkFailure()
				recorder.Add(Finding{Layer: LayerL3, Severity: SeverityCritical, Category: CategoryOperational, Code: "CDN_NETWORK_STATUS", Subject: object.Label, Message: "CDN authentication or service availability prevented object verification", Fields: []Field{{Key: "actual", Value: fmt.Sprintf("%d", response.StatusCode)}, {Key: "expected", Value: fmt.Sprintf("%d", wantedStatus)}}})
				continue
			}
			recorder.Add(Finding{Layer: LayerL3, Severity: SeverityError, Category: CategoryDrift, Code: "CDN_STATUS_DRIFT", Subject: object.Label, Message: "CDN returned an unexpected status", Fields: []Field{{Key: "actual", Value: fmt.Sprintf("%d", response.StatusCode)}, {Key: "expected", Value: fmt.Sprintf("%d", wantedStatus)}}})
			continue
		}
		headerNames := make([]string, 0, len(expectedHeaders))
		for name := range expectedHeaders {
			headerNames = append(headerNames, name)
		}
		sort.Strings(headerNames)
		for _, name := range headerNames {
			if response.Header.Get(name) != expectedHeaders[name] {
				recorder.Add(Finding{Layer: LayerL3, Severity: SeverityError, Category: CategoryDrift, Code: "CDN_HEADER_DRIFT", Subject: object.Label + "#" + name, Message: "CDN response header differs from the expected publication contract", Fields: []Field{{Key: "header", Value: name}}})
			}
		}
		hasher := sha256.New()
		limited := io.LimitReader(response.Body, object.Size+1)
		written, copyErr := io.CopyBuffer(hasher, limited, make([]byte, 256*1024))
		closeErr := response.Body.Close()
		if copyErr != nil || closeErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			c.markNetworkFailure()
			recorder.Add(Finding{Layer: LayerL3, Severity: SeverityCritical, Category: CategoryOperational, Code: "CDN_BODY_READ_FAILED", Subject: object.Label, Message: "CDN response body could not be read completely"})
			continue
		}
		actualHash := hex.EncodeToString(hasher.Sum(nil))
		if written != object.Size || actualHash != object.SHA256 {
			recorder.Add(Finding{Layer: LayerL3, Severity: SeverityError, Category: CategoryDrift, Code: "CDN_BYTES_DRIFT", Subject: object.Label, Message: "CDN response bytes differ from the expected immutable object", Fields: []Field{{Key: "actual_sha256", Value: actualHash}, {Key: "actual_size", Value: fmt.Sprintf("%d", written)}, {Key: "expected_sha256", Value: object.SHA256}, {Key: "expected_size", Value: fmt.Sprintf("%d", object.Size)}}})
		}
	}
	return nil
}

func (c HTTPCheck) markNetworkFailure() {
	if c.MarkNetworkFailure != nil {
		c.MarkNetworkFailure()
	}
}

func networkHTTPStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusProxyAuthRequired || status == http.StatusTooManyRequests || status >= 500
}

func canonicalExpectedHeaders(input map[string]string) (map[string]string, error) {
	result := make(map[string]string, len(input))
	for name, value := range input {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical == "" || strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("invalid response header expectation")
		}
		if previous, exists := result[canonical]; exists && previous != value {
			return nil, errors.New("conflicting response header expectation")
		}
		result[canonical] = value
	}
	return result, nil
}

func validateHTTPObject(object HTTPObject) error {
	if strings.TrimSpace(object.Label) == "" || object.Size < 0 || object.Size == math.MaxInt64 || !lowerSHA256(object.SHA256) {
		return errors.New("invalid label, size, or SHA256")
	}
	parsed, err := url.Parse(object.URL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.RawPath != "" ||
		path.Clean(parsed.Path) != parsed.Path || parsed.Scheme != "https" && !(object.AllowHTTP && parsed.Scheme == "http") {
		return errors.New("invalid probe URL")
	}
	return nil
}

func validateHTTPAbsentObject(object HTTPAbsentObject) error {
	if strings.TrimSpace(object.Label) == "" {
		return errors.New("invalid absence label")
	}
	parsed, err := url.Parse(object.URL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.RawPath != "" ||
		path.Clean(parsed.Path) != parsed.Path || parsed.Scheme != "https" && !(object.AllowHTTP && parsed.Scheme == "http") {
		return errors.New("invalid absence probe URL")
	}
	return nil
}
