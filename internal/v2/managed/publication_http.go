package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/pgsty/sow/internal/r2"
	"github.com/pgsty/sow/internal/v2/state"
)

const (
	publicResponseTimeout = 2 * time.Minute
	publicTransientWindow = 30 * time.Second
)

type publicVerificationDisposition uint8

const (
	publicVerificationFatal publicVerificationDisposition = iota
	publicVerificationTransient
	publicVerificationStale
)

// httpPublicationVerifier is provider-neutral public-delivery evidence. It
// deliberately has no whole-request timeout: response headers and body idle
// progress are bounded independently so large, steadily streaming objects can
// complete. Ordinary canonical GETs alone are authoritative; no-cache probes
// only accelerate cache revalidation between ordinary observations.
type httpPublicationVerifier struct {
	client               *http.Client
	base                 *url.URL
	maxCacheTTL          time.Duration
	transientRetryWindow time.Duration
	readIdleTimeout      time.Duration
	sleep                func(context.Context, time.Duration) error
	now                  func() time.Time
}

// Redirect connections use a separate pool so even a reused connection has
// passed the address check. Explicitly configured local delivery stays usable.
type publicTransport struct {
	origin, redirect *http.Transport
	base             *url.URL
}

func (t publicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Response == nil || isLoopbackOrLinkLocalHost(t.base.Hostname()) {
		return t.origin.RoundTrip(req)
	}
	if t.origin.Proxy != nil {
		proxy, err := t.origin.Proxy(req)
		if err != nil {
			return nil, err
		}
		if proxy != nil {
			// The configured proxy is trusted for the explicitly configured origin.
			if req.URL.Scheme == t.base.Scheme && strings.EqualFold(req.URL.Host, t.base.Host) {
				return t.origin.RoundTrip(req)
			}
			return nil, errors.New("cannot verify a cross-origin redirect destination through a proxy")
		}
	}
	return t.redirect.RoundTrip(req)
}

func (t publicTransport) CloseIdleConnections() {
	t.origin.CloseIdleConnections()
	t.redirect.CloseIdleConnections()
}

func checkPublicDialAddress(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if isLoopbackOrLinkLocalHost(host) {
		return errors.New("refused redirect connection to a loopback, unspecified or link-local address")
	}
	return nil
}

func newPublicVerificationClient(base *url.URL) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = publicResponseTimeout
	transport.MaxIdleConns = max(transport.MaxIdleConns, 100)
	transport.MaxIdleConnsPerHost = max(transport.MaxIdleConnsPerHost, 32)
	redirect := transport.Clone()
	redirect.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: checkPublicDialAddress}).DialContext
	redirect.Proxy = nil
	return &http.Client{
		Transport: publicTransport{origin: transport, redirect: redirect, base: base},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
				return fmt.Errorf("disallowed redirect scheme %q", req.URL.Scheme)
			}
			origin := via[0].URL
			if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return errors.New("refused https-to-http redirect downgrade")
			}
			if !isLoopbackOrLinkLocalHost(origin.Hostname()) && isLoopbackOrLinkLocalHost(req.URL.Hostname()) {
				return errors.New("refused redirect to loopback or link-local address")
			}
			return nil
		},
	}
}

func isLoopbackOrLinkLocalHost(host string) bool {
	lower := strings.ToLower(strings.TrimSpace(host))
	if strings.TrimSuffix(lower, ".") == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(lower)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func (v httpPublicationVerifier) Verify(ctx context.Context, expected state.GenerationFile) error {
	return v.verify(ctx, func(revalidate bool) (publicVerificationDisposition, error) {
		return verifyHTTPPublicationObjectOnce(ctx, v.httpClient(), v.base, expected, revalidate, v.idleTimeout())
	})
}

func (v httpPublicationVerifier) VerifyAbsent(ctx context.Context, objectPath string) error {
	if !validPublicationObjectPath(objectPath) {
		return fmt.Errorf("%w: invalid public absence path", ErrRejected)
	}
	return v.verify(ctx, func(revalidate bool) (publicVerificationDisposition, error) {
		return verifyHTTPPublicationAbsenceOnce(ctx, v.httpClient(), v.base, objectPath, revalidate)
	})
}

func (v httpPublicationVerifier) verify(ctx context.Context, once func(bool) (publicVerificationDisposition, error)) error {
	if ctx == nil || v.base == nil || v.maxCacheTTL < 0 || v.transientRetryWindow < 0 {
		return fmt.Errorf("%w: invalid public verification input", ErrRejected)
	}
	now := v.nowTime()
	cacheDeadline := now.Add(v.maxCacheTTL)
	transientDeadline := now.Add(v.transientWindow())
	backoff := 100 * time.Millisecond
	for {
		disposition, err := once(false)
		if err == nil {
			return nil
		}
		deadline := transientDeadline
		if disposition == publicVerificationStale {
			deadline = cacheDeadline
		}
		if disposition == publicVerificationFatal || !v.nowTime().Before(deadline) {
			return err
		}
		if disposition == publicVerificationStale {
			_, _ = once(true)
		}
		remaining := deadline.Sub(v.nowTime())
		wait := min(backoff, remaining)
		if wait <= 0 {
			return err
		}
		if sleepErr := v.sleepFor(ctx, wait); sleepErr != nil {
			return errors.Join(err, sleepErr)
		}
		backoff = min(2*backoff, 5*time.Second)
	}
}

func (v httpPublicationVerifier) httpClient() *http.Client {
	if v.client != nil {
		return v.client
	}
	return newPublicVerificationClient(v.base)
}

func (v httpPublicationVerifier) idleTimeout() time.Duration {
	if v.readIdleTimeout > 0 {
		return v.readIdleTimeout
	}
	return publicResponseTimeout
}

func (v httpPublicationVerifier) transientWindow() time.Duration {
	return v.transientRetryWindow
}

func (v httpPublicationVerifier) nowTime() time.Time {
	if v.now != nil {
		return v.now()
	}
	return time.Now()
}

func (v httpPublicationVerifier) sleepFor(ctx context.Context, duration time.Duration) error {
	if v.sleep != nil {
		return v.sleep(ctx, duration)
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func verifyHTTPPublicationObjectOnce(ctx context.Context, client *http.Client, base *url.URL, expected state.GenerationFile, revalidate bool, readIdleTimeout time.Duration) (publicVerificationDisposition, error) {
	if ctx == nil || client == nil || base == nil || expected.Size < 0 || !validPublicationObjectPath(expected.Path) || !lowercaseSHA256.MatchString(expected.SHA256) {
		return publicVerificationFatal, fmt.Errorf("%w: invalid public verification input", ErrRejected)
	}
	response, err := doHTTPPublicationGET(ctx, client, base, expected.Path, revalidate)
	if err != nil {
		return publicVerificationTransient, err
	}
	response.Body = r2.NewIdleReadCloser(ctx, response.Body, readIdleTimeout)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return classifyHTTPPublicationStatus(response.StatusCode, expected.Path, false)
	}
	hash := sha256.New()
	limit := expected.Size
	if limit < math.MaxInt64 {
		limit++
	}
	size, err := io.Copy(hash, &managedContextReader{ctx: ctx, reader: io.LimitReader(response.Body, limit)})
	if err != nil {
		return publicVerificationTransient, errors.Join(fmt.Errorf("%w: public GET failed while reading %q", ErrIntegrity, expected.Path), err)
	}
	if size != expected.Size || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return publicVerificationStale, fmt.Errorf("%w: public GET content differs for %q", ErrIntegrity, expected.Path)
	}
	return publicVerificationFatal, nil
}

func verifyHTTPPublicationAbsenceOnce(ctx context.Context, client *http.Client, base *url.URL, objectPath string, revalidate bool) (publicVerificationDisposition, error) {
	if ctx == nil || client == nil || base == nil || !validPublicationObjectPath(objectPath) {
		return publicVerificationFatal, fmt.Errorf("%w: invalid public absence verification input", ErrRejected)
	}
	response, err := doHTTPPublicationGET(ctx, client, base, objectPath, revalidate)
	if err != nil {
		return publicVerificationTransient, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusNotFound, http.StatusGone:
		return publicVerificationFatal, nil
	case http.StatusOK:
		return publicVerificationStale, fmt.Errorf("%w: public GET still serves %q", ErrIntegrity, objectPath)
	default:
		return classifyHTTPPublicationStatus(response.StatusCode, objectPath, true)
	}
}

func doHTTPPublicationGET(ctx context.Context, client *http.Client, base *url.URL, objectPath string, revalidate bool) (*http.Response, error) {
	u := *base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + objectPath
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if revalidate {
		request.Header.Set("Cache-Control", "no-cache")
		request.Header.Set("Pragma", "no-cache")
	}
	return client.Do(request)
}

func classifyHTTPPublicationStatus(status int, objectPath string, absence bool) (publicVerificationDisposition, error) {
	disposition := publicVerificationFatal
	if !absence && status == http.StatusNotFound {
		disposition = publicVerificationStale
	} else if status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= 500 {
		disposition = publicVerificationTransient
	}
	return disposition, fmt.Errorf("%w: public GET %q returned status %d", ErrIntegrity, objectPath, status)
}

func validPublicationObjectPath(objectPath string) bool {
	return objectPath != "" && (strings.HasPrefix(objectPath, "pool/") || strings.HasPrefix(objectPath, "dists/")) && publicFilePhase(objectPath) != ""
}
