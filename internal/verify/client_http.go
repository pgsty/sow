package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

type protocolFetcher struct {
	base      *url.URL
	client    *http.Client
	headers   http.Header
	allowHTTP bool
}

func newProtocolFetcher(rawBase string, client *http.Client, headers http.Header, allowHTTP bool) (*protocolFetcher, error) {
	base, err := url.Parse(rawBase)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.RawPath != "" ||
		(base.Scheme != "https" && !(allowHTTP && base.Scheme == "http")) {
		return nil, fmt.Errorf("%w: invalid configured CDN base", ErrClientCoverage)
	}
	if base.Path == "" {
		base.Path = "/"
	}
	clean := path.Clean(base.Path)
	if clean != strings.TrimSuffix(base.Path, "/") && base.Path != "/" {
		return nil, fmt.Errorf("%w: non-canonical configured CDN base", ErrClientCoverage)
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/"
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	copyClient := *client
	if copyClient.Timeout == 0 {
		copyClient.Timeout = 2 * time.Minute
	}
	// Client evidence is bound to the requested repository route. Never follow
	// even a same-origin redirect: doing so can forward Basic credentials to a
	// sibling path or let a public route stand in for the selected Pro route.
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &protocolFetcher{base: base, client: &copyClient, headers: headers.Clone(), allowHTTP: allowHTTP}, nil
}

func (f *protocolFetcher) resolve(relative string) (*url.URL, error) {
	if relative == "" || strings.HasPrefix(relative, "/") || path.Clean(relative) != relative || strings.ContainsAny(relative, "\\%?#\x00\r\n\t") {
		return nil, fmt.Errorf("%w: unsafe repository path", ErrClientIntegrity)
	}
	result := *f.base
	result.Path = path.Join(f.base.Path, relative)
	result.RawPath = ""
	return &result, nil
}

func (f *protocolFetcher) absolute(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" ||
		u.Scheme != f.base.Scheme || !strings.EqualFold(u.Host, f.base.Host) || path.Clean(u.Path) != strings.TrimSuffix(u.Path, "/") && u.Path != "/" {
		return nil, fmt.Errorf("%w: mirror endpoint is outside the configured CDN origin", ErrClientIntegrity)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

func (f *protocolFetcher) readRelative(ctx context.Context, relative string, limit int64) ([]byte, error) {
	u, err := f.resolve(relative)
	if err != nil {
		return nil, err
	}
	return f.readURL(ctx, u, limit)
}

func (f *protocolFetcher) readURL(ctx context.Context, u *url.URL, limit int64) ([]byte, error) {
	if limit < 1 {
		return nil, fmt.Errorf("%w: invalid response limit", ErrClientCoverage)
	}
	response, err := f.open(ctx, u, limit)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: response body read failed", ErrClientNetwork)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: response exceeds safety limit", ErrClientIntegrity)
	}
	return body, nil
}

func (f *protocolFetcher) downloadRelative(ctx context.Context, relative, destination string, expectedSize int64, expectedSHA string, maximum int64) error {
	u, err := f.resolve(relative)
	if err != nil {
		return err
	}
	return f.downloadURL(ctx, u, destination, expectedSize, expectedSHA, maximum)
}

func (f *protocolFetcher) downloadURL(ctx context.Context, u *url.URL, destination string, expectedSize int64, expectedSHA string, maximum int64) error {
	if expectedSize < 0 || expectedSize > maximum || !lowerSHA256(expectedSHA) {
		return fmt.Errorf("%w: unsafe expected object identity", ErrClientIntegrity)
	}
	response, err := f.open(ctx, u, expectedSize+1)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.ContentLength >= 0 && response.ContentLength != expectedSize {
		return fmt.Errorf("%w: object Content-Length disagrees with signed metadata", ErrClientIntegrity)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("%w: create protocol spool", ErrClientCoverage)
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(destination)
		}
	}()
	hasher := newSHA256Writer(file)
	written, copyErr := io.CopyBuffer(hasher, &contextReader{ctx: ctx, reader: io.LimitReader(response.Body, expectedSize+1)}, make([]byte, 256*1024))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: object download interrupted", ErrClientNetwork)
	}
	if written != expectedSize || hasher.Sum() != expectedSHA {
		return fmt.Errorf("%w: downloaded object differs from signed metadata", ErrClientIntegrity)
	}
	committed = true
	return nil
}

func (f *protocolFetcher) open(ctx context.Context, u *url.URL, maximum int64) (*http.Response, error) {
	if u == nil || u.Scheme != f.base.Scheme || !strings.EqualFold(u.Host, f.base.Host) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || path.Clean(u.Path) != u.Path {
		return nil, fmt.Errorf("%w: request escaped configured CDN origin", ErrClientIntegrity)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: construct CDN request", ErrClientCoverage)
	}
	request.Header = f.headers.Clone()
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := f.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: CDN request failed", ErrClientNetwork)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = response.Body.Close()
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			return nil, fmt.Errorf("%w: CDN redirect refused", ErrClientIntegrity)
		}
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusProxyAuthRequired || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			return nil, fmt.Errorf("%w: CDN returned status %d", ErrClientNetwork, response.StatusCode)
		}
		return nil, fmt.Errorf("%w: CDN returned status %d", ErrClientIntegrity, response.StatusCode)
	}
	if response.ContentLength > maximum {
		_ = response.Body.Close()
		return nil, fmt.Errorf("%w: CDN response exceeds safety limit", ErrClientIntegrity)
	}
	return response, nil
}

type hashingFileWriter struct {
	destination io.Writer
	hash        hash.Hash
}

func newSHA256Writer(destination io.Writer) *hashingFileWriter {
	return &hashingFileWriter{destination: destination, hash: sha256.New()}
}

func (w *hashingFileWriter) Write(data []byte) (int, error) {
	n, err := w.destination.Write(data)
	if n > 0 {
		_, _ = w.hash.Write(data[:n])
	}
	return n, err
}

func (w *hashingFileWriter) Sum() string { return hex.EncodeToString(w.hash.Sum(nil)) }
