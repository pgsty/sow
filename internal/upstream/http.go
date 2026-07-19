package upstream

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/syncer"
)

func normalizeBase(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("%w: base URL must be absolute HTTPS without credentials, query, or fragment", ErrUnsafeURL)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	if strings.ContainsAny(u.Path, "\\\x00\r\n") {
		return nil, fmt.Errorf("%w: invalid base path", ErrUnsafeURL)
	}
	if strings.Contains(u.EscapedPath(), "%") {
		return nil, fmt.Errorf("%w: percent-encoded base paths are not supported", ErrUnsafeURL)
	}
	cleanPath := path.Clean(u.Path)
	if u.Path != "/" && strings.TrimSuffix(u.Path, "/") != cleanPath {
		return nil, fmt.Errorf("%w: base path must be canonical", ErrUnsafeURL)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u, nil
}

func resolveRelative(base *url.URL, ref string) (string, error) {
	if base == nil || ref == "" || strings.ContainsAny(ref, "\\\x00\r\n") {
		return "", fmt.Errorf("%w: empty or malformed relative path", ErrUnsafeURL)
	}
	r, err := url.Parse(ref)
	if err != nil || r.IsAbs() || r.Host != "" || r.User != nil || r.RawQuery != "" || r.Fragment != "" {
		return "", fmt.Errorf("%w: metadata href must be a relative path", ErrUnsafeURL)
	}
	if strings.Contains(r.EscapedPath(), "%") {
		return "", fmt.Errorf("%w: percent-encoded metadata href %q", ErrUnsafeURL, ref)
	}
	decoded, err := url.PathUnescape(r.EscapedPath())
	if err != nil || decoded == "" || strings.HasPrefix(decoded, "/") || strings.Contains(decoded, "\\") {
		return "", fmt.Errorf("%w: malformed metadata href %q", ErrUnsafeURL, ref)
	}
	clean := path.Clean(decoded)
	if clean != decoded || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("%w: non-canonical metadata href %q", ErrUnsafeURL, ref)
	}
	for _, segment := range strings.Split(clean, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("%w: unsafe path segment in %q", ErrUnsafeURL, ref)
		}
	}
	resolved := base.ResolveReference(&url.URL{Path: clean})
	if resolved.Scheme != "https" || resolved.User != nil || resolved.RawQuery != "" || resolved.Fragment != "" {
		return "", fmt.Errorf("%w: unsafe resolved URL", ErrUnsafeURL)
	}
	return resolved.String(), nil
}

func secureHTTPClient(source *http.Client) *http.Client {
	if source == nil {
		source = http.DefaultClient
	}
	clone := *source
	if clone.Timeout <= 0 {
		clone.Timeout = 2 * time.Hour
	}
	if _, secured := source.Transport.(secureRoundTripper); !secured {
		transport := source.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		clone.Transport = secureRoundTripper{next: transport}
	}
	prior := source.CheckRedirect
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("upstream: stopped after 10 redirects")
		}
		if err := validateHTTPURL(req.URL); err != nil {
			return err
		}
		if prior != nil {
			return prior(req, via)
		}
		return nil
	}
	return &clone
}

func validateHTTPURL(u *url.URL) error {
	if u == nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("%w: request and redirect URLs must be clean HTTPS URLs", ErrUnsafeURL)
	}
	if strings.ContainsAny(u.Path, "\\\x00\r\n") || strings.Contains(u.EscapedPath(), "%") {
		return fmt.Errorf("%w: request paths must be canonical and unescaped", ErrUnsafeURL)
	}
	clean := path.Clean(u.Path)
	if u.Path != "" && u.Path != "/" && clean != u.Path {
		return fmt.Errorf("%w: request paths must be canonical and unescaped", ErrUnsafeURL)
	}
	return nil
}

type secureRoundTripper struct {
	next http.RoundTripper
}

func (t secureRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil {
		return nil, fmt.Errorf("%w: nil HTTP request", ErrUnsafeURL)
	}
	if err := validateHTTPURL(request.URL); err != nil {
		return nil, err
	}
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	// Byte-level repository checksums cover the representation on the wire.
	// Explicit identity prevents net/http from transparently expanding a gzip
	// Content-Encoding before those bytes reach the verifier.
	clone.Header.Set("Accept-Encoding", "identity")
	response, err := t.next.RoundTrip(clone)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, err
	}
	if response == nil || response.Body == nil {
		return nil, errors.New("upstream: HTTP transport returned a nil response")
	}
	encoding := strings.TrimSpace(strings.ToLower(response.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" {
		_ = response.Body.Close()
		return nil, fmt.Errorf("%w: unexpected HTTP Content-Encoding %q", ErrInvalidMetadata, encoding)
	}
	return response, nil
}

func fetchBytes(ctx context.Context, client *http.Client, rawURL string, limit int64, optional bool) ([]byte, bool, error) {
	u, err := url.Parse(rawURL)
	if err != nil || validateHTTPURL(u) != nil {
		return nil, false, fmt.Errorf("%w: invalid request URL", ErrUnsafeURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := secureHTTPClient(client).Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if optional && resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("upstream: GET %s returned HTTP %d", rawURL, resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, false, ErrMetadataTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return nil, false, ErrMetadataTooLarge
	}
	return data, true, nil
}

func preserveBytes(workDir, kind, rawURL string, data []byte, verified bool) (Evidence, error) {
	return preserveBytesWithDirectorySync(workDir, kind, rawURL, data, verified, syncUpstreamEvidenceDirectory)
}

func preserveBytesWithDirectorySync(workDir, kind, rawURL string, data []byte, verified bool, syncDirectory func(string) error) (Evidence, error) {
	if syncDirectory == nil {
		return Evidence{}, errors.New("upstream: evidence directory sync is unavailable")
	}
	digest := sha256.Sum256(data)
	hexDigest := hex.EncodeToString(digest[:])
	root, absolute, err := openDownloadRoot(workDir)
	if err != nil {
		return Evidence{}, err
	}
	defer root.Close()
	if err := ensureSafeSubdir(root, "evidence"); err != nil {
		return Evidence{}, err
	}
	if err := ensureSafeSubdir(root, filepath.Join("evidence", "sha256")); err != nil {
		return Evidence{}, err
	}
	relative := filepath.Join("evidence", "sha256", hexDigest)
	destination := filepath.Join(absolute, relative)
	verifyExisting := func() error {
		pathInfo, err := root.Lstat(relative)
		if err != nil {
			return err
		}
		if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Size() != int64(len(data)) {
			return fmt.Errorf("upstream: evidence destination is not a regular file: %s", destination)
		}
		existing, err := root.Open(relative)
		if err != nil {
			return err
		}
		openedInfo, err := existing.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
			_ = existing.Close()
			return fmt.Errorf("upstream: evidence changed while opening: %s", destination)
		}
		hash := sha256.New()
		written, copyErr := io.CopyBuffer(hash, existing, make([]byte, 256*1024))
		closeErr := existing.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
		if written != int64(len(data)) || hex.EncodeToString(hash.Sum(nil)) != hexDigest {
			return fmt.Errorf("upstream: evidence hash collision at %s", destination)
		}
		return nil
	}
	if err := verifyExisting(); err == nil {
		// Reusing immutable, byte-identical evidence is idempotent.
	} else if !errors.Is(err, os.ErrNotExist) {
		return Evidence{}, err
	} else {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return Evidence{}, err
		}
		tmpRelative := filepath.Join("evidence", "sha256", ".evidence-"+hex.EncodeToString(random[:]))
		tmp, err := root.OpenFile(tmpRelative, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return Evidence{}, err
		}
		defer root.Remove(tmpRelative)
		if _, err := tmp.Write(data); err != nil {
			_ = tmp.Close()
			return Evidence{}, err
		}
		if err := tmp.Sync(); err != nil {
			_ = tmp.Close()
			return Evidence{}, err
		}
		if err := tmp.Close(); err != nil {
			return Evidence{}, err
		}
		if err := root.Link(tmpRelative, relative); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return Evidence{}, err
			}
			if err := verifyExisting(); err != nil {
				return Evidence{}, err
			}
		}
	}
	if err := syncDirectory(filepath.Join(absolute, "evidence", "sha256")); err != nil {
		return Evidence{}, fmt.Errorf("upstream: sync evidence directory: %w", err)
	}
	return Evidence{Kind: kind, URL: rawURL, Path: destination, SHA256: hexDigest, Size: int64(len(data)), Verified: verified}, nil
}

func syncUpstreamEvidenceDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func ensureSafeSubdir(root *os.Root, relative string) error {
	info, err := root.Lstat(relative)
	if errors.Is(err, os.ErrNotExist) {
		if err := root.Mkdir(relative, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err = root.Lstat(relative)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("upstream: evidence path %s must be a real directory", relative)
	}
	return nil
}

func downloadEvidence(ctx context.Context, workDir, kind string, candidate syncer.Candidate, client *http.Client, limits Limits) (Evidence, error) {
	if candidate.Size > limits.IndexCompressedBytes {
		return Evidence{}, ErrMetadataTooLarge
	}
	downloader := syncer.Downloader{Client: secureHTTPClient(client), Attempts: 4}
	file, err := verifiedDownload(ctx, candidate, filepath.Join(workDir, "downloads"), downloader)
	if err != nil {
		return Evidence{}, err
	}
	return Evidence{Kind: kind, URL: candidate.URL, Path: file, SHA256: candidate.SHA256, Size: candidate.Size, Verified: true}, nil
}
