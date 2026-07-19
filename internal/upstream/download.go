package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pgsty/sow/internal/syncer"
	"golang.org/x/sys/unix"
)

var downloadLockOpen sync.Mutex

func verifiedDownload(ctx context.Context, candidate syncer.Candidate, dir string, settings syncer.Downloader) (result string, resultErr error) {
	if ctx == nil {
		return "", errors.New("upstream: nil context")
	}
	if err := candidate.Validate(); err != nil {
		return "", err
	}
	parsed, err := url.Parse(candidate.URL)
	if err != nil || validateHTTPURL(parsed) != nil {
		return "", fmt.Errorf("%w: package URL is not canonical HTTPS", ErrUnsafeURL)
	}
	if candidate.Size <= 0 {
		return "", fmt.Errorf("%w: download size must be positive", ErrInvalidMetadata)
	}
	root, absolute, err := openDownloadRoot(dir)
	if err != nil {
		return "", err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()

	unlock, err := lockDownload(ctx, root, candidate.SHA256+".lock")
	if err != nil {
		return "", err
	}
	defer propagateDownloadUnlock(unlock, &resultErr)

	partial := candidate.SHA256 + ".part"
	complete := candidate.SHA256 + ".download"
	if exists, err := safeRegularExists(root, complete); err != nil {
		return "", err
	} else if exists {
		if err := verifyRootFile(root, complete, candidate.Size, candidate.SHA256, downloadBufferSize(settings)); err != nil {
			return "", fmt.Errorf("%w: completed download %s: %v", ErrEvidence, candidate.SHA256, err)
		}
		return filepath.Join(absolute, complete), nil
	}

	attempts := settings.Attempts
	if attempts <= 0 {
		attempts = 4
	}
	client := secureHTTPClient(settings.Client)
	var last error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if exists, err := safeRegularExists(root, partial); err != nil {
			return "", err
		} else if exists {
			info, err := root.Lstat(partial)
			if err != nil {
				return "", err
			}
			if info.Size() > candidate.Size {
				if err := root.Remove(partial); err != nil {
					return "", err
				}
			} else if info.Size() == candidate.Size {
				if err := verifyRootFile(root, partial, candidate.Size, candidate.SHA256, downloadBufferSize(settings)); err == nil {
					if err := installDownload(root, absolute, partial, complete, candidate, settings); err != nil {
						return "", err
					}
					return filepath.Join(absolute, complete), nil
				}
				if err := root.Remove(partial); err != nil {
					return "", err
				}
			}
		}

		last = downloadAttempt(ctx, root, client, candidate, partial, downloadBufferSize(settings))
		if last == nil {
			if err := verifyRootFile(root, partial, candidate.Size, candidate.SHA256, downloadBufferSize(settings)); err != nil {
				_ = root.Remove(partial)
				last = err
			} else if err := installDownload(root, absolute, partial, complete, candidate, settings); err != nil {
				return "", err
			} else {
				return filepath.Join(absolute, complete), nil
			}
		}
		if attempt < attempts {
			delay := settings.RetryDelay
			if delay <= 0 {
				delay = time.Duration(attempt) * 100 * time.Millisecond
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", ctx.Err()
			case <-timer.C:
			}
		}
	}
	return "", fmt.Errorf("upstream: download failed after %d attempts: %w", attempts, last)
}

type downloadUnlock func() error

func propagateDownloadUnlock(unlock downloadUnlock, resultErr *error) {
	if unlock == nil || resultErr == nil {
		return
	}
	*resultErr = errors.Join(*resultErr, unlock())
}

func openDownloadRoot(dir string) (*os.Root, string, error) {
	if dir == "" {
		return nil, "", errors.New("upstream: download directory is required")
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, "", errors.New("upstream: download directory must be a real directory")
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, "", err
	}
	return root, absolute, nil
}

func lockDownload(ctx context.Context, root *os.Root, name string) (downloadUnlock, error) {
	downloadLockOpen.Lock()
	if info, err := root.Lstat(name); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		downloadLockOpen.Unlock()
		return nil, errors.New("upstream: unsafe download lock file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		downloadLockOpen.Unlock()
		return nil, err
	}
	var file *os.File
	var err error
	for attempt := 0; attempt < 8; attempt++ {
		file, err = root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			downloadLockOpen.Unlock()
			return nil, err
		}
		time.Sleep(time.Duration(attempt+1) * time.Millisecond)
	}
	if err != nil {
		downloadLockOpen.Unlock()
		return nil, err
	}
	downloadLockOpen.Unlock()
	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() error {
				return errors.Join(unix.Flock(int(file.Fd()), unix.LOCK_UN), file.Close())
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return nil, errors.Join(err, file.Close())
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, errors.Join(ctx.Err(), file.Close())
		case <-timer.C:
		}
	}
}

func safeRegularExists(root *os.Root, name string) (bool, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("upstream: unsafe download file %s", name)
	}
	return true, nil
}

func downloadAttempt(ctx context.Context, root *os.Root, client *http.Client, candidate syncer.Candidate, partial string, bufferSize int) error {
	offset := int64(0)
	if exists, err := safeRegularExists(root, partial); err != nil {
		return err
	} else if exists {
		info, err := root.Lstat(partial)
		if err != nil {
			return err
		}
		offset = info.Size()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate.URL, nil)
	if err != nil {
		return err
	}
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	appendMode := false
	expectedBody := candidate.Size
	if offset > 0 && resp.StatusCode == http.StatusPartialContent {
		var end int64
		end, err = validateRangeResponse(resp.Header.Get("Content-Range"), offset, candidate.Size)
		if err != nil {
			return err
		}
		appendMode = true
		expectedBody = end - offset + 1
	} else if resp.StatusCode == http.StatusOK {
		offset = 0
	} else {
		return fmt.Errorf("upstream: unexpected HTTP status %d", resp.StatusCode)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != expectedBody {
		return fmt.Errorf("upstream: response Content-Length %d, expected %d", resp.ContentLength, expectedBody)
	}

	flags := os.O_CREATE | os.O_WRONLY
	if appendMode {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	file, err := root.OpenFile(partial, flags, 0o600)
	if err != nil {
		return err
	}
	if info, statErr := file.Stat(); statErr != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return errors.New("upstream: partial download is not a regular file")
	}
	written, copyErr := io.CopyBuffer(file, io.LimitReader(resp.Body, expectedBody+1), make([]byte, bufferSize))
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return errors.Join(copyErr, syncErr, closeErr)
	}
	if written > expectedBody {
		_ = root.Remove(partial)
		return errors.New("upstream: server sent more bytes than metadata declared")
	}
	if written < expectedBody {
		return fmt.Errorf("upstream: short response: received %d of %d bytes", written, expectedBody)
	}
	info, err := root.Lstat(partial)
	if err != nil {
		return err
	}
	wantTotal := offset + expectedBody
	if info.Size() != wantTotal || wantTotal > candidate.Size {
		_ = root.Remove(partial)
		return fmt.Errorf("upstream: partial file size %d, expected %d", info.Size(), wantTotal)
	}
	if wantTotal < candidate.Size {
		return fmt.Errorf("upstream: ranged response ended at %d of %d bytes", wantTotal, candidate.Size)
	}
	return nil
}

func validateRangeResponse(value string, offset, size int64) (int64, error) {
	if !strings.HasPrefix(value, "bytes ") {
		return 0, fmt.Errorf("upstream: invalid Content-Range %q", value)
	}
	parts := strings.Split(strings.TrimPrefix(value, "bytes "), "/")
	if len(parts) != 2 {
		return 0, fmt.Errorf("upstream: invalid Content-Range %q", value)
	}
	span := strings.Split(parts[0], "-")
	if len(span) != 2 {
		return 0, fmt.Errorf("upstream: invalid Content-Range %q", value)
	}
	start, startErr := strconv.ParseInt(span[0], 10, 64)
	end, endErr := strconv.ParseInt(span[1], 10, 64)
	total, totalErr := strconv.ParseInt(parts[1], 10, 64)
	if startErr != nil || endErr != nil || totalErr != nil || start != offset || end < start || end >= size || total != size {
		return 0, fmt.Errorf("upstream: invalid Content-Range %q", value)
	}
	return end, nil
}

func verifyRootFile(root *os.Root, name string, size int64, expected string, bufferSize int) error {
	if exists, err := safeRegularExists(root, name); err != nil || !exists {
		if err != nil {
			return err
		}
		return os.ErrNotExist
	}
	pathInfo, err := root.Lstat(name)
	if err != nil {
		return err
	}
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		return errors.New("upstream: download changed while opening")
	}
	hash := sha256.New()
	written, copyErr := io.CopyBuffer(hash, file, make([]byte, bufferSize))
	closeErr := file.Close()
	actual := hex.EncodeToString(hash.Sum(nil))
	afterInfo, statErr := root.Lstat(name)
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	if statErr != nil || !os.SameFile(pathInfo, afterInfo) || afterInfo.Size() != pathInfo.Size() ||
		!afterInfo.ModTime().Equal(pathInfo.ModTime()) {
		return errors.New("upstream: download changed while hashing")
	}
	if written != size || actual != expected {
		return fmt.Errorf("verification failed: size=%d sha256=%s", written, actual)
	}
	return nil
}

func installDownload(root *os.Root, absolute, partial, complete string, candidate syncer.Candidate, settings syncer.Downloader) error {
	if exists, err := safeRegularExists(root, complete); err != nil {
		return err
	} else if exists {
		if err := verifyRootFile(root, complete, candidate.Size, candidate.SHA256, downloadBufferSize(settings)); err != nil {
			return fmt.Errorf("%w: concurrent completed download: %v", ErrEvidence, err)
		}
		return root.Remove(partial)
	}
	if err := root.Rename(partial, complete); err != nil {
		return err
	}
	directory, err := os.Open(absolute)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func downloadBufferSize(settings syncer.Downloader) int {
	if settings.BufferSize > 0 {
		return settings.BufferSize
	}
	return 256 * 1024
}
