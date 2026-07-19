package syncer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Downloader struct {
	Client     *http.Client
	Attempts   int
	RetryDelay time.Duration
	BufferSize int
}

func (d Downloader) Download(ctx context.Context, candidate Candidate, dir string) (string, error) {
	if err := candidate.Validate(); err != nil {
		return "", err
	}
	if d.Client == nil {
		d.Client = &http.Client{Timeout: 5 * time.Minute}
	}
	if d.Attempts <= 0 {
		d.Attempts = 4
	}
	if d.BufferSize <= 0 {
		d.BufferSize = 256 * 1024
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	partial := filepath.Join(dir, candidate.SHA256+".part")
	complete := filepath.Join(dir, candidate.SHA256+".download")
	if _, err := os.Stat(complete); err == nil {
		if err := verifyFile(complete, candidate.Size, candidate.SHA256, d.BufferSize); err != nil {
			return "", fmt.Errorf("existing completed download is corrupt: %w", err)
		}
		return complete, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var last error
	for attempt := 1; attempt <= d.Attempts; attempt++ {
		if info, err := os.Stat(partial); err == nil && info.Size() == candidate.Size {
			if err := verifyFile(partial, candidate.Size, candidate.SHA256, d.BufferSize); err == nil {
				if err := os.Rename(partial, complete); err != nil {
					return "", err
				}
				return complete, nil
			}
			_ = os.Remove(partial)
		}
		if err := d.downloadAttempt(ctx, candidate, partial); err == nil {
			if err := verifyFile(partial, candidate.Size, candidate.SHA256, d.BufferSize); err != nil {
				_ = os.Remove(partial)
				last = err
				continue
			}
			if err := os.Rename(partial, complete); err != nil {
				return "", err
			}
			return complete, nil
		} else {
			last = err
		}
		if attempt < d.Attempts && d.RetryDelay > 0 {
			timer := time.NewTimer(d.RetryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", ctx.Err()
			case <-timer.C:
			}
		}
	}
	return "", fmt.Errorf("download failed after %d attempts: %w", d.Attempts, last)
}

func (d Downloader) downloadAttempt(ctx context.Context, candidate Candidate, partial string) error {
	offset := int64(0)
	if info, err := os.Stat(partial); err == nil {
		offset = info.Size()
		if offset > candidate.Size {
			if err := os.Remove(partial); err != nil {
				return err
			}
			offset = 0
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate.URL, nil)
	if err != nil {
		return err
	}
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	appendMode := offset > 0 && resp.StatusCode == http.StatusPartialContent
	if appendMode {
		if err := validateContentRange(resp.Header.Get("Content-Range"), offset, candidate.Size); err != nil {
			return err
		}
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	flags := os.O_CREATE | os.O_WRONLY
	if appendMode {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
		offset = 0
	}
	f, err := os.OpenFile(partial, flags, 0o600)
	if err != nil {
		return err
	}
	buffer := make([]byte, d.BufferSize)
	written, copyErr := io.CopyBuffer(f, resp.Body, buffer)
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return errors.Join(copyErr, syncErr, closeErr)
	}
	if offset+written > candidate.Size {
		return fmt.Errorf("server sent more bytes than declared")
	}
	if offset+written < candidate.Size {
		return fmt.Errorf("short response: have %d of %d bytes", offset+written, candidate.Size)
	}
	return nil
}

func validateContentRange(value string, offset, size int64) error {
	if !strings.HasPrefix(value, "bytes ") {
		return fmt.Errorf("invalid Content-Range %q for offset %d size %d", value, offset, size)
	}
	parts := strings.Split(strings.TrimPrefix(value, "bytes "), "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid Content-Range %q for offset %d size %d", value, offset, size)
	}
	span := strings.Split(parts[0], "-")
	start, startErr := strconv.ParseInt(span[0], 10, 64)
	end, endErr := int64(-1), error(nil)
	if len(span) == 2 {
		end, endErr = strconv.ParseInt(span[1], 10, 64)
	}
	total, totalErr := strconv.ParseInt(parts[1], 10, 64)
	if len(span) != 2 || startErr != nil || endErr != nil || totalErr != nil || start != offset || end != size-1 || total != size {
		return fmt.Errorf("invalid Content-Range %q for offset %d size %d", value, offset, size)
	}
	return nil
}

func verifyFile(path string, size int64, expected string, bufferSize int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hash := sha256.New()
	written, err := io.CopyBuffer(hash, f, make([]byte, bufferSize))
	if err != nil {
		return err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if written != size || actual != expected {
		return fmt.Errorf("download verification failed: size=%d sha256=%s", written, actual)
	}
	return nil
}
