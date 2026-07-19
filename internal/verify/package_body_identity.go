package verify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/pgsty/sow/internal/manifest"
)

// buildPackageBodyIdentityManifest inspects a manifest stream with bounded
// concurrency while retaining external-sort memory bounds. inspect must bind
// each result to the exact descriptor represented by entry.
func buildPackageBodyIdentityManifest(ctx context.Context, tempRoot, payloadPath string, workers, chunkEntries int, inspect func(context.Context, manifest.Entry) (manifest.Entry, error)) (string, func() error, error) {
	if inspect == nil {
		return "", nil, errors.New("nil package body inspector")
	}
	if workers <= 0 {
		workers = 4
	}
	if workers > 64 {
		workers = 64
	}
	input, err := os.Open(payloadPath)
	if err != nil {
		return "", nil, err
	}
	spool, err := newManifestSpool(tempRoot, chunkEntries)
	if err != nil {
		if closeErr := input.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return "", nil, err
	}
	workCtx, cancel := context.WithCancel(ctx)
	jobs := make(chan manifest.Entry, workers*2)
	type result struct {
		entry    manifest.Entry
		err      error
		teardown bool
	}
	results := make(chan result, workers*2)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for entry := range jobs {
				if workCtx.Err() != nil {
					continue
				}
				identity, err := inspect(workCtx, entry)
				select {
				case results <- result{entry: identity, err: err}:
				case <-workCtx.Done():
					return
				}
				if err != nil {
					return
				}
			}
		}()
	}
	go func() {
		reader := manifest.NewReader(input)
	readLoop:
		for {
			entry, readErr := reader.Next()
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				select {
				case results <- result{err: readErr}:
				case <-workCtx.Done():
				}
				break
			}
			select {
			case jobs <- entry:
			case <-workCtx.Done():
				break readLoop
			}
			if workCtx.Err() != nil {
				break
			}
		}
		close(jobs)
		wait.Wait()
		if closeErr := input.Close(); closeErr != nil {
			results <- result{err: fmt.Errorf("close package body manifest: %w", closeErr), teardown: true}
		}
		close(results)
	}()
	var firstErr, teardownErr error
	for result := range results {
		if result.err != nil {
			if result.teardown {
				teardownErr = errors.Join(teardownErr, result.err)
				continue
			}
			if firstErr == nil {
				firstErr = result.err
				cancel()
			}
			continue
		}
		if firstErr == nil {
			if err := spool.Add(result.entry); err != nil {
				firstErr = err
				cancel()
			}
		}
	}
	cancel()
	if firstErr != nil || teardownErr != nil {
		resultErr := firstErr
		if teardownErr != nil {
			resultErr = errors.Join(resultErr, teardownErr)
		}
		if closeErr := spool.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
		return "", nil, resultErr
	}
	output, err := spool.Finish(ctx)
	if err != nil {
		if closeErr := spool.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return "", nil, err
	}
	return output, spool.Close, nil
}

func joinVerificationCleanup(resultErr *error, cleanup func() error) {
	if resultErr == nil || cleanup == nil {
		return
	}
	if cleanupErr := cleanup(); cleanupErr != nil {
		*resultErr = errors.Join(*resultErr, cleanupErr)
	}
}
