package aptrepo

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ulikunitz/xz"
)

// GenerateStreaming is the production APT index path. Unlike Generate, it
// never retains package collections or PoolObjects: callers materialize CAS
// bodies first and supply one externally sorted iterator per index. Package
// sources are rehashed while their control paragraphs are streamed.
func GenerateStreaming(ctx context.Context, outputDir string, cfg RepositoryConfig, indexes []StreamingIndex, signer *Signer, options StreamingOptions) (result BuildResult, resultErr error) {
	if ctx == nil {
		return BuildResult{}, errors.New("aptrepo: nil context")
	}
	if err := ctx.Err(); err != nil {
		return BuildResult{}, err
	}
	validated, err := validateRepositoryConfig(cfg)
	if err != nil {
		return BuildResult{}, err
	}
	if signer == nil {
		return BuildResult{}, errors.New("aptrepo: signing key is required")
	}
	if err := signer.Validate(validated.Date); err != nil {
		return BuildResult{}, err
	}
	if outputDir == "" {
		return BuildResult{}, errors.New("aptrepo: output directory is required")
	}
	if options.Workers < 1 {
		return BuildResult{}, errors.New("aptrepo: streaming workers must be positive")
	}
	if options.Workers > 64 {
		options.Workers = 64
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return BuildResult{}, fmt.Errorf("aptrepo: create output directory: %w", err)
	}
	if err := validateOutputRoot(outputDir); err != nil {
		return BuildResult{}, err
	}
	unlock, err := acquireOutputLock(ctx, outputDir)
	if err != nil {
		return BuildResult{}, err
	}
	defer propagateOutputUnlock(unlock, &resultErr)
	outputAbs, err := filepath.Abs(outputDir)
	if err != nil {
		return BuildResult{}, fmt.Errorf("aptrepo: resolve output directory: %w", err)
	}
	stageRoot, err := os.MkdirTemp(filepath.Dir(outputAbs), ".sow-apt-stage-")
	if err != nil {
		return BuildResult{}, fmt.Errorf("aptrepo: create staging directory: %w", err)
	}
	defer os.RemoveAll(stageRoot)

	result, err = generateStreamingTree(ctx, stageRoot, validated, indexes, signer, options.Workers)
	if err != nil {
		return BuildResult{}, err
	}
	if options.StagedTransform != nil {
		beforeTransform := result
		if err := options.StagedTransform(stageRoot, result); err != nil {
			return BuildResult{}, fmt.Errorf("aptrepo: transform staged build: %w", err)
		}
		result, err = resealStagedBuild(stageRoot, result)
		if err != nil {
			return BuildResult{}, err
		}
		if err := validateStagedSignatureTransform(beforeTransform, result); err != nil {
			return BuildResult{}, err
		}
	}
	if err := commitStagedBuildGuarded(ctx, stageRoot, outputDir, result, options.CommitGuard); err != nil {
		return BuildResult{}, err
	}
	return result, nil
}

type streamingIndexJob struct {
	key      indexKey
	packages PackageIterator
}

type streamingIndexResult struct {
	artifacts    []Artifact
	canonical    []Artifact
	byHashPaths  []string
	packageCount int64
	err          error
}

func generateStreamingTree(ctx context.Context, outputDir string, cfg RepositoryConfig, indexes []StreamingIndex, signer *Signer, workers int) (BuildResult, error) {
	streams, err := validateStreamingIndexes(cfg, indexes)
	if err != nil {
		return BuildResult{}, err
	}
	result := BuildResult{
		ReleasePath:           path.Join("dists", cfg.Suite, "Release"),
		InReleasePath:         path.Join("dists", cfg.Suite, "InRelease"),
		DetachedSignaturePath: path.Join("dists", cfg.Suite, "Release.gpg"),
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return BuildResult{}, fmt.Errorf("aptrepo: create output directory: %w", err)
	}
	if err := validateOutputRoot(outputDir); err != nil {
		return BuildResult{}, err
	}

	jobs := make([]streamingIndexJob, 0, len(cfg.Components)*len(cfg.Architectures))
	for _, component := range cfg.Components {
		for _, architecture := range cfg.Architectures {
			key := indexKey{component: component, architecture: architecture}
			jobs = append(jobs, streamingIndexJob{key: key, packages: streams[key]})
		}
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	if workers < 1 {
		workers = 1
	}

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobCh := make(chan streamingIndexJob)
	resultCh := make(chan streamingIndexResult, len(jobs))
	var group sync.WaitGroup
	var active atomic.Int64
	var peak atomic.Int64
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for job := range jobCh {
				current := active.Add(1)
				for previous := peak.Load(); current > previous && !peak.CompareAndSwap(previous, current); previous = peak.Load() {
				}
				built := generateStreamingIndex(workerCtx, outputDir, cfg.Suite, job)
				active.Add(-1)
				if built.err != nil {
					cancel()
				}
				resultCh <- built
			}
		}()
	}
	go func() {
		defer close(jobCh)
		for _, job := range jobs {
			select {
			case jobCh <- job:
			case <-workerCtx.Done():
				return
			}
		}
	}()
	go func() {
		group.Wait()
		close(resultCh)
	}()

	var canonicalIndexes []Artifact
	var byHashPaths []string
	var firstErr error
	for built := range resultCh {
		if built.err != nil {
			if firstErr == nil {
				firstErr = built.err
			}
			continue
		}
		result.Artifacts = append(result.Artifacts, built.artifacts...)
		canonicalIndexes = append(canonicalIndexes, built.canonical...)
		byHashPaths = append(byHashPaths, built.byHashPaths...)
		result.StreamedPackages += built.packageCount
	}
	if firstErr != nil {
		return BuildResult{}, firstErr
	}
	if err := ctx.Err(); err != nil {
		return BuildResult{}, err
	}
	result.PeakIndexWorkers = int(peak.Load())
	return finalizeBuild(ctx, outputDir, cfg, result, canonicalIndexes, byHashPaths, signer)
}

func validateStreamingIndexes(cfg RepositoryConfig, indexes []StreamingIndex) (map[indexKey]PackageIterator, error) {
	configured := make(map[indexKey]struct{}, len(cfg.Components)*len(cfg.Architectures))
	for _, component := range cfg.Components {
		for _, architecture := range cfg.Architectures {
			configured[indexKey{component: component, architecture: architecture}] = struct{}{}
		}
	}
	streams := make(map[indexKey]PackageIterator, len(indexes))
	for _, index := range indexes {
		if err := validateComponent(index.Component); err != nil {
			return nil, err
		}
		if !architecturePattern.MatchString(index.Architecture) || index.Architecture == "all" {
			return nil, fmt.Errorf("aptrepo: unsafe index architecture %q", index.Architecture)
		}
		key := indexKey{component: index.Component, architecture: index.Architecture}
		if _, ok := configured[key]; !ok {
			return nil, fmt.Errorf("aptrepo: index %s/%s is not configured", index.Component, index.Architecture)
		}
		if _, duplicate := streams[key]; duplicate {
			return nil, fmt.Errorf("aptrepo: duplicate index %s/%s", index.Component, index.Architecture)
		}
		streams[key] = index.Packages
	}
	return streams, nil
}

func generateStreamingIndex(ctx context.Context, outputDir, suite string, job streamingIndexJob) streamingIndexResult {
	base, err := IndexBasePath(suite, job.key.component, job.key.architecture)
	if err != nil {
		return streamingIndexResult{err: err}
	}
	packagesPath := path.Join(base, "Packages")
	var count int64
	packagesArtifact, err := writeArtifact(ctx, outputDir, packagesPath, func(w io.Writer) error {
		writer, err := NewPackagesWriter(w)
		if err != nil {
			return err
		}
		if job.packages == nil {
			return nil
		}
		for {
			pkg, nextErr := job.packages.Next(ctx)
			if errors.Is(nextErr, io.EOF) {
				return nil
			}
			if nextErr != nil {
				return nextErr
			}
			if pkg.Component != job.key.component {
				return fmt.Errorf("aptrepo: package component %q does not match index %q", pkg.Component, job.key.component)
			}
			if pkg.Architecture != "all" && pkg.Architecture != job.key.architecture {
				return fmt.Errorf("aptrepo: package architecture %q does not match index %q", pkg.Architecture, job.key.architecture)
			}
			if err := verifyPackageSource(ctx, pkg); err != nil {
				return err
			}
			if err := writer.Write(pkg); err != nil {
				return err
			}
			count++
		}
	})
	if err != nil {
		return streamingIndexResult{err: err}
	}
	gzipArtifact, err := writeArtifact(ctx, outputDir, packagesPath+".gz", func(w io.Writer) error {
		zw, err := gzip.NewWriterLevel(w, gzip.BestCompression)
		if err != nil {
			return fmt.Errorf("aptrepo: create gzip writer: %w", err)
		}
		zw.Header.ModTime = time.Time{}
		zw.Header.OS = 255
		if err := copyArtifact(ctx, outputDir, packagesPath, zw); err != nil {
			_ = zw.Close()
			return err
		}
		if err := zw.Close(); err != nil {
			return fmt.Errorf("aptrepo: close gzip index: %w", err)
		}
		return nil
	})
	if err != nil {
		return streamingIndexResult{err: err}
	}
	xzArtifact, err := writeArtifact(ctx, outputDir, packagesPath+".xz", func(w io.Writer) error {
		zw, err := xz.NewWriter(w)
		if err != nil {
			return fmt.Errorf("aptrepo: create xz writer: %w", err)
		}
		if err := copyArtifact(ctx, outputDir, packagesPath, zw); err != nil {
			_ = zw.Close()
			return err
		}
		if err := zw.Close(); err != nil {
			return fmt.Errorf("aptrepo: close xz index: %w", err)
		}
		return nil
	})
	if err != nil {
		return streamingIndexResult{err: err}
	}
	artifacts := []Artifact{packagesArtifact, gzipArtifact, xzArtifact}
	result := streamingIndexResult{canonical: append([]Artifact(nil), artifacts...), packageCount: count}
	for _, artifact := range artifacts {
		byHashPath := path.Join(base, "by-hash", "SHA256", artifact.SHA256)
		byHashArtifact, err := linkByHash(outputDir, artifact, byHashPath)
		if err != nil {
			return streamingIndexResult{err: err}
		}
		result.artifacts = append(result.artifacts, artifact, byHashArtifact)
		result.byHashPaths = append(result.byHashPaths, byHashPath)
	}
	sort.Slice(result.artifacts, func(i, j int) bool { return result.artifacts[i].Path < result.artifacts[j].Path })
	return result
}
