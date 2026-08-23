// Package workmetrics carries operation-local performance counters through a
// context. The collector is deliberately in-memory and optional: production
// behavior is unchanged when a command has not installed one.
package workmetrics

import (
	"context"
	"sync"
)

// PayloadReads records package-sized content reads. Metadata reads are not
// included: the metric exists to make package-byte amplification explicit.
type PayloadReads struct {
	Bytes int64 `json:"bytes"`
	Full  int64 `json:"full_reads"`
}

// Snapshot is the stable operation metric payload retained in build events.
// Stat and SQL counters are present from the first schema so later fast-path
// milestones can populate them without changing the event wire format.
type Snapshot struct {
	PayloadBytesRead   int64                   `json:"payload_bytes_read"`
	FullPackageReads   int64                   `json:"full_package_reads"`
	SignatureBytesRead int64                   `json:"signature_bytes_read"`
	SignatureStreams   int64                   `json:"signature_streams"`
	MetadataBytesRead  int64                   `json:"metadata_bytes_read"`
	MetadataTreeHashes int64                   `json:"metadata_tree_hashes"`
	TreeWalks          int64                   `json:"tree_walks"`
	FactRowsRead       int64                   `json:"fact_rows_read"`
	FactBytesRead      int64                   `json:"fact_bytes_read"`
	StatHits           int64                   `json:"stat_hits"`
	StatMisses         int64                   `json:"stat_misses"`
	FactCacheHits      int64                   `json:"fact_cache_hits"`
	FactCacheMisses    int64                   `json:"fact_cache_misses"`
	SQLStatements      int64                   `json:"sql_statements"`
	PayloadByPhase     map[string]PayloadReads `json:"payload_by_phase,omitempty"`
}

// Collector is safe for concurrent package workers.
type Collector struct {
	mu       sync.Mutex
	snapshot Snapshot
}

type collectorContextKey struct{}
type phaseContextKey struct{}

// Ensure installs a collector unless the context already carries one.
func Ensure(ctx context.Context) (context.Context, *Collector) {
	if collector := FromContext(ctx); collector != nil {
		return ctx, collector
	}
	collector := &Collector{}
	return context.WithValue(ctx, collectorContextKey{}, collector), collector
}

// FromContext returns the operation collector, when instrumentation is active.
func FromContext(ctx context.Context) *Collector {
	if ctx == nil {
		return nil
	}
	collector, _ := ctx.Value(collectorContextKey{}).(*Collector)
	return collector
}

// WithPhase attributes subsequent payload reads to one deterministic phase.
func WithPhase(ctx context.Context, phase string) context.Context {
	if ctx == nil || phase == "" {
		return ctx
	}
	return context.WithValue(ctx, phaseContextKey{}, phase)
}

func phaseFromContext(ctx context.Context) string {
	if ctx == nil {
		return "unclassified"
	}
	phase, _ := ctx.Value(phaseContextKey{}).(string)
	if phase == "" {
		return "unclassified"
	}
	return phase
}

// RecordFullPackageRead records one completed whole-package content pass.
func RecordFullPackageRead(ctx context.Context, bytes int64) {
	collector := FromContext(ctx)
	if collector == nil || bytes < 0 {
		return
	}
	phase := phaseFromContext(ctx)
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.snapshot.PayloadBytesRead += bytes
	collector.snapshot.FullPackageReads++
	if collector.snapshot.PayloadByPhase == nil {
		collector.snapshot.PayloadByPhase = make(map[string]PayloadReads)
	}
	value := collector.snapshot.PayloadByPhase[phase]
	value.Bytes += bytes
	value.Full++
	collector.snapshot.PayloadByPhase[phase] = value
}

// RecordSignatureStream records one complete RPM signature-verification byte
// stream. The stream may feed multiple hashers and trust rings; callers must
// record the physical read once rather than once per consumer.
func RecordSignatureStream(ctx context.Context, bytes int64) {
	if collector := FromContext(ctx); collector != nil && bytes >= 0 {
		collector.mu.Lock()
		collector.snapshot.SignatureBytesRead += bytes
		collector.snapshot.SignatureStreams++
		collector.mu.Unlock()
	}
}

// RecordMetadataRead records bytes consumed while hashing or authenticating
// public/private metadata. Package payload bytes belong in RecordFullPackageRead.
func RecordMetadataRead(ctx context.Context, bytes int64) {
	if collector := FromContext(ctx); collector != nil && bytes >= 0 {
		collector.mu.Lock()
		collector.snapshot.MetadataBytesRead += bytes
		collector.mu.Unlock()
	}
}

// RecordMetadataTreeHash records one complete metadata-tree hash traversal.
func RecordMetadataTreeHash(ctx context.Context) {
	if collector := FromContext(ctx); collector != nil {
		collector.mu.Lock()
		collector.snapshot.MetadataTreeHashes++
		collector.mu.Unlock()
	}
}

// RecordTreeWalk records one descriptor-bound filesystem tree traversal.
func RecordTreeWalk(ctx context.Context) {
	if collector := FromContext(ctx); collector != nil {
		collector.mu.Lock()
		collector.snapshot.TreeWalks++
		collector.mu.Unlock()
	}
}

// RecordFactRows records validated SQLite package-fact rows and their BLOB
// bytes. Invalid negative deltas are ignored to keep metrics observational.
func RecordFactRows(ctx context.Context, rows, bytes int64) {
	if collector := FromContext(ctx); collector != nil && rows >= 0 && bytes >= 0 {
		collector.mu.Lock()
		collector.snapshot.FactRowsRead += rows
		collector.snapshot.FactBytesRead += bytes
		collector.mu.Unlock()
	}
}

// RecordStatHit records one file whose persisted fingerprint avoided hashing.
func RecordStatHit(ctx context.Context) {
	if collector := FromContext(ctx); collector != nil {
		collector.mu.Lock()
		collector.snapshot.StatHits++
		collector.mu.Unlock()
	}
}

// RecordStatMiss records one file selected for content verification.
func RecordStatMiss(ctx context.Context) {
	if collector := FromContext(ctx); collector != nil {
		collector.mu.Lock()
		collector.snapshot.StatMisses++
		collector.mu.Unlock()
	}
}

func RecordFactCacheHit(ctx context.Context) {
	if collector := FromContext(ctx); collector != nil {
		collector.mu.Lock()
		collector.snapshot.FactCacheHits++
		collector.mu.Unlock()
	}
}

func RecordFactCacheMiss(ctx context.Context) {
	if collector := FromContext(ctx); collector != nil {
		collector.mu.Lock()
		collector.snapshot.FactCacheMisses++
		collector.mu.Unlock()
	}
}

// RecordSQLStatements adds explicitly counted SQL statements. State hot paths
// adopt this counter incrementally rather than relying on a driver hook.
func RecordSQLStatements(ctx context.Context, statements int64) {
	if collector := FromContext(ctx); collector != nil && statements > 0 {
		collector.mu.Lock()
		collector.snapshot.SQLStatements += statements
		collector.mu.Unlock()
	}
}

// Snapshot returns an immutable copy of the current counters.
func (c *Collector) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	result := c.snapshot
	if c.snapshot.PayloadByPhase != nil {
		result.PayloadByPhase = make(map[string]PayloadReads, len(c.snapshot.PayloadByPhase))
		for phase, value := range c.snapshot.PayloadByPhase {
			result.PayloadByPhase[phase] = value
		}
	}
	return result
}
