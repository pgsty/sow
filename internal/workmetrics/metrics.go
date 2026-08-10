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
	PayloadBytesRead int64                   `json:"payload_bytes_read"`
	FullPackageReads int64                   `json:"full_package_reads"`
	StatHits         int64                   `json:"stat_hits"`
	StatMisses       int64                   `json:"stat_misses"`
	FactCacheHits    int64                   `json:"fact_cache_hits"`
	FactCacheMisses  int64                   `json:"fact_cache_misses"`
	SQLStatements    int64                   `json:"sql_statements"`
	PayloadByPhase   map[string]PayloadReads `json:"payload_by_phase,omitempty"`
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
