package workmetrics

import (
	"context"
	"sync"
	"testing"
)

func TestCollectorAggregatesConcurrentPayloadReads(t *testing.T) {
	ctx, collector := Ensure(context.Background())
	ctx = WithPhase(ctx, "render_rpm")
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			RecordFullPackageRead(ctx, 1024)
		}()
	}
	workers.Wait()
	RecordStatHit(ctx)
	RecordStatMiss(ctx)
	RecordFactCacheHit(ctx)
	RecordFactCacheMiss(ctx)
	RecordSQLStatements(ctx, 3)

	got := collector.Snapshot()
	if got.PayloadBytesRead != 8*1024 || got.FullPackageReads != 8 || got.StatHits != 1 || got.StatMisses != 1 || got.FactCacheHits != 1 || got.FactCacheMisses != 1 || got.SQLStatements != 3 {
		t.Fatalf("snapshot=%#v", got)
	}
	if phase := got.PayloadByPhase["render_rpm"]; phase.Bytes != 8*1024 || phase.Full != 8 {
		t.Fatalf("phase=%#v", phase)
	}
	got.PayloadByPhase["render_rpm"] = PayloadReads{}
	if collector.Snapshot().PayloadByPhase["render_rpm"].Full != 8 {
		t.Fatal("snapshot returned a mutable phase map")
	}
}
