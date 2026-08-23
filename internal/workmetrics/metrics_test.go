package workmetrics

import (
	"context"
	"reflect"
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
	RecordSignatureStream(ctx, 2048)
	RecordMetadataRead(ctx, 512)
	RecordMetadataTreeHash(ctx)
	RecordTreeWalk(ctx)
	RecordFactRows(ctx, 2, 768)
	RecordSQLStatements(ctx, 3)

	got := collector.Snapshot()
	if got.PayloadBytesRead != 8*1024 || got.FullPackageReads != 8 ||
		got.SignatureBytesRead != 2048 || got.SignatureStreams != 1 ||
		got.MetadataBytesRead != 512 || got.MetadataTreeHashes != 1 || got.TreeWalks != 1 ||
		got.FactRowsRead != 2 || got.FactBytesRead != 768 ||
		got.StatHits != 1 || got.StatMisses != 1 || got.FactCacheHits != 1 || got.FactCacheMisses != 1 || got.SQLStatements != 3 {
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

func TestCollectorRejectsInvalidMetricDeltas(t *testing.T) {
	ctx, collector := Ensure(context.Background())
	RecordSignatureStream(ctx, -1)
	RecordMetadataRead(ctx, -1)
	RecordFactRows(ctx, -1, 10)
	RecordFactRows(ctx, 1, -10)
	RecordSQLStatements(ctx, -1)
	if got := collector.Snapshot(); !reflect.DeepEqual(got, Snapshot{}) {
		t.Fatalf("invalid deltas changed snapshot: %#v", got)
	}
}
