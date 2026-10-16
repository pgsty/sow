// This template is overlaid only by check-os-io.py; normal go list ignores testdata.
package managed

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/pgsty/sow/internal/workmetrics"
)

type sowCheckIOBytes struct {
	Read    int64
	ReadAt  int64
	Problem string
}

// Observe only Check, after fixture construction. FileInfo identity also covers
// hardlink aliases; path spellings and workmetrics never decide byte attribution.
func sowCheckObserve(t *testing.T, root string, size int) func() sowCheckIOBytes {
	t.Helper()
	target, err := os.Open(filepath.Join(root, "repo", "pool", "s", "sow-check-facts", "sow-check-facts_1.0-1_all.deb"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := target.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != 1050816 || size != 1050816 {
		_ = target.Close()
		t.Fatalf("Check OS I/O fixture changed: info=%v size=%d err=%v", info, size, err)
	}
	var mu sync.Mutex
	var actual sowCheckIOBytes
	registered := os.SOWCheckSetIOObserver(func(file *os.File, kind string, n int64) {
		mu.Lock()
		defer mu.Unlock()
		// ReadFrom's receiver may be the destination, so reject every handled
		// transfer in this read-only window, even if its receiver is not target.
		if kind == "ReadFrom" || kind == "WriteTo" {
			actual.Problem = fmt.Sprintf("unexpected handled %s (%d bytes)", kind, n)
			return
		}
		identity, err := file.Stat()
		if err != nil {
			actual.Problem = "observer descriptor stat: " + err.Error()
			return
		}
		if !os.SameFile(identity, info) {
			return
		}
		switch kind {
		case "Read":
			actual.Read += n
		case "ReadAt":
			actual.ReadAt += n
		default:
			actual.Problem = "unknown observer method: " + kind
		}
	})
	if !registered {
		_ = target.Close()
		t.Fatal("Check OS I/O observer already registered")
	}
	var once sync.Once
	stop := func() sowCheckIOBytes {
		once.Do(func() {
			os.SOWCheckSetIOObserver(nil)
			mu.Lock()
			defer mu.Unlock()
			if err := target.Close(); err != nil {
				actual.Problem = "observer target close: " + err.Error()
			}
		})
		mu.Lock()
		defer mu.Unlock()
		return actual
	}
	t.Cleanup(func() { stop() })
	return stop
}

func sowCheckAssert(t *testing.T, name string, actual sowCheckIOBytes, metrics workmetrics.Snapshot) {
	t.Helper()
	record, err := json.Marshal(map[string]any{
		"window": name, "read": actual.Read, "read_at": actual.ReadAt,
		"logical_full": metrics.FullPackageReads, "logical_bytes": metrics.PayloadBytesRead,
		"problem": actual.Problem,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SOW_CHECK_OS_IO %s", record)
	if actual.Problem != "" {
		t.Fatal(actual.Problem)
	}
	wantHeader := int64(0)
	if name == "missing facts" {
		wantHeader = 2428 // Fixed for this fixture/parser; never learn from output.
	} else if name != "cached facts" {
		t.Fatalf("unknown Check OS I/O window: %q", name)
	}
	if actual.Read != 1050816 || actual.ReadAt != wantHeader {
		t.Fatalf("SOW_CHECK_OS_IO_BUDGET %s", name)
	}
}
