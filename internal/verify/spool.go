package verify

import (
	"bufio"
	"container/heap"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/pgsty/sow/internal/manifest"
)

// manifestSpool is a bounded-memory external sorter used to turn package-index
// references into the same canonical stream as a filesystem scan.
type manifestSpool struct {
	dir       string
	chunkSize int
	chunk     []manifest.Entry
	runs      []string
	finished  string
}

func newManifestSpool(tempDir string, chunkSize int) (*manifestSpool, error) {
	if chunkSize <= 0 {
		chunkSize = 4096
	}
	dir, err := os.MkdirTemp(tempDir, "sow-verify-sort-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &manifestSpool{dir: dir, chunkSize: chunkSize, chunk: make([]manifest.Entry, 0, chunkSize)}, nil
}

func (s *manifestSpool) Add(entry manifest.Entry) error {
	if s.finished != "" {
		return errors.New("manifest spool is already finished")
	}
	if err := entry.Validate(); err != nil {
		return err
	}
	s.chunk = append(s.chunk, entry)
	if len(s.chunk) >= s.chunkSize {
		return s.flush()
	}
	return nil
}

func (s *manifestSpool) flush() error {
	if len(s.chunk) == 0 {
		return nil
	}
	sort.Slice(s.chunk, func(i, j int) bool { return s.chunk[i].Path < s.chunk[j].Path })
	f, err := os.CreateTemp(s.dir, "run-*.tsv")
	if err != nil {
		return err
	}
	name := f.Name()
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(name)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	writer := bufio.NewWriterSize(f, 256*1024)
	for index, entry := range s.chunk {
		if index != 0 && entry.Path == s.chunk[index-1].Path {
			if entry.Size != s.chunk[index-1].Size || entry.SHA256 != s.chunk[index-1].SHA256 {
				return fmt.Errorf("conflicting package references for %q", entry.Path)
			}
			continue
		}
		if err := manifest.WriteEntry(writer, entry); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	keep = true
	s.runs = append(s.runs, name)
	s.chunk = s.chunk[:0]
	return nil
}

func (s *manifestSpool) Finish(ctx context.Context) (string, error) {
	if s.finished != "" {
		return s.finished, nil
	}
	if err := s.flush(); err != nil {
		return "", err
	}
	output := filepath.Join(s.dir, "manifest.tsv")
	if len(s.runs) == 0 {
		f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return "", err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		s.finished = output
		return output, nil
	}
	const mergeFanIn = 64
	runs := append([]string(nil), s.runs...)
	for pass := 0; len(runs) > mergeFanIn; pass++ {
		next := make([]string, 0, (len(runs)+mergeFanIn-1)/mergeFanIn)
		for start := 0; start < len(runs); start += mergeFanIn {
			end := start + mergeFanIn
			if end > len(runs) {
				end = len(runs)
			}
			intermediate := filepath.Join(s.dir, fmt.Sprintf("merge-%03d-%06d.tsv", pass, len(next)))
			if err := mergeManifestRuns(ctx, runs[start:end], intermediate); err != nil {
				return "", err
			}
			next = append(next, intermediate)
		}
		for _, run := range runs {
			_ = os.Remove(run)
		}
		runs = next
	}
	if err := mergeManifestRuns(ctx, runs, output); err != nil {
		return "", err
	}
	s.finished = output
	return output, nil
}

func (s *manifestSpool) Close() error {
	if s == nil || s.dir == "" {
		return nil
	}
	err := os.RemoveAll(s.dir)
	s.dir = ""
	return err
}

type spoolCursor struct {
	entry  manifest.Entry
	reader *manifest.Reader
	file   *os.File
	index  int
}

type spoolHeap []*spoolCursor

func (h spoolHeap) Len() int { return len(h) }
func (h spoolHeap) Less(i, j int) bool {
	if h[i].entry.Path != h[j].entry.Path {
		return h[i].entry.Path < h[j].entry.Path
	}
	return h[i].index < h[j].index
}
func (h spoolHeap) Swap(i, j int)   { h[i], h[j] = h[j], h[i] }
func (h *spoolHeap) Push(value any) { *h = append(*h, value.(*spoolCursor)) }
func (h *spoolHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

func mergeManifestRuns(ctx context.Context, runs []string, output string) error {
	out, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = out.Close()
		if !committed {
			_ = os.Remove(output)
		}
	}()
	queue := make(spoolHeap, 0, len(runs))
	for index, run := range runs {
		f, err := os.Open(run)
		if err != nil {
			closeSpoolCursors(queue)
			return err
		}
		reader := manifest.NewReader(f)
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			_ = f.Close()
			continue
		}
		if err != nil {
			_ = f.Close()
			closeSpoolCursors(queue)
			return err
		}
		queue = append(queue, &spoolCursor{entry: entry, reader: reader, file: f, index: index})
	}
	heap.Init(&queue)
	writer := bufio.NewWriterSize(out, 256*1024)
	var previous *manifest.Entry
	for queue.Len() != 0 {
		if err := ctx.Err(); err != nil {
			closeSpoolCursors(queue)
			return err
		}
		cursor := heap.Pop(&queue).(*spoolCursor)
		entry := cursor.entry
		if previous != nil && previous.Path == entry.Path {
			if previous.Size != entry.Size || previous.SHA256 != entry.SHA256 {
				_ = cursor.file.Close()
				closeSpoolCursors(queue)
				return fmt.Errorf("conflicting package references for %q", entry.Path)
			}
		} else {
			if err := manifest.WriteEntry(writer, entry); err != nil {
				_ = cursor.file.Close()
				closeSpoolCursors(queue)
				return err
			}
			copyEntry := entry
			previous = &copyEntry
		}
		next, err := cursor.reader.Next()
		switch {
		case errors.Is(err, io.EOF):
			if err := cursor.file.Close(); err != nil {
				closeSpoolCursors(queue)
				return err
			}
		case err != nil:
			_ = cursor.file.Close()
			closeSpoolCursors(queue)
			return err
		default:
			cursor.entry = next
			heap.Push(&queue, cursor)
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	committed = true
	return nil
}

func closeSpoolCursors(queue spoolHeap) {
	for _, cursor := range queue {
		_ = cursor.file.Close()
	}
}
