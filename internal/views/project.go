package views

import (
	"container/heap"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/pgsty/sow/internal/manifest"
)

// ProjectionInput is one canonical view leaf. Label is used only in errors and
// must never contain secrets.
type ProjectionInput struct {
	Label  string
	Reader io.Reader
}

type projectionCursor struct {
	label  string
	reader *Reader
	entry  Entry
	index  int
}

type projectionHeap []*projectionCursor

func (h projectionHeap) Len() int { return len(h) }
func (h projectionHeap) Less(i, j int) bool {
	if h[i].entry.Path != h[j].entry.Path {
		return h[i].entry.Path < h[j].entry.Path
	}
	return h[i].index < h[j].index
}
func (h projectionHeap) Swap(i, j int)   { h[i], h[j] = h[j], h[i] }
func (h *projectionHeap) Push(value any) { *h = append(*h, value.(*projectionCursor)) }
func (h *projectionHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

// ProjectManifest merges already sorted view leaves into one sorted three-field
// content manifest with O(number-of-leaves) memory. Duplicate paths are
// deduplicated only when their bytes agree; a path collision is fatal.
func ProjectManifest(inputs []ProjectionInput, out io.Writer) (entries int64, bytes int64, err error) {
	if out == nil {
		return 0, 0, errors.New("nil projected manifest writer")
	}
	queue := make(projectionHeap, 0, len(inputs))
	for index, input := range inputs {
		if input.Reader == nil {
			return 0, 0, fmt.Errorf("projection input %d is nil", index)
		}
		cursor := &projectionCursor{label: input.Label, reader: NewReader(input.Reader), index: index}
		cursor.entry, err = cursor.reader.Next()
		if errors.Is(err, io.EOF) {
			continue
		}
		if err != nil {
			return 0, 0, fmt.Errorf("read view %s: %w", input.Label, err)
		}
		heap.Push(&queue, cursor)
	}
	for queue.Len() > 0 {
		cursor := heap.Pop(&queue).(*projectionCursor)
		canonical := cursor.entry
		labels := []string{cursor.label}
		if err := advanceProjectionCursor(&queue, cursor); err != nil {
			return entries, bytes, err
		}
		for queue.Len() > 0 && queue[0].entry.Path == canonical.Path {
			duplicate := heap.Pop(&queue).(*projectionCursor)
			if duplicate.entry.Size != canonical.Size || duplicate.entry.SHA256 != canonical.SHA256 {
				return entries, bytes, fmt.Errorf("view projection path conflict %q between %s and %s", canonical.Path, labels[0], duplicate.label)
			}
			labels = append(labels, duplicate.label)
			if err := advanceProjectionCursor(&queue, duplicate); err != nil {
				return entries, bytes, err
			}
		}
		digest, decodeErr := hex.DecodeString(canonical.SHA256)
		if decodeErr != nil || len(digest) != sha256.Size {
			return entries, bytes, fmt.Errorf("view projection has invalid SHA256 for %q", canonical.Path)
		}
		var hash [sha256.Size]byte
		copy(hash[:], digest)
		if err := manifest.WriteEntry(out, manifest.Entry{Path: canonical.Path, Size: canonical.Size, SHA256: hash}); err != nil {
			return entries, bytes, err
		}
		entries++
		bytes += canonical.Size
	}
	return entries, bytes, nil
}

func advanceProjectionCursor(queue *projectionHeap, cursor *projectionCursor) error {
	next, err := cursor.reader.Next()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read view %s: %w", cursor.label, err)
	}
	cursor.entry = next
	heap.Push(queue, cursor)
	return nil
}
