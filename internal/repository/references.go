package repository

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/pgsty/sow/internal/manifest"
)

// Reference records how many canonical paths/roots retain an immutable object.
type Reference struct {
	Object Object
	Count  uint64
}

// ReferenceSet is the union of every preservation root used for reachability:
// repo/view/snapshot/remote refs, retained history, provenance, materialized
// generations, and incomplete journals. Its zero value is ready for use.
type ReferenceSet struct {
	mu      sync.RWMutex
	objects map[Digest]Reference
}

// Add records one canonical reference to object.
func (set *ReferenceSet) Add(object Object) error {
	if err := object.validate(); err != nil {
		return err
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	if set.objects == nil {
		set.objects = make(map[Digest]Reference)
	}
	return addReference(set.objects, object, 1)
}

// AddManifest atomically merges every entry from one sorted manifest. A bad or
// truncated manifest adds no references from that manifest.
func (set *ReferenceSet) AddManifest(source io.Reader) error {
	if source == nil {
		return errors.New("nil reference manifest reader")
	}
	pending := make(map[Digest]Reference)
	reader := manifest.NewReader(source)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read reference manifest: %w", err)
		}
		object := Object{SHA256: Digest(entry.SHA256), Size: entry.Size}
		if err := addReference(pending, object, 1); err != nil {
			return err
		}
	}

	set.mu.Lock()
	defer set.mu.Unlock()
	if set.objects == nil {
		set.objects = make(map[Digest]Reference)
	}
	for digest, incoming := range pending {
		if current, ok := set.objects[digest]; ok {
			if current.Object.Size != incoming.Object.Size {
				return fmt.Errorf("SHA-256 %s has conflicting referenced sizes %d and %d", digest, current.Object.Size, incoming.Object.Size)
			}
			if math.MaxUint64-current.Count < incoming.Count {
				return fmt.Errorf("reference count overflow for %s", digest)
			}
		}
	}
	for digest, incoming := range pending {
		current := set.objects[digest]
		if current.Count == 0 {
			set.objects[digest] = incoming
			continue
		}
		current.Count += incoming.Count
		set.objects[digest] = current
	}
	return nil
}

func addReference(objects map[Digest]Reference, object Object, count uint64) error {
	if err := object.validate(); err != nil {
		return err
	}
	current, exists := objects[object.SHA256]
	if exists && current.Object.Size != object.Size {
		return fmt.Errorf("SHA-256 %s has conflicting referenced sizes %d and %d", object.HashString(), current.Object.Size, object.Size)
	}
	if exists && math.MaxUint64-current.Count < count {
		return fmt.Errorf("reference count overflow for %s", object.HashString())
	}
	if !exists {
		current.Object = object
	}
	current.Count += count
	objects[object.SHA256] = current
	return nil
}

func (set *ReferenceSet) Count(digest Digest) uint64 {
	if set == nil {
		return 0
	}
	set.mu.RLock()
	defer set.mu.RUnlock()
	return set.objects[digest].Count
}

func (set *ReferenceSet) Len() int {
	if set == nil {
		return 0
	}
	set.mu.RLock()
	defer set.mu.RUnlock()
	return len(set.objects)
}

// WriteManifest emits one deterministic entry per referenced CAS object. The
// synthetic objects/<sha256> paths carry no serving meaning; they provide a
// canonical stream for verification and audit composition without exposing
// the set's internal map or retaining duplicate reference counts.
func (set *ReferenceSet) WriteManifest(destination io.Writer) error {
	if destination == nil {
		return errors.New("nil reference manifest destination")
	}
	references := snapshotReferences(set)
	digests := make([]Digest, 0, len(references))
	for digest := range references {
		digests = append(digests, digest)
	}
	sort.Slice(digests, func(i, j int) bool { return digests[i].String() < digests[j].String() })
	for _, digest := range digests {
		reference := references[digest]
		entry := manifest.Entry{Path: "objects/" + digest.String(), Size: reference.Object.Size, SHA256: [sha256.Size]byte(digest)}
		if err := manifest.WriteEntry(destination, entry); err != nil {
			return err
		}
	}
	return nil
}

func snapshotReferences(set *ReferenceSet) map[Digest]Reference {
	result := make(map[Digest]Reference)
	if set == nil {
		return result
	}
	set.mu.RLock()
	defer set.mu.RUnlock()
	for digest, reference := range set.objects {
		result[digest] = reference
	}
	return result
}

// ReachabilityStats separates canonical references from physical CAS objects.
type ReachabilityStats struct {
	ReferenceEntries  uint64
	ReferencedObjects int64
	ReferencedBytes   int64
	PoolObjects       int64
	PoolBytes         int64
	ReachableObjects  int64
	ReachableBytes    int64
	OrphanObjects     int64
	OrphanBytes       int64
	MissingObjects    int64
	MissingBytes      int64
}

// AuditReport is a verified reachability partition. Orphans are present but
// unreachable CAS objects; Missing are canonical references absent from CAS.
type AuditReport struct {
	Stats           ReachabilityStats
	Orphans         []Object
	Missing         []Object
	OrphanSetSHA256 string
}

// Audit verifies every canonical pool object and partitions it against roots.
// It never mutates the pool.
func (s *Store) Audit(ctx context.Context, roots *ReferenceSet) (AuditReport, error) {
	return s.audit(ctx, snapshotReferences(roots))
}

func (s *Store) audit(ctx context.Context, references map[Digest]Reference) (AuditReport, error) {
	if s.readOnly {
		return s.auditReadOnly(ctx, references)
	}
	var report AuditReport
	if err := s.ensurePoolBase(); err != nil {
		return report, err
	}
	missing := make(map[Digest]Reference, len(references))
	for digest, reference := range references {
		missing[digest] = reference
		report.Stats.ReferenceEntries += reference.Count
		report.Stats.ReferencedObjects++
		if reference.Object.Size > math.MaxInt64-report.Stats.ReferencedBytes {
			return report, errors.New("referenced byte count overflow")
		}
		report.Stats.ReferencedBytes += reference.Object.Size
	}

	shards, err := os.ReadDir(s.poolRoot)
	if err != nil {
		return report, fmt.Errorf("read CAS root: %w", err)
	}
	for _, shardEntry := range shards {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}
		if shardEntry.Name() == ".tmp" {
			if err := inspectDirectory(filepath.Join(s.poolRoot, shardEntry.Name())); err != nil {
				return report, fmt.Errorf("inspect CAS temporary directory: %w", err)
			}
			continue
		}
		if !isCanonicalShard(shardEntry.Name()) {
			return report, fmt.Errorf("%w: unexpected entry %q in CAS root", ErrUnsafePath, shardEntry.Name())
		}
		shardPath := filepath.Join(s.poolRoot, shardEntry.Name())
		if err := inspectDirectory(shardPath); err != nil {
			return report, fmt.Errorf("inspect CAS shard %q: %w", shardEntry.Name(), err)
		}
		objects, err := os.ReadDir(shardPath)
		if err != nil {
			return report, fmt.Errorf("read CAS shard %q: %w", shardEntry.Name(), err)
		}
		for _, objectEntry := range objects {
			select {
			case <-ctx.Done():
				return report, ctx.Err()
			default:
			}
			digest, err := ParseDigest(objectEntry.Name())
			if err != nil || !strings.HasPrefix(objectEntry.Name(), shardEntry.Name()) {
				return report, fmt.Errorf("%w: invalid CAS coordinate %q/%q", ErrUnsafePath, shardEntry.Name(), objectEntry.Name())
			}
			objectPath := filepath.Join(shardPath, objectEntry.Name())
			info, err := os.Lstat(objectPath)
			if err != nil {
				return report, fmt.Errorf("inspect CAS object %s: %w", digest, err)
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return report, fmt.Errorf("%w: CAS coordinate %s is a symlink or special file", ErrUnsafePath, digest)
			}
			object := Object{SHA256: digest, Size: info.Size()}
			if err := s.Verify(ctx, object); err != nil {
				return report, err
			}
			report.Stats.PoolObjects++
			report.Stats.PoolBytes += object.Size
			if reference, reachable := references[digest]; reachable {
				if reference.Object.Size != object.Size {
					return report, fmt.Errorf("%w: referenced object %s expects size %d, pool has %d", ErrObjectCorrupt, digest, reference.Object.Size, object.Size)
				}
				report.Stats.ReachableObjects++
				report.Stats.ReachableBytes += object.Size
				delete(missing, digest)
			} else {
				report.Stats.OrphanObjects++
				report.Stats.OrphanBytes += object.Size
				report.Orphans = append(report.Orphans, object)
			}
		}
	}

	for _, reference := range missing {
		report.Missing = append(report.Missing, reference.Object)
		report.Stats.MissingObjects++
		report.Stats.MissingBytes += reference.Object.Size
	}
	sortObjects(report.Orphans)
	sortObjects(report.Missing)
	report.OrphanSetSHA256 = fingerprintObjects(report.Orphans)
	return report, nil
}

func isCanonicalShard(name string) bool {
	if len(name) != 2 {
		return false
	}
	for _, character := range name {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func sortObjects(objects []Object) {
	sort.Slice(objects, func(left, right int) bool {
		return objects[left].HashString() < objects[right].HashString()
	})
}

func fingerprintObjects(objects []Object) string {
	hasher := sha256.New()
	io.WriteString(hasher, "sow-orphan-set/v1\n")
	for _, object := range objects {
		fmt.Fprintf(hasher, "%s\t%d\n", object.HashString(), object.Size)
	}
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

// GCOptions defaults to a dry run. Apply additionally requires the exact
// OrphanSetSHA256 from a current dry run, making deletions both explicit and
// resistant to a changed reference/pool set.
type GCOptions struct {
	Apply                  bool
	ConfirmOrphanSetSHA256 string
}

type GCResult struct {
	Report         AuditReport
	DryRun         bool
	DeletedObjects int64
	DeletedBytes   int64
}

// GC audits first and deletes only objects explicitly partitioned as orphans.
// It never deletes unexpected, corrupt, referenced, or temporary files.
func (s *Store) GC(ctx context.Context, roots *ReferenceSet, options GCOptions) (GCResult, error) {
	if s.readOnly && options.Apply {
		return GCResult{DryRun: false}, fmt.Errorf("%w: read-only CAS cannot delete objects", ErrUnsafePath)
	}
	references := snapshotReferences(roots)
	report, err := s.audit(ctx, references)
	result := GCResult{Report: report, DryRun: !options.Apply}
	if err != nil {
		return result, err
	}
	if !options.Apply {
		return result, nil
	}
	if report.Stats.MissingObjects != 0 {
		return result, fmt.Errorf("%w: %d object(s), %d byte(s)", ErrReferencedObjectMissing, report.Stats.MissingObjects, report.Stats.MissingBytes)
	}
	if options.ConfirmOrphanSetSHA256 == "" || options.ConfirmOrphanSetSHA256 != report.OrphanSetSHA256 {
		return result, fmt.Errorf("%w: confirm orphan set %q, current set is %q", ErrGCProtection, options.ConfirmOrphanSetSHA256, report.OrphanSetSHA256)
	}

	directories := make(map[string]struct{})
	for _, object := range report.Orphans {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		if _, reachable := references[object.SHA256]; reachable || (roots != nil && roots.Count(object.SHA256) != 0) {
			return result, fmt.Errorf("%w: object %s became reachable during GC", ErrGCProtection, object.HashString())
		}
		if err := s.Verify(ctx, object); err != nil {
			return result, err
		}
		objectPath := s.ObjectPath(object.SHA256)
		if err := os.Remove(objectPath); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return result, fmt.Errorf("%w: object %s disappeared during GC", ErrGCProtection, object.HashString())
			}
			return result, fmt.Errorf("delete unreachable object %s: %w", object.HashString(), err)
		}
		result.DeletedObjects++
		result.DeletedBytes += object.Size
		directories[filepath.Dir(objectPath)] = struct{}{}
	}
	for directory := range directories {
		if err := syncDirectory(directory); err != nil {
			return result, fmt.Errorf("sync CAS shard after GC: %w", err)
		}
	}
	return result, nil
}
