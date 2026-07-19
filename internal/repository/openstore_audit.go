package repository

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
)

// auditReadOnly walks only descendants of the sha256 descriptor retained by
// OpenStore. It never reopens PoolRoot or ObjectPath, so a replacement public
// repository coordinate cannot redirect an audit into the replacement tree.
func (s *Store) auditReadOnly(ctx context.Context, references map[Digest]Reference) (AuditReport, error) {
	var report AuditReport
	if err := s.verifyReadOnlyPoolBase(); err != nil {
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

	pool, err := duplicateReadOnlyDirectory(s.readPool)
	if err != nil {
		return report, fmt.Errorf("read retained CAS root: %w", err)
	}
	defer pool.Close()
	shardEntries, err := pool.ReadDir(-1)
	if err != nil {
		return report, fmt.Errorf("read retained CAS root: %w", err)
	}
	sort.Slice(shardEntries, func(i, j int) bool { return shardEntries[i].Name() < shardEntries[j].Name() })
	for _, shardEntry := range shardEntries {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}
		name := shardEntry.Name()
		if name == ".tmp" {
			temp, _, err := openStableReadOnlyDirectoryAt(pool, name)
			if err != nil {
				return report, fmt.Errorf("inspect CAS temporary directory: %w", err)
			}
			if err := temp.Close(); err != nil {
				return report, err
			}
			continue
		}
		if !isCanonicalShard(name) {
			return report, fmt.Errorf("%w: unexpected entry %q in CAS root", ErrUnsafePath, name)
		}
		listedShard, err := lstatMaterializeAt(pool, name)
		if err != nil {
			return report, errors.Join(err, fmt.Errorf("%w: inspect CAS shard %q", ErrUnsafePath, name))
		}
		shard, shardInfo, err := openStableReadOnlyDirectoryAt(pool, name)
		var openedShard materializeFileIdentity
		var identityErr error
		if shard != nil {
			openedShard, identityErr = fstatMaterialize(shard)
		}
		if err != nil || identityErr != nil || listedShard != openedShard {
			if shard != nil {
				_ = shard.Close()
			}
			return report, errors.Join(err, identityErr, fmt.Errorf("%w: CAS shard %q changed during audit", ErrUnsafePath, name))
		}
		if s.readOnlyTestHook != nil {
			if err := s.readOnlyTestHook(readOnlyStoreTestAfterShardOpen, name); err != nil {
				_ = shard.Close()
				return report, err
			}
		}
		if err := s.auditReadOnlyShard(ctx, shard, shardInfo, pool, name, references, missing, &report); err != nil {
			_ = shard.Close()
			return report, err
		}
		if err := shard.Close(); err != nil {
			return report, err
		}
	}
	if err := s.verifyReadOnlyPoolBase(); err != nil {
		return report, err
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

func (s *Store) auditReadOnlyShard(ctx context.Context, shard *os.File, shardInfo os.FileInfo, pool *os.File, shardName string, references map[Digest]Reference, missing map[Digest]Reference, report *AuditReport) error {
	entries, err := shard.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("read CAS shard %q: %w", shardName, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		digest, err := ParseDigest(entry.Name())
		if err != nil || !strings.HasPrefix(entry.Name(), shardName) {
			return fmt.Errorf("%w: invalid CAS coordinate %q/%q", ErrUnsafePath, shardName, entry.Name())
		}
		listed, err := lstatMaterializeAt(shard, entry.Name())
		if err != nil {
			return errors.Join(err, fmt.Errorf("%w: inspect CAS coordinate %s", ErrUnsafePath, digest))
		}
		file, info, err := openMaterializeRegularAt(shard, entry.Name())
		var opened materializeFileIdentity
		var identityErr error
		if file != nil {
			opened, identityErr = fstatMaterialize(file)
		}
		if err != nil || identityErr != nil || listed != opened {
			if file != nil {
				_ = file.Close()
			}
			return errors.Join(err, identityErr, fmt.Errorf("%w: CAS coordinate %s changed during audit", ErrUnsafePath, digest))
		}
		if s.readOnlyTestHook != nil {
			if err := s.readOnlyTestHook(readOnlyStoreTestAfterObjectOpen, entry.Name()); err != nil {
				_ = file.Close()
				return err
			}
		}
		object := Object{SHA256: digest, Size: info.Size()}
		verifyErr := verifyOpenedObject(ctx, file, object)
		if verifyErr != nil {
			return errors.Join(verifyErr, file.Close())
		}
		coordinate, coordinateInfo, coordinateErr := openMaterializeRegularAt(shard, entry.Name())
		if coordinateErr != nil {
			return errors.Join(coordinateErr, file.Close(), fmt.Errorf("%w: CAS coordinate %s changed after audit", ErrUnsafePath, digest))
		}
		coordinateCloseErr := coordinate.Close()
		fileCloseErr := file.Close()
		if coordinateCloseErr != nil || fileCloseErr != nil || !os.SameFile(info, coordinateInfo) {
			return errors.Join(coordinateCloseErr, fileCloseErr, fmt.Errorf("%w: CAS coordinate %s was replaced during audit", ErrUnsafePath, digest))
		}
		report.Stats.PoolObjects++
		report.Stats.PoolBytes += object.Size
		if reference, reachable := references[digest]; reachable {
			if reference.Object.Size != object.Size {
				return fmt.Errorf("%w: referenced object %s expects size %d, pool has %d", ErrObjectCorrupt, digest, reference.Object.Size, object.Size)
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
	current, currentInfo, err := openStableReadOnlyDirectoryAt(pool, shardName)
	if err != nil {
		return fmt.Errorf("%w: CAS shard %q changed after audit: %v", ErrUnsafePath, shardName, err)
	}
	closeErr := current.Close()
	if closeErr != nil || !os.SameFile(shardInfo, currentInfo) {
		return errors.Join(closeErr, fmt.Errorf("%w: CAS shard %q was replaced during audit", ErrUnsafePath, shardName))
	}
	return nil
}

func duplicateReadOnlyDirectory(directory *os.File) (*os.File, error) {
	if directory == nil {
		return nil, fmt.Errorf("%w: retained read-only directory is closed", ErrUnsafePath)
	}
	want, err := fstatMaterialize(directory)
	if err != nil {
		return nil, err
	}
	duplicate, err := openMaterializeDirectoryAt(directory, ".")
	if err != nil {
		return nil, err
	}
	got, err := fstatMaterialize(duplicate)
	if err != nil || want != got {
		return nil, errors.Join(err, duplicate.Close(), fmt.Errorf("%w: retained directory duplication changed identity", ErrUnsafePath))
	}
	return duplicate, nil
}
