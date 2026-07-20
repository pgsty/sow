package cli

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
)

const (
	historicalConfigCacheMaxEntries        = 2
	historicalConfigCacheMaxCanonicalBytes = int64(16 << 20)
)

// historicalConfigCacheStats makes the bounded-retention contract observable
// to focused tests without exposing it as product state or a persistent cache.
type historicalConfigCacheStats struct {
	Entries        int
	CanonicalBytes int64
	PeakEntries    int
	PeakBytes      int64
	Hits           uint64
	Misses         uint64
	Loads          uint64
	Evictions      uint64
}

type historicalConfigCacheEntry struct {
	identity state.BlobIdentity
	config   *config.Config
	lru      *list.Element
}

// historicalConfigCache retains decoded canonical configurations by immutable
// Git blob identity. It deliberately accounts the canonical input size rather
// than attempting to estimate the decoded Go object graph.
type historicalConfigCache struct {
	maxEntries int
	maxBytes   int64
	entries    map[plumbing.Hash]*historicalConfigCacheEntry
	lru        *list.List
	stats      historicalConfigCacheStats
}

func newHistoricalConfigCache() *historicalConfigCache {
	return newHistoricalConfigCacheWithLimits(historicalConfigCacheMaxEntries, historicalConfigCacheMaxCanonicalBytes)
}

func newHistoricalConfigCacheWithLimits(maxEntries int, maxBytes int64) *historicalConfigCache {
	return &historicalConfigCache{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		entries:    make(map[plumbing.Hash]*historicalConfigCacheEntry),
		lru:        list.New(),
	}
}

// get returns a decoded config for identity. A miss evicts before reading or
// decoding so retained canonical inputs never temporarily exceed the budget.
// Loader and decode failures are never inserted and therefore remain retryable.
func (c *historicalConfigCache) get(identity state.BlobIdentity, load func() ([]byte, error)) (*config.Config, error) {
	if c == nil {
		return nil, errors.New("historical config cache is unavailable")
	}
	if c.maxEntries <= 0 || c.maxBytes <= 0 {
		return nil, errors.New("historical config cache has invalid limits")
	}
	if identity.Hash.IsZero() {
		return nil, errors.New("historical config identity has a zero hash")
	}
	if identity.Size < 0 {
		return nil, fmt.Errorf("historical config blob %s has negative size %d", identity.Hash, identity.Size)
	}
	if identity.Size > config.MaxConfigBytes {
		return nil, fmt.Errorf("historical config blob %s is %d bytes (maximum %d)", identity.Hash, identity.Size, config.MaxConfigBytes)
	}
	if identity.Size > c.maxBytes {
		return nil, fmt.Errorf("historical config blob %s is %d bytes (cache maximum %d)", identity.Hash, identity.Size, c.maxBytes)
	}
	if entry := c.entries[identity.Hash]; entry != nil {
		if entry.identity.Size != identity.Size {
			return nil, fmt.Errorf("historical config blob %s size identity changed from %d to %d", identity.Hash, entry.identity.Size, identity.Size)
		}
		c.lru.MoveToFront(entry.lru)
		c.stats.Hits++
		return entry.config, nil
	}

	c.stats.Misses++
	for len(c.entries) >= c.maxEntries || c.stats.CanonicalBytes+identity.Size > c.maxBytes {
		if !c.evictOldest() {
			return nil, errors.New("historical config cache cannot satisfy its configured limits")
		}
	}
	if load == nil {
		return nil, errors.New("historical config loader is nil")
	}
	body, err := load()
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != identity.Size {
		return nil, fmt.Errorf("historical config blob %s read %d bytes (expected %d)", identity.Hash, len(body), identity.Size)
	}
	actual := plumbing.ComputeHash(plumbing.BlobObject, body)
	if actual != identity.Hash {
		return nil, fmt.Errorf("historical config blob hash mismatch: expected %s, got %s", identity.Hash, actual)
	}
	decoded, err := config.Decode(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	element := c.lru.PushFront(identity.Hash)
	c.entries[identity.Hash] = &historicalConfigCacheEntry{identity: identity, config: decoded, lru: element}
	c.stats.Loads++
	c.stats.Entries = len(c.entries)
	c.stats.CanonicalBytes += identity.Size
	if c.stats.Entries > c.stats.PeakEntries {
		c.stats.PeakEntries = c.stats.Entries
	}
	if c.stats.CanonicalBytes > c.stats.PeakBytes {
		c.stats.PeakBytes = c.stats.CanonicalBytes
	}
	return decoded, nil
}

func (c *historicalConfigCache) evictOldest() bool {
	oldest := c.lru.Back()
	if oldest == nil {
		return false
	}
	hash, ok := oldest.Value.(plumbing.Hash)
	if !ok {
		return false
	}
	entry := c.entries[hash]
	if entry == nil {
		return false
	}
	delete(c.entries, hash)
	c.lru.Remove(oldest)
	c.stats.Entries = len(c.entries)
	c.stats.CanonicalBytes -= entry.identity.Size
	c.stats.Evictions++
	return true
}

func (c *historicalConfigCache) snapshot() historicalConfigCacheStats {
	if c == nil {
		return historicalConfigCacheStats{}
	}
	return c.stats
}

// readHistoricalConfigBlob reopens an immutable object by the recorded blob
// identity. Declared size, limit+1 streaming size, and hash are independently
// checked across this function and historicalConfigCache.get.
func readHistoricalConfigBlob(repository *git.Repository, identity state.BlobIdentity) ([]byte, error) {
	if repository == nil {
		return nil, errors.New("historical config Git repository is unavailable")
	}
	if identity.Hash.IsZero() {
		return nil, errors.New("historical config identity has a zero hash")
	}
	if identity.Size < 0 || identity.Size > config.MaxConfigBytes {
		return nil, fmt.Errorf("historical config blob %s has invalid size %d", identity.Hash, identity.Size)
	}
	blob, err := repository.BlobObject(identity.Hash)
	if err != nil {
		return nil, fmt.Errorf("open historical config blob %s: %w", identity.Hash, err)
	}
	if blob.Size != identity.Size {
		return nil, fmt.Errorf("historical config blob %s declared size changed from %d to %d", identity.Hash, identity.Size, blob.Size)
	}
	reader, err := blob.Reader()
	if err != nil {
		return nil, fmt.Errorf("open historical config blob %s reader: %w", identity.Hash, err)
	}
	body, readErr := io.ReadAll(io.LimitReader(reader, config.MaxConfigBytes+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		return nil, fmt.Errorf("read historical config blob %s: %w", identity.Hash, errors.Join(readErr, closeErr))
	}
	if len(body) > config.MaxConfigBytes {
		return nil, fmt.Errorf("historical config blob %s exceeds %d-byte safety limit", identity.Hash, config.MaxConfigBytes)
	}
	if int64(len(body)) != identity.Size {
		return nil, fmt.Errorf("historical config blob %s read %d bytes (expected %d)", identity.Hash, len(body), identity.Size)
	}
	return body, nil
}

// detachHistoricalRepository keeps only one independently owned repository
// contract after the decoded configuration is evicted. A plain Repo assignment
// would retain slice backing arrays and nested maps from that decoded object,
// making the cache's entry limit understate the live heap.
func detachHistoricalRepository(repo config.Repo) config.Repo {
	result := repo
	result.Arches = append([]string(nil), repo.Arches...)
	result.Include = append([]string(nil), repo.Include...)
	result.Exclude = append([]string(nil), repo.Exclude...)
	result.PublishTargets = append([]string(nil), repo.PublishTargets...)
	if repo.Active != nil {
		active := *repo.Active
		result.Active = &active
	}
	if repo.APT != nil {
		apt := *repo.APT
		apt.Suites = append([]string(nil), repo.APT.Suites...)
		apt.Components = append([]string(nil), repo.APT.Components...)
		apt.SuiteComponents = detachHistoricalStringSlices(repo.APT.SuiteComponents)
		apt.SuiteLifecycle = detachHistoricalStrings(repo.APT.SuiteLifecycle)
		result.APT = &apt
	}
	if repo.YUM != nil {
		yum := *repo.YUM
		result.YUM = &yum
	}
	if repo.Asset != nil {
		asset := *repo.Asset
		asset.MutablePaths = append([]string(nil), repo.Asset.MutablePaths...)
		asset.RootKeys = append([]string(nil), repo.Asset.RootKeys...)
		result.Asset = &asset
	}
	return result
}

func detachHistoricalStringSlices(values map[string][]string) map[string][]string {
	if values == nil {
		return nil
	}
	result := make(map[string][]string, len(values))
	for key, items := range values {
		result[key] = append([]string(nil), items...)
	}
	return result
}

func detachHistoricalStrings(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
