package catalog

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	crpm "github.com/cavaliergopher/rpm"
	"github.com/go-git/go-git/v5/plumbing"
	_ "modernc.org/sqlite"
	"pault.ag/go/debian/dependency"
	debianversion "pault.ag/go/debian/version"
)

func openReadOnly(ctx context.Context, stateDir string) (*sql.DB, error) {
	dsn := (&url.URL{Scheme: "file", Path: Path(stateDir)}).String() + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `PRAGMA query_only=ON; PRAGMA foreign_keys=ON;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// Version reads the cache schema in SQLite read-only mode.
func Version(ctx context.Context, stateDir string) (int, error) {
	db, err := openReadOnly(ctx, stateDir)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var raw string
	if err := db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='schema_version'`).Scan(&raw); err != nil {
		return 0, err
	}
	return strconv.Atoi(raw)
}

// CanonicalHead returns the exact canonical Git HEAD from which the disposable
// SQLite projection was rebuilt. Row-only manifest comparison cannot detect a
// stale snapshot, view-membership, provenance, or ref-only cache after a
// canonical commit, so callers must bind the cache to this identity as well.
func CanonicalHead(ctx context.Context, stateDir string) (plumbing.Hash, error) {
	db, err := openReadOnly(ctx, stateDir)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	defer db.Close()
	var raw string
	if err := db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='canonical_head'`).Scan(&raw); err != nil {
		return plumbing.ZeroHash, err
	}
	hash := plumbing.NewHash(raw)
	if hash.IsZero() || hash.String() != raw {
		return plumbing.ZeroHash, errors.New("catalog: canonical head identity is invalid")
	}
	return hash, nil
}

// AdvanceCanonicalHead updates only the exact canonical Git HEAD identity of
// an otherwise unchanged projection. Callers must prove that every projection
// input (config, manifests, views, snapshots, provenance, package bytes, and
// their SOW refs) is unchanged between expected and current. A missing,
// malformed, stale, or wrong-schema cache fails closed so the caller can
// rebuild it from canonical state instead.
//
// The cache remains a disposable read-only artifact: the database is opened
// with mode=rw (never created), the compare-and-set runs under a FULL-sync
// SQLite transaction, and permissions are restored to 0444 on every path.
func AdvanceCanonicalHead(ctx context.Context, stateDir string, expected, current plumbing.Hash) (resultErr error) {
	if ctx == nil {
		return errors.New("catalog: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if expected.IsZero() || current.IsZero() {
		return errors.New("catalog: canonical head advance requires non-zero identities")
	}
	cachePath := Path(stateDir)
	info, err := os.Lstat(cachePath)
	if err != nil {
		return fmt.Errorf("catalog: inspect cache before head advance: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("catalog: cache is not a regular non-symlink file")
	}
	if err := os.Chmod(cachePath, 0o600); err != nil {
		return fmt.Errorf("catalog: make cache writable for head advance: %w", err)
	}
	defer func() {
		if err := os.Chmod(cachePath, 0o444); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("catalog: restore read-only cache permissions: %w", err))
		}
	}()

	dsn := (&url.URL{Scheme: "file", Path: cachePath}).String() + "?mode=rw"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("catalog: open cache for head advance: %w", err)
	}
	db.SetMaxOpenConns(1)
	defer func() {
		resultErr = errors.Join(resultErr, db.Close())
	}()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("catalog: open existing cache for head advance: %w", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;`); err != nil {
		return fmt.Errorf("catalog: configure head advance: %w", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("catalog: begin head advance: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, tx.Rollback())
		}
	}()
	var schemaRaw, headRaw string
	if err := tx.QueryRowContext(ctx, `SELECT
 (SELECT value FROM meta WHERE key='schema_version'),
 (SELECT value FROM meta WHERE key='canonical_head')`).Scan(&schemaRaw, &headRaw); err != nil {
		return fmt.Errorf("catalog: read cache identity before head advance: %w", err)
	}
	schema, err := strconv.Atoi(schemaRaw)
	if err != nil || schema != SchemaVersion {
		return errors.Join(err, fmt.Errorf("catalog: cache schema is %q, expected %d", schemaRaw, SchemaVersion))
	}
	if headRaw == current.String() {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("catalog: commit idempotent head advance: %w", err)
		}
		committed = true
		return nil
	}
	if headRaw != expected.String() {
		return fmt.Errorf("catalog: cache head is %s, expected %s before advance to %s", headRaw, expected, current)
	}
	result, err := tx.ExecContext(ctx, `UPDATE meta SET value=? WHERE key='canonical_head' AND value=?`, current.String(), expected.String())
	if err != nil {
		return fmt.Errorf("catalog: update canonical head: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return errors.Join(err, fmt.Errorf("catalog: canonical head compare-and-set changed %d rows", rows))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("catalog: commit canonical head advance: %w", err)
	}
	committed = true
	if err := syncCatalogHeadAdvance(cachePath); err != nil {
		return err
	}
	return nil
}

func syncCatalogHeadAdvance(cachePath string) error {
	file, err := os.Open(cachePath)
	if err != nil {
		return fmt.Errorf("catalog: open advanced cache for sync: %w", err)
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	directory, dirErr := os.Open(filepath.Dir(cachePath))
	if dirErr == nil {
		dirErr = errors.Join(directory.Sync(), directory.Close())
	}
	return errors.Join(syncErr, closeErr, dirErr)
}

func Statistics(ctx context.Context, stateDir string) (Stats, error) {
	db, err := openReadOnly(ctx, stateDir)
	if err != nil {
		return Stats{}, err
	}
	defer db.Close()
	var result Stats
	err = db.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM files),
 (SELECT count(*) FROM packages),
 (SELECT count(*) FROM memberships),
 (SELECT count(*) FROM relations),
 (SELECT count(*) FROM provenance)`).Scan(
		&result.Files, &result.Packages, &result.Memberships, &result.Relations, &result.Provenance,
	)
	return result, err
}

// OpenManifestProjection streams one repository's cached path/size/SHA256
// rows in canonical manifest order. The returned reader owns both rows and the
// read-only database handle and must be closed.
func OpenManifestProjection(ctx context.Context, stateDir, repo string) (io.ReadCloser, error) {
	db, err := openReadOnly(ctx, stateDir)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT path,size,sha256 FROM files WHERE repo=? ORDER BY path`, repo)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &manifestProjection{db: db, rows: rows}, nil
}

type manifestProjection struct {
	db      *sql.DB
	rows    *sql.Rows
	pending bytes.Reader
	done    bool
	err     error
}

func (r *manifestProjection) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	for r.pending.Len() == 0 && !r.done {
		if !r.rows.Next() {
			r.done = true
			r.err = r.rows.Err()
			break
		}
		var path, digest string
		var size int64
		if err := r.rows.Scan(&path, &size, &digest); err != nil {
			r.done = true
			r.err = err
			break
		}
		r.pending.Reset([]byte(fmt.Sprintf("%s\t%d\t%s\n", path, size, digest)))
	}
	if r.pending.Len() != 0 {
		return r.pending.Read(destination)
	}
	if r.err != nil {
		err := r.err
		r.err = nil
		return 0, err
	}
	return 0, io.EOF
}

func (r *manifestProjection) Close() error {
	if r.rows == nil && r.db == nil {
		return nil
	}
	var err error
	if r.rows != nil {
		err = r.rows.Close()
		r.rows = nil
	}
	if r.db != nil {
		err = errors.Join(err, r.db.Close())
		r.db = nil
	}
	return err
}

var ErrPackageNotFound = errors.New("catalog: package not found in scope")

// Scope identifies one installable leaf. Kind defaults to view; snapshot is
// also supported so immutable historical refs remain queryable.
type Scope struct {
	Kind string
	Name string
	Repo string
	OS   string
	Arch string
}

// MembershipCount returns the exact number of package memberships projected
// for one canonical view or snapshot scope. It is primarily an audit primitive
// for proving that ref-only canonical mutations reached the rebuildable cache.
func MembershipCount(ctx context.Context, stateDir string, scope Scope) (int64, error) {
	if ctx == nil {
		return 0, errors.New("catalog: nil context")
	}
	normalized, err := scope.validate()
	if err != nil {
		return 0, err
	}
	db, err := openReadOnly(ctx, stateDir)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var count int64
	err = db.QueryRowContext(ctx, `SELECT count(*) FROM memberships WHERE scope_kind=? AND scope=? AND repo=? AND os=? AND arch=?`,
		normalized.Kind, normalized.Name, normalized.Repo, normalized.OS, normalized.Arch).Scan(&count)
	return count, err
}

func (s Scope) validate() (Scope, error) {
	if s.Kind == "" {
		s.Kind = "view"
	}
	if s.Kind != "view" && s.Kind != "snapshot" {
		return s, fmt.Errorf("catalog: scope kind must be view or snapshot")
	}
	for field, value := range map[string]string{"name": s.Name, "repo": s.Repo, "os": s.OS, "arch": s.Arch} {
		if value == "" || strings.ContainsAny(value, "\x00\t\r\n") {
			return s, fmt.Errorf("catalog: scope %s is empty or unsafe", field)
		}
	}
	return s, nil
}

type PackageSelector struct {
	Name    string
	Version string
}

// PackageRecord is the package/version/architecture/source projection plus
// its exact repo/view/pool membership.
type PackageRecord struct {
	SHA256  string
	Format  string
	Name    string
	Version string
	Arch    string
	Source  string
	Size    int64
	Scope   Scope
	Path    string
	Pool    string
}

type RelationAlternative struct {
	Name          string
	Operator      string
	Version       string
	ArchQualifier string
}

type UnresolvedRelation struct {
	FromSHA256   string
	FromPackage  string
	Kind         string
	Group        int
	Alternatives []RelationAlternative
}

type ProvenanceRecord struct {
	ReceiptID      string
	ArtifactSHA256 string
	Format         string
	Kind           string
	Repo           string
	SourcePath     string
	Pool           string
	UpstreamURL    string
	ObservedAt     string
}

// ProvenanceProjection streams the disposable cache's legacy provenance rows
// without loading a repository-sized receipt set into memory. Rows are ordered
// by source path and receipt identity so callers can compare a deterministic
// projection against the canonical JSONL ledger.
type ProvenanceProjection struct {
	db   *sql.DB
	rows *sql.Rows
}

// OpenLegacyProvenanceProjection opens the complete legacy provenance
// projection for one repository. The caller must close the returned stream.
func OpenLegacyProvenanceProjection(ctx context.Context, stateDir, repo string) (*ProvenanceProjection, error) {
	if ctx == nil {
		return nil, errors.New("catalog: nil context")
	}
	if repo == "" || strings.ContainsAny(repo, "\x00\t\r\n") {
		return nil, errors.New("catalog: provenance repository is empty or unsafe")
	}
	db, err := openReadOnly(ctx, stateDir)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT receipt_id,artifact_sha256,format,kind,repo,source_path,pool,upstream_url,observed_at
FROM provenance WHERE kind='legacy' AND repo=? ORDER BY source_path,receipt_id`, repo)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &ProvenanceProjection{db: db, rows: rows}, nil
}

// Next returns the next projected receipt or io.EOF.
func (p *ProvenanceProjection) Next() (ProvenanceRecord, error) {
	var record ProvenanceRecord
	if p == nil || p.rows == nil {
		return record, io.EOF
	}
	if !p.rows.Next() {
		if err := p.rows.Err(); err != nil {
			return record, err
		}
		return record, io.EOF
	}
	if err := p.rows.Scan(&record.ReceiptID, &record.ArtifactSHA256, &record.Format, &record.Kind, &record.Repo,
		&record.SourcePath, &record.Pool, &record.UpstreamURL, &record.ObservedAt); err != nil {
		return ProvenanceRecord{}, err
	}
	return record, nil
}

// Close releases both the SQLite rows and their read-only database handle.
func (p *ProvenanceProjection) Close() error {
	if p == nil {
		return nil
	}
	var err error
	if p.rows != nil {
		err = p.rows.Close()
		p.rows = nil
	}
	if p.db != nil {
		err = errors.Join(err, p.db.Close())
		p.db = nil
	}
	return err
}

type ClosureQuery struct {
	Scope Scope
	Roots []PackageSelector
}

type ClosureResult struct {
	Packages   []PackageRecord
	Unresolved []UnresolvedRelation
	Provenance []ProvenanceRecord
}

// DependencyClosure resolves required relations only: Depends/Pre-Depends for
// DEB and Requires for RPM. Alternatives retain package order; resolution picks
// the first satisfiable alternative and the newest format-native version in the
// requested leaf. A SHA visited set makes cycles finite. Unresolved capabilities
// are evidence, not silently treated as satisfied.
func DependencyClosure(ctx context.Context, stateDir string, query ClosureQuery) (ClosureResult, error) {
	if ctx == nil {
		return ClosureResult{}, errors.New("catalog: nil context")
	}
	scope, err := query.Scope.validate()
	if err != nil {
		return ClosureResult{}, err
	}
	if len(query.Roots) == 0 {
		return ClosureResult{}, errors.New("catalog: dependency closure requires at least one root")
	}
	db, err := openReadOnly(ctx, stateDir)
	if err != nil {
		return ClosureResult{}, err
	}
	defer db.Close()

	queue := make([]PackageRecord, 0, len(query.Roots))
	for _, root := range query.Roots {
		if root.Name == "" || strings.ContainsAny(root.Name, "\x00\t\r\n") {
			return ClosureResult{}, errors.New("catalog: root package name is empty or unsafe")
		}
		candidates, err := loadCandidates(ctx, db, scope, root.Name, false)
		if err != nil {
			return ClosureResult{}, err
		}
		if root.Version != "" {
			filtered := candidates[:0]
			for _, candidate := range candidates {
				if candidate.Package.Version == root.Version {
					filtered = append(filtered, candidate)
				}
			}
			candidates = filtered
		}
		selected, found, err := chooseCandidate(candidates, "", "")
		if err != nil {
			return ClosureResult{}, err
		}
		if !found {
			return ClosureResult{}, fmt.Errorf("%w: %s %s in %s/%s/%s/%s", ErrPackageNotFound, root.Name, root.Version, scope.Name, scope.Repo, scope.OS, scope.Arch)
		}
		queue = append(queue, selected.Package)
	}

	visited := make(map[string]struct{})
	var result ClosureResult
	for len(queue) != 0 {
		if err := ctx.Err(); err != nil {
			return ClosureResult{}, err
		}
		current := queue[0]
		queue = queue[1:]
		if _, exists := visited[current.SHA256]; exists {
			continue
		}
		visited[current.SHA256] = struct{}{}
		result.Packages = append(result.Packages, current)
		groups, err := requiredRelationGroups(ctx, db, current, scope.Arch)
		if err != nil {
			return ClosureResult{}, err
		}
		for _, group := range groups {
			resolved := false
			for _, alternative := range group.alternatives {
				candidates, err := loadCandidates(ctx, db, scope, alternative.Name, true)
				if err != nil {
					return ClosureResult{}, err
				}
				selected, found, err := chooseCandidate(candidates, alternative.Operator, alternative.Version)
				if err != nil {
					return ClosureResult{}, err
				}
				if found {
					queue = append(queue, selected.Package)
					resolved = true
					break
				}
			}
			if !resolved {
				result.Unresolved = append(result.Unresolved, UnresolvedRelation{
					FromSHA256: current.SHA256, FromPackage: current.Name,
					Kind: group.kind, Group: group.number,
					Alternatives: append([]RelationAlternative(nil), group.alternatives...),
				})
			}
		}
	}
	sort.Slice(result.Packages, func(i, j int) bool {
		left, right := result.Packages[i], result.Packages[j]
		if left.Format != right.Format {
			return left.Format < right.Format
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Version != right.Version {
			return left.Version < right.Version
		}
		if left.Arch != right.Arch {
			return left.Arch < right.Arch
		}
		return left.SHA256 < right.SHA256
	})
	for _, pkg := range result.Packages {
		receipts, err := artifactProvenance(ctx, db, pkg.SHA256)
		if err != nil {
			return ClosureResult{}, err
		}
		result.Provenance = append(result.Provenance, receipts...)
	}
	return result, nil
}

type candidate struct {
	Package      PackageRecord
	direct       bool
	matchVersion string
}

func loadCandidates(ctx context.Context, db *sql.DB, scope Scope, name string, includeProviders bool) ([]candidate, error) {
	rows, err := db.QueryContext(ctx, `SELECT p.sha256,p.format,p.name,p.version,p.arch,p.source,p.size,m.path,m.pool
FROM packages p JOIN memberships m ON m.sha256=p.sha256
WHERE m.scope_kind=? AND m.scope=? AND m.repo=? AND m.os=? AND m.arch=? AND p.name=?
ORDER BY p.sha256,m.path`, scope.Kind, scope.Name, scope.Repo, scope.OS, scope.Arch, name)
	if err != nil {
		return nil, err
	}
	result, err := scanCandidates(rows, scope, true, "")
	if err != nil || !includeProviders {
		return result, err
	}
	rows, err = db.QueryContext(ctx, `SELECT p.sha256,p.format,p.name,p.version,p.arch,p.source,p.size,m.path,m.pool,r.version
FROM relations r JOIN packages p ON p.sha256=r.sha256 JOIN memberships m ON m.sha256=p.sha256
WHERE m.scope_kind=? AND m.scope=? AND m.repo=? AND m.os=? AND m.arch=? AND r.kind='provides' AND r.name=?
ORDER BY p.sha256,m.path,r.relation_group,r.alternative`, scope.Kind, scope.Name, scope.Repo, scope.OS, scope.Arch, name)
	if err != nil {
		return nil, err
	}
	provided, err := scanProviderCandidates(rows, scope)
	if err != nil {
		return nil, err
	}
	bySHA := make(map[string]int, len(result)+len(provided))
	for index, value := range result {
		bySHA[value.Package.SHA256] = index
	}
	for _, value := range provided {
		if _, exists := bySHA[value.Package.SHA256]; !exists {
			bySHA[value.Package.SHA256] = len(result)
			result = append(result, value)
		}
	}
	return result, nil
}

func scanCandidates(rows *sql.Rows, scope Scope, direct bool, matchVersion string) ([]candidate, error) {
	defer rows.Close()
	var result []candidate
	seen := make(map[string]struct{})
	for rows.Next() {
		var value candidate
		value.Package.Scope = scope
		if err := rows.Scan(&value.Package.SHA256, &value.Package.Format, &value.Package.Name, &value.Package.Version, &value.Package.Arch, &value.Package.Source, &value.Package.Size, &value.Package.Path, &value.Package.Pool); err != nil {
			return nil, err
		}
		if _, exists := seen[value.Package.SHA256]; exists {
			continue
		}
		seen[value.Package.SHA256] = struct{}{}
		value.direct, value.matchVersion = direct, matchVersion
		if direct {
			value.matchVersion = value.Package.Version
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func scanProviderCandidates(rows *sql.Rows, scope Scope) ([]candidate, error) {
	defer rows.Close()
	var result []candidate
	seen := make(map[string]struct{})
	for rows.Next() {
		var value candidate
		value.Package.Scope = scope
		if err := rows.Scan(&value.Package.SHA256, &value.Package.Format, &value.Package.Name, &value.Package.Version, &value.Package.Arch, &value.Package.Source, &value.Package.Size, &value.Package.Path, &value.Package.Pool, &value.matchVersion); err != nil {
			return nil, err
		}
		if _, exists := seen[value.Package.SHA256]; exists {
			continue
		}
		seen[value.Package.SHA256] = struct{}{}
		result = append(result, value)
	}
	return result, rows.Err()
}

func chooseCandidate(candidates []candidate, operator, wanted string) (candidate, bool, error) {
	var selected candidate
	found := false
	directAvailable := false
	for _, value := range candidates {
		matches, err := versionSatisfies(value.Package.Format, value.matchVersion, operator, wanted)
		if err != nil {
			return candidate{}, false, err
		}
		if matches && value.direct {
			directAvailable = true
		}
	}
	for _, value := range candidates {
		if directAvailable && !value.direct {
			continue
		}
		matches, err := versionSatisfies(value.Package.Format, value.matchVersion, operator, wanted)
		if err != nil {
			return candidate{}, false, err
		}
		if !matches {
			continue
		}
		if !found {
			selected, found = value, true
			continue
		}
		comparison, err := compareNativeVersions(value.Package.Format, value.Package.Version, selected.Package.Version)
		if err != nil {
			return candidate{}, false, err
		}
		if comparison > 0 || comparison == 0 && value.Package.SHA256 < selected.Package.SHA256 {
			selected = value
		}
	}
	return selected, found, nil
}

type relationGroup struct {
	kind         string
	number       int
	alternatives []RelationAlternative
}

func requiredRelationGroups(ctx context.Context, db *sql.DB, pkg PackageRecord, targetArch string) ([]relationGroup, error) {
	kinds := []string{"requires"}
	if pkg.Format == "deb" {
		kinds = []string{"pre-depends", "depends"}
	}
	placeholders := make([]string, len(kinds))
	arguments := make([]any, 0, len(kinds)+1)
	arguments = append(arguments, pkg.SHA256)
	for index, kind := range kinds {
		placeholders[index] = "?"
		arguments = append(arguments, kind)
	}
	rows, err := db.QueryContext(ctx, `SELECT kind,relation_group,alternative,name,operator,version,arch_qualifier,arch_filter_not
FROM relations WHERE sha256=? AND kind IN (`+strings.Join(placeholders, ",")+`)
ORDER BY kind,relation_group,alternative`, arguments...)
	if err != nil {
		return nil, err
	}
	type rawRelation struct {
		kind, name, operator, wanted, qualifier string
		group, alternative, filterNot           int
	}
	var raw []rawRelation
	for rows.Next() {
		var value rawRelation
		if err := rows.Scan(&value.kind, &value.group, &value.alternative, &value.name, &value.operator, &value.wanted, &value.qualifier, &value.filterNot); err != nil {
			_ = rows.Close()
			return nil, err
		}
		raw = append(raw, value)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var result []relationGroup
	for _, value := range raw {
		applies, err := relationApplies(ctx, db, pkg.SHA256, value.kind, value.group, value.alternative, value.filterNot != 0, targetArch)
		if err != nil {
			return nil, err
		}
		if !applies {
			continue
		}
		if len(result) == 0 || result[len(result)-1].kind != value.kind || result[len(result)-1].number != value.group {
			result = append(result, relationGroup{kind: value.kind, number: value.group})
		}
		result[len(result)-1].alternatives = append(result[len(result)-1].alternatives, RelationAlternative{Name: value.name, Operator: value.operator, Version: value.wanted, ArchQualifier: value.qualifier})
	}
	return result, nil
}

func relationApplies(ctx context.Context, db *sql.DB, sha, kind string, group, alternative int, negated bool, target string) (bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT arch FROM relation_arches WHERE sha256=? AND kind=? AND relation_group=? AND alternative=? ORDER BY arch`, sha, kind, group, alternative)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var architectures []dependency.Arch
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return false, err
		}
		parsed, err := dependency.ParseArch(raw)
		if err != nil {
			return false, fmt.Errorf("catalog: parse projected architecture %q: %w", raw, err)
		}
		architectures = append(architectures, *parsed)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	if len(architectures) == 0 {
		return true, nil
	}
	targetArch, err := dependency.ParseArch(target)
	if err != nil {
		return false, fmt.Errorf("catalog: parse target architecture %q: %w", target, err)
	}
	set := dependency.ArchSet{Not: negated, Architectures: architectures}
	return set.Matches(targetArch), nil
}

func versionSatisfies(format, actual, operator, wanted string) (bool, error) {
	if operator == "" || wanted == "" {
		return true, nil
	}
	if actual == "" {
		return false, nil
	}
	comparison, err := compareNativeVersions(format, actual, wanted)
	if err != nil {
		return false, err
	}
	switch operator {
	case "=":
		return comparison == 0, nil
	case "<", "<<":
		return comparison < 0, nil
	case "<=":
		return comparison <= 0, nil
	case ">", ">>":
		return comparison > 0, nil
	case ">=":
		return comparison >= 0, nil
	default:
		return false, fmt.Errorf("catalog: unsupported %s version operator %q", format, operator)
	}
}

func compareNativeVersions(format, left, right string) (int, error) {
	switch format {
	case "deb":
		leftVersion, err := debianversion.Parse(left)
		if err != nil {
			return 0, fmt.Errorf("catalog: parse Debian version %q: %w", left, err)
		}
		rightVersion, err := debianversion.Parse(right)
		if err != nil {
			return 0, fmt.Errorf("catalog: parse Debian version %q: %w", right, err)
		}
		return debianversion.Compare(leftVersion, rightVersion), nil
	case "rpm":
		leftVersion, err := parseRPMVersion(left)
		if err != nil {
			return 0, err
		}
		rightVersion, err := parseRPMVersion(right)
		if err != nil {
			return 0, err
		}
		return crpm.Compare(leftVersion, rightVersion), nil
	default:
		return 0, fmt.Errorf("catalog: unsupported package format %q", format)
	}
}

type rpmVersion struct {
	epoch   int
	version string
	release string
}

func (v rpmVersion) Epoch() int      { return v.epoch }
func (v rpmVersion) Version() string { return v.version }
func (v rpmVersion) Release() string { return v.release }

func parseRPMVersion(value string) (rpmVersion, error) {
	result := rpmVersion{}
	if colon := strings.IndexByte(value, ':'); colon >= 0 {
		epoch, err := strconv.Atoi(value[:colon])
		if err != nil || epoch < 0 {
			return result, fmt.Errorf("catalog: invalid RPM epoch in %q", value)
		}
		result.epoch = epoch
		value = value[colon+1:]
	}
	if dash := strings.LastIndexByte(value, '-'); dash >= 0 {
		result.version, result.release = value[:dash], value[dash+1:]
	} else {
		result.version = value
	}
	if result.version == "" {
		return result, fmt.Errorf("catalog: invalid RPM version %q", value)
	}
	return result, nil
}

func artifactProvenance(ctx context.Context, db *sql.DB, sha string) ([]ProvenanceRecord, error) {
	rows, err := db.QueryContext(ctx, `SELECT receipt_id,artifact_sha256,format,kind,repo,source_path,pool,upstream_url,observed_at
FROM provenance WHERE artifact_sha256=? ORDER BY kind,receipt_id`, sha)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ProvenanceRecord
	for rows.Next() {
		var value ProvenanceRecord
		if err := rows.Scan(&value.ReceiptID, &value.ArtifactSHA256, &value.Format, &value.Kind, &value.Repo, &value.SourcePath, &value.Pool, &value.UpstreamURL, &value.ObservedAt); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func ArtifactProvenance(ctx context.Context, stateDir, sha string) ([]ProvenanceRecord, error) {
	db, err := openReadOnly(ctx, stateDir)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return artifactProvenance(ctx, db, sha)
}
