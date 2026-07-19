// Package catalog owns SOW's disposable, read-only SQLite query projection.
// Canonical manifests, refs, package bytes in CAS, and provenance receipts are
// the only inputs; deleting state.db and rebuilding it must preserve results.
package catalog

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
	_ "modernc.org/sqlite"
)

const SchemaVersion = 3

func Path(stateDir string) string { return filepath.Join(stateDir, "cache", "state.db") }

// Stats reports projection row counts without treating any SQLite row as
// canonical state.
type Stats struct {
	Files       int64
	Packages    int64
	Memberships int64
	Relations   int64
	Provenance  int64
}

func Rebuild(stateDir string) error {
	return RebuildContext(context.Background(), stateDir)
}

// RebuildContext streams all canonical inputs through one SQLite transaction,
// closes and fsyncs the new database, then atomically replaces the old cache.
// A malformed ref, package, receipt, or cancellation leaves the prior cache
// untouched.
func RebuildContext(ctx context.Context, stateDir string) error {
	if ctx == nil {
		return errors.New("catalog: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	canonical := state.New(stateDir)
	refs, err := canonical.SOWRefs()
	if err != nil {
		return fmt.Errorf("catalog: enumerate canonical refs: %w", err)
	}
	head, err := canonical.HeadHash()
	if err != nil {
		return fmt.Errorf("catalog: read canonical HEAD: %w", err)
	}
	headRepoTypes, err := canonicalRepoTypes(canonical, head)
	if err != nil {
		return err
	}
	repoTypesByCommit := map[plumbing.Hash]map[string]string{head: headRepoTypes}

	cacheDir := filepath.Join(stateDir, "cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return fmt.Errorf("catalog: create cache directory: %w", err)
	}
	tmp, err := os.CreateTemp(cacheDir, "state-*.db")
	if err != nil {
		return fmt.Errorf("catalog: create cache file: %w", err)
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	_ = os.Remove(tmpPath)
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
			_ = os.Remove(tmpPath + "-journal")
		}
	}()

	db, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return fmt.Errorf("catalog: open new cache: %w", err)
	}
	db.SetMaxOpenConns(1)
	closeDB := true
	defer func() {
		if closeDB {
			_ = db.Close()
		}
	}()
	if _, err := db.ExecContext(ctx, `PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;`); err != nil {
		return fmt.Errorf("catalog: configure cache: %w", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, schemaSQL, SchemaVersion, head.String()); err != nil {
		return fmt.Errorf("catalog: create cache schema: %w", err)
	}
	builder, err := newBuilder(ctx, tx, filepath.Dir(filepath.Clean(stateDir)))
	if err != nil {
		return err
	}
	defer builder.Close()
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return err
		}
		coordinate, ok, err := parseCanonicalRef(ref)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		switch coordinate.kind {
		case "repo":
			reader, err := canonical.OpenPathAt(ref.Hash, path.Join("manifests", coordinate.repo+".tsv"))
			if err != nil {
				return err
			}
			err = builder.importManifest(coordinate.repo, reader)
			closeErr := reader.Close()
			if err != nil || closeErr != nil {
				return errors.Join(err, closeErr)
			}
		case "view", "snapshot":
			repoTypes, exists := repoTypesByCommit[ref.Hash]
			if !exists {
				repoTypes, err = canonicalRepoTypes(canonical, ref.Hash)
				if err != nil {
					// Pre-schema-v2 canonical commits can contain a valid view
					// before config/sow.yaml was made mandatory in every mutation.
					// A still-configured repository provides a safe migration type;
					// removed historical repos must retain their own frozen config.
					if currentType, configured := headRepoTypes[coordinate.repo]; configured {
						repoTypes = map[string]string{coordinate.repo: currentType}
					} else {
						return err
					}
				}
				repoTypesByCommit[ref.Hash] = repoTypes
			}
			coordinate.repoType, exists = repoTypes[coordinate.repo]
			if !exists {
				return fmt.Errorf("catalog: canonical %s %s names repo %s absent from config at %s", coordinate.kind, coordinate.scope, coordinate.repo, ref.Hash)
			}
			canonicalPath := path.Join(coordinate.kind+"s", coordinate.scope, coordinate.repo, coordinate.os, coordinate.arch+".tsv")
			reader, err := canonical.OpenPathAt(ref.Hash, canonicalPath)
			if err != nil {
				return err
			}
			err = builder.importView(coordinate, reader)
			closeErr := reader.Close()
			if err != nil || closeErr != nil {
				return errors.Join(err, closeErr)
			}
		}
	}
	if !head.IsZero() {
		if err := builder.importProvenance(canonical, head); err != nil {
			return err
		}
	}
	if err := builder.Close(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("catalog: commit cache rebuild: %w", err)
	}
	rollback = false
	if err := db.Close(); err != nil {
		return fmt.Errorf("catalog: close rebuilt cache: %w", err)
	}
	closeDB = false
	if err := os.Chmod(tmpPath, 0o444); err != nil {
		return err
	}
	f, err := os.Open(tmpPath)
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if syncErr != nil || closeErr != nil {
		return errors.Join(syncErr, closeErr)
	}
	if err := os.Rename(tmpPath, Path(stateDir)); err != nil {
		return fmt.Errorf("catalog: replace cache: %w", err)
	}
	committed = true
	directory, err := os.Open(cacheDir)
	if err != nil {
		return fmt.Errorf("catalog: open cache directory after replacement: %w", err)
	}
	if syncErr, closeErr := directory.Sync(), directory.Close(); syncErr != nil || closeErr != nil {
		return fmt.Errorf("catalog: sync cache directory after replacement: %w", errors.Join(syncErr, closeErr))
	}
	return nil
}

const schemaSQL = `
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE files (
  repo TEXT NOT NULL,
  path TEXT NOT NULL,
  size INTEGER NOT NULL CHECK(size >= 0),
  sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
  PRIMARY KEY (repo, path)
) WITHOUT ROWID;
CREATE INDEX files_sha256 ON files(sha256);
CREATE TABLE packages (
  sha256 TEXT PRIMARY KEY CHECK(length(sha256) = 64),
  format TEXT NOT NULL CHECK(format IN ('deb','rpm')),
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  arch TEXT NOT NULL,
  source TEXT NOT NULL,
  size INTEGER NOT NULL CHECK(size >= 0)
) WITHOUT ROWID;
CREATE INDEX packages_identity ON packages(format,name,version,arch);
CREATE TABLE memberships (
  scope_kind TEXT NOT NULL CHECK(scope_kind IN ('view','snapshot')),
  scope TEXT NOT NULL,
  repo TEXT NOT NULL,
  os TEXT NOT NULL,
  arch TEXT NOT NULL,
  path TEXT NOT NULL,
  pool TEXT NOT NULL CHECK(pool IN ('public','gated')),
  sha256 TEXT NOT NULL REFERENCES packages(sha256),
  PRIMARY KEY (scope_kind,scope,repo,os,arch,path)
) WITHOUT ROWID;
CREATE INDEX memberships_leaf_package ON memberships(scope_kind,scope,repo,os,arch,sha256);
CREATE TABLE relations (
  sha256 TEXT NOT NULL REFERENCES packages(sha256),
  kind TEXT NOT NULL,
  relation_group INTEGER NOT NULL CHECK(relation_group >= 0),
  alternative INTEGER NOT NULL CHECK(alternative >= 0),
  name TEXT NOT NULL,
  operator TEXT NOT NULL,
  version TEXT NOT NULL,
  arch_qualifier TEXT NOT NULL,
  arch_filter_not INTEGER NOT NULL CHECK(arch_filter_not IN (0,1)),
  pre INTEGER NOT NULL CHECK(pre IN (0,1)),
  PRIMARY KEY (sha256,kind,relation_group,alternative)
) WITHOUT ROWID;
CREATE INDEX relations_name ON relations(kind,name);
CREATE TABLE relation_arches (
  sha256 TEXT NOT NULL,
  kind TEXT NOT NULL,
  relation_group INTEGER NOT NULL,
  alternative INTEGER NOT NULL,
  arch TEXT NOT NULL,
  PRIMARY KEY (sha256,kind,relation_group,alternative,arch),
  FOREIGN KEY (sha256,kind,relation_group,alternative)
    REFERENCES relations(sha256,kind,relation_group,alternative)
) WITHOUT ROWID;
CREATE TABLE provenance (
  receipt_id TEXT PRIMARY KEY,
  artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256) = 64),
  format TEXT NOT NULL CHECK(format IN ('deb','rpm','asset')),
  kind TEXT NOT NULL CHECK(kind IN ('upstream','legacy')),
  repo TEXT NOT NULL,
  source_path TEXT NOT NULL,
  pool TEXT NOT NULL,
  upstream_url TEXT NOT NULL,
  observed_at TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX provenance_artifact ON provenance(artifact_sha256);
INSERT INTO meta(key, value) VALUES ('schema_version', ?), ('canonical_head', ?);`

type canonicalCoordinate struct {
	kind     string
	scope    string
	repo     string
	os       string
	arch     string
	repoType string
}

func parseCanonicalRef(ref state.RefRecord) (canonicalCoordinate, bool, error) {
	parts := strings.Split(ref.Name.String(), "/")
	if len(parts) == 4 && parts[0] == "refs" && parts[1] == "sow" && parts[2] == "repos" {
		return canonicalCoordinate{kind: "repo", repo: parts[3]}, true, nil
	}
	if len(parts) == 7 && parts[0] == "refs" && parts[1] == "sow" && (parts[2] == "views" || parts[2] == "snapshots") {
		kind := strings.TrimSuffix(parts[2], "s")
		return canonicalCoordinate{kind: kind, scope: parts[3], repo: parts[4], os: parts[5], arch: parts[6]}, true, nil
	}
	return canonicalCoordinate{}, false, nil
}

func canonicalRepoTypes(canonical *state.Store, head plumbing.Hash) (map[string]string, error) {
	result := make(map[string]string)
	if head.IsZero() {
		return result, nil
	}
	reader, err := canonical.OpenPathAt(head, "config/sow.yaml")
	if err != nil {
		return nil, fmt.Errorf("catalog: open canonical config: %w", err)
	}
	cfg, decodeErr := config.Decode(reader)
	closeErr := reader.Close()
	if decodeErr != nil || closeErr != nil {
		return nil, errors.Join(decodeErr, closeErr)
	}
	for _, repo := range cfg.Repos {
		result[repo.ID] = repo.Type
	}
	return result, nil
}

type builder struct {
	ctx       context.Context
	tx        *sql.Tx
	root      string
	pool      *repository.Store
	stmts     []*sql.Stmt
	file      *sql.Stmt
	member    *sql.Stmt
	packageIn *sql.Stmt
	relation  *sql.Stmt
	relArch   *sql.Stmt
	receipt   *sql.Stmt
}

func newBuilder(ctx context.Context, tx *sql.Tx, root string) (*builder, error) {
	b := &builder{ctx: ctx, tx: tx, root: root}
	queries := []struct {
		dst **sql.Stmt
		sql string
	}{
		{&b.file, `INSERT INTO files(repo,path,size,sha256) VALUES(?,?,?,?)`},
		{&b.member, `INSERT INTO memberships(scope_kind,scope,repo,os,arch,path,pool,sha256) VALUES(?,?,?,?,?,?,?,?)`},
		{&b.packageIn, `INSERT INTO packages(sha256,format,name,version,arch,source,size) VALUES(?,?,?,?,?,?,?)`},
		{&b.relation, `INSERT INTO relations(sha256,kind,relation_group,alternative,name,operator,version,arch_qualifier,arch_filter_not,pre) VALUES(?,?,?,?,?,?,?,?,?,?)`},
		{&b.relArch, `INSERT INTO relation_arches(sha256,kind,relation_group,alternative,arch) VALUES(?,?,?,?,?)`},
		{&b.receipt, `INSERT INTO provenance(receipt_id,artifact_sha256,format,kind,repo,source_path,pool,upstream_url,observed_at) VALUES(?,?,?,?,?,?,?,?,?)`},
	}
	for _, query := range queries {
		statement, err := tx.PrepareContext(ctx, query.sql)
		if err != nil {
			_ = b.Close()
			return nil, err
		}
		*query.dst = statement
		b.stmts = append(b.stmts, statement)
	}
	return b, nil
}

func (b *builder) Close() error {
	var result error
	for _, statement := range b.stmts {
		if statement != nil {
			result = errors.Join(result, statement.Close())
		}
	}
	b.stmts = nil
	return result
}

func (b *builder) importManifest(repo string, source io.Reader) error {
	reader := manifest.NewReader(source)
	for {
		if err := b.ctx.Err(); err != nil {
			return err
		}
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("catalog: read canonical manifest %s: %w", repo, err)
		}
		if _, err := b.file.ExecContext(b.ctx, repo, entry.Path, entry.Size, entry.HashString()); err != nil {
			return fmt.Errorf("catalog: cache manifest %s path %s: %w", repo, entry.Path, err)
		}
	}
}

func (b *builder) importView(coordinate canonicalCoordinate, source io.Reader) error {
	repoType := coordinate.repoType
	reader := views.NewReader(source)
	for {
		if err := b.ctx.Err(); err != nil {
			return err
		}
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("catalog: read %s %s/%s/%s/%s: %w", coordinate.kind, coordinate.scope, coordinate.repo, coordinate.os, coordinate.arch, err)
		}
		if entry.Repo != coordinate.repo || entry.OS != coordinate.os || entry.Arch != coordinate.arch {
			return fmt.Errorf("catalog: %s %s coordinate differs from entry %s/%s/%s", coordinate.kind, coordinate.scope, entry.Repo, entry.OS, entry.Arch)
		}
		if repoType == "asset" {
			continue
		}
		if repoType != "apt" && repoType != "yum" {
			return fmt.Errorf("catalog: unsupported repo type %q for %s", repoType, coordinate.repo)
		}
		if err := b.ensurePackage(repoType, entry); err != nil {
			return err
		}
		if _, err := b.member.ExecContext(b.ctx, coordinate.kind, coordinate.scope, coordinate.repo, coordinate.os, coordinate.arch, entry.Path, entry.Pool, entry.SHA256); err != nil {
			return fmt.Errorf("catalog: project membership %s: %w", entry.Path, err)
		}
	}
}

func (b *builder) ensurePackage(repoType string, entry views.Entry) error {
	var format, name, version, arch, source string
	var size int64
	err := b.tx.QueryRowContext(b.ctx, `SELECT format,name,version,arch,source,size FROM packages WHERE sha256=?`, entry.SHA256).Scan(&format, &name, &version, &arch, &source, &size)
	if err == nil {
		if format != packageFormat(repoType) || name != entry.Name || version != entry.Version || size != entry.Size {
			return fmt.Errorf("catalog: canonical package identity conflict for %s", entry.SHA256)
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if b.pool == nil {
		pool, err := repository.NewStore(b.root)
		if err != nil {
			return fmt.Errorf("catalog: open CAS: %w", err)
		}
		b.pool = pool
	}
	digest, err := repository.ParseDigest(entry.SHA256)
	if err != nil {
		return err
	}
	object := repository.Object{SHA256: digest, Size: entry.Size}
	if err := b.pool.Verify(b.ctx, object); err != nil {
		return fmt.Errorf("catalog: verify package CAS object %s: %w", entry.SHA256, err)
	}
	objectPath := b.pool.ObjectPath(digest)
	switch repoType {
	case "apt":
		component, err := aptComponent(entry.Path)
		if err != nil {
			return err
		}
		pkg, err := aptrepo.InspectPackageAs(b.ctx, objectPath, component, path.Base(entry.Path))
		if err != nil {
			return fmt.Errorf("catalog: inspect DEB %s: %w", entry.Path, err)
		}
		if pkg.Name != entry.Name || pkg.Version != entry.Version || pkg.SHA256 != entry.SHA256 || pkg.Size != entry.Size || !strings.HasSuffix(entry.Path, "/"+pkg.PoolPath) {
			return fmt.Errorf("catalog: DEB body identity differs from canonical view at %s", entry.Path)
		}
		format, name, version, arch, source, size = "deb", pkg.Name, pkg.Version, pkg.Architecture, pkg.Source, pkg.Size
		if _, err := b.packageIn.ExecContext(b.ctx, entry.SHA256, format, name, version, arch, source, size); err != nil {
			return err
		}
		relations, err := pkg.CatalogRelations()
		if err != nil {
			return err
		}
		for _, relation := range relations {
			if err := b.insertRelation(entry.SHA256, relation.Kind, relation.Group, relation.Alternative, relation.Name, relation.Operator, relation.Version, relation.ArchQualifier, relation.ArchFilterNot, false, relation.Architectures); err != nil {
				return err
			}
		}
	case "yum":
		pkg, err := yumrepo.InspectCatalogPackage(b.ctx, yumrepo.PackageInput{Path: objectPath, Basename: path.Base(entry.Path)})
		if err != nil {
			return fmt.Errorf("catalog: inspect RPM %s: %w", entry.Path, err)
		}
		if pkg.Name != entry.Name || pkg.DisplayVersion != entry.Version || pkg.SHA256 != entry.SHA256 || pkg.Size != entry.Size || !strings.HasSuffix(entry.Path, "/"+pkg.Location) {
			return fmt.Errorf("catalog: RPM body identity differs from canonical view at %s", entry.Path)
		}
		format, name, version, arch, source, size = "rpm", pkg.Name, pkg.DisplayVersion, pkg.Arch, pkg.Source, pkg.Size
		if _, err := b.packageIn.ExecContext(b.ctx, entry.SHA256, format, name, version, arch, source, size); err != nil {
			return err
		}
		for _, relation := range pkg.Relations {
			if err := b.insertRelation(entry.SHA256, relation.Kind, relation.Group, 0, relation.Name, relation.Operator, relation.Version, "", false, relation.Pre, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *builder) insertRelation(sha, kind string, group, alternative int, name, operator, version, qualifier string, filterNot, pre bool, architectures []string) error {
	if name == "" {
		return fmt.Errorf("catalog: empty %s relation for %s", kind, sha)
	}
	if _, err := b.relation.ExecContext(b.ctx, sha, kind, group, alternative, name, operator, version, qualifier, boolInt(filterNot), boolInt(pre)); err != nil {
		return fmt.Errorf("catalog: project %s relation %s: %w", kind, name, err)
	}
	for _, architecture := range architectures {
		if _, err := b.relArch.ExecContext(b.ctx, sha, kind, group, alternative, architecture); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) importProvenance(canonical *state.Store, head plumbing.Hash) error {
	return canonical.ForEachFileAt(head, "provenance/", func(canonicalPath string) error {
		if err := b.ctx.Err(); err != nil {
			return err
		}
		parts := strings.Split(canonicalPath, "/")
		switch {
		case len(parts) == 3 && (parts[1] == "deb" || parts[1] == "rpm") && strings.HasSuffix(parts[2], ".json"):
			reader, err := canonical.OpenPathAt(head, canonicalPath)
			if err != nil {
				return err
			}
			data, readErr := io.ReadAll(io.LimitReader(reader, 4*1024*1024+1))
			closeErr := reader.Close()
			if readErr != nil || closeErr != nil || len(data) > 4*1024*1024 {
				return errors.Join(readErr, closeErr, errors.New("catalog: provenance receipt exceeds 4 MiB"))
			}
			receipt, err := provenance.Decode(data)
			if err != nil {
				return fmt.Errorf("catalog: decode %s: %w", canonicalPath, err)
			}
			if parts[1] != receipt.Format || strings.TrimSuffix(parts[2], ".json") != receipt.ArtifactSHA256 {
				return fmt.Errorf("catalog: provenance path disagrees with receipt %s", canonicalPath)
			}
			id, err := receipt.ID()
			if err != nil {
				return err
			}
			if _, err := b.receipt.ExecContext(b.ctx, id, receipt.ArtifactSHA256, receipt.Format, "upstream", "", "", "", receipt.UpstreamURL, receipt.ObservedAt.Format("2006-01-02T15:04:05.999999999Z")); err != nil {
				return err
			}
		case len(parts) == 3 && parts[1] == "legacy" && strings.HasSuffix(parts[2], ".jsonl"):
			reader, err := canonical.OpenPathAt(head, canonicalPath)
			if err != nil {
				return err
			}
			legacy := provenance.NewLegacyAdoptionReader(reader)
			for {
				receipt, err := legacy.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					_ = reader.Close()
					return err
				}
				data, err := receipt.CanonicalJSON()
				if err != nil {
					_ = reader.Close()
					return err
				}
				digest := sha256.Sum256(data)
				id := hex.EncodeToString(digest[:])
				if _, err := b.receipt.ExecContext(b.ctx, id, receipt.ArtifactSHA256, receipt.Format, "legacy", receipt.Repo, receipt.SourcePath, receipt.Pool, "", receipt.AdoptedAt.Format("2006-01-02T15:04:05.999999999Z")); err != nil {
					_ = reader.Close()
					return err
				}
			}
			if err := reader.Close(); err != nil {
				return err
			}
		}
		return nil
	})
}

func packageFormat(repoType string) string {
	if repoType == "apt" {
		return "deb"
	}
	return "rpm"
}

func aptComponent(value string) (string, error) {
	parts := strings.Split(value, "/")
	for index := len(parts) - 2; index >= 0; index-- {
		if parts[index] == "pool" && index+1 < len(parts) {
			return parts[index+1], nil
		}
	}
	return "", fmt.Errorf("catalog: APT package path lacks pool component: %s", value)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// Count preserves the original CLI-facing file count while richer row counts
// are available through Statistics.
func Count(stateDir string) (int64, error) {
	stats, err := Statistics(context.Background(), stateDir)
	return stats.Files, err
}
