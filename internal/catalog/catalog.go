package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pgsty/sow/internal/manifest"
	_ "modernc.org/sqlite"
)

const SchemaVersion = 1

func Path(stateDir string) string { return filepath.Join(stateDir, "cache", "state.db") }

func Rebuild(stateDir string) error {
	manifestDir := filepath.Join(stateDir, "state", "manifests")
	entries, err := os.ReadDir(manifestDir)
	if err != nil {
		return fmt.Errorf("list canonical manifests: %w", err)
	}
	cacheDir := filepath.Join(stateDir, "cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}
	tmp, err := os.CreateTemp(cacheDir, "state-*.db")
	if err != nil {
		return fmt.Errorf("create cache file: %w", err)
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
		return fmt.Errorf("open new cache: %w", err)
	}
	closeDB := true
	defer func() {
		if closeDB {
			_ = db.Close()
		}
	}()
	if _, err := db.Exec(`PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;`); err != nil {
		return fmt.Errorf("configure cache: %w", err)
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE files (
  repo TEXT NOT NULL,
  path TEXT NOT NULL,
  size INTEGER NOT NULL CHECK(size >= 0),
  sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
  PRIMARY KEY (repo, path)
) WITHOUT ROWID;
CREATE INDEX files_sha256 ON files(sha256);
INSERT INTO meta(key, value) VALUES ('schema_version', ?);`, SchemaVersion); err != nil {
		return fmt.Errorf("create cache schema: %w", err)
	}
	insert, err := tx.Prepare(`INSERT INTO files(repo, path, size, sha256) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tsv") {
			continue
		}
		repo := strings.TrimSuffix(entry.Name(), ".tsv")
		if repo == "" {
			return errors.New("canonical manifest has an empty repo name")
		}
		if err := importManifest(insert, repo, filepath.Join(manifestDir, entry.Name())); err != nil {
			_ = insert.Close()
			return err
		}
	}
	if err := insert.Close(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit cache rebuild: %w", err)
	}
	rollback = false
	if err := db.Close(); err != nil {
		return fmt.Errorf("close rebuilt cache: %w", err)
	}
	closeDB = false
	if err := os.Chmod(tmpPath, 0o600); err != nil {
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
		return fmt.Errorf("replace cache: %w", err)
	}
	committed = true
	if dir, err := os.Open(cacheDir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func importManifest(insert *sql.Stmt, repo, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := manifest.NewReader(f)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read canonical manifest %s: %w", repo, err)
		}
		if _, err := insert.Exec(repo, entry.Path, entry.Size, entry.HashString()); err != nil {
			return fmt.Errorf("cache manifest %s path %s: %w", repo, entry.Path, err)
		}
	}
}

func Count(stateDir string) (int64, error) {
	dsn := (&url.URL{Scheme: "file", Path: Path(stateDir)}).String() + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var count int64
	if err := db.QueryRow(`SELECT count(*) FROM files`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
