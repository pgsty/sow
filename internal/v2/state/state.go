package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"modernc.org/sqlite"
)

const (
	SchemaVersion            = 10
	SchemaV1SHA256           = "9953cdc1f655fb03814da8b4c7a45a4a92a74e03facf03c2a45709cc860b9bc7"
	SchemaV2SHA256           = "aea5b37365510221ab36c4f0fc9e6bc77ba825354649e1e06336b64551c14e25"
	SchemaV3SHA256           = "9ae957e0e8d9eac21eda3929386f11d001608df5ee7feb75c44194f624f0a177"
	SchemaV4SHA256           = "2282778aacbb3f1adaab3e038f848d3dfe24addabf9c946811a441d80c425ab2"
	SchemaV5SHA256           = "0f89b33d7c42d03907d5b73883031723cb177b03c3c74d461b7d943618ecf794"
	SchemaV6SHA256           = "7ce4382cea6379d2f893e8cd2cd7fc1310c424d4858f82fbbd666f19a18f091a"
	SchemaV7SHA256           = "b3869aafea84722652738f2ebb352aaa10e13659ae61448f32efafc064c23ac3"
	SchemaV8SHA256           = "79e1d22b7884dd8cf4f2bcf26d14a973c84264259e85ace0125685c8440788f5"
	SchemaV9SHA256           = "dcbe4aa8dff14151879b48c069f161261a2f30cb6d2b7668fe0ccac2aff298ce"
	SchemaV10SHA256          = "9a6a64d7276ca7eb3a7579ddb55e1e9e6073baf235e0e1d1a909684783cb38dd"
	MaxOperationPayloadBytes = 16 << 20
)

//go:embed schema_v1.sql
var schemaV1SQL string

//go:embed schema_v2.sql
var schemaV2SQL string

//go:embed schema_v3.sql
var schemaV3SQL string

//go:embed schema_v4.sql
var schemaV4SQL string

//go:embed schema_v5.sql
var schemaV5SQL string

//go:embed schema_v6.sql
var schemaV6SQL string

//go:embed schema_v7.sql
var schemaV7SQL string

//go:embed schema_v8.sql
var schemaV8SQL string

//go:embed schema_v9.sql
var schemaV9SQL string

//go:embed schema_v10.sql
var schemaV10SQL string

var (
	ErrSchema     = errors.New("unsupported or corrupt repository schema")
	ErrNotFound   = errors.New("state object not found")
	ErrExists     = errors.New("state object already exists")
	ErrConflict   = errors.New("state object conflicts with existing identity")
	ErrTransition = errors.New("invalid operation transition")

	schemaV1ContractOnce     sync.Once
	schemaV1ContractObjects  []schemaObject
	schemaV1ContractErr      error
	schemaV2ContractOnce     sync.Once
	schemaV2ContractObjects  []schemaObject
	schemaV2ContractErr      error
	schemaV3ContractOnce     sync.Once
	schemaV3ContractObjects  []schemaObject
	schemaV3ContractErr      error
	schemaV4ContractOnce     sync.Once
	schemaV4ContractObjects  []schemaObject
	schemaV4ContractErr      error
	schemaV5ContractOnce     sync.Once
	schemaV5ContractObjects  []schemaObject
	schemaV5ContractErr      error
	schemaV6ContractOnce     sync.Once
	schemaV6ContractObjects  []schemaObject
	schemaV6ContractErr      error
	schemaV7ContractOnce     sync.Once
	schemaV7ContractObjects  []schemaObject
	schemaV7ContractErr      error
	schemaV8ContractOnce     sync.Once
	schemaV8ContractObjects  []schemaObject
	schemaV8ContractErr      error
	schemaV9ContractOnce     sync.Once
	schemaV9ContractObjects  []schemaObject
	schemaV9ContractErr      error
	schemaV10ContractOnce    sync.Once
	schemaV10ContractObjects []schemaObject
	schemaV10ContractErr     error
)

// Legacy lowercase hexadecimal IDs remain readable so interrupted development
// workspaces can recover. New public IDs are positive decimal integers.
var operationIDPattern = regexp.MustCompile(`^(?:0|[1-9][0-9]*|[0-9a-f]{64})$`)
var metadataFingerprintPattern = regexp.MustCompile(`^(?:[0-9A-F]{40}|[0-9A-F]{64})$`)

type Store struct {
	path          string
	db            *sql.DB
	schemaVersion int
	readOnly      bool
}

type Architecture struct {
	Family        string `json:"family"`
	EcosystemArch string `json:"ecosystem_arch"`
}

type ArchitectureReference struct {
	Dist         string
	Format       string
	Architecture string
	Source       string
}

type Dist struct {
	Name                      string         `json:"name"`
	Format                    string         `json:"format"`
	EffectiveConfigSHA256     string         `json:"effective_config_sha256"`
	BuiltGeneration           GenerationID   `json:"built_generation"`
	Architectures             []Architecture `json:"architectures"`
	MetadataSignerFingerprint string         `json:"metadata_signer_fingerprint,omitempty"`
	MetadataSignerPublicKey   []byte         `json:"-"`
	EffectiveSigningJSON      string         `json:"-"`
}

type RepositorySummary struct {
	DesiredRevision int64        `json:"desired_revision"`
	BuiltGeneration GenerationID `json:"built_generation"`
	Status          string       `json:"status"`
	DirtyReason     string       `json:"dirty_reason,omitempty"`
	DistCount       int64        `json:"dist_count"`
	PackageCount    int64        `json:"package_count"`
	MembershipCount int64        `json:"membership_count"`
}

type DistCounts struct {
	Memberships      int64 `json:"memberships"`
	BuiltMemberships int64 `json:"built_memberships"`
}

type OperationState string

const (
	OperationPlanned    OperationState = "planned"
	OperationStaged     OperationState = "staged"
	OperationApplied    OperationState = "applied"
	OperationBuilt      OperationState = "built"
	OperationDone       OperationState = "done"
	OperationDoneDirty  OperationState = "done_dirty"
	OperationRecovering OperationState = "recovering"
	OperationRolledBack OperationState = "rolled_back"
	OperationFailed     OperationState = "failed"
)

type Operation struct {
	ID           string         `json:"id"`
	Kind         string         `json:"kind"`
	State        OperationState `json:"state"`
	PayloadJSON  string         `json:"payload_json"`
	ResultJSON   string         `json:"result_json"`
	ErrorClass   string         `json:"error_class,omitempty"`
	ErrorMessage string         `json:"error_message,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

func Open(path string) (*Store, error) {
	absolute, err := cleanDatabasePath(path, false)
	if err != nil {
		return nil, err
	}
	db, err := openDatabase(absolute, false)
	if err != nil {
		return nil, err
	}
	store := &Store{path: absolute, db: db, schemaVersion: SchemaVersion}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

// OpenExisting opens an existing current-schema repository database for
// mutation without
// permitting SQLite to create a replacement file. Lifecycle operations must
// use this path so a missing state database is an integrity failure, never an
// implicit reset beside an existing Pool.
func OpenExisting(path string) (*Store, error) {
	absolute, err := cleanDatabasePath(path, true)
	if err != nil {
		return nil, err
	}
	probe, err := openDatabaseMode(absolute, "ro", false, false)
	if err != nil {
		return nil, err
	}
	probeStore := &Store{path: absolute, db: probe, schemaVersion: SchemaVersion}
	probeErr := probeStore.validateSchema(context.Background())
	closeErr := probe.Close()
	if err := errors.Join(probeErr, closeErr); err != nil {
		return nil, err
	}
	db, err := openDatabaseMode(absolute, "rw", true, false)
	if err != nil {
		return nil, err
	}
	store := &Store{path: absolute, db: db, schemaVersion: SchemaVersion}
	if err := store.validateSchema(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

// OpenExistingForMigration is the only existing-file writer authorized to
// advance a known predecessor schema. Ordinary mutations use OpenExisting and
// therefore cannot silently cross the explicit Repository migration boundary.
func OpenExistingForMigration(path string) (*Store, error) {
	absolute, err := cleanDatabasePath(path, true)
	if err != nil {
		return nil, err
	}
	probe, err := openDatabaseMode(absolute, "ro", false, false)
	if err != nil {
		return nil, err
	}
	probeStore := &Store{path: absolute, db: probe}
	probeErr := probeStore.validateUpgradeableSchema(context.Background())
	closeErr := probe.Close()
	if err := errors.Join(probeErr, closeErr); err != nil {
		return nil, err
	}
	db, err := openDatabaseMode(absolute, "rw", true, false)
	if err != nil {
		return nil, err
	}
	store := &Store{path: absolute, db: db, schemaVersion: SchemaVersion}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

// OpenInitializing resumes creation of a repository database after an
// authorized repo.init or repo.new workspace journal has committed. It is the
// only existing-file open path that may migrate an empty version-0 database;
// ordinary lifecycle and read-only callers must continue to use OpenExisting
// and OpenReadOnly so a missing or uninitialized database cannot be adopted.
func OpenInitializing(path string) (*Store, error) {
	absolute, err := cleanDatabasePath(path, true)
	if err != nil {
		return nil, err
	}
	probe, err := openDatabaseMode(absolute, "ro", false, false)
	if err != nil {
		return nil, fmt.Errorf("%w: open initializing database: %v", ErrSchema, err)
	}
	probeStore := &Store{path: absolute, db: probe}
	probeErr := probeStore.validateInitializingSchema(context.Background())
	closeErr := probe.Close()
	if err := errors.Join(probeErr, closeErr); err != nil {
		return nil, err
	}

	db, err := openDatabaseMode(absolute, "rw", true, false)
	if err != nil {
		return nil, fmt.Errorf("%w: resume initializing database: %v", ErrSchema, err)
	}
	store := &Store{path: absolute, db: db, schemaVersion: SchemaVersion}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.Checkpoint(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func OpenReadOnly(path string) (*Store, error) {
	absolute, err := cleanDatabasePath(path, true)
	if err != nil {
		return nil, err
	}
	db, err := openDatabase(absolute, true)
	if err != nil {
		return nil, err
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		db.Close()
		return nil, fmt.Errorf("%w: read user_version: %v", ErrSchema, err)
	}
	if version != 6 && version != SchemaVersion {
		db.Close()
		return nil, fmt.Errorf("%w: read-only database version %d is neither frozen v0.2 nor current", ErrSchema, version)
	}
	store := &Store{path: absolute, db: db, schemaVersion: version, readOnly: true}
	if err := store.validateSchemaVersion(context.Background(), version); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

// ReadOnlyRequiresLifecycleFence reports whether OpenReadOnly must use
// immutable mode to avoid creating SQLite WAL coordination files. Callers
// that can race a lifecycle writer must hold their shared repository lock for
// the whole immutable read. Current writers enable persistent WAL and make
// this a one-time compatibility path for settled legacy databases.
func ReadOnlyRequiresLifecycleFence(path string) (bool, error) {
	absolute, err := cleanDatabasePath(path, true)
	if err != nil {
		return false, err
	}
	walInfo, err := os.Lstat(absolute + "-wal")
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect repository sqlite WAL: %w", err)
	}
	if walInfo.Mode()&os.ModeSymlink != 0 || !walInfo.Mode().IsRegular() {
		return false, fmt.Errorf("database WAL is not a regular file: %s", absolute+"-wal")
	}
	if walInfo.Size() != 0 {
		return false, nil
	}
	shmInfo, shmErr := os.Lstat(absolute + "-shm")
	if errors.Is(shmErr, os.ErrNotExist) {
		return true, nil
	}
	if shmErr != nil {
		return false, fmt.Errorf("inspect repository sqlite shared memory: %w", shmErr)
	}
	if shmInfo.Mode()&os.ModeSymlink != 0 || !shmInfo.Mode().IsRegular() {
		return false, fmt.Errorf("database shared memory is not a regular file: %s", absolute+"-shm")
	}
	return false, nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Path() string { return s.path }

// SchemaVersion reports the byte-for-byte schema contract validated when the
// Store was opened. Version 6 is the frozen v0.2 C2 read-only compatibility
// surface; writable Stores are always current.
func (s *Store) SchemaVersion() int { return s.schemaVersion }

// ReadOnly reports whether the Store was opened through OpenReadOnly. Cache
// users can still rebuild derived facts in memory while skipping persistence
// on status and preview surfaces.
func (s *Store) ReadOnly() bool { return s != nil && s.readOnly }

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func cleanDatabasePath(path string, mustExist bool) (string, error) {
	if path == "" {
		return "", fmt.Errorf("database path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve database path: %w", err)
	}
	if info, statErr := os.Lstat(absolute); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", fmt.Errorf("database path is not a regular file: %s", absolute)
		}
		if err := requirePrivateRegularPath(absolute); err != nil {
			return "", err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("inspect database path: %w", statErr)
	} else if mustExist {
		return "", fmt.Errorf("open repository state read-only: %w", statErr)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		sidecar := absolute + suffix
		info, statErr := os.Lstat(sidecar)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return "", fmt.Errorf("inspect database sidecar %q: %w", sidecar, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", fmt.Errorf("database sidecar is not a regular file: %s", sidecar)
		}
		if err := requirePrivateRegularPath(sidecar); err != nil {
			return "", err
		}
	}
	return absolute, nil
}

func requirePrivateRegularPath(path string) error {
	var raw unix.Stat_t
	if err := unix.Lstat(path, &raw); err != nil {
		return fmt.Errorf("inspect private regular file %q: %w", path, err)
	}
	if uint32(raw.Mode)&unix.S_IFMT != unix.S_IFREG || raw.Nlink != 1 {
		return fmt.Errorf("private regular file %q is unsafe or multiply linked", path)
	}
	return nil
}

func requireDatabasePrivateFiles(path string) error {
	if err := requirePrivateRegularPath(path); err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		candidate := path + suffix
		if err := requirePrivateRegularPath(candidate); err != nil && !errors.Is(err, os.ErrNotExist) {
			var raw unix.Stat_t
			if statErr := unix.Lstat(candidate, &raw); errors.Is(statErr, unix.ENOENT) {
				continue
			}
			return err
		}
	}
	return nil
}

func openDatabase(path string, readOnly bool) (*sql.DB, error) {
	mode := "rwc"
	if readOnly {
		mode = "ro"
	}
	return openDatabaseMode(path, mode, !readOnly, readOnly)
}

func openDatabaseMode(path, mode string, writable, physicallyReadOnly bool) (*sql.DB, error) {
	probe, probeInfo, existed, err := bindDatabaseFile(path, mode != "rwc")
	if err != nil {
		return nil, err
	}
	if probe != nil {
		defer probe.Close()
	}
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := url.Values{}
	query.Set("mode", mode)
	if mode == "ro" {
		// A crashed writer can leave a committed Operation in a hot WAL between
		// COMMIT and the application's explicit checkpoint. immutable=1 would
		// silently ignore that WAL and misreport a recovering Repository as
		// clean. Use immutable for the settled, sidecar-free case so reads cannot
		// create SQLite files; only an already-existing non-empty WAL selects the
		// normal read-only WAL path.
		query.Add("_pragma", "query_only(1)")
		walInfo, statErr := os.Lstat(path + "-wal")
		switch {
		case errors.Is(statErr, os.ErrNotExist):
			query.Set("immutable", "1")
		case statErr != nil:
			return nil, fmt.Errorf("inspect repository sqlite WAL: %w", statErr)
		case walInfo.Mode()&os.ModeSymlink != 0 || !walInfo.Mode().IsRegular():
			return nil, fmt.Errorf("database WAL is not a regular file: %s", path+"-wal")
		default:
			// A current writer persistently retains a usable -shm beside even a
			// zero-length WAL. Prefer that ordinary WAL snapshot path: immutable=1
			// is unsafe if a writer starts or checkpoints after this observation.
			// Legacy settled databases without a sidecar remain immutable until an
			// authorized current writer enables persistent WAL.
			shmInfo, shmErr := os.Lstat(path + "-shm")
			usableSHM := shmErr == nil && shmInfo.Mode().IsRegular() && shmInfo.Mode()&os.ModeSymlink == 0 && shmInfo.Size() != 0
			if physicallyReadOnly && !usableSHM {
				if walInfo.Size() == 0 && errors.Is(shmErr, os.ErrNotExist) {
					query.Set("immutable", "1")
				} else {
					return nil, fmt.Errorf("read-only repository sqlite has a WAL without a usable existing shared-memory sidecar: %w", errors.Join(shmErr, ErrSchema))
				}
			}
		}
	}
	query.Add("_pragma", "foreign_keys(1)")
	busyTimeout := "0"
	if mode == "ro" {
		// Multiple physically read-only connections may arrive immediately
		// after a writer releases the lifecycle lock. One reader can briefly
		// own WAL recovery while the others receive SQLITE_BUSY_RECOVERY. Give
		// SQLite a bounded window to serialize that coordination instead of
		// surfacing a transient repository integrity failure.
		busyTimeout = "5000"
	}
	query.Add("_pragma", "busy_timeout("+busyTimeout+")")
	if writable {
		query.Add("_pragma", "journal_mode(WAL)")
		query.Add("_pragma", "synchronous(FULL)")
	}
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, fmt.Errorf("open repository sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open repository sqlite: %w", err)
	}
	if writable {
		// Preserve WAL coordination files after the last writer closes. Read
		// surfaces can then use SQLite's real read-only snapshot protocol without
		// creating Workspace files or hot-switching to immutable mode.
		connection, connErr := db.Conn(context.Background())
		if connErr == nil {
			connErr = connection.Raw(func(driverConn any) error {
				control, ok := driverConn.(sqlite.FileControl)
				if !ok {
					return errors.New("sqlite driver does not expose persistent WAL control")
				}
				mode, err := control.FileControlPersistWAL("main", 1)
				if err != nil {
					return err
				}
				if mode != 1 {
					return fmt.Errorf("sqlite persistent WAL mode=%d", mode)
				}
				return nil
			})
			connErr = errors.Join(connErr, connection.Close())
		}
		if connErr != nil {
			db.Close()
			return nil, fmt.Errorf("enable persistent repository sqlite WAL: %w", connErr)
		}
	}
	if err := requireDatabasePrivateFiles(path); err != nil {
		db.Close()
		return nil, fmt.Errorf("open repository sqlite: %w", err)
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 || (existed && !os.SameFile(probeInfo, current)) {
		db.Close()
		return nil, fmt.Errorf("open repository sqlite: database path changed while opening: %w", errors.Join(err, errors.New("database inode binding failed")))
	}
	return db, nil
}

func bindDatabaseFile(path string, mustExist bool) (*os.File, os.FileInfo, bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) && !mustExist {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("bind repository sqlite: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	var openedRaw, entryRaw unix.Stat_t
	rawErr := unix.Fstat(fd, &openedRaw)
	entryErr := unix.Lstat(path, &entryRaw)
	if err != nil || rawErr != nil || entryErr != nil || !info.Mode().IsRegular() || openedRaw.Nlink != 1 || entryRaw.Nlink != 1 || openedRaw.Dev != entryRaw.Dev || openedRaw.Ino != entryRaw.Ino {
		_ = file.Close()
		return nil, nil, false, fmt.Errorf("bind repository sqlite: %w", errors.Join(err, rawErr, entryErr, errors.New("database is not a private single-link regular file")))
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(info, current) {
		_ = file.Close()
		return nil, nil, false, fmt.Errorf("bind repository sqlite: %w", errors.Join(err, errors.New("database changed while binding")))
	}
	return file, info, true, nil
}

func (s *Store) migrate(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("%w: read user_version: %v", ErrSchema, err)
	}
	switch {
	case version == SchemaVersion:
		return s.validateSchema(ctx)
	case version > SchemaVersion:
		return fmt.Errorf("%w: database version %d is newer than supported version %d", ErrSchema, version, SchemaVersion)
	case version != 0 && version != 1 && version != 2 && version != 3 && version != 4 && version != 5 && version != 6 && version != 7 && version != 8 && version != 9:
		return fmt.Errorf("%w: cannot migrate version %d", ErrSchema, version)
	}
	if version == 0 {
		var objectCount int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`).Scan(&objectCount); err != nil {
			return fmt.Errorf("inspect empty database: %w", err)
		}
		if objectCount != 0 {
			return fmt.Errorf("%w: user_version is 0 but database is not empty", ErrSchema)
		}
	} else if err := s.validateSchemaVersion(ctx, version); err != nil {
		return err
	}
	if err := validateEmbeddedSchema("v1", schemaV1SQL, SchemaV1SHA256); err != nil {
		return err
	}
	if err := validateEmbeddedSchema("v2", schemaV2SQL, SchemaV2SHA256); err != nil {
		return err
	}
	if err := validateEmbeddedSchema("v3", schemaV3SQL, SchemaV3SHA256); err != nil {
		return err
	}
	if err := validateEmbeddedSchema("v4", schemaV4SQL, SchemaV4SHA256); err != nil {
		return err
	}
	if err := validateEmbeddedSchema("v5", schemaV5SQL, SchemaV5SHA256); err != nil {
		return err
	}
	if err := validateEmbeddedSchema("v6", schemaV6SQL, SchemaV6SHA256); err != nil {
		return err
	}
	if err := validateEmbeddedSchema("v7", schemaV7SQL, SchemaV7SHA256); err != nil {
		return err
	}
	if err := validateEmbeddedSchema("v8", schemaV8SQL, SchemaV8SHA256); err != nil {
		return err
	}
	if err := validateEmbeddedSchema("v9", schemaV9SQL, SchemaV9SHA256); err != nil {
		return err
	}
	if err := validateEmbeddedSchema("v10", schemaV10SQL, SchemaV10SHA256); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema migration: %w", err)
	}
	defer tx.Rollback()
	if version == 0 {
		if _, err := tx.ExecContext(ctx, schemaV1SQL); err != nil {
			return fmt.Errorf("apply schema v1: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (1, ?, ?)`, SchemaV1SHA256, nowText()); err != nil {
			return fmt.Errorf("record schema v1: %w", err)
		}
	}
	if version <= 1 {
		if _, err := tx.ExecContext(ctx, schemaV2SQL); err != nil {
			return fmt.Errorf("apply schema v2: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (2, ?, ?)`, SchemaV2SHA256, nowText()); err != nil {
			return fmt.Errorf("record schema v2: %w", err)
		}
	}
	if version <= 2 {
		if _, err := tx.ExecContext(ctx, schemaV3SQL); err != nil {
			return fmt.Errorf("apply schema v3: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (3, ?, ?)`, SchemaV3SHA256, nowText()); err != nil {
			return fmt.Errorf("record schema v3: %w", err)
		}
	}
	if version <= 3 {
		if _, err := tx.ExecContext(ctx, schemaV4SQL); err != nil {
			return fmt.Errorf("apply schema v4: %w", err)
		}
		if err := normalizeOperationTimestamps(ctx, tx); err != nil {
			return fmt.Errorf("normalize operation timestamps: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (4, ?, ?)`, SchemaV4SHA256, nowText()); err != nil {
			return fmt.Errorf("record schema v4: %w", err)
		}
	}
	if version <= 4 {
		if _, err := tx.ExecContext(ctx, schemaV5SQL); err != nil {
			return fmt.Errorf("apply schema v5: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (5, ?, ?)`, SchemaV5SHA256, nowText()); err != nil {
			return fmt.Errorf("record schema v5: %w", err)
		}
	}
	if version <= 5 {
		if _, err := tx.ExecContext(ctx, schemaV6SQL); err != nil {
			return fmt.Errorf("apply schema v6: %w", err)
		}
		if err := upgradeEffectiveSigningSnapshots(ctx, tx); err != nil {
			return fmt.Errorf("upgrade retained signing snapshots: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (6, ?, ?)`, SchemaV6SHA256, nowText()); err != nil {
			return fmt.Errorf("record schema v6: %w", err)
		}
	}
	if version <= 6 {
		if _, err := tx.ExecContext(ctx, schemaV7SQL); err != nil {
			return fmt.Errorf("apply schema v7: %w", err)
		}
		if version == 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE repository_state SET layout_version = 'single-payload-v1' WHERE singleton = 1`); err != nil {
				return fmt.Errorf("initialize terminal repository layout: %w", err)
			}
		}
		if version >= 2 {
			if err := normalizeLegacyRetainedGenerationLedgerTx(ctx, tx); err != nil {
				return fmt.Errorf("%w: validate legacy retained Generation ledger: %v", ErrSchema, err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (7, ?, ?)`, SchemaV7SHA256, nowText()); err != nil {
			return fmt.Errorf("record schema v7: %w", err)
		}
	}
	if version <= 7 {
		if _, err := tx.ExecContext(ctx, schemaV8SQL); err != nil {
			return fmt.Errorf("apply schema v8: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (8, ?, ?)`, SchemaV8SHA256, nowText()); err != nil {
			return fmt.Errorf("record schema v8: %w", err)
		}
	}
	if version <= 8 {
		if _, err := tx.ExecContext(ctx, schemaV9SQL); err != nil {
			return fmt.Errorf("apply schema v9: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (9, ?, ?)`, SchemaV9SHA256, nowText()); err != nil {
			return fmt.Errorf("record schema v9: %w", err)
		}
	}
	if version <= 9 {
		if _, err := tx.ExecContext(ctx, schemaV10SQL); err != nil {
			return fmt.Errorf("apply schema v10: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, checksum, applied_at) VALUES (10, ?, ?)`, SchemaV10SHA256, nowText()); err != nil {
			return fmt.Errorf("record schema v10: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema v10: %w", err)
	}
	return s.validateSchema(ctx)
}

func validateEmbeddedSchema(label, schema, expected string) error {
	hash := sha256.Sum256([]byte(schema))
	if got := hex.EncodeToString(hash[:]); got != expected {
		return fmt.Errorf("%w: embedded schema %s checksum %s does not match compiled checksum %s", ErrSchema, label, got, expected)
	}
	return nil
}

func (s *Store) validateInitializingSchema(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("%w: read user_version: %v", ErrSchema, err)
	}
	switch version {
	case SchemaVersion:
		return s.validateSchema(ctx)
	case 0:
		var objectCount int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`).Scan(&objectCount); err != nil {
			return fmt.Errorf("%w: inspect initializing database: %v", ErrSchema, err)
		}
		if objectCount != 0 {
			return fmt.Errorf("%w: user_version is 0 but database is not empty", ErrSchema)
		}
		var result string
		if err := s.db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&result); err != nil {
			return fmt.Errorf("%w: sqlite quick_check: %v", ErrSchema, err)
		}
		if result != "ok" {
			return fmt.Errorf("%w: sqlite quick_check: %s", ErrSchema, result)
		}
		return nil
	default:
		return fmt.Errorf("%w: database version %d cannot be resumed as an initialization; only an empty v0 or current schema is authorized", ErrSchema, version)
	}
}

// validateUpgradeableSchema is used only by the immutable read-only probe in
// OpenExisting. It accepts a byte-for-byte known older schema, but performs no
// migration; the following authorized writable open owns that transition.
func (s *Store) validateUpgradeableSchema(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("%w: read user_version: %v", ErrSchema, err)
	}
	switch version {
	case 1, 2, 3, 4, 5, 6, 7, 8, 9, SchemaVersion:
		return s.validateSchemaVersion(ctx, version)
	case 0:
		return fmt.Errorf("%w: uninitialized database cannot be adopted", ErrSchema)
	default:
		return fmt.Errorf("%w: database version %d cannot be upgraded", ErrSchema, version)
	}
}

func (s *Store) validateSchema(ctx context.Context) error {
	return s.validateSchemaVersion(ctx, SchemaVersion)
}

func (s *Store) validateSchemaVersion(ctx context.Context, expectedVersion int) error {
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("%w: read user_version: %v", ErrSchema, err)
	}
	if version != expectedVersion {
		return fmt.Errorf("%w: database version %d, expected %d", ErrSchema, version, expectedVersion)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("%w: read schema migration ledger: %v", ErrSchema, err)
	}
	var migrations []struct {
		version  int
		checksum string
	}
	for rows.Next() {
		var migration struct {
			version  int
			checksum string
		}
		if err := rows.Scan(&migration.version, &migration.checksum); err != nil {
			_ = rows.Close()
			return fmt.Errorf("%w: scan schema migration ledger: %v", ErrSchema, err)
		}
		migrations = append(migrations, migration)
	}
	ledgerErr := errors.Join(rows.Err(), rows.Close())
	if ledgerErr != nil {
		return fmt.Errorf("%w: read schema migration ledger: %v", ErrSchema, ledgerErr)
	}
	expectedMigrations := []struct {
		version  int
		checksum string
	}{{1, SchemaV1SHA256}}
	if expectedVersion >= 2 {
		expectedMigrations = append(expectedMigrations, struct {
			version  int
			checksum string
		}{2, SchemaV2SHA256})
	}
	if expectedVersion >= 3 {
		expectedMigrations = append(expectedMigrations, struct {
			version  int
			checksum string
		}{3, SchemaV3SHA256})
	}
	if expectedVersion >= 4 {
		expectedMigrations = append(expectedMigrations, struct {
			version  int
			checksum string
		}{4, SchemaV4SHA256})
	}
	if expectedVersion >= 5 {
		expectedMigrations = append(expectedMigrations, struct {
			version  int
			checksum string
		}{5, SchemaV5SHA256})
	}
	if expectedVersion >= 6 {
		expectedMigrations = append(expectedMigrations, struct {
			version  int
			checksum string
		}{6, SchemaV6SHA256})
	}
	if expectedVersion >= 7 {
		expectedMigrations = append(expectedMigrations, struct {
			version  int
			checksum string
		}{7, SchemaV7SHA256})
	}
	if expectedVersion >= 8 {
		expectedMigrations = append(expectedMigrations, struct {
			version  int
			checksum string
		}{8, SchemaV8SHA256})
	}
	if expectedVersion >= 9 {
		expectedMigrations = append(expectedMigrations, struct {
			version  int
			checksum string
		}{9, SchemaV9SHA256})
	}
	if expectedVersion >= 10 {
		expectedMigrations = append(expectedMigrations, struct {
			version  int
			checksum string
		}{10, SchemaV10SHA256})
	}
	if !reflectMigrations(migrations, expectedMigrations) {
		return fmt.Errorf("%w: migration ledger does not exactly match schema v%d", ErrSchema, expectedVersion)
	}
	wantObjects, err := expectedSchemaObjects(expectedVersion)
	if err != nil {
		return fmt.Errorf("%w: build schema v%d contract: %v", ErrSchema, expectedVersion, err)
	}
	gotObjects, err := readSchemaObjects(ctx, s.db)
	if err != nil {
		return fmt.Errorf("%w: read installed schema objects: %v", ErrSchema, err)
	}
	if !sameSchemaObjects(gotObjects, wantObjects) {
		return fmt.Errorf("%w: installed sqlite schema differs from schema v%d", ErrSchema, expectedVersion)
	}
	var result string
	if err := s.db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&result); err != nil {
		return fmt.Errorf("%w: sqlite quick_check: %v", ErrSchema, err)
	}
	if result != "ok" {
		return fmt.Errorf("%w: sqlite quick_check: %s", ErrSchema, result)
	}
	if expectedVersion >= 4 {
		if err := validateOperationTimestamps(ctx, s.db); err != nil {
			return fmt.Errorf("%w: %v", ErrSchema, err)
		}
	}
	return nil
}

func reflectMigrations(left, right []struct {
	version  int
	checksum string
}) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type schemaObject struct {
	Type  string
	Name  string
	Table string
	SQL   string
}

func expectedSchemaObjects(version int) ([]schemaObject, error) {
	if version == 1 {
		schemaV1ContractOnce.Do(func() {
			schemaV1ContractObjects, schemaV1ContractErr = buildExpectedSchemaObjects(schemaV1SQL)
		})
		return append([]schemaObject(nil), schemaV1ContractObjects...), schemaV1ContractErr
	}
	if version == 2 {
		schemaV2ContractOnce.Do(func() {
			schemaV2ContractObjects, schemaV2ContractErr = buildExpectedSchemaObjects(schemaV1SQL, schemaV2SQL)
		})
		return append([]schemaObject(nil), schemaV2ContractObjects...), schemaV2ContractErr
	}
	if version == 3 {
		schemaV3ContractOnce.Do(func() {
			schemaV3ContractObjects, schemaV3ContractErr = buildExpectedSchemaObjects(schemaV1SQL, schemaV2SQL, schemaV3SQL)
		})
		return append([]schemaObject(nil), schemaV3ContractObjects...), schemaV3ContractErr
	}
	if version == 4 {
		schemaV4ContractOnce.Do(func() {
			schemaV4ContractObjects, schemaV4ContractErr = buildExpectedSchemaObjects(schemaV1SQL, schemaV2SQL, schemaV3SQL, schemaV4SQL)
		})
		return append([]schemaObject(nil), schemaV4ContractObjects...), schemaV4ContractErr
	}
	if version == 5 {
		schemaV5ContractOnce.Do(func() {
			schemaV5ContractObjects, schemaV5ContractErr = buildExpectedSchemaObjects(schemaV1SQL, schemaV2SQL, schemaV3SQL, schemaV4SQL, schemaV5SQL)
		})
		return append([]schemaObject(nil), schemaV5ContractObjects...), schemaV5ContractErr
	}
	if version == 6 {
		schemaV6ContractOnce.Do(func() {
			schemaV6ContractObjects, schemaV6ContractErr = buildExpectedSchemaObjects(schemaV1SQL, schemaV2SQL, schemaV3SQL, schemaV4SQL, schemaV5SQL, schemaV6SQL)
		})
		return append([]schemaObject(nil), schemaV6ContractObjects...), schemaV6ContractErr
	}
	if version == 7 {
		schemaV7ContractOnce.Do(func() {
			schemaV7ContractObjects, schemaV7ContractErr = buildExpectedSchemaObjects(schemaV1SQL, schemaV2SQL, schemaV3SQL, schemaV4SQL, schemaV5SQL, schemaV6SQL, schemaV7SQL)
		})
		return append([]schemaObject(nil), schemaV7ContractObjects...), schemaV7ContractErr
	}
	if version == 8 {
		schemaV8ContractOnce.Do(func() {
			schemaV8ContractObjects, schemaV8ContractErr = buildExpectedSchemaObjects(schemaV1SQL, schemaV2SQL, schemaV3SQL, schemaV4SQL, schemaV5SQL, schemaV6SQL, schemaV7SQL, schemaV8SQL)
		})
		return append([]schemaObject(nil), schemaV8ContractObjects...), schemaV8ContractErr
	}
	if version == 9 {
		schemaV9ContractOnce.Do(func() {
			schemaV9ContractObjects, schemaV9ContractErr = buildExpectedSchemaObjects(schemaV1SQL, schemaV2SQL, schemaV3SQL, schemaV4SQL, schemaV5SQL, schemaV6SQL, schemaV7SQL, schemaV8SQL, schemaV9SQL)
		})
		return append([]schemaObject(nil), schemaV9ContractObjects...), schemaV9ContractErr
	}
	if version == 10 {
		schemaV10ContractOnce.Do(func() {
			schemaV10ContractObjects, schemaV10ContractErr = buildExpectedSchemaObjects(schemaV1SQL, schemaV2SQL, schemaV3SQL, schemaV4SQL, schemaV5SQL, schemaV6SQL, schemaV7SQL, schemaV8SQL, schemaV9SQL, schemaV10SQL)
		})
		return append([]schemaObject(nil), schemaV10ContractObjects...), schemaV10ContractErr
	}
	return nil, fmt.Errorf("unsupported schema contract version %d", version)
}

func buildExpectedSchemaObjects(schemas ...string) ([]schemaObject, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	for _, schema := range schemas {
		if _, err := db.Exec(schema); err != nil {
			return nil, err
		}
	}
	return readSchemaObjects(context.Background(), db)
}

func readSchemaObjects(ctx context.Context, db *sql.DB) ([]schemaObject, error) {
	rows, err := db.QueryContext(ctx, `
SELECT type, name, tbl_name, COALESCE(sql, '')
FROM sqlite_master
WHERE name NOT LIKE 'sqlite_%'
ORDER BY type, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	objects := []schemaObject{}
	for rows.Next() {
		var object schemaObject
		if err := rows.Scan(&object.Type, &object.Name, &object.Table, &object.SQL); err != nil {
			return nil, err
		}
		objects = append(objects, object)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return objects, nil
}

func sameSchemaObjects(left, right []schemaObject) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (s *Store) Check(ctx context.Context) error {
	if err := s.validateSchemaVersion(ctx, s.schemaVersion); err != nil {
		return err
	}
	if err := s.validateSemanticState(ctx); err != nil {
		return err
	}
	// Row-level package validation is intentionally part of the semantic DB
	// check. SQL constraints cannot express the source-derived pool path, and
	// SQLite's ordinary UNIQUE collation does not model case-insensitive host
	// filesystems.
	if err := s.validatePackageObjectRows(ctx); err != nil {
		return fmt.Errorf("%w: validate package objects: %v", ErrSchema, err)
	}
	var portableCollisions int64
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM (
SELECT lower(pool_path) FROM package_objects GROUP BY lower(pool_path) HAVING count(*) > 1
)`).Scan(&portableCollisions); err != nil {
		return fmt.Errorf("%w: inspect portable package paths: %v", ErrSchema, err)
	}
	if portableCollisions != 0 {
		return fmt.Errorf("%w: %d case-insensitive package Pool path collision(s)", ErrSchema, portableCollisions)
	}
	return nil
}

// validateSemanticState checks cross-table relations that SQLite foreign keys
// and column CHECK constraints cannot express.  It is read-only and keeps
// schema shape validation separate from repository history/filesystem checks.
func (s *Store) validateSemanticState(ctx context.Context) error {
	var singletonCount int64
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM repository_state WHERE singleton = 1`).Scan(&singletonCount); err != nil {
		return err
	}
	if singletonCount != 1 {
		return fmt.Errorf("%w: repository_state singleton count is %d", ErrSchema, singletonCount)
	}
	zeroGeneration := "'00000000000000000000'"
	if s.schemaVersion == 6 {
		zeroGeneration = "0"
	}
	checks := []struct {
		label string
		query string
	}{
		{
			"Dist revision or Generation exceeds Repository head",
			`SELECT count(*) FROM dists AS d CROSS JOIN repository_state AS r
WHERE r.singleton = 1 AND (d.desired_revision > r.desired_revision OR d.built_generation > r.built_generation)`,
		},
		{
			"Dist Built Generation is absent from retained ledger",
			fmt.Sprintf(`SELECT count(*) FROM dists AS d
WHERE d.built_generation > %s
  AND EXISTS (SELECT 1 FROM generations)
			  AND NOT EXISTS (SELECT 1 FROM generations AS g WHERE g.generation = d.built_generation)`, zeroGeneration),
		},
		{
			"Dist architecture Generation differs from owning Dist",
			`SELECT count(*) FROM dist_architectures AS a JOIN dists AS d ON d.name = a.dist_name
WHERE a.built_generation != d.built_generation`,
		},
		{
			"Built Membership Generation or storage differs from owning Dist",
			`SELECT count(*) FROM built_memberships AS b
JOIN dists AS d ON d.name = b.dist_name
JOIN package_objects AS p ON p.sha256 = b.package_sha256
CROSS JOIN repository_state AS r
WHERE r.singleton = 1 AND (b.generation != d.built_generation OR b.generation > r.built_generation OR p.storage != 'pool')`,
		},
		{
			"Prior Built Membership Generation or storage is invalid",
			fmt.Sprintf(`SELECT count(*) FROM prior_built_memberships AS b
JOIN dists AS d ON d.name = b.dist_name
JOIN package_objects AS p ON p.sha256 = b.package_sha256
CROSS JOIN repository_state AS r
WHERE r.singleton = 1 AND (b.generation >= d.built_generation OR b.generation > r.built_generation OR p.storage != 'pool'
  OR (b.generation > %s AND EXISTS (SELECT 1 FROM generations)
      AND NOT EXISTS (SELECT 1 FROM generations AS g WHERE g.generation = b.generation)))`, zeroGeneration),
		},
		{
			"Package Object creation revision exceeds Repository revision",
			`SELECT count(*) FROM package_objects AS p CROSS JOIN repository_state AS r
WHERE r.singleton = 1 AND p.created_revision > r.desired_revision`,
		},
		{
			"Desired Membership revision differs from owning Dist",
			`SELECT count(*) FROM memberships AS m
JOIN dists AS d ON d.name = m.dist_name
JOIN package_objects AS p ON p.sha256 = m.package_sha256
CROSS JOIN repository_state AS r
WHERE r.singleton = 1 AND (m.created_revision != d.desired_revision OR m.created_revision > r.desired_revision OR m.created_revision < p.created_revision)`,
		},
		{
			"Pending Package Object is unreferenced or already Built",
			`SELECT count(*) FROM package_objects AS p
WHERE p.storage = 'pending' AND (
  NOT EXISTS (SELECT 1 FROM memberships AS m WHERE m.package_sha256 = p.sha256)
  OR EXISTS (SELECT 1 FROM built_memberships AS b WHERE b.package_sha256 = p.sha256)
  OR EXISTS (SELECT 1 FROM prior_built_memberships AS b WHERE b.package_sha256 = p.sha256))`,
		},
	}
	issues := []error{}
	for _, check := range checks {
		var count int64
		if err := s.db.QueryRowContext(ctx, check.query).Scan(&count); err != nil {
			issues = append(issues, fmt.Errorf("%s: %w", check.label, err))
		} else if count != 0 {
			issues = append(issues, fmt.Errorf("%s (%d row(s))", check.label, count))
		}
	}
	var status string
	var reason sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT status, dirty_reason FROM repository_state WHERE singleton = 1`).Scan(&status, &reason); err != nil {
		issues = append(issues, err)
	} else {
		var projectionDirty int
		var activeOperations int
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM dists AS d
WHERE d.effective_config_sha256 != d.built_config_sha256
   OR EXISTS (SELECT package_sha256 FROM memberships WHERE dist_name = d.name
              EXCEPT SELECT package_sha256 FROM built_memberships WHERE dist_name = d.name)
   OR EXISTS (SELECT package_sha256 FROM built_memberships WHERE dist_name = d.name
              EXCEPT SELECT package_sha256 FROM memberships WHERE dist_name = d.name)
)`).Scan(&projectionDirty); err != nil {
			issues = append(issues, err)
		}
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE state NOT IN ('done', 'done_dirty', 'rolled_back', 'failed')`).Scan(&activeOperations); err != nil {
			issues = append(issues, err)
		} else if status == "clean" && projectionDirty != 0 || status == "dirty" && projectionDirty == 0 && activeOperations == 0 {
			issues = append(issues, fmt.Errorf("Repository status %s contradicts Desired/Built projection", status))
		}
		if status == "clean" && reason.Valid || status == "dirty" && (!reason.Valid || strings.TrimSpace(reason.String) == "") {
			issues = append(issues, fmt.Errorf("Repository status %s has inconsistent dirty_reason", status))
		}
	}
	if s.schemaVersion != 6 {
		identity, identityErr := s.RepositoryIdentity(ctx)
		if identityErr != nil {
			issues = append(issues, identityErr)
		} else {
			control, controlErr := s.LayoutTransitionControl(ctx)
			if controlErr != nil {
				issues = append(issues, controlErr)
			} else if control != nil {
				var head GenerationID
				headErr := s.db.QueryRowContext(ctx, `SELECT built_generation FROM repository_state WHERE singleton = 1`).Scan(&head)
				if headErr != nil || control.RepositoryID != identity.RepositoryID ||
					identity.LayoutVersion == LayoutC2V1 || identity.LayoutVersion == LayoutC2ToSingleV1 && head != control.BaseGeneration ||
					identity.LayoutVersion == LayoutSinglePayloadV1 && (identity.TransitionReceiptSHA256 == "" || control.CommitIntentAt == "") {
					issues = append(issues, errors.Join(errors.New("Repository layout transition control differs from identity/base/layout"), headErr))
				}
				if identity.LayoutVersion == LayoutSinglePayloadV1 && headErr == nil {
					var headManifest string
					manifestErr := s.db.QueryRowContext(ctx, `SELECT manifest_sha256 FROM generations WHERE generation = ?`, head).Scan(&headManifest)
					if manifestErr != nil || headManifest != control.TargetManifestSHA256 {
						issues = append(issues, errors.Join(errors.New("Repository layout transition control target differs from head Generation"), manifestErr))
					}
				}
			} else if identity.LayoutVersion == LayoutSinglePayloadV1 && identity.TransitionReceiptSHA256 != "" {
				issues = append(issues, errors.New("migrated Repository has no layout transition control anchor"))
			}
			if identity.LayoutVersion != LayoutSinglePayloadV1 && identity.TransitionReceiptSHA256 != "" {
				issues = append(issues, errors.New("non-terminal Repository layout has a transition receipt"))
			}
			var migrationCount int64
			if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE kind = 'layout.migrate' AND state = 'done'`).Scan(&migrationCount); err != nil {
				issues = append(issues, err)
			} else if migrationCount > 1 {
				issues = append(issues, fmt.Errorf("Repository has %d completed layout migrations", migrationCount))
			} else if migrationCount == 0 {
				if identity.TransitionReceiptSHA256 != "" {
					issues = append(issues, errors.New("Repository transition receipt has no completed layout migration"))
				}
			} else {
				var operationID, payload string
				if err := s.db.QueryRowContext(ctx, `SELECT id, payload_json FROM operations WHERE kind = 'layout.migrate' AND state = 'done'`).Scan(&operationID, &payload); err != nil {
					issues = append(issues, err)
				} else {
					var wire struct {
						BaseGeneration          GenerationID `json:"base_generation"`
						TargetGeneration        GenerationID `json:"target_generation"`
						TransitionReceiptSHA256 string       `json:"transition_receipt_sha256"`
					}
					decoder := json.NewDecoder(strings.NewReader(payload))
					decoder.DisallowUnknownFields()
					decodeErr := decoder.Decode(&wire)
					var trailing any
					trailingErr := decoder.Decode(&trailing)
					var head GenerationID
					headErr := s.db.QueryRowContext(ctx, `SELECT built_generation FROM repository_state WHERE singleton = 1`).Scan(&head)
					next, nextErr := wire.BaseGeneration.Next()
					var generationLinkCount int64
					linkErr := s.db.QueryRowContext(ctx, `SELECT count(*) FROM generations WHERE operation_id = ? AND generation = ? AND previous_generation = ?`, operationID, wire.TargetGeneration, wire.BaseGeneration).Scan(&generationLinkCount)
					if decodeErr != nil || trailingErr != io.EOF || headErr != nil ||
						identity.LayoutVersion != LayoutSinglePayloadV1 || identity.TransitionReceiptSHA256 == "" ||
						wire.TransitionReceiptSHA256 != identity.TransitionReceiptSHA256 || wire.TargetGeneration != head ||
						nextErr != nil || wire.TargetGeneration != next || linkErr != nil || generationLinkCount != 1 {
						issues = append(issues, errors.Join(errors.New("Repository layout migration identity/layout/receipt/generation coupling is invalid"), decodeErr, headErr, nextErr, linkErr))
					}
				}
			}
		}
	}
	if len(issues) != 0 {
		return fmt.Errorf("%w: semantic state relations are invalid: %v", ErrConflict, errors.Join(issues...))
	}
	return nil
}

// Checkpoint copies every committed WAL frame into the main database. A
// concurrent read snapshot may legitimately prevent the final TRUNCATE while
// all frames are already checkpointed; that is deferred maintenance, not a
// failed committed mutation.
func (s *Store) Checkpoint(ctx context.Context) error {
	var busy, logFrames, checkpointed int
	if err := s.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); err != nil {
		return fmt.Errorf("checkpoint repository state: %w", err)
	}
	if logFrames != checkpointed {
		return fmt.Errorf("checkpoint repository state incomplete: busy=%d log=%d checkpointed=%d", busy, logFrames, checkpointed)
	}
	return nil
}

func (s *Store) Summary(ctx context.Context) (RepositorySummary, error) {
	var out RepositorySummary
	var dirty sql.NullString
	err := s.db.QueryRowContext(ctx, `
SELECT desired_revision, built_generation, status, dirty_reason,
       (SELECT count(*) FROM dists),
       (SELECT count(*) FROM package_objects),
       (SELECT count(*) FROM memberships)
FROM repository_state WHERE singleton = 1`).Scan(
		&out.DesiredRevision, &out.BuiltGeneration, &out.Status, &dirty,
		&out.DistCount, &out.PackageCount, &out.MembershipCount,
	)
	if err != nil {
		return RepositorySummary{}, fmt.Errorf("read repository state: %w", err)
	}
	if dirty.Valid {
		out.DirtyReason = dirty.String
	}
	return out, nil
}

func (s *Store) ListDists(ctx context.Context) ([]Dist, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT d.name, d.format, d.effective_config_sha256, d.built_generation,
       COALESCE(s.fingerprint, ''), COALESCE(s.public_key, X''), d.effective_signing_json
FROM dists AS d
LEFT JOIN dist_metadata_signers AS s ON s.dist_name = d.name
ORDER BY d.name`)
	if err != nil {
		return nil, fmt.Errorf("list dists: %w", err)
	}
	defer rows.Close()
	var out []Dist
	for rows.Next() {
		var dist Dist
		if err := rows.Scan(&dist.Name, &dist.Format, &dist.EffectiveConfigSHA256, &dist.BuiltGeneration, &dist.MetadataSignerFingerprint, &dist.MetadataSignerPublicKey, &dist.EffectiveSigningJSON); err != nil {
			return nil, fmt.Errorf("scan dist: %w", err)
		}
		out = append(out, dist)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list dists: %w", err)
	}
	for index := range out {
		architectures, err := s.distArchitectures(ctx, out[index].Name)
		if err != nil {
			return nil, err
		}
		out[index].Architectures = architectures
	}
	if out == nil {
		out = []Dist{}
	}
	return out, nil
}

func (s *Store) GetDist(ctx context.Context, name string) (Dist, error) {
	var out Dist
	err := s.db.QueryRowContext(ctx, `
SELECT d.name, d.format, d.effective_config_sha256, d.built_generation,
       COALESCE(s.fingerprint, ''), COALESCE(s.public_key, X''), d.effective_signing_json
FROM dists AS d
LEFT JOIN dist_metadata_signers AS s ON s.dist_name = d.name
WHERE d.name = ?`, name).Scan(
		&out.Name, &out.Format, &out.EffectiveConfigSHA256, &out.BuiltGeneration, &out.MetadataSignerFingerprint, &out.MetadataSignerPublicKey, &out.EffectiveSigningJSON,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Dist{}, fmt.Errorf("%w: dist %q", ErrNotFound, name)
	}
	if err != nil {
		return Dist{}, fmt.Errorf("read dist %q: %w", name, err)
	}
	out.Architectures, err = s.distArchitectures(ctx, name)
	if err != nil {
		return Dist{}, err
	}
	return out, nil
}

func (s *Store) distArchitectures(ctx context.Context, name string) ([]Architecture, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT family, ecosystem_arch FROM dist_architectures WHERE dist_name = ? ORDER BY CASE family WHEN 'x86_64' THEN 0 WHEN 'aarch64' THEN 1 ELSE 2 END, family`, name)
	if err != nil {
		return nil, fmt.Errorf("list architectures for dist %q: %w", name, err)
	}
	defer rows.Close()
	architectures := []Architecture{}
	for rows.Next() {
		var architecture Architecture
		if err := rows.Scan(&architecture.Family, &architecture.EcosystemArch); err != nil {
			return nil, fmt.Errorf("scan architecture for dist %q: %w", name, err)
		}
		architectures = append(architectures, architecture)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list architectures for dist %q: %w", name, err)
	}
	return architectures, nil
}

func (s *Store) AddDist(ctx context.Context, dist Dist) error {
	if dist.Name == "" || dist.Format != "rpm" && dist.Format != "deb" {
		return fmt.Errorf("invalid dist state")
	}
	architectures := append([]Architecture(nil), dist.Architectures...)
	effectiveSigning, err := normalizeEffectiveSigningJSON(dist.EffectiveSigningJSON)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin dist add: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO dists(name, format, effective_config_sha256, built_config_sha256, built_generation, effective_signing_json) VALUES (?, ?, ?, ?, ?, ?)`, dist.Name, dist.Format, dist.EffectiveConfigSHA256, dist.EffectiveConfigSHA256, dist.BuiltGeneration, effectiveSigning); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("%w: dist %q", ErrExists, dist.Name)
		}
		return fmt.Errorf("insert dist %q: %w", dist.Name, err)
	}
	if err := replaceDistMetadataSignerTx(ctx, tx, dist); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, architecture := range architectures {
		if _, duplicate := seen[architecture.Family]; duplicate {
			return fmt.Errorf("duplicate architecture %q", architecture.Family)
		}
		seen[architecture.Family] = struct{}{}
		if _, err := tx.ExecContext(ctx, `INSERT INTO dist_architectures(dist_name, family, ecosystem_arch, built_generation) VALUES (?, ?, ?, ?)`, dist.Name, architecture.Family, architecture.EcosystemArch, dist.BuiltGeneration); err != nil {
			return fmt.Errorf("insert architecture %q for dist %q: %w", architecture.Family, dist.Name, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE repository_state SET built_generation = max(built_generation, ?), status = 'clean', dirty_reason = NULL WHERE singleton = 1`, dist.BuiltGeneration); err != nil {
		return fmt.Errorf("advance repository generation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit dist add: %w", err)
	}
	return s.Checkpoint(ctx)
}

func (s *Store) RemoveDist(ctx context.Context, name string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM dists WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("remove dist %q: %w", name, err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("remove dist %q: %w", name, err)
	}
	if count == 0 {
		return fmt.Errorf("%w: dist %q", ErrNotFound, name)
	}
	return s.Checkpoint(ctx)
}

func (s *Store) CountsForDist(ctx context.Context, name string) (DistCounts, error) {
	var exists int
	var counts DistCounts
	err := s.db.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM dists WHERE name = ?),
       (SELECT count(*) FROM memberships WHERE dist_name = ?),
       (SELECT count(*) FROM built_memberships WHERE dist_name = ?)`, name, name, name).Scan(&exists, &counts.Memberships, &counts.BuiltMemberships)
	if err != nil {
		return DistCounts{}, fmt.Errorf("count dist %q state: %w", name, err)
	}
	if exists == 0 {
		return DistCounts{}, fmt.Errorf("%w: dist %q", ErrNotFound, name)
	}
	return counts, nil
}

// FinalizeDistAdd atomically installs the SQL projection and marks a built
// operation done. File/config publication must already have reached its
// durable built phase under the repository lock.
func (s *Store) FinalizeDistAdd(ctx context.Context, operationID string, dist Dist, manifest []GenerationFile, changes []FileChange) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin dist add finalization: %w", err)
	}
	defer tx.Rollback()
	state, err := operationStateTx(ctx, tx, operationID)
	if err != nil {
		return err
	}
	if state == OperationDone {
		return nil
	}
	if state != OperationBuilt {
		return fmt.Errorf("%w: finalize dist add from %s", ErrTransition, state)
	}
	if err := recordGenerationTx(ctx, tx, operationID, dist.BuiltGeneration, manifest, changes); err != nil {
		return err
	}
	if err := insertDistTx(ctx, tx, dist); err != nil {
		return err
	}
	if err := advanceGenerationTx(ctx, tx, dist.BuiltGeneration); err != nil {
		return err
	}
	if err := setOperationStateTx(ctx, tx, operationID, OperationDone, "", ""); err != nil {
		return fmt.Errorf("complete dist add operation %q: %w", operationID, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit dist add finalization: %w", err)
	}
	return s.Checkpoint(ctx)
}

// FinalizeDistRemoval preserves the original error-only API used by P1 state
// callers. Managed lifecycle code uses FinalizeDistRemovalAndCollect so it can
// durably remove private pending bytes made unreachable by the Dist cascade.
func (s *Store) FinalizeDistRemoval(ctx context.Context, operationID, name string, generation GenerationID, manifest []GenerationFile, changes []FileChange) error {
	_, err := s.FinalizeDistRemovalAndCollect(ctx, operationID, name, generation, manifest, changes)
	return err
}

// FinalizeDistRemovalAndCollect removes the Dist projection but never deletes
// public Pool objects. Pending objects that lose their final Membership are
// removed from SQLite in the same transaction and returned in result_json so
// filesystem cleanup remains idempotently recoverable after a process stop.
func (s *Store) FinalizeDistRemovalAndCollect(ctx context.Context, operationID, name string, generation GenerationID, manifest []GenerationFile, changes []FileChange) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin dist removal finalization: %w", err)
	}
	defer tx.Rollback()
	state, err := operationStateTx(ctx, tx, operationID)
	if err != nil {
		return nil, err
	}
	if state == OperationDone {
		var resultJSON string
		if err := tx.QueryRowContext(ctx, `SELECT result_json FROM operations WHERE id = ?`, operationID).Scan(&resultJSON); err != nil {
			return nil, err
		}
		return decodeDistRemovalResult(resultJSON)
	}
	if state != OperationBuilt {
		return nil, fmt.Errorf("%w: finalize dist removal from %s", ErrTransition, state)
	}
	if err := recordGenerationTx(ctx, tx, operationID, generation, manifest, changes); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM operation_memberships WHERE operation_id = ?`, operationID); err != nil {
		return nil, fmt.Errorf("reset dist removal membership audit: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT package_sha256 FROM memberships WHERE dist_name = ? ORDER BY package_sha256`, name)
	if err != nil {
		return nil, fmt.Errorf("list dist %q removal memberships: %w", name, err)
	}
	removed := []string{}
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			rows.Close()
			return nil, err
		}
		removed = append(removed, digest)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	for sequence, digest := range removed {
		if _, err := tx.ExecContext(ctx, `INSERT INTO operation_memberships(operation_id, sequence, dist_name, package_sha256, action) VALUES (?, ?, ?, ?, 'remove')`, operationID, sequence, name, digest); err != nil {
			return nil, fmt.Errorf("record dist %q removal membership: %w", name, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM dists WHERE name = ?`, name); err != nil {
		return nil, fmt.Errorf("remove dist %q state: %w", name, err)
	}
	droppedPending := []string{}
	rows, err = tx.QueryContext(ctx, `SELECT sha256 FROM package_objects WHERE storage = 'pending' AND NOT EXISTS (SELECT 1 FROM memberships WHERE memberships.package_sha256 = package_objects.sha256) ORDER BY sha256`)
	if err != nil {
		return nil, fmt.Errorf("list unreachable pending objects after Dist removal: %w", err)
	}
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			rows.Close()
			return nil, err
		}
		droppedPending = append(droppedPending, digest)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	for _, digest := range droppedPending {
		if _, err := tx.ExecContext(ctx, `DELETE FROM package_objects WHERE sha256 = ?`, digest); err != nil {
			return nil, fmt.Errorf("remove unreachable pending object %s: %w", digest, err)
		}
	}
	resultJSON, err := json.Marshal(struct {
		DroppedPending []string `json:"dropped_pending"`
	}{DroppedPending: droppedPending})
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET result_json = ? WHERE id = ?`, string(resultJSON), operationID); err != nil {
		return nil, fmt.Errorf("record Dist removal pending cleanup: %w", err)
	}
	if err := advanceGenerationTx(ctx, tx, generation); err != nil {
		return nil, err
	}
	if err := setOperationStateTx(ctx, tx, operationID, OperationDone, "", ""); err != nil {
		return nil, fmt.Errorf("complete dist removal operation %q: %w", operationID, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit dist removal finalization: %w", err)
	}
	if err := s.Checkpoint(ctx); err != nil {
		return nil, err
	}
	return droppedPending, nil
}

func decodeDistRemovalResult(data string) ([]string, error) {
	var result struct {
		DroppedPending []string `json:"dropped_pending"`
	}
	dec := json.NewDecoder(strings.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result); err != nil {
		return nil, fmt.Errorf("decode Dist removal result: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, errors.New("Dist removal result has trailing content")
	}
	for _, digest := range result.DroppedPending {
		if !validSHA256Text(digest) {
			return nil, errors.New("Dist removal result has invalid pending digest")
		}
	}
	return result.DroppedPending, nil
}

func operationStateTx(ctx context.Context, tx *sql.Tx, id string) (OperationState, error) {
	var current string
	err := tx.QueryRowContext(ctx, `SELECT state FROM operations WHERE id = ?`, id).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: operation %q", ErrNotFound, id)
	}
	if err != nil {
		return "", fmt.Errorf("read operation %q: %w", id, err)
	}
	return OperationState(current), nil
}

func insertDistTx(ctx context.Context, tx *sql.Tx, dist Dist) error {
	if dist.Name == "" || dist.Format != "rpm" && dist.Format != "deb" {
		return fmt.Errorf("invalid dist state")
	}
	effectiveSigning, err := normalizeEffectiveSigningJSON(dist.EffectiveSigningJSON)
	if err != nil {
		return err
	}
	var existingFormat, existingHash, existingSigning string
	var existingGeneration GenerationID
	err = tx.QueryRowContext(ctx, `SELECT format, effective_config_sha256, built_generation, effective_signing_json FROM dists WHERE name = ?`, dist.Name).Scan(&existingFormat, &existingHash, &existingGeneration, &existingSigning)
	if err == nil {
		if existingFormat == dist.Format && existingHash == dist.EffectiveConfigSHA256 && existingGeneration == dist.BuiltGeneration && existingSigning == effectiveSigning {
			return nil
		}
		return fmt.Errorf("%w: dist %q exists with different state", ErrExists, dist.Name)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("inspect dist %q: %w", dist.Name, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO dists(name, format, effective_config_sha256, built_config_sha256, built_generation, effective_signing_json) VALUES (?, ?, ?, ?, ?, ?)`, dist.Name, dist.Format, dist.EffectiveConfigSHA256, dist.EffectiveConfigSHA256, dist.BuiltGeneration, effectiveSigning); err != nil {
		return fmt.Errorf("insert dist %q: %w", dist.Name, err)
	}
	if err := replaceDistMetadataSignerTx(ctx, tx, dist); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, architecture := range dist.Architectures {
		if _, duplicate := seen[architecture.Family]; duplicate {
			return fmt.Errorf("duplicate architecture %q", architecture.Family)
		}
		seen[architecture.Family] = struct{}{}
		if _, err := tx.ExecContext(ctx, `INSERT INTO dist_architectures(dist_name, family, ecosystem_arch, built_generation) VALUES (?, ?, ?, ?)`, dist.Name, architecture.Family, architecture.EcosystemArch, dist.BuiltGeneration); err != nil {
			return fmt.Errorf("insert architecture %q for dist %q: %w", architecture.Family, dist.Name, err)
		}
	}
	return nil
}

func normalizeEffectiveSigningJSON(value string) (string, error) {
	if value == "" {
		value = "{}"
	}
	if len(value) < 2 || len(value) > MaxOperationPayloadBytes || !json.Valid([]byte(value)) {
		return "", errors.New("invalid effective signing snapshot")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value), &object); err != nil || object == nil {
		return "", errors.New("effective signing snapshot must be a JSON object")
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		return "", err
	}
	return string(canonical), nil
}

func replaceDistMetadataSignerTx(ctx context.Context, tx *sql.Tx, dist Dist) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM dist_metadata_signers WHERE dist_name = ?`, dist.Name); err != nil {
		return fmt.Errorf("clear metadata signer for Dist %q: %w", dist.Name, err)
	}
	if dist.MetadataSignerFingerprint == "" && len(dist.MetadataSignerPublicKey) == 0 {
		return nil
	}
	if !metadataFingerprintPattern.MatchString(dist.MetadataSignerFingerprint) || len(dist.MetadataSignerPublicKey) == 0 || len(dist.MetadataSignerPublicKey) > 16<<20 {
		return fmt.Errorf("invalid metadata signer state for Dist %q", dist.Name)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO dist_metadata_signers(dist_name, fingerprint, public_key) VALUES (?, ?, ?)`, dist.Name, dist.MetadataSignerFingerprint, dist.MetadataSignerPublicKey); err != nil {
		return fmt.Errorf("record metadata signer for Dist %q: %w", dist.Name, err)
	}
	return nil
}

func advanceGenerationTx(ctx context.Context, tx *sql.Tx, generation GenerationID) error {
	if _, err := tx.ExecContext(ctx, `UPDATE repository_state SET built_generation = max(built_generation, ?), status = 'clean', dirty_reason = NULL WHERE singleton = 1`, generation); err != nil {
		return fmt.Errorf("advance repository generation: %w", err)
	}
	return nil
}

func (s *Store) ReferencedArchitectures(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT family FROM dist_architectures ORDER BY CASE family WHEN 'x86_64' THEN 0 WHEN 'aarch64' THEN 1 ELSE 2 END, family`)
	if err != nil {
		return nil, fmt.Errorf("list referenced architectures: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var family string
		if err := rows.Scan(&family); err != nil {
			return nil, fmt.Errorf("scan referenced architecture: %w", err)
		}
		out = append(out, family)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list referenced architectures: %w", err)
	}
	return out, nil
}

// ArchitectureReferences returns every CPU-architecture-bearing state edge.
// Package architectures are deliberately left in ecosystem spelling so the
// control plane can apply the format-specific canonical/neutral mapping.
func (s *Store) ArchitectureReferences(ctx context.Context) ([]ArchitectureReference, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT d.name, d.format, da.family, 'built generation'
FROM dist_architectures AS da
JOIN dists AS d ON d.name = da.dist_name
UNION ALL
SELECT d.name, d.format, p.architecture, 'membership'
FROM memberships AS m
JOIN dists AS d ON d.name = m.dist_name
JOIN package_objects AS p ON p.sha256 = m.package_sha256
ORDER BY 1, 4, 3`)
	if err != nil {
		return nil, fmt.Errorf("list architecture references: %w", err)
	}
	defer rows.Close()
	refs := []ArchitectureReference{}
	for rows.Next() {
		var ref ArchitectureReference
		if err := rows.Scan(&ref.Dist, &ref.Format, &ref.Architecture, &ref.Source); err != nil {
			return nil, fmt.Errorf("scan architecture reference: %w", err)
		}
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list architecture references: %w", err)
	}
	return refs, nil
}

func (s *Store) BeginOperation(ctx context.Context, operation Operation) error {
	if err := s.RequireTerminalLayout(ctx); err != nil {
		return err
	}
	if !operationIDPattern.MatchString(operation.ID) || operation.Kind == "" || !validOperationState(operation.State) || isTerminal(operation.State) {
		return fmt.Errorf("invalid operation")
	}
	if err := validateOperationPayload(operation.PayloadJSON); err != nil {
		return err
	}
	if operation.ResultJSON == "" {
		operation.ResultJSON = `{}`
	}
	if err := validateOperationPayload(operation.ResultJSON); err != nil {
		return fmt.Errorf("invalid operation result: %w", err)
	}
	now := nowText()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin operation %q: %w", operation.ID, err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, error_class, error_message, created_at, updated_at) VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?)`, operation.ID, operation.Kind, string(operation.State), operation.PayloadJSON, operation.ResultJSON, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("%w: operation %q", ErrExists, operation.ID)
		}
		return fmt.Errorf("begin operation %q: %w", operation.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operation_events(operation_id, sequence, state, detail_json, occurred_at) VALUES (?, 0, ?, '{}', ?)`, operation.ID, string(operation.State), now); err != nil {
		return fmt.Errorf("record operation %q start: %w", operation.ID, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit operation %q start: %w", operation.ID, err)
	}
	return s.Checkpoint(ctx)
}

func (s *Store) SetOperationState(ctx context.Context, id string, next OperationState, errorClass string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin operation %q transition: %w", id, err)
	}
	defer tx.Rollback()
	if err := setOperationStateTx(ctx, tx, id, next, errorClass, ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit operation %q transition: %w", id, err)
	}
	return s.Checkpoint(ctx)
}

// FailOperation atomically records the bounded public result and terminal
// failure reason for an operation that was rejected before any Desired or
// public state was applied. Interrupted processes deliberately do not call
// this path; their non-terminal journal remains available to recovery.
func (s *Store) FailOperation(ctx context.Context, id, errorClass, errorMessage, resultJSON string) error {
	if errorClass == "" || errorMessage == "" {
		return errors.New("operation failure requires class and message")
	}
	if err := validateOperationPayload(resultJSON); err != nil {
		return fmt.Errorf("invalid operation failure result: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin operation %q failure: %w", id, err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET result_json = ? WHERE id = ?`, resultJSON, id); err != nil {
		return fmt.Errorf("record operation %q failure result: %w", id, err)
	}
	if err := setOperationStateTx(ctx, tx, id, OperationFailed, errorClass, errorMessage); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit operation %q failure: %w", id, err)
	}
	return s.Checkpoint(ctx)
}

func setOperationStateTx(ctx context.Context, tx *sql.Tx, id string, next OperationState, errorClass, errorMessage string) error {
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM operations WHERE id = ?`, id).Scan(&current); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: operation %q", ErrNotFound, id)
	} else if err != nil {
		return fmt.Errorf("read operation %q: %w", id, err)
	}
	from := OperationState(current)
	if from == next {
		return nil
	}
	if !canTransition(from, next) {
		return fmt.Errorf("%w: %s -> %s", ErrTransition, from, next)
	}
	var errorValue, messageValue any
	if errorClass != "" {
		errorValue = errorClass
	}
	if errorMessage != "" {
		messageValue = errorMessage
	}
	now := nowText()
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET state = ?, error_class = ?, error_message = ?, updated_at = ? WHERE id = ?`, string(next), errorValue, messageValue, now, id); err != nil {
		return fmt.Errorf("update operation %q: %w", id, err)
	}
	var sequence int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(max(sequence), -1) + 1 FROM operation_events WHERE operation_id = ?`, id).Scan(&sequence); err != nil {
		return fmt.Errorf("sequence operation %q event: %w", id, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operation_events(operation_id, sequence, state, detail_json, occurred_at) VALUES (?, ?, ?, '{}', ?)`, id, sequence, string(next), now); err != nil {
		return fmt.Errorf("record operation %q transition: %w", id, err)
	}
	return nil
}

func (s *Store) UpdateOperationResult(ctx context.Context, id, resultJSON string) error {
	if err := validateOperationPayload(resultJSON); err != nil {
		return fmt.Errorf("invalid operation result: %w", err)
	}
	result, err := s.db.ExecContext(ctx, `UPDATE operations SET result_json = ?, updated_at = ? WHERE id = ?`, resultJSON, nowText(), id)
	if err != nil {
		return fmt.Errorf("update operation %q result: %w", id, err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return fmt.Errorf("%w: operation %q", ErrNotFound, id)
	}
	return s.Checkpoint(ctx)
}

// RecordOperationProgress appends an audit event without changing the durable
// operation state. Long-running build phases use the current state plus a
// structured detail object so observers can distinguish rendering, payload
// promotion, pointer publication, normalization, and finalization.
//
// Unlike every state transition, progress deliberately does not checkpoint. It
// advances no state machine and gates no physical decision, so a build must
// never pay one WAL truncation per rendered Dist, and a busy checkpoint must
// never be able to fail an otherwise complete build from pure telemetry. The
// committed event is already durable in the WAL and the next transition folds
// it back into the database.
func (s *Store) RecordOperationProgress(ctx context.Context, id, detailJSON string) error {
	if err := validateOperationPayload(detailJSON); err != nil {
		return fmt.Errorf("invalid operation progress: %w", err)
	}
	var detail map[string]json.RawMessage
	if err := json.Unmarshal([]byte(detailJSON), &detail); err != nil || detail == nil {
		return errors.New("operation progress must be a JSON object")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin operation %q progress: %w", id, err)
	}
	defer tx.Rollback()
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM operations WHERE id = ?`, id).Scan(&current); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: operation %q", ErrNotFound, id)
	} else if err != nil {
		return fmt.Errorf("read operation %q progress state: %w", id, err)
	}
	operationState := OperationState(current)
	if !validOperationState(operationState) || isTerminal(operationState) {
		return fmt.Errorf("%w: cannot record progress in state %s", ErrTransition, current)
	}
	var sequence int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(max(sequence), -1) + 1 FROM operation_events WHERE operation_id = ?`, id).Scan(&sequence); err != nil {
		return fmt.Errorf("sequence operation %q progress: %w", id, err)
	}
	now := nowText()
	if _, err := tx.ExecContext(ctx, `INSERT INTO operation_events(operation_id, sequence, state, detail_json, occurred_at) VALUES (?, ?, ?, ?, ?)`, id, sequence, current, detailJSON, now); err != nil {
		return fmt.Errorf("record operation %q progress: %w", id, err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET updated_at = ? WHERE id = ?`, now, id); err != nil {
		return fmt.Errorf("update operation %q progress time: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit operation %q progress: %w", id, err)
	}
	return nil
}

// UpdateOperationPayload durably enriches an operation before its public-file
// commit decision. Applied mutation operations may add verified build-tree
// evidence before any Pool or Dist publication begins.
func (s *Store) UpdateOperationPayload(ctx context.Context, id, payloadJSON string) error {
	if err := validateOperationPayload(payloadJSON); err != nil {
		return err
	}
	var current string
	if err := s.db.QueryRowContext(ctx, `SELECT state FROM operations WHERE id = ?`, id).Scan(&current); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: operation %q", ErrNotFound, id)
	} else if err != nil {
		return fmt.Errorf("read operation %q: %w", id, err)
	}
	if OperationState(current) != OperationPlanned && OperationState(current) != OperationStaged && OperationState(current) != OperationApplied {
		return fmt.Errorf("%w: cannot update payload in state %s", ErrTransition, current)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE operations SET payload_json = ?, updated_at = ? WHERE id = ?`, payloadJSON, nowText(), id); err != nil {
		return fmt.Errorf("update operation %q payload: %w", id, err)
	}
	return s.Checkpoint(ctx)
}

func validateOperationPayload(payloadJSON string) error {
	if len(payloadJSON) > MaxOperationPayloadBytes {
		return fmt.Errorf("operation payload exceeds %d bytes", MaxOperationPayloadBytes)
	}
	if !json.Valid([]byte(payloadJSON)) {
		return errors.New("operation payload is not valid JSON")
	}
	return nil
}

func (s *Store) PendingOperations(ctx context.Context) ([]Operation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, state, payload_json, result_json, error_class, error_message, created_at, updated_at FROM operations WHERE state NOT IN ('done', 'done_dirty', 'rolled_back', 'failed') ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("list pending operations: %w", err)
	}
	defer rows.Close()
	out := []Operation{}
	for rows.Next() {
		operation, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, operation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list pending operations: %w", err)
	}
	return out, nil
}

// DoneOperations returns terminal operations whose private stage or recovery
// directories may still require idempotent cleanup after a process died
// between SQL finalization and filesystem cleanup.
func (s *Store) DoneOperations(ctx context.Context) ([]Operation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, state, payload_json, result_json, error_class, error_message, created_at, updated_at FROM operations WHERE state IN ('done', 'done_dirty') ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("list completed operations: %w", err)
	}
	defer rows.Close()
	out := []Operation{}
	for rows.Next() {
		operation, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, operation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list completed operations: %w", err)
	}
	return out, nil
}

func (s *Store) LastOperation(ctx context.Context) (*Operation, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, kind, state, payload_json, result_json, error_class, error_message, created_at, updated_at FROM operations ORDER BY created_at DESC, id DESC LIMIT 1`)
	operation, err := scanOperation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &operation, nil
}

func (s *Store) LastTerminalOperation(ctx context.Context) (*Operation, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, kind, state, payload_json, result_json, error_class, error_message, created_at, updated_at FROM operations WHERE state IN ('done', 'done_dirty', 'rolled_back', 'failed') ORDER BY created_at DESC, id DESC LIMIT 1`)
	operation, err := scanOperation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &operation, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanOperation(row rowScanner) (Operation, error) {
	var out Operation
	var state, created, updated string
	var errorClass, errorMessage sql.NullString
	if err := row.Scan(&out.ID, &out.Kind, &state, &out.PayloadJSON, &out.ResultJSON, &errorClass, &errorMessage, &created, &updated); err != nil {
		return Operation{}, fmt.Errorf("scan operation: %w", err)
	}
	out.State = OperationState(state)
	out.ErrorClass = errorClass.String
	out.ErrorMessage = errorMessage.String
	var err error
	out.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return Operation{}, fmt.Errorf("parse operation created_at: %w", err)
	}
	out.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return Operation{}, fmt.Errorf("parse operation updated_at: %w", err)
	}
	return out, nil
}

func validOperationState(state OperationState) bool {
	switch state {
	case OperationPlanned, OperationStaged, OperationApplied, OperationBuilt, OperationDone, OperationDoneDirty, OperationRecovering, OperationRolledBack, OperationFailed:
		return true
	default:
		return false
	}
}

func isTerminal(state OperationState) bool {
	return state == OperationDone || state == OperationDoneDirty || state == OperationRolledBack || state == OperationFailed
}

func canTransition(from, to OperationState) bool {
	switch from {
	case OperationPlanned:
		return to == OperationStaged || to == OperationRecovering || to == OperationRolledBack || to == OperationFailed
	case OperationStaged:
		return to == OperationApplied || to == OperationRecovering || to == OperationRolledBack || to == OperationFailed
	case OperationApplied:
		return to == OperationBuilt || to == OperationDone || to == OperationDoneDirty || to == OperationRecovering || to == OperationFailed
	case OperationBuilt:
		return to == OperationDone || to == OperationRecovering || to == OperationFailed
	case OperationRecovering:
		return to == OperationApplied || to == OperationBuilt || to == OperationDone || to == OperationDoneDirty || to == OperationRolledBack || to == OperationFailed
	default:
		return false
	}
}

func normalizeOperationTimestamps(ctx context.Context, tx *sql.Tx) error {
	type timestampRow struct {
		id      string
		created string
		updated string
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, created_at, updated_at FROM operations`)
	if err != nil {
		return err
	}
	values := []timestampRow{}
	for rows.Next() {
		var value timestampRow
		if err := rows.Scan(&value.id, &value.created, &value.updated); err != nil {
			_ = rows.Close()
			return err
		}
		values = append(values, value)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, value := range values {
		created, err := time.Parse(time.RFC3339Nano, value.created)
		if err != nil {
			return fmt.Errorf("operation %q has invalid created_at: %w", value.id, err)
		}
		updated, err := time.Parse(time.RFC3339Nano, value.updated)
		if err != nil {
			return fmt.Errorf("operation %q has invalid updated_at: %w", value.id, err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE operations SET created_at = ?, updated_at = ? WHERE id = ?`, formatTimestamp(created), formatTimestamp(updated), value.id); err != nil {
			return err
		}
	}
	return nil
}

func validateOperationTimestamps(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT id, created_at, updated_at FROM operations`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, createdText, updatedText string
		if err := rows.Scan(&id, &createdText, &updatedText); err != nil {
			return err
		}
		created, createdErr := time.Parse(time.RFC3339Nano, createdText)
		updated, updatedErr := time.Parse(time.RFC3339Nano, updatedText)
		if createdErr != nil || updatedErr != nil || createdText != formatTimestamp(created) || updatedText != formatTimestamp(updated) {
			return fmt.Errorf("operation %q has non-canonical timestamps", id)
		}
	}
	return rows.Err()
}

const fixedTimestampLayout = "2006-01-02T15:04:05.000000000Z"

func formatTimestamp(at time.Time) string { return at.UTC().Format(fixedTimestampLayout) }

func nowText() string { return formatTimestamp(time.Now()) }
