package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"modernc.org/libc"
	sqlite3 "modernc.org/sqlite/lib"
)

// Darwin releases this process's POSIX locks when a separate descriptor for the
// same inode closes, including O_EVTONLY descriptors. Let the same SQLite VFS
// own this no-query connection so its deferred-close accounting preserves locks
// while the guard pins the inode until the actual connection has opened.
// https://www.sqlite.org/howtocorrupt.html#_posix_advisory_locks_canceled_by_a_separate_thread_doing_close_
type sqliteDatabaseGuard struct {
	tls          *libc.TLS
	db           uintptr
	path         string
	physicalPath string
}

func bindDatabaseFile(path string, mustExist bool) (*sqliteDatabaseGuard, os.FileInfo, bool, error) {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && !mustExist {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("bind repository sqlite: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, nil, false, errors.New("bind repository sqlite: database is not a private single-link regular file")
	}
	if err := requirePrivateRegularPath(path); err != nil {
		return nil, nil, false, err
	}
	// SQLITE_OPEN_NOFOLLOW also rejects parent symlinks. Resolve only the parent
	// first so ordinary aliases such as Darwin's /tmp and /var remain supported.
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, nil, false, err
	}
	guard := &sqliteDatabaseGuard{tls: libc.NewTLS(), path: path, physicalPath: filepath.Join(parent, filepath.Base(path))}
	if err := guard.open(); err != nil {
		closeErr := guard.Close()
		return nil, nil, false, errors.Join(err, closeErr)
	}
	current, err := guard.Stat()
	if err != nil || !os.SameFile(before, current) {
		closeErr := guard.Close()
		return nil, nil, false, fmt.Errorf("bind repository sqlite: %w", errors.Join(err, closeErr, errors.New("database changed while binding")))
	}
	return guard, current, true, nil
}

func (g *sqliteDatabaseGuard) open() error {
	name, err := libc.CString(g.physicalPath)
	if err != nil {
		return err
	}
	defer libc.Xfree(g.tls, name)
	// Only public C API output parameters cross this boundary. Keep their
	// scratch lifetime inside open, before the caller can close the guard's TLS.
	size := int(unsafe.Sizeof(uintptr(0)))
	out := g.tls.Alloc(size)
	defer g.tls.Free(size)
	libc.AssignPtrUintptr(out, 0)
	// Public open flags: https://www.sqlite.org/c3ref/open.html
	flags := int32(sqlite3.SQLITE_OPEN_READONLY | sqlite3.SQLITE_OPEN_FULLMUTEX | sqlite3.SQLITE_OPEN_NOFOLLOW)
	rc := sqlite3.Xsqlite3_open_v2(g.tls, name, out, flags, 0)
	g.db = libc.AtomicLoadPUintptr(out)
	if rc != sqlite3.SQLITE_OK {
		// Copy diagnostics before Close releases the failed connection. SQLite
		// may have no underlying errno, so never infer one from SQLITE_CANTOPEN.
		// https://www.sqlite.org/c3ref/system_errno.html
		// https://www.sqlite.org/c3ref/errcode.html
		message := libc.GoString(sqlite3.Xsqlite3_errstr(g.tls, rc))
		var systemErrno int32
		if g.db != 0 {
			systemErrno = sqlite3.Xsqlite3_system_errno(g.tls, g.db)
			message = libc.GoString(sqlite3.Xsqlite3_errmsg(g.tls, g.db))
		}
		err := fmt.Errorf("bind repository sqlite: sqlite3_open_v2 returned %d: %s", rc, message)
		if systemErrno != 0 {
			return fmt.Errorf("%w: %w", err, syscall.Errno(systemErrno))
		}
		return err
	}
	return nil
}

func (g *sqliteDatabaseGuard) Stat() (os.FileInfo, error) {
	current, err := os.Lstat(g.path)
	if err != nil {
		return nil, err
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() {
		return nil, errors.New("database is not a regular file")
	}
	if err := requirePrivateRegularPath(g.path); err != nil {
		return nil, err
	}
	physical, err := os.Lstat(g.physicalPath)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(current, physical) {
		return nil, errors.New("database parent path changed")
	}
	out := g.tls.Alloc(4)
	defer g.tls.Free(4)
	libc.AssignPtrInt32(out, -1)
	// Fail closed unless the VFS confirms that its held file has not moved.
	// https://www.sqlite.org/c3ref/c_fcntl_begin_atomic_write.html#sqlitefcntlhasmoved
	rc := sqlite3.Xsqlite3_file_control(g.tls, g.db, 0, sqlite3.SQLITE_FCNTL_HAS_MOVED, out)
	moved := libc.AtomicLoadPInt32(out)
	if rc != sqlite3.SQLITE_OK || moved != 0 {
		return nil, fmt.Errorf("database moved or cannot verify binding: rc=%d moved=%d", rc, moved)
	}
	return current, nil
}

func (g *sqliteDatabaseGuard) Close() error {
	if g == nil || g.tls == nil {
		return nil
	}
	if g.db != 0 {
		if rc := sqlite3.Xsqlite3_close_v2(g.tls, g.db); rc != sqlite3.SQLITE_OK {
			return fmt.Errorf("close sqlite database guard: rc=%d", rc)
		}
		g.db = 0
	}
	g.tls.Close()
	g.tls = nil
	return nil
}
