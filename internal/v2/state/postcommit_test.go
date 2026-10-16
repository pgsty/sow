package state

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"modernc.org/sqlite"
)

// This wrapper always forwards the transaction to modernc SQLite. It only
// cancels after the last real statement/before sql.Tx.Commit, cancels after
// successful driver.Tx.Commit, or injects EIO at a later checkpoint query.
type postcommitHook struct {
	sync.Mutex
	mode                 string
	cancel               context.CancelFunc
	commits, checkpoints int
	connections, closed  int
}
type postcommitConnector struct {
	dsn  string
	hook *postcommitHook
}

func (c postcommitConnector) Driver() driver.Driver { return &sqlite.Driver{} }
func (c postcommitConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.Driver().Open(c.dsn)
	if err != nil {
		return nil, err
	}
	c.hook.Lock()
	c.hook.connections++
	c.hook.Unlock()
	return &postcommitConn{Conn: conn, hook: c.hook}, nil
}

type postcommitConn struct {
	driver.Conn
	hook *postcommitHook
}

func (c *postcommitConn) Close() error {
	c.hook.Lock()
	c.hook.closed++
	c.hook.Unlock()
	return c.Conn.Close()
}

func (c *postcommitConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &postcommitTx{Tx: tx, hook: c.hook}, nil
}
func (c *postcommitConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	return c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, q)
}
func (c *postcommitConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if q == "PRAGMA busy_timeout=5000" {
		c.hook.Lock()
		mode := c.hook.mode
		if mode == "restore_io" || mode == "restore_timeout" || mode == "io_restore_io" {
			c.hook.mode = ""
		}
		c.hook.Unlock()
		if mode == "restore_io" || mode == "io_restore_io" {
			return nil, fmt.Errorf("injected restore: %w", syscall.EIO)
		}
		if mode == "restore_timeout" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	result, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
	if err == nil && strings.HasPrefix(strings.TrimSpace(q), "UPDATE operations SET payload_json") {
		c.hook.Lock()
		var cancel context.CancelFunc
		if c.hook.mode == "autocommit_after" {
			cancel = c.hook.cancel
			c.hook.mode = ""
		}
		if c.hook.mode == "autocommit_io" {
			c.hook.mode = "io"
			c.hook.commits++
		}
		c.hook.Unlock()
		if cancel != nil {
			cancel()
		}
	}
	if err == nil && strings.HasPrefix(strings.TrimSpace(q), "INSERT INTO operation_events") {
		c.hook.Lock()
		var cancel context.CancelFunc
		if c.hook.mode == "before" {
			cancel = c.hook.cancel
			c.hook.mode = ""
		}
		c.hook.Unlock()
		if cancel != nil {
			cancel()
		}
	}
	return result, err
}
func (c *postcommitConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(q, "PRAGMA wal_checkpoint(TRUNCATE)") {
		c.hook.Lock()
		c.hook.checkpoints++
		mode, cancel := c.hook.mode, c.hook.cancel
		ioFailure := mode == "io" && c.hook.commits > 0
		c.hook.Unlock()
		if mode == "checkpoint_timeout" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if mode == "checkpoint_cancel" {
			cancel()
			return nil, ctx.Err()
		}
		if mode == "io_restore_io" {
			return nil, fmt.Errorf("injected checkpoint capacity: %w", syscall.ENOSPC)
		}
		if ioFailure {
			return nil, fmt.Errorf("injected checkpoint fsync: %w", syscall.EIO)
		}
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}

type postcommitTx struct {
	driver.Tx
	hook *postcommitHook
}

func (tx *postcommitTx) Commit() error {
	if err := tx.Tx.Commit(); err != nil {
		return err
	}
	tx.hook.Lock()
	tx.hook.commits++
	var cancel context.CancelFunc
	if tx.hook.mode == "after" {
		cancel = tx.hook.cancel
		tx.hook.mode = ""
	}
	tx.hook.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}
func postcommitOpen(t *testing.T, seed func(*Store)) (*Store, *postcommitHook) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "repo.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if seed != nil {
		seed(s)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	hook := new(postcommitHook)
	db := sql.OpenDB(postcommitConnector{dsn: "file:" + filepath.ToSlash(p) + "?mode=rw&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", hook: hook})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s = &Store{path: p, db: db, schemaVersion: SchemaVersion}
	t.Cleanup(func() { s.Close() })
	return s, hook
}
func postcommitCount(t *testing.T, s *Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func postcommitArm(h *postcommitHook, mode string, cancel context.CancelFunc) {
	h.Lock()
	h.mode = mode
	h.cancel = cancel
	h.commits = 0
	h.checkpoints = 0
	h.Unlock()
}
func postcommitOperation(t *testing.T, s *Store, id string, states ...OperationState) {
	t.Helper()
	ctx := context.Background()
	if err := s.BeginOperation(ctx, Operation{ID: id, Kind: "build", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	for _, st := range states {
		if err := s.SetOperationState(ctx, id, st, ""); err != nil {
			t.Fatal(err)
		}
	}
}
func TestPostcommitBeginCommitBoundary(t *testing.T) {
	for _, mode := range []string{"before", "after", "io"} {
		t.Run(mode, func(t *testing.T) {
			s, h := postcommitOpen(t, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			postcommitArm(h, mode, cancel)
			op := Operation{ID: "101", Kind: "add", State: OperationPlanned, PayloadJSON: `{}`}
			err := s.BeginOperation(ctx, op)
			if mode == "io" {
				if !errors.Is(err, syscall.EIO) {
					t.Fatalf("expected EIO, got %v", err)
				}
			} else if mode == "before" && !errors.Is(err, context.Canceled) || mode == "after" && err != nil {
				t.Fatalf("mode=%s err=%v", mode, err)
			}
			assertPostcommitError(t, err, mode == "io")
			n := postcommitCount(t, s, `SELECT count(*) FROM operations WHERE id='101'`)
			events := postcommitCount(t, s, `SELECT count(*) FROM operation_events WHERE operation_id='101'`)
			want := 1
			if mode == "before" {
				want = 0
			}
			if n != want || events != want {
				t.Fatalf("operation=%d events=%d", n, events)
			}
			h.Lock()
			commits, checkpoints := h.commits, h.checkpoints
			h.mode = ""
			h.Unlock()
			retryErr := s.BeginOperation(context.Background(), op)
			if mode == "before" {
				if retryErr != nil {
					t.Fatal(retryErr)
				}
			} else if !errors.Is(retryErr, ErrExists) {
				t.Fatalf("retry=%v", retryErr)
			}
			t.Logf("mode=%s err=%v commits=%d checkpoint_queries=%d rows=%d audit_events=%d retry_err=%v final_rows=%d final_events=%d", mode, err, commits, checkpoints, n, events, retryErr, postcommitCount(t, s, `SELECT count(*) FROM operations WHERE id='101'`), postcommitCount(t, s, `SELECT count(*) FROM operation_events WHERE operation_id='101'`))
		})
	}
}
func TestPostcommitDesiredCommitBoundaryAndReplay(t *testing.T) {
	for _, mode := range []string{"before", "after", "io"} {
		t.Run(mode, func(t *testing.T) {
			object := PackageObject{SHA256: strings.Repeat("1", 64), Format: "rpm", Coordinate: "pkg-0:1.0-1.x86_64", Architecture: "x86_64", CanonicalArch: "x86_64", PoolPath: "pool/p/pkg/pkg-1.0-1.x86_64.rpm", Filename: "pkg-1.0-1.x86_64.rpm", Size: 7, Name: "pkg", Source: "pkg", Version: "1.0", Epoch: "0", Release: "1", Kind: "main", PayloadSHA256: strings.Repeat("2", 64), Storage: "pending"}
			s, h := postcommitOpen(t, func(s *Store) {
				if err := s.AddDist(context.Background(), Dist{Name: "el9", Format: "rpm", EffectiveConfigSHA256: "cfg", Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}}}); err != nil {
					t.Fatal(err)
				}
				postcommitOperation(t, s, "102", OperationStaged)
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			postcommitArm(h, mode, cancel)
			apply := func(ctx context.Context) (DesiredMutationResult, error) {
				return s.ApplyDesiredMutation(ctx, "102", []PackageObject{object}, map[string][]string{"el9": {object.SHA256}}, `{"accepted":1}`)
			}
			out, err := apply(ctx)
			if mode == "io" {
				if !errors.Is(err, syscall.EIO) {
					t.Fatalf("expected EIO: %v", err)
				}
			} else if mode == "before" && !errors.Is(err, context.Canceled) || mode == "after" && err != nil {
				t.Fatalf("mode=%s err=%v", mode, err)
			}
			assertPostcommitError(t, err, mode == "io")
			summary, e := s.Summary(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			members := postcommitCount(t, s, `SELECT count(*) FROM memberships`)
			audit := postcommitCount(t, s, `SELECT count(*) FROM operation_memberships WHERE operation_id='102'`)
			want := 1
			if mode == "before" {
				want = 0
			}
			if summary.DesiredRevision != int64(want) || members != want || audit != want || out.Revision != int64(want) {
				t.Fatalf("out=%+v summary=%+v memberships=%d audit=%d", out, summary, members, audit)
			}
			h.Lock()
			commits := h.commits
			h.mode = ""
			h.Unlock()
			retry, errRetry := apply(context.Background())
			if mode == "before" {
				if errRetry != nil || !retry.Changed {
					t.Fatalf("retry=%+v %v", retry, errRetry)
				}
			} else {
				if !errors.Is(errRetry, ErrTransition) {
					t.Fatalf("direct retry=%+v %v", retry, errRetry)
				}
				if e := s.SetOperationState(context.Background(), "102", OperationRecovering, ""); e != nil {
					t.Fatal(e)
				}
				replay, e := apply(context.Background())
				if e != nil || replay.Changed || replay.Revision != 1 {
					t.Fatalf("replay=%+v %v", replay, e)
				}
			}
			after, e := s.Summary(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if after.DesiredRevision != 1 || postcommitCount(t, s, `SELECT count(*) FROM operation_memberships WHERE operation_id='102'`) != 1 {
				t.Fatal("replay duplicated business or membership audit")
			}
			t.Logf("mode=%s err=%v committed=%d returned_revision=%d SQL_revision=%d memberships=%d membership_audit=%d direct_retry_err=%v final_revision=%d final_membership_audit=%d", mode, err, commits, out.Revision, summary.DesiredRevision, members, audit, errRetry, after.DesiredRevision, postcommitCount(t, s, `SELECT count(*) FROM operation_memberships WHERE operation_id='102'`))
		})
	}
}
func TestPostcommitTerminalCommitResults(t *testing.T) {
	for _, kind := range []string{"build", "noop"} {
		t.Run(kind, func(t *testing.T) {
			s, h := postcommitOpen(t, func(s *Store) {
				if err := s.AddDist(context.Background(), Dist{Name: "noble", Format: "deb", EffectiveConfigSHA256: "cfg"}); err != nil {
					t.Fatal(err)
				}
				postcommitOperation(t, s, "103", OperationStaged, OperationApplied)
				if kind == "build" {
					if err := s.SetOperationState(context.Background(), "103", OperationBuilt, ""); err != nil {
						t.Fatal(err)
					}
				}
			})
			input := FinalizeBuildInput{OperationID: "103", Generation: 1, Dists: []DistBuild{{Name: "noble", Format: "deb", EffectiveConfigSHA256: "cfg"}}}
			run := func(ctx context.Context) error {
				if kind == "build" {
					return s.FinalizeBuild(ctx, input)
				}
				return s.FinalizeNoopBuild(ctx, "103")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			postcommitArm(h, "after", cancel)
			err := run(ctx)
			if err != nil {
				t.Fatalf("committed terminal operation: %v", err)
			}
			_, sameContextErr := s.Summary(ctx)
			if !errors.Is(sameContextErr, context.Canceled) {
				t.Fatal(sameContextErr)
			}
			summary, e := s.Summary(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			operation, e := s.LastOperation(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if operation.State != OperationDone {
				t.Fatalf("operation=%+v", operation)
			}
			wantGen := GenerationID(0)
			if kind == "build" {
				wantGen = 1
			}
			if summary.BuiltGeneration != wantGen {
				t.Fatalf("summary=%+v", summary)
			}
			eventsBefore := postcommitCount(t, s, `SELECT count(*) FROM operation_events WHERE operation_id='103'`)
			if e := run(context.Background()); e != nil {
				t.Fatal(e)
			}
			eventsAfter := postcommitCount(t, s, `SELECT count(*) FROM operation_events WHERE operation_id='103'`)
			if eventsBefore != eventsAfter {
				t.Fatal("terminal retry duplicated audit")
			}
			t.Logf("kind=%s err=%v canceled_summary=%v durable_generation=%d last_operation_state=%s audit_events_before=%d after_retry=%d", kind, err, sameContextErr, summary.BuiltGeneration, operation.State, eventsBefore, eventsAfter)
		})
	}
}

func assertPostcommitError(t *testing.T, err error, want bool) {
	t.Helper()
	var committed *CommittedMaintenanceError
	if errors.As(err, &committed) != want {
		t.Fatalf("committed maintenance error=%v want=%t", err, want)
	}
}

func TestPostcommitAutocommitPayload(t *testing.T) {
	for _, mode := range []string{"autocommit_after", "autocommit_io"} {
		t.Run(mode, func(t *testing.T) {
			s, h := postcommitOpen(t, func(s *Store) { postcommitOperation(t, s, "104") })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			postcommitArm(h, mode, cancel)
			err := s.UpdateOperationPayload(ctx, "104", `{"committed":true}`)
			if mode == "autocommit_after" && err != nil || mode == "autocommit_io" && !errors.Is(err, syscall.EIO) {
				t.Fatal(err)
			}
			assertPostcommitError(t, err, mode == "autocommit_io")
			op, e := s.GetOperationSummary(context.Background(), "104")
			if e != nil || op.PayloadJSON != `{"committed":true}` || op.State != OperationPlanned {
				t.Fatalf("operation=%+v err=%v", op, e)
			}
		})
	}
}

func TestPostcommitRestoreDiscardsConnection(t *testing.T) {
	for _, mode := range []string{"restore_io", "restore_timeout"} {
		t.Run(mode, func(t *testing.T) {
			s, h := postcommitOpen(t, nil)
			postcommitArm(h, mode, nil)
			started := time.Now()
			err := s.BeginOperation(context.Background(), Operation{ID: "105", Kind: "build", State: OperationPlanned, PayloadJSON: `{}`})
			assertPostcommitError(t, err, true)
			cause := error(syscall.EIO)
			if mode == "restore_timeout" {
				cause = context.DeadlineExceeded
			}
			if !errors.Is(err, cause) || time.Since(started) > 2*time.Second {
				t.Fatalf("elapsed=%s err=%v", time.Since(started), err)
			}
			var timeout int
			if e := s.DB().QueryRowContext(context.Background(), `PRAGMA busy_timeout`).Scan(&timeout); e != nil || timeout != 5000 {
				t.Fatalf("timeout=%d err=%v", timeout, e)
			}
			h.Lock()
			opened, closed := h.connections, h.closed
			h.Unlock()
			if opened != 2 || closed != 1 {
				t.Fatalf("opened=%d closed=%d", opened, closed)
			}
			if postcommitCount(t, s, `SELECT count(*) FROM operations WHERE id='105'`) != 1 {
				t.Fatal("committed operation missing")
			}
		})
	}
}

func TestPostcommitStandaloneCheckpointCancellation(t *testing.T) {
	s, _ := postcommitOpen(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.Checkpoint(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	assertPostcommitError(t, err, false)
}

func TestPostcommitPruneCompactionBoundary(t *testing.T) {
	for _, mode := range []string{"after", "io"} {
		t.Run(mode, func(t *testing.T) {
			s, h := postcommitOpen(t, func(s *Store) { postcommitOperation(t, s, "106", OperationStaged, OperationApplied, OperationDone) })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			postcommitArm(h, mode, cancel)
			count, err := s.PruneTerminalOperations(ctx, time.Now().Add(time.Hour))
			if count != 1 || mode == "after" && err != nil || mode == "io" && !errors.Is(err, syscall.EIO) {
				t.Fatalf("count=%d err=%v", count, err)
			}
			assertPostcommitError(t, err, mode == "io")
			if postcommitCount(t, s, `SELECT count(*) FROM operations`) != 0 {
				t.Fatal("pruned rows restored")
			}
		})
	}
}

func TestPostcommitDistRemovalKeepsDroppedPending(t *testing.T) {
	object := PackageObject{SHA256: strings.Repeat("1", 64), Format: "rpm", Coordinate: "pkg-0:1.0-1.x86_64", Architecture: "x86_64", CanonicalArch: "x86_64", PoolPath: "pool/p/pkg/pkg-1.0-1.x86_64.rpm", Filename: "pkg-1.0-1.x86_64.rpm", Size: 7, Name: "pkg", Source: "pkg", Version: "1.0", Epoch: "0", Release: "1", Kind: "main", PayloadSHA256: strings.Repeat("2", 64), Storage: "pending"}
	s, h := postcommitOpen(t, func(s *Store) {
		ctx := context.Background()
		if err := s.AddDist(ctx, Dist{Name: "el9", Format: "rpm", EffectiveConfigSHA256: "cfg"}); err != nil {
			t.Fatal(err)
		}
		postcommitOperation(t, s, "107", OperationStaged)
		if _, err := s.ApplyDesiredMutation(ctx, "107", []PackageObject{object}, map[string][]string{"el9": {object.SHA256}}, `{}`); err != nil {
			t.Fatal(err)
		}
		if err := s.SetOperationState(ctx, "107", OperationDoneDirty, ""); err != nil {
			t.Fatal(err)
		}
		postcommitOperation(t, s, "108", OperationStaged, OperationApplied, OperationBuilt)
	})
	postcommitArm(h, "io", nil)
	dropped, err := s.FinalizeDistRemovalAndCollect(context.Background(), "108", "el9", 1, nil, nil)
	if !errors.Is(err, syscall.EIO) || len(dropped) != 1 || dropped[0] != object.SHA256 {
		t.Fatalf("dropped=%v err=%v", dropped, err)
	}
	assertPostcommitError(t, err, true)
	if postcommitCount(t, s, `SELECT count(*) FROM package_objects`) != 0 {
		t.Fatal("unreachable pending object remains")
	}
	postcommitArm(h, "", nil)
	replay, replayErr := s.FinalizeDistRemovalAndCollect(context.Background(), "108", "el9", 1, nil, nil)
	if replayErr != nil || len(replay) != 1 || replay[0] != object.SHA256 {
		t.Fatalf("replay=%v err=%v", replay, replayErr)
	}
}

func TestPostcommitCheckpointDeadlineAndRestoreDiagnostics(t *testing.T) {
	for _, mode := range []string{"checkpoint_cancel", "checkpoint_timeout", "io_restore_io"} {
		t.Run(mode, func(t *testing.T) {
			s, h := postcommitOpen(t, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			postcommitArm(h, mode, cancel)
			started := time.Now()
			var err error
			if mode == "checkpoint_cancel" {
				err = s.Checkpoint(ctx)
			} else {
				err = s.BeginOperation(ctx, Operation{ID: "109", Kind: "build", State: OperationPlanned, PayloadJSON: `{}`})
			}
			assertPostcommitError(t, err, mode != "checkpoint_cancel")
			switch mode {
			case "checkpoint_cancel":
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case "checkpoint_timeout":
				if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 6*time.Second {
					t.Fatalf("elapsed=%s err=%v", time.Since(started), err)
				}
			case "io_restore_io":
				if !errors.Is(err, syscall.ENOSPC) || !errors.Is(err, syscall.EIO) {
					t.Fatalf("joined diagnostics: %v", err)
				}
			}
			postcommitArm(h, "", nil)
			var timeout int
			if e := s.DB().QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); e != nil || timeout != 5000 {
				t.Fatalf("timeout=%d err=%v", timeout, e)
			}
		})
	}
}

func TestAbandonLayoutTransitionRetainsExistingEligibility(t *testing.T) {
	for _, layout := range []string{LayoutC2V1, LayoutC2ToSingleV1, LayoutSinglePayloadV1} {
		t.Run(layout, func(t *testing.T) {
			ctx := context.Background()
			s, _ := postcommitOpen(t, func(s *Store) {
				if _, err := s.DB().Exec(`UPDATE repository_state SET layout_version = ?`, layout); err != nil {
					t.Fatal(err)
				}
			})
			before, err := s.RepositoryIdentity(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if layout == LayoutC2ToSingleV1 {
				if err := s.AnchorLayoutTransitionPlan(ctx, before.RepositoryID, 0, strings.Repeat("a", 64), strings.Repeat("b", 64), "2026-08-05T12:00:00Z"); err != nil {
					t.Fatal(err)
				}
			}
			for attempt := range 2 {
				err := s.AbandonLayoutTransition(ctx)
				if layout == LayoutC2ToSingleV1 && err != nil || layout != LayoutC2ToSingleV1 && !errors.Is(err, ErrTransition) {
					t.Fatalf("attempt=%d layout=%s err=%v", attempt, layout, err)
				}
				after, err := s.RepositoryIdentity(ctx)
				if err != nil || before != after {
					t.Fatalf("abort rewrote identity/layout/receipt: before=%+v after=%+v err=%v", before, after, err)
				}
				if n := postcommitCount(t, s, `SELECT count(*) FROM layout_transition_control`); n != 0 {
					t.Fatalf("control remains: %d", n)
				}
			}
		})
	}
}

func TestPostcommitAbandonLayoutTransitionBoundary(t *testing.T) {
	for _, mode := range []string{"canceled-before", "after", "io", "checkpoint_timeout", "committed-intent"} {
		t.Run(mode, func(t *testing.T) {
			s, hook := postcommitOpen(t, func(s *Store) {
				if _, err := s.DB().Exec(`UPDATE repository_state SET layout_version = ?`, LayoutC2ToSingleV1); err != nil {
					t.Fatal(err)
				}
				identity, err := s.RepositoryIdentity(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if err := s.AnchorLayoutTransitionPlan(context.Background(), identity.RepositoryID, 0, strings.Repeat("a", 64), strings.Repeat("b", 64), "2026-08-05T12:00:00Z"); err != nil {
					t.Fatal(err)
				}
				if mode == "committed-intent" {
					if err := s.CommitLayoutTransitionPlan(context.Background(), strings.Repeat("b", 64), "2026-08-05T12:00:00Z", "2026-09-05T12:00:00Z"); err != nil {
						t.Fatal(err)
					}
				}
			})
			before, err := s.RepositoryIdentity(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			postcommitArm(hook, mode, cancel)
			if mode == "canceled-before" {
				cancel()
			}
			started := time.Now()
			err = s.AbandonLayoutTransition(ctx)
			wantControl := mode == "canceled-before" || mode == "committed-intent"
			switch mode {
			case "canceled-before":
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case "committed-intent":
				if !errors.Is(err, ErrTransition) {
					t.Fatal(err)
				}
			case "after":
				if err != nil || ctx.Err() == nil {
					t.Fatalf("durable reset err=%v context=%v", err, ctx.Err())
				}
			case "io":
				assertPostcommitError(t, err, true)
				if !errors.Is(err, syscall.EIO) {
					t.Fatal(err)
				}
			case "checkpoint_timeout":
				assertPostcommitError(t, err, true)
				if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 6*time.Second {
					t.Fatalf("unbounded/reset diagnostic: %v duration=%v", err, time.Since(started))
				}
			}
			control, readErr := s.LayoutTransitionControl(context.Background())
			if readErr != nil || (control != nil) != wantControl {
				t.Fatalf("durable control=%+v want=%t err=%v", control, wantControl, readErr)
			}
			after, readErr := s.RepositoryIdentity(context.Background())
			if readErr != nil || before != after {
				t.Fatalf("identity changed: before=%+v after=%+v err=%v", before, after, readErr)
			}
			postcommitArm(hook, "", nil)
			if !wantControl {
				if err := s.AbandonLayoutTransition(context.Background()); err != nil {
					t.Fatalf("repeat reset: %v", err)
				}
			}
			t.Logf("mode=%s error=%v control_retained=%t layout=%s", mode, err, wantControl, after.LayoutVersion)
		})
	}
}
