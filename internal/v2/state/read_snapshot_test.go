package state

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"modernc.org/sqlite"
)

// These probes only interpose the real driver boundary. Every query,
// Rows value, transaction and commit is executed by modernc SQLite against the
// same WAL database. The writer owns a different database/sql connection.
type sow013Connector struct {
	driver.Connector
	before   func(context.Context, string) error
	observer *sow013ReadObserver
}

func (c *sow013Connector) Connect(ctx context.Context) (driver.Conn, error) {
	raw, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &sow013Conn{Conn: raw, before: c.before, observer: c.observer}, nil
}

type sow013Conn struct {
	driver.Conn
	before   func(context.Context, string) error
	observer *sow013ReadObserver
}

func (c *sow013Conn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if err := c.before(ctx, q); err != nil {
		return nil, err
	}
	rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
	if err != nil || c.observer == nil {
		return rows, err
	}
	c.observer.openRows.Add(1)
	return &sow013ObservedRows{Rows: rows, ctx: ctx, query: q, observer: c.observer}, nil
}
func (c *sow013Conn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil || c.observer == nil {
		return tx, err
	}
	c.observer.begins.Add(1)
	if opts.ReadOnly {
		c.observer.readOnlyBegins.Add(1)
	}
	return &sow013ObservedTx{Tx: tx, observer: c.observer}, nil
}
func (c *sow013Conn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}

func sow013GatedReader(t *testing.T, writer *Store, match string, commit func(context.Context) error) (*Store, context.Context, *bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	reached := make(chan struct{})
	done := make(chan error, 1)
	fired := false
	go func() {
		select {
		case <-reached:
			done <- commit(ctx)
		case <-ctx.Done():
			done <- ctx.Err()
		}
	}()
	rawURL := &url.URL{Scheme: "file", Path: writer.path}
	query := url.Values{}
	query.Set("mode", "ro")
	query.Add("_pragma", "query_only(1)")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "busy_timeout(5000)")
	rawURL.RawQuery = query.Encode()
	base, err := sqlite.NewConnector(rawURL.String())
	if err != nil {
		t.Fatal(err)
	}
	conn := &sow013Connector{Connector: base, before: func(ctx context.Context, q string) error {
		if fired || !strings.Contains(q, match) {
			return nil
		}
		fired = true
		close(reached)
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() {
		cancel()
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return &Store{path: writer.path, db: db, schemaVersion: writer.schemaVersion, readOnly: true}, ctx, &fired
}
func sow013RemoveSelected(ctx context.Context, writer *Store) error {
	tx, err := writer.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"memberships", "built_memberships"} {
		if _, err = tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE dist_name='selected'`); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func TestSOW013ObjectsMustBeSingleSnapshot(t *testing.T) {
	writer, _ := newSparseMembershipFixture(t, 1, 1)
	before, err := writer.ListPackageObjects(context.Background(), []string{"selected"}, false)
	if err != nil {
		t.Fatal(err)
	}
	reader, ctx, fired := sow013GatedReader(t, writer, "SELECT package_sha256, dist_name FROM memberships", func(ctx context.Context) error { return sow013RemoveSelected(ctx, writer) })
	got, err := reader.ListPackageObjects(ctx, []string{"selected"}, false)
	if err != nil {
		t.Fatal(err)
	}
	after, err := writer.ListPackageObjects(ctx, []string{"selected"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !*fired {
		t.Fatal("query boundary not reached")
	}
	t.Logf("actual writer COMMIT between object selection and Desired projection; before=%+v; after=%+v; returned=%+v", before, after, got)
	if !reflect.DeepEqual(got, before) && !reflect.DeepEqual(got, after) {
		t.Fatal("single API returned a mixture of committed states: selected object without selected membership")
	}
}
func TestSOW013DistMustBeSingleSnapshot(t *testing.T) {
	writer, _ := newSparseMembershipFixture(t, 1, 1)
	before, err := writer.GetDist(context.Background(), "selected")
	if err != nil {
		t.Fatal(err)
	}
	reader, ctx, fired := sow013GatedReader(t, writer, "SELECT family, ecosystem_arch FROM dist_architectures", func(ctx context.Context) error {
		tx, err := writer.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, `UPDATE dists SET effective_config_sha256='after' WHERE name='selected'`); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE dist_architectures SET family='aarch64',ecosystem_arch='aarch64' WHERE dist_name='selected'`); err != nil {
			return err
		}
		return tx.Commit()
	})
	got, err := reader.GetDist(ctx, "selected")
	if err != nil {
		t.Fatal(err)
	}
	after, err := writer.GetDist(ctx, "selected")
	if err != nil {
		t.Fatal(err)
	}
	if !*fired {
		t.Fatal("query boundary not reached")
	}
	t.Logf("actual writer COMMIT between Dist row and architecture query; before=%+v; after=%+v; returned=%+v", before, after, got)
	if !reflect.DeepEqual(got, before) && !reflect.DeepEqual(got, after) {
		t.Fatal("single API returned old Dist configuration with new architectures")
	}
}
func TestSOW013AuditMustBeSingleSnapshot(t *testing.T) {
	writer, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	ctx := context.Background()
	id := "1"
	if err := writer.BeginOperation(ctx, Operation{ID: id, Kind: "add", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	if err := writer.SetOperationState(ctx, id, OperationStaged, ""); err != nil {
		t.Fatal(err)
	}
	before, err := writer.GetOperation(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	reader, ctx, fired := sow013GatedReader(t, writer, "SELECT sequence, state, detail_json, occurred_at FROM operation_events", func(ctx context.Context) error { return writer.FailOperation(ctx, id, "cancelled", "cancelled", `{}`) })
	got, err := reader.GetOperation(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	after, err := writer.GetOperation(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !*fired {
		t.Fatal("query boundary not reached")
	}
	t.Logf("actual FailOperation COMMIT between summary and events; before_state=%s before_events=%d; after_state=%s after_events=%d; returned_state=%s returned_events=%d last_event=%s", before.Operation.State, len(before.Events), after.Operation.State, len(after.Events), got.Operation.State, len(got.Events), got.Events[len(got.Events)-1].State)
	if !reflect.DeepEqual(got, before) && !reflect.DeepEqual(got, after) {
		t.Fatal("single API returned staged header with failed terminal event")
	}
}
func TestSOW013ActiveAttemptMustBeSingleSnapshot(t *testing.T) {
	writer, binding, manifest := publicationStoreFixture(t)
	defer writer.Close()
	ctx := context.Background()
	_, manifestSHA, _ := ManifestBytes(manifest)
	attempt := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1, ManifestSHA256: manifestSHA, PlanSHA256: strings.Repeat("a", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	if err := writer.PutPublicationAttempt(ctx, &attempt); err != nil {
		t.Fatal(err)
	}
	reader, ctx, fired := sow013GatedReader(t, writer, "SELECT attempt_identity, schema_version, repository_id, target_identity", func(ctx context.Context) error {
		return writer.AbandonPublicationAttempt(ctx, attempt.AttemptIdentity, nil)
	})
	got, err := reader.GetActivePublicationAttempt(ctx, binding.TargetIdentity)
	if err != nil && !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	after, afterErr := writer.GetActivePublicationAttempt(ctx, binding.TargetIdentity)
	if !*fired {
		t.Fatal("query boundary not reached")
	}
	t.Logf("actual AbandonPublicationAttempt COMMIT after active selection; before=planned; after=%+v after_error=%v; returned_phase=%s returned_error=%v", after, afterErr, got.Phase, err)
	if err == nil && got.Phase != "planned" {
		t.Fatal("GetActivePublicationAttempt returned abandoned attempt, which was never active in that state")
	}
}

// This control demonstrates the driver's real read transaction semantics only;
// it is deliberately not a replacement implementation of any Store API.
func TestSOW013SQLiteReadTransactionControl(t *testing.T) {
	writer, _ := newSparseMembershipFixture(t, 1, 1)
	reader, err := OpenReadOnly(writer.path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ctx, cancel := context.WithCancel(context.Background())
	tx, err := reader.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var before, within int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM memberships WHERE dist_name='selected'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err = sow013RemoveSelected(context.Background(), writer); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM memberships WHERE dist_name='selected'`).Scan(&within); err != nil {
		t.Fatal(err)
	}
	if before != 1 || within != 1 {
		t.Fatalf("snapshot before=%d within=%d", before, within)
	}
	cancel()
	_ = tx.Rollback()
	released, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	var after int
	if err = reader.db.QueryRowContext(released, `SELECT count(*) FROM memberships WHERE dist_name='selected'`).Scan(&after); err != nil {
		t.Fatalf("reader connection not released after cancellation: %v", err)
	}
	if after != 0 {
		t.Fatalf("after=%d", after)
	}
	if err = writer.Checkpoint(released); err != nil {
		t.Fatal(err)
	}
	var busy, logFrames, copied int
	if err = writer.db.QueryRowContext(released, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &copied); err != nil || busy != 0 {
		t.Fatalf("checkpoint after cancel busy=%d frames=%d copied=%d err=%v", busy, logFrames, copied, err)
	}
	t.Logf("real SQLite ReadOnlyTx kept count=%d across second-connection commit, cancellation released MaxOpenConns(1), next query=%d, checkpoint busy=%d", within, after, busy)
}

// Seed valid SQL state; the interleaved mutations below use supported Store
// writer APIs. There is no product-source rewrite or mocked SQL response.
func sow013CompositeFixture(t *testing.T) (*Store, PackageObject, []GenerationFile) {
	t.Helper()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	object := localGCCaseObject()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = insertPackageObjectTx(ctx, tx, object); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	manifest := []GenerationFile{{Path: object.PoolPath, Phase: "payload", Size: object.Size, SHA256: object.SHA256}}
	if err = s.BeginOperation(ctx, Operation{ID: "1", Kind: "dist.new", State: OperationBuilt, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	dist := Dist{Name: "stable", Format: "deb", EffectiveConfigSHA256: "cfg", BuiltGeneration: 1, Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "amd64"}}}
	if err = s.FinalizeDistAdd(ctx, "1", dist, manifest, DiffManifests(nil, manifest)); err != nil {
		t.Fatal(err)
	}
	if err = s.Check(ctx); err != nil {
		t.Fatalf("fixture semantic check: %v", err)
	}
	if err = s.ValidateGenerationLedger(ctx); err != nil {
		t.Fatalf("fixture generation ledger: %v", err)
	}
	return s, object, manifest
}
func TestSOW013SupplementPublicationRootRequirement(t *testing.T) {
	writer, binding, _ := publicationStoreFixture(t)
	defer writer.Close()
	ctx := context.Background()
	before, err := writer.PublicationRootRequirement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rebound := binding
	rebound.PublicEndpoint = "https://rebound.example.test/prod/repo/"
	rebound.MaxCacheTTL = 48 * time.Hour
	rebound.ConfigIdentity = ""
	reader, ctx, fired := sow013GatedReader(t, writer, "SELECT target_identity, revision, target_storage_id", func(ctx context.Context) error {
		return writer.RebindPublicationTarget(ctx, PublicationTargetRebind{Binding: rebound, Reason: "snapshot_probe", OperatorConfirmed: true})
	})
	got, err := reader.PublicationRootRequirement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	after, err := writer.PublicationRootRequirement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !*fired {
		t.Fatal("hash-query boundary not reached")
	}
	t.Logf("supported RebindPublicationTarget committed between binding and revision hashing; before=%s; after=%s; returned=%s; complete(before/after/returned)=%t/%t/%t", before.EvidenceIdentity, after.EvidenceIdentity, got.EvidenceIdentity, before.StateComplete, after.StateComplete, got.StateComplete)
	if !reflect.DeepEqual(got, before) && !reflect.DeepEqual(got, after) {
		t.Fatal("publication requirement attested hash not present in either complete SQLite state")
	}
}
func TestSOW013SupplementLocalGCInventory(t *testing.T) {
	writer, object, _ := sow013CompositeFixture(t)
	ctx := context.Background()
	before, err := writer.LocalGCInventory(ctx)
	if err != nil || len(before.Candidates) != 1 {
		t.Fatalf("before=%+v err=%v", before, err)
	}
	reader, ctx, fired := sow013GatedReader(t, writer, "FROM package_objects AS p\nWHERE p.storage = 'pool'", func(ctx context.Context) error {
		if err := writer.BeginOperation(ctx, Operation{ID: "2", Kind: "add", State: OperationStaged, PayloadJSON: `{}`}); err != nil {
			return err
		}
		_, err := writer.ApplyDesiredMutation(ctx, "2", []PackageObject{object}, map[string][]string{"stable": {object.SHA256}}, `{}`)
		return err
	})
	got, err := reader.LocalGCInventory(ctx)
	after, afterErr := writer.LocalGCInventory(ctx)
	if !*fired {
		t.Fatal("candidate-query boundary not reached")
	}
	if !errors.Is(afterErr, ErrConflict) {
		t.Fatalf("after not expected dirty-state rejection: %v", afterErr)
	}
	if checkErr := writer.Check(ctx); checkErr != nil {
		t.Fatalf("writer left corrupt state: %v", checkErr)
	}
	t.Logf("supported BeginOperation/ApplyDesiredMutation committed after clean+no-pending checks; before candidates=%d gen=%s; after=%+v err=%v; returned candidates=%d gen=%s err=%v", len(before.Candidates), before.Generation, after, afterErr, len(got.Candidates), got.Generation, err)
	if err == nil && !reflect.DeepEqual(got, before) {
		t.Fatal("LocalGCInventory returned clean authorization combined with dirty-state candidate set; no complete valid snapshot has this result")
	}
}
func TestSOW013SupplementValidateGenerationLedger(t *testing.T) {
	writer, _, manifest := sow013CompositeFixture(t)
	ctx := context.Background()
	if err := writer.ValidateGenerationLedger(ctx); err != nil {
		t.Fatal(err)
	}
	reader, ctx, fired := sow013GatedReader(t, writer, "SELECT generation, previous_generation, operation_id, manifest_sha256 FROM generations ORDER BY generation", func(ctx context.Context) error {
		if err := writer.BeginOperation(ctx, Operation{ID: "2", Kind: "dist.new", State: OperationBuilt, PayloadJSON: `{}`}); err != nil {
			return err
		}
		return writer.FinalizeDistAdd(ctx, "2", Dist{Name: "next", Format: "deb", EffectiveConfigSHA256: "cfg", BuiltGeneration: 2, Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "amd64"}}}, manifest, DiffManifests(manifest, manifest))
	})
	gotErr := reader.ValidateGenerationLedger(ctx)
	afterErr := writer.ValidateGenerationLedger(ctx)
	if !*fired {
		t.Fatal("ledger-query boundary not reached")
	}
	if afterErr != nil {
		t.Fatalf("writer left invalid ledger: %v", afterErr)
	}
	t.Logf("supported FinalizeDistAdd committed after repository current generation read and before ledger SELECT; before=nil; after=nil; returned=%v", gotErr)
	if gotErr != nil {
		t.Fatalf("healthy ledger falsely reported inconsistent after complete atomic generation commit: %v", gotErr)
	}
}

// Observe real transaction and Rows lifetimes. Faults are introduced only at
// the driver boundary, after a real snapshot and a second connection's commit.
type sow013ReadObserver struct {
	begins, readOnlyBegins, commits, rollbacks, openRows atomic.Int32
	next                                                 func(context.Context, string, int) error
}
type sow013ObservedTx struct {
	driver.Tx
	observer *sow013ReadObserver
}

func (tx *sow013ObservedTx) Commit() error {
	err := tx.Tx.Commit()
	if err == nil {
		tx.observer.commits.Add(1)
	}
	return err
}
func (tx *sow013ObservedTx) Rollback() error {
	err := tx.Tx.Rollback()
	tx.observer.rollbacks.Add(1)
	return err
}

type sow013ObservedRows struct {
	driver.Rows
	ctx      context.Context
	query    string
	observer *sow013ReadObserver
	count    int
	closed   bool
}

func (r *sow013ObservedRows) Next(dest []driver.Value) error {
	if r.observer.next != nil {
		if err := r.observer.next(r.ctx, r.query, r.count); err != nil {
			return err
		}
	}
	err := r.Rows.Next(dest)
	if err == nil {
		r.count++
	}
	return err
}
func (r *sow013ObservedRows) Close() error {
	if !r.closed {
		r.closed = true
		r.observer.openRows.Add(-1)
	}
	return r.Rows.Close()
}
func sow013ObservedReader(t *testing.T, writer *Store, before func(context.Context, string) error, observer *sow013ReadObserver) *Store {
	t.Helper()
	uri := &url.URL{Scheme: "file", Path: writer.path}
	query := url.Values{"mode": {"ro"}, "_pragma": {"query_only(1)", "foreign_keys(1)", "busy_timeout(5000)"}}
	uri.RawQuery = query.Encode()
	base, err := sqlite.NewConnector(uri.String())
	if err != nil {
		t.Fatal(err)
	}
	if before == nil {
		before = func(context.Context, string) error { return nil }
	}
	db := sql.OpenDB(&sow013Connector{Connector: base, before: before, observer: observer})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return &Store{path: writer.path, db: db, schemaVersion: writer.schemaVersion, readOnly: true}
}

func TestSOW013ObjectVariantsKeepOneSnapshot(t *testing.T) {
	for _, name := range []string{"desired", "built", "prior", "unfiltered", "digest", "coordinate"} {
		t.Run(name, func(t *testing.T) {
			writer, objects := newSparseMembershipFixture(t, 2, 2)
			if _, err := writer.db.Exec(`INSERT INTO prior_built_memberships(dist_name, package_sha256, generation) SELECT dist_name, package_sha256, generation FROM built_memberships`); err != nil {
				t.Fatal(err)
			}
			read := func(s *Store, ctx context.Context) ([]PackageObject, error) {
				switch name {
				case "prior":
					return s.ListPriorBuiltPackageObjects(ctx, []string{"selected"})
				case "unfiltered":
					return s.ListPackageObjects(ctx, nil, false)
				case "digest", "coordinate":
					var object PackageObject
					var err error
					if name == "digest" {
						object, err = s.GetPackageObject(ctx, objects[0].SHA256)
					} else {
						object, err = s.FindPackageByCoordinate(ctx, objects[0].Format, objects[0].Coordinate)
					}
					if err != nil {
						return nil, err
					}
					return []PackageObject{object}, nil
				default:
					return s.ListPackageObjects(ctx, []string{"selected"}, name == "built")
				}
			}
			before, err := read(writer, context.Background())
			if err != nil {
				t.Fatal(err)
			}
			match := "SELECT package_sha256, dist_name FROM built_memberships"
			if name == "digest" || name == "coordinate" {
				match = "SELECT dist_name FROM built_memberships"
			}
			reader, ctx, fired := sow013GatedReader(t, writer, match, func(ctx context.Context) error { return writer.RemoveDist(ctx, "selected") })
			got, err := read(reader, ctx)
			if err != nil || !*fired || !reflect.DeepEqual(got, before) {
				t.Fatalf("old snapshot lost: fired=%t err=%v got=%+v before=%+v", *fired, err, got, before)
			}
			after, err := read(writer, ctx)
			if err != nil || reflect.DeepEqual(before, after) {
				t.Fatalf("writer did not change the projection: err=%v", err)
			}
		})
	}
}

func TestSOW013PackageBatchesKeepOneSnapshot(t *testing.T) {
	writer, _ := newSparseMembershipFixture(t, 1_200, 1_101)
	before, err := writer.ListPackageObjects(context.Background(), []string{"selected"}, false)
	if err != nil {
		t.Fatal(err)
	}
	// The first two 500-digest batches have finished before the final 101
	// Desired digests are read. Built expansion must use that same old view.
	match := "SELECT package_sha256, dist_name FROM memberships WHERE package_sha256 IN (" + strings.TrimSuffix(strings.Repeat("?,", 101), ",") + ") ORDER BY"
	reader, ctx, fired := sow013GatedReader(t, writer, match, func(ctx context.Context) error { return writer.RemoveDist(ctx, "selected") })
	got, err := reader.ListPackageObjects(ctx, []string{"selected"}, false)
	if err != nil || !*fired || !reflect.DeepEqual(got, before) {
		t.Fatalf("cross-batch snapshot lost: fired=%t err=%v returned=%d", *fired, err, len(got))
	}
	after, err := writer.ListPackageObjects(ctx, []string{"selected"}, false)
	if err != nil || len(after) != 0 {
		t.Fatalf("after removal: objects=%d err=%v", len(after), err)
	}
}

func TestSOW013DistListAndMembershipExistenceKeepOneSnapshot(t *testing.T) {
	t.Run("list", func(t *testing.T) {
		writer, _ := newSparseMembershipFixture(t, 1, 1)
		before, err := writer.ListDists(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		reader, ctx, fired := sow013GatedReader(t, writer, "SELECT family, ecosystem_arch FROM dist_architectures", func(ctx context.Context) error { return writer.RemoveDist(ctx, "selected") })
		got, err := reader.ListDists(ctx)
		if err != nil || !*fired || !reflect.DeepEqual(got, before) {
			t.Fatalf("Dist list lost architectures across removal: fired=%t err=%v got=%+v", *fired, err, got)
		}
	})
	for _, built := range []bool{false, true} {
		t.Run(fmt.Sprintf("members_built_%t", built), func(t *testing.T) {
			writer, _ := newSparseMembershipFixture(t, 1, 1)
			before, err := writer.MembershipDigests(context.Background(), "selected", built)
			if err != nil {
				t.Fatal(err)
			}
			reader, ctx, fired := sow013GatedReader(t, writer, "SELECT package_sha256 FROM", func(ctx context.Context) error { return writer.RemoveDist(ctx, "selected") })
			got, err := reader.MembershipDigests(ctx, "selected", built)
			if err != nil || !*fired || !reflect.DeepEqual(got, before) {
				t.Fatalf("existence and membership snapshot differ: fired=%t err=%v got=%v", *fired, err, got)
			}
			if _, err := writer.MembershipDigests(ctx, "selected", built); !errors.Is(err, ErrNotFound) {
				t.Fatalf("removed Dist: %v", err)
			}
		})
	}
}

func TestSOW013CheckDuringBindingRebind(t *testing.T) {
	writer, binding, _ := publicationStoreFixture(t)
	defer writer.Close()
	if err := writer.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	rebound := binding
	rebound.PublicEndpoint = "https://check-rebound.example.test/prod/repo/"
	rebound.ConfigIdentity = ""
	reader, ctx, fired := sow013GatedReader(t, writer, "SELECT revision, target_identity, target_storage_id", func(ctx context.Context) error {
		return writer.RebindPublicationTarget(ctx, PublicationTargetRebind{Binding: rebound, Reason: "check_snapshot", OperatorConfirmed: true})
	})
	if err := reader.Check(ctx); err != nil || !*fired {
		t.Fatalf("healthy rebind reported corruption: fired=%t err=%v", *fired, err)
	}
	if err := writer.Check(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSOW013OperationChildrenSurviveConcurrentPrune(t *testing.T) {
	for _, table := range []string{"operation_events", "operation_packages", "operation_memberships", "operation_files"} {
		t.Run(table, func(t *testing.T) {
			writer, err := Open(filepath.Join(t.TempDir(), "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			ctx := context.Background()
			if err := writer.BeginOperation(ctx, Operation{ID: "1", Kind: "add", State: OperationStaged, PayloadJSON: `{}`}); err != nil {
				t.Fatal(err)
			}
			// Populate each child family before the only interleaved mutation:
			// the supported pruning API atomically deletes header and children.
			for _, query := range []string{
				`INSERT INTO operation_packages(operation_id, sequence, input_path, disposition) VALUES ('1', 0, 'pkg.rpm', 'accepted')`,
				`INSERT INTO operation_memberships(operation_id, sequence, dist_name, package_sha256, action) VALUES ('1', 0, 'selected', 'digest', 'add')`,
				`INSERT INTO operation_files(operation_id, sequence, action, phase, path, size, sha256) VALUES ('1', 0, 'add', 'payload', 'pool/p/pkg/pkg.rpm', 1, 'digest')`,
			} {
				if _, err := writer.db.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.FailOperation(ctx, "1", "fixture", "fixture", `{}`); err != nil {
				t.Fatal(err)
			}
			before, err := writer.GetOperation(ctx, "1")
			if err != nil {
				t.Fatal(err)
			}
			reader, readCtx, fired := sow013GatedReader(t, writer, "FROM "+table+" WHERE", func(ctx context.Context) error {
				count, err := writer.PruneTerminalOperations(ctx, time.Now().Add(time.Hour))
				if err == nil && count != 1 {
					return fmt.Errorf("pruned %d operations", count)
				}
				return err
			})
			got, err := reader.GetOperation(readCtx, "1")
			if err != nil || !*fired || !reflect.DeepEqual(got, before) {
				t.Fatalf("prune fractured audit: fired=%t err=%v got=%+v", *fired, err, got)
			}
			if _, err := writer.GetOperation(ctx, "1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("pruned operation: %v", err)
			}
		})
	}
}

func sow013CheckpointState(t *testing.T, writer *Store, wantPinned bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := writer.db.ExecContext(ctx, `PRAGMA busy_timeout=0`); err != nil {
		t.Fatal(err)
	}
	var busy, frames, copied int
	err := writer.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &frames, &copied)
	if _, restoreErr := writer.db.ExecContext(ctx, `PRAGMA busy_timeout=5000`); restoreErr != nil {
		t.Fatal(restoreErr)
	}
	if err != nil || (busy != 0) != wantPinned {
		t.Fatalf("checkpoint pinned=%t busy=%d frames=%d copied=%d err=%v", wantPinned, busy, frames, copied, err)
	}
}

func TestSOW013ReadSnapshotRelease(t *testing.T) {
	for _, mode := range []string{"success", "query_error", "rows_error", "cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			writer, _ := newSparseMembershipFixture(t, 2, 2)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			injected := errors.New("snapshot driver read failure")
			observer := &sow013ReadObserver{}
			fired := false
			pin := func() error {
				// This commits on a different real connection while the reader
				// has materialized at least one row from its old snapshot.
				err := writer.BeginOperation(context.Background(), Operation{ID: "9", Kind: "add", State: OperationStaged, PayloadJSON: `{}`})
				if err == nil {
					sow013CheckpointState(t, writer, true)
				}
				return err
			}
			before := func(queryCtx context.Context, query string) error {
				if fired || !strings.Contains(query, "SELECT package_sha256, dist_name FROM memberships") || mode == "rows_error" {
					return nil
				}
				fired = true
				if err := pin(); err != nil {
					return err
				}
				switch mode {
				case "query_error":
					return injected
				case "cancel":
					cancel()
					return queryCtx.Err()
				case "deadline":
					<-queryCtx.Done()
					return queryCtx.Err()
				}
				return nil
			}
			if mode == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, time.Second)
				defer stop()
			}
			observer.next = func(_ context.Context, query string, rows int) error {
				if fired || mode != "rows_error" || rows != 1 || !strings.Contains(query, "SELECT DISTINCT p.sha256") {
					return nil
				}
				fired = true
				if err := pin(); err != nil {
					return err
				}
				return injected
			}
			reader := sow013ObservedReader(t, writer, before, observer)
			got, err := reader.ListPackageObjects(ctx, []string{"selected"}, false)
			if !fired {
				t.Fatal("read boundary was not reached")
			}
			if mode == "success" {
				if err != nil || len(got) != 2 {
					t.Fatalf("successful read: %v %v", got, err)
				}
			} else {
				want := injected
				if mode == "cancel" {
					want = context.Canceled
				}
				if mode == "deadline" {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) || got != nil {
					t.Fatalf("partial or wrong error: objects=%v err=%v want=%v", got, err, want)
				}
			}
			fresh, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			var count int
			if err := reader.db.QueryRowContext(fresh, `SELECT count(*) FROM operations WHERE id='9'`).Scan(&count); err != nil || count != 1 {
				t.Fatalf("MaxOpenConns(1) not released/new state invisible: count=%d err=%v", count, err)
			}
			if observer.begins.Load() != 1 || observer.readOnlyBegins.Load() != 1 || observer.openRows.Load() != 0 || observer.commits.Load()+observer.rollbacks.Load() != 1 {
				t.Fatalf("read transaction/Rows leaked: begin=%d readOnly=%d commit=%d rollback=%d rows=%d", observer.begins.Load(), observer.readOnlyBegins.Load(), observer.commits.Load(), observer.rollbacks.Load(), observer.openRows.Load())
			}
			if mode == "success" && observer.commits.Load() != 1 || mode != "success" && observer.rollbacks.Load() != 1 {
				t.Fatalf("wrong terminal transaction action for %s", mode)
			}
			if reader.db.Stats().InUse != 0 || reader.db.Stats().MaxOpenConnections != 1 {
				t.Fatalf("reader pool still in use: %+v", reader.db.Stats())
			}
			if err := writer.Checkpoint(fresh); err != nil {
				t.Fatal(err)
			}
			sow013CheckpointState(t, writer, false)
			t.Logf("mode=%s begin=%d commit=%d rollback=%d openRows=%d; follow-up SELECT sees writer commit; TRUNCATE checkpoint unpinned", mode, observer.begins.Load(), observer.commits.Load(), observer.rollbacks.Load(), observer.openRows.Load())
		})
	}
}

func TestSOW013CompositeCancellationReleasesSnapshot(t *testing.T) {
	for _, name := range []string{"objects", "dist", "operation", "active", "check", "roots", "gc", "ledger"} {
		t.Run(name, func(t *testing.T) {
			var writer *Store
			var binding PublicationTargetBinding
			var manifest []GenerationFile
			switch name {
			case "objects", "dist":
				writer, _ = newSparseMembershipFixture(t, 1, 1)
			case "active", "check", "roots":
				writer, binding, manifest = publicationStoreFixture(t)
				defer writer.Close()
			default:
				writer, _, _ = sow013CompositeFixture(t)
			}
			if name == "active" {
				_, digest, err := ManifestBytes(manifest)
				if err != nil {
					t.Fatal(err)
				}
				attempt := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1, ManifestSHA256: digest, PlanSHA256: strings.Repeat("a", 64), Phase: "planned", Views: []PublicationAttemptView{}}
				if err := writer.PutPublicationAttempt(context.Background(), &attempt); err != nil {
					t.Fatal(err)
				}
			}
			match := map[string]string{
				"objects":   "SELECT package_sha256, dist_name FROM memberships",
				"dist":      "SELECT family, ecosystem_arch FROM dist_architectures",
				"operation": "FROM operation_events WHERE",
				"active":    "SELECT attempt_identity, schema_version, repository_id, target_identity",
				"check":     "SELECT revision, target_identity, target_storage_id",
				"roots":     "SELECT target_identity, revision, target_storage_id",
				"gc":        "WHERE p.storage = 'pool'",
				"ledger":    "SELECT generation, previous_generation, operation_id, manifest_sha256 FROM generations ORDER BY generation",
			}[name]
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fired := false
			observer := &sow013ReadObserver{}
			reader := sow013ObservedReader(t, writer, func(queryCtx context.Context, query string) error {
				if fired || !strings.Contains(query, match) {
					return nil
				}
				fired = true
				if err := writer.BeginOperation(context.Background(), Operation{ID: "9", Kind: "add", State: OperationStaged, PayloadJSON: `{}`}); err != nil {
					return err
				}
				sow013CheckpointState(t, writer, true)
				cancel()
				return queryCtx.Err()
			}, observer)
			var got any
			var err error
			switch name {
			case "objects":
				got, err = reader.ListPackageObjects(ctx, []string{"selected"}, false)
			case "dist":
				got, err = reader.GetDist(ctx, "selected")
			case "operation":
				got, err = reader.GetOperation(ctx, "1")
			case "active":
				got, err = reader.GetActivePublicationAttempt(ctx, binding.TargetIdentity)
			case "check":
				err = reader.Check(ctx)
			case "roots":
				got, err = reader.PublicationRootRequirement(ctx)
			case "gc":
				got, err = reader.LocalGCInventory(ctx)
			case "ledger":
				err = reader.ValidateGenerationLedger(ctx)
			}
			if !fired || err == nil || got != nil && !reflect.ValueOf(got).IsZero() {
				t.Fatalf("cancellation returned partial/complete result: fired=%t result=%+v err=%v", fired, got, err)
			}
			fresh, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			var count int
			if err := reader.db.QueryRowContext(fresh, `SELECT count(*) FROM operations WHERE id='9'`).Scan(&count); err != nil || count != 1 {
				t.Fatalf("connection not reusable after %s cancellation: count=%d err=%v", name, count, err)
			}
			if observer.begins.Load() != 1 || observer.readOnlyBegins.Load() != 1 || observer.rollbacks.Load() != 1 || observer.commits.Load() != 0 || observer.openRows.Load() != 0 {
				t.Fatalf("snapshot not rolled back: begins=%d readOnly=%d commits=%d rollbacks=%d rows=%d", observer.begins.Load(), observer.readOnlyBegins.Load(), observer.commits.Load(), observer.rollbacks.Load(), observer.openRows.Load())
			}
			if err := writer.Checkpoint(fresh); err != nil {
				t.Fatal(err)
			}
			sow013CheckpointState(t, writer, false)
			t.Logf("%s cancellation returns no result; one readonly BEGIN/ROLLBACK; next SELECT and checkpoint succeed", name)
		})
	}
}

func TestSOW013PublicationManifestReadFailureIsNotIncompleteEvidence(t *testing.T) {
	writer, binding, manifest := publicationStoreFixture(t)
	defer writer.Close()
	_, digest, err := ManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	attempt := PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: 1, ManifestSHA256: digest, PlanSHA256: strings.Repeat("a", 64), Phase: "planned", Views: []PublicationAttemptView{}}
	if err := writer.PutPublicationAttempt(context.Background(), &attempt); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("generation manifest read failed")
	fired := false
	observer := &sow013ReadObserver{}
	reader := sow013ObservedReader(t, writer, func(_ context.Context, query string) error {
		if strings.Contains(query, "SELECT path, phase, size, sha256 FROM generation_files") {
			fired = true
			return injected
		}
		return nil
	}, observer)
	got, err := reader.PublicationRootRequirement(context.Background())
	if !fired || !errors.Is(err, injected) || !reflect.ValueOf(got).IsZero() {
		t.Fatalf("read error became a pseudo snapshot: fired=%t result=%+v err=%v", fired, got, err)
	}
	if observer.rollbacks.Load() != 1 || observer.openRows.Load() != 0 {
		t.Fatal("failed root read leaked its transaction")
	}
}
