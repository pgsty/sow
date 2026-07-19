package repository

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
)

func TestOpenStoreRetainedRootABAReturnsToOriginalWithoutReadingReplacement(t *testing.T) {
	workspace, root, readOnly, object := newReadOnlyStoreFixture(t, "retained-A")
	replacement := filepath.Join(workspace, "replacement-B")
	if err := installReplacementCASObject(replacement, object, []byte("replacement-B-corrupt")); err != nil {
		t.Fatal(err)
	}
	replacementObject := filepath.Join(replacement, ".pool", "sha256", object.HashString()[:2], object.HashString())

	displacedA := filepath.Join(workspace, "retained-A-displaced")
	displacedB := filepath.Join(workspace, "replacement-B-restored")
	if err := os.Rename(root, displacedA); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, root); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, displacedB); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(displacedA, root); err != nil {
		t.Fatal(err)
	}

	file, err := readOnly.OpenVerified(context.Background(), object)
	if err != nil {
		t.Fatalf("A -> B -> A must retain original A capability: %v", err)
	}
	body, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || string(body) != "retained-A" {
		t.Fatalf("retained body=%q readErr=%v closeErr=%v", body, readErr, closeErr)
	}
	replacementBody, err := os.ReadFile(filepath.Join(displacedB, ".pool", "sha256", object.HashString()[:2], object.HashString()))
	if err != nil || string(replacementBody) != "replacement-B-corrupt" {
		t.Fatalf("replacement B changed or was selected: body=%q err=%v original=%s", replacementBody, err, replacementObject)
	}

	var roots ReferenceSet
	if err := roots.Add(object); err != nil {
		t.Fatal(err)
	}
	report, err := readOnly.Audit(context.Background(), &roots)
	if err != nil || report.Stats.ReachableObjects != 1 || report.Stats.OrphanObjects != 0 {
		t.Fatalf("retained A audit report=%+v err=%v", report.Stats, err)
	}
}

func TestOpenStoreComponentABARestorationUsesOriginalCoordinates(t *testing.T) {
	for _, component := range []string{"pool", "sha256", "shard", "object"} {
		t.Run(component, func(t *testing.T) {
			_, root, readOnly, object := newReadOnlyStoreFixture(t, "retained-A")
			hash := object.HashString()
			coordinate := filepath.Join(root, ".pool")
			switch component {
			case "sha256":
				coordinate = filepath.Join(root, ".pool", "sha256")
			case "shard":
				coordinate = filepath.Join(root, ".pool", "sha256", hash[:2])
			case "object":
				coordinate = filepath.Join(root, ".pool", "sha256", hash[:2], hash)
			}
			displacedA := coordinate + "-retained-A"
			replacementB := coordinate + "-replacement-B"
			restoredB := coordinate + "-restored-B"
			var replacementObject string
			switch component {
			case "pool":
				replacementObject = filepath.Join(replacementB, "sha256", hash[:2], hash)
				if err := os.MkdirAll(filepath.Dir(replacementObject), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(replacementB, "sha256", ".tmp"), 0o755); err != nil {
					t.Fatal(err)
				}
			case "sha256":
				replacementObject = filepath.Join(replacementB, hash[:2], hash)
				if err := os.MkdirAll(filepath.Dir(replacementObject), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(replacementB, ".tmp"), 0o755); err != nil {
					t.Fatal(err)
				}
			case "shard":
				replacementObject = filepath.Join(replacementB, hash)
				if err := os.Mkdir(replacementB, 0o755); err != nil {
					t.Fatal(err)
				}
			case "object":
				replacementObject = replacementB
			}
			if err := os.WriteFile(replacementObject, []byte("replacement-B-corrupt"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(coordinate, displacedA); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacementB, coordinate); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(coordinate, restoredB); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(displacedA, coordinate); err != nil {
				t.Fatal(err)
			}
			if err := readOnly.Verify(context.Background(), object); err != nil {
				t.Fatalf("%s A -> B -> A did not return to retained A: %v", component, err)
			}
			restoredObject := replacementObject
			if component == "object" {
				restoredObject = restoredB
			} else {
				relative, err := filepath.Rel(replacementB, replacementObject)
				if err != nil {
					t.Fatal(err)
				}
				restoredObject = filepath.Join(restoredB, relative)
			}
			body, err := os.ReadFile(restoredObject)
			if err != nil || string(body) != "replacement-B-corrupt" {
				t.Fatalf("replacement B changed: body=%q err=%v", body, err)
			}
		})
	}
}

func TestOpenStorePersistentBaseReplacementFailsBeforeObjectRead(t *testing.T) {
	for _, component := range []string{"root", "pool", "sha256"} {
		t.Run(component, func(t *testing.T) {
			workspace, root, readOnly, object := newReadOnlyStoreFixture(t, "retained")
			replaced := root
			switch component {
			case "pool":
				replaced = filepath.Join(root, ".pool")
			case "sha256":
				replaced = filepath.Join(root, ".pool", "sha256")
			}
			displaced := filepath.Join(workspace, "displaced-"+component)
			if component != "root" {
				displaced = replaced + "-displaced"
			}
			if err := os.Rename(replaced, displaced); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(replaced, 0o755); err != nil {
				t.Fatal(err)
			}
			canary := filepath.Join(replaced, "replacement-B-canary")
			if err := os.WriteFile(canary, []byte("replacement-B-untouched"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := readOnly.Verify(context.Background(), object); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("persistent %s replacement error=%v", component, err)
			}
			if _, err := readOnly.Audit(context.Background(), nil); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("persistent %s replacement audit error=%v", component, err)
			}
			body, err := os.ReadFile(canary)
			if err != nil || string(body) != "replacement-B-untouched" {
				t.Fatalf("replacement B mutated: body=%q err=%v", body, err)
			}
		})
	}
}

func TestStoreVerifyRootIdentityUsesRetainedReadOnlyCapability(t *testing.T) {
	workspace, root, readOnly, _ := newReadOnlyStoreFixture(t, "retained-A")
	expected, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := readOnly.VerifyRootIdentity(expected); err != nil {
		t.Fatalf("retained root identity: %v", err)
	}
	other := filepath.Join(workspace, "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	otherInfo, err := os.Stat(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := readOnly.VerifyRootIdentity(otherInfo); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("different expected root identity error=%v", err)
	}

	displaced := filepath.Join(workspace, "retained-displaced")
	if err := os.Rename(root, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := readOnly.VerifyRootIdentity(expected); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("persistent replacement identity error=%v", err)
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(displaced, root); err != nil {
		t.Fatal(err)
	}
	if err := readOnly.VerifyRootIdentity(expected); err != nil {
		t.Fatalf("A -> B -> A root identity must return to retained A: %v", err)
	}
}

func TestOpenStoreRejectsSymlinkedBaseShardAndObjectWithoutFollowing(t *testing.T) {
	for _, component := range []string{"root", "pool", "sha256", "shard", "object"} {
		t.Run(component, func(t *testing.T) {
			workspace, root, readOnly, object := newReadOnlyStoreFixture(t, "retained")
			hash := object.HashString()
			replaced := root
			switch component {
			case "pool":
				replaced = filepath.Join(root, ".pool")
			case "sha256":
				replaced = filepath.Join(root, ".pool", "sha256")
			case "shard":
				replaced = filepath.Join(root, ".pool", "sha256", hash[:2])
			case "object":
				replaced = filepath.Join(root, ".pool", "sha256", hash[:2], hash)
			}
			displaced := filepath.Join(workspace, "symlink-displaced-"+component)
			if component != "root" {
				displaced = replaced + "-displaced"
			}
			if err := os.Rename(replaced, displaced); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(workspace, "outside-"+component)
			if component == "object" {
				if err := os.WriteFile(outside, []byte("outside-object"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(outside, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, replaced); err != nil {
				t.Fatal(err)
			}
			if err := readOnly.Verify(context.Background(), object); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("symlinked %s error=%v", component, err)
			}
			if _, err := readOnly.Audit(context.Background(), nil); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("symlinked %s audit error=%v", component, err)
			}
			if component == "object" {
				body, err := os.ReadFile(outside)
				if err != nil || string(body) != "outside-object" {
					t.Fatalf("outside object changed: body=%q err=%v", body, err)
				}
			}
		})
	}
}

func TestOpenStoreRejectsShardAndObjectReplacementAfterBinding(t *testing.T) {
	for _, point := range []readOnlyStoreTestPoint{readOnlyStoreTestAfterShardOpen, readOnlyStoreTestAfterObjectOpen} {
		for _, operation := range []string{"verify", "audit"} {
			t.Run(fmt.Sprintf("%d/%s", point, operation), func(t *testing.T) {
				_, root, readOnly, object := newReadOnlyStoreFixture(t, "retained")
				hash := object.HashString()
				shard := filepath.Join(root, ".pool", "sha256", hash[:2])
				coordinate := filepath.Join(shard, hash)
				replacementBody := []byte("replacement-B-untouched")
				var once sync.Once
				var hookErr error
				readOnly.readOnlyTestHook = func(actual readOnlyStoreTestPoint, _ string) error {
					if actual != point {
						return nil
					}
					once.Do(func() {
						if point == readOnlyStoreTestAfterShardOpen {
							displaced := shard + "-displaced"
							if err := os.Rename(shard, displaced); err != nil {
								hookErr = err
								return
							}
							if err := os.Mkdir(shard, 0o755); err != nil {
								hookErr = err
								return
							}
							if err := os.WriteFile(coordinate, replacementBody, 0o600); err != nil {
								hookErr = err
							}
							return
						}
						displaced := coordinate + "-displaced"
						if err := os.Rename(coordinate, displaced); err != nil {
							hookErr = err
							return
						}
						if err := os.WriteFile(coordinate, replacementBody, 0o600); err != nil {
							hookErr = err
						}
					})
					return hookErr
				}
				var operationErr error
				if operation == "verify" {
					operationErr = readOnly.Verify(context.Background(), object)
				} else {
					_, operationErr = readOnly.Audit(context.Background(), nil)
				}
				if !errors.Is(operationErr, ErrUnsafePath) {
					t.Fatalf("replacement point %d operation=%s error=%v hookErr=%v", point, operation, operationErr, hookErr)
				}
				body, err := os.ReadFile(coordinate)
				if err != nil || !bytes.Equal(body, replacementBody) {
					t.Fatalf("replacement object changed: body=%q err=%v", body, err)
				}
			})
		}
	}
}

func TestOpenStoreAuditGCDryRunMutationRejectionAndCloseLifecycle(t *testing.T) {
	_, root, readOnly, object := newReadOnlyStoreFixture(t, "reachable")
	var roots ReferenceSet
	if err := roots.Add(object); err != nil {
		t.Fatal(err)
	}
	report, err := readOnly.Audit(context.Background(), &roots)
	if err != nil || report.Stats.ReachableObjects != 1 {
		t.Fatalf("audit report=%+v err=%v", report.Stats, err)
	}
	dryRun, err := readOnly.GC(context.Background(), &roots, GCOptions{})
	if err != nil || !dryRun.DryRun || dryRun.Report.Stats.ReachableObjects != 1 {
		t.Fatalf("dry-run=%+v err=%v", dryRun, err)
	}
	if _, err := readOnly.GC(context.Background(), &roots, GCOptions{Apply: true, ConfirmOrphanSetSHA256: dryRun.Report.OrphanSetSHA256}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("read-only GC apply error=%v", err)
	}
	missingSource := filepath.Join(root, "must-not-be-opened")
	if _, err := readOnly.Import(context.Background(), missingSource); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("read-only import touched its source before rejecting mutation: %v", err)
	}
	if _, err := readOnly.ImportExpected(context.Background(), missingSource, object); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("read-only expected import touched its source before rejecting mutation: %v", err)
	}
	manifestBody := manifestBytes(t, manifest.Entry{Path: "export/object", Size: object.Size, SHA256: [32]byte(object.SHA256)})
	if _, err := readOnly.Materialize(context.Background(), bytes.NewReader(manifestBody), "export"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("read-only materialize error=%v", err)
	}
	desired := filepath.Join(root, "desired.tsv")
	if err := os.WriteFile(desired, manifestBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readOnly.ReconcileExact(context.Background(), desired, "export", 1, 1); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("read-only reconcile error=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "export")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only methods created export: %v", err)
	}
	retained := []*os.File{readOnly.readRootParent, readOnly.readRoot, readOnly.readPoolParent, readOnly.readPool}
	if err := readOnly.Close(); err != nil {
		t.Fatal(err)
	}
	for index, handle := range retained {
		if _, err := handle.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("retained descriptor %d remains usable after Close: %v", index, err)
		}
	}
	if err := readOnly.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if err := readOnly.Verify(context.Background(), object); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("closed store verification error=%v", err)
	}
}

func TestOpenStoreConcurrentVerifyOpenVerifiedAndAudit(t *testing.T) {
	_, _, readOnly, object := newReadOnlyStoreFixture(t, strings.Repeat("concurrent", 4096))
	var roots ReferenceSet
	if err := roots.Add(object); err != nil {
		t.Fatal(err)
	}
	const workers = 24
	const iterations = 12
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				switch worker % 3 {
				case 0:
					if err := readOnly.Verify(context.Background(), object); err != nil {
						errs <- err
						return
					}
				case 1:
					file, err := readOnly.OpenVerified(context.Background(), object)
					if err == nil {
						err = file.Close()
					}
					if err != nil {
						errs <- err
						return
					}
				case 2:
					report, err := readOnly.Audit(context.Background(), &roots)
					if err != nil || report.Stats.ReachableObjects != 1 {
						errs <- errors.Join(err, fmt.Errorf("reachable=%d", report.Stats.ReachableObjects))
						return
					}
				}
			}
		}(worker)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func newReadOnlyStoreFixture(t *testing.T, body string) (workspace, root string, readOnly *Store, object Object) {
	t.Helper()
	workspace = t.TempDir()
	root = filepath.Join(workspace, "repository")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writable := newTestStore(t, root)
	var err error
	object, err = writable.Put(context.Background(), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	readOnly, err = OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = readOnly.Close() })
	return workspace, root, readOnly, object
}

func installReplacementCASObject(root string, object Object, body []byte) error {
	shard := filepath.Join(root, ".pool", "sha256", object.HashString()[:2])
	if err := os.MkdirAll(filepath.Join(root, ".pool", "sha256", ".tmp"), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(shard, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(shard, object.HashString()), body, 0o600)
}
