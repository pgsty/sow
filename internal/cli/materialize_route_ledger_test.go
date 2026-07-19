package cli

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

func TestStageAndLoadMaterializedRouteLedgerRoundTrip(t *testing.T) {
	receipt, exact, payload := cliMaterializedRouteFixture(t)
	stageDir := t.TempDir()
	staged, err := stageMaterializedRouteLedger(stageDir, receipt, exact, payload)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath, exactPath, payloadPath, err := materializedRouteLedgerPaths(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, canonical := range []string{receiptPath, exactPath, payloadPath} {
		local, exists := staged[canonical]
		if !exists {
			t.Fatalf("missing staged path %s in %#v", canonical, staged)
		}
		info, err := os.Stat(local)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("stage %s mode=%v", canonical, info.Mode().Perm())
		}
	}
	store := state.New(filepath.Join(t.TempDir(), ".sow"))
	commit, changed, err := store.InstallPaths(staged, "test: materialized route receipt")
	if err != nil || !changed || commit.IsZero() {
		t.Fatalf("commit=%s changed=%v err=%v", commit, changed, err)
	}
	loaded, err := loadMaterializedRouteLedgerAt(store, commit, receiptPath, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.Receipt, receipt) || loaded.ExactCanonicalPath != exactPath || loaded.PayloadCanonicalPath != payloadPath {
		t.Fatalf("loaded ledger differs: %#v", loaded)
	}
	assertSameFileBytes(t, exact, loaded.ExactManifest)
	assertSameFileBytes(t, payload, loaded.PayloadManifest)
	all, err := loadMaterializedRouteLedgersAt(store, commit, receipt.TargetSHA256, receipt.View, t.TempDir())
	if err != nil || len(all) != 1 || all[0].Receipt.ID != receipt.ID {
		t.Fatalf("enumerated ledgers=%#v err=%v", all, err)
	}
}

func TestStageMaterializedRouteLedgerRejectsManifestDriftAndSymlink(t *testing.T) {
	receipt, exact, payload := cliMaterializedRouteFixture(t)
	if err := os.WriteFile(exact, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if staged, err := stageMaterializedRouteLedger(t.TempDir(), receipt, exact, payload); err == nil || len(staged) != 0 {
		t.Fatalf("drift staged=%#v err=%v", staged, err)
	}
	_, exact, payload = cliMaterializedRouteFixture(t)
	link := filepath.Join(t.TempDir(), "payload.tsv")
	if err := os.Symlink(payload, link); err != nil {
		t.Fatal(err)
	}
	if staged, err := stageMaterializedRouteLedger(t.TempDir(), receipt, exact, link); err == nil || len(staged) != 0 {
		t.Fatalf("symlink staged=%#v err=%v", staged, err)
	}
}

func TestLoadMaterializedRouteLedgersRejectsOrphanAndWrongIdentityPath(t *testing.T) {
	receipt, exact, payload := cliMaterializedRouteFixture(t)
	staged, err := stageMaterializedRouteLedger(t.TempDir(), receipt, exact, payload)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := serving.MaterializedRouteStatePrefix(receipt.TargetSHA256, receipt.View)
	if err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(t.TempDir(), "orphan.tsv")
	if err := os.WriteFile(orphan, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	staged[prefix+strings.Repeat("f", 64)+".exact.tsv"] = orphan
	store := state.New(filepath.Join(t.TempDir(), ".sow"))
	commit, _, err := store.InstallPaths(staged, "test: orphan materialized route")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadMaterializedRouteLedgersAt(store, commit, receipt.TargetSHA256, receipt.View, t.TempDir()); err == nil || !strings.Contains(err.Error(), "orphan or unknown") {
		t.Fatalf("orphan ledger error=%v", err)
	}

	canonicalBody, err := receipt.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	wrongReceipt := prefix + strings.Repeat("e", 64) + ".json"
	receiptStage := filepath.Join(t.TempDir(), "wrong.json")
	if err := os.WriteFile(receiptStage, canonicalBody, 0o600); err != nil {
		t.Fatal(err)
	}
	wrongStore := state.New(filepath.Join(t.TempDir(), ".sow"))
	wrongCommit, _, err := wrongStore.InstallPaths(map[string]string{wrongReceipt: receiptStage}, "test: wrong route identity")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadMaterializedRouteLedgerAt(wrongStore, wrongCommit, wrongReceipt, t.TempDir()); err == nil || !strings.Contains(err.Error(), "wrong identity path") {
		t.Fatalf("wrong identity error=%v", err)
	}
}

func TestMaterializedRouteTargetSHAUsesOneLexicalAbsoluteIdentity(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "target")
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(working, abs)
	if err != nil {
		t.Fatal(err)
	}
	absSHA, err := materializationTargetSHA256(abs)
	if err != nil {
		t.Fatal(err)
	}
	relativeSHA, err := materializationTargetSHA256(relative)
	if err != nil {
		t.Fatal(err)
	}
	if absSHA != relativeSHA {
		t.Fatalf("relative/absolute target identity differs: %s != %s", relativeSHA, absSHA)
	}
}

func cliMaterializedRouteFixture(t *testing.T) (serving.MaterializedRoute, string, string) {
	t.Helper()
	directory := t.TempDir()
	payloadBody := []byte("payload\n")
	metadataBody := []byte("metadata\n")
	exact := filepath.Join(directory, "exact.tsv")
	payload := filepath.Join(directory, "payload.tsv")
	entries := []manifest.Entry{
		{Path: "yum/infra/x86_64/Packages/p/pkg.rpm", Size: int64(len(payloadBody)), SHA256: sha256.Sum256(payloadBody)},
		{Path: "yum/infra/x86_64/repodata/repomd.xml", Size: int64(len(metadataBody)), SHA256: sha256.Sum256(metadataBody)},
	}
	writeCLIRouteManifest(t, exact, entries)
	writeCLIRouteManifest(t, payload, entries[:1])
	exactReader, err := os.Open(exact)
	if err != nil {
		t.Fatal(err)
	}
	payloadReader, err := os.Open(payload)
	if err != nil {
		t.Fatal(err)
	}
	receipt, deriveErr := serving.NewMaterializedRoute(serving.MaterializedRouteIdentity{
		Kind: "yum", View: "latest", Source: "latest", TargetSHA256: strings.Repeat("a", 64),
		Claims:       []serving.MaterializedRouteClaim{{Kind: serving.MaterializedRouteClaimPrefix, RelativeRoot: "yum/infra/x86_64"}},
		ConfigSHA256: strings.Repeat("b", 64), ConfigCommit: strings.Repeat("e", 40), ServingTargetID: strings.Repeat("9", 64), Repo: "infra", OS: "all", Arch: "x86_64",
		Refs: []serving.MaterializedRouteRef{{Name: "refs/sow/views/latest/infra/el8/x86_64", Commit: strings.Repeat("c", 40), ManifestBlob: strings.Repeat("f", 40), ManifestSize: 1}},
	}, exactReader, payloadReader)
	closeErr := errors.Join(exactReader.Close(), payloadReader.Close())
	if deriveErr != nil || closeErr != nil {
		t.Fatal(errors.Join(deriveErr, closeErr))
	}
	return receipt, exact, payload
}

func writeCLIRouteManifest(t *testing.T, name string, entries []manifest.Entry) {
	t.Helper()
	file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := manifest.WriteEntry(file, entry); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertSameFileBytes(t *testing.T, left, right string) {
	t.Helper()
	leftBody, leftErr := os.ReadFile(left)
	rightBody, rightErr := os.ReadFile(right)
	if leftErr != nil || rightErr != nil || string(leftBody) != string(rightBody) {
		t.Fatalf("file bytes differ left=%q right=%q err=%v", leftBody, rightBody, errors.Join(leftErr, rightErr))
	}
}
