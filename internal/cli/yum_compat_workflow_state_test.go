package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

func completeYUMCompatibilityCandidate(t *testing.T) yumCompatibilityCandidate {
	t.Helper()
	hash := func(value byte) string { return strings.Repeat(string(value), 64) }
	git := func(value byte) string { return strings.Repeat(string(value), 40) }
	result := yumCompatibilityCandidate{
		Schema: yumCompatibilityCandidateSchema, ID: "infra-legacy-x86-64", Root: "yum/infra/x86_64", Carrier: "infra-carrier", OwnerRepo: "infra-el9",
		SourceRef: "refs/sow/compatibility/yum-source/infra-legacy-x86-64", SourceCommit: git('a'),
		SourceManifestSHA256: hash('a'), SourceManifestGit: git('b'), SourceManifestSize: 101,
		AdoptionSHA256: hash('b'), AdoptionGit: git('c'), AdoptionSize: 102,
		PackageTrustSHA256: hash('c'), PackageTrustGit: git('d'), PackageTrustSize: 103,
		CandidatePath: "/operator/private/candidate", CandidateManifestSHA256: hash('d'), CandidateManifestGit: git('e'), CandidateManifestSize: 104,
		RepomdSHA256: hash('e'), RepositoryKeySHA256: hash('f'), RepositoryTrustSHA256: hash('1'), RepositoryTrustGit: git('f'), RepositoryTrustSize: 105,
		Packages: 2, Bytes: 200,
	}
	var err error
	result.FreezeConfirm, err = yumCompatibilityConfirmation("freeze", result)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testYUMCompatibilityCandidateBinding(t *testing.T, output string) *yumCompatibilityCandidateBinding {
	t.Helper()
	hostedRoot := t.TempDir()
	binding, err := openYUMCompatibilityCandidateBinding(&config.Config{Root: hostedRoot}, output)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = binding.Close() })
	return binding
}

func TestYUMCompatibilityCandidateCanonicalReceiptOmitsOperatorPath(t *testing.T) {
	receipt := completeYUMCompatibilityCandidate(t)
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("candidate_path")) || bytes.Contains(body, []byte(receipt.CandidatePath)) {
		t.Fatalf("canonical receipt leaked operator path: %s", body)
	}
	decoded, err := decodeYUMCompatibilityCandidate(body)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.CandidatePath != "" || decoded.RepositoryTrustSHA256 != receipt.RepositoryTrustSHA256 || decoded.RepositoryTrustGit != receipt.RepositoryTrustGit || decoded.RepositoryTrustSize != receipt.RepositoryTrustSize {
		t.Fatalf("decoded portable receipt=%+v", decoded)
	}
	confirmation, err := yumCompatibilityConfirmation("freeze", decoded)
	if err != nil || confirmation != receipt.FreezeConfirm {
		t.Fatalf("portable confirmation=%q want=%q err=%v", confirmation, receipt.FreezeConfirm, err)
	}
}

func TestYUMCompatibilityFreezeExpectedFilesCoverEveryStagedArtifact(t *testing.T) {
	paths := []string{
		"compatibility/yum/id/projection.json",
		"compatibility/yum/id/manifest.tsv",
		"compatibility/yum/id/package-trust.pgp",
		"compatibility/yum/id/candidate.tsv",
		"compatibility/yum/id/candidate.json",
		"compatibility/yum/id/repository-trust.pgp",
	}
	trust := yumCompatibilityPackageTrust{size: 123, sha256: strings.Repeat("a", 64)}
	expected := yumCompatibilityFreezeExpectedFiles(paths[0], paths[1], paths[2], paths[3], paths[4], paths[5], trust)
	if len(expected) != len(paths) {
		t.Fatalf("freeze expected-file closure has %d paths, want %d: %+v", len(expected), len(paths), expected)
	}
	for _, canonicalPath := range paths {
		if _, exists := expected[canonicalPath]; !exists {
			t.Fatalf("freeze expected-file closure omitted %s", canonicalPath)
		}
	}
	for _, canonicalPath := range []string{paths[0], paths[1], paths[3], paths[4], paths[5]} {
		if expectation := expected[canonicalPath]; !expectation.AllowAbsent || len(expectation.Identities) != 0 {
			t.Fatalf("new S2 path %s expectation=%+v", canonicalPath, expectation)
		}
	}
	packageExpectation := expected[paths[2]]
	if packageExpectation.AllowAbsent || len(packageExpectation.Identities) != 1 || packageExpectation.Identities[0].Size != trust.size || packageExpectation.Identities[0].SHA256 != trust.sha256 {
		t.Fatalf("S1 package trust is not exact compare-and-set evidence: %+v", packageExpectation)
	}
}

func TestYUMCompatibilityCandidateShapeRejectsExtraRootAndRepodataFiles(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{filepath.Join(root, "Packages", "a"), filepath.Join(root, "repodata")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"pkg.rpm": "flat", "Packages/a/pkg.rpm": "canonical",
		"repodata/00-primary.xml.gz": "primary", "repodata/01-filelists.xml.gz": "filelists", "repodata/02-other.xml.gz": "other",
		"repodata/repomd.xml": "repomd", "repodata/repomd.xml.asc": "signature",
	} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	payload := filepath.Join(t.TempDir(), "payload.tsv")
	if _, err := manifest.Scan(t.Context(), root, manifest.Scope{Path: ".", Include: []string{"Packages/**", "*.rpm"}}, payload, manifest.ScanOptions{Workers: 1, ChunkEntries: 2, TempDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	generation := &yumrepo.Generation{Artifacts: [3]yumrepo.Artifact{
		{Type: "primary", Path: "repodata/00-primary.xml.gz"},
		{Type: "filelists", Path: "repodata/01-filelists.xml.gz"},
		{Type: "other", Path: "repodata/02-other.xml.gz"},
	}}
	if err := validateYUMCompatibilityCandidateShape(root, payload, generation); err != nil {
		t.Fatalf("exact candidate shape rejected: %v", err)
	}
	for _, extra := range []string{"unexpected.txt", "repodata/canary"} {
		t.Run(extra, func(t *testing.T) {
			filename := filepath.Join(root, filepath.FromSlash(extra))
			if err := os.WriteFile(filename, []byte("must reject"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validateYUMCompatibilityCandidateShape(root, payload, generation); err == nil || !strings.Contains(err.Error(), "unexpected file") {
				t.Fatalf("extra candidate file was accepted: %v", err)
			}
			if err := os.Remove(filename); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestYUMCompatibilityVerbHelpUsesDedicatedFlagSurface(t *testing.T) {
	verbs := map[string][]string{
		"yum-adopt":     nil,
		"yum-candidate": {"--output", "--gpg-private-key-file", "--gpg-passphrase-file"},
		"yum-freeze":    {"--candidate", "--confirm"},
		"yum-cutover":   {"--confirm"},
		"yum-rollback":  {"--confirm"},
	}
	common := []string{"--config", "--root", "--workers", "--chunk-entries", "--recover", "--id"}
	for verb, extra := range verbs {
		t.Run(verb, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Main([]string{"compatibility", verb, "--help"}, &stdout, &stderr); code != ExitOK {
				t.Fatalf("help exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			body := stdout.String() + stderr.String()
			for _, flagName := range append(append([]string(nil), common...), extra...) {
				if !strings.Contains(body, flagName) {
					t.Errorf("help omitted supported flag %s: %s", flagName, body)
				}
			}
			for _, forbidden := range []string{"--repo", "--os", "--arch"} {
				if strings.Contains(body, forbidden) {
					t.Errorf("help exposed ordinary selector %s: %s", forbidden, body)
				}
			}
			if !strings.Contains(body, "[--chunk-entries N]") {
				t.Errorf("synopsis omitted --chunk-entries: %s", body)
			}
		})
	}
}

func TestYUMCompatibilityVerbsRejectOrdinarySelectorFlagsAtParseBoundary(t *testing.T) {
	for _, verb := range []string{"yum-adopt", "yum-candidate", "yum-freeze", "yum-cutover", "yum-rollback"} {
		for _, selector := range []string{"--repo", "--os", "--arch"} {
			t.Run(verb+"/"+selector, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				if code := Main([]string{"compatibility", verb, selector, "forbidden"}, &stdout, &stderr); code != ExitUsage || !strings.Contains(stderr.String(), "flag provided but not defined") {
					t.Fatalf("selector exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
				}
			})
		}
	}
}

func sealYUMCompatibilityCutoverEvent(t *testing.T, event yumCompatibilityCutoverEvent) yumCompatibilityCutoverEvent {
	t.Helper()
	event.EventSHA256 = ""
	value, err := buildYUMCompatibilityCutoverEventHash(event)
	if err != nil {
		t.Fatal(err)
	}
	event.EventSHA256 = value
	return event
}

func TestYUMCompatibilityCutoverLedgerUsesPortableLogicalPaths(t *testing.T) {
	digest := strings.Repeat("a", 64)
	freeze := strings.Repeat("b", 40)
	id := "infra-legacy-x86-64"
	cutover := sealYUMCompatibilityCutoverEvent(t, yumCompatibilityCutoverEvent{
		Schema: yumCompatibilityCutoverEventSchema, Sequence: 1, ID: id, Action: "cutover",
		ServingLink: path.Join(".sow", "serving", "compatibility", "yum", id, "current"),
		FromTarget:  "yum/infra/x86_64", ToTarget: path.Join(".sow", "materialized", "compatibility", id, digest),
		FreezeCommit: freeze, CandidateManifestSHA256: digest, PreviousEventSHA256: strings.Repeat("0", 64),
	})
	first, _ := json.Marshal(cutover)
	events, err := decodeYUMCompatibilityCutoverLedger(append(first, '\n'))
	if err != nil || len(events) != 1 || yumCompatibilityLedgerStage(events) != yumCompatibilityStageS3 {
		t.Fatalf("portable cutover ledger events=%+v err=%v", events, err)
	}
	rollback := sealYUMCompatibilityCutoverEvent(t, yumCompatibilityCutoverEvent{
		Schema: yumCompatibilityCutoverEventSchema, Sequence: 2, ID: id, Action: "rollback",
		ServingLink: cutover.ServingLink, FromTarget: cutover.ToTarget, ToTarget: cutover.FromTarget,
		FreezeCommit: freeze, CandidateManifestSHA256: digest, PreviousEventSHA256: cutover.EventSHA256,
	})
	second, _ := json.Marshal(rollback)
	ledger := append(append(append([]byte(nil), first...), '\n'), second...)
	ledger = append(ledger, '\n')
	events, err = decodeYUMCompatibilityCutoverLedger(ledger)
	if err != nil || yumCompatibilityLedgerStage(events) != yumCompatibilityStageRolledBack {
		t.Fatalf("portable rollback ledger events=%+v err=%v", events, err)
	}
	for name, mutate := range map[string]func(*yumCompatibilityCutoverEvent){
		"absolute serving link":  func(event *yumCompatibilityCutoverEvent) { event.ServingLink = "/tmp/current" },
		"parent traversal":       func(event *yumCompatibilityCutoverEvent) { event.FromTarget = "../production" },
		"wrong candidate target": func(event *yumCompatibilityCutoverEvent) { event.ToTarget = "candidate" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cutover
			mutate(&changed)
			changed = sealYUMCompatibilityCutoverEvent(t, changed)
			body, _ := json.Marshal(changed)
			if _, err := decodeYUMCompatibilityCutoverLedger(append(body, '\n')); err == nil {
				t.Fatalf("unsafe canonical event accepted: %+v", changed)
			}
		})
	}
}

func TestYUMCompatibilityCandidateJournalRecoversPartialSidecarCommit(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "candidate")
	id := "infra-legacy-x86-64"
	binding := testYUMCompatibilityCandidateBinding(t, output)
	journal, err := createYUMCompatibilityCandidateJournal(id, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journal.Stage, "payload"), []byte("candidate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal.PendingManifest, []byte("manifest"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal.PendingReceipt, []byte("receipt"), 0o600); err != nil {
		t.Fatal(err)
	}
	journal.Phase = yumCompatibilityCandidatePrepared
	if err := writeYUMCompatibilityCandidateJournal(binding, journal, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(yumCompatibilityCandidateJournalPath(output)+".next", []byte("{\"phase\":"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := recoverYUMCompatibilityCandidateJournal(id, binding, true)
	if err != nil || !recovered {
		t.Fatalf("recover candidate=%v err=%v", recovered, err)
	}
	manifestPath, receiptPath := yumCompatibilityCandidateSidecars(output)
	for _, name := range []string{filepath.Join(output, "payload"), manifestPath, receiptPath, yumCompatibilityCandidateJournalPath(output)} {
		if _, err := os.Lstat(name); err != nil {
			t.Fatalf("recovered path %s: %v", name, err)
		}
	}
	if err := removeYUMCompatibilityCandidateJournal(binding); err != nil {
		t.Fatal(err)
	}
}

func TestYUMCompatibilityCandidateJournalNeverOverwritesSidecar(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "candidate")
	id := "infra-legacy-x86-64"
	binding := testYUMCompatibilityCandidateBinding(t, output)
	journal, err := createYUMCompatibilityCandidateJournal(id, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal.PendingManifest, []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal.PendingReceipt, []byte("receipt"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath, _ := yumCompatibilityCandidateSidecars(output)
	if err := os.WriteFile(manifestPath, []byte("operator-owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	journal.Phase = yumCompatibilityCandidatePrepared
	if err := writeYUMCompatibilityCandidateJournal(binding, journal, false); err != nil {
		t.Fatal(err)
	}
	if _, err := recoverYUMCompatibilityCandidateJournal(id, binding, true); err == nil || !strings.Contains(err.Error(), "refuses to overwrite") {
		t.Fatalf("preexisting sidecar was not protected: %v", err)
	}
	body, _ := os.ReadFile(manifestPath)
	if string(body) != "operator-owned" {
		t.Fatalf("preexisting sidecar changed: %q", body)
	}
}

func TestYUMCompatibilityCandidateBindingRejectsParentReplacementWithoutRedirect(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "candidate")
	hostedRoot := t.TempDir()
	binding, err := openYUMCompatibilityCandidateBinding(&config.Config{Root: hostedRoot}, output)
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	displaced := parent + ".bound-original"
	canary := t.TempDir()
	if err := os.Rename(parent, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canary, parent); err != nil {
		t.Fatal(err)
	}
	journal := expectedYUMCompatibilityCandidateJournal("infra-legacy-x86-64", binding)
	if err := binding.writeExclusive(yumCompatibilityCandidateJournalPath(output), []byte("must-not-write")); err == nil || !strings.Contains(err.Error(), "parent was replaced") {
		t.Fatalf("replaced candidate parent was accepted: %v", err)
	}
	for _, name := range []string{
		filepath.Join(canary, filepath.Base(yumCompatibilityCandidateJournalPath(output))),
		filepath.Join(hostedRoot, filepath.Base(journal.Output)),
		filepath.Join(displaced, filepath.Base(yumCompatibilityCandidateJournalPath(output))),
	} {
		if _, err := os.Lstat(name); !os.IsNotExist(err) {
			t.Fatalf("candidate mutation escaped bound parent to %s: %v", name, err)
		}
	}
}

func TestYUMCompatibilityCandidateBindingRejectsWritableParentWithoutChmod(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(parent, "candidate")
	if _, err := openYUMCompatibilityCandidateBinding(&config.Config{Root: t.TempDir()}, output); err == nil ||
		!strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("writable candidate parent was admitted: %v", err)
	}
	info, err := os.Lstat(parent)
	if err != nil || info.Mode().Perm() != 0o777 {
		t.Fatalf("unsafe candidate parent was mutated: mode=%v err=%v", info.Mode().Perm(), err)
	}
}

func TestYUMCompatibilityCandidateJournalRejectsHardlinkAlias(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "candidate")
	id := "infra-legacy-x86-64"
	binding := testYUMCompatibilityCandidateBinding(t, output)
	if _, err := createYUMCompatibilityCandidateJournal(id, binding); err != nil {
		t.Fatal(err)
	}
	journalPath := yumCompatibilityCandidateJournalPath(output)
	alias := filepath.Join(t.TempDir(), "candidate-journal-alias")
	if err := os.Link(journalPath, alias); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readYUMCompatibilityCandidateJournal(binding, id); err == nil ||
		!strings.Contains(err.Error(), "link count") {
		t.Fatalf("hardlink-aliased candidate journal was read: %v", err)
	}
	if err := removeYUMCompatibilityCandidateJournal(binding); err == nil ||
		!strings.Contains(err.Error(), "link count") {
		t.Fatalf("hardlink-aliased candidate journal was removed: %v", err)
	}
	left, leftErr := os.Lstat(journalPath)
	right, rightErr := os.Lstat(alias)
	if leftErr != nil || rightErr != nil || !os.SameFile(left, right) {
		t.Fatalf("candidate journal alias evidence was not preserved: left=%v right=%v", leftErr, rightErr)
	}
}

func TestYUMCompatibilityCandidatePhaseExchangeRejectsDestinationAlias(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "candidate")
	id := "infra-legacy-x86-64"
	binding := testYUMCompatibilityCandidateBinding(t, output)
	journal, err := createYUMCompatibilityCandidateJournal(id, binding)
	if err != nil {
		t.Fatal(err)
	}
	base := yumCompatibilityCandidateJournalPath(binding.output)
	before, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "candidate-phase-alias")
	previous := derivedStateControlBeforeExchangeHook
	fired := false
	derivedStateControlBeforeExchangeHook = func(_, destination string) error {
		if fired || destination != filepath.Base(base) {
			return nil
		}
		fired = true
		return os.Link(base, alias)
	}
	t.Cleanup(func() { derivedStateControlBeforeExchangeHook = previous })
	journal.Phase = yumCompatibilityCandidatePrepared
	if err := writeYUMCompatibilityCandidateJournal(binding, journal, false); err == nil ||
		!strings.Contains(err.Error(), "link count") {
		t.Fatalf("hardlink-aliased candidate phase destination was overwritten: %v", err)
	}
	derivedStateControlBeforeExchangeHook = previous
	if !fired {
		t.Fatal("candidate destination race was not injected")
	}
	assertUnchangedHardlinkEvidence(t, base, alias, before)
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := writeYUMCompatibilityCandidateJournal(binding, journal, false); err != nil {
		t.Fatalf("candidate phase retry after removing alias: %v", err)
	}
	observed, exists, err := readYUMCompatibilityCandidateJournal(binding, id)
	if err != nil || !exists || observed.Phase != yumCompatibilityCandidatePrepared {
		t.Fatalf("candidate phase retry observed=%+v exists=%t err=%v", observed, exists, err)
	}
}

func TestYUMCompatibilityBoundCutoverJournalRejectsHardlinkAlias(t *testing.T) {
	statePath := t.TempDir()
	root, err := os.OpenRoot(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	id := "infra-legacy-x86-64"
	name, err := yumCompatibilityCutoverJournalName(id)
	if err != nil {
		t.Fatal(err)
	}
	journal := yumCompatibilityCutoverJournal{
		Schema: yumCompatibilityCutoverJournalSchema, ID: id, Action: "cutover",
		Phase: yumCompatibilityCutoverPrepared, EventSHA256: strings.Repeat("a", 64),
		ServingLink: "/tmp/serving", FromTarget: "/tmp/raw", ToTarget: "/tmp/candidate",
	}
	body, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statePath, name), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "cutover-journal-alias")
	if err := os.Link(filepath.Join(statePath, name), alias); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readYUMCompatibilityCutoverJournalBoundAt(root, name, id); err == nil ||
		!strings.Contains(err.Error(), "link count") {
		t.Fatalf("hardlink-aliased cutover journal was read: %v", err)
	}
	info, err := root.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := removeExactYUMCompatibilityBoundControlFile(root, name, info); err == nil ||
		!strings.Contains(err.Error(), "link count") {
		t.Fatalf("hardlink-aliased cutover journal was removed: %v", err)
	}
	left, leftErr := os.Lstat(filepath.Join(statePath, name))
	right, rightErr := os.Lstat(alias)
	if leftErr != nil || rightErr != nil || !os.SameFile(left, right) {
		t.Fatalf("cutover journal alias evidence was not preserved: left=%v right=%v", leftErr, rightErr)
	}
}

func TestYUMCompatibilityControlWritersRejectHardlinkBeforeWrite(t *testing.T) {
	t.Run("candidate", func(t *testing.T) {
		parent := t.TempDir()
		output := filepath.Join(parent, "candidate")
		binding := testYUMCompatibilityCandidateBinding(t, output)
		control := yumCompatibilityCandidateJournalPath(binding.output)
		alias := filepath.Join(t.TempDir(), "candidate-control-alias")
		previous := derivedStateControlBeforeWriteHook
		fired := false
		derivedStateControlBeforeWriteHook = func(kind, name string) error {
			if fired || kind != "yum-candidate" || name != control {
				return nil
			}
			fired = true
			return os.Link(control, alias)
		}
		t.Cleanup(func() { derivedStateControlBeforeWriteHook = previous })

		if _, err := binding.writeExclusiveControl(control, []byte("must not reach alias\n")); err == nil ||
			!strings.Contains(err.Error(), "link count") {
			t.Fatalf("hardlink-aliased candidate control was written: %v", err)
		}
		derivedStateControlBeforeWriteHook = previous
		if !fired {
			t.Fatal("candidate hardlink race was not injected")
		}
		assertEmptyHardlinkEvidence(t, control, alias)
	})

	t.Run("bound", func(t *testing.T) {
		statePath := t.TempDir()
		root, err := os.OpenRoot(statePath)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		name := "bound-control.next"
		control := filepath.Join(statePath, name)
		alias := filepath.Join(t.TempDir(), "bound-control-alias")
		previous := derivedStateControlBeforeWriteHook
		fired := false
		derivedStateControlBeforeWriteHook = func(kind, observed string) error {
			if fired || kind != "yum-bound" || observed != name {
				return nil
			}
			fired = true
			return os.Link(control, alias)
		}
		t.Cleanup(func() { derivedStateControlBeforeWriteHook = previous })

		if _, err := writeYUMCompatibilityBoundControlFile(root, name, []byte("must not reach alias\n")); err == nil ||
			!strings.Contains(err.Error(), "link count") {
			t.Fatalf("hardlink-aliased bound control was written: %v", err)
		}
		derivedStateControlBeforeWriteHook = previous
		if !fired {
			t.Fatal("bound hardlink race was not injected")
		}
		assertEmptyHardlinkEvidence(t, control, alias)
	})
}

func assertEmptyHardlinkEvidence(t *testing.T, control, alias string) {
	t.Helper()
	left, leftErr := os.Lstat(control)
	right, rightErr := os.Lstat(alias)
	if leftErr != nil || rightErr != nil || left == nil || right == nil ||
		!os.SameFile(left, right) || left.Size() != 0 || right.Size() != 0 {
		t.Fatalf("hardlink evidence changed: left=%v right=%v errors=%v/%v", left, right, leftErr, rightErr)
	}
}

func assertUnchangedHardlinkEvidence(t *testing.T, control, alias string, before []byte) {
	t.Helper()
	left, leftErr := os.Lstat(control)
	right, rightErr := os.Lstat(alias)
	after, readErr := os.ReadFile(control)
	if leftErr != nil || rightErr != nil || readErr != nil || left == nil || right == nil ||
		!os.SameFile(left, right) || !bytes.Equal(after, before) {
		t.Fatalf("hardlink destination evidence changed: before=%q after=%q left=%v right=%v errors=%v/%v/%v", before, after, left, right, leftErr, rightErr, readErr)
	}
}

func TestYUMCompatibilityCandidateRecoveryRejectsCrossProcessParentClone(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "candidate")
	hostedRoot := t.TempDir()
	id := "infra-legacy-x86-64"
	original, err := openYUMCompatibilityCandidateBinding(&config.Config{Root: hostedRoot}, output)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := createYUMCompatibilityCandidateJournal(id, original)
	if err != nil {
		t.Fatal(err)
	}
	journalBody, err := os.ReadFile(yumCompatibilityCandidateJournalPath(output))
	if err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	displaced := parent + ".original"
	if err := os.Rename(parent, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(yumCompatibilityCandidateJournalPath(output), journalBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(journal.Stage, 0o700); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(journal.Stage, "must-survive")
	if err := os.WriteFile(canary, []byte("clone canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := openYUMCompatibilityCandidateBinding(&config.Config{Root: hostedRoot}, output)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := recoverYUMCompatibilityCandidateJournal(id, reopened, true); err == nil || !strings.Contains(err.Error(), "identity differs") {
		t.Fatalf("cloned journal parent identity was accepted: %v", err)
	}
	bodyAfter, readErr := os.ReadFile(yumCompatibilityCandidateJournalPath(output))
	if readErr != nil || !bytes.Equal(bodyAfter, journalBody) {
		t.Fatalf("replacement journal was mutated: equal=%t err=%v", bytes.Equal(bodyAfter, journalBody), readErr)
	}
	if body, readErr := os.ReadFile(canary); readErr != nil || string(body) != "clone canary" {
		t.Fatalf("replacement stage canary was mutated: body=%q err=%v", body, readErr)
	}
	if _, err := os.Lstat(filepath.Join(displaced, filepath.Base(journal.Stage))); err != nil {
		t.Fatalf("original bound stage was mutated: %v", err)
	}
}

func TestYUMCompatibilityCandidateBindingRejectsStageReplacementAndOutputSymlink(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "candidate")
	binding := testYUMCompatibilityCandidateBinding(t, output)
	journal, err := createYUMCompatibilityCandidateJournal("infra-legacy-x86-64", binding)
	if err != nil {
		t.Fatal(err)
	}
	stageRoot, stageIdentity, err := binding.openBoundDirectory(journal.Stage)
	if err != nil {
		t.Fatal(err)
	}
	defer stageRoot.Close()
	displaced := journal.Stage + ".displaced"
	canary := t.TempDir()
	if err := os.Rename(journal.Stage, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canary, journal.Stage); err != nil {
		t.Fatal(err)
	}
	if err := binding.verifyBoundDirectory(journal.Stage, stageIdentity); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("replaced candidate stage was accepted: %v", err)
	}
	if entries, err := os.ReadDir(canary); err != nil || len(entries) != 0 {
		t.Fatalf("replaced candidate stage canary was mutated: entries=%v err=%v", entries, err)
	}
	if err := os.Remove(journal.Stage); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(displaced, journal.Stage); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canary, output); err != nil {
		t.Fatal(err)
	}
	if err := reconcileCandidateRename(binding, journal.Stage, output, true); err == nil {
		t.Fatal("symlink candidate output was overwritten")
	}
	if info, err := os.Lstat(output); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("candidate output symlink changed: info=%v err=%v", info, err)
	}
}

func TestYUMCompatibilityCandidateStageAfterAdmissionCannotWriteReplacementParent(t *testing.T) {
	repositoryPath := filepath.Join(t.TempDir(), "repository")
	if err := os.Mkdir(repositoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(repositoryPath)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("candidate-stage-capability-payload\n")
	object, err := pool.Put(t.Context(), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.AcquireLock(filepath.Join(repositoryPath, config.StateDirectory), "compatibility-candidate-stage-capability", false)
	if err != nil {
		t.Fatal(err)
	}
	workflow := yumCompatibilityWorkflow{cfg: &config.Config{Root: repositoryPath}}
	if err := workflow.bindMutationRoots(lock); err != nil {
		t.Fatal(err)
	}
	candidateParent := t.TempDir()
	output := filepath.Join(candidateParent, "candidate")
	binding := testYUMCompatibilityCandidateBinding(t, output)
	journal, err := createYUMCompatibilityCandidateJournal("infra-legacy-x86-64", binding)
	if err != nil {
		t.Fatal(err)
	}
	desired := filepath.Join(t.TempDir(), "candidate.tsv")
	if err := os.WriteFile(desired, []byte(fmt.Sprintf("repodata/payload\t%d\t%s\n", object.Size, object.HashString())), 0o600); err != nil {
		t.Fatal(err)
	}
	actual := filepath.Join(t.TempDir(), "actual.tsv")
	displaced := candidateParent + ".original"
	replacementStage := filepath.Join(candidateParent, filepath.Base(journal.Stage))
	workflow.mutationHook = func(phase string) error {
		if phase != "populate external yum-candidate stage" {
			return fmt.Errorf("unexpected mutation phase %s", phase)
		}
		if err := os.Rename(candidateParent, displaced); err != nil {
			return err
		}
		if err := os.Mkdir(candidateParent, 0o700); err != nil {
			return err
		}
		if err := os.Mkdir(replacementStage, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(replacementStage, "canary"), []byte("replacement-must-survive\n"), 0o600)
	}
	_, err = populateYUMCompatibilityBoundCandidateStage(t.Context(), workflow, binding, journal.Stage, desired, actual)
	if err == nil || !strings.Contains(err.Error(), "parent was replaced") {
		t.Fatalf("bound candidate stage did not report replacement parent: %v", err)
	}
	if body, readErr := os.ReadFile(filepath.Join(displaced, filepath.Base(journal.Stage), "repodata", "payload")); readErr != nil || !bytes.Equal(body, payload) {
		t.Fatalf("bound original candidate stage payload=%q err=%v", body, readErr)
	}
	if _, err := os.Lstat(filepath.Join(replacementStage, "repodata", "payload")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement candidate stage received payload: %v", err)
	}
	if body, readErr := os.ReadFile(filepath.Join(replacementStage, "canary")); readErr != nil || string(body) != "replacement-must-survive\n" {
		t.Fatalf("replacement candidate stage canary changed: body=%q err=%v", body, readErr)
	}
	if err := workflow.closeMutationRoots(); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestYUMCompatibilityMutationBoundaryRejectsRepositoryRootSwap(t *testing.T) {
	parent := t.TempDir()
	repositoryPath := filepath.Join(parent, "repository")
	if err := os.Mkdir(repositoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	originalCanary := filepath.Join(repositoryPath, "original-canary")
	if err := os.WriteFile(originalCanary, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := state.AcquireLock(filepath.Join(repositoryPath, config.StateDirectory), "compatibility-first", false)
	if err != nil {
		t.Fatal(err)
	}
	workflow := yumCompatibilityWorkflow{cfg: &config.Config{Root: repositoryPath}}
	if err := workflow.bindMutationRoots(first); err != nil {
		t.Fatal(err)
	}
	displaced := repositoryPath + ".original"
	if err := os.Rename(repositoryPath, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(repositoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	replacementCanary := filepath.Join(repositoryPath, "replacement-canary")
	if err := os.WriteFile(replacementCanary, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := state.AcquireLock(filepath.Join(repositoryPath, config.StateDirectory), "compatibility-second", false)
	if err != nil {
		t.Fatal(err)
	}
	replacementLock := filepath.Join(repositoryPath, config.StateDirectory, "locks", "state.lock")
	replacementLockInfo, err := os.Lstat(replacementLock)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "fault-injected mutation"); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("repository replacement was accepted: %v", err)
	}
	if err := workflow.closeMutationRoots(); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("first holder released through a replaced repository coordinate: %v", err)
	}
	if current, err := os.Lstat(replacementLock); err != nil || !os.SameFile(replacementLockInfo, current) {
		t.Fatalf("first holder removed replacement lock: %v", err)
	}
	for filename, expected := range map[string]string{
		filepath.Join(displaced, "original-canary"): "original",
		replacementCanary: "replacement",
	} {
		body, err := os.ReadFile(filename)
		if err != nil || string(body) != expected {
			t.Fatalf("root-swap canary %s changed: body=%q err=%v", filename, body, err)
		}
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(repositoryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(displaced, repositoryPath); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("first holder could not release after restoring its exact coordinate: %v", err)
	}
}

func TestYUMCompatibilityCanonicalCommitAfterAdmissionCannotWriteReplacementRoot(t *testing.T) {
	parent := t.TempDir()
	repositoryPath := filepath.Join(parent, "repository")
	if err := os.Mkdir(repositoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(repositoryPath, config.StateDirectory)
	first, err := state.AcquireLock(statePath, "compatibility-bound-canonical-first", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(statePath, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statePath, "state", "canary"), []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workflow := yumCompatibilityWorkflow{cfg: &config.Config{Root: repositoryPath}}
	if err := workflow.bindMutationRoots(first); err != nil {
		t.Fatal(err)
	}
	workspace, err := newYUMCompatibilityCanonicalWorkspace(workflow)
	if err != nil {
		t.Fatal(err)
	}
	defer workspace.Close()
	if err := os.WriteFile(filepath.Join(workspace.stateDir, "state", "canary"), []byte("committed-to-original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	displaced := repositoryPath + ".original"
	var second *state.Lock
	workflow.mutationHook = func(phase string) error {
		if phase != "fault-after-admission" {
			return fmt.Errorf("unexpected mutation phase %s", phase)
		}
		if err := os.Rename(repositoryPath, displaced); err != nil {
			return err
		}
		if err := os.Mkdir(repositoryPath, 0o700); err != nil {
			return err
		}
		var err error
		second, err = state.AcquireLock(filepath.Join(repositoryPath, config.StateDirectory), "compatibility-bound-canonical-second", false)
		if err != nil {
			return err
		}
		if err := os.Mkdir(filepath.Join(repositoryPath, config.StateDirectory, "state"), 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(repositoryPath, config.StateDirectory, "state", "canary"), []byte("replacement-must-survive\n"), 0o600)
	}
	changed, err := workspace.Commit(workflow, "fault-after-admission")
	if !changed || err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("bound commit did not report the injected namespace replacement: changed=%t err=%v", changed, err)
	}
	for filename, expected := range map[string]string{
		filepath.Join(displaced, config.StateDirectory, "state", "canary"):      "committed-to-original\n",
		filepath.Join(repositoryPath, config.StateDirectory, "state", "canary"): "replacement-must-survive\n",
	} {
		body, readErr := os.ReadFile(filename)
		if readErr != nil || string(body) != expected {
			t.Fatalf("canonical root-swap canary %s: body=%q err=%v want=%q", filename, body, readErr, expected)
		}
	}
	if entries, err := os.ReadDir(filepath.Join(repositoryPath, config.StateDirectory)); err != nil {
		t.Fatal(err)
	} else {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".yum-canonical-install-") {
				t.Fatalf("replacement root received canonical stage %s", entry.Name())
			}
		}
	}
	if err := workflow.closeMutationRoots(); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("first holder released through a replaced repository coordinate: %v", err)
	}
	if second == nil {
		t.Fatal("replacement lock was not acquired")
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(repositoryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(displaced, repositoryPath); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("first holder could not release after restoring its exact coordinate: %v", err)
	}
}

func TestYUMCompatibilityCutoverJournalAfterAdmissionCannotWriteReplacementRoot(t *testing.T) {
	parent := t.TempDir()
	repositoryPath := filepath.Join(parent, "repository")
	if err := os.Mkdir(repositoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := state.AcquireLock(filepath.Join(repositoryPath, config.StateDirectory), "compatibility-bound-journal-first", false)
	if err != nil {
		t.Fatal(err)
	}
	workflow := yumCompatibilityWorkflow{cfg: &config.Config{Root: repositoryPath}}
	if err := workflow.bindMutationRoots(first); err != nil {
		t.Fatal(err)
	}
	displaced := repositoryPath + ".original"
	var second *state.Lock
	workflow.mutationHook = func(phase string) error {
		if phase != "write-cutover-journal" {
			return fmt.Errorf("unexpected mutation phase %s", phase)
		}
		if err := os.Rename(repositoryPath, displaced); err != nil {
			return err
		}
		if err := os.Mkdir(repositoryPath, 0o700); err != nil {
			return err
		}
		var err error
		second, err = state.AcquireLock(filepath.Join(repositoryPath, config.StateDirectory), "compatibility-bound-journal-second", false)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(repositoryPath, config.StateDirectory, "replacement-canary"), []byte("replacement-must-survive\n"), 0o600)
	}
	journal := yumCompatibilityCutoverJournal{
		Schema: yumCompatibilityCutoverJournalSchema, ID: "infra-legacy-x86-64", Action: "cutover", Phase: yumCompatibilityCutoverPrepared,
		EventSHA256: strings.Repeat("a", 64), ServingLink: filepath.Join(repositoryPath, ".sow", "serving", "current"),
		FromTarget: filepath.Join(repositoryPath, "raw"), ToTarget: filepath.Join(repositoryPath, "candidate"),
	}
	err = writeYUMCompatibilityCutoverJournalBound(workflow, journal, true)
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("bound journal write did not report the injected namespace replacement: %v", err)
	}
	journalName, _ := yumCompatibilityCutoverJournalName(journal.ID)
	if body, readErr := os.ReadFile(filepath.Join(displaced, config.StateDirectory, journalName)); readErr != nil || !bytes.Contains(body, []byte(journal.EventSHA256)) {
		t.Fatalf("original bound journal missing after root swap: body=%q err=%v", body, readErr)
	}
	if _, err := os.Lstat(filepath.Join(repositoryPath, config.StateDirectory, journalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement root received cutover journal: %v", err)
	}
	if body, err := os.ReadFile(filepath.Join(repositoryPath, config.StateDirectory, "replacement-canary")); err != nil || string(body) != "replacement-must-survive\n" {
		t.Fatalf("replacement journal canary changed: body=%q err=%v", body, err)
	}
	if err := workflow.closeMutationRoots(); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("first holder released through a replaced repository coordinate: %v", err)
	}
	if second == nil {
		t.Fatal("replacement lock was not acquired")
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(repositoryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(displaced, repositoryPath); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("first holder could not release after restoring its exact coordinate: %v", err)
	}
}

func TestYUMCompatibilityCASCommitAfterAdmissionCannotWriteReplacementRoot(t *testing.T) {
	parent := t.TempDir()
	repositoryPath := filepath.Join(parent, "repository")
	if err := os.Mkdir(repositoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := state.AcquireLock(filepath.Join(repositoryPath, config.StateDirectory), "compatibility-bound-cas-first", false)
	if err != nil {
		t.Fatal(err)
	}
	workflow := yumCompatibilityWorkflow{cfg: &config.Config{Root: repositoryPath}}
	if err := workflow.bindMutationRoots(first); err != nil {
		t.Fatal(err)
	}
	workspace, err := newYUMCompatibilityCASWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	defer workspace.Close()
	payload := []byte("immutable compatibility CAS payload\n")
	object, err := workspace.Store().Put(t.Context(), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(t.TempDir(), "payload.tsv")
	if err := os.WriteFile(manifestPath, []byte(fmt.Sprintf("payload\t%d\t%s\n", object.Size, object.HashString())), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := workspace.TrackManifest(manifestPath); err != nil {
		t.Fatal(err)
	}
	displaced := repositoryPath + ".original"
	var second *state.Lock
	workflow.mutationHook = func(phase string) error {
		if phase != "commit-fault-cas" {
			return fmt.Errorf("unexpected mutation phase %s", phase)
		}
		if err := os.Rename(repositoryPath, displaced); err != nil {
			return err
		}
		if err := os.Mkdir(repositoryPath, 0o700); err != nil {
			return err
		}
		var err error
		second, err = state.AcquireLock(filepath.Join(repositoryPath, config.StateDirectory), "compatibility-bound-cas-second", false)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(repositoryPath, config.StateDirectory, "replacement-canary"), []byte("replacement-must-survive\n"), 0o600)
	}
	err = workspace.Commit(t.Context(), workflow, "commit-fault-cas")
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("bound CAS commit did not report the injected namespace replacement: %v", err)
	}
	objectRelative := yumCompatibilityCASObjectRelative(object.SHA256)
	if _, err := os.Lstat(filepath.Join(displaced, objectRelative)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("CAS object was written after repository-root replacement: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(repositoryPath, objectRelative)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement root received CAS object: %v", err)
	}
	if body, err := os.ReadFile(filepath.Join(repositoryPath, config.StateDirectory, "replacement-canary")); err != nil || string(body) != "replacement-must-survive\n" {
		t.Fatalf("replacement CAS canary changed: body=%q err=%v", body, err)
	}
	if err := workflow.closeMutationRoots(); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("first holder released through a replaced repository coordinate: %v", err)
	}
	if second == nil {
		t.Fatal("replacement lock was not acquired")
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(repositoryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(displaced, repositoryPath); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("first holder could not release after restoring its exact coordinate: %v", err)
	}
}

func TestYUMCompatibilityCASCommitAfterAdmissionCannotWriteReplacementDirectory(t *testing.T) {
	for _, level := range []string{"pool", "sha256", "tmp", "shard"} {
		t.Run(level, func(t *testing.T) {
			repositoryPath := filepath.Join(t.TempDir(), "repository")
			if err := os.Mkdir(repositoryPath, 0o700); err != nil {
				t.Fatal(err)
			}
			lock, err := state.AcquireLock(filepath.Join(repositoryPath, config.StateDirectory), "compatibility-bound-cas-"+level, false)
			if err != nil {
				t.Fatal(err)
			}
			workflow := yumCompatibilityWorkflow{cfg: &config.Config{Root: repositoryPath}}
			if err := workflow.bindMutationRoots(lock); err != nil {
				_ = lock.Release()
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = workflow.closeMutationRoots()
				_ = lock.Release()
			})
			workspace, err := newYUMCompatibilityCASWorkspace()
			if err != nil {
				t.Fatal(err)
			}
			defer workspace.Close()
			payload := []byte("immutable compatibility CAS " + level + " payload\n")
			object, err := workspace.Store().Put(t.Context(), bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(t.TempDir(), "payload.tsv")
			if err := os.WriteFile(manifestPath, []byte(fmt.Sprintf("payload\t%d\t%s\n", object.Size, object.HashString())), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := workspace.TrackManifest(manifestPath); err != nil {
				t.Fatal(err)
			}
			relative := ".pool"
			switch level {
			case "sha256":
				relative = filepath.Join(".pool", "sha256")
			case "tmp":
				relative = filepath.Join(".pool", "sha256", ".tmp")
			case "shard":
				relative = filepath.Join(".pool", "sha256", object.HashString()[:2])
			}
			coordinate := filepath.Join(repositoryPath, relative)
			displaced := coordinate + ".original"
			phase := "commit-fault-cas-" + level
			workflow.mutationHook = func(observed string) error {
				if observed != phase {
					return fmt.Errorf("unexpected mutation phase %s", observed)
				}
				if err := os.Rename(coordinate, displaced); err != nil {
					return err
				}
				if err := os.Mkdir(coordinate, 0o700); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(coordinate, "replacement-canary"), []byte("replacement-must-survive\n"), 0o600)
			}
			err = workspace.Commit(t.Context(), workflow, phase)
			if err == nil || !strings.Contains(err.Error(), "replaced") {
				t.Fatalf("bound CAS %s replacement was not detected: %v", level, err)
			}
			if body, err := os.ReadFile(filepath.Join(coordinate, "replacement-canary")); err != nil || string(body) != "replacement-must-survive\n" {
				t.Fatalf("replacement %s canary changed: body=%q err=%v", level, body, err)
			}
			if err := filepath.WalkDir(repositoryPath, func(filename string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.Name() == object.HashString() || strings.HasPrefix(entry.Name(), "compat-") {
					return fmt.Errorf("post-admission replacement received CAS write %s", filename)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestYUMCompatibilityCanonicalStageCleanupRefusesReplacement(t *testing.T) {
	statePath := t.TempDir()
	root, err := os.OpenRoot(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	stage := ".yum-canonical-install-" + strings.Repeat("a", 32)
	if err := root.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	expected, err := root.Lstat(stage)
	if err != nil {
		t.Fatal(err)
	}
	displaced := stage + ".original"
	if err := root.Rename(stage, displaced); err != nil {
		t.Fatal(err)
	}
	if err := root.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(filepath.Join(stage, "replacement-canary"), []byte("replacement-must-survive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = removeExactYUMCompatibilityBoundDirectory(root, stage, expected)
	if err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("canonical stage replacement was not rejected: %v", err)
	}
	if body, err := root.ReadFile(filepath.Join(stage, "replacement-canary")); err != nil || string(body) != "replacement-must-survive\n" {
		t.Fatalf("replacement canonical stage was deleted or changed: body=%q err=%v", body, err)
	}
	if info, err := root.Lstat(displaced); err != nil || !os.SameFile(expected, info) {
		t.Fatalf("original canonical stage identity changed: info=%v err=%v", info, err)
	}
}

func TestYUMCompatibilityJournalTempCleanupRefusesReplacement(t *testing.T) {
	statePath := t.TempDir()
	root, err := os.OpenRoot(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	temporary, expected, err := writeYUMCompatibilityBoundStateFile(root, ".journal-temp-", []byte("original\n"))
	if err != nil {
		t.Fatal(err)
	}
	displaced := temporary + ".original"
	if err := root.Rename(temporary, displaced); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(temporary, []byte("replacement-must-survive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = removeExactYUMCompatibilityBoundFile(root, temporary, expected)
	if err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("journal temporary replacement was not rejected: %v", err)
	}
	for name, want := range map[string]string{temporary: "replacement-must-survive\n", displaced: "original\n"} {
		if body, err := root.ReadFile(name); err != nil || string(body) != want {
			t.Fatalf("journal temporary %s body=%q err=%v want=%q", name, body, err, want)
		}
	}
}

func TestYUMCompatibilityMaterializeAfterAdmissionCannotWriteReplacementRoot(t *testing.T) {
	parent := t.TempDir()
	repositoryPath := filepath.Join(parent, "repository")
	if err := os.Mkdir(repositoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(repositoryPath)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("bound materialized compatibility payload\n")
	object, err := pool.Put(t.Context(), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	first, err := state.AcquireLock(filepath.Join(repositoryPath, config.StateDirectory), "compatibility-bound-materialize-first", false)
	if err != nil {
		t.Fatal(err)
	}
	workflow := yumCompatibilityWorkflow{cfg: &config.Config{Root: repositoryPath}}
	if err := workflow.bindMutationRoots(first); err != nil {
		t.Fatal(err)
	}
	desired := filepath.Join(t.TempDir(), "candidate.tsv")
	if err := os.WriteFile(desired, []byte(fmt.Sprintf("repodata/payload\t%d\t%s\n", object.Size, object.HashString())), 0o600); err != nil {
		t.Fatal(err)
	}
	actual := filepath.Join(t.TempDir(), "actual.tsv")
	targetRelative := filepath.Join(config.StateDirectory, "materialized", "compatibility", "infra-legacy-x86-64", strings.Repeat("a", 64))
	displaced := repositoryPath + ".original"
	var second *state.Lock
	workflow.mutationHook = func(phase string) error {
		if phase != "install yum-cutover candidate" {
			return fmt.Errorf("unexpected mutation phase %s", phase)
		}
		if err := os.Rename(repositoryPath, displaced); err != nil {
			return err
		}
		if err := os.Mkdir(repositoryPath, 0o700); err != nil {
			return err
		}
		var err error
		second, err = state.AcquireLock(filepath.Join(repositoryPath, config.StateDirectory), "compatibility-bound-materialize-second", false)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(repositoryPath, config.StateDirectory, "replacement-canary"), []byte("replacement-must-survive\n"), 0o600)
	}
	err = materializeYUMCompatibilityManifestBound(t.Context(), workflow, desired, targetRelative, actual)
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("bound materialization did not report the injected namespace replacement: %v", err)
	}
	if body, readErr := os.ReadFile(filepath.Join(displaced, targetRelative, "repodata", "payload")); readErr != nil || !bytes.Equal(body, payload) {
		t.Fatalf("original bound materialization missing after root swap: body=%q err=%v", body, readErr)
	}
	if _, err := os.Lstat(filepath.Join(repositoryPath, targetRelative)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement root received materialized candidate: %v", err)
	}
	if body, err := os.ReadFile(filepath.Join(repositoryPath, config.StateDirectory, "replacement-canary")); err != nil || string(body) != "replacement-must-survive\n" {
		t.Fatalf("replacement materialize canary changed: body=%q err=%v", body, err)
	}
	if err := workflow.closeMutationRoots(); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("first holder released through a replaced repository coordinate: %v", err)
	}
	if second == nil {
		t.Fatal("replacement lock was not acquired")
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(repositoryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(displaced, repositoryPath); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("first holder could not release after restoring its exact coordinate: %v", err)
	}
}

func TestYUMCompatibilityServingLinkRejectsSymlinkTargetsAndParents(t *testing.T) {
	root := t.TempDir()
	raw := filepath.Join(root, "raw")
	candidate := filepath.Join(root, "candidate")
	if err := os.Mkdir(raw, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(candidate, 0o755); err != nil {
		t.Fatal(err)
	}
	symlinkTarget := filepath.Join(root, "candidate-link")
	if err := os.Symlink(candidate, symlinkTarget); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Root: root}
	journal := yumCompatibilityCutoverJournal{ServingLink: filepath.Join(root, "serving", "current"), FromTarget: raw, ToTarget: symlinkTarget}
	if err := reconcileYUMCompatibilityServingLink(cfg, journal); err == nil {
		t.Fatal("symlink target was accepted")
	}
	realParent := filepath.Join(root, "real-parent")
	if err := os.Mkdir(realParent, 0o755); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(root, "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	journal.ToTarget = candidate
	journal.ServingLink = filepath.Join(linkedParent, "current")
	if err := reconcileYUMCompatibilityServingLink(cfg, journal); err == nil {
		t.Fatal("symlinked serving parent was accepted")
	}
}

func TestYUMCompatibilityServingLinkParentReplacementCannotRedirectMutation(t *testing.T) {
	root := t.TempDir()
	raw := filepath.Join(root, "raw")
	candidate := filepath.Join(root, "candidate")
	if err := os.Mkdir(raw, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(candidate, 0o755); err != nil {
		t.Fatal(err)
	}
	servingParent := filepath.Join(root, ".sow", "serving", "compatibility", "yum", "infra-legacy-x86-64")
	servingLink := filepath.Join(servingParent, "current")
	outside := t.TempDir()
	displaced := filepath.Join(root, "displaced-serving-parent")
	journal := yumCompatibilityCutoverJournal{ServingLink: servingLink, FromTarget: raw, ToTarget: candidate}
	err := reconcileYUMCompatibilityServingLinkWithHook(&config.Config{Root: root}, journal, func() error {
		if err := os.Rename(servingParent, displaced); err != nil {
			return err
		}
		return os.Symlink(outside, servingParent)
	})
	if err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("parent replacement was not detected: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "current")); !os.IsNotExist(err) {
		t.Fatalf("root-bound mutation escaped through replacement parent: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(displaced, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original parent was mutated after its namespace coordinate was replaced: %v", err)
	}
}

func TestYUMCompatibilityServingTargetReplacementPreservesPriorLinkAndJournal(t *testing.T) {
	parent := t.TempDir()
	repositoryPath := filepath.Join(parent, "repository")
	raw := filepath.Join(repositoryPath, "raw")
	candidate := filepath.Join(repositoryPath, "candidate")
	servingParent := filepath.Join(repositoryPath, config.StateDirectory, "serving", "compatibility", "yum", "infra-legacy-x86-64")
	for _, directory := range []string{repositoryPath, raw, candidate, servingParent} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	servingLink := filepath.Join(servingParent, "current")
	rawRelative, err := filepath.Rel(servingParent, raw)
	if err != nil || filepath.IsAbs(rawRelative) {
		t.Fatalf("raw relative target=%q err=%v", rawRelative, err)
	}
	if err := os.Symlink(rawRelative, servingLink); err != nil {
		t.Fatal(err)
	}
	lock, err := state.AcquireLock(filepath.Join(repositoryPath, config.StateDirectory), "compatibility-serving-target-replacement", false)
	if err != nil {
		t.Fatal(err)
	}
	workflow := yumCompatibilityWorkflow{cfg: &config.Config{Root: repositoryPath}}
	if err := workflow.bindMutationRoots(lock); err != nil {
		_ = lock.Release()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = workflow.closeMutationRoots()
		_ = lock.Release()
	})
	journal := yumCompatibilityCutoverJournal{
		Schema: yumCompatibilityCutoverJournalSchema, ID: "infra-legacy-x86-64", Action: "cutover", Phase: yumCompatibilityCutoverPrepared,
		EventSHA256: strings.Repeat("a", 64), ServingLink: servingLink, FromTarget: raw, ToTarget: candidate,
	}
	if err := writeYUMCompatibilityCutoverJournalBound(workflow, journal, true); err != nil {
		t.Fatal(err)
	}
	journalName, err := yumCompatibilityCutoverJournalName(journal.ID)
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(repositoryPath, config.StateDirectory, journalName)
	journalBefore, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	displaced := candidate + ".original"
	workflow.mutationHook = func(phase string) error {
		if phase != "flip controlled compatibility serving link" {
			return fmt.Errorf("unexpected mutation phase %s", phase)
		}
		if err := os.Rename(candidate, displaced); err != nil {
			return err
		}
		if err := os.Mkdir(candidate, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(candidate, "replacement-canary"), []byte("replacement-must-survive\n"), 0o600)
	}
	err = reconcileYUMCompatibilityServingLinkBound(workflow, journal)
	if err == nil || (!strings.Contains(err.Error(), "changed") && !strings.Contains(err.Error(), "replaced")) {
		t.Fatalf("target replacement was not detected: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(servingLink)
	resolvedInfo, resolvedErr := os.Stat(resolved)
	rawInfo, rawErr := os.Stat(raw)
	if err != nil || resolvedErr != nil || rawErr != nil || !os.SameFile(resolvedInfo, rawInfo) {
		t.Fatalf("failed cutover exposed replacement target: resolved=%q eval_err=%v stat_err=%v raw_err=%v want=%q", resolved, err, resolvedErr, rawErr, raw)
	}
	if _, err := os.Stat(displaced); err != nil {
		t.Fatalf("retained admitted target disappeared: %v", err)
	}
	entries, err := os.ReadDir(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "replacement-canary" {
		t.Fatalf("replacement target received workflow writes: %v", entries)
	}
	if body, err := os.ReadFile(filepath.Join(candidate, "replacement-canary")); err != nil || string(body) != "replacement-must-survive\n" {
		t.Fatalf("replacement canary changed: body=%q err=%v", body, err)
	}
	journalAfter, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(journalAfter, journalBefore) {
		t.Fatalf("failed cutover removed or changed recovery journal: before=%q after=%q err=%v", journalBefore, journalAfter, err)
	}
}

func TestYUMCompatibilityServingLinkAuditIsRootBoundAndStable(t *testing.T) {
	newFixture := func(t *testing.T) (*config.Config, yumCompatibilityCutoverJournal, string) {
		t.Helper()
		root := t.TempDir()
		raw := filepath.Join(root, "raw")
		candidate := filepath.Join(root, "candidate")
		servingParent := filepath.Join(root, ".sow", "serving", "compatibility", "yum", "infra-legacy-x86-64")
		if err := os.MkdirAll(servingParent, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, directory := range []string{raw, candidate} {
			if err := os.Mkdir(directory, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		link := filepath.Join(servingParent, "current")
		relative, err := filepath.Rel(servingParent, candidate)
		if err != nil || filepath.IsAbs(relative) {
			t.Fatalf("relative target=%q err=%v", relative, err)
		}
		if err := os.Symlink(relative, link); err != nil {
			t.Fatal(err)
		}
		return &config.Config{Root: root}, yumCompatibilityCutoverJournal{ServingLink: link, FromTarget: raw, ToTarget: candidate}, servingParent
	}

	t.Run("exact", func(t *testing.T) {
		cfg, journal, _ := newFixture(t)
		if err := auditYUMCompatibilityServingLink(cfg, journal); err != nil {
			t.Fatalf("exact controlled link was rejected: %v", err)
		}
	})

	t.Run("symlinked-parent", func(t *testing.T) {
		cfg, journal, parent := newFixture(t)
		realParent := parent + "-real"
		if err := os.Rename(parent, realParent); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realParent, parent); err != nil {
			t.Fatal(err)
		}
		if err := auditYUMCompatibilityServingLink(cfg, journal); err == nil {
			t.Fatal("symlinked admission parent was accepted")
		}
	})

	t.Run("parent-replaced-during-read", func(t *testing.T) {
		cfg, journal, parent := newFixture(t)
		displaced := parent + "-displaced"
		outside := t.TempDir()
		err := auditYUMCompatibilityServingLinkWithHook(cfg, journal, func() error {
			if err := os.Rename(parent, displaced); err != nil {
				return err
			}
			return os.Symlink(outside, parent)
		})
		if err == nil || !strings.Contains(err.Error(), "replaced") {
			t.Fatalf("parent replacement was not rejected: %v", err)
		}
	})

	t.Run("link-replaced-during-read", func(t *testing.T) {
		cfg, journal, parent := newFixture(t)
		other := filepath.Join(cfg.Root, "other")
		if err := os.Mkdir(other, 0o755); err != nil {
			t.Fatal(err)
		}
		err := auditYUMCompatibilityServingLinkWithHook(cfg, journal, func() error {
			if err := os.Rename(journal.ServingLink, journal.ServingLink+".old"); err != nil {
				return err
			}
			relative, err := filepath.Rel(parent, other)
			if err != nil {
				return err
			}
			return os.Symlink(relative, journal.ServingLink)
		})
		if err == nil || !strings.Contains(err.Error(), "replaced") {
			t.Fatalf("link replacement was not rejected: %v", err)
		}
	})
}

func TestPendingYUMCompatibilityCutoverJournalBlocksOrdinaryCanonicalPreparation(t *testing.T) {
	stateDir := t.TempDir()
	id := "infra-legacy-x86-64"
	name := filepath.Join(stateDir, "yum-compatibility-cutover-"+id+".journal.json")
	if err := os.WriteFile(name, []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := prepareCanonicalStateCore(context.Background(), state.New(stateDir), false, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "blocks ordinary commands") || !strings.Contains(err.Error(), "--recover") {
		t.Fatalf("ordinary canonical preparation did not fail closed: %v", err)
	}
	if err := requireNoPendingYUMCompatibilityCutoverJournalsExcept(stateDir, id); err != nil {
		t.Fatalf("matching compatibility recovery was blocked: %v", err)
	}
	other := filepath.Join(stateDir, "yum-compatibility-cutover-other.journal.json.next")
	if err := os.WriteFile(other, []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireNoPendingYUMCompatibilityCutoverJournalsExcept(stateDir, id); err == nil || !strings.Contains(err.Error(), other) {
		t.Fatalf("another projection pending journal was not fail-closed: %v", err)
	}
}

func TestYUMCompatibilityCommittedEventRecoveryFlipsLinkAndRollbackAppends(t *testing.T) {
	fixture := newYUMCompatibilityContractFixture(t, "")
	id := fixture.cfg.CompatibilityProjections[0].ID
	frozen, err := loadYUMCompatibilityFrozenStateAt(fixture.canonical, fixture.anchor, id)
	if err != nil {
		t.Fatal(err)
	}
	stateAtHead, err := loadYUMCompatibilityCutoverStateAt(fixture.canonical, fixture.anchor, id)
	if err != nil || stateAtHead.Stage != yumCompatibilityStageS2 {
		t.Fatalf("load S2 state=%+v err=%v", stateAtHead, err)
	}
	event, err := buildNextYUMCompatibilityCutoverEvent(frozen, stateAtHead, "cutover")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := physicalYUMCompatibilityCutoverJournal(fixture.cfg, event)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{journal.FromTarget, journal.ToTarget} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeYUMCompatibilityCutoverJournal(fixture.cfg, journal, true); err != nil {
		t.Fatal(err)
	}
	cutoverTx, err := newTransactionDir(fixture.cfg.StatePath(), "test-yum-cutover-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(cutoverTx)
	commit, err := appendYUMCompatibilityCutoverEvent(t.Context(), fixture.canonical, event, cutoverTx)
	if err != nil || commit.IsZero() {
		t.Fatalf("append committed cutover event commit=%s err=%v", commit, err)
	}
	if err := os.WriteFile(yumCompatibilityCutoverJournalPath(fixture.cfg, id)+".next", []byte("{\"phase\":"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(journal.ServingLink); !os.IsNotExist(err) {
		t.Fatalf("serving link changed before local recovery: %v", err)
	}
	if err := prepareCanonicalStateCore(t.Context(), fixture.canonical, false, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "blocks ordinary commands") {
		t.Fatalf("ordinary state path did not stop after event-before-link crash: %v", err)
	}
	if err := recoverYUMCompatibilityCutoverJournal(fixture.cfg, fixture.canonical, id, false); err == nil || !strings.Contains(err.Error(), "--recover") {
		t.Fatalf("implicit recovery was accepted: %v", err)
	}
	if err := recoverYUMCompatibilityCutoverJournal(fixture.cfg, fixture.canonical, id, true); err != nil {
		t.Fatalf("explicit cutover recovery: %v", err)
	}
	assertYUMCompatibilityServingLinkTarget(t, journal.ServingLink, journal.ToTarget)
	if _, err := os.Lstat(yumCompatibilityCutoverJournalPath(fixture.cfg, id)); !os.IsNotExist(err) {
		t.Fatalf("completed cutover journal remains: %v", err)
	}
	if err := os.Remove(journal.ServingLink); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(yumCompatibilityCutoverJournalPath(fixture.cfg, id)+".next", []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverYUMCompatibilityCutoverJournal(fixture.cfg, fixture.canonical, id, true); err != nil {
		t.Fatalf("rebuild journal and serving link from canonical event: %v", err)
	}
	assertYUMCompatibilityServingLinkTarget(t, journal.ServingLink, journal.ToTarget)
	if _, err := os.Lstat(yumCompatibilityCutoverJournalPath(fixture.cfg, id) + ".next"); !os.IsNotExist(err) {
		t.Fatalf("orphan partial cutover phase remains: %v", err)
	}

	stateAtHead, err = loadYUMCompatibilityCutoverStateAt(fixture.canonical, plumbing.ZeroHash, id)
	if err != nil || !stateAtHead.Active || len(stateAtHead.Events) != 1 {
		t.Fatalf("recovered S3 state=%+v err=%v", stateAtHead, err)
	}
	rollback, err := buildNextYUMCompatibilityCutoverEvent(frozen, stateAtHead, "rollback")
	if err != nil {
		t.Fatal(err)
	}
	rollbackJournal, err := physicalYUMCompatibilityCutoverJournal(fixture.cfg, rollback)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeYUMCompatibilityCutoverJournal(fixture.cfg, rollbackJournal, true); err != nil {
		t.Fatal(err)
	}
	rollbackTx, err := newTransactionDir(fixture.cfg.StatePath(), "test-yum-rollback-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(rollbackTx)
	rollbackCommit, err := appendYUMCompatibilityCutoverEvent(t.Context(), fixture.canonical, rollback, rollbackTx)
	if err != nil || rollbackCommit.IsZero() {
		t.Fatalf("append rollback event commit=%s err=%v", rollbackCommit, err)
	}
	rollbackJournal.Phase = yumCompatibilityCutoverCommitted
	if err := writeYUMCompatibilityCutoverJournal(fixture.cfg, rollbackJournal, false); err != nil {
		t.Fatal(err)
	}
	if err := recoverYUMCompatibilityCutoverJournal(fixture.cfg, fixture.canonical, id, true); err != nil {
		t.Fatalf("explicit rollback recovery: %v", err)
	}
	assertYUMCompatibilityServingLinkTarget(t, rollbackJournal.ServingLink, rollbackJournal.ToTarget)
	stateAtHead, err = loadYUMCompatibilityCutoverStateAt(fixture.canonical, plumbing.ZeroHash, id)
	if err != nil || stateAtHead.Active || stateAtHead.Stage != yumCompatibilityStageRolledBack || len(stateAtHead.Events) != 2 {
		t.Fatalf("rolled-back S3 state=%+v err=%v", stateAtHead, err)
	}
}

func TestYUMCompatibilityCutoverJournalDualFileRecovery(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{Root: root}
	if err := os.MkdirAll(cfg.StatePath(), 0o700); err != nil {
		t.Fatal(err)
	}
	candidate := completeYUMCompatibilityCandidate(t)
	frozen := yumCompatibilityFrozenState{Receipt: candidate}
	link, raw, target := yumCompatibilityLogicalServingPaths(frozen)
	event := sealYUMCompatibilityCutoverEvent(t, yumCompatibilityCutoverEvent{
		Schema: yumCompatibilityCutoverEventSchema, Sequence: 1, ID: candidate.ID, Action: "cutover",
		ServingLink: link, FromTarget: raw, ToTarget: target, FreezeCommit: candidate.SourceCommit,
		CandidateManifestSHA256: candidate.CandidateManifestSHA256, PreviousEventSHA256: strings.Repeat("0", 64),
	})
	prepared, err := physicalYUMCompatibilityCutoverJournal(cfg, event)
	if err != nil {
		t.Fatal(err)
	}
	base := yumCompatibilityCutoverJournalPath(cfg, candidate.ID)
	write := func(name string, value yumCompatibilityCutoverJournal) {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, append(body, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := writeYUMCompatibilityCutoverJournal(cfg, prepared, true); err != nil {
		t.Fatal(err)
	}
	committed := prepared
	committed.Phase = yumCompatibilityCutoverCommitted
	write(base+".next", committed)
	pair, err := readYUMCompatibilityCutoverJournalPair(cfg, candidate.ID, true)
	if err != nil || !pair.MainExists || !pair.NextExists || pair.Next.Phase != yumCompatibilityCutoverCommitted {
		t.Fatalf("valid prepared/committed pair=%+v err=%v", pair, err)
	}

	if err := os.Remove(base + ".next"); err != nil {
		t.Fatal(err)
	}
	tampered := committed
	tampered.ToTarget = filepath.Join(root, "different-target")
	write(base+".next", tampered)
	if _, err := readYUMCompatibilityCutoverJournalPair(cfg, candidate.ID, true); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("mismatched committed phase was accepted: %v", err)
	}
	if err := os.Remove(base + ".next"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".next", []byte("{\"phase\":"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readYUMCompatibilityCutoverJournalPair(cfg, candidate.ID, true); err == nil || !errors.Is(err, errPartialYUMCompatibilityCutoverJournalNext) {
		t.Fatalf("partial committed phase was accepted: %v", err)
	}
	if err := os.Remove(base + ".next"); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(base, base+".next"); err != nil {
		t.Fatal(err)
	}
	pair, err = readYUMCompatibilityCutoverJournalPair(cfg, candidate.ID, true)
	if err == nil || !strings.Contains(err.Error(), "link count") {
		t.Fatalf("hardlink-aliased first-install pair was accepted: %+v err=%v", pair, err)
	}
	baseInfo, baseErr := os.Lstat(base)
	nextInfo, nextErr := os.Lstat(base + ".next")
	if baseErr != nil || nextErr != nil || !os.SameFile(baseInfo, nextInfo) {
		t.Fatalf("hardlink-aliased pair evidence was not preserved: base=%v next=%v", baseErr, nextErr)
	}
	if err := os.Remove(base + ".next"); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(base); err != nil {
		t.Fatal(err)
	}
	write(base+".next", prepared)
	pair, err = readYUMCompatibilityCutoverJournalPair(cfg, candidate.ID, true)
	if err != nil || pair.MainExists || !pair.NextExists || pair.Next.Phase != yumCompatibilityCutoverPrepared {
		t.Fatalf("prepared pre-link journal was not exposed for canonical recovery: %+v err=%v", pair, err)
	}
	if err := os.Remove(base + ".next"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".next", []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readYUMCompatibilityCutoverJournalPair(cfg, candidate.ID, true); err == nil {
		t.Fatal("partial first-install journal was not fail-closed")
	}
	if _, err := os.Lstat(base); !os.IsNotExist(err) {
		t.Fatalf("partial first-install unexpectedly created durable base: %v", err)
	}
}

func TestYUMCompatibilityCandidateJournalRejectsMismatchedPendingPhase(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "candidate")
	id := "infra-legacy-x86-64"
	binding := testYUMCompatibilityCandidateBinding(t, output)
	journal, err := createYUMCompatibilityCandidateJournal(id, binding)
	if err != nil {
		t.Fatal(err)
	}
	next := journal
	next.Phase = yumCompatibilityCandidatePrepared
	next.PendingReceipt += ".tampered"
	body, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(yumCompatibilityCandidateJournalPath(output)+".next", append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recoverYUMCompatibilityCandidateJournal(id, binding, true); err == nil {
		t.Fatal("mismatched candidate pending phase was accepted")
	}
}

func TestYUMCompatibilityCandidateOrphanPartialFirstInstallRecoversWhenArtifactsAbsent(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "candidate")
	id := "infra-legacy-x86-64"
	binding := testYUMCompatibilityCandidateBinding(t, output)
	next := yumCompatibilityCandidateJournalPath(output) + ".next"
	if err := os.WriteFile(next, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := recoverYUMCompatibilityCandidateJournal(id, binding, true)
	if err != nil || recovered {
		t.Fatalf("orphan partial candidate first-install recovered=%t err=%v", recovered, err)
	}
	if _, err := os.Lstat(next); !os.IsNotExist(err) {
		t.Fatalf("orphan partial candidate journal remains: %v", err)
	}
}

func TestYUMCompatibilityCutoverOrphanPartialFirstInstallRecoversFromS2(t *testing.T) {
	fixture := newYUMCompatibilityContractFixture(t, "")
	id := fixture.cfg.CompatibilityProjections[0].ID
	next := yumCompatibilityCutoverJournalPath(fixture.cfg, id) + ".next"
	if err := os.WriteFile(next, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverYUMCompatibilityCutoverJournal(fixture.cfg, fixture.canonical, id, true); err != nil {
		t.Fatalf("recover orphan partial pre-cutover journal: %v", err)
	}
	if _, err := os.Lstat(next); !os.IsNotExist(err) {
		t.Fatalf("orphan partial pre-cutover journal remains: %v", err)
	}
	stateAtHead, err := loadYUMCompatibilityCutoverStateAt(fixture.canonical, plumbing.ZeroHash, id)
	if err != nil || stateAtHead.Stage != yumCompatibilityStageS2 || len(stateAtHead.Events) != 0 {
		t.Fatalf("orphan partial recovery changed S2 authority: %+v err=%v", stateAtHead, err)
	}
}

func assertYUMCompatibilityServingLinkTarget(t *testing.T, link, want string) {
	t.Helper()
	value, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(filepath.Dir(link), value)
	}
	if filepath.Clean(value) != filepath.Clean(want) {
		t.Fatalf("serving link %s targets %s, want %s", link, value, want)
	}
}

func TestLegacyYUMCompatibilityRepomdRequiresOpenIdentityForEveryRecord(t *testing.T) {
	root := t.TempDir()
	repodata := filepath.Join(root, "repodata")
	if err := os.Mkdir(repodata, 0o755); err != nil {
		t.Fatal(err)
	}
	types := []string{"primary", "filelists", "other", "primary_db", "filelists_db", "other_db", "modules"}
	var records strings.Builder
	for index, kind := range types {
		filename, compressed, open := legacyYUMCompatibilityFixtureArtifact(t, index, kind)
		compressedDigest := sha256.Sum256(compressed)
		openDigest := sha256.Sum256(open)
		if err := os.WriteFile(filepath.Join(repodata, filename), compressed, 0o644); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&records, `<data type="%s"><checksum type="sha256">%s</checksum><open-checksum type="sha256">%s</open-checksum><location href="repodata/%s"/><size>%d</size><open-size>%d</open-size></data>`,
			kind, hex.EncodeToString(compressedDigest[:]), hex.EncodeToString(openDigest[:]), filename, len(compressed), len(open))
	}
	repomd := []byte(`<repomd xmlns="http://linux.duke.edu/metadata/repo">` + records.String() + `</repomd>`)
	repomdPath := filepath.Join(repodata, "repomd.xml")
	if err := os.WriteFile(repomdPath, repomd, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateLegacyYUMCompatibilityRepomd(context.Background(), root); err != nil {
		t.Fatalf("complete seven-record legacy repomd rejected: %v", err)
	}
	broken := bytes.Replace(repomd, []byte("<open-size>"), []byte("<missing-open-size>"), 1)
	broken = bytes.Replace(broken, []byte("</open-size>"), []byte("</missing-open-size>"), 1)
	if err := os.WriteFile(repomdPath, broken, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateLegacyYUMCompatibilityRepomd(context.Background(), root); err == nil || !strings.Contains(err.Error(), "open-size") {
		t.Fatalf("missing open-size was accepted: %v", err)
	}
	assertRejected := func(name string, changed []byte) {
		t.Helper()
		if err := os.WriteFile(repomdPath, changed, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := validateLegacyYUMCompatibilityRepomd(context.Background(), root); err == nil {
			t.Fatalf("%s frozen repomd mutation was accepted", name)
		}
	}
	assertRejected("duplicate", bytes.Replace(repomd, []byte(`type="modules"`), []byte(`type="primary"`), 1))
	assertRejected("unknown", bytes.Replace(repomd, []byte(`type="modules"`), []byte(`type="comps"`), 1))
	assertRejected("wrong suffix", bytes.Replace(repomd, []byte(`06-modules.yaml.gz`), []byte(`06-modules.xml.gz`), 1))
	moduleStart := bytes.Index(repomd, []byte(`<data type="modules">`))
	if moduleStart < 0 {
		t.Fatal("module fixture record is unavailable")
	}
	moduleEndRelative := bytes.Index(repomd[moduleStart:], []byte(`</data>`))
	if moduleEndRelative < 0 {
		t.Fatal("module fixture record is unavailable")
	}
	moduleEnd := moduleStart + moduleEndRelative + len(`</data>`)
	withoutModule := append(append([]byte(nil), repomd[:moduleStart]...), repomd[moduleEnd:]...)
	assertRejected("missing", withoutModule)
	extraModule := append(append([]byte(nil), repomd[:len(repomd)-len(`</repomd>`)]...), repomd[moduleStart:moduleEnd]...)
	extraModule = append(extraModule, []byte(`</repomd>`)...)
	assertRejected("extra", extraModule)
}

func TestPhysicalCutoverJournalContainsAbsolutePathsOnlyOutsideCanonicalEvent(t *testing.T) {
	root := t.TempDir()
	candidate := completeYUMCompatibilityCandidate(t)
	frozen := yumCompatibilityFrozenState{Receipt: candidate}
	link, raw, target := yumCompatibilityLogicalServingPaths(frozen)
	event := sealYUMCompatibilityCutoverEvent(t, yumCompatibilityCutoverEvent{
		Schema: yumCompatibilityCutoverEventSchema, Sequence: 1, ID: candidate.ID, Action: "cutover",
		ServingLink: link, FromTarget: raw, ToTarget: target, FreezeCommit: candidate.SourceCommit,
		CandidateManifestSHA256: candidate.CandidateManifestSHA256, PreviousEventSHA256: strings.Repeat("0", 64),
	})
	journal, err := physicalYUMCompatibilityCutoverJournal(&config.Config{Root: root}, event)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{journal.ServingLink, journal.FromTarget, journal.ToTarget} {
		if !filepath.IsAbs(value) || !strings.HasPrefix(value, root+string(filepath.Separator)) {
			t.Fatalf("physical journal path escaped root: %s", value)
		}
	}
	canonical, _ := json.Marshal(event)
	if bytes.Contains(canonical, []byte(root)) || bytes.Contains(canonical, []byte("/tmp/")) {
		t.Fatalf("canonical event contains physical root: %s", canonical)
	}
}
