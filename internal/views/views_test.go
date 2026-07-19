package views

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

func viewEntry(name, pool string) Entry {
	digest := sha256.Sum256([]byte(name))
	return Entry{Repo: "repo", OS: "el9", Arch: "x86_64", Name: name, Version: "1", Path: "yum/Packages/" + name + ".rpm", Size: int64(len(name)), SHA256: hex.EncodeToString(digest[:]), Pool: pool}
}

func viewText(t *testing.T, entries ...Entry) string {
	t.Helper()
	var result bytes.Buffer
	for _, entry := range entries {
		if err := WriteEntry(&result, entry); err != nil {
			t.Fatal(err)
		}
	}
	return result.String()
}

func TestPublicClosureCannotBeSkipped(t *testing.T) {
	gated := viewText(t, viewEntry("secret", "gated"))
	if _, err := ValidateConfidentiality(strings.NewReader(gated), true); err == nil || !strings.Contains(err.Error(), "closure violation") {
		t.Fatalf("gated object passed public closure: %v", err)
	}
	var out bytes.Buffer
	if _, err := Promote(strings.NewReader(""), strings.NewReader(gated), &out, Selector{}, true); err == nil || !strings.Contains(err.Error(), "closure violation") {
		t.Fatalf("promotion bypassed public closure: %v", err)
	}
	if _, err := ValidateLeaf(strings.NewReader(gated), "repo", "el9", "x86_64", true); err == nil || !strings.Contains(err.Error(), "closure violation") {
		t.Fatalf("leaf validation bypassed public closure: %v", err)
	}
	debug := viewEntry("postgresql-debuginfo", "public")
	debug.DebugInfo = true
	debugView := viewText(t, debug)
	if _, err := ValidateLeaf(strings.NewReader(debugView), "repo", "el9", "x86_64", true); err == nil || !strings.Contains(err.Error(), "debuginfo") {
		t.Fatalf("public leaf accepted debuginfo: %v", err)
	}
	if _, err := Promote(strings.NewReader(""), strings.NewReader(debugView), &bytes.Buffer{}, Selector{}, true); err == nil || !strings.Contains(err.Error(), "debuginfo") {
		t.Fatalf("public promotion accepted debuginfo: %v", err)
	}
	if _, err := Mutate(strings.NewReader(""), &bytes.Buffer{}, Mutation{Upserts: []Entry{debug}, Public: true}); err == nil || !strings.Contains(err.Error(), "debuginfo") {
		t.Fatalf("public mutation accepted debuginfo: %v", err)
	}
}

func TestLeafMembershipCannotDriftAcrossRefs(t *testing.T) {
	entry := viewEntry("a", "public")
	if _, err := ValidateLeaf(strings.NewReader(viewText(t, entry)), "other", "el9", "x86_64", true); err == nil || !strings.Contains(err.Error(), "contains entry") {
		t.Fatalf("cross-leaf entry accepted: %v", err)
	}
}

func TestValidateLeafEntriesRunsAdmissionInStreamingOrder(t *testing.T) {
	first, second := viewEntry("a", "public"), viewEntry("b", "public")
	var paths []string
	count, err := ValidateLeafEntries(strings.NewReader(viewText(t, first, second)), "repo", "el9", "x86_64", true, func(entry Entry) error {
		paths = append(paths, entry.Path)
		if entry.Path == second.Path {
			return fmt.Errorf("rejected %s", entry.Path)
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), second.Path) || count != 1 || len(paths) != 2 || paths[0] != first.Path || paths[1] != second.Path {
		t.Fatalf("admission count=%d paths=%v err=%v", count, paths, err)
	}
}

func TestPromoteIsSortedIdempotentUnion(t *testing.T) {
	a, b := viewEntry("a", "public"), viewEntry("b", "public")
	var first bytes.Buffer
	if count, err := Promote(strings.NewReader(viewText(t, a)), strings.NewReader(viewText(t, a, b)), &first, Selector{}, true); err != nil || count != 2 {
		t.Fatalf("first promote count=%d err=%v", count, err)
	}
	var second bytes.Buffer
	if count, err := Promote(bytes.NewReader(first.Bytes()), strings.NewReader(viewText(t, a, b)), &second, Selector{}, true); err != nil || count != 2 {
		t.Fatalf("idempotent promote count=%d err=%v", count, err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("idempotent promotion changed the manifest")
	}
}

func TestPromoteReplacesOnlyExplicitMutablePath(t *testing.T) {
	old := viewEntry("mutable", "public")
	replacement := old
	replacement.Version = "2"
	replacement.SHA256 = viewEntry("replacement", "public").SHA256
	if _, err := Promote(strings.NewReader(viewText(t, old)), strings.NewReader(viewText(t, replacement)), &bytes.Buffer{}, Selector{}, true); err == nil {
		t.Fatal("strict promotion accepted a replacement")
	}
	var promoted bytes.Buffer
	count, err := PromoteWithReplacements(
		strings.NewReader(viewText(t, old)), strings.NewReader(viewText(t, replacement)), &promoted, Selector{}, true,
		func(entry Entry) bool { return entry.Path == old.Path },
	)
	if err != nil || count != 1 || promoted.String() != viewText(t, replacement) {
		t.Fatalf("scoped replacement count=%d err=%v manifest=%s", count, err, promoted.String())
	}
	if _, err := PromoteWithReplacements(
		strings.NewReader(viewText(t, old)), strings.NewReader(viewText(t, replacement)), &bytes.Buffer{}, Selector{}, true,
		func(Entry) bool { return false },
	); err == nil {
		t.Fatal("out-of-scope replacement was accepted")
	}
}

func TestStableRemovalAndSnapshotNaming(t *testing.T) {
	if _, err := Remove(strings.NewReader(viewText(t, viewEntry("a", "public"))), &bytes.Buffer{}, Selector{}, true); err == nil {
		t.Fatal("append-only removal accepted")
	}
	id, err := SnapshotID("jammy", time.Date(2026, 7, 11, 23, 59, 0, 0, time.FixedZone("offset", 8*3600)))
	if err != nil || id != "jammy-20260711" {
		t.Fatalf("snapshot id=%s err=%v", id, err)
	}
}

func TestProjectManifestStreamsSortedUnionAndRejectsConflicts(t *testing.T) {
	a := viewEntry("a", "public")
	b := viewEntry("b", "public")
	var projected bytes.Buffer
	entries, total, err := ProjectManifest([]ProjectionInput{
		{Label: "left", Reader: strings.NewReader(viewText(t, a, b))},
		{Label: "right", Reader: strings.NewReader(viewText(t, b))},
	}, &projected)
	if err != nil || entries != 2 || total != a.Size+b.Size {
		t.Fatalf("projection entries=%d total=%d err=%v", entries, total, err)
	}
	if !strings.Contains(projected.String(), a.Path+"\t") || !strings.Contains(projected.String(), b.Path+"\t") {
		t.Fatalf("missing projected paths: %s", projected.String())
	}
	conflict := b
	conflict.SHA256 = a.SHA256
	if _, _, err := ProjectManifest([]ProjectionInput{
		{Label: "left", Reader: strings.NewReader(viewText(t, b))},
		{Label: "right", Reader: strings.NewReader(viewText(t, conflict))},
	}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "path conflict") {
		t.Fatalf("projection conflict accepted: %v", err)
	}
}

func TestMutateStreamsUpsertRemoveAndPreservesGates(t *testing.T) {
	a, b, c := viewEntry("a", "public"), viewEntry("b", "public"), viewEntry("c", "public")
	replacement := b
	replacement.Version = "2"
	replacement.SHA256 = c.SHA256
	var out bytes.Buffer
	stats, err := Mutate(strings.NewReader(viewText(t, a, b)), &out, Mutation{
		Upserts: []Entry{replacement, c}, RemovePaths: []string{a.Path}, AllowReplace: true, Public: true,
	})
	if err != nil || stats.Added != 1 || stats.Replaced != 1 || stats.Removed != 1 {
		t.Fatalf("mutation stats=%+v err=%v", stats, err)
	}
	if _, err := ValidateLeaf(bytes.NewReader(out.Bytes()), "repo", "el9", "x86_64", true); err != nil {
		t.Fatal(err)
	}
	if _, err := Mutate(strings.NewReader(viewText(t, a)), &bytes.Buffer{}, Mutation{RemovePaths: []string{a.Path}, AppendOnly: true}); err == nil {
		t.Fatal("append-only removal accepted")
	}
	if _, err := Mutate(strings.NewReader(viewText(t, b)), &bytes.Buffer{}, Mutation{Upserts: []Entry{replacement}, AllowReplace: true, AppendOnly: true}); err == nil {
		t.Fatal("append-only mutation accepted an unscoped replacement")
	}
	var scoped bytes.Buffer
	scopedStats, err := Mutate(strings.NewReader(viewText(t, b)), &scoped, Mutation{
		Upserts: []Entry{replacement}, AllowReplace: true, AppendOnly: true,
		AppendOnlyReplacementPaths: []string{b.Path},
	})
	if err != nil || scopedStats.Replaced != 1 {
		t.Fatalf("scoped append-only replacement stats=%+v err=%v", scopedStats, err)
	}
	gated := viewEntry("secret", "gated")
	if _, err := Mutate(strings.NewReader(""), &bytes.Buffer{}, Mutation{Upserts: []Entry{gated}, Public: true}); err == nil || !strings.Contains(err.Error(), "closure violation") {
		t.Fatalf("public mutation accepted gated entry: %v", err)
	}
}
