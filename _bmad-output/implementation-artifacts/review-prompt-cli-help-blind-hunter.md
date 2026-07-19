# Blind Hunter review prompt: complete CLI help flags

Invoke the `bmad-review-adversarial-general` skill on this focused diff. Work
without prior conversation context. The shared worktree contains unrelated
changes, so review only the paths and hunks described here. Return concrete
findings with file, line, consequence, and evidence; do not edit files.

Baseline commit: `84800a6743b0d72f3664a45dcf3eca59d1a1e663`

Intent: every implemented `sow` subcommand must preserve its concise synopsis
and notes while deriving the complete option list from its actual Go
`flag.FlagSet`. Help must return exit 0 and must not echo secret values supplied
before `--help`. No flag list may be duplicated by hand.

Focused diff:

```diff
--- a/internal/cli/app.go
+++ b/internal/cli/app.go
@@
+func printSubcommandUsage(fs *flag.FlagSet, synopsis string, notes ...string) {
+    output := fs.Output()
+    fmt.Fprintf(output, "Usage: %s\n", synopsis)
+    for _, note := range notes {
+        if note != "" {
+            fmt.Fprintln(output, note)
+        }
+    }
+    fmt.Fprintln(output)
+    fmt.Fprintln(output, "Options:")
+    fs.PrintDefaults()
+}
```

The `fs.Usage` callbacks in these commands changed from printing only a
hand-written `Usage:` line to calling the helper above after all flags are
registered:

- `internal/cli/app.go`: `init`, `fsck`
- `internal/cli/add.go`: `add`
- `internal/cli/remove.go`: `rm`
- `internal/cli/sync.go`: `sync`
- `internal/cli/promote.go`: `promote`
- `internal/cli/publish.go`: `publish` (its three restore/stable notes are
  passed as helper notes)
- `internal/cli/verify.go`: `verify`
- `internal/cli/materialize.go`: `materialize`
- `internal/cli/gc.go`: `gc`

```diff
--- a/internal/cli/app_test.go
+++ b/internal/cli/app_test.go
@@
+func TestHelpAndUsageCodes(t *testing.T) {
+    // Existing top-level and unknown-command assertions remain.
+    for _, command := range []string{
+        "init", "fsck", "add", "rm", "sync", "publish", "gc",
+        "verify", "promote", "materialize",
+    } {
+        // Main([]string{command, "--help"}) must return ExitOK, print the
+        // matching Usage line and an Options section to stderr, and must not
+        // emit a "sow: " error.
+    }
+}
+
+func TestHelpPrinterIncludesEveryRegisteredFlag(t *testing.T) {
+    fs := flag.NewFlagSet("fixture", flag.ContinueOnError)
+    // bool, int, string, and custom csvFlag values are registered.
+    printSubcommandUsage(fs, "sow fixture [options]", "Fixture note.")
+    // fs.VisitAll checks an exact option line exists for every registered
+    // flag name (not a prefix-only match).
+}
+
+func TestHelpDoesNotEchoSensitiveFlagValues(t *testing.T) {
+    // add/rm/sync/publish/materialize receive GPG private/passphrase marker
+    // paths; verify receives public-key/pro-token marker paths. In every case
+    // the marker is supplied before --help, Main returns ExitOK, and combined
+    // stdout/stderr contains neither the marker nor "sow: ".
+}
```

Documentation changes:

- `README.md:32-34` documents FlagSet-derived options and non-echo behavior.
- `docs/requirements-traceability.md:152` cites both new regression tests as
  FR-42 evidence.

Current verification evidence:

```text
GOTOOLCHAIN=go1.26.5 go test -count=1 ./internal/cli -run Help
ok github.com/pgsty/sow/internal/cli

GOTOOLCHAIN=go1.26.5 go test -race -count=1 ./internal/cli -run Help
ok github.com/pgsty/sow/internal/cli

GOTOOLCHAIN=go1.26.5 go vet ./internal/cli ./cmd/sow
exit 0

git diff --check
exit 0
```

Inspect the current versions of the scoped files to verify the summarized
hunks and line-level behavior.
