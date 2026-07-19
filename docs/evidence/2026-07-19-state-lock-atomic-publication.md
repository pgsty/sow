# State-lock process-instance and atomic-publication evidence

Date: 2026-07-19
Scope: V-28, FR-28 and NFR-09 local writer lease
Result: **local crash/recovery contract PASS; remote/cloud publication gates unchanged**

## Closed failure mode

The existing process-instance protocol already bound a lock to a random
256-bit ID, PID, Linux boot ID plus `/proc/<pid>/stat` start token, or Darwin
boot time plus `kinfo_proc` start time. Focused recovery tests covered exact
live instances, PID reuse, dead and zombie processes, unavailable probes,
legacy live/dead records, advisory leases, path replacement and in-place
record tampering.

The review found one remaining acquisition crash window: the authoritative
`state.lock` path was created before its JSON record was encoded. An abrupt
exit in that interval could leave an empty or partial authoritative file that
neither ordinary acquisition nor explicit recovery could safely classify.

The record now has a single namespace commit point:

1. Generate and validate the complete v1 process-instance record.
2. Create a private mode-0600 `state.lock.unpublished-<lock-id>` inode and
   acquire its advisory lease.
3. Encode and fsync the complete record.
4. Publish that exact leased inode with a create-only hardlink named
   `state.lock`.
5. Re-read the visible record, remove the private name through an inode-bound
   unlink, fsync the directory, then bind and validate state root, locks root,
   persistent lease, visible lock inode, record ID and process identity before
   any permission reconciliation or canonical mutation.

A crash before step 4 leaves only non-authoritative private evidence; ordinary
acquisition may continue and preserves that evidence byte-for-byte. A crash
after step 4 leaves a complete authoritative record, so ordinary acquisition
reports the stale owner and `--recover` hardlinks the exact old inode to a
stale-evidence name before taking a new lock. A concurrent legacy create-only
winner is never overwritten: the hardlink collision discards only the private
prepared inode and then classifies the winning `state.lock` normally.

## Fault and boundary matrix

- Real child processes call `os.Exit(86)` immediately before and immediately
  after the hardlink commit point. Pre-commit leaves no `state.lock`; post-commit
  leaves byte-identical prepared/visible hardlinks and recovers with exactly one
  preserved stale record.
- A deliberately partial unpublished JSON file remains non-authoritative,
  unchanged and unable to block a normal acquisition.
- Returned failures before and after publication remove both prepared and
  visible names when they are still the exact leased inode; a clean retry
  succeeds.
- A legacy-compatible record created between the absence check and hardlink
  wins create-only publication, remains byte-identical and is recovered only
  under the normal explicit policy.
- Replacing the visible `state.lock` after publication but before permission
  reconciliation fails the full holder-binding check. The foreign replacement
  and displaced evidence remain untouched, and an unrelated mode-0666 control
  file proves that no reconciliation mutation ran first.
- Exact live instances, same-process re-entry, persistent-lease replacement,
  PID reuse, dead process, conservative legacy migration, malformed records,
  symlinks, permission drift and release tampering retain their prior negative
  coverage.

## Reproduced commands

```bash
go test -count=1 ./internal/state
go test -race -count=1 ./internal/state
go vet ./internal/state
staticcheck -checks='SA*,S1*' ./internal/state
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go test -c -o /tmp/sow-state-linux-amd64.test ./internal/state
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
  go test -c -o /tmp/sow-state-darwin-arm64.test ./internal/state
go test ./... -run '^$'
SOW_RUN_REAL_CLOUD=0 SOW_RUN_REAL_EDGE_EVIDENCE=0 \
  SOW_RUN_REAL_UPSTREAM=0 \
  go test -count=1 ./test/compat/cleandelivery
git diff --check
```

Final current-source results:

```text
internal/state ordinary PASS (4.693s)
internal/state race PASS (11.105s)
go vet PASS
Staticcheck SA*/S1* PASS
Linux amd64 and Darwin arm64 test binaries compile PASS
all root-module packages and tests compile PASS (14.158s final compile gate)
clean-delivery policy closure PASS (1.954s)
git diff --check PASS
```

Two independent read-only reviews were run on the baseline diff. The blind
review found no high-confidence defect. The edge review found the
publish-to-permission path-replacement window described above; the final
pre-mutation binding and its negative test close that finding.

All executions used temporary local directories and local child processes.
No credential was read, no network or cloud request was made, and no CO/COS,
Cloudflare production repository, or Pigsty production checkout was modified.

## Evidence boundary

This closes the local SOW writer-lock and acquisition-interruption contract. It
does not upgrade FR-28 or NFR-09 beyond `已实现/未验证`, because their overall
status also requires real non-production R2/COS checkpoint races, CDN failure
replay and the final dual-target publication exercise. Production resources
remain forbidden as test targets.
