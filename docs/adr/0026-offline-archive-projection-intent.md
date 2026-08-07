# ADR-0026: Offline archive projection intent

> **Historical V1 ADR.** Next offline/leaf output is an external derived export,
> never a Generation or publish input; see [`../../design/next/specs/compatibility.md`](../../design/next/specs/compatibility.md).

Status: Accepted

Date: 2026-07-15

## Context

An offline archive has two durability domains: its canonical digest-level confidentiality receipt and its operator-visible filesystem name. A receipt alone cannot recover an interrupted publication because it does not bind the destination, and regenerating from `latest`, `beta`, or `stable` after a crash can produce different bytes if the mutable ref has advanced.

The destination tree must remain directly hostable. Complete or partial staging names therefore cannot be created in a directory served by Nginx. Publication must also remain no-clobber and atomic.

## Decision

Before committing a taint receipt or exposing the final name, SOW creates a second hard link to the completed `0444` archive inode below `.sow/offline-archive-projection/`, a `0700` directory, and fsyncs that directory. It then writes and fsyncs `offline-archive-projection-intent.json`.

The intent binds:

- the exact frozen canonical refs, commits, manifest paths, entry digest, and confidentiality proof;
- the archive digest, size, entry count, and source-byte count;
- the current canonical configuration digest;
- the exact validated materialization root and absolute destination;
- the private durable stage name and transaction identity.

When `--asset-repo` is selected, the same intent also owns an archive-adoption
contract. That contract binds the semantic source proof, archive digest and
size, and the exact destination repo/pool/view/path. The outer intent is not
removed after the archive filename becomes visible: it remains the recovery
owner while the asset ref, selected-set journal, CAS object, and directly
hostable asset tree converge. The archive-adoption selected-set journal embeds
the same contract and is the only canonical-mutation exception admitted while
the outer intent is live.

Only after those boundaries are durable may SOW commit the canonical taint receipt and install the final name with a cross-directory no-clobber hard link. The intent remains until the destination directory has been fsynced, the final inode has been reverified, and private staging cleanup is durable.

`materialize --recover` always converges this frozen transaction first and exits. It does not rebuild from current selectors. If the mutable ref advanced, a later independent invocation may create a new archive at a different unused destination. An existing taint receipt may use a different Git commit witness only when its ref coordinates, manifest path, entry digest, policy counts, and confidentiality are semantically identical. Other canonical mutations are fenced while the intent exists. L1 verification and fsck report the pending intent as critical recovery state.

## Gzip and tar admission

SOW parses gzip framing as a context-aware bounded stream instead of relying on Go's bounded header-string reader. Legal long FEXTRA, FNAME, or FCOMMENT fields remain opaque-compatible, while FHCRC, payload CRC32, ISIZE, member boundaries, expansion budgets, and reserved flags are checked. Tar inspection continues after the first end-of-archive marker so a second tar stream in the same gzip member cannot conceal the payload policy marker. A malformed tar barrier, a later gzip member, or a byte prefix before an otherwise valid SOW gzip cannot conceal a policy marker.

An asset that does not start with gzip remains opaque. SOW does not recursively
classify every incidental `1f8b` byte pair in arbitrary binaries: compressed
source archives and images can contain such pairs, including complete nested
gzip members. The embedded-prefix tripwire instead recognizes the deterministic
SOW envelope frozen by the archive writer (zero MTIME, best-compression XFL,
and OS 255), with gzip flags deliberately left to the strict parser so a copied
archive with a removed FCOMMENT remains detectable and corrupt/reserved flags
fail closed. The recognized candidate is still fully validated through its
gzip trailer and first-entry tar policy marker. This boundary detects unchanged
or header-comment-stripped SOW archives placed behind an opaque prefix without
turning the asset manager into a recursive content/DLP scanner.

The in-band marker remains an integrity tripwire, not a substitute for an
external signature or a general DLP boundary: an actor able to deliberately
rewrite the deterministic envelope, or decompress and rebuild the archive, can
bypass or remove it. Canonical taint receipts and configured public/gated
closure remain authoritative within a managed SOW state root.

## Consequences

- Post-receipt and post-link process crashes are replayable without consulting mutable refs.
- A process stop between archive projection and asset adoption replays the exact
  frozen archive before current selectors may start new work.
- No staging filename is ever visible below the served destination parent.
- The private state and destination must support atomic hard links. Ordinary cross-device destinations fail before receipt; a late platform-specific `EXDEV` remains safely pending for recovery rather than exposing partial bytes.
- A successfully generated archive temporarily has one additional private hard link until the transaction completes.
- Ordinary opaque assets and nested third-party gzip data are admitted by
  digest; only the frozen SOW envelope activates embedded archive inspection.
