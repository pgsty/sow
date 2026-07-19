# ADR-0014: RPM provenance signature-evidence boundary

Status: accepted as the historical v1/v2 encoding and packet-evidence record;
decisions 1, 3, 5 and 6 for new receipts, plus current-ingestion policy, are superseded by
[ADR-0017](0017-rpm-package-keyring-and-cryptographic-verification.md) on
2026-07-13. Structural inspection is no longer sufficient for new ingestion,
L1, materialization, or publication.

## Context

FR-16 and FR-17 require mirrored RPM bytes, including any embedded package
signature, to remain byte-identical. They do not authorize Day-1 re-signing.
The original `sow-provenance/v1` receipt bound the RPM SHA-256 to signed YUM
primary metadata and named the policy `preserve-upstream`, but it did not
inspect the RPM signature header. That proved byte preservation while leaving
the phrase "embedded signature" unsupported for an unsigned or malformed RPM.

The pinned RPM parser's former verification helper used the abandoned
`golang.org/x/crypto/openpgp` implementation and cannot safely stand in for a
modern package-keyring verifier. Repository metadata authentication and RPM
package-signature trust are also distinct: signed repomd/primary authenticates
the expected RPM bytes, while `rpm -K`/DNF `gpgcheck=1` verifies the embedded
signature against a package keyring.

## Decision

The numbered decisions below describe the v2 transition and remain normative
only when decoding or auditing historical v1/v2 receipts. ADR-0017 defines the
schema and trust checks for every new receipt and current replay.

1. New receipts use `sow-provenance/v2`. An RPM receipt is created only after
   SOW parses the downloaded or already-present exact RPM bytes and finds at
   least one structurally valid signature packet in the supported RPM header
   tags: modern `RPMSIGTAG_RSA`/`RPMSIGTAG_DSA` and legacy
   `RPMSIGTAG_PGP`/`RPMSIGTAG_GPG`/`RPMSIGTAG_PGP5`.
2. Each entry records the header tag, exact packet SHA-256 and size, OpenPGP
   packet version, public-key/hash algorithm identifiers and issuer key ID when
   present. Inspection uses a signature-header-only parser with an independent
   2 MiB raw-header/256-index budget and never reads the RPM main header or
   payload. Only binary-document signatures are accepted. A v4 issuer
   fingerprint must name a v4 key and contain exactly 20 fingerprint bytes.
   Packet, header, subpacket and MPI lengths are bounded and checked; unsigned
   RPMs, malformed packets, conflicting issuers, tag/algorithm mismatches and
   trailing packet bytes fail closed before provenance commit.
3. The receipt field `signature_verification` is exactly `not-performed`.
   Signature metadata proves inspection and byte preservation only. It must
   never be presented as cryptographic validity or signer trust. Real
   `rpm -K`/DNF evidence remains a separate compatibility gate using the
   configured public package trust bundle.
4. `sow-provenance/v1` remains strictly decodable and canonical: empty v2
   fields are omitted and no signature facts are invented. Replay still
   validates the current signed metadata, and present RPM replay still inspects
   the exact body. Because the ledger is keyed by immutable artifact SHA-256,
   the first valid signed observation wins: later mirror URLs, primary hashes,
   Packages entries and Release roots may rotate without rewriting that receipt.
   For v2-to-v2 RPM replay, body-derived embedded-signature evidence must remain
   byte-for-byte equal. v1/v1 and v1/v2 replay are symmetric and retain whichever
   valid receipt was canonical first. Artifact identity, format, size, RPM
   signature policy or v2 body-derived evidence differences remain conflicts.
5. SOW does not add an unsafe OpenPGP verifier, package-keyring schema or RPM
   re-signing path under this change. Cryptographic package verification inside
   sync requires a separately frozen trust-source/rotation contract; full
   re-signing remains governed by FR-17's commercial-phase prerequisites.
6. New DEB receipts also carry the v2 schema marker, but their proof fields and
   trust semantics are unchanged. Current Packages/Release evidence is verified
   before commit, then a matching artifact reuses its first v1 or v2 receipt
   even when that observation chain rotated; no duplicate or automatic history
   rewrite is produced.

## Consequences

- `preserve-upstream` now has concrete, reproducible evidence for new receipts:
  artifact identity plus hashes of the embedded packets actually found.
- A repository with signed repomd but an unsigned or structurally corrupt RPM
  is rejected rather than receiving a misleading provenance receipt.
- Existing v1 state remains readable and replayable without silently upgrading
  historical claims. Operators can distinguish legacy byte-only evidence from
  v2 inspected-signature evidence by schema.
- Long-lived packages no longer conflict merely because an upstream publishes a
  new signed index or changes mirrors; genuine APT/YUM executor and production
  CLI tests retain the old receipt, admit a new package and signed evidence,
  then replay with zero downloads.
- Cryptographic signer validity is intentionally not inferred from packet
  syntax, issuer metadata, TLS, repomd verification or successful parsing.
