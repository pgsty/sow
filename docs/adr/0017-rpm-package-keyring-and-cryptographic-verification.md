# ADR-0017: RPM package keyring and cryptographic verification

Status: accepted — 2026-07-13

Supersedes: ADR-0014 decisions 1, 3, 5 and 6 for new receipts, its
current-ingestion policy, and every statement that treats structural
signature-packet inspection as sufficient for FR-29 or TECH-06. ADR-0014
remains authoritative for byte preservation and historical v1/v2
encoding/packet evidence; current replay additionally obeys this ADR.

## Context

RPM metadata trust and RPM package trust are separate. A valid `repomd.xml.asc`
authenticates the advertised package digest, but FR-29 also requires the package
signature itself to be valid, and the frozen sync boundary is
download checksum, package verification, then provenance commit. Recording an
embedded packet without checking it against a trusted key therefore cannot
satisfy either contract.

The repository is append-only. Key rotation cannot discard an old signing key
while retained stable or snapshot content still depends on it. Verification
also cannot shell out to `rpm`, `gpg`, or `dnf`, because the product is one Go
binary with no external runtime dependency.

## Decision

1. Every YUM repository declares `repos[].yum.package_keyring`. It is a bounded,
   public-only OpenPGP bundle resolved relative to `sow.yaml`. For backward
   compatibility it defaults to `gpg.public_key`, which is the Pigsty package
   key for locally built RPMs. A third-party mirror declares an explicit bundle
   containing all package signers accepted into that repository.
2. Rotation is bundle based. Add the new public key before accepting packages
   signed by it. Retain every old key while any append-only view, snapshot, or
   history ref can still reach a package signed by that key. Removing a needed
   key makes add, sync, L1, materialize, and publish fail closed.
3. Verification is pure Go. Legacy whole-package PGP/GPG signatures cover the
   main header plus payload. Modern RSA/DSA header signatures verify the exact
   RPM main-header bytes and additionally require the signed header's declared
   payload digest to match the streamed payload. Unsigned, unknown-issuer,
   malformed, unsupported-digest, header-tampered, and payload-tampered RPMs are
   rejected. Package-keyring parsing preserves the primary key's historical
   self-certification and revocation packets plus every signing-subkey binding,
   embedded primary-key-binding cross-signature and revocation packet. It must
   not collapse those packets into only the library's current `Entity` view,
   because retained RPMs have to be evaluated against the policy that existed
   when their package signature was created. Binary OpenPGP keyring input is
   parsed byte-for-byte; generic whitespace trimming is forbidden because bytes
   such as a trailing `0x0b` are valid packet data. Only ASCII-armored input may
   accept outer textual whitespace before armor decoding.
4. New upstream RPM receipts use `sow-provenance/v3`. They retain v2 packet
   evidence and additionally record `signature_verification=verified`, the
   package-keyring SHA-256, signature creation time, coverage, signed byte
   count, payload digest evidence when applicable, and the verified signer and
   primary-key fingerprint/key ID for each accepted packet. At least one
   trusted signature must cover the whole package, directly or through the
   signed payload digest. New receipts cannot claim trust without the required
   fields. Historical v1/v2 receipts remain strictly decodable and canonical;
   replay verifies their package bytes against the current keyring without
   rewriting the first canonical observation.
5. `sow add` copies the pathname input into a private `0700` snapshot directory
   and inspects that snapshot. Signature verification consumes a stable opened
   descriptor and closes it promptly; CAS `ImportExpected` reopens only the
   private snapshot and streams it against the exact inspected size and digest
   before installation. Replacing either the caller pathname or snapshot cannot
   substitute different CAS bytes, while large batches do not retain one file
   descriptor per package. `sow sync` verifies
   downloaded and already-present RPMs before the provenance commit. L1 verifies
   every indexed RPM with bounded concurrency. Materialization and publish
   preparation perform the same package-trust gate, so legacy-adopted content
   cannot bypass verification.
6. Repository metadata signing remains controlled by `gpg.public_key` plus the
   protected private-key reference. Package-keyring material is public and is
   never accepted from a secret reference, command output, or remote metadata.
7. Publication loads one immutable trust snapshot for the complete target ref
   vector. Its domain-separated publication identity binds canonical YAML plus
   the SHA-256 identities of only the YUM `package_keyring` files reachable from
   that vector; the exact parsed in-memory keyrings from the same reads supply
   package verification. An exact inherited ref under the same identity reuses
   the parent's proof without reading its manifest or package bytes. A changed
   ref under the same trust policy streams the old/new manifest delta and
   verifies only additions and replacements. First publication, or any
   publication-identity/keyring-policy change, revalidates the complete reachable
   RPM closure.
8. Publish hashes and verifies each CAS RPM through one opened file descriptor,
   then checks descriptor metadata and the canonical path/inode, size, and mtime
   for stability. A pathname swap between digest and embedded-signature checks
   cannot combine evidence from two objects. L4 client verification downloads a
   sampled RPM advertised by signed metadata and verifies its embedded package
   signature against the repository package keyring; repomd and payload checksum
   success alone is not an L4 pass.
9. Historical trust is time- and policy-aware. For a package signature, SOW
   selects the newest cryptographically authenticated primary self-certification
   or subkey binding whose creation time is not later than the package signature
   time. Only after selecting that newest policy packet does it enforce signing
   flags, primary/subkey lifetime, outer self-certification or binding expiry,
   embedded cross-certification presence and expiry, and revocation semantics.
   An invalid newest policy is terminal: verification may not fall back to an
   older, more permissive packet. `KeySuperseded` and `KeyRetired` revocations
   are prospective from their authenticated creation time; compromise and
   unspecified/no-reason revocations are retroactive and invalidate earlier
   signatures as well.
10. Upstream `present` status is not permission to trust a pathname or size.
    Every newly downloaded or previously unproven present body is opened through
    a stability-checked handle and bound to its advertised SHA-256 and size;
    RPMs additionally pass embedded-signature verification. FR-06 permits reuse
    only of an unchanged first-valid DEB receipt, or an RPM v3 receipt whose
    package-keyring SHA-256 exactly matches the current immutable keyring.
    Package-keyring rotation and legacy v1/v2 RPM receipts force body hashing and
    signature revalidation. If the same CAS object is newly entering a selected
    view, SOW independently runs the CAS pool verifier before creating a view
    link, so a corrupt existing pool object cannot be admitted by receipt reuse.
11. APT present-candidate suppression is coordinate exact. A manifest entry can
    suppress work only when its repository-relative path, component, package
    name, version and size match the candidate (within the already selected
    suite/view/architecture). Component extraction first removes the exact
    configured `repo.path + "/"` prefix and then accepts only the relative
    `pool/<configured-component>/...` shape. A `pool/main` substring in the repo
    root, or a same-digest package moving from `main` to `contrib`, cannot hide a
    required new placement.

## Consequences

- FR-16 byte-preserving provenance and FR-17 no-resign policy are unchanged;
  signer trust is now an additional evidence layer rather than an inference.
- Key rotation is explicit and auditable, but old trust keys normally remain
  for the lifetime of stable history.
- A no-change publication remains O(change set): exact inherited refs perform no
  manifest or package reads, while changed refs under the same trust policy read
  manifests and verify only added/replaced RPMs. Trust-policy changes deliberately
  pay one complete reachable-closure verification.
- L1 and first materialization after migration perform package-sized streaming
  work. Memory remains bounded and package checks use the configured worker
  budget.
- Existing v1/v2 ledgers remain reproducible, but a package trusted only by a
  removed key cannot be replayed or published merely because an old receipt
  exists.
- Historical key renewal remains usable without reviving superseded policy:
  packet preservation enables verification at the package-signature time, while
  newest-policy-first validation prevents fallback across expiry, usage,
  lifetime, cross-certification or revocation failures.
- Incremental sync avoids whole-CAS rescans on the normal path, but receipt reuse
  remains evidence-bound and a newly selected view always proves its CAS body.
- Keyring transport is lossless for binary packets. Human-friendly outer
  whitespace handling is limited to armored text and cannot mutate binary trust
  material before its SHA-256 identity or packet history is parsed.
