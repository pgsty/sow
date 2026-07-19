# ADR-0010: Repository signing identity and rotation boundary

Status: accepted

## Context

`gpg.public_key` is a path, while the private key may be injected from an
environment reference or CLI file. Hashing only the declarative configuration
cannot detect replacement of key bytes at the same path. Self-verifying new
metadata with an unrelated private override is also insufficient: apt and dnf
clients trust the configured public export, not whichever private key the
current process selected.

A target generation may carry package metadata from beta, latest, stable and
snapshots at once. Replacing the one signing key for one intent would create a
mixed-signature target. S3 has no transaction that can replace every intent,
CDN object and client trust configuration at once. The frozen product contract
chooses one repository signing key, not a dual-sign or multi-key protocol.

## Decision

1. Every APT/YUM signing operation requires one configured public OpenPGP
   entity with exactly one currently usable signing-capable fingerprint. The
   injected private entity must have the same primary fingerprint and the same
   sole signing fingerprint. Public files containing private material,
   unrelated overrides, expired/revoked keys and multiple signing keys fail
   before metadata staging.
2. The public-key identity is SHA-256 over a domain separator and the exact
   decoded OpenPGP packet stream. ASCII armor framing is normalized away. SOW
   never reserializes an `Entity` for this identity because its identity map has
   no deterministic iteration order.
3. Package target generations carry `repository_key_sha256`. The immutable
   generation digest consequently binds the identity into its checkpoint, COS
   create-only lock, journal and transaction ID. Genuinely asset-only
   generations leave the field empty.
4. The identity captured by the same safe public-key read used for private/public
   pairing is carried through metadata preparation. Planning rejects a changed
   public path after signing. Existing target refs must also remain exactly
   representable by the current repo type, suite/OS and architecture schema;
   removed or retyped package refs cannot silently lose their key binding.
5. In-place online replacement of a key for an already published package target
   is unsupported and fails before local repository materialization, CDN purge
   or remote mutation. Interrupted publication and forward restore must use the
   recorded key. This is a deliberate single-key safety boundary, not a warning
   or automatic best effort.
6. "One repository signing key" governs metadata produced by SOW: APT Release/
   InRelease and YUM repomd. It does not erase the embedded signatures on
   byte-preserved upstream RPMs. Until the optional FR-17 full re-signing phase,
   DNF clients must receive a fingerprint-pinned package trust bundle containing
   the SOW/Pigsty key plus every admitted upstream package signer. Those public
   verification keys are ordinary published assets, never additional SOW
   signing identities or private-key inputs. Treating the package trust bundle
   as a second metadata signing scheme, or installing a release RPM before its
   signer is trusted, is forbidden.

## Consequences

- Reformatting the same packet stream as binary or ASCII armor does not create
  drift. Changing packets, subkeys, revocations or expiration evidence does.
- `publish` no-change preflight and L2-L4 verification compare the current
  identity with the committed generation; selectors and asset-only updates
  cannot bypass the check when the target already carries packages.
- A planned key replacement is a breaking offline migration. Keep the old key
  available to finish incomplete transactions, build and validate a fresh
  target with the new key, stage client trust/URL changes, then cut over with
  the old target retained as rollback. SOW does not claim zero-downtime key
  rotation under schema v1.
- `repo_gpgcheck=1` and `gpgcheck=1` are independent mandatory client gates.
  Removing an upstream signer from the trust bundle requires first proving that
  no reachable view/snapshot still contains a package signed only by that key.
