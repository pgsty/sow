# ADR-0019: Frozen EL7 YUM metadata compatibility

Status: accepted — 2026-07-14

## Context

The migration map retains the historical `yum/pgsql/el7.{arch}` repository.
SOW's normal YUM policy intentionally covers EL8 gzip and EL9/10 zstd, so the
generic `CompressionForEL(7)` path rejects EL7. Rejecting materialization for a
configured, frozen legacy leaf would leave the documented migration command
without a runnable equivalent; generally enabling EL7 would silently expand
the active product support matrix.

Modulemd, sqlite repodata and zchunk remain outside the frozen product scope.
The compatibility path therefore has to reuse the existing primary,
filelists, other and signed repomd generation rather than introduce another
metadata dialect.

## Decision

1. Configuration accepts YUM majors 7 through 10 only. EL7 is valid only with
   `os.lifecycle: frozen` and `yum.compression: gzip`; EL8 remains frozen gzip;
   EL9 and EL10 remain zstd. EL1-6, EL11+, active EL7 and EL7 zstd fail during
   configuration loading before state or serving bytes are created.
2. `yumrepo.CompressionForEL(7)` continues to reject EL7. Callers must construct
   explicit generation `Options` carrying major, frozen state and configured
   compression. `CompressionForOptions` is the sole narrow exception and
   accepts only frozen EL7 gzip.
3. Both direct YUM generation and dedicated materialization use the same
   `Options` value for generation and activation validation. A caller cannot
   generate under the exception and then activate through a broader or
   contradictory policy.
4. The emitted/accepted generation contains exactly primary, filelists, other,
   `repomd.xml` and `repomd.xml.asc`. Modulemd and every other extra repodata
   artifact remain fail-closed.
5. This is migration compatibility for an immutable legacy repository, not a
   commitment to active EL7 updates, upstream sync expansion or package build
   support.
6. YUM detached signatures keep SHA-256 and the exact signing identity, but
   disable go-crypto's randomized salt notation and emit the standard
   creation-time/key-flags subpackets as non-critical. This makes retries
   byte-deterministic and keeps the result parseable by the frozen YUM 3.4.3
   OpenPGP implementation without weakening cryptographic verification.

## Consequences

- A retained EL7 repository can be adopted and deterministically materialized
  without external `createrepo_c`, Python, Perl or `gpg`.
- Mutation policy remains frozen: normal add/sync paths cannot turn the
  compatibility leaf into an active EL7 channel.
- A digest-pinned CentOS 7 client (`yum 3.4.3`, RPM 4.11.3) now exercises this
  path end to end: `repo_gpgcheck=1`, all three gzip metadata streams, exact
  signed-RPM installation and `rpm -K`. The fixture is disposable and never
  reads or writes a production repository.
- The synthetic 33-selector test proves general selector/configuration behavior
  only. It is not evidence that every old vendor repository's multi-major
  physical topology or any production origin has been migrated.
