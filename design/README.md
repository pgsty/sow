# SOW internal design

This directory contains implementation-facing design, specifications, review
notes, and acceptance evidence maintained with the SOW source tree.

It is not the public documentation source. Public/user documentation is owned
by the separate `sow.pgsty.com` checkout. The repository-level `docs/` path is
therefore intentionally ignored for newly generated files; already tracked
historical files are retained only as brownfield context.

- [`next/`](next/) -- current Repository-scoped single-payload
  `pool/ + dists/` contract. Source implementation and local/mock verification
  are present; live client and real-object-store release evidence remains
  explicitly incomplete. It also owns the explicit migration/publication abort,
  target pointer-withdrawal fence, and filesystem effective-path overlap rules.
- [`v0.2/`](v0.2/) -- archived v0.2.0 contract, implementation description,
  reviews, and evidence. Its C2 hardlink layout remains historical fact but is
  superseded for future work.
- [`v0.2/architecture.md`](v0.2/architecture.md) -- implemented v0.2 architecture.
- [`v0.2/prd/`](v0.2/prd/) -- product and API design inputs.
- [`v0.2/specs/`](v0.2/specs/) -- P0-P3 implementation specifications.
- [`v0.2/evidence/`](v0.2/evidence/) -- time-stamped acceptance evidence.
- [`v0.2/research/`](v0.2/research/) -- implementation-facing technical research.
- [`v0.2/release-spec.md`](v0.2/release-spec.md) -- v0.2.0 release contract.
