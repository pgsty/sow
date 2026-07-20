# ADR-0040: Bound configuration topology before default expansion

- Status: Accepted
- Date: 2026-07-20

## Context

The schema-v1 decoder already rejects configuration input larger than 8 MiB,
but byte size alone does not bound the work implied by that input. A small YAML
document can omit every upstream architecture/component list and cause those
lists to be copied from a wide repository, or can declare APT
suite/component/architecture dimensions whose operational leaves are a
cartesian product. Repeated linear membership and path-prefix scans compounded
that amplification.

This is configuration topology, not package inventory. Package rows must remain
governed by the existing streaming, spool, chunk, and worker contracts so a
large repository is not rejected merely for containing many artifacts.

## Decision

Schema v1 has two independent fixed preflight ceilings:

- 65,536 configuration topology work units
  (`config.MaxConfigTopologyUnits`). One unit is one decoded collection member,
  one member that sequence default propagation would copy, or one logical
  metadata/selector leaf.
- 64 MiB of derived string bytes (`config.MaxConfigDerivedStringBytes`). This
  charges bytes repeated by templated paths, defaulted sequence values,
  package-keyring defaults, canonical serialization, and logical
  repo/view/metadata coordinates.

Accounting includes repo/group/upstream/view/target members, APT
suite-component-architecture leaves, every YUM OS/architecture selector,
repo/view selection leaves, publish-target defaults, omitted upstream
architecture/component defaults, and invalid zero-dimension default-view pairs
that the later strict schema check will reject. The raw YAML remains subject to
the independent 8 MiB input limit.

`Config.Validate` performs this accounting immediately after the schema check
and before any sequence default copy or derived topology allocation. Addition
and multiplication use pre-operation overflow checks. Either exact limit is
accepted; the first excess unit or byte fails with a stable configuration error
and does not partially mutate upstream slices.

Validation and its executable edge/Nginx projections then use indexed
membership, one-pass configured-arch expansion, and deterministic `O(n log n)`
path ownership checks. Error ordering remains compatible with the prior
quadratic reference behavior. Package count is explicitly excluded.

Changing either ceiling or what it charges is a schema-v1 operational contract
change and requires an ADR update plus boundary, migration-fixture, ordinary,
and race evidence.

## Consequences

- Hostile sub-8-MiB input cannot drive unbounded default-copy,
  cartesian-leaf, long-string repetition, or invalid zero-dimension
  cross-product work.
- Normal configuration remains comfortably below the limit: the shipped
  example, PGDG example, and 98-repository migration fixture currently consume
  33, 200, and 1,771 units.
- The ceiling is intentionally conservative: the largest current fixture has
  roughly 37 times headroom, while a 257-by-257 APT leaf product is rejected.
- The same fixtures consume only 561, 5,197, and 58,182 derived bytes out of
  64 MiB.
- New configuration dimensions and repeated string projections must be charged
  here before they are expanded.

## Evidence

See [the implementation report](../evidence/2026-07-20-config-topology-complexity-bound.md),
`internal/config/complexity.go`, `internal/config/complexity_test.go`, and
`internal/cli/config_complexity_test.go`.
