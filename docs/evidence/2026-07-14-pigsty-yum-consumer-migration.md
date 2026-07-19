# Pigsty YUM generation-mirrorlist consumer migration evidence

Date: 2026-07-14
Scope: local, non-production migration tooling for FZ-06 / MIG-04
Result: **local executable path PASS; production endpoint and client cutover remain open**

## Implemented contract

- `docs/migration/yum-consumer-map.tsv` schema v2 maps the four reviewed Pigsty
  definitions to exact architecture-specific `repo/os/arch` routes. Infra uses
  the two frozen cross-EL compatibility projections rather than a nonexistent
  per-release repository.
- `docs/migration/yum-consumer-files.tsv` freezes the two renderers and nine
  source files containing 28 managed definitions.
- `docs/migration/migrate-pigsty-yum-consumers.sh` provides read-only
  `audit`/`stage`/`verify`, digest-confirmed `apply`, and byte-exact
  `rollback`.
- The staged renderer selects `mirrorlist[region][os_arch]` before reviewed
  scalar-mirrorlist and raw `baseurl` fallbacks, emits a regional public-key bundle URL, and enables both
  `gpgcheck=1` and `repo_gpgcheck=1` for the mapped definitions.
- Stage/evidence directories must be outside the Pigsty checkout. Apply accepts
  only the exact before/after hash of every allow-listed regular file; rollback
  rejects foreign drift. Mixed before/after states are safe to replay after an
  interrupted apply or rollback.
- Existing raw URLs remain only as explicit source-level rollback/origin
  fallbacks. The generated `.repo` content uses `mirrorlist=` for the
  `default` and `china` regions.
- V-27 adds `sow compatibility yum-consumer-preflight` and its network-free
  receipt checker. Shell apply now refuses to create evidence/backups or edit
  Pigsty until an unexpired receipt binds every expanded route, canonical
  publication state, exact aggregate-owned trust identity/bytes and full
  RPM-MD/RPM evidence. It archives that receipt by digest before source
  mutation, then revalidates the same receipt immediately before the first
  write, so expiry during backups fails closed and an interrupted apply retains
  its proof chain.
  See `2026-07-19-pigsty-yum-consumer-preflight.md` and ADR-0038.

The generated key URL is
`/pkg/keys/rpm-trust.asc`. This is a public multi-key package trust bundle,
not the schema-v1 single repository-signing identity. It must contain the
fingerprint-reviewed repository public key plus every retained RPM source key
before any client cutover.

## Reproducible local checks

```bash
docs/migration/migrate-pigsty-yum-consumers.sh audit \
  --pigsty-root /Users/vonng/pgsty/pigsty

docs/migration/test-migrate-pigsty-yum-consumers.sh
```

Observed:

```text
mapped_definitions=28 already_migrated=
audit=pass
pigsty_yum_consumer_audit=pass mapped_definitions=28
pigsty_yum_consumer_stage=pass source_unchanged=true
pigsty_yum_consumer_apply=pass replay_idempotent=true mixed_state_recovered=true
pigsty_yum_consumer_preflight_gate=pass rejected_before_mutation=true receipt_bound=true
pigsty_yum_consumer_rollback=pass foreign_drift_rejected=true exact_bytes_restored=true replay_idempotent=true mixed_state_recovered=true
```

A fresh stage against the current Pigsty source produced:

```text
plan_sha256=2568d84b7d712e2a6ae756581bd5e349ab91181805e4b2e511fa6fcfd91cc371
changed=true
```

The test copies only the 11 allow-listed files to an isolated temporary tree.
It proves that audit/stage do not mutate the source checkout, applies the exact
plan, verifies a no-op replay, rejects foreign drift, recovers deliberately
mixed apply/rollback states, and compares every rolled-back file to its
original SHA-256.

## Real Pigsty renderer evaluation

The exact staged Jinja block was extracted and evaluated by the installed
Ansible renderer with `region=default`, EL9, and a mapped infra definition.
The rendered repository fragment contained:

```ini
mirrorlist = https://repo.example/_sow/v1/mirrorlist/latest/infra-legacy-x86-64/cross-el/x86_64.txt
gpgcheck = 1
enabled = 1
module_hotfixes = 1
repo_gpgcheck = 1
gpgkey = https://repo.example/pkg/keys/rpm-trust.asc
```

A second render with `region=origin` and a Percona definition selected the
retained upstream `baseurl`, proving the explicit non-SOW fallback is not
mistaken for a SOW generation mirrorlist.

## Deliberately not claimed

The production Pigsty checkout was not modified. The retained
`pigsty-v1-synthetic.yaml` fixture only proves the four per-major PGSQL parser shapes. The new
`pigsty-v1.yaml` machine contract maps all 130 ordinary YUM leaves but is still local migration
inventory, not published endpoint evidence: `yum/infra/{arch}` remains inactive
`quarantine-compat`, all signer/lifecycle fields remain explicit non-claims, and no cloud target is
configured. Therefore:

1. the plan must not be applied to production Pigsty yet;
2. every mapped mirrorlist and the aggregate-owned `rpm-trust.asc` must first
   exist on both public origins, pass the Go endpoint receipt gate and match the
   reviewed fingerprints/bytes;
3. isolated EL7/8/9/10 clients must render the resulting Pigsty `.repo` files;
   EL7 must run YUM 3 and EL8/9/10 must run DNF, all with
   `repo_gpgcheck=1`, and install a selected package;
4. only after those checks may the source plan be applied and deployed; the
   same evidence directory/digest is the rollback authority.

A provisional v1 consumer plan is not upgraded in place: use its retained
evidence to restore byte-identical raw definitions, then stage v2. Current
rollback keeps that legacy evidence path usable; v2 apply/rollback additionally
retains the endpoint receipt archive and digest marker.

This file does not upgrade MIG-04 or FZ-06 to production PASS. It closes the
previously missing local executable migration/recovery mechanism and leaves the
real topology, trust-bundle publication, dual-origin probing, and dnf cutover as
explicit evidence gates.
