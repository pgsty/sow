# `yum/infra` package-signature inventory — 2026-07-16

## Current-status update — 2026-07-17

This report is the immutable discovery record for the 2026-07-16 snapshot.
It no longer describes the current source tree. A new read-only snapshot found
all 216 RPM paths byte-identical to the copied source and accepted by
`rpmkeys -K` with only the Pigsty public key; the previously unsigned builder
wave has been replaced upstream of SOW.

The current snapshot then completed the real S0→S3 compatibility workflow,
EL8/9/10 × aarch64/x86_64 `repo_gpgcheck=1`/`gpgcheck=1` installs,
`fsck`, L1 and idempotent replay on a disposable copy. See
[`2026-07-17-yum-infra-current-compatibility-cutover.md`](2026-07-17-yum-infra-current-compatibility-cutover.md).
The exact unsigned table below remains useful provenance for the condition that
SOW correctly rejected; it must not be used as a current blocker.

## Result

The read-only Pigsty v1 `yum/infra/{aarch64,x86_64}` tree contains 216 RPM
paths. With the public Pigsty key `gpg-pubkey-b9bd8b20-6695e4fc` imported into
an ephemeral RPM database:

- 194 paths return `digests signatures OK`;
- 22 paths return only `digests OK` and have no embedded RPM signature;
- the 22 paths are 627,901,590 bytes and 21 unique objects (the noarch Kafka
  object is present in both architecture leaves).

All 21 unique unsigned objects were built in two recent waves, 2026-06-18 and
2026-06-24. Their RPM packager fields name Pigsty/Ruohang Feng except MinIO's
upstream packager label. This is a bounded missed builder-signing wave, not an
unknown historical signer rotation.

Both current gzip primary indexes reference all 22 paths exactly; none is an
unindexed orphan that can be quarantined without changing the repository
membership contract.

The source was mounted read-only into an AlmaLinux 9 container with
`--network none`; the RPM database lived only in a tmpfs. The production tree,
the writable adoption copy, and every cloud resource were unchanged. No
private key or `bin/fileauth.txt` was read.

```text
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev \
  --mount type=bind,source=/Users/vonng/pgsty/repo/yum/infra,target=/repo,readonly \
  --mount type=bind,source=/private/tmp/sow-pigsty-rpm-trust-20260716.asc,target=/key.asc,readonly \
  almalinux:9 sh -c '<ephemeral rpmdb import and rpmkeys -K over every RPM>'

signed=194 unsigned=22 other=0
```

The public key itself was fetched read-only from the documented Pigsty public
key URL. Its file SHA-256 is
`17b9c7727c3a4d3b77463299ade471b28a8ba97da263e6bbb02986a578de0882`;
the accepted full fingerprint is
`9592A7BC7A682E7333376E09E7935D8DB9BD8B20`.

## Exact unsigned set

| repository path | bytes | SHA-256 |
|---|---:|---|
| `yum/infra/aarch64/asciinema-3.2.1-1.aarch64.rpm` | 4,155,294 | `f6ab541e838c3d74145646250c73c0c39b205726876d024aaa4df97c8afde852` |
| `yum/infra/aarch64/duckdb-1.5.4-1.aarch64.rpm` | 20,541,521 | `7d5a398c9d3f29ec6bf0ce550138cb71b4569df8aac7085105f6463f1430cf9d` |
| `yum/infra/aarch64/grafana-victorialogs-ds-0.29.0-1.aarch64.rpm` | 11,852,893 | `3754d1b5fbb32742bc0057326434001a38fa12f86f1c38e0048d8061430ffb4b` |
| `yum/infra/aarch64/kafka-4.3.1-1.noarch.rpm` | 137,719,885 | `e43b9610ec2b8588175fbfc5ff95b06e69298cc60256649cb459283d077550a4` |
| `yum/infra/aarch64/minio-20260618000000.0.0-1.aarch64.rpm` | 32,616,493 | `5d3084a3712f3b830448dc83e8b9769ebf9b75566d05276a0de8c187fce33a1b` |
| `yum/infra/aarch64/nodejs-24.18.0-1.aarch64.rpm` | 61,429,800 | `37f8f70aac976e884a828bf134f2b67847e3d51d4a0c1fe11dc10f433be9d9f9` |
| `yum/infra/aarch64/pg_exporter-1.3.0-1.aarch64.rpm` | 4,822,763 | `3ae4f8c554242ae52c4ba0fa07a9d95b702f72938ce55e8456dd97242cc46faf` |
| `yum/infra/aarch64/rainfrog-0.3.19-1.aarch64.rpm` | 7,678,252 | `9a71fb2d8b9a22a67e768f7c12769d17d198aa831036a43fa62823fbdca5c8b4` |
| `yum/infra/aarch64/victoria-logs-1.51.0-1.aarch64.rpm` | 11,497,201 | `0ed987a9103fd453acf521a5d715721670f53f03a26ef04352f97b5bb50c7618` |
| `yum/infra/aarch64/vlagent-1.51.0-1.aarch64.rpm` | 9,945,345 | `678a1335025c3dca13b4a32ca569d9f0538951fd769ed1ea8b8edd928958f346` |
| `yum/infra/aarch64/vlogscli-1.51.0-1.aarch64.rpm` | 7,358,734 | `f5ddd072e0d6c98d883ce52b5db77e882e01bc00cd8a1620d550ad9ce47315f9` |
| `yum/infra/x86_64/asciinema-3.2.1-1.x86_64.rpm` | 4,429,142 | `82222d2639e64c04ab4f6060a45bb48843e8bc252c286214ca1e40eb4136d10a` |
| `yum/infra/x86_64/duckdb-1.5.4-1.x86_64.rpm` | 22,738,569 | `3c2d9441400b5c3722322144f9168cac32ac3590d2227b37a6dd05f0bf619b32` |
| `yum/infra/x86_64/grafana-victorialogs-ds-0.29.0-1.x86_64.rpm` | 12,783,924 | `70a9010af88a35ef4f8eaf1c229b0f3652ef48476f09b0a93ee2eee399d79bb2` |
| `yum/infra/x86_64/kafka-4.3.1-1.noarch.rpm` | 137,719,885 | `e43b9610ec2b8588175fbfc5ff95b06e69298cc60256649cb459283d077550a4` |
| `yum/infra/x86_64/minio-20260618000000.0.0-1.x86_64.rpm` | 35,842,436 | `e955946d2d415785144c4494bcf4684071c85a8531122240c50d2f069c92401d` |
| `yum/infra/x86_64/nodejs-24.18.0-1.x86_64.rpm` | 61,676,937 | `d5bf5090ff87b861ecb8b78733932fc799b704dd9eb93b99e2c39e580c704a55` |
| `yum/infra/x86_64/pg_exporter-1.3.0-1.x86_64.rpm` | 5,338,872 | `316a97ccb2df9a02de99dda33826857ec32bbd6fd874ffb950625bc064d62496` |
| `yum/infra/x86_64/rainfrog-0.3.19-1.x86_64.rpm` | 8,238,996 | `901ad01d7c08c3a7799dcc4c030b476caa799c892b5735e0540742d0353fcbd5` |
| `yum/infra/x86_64/victoria-logs-1.51.0-1.x86_64.rpm` | 11,933,027 | `af40f8de06db3c5b828dd076912c5c9593c112a72c596d2e48f430423f754c62` |
| `yum/infra/x86_64/vlagent-1.51.0-1.x86_64.rpm` | 10,224,297 | `c7aad57ea8ef6c37ec933c76d871ba6386474f5cd834cd4239c1a7178b03881d` |
| `yum/infra/x86_64/vlogscli-1.51.0-1.x86_64.rpm` | 7,357,324 | `b2e3f0cb7fe157c32950157611ea6a6ab3318685113c731ff2d238f62b250998` |

No alternate same-NEVRA RPM was present anywhere below the local
`/Users/vonng/pgsty/infra-pkg` or `/Users/vonng/pgsty/repo` trees.

## Consequence and remediation boundary

This is not caused by the EL8 lifecycle value. EL8 is frozen starting with
Pigsty v5.0.0, but the cross-EL compatibility projection still has to pass
package trust before its S1 freeze. ADR-0021 correctly rejects these 22 paths.

SOW must not mutate them with an implicit `rpmsign`: FR-17 says self-built RPMs
arrive signed from the builder, while mirrored RPMs retain their original
embedded signature. The admissible repair is therefore 21 signed replacement
objects from the builder (22 indexed paths), followed by regenerated index
membership and a fresh disposable-copy M0/S0 baseline. Excluding the files or
marking `digests OK` as a trusted signature would silently weaken FR-17,
FR-29, and NFR-06 and is not permitted.
