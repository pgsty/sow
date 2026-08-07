# Brownfield baseline

> **Historical v0.2 baseline.** This file describes the implementation surface
> that led to C2 and is not a forward layout contract. The approved
> Repository-scoped single-payload design is [`../../next/`](../../next/);
> current code remains v0.2 until that migration is implemented.

## Current active surface

- `cmd/sow` 只进入 `internal/v2cli`；当前公开能力为 P0 `create` 和 P1 `init/config/repo/dist`。
- `internal/v2/{config,state,managed}` 已有 strict config、Workspace/Repository lock、SQLite schema v1、workspace/repository journal 与空 Dist renderer。
- P1 的 YUM layout 已通过真实客户端门禁后固定为 C2：root Pool + view-local hardlink aliases。原 API 文稿中的 `../../../pool` href 已被 reposync 实证否决。
- `internal/aptrepo`、`internal/yumrepo` 与 `internal/v2/plain` 提供可复用 parser、version、renderer、signature 与安全文件原语，但复用必须重新适配 Managed identity/transaction 语义。

## Deliberately absent today

- CLI 未注册 `add/rm/ls/show/where/status/build/check/changes/log`。
- 配置当前拒绝 `limit/exclude/signing/trusted_keys`，SQLite 的 package/membership 扩展点没有公共 mutation consumer。
- 非空 C2 package projection、private pending、Desired/Built 收敛、Generation manifest/Changeset、Managed metadata signing 和完整 check 尚未形成垂直闭环。

## Preservation and debt

- P0 Plain 的现有 repo2 traditional-tool/client/signing evidence 必须作为回归层保留，但最终仍要用最终 checkout 复跑关键门禁。
- Plain pre-journal stage orphan ownership/cleanup 是已登记债务；不得让 P2/P3 新 stage 复制同一无所有权残留模式。
- RPM reader 的 hash/header 同 inode ABA 风险在 P2 外部输入解析中变成 load-bearing；P2 应先从不可变私有 snapshot 解析或对同 descriptor 做可证明的一致性校验。
- 旧 V1 `internal/cli` 的大规模 fsync 套件可能超过默认 package timeout；它与活动 V2 图分层报告，但不能隐藏真正失败。
- 历史生产目录 metadata 观察不能证明本目标的零写入；本目标建立新的安全边界，只使用显式 lab 作为任何写路径。

## Source-of-truth order

1. `api-contract.md`：公共 API、参数、状态、退出码。
2. `SPEC.md` 与 `acceptance-matrix.md`：本目标能力、冻结修正与证据门槛。
3. PRD：产品目的、FR/NFR 与成功指标。
4. addendum：设计理由和行业证据。
5. 现有代码、旧 spec 和旧 acceptance：实现/证据线索，不覆盖上述契约。
