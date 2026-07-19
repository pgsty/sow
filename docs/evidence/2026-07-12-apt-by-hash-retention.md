# APT by-hash 自动保留证据（2026-07-12）

## 验收边界

本证据针对 FR-07 的“SHA256 by-hash、保留 N 版自动清旧”产品路径。配置项
`state.apt_by_hash_retention` 为正整数，默认 2，含义是总共保留 live 与最近完整
代际中的 2 代。每个 mutable view/repo/suite 在 `.sow/state` 内保存带 SHA-256
封印及单调序号的 Git 正典账本；SQLite 不参与清理决策。

索引生成先安装不可变 by-hash 与 mutable Release 文件，最后翻转 `InRelease`。
只有翻转成功后才加载并完整校验账本、预检所有 retained 对象，再删除精确旧路径。
删除成功后才把账本加入 canonical state 事务。因此进程在删除或 Git 提交间中断时，
旧账本仍可导出同一个删除计划；缺失路径的删除是幂等的。publish 的 repo 准备可以
并发，但账本在结果汇总阶段仅执行一次串行 Git 写入。远端授权不是把任意 manifest
removal 直接转成 DELETE：每个 target 从自己的旧 content manifest 取得 size/SHA，要求
当前 sealed ledger 与 live Release 一致、路径不在任何 retained generation，并在 Git
祖先中找到有效 ownership 后才删除。因历史 ledger 不会被先成功的 target 消费，cf/cos
可错峰推进。

## 实跑命令与结果

```text
$ go test ./internal/cli \
    -run TestCLIAPTByHashRetentionKeepsTwoGenerationsAndFailsClosed \
    -count=1
ok github.com/pgsty/sow/internal/cli 3.450s

$ go test ./internal/aptrepo \
    -run 'TestPlanAndApplyByHashCleanup|TestByHashCleanup|TestByHashLedger' \
    -count=1
ok github.com/pgsty/sow/internal/aptrepo 0.498s

$ go test ./internal/cli \
    -run TestPublishCLIAPTByHashRetentionDeletesBothTargetsAcrossStaggeredPublishes \
    -count=1
ok github.com/pgsty/sow/internal/cli

$ go test -race ./internal/cli \
    -run 'TestCLIAPTByHashRetentionKeepsTwoGenerationsAndFailsClosed|TestDEBAddBuildsSignedByHashRepositoryFromExternalPackage|Test.*Publish' \
    -count=1
ok github.com/pgsty/sow/internal/cli 57.714s

$ go test ./... -count=1
all packages passed; internal/cli 64.228s, test/compat 3.819s
```

CLI 用例通过真实 `sow add` 命令创建四个合法 `.deb` 版本并使用生产 APT
streaming generator：

1. 连续前三次生成三个不同 Release；第三次后第一代独有的三个 by-hash 路径已删除，
   第二、第三代所有路径仍存在且内容摘要与文件名一致。
2. canonical ledger 的 `last_sequence=3`，当前文件只保留第二、第三代；被清理的第一代
   仍可从内嵌 Git 历史审计。
3. 重放第三个包得到相同 generation，ledger 字节不变、`changed=false`、无删除。
4. 同一用例执行 `promote beta latest` 与真实 `sow materialize latest`，并验证 latest
   serving tree 的独立 canonical ledger 已提交，证明 materialize 命令没有绕过清理路径。
5. 篡改 ledger 的 repo 字段但不更新封印后再加入第四版：新 Release 已生成，但命令以
   `by-hash ledger checksum mismatch` 失败，原本下一轮应删除的第二代独有路径仍存在，
   证明损坏账本不会触发任何清理。
6. aptrepo 层另测 retained/live 路径缺失、非普通文件或摘要错误时，在检查 removal
   集之前失败；删除集中的文件保持原样。
7. 真实 publish 协议夹具先发布 cf、提交其 remote state，再单独发布 cos；两端各删除
   第一代三个唯一 by-hash key、保留后两代全部 key，且 by-hash URL 不进入 purge。

真实 `apt update/install`、InRelease 签名与 Nginx 直接托管兼容证据在
`2026-07-11-client-compat.md`，不以本单测替代。
