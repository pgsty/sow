# Client, mirror, and hardlink compatibility

## Support contract

| Consumer / operation | Contract | Current evidence / caveat |
| --- | --- | --- |
| APT archive-root repository | required | raw `Filename`/encode-once/by-hash locally tested; required live client matrix unverified |
| DNF ordinary over `file://` | required | current resolver/checker locally tested; pinned AlmaLinux 9/DNF4 historical fixture PASS at one view depth |
| DNF ordinary over HTTP(S) | required | URI round-trip locally tested; real next client/origin gate unverified |
| Direct static object hosting | required design target | filesystem and mocked R2 publication implemented; real target unverified |
| Whole-root locked handoff by SOW/known operator | required | one-to-one full manifest publication implemented; live relocated client handoff unverified |
| Default EL `dnf reposync` | unsupported product contract | pinned AlmaLinux 9 rejects; other EL variants remain matrix cells |
| DNF4/DNF5 `reposync --safe-write-path` | best effort, unverified | opt-in, single-repo, wider overwrite authority; not a promised fallback |
| Leaf-only copy/mirror | unsupported | leaf does not contain Pool |
| Pulp/Nexus/Artifactory/Foreman/other tools | matrix, not promise | require live proof; export is the explicit compatibility route |
| RPM standalone compatibility export | required capability | copy/default and hardlink/opt-in implementation locally tested; real default reposync consumption unverified |

“协议能表达”“普通包管理客户端能消费”“镜像命令能生成自包含副本”是三个不同
结论，测试和文档不得合并成一个 `compatible=true`。

## Why default EL reposync fails

普通 DNF 把 package href 当 URL relative reference，能够从
`dists/el9/x86_64/` 回到 root `pool/`。`reposync` 还要把 location 映射为本地
filename；它默认只允许写入 `<download-path>/<repoid>/`。规范化
`../../../pool/...` 后，本地 target 位于该目录之外，于是下载前即被安全门禁拒绝。

这不是 metadata checksum、HTTP server、硬链接或 package arch 的问题，而是
`reposync` 的本地写入 containment policy。上游 DNF4/DNF5 文档提供
`--safe-write-path` 显式扩大允许范围，并警告该范围内文件可能被覆盖；Red Hat
因路径穿越安全顾虑没有把这一行为作为 RHEL 默认支持能力。该 flag 的 multi-view
输出形态尚无 retained PoC。因此 next design
接受默认 EL reposync 不兼容，不再为它复制 canonical payload。

## Compatibility export

需要一个可独立托管或交给旧 mirror 工具的 RPM leaf 时，生成仓库外的唯一初始
profile `sow-rpm-leaf-v1`：

```text
<export-root>/
├── .sow-export.json             # completion/ownership marker, installed last
├── manifest.tsv                 # exact repodata/ + pool/ path/size/SHA-256 closure
├── repodata/
└── pool/<prefix>/<source>/<filename>
```

约束如下：

- 输入绑定一个 `repository_id + Built Generation + RPM Dist + architecture view`。
  closure 是该 view 的全部 Built Membership（native + neutral，以及配置明确包含的
  source/debug/module/comps metadata），不能从当前目录猜测。
- exporter 从 canonical Pool 读取 payload，并重新生成该 leaf 的 RPM-MD；Location 固定
  为 leaf-local `pool/...`，不得复制 canonical parent-relative href。metadata signing
  policy 与绑定 Generation 一致；签名开启时重新生成并验证 `repomd.xml.asc`。
- `manifest.tsv` **只**覆盖 `repodata/...` 与 `pool/...` regular files，明确排除
  `manifest.tsv` 与 `.sow-export.json`，从而不存在 self-hash cycle；按 path bytewise
  排序，每行固定为 `sha256 SP size SP path LF`，其中 size 是无前导零 ASCII decimal，
  范围 `0..9223372036854775807`，无重复 path。verifier 先按 manifest
  逐项验证 data closure，再单独计算 manifest SHA-256 并与 marker 比较。
- `.sow-export.json` 是 RFC 8785 canonical JSON，v1 恰好只有这些字段且拒绝 unknown
  field：`schema` string 固定 `sow/export/v1`、`profile` string 固定
  `sow-rpm-leaf-v1`、`repository_id` canonical UUID string、`generation` 是 20-digit
  `GenerationID` JSON string、`dist` 匹配 `[a-z0-9][a-z0-9._-]*`、`arch` enum
  `x86_64|aarch64`、`method` enum `copy|hardlink`、`signed` JSON boolean、
  `signer_identity`（unsigned 时固定 `none`；signed 时必须逐 byte 等于 bound Built
  Generation 对应 RPM view signing record 的 lowercase 64-hex identity）、
  `manifest_sha256` lowercase 64-hex string。exporter/source-bound verifier 必须比较该 identity
  与 bound signing record 相等，并用该 record 绑定的 trusted public key 验证
  `repodata/repomd.xml.asc`；standalone verifier 必须由外部 trust configuration 把相同 identity
  映射到同一 public key，不能从 marker 自封信任或用未冻结的 policy/key 拼接规则重算。
  `signed=true` 要求 manifest 覆盖并验证 `.asc`；false 要求它不存在。marker 在所有 data 与
  manifest 已 fsync/复验后
  通过同目录 temp + rename 最后安装；缺 marker 或任一 field 不合规都表示不完整导出。
- v1 输出目录必须不存在或为空；**不提供 in-place `--replace`**。重新导出必须使用新的
  export root，验证完成后由操作者切换外部引用。这样 exporter 永远不递归清理已有、foreign
  或半成品目录，也不需要在 canonical Repository 中保存 export recovery state。
- export root 必须与 canonical Repository、Workspace private state 以及每个 configured
  filesystem publish prefix 双向不重叠；比较使用 endpoint + prefix 展开后的 canonical
  effective filesystem path，不能借不同 `file:` URL spelling 绕过。
- 默认 method 是 copy；这是独立、可修改、可上传的导出。
- hardlink 只在显式 opt-in、同文件系统、受控只读目标下允许。它共享 inode，修改
  export、chmod 后写入或任何同 UID hostile writer 都可能同时破坏 canonical Pool；因此
  hardlink mode 明确退出 hostile-writer/独立完整性承诺，只适用于操作者信任且保持只读的
  disposable tree。SOW 记录 method/manifest 并在完成前复验 digest，但 link count 仍不是
  Repository/package correctness 条件。
- export 不写回 Membership，不产生 Built Generation，不进入 `changes`，不作为
  publish 输入或 GC root；删除它只是删除衍生物。
- 若上传 export，对象存储出现重复 payload 是操作者明确选择的兼容成本，不得
  混入 canonical publish prefix 或 snapshot。
- canonical Pool 中合法的 RPM basename 即使含字面 `:` 或 `%`，exporter 也必须按 managed
  Pool grammar 读取并在 leaf metadata 中 encode-once；不能把宽于普通文件名 helper 的合法
  basename误判为 C2 alias 或拒绝导出。

具体 CLI 名称可在实现规格中冻结；上述 profile、所有权、默认值和完成门不可改变。
默认 EL reposync 必须对 completed RPM export 通过，才可宣称它是 reposync fallback。

## Allowed hardlinks

| 场景 | 允许 | 原因/限制 |
| --- | --- | --- |
| `.sow` 私有 transaction pre-image/recovery | yes | 不上传；用于本地原子恢复 |
| APT by-hash metadata | yes | 小型 immutable index alias，不是 package payload |
| explicit external export | opt-in | 同文件系统、可信只读、非 canonical；退出 hostile-writer 保证 |
| canonical per-Dist/per-arch package alias | no | 上传后成为完整重复对象 |
| per-generation/per-snapshot package alias | no | 保留点数量会放大容量 |
| package correctness 的 `SameFile`/link-count 检查 | no | 文件系统实现细节不能定义协议正确性 |

普通 copy、tar、对象存储 upload 或不支持 hardlink 的文件系统都不得改变 canonical
Repository 的功能正确性。

whole-root handoff 是 SOW/操作者已知 Repository owner 下的受控复制，不等于 reposync 或
第三方工具能从 architecture metadata 自动发现 sibling Pool。handoff 必须绑定一个 settled
Built Generation：先取得读锁/immutable inventory，复制 `pool/` 与 `dists/`，再按 manifest
复验；复制期间不能跟随正在切换的 pointers。

## HTTP and proxy boundary

常见 URL client 会在发送请求前按 RFC relative-reference 规则消解 dot segments；
canonical object key 本身不含 `.`/`..`。但第三方 proxy、WAF、签名 URL 层可能在
规范化顺序或安全策略上不同，因此必须逐目标验证：

- GET、HEAD、Range、Content-Length、ETag/cache semantics；
- href 解析后的 request path 恰好位于同一 publish prefix 的 `pool/`；
- raw encoded dot segment、backslash、double escaping 和越界路径被拒绝；
- public/private ACL 在整个 Repository prefix 一致执行。

若某一目标无法满足，首选 whole-root copy 或 external export；不得自动恢复
canonical hardlink aliases。
