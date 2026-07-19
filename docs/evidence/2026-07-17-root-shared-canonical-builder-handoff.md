# 2026-07-17 shared root canonical builder handoff

状态：本地 builder 与 SOW admission 闭合；只读生产源未改变，未访问或写入任何云资源，
生产 URL/cutover/rollback 仍待独立变更窗口。

旧 `copy-bin`/`copy-beta` 对 `/get`、`/pig`、`/pkg`、`/beta` 分别向 CF/COS 发布
不同 `.io/.cc` 正文，不能进入 SOW 的单一 canonical manifest。新的迁移期 external builder：

- 在读取前钉住八个源文件的 size/SHA-256；任一漂移立即失败；
- 解析 output parent 的真实路径，禁止直接或经 symlink 写回 source tree；
- 从一份受版本控制的模板确定性生成四个 standalone Bash asset；
- 正文只允许 `https://repo.pigsty.io` 与 `https://repo.pigsty.cc`，默认 global，
  global 失败自动回退 China；`PIGSTY_REGION=cn` 可反向选择，
  `PIGSTY_REPO_URL` 只接受两个 exact URL，其他 host 在首次下载前退出 64；
- `/pkg` 根据真正成功的 mirror 决定是否向 `bin/get-pkg` 传 `-c`；`/pig` 的
  DEB/RPM 下载使用相同回退合同。

当前生成身份：

| key | bytes | SHA-256 |
|---|---:|---|
| `/beta` | 6,420 | `e5c5f943296cfcc8404953acf8cc1672b10651df22cadaa2dd053a7a36bd5bb6` |
| `/get` | 6,419 | `a4a3fad30eaaf6e2d52ed7c00238eb29d3188f6ae86b47153b69de27dadb418a` |
| `/pig` | 6,419 | `6be17b2f2cc250340abb0b8d89f417dba3fe216396af376a42076e6be3b1dc48` |
| `/pkg` | 6,419 | `3e8b05521783c4adf1afac1be2b67c7ea09f0e800a423bcb6e0841033f061580` |

`TestPigstyRootBothBuilderHandoff` 在两个独立目录生成并逐字节比较输出，用 fake curl
执行 global→China fallback、China-first、`get-pkg -c`、DEB install 和非法 host 零下载负例，
然后通过真实 `cli.Main` 完成 `init`、四次 digest-bound `add`、`promote`、working-tree
hardlink `materialize`、exact-root Nginx include、L1、`fsck`、GC dry-run 与幂等重放。
普通/race 包运行分别为 10.500s/11.574s，均输出：

```text
root_both_handoff files=4 bytes=25677 source_read_only=true cloud=false
PASS
```

八个 `/Users/vonng/pgsty/repo/bin/{get,pig,pkg,beta}.{io,cc}` 文件在测试前后 inode、
mtime、size 与正文一致。迁移 fixture 因此把 `asset-root-both` 从 inactive inventory boundary
推进为 active、`publish_targets: [cf,cos]` 的 local-cutover-pending owner；这不表示已向任何
bucket 上传，也不替代真实 `.io/.cc` URL 回归。

可复现命令：

```text
SOW_RUN_PIGSTY_ROOT_BOTH_HANDOFF=1 \
SOW_PIGSTY_REPO_ROOT=/Users/vonng/pgsty/repo \
go test [-race] ./test/compat -run '^TestPigstyRootBothBuilderHandoff$' -count=1 -v
```
