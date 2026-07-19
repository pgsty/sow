# ADR-0005：旧 Make 目标的处置边界

- 状态：Accepted
- 日期：2026-07-12
- 决策范围：G5、FR-05、FR-17、FR-25、FR-35–FR-42、NFR-04

## 背景

四个旧 Makefile 实际暴露 176 个普通 target，可归并为 44 个操作族。它们混合了仓库
业务、笛卡尔积别名、容器生命周期、造包/收集、无状态文件传输、秘密分发和违反 FR-17
的 RPM 原地重签。如果只给“约 40 个目标”贴一个总标签，会同时产生漏项和范围偷渡。

## 决策

1. `docs/migration/make-target-map.md` 的四张逐目标表是
   `sow-legacy-target-map/v1`。每行只能使用 `sow-cli`、`retire`、`policy-reject`、
   `external-handoff`、`migration-only` 五种机器处置；处置闭合与生产验证状态严格分离。
2. SOW 只承接仓库状态机职责：init/adopt、add/rm、sync、promote、materialize、publish、
   verify/fsck/gc。旧 alias/wrapper 由动词 × repo/OS/arch/view/target 选择器替代，不复制
   Make target 名。
3. `copy-auth` 不再把 `fileauth.txt` 当公开或 gated asset。token/Basic entitlement 数据由
   边缘运行环境的 secret/provider 注入，SOW 配置只保存非秘密 provider 引用。
4. `ext-list`、旧 MD5 `checksums` 如仍是外部 URL 合同，由文档/制品 builder 生成普通文件
   后以 `sow add --expected-object sha256:<digest>:<size>` 交接；SOW manifest 的正典
   摘要仍为 SHA-256，不引入通用派生文件生成器。
5. `parade`、`get-d13`、`get-d13a` 和 Docker/造包收集属于 external builder；handoff
   边界是已经构建并签名、由 builder 声明精确 SHA-256/size 的 DEB/RPM 路径。
   SOW 对每个 positional input 逐一验证该声明后才走普通 add/CAS/index 路径；不造包、
   不管理构建容器。
6. `sv` 的 push/pull 不是 PRD 冻结的 cf/cos 发布目标。长期无状态 rsync 被退役；一次性
   迁移只能先下载到隔离目录，再用 `sow init --adopt-content` 纳管。任何 `--delete` 不得
   冒充 publish/rollback。
7. reprepro list/stash、createrepo/modulemd、任意 container shell/exec 和镜像 RPM 原地
   重签均退役或 policy-reject。未来商业全量重签仍必须按 FR-17 的独立前置条件重开决策。
8. 旧 `copy-bin`/`copy-beta` 对 CF/COS 同一 key 发布不同 `.io/.cc` 正文，不能映射成
   “同一 `sow publish` 发布两端”。SOW 的单一 canonical view 要求同一 ref/key 正文一致；
   外部 asset builder 必须先生成一份可按 Host 自适应的 canonical 正文，或另立产品契约。
   当前 builder 已钉住八个源文件并生成四份 mirror-aware canonical 正文，通过
   digest-bound SOW handoff；真实双 target URL/cutover 回归前仍保留生产迁移门禁。
   APT `ls-*` 和 Docker `status/ps` 也明确退役，不以 L1/fsck 冒充列表输出或容器诊断。

## 结果

- 审核脚本固定旧源 SHA-256，精确枚举 176 行，校验处置、回滚码、当前 CLI flag 和闭合
  enum，并只在全部通过后输出 177 行（含 header）的规范化 TSV；旧 recipe 内容变化但
  target 名不变也会 fail closed。它不证明命令级业务等价，后者仍需逐操作 E2E。
- 机器映射通过不代表 G5 通过。digest-bound handoff 机制的本地 E2E 也不代表真实
  builder/canonical 正文已经交付；真实旧树切换、权限撤销、公开 URL、
  apt/dnf 和双云/CDN 回滚仍由 runbook 的独立生产门禁控制。
- 若未来要把 `sv` 或其他供应商加入正式目标，必须扩展 PRD/配置/provider/checkpoint/
  purge/verify 契约；不得把旧 rsync target 直接改名为 SOW 命令。
