# ADR-0007：Pro/OSS 合一仓库取代独立 Pro bucket

- 状态：Accepted
- 日期：2026-07-12
- 决策范围：FR-33、FR-35–FR-40、NFR-07、MIG-07

## 背景

2026-07-10 的 `pigsty-pro-repo-design-20260710.md` 建议每云拆出独立 Pro bucket，
再以 rclone 从社区仓库晋升。随后冻结的 SOW PRD、Addendum 与 Brainstorm 已明确推翻
该拓扑：重复物理仓库会重新引入追加同步、裁剪导出、双份漂移和额外存储，而且无法
利用 manifest 视图表达 OSS/Pro 的共同来源。

## 决策

1. 每个云目标只有一个 SOW 管理的物理 repository bucket；Cloudflare/R2 与
   EdgeOne/COS 仍是两个独立发布目标，可各自滞后，但每个目标内不再拆社区/Pro 桶。
2. beta/latest/stable/snapshot 是同一 canonical manifest/CAS 的视图和 ref。公开闭包只能
   引用 public pool；需要保密的制品进入 gated pool，并且只能经冻结的
   `/pro/v1/{token}/` 或 `/pro/v1/basic/` 边缘路径访问。
3. OSS/Pro 差异由元数据闭包、debuginfo 维度和 entitlement 决定；禁止恢复
   “社区 bucket → Pro bucket”的 rclone 晋升、裁剪导出或隐式双写。
4. 两云各自的远端 checkpoint、generation、purge 和验证仍独立。合一是单个云内的
   物理布局决策，不把 R2 与 COS 抽象成一个共同故障域。

## 结果

- 原 Pro 报告中“独立 bucket”“双云双 bucket + rclone 晋升”的结论只保留为历史调研，
  不再是实施输入；原文件顶部已写入 superseded 标记。
- `sow.yaml` 每个 target 只声明一个 bucket；公开与商业访问共享不可变包体，但使用不同
  元数据/边缘命名空间和不可绕过的机密性门禁。
- “预计每云节省约 60GB”仍是 PRD 假设，必须用真实迁移前后 inventory/账单测量；本 ADR
  不把该数值伪报为已验证。
