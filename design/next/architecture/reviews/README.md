# Architecture review index

本目录保存 `design/next` 的独立评审证据与问题关闭记录。评审文件不是规格权威；若评审
文字与 [`../../specs/SPEC.md`](../../specs/SPEC.md) 或
[`../ARCHITECTURE-SPINE.md`](../ARCHITECTURE-SPINE.md) 冲突，以规格/架构脊柱为准。

## Current gate

本目录的 review 与 closure 是**实现前设计评审快照**。下面保留其当时的
“READY for implementation / NOT READY for release”文字作为审计轨迹；当前实现状态与
外部未验证项以 [`../../evidence/`](../../evidence/) 和 acceptance matrix 为准，不能通过
改写历史 review 来制造当前 PASS。

- [`review-rubric-final.md`](review-rubric-final.md)：需求与架构 gate；当前结论为
  **READY for implementation, NOT READY for release/compatibility claim**。
- [`review-adversarial-final.md`](review-adversarial-final.md)：wire、恢复与跨实现歧义复核；
  final closure 记录最新字节级修订是否关闭剩余发现。
- [`review-reality-final.md`](review-reality-final.md)：源码、PoC、上游行为与 Cloudflare R2
  能力的现实核验。

这里的 “READY for implementation” 只表示当时设计没有已知架构阻塞。当前 0.3 已有
实现与本地测试，但没有 fixture lock、当前 checkout live-client matrix 与真实 target
evidence 时，相应外部 compatibility capability 仍不得标为 PASS。

## Review history

- `review-*.md`：第一轮独立发现，包含当时的 BLOCKED/PARTIAL 状态。
- `review-*-resolution.md`：针对第一轮发现的逐项处置。
- `review-*-final.md`：最终 gate 与 post-review closure。

历史 BLOCKED 文字保留为审计轨迹，不代表当前结论；判断当前状态必须读对应 final 文件
及其 closure，并核对其中绑定的当前文件 hash。
