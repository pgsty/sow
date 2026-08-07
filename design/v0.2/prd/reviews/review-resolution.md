# PRD High-Priority Resolution Verification — sow V2 阶段一

> **历史 v0.2 复核。** 这里的 PASS 只说明当时的 PRD 问题已关闭，不代表
> C2 是前向方案；新设计见 [`../../../next/`](../../../next/)。

## Verdict

**PASS。** 上轮五个 high 均已充分关闭；本轮定向扫描未发现新增 critical/high。此结论只复核 high-priority resolution，不重新评级上一轮 medium/low 项。

## Verified snapshot

- `prd.md`: `c7184f7233bfc74e365c4ebe721ad4a9031c919d8f0ea6447ab392f0a1078165`
- `api-contract.md`: `77ae3acb6e493da32f6ea9008c9ff9dd74638de2f930849b7d70056160358caa`
- `addendum.md`: `f4c8cfba176714c87e72fd0731e57cd55f753bb9c4f45ba30529798fcb37fa59`

## Resolution status

| 上轮 high | 状态 | 关闭证据 |
| --- | --- | --- |
| RPM 签名与重复 `add` 幂等冲突 | **RESOLVED** | API §9.1–9.2、§10.1 定义 signature-neutral payload digest、查询优先于签名、按当前 `never/fill/always` 策略复用既有最终对象，并对不能复用的同坐标输入硬冲突；PRD FR-7 与附录 §4.3 一致。跨时间重签不再产生伪冲突。 |
| Managed metadata 签名缺少配置/产物契约 | **RESOLVED** | API §11.3 与 §13 分离 package/metadata key，明确 RPM `repomd.xml.asc`、DEB `Release`/`InRelease`/`Release.gpg`、无 key 行为、key/fingerprint dirty 规则、config/check 责任及 secret redaction；PRD FR-12 与附录 §4.4 对齐。 |
| `exclude/kind` 语义不可唯一验收 | **RESOLVED** | API §9.4 封闭字段、rule/field/pattern 的 AND/OR、大小写、shell glob、非法配置行为、canonical arch、RPM/DEB kind 后缀枚举、求值顺序与 golden-test 输出；PRD FR-8 和附录 §5.3 对齐。 |
| YUM 相对 Pool PoC 晚于布局冻结 | **RESOLVED** | PRD P1、API §2.3、附录 §3.3 均把真实 DNF/YUM makecache/install 与 reposync PoC 设为 layout/schema/renderer 冻结前 gate，失败必须回到布局决策且不得偷换绝对 URL。 |
| `--pigsty` DEB 3.0.4 判定与破坏性恢复不明确 | **RESOLVED** | PRD FR-2/P0、API §5.1、附录 §2.1–2.2 明确 RPM VERSION 与 DEB upstream version 的 epoch/revision 处理、`3.0.4+foo` 反例、recovery trash、marker/pointer/package rename 顺序及逐点 crash injection。 |

## Unclosed critical/high

无。
