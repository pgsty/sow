# 生产 R2/COS 迁移前 inventory 基线（2026-07-12）

## 范围与安全

使用本机既有只读 rclone remote 执行 `ListObjects`/size 汇总；没有 PUT、COPY、DELETE、
purge 或配置输出，未读取/记录凭据。该结果是真实生产 bucket 的迁移前逻辑对象统计，
不是 SOW provider/checkpoint/publish PoC，也不是迁移后的成本结论。

## 可复现命令

```bash
rclone size --json cf:/repo
rclone size --json cos:/repo-1304744452
rclone lsd cf:/repo
rclone lsd cos:/repo-1304744452
rclone size --json cos:/repo-1304744452/pro
rclone size --json cos:/repo-1304744452/apt/pgdg
rclone size --json cos:/repo-1304744452/yum/pgdg
```

## 实测值

| 位置 | 对象数 | 逻辑字节 |
|---|---:|---:|
| R2 `cf:/repo` | 37,000 | 70,638,482,043 |
| COS `cos:/repo-1304744452` | 74,118 | 127,879,910,277 |
| COS `pro/` | 16 | 23,497,439,223 |
| COS `apt/pgdg/` | 21,687 | 13,623,231,720 |
| COS `yum/pgdg/` | 15,977 | 18,312,944,521 |

R2 顶层为 `apt,dba,etc,ext,img,pkg,rpm,src,yum`；COS 还含 `pro`、`tmp`、
`.well-known` 等历史/运营前缀。COS 三个单列前缀合计 55,433,615,464 字节，但这不是
“可直接删除”集合：PGDG 历史和 Pro 离线包属于产品数据，必须先进入 canonical
manifest/CAS/ref、完成客户端与回滚验证，才可讨论物理去重或退役。

## 后续比较合同

迁移后以同一命令保存对象数与逻辑字节，并另取供应商账单/存储类别。只有在确认
canonical 引用、SOW `fsck`、真实 apt/dnf、旧 URL 与双云回滚全部通过后，才能比较
ANTI-02 的“成本不升/约 60GB”假设。当前结果只建立 before 基线，不能把 ANTI-02、
G6 或 POC-06 标为通过。
