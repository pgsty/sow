# ADR-0023：Admission-bound Git 对象内容完整性

- 状态：Accepted
- 日期：2026-07-15
- 决策范围：FR-01、FR-06、NFR-02、NFR-08

## 背景

canonical state 的 HEAD/ref 名称正确，不等于其 Git object bytes 正确。go-git v5.19.1
filesystem storer 会按请求 hash 定位 loose object，但小对象不会比较 payload 计算出的 object ID
与请求 hash；大对象的 lazy reader 也只复核 header type/size。默认 object LRU 还会让 session
末尾的重复读取命中旧 MemoryObject，从而遮蔽 loose object 原位变化。

因此，仅绑定 `.git` 的目录能力、固定 HEAD/direct refs 与拒绝 symlink，仍不能证明 commit、tree、
blob 是 ref 所命名的内容。

## 决策

本决策只适用于 `OpenBoundRepository` 创建的 admission-bound 只读 reader；普通本地 writer
仍使用 go-git 的标准 storage。

1. capability-bound storage 禁用 object cache。每次对象请求都以请求 hash 为预期身份，流式校验
   object type、声明 size、精确 payload 长度及 `type + size + payload` Git hash。
2. loose object 额外从保留的 `.git` root 读取原始 header，避免小对象 MemoryObject 将伪造的
   声明 size 归一成实际长度。pack object 通过解码后的同一流式 hash 校验。
3. 每个成功访问的 commit/tree/blob 身份进入 session 访问集。返回给 go-git 的 Reader 再校验
   实际消费流；lazy 大对象在首次校验后被原位改写、提前 Close、读取错误或 Close 错误都会永久
   poison 当前 session。
4. `VerifyReadSnapshot` 在 HEAD/direct-ref vector 复核后，通过无缓存底层重新流式校验完整访问集。
   一旦发现失败，即使对象随后恢复原字节，该 session 也不得重新变为可信。
5. session 首次读取 packed object 时流式绑定 `objects/pack/*.idx` 名称与内容摘要，并在 final
   rehash 前后复核。这样 go-git 已解码并缓存 index 后的同路径 `.idx` 改写也不能被隐藏；相关
   `.pack` payload 仍按实际访问对象逐个复算 Git hash，不扫描未访问的 pack payload。
6. 会返回未包装 storer 的 submodule、object iterator 及可选 loose/packed/delta 接口在此 reader
   上失败关闭。canonical SOW state 不使用 Git submodule 或全对象枚举。

## 结果与权衡

- 对象体校验内存保持 O(1)：按流传输且不缓存大 blob；仅保留 O(实际访问对象数) 的
  hash/type/size 小身份集。packed object session 另保留 O(pack 数) 的 index 摘要；`.idx` 内容
  在首次绑定和 final 前后以 O(1) 流式内存读取，但不读取未访问的 `.pack` payload。
- 代价是对象读放大：首次 admission、实际 decoder/consumer read 与 final rehash 最多各读取一次。
  这是 canonical control-plane 数据的完整性成本，不扩展为仓库包体或整个 Git object database 的 fsck。
- reader 保持零写、Linux/macOS 单 Go runtime；不依赖外部 git 或其他程序。
- 验证只使用本地临时仓库和离线测试。任何情况下不得以 CO/COS/Cloudflare 生产仓库或其它云资源
  作为本契约的测试目标。
