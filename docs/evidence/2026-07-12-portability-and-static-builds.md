# Linux/macOS 单二进制构建证据（2026-07-12）

## 结论

同一源码在 `CGO_ENABLED=0` 下成功生成 Darwin/Linux × amd64/arm64 四个
`sow` 可执行文件。Linux 产物由 `file(1)` 确认为 statically linked；生产
代码不包含 `os/exec`，运行时不需要 Python、Perl、gpg、createrepo_c 或 aptly。
这证明构建与依赖边界；它不替代每个目标 OS 上的启动烟测，也不替代真实云 PoC。

## 环境与复现

```text
go version go1.26.5 darwin/arm64
Darwin 25.5.0 arm64
```

```bash
for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do
  GOOS=${target%/*} GOARCH=${target#*/} CGO_ENABLED=0 \
    go build -trimpath -o /tmp/sow-${target%/*}-${target#*/} ./cmd/sow
done
```

本轮实际执行上述四个构建，全部退出码为 0。产物判型：

```text
/tmp/sow-darwin-amd64: Mach-O 64-bit executable x86_64
/tmp/sow-darwin-arm64: Mach-O 64-bit executable arm64
/tmp/sow-linux-amd64:  ELF 64-bit LSB executable, x86-64, statically linked
/tmp/sow-linux-arm64:  ELF 64-bit LSB executable, ARM aarch64, statically linked
```

大小和 SHA-256（只标识当次产物，不作为发布校验和）：

```text
28095984  67163d534fed416c9abcc93e92644124d693700ddba185d5a3621505f274af80  darwin/amd64
26281746  b22f99388b07d3c30bb4edc614eeeed129362cea6e1dd52335c416f46179644e  darwin/arm64
27535422  b7303da18a06606319c9056e0430c0cc9f1d8608b66a72d1097c7e811dd015a7  linux/amd64
25515216  55766abdef99c0ca354692e82be8ad96cca6a24dfba1726a21ecd493acc4ded2  linux/arm64
```

该次构建绑定 Git 基线 `84800a60e01aaaf8dc5b189c3ddb1380930f4865` 与未提交
product-source 集合（320 文件）摘要
`667ad529751a9a975944fa51dbcd52e30e36b40d19a5203c9a4d084ddeeae5b6`；证据文档
本身不在该摘要集合内。

CI 在 `.github/workflows/ci.yml` 的 `Cross-build static CLI` 门禁中重复同一矩阵；
本地构建后另执行 `go vet ./...`，退出码为 0。
