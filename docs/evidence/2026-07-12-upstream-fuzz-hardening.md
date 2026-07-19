# 上游 URL 与 Release 解析 fuzz 证据（2026-07-12）

两条 production parser 边界分别独立 fuzz 5 秒：相对 URL 必须保持在原 HTTPS base
内；APT Release checksum path 不能通过编码、dot segment、反斜杠或控制字符逃逸。

```bash
go test ./internal/upstream -run '^$' \
  -fuzz '^FuzzResolveRelativeStaysInsideHTTPSBase$' -fuzztime=5s
go test ./internal/upstream -run '^$' \
  -fuzz '^FuzzReleaseParserNeverAcceptsUnsafeChecksumPath$' -fuzztime=5s
```

```text
FuzzResolveRelativeStaysInsideHTTPSBase:
  execs=641855 new interesting=18 total=275 PASS
FuzzReleaseParserNeverAcceptsUnsafeChecksumPath:
  execs=619044 new interesting=51 total=331 PASS
```

本轮运行使用 18 个 fuzz worker；两个进程分别 6.563/6.038 秒退出 0。该短时门禁补充
固定的恶意路径/重定向/大小边界用例，不等于无限输入空间证明；CI 默认仍运行 seed
corpus，发布审计可重复执行更长 fuzztime。上述 execution 数只是调度相关观察值，不是
通过阈值；通过条件是每个 seed corpus 启动的 5 秒 fuzz 窗口无失败并正常退出。
