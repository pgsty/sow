# 验收证据目录

本目录保存可复现命令、环境、原始日志与结果摘要。文件只有在实际命令成功运行后才可作为需求矩阵证据；设计说明、资料调研和 Mock-only 测试不得放宽通过标准。

大仓库 manifest 性能用例通过 `perf` build tag 隔离，默认单测不会意外读取 100GB 级夹具：

```bash
SOW_PERF_ROOT=/Users/vonng/pgsty/repo \
  /usr/bin/time -l go test -tags perf -run TestLargeRepositoryManifest -v ./test/perf
```

运行时应将完整 stdout/stderr、硬件与仓库包数保存为日期化日志，并把实测值回写需求矩阵；测试代码存在本身不算通过。
