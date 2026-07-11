# sow

`sow` 是 Pigsty 制品仓库的 Git 式管理器。产品正依据冻结的 PRD 与架构合同持续实现；CLI 只暴露已有真实实现的命令，不用占位命令伪装完整度。

当前可执行命令面：

```bash
go build ./cmd/sow
./sow help
./sow init --config sow.yaml
./sow fsck --config sow.yaml
```

`init` 只扫描 `sow.yaml` 声明的仓库路径，在遮蔽的 `.sow/` 控制目录中写入确定性排序 manifest，并用内嵌 Go Git 实现提交历史；现有发布文件不会被修改。`fsck` 独立重扫相同路径，发现新增、删除或内容变化时以退出码 4 失败。

配置合同为 `schema: sow/v1`，可从 [sow.example.yaml](sow.example.yaml) 开始。秘密字段只接受 `env://NAME` 或明确支持的安全 provider 引用。持续执行账本见 [需求可追踪矩阵](docs/requirements-traceability.md)；设计文档或单层单测通过不等于产品验收完成。
