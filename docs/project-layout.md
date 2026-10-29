# 项目文件布局

| 路径 | 用途 |
| --- | --- |
| `main.go`、`go.mod`、`go.sum` | 程序入口和 Go 模块定义 |
| `coremain/` | 配置加载、插件生命周期与服务管理 |
| `pkg/` | DNS 响应、传输、GeoData、测速等通用组件 |
| `plugin/` | 数据提供者、匹配器、执行器及监听服务 |
| `mlog/` | 日志封装 |
| `tools/` | 随二进制编译的 Go CLI 子命令，如 config、probe |
| [scripts/](../scripts/README.md) | Python 维护脚本和 OpenWrt 部署文件 |
| [tests/integration/](../tests/integration/README.md) | 跨模块、示例配置与本机服务的 Go 集成测试 |
| `scripts/tests/` | Python 数据导出测试 |
| [docs/](README.md) | 使用文档、开发说明和有日期的验证记录 |
| [examples/](../examples/README.md) | 可选配置与小型示例规则 |
| [data/](../data/README.md) | 本地导出的实际规则数据库；不随 Git 提交 |
| `release/` | 本地构建包、校验清单和验证归档；不随 Git 提交 |

## 源码与测试

单元测试与被测包放在同一目录。跨模块、示例配置与 UDP/TCP 服务测试集中在
`tests/integration/`，其中 SmartDNS 测试共享同包辅助函数。该测试包显式注册全部插件，
并在独立测试进程中切到仓库根目录，保持示例及数据库的相对路径不变。
Python 数据导出测试位于 `scripts/tests/`；两类测试的范围和命令见
[集成测试说明](../tests/integration/README.md)。

`tools/` 是 Go 源码包，维护脚本统一放在 `scripts/`。

发布入口为 `python scripts/release.py`，从仓库根目录执行；CI 使用同一路径。
它仍向 `release/` 输出发布 ZIP，发布工作流的文件匹配路径保持不变。

## 本地文件

- `data/smartdns/` 保留现用的 GeoSite、GeoIP、ASN、自定义 IP 文本和核对文本，
  不因清理测试产物而删除。
- 根目录 `mosdns.exe` 是本地开发构建，沿用现有启动命令；Linux 对应输出 `mosdns`。
  两者均忽略 Git，不替代带版本记录的发布包。
- `release/20261021-160707/`、`release/low-privilege-service-20261021/` 保留原路径、
  二进制、构建信息与校验文件；这些是历史构建，不自动视为当前源码构建。
- `release/_validation/` 按任务归档源码快照、验证结果、临时交叉构建与日志。
  下划线前缀使 Go 的包枚举跳过历史源码，避免将旧快照混入正常构建与测试。
  本地 `release/README.md` 提供归档导航，整理清单位于
  `release/_validation/project-layout-20261029/organization.json`。
- `.reference/` 保存外部参考源码，`.zcode/` 保存本地工作记录；均保持本地并忽略 Git。
- `__pycache__/`、`.pytest_cache/`、`.ruff_cache/` 和临时编译缓存可重建，不作为交付物。

只在核实哈希一致后清理重复导出。历史配置快照和验证记录保留原始内容，不用当前
配置覆盖，以便区分版本及验证范围。
