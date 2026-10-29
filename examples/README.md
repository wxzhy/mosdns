# 配置示例

从仓库根目录启动；配置中的相对路径以进程工作目录为基准。
以下文件各自独立使用，不能直接拼接全部插件。

| 文件 | 用途 | 配套说明 |
| --- | --- | --- |
| [speedcheck.yaml](speedcheck.yaml) | 不依赖 GeoData 数据库的完整测速流程 | [测速配置](../docs/speedcheck.md) |
| [speedcheck-full.yaml](speedcheck-full.yaml) | 全参数模板，需准备 GeoIP 和 ASN 数据库 | [参数与依赖](../docs/speedcheck.md) |
| [speedcheck-windows.yaml](speedcheck-windows.yaml) | Windows 最小 UDP/TCP 示例 | [Windows 说明](../docs/speedcheck-windows.md) |
| [ip-replace.yaml](ip-replace.yaml) | 不访问公网的地址前缀替换演示 | [IP 替换](../docs/ip-replace.md) |
| [ip-fallback.yaml](ip-fallback.yaml) | 不访问公网的静态回退演示 | [静态回退](../docs/ip-fallback.md) |
| [https-record.yaml](https-record.yaml) | 离线 HTTPS/SVCB 响应处理演示 | [HTTPS 处理](../docs/https-record.md) |
| [smartdns/config.yaml](smartdns/config.yaml) | 原普通网络部署的迁移配置 | [迁移说明](../docs/smartdns-migration.md) |
| [smartdns/config-cernet.yaml](smartdns/config-cernet.yaml) | 原 CERNET 部署的迁移配置 | [规则数据准备](smartdns/README-data.md) |

`data/` 存放示例引用的小型文本规则；SmartDNS 导出的实际数据库位于仓库根目录的
`data/smartdns/`，两者用途不同。两份 SmartDNS 配置保留原私有部署端点，迁移到其他
网络时需按[迁移说明](../docs/smartdns-migration.md)检查参数。

查询所有已启用模块的字段时使用 [全模块模板](../docs/examples/all-modules.yaml)。
