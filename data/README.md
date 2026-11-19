# 本地规则数据

`smartdns/` 存放本地部署数据和从相邻 SmartDNS 项目导出的旧规则，已加入 Git 忽略规则。
准备方法与数据语义见[规则数据说明](../examples/smartdns/README-data.md)。

| 内容 | 用途 |
| --- | --- |
| `smartdns/geosite-deployment.dat` | 当前示例加载的域名集合，保留 GeoSite 属性和遥测分类 |
| `smartdns/geosite.dat` | 旧 SmartDNS 规则导出，用于迁移核对 |
| `smartdns/Country.mmdb` | `geoip:标签` 使用的数据库 |
| `smartdns/ASN.mmdb` | `asn:号码` 和数字 ASN 配置使用的数据库 |
| `smartdns/ips/` | 两组自定义 GitHub CIDR 文本，已内联进迁移配置，仅供核对 |
| `smartdns/domains/` | 与 DAT 同份规则的核对文本，供独立等价测试使用 |
| `smartdns/manifest.json` | 输入、输出哈希和各集合数量 |

运行当前示例需要部署 GeoSite 和两份 MMDB。旧导出的 `domains/` 和 `ips/` 可供核对。
整理项目时保留整个目录，重复导出或测试副本放到 `release/_validation/`。
提交到 Git 的小型示例数据位于 `examples/data/`。
