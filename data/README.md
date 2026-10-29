# 本地规则数据

`smartdns/` 是从相邻 SmartDNS 项目导出的本地数据，已加入 Git 忽略规则。
准备方法与数据语义见[规则数据导出说明](../examples/smartdns/README-data.md)。

| 内容 | 用途 |
| --- | --- |
| `smartdns/geosite.dat` | 迁移配置按 `geosite:标签` 加载的域名集合 |
| `smartdns/Country.mmdb` | `geoip:标签` 使用的数据库 |
| `smartdns/ASN.mmdb` | `asn:号码` 和数字 ASN 配置使用的数据库 |
| `smartdns/ips/` | 两组自定义 GitHub CIDR 文本 |
| `smartdns/domains/` | 与 DAT 同份规则的核对文本，供独立等价测试使用 |
| `smartdns/manifest.json` | 输入、输出哈希和各集合数量 |

运行时需要三个数据库及两个自定义 IP 文本；核对测试还需要 `domains/`。
整理项目时保留整个目录，重复导出或测试副本放到 `release/_validation/`。
提交到 Git 的小型示例数据位于 `examples/data/`。
