# SmartDNS 数据迁移

在 mosdns 项目根目录执行，复用 smartdns-test 已有 Python 环境：

```powershell
& ..\smartdns-test\.venv\Scripts\python.exe scripts/migrate_smartdns_data.py `
  --source ..\smartdns-test --output data/smartdns
```

Linux 的对应命令：

```sh
../smartdns-test/.venv/bin/python scripts/migrate_smartdns_data.py \
  --source ../smartdns-test --output data/smartdns
```

输出包含两份配置共用的 `geosite.dat`（19 个命名集合）、两个
`ips/<tag>.txt`、`Country.mmdb`、`ASN.mmdb` 和 SHA-256 清单
`manifest.json`，另保留 `domains/<tag>.txt` 供核对。两份配置都以 mosdns
启动时的工作目录解析 `data/smartdns` 路径。部署可复制整个目录；运行只需要
三个数据库和两个 IP 文本，不依赖 `domains` 文本或 Python。生成的数据无需加入 Git。

| SmartDNS 数据 | mosdns 数据与用途 |
|---|---|
| `tags/output/geosite.trie` | 默认转换成保留后缀语义的 `geosite.dat`，直接使用 `geosite:cn` 等集合名称；同份规则另导出为文本供核对 |
| `tags/geoip/github.txt`、`github-raw.txt` | 规范化 CIDR，供 `ip_set.files` 加载 |
| `tags/output/geoip.metadb` | 原样复制为 `Country.mmdb`；顶层 `geodata.geoip` 指定后使用 `geoip:标签`，保留国家和 CDN 多标签 |
| `tags/output/asn.mmdb` | 原样复制为 `ASN.mmdb`；顶层 `geodata.asn` 指定后使用 `asn:号码` |
| `tags/output/geoip.radix` | 不直接加载。它是 Python pickle，两个自定义集合用原始文本迁移 |

数据库路径在 YAML 顶层集中声明，路由和动作直接引用名称，不再为每个域名集合
建立 `domain_set` 插件。两个 GitHub 集合是自定义精确 IP 段，继续使用文件；用较宽的
MMDB 标签或 ASN 替代会扩大匹配范围。

```yaml
geodata:
  geosite: ./data/smartdns/geosite.dat
  geoip: ./data/smartdns/Country.mmdb
  asn: ./data/smartdns/ASN.mmdb
# 匹配示例：qname geosite:cn geosite:apple-cn
# IP 表达式示例：geoip:cloudflare、asn:33191
```

## 域名匹配语义

默认 `--domain-mode runtime` 迁移**旧程序当前加载的 trie**。它保留完整标签
成员关系，包括 GeoSite 属性生成的全局标签和自定义文件；不会根据更新过的
原始文本悄悄改变运行结果。旧版 `utils/convert.py` 已把 GeoSite 的
`full`、`plain`、`domain` 都转换成域名后缀，并丢弃正则。trie 已经没有这些
类型信息，导出时无法无损恢复；本模式有意沿用已生效行为。打包进 `geosite.dat`
只改变存储形式，仍使用 `domain` 类型；不能直接复制原始 dat 替代本次导出。

若希望保留原始 GeoSite 类型，使用：

```powershell
& ..\smartdns-test\.venv\Scripts\python.exe scripts/migrate_smartdns_data.py `
  --source ..\smartdns-test --output data/smartdns --domain-mode typed
```

`typed` 从 `tags/geosite.dat` 读取 protobuf，使用原项目已安装的生成类和
betterproto2，不引入新的解析依赖。映射为 `full:`、`domain:`、`regexp:`、
`keyword:`，属性键继续形成标签。GeoSite 的 include 已在上游编译为 dat 时
展开，因此保留其展开后的成员关系。自定义 `tags/geosite/*.txt` 可使用裸域名
或四种显式类型，支持 `@属性`；尚未编译的 `include:` 指令会报错，需要先用
上游数据编译工具展开，不能当成普通域名加载。

`typed` 是规则语义变更，会减少 full 匹配范围，并启用旧 trie 丢弃的正则和
keyword；不要把它与 runtime 数据混用。Go 的正则使用 RE2；不兼容的表达式会在
mosdns 加载配置时明确报错。

`--domain-tag` 和 `--ip-tag` 可重复提供，用于覆盖默认导出标签；标签不存在、
IP 非法、MMDB 缺失均会失败。目标域名标签不能含 `@`，因为 `geosite:` 将它解释为
属性分隔符。导出稳定排序并去重，已有同名文件会更新；不再使用的旧文件不会自动删除。
`manifest.json` 记录本次输入哈希、输出哈希和规则数量，以及 GeoSite 各集合数量，
用于部署核对。脚本拒绝把输出写进原 smartdns-test 目录，不修改其输入数据。
