# LuCI 补丁实现核查与迁移配置合并

> 2026-10-31 的[逐补丁功能复核](luci-patch-audit-20261031.md)是修复前的历史快照，不代表后续工作区修改仍保留相同缺陷。225 后续已补齐获胜分支 marks 并集与 KV 同键覆盖，且只对 fallback 启用该语义。

本次核查基于本仓库 `559ee09` 及工作区修改，对照
[sbwml/luci-app-mosdns v5 补丁目录](https://github.com/sbwml/luci-app-mosdns/tree/dbdd91ab8ac8b079b6a3ca1a48d99e970d17111b/mosdns/patches)，
固定来源提交为 `dbdd91ab8ac8b079b6a3ca1a48d99e970d17111b`。

## 实现状态

| 补丁 | 当前实现与核查结果 |
|---|---|
| 100 依赖更新 | 使用当前 `go.mod` 的较新依赖与 Go 1.27.3；没有回退到原补丁锁定的版本。 |
| 203 HTTP 非法请求 | 已有显式 HTTP 400 响应，直接回归覆盖错误请求。 |
| 204 黑洞地址洗牌 | 已有请求内地址副本和洗牌，结合 229 避免修改共享配置。 |
| 205、209、212、215 日志 | 已有格式化时间、文件轮转、外部截断保护，默认 5 MiB、0 备份；补充尺寸乘法溢出拒绝及合法备份时间戳校验，避免清理无关文件。 |
| 206 文本规则重载 | 已有文件轮询及 matcher 原子切换，覆盖 domain/ip/adblock 集合、redirect、hosts 和 arbitrary。返回加载错误时保留有效旧数据，关闭等待回调结束；解析器跳过无效行并不属于返回错误。另有建立监视基线的窗口，见功能复核。GeoData 数据库仍按其加载缓存语义处理。 |
| 207、208、210 广告规则 | 已有实际 `adblock_set` provider，支持原补丁的 ABP、hosts、多域名、例外和裸域名/完整匹配语义，含 229 的解析修复；已修复原生正则末尾 `$` 锚点误删。 |
| 211 查询日志 | 核查时仅统计元数据完整，逐查询日志入口和协议传递缺失。本次补齐 UDP/TCP/DoT/DoH/DoQ 协议、Info 单次查询日志、Debug 规则明细、上游/缓存/答案/耗时等字段。日志级别按实例判断，避免跨实例全局级别耦合。 |
| 213、214 缓存预取 | 已有命中计数、后台预取和加载恢复；另含有界并发、去重、刷新前复查及条件写回。已补缓存转储存储时间、旧转储 TTL 兼容恢复及 lazy 刷新与 Flush/Close 的代际和取消保护；预取首次捕获 continuation 的多调用位置限制仍存在，默认不启用预取。 |
| 216–224、226、228、230、231 统计 | 已有历史 API 与短路径别名、环形日志、热门与历史、QPS、v1 gzip 转储，以及缓存分母、hosts/arbitrary、超时、合法负响应和 loopback 分类。已修正被拦截请求的缓存命中率计数、执行错误时 SERVFAIL 的日志状态及内联插件 Flush 可达性；历史导入影响 QPS 等次级问题见复核记录。 |
| 225、227 fallback 元数据 | `ResponseSnapshot` 现在同时持有独立复制的 marks/KV；`CommitResponse` 可显式使用 `CommitMerge`（marks 并集、KV 同键覆盖）或 `CommitReplace`（marks/KV 全量替换，包括删除）。fallback 采用 `CommitMerge`，落败或失败分支不提交状态；其他调用未指定模式时保持原有仅响应提交和父状态隔离语义。保留获胜分支 EDNS、有效期和统计元数据及 always_standby 竞态修复。 |
| 229 并发与默认值 | 已有 concurrent_map 清空修复、黑洞并发安全、正常插件入口的监听器默认超时及相关解析修复；日志 JSON 模式保持 JSON 输出。已补充 HTTP/QUIC 的失败路径及关闭时的监听器资源回收；Linux 实机端口释放仍需部署验证。 |

## 合并范围

合并至 [普通配置](../examples/smartdns/config.yaml) 和
[CERNET 配置](../examples/smartdns/config-cernet.yaml) 的内容为：

1. `log.level: info`、`log.file: /var/log/mosdns.log`、API `0.0.0.0:9091`、空 include。
2. `stats_collector`：capacity 2000、600 秒转储，在 `main` 缓存之前执行一次。
3. 复用 `response_cache`：size 20000、lazy 保留期 86400 秒、600 秒转储。
4. 普通配置使用 `stats.dump`、`cache.dump`；CERNET 使用 `stats-cernet.dump`、`cache-cernet.dump`，均在 `/etc/mosdns/`。

没有合入示例中另一套国内/国外上游和 fallback 路由。GeoData 名称、全部候选、测速、
CDN 改写、过滤、HTTPS 策略和原监听器保留。原 SmartDNS 源文件已变化，因此本次从
已有迁移 YAML 合并，并保留原来源 SHA-256；完整策略图摘要回归防止无意改变解析策略。

生成器的 `--merge-existing` 模式不读取相邻源配置，重复合并结果相同。默认完整迁移模式
仍会读取指定源文件，并自动合入相同基础功能，详见[迁移说明](smartdns-migration.md)。

## 验证入口与边界

本次已通过完整 `go test -race -p 4 -mod=readonly ./... -count=1 -timeout=180s`、
14 项 Python 检查，以及启用真实 GeoData 的 `TestSmartdns` race 检查。首次全测遇到
Windows 上 UDP 自动分配端口不能用于 TCP 的测试夹具问题；修正为先保留 TCP 监听、
仅对绑定限制有界重试后，重新完成全量检查，未跳过测试或改变系统端口设置。

合并回归还实际验证 TTL=2 秒到期后返回 TTL=5 的旧缓存，后台重新解析/测速不增加
客户端计数，后续命中刷新结果不重复解析。普通/CERNET 两份配置分别验证统计与缓存重启恢复。

- `scripts/tests/test_migrate_smartdns_configs.py`：完整旧策略图摘要、合并幂等、CLI 来源记录及冲突标签。
- `tests/integration/merged_profile_test.go`：两份配置的主查询/辅助查询统计边界、完整 HTTPS 后处理、缓存和重启恢复。
- `tests/integration/luci_config_test.go`、`legacy_config_test.go`：历史完整 JSON/YAML、广告规则、UDP/TCP、旧统计 API 与转储。
- `pkg/query_context/query_log_test.go`、`pkg/server_handler/query_log_test.go`、`pkg/server/query_meta_test.go`：查询日志字段、各实例级别及真实回环传输协议。
- `mlog/rotator_test.go`、各插件 reload/prefetch 并发测试：日志轮转、重载和后台刷新。

本机测试使用回环服务、受控 DNS/探测 I/O 和工作区临时转储目录；真实 GeoData 检查需要
设置 `MOSDNS_SMARTDNS_LOCAL_DATA=1`。这些检查不代替目标 Linux 的网络、权限和服务部署验证。
示例中的日志与转储路径用于直接运行；低权限 systemd 服务的可写路径见[迁移说明](smartdns-migration.md)。
