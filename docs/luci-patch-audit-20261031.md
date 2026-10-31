# LuCI 上游补丁功能复核（2026-10-31）

## 结论与来源

**30 个补丁均有对应实现，但当前功能不能认定为全部完成。** 225 的分支状态传递是明确的非等价适配；此外，受控探针复现了缓存、统计、规则解析、日志轮转和监听器回收缺陷。多数缺陷已经存在于上游补丁或 mosdns 基础代码中，不能归因为漏移植。

本次重新读取 [sbwml/luci-app-mosdns v5 补丁树](https://github.com/sbwml/luci-app-mosdns/tree/dbdd91ab8ac8b079b6a3ca1a48d99e970d17111b/mosdns/patches)，来源仍为 `dbdd91ab8ac8b079b6a3ca1a48d99e970d17111b`，包含 100 和 203–231，共 30 个补丁。核查对象为本仓库 `559ee0921a2a60119a0b01c1ebf3b8a1c3554582` **及当前未提交修改**，包括此前补齐的 211 查询日志和迁移配置合并。

本轮只复核和记录，不修复生产代码、不改变迁移策略。下文“已实现”表示代码路径和功能入口存在，不表示所有边界均已验证无缺陷。旧的[实现状态说明](luci-patch-status.md)应结合本报告阅读。

## 逐补丁状态

| 补丁 | 当前实现 | 功能结论 |
| --- | --- | --- |
| 100 | 当前 Go 1.27.3、较新依赖及构建版本来源 | 已适配，没有回退到原补丁版本；QUIC 资源所有权仍有缺陷，见 F3。 |
| 203 | 非法 DoH 消息返回 HTTP 400 | 已实现，现有直接回归通过。 |
| 204 | 黑洞地址 Fisher–Yates 洗牌 | 已实现，结合 229 使用请求内副本。 |
| 205 | 格式化日志时间 | 已实现，JSON 模式保留。 |
| 206 | domain/ip/adblock、hosts、arbitrary、redirect 文件轮询与原子替换 | 已实现；解析宽松性和建立监视基线的窗口见兼容边界。 |
| 207 | 注册 adblock_set、ABP/正则规则 | 已实现，但正则锚点被破坏，见 F5。 |
| 208 | hosts 格式及多域名 | 已实现。 |
| 209 | 日志尺寸与备份配置、轮转器 | 已实现，但备份文件识别过宽，见 F9。 |
| 210 | 裸域名、完整匹配及原生规则前缀 | 已实现；原生 regexp 同样受 F5 影响。 |
| 211 | 查询统计元数据、逐查询日志、协议传递 | 当前工作区已补齐；Info/Debug 及五种回环传输的现有回归通过。 |
| 212 | 外部截断后的日志偏移处理 | 已实现；Windows 未验证打开文件被外部 rename 的场景。 |
| 213 | 主动预取、命中计数与指标 | 已实现，并增加有界 worker 和条件写回；仍要求单一固定调用位置。 |
| 214 | continuation 原子发布、空 question、预取去重隔离 | 已实现；不解决既有 lazy 刷新的清空/关闭边界，见 F2。 |
| 215 | 默认 5 MiB、0 备份 | 已实现；默认删除备份使 F9 可达。 |
| 216 | stats_api 注册、环形日志、统计与查询接口 | 已实现，后续补丁的接口及 v1 转储兼容路径存在。 |
| 217 | 拦截域名单独计数 | 已实现；缓存负响应的来源丢失见次级问题。 |
| 218 | 热门列表排除拦截域名 | 已实现。 |
| 219 | gzip v1 转储、加载与定时保存 | 已实现；导入未校验计数间的一致性。 |
| 220 | 规则命中提取、上游地址格式 | 已实现。 |
| 221 | 系统本地时间、历史小时分桶 | 已实现；DST 回拨合并小时，见次级问题。 |
| 222 | 缓存命中率排除拦截分母 | 原公式已移植，但分子未同步排除，见 F6。 |
| 223 | 实时 QPS | 已实现采样循环，但启动和在线恢复存在失真，见次级问题。 |
| 224 | hosts/arbitrary 来源与统计排除 | 已实现；与缓存交叉分类时仍受 F6 影响。 |
| 225 | 获胜分支响应及统计元数据回传 | **部分适配**：marks/KV 不回传，详见兼容边界。 |
| 226 | 合法上游负响应避免误判拦截 | 已实现；本地负拦截缓存后会失去来源。 |
| 227 | fallback 保留 EDNS 响应选项 | 已实现，独立副本及嵌套分支探针确认选项保留。 |
| 228 | 自然超时与上游错误分类 | 已实现，但已有响应后返回错误时与实际返回不一致，见 F8。 |
| 229 | map 清空锁、黑洞并发安全、fallback、默认值及解析修复 | 目标代码均有覆盖；资源回收仍不完整，见 F3/F4。正常插件 Init 初始化默认值，直接 StartServer 调用不同。 |
| 230 | loopback/SVCB 分类、原子转储、清空入口 | 已实现，但无法清除 sequence 内联选择器，见 F7。 |
| 231 | 超时独立计数、平均延迟排除、旧转储兼容 | 已实现；与 228 的状态冲突仍在，见 F8。 |

## 已复现的主要缺陷

以下均为当前源代码的受控复现，优先级为 P2。它们不依赖公网 DNS；其中 Windows 的 socket 结果不能替代目标 Linux 验证。

### F1：持久化缓存恢复后，正常响应 TTL 被压到 1 秒

- 位置：`plugin/executable/cache/cache.go:567–572`、`:636–637`，`plugin/executable/cache/utils.go:147–149`。
- 原因：转储不写 `MsgStoredTime`，恢复却使用该字段；零值被恢复为 1970 年，再按存储时间计算已流逝 TTL。
- 复现：冷响应 TTL=60；恢复时内部剩余有效期仍为 59 秒，但客户端得到 TTL=1，且没有重新请求上游。
- 来源：原 mosdns 基础提交 `28fdfa5` 已存在，213/214 没有修改此段转储逻辑。
- 影响：两份合并配置均启用缓存转储，重启恢复可触发，客户端缓存时间异常缩短。

### F2：lazy 刷新可以越过 Flush/Close 完成边界

- 位置：`plugin/executable/cache/cache.go:267–290`、`:409–419`、`:525`。
- 原因：lazy 后台任务无条件保存响应；Flush 没有代际检查，Close 仅等待预取 worker，没有等待或取消 lazy 任务。
- 复现：门控上游请求期间 Flush，缓存已空；放行请求后该项重新出现。Close 在上游仍阻塞时返回，之后仍发生后台写入。
- 来源：基础代码已有；214 仍保留该保存路径。本仓库新增的预取条件写回只保护预取路径。
- 影响：两份合并配置均启用 `lazy_cache_ttl: 86400`，清缓存和退出时实际可达。

### F3：QUIC 关闭后 UDP socket 仍被占用

- 位置：`plugin/server/quic_server/quic_server.go:61–62`、`:89`、`:112–119`、`:130–133`。
- 原因：插件自行创建 UDP Conn 后传给 Transport，却只保留和关闭 Listener；外部 Conn 需要调用方关闭。Transport 及 socket 的所有权没有保留，失败分支仅调用 Transport.Close 也不足以关闭外部 Conn。
- 复现：QuicServer.Close 返回后，同进程重新绑定相同 UDP 地址失败。
- 依据：固定依赖 quic-go v0.64.1 的 `transport.go` 以及[官方服务器文档](https://github.com/quic-go/docs/blob/master/content/docs/quic/server.md)均表明 Listener 与 Transport 生命周期独立；外部 Conn 另有所有权。
- 来源：HEAD 和 `559ee09^` 已存在，未由当前 211 协议日志改动引入。229 的默认值补丁没有修复该资源路径。

### F4：HTTP TLS 启动失败后，Close 未释放监听器

- 位置：`plugin/server/http_server/http_server.go:66–67`、`:101`、`:113–125`。
- 原因：先建立 TCP listener，再异步 ServeTLS；缺失证书导致 ServeTLS 在 listener 纳入 http.Server 管理前失败，插件只调用 http.Server.Close。
- 复现：等待启动失败信号并关闭插件后，TCP 仍可建立连接。这里仅说明 TCP 握手成功，不表示仍能提供有效 DoH 响应。
- 来源：HEAD 和 `559ee09^` 已存在；不是本轮改动引入。配置 http2 失败后的 listener 释放还存在同类源码路径，未单独注入该错误复现。

### F5：广告规则的正则 `$` 锚点被当作 ABP 选项删除

- 位置：`plugin/data_provider/adblock_set/parser.go:71–75`，早于正则格式识别。
- 复现：`/^ads[.]example$/` 不匹配 `ads.example`；`regexp:^ads[.]example$` 错误匹配 `ads.example.unwanted`。
- 来源：207 引入的选项截断顺序，208/210/229 没有修复。
- 影响：使用相应规则时出现漏拦截或过度匹配；普通域名、hosts 规则不受此案例影响。

### F6：被拦截的缓存命中污染命中率

- 位置：`plugin/executable/stats_api/stats_api.go:1166–1168`、`:756–760`。
- 原因：先累计全部缓存命中，计算比例时仅从分母排除拦截/hosts/arbitrary。
- 复现：一次命中缓存的 `0.0.0.0` 拦截，加一次未命中的正常查询，得到 total=2、blocked=1、cached=1、cached_percentage=100；按接口排除拦截的口径应为 0%。
- 来源：222/224 原实现即存在；现有测试直接写计数，没有覆盖该实际 Exec 交叉路径。

### F7：清缓存接口成功返回，却没有清除内联 prefer_ipv4 状态

- 位置：`coremain/mosdns.go:222–227`，`plugin/executable/sequence/sequence.go:42–53`。
- 原因：FlushAllCaches 只遍历顶层注册插件；内联选择器位于 sequence.anonymousPlugins，Sequence 没有转发 Flush。
- 复现：旧 IPv4 偏好被缓存后，调用 `/plugins/stats_collector/api/v1/cache/clear` 返回 200/success；后续 AAAA 仍被抑制，上游解析次数不变。相同条件的新选择器能返回 AAAA。
- 来源：230 同样存在可达性缺口，Selector.Flush 虽已移植，内联调用方式仍不可达。普通顶层缓存确实会清空，接口并非完全无效。

### F8：实际返回 SERVFAIL，统计环形日志仍显示 NOERROR

- 位置：`plugin/executable/stats_api/stats_api.go:1178–1208`。
- 复现：执行器先设置正常响应，再返回 DeadlineExceeded；实际返回 SERVFAIL，而统计日志保留 NOERROR 和正答案，同时 timeout_queries=1。
- 原因：只有 R()==nil 才优先处理错误；服务入口处理错误时会覆盖已有响应。
- 来源：228/231 原实现的组合缺陷。211 的逐查询服务日志已依据最终发送响应记录，本问题指 stats_api 的查询日志接口。

### F9：日志备份清理可删除并非轮转器生成的文件

- 位置：`mlog/rotator.go:176–194`。
- 原因：仅检查前缀、扩展名和中间字符串长度为 23，没有验证时间戳。
- 复现：在独立临时目录中放置 `app-xxxxxxxxxxxxxxxxxxxxxxx.log` 哨兵文件；app.log 一次轮转且 backups=0 后，哨兵被删除。
- 来源：209 原实现，215 的默认 backups=0 仍沿用；本次未操作任何用户已有日志。
- 影响范围：需要同目录存在恰好满足该名称模式的其他文件；并非任意路径删除。

## 其他已复现的统计问题

| 行为 | 位置（stats_api.go） | 结果与来源 |
| --- | --- | --- |
| 本地 NXDOMAIN 拦截进入缓存后丢失分类 | 1171、1213–1215 | 两次策略拦截仅累计一次 blocked；缓存命中被当作有上游。继承 226 的来源信息不足。 |
| 在线导入历史累计数影响实时 QPS | 1085、1090–1095 | 测试期间 0 次查询，导入 total=1000 后 QPS=500。继承 223。 |
| 启动首条查询可能不计入 QPS | 1085 | 单核调度下查询先于采样协程初始基线，首个采样 QPS=0。继承 223。 |
| v1 转储未验证计数关系 | 964–985 | 合法 gzip/JSON 的 total=1、blocked=10、cached=20、timeout=50 被 HTTP 200 接受。属于 219 的输入完整性边界，格式兼容不等于数据可信。 |
| DST 回拨小时被合并 | 455 | 纽约两个不同偏移的 2026-11-01 01:30 合为一个小时桶。继承 221；Asia/Shanghai 不触发。 |

## 兼容边界与主动适配

1. **225 的 marks/KV 不等价。** `pkg/query_context/context.go:178–199` 明确使 ResponseSnapshot 排除 marks 和任意插件状态；原补丁将获胜分支的新状态合入父级。嵌套 fallback 探针确认 upstream/EDNS 保留、父 mark 保留，但获胜分支新增 mark=42 和 KV 不回传。当前两份迁移配置没有 `type: fallback`，用户所给历史示例的分支也未依赖新增 mark/KV；其他自定义旧配置可能依赖，不能宣称完全兼容。修复前应确定如何在保留分支隔离的同时显式传递允许的状态。
2. **213 的预取仍假设固定调用位置。** `cache.go:221` 只捕获首次 continuation。复现中 B 链保存 192.0.2.2，后续预取执行 A 链并覆盖为 192.0.2.1。这继承上游的使用假设；两份迁移配置均未启用 prefetch，目前不触发。
3. **解析失败和无效行不同。** adblock 解析器跳过无效行；全文件只有 `regexp:[` 时解析整体返回成功，并将旧集合替换为空集合。这符合上游宽松策略，不能将其描述为“所有内容错误均保留旧数据”。I/O/返回错误的重载路径才保留旧数据。
4. **先加载后监视存在窗口。** 构造器先读文件，StartFileWatcher 后记录当前状态；两步间发生的修改可能成为新基线而不触发加载。组件探针确认基线建立前的修改不产生回调；对完整构造流程的发生窗口属于源码推断，尚未作端到端门控复现。
5. **229 默认值入口有差别。** 当前正常插件 Init 会调用 args.init；直接调用部分 StartServer 导出函数时不初始化，区别于补丁内部初始化的方式。生产配置走正常入口，本报告没有据此认定配置默认值失效。

## 复现证据与验证范围

本轮使用 Windows/amd64、Go 1.27.3。现有定向 race 测试通过，但上述诊断仍复现，表明测试覆盖存在缺口。探针退出码 0 表示诊断程序成功完成，**不表示业务断言通过**。

| 证据 | 内容 |
| --- | --- |
| `release/_validation/cache-fallback-audit/probe.go`、`probe-result.json` | 转储 TTL、lazy Flush/Close、首次预取链、fallback 状态；探针使用 -race。 |
| `release/_validation/stats-audit/main.go`、`results.json` | 八类统计/接口案例；探针使用 -race。 |
| `release/_validation/patch-audit-20261031/probe.go`、`probe-1621715166/results.json` | 正则、无效行重载、watcher 窗口、HTTP/QUIC 回收。 |
| `release/_validation/patch-audit-20261031/focused-race.log` | 日志、watcher、provider、sequence/fallback、服务端等现有定向 race 回归。 |
| `release/_validation/upstream-audit-20261031/rotator_probe.go`、`rotator-probe.json` | 完全隔离的备份候选误删除复现。 |
| `release/_validation/upstream-audit-20261031/source-manifest.json` | 当前 HEAD、上游来源、相关源文件 SHA-256。 |

从仓库根目录重放诊断（临时目录和缓存均放在工作区）：

```powershell
$env:TEMP = "$PWD/release/_validation/test-tmp"
$env:TMP = $env:TEMP
$env:GOCACHE = "$PWD/release/_validation/go-build-cache"
New-Item -ItemType Directory -Force $env:TEMP | Out-Null

go run -mod=readonly -race release/_validation/cache-fallback-audit/probe.go
go run -mod=readonly -race release/_validation/stats-audit/main.go
go run -mod=readonly release/_validation/patch-audit-20261031/probe.go
go run -mod=readonly release/_validation/upstream-audit-20261031/rotator_probe.go
```

现有定向测试覆盖 cache、底层 cache、concurrent_map、fallback、query_context、stats_api、coremain，以及 focused-race.log 中列出的 provider/日志/服务端包。此前合并工作的完整 race 检查也通过，记录位于 `release/_validation/profile-merge-20261031/test-race-final.log`；本轮没有把该历史检查冒充重新运行的全量检查。

两份迁移 YAML 的统计、持久化缓存、日志/API 基础功能已经合入，原 GeoData/分流/测速/CDN 策略继续保留。本轮没有改动配置。F1/F2 和统计问题与已启用功能相关，应先补实际路径的回归并修复；随后处理正则、轮转和监听器所有权。225 的兼容差异及多位置预取需要单独确定状态传递约定。当前结果不构成目标 Linux amd64 v2 机器的权限、网络或部署验证。
