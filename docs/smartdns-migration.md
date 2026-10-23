# SmartDNS 两份部署配置迁移

已迁移相邻 `smartdns-test` 的 `config.yaml`、`config-cernet.yaml`：

- [普通网络配置](../examples/smartdns/config.yaml)
- [CERNET 配置](../examples/smartdns/config-cernet.yaml)
- [规则数据导出说明](../examples/smartdns/README-data.md)

两份 YAML 独立使用，均监听 UDP/TCP `[::]:5335`，不能同时在同一端口启动。
保留原部署的上游 URL、个人解析配置标识、代理地址和 `insecure_skip_verify`
选择；这些不是通用公共上游示例，分享或用于其他网络前应检查并调整。
CERNET 的代理 IPv6 `2001:db8::64` 仍是原配置的占位地址。

## 准备与启动

以下命令在 mosdns 仓库根目录执行。复用旧项目现有 Python 环境，运行时不依赖 Python。

```powershell
# 导出已生效域名集合的 GeoSite 数据库、两个自定义 IP 文本和两份 MMDB。
& ..\smartdns-test\.venv\Scripts\python.exe scripts/migrate_smartdns_data.py `
  --source ..\smartdns-test --output data/smartdns

# YAML 已随项目提供；需要根据旧配置重新生成时运行：
& ..\smartdns-test\.venv\Scripts\python.exe scripts/migrate_smartdns_configs.py

go build -o mosdns.exe .
.\mosdns.exe start -c examples/smartdns/config.yaml
# CERNET 环境改为：
# .\mosdns.exe start -c examples/smartdns/config-cernet.yaml
```

Linux/OpenWrt 部署时复制所选 YAML、`data/smartdns` 和对应平台的 mosdns。
仍从包含 `data` 的工作目录启动，例如 `./mosdns start -c config.yaml`。
规则路径相对于启动工作目录，不相对于 YAML 所在目录。

两份配置已统一数据库路径，路由和动作以 GeoData 集合名称引用规则：

```yaml
geodata:
  geosite: ./data/smartdns/geosite.dat
  geoip: ./data/smartdns/Country.mmdb
  asn: ./data/smartdns/ASN.mmdb
# 域名直接写 qname geosite:cn geosite:apple-cn，无需中间 domain_set 插件。
# IP 集合、过滤、替换、测速标签使用 geoip:cloudflare、asn:33191。
```

19 组域名都从本次导出的 `geosite.dat` 按名称加载；六组 MMDB 标签与两组 ASN
也使用名称。仅 GitHub、GitHub raw 两组自定义 IP 段保留文件引用，避免用更宽的
标签扩大匹配范围。域名数据库由旧程序实际加载的 runtime 规则打包，保持原后缀
匹配结果；直接复制旧项目的原始 `tags/geosite.dat` 会改变 full/domain/regexp
语义。导出的域名文本仅供核对，运行不再依赖它们。

关键处理链的注释随配置生成器一起维护，重新生成 YAML 也会保留。两份配置分别
省去 19 个域名集合中间插件，路由、过滤、替换与动作顺序保持不变。

测速保留旧配置的 **仅 ICMP**：`probe.tcp_ports: []`、`icmp: true`、超时 300ms。
Windows 需使用允许 raw ICMP 的权限运行；Linux 优先使用非特权接口，必要时
使用允许 raw ICMP 的权限。仅 ICMP 且能力不可用时启动报错。若希望降低权限要求，
将三个 `select_cn/global/default` 的 `probe` 一致改为：

```yaml
probe:
  tcp_ports: [80, 443]
  icmp: false
  timeout: 300ms
```

这会改用 TCP 建连 RTT，选址结果可能与原 ICMP 不同。也可同时启用两种方法。
监听 `[::]` 的 IPv4 可达性取决于系统双栈设置；只开放本机时改为
`127.0.0.1:5335`，需要独立 IPv4/IPv6 监听时增加对应 server 实例。

## 路由与处理顺序

路由只按原请求名匹配，按下表优先级首次命中。CNAME 参与后续动作的允许/排除条件，
不会触发重新分流。合法 NXDOMAIN 保留，不继续落入下一条路由。

| 优先级 | 原规则 | 迁移处理 |
|---|---|---|
| 1 | ads/category-ads/category-ads-all | A→127.0.0.1、AAAA→::1，TTL 86400；其他类型 NOERROR 空答 |
| 2 | proxy，限 A/AAAA | 原配置中的静态代理地址，TTL 86400 |
| 3 | google-cn | 原 Google UDP 上游，ECS `240b:4001:23c::/48`，随后 HTTPS 策略 |
| 4 | cn/google-cn/apple-cn | `select_cn`，随后 HTTPS 策略 |
| 5 | google/gfw | `select_global`，Google 静态 IPv6 回退，随后 HTTPS 策略 |
| 6 | tld-opennic | 原 OpenNIC TCP 上游，保留完整响应，不额外测速或改写 HTTPS |
| 7 | default | `select_default`，Google 静态 IPv6 回退，随后 HTTPS 策略 |

```mermaid
flowchart LR
    A[请求与最终响应缓存] --> B[按原始域名分流]
    B --> C[并行来源查询]
    C --> D[各来源必需过滤]
    D --> E[CDN IP 替换]
    E --> F[响应到达即测速与选址]
    F --> G[域名限定的静态回退]
    G --> H[HTTPS hint ALPN ECH 策略]
```

各组的实际动作：

| 配置 | cn | global | default |
|---|---|---|---|
| 普通 | 测速 | CDN 替换→Twitter 替换→测速 | 过滤→CDN 替换→测速 |
| CERNET | 过滤→测速 | CDN 替换→测速 | 过滤→CDN 替换→测速 |

过滤检查整份来源响应，命中被排除的 IP/ASN 时丢弃该来源；域名豁免同时检查请求名
与 CNAME。HTTPS/SVCB 的 ServiceMode hint 在清理前也参与过滤。
私网地址仅通过 `probe_match.labels_exclude: [private]` 跳过测速，仍可作为答案。
原 `routing.after` 中的 `filter` 没有实际动作入口，因此没有迁成额外全局过滤。

CDN 按原规则顺序替换 Cloudflare（普通配置另含 ASN 33191）、CloudFront、
GitHub raw、Fastly。默认 `/32`、`/128` 为固定替换；Fastly 保留 `/22`、`/64`
主机位。目标均沿用原配置，替换后再测速，不探测已经被替换的原地址。
Google IPv6 回退只在允许的 Google 域名上执行，排除 google-cn/googlefcm/NTP/STUN；
条件是全部真实探测失败或 NOERROR 无地址，不把私网未测量直接当作失败。

HTTPS 处理保留原来的 hint/H3 清理、ECH 注入和辅助 A 查询。名称条件只限制注入和
辅助查询，清理始终执行。普通配置的 cn 路由关闭辅助查询；global 先执行 Twitter
策略，再执行通用策略。CERNET 使用通用策略。ECH 查 `crypto.cloudflare.com HTTPS`，
辅助 A 查询走 `resolve_cached`，包含完整分流、来源过滤、替换、测速和静态回退，
不会递归调用 HTTPS 主链。

## 有意保留与不能逐项等价的行为

- 普通 `cn.wait_all=false` 映射为 `bounded`：首个正响应后最多收集 300ms，首次
  测速成功后收集 25ms。旧程序直接采用首个完成测速的来源，结果和延时可能不同。
  其他测速组为 `wait_all`，cn 总预算 2s，global/default 为 5s；仍受父截止时间限制。
- 每个测速来源只查询一个上游。原 aiodns 地址列表和 HTTP hosts 地址池展开并行，
  不再随机挑一个拨号地址，也不逐项模拟 aiodns 的 tries/轮询退避。Google-cn、
  OpenNIC、ECH 查询不需要地址测速，使用独立完整响应 forward 池。
- `probe_match` 保留整份来源的测速门控，任一私网地址会让该来源跳过测速；同 IP
  若在其他允许测速的来源出现，仍可共享已取得的 RTT。当前 `resp_ip`、`cname`
  matcher 检查整个 Answer，旧程序只检查有效链/终点：无关的被禁 IP 也可能拒绝来源，无关的域名 CNAME 也可能
  命中动作豁免。地址替换和选址本身仍校验有效 CNAME 链，仅采用终点地址。
  原过滤限于 A/AAAA/HTTPS；迁移过滤同时适用于 SVCB 及其他带 Answer 地址的类型。
- DoH 保留 POST、原 URL/TLS SNI、独立 HTTP Host 和指定拨号 IP。新参数
  `http_host`、`http_method` 仅用于 DoH；未指定时仍为 URL Host 和 GET。
  连接池继续复用，并保留旧默认 Chrome TLS 指纹。iij/hinet 保留原来的不验证证书配置。
- 当前 ECH 上游查不到有效配置时连接失败；旧 curl 在查不到 ECH 时可能继续无 ECH
  连接。保持当前实现，不自动降低连接要求。上游 ECH 引导使用原 client resolver
  中的第一个 114DNS 地址；响应 ECH 注入使用两条 114DNS 并行查询。
  iij/hinet 原先隐含的 curl `ech: true` 是机会式自动 ECH，当前没有同等选项，
  这两组只保留普通 TLS。Chrome 指纹复用 uTLS 的配置，不保证与 curl-cffi 逐字节一致。
- 保留容量 10000 的最终响应缓存，TTL 按 DNS 响应计算；命中后不重新测速。
  不重复建立原每个 resolver 的独立响应缓存。禁用最终响应缓存时，删除 `main`
  和 `resolve_cached` 开头的 `$response_cache` 及其后缓存命中 `has_resp/accept`
  两条规则。探测 RTT 缓存仍生效。
- mosdns 使用 Go 并发调度，没有旧 `worker_count` 的逐项配置；监听器请求预算和
  各解析器重试策略也没有完全相同的参数。TCP `idle_timeout` 是空闲连接期限，
  不等同于旧 listener 的单次请求超时。
- 当前响应组件继续保护 DO=1：不裁剪、合并或替换签名 RRset；合法负响应、CNAME
  链和 ECS 视图按当前校验规则处理。旧程序更宽松的重写行为不会覆盖这些保护。
- 旧 HTTPS 辅助 A 查询总是查询原请求名；当前 `https_record` 按 ServiceMode 的
  TargetName 查询并分别判断。非 `.` 目标或多个 ServiceMode 记录可能得到不同结果。
- 未参与原路由的 test-tcp、Google 3/4、trafficroute、v-dns、普通 v-cn 及 Facebook
  替换定义保留为独立插件，主链不引用；存在不代表会额外发送查询。

生成器只针对这两份配置的既有结构，不是任意 SmartDNS 配置的通用编译器。
源 YAML 的 SHA-256 写在迁移配置开头；数据导出清单记录输入和输出哈希。
默认 runtime 规则保留旧 trie 已生效的后缀语义；切换 typed 模式属于规则语义变更，
详见[数据说明](../examples/smartdns/README-data.md)。

## 验证边界

完整策略、真实 UDP/TCP、公网可达性、慢来源与整仓回归结果见
[两份配置功能验证](smartdns-validation.md)。

`go test . -run TestSmartdnsMigration -count=1` 检查严格参数解码、按顺序的插件引用、
路由、来源过滤、替换后测速和前缀保留。外部 DNS、测速与监听端口用离线替身，
避免向私人解析配置发送测试流量。数据转换另检查原 trie 成员、MMDB 哈希和稳定导出。
这些检查不能证明当前网络能访问原上游、代理或相应 CDN 节点；部署后仍需在目标
网络检查 DNS 连通、ICMP 权限和实际延迟。

准备好实际数据且允许本地 ICMP 能力检查时，可额外运行完整初始化与关闭测试：

```powershell
$env:MOSDNS_SMARTDNS_LOCAL_DATA = "1"
go test -race . -run '^TestSmartdnsMigration' -count=1 -timeout=120s
Remove-Item Env:MOSDNS_SMARTDNS_LOCAL_DATA
```

该测试将监听改为临时回环端口，不向配置中的公网解析器发送查询。

2026-10-20 迁移构建检查已通过 Windows AMD64、Linux ARM64、Linux MIPSLE softfloat。
Linux/OpenWrt 为交叉构建检查，尚未在目标机运行。当前扩展验证与整仓结果以
上述功能验证记录为准。两份 YAML 重复生成结果一致；
默认导出的 19 个域名标签共 229,878 条成员与原 trie 一致，两份 MMDB 哈希一致。
