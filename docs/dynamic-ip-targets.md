# fallback 与 IP 替换的域名地址来源

`ip_fallback` 和 `ip_replace` 的 `ipv4`、`ipv6` 列表都接受 `domain:<域名>`，可以与固定 IP 混用。配置域名目标时，插件级 `ip_source` 必须引用**此前定义的 forward 或 sequence 标签**，不带 `$`。纯 IP 配置及原有构造函数调用保持兼容。

```yaml
# target_resolve 需在这两个插件之前定义。
- tag: dynamic_fallback
  type: ip_fallback
  args:
    ip_source: target_resolve
    timeout: 500ms
    ipv4: ["203.0.113.42", "domain:backup.example.org"]
    ipv6: ["domain:backup.example.org"]
    on: [no_rtt, nodata]

- tag: dynamic_replace
  type: ip_replace
  args:
    ip_source: target_resolve
    timeout: 500ms
    replace_map:
      - match_ip: ["192.0.2.0/24"]
        ipv4_prefixlen: 24
        ipv4: ["domain:cdn.example.org"]
```

`ip_replace.ip_source` 和 `timeout` 对插件内所有规则生效。`timeout` 是一次执行中全部目标查询共享的总预算，省略或为 `0` 时使用 `500ms`，负值或无法解析的时长启动报错。预算同时受父请求剩余时间限制，并为原响应回传预留最多 25ms。它不会为每个目标分别重新计时。

域名大小写和末尾点统一为小写绝对域名，例如 `domain:BACKUP.Example` 与 `domain:backup.example.` 是同一个目标。仅接受由字母、数字、连字符组成的非空 DNS 主机名；国际化域名请先转换为 Punycode。非法域名、目标 IP 地址族错误、缺少来源或引用了未定义/错误类型的标签均在初始化时报错。

## 查询时机、顺序与失败处理

- `ip_fallback` 先判断现有 `on` 条件，成立后才查询当前地址族目标。没有经过测速的普通正响应不会仅因配置了 `no_rtt` 就触发回退。
- `ip_replace` 先匹配规则与原终点地址，命中后才解析目标。首个命中规则拥有最终决定权；该规则没有当前地址族目标，或动态目标全部失败时，保留原响应并结束。
- `ipv4` 内域名只查询 A，`ipv6` 内域名只查询 AAAA；同一次执行中相同规范化域名只查询一次，最多并发 8 个域名。不同请求的缓存由解析链提供。
- 按列表配置顺序展开，保留各目标来源的地址顺序，与固定 IP 稳定合并去重。重复地址由首个出现位置决定其来源；前缀映射后还会去重。
- 单个目标超时、错误、NXDOMAIN、NODATA、关联性或 CNAME 校验失败时忽略该项，并记录 debug 日志；其余域名和固定地址仍可使用。所有目标不可用时保留原响应，扣除等待期间消耗的 TTL。父请求取消则向上传播取消原因。

域名结果与固定地址执行完全相同的前缀映射。默认 `/32`、`/128` 完整替换；较短前缀保留首个命中原地址的主机位。例如原地址 `192.0.2.42`、域名查询得到 `203.0.113.99`、`ipv4_prefixlen: 24`，生成 `203.0.113.42`。

## 专用缓存链与离线示例

[dynamic-ip-targets.yaml](../examples/dynamic-ip-targets.yaml) 是完整、无需公网的配置，涵盖 hosts、专用 cache、目标解析链、两个重写插件和禁用探测的 speedcheck。启动命令：

```text
mosdns start -c examples/dynamic-ip-targets.yaml
```

它监听本机 UDP/TCP `15353`：

```text
nslookup -port=15353 -type=A fallback.dynamic-ip.invalid 127.0.0.1
nslookup -port=15353 -type=AAAA nodata.dynamic-ip.invalid 127.0.0.1
nslookup -port=15353 -type=A replace.dynamic-ip.invalid 127.0.0.1
```

示例 A 回退/替换均生成 `203.0.113.42`、`198.51.100.42`；AAAA 回退为 `2001:db8:ffff::42`，替换为 `2001:db8:100::42`。目标链 TTL 30 秒限制最终寿命，即使 fallback 配置了更长 TTL。示例禁用 TCP/ICMP 探测，因此显式使用 `on: [no_rtt, nodata]`；默认 `all_probes_failed` 不将禁测当成探测失败。

目标链的关键接法如下，`target_hosts` 需提前定义；生产环境可将它替换为此前定义的 forward，并按需要加入 ECS：

```yaml
- tag: target_cache
  type: cache
  args:
    size: 1024
    scope: sequence
    lazy_cache_ttl: 0
    prefetch: false
- tag: target_resolve
  type: sequence
  args:
    - exec: $target_cache
    - matches: [has_resp]
      exec: accept
    - exec: $target_hosts
    - matches: [has_resp]
      exec: accept
    - exec: reject 3
```

缓存后面的 `has_resp → accept` 用于阻止后续解析覆盖缓存命中。插件没有内部缓存、轮询或后台刷新。现有 cache 负责 TTL、预取和 lazy；目标查询的递归保护标记会继续传递到 lazy/预取，不改变普通缓存行为。

替换应放在 speedcheck 的每个来源内部、来源返回之前，确保测量生成的地址。fallback 放在选择之后、最终 `accept` 之前；fallback 输出不再参加当前这一轮排名。此次扩展不改变 speedcheck 选择窗口或 `fallback.on` 语义。

## 缓存键与有效期计算

需要区分专用解析链保存的**目标域名响应**与最终返回给客户端的**合成响应**。两个重写插件只在本次执行内合并、去重查询，不跨请求保存地址；跨请求复用完全由 `ip_source` 链中的 cache 决定。直接引用 forward 而不配置 cache 时，每次触发重写都会重新解析域名。

缓存键使用规范化后的目标域名、查询类型、查询类别和 AD/CD/DO 标志；`scope: sequence` 额外加入 sequence 身份及继续执行位置，不按客户端 IP 隔离。例如多个用户域名都引用 `domain:backup.example.org` 时，在同一目标链及相同查询参数下共用 `backup.example.org` 的 A 缓存；AAAA 是另一条缓存。`size: 1024` 表示条目容量，不是缓存秒数；底层最低容量为 1024，填写 `size: 128` 也会提升至 1024。`timeout: 500ms` 是全部目标查询共享的执行预算，也不是缓存寿命。

正常正响应的计算为：

```text
目标缓存 TTL = min(Answer、Authority、Additional 中各记录 TTL，排除 OPT)
缓存到期时间 = 写入时间 + 目标缓存 TTL
命中记录 TTL = 存入的记录 TTL - floor(命中时间 - 写入时间，单位秒)
```

cache 返回前会扣除已经经过的整秒；重写组件继续按实际处理时间保守取整，并复核绝对期限，因此线上 TTL 可能比直观估计再少 1 秒。缓存寿命可能被不参与地址提取的其他响应记录缩短；重写只提取可达 CNAME 终点的对应地址族。

对最终响应，先将各来源寿命换算为提交时的剩余秒数，再应用：

```text
动态目标剩余寿命 = min(目标地址 RRset、目标 CNAME 链、继承的适用截止时间)
fallback TTL = min(配置 ttl、实际贡献目标的剩余寿命、原 CNAME 链及适用截止时间)
IP 替换 TTL = min(原地址 RRset 与原 CNAME 的剩余寿命、实际贡献目标的剩余寿命)
```

没有动态来源或原 CNAME 时，省去相应约束。固定地址不引入额外的动态寿命；混合多个有效目标时，整个合成 Answer 保守采用最短期限。动态来源若只产生已出现过的重复地址、没有实际贡献新地址，则不增加约束。fallback 可以重设原地址的 TTL；保留的原 CNAME 链仍构成约束。替换继续受原地址寿命限制。

例如目标 A 的 TTL 为 30 秒、目标 CNAME 为 120 秒，缓存关闭 lazy，fallback 配置 `ttl: 86400`：首次生成的 TTL 不超过 30 秒；约 10 秒后命中，返回不超过约 20 秒；30 秒到期后，下次触发目标查询会重新解析。如果同时贡献地址的另一目标只剩 8 秒，最终 TTL 不超过 8 秒；替换时原响应仅剩 5 秒，则不超过 5 秒。

### 过期、lazy 与预取

| 配置或结果 | 当前行为 |
| --- | --- |
| `lazy_cache_ttl: 0`、`prefetch: false` | 本示例的设置。到期后不返回旧目标，下一次符合重写条件的请求重新解析。 |
| `lazy_cache_ttl: 300` | 对正常正响应，自写入起最多保留 300 秒；不是 DNS TTL 到期后再保留 300 秒。TTL=30 时，旧条目最多还可供约 270 秒 lazy 命中；小于 DNS TTL 的保留时间会提前淘汰条目。 |
| lazy 命中 | 在保留期内使用旧目标响应，临时 TTL=5 秒，并在后台刷新。合成响应还会受其他适用寿命约束。 |
| `prefetch: true` | 命中次数达到 `prefetch_min_hits`，且正的剩余寿命小于 `prefetch_before_expire` 时，在扫描中安排刷新；默认分别为 3 次、10 秒，扫描间隔 `prefetch_scan_interval` 默认 5 秒。不保证每个条目都会在到期前刷新。 |
| 目标 TTL=0 | 正响应不写入 cache；本次合成保留 TTL=0。 |
| NXDOMAIN/NODATA | 带 SOA 时按 `min(SOA TTL, SOA.MINIMUM)` 负缓存；动态目标不贡献地址。缺少可用 SOA 的负答不缓存。 |
| SERVFAIL | 当前 cache 保留 5 秒；动态目标忽略该结果。 |

lazy 允许短暂继续使用过期目标，是显式启用的缓存策略；目标一过期就必须重新查询的场景使用本示例的 `lazy_cache_ttl: 0`。后台刷新使用 cache 自己的生命周期和超时，不受已经返回的那次 `timeout: 500ms` 继续计时。

当前 cache 保存 DNS 报文、写入及到期时间，不保存整个 `ResponseSnapshot.ValidUntil` 元数据。目标查询命中后，重写组件依据返回报文的剩余 TTL 重新分析寿命；本次分析与改写链内继续保留绝对期限。如果另在用户入口缓存最终响应，命中后立即 `accept` 会直接复用合成结果，跳过这一轮解析、替换和测速；其寿命按写入的 DNS TTL 计算。后置 `ttl` 动作也会改变缓存实际看到的 TTL，请根据所需的新鲜度安排。

### ECS 与策略隔离

当前 cache 对含任意非 Padding EDNS 选项的查询直接绕过缓存，**包括 ECS**，没有按 ECS 子网划分缓存键。来源链在 cache 之后添加 ECS 时，该结果也不会写入普通缓存键，但已经命中的响应不会再执行后面的 ECS。因此，改变响应视图的 ECS 操作应放在 cache 之前；不能将 `scope: sequence` 解释为 ECS 缓存隔离。

即使没有 ECS，若目标结果依赖客户端地址或路由策略，也应使用相应的独立缓存实例或独立策略链；预取使用中立查询，不恢复任意客户端 marks/KV。更完整的边界见[缓存行为](cache-behavior.md)。

## 响应寿命与隔离

目标查询使用全新子请求，保留 DNS/EDNS 参数及客户端网络元数据；原响应、marks、私有值和测速状态均隔离，辅助查询的修改不会提交到父请求。两个重写插件共享递归保护标记，目标解析链间接包含任一个插件时都会跳过地址重写。

来源响应由现有响应分析器校验查询关联性、唯一可达的 CNAME 链及终点地址。无关 Answer/Additional 地址不作为目标；目标域名的 CNAME 不拼接到用户响应。输出保留用户原查询的 owner 和原有 CNAME 语义，DO=1 与不能安全重建的响应仍保留现有保护。

每个实际贡献地址的动态来源，以其完整地址 RRset、CNAME 链的剩余 TTL 和绝对有效期限限制最终响应。fallback 另受配置 `ttl` 与用户原 CNAME 寿命约束；替换另受原响应地址和 CNAME 寿命约束。混合列表保守使用这些约束的最短期限，重复且未实际贡献新地址的来源不额外缩短寿命。

原生 TTL=0 保持为零；不足一秒而取整成零的 TTL 仍在本次响应处理链内保留非零的绝对截止时间，后续测速据此拒绝已过期地址。并行等待期间过期的目标会被忽略；提交前再次检查期限。插件关闭或父请求取消会取消并回收正在进行的目标查询，解析来源应遵守传入上下文的取消信号。

离线测试使用可控时钟覆盖目标 TTL、CNAME、零 TTL、等待期间过期、失败后的原响应老化、缓存命中/过期刷新、lazy/预取递归保护，并用替身探测器确认替换地址进入测速。UDP/TCP 验证使用本机临时端口，不代表部署设备或公网 DNS 验证。

2026-11-15，本地 Windows 验证命令（普通测试与 race 使用相同范围）：

```powershell
# 使用项目内临时目录，避免沙箱默认临时路径大小写影响 coremain 路径断言。
New-Item -ItemType Directory -Force .reference/dynamic-ip-tests/tmp | Out-Null
$env:TEMP = Join-Path $PWD '.reference/dynamic-ip-tests/tmp'
$env:TMP = $env:TEMP
$packages = @(
  './pkg/response', './pkg/query_context', './pkg/query_policy',
  './plugin/executable/internal/iptarget', './plugin/executable/ip_fallback',
  './plugin/executable/ip_replace', './plugin/executable/cache',
  './plugin/executable/speedcheck', './plugin/executable/sequence/...',
  './coremain', './tests/integration', '.'
)
go test -p 2 @packages
go test -race -p 2 @packages
go vet -p 2 ./...
```

集成包同时执行完整示例的严格参数解码、插件实际初始化和本机 UDP/TCP 查询；不要求运行示例监听端口或访问公网。
