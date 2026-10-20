# HTTPS/SVCB 记录处理 https_record

`https_record` 清理 HTTPS（类型 65）和 SVCB（类型 64）的地址 hint、指定 ALPN，并按域名及地址条件给缺少 `ech` 的 ServiceMode 记录注入 ECHConfigList。它处理的是发给客户端的 DNS 记录；`forward` 中用于连接上游的 TLS/ECH/ALPN 参数是另一组配置。

已有 ECH 不被覆盖，AliasMode 保持原样。清理先完成，再进行可选 ECH/A 查询；辅助工作超时或失败时仍保留已清理的完整主响应。客户端或当前查询 DO=1 时提前跳过整个动作。

## 离线完整示例

[https-record.yaml](../examples/https-record.yaml) 的主 HTTPS/SVCB 记录和 ECH 来源均为 `arbitrary`，A 来源为 hosts 加明确禁测的 speedcheck。所有辅助查询在进程内完成，不访问公网、不探测文档地址，也不需要证书或数据库。

```powershell
go build -o .\mosdns.exe .
.\mosdns.exe start -c .\examples\https-record.yaml
```

Linux 对应使用 `go build -o ./mosdns .` 和 `./mosdns start -c examples/https-record.yaml`。示例监听本机 UDP/TCP `15353`，API 监听 `19091`；与其他演示使用同一端口时请只运行一份实例。

使用支持 HTTPS RR 的查询工具检查内容，例如：

```text
dig @127.0.0.1 -p 15353 hint.https-record.invalid HTTPS
dig @127.0.0.1 -p 15353 hintless.https-record.invalid HTTPS
dig @127.0.0.1 -p 15353 nodata.https-record.invalid HTTPS
dig @127.0.0.1 -p 15353 alias.https-record.invalid HTTPS
dig @127.0.0.1 -p 15353 svcb.https-record.invalid SVCB
```

Windows 上可使用支持 HTTPS/SVCB 类型的本地 DNS 客户端；`nslookup` 的类型支持取决于版本。正常不设置 DO 的查询结果为：

| 名称 | 预期行为 |
| --- | --- |
| `hint.https-record.invalid` | 使用原 hint 匹配 IP 条件；移除 hint 和 h3，保留 h2，添加 ech，并同步修复 mandatory。 |
| `hintless.https-record.invalid` | 查询该记录 TargetName `gate-target.https-record.invalid` 的 A，经本地路由匹配后添加 ech；纯 h3 的 ALPN 与 no-default-alpn 被移除。 |
| `nodata.https-record.invalid` | 主来源产生合法 NODATA；原问题名称的本地 A 通过条件后合成 `HTTPS 1 . ech=...`。 |
| `alias.https-record.invalid` | 原样保留 `HTTPS 0 gate-target.https-record.invalid.`，不为 AliasMode 注入 ECH 或发 A 查询。 |
| `svcb.https-record.invalid` | 对 SVCB ServiceMode 执行同样的 hint/ALPN 清理与 ECH 注入。 |

示例 ECHConfigList 是结构完整的固定测试数据：版本 `0xfe0d`、config_id `66`、KEM `0x0020`（X25519）、32 字节公开点 `09` 后接 31 个零、HKDF-SHA256/AES-128-GCM 套件 `(1,1)`、空扩展及保留域名 `public.https-record.invalid`。它仅用于验证 DNS 参数结构与处理流程，没有对应的 TLS 服务。生产环境必须使用目标 CDN/服务实际支持的 ECH 域名及来源，限定允许修改的域名；不能给任意网站套用 Cloudflare 或其他服务的 ECH 配置。

## 全部配置参数

先声明被引用的集合、`ech_lookup` 与 `ip_lookup` 命名 sequence，再声明插件：

```yaml
- tag: process_bindings
  type: https_record
  args:
    remove_hint: true
    remove_h3: true
    remove_alpn: ["h3-29", "h3-32"]
    add_ech: true
    enable_subquery: true
    ech_source: ech_lookup
    ech_domain: crypto.cloudflare.com
    ip_source: ip_lookup
    match_name: ["domain:example.org"]
    match_ip: ["$cdn_addresses", "192.0.2.0/24"]
    exclude_ip: ["192.0.2.99"]
    timeout: 500ms
```

该片段展示字段关系；域名、目标网络和 ECH 来源须按实际兼容的服务配套设置。

| 字段 | 默认值与行为 |
| --- | --- |
| `remove_hint` | `true`；移除 ServiceMode 中的 ipv4hint 和 ipv6hint。 |
| `remove_h3` | `true`；移除精确 ALPN ID `h3`，不会隐含匹配 `h3-29` 等其他 ID。 |
| `remove_alpn` | 空；额外移除的精确 ALPN ID 列表。每个 ID 为 1..255 字节；可与 `remove_h3` 共同使用。 |
| `add_ech` | `true`；为符合条件且尚无 ech 的 ServiceMode 添加 ECH。设为 false 时不需要任何辅助来源。 |
| `enable_subquery` | `true`；允许缺 hint 时的 A 门控，以及 NODATA 的 A 确认。设为 false 不发 A 查询，但有 hint 或无 IP 门控的现有 ServiceMode 仍可注入 ECH。 |
| `ech_source` | 无默认；`add_ech: true` 时必填，引用此前声明的可执行来源，推荐专用命名 sequence。 |
| `ech_domain` | `crypto.cloudflare.com`；向 ech_source 查询其 HTTPS 记录并读取可用 ECHConfigList，生产配置应显式选用兼容目标。 |
| `ip_source` | 无默认；`add_ech: true` 且 `enable_subquery: true` 时必填，引用此前声明的完整 A 处理链。 |
| `match_name` | 省略表示不限；表达式间 OR。显式 `[]` 拒绝全部 ECH 注入及辅助查询，清理仍执行。 |
| `match_ip` | 省略表示不限制 IP；表达式间 OR。显式 `[]` 拒绝全部 IP 注入条件。 |
| `exclude_ip` | 默认无排除；任一命中地址否决当前 ServiceMode 记录的注入，优先于 include。空列表没有实际排除条件。 |
| `timeout` | `500ms`；省略或 `0` 使用默认值，负值报错。ECH 与全部 A 查询共用此预算，受父请求截止限制，并预留 `min(25ms, 剩余时间/2)` 给后续处理和回包。 |

`match_name` 支持现有域名表达式、`$domain_set`、`&文件`、GeoSite 等；匹配原问题名称、有效 CNAME 链、终点 owner 或当前记录的规范化 TargetName。`match_ip` 与 `exclude_ip` 支持 IP/CIDR、`$ip_set`、`&文件`、GeoIP/ASN 表达式。所有引用必须指向此前声明的插件；文件路径按进程工作目录解析。

## 处理顺序与逐 Target 门控

仅处理合法 IN/HTTPS、IN/SVCB、NOERROR、非截断响应，沿最多 16 跳的有效 CNAME 链找到终点 RRset。无关 Answer 与 Additional 的地址不参与条件。每条 ServiceMode 分别判断；不会因一条记录命中，就把同一 RRset 中不同 Target 的记录一起授权。

1. 使用独立快照清理所有终点 ServiceMode 的 hint/ALPN。ALPN 为空时删除 ALPN 及 no-default-alpn，mandatory 中不再存在的键也一并移除。
2. `match_name`、`match_ip`、`exclude_ip` 只控制 ECH 与辅助查询，不控制上一步清理。若要限制整个动作的域名范围，应在外层 sequence 调用时使用 `matches`。
3. 当前记录已有 hint 时，用这条记录原本的全部 hint 判定；任一 exclude 否决该条，否则任一 include 命中即可。不使用其他 Target 的 hint。
4. 缺 hint 且存在 IP 门控时，通过 ip_source 查询该记录 TargetName 的 A；根目标 `.` 表示 CNAME 终点 owner。相同规范化 Target 在本次请求内去重，最多 8 个 A 查询并行。
5. 没有 IP 门控的现有 ServiceMode 可直接按名称授权，无需 A 查询。NODATA 始终需要先查询原问题名称的 A，并取得合法匹配地址后才能合成。

ECH 查询与所需 A 查询重叠运行，共用一个预算。辅助 A 是本插件自己调用的命名处理链；**不保证浏览器同时发出的 A 查询已经返回，也不会等待浏览器查询的缓存结果**。ip_source 可接入已有替换、过滤、speedcheck、ip_fallback 和响应缓存组成的完整 A 路由，返回的最终地址才用于判断。

```yaml
# 已定义 select_fast_ip、static_ip_fallback、ech_lookup 和 normal_resolve。
- tag: ip_lookup
  type: sequence
  args:
    - exec: $select_fast_ip
    - exec: $static_ip_fallback
- tag: process_bindings
  type: https_record
  args:
    ech_source: ech_lookup
    ech_domain: compatible-ech.cdn.example  # 替换为实际兼容服务的ECH域名。
    ip_source: ip_lookup
    match_name: ["domain:example.org"]
- tag: main
  type: sequence
  args:
    - exec: $normal_resolve
    - matches: ["qname domain:example.org"]
      exec: $process_bindings
    - matches: [has_resp]
      exec: accept
```

上述引用应按“地址处理依赖 → ip_lookup/ech_lookup → process_bindings → main”顺序声明。ECH 专用来源保留 DNS/EDNS 及服务端元信息，但不继承请求的 marks/任意 kv；A 来源继承完整查询上下文，以便复用正常路由。辅助调用携带内部标记，即使来源链再次经过 https_record，也只执行清理，不递归发起新的辅助查询。

## 在来源中按 hint 过滤

在执行本插件删除 hint 之前，来源可用现有 `resp_ip` 读取合法 HTTPS/SVCB 终点 ServiceMode 的地址，并通过 `drop_resp` 拒绝候选。例如：

```yaml
- exec: $upstream
- matches: ["qtype 64 65", "resp_ip 0.0.0.0/8 ::/128"]
  exec: drop_resp
- exec: $process_bindings
```

这个 matcher 不取无关 owner 或 Additional 中的 hint；A/AAAA 的原有 Answer 地址匹配行为保持兼容。它与本插件的 `match_ip` 用途不同：前者可丢弃整份来源，后者仅控制对应记录的 ECH 注入。两者都可复用 IPSet/GeoIP/ASN 表达式。

## ECH 缓存与生存期

每个插件实例最多缓存 **100 条成功 ECH 结果**，有效期不超过来源 RRset/CNAME 剩余期限及 **300 秒**；TTL=0 可用于本次注入但不缓存。缓存按去掉 ID 的完整辅助查询及 ServerMeta 区分，保留 EDNS/ECS 视图隔离。A 查询没有本插件自带的结果缓存，需要时由 ip_source 的正常缓存链负责。

每个请求至多进行一次 ECH 来源查询，供该请求中符合条件的记录复用。并发请求可以命中成功缓存；当前不合并尚在进行的 ECH 查询。

没有负缓存：无 ECH、错误、超时及临时失败均不写入 ECH 缓存。ECH 缓存仅保存来源数据，不保存清理后的最终 DNS 响应，也不保存 IP 授权结论。

清理不会重置原 RRset 生存期。注入 ECH 后，同一 RRset 的 TTL 还受 ECH 来源，以及用于门控的 A 记录/CNAME 链期限约束。NODATA 合成额外受 300 秒上限、主响应的有效 CNAME/否定 SOA 期限约束；保留主 CNAME 链及终点 owner，移除不再适用的负 SOA。原生 TTL=0 与正 TTL 老化后取整为 0 的内部期限保持区分，过期来源不会因重建获得新生存期。

## 保留响应与取消

AliasMode（priority=0）保持原样；已有 ECH 不覆盖。NXDOMAIN、错误响应、截断和 DNAME/TSIG/SIG(0) 等不适合重建的合法消息不被合成；主响应的非法关联信息或链返回错误，辅助来源的非法结果按可选工作失败处理。DO=1 时不做清理、注入或合成。

DO=0 重建响应清除 AD/AA 和失效签名、否定证明，清理连接相关 EDNS 选项并保留一致的 ECS 视图。父查询、marks、任意 kv 及上游共享响应不会被辅助来源覆盖。父请求取消向上传播；可选来源错误、局部超时和 panic 不抹掉先前完成的清理。实例关闭会取消并等待辅助工作；来源 sequence 应遵守继承的 context 取消。

## 验证

根包集成测试对离线示例严格解码、初始化全部处理插件，再创建随机回环端口的实际 UDP/TCP 服务，覆盖上述五种 HTTPS/SVCB 场景、普通本地 A 路由及 DO 保护。Windows 的两种传输均已通过，实际探测次数为零。ECH 测试数据还单独检查了全部长度字段、当前版本、HPKE 参数、公钥及可执行的 X25519 ECDH；该示例没有对应 TLS 服务，不代表真实 ECH 握手成功。

最终独立提交快照的跨平台检查与本机 WSL UDP 限制，见[迁移验证范围](response-migration.md#离线示例与验证范围)。

相关逻辑与并发检查可运行：

```powershell
go test -race -p 2 ./pkg/response ./plugin/executable/https_record
```
