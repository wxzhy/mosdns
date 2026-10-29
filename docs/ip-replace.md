# CDN 地址前缀替换 ip_replace

`ip_replace` 根据响应中的 CDN 地址生成一组替代地址，支持按规则设置 IPv4、IPv6 的目标前缀长度。替换成功后只返回生成地址；不会保留原地址作为额外候选。插件只改写当前 DNS 响应，不发查询或探测。

[完整本地演示](../examples/ip-replace.yaml) 使用 hosts 为保留域名生成原地址，再执行替换，无需公网 DNS、数据库或证书。它监听本机 UDP/TCP `15353`，API 监听 `19091`，不调用 speedcheck，不探测示例中的文档地址。在仓库根目录运行：

```powershell
go build -o .\mosdns.exe .
.\mosdns.exe start -c .\examples\ip-replace.yaml
```

Linux 对应使用 `go build -o ./mosdns .` 和 `./mosdns start -c examples/ip-replace.yaml`。另开终端查询：

```text
nslookup -port=15353 -type=A cdn.ip-replace.invalid 127.0.0.1
nslookup -port=15353 -type=AAAA cdn.ip-replace.invalid 127.0.0.1
```

默认未设置 DO 的 A 查询得到 `203.0.113.42`、`198.51.100.42`；AAAA 查询得到 `2001:db8:100::42`。顺序按目标列表，客户端展示顺序可能不同。原 hosts 地址分别为 `192.0.2.42`、`2001:db8:20::42`；其他名称在演示配置中返回 NXDOMAIN。上述地址均为文档保留地址，仅用于检查响应内容。

## 全部配置参数

先定义被引用的 IPSet，再定义插件，最后在 sequence 中调用：

```yaml
- tag: cdn_networks
  type: ip_set
  args:
    ips: ["192.0.2.0/24", "2001:db8:20::/48"]
- tag: replace_cdn
  type: ip_replace
  args:
    replace_map:
      - match_ip: ["$cdn_networks"]
        exclude_ip: ["192.0.2.99", "2001:db8:20::99"]
        ipv4_prefixlen: 24
        ipv6_prefixlen: 64
        ipv4: ["203.0.113.99", "198.51.100.77"]
        ipv6: ["2001:db8:100::99"]
```

| 字段 | 默认值与行为 |
| --- | --- |
| `replace_map` | 有序规则列表；省略或 `[]` 不替换。 |
| `replace_map[].match_ip` | 必填且非空的表达式列表，列表内 OR；只匹配当前问题沿 CNAME 链可达的终点 A/AAAA 地址。 |
| `replace_map[].exclude_ip` | 默认空；逐 IP 排除，优先于该规则的 `match_ip`。排除一个 IP 不会拒绝整份响应或阻止其他 IP 匹配。 |
| `replace_map[].ipv4_prefixlen` | 默认 `32`；整数 `0..32`，显式 `0` 有效。 |
| `replace_map[].ipv6_prefixlen` | 默认 `128`；整数 `0..128`，显式 `0` 有效。 |
| `replace_map[].ipv4` | 默认空；目标 IPv4 地址字符串列表，不带 CIDR；按配置顺序生成并去重。 |
| `replace_map[].ipv6` | 默认空；目标 IPv6 地址字符串列表，不带 CIDR；按配置顺序生成并去重。 |

两种匹配列表复用现有 IP matcher，支持裸 IP、CIDR、`$ip_set_tag`、`&./rules/ips.txt`、`geoip:cn`、`asn:AS13335`、`ext:./data/Country.mmdb:CN`、`ext:./data/ASN.mmdb:AS13335`。数据库表达式需要对应文件，详情见[数据集合配置](configuration-reference.md)。不需要数据库时直接使用 CIDR/IPSet。每个列表元素是一条独立表达式，`&` 后的完整字符串作为文件路径，因此可将含空格的路径写在同一个 YAML 字符串内；相对路径从进程工作目录解析。

规则在启动时加载；非法 prefix、无效 IP、目标地址族错误或加载匹配表达式失败都会使初始化报错。目标列表不接受 `203.0.113.0/24` 这样的 CIDR、带 zone 的 IPv6（如 `fe80::1%eth0`）或 IPv4-mapped IPv6（如 `::ffff:192.0.2.1`）；前缀长度由对应的 `prefixlen` 单独指定。

## 选择顺序与地址计算

先按 `replace_map` 顺序扫描规则，再在该规则内按原响应记录顺序扫描终点地址。首个命中且未被排除的 IP 作为本次唯一的主机位来源，用它生成该地址族的全部目标地址。不会为原响应中的每个 IP 分别生成一组结果。首个命中规则的当前地址族目标列表为空时，保留原响应并结束，不尝试后续规则。没有命中时也保留原响应。

对长度为 `p` 的目标前缀，自动将目标基址规范化，再保留原地址的低位：

```text
新地址 = (目标地址 & 前缀掩码) | (原地址 & 主机位掩码)
```

例如 `192.0.2.42`、目标 `203.0.113.99`、`ipv4_prefixlen: 24` 得到 `203.0.113.42`。这里 `.99` 会被掩码清除，不与 `.42` 相加，因此不会产生跨网段进位。非整字节长度也按位处理。

| prefix | 行为 |
| --- | --- |
| IPv4 `/32`、IPv6 `/128` | 全部位来自目标，等同固定地址替换；也是省略 prefix 时的默认行为。 |
| `/0` | 全部位来自首个匹配原地址；多个目标会生成同一 IP，最终去重。 |
| 其他合法长度 | 高 `p` 位来自规范化目标，低位来自首个匹配原地址。 |

## 与 speedcheck 接线

在每份来源的 forward 和必需过滤之后调用替换，再让来源 sequence 返回给 speedcheck：

```yaml
# 此前已定义 upstream_a、upstream_b、source_response_filters、replace_cdn。
- tag: source_a
  type: sequence
  args:
    - exec: $upstream_a
    - exec: $source_response_filters
    - exec: $replace_cdn
- tag: source_b
  type: sequence
  args:
    - exec: $upstream_b
    - exec: $source_response_filters
    - exec: $replace_cdn
- tag: select_fast_ip
  type: speedcheck
  args:
    sources: [source_a, source_b]
```

这样标签、ASN 倍率、候选过滤、探测和 RTT 缓存都作用于替换后的地址。同一个目标 IP 可在来源间共享探测结果。某来源完成替换即进入测速，其他来源仍可同时查询，无收齐屏障。不要在最终 `$select_fast_ip` 之后替换，否则返回地址没有参与这一轮选址。正式接线前将文档保留地址改成实际使用的 CDN 网段；完整时序与过滤说明见 [speedcheck](speedcheck.md)。

域名和 CNAME 条件由来源 sequence 的 `matches` 控制；例如在调用动作上增加 `matches: ["qname domain:example.org"]`。若只对已替换地址执行额外网络过滤，可在替换后、来源返回前追加现有 matcher 与 `drop_resp`。

## 响应与 DNSSEC 保护

仅合法 IN/A、IN/AAAA 正响应适用；按照当前问题追踪唯一、无环且最多 16 跳的 CNAME 链，只使用终点的同类型、同类别 RRset。无关 Answer 和 Additional 地址不参与匹配或生成。无响应、NXDOMAIN/NODATA、截断及 DNAME、TSIG 等不适合重建的响应保持原样；非法响应返回错误，由外层 fallback 处理。

替换使用独立响应快照，保留 CNAME 链和终点 owner。生成地址的 TTL 受原终点 RRset 与 CNAME 链剩余期限约束；重建会扣除已消耗时间，并在内部保留原非零 TTL 的绝对有效期限。剩余不足一秒时可以即时返回线上的 TTL=0；命中替换的来源在提交前已过期则返回错误，交外层 fallback，进入 speedcheck 后过期的候选会被丢弃。真正原生 TTL=0 不被改成长 TTL。内部期限没有 YAML 配置项，也不会覆盖父查询、marks 或插件 kv。

客户端或当前查询 DO=1 时跳过替换，保留完整来源响应。DO=0 的合成响应清除 AD/AA，删除失效签名和证明记录，并沿用响应组件的 EDNS 清理策略。插件不改变 ECS 查询视图，也不改写 HTTPS/SVCB 的 `ipv4hint`、`ipv6hint`；这些类型会保留原响应。

## 本轮验证

2026-10-20，使用 Go 1.27.2 完成以下检查：

- Windows race：`query_context`、`response`、`ip_replace`、`speedcheck`、`sequence/fallback`、`coremain` 和根包全部通过。
- Linux Debian WSL：将同版 Go 交叉编译的 linux/amd64 测试二进制在本地运行，`query_context`、`response`、`ip_replace`、`speedcheck` 和根包通过；此次 Linux 检查未启用 race。
- 整仓 `go vet -p 2 ./...`、Windows 构建与版本命令、Linux ARM64 和 MIPSLE softfloat 的 `CGO_ENABLED=0 go build -p 2 ./...` 通过。交叉构建不代表已经在 OpenWrt 目标机运行。
- 五份文档示例的严格解码和注册插件覆盖检查通过；本地替换示例实际初始化后，A/AAAA 主链返回文档列出的地址，不依赖公网查询。

确定性测试验证：快来源在 10ms 返回后立即开始对替换地址的 20ms 探测，bounded 在首个成功后的 25ms 窗口结束时于 **55ms 逻辑时间**提交，200ms 的慢来源仍在查询；wait_all 于 200ms 提交。多个来源生成相同目标时只探测每个目标一次，倍率也按替换地址计算。这是可控时钟测试，不是实际 CDN 网络延时。

测试同时覆盖全部 IPv4/IPv6 前缀长度、默认值与显式 `/0`、规则及记录顺序、exclude、空目标、去重、CNAME、负答、短 TTL/TTL0、DO、EDNS 和响应独立性。本轮保留另一任务的 upstream/GeoIP 修改，没有运行整仓测试，也没有修复此前记录的上游测试失败；历史失败及其验证范围见[测速验证记录](speedcheck-validation.md)。

逐步提交时，另从 Git 索引导出不含其他任务未提交修改的独立源码快照，Windows 相关 race、五份示例检查、整仓 vet、Windows 构建及版本命令、Linux ARM64/MIPSLE softfloat 交叉构建同样通过。上面的 Linux 运行测试来自此前工作树，未在此独立快照重复运行。

在仓库根目录复现主要 Windows 检查：

```powershell
go test -race -p 2 ./pkg/query_context ./pkg/response ./plugin/executable/ip_replace ./plugin/executable/speedcheck ./plugin/executable/sequence/fallback ./coremain ./tests/integration
go vet -p 2 ./...
go test ./plugin/executable/speedcheck -run TestIPReplacementPrecedesStreamingProbe -v
go test ./tests/integration -run 'TestIPReplace|TestDocumentedExamplesUseKnownPluginParameters' -v
```
