# 静态地址回退 ip_fallback

`ip_fallback` 在 `speedcheck` 后检查当前响应的测速状态，满足配置条件时以指定地址生成新响应。默认处理“全部真实探测失败”和合法 NOERROR/NODATA；关闭测速、队列不足或尚未测完时默认继续采用 DNS 地址。要在这些情况下使用静态地址，显式选择 `no_rtt`。

插件不会发起 DNS 查询或探测，也不会对静态地址执行倍率排序。静态地址按配置顺序返回并去重，`speedcheck.max_num` 不会再次裁剪这份地址列表。请只为明确允许的域名配置回退，并先确认真实目标地址可用。

## 本地完整示例

[ip-fallback.yaml](../examples/ip-fallback.yaml) 使用 hosts 生成本地响应，再由明确禁用 TCP/ICMP 的 speedcheck 标记为未测量，最后用 `no_rtt` 回退。所有地址均为文档地址；此配置不访问公网、不探测地址、不使用数据库或最终响应缓存。

从仓库根目录启动：

```powershell
go build -o .\mosdns.exe .
.\mosdns.exe start -c .\examples\ip-fallback.yaml
```

Linux 对应使用 `go build -o ./mosdns .` 和 `./mosdns start -c examples/ip-fallback.yaml`。示例监听本机 UDP/TCP `15353`，API 监听 `19091`。另开终端查询：

```text
nslookup -port=15353 -type=A no-rtt.ip-fallback.invalid 127.0.0.1
nslookup -port=15353 -type=AAAA no-rtt.ip-fallback.invalid 127.0.0.1
nslookup -port=15353 -type=AAAA nodata.ip-fallback.invalid 127.0.0.1
```

默认未设置 DO 的 A 查询返回 `203.0.113.42`、`198.51.100.42`，AAAA 返回 `2001:db8:ffff::42`。`nodata.ip-fallback.invalid` 的原始 hosts 条目只有 IPv4，AAAA 查询由 NODATA 回退生成地址。其他名称没有本地条目，也没有外部上游。

将示例的 `on` 改为 `[all_probes_failed, nodata]` 后，`no-rtt.ip-fallback.invalid` 保留原 hosts 地址，因为禁用探测不等于探测失败；AAAA 的 NODATA 演示仍会回退。

## 全部配置参数

```yaml
- tag: static_fallback
  type: ip_fallback
  args:
    ipv4: ["203.0.113.42", "198.51.100.42"]
    ipv6: ["2001:db8:ffff::42"]
    ttl: 86400
    on: [all_probes_failed, nodata]
```

| 字段 | 默认值与行为 |
| --- | --- |
| `ipv4` | 空列表；IPv4 目标字符串列表，按顺序返回并稳定去重。 |
| `ipv6` | 空列表；IPv6 目标字符串列表，按顺序返回并稳定去重。 |
| `ttl` | `86400` 秒；整数 `0..4294967295`，显式 `0` 表示即时返回且不缓存。 |
| `on` | 省略时为 `[all_probes_failed, nodata]`；显式 `[]` 关闭所有触发条件。列表内为 OR，未知条件启动报错。 |
| `on: all_probes_failed` | speedcheck 采用的合格地址集合全部取得已完成的失败结果时触发。 |
| `on: nodata` | 当前 A/AAAA 查询有合法 NOERROR 响应，沿 CNAME 链的终点没有同类型地址时触发。 |
| `on: no_rtt` | 已经过 speedcheck，但合格地址中没有任何成功 RTT 时触发，包含全失败、明确禁测、未匹配探测、未完成及排队受限；未经过 speedcheck 的原始响应不触发。 |

目标列表只接受对应地址族的裸 IP。CIDR、zone（如 `fe80::1%eth0`）、IPv4-mapped IPv6（如 `::ffff:192.0.2.1`）、地址族错误或无效地址会使启动失败。TTL 负值和超范围值也会启动报错。当前查询地址族的目标列表为空时保留原响应。

## 探测状态与默认行为

状态随当前响应快照传递；外层 `sequence/fallback` 采用某个分支时会保留该状态。新的普通响应清除旧状态，静态回退后也会清除原探测失败证据，避免重复执行时持续重置 TTL。

| 当前地址响应 | 默认 `all_probes_failed` | 显式 `no_rtt` |
| --- | --- | --- |
| 至少一个有效 RTT，包括 0 RTT | 保留 DNS 地址 | 保留 DNS 地址 |
| 所有合格地址均完成探测且全部失败 | 回退 | 回退 |
| 探测被明确禁用或未匹配 `probe_match` | 保留 DNS 地址 | 回退 |
| 有真实失败，也有未测量或尚未完成的地址 | 保留 DNS 地址 | 回退 |
| 容量不足、排队截止或选择窗口结束前未测完 | 保留 DNS 地址 | 回退 |
| 原始响应，没有 speedcheck 的状态 | 保留 DNS 地址 | 保留 DNS 地址 |

NODATA 是独立条件；若希望它与 `no_rtt` 一起触发，请使用 `on: [no_rtt, nodata]`。NXDOMAIN、SERVFAIL、查询错误和没有响应都不会被这个插件改成静态地址。查询失败的备用解析链仍由已有的 [`fallback`](configuration-reference.md) 插件处理。

参考 smartdns-test 的默认语义是“未测量仍可用，全部探测失败才回退”。当前实现进一步区分真实失败与容量或预算导致的未测量；后者默认保留 DNS 地址。`no_rtt` 是明确扩大回退范围的选项，不会将未测量结果写入真实失败的探测缓存。

## 来源与域名接线

先让来源完成过滤和可选的 [`ip_replace`](ip-replace.md)，再由 speedcheck 收集候选并探测。静态回退在最终选择之后调用：

```yaml
# 已定义 select_fast_ip 和 static_fallback；生产目标需替换文档地址。
- tag: main
  type: sequence
  args:
    - exec: $select_fast_ip
    - matches: ["qname domain:example.org"]
      exec: $static_fallback
    - matches: [has_resp]
      exec: accept
```

域名和 CNAME 条件由外层 sequence 的 `qname`、`cname` 等 matcher 控制。本插件没有重复的域名映射或 IP 标签配置；原始 DNS 候选的标签、ASN 倍率、过滤及 RTT 排名仍由 speedcheck 完成。静态目标是显式的最终策略，不重新调用来源，也不增加等待全部上游返回的屏障。

## TTL、响应重建与 DNSSEC

配置 TTL 为静态地址开启新的期限；无 CNAME 时不沿用旧地址 RRset 的短 TTL。存在 CNAME 时，保留同一规范化链和终点 owner，静态响应受链的剩余期限约束；若来源已经重建，还会保守继承其内部期限，因此实际 TTL 可能低于配置值。过期链不能借回退重新获得生存期。真正的 TTL=0 与正 TTL 老化后在线上取整为 0 的情形保持区分。

只处理合法 IN/A、IN/AAAA、NOERROR、非截断响应。DNAME、TSIG、SIG(0) 等不适合重建的合法消息保持原样；适用查询的响应先校验关联性和 CNAME 链，非法响应返回错误，交外层 fallback。客户端或当前查询 DO=1 时提前跳过，保持完整来源响应。生成 DO=0 正响应时移除不再适用的 SOA、签名及否定证明，清除 AD/AA，并清理连接相关 EDNS 选项。

响应使用独立快照，保留查询、marks、插件 kv 和客户端 EDNS 能力；父请求取消时传播取消。插件不处理 HTTPS/SVCB hint、ECH 或 ALPN，相关记录不会被此功能改写。

## 验证方式

本地逻辑测试使用假探测器和可控时间，覆盖全失败、禁测、混合、未完成、0 RTT、TTL/CNAME、DO、EDNS、不可变响应及外层 fallback 的状态提交；不将这些结果视为真实 CDN 网络性能。

```powershell
go test -race -p 2 ./plugin/executable/ip_fallback ./plugin/executable/speedcheck
go test ./plugin/executable/speedcheck -run 'TestIPFallback|TestOuterFallbackPreservesProbeStatus' -v
```
