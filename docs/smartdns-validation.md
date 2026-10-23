# 两份 SmartDNS 配置功能验证

2026-10-20，Windows，本仓库当前工作区。两份配置均可启动，功能链检查通过，
公网主链可以解析；当前网络存在两个不可达上游、`wait_all` 延时和 Google 探测失败。
CERNET 配置是在本机当前网络测试，并非 CERNET 目标节点验收。

本次没有修改生产插件或两份部署 YAML。新增三份持续回归测试：

- [受控策略与完整主链](../smartdns_policy_test.go)
- [真实规则/MMDB 策略](../smartdns_realdata_policy_test.go)
- [真实 UDP/TCP 服务与缓存](../smartdns_wire_test.go)

## 本地功能

| 检查 | 结果与证据 |
|---|---|
| 严格配置解码、默认数据库路径与插件依赖 | 通过，两份完整配置实际初始化 |
| 广告/代理、分流优先级 | 通过，真实域名规则；广告抢先于 Google/CN 规则 |
| UDP/TCP 与事务关联 | 每轮 40 次真实回环请求；连续 3 轮通过，检查 QR、ID、Question 与 Rcode |
| 静态记录和最终缓存 | 通过，广告 A/AAAA 为 127.0.0.1/::1，TXT 为 NOERROR 空答；两配置代理地址、约 86400 秒 TTL 和缓存命中正确 |
| 来源过滤与域名豁免 | 通过，AS19679 独立过滤、混合 RRset 整份拒绝、Dropbox/CNAME 豁免均实际执行 |
| CDN 替换后测速 | 通过，Cloudflare/CloudFront/GitHub raw 优先级、Fastly IPv4 /22 与 IPv6 /64、ASN33191 普通/CERNET 差异、仅探测替换地址 |
| CNAME、DO 与负响应 | 通过，替换排除、DO 保护、合法 NXDOMAIN 不落入其他路由或静态回退 |
| 测速失败回退 | 通过，真实失败与私网未测量区分，Google AAAA 按条件回退 |
| HTTPS 策略 | 通过，原 hint 先过滤再清理、hint/H3 无条件清理、ECH 门控、完整 A 子查询与缓存，无递归 |
| 关闭回收 | 通过，实例等待关闭完成，UDP/TCP 端口可重新绑定 |

代理用例检查 DNS 返回内容；CERNET 的 `2001:db8::64` 仍是原配置保留的占位地址，
正式部署需换成实际代理 IPv6。本次没有验证代理服务可达性。

这些策略检查使用原 YAML 的 sequence/插件；只有 DNS/probe I/O 被替换。
真实数据模式直接读取 `data/smartdns`，没有用 fixture CIDR 代替 MMDB。
回环服务检查保留全部插件，仅改变监听地址、日志和禁止缓存落盘。

```powershell
$env:MOSDNS_SMARTDNS_LOCAL_DATA = "1"
go test -race . -run '^TestSmartdns' -count=1 -timeout=180s
go test . -run '^TestSmartdnsMigrationLocalWire$' -count=3 -timeout=120s
Remove-Item Env:MOSDNS_SMARTDNS_LOCAL_DATA
go vet ./...
```

上述 race 和 vet 通过；wire 连跑 3 次通过。

## 当前网络实测

使用当前工作区构建的 CLI，临时副本只将 UDP/TCP/API 监听绑定到回环随机端口。
通过实际服务查询 `www.baidu.com`、`google.cn`、`google.com`、`example.com`、
`raw.githubusercontent.com`、`example.geek`，覆盖 A/AAAA/HTTPS 与各动态路由。
每次检查响应事务、问题区、Rcode 与可解析的 Answer。

| 检查 | 普通配置 | CERNET 配置 |
|---|---|---|
| 原配置动态 UDP 查询 | 11/11 NOERROR，均有 Answer | 11/11 NOERROR，均有 Answer |
| 成功 A 查询改用 TCP 复查 | 3/3 NOERROR，约 1.47–2.50ms | 3/3 NOERROR，约 2.97–7.47ms |
| 独立上游诊断 | 25/27 NOERROR | 14/16 NOERROR |
| 查询后探测资源 | active/queued/flights 全为 0 | active/queued/flights 全为 0 |

独立诊断保留原 forward 参数，通过额外的回环 HTTP 入口逐一执行活跃来源和
Google-cn/OpenNIC/ECH forward 池，每个入口查询一次 `example.com A`。
它检验该次请求的连通性，不表示每个域名、所有时刻或池内每个成员都已验证。
配置中的 DoH 来源本次均取得响应。

两份配置各有两个失败入口，实际对应同一对地址：

| 地址 | 普通配置入口 | CERNET 配置入口 | 绕过 mosdns 复查 |
|---|---|---|---|
| `114.114.115.115` | `upstream_114dns_2` | `upstream_114dns_2` | 原生 UDP 连续 3 次各等待 2s，全部超时 |
| `218.4.4.4` | `upstream_isp_2` | `upstream_telecom_2` | 原生 UDP 连续 3 次各等待 2s，全部超时 |

`114.114.114.114`、`119.29.29.29`、Google IPv4/IPv6 DNS 的对照查询成功。
失败地址在本机当前网络不可达，正式部署时应按目标网络替换或剔除。

### 延时对照

仅在临时副本中把 `select_default.mode` 改成 `bounded`，保留上游和其他参数：

| 查询 | 原 `wait_all` | 临时 `bounded` |
|---|---:|---:|
| 普通 `example.com A` | 4955.99ms | 183.24ms |
| 普通 `example.com AAAA` | 4953.35ms | 207.07ms |
| CERNET `example.com A` | 4956.22ms | 175.97ms |
| CERNET `example.com AAAA` | 4955.15ms | 213.90ms |

四次对照均返回 NOERROR。这是单次本机网络样本，不是目标机性能基准。
原配置的 `wait_all` 会等待失败/慢来源至预算结束；若优先响应延时，可选择
`bounded`，但晚到来源可能不参与本次选择。两份部署 YAML 没有自动改模式。

### 探测与回退

默认仅 ICMP。Google 的 A/AAAA 在本次网络测试出现全部探测失败；IPv4 保留来源
地址，IPv6 则实际返回原配置的六条静态回退地址。因此 Google IPv6 当前结果来自
回退，不能解释为已测得的最快 IP。

另用临时副本并行启用 TCP 80/443 与 ICMP：六次动态查询仍为 NOERROR，
Google 的探测失败和 IPv6 回退仍出现，不能把增加 TCP 端口当作已验证的解决方案。
GitHub raw 的选址发生变化。可达性及探测方法仍需在目标网络评估。

## 整仓回归边界

配置相关 race 通过，`go vet ./...` 通过。
`go test ./... -count=1 -timeout=180s` 本次**未全部通过**：

- `Test_fastUpstream` 的 UDP、大报文、零延时子用例超时。
- `Test_DoT_ech_dns_query` 超时。

两项随后独立运行五轮均通过：

```powershell
go test ./pkg/upstream -run '^(Test_fastUpstream|Test_DoT_ech_dns_query)$' -count=5 -timeout=120s
```

这表明失败未稳定复现；不能据此抹去整仓失败，也尚未确认根因。
本次按既定范围单独记录上游回归问题，没有将配置测试通过表述为整仓全绿。

本地原始记录保留于 `.reference/smartdns-validation/`：`network.json`、
`upstreams.json`、`rechecks.json`、`bounded.json`、`tcp-probes.json`。
该目录由 Git 忽略，不是运行配置的数据依赖。

本次测试的配置 SHA-256：

```text
config.yaml        76344d04ab5b7863f69c4788e64513123a8e55a71d646605490ad3abd2493cde
config-cernet.yaml 6e62a6bec9ecd9e44d7f3af2a414248c69f0b568fb16697a00cc3dcc382548fc
```
