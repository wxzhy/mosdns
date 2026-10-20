# 并行多上游选址 speedcheck

`speedcheck` 将多个已命名的 sequence 同时执行；任一来源完成过滤并返回 DNS 响应，就立即开始探测其终点地址。其他来源继续查询，不等待所有 DNS 到齐。每个来源应只有一个上游；单个 `forward` 内部的竞速会提前丢弃其他响应。

## 示例选择与启动

| 文件 | 用途与前置条件 |
| --- | --- |
| [基础完整流程](../examples/speedcheck.yaml) | 不依赖数据库；两个来源、域名/CNAME/响应过滤、外层静态 fallback、UDP/TCP 监听和 metrics |
| [全参数模板](../examples/speedcheck-full.yaml) | 显式展示全部 speedcheck、probe、倍率及两类 IPFilter 字段；需要 GeoIP 国家库与 MaxMind ASN 库 |
| [Windows 最小配置](../examples/speedcheck-windows.yaml) | Windows 上从最少配置启动，平台和 ping 说明见 [Windows 文档](speedcheck-windows.md) |

从项目根目录运行，配置和规则文件中的相对路径按工作目录解析；全参数模板引用的两个小型文本规则已放在 [examples/data](../examples/data)。上游地址、示例文档网段和静态地址应按自己的网络替换。两份配置使用相同端口，分别启动。

```powershell
go build -o .\mosdns.exe .
.\mosdns.exe start -c .\examples\speedcheck.yaml
```

Linux 对应使用 `go build -o ./mosdns .` 和 `./mosdns start -c examples/speedcheck.yaml`。默认监听本机 UDP/TCP `15353`，API 监听本机 `19091`。下面的静态兜底查询不访问外网，可先验证完整接线：

```text
nslookup -port=15353 fallback.speedcheck.invalid 127.0.0.1
curl http://127.0.0.1:19091/metrics
```

应得到文档地址 `192.0.2.10`（AAAA 为 `2001:db8::10`）。之后再查询普通域名，检查实际 DNS 和探测网络。Linux 可用 `dig @127.0.0.1 -p 15353 example.com A` 与加 `+tcp` 检查两种传输。此处静态地址只用于证明 fallback 接线；配置不会把所有失败域名改成同一个地址。

## 参数

| 参数 | 默认 | 含义 |
| --- | --- | --- |
| `sources` | 必填 | 已在此前定义的 executable/sequence 标签列表，顺序用于平分时裁决 |
| `mode` | `bounded` | `bounded` 限时选优；`wait_all` 等所有来源及相关探测 |
| `total_timeout` | `5s` | 总预算，同时受父请求截止时间限制 |
| `selection_timeout` | `300ms` | bounded 首个合格正答到达后的等待上限 |
| `settle_window` | `25ms` | bounded 首个成功探测后的收集窗口，后续结果不重置 |
| `probe.tcp_ports` | `[80,443]` | 并行 TCP connect，成功立即关连接；显式 `[]` 禁用 TCP |
| `probe.icmp` | `false` | ICMP 与 TCP 并行，任一方法成功即取消其余方法 |
| `probe.timeout` | `300ms` | 单次实际探测预算 |
| `max_num` | `1` | 1–64，输出地址上限；客户端 DO=1 时保留完整来源 RRset |
| `threshold_ms` | `100` | 与最佳加权分数的最大差，可显式设为 0 |
| `labels` | 空 | 标签到 IP 匹配表达式列表的映射；用于权重、过滤及多 IP 分组 |
| `tag_multipliers` | 空 | 有序 `{tag, multiplier}` 列表，首个命中项生效 |
| `asn_multipliers` | 空 | ASN 整数到倍率的映射，标签倍率均未命中时使用 |
| `candidate_filter` | 未配置 | 来源候选过滤，支持下表中的全部字段 |
| `probe_match` | 未配置 | 使用相同字段限制探测启动；不丢弃有效候选 |

`candidate_filter` 与 `probe_match` 的子字段完整如下。所有名称必须是已声明标签，ASN 必须能从本地默认 ASN 数据库加载。

| 字段 | 未配置时 | 示例 |
| --- | --- | --- |
| `labels_include` | 不增加 include 条件 | `[domestic, preferred]` |
| `labels_exclude` | 不按标签排除 | `[blocked]` |
| `asn_include` | 不增加 include 条件 | `[13335, 15169]` |
| `asn_exclude` | 不按 ASN 排除 | `[64512]` |

bounded 在收集窗口、首正答上限、总预算、全部工作完成中最早结束。wait_all 忽略两个收集窗口，但仍有总预算。在总预算和父截止中较早的时刻之前预留 `min(50ms, 剩余时间/2)` 给回包。父取消直接返回取消错误。截止后冻结结果并解除探测订阅；迟到结果不能改变父响应。

## 标签、倍率和过滤

`labels` 是名称到 IP 匹配表达式列表的映射，列表内按 OR 匹配。支持 CIDR/IP、`$ip_set标签`、`&文件`，以及已有的 `geoip:cn`、`asn:13335`、`ext:文件:代码` 表达式。数据库沿用现有 IPSet/GeoIP 组件。标签集合由所有声明标签组成，不能只声明参与倍率的标签就假定它与其他网络同组。

下面是完整的选择器参数块；引用的来源、IPSet 和规则文件在 [全参数模板](../examples/speedcheck-full.yaml) 中定义。`geoip:cn` 按顺序寻找工作目录中的 `geoip.dat`、`geoip.metadb`、`Country.mmdb`、`geoip.mmdb`，使用第一个存在的文件，需包含 CN 数据。`asn:`、数字 ASN 倍率及过滤器按顺序寻找 `ASN.mmdb`、`GeoLite2-ASN.mmdb`、`asn.mmdb`，必须是受支持的 ASN 类型 MaxMind 数据库。数据库不随示例附带，也不会自动下载；缺失、损坏或 ASN 类型不兼容会使初始化失败。DAT 缺少指定代码会报错；MMDB 未覆盖的地址或国家/ASN 则不会命中。只想使用 CIDR/文本标签时运行基础示例即可。

```yaml
- tag: select_fast_ip
  type: speedcheck
  args:
    sources: [source_a, source_b]
    mode: bounded                 # wait_all 仍并行，只是等待全部工作终结。
    total_timeout: 5s
    selection_timeout: 300ms
    settle_window: 25ms
    probe:
      tcp_ports: [80, 443]         # [] 禁用 TCP，省略则使用默认端口。
      icmp: false                 # 改为 true 启用 pro-bing，与 TCP 并行。
      timeout: 300ms
    max_num: 2
    threshold_ms: 100
    labels:
      preferred: ["$preferred_networks"]
      domestic: ["geoip:cn"]
      global: ["0.0.0.0/0", "::/0"]
      blocked: ["$blocked_networks"]
      do_not_probe: ["198.18.0.0/15"]
      file_networks: ["&examples/data/speedcheck-preferred-ips.txt"]
      cloudflare: ["asn:13335"]
    tag_multipliers:
      - {tag: preferred, multiplier: 0.8}
      - {tag: domestic, multiplier: 1.0}
    asn_multipliers: {13335: 0.9, 15169: 1.1}
    candidate_filter:
      labels_include: [global, domestic, preferred]
      labels_exclude: [blocked]
      asn_include: [13335, 15169]
      asn_exclude: [64512]
    probe_match:
      labels_include: [global]
      labels_exclude: [do_not_probe]
      asn_include: [13335]
      asn_exclude: [64512]
```

倍率必须有限且大于 0。按 `tag_multipliers` 列表首个命中项取值，未命中才使用 ASN 倍率，其余为 1。`global` 标签让完整模板的标签 include 覆盖所有地址，展示 include/exclude 接线；如需限定国家或网络，应删除它在 include 列表中的引用。

过滤以每份完整来源响应为单位：任一终点地址命中 exclude 即拒绝该来源；include 的标签和 ASN 两类为 OR，任一地址命中即保留。省略两类 include 不限范围；显式 `labels_include: []` 且没有其他 include 命中时拒绝所有正答。`probe_match` 使用同样的整份来源规则：任一地址命中其 exclude，该来源的所有地址都不启动新探测；include 命中一个地址则该来源全部地址可启动探测。未匹配来源仍是有效候选，同 IP 已由其他合格来源取得的共享 RTT 也可以复用。域名/CNAME 过滤放在来源 sequence 中。来源应返回同一个问题的响应，不能通过修改查询名称提交另一域名的答案。

有有效 RTT 时优先按 `RTT_ms × multiplier` 排序，0 RTT 有效；同分按来源、原记录顺序和 IP 排序。多地址要求与最佳地址完整标签集合一致且分差不超过阈值。全部探测失败或未完成时仍可使用合格 DNS 地址，按倍率稳定排序，不受标签同组和分差限制。若所有来源错误、非法或被过滤，返回错误交外层 `fallback`；NXDOMAIN/NODATA 保留完整来源语义。

若需将测速失败结果改为静态 IP，在选择器之后、`accept` 之前显式调用 [`ip_fallback`](ip-fallback.md)。它默认只处理全部真实探测失败或 NOERROR/NODATA，不把关闭测速、队列不足或未完成当作失败；`on: [no_rtt, nodata]` 可额外选择在没有成功 RTT 时回退。无响应/来源错误继续使用已有外层 `fallback` 执行链；DNSSEC DO=1 跳过静态重建。可直接运行的无公网、无主动测速示例见 [ip-fallback.yaml](../examples/ip-fallback.yaml)。

## 来源过滤、fallback、监听和缓存的接线

完整文件按“数据集 → 单上游 forward → 来源 sequence → speedcheck → fallback → main → 监听器”顺序声明。插件引用必须指向此前定义的标签；`exec: $标签`、`sources: [标签]` 与 `fallback.primary/secondary: 标签` 的写法不同。

来源示例先按查询域名跳过不适用的来源，再查询并过滤响应。`return` 在此结束独立来源、产生无响应；不要用 `reject` 替代，它会生成一份合法错误响应。`drop_resp` 清空响应使选择器忽略该来源，不能把被拒绝地址泄露给后续选址。

```yaml
- tag: source_a
  type: sequence
  args:
    - matches: ["qname $skip_source_domains"]
      exec: return
    - exec: $upstream_a
    - matches: ["cname domain:blocked-cname.invalid"]
      exec: drop_resp
    - matches: ["resp_ip $blocked_networks"]
      exec: drop_resp
    - matches: ["rcode 2 5"]        # SERVFAIL / REFUSED；不删除正常 NXDOMAIN。
      exec: drop_resp
```

这里 `resp_ip` 检查 Answer 内的 A/AAAA；选择器自身的 `candidate_filter` 仅检查 CNAME 终点地址，范围不同。一个 `matches` 列表中多个条件为 AND，单个 matcher 内的多个取值一般为 OR。慢过滤也会推迟此来源开始测速，因此只把提交候选必需的处理放在来源中；写 ipset/nftset 等副作用放在最终选择后。

若需替换 CDN IP，先声明 [`ip_replace`](ip-replace.md)，再在每个来源的查询和必需过滤之后调用；不能放在最终 speedcheck 选址之后：

```yaml
# replace_cdn 和 source_response_filters 应在来源之前定义。
- tag: source_a
  type: sequence
  args:
    - exec: $upstream_a
    - exec: $source_response_filters
    - exec: $replace_cdn
# source_b 同样依次调用 upstream_b、过滤、replace_cdn。
```

来源返回后，候选标签、ASN 权重、过滤、探测和缓存均采用替换地址；相同目标可跨来源共享 RTT。替换不增加收齐屏障，其他来源继续并行查询。客户端或查询 DO=1 时跳过替换。无需外网、不会真实探测文档地址的独立演示见 [ip-replace.yaml](../examples/ip-replace.yaml)。

基础示例的 `fallback.speedcheck.invalid` 同时在两个来源中被跳过，外层 fallback 随主分支失败立即取静态 hosts。`fallback.threshold` 的单位为毫秒，`5000` 与默认选择总预算配合，避免静态答案在正常选择窗口之前抢先返回。有效 NXDOMAIN/NODATA 是成功结果，不会自动触发兜底。`always_standby: true` 会立即准备 secondary，在阈值或主分支失败后才能采用它；静态主机仅配置明确允许的域名。

```yaml
# 省略此前已定义的 select_fast_ip 与 static_fallback。
- tag: resolve_with_fallback
  type: fallback
  args:
    primary: select_fast_ip
    secondary: static_fallback
    threshold: 5000
    always_standby: false
- tag: main
  type: sequence
  args:
    - exec: $resolve_with_fallback
    - exec: accept
- tag: udp_listener
  type: udp_server
  args:
    entry: main
    listen: "127.0.0.1:15353"
- tag: tcp_listener
  type: tcp_server
  args:
    entry: main
    listen: "127.0.0.1:15353"
    idle_timeout: 10               # 秒
    cert: ""                      # cert/key 都空为普通 TCP；同时提供则启用 TLS。
    key: ""
```

metrics 的开关在顶层，不放在插件 `args` 中：

```yaml
log:
  level: info
api:
  http: "127.0.0.1:19091"           # GET /metrics
plugins: []                       # 实际配置替换为上面的插件列表。
```

全参数模板定义了未调用的普通响应缓存，并展示其全部字段。要启用，在 `main` 中先执行 `$response_cache`，然后用 `has_resp`/`accept` 截住缓存命中，再执行 `$resolve_with_fallback`。cache 是递归执行器，命中与未命中都会继续链；缺少这个条件退出时仍会重新进入选择器。未命中时后续响应会回到 cache 保存。它与内置原始 RTT 缓存不同，配好条件退出后，命中响应缓存会跳过这一轮选址；lazy stale 响应还可能延长旧选择，因此示例保持禁用调用、`lazy_cache_ttl: 0`。`dump_interval` 为秒，`dump_file` 非空时才持久化，父目录需存在且可写。

```yaml
- tag: response_cache
  type: cache
  args:
    size: 1024
    lazy_cache_ttl: 0
    dump_file: ""
    dump_interval: 600
# main.args 启用时：
# - exec: $response_cache
# - matches: ["has_resp"]
#   exec: accept
# - exec: $resolve_with_fallback
# - exec: accept
```

探测 RTT 缓存容量/TTL、socket/队列上限是当前实现常量，未提供 `speedcheck` YAML 配置项。`probe` 只有 `tcp_ports`、`icmp`、`timeout`，没有 SOCKS、网卡绑定或自定义缓存字段。

## DNS 响应保护

仅 IN/A、IN/AAAA 探测和改写；其他类型竞速取得合法完整来源响应。检查 QR、Opcode、Question、ID，追踪唯一、无环、最多 16 跳 CNAME，只探测终点同类型同类别 RRset；无关 Answer 和 Additional 地址不参与。

使用最佳地址的来源作为骨架。仅规范化完整 CNAME 链、终点、问题类型/类别及 ECS 查询视图兼容的来源可合并。不同终点或中间链不同的响应分别竞争，不改名拼接。同 IP 可以共享 RTT，但来源响应和期限始终各自保存。输出 TTL 消耗收集和探测时间，同一合成 RRset 采用贡献来源共同的最早期限，CNAME 不延寿；TTL=0 可立即返回，不能缓存。

客户端 DO=1 时传递 DO 并选取完整来源，不裁剪、合并或按 `max_num` 截断。DO=0 合成响应清除 AD/AA，删除失效的签名和证明记录；DNAME、TSIG 等不适合重建的响应保留整份来源。响应 OPT、上游 OPT 和下游 OPT 独立保存，提交不覆盖父 query、marks 或插件 kv。DoH 受控分支继承取消并扣除 HTTP Age；取消不会关闭共享 HTTP 客户端。

## 资源、缓存和平台

每个 Mosdns 实例共享一个探测管理器：最多 128 个实际探测 socket、1024 个排队方法、每请求采用最多 64 个唯一 IP，按来源配置顺序和记录顺序截断。每请求累计向探测管理器提交至多 64 个不同 IP；若晚到的前序来源替换了候选集合，新地址超出此预算时按未测量处理，仍可参与倍率回退，避免为确定性排序阻塞先到响应的探测。缓存命中和共享飞行等待不占 socket。队列满、取消和排队截止记为未测量，不写失败缓存。单个请求退出仅解除自己的订阅；最后等待者退出才取消共享任务。实例关闭会取消并等待资源回收。

排队最多等待 `probe.timeout`，获得名额后每个实际方法再获得完整的 `probe.timeout`；二者分开计时，避免排队挤占探测预算而误写失败缓存。请求的选择窗口和总截止仍可随时解除订阅，不会为排队延长请求预算。

原始 RTT 的 LRU 缓存容量 10000，成功 60s，真实失败 5s，键包含 IP、规范化端口集合、ICMP 配置与超时。探测通过系统直连路由；上游 forward 的 SOCKS、设备绑定和 mark 不会作用于目标 IP 探测。管理器没有不同网络配置共用一个键的入口。缓存不保存权重、来源或最终排名。基础示例不包最终响应缓存；全参数模板定义但默认不调用这一层。启用时须按前述 `cache` → `has_resp` / `accept` 接线，命中才会绕过重新选址。

ICMP 后端使用 `prometheus-community/pro-bing v0.9.1` 的单包 `RunWithContext`，由库处理 ICMP 报文和回包关联。Linux 优先非特权模式，必要时尝试 raw ICMP；Windows 按库要求使用 `SetPrivileged(true)` 的 raw 模式，该设置不等于所有 Windows 机器都必须提升权限。启用 ICMP 会先用同一后端做 loopback 能力检查；不可用且配置 TCP 时记录诊断后保留 TCP；仅 ICMP 且无可用接口时启动报错。成功回调立即参与选择，socket 名额在库实际退出后才释放。Linux 权限取决于 `ping_group_range` 或 `CAP_NET_RAW`，容器也可能受网络策略限制。TCP connect RTT 表示连接可达和建连速度，不是 HTTP 应用耗时。Windows 启动和平台限制见 [Windows 说明](speedcheck-windows.md)。

指标由已有 `/metrics` 暴露：`mosdns_speedcheck_*` 记录来源接受/拒绝、选择耗时、RTT/倍率/负答等结果、探测结果及缓存命中，`fallback_total{reason}` 区分全失败、未测、混合、负答与无候选；`mosdns_speedcheck_manager_*` 记录探测 socket 名额、队列、共享任务、缓存和探测次数。不用域名或动态 IP 作为指标标签。来源 executable 应响应 context，实例关闭会等待其退出。

## 验证

```text
go test ./pkg/response ./pkg/speedtest ./pkg/query_context ./pkg/upstream/doh ./plugin/executable/forward ./plugin/executable/speedcheck ./coremain
go test -race ./...
go test ./plugin/executable/speedcheck -run TestStreamingOverlapsDNSAndProbe -v
go test ./plugin/executable/speedcheck -run '^$' -bench . -benchmem
go test ./pkg/speedtest -run '^$' -bench BenchmarkLocalTCPProbe -benchmem
GOOS=linux GOARCH=arm64 go build ./...
GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build ./...
```

可控时钟测试用于验证窗口与流式执行顺序；本地 TCP/ICMP 测试用于验证 socket 与取消路径。基准中的假来源、逻辑延时和本机资源开销必须分开报告。Linux/OpenWrt 目标机吞吐、CPU 和真实网络 p50/p95/p99 需在目标硬件另行测量，不能用 Windows 或 WSL 数据代替。
