# 配置参数与全模块示例

本文按本仓库 `coremain.Config`、`plugin/enabled_plugins.go` 和各插件实际注册入口整理。示例分为可直接启动的最小配置，以及需要按用途选用的模块片段。除特别说明，路径相对于进程工作目录，即 `mosdns start -d` 指定的目录，不相对于 YAML 文件目录；引用其他插件时须先定义被引用插件。

可复制的 [全模块参数模板](examples/all-modules.yaml) 集中展示全部顶层插件字段，并用独立 sequence 展示快速动作。该模板需要数据库、规则文件和证书，须按用途裁剪；无需这些资源的测速配置见 [基础示例](../examples/speedcheck.yaml)。

`speedcheck` 的完整参数、并行时序、标签、ASN 和过滤示例见 [speedcheck](speedcheck.md)、[Windows 运行说明](speedcheck-windows.md) 及 [完整测速示例](../examples/speedcheck-full.yaml)。本页同时覆盖其余全部已启用模块，不能把所有片段直接拼成一个生产配置：有些动作互斥，有些依赖数据库、证书或 Linux 防火墙集合。

系统服务的运行账户、配置读取及可写路径要求见[低权限系统服务](service.md)。启用服务沙箱后，相对路径仍按工作目录解析；日志和缓存输出需放入允许写入的目录。

`ip_replace` 支持按前缀替换 CDN 地址；[独立说明](ip-replace.md) 包含计算方式与测速接线，[本地演示](../examples/ip-replace.yaml) 使用 hosts 生成原响应，无需外网或数据库。

[全模块 YAML 参数模板](examples/all-modules.yaml) 将全部顶层插件和完整参数汇集到同一文件，可用于严格解码检查；文件顶部列出了外部资源要求。模块片段适用于插入 `plugins` 列表，动作片段适用于 sequence 的 `args` 列表。

## 一个可启动的配置

以下配置不需要数据库或证书，监听本机 UDP/TCP 15353。上游地址需按实际网络替换。

```yaml
log:
  level: info
  production: false
include: []
api:
  http: "127.0.0.1:9091"
plugins:
  - tag: upstream
    type: forward
    args:
      concurrent: 1
      upstreams:
        - tag: dns_a
          addr: "udp://1.1.1.1:53"
  - tag: main
    type: sequence
    args:
      - exec: $upstream
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
      idle_timeout: 10
```

运行：`mosdns start -d /path/to/workdir -c config.yaml`；Windows 路径示例见 Windows 说明。查询：`nslookup -port=15353 example.com 127.0.0.1`。

## 顶层与通用插件字段

| 字段 | 类型、默认值与行为 |
| --- | --- |
| `log.level` | 字符串；空值按日志库采用 `info`。可用 `debug`、`info`、`warn`、`error`、`dpanic`、`panic`、`fatal`。 |
| `log.file` | 字符串；空值写 stderr；非空时写指定文件。 |
| `log.size` | 文件轮转阈值，默认 `5M`；支持 K/KB、M/MB、G/GB、T/TB，按 1024 进位。无单位按 MiB，如 JSON 字符串 `"1"` 表示 1 MiB。仅文件输出使用。 |
| `log.backups` | 默认 0，不保留轮转备份；正数限制备份数量，负数保留全部。 |
| `log.production` | 布尔，默认 `false`；`true` 使用 JSON 日志。 |
| `include` | YAML 配置文件路径列表，默认空；先递归加载 include 中的插件，再按顺序加载本文件插件。递归加载有深度上限，避免循环 include。子文件的 `log`/`api` 不覆盖主文件设置；子文件不得设置非空 `geodata` 默认路径，即使与根配置相同也报错；空对象与未指定等价。 |
| `geodata.geosite` | 空；为本实例的 `geosite:` 表达式指定默认 *ray GeoSite dat 文件。未指定时使用工作目录中的 `geosite.dat`。 |
| `geodata.geoip` | 空；为本实例的 `geoip:` 表达式指定默认 GeoIP dat / MaxMind 数据库。未指定时按下文列出的文件名顺序寻找。 |
| `geodata.asn` | 空；为本实例的 `asn:` 表达式及 speedcheck 数字 ASN 倍率、过滤指定默认 MaxMind ASN 数据库。未指定时按下文列出的文件名顺序寻找。 |
| `plugins` | 插件列表；逐项初始化。 |
| `plugins[].tag` | 可选名称；省略时按类型和当前插件数量自动生成 tag。需要被 `$tag`、`sources`、`entry` 等引用时应显式命名。 |
| `plugins[].type` | 必填，已注册的顶层插件类型。 |
| `plugins[].args` | 参数结构取决于类型；`sequence` 为规则列表，其余通常为对象。 |
| `api.http` | 监听地址，空值不启动 API；提供 `/metrics`、`/debug/pprof` 及插件 API，无内置认证。示例绑定回环地址。 |

```yaml
log:
  level: info
  file: "./mosdns.log"              # 留空则输出到 stderr
  size: "5M"
  backups: 0
  production: true
include:
  - "./providers.yaml"             # 被引用的 providers 先加载
  - "./upstreams.yaml"
geodata:                            # 仅在根配置声明，所有 include 共享
  geosite: "./data/geosite.dat"
  geoip: "./data/Country.mmdb"
  asn: "./data/ASN.mmdb"
api:
  http: "127.0.0.1:9091"
plugins: []
```

未声明字段会被配置解码器拒绝。Go `time.Duration` 字段使用 `300ms`、`5s` 等带单位字符串；本页明确标注为整数秒/毫秒的字段不能写成这种字符串。

`geodata` 是每个 Mosdns 实例的配置，适用于 provider、sequence 行内 matcher、`ip_replace`、`https_record` 和 `speedcheck` 等公共表达式入口。路径仍相对于进程工作目录；显式 `ext:文件:代码` 始终使用指定文件，不受默认路径影响。已配置的文件缺失、损坏或格式不兼容时，在首次使用相应数据库初始化插件时返回错误，不改用其他候选文件。数据库不会自动下载或热重载，修改路径或数据后需要重启。

## 数据集合：domain_set、ip_set

两个类型都是数据提供器，不直接发起查询或生成响应。集合项之间采用 OR；引用已有集合的 `sets` 填 tag，不带 `$`。

| 类型 | 全部 `args` 字段 | 默认值 |
| --- | --- | --- |
| `domain_set` | `exps`: 域名表达式字符串列表；`sets`: 已有 domain_set tag 列表；`files`: 文本域名规则文件列表 | 全部空 |
| `ip_set` | `ips`: IP/CIDR/GeoIP/ASN 表达式列表；`sets`: 已有 ip_set tag 列表；`files`: 文本 IP/CIDR 文件列表 | 全部空 |

```yaml
- tag: local_domains
  type: domain_set
  args:
    exps:
      - "full:router.example"        # 精确域名
      - "domain:example.org"         # 本域及子域
      - "keyword:tracker"
      - 'regexp:^ad[0-9]+\.example$'
    sets: []
    files: []                        # 如 ./rules/domains.txt，每行一个表达式
- tag: all_local_domains
  type: domain_set
  args:
    exps: ["full:nas.example"]
    sets: [local_domains]
    files: []
- tag: local_ips
  type: ip_set
  args:
    ips: ["192.168.0.0/16", "fd00::/8", "127.0.0.1"]
    sets: []
    files: []                        # 如 ./rules/ips.txt，每行一个 IP/CIDR
- tag: all_local_ips
  type: ip_set
  args:
    ips: ["10.0.0.0/8"]
    sets: [local_ips]
    files: []
```

普通 `domain_set` 表达式支持 `full:`、`domain:`、`keyword:`、`regexp:` 前缀；不带前缀时默认为 domain（本域及子域）。文件允许空行及 `#` 注释。`files` 加载普通文本规则，不根据扩展名自动把文件当作 GeoSite/GeoIP 数据库。

数据库表达式必须在相应数据库可读时才启用：

```yaml
- tag: sites_from_database
  type: domain_set
  args:
    exps:
      - "geosite:cn"                 # 上文 geodata.geosite 指定的文件
      - "geosite:google@cn"
      - "ext:./data/other-geosite.dat:google@cn" # 显式覆盖默认文件
      # ext-domain:、ext-site: 为 ext: 的别名；多个 @attr 使用 AND
    sets: []
    files: []
- tag: ips_from_database
  type: ip_set
  args:
    ips:
      - "geoip:cn"
      - "asn:AS13335"
      - "geoip:US"
      - "asn:15169"
      # ext-ip: 为 ext: 的别名
    sets: []
    files: []
```

未配置对应 `geodata` 路径时，`geosite:` 使用工作目录中的 `geosite.dat`；`geoip:` 依次寻找 `geoip.dat`、`geoip.metadb`、`Country.mmdb`、`geoip.mmdb`；`asn:` 及 speedcheck 数字 ASN 倍率、过滤依次寻找 `ASN.mmdb`、`GeoLite2-ASN.mmdb`、`asn.mmdb`，使用第一个存在的文件。GeoIP 格式按文件内容识别，支持 *ray dat 和 MaxMind；ASN 需要受支持的 ASN 类型 MaxMind 数据库。GeoSite 仅支持 *ray dat，不读取 SmartDNS 的 trie 或文本目录；导出的普通文本仍通过 `domain_set.files` 加载。可用代码及属性由实际数据库决定，多个 `@attr` 使用 AND；ASN 支持纯数字或 `AS` 前缀。数据实现与普通 CIDR matcher 均可在 Windows 使用，它们和下文操作 Linux 防火墙的 `ipset` 动作不同。

### adblock_set：广告域名规则

`adblock_set` 是域名数据提供器，参数为 `files`（文本文件路径列表，默认空）；通过 `matches: qname $tag` 引用，由 sequence 决定返回黑洞地址或拒绝响应。它与 `domain_set` 使用同一 provider 接口，保留 [sbwml 207/208/210 及 229 号补丁](https://github.com/sbwml/luci-app-mosdns/tree/dbdd91ab8ac8b079b6a3ca1a48d99e970d17111b/mosdns/patches) 的解析语义：

- 裸域名匹配自身和子域名；`^example.org`、`full:example.org` 限制为完整匹配，`domain:example.org` 为域名后缀匹配。
- 支持 `||example.org^`、`@@` 例外、正则和关键词规则，以及 hosts 格式、多域名 hosts 行和行尾注释。
- 例外规则优先于拦截规则。HTTP 路径、元素隐藏等规则按解析器规则跳过，不参与 DNS 域名匹配。

```yaml
- tag: blocklist
  type: adblock_set
  args:
    files: ["./rules/blocklist.txt", "./rules/disable-ads.txt"]
- tag: reject_ads
  type: sequence
  args:
    - matches: qname $blocklist
      exec: reject 3
```

初始文件缺失、读取或整份加载失败时初始化失败，无法识别的单条规则按原补丁跳过。文件修改或替换后自动重新加载并切换完整 matcher；重新加载失败保留上一份有效规则。基于 206 号补丁的轮询加载器也用于 `domain_set`、`ip_set`、`redirect`、`hosts`、`arbitrary` 的文本文件，识别文件原子替换。GeoSite/GeoIP/ASN 数据库加载仍按其缓存与启动语义处理。

## sequence 规则与控制流

`type: sequence` 的 `args` 是规则列表；每条规则只有两个用户字段：`matches`（可省略的字符串列表）与 `exec`（动作字符串，必填）。同一 `matches` 中条件为 AND；各条件内部的多个值通常为 OR。前缀 `!` 取反，字符串应加引号防止 YAML 类型解释。只有匹配时才执行动作；动作错误会终止本条执行链，不能靠后面的普通规则捕获错误。

```yaml
- tag: check_private
  type: sequence
  args:
    - matches: ["qname $local_domains", "qtype 1 28"]
      exec: mark 10
    - exec: return
- tag: main
  type: sequence
  args:
    - exec: jump check_private
    - matches: ["mark 10"]
      exec: $hosts_local
    - matches: ["has_resp"]
      exec: accept
    - exec: $upstream
    - exec: accept
```

| 动作 | 参数、示例与行为 |
| --- | --- |
| `$tag [参数]` | 使用已有可执行插件；如 `$upstream dns_a` 可选择 forward 内已命名上游。不是每种插件都接受尾随参数。 |
| `accept` | 无参数；立即结束链，保留当前响应，不自动生成响应。 |
| `reject [rcode]` | 默认 `5`（REFUSED）；可写 `reject 3`（NXDOMAIN）或 `reject 0`（NOERROR 空响应）；rcode 为整数 0–4095。生成响应并结束链。 |
| `return` | 无参数；结束当前子链并返回 jump 的后续规则；顶层则结束。 |
| `jump tag` | 调用已有 sequence，执行完毕返回调用位置后续规则。tag 不带 `$`。 |
| `goto tag` | 转入已有 sequence，不再返回调用位置。tag 不带 `$`。 |

注册表中的 `RuleConfig`、`MatchConfig` 是内部解析表示；不要把 `type`、`tag`、`args`、`reverse` 填进 sequence 的每条 YAML 规则。用户入口是上述字符串语法。

### 所有匹配条件

以下条件在 `matches` 中快速配置，不是顶层 `plugins[].type`。`rate_limiter` 是例外：先声明顶层实例，再用 `$tag` 引用 matcher。

| matcher | 完整参数与例子 | 范围/行为 |
| --- | --- | --- |
| `qname` | `qname full:example.com domain:example.org $local_domains &./rules/domains.txt` | 首个 Question 的名称；多个表达式/集合/文件 OR。支持上述数据库表达式。 |
| `cname` | `cname domain:cdn.example $local_domains` | 响应 Answer 中任一 CNAME 的 Target。 |
| `client_ip` | `client_ip 192.168.0.0/16 ::1 $local_ips &./rules/ips.txt` | 服务端识别的客户端地址。 |
| `resp_ip` | `resp_ip 203.0.113.0/24 $local_ips` | Answer 中任一 A/AAAA，**不只是 CNAME 终点**；HTTPS/SVCB 查询额外匹配有效 CNAME 终点 ServiceMode 的 hint。 |
| `ptr_ip` | `ptr_ip 192.168.0.0/16 $local_ips` | 从 PTR 查询名还原出的地址。 |
| `qtype` | `qtype 1 28` | 整数 DNS 类型，A=1、AAAA=28、PTR=12、HTTPS=65；不接受 `A`/`AAAA` 名称。 |
| `qclass` | `qclass 1` | 整数 DNS 类，IN=1。 |
| `rcode` | `rcode 0 3` | 现有响应的整数返回码；无响应时不匹配。 |
| `has_resp` | 无参数 | 当前是否存在响应。 |
| `has_wanted_ans` | 无参数 | Answer 中有与问题 type/class 一致的 RR；不检查 owner name，也不代替 speedcheck 的 CNAME 链校验。 |
| `mark` | `mark 10 20` | 命中任一已设置的十进制 uint32 mark。 |
| `random` | `random 0.1` | 浮点概率，示例 10%；应使用 0–1，当前实现不主动拒绝越界数值。 |
| `env` | `env MOSDNS_DEBUG` | 初始化时判断环境变量是否存在；后续环境变化不重新求值。当前双参数形式有解析缺陷，请用 `string_exp $MOSDNS_MODE eq office` 做值比较。 |
| `string_exp` | `string_exp url_path prefix /dns-query` | 见下表，运行时读取字符串。 |
| `_true` / `_false` | 无参数 | 常真/常假，保留下划线以免被 YAML 解释为布尔。 |
| `$rate_limit` | 无参数；或 `!$rate_limit` | 已命名 rate_limiter；正常放行返回 true，限流返回 false。 |

IP 类 matcher 接受裸 IP、CIDR、`geoip:`、`asn:`、`ext:`，以及 `$ip_set_tag`、`&文本文件`。文件参数由空白分词，因此这种行内语法不能直接表达含空格的文件路径；需要时使用顶层 provider 的 `files` 列表。

`string_exp` 的格式是 `来源 操作 [值]...`：

| 字段 | 支持值 |
| --- | --- |
| 来源 | `url_path`（HTTP 路径）、`server_name`（TLS SNI 等服务元信息）、`$环境变量名`；未提供的服务元信息为空串。 |
| 操作 | `zl`：空串；`eq`：相等；`prefix`：前缀；`suffix`：后缀；`contains`：包含；`regexp`：Go 正则。 |
| 值 | 除 `zl` 外为若干空白分隔的字符串，任一命中即可。 |

```yaml
- matches: ["string_exp $MOSDNS_MODE eq office home"]
  exec: mark 20
- matches: ["string_exp url_path eq /dns-query", "!qtype 255"]
  exec: debug_print doh_query
- matches: ["_false"]
  exec: reject
```

## forward：上游与传输

`forward` 可以声明为顶层插件，也可以直接写 `exec: forward 地址...`。顶层形式允许完整参数及按上游 tag 选择；快速形式只接收地址，默认并发为 3。

| `args` 字段 | 默认值与含义 |
| --- | --- |
| `upstreams` | 必须至少一个对象；完整字段见下一表。 |
| `concurrent` | 顶层默认 1；大于 3 截为 3；小于等于 0 按 1。每次从随机起点选择上游，响应先到先取，并非 fastest-IP。 |
| `socks5` | 空；SOCKS5 `host:port`，用于 TCP 类传输，不用于 UDP/HTTP3/DoQ。无用户名密码配置项。 |
| `so_mark` | 0；Linux socket mark，通常需要权限；Windows 等非 Linux 路径无操作。 |
| `bind_to_device` | 空；Linux 绑定接口名称，通常需要权限；非 Linux 路径无操作。 |
| `bootstrap` | 空；解析加密上游主机名的明文 DNS IP，可带端口；不填用系统解析路径。 |
| `bootstrap_version` | 0 等同 IPv4；支持 0、4、6，非双栈竞速。 |

上述五个全局字段也可以在每个 `upstreams[]` 中设置，非空字符串/正数的逐上游值优先；零值/空串继承全局值，因此不能用 0/空串取消已有全局设置。

| `upstreams[]` 字段 | 默认值、单位及适用性 |
| --- | --- |
| `tag` | 可选上游名称；显式命名才注册该上游指标；同一 forward 内不能重复。 |
| `addr` | 必填，上游地址/URL/DNS stamp。 |
| `dial_addr` | 空；覆盖实际拨号目标，可带端口，不改变 TLS SNI 或 HTTP Host。 |
| `http_host` | 空；DoH 默认使用 URL 的 Host。非空单独覆盖 HTTP Host / HTTP2 `:authority`，不改变 URL、TLS SNI 或证书验证名称。 |
| `http_method` | `GET`；DoH 可选 `GET` / `POST`，大小写不敏感。POST 使用 `application/dns-message` 请求体；GET 使用 `dns` 查询参数。 |
| `idle_timeout` | 整数秒；TCP/DoT 默认 10，DoH/HTTP3/DoQ 默认 30；UDP transport 固定 300 秒。当前 DoT 非 pipeline 路径采用底层默认 10 秒，填写该值并不改变其复用超时。 |
| `max_conns` | 兼容旧配置但已弃用，**无效果**。 |
| `enable_pipeline` | `false`；仅 TCP/DoT，要求上游支持同一连接并发，不做不兼容回退。 |
| `enable_http3` | `false`；DoH 改用 HTTP/3，无自动回退。 |
| `insecure_skip_verify` | `false`；关闭标准 TLS 证书校验；一般保留 false。 |
| `alpn` | 空列表，按传输采用默认值；如 DoT `['dot']`，DoQ `['doq']`。 |
| `verify_peer_cert_by_name` | 空；逗号分隔的证书名称列表，使用这些名称验证证书链。 |
| `fingerprint` | 空表示普通 TLS；非空启用 uTLS，例如 `chrome`、`firefox`、`safari`、`ios`、`android`、`edge`、`360`、`qq`、`random`、`randomized`、`randomizednoalpn`；也支持 `pkg/upstream/utls.go` 中列出的 uTLS 常量名称。仅 DoT/DoH 的 TCP TLS 路径，HTTP3/DoQ 拒绝此参数。 |
| `ech_config_list` | 空；base64 ECHConfigList，或 `域名+DNS上游URL`，例如 `example.com+https://1.1.1.1/dns-query`；后者通过 HTTPS RR 获取 ECH。仅 DoT/DoH TCP TLS；ECH 握手失败不会降级明文 ClientHello。 |
| `repeat` | 默认 0；UDP 每次额外发的副本数，即实际发送 `repeat+1`；等待时 transport 每秒重发，每次仍发送这些副本。 |
| `use_tricks` | `false`；只用于 UDP/TCP。UDP 要求 EDNS0 回显且执行长度/记录数启发式过滤；TCP 使用 OOB 发送帧前 16 字节，启用时应显式设置 `enable_pipeline: false` 并使用普通 `tcp://`。可用性取决于链路/上游；Windows 也有对应 TCP OOB 路径。 |
| `socks5` / `so_mark` / `bind_to_device` / `bootstrap` / `bootstrap_version` | 见上表的逐上游覆盖规则。 |

```yaml
- tag: upstream_full
  type: forward
  args:
    concurrent: 2
    socks5: ""
    so_mark: 0
    bind_to_device: ""
    bootstrap: "1.1.1.1:53"
    bootstrap_version: 4
    upstreams:
      - tag: udp_a
        addr: "udp://1.1.1.1:53"
        dial_addr: ""
        repeat: 1
        use_tricks: false
      - tag: doh_a
        addr: "https://cloudflare-dns.com/dns-query"
        dial_addr: "1.1.1.1:443"
        http_host: ""
        http_method: GET
        idle_timeout: 30
        max_conns: 0                   # 已弃用，无效果
        enable_pipeline: false
        enable_http3: false
        insecure_skip_verify: false
        alpn: ["h2", "http/1.1"]
        verify_peer_cert_by_name: "cloudflare-dns.com"
        fingerprint: "chrome"
        ech_config_list: ""            # 有有效 ECH 配置时再填写
        socks5: ""
        so_mark: 0
        bind_to_device: ""
        bootstrap: "1.1.1.1"
        bootstrap_version: 4
```

地址格式与互斥选择如下；按需要选择，不必同时声明所有地址：

```yaml
# 以下每行都是可选的 upstreams[] 项；不要把占位 stamp 原样投入使用。
- addr: "1.1.1.1"                     # 缺省 UDP/53
- addr: "udp://[2606:4700:4700::1111]:53"
- addr: "tcp://1.1.1.1:53"
- addr: "tcp+pipeline://1.1.1.1:53"
- addr: "tls://cloudflare-dns.com:853"
- addr: "tls+pipeline://cloudflare-dns.com:853"
- addr: "https://cloudflare-dns.com/dns-query"
- addr: "h3://cloudflare-dns.com/dns-query"   # 等于 https + enable_http3
- addr: "quic://dns.example:853"       # doq:// 亦支持；须有实际 DoQ 服务
# - addr: "sdns://有效的DNS-stamp"      # Plain/DNSCrypt/DoH/DoT/DoQ
```

明文 UDP/TCP 上游的实际目标必须为 IP（TCP 经 SOCKS5 时代理可接收域名）。UDP 截断响应会转 TCP 重试。每个上游交换的内部超时为 5 秒，不存在可写 `timeout` 参数。普通 forward 的兼容路径允许在返回后继续其余交换；speedcheck 控制的来源分支继承取消，能及时结束未选中的请求。要做多上游地址测速，每个上游放进独立 source sequence，详见 speedcheck 完整示例。

## 响应来源与改写

### hosts

全部参数：`entries`（字符串列表，默认空）、`files`（规则文件列表，默认空）。**顺序是“域名表达式 IP...”**，与操作系统 hosts 文件的 IP 在前不同。缺省域名匹配为 full，可显式用 `domain:` 扩展子域。支持 IPv4/IPv6；匹配的地址族不存在时可生成 NODATA；内置地址 TTL 为 10 秒。

```yaml
- tag: hosts_local
  type: hosts
  args:
    entries:
      - "router.example 192.168.1.1 fd00::1"
      - "domain:lab.example 192.168.1.2"
    files: []                         # 同样采用 域名 IP... 格式
```

在 sequence 使用 `$hosts_local` 后接 `matches: [has_resp]`、`exec: accept`，避免后续上游覆盖本地响应。

### ip_replace：CDN IP 前缀替换

只对合法 IN/A、IN/AAAA 正响应的 CNAME 终点地址执行替换；按规则顺序、原记录顺序选取首个匹配 IP，使用其主机位生成目标列表。替换后只返回生成地址，不混入原地址。完整说明与无外网演示见 [ip_replace](ip-replace.md)。

| `args` 字段 | 默认值与行为 |
| --- | --- |
| `replace_map` | 有序规则列表，空列表不替换。 |
| `replace_map[].match_ip` | 必填、非空的 IP matcher 表达式列表，列表内 OR；支持 IP/CIDR、`$ip_set`、`&文件`、GeoIP/ASN/`ext:`。 |
| `replace_map[].exclude_ip` | 默认空；逐 IP 排除，优先于当前规则的 match。 |
| `replace_map[].ipv4_prefixlen` | 默认 `32`，整数 `0..32`；显式 `0` 保留原地址全部位。 |
| `replace_map[].ipv6_prefixlen` | 默认 `128`，整数 `0..128`；显式 `0` 保留原地址全部位。 |
| `replace_map[].ipv4` | 默认空；不带 CIDR 的 IPv4 目标列表，按配置顺序生成并去重。 |
| `replace_map[].ipv6` | 默认空；不带 CIDR 的 IPv6 目标列表，按配置顺序生成并去重。 |

```yaml
- tag: replace_cdn
  type: ip_replace
  args:
    replace_map:
      - match_ip: ["192.0.2.0/24", "2001:db8:20::/48"]
        exclude_ip: []
        ipv4_prefixlen: 24
        ipv6_prefixlen: 64
        ipv4: ["203.0.113.99", "198.51.100.77"]
        ipv6: ["2001:db8:100::99"]
```

地址计算为 `(目标 & 前缀掩码) | (原地址 & 主机位掩码)`，目标自动规范化。例如 `192.0.2.42` 配目标 `203.0.113.99`、prefix 24，生成 `203.0.113.42`；不会把基址与原主机位相加。默认 `/32`、`/128` 等同固定地址替换。首个命中规则没有当前地址族目标时保留原响应并结束，不继续匹配后面的规则。配置中非法 IP、地址族或 prefix 会在启动时报错；目标不接受带 zone 的 IPv6 或 IPv4-mapped IPv6。

在 speedcheck 的每个来源中，放在 forward 和必需过滤之后、来源 sequence 返回之前，保证测速的是替换地址。DO=1 跳过；重建保留 CNAME 和剩余 TTL，清理 AD/AA 及失效证明记录。HTTPS/SVCB hint 与 ECS 不改写。示例使用文档地址，不应对它们运行真实探测；实际使用需换成目标 CDN 网段。

### ip_fallback：无地址或测速失败后的静态 IP

此插件处理当前合法 A/AAAA 响应，与主次查询链的 `fallback` 分工不同。放在 speedcheck 之后、`accept` 之前，域名/CNAME 范围继续由 sequence 的 `matches` 控制。

| `args` 字段 | 默认值与行为 |
| --- | --- |
| `ipv4`、`ipv6` | 默认空；对应地址族的静态地址列表，按配置顺序去重；不带 CIDR。 |
| `ttl` | 默认 `86400` 整数秒；允许 `0..4294967295`，显式 `0` 有效。 |
| `on` | 默认 `[all_probes_failed, nodata]`；显式 `[]` 关闭。`all_probes_failed` 要求全部合格地址真实探测失败；`nodata` 为 NOERROR 无终点地址；可选 `no_rtt` 还包含已执行选择但未测量、禁测或尚未完成的情况。 |

```yaml
- tag: static_cdn_ip
  type: ip_fallback
  args:
    ipv4: ["203.0.113.42"]
    ipv6: ["2001:db8:ffff::42"]
    ttl: 60
    on: [all_probes_failed, nodata]
# 在已经定义的主链中：
# - exec: $select_fast_ip
# - matches: ["qname domain:cdn.example"]
#   exec: $static_cdn_ip
```

默认不把缺少测速统计或关闭测速判为失败；若明确希望禁测时也静态回退，配置 `no_rtt`。已有成功 RTT（包括 0）不触发。无响应、NXDOMAIN/SERVFAIL、截断、opaque 或 DO=1 保留，不做静态伪造。重建只输出配置地址及必要 CNAME；静态 TTL 可重设地址期限，有链时保守受其既存有效期限约束。完整说明与无公网演示见 [ip_fallback](ip-fallback.md)。

### https_record：HTTPS/SVCB 的 ECH、hint 与 ALPN

处理客户端收到的 DNS 记录，与上游 TLS 连接的 ECH/ALPN 配置不同。完整参数、逐 Target 门控、子查询和离线示例见 [https_record](https-record.md)。

| `args` 字段 | 默认值与行为 |
| --- | --- |
| `remove_hint` | `true`；移除 ServiceMode 的 ipv4hint/ipv6hint。 |
| `remove_h3` | `true`；删除精确 ALPN `h3`。 |
| `remove_alpn` | 空列表；额外删除的精确协议 ID，每项 1..255 字节。 |
| `add_ech` | `true`；为符合条件且缺少 ECH 的 ServiceMode 补值，不覆盖已有 ECH。 |
| `enable_subquery` | `true`；允许缺 hint 时用 A 判断，以及 NODATA 的 A 确认。 |
| `ech_source` | 开启 ECH 时必填；此前定义的专用查询链 tag，不带 `$`。 |
| `ech_domain` | `crypto.cloudflare.com`；生产环境须与目标服务/CDN 兼容。 |
| `ip_source` | 开启 ECH 和子查询时必填；此前定义的完整 A 查询链 tag。 |
| `match_name` | 省略不限；支持域名表达式、`$domain_set`、`&文件`、GeoSite；显式 `[]` 拒绝注入/辅助查询。 |
| `match_ip` | 省略不限；IP/CIDR、`$ip_set`、`&文件`、GeoIP/ASN 表达式 OR；显式 `[]` 拒绝注入。 |
| `exclude_ip` | 默认无排除；任一当前记录的 hint/A 地址命中就否决该条注入。 |
| `timeout` | `500ms`；省略或 `0` 采用默认值，负值报错。全部辅助工作共用预算，受父截止限制，预留最多 25ms 回包时间。 |

```yaml
# 此前定义 ech_lookup、ip_lookup，分别返回ECH域名的HTTPS及目标域名的最终A响应。
- tag: process_bindings
  type: https_record
  args:
    remove_hint: true
    remove_h3: true
    remove_alpn: ["h3-29"]
    add_ech: true
    enable_subquery: true
    ech_source: ech_lookup
    ech_domain: compatible-ech.cdn.example
    ip_source: ip_lookup
    match_name: ["domain:example.org"]
    match_ip: ["$cdn_networks"]
    exclude_ip: []
    timeout: 500ms
```

hint/ALPN 清理先执行；名称/IP 条件只控制 ECH 注入和辅助查询。正 ServiceMode 按各自 TargetName/hint 分别判定，A 查询按目标去重且最多 8 个并行，并与单次 ECH 查询重叠。NOERROR/NODATA 必须先得到合法匹配的 A，才合成短 TTL 的 ECH-only 记录；AliasMode 不改。DO=1 跳过，重建清理 AD/AA、失效证明并限制 TTL。成功 ECH 缓存最多 100 条、300 秒，不超过来源期限；TTL0、无 ECH 及异常不缓存。不提供跨请求在途合并。

来源若需按原 hint 丢弃候选，在清理前使用 `resp_ip` 配合 `drop_resp`；该 matcher 已扩展到合法 HTTPS/SVCB 终点 ServiceMode 的 hint，不取无关记录和 Additional 的 hint。A/AAAA 的既有 Answer 匹配保持兼容；speedcheck 不探测 HTTPS hint。

### arbitrary

全部参数：`rules`（DNS zone 格式 RR 字符串列表，默认空）、`files`（zone 文本文件列表，默认空）。可生成 A/AAAA/TXT/MX 等任意资源记录；未匹配时继续。

```yaml
- tag: static_records
  type: arbitrary
  args:
    rules:
      - 'status.example. 60 IN TXT "ready"'
      - 'mail.example. 300 IN MX 10 mx.example.'
      - 'mx.example. 300 IN A 192.0.2.10'
    files: []
```

### redirect

全部参数：`rules`（`原域名表达式 目标域名` 字符串列表，默认空）、`files`（同格式文件列表，默认空）。默认 full 匹配。递归执行后续查询，恢复原问题并插入 TTL=1 的 CNAME，因此应放在后续 forward 前。

```yaml
- tag: aliases
  type: redirect
  args:
    rules:
      - "www.alias.example www.target.example"
      - "domain:old.example new.example"
    files: []
# sequence 片段：
# - exec: $aliases
# - exec: $upstream
```

### black_hole、ttl、drop_resp

这三项仅支持 sequence 快速配置，无对应顶层 `type`。

```yaml
- matches: ["qname domain:blocked.example"]
  exec: "black_hole 0.0.0.0 ::"        # 含 IPv6 尾冒号时给整个动作加引号；TTL=300
- matches: ["qname domain:blocked.example", "has_resp"]
  exec: accept
- exec: $upstream
- exec: ttl 30-600                    # 把当前响应 TTL 限于 30..600 秒
# - exec: ttl 60                      # 另一种选择：固定为 60 秒
# - exec: ttl 0-600                   # 只设置上限；0 表示不设置此方向限制
# - exec: drop_resp                   # 清除当前响应，然后才能让后续上游重新回答
```

`ttl` 参数为 uint32 十进制整数或 `下限-上限`，单位秒；`ttl 0` 不把 TTL 强制设为 0，而是不做改写。`drop_resp` 无参数。上游原始 TTL、speedcheck 期限和 DNSSEC 保护不应被后续强制延长 TTL 的动作无意覆盖。

## cache：响应缓存

| 全部 `args` 字段 | 默认值与单位 |
| --- | --- |
| `size` | 默认 1024 项；小于等于 0 回到默认。底层固定 64 个分片，每片容量为 `floor(size/64)`，实际总容量向下取整到 64 的倍数。建议使用至少 1024 且为 64 倍数的值；1–63 会产生零容量阈值，当前实现反而不限制分片容量。 |
| `lazy_cache_ttl` | 默认 0，关闭过期缓存；正整数秒是从写入起的总缓存保留时间，不是在原 DNS TTL 到期后再额外增加该时长。小于正常 TTL 时会提前淘汰；保留期内的过期命中暂以 TTL=5 秒返回并后台更新。 |
| `dump_file` | 空表示不落盘；非空时启动加载并定期导出。 |
| `dump_interval` | 默认 600，整数秒；周期写出还要求自上次写出至少 1024 次键更新。 |

```yaml
- tag: response_cache
  type: cache
  args:
    size: 4096
    lazy_cache_ttl: 0
    dump_file: "./cache.dump"
    dump_interval: 600
- tag: cached_main
  type: sequence
  args:
    - exec: $response_cache           # cache 递归包住后续处理，回程保存响应
    - matches: ["has_resp"]
      exec: accept
    - exec: $upstream
    - exec: accept
# 快速、独立匿名实例：exec: cache 4096；不支持完整配置/命名指标/API。
```

API：`GET /plugins/response_cache/flush` 清空、`GET /plugins/response_cache/dump` 下载、`POST /plugins/response_cache/load_dump` 导入。缓存键不是所有可能查询视图的完整隔离机制；不同 ECS/策略视图应使用独立缓存实例或独立链。speedcheck 首版示例不包最终响应缓存，确保每次进入选择器都重新评估。

## fallback：主备执行链

| 全部 `args` 字段 | 默认与语义 |
| --- | --- |
| `primary` | 必填，主可执行插件/sequence tag，不带 `$`。 |
| `secondary` | 必填，备用可执行插件/sequence tag，不带 `$`。 |
| `threshold` | 500，整数毫秒，小于等于 0 使用默认。主链失败或超过阈值时使用备链。 |
| `always_standby` | 默认 false；true 时从开始就启动备链待用。 |

```yaml
- tag: primary_query
  type: sequence
  args:
    - exec: $upstream
    - matches: ["rcode 2 5"]
      exec: drop_resp
- tag: secondary_query
  type: sequence
  args:
    - exec: forward 8.8.8.8
- tag: main_fallback
  type: fallback
  args:
    primary: primary_query
    secondary: secondary_query
    threshold: 500
    always_standby: true
```

主链的合法 NXDOMAIN/NODATA 也算存在响应；若要针对 rcode 或答案内容回退，应在来源链用 matcher + `drop_resp` 表达拒绝条件。fallback 无单独可配置总超时：父请求已有截止时间时直接沿用，未设置截止时间时每个分支默认 5 秒。speedcheck 全来源失败的错误可以由外层 fallback 接收。

## ECS 与 EDNS0

### ecs_handler

| 全部 `args` 字段 | 默认与优先顺序 |
| --- | --- |
| `forward` | false；尝试向上游转发客户端 ECS，若成功也回传上游 ECS。 |
| `send` | false；无可转发 ECS/预设时，依据服务识别的客户端地址生成 ECS。 |
| `preset` | 空；固定 IPv4 或 IPv6 地址，不填掩码。优先于 send。 |
| `mask4` | 默认 24；接受 0..32，其中 0 会回到默认，不能据此发送 /0。 |
| `mask6` | 默认 48；接受 0..128，其中 0 会回到默认。 |

如果查询已经有 ECS，插件不再添加。其余依次选 `forward` → `preset` → `send`；仅 IN 查询添加。

```yaml
- tag: client_ecs
  type: ecs_handler
  args:
    forward: true
    send: false
    preset: "203.0.113.10"            # 演示地址；使用时换成合适的真实客户端网段地址
    mask4: 24
    mask6: 48
# sequence 中在 forward 前使用：- exec: $client_ecs
```

兼容快速动作 `exec: ecs 203.0.113.10`；旧的 `IP/掩码 第二个IP/掩码` 语法仍解析，但仅使用第一个地址，忽略传入掩码及第二地址，采用 24/48 默认值。需要可控掩码时使用 `ecs_handler`。

### forward_edns0opt

仅 sequence 快速配置：`exec: forward_edns0opt 10 15`。参数为若干十进制 EDNS0 option code（0..65535），向上游转发客户端对应 option，并在回程转发上游对应 option。它是递归动作，须放在 forward 前。ECS（code 8）建议交给 ecs_handler 统一管理，避免同时配置产生重复。DO bit 由查询上下文传递，无单独开关。

## 双栈偏好与反向查询

### prefer_ipv4、prefer_ipv6（dual_selector）

这是两个无参数的 sequence 动作；不存在可写的顶层 `type: dual_selector`。在后续查询前放置 `exec: prefer_ipv4` 或 `exec: prefer_ipv6`，会查询/参考首选地址族是否存在，存在时抑制另一族响应。内部参考等待为 500ms、参考缓存 65536 项/1 小时，这些都是内部常量而非配置参数。

```yaml
- exec: prefer_ipv4                   # 与 prefer_ipv6 二选一
- exec: $upstream
```

### reverse_lookup

| 全部 `args` 字段 | 默认与行为 |
| --- | --- |
| `size` | 65536，缓存项数；小于等于 0 使用默认。 |
| `handle_ptr` | false；true 时用已观察到的正向记录回答 PTR。 |
| `ttl` | 7200，整数秒，反向映射的保存时间，同时将经过它的 Answer A/AAAA TTL 限制到此上限；小于等于 0 使用默认。PTR 响应本身使用 TTL=5 秒。 |

```yaml
- tag: seen_names
  type: reverse_lookup
  args:
    size: 65536
    handle_ptr: true
    ttl: 7200
# sequence 在 forward 前使用：- exec: $seen_names
# 查询观察结果：GET /plugins/seen_names/?ip=192.0.2.10
```

它是递归动作：先尝试已有 PTR 映射，然后执行后续正向查询并保存 Answer 中地址。不是主动扫描网络的反向 DNS 服务。

## rate_limiter

顶层声明 matcher；无 `exec: rate_limiter` 快速动作。

| 全部 `args` 字段 | 默认与单位 |
| --- | --- |
| `qps` | 20，浮点，每个客户端前缀每秒令牌数；小于等于 0 使用默认。 |
| `burst` | 40，突发容量；小于等于 0 使用默认。 |
| `mask4` | 32，IPv4 分组前缀，范围 0..32；小于等于 0 使用默认。 |
| `mask6` | 48，IPv6 分组前缀，范围 0..128；小于等于 0 使用默认。 |

```yaml
- tag: rate_limit
  type: rate_limiter
  args:
    qps: 20
    burst: 40
    mask4: 32
    mask6: 48
- tag: limited_main
  type: sequence
  args:
    - matches: ["!$rate_limit"]
      exec: reject 5
    - exec: $upstream
```

matcher true 表示本次允许，通过取反拒绝超限；缺少可识别客户端地址时放行。

## Linux 防火墙集合：ipset、nftset

这两个模块只有 sequence 快速语法；虽然源码内部有 Args 结构，未注册顶层构造器，不能直接写 `type: ipset` 或 `type: nftset`。只把响应 Answer 的地址写入系统中已存在且类型合适的集合，不创建集合/防火墙规则。Linux 需要相应内核能力与权限；**Windows/其他非 Linux 构建是空操作**，不会配置其本机防火墙。

```yaml
- exec: $upstream
- exec: ipset dns4,inet,24 dns6,inet6,48
# 字段：set_name,地址族inet或inet6,前缀长度；至多两个项。
# IPv4/IPv6 只需一项时可省略另一项；mask=0 在 Linux 中分别采用默认 24/32。

# nftset 是另一种选择：
- exec: nftset inet,dns_table,dns4,ipv4_addr,24 inet,dns_table,dns6,ipv6_addr,48
# 字段：table_family,table_name,set_name,元素族ipv4_addr或ipv6_addr,前缀长度。
# table_family 取 ip / ip6 / inet；至多两个项。
# mask<=0 采用默认 IPv4=24、IPv6=48。
```

两项均需放在已得到响应的位置；如 cache 命中后提前 accept，则这些动作不会处理缓存命中，应按需要安排控制流。

## stats_api：查询统计与环形日志

顶层插件 `stats_api` 兼容 [sbwml/luci-app-mosdns 的 v5 补丁集](https://github.com/sbwml/luci-app-mosdns/tree/dbdd91ab8ac8b079b6a3ca1a48d99e970d17111b/mosdns/patches) 中的配置、HTTP 接口和统计转储。实现按 216–231 号统计补丁及其查询元数据依赖迁移。

| 字段 | 类型、默认值与行为 |
| --- | --- |
| `listen` | 默认空；非空时额外启动该插件自己的 HTTP 服务。通常使用顶层 `api.http` 即可。 |
| `capacity` | 默认 2000，查询日志最多保留的条数；满后 FIFO 覆盖最旧记录，累计统计继续增长。非正数使用默认值。 |
| `dump_file` | 默认空，不持久化；非空时启动读取、定时转储，并在关闭时保存。尝试创建父目录，目标目录须可创建或可写。 |
| `dump_interval` | 默认 600，整数秒；非正数使用默认值。 |

```yaml
- tag: stats_collector
  type: stats_api
  args:
    capacity: 2000
    dump_file: "/etc/mosdns/stats.dump"
    dump_interval: 600
- tag: main_sequence
  type: sequence
  args:
    - exec: $stats_collector
    - exec: $lazy_cache        # 需在本 sequence 前定义
    - matches: has_resp
      exec: accept
    - exec: $forward_local     # 需在本 sequence 前定义
```

该插件递归执行后续链，在返回时记录一次完成的查询，保留原响应与错误。放在 cache 前可覆盖缓存命中及实际解析；cache 的后台刷新从 cache 后继续，不会重复进入该统计入口。上游有效 `NXDOMAIN` 不计作本地拦截；沿用补丁中的 `TIMEOUT`、`ERROR`、`DROPPED` 与拦截判定。超时单独计数，不纳入平均延迟。缓存命中率分母排除拦截、hosts 和 arbitrary 命中。日志包含缓存状态、获胜上游及实际匹配规则；fallback 仅传回获胜分支的元数据。

API 挂在 `/plugins/<tag>`，因此示例对应：

- `GET /plugins/stats_collector/api/v1/stats`：累计查询、拦截、缓存、hosts、arbitrary、超时计数，相应百分比、`avg_latency_ms` 和实时 `qps`。
- `GET /plugins/stats_collector/api/v1/logs`：`{ "total": ..., "items": [...] }`；支持 `limit`（默认 50，最多 500）、`offset`、`search`、`filter`，最新记录在前。日志字段保留 `domain`、`qtype`、`status`、`is_blocked`、`is_cached`、`elapsed_ms`、`upstream`、`rule` 和 `answers` 等原字段。
- `GET /plugins/stats_collector/api/v1/top`、`/api/v1/history`：热门域名、客户端、拦截域名和历史统计。
- `GET /plugins/stats_collector/api/v1/dump`、`POST /plugins/stats_collector/api/v1/load_dump`：导出、恢复 gzip 转储。
- `POST /plugins/stats_collector/api/v1/logs/clear`、`/api/v1/cache/clear`：清空统计日志或已注册缓存。

同一组接口保留省略 `/api/v1` 的短路径别名，如 `/plugins/stats_collector/stats`、`/plugins/stats_collector/logs`。设置 `listen` 时，插件独立服务直接提供 `/api/v1/*` 及短路径，无 `/plugins/<tag>` 前缀。

转储保留 gzip 名称 `mosdns_stats_v1` 和版本 1 的 `StatsDumpData` JSON 字段；可读取 219 号补丁生成、尚未添加 hosts/arbitrary/timeout 等可选字段的旧转储。重启恢复累计统计、热门列表、历史、日志及序号，减小 capacity 时只保留最新记录。写盘先完成同目录临时文件及同步，再替换旧文件；关闭等待已进入统计器的查询和后台转储完成。无法识别或损坏的已有文件会记录错误、保留原文件，并禁用该实例的持久化，内存统计仍正常。

## 日志、指标、marks 与延时

监听器为完成打包的客户端查询记录一次 `query log`：`info` 包含请求名、字符串查询类型、
协议、RCODE、上游、缓存状态、应答地址/CNAME/TTL、响应大小及耗时；`debug` 额外记录
规则命中。日志级别按实例判断，`warn`/`error` 不输出普通查询日志。协议区分 UDP、TCP、
DoT、DoH 和 DoQ，最终 SERVFAIL/REFUSED 也按实际准备返回的响应记录。该日志与
`stats_api` 的环形日志分别维护。

| 动作 | 全部用户参数与默认 |
| --- | --- |
| `debug_print [文本]` | 当前 query/response 的 INFO 日志；默认标题 `debug print`。仅快速动作。 |
| `query_summary [文本]` | 执行后续链后记录查询概要与错误；默认标题 `query summary`。仅快速动作，放在待观察处理前。 |
| `metrics_collector 名称` | 为后续链注册查询/错误/并发/延迟指标；名称用作 label，相同名称的重复实例可能发生注册冲突。仅快速动作，通过 API `/metrics` 暴露。 |
| `mark 数字...` | 设置若干十进制 uint32 mark；匹配使用同名 matcher。当前解析器不接受源码注释中旧示例的 `0x`/`0b` 数字写法。 |
| `sleep 毫秒` | 整数毫秒；无默认参数，0 不等待。会响应请求取消。也支持下方顶层形式。 |
| `$_sleep_500ms` | 无参数，内置预设的 500ms sleep 插件引用。 |

```yaml
- tag: short_delay
  type: sleep
  args:
    duration: 10                      # uint 毫秒；默认 0
- tag: observed_main
  type: sequence
  args:
    - exec: metrics_collector observed_main
    - exec: query_summary dns_query
    - matches: ["random 0.01"]
      exec: debug_print sampled_query
    - exec: mark 100
    - matches: ["mark 100"]
      exec: $short_delay
    - exec: $upstream
    - exec: accept
```

## DNS 监听服务

服务插件放在入口 chain 定义之后；`entry`/HTTP 的 `entries[].exec` 都填可执行插件 tag，**不带 `$`**。监听协议和上游协议相互独立。以下 TLS/QUIC 片段必须先提供可用证书，不属于无需资源即可运行的示例。

当前服务构造路径未调用 Args 上用于默认值的 `init()`。因此请始终显式写 `listen`，不要把空值当作自动绑定 `127.0.0.1:53`；TCP 下层会对非正 idle_timeout 采用 10 秒，DoQ 下层 30 秒，但 QUIC/HTTP 上层仍有自己的超时行为。示例统一显式填入 `idle_timeout`，避免依赖这些差异。

### udp_server

全部参数只有 `entry` 与 `listen`。

```yaml
- tag: dns_udp
  type: udp_server
  args:
    entry: main
    listen: "127.0.0.1:15353"
```

IPv6 用 `[::1]:15353`；对外服务可填实际本机地址。没有 TLS、buffer、worker、timeout 等可配置字段。

### tcp_server：普通 TCP 或 DoT

全部参数：`entry`、`listen`、`cert`、`key`、`idle_timeout`（整数秒；TCP 下层默认 10 秒）。`cert`/`key` 同时为空则普通 TCP；任一非空会加载证书，正常配置应成对给出。

```yaml
- tag: dns_tcp
  type: tcp_server
  args:
    entry: main
    listen: "127.0.0.1:15353"
    cert: ""
    key: ""
    idle_timeout: 10
- tag: dns_tls
  type: tcp_server
  args:
    entry: main
    listen: "127.0.0.1:1853"
    cert: "./tls/server.crt"
    key: "./tls/server.key"
    idle_timeout: 10
```

### quic_server：DoQ

全部参数：`entry`、`listen`、`cert`、`key`、`idle_timeout`（整数秒；建议显式 30）。证书和密钥必填；使用 UDP socket 和 ALPN `doq`。不提供 HTTP/3 服务，0-RTT 未启用，无可配置开关。

```yaml
- tag: dns_quic
  type: quic_server
  args:
    entry: main
    listen: "127.0.0.1:1853"           # 和上面 TCP/DoT 端口相同但传输不同
    cert: "./tls/server.crt"
    key: "./tls/server.key"
    idle_timeout: 30
```

### http_server：DoH

| 全部 `args` 字段 | 默认与行为 |
| --- | --- |
| `entries` | 路由列表，每项 `exec` 为可执行 tag、`path` 为 HTTP 路由，例如 `/dns-query`。 |
| `listen` | TCP 监听地址，应显式填写。 |
| `src_ip_header` | 空则使用直接连接地址；非空从指定 HTTP header 取得源 IP。只在前置代理会正确清洗该 header 时使用。 |
| `cert`、`key` | 都空则明文 HTTP；设置时加载 TLS，支持 HTTP/2；不是 HTTP/3。 |
| `idle_timeout` | 整数秒；示例 30。当前未执行 Args 默认初始化，省略会把 0 交给 HTTP/HTTP2 层，请显式填写。 |

```yaml
- tag: dns_https
  type: http_server
  args:
    entries:
      - exec: main
        path: /dns-query
      - exec: observed_main
        path: /dns-query-observed
    listen: "127.0.0.1:18443"
    src_ip_header: ""
    cert: "./tls/server.crt"
    key: "./tls/server.key"
    idle_timeout: 30
# 前置反向代理场景的另一种选择：
# listen: 127.0.0.1:18080
# src_ip_header: X-Real-IP
# cert: ""
# key: ""
```

TCP/HTTP 监听地址以 `@` 开头时，代码会选择 Unix socket；这是面向支持该 socket 类型的平台的配置，不是 Windows 常规运行示例。Windows 推荐使用明确的 IP:端口。Linux 的 SO_REUSEPORT/接收缓冲优化未暴露成 YAML 参数，非 Linux 有各自系统实现。

## 覆盖索引与配置检查

本页覆盖的注册模块：

- 数据：`domain_set`、`ip_set`、`adblock_set`。
- 匹配：`client_ip`、`cname`、`env`、`has_resp`、`has_wanted_ans`、`ptr_ip`、`qclass`、`qname`、`qtype`、`random`、`rcode`、`resp_ip`、`string_exp`、`mark`，及 `_true`/`_false`。
- 执行：`arbitrary`、`black_hole`、`cache`、`debug_print`、`drop_resp`、`dual_selector` 的 `prefer_ipv4`/`prefer_ipv6`、`ecs_handler`/`ecs`、`forward`、`forward_edns0opt`、`hosts`、`https_record`、`ip_fallback`、`ip_replace`、`ipset`、`metrics_collector`、`nftset`、`query_summary`、`rate_limiter`（实际 matcher）、`redirect`、`reverse_lookup`、`sequence`/内置控制流、`fallback`、`sleep`、`stats_api`、`ttl`。`speedcheck` 链接至专门参考和完整示例。
- 服务：`http_server`、`quic_server`、`tcp_server`、`udp_server`。

配置核对顺序：先检查顶层/插件字段名及依赖定义顺序，再检查单位和快速语法，最后在本机未占用端口启动并做真实查询。程序目前没有独立的“只解析、不启动插件”配置检查命令；`start` 会真实打开文件、数据库和监听 socket。不要把源码中未注册的结构字段或内部常量当成用户配置项。

在仓库根目录运行 `go test ./tests/integration -run TestDocumentedExamplesUseKnownPluginParameters`，可严格解码七份示例，检查未知字段、插件类型及全部顶层注册类型的示例覆盖。全模块/全参数模板只做解码，不加载其外部资源；基础测速、IP 替换和静态回退另有无外网的初始化及 A/AAAA 主链测试，HTTPS/SVCB 离线示例验证实际本机 UDP/TCP 回包。这些检查不代替目标环境中的数据库、证书和网络验证。
