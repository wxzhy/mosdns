# Windows 运行与配置

Windows amd64 可以运行本功能，默认 TCP 探测不需要 ICMP 权限。ICMP 后端使用 [prometheus-community/pro-bing v0.9.1](https://github.com/prometheus-community/pro-bing/tree/v0.9.1)，不调用系统 ping.exe。本机 IPv4/IPv6 回声和 DNS 服务测试见下文；其他机器仍以自身网络策略和启动能力检查为准。

## 构建与启动

仓库要求 Go 1.26.4 或更新版本。当前功能需从本工作树构建，旧版发行包不包含 `type: speedcheck`。

```powershell
Set-Location 'C:\Users\Lenovo\Documents\Dev\mosdns'
go build -o .\mosdns.exe .
.\mosdns.exe start -d 'C:\Users\Lenovo\Documents\Dev\mosdns' -c 'examples\speedcheck-windows.yaml'
```

[Windows 完整示例](../examples/speedcheck-windows.yaml) 不依赖 GeoIP/ASN 文件，同时监听 UDP 和 TCP 的 `127.0.0.1:15353`。使用本机实际可达的 DNS 上游替换示例地址。前台运行后用 Ctrl+C 关闭。

在另一终端查询自定义端口：

```powershell
nslookup -port=15353 example.com 127.0.0.1
```

也可进入 nslookup 交互模式，执行 `server 127.0.0.1`、`set port=15353`、`set type=A` 后查询域名；`set type=AAAA` 查询 IPv6，`set vc` 使用 TCP。[微软端口配置说明](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nslookup-set-port)。Windows 系统 DNS 地址设置没有端口字段；若要让普通应用通过系统解析器使用它，应让 UDP/TCP 都监听 `127.0.0.1:53` 并检查端口是否已占用。本次检查没有修改系统 DNS 或防火墙。

## 测速配置

```yaml
- tag: select_fast_ip
  type: speedcheck
  args:
    sources: [source_a, source_b]
    mode: bounded
    total_timeout: 5s
    selection_timeout: 300ms
    settle_window: 25ms
    probe:
      tcp_ports: [80, 443]
      icmp: false
      timeout: 300ms
    max_num: 1
    threshold_ms: 100
```

`source_a`、`source_b` 是此前定义的 sequence，每份来源通常只配置一个 forward 上游。序列完成过滤就提交完整候选；地址探测与其他 DNS 查询重叠执行。默认在首个成功 RTT 后再收集 25ms，同时受首个合格正答后 300ms、总预算和所有工作完成的限制。`wait_all` 等待全部来源及相关探测，但仍受总预算限制。

启用 ping 时改为：

```yaml
probe:
  tcp_ports: [80, 443]
  icmp: true
  timeout: 300ms
```

TCP 各端口和 ICMP 并行，首个成功结果立即参与排名，随后取消其他方法。`tcp_ports: []` 显式禁用 TCP，省略该字段则仍默认 80、443。只配置 ICMP 而能力检测失败时初始化报错；保留 TCP 时会记录诊断并禁用不可用的 ICMP。仅一个地址族可用时，另一族的 ICMP 记为未测量，不写真实失败缓存。

pro-bing 以 `Count=1`、`RunWithContext` 和 `OnRecv` 取 RTT，禁用 `RecordRtts` / `RecordTTLs`；直接设置目标 IP，不增加一次域名解析。Windows 按库说明调用 `SetPrivileged(true)`。这个名字表示 raw ICMP 模式，[库文档说明 Windows 10 通常不需要提升权限](https://github.com/prometheus-community/pro-bing/blob/v0.9.1/README.md#windows)，本机非提升进程的 IPv4、IPv6 测试也通过；不能据此保证所有 Windows 策略环境都允许 raw socket。启动时使用同一后端对 loopback 做能力检查，不只检查能否创建 socket。

库的读循环取消可能需要等待其读超时收尾。管理器通过回调提前发布成功 RTT，直到 `RunWithContext` 真正结束才释放该物理 socket 名额；实例关闭等待全部收尾。不会为加快回包而提前归还仍在使用的名额。

## 权重、过滤与文件路径

标签 CIDR/IP 匹配、`ip_set` 数据提供器、GeoIP 和 ASN 匹配均可在 Windows 使用。例如：

```yaml
labels:
  preferred: ['&C:/mosdns/data/preferred.txt']
  cf: ['ext:C:/mosdns/data/ASN.mmdb:13335']
tag_multipliers:
  - {tag: preferred, multiplier: 0.8}
  - {tag: cf, multiplier: 0.9}
```

首个命中的标签倍率优先于 ASN 倍率，分数为 `RTT_ms × multiplier`，越小越优先；未命中倍率为 1。多个输出地址须与最佳 IP 的完整标签集合一致，且分差不大于 `threshold_ms`；全部无成功 RTT 时按倍率回退。客户端 DO=1 时选择完整来源，不按 `max_num` 裁剪 RRset。

Windows YAML 路径用单引号或正斜杠，避免双引号中的反斜杠被当作转义。`-d` 先设置进程工作目录，再读取 `-c`，因此相对配置、规则文件和默认数据库都相对工作目录。数值 `asn_multipliers` 依次查找工作目录中的 `ASN.mmdb`、`GeoLite2-ASN.mmdb`、`asn.mmdb`；需要指定其他位置时可像上例那样使用标签表达式。

## Windows 平台边界

| 项目 | 行为 |
| --- | --- |
| TCP 探测 | 标准 `net.Dialer.DialContext`，IPv4/IPv6，成功立即关闭 |
| ICMP 探测 | pro-bing 的 Windows raw 模式，启动能力检查和不可用降级 |
| UDP/TCP DNS 监听 | 均支持；完整示例同时配置两者 |
| `ip_set` 数据匹配 | 支持，注意与下面的 executable 名称不同 |
| executable `ipset`、`nftset` | Windows 分支不执行内核集合操作，不会写入 Windows 防火墙 |
| forward 的 `so_mark`、`bind_to_device` | Windows 无效 |
| forward 的 `use_tricks` | UDP 启发式过滤及 Winsock TCP OOB 路径有实现，不是 Linux 专属；与目标地址测速无关 |
| forward 的 SOCKS/绑定设置 | 不会作用于 speedcheck 探测；探测使用系统直连路由 |

首版只内置原始 RTT 缓存：成功 60s、真实失败 5s、10000 项。每个实例共享，最多 128 个物理探测 socket。若在选择器前增加最终 DNS 响应缓存，应在缓存后以 `has_resp` / `accept` 提前结束链，命中才会绕过选择器；`cache` 自身仍会继续执行后续规则。Windows 示例没有包这一层缓存。完整筛选和 DNS 保护规则见 [通用说明](speedcheck.md)。

## 本机验证

日期 2026-10-20，Windows amd64、Go 1.27.2。已构建 CGO_ENABLED=0 的 Windows 可执行文件并成功运行版本命令。pro-bing 的真实 IPv4/IPv6 loopback 测试在进程 `IsElevated=false` 下通过；该值不代替对其他机器权限的判断。

新增 Windows 端到端测试，使用本机两路 UDP DNS 上游、真实 TCP 探测监听和本项目 UDP/TCP DNS 服务实现，覆盖 A/AAAA、TCP-only 与 TCP+ICMP、跨 DNS 传输复用探测缓存以及关闭后资源归零。慢上游被明确阻塞，快来源仍可先回包；这证明执行重叠，不是互联网测速结果。

```powershell
go test -race -v ./pkg/speedtest -run 'TestWindowsICMP|TestTCPProbe'
go test -race -v . -run TestWindowsSpeedcheckEndToEnd
```

Windows 服务接口已存在，但本轮没有安装服务或修改系统设置。若需要服务运行，可在部署目录执行 `service install -d ... -c ...` 后 `service start`；服务安装权限与普通前台运行是两回事。
