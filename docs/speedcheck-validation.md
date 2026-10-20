# speedcheck 本地验证记录

日期：2026-10-20。验证对象为当前工作树中的新选择器、响应处理和探测管理器。工作区同时存在另一任务的 upstream/GeoIP 修改，已按用户要求保留；这里不把那些改动记为本功能的交付内容。

## 环境与检查

| 项目 | 环境 / 结果 |
| --- | --- |
| Windows | AMD Ryzen 7 H 255，windows/amd64，Go 1.27.2 |
| Linux | 本机 Debian WSL，linux/amd64，Go 1.26.4，基准 GOMAXPROCS=4 |
| Windows 整仓检查 | pro-bing 迁移后执行 `go test -race -p 2 ./...`：测速相关包通过，`upstream/transport` 的 `Test_dnsConn_exchange/read_err` 断言失败；保留另一任务正在修改的该文件 |
| Linux 定向 race | query_context、response、speedtest、DoH、forward、speedcheck、coremain、fallback 和示例配置集成通过 |
| TCP 集成 | Windows 本机连接成功、连接立即关闭及后续请求可继续使用共享 DoH 客户端 |
| ICMP 集成 | pro-bing v0.9.1；Windows 127.0.0.1 与 ::1 使用 raw 模式，Linux 分别使用 udp4、udp6，实际回声均通过 |
| ICMP 权限降级 | 注入不可用能力，验证有 TCP 时降级、仅 ICMP 时启动报错；未在本机强制禁用真实 socket 权限 |
| 静态检查 | 新功能相关包 `go vet -p 2` 通过 |
| 交叉构建 | Linux ARM64 与 Linux MIPSLE softfloat 整仓 `go build ./...` 通过，CGO_ENABLED=0 |

Go 1.26.4 Linux SDK 下载包 SHA256 经 [官方元数据](https://go.dev/dl/?mode=json&include=all) 核对：`1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f`。验证时使用的 SDK、测试二进制、CPU profile 和临时日志不进入源码改动；本轮提交前清理这些生成物，保留原有参考项目和另一任务的文件。

## pro-bing 与 Windows 运行验证

ICMP 已改用 `github.com/prometheus-community/pro-bing v0.9.1`，不再自行构造和解析 echo 报文。每次发送一个包，通过 `OnRecv` 提前发布 RTT；实际 socket 名额保留到 `RunWithContext` 完成清理。测试验证结果可先返回，而实例关闭仍等待该清理结束，且不会重复发布或写入失败缓存。

回调及管理器同时检查取消和物理探测截止时间，避免读循环在截止后取到迟到回声并写成功缓存；确定性测试分别覆盖取消、超时，以及重复上报仍保持超时失败缓存语义。

Windows 的实际测试进程 `IsElevated=false`，IPv4、IPv6 回声均成功；库的 `SetPrivileged(true)` 表示 raw 模式，不能据此判定所有 Windows 环境都需要管理员权限。启动检查会使用同一后端验证本地回声；不可用时保留 TCP，只有纯 ICMP 配置才拒绝启动。权限降级的注入测试通过，本次没有修改系统权限或防火墙。

`TestWindowsSpeedcheckEndToEnd` 在 IPv4/IPv6 × TCP/TCP+ICMP 四种配置下，实际启动本地 DNS 上游及 UDP/TCP DNS 服务。快来源延时 10ms，慢来源保持阻塞；两种 DNS 传输均在慢来源完成前返回正确地址，本次约 36–38ms。后续请求命中探测缓存，实例关闭后在途、排队和共享探测均归零。Windows 与 WSL 的相关 race 测试通过，迁移后 Linux ARM64、MIPSLE softfloat 整仓交叉构建通过。

迁移后的整仓 Windows race 没有全部通过：另一任务修改中的 `conn_traditional_test.go:187` 在 `read_err` 情况下期望连接尚未关闭，实际已经关闭。单独以 `-count=10` 重复该测试仍出现同一断言，另出现一次 Windows ThreadSanitizer 的 `failed to restore address` 运行时错误。本轮没有修改这些传输文件，也不把定向测速验证表述为整仓通过。

可直接运行的 Windows 配置与命令见 [Windows 说明](speedcheck-windows.md) 和 [配置示例](../examples/speedcheck-windows.yaml)。

## 提交前独立快照检查

为避免把另一任务的 upstream/GeoIP 修改混入提交，使用独立索引导出拟提交源码：forward 只包含分支取消策略，DoH 保留取消、迟到缓冲区回收及 Age/响应校验；另一任务新增的 Close、URL 参数处理、传输与 GeoIP 修改均未纳入。

- 四份示例严格解码通过：基础流程、Windows、speedcheck 全参数、全部模块参数模板；检查未知字段、重复标签、注册插件类型和全部顶层类型覆盖。
- 基础配置实际初始化及保留域名的 A/AAAA 静态 fallback 通过，探测次数为 0；检查不依赖公网查询。全模块及含数据库模板仅做解码，未声称完成数据库/证书/系统集合的运行验证。
- Windows 的独立快照测速相关包和根包 race 测试通过，包含真实 IPv4/IPv6 TCP/ICMP 及 UDP/TCP DNS 端到端验证。Linux 独立快照的根包与 speedtest race 通过。
- Linux 独立快照整仓 race 在原有 `pkg/upstream`、`pkg/upstream/dnscrypt` 的 UDP、DNSCrypt 和 ECH 查询测试中超时，其余包通过。额外导出未改动的 HEAD，定向运行 `Test_UDP_repeat`、`TestUpstream_Exchange`，复现相同超时；这些失败没有随本次 speedcheck 引入，也没有在本次提交中修复。
- 独立快照的 `go vet -p 2 ./...`、Windows CGO_ENABLED=0 构建、版本命令，以及 Linux ARM64、MIPSLE softfloat 整仓交叉构建通过。Markdown 本地链接与 Git 空白检查通过。

原始混合工作树的验证与本节独立提交快照的验证范围不同，不能合并为“整仓全部通过”。临时源码快照、索引、构建产物和验证工具在检查结束后清理。

## 确定性正确性

可控时钟证明：快来源 DNS 10ms 到达后立即开始 20ms 探测，在首个成功后的 25ms 窗口结束时于 **55ms 逻辑时间**提交，此时 200ms 的慢来源尚未完成。相同地址的 `wait_all` 于 200ms 提交，复用已经完成的唯一探测。

测试还覆盖：窗口不重置、乱序事件取最早完成时间、截止前排队结果排空和最终冻结、父取消、插件关闭等待；缓存命中、同键共享、部分/最后订阅取消、队列满和排队截止不记真实失败；标签优先、ASN 回退、零 RTT、倍率与分差边界、完整标签分组、探测全失败和禁测回退；负答、同 IP 多来源、严格 CNAME 链合并、不同终点隔离、过期/TTL0、过滤后等待不延 TTL、无关地址、OPT、DO 和签名处理。

响应快照只提交响应状态，不回写父 query/marks/kv。外层 fallback 的测试同时检查 OPT、接收时间与父取消传递。排队另设截止，实际探测从获得名额开始计时；测试证明排队 80ms 后仍可在 100ms 物理预算内完成 80ms 探测并正确缓存成功。Linux 的 fallback 测试使用真实时钟；旧的全局 timer 池不能在 Go 1.26 的不同 synctest bubble 之间复用，选择器自身的确定性测试使用独立 timer。

## 可控延时对比

本节和下一节为引入 pro-bing 前完成的假探测器/TCP 基准，保留为原始测量记录；本次未重新测量 pro-bing 的 ICMP 吞吐、CPU 或尾延时。

每种模式 40 个样本。两来源分别延时 10ms 和 200ms，返回同一个地址；假探测器延时 20ms。对照先等待两来源，再交给同一选择器测速。全部工作完成允许提前结束，所以对照不额外等待 25ms。结果包含选择器构造与关闭。

| 环境 / 模式 | p50 ms | p95 ms | p99 ms | 进程 CPU ms/请求 | 探测订阅/请求 | 采样 goroutine 峰值 | B/请求 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Windows 流式 | 56.52 | 62.42 | 64.33 | 0.3906 | 1 | 5 | 31586 |
| Windows 先收齐 | 220.9 | 223.7 | 226.7 | 0* | 1 | 5 | 38101 |
| WSL 流式 | 56.52 | 57.00 | 57.03 | 1.323 | 1 | 5 | 31402 |
| WSL 先收齐 | 221.6 | 221.9 | 221.9 | 1.319 | 1 | 5 | 38164 |

`*` Windows 短样本进程 CPU 计时落在量化下限，不能解读为零开销或更省 CPU。Linux 使用 getrusage，Windows 使用 GetProcessTimes；CPU 包含本测试进程的所有线程。采样 goroutine 峰值不是连续采样的绝对峰值。

这组对照表明等待 DNS 与探测重叠后，p50 约缩短 74%，CPU 时间没有显示可辨认的改进。假探测器不打开 socket，两模式逻辑探测峰值均为 1；不能据此推断真实网络连接的峰值。

Windows 无人为 DNS/探测延时的 `BenchmarkSelectorOverhead`：94735 次，29990 ns/请求，0.05839 CPU ms/请求，24462 B/请求，132 allocations/请求。2.84s CPU profile 采样累计 4.07s CPU，包含多线程工作；主要开销位于调度、锁和内存管理。此项是本机实现开销，不是网络延时或目标机吞吐。

## 真实 TCP 资源基准

`BenchmarkLocalTCPProbe` 使用真实 loopback listener，成功即关闭；每次使用不同超时配置键，强制实际探测，避免粗粒度时钟导致短 TTL 缓存意外命中。每模式 100 次，Windows 本机结果：

| 模式 | ns/请求 | 实际探测/请求 | 探测名额峰值 | B/请求 |
| --- | ---: | ---: | ---: | ---: |
| 串行 | 310114 | 1 | 1 | 3915 |
| 并行 | 40930 | 1 | 16 | 4249 |

名额是在实际 socket 方法执行前保留的上界，包含拨号前后的极短准备/清理时间；它不是操作系统 socket 表的连续采样。128 名额硬上限、1024 排队上限和关闭归零另有可控管理器测试验证。共享飞行和缓存避免物理探测的行为由独立测试覆盖，本基准特意绕过这两者。

## 复现与未覆盖范围

完整配置见 [speedcheck.yaml](../examples/speedcheck.yaml)，参数与语义见 [说明](speedcheck.md)。运行：

```text
go test -race -p 2 ./...
go test ./plugin/executable/speedcheck -run TestStreamingOverlapsDNSAndProbe -v
go test ./plugin/executable/speedcheck -run '^$' -bench BenchmarkControlledLatency -benchtime=40x -benchmem
go test ./plugin/executable/speedcheck -run '^$' -bench BenchmarkSelectorOverhead -benchtime=2s -benchmem -cpuprofile speedcheck-cpu.pprof
go test ./pkg/speedtest -run '^$' -bench BenchmarkLocalTCPProbe -benchtime=100x -benchmem
```

未运行真实 OpenWrt/ARM64/MIPSLE 目标机吞吐、长时间多客户端负载或真实互联网路径对比；Windows ICMP 仅验证了本机当前权限与网络策略。交叉编译证明构建兼容，WSL/Windows 数字不能充当目标机性能结论。每请求累计 64 个不同 IP 探测预算耗尽后，迟到高优先级来源中的新地址保留为未测量候选；自定义 source 必须响应 context 才能及时关闭。
