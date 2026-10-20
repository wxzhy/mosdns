# 响应链简化与性能优化

本轮基于 `33ba1fe`，提交在 `codex/simplify-response-pipeline` 分支。优先复用标准库、现有依赖与公共模块，保留原有配置格式和响应处理策略。未引入新依赖，`go.mod`、`go.sum` 不变。

## 复用与简化

| 部分 | 调整 |
| --- | --- |
| IP/domain 表达式 | `ip_set.CompileExpressions`、`domain_set.CompileExpressions` 统一 `$provider`、`&file` 和普通表达式，内部使用已有 loader、GeoIP/ASN/GeoSite 加载器。`speedcheck`、`ip_replace`、`https_record` 复用同一入口。 |
| ECH 缓存 | 使用现有 `pkg/lru` 替代私有顺序计数与手写淘汰。保留生命周期锁、容量 100、每项来源期限、最长 300 秒及写前过期清理，不新增后台任务。修复满容量重复更新同一个 key 时额外淘汰其他项的问题。 |
| map 复制 | 使用标准库 `maps.Clone` 替代四个私有复制函数，保持独立 map 容器及原有浅复制语义。 |
| 测速候选 | `Analyze` 已按 Answer 顺序生成索引严格递增的独立候选；每轮刷新直接遍历，移除重复切片复制及反射排序。最终排名使用 `slices.SortStableFunc`、`cmp.Compare` 和 `netip.Addr.Compare`，维持原比较次序。 |

DNS 报文与 ICMP 继续分别由 `miekg/dns`、`pro-bing` 处理。CNAME、ECS、TTL、DNSSEC、取消、来源兼容性和响应所有权检查继续保留。代码已运行 `gofmt`，8 个生产 Go 文件合计净减少 81 行；新增回归及基准文件另计。

## 配置兼容性

已有有效配置无需迁移，include 的省略与显式空列表仍由各插件保留并区分。共享加载器统一去除表达式外侧空白，并在启动时拒绝空表达式、裸 `$`/`&`、缺失或类型错误的 provider、返回 nil matcher 的 provider。旧 `speedcheck.labels` 某些无效输入可能曾被忽略或延迟到查询时报错，现在会明确拒绝。

旧 `base_ip`、`base_domain` 的结构化字段语义保持不变；没有把它们的普通 `ips`/`exps` 字段重新解释成 provider 或文件引用。

## 基准方法

基线为干净 `33ba1fe`，仅拷入同一个新增基准文件；优化版本为本次暂存快照。两者均排除其他任务的 upstream/GeoIP 工作区改动。先分别编译测试程序，待验证与编译任务结束，再以 `GOMAXPROCS=4` 交替运行五轮，每项 `500ms`。相同基准文件的哈希用于核对输入一致。

- `BenchmarkRefreshProbes64IPs`：1、4、16 个来源，每来源包含 64 个由真实 `Analyze` 生成的地址；最终候选上限仍为 64。只测刷新开销，复用预先完成的探测状态，不建立 socket。
- `BenchmarkSelectorOverhead`：现有两个本地假来源的完整选择器开销，未注入 DNS/探测延迟。

这些数值只代表本机 Windows 的 CPU/分配开销，不能代替 Linux/OpenWrt 目标机结果或真实 CDN 延迟。原有 55ms 逻辑时间测试继续验证查询与探测重叠。

## 本机对照结果

环境：Go 1.27.2、Windows amd64、AMD Ryzen 7 H 255，`GOMAXPROCS=4`。下表分别取两版本五轮中位数；耗时单位为微秒，内存和分配列按“基线 → 优化后”列出。[全部 40 个原始样本](benchmarks/response-optimization-windows-20261020.json)保留迭代次数、指标、执行顺序及相同基准文件的 SHA-256。

| 场景 | 基线 µs/op | 优化后 µs/op | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: |
| 候选刷新，1 来源 | 17.990 | 16.249 | 26,040 → 21,808 | 30 → 26 |
| 候选刷新，4 来源 | 29.849 | 23.285 | 38,736 → 21,808 | 42 → 26 |
| 候选刷新，16 来源 | 73.442 | 50.023 | 89,520 → 21,808 | 90 → 26 |
| 完整选择器，2 个本地来源 | 17.175 | 17.023 | 24,636 → 23,932 | 131 → 118 |

候选刷新五轮配对均更快，中位耗时分别下降约 9.7%、22.0%、31.9%。完整选择器的约 0.9% 差异不足以作为稳定的耗时改善结论；该项主要确认分配下降，未观察到明显耗时回退。

## 验证范围

冻结暂存快照排除了其他任务的 upstream/GeoIP 修改，完成：

- Windows 19 个相关包的 `-race -count=1`，含原有逻辑时间、容量、取消、DO、配置及真实 UDP/TCP 集成测试。
- `go vet -p 2 ./...`，本批 Go 文件的 `gofmt` 及 Git 空白检查。
- Windows amd64、Linux ARM64、Linux MIPSLE softfloat 的 `CGO_ENABLED=0` 全包构建。
- WSL Linux 的 LRU、query_context、IP/domain 加载器、HTTPS/SVCB、IP 替换、测速包普通测试，以及根包配置和 TCP 集成；Linux 本轮没有启用 race。
- 保留另一任务 upstream/GeoIP 修改的当前工作区，再次通过 7 个相关包的 race 测试，覆盖加载器、IP 替换、HTTPS/SVCB、测速、query_context 和根包集成。

没有将上述结果表述为整仓测试全过。此前的工作区上游 UDP 大报文失败和 WSL UDP 回环限制仍按[响应迁移验证记录](response-migration.md#二次检查与边界修复)保留，本轮没有修改这些代码或系统网络设置。

复现基准：先分别编译基线和优化后的测试程序，再串行交替执行，避免编译/测试负载影响对照。

```powershell
$env:GOMAXPROCS = '4'
go test -c -o speedcheck.test.exe ./plugin/executable/speedcheck
./speedcheck.test.exe '-test.run=^$' '-test.bench=^(BenchmarkSelectorOverhead|BenchmarkRefreshProbes64IPs)$' '-test.benchmem' '-test.benchtime=500ms'
```

干净 `33ba1fe` 的基线需要先拷入同一份 `selector_refresh_bench_test.go`，只增加基准，不改生产代码。每个版本各运行五次，顺序按基线/优化、优化/基线交替。
