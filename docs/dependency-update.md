# 依赖更新记录

日期：2026-10-20。基于 `efd4bfe` 更新当前模块路径下的可用版本，使用 Go 模块代理查询及校验，不跨模块主版本改写 import。完整锁定结果见 [go.mod](../go.mod) 和 [go.sum](../go.sum)。

## 构建与配置兼容性

- `github.com/AdguardTeam/golibs v0.35.17` 要求 Go **1.27.2**，因此同步提高本项目最低 Go 版本。Windows 构建文档与 README 已更新；历史测试报告中的旧工具链版本保留。
- CI 测试、交叉构建及发布使用 `go-version-file: go.mod`，避免构建版本与依赖要求分离。该输入由 [actions/setup-go](https://github.com/actions/setup-go#usage) 支持。
- `pkg/utils.WeakDecode` 统一到现有 `github.com/go-viper/mapstructure/v2 v2.5.0`，保留 duration hook、严格未知字段检查、弱类型输入和 YAML tag；参见[官方迁移说明](https://github.com/go-viper/mapstructure#-migrating-from-githubcommitchellhmapstructure)。
- 保留 `github.com/nadoo/ipset` 的现有 fork replace，Linux 插件依赖其连接实例与显式关闭接口。
- uTLS、pro-bing、DNSCrypt、MaxMind 等没有查到更新版本，继续使用现有锁定版本。

## 版本变化

共升级 27 个保留在 `go.mod` 中的模块。

| 模块 | 更新前 | 更新后 |
| --- | --- | --- |
| `github.com/go-chi/chi/v5` | `v5.2.5` | `v5.5.0` |
| `github.com/kardianos/service` | `v1.2.4` | `v1.3.0` |
| `github.com/klauspost/compress` | `v1.18.4` | `v1.20.3` |
| `github.com/miekg/dns` | `v1.1.72` | `v1.1.73` |
| `github.com/prometheus/client_golang` | `v1.23.2` | `v1.25.0` |
| `github.com/prometheus/client_model` | `v0.6.2` | `v0.6.3` |
| `github.com/quic-go/quic-go` | `v0.59.0` | `v0.64.1` |
| `github.com/vishvananda/netlink` | `v1.3.0` | `v1.3.1` |
| `go.uber.org/zap` | `v1.27.1` | `v1.28.0` |
| `go4.org/netipx` | `v0.0.0-20231129151722-fdeea329fbba` | `v0.0.0-20260823151212-3075585bcbeb` |
| `golang.org/x/crypto` | `v0.57.0` | `v0.58.0` |
| `golang.org/x/exp` | `v0.0.0-20260611194520-c48552f49976` | `v0.0.0-20261014143641-f0251eb4aa3e` |
| `golang.org/x/net` | `v0.59.0` | `v0.61.0` |
| `golang.org/x/sync` | `v0.23.0` | `v0.24.0` |
| `golang.org/x/sys` | `v0.48.0` | `v0.49.0` |
| `golang.org/x/time` | `v0.14.0` | `v0.16.0` |
| `google.golang.org/protobuf` | `v1.36.11` | `v1.36.12` |
| `github.com/AdguardTeam/golibs` | `v0.35.13` | `v0.35.17` |
| `github.com/andybalholm/brotli` | `v1.0.6` | `v1.2.6` |
| `github.com/fsnotify/fsnotify` | `v1.9.0` | `v1.10.1` |
| `github.com/mdlayher/netlink` | `v1.8.0` | `v1.11.2` |
| `github.com/mdlayher/socket` | `v0.5.1` | `v0.8.0` |
| `github.com/pelletier/go-toml/v2` | `v2.2.4` | `v2.4.3` |
| `github.com/prometheus/common` | `v0.67.5` | `v0.72.1` |
| `github.com/prometheus/procfs` | `v0.20.0` | `v0.22.0` |
| `github.com/vishvananda/netns` | `v0.0.4` | `v0.0.5` |
| `golang.org/x/text` | `v0.42.0` | `v0.43.0` |

`go mod tidy` 移除了 `github.com/mitchellh/mapstructure`、`go.yaml.in/yaml/v2`、`golang.org/x/mod`、`golang.org/x/tools` 四项不再需要的显式 require；模块图中的工具或测试依赖仍由上游决定。`client_model` 由间接依赖改为直接依赖，因为测速指标测试直接使用其类型。

## 验证

环境为 Windows amd64、Go 1.27.2；使用从 `efd4bfe` 导出并只叠加本轮文件的快照，排除另一任务的 upstream/GeoIP 改动。

- `go mod verify`、`go mod tidy -diff` 通过；再次查询全部保留的 require，没有发现可用更新。
- 快照全仓 `go test -mod=readonly -race -count=1 -p 2 -timeout 90s ./...` 通过：36 个有测试包通过，46 个包无测试文件。
- 全仓 `go vet -mod=readonly -p 2 ./...` 通过。
- `CGO_ENABLED=0` 的 Windows amd64、Linux ARM64、Linux MIPSLE softfloat 全包构建通过。
- 保留另一任务修改的当前工作区中，GeoIP、DoH、DNSCrypt、forward、utils 和根包这 6 个包的 race 回归通过。
- 新增本地 DoQ/HTTP3 传输适配层测试，覆盖真实 TLS 握手、DNS 往返、ID 恢复、缓冲保护、双端取消及取消后的再次查询。当前工作区连续 5 轮、干净快照连续 3 轮 race 通过，新增测试的 vet 通过。测试显式拥有并关闭客户端传输和 socket；不依赖另一任务对 `NewUpstream` 资源装配的修复。

`govulncheck v1.9.0` 按 Windows 构建条件执行源码符号扫描并返回 0，没有发现当前调用链可达的已知漏洞。扫描保留了一项只有模块信息的 [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)：它针对 `x/crypto/openpgp` 的所有版本，项目没有导入该包。另一次按 Linux 构建条件的扫描及一次重试均因 `vuln.go.dev` 返回不匹配域名的 TLS 证书而中止，未关闭证书校验；因此不将 Windows 扫描结果推广为 Linux 扫描通过。

本轮没有在 Linux 运行全仓测试或需要权限的 ipset/nftables 内核集成。此前记录的工作区上游 UDP 间歇失败和 WSL UDP 限制不作为已修复问题；本次干净快照的 Windows 全仓回归没有重现该失败。
