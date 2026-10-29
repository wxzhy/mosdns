# 集成测试

这里集中跨模块测试；各 Go 包的单元测试仍与对应源码放在同一目录。

| 测试文件 | 范围 |
| --- | --- |
| `speedcheck_config_test.go` | 测速示例初始化、全部示例的严格参数解码 |
| `speedcheck_windows_test.go` | Windows 本机 DNS、TCP/ICMP 选址与 UDP/TCP 回包 |
| `ip_replace_config_test.go` | 地址替换示例及本机完整处理链 |
| `ip_fallback_config_test.go` | 静态回退示例及本机完整处理链 |
| `https_record_config_test.go` | HTTPS/SVCB 离线示例的 UDP/TCP 回包 |
| `smartdns_migration_test.go` | 迁移配置解码、路由、过滤、替换及共享 fixture |
| `smartdns_policy_test.go` | 缓存、CNAME、DO、负响应、回退和 HTTPS 辅助查询 |
| `smartdns_realdata_policy_test.go` | 真实数据库规则、MMDB 策略及 DAT 与文本等价 |
| `smartdns_wire_test.go` | 真实数据的回环 UDP/TCP 服务和缓存 |

测试包显式注册生产插件，并在独立进程中定位仓库根目录；示例内的相对路径保持不变。
测试替换外部 DNS 和测速 I/O，或使用本机回环端口。ICMP 能力检查也仅访问回环。

从仓库根目录执行：

```sh
go test -race ./tests/integration -count=1 -timeout=180s
```

需要检查已导出的本地数据库时，在 PowerShell 中执行：

```powershell
$env:MOSDNS_SMARTDNS_LOCAL_DATA = "1"
go test -race ./tests/integration -run '^TestSmartdns' -count=1 -timeout=180s
Remove-Item Env:MOSDNS_SMARTDNS_LOCAL_DATA
```

未启用该环境变量时跳过真实数据检查，不要求 `data/smartdns/` 已存在。
Windows 专属测试仅在 Windows 编译执行；ICMP 能力不可用时按测试定义处理。

Python 数据导出测试位于 `scripts/tests/`，从仓库根目录执行：

```sh
python -m unittest discover -s scripts/tests -v
```

日常 `go test ./...` 仍会自动发现本目录，无需额外维护测试文件列表。
