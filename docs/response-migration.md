# SmartDNS 响应处理迁移对照

本批对照同级 `smartdns-test/smartdns/actions` 的当前代码与测试，迁移响应处理能力。参考项目只读，不修改其配置或源码；mosdns 工作区另一任务的 upstream/GeoIP 改动不并入本批提交。

## 功能对应

| smartdns-test action | mosdns 接线 | 本批处理 |
| --- | --- | --- |
| `log` | `query_summary`、`debug_print` | 使用已有动作。 |
| `static` | `hosts`、`arbitrary`、`black_hole` 加 `accept`；其他类型可显式 `reject 0` 产生空正答 | 使用已有动作；静态 TTL 按实际动作配置。 |
| `replace` | [`ip_replace`](ip-replace.md) | 已有按 prefix 掩码替换，只保留生成地址。 |
| `speedcheck` | [`speedcheck`](speedcheck.md) | 已有多来源流式测速、倍率、过滤和禁测排序；新增响应级测速结果状态。 |
| `filter` | 来源 sequence 的 `matches`、`resp_ip`、`drop_resp`，及地址选择器的 `candidate_filter` | 扩展 `resp_ip` 读取 HTTPS/SVCB 终点 ServiceMode 的 hint，供来源过滤；不把 hint 当作测速候选。 |
| `fallback` | 新增 [`ip_fallback`](ip-fallback.md)；查询错误仍使用既有主次执行链 `fallback` | 默认处理真实测速全失败和 NOERROR/NODATA；可显式 `no_rtt` 扩展到禁测/未完成。 |
| `https` | 新增 [`https_record`](https-record.md) | 清理 hint/ALPN，按每条记录的 Target 和 IP 条件添加 ECH，执行完整 A 路由辅助查询与 NODATA 合成；额外支持 SVCB。 |

本表覆盖 SmartDNS 的上述七类 action，不代表恢复 mosdns v4 的所有插件。v4 的 padding、bufsize、通用 edns0_filter 等不属于本次 SmartDNS 响应功能迁移。

## 处理顺序

对 A/AAAA，来源内部先查询、过滤、可选 prefix 替换；speedcheck 在来源返回时立即探测，最终选择后执行按域名限制的 ip_fallback。静态备用地址不重新探测，也不混入原地址。关闭测速使用显式 `tcp_ports: []` 和 `icmp: false`；是否静态回退由 ip_fallback.on 决定。

对 HTTPS/SVCB，先完成需要使用原 hint 的来源过滤，再调用 https_record。它先提交独立的参数清理结果，再并行处理 ECH 与有界的目标 A 查询。A 来源可以复用完整的替换、过滤、测速、静态回退及缓存链；其结果仅用于当前记录门控，不回写父查询，也不表示浏览器自己的 A 查询已经收到响应。

```yaml
# 来源过滤片段，在 $process_bindings 清理 hint 之前执行：
- exec: $upstream
- matches: ["qtype 64 65", "resp_ip 0.0.0.0/8 ::/128"]
  exec: drop_resp
- exec: $process_bindings
```

`resp_ip` 对 A/AAAA 保持原有 Answer 匹配；新增的 hint 匹配只读取合法服务绑定终点，不读取 Additional 或无关 owner 的 hint。需要标签/ASN 条件时仍可通过现有 IPSet/GeoIP/ASN 表达式组合 matcher。

## 与参考实现的取舍

- 配置沿用 mosdns 的命名 sequence 和 matcher，未复制另一套路由/域名映射系统。静态回退与执行链 fallback 分开命名。
- 禁测、容量受限、排队截止和未完成保持“未测量”；默认不视作真实失败。显式 `no_rtt` 才扩大静态回退条件。
- ECH 授权按每条 ServiceMode 独立的 hints/TargetName 判定，避免整份响应汇总 IP 后误授权其他端点。hint 处理包含匹配、过滤与删除，不会凭空补入 A 结果或把其地址硬拼到不同 Target。
- 参考仅处理 HTTPS；本实现同样支持类型 64 的 SVCB。AliasMode 保留，已有 ECH 不覆盖，删除 ALPN 时同步修复 no-default-alpn 和 mandatory。
- 所有重建使用独立响应快照；客户端/查询 DO=1 跳过。DO=0 清除失效的签名、证明及 AD/AA，保留有效 CNAME、EDNS/ECS 视图与来源有效期限。
- ECH 成功缓存按插件实例、完整查询视图和 ServerMeta 隔离，最多 100 条、300 秒且不超过来源期限；TTL0 不缓存。目前不实现跨请求在途 ECH 合并或无 ECH 负缓存，失败后可重试。缓存只保存原 ECH，不保存最终排名或授权结论。

服务绑定参数的处理依据 [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html)，ECH DNS 参数与列表外框分别参考 [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html)、[RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html)。ECH 外框校验不替代 TLS 客户端对全部 HPKE 参数的验证。

## 离线示例与验证范围

[静态回退示例](../examples/ip-fallback.yaml) 和 [HTTPS/SVCB 示例](../examples/https-record.yaml) 不查询公网，也不探测文档地址。ECH 示例为结构完整的固定测试配置，没有对应 TLS 服务；生产环境需要兼容目标 CDN 的真实 ECH 来源。

```powershell
go test -race -p 2 ./pkg/query_context ./pkg/response ./plugin/executable/ip_fallback ./plugin/executable/https_record ./plugin/executable/speedcheck ./plugin/matcher/resp_ip .
go vet -p 2 ./...
```

根包严格解码全部文档示例并检查注册插件覆盖；应用集成检查本地 A/AAAA、HTTPS/SVCB 和 DNS 序列化。逻辑时间与假探测器验证查询/探测重叠、失败与未测量的区别，以及 ECH/A 并行、取消、期限和清理；这些结果不能作为实际 CDN 延时或 TLS/ECH 握手成功的证据。上游原有测试问题仍单独保留，不能将相关包通过表述为整仓测试通过。

2026-10-20，使用单独导出的 Git 暂存快照验证；快照不含另一任务的 upstream/GeoIP 修改。Go 版本为 1.27.2，结果如下：

| 检查 | 结果与范围 |
| --- | --- |
| Windows race | query_context、response、ip_fallback、https_record、ip_replace、speedcheck、resp_ip、sequence/fallback、coremain 及根包通过；包含实际 UDP/TCP 回包与严格示例覆盖。 |
| Linux amd64 普通测试 | WSL Debian 中 query_context、response、ip_fallback、https_record、speedcheck、resp_ip 通过；根包配置检查与 HTTPS/SVCB 的全部 TCP 场景通过。此次 Linux 测试没有启用 race。 |
| Linux UDP 限制 | 根包 UDP 场景在本机 WSL 超时；不含 DNS 代码的标准库 UDP 回环程序，分别使用 ReadFrom 和 ReadMsg，也收不到自身发出的数据。故 Linux UDP 运行验证尚未完成，未据此改动产品监听器。 |
| 静态检查与构建 | 快照上 `go vet -p 2 ./...` 通过；Windows amd64 可执行文件构建并运行 version；`CGO_ENABLED=0` 的 Linux ARM64、MIPSLE softfloat 全包交叉构建通过。 |
| 文档与格式 | 新示例严格解码与注册插件覆盖通过；本批 Markdown 本地链接及 Go 格式检查通过。 |

本批没有运行或宣称通过整仓 `go test ./...`，也未执行真实 CDN 或 TLS/ECH 端到端测试。
