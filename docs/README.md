# 文档目录

## 配置与部署

| 文档 | 内容 |
| --- | --- |
| [配置参考](configuration-reference.md) | 顶层字段、全部已启用插件与 sequence 控制流 |
| [全模块模板](examples/all-modules.yaml) | 参数查询模板，需要按用途裁剪 |
| [并行测速选址](speedcheck.md) | 来源链、探测参数、权重、过滤与缓存 |
| [Windows 运行](speedcheck-windows.md) | 构建、ICMP 能力与平台限制 |
| [服务安装](service.md) | Windows、systemd 与 OpenWrt 低权限部署 |
| [IP 前缀替换](ip-replace.md) | CDN 替换顺序和前缀保留 |
| [静态回退](ip-fallback.md) | 无地址、测速失败及未测量的处理 |
| [HTTPS/SVCB 处理](https-record.md) | ECH、hint、ALPN 与辅助查询 |

## 迁移与开发

| 文档 | 内容 |
| --- | --- |
| [SmartDNS 部署迁移](smartdns-migration.md) | 普通/CERNET 配置、数据准备和已知差异 |
| [响应功能迁移对照](response-migration.md) | SmartDNS 与本项目响应处理能力的映射 |
| [依赖更新](dependency-update.md) | Go 版本、依赖更新与验证 |
| [LuCI 补丁核查](luci-patch-status.md) | 补丁覆盖、查询日志补齐和示例基础功能合并 |
| [LuCI 补丁功能复核](luci-patch-audit-20261031.md) | 逐补丁状态、已复现缺陷、来源归因与兼容边界 |
| [优化说明](optimization.md) | 代码复用和性能对照 |
| [项目文件布局](project-layout.md) | 源码、测试、脚本、数据和本地产物 |

## 验证记录

| 记录 | 范围 |
| --- | --- |
| [SmartDNS 配置验证](smartdns-validation.md) | 按日期区分规则等价、受控测试、回环服务和公网实测 |
| [测速验证](speedcheck-validation.md) | 平台、并发、正确性和资源回收 |
| [基准数据](benchmarks/response-optimization-windows-20261020.json) | 优化说明引用的 Windows 测量结果 |

验证记录保留原日期和环境，不代表后续版本或目标部署机器已经验收。
