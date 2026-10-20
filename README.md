# mosdns

功能概述、配置方式、教程等，详见: [wiki](https://irine-sistiana.gitbook.io/mosdns-wiki/)

下载预编译文件、更新日志，详见: [release](https://github.com/IrineSistiana/mosdns/releases)

docker 镜像: [docker hub](https://hub.docker.com/r/irinesistiana/mosdns)

本地配置参考：[顶层配置、全部已启用插件与 sequence 规则](docs/configuration-reference.md) · [全模块参数模板](docs/examples/all-modules.yaml)

并行多上游测速选址：[speedcheck 配置与说明](docs/speedcheck.md) · [基础示例](examples/speedcheck.yaml) · [全参数示例](examples/speedcheck-full.yaml)

CDN 地址前缀替换：[ip_replace 参数与行为](docs/ip-replace.md) · [无外网演示配置](examples/ip-replace.yaml)

测速失败与无 RTT 静态回退：[ip_fallback 配置说明](docs/ip-fallback.md) · [本地演示](examples/ip-fallback.yaml)

HTTPS/SVCB 响应处理：[ECH、hint 与 ALPN](docs/https-record.md) · [离线完整示例](examples/https-record.yaml) · [SmartDNS 响应功能迁移对照](docs/response-migration.md)

Windows：[运行与配置](docs/speedcheck-windows.md) · [UDP/TCP 完整示例](examples/speedcheck-windows.yaml)
