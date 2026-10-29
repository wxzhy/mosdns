# mosdns

功能概述、配置方式、教程等，详见: [wiki](https://irine-sistiana.gitbook.io/mosdns-wiki/)

下载预编译文件、更新日志，详见: [release](https://github.com/IrineSistiana/mosdns/releases)

docker 镜像: [docker hub](https://hub.docker.com/r/irinesistiana/mosdns)

源码构建需要 Go 1.27.2 或更新版本，以 [go.mod](go.mod) 为准；参见[依赖更新与验证](docs/dependency-update.md)。

## 配置与部署

| 用途 | 说明 | 配置示例 |
| --- | --- | --- |
| 全部配置与插件 | [配置参考](docs/configuration-reference.md) | [全模块模板](docs/examples/all-modules.yaml) |
| 并行测速选址 | [speedcheck](docs/speedcheck.md) | [基础](examples/speedcheck.yaml) · [全参数](examples/speedcheck-full.yaml) |
| CDN 地址前缀替换 | [ip_replace](docs/ip-replace.md) | [本地演示](examples/ip-replace.yaml) |
| 测速失败静态回退 | [ip_fallback](docs/ip-fallback.md) | [本地演示](examples/ip-fallback.yaml) |
| HTTPS/SVCB 处理 | [ECH、hint 与 ALPN](docs/https-record.md) | [离线演示](examples/https-record.yaml) |
| Windows | [运行说明](docs/speedcheck-windows.md) | [UDP/TCP 示例](examples/speedcheck-windows.yaml) |
| SmartDNS 部署迁移 | [配置、数据与行为差异](docs/smartdns-migration.md) | [普通](examples/smartdns/config.yaml) · [CERNET](examples/smartdns/config-cernet.yaml) |
| 服务安装 | [Windows、systemd 与 OpenWrt 低权限运行](docs/service.md) | [OpenWrt 文件](scripts/openwrt) |

## 项目导航

- [文档目录](docs/README.md)：配置、部署、迁移、性能与验证记录。
- [示例目录](examples/README.md)：按用途选择配置及所需数据。
- [维护脚本](scripts/README.md)：发布构建、规则导出与 OpenWrt 文件。
- [集成测试](tests/integration/README.md)：示例配置、策略和回环服务检查。
- [项目文件布局](docs/project-layout.md)：源码、测试、本地数据和构建产物的存放约定。
