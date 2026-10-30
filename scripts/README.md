# 项目维护脚本

以下命令均从仓库根目录运行。Python 脚本用于构建和准备数据，mosdns 运行时不依赖 Python。

| 类别 | 文件与用途 |
|---|---|
| 发布构建 | `release.py`：按预设平台构建二进制并打包，输出到根目录 `release/`；CI 使用同一入口。需要 Go、Git 和 Python，启用 `-upx` 时另需 UPX。 |
| SmartDNS 迁移 | `migrate_smartdns_configs.py` 生成两份迁移配置；`migrate_smartdns_data.py` 导出规则数据库、IP 文本及校验清单；`tests/test_migrate_smartdns_data.py` 是数据打包的离线回归测试。 |
| 旧规则更新 | `update_chn_ip_domain.py` 从公开数据源更新规则文本，依赖 `requests`、`netaddr`，结果写入当前工作目录。 |

发布构建：

```sh
python scripts/release.py
```

构建 Windows / Linux AMD64 的六个版本（基础版为 GOAMD64=v1，
另有 v2、v3）：

```sh
python scripts/release.py --amd64-only
```

产物位于 `release/`，命名为 `mosdns-{windows,linux}-amd64[-v2|-v3].zip`。
每个归档包含对应可执行文件、`config.yaml`、`README.md` 和许可证。
可先使用 `--list-targets` 查看目标列表而不构建；
原有 `-i N` 参数仍可选择单个目标。发布工作流使用完整目标列表，
包含上述六个 AMD64 归档。
构建后可运行 `python scripts/verify_release_archives.py`，
核验压缩包内容、Windows PE / Linux ELF 格式以及 GOAMD64 级别。

SmartDNS 迁移复用相邻 `smartdns-test` 已安装 PyYAML、marisa-trie 等依赖的 Python 环境；不另建运行时依赖。Windows 示例：

```powershell
& ..\smartdns-test\.venv\Scripts\python.exe scripts/migrate_smartdns_data.py
& ..\smartdns-test\.venv\Scripts\python.exe scripts/migrate_smartdns_configs.py
```

数据模式、源目录和输出位置见 [迁移说明](../docs/smartdns-migration.md)及[数据说明](../examples/smartdns/README-data.md)。

`openwrt/` 保存 OpenWrt 原生 init 脚本及配套 capability 文件，安装方式见 [service 说明](../docs/service.md)。

根目录的 [tools/](../tools/) 是编入 mosdns 的 Go CLI 子命令包（`config`、`probe`），与本目录的维护脚本分开保留。

从仓库根目录执行数据打包的离线测试，仅需要 Python 标准库：

```sh
python -m unittest discover -s scripts/tests -v
```
