# 低权限系统服务

`mosdns service install` 创建服务登记，不立即启动，也不验证完整插件链能否运行。安装程序不自动修改已有程序、配置、数据的所有者、文件权限或 Windows ACL；管理员应先准备可读资源和独立的可写目录，再安装、启动并检查日志。

Windows 新安装的服务使用 `NT AUTHORITY\LocalService`。Linux 的内置安装入口仅支持 systemd 247 及以上版本，采用 `User=mosdns`、`DynamicUser=yes` 和 `LoadCredential=`。不满足条件或使用其他 Linux 服务管理器时会报错，不会回退为 root。OpenWrt 使用下文的原生 procd/ujail 脚本。

## 工作目录与配置路径

`service install -d <目录> -c <配置>` 保留指定的工作目录。相对 `-c` 按该工作目录解析，再保存为绝对路径；省略 `-d` 时使用可执行文件所在目录。配置中的 `include`、规则、数据库、证书和其他相对路径仍相对工作目录，不相对主配置文件所在目录。

Linux 将主配置通过 credential 传给服务，临时配置文件保留原格式对应的扩展名；这不会改变相对路径的解析基准。不要将工作目录改成 credential 目录来寻找数据文件。

安装会检查配置格式及文件存在性；systemd 主配置限制为 1,000,000 字节。为避免 unit 解析和服务模板歧义，systemd 工作目录及主配置路径不能以空白或反斜线结尾，也不能包含 `{{`。

替换二进制不会自动更新已登记服务的账户或服务配置。已有部署需按 `stop → uninstall → install → start` 重新登记，并在重新启动前完成权限和可写路径调整。卸载服务不替代配置及状态数据的备份。

## Windows

在管理员 PowerShell 中安装和管理服务；运行时使用 LocalService。建议将二进制放在 `C:\Program Files\mosdns`，将只读配置和数据放在 `C:\ProgramData\mosdns\config`，将日志、缓存等输出放在 `C:\ProgramData\mosdns\state`。服务账户需要读取和执行程序、穿过工作目录并读取被引用文件，不需要修改二进制或配置。

下面示例用于新建部署目录。准备好匹配平台的 `mosdns.exe` 和确认过的 `config.yaml`；已有目录应先检查其 ACL，不直接套用权限示例。

```powershell
$app = 'C:\Program Files\mosdns'
$work = 'C:\ProgramData\mosdns\config'
$state = 'C:\ProgramData\mosdns\state'
New-Item -ItemType Directory -Path $app, $work, $state -Force | Out-Null

# 以下 ACL 由管理员显式设置，service install 不执行这些操作。
icacls $app /grant '*S-1-5-19:(OI)(CI)RX'
icacls $work /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX'
icacls $state /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)M'

Copy-Item .\mosdns.exe "$app\mosdns.exe"
Copy-Item .\config.yaml "$work\config.yaml"
# 将配置引用的规则、数据库和证书放到已准备好读取权限的位置。

& "$app\mosdns.exe" service install -d $work -c config.yaml
& "$app\mosdns.exe" service start
& "$app\mosdns.exe" service status
```

示例 SID 分别为 LocalService、SYSTEM 和本机 Administrators，避免依赖系统界面的账户名称语言。示例未递归重置已有子文件 ACL；复制已有资源后，仍需逐项确认读取权限。Program Files 目录应由管理员管理，不应向 LocalService 授予写权限。

配置中的可写文件使用明确的路径，例如：

```yaml
log:
  level: info
  file: 'C:/ProgramData/mosdns/state/mosdns.log'
# cache 插件的 args 中：
# dump_file: 'C:/ProgramData/mosdns/state/cache.dump'
```

LocalService 的文件访问、用户证书存储和网络身份与当前登录用户不同。终端中能读取的私钥或用户目录文件，不一定能被服务读取。ICMP 应在服务账户的实际环境中检查；管理员终端或普通用户终端中的探测成功不能代替该检查。可先保留 TCP 探测，再根据服务启动日志确认 ICMP 能力，不自动提升为 LocalSystem。相关探测行为见 [Windows 运行说明](speedcheck-windows.md)。

服务控制命令为 `service stop`、`service restart`、`service status` 和 `service uninstall`。停止服务后再替换二进制；需要更新旧登记时，再执行安装命令及启动命令。

## Linux systemd

内置安装要求系统级 systemd 247 或更新版本。新登记的服务使用动态用户 `mosdns`，主配置由 `LoadCredential=` 提供，工作目录保持安装时指定的目录。主配置可以由 root 拥有、权限为 0600；其他 include、证书、规则和数据库仍需满足动态服务用户的读取及路径穿过权限。

如果系统已存在同名静态账户，systemd 可能复用它。服务启动时会检查实际 UID/GID，拒绝以 UID 0 或 GID 0 初始化 DNS 插件；旧的 root 服务应先重新登记，不会自动修改既有账户。

服务启用 `ProtectHome=true`，二进制和工作目录不能位于 `/home`、`/root` 或 `/run/user` 下。放在这些位置的其他运行时资源同样会被遮蔽。主配置由服务管理器读取，可以通过 credential 从这些目录提供，但建议统一放到 `/etc/mosdns`，避免部署依赖个人目录。

以下命令示范新部署。将二进制文件名换成目标架构对应的文件；示例不会递归更改现有目录树的权限。

```sh
sudo install -o root -g root -m 0755 ./mosdns-linux-amd64-v2 /usr/local/bin/mosdns
sudo install -d -o root -g root -m 0755 /etc/mosdns
sudo install -o root -g root -m 0600 ./config.yaml /etc/mosdns/config.yaml

# 按配置逐项准备数据。公开规则可采用以下权限；私钥不能照此处理。
sudo install -d -o root -g root -m 0755 /etc/mosdns/data
# sudo install -o root -g root -m 0644 ./geosite.dat /etc/mosdns/data/geosite.dat

systemctl --version
sudo /usr/local/bin/mosdns service install -d /etc/mosdns -c config.yaml
sudo systemctl cat mosdns
sudo /usr/local/bin/mosdns service start
sudo /usr/local/bin/mosdns service status
sudo journalctl -u mosdns -n 100 --no-pager
```

配置中的默认 stderr 日志由 journal 收集。启用 `ProtectSystem=strict` 后，服务可写目录为 `/var/lib/mosdns`、`/var/log/mosdns` 和 `/run/mosdns`，分别用于持久状态、文件日志和临时运行数据。它们由 systemd 的目录管理设置创建，避免把目录长期绑定到某次动态分配的 UID。不要先创建一个随机 UID，再对整个程序或数据树执行 chown。

配置需显式指定可写文件位置。例如，在 cache 插件的 `args` 中设置：

```yaml
dump_file: /var/lib/mosdns/cache.dump
```

若选择文件日志，设置 `log.file: /var/log/mosdns/mosdns.log`。原来的 `./cache.dump` 或 `./mosdns.log` 仍指向工作目录，通常不可写；设置 HOME 不会改变这一点。配置值不会展开 `$STATE_DIRECTORY`、`$LOGS_DIRECTORY` 等环境变量，应写实际的绝对路径。`/run/mosdns` 不用于需要跨重启保存的数据。

`LoadCredential=` 只处理主配置，不会自动递归提供 include 或私钥。应逐项设计这些文件的读取权限；不能为解决读取错误而把私钥改成公开可读。该机制及动态用户的目录行为见 [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)。

基础服务只授予 `CAP_NET_BIND_SERVICE` 和 `CAP_NET_RAW`，用于低端口监听和 raw ICMP；允许的地址族包含 `AF_NETLINK`，但不默认授予 `CAP_NET_ADMIN`。读取文本 `ip_set` 数据与执行内核 `ipset`/`nftset` 是不同操作。后者以及某些 socket 路由选项可能需要额外网络权限，管理员应根据实际配置和内核评估，不能依赖安装程序自动扩权。

确需内核集合操作时，可由管理员审查后通过 `systemctl edit mosdns` 添加 override，例如：

```ini
[Service]
AmbientCapabilities=
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN
```

`CAP_NET_ADMIN` 允许修改宿主网络状态，范围明显大于 DNS 监听和 ICMP。应用 override 后执行 `systemctl daemon-reload` 和 `systemctl restart mosdns`，并验证具体动作。基础服务设置 `Restart=on-failure`、`RestartSec=3` 和 `TimeoutStopSec=35`；这不代表能检测进程仍存活时的所有 DNS 故障。

服务安装成功只表示登记完成。仍应检查配置和资源读取、监听端口、所用地址族、测速能力、缓存写入及正常停止；安装过程不会以 root 身份运行整条插件链来代替这些验证。

## OpenWrt procd / ujail

OpenWrt 不使用内置 `service install`。采用仓库的 [原生 init 脚本](../scripts/openwrt/mosdns-init-openwrt) 和配套 capability 文件，使用固定的非 root 用户及组 `mosdns`。先准备固件对应的用户管理工具和可用的 `/sbin/ujail`；脚本在缺少用户、jail 或必要权限配置时拒绝启动，不静默回退为 root。

挂载路径不能含空白或通配符 `* ? [ ]`，脚本会在修改运行目录前拒绝这些路径。运行目录限定在 `/var/run/` 下，状态目录限定在 `/var/lib/` 下，两者不能重叠，也不能覆盖程序、配置或资源树。

以下示例用于新部署；账户已存在时先检查再跳过创建。二进制应匹配路由器架构，路径需与脚本顶部的设置一致。

```sh
# 以下命令在路由器的管理员 shell 执行。
groupadd --system mosdns
useradd --system --gid mosdns --home-dir /var/lib/mosdns \
  --no-create-home --shell /bin/false mosdns

mkdir -p /etc/mosdns /var/lib/mosdns /var/run/mosdns
cp ./mosdns-linux-arm64 /usr/bin/mosdns
cp ./config.yaml /etc/mosdns/config.yaml
cp scripts/openwrt/mosdns-init-openwrt /etc/init.d/mosdns
cp scripts/openwrt/mosdns.capabilities.json /etc/mosdns/mosdns.capabilities.json

chown root:root /usr/bin/mosdns /etc/init.d/mosdns /etc/mosdns
chmod 0755 /usr/bin/mosdns /etc/init.d/mosdns /etc/mosdns
chown root:mosdns /etc/mosdns/config.yaml
chmod 0640 /etc/mosdns/config.yaml
chown root:root /etc/mosdns/mosdns.capabilities.json
chmod 0644 /etc/mosdns/mosdns.capabilities.json
chown mosdns:mosdns /var/lib/mosdns /var/run/mosdns
chmod 0750 /var/lib/mosdns /var/run/mosdns

/etc/init.d/mosdns enable
/etc/init.d/mosdns start
logread -e mosdns
```

上述用户管理命令需要提供 `groupadd` / `useradd` 的软件包；不同固件的软件包管理器和可用选项可能不同。不要复制开发机账户数据库或用宿主 Linux 的服务管理方式替代 procd。

程序、配置、规则和数据在 jail 中只读；可写位置为 `/var/lib/mosdns` 和 `/var/run/mosdns`。配置中的缓存输出使用 `/var/lib/mosdns/cache.dump`，默认 stderr/stdout 由 logd 收集。相对资源从脚本指定的工作目录解析，工作目录外的证书或数据库还必须按最小范围增加只读挂载。

`/etc/mosdns/mosdns.capabilities.json` 须是管理员管理的普通文件；基础配置仅保留 `CAP_NET_BIND_SERVICE` 和 `CAP_NET_RAW`，并设置 `no_new_privs`。需要 ipset/nftset 时，应另行评估 capability 和 jail 的网络访问条件，不把基础模式当作已具备网络管理权限。

使用 `/etc/init.d/mosdns stop`、`restart`、`status` 管理实例，停止命令会等待实例结束；不要仅 kill 被 procd 监管的子进程，否则 respawn 会重新拉起它。配置、capability 或挂载路径变动后重启并检查日志。现有部署更换脚本或账户前，应先停止原实例并保留配置与状态文件。

以上是部署说明和命令示例，未在本次文档编写过程中实际安装、启动或修改任何系统服务。
