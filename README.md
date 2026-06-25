# cfnat-linux

面向 Linux 的 Cloudflare IP 优选、TCP 转发、健康检查和 DNS 自动同步服务。

它参考了 `amclubs-cfnat` 的工作方式，但核心代码为独立实现，不依赖原项目未公开的二进制源码。

## 功能

- 从本地文件或 HTTP(S) 地址读取 IPv4/IPv6 CIDR 或裸 IP，并缓存成功下载的远程 IP 池。
- 随机抽样或按顺序展开候选 IP。
- 两阶段扫描：先进行轻量 TCP 初筛，再对最快候选执行 TLS、HTTP 状态码和延迟检查，避免大并发完整请求触发限速。
- 可通过 `/cdn-cgi/trace` 按 Cloudflare `colo` 筛选数据中心。
- 维护低延迟目标池，为本地连接进行轮询 TCP 透传。
- 定期健康检查；连续失败后重新优选并无损替换目标池。
- 将前 N 个优选 IP 同步为 Cloudflare `A` 或 `AAAA` 记录。
- DNS 采用“先创建新记录、再删除旧记录”，扫描失败时绝不清空解析。
- systemd 开机启动、自动重启、journald 日志和低权限运行。
- 首次扫描无结果时保持后台运行并定期重试，不再进入 systemd 重启循环。
- 支持 Linux amd64、arm64 和 386。

## 工作流程

```text
IP/CIDR 来源 → 候选生成 → TCP 初筛 → TLS/HTTP 复筛 → 延迟排序 → 目标池 → TCP 转发
                                  ↓
                         Cloudflare DNS 同步
                                  ↓
                      定时健康检查与重新优选
```

## 一键安装

安装机需要 systemd、curl、tar 和 sha256sum。若系统没有 Go，安装脚本会下载经过 SHA-256 校验的临时官方 Go 工具链；编译完成后自动删除，不污染系统环境。

```bash
tar -xzf cfnat-linux-v0.3.0.tar.gz
cd cfnat-linux
sudo ./scripts/install.sh
```

安装脚本会交互询问：

- 本地监听地址；
- IPv4 或 IPv6；
- 最大允许延迟（毫秒）；
- 可选 Cloudflare 数据中心；
- 是否同步 DNS；
- Zone ID、完整记录名和 API Token。

向导会逐项检查输入格式。地址、端口、IP 版本、数据中心代码或 DNS 参数有误时，会说明原因并重新询问当前项目，不会退出整个安装过程。

安装完成后服务会立即进行首次优选。运行管理面板：

```bash
sudo cfnatctl
```

面板会展示：

- systemd 服务是否运行；
- 监听 IP、端口和最大允许延迟；
- 扫描正在进行、已经完成或失败；
- 当前最优 IP；
- 优选池每个 IP 的延迟、colo 和健康状态；
- Cloudflare DNS 是否启用、是否同步成功、解析域名和同步 IP。

面板下方提供运行开关、立即重扫、诊断扫描、修改配置、实时日志以及一键关闭并卸载。运行状态同时保存于 `/var/lib/cfnat/state.json`。

扫描日志会汇总失败原因，例如 `tcp_timeout`、`tls`、`status`、`latency` 和 `colo`。这样可以直接判断是线路不可达、TLS/SNI、探测网址、延迟阈值还是机房筛选导致无结果。

也可以直接使用命令：

```bash
cfnatctl status       # 服务状态
cfnatctl logs         # 实时日志
cfnatctl pool         # 当前优选池
cfnatctl scan         # 重启服务并立即重新优选
cfnatctl config       # 进入配置修改菜单
cfnatctl restart      # 重启服务
cfnatctl uninstall    # 确认后关闭并卸载
```

## Cloudflare DNS 配置

建议创建一个仅限目标 Zone 的 API Token，权限为：

```text
Zone / DNS / Edit
```

Token 保存于 `/etc/cfnat/cfnat.env`，权限为 `0640`，不会写入 JSON、命令行或日志。

优选记录必须保持：

```json
"proxied": false
```

如果开启橙云，DNS 响应会重新变成 Cloudflare Anycast 地址，客户端无法直接得到优选 IP。程序会拒绝 `proxied=true` 配置。

DNS 同步只删除 `comment` 等于 `managed-by:cfnat-linux` 的旧记录，不删除同域名下由用户创建的记录。为避免短暂空解析，它总是先创建新记录，再删除旧记录。

## 配置文件

主配置位于 `/etc/cfnat/config.json`，完整示例见 `configs/config.example.json`。

关键参数：

| 参数 | 默认值 | 说明 |
|---|---:|---|
| `listen` | `0.0.0.0:1234` | 本地 TCP 监听地址 |
| `ip_version` | `4` | `4` 或 `6` |
| `ip_sources` | Cloudflare 官方列表 | CIDR 文件或 URL，可配置多个 |
| `max_candidates` | `2000` | 单轮最多探测的候选数 |
| `concurrency` | `100` | TCP 初筛并发数；完整 TLS/HTTP 复筛自动限制为最多 20 |
| `valid_ip_count` | `20` | 保留的有效 IP 数 |
| `pool_size` | `10` | TCP 转发目标池大小 |
| `target_port` | `443` | 上游 Cloudflare 端口 |
| `check_url` | `https://cloudflare.com/cdn-cgi/trace` | HTTP 状态检查地址及 TLS SNI 来源 |
| `expected_status` | `200` | 期望响应码 |
| `max_latency` | `800ms` | TLS/HTTP 首包最大延迟；超过阈值的 IP 直接淘汰 |
| `colos` | `[]` | 例如 `HKG`、`NRT`、`SJC`；空数组不筛选 |
| `scan_interval` | `6h` | 定期完整重选周期 |
| `health_interval` | `60s` | 当前池健康检查周期 |
| `health_failures` | `3` | 连续失败多少次后重选 |
| `source_cache_dir` | `/var/lib/cfnat/ip-cache` | 远程 IP 池成功下载后的本地缓存目录 |
| `cloudflare_dns.sync_count` | `1` | 同步排名前几个 IP |
| `cloudflare_dns.ttl` | `1` | Cloudflare API 中 `1` 表示自动 TTL |

### 使用自定义 IP 池

创建 `/etc/cfnat/ips-v4.txt`：

```text
1.0.0.0/24
1.1.1.0/24
104.16.0.1
```

修改配置：

```json
"ip_sources": [
  "/etc/cfnat/ips-v4.txt",
  "https://example.com/extra-cidr.txt"
]
```

然后执行：

```bash
cfnatctl check
cfnatctl restart
```

## 手动构建

需要 Go 1.22 或更高版本：

```bash
make test
make build
```

生成三个 Linux 架构版本：

```bash
make release VERSION=v0.3.0
```

## 命令行

```bash
cfnat -config ./config.json check-config
cfnat -config ./config.json migrate-config
cfnat -config ./config.json scan
cfnat -config ./config.json status
cfnat -config ./config.json run
cfnat version
```

`scan` 仅输出扫描结果，不更新 DNS；DNS 只由常驻的 `run` 模式管理。

再次运行安装脚本升级时，会保留已有配置；只有旧版默认的失效探测地址会迁移为新地址，用户自定义的 `check_url` 不会被覆盖。

## 安全与运行边界

- 服务以独立的 `cfnat` 系统用户运行。
- systemd 开启文件系统、设备、权限和内核相关的沙箱限制。
- 仅保留绑定低端口所需的 `CAP_NET_BIND_SERVICE`。
- TLS 默认校验证书，除非明确设置 `insecure_skip_verify=true`。
- 这是四层 TCP 透传，不终止 TLS，也不解析 VLESS、Trojan 等上层协议。
- 程序只负责更新 Cloudflare DNS，不会创建 Zone、修改其他记录或代理状态。

请遵守服务器所在地及使用者所在地的法律法规。

## 卸载

```bash
sudo ./scripts/uninstall.sh
```

或进入 `sudo cfnatctl`，选择“一键关闭并卸载”。

卸载脚本保留 `/etc/cfnat` 和 `/var/lib/cfnat`，防止误删 Token、配置和运行状态。
