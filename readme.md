# MES 抓包与重传（mes_sniffer_resender_cli）

一个用于**旁路抓取 TCP/HTTP POST(JSON)** 报文并**离线重传**到 MES 的实用 CLI + Web UI 工具。核心特性：

- ✅ 使用 `gopacket` + `tcpassembly` 对 TCP 流进行**会话重组**，解析 `http.ReadRequest`
- ✅ 自动识别 `Content-Type: application/json` 的 **POST 请求**
- ✅ 将报文与元信息写入 **BoltDB**（本地 `spool.db`）
- ✅ 提供**Web 界面**（默认 `http://127.0.0.1:8080`）用于列表、筛选（按 SN）、单条/批量重传
- ✅ 提供**交互式 CLI** 用于配置、控制抓包、重传与状态观察
- ✅ 可配置 BPF 过滤器，仅抓取指向 MES Host/Port 的流量
- ✅ 支持**超时控制**、错误信息记录、重试次数统计

> 适用于产线设备→MES 的 HTTP/JSON 报文旁路抓取与补发场景。

---

## 目录

- [快速开始](#快速开始)
- [编译 & 运行](#编译--运行)
- [权限与依赖](#权限与依赖)
- [配置说明](#配置说明)
- [CLI 命令](#cli-命令)
- [Web 界面](#web-界面)
- [数据结构](#数据结构)
- [工作原理](#工作原理)
- [常见问题](#常见问题)
- [安全建议](#安全建议)
- [系统服务示例（systemd）](#系统服务示例systemd)
- [变更记录](#变更记录)

---

## 快速开始

```bash
# 1) 获取源码
# 假设当前目录包含 main 文件：mes_sniffer_resender_cli.go

# 2) 编译（需要 Go 1.20+）
go build -o mes-sniffer ./

# 3) 运行（首次会生成默认 config.json 与 spool.db）
./mes-sniffer

# 4) 在 CLI 里进行配置（至少设置网卡）
> list-ifaces          # 查看可用网卡
> set iface "eth0"     # 或 Windows 下如 "\Device\NPF_{GUID}"
> set host 192.168.111.239
> set port 9888
> set mes-url http://192.168.111.239:9888/eam/snTest/PostInsertTest
> save
> start                # 启动抓包

# 5) 打开 Web 界面
# 浏览器访问 http://127.0.0.1:8080
```

---

## 编译 & 运行

### 环境要求
- Go **1.20+**（推荐 1.21/1.22）
- 平台：Linux / Windows / macOS
- 抓包驱动：
  - **Linux**：需具有 `CAP_NET_RAW` 或 root 权限
  - **Windows**：安装 **Npcap**（WinPcap 兼容）
  - **macOS**：需要 `libpcap`，并以管理员权限运行

### 依赖（已在源码中导入）
- `github.com/google/gopacket`
- `go.etcd.io/bbolt`
- `github.com/google/uuid`

> 这些依赖将由 `go mod` 自动拉取。

### 构建
```bash
go build -trimpath -ldflags "-s -w" -o mes-sniffer ./
```

### 运行
```bash
./mes-sniffer -config /path/to/config.json   # 可选，默认为工作目录下 config.json
```

启动后会显示：
- 配置文件路径
- Web 界面地址（默认 `http://127.0.0.1:8080`）

---

## 权限与依赖

抓包需要底层网卡访问权限：
- Linux：`sudo ./mes-sniffer` 或给予二进制 `CAP_NET_RAW` 能力：
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip ./mes-sniffer
  ```
- Windows：安装 **Npcap**，以管理员身份运行终端。
- macOS：首次运行可能触发权限提示，需允许网络抓包。

---

## 配置说明

配置文件：`config.json`（程序自动创建/更新）。字段如下：

| 字段 | 类型 | 说明 | 默认 |
|---|---|---|---|
| `iface` | string | 抓包网卡名称 | 空（必须设置） |
| `host` | string | 目标 MES IP/主机名（用于自动 BPF） | `192.168.111.239` |
| `port` | int | 目标 MES 端口 | `9888` |
| `mes_url` | string | 默认重传目标 URL | `http://192.168.111.239:9888/eam/snTest/PostInsertTest` |
| `db_path` | string | BoltDB 文件路径 | `spool.db` |
| `ui_addr` | string | Web 监听地址 | `:8080` |
| `bpf_filter` | string | 自定义 BPF（留空时自动生成） | 空 |
| `timeout_sec` | int | HTTP 重传超时（秒） | `10` |

> 若设置了 `bpf_filter`，将**完全覆盖**自动生成的过滤规则。

### 自动 BPF 规则
当 `bpf_filter` 留空时，程序按配置生成：
```
tcp and dst host <host> and dst port <port>
```

---

## CLI 命令

进入程序后，内置交互式命令可用于配置/控制：

```
help                       显示帮助
wizard                     向导填写配置（网卡、MES、端口等）
show                       查看当前配置
save                       保存当前配置到 config.json
list-ifaces                列出可用网卡
start                      启动抓包
stop                       停止抓包
status                     查看抓包状态
set iface "<网卡名>"        设置网卡
set host 192.168.111.239   设置 MES IP
set port 9888              设置 MES 端口
set mes-url http://...     设置默认重传 URL
set timeout 10             设置重传超时（秒）
set bpf "<表达式>"         自定义 BPF 过滤
resend id=<ID> [url=<URL>] 立刻重传某条记录（可临时覆盖 URL）
retry-all [sn=<SN>]        批量重传 captured/failed（可按 SN 过滤）
exit                       退出程序
```

> **提示**：修改配置后可 `save` 落盘，或直接 `start` 让新配置生效。

---

## Web 界面

默认监听 `http://127.0.0.1:8080`。

- 列表字段：时间、SN（从 JSON 中解析 `sn`）、测试结果（`testResult`）、状态（captured/sent/failed）、URL Path、尝试次数
- 顶部支持**按 SN 筛选**（包含于 Body 或汇总字段皆可）
- 操作：
  - **查看**：原始 JSON（已 HTML 转义）
  - **重传**：对单条记录发送到 `mes_url`（或 CLI `resend` 指定 URL）
  - **批量重传**：对列表中 `captured/failed` 状态全部尝试重传

> Web 与 CLI 可同时使用；Web 仅作操作层，数据仍落在 BoltDB。

---

## 数据结构

### BoltDB 表（bucket: `spool`）

每条记录为一份 **SpoolItem**（JSON 序列化）：

```jsonc
{
  "id": "uuid",
  "captured_at": "2025-01-01T12:00:00Z",
  "method": "POST",
  "url": "http://host:port/path",
  "host": "host:port",
  "path": "/path",
  "headers": { "Content-Type": ["application/json"] },
  "body_b64": "<base64(JSON)>",
  "status": "captured|sent|failed",
  "attempts": 0,
  "last_tried": "2025-01-01T12:34:56Z",
  "last_error": "",
  "summary": { "sn": "...", "testResult": "..." },
  "peer": "<dstIP:dstPort>"
}
```

> Body 以 **Base64** 保存，避免编码问题；Web 查看时自动解码并转义。

---

## 工作原理

1. **抓包层**：使用 `pcap` 在指定网卡上按 BPF 过滤接收数据包。
2. **TCP 重组**：`tcpassembly` 将同一 TCP 连接的分片重组为有序字节流。
3. **HTTP 解析**：对重组后的数据流使用 `http.ReadRequest` 解析，仅处理 `POST` 且 `Content-Type` 包含 `application/json` 的请求。
4. **入库**：将请求元数据与 JSON Body（Base64）写入 BoltDB。
5. **重传**：
   - 单条：使用原请求方法/头/体向指定 `mes_url` 发送。
   - 批量：对未发送成功的记录进行遍历重试（可按 SN 过滤）。
6. **状态更新**：记录尝试次数、最后一次错误、时间戳，便于追踪。

---

## 常见问题

### 1) 看不到任何数据？
- 确认 **网卡名称** 设置正确（`list-ifaces`）
- 确认 **权限** 足够（root/Npcap/管理员）
- 确认 **BPF** 是否过于严格（尝试清空 `bpf_filter` 使用自动规则）
- 目标流量是否确实是 **TCP → MES host:port** 且 **HTTP POST JSON**

### 2) 抓到了但重传失败？
- 检查 `config.json` 的 `mes_url` 是否可达、路径是否正确
- 查看记录的 `last_error`（Web/CLI），是否为 4xx/5xx 或网络错误
- 超时可通过 `set timeout 20` 调大
- 某些 MES 需要鉴权/签名，当前仅转发原有 `Authorization`/`Cookie` 头；若缺少，请在上游补齐

### 3) Windows 网卡名字怎么填？
- 使用 `list-ifaces` 查看，形如 `\Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`，将整段填入 `set iface "..."`

### 4) 会不会抓到**响应**？
- 本工具仅解析**请求**（`http.ReadRequest`），不解析响应。

### 5) 如何限制数据保留量？
- 目前未内置过期/清理策略，可通过外部脚本或定期归档 `spool.db`。

---

## 安全建议

- 将 Web 绑定到 `127.0.0.1`（默认）并通过隧道/堡垒机访问；如需对外开放，请置于受控网络并加反向代理鉴权。
- `spool.db` 含业务数据，请妥善备份与访问控制。
- 抓包进程拥有较高权限，建议最小化运行权限与暴露面。

---

## 系统服务示例（systemd）

`/etc/systemd/system/mes-sniffer.service`
```ini
[Unit]
Description=MES Sniffer & Resender
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/mes-sniffer
ExecStart=/opt/mes-sniffer/mes-sniffer -config /opt/mes-sniffer/config.json
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

启用：
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mes-sniffer
```

---

## 变更记录

- v0.1.0 初版：抓包、BoltDB 入库、Web/CLI 重传与过滤

---

## 许可证

内部工具示例（如需开源请补充 LICENSE）。

