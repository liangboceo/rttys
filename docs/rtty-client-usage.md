# rtty-client 使用文档

rtty-client 是 `rttys` 服务端配套的设备端客户端，用于将本地设备接入 rttys 服务端，提供远程终端、命令执行、文件传输、HTTP 代理及内网穿透隧道能力。

## 1. 编译安装

### 1.1 本地编译

```bash
cd rtty-client
go build -o rtty-client .
```

### 1.2 交叉编译

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -o rtty-client-linux-amd64 ./rtty-client/

# Linux arm64
GOOS=linux GOARCH=arm64 go build -o rtty-client-linux-arm64 ./rtty-client/

# Windows amd64
GOOS=windows GOARCH=amd64 go build -o rtty-client-windows-amd64.exe ./rtty-client/

# macOS amd64
GOOS=darwin GOARCH=amd64 go build -o rtty-client-darwin-amd64 ./rtty-client/
```

## 2. 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-addr` | `127.0.0.1:5912` | rttys 服务端设备监听地址（`addr-dev`） |
| `-id` | 主机名 | 设备唯一标识 ID |
| `-desc` | `rtty-client on GOOS/GOARCH` | 设备描述信息 |
| `-token` | `""` | 设备连接 Token，若服务端启用了 Token 校验则必填 |
| `-tls` | `false` | 使用 TLS 连接服务端 |
| `-insecure` | `false` | 跳过 TLS 证书校验（自签名证书场景） |
| `-root` | `.` | 文件传输的根目录（绝对路径） |
| `-http-host` | `127.0.0.1` | 旧 HTTP 代理默认目标 Host |
| `-http-port` | `80` | 旧 HTTP 代理默认目标端口 |
| `-reconnect` | `5s` | 断线重连间隔，设为 `0` 则禁用自动重连 |

## 3. 快速开始

### 3.1 基础连接

```bash
./rtty-client -addr 192.168.1.100:5912 -id my-device
```

### 3.2 带 Token 连接

```bash
./rtty-client -addr 192.168.1.100:5912 -id my-device -token your-secret-token
```

### 3.3 TLS 连接（服务端开启了 TLS）

```bash
./rtty-client -addr 192.168.1.100:5912 -id my-device -tls -insecure
```

### 3.4 自定义文件传输目录

```bash
./rtty-client -addr 192.168.1.100:5912 -id my-device -root /var/shared
```

## 4. 支持的功能

### 4.1 设备注册与心跳

- 启动后自动向 rttys 发送注册消息（`msgTypeRegister`）
- 每 `5` 秒自动发送心跳（`msgTypeHeartbeat`），保持连接活跃
- 支持自动重连，断线后按 `-reconnect` 间隔恢复连接

### 4.2 远程终端

- 服务端下发 `msgTypeLogin` 后，客户端启动本地 Shell（默认 `$SHELL`，不存在则回退到 `/bin/sh`）
- 支持标准输入输出重定向，远程可实时操作设备 Shell
- 支持窗口大小调整（`msgTypeWinsize`）
- 会话关闭时自动清理进程

### 4.3 命令执行

- 服务端下发 `msgTypeCmd` 后，客户端在本地执行指定命令
- 支持带参数命令执行
- 命令输出通过 JSON 格式回传服务端

### 4.4 文件传输

- **文件接收**：服务端下发文件信息，客户端在 `-root` 目录下创建文件并写入数据
- **文件发送**：服务端请求下载，客户端从 `-root` 目录读取文件并分片发送
- 支持传输中断（Abort）和确认（Ack）机制

### 4.5 HTTP 代理

- 服务端通过 `msgTypeHttp` 下发 HTTP 代理请求
- 客户端将请求转发到本地目标服务（默认 `127.0.0.1:80`，可通过 `-http-host` / `-http-port` 调整）
- 响应数据原样回传服务端

### 4.6 内网穿透隧道

- 服务端下发隧道创建消息（`msgTypeHttp` 隧道创建格式）后，客户端记录隧道目标端口
- 后续该隧道对应的公网端口请求，会被转发到设备本地 `127.0.0.1:<tunnel_port>`
- 支持流式分片传输大响应，避免单包大小限制
- 隧道回收时客户端自动清理对应记录

## 5. 运行日志示例

```
2026/07/13 14:00:00 connected to 192.168.1.100:5912 as device my-device
2026/07/13 14:00:00 register ack: code=0 msg="ok"
2026/07/13 14:00:05 tunnel create tunnel=tun-265064e4fa93 local_port=9210 proto=http
2026/07/13 14:00:10 session login: abc123def456...
2026/07/13 14:00:15 file receive start sid=xxx path=/var/shared/upload.bin size=1024
2026/07/13 14:00:20 connection closed: EOF; reconnecting in 5s
2026/07/13 14:00:25 connected to 192.168.1.100:5912 as device my-device
```

## 6. 注意事项

1. **服务端地址**：`-addr` 必须对应 rttys 的 `addr-dev` 监听地址，不是用户端 Web 地址
2. **设备 ID 唯一性**：同一 rttys 实例下，`-id` 必须唯一，重复 ID 会导致后连设备踢掉先连设备
3. **Token 校验**：如果 rttys 配置了 `token`，客户端 `-token` 必须与之匹配，否则注册会被拒绝
4. **文件目录权限**：`-root` 指定的目录需要对运行用户可读写
5. **防火墙**：确保设备能访问 rttys 的 `addr-dev` 端口，隧道代理端口由服务端监听，设备端只需能访问本地目标服务
6. **隧道目标**：内网穿透隧道会将公网请求转发到设备本地 `127.0.0.1:<device_port>`，请确保该端口有服务在监听

## 7. 作为后台服务运行（Linux）

### 使用 systemd

创建 `/etc/systemd/system/rtty-client.service`：

```ini
[Unit]
Description=rtty-client
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rtty-client -addr 192.168.1.100:5912 -id my-device -token your-token
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable rtty-client
sudo systemctl start rtty-client
```

## 8. 相关文档

- [服务端配置说明](../rttys.conf)
- [隧道创建接口文档](./tunnel_create_api.md)
