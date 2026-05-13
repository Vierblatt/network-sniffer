# 网络嗅探器 — 协议分析工具

计算机网络课程设计项目，基于 Go 语言的网络数据包捕获与协议分析工具。

## 三种运行形态

| 版本 | 构建命令 | 捕获引擎 |
|-----|---------|---------|
| CLI | `go build -o sniffer.exe .` | 原始套接字（默认），pcap 自动回退 |
| GUI | `go build -tags=gui -ldflags="-H windowsgui" -o sniffer_gui.exe .` | pcap/Npcap |
| Web | `go build -tags=web -o sniffer_web.exe .` | pcap/Npcap |

## 功能特性

- **Windows 原始套接字**：`syscall.Socket(AF_INET, SOCK_RAW, IPPROTO_IP)` + `WSAIoctl(SIO_RCVALL)` 实现混杂模式捕获，无需 Npcap
- **四层协议分析**：链路层（以太网帧）→ 网络层（IPv4/ARP）→ 传输层（TCP/UDP/ICMP）→ 应用层（HTTP/HTTPS/DNS/SSH 等 15+ 协议）
- **TCP 标志位解析**：SYN/ACK/FIN/RST/PSH
- **GUI 桌面界面**：接口选择、实时表格、分层详情面板、分类统计
- **Web 可视化**：RESTful API + SPA 前端

## 快速开始

```bash
# CLI 版（原始套接字，推荐）
go build -o sniffer.exe .
./sniffer.exe

# GUI 桌面版
go install github.com/akavel/rsrc@latest
rsrc -manifest app.manifest -o rsrc.syso
go build -tags=gui -ldflags="-H windowsgui" -o sniffer_gui.exe .
./sniffer_gui.exe

# Web 版
go build -tags=web -o sniffer_web.exe .
./sniffer_web.exe
```

所有版本均需**以管理员权限运行**。pcap 模式需安装 [Npcap](https://npcap.com)。

## 环境要求

- Windows 10/11（64 位）
- Go 1.26+
- Npcap 1.79（仅 pcap/GUI/Web 模式）

## 项目结构

```
├── main.go                   # CLI 入口（原始套接字 + pcap 回退）
├── gui.go                    # GUI 入口（walk 桌面应用）
├── server.go                 # Web 入口（HTTP 服务器）
├── analyzer/analyzer.go      # 协议分析器
├── capture/
│   ├── capture.go            # pcap/Npcap 捕获器
│   └── raw_socket.go         # Windows 原始套接字捕获器
├── web/
│   ├── static/app.js         # Web 前端
│   └── templates/index.html # Web 模板
├── go.mod / go.sum           # Go 模块依赖
└── app.manifest              # Windows GUI 清单
```

## 与任务书要求的对应

| 任务书要求 | 实现 |
|-----------|------|
| 原始套接字与网卡绑定 | `raw_socket.go`：Socket + Bind + SIO_RCVALL |
| 提取源/目的 IP | `parseIPv4()`：IP 头部 data[12:16]、data[16:20] |
| 传输层协议+端口 | `parseTCP()`/`parseUDP()`：协议号 + 端口号 |
| 数据包长度 | `AnalyzeResult.Length`：IPv4 总长度字段 |
| 多层协议分析 | 链路层→网络层→传输层→应用层 |
| 结果显示 | CLI 实时输出 / GUI 表格+详情 / Web 可视化 |

## 文档

- `构建运行说明.md` — 详细构建与运行说明
- `项目完成度评估报告.md` — 逐项完成度自评
- `计算机网络课程设计报告 (1).htm` — Word 导出的课程设计报告
