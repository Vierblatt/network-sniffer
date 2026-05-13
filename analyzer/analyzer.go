// 协议分析器 —— 对捕获的网络数据包进行逐层协议解析。
// 支持：以太网帧 → IPv4 → TCP/UDP/ICMP → 应用层协议识别。
// 提供两个入口：Analyze（pcap 捕获，含以太网头）、AnalyzeRaw（原始套接字捕获，无以太网头）。
package analyzer

import (
	"encoding/binary"
	"fmt"
	"net"
)

// AnalyzeResult 协议分析结果，包含各层关键字段。
type AnalyzeResult struct {
	SrcIP        string // 源 IP 地址
	DstIP        string // 目的 IP 地址
	SrcMAC       string // 源 MAC 地址（原始套接字捕获时为 "-"）
	DstMAC       string // 目的 MAC 地址（原始套接字捕获时为 "-"）
	Protocol     string // 传输层协议（TCP/UDP/ICMP/ARP 等）
	SrcPort      string // 源端口号
	DstPort      string // 目的端口号
	Length       int    // 数据包总长度（字节）
	Detail       string // 详细解析信息（标志位、序列号、应用协议等）
	EthernetType string // 以太网帧类型（IPv4/ARP/IPv6/VLAN）
}

// Analyzer 协议分析器（无状态，可复用）。
type Analyzer struct{}

// NewAnalyzer 创建协议分析器实例。
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// AnalyzeRaw 从 IP 层开始解析数据包（适用原始套接字捕获，无以太网头）。
func (a *Analyzer) AnalyzeRaw(data []byte) AnalyzeResult {
	result := AnalyzeResult{Length: len(data)}
	result.SrcMAC = "-"
	result.DstMAC = "-"

	if len(data) < 20 {
		result.Detail = "数据包长度不足（需至少 20 字节 IP 头）"
		return result
	}

	// 从 data[0] 直接解析 IPv4 头部
	result.EthernetType = "IPv4"
	a.parseIPv4(data, &result)
	return result
}

// Analyze 从以太网帧开始解析数据包（适用 pcap/Npcap 捕获）。
func (a *Analyzer) Analyze(data []byte) AnalyzeResult {
	result := AnalyzeResult{Length: len(data)}
	if len(data) < 14 {
		result.Detail = "数据包长度不足（需至少 14 字节以太网头）"
		return result
	}

	// 解析以太网帧头（6字节目的MAC + 6字节源MAC + 2字节类型）
	result.DstMAC = net.HardwareAddr(data[0:6]).String()
	result.SrcMAC = net.HardwareAddr(data[6:12]).String()
	etherType := binary.BigEndian.Uint16(data[12:14])

	// EtherType <= 1500 表示 IEEE 802.3 帧（长度字段，非类型字段）
	if etherType <= 1500 {
		result.EthernetType = "IEEE 802.3"
		result.Detail = fmt.Sprintf("MAC:%s->%s | IEEE802.3", result.SrcMAC, result.DstMAC)
	} else {
		result.Detail = fmt.Sprintf("MAC:%s->%s", result.SrcMAC, result.DstMAC)
		switch etherType {
		case 0x0800: // IPv4
			result.EthernetType = "IPv4"
			a.parseIPv4(data[14:], &result)
		case 0x0806: // ARP
			result.EthernetType = "ARP"
			a.parseARP(data[14:], &result)
		case 0x86DD: // IPv6
			result.EthernetType = "IPv6"
			result.Protocol = "IPv6"
		case 0x8100: // VLAN (802.1Q)
			result.EthernetType = "VLAN"
			result.Protocol = "VLAN"
		}
	}
	return result
}

// parseIPv4 解析 IPv4 头部，根据协议号分派到 TCP/UDP/ICMP 解析。
func (a *Analyzer) parseIPv4(data []byte, result *AnalyzeResult) {
	if len(data) < 20 {
		return
	}

	// IHL（Internet Header Length）：data[0] 低 4 位 × 4 = IP 头字节数
	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || ihl > len(data) {
		return
	}

	result.SrcIP = net.IP(data[12:16]).String()
	result.DstIP = net.IP(data[16:20]).String()
	result.Length = int(binary.BigEndian.Uint16(data[2:4]))

	// data[9] = 协议号：1=ICMP, 6=TCP, 17=UDP
	protocol := data[9]
	switch protocol {
	case 1:
		result.Protocol = "ICMP"
		a.parseICMP(data[ihl:], result)
	case 6:
		result.Protocol = "TCP"
		a.parseTCP(data[ihl:], result)
	case 17:
		result.Protocol = "UDP"
		a.parseUDP(data[ihl:], result)
	default:
		result.Protocol = fmt.Sprintf("IP-%d", protocol)
	}
}

// parseTCP 解析 TCP 段：端口号、序列号、标志位、窗口大小、应用协议。
func (a *Analyzer) parseTCP(data []byte, result *AnalyzeResult) {
	if len(data) < 20 {
		return
	}

	// 源端口（data[0:2]）、目的端口（data[2:4]）
	srcPort := binary.BigEndian.Uint16(data[0:2])
	dstPort := binary.BigEndian.Uint16(data[2:4])
	result.SrcPort = fmt.Sprintf("%d", srcPort)
	result.DstPort = fmt.Sprintf("%d", dstPort)

	// 序列号（data[4:8]）、窗口大小（data[14:16]）
	detail := fmt.Sprintf("Seq=%d Win=%d",
		binary.BigEndian.Uint32(data[4:8]),
		binary.BigEndian.Uint16(data[14:16]))

	// TCP 标志位（data[13]）：SYN(0x02)、ACK(0x10)、FIN(0x01)、RST(0x04)、PSH(0x08)
	flags := data[13]
	flagStr := ""
	if flags&0x02 != 0 {
		flagStr += "SYN "
	}
	if flags&0x10 != 0 {
		flagStr += "ACK "
	}
	if flags&0x01 != 0 {
		flagStr += "FIN "
	}
	if flags&0x04 != 0 {
		flagStr += "RST "
	}
	if flags&0x08 != 0 {
		flagStr += "PSH "
	}
	if flagStr != "" {
		detail += fmt.Sprintf(" [%s]", flagStr)
	}

	// 基于端口号识别常见应用层协议
	if app := identifyAppProtocol(srcPort, dstPort); app != "" {
		detail += " " + app
	}
	result.Detail += " | " + detail
}

// parseUDP 解析 UDP 数据报：端口号、应用协议。
func (a *Analyzer) parseUDP(data []byte, result *AnalyzeResult) {
	if len(data) < 8 {
		return
	}

	// UDP 头：源端口（data[0:2]）、目的端口（data[2:4]）、长度（data[4:6]）、校验和（data[6:8]）
	srcPort := binary.BigEndian.Uint16(data[0:2])
	dstPort := binary.BigEndian.Uint16(data[2:4])
	result.SrcPort = fmt.Sprintf("%d", srcPort)
	result.DstPort = fmt.Sprintf("%d", dstPort)

	// 基于端口号识别常见应用层协议
	if app := identifyAppProtocol(srcPort, dstPort); app != "" {
		result.Detail += " | " + app
	}
}

// parseICMP 解析 ICMP 报文：类型和代码。
func (a *Analyzer) parseICMP(data []byte, result *AnalyzeResult) {
	if len(data) < 4 {
		return
	}
	// ICMP 头：类型（data[0]）、代码（data[1]）
	// 常见类型：0=回显应答, 8=回显请求, 3=目标不可达, 11=TTL超时
	result.Detail += fmt.Sprintf(" Type=%d Code=%d", data[0], data[1])
}

// parseARP 解析 ARP 数据包：操作类型（请求/响应）、IP-MAC 映射。
func (a *Analyzer) parseARP(data []byte, result *AnalyzeResult) {
	if len(data) < 28 {
		return
	}

	// ARP 报文格式：
	// 硬件类型(2) + 协议类型(2) + 硬件地址长度(1) + 协议地址长度(1)
	// 操作码(2): 1=请求, 2=响应
	// 发送方MAC(6) + 发送方IP(4) + 目标MAC(6) + 目标IP(4)
	result.SrcIP = net.IP(data[14:18]).String()
	result.DstIP = net.IP(data[24:28]).String()
	result.Protocol = "ARP"

	op := "请求"
	if binary.BigEndian.Uint16(data[6:8]) == 2 {
		op = "响应"
	}
	result.Detail += fmt.Sprintf(" | ARP%s %s->%s", op, result.SrcIP, result.DstIP)
}

// identifyAppProtocol 根据源/目的端口号识别常见应用层协议。
// 优先级：先匹配源端口，再匹配目的端口。
func identifyAppProtocol(srcPort, dstPort uint16) string {
	portMap := map[uint16]string{
		20: "FTP-D", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
		53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
		123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB",
		3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
		6379: "Redis", 8080: "HTTP-Alt",
	}
	if name, ok := portMap[srcPort]; ok {
		return name
	}
	if name, ok := portMap[dstPort]; ok {
		return name
	}
	return ""
}
