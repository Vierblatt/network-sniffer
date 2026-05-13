// 网络嗅探器 CLI 版 —— 命令行交互式网络数据包捕获与协议分析工具。
// 默认使用 Windows 原始套接字（无需 Npcap），符合课程设计任务书要求。
// 若原始套接字不可用（非 Windows 或权限不足），自动回退到 pcap/Npcap。
// 构建：go build -o sniffer.exe .
//go:build !gui && !web

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"sniffer/analyzer"
	"sniffer/capture"
)

// 捕获统计信息
type Stats struct {
	Total   int
	TCP     int
	UDP     int
	ICMP    int
	ARP     int
	Other   int
	StartAt time.Time
}

// Add 根据协议类型递增对应计数器。
func (s *Stats) Add(proto string) {
	s.Total++
	switch proto {
	case "TCP":
		s.TCP++
	case "UDP":
		s.UDP++
	case "ICMP":
		s.ICMP++
	case "ARP":
		s.ARP++
	default:
		s.Other++
	}
}

// Print 输出格式化的捕获统计信息。
func (s *Stats) Print() {
	elapsed := time.Since(s.StartAt)
	rate := 0.0
	if elapsed.Seconds() > 0 && s.Total > 0 {
		rate = float64(s.Total) / elapsed.Seconds()
	}
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════╗")
	fmt.Println("║          捕获统计                        ║")
	fmt.Println("╠══════════════════════════════════════════╣")
	fmt.Printf("║  总计: %-5d  TCP: %-5d  UDP: %-5d      ║\n", s.Total, s.TCP, s.UDP)
	fmt.Printf("║  ICMP: %-5d  ARP: %-5d  其他: %-5d     ║\n", s.ICMP, s.ARP, s.Other)
	fmt.Printf("║  速率: %-8.1f 包/秒                        ║\n", rate)
	fmt.Printf("║  耗时: %-30s║\n", formatDur(elapsed))
	fmt.Println("╚══════════════════════════════════════════╝")
}

func formatDur(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func main() {
	fmt.Println("╔══════════════════════════════════════════╗")
	fmt.Println("║   计算机网络课程设计 - 网络嗅探器        ║")
	fmt.Println("║         协议分析工具 (CLI版)             ║")
	fmt.Println("╚══════════════════════════════════════════╝")
	fmt.Println()

	// ── 1. 尝试原始套接字 ──
	rawInfos, rawErr := capture.ListRawInterfaces()
	useRaw := rawErr == nil && len(rawInfos) > 0

	if useRaw {
		fmt.Println(">> 使用原始套接字模式（无需 Npcap）")
		fmt.Println()
		fmt.Println("可用的网络接口:")
		for i, info := range rawInfos {
			fmt.Printf("  [%d] %s\n", i, info.Display)
		}

		var choice int
		fmt.Print("请选择接口编号 (0): ")
		_, err := fmt.Scanf("%d", &choice)
		if err != nil || choice < 0 || choice >= len(rawInfos) {
			choice = 0
		}
		bufio.NewReader(os.Stdin).ReadString('\n')

		selected := rawInfos[choice]
		capturer, err := capture.NewRawCapturer(selected.IP)
		if err != nil {
			log.Fatalf("创建原始套接字捕获器失败: %v", err)
		}
		defer capturer.Close()

		runCapture(selected.Display, capturer, true)
		return
	}

	// ── 2. 回退到 pcap/Npcap ──
	fmt.Println(">> 原始套接字不可用，回退到 pcap/Npcap 模式")
	if rawErr != nil {
		fmt.Printf("   （原始套接字错误: %v）\n", rawErr)
	}
	fmt.Println()

	infos, err := capture.ListInterfacesDetailed()
	if err != nil {
		log.Fatalf("获取网络接口列表失败: %v", err)
	}

	fmt.Println("可用的网络接口:")
	for i, info := range infos {
		fmt.Printf("  [%d] %s\n", i, info.Display)
	}

	var choice int
	fmt.Print("请选择接口编号 (0): ")
	_, err = fmt.Scanf("%d", &choice)
	if err != nil || choice < 0 || choice >= len(infos) {
		choice = 0
	}
	bufio.NewReader(os.Stdin).ReadString('\n')

	selected := infos[choice]
	capturer, err := capture.NewCapturer(selected.Name)
	if err != nil {
		log.Fatalf("创建 pcap 捕获器失败: %v", err)
	}
	defer capturer.Close()

	runCapture(selected.Display, capturer, false)
}

// Capturer 接口：统一原始套接字和 pcap 的捕获接口。
type Capturer interface {
	CapturePacket() ([]byte, error)
	Close()
}

func runCapture(ifaceDisplay string, capturer Capturer, useRaw bool) {
	packetAnalyzer := analyzer.NewAnalyzer()

	// Ctrl+C 信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	stats := &Stats{StartAt: time.Now()}
	seq := 0

	// 按 Enter 停止捕获
	stopCh := make(chan struct{})
	go func() {
		bufio.NewReader(os.Stdin).ReadString('\n')
		close(stopCh)
	}()

	fmt.Printf("\n📡 监听接口: %s\n", ifaceDisplay)
	if useRaw {
		fmt.Println("   （原始套接字模式 — 仅捕获 IPv4 数据包，不含以太网头）")
	}
	fmt.Println("⏎ 按 Enter 停止捕获")
	fmt.Println()
	fmt.Println(strings.Repeat("━", 80))

	// 显示表头
	fmt.Printf("%-5s %-8s %-16s %-16s %-6s %-6s %-6s %s\n",
		"#", "时间", "源IP", "目的IP", "协议", "源端口", "目的端口", "长度")

	firstPacket := true

loop:
	for {
		select {
		case <-sigChan:
			fmt.Println("\n⚠ 收到中断信号")
			break loop
		case <-stopCh:
			fmt.Println("\n⏹ 用户停止捕获")
			break loop
		default:
			data, err := capturer.CapturePacket()
			if err != nil {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			seq++

			// 根据捕获模式选择对应的分析方法
			var result analyzer.AnalyzeResult
			if useRaw {
				result = packetAnalyzer.AnalyzeRaw(data)
			} else {
				result = packetAnalyzer.Analyze(data)
			}
			stats.Add(result.Protocol)

			// 每 20 个包重新打印表头，方便阅读
			if seq%20 == 1 && !firstPacket {
				fmt.Println()
				fmt.Println(strings.Repeat("━", 80))
				fmt.Printf("%-5s %-8s %-16s %-16s %-6s %-6s %-6s %s\n",
					"#", "时间", "源IP", "目的IP", "协议", "源端口", "目的端口", "长度")
			}
			firstPacket = false

			now := time.Now().Format("15:04:05")
			srcIP := result.SrcIP
			if srcIP == "" {
				srcIP = "-"
			}
			dstIP := result.DstIP
			if dstIP == "" {
				dstIP = "-"
			}
			proto := result.Protocol
			if proto == "" {
				proto = "-"
			}
			srcPort := result.SrcPort
			if srcPort == "" {
				srcPort = "-"
			}
			dstPort := result.DstPort
			if dstPort == "" {
				dstPort = "-"
			}
			length := fmt.Sprintf("%d", result.Length)
			fmt.Printf("%-5d %-8s %-16s %-16s %-6s %-6s %-6s %s\n",
				seq, now, srcIP, dstIP, proto, srcPort, dstPort, length)
		}
	}

	stats.Print()
	fmt.Println()
	fmt.Print("按 Enter 键退出...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
