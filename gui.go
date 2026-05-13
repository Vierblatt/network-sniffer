// 网络嗅探器 GUI 版 —— 基于 walk 工具包的 Windows 桌面图形界面。
// 功能：接口选择、开始/停止/清空捕获、实时数据包表格、分层详情面板、统计栏。
// 基于 pcap/Npcap 捕获，需管理员权限运行。
// 构建：go build -tags=gui -ldflags="-H windowsgui" -o sniffer_gui.exe .
// 编译前需生成 rsrc.syso：go install github.com/akavel/rsrc@latest && rsrc -manifest app.manifest -o rsrc.syso
//go:build gui

package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"sniffer/analyzer"
	"sniffer/capture"
)

// ---- Data Types ----

type PacketEntry struct {
	Seq      int
	Time     string
	SrcIP    string
	DstIP    string
	Protocol string
	SrcPort  string
	DstPort  string
	Length   string
	Detail   string
	SrcMAC   string
	DstMAC   string
}

// PacketTableModel implements walk.TableModel for the packet list.
type PacketTableModel struct {
	walk.TableModelBase
	mu    sync.RWMutex
	items []PacketEntry
}

func (m *PacketTableModel) RowCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.items)
}

func (m *PacketTableModel) Value(row, col int) interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if row < 0 || row >= len(m.items) {
		return nil
	}
	p := m.items[row]
	switch col {
	case 0:
		return p.Seq
	case 1:
		return p.Time
	case 2:
		return p.SrcIP
	case 3:
		return p.DstIP
	case 4:
		return p.Protocol
	case 5:
		return p.SrcPort
	case 6:
		return p.DstPort
	case 7:
		return p.Length
	}
	return nil
}

func (m *PacketTableModel) Append(p PacketEntry) {
	m.mu.Lock()
	m.items = append(m.items, p)
	if len(m.items) > 5000 {
		m.items = m.items[2500:]
	}
	m.mu.Unlock()
}

func (m *PacketTableModel) Reset() {
	m.mu.Lock()
	m.items = nil
	m.mu.Unlock()
}

func (m *PacketTableModel) Row(row int) *PacketEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if row < 0 || row >= len(m.items) {
		return nil
	}
	p := m.items[row]
	return &p
}

// IfaceListModel implements walk.ListModel for the interface combobox.
type IfaceListModel struct {
	walk.ListModelBase
	items []string
}

func (m *IfaceListModel) ItemCount() int {
	return len(m.items)
}

func (m *IfaceListModel) Value(index int) interface{} {
	if index < 0 || index >= len(m.items) {
		return nil
	}
	return m.items[index]
}

// ---- Capture Statistics ----

type GuiStats struct {
	mu                       sync.Mutex
	Total, TCP, UDP, ICMP, ARP, Other int
	StartTime                time.Time
}

func (s *GuiStats) Add(proto string) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func (s *GuiStats) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Total = 0
	s.TCP = 0
	s.UDP = 0
	s.ICMP = 0
	s.ARP = 0
	s.Other = 0
	s.StartTime = time.Time{}
}

func (s *GuiStats) Snapshot() (total, tcp, udp, icmp, arp int, rate float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	total, tcp, udp, icmp, arp = s.Total, s.TCP, s.UDP, s.ICMP, s.ARP
	if !s.StartTime.IsZero() && total > 0 {
		elapsed := time.Since(s.StartTime).Seconds()
		if elapsed > 0 {
			rate = float64(total) / elapsed
		}
	}
	return
}

// ---- Global State ----

var (
	// widgets
	mainWindow  *walk.MainWindow
	packetTable *walk.TableView
	detailEdit  *walk.TextEdit
	ifaceCombo  *walk.ComboBox
	startBtn    *walk.PushButton
	stopBtn     *walk.PushButton
	totalLabel  *walk.Label
	tcpLabel    *walk.Label
	udpLabel    *walk.Label
	icmpLabel   *walk.Label
	arpLabel    *walk.Label
	rateLabel   *walk.Label

	// data
	packetModel *PacketTableModel
	guiStats    *GuiStats

	// capture state
	capturer    *capture.Capturer
	pktAnalyzer *analyzer.Analyzer
	isCapturing bool
	captureMu   sync.Mutex
	stopCh      chan struct{}
	captureDone chan struct{}

	// scroll / selection state
	autoScroll         = true
	programmaticSelect bool
	packetsDirty       bool
)

// ---- Event Handlers ----

func onStart() {
	captureMu.Lock()
	defer captureMu.Unlock()

	if isCapturing {
		return
	}

	idx := ifaceCombo.CurrentIndex()
	if idx < 0 {
		walk.MsgBox(mainWindow, "错误", "请先选择网络接口", walk.MsgBoxIconError)
		return
	}

	displayName := ifaceCombo.Text()
	infos, err := capture.ListInterfacesDetailed()
	if err != nil {
		walk.MsgBox(mainWindow, "错误", "获取接口列表失败: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	var deviceName string
	for _, info := range infos {
		if info.Display == displayName {
			deviceName = info.Name
			break
		}
	}
	if deviceName == "" {
		deviceName = displayName
	}

	c, err := capture.NewCapturer(deviceName)
	if err != nil {
		walk.MsgBox(mainWindow, "错误",
			"打开网络接口失败:\n"+err.Error()+"\n\n请确认:\n1. 已安装 Npcap\n2. 以管理员权限运行",
			walk.MsgBoxIconError)
		return
	}

	capturer = c
	pktAnalyzer = analyzer.NewAnalyzer()
	packetModel.Reset()
	packetModel.PublishRowsReset()
	guiStats.Clear()
	guiStats.StartTime = time.Now()
	statsSnapshot = statsLabelText{}

	isCapturing = true
	stopCh = make(chan struct{})
	captureDone = make(chan struct{})

	autoScroll = true
	packetsDirty = false
	detailEdit.SetText("")

	startBtn.SetEnabled(false)
	stopBtn.SetEnabled(true)
	ifaceCombo.SetEnabled(false)

	go captureLoop()
}

func onStop() {
	captureMu.Lock()
	if !isCapturing {
		captureMu.Unlock()
		return
	}
	isCapturing = false
	close(stopCh)
	captureMu.Unlock()

	// Wait for captureLoop to finish, then update UI
	go func() {
		<-captureDone
		mainWindow.Synchronize(func() {
			startBtn.SetEnabled(true)
			stopBtn.SetEnabled(false)
			ifaceCombo.SetEnabled(true)
		})
	}()
}

func onClear() {
	captureMu.Lock()
	active := isCapturing
	captureMu.Unlock()

	if active {
		onStop()
		<-captureDone
	}
	packetModel.Reset()
	packetModel.PublishRowsReset()
	guiStats.Clear()
	statsSnapshot = statsLabelText{}
	detailEdit.SetText("")
	autoScroll = true
	packetsDirty = false
	updateStatsLabels()
}

func onSelectionChanged() {
	if programmaticSelect {
		return
	}
	idx := packetTable.CurrentIndex()
	if idx < 0 {
		detailEdit.SetText("")
		return
	}
	updateDetail(idx)
	// User manually clicked a row — track whether they're at the bottom
	n := packetModel.RowCount()
	autoScroll = (idx >= n-1)
}

func updateDetail(idx int) {
	p := packetModel.Row(idx)
	if p == nil {
		detailEdit.SetText("")
		return
	}
	detailEdit.SetText(formatDetail(p))
}

func formatDetail(p *PacketEntry) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("═══ 数据包 #%d ═══\r\n\r\n", p.Seq))

	b.WriteString("── 链路层 ──\r\n")
	b.WriteString(fmt.Sprintf("  源MAC:    %s\r\n", p.SrcMAC))
	b.WriteString(fmt.Sprintf("  目的MAC:   %s\r\n\r\n", p.DstMAC))

	b.WriteString("── 网络层 ──\r\n")
	b.WriteString(fmt.Sprintf("  源IP:     %s\r\n", p.SrcIP))
	b.WriteString(fmt.Sprintf("  目的IP:   %s\r\n", p.DstIP))
	b.WriteString(fmt.Sprintf("  协议:     %s\r\n", p.Protocol))
	b.WriteString(fmt.Sprintf("  长度:     %s 字节\r\n", p.Length))

	if p.SrcPort != "-" || p.DstPort != "-" {
		b.WriteString("\r\n── 传输层 ──\r\n")
		b.WriteString(fmt.Sprintf("  源端口:   %s\r\n", p.SrcPort))
		b.WriteString(fmt.Sprintf("  目的端口: %s\r\n", p.DstPort))
	}

	if p.Detail != "" {
		b.WriteString("\r\n── 协议解析 ──\r\n")
		b.WriteString("  " + p.Detail + "\r\n")
	}

	b.WriteString("\r\n" + strings.Repeat("═", 32))
	return b.String()
}

// ---- Capture Loop (runs in background goroutine) ----

func captureLoop() {
	defer func() {
		captureMu.Lock()
		if capturer != nil {
			capturer.Close()
			capturer = nil
		}
		isCapturing = false
		captureMu.Unlock()
		close(captureDone)
	}()

	seq := 0
	for {
		select {
		case <-stopCh:
			return
		default:
		}

		captureMu.Lock()
		if !isCapturing {
			captureMu.Unlock()
			return
		}
		c := capturer
		captureMu.Unlock()

		data, err := c.CapturePacket()
		if err != nil {
			select {
			case <-stopCh:
				return
			default:
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}

		result := pktAnalyzer.Analyze(data)
		guiStats.Add(result.Protocol)
		seq++

		now := time.Now().Format("15:04:05")
		srcIP := orDash(result.SrcIP)
		dstIP := orDash(result.DstIP)
		proto := orDash(result.Protocol)
		srcPort := orDash(result.SrcPort)
		dstPort := orDash(result.DstPort)
		length := fmt.Sprintf("%d", result.Length)

		packetModel.Append(PacketEntry{
			Seq: seq, Time: now,
			SrcIP: srcIP, DstIP: dstIP,
			Protocol: proto, SrcPort: srcPort, DstPort: dstPort,
			Length: length, Detail: result.Detail,
			SrcMAC: result.SrcMAC, DstMAC: result.DstMAC,
		})
		packetsDirty = true
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ---- UI Refresh (called via timer on main thread) ----

type statsLabelText struct {
	total, tcp, udp, icmp, arp, rate string
}

var statsSnapshot statsLabelText

func uiRefreshLoop() {
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		if mainWindow.IsDisposed() {
			return
		}
		mainWindow.Synchronize(func() {
			if mainWindow.IsDisposed() {
				return
			}

			if packetsDirty {
				packetsDirty = false
				prevIdx := packetTable.CurrentIndex()
				packetModel.PublishRowsReset()

				n := packetModel.RowCount()
				// Decide which row to select: keep user's selection or auto-scroll
				if n > 0 && autoScroll {
					programmaticSelect = true
					packetTable.SetCurrentIndex(n - 1)
					programmaticSelect = false
					updateDetail(n - 1)
				} else if prevIdx >= 0 && prevIdx < n {
					programmaticSelect = true
					packetTable.SetCurrentIndex(prevIdx)
					programmaticSelect = false
				}
			}

			updateStatsLabels()
		})
	}
}

func updateStatsLabels() {
	total, tcp, udp, icmp, arp, rate := guiStats.Snapshot()
	totalLabel.SetText(fmt.Sprintf("总计: %d", total))
	tcpLabel.SetText(fmt.Sprintf("TCP: %d", tcp))
	udpLabel.SetText(fmt.Sprintf("UDP: %d", udp))
	icmpLabel.SetText(fmt.Sprintf("ICMP: %d", icmp))
	arpLabel.SetText(fmt.Sprintf("ARP: %d", arp))
	rateLabel.SetText(fmt.Sprintf("速率: %.1f 包/秒", rate))
}

// ---- Main ----

func main() {
	runtime.LockOSThread()

	// Log to file
	logFile, _ := os.Create("sniffer_gui.log")
	if logFile != nil {
		log.SetOutput(logFile)
		defer logFile.Close()
	}

	// Enumerate interfaces
	infos, err := capture.ListInterfacesDetailed()
	if err != nil {
		log.Fatalf("获取接口列表失败: %v", err)
	}
	var ifaceNames []string
	for _, info := range infos {
		ifaceNames = append(ifaceNames, info.Display)
	}
	if len(ifaceNames) == 0 {
		ifaceNames = []string{"(无可用接口 - 请以管理员身份运行)"}
	}

	packetModel = &PacketTableModel{}
	guiStats = &GuiStats{}
	ifaceModel := &IfaceListModel{items: ifaceNames}

	err = (MainWindow{
		AssignTo: &mainWindow,
		Title:    "网络嗅探器 - 协议分析工具",
		Size:     Size{Width: 1100, Height: 700},
		MinSize:  Size{Width: 800, Height: 500},
		Layout:   VBox{Margins: Margins{}, Spacing: 0},
		Children: []Widget{
			// ---- Toolbar ----
			Composite{
				Layout: HBox{
					Margins: Margins{Left: 8, Top: 8, Right: 8, Bottom: 4},
					Spacing: 8,
				},
				Children: []Widget{
					Label{Text: "网络接口:", MinSize: Size{Width: 60}},
					ComboBox{
						AssignTo: &ifaceCombo,
						Model:    ifaceModel,
						MinSize:  Size{Width: 280},
					},
					HSpacer{Size: 8},
					PushButton{
						AssignTo:  &startBtn,
						Text:      "▶  开始捕获",
						MinSize:   Size{Width: 90},
						OnClicked: onStart,
					},
					PushButton{
						AssignTo: &stopBtn,
						Text:     "■  停止",
						MinSize:  Size{Width: 70},
						Enabled:  false,
						OnClicked: onStop,
					},
					PushButton{
						Text:      "✖  清空",
						MinSize:   Size{Width: 70},
						OnClicked: onClear,
					},
				},
			},

			// ---- Packet Table ----
			TableView{
				AssignTo:              &packetTable,
				Model:                 packetModel,
				MultiSelection:        false,
				AlternatingRowBG:      true,
				OnCurrentIndexChanged: onSelectionChanged,
				Columns: []TableViewColumn{
					{Title: "#", Width: 45},
					{Title: "时间", Width: 75},
					{Title: "源IP", Width: 135},
					{Title: "目的IP", Width: 135},
					{Title: "协议", Width: 55},
					{Title: "源端口", Width: 65},
					{Title: "目的端口", Width: 65},
					{Title: "长度", Width: 55},
				},
			},

			// ---- Detail Panel ----
			Label{Text: " 数据包详情:", Font: Font{Bold: true}},
			TextEdit{
				AssignTo: &detailEdit,
				ReadOnly: true,
				MinSize:  Size{Height: 120},
				Text:     "选择一个数据包以查看协议解析详情...",
				Font:     Font{Family: "Consolas", PointSize: 10},
				VScroll:  true,
			},

			// ---- Statistics Bar ----
			Composite{
				Layout: HBox{
					Margins: Margins{Left: 8, Top: 4, Right: 8, Bottom: 6},
					Spacing: 20,
				},
				Children: []Widget{
					Label{AssignTo: &totalLabel, Text: "总计: 0", Font: Font{Bold: true}},
					Label{AssignTo: &tcpLabel, Text: "TCP: 0"},
					Label{AssignTo: &udpLabel, Text: "UDP: 0"},
					Label{AssignTo: &icmpLabel, Text: "ICMP: 0"},
					Label{AssignTo: &arpLabel, Text: "ARP: 0"},
					HSpacer{},
					Label{AssignTo: &rateLabel, Text: "速率: 0.0 包/秒", Font: Font{Bold: true}},
				},
			},
		},
	}).Create()

	if err != nil {
		log.Fatalf("创建窗口失败: %v", err)
	}

	// Set initial interface selection
	if len(ifaceNames) > 0 {
		ifaceCombo.SetCurrentIndex(0)
	}

	// Handle window close
	mainWindow.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		onStop()
	})

	// Start UI refresh
	go uiRefreshLoop()

	mainWindow.Run()
}
