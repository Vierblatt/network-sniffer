// 网络嗅探器 Web 版 —— HTTP 服务器 + 浏览器前端。
// 提供 RESTful API（接口列表、开始/停止/清空捕获、获取数据包/统计）和 SPA 前端页面。
// 基于 pcap/Npcap 捕获，需管理员权限运行。构建：go build -tags=web -o sniffer_web.exe .
//go:build web

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"sniffer/analyzer"
	"sniffer/capture"
)

var (
	isCapturing    bool
	captureMu      sync.Mutex
	packetAnalyzer *analyzer.Analyzer
	capturer       *capture.Capturer
	packets        []PacketData
	packetMu       sync.RWMutex
	stats          = &CaptureStats{}
	startTime      time.Time
	endTime        time.Time // 停止捕获时间，停止后耗时锁定

	// 接口显示名(描述) -> 设备名(如 \Device\NPF_{UUID}) 的映射
	ifaceNameMap map[string]string
)

type PacketData struct {
	Seq      int    `json:"seq"`
	Time     string `json:"time"`
	SrcIP    string `json:"srcIP"`
	DstIP    string `json:"dstIP"`
	Protocol string `json:"protocol"`
	SrcPort  string `json:"srcPort"`
	DstPort  string `json:"dstPort"`
	Length   string `json:"length"`
	SrcMAC   string `json:"srcMAC"`
	DstMAC   string `json:"dstMAC"`
	Detail   string `json:"detail"`
}

type CaptureStats struct {
	TotalPackets int    `json:"totalPackets"`
	TCPCount     int    `json:"tcpCount"`
	UDPCount     int    `json:"udpCount"`
	ICMPCount    int    `json:"icmpCount"`
	ARPCount     int    `json:"arpCount"`
	OtherCount   int    `json:"otherCount"`
	Elapsed      string `json:"elapsed"`
	Rate         string `json:"rate"`
	mu           sync.Mutex
}

func (s *CaptureStats) Add(protocol string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalPackets++
	switch protocol {
	case "TCP":
		s.TCPCount++
	case "UDP":
		s.UDPCount++
	case "ICMP":
		s.ICMPCount++
	case "ARP":
		s.ARPCount++
	default:
		s.OtherCount++
	}
}

func (s *CaptureStats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalPackets = 0
	s.TCPCount = 0
	s.UDPCount = 0
	s.ICMPCount = 0
	s.ARPCount = 0
	s.OtherCount = 0
}

func (s *CaptureStats) Get() CaptureStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	var elapsed time.Duration
	captureMu.Lock()
	if !isCapturing && !endTime.IsZero() {
		elapsed = endTime.Sub(startTime)
	} else {
		elapsed = time.Since(startTime)
	}
	captureMu.Unlock()
	rate := 0.0
	if elapsed.Seconds() > 0 && s.TotalPackets > 0 {
		rate = float64(s.TotalPackets) / elapsed.Seconds()
	}
	return CaptureStats{
		TotalPackets: s.TotalPackets,
		TCPCount:     s.TCPCount,
		UDPCount:     s.UDPCount,
		ICMPCount:    s.ICMPCount,
		ARPCount:     s.ARPCount,
		OtherCount:   s.OtherCount,
		Elapsed:      fmt.Sprintf("%ds", int(elapsed.Seconds())),
		Rate:         fmt.Sprintf("%.1f", rate),
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	// 刷新接口映射
	refreshInterfaceMap()

	tmpl, err := template.ParseFiles("web/templates/index.html")
	if err != nil {
		http.Error(w, "模板加载失败: "+err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, nil)
}

func refreshInterfaceMap() {
	infos, err := capture.ListInterfacesDetailed()
	if err != nil {
		return
	}
	ifaceNameMap = make(map[string]string)
	for _, info := range infos {
		ifaceNameMap[info.Display] = info.Name
	}
}

func handleInterfaces(w http.ResponseWriter, r *http.Request) {
	refreshInterfaceMap()
	// 返回显示名列表（前端期望 []string）
	var displayNames []string
	for display := range ifaceNameMap {
		displayNames = append(displayNames, display)
	}
	if len(displayNames) == 0 {
		displayNames = []string{"(无可用接口，请以管理员身份运行)"}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(displayNames)
}

func handleStart(w http.ResponseWriter, r *http.Request) {
	displayName := r.URL.Query().Get("iface")
	if displayName == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]string{"error": "未指定接口"})
		return
	}

	deviceName := ifaceNameMap[displayName]
	if deviceName == "" {
		deviceName = displayName
	}

	captureMu.Lock()
	if isCapturing {
		captureMu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]string{"error": "已在捕获中"})
		return
	}
	captureMu.Unlock()

	log.Printf("开始捕获: 显示名=%s 设备名=%s", displayName, deviceName)

	c, err := capture.NewCapturer(deviceName)
	if err != nil {
		log.Printf("创建捕获器失败: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	captureMu.Lock()
	capturer = c
	packetMu.Lock()
	packets = nil
	packetMu.Unlock()
	stats.Reset()
	startTime = time.Now()
	endTime = time.Time{}
	isCapturing = true
	packetAnalyzer = analyzer.NewAnalyzer()
	captureMu.Unlock()

	go captureLoop()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func captureLoop() {
	defer func() {
		captureMu.Lock()
		if capturer != nil {
			capturer.Close()
			capturer = nil
		}
		isCapturing = false
		endTime = time.Now()
		captureMu.Unlock()
	}()

	seq := 0
	for {
		captureMu.Lock()
		if !isCapturing {
			captureMu.Unlock()
			return
		}
		c := capturer
		captureMu.Unlock()

		data, err := c.CapturePacket()
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		result := packetAnalyzer.Analyze(data)
		stats.Add(result.Protocol)
		seq++

		pd := PacketData{
			Seq:      seq,
			Time:     time.Now().Format("15:04:05.000"),
			SrcIP:    result.SrcIP,
			DstIP:    result.DstIP,
			Protocol: result.Protocol,
			SrcPort:  result.SrcPort,
			DstPort:  result.DstPort,
			Length:   fmt.Sprintf("%d", result.Length),
			SrcMAC:   result.SrcMAC,
			DstMAC:   result.DstMAC,
			Detail:   result.Detail,
		}
		packetMu.Lock()
		packets = append(packets, pd)
		if len(packets) > 10000 {
			packets = packets[len(packets)-5000:]
		}
		packetMu.Unlock()
	}
}

func handleStop(w http.ResponseWriter, r *http.Request) {
	captureMu.Lock()
	if isCapturing {
		isCapturing = false
	}
	captureMu.Unlock()
	// capturer closed by captureLoop defer

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleClear(w http.ResponseWriter, r *http.Request) {
	// Stop active capture first
	captureMu.Lock()
	if isCapturing {
		isCapturing = false
	}
	captureMu.Unlock()
	// Wait for captureLoop to exit (capturer.Close called in defer)
	time.Sleep(600 * time.Millisecond)

	packetMu.Lock()
	packets = nil
	packetMu.Unlock()
	stats.Reset()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handlePackets(w http.ResponseWriter, r *http.Request) {
	packetMu.RLock()
	defer packetMu.RUnlock()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(packets)
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(stats.Get())
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "windows":
		err = exec.Command("cmd", "/c", "start", url).Run()
	case "darwin":
		err = exec.Command("open", url).Run()
	default:
		err = exec.Command("xdg-open", url).Run()
	}
	if err != nil {
		log.Printf("打开浏览器失败: %v", err)
	}
}

func main() {
	logFile, err := os.Create("sniffer_server.log")
	if err == nil {
		log.SetOutput(logFile)
		defer logFile.Close()
	}

	// 预加载接口映射
	refreshInterfaceMap()

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/interfaces", handleInterfaces)
	http.HandleFunc("/api/start", handleStart)
	http.HandleFunc("/api/stop", handleStop)
	http.HandleFunc("/api/clear", handleClear)
	http.HandleFunc("/api/packets", handlePackets)
	http.HandleFunc("/api/stats", handleStats)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))

	fmt.Println("========================================")
	fmt.Println("    网络嗅探器 - Web 服务器版本")
	fmt.Println("========================================")
	fmt.Println("服务器启动: http://localhost:8080")
	fmt.Println("自动打开浏览器中...")
	fmt.Println("按 Ctrl+C 停止服务器")
	fmt.Println("========================================")

	go func() {
		time.Sleep(500 * time.Millisecond)
		openBrowser("http://localhost:8080")
	}()

	log.Fatal(http.ListenAndServe(":8080", nil))
}
