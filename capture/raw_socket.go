// 原始套接字捕获器 —— 利用 Windows 原始套接字 + SIO_RCVALL 实现网络嗅探。
// 不依赖 Npcap，捕获的是 IP 层数据包（无以太网帧头），符合课程设计任务书要求。
package capture

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// SIO_RCVALL 控制码：将套接字设为混杂模式，接收所有流经网卡的 IP 数据包。
const (
	SIO_RCVALL = 0x98000001
	RCVALL_ON  = 1
	RCVALL_OFF = 0
)

// RawInterfaceInfo 原始套接字可用的网络接口信息。
type RawInterfaceInfo struct {
	Name    string // 接口名称（如 "eth0"）
	IP      string // 本机 IPv4 地址
	Display string // 显示用字符串
}

// RawCapturer 基于原始套接字的网络数据包捕获器。
type RawCapturer struct {
	socket syscall.Handle
	iface  string
}

// ListRawInterfaces 枚举本机所有可用 IPv4 接口（排除回环接口）。
func ListRawInterfaces() ([]RawInterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("枚举网络接口失败: %v", err)
	}
	var infos []RawInterfaceInfo
	for _, iface := range ifaces {
		// 排除回环接口
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// 接口必须处于 UP 状态
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}
			display := fmt.Sprintf("%s [%s]", iface.Name, ip4.String())
			infos = append(infos, RawInterfaceInfo{
				Name:    iface.Name,
				IP:      ip4.String(),
				Display: display,
			})
			break // 每个接口只取第一个 IPv4 地址
		}
	}
	if len(infos) == 0 {
		return nil, fmt.Errorf("未找到可用的 IPv4 接口（请以管理员身份运行）")
	}
	return infos, nil
}

// NewRawCapturer 创建原始套接字捕获器，绑定到指定 IP 地址并启用混杂模式。
// 需要管理员权限。
func NewRawCapturer(ifaceIP string) (*RawCapturer, error) {
	// 初始化 Winsock
	var wsaData syscall.WSAData
	err := syscall.WSAStartup(uint32(0x202), &wsaData)
	if err != nil {
		return nil, fmt.Errorf("WSAStartup 失败: %v", err)
	}

	// 创建原始套接字（AF_INET + SOCK_RAW + IPPROTO_IP）
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IP)
	if err != nil {
		syscall.WSACleanup()
		return nil, fmt.Errorf("创建原始套接字失败: %v（请以管理员身份运行）", err)
	}

	// 绑定到指定 IP 地址
	ip := net.ParseIP(ifaceIP)
	if ip == nil {
		syscall.Closesocket(socket)
		syscall.WSACleanup()
		return nil, fmt.Errorf("无效的 IP 地址: %s", ifaceIP)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		syscall.Closesocket(socket)
		syscall.WSACleanup()
		return nil, fmt.Errorf("仅支持 IPv4: %s", ifaceIP)
	}

	addr := syscall.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], ip4)
	err = syscall.Bind(socket, &addr)
	if err != nil {
		syscall.Closesocket(socket)
		syscall.WSACleanup()
		return nil, fmt.Errorf("绑定 IP 地址失败: %v", err)
	}

	// 启用 SIO_RCVALL 混杂模式，接收所有流经网卡的数据包
	var flag uint32 = RCVALL_ON
	var bytesReturned uint32
	err = syscall.WSAIoctl(socket, SIO_RCVALL, (*byte)(unsafe.Pointer(&flag)), 4,
		nil, 0, &bytesReturned, nil, 0)
	if err != nil {
		syscall.Closesocket(socket)
		syscall.WSACleanup()
		return nil, fmt.Errorf("启用混杂模式失败: %v", err)
	}

	return &RawCapturer{socket: socket, iface: ifaceIP}, nil
}

// CapturePacket 接收一个原始 IP 数据包，返回完整的 IP 层数据（含 IP 头）。
// 注意：原始套接字捕获的包不含以太网帧头，直接从 IP 头开始。
func (r *RawCapturer) CapturePacket() ([]byte, error) {
	buf := make([]byte, 65536)
	n, _, err := syscall.Recvfrom(r.socket, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("接收数据包失败: %v", err)
	}
	// 返回实际接收到的 IP 数据包（从 IP 头开始）
	packet := make([]byte, n)
	copy(packet, buf[:n])
	return packet, nil
}

// Close 关闭原始套接字并清理 Winsock 资源。
func (r *RawCapturer) Close() {
	if r.socket != syscall.InvalidHandle {
		// 先退出混杂模式
		var flag uint32 = RCVALL_OFF
		var bytesReturned uint32
		syscall.WSAIoctl(r.socket, SIO_RCVALL, (*byte)(unsafe.Pointer(&flag)), 4,
			nil, 0, &bytesReturned, nil, 0)

		syscall.Closesocket(r.socket)
		r.socket = syscall.InvalidHandle
	}
	syscall.WSACleanup()
}
