// 基于 pcap/Npcap 的网络数据包捕获器。
// 用于 GUI 和 Web 版本（原始套接字在 walk GUI 和 HTTP 服务器场景下不够稳定）。
// 需要安装 Npcap 驱动并以管理员权限运行。
package capture

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// InterfaceInfo 网络接口信息。
type InterfaceInfo struct {
	Name        string // pcap 设备名（如 \Device\NPF_{UUID}）
	Description string // 接口描述
	Display     string // 显示名（描述+IP）
}

// Capturer 基于 pcap/Npcap 的数据包捕获器。
type Capturer struct {
	handle *pcap.Handle
	source *gopacket.PacketSource
	iface  string
}

// ListInterfaces 返回接口显示名称列表（简化版）。
func ListInterfaces() ([]string, error) {
	infos, err := ListInterfacesDetailed()
	if err != nil {
		return nil, err
	}
	var display []string
	for _, info := range infos {
		display = append(display, info.Display)
	}
	return display, nil
}

// ListInterfacesDetailed 枚举所有网络接口，返回包含 IP 地址的详细信息列表。
func ListInterfacesDetailed() ([]InterfaceInfo, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("查找网络设备失败: %v", err)
	}
	var infos []InterfaceInfo
	for _, device := range devices {
		desc := device.Description
		if desc == "" {
			desc = device.Name
		}
		display := desc
		for _, addr := range device.Addresses {
			if addr.IP != nil {
				display = fmt.Sprintf("%s [%s]", display, addr.IP.String())
				break
			}
		}
		infos = append(infos, InterfaceInfo{
			Name:        device.Name,
			Description: device.Description,
			Display:     display,
		})
	}
	if len(infos) == 0 {
		return nil, fmt.Errorf("未找到可用的网络接口")
	}
	return infos, nil
}

func NewCapturer(ifaceName string) (*Capturer, error) {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, 500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("打开网络接口失败: %v (需要管理员权限)", err)
	}
	handle.SetBPFFilter("")
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.DecodeOptions = gopacket.Lazy
	return &Capturer{handle: handle, source: source, iface: ifaceName}, nil
}

func (c *Capturer) CapturePacket() ([]byte, error) {
	packet, err := c.source.NextPacket()
	if err != nil {
		return nil, fmt.Errorf("捕获数据包失败: %v", err)
	}
	return packet.Data(), nil
}

func (c *Capturer) Close() {
	if c.handle != nil {
		c.handle.Close()
	}
}
