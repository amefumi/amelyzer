package Amelyzer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"sync"
	"time"
)

type NetworkDevice struct {
	Name        string
	Description string
}

type SnifferConfigure struct {
	DeviceName     string
	SnapshotLength int32
	NicMix         bool
	Timeout        time.Duration
	BPFFilter      string
}

type PacketItem struct {
	Number    int
	Time      string
	Length    int
	Source    string
	Target    string
	Protocol  string
	InfoShort string
}

type PacketDetail struct {
	Number int
	Time   string

	Layer2 struct {
		// Ethernet and LoopBack
		Protocol string
		Src      string
		Dst      string
		Type     string
		Info     string
	}
	Layer3 struct {
		// IP and ARP
		Protocol string
		Src      string
		Dst      string
		Version  string
		Info     string
	}
	Layer4 struct {
		// TCP UPD ICMP
		Protocol string
		Info     string
	}
	Layer5 struct {
		Protocol string
	}
	dump gopacket.Packet
}

var PacketNumber = 0

var PacketPool []PacketDetail
var mu sync.RWMutex
var stop = make(chan bool)

func ListDeviceName() (networkDevices []NetworkDevice) {
	// 输出网络设备的名称（用于抓包）和描述（用于展示给用户）
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, device := range devices {
		networkDevices = append(networkDevices, NetworkDevice{Name: device.Name, Description: device.Description})
	}
	return networkDevices
}

var err error
var handle *pcap.Handle

func PollPacket(c SnifferConfigure, itemsOut chan PacketItem) {
	handle, err = pcap.OpenLive(c.DeviceName, c.SnapshotLength, c.NicMix, c.Timeout)
	if err != nil {
		log.Fatal(err)
	}
	if c.BPFFilter != "" {
		err = handle.SetBPFFilter(c.BPFFilter)
		if err != nil {
			log.Fatal(err)
		}
	}
	defer handle.Close()
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			fmt.Println(packet)
			items, detail := parsePacket(packet)
			itemsOut <- items
			mu.Lock()
			PacketPool = append(PacketPool, detail)
			mu.Unlock()
		}
	}
}

func StopSniffer() {
	stop <- true
}

// GoPacket Layer包中预定义了对网络协议栈中多数协议的解析，考虑到任务的需求，这里不使用GoPacket Layer中定义的协议解析，而是调用其自定义层接口

func parsePacket(packet gopacket.Packet) (item PacketItem, detail PacketDetail) {
	// Layer 2: Ethernet or LoopBack
	item.Number = PacketNumber
	item.Time = time.Now().Format("15:04:05.000")
	item.Length = packet.Metadata().Length
	detail.dump = packet
	detail.Number = PacketNumber
	detail.Time = item.Time

	// Layer 2 Process
	loopbackLayer := packet.Layer(layers.LayerTypeLoopback)
	if loopbackLayer != nil {
		loopbackPacket, _ := loopbackLayer.(*layers.Loopback)
		detail.Layer2.Protocol = "loopback"
		detail.Layer2.Info = fmt.Sprintf("Loopback Family: %s", loopbackPacket.Family)
		item.Protocol = "LoopBack"
		item.InfoShort = detail.Layer2.Info
	} else {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer == nil {
			detail.Layer2.Protocol = "Unknown"
			detail.Layer2.Info = "Unknown Layer2 Protocol"
			item.Protocol = "Unknown Protocol"
			item.InfoShort = detail.Layer2.Info
		} else {
			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
			detail.Layer2.Src = fmt.Sprintf("%s", ethernetPacket.SrcMAC)
			detail.Layer2.Dst = fmt.Sprintf("%s", ethernetPacket.DstMAC)
			detail.Layer2.Type = fmt.Sprintf("%s", ethernetPacket.EthernetType)
			detail.Layer2.Info = "Ethernet, Src: " + detail.Layer2.Src + ", Dst: " + detail.Layer2.Dst
			detail.Layer2.Protocol = detail.Layer2.Type
			item.Source = detail.Layer2.Src
			item.Target = detail.Layer2.Dst
			item.Protocol = detail.Layer2.Type
			item.InfoShort = detail.Layer2.Info

			// Layer 3 Process
			v4Layer := packet.Layer(layers.LayerTypeIPv4)
			v6Layer := packet.Layer(layers.LayerTypeIPv6)
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if v4Layer != nil {

			} else if v6Layer != nil {

			} else if arpLayer != nil {

			} else {

			}

		}
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)
		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
	}
	// Let's see if the packet is TCP
	// 判断数据包是否为TCP数据包，可解析源端口、目的端口、seq序列号、tcp标志位等
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)
		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		fmt.Println()
	}
	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}
	///.......................................................
	// Check for errors
	// 判断layer是否存在错误
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
	return item, detail
}

func GetDetailPacket(packetNumber int) (detail PacketDetail) {
	mu.RLock()
	defer mu.RUnlock()
	return PacketPool[packetNumber-1]
}
