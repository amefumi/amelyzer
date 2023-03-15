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
		SrcPort  uint16
		DstPort  uint16
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

func StartSniffer(c SnifferConfigure, itemsOut chan PacketItem, detailsOut chan PacketDetail) {
	PacketNumber = 0 // PollPacket函数的重新运行表明重新开始嗅探过程，所以先对PacketNumber归零
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
			items, detail := parsePacket(packet)
			itemsOut <- items
			detailsOut <- detail
			// 通过channel将解析后的数据结构传出
		}
	}
}

func StopSniffer() {
	stop <- true
}

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
			detail.Layer2.Info = fmt.Sprintf("Ethernet [%s], Src: %s, Dst: %s", ethernetPacket.EthernetType,
				ethernetPacket.SrcMAC, ethernetPacket.DstMAC)
			detail.Layer2.Protocol = detail.Layer2.Type
			item.Source = detail.Layer2.Src
			item.Target = detail.Layer2.Dst
			item.Protocol = detail.Layer2.Type
			item.InfoShort = "[Ethernet] Src: " + detail.Layer2.Src + ", Dst: " + detail.Layer2.Dst

			// Layer 3 Process
			v4Layer := packet.Layer(layers.LayerTypeIPv4)
			v6Layer := packet.Layer(layers.LayerTypeIPv6)
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if v4Layer != nil {
				v4Packet := v4Layer.(*layers.IPv4)
				detail.Layer3.Protocol = "IPv4"
				detail.Layer3.Src = fmt.Sprintf("%s", v4Packet.SrcIP)
				detail.Layer3.Dst = fmt.Sprintf("%s", v4Packet.DstIP)
				detail.Layer3.Version = fmt.Sprintf("%d", v4Packet.Version)
				detail.Layer3.Info = fmt.Sprintf("Internet Protocol Version 4, Src: %s, Dst: %s\n\rVersion: 4\n\r"+
					"Header Length: %d bytes\n\rType of Services: 0x%x\n\rTotol Length: %d\n\rIdentification: %d\n\r"+
					"Flags: 0x%x\n\rFragment Offset: %d\n\rTime To Live: %d\n\rHeader Checksum:0x%x", v4Packet.SrcIP,
					v4Packet.DstIP, v4Packet.IHL, v4Packet.TOS, v4Packet.Length, v4Packet.Id, v4Packet.Flags,
					v4Packet.FragOffset, v4Packet.TTL, v4Packet.Checksum)
				item.Source = detail.Layer3.Src
				item.Target = detail.Layer3.Dst
				item.Protocol = detail.Layer3.Protocol
				item.InfoShort = fmt.Sprintf("Internet Protocol Version 4, Src: %s, Dst: %s", v4Packet.SrcIP,
					v4Packet.DstIP)
			} else if v6Layer != nil {
				v6Packet := v6Layer.(*layers.IPv6)
				detail.Layer3.Protocol = "IPv6"
				detail.Layer3.Src = fmt.Sprintf("%s", v6Packet.SrcIP)
				detail.Layer3.Dst = fmt.Sprintf("%s", v6Packet.DstIP)
				detail.Layer3.Version = fmt.Sprintf("%d", v6Packet.Version)
				detail.Layer3.Info = fmt.Sprintf("Inter Protocol Version 6, Src: %s, Dst: %s\n\rVersion: 6\n\r"+
					"Traffic Class: 0x%x\n\rFlow Lable: 0x%x\n\rPayload Length: %d\n\rNextHeader: %s\n\r Hop Limit: %d",
					v6Packet.SrcIP, v6Packet.DstIP, v6Packet.TrafficClass, v6Packet.FlowLabel, v6Packet.Length,
					v6Packet.NextHeader, v6Packet.HopLimit)
				item.Source = detail.Layer3.Src
				item.Target = detail.Layer3.Dst
				item.Protocol = detail.Layer3.Protocol
				item.InfoShort = fmt.Sprintf("[IPv6] Src: %s Dst: %s", v6Packet.SrcIP, v6Packet.DstIP)
			} else if arpLayer != nil {
				arpPacket := arpLayer.(*layers.ARP)
				detail.Layer3.Protocol = fmt.Sprintf("%s", arpPacket.Protocol)
				detail.Layer3.Src = fmt.Sprintf("%s", arpPacket.SourceProtAddress)
				detail.Layer3.Dst = fmt.Sprintf("%s", arpPacket.DstProtAddress)
				detail.Layer3.Version = fmt.Sprintf("%d", arpPacket.Protocol)
				detail.Layer3.Info = fmt.Sprintf("Address Resolution Protocol\n\rProtocol type: %s\n\rOpcode:%d\n\r"+
					"Sender MAC address: %s\n\rSender IP address: %s\n\rTarget MAC address: %s\n\rTarget IP address: %s",
					arpPacket.Protocol, arpPacket.Operation, arpPacket.SourceHwAddress, arpPacket.SourceProtAddress,
					arpPacket.DstHwAddress, arpPacket.DstProtAddress)
				item.Source = detail.Layer3.Src
				item.Target = detail.Layer3.Dst
				item.Protocol = detail.Layer3.Protocol
				item.InfoShort = fmt.Sprintf("Who has %s? Tell %s", arpPacket.SourceProtAddress, arpPacket.DstProtAddress)

			} else {
				// Unknown L3 Protocol
			}
			if v4Layer != nil || v6Layer != nil {
				// Layer 4 Based on IP
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				//icmpv4Layer := packet.Layer(layers.LayerTypeICMPv4)
				icmpv6layer := packet.Layer(layers.LayerTypeICMPv6)
				if tcpLayer != nil {
					tcpPacket := tcpLayer.(*layers.TCP)
					detail.Layer4.Protocol = "TCP"
					var tcpFlagString = ""
					if tcpPacket.ACK {
						tcpFlagString += "ACK,"
					}
					if tcpPacket.SYN {
						tcpFlagString += "SYN,"
					}
					if tcpPacket.FIN {
						tcpFlagString += "FIN,"
					}
					if tcpPacket.RST {
						tcpFlagString += "RST,"
					}
					item.Protocol = "TCP"
					item.InfoShort = fmt.Sprintf("%d -> %d Seq=%d [%s] Ack=%d Win=%d", tcpPacket.SrcPort,
						tcpPacket.DstPort, tcpPacket.Seq, tcpFlagString, tcpPacket.Ack, tcpPacket.Window)
					detail.Layer4.Info = fmt.Sprintf("Transmission Control Protocol, %s\n\r Checksum: 0x%x",
						item.InfoShort, tcpPacket.Checksum)
					detail.Layer4.SrcPort = uint16(tcpPacket.SrcPort)
					detail.Layer4.DstPort = uint16(tcpPacket.DstPort)
				} else if udpLayer != nil {
					udpPacket := udpLayer.(*layers.UDP)
					detail.Layer4.Protocol = "UDP"
					item.Protocol = "UDP"
					item.InfoShort = fmt.Sprintf("%d -> %d, Len=%d", udpPacket.SrcPort, udpPacket.DstPort, udpPacket.Length)
					detail.Layer4.Info = fmt.Sprintf("User Datagram Protocol, %s\n\rLength: %d\n\rChecksum: 0x%x",
						item.InfoShort, udpPacket.Length, udpPacket.Checksum)
					detail.Layer4.SrcPort = uint16(udpPacket.SrcPort)
					detail.Layer4.DstPort = uint16(udpPacket.DstPort)
					//} else if icmpv4Layer != nil {
					//	icmpv4Packet := icmpv4Layer.(*layers.ICMPv4)
					//	item.Protocol = "ICMPv4"
					//	item.InfoShort =
				} else if icmpv6layer != nil {

				} else {
					// Other Layer 4 Protocol: return directly.
					return item, detail
				}
				// Layer 5 Based on TCP/UDP
				//DNSPacket := packet.Layer(layers.LayerTypeDNS)
				//TLSPacket := packet.Layer(layers.LayerTypeTLS)

			}

		}
	}

	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
	return item, detail
}
