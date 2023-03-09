package AmelyzerSniffer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

type PacketItem struct {
	number   int32
	time     float64
	source   string
	target   string
	protocol string
	length   int32
	info     string
}

func ListDevice() {
	// 得到所有的(网络)设备
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ")
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
}

var err error
var handle *pcap.Handle

func PollPacket(device string, snapshotLen int32, nicMix bool, timeout time.Duration) {

	handle, err = pcap.OpenLive(device, snapshotLen, nicMix, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	app, _, _ := handle.ReadPacketData()
	//packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//for packet := range packetSource.Packets() {
	//	parsePacket(packet)
	//	// fmt.Println(packet) // fmt.Println实际上已经对packet提供了解析，因此不使用。
	//}
}

func StopSniffer() {
	handle.Close()
}

// GoPacket Layer包中预定义了对网络协议栈中多数协议的解析，考虑到任务的需求，这里不使用GoPacket Layer中定义的协议解析，而是调用其自定义层接口

func parsePacket(packet gopacket.Packet) {

}
