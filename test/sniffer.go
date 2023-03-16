package main

import (
	Amelyzer "Amelyzer/src/network"
	"fmt"
	"time"
)

func main() {
	fmt.Println(time.Now())
	devices := Amelyzer.ListDeviceName()
	configure := Amelyzer.SnifferConfigure{
		DeviceName:     devices[5].Name,
		SnapshotLength: 1500,
		NicMix:         false,
		Timeout:        -1,
		BPFFilter:      "udp",
	}
	itemChan := make(chan Amelyzer.PacketItem)
	detailChan := make(chan Amelyzer.PacketDetail)
	go Amelyzer.StartSniffer(configure, itemChan, detailChan)
	for {
		var item Amelyzer.PacketItem
		var detail Amelyzer.PacketDetail
		select {
		case item = <-itemChan:
			fmt.Print(item.InfoShort)
		case detail = <-detailChan:
			fmt.Println(detail.Layer4.Info)
			//	fmt.Print(detail)
		}
	}
}
