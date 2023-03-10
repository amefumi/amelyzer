package main

import (
	Amelyzer "Amelyzer/src/network"
	"fmt"
	"time"
)

var done chan bool

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
	stopChan := make(chan bool)
	itemChan := make(chan Amelyzer.PacketItem)
	go Amelyzer.PollPacket(configure, stopChan, itemChan)
	fmt.Println("Go to PollPacket Routine Successfully.")
	time.Sleep(5 * time.Second)
	Amelyzer.StopSniffer(stopChan)
	////	done <- true
	////}()
	////select {
	////case <-done:
	////	fmt.Println("Exit！")
	////}
}
