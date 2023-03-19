package Amelyzer

import (
	"fmt"
	"github.com/cakturk/go-netstat/netstat"
)

func FindUDPPort(add1 string, add2 string) (e netstat.SockTabEntry, err error) {
	socks, err := netstat.UDPSocks(netstat.NoopFilter)
	if err != nil {
		return netstat.SockTabEntry{}, err
	}
	for _, e := range socks {
		la := fmt.Sprint(e.LocalAddr)
		if la == add1 || la == add2 {
			return e, nil
		}
	}
	return netstat.SockTabEntry{}, nil
}

func FindTCPPort(add1 string, add2 string) (e netstat.SockTabEntry, err error) {
	socks, err := netstat.TCPSocks(netstat.NoopFilter)
	if err != nil {
		return netstat.SockTabEntry{}, err
	}
	for _, e := range socks {
		la := fmt.Sprint(e.LocalAddr)
		lr := fmt.Sprint(e.RemoteAddr)
		if la == add1 || la == add2 || lr == add1 || lr == add2 {
			return e, nil
		}
	}
	return netstat.SockTabEntry{}, nil
}

func ProcessConnection(process string) (conns []netstat.SockTabEntry) {
	conns = make([]netstat.SockTabEntry, 0)
	socks, _ := netstat.UDPSocks(netstat.NoopFilter)
	for _, e := range socks {
		proc := fmt.Sprint(e.Process)
		if proc == process {
			conns = append(conns, e)
		}
	}
	socks, _ = netstat.TCPSocks(netstat.NoopFilter)
	for _, e := range socks {
		proc := fmt.Sprint(e.Process)
		if proc == process {
			conns = append(conns, e)
		}
	}
	return conns

}
