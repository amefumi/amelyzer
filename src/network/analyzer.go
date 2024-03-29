package Amelyzer

import (
	"fmt"
	"github.com/cakturk/go-netstat/netstat"
)

type Connection struct {
	Protocol string
	Local    string
	Remote   string
	State    string
	Process  string
}

type TCPFlow struct {
	Addr1 string
	Port1 uint16
	Addr2 string
	Port2 uint16
}

func IsSameTCPConnection(f *TCPFlow, p *PacketItem) (r bool) {
	if p.Protocol != "TCP" && p.Protocol != "HTTP" && p.Protocol != "TLS" {
		return false
	}
	if f.Addr1 == p.Source && f.Port1 == p.SourcePort && f.Addr2 == p.Target && f.Port2 == p.TargetPort {
		return true
	}
	if f.Addr2 == p.Source && f.Port2 == p.SourcePort && f.Addr1 == p.Target && f.Port1 == p.TargetPort {
		return true
	}
	return false
}

func FindUDPPort(add1 string, add2 string) (e netstat.SockTabEntry) {
	socks, _ := netstat.UDPSocks(netstat.NoopFilter)
	for _, e := range socks {
		la := fmt.Sprint(e.LocalAddr)
		lb := fmt.Sprint(e.RemoteAddr)
		fmt.Println("udp", la, lb)

		if la == add1 || la == add2 || lb == add1 || lb == add2 {
			return e
		}
	}
	return netstat.SockTabEntry{}
}

func FindTCPPort(add1 string, add2 string) (e netstat.SockTabEntry) {
	socks, _ := netstat.TCPSocks(netstat.NoopFilter)
	for _, e := range socks {
		la := fmt.Sprint(e.LocalAddr)
		lr := fmt.Sprint(e.RemoteAddr)
		fmt.Println("tcp", la, lr)
		if la == add1 || la == add2 || lr == add1 || lr == add2 {
			return e
		}
	}
	return netstat.SockTabEntry{}
}

func ProcessConnection(process string) (conns []Connection) {
	conns = make([]Connection, 0)
	socks, _ := netstat.UDPSocks(netstat.NoopFilter)
	for _, e := range socks {
		proc := fmt.Sprint(e.Process)
		if proc == process {
			conns = append(conns, Connection{
				Protocol: "UDP",
				Local:    e.LocalAddr.String(),
				Remote:   e.RemoteAddr.String(),
				State:    e.State.String(),
				Process:  e.Process.String(),
			})
		}
	}
	socks, _ = netstat.TCPSocks(netstat.NoopFilter)
	for _, e := range socks {
		proc := fmt.Sprint(e.Process)
		if proc == process {
			conns = append(conns, Connection{
				Protocol: "TCP",
				Local:    e.LocalAddr.String(),
				Remote:   e.RemoteAddr.String(),
				State:    e.State.String(),
				Process:  e.Process.String(),
			})
		}
	}
	return conns

}
