package Amelyzer

//
//import (
//	"fmt"
//	"net"
//	"strconv"
//)
//
//func main() {
//	// 端口号和协议类型
//	port := 8080
//	protocol := "tcp"
//
//	// 解析地址
//	addr, err := net.ResolveTCPAddr(protocol, "localhost:"+strconv.Itoa(port))
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//
//	// 获取监听器
//	lc := net.ListenConfig{}
//	listener, err := lc.Listen(nil, addr)
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//	defer listener.Close()
//
//	// 获取连接的本地地址
//	laddr := listener.Addr().(*net.TCPAddr)
//
//	// 查找正在使用该端口的进程
//	p, err := net.LookupPid("tcp", laddr.IP.String(), strconv.Itoa(laddr.Port))
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//	fmt.Println("进程ID:", p)
//}
