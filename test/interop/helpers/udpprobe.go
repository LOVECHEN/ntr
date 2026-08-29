//go:build ignore

// UDP-over-SOCKS5 探针:对 socks5 代理做 UDP ASSOCIATE,向目标发一包并读回显。
// 用法:udpprobe <socks5 host:port> <target host:port> <message>
// 退出 0 = 收到与发送一致的回显;否则非 0。
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Println("usage: udpprobe <socks> <target> <msg>")
		os.Exit(2)
	}
	socksAddr, targetAddr, msg := os.Args[1], os.Args[2], []byte(os.Args[3])

	// 目标解析为 IP(mieru UDP 回读不接受 FQDN;链路统一走 IP)。
	th, tp, _ := net.SplitHostPort(targetAddr)
	tips, err := net.LookupIP(th)
	if err != nil || len(tips) == 0 {
		fmt.Println("resolve target:", err)
		os.Exit(1)
	}
	tip := tips[0].To4()
	tport, _ := strconv.Atoi(tp)

	// 1) TCP 连 socks5,握手 + UDP ASSOCIATE。
	tc, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		fmt.Println("dial socks:", err)
		os.Exit(1)
	}
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := tc.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		fmt.Println("greet:", err)
		os.Exit(1)
	}
	rep := make([]byte, 2)
	if _, err := tc.Read(rep); err != nil || rep[1] != 0x00 {
		fmt.Println("method:", err, rep)
		os.Exit(1)
	}
	// UDP ASSOCIATE(客户端 bind 地址填 0）。
	if _, err := tc.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		fmt.Println("assoc:", err)
		os.Exit(1)
	}
	head := make([]byte, 4)
	if _, err := tc.Read(head); err != nil || head[1] != 0x00 {
		fmt.Println("assoc reply:", err, head)
		os.Exit(1)
	}
	var bndIP net.IP
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		tc.Read(b)
		bndIP = net.IP(b)
	case 0x04:
		b := make([]byte, 16)
		tc.Read(b)
		bndIP = net.IP(b)
	default:
		fmt.Println("unexpected bnd atyp", head[3])
		os.Exit(1)
	}
	pb := make([]byte, 2)
	tc.Read(pb)
	bndPort := binary.BigEndian.Uint16(pb)
	// BND.ADDR 可能是 0.0.0.0 → 用 socks 主机 IP 代替。
	if bndIP.IsUnspecified() {
		sh, _, _ := net.SplitHostPort(socksAddr)
		if ips, e := net.LookupIP(sh); e == nil && len(ips) > 0 {
			bndIP = ips[0]
		}
	}

	// 2) UDP 发到 relay,封 socks5 UDP 头(RSV2 FRAG ATYP IPv4 PORT)。
	uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: bndIP, Port: int(bndPort)})
	if err != nil {
		fmt.Println("dial udp relay:", err)
		os.Exit(1)
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(8 * time.Second))
	var pkt bytes.Buffer
	pkt.Write([]byte{0, 0, 0, 0x01})
	pkt.Write(tip)
	pp := make([]byte, 2)
	binary.BigEndian.PutUint16(pp, uint16(tport))
	pkt.Write(pp)
	pkt.Write(msg)
	if _, err := uc.Write(pkt.Bytes()); err != nil {
		fmt.Println("udp write:", err)
		os.Exit(1)
	}

	// 3) 读回显,剥头比对。
	rbuf := make([]byte, 64*1024)
	n, err := uc.Read(rbuf)
	if err != nil {
		fmt.Println("udp read:", err)
		os.Exit(1)
	}
	if n < 10 {
		fmt.Println("short reply", n)
		os.Exit(1)
	}
	// 头长:RSV2+FRAG1+ATYP1+(4 或 16)+PORT2
	hl := 3 + 1 + 2
	if rbuf[3] == 0x01 {
		hl += 4
	} else {
		hl += 16
	}
	payload := rbuf[hl:n]
	if !bytes.Equal(payload, msg) {
		fmt.Printf("MISMATCH got=%q want=%q\n", payload, msg)
		os.Exit(1)
	}
	fmt.Println("UDP-ECHO-OK")
}
