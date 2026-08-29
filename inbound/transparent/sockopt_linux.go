//go:build linux

package transparent

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/LOVECHEN/ntr/addr"
)

// SO_ORIGINAL_DST(v4 与 v6 同值 80)—— iptables REDIRECT 把连接的原始目的地存在此 getsockopt。
const soOriginalDst = 80

// listenTCP:redirect 用普通 listener;tproxy 用带 IP_TRANSPARENT 的 listener。
func (h *Inbound) listenTCP(ctx context.Context, listen string) (net.Listener, error) {
	if h.mode != "tproxy" {
		return net.Listen("tcp", listen)
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var cerr error
		if err := c.Control(func(fd uintptr) {
			// v4/v6 都尝试开透明;至少一个成功即可(取决于监听族)。
			e4 := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			e6 := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
			if e4 != nil && e6 != nil {
				cerr = fmt.Errorf("IP_TRANSPARENT:%v / IPV6:%v", e4, e6)
			}
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return cerr
	}}
	return lc.Listen(ctx, "tcp", listen)
}

// origDstTCP:tproxy 下原始目的 = 连接本地地址;redirect 下用 SO_ORIGINAL_DST getsockopt。
func (h *Inbound) origDstTCP(c net.Conn) (netip.AddrPort, error) {
	if h.mode == "tproxy" {
		if ap, ok := toAddrPort(c.LocalAddr()); ok {
			return ap, nil
		}
		return netip.AddrPort{}, fmt.Errorf("transparent: tproxy 取本地地址失败")
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("transparent: 连接不支持 SyscallConn")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var ap netip.AddrPort
	var perr error
	if err := raw.Control(func(fd uintptr) {
		ap, perr = getOrigDst(int(fd))
	}); err != nil {
		return netip.AddrPort{}, err
	}
	return ap, perr
}

// getOrigDst 读 SO_ORIGINAL_DST:先按 v4 试,失败再按 v6。
func getOrigDst(fd int) (netip.AddrPort, error) {
	var buf [unix.SizeofSockaddrInet6]byte // 够放 v4/v6
	sz := uint32(unix.SizeofSockaddrInet4)
	_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(unix.SOL_IP),
		uintptr(soOriginalDst), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&sz)), 0)
	if e == 0 {
		return parseSockaddr(buf[:sz])
	}
	sz = uint32(unix.SizeofSockaddrInet6)
	_, _, e = unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(unix.SOL_IPV6),
		uintptr(soOriginalDst), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&sz)), 0)
	if e == 0 {
		return parseSockaddr(buf[:sz])
	}
	return netip.AddrPort{}, fmt.Errorf("transparent: SO_ORIGINAL_DST getsockopt:%v", e)
}

// parseSockaddr 解析内核回填的 sockaddr_in / sockaddr_in6(family 本机序,port 网络序)。
func parseSockaddr(b []byte) (netip.AddrPort, error) {
	if len(b) < 4 {
		return netip.AddrPort{}, fmt.Errorf("transparent: sockaddr 过短")
	}
	family := *(*uint16)(unsafe.Pointer(&b[0]))
	port := binary.BigEndian.Uint16(b[2:4])
	switch family {
	case unix.AF_INET:
		if len(b) < 8 {
			return netip.AddrPort{}, fmt.Errorf("transparent: sockaddr_in 过短")
		}
		return netip.AddrPortFrom(netip.AddrFrom4(*(*[4]byte)(b[4:8])), port), nil
	case unix.AF_INET6:
		if len(b) < 24 {
			return netip.AddrPort{}, fmt.Errorf("transparent: sockaddr_in6 过短")
		}
		return netip.AddrPortFrom(netip.AddrFrom16(*(*[16]byte)(b[8:24])), port), nil
	}
	return netip.AddrPort{}, fmt.Errorf("transparent: 未知 family %d", family)
}

// serveUDP:tproxy UDP —— 透明收包 socket(IP_TRANSPARENT + IP_RECVORIGDSTADDR),recvmsg 取
// (src, origdst),按 src+origdst 聚流,回包用一个共享的透明发包 socket 伪造源地址(IP_PKTINFO)。
func (h *Inbound) serveUDP(ctx context.Context, listen string) error {
	sa, family, err := resolveSockaddr(listen)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("transparent: udp socket:%w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return fmt.Errorf("transparent: udp bind %s:%w", listen, err)
	}
	context.AfterFunc(ctx, func() { unix.Close(fd) })

	laddr := &net.UDPAddr{IP: net.IPv4zero, Port: portOf(listen)}
	buf := make([]byte, 64*1024)
	oob := make([]byte, 512)
	for {
		n, oobn, _, from, err := unix.Recvmsg(fd, buf, oob, 0)
		if err != nil {
			return err
		}
		src, ok := sockaddrToAddrPort(from)
		if !ok {
			continue
		}
		origdst, ok := parseOrigDst(oob[:oobn])
		if !ok {
			continue // 无原始目的(未走 TPROXY),丢弃
		}
		od, sc := origdst, src
		// 每流一个绑定到 origdst 的透明回写 socket:回包源 = origdst(IP+端口都对),
		// 客户端的 connected UDP 才认(IP_PKTINFO 只能定源 IP、定不了源端口,故必须 bind)。
		open := func() (func([]byte) error, func(), error) { return newTProxyReply(od, sc) }
		key := src.String() + "->" + origdst.String()
		h.nat.Dispatch(ctx, h.out, key, addr.FromIPPort(origdst), laddr, open, buf[:n])
	}
}

// newTProxyReply 建一个绑定到 origdst 的透明 UDP socket,回写到 src(源地址即 origdst,IP+端口俱全)。
func newTProxyReply(origdst, src netip.AddrPort) (func([]byte) error, func(), error) {
	family := unix.AF_INET
	var bindSa, toSa unix.Sockaddr
	if origdst.Addr().Is4() {
		bindSa = &unix.SockaddrInet4{Port: int(origdst.Port()), Addr: origdst.Addr().As4()}
		toSa = &unix.SockaddrInet4{Port: int(src.Port()), Addr: src.Addr().As4()}
	} else {
		family = unix.AF_INET6
		bindSa = &unix.SockaddrInet6{Port: int(origdst.Port()), Addr: origdst.Addr().As16()}
		toSa = &unix.SockaddrInet6{Port: int(src.Port()), Addr: src.Addr().As16()}
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, nil, err
	}
	// IP_TRANSPARENT 允许绑定到「非本机地址」(origdst 是被代理的真目标,不是 gw 自己的地址);
	// REUSEADDR/PORT 允许多个流各自绑同一 origdst(4 元组因 src 不同而唯一)。
	if origdst.Addr().Is4() {
		_ = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	} else {
		_ = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	if err := unix.Bind(fd, bindSa); err != nil {
		unix.Close(fd)
		return nil, nil, fmt.Errorf("transparent: reply bind %v:%w", origdst, err)
	}
	sendBack := func(p []byte) error { return unix.Sendmsg(fd, p, nil, toSa, 0) }
	onClose := func() { unix.Close(fd) }
	return sendBack, onClose, nil
}

// parseOrigDst 从 recvmsg 的控制消息里取 IP_ORIGDSTADDR / IPV6_ORIGDSTADDR。
func parseOrigDst(oob []byte) (netip.AddrPort, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, false
	}
	for _, m := range msgs {
		if m.Header.Level == unix.SOL_IP && m.Header.Type == unix.IP_ORIGDSTADDR {
			if ap, err := parseSockaddr(m.Data); err == nil {
				return ap, true
			}
		}
		if m.Header.Level == unix.SOL_IPV6 && m.Header.Type == unix.IPV6_ORIGDSTADDR {
			if ap, err := parseSockaddr(m.Data); err == nil {
				return ap, true
			}
		}
	}
	return netip.AddrPort{}, false
}

// ── 地址小工具 ──────────────────────────────────────────────────────────────

func toAddrPort(a net.Addr) (netip.AddrPort, bool) {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.AddrPort(), true
	}
	ap, err := netip.ParseAddrPort(a.String())
	return ap, err == nil
}

func sockaddrToAddrPort(sa unix.Sockaddr) (netip.AddrPort, bool) {
	switch v := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(v.Addr), uint16(v.Port)), true
	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(v.Addr), uint16(v.Port)), true
	}
	return netip.AddrPort{}, false
}

// resolveSockaddr 把 listen(host:port)解析成绑定用 sockaddr + 地址族。
func resolveSockaddr(listen string) (unix.Sockaddr, int, error) {
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, 0, fmt.Errorf("transparent: 解析 listen %q:%w", listen, err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	if host == "" || host == "0.0.0.0" || host == "*" {
		return &unix.SockaddrInet4{Port: port}, unix.AF_INET, nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, 0, fmt.Errorf("transparent: listen host 需 IP,得 %q", host)
	}
	if ip.Is4() {
		return &unix.SockaddrInet4{Port: port, Addr: ip.As4()}, unix.AF_INET, nil
	}
	return &unix.SockaddrInet6{Port: port, Addr: ip.As16()}, unix.AF_INET6, nil
}

func portOf(listen string) int {
	_, portStr, _ := net.SplitHostPort(listen)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}
