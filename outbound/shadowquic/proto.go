// Package shadowquic 自写实现 ShadowQUIC —— JLS-over-QUIC 的抗检测代理协议(mihomo 独有;
// xray/sing-box 无)。QUIC + JLS 密码学核心桥独立库 github.com/metacubex/jls-quic-go(内含 jls-tls),
// 协议线格式(命令 + socks5 目标地址 + UDP 帧)自写、逐字节对齐 mihomo transport/shadowquic。
//
// 线格式(承 mihomo transport/shadowquic/protocol.go,禁改):QUIC 双向流上,首段 = [command][socks5.Addr],
// CommandConnect=0x01 后即 TCP 中继。socks5.Addr = [atyp][addr][port BE],atyp 1=IPv4/3=域名/4=IPv6。
// JLS 认证在 QUIC 的 TLS 握手层(jls-tls),故认证通过的对端与 mihomo 逐字节一致。
//
// v1:TCP CONNECT 路径 + 双向交叉验证。UDP(CommandAssociateDatagram/Stream)、Brutal 拥塞为后续增量。
package shadowquic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"

	"github.com/LOVECHEN/ntr/addr"
)

// 命令字节(对齐 mihomo transport/shadowquic)。
const (
	cmdConnect byte = 0x01 // TCP CONNECT
)

// socks5 地址类型。
const (
	atypIPv4   byte = 1
	atypDomain byte = 3
	atypIPv6   byte = 4
)

var errBadAddr = errors.New("shadowquic: 无效地址")

// encodeSocksAddr 把 dst 编成 socks5 wire 地址 [atyp][addr][port BE]。
func encodeSocksAddr(a addr.Socksaddr) ([]byte, error) {
	var out []byte
	switch {
	case a.IsIP():
		ip := a.Addr.Unmap()
		if ip.Is4() {
			out = append(out, atypIPv4)
			b := ip.As4()
			out = append(out, b[:]...)
		} else {
			out = append(out, atypIPv6)
			b := ip.As16()
			out = append(out, b[:]...)
		}
	case a.IsFqdn():
		if len(a.Fqdn) > 255 {
			return nil, errBadAddr
		}
		out = append(out, atypDomain, byte(len(a.Fqdn)))
		out = append(out, a.Fqdn...)
	default:
		return nil, errBadAddr
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], a.Port)
	return append(out, pb[:]...), nil
}

// readSocksAddr 从 r 读一个 socks5 wire 地址,返回 addr.Socksaddr。
func readSocksAddr(r io.Reader) (addr.Socksaddr, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return addr.Socksaddr{}, err
	}
	switch atyp[0] {
	case atypIPv4:
		var b [4 + 2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return addr.Socksaddr{}, err
		}
		ip := netip.AddrFrom4([4]byte(b[:4]))
		port := binary.BigEndian.Uint16(b[4:])
		return addr.FromIPPort(netip.AddrPortFrom(ip, port)), nil
	case atypIPv6:
		var b [16 + 2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return addr.Socksaddr{}, err
		}
		ip := netip.AddrFrom16([16]byte(b[:16]))
		port := binary.BigEndian.Uint16(b[16:])
		return addr.FromIPPort(netip.AddrPortFrom(ip, port)), nil
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return addr.Socksaddr{}, err
		}
		buf := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return addr.Socksaddr{}, err
		}
		host := string(buf[:l[0]])
		port := binary.BigEndian.Uint16(buf[l[0]:])
		// 域名可能本身是 IP 字面量,归一化。
		if ip, err := netip.ParseAddr(host); err == nil {
			return addr.FromIPPort(netip.AddrPortFrom(ip, port)), nil
		}
		return addr.FromFqdn(host, port), nil
	default:
		return addr.Socksaddr{}, fmt.Errorf("%w: atyp %d", errBadAddr, atyp[0])
	}
}

// writeConnectRequest 写 [cmdConnect][socks5.Addr]。
func writeConnectRequest(w io.Writer, dst addr.Socksaddr) error {
	saddr, err := encodeSocksAddr(dst)
	if err != nil {
		return err
	}
	buf := make([]byte, 0, 1+len(saddr))
	buf = append(buf, cmdConnect)
	buf = append(buf, saddr...)
	_, err = w.Write(buf)
	return err
}

// hostPort 拼 host:port(供 dial)。
func hostPort(host string, port uint16) string {
	return host + ":" + strconv.Itoa(int(port))
}
