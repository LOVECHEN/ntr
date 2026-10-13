// Package juicity 自写实现 Juicity —— QUIC 之上的代理协议(TUIC 的改进版,UDP 走 stream 而非
// datagram/单向流)。xray/sing-box/mihomo 均未实现;权威实现是 github.com/juicity/juicity
// (server)+ github.com/daeuniverse/outbound/protocol/juicity(client),本包按其线格式 clean-room
// 自写(只取线格式事实,不搬实现代码),并以官方二进制交叉验证。
//
// 线格式(以官方实现为准):
//
//	传输:QUIC,TLS 1.3,ALPN = "h3";拥塞控制至少支持 BBR(规范 MUST)。
//
//	鉴权(每条 QUIC 连接一次):客户端开一条【单向流】写
//	  [ver=0x00][cmd=0x00][uuid 16B][token 32B]
//	  token = TLS ExportKeyingMaterial(label = uuid 的 16 字节原始串, context = password, 32)
//	  (与 TUIC v5 同算法,仅 ver 不同)。无应答;服务端鉴权失败直接关整条连接。客户端无需等待鉴权
//	  完成即可并发开代理流,服务端在鉴权成功后才处理代理流。新版客户端可在同一单向流上续写
//	  underlay 鉴权帧,服务端须容忍(读掉/忽略)。
//
//	代理流(每条 TCP 连接 / 每个 UDP 会话一条【双向流】),流首 = [network][socks 地址]:
//	  network:0x01 = TCP,0x03 = UDP
//	  TCP:流首之后即裸字节双向中继,服务端不回任何应答头。
//	  UDP:流首之后两个方向都是数据报帧序列,每帧 = [socks 地址][长度 u16 BE][负载]
//	       (客户端→服务端:目标地址;服务端→客户端:来源地址)。
//
//	socks 地址:[atyp][addr][port u16 BE],atyp 0x01=IPv4(4B)、0x03=域名(1B 长度+字节)、0x04=IPv6(16B)。
//
// ★规范文档(docs/spec.md)写的 AddrType 是 IPv4=0 / IPv6=1 / Domain=2,但官方实现(trojanc.Metadata)
// 用的是 socks5 编号 1/4/3 —— 照文档写会与官方客户端/服务端互不通。本包以实现为准(互通是唯一判据)。
package juicity

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/LOVECHEN/ntr/addr"
)

const (
	version0        byte = 0x00
	cmdAuthenticate byte = 0x00

	networkTCP byte = 0x01
	networkUDP byte = 0x03

	atypIPv4   byte = 0x01
	atypDomain byte = 0x03
	atypIPv6   byte = 0x04

	authLen  = 2 + 16 + 32 // ver + cmd + uuid + token
	tokenLen = 32
)

var (
	errBadAddr    = errors.New("juicity: 无效地址")
	errBadVersion = errors.New("juicity: 不支持的协议版本")
	errBadCommand = errors.New("juicity: 不支持的命令")
	errBadNetwork = errors.New("juicity: 不支持的 network")
)

// appendAddr 把目标地址编成 socks 地址追加到 b。
func appendAddr(b []byte, a addr.Socksaddr) ([]byte, error) {
	switch {
	case a.IsFqdn():
		if len(a.Fqdn) > 255 {
			return nil, fmt.Errorf("%w: 域名过长(%d)", errBadAddr, len(a.Fqdn))
		}
		b = append(b, atypDomain, byte(len(a.Fqdn)))
		b = append(b, a.Fqdn...)
	case a.Addr.Unmap().Is4():
		ip := a.Addr.Unmap().As4()
		b = append(b, atypIPv4)
		b = append(b, ip[:]...)
	case a.Addr.Is6():
		ip := a.Addr.As16()
		b = append(b, atypIPv6)
		b = append(b, ip[:]...)
	default:
		return nil, errBadAddr
	}
	return binary.BigEndian.AppendUint16(b, a.Port), nil
}

// readAddr 从 r 读一个 socks 地址。
func readAddr(r io.Reader) (addr.Socksaddr, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return addr.Socksaddr{}, err
	}
	var a addr.Socksaddr
	switch t[0] {
	case atypIPv4:
		var b [4 + 2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return addr.Socksaddr{}, err
		}
		a.Addr = netip.AddrFrom4([4]byte(b[:4]))
		a.Port = binary.BigEndian.Uint16(b[4:])
	case atypIPv6:
		var b [16 + 2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return addr.Socksaddr{}, err
		}
		a.Addr = netip.AddrFrom16([16]byte(b[:16]))
		a.Port = binary.BigEndian.Uint16(b[16:])
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return addr.Socksaddr{}, err
		}
		b := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return addr.Socksaddr{}, err
		}
		if l[0] == 0 {
			return addr.Socksaddr{}, fmt.Errorf("%w: 空域名", errBadAddr)
		}
		a.Fqdn = string(b[:l[0]])
		a.Port = binary.BigEndian.Uint16(b[l[0]:])
	default:
		return addr.Socksaddr{}, fmt.Errorf("%w: atyp=%#x", errBadAddr, t[0])
	}
	return a, nil
}

// genToken 由 TLS 会话导出鉴权 token(label = uuid 原始 16 字节,context = password)。
func genToken(cs tls.ConnectionState, uuid [16]byte, password string) ([tokenLen]byte, error) {
	var tok [tokenLen]byte
	km, err := cs.ExportKeyingMaterial(string(uuid[:]), []byte(password), tokenLen)
	if err != nil {
		return tok, err
	}
	copy(tok[:], km)
	return tok, nil
}

// appendAuth 编鉴权命令(写在单向流上)。
func appendAuth(b []byte, uuid [16]byte, token [tokenLen]byte) []byte {
	b = append(b, version0, cmdAuthenticate)
	b = append(b, uuid[:]...)
	return append(b, token[:]...)
}

// readAuth 读鉴权命令,校验版本与命令字。
func readAuth(r io.Reader) (uuid [16]byte, token [tokenLen]byte, err error) {
	var b [authLen]byte
	if _, err = io.ReadFull(r, b[:]); err != nil {
		return
	}
	if b[0] != version0 {
		err = fmt.Errorf("%w: %#x", errBadVersion, b[0])
		return
	}
	if b[1] != cmdAuthenticate {
		err = fmt.Errorf("%w: %#x", errBadCommand, b[1])
		return
	}
	copy(uuid[:], b[2:18])
	copy(token[:], b[18:])
	return
}

// appendStreamHeader 编代理流首 [network][socks 地址]。
func appendStreamHeader(b []byte, network byte, dst addr.Socksaddr) ([]byte, error) {
	return appendAddr(append(b, network), dst)
}

// readStreamHeader 读代理流首。
func readStreamHeader(r io.Reader) (byte, addr.Socksaddr, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return 0, addr.Socksaddr{}, err
	}
	if n[0] != networkTCP && n[0] != networkUDP {
		return 0, addr.Socksaddr{}, fmt.Errorf("%w: %#x", errBadNetwork, n[0])
	}
	a, err := readAddr(r)
	return n[0], a, err
}

// appendUDPFrame 编一个 UDP 数据报帧 [socks 地址][长度 u16][负载]。
func appendUDPFrame(b []byte, a addr.Socksaddr, payload []byte) ([]byte, error) {
	if len(payload) > 0xffff {
		return nil, fmt.Errorf("juicity: UDP 负载过长(%d)", len(payload))
	}
	b, err := appendAddr(b, a)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
	return append(b, payload...), nil
}

// readUDPFrame 读一个 UDP 数据报帧到 p:返回地址与写入 p 的字节数。负载超出 p 时截断并丢弃余下部分
// (与官方实现一致,保证流上帧边界不错位)。
func readUDPFrame(r io.Reader, p []byte) (addr.Socksaddr, int, error) {
	a, err := readAddr(r)
	if err != nil {
		return addr.Socksaddr{}, 0, err
	}
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return addr.Socksaddr{}, 0, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n <= len(p) {
		_, err = io.ReadFull(r, p[:n])
		return a, n, err
	}
	if _, err = io.ReadFull(r, p); err != nil {
		return addr.Socksaddr{}, 0, err
	}
	_, err = io.CopyN(io.Discard, r, int64(n-len(p)))
	return a, len(p), err
}
