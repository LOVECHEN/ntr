package socks

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

// SOCKS4 / SOCKS4a(RFC 无正式编号,事实标准见 openssh / curl 实现)。
//
// 请求(VN 已被上层消费):
//
//	[0]    VN   = 0x04
//	[1]    CD   = 0x01 CONNECT / 0x02 BIND
//	[2:4]  DSTPORT(大端)
//	[4:8]  DSTIP
//	[8:]   USERID,以 0x00 结尾
//	★ SOCKS4a:若 DSTIP 形如 0.0.0.x(x≠0),则 USERID 之后再跟一个以 0x00 结尾的域名。
//
// 应答:
//
//	[0]    VN   = 0x00(注意不是 0x04)
//	[1]    CD   = 0x5A 允许 / 0x5B 拒绝
//	[2:4]  DSTPORT(回显即可)
//	[4:8]  DSTIP(回显即可)
const (
	version4 = 0x04

	cmd4Connect = 0x01

	rep4Granted  = 0x5A
	rep4Rejected = 0x5B

	maxSocks4Field = 256 // USERID / 域名的长度上限,防恶意超长读
)

var (
	// ErrSocks4Command 表示 SOCKS4 请求了非 CONNECT 命令(BIND 未支持)。
	ErrSocks4Command = errors.New("socks4: 仅支持 CONNECT")
	// ErrSocks4Field 表示 USERID / 域名字段超长或未正确以 NUL 结尾。
	ErrSocks4Field = errors.New("socks4: 字段超长或缺 NUL 结尾")
)

// serverHandshake4 处理 SOCKS4 / SOCKS4a 握手(VN 字节已被调用方消费)。
func (p *Proxy) serverHandshake4(below link.Stream, auth proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	var h [7]byte // CD(1) + DSTPORT(2) + DSTIP(4)
	if _, err := io.ReadFull(below, h[:]); err != nil {
		return nil, nil, err
	}
	cmd := h[0]
	port := binary.BigEndian.Uint16(h[1:3])
	ip := netip.AddrFrom4([4]byte{h[3], h[4], h[5], h[6]})

	// 用 bufio 读两个 NUL 结尾字段;剩余缓冲要还给上层(可能已携带 payload 首段)。
	br := bufio.NewReader(below)
	if _, err := readCString(br); err != nil { // USERID(不做鉴权,读掉即可)
		return nil, nil, err
	}

	var dst addr.Socksaddr
	if isSocks4aMarker(h[3:7]) { // SOCKS4a:域名跟在 USERID 之后
		host, err := readCString(br)
		if err != nil {
			return nil, nil, err
		}
		if host == "" {
			_, _ = below.Write(reply4(rep4Rejected, port, ip))
			return nil, nil, ErrSocks4Field
		}
		dst = addr.FromFqdn(host, port)
	} else {
		dst = addr.FromIPPort(netip.AddrPortFrom(ip, port))
	}

	if cmd != cmd4Connect { // BIND 未支持
		_, _ = below.Write(reply4(rep4Rejected, port, ip))
		return nil, nil, ErrSocks4Command
	}
	if _, err := below.Write(reply4(rep4Granted, port, ip)); err != nil { // 乐观允许
		return nil, nil, err
	}

	ref := cred.Ref{ID: cred.Ambient} // 本地无鉴权入站 → Ambient
	if r, ok := auth.Auth("socks", nil); ok {
		ref = r
	}
	// bufio 里可能已预读了 payload 首段,必须把它接回给上层,否则丢数据。
	return &bufStream{Stream: below, br: br}, &proxy.Request{
		Cred:    ref,
		Network: endpoint.NetworkTCP,
		Command: cmd,
		Dst:     dst,
	}, nil
}

// isSocks4aMarker 判断 DSTIP 是否为 SOCKS4a 的 0.0.0.x(x≠0)标记。
func isSocks4aMarker(ip []byte) bool {
	return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0
}

// readCString 读一个以 NUL 结尾的字段(带长度上限)。
func readCString(br *bufio.Reader) (string, error) {
	var out []byte
	for range maxSocks4Field {
		b, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if b == 0 {
			return string(out), nil
		}
		out = append(out, b)
	}
	return "", ErrSocks4Field
}

// reply4 构造 SOCKS4 应答:VN=0x00 + CD + 回显 PORT/IP。
func reply4(rep byte, port uint16, ip netip.Addr) []byte {
	out := make([]byte, 8)
	out[0] = 0x00 // 应答的 VN 恒为 0,不是 0x04
	out[1] = rep
	binary.BigEndian.PutUint16(out[2:4], port)
	v4 := ip.As4()
	copy(out[4:8], v4[:])
	return out
}

// bufStream 把 bufio 里已预读的字节接回数据面,避免握手期多读的 payload 丢失。
type bufStream struct {
	link.Stream
	br *bufio.Reader
}

func (s *bufStream) Read(p []byte) (int, error) { return s.br.Read(p) }
func (s *bufStream) Unwrap() any                { return s.Stream }
