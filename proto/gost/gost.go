// Package gost 实现 gost relay 协议(go-gost/relay v1;mihomo 作 type: gost-relay 出站暴露;BandProxy)。
//
// gost relay 是"薄头连接式代理":客户端连到 relay 服务端,发一个 CONNECT 请求(携带目标地址、网络类型、
// 可选用户名口令),服务端连目标并中继。自身无加密 —— 机密性/抗探测靠可选的下层 [tls]/[ws]/mux。
//
// 线格式(禁改,承 go-gost/relay v1,与 mihomo transport/gost 逐字节一致):
//
//	请求(客户端→服务端):
//	  [0x01 版本][0x01 命令=connect][2B BE 特征区长]
//	  特征区 = 若干特征,每个 [1B 类型][2B BE 长度][载荷]:
//	    - 0x01 UserAuth:[1B ulen][user][1B plen][pass]        (有 user/pass 才发)
//	    - 0x02 Addr:    [1B addrtype][addr][2B BE port]         (目标;0x01=IPv4,0x03=域名[1B len][host],0x04=IPv6)
//	    - 0x04 Network: [2B BE network]                         (0x0000 TCP,0x0001 UDP)
//	响应(服务端→客户端):[0x01 版本][status][2B BE 特征区长][特征区...];status 0x00=OK。
//
// v1:仅 TCP CONNECT(gost relay 的 UDP 关联后续)。
package gost

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/proxy"
)

const (
	version1   = 0x01
	cmdConnect = 0x01

	statusOK           = 0x00
	statusBadRequest   = 0x01
	statusUnauthorized = 0x02

	featureUserAuth = 0x01
	featureAddr     = 0x02
	featureNetwork  = 0x04

	addrIPv4   = 0x01
	addrDomain = 0x03
	addrIPv6   = 0x04

	networkTCP = 0x0000
	networkUDP = 0x0001
)

var (
	_ proxy.Server = (*Proxy)(nil)
	_ proxy.Client = (*Proxy)(nil)

	errBadVersion = errors.New("gost: 版本号错")
	errAtyp       = errors.New("gost: 未知地址类型")
	errNoAddr     = errors.New("gost: 请求缺目标地址特征")
	errAuth       = errors.New("gost: 鉴权失败")
)

// Config 是 gost relay 配置:可选 username/password(两端一致;置空=不鉴权)。
type Config struct {
	Username string
	Password string
}

// Proxy 是 gost relay 连接级句柄(Descriptor.Build 产物,连接间复用;authRequired 在装配期一次性设定)。
type Proxy struct {
	cfg          Config
	authRequired bool // 装配侧经 AuthGate 告知:本口配了 per-user 凭据 → 未匹配即拒
}

// Build 构造 Proxy。
func Build(_ context.Context, cfg Config, _ any) (any, error) { return &Proxy{cfg: cfg}, nil }

// per-user 凭据(第4章顶层 users):线上明文 user/pass,凭据串约定 "user:pass"(冒号首切,口令可含冒号,
// 与 socks/client.go 同款);两端都是 identity,无派生。
var (
	_ proxy.CredentialCodec = (*Proxy)(nil)
	_ proxy.AuthGate        = (*Proxy)(nil)
)

func (*Proxy) ClientKey(secret string) ([]byte, error) { return []byte(secret), nil }
func (*Proxy) AuthKey(secret string) ([]byte, error)   { return []byte(secret), nil }
func (p *Proxy) SetAuthRequired(required bool)         { p.authRequired = required }

// splitUserPass 把 "user:pass" 冒号首切;缺冒号则整体作用户名、口令空。
func splitUserPass(s string) (user, pass string) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}

// userPassKey 是 Authenticator 的精确键:与 AuthKey("user:pass") 同字节。
func userPassKey(user, pass string) []byte { return []byte(user + ":" + pass) }

// ClientHandshake 实现 proxy.Client:写 CONNECT 请求(目标=dst),返回【惰性读响应】的流。
// 凭据:出站 secret(经 ClientKey 原样传入的 "user:pass")优先;为空则退回口级 cfg.Username/Password。
// ★惰性:go-gost v3 的 relay 响应是【懒发】—— connect 后不立刻回,而是把 [0x01][status][2B] 前缀【拼在目标
// 首段下行数据前】一起发(省一个 RTT)。若客户端在握手里阻塞读响应,就与"服务端等客户端先发数据"死锁
// (同 grpc 懒响应那课)。故这里握手只写请求即返回,首次 Read 时才剥响应前缀。
func (p *Proxy) ClientHandshake(_ context.Context, below link.Stream, key []byte, dst addr.Socksaddr) (link.Stream, error) {
	user, pass := p.cfg.Username, p.cfg.Password
	if len(key) > 0 {
		user, pass = splitUserPass(string(key))
	}
	var b bytes.Buffer
	writeRelayRequest(&b, cmdConnect, dst, networkTCP, user, pass)
	if _, err := below.Write(b.Bytes()); err != nil {
		return nil, err
	}
	return &clientStream{Stream: below}, nil
}

// clientStream 惰性剥 relay 响应前缀:首次 Read 前先读掉 [0x01][status][2B featlen][features]。
type clientStream struct {
	link.Stream
	once    sync.Once
	respErr error
}

func (c *clientStream) Read(p []byte) (int, error) {
	c.once.Do(func() { c.respErr = readConnectResponse(c.Stream) })
	if c.respErr != nil {
		return 0, c.respErr
	}
	return c.Stream.Read(p)
}

func (c *clientStream) Unwrap() any { return c.Stream }

// ServerHandshake 实现 proxy.Server:读 CONNECT 请求 → 解目标/网络/鉴权 → 回 OK → 返回下层中继流。
func (p *Proxy) ServerHandshake(_ context.Context, below link.Stream, auth proxy.Authenticator) (link.Stream, *proxy.Request, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(below, hdr[:]); err != nil {
		return nil, nil, err
	}
	if hdr[0] != version1 {
		return nil, nil, errBadVersion
	}
	payloadLen := int(hdr[2])<<8 | int(hdr[3])
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(below, payload); err != nil {
		return nil, nil, err
	}
	dst, network, user, pass, err := parseFeatures(payload)
	if err != nil {
		_ = writeResponse(below, statusBadRequest)
		return nil, nil, err
	}
	// 鉴权三档(按优先级):① 顶层 users 精确命中 → 该用户;② 口级单凭据(旧写法 cfg.Username/Password)
	// 比对 → Ambient;③ 本口配了 users 却未命中 → 拒(AuthGate);④ 什么都没配 → no-auth Ambient。
	ref := cred.Ref{ID: cred.Ambient}
	if r, ok := auth.Auth("gost", userPassKey(user, pass)); ok {
		ref = r
	} else if p.cfg.Username != "" || p.cfg.Password != "" {
		if user != p.cfg.Username || pass != p.cfg.Password {
			_ = writeResponse(below, statusUnauthorized)
			return nil, nil, errAuth
		}
	} else if p.authRequired {
		_ = writeResponse(below, statusUnauthorized)
		return nil, nil, errAuth
	}
	if err := writeResponse(below, statusOK); err != nil {
		return nil, nil, err
	}
	net := endpoint.NetworkTCP
	if network == networkUDP {
		net = endpoint.NetworkUDP
	}
	return below, &proxy.Request{Cred: ref, Network: net, Command: cmdConnect, Dst: dst}, nil
}

// writeRelayRequest 编 CONNECT 请求(逐字节承 mihomo/go-gost)。
func writeRelayRequest(w *bytes.Buffer, command byte, dst addr.Socksaddr, network uint16, user, pass string) {
	var feats bytes.Buffer
	if user != "" || pass != "" {
		var ua bytes.Buffer
		ua.WriteByte(byte(len(user)))
		ua.WriteString(user)
		ua.WriteByte(byte(len(pass)))
		ua.WriteString(pass)
		writeFeature(&feats, featureUserAuth, ua.Bytes())
	}
	var ab bytes.Buffer
	writeAddr(&ab, dst)
	writeFeature(&feats, featureAddr, ab.Bytes())
	writeFeature(&feats, featureNetwork, []byte{byte(network >> 8), byte(network)})

	w.WriteByte(version1)
	w.WriteByte(command)
	var pl [2]byte
	binary.BigEndian.PutUint16(pl[:], uint16(feats.Len()))
	w.Write(pl[:])
	w.Write(feats.Bytes())
}

func writeFeature(w *bytes.Buffer, ftype byte, payload []byte) {
	w.WriteByte(ftype)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	w.Write(l[:])
	w.Write(payload)
}

func writeAddr(w *bytes.Buffer, d addr.Socksaddr) {
	switch {
	case d.IsFqdn():
		w.WriteByte(addrDomain)
		w.WriteByte(byte(len(d.Fqdn)))
		w.WriteString(d.Fqdn)
	case d.Addr.Is4():
		w.WriteByte(addrIPv4)
		a := d.Addr.As4()
		w.Write(a[:])
	default:
		w.WriteByte(addrIPv6)
		a := d.Addr.As16()
		w.Write(a[:])
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], d.Port)
	w.Write(pb[:])
}

// writeResponse 编响应:[0x01][status][2B 特征区长=0]。
func writeResponse(w io.Writer, status byte) error {
	_, err := w.Write([]byte{version1, status, 0x00, 0x00})
	return err
}

// readConnectResponse 读响应,校验版本 + status OK,丢弃特征区。
func readConnectResponse(r io.Reader) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != version1 {
		return errBadVersion
	}
	if hdr[1] != statusOK {
		return errors.New("gost: 服务端拒绝(status 0x" + hexByte(hdr[1]) + ")")
	}
	featLen := int(hdr[2])<<8 | int(hdr[3])
	if featLen > 0 {
		_, err := io.CopyN(io.Discard, r, int64(featLen))
		return err
	}
	return nil
}

// parseFeatures 解请求特征区 → (目标, 网络, user, pass)。目标特征必存。
func parseFeatures(payload []byte) (addr.Socksaddr, uint16, string, string, error) {
	var dst addr.Socksaddr
	network := uint16(networkTCP)
	var user, pass string
	haveAddr := false
	for len(payload) > 0 {
		if len(payload) < 3 {
			return dst, 0, "", "", errors.New("gost: 特征头截断")
		}
		ftype := payload[0]
		flen := int(payload[1])<<8 | int(payload[2])
		payload = payload[3:]
		if len(payload) < flen {
			return dst, 0, "", "", errors.New("gost: 特征载荷截断")
		}
		body := payload[:flen]
		payload = payload[flen:]
		switch ftype {
		case featureUserAuth:
			user, pass = parseUserAuth(body)
		case featureAddr:
			d, err := parseAddr(body)
			if err != nil {
				return dst, 0, "", "", err
			}
			dst, haveAddr = d, true
		case featureNetwork:
			if flen >= 2 {
				network = uint16(body[0])<<8 | uint16(body[1])
			}
		}
	}
	if !haveAddr {
		return dst, 0, "", "", errNoAddr
	}
	return dst, network, user, pass, nil
}

func parseUserAuth(b []byte) (string, string) {
	if len(b) < 1 {
		return "", ""
	}
	ul := int(b[0])
	if len(b) < 1+ul+1 {
		return "", ""
	}
	user := string(b[1 : 1+ul])
	pl := int(b[1+ul])
	if len(b) < 1+ul+1+pl {
		return user, ""
	}
	return user, string(b[1+ul+1 : 1+ul+1+pl])
}

func parseAddr(b []byte) (addr.Socksaddr, error) {
	var host addr.Socksaddr
	if len(b) < 1 {
		return host, errAtyp
	}
	atyp := b[0]
	b = b[1:]
	switch atyp {
	case addrIPv4:
		if len(b) < 4+2 {
			return host, errAtyp
		}
		host.Addr = netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
		b = b[4:]
	case addrIPv6:
		if len(b) < 16+2 {
			return host, errAtyp
		}
		var a [16]byte
		copy(a[:], b[:16])
		host.Addr = netip.AddrFrom16(a)
		b = b[16:]
	case addrDomain:
		if len(b) < 1 {
			return host, errAtyp
		}
		l := int(b[0])
		if len(b) < 1+l+2 {
			return host, errAtyp
		}
		host.Fqdn = string(b[1 : 1+l])
		b = b[1+l:]
	default:
		return host, errAtyp
	}
	host.Port = binary.BigEndian.Uint16(b[:2])
	return host, nil
}

func hexByte(b byte) string {
	const h = "0123456789abcdef"
	return string([]byte{h[b>>4], h[b&0xf]})
}
