package snellv6

import (
	"bufio"
	"encoding/binary"
	"net"
	"strconv"
	"sync"
)

// ServerPacketConn 把一个 v6 UDP 会话(CmdUDP 握手后)的 chunk 流适配成多目标数据报读写:
// 复用握手已建立的 send/recv(AEAD 状态延续),chunk 级(一个 chunk == 一个 UDP frame,保数据报
// 边界)。供上层(NTR proto/snell)接进协议无关的 udpNAT 落地 —— 取代 vendored serveUDP 里
// 一体化的"自建 relay socket 直接落地"(那绕过了 NTR 的 outbound/路由)。
//
// 帧格式与 serveUDP 严格一致:请求 parseUDPFrame([01][addr][port][data]),响应
// buildUDPResponse([type][ip][port][data]) 且【不加 0x00 status 字节】(UDP 与 TCP 首响应不同)。
type ServerPacketConn struct {
	conn    net.Conn
	br      *bufio.Reader
	send    chunkEncoder
	recv    chunkDecoder
	initial []byte // CmdUDP 命令 chunk 后 piggyback 的第一个 UDP frame(首次 ReadFrom 先消费)
	wmu     sync.Mutex
}

// NewServerPacketConn 用任意 chunk 编解码器 + 承载连接构造 UDP 数据报适配。UDP 帧格式在 v3/v4/v5/v6
// 完全一致(仅 chunk 分帧不同),故 snellv123(SS-AEAD)/snellv45 可复用本适配,只传各自的 send/recv。
func NewServerPacketConn(conn net.Conn, br *bufio.Reader, send chunkEncoder, recv chunkDecoder, initial []byte) *ServerPacketConn {
	return &ServerPacketConn{conn: conn, br: br, send: send, recv: recv, initial: initial}
}

// AsServerPacketConn 从 AcceptResult(command==CmdUDP)构造 UDP 数据报适配;非 v6 serverConn 返回 false。
// r.Initial 是命令后剩余字节 —— 若客户端把命令与第一个 UDP frame 合并进同一 chunk(piggyback,
// 省 RTT),第一个数据报就在这里,须先消费(vendored serveUDP 丢了它,DNS 查询/QUIC Initial 会缺)。
func (r *AcceptResult) AsServerPacketConn() (*ServerPacketConn, bool) {
	sc, ok := r.Conn.(*serverConn)
	if !ok {
		return nil, false
	}
	return &ServerPacketConn{conn: sc.conn, br: sc.br, send: sc.send, recv: sc.recv, initial: r.Initial}, true
}

// ReadFrom 读一个客户端 UDP 请求(一个 chunk == 一个 frame),返回 target "host:port" + payload。
// 首次先消费命令 chunk piggyback 的 initial;空 chunk(keepalive)跳过继续读(对齐 serveUDP)。
func (c *ServerPacketConn) ReadFrom() (target string, data []byte, err error) {
	for {
		var payload []byte
		if len(c.initial) > 0 {
			payload = c.initial
			c.initial = nil
		} else {
			payload, err = c.recv.DecodeChunk(c.br)
			if err != nil {
				return "", nil, err
			}
		}
		if len(payload) == 0 {
			continue
		}
		return parseUDPFrame(payload)
	}
}

// WriteTo 把响应数据报封成 frame → chunk 写回客户端。srcIP/srcPort 为响应来源(填入 frame 供客户端
// 匹配会话)。写加锁串行化(多目标反向可能并发)。
func (c *ServerPacketConn) WriteTo(srcIP net.IP, srcPort uint16, data []byte) error {
	frame := buildUDPResponse(&net.UDPAddr{IP: srcIP, Port: int(srcPort)}, data)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	enc, err := c.send.EncodeChunk(frame)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(enc)
	return err
}

// Close 关闭底层 TCP 会话。
func (c *ServerPacketConn) Close() error { return c.conn.Close() }

// -------- 客户端 UDP(vendored 只有服务端 serveUDP,此处补对称的客户端方向)--------

// ClientPacketConn 是 v6 UDP 客户端会话(CmdUDP 握手后):WriteTo 发请求 frame(target 在每帧),
// ReadFrom 收响应 frame。收发字节严格对称于服务端(parseUDPFrame/buildUDPResponse)。
type ClientPacketConn struct {
	conn net.Conn
	br   *bufio.Reader
	send chunkEncoder
	recv chunkDecoder
	wmu  sync.Mutex
}

// DialUDPOver 在已建立的 conn 上跑 CmdUDP 握手(命令 [1][6][idLen=0]),返回 UDP 会话。
func (c *Client) DialUDPOver(conn net.Conn) (*ClientPacketConn, error) {
	pc := &ClientPacketConn{conn: conn, br: bufio.NewReader(conn), send: c.newEncoder(), recv: c.newDecoder()}
	enc, err := pc.send.EncodeChunk([]byte{1, cmdUDP, 0}) // ver=1, CmdUDP, idLen=0
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(enc); err != nil {
		return nil, err
	}
	return pc, nil
}

// WriteTo 把 data 发到 target("host:port"):封请求 frame → chunk 写出。
func (c *ClientPacketConn) WriteTo(target string, data []byte) error {
	frame, err := buildUDPRequest(target, data)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	enc, err := c.send.EncodeChunk(frame)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(enc)
	return err
}

// ReadFrom 读一个响应数据报(一个 chunk == 一个 response frame [type][ip][port][data])。
func (c *ClientPacketConn) ReadFrom() (srcIP net.IP, srcPort uint16, data []byte, err error) {
	for {
		payload, e := c.recv.DecodeChunk(c.br)
		if e != nil {
			return nil, 0, nil, e
		}
		if len(payload) == 0 {
			continue
		}
		return parseUDPResponse(payload)
	}
}

// Close 关闭底层 TCP 会话。
func (c *ClientPacketConn) Close() error { return c.conn.Close() }

// buildUDPRequest 构造客户端 UDP 请求 frame(对称 parseUDPFrame):
// IP 形式 [01][00][type][ip][port];域名形式 [01][addrLen][host][port];后跟 data。
func buildUDPRequest(target string, data []byte) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			out := append([]byte{1, 0, 4}, ip4...)
			out = append(out, pb[:]...)
			return append(out, data...), nil
		}
		out := append([]byte{1, 0, 6}, ip.To16()...)
		out = append(out, pb[:]...)
		return append(out, data...), nil
	}
	if len(host) > 255 {
		return nil, errUDPFrame
	}
	out := append([]byte{1, byte(len(host))}, host...)
	out = append(out, pb[:]...)
	return append(out, data...), nil
}

// parseUDPResponse 解服务端响应 frame(对称 buildUDPResponse):[type][ip][port][data]。
func parseUDPResponse(b []byte) (net.IP, uint16, []byte, error) {
	if len(b) < 1 {
		return nil, 0, nil, errUDPFrame
	}
	switch b[0] {
	case 4:
		if len(b) < 7 {
			return nil, 0, nil, errUDPFrame
		}
		return net.IP(b[1:5]), binary.BigEndian.Uint16(b[5:7]), b[7:], nil
	case 6:
		if len(b) < 19 {
			return nil, 0, nil, errUDPFrame
		}
		return net.IP(b[1:17]), binary.BigEndian.Uint16(b[17:19]), b[19:], nil
	default:
		return nil, 0, nil, errUDPFrame
	}
}
