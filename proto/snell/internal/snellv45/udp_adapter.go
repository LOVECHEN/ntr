package snellv45

import (
	"bufio"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
)

// commandTunnel 是 snell v4/v5 UDP 的隧道就绪回复字节:服务端收到 CmdUDP 后须先回 [0x00],
// 客户端阻塞读到它(mihomo ReadReply)才开始发 UDP 帧。缺此则双方死锁(服务端等帧、客户端等回复)。
// v6 UDP 无此回复(官方 v6 行为不同),故仅在本 v4/v5 适配器里处理。
const commandTunnel = 0x00

// Snell v4/v5 UDP 数据面。★命令层与帧格式与 v6 【逐字节相同】(都 refer icpz/snell-server-reversed
// 与 mihomo transport/snell:CommandUDP=6,请求 [01][addr][payload],响应 [type][ip][port][payload]);
// 唯一差异是 chunk 层 —— 这里用 v4/v5 的 Sender/Receiver 取代 v6 的 encoder/decoder。故帧编解码逻辑
// 与 snellv6/udp_adapter.go + udp_server.go 保持一致(含 hostname 零 data 帧拒绝等边界)。
//
// 一个 chunk == 一个 UDP frame(保数据报边界)。UDP 响应【不含】TCP 首响应的 0x00 状态字节,故
// 收发直接走 send/recv,绕过 serverConn.Write 的状态前置。

var (
	errUDPFrame      = errors.New("snellv45: malformed UDP frame")
	errUDPBadCommand = errors.New("snellv45: unsupported UDP command")
)

// ---------- 服务端 ----------

// ServerPacketConn 把 CmdUDP 握手后的 chunk 流适配成多目标数据报读写(复用握手已建立的 send/recv)。
type ServerPacketConn struct {
	conn    net.Conn
	br      *bufio.Reader
	send    *Sender
	recv    *Receiver
	initial []byte // 命令 chunk 后 piggyback 的首个 UDP frame(serverConn.rbuf;首次 ReadFrom 先消费)
	wmu     sync.Mutex
}

// AsServerPacketConn 从 AcceptResult(Command==CmdUDP)构造 UDP 数据报适配;非 v45 serverConn 返回 false。
// ★立即回 CommandTunnel(0x00):客户端(mihomo)发完 CmdUDP 后阻塞 ReadReply 等此字节,不回则死锁。
func (r *AcceptResult) AsServerPacketConn() (*ServerPacketConn, bool) {
	sc, ok := r.Conn.(*serverConn)
	if !ok {
		return nil, false
	}
	spc := &ServerPacketConn{conn: sc.conn, br: sc.br, send: sc.send, recv: sc.recv, initial: sc.rbuf}
	enc, err := spc.send.EncodeChunk([]byte{commandTunnel}) // 首个服务端 chunk:salt+padding+[0x00]
	if err != nil {
		return nil, false
	}
	if _, err := spc.conn.Write(enc); err != nil {
		return nil, false
	}
	return spc, true
}

// ReadFrom 读一个客户端 UDP 请求(一个 chunk == 一个 frame),返回 target "host:port" + payload。
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

// WriteTo 把响应数据报封成 frame → chunk 写回客户端(src=响应来源,填入 frame 供客户端匹配会话)。
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

func (c *ServerPacketConn) Close() error { return c.conn.Close() }

// ---------- 客户端 ----------

// ClientPacketConn 是 v4/v5 UDP 客户端会话(CmdUDP 握手后):WriteTo 发请求 frame(target 在每帧),
// ReadFrom 收响应 frame。收发字节严格对称于服务端。
type ClientPacketConn struct {
	conn net.Conn
	br   *bufio.Reader
	send *Sender
	recv *Receiver
	wmu  sync.Mutex
}

// DialUDPOver 在已建立的 conn 上跑 CmdUDP 握手(命令 [1][6][idLen=0]),返回 UDP 会话。
func (c *Client) DialUDPOver(conn net.Conn) (*ClientPacketConn, error) {
	snd, err := NewSender(c.PSK)
	if err != nil {
		return nil, err
	}
	pc := &ClientPacketConn{conn: conn, br: bufio.NewReader(conn), send: snd, recv: NewReceiver(c.PSK)}
	enc, err := pc.send.EncodeChunk([]byte{1, CmdUDP, 0}) // ver=1, CmdUDP, idLen=0
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(enc); err != nil {
		return nil, err
	}
	// ★读服务端 CommandTunnel(0x00)回复(对称 mihomo ReadReply):snell v4/v5 UDP 要求服务端先回此
	// 字节表示隧道就绪,不读则首个响应帧会误含它、parseUDPResponse 报错。空块(keepalive)跳过。
	for {
		reply, e := pc.recv.DecodeChunk(pc.br)
		if e != nil {
			return nil, e
		}
		if len(reply) == 0 {
			continue
		}
		if reply[0] != commandTunnel {
			return nil, errUDPBadCommand
		}
		break
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

func (c *ClientPacketConn) Close() error { return c.conn.Close() }

// ---------- 帧编解码(与 snellv6 逐字节一致)----------

// buildUDPRequest 构造客户端 UDP 请求 frame:IP 形式 [01][00][type][ip][port];域名形式
// [01][addrLen][host][port];后跟 data。
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

// parseUDPFrame 解客户端请求 frame [01][addr][data]:域名 [01][len][host][port];IP [01][00][type][ip][port]。
func parseUDPFrame(b []byte) (string, []byte, error) {
	if len(b) < 1 || b[0] != 1 {
		return "", nil, errUDPBadCommand
	}
	if len(b) < 2 {
		return "", nil, errUDPFrame
	}
	addrLen := int(b[1])
	if addrLen != 0 {
		// hostname 形式:官方要求 host+port 后至少一字节 data(拒绝零 data 主机名帧)。
		q := 2 + addrLen
		if len(b) < q+3 {
			return "", nil, errUDPFrame
		}
		host := string(b[2:q])
		port := binary.BigEndian.Uint16(b[q : q+2])
		return net.JoinHostPort(host, strconv.Itoa(int(port))), b[q+2:], nil
	}
	// IP 形式:[01][00][type][addr][port]
	if len(b) < 3 {
		return "", nil, errUDPFrame
	}
	switch b[2] {
	case 4:
		if len(b) < 9 {
			return "", nil, errUDPFrame
		}
		ip := net.IP(b[3:7])
		port := binary.BigEndian.Uint16(b[7:9])
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), b[9:], nil
	case 6:
		if len(b) < 21 {
			return "", nil, errUDPFrame
		}
		ip := net.IP(b[3:19])
		port := binary.BigEndian.Uint16(b[19:21])
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), b[21:], nil
	default:
		return "", nil, errUDPFrame
	}
}

// buildUDPResponse 构造服务端响应 frame [type][ip][port][data]。
func buildUDPResponse(src *net.UDPAddr, data []byte) []byte {
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(src.Port))
	if ip4 := src.IP.To4(); ip4 != nil {
		out := make([]byte, 0, 7+len(data))
		out = append(out, 4)
		out = append(out, ip4...)
		out = append(out, pb[:]...)
		return append(out, data...)
	}
	out := make([]byte, 0, 19+len(data))
	out = append(out, 6)
	out = append(out, src.IP.To16()...)
	out = append(out, pb[:]...)
	return append(out, data...)
}

// parseUDPResponse 解服务端响应 frame [type][ip][port][data]。
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
