package snellv45

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// 命令字节(与 v6 同)。
const (
	CmdPing         = 0
	CmdConnect      = 1
	CmdConnectReuse = 5
	CmdUDP          = 6
)

type command struct {
	command  byte
	clientID string
	host     string
	port     uint16
}

// parseCommand 解 stage-S0 请求头:[ver=1][cmd][idLen][clientID][hostLen][host][port BE]。
// 返回 (nil,0,nil) 表示需要更多字节。
func parseCommand(b []byte) (*command, int, error) {
	if len(b) < 2 {
		return nil, 0, nil
	}
	if b[0] != 1 {
		return nil, 0, fmt.Errorf("snellv45: bad version %d", b[0])
	}
	cmd := b[1]
	if cmd == CmdPing {
		return &command{command: CmdPing}, 2, nil
	}
	if cmd&0xFB != 1 && cmd != CmdUDP {
		return nil, 0, fmt.Errorf("snellv45: unknown command %d", cmd)
	}
	if len(b) < 3 {
		return nil, 0, nil
	}
	idLen := int(b[2])
	p := 3 + idLen
	if len(b) < p {
		return nil, 0, nil
	}
	clientID := string(b[3:p])
	if cmd == CmdUDP {
		return &command{command: CmdUDP, clientID: clientID}, p, nil
	}
	if len(b) < p+1 {
		return nil, 0, nil
	}
	hostLen := int(b[p])
	q := p + 1 + hostLen
	if len(b) < q+2 {
		return nil, 0, nil
	}
	host := string(b[p+1 : q])
	port := binary.BigEndian.Uint16(b[q : q+2])
	return &command{command: cmd, clientID: clientID, host: host, port: port}, q + 2, nil
}

// ---------- Client ----------

// Client 是 Snell v4/v5 客户端。
type Client struct{ PSK []byte }

// DialTCPOver 在已建立的 conn 上跑 v4/v5 CONNECT 握手,返回承载中继 payload 的 net.Conn。
func (c *Client) DialTCPOver(conn net.Conn, host string, port uint16, initial []byte) (net.Conn, error) {
	snd, err := NewSender(c.PSK)
	if err != nil {
		return nil, err
	}
	cc := &clientConn{conn: conn, br: bufio.NewReader(conn), send: snd, recv: NewReceiver(c.PSK)}
	cmd := make([]byte, 0, 6+len(host)+len(initial))
	cmd = append(cmd, 1, CmdConnect, 0, byte(len(host))) // ver=1, CONNECT, idLen=0, hostLen
	cmd = append(cmd, host...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	cmd = append(cmd, pb[:]...)
	cmd = append(cmd, initial...)
	enc, err := snd.EncodeChunk(cmd)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(enc); err != nil {
		return nil, err
	}
	return cc, nil
}

type clientConn struct {
	conn      net.Conn
	br        *bufio.Reader
	send      *Sender
	recv      *Receiver
	rbuf      []byte
	gotStatus bool
}

func (c *clientConn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		payload, err := c.recv.DecodeChunk(c.br)
		if err != nil {
			return 0, err
		}
		if payload == nil {
			return 0, io.EOF // 零长块 = 服务端半关
		}
		if !c.gotStatus {
			c.gotStatus = true
			if payload[0] == 0x02 { // 0x02 = 服务端错误 [type][len][msg]
				msg := ""
				if len(payload) >= 3 {
					n := int(payload[2])
					if 3+n <= len(payload) {
						msg = string(payload[3 : 3+n])
					}
				}
				return 0, fmt.Errorf("snellv45: server error: %s", msg)
			}
			payload = payload[1:] // 剥 0x00 OK 状态字节
			if len(payload) == 0 {
				continue
			}
		}
		c.rbuf = payload
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *clientConn) Write(p []byte) (int, error) {
	enc, err := c.send.EncodeChunk(p)
	if err != nil {
		return 0, err
	}
	if _, err := c.conn.Write(enc); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *clientConn) CloseWrite() error {
	zero, err := c.send.EncodeChunk(nil)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(zero)
	return err
}

func (c *clientConn) Close() error                       { return c.conn.Close() }
func (c *clientConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *clientConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *clientConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *clientConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *clientConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// ---------- Server ----------

// Server 是 Snell v4/v5 服务端(单端口 PSK)。
type Server struct {
	PSK              []byte
	HandshakeTimeout time.Duration
}

// AcceptResult 是服务端握手产物(字段与 v6 对齐)。
type AcceptResult struct {
	Command  byte
	Host     string
	Port     uint16
	ClientID string
	Initial  []byte
	Conn     net.Conn
}

// Accept 用端口 PSK 跑 v4/v5 服务端握手,解出命令 + 返回中继流。不 dial target。
func (s *Server) Accept(client net.Conn) (*AcceptResult, error) {
	br := bufio.NewReader(client)
	recv := NewReceiver(s.PSK)
	to := s.HandshakeTimeout
	if to == 0 {
		to = 10 * time.Second
	}
	_ = client.SetReadDeadline(time.Now().Add(to))

	var acc []byte
	for {
		payload, err := recv.DecodeChunk(br)
		if err != nil {
			return nil, err
		}
		if payload == nil {
			return nil, io.ErrUnexpectedEOF // 命令前收到半关
		}
		acc = append(acc, payload...)
		cmd, n, err := parseCommand(acc)
		if err != nil {
			return nil, err
		}
		if cmd != nil {
			_ = client.SetReadDeadline(time.Time{})
			snd, err := NewSender(s.PSK)
			if err != nil {
				return nil, err
			}
			sc := &serverConn{conn: client, br: br, send: snd, recv: recv, rbuf: append([]byte(nil), acc[n:]...)}
			return &AcceptResult{Command: cmd.command, Host: cmd.host, Port: cmd.port, ClientID: cmd.clientID, Conn: sc}, nil
		}
	}
}

type serverConn struct {
	conn       net.Conn
	br         *bufio.Reader
	send       *Sender
	recv       *Receiver
	rbuf       []byte
	sentStatus bool
}

func (c *serverConn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		payload, err := c.recv.DecodeChunk(c.br)
		if err != nil {
			return 0, err
		}
		if payload == nil {
			return 0, io.EOF // 零长块 = 客户端半关
		}
		c.rbuf = payload
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *serverConn) Write(p []byte) (int, error) {
	data := p
	if !c.sentStatus {
		c.sentStatus = true
		data = append([]byte{0x00}, p...) // 首响应前置 0x00 OK 状态字节
	}
	enc, err := c.send.EncodeChunk(data)
	if err != nil {
		return 0, err
	}
	if _, err := c.conn.Write(enc); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *serverConn) CloseWrite() error {
	zero, err := c.send.EncodeChunk(nil)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(zero)
	return err
}

func (c *serverConn) Close() error                       { return c.conn.Close() }
func (c *serverConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *serverConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *serverConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *serverConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *serverConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
