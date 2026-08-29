package snellv6

import (
	"bufio"
	"io"
	"net"
	"time"
)

// 导出命令常量(NTR 适配层用)。
const (
	CmdPing         = cmdPing    // 0
	CmdConnect      = cmdConnect // 1
	CmdConnectReuse = 5          // CONNECT with tunnel reuse
	CmdUDP          = cmdUDP     // 6
)

// AcceptResult 是服务端握手的结果:解码出的 stage-S0 命令 + 承载中继 payload 的 net.Conn。
type AcceptResult struct {
	Command  byte     // 1=CONNECT, 5=CONNECT+reuse, 6=UDP, 0=PING
	Host     string   // CONNECT 目标主机(域名或 IP 字面量)
	Port     uint16   // CONNECT 目标端口
	ClientID string   // 多用户身份(clientID → 用户;per-user 计量/限速归属)
	Initial  []byte   // 命令后 piggyback 的初始数据(应先发给 target)
	Conn     net.Conn // 中继流:Read/Write 载 app 字节,Snell framing 内部处理
}

// Accept 用端口 PSK 在 client 上跑 Snell v6 服务端握手(descatter salt + 会话密钥 +
// 解 stage-S0 命令 + 反重放),返回命令 + 中继流。
//
// 与 ServeConn 不同:它【不 dial target】—— egress 交给上层(NTR router)。这是为把
// vendored 引擎接进 NTR 的 admission/路由模型而加的入口(多用户 = 单端口 PSK + clientID)。
func (s *Server) Accept(client net.Conn) (*AcceptResult, error) {
	s.init()
	br := bufio.NewReader(client)
	recv := s.newDecoder()
	checked := false

	client.SetReadDeadline(time.Now().Add(s.HandshakeTimeout))
	hdr, initial, err := s.readCommand(recv, br, &checked, client)
	if err != nil {
		return nil, err
	}
	client.SetReadDeadline(time.Time{})

	send := s.newEncoder(recv.UsesChaCha()) // 匹配客户端 cipher
	return &AcceptResult{
		Command:  hdr.command,
		Host:     hdr.host,
		Port:     hdr.port,
		ClientID: hdr.clientID,
		Initial:  initial,
		Conn:     &serverConn{conn: client, br: br, send: send, recv: recv},
	}, nil
}

// serverConn 把 Snell framing 适配成承载中继 payload 的 net.Conn(服务端侧)。
// 首个响应块前置 0x00 OK 状态字节(sub_3EF60),与 clientConn 的 strip 对齐。
type serverConn struct {
	conn       net.Conn
	br         *bufio.Reader
	send       chunkEncoder
	recv       chunkDecoder
	rbuf       []byte
	sentStatus bool
}

func (c *serverConn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		payload, err := c.recv.DecodeChunk(c.br)
		if err != nil {
			return 0, err
		}
		if len(payload) == 0 {
			return 0, io.EOF // 零长块 == 客户端半关
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
		data = append([]byte{0x00}, p...) // 首响应带 0x00 OK 状态字节
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

// CloseWrite 发零长块作半关标记,不拆读方向。
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
