// Package ws 实现 WebSocket(RFC 6455)传输层(core/transport.StreamTransport)。
//
// WS 是最通用的过 CDN 传输:一次 HTTP/1.1 Upgrade(带 Sec-WebSocket-Key/Accept)+ 之后
// RFC 6455 二进制帧承载代理流(客户端掩码、服务端不掩码)。线格式与 Xray / mihomo / sing-box
// 的 ws 完全一致。占 Frame band,惯用叠法 [tls, ws, vless/vmess/trojan]。
//
// 自研纯 Go 帧编解码(net/http 仅解析握手报文),不引重依赖 —— 符合瘦核心。为代理流服务:把所有
// 数据帧(binary/text/continuation)payload 顺序拼成字节流,分片对上层透明;ping 自动回 pong。
package ws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/LOVECHEN/ntr/core/link"
	"github.com/LOVECHEN/ntr/core/spec"
)

const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// maxFrameLen 单帧 payload 上限(防对端发超大 length 触发 OOM)。代理中继写缓冲远小于此,不误伤。
const maxFrameLen = 64 << 20 // 64 MiB

// wsHandshakeTimeout 读 HTTP Upgrade 请求的最长时限(防 slow-loris 半开握手钉住 goroutine)。
const wsHandshakeTimeout = 10 * time.Second

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// Config 是 WS 层自有配置。Path 是握手路径(默认 /);Host 是 Host 头(过 CDN 填伪装域名)。
type Config struct {
	Path string
	Host string
}

// Parse 从哑节点解出 Config。
func Parse(n *spec.Node) (Config, error) {
	path := n.Get("path").Str()
	if path == "" {
		path = "/"
	}
	return Config{Path: path, Host: n.Get("host").Str()}, nil
}

// Transport 是 WS 传输层句柄。
type Transport struct {
	path string
	host string
}

// Build 构造 Transport。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	path := cfg.Path
	if path == "" {
		path = "/"
	}
	return &Transport{path: path, host: cfg.Host}, nil
}

// ClientWrap 实现 StreamTransport:发 WS 握手、校验 Accept,返回帧承载的裸流(客户端掩码)。
func (t *Transport) ClientWrap(_ context.Context, below link.Stream) (link.Stream, error) {
	host := t.host
	if host == "" {
		if a := below.RemoteAddr(); a != nil {
			host = a.String()
		}
	}
	var keyRaw [16]byte
	if _, err := rand.Read(keyRaw[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyRaw[:])
	req := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: t.path}, Host: host, Header: http.Header{}}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")
	if err := req.Write(below); err != nil {
		return nil, err
	}
	br := bufio.NewReader(below)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		resp.Header.Get("Sec-WebSocket-Accept") != acceptKey(key) {
		return nil, errors.New("ws: 握手失败(状态 " + resp.Status + " 或 Accept 不匹配)")
	}
	return &wsConn{Conn: below, br: br, isClient: true, below: below}, nil
}

// ServerWrap 实现 StreamTransport:读 WS 握手、回 101 + Accept,返回帧承载的裸流(服务端不掩码)。
func (t *Transport) ServerWrap(ctx context.Context, below link.Stream) (link.Stream, error) {
	// 传播 ctx 取消 + 防 slow-loris:ctx 取消或握手超时即令读出错,打断 http.ReadRequest;
	// 否则半开握手(只发半截请求)会永久钉住本 goroutine+fd,且服务器关停打不断它。
	stop := context.AfterFunc(ctx, func() { _ = below.SetReadDeadline(time.Now()) })
	defer stop()
	_ = below.SetReadDeadline(time.Now().Add(wsHandshakeTimeout))
	br := bufio.NewReader(below)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("ws: 非 WebSocket 请求")
	}
	key := req.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("ws: 缺 Sec-WebSocket-Key")
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: " + acceptKey(key) + "\r\n\r\n"
	if _, err := below.Write([]byte(resp)); err != nil {
		return nil, err
	}
	_ = below.SetReadDeadline(time.Time{}) // 握手成功,清除 deadline(免 relay 读超时)
	return &wsConn{Conn: below, br: br, isClient: false, below: below}, nil
}

func acceptKey(key string) string {
	h := sha1.Sum([]byte(key + wsMagic))
	return base64.StdEncoding.EncodeToString(h[:])
}

// wsConn 把 WS 帧流抬成 link.Stream。Read 拼数据帧 payload;Write 每次发一个 binary 帧。
type wsConn struct {
	net.Conn
	br       *bufio.Reader
	isClient bool
	readBuf  []byte // 当前帧未读完的 payload
	below    any
	wmu      sync.Mutex // 串行化写:Read 路径的 pong 回写与 Write 路径的数据写不得交错成帧
}

func (c *wsConn) Unwrap() any { return c.below }

func (c *wsConn) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		payload, opcode, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		switch opcode {
		case opBinary, opText, opContinuation:
			c.readBuf = payload
		case opPing:
			if err := c.writeFrame(opPong, payload); err != nil {
				return 0, err
			}
		case opClose:
			return 0, io.EOF
		case opPong:
			// 忽略
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.writeFrame(opBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// readFrame 读一个 WS 帧,返回(解掩码后的)payload + opcode。
func (c *wsConn) readFrame() ([]byte, byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return nil, 0, err
	}
	opcode := hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return nil, 0, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return nil, 0, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > maxFrameLen {
		return nil, 0, errors.New("ws: 帧超长(疑似恶意 length)")
	}
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, maskKey[:]); err != nil {
			return nil, 0, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return nil, 0, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i&3]
		}
	}
	return payload, opcode, nil
}

// writeFrame 写一个 WS 帧(FIN=1)。客户端掩码,服务端不掩码。wmu 串行化,保证整帧不被并发写打断。
func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var hdr []byte
	b0 := byte(0x80 | opcode) // FIN=1
	n := len(payload)
	switch {
	case n < 126:
		hdr = []byte{b0, byte(n)}
	case n <= 0xffff:
		hdr = []byte{b0, 126, byte(n >> 8), byte(n)}
	default:
		hdr = make([]byte, 10)
		hdr[0], hdr[1] = b0, 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}
	if c.isClient {
		hdr[1] |= 0x80 // mask bit
		var mask [4]byte
		binary.BigEndian.PutUint32(mask[:], mrand.Uint32())
		// 单缓冲一次成型:[hdr][mask][masked payload];复制 + 掩码在同一遍完成,不建中间 masked 切片
		// (原来 2 次分配 + payload 复制两遍 → 现 1 次分配 + 一遍)。
		buf := make([]byte, len(hdr)+4+n)
		copy(buf, hdr)
		copy(buf[len(hdr):], mask[:])
		off := len(hdr) + 4
		for i := 0; i < n; i++ {
			buf[off+i] = payload[i] ^ mask[i&3]
		}
		_, err := c.Conn.Write(buf)
		return err
	}
	buf := make([]byte, 0, len(hdr)+n)
	buf = append(buf, hdr...)
	buf = append(buf, payload...)
	_, err := c.Conn.Write(buf)
	return err
}
