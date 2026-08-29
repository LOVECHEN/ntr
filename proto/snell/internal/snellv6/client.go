package snellv6

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Client dials a Snell v6 server (optionally behind a transparent ShadowTLS
// tunnel — point serverAddr at the local shadow-tls client port). It is the
// peer of cmd/server and is validated bit-exact against the real binary.
type Client struct {
	PSK    []byte
	ChaCha bool // wire cipher; AES-128-GCM by default (what Surge uses on ARM)
	Mode   Mode // b3 encryption mode (default|unshaped|unsafe-raw); must match the server
}

// DialTCP opens a relayed TCP stream to host:port through serverAddr. The
// returned Conn's Read/Write carry the application payload (the Snell framing
// is handled internally). initial may carry bytes to piggyback on the command.
func (c *Client) DialTCP(serverAddr, host string, port uint16, initial []byte) (net.Conn, error) {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	rc, err := c.DialTCPOver(conn, host, port, initial)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return rc, nil
}

// DialTCPOver runs the Snell v6 CONNECT handshake over an already-established
// transport `conn` (e.g. a ShadowTLS tunnel) and returns the relayed stream.
func (c *Client) DialTCPOver(conn net.Conn, host string, port uint16, initial []byte) (net.Conn, error) {
	cc := &clientConn{
		conn: conn,
		br:   bufio.NewReader(conn),
		send: c.newEncoder(),
		recv: c.newDecoder(),
	}
	// command: ver=1, cmd=1(connect), idLen=0, hostLen, host, port BE, data
	cmd := make([]byte, 0, 6+len(host)+len(initial))
	cmd = append(cmd, 1, 1, 0, byte(len(host)))
	cmd = append(cmd, host...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	cmd = append(cmd, pb[:]...)
	cmd = append(cmd, initial...)
	enc, err := cc.send.EncodeChunk(cmd)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(enc); err != nil {
		return nil, err
	}
	return cc, nil
}

func (c *Client) newEncoder() chunkEncoder {
	snd := NewSender(c.PSK, c.ChaCha)
	snd.Mode = c.Mode
	return snd
}

func (c *Client) newDecoder() chunkDecoder {
	r := NewReceiver(c.PSK)
	r.Mode = c.Mode
	return r
}

// clientConn adapts the Snell framing to a net.Conn carrying the relayed stream.
type clientConn struct {
	conn      net.Conn
	br        *bufio.Reader
	send      chunkEncoder
	recv      chunkDecoder
	rbuf      []byte // leftover decoded bytes not yet read
	gotStatus bool   // stripped the server's first-response 0x00 status byte yet
}

func (c *clientConn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		payload, err := c.recv.DecodeChunk(c.br)
		if err != nil {
			return 0, err
		}
		if len(payload) == 0 {
			return 0, io.EOF // zero-length chunk == server half-close
		}
		if !c.gotStatus {
			// First response carries a status byte (sub_3EF60/sub_3F020):
			// 0x00 = OK (data follows), 0x02 = error ([type][len][message]).
			c.gotStatus = true
			if payload[0] == 0x02 {
				msg := ""
				if len(payload) >= 3 {
					n := int(payload[2])
					if 3+n <= len(payload) {
						msg = string(payload[3 : 3+n])
					}
				}
				return 0, fmt.Errorf("snellv6: server error: %s", msg)
			}
			payload = payload[1:] // strip the 0x00 OK status byte
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

// CloseWrite signals EOF to the server with a zero-length chunk (the snell
// half-close marker), without tearing down the read direction.
func (c *clientConn) CloseWrite() error {
	zero, err := c.send.EncodeChunk(nil)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(zero)
	return err
}

func (c *clientConn) Write(p []byte) (int, error) {
	// EncodeChunk shapes/splits arbitrary-length writes internally (sub_3B990).
	enc, err := c.send.EncodeChunk(p)
	if err != nil {
		return 0, err
	}
	if _, err := c.conn.Write(enc); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *clientConn) Close() error                      { return c.conn.Close() }
func (c *clientConn) LocalAddr() net.Addr               { return c.conn.LocalAddr() }
func (c *clientConn) RemoteAddr() net.Addr              { return c.conn.RemoteAddr() }
func (c *clientConn) SetDeadline(t time.Time) error     { return c.conn.SetDeadline(t) }
func (c *clientConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }
func (c *clientConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
