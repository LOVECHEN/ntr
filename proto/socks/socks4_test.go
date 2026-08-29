package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/endpoint"
)

// buildSocks4Req 造一条 SOCKS4/4a 请求。domain 非空 = SOCKS4a(DSTIP 置 0.0.0.1)。
func buildSocks4Req(port uint16, ip [4]byte, userID, domain string) []byte {
	var b bytes.Buffer
	b.WriteByte(version4)
	b.WriteByte(cmd4Connect)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	b.Write(p[:])
	if domain != "" {
		b.Write([]byte{0, 0, 0, 1}) // SOCKS4a 标记
	} else {
		b.Write(ip[:])
	}
	b.WriteString(userID)
	b.WriteByte(0)
	if domain != "" {
		b.WriteString(domain)
		b.WriteByte(0)
	}
	return b.Bytes()
}

// runSocks4 把请求喂给服务端握手,返回解析出的目标与应答字节。
func runSocks4(t *testing.T, req []byte, payload []byte) (dstStr string, reply []byte, gotPayload []byte) {
	t.Helper()
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	p := &Proxy{}
	type res struct {
		dst string
		st  io.Reader
		err error
	}
	done := make(chan res, 1)
	go func() {
		st, rq, err := p.ServerHandshake(context.Background(), pipeStream{srv}, authStub{})
		if err != nil {
			done <- res{err: err}
			return
		}
		if rq.Network != endpoint.NetworkTCP {
			done <- res{err: errNotTCP}
			return
		}
		done <- res{dst: rq.Dst.String(), st: st}
	}()

	go func() {
		_, _ = cli.Write(req)
		if len(payload) > 0 {
			_, _ = cli.Write(payload)
		}
	}()

	reply = make([]byte, 8)
	if _, err := io.ReadFull(cli, reply); err != nil {
		t.Fatalf("读应答失败:%v", err)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("握手失败:%v", r.err)
	}
	if len(payload) > 0 {
		gotPayload = make([]byte, len(payload))
		if _, err := io.ReadFull(r.st, gotPayload); err != nil {
			t.Fatalf("读 payload 失败:%v", err)
		}
	}
	return r.dst, reply, gotPayload
}

var errNotTCP = io.ErrUnexpectedEOF

type authStub struct{}

func (authStub) Auth(string, []byte) (cred.Ref, bool) { return cred.Ref{}, false }

// TestSocks4Connect:SOCKS4 直连 IP 目标。
func TestSocks4Connect(t *testing.T) {
	req := buildSocks4Req(8080, [4]byte{93, 184, 216, 34}, "nobody", "")
	dst, reply, _ := runSocks4(t, req, nil)
	if dst != "93.184.216.34:8080" {
		t.Fatalf("目标解析错:%s", dst)
	}
	if reply[0] != 0x00 || reply[1] != rep4Granted {
		t.Fatalf("应答应为 VN=0x00 CD=0x5A,得到 %#x %#x", reply[0], reply[1])
	}
	if binary.BigEndian.Uint16(reply[2:4]) != 8080 {
		t.Errorf("应答应回显端口 8080,得到 %d", binary.BigEndian.Uint16(reply[2:4]))
	}
}

// TestSocks4aDomain:SOCKS4a 用 0.0.0.x 标记 + 域名。
func TestSocks4aDomain(t *testing.T) {
	req := buildSocks4Req(443, [4]byte{}, "u", "example.com")
	dst, reply, _ := runSocks4(t, req, nil)
	if dst != "example.com:443" {
		t.Fatalf("SOCKS4a 域名解析错:%s", dst)
	}
	if reply[1] != rep4Granted {
		t.Fatalf("应答应为 granted,得到 %#x", reply[1])
	}
}

// TestSocks4PayloadPreserved:握手期 bufio 预读的 payload 首段不得丢失。
func TestSocks4PayloadPreserved(t *testing.T) {
	req := buildSocks4Req(80, [4]byte{1, 2, 3, 4}, "user", "")
	payload := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	dst, _, got := runSocks4(t, req, payload)
	if dst != "1.2.3.4:80" {
		t.Fatalf("目标错:%s", dst)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload 丢失或错位:%q != %q", got, payload)
	}
}

// TestSocks4EmptyUserID:USERID 为空(仅一个 NUL)也应正常。
func TestSocks4EmptyUserID(t *testing.T) {
	req := buildSocks4Req(1080, [4]byte{10, 0, 0, 1}, "", "")
	dst, reply, _ := runSocks4(t, req, nil)
	if dst != "10.0.0.1:1080" || reply[1] != rep4Granted {
		t.Fatalf("空 USERID 应正常:dst=%s rep=%#x", dst, reply[1])
	}
}

// TestSocks4BindRejected:BIND(CD=0x02)未支持,应回 0x5B 拒绝。
func TestSocks4BindRejected(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	p := &Proxy{}
	go func() { _, _, _ = p.ServerHandshake(context.Background(), pipeStream{srv}, authStub{}) }()
	go func() {
		var b bytes.Buffer
		b.WriteByte(version4)
		b.WriteByte(0x02) // BIND
		b.Write([]byte{0x00, 0x50, 1, 2, 3, 4})
		b.WriteByte(0) // 空 USERID
		_, _ = cli.Write(b.Bytes())
	}()
	reply := make([]byte, 8)
	if _, err := io.ReadFull(cli, reply); err != nil {
		t.Fatalf("读应答失败:%v", err)
	}
	if reply[1] != rep4Rejected {
		t.Fatalf("BIND 应被拒(0x5B),得到 %#x", reply[1])
	}
}

// TestSocks5StillWorks:加了 v4 分派后,SOCKS5 线格式必须完全不受影响。
func TestSocks5StillWorks(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	p := &Proxy{}
	done := make(chan string, 1)
	go func() {
		_, rq, err := p.ServerHandshake(context.Background(), pipeStream{srv}, authStub{})
		if err != nil {
			done <- "ERR:" + err.Error()
			return
		}
		done <- rq.Dst.String()
	}()
	go func() {
		_, _ = cli.Write([]byte{0x05, 0x01, 0x00}) // 问候:VER NMETHODS NOAUTH
		hdr := make([]byte, 2)
		_, _ = io.ReadFull(cli, hdr)                     // 方法选择应答
		_, _ = cli.Write([]byte{0x05, 0x01, 0x00, 0x01}) // CONNECT + IPv4
		_, _ = cli.Write([]byte{93, 184, 216, 34, 0x01, 0xBB})
		// net.Pipe 是同步的:必须在此处把服务端的 10 字节应答读掉,
		// 否则服务端阻塞在 Write、done 永远不来 → 死锁。
		_, _ = io.ReadFull(cli, make([]byte, 10))
	}()
	got := <-done
	if got != "93.184.216.34:443" {
		t.Fatalf("SOCKS5 应仍正常,得到 %s", got)
	}
}
