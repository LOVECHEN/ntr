package juicity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
)

// 黄金向量:按官方实现(daeuniverse/outbound trojanc.Metadata.PackTo + juicity SealUDP)的字节布局手算。
func TestGoldenVectors(t *testing.T) {
	cases := []struct {
		name string
		got  func() ([]byte, error)
		want string
	}{
		{"tcp 头 IPv4", func() ([]byte, error) {
			return appendStreamHeader(nil, networkTCP, addr.FromIPPort(netip.MustParseAddrPort("1.2.3.4:80")))
		}, "01" + "01" + "01020304" + "0050"},
		{"tcp 头 域名", func() ([]byte, error) {
			return appendStreamHeader(nil, networkTCP, addr.FromFqdn("example.com", 443))
		}, "01" + "03" + "0b" + hex.EncodeToString([]byte("example.com")) + "01bb"},
		{"udp 头 IPv6", func() ([]byte, error) {
			return appendStreamHeader(nil, networkUDP, addr.FromIPPort(netip.MustParseAddrPort("[::1]:53")))
		}, "03" + "04" + "00000000000000000000000000000001" + "0035"},
		{"udp 帧", func() ([]byte, error) {
			return appendUDPFrame(nil, addr.FromIPPort(netip.MustParseAddrPort("8.8.8.8:53")), []byte("ab"))
		}, "01" + "08080808" + "0035" + "0002" + "6162"},
		{"v4-mapped 按 IPv4 编", func() ([]byte, error) {
			return appendAddr(nil, addr.FromIPPort(netip.MustParseAddrPort("[::ffff:10.0.0.1]:1")))
		}, "01" + "0a000001" + "0001"},
	}
	for _, c := range cases {
		b, err := c.got()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if g := hex.EncodeToString(b); g != c.want {
			t.Errorf("%s:\n got  %s\n want %s", c.name, g, c.want)
		}
	}
}

func TestAuthLayout(t *testing.T) {
	var uuid [16]byte
	var tok [tokenLen]byte
	for i := range uuid {
		uuid[i] = byte(i + 1)
	}
	for i := range tok {
		tok[i] = byte(0xa0 + i)
	}
	b := appendAuth(nil, uuid, tok)
	if len(b) != authLen || b[0] != 0x00 || b[1] != 0x00 {
		t.Fatalf("鉴权布局错: len=%d head=% x", len(b), b[:2])
	}
	if !bytes.Equal(b[2:18], uuid[:]) || !bytes.Equal(b[18:], tok[:]) {
		t.Fatal("uuid/token 位置错")
	}
	gu, gt, err := readAuth(bytes.NewReader(b))
	if err != nil || gu != uuid || gt != tok {
		t.Fatalf("readAuth 往返失败: %v", err)
	}
	bad := append([]byte(nil), b...)
	bad[0] = 5 // TUIC v5 的版本字节 —— juicity 必须拒
	if _, _, err := readAuth(bytes.NewReader(bad)); !errors.Is(err, errBadVersion) {
		t.Fatalf("应拒非 0 版本: %v", err)
	}
}

func TestAddrRoundTrip(t *testing.T) {
	for _, a := range []addr.Socksaddr{
		addr.FromIPPort(netip.MustParseAddrPort("192.168.1.1:65535")),
		addr.FromIPPort(netip.MustParseAddrPort("[2001:db8::1]:8443")),
		addr.FromFqdn("a.b.c.example", 1),
	} {
		b, err := appendAddr(nil, a)
		if err != nil {
			t.Fatal(err)
		}
		g, err := readAddr(bytes.NewReader(b))
		if err != nil || g != a {
			t.Fatalf("往返失败: %v -> %v (%v)", a, g, err)
		}
	}
	if _, err := readAddr(bytes.NewReader([]byte{0x02, 0, 0})); !errors.Is(err, errBadAddr) {
		t.Fatalf("应拒未知 atyp: %v", err)
	}
	if _, _, err := readStreamHeader(bytes.NewReader([]byte{0x02})); !errors.Is(err, errBadNetwork) {
		t.Fatalf("应拒未知 network: %v", err)
	}
}

// 负载超出读缓冲时截断并丢余下部分,下一帧边界不错位。
func TestUDPFrameTruncateKeepsBoundary(t *testing.T) {
	dst := addr.FromIPPort(netip.MustParseAddrPort("1.1.1.1:53"))
	var stream []byte
	stream, _ = appendUDPFrame(stream, dst, []byte("0123456789"))
	stream, _ = appendUDPFrame(stream, dst, []byte("next"))
	r := bytes.NewReader(stream)
	p := make([]byte, 4)
	a, n, err := readUDPFrame(r, p)
	if err != nil || a != dst || n != 4 || string(p[:n]) != "0123" {
		t.Fatalf("截断帧: a=%v n=%d p=%q err=%v", a, n, p[:n], err)
	}
	p = make([]byte, 64)
	_, n, err = readUDPFrame(r, p)
	if err != nil || string(p[:n]) != "next" {
		t.Fatalf("下一帧错位: %q err=%v", p[:n], err)
	}
}

// token:真实 TLS 1.3 握手后,客户端 genToken 与服务端按同参数导出的值一致。
func TestTokenMatchesBothSides(t *testing.T) {
	cert := selfSigned(t)
	cConn, sConn := net.Pipe()
	srv := tls.Server(sConn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}})
	cli := tls.Client(cConn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}})
	errc := make(chan error, 1)
	go func() { errc <- srv.Handshake() }()
	if err := cli.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	uuid := [16]byte{0xde, 0xad, 0xbe, 0xef}
	ct, err := genToken(cli.ConnectionState(), uuid, "pass")
	if err != nil {
		t.Fatal(err)
	}
	st, err := genToken(srv.ConnectionState(), uuid, "pass")
	if err != nil {
		t.Fatal(err)
	}
	if ct != st {
		t.Fatal("两端 token 不一致")
	}
	wt, _ := genToken(srv.ConnectionState(), uuid, "wrong")
	if wt == ct {
		t.Fatal("错误密码竟得到相同 token")
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "juicity-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"juicity-test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}
