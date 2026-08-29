package reality

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// TestRealityInterop:NTR 的 uTLS REALITY 客户端 ↔ 参考实现 reality.Server 端到端全握手 +
// 双向数据。跑通即证明客户端认证注入【字节精确】且与真实 Xray/sing-box REALITY 互通。
//
// REALITY 本质依赖【真实网站】作 dest(借其证书 + 按其记录长度填充抗观测;合成站证书过小会
// 负 padding),故本测试需外网,默认跳过。按需运行:
//
//	NTR_REALITY_E2E=1 [NTR_REALITY_DEST=www.apple.com] go test ./transport/reality/ -run Interop -v
func TestRealityInterop(t *testing.T) {
	if os.Getenv("NTR_REALITY_E2E") == "" {
		t.Skip("需真实网站作 dest;设 NTR_REALITY_E2E=1 运行")
	}
	host := os.Getenv("NTR_REALITY_DEST")
	if host == "" {
		host = "www.apple.com"
	}
	// dest 可达性预检:不可达则跳过而非失败(避免离线误报)。
	if c, err := net.DialTimeout("tcp", host+":443", 5*time.Second); err != nil {
		t.Skipf("dest %s 不可达:%v", host, err)
	} else {
		_ = c.Close()
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	ctx := context.Background()

	serverT, err := Build(ctx, Config{PrivateKey: priv.Bytes(), Dest: host + ":443", ServerName: host}, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientT, err := Build(ctx, Config{PublicKey: pub, ServerName: host, Fingerprint: "chrome"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := serverT.(*Transport)
	ct := clientT.(*Transport)
	time.Sleep(2 * time.Second) // 等 DetectPostHandshakeRecordsLens 探完 dest

	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvLn.Close()

	srvErr := make(chan error, 1)
	go func() {
		conn, err := srvLn.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		s, err := st.ServerWrap(ctx, rawStream{conn}) // 只对通过 x25519 鉴权的连接成功
		if err != nil {
			srvErr <- err
			return
		}
		b := make([]byte, 5)
		if _, err := io.ReadFull(s, b); err != nil {
			srvErr <- err
			return
		}
		_, err = s.Write(b)
		srvErr <- err
	}()

	raw, err := net.Dial("tcp", srvLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))

	cs, err := ct.ClientWrap(ctx, rawStream{raw})
	if err != nil {
		t.Fatalf("REALITY 客户端握手失败:%v", err)
	}
	if _, err := cs.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(cs, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("echo mismatch: %q", got)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("服务端(鉴权应成功):%v", err)
	}
}

// rawStream 把 net.Conn 抬成 link.Stream,Unwrap 返回底层供 reality baseConn 探到 *net.TCPConn。
type rawStream struct{ net.Conn }

func (r rawStream) Unwrap() any { return r.Conn }

// TestClientMissingServerNameLoud:客户端配置(有 public-key,无 server-name/sni)应在 Build 期
// 大声报错,而非拖到握手期被静默吞(第9轮血泪:server-name 写成 sni 曾误判成协议 bug)。
func TestClientMissingServerNameLoud(t *testing.T) {
	pub := make([]byte, 32)
	if _, err := Build(context.Background(), Config{PublicKey: pub /* 无 ServerName */}, nil); err == nil {
		t.Fatal("客户端缺 server-name 应在 Build 期报错")
	}
	// 补上 server-name 即应成功
	if _, err := Build(context.Background(), Config{PublicKey: pub, ServerName: "www.example.com"}, nil); err != nil {
		t.Fatalf("补齐 server-name 后不应报错:%v", err)
	}
}
