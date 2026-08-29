package tlsmirror

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
)

// Dial 在 rawConn(到 tlsmirror 服务端的 TCP)上建立隐蔽隧道:
//  1. net.Pipe 一端跑【真·TLS1.3 客户端握手】(SNI=被镜像的真后端),握手记录经镜像转发到服务端 → 真后端;
//  2. 镜像层把隧道数据封成隐蔽 app-data 记录插进流;
//  3. 握手完成后返回隐蔽 Conn;另起 goroutine 排空载体 app-data(会话票据等)保活读泵。
func Dial(ctx context.Context, rawConn net.Conn, cfg ClientConfig) (*Conn, error) {
	key, err := DecodePrimaryKey(cfg.PrimaryKey)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	serverName := cfg.ServerName
	if serverName == "" && !cfg.SkipCertVerify {
		_ = rawConn.Close()
		return nil, fmt.Errorf("tlsmirror: server-name is required when certificate verification is enabled")
	}

	tlsSide, mirrorSide := net.Pipe()
	lifetimeCtx := context.Background()
	var hidden *Conn
	mirror := newMirrorConn(lifetimeCtx, mirrorSide, rawConn, cfg.ExplicitNonceCipherSuites,
		nil,
		func(rec *record) (bool, error) { return hidden.handleInboundRecord(rec) },
		nil,
		nil,
	)
	hidden = newHiddenConn(lifetimeCtx, mirror, key, false, features{padding: cfg.Padding, watermark: cfg.Watermark})
	mirror.onC2SMessageTx = hidden.handleOutboundRecordTx
	mirror.start()

	tlsConf := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: cfg.SkipCertVerify,
		NextProtos:         cfg.ALPN,
		MinVersion:         tls.VersionTLS13, // 默认 TLS1.3 载体(隐蔽 nonce overhead=0)
	}
	if cfg.CarrierTLS12 {
		// TLS1.2 显式 nonce 载体:钉到 1.2 + AES-128-GCM,让 ServerHello 命中显式 nonce 套件。
		tlsConf.MinVersion = tls.VersionTLS12
		tlsConf.MaxVersion = tls.VersionTLS12
		tlsConf.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	}
	tlsConn := tls.Client(tlsSide, tlsConf)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = hidden.Close()
		return nil, fmt.Errorf("%w: %w", errCarrierHandshake, err)
	}
	// 无嵌入流量生成器(default 配置):仅排空载体读侧,让 TLS1.3 会话票据等被处理,不产生掩护流量。
	go func() { _, _ = io.Copy(io.Discard, tlsConn) }()
	return hidden, nil
}
