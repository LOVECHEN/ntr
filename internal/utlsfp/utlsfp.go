// Package utlsfp 提供 uTLS 客户端指纹伪装的共享入口。
//
// 用途:让走 TLS 的会话式协议出站(naive / trusttunnel 等)能把 ClientHello 伪装成
// 真实浏览器,使 JA3/JA4 指纹与真 Chrome/Firefox/Safari 一致 —— 否则纯 Go 的
// crypto/tls 会留下"这是 Go 程序"的指纹,被 DPI 一眼认出。
//
// 放在 internal/ 而非 transport/:门禁规定 outbound/ 的非测试源码零 import transport/*,
// 故指纹映射不能复用 transport/reality 里那份,提到此处共享。
package utlsfp

import (
	"context"
	cryptotls "crypto/tls"
	"net"

	utls "github.com/refraction-networking/utls"
)

// Parse 把配置里的指纹名映射到 uTLS ClientHelloID。
// 返回 ok=false 表示未配置(应走标准 crypto/tls,不做伪装)。
func Parse(name string) (utls.ClientHelloID, bool) {
	switch name {
	case "":
		return utls.ClientHelloID{}, false
	case "chrome":
		return utls.HelloChrome_Auto, true
	case "chrome_120":
		return utls.HelloChrome_120, true
	case "firefox":
		return utls.HelloFirefox_Auto, true
	case "safari":
		return utls.HelloSafari_Auto, true
	case "ios":
		return utls.HelloIOS_Auto, true
	case "edge":
		return utls.HelloEdge_Auto, true
	case "random", "randomized":
		return utls.HelloRandomized, true
	default:
		return utls.HelloChrome_Auto, true // 未知名字回落 Chrome,不静默禁用伪装
	}
}

// Client 在 conn 上以指定指纹完成 uTLS 客户端握手,返回已握手的连接。
// cfg 的 ServerName / InsecureSkipVerify / NextProtos / MinVersion 会被透传。
func Client(ctx context.Context, conn net.Conn, cfg *cryptotls.Config, id utls.ClientHelloID) (net.Conn, error) {
	uc := &utls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		NextProtos:         cfg.NextProtos,
		MinVersion:         cfg.MinVersion,
		RootCAs:            cfg.RootCAs,
	}
	u := utls.UClient(conn, uc, id)
	if err := u.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return u, nil
}

// Dial 是便捷入口:fingerprint 为空则走标准 crypto/tls,否则用 uTLS 指纹伪装。
// 两条路都返回已完成握手的连接,调用方无需分支。
func Dial(ctx context.Context, conn net.Conn, cfg *cryptotls.Config, fingerprint string) (net.Conn, error) {
	if id, ok := Parse(fingerprint); ok {
		return Client(ctx, conn, cfg, id)
	}
	tc := cryptotls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tc, nil
}
