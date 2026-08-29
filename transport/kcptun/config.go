// Package kcptun 自写实现 kcptun 传输 —— xtaci/kcptun 的 KCP(+Reed-Solomon FEC)+ 可选 block 加密 + 可选
// snappy 压缩 + smux 多路复用隧道(mihomo 作 shadowsocks 的 plugin: kcptun 暴露,client+server 两端俱全)。
// 线格式逐字节承 mihomo transport/kcptun(其本身 copy 自 xtaci/kcptun),复用同版本 metacubex/kcp-go、
// metacubex/smux、golang/snappy → 与 mihomo 直接互通。是 BaseTransport(UDP→KCP→smux,每 OpenStream 产一
// 条 link.Stream),惯用叠法 [kcptun, shadowsocks]。
//
// 线格式(禁改,承 xtaci/kcptun / mihomo):
//   - UDP 之上跑 metacubex/kcp-go 的 KCP(convid 随机,dataShard/parityShard 的 RS-FEC);block 加密 =
//     pbkdf2(key, "kcp-go", 4096, 32, sha1) 派生密钥喂对应 BlockCrypt(默认 aes=AES-256)。
//   - KCP 之上(可选)snappy 压缩流,再之上 smux 多路复用;每条代理连接 = 一条 smux stream。
//   - 两端 key/crypt/datashard/parityshard/mode(nodelay/interval/resend/nc)/mtu/窗口/smuxver/nocomp 须一致。
package kcptun

import (
	"crypto/sha1"

	"github.com/metacubex/kcp-go"
	"golang.org/x/crypto/pbkdf2"
)

// SALT 是 pbkdf2 密钥扩展盐(承 kcptun)。maxSmuxVer 支持到 smux v2。
const (
	SALT       = "kcp-go"
	maxSmuxVer = 2
)

// Config 是 kcptun 参数(字段名/默认值/mode 映射与 mihomo/xtaci-kcptun 完全一致)。
type Config struct {
	Key          string
	Crypt        string
	Mode         string
	Conn         int
	MTU          int
	RateLimit    int
	SndWnd       int
	RcvWnd       int
	DataShard    int
	ParityShard  int
	DSCP         int
	NoComp       bool
	AckNodelay   bool
	NoDelay      int
	Interval     int
	Resend       int
	NoCongestion int
	SockBuf      int
	SmuxVer      int
	SmuxBuf      int
	FrameSize    int
	StreamBuf    int
	KeepAlive    int
}

// FillDefaults 补齐缺省(逐字节对齐 mihomo/xtaci-kcptun,含 mode→KCP 参数映射)。
func (config *Config) FillDefaults() {
	if config.Key == "" {
		config.Key = "it's a secrect"
	}
	if config.Crypt == "" {
		config.Crypt = "aes"
	}
	if config.Mode == "" {
		config.Mode = "fast"
	}
	if config.Conn == 0 {
		config.Conn = 1
	}
	if config.MTU == 0 {
		config.MTU = 1350
	}
	if config.SndWnd == 0 {
		config.SndWnd = 128
	}
	if config.RcvWnd == 0 {
		config.RcvWnd = 512
	}
	if config.DataShard == 0 {
		config.DataShard = 10
	}
	if config.ParityShard == 0 {
		config.ParityShard = 3
	}
	if config.Interval == 0 {
		config.Interval = 50
	}
	if config.SockBuf == 0 {
		config.SockBuf = 4194304
	}
	if config.SmuxVer == 0 {
		config.SmuxVer = 1
	}
	if config.SmuxBuf == 0 {
		config.SmuxBuf = 4194304
	}
	if config.FrameSize == 0 {
		config.FrameSize = 8192
	}
	if config.StreamBuf == 0 {
		config.StreamBuf = 2097152
	}
	if config.KeepAlive == 0 {
		config.KeepAlive = 10
	}
	switch config.Mode {
	case "normal":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
	case "fast":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
	case "fast2":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
	case "fast3":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
	}
	if config.SmuxVer > maxSmuxVer {
		config.SmuxVer = maxSmuxVer
	}
}

// NewBlock 从 key 派生 kcp-go 的 BlockCrypt(pbkdf2→对应密码算法;默认 aes=AES-256),禁改 —— 与 mihomo 一致。
func (config *Config) NewBlock() (block kcp.BlockCrypt) {
	pass := pbkdf2.Key([]byte(config.Key), []byte(SALT), 4096, 32, sha1.New)
	switch config.Crypt {
	case "null":
		block = nil
	case "tea":
		block, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		block, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		block, _ = kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		block, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		block, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		block, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		block, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		block, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		block, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		block, _ = kcp.NewSalsa20BlockCrypt(pass)
	case "aes-128-gcm":
		block, _ = kcp.NewAESGCMCrypt(pass[:16])
	default:
		config.Crypt = "aes"
		block, _ = kcp.NewAESBlockCrypt(pass)
	}
	return
}
