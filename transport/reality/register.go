package reality

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
	xreality "github.com/xtls/reality"

	"github.com/LOVECHEN/ntr/core/cap"
	"github.com/LOVECHEN/ntr/core/registry"
	"github.com/LOVECHEN/ntr/core/spec"
)

// Config 是 REALITY 层自有配置。服务端给 private-key + dest(+ server-name);
// 客户端给 public-key + server-name(+ short-id / fingerprint)。
type Config struct {
	PrivateKey []byte // 服务端 x25519 私钥(32)
	PublicKey  []byte // 客户端:服务端 x25519 公钥(32)
	ShortID    [8]byte
	ServerName string
	Dest       string // 服务端:借证书/回落的真实站 host:port
	Fingerprint string
}

// Parse 从哑节点解出 Config(密钥 base64/hex 自适应,short-id hex 右补零)。
func Parse(n *spec.Node) (Config, error) {
	var c Config
	if s := n.Get("private-key").Str(); s != "" {
		k, err := decodeKey(s)
		if err != nil {
			return c, fmt.Errorf("reality: private-key 解码失败:%w", err)
		}
		c.PrivateKey = k
	}
	if s := n.Get("public-key").Str(); s != "" {
		k, err := decodeKey(s)
		if err != nil {
			return c, fmt.Errorf("reality: public-key 解码失败:%w", err)
		}
		c.PublicKey = k
	}
	if s := n.Get("short-id").Str(); s != "" {
		b, err := hex.DecodeString(s)
		if err != nil {
			return c, fmt.Errorf("reality: short-id 需 hex:%w", err)
		}
		if len(b) > 8 {
			return c, fmt.Errorf("reality: short-id 超过 8 字节")
		}
		copy(c.ShortID[:], b) // 右补零
	}
	// server-name 是 REALITY 惯用键;同时接受 sni 别名(与 tls 层一致),防"写成 sni 被静默忽略"的坑。
	c.ServerName = n.Get("server-name").Str()
	if c.ServerName == "" {
		c.ServerName = n.Get("sni").Str()
	}
	c.Dest = n.Get("dest").Str()
	c.Fingerprint = n.Get("fingerprint").Str()
	return c, nil
}

// Build 构造 Transport:按配置分别装配服务端 reality.Config 与客户端认证参数。
func Build(_ context.Context, cfg Config, _ any) (any, error) {
	t := &Transport{
		pubKey:      cfg.PublicKey,
		shortID:     cfg.ShortID,
		serverName:  cfg.ServerName,
		fingerprint: fingerprintOf(cfg.Fingerprint),
	}
	if len(cfg.PrivateKey) == 32 && cfg.Dest != "" {
		sn := cfg.ServerName
		t.server = &xreality.Config{
			DialContext:            (&net.Dialer{}).DialContext,
			Type:                   "tcp",
			Dest:                   cfg.Dest,
			ServerNames:            map[string]bool{sn: true},
			PrivateKey:             cfg.PrivateKey,
			ShortIds:               map[[8]byte]bool{cfg.ShortID: true},
			SessionTicketsDisabled: true, // 免服务端生成 NST(否则要按 dest 的 NST 长度填充,dest 无 NST 则负 padding)
		}
		// 预探 dest 的 post-handshake 记录长度(填充抗观测所需);NewListener 内部也这么做,
		// 我们直连 Server 需自行触发,否则握手后 padding 循环会一直等这份数据。
		go xreality.DetectPostHandshakeRecordsLens(t.server)
	}
	if t.server == nil {
		// 非服务端 → 应是客户端:public-key 与 server-name/sni 都必须齐(否则握手期才报、且被静默吞,
		// 极难查 —— 第9轮就栽在 server-name 写成 sni 上)。在此 Build/启动期就大声报。
		if len(cfg.PublicKey) != 32 {
			return nil, fmt.Errorf("reality: 配置既非服务端(缺 private-key/dest)也非客户端(缺 public-key)")
		}
		if cfg.ServerName == "" {
			return nil, fmt.Errorf("reality: 客户端缺 server-name(或 sni)—— 借用站域名,必填")
		}
	}
	return t, nil
}

// decodeKey 依次尝试 base64(url/std)与 hex,得到 32 字节密钥。
func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, dec := range []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("非 32 字节的 base64/hex 密钥")
}

// fingerprintOf 把配置名映射到 uTLS 指纹(默认 Chrome)。
func fingerprintOf(name string) utls.ClientHelloID {
	switch strings.ToLower(name) {
	case "chrome", "":
		return utls.HelloChrome_Auto
	case "chrome-120":
		return utls.HelloChrome_120
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "edge":
		return utls.HelloEdge_Auto
	default:
		return utls.HelloChrome_Auto
	}
}

// 注册 REALITY 传输层(Band=Crypto)—— manifest 一行 blank-import 即链接进来。
func init() {
	registry.Register(registry.Descriptor[Config]{
		Name:     "reality",
		Display:  "REALITY",
		Band:     registry.BandCrypto,
		In:       []registry.Sort{registry.SortStream},
		Out:      registry.SortStream,
		Provides: []cap.ID{cap.IDSecureCarrier}, // REALITY 提供 TLS 级机密性(可载 vless / trojan)
		Reload:   registry.ReloadDrain,
		Parse:    Parse,
		Build:    Build,
	})
}
