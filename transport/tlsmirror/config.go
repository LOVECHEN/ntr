package tlsmirror

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// RecommendedExplicitNonceCipherSuites 是 TLS1.2 显式 nonce 载体的推荐 GCM 套件列表(与 mihomo/v2ray 一致):
// 观察到 ServerHello 选中其中之一即判定载体为 TLS1.2 显式 nonce 模式(隐蔽记录前置 8B 显式 nonce 伪装)。
var RecommendedExplicitNonceCipherSuites = []uint16{
	156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171,
	172, 173, 49195, 49196, 49197, 49198, 49199, 49200, 49201, 49202, 49290,
	49291, 49293, 49316, 49317, 49318, 49319, 49320, 49321, 49322, 49323,
	49324, 49325, 49326, 49327, 52392, 52393, 52394, 52395, 52396, 52397,
	52398,
}

// ClientConfig 是 tlsmirror 客户端参数。ServerName 是【载体真 TLS 握手】的 SNI(= 被镜像的真后端域名);
// PrimaryKey 是两端共享的 32B 隐蔽密钥(标准 base64)。
type ClientConfig struct {
	PrimaryKey                string
	ServerName                string
	SkipCertVerify            bool
	ALPN                      []string
	Padding                   bool     // 传输层填充(两端须一致)
	Watermark                 bool     // 序列水印(两端须一致)
	ExplicitNonceCipherSuites []uint16 // 非空 → 识别 TLS1.2 显式 nonce 套件
	CarrierTLS12              bool     // 客户端把载体握手钉到 TLS1.2 + AES-128-GCM(启用显式 nonce 路径)
}

// ServerConfig 是 tlsmirror 服务端参数(Dest/后端由 NTR 传输层单独持有并逐连接拨号)。
type ServerConfig struct {
	PrimaryKey                string
	Padding                   bool
	Watermark                 bool
	ExplicitNonceCipherSuites []uint16
}

// GeneratePrimaryKey 生成一枚随机 32B 主密钥(标准 base64),与 mihomo/v2ray 同格式。
func GeneratePrimaryKey() string {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

// DecodePrimaryKey 解主密钥:必须标准 base64 且解码为 32 字节。
func DecodePrimaryKey(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("tlsmirror: missing primary key")
	}
	key, err := base64.StdEncoding.DecodeString(value)
	if err == nil && len(key) == 32 {
		return key, nil
	}
	return nil, errors.New("tlsmirror: primary key must be standard base64 and decode to 32 bytes")
}
