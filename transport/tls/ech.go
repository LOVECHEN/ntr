package tls

// ECH(Encrypted Client Hello):把 ClientHello 的敏感部分(尤其 SNI)用服务端公钥 HPKE 加密,
// 外层只暴露一个公开名(public-name)—— 抗基于 SNI 的审查。格式与 sing-box 逐字节兼容
// (PEM "ECH CONFIGS" 给客户端、"ECH KEYS" 给服务端;keyBytes = [u16 私钥][u16 ECHConfig]),
// 故可与 sing-box 交叉验证。keygen/marshal 移植自 sing-box common/tls/ech_shared.go(仅 crypto/ecdh + cryptobyte)。

import (
	"crypto/ecdh"
	"crypto/rand"
	cryptotls "crypto/tls"
	"encoding/pem"
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

// parseECHConfigs 解 "ECH CONFIGS" PEM → ECHConfigList 字节(客户端 EncryptedClientHelloConfigList)。
func parseECHConfigs(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "ECH CONFIGS" {
		return nil, errors.New("tls: 无效 ECH CONFIGS pem(需 -----BEGIN ECH CONFIGS-----)")
	}
	return block.Bytes, nil
}

// parseECHKeys 解 "ECH KEYS" PEM → []EncryptedClientHelloKey(服务端);keyBytes = 若干 [u16 私钥][u16 ECHConfig]。
func parseECHKeys(pemBytes []byte) ([]cryptotls.EncryptedClientHelloKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "ECH KEYS" {
		return nil, errors.New("tls: 无效 ECH KEYS pem(需 -----BEGIN ECH KEYS-----)")
	}
	var keys []cryptotls.EncryptedClientHelloKey
	s := cryptobyte.String(block.Bytes)
	for !s.Empty() {
		var priv, cfg cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&priv) || !s.ReadUint16LengthPrefixed(&cfg) {
			return nil, errors.New("tls: ECH KEYS 格式错")
		}
		keys = append(keys, cryptotls.EncryptedClientHelloKey{Config: []byte(cfg), PrivateKey: []byte(priv)})
	}
	if len(keys) == 0 {
		return nil, errors.New("tls: ECH KEYS 空")
	}
	return keys, nil
}

// ECHKeygen 生成一对 ECH 密钥:configPem 给客户端(ech-config)、keyPem 给服务端(ech-key)。
// 与 sing-box `generate ech-keypair` 逐字节兼容。publicName = 外层暴露的公开域名(如 public.example)。
func ECHKeygen(publicName string) (configPem, keyPem string, err error) {
	echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	echConfig, err := marshalECHConfig(0, echKey.PublicKey().Bytes(), publicName, 0)
	if err != nil {
		return
	}
	cb := cryptobyte.NewBuilder(nil)
	cb.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(echConfig) })
	configBytes, err := cb.Bytes()
	if err != nil {
		return
	}
	kb := cryptobyte.NewBuilder(nil)
	kb.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(echKey.Bytes()) })
	kb.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(echConfig) })
	keyBytes, err := kb.Bytes()
	if err != nil {
		return
	}
	configPem = string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: configBytes}))
	keyPem = string(pem.EncodeToMemory(&pem.Block{Type: "ECH KEYS", Bytes: keyBytes}))
	return
}

func marshalECHConfig(id uint8, pubKey []byte, publicName string, maxNameLen uint8) ([]byte, error) {
	const extensionEncryptedClientHello = 0xfe0d
	const dhkemX25519HKDFSHA256 = 0x0020
	const kdfHKDFSHA256 = 0x0001
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(extensionEncryptedClientHello)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(id)
		b.AddUint16(dhkemX25519HKDFSHA256)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(pubKey) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			const (
				aeadAES128GCM = 0x0001
				aeadAES256GCM = 0x0002
				aeadChaCha20P = 0x0003
			)
			for _, aeadID := range []uint16{aeadAES128GCM, aeadAES256GCM, aeadChaCha20P} {
				b.AddUint16(kdfHKDFSHA256)
				b.AddUint16(aeadID)
			}
		})
		b.AddUint8(maxNameLen)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(publicName)) })
		b.AddUint16(0) // extensions
	})
	return b.Bytes()
}
