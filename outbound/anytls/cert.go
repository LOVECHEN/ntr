package anytls

import (
	cryptotls "crypto/tls"

	"github.com/LOVECHEN/ntr/internal/selfcert"
)

// ServerTLSConfig 造 AnyTLS 服务端的 *tls.Config:给了 cert/key PEM 就用,否则自签临时证书(dev)。
func ServerTLSConfig(certPEM, keyPEM string) (*cryptotls.Config, error) {
	return selfcert.Std(certPEM, keyPEM)
}
