package hysteria2

import (
	mtls "github.com/metacubex/tls"

	"github.com/LOVECHEN/ntr/internal/selfcert"
)

// ServerTLSConfig 造 hy2 服务端的 *metacubex-tls.Config:给了 PEM 用之,否则自签临时证书(dev)。
func ServerTLSConfig(certPEM, keyPEM string) (*mtls.Config, error) {
	return selfcert.Metacubex(certPEM, keyPEM)
}
