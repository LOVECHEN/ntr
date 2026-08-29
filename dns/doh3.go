package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	mhttp "github.com/metacubex/http"
	mquic "github.com/metacubex/quic-go"
	h3 "github.com/metacubex/quic-go/http3"
	mtls "github.com/metacubex/tls"
)

// queryDoH3 做 DNS-over-HTTP/3:RFC 8484 的 DoH wire(POST application/dns-message)跑在 HTTP/3 之上。
// wire 与 DoH 完全一致、只换承载(禁改线格式:与 queryDoH 是两条独立路径,DoH3 走 HTTP/3、DoH 走 HTTP/1.1)。
// QUIC 经 detour 出站的 UDP(pktConnAdapter,与 DoQ 复用),防泄漏;每查询即用即关。
// ★请求必须用 metacubex/http:h3.Transport.RoundTrip 收的是其 *Request,误用 stdlib net/http 编译不过。
func (u *upstream) queryDoH3(ctx context.Context, raw []byte) ([]byte, error) {
	tr := &h3.Transport{
		TLSClientConfig: &mtls.Config{ServerName: u.sni, InsecureSkipVerify: u.insecure, MinVersion: mtls.VersionTLS13},
		QUICConfig:      &mquic.Config{MaxIdleTimeout: 30 * time.Second},
		Dial: func(ctx context.Context, _ string, tlsCfg *mtls.Config, cfg *mquic.Config) (*mquic.Conn, error) {
			pc, err := u.detour.DialPacket(ctx, u.dst)
			if err != nil {
				return nil, err
			}
			npc := &pktConnAdapter{pc: pc, dst: u.dst, remote: udpAddrOf(u.dst)}
			return mquic.DialEarly(ctx, npc, npc.remote, tlsCfg, cfg)
		},
	}
	defer tr.Close()
	req, err := mhttp.NewRequestWithContext(ctx, mhttp.MethodPost, u.dohURL, bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("dns[%s]: DoH3 建请求:%w", u.tag, err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("dns[%s]: DoH3 请求:%w", u.tag, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != mhttp.StatusOK {
		return nil, fmt.Errorf("dns[%s]: DoH3 状态 %d", u.tag, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}
