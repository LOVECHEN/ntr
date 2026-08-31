#!/bin/bash
# ============================================================================
# MASQUE 第三方互通:NTR masque(metacubex/quic-go fork)↔ masque-go(quic-go 官方 fork)
# 证 NTR 的 RFC 9298 connect-udp 线格式【标准】—— 能被独立第三方实现(quic-go/masque-go)
# 理解并互通,不只是 NTR↔NTR 自证。两个独立 quic-go fork 的 http3 + HTTP Datagram 对拍。
#   socksudp.py → NTR client(socks UDP)→ masque connect-udp → masque-go proxy → udpecho
# masque-go proxy 是脚本内联源码 + docker 编译(quic-go 官方 v0.60.0),配 NTR 同款 RFC9298 template。
# 专属 network=ix-mqint;固定容器名(socksudp.py 硬编码 cli/echo)。
# ============================================================================
set -u
NET=ix-mqint; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
PASS=0; FAIL=0
cleanup(){ docker rm -f echo cli mgproxy >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT
cleanup; docker network create $NET >/dev/null 2>&1
H="$(cd "$(dirname "$0")" && pwd)"
cp "$H/socksudp.py" "$H/udpecho.py" "$D/" 2>/dev/null

# ---- 编 masque-go proxy(quic-go 官方 fork,第三方对端;缓存到 $D/masque-go-proxy)----
MGP=$D/masque-go-proxy
if [ ! -x "$MGP" ]; then
  echo "编 masque-go proxy(quic-go 官方 v0.60.0,首次约 1 分钟)..."
  W=$D/_mgp-src; mkdir -p "$W"
  cat > "$W/main.go" <<'GOEOF'
// masque-go(quic-go 官方 fork)connect-udp proxy —— NTR masque 第三方互通对端。
// 用 NTR 相同 RFC 9298 template /.well-known/masque/udp/{target_host}/{target_port}/。
package main

import (
	"crypto/tls"
	"log"
	"net/http"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	p := &masque.Proxy{}
	tmpl := uritemplate.MustNew("https://mgproxy:8443/.well-known/masque/udp/{target_host}/{target_port}/")
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/masque/udp/", func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseProxyRequest(r, tmpl)
		if err != nil {
			log.Printf("parse err: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		log.Printf("connect-udp accepted")
		if err := p.Proxy(w, req); err != nil {
			log.Printf("proxy err: %v", err)
		}
	})
	cert, err := tls.LoadX509KeyPair("/cert.pem", "/key.pem")
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	server := &http3.Server{
		Addr:            ":8443",
		Handler:         mux,
		EnableDatagrams: true,
		TLSConfig:       &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}},
	}
	log.Println("masque-go connect-udp proxy on :8443")
	log.Fatal(server.ListenAndServe())
}
GOEOF
  cat > "$W/go.mod" <<'MODEOF'
module masqueproxy

go 1.25

require (
	github.com/quic-go/masque-go v0.4.0
	github.com/quic-go/quic-go v0.60.0
	github.com/yosida95/uritemplate/v3 v3.0.2
)
MODEOF
  rm -f "$W/go.sum"
  docker run --rm -e GOPROXY="${GOPROXY:-https://goproxy.cn,https://proxy.golang.org,direct}" \
    -v "$W":/w -w /w golang:alpine sh -c 'go mod tidy >/dev/null 2>&1 && CGO_ENABLED=0 go build -o proxy .' 2>&1 | tail -3
  cp "$W/proxy" "$MGP" 2>/dev/null
fi
[ -x "$MGP" ] || { echo "❌ masque-go proxy 编译失败,无法互通验证"; exit 1; }

# ---- 拓扑 ----
docker run -d --name echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
docker run -d --name mgproxy --network $NET -v $MGP:/proxy:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /proxy >/dev/null 2>&1
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: masque, server: "mgproxy:8443", sni: example.com, insecure: true}\n' > $D/mqint-cli.yaml
docker run -d --name cli --network $NET -e NTR_DEBUG=1 -v $NTR:/ntr:ro -v $D/mqint-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 5

# ---- 验证:NTR masque 客户端(connect-udp)↔ masque-go proxy ----
echo "=== NTR masque client → RFC9298 connect-udp → masque-go proxy(quic-go 官方)→ udpecho ==="
ok=""
for i in 1 2 3 4 5; do
  docker run --rm --network $NET -v $D/socksudp.py:/c.py:ro python:3-alpine python /c.py >/dev/null 2>&1 && { ok=1; break; }
  sleep 2
done
if [ -n "$ok" ]; then echo "  ✅ MASQUE connect-udp 与 quic-go/masque-go 官方实现互通(UDP 回显匹配)"; PASS=$((PASS+1))
else echo "  ❌ 不通"; FAIL=$((FAIL+1)); echo "  proxy:"; docker logs mgproxy 2>&1|tail -6|sed 's/^/    /'; echo "  cli:"; docker logs cli 2>&1|tail -6|sed 's/^/    /'; fi

echo "════════ ix-masque-interop:PASS=$PASS FAIL=$FAIL ════════"
[ $FAIL -eq 0 ] && echo "✅ MASQUE 第三方互通全绿" || echo "❌ 有失败"
