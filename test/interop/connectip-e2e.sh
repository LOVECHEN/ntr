#!/bin/bash
set -u
NET=cip-net; D=/tmp/ntr-interop; DEST=example.com
cleanup(){ docker rm -f cip-target cip-srv cip-cli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT
docker network create $NET >/dev/null 2>&1; docker rm -f cip-target cip-srv cip-cli >/dev/null 2>&1
docker run -d --name cip-target --network $NET traefik/whoami >/dev/null
# 服务端:connect-ip 入站(QUIC/h3),收到的 IP 包经 netstack forwarder 合成 L4 → direct 落地
printf 'inbounds:\n  - name: cip-in\n    type: connect-ip\n    listen: 0.0.0.0:8443\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\n    assign-address: "10.9.0.2/32"\noutbounds:\n  - name: direct\n    type: direct\n' > $D/cip-srv.yaml
docker run -d --name cip-srv --network $NET -e NTR_DEBUG=1 -v $D/ntr-l3:/ntr:ro -v $D/cip-srv.yaml:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
# 客户端:socks 入站 → connect-ip 出站
printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: connect-ip\n    server: "cip-srv:8443"\n    sni: %s\n    insecure: true\n    local-address:\n      - "10.9.0.2/32"\n' "$DEST" > $D/cip-cli.yaml
docker run -d --name cip-cli --network $NET -e NTR_DEBUG=1 -v $D/ntr-l3:/ntr:ro -v $D/cip-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 7
TIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' cip-target)
OUT=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 15 -x socks5h://cip-cli:1080 "http://$TIP/" 2>&1)
if echo "$OUT" | grep -q Hostname; then
  echo "✅ NTR connect-ip 自环通(L3 隧道:socks → IP 包 → h3 datagram → netstack forwarder → direct)"
else
  echo "❌ 不通"; echo "--- client ---"; docker logs cip-cli 2>&1|tail -8; echo "--- server ---"; docker logs cip-srv 2>&1|tail -8
fi
