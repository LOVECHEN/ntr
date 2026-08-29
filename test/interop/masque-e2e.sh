#!/bin/bash
set -u
NET=mq-net; D=/tmp/ntr-interop; DEST=example.com
docker network create $NET >/dev/null 2>&1; docker rm -f mq-target mq-srv mq-cli >/dev/null 2>&1
docker run -d --name mq-target --network $NET traefik/whoami >/dev/null
# MASQUE 服务端:QUIC/h3 自管监听
printf 'inbounds:\n  - listen: 0.0.0.0:8443\n    type: masque\n    tls: {cert-file: /cert.pem, key-file: /key.pem}\noutbounds: [{name: direct, type: direct}]\n' > $D/mq-srv.yaml
docker run -d --name mq-srv --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/mq-srv.yaml:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
# 客户端:socks 入站 → masque 出站
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: masque, server: "mq-srv:8443", sni: %s, insecure: true}\n' "$DEST" > $D/mq-cli.yaml
docker run -d --name mq-cli --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/mq-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 5
echo "--- TCP(CONNECT over h3)---"
OUT=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x socks5h://mq-cli:1080 http://mq-target/ 2>&1)
echo "$OUT" | grep -q Hostname && echo "✅ MASQUE TCP 通(socks→CONNECT over h3→direct)" || { echo "❌ TCP 不通"; echo "srv:"; docker logs mq-srv 2>&1|tail -8; echo "cli:"; docker logs mq-cli 2>&1|tail -8; echo "curl: $(echo "$OUT"|head -2)"; }
docker rm -f mq-target mq-srv mq-cli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1
