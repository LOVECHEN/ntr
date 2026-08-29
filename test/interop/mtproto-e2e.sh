#!/bin/bash
set -u
NET=mt-net; D=/tmp/ntr-interop; SEC="ee3031323334353637383961626364656673746f726167652e676f6f676c65617069732e636f6d"
docker network create $NET >/dev/null 2>&1; docker rm -f mt-target mt-srv mt-cli >/dev/null 2>&1
docker run -d --name mt-target --network $NET traefik/whoami >/dev/null
# 服务端:mtproto 入站;dc-map 把 DC 2 指向靶机(生产环境走内置 Telegram DC 表)
printf 'inbounds:\n  - listen: 0.0.0.0:8443\n    layers: [{type: mtproto, secret: "%s", dc-map: "2=mt-target:80"}]\noutbounds: [{name: direct, type: direct}]\n' "$SEC" > $D/mt-srv.yaml
docker run -d --name mt-srv --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/mt-srv.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
# 客户端:socks 入站 → mtproto 出站(dc=2)
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: proxy, server: "mt-srv:8443", layers: [{type: mtproto, secret: "%s", dc: "2"}]}\n' "$SEC" > $D/mt-cli.yaml
docker run -d --name mt-cli --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/mt-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 5
OUT=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x socks5h://mt-cli:1080 http://mt-target/ 2>&1)
echo "$OUT" | grep -q Hostname && echo "✅ NTR↔NTR MTProto(faketls + obfuscated2)通" || { echo "❌ 不通"; echo "srv:"; docker logs mt-srv 2>&1|tail -8; echo "cli:"; docker logs mt-cli 2>&1|tail -8; echo "curl: $(echo "$OUT"|head -2)"; }
docker rm -f mt-target mt-srv mt-cli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1
