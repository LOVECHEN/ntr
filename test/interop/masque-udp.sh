#!/bin/bash
set -u
NET=mqu-net; D=/tmp/ntr-interop; DEST=example.com
docker network create $NET >/dev/null 2>&1; docker rm -f echo mq-srv cli >/dev/null 2>&1
docker run -d --name echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
# MASQUE 服务端(QUIC/h3)
printf 'inbounds:\n  - name: srv-in\n    type: masque\n    listen: 0.0.0.0:8443\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\noutbounds:\n  - name: direct\n    type: direct\n' > $D/mqu-srv.yaml
docker run -d --name mq-srv --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/mqu-srv.yaml:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
# 客户端(容器名必须叫 cli,socksudp.py 硬编码):socks 入站(含 UDP ASSOCIATE)→ masque 出站
printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: masque\n    server: "mq-srv:8443"\n    sni: %s\n    insecure: true\n' "$DEST" > $D/mqu-cli.yaml
docker run -d --name cli --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/mqu-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 5
echo "=== socks-udp 用户 → NTR client → MASQUE connect-udp(RFC 9298)→ 服务端 → UDP echo ==="
docker run --rm --network $NET -v $D/socksudp.py:/c.py:ro python:3-alpine python /c.py 2>&1; RC=$?
echo "--- exit=$RC (0=UDP 回显匹配)---"
[ $RC -eq 0 ] && echo "✅ MASQUE UDP(connect-udp + HTTP Datagram)通" || { echo "❌ UDP 不通"; echo "srv:"; docker logs mq-srv 2>&1|tail -8; echo "cli:"; docker logs cli 2>&1|tail -8; }
docker rm -f echo mq-srv cli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1
