#!/bin/bash
set -u
NET=mx-net; D=/tmp/ntr-interop
docker network create $NET >/dev/null 2>&1; docker rm -f mx-target mx-srv >/dev/null 2>&1
docker run -d --name mx-target --network $NET traefik/whoami >/dev/null
# 单一端口同时接受 socks 与 http
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: mixed}], outbound: direct}\noutbounds: [{name: direct, type: direct}]\n' > $D/mx.yaml
docker run -d --name mx-srv --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/mx.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 4
S=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://mx-srv:1080 http://mx-target/ 2>&1)
H=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x http://mx-srv:1080 http://mx-target/ 2>&1)
S4=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks4a://mx-srv:1080 http://mx-target/ 2>&1)
echo "$S"  | grep -q Hostname && echo "  ✅ socks5  经 mixed:1080" || echo "  ❌ socks5"
echo "$S4" | grep -q Hostname && echo "  ✅ socks4a 经 mixed:1080" || echo "  ❌ socks4a"
echo "$H"  | grep -q Hostname && echo "  ✅ http    经 mixed:1080(同一端口)" || echo "  ❌ http"
docker rm -f mx-target mx-srv >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1
