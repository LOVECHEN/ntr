#!/bin/bash
set -u
NET=ntr-interop; D=/tmp/ntr-interop; U=u; PW=nvpw; DEST=example.com
docker network create $NET >/dev/null 2>&1; docker rm -f target nvsrv nvcli >/dev/null 2>&1
docker run -d --name target --network $NET traefik/whoami >/dev/null
printf 'inbounds:\n  - name: srv-in\n    type: naive\n    listen: 0.0.0.0:8443\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\n    users:\n      - name: %s\n        password: "%s"\noutbounds:\n  - name: direct\n    type: direct\n' "$U" "$PW" > $D/nv-srv.yaml
docker run -d --name nvsrv --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/nv-srv.yaml:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: naive\n    server: "nvsrv:8443"\n    user: %s\n    secret: "%s"\n    sni: %s\n    insecure: true\n' "$U" "$PW" "$DEST" > $D/nv-cli.yaml
docker run -d --name nvcli --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/nv-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 5
OUT=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 10 -x socks5h://nvcli:1080 http://target/ 2>&1)
echo "$OUT" | grep -q Hostname && echo "✅ NTR↔NTR NaiveProxy(h2 CONNECT + padding)通" || { echo "❌ 不通"; echo "srv:"; docker logs nvsrv 2>&1|tail -6; echo "cli:"; docker logs nvcli 2>&1|tail -6; echo "curl: $(echo "$OUT"|head -2)"; }
docker rm -f target nvsrv nvcli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1
