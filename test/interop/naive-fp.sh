#!/bin/bash
set -u
NET=fp-net; D=/tmp/ntr-interop; U=u; PW=nvpw; DEST=example.com
docker network create $NET >/dev/null 2>&1; docker rm -f fp-target fp-srv fp-cli >/dev/null 2>&1
docker run -d --name fp-target --network $NET traefik/whoami >/dev/null
printf 'inbounds:\n  - name: srv-in\n    type: naive\n    listen: 0.0.0.0:8443\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\n    users:\n      - name: %s\n        password: "%s"\noutbounds:\n  - name: direct\n    type: direct\n' "$U" "$PW" > $D/fp-srv.yaml
docker run -d --name fp-srv --network $NET -v $D/ntr:/ntr:ro -v $D/fp-srv.yaml:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
for FP in "" chrome firefox safari ios edge random; do
  printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: naive\n    server: "fp-srv:8443"\n    user: %s\n    secret: "%s"\n    sni: %s\n    insecure: true\n    client-fingerprint: "%s"\n' "$U" "$PW" "$DEST" "$FP" > $D/fp-cli.yaml
  docker rm -f fp-cli >/dev/null 2>&1
  docker run -d --name fp-cli --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/fp-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 3
  OUT=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 10 -x socks5h://fp-cli:1080 http://fp-target/ 2>&1)
  LABEL="${FP:-<无指纹/标准 crypto-tls>}"
  echo "$OUT" | grep -q Hostname && echo "  ✅ $LABEL" || { echo "  ❌ $LABEL"; docker logs fp-cli 2>&1|tail -3; }
done
docker rm -f fp-target fp-srv fp-cli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1
