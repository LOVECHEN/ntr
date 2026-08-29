#!/bin/bash
set -u
NET=ntr-interop; D=/tmp/ntr-interop; U=u; PW=ttpw; DEST=example.com
docker network create $NET >/dev/null 2>&1; docker rm -f target ttsrv ttcli >/dev/null 2>&1
docker run -d --name target --network $NET traefik/whoami >/dev/null
printf 'inbounds:\n  - listen: 0.0.0.0:8443\n    type: trusttunnel\n    tls: {cert-file: /cert.pem, key-file: /key.pem}\n    users: [{name: %s, password: "%s"}]\noutbounds: [{name: direct, type: direct}]\n' "$U" "$PW" > $D/tt-srv.yaml
docker run -d --name ttsrv --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/tt-srv.yaml:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: trusttunnel, server: "ttsrv:8443", user: %s, secret: "%s", sni: %s, insecure: true}\n' "$U" "$PW" "$DEST" > $D/tt-cli.yaml
docker run -d --name ttcli --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/tt-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 5
OUT=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 10 -x socks5h://ttcli:1080 http://target/ 2>&1)
echo "$OUT" | grep -q Hostname && echo "✅ NTR↔NTR TrustTunnel(H2 CONNECT)通(socks→trusttunnel→direct 落地)" || { echo "❌ 不通"; echo "srv:"; docker logs ttsrv 2>&1|tail -6; echo "cli:"; docker logs ttcli 2>&1|tail -6; echo "curl: $(echo "$OUT"|head -2)"; }
docker rm -f target ttsrv ttcli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1
