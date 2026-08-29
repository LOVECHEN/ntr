#!/bin/bash
set -u
NET=ntr-interop; D=/tmp/ntr-interop; CD=reverse.ntr; U=u; PW=ttpw; DEST=example.com
docker network create $NET >/dev/null 2>&1; docker rm -f target portal bridge usr >/dev/null 2>&1
docker run -d --name target --network $NET traefik/whoami >/dev/null
printf 'inbounds:\n  - listen: 0.0.0.0:8443\n    type: trusttunnel\n    control-domain: %s\n    tls: {cert-file: /cert.pem, key-file: /key.pem}\n    users: [{name: %s, password: "%s"}]\noutbounds: [{name: direct, type: direct}]\n' "$CD" "$U" "$PW" > $D/ttp-portal.yaml
docker run -d --name portal --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ttp-portal.yaml:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
printf 'outbounds:\n  - {name: up, type: trusttunnel, server: "portal:8443", user: %s, secret: "%s", sni: %s, insecure: true}\nbridges:\n  - {portal: up, control-domain: %s, pool: 2}\n' "$U" "$PW" "$DEST" "$CD" > $D/ttp-bridge.yaml
docker run -d --name bridge --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ttp-bridge.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: trusttunnel, server: "portal:8443", user: %s, secret: "%s", sni: %s, insecure: true}\n' "$U" "$PW" "$DEST" > $D/ttp-user.yaml
docker run -d --name usr --network $NET -v $D/ntr:/ntr:ro -v $D/ttp-user.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 5
BIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bridge)
RA=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 10 -x socks5h://usr:1080 http://target/ 2>&1|grep -i RemoteAddr|sed 's/.*RemoteAddr: //; s/:[0-9]*$//')
echo "[tt] target 来源=$RA  bridge=$BIP"
[ "$RA" = "$BIP" ] && echo "✅ TrustTunnel 当反连 portal 成立" || { echo "❌"; docker logs portal 2>&1|tail -4; docker logs bridge 2>&1|tail -4; }
docker rm -f target portal bridge usr >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1
