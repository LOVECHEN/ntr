#!/bin/bash
set -u
NET=ntr-interop; D=/tmp/ntr-interop; CD=reverse.ntr; PW=sshpw; U=nt
docker network create $NET >/dev/null 2>&1; docker rm -f target portal bridge usr >/dev/null 2>&1
docker run -d --name target --network $NET traefik/whoami >/dev/null
printf 'inbounds:\n  - name: portal-in\n    type: ssh\n    mode: portal\n    listen: 0.0.0.0:2222\n    control-domain: %s\n    tls:\n      key-file: /hostkey\n    users:\n      - name: %s\n        password: "%s"\noutbounds:\n  - name: direct\n    type: direct\n' "$CD" "$U" "$PW" > $D/sp-portal.yaml
docker run -d --name portal --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/sp-portal.yaml:/c.yaml:ro -v $D/ssh_hostkey:/hostkey:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
printf 'outbounds:\n  - name: up\n    type: ssh\n    server: "portal:2222"\n    user: %s\n    secret: "%s"\nbridges:\n  - portal: up\n    control-domain: %s\n    pool: 2\n' "$U" "$PW" "$CD" > $D/sp-bridge.yaml
docker run -d --name bridge --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/sp-bridge.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: ssh\n    server: "portal:2222"\n    user: %s\n    secret: "%s"\n' "$U" "$PW" > $D/sp-user.yaml
docker run -d --name usr --network $NET -v $D/ntr:/ntr:ro -v $D/sp-user.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 5
BIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bridge)
RA=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 10 -x socks5h://usr:1080 http://target/ 2>&1|grep -i RemoteAddr|sed 's/.*RemoteAddr: //; s/:[0-9]*$//')
echo "[ssh] target 来源=$RA  bridge=$BIP"
[ "$RA" = "$BIP" ] && echo "✅ 会话式 SSH 协议当反连 portal 成立" || { echo "❌ ssh portal"; docker logs portal 2>&1|tail -4; docker logs bridge 2>&1|tail -4; }
docker rm -f target portal bridge usr >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1
