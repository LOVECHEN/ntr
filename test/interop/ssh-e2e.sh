#!/bin/bash
set -u
NET=ntr-interop; D=/tmp/ntr-interop; PW=sshpw; U=nt
docker network create $NET >/dev/null 2>&1; docker rm -f target sshsrv sshcli >/dev/null 2>&1
docker run -d --name target --network $NET traefik/whoami >/dev/null
# SSH 服务端:type=ssh + host 私钥(tls.key) + 密码用户 + direct 落地
printf 'inbounds:\n  - listen: 0.0.0.0:2222\n    type: ssh\n    tls: {key-file: /hostkey}\n    users: [{name: %s, password: "%s"}]\noutbounds: [{name: direct, type: direct}]\n' "$U" "$PW" > $D/ssh-srv.yaml
docker run -d --name sshsrv --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ssh-srv.yaml:/c.yaml:ro -v $D/ssh_hostkey:/hostkey:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
# SSH 客户端:socks 入站 → ssh 出站
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: ssh, server: "sshsrv:2222", user: %s, secret: "%s"}\n' "$U" "$PW" > $D/ssh-cli.yaml
docker run -d --name sshcli --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/ssh-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 5
OUT=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 10 -x socks5h://sshcli:1080 http://target/ 2>&1)
echo "$OUT" | grep -q Hostname && echo "✅ NTR↔NTR SSH 隧道通(socks→ssh direct-tcpip→direct 落地)" || { echo "❌ 不通"; echo "srv:"; docker logs sshsrv 2>&1|tail -6; echo "cli:"; docker logs sshcli 2>&1|tail -6; echo "curl: $OUT"|head -3; }
docker rm -f target sshsrv sshcli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1
