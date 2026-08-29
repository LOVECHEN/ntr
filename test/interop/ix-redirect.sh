#!/bin/bash
# redirect 入站验证:iptables nat REDIRECT + getsockopt(SO_ORIGINAL_DST) 恢复原始目的地。
# 拓扑:whoami(W:80)+ gw 容器(NET_ADMIN):内跑 NTR redirect 入站(:12345,出站 direct)+ iptables。
#   规则:OUTPUT 里把「非 NTR 自身(uid!=1000)的 tcp:80」REDIRECT 到 :12345;NTR 自身出站(uid 1000)
#   RETURN 直连,避免回环。gw 内 curl W:80(root)→ 被 REDIRECT → NTR 读 SO_ORIGINAL_DST=W:80 → direct → W。
set -u
NET=ix-redirect; PFX=ixrdr-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1

docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1
W=$(docker inspect ${PFX}target --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
echo "whoami W=$W"

cat > $D/_rdr.yaml <<Y
inbounds:
  - {listen: 0.0.0.0:12345, type: redirect, outbound: direct}
outbounds: [{name: direct, type: direct}]
Y
docker run -d --name ${PFX}gw --network $NET --cap-add NET_ADMIN \
  -v $NTR:/ntr:ro -v $D/_rdr.yaml:/c.yaml:ro alpine sleep infinity >/dev/null 2>&1

echo "=== gw 内:装 iptables/curl,建 REDIRECT 规则,起 NTR(uid 1000)==="
docker exec ${PFX}gw sh -c '
  apk add -q iptables curl >/dev/null 2>&1
  adduser -D -u 1000 ntr 2>/dev/null
  iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner 1000 -j RETURN
  iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 12345
  echo "  规则:"; iptables -t nat -S OUTPUT | sed "s/^/    /"
'
docker exec -d ${PFX}gw su ntr -c "/ntr -config /c.yaml >/tmp/ntr.log 2>&1"
sleep 2

echo "=== gw 内 curl W:80(root,被 REDIRECT → NTR redirect 入站 → direct → whoami)==="
ok=FAIL
for i in 1 2 3 4 5; do
  r=$(docker exec ${PFX}gw curl -s --max-time 6 http://$W/ 2>/dev/null)
  echo "$r" | grep -q Hostname && { ok=PASS; break; }
  sleep 1
done
echo "  [NTR redirect 入站 → direct → whoami]  $ok"
[ $ok = FAIL ] && docker exec ${PFX}gw sh -c 'tail -8 /tmp/ntr.log 2>&1' | sed 's/^/  NTR:/'
cleanup; echo DONE