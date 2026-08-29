#!/bin/bash
# TUN 入站交叉验证:NTR 原生用户态栈(gVisor)从 TUN 网卡捕获 IP 流量 → 合成 TCP/UDP → 任意出站落地。
# 拓扑(避免 TUN 回环):whoami(W)+ 网关 P(NTR socks→direct,eth0 可达 W)+ TUN 容器(NTR-tun:
#   tun 入站 → socks 出站到 P)。仅把 W/32 路由进 tun;P 走 eth0 不回环。
#   容器内 curl W → SYN 进 tun → NTR netstack 合成 → socks-out → P → direct → W → 回显。
# 需 -tags with_tun 的 ntr-tun 二进制;容器需 --cap-add NET_ADMIN + /dev/net/tun。
set -u
NET=ix-tun; PFX=ixtun-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; NTRTUN=${NTRTUN_BIN:-$D/ntr-tun}
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1

H="$(cd "$(dirname "$0")" && pwd)/helpers"
[ -x $D/udpecho ]   || CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $D/udpecho   "$H/udpecho.go"
[ -x $D/udpclient ] || CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $D/udpclient "$H/udpclient.go"
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
docker run -d --name ${PFX}uecho --network $NET -v $D/udpecho:/udpecho:ro alpine /udpecho >/dev/null 2>&1
sleep 1
W=$(docker inspect ${PFX}target --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
U=$(docker inspect ${PFX}uecho  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
echo "whoami W=$W  udpecho U=$U"

# 网关 P:NTR socks 入站 → direct(eth0 可达 W)
cat > $D/_tun_gw.yaml <<Y
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: direct}
outbounds: [{name: direct, type: direct}]
Y
docker run -d --name ${PFX}gw --network $NET -v $NTR:/ntr:ro -v $D/_tun_gw.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1

# TUN 容器:NTR-tun tun 入站 → socks 出站到网关
cat > $D/_tun_ntr.yaml <<Y
inbounds:
  - type: tun
    if-name: ntr-tun0
    address: [10.9.9.1/24]
    mtu: 1500
    outbound: up
outbounds:
  - {name: up, type: proxy, server: "${PFX}gw:1080", layers: [{type: socks}]}
Y
docker run -d --name ${PFX}tun --network $NET --cap-add NET_ADMIN --device /dev/net/tun \
  -v $NTRTUN:/ntr-tun:ro -v $D/_tun_ntr.yaml:/c.yaml:ro -v $D/udpclient:/udpclient:ro alpine /ntr-tun -config /c.yaml >/dev/null 2>&1
sleep 3

# 等 ntr-tun0 出现,装 iproute2/curl,路由 W/32 + U/32 进 tun
docker exec ${PFX}tun sh -c 'apk add -q iproute2 curl >/dev/null 2>&1; for i in 1 2 3 4 5; do ip link show ntr-tun0 >/dev/null 2>&1 && break; sleep 1; done'
echo "=== tun 容器网卡/路由 ==="
docker exec ${PFX}tun sh -c "ip -brief addr show ntr-tun0 2>&1; ip route add $W/32 dev ntr-tun0 2>&1; ip route add $U/32 dev ntr-tun0 2>&1 && echo '路由 W/U -> tun 已加'"

echo "=== TCP:容器内 curl W(经 tun → netstack → socks-out → P → whoami)==="
ok=FAIL
for i in 1 2 3 4 5; do
  r=$(docker exec ${PFX}tun curl -s --max-time 6 http://$W/ 2>/dev/null)
  echo "$r" | grep -q Hostname && { ok=PASS; break; }
  sleep 1
done
echo "  [NTR TUN 入站 TCP → socks 出站 → whoami]  $ok"
[ $ok = FAIL ] && { docker logs ${PFX}tun 2>&1|tail -5|sed 's/^/  TUN:/'; docker logs ${PFX}gw 2>&1|tail -3|sed 's/^/  GW:/'; }

echo "=== UDP:容器内 udpclient U:5353(经 tun → netstack UDP → socks-out UDP → P → echo)==="
uok=FAIL
for i in 1 2 3 4; do
  r=$(docker exec ${PFX}tun /udpclient $U:5353 "tun-udp-42" 2>&1)
  echo "$r" | grep -q UDP-CLIENT-OK && { uok=PASS; break; }
  sleep 1
done
echo "  [NTR TUN 入站 UDP → socks 出站 → echo]  $uok"
[ $uok = FAIL ] && { echo "$r"|sed 's/^/  PROBE:/'; docker logs ${PFX}tun 2>&1|tail -3|sed 's/^/  TUN:/'; }
cleanup; echo DONE
