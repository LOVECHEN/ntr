#!/bin/bash
# tproxy 入站验证:iptables mangle TPROXY + IP_TRANSPARENT 透明代理。TCP + UDP。
# 拓扑:whoami(W:80)+ udpecho(U:5353)+ gw 路由器(NET_ADMIN,ip_forward,TPROXY→NTR tproxy 入站
#   :12345,出站 direct)+ client(把 W/U 路由指向 gw)。
#   client → W:80 / U:5353 经 gw PREROUTING TPROXY 截获 → NTR 读原始目的(TCP=本地地址/UDP=IP_ORIGDSTADDR)
#   → direct 拨真目标 → 回包经 IP_TRANSPARENT 伪造源(=原始目的)送回 client。
set -u
NET=ix-tproxy; PFX=ixtpx-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1

H="$(cd "$(dirname "$0")" && pwd)/helpers"
[ -x $D/udpecho ]   || CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $D/udpecho   "$H/udpecho.go"
[ -x $D/udpclient ] || CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $D/udpclient "$H/udpclient.go"
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
docker run -d --name ${PFX}uecho  --network $NET -v $D/udpecho:/udpecho:ro alpine /udpecho >/dev/null 2>&1
sleep 1
W=$(docker inspect ${PFX}target --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
U=$(docker inspect ${PFX}uecho  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)

cat > $D/_tpx.yaml <<Y
inbounds:
  - {listen: 0.0.0.0:12345, type: tproxy, network: [tcp, udp], outbound: direct}
outbounds: [{name: direct, type: direct}]
Y
docker run -d --name ${PFX}gw --network $NET --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
  -v $NTR:/ntr:ro -v $D/_tpx.yaml:/c.yaml:ro alpine sleep infinity >/dev/null 2>&1
docker run -d --name ${PFX}cli --network $NET --cap-add NET_ADMIN \
  -v $D/udpclient:/udpclient:ro alpine sleep infinity >/dev/null 2>&1
sleep 1
GW=$(docker inspect ${PFX}gw --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
echo "whoami W=$W  udpecho U=$U  gw GW=$GW"

echo "=== gw:TPROXY 规则 + ip rule/route + 起 NTR ==="
docker exec ${PFX}gw sh -c "
  apk add -q iptables iproute2 >/dev/null 2>&1
  ip rule add fwmark 1 table 100 2>/dev/null
  ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null
  iptables -t mangle -A PREROUTING -p tcp --dport 80   -j TPROXY --on-port 12345 --tproxy-mark 1
  iptables -t mangle -A PREROUTING -p udp --dport 5353 -j TPROXY --on-port 12345 --tproxy-mark 1
  echo '  mangle PREROUTING:'; iptables -t mangle -S PREROUTING | grep TPROXY | sed 's/^/    /'
"
docker exec -d ${PFX}gw sh -c "/ntr -config /c.yaml >/tmp/ntr.log 2>&1"
sleep 2

echo "=== client:把 W/U 路由指向 gw ==="
docker exec ${PFX}cli sh -c "
  apk add -q iproute2 curl >/dev/null 2>&1
  ip route add $W/32 via $GW
  ip route add $U/32 via $GW
  echo '  routes:'; ip route | grep -E '$W|$U' | sed 's/^/    /'
"

echo "=== TCP:client curl W:80(经 gw TPROXY → NTR tproxy 入站 → direct → whoami)==="
ok=FAIL
for i in 1 2 3 4 5; do
  r=$(docker exec ${PFX}cli curl -s --max-time 6 http://$W/ 2>/dev/null)
  echo "$r" | grep -q Hostname && { ok=PASS; break; }
  sleep 1
done
echo "  [NTR tproxy 入站 TCP → direct → whoami]  $ok"

echo "=== UDP:client udpclient U:5353(经 gw TPROXY → NTR tproxy 入站 → direct → echo)==="
uok=FAIL
for i in 1 2 3 4; do
  r=$(docker exec ${PFX}cli /udpclient $U:5353 "tproxy-udp-9" 2>&1)
  echo "$r" | grep -q UDP-CLIENT-OK && { uok=PASS; break; }
  sleep 1
done
echo "  [NTR tproxy 入站 UDP → direct → echo]  $uok"
[ $ok = FAIL -o $uok = FAIL ] && docker exec ${PFX}gw sh -c 'tail -10 /tmp/ntr.log 2>&1' | sed 's/^/  NTR:/'
cleanup; echo DONE