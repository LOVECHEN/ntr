#!/bin/bash
# tunnel 入站验证:固定目标端口转发(xray dokodemo-door 指定 address 形态)。TCP + UDP。
# 拓扑:whoami(W:80)+ udpecho(U:5353)+ NTR(tunnel 入站 5000→W:80 / 5001→U:5353,出站 direct)。
#   客户端 curl ntr:5000 → 转发到 W:80 → whoami 回显;udpclient ntr:5001 → 转发到 U:5353 → echo。
# 证明 tunnel 入站正确把「无协议裸连接」定向到固定目标(出站 protocol-agnostic,此处 direct)。
set -u
NET=ix-tunnel; PFX=ixtnl-; D=/tmp/ntr-interop
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
echo "whoami W=$W  udpecho U=$U"

cat > $D/_tnl.yaml <<Y
inbounds:
  - {listen: 0.0.0.0:5000, type: tunnel, target: "$W:80",   network: [tcp], outbound: direct}
  - {listen: 0.0.0.0:5001, type: tunnel, target: "$U:5353", network: [udp], outbound: direct}
outbounds: [{name: direct, type: direct}]
Y
docker run -d --name ${PFX}ntr --network $NET \
  -v $NTR:/ntr:ro -v $D/_tnl.yaml:/c.yaml:ro -v $D/udpclient:/udpclient:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 2
docker exec ${PFX}ntr sh -c 'apk add -q curl >/dev/null 2>&1' 2>/dev/null

echo "=== TCP:curl ntr:5000 → 固定目标 W:80(whoami)==="
ok=FAIL
for i in 1 2 3 4 5; do
  r=$(docker run --rm --network $NET alpine sh -c "apk add -q curl >/dev/null 2>&1; curl -s --max-time 6 http://${PFX}ntr:5000/" 2>/dev/null)
  echo "$r" | grep -q Hostname && { ok=PASS; break; }
  sleep 1
done
echo "  [NTR tunnel 入站 TCP → 固定 W:80]  $ok"

echo "=== UDP:udpclient ntr:5001 → 固定目标 U:5353(echo)==="
uok=FAIL
for i in 1 2 3 4; do
  r=$(docker exec ${PFX}ntr /udpclient ${PFX}ntr:5001 "tunnel-udp-7" 2>&1)
  echo "$r" | grep -q UDP-CLIENT-OK && { uok=PASS; break; }
  sleep 1
done
echo "  [NTR tunnel 入站 UDP → 固定 U:5353]  $uok"
[ $ok = FAIL -o $uok = FAIL ] && docker logs ${PFX}ntr 2>&1 | tail -6 | sed 's/^/  NTR:/'
cleanup; echo DONE