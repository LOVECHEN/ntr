#!/bin/bash
# Mux.cool UDP-over-mux(XUDP 全锥)交叉验证:承载上跑 UDP 子流(New/Keep 带地址),回程带 source。
# 用 tunnel(udp) 入站免 socks-UDP 客户端:udpclient → NTR tunnel(udp):6000 → mux.cool 出站 → 服务端解复用
#   → direct → udpecho 回显。
#   A. NTR mux.cool 客户端 -> NTR vless 服务端(自环)
#   B. NTR mux.cool 客户端 -> 真 xray vless 服务端
set -u
NET=ix-mcu; PFX=ixmcu-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; UUID=11111111-2222-3333-4444-555555555555
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
H="$(cd "$(dirname "$0")" && pwd)/helpers"
[ -x $D/udpecho ]   || CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $D/udpecho   "$H/udpecho.go"
[ -x $D/udpclient ] || CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $D/udpclient "$H/udpclient.go"
docker run -d --name ${PFX}uecho --network $NET -v $D/udpecho:/udpecho:ro alpine /udpecho >/dev/null 2>&1
sleep 1
U=$(docker inspect ${PFX}uecho --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
echo "udpecho U=$U"

xray(){ docker run -d --name $1 --network $NET -v $2:/c.json:ro ghcr.io/xtls/xray-core:latest -c /c.json >/dev/null 2>&1; }
ntr(){  docker run -d --name $1 --network $NET -v $NTR:/ntr:ro -v $2:/c.yaml:ro -v $D/udpclient:/udpclient:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }

# NTR 客户端:tunnel(udp):6000 → 固定 U:5353,经 mux.cool(vless)出站到 ${PFX}s
cat > $D/_mcu_ntrcli.yaml <<Y
inbounds:
  - {listen: 0.0.0.0:6000, type: tunnel, target: "$U:5353", network: [udp], outbound: up}
outbounds:
  - {name: up, type: proxy, server: "${PFX}s:10000", secret: "$UUID", layers: [{type: vless}], mux: {protocol: cool}}
Y
# NTR vless 服务端
cat > $D/_mcu_ntrsrv.yaml <<Y
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: vless}]
    users: [{uuid: "$UUID"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
# xray vless 服务端
cat > $D/_mcu_xraysrv.json <<J
{"log":{"loglevel":"warning"},"inbounds":[{"port":10000,"listen":"0.0.0.0","protocol":"vless","settings":{"clients":[{"id":"$UUID"}],"decryption":"none"}}],"outbounds":[{"protocol":"freedom"}]}
J

run_case(){ # $1 label  $2 srv-launcher
  docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
  eval "$2"; sleep 2
  ntr ${PFX}c $D/_mcu_ntrcli.yaml; sleep 2
  local ok=FAIL i r
  for i in 1 2 3 4 5; do
    r=$(docker exec ${PFX}c /udpclient 127.0.0.1:6000 "muxcool-udp-$i" 2>&1)
    echo "$r" | grep -q UDP-CLIENT-OK && { ok=PASS; break; }
    sleep 1
  done
  echo "  [$1]  $ok"
  [ $ok = FAIL ] && { echo "$r"|sed 's/^/    PROBE:/'; docker logs ${PFX}c 2>&1|tail -3|sed 's/^/    CLI:/'; docker logs ${PFX}s 2>&1|tail -3|sed 's/^/    SRV:/'; }
}

run_case "A. NTR mux.cool UDP 客户端 -> NTR vless 服务端(自环)"  'ntr ${PFX}s $D/_mcu_ntrsrv.yaml'
run_case "B. NTR mux.cool UDP 客户端 -> 真 xray vless 服务端"     'xray ${PFX}s $D/_mcu_xraysrv.json'
cleanup; echo DONE