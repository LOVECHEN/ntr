#!/bin/bash
# mieru UDP 载荷交叉验证(双向 × mieru 传输 TCP/UDP):NTR mieru <-> mihomo mieru,UDP-over-tunnel。
# 用 UDP-over-socks5 探针驱动某端的 socks-UDP 入站 ASSOCIATE。
#   A: NTR socks-UDP 入站 → NTR mieru UDP 出站(DialPacket)→ mihomo mieru 服务端 → echo
#   B: probe → mihomo socks-UDP → mihomo mieru 客户端(udp) → NTR mieru 入站(serveUDP)→ echo
# 官方库 enfein/mieru/v3,禁改线格式。
set -u
NET=ix-miu; PFX=ixmiu-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; U=mieruuser; P=mierupass123
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
# 探针/echo 静态二进制(缺则从 helpers/ 现编;纯 static,无本机污染)
H="$(cd "$(dirname "$0")" && pwd)/helpers"
[ -x $D/udpprobe ] || CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $D/udpprobe "$H/udpprobe.go"
[ -x $D/udpecho ]  || CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $D/udpecho  "$H/udpecho.go"
docker run -d --name ${PFX}echo --network $NET -v $D/udpecho:/udpecho:ro alpine /udpecho >/dev/null 2>&1
sleep 1

probe(){ docker run --rm --network $NET -v $D/udpprobe:/udpprobe:ro alpine /udpprobe "$1" ${PFX}echo:5353 "$2" 2>&1; }

# 方向 A:mihomo mieru 服务端 + NTR(socks-UDP 入站 → mieru UDP 出站),探针打 NTR socks。
dir_A(){ local t=$1
  cat > $D/_miu_msrv.yaml <<Y
mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: warning
listeners:
  - {name: mieru-in, type: mieru, port: 10818, listen: 0.0.0.0, transport: $t, users: {$U: $P}}
rules: ["MATCH,DIRECT"]
Y
  docker run -d --name ${PFX}s --network $NET -v $D/_miu_msrv.yaml:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1
  cat > $D/_miu_ntr.yaml <<Y
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}
outbounds:
  - {name: up, type: mieru, server: "${PFX}s:10818", transport: $t, user: $U, secret: "$P"}
Y
  docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_miu_ntr.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 3; probe ${PFX}c:1080 "A-udp-$t"
}

# 方向 B:NTR mieru 服务端 + mihomo(socks-UDP → mieru UDP 客户端),探针打 mihomo socks。
dir_B(){ local t=$1
  cat > $D/_miu_nsrv.yaml <<Y
inbounds:
  - listen: 0.0.0.0:10818
    type: mieru
    transport: $t
    users: [{name: $U, password: "$P"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
  docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_miu_nsrv.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  cat > $D/_miu_mcli.yaml <<Y
mixed-port: 1080
allow-lan: true
bind-address: '*'
mode: global
log-level: warning
proxies:
  - {name: mieru, type: mieru, server: ${PFX}s, port: 10818, transport: $t, username: $U, password: "$P", udp: true}
proxy-groups:
  - {name: GLOBAL, type: select, proxies: [mieru]}
Y
  docker run -d --name ${PFX}c --network $NET -v $D/_miu_mcli.yaml:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1
  sleep 4; probe ${PFX}c:1080 "B-udp-$t"
}

run(){ # $1=label $2=fn $3=transport
  local ok=FAIL i out
  for i in 1 2 3 4; do out=$($2 "$3"); echo "$out" | grep -q UDP-ECHO-OK && { ok=PASS; break; }; sleep 1; done
  printf "  [%s / mieru传输 %s]  %s\n" "$1" "$3" "$ok"
  [ $ok = PASS ] || { echo "$out"|sed 's/^/    PROBE:/'; docker logs ${PFX}s 2>&1|tail -2|sed 's/^/    S:/'; docker logs ${PFX}c 2>&1|tail -2|sed 's/^/    C:/'; }
  docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
}

run "A NTRcli->mihomoSrv" dir_A TCP
run "A NTRcli->mihomoSrv" dir_A UDP
run "B mihomoCli->NTRSrv" dir_B TCP
run "B mihomoCli->NTRSrv" dir_B UDP
cleanup; echo DONE
