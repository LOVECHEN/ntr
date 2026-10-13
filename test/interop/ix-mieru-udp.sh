#!/bin/bash
# mieru UDP 载荷交叉验证(双向 × mieru 传输 TCP/UDP):NTR mieru <-> mihomo mieru,UDP-over-tunnel。
# 用 UDP-over-socks5 探针驱动某端的 socks-UDP 入站 ASSOCIATE。
#   A: NTR socks-UDP 入站 → NTR mieru UDP 出站(DialPacket)→ mihomo mieru 服务端 → echo
#   B: probe → mihomo socks-UDP → mihomo mieru 客户端(udp) → NTR mieru 入站(serveUDP)→ echo
#   C: NTR socks-UDP → NTR mieru 出站 → NTR mieru 入站 → echo(目标为域名)。mieru UDP 包头只许 IP(官方
#      UDPAssociateWrapper 拒 FQDN);mihomo 客户端发前先解析、其服务端回 IP,故 A/B 测不出 NTR 两端漏解析 ——
#      C 专堵这条:此前 NTR↔NTR 带域名目标的 UDP 一直不通。
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
# C 方向用 python 探针:以 socks5 ATYP=3(域名)发目标(udpprobe 会先解析成 IP,测不到域名路径)
cp "$(dirname "$0")"/udpecho.py "$(dirname "$0")"/socksudp-cfg.py $D/ 2>/dev/null
docker run -d --name ${PFX}pyecho --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
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
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: mieru
    server: "${PFX}s:10818"
    transport: $t
    user: $U
    secret: "$P"
Y
  docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_miu_ntr.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 3; probe ${PFX}c:1080 "A-udp-$t"
}

# 方向 B:NTR mieru 服务端 + mihomo(socks-UDP → mieru UDP 客户端),探针打 mihomo socks。
dir_B(){ local t=$1
  cat > $D/_miu_nsrv.yaml <<Y
inbounds:
  - name: srv-in
    listen: 0.0.0.0:10818
    type: mieru
    transport: $t
    users:
      - name: $U
        password: "$P"
    outbound: direct
outbounds:
  - name: direct
    type: direct
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

# 方向 C:NTR mieru 服务端 + NTR(socks-UDP → mieru UDP 出站),探针目标为域名(${PFX}echo)。
dir_C(){ local t=$1
  cat > $D/_miu_nsrv.yaml <<Y
inbounds:
  - name: srv-in
    listen: 0.0.0.0:10818
    type: mieru
    transport: $t
    users:
      - name: $U
        password: "$P"
outbounds:
  - name: direct
    type: direct
Y
  docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_miu_nsrv.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  cat > $D/_miu_ntr.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: mieru
    server: "${PFX}s:10818"
    transport: $t
    user: $U
    secret: "$P"
Y
  docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_miu_ntr.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 3
  local out; out=$(docker run --rm --network $NET -e CLI=${PFX}c -e ECHO=${PFX}pyecho -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1)
  echo "$out"; echo "$out" | grep -q "GOT b'PINGUDP-ss-42'" && echo UDP-ECHO-OK
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
run "C NTRcli->NTRSrv(域名目标)" dir_C TCP
run "C NTRcli->NTRSrv(域名目标)" dir_C UDP
cleanup; echo DONE
