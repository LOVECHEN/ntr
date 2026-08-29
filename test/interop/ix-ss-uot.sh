#!/bin/bash
# Shadowsocks UDP-over-TCP(UoT)交叉验证:NTR SS-UoT 客户端 → sing-box / mihomo SS 服务端。
# NTR 出站 udp-over-tcp:出站 UDP 另拨 SS 流到 uot 魔术地址(sp.v2.udp-over-tcp.arpa),流内 uot 分帧承载
# 多目标 UDP;服务端自动检测魔术地址走 UoT。用 UDP-over-socks5 探针驱动 NTR socks-UDP 入站。禁改线格式。
set -u
NET=ix-uot; PFX=ixuot-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; M="aes-256-gcm"; PW64=$(printf 'ss-uot-pass-32byte-key-abcdefgh' | base64 | tr -d '\n')
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
H="$(cd "$(dirname "$0")" && pwd)/helpers"
[ -x $D/udpprobe ] || CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $D/udpprobe "$H/udpprobe.go"
[ -x $D/udpecho ]  || CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $D/udpecho  "$H/udpecho.go"
docker run -d --name ${PFX}echo --network $NET -v $D/udpecho:/udpecho:ro alpine /udpecho >/dev/null 2>&1
# 用短口令 method(经典 AEAD 密码即口令,非 base64 key)——避免 2022 的 key 格式
PW="ss-uot-secret-pw"
sleep 1

singbox_srv(){ cat > $D/_uot_sbsrv.json <<J
{"log":{"level":"error"},"inbounds":[{"type":"shadowsocks","listen":"::","listen_port":10000,"method":"$M","password":"$PW"}],"outbounds":[{"type":"direct"}]}
J
  docker run -d --name ${PFX}s --network $NET -v $D/_uot_sbsrv.json:/c.json:ro ghcr.io/sagernet/sing-box:latest run -c /c.json >/dev/null 2>&1; }
mihomo_srv(){ cat > $D/_uot_msrv.yaml <<Y
mixed-port: 7890
log-level: warning
listeners:
  - {name: ssin, type: shadowsocks, listen: 0.0.0.0, port: 10000, cipher: $M, password: "$PW", udp: true}
Y
  docker run -d --name ${PFX}s --network $NET -v $D/_uot_msrv.yaml:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1; }

ntr_cli(){ cat > $D/_uot_ncli.yaml <<Y
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}
outbounds:
  - {name: up, type: proxy, server: "${PFX}s:10000", layers: [{type: shadowsocks, method: $M, password: "$PW", udp-over-tcp: true}]}
Y
  docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_uot_ncli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }

# ---- 方向 B:NTR SS 服务端(自动检测 UoT)+ 对端 SS-UoT 客户端 ----
ntr_srv(){ cat > $D/_uot_nsrv.yaml <<Y
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: shadowsocks, method: $M, password: "$PW"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
  docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_uot_nsrv.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
singbox_cli(){ cat > $D/_uot_sbcli.json <<J
{"log":{"level":"error"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"shadowsocks","server":"${PFX}s","server_port":10000,"method":"$M","password":"$PW","udp_over_tcp":true}]}
J
  docker run -d --name ${PFX}c --network $NET -v $D/_uot_sbcli.json:/c.json:ro ghcr.io/sagernet/sing-box:latest run -c /c.json >/dev/null 2>&1; }
mihomo_cli(){ cat > $D/_uot_mcli.yaml <<Y
mixed-port: 1080
allow-lan: true
bind-address: '*'
log-level: warning
proxies:
  - {name: p, type: ss, server: ${PFX}s, port: 10000, cipher: $M, password: "$PW", udp: true, udp-over-tcp: true}
rules: ["MATCH,p"]
Y
  docker run -d --name ${PFX}c --network $NET -v $D/_uot_mcli.yaml:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1; }

probe(){ docker run --rm --network $NET -v $D/udpprobe:/udpprobe:ro alpine /udpprobe ${PFX}c:1080 ${PFX}echo:5353 "$1" 2>&1; }
test_dir(){ # $1=label $2=srv-fn $3=cli-fn
  docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
  $2; sleep 3; $3; sleep 3
  local ok=FAIL i out; for i in 1 2 3 4; do out=$(probe "uot-$1"); echo "$out"|grep -q UDP-ECHO-OK && { ok=PASS; break; }; sleep 1; done
  printf "  [%s]  %s\n" "$1" "$ok"
  [ $ok = PASS ] || { echo "$out"|sed 's/^/    PROBE:/'; docker logs ${PFX}c 2>&1|tail -2|sed 's/^/    C:/'; docker logs ${PFX}s 2>&1|tail -2|sed 's/^/    S:/'; }
  docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1; }

test_dir "A NTR-UoT-cli -> sing-box SS-srv" singbox_srv ntr_cli
test_dir "A NTR-UoT-cli -> mihomo SS-srv"   mihomo_srv  ntr_cli
test_dir "B sing-box UoT-cli -> NTR SS-srv" ntr_srv singbox_cli
test_dir "B mihomo UoT-cli -> NTR SS-srv"   ntr_srv mihomo_cli
cleanup; echo DONE
