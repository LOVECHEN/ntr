#!/bin/bash
# SS UDP 入站三家交叉验证:NTR 作 SS UDP server(PacketServer)<- {xray,mihomo,singbox} SS UDP client -> udpecho。
# 两代加密都测:经典 aes-256-gcm + 2022-blake3-aes-128-gcm,覆盖服务端两条 headroom 路径。
# 链路:socksudp.py -> 真核 socks/mixed 入站(UDP)-> 真核 SS 出站 -> NTR SS 服务端(原生 UDP)-> echo。
set -u
NET=ix-ssui; PFX=ixsi-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
PW_CLASSIC=mypassword123
PW_2022=$(head -c16 /dev/zero | base64)
mkdir -p $D; cp "$(dirname "$0")"/udpecho.py "$(dirname "$0")"/socksudp-cfg.py $D/ 2>/dev/null
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
sleep 1

# NTR SS 服务端(原生 UDP 入站)。★写到 $4(带 cipher 的唯一文件名),避免原地截断同名文件时
# OrbStack 文件同步延迟导致容器读到半写配置的竞态。
ntr_srv(){ cat > "$3" <<Y
inbounds:
  - name: srv-in
    type: shadowsocks
    listen: 0.0.0.0:10000
    method: $1
    password: "$2"
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
}
# 各核 SS UDP 客户端(socks/mixed 入站 -> SS 出站,指向 NTR 服务端 $3);写到 $4(带 cipher 唯一名)。
xray_cli(){ cat > "$4" <<J
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{"address":"$3","port":10000,"method":"$1","password":"$2"}]}}]}
J
}
mihomo_cli(){ cat > "$4" <<EOF
mixed-port: 1080
allow-lan: true
bind-address: "*"
log-level: warning
proxies: [{name: p, type: ss, server: $3, port: 10000, cipher: $1, password: "$2", udp: true}]
rules:
  - MATCH,p
EOF
}
singbox_cli(){ cat > "$4" <<J
{"log":{"level":"error"},"inbounds":[{"type":"mixed","listen":"0.0.0.0","listen_port":1080}],"outbounds":[{"type":"shadowsocks","server":"$3","server_port":10000,"method":"$1","password":"$2"}]}
J
}
runudp(){ docker run --rm --network $NET -e CLI=$1 -e ECHO=${PFX}echo -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1; }

test_case(){ # $1 cli-eng $2 cipher $3 pw
  local sn=${PFX}s cn=${PFX}c ctag=$(echo "$2" | tr -d '-') scfg
  scfg=$D/_ssi_s_${1}_${ctag}.cfg
  docker rm -f $sn $cn >/dev/null 2>&1
  ntr_srv "$2" "$3" "$scfg"
  docker run -d --name $sn --network $NET -v $NTR:/ntr:ro -v $scfg:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 2
  local ccfg=$D/_ssi_c_${1}_${ctag}.cfg
  ${1}_cli "$2" "$3" $sn "$ccfg"
  case $1 in
    xray)    docker run -d --name $cn --network $NET -v $ccfg:/cfg.json:ro ghcr.io/xtls/xray-core:latest run -c /cfg.json >/dev/null 2>&1;;
    mihomo)  docker run -d --name $cn --network $NET -v $ccfg:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1;;
    singbox) docker run -d --name $cn --network $NET -v $ccfg:/etc/sing-box/config.json:ro ghcr.io/sagernet/sing-box:latest run -c /etc/sing-box/config.json >/dev/null 2>&1;;
  esac
  sleep 2
  local out=$(runudp $cn)
  if echo "$out" | grep -q "GOT b'PINGUDP-ss-42'"; then echo "  [NTR <- $1 / $2] ==> PASS"
  else echo "  [NTR <- $1 / $2] ==> FAIL: $out"; docker logs $cn 2>&1 | tail -3 | sed 's/^/    CLI: /'; docker logs $sn 2>&1 | tail -3 | sed 's/^/    SRV: /'; fi
  docker rm -f $sn $cn >/dev/null 2>&1
}

echo "== 经典 shadowaead (aes-256-gcm) =="
for e in xray mihomo singbox; do test_case $e aes-256-gcm "$PW_CLASSIC"; done
echo "== 2022 shadowaead_2022 (2022-blake3-aes-128-gcm) =="
for e in xray mihomo singbox; do test_case $e 2022-blake3-aes-128-gcm "$PW_2022"; done
cleanup; echo DONE
