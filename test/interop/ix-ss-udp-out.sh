#!/bin/bash
# SS UDP 出站三家交叉验证:NTR 作 SS UDP client(NativePacketConnClient)-> {xray,mihomo,singbox} SS server -> udpecho。
# 两代加密都测:经典 aes-256-gcm(shadowaead)+ 2022-blake3-aes-128-gcm(shadowaead_2022),覆盖两条 headroom 路径。
# 链路:socksudp.py -> NTR socks 入站(UDP associate)-> NTR up 出站(SS UDP)-> 真 SS 服务端 -> echo。
set -u
NET=ix-ssuo; PFX=ixso-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
# 2022 密钥须是 base64(16B for aes-128);经典口令任意。
PW_CLASSIC=mypassword123
PW_2022=$(head -c16 /dev/zero | base64) # 16 字节全零的 base64,两端同值即可
mkdir -p $D; cp "$(dirname "$0")"/udpecho.py "$(dirname "$0")"/socksudp-cfg.py $D/ 2>/dev/null # 自举 helper 到 $D
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
sleep 1

ntr_cli(){ cat > $D/_sso_c.cfg <<Y
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}
outbounds:
  - {name: up, type: proxy, server: "$3:10000", layers: [{type: shadowsocks, method: $1, password: "$2"}]}
Y
}
# ★ 每引擎独立配置文件名:避免原地截断同名文件时 OrbStack 文件同步延迟导致容器读到空文件的竞态。
xray_srv(){ cat > $D/_sso_s_xray.cfg <<J
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":10000,"protocol":"shadowsocks","settings":{"method":"$1","password":"$2","network":"tcp,udp"}}],"outbounds":[{"protocol":"freedom"}]}
J
}
mihomo_srv(){ cat > $D/_sso_s_mihomo.cfg <<EOF
log-level: warning
listeners:
  - {name: in, type: shadowsocks, listen: 0.0.0.0, port: 10000, password: "$2", cipher: $1, udp: true}
EOF
}
singbox_srv(){ cat > $D/_sso_s_singbox.cfg <<J
{"log":{"level":"error"},"inbounds":[{"type":"shadowsocks","listen":"0.0.0.0","listen_port":10000,"method":"$1","password":"$2"}],"outbounds":[{"type":"direct"}]}
J
}

srv_up(){ local eng=$1 c=$2 p=$3 sn=${PFX}s
  docker rm -f $sn >/dev/null 2>&1
  ${eng}_srv "$c" "$p"
  case $eng in
    xray)    docker run -d --name $sn --network $NET -v $D/_sso_s_xray.cfg:/cfg.json:ro ghcr.io/xtls/xray-core:latest run -c /cfg.json >/dev/null 2>&1;;
    mihomo)  docker run -d --name $sn --network $NET -v $D/_sso_s_mihomo.cfg:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1;;
    singbox) docker run -d --name $sn --network $NET -v $D/_sso_s_singbox.cfg:/etc/sing-box/config.json:ro ghcr.io/sagernet/sing-box:latest run -c /etc/sing-box/config.json >/dev/null 2>&1;;
  esac
  sleep 2
}
runudp(){ docker run --rm --network $NET -e CLI=$1 -e ECHO=${PFX}echo -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1; }

test_case(){ # $1 srv-eng $2 cipher $3 pw
  local sn=${PFX}s cn=${PFX}c
  srv_up "$1" "$2" "$3"
  ntr_cli "$2" "$3" $sn
  docker rm -f $cn >/dev/null 2>&1
  docker run -d --name $cn --network $NET -v $NTR:/ntr:ro -v $D/_sso_c.cfg:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 2
  local out=$(runudp $cn)
  if echo "$out" | grep -q "GOT b'PINGUDP-ss-42'"; then echo "  [$1 <- NTR / $2] ==> PASS"
  else echo "  [$1 <- NTR / $2] ==> FAIL: $out"; docker logs $cn 2>&1 | tail -3 | sed 's/^/    CLI: /'; docker logs $sn 2>&1 | tail -3 | sed 's/^/    SRV: /'; fi
  docker rm -f $sn $cn >/dev/null 2>&1
}

echo "== 经典 shadowaead (aes-256-gcm) =="
for e in xray mihomo singbox; do test_case $e aes-256-gcm "$PW_CLASSIC"; done
echo "== 2022 shadowaead_2022 (2022-blake3-aes-128-gcm) =="
for e in xray mihomo singbox; do test_case $e 2022-blake3-aes-128-gcm "$PW_2022"; done
cleanup; echo DONE
