#!/bin/bash
# SOCKS 出站三家交叉验证:NTR 作 SOCKS5 出站(proxy.Client + PacketConnClient)-> {xray,mihomo,singbox}
# 的 SOCKS 入站 -> 目标。TCP:curl 经 NTR socks-in -> NTR socks-out -> 真 socks 服务端 -> whoami。
# UDP:socksudp.py -> NTR socks-in(associate)-> NTR socks-out(associate)-> 真 socks 服务端 -> udpecho。
set -u
NET=ix-sko; PFX=ixko-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
mkdir -p $D; cp "$(dirname "$0")"/udpecho.py "$(dirname "$0")"/socksudp-cfg.py $D/ 2>/dev/null
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
docker run -d --name ${PFX}echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
sleep 1

# NTR 客户端:socks 入站 :1080 -> socks 出站到真服务端 $1:10000
ntr_cli(){ cat > "$2" <<Y
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}
outbounds:
  - {name: up, type: proxy, server: "$1:10000", layers: [{type: socks}]}
Y
}
# 真服务端:socks 入站(no-auth,含 UDP)-> direct/freedom
xray_srv(){ cat > "$1" <<J
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":10000,"protocol":"socks","settings":{"udp":true,"auth":"noauth"}}],"outbounds":[{"protocol":"freedom"}]}
J
}
mihomo_srv(){ cat > "$1" <<EOF
log-level: warning
listeners:
  - {name: in, type: socks, listen: 0.0.0.0, port: 10000, udp: true}
EOF
}
singbox_srv(){ cat > "$1" <<J
{"log":{"level":"error"},"inbounds":[{"type":"socks","listen":"0.0.0.0","listen_port":10000}],"outbounds":[{"type":"direct"}]}
J
}

runudp(){ docker run --rm --network $NET -e CLI=$1 -e ECHO=${PFX}echo -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1; }
runtcp(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 6 -x socks5h://$1:1080 http://${PFX}target/ 2>/dev/null; }

test_case(){ # $1 srv-eng
  local sn=${PFX}s cn=${PFX}c scfg=$D/_sko_s_$1.cfg ccfg=$D/_sko_c_$1.cfg
  docker rm -f $sn $cn >/dev/null 2>&1
  ${1}_srv "$scfg"
  case $1 in
    xray)    docker run -d --name $sn --network $NET -v $scfg:/cfg.json:ro ghcr.io/xtls/xray-core:latest run -c /cfg.json >/dev/null 2>&1;;
    mihomo)  docker run -d --name $sn --network $NET -v $scfg:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1;;
    singbox) docker run -d --name $sn --network $NET -v $scfg:/etc/sing-box/config.json:ro ghcr.io/sagernet/sing-box:latest run -c /etc/sing-box/config.json >/dev/null 2>&1;;
  esac
  sleep 2
  ntr_cli $sn "$ccfg"
  docker run -d --name $cn --network $NET -v $NTR:/ntr:ro -v $ccfg:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 2
  local t=$(runtcp $cn) u=$(runudp $cn) tok=FAIL uok=FAIL
  echo "$t" | grep -q Hostname && tok=PASS
  echo "$u" | grep -q "GOT b'PINGUDP-ss-42'" && uok=PASS
  echo "  [NTR socks-out -> $1]  TCP=$tok  UDP=$uok"
  [ $tok = FAIL ] && { docker logs $cn 2>&1 | tail -2 | sed 's/^/    CLI: /'; docker logs $sn 2>&1 | tail -2 | sed 's/^/    SRV: /'; }
  [ $uok = FAIL ] && echo "    UDP out: $u" | tail -1
  docker rm -f $sn $cn >/dev/null 2>&1
}

for e in xray mihomo singbox; do test_case $e; done
cleanup; echo DONE
