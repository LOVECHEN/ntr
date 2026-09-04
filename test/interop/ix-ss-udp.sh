#!/bin/bash
# 组3 SS UDP:socks UDP associate -> SS 隧道 -> udpecho。验 NTR 作 SS client / server 的 UDP。
set -u
NET=ix-ss; PFX=ixs-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; CPW=mypassword123; C=aes-256-gcm
mkdir -p $D; cp "$(dirname "$0")"/udpecho.py "$(dirname "$0")"/socksudp-cfg.py $D/ 2>/dev/null # 自举 helper 到 $D
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
sleep 1

ntr_srv(){ cat > $D/_udp_s.cfg <<Y
inbounds:
  - name: srv-in
    type: shadowsocks
    listen: 0.0.0.0:10000
    method: $C
    password: "$CPW"
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
}
ntr_cli(){ cat > $D/_udp_c.cfg <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: shadowsocks
    server: "$1:10000"
    method: $C
    password: "$CPW"
Y
}
xray_srv(){ cat > $D/_udp_s.cfg <<J
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":10000,"protocol":"shadowsocks","settings":{"method":"$C","password":"$CPW","network":"tcp,udp"}}],"outbounds":[{"protocol":"freedom"}]}
J
}
xray_cli(){ cat > $D/_udp_c.cfg <<J
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{"address":"$1","port":10000,"method":"$C","password":"$CPW"}]}}]}
J
}
runudp(){ docker run --rm --network $NET -e CLI=$1 -e ECHO=${PFX}echo -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1; }

test_case(){ # $1 label $2 srv(ntr/xray) $3 cli(ntr/xray)
  local sn=${PFX}us cn=${PFX}uc
  docker rm -f $sn $cn >/dev/null 2>&1
  ${2}_srv; if [ "$2" = ntr ]; then docker run -d --name $sn --network $NET -v $NTR:/ntr:ro -v $D/_udp_s.cfg:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  else docker run -d --name $sn --network $NET -v $D/_udp_s.cfg:/cfg.json:ro ghcr.io/xtls/xray-core:latest run -c /cfg.json >/dev/null 2>&1; fi
  sleep 2
  ${3}_cli $sn; if [ "$3" = ntr ]; then docker run -d --name $cn --network $NET -v $NTR:/ntr:ro -v $D/_udp_c.cfg:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  else docker run -d --name $cn --network $NET -v $D/_udp_c.cfg:/cfg.json:ro ghcr.io/xtls/xray-core:latest run -c /cfg.json >/dev/null 2>&1; fi
  sleep 2
  local out=$(runudp $cn); echo "  [$1] $out"
  echo "$out" | grep -q "GOT b'PINGUDP-ss-42'" && echo "  ==> PASS" || { echo "  ==> FAIL"; docker logs $cn 2>&1 | tail -3 | sed 's/^/    CLI: /'; }
  docker rm -f $sn $cn >/dev/null 2>&1
}
echo "== sanity: xray srv <- xray cli (证 harness 对) =="; test_case "xray<-xray" xray xray
echo "== NTR client UDP: xray srv <- NTR cli =="; test_case "xray<-NTR" xray ntr
echo "== NTR server UDP: NTR srv <- xray cli =="; test_case "NTR<-xray" ntr xray
cleanup; echo DONE
