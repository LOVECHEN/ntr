#!/bin/bash
# Snell v4/v5 UDP 交叉验证:NTR snell v4/v5 UDP 客户端/服务端 <-> mihomo(唯一另一个 snell v4/v5 实现)。
# snell 闭源、xray/sing-box 无 snell,故仅 mihomo 可验(+ 进程内自环 udp_test.go 覆盖 v4/v5/v6)。
# 链路:socksudp.py -> socks/mixed 入站(UDP)-> snell UDP -> 对端 snell 服务端 -> udpecho。
set -u
NET=ix-snu; PFX=ixsnu-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; PSK=snellpsk0123456789abcdef
mkdir -p $D; cp "$(dirname "$0")"/udpecho.py "$(dirname "$0")"/socksudp-cfg.py $D/ 2>/dev/null
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
sleep 1
runudp(){ docker run --rm --network $NET -e CLI=$1 -e ECHO=${PFX}echo -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1; }

# NTR snell 服务端
ntr_srv(){ cat > "$2" <<Y
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: snell, psk: $PSK, version: $1}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
}
# NTR snell 客户端(socks 入站 UDP -> snell 出站)
ntr_cli(){ cat > "$2" <<Y
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}
outbounds:
  - {name: up, type: proxy, server: "${PFX}s:10000", layers: [{type: snell, psk: $PSK, version: $1}]}
Y
}
# mihomo snell 客户端(mixed 入站 UDP -> snell 代理 udp:true)
mi_cli(){ cat > "$2" <<Y
mixed-port: 1080
allow-lan: true
bind-address: "*"
log-level: warning
mode: rule
proxies:
  - {name: p, type: snell, server: ${PFX}s, port: 10000, psk: "$PSK", version: $1, udp: true}
rules: ["MATCH,p"]
Y
}
# mihomo snell 服务端(listener)
mi_srv(){ cat > "$2" <<Y
mixed-port: 7890
allow-lan: true
bind-address: "*"
log-level: warning
listeners:
  - {name: snell-in, type: snell, listen: 0.0.0.0, port: 10000, psk: "$PSK", version: $1}
proxies: []
rules: ["MATCH,DIRECT"]
Y
}
run_ntr(){ docker run -d --name $1 --network $NET -v $NTR:/ntr:ro -v $2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
run_mi(){ docker run -d --name $1 --network $NET -v $2:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1; }

# 方向1:mihomo snell client -> NTR snell server
dir_mi2ntr(){ local v=$1 sn=${PFX}s cn=${PFX}c
  docker rm -f $sn $cn >/dev/null 2>&1
  ntr_srv $v $D/_snu_s_$v.yaml; run_ntr $sn $D/_snu_s_$v.yaml; sleep 2
  mi_cli  $v $D/_snu_c_$v.yaml; run_mi  $cn $D/_snu_c_$v.yaml; sleep 3
  local out=$(runudp $cn)
  echo "$out" | grep -q "GOT b'PINGUDP-ss-42'" && echo "  [NTR-srv <- mihomo-cli / snell v$v UDP] PASS" \
    || { echo "  [NTR-srv <- mihomo-cli / snell v$v UDP] FAIL: $out"; docker logs $cn 2>&1|tail -2|sed 's/^/    CLI: /'; docker logs $sn 2>&1|tail -2|sed 's/^/    SRV: /'; }
  docker rm -f $sn $cn >/dev/null 2>&1
}
# 方向2:NTR snell client -> mihomo snell server
dir_ntr2mi(){ local v=$1 sn=${PFX}s cn=${PFX}c
  docker rm -f $sn $cn >/dev/null 2>&1
  mi_srv  $v $D/_snu_ms_$v.yaml; run_mi  $sn $D/_snu_ms_$v.yaml; sleep 3
  ntr_cli $v $D/_snu_nc_$v.yaml; run_ntr $cn $D/_snu_nc_$v.yaml; sleep 2
  local out=$(runudp $cn)
  echo "$out" | grep -q "GOT b'PINGUDP-ss-42'" && echo "  [mihomo-srv <- NTR-cli / snell v$v UDP] PASS" \
    || { echo "  [mihomo-srv <- NTR-cli / snell v$v UDP] FAIL: $out"; docker logs $cn 2>&1|tail -2|sed 's/^/    CLI: /'; docker logs $sn 2>&1|tail -2|sed 's/^/    SRV: /'; }
  docker rm -f $sn $cn >/dev/null 2>&1
}

for v in 4 5; do dir_mi2ntr $v; dir_ntr2mi $v; done
# v3:NTR 仅服务端 UDP(v1/v2 无 UDP;NTR v3 客户端 UDP 后续)→ 只验 mihomo v3 客户端 → NTR v3 服务端
dir_mi2ntr 3
cleanup; echo DONE
