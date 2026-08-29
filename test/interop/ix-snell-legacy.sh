#!/bin/bash
# Snell v1/v2/v3(旧版,shadowsocks-AEAD 分帧)交叉验证。sing-box/xray 无 snell;mihomo 支持 version 1-5。
#   对每个 v ∈ {1,2,3}:
#     A. mihomo snell 客户端(version v)→ NTR snell 服务端(version v)  [验 NTR 服务端 vs mihomo 逐字节]
#     B. NTR snell 客户端(version v)→ NTR snell 服务端(version v)     [自环,验 NTR 客户端+服务端]
# cipher 由版本定:v1=chacha20-ietf-poly1305,v2/v3=aes-128-gcm(两端自动一致)。仅 TCP(v1/v2 无 UDP)。
set -u
NET=ix-snl; PFX=ixsnl-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; PSK=snelllegacypsk123
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

ntr(){ docker run -d --name $1 --network $NET -v $NTR:/ntr:ro -v $2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
mihomo(){ docker run -d --name $1 --network $NET -v $2:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1; }
pull(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://$1:1080 http://${PFX}target/ 2>/dev/null; }

test_ver(){ # $1 = version
  local v=$1
  cat > $D/_snl_srv.yaml <<Y
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: snell, psk: $PSK, version: $v}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
  cat > $D/_snl_ntrcli.yaml <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}]
outbounds:
  - {name: up, type: proxy, server: "${PFX}s:10000", layers: [{type: snell, psk: $PSK, version: $v}]}
Y
  cat > $D/_snl_micli.yaml <<Y
log-level: warning
mixed-port: 1080
allow-lan: true
proxies:
  - {name: p, type: snell, server: ${PFX}s, port: 10000, psk: "$PSK", version: $v}
rules: ["MATCH,p"]
Y
  # A. mihomo 客户端 → NTR 服务端
  docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
  ntr ${PFX}s $D/_snl_srv.yaml; sleep 2
  mihomo ${PFX}c $D/_snl_micli.yaml; sleep 2
  local a=FAIL i; for i in 1 2 3 4 5; do echo "$(pull ${PFX}c)" | grep -q Hostname && { a=PASS; break; }; sleep 1; done
  echo "  [v$v A. mihomo 客户端 → NTR 服务端]  $a"
  [ $a = FAIL ] && { docker logs ${PFX}c 2>&1|tail -2|sed 's/^/     mi:/'; docker logs ${PFX}s 2>&1|tail -2|sed 's/^/     ntr:/'; }
  # B. NTR 客户端 → NTR 服务端(自环)
  docker rm -f ${PFX}c >/dev/null 2>&1
  ntr ${PFX}c $D/_snl_ntrcli.yaml; sleep 2
  local b=FAIL; for i in 1 2 3 4 5; do echo "$(pull ${PFX}c)" | grep -q Hostname && { b=PASS; break; }; sleep 1; done
  echo "  [v$v B. NTR 客户端 → NTR 服务端(自环)]  $b"
  [ $b = FAIL ] && { docker logs ${PFX}c 2>&1|tail -2|sed 's/^/     ntrcli:/'; docker logs ${PFX}s 2>&1|tail -2|sed 's/^/     ntrsrv:/'; }
}

for v in 1 2 3; do echo "=== Snell v$v ==="; test_ver $v; done
cleanup; echo DONE