#!/bin/bash
# SSR 服务端交叉验证:mihomo ssr 客户端 → NTR ssr 服务端(自写服务端逆向:plain obfs +
# origin/auth_aes128_sha1/auth_aes128_md5 protocol,对称 stream cipher)。三家引擎无 SSR 服务端,
# 故以 mihomo ssr 客户端验证 NTR 服务端(补齐 SSR 反向)。禁改线格式。
# ★配置文件用唯一名(避 OrbStack 落盘竞态导致的半写 YAML)。
set -u
NET=ix-ssrsv; PFX=ixssrsv-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; PW="ssr-srv-pass"
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

test_combo(){ # $1=cipher $2=protocol $3=obfs
  local tag="${1}_${2}_${3}" nsrv mcli
  nsrv=$D/_ssrsv_n_${tag}.yaml; mcli=$D/_ssrsv_m_${tag}.yaml
  cat > "$nsrv" <<Y
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: ssr, cipher: $1, password: "$PW", protocol: $2, obfs: $3}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
  cat > "$mcli" <<Y
mixed-port: 1080
allow-lan: true
bind-address: '*'
mode: global
log-level: warning
proxies:
  - {name: ssr, type: ssr, server: ${PFX}s, port: 10000, cipher: $1, password: "$PW", protocol: $2, protocol-param: '', obfs: $3, obfs-param: ''}
proxy-groups:
  - {name: GLOBAL, type: select, proxies: [ssr]}
Y
  sync; sleep 0.3
  docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
  docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v "$nsrv":/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 2
  docker run -d --name ${PFX}c --network $NET -v "$mcli":/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1
  sleep 3
  local ok=FAIL i
  for i in 1 2 3 4; do
    r=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>/dev/null)
    echo "$r" | grep -q Hostname && { ok=PASS; break; }; sleep 1
  done
  printf "  [mihomo ssr-cli(%s/%s/%s) -> NTR ssr-srv]  %s\n" "$1" "$2" "$3" "$ok"
  [ $ok = FAIL ] && { docker logs ${PFX}s 2>&1|tail -2|sed 's/^/    NTRsrv:/'; docker logs ${PFX}c 2>&1|tail -2|sed 's/^/    MHcli:/'; }
  docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
  rm -f "$nsrv" "$mcli"
}

test_combo aes-256-cfb   origin           plain
test_combo aes-256-cfb   auth_aes128_sha1 plain
test_combo rc4-md5       auth_aes128_md5  plain
test_combo chacha20-ietf auth_aes128_sha1 plain
test_combo aes-256-cfb   origin           http_simple
test_combo aes-256-cfb   auth_aes128_sha1 http_simple
test_combo rc4-md5       auth_aes128_md5  http_simple
test_combo aes-256-cfb   auth_aes128_md5  http_post
test_combo aes-256-cfb   auth_aes128_sha1 random_head
test_combo aes-256-cfb   auth_sha1_v4     plain
test_combo rc4-md5       auth_sha1_v4     http_simple
test_combo aes-256-cfb   auth_chain_a     plain
test_combo rc4-md5       auth_chain_a     http_simple
test_combo aes-256-cfb   auth_chain_b     plain
test_combo chacha20-ietf auth_chain_b     random_head
test_combo aes-256-cfb   origin           tls1.2_ticket_auth
test_combo aes-256-cfb   auth_aes128_sha1 tls1.2_ticket_auth
test_combo rc4-md5       auth_chain_a     tls1.2_ticket_auth
cleanup; echo DONE
