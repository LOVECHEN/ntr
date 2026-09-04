#!/bin/bash
# ShadowsocksR(SSR)交叉验证:NTR ssr 客户端 → 参考 SSR 服务端(teddysun/shadowsocks-r,即
# shadowsocksr 原版 Python 实现)。并以 mihomo ssr 客户端 → 同服务端 作对照,证 NTR≡mihomo 客户端。
# 三家引擎(xray/sing-box/mihomo)均无 SSR 入站,故 SSR 服务端用其原生参考实现验证(同 mtproto 用 mtg)。
# 底层 obfs/protocol/stream-cipher vendored 自 mihomo,禁改线格式。
set -u
NET=ix-ssr; PFX=ixssr-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; PW="ssr-pass-42"
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

# 参考 SSR 服务端(Python shadowsocksr)。$1=cipher $2=protocol $3=obfs
ssr_server(){ local f=$D/_ssr_srv.json
  cat > "$f" <<J
{"server":"0.0.0.0","server_port":9000,"password":"$PW","timeout":120,"method":"$1","protocol":"$2","protocol_param":"","obfs":"$3","obfs_param":"","fast_open":false,"workers":1}
J
  docker rm -f ${PFX}s >/dev/null 2>&1
  docker run -d --name ${PFX}s --network $NET -v "$f":/etc/shadowsocks-r/config.json:ro teddysun/shadowsocks-r >/dev/null 2>&1
}

# NTR ssr 客户端:socks 入站 → ssr 出站。$1=cipher $2=protocol $3=obfs
ntr_client(){ local f=$D/_ssr_ntr.yaml
  cat > "$f" <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: ssr
    server: "${PFX}s:9000"
    cipher: $1
    password: "$PW"
    protocol: $2
    obfs: $3
Y
  docker rm -f ${PFX}c >/dev/null 2>&1
  docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v "$f":/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
}

# mihomo ssr 客户端(对照)。$1=cipher $2=protocol $3=obfs
mihomo_client(){ local f=$D/_ssr_mh.yaml
  cat > "$f" <<Y
mixed-port: 1080
allow-lan: true
bind-address: '*'
mode: global
log-level: warning
proxies:
  - {name: ssr, type: ssr, server: ${PFX}s, port: 9000, cipher: $1, password: "$PW", protocol: $2, protocol-param: '', obfs: $3, obfs-param: ''}
proxy-groups:
  - {name: GLOBAL, type: select, proxies: [ssr]}
Y
  docker rm -f ${PFX}c >/dev/null 2>&1
  docker run -d --name ${PFX}c --network $NET -v "$f":/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1
}

runtcp(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>/dev/null; }

test_combo(){ # $1=cipher $2=protocol $3=obfs
  echo "### combo: $1 / $2 / $3"
  ssr_server "$1" "$2" "$3"; sleep 2
  for eng in ntr mihomo; do
    ${eng}_client "$1" "$2" "$3"; sleep 2
    local ok=FAIL i; for i in 1 2 3 4; do echo "$(runtcp)" | grep -q Hostname && { ok=PASS; break; }; sleep 1; done
    printf "  [%-7s ssr-cli -> ref-ssr-srv]  %s\n" "$eng" "$ok"
    [ $ok = FAIL ] && { docker logs ${PFX}c 2>&1|tail -2|sed 's/^/    CLI:/'; docker logs ${PFX}s 2>&1|tail -2|sed 's/^/    SRV:/'; }
    docker rm -f ${PFX}c >/dev/null 2>&1
  done
  docker rm -f ${PFX}s >/dev/null 2>&1
}

test_combo aes-256-cfb    origin            plain
test_combo aes-256-cfb    auth_aes128_sha1  tls1.2_ticket_auth
test_combo rc4-md5        auth_aes128_md5   http_simple
test_combo chacha20-ietf  auth_chain_a      plain
cleanup; echo DONE
