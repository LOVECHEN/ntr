#!/bin/bash
# mieru 交叉验证(双向 × TCP/UDP 传输):NTR mieru <-> mihomo mieru。
# mihomo 是三家中唯一实现 mieru 的(client+listener)。NTR 客户端+服务端均用官方库 enfein/mieru/v3
# (mihomo 同库),禁改线格式。用户名+口令认证。
#   A: NTR mieru 客户端 → mihomo mieru 入站监听
#   B: mihomo mieru 客户端 → NTR mieru 入站监听
set -u
NET=ix-mieru; PFX=ixmi-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; U=mieruuser; P=mierupass123
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

# ---- 服务端 ----
mihomo_srv(){ local f=$D/_mi_msrv.yaml t=$1  # $1=transport
  cat > "$f" <<Y
mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: warning
listeners:
  - {name: mieru-in, type: mieru, port: 10818, listen: 0.0.0.0, transport: $t, users: {$U: $P}}
rules:
  - MATCH,DIRECT
Y
  docker rm -f ${PFX}s >/dev/null 2>&1
  docker run -d --name ${PFX}s --network $NET -v "$f":/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1
}
ntr_srv(){ local f=$D/_mi_nsrv.yaml t=$1
  cat > "$f" <<Y
inbounds:
  - listen: 0.0.0.0:10818
    type: mieru
    transport: $t
    users: [{name: $U, password: "$P"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
  docker rm -f ${PFX}s >/dev/null 2>&1
  docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v "$f":/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
}

# ---- 客户端(socks 1080 → mieru 出站 → ${PFX}s:10818)----
ntr_cli(){ local f=$D/_mi_ncli.yaml t=$1
  cat > "$f" <<Y
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}
outbounds:
  - {name: up, type: mieru, server: "${PFX}s:10818", transport: $t, user: $U, secret: "$P"}
Y
  docker rm -f ${PFX}c >/dev/null 2>&1
  docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v "$f":/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
}
mihomo_cli(){ local f=$D/_mi_mcli.yaml t=$1
  cat > "$f" <<Y
mixed-port: 1080
allow-lan: true
bind-address: '*'
mode: global
log-level: warning
proxies:
  - {name: mieru, type: mieru, server: ${PFX}s, port: 10818, transport: $t, username: $U, password: "$P"}
proxy-groups:
  - {name: GLOBAL, type: select, proxies: [mieru]}
Y
  docker rm -f ${PFX}c >/dev/null 2>&1
  docker run -d --name ${PFX}c --network $NET -v "$f":/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1
}

runtcp(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>/dev/null; }

test_dir(){ # $1=label $2=srv-fn $3=cli-fn $4=transport
  echo "### $1 / transport $4"
  $2 "$4"; sleep 3
  $3 "$4"; sleep 3
  local ok=FAIL i; for i in 1 2 3 4 5; do echo "$(runtcp)" | grep -q Hostname && { ok=PASS; break; }; sleep 1; done
  printf "  [%s / %s]  %s\n" "$1" "$4" "$ok"
  [ $ok = FAIL ] && { docker logs ${PFX}c 2>&1|tail -2|sed 's/^/    CLI:/'; docker logs ${PFX}s 2>&1|tail -2|sed 's/^/    SRV:/'; }
  docker rm -f ${PFX}c ${PFX}s >/dev/null 2>&1
}

test_dir "A NTRcli->mihomoSrv"  mihomo_srv ntr_cli    TCP
test_dir "A NTRcli->mihomoSrv"  mihomo_srv ntr_cli    UDP
test_dir "B mihomoCli->NTRSrv"  ntr_srv    mihomo_cli TCP
test_dir "B mihomoCli->NTRSrv"  ntr_srv    mihomo_cli UDP
cleanup; echo DONE
