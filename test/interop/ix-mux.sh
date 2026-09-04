#!/bin/bash
# sing 家族 mux(h2mux/smux/yamux)双向交叉验证:base=vless(plain),mux 包在其上。
# NTR mux 客户端(outbound.mux)<-> {sing-box, mihomo} mux;NTR mux 服务端(service/mux.go 自动解复用)。
# xray 用自家 mux.cool(非 sing-mux),不在本互通范围。链路:curl -x socks5h -> 入站 -> vless+mux -> 出站 -> whoami。
# ★NTR_BIN 必须用 build.sh(或 -tags http2legacy)构建:h2mux 客户端走 x/net/http2,Go 1.27 起 x/net 默认转发
#   标准库 net/http,后者拒 sing-mux 的 nil Request.Header → h2mux 客户端 FAIL(smux/yamux 不受影响)。普通
#   `go build` 出的二进制会让 h2mux 客户端向失败;release build.sh 已带该 tag,故正式产物 12/12 全通。
set -u
NET=ix-mux; PFX=ixm-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; UUID="11111111-1111-1111-1111-111111111111"
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

# --- 配置生成(每引擎+角色+协议唯一文件名,避 OrbStack 原地截断竞态)---
ntr_cli(){ cat > "$3" <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: vless
    server: "$1:10000"
    secret: "$UUID"
    mux:
      protocol: $2
Y
}
ntr_srv(){ cat > "$2" <<Y
inbounds:
  - name: srv-in
    type: vless
    listen: 0.0.0.0:10000
    users:
      - uuid: "$UUID"
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
}
singbox_cli(){ cat > "$3" <<J
{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"vless","server":"$1","server_port":10000,"uuid":"$UUID","multiplex":{"enabled":true,"protocol":"$2","max_connections":4,"padding":false}}]}
J
}
singbox_srv(){ cat > "$2" <<J
{"log":{"level":"warn"},"inbounds":[{"type":"vless","listen":"::","listen_port":10000,"users":[{"uuid":"$UUID"}],"multiplex":{"enabled":true}}],"outbounds":[{"type":"direct"}]}
J
}
mihomo_cli(){ cat > "$3" <<EOF
log-level: warning
mixed-port: 1080
allow-lan: true
proxies:
  - {name: o, type: vless, server: $1, port: 10000, uuid: $UUID, network: tcp, udp: true, smux: {enabled: true, protocol: $2}}
rules:
  - MATCH,o
EOF
}
mihomo_srv(){ cat > "$2" <<EOF
log-level: warning
listeners:
  - {name: vless-in, type: vless, port: 10000, listen: 0.0.0.0, allow-insecure: true, users: [{username: u, uuid: $UUID}]}
EOF
}

start_srv(){ local eng=$1 f=$2 sn=${PFX}s; docker rm -f $sn >/dev/null 2>&1
  case $eng in
    ntr)     docker run -d --name $sn --network $NET -v $NTR:/ntr:ro -v $f:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1;;
    mihomo)  docker run -d --name $sn --network $NET -v $f:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1;;
    singbox) docker run -d --name $sn --network $NET -v $f:/etc/sing-box/config.json:ro ghcr.io/sagernet/sing-box:latest run -c /etc/sing-box/config.json >/dev/null 2>&1;;
  esac; }
start_cli(){ local eng=$1 f=$2 cn=${PFX}c; docker rm -f $cn >/dev/null 2>&1
  case $eng in
    ntr)     docker run -d --name $cn --network $NET -v $NTR:/ntr:ro -v $f:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1;;
    mihomo)  docker run -d --name $cn --network $NET -v $f:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1;;
    singbox) docker run -d --name $cn --network $NET -v $f:/etc/sing-box/config.json:ro ghcr.io/sagernet/sing-box:latest run -c /etc/sing-box/config.json >/dev/null 2>&1;;
  esac; }
runtcp(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 6 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>/dev/null; }

test_case(){ # $1 srv-eng $2 cli-eng $3 proto
  local sn=${PFX}s cn=${PFX}c scfg=$D/_mux_s_${1}_$3 ccfg=$D/_mux_c_${2}_$3
  docker rm -f $sn $cn >/dev/null 2>&1
  ${1}_srv $sn "$scfg"; start_srv $1 "$scfg"; sleep 2
  ${2}_cli $sn $3 "$ccfg"; start_cli $2 "$ccfg"; sleep 2
  local ok=FAIL i; for i in 1 2 3 4; do echo "$(runtcp)" | grep -q Hostname && { ok=PASS; break; }; sleep 1; done
  echo "  [$1-srv <- $2-cli / $3]  $ok"
  [ $ok = FAIL ] && { docker logs $cn 2>&1 | tail -2 | sed 's/^/    CLI: /'; docker logs $sn 2>&1 | tail -2 | sed 's/^/    SRV: /'; }
  docker rm -f $sn $cn >/dev/null 2>&1
}

for proto in h2mux smux yamux; do
  echo "== protocol=$proto =="
  test_case singbox ntr $proto   # NTR mux 客户端 -> sing-box mux 服务端
  test_case mihomo  ntr $proto   # NTR mux 客户端 -> mihomo mux 服务端
  test_case ntr singbox $proto   # sing-box mux 客户端 -> NTR mux 服务端
  test_case ntr mihomo  $proto   # mihomo mux 客户端 -> NTR mux 服务端
done
cleanup; echo DONE
