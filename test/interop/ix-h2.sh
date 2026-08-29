#!/bin/bash
# HTTP/2(V2Ray http)传输交叉验证:NTR h2 <-> {sing-box, mihomo}。base=vless(plain)。
# 明文 h2 传输:NTR 服务端双模(h2 preface→h2c / 否则→手搓 h1.1),故收得下 sing-box/mihomo 的 h1.1 出站。
# NTR 客户端用 h2c:sing-box 服务端接受;【mihomo vless 入站无 http/h2 传输(仅 ws/grpc/xhttp),故 NTR→mihomo NA】。
# xray 无独立 h2(并入 xhttp),不在范围。
set -u
NET=ix-h2; PFX=ixh2t-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; UUID="11111111-1111-1111-1111-111111111111"; P="/h2path"
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

ntr_srv(){ cat > "$1" <<Y
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: h2, path: $P, method: PUT}, {type: vless}]
    users: [{uuid: "$UUID"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
}
ntr_cli(){ cat > "$1" <<Y
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}
outbounds:
  - {name: up, type: proxy, server: "${PFX}s:10000", secret: "$UUID", layers: [{type: h2, path: $P, host: example.com}, {type: vless}]}
Y
}
singbox_srv(){ cat > "$1" <<J
{"log":{"level":"warn"},"inbounds":[{"type":"vless","listen":"::","listen_port":10000,"users":[{"uuid":"$UUID"}],"transport":{"type":"http","path":"$P","method":"PUT"}}],"outbounds":[{"type":"direct"}]}
J
}
singbox_cli(){ cat > "$1" <<J
{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"vless","server":"${PFX}s","server_port":10000,"uuid":"$UUID","transport":{"type":"http","path":"$P","method":"PUT"}}]}
J
}
mihomo_srv(){ cat > "$1" <<Y
log-level: warning
listeners:
  - {name: vless-in, type: vless, listen: 0.0.0.0, port: 10000, allow-insecure: true, users: [{username: u, uuid: $UUID}], network: http, http-opts: {path: [$P], method: PUT}}
Y
}
mihomo_cli(){ cat > "$1" <<Y
log-level: warning
mixed-port: 1080
allow-lan: true
proxies:
  - {name: o, type: vless, server: ${PFX}s, port: 10000, uuid: $UUID, network: http, http-opts: {path: [$P], method: PUT}}
rules: ["MATCH,o"]
Y
}
run_srv(){ local eng=$1 f=$2 sn=${PFX}s; docker rm -f $sn >/dev/null 2>&1
  case $eng in
    ntr)    docker run -d --name $sn --network $NET -v $NTR:/ntr:ro -v $f:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1;;
    singbox)docker run -d --name $sn --network $NET -v $f:/etc/sing-box/config.json:ro ghcr.io/sagernet/sing-box:latest run -c /etc/sing-box/config.json >/dev/null 2>&1;;
    mihomo) docker run -d --name $sn --network $NET -v $f:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1;;
  esac; }
run_cli(){ local eng=$1 f=$2 cn=${PFX}c; docker rm -f $cn >/dev/null 2>&1
  case $eng in
    ntr)    docker run -d --name $cn --network $NET -v $NTR:/ntr:ro -v $f:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1;;
    singbox)docker run -d --name $cn --network $NET -v $f:/etc/sing-box/config.json:ro ghcr.io/sagernet/sing-box:latest run -c /etc/sing-box/config.json >/dev/null 2>&1;;
    mihomo) docker run -d --name $cn --network $NET -v $f:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1;;
  esac; }
runtcp(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>/dev/null; }

test_case(){ # $1 srv-eng $2 cli-eng
  local sn=${PFX}s cn=${PFX}c scfg=$D/_h2t_s_$1 ccfg=$D/_h2t_c_$2
  docker rm -f $sn $cn >/dev/null 2>&1
  ${1}_srv "$scfg"; run_srv $1 "$scfg"; sleep 2
  ${2}_cli "$ccfg"; run_cli $2 "$ccfg"; sleep 2
  local ok=FAIL i; for i in 1 2 3 4; do echo "$(runtcp)" | grep -q Hostname && { ok=PASS; break; }; sleep 1; done
  echo "  [$1-srv <- $2-cli / h2]  $ok"
  [ $ok = FAIL ] && { docker logs $cn 2>&1|tail -2|sed 's/^/    CLI:/'; docker logs $sn 2>&1|tail -2|sed 's/^/    SRV:/'; }
  docker rm -f $sn $cn >/dev/null 2>&1
}

test_case ntr     ntr
test_case singbox ntr
test_case ntr     singbox
# NTR→mihomo(mihomo 作 h2 服务端):【NA·mihomo 侧限制】mihomo 的 vless listener 只支持 ws/grpc/xhttp/reality
# 传输(见 listener/inbound/vless.go),【无】V2Ray http/h2 传输服务端 —— network:http/h2-opts 在 listener 上被
# 静默忽略、退回明文 vless-TCP,故 NTR 的 h2c 客户端无法握手。非 NTR 缺陷。mihomo 的 network:http 只有【出站】
# (StreamHTTPConn,且那是 HTTP/1.1 obfs,非 HTTP/2),已由下面 mihomo→NTR 方向覆盖(NTR 服务端双模收 h1.1)。
echo "  [mihomo-srv <- ntr-cli / h2]  NA(mihomo vless 入站无 http/h2 传输,仅 ws/grpc/xhttp)"
test_case ntr     mihomo
cleanup; echo DONE
