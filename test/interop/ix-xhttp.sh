#!/bin/bash
# XHTTP(SplitHTTP)stream-one 交叉验证:NTR xhttp 传输 <-> {xray, mihomo}。base=vless(plain,无 TLS)。
# stream-one 必须 HTTP/2(h2c)全双工:NTR 客户端恒 h2c;服务端双模(h2c ServeConn / 手搓 h1.1 全双工)。
# sing-box 无 xhttp,不在互通范围。链路:curl -x socks5h -> 入站 -> vless+xhttp -> 出站 -> whoami。
set -u
NET=ix-xh; PFX=ixxt-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; UUID="11111111-1111-1111-1111-111111111111"; P="/testpath"
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

ntr_srv(){ cat > "$1" <<Y
inbounds:
  - name: srv-in
    type: vless
    listen: 0.0.0.0:10000
    xhttp:
      path: $P
    users:
      - uuid: "$UUID"
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
}
ntr_cli(){ cat > "$1" <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: vless
    server: "${PFX}s:10000"
    secret: "$UUID"
    xhttp:
      path: $P
      host: example.com
Y
}
xray_srv(){ cat > "$1" <<J
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":10000,"protocol":"vless","settings":{"clients":[{"id":"$UUID"}],"decryption":"none"},"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"$P","mode":"stream-one"}}}],"outbounds":[{"protocol":"freedom"}]}
J
}
xray_cli(){ cat > "$1" <<J
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"${PFX}s","port":10000,"users":[{"id":"$UUID","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","xhttpSettings":{"host":"example.com","path":"$P","mode":"stream-one"}}}]}
J
}
mihomo_srv(){ cat > "$1" <<Y
log-level: warning
listeners:
  - {name: vless-in, type: vless, listen: 0.0.0.0, port: 10000, allow-insecure: true, users: [{username: u, uuid: $UUID}], xhttp-config: {path: $P, mode: stream-one}}
Y
}
mihomo_cli(){ cat > "$1" <<Y
log-level: warning
mixed-port: 1080
allow-lan: true
proxies:
  - {name: o, type: vless, server: ${PFX}s, port: 10000, uuid: $UUID, network: xhttp, xhttp-opts: {path: $P, mode: stream-one}}
rules: ["MATCH,o"]
Y
}
run_srv(){ local eng=$1 f=$2 sn=${PFX}s; docker rm -f $sn >/dev/null 2>&1
  case $eng in
    ntr)    docker run -d --name $sn --network $NET -v $NTR:/ntr:ro -v $f:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1;;
    xray)   docker run -d --name $sn --network $NET -v $f:/c.json:ro ghcr.io/xtls/xray-core:latest run -c /c.json >/dev/null 2>&1;;
    mihomo) docker run -d --name $sn --network $NET -v $f:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1;;
  esac; }
run_cli(){ local eng=$1 f=$2 cn=${PFX}c; docker rm -f $cn >/dev/null 2>&1
  case $eng in
    ntr)    docker run -d --name $cn --network $NET -v $NTR:/ntr:ro -v $f:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1;;
    xray)   docker run -d --name $cn --network $NET -v $f:/c.json:ro ghcr.io/xtls/xray-core:latest run -c /c.json >/dev/null 2>&1;;
    mihomo) docker run -d --name $cn --network $NET -v $f:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1;;
  esac; }
runtcp(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 6 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>/dev/null; }

test_case(){ # $1 srv-eng $2 cli-eng
  local sn=${PFX}s cn=${PFX}c scfg=$D/_xt_s_$1 ccfg=$D/_xt_c_$2
  docker rm -f $sn $cn >/dev/null 2>&1
  ${1}_srv "$scfg"; run_srv $1 "$scfg"; sleep 2
  ${2}_cli "$ccfg"; run_cli $2 "$ccfg"; sleep 2
  local ok=FAIL i; for i in 1 2 3 4; do echo "$(runtcp)" | grep -q Hostname && { ok=PASS; break; }; sleep 1; done
  echo "  [$1-srv <- $2-cli / xhttp stream-one]  $ok"
  [ $ok = FAIL ] && { docker logs $cn 2>&1|tail -2|sed 's/^/    CLI:/'; docker logs $sn 2>&1|tail -2|sed 's/^/    SRV:/'; }
  docker rm -f $sn $cn >/dev/null 2>&1
}

test_case ntr  ntr     # NTR↔NTR
test_case xray ntr     # NTR 客户端 → xray 服务端
test_case ntr  xray    # xray 客户端 → NTR 服务端
test_case mihomo ntr   # NTR → mihomo
test_case ntr  mihomo  # mihomo → NTR
cleanup; echo DONE
