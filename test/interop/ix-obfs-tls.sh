#!/bin/bash
# simple-obfs(TLS 伪装)交叉验证:NTR obfs 传输 <-> {mihomo, sing-box}。叠法 [obfs, shadowsocks]。
# obfs 首包裹假 ClientHello(数据在 session-ticket)+ 之后裸流。NTR obfs 客户端/服务端 ↔ mihomo 双向 + sing-box→NTR。
# mihomo:proxy plugin=obfs / listener simple-obfs.enable;sing-box:plugin=obfs-local(仅客户端)。
set -u
NET=ix-obtls; PFX=ixobtls-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; PW=obfspass123; HOST=bing.com; M=aes-256-gcm
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

ntr_srv(){ cat > "$1" <<Y
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: obfs, mode: tls, host: $HOST}, {type: shadowsocks, method: $M, password: "$PW"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
}
ntr_cli(){ cat > "$1" <<Y
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}
outbounds:
  - {name: up, type: proxy, server: "${PFX}s:10000", layers: [{type: obfs, mode: tls, host: $HOST}, {type: shadowsocks, method: $M, password: "$PW"}]}
Y
}
mihomo_srv(){ cat > "$1" <<Y
log-level: warning
listeners:
  - {name: ss-in, type: shadowsocks, listen: 0.0.0.0, port: 10000, password: "$PW", cipher: $M, simple-obfs: {enable: true, mode: tls}}
Y
}
mihomo_cli(){ cat > "$1" <<Y
log-level: warning
mixed-port: 1080
allow-lan: true
proxies:
  - {name: o, type: ss, server: ${PFX}s, port: 10000, cipher: $M, password: "$PW", plugin: obfs, plugin-opts: {mode: tls, host: $HOST}}
rules: ["MATCH,o"]
Y
}
singbox_cli(){ cat > "$1" <<J
{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"shadowsocks","server":"${PFX}s","server_port":10000,"method":"$M","password":"$PW","plugin":"obfs-local","plugin_opts":"obfs=tls;obfs-host=$HOST"}]}
J
}
run_srv(){ local eng=$1 f=$2 sn=${PFX}s; docker rm -f $sn >/dev/null 2>&1
  case $eng in
    ntr)    docker run -d --name $sn --network $NET -v $NTR:/ntr:ro -v $f:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1;;
    mihomo) docker run -d --name $sn --network $NET -v $f:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1;;
  esac; }
run_cli(){ local eng=$1 f=$2 cn=${PFX}c; docker rm -f $cn >/dev/null 2>&1
  case $eng in
    ntr)    docker run -d --name $cn --network $NET -v $NTR:/ntr:ro -v $f:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1;;
    mihomo) docker run -d --name $cn --network $NET -v $f:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1;;
    singbox)docker run -d --name $cn --network $NET -v $f:/etc/sing-box/config.json:ro ghcr.io/sagernet/sing-box:latest run -c /etc/sing-box/config.json >/dev/null 2>&1;;
  esac; }
runtcp(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>/dev/null; }

test_case(){ # $1 label $2 srv-eng $3 cli-eng
  local sn=${PFX}s cn=${PFX}c scfg=$D/_obt_s_$2 ccfg=$D/_obt_c_$3
  docker rm -f $sn $cn >/dev/null 2>&1
  ${2}_srv "$scfg"; run_srv $2 "$scfg"; sleep 2
  ${3}_cli "$ccfg"; run_cli $3 "$ccfg"; sleep 2
  local ok=FAIL i; for i in 1 2 3 4; do echo "$(runtcp)" | grep -q Hostname && { ok=PASS; break; }; sleep 1; done
  echo "  [$1]  $ok"
  [ $ok = FAIL ] && { docker logs $cn 2>&1|tail -2|sed 's/^/    CLI:/'; docker logs $sn 2>&1|tail -2|sed 's/^/    SRV:/'; }
  docker rm -f $sn $cn >/dev/null 2>&1
}

test_case "NTR<-NTR"      ntr    ntr
test_case "NTR<-mihomo"   ntr    mihomo
test_case "NTR<-singbox"  ntr    singbox
test_case "mihomo<-NTR"   mihomo ntr
cleanup; echo DONE
