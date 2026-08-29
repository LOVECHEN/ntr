#!/bin/bash
# V2Ray QUIC 独立传输交叉验证:NTR quic <-> sing-box(v2rayquic)。base=vless,ALPN h3,内建 TLS。
# quic 是 UDP-base:NTR 出站拨 UDP+QUIC→OpenStream、入站 UDP 监听 QUIC→每 conn 多流。
# xray 已移除 QUIC(v24.9.7)、mihomo 无独立 QUIC 传输,故仅 sing-box 可验。
set -u
NET=ix-q; PFX=ixqt-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; UUID="11111111-1111-1111-1111-111111111111"
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
# 自签证书(sing-box 服务端 TLS 用)
docker run --rm -v $D:/out alpine sh -c "apk add -q openssl >/dev/null 2>&1; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout /out/_qt_key.pem -out /out/_qt_cert.pem -days 3650 -nodes -subj '/CN=example.com' >/dev/null 2>&1"
sleep 1

ntr_srv(){ cat > "$1" <<Y
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: quic}, {type: vless}]
    users: [{uuid: "$UUID"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
}
ntr_cli(){ cat > "$1" <<Y
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}
outbounds:
  - {name: up, type: proxy, server: "${PFX}s:10000", secret: "$UUID", layers: [{type: quic, sni: example.com, insecure: true}, {type: vless}]}
Y
}
singbox_srv(){ cat > "$1" <<J
{"log":{"level":"warn"},"inbounds":[{"type":"vless","listen":"::","listen_port":10000,"users":[{"uuid":"$UUID"}],"tls":{"enabled":true,"server_name":"example.com","certificate_path":"/cert.pem","key_path":"/key.pem"},"transport":{"type":"quic"}}],"outbounds":[{"type":"direct"}]}
J
}
singbox_cli(){ cat > "$1" <<J
{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"vless","server":"${PFX}s","server_port":10000,"uuid":"$UUID","tls":{"enabled":true,"server_name":"example.com","insecure":true},"transport":{"type":"quic"}}]}
J
}
run_srv(){ local eng=$1 f=$2 sn=${PFX}s; docker rm -f $sn >/dev/null 2>&1
  case $eng in
    ntr)    docker run -d --name $sn --network $NET -v $NTR:/ntr:ro -v $f:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1;;
    singbox)docker run -d --name $sn --network $NET -v $f:/c.json:ro -v $D/_qt_cert.pem:/cert.pem:ro -v $D/_qt_key.pem:/key.pem:ro ghcr.io/sagernet/sing-box:latest run -c /c.json >/dev/null 2>&1;;
  esac; }
run_cli(){ local eng=$1 f=$2 cn=${PFX}c; docker rm -f $cn >/dev/null 2>&1
  case $eng in
    ntr)    docker run -d --name $cn --network $NET -v $NTR:/ntr:ro -v $f:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1;;
    singbox)docker run -d --name $cn --network $NET -v $f:/c.json:ro ghcr.io/sagernet/sing-box:latest run -c /c.json >/dev/null 2>&1;;
  esac; }
runtcp(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>/dev/null; }

test_case(){ # $1 srv-eng $2 cli-eng
  local sn=${PFX}s cn=${PFX}c scfg=$D/_qt_s_$1 ccfg=$D/_qt_c_$2
  docker rm -f $sn $cn >/dev/null 2>&1
  ${1}_srv "$scfg"; run_srv $1 "$scfg"; sleep 2
  ${2}_cli "$ccfg"; run_cli $2 "$ccfg"; sleep 2
  local ok=FAIL i; for i in 1 2 3 4; do echo "$(runtcp)" | grep -q Hostname && { ok=PASS; break; }; sleep 1; done
  echo "  [$1-srv <- $2-cli / quic]  $ok"
  [ $ok = FAIL ] && { docker logs $cn 2>&1|tail -2|sed 's/^/    CLI:/'; docker logs $sn 2>&1|tail -2|sed 's/^/    SRV:/'; }
  docker rm -f $sn $cn >/dev/null 2>&1
}

test_case ntr     ntr
test_case singbox ntr
test_case ntr     singbox
cleanup; echo DONE
