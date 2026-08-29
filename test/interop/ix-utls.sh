#!/bin/bash
# uTLS 独立指纹层验证:NTR 的 tls 传输配 fingerprint 后走 uTLS 仿真真实浏览器 ClientHello(抗 TLS 指纹审查)。
# 客户端指纹是 ClientHello 形状,合法 TLS 服务端照常接受 → 用 [tls(fingerprint:chrome), vless] 客户端打真 xray /
# sing-box 的 [tls, vless] 服务端,curl socks5h→whoami 通即证 uTLS-tls 与真实现互通(且走的是浏览器指纹)。
set -u
NET=ixutls; PFX=ixutls-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}; UUID="11111111-1111-1111-1111-111111111111"
CURL=curlimages/curl:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
[ -f "$D/ucert.pem" ] || docker run --rm -v $D:/w -w /w alpine sh -c 'apk add openssl>/dev/null 2>&1; openssl req -x509 -newkey rsa:2048 -keyout ukey.pem -out ucert.pem -days 3650 -nodes -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com" >/dev/null 2>&1'
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami --name UTLS-TARGET >/dev/null 2>&1
sleep 1

ntr_cli(){ # $1=server host
  printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: proxy, server: "%s:10000", secret: "%s", layers: [{type: tls, sni: example.com, insecure: true, fingerprint: chrome}, {type: vless}]}\n' "$1" "$UUID" > $D/_utls_c.yaml
}
run_case(){ # $1=label $2=srv-kind
  local srv=${PFX}$2s
  case $2 in
    xray) printf '{"log":{"loglevel":"warning"},"inbounds":[{"port":10000,"protocol":"vless","settings":{"clients":[{"id":"%s"}],"decryption":"none"},"streamSettings":{"security":"tls","tlsSettings":{"alpn":["http/1.1"],"certificates":[{"certificateFile":"/cert.pem","keyFile":"/key.pem"}]}}}],"outbounds":[{"protocol":"freedom"}]}\n' "$UUID" > $D/_utls_s.json
          docker run -d --name $srv --network $NET -v $D/_utls_s.json:/c.json:ro -v $D/ucert.pem:/cert.pem:ro -v $D/ukey.pem:/key.pem:ro ghcr.io/xtls/xray-core:latest -c /c.json >/dev/null 2>&1; sleep 3;;
    singbox) printf '{"log":{"level":"warn"},"inbounds":[{"type":"vless","listen":"::","listen_port":10000,"users":[{"uuid":"%s"}],"tls":{"enabled":true,"alpn":["http/1.1"],"certificate_path":"/cert.pem","key_path":"/key.pem"}}],"outbounds":[{"type":"direct"}]}\n' "$UUID" > $D/_utls_s.json
          docker run -d --name $srv --network $NET -v $D/_utls_s.json:/c.json:ro -v $D/ucert.pem:/cert.pem:ro -v $D/ukey.pem:/key.pem:ro ghcr.io/sagernet/sing-box:latest -c /c.json run >/dev/null 2>&1; sleep 3;;
  esac
  ntr_cli "$srv"
  docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_utls_c.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  wait_log ${PFX}c "监听于" 15
  R=$(docker run --rm --network $NET $CURL -s --max-time 12 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>&1)
  echo "  [$1]  $(echo "$R"|grep -q 'Name: UTLS-TARGET' && echo PASS || echo FAIL)"
  docker rm -f ${PFX}c $srv >/dev/null 2>&1
}
run_case "NTR uTLS(chrome)客户端 → xray [tls,vless] 服务端" xray
run_case "NTR uTLS(chrome)客户端 → sing-box [tls,vless] 服务端" singbox
cleanup; echo DONE
