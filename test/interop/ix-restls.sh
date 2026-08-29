#!/bin/bash
# restls(REST-TLS)交叉验证:抗探测伪装传输,握手全程中继到【真站】(此处 www.microsoft.com)。
# 叠法 [restls, shadowsocks]。restls 仅 mihomo 支持(同库 metacubex/restls-client-go)→ 对 mihomo 验。
#   A. NTR↔NTR 自环(NTR restls 客户端 ↔ NTR restls 服务端)
#   B. NTR restls 服务端 ← mihomo restls 客户端
set -u
NET=ix-rtls; PFX=ixrtls-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; RPW=restlspass123; SSPW=ssrestlspass456; M=aes-256-gcm
HOST=www.microsoft.com
SCRIPT='250?100<1,350~100<1,600~100,300~200,300~100'
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

ntr(){  docker run -d --name $1 --network $NET -v $NTR:/ntr:ro -v $2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
mihomo(){ docker run -d --name $1 --network $NET -v $2:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1; }
pull(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x socks5h://$1:1080 http://${PFX}target/ 2>/dev/null; }

# NTR restls+ss 服务端
cat > $D/_rtls_srv.yaml <<Y
inbounds:
  - listen: 0.0.0.0:10000
    layers:
      - {type: restls, server-name: "$HOST", password: "$RPW", restls-script: "$SCRIPT"}
      - {type: shadowsocks, method: $M, password: "$SSPW"}
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
# NTR restls+ss 客户端
cat > $D/_rtls_cli.yaml <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}]
outbounds:
  - name: up
    type: proxy
    server: "${PFX}s:10000"
    layers:
      - {type: restls, server-name: "$HOST", password: "$RPW", restls-script: "$SCRIPT"}
      - {type: shadowsocks, method: $M, password: "$SSPW"}
Y
# mihomo restls+ss 客户端
cat > $D/_rtls_mihomo.yaml <<Y
log-level: warning
mixed-port: 1080
allow-lan: true
proxies:
  - name: r
    type: ss
    server: ${PFX}s
    port: 10000
    cipher: $M
    password: "$SSPW"
    plugin: restls
    client-fingerprint: chrome
    plugin-opts:
      host: "$HOST"
      password: "$RPW"
      version-hint: tls13
      restls-script: "$SCRIPT"
rules: ["MATCH,r"]
Y

run_case(){ # $1 label  $2 cli-launcher
  docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
  ntr ${PFX}s $D/_rtls_srv.yaml; sleep 2
  eval "$2"; sleep 3
  local ok=FAIL i
  for i in 1 2 3 4 5 6; do echo "$(pull ${PFX}c)" | grep -q Hostname && { ok=PASS; break; }; sleep 1; done
  echo "  [$1]  $ok"
  [ $ok = FAIL ] && { docker logs ${PFX}c 2>&1|tail -3|sed 's/^/    CLI:/'; docker logs ${PFX}s 2>&1|tail -3|sed 's/^/    SRV:/'; }
}

run_case "A. NTR restls 客户端 -> NTR restls 服务端(自环)" 'ntr    ${PFX}c $D/_rtls_cli.yaml'
run_case "B. NTR restls 服务端 <- mihomo restls 客户端"    'mihomo ${PFX}c $D/_rtls_mihomo.yaml'
cleanup; echo DONE