#!/bin/bash
# 交叉验证:NTR trusttunnel <-> mihomo trusttunnel(H2 CONNECT + Basic 认证)
# 专属 network=xv-tt 容器前缀=xvt-。结束清理自己起的一切。
set -u
NET=xv-tt; PFX=xvt-; D=/tmp/ntr-interop; U=u; PW=ttpw; MIMG=metacubex/mihomo:latest
CURL=curlimages/curl:latest
say(){ echo -e "$@"; }
cleanup(){ docker rm -f ${PFX}target ${PFX}msrv ${PFX}ncli ${PFX}nsrv ${PFX}mcli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT
cleanup
docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null

# mihomo 限制证书路径必须在 home 内(SAFE_PATHS),故把 PEM 内联进 yaml
CERT_IND=$(sed 's/^/      /' $D/cert.pem); KEY_IND=$(sed 's/^/      /' $D/key.pem)

########## 方向 A:NTR trusttunnel 客户端 -> mihomo trusttunnel 服务端 ##########
cat > $D/xvt-msrv.yaml <<EOF
log-level: debug
mode: rule
listeners:
  - name: tt-in
    type: trusttunnel
    port: 8443
    listen: 0.0.0.0
    users:
      - username: $U
        password: $PW
    certificate: |
$CERT_IND
    private-key: |
$KEY_IND
proxies: []
rules:
  - MATCH,DIRECT
EOF
docker run -d --name ${PFX}msrv --network $NET \
  -v $D/xvt-msrv.yaml:/root/.config/mihomo/config.yaml:ro \
  $MIMG >/dev/null 2>&1

cat > $D/xvt-ncli.yaml <<EOF
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: trusttunnel
    server: "${PFX}msrv:8443"
    user: $U
    secret: "$PW"
    sni: example.com
    insecure: true
EOF
docker run -d --name ${PFX}ncli --network $NET -e NTR_DEBUG=1 \
  -v $D/ntr:/ntr:ro -v $D/xvt-ncli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1

sleep 5
A=$(docker run --rm --network $NET $CURL -s --max-time 12 -x socks5h://${PFX}ncli:1080 http://${PFX}target/ 2>&1)
if echo "$A" | grep -q Hostname; then
  RESA="通"; say "方向A ✅ NTR(cli)->mihomo(srv): $(echo "$A"|grep -i Hostname|tr -d '\r')"
else
  RESA="不通"; say "方向A ❌ NTR(cli)->mihomo(srv)"
  say "--- mihomo srv log ---"; docker logs ${PFX}msrv 2>&1 | tail -12
  say "--- ntr cli log ---"; docker logs ${PFX}ncli 2>&1 | tail -12
  say "--- curl ---"; echo "$A" | head -3
fi

########## 方向 B:mihomo trusttunnel 客户端 -> NTR trusttunnel 服务端 ##########
cat > $D/xvt-nsrv.yaml <<EOF
inbounds:
  - name: srv-in
    type: trusttunnel
    listen: 0.0.0.0:8443
    tls:
      cert-file: /cert.pem
      key-file: /key.pem
    users:
      - name: $U
        password: "$PW"
outbounds:
  - name: direct
    type: direct
EOF
docker run -d --name ${PFX}nsrv --network $NET -e NTR_DEBUG=1 \
  -v $D/ntr:/ntr:ro -v $D/xvt-nsrv.yaml:/c.yaml:ro \
  -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1

cat > $D/xvt-mcli.yaml <<EOF
mixed-port: 1080
allow-lan: true
log-level: debug
mode: rule
proxies:
  - name: p
    type: trusttunnel
    server: ${PFX}nsrv
    port: 8443
    username: $U
    password: "$PW"
    sni: example.com
    skip-cert-verify: true
    alpn: [h2]
rules:
  - MATCH,p
EOF
docker run -d --name ${PFX}mcli --network $NET \
  -v $D/xvt-mcli.yaml:/root/.config/mihomo/config.yaml:ro $MIMG >/dev/null 2>&1

sleep 5
B=$(docker run --rm --network $NET $CURL -s --max-time 12 -x socks5h://${PFX}mcli:1080 http://${PFX}target/ 2>&1)
if echo "$B" | grep -q Hostname; then
  RESB="通"; say "方向B ✅ mihomo(cli)->NTR(srv): $(echo "$B"|grep -i Hostname|tr -d '\r')"
else
  RESB="不通"; say "方向B ❌ mihomo(cli)->NTR(srv)"
  say "--- ntr srv log ---"; docker logs ${PFX}nsrv 2>&1 | tail -12
  say "--- mihomo cli log ---"; docker logs ${PFX}mcli 2>&1 | tail -15
  say "--- curl ---"; echo "$B" | head -3
fi

say ""
say "==== 结论 ===="
say "方向A NTR客户端->mihomo服务端: $RESA"
say "方向B mihomo客户端->NTR服务端: $RESB"
