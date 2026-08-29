#!/bin/bash
# AnyTLS UDP(UoT / UDP-over-TCP)互通:补完 anytls 的 UDP 数据面,对真 sing-box 双向验。
# 线格式禁改:anytls 只多开一条到 uot 魔术地址(sp.v2.udp-over-tcp.arpa)的普通复用流,UDP 语义全在
# sing 的 uot 层(与 sing-box anytls 出/入站同款)。① NTR anytls-udp 客户端→sing-box 服务端;
# ② sing-box anytls-udp 客户端→NTR 服务端。经 socks5 UDP ASSOCIATE 打 udpecho:9999,回显即通。
set -u
NET=ixatu; PFX=ixatu-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}; PW="atudp123"
CURL=curlimages/curl:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
cp "$(dirname "$0")"/udpecho.py "$(dirname "$0")"/socksudp-cfg.py $D/ 2>/dev/null
[ -f "$D/atcert.pem" ] || docker run --rm -v $D:/w -w /w alpine sh -c 'apk add openssl>/dev/null 2>&1; openssl req -x509 -newkey rsa:2048 -keyout atkey.pem -out atcert.pem -days 3650 -nodes -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com" >/dev/null 2>&1'
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
sleep 1
runudp(){ docker run --rm --network $NET -e CLI=$1 -e ECHO=${PFX}echo -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1; }
chk(){ echo "$1" | grep -q "GOT b'PINGUDP-ss-42'" && echo "PASS" || echo "FAIL"; }

# ── ① NTR anytls-udp 客户端 → sing-box anytls 服务端 ──
cat > $D/_atu_sbs.json <<J
{"log":{"level":"warn"},"inbounds":[{"type":"anytls","listen":"::","listen_port":8443,"users":[{"password":"$PW"}],"tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem"}}],"outbounds":[{"type":"direct"}]}
J
docker run -d --name ${PFX}sbs --network $NET -v $D/_atu_sbs.json:/c.json:ro -v $D/atcert.pem:/cert.pem:ro -v $D/atkey.pem:/key.pem:ro ghcr.io/sagernet/sing-box:latest run -c /c.json >/dev/null 2>&1
sleep 2
cat > $D/_atu_ntrc.yaml <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: at}]
outbounds: [{name: at, type: anytls, server: "${PFX}sbs:8443", secret: "$PW", sni: example.com, insecure: true}]
Y
docker run -d --name ${PFX}ntrc --network $NET -v $NTR:/ntr:ro -v $D/_atu_ntrc.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
wait_log ${PFX}ntrc "监听于" 15
R1=$(runudp ${PFX}ntrc)
echo "  [① NTR anytls-udp 客户端 → sing-box 服务端]  $(chk "$R1")  ($(echo "$R1"|tail -1))"
docker rm -f ${PFX}sbs ${PFX}ntrc >/dev/null 2>&1

# ── ② sing-box anytls-udp 客户端 → NTR anytls 服务端 ──
cat > $D/_atu_ntrs.yaml <<Y
inbounds:
  - listen: 0.0.0.0:8443
    type: anytls
    users: [{password: "$PW"}]
    tls: {cert-file: /cert.pem, key-file: /key.pem}
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
docker run -d --name ${PFX}ntrs --network $NET -v $NTR:/ntr:ro -v $D/_atu_ntrs.yaml:/c.yaml:ro -v $D/atcert.pem:/cert.pem:ro -v $D/atkey.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
wait_log ${PFX}ntrs "监听于" 15
cat > $D/_atu_sbc.json <<J
{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"anytls","server":"${PFX}ntrs","server_port":8443,"password":"$PW","tls":{"enabled":true,"server_name":"example.com","insecure":true}}]}
J
docker run -d --name ${PFX}sbc --network $NET -v $D/_atu_sbc.json:/c.json:ro ghcr.io/sagernet/sing-box:latest run -c /c.json >/dev/null 2>&1
sleep 2
R2=$(runudp ${PFX}sbc)
echo "  [② sing-box anytls-udp 客户端 → NTR 服务端]  $(chk "$R2")  ($(echo "$R2"|tail -1))"

cleanup; echo DONE
