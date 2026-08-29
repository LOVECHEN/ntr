#!/bin/bash
# ECH(Encrypted Client Hello)验证:ClientHello 的真实 SNI 用服务端公钥 HPKE 加密,外层只露 public-name(抗 SNI 审查)。
# NTR 的 ECH 格式(ECH CONFIGS / ECH KEYS PEM)与 sing-box 逐字节兼容。★Go 客户端配了 ECHConfigList 后强制 ECH
# (服务端不支持则 ECHRejectionError),故握手成功 == ECH 真的生效。
# ① NTR ECH 客户端 → NTR ECH 服务端(自证 ECH 实现);② NTR ECH 客户端 → 真 sing-box ECH 服务端(跨实现)。
set -u
NET=ixech; PFX=ixech-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}; UUID="11111111-1111-1111-1111-111111111111"
CURL=curlimages/curl:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami --name ECH-TARGET >/dev/null 2>&1
# 证书(内层真 SNI = secret.example)+ ECH 密钥对(公开名 public.example)
[ -f "$D/echcert.pem" ] || docker run --rm -v $D:/w -w /w alpine sh -c 'apk add openssl>/dev/null 2>&1; openssl req -x509 -newkey rsa:2048 -keyout echkey.pem -out echcert.pem -days 3650 -nodes -subj "/CN=secret.example" -addext "subjectAltName=DNS:secret.example" >/dev/null 2>&1'
docker run --rm -v $NTR:/ntr:ro alpine /ntr ech-keygen public.example > $D/_ech_all.pem 2>/dev/null
sed -n '/BEGIN ECH CONFIGS/,/END ECH CONFIGS/p' $D/_ech_all.pem > $D/ech-configs.pem
sed -n '/BEGIN ECH KEYS/,/END ECH KEYS/p'       $D/_ech_all.pem > $D/ech-keys.pem
[ -s "$D/ech-configs.pem" ] || { echo "  [ech-keygen 失败]  FAIL"; cleanup; echo DONE; exit 0; }
sleep 1

# NTR ECH 服务端
cat > $D/_ech_s.yaml <<Y
inbounds:
  - listen: 0.0.0.0:10000
    layers: [{type: tls, cert-file: /cert.pem, key-file: /key.pem, ech-key-file: /ech-keys.pem}, {type: vless}]
    users: [{uuid: "$UUID"}]
    outbound: direct
outbounds: [{name: direct, type: direct}]
Y
# NTR ECH 客户端(内层 sni=secret.example,ech-config 给公钥)
ntr_cli(){ cat > $D/_ech_c.yaml <<Y
inbounds: [{listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}]
outbounds:
  - {name: up, type: proxy, server: "$1:10000", secret: "$UUID", layers: [{type: tls, sni: secret.example, insecure: true, ech-config-file: /ech-configs.pem}, {type: vless}]}
Y
}

# ① NTR ECH 客户端 → NTR ECH 服务端
docker run -d --name ${PFX}ns --network $NET -v $NTR:/ntr:ro -v $D/_ech_s.yaml:/c.yaml:ro -v $D/echcert.pem:/cert.pem:ro -v $D/echkey.pem:/key.pem:ro -v $D/ech-keys.pem:/ech-keys.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
wait_log ${PFX}ns "监听于" 15
ntr_cli ${PFX}ns
docker run -d --name ${PFX}nc --network $NET -v $NTR:/ntr:ro -v $D/_ech_c.yaml:/c.yaml:ro -v $D/ech-configs.pem:/ech-configs.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
wait_log ${PFX}nc "监听于" 15
R1=$(docker run --rm --network $NET $CURL -s --max-time 12 -x socks5h://${PFX}nc:1080 http://${PFX}target/ 2>&1)
echo "  [① NTR ECH 客户端 → NTR ECH 服务端(握手成功=ECH 生效)]  $(echo "$R1"|grep -q 'Name: ECH-TARGET' && echo PASS || echo FAIL)"
docker rm -f ${PFX}nc ${PFX}ns >/dev/null 2>&1

# ② NTR ECH 客户端 → 真 sing-box ECH 服务端
CFG=$(sed 's/.*/      "&"/' $D/ech-configs.pem); KEY=$(sed 's/.*/      "&"/' $D/ech-keys.pem)
cat > $D/_ech_sb.json <<J
{"log":{"level":"warn"},"inbounds":[{"type":"vless","listen":"::","listen_port":10000,"users":[{"uuid":"$UUID"}],"tls":{"enabled":true,"server_name":"secret.example","certificate_path":"/cert.pem","key_path":"/key.pem","ech":{"enabled":true,"key_path":"/ech-keys.pem"}}}],"outbounds":[{"type":"direct"}]}
J
docker run -d --name ${PFX}sbs --network $NET -v $D/_ech_sb.json:/c.json:ro -v $D/echcert.pem:/cert.pem:ro -v $D/echkey.pem:/key.pem:ro -v $D/ech-keys.pem:/ech-keys.pem:ro ghcr.io/sagernet/sing-box:latest -c /c.json run >/dev/null 2>&1
sleep 3
ntr_cli ${PFX}sbs
docker run -d --name ${PFX}nc --network $NET -v $NTR:/ntr:ro -v $D/_ech_c.yaml:/c.yaml:ro -v $D/ech-configs.pem:/ech-configs.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
wait_log ${PFX}nc "监听于" 15
R2=$(docker run --rm --network $NET $CURL -s --max-time 12 -x socks5h://${PFX}nc:1080 http://${PFX}target/ 2>&1)
echo "  [② NTR ECH 客户端 → 真 sing-box ECH 服务端]  $(echo "$R2"|grep -q 'Name: ECH-TARGET' && echo PASS || echo FAIL)"

cleanup; echo DONE
