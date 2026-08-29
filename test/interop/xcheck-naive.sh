#!/bin/bash
# 交叉验证:NTR naive <-> sing-box naive
# 专属 network: xv-naive  容器前缀: xvn-
set -u
NET=xv-naive
D=/tmp/ntr-interop
U=u; PW=nvpw
SB=ghcr.io/sagernet/sing-box:latest
PA="--platform linux/amd64"   # ntr 是 amd64,镜像/靶机用本机原生 arch

cleanup(){ docker rm -f xvn-target xvn-sbsrv xvn-ntrcli xvn-ntrsrv xvn-sbcli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup
docker network create $NET >/dev/null 2>&1
docker run -d --name xvn-target --network $NET traefik/whoami >/dev/null 2>&1

echo "############ 方向 A: NTR naive 客户端 -> sing-box naive 服务端 ############"
# sing-box naive inbound (JSON, 1.13)
cat > $D/xvn-sb-srv.json <<JSON
{
  "log": {"level": "debug"},
  "inbounds": [{
    "type": "naive",
    "listen": "0.0.0.0",
    "listen_port": 8443,
    "users": [{"username": "$U", "password": "$PW"}],
    "tls": {"enabled": true, "certificate_path": "/cert.pem", "key_path": "/key.pem"}
  }],
  "outbounds": [{"type": "direct"}]
}
JSON
docker run -d --name xvn-sbsrv --network $NET \
  -v $D/xvn-sb-srv.json:/etc/sing-box/config.json:ro \
  -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro \
  $SB -c /etc/sing-box/config.json run >/dev/null 2>&1

# NTR naive 客户端
printf 'inbounds:\n  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: up}\noutbounds:\n  - {name: up, type: naive, server: "xvn-sbsrv:8443", user: %s, secret: "%s", sni: example.com, insecure: true}\n' "$U" "$PW" > $D/xvn-ntr-cli.yaml
docker run -d --name xvn-ntrcli --network $NET $PA -e NTR_DEBUG=1 \
  -v $D/ntr:/ntr:ro -v $D/xvn-ntr-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1

sleep 6
OUTA=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 15 -x socks5h://xvn-ntrcli:1080 http://xvn-target/ 2>&1)
if echo "$OUTA" | grep -q Hostname; then
  RES_A="通"; echo "[A] ✅ 通"; echo "$OUTA" | grep -i hostname
else
  RES_A="不通"; echo "[A] ❌ 不通"
  echo "--- sing-box srv log ---"; docker logs xvn-sbsrv 2>&1 | tail -12
  echo "--- ntr cli log ---"; docker logs xvn-ntrcli 2>&1 | tail -12
  echo "--- curl ---"; echo "$OUTA" | head -3
fi

echo
echo "############ 方向 B: sing-box naive 出站 -> NTR naive 服务端 ############"
# cronet(Chromium)对服务端证书有一堆策略:有效期<=398天、非Ed25519、须serverAuth EKU、
# 且自签叶子同时当根锚点仍会被判"validity too long"。→ 专门造一条 CA->叶子 链:
#   - CA(ECDSA P-256,长效,CA:TRUE)作 cronet 的 pinned trusted root
#   - 叶子(90天,SAN example.com,EKU serverAuth)由 CA 签,NTR 服务端出示 fullchain
# 纯测试证书策略,不动 naive 线格式;共享 cert.pem 保持不变供其它并行测试用
if [ ! -f $D/xvn-fullchain.pem ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out $D/xvn-ca.key 2>/dev/null
  openssl req -x509 -key $D/xvn-ca.key -out $D/xvn-ca.pem -days 3650 \
    -subj "/CN=xvn-naive-CA" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl ecparam -name prime256v1 -genkey -noout -out $D/xvn-leaf.key 2>/dev/null
  openssl req -new -key $D/xvn-leaf.key -out $D/xvn-leaf.csr -subj "/CN=example.com" 2>/dev/null
  openssl x509 -req -in $D/xvn-leaf.csr -CA $D/xvn-ca.pem -CAkey $D/xvn-ca.key -CAcreateserial \
    -out $D/xvn-leaf.pem -days 90 \
    -extfile <(printf 'subjectAltName=DNS:example.com\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n') 2>/dev/null
  cat $D/xvn-leaf.pem $D/xvn-ca.pem > $D/xvn-fullchain.pem
fi
# NTR naive 服务端(出示 leaf+CA 全链)
printf 'inbounds:\n  - listen: 0.0.0.0:8443\n    type: naive\n    tls: {cert-file: /cert.pem, key-file: /key.pem}\n    users: [{name: %s, password: "%s"}]\noutbounds: [{name: direct, type: direct}]\n' "$U" "$PW" > $D/xvn-ntr-srv.yaml
docker run -d --name xvn-ntrsrv --network $NET $PA -e NTR_DEBUG=1 \
  -v $D/ntr:/ntr:ro -v $D/xvn-ntr-srv.yaml:/c.yaml:ro \
  -v $D/xvn-fullchain.pem:/cert.pem:ro -v $D/xvn-leaf.key:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1

# sing-box naive outbound + mixed inbound(socks)
cat > $D/xvn-sb-cli.json <<JSON
{
  "log": {"level": "debug"},
  "inbounds": [{"type": "mixed", "listen": "0.0.0.0", "listen_port": 1080}],
  "outbounds": [{
    "type": "naive",
    "server": "xvn-ntrsrv",
    "server_port": 8443,
    "username": "$U",
    "password": "$PW",
    "tls": {"enabled": true, "server_name": "example.com", "certificate_path": "/cert.pem"}
  }]
}
JSON
docker run -d --name xvn-sbcli --network $NET \
  -v $D/xvn-sb-cli.json:/etc/sing-box/config.json:ro \
  -v $D/xvn-ca.pem:/cert.pem:ro \
  $SB -c /etc/sing-box/config.json run >/dev/null 2>&1

sleep 6
OUTB=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 15 -x socks5h://xvn-sbcli:1080 http://xvn-target/ 2>&1)
if echo "$OUTB" | grep -q Hostname; then
  RES_B="通"; echo "[B] ✅ 通"; echo "$OUTB" | grep -i hostname
else
  RES_B="不通"; echo "[B] ❌ 不通"
  echo "--- sing-box cli log ---"; docker logs xvn-sbcli 2>&1 | tail -15
  echo "--- ntr srv log ---"; docker logs xvn-ntrsrv 2>&1 | tail -12
  echo "--- curl ---"; echo "$OUTB" | head -3
fi

echo
echo "======== 结论: A(NTR cli->SB srv)=$RES_A  B(SB cli->NTR srv)=$RES_B ========"
[ "${1:-}" = "keep" ] || cleanup
