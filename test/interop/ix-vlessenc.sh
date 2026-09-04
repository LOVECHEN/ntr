#!/bin/bash
# VLESS Encryption(Xray 后量子加密层 ML-KEM-768 + X25519)交叉验证:NTR vlessenc <-> xray。
# NTR 用 vendored 自 xtls/xray-core 的 encryption 包(禁改线格式),叠法 [vlessenc, vless]。
# 覆盖模式:native / xorpub / random(XOR 混淆);以及 0-RTT。
#   A: NTR 客户端 → xray 服务端    B: xray 客户端 → NTR 服务端
set -u
NET=ix-venc; PFX=ixvenc-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; UUID="11111111-1111-1111-1111-111111111111"
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
keys=$(docker run --rm -v "$(cd "$(dirname "$0")/../.." && pwd)":/src -w /src golang:alpine sh -c '
cat > /tmp/g.go <<GO
package main
import ("crypto/ecdh";"crypto/rand";"encoding/base64";"fmt")
func main(){p,_:=ecdh.X25519().GenerateKey(rand.Reader);fmt.Println(base64.RawURLEncoding.EncodeToString(p.Bytes()));fmt.Println(base64.RawURLEncoding.EncodeToString(p.PublicKey().Bytes()))}
GO
go run /tmp/g.go 2>/dev/null')
PRIV=$(echo "$keys" | sed -n 1p); PUB=$(echo "$keys" | sed -n 2p)
[ -z "$PRIV" ] && { echo "keygen 失败"; exit 1; }
echo "keys ok"; sleep 1

# $1=mode(native/xorpub/random) $2=zerortt(0|1)
ntr_srv(){ local secs=0; [ "$2" = 1 ] && secs=600
  cat > $D/_venc_nsrv.yaml <<Y
inbounds:
  - name: venc-in
    type: vless
    listen: 0.0.0.0:10000
    vlessenc:
      key: "$PRIV"
      mode: $1
      seconds: $secs
    users:
      - uuid: "$UUID"
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
  docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_venc_nsrv.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
xray_srv(){ local s2="0"; [ "$2" = 1 ] && s2="600"
  cat > $D/_venc_xsrv.json <<J
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":10000,"protocol":"vless","settings":{"clients":[{"id":"$UUID"}],"decryption":"mlkem768x25519plus.$1.$s2.$PRIV"},"streamSettings":{"network":"tcp","security":"none"}}],"outbounds":[{"protocol":"freedom"}]}
J
  docker run -d --name ${PFX}s --network $NET -v $D/_venc_xsrv.json:/etc/xray/config.json:ro ghcr.io/xtls/xray-core:latest -c /etc/xray/config.json >/dev/null 2>&1; }

ntr_cli(){ local z=false; [ "$2" = 1 ] && z=true
  cat > $D/_venc_ncli.yaml <<Y
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
    vlessenc:
      key: "$PUB"
      mode: $1
      zero-rtt: $z
Y
  docker run -d --name ${PFX}c --network $NET -v $NTR:/ntr:ro -v $D/_venc_ncli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
xray_cli(){ local rtt=1rtt; [ "$2" = 1 ] && rtt=0rtt
  cat > $D/_venc_xcli.json <<J
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"${PFX}s","port":10000,"users":[{"id":"$UUID","encryption":"mlkem768x25519plus.$1.$rtt.$PUB"}]}]},"streamSettings":{"network":"tcp","security":"none"}}]}
J
  docker run -d --name ${PFX}c --network $NET -v $D/_venc_xcli.json:/etc/xray/config.json:ro ghcr.io/xtls/xray-core:latest -c /etc/xray/config.json >/dev/null 2>&1; }

runtcp(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 8 -x socks5h://${PFX}c:1080 http://${PFX}target/ 2>/dev/null; }

test_dir(){ # $1=label $2=srv-fn $3=cli-fn $4=mode $5=zerortt
  docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1
  $2 "$4" "$5"; sleep 2; $3 "$4" "$5"; sleep 3
  local ok=FAIL i; for i in 1 2 3 4 5; do echo "$(runtcp)" | grep -q Hostname && { ok=PASS; break; }; sleep 1; done
  printf "  [%s / %s%s]  %s\n" "$1" "$4" "$([ "$5" = 1 ] && echo /0rtt)" "$ok"
  [ $ok = FAIL ] && { docker logs ${PFX}c 2>&1|tail -2|sed 's/^/    CLI:/'; docker logs ${PFX}s 2>&1|tail -2|sed 's/^/    SRV:/'; }
  docker rm -f ${PFX}s ${PFX}c >/dev/null 2>&1; }

for m in native xorpub random; do
  test_dir "A NTRcli->xraySrv" xray_srv ntr_cli "$m" 0
  test_dir "B xrayCli->NTRSrv" ntr_srv xray_cli "$m" 0
done
echo "--- 0-RTT ---"
test_dir "A NTRcli->xraySrv" xray_srv ntr_cli native 1
test_dir "B xrayCli->NTRSrv" ntr_srv xray_cli native 1
cleanup; echo DONE
