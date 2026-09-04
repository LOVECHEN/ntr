#!/bin/bash
# ============================================================================
# 交叉验证:MASQUE ↔ mihomo   (docker network=xc-mq  容器前缀=xcm-)
# ----------------------------------------------------------------------------
# 结论:mihomo 的 masque 出站是 Cloudflare WARP 的 CONNECT-IP(RFC 9484,
#       走 connect-ip-go,全 L3 IP 隧道 + TUN/netstack),而 NTR 的 masque 是
#       RFC 9298 connect-udp(逐流 UDP)+ RFC 9220 CONNECT-over-h3(TCP)。
#       两者是【不同 MASQUE 变体,线格式不同,不可互通】—— (c) 类,非 NTR 失败。
#       NTR 未做任何修改。
# 本脚本:①方向 A 实证 —— mihomo masque 客户端打 NTR masque 服务端 → 得 connect-ip 400;
#         ②方向 B —— mihomo 无 masque inbound(文档已证),N/A;
#         ③回退验证 NTR masque 自环 TCP + UDP 仍通。
# ============================================================================
set -u
NET=xc-mq; PFX=xcm-; D=/tmp/ntr-interop; DEST=example.com
cleanup(){ docker rm -f ${PFX}target ${PFX}srv ${PFX}cli ${PFX}echo ${PFX}mihomo cli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1

echo "########################################################################"
echo "# 方向 A:mihomo masque 客户端(connect-ip)→ NTR masque 服务端"
echo "########################################################################"
printf 'inbounds:\n  - name: srv-in\n    type: masque\n    listen: 0.0.0.0:8443\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\noutbounds:\n  - name: direct\n    type: direct\n' > $D/${PFX}srv.yaml
docker run -d --name ${PFX}srv --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/${PFX}srv.yaml:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
# mihomo masque 需 WARP 专有字段:SEC1 EC 私钥/公钥 + ip CIDR + mtu
openssl ecparam -name prime256v1 -genkey -noout -out $D/${PFX}ec.key 2>/dev/null
PRIV=$(openssl ec -in $D/${PFX}ec.key -outform DER 2>/dev/null | base64 | tr -d '\n')
PUB=$(openssl ec -in $D/${PFX}ec.key -pubout -outform DER 2>/dev/null | base64 | tr -d '\n')
cat > $D/${PFX}mihomo.yaml <<EOF
mixed-port: 1080
allow-lan: true
bind-address: '*'
log-level: warning
proxies:
  - {name: up, type: masque, server: xcm-srv, port: 8443, sni: example.com, private-key: $PRIV, public-key: $PUB, ip: 172.16.0.2/32, mtu: 1280, skip-cert-verify: true, udp: true}
rules:
  - MATCH,up
EOF
docker run -d --name ${PFX}mihomo --network $NET -v $D/${PFX}mihomo.yaml:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
sleep 6
docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x socks5h://${PFX}mihomo:1080 http://${PFX}target/ >/dev/null 2>&1
sleep 2
MLOG=$(docker logs ${PFX}mihomo 2>&1 | grep -iE "connect-ip|masque" | tail -1)
if echo "$MLOG" | grep -qi "connect-ip"; then
  echo "✅[如实报告-不可互通] mihomo 发的是 CONNECT-IP,NTR 回 400:"
  echo "   $MLOG"
else
  echo "?? 未捕获 connect-ip 日志:$MLOG"
fi
docker rm -f ${PFX}mihomo ${PFX}target >/dev/null 2>&1

echo
echo "########################################################################"
echo "# 方向 B:mihomo 有无 masque inbound?"
echo "########################################################################"
echo "   mihomo 无 masque 入站/监听(wiki 仅列 masque 出站;transport/masque 只有客户端"
echo "   ConnectTunnel/L4Client)。→ N/A,无法测。"

echo
echo "########################################################################"
echo "# 回退验证:NTR masque 自环 TCP(RFC 9220 CONNECT over h3)"
echo "########################################################################"
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null
printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: masque\n    server: "xcm-srv:8443"\n    sni: %s\n    insecure: true\n' "$DEST" > $D/${PFX}cli.yaml
docker run -d --name ${PFX}cli --network $NET -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/${PFX}cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 5
OUT=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x socks5h://${PFX}cli:1080 http://${PFX}target/ 2>&1)
echo "$OUT" | grep -q Hostname && echo "✅ NTR-masque-TCP 自环通  ($(echo "$OUT"|grep Hostname))" || { echo "❌ 不通"; docker logs ${PFX}srv 2>&1|tail -6; docker logs ${PFX}cli 2>&1|tail -6; }
docker rm -f ${PFX}target ${PFX}cli >/dev/null 2>&1

echo
echo "########################################################################"
echo "# 回退验证:NTR masque 自环 UDP(RFC 9298 connect-udp + HTTP Datagram)"
echo "########################################################################"
docker run -d --name ${PFX}echo --network $NET --network-alias echo -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
sleep 2
docker run -d --name cli --network $NET --network-alias cli -e NTR_DEBUG=1 -v $D/ntr:/ntr:ro -v $D/${PFX}cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 4
RC=1; docker run --rm --network $NET -v $D/socksudp.py:/c.py:ro python:3-alpine python /c.py 2>&1 && RC=0 || RC=$?
[ $RC -eq 0 ] && echo "✅ NTR-masque-UDP 自环通(connect-udp)" || { echo "❌ 不通 rc=$RC"; docker logs ${PFX}srv 2>&1|tail -6; docker logs cli 2>&1|tail -6; }

cleanup; rm -f $D/${PFX}ec.key
echo; echo "######## done ########"
