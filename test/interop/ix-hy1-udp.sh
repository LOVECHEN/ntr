#!/bin/bash
# Hysteria v1 UDP(请求流换 UDPSessionID + QUIC datagram 会话)互通:补完 hy1 的 UDP 数据面。
# 线格式禁改:UDP 帧全在库(sagernet/sing-quic hysteria),NTR 只在两端接运行时 —— 入站 UDP 会话交
# PacketDispatch(准入 + 计量 + udpNAT),出站 DialPacket 开会话。mihomo 无 hy1 入站,故只测其客户端方向。
# 经 socks5 UDP ASSOCIATE 打 udpecho:9999,回显即通:
#   ① NTR→sing-box  ② sing-box→NTR  ③ mihomo→NTR
#   ④ 反向对照:NTR 客户端错口令 → UDP 必须不通(堵「绕过 hy1 直连 echo 也回显」的假绿)
# 专属隔离:network=ixh1u 容器前缀=ixh1u-
set -u
NET=ixh1u; PFX=ixh1u-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}; PW="hy1udp123"
SB=ghcr.io/sagernet/sing-box:latest
MH=metacubex/mihomo:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
cp "$(dirname "$0")"/udpecho.py "$(dirname "$0")"/socksudp-cfg.py $D/ 2>/dev/null
# 证书自举(脚本自包含;缺失时 docker 会把单文件挂载点建成空目录)
for f in cert.pem key.pem ca.pem; do [ -d "$D/$f" ] && rmdir "$D/$f"; done
[ -f "$D/cert.pem" ] && [ -f "$D/key.pem" ] || docker run --rm -v $D:/w -w /w alpine sh -c 'apk add openssl>/dev/null 2>&1; openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 90 -nodes -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com" -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1'
[ -f "$D/ca.pem" ] || cp $D/cert.pem $D/ca.pem
chmod 644 $D/cert.pem $D/key.pem $D/ca.pem 2>/dev/null
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1

nsrv(){ docker run -d --name $PFX$1 --network $NET -v $NTR:/ntr:ro -v $D/$2:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
ncli(){ docker run -d --name $PFX$1 --network $NET -v $NTR:/ntr:ro -v $D/$2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
sbs(){  docker run -d --name $PFX$1 --network $NET -v $D/$2:/c.json:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro $SB -c /c.json run >/dev/null 2>&1; }
sbc(){  docker run -d --name $PFX$1 --network $NET -v $D/$2:/c.json:ro $SB -c /c.json run >/dev/null 2>&1; }
mhs(){  docker run -d --name $PFX$1 --network $NET -v $D/$2:/root/.config/mihomo/config.yaml:ro -v $D/cert.pem:/root/.config/mihomo/cert.pem:ro -v $D/key.pem:/root/.config/mihomo/key.pem:ro $MH >/dev/null 2>&1; }
mhc(){  docker run -d --name $PFX$1 --network $NET -v $D/$2:/root/.config/mihomo/config.yaml:ro $MH >/dev/null 2>&1; }
# UDP 探测:QUIC 冷启动 / 对端未就绪时首包可能丢,重试至回显
runudp(){ local i out; for i in 1 2 3 4 5 6; do
  out=$(docker run --rm --network $NET -e CLI=$PFX$1 -e ECHO=${PFX}echo -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1)
  echo "$out" | grep -q "GOT b'PINGUDP-ss-42'" && { echo "$out" | tail -1; return 0; }; sleep 2; done; echo "$out" | tail -1; return 1; }
chk(){ local r; r=$(runudp $1) && echo "  ✅ $2  ($r)" || echo "  ❌ $2  ($(echo "$r"|tr -d '\n'|head -c 120))"; }

# ---- 配置 ----
printf 'users:\n  - name: alice\n    keys:\n      hysteria1: "%s"\ninbounds:\n  - name: hy1-in\n    type: hysteria1\n    listen: 0.0.0.0:8443\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\noutbounds:\n  - name: direct\n    type: direct\n' "$PW" > $D/_h1u_ntrsrv.yaml
printf '{"log":{"level":"warn"},"inbounds":[{"type":"hysteria","listen":"::","listen_port":8443,"up_mbps":100,"down_mbps":100,"users":[{"auth_str":"%s"}],"tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem","alpn":["hysteria"]}}],"outbounds":[{"type":"direct"}]}\n' "$PW" > $D/_h1u_sbsrv.json
mk_ncli(){ printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: hysteria1\n    server: "%s:8443"\n    secret: "%s"\n    sni: example.com\n    insecure: true\n' "$1" "$3" > $D/$2; }
mk_ncli ${PFX}sbsrv _h1u_ncli_sb.yaml  "$PW"
mk_ncli ${PFX}sbsrv _h1u_ncli_bad.yaml "wrong-pw"
printf '{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"hysteria","server":"%sntrsrv","server_port":8443,"up_mbps":100,"down_mbps":100,"auth_str":"%s","tls":{"enabled":true,"server_name":"example.com","insecure":true,"alpn":["hysteria"]}}]}\n' "$PFX" "$PW" > $D/_h1u_sbcli.json
printf 'mixed-port: 1080\nallow-lan: true\nlog-level: warning\nproxies:\n  - name: p\n    type: hysteria\n    server: %sntrsrv\n    port: 8443\n    auth-str: "%s"\n    up: "100 Mbps"\n    down: "100 Mbps"\n    sni: example.com\n    skip-cert-verify: true\n    alpn:\n      - hysteria\n    udp: true\nrules:\n  - MATCH,p\n' "$PFX" "$PW" > $D/_h1u_mcli.yaml

# ---- 起服务端 → 客户端 ----
nsrv ntrsrv _h1u_ntrsrv.yaml; sbs sbsrv _h1u_sbsrv.json
wait_log ${PFX}ntrsrv "监听于" 15; sleep 2
ncli ncli-sb _h1u_ncli_sb.yaml; ncli ncli-bad _h1u_ncli_bad.yaml
sbc sbcli _h1u_sbcli.json; mhc mcli _h1u_mcli.yaml
wait_log ${PFX}ncli-sb "监听于" 15; wait_log ${PFX}ncli-bad "监听于" 15; sleep 3

echo "==== Hysteria v1 UDP ===="
chk ncli-sb "① NTR hy1 客户端 → sing-box 服务端 UDP"
chk sbcli   "② sing-box hy1 客户端 → NTR 服务端 UDP(顶层 users 计量路径)"
chk mcli    "③ mihomo hy1 客户端 → NTR 服务端 UDP"
grep -q 'wrong-pw' $D/_h1u_ncli_bad.yaml || echo "  ❌ ④ 反向对照配置未生成"
R=$(docker run --rm --network $NET -e CLI=${PFX}ncli-bad -e ECHO=${PFX}echo -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1)
echo "$R" | grep -q "GOT b'PINGUDP-ss-42'" && echo "  ❌ ④ 错口令仍回显(UDP 绕过了 hy1,前述结果不可信)" || echo "  ✅ ④ 反向对照:错口令 UDP 不通"

cleanup; echo DONE
