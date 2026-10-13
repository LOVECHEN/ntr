#!/bin/bash
# TUIC v5 UDP(assocID 会话:native = QUIC datagram / quic = 每包单向流)互通:补完 tuic 的 UDP 数据面,
# 对真 sing-box / mihomo 双向验。线格式禁改:UDP 帧全在库(sagernet/sing-quic tuic),NTR 只在两端接运行时 ——
# 入站 UDP 会话交 PacketDispatch(准入 + 计量 + udpNAT),出站 DialPacket 开会话。
# 经 socks5 UDP ASSOCIATE 打 udpecho:9999,回显即通:
#   ① NTR→sing-box  ② NTR→mihomo  ③ sing-box→NTR  ④ mihomo→NTR
#   ⑤ NTR→sing-box(udp-relay-mode: quic)  ⑥ sing-box(udp_relay_mode: quic)→NTR
#   ⑦ 反向对照:NTR 客户端错口令 → UDP 必须不通(堵「绕过 tuic 直连 echo 也回显」的假绿)
# 专属隔离:network=ixtuu 容器前缀=ixtuu-
set -u
NET=ixtuu; PFX=ixtuu-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}; PW="tuicudp123"
UUID=00000000-0000-0000-0000-0000000000ef
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
printf 'users:\n  - name: alice\n    keys:\n      tuic:\n        uuid: "%s"\n        password: "%s"\ninbounds:\n  - name: tuic-in\n    type: tuic\n    listen: 0.0.0.0:8443\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\noutbounds:\n  - name: direct\n    type: direct\n' "$UUID" "$PW" > $D/_tuu_ntrsrv.yaml
printf '{"log":{"level":"warn"},"inbounds":[{"type":"tuic","listen":"::","listen_port":8443,"users":[{"uuid":"%s","password":"%s"}],"congestion_control":"bbr","tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem","alpn":["h3"]}}],"outbounds":[{"type":"direct"}]}\n' "$UUID" "$PW" > $D/_tuu_sbsrv.json
printf 'log-level: warning\nlisteners:\n  - name: tuicin\n    type: tuic\n    listen: 0.0.0.0\n    port: 8443\n    users:\n      "%s": "%s"\n    congestion-controller: bbr\n    alpn:\n      - h3\n    certificate: /root/.config/mihomo/cert.pem\n    private-key: /root/.config/mihomo/key.pem\n' "$UUID" "$PW" > $D/_tuu_msrv.yaml
mk_ncli(){ # $1=服务端 $2=文件 $3=口令 $4=udp-relay-mode(可空)
  { printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: tuic\n    server: "%s:8443"\n    uuid: "%s"\n    secret: "%s"\n    sni: example.com\n    insecure: true\n' "$1" "$UUID" "$3"
    [ -n "${4:-}" ] && printf '    udp-relay-mode: %s\n' "$4"; } > $D/$2; }
mk_ncli ${PFX}sbsrv  _tuu_ncli_sb.yaml   "$PW"
mk_ncli ${PFX}msrv   _tuu_ncli_mh.yaml   "$PW"
mk_ncli ${PFX}sbsrv  _tuu_ncli_sbq.yaml  "$PW" quic
mk_ncli ${PFX}sbsrv  _tuu_ncli_bad.yaml  "wrong-pw"
mk_sbc(){ # $1=文件 $2=udp_relay_mode
  printf '{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"tuic","server":"%sntrsrv","server_port":8443,"uuid":"%s","password":"%s","congestion_control":"bbr","udp_relay_mode":"%s","tls":{"enabled":true,"server_name":"example.com","insecure":true,"alpn":["h3"]}}]}\n' "$PFX" "$UUID" "$PW" "$2" > $D/$1; }
mk_sbc _tuu_sbcli.json  native
mk_sbc _tuu_sbcliq.json quic
printf 'mixed-port: 1080\nallow-lan: true\nlog-level: warning\nproxies:\n  - name: p\n    type: tuic\n    server: %sntrsrv\n    port: 8443\n    uuid: "%s"\n    password: "%s"\n    congestion-controller: bbr\n    udp-relay-mode: native\n    alpn:\n      - h3\n    sni: example.com\n    skip-cert-verify: true\n    udp: true\nrules:\n  - MATCH,p\n' "$PFX" "$UUID" "$PW" > $D/_tuu_mcli.yaml

# ---- 起服务端 → 客户端 ----
nsrv ntrsrv _tuu_ntrsrv.yaml; sbs sbsrv _tuu_sbsrv.json; mhs msrv _tuu_msrv.yaml
wait_log ${PFX}ntrsrv "监听于" 15; sleep 2
ncli ncli-sb _tuu_ncli_sb.yaml; ncli ncli-mh _tuu_ncli_mh.yaml; ncli ncli-sbq _tuu_ncli_sbq.yaml; ncli ncli-bad _tuu_ncli_bad.yaml
sbc sbcli _tuu_sbcli.json; sbc sbcliq _tuu_sbcliq.json; mhc mcli _tuu_mcli.yaml
wait_log ${PFX}ncli-sb "监听于" 15; wait_log ${PFX}ncli-bad "监听于" 15; sleep 3

echo "==== TUIC v5 UDP ===="
chk ncli-sb  "① NTR tuic 客户端 → sing-box 服务端 UDP(native)"
chk ncli-mh  "② NTR tuic 客户端 → mihomo 服务端 UDP(native)"
chk sbcli    "③ sing-box tuic 客户端 → NTR 服务端 UDP(native·顶层 users 计量路径)"
chk mcli     "④ mihomo tuic 客户端 → NTR 服务端 UDP(native)"
chk ncli-sbq "⑤ NTR tuic 客户端 → sing-box 服务端 UDP(quic 中继模式)"
chk sbcliq   "⑥ sing-box tuic 客户端 → NTR 服务端 UDP(quic 中继模式)"
grep -q 'wrong-pw' $D/_tuu_ncli_bad.yaml || echo "  ❌ ⑦ 反向对照配置未生成"
R=$(docker run --rm --network $NET -e CLI=${PFX}ncli-bad -e ECHO=${PFX}echo -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1)
echo "$R" | grep -q "GOT b'PINGUDP-ss-42'" && echo "  ❌ ⑦ 错口令仍回显(UDP 绕过了 tuic,前述结果不可信)" || echo "  ✅ ⑦ 反向对照:错口令 UDP 不通"

cleanup; echo DONE
