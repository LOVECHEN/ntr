#!/bin/bash
# TrustTunnel UDP(_udp2 帧复用)互通:NTR <-> mihomo。线格式(禁改):H2 CONNECT 到魔术 authority "_udp2",
# 回 200 后流上双向长度前缀帧,地址只许 IP —— 客户端→服务端 [len u32][源 16B=0][源端口=0][目的 16B][目的端口]
# [appName 长][appName][payload];服务端→客户端 [len u32][源 16B][源端口][目的 16B=0][目的端口=0][payload];
# 16B 地址的 IPv4 = 12 字节 0 + 4 字节。经 socks5 UDP ASSOCIATE 打 udpecho:9999(目标以 ATYP=3 域名发),回显即通:
#   A  NTR 客户端 → mihomo 服务端     B  mihomo 客户端 → NTR 服务端(顶层 users 计量路径)
#   C  NTR ↔ NTR                     D  反向对照:NTR 客户端错口令 → UDP 必须不通
# 专属隔离:network=ixttu 容器前缀=ixttu-
set -u
NET=ixttu; PFX=ixttu-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}; U=ttuser; PW=ttudppw
MH=metacubex/mihomo:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
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
mhs(){  docker run -d --name $PFX$1 --network $NET -v $D/$2:/root/.config/mihomo/config.yaml:ro -v $D/cert.pem:/root/.config/mihomo/cert.pem:ro -v $D/key.pem:/root/.config/mihomo/key.pem:ro $MH >/dev/null 2>&1; }
mhc(){  docker run -d --name $PFX$1 --network $NET -v $D/$2:/root/.config/mihomo/config.yaml:ro $MH >/dev/null 2>&1; }
udp(){ local i out; for i in 1 2 3 4 5 6; do
  out=$(docker run --rm --network $NET -e CLI=$PFX$1 -e ECHO=${PFX}echo -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1)
  echo "$out" | grep -q "GOT b'PINGUDP-ss-42'" && { echo "$out" | tail -1; return 0; }; sleep 2; done; echo "$out" | tail -1; return 1; }
chk(){ local r; r=$(udp $1) && echo "  ✅ $2  ($r)" || echo "  ❌ $2  ($(echo "$r"|tr -d '\n'|head -c 120))"; }

printf 'users:\n  - name: %s\n    keys:\n      trusttunnel: "%s"\ninbounds:\n  - name: tt-in\n    type: trusttunnel\n    listen: 0.0.0.0:8443\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\noutbounds:\n  - name: direct\n    type: direct\n' "$U" "$PW" > $D/_ttu_ns.yaml
printf 'log-level: warning\nlisteners:\n  - name: tt-in\n    type: trusttunnel\n    port: 8443\n    listen: 0.0.0.0\n    users:\n      - username: %s\n        password: "%s"\n    certificate: /root/.config/mihomo/cert.pem\n    private-key: /root/.config/mihomo/key.pem\nrules:\n  - MATCH,DIRECT\n' "$U" "$PW" > $D/_ttu_ms.yaml
mk_ncli(){ printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: trusttunnel\n    server: "%s:8443"\n    user: %s\n    secret: "%s"\n    sni: example.com\n    insecure: true\n' "$1" "$2" "$3" > $D/$4; }
# 顶层 users 下 Basic 名 = 计量 tag(BillID@口名)
mk_ncli ${PFX}ms "$U"       "$PW"      _ttu_nc_ms.yaml
mk_ncli ${PFX}ns "$U@tt-in" "$PW"      _ttu_nc_ns.yaml
mk_ncli ${PFX}ns "$U@tt-in" "wrong-pw" _ttu_nc_bad.yaml
printf 'mixed-port: 1080\nallow-lan: true\nlog-level: warning\nproxies:\n  - name: p\n    type: trusttunnel\n    server: %sns\n    port: 8443\n    username: "%s@tt-in"\n    password: "%s"\n    sni: example.com\n    skip-cert-verify: true\n    alpn:\n      - h2\n    udp: true\nrules:\n  - MATCH,p\n' "$PFX" "$U" "$PW" > $D/_ttu_mc.yaml

nsrv ns _ttu_ns.yaml; mhs ms _ttu_ms.yaml; sleep 3
ncli ncms _ttu_nc_ms.yaml; ncli ncns _ttu_nc_ns.yaml; ncli bad _ttu_nc_bad.yaml; mhc mc _ttu_mc.yaml
sleep 4

echo "==== TrustTunnel UDP(_udp2) ===="
chk ncms "A NTR 客户端 → mihomo 服务端"
chk mc   "B mihomo 客户端 → NTR 服务端(顶层 users 计量路径)"
chk ncns "C NTR ↔ NTR"
grep -q 'wrong-pw' $D/_ttu_nc_bad.yaml || echo "  ❌ D 反向对照配置未生成"
R=$(docker run --rm --network $NET -e CLI=${PFX}bad -e ECHO=${PFX}echo -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1)
echo "$R" | grep -q "GOT b'PINGUDP-ss-42'" && echo "  ❌ D 错口令仍回显(UDP 绕过了 trusttunnel,前述结果不可信)" || echo "  ✅ D 反向对照:错口令 UDP 不通"

cleanup; echo DONE
