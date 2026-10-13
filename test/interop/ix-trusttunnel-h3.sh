#!/bin/bash
# TrustTunnel over HTTP/3(QUIC)互通:NTR <-> mihomo。与 H2 同一语义 —— 普通 CONNECT(:authority = 目标 / _udp2),
# 回 200 后请求流即双向字节流;服务端在与 H2 相同的端口另开 UDP 跑 H3(NTR quic: true,mihomo network: [tcp, udp]),
# 客户端 quic: true。判据:TCP 经 socks5h 打 whoami 拿 Hostname;UDP 经 socks5 UDP ASSOCIATE 打 udpecho 回显。
#   A1/A2 NTR 客户端 → mihomo 服务端(TCP / UDP)      B1/B2 mihomo 客户端 → NTR 服务端(TCP / UDP)
#   C     NTR ↔ NTR(TCP + UDP)
#   D1/D2 反向对照:服务端不开 quic(只有 H2/TCP),NTR / mihomo 的 quic 客户端都必须不通(证明前述确实走的 H3,
#         且 mihomo 客户端不会回落 H2)
# 专属隔离:network=ixtth3 容器前缀=ixtth3-
set -u
NET=ixtth3; PFX=ixtth3-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}; U=ttuser; PW=tth3pw
MH=metacubex/mihomo:latest; CURL=curlimages/curl:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cp "$(dirname "$0")"/udpecho.py "$(dirname "$0")"/socksudp-cfg.py $D/ 2>/dev/null
# 证书自举(脚本自包含;缺失时 docker 会把单文件挂载点建成空目录)
for f in cert.pem key.pem ca.pem; do [ -d "$D/$f" ] && rmdir "$D/$f"; done
[ -f "$D/cert.pem" ] && [ -f "$D/key.pem" ] || docker run --rm -v $D:/w -w /w alpine sh -c 'apk add openssl>/dev/null 2>&1; openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 90 -nodes -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com" -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1'
[ -f "$D/ca.pem" ] || cp $D/cert.pem $D/ca.pem
chmod 644 $D/cert.pem $D/key.pem $D/ca.pem 2>/dev/null
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
docker run -d --name ${PFX}echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
nsrv(){ docker run -d --name $PFX$1 --network $NET -v $NTR:/ntr:ro -v $D/$2:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
ncli(){ docker run -d --name $PFX$1 --network $NET -v $NTR:/ntr:ro -v $D/$2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
mhs(){  docker run -d --name $PFX$1 --network $NET -v $D/$2:/root/.config/mihomo/config.yaml:ro -v $D/cert.pem:/root/.config/mihomo/cert.pem:ro -v $D/key.pem:/root/.config/mihomo/key.pem:ro $MH >/dev/null 2>&1; }
mhc(){  docker run -d --name $PFX$1 --network $NET -v $D/$2:/root/.config/mihomo/config.yaml:ro $MH >/dev/null 2>&1; }
tcp(){ local i out; for i in 1 2 3 4 5; do out=$(docker run --rm --network $NET $CURL -s --max-time 8 -x socks5h://$PFX$1:1080 http://${PFX}target/ 2>&1); echo "$out" | grep -q Hostname && { echo "$out" | grep Hostname; return 0; }; sleep 2; done; echo "$out" | head -c 100; return 1; }
udp(){ local i out; for i in 1 2 3 4 5; do out=$(docker run --rm --network $NET -e CLI=$PFX$1 -e ECHO=${PFX}echo -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1); echo "$out" | grep -q "GOT b'PINGUDP-ss-42'" && { echo "$out" | tail -1; return 0; }; sleep 2; done; echo "$out" | tail -1; return 1; }
chk(){ local r; r=$($1 $2) && echo "  ✅ $3  ($r)" || echo "  ❌ $3  ($(echo "$r"|tr -d '\n'|head -c 120))"; }

ntr_srv(){ # $1=文件 $2=quic(true|false)
  printf 'inbounds:\n  - name: tt-in\n    type: trusttunnel\n    listen: 0.0.0.0:8443\n    quic: %s\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\n    users:\n      - name: %s\n        password: "%s"\noutbounds:\n  - name: direct\n    type: direct\n' "$2" "$U" "$PW" > $D/$1; }
ntr_cli(){ printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: trusttunnel\n    server: "%s:8443"\n    user: %s\n    secret: "%s"\n    sni: example.com\n    insecure: true\n    quic: true\n' "$1" "$U" "$PW" > $D/$2; }
ntr_srv _tth3_ns.yaml true; ntr_srv _tth3_ns_noquic.yaml false
printf 'log-level: warning\nlisteners:\n  - name: tt-in\n    type: trusttunnel\n    port: 8443\n    listen: 0.0.0.0\n    users:\n      - username: %s\n        password: "%s"\n    certificate: /root/.config/mihomo/cert.pem\n    private-key: /root/.config/mihomo/key.pem\n    network:\n      - tcp\n      - udp\nrules:\n  - MATCH,DIRECT\n' "$U" "$PW" > $D/_tth3_ms.yaml
ntr_cli ${PFX}ms _tth3_nc_ms.yaml; ntr_cli ${PFX}ns _tth3_nc_ns.yaml; ntr_cli ${PFX}nsh2 _tth3_nc_h2only.yaml
mk_mc(){ printf 'mixed-port: 1080\nallow-lan: true\nlog-level: warning\nproxies:\n  - name: p\n    type: trusttunnel\n    server: %s\n    port: 8443\n    username: %s\n    password: "%s"\n    sni: example.com\n    skip-cert-verify: true\n    quic: true\n    udp: true\nrules:\n  - MATCH,p\n' "$1" "$U" "$PW" > $D/$2; }
mk_mc ${PFX}ns _tth3_mc.yaml; mk_mc ${PFX}nsh2 _tth3_mc_h2only.yaml

nsrv ns _tth3_ns.yaml; nsrv nsh2 _tth3_ns_noquic.yaml; mhs ms _tth3_ms.yaml; sleep 3
ncli ncms _tth3_nc_ms.yaml; ncli ncns _tth3_nc_ns.yaml; ncli nch2 _tth3_nc_h2only.yaml; mhc mc _tth3_mc.yaml; mhc mch2 _tth3_mc_h2only.yaml
sleep 4

echo "==== TrustTunnel over HTTP/3 ===="
chk tcp ncms "A1 NTR 客户端 → mihomo 服务端(H3 · TCP)"
chk udp ncms "A2 NTR 客户端 → mihomo 服务端(H3 · UDP _udp2)"
chk tcp mc   "B1 mihomo 客户端 → NTR 服务端(H3 · TCP)"
chk udp mc   "B2 mihomo 客户端 → NTR 服务端(H3 · UDP _udp2)"
chk tcp ncns "C1 NTR ↔ NTR(H3 · TCP)"
chk udp ncns "C2 NTR ↔ NTR(H3 · UDP _udp2)"
R=$(docker run --rm --network $NET $CURL -s --max-time 8 -x socks5h://${PFX}nch2:1080 http://${PFX}target/ 2>&1)
echo "$R" | grep -q Hostname && echo "  ❌ D1 服务端未开 quic,NTR quic 客户端仍通(并非走 H3,前述结果不可信)" || echo "  ✅ D1 反向对照:服务端只有 H2 时 NTR quic 客户端不通"
R=$(docker run --rm --network $NET $CURL -s --max-time 8 -x socks5h://${PFX}mch2:1080 http://${PFX}target/ 2>&1)
echo "$R" | grep -q Hostname && echo "  ❌ D2 服务端未开 quic,mihomo quic 客户端仍通(回落了 H2,B 组不可信)" || echo "  ✅ D2 反向对照:服务端只有 H2 时 mihomo quic 客户端不通"

cleanup; echo DONE
