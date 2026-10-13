#!/bin/bash
# ShadowQUIC UDP 关联互通:NTR <-> mihomo(唯一另一实现;xray/sing-box 无)。线格式(对齐 mihomo
# transport/shadowquic,禁改):关联 = 双向流 [cmd 0x03|0x04][socks5addr] 后作控制流,每方向首次往某地址发包前
# 宣告 [socks5addr][id u16];数据走 QUIC datagram [id][payload](0x03)或每地址一条单向流 [id]+[len][payload](0x04)。
# 经 socks5 UDP ASSOCIATE 打 udpecho:9999(目标以 ATYP=3 域名发),回显即通:
#   A1/A2 mihomo 客户端 → NTR 服务端(datagram / udp-over-stream)
#   B1/B2 NTR 客户端 → mihomo 服务端(datagram / udp-over-stream)
#   C1/C2 NTR ↔ NTR(datagram / udp-over-stream)
#   D     反向对照:NTR 客户端错口令 → UDP 必须不通(堵「绕过 shadowquic 直连 echo 也回显」的假绿)
# 专属隔离:network=ixsqu 容器前缀=ixsqu-
set -u
NET=ixsqu; PFX=ixsqu-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
U=squser; PW=sqpass
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cp "$(dirname "$0")"/udpecho.py "$(dirname "$0")"/socksudp-cfg.py $D/ 2>/dev/null
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}echo --network $NET -v $D/udpecho.py:/e.py:ro python:3-alpine python /e.py >/dev/null 2>&1
run_ntr(){ docker run -d --name $1 --network $NET -v $NTR:/ntr:ro -v $2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
run_mi(){ docker run -d --name $1 --network $NET -v $2:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1; }
# UDP 探测:QUIC 冷启动 / 对端未就绪时首包可能丢,重试至回显
udp(){ local i out; for i in 1 2 3 4 5 6; do
  out=$(docker run --rm --network $NET -e CLI=$1 -e ECHO=${PFX}echo -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1)
  echo "$out" | grep -q "GOT b'PINGUDP-ss-42'" && { echo "$out" | tail -1; return 0; }; sleep 2; done; echo "$out" | tail -1; return 1; }
chk(){ local r; r=$(udp $1) && echo "  ✅ $2  ($r)" || echo "  ❌ $2  ($(echo "$r"|tr -d '\n'|head -c 120))"; }

ntr_srv(){ cat > $1 <<Y
inbounds:
  - name: sq-in
    type: shadowquic
    listen: 0.0.0.0:10000
    tls:
      sni: example.com
    users:
      - username: $U
        password: $PW
outbounds:
  - name: direct
    type: direct
Y
}
ntr_cli(){ # $1=文件 $2=服务端 $3=udp-over-stream(true|false) $4=口令
  cat > $1 <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: up
outbounds:
  - name: up
    type: shadowquic
    server: "$2:10000"
    user: $U
    secret: $4
    sni: example.com
    udp-over-stream: $3
Y
}
mi_cli(){ # $1=文件 $2=服务端 $3=udp-over-stream
  cat > $1 <<Y
log-level: warning
mixed-port: 1080
allow-lan: true
proxies:
  - name: p
    type: shadowquic
    server: $2
    port: 10000
    username: $U
    password: $PW
    sni: example.com
    alpn:
      - h3
    udp: true
    udp-over-stream: $3
rules:
  - MATCH,p
Y
}
mi_srv(){ cat > $1 <<Y
log-level: warning
listeners:
  - name: sq-in
    type: shadowquic
    listen: 0.0.0.0
    port: 10000
    users:
      - username: $U
        password: $PW
    jls-upstream:
      addr: "example.com:443"
      sni: example.com
    alpn:
      - h3
Y
}

# A:mihomo 客户端 → NTR 服务端
ntr_srv $D/_squ_ns.yaml; run_ntr ${PFX}ns $D/_squ_ns.yaml; sleep 2
mi_cli $D/_squ_mc1.yaml ${PFX}ns false; run_mi ${PFX}mc1 $D/_squ_mc1.yaml
mi_cli $D/_squ_mc2.yaml ${PFX}ns true;  run_mi ${PFX}mc2 $D/_squ_mc2.yaml
# B:NTR 客户端 → mihomo 服务端
mi_srv $D/_squ_ms.yaml; run_mi ${PFX}ms $D/_squ_ms.yaml; sleep 3
ntr_cli $D/_squ_nc1.yaml ${PFX}ms false $PW; run_ntr ${PFX}nc1 $D/_squ_nc1.yaml
ntr_cli $D/_squ_nc2.yaml ${PFX}ms true  $PW; run_ntr ${PFX}nc2 $D/_squ_nc2.yaml
# C:NTR ↔ NTR;D:错口令
ntr_cli $D/_squ_nn1.yaml ${PFX}ns false $PW;      run_ntr ${PFX}nn1 $D/_squ_nn1.yaml
ntr_cli $D/_squ_nn2.yaml ${PFX}ns true  $PW;      run_ntr ${PFX}nn2 $D/_squ_nn2.yaml
ntr_cli $D/_squ_bad.yaml ${PFX}ns false wrongpw;  run_ntr ${PFX}bad $D/_squ_bad.yaml
sleep 4

echo "==== ShadowQUIC UDP ===="
chk ${PFX}mc1 "A1 mihomo 客户端 → NTR 服务端(datagram)"
chk ${PFX}mc2 "A2 mihomo 客户端 → NTR 服务端(udp-over-stream)"
chk ${PFX}nc1 "B1 NTR 客户端 → mihomo 服务端(datagram)"
chk ${PFX}nc2 "B2 NTR 客户端 → mihomo 服务端(udp-over-stream)"
chk ${PFX}nn1 "C1 NTR ↔ NTR(datagram)"
chk ${PFX}nn2 "C2 NTR ↔ NTR(udp-over-stream)"
grep -q 'wrongpw' $D/_squ_bad.yaml || echo "  ❌ D 反向对照配置未生成"
R=$(docker run --rm --network $NET -e CLI=${PFX}bad -e ECHO=${PFX}echo -v $D/socksudp-cfg.py:/u.py:ro python:3-alpine python /u.py 2>&1)
echo "$R" | grep -q "GOT b'PINGUDP-ss-42'" && echo "  ❌ D 错口令仍回显(UDP 绕过了 shadowquic,前述结果不可信)" || echo "  ✅ D 反向对照:错口令 UDP 不通"

cleanup; echo DONE
