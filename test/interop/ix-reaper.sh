#!/bin/bash
# reaper 生命周期脊柱(§10)e2e:
#   ① Seam 3 idle reaper —— vless 口(metrics + lifecycle.tcp-idle 短)建一条【空闲】计量连接(目标只接不回),
#      断言 conns_live 先 ≥1、过 tcp-idle+tick 后被回收归 0(时间驱动 sweep,非仅 mem-guard 硬档)。
#   ② Seam 1 握手 deadline —— 裸 TCP 连 vless 口一字节不发(slow-loris),断言服务端在 handshake deadline
#      内主动断开(读到 EOF),而非永久钉住。
# 自包含(遵 ntr-ci-interop-self-contained):$D 只需 ntr 二进制;明文 vless 无需证书。
set -u
NET=ix-reaper; PFX=ixrp-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
UUID="cccccccc-cccc-cccc-cccc-cccccccccccc"
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1

# 目标:只 accept 不回包(让穿过隧道的连接保持空闲,便于触发 idle reaper)
docker run -d --name ${PFX}hold --network $NET python:3-alpine python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',80)); s.listen(64)
conns=[]
while True:
    c,_=s.accept(); conns.append(c)  # 只留着,永不回写
" >/dev/null 2>&1

# vless 服务端:metrics + lifecycle(handshake 2s / tcp-idle 5s)+ 口内 user
cat > $D/_reaper-srv.yaml <<Y
metrics:
  access:
    - "0.0.0.0/0"
  listen: 0.0.0.0:9091
lifecycle:
  handshake: 2s
  tcp-idle: 5s
inbounds:
  - name: vless-in
    type: vless
    listen: 0.0.0.0:10000
    users:
      - uuid: "$UUID"
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_reaper-srv.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
# vless 客户端:socks → vless
cat > $D/_reaper-cli.yaml <<Y
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
Y
docker run -d --name ${PFX}cli --network $NET -v $NTR:/ntr:ro -v $D/_reaper-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 2

stats(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 5 http://${PFX}s:9091/stats 2>/dev/null; }
live(){ stats | grep -oE '"conns_live":[0-9]+' | grep -oE '[0-9]+' | sort -rn | head -1; }  # 取最大槽的 live
pass=0; fail=0

echo "=== Seam 3:建空闲计量连接(curl 穿隧道打 hold 目标,会 idle 挂住)==="
docker run -d --name ${PFX}probe --network $NET curlimages/curl:latest -s --max-time 60 -x socks5h://${PFX}cli:1080 http://${PFX}hold/ >/dev/null 2>&1
sleep 3
l0=$(live); l0=${l0:-0}
if [ "$l0" -ge 1 ]; then echo "  [建连后 conns_live=$l0 ≥1] PASS"; pass=$((pass+1)); else echo "  [建连后 conns_live=$l0 应≥1] FAIL"; fail=$((fail+1)); fi

echo "=== 等 tcp-idle(5s)+ reaper tick 回收空闲连接(轮询至多 20s)==="
reaped=0
for i in $(seq 1 20); do
  sleep 1
  ln=$(live); ln=${ln:-0}
  if [ "$ln" = 0 ]; then reaped=1; echo "  第 ${i}s:conns_live=0(已回收)"; break; fi
done
if [ "$reaped" = 1 ]; then echo "  [空闲连接被 idle reaper 回收→conns_live=0] PASS"; pass=$((pass+1)); else echo "  [空闲连接未被回收] FAIL(conns_live=$(live))"; fail=$((fail+1)); docker logs ${PFX}s 2>&1|tail -6|sed 's/^/  SRV:/'; fi

echo "=== Seam 1:slow-loris 裸 TCP 连 vless 口不发字节,应被 handshake deadline 断开 ==="
# 连上后阻塞 recv;服务端 2s handshake deadline 到 → 关连接 → recv 返回(EOF/空)。测总耗时应 < ~5s。
sl=$(docker run --rm --network $NET python:3-alpine python3 -c "
import socket,time
s=socket.socket(); s.settimeout(10); t=time.time()
s.connect(('${PFX}s',10000))
try:
    data=s.recv(16)          # 不发任何字节;等服务端因 handshake 超时主动关
    print('closed', round(time.time()-t,1))
except Exception as e:
    print('err', round(time.time()-t,1))
" 2>&1)
echo "  slow-loris 结果:$sl"
secs=$(echo "$sl" | grep -oE '[0-9]+\.[0-9]+' | head -1)
# 服务端在 ~2s handshake deadline 内关连接(给足余量 <5s)= PASS
if echo "$sl" | grep -q closed && [ -n "$secs" ] && awk "BEGIN{exit !($secs<5)}"; then
  echo "  [slow-loris 被 handshake deadline 断开(${secs}s)] PASS"; pass=$((pass+1))
else
  echo "  [slow-loris 未在 deadline 内断开] FAIL"; fail=$((fail+1))
fi

echo "═══ reaper e2e: $pass 通 / $fail 失败 ═══"
cleanup; echo DONE
