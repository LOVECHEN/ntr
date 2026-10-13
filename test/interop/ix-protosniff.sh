#!/bin/bash
# ============================================================================
# 协议级嗅探端到端:UDP 首包识别 STUN / DTLS / QUIC → protocol 规则拦截
# (WebRTC 防真实公网 IP 泄漏:不靠端口/域名/IP 名单,靠报文本身的协议铁证)
#
# 机制:socks UDP ASSOCIATE 关联里,udpnat 对【新目标】的首包 sniffPacket 识别协议,
#       按 routing.rules 的 protocol 维度选出站;同一目标之后沿用首次路由 —— 故每个
#       用例发往【不同目标端口】。
# 判据:
#   A(规则 protocol:[stun,dtls,quic]→block):
#     ① STUN binding request → echo:9001  收不到回显(被拦)
#     ② DTLS 握手 record      → echo:9002  收不到回显(被拦)
#     ③ QUIC v1 Initial 长包头 → echo:9003  收不到回显(被拦)
#     ④ 普通负载              → echo:9004  正常回显(未误拦)
#   B(负向对照,无 protocol 规则):
#     ⑤ 同样的 STUN 包        → echo:9001  正常回显 —— 证 A 的拦截确由规则贡献
# 自包含:python 助手内联生成(隔离 CI job 无前序产物)。专属 network=ixps,前缀=ixps-
# ============================================================================
set -u
NET=ixps; PFX=ixps-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
PY=python:3-alpine
mkdir -p "$D"
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1 | grep -q "$2" && return 0; sleep 0.5; done; return 1; }
trap cleanup EXIT
cleanup; docker network create $NET >/dev/null 2>&1

# UDP 回显靶机:同一容器监听 9001-9004,收啥回啥
cat > $D/_ps_echo.py <<'PY'
import socket, threading
def serve(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', p))
    while True:
        d, a = s.recvfrom(4096)
        s.sendto(d, a)
for p in (9001, 9002, 9003):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
serve(9004)
PY

# socks5 UDP 客户端:一条关联里按 [(端口, 用例名, 负载)] 逐个发,每个等 3s,打印 GOT/TIMEOUT
cat > $D/_ps_client.py <<'PY'
import socket, struct, sys
cases = sys.argv[1].split(',')  # 形如 stun:9001,dtls:9002
stun = struct.pack('>HHI', 0x0001, 0, 0x2112A442) + b'\x11' * 12            # 20B binding request
dtls = bytes([22, 0xfe, 0xfd]) + b'\x00\x00' + b'\x00' * 6 + struct.pack('>H', 4) + b'\x01\x00\x00\x00'
quic = bytes([0xc0]) + struct.pack('>I', 1) + bytes([8]) + b'\x22' * 8 + bytes([0]) + b'\x00' * 16
plain = b'hello-plain-payload'
pay = {'stun': stun, 'dtls': dtls, 'quic': quic, 'plain': plain}
tcp = socket.create_connection(('cli', 1080), timeout=8)
tcp.sendall(b'\x05\x01\x00')
if tcp.recv(2) != b'\x05\x00':
    print('GREET_FAIL'); sys.exit(2)
tcp.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
r = tcp.recv(10)
if len(r) < 10 or r[1] != 0:
    print('ASSOC_FAIL', r); sys.exit(3)
bip = socket.inet_ntoa(r[4:8]); bport = struct.unpack('>H', r[8:10])[0]
if bip in ('0.0.0.0', '127.0.0.1'):
    bip = socket.gethostbyname('cli')
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
host = b'echo'
for c in cases:
    name, port = c.split(':'); port = int(port)
    body = pay[name]
    hdr = b'\x00\x00\x00\x03' + bytes([len(host)]) + host + struct.pack('>H', port)
    u.sendto(hdr + body, (bip, bport))
    try:
        d, _ = u.recvfrom(4096)
        atyp = d[3]
        off = 10 if atyp == 1 else (22 if atyp == 4 else 4 + 1 + d[4] + 2)
        print(f'{name}:{port}=' + ('GOT' if d[off:] == body else 'GOT_MISMATCH'))
    except socket.timeout:
        print(f'{name}:{port}=TIMEOUT')
PY

docker run -d --name ${PFX}echo --network-alias echo --network $NET -v $D/_ps_echo.py:/e.py:ro $PY python3 /e.py >/dev/null 2>&1

mkntr(){ # $1=标签 $2=routing 块(空=无规则)
  cat > $D/_ps_$1.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: direct
outbounds:
  - name: direct
    type: direct
  - name: block
    type: block
$2
Y
  docker rm -f ${PFX}cli >/dev/null 2>&1
  docker run -d --name ${PFX}cli --network-alias cli --network $NET -v $NTR:/ntr:ro -v $D/_ps_$1.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  wait_log ${PFX}cli "监听于" 15 || { echo "  NTR 未就绪:"; docker logs ${PFX}cli 2>&1 | tail -5; }
}
run(){ docker run --rm --network $NET -v $D/_ps_client.py:/c.py:ro $PY python3 /c.py "$1" 2>&1; }
PASS=0; FAIL=0
chk(){ # $1=说明 $2=输出 $3=键 $4=期望
  if echo "$2" | grep -qx "$3=$4"; then echo "  ✅ $1"; PASS=$((PASS+1));
  else echo "  ❌ $1(期望 $3=$4,实得:$(echo "$2" | grep "^$3=" | head -1))"; FAIL=$((FAIL+1)); fi
}

sleep 1
echo "===== A: protocol:[stun,dtls,quic] → block ====="
mkntr rule 'routing:
  default: direct
  rules:
    - protocol:
        - stun
        - dtls
        - quic
      to: block'
OA=$(run 'stun:9001,dtls:9002,quic:9003,plain:9004'); echo "$OA" | sed 's/^/    /'
chk "① STUN 首包被拦"           "$OA" stun:9001  TIMEOUT
chk "② DTLS 首包被拦"           "$OA" dtls:9002  TIMEOUT
chk "③ QUIC Initial 首包被拦"   "$OA" quic:9003  TIMEOUT
chk "④ 普通负载正常回显(未误拦)" "$OA" plain:9004 GOT

echo "===== B: 负向对照 —— 无 protocol 规则 ====="
mkntr norule ''
OB=$(run 'stun:9001'); echo "$OB" | sed 's/^/    /'
chk "⑤ 同样的 STUN 包无规则时正常回显(证 A 的拦截来自规则)" "$OB" stun:9001 GOT

echo "════════ ix-protosniff 结论:PASS=$PASS FAIL=$FAIL ════════"
[ "$FAIL" -eq 0 ] && echo "✅ 协议级嗅探 STUN/DTLS/QUIC 拦截全绿" || echo "❌ 有失败"
