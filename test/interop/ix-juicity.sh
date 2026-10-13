#!/bin/bash
# ============================================================================
# Juicity 交叉验证:NTR 自写实现 ↔ 官方 juicity(github.com/juicity/juicity,钉 v0.5.0)
# xray/sing-box/mihomo 均无 juicity,唯一权威对端是官方二进制(从源码自举,缓存于 $D)。
#
#   A 官方 juicity-client → NTR juicity 入站
#     A1 TCP:client 的 socks5 → curl whoami(域名目标,NTR 服务端解析)
#     A2 UDP:client 的 forward 0.0.0.0:5353/udp → uecho:9999(域名 UDP 目标,NTR 服务端 udpNAT)
#   B NTR juicity 出站 → 官方 juicity-server
#     B1 TCP:NTR socks 入站 → juicity 出站 → curl whoami
#     B2 UDP:NTR socks UDP ASSOCIATE → juicity 出站 → uecho:9999
#   C 负向对照(错密码必须不通)
#     C1 官方 client 错密码 → NTR 服务端   C2 NTR 错密码 → 官方服务端
#
# 自包含:证书 / 官方二进制 / python 助手都在本脚本内自举(CI 隔离 job 无前序产物)。
# 专属 network=ixjc,前缀=ixjc-
# ============================================================================
set -u
NET=ixjc; PFX=ixjc-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
JV=v0.5.0
JS=$D/juicity-server-$JV; JC=$D/juicity-client-$JV
U=b831381d-6324-4d53-ad4f-8cda48b30811; PW=juicity-pw-1; BAD=wrong-pw
PY=python:3-alpine; CURL=curlimages/curl:latest; WHOAMI=traefik/whoami:latest
mkdir -p "$D"
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1 | grep -q "$2" && return 0; sleep 0.5; done; return 1; }
trap cleanup EXIT
PASS=0; FAIL=0
ok(){ echo "  ✅ $1"; PASS=$((PASS+1)); }
ng(){ echo "  ❌ $1"; FAIL=$((FAIL+1)); }

# ---- 自举:证书(有效期 ≤398 天,chmod 644 供非 root 读)----
[ -s "$D/cert.pem" ] || docker run --rm -v "$D":/w -w /w alpine sh -c 'apk add -q openssl >/dev/null 2>&1; openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 90 -nodes -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com" -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1; chmod 644 cert.pem key.pem'

# ---- 自举:官方 juicity server/client(源码编,按 tag 钉版本,缓存)----
if [ ! -x "$JS" ] || [ ! -x "$JC" ]; then
  echo "  编译官方 juicity $JV ..."
  docker run --rm -v "$D":/out golang:1.24-alpine sh -c "
    apk add -q git >/dev/null 2>&1 &&
    git clone -q --depth 1 --branch $JV https://github.com/juicity/juicity /src && cd /src &&
    CGO_ENABLED=0 go build -trimpath -o /out/juicity-server-$JV ./cmd/server &&
    CGO_ENABLED=0 go build -trimpath -o /out/juicity-client-$JV ./cmd/client" || { echo "  ❌ 官方 juicity 编译失败"; exit 1; }
fi

# ---- python 助手:UDP 直发 / socks5 UDP ----
cat > "$D/_jc_udp.py" <<'PY'
import socket, sys
host, port, msg = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
for _ in range(3):
    s.sendto(msg, (socket.gethostbyname(host), port))
    try:
        d, _ = s.recvfrom(4096); print('GOT' if d == msg else 'MISMATCH'); sys.exit(0)
    except socket.timeout:
        pass
print('TIMEOUT')
PY
cat > "$D/_jc_s5udp.py" <<'PY'
import socket, struct, sys
proxy, thost, tport, msg = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4].encode()
tcp = socket.create_connection((proxy, 1080), timeout=8)
tcp.sendall(b'\x05\x01\x00')
if tcp.recv(2) != b'\x05\x00': print('GREET_FAIL'); sys.exit()
tcp.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
r = tcp.recv(10)
if len(r) < 10 or r[1] != 0: print('ASSOC_FAIL'); sys.exit()
bip = socket.inet_ntoa(r[4:8]); bport = struct.unpack('>H', r[8:10])[0]
if bip in ('0.0.0.0', '127.0.0.1'): bip = socket.gethostbyname(proxy)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
h = thost.encode()
pkt = b'\x00\x00\x00\x03' + bytes([len(h)]) + h + struct.pack('>H', tport) + msg
for _ in range(3):
    u.sendto(pkt, (bip, bport))
    try:
        d, _ = u.recvfrom(4096)
        off = 10 if d[3] == 1 else (22 if d[3] == 4 else 4 + 1 + d[4] + 2)
        print('GOT' if d[off:] == msg else 'MISMATCH'); sys.exit()
    except socket.timeout:
        pass
print('TIMEOUT')
PY
cat > "$D/_jc_echo.py" <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('0.0.0.0', 9999))
while True:
    d, a = s.recvfrom(4096); s.sendto(d, a)
PY

cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}tgt --network-alias tgt --network $NET $WHOAMI >/dev/null 2>&1
docker run -d --name ${PFX}uecho --network-alias uecho --network $NET -v "$D/_jc_echo.py":/e.py:ro $PY python3 /e.py >/dev/null 2>&1

curl_via(){ # $1=socks 代理主机 → 打印 whoami 输出(含 Hostname 即通)
  local o i; for i in 1 2 3 4 5; do
    o=$(docker run --rm --network $NET $CURL -s --max-time 8 -x "socks5h://$1:1080" http://tgt/ 2>&1)
    echo "$o" | grep -q Hostname && { echo "$o"; return; }; sleep 1; done; echo "$o"; }
udp_direct(){ docker run --rm --network $NET -v "$D/_jc_udp.py":/u.py:ro $PY python3 /u.py "$1" "$2" "$3" 2>&1; }
udp_socks(){ docker run --rm --network $NET -v "$D/_jc_s5udp.py":/u.py:ro $PY python3 /u.py "$1" uecho 9999 "$2" 2>&1; }

# ---- 起 NTR juicity 服务端(alias ntrsrv:23182)----
cat > "$D/_jc_ntrsrv.yaml" <<Y
inbounds:
  - name: j-in
    type: juicity
    listen: 0.0.0.0:23182
    tls:
      cert-file: /cert.pem
      key-file: /key.pem
    users:
      - uuid: $U
        password: $PW
outbounds:
  - name: direct
    type: direct
Y
docker run -d --name ${PFX}ntrsrv --network-alias ntrsrv --network $NET -v "$NTR":/ntr:ro -v "$D/_jc_ntrsrv.yaml":/c.yaml:ro \
  -v "$D/cert.pem":/cert.pem:ro -v "$D/key.pem":/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
wait_log ${PFX}ntrsrv "监听于" 15 || { echo "  NTR 服务端未就绪:"; docker logs ${PFX}ntrsrv 2>&1 | tail -5; }

# ---- 起官方 juicity-server(alias jsrv:23183)----
cat > "$D/_jc_jsrv.json" <<J
{"listen":"0.0.0.0:23183","users":{"$U":"$PW"},"certificate":"/cert.pem","private_key":"/key.pem","congestion_control":"bbr","log_level":"info"}
J
docker run -d --name ${PFX}jsrv --network-alias jsrv --network $NET -v "$JS":/jsrv:ro -v "$D/_jc_jsrv.json":/c.json:ro \
  -v "$D/cert.pem":/cert.pem:ro -v "$D/key.pem":/key.pem:ro alpine /jsrv run -c /c.json >/dev/null 2>&1
sleep 2

# 官方 client:$1=容器名后缀 $2=密码(socks5 :1080 + forward 0.0.0.0:5353/udp → uecho:9999)
jclient(){
  cat > "$D/_jc_cli_$1.json" <<J
{"listen":"0.0.0.0:1080","server":"ntrsrv:23182","uuid":"$U","password":"$2","sni":"example.com","allow_insecure":true,"congestion_control":"bbr","log_level":"info","forward":{"0.0.0.0:5353/udp":"uecho:9999"}}
J
  docker run -d --name ${PFX}$1 --network-alias $1 --network $NET -v "$JC":/jcli:ro -v "$D/_jc_cli_$1.json":/c.json:ro \
    alpine /jcli run -c /c.json >/dev/null 2>&1
  sleep 2
}
# NTR client:$1=容器名后缀 $2=密码(socks5 :1080 → juicity 出站 → jsrv)
ntrclient(){
  cat > "$D/_jc_ntrcli_$1.yaml" <<Y
inbounds:
  - name: s5
    type: socks
    listen: 0.0.0.0:1080
    outbound: j
outbounds:
  - name: j
    type: juicity
    server: jsrv:23183
    uuid: $U
    secret: $2
    insecure: true
Y
  docker run -d --name ${PFX}$1 --network-alias $1 --network $NET -v "$NTR":/ntr:ro -v "$D/_jc_ntrcli_$1.yaml":/c.yaml:ro \
    alpine /ntr -config /c.yaml >/dev/null 2>&1
  wait_log ${PFX}$1 "监听于" 15 || { echo "  NTR 客户端未就绪:"; docker logs ${PFX}$1 2>&1 | tail -5; }
}

echo "===== A 官方 juicity-client → NTR juicity 入站 ====="
jclient jcli "$PW"
O=$(curl_via jcli); echo "$O" | grep -q Hostname && ok "A1 TCP 通(whoami 返回 Hostname)" || { ng "A1 TCP 不通:$(echo "$O" | head -2)"; docker logs ${PFX}jcli 2>&1 | tail -3; docker logs ${PFX}ntrsrv 2>&1 | tail -3; }
R=$(udp_direct jcli 5353 ping-a2); [ "$R" = GOT ] && ok "A2 UDP 通(client forward → NTR 服务端 udpNAT → uecho)" || ng "A2 UDP:$R"

echo "===== B NTR juicity 出站 → 官方 juicity-server ====="
ntrclient ntrcli "$PW"
O=$(curl_via ntrcli); echo "$O" | grep -q Hostname && ok "B1 TCP 通(whoami 返回 Hostname)" || { ng "B1 TCP 不通:$(echo "$O" | head -2)"; docker logs ${PFX}ntrcli 2>&1 | tail -3; docker logs ${PFX}jsrv 2>&1 | tail -3; }
R=$(udp_socks ntrcli ping-b2); [ "$R" = GOT ] && ok "B2 UDP 通(socks UDP → juicity 出站 → 官方服务端 → uecho)" || ng "B2 UDP:$R"

echo "===== C 负向对照:错密码必须不通 ====="
jclient jbad "$BAD"
O=$(docker run --rm --network $NET $CURL -s --max-time 6 -x "socks5h://jbad:1080" http://tgt/ 2>&1)
echo "$O" | grep -q Hostname && ng "C1 官方 client 错密码竟通了(NTR 服务端未拒)" || ok "C1 官方 client 错密码被 NTR 服务端拒"
ntrclient nbad "$BAD"
O=$(docker run --rm --network $NET $CURL -s --max-time 6 -x "socks5h://nbad:1080" http://tgt/ 2>&1)
echo "$O" | grep -q Hostname && ng "C2 NTR 错密码竟通了(官方服务端未拒?token 算法可疑)" || ok "C2 NTR 错密码被官方服务端拒"

echo "════════ ix-juicity 结论:PASS=$PASS FAIL=$FAIL ════════"
[ "$FAIL" -eq 0 ] && echo "✅ juicity 与官方实现双向互通全绿" || echo "❌ 有失败"
