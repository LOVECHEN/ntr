#!/bin/bash
# full-cone NAT 验证:endpoint-independent 映射 —— 同一客户端 UDP 会话发往【多个不同目标】,
# NTR 对外用【同一个外部端口】收发(这正是 full-cone 区别于 restricted/symmetric 的关键:
# symmetric 每目标换一个外部端口)。
#
#   client(socks5 UDP ASSOCIATE,单 socket) ──► NTR full-cone direct ──► echoA / echoB(两个不同主机)
#   echoA/echoB 各回显【它看到的 NTR 源地址】"FROM ip:port"。
#   ① full-cone 开 :两目标看到的 NTR 源端口【相同】→ PASS(endpoint-independent)。
#   ② full-cone 关 :两目标看到的 NTR 源端口【不同】→ PASS(反证:确实是 full-cone 在复用单端口;
#      per-target 退化成每目标一条 connected socket,外部端口自然不同)。
set -u
NET=ixfc; PFX=ixfc-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
PY=python:3-alpine
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
wait_log(){ local i; for i in $(seq 1 $(( ${3:-20} * 2 ))); do docker logs "$1" 2>&1|grep -q "$2" && return 0; sleep 0.5; done; return 1; }
cleanup; docker network create $NET >/dev/null 2>&1

# UDP echo:回显【它看到的来源地址】"FROM ip:port"(据此判 NTR 对外用的端口)
cat > $D/_fc_echo.py <<'PY'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',9999))
while True:
    d,a=s.recvfrom(4096); s.sendto(('FROM %s:%d'%(a[0],a[1])).encode(),a)
PY
# socks5 UDP client:单 socket 连发两个目标,解析各自回显里的 NTR 源端口
cat > $D/_fc_client.py <<'PY'
import socket,struct,sys,re
proxy=('cli',1080); targets=[('echoa',9999),('echob',9999)]
tcp=socket.create_connection(proxy,timeout=8)
tcp.sendall(b'\x05\x01\x00')
if tcp.recv(2)!=b'\x05\x00': print('greet fail'); sys.exit(2)
tcp.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
r=tcp.recv(10)
if r[1]!=0: print('associate fail',r); sys.exit(3)
bnd_ip=socket.inet_ntoa(r[4:8]); bnd_port=struct.unpack('>H',r[8:10])[0]
if bnd_ip in ('0.0.0.0','127.0.0.1'): bnd_ip=proxy[0]
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.settimeout(8)
ports=[]
for host,port in targets:
    th=host.encode()
    pkt=b'\x00\x00\x00\x03'+bytes([len(th)])+th+struct.pack('>H',port)+b'PING'
    udp.sendto(pkt,(bnd_ip,bnd_port))
    data,_=udp.recvfrom(4096)
    atyp=data[3]
    off=10 if atyp==1 else (22 if atyp==4 else 4+1+data[4]+2)
    payload=data[off:].decode('utf-8','replace')
    m=re.search(r':(\d+)$',payload)
    if not m: print('bad payload',repr(payload)); sys.exit(4)
    ports.append(int(m.group(1)))
    print('  target %s 看到 NTR 源 %s'%(host,payload))
print('PORTS %d %d'%(ports[0],ports[1]))
# 退出码:0=两端口相同(full-cone),5=不同(per-target)。脚本据此+期望判 PASS/FAIL。
sys.exit(0 if ports[0]==ports[1] else 5)
PY

docker run -d --name ${PFX}echoa --network-alias echoa --network $NET -v $D/_fc_echo.py:/e.py:ro $PY python3 /e.py >/dev/null 2>&1
docker run -d --name ${PFX}echob --network-alias echob --network $NET -v $D/_fc_echo.py:/e.py:ro $PY python3 /e.py >/dev/null 2>&1
sleep 2

# NTR:socks5 入站(UDP ASSOCIATE)+ direct 出站(full-cone 可开关)
mkntr(){ cat > $D/_fc_$1.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: direct
outbounds:
  - name: direct
    type: direct
    full-cone: $2
routing:
  default: direct
Y
docker rm -f ${PFX}cli >/dev/null 2>&1
docker run -d --name ${PFX}cli --network-alias cli --network $NET -v $NTR:/ntr:ro -v $D/_fc_$1.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
wait_log ${PFX}cli "监听于" 15; }
run(){ docker run --rm --network $NET -v $D/_fc_client.py:/c.py:ro $PY python3 /c.py 2>&1; echo "RC=$?"; }

echo "=== full-cone 开:期望两目标看到【同一】NTR 源端口(endpoint-independent)==="
mkntr on true
O1=$(run); echo "$O1"|grep -v '^RC='
RC1=$(echo "$O1"|sed -n 's/^RC=//p')
echo "  [① full-cone 单端口]  $([ "$RC1" = 0 ] && echo PASS || echo "FAIL(rc=$RC1)")"

echo "=== full-cone 关(反证):期望两目标看到【不同】NTR 源端口(per-target)==="
mkntr off false
O2=$(run); echo "$O2"|grep -v '^RC='
RC2=$(echo "$O2"|sed -n 's/^RC=//p')
echo "  [② per-target 各自端口]  $([ "$RC2" = 5 ] && echo PASS || echo "FAIL(rc=$RC2)")"

cleanup; echo DONE
