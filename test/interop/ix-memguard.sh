#!/bin/bash
# mem-guard(防 OOM 三道防线)端到端:真进程、真 RSS、真连接。
#   ① 基线:mem-guard limit 1gb 起 NTR,经 /memguard 读空载 RSS = B
#   ②a soft:soft = B+4MB、hard 设 99%(够不着),经 socks 每 10ms 开一条空闲连接(每条约 30KB RSS)慢速爬升 ——
#       断言 soft 拒新(soft_rejected>0、客户端在 600 条前被拒)、已建连接不动(无一被断)、hard_evicted=0
#   ②b hard:soft = B+5MB、hard = B+5.5MB,600 条快速突发(一个采样周期内越过 hard)—— 断言 hard 踢最久空闲
#       (hard_evicted>0,且客户端确实观察到已建连接被断开)
#   两道防线分开验:soft 一旦拒新 RSS 就不再涨、到不了 hard,同一负载无法兼测。
#   ③ 反向对照:同样负载、limit 1gb → 600 条全开、soft_rejected=hard_evicted=0(证明拒/踢源于 mem-guard)
# 专属隔离:network=ixmg 容器前缀=ixmg-
set -u
NET=ixmg; PFX=ixmg-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}; N=600
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1

# 汇点:接受并持有所有连接(不读不写)
cat > $D/_mg_sink.py <<'EOF'
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",7000)); s.listen(4096)
held=[]
while True:
    c,_=s.accept(); held.append(c)
EOF
# 打开器:经 socks 逐条 CONNECT 到汇点并持有;被拒即停。准入在 socks 应答之后,被拒连接是「握手成功随即被关」,
# 故开完先静置 1s 统计 early(= 准入被拒),再持有 hold 秒统计 late(= 已建连接被服务端断开)。
cat > $D/_mg_open.py <<'EOF'
import socket,sys,time,struct
n=int(sys.argv[1]); host=sys.argv[2]; hold=float(sys.argv[3]); gap=float(sys.argv[4]); conns=[]; rej=-1
t=b'ixmg-sink'
for i in range(n):
    try:
        c=socket.create_connection((host,1080),timeout=5)
        c.sendall(b'\x05\x01\x00'); c.recv(2)
        c.sendall(b'\x05\x01\x00\x03'+bytes([len(t)])+t+struct.pack('>H',7000))
        r=c.recv(10)
        if len(r)<2 or r[1]!=0: rej=i; break
        c.setblocking(False)
        try:
            if c.recv(1)==b'': rej=i; break   # 准入在握手后:被拒的连接随即被关
        except BlockingIOError: pass
        conns.append(c)
        if gap: time.sleep(gap)
    except Exception:
        rej=i; break
def gone(c):
    try: return c.recv(1)==b''
    except BlockingIOError: return False
    except Exception: return True
time.sleep(1)
alive=[c for c in conns if not gone(c)]
print("opened",len(conns),"rejected_at",rej,"early",len(conns)-len(alive)); sys.stdout.flush()
time.sleep(hold)
print("late",sum(1 for c in alive if gone(c))); sys.stdout.flush()
EOF
docker run -d --name ${PFX}sink --network $NET -v $D/_mg_sink.py:/s.py:ro python:3-alpine python /s.py >/dev/null 2>&1
cfg(){ # $1=文件 $2=limit $3=soft $4=hard
  printf 'mem-guard:\n  limit: %s\n  soft: "%s"\n  hard: "%s"\nmetrics:\n  listen: 0.0.0.0:9091\n  access:\n    - 0.0.0.0/0\ninbounds:\n  - name: s5\n    type: socks\n    listen: 0.0.0.0:1080\noutbounds:\n  - name: direct\n    type: direct\n' "$2" "$3" "$4" > $D/$1; }
run(){ docker run -d --name $1 --network $NET -v $NTR:/ntr:ro -v $D/$2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
mg(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 5 http://$1:9091/memguard 2>/dev/null; }
field(){ echo "$1" | sed -n "s/.*\"$2\":\([0-9]*\).*/\1/p"; }
open(){ docker run --rm --network $NET -v $D/_mg_open.py:/o.py:ro python:3-alpine python /o.py $N $1 $2 ${3:-0} 2>&1; }

# ① 基线
cfg _mg_base.yaml 1gb 0.8 0.92; run ${PFX}base _mg_base.yaml; sleep 3
B=$(field "$(mg ${PFX}base)" current_bytes); docker rm -f ${PFX}base >/dev/null 2>&1
[ -n "$B" ] && [ "$B" -gt 0 ] || { echo "  ❌ 读不到基线 RSS"; cleanup; exit 0; }
L=256000000 # "256mb" 按十进制 MB 解析
pct(){ awk -v b=$B -v l=$L -v m=$1 'BEGIN{printf "%.6f",(b+m*1048576)/l}'; }
echo "  基线 RSS=$((B/1048576))MB  limit=256mb"

# ②a soft:慢速爬升,hard 够不着
cfg _mg_s.yaml 256mb $(pct 4) 0.99; run ${PFX}s _mg_s.yaml; sleep 3
OUT=$(open ${PFX}s 4 0.01)
S=$(mg ${PFX}s); SR=$(field "$S" soft_rejected); HE=$(field "$S" hard_evicted)
OPENED=$(echo "$OUT" | sed -n 's/^opened \([0-9]*\).*/\1/p'); EARLY=$(echo "$OUT" | sed -n 's/.* early \([0-9]*\)/\1/p'); LATE=$(echo "$OUT" | sed -n 's/^late \([0-9]*\)/\1/p')
ESTAB=$(( ${OPENED:-0} - ${EARLY:-0} ))
echo "  soft 受测:$(echo "$OUT"|tr '\n' ' ')· memguard=$S"
[ "${SR:-0}" -gt 0 ] && [ $ESTAB -lt $N ] && echo "  ✅ soft 拒新:soft_rejected=$SR,只建成 $ESTAB 条(其余握手后即被准入拒绝)" || echo "  ❌ soft 未拒新(soft_rejected=${SR:-?} 建成=$ESTAB)"
[ "${LATE:-1}" = 0 ] && [ "${HE:-1}" = 0 ] && echo "  ✅ soft 档已建连接不动:已建的 $ESTAB 条持有期内无一被断、hard_evicted=0" || echo "  ❌ soft 档动了已建连接(late=${LATE:-?} hard_evicted=${HE:-?})"
docker rm -f ${PFX}s >/dev/null 2>&1

# ②b hard:快速突发越过 hard
cfg _mg_h.yaml 256mb $(pct 5) $(pct 5.5); run ${PFX}h _mg_h.yaml; sleep 3
OUT=$(open ${PFX}h 8 0)
S=$(mg ${PFX}h); HE=$(field "$S" hard_evicted)
SR=$(field "$S" soft_rejected); EARLY=$(echo "$OUT" | sed -n 's/.* early \([0-9]*\)/\1/p'); LATE=$(echo "$OUT" | sed -n 's/^late \([0-9]*\)/\1/p')
CLOSED=$(( ${EARLY:-0} + ${LATE:-0} ))
echo "  hard 受测:$(echo "$OUT"|tr '\n' ' ')· memguard=$S"
[ "${HE:-0}" -gt 0 ] && [ $CLOSED -gt 0 ] && [ "${SR:-1}" = 0 ] && echo "  ✅ hard 踢空闲:hard_evicted=$HE,客户端观察到 $CLOSED 条已建连接被断(突发全数建成,无准入拒绝)" || echo "  ❌ hard 未踢空闲(hard_evicted=${HE:-?} closed=$CLOSED soft_rejected=${SR:-?})"
docker rm -f ${PFX}h >/dev/null 2>&1

# ③ 反向对照
cfg _mg_ctl.yaml 1gb 0.8 0.92; run ${PFX}ctl _mg_ctl.yaml; sleep 3
OUT=$(open ${PFX}ctl 3); S=$(mg ${PFX}ctl)
OPENED=$(echo "$OUT" | sed -n 's/^opened \([0-9]*\).*/\1/p')
[ "${OPENED:-0}" = $N ] && [ "$(field "$S" soft_rejected)" = 0 ] && [ "$(field "$S" hard_evicted)" = 0 ] \
  && echo "  ✅ 反向对照:limit 1gb 下 $N 条全开、无拒无踢" || echo "  ❌ 反向对照异常(opened=${OPENED:-?} memguard=$S)"

cleanup; echo DONE
