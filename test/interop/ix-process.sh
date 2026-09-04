#!/bin/bash
# process 进程规则验证:NTR 按【发起连接的本机进程名】分流(process-name)。
#
# NTR 与 client 同容器(共享 pid+net ns)—— NTR 才能读 client 进程的 /proc 反查发起者。
#   规则:process-name [blocked-app] → block;default → direct。
#   ① 把 curl 复制成 /usr/local/bin/blocked-app(改 exe basename)→ 经 socks 连靶机 → NTR 反查发起进程=
#      blocked-app → 命中 process 规则 → block → 000。
#   ② 原名 curl 经 socks 连同一靶机 → 反查=curl → 不匹配 → default direct → 200。
#   两者目标/端口/网络全同,唯一变量是【发起进程名】—— 证分流确实靠进程反查(而非目标)。
set -u
NET=ixproc; PFX=ixproc-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
WHOAMI=traefik/whoami:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1

# HTTP 靶机(返 200)
docker run -d --name ${PFX}tgt --network-alias tgt --network $NET $WHOAMI >/dev/null 2>&1
sleep 1

# NTR:socks 入站 + process-name 规则
cat > $D/_proc.yaml <<'Y'
inbounds:
  - name: s5-in
    type: socks
    listen: 127.0.0.1:1080
    outbound: direct
outbounds:
  - name: direct
    type: direct
  - name: block
    type: block
routing:
  default: direct
  rules:
    - process-name:
        - blocked-app
      to: block
Y

# 主容器内编排脚本(NTR 后台 + 改名 curl + 两次探测)。socks5h:域名交 NTR 解析,分流后 direct 才连靶机。
cat > $D/_proc_run.sh <<'SH'
set -u
apk add -q curl >/dev/null 2>&1
/ntr -config /c.yaml >/ntr.log 2>&1 &
for i in $(seq 1 30); do grep -q "监听于" /ntr.log && break; sleep 0.5; done
cp /usr/bin/curl /usr/local/bin/blocked-app
probe(){ "$1" -s --max-time 8 -o /dev/null -w '%{http_code}' -x socks5h://127.0.0.1:1080 http://tgt/ 2>&1; }
R1=$(probe blocked-app)   # 命中 process → block
R2=$(probe curl)          # 不匹配 → direct
echo "RESULT R1=$R1 R2=$R2"
SH

OUT=$(docker run --rm --network $NET -v $NTR:/ntr:ro -v $D/_proc.yaml:/c.yaml:ro -v $D/_proc_run.sh:/run.sh:ro alpine sh /run.sh 2>&1)
echo "$OUT" | grep -v '^RESULT'
R1=$(echo "$OUT"|sed -n 's/.*R1=\([0-9]*\).*/\1/p')
R2=$(echo "$OUT"|sed -n 's/.*R2=\([0-9]*\)$/\1/p')
echo "  [① blocked-app → process 命中 → block]  $([ "$R1" = 000 ] && echo PASS || echo "FAIL(http=$R1)")"
echo "  [② curl → 不匹配 → direct → 200]        $([ "$R2" = 200 ] && echo PASS || echo "FAIL(http=$R2)")"
cleanup; echo DONE
