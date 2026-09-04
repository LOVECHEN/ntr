#!/bin/bash
# block 内置出站验证(mihomo Reject / Xray Blackhole 对位):socks 入站 → block 出站。
#   reject 模式:curl 经 socks 立即失败(出站拒绝→关连接)。
#   drop   模式:curl 经 socks 挂起到超时(黑洞吞数据不回)。
set -u
NET=ix-block; PFX=ixblk-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1

run_case(){ # $1=mode $2=期望(fail|timeout)
  local mode=$1 expect=$2
  cat > $D/_blk.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:1080
    outbound: b
outbounds:
  - name: b
    type: block
    mode: $mode
Y
  docker rm -f ${PFX}ntr >/dev/null 2>&1
  docker run -d --name ${PFX}ntr --network $NET -v $NTR:/ntr:ro -v $D/_blk.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 1.5
  # 经 socks 拨 example.com:80;block 应拒绝/黑洞
  out=$(docker run --rm --network $NET alpine sh -c "apk add -q curl >/dev/null 2>&1; curl -sS --max-time 4 -x socks5h://${PFX}ntr:1080 http://example.com/ -o /dev/null -w 'HTTP=%{http_code}' 2>&1; echo \" rc=\$?\"")
  echo "  mode=$mode → $out"
  local ok=FAIL
  case $expect in
    fail)    echo "$out" | grep -qE 'rc=(7|56|97|1|52|35)|refused|reset|closed|Empty reply' && ok=PASS ;;
    timeout) echo "$out" | grep -qE 'rc=28|timed out|Operation timed out' && ok=PASS ;;
  esac
  echo "  [block $mode 期望 $expect]  $ok"
}

echo "=== block reject(立拒)==="
run_case reject fail
echo "=== block drop(黑洞挂起)==="
run_case drop timeout
cleanup; echo DONE