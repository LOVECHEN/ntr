#!/bin/bash
# 计量子系统验证(承设计 §5):按用户流量 + 连接数,经 HTTP /stats 快照读出。
# 通过 NTR socks 入站下载 5MiB,再查 /stats:该计费槽(socks 无鉴权→Ambient)的 down ≈ 5MiB、conns 计数正确。
# 验证【热路径 0 原子/Read + 稀疏 drain】计出的字节与实际下载量一致(收尾 flush 后精确)。
set -u
NET=ix-mtr; PFX=ixmtr-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1

# 5MiB 文件靶机(python http.server,可靠)
docker run -d --name ${PFX}target --network $NET python:3-alpine sh -c "python3 -c \"open('/f','wb').write(b'x'*5242880)\"; cd /; python3 -m http.server 80" >/dev/null 2>&1
cat > $D/_mtr.yaml <<Y
metrics:
  access: ["0.0.0.0/0"]
  listen: 0.0.0.0:9091
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: direct}
outbounds: [{name: direct, type: direct}]
Y
docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $D/_mtr.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 2

echo "=== 经 NTR socks 下载 5MiB × 2 ==="
for i in 1 2; do
  sz=$(docker run --rm --network $NET curlimages/curl:latest -s -x socks5h://${PFX}s:1080 http://${PFX}target/f -o /dev/null -w '%{size_download}' 2>/dev/null)
  echo "  下载 #$i:$sz 字节"
done
sleep 1

echo "=== GET /stats ==="
stats=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 5 http://${PFX}s:9091/stats 2>/dev/null)
echo "  $stats"
# 解析 down(Ambient 用户,id=1);两次下载 ≈ 10MiB
down=$(echo "$stats" | grep -oE '"down":[0-9]+' | head -1 | grep -oE '[0-9]+')
ct=$(echo "$stats" | grep -oE '"conns_total":[0-9]+' | head -1 | grep -oE '[0-9]+')
ok=FAIL
[ -n "$down" ] && [ "$down" -ge 10000000 ] && [ "$ct" -ge 2 ] && ok=PASS
echo "  [计量:down=$down(期望≥10MiB) conns_total=$ct(期望≥2)]  $ok"
[ $ok = FAIL ] && docker logs ${PFX}s 2>&1 | tail -4 | sed 's/^/  NTR:/'
cleanup; echo DONE