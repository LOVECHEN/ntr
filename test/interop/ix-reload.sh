#!/bin/bash
# 配置热重载验证(承设计 §4.8「服务/端口随时上下线」):SIGHUP 运行时增删入站,未变的口零断连。
#   初始:socks :1080 + :1081。启一个【慢速大下载】在 :1080(跨越重载)。
#   改配置:去掉 :1081、加 :1082(:1080 不变)→ 覆盖配置文件 → docker kill -s HUP。
#   期望::1080 仍通【且慢下载不中断完成】、:1081 被停(拒)、:1082 新起(通)。
set -u
NET=ix-rld; PFX=ixrld-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; CFG=$D/_reload.yaml
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
# 50MiB 靶机 + whoami
docker run -d --name ${PFX}big --network $NET python:3-alpine sh -c "python3 -c \"open('/f','wb').write(b'x'*52428800)\"; cd /; python3 -m http.server 80" >/dev/null 2>&1
docker run -d --name ${PFX}who --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

write_cfg(){ cat > $CFG <<Y
inbounds:
$1
outbounds:
  - name: direct
    type: direct
Y
}
# v1:1080 + 1081
write_cfg '  - name: s5-1080
    type: socks
    listen: 0.0.0.0:1080
    outbound: direct
  - name: s5-1081
    type: socks
    listen: 0.0.0.0:1081
    outbound: direct'
docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $CFG:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 2

port_ok(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 6 -x socks5h://${PFX}s:$1 http://${PFX}who/ 2>/dev/null | grep -c Hostname; }
echo "=== 初始:两口都通 ==="
echo "  :1080 → $([ "$(port_ok 1080)" = 1 ] && echo PASS || echo FAIL)   :1081 → $([ "$(port_ok 1081)" = 1 ] && echo PASS || echo FAIL)"

echo "=== 起慢速大下载(50MiB@2MiB/s,~25s)在 :1080,跨越重载 ==="
docker run -d --name ${PFX}dl --network $NET curlimages/curl:latest \
  -s --max-time 60 --limit-rate 2M -x socks5h://${PFX}s:1080 http://${PFX}big/f -o /dev/null -w '%{size_download}' >/dev/null 2>&1
sleep 3  # 确保下载进行中

echo "=== 改配置(去 :1081、加 :1082)+ SIGHUP 热重载 ==="
write_cfg '  - name: s5-1080
    type: socks
    listen: 0.0.0.0:1080
    outbound: direct
  - name: s5-1082
    type: socks
    listen: 0.0.0.0:1082
    outbound: direct'
docker kill -s HUP ${PFX}s >/dev/null 2>&1
sleep 2
docker logs ${PFX}s 2>&1 | grep -iE '热重载完成' | tail -1 | sed 's/^/  /'

echo "=== 重载后 ==="
a=$([ "$(port_ok 1080)" = 1 ] && echo PASS || echo FAIL)
b=$([ "$(port_ok 1081)" = 0 ] && echo PASS || echo FAIL)   # 应被停
c=$([ "$(port_ok 1082)" = 1 ] && echo PASS || echo FAIL)   # 新起
echo "  :1080 仍通 → $a    :1081 已停(拒)→ $b    :1082 新起 → $c"

echo "=== 慢下载(跨重载)是否完成不中断 ==="
docker wait ${PFX}dl >/dev/null 2>&1
sz=$(docker logs ${PFX}dl 2>&1 | tail -1)
d=$([ "$sz" = "52428800" ] && echo PASS || echo FAIL)
echo "  下载字节=$sz(期望 52428800)→ $d   [未变的口零断连]"

[ "$a" = PASS -a "$b" = PASS -a "$c" = PASS -a "$d" = PASS ] && echo "=== 服务/端口随时上下线 + 零断连 验证通过 ===" || docker logs ${PFX}s 2>&1|tail -6|sed 's/^/  SRV:/'
cleanup; echo DONE