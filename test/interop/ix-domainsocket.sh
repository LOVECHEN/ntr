#!/bin/bash
# DomainSocket(unix 域套接字基础传输)互通:NTR <-> v2ray-core(v2fly;sing-box 无、xray 已移除)。
# 线上是裸字节流(unix socket 替代 TCP),其上照常叠协议。两容器经 docker 命名卷共享套接字文件;
# 抽象命名空间按网络命名空间隔离,故 abstract 用例让客户端加入服务端的网络命名空间(--network container:)。
#   A  v2ray vless 客户端 → NTR vless 服务端(文件套接字)
#   B  NTR vless 客户端 → v2ray vless 服务端(文件套接字)
#   C  NTR ↔ NTR:trojan + tls 叠在 domainsocket 上(栈可叠)
#   D1 v2ray → NTR:abstract(Linux 抽象命名空间)
#   D2 NTR ↔ NTR:abstract + padding(抽象名补零到 sun_path 全长 108 字节),并断言内核里的名确为全长。
#      注:v2ray 5.41 自身的 padding 拨号必报 EINVAL(它用前导 \x00 + 补零到 108,Go syscall 对「首字节非 '@' 且长度
#      等于 sun_path」返回 EINVAL),无法拿它对拍 padding,故 D2 用 NTR 自环 + /proc/net/unix 断言。
#   E  反向对照:NTR 客户端指向不存在的套接字 → 必须不通
# 判据:curl 经客户端 socks5h 打 whoami 靶机,拿到 Hostname = 通。专属 network=ixds 容器前缀=ixds- 卷=ixds-sock
set -u
NET=ixds; PFX=ixds-; VOL=ixds-sock; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}
UUID=33333333-3333-3333-3333-333333333333; PW=dspass; V2=v2fly/v2fly-core:latest
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker volume rm $VOL >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
# 证书自举(C 用例 tls;脚本自包含)
for f in cert.pem key.pem ca.pem; do [ -d "$D/$f" ] && rmdir "$D/$f"; done
[ -f "$D/cert.pem" ] && [ -f "$D/key.pem" ] || docker run --rm -v $D:/w -w /w alpine sh -c 'apk add openssl>/dev/null 2>&1; openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 90 -nodes -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com" -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1'
[ -f "$D/ca.pem" ] || cp $D/cert.pem $D/ca.pem
chmod 644 $D/cert.pem $D/key.pem $D/ca.pem 2>/dev/null
cleanup; docker network create $NET >/dev/null 2>&1; docker volume create $VOL >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null 2>&1
# $1=名 $2=配置 $3=网络(缺省 $NET)
ntr(){ docker run -d --name $1 --network ${3:-$NET} -v $VOL:/sock -v $NTR:/ntr:ro -v $D/$2:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
v2(){  docker run -d --name $1 --network ${3:-$NET} -v $VOL:/sock -v $D/$2:/c.json:ro $V2 run -c /c.json >/dev/null 2>&1; }
pull(){ local i out; for i in 1 2 3 4 5; do out=$(docker run --rm --network ${2:-$NET} curlimages/curl:latest -s --max-time 8 -x socks5h://$1:1080 http://${PFX}target/ 2>&1); echo "$out" | grep -q Hostname && { echo "$out" | grep Hostname; return 0; }; sleep 2; done; echo "$out" | head -c 100; return 1; }
chk(){ local r; r=$(pull "$1" "${3:-}") && echo "  ✅ $2  ($r)" || echo "  ❌ $2  ($r)"; }

v2_vless_cli(){ # $1=文件 $2=dsSettings JSON
  printf '{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":10000,"users":[{"id":"%s","encryption":"none"}]}]},"streamSettings":{"network":"domainsocket","dsSettings":%s}}]}\n' "$UUID" "$2" > $D/$1; }
v2_vless_srv(){ # $1=文件 $2=dsSettings JSON
  printf '{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":10000,"protocol":"vless","settings":{"clients":[{"id":"%s"}],"decryption":"none"},"streamSettings":{"network":"domainsocket","dsSettings":%s}}],"outbounds":[{"protocol":"freedom"}]}\n' "$UUID" "$2" > $D/$1; }
ntr_vless_srv(){ # $1=文件 $2=domainsocket 块(缩进 6 空格的行)
  printf 'inbounds:\n  - name: srv-in\n    type: vless\n    listen: 0.0.0.0:10000\n    domainsocket:\n%s    users:\n      - uuid: "%s"\noutbounds:\n  - name: direct\n    type: direct\n' "$2" "$UUID" > $D/$1; }
ntr_vless_cli(){ # $1=文件 $2=domainsocket 块
  printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: vless\n    server: "127.0.0.1:10000"\n    secret: "%s"\n    domainsocket:\n%s' "$UUID" "$2" > $D/$1; }

# A:v2ray 客户端 → NTR 服务端
ntr_vless_srv _ds_a_s.yaml $'      path: /sock/a.sock\n'; ntr ${PFX}a-s _ds_a_s.yaml; sleep 2
v2_vless_cli _ds_a_c.json '{"path":"/sock/a.sock"}'; v2 ${PFX}a-c _ds_a_c.json
# B:NTR 客户端 → v2ray 服务端
v2_vless_srv _ds_b_s.json '{"path":"/sock/b.sock"}'; v2 ${PFX}b-s _ds_b_s.json; sleep 2
ntr_vless_cli _ds_b_c.yaml $'      path: /sock/b.sock\n'; ntr ${PFX}b-c _ds_b_c.yaml
# C:NTR ↔ NTR,trojan + tls 叠在 domainsocket 上
printf 'inbounds:\n  - name: srv-in\n    type: trojan\n    listen: 0.0.0.0:10000\n    domainsocket:\n      path: /sock/c.sock\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\n    users:\n      - password: "%s"\noutbounds:\n  - name: direct\n    type: direct\n' "$PW" > $D/_ds_c_s.yaml
printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: trojan\n    server: "127.0.0.1:10000"\n    secret: "%s"\n    domainsocket:\n      path: /sock/c.sock\n    tls:\n      sni: example.com\n      insecure: true\n' "$PW" > $D/_ds_c_c.yaml
ntr ${PFX}c-s _ds_c_s.yaml; sleep 2; ntr ${PFX}c-c _ds_c_c.yaml
# D1:v2ray 客户端 → NTR 服务端,abstract(客户端加入服务端网络命名空间)
ntr_vless_srv _ds_d_s.yaml $'      path: ntr-ds-abstract\n      abstract: true\n'; ntr ${PFX}d-s _ds_d_s.yaml; sleep 2
v2_vless_cli _ds_d_c.json '{"path":"ntr-ds-abstract","abstract":true}'; v2 ${PFX}d-c _ds_d_c.json container:${PFX}d-s
# D2:NTR ↔ NTR,abstract + padding(同网络命名空间)
ntr_vless_srv _ds_p_s.yaml $'      path: ntr-ds-pad\n      abstract: true\n      padding: true\n'; ntr ${PFX}p-s _ds_p_s.yaml; sleep 2
ntr_vless_cli _ds_p_c.yaml $'      path: ntr-ds-pad\n      abstract: true\n      padding: true\n'; ntr ${PFX}p-c _ds_p_c.yaml container:${PFX}p-s
# E:反向对照 —— 指向不存在的套接字
ntr_vless_cli _ds_e_c.yaml $'      path: /sock/nonexistent.sock\n'; ntr ${PFX}e-c _ds_e_c.yaml
sleep 4

echo "==== DomainSocket ===="
chk ${PFX}a-c "A v2ray vless 客户端 → NTR 服务端(文件套接字)"
chk ${PFX}b-c "B NTR vless 客户端 → v2ray 服务端(文件套接字)"
chk ${PFX}c-c "C NTR ↔ NTR(trojan + tls 叠在 domainsocket 上)"
chk 127.0.0.1 "D1 v2ray 客户端 → NTR 服务端(abstract)" container:${PFX}d-s
chk 127.0.0.1 "D2 NTR ↔ NTR(abstract + padding)" container:${PFX}p-s
L=$(docker exec ${PFX}p-s sh -c 'cat /proc/net/unix' | awk '$NF ~ /^@ntr-ds-pad/ {print length($NF)}' | head -1)
[ "$L" = 108 ] && echo "  ✅ D2 内核套接字名为补零全长(108 字节)" || echo "  ❌ D2 内核套接字名长度 ${L:-无}(期望 108)"
R=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 6 -x socks5h://${PFX}e-c:1080 http://${PFX}target/ 2>&1)
echo "$R" | grep -q Hostname && echo "  ❌ E 指向不存在的套接字仍通(流量没走 domainsocket,前述结果不可信)" || echo "  ✅ E 反向对照:不存在的套接字不通"

cleanup; echo DONE
