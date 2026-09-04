#!/bin/bash
# 组6:Hysteria1 / Hysteria2 / TUIC v5 —— NTR ⇄ sing-box / mihomo 双向互通回归。
# 铁律:禁止修改协议线格式。失败先查测试配置;线格式不符则改 NTR 匹配真实现。
# 专属隔离:network=ix-q  容器前缀=ixq-
set -u
D=/tmp/ntr-interop; cd $D
NTR=${NTR:-$D/ntr}                 # 被测 NTR 二进制(默认共享;验证时可传 NTR=.../ntr-h1fix)
NET=ix-q
SB=ghcr.io/sagernet/sing-box:latest
MH=metacubex/mihomo:latest
CURL=curlimages/curl:latest
UUID=00000000-0000-0000-0000-0000000000ab

pfx=ixq-
rmall(){ docker ps -aq --filter "name=$pfx" | xargs -r docker rm -f >/dev/null 2>&1; }
hit(){ echo "$1" | grep -q Hostname && echo "  ✅ $2" || echo "  ❌ $2 :: $(echo "$1"|tr -d '\n'|head -c 120)"; }
nsrv(){ docker run -d --name $pfx$1 --network $NET -v $NTR:/ntr:ro -v $D/$2:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
ncli(){ docker run -d --name $pfx$1 --network $NET -v $NTR:/ntr:ro -v $D/$2:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1; }
sb(){   docker run -d --name $pfx$1 --network $NET -v $D/$2:/c.json:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro $SB -c /c.json run >/dev/null 2>&1; }
sbc(){  docker run -d --name $pfx$1 --network $NET -v $D/$2:/c.json:ro $SB -c /c.json run >/dev/null 2>&1; }
mh(){   docker run -d --name $pfx$1 --network $NET -v $D/$2:/root/.config/mihomo/config.yaml:ro -v $D/cert.pem:/root/.config/mihomo/cert.pem:ro -v $D/key.pem:/root/.config/mihomo/key.pem:ro $MH >/dev/null 2>&1; }
mhc(){  docker run -d --name $pfx$1 --network $NET -v $D/$2:/root/.config/mihomo/config.yaml:ro $MH >/dev/null 2>&1; }
# 探测重试至就绪:CI 冷 runner 上对端 QUIC 服务端起得慢,固定 sleep 常不够;成功即早退。
probe(){ local i out; for i in 1 2 3 4 5 6; do out=$(docker run --rm --network $NET $CURL -s --max-time 12 -x socks5h://$pfx$1:1080 http://${pfx}target/ 2>&1); echo "$out" | grep -q Hostname && { echo "$out"; return; }; sleep 1.5; done; echo "$out"; }

docker network create $NET >/dev/null 2>&1
rmall
docker run -d --name ${pfx}target --network $NET traefik/whoami >/dev/null 2>&1

# ---- 生成配置 ----
# hy2
printf 'inbounds:\n  - name: hy2-in\n    type: hysteria2\n    listen: 0.0.0.0:8443\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\n    users:\n      - password: "hy2pw"\noutbounds:\n  - name: direct\n    type: direct\n' > q-hy2-ntrsrv.yaml
printf '{"inbounds":[{"type":"hysteria2","listen":"::","listen_port":8443,"users":[{"password":"hy2pw"}],"tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem"}}],"outbounds":[{"type":"direct"}]}\n' > q-hy2-sbsrv.json
printf 'log-level: warning\nlisteners:\n  - {name: hy2in, type: hysteria2, listen: 0.0.0.0, port: 8443, users: {u: "hy2pw"}, certificate: /root/.config/mihomo/cert.pem, private-key: /root/.config/mihomo/key.pem}\n' > q-hy2-msrv.yaml
mk_hy2_ncli(){ printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: hysteria2\n    server: "%s:8443"\n    secret: "hy2pw"\n    sni: example.com\n    insecure: true\n' "$1" > "$2"; }
mk_hy2_ncli ${pfx}hy2-sbsrv q-hy2-ncli-sb.yaml
mk_hy2_ncli ${pfx}hy2-msrv  q-hy2-ncli-mh.yaml
printf '{"log":{"level":"error"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"hysteria2","server":"%shy2-ntrsrv","server_port":8443,"password":"hy2pw","tls":{"enabled":true,"server_name":"example.com","insecure":true}}]}\n' "$pfx" > q-hy2-sbcli.json
printf 'mixed-port: 1080\nallow-lan: true\nlog-level: warning\nproxies:\n  - {name: p, type: hysteria2, server: %shy2-ntrsrv, port: 8443, password: "hy2pw", sni: example.com, skip-cert-verify: true}\nrules: ["MATCH,p"]\n' "$pfx" > q-hy2-mcli.yaml

# tuic
printf 'inbounds:\n  - name: tuic-in\n    type: tuic\n    listen: 0.0.0.0:8443\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\n    users:\n      - uuid: "%s"\n        password: "tuicpw"\noutbounds:\n  - name: direct\n    type: direct\n' "$UUID" > q-tuic-ntrsrv.yaml
printf '{"inbounds":[{"type":"tuic","listen":"::","listen_port":8443,"users":[{"uuid":"%s","password":"tuicpw"}],"congestion_control":"bbr","tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem","alpn":["h3"]}}],"outbounds":[{"type":"direct"}]}\n' "$UUID" > q-tuic-sbsrv.json
printf 'log-level: warning\nlisteners:\n  - {name: tuicin, type: tuic, listen: 0.0.0.0, port: 8443, users: {"%s": "tuicpw"}, congestion-controller: bbr, alpn: [h3], certificate: /root/.config/mihomo/cert.pem, private-key: /root/.config/mihomo/key.pem}\n' "$UUID" > q-tuic-msrv.yaml
mk_tuic_ncli(){ printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: tuic\n    server: "%s:8443"\n    uuid: "%s"\n    secret: "tuicpw"\n    sni: example.com\n    insecure: true\n' "$1" "$UUID" > "$2"; }
mk_tuic_ncli ${pfx}tuic-sbsrv q-tuic-ncli-sb.yaml
mk_tuic_ncli ${pfx}tuic-msrv  q-tuic-ncli-mh.yaml
printf '{"log":{"level":"error"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"tuic","server":"%stuic-ntrsrv","server_port":8443,"uuid":"%s","password":"tuicpw","congestion_control":"bbr","tls":{"enabled":true,"server_name":"example.com","insecure":true,"alpn":["h3"]}}]}\n' "$pfx" "$UUID" > q-tuic-sbcli.json
printf 'mixed-port: 1080\nallow-lan: true\nlog-level: warning\nproxies:\n  - {name: p, type: tuic, server: %stuic-ntrsrv, port: 8443, uuid: "%s", password: "tuicpw", congestion-controller: bbr, alpn: [h3], sni: example.com, skip-cert-verify: true}\nrules: ["MATCH,p"]\n' "$pfx" "$UUID" > q-tuic-mcli.yaml

# hy1
printf 'inbounds:\n  - name: hy1-in\n    type: hysteria1\n    listen: 0.0.0.0:8443\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\n    users:\n      - password: "h1pw"\noutbounds:\n  - name: direct\n    type: direct\n' > q-h1-ntrsrv.yaml
printf '{"inbounds":[{"type":"hysteria","listen":"::","listen_port":8443,"up_mbps":100,"down_mbps":100,"users":[{"auth_str":"h1pw"}],"tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem","alpn":["hysteria"]}}],"outbounds":[{"type":"direct"}]}\n' > q-h1-sbsrv.json
printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: hysteria1\n    server: "%sh1-sbsrv:8443"\n    secret: "h1pw"\n    sni: example.com\n    insecure: true\n' "$pfx" > q-h1-ncli-sb.yaml
printf '{"log":{"level":"error"},"inbounds":[{"type":"mixed","listen":"::","listen_port":1080}],"outbounds":[{"type":"hysteria","server":"%sh1-ntrsrv","server_port":8443,"up_mbps":100,"down_mbps":100,"auth_str":"h1pw","tls":{"enabled":true,"server_name":"example.com","insecure":true,"alpn":["hysteria"]}}]}\n' "$pfx" > q-h1-sbcli.json
printf 'mixed-port: 1080\nallow-lan: true\nlog-level: warning\nproxies:\n  - {name: p, type: hysteria, server: %sh1-ntrsrv, port: 8443, auth-str: "h1pw", up: "100 Mbps", down: "100 Mbps", sni: example.com, skip-cert-verify: true, alpn: [hysteria]}\nrules: ["MATCH,p"]\n' "$pfx" > q-h1-mcli.yaml

# ---- 起服务端 ----
nsrv hy2-ntrsrv q-hy2-ntrsrv.yaml; sb hy2-sbsrv q-hy2-sbsrv.json; mh hy2-msrv q-hy2-msrv.yaml
nsrv tuic-ntrsrv q-tuic-ntrsrv.yaml; sb tuic-sbsrv q-tuic-sbsrv.json; mh tuic-msrv q-tuic-msrv.yaml
nsrv h1-ntrsrv q-h1-ntrsrv.yaml; sb h1-sbsrv q-h1-sbsrv.json
sleep 4
# ---- 起客户端 ----
ncli hy2-ncli-sb q-hy2-ncli-sb.yaml; ncli hy2-ncli-mh q-hy2-ncli-mh.yaml; sbc hy2-sbcli q-hy2-sbcli.json; mhc hy2-mcli q-hy2-mcli.yaml
ncli tuic-ncli-sb q-tuic-ncli-sb.yaml; ncli tuic-ncli-mh q-tuic-ncli-mh.yaml; sbc tuic-sbcli q-tuic-sbcli.json; mhc tuic-mcli q-tuic-mcli.yaml
ncli h1-ncli-sb q-h1-ncli-sb.yaml; sbc h1-sbcli q-h1-sbcli.json; mhc h1-mcli q-h1-mcli.yaml
sleep 6

echo "==== Hysteria2 ===="
hit "$(probe hy2-ncli-sb)" "hy2  NTR→sing-box"
hit "$(probe hy2-ncli-mh)" "hy2  NTR→mihomo"
hit "$(probe hy2-sbcli)"   "hy2  sing-box→NTR"
hit "$(probe hy2-mcli)"    "hy2  mihomo→NTR"
echo "==== TUIC v5 ===="
hit "$(probe tuic-ncli-sb)" "tuic NTR→sing-box"
hit "$(probe tuic-ncli-mh)" "tuic NTR→mihomo"
hit "$(probe tuic-sbcli)"   "tuic sing-box→NTR"
hit "$(probe tuic-mcli)"    "tuic mihomo→NTR"
echo "==== Hysteria1 ===="
hit "$(probe h1-ncli-sb)" "hy1  NTR→sing-box"
echo "  ⛔ hy1  NTR→mihomo  (mihomo 无 hysteria v1 入站 listener:unsupport proxy type: hysteria)"
hit "$(probe h1-sbcli)"   "hy1  sing-box→NTR"
hit "$(probe h1-mcli)"    "hy1  mihomo→NTR"

rmall; docker network rm $NET >/dev/null 2>&1
