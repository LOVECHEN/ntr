#!/bin/bash
# NTR 新协议(trusttunnel / naive / ssh)对真实第三方内核的双向交叉验证。
# 铁律:禁止修改协议通信格式 —— 失败一律先查测试配置,线格式不符则改 NTR 匹配真实现。
#
# 前置:$D/ntr = linux/amd64 交叉编译的 NTR 二进制
# 证书:必须 CA + 叶子分离,叶子 ≤398 天(Chromium/cronet 的 ERR_CERT_VALIDITY_TOO_LONG)
set -u
D=/tmp/ntr-interop; cd $D

# ---- 证书:CA + 短期叶子(sing-box naive outbound 用内嵌 cronet,不支持 insecure)----
gen_certs() {
  openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca.pem -days 3650 -nodes \
    -subj "/CN=NTR Test CA" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
  openssl req -newkey rsa:2048 -keyout key.pem -out leaf.csr -nodes -subj "/CN=example.com" 2>/dev/null
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:example.com,DNS:localhost,IP:127.0.0.1\n' > leaf.ext
  openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out cert.pem -days 90 -sha256 -extfile leaf.ext 2>/dev/null
  [ -f ssh_hostkey ] || ssh-keygen -t ed25519 -f ssh_hostkey -N "" -q
}

hit(){ echo "$1" | grep -q Hostname && echo "✅ $2" || echo "❌ $2"; }

# ============ TrustTunnel ⇄ mihomo ============
tt() {
  NET=xv-tt; docker network create $NET >/dev/null 2>&1
  docker rm -f xvt-target xvt-mihomo xvt-ntr xvt-ntrsrv xvt-mhcli >/dev/null 2>&1
  docker run -d --name xvt-target --network $NET traefik/whoami >/dev/null
  # 注意:mihomo 有路径安全限制,证书必须放在 /root/.config/mihomo 下
  printf 'log-level: debug\nlisteners:\n  - name: tt-in\n    type: trusttunnel\n    port: 8443\n    listen: 0.0.0.0\n    users:\n      - username: u\n        password: ttpw\n    certificate: /root/.config/mihomo/cert.pem\n    private-key: /root/.config/mihomo/key.pem\n' > mh-tt-srv.yaml
  docker run -d --name xvt-mihomo --network $NET -v $D/mh-tt-srv.yaml:/root/.config/mihomo/config.yaml:ro \
    -v $D/cert.pem:/root/.config/mihomo/cert.pem:ro -v $D/key.pem:/root/.config/mihomo/key.pem:ro \
    metacubex/mihomo:latest >/dev/null 2>&1
  printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: trusttunnel\n    server: "xvt-mihomo:8443"\n    user: u\n    secret: "ttpw"\n    sni: example.com\n    insecure: true\n' > ntr-tt-cli.yaml
  docker run -d --name xvt-ntr --network $NET -v $D/ntr:/ntr:ro -v $D/ntr-tt-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  printf 'inbounds:\n  - name: srv-in\n    type: trusttunnel\n    listen: 0.0.0.0:8443\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\n    users:\n      - name: u\n        password: "ttpw"\noutbounds:\n  - name: direct\n    type: direct\n' > ntr-tt-srv.yaml
  docker run -d --name xvt-ntrsrv --network $NET -v $D/ntr:/ntr:ro -v $D/ntr-tt-srv.yaml:/c.yaml:ro \
    -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  printf 'log-level: debug\nmixed-port: 1080\nallow-lan: true\nproxies:\n  - name: tt-out\n    type: trusttunnel\n    server: xvt-ntrsrv\n    port: 8443\n    username: u\n    password: ttpw\n    sni: example.com\n    skip-cert-verify: true\nrules:\n  - MATCH,tt-out\n' > mh-tt-cli.yaml
  docker run -d --name xvt-mhcli --network $NET -v $D/mh-tt-cli.yaml:/root/.config/mihomo/config.yaml:ro metacubex/mihomo:latest >/dev/null 2>&1
  sleep 6
  hit "$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x socks5h://xvt-ntr:1080 http://xvt-target/ 2>&1)" "trusttunnel A: NTR client → mihomo server"
  hit "$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x http://xvt-mhcli:1080 http://xvt-target/ 2>&1)"  "trusttunnel B: mihomo client → NTR server"
  docker rm -f xvt-target xvt-mihomo xvt-ntr xvt-ntrsrv xvt-mhcli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1
}

# ============ naive ⇄ sing-box(真 NaiveProxy/cronet)============
naive() {
  NET=xv-naive; docker network create $NET >/dev/null 2>&1
  docker rm -f xvn-target xvn-sb xvn-ntr xvn-ntrsrv xvn-sbcli >/dev/null 2>&1
  docker run -d --name xvn-target --network $NET traefik/whoami >/dev/null
  printf '{"log":{"level":"debug"},"inbounds":[{"type":"naive","tag":"naive-in","listen":"::","listen_port":8443,"users":[{"username":"u","password":"nvpw"}],"tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem"}}],"outbounds":[{"type":"direct","tag":"direct"}]}\n' > sb-naive-srv.json
  docker run -d --name xvn-sb --network $NET -v $D/sb-naive-srv.json:/c.json:ro \
    -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro ghcr.io/sagernet/sing-box:latest -c /c.json run >/dev/null 2>&1
  printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: naive\n    server: "xvn-sb:8443"\n    user: u\n    secret: "nvpw"\n    sni: example.com\n    insecure: true\n' > ntr-nv-cli.yaml
  docker run -d --name xvn-ntr --network $NET -v $D/ntr:/ntr:ro -v $D/ntr-nv-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  printf 'inbounds:\n  - name: srv-in\n    type: naive\n    listen: 0.0.0.0:8443\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\n    users:\n      - name: u\n        password: "nvpw"\noutbounds:\n  - name: direct\n    type: direct\n' > ntr-nv-srv.yaml
  docker run -d --name xvn-ntrsrv --network $NET -v $D/ntr:/ntr:ro -v $D/ntr-nv-srv.yaml:/c.yaml:ro \
    -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  # sing-box naive outbound = 内嵌 NaiveProxy/cronet,不支持 insecure,必须信任 CA
  printf '{"log":{"level":"debug"},"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"::","listen_port":1080}],"outbounds":[{"type":"naive","tag":"naive-out","server":"xvn-ntrsrv","server_port":8443,"username":"u","password":"nvpw","tls":{"enabled":true,"server_name":"example.com","certificate_path":"/ca.pem"}}]}\n' > sb-naive-cli.json
  docker run -d --name xvn-sbcli --network $NET -v $D/sb-naive-cli.json:/c.json:ro -v $D/ca.pem:/ca.pem:ro \
    ghcr.io/sagernet/sing-box:latest -c /c.json run >/dev/null 2>&1
  sleep 6
  hit "$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x socks5h://xvn-ntr:1080 http://xvn-target/ 2>&1)" "naive A: NTR client → sing-box server"
  hit "$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x http://xvn-sbcli:1080 http://xvn-target/ 2>&1)"  "naive B: sing-box(cronet) client → NTR server"
  docker rm -f xvn-target xvn-sb xvn-ntr xvn-ntrsrv xvn-sbcli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1
}

# ============ ssh ⇄ 真 OpenSSH ============
sshx() {
  NET=xv-ssh; docker network create $NET >/dev/null 2>&1
  docker rm -f xvs-target xvs-sshd xvs-ntr xvs-ntrsrv xvs-sshcli >/dev/null 2>&1
  docker run -d --name xvs-target --network $NET traefik/whoami >/dev/null
  # 坑:Alpine 默认 sshd_config 里 AllowTcpForwarding no,必须 sed 改(append 会被前面的 no 覆盖)
  docker run -d --name xvs-sshd --network $NET alpine sh -c '
apk add --no-cache openssh >/dev/null 2>&1; ssh-keygen -A >/dev/null 2>&1
adduser -D -s /bin/sh u >/dev/null 2>&1; echo "u:pw" | chpasswd >/dev/null 2>&1
sed -i "s/^#*AllowTcpForwarding.*/AllowTcpForwarding yes/" /etc/ssh/sshd_config
sed -i "s/^#*PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config
/usr/sbin/sshd -D -e' >/dev/null 2>&1
  printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: ssh\n    server: "xvs-sshd:22"\n    user: u\n    secret: "pw"\n' > ntr-ssh-cli.yaml
  docker run -d --name xvs-ntr --network $NET -v $D/ntr:/ntr:ro -v $D/ntr-ssh-cli.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  printf 'inbounds:\n  - name: srv-in\n    type: ssh\n    listen: 0.0.0.0:2222\n    tls:\n      key-file: /hostkey\n    users:\n      - name: u\n        password: "pw"\noutbounds:\n  - name: direct\n    type: direct\n' > ntr-ssh-srv.yaml
  docker run -d --name xvs-ntrsrv --network $NET -v $D/ntr:/ntr:ro -v $D/ntr-ssh-srv.yaml:/c.yaml:ro -v $D/ssh_hostkey:/hostkey:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 3
  docker run -d --name xvs-sshcli --network $NET alpine sh -c '
apk add --no-cache openssh-client sshpass >/dev/null 2>&1
sshpass -p pw ssh -N -D 0.0.0.0:1080 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ExitOnForwardFailure=yes u@xvs-ntrsrv' >/dev/null 2>&1
  sleep 12
  hit "$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x socks5h://xvs-ntr:1080 http://xvs-target/ 2>&1)"    "ssh A: NTR client → 真 OpenSSH sshd"
  hit "$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 12 -x socks5h://xvs-sshcli:1080 http://xvs-target/ 2>&1)" "ssh B: 真 OpenSSH client(-D)→ NTR server"
  docker rm -f xvs-target xvs-sshd xvs-ntr xvs-ntrsrv xvs-sshcli >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1
}

gen_certs
echo "════ 新协议交叉验证(6 个方向)════"
tt; naive; sshx
