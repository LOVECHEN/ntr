#!/bin/bash
# 会话式协议当反连 portal:hy2 / tuic / anytls / hysteria1 / juicity 各自 type + mode: portal,协议本身一行不改,
# 只靠运行时注入的 StreamDispatch 把已握手流改派进隧道。每协议一组:
#   portal(NTR,mode: portal)← bridge(NTR,bridges: 反连拨 portal)  usr(NTR socks → 同协议拨 portal)
# 判据:usr 经 portal 打靶机 whoami,靶机看到的来源 IP == bridge 的 IP(流量确从 bridge 落地,而非 portal 直出)。
# 专属隔离:network=ixsp 容器前缀=ixsp-
set -u
NET=ixsp; PFX=ixsp-; D=/tmp/ntr-interop; NTR=${NTR_BIN:-$D/ntr}; CD=reverse.ntr; PW=sppw
UUID=00000000-0000-0000-0000-0000000000cd
cleanup(){ docker ps -aq --filter "name=$PFX"|xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
# 证书自举(脚本自包含;缺失时 docker 会把单文件挂载点建成空目录)
for f in cert.pem key.pem ca.pem; do [ -d "$D/$f" ] && rmdir "$D/$f"; done
[ -f "$D/cert.pem" ] && [ -f "$D/key.pem" ] || docker run --rm -v $D:/w -w /w alpine sh -c 'apk add openssl>/dev/null 2>&1; openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 90 -nodes -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com" -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1'
[ -f "$D/ca.pem" ] || cp $D/cert.pem $D/ca.pem
chmod 644 $D/cert.pem $D/key.pem $D/ca.pem 2>/dev/null
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}target --network $NET traefik/whoami >/dev/null

# $1=协议 type;入站用户行 / 出站凭据行按协议给
users_of(){ case $1 in
  tuic|juicity) printf '      - uuid: "%s"\n        password: "%s"\n' "$UUID" "$PW" ;;
  *)            printf '      - password: "%s"\n' "$PW" ;;
esac; }
cred_of(){ case $1 in
  tuic|juicity) printf '    uuid: "%s"\n    secret: "%s"\n' "$UUID" "$PW" ;;
  *)            printf '    secret: "%s"\n' "$PW" ;;
esac; }

one(){ local P=$1 p=${PFX}$1-
  { printf 'inbounds:\n  - name: portal-in\n    type: %s\n    mode: portal\n    listen: 0.0.0.0:8443\n    control-domain: %s\n    tls:\n      cert-file: /cert.pem\n      key-file: /key.pem\n    users:\n' "$P" "$CD"
    users_of $P
    printf 'outbounds:\n  - name: direct\n    type: direct\n'; } > $D/_sp_${P}_portal.yaml
  { printf 'outbounds:\n  - name: up\n    type: %s\n    server: "%sportal:8443"\n' "$P" "$p"; cred_of $P
    printf '    sni: example.com\n    insecure: true\nbridges:\n  - portal: up\n    control-domain: %s\n    pool: 2\n' "$CD"; } > $D/_sp_${P}_bridge.yaml
  { printf 'inbounds:\n  - name: s5-in\n    type: socks\n    listen: 0.0.0.0:1080\n    outbound: up\noutbounds:\n  - name: up\n    type: %s\n    server: "%sportal:8443"\n' "$P" "$p"; cred_of $P
    printf '    sni: example.com\n    insecure: true\n'; } > $D/_sp_${P}_user.yaml
  docker run -d --name ${p}portal --network $NET -v $NTR:/ntr:ro -v $D/_sp_${P}_portal.yaml:/c.yaml:ro -v $D/cert.pem:/cert.pem:ro -v $D/key.pem:/key.pem:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 2
  docker run -d --name ${p}bridge --network $NET -v $NTR:/ntr:ro -v $D/_sp_${P}_bridge.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  docker run -d --name ${p}usr --network $NET -v $NTR:/ntr:ro -v $D/_sp_${P}_user.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
  sleep 4
  local BIP RA i
  BIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ${p}bridge)
  for i in 1 2 3 4 5; do
    RA=$(docker run --rm --network $NET curlimages/curl:latest -s --max-time 10 -x socks5h://${p}usr:1080 http://${PFX}target/ 2>&1|grep -i RemoteAddr|sed 's/.*RemoteAddr: //; s/:[0-9]*$//')
    [ -n "$RA" ] && break; sleep 2
  done
  if [ -n "$RA" ] && [ "$RA" = "$BIP" ]; then echo "  ✅ $P 当反连 portal(靶机来源=$RA = bridge)"
  else echo "  ❌ $P 当反连 portal(靶机来源=${RA:-无} bridge=$BIP)"; docker logs ${p}portal 2>&1|tail -3; docker logs ${p}bridge 2>&1|tail -3; fi
  docker rm -f ${p}portal ${p}bridge ${p}usr >/dev/null 2>&1
}

echo "==== 会话式协议当反连 portal ===="
for P in hysteria2 tuic anytls hysteria1 juicity; do one $P; done
cleanup; echo DONE
