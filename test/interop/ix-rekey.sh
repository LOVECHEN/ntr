#!/bin/bash
# 凭据级热重载(Tier-1 止血)验证:改【顶层 users 的 keys】但【口形态不变】→ SIGHUP → 该口按新凭据重启。
#   起 vless 口(顶层 user alice.keys.vless=UUID_A)。客户端 A(UUID_A)先通。
#   改配置:alice.keys.vless A→B(listen/传输/协议全不变)→ SIGHUP。
#   期望:① 客户端 A(老 UUID_A)被拒(= footgun 锚点:修前热重载 no-op → 老 key 仍通 → 本条 FAIL);
#         ② 新客户端 B(UUID_B)通。
# 自包含(遵 ntr-ci-interop-self-contained):$D 只需 ntr 二进制;明文 vless 无需证书。
set -u
NET=ix-rekey; PFX=ixrk-; D=/tmp/ntr-interop
NTR=${NTR_BIN:-$D/ntr}; CFG=$D/_rekey.yaml
UUIDA="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
UUIDB="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
cleanup(){ docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; docker network create $NET >/dev/null 2>&1
docker run -d --name ${PFX}who --network $NET traefik/whoami >/dev/null 2>&1
sleep 1

# 服务端:顶层 user alice,keys.vless=$1;vless 口 :10000(形态恒定)→ direct
write_srv(){ cat > $CFG <<Y
users:
  - name: alice
    keys:
      vless: $1
inbounds:
  - name: vless-in
    type: vless
    listen: 0.0.0.0:10000
    outbound: direct
outbounds:
  - name: direct
    type: direct
Y
}
# 客户端:socks :$1 → vless 出站 uuid=$2
cli_cfg(){ cat > $D/_rk-cli$1.yaml <<Y
inbounds:
  - name: s5-in
    type: socks
    listen: 0.0.0.0:$1
    outbound: up
outbounds:
  - name: up
    type: vless
    server: "${PFX}s:10000"
    secret: "$2"
Y
}

write_srv "$UUIDA"
docker run -d --name ${PFX}s --network $NET -v $NTR:/ntr:ro -v $CFG:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
cli_cfg 1080 "$UUIDA"; docker run -d --name ${PFX}cliA --network $NET -v $NTR:/ntr:ro -v $D/_rk-cli1080.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 3

probe(){ docker run --rm --network $NET curlimages/curl:latest -s --max-time 6 -x socks5h://$1:$2 http://${PFX}who/ 2>/dev/null | grep -c Hostname; }
pass=0; fail=0
chk(){ local label=$1 got=$2 want=$3; if [ "$got" = "$want" ]; then echo "  [$label] PASS"; pass=$((pass+1)); else echo "  [$label] FAIL (want $want got $got)"; fail=$((fail+1)); fi; }

echo "=== 重载前:客户端 A(UUID_A)应通 ==="
chk "A(keyA)通" "$(probe ${PFX}cliA 1080)" 1

echo "=== 改 keys.vless A→B(口形态不变)+ SIGHUP ==="
write_srv "$UUIDB"
docker kill -s HUP ${PFX}s >/dev/null 2>&1
sleep 3
docker logs ${PFX}s 2>&1 | grep -iE '热重载完成' | tail -1 | sed 's/^/  /'

echo "=== 重载后 ==="
# ① 老 UUID_A 应被拒(footgun 锚点:修前会仍通=0→本条断言 got=0=拒)
chk "A(老keyA)被拒" "$(probe ${PFX}cliA 1080)" 0
# ② 新 UUID_B 应通
cli_cfg 1081 "$UUIDB"; docker run -d --name ${PFX}cliB --network $NET -v $NTR:/ntr:ro -v $D/_rk-cli1081.yaml:/c.yaml:ro alpine /ntr -config /c.yaml >/dev/null 2>&1
sleep 3
chk "B(新keyB)通" "$(probe ${PFX}cliB 1081)" 1

echo "═══ 凭据级热重载 Tier-1 e2e: $pass 通 / $fail 失败 ═══"
[ "$fail" != 0 ] && { echo "--- srv ---"; docker logs ${PFX}s 2>&1|tail -8; }
cleanup; echo DONE
