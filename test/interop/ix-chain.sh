#!/bin/bash
# ============================================================================
# 组 J:relay 多跳 / dialerProxy 端到端 —— 出站配 dialer 经另一具名出站建底层连接
# 语义:出站 A 配 `dialer: B` → A 的底层拨号(拨到 A 的上游 server)改经出站 B 建流,
#       天然支持多级链 A→B→C(config.wireDialers 第二趟设 BaseDial + 环检测)。
# 铁律:双网络隔离【反证】流量必经中间跳 —— 出口代理只在后端网、client 够不到,
#       唯有 relay 生效(底层连接经跨网的中间跳)才可能通。再加负向对照坐实隔离真实。
# 专属 network=ix-chain-f(前端 client↔入口跳)/ix-chain-b(后端 跳↔出口↔靶机);前缀=ixc-
# 判据:curl 经 socks5h 打 whoami 靶机;Hostname 行=通,RemoteAddr==出口代理=确从出口落地
# ============================================================================
set -u
D=/tmp/ntr-interop; cd "$D"
NF=ix-chain-f       # 前端网:client ↔ 入口跳(client 唯一够得到的网)
NB=ix-chain-b       # 后端网:中间/出口跳 ↔ 靶机(client 够不到)
U=11111111-1111-1111-1111-111111111111
U2=22222222-2222-2222-2222-222222222222
U3=33333333-3333-3333-3333-333333333333
PASS=0; FAIL=0

clean(){ docker rm -f $(docker ps -aq --filter "name=ixc-") >/dev/null 2>&1; }
netup(){ docker network create "$NF" >/dev/null 2>&1; docker network create "$NB" >/dev/null 2>&1; }
netdown(){ docker network rm "$NF" "$NB" >/dev/null 2>&1; }
trap 'clean; netdown' EXIT

# 起 NTR 容器接指定网络(明文 vless,免证书)
ntr(){ local name=$1 cfg=$2 net=$3
  docker run -d --name "$name" --network "$net" -v "$D/ntr:/ntr:ro" -v "$D/$cfg:/c.yaml:ro" \
    alpine /ntr -config /c.yaml >/dev/null 2>&1
}
# NTR proxy 服务端:vless(none 明文)入 10000 → direct 出;$1=uuid $2=输出文件
gen_srv(){ local uuid=$1 out=$2
  printf 'inbounds:\n  - listen: 0.0.0.0:10000\n    layers: [{type: vless}]\n    users: [{uuid: "%s"}]\n    outbound: direct\noutbounds: [{name: direct, type: direct}]\n' "$uuid" > "$out"
}
pull(){ docker run --rm --network "$NF" curlimages/curl:latest -s --max-time 15 -x "socks5h://ixc-cli:1080" http://ixc-target/ 2>&1; }
pull_retry(){ local o=""; local i; for i in $(seq 1 8); do o=$(pull); echo "$o" | grep -q Hostname && { echo "$o"; return; }; sleep 2; done; echo "$o"; }
ipof(){ docker inspect -f "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$1" 2>/dev/null; }
raddr(){ echo "$1" | grep -i RemoteAddr | sed 's/.*RemoteAddr: //; s/:[0-9]*$//'; }
dumplogs(){ local c; for c in "$@"; do echo "    --- $c ---"; docker logs "$c" 2>&1 | tail -5 | sed 's/^/      /'; done; }

# ---------------------------------------------------------------------------
# 用例1:2 跳 relay(client → exit[dialer:mid] → target)+ 双网络隔离
#   拓扑:client 仅前端网;exit 仅后端网(client 够不到);mid 跨前后端(唯一桥)。
#   relay 生效:exit 底层拨号经 mid → client 只需连 mid(前端)→ mid 连 exit(后端)→ 落地。
# ---------------------------------------------------------------------------
case_2hop(){
  echo "===== 用例1:2 跳 relay(client → exit[dialer:mid] → target)双网络隔离 ====="
  clean
  docker run -d --name ixc-target --network "$NB" traefik/whoami >/dev/null
  gen_srv "$U"  s-exit.yaml; ntr ixc-exit s-exit.yaml "$NB"        # 出口:仅后端网
  gen_srv "$U2" s-mid.yaml;  ntr ixc-mid  s-mid.yaml  "$NB"        # 中间:后端网起…
  docker network connect "$NF" ixc-mid                              # …再接前端网(跨网桥)
  sleep 2
  cat > c-2hop.yaml <<EOF
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: exit}
outbounds:
  - {name: exit, type: proxy, server: "ixc-exit:10000", secret: "$U",  layers: [{type: vless}], dialer: mid}
  - {name: mid,  type: proxy, server: "ixc-mid:10000",  secret: "$U2", layers: [{type: vless}]}
EOF
  ntr ixc-cli c-2hop.yaml "$NF"
  sleep 3
  local OUT RA EXIP; OUT=$(pull_retry); RA=$(raddr "$OUT"); EXIP=$(ipof ixc-exit "$NB")
  echo "  exit(后端)IP=$EXIP  靶机看到来源=$RA"
  if echo "$OUT" | grep -q Hostname && [ -n "$EXIP" ] && [ "$RA" = "$EXIP" ]; then
    echo "  ✅ 用例1 通:底层连接经 mid 跨网、从 exit 落地(RemoteAddr==exit)"; PASS=$((PASS+1))
  else
    echo "  ❌ 用例1 失败 OUT=$OUT"; FAIL=$((FAIL+1)); dumplogs ixc-cli ixc-mid ixc-exit
  fi
  echo
}

# ---------------------------------------------------------------------------
# 用例2:负向对照 —— 去掉 dialer 直连,client 够不到后端网 exit,【必须】失败。
#   坐实用例1 的“通”确由 relay 贡献,而非网络本就连通。
# ---------------------------------------------------------------------------
case_isolation(){
  echo "===== 用例2:负向对照 —— exit 去掉 dialer 直连,client 够不到后端网,必须失败 ====="
  clean
  docker run -d --name ixc-target --network "$NB" traefik/whoami >/dev/null
  gen_srv "$U" s-exit.yaml; ntr ixc-exit s-exit.yaml "$NB"
  sleep 2
  cat > c-iso.yaml <<EOF
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: exit}
outbounds:
  - {name: exit, type: proxy, server: "ixc-exit:10000", secret: "$U", layers: [{type: vless}]}
EOF
  ntr ixc-cli c-iso.yaml "$NF"
  sleep 5
  local OUT; OUT=$(pull)
  if echo "$OUT" | grep -q Hostname; then
    echo "  ❌ 对照异常:直连竟然通了 → 网络隔离无效,用例1 的 PASS 不可信!OUT=$OUT"; FAIL=$((FAIL+1))
  else
    echo "  ✅ 用例2 符合预期:去掉 dialer 直连不通(隔离真实 → 用例1 的通确由 relay 贡献)"; PASS=$((PASS+1))
  fi
  echo
}

# ---------------------------------------------------------------------------
# 用例3:3 跳链 client → entry → mid → exit → target(dialer 链式 A→B→C)。
#   仅 entry 跨到前端网(client 唯一入口);mid/exit/靶机 皆在后端网。
#   证明 config.wireDialers 的链式 BaseDial(exit→mid→entry)天然多级串联。
# ---------------------------------------------------------------------------
case_3hop(){
  echo "===== 用例3:3 跳链 client → entry → mid → exit → target(dialer 链式 A→B→C) ====="
  clean
  docker run -d --name ixc-target --network "$NB" traefik/whoami >/dev/null
  gen_srv "$U"  s-exit.yaml;  ntr ixc-exit  s-exit.yaml  "$NB"
  gen_srv "$U2" s-mid.yaml;   ntr ixc-mid   s-mid.yaml   "$NB"
  gen_srv "$U3" s-entry.yaml; ntr ixc-entry s-entry.yaml "$NB"
  docker network connect "$NF" ixc-entry                           # 仅 entry 跨前端网
  sleep 2
  cat > c-3hop.yaml <<EOF
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: exit}
outbounds:
  - {name: exit,  type: proxy, server: "ixc-exit:10000",  secret: "$U",  layers: [{type: vless}], dialer: mid}
  - {name: mid,   type: proxy, server: "ixc-mid:10000",   secret: "$U2", layers: [{type: vless}], dialer: entry}
  - {name: entry, type: proxy, server: "ixc-entry:10000", secret: "$U3", layers: [{type: vless}]}
EOF
  ntr ixc-cli c-3hop.yaml "$NF"
  sleep 3
  local OUT RA EXIP; OUT=$(pull_retry); RA=$(raddr "$OUT"); EXIP=$(ipof ixc-exit "$NB")
  echo "  exit IP=$EXIP  靶机看到来源=$RA"
  if echo "$OUT" | grep -q Hostname && [ -n "$EXIP" ] && [ "$RA" = "$EXIP" ]; then
    echo "  ✅ 用例3 通:client→entry→mid→exit→target 三跳链,从 exit 落地"; PASS=$((PASS+1))
  else
    echo "  ❌ 用例3 失败 OUT=$OUT"; FAIL=$((FAIL+1)); dumplogs ixc-cli ixc-entry ixc-mid ixc-exit
  fi
  echo
}

# ---------------------------------------------------------------------------
# 用例4:环检测 —— dialer 成环(a→b→a)配置必须被建栈期拒绝(不静默、不死循环)。
# ---------------------------------------------------------------------------
case_cycle(){
  echo "===== 用例4:dialer 成环(a→b→a)必须被建栈期拒绝 ====="
  clean
  cat > c-cycle.yaml <<EOF
inbounds:
  - {listen: 0.0.0.0:1080, layers: [{type: socks}], outbound: a}
outbounds:
  - {name: a, type: proxy, server: "ixc-x:10000", secret: "$U",  layers: [{type: vless}], dialer: b}
  - {name: b, type: proxy, server: "ixc-y:10000", secret: "$U2", layers: [{type: vless}], dialer: a}
EOF
  local LOG; LOG=$(docker run --rm --network "$NF" -v "$D/ntr:/ntr:ro" -v "$D/c-cycle.yaml:/c.yaml:ro" alpine /ntr -config /c.yaml 2>&1)
  if echo "$LOG" | grep -q "成环"; then
    echo "  ✅ 用例4:环被拒(报错含‘成环’)"; PASS=$((PASS+1))
  else
    echo "  ❌ 用例4:环未被拒 LOG=$(echo "$LOG" | tail -3)"; FAIL=$((FAIL+1))
  fi
  echo
}

run_all(){
  netup
  case_2hop
  case_isolation
  case_3hop
  case_cycle
  echo "════════ ix-chain 结论:PASS=$PASS FAIL=$FAIL ════════"
  [ "$FAIL" -eq 0 ] && echo "✅ relay 多跳 / dialerProxy 全绿" || echo "❌ 有失败"
}
"${@:-run_all}"
