#!/usr/bin/env bash
# End-to-end test: a coordination server and three nodes in network
# namespaces, two of them behind separate NAT routers. Needs root, nft,
# nsenter, bc and python3. Run from the repository root: sudo test/mesh.sh
# Set KEEP=1 to leave the lab running afterwards for inspection.
set -u
cd "$(dirname "$0")/.."
T=${TMPDIR:-/tmp}/wyrm-e2e
BIN=$T/wyrm
HERE=$PWD/test
fails=0

ok()    { echo "PASS  $*"; }
bad()   { echo "FAIL  $*"; fails=$((fails+1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
deny()  { local name=$1; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }
NS()    { local n=$1; shift; nsenter --net=/run/netns/wl-$n "$@"; }
# bg <name> <netns> <command...>: run a daemon in a namespace, remember its pid
bg()    { local name=$1 n=$2; shift 2; (exec nsenter --net=/run/netns/wl-$n "$@") >>"$T/$name.log" 2>&1 & echo $! >"$T/$name.pid"; }
stop()  { local p; p=$(cat "$T/$1.pid" 2>/dev/null) || return 0; kill "$p" 2>/dev/null
          for _ in $(seq 50); do kill -0 "$p" 2>/dev/null || return 0; sleep 0.1; done; echo "FAIL  $1 did not exit"; fails=$((fails+1)); }
W()     { local n=$1; shift; WYRM_SOCK="$T/$n/run/wyrmd.sock" "$BIN" "$@"; }
has()   { local n=$1 cmd=$2; shift 2; W $n $cmd | grep -q -- "$@"; }   # has <node> <command> <pattern>
json()  { W $1 $2 --json | python3 -c "import json,sys; d=json.load(sys.stdin); print($3)"; }
node()  { local n=$1; shift   # node <name> [extra flags]: start the node daemon
          WYRM_AUTHKEY=${KEY:-} WYRM_SOCK="$T/$n/run/wyrmd.sock" bg $n $n "$BIN" up --state "$T/$n" \
            --coord https://10.0.0.1:8443 --pin "$PIN" --name node-$n "$@"; wait_for 5 W $n status; }
wait_for() { local t=$1; shift; for _ in $(seq $((t*5))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }
direct() { [ "$(W $1 peers | awk 'NR>1 && $3=="direct"' | wc -l)" = "$2" ] && [ "$(W $1 peers | awk 'NR>1' | wc -l)" = "$2" ]; }
send()  { NS $1 timeout 40 python3 "$HERE/net.py" send $2 $3 ${4:-200000}; }
coord_up() { bg coord coord "$BIN" coord serve --dir "$T/coord" --listen 10.0.0.1:8443 --stun 10.0.0.1:3478
             wait_for 5 "$BIN" coord nodes --dir "$T/coord"; }
cleanup() { for n in a b c coord; do stop $n; done; pkill -f "$HERE/net.py" 2>/dev/null; "$T/lab" down 2>/dev/null; }
trap cleanup EXIT

rm -rf "$T"; mkdir -p "$T"
CGO_ENABLED=0 go build -o "$BIN" ./cmd/wyrm && go build -o "$T/lab" ./test/lab || exit 1
"$T/lab" up || exit 1
for r in natA natB; do NS $r sh -c "echo 1 >/proc/sys/net/ipv4/ip_forward; nft -f $HERE/nat.nft" || exit 1; done
coord_up || { echo "coordination server did not start"; cat "$T/coord.log"; exit 1; }
PIN=$("$BIN" coord pin --dir "$T/coord")
KEY=$("$BIN" coord authkey --dir "$T/coord" --reusable --ttl 10m 2>/dev/null)

echo "-- enrollment and NAT traversal"
for n in a b c; do node $n; done
t0=$(date +%s.%N)
if wait_for 20 direct a 2 && wait_for 20 direct b 2 && wait_for 20 direct c 2; then
  ok "all six paths direct ($(echo "$(date +%s.%N) - $t0" | bc | cut -c1-4)s after the last node started)"
else bad "paths not direct"; W a peers; W b peers; W c peers; fi
IPA=$(json a status 'd["ip"]'); IPB=$(json b status 'd["ip"]'); IPC=$(json c status 'd["ip"]')
check "a reaches b through b's NAT (10.0.0.3)" has a peers 'node-b .*10.0.0.3:51820'
check "b reaches a through a's NAT (10.0.0.2)" has b peers 'node-a .*10.0.0.2:51820'
check "a advertises reflexive and LAN endpoints" has a status 'endpoints *10.0.0.2:51820 192.168.1.2:51820'
stop a; node a --no-lan
wait_for 10 has a status 'endpoints *10.0.0.2:51820$' && ok "--no-lan advertises only the address STUN saw" || bad "--no-lan: $(W a status | grep endpoints)"
stop a; node a; wait_for 20 direct a 2; wait_for 20 direct b 2

echo "-- data plane"
for n in a b c; do
  ip=$(json $n status 'd["ip"]')
  for port in 9000 9001; do NS $n python3 "$HERE/net.py" serve $ip $port >/dev/null 2>&1 & done
done
sleep 0.5
# p1 is natA's port on the WAN bridge: everything a exchanges with the internet.
NS wan python3 "$HERE/net.py" sniff p1 4 >"$T/sniff.out" 2>&1 & sniff=$!
sleep 0.3
r=$(send a $IPB 9000 30000000) && ok "30 MB a->b across two NATs, digest verified, $r" || bad "transfer a->b: $r"
check "flow visible on a (initiator out)" has a flows "tcp .*$IPB:9000 *out"
check "flow visible on b (initiator in)" has b flows "tcp *$IPB:9000 .* in "
r=$(send b $IPC 9000 5000000) && ok "5 MB b->c, digest verified, $r" || bad "transfer b->c: $r"
wait $sniff
read -r udp leaked <<<"$(sed 's/udp=//;s/leaked=//' "$T/sniff.out")"
[ "${udp:-0}" -gt 1000 ] && [ "${leaked:-1}" = 0 ] && ok "WAN carried $udp UDP frames, none containing the plaintext marker" || bad "WAN sniff: $(cat "$T/sniff.out")"

echo "-- traffic control"
id=$(W b rule add drop in tcp $IPA 9000)
deny  "drop rule blocks a->b:9000" send a $IPB 9000
check "same rule leaves a->b:9001 alone" send a $IPB 9001
check "same rule leaves c->b:9000 alone" send c $IPB 9000
check "rule hit counter moved" [ "$(json b rules 'd[0]["hits"] > 0')" = True ]
check "dropped packets appear in the packet ring" has b packets 'in *drop *tcp'
W b rule del $id
check "deleting the rule restores a->b:9000" send a $IPB 9000
W b shields on
deny  "shields block unsolicited inbound (a->b:9000)" send a $IPB 9000
check "shields allow replies to outbound flows (b->a:9000)" send b $IPA 9000
W b rule add allow in tcp any 9001 >/dev/null
check "allow rule opens one port through shields (a->b:9001)" send a $IPB 9001
deny  "other ports stay closed (a->b:9000)" send a $IPB 9000

echo "-- capture"
W a capture -s 96 -o "$T/cap.pcap" >/dev/null 2>&1 & cap=$!
sleep 0.5; send a $IPC 9000 500000 >/dev/null; sleep 0.5; kill $cap; wait $cap 2>/dev/null
r=$(python3 "$HERE/net.py" pcap "$T/cap.pcap" 2>&1) && ok "pcap valid: $r" || bad "pcap: $r"
check "capture file is private (0600)" [ "$(stat -c %a "$T/cap.pcap")" = 600 ]

echo "-- persistence and restart"
idb=$(json b status 'd["node_id"]')
stop b; KEY= node b
check "node b really restarted" [ "$(grep -c 'tunnel up' "$T/b.log")" = 2 ]
check "restart keeps identity without an auth key" [ "$(json b status 'd["node_id"]')" = "$idb" ]
check "restart keeps shields" has b status 'shields *true'
check "restart keeps rules" has b rules 'allow *in *tcp *any *9001'
wait_for 20 direct b 2 && wait_for 20 direct a 2 && ok "paths re-established after restart (new discovery key)" || bad "paths after restart"
check "tunnel works after restart" send b $IPA 9000
W b shields off
stop coord
deny  "coordination server is down" "$BIN" coord nodes --dir "$T/coord"
check "tunnels survive a coordination server outage" send a $IPB 9000
wait_for 10 has a status unreachable && ok "nodes report the outage" || bad "outage not reported: $(W a status | grep coordination)"
coord_up
wait_for 40 sh -c "'$BIN' coord nodes --dir $T/coord | grep node-a | grep -q 10.0.0.2:51820" && ok "nodes re-publish endpoints after the server restarts" || bad "re-sync after coordination server restart"
wait_for 10 has a status synced

echo "-- access control"
"$BIN" coord rm --dir "$T/coord" node-c
wait_for 10 direct a 1 && wait_for 10 direct b 1 && ok "removed node dropped by its peers" || bad "removed node still a peer"
deny  "removed node cut off from the mesh" send c $IPA 9000
wait_for 40 has c status unauthorized && ok "removed node sees 'unauthorized'" || bad "removed node state: $(W c status | grep coordination)"
WRONG=sha256:$(head -c 32 /dev/urandom | base64)
WYRM_AUTHKEY=$KEY WYRM_SOCK="$T/d.sock" NS c "$BIN" up --state "$T/d" --iface wyrm9 --coord https://10.0.0.1:8443 --pin "$WRONG" >"$T/d.log" 2>&1
grep -q "does not match pin" "$T/d.log" && [ ! -e "$T/d/node.json" ] && ok "wrong server pin refused, nothing enrolled" || bad "wrong pin: $(cat "$T/d.log")"
WYRM_AUTHKEY=wyrm-auth-forged WYRM_SOCK="$T/d.sock" NS c "$BIN" up --state "$T/d" --iface wyrm9 --coord https://10.0.0.1:8443 --pin "$PIN" >"$T/d.log" 2>&1
grep -q "enrollment refused" "$T/d.log" && [ ! -e "$T/d/node.json" ] && ok "forged auth key refused, nothing enrolled" || bad "forged key: $(cat "$T/d.log")"
deny  "TLS without a client certificate gets no HTTP service" NS c python3 -c "
import ssl, socket
s = ssl._create_unverified_context().wrap_socket(socket.create_connection(('10.0.0.1', 8443), timeout=3))
s.sendall(b'GET /v1/netmap HTTP/1.1\r\nHost: x\r\n\r\n'); assert s.recv(100)"
perms=$(stat -c %a "$T/a/node.json" "$T/b/policy.json" "$T/a/run/wyrmd.sock" "$T/coord/state.json" "$T/coord/coord.key" "$T/coord/admin.sock" | sort -u | tr '\n' ' ')
[ "$perms" = "600 " ] && ok "keys, state, policy and sockets are owner-only (0600)" || bad "permissions: $perms"
deny  "auth key secret is not stored or logged" grep -R -q -- "$KEY" "$T/coord" "$T"/a.log "$T"/b.log "$T"/c.log "$T"/coord.log
deny  "no key material in logs" grep -h -i "private\|seed\|auth-" "$T"/a.log "$T"/b.log "$T"/c.log "$T"/coord.log

echo "-- dashboard"
for v in peers flows packets rules; do W a top --once --view $v >"$T/top-$v.txt" 2>&1 || bad "top --once --view $v"; done
check "top renders all four views" sh -c "grep -q 'NAME *MESH-IP' $T/top-peers.txt && grep -q 'PROTO *LOCAL' $T/top-flows.txt && grep -q 'TIME *DIR' $T/top-packets.txt && grep -q 'ID *ACTION' $T/top-rules.txt"
check "interactive dashboard: keys, actions, resize, clean exit (10 steps)" python3 "$HERE/tui_drive.py" "$T/a/run/wyrmd.sock" "$BIN"

echo
[ $fails = 0 ] && echo "ALL PASSED" || echo "$fails FAILED"
[ "${KEEP:-}" ] && { trap - EXIT; echo "lab left running in $T"; }
exit $fails
