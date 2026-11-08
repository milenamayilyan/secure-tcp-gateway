#!/usr/bin/env bash
# End-to-end demo on ONE Linux machine using network namespaces:
#
#   pc1 (10.0.1.2) -- d1 (10.0.1.1 | 10.0.12.1) -- d2 (10.0.12.2 | 10.0.2.1) -- pc2 (10.0.2.2)
#
# Usage:  sudo demo/netns_demo.sh run      # build topology, start gateways, test, clean up
#         sudo demo/netns_demo.sh up|down  # just build / tear down the topology
# Needs: iproute2, iptables, ethtool, curl, python3 (+ scgw deps), optionally tcpdump.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
PY=${PYTHON:-python3}
WORK=/tmp/scgw-demo
MARKER="TOP-SECRET-MARKER-$(date +%s)"

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

up() {
  down 2>/dev/null || true
  for n in pc1 d1 d2 pc2; do ip netns add $n; ip -n $n link set lo up; done
  ip link add veth-p1  type veth peer name veth-d1l
  ip link add veth-d1w type veth peer name veth-d2w
  ip link add veth-d2l type veth peer name veth-p2
  ip link set veth-p1  netns pc1; ip link set veth-d1l netns d1
  ip link set veth-d1w netns d1;  ip link set veth-d2w netns d2
  ip link set veth-d2l netns d2;  ip link set veth-p2  netns pc2
  ip -n pc1 addr add 10.0.1.2/24  dev veth-p1
  ip -n d1  addr add 10.0.1.1/24  dev veth-d1l
  ip -n d1  addr add 10.0.12.1/24 dev veth-d1w
  ip -n d2  addr add 10.0.12.2/24 dev veth-d2w
  ip -n d2  addr add 10.0.2.1/24  dev veth-d2l
  ip -n pc2 addr add 10.0.2.2/24  dev veth-p2
  for pair in pc1:veth-p1 d1:veth-d1l d1:veth-d1w d2:veth-d2w d2:veth-d2l pc2:veth-p2; do
    ns=${pair%%:*}; dev=${pair##*:}
    ip -n "$ns" link set "$dev" up
    # real checksums + no segmentation offload, so the gateways see wire-format packets
    ip netns exec "$ns" ethtool -K "$dev" tx off rx off gso off tso off gro off >/dev/null 2>&1 || true
  done
  ip -n pc1 route add default via 10.0.1.1
  ip -n pc2 route add default via 10.0.2.1
  ip -n d1  route add 10.0.2.0/24 via 10.0.12.2
  ip -n d2  route add 10.0.1.0/24 via 10.0.12.1
  for d in d1 d2; do
    ip netns exec $d sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
  done
}

down() {
  pkill -f "scgw --role" 2>/dev/null || true
  pkill -f "http.server 8080" 2>/dev/null || true
  pkill tcpdump 2>/dev/null || true
  for n in pc1 d1 d2 pc2; do ip netns del $n 2>/dev/null || true; done
}

run() {
  trap 'down' EXIT
  up
  mkdir -p $WORK; rm -f $WORK/*
  echo "$MARKER" > $WORK/secret.txt
  head -c 300000 /dev/urandom > $WORK/big.bin
  ( cd $WORK && sha256sum big.bin > big.sha )
  [[ -f $WORK/psk ]] || "$ROOT/scripts/gen_psk.sh" $WORK/psk >/dev/null

  echo "[*] baseline: gateways NOT running, rules installed -> traffic must be blocked (fail closed)"
  ip netns exec d1 "$ROOT/scripts/setup_iptables.sh" --lan-if veth-d1l --wan-if veth-d1w --local-host 10.0.1.2 --remote-host 10.0.2.2 --ports 8080 >/dev/null
  ip netns exec d2 "$ROOT/scripts/setup_iptables.sh" --lan-if veth-d2l --wan-if veth-d2w --local-host 10.0.2.2 --remote-host 10.0.1.2 --ports 8080 >/dev/null

  ip netns exec pc2 $PY -m http.server 8080 --bind 10.0.2.2 --directory $WORK >/dev/null 2>&1 &
  sleep 1
  if ip netns exec pc1 curl -s --max-time 3 http://10.0.2.2:8080/secret.txt >/dev/null; then
    echo "FAIL: traffic flowed without gateways"; exit 1
  else echo "    OK: blocked"; fi

  echo "[*] starting gateways"
  export PYTHONPATH=$ROOT/src
  ip netns exec d2 $PY -m scgw --role responder  --local-host 10.0.2.2 --remote-host 10.0.1.2 --peer-addr 10.0.12.1 --psk-file $WORK/psk --stats-interval 5 >$WORK/d2.log 2>&1 &
  sleep 1
  ip netns exec d1 $PY -m scgw --role initiator  --local-host 10.0.1.2 --remote-host 10.0.2.2 --peer-addr 10.0.12.2 --psk-file $WORK/psk --stats-interval 5 >$WORK/d1.log 2>&1 &
  for _ in $(seq 1 20); do grep -q "established" $WORK/d1.log 2>/dev/null && break; sleep 0.5; done
  grep -q "established" $WORK/d1.log || { echo "FAIL: no session"; cat $WORK/d1.log $WORK/d2.log; exit 1; }
  echo "    $(grep established $WORK/d1.log | tail -1)"

  if command -v tcpdump >/dev/null; then
    ip netns exec d1 tcpdump -i veth-d1l -w $WORK/lan.pcap -U tcp port 8080 >/dev/null 2>&1 &
    ip netns exec d1 tcpdump -i veth-d1w -w $WORK/wan.pcap -U tcp port 8080 >/dev/null 2>&1 &
    sleep 1
  fi

  echo "[*] PC1 -> PC2 transfer through the secure channel"
  GOT=$(ip netns exec pc1 curl -sS --max-time 15 http://10.0.2.2:8080/secret.txt)
  [[ "$GOT" == "$MARKER" ]] && echo "    OK: small file received intact" || { echo "FAIL: got '$GOT'"; exit 1; }
  ip netns exec pc1 curl -sS --max-time 30 -o $WORK/big.recv http://10.0.2.2:8080/big.bin
  ( cd $WORK && sha256sum big.recv | cut -d' ' -f1 | grep -q "$(cut -d' ' -f1 big.sha)" ) \
     && echo "    OK: 300 KB random file received, sha256 matches" || { echo "FAIL: checksum mismatch"; exit 1; }

  if command -v tcpdump >/dev/null; then
    sleep 1; pkill tcpdump || true; sleep 0.5
    L=$(grep -a -c "$MARKER" $WORK/lan.pcap || true); W=$(grep -a -c "$MARKER" $WORK/wan.pcap || true)
    echo "[*] marker occurrences  PC-side link: $L   Device1<->Device2 link: $W"
    [[ "$L" -ge 1 && "$W" -eq 0 ]] && echo "    OK: plaintext on LAN side only, ciphertext between devices" \
      || { echo "FAIL: unexpected capture result"; exit 1; }
  else
    echo "[i] tcpdump not installed - skipping wire capture check"
  fi
  sleep 5
  echo "[*] gateway statistics"; grep -h "stats" $WORK/d1.log $WORK/d2.log | tail -4 || true
  echo "ALL CHECKS PASSED"
}

case "${1:-run}" in up) up;; down) down;; run) run;; *) echo "usage: $0 run|up|down"; exit 1;; esac
