#!/usr/bin/env bash
# Configure a gateway (Device1 or Device2) to divert the selected TCP flows to scgw.
#
#   Device1: --lan-if <towards PC1> --wan-if <towards Device2> --local-host PC1 --remote-host PC2
#   Device2: --lan-if <towards PC2> --wan-if <towards Device1> --local-host PC2 --remote-host PC1
#
# Queue 0: LAN -> WAN direction (protect / encrypt)
# Queue 1: WAN -> LAN direction (unprotect / decrypt)
set -euo pipefail

IPT=${IPT:-iptables}
LAN_IF=""; WAN_IF=""; LOCAL=""; REMOTE=""; PORTS=""; MSS=1400; QP=0; QU=1

usage() {
  cat <<USAGE
Usage: $0 --lan-if IF --wan-if IF --local-host IP --remote-host IP
          [--ports 80,443,8080] [--mss 1400] [--queue-protect 0] [--queue-unprotect 1]
Selected traffic = TCP between local-host and remote-host (optionally only these
ports, matched on source OR destination port).
USAGE
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lan-if) LAN_IF=$2; shift 2;;
    --wan-if) WAN_IF=$2; shift 2;;
    --local-host) LOCAL=$2; shift 2;;
    --remote-host) REMOTE=$2; shift 2;;
    --ports) PORTS=$2; shift 2;;
    --mss) MSS=$2; shift 2;;
    --queue-protect) QP=$2; shift 2;;
    --queue-unprotect) QU=$2; shift 2;;
    -h|--help) usage;;
    *) echo "unknown option: $1"; usage;;
  esac
done
[[ -n $LAN_IF && -n $WAN_IF && -n $LOCAL && -n $REMOTE ]] || usage
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

PM=()
[[ -n $PORTS ]] && PM=(-m multiport --ports "$PORTS")

sysctl -qw net.ipv4.ip_forward=1
# NIC offloads merge/split packets (GRO/LRO/GSO/TSO) - the gateway must see real wire packets.
if command -v ethtool >/dev/null; then
  for d in "$LAN_IF" "$WAN_IF"; do ethtool -K "$d" gro off lro off gso off tso off 2>/dev/null || true; done
fi

mkchain() {  # table chain hook
  $IPT -t "$1" -N "$2" 2>/dev/null || $IPT -t "$1" -F "$2"
  $IPT -t "$1" -C "$3" -j "$2" 2>/dev/null || $IPT -t "$1" -I "$3" 1 -j "$2"
}

# 1) Exempt selected flows from conntrack: conntrack would otherwise see payloads that
#    changed length (and may seq-adjust / mark them INVALID).
mkchain raw SCGW_RAW PREROUTING
$IPT -t raw -A SCGW_RAW -p tcp -i "$LAN_IF" -s "$LOCAL"  -d "$REMOTE" "${PM[@]}" -j CT --notrack
$IPT -t raw -A SCGW_RAW -p tcp -i "$WAN_IF" -s "$REMOTE" -d "$LOCAL"  "${PM[@]}" -j CT --notrack

# 2) Clamp MSS so payload + 24 bytes of overhead still fits the path MTU (no fragmentation).
mkchain mangle SCGW_MSS FORWARD
for pair in "$LOCAL $REMOTE" "$REMOTE $LOCAL"; do
  set -- $pair
  $IPT -t mangle -A SCGW_MSS -p tcp --tcp-flags SYN,RST SYN -s "$1" -d "$2" "${PM[@]}" -j TCPMSS --set-mss "$MSS"
done

# 3) Divert data to userspace.  NO --queue-bypass: if scgw is not running, packets are
#    dropped (fail closed) instead of leaking in clear text.
mkchain filter SCGW_FWD FORWARD
$IPT -A SCGW_FWD -p tcp -i "$LAN_IF" -s "$LOCAL"  -d "$REMOTE" "${PM[@]}" -j NFQUEUE --queue-num "$QP"
$IPT -A SCGW_FWD -p tcp -i "$WAN_IF" -s "$REMOTE" -d "$LOCAL"  "${PM[@]}" -j NFQUEUE --queue-num "$QU"

echo "scgw iptables rules installed (LAN=$LAN_IF WAN=$WAN_IF local=$LOCAL remote=$REMOTE ports=${PORTS:-all} mss=$MSS)"
