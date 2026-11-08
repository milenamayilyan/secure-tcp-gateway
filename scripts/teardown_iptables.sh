#!/usr/bin/env bash
# Remove everything installed by setup_iptables.sh
set -uo pipefail
IPT=${IPT:-iptables}
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
rm_chain() {  # table chain hook
  $IPT -t "$1" -D "$3" -j "$2" 2>/dev/null
  $IPT -t "$1" -F "$2" 2>/dev/null
  $IPT -t "$1" -X "$2" 2>/dev/null
}
rm_chain filter SCGW_FWD FORWARD
rm_chain mangle SCGW_MSS FORWARD
rm_chain raw SCGW_RAW PREROUTING
echo "scgw iptables rules removed"
