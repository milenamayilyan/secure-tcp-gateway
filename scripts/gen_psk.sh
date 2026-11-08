#!/usr/bin/env bash
# Generate a 256-bit pre-shared key. Copy the SAME file to both devices (securely!).
set -euo pipefail
OUT=${1:-scgw.psk}
umask 077
openssl rand -hex 32 > "$OUT"
echo "wrote $OUT (mode 600)"
