"""Packet transformation engine (no kernel dependency, fully unit-testable).

protect():    plaintext packet  -> packet whose TCP payload is  CT || TAG || CTR
unprotect():  protected packet  -> original packet (checksums recomputed)

Only the TCP *payload* is touched.  IP and TCP headers (addresses, ports, seq,
ack, flags, options, TTL, ...) are preserved; only the IP total-length, IP header
checksum and TCP checksum are recomputed.  There is no UDP encapsulation and no
extra header.

Authenticated associated data (AAD):  "SCGW1" || src_ip || dst_ip || sport || dport || seq
This binds each ciphertext to its flow and TCP sequence position, so a payload
cannot be spliced into a different connection or sequence number.

Policy (fail closed):
  * data packets while no valid session exists are DROPPED, never sent in clear
  * IP fragments of selected flows are dropped
  * anything failing tag verification / replay check is dropped
  * zero-length segments (SYN, pure ACK, FIN, RST) carry no data and pass unchanged
"""
from __future__ import annotations

import logging
import socket
import struct
from collections import Counter
from typing import Optional

from .crypto import OVERHEAD, InvalidTag, ReplayError, SessionExhausted
from .packet import PacketError, TcpPacket, assemble, parse
from .session import SessionManager

log = logging.getLogger("scgw.engine")


def make_aad(p: TcpPacket) -> bytes:
    return b"SCGW1" + p.src + p.dst + struct.pack("!HHI", p.sport, p.dport, p.seq)


class Engine:
    def __init__(self, manager: SessionManager, local_ip: str, remote_ip: str) -> None:
        self.mgr = manager
        self.local = socket.inet_aton(local_ip)    # host behind this device
        self.remote = socket.inet_aton(remote_ip)  # host behind the peer device
        self.stats: Counter = Counter()
        self._need_rekey = False

    def take_rekey_request(self) -> bool:
        """True once after the nonce space of the tx direction was exhausted."""
        flag, self._need_rekey = self._need_rekey, False
        return flag

    # -- outbound: LAN side -> peer device -------------------------------
    def protect(self, raw: bytes) -> Optional[bytes]:
        """Return bytes to forward, or None to drop."""
        try:
            p = parse(raw)
        except PacketError as e:
            self.stats["drop_malformed_or_fragment"] += 1
            log.debug("protect: drop (%s)", e)
            return None
        if p.src != self.local or p.dst != self.remote:
            self.stats["drop_unexpected_flow"] += 1
            return None
        if not p.payload:
            self.stats["pass_empty_segment"] += 1
            return raw
        sess = self.mgr.tx_session()
        if sess is None:
            self.stats["drop_no_session"] += 1
            return None
        try:
            wire = sess.tx.seal(p.payload, make_aad(p))
            out = assemble(p, wire)
        except SessionExhausted:
            self._need_rekey = True
            self.stats["drop_nonce_exhausted"] += 1
            return None
        except PacketError:
            self.stats["drop_too_large"] += 1
            return None
        self.stats["protected"] += 1
        return out

    # -- inbound: peer device -> LAN side --------------------------------
    def unprotect(self, raw: bytes) -> Optional[bytes]:
        try:
            p = parse(raw)
        except PacketError as e:
            self.stats["drop_malformed_or_fragment"] += 1
            log.debug("unprotect: drop (%s)", e)
            return None
        if p.src != self.remote or p.dst != self.local:
            self.stats["drop_unexpected_flow"] += 1
            return None
        if not p.payload:
            self.stats["pass_empty_segment"] += 1
            return raw
        if len(p.payload) < OVERHEAD:
            self.stats["drop_short_payload"] += 1
            return None
        aad = make_aad(p)
        replay = False
        for sess in self.mgr.rx_sessions():
            try:
                plain = sess.rx.open(p.payload, aad)
            except ReplayError:
                replay = True
                continue
            except (InvalidTag, ValueError):
                continue
            self.stats["unprotected"] += 1
            return assemble(p, plain)
        self.stats["drop_replay" if replay else "drop_auth_failure"] += 1
        return None
