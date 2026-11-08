"""Minimal IPv4/TCP parsing and checksum helpers (pure Python, no scapy).

Only what the gateway needs: split a raw IPv4 packet into (IP header,
TCP header, payload), and re-assemble it with a corrected IP total length,
IP header checksum and TCP checksum.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass


class PacketError(ValueError):
    """Packet is malformed or unsupported."""


class NotTcp(PacketError):
    pass


class Fragmented(PacketError):
    pass


def checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum."""
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


@dataclass(frozen=True)
class TcpPacket:
    ip_hdr: bytes
    tcp_hdr: bytes
    payload: bytes

    @property
    def src(self) -> bytes:
        return self.ip_hdr[12:16]

    @property
    def dst(self) -> bytes:
        return self.ip_hdr[16:20]

    @property
    def sport(self) -> int:
        return struct.unpack_from("!H", self.tcp_hdr, 0)[0]

    @property
    def dport(self) -> int:
        return struct.unpack_from("!H", self.tcp_hdr, 2)[0]

    @property
    def seq(self) -> int:
        return struct.unpack_from("!I", self.tcp_hdr, 4)[0]

    @property
    def flags(self) -> int:
        return self.tcp_hdr[13]


def parse(raw: bytes) -> TcpPacket:
    """Parse an IPv4/TCP packet. Raises PacketError (or subclass) otherwise."""
    if len(raw) < 20:
        raise PacketError("short packet")
    if raw[0] >> 4 != 4:
        raise PacketError("not IPv4")
    ihl = (raw[0] & 0x0F) * 4
    if ihl < 20 or len(raw) < ihl:
        raise PacketError("bad IHL")
    total = struct.unpack_from("!H", raw, 2)[0]
    if total < ihl + 20 or total > len(raw):
        raise PacketError("bad total length")
    if raw[9] != 6:
        raise NotTcp("not TCP")
    if struct.unpack_from("!H", raw, 6)[0] & 0x3FFF:  # MF flag or frag offset
        raise Fragmented("IP fragment")
    raw = raw[:total]  # strip any link-layer padding
    doff = (raw[ihl + 12] >> 4) * 4
    if doff < 20 or ihl + doff > total:
        raise PacketError("bad TCP data offset")
    return TcpPacket(raw[:ihl], raw[ihl : ihl + doff], raw[ihl + doff :])


def assemble(pkt: TcpPacket, new_payload: bytes) -> bytes:
    """Rebuild `pkt` carrying `new_payload`; fix IP length + both checksums."""
    ip = bytearray(pkt.ip_hdr)
    tcp = bytearray(pkt.tcp_hdr)
    total = len(ip) + len(tcp) + len(new_payload)
    if total > 0xFFFF:
        raise PacketError("resulting packet exceeds 65535 bytes")
    struct.pack_into("!H", ip, 2, total)
    struct.pack_into("!H", ip, 10, 0)
    struct.pack_into("!H", ip, 10, checksum(bytes(ip)))
    struct.pack_into("!H", tcp, 16, 0)
    pseudo = bytes(ip[12:20]) + struct.pack("!BBH", 0, 6, len(tcp) + len(new_payload))
    struct.pack_into("!H", tcp, 16, checksum(pseudo + bytes(tcp) + new_payload))
    return bytes(ip) + bytes(tcp) + new_payload


def checksums_ok(raw: bytes) -> bool:
    """True if both the IP header and TCP checksums verify."""
    p = parse(raw)
    if checksum(p.ip_hdr) != 0:
        return False
    pseudo = p.src + p.dst + struct.pack("!BBH", 0, 6, len(p.tcp_hdr) + len(p.payload))
    return checksum(pseudo + p.tcp_hdr + p.payload) == 0


def build_tcp_packet(src: str, dst: str, sport: int, dport: int, seq: int = 1,
                     ack: int = 0, flags: int = 0x18, payload: bytes = b"",
                     ident: int = 1, ttl: int = 63) -> bytes:
    """Build a valid IPv4/TCP packet (20-byte headers, DF set). Test helper."""
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 20 + len(payload), ident, 0x4000,
                     ttl, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return assemble(TcpPacket(ip, tcp, b""), payload)
