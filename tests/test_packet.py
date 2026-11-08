import pytest
from scgw.packet import Fragmented, NotTcp, PacketError, build_tcp_packet, checksums_ok, parse


def test_build_and_parse_roundtrip():
    raw = build_tcp_packet("10.0.1.2", "10.0.2.2", 40000, 8080, seq=1234, payload=b"hello")
    assert checksums_ok(raw)
    p = parse(raw)
    assert (p.sport, p.dport, p.seq, p.payload) == (40000, 8080, 1234, b"hello")


def test_odd_length_payload_checksum():
    assert checksums_ok(build_tcp_packet("1.1.1.1", "2.2.2.2", 1, 2, payload=b"abc"))


def test_rejects_non_tcp_and_fragments_and_garbage():
    raw = bytearray(build_tcp_packet("1.1.1.1", "2.2.2.2", 1, 2, payload=b"x"))
    udp = bytearray(raw); udp[9] = 17
    with pytest.raises(NotTcp):
        parse(bytes(udp))
    frag = bytearray(raw); frag[6] |= 0x20
    with pytest.raises(Fragmented):
        parse(bytes(frag))
    with pytest.raises(PacketError):
        parse(b"\x45\x00")
    v6 = bytearray(raw); v6[0] = 0x65
    with pytest.raises(PacketError):
        parse(bytes(v6))


def test_trailing_padding_is_stripped():
    raw = build_tcp_packet("1.1.1.1", "2.2.2.2", 1, 2, payload=b"x") + b"\x00" * 6
    assert parse(raw).payload == b"x"
