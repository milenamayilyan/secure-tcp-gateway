import struct

import pytest
from conftest import PC1, PC2
from scgw.crypto import OVERHEAD
from scgw.packet import build_tcp_packet, checksums_ok, parse
from scgw.session import SessionManager
from scgw.engine import Engine


def pkt(payload, seq=1000, src=PC1, dst=PC2, sport=40000, dport=8080, **kw):
    return build_tcp_packet(src, dst, sport, dport, seq=seq, payload=payload, **kw)


def test_roundtrip_restores_original_exactly(pair):
    d1, d2 = pair
    for size in (1, 15, 16, 17, 100, 1400):
        orig = pkt(b"A" * size, seq=size)
        wire = d1.protect(orig)
        assert wire is not None and wire != orig
        assert checksums_ok(wire)                              # D1 output checksums valid
        w, o = parse(wire), parse(orig)
        assert len(w.payload) == len(o.payload) + OVERHEAD     # CT + tag + counter
        assert w.ip_hdr[12:20] == o.ip_hdr[12:20]              # addresses preserved
        assert w.tcp_hdr[:16] == o.tcp_hdr[:16]                # ports/seq/ack preserved
        assert w.tcp_hdr[18:] == o.tcp_hdr[18:]
        assert o.payload not in w.payload                      # actually encrypted
        back = d2.unprotect(wire)
        assert back == orig                                    # byte-identical, checksums fixed
        assert checksums_ok(back)


def test_reverse_direction(pair):
    d1, d2 = pair
    orig = pkt(b"response data", src=PC2, dst=PC1, sport=8080, dport=40000)
    assert d1.unprotect(d2.protect(orig)) == orig



def test_tcp_options_preserved(pair):
    d1, d2 = pair
    base = bytearray(pkt(b"hi there"))
    opts = b"\x01\x01\x08\x0a" + struct.pack("!II", 11, 22)          # NOP NOP TIMESTAMP
    ihl = 20
    tcp = bytearray(base[ihl:ihl + 20]); tcp[12] = (8 << 4)
    raw = bytes(base[:ihl]) + bytes(tcp) + opts + b"hi there"
    raw = bytearray(raw); struct.pack_into("!H", raw, 2, len(raw))
    from scgw.packet import assemble
    p = parse(bytes(raw)); raw = assemble(p, p.payload)
    assert parse(raw).tcp_hdr[20:] == opts
    wire = d1.protect(raw)
    assert parse(wire).tcp_hdr[20:] == opts
    assert d2.unprotect(wire) == raw


def test_empty_segments_pass_untouched(pair):
    d1, d2 = pair
    syn = pkt(b"", flags=0x02)
    assert d1.protect(syn) == syn and d2.unprotect(syn) == syn


def test_tampering_any_payload_byte_is_dropped(pair):
    d1, d2 = pair
    wire = d1.protect(pkt(b"confidential"))
    p = parse(wire)
    from scgw.packet import assemble
    for i in range(len(p.payload)):
        bad = bytearray(p.payload); bad[i] ^= 0x80
        assert d2.unprotect(assemble(p, bytes(bad))) is None
    assert d2.unprotect(wire) is not None       # good packet still accepted afterwards


def test_replay_dropped(pair):
    d1, d2 = pair
    wire = d1.protect(pkt(b"once"))
    assert d2.unprotect(wire) is not None
    assert d2.unprotect(wire) is None
    assert d2.stats["drop_replay"] == 1


def test_splice_into_other_flow_or_seq_dropped(pair):
    d1, d2 = pair
    from scgw.packet import assemble
    p = parse(d1.protect(pkt(b"data", seq=500)))
    for hdr_edit in (lambda t: struct.pack_into("!I", t, 4, 501),       # other seq
                     lambda t: struct.pack_into("!H", t, 2, 9999)):    # other dport
        tcp = bytearray(p.tcp_hdr); hdr_edit(tcp)
        from scgw.packet import TcpPacket
        forged = assemble(TcpPacket(p.ip_hdr, bytes(tcp), b""), p.payload)
        assert d2.unprotect(forged) is None


def test_plaintext_data_from_peer_side_is_rejected(pair):
    _, d2 = pair
    assert d2.unprotect(pkt(b"x" * 100)) is None           # unprotected data injected on wire
    assert d2.unprotect(pkt(b"short")) is None             # shorter than overhead


def test_fail_closed_without_session():
    e = Engine(SessionManager(), PC1, PC2)
    assert e.protect(pkt(b"leak?")) is None
    assert e.stats["drop_no_session"] == 1


def test_wrong_flow_and_fragments_dropped(pair):
    d1, _ = pair
    assert d1.protect(pkt(b"x", src="10.9.9.9")) is None
    frag = bytearray(pkt(b"x")); frag[6] |= 0x20
    assert d1.protect(bytes(frag)) is None


def test_unique_nonce_for_every_packet_including_retransmissions(pair):
    d1, _ = pair
    same = pkt(b"retransmitted segment", seq=777)
    nonces = [parse(d1.protect(same)).payload[-8:] for _ in range(2000)]
    assert len(set(nonces)) == 2000
    ciphertexts = {parse(d1.protect(same)).payload for _ in range(50)}
    assert len(ciphertexts) == 50                      # same plaintext -> different ciphertext


def test_exhausted_nonce_space_drops_and_requests_rekey(pair):
    d1, _ = pair
    d1.mgr.current().tx._limit = 2
    assert d1.protect(pkt(b"1")) and d1.protect(pkt(b"2"))
    assert d1.protect(pkt(b"3")) is None
    assert d1.take_rekey_request() is True and d1.take_rekey_request() is False


def test_stale_session_still_decrypts_during_rekey_grace(pair):
    d1, d2 = pair
    from conftest import do_handshake
    wire = d1.protect(pkt(b"in flight during rekey"))
    new = do_handshake()
    d2.mgr.install(new["r"])                           # responder switched to a new session
    assert d2.unprotect(wire) is not None              # old session kept for a grace period
