from conftest import PSK, do_handshake


def test_both_sides_derive_matching_directional_keys():
    out = do_handshake()
    i, r = out["i"], out["r"]
    assert i.id == r.id
    blob = i.tx.seal(b"from-initiator", b"a")
    assert r.rx.open(blob, b"a") == b"from-initiator"
    blob = r.tx.seal(b"from-responder", b"a")
    assert i.rx.open(blob, b"a") == b"from-responder"


def test_wrong_psk_rejected():
    out = do_handshake(psk_i=PSK, psk_r=b"x" * 32)
    assert "r_err" in out and "i" not in out


def test_unauthenticated_peer_rejected_when_psk_required():
    out = do_handshake(psk_i=None, psk_r=PSK)
    assert "r_err" in out


def test_every_handshake_yields_fresh_session():
    a, b = do_handshake()["i"], do_handshake()["i"]
    assert a.id != b.id
