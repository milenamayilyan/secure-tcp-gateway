import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scgw.engine import Engine  # noqa: E402
from scgw.handshake import initiator_handshake, responder_handshake  # noqa: E402
from scgw.session import SessionManager  # noqa: E402

PC1, PC2 = "10.0.1.2", "10.0.2.2"
PSK = b"k" * 32


def do_handshake(psk_i=PSK, psk_r=PSK):
    a, b = socket.socketpair()
    out = {}

    def resp():
        try:
            out["r"] = responder_handshake(b, psk_r)
        except Exception as e:  # noqa: BLE001
            out["r_err"] = e
            b.close()

    t = threading.Thread(target=resp)
    t.start()
    try:
        out["i"] = initiator_handshake(a, psk_i)
    except Exception as e:  # noqa: BLE001
        out["i_err"] = e
        a.close()
    t.join(10)
    return out


@pytest.fixture()
def pair():
    """Two engines (Device1, Device2) sharing a freshly negotiated session."""
    out = do_handshake()
    m1, m2 = SessionManager(), SessionManager()
    m1.install(out["i"])
    m2.install(out["r"])
    d1 = Engine(m1, PC1, PC2)   # PC1 is behind Device1
    d2 = Engine(m2, PC2, PC1)   # PC2 is behind Device2
    return d1, d2
