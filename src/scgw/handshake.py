"""Handshake on a dedicated TCP control connection between Device1 and Device2.

    I -> R : ClientHello  = ver || nonce_i(32) || DH_pub_i(256)         [+ HMAC_psk]
    R -> I : ServerHello  = ver || nonce_r(32) || DH_pub_r(256)         [+ HMAC_psk over CH||SH]
    I -> R : Finished_I   = HMAC(confirm_key, "I" || H(CH||SH))
    R -> I : Finished_R   = HMAC(confirm_key, "R" || H(CH||SH))

Raw unauthenticated DH is vulnerable to an active man-in-the-middle, so the
hello messages are authenticated with a pre-shared key (PSK) by default.
Pass psk=None only for experiments.  Session keys come from HKDF over the DH
shared secret, salted with both nonces and bound to the transcript hash.
The data plane never uses this protocol: protected packets carry no header.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
from typing import Optional

from .crypto import PUB_LEN, DHKeyPair, derive_keys
from .session import Session

VERSION = 1
HELLO_LEN = 1 + 32 + PUB_LEN
MAX_FRAME = 16384


class HandshakeError(Exception):
    pass


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise HandshakeError("connection closed during handshake")
        buf += chunk
    return buf


def _send(sock, obj: dict) -> None:
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack("!I", len(data)) + data)


def _recv(sock, expect: str) -> dict:
    (n,) = struct.unpack("!I", _recv_exact(sock, 4))
    if n > MAX_FRAME:
        raise HandshakeError("oversized frame")
    try:
        msg = json.loads(_recv_exact(sock, n))
    except ValueError as e:
        raise HandshakeError("bad frame") from e
    if not isinstance(msg, dict) or msg.get("type") != expect:
        raise HandshakeError("unexpected message, wanted %s" % expect)
    return msg


def _mac(key: bytes, label: bytes, *parts: bytes) -> bytes:
    h = hmac.new(key, label, hashlib.sha256)
    for p in parts:
        h.update(struct.pack("!I", len(p)))
        h.update(p)
    return h.digest()


def _hex(msg: dict, field: str) -> bytes:
    try:
        return bytes.fromhex(msg[field])
    except (KeyError, ValueError, TypeError) as e:
        raise HandshakeError("bad field %s" % field) from e


def _check_hello(body: bytes) -> None:
    if len(body) != HELLO_LEN or body[0] != VERSION:
        raise HandshakeError("bad hello (length/version)")


def _verify(expected: bytes, got: bytes, what: str) -> None:
    if not hmac.compare_digest(expected, got):
        raise HandshakeError("%s verification failed" % what)


def initiator_handshake(sock, psk: Optional[bytes], max_age: float = 7200.0) -> Session:
    kp = DHKeyPair()
    n_i = os.urandom(32)
    ch = bytes([VERSION]) + n_i + kp.public_bytes()
    _send(sock, {"type": "client_hello", "body": ch.hex(),
                 "mac": _mac(psk, b"CH", ch).hex() if psk else ""})

    m = _recv(sock, "server_hello")
    sh = _hex(m, "body")
    _check_hello(sh)
    if psk:
        _verify(_mac(psk, b"SH", ch, sh), _hex(m, "mac"), "server_hello MAC")
    try:
        shared = kp.exchange(sh[33:])
    except ValueError as e:
        raise HandshakeError(str(e)) from e
    th = hashlib.sha256(ch + sh).digest()
    km = derive_keys(shared, n_i, sh[1:33], th)

    _send(sock, {"type": "finished", "mac": _mac(km.confirm_key, b"I", th).hex()})
    fin = _recv(sock, "finished")
    _verify(_mac(km.confirm_key, b"R", th), _hex(fin, "mac"), "finished")
    return Session("initiator", km, th, max_age)


def responder_handshake(sock, psk: Optional[bytes], max_age: float = 7200.0) -> Session:
    m = _recv(sock, "client_hello")
    ch = _hex(m, "body")
    _check_hello(ch)
    if psk:
        _verify(_mac(psk, b"CH", ch), _hex(m, "mac"), "client_hello MAC")

    kp = DHKeyPair()
    n_r = os.urandom(32)
    sh = bytes([VERSION]) + n_r + kp.public_bytes()
    _send(sock, {"type": "server_hello", "body": sh.hex(),
                 "mac": _mac(psk, b"SH", ch, sh).hex() if psk else ""})
    try:
        shared = kp.exchange(ch[33:])
    except ValueError as e:
        raise HandshakeError(str(e)) from e
    th = hashlib.sha256(ch + sh).digest()
    km = derive_keys(shared, ch[1:33], n_r, th)

    fin = _recv(sock, "finished")
    _verify(_mac(km.confirm_key, b"I", th), _hex(fin, "mac"), "finished")
    _send(sock, {"type": "finished", "mac": _mac(km.confirm_key, b"R", th).hex()})
    return Session("responder", km, th, max_age)
