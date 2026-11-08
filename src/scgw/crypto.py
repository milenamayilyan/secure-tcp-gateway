"""Crypto primitives: DH group, key schedule, AES-GCM tx/rx state, replay window.

Nonce construction (96 bit)
---------------------------
    nonce = fixed(4 bytes, HKDF-derived, per direction) || counter(8 bytes, big endian)

* Every (session, direction) has its OWN AES-256 key (HKDF), so the two
  directions can never collide even though both start counting at 0.
* The counter is a strictly increasing per-direction integer, incremented
  under a lock *before* encryption.  A counter value is never handed out twice,
  even when encryption fails or the packet is later dropped.
* When the counter reaches HARD_LIMIT the direction refuses to encrypt
  (fail closed) until a new session (fresh DH, fresh keys) is installed.
* A new session always has a fresh key, so restarting the counter at 0 can
  never repeat a (key, nonce) pair.
"""
from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag  # re-exported
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = ["InvalidTag", "DHKeyPair", "derive_keys", "TxState", "RxState",
           "ReplayWindow", "ReplayError", "SessionExhausted", "OVERHEAD"]

# RFC 3526 group 14: 2048-bit MODP safe prime, generator 2.
_P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05
98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB
9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
"""
P = int("".join(_P_HEX.split()), 16)
G = 2
Q = (P - 1) // 2
PUB_LEN = 256

TAG_LEN = 16
COUNTER_LEN = 8                       # explicit 64-bit nonce counter after the tag
OVERHEAD = TAG_LEN + COUNTER_LEN      # bytes added to every protected payload
HARD_LIMIT = 2 ** 32                  # max packets per direction per session
DEFAULT_REKEY_PACKETS = 2 ** 30

PRIVATE_BITS = 320   # RFC 7919 recommends >= 2*security-level bits for ffdhe2048


class ReplayError(Exception):
    pass


class SessionExhausted(Exception):
    pass


class DHKeyPair:
    """Ephemeral finite-field Diffie-Hellman key pair (RFC 3526 group 14).

    Implemented with Python big-int arithmetic (the `cryptography` package is
    deprecating its FFDH API).  Keys are ephemeral, one per handshake.
    NOTE: Python's pow() is not constant-time; for production use a hardened
    library or an ECDH group (X25519) instead.
    """

    def __init__(self) -> None:
        self._x = 0
        while self._x < 2:
            self._x = secrets.randbits(PRIVATE_BITS)
        self.public: int = pow(G, self._x, P)

    def public_bytes(self) -> bytes:
        return self.public.to_bytes(PUB_LEN, "big")

    def exchange(self, peer_public: bytes) -> bytes:
        if len(peer_public) != PUB_LEN:
            raise ValueError("bad DH public value length")
        y = int.from_bytes(peer_public, "big")
        # Reject 0, 1, p-1 and anything outside the prime-order subgroup.
        if not (2 <= y <= P - 2) or pow(y, Q, P) != 1:
            raise ValueError("invalid DH public value")
        return pow(y, self._x, P).to_bytes(PUB_LEN, "big")


@dataclass(frozen=True)
class KeyMaterial:
    key_i2r: bytes
    key_r2i: bytes
    fixed_i2r: bytes
    fixed_r2i: bytes
    confirm_key: bytes


def derive_keys(shared: bytes, nonce_i: bytes, nonce_r: bytes, transcript_hash: bytes) -> KeyMaterial:
    """HKDF-SHA256 key schedule. The transcript hash binds keys to the handshake."""
    salt = hashlib.sha256(nonce_i + nonce_r).digest()
    okm = HKDF(algorithm=hashes.SHA256(), length=32 + 32 + 4 + 4 + 32, salt=salt,
               info=b"scgw/v1/keys" + transcript_hash).derive(shared)
    return KeyMaterial(okm[0:32], okm[32:64], okm[64:68], okm[68:72], okm[72:104])


class TxState:
    """Encrypting half of a session direction."""

    def __init__(self, key: bytes, fixed: bytes, limit: int = HARD_LIMIT) -> None:
        self._aead = AESGCM(key)
        self._fixed = fixed
        self._limit = limit
        self._ctr = 0
        self._lock = threading.Lock()

    @property
    def count(self) -> int:
        return self._ctr

    def seal(self, plaintext: bytes, aad: bytes) -> bytes:
        """Return ciphertext || tag(16) || counter(8)."""
        with self._lock:
            if self._ctr >= self._limit:
                raise SessionExhausted("nonce space exhausted; rekey required")
            ctr = self._ctr
            self._ctr += 1          # consumed even if encryption fails below
        ctr_bytes = ctr.to_bytes(8, "big")
        return self._aead.encrypt(self._fixed + ctr_bytes, plaintext, aad) + ctr_bytes


class ReplayWindow:
    """Sliding-window anti-replay (bit i set => counter top-i already accepted)."""

    def __init__(self, size: int = 4096) -> None:
        self.size = size
        self.top = -1
        self.bits = 0

    def check(self, ctr: int) -> bool:
        if ctr > self.top:
            return True
        d = self.top - ctr
        return d < self.size and not (self.bits >> d) & 1

    def commit(self, ctr: int) -> None:
        if ctr > self.top:
            shift = ctr - self.top
            self.bits = 1 if shift >= self.size else ((self.bits << shift) | 1) & ((1 << self.size) - 1)
            self.top = ctr
        else:
            self.bits |= 1 << (self.top - ctr)


class RxState:
    """Decrypting half of a session direction."""

    def __init__(self, key: bytes, fixed: bytes, window: int = 4096) -> None:
        self._aead = AESGCM(key)
        self._fixed = fixed
        self._win = ReplayWindow(window)
        self._lock = threading.Lock()

    @property
    def highest(self) -> int:
        return self._win.top

    def open(self, blob: bytes, aad: bytes) -> bytes:
        """Verify tag + decrypt `ciphertext||tag||counter`.

        Raises InvalidTag / ReplayError / ValueError. The replay window is
        only advanced after the tag verified, so forged packets cannot move it.
        """
        if len(blob) < OVERHEAD:
            raise ValueError("protected payload too short")
        ctr = int.from_bytes(blob[-8:], "big")
        if ctr >= HARD_LIMIT:
            raise ReplayError("counter beyond hard limit")
        with self._lock:
            if not self._win.check(ctr):
                raise ReplayError("replayed or too-old counter")
        plaintext = self._aead.decrypt(self._fixed + blob[-8:], blob[:-8], aad)
        with self._lock:
            if not self._win.check(ctr):
                raise ReplayError("replayed counter")
            self._win.commit(ctr)
        return plaintext
