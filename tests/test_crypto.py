import random
import threading

import pytest
from scgw import crypto
from scgw.crypto import (OVERHEAD, DHKeyPair, InvalidTag, ReplayError, ReplayWindow,
                         RxState, SessionExhausted, TxState)


def _is_probable_prime(n, rounds=6):
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2; s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def test_dh_group_is_2048bit_safe_prime():
    assert crypto.P.bit_length() == 2048
    assert _is_probable_prime(crypto.P) and _is_probable_prime(crypto.Q)


def test_dh_agreement_and_validation():
    a, b = DHKeyPair(), DHKeyPair()
    assert a.exchange(b.public_bytes()) == b.exchange(a.public_bytes())
    for bad in (0, 1, crypto.P - 1, crypto.P, 2 ** 2048 - 1):
        with pytest.raises(ValueError):
            a.exchange(bad.to_bytes(256, "big"))
    with pytest.raises(ValueError):
        a.exchange(b"short")


def test_seal_open_and_layout():
    tx, rx = TxState(b"k" * 32, b"abcd"), RxState(b"k" * 32, b"abcd")
    blob = tx.seal(b"payload", b"aad")
    assert len(blob) == len(b"payload") + OVERHEAD
    assert rx.open(blob, b"aad") == b"payload"


def test_nonce_counter_never_repeats_and_is_sequential():
    tx = TxState(b"k" * 32, b"abcd")
    ctrs = [int.from_bytes(tx.seal(b"x", b"")[-8:], "big") for _ in range(5000)]
    assert ctrs == list(range(5000))


def test_nonce_unique_across_threads():
    tx = TxState(b"k" * 32, b"abcd")
    seen, lock = [], threading.Lock()

    def work():
        local = [tx.seal(b"x", b"")[-8:] for _ in range(500)]
        with lock:
            seen.extend(local)

    ts = [threading.Thread(target=work) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert len(seen) == len(set(seen)) == 4000


def test_exhaustion_fails_closed():
    tx = TxState(b"k" * 32, b"abcd", limit=3)
    for _ in range(3):
        tx.seal(b"x", b"")
    with pytest.raises(SessionExhausted):
        tx.seal(b"x", b"")


def test_tamper_replay_and_aad():
    tx, rx = TxState(b"k" * 32, b"abcd"), RxState(b"k" * 32, b"abcd")
    blob = tx.seal(b"secret", b"aad")
    for i in range(len(blob)):               # flip every single byte -> must fail
        bad = bytearray(blob); bad[i] ^= 1
        with pytest.raises((InvalidTag, ReplayError, ValueError)):
            rx.open(bytes(bad), b"aad")
    with pytest.raises(InvalidTag):
        rx.open(blob, b"other-aad")
    assert rx.open(blob, b"aad") == b"secret"   # forged attempts did not poison state
    with pytest.raises(ReplayError):
        rx.open(blob, b"aad")


def test_replay_window_reordering():
    w = ReplayWindow(64)
    for c in (5, 3, 4, 10):
        assert w.check(c); w.commit(c)
    assert not w.check(4) and not w.check(10)
    assert w.check(9)
    w.commit(200)
    assert not w.check(100)          # too old
    w.commit(2 ** 40)                # huge jump must not blow up memory
    assert not w.check(2 ** 40)
