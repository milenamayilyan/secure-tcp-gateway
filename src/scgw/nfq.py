"""NFQUEUE glue: feeds raw packets from the kernel to the Engine."""
from __future__ import annotations

import logging
import selectors
import socket
import threading
from typing import Callable, Optional

from .engine import Engine

log = logging.getLogger("scgw.nfq")


def _callback(fn: Callable[[bytes], Optional[bytes]]):
    def cb(pkt) -> None:
        raw = pkt.get_payload()
        try:
            out = fn(raw)
        except Exception:  # never let an exception leak a plaintext packet
            log.exception("unhandled error; dropping packet")
            out = None
        if out is None:
            pkt.drop()
            return
        if out is not raw:
            pkt.set_payload(out)
        pkt.accept()
    return cb


def run(engine: Engine, queue_protect: int, queue_unprotect: int, stop: threading.Event,
        stats_interval: float = 0.0) -> None:
    from netfilterqueue import NetfilterQueue  # imported lazily (Linux only)

    sel = selectors.DefaultSelector()
    queues = []
    for num, fn in ((queue_protect, engine.protect), (queue_unprotect, engine.unprotect)):
        q = NetfilterQueue()
        q.bind(num, _callback(fn))
        sock = socket.fromfd(q.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        sel.register(sock, selectors.EVENT_READ, q)
        queues.append(q)
        log.info("bound NFQUEUE %d", num)

    last = 0.0
    import time
    try:
        while not stop.is_set():
            for key, _ in sel.select(timeout=1.0):
                key.data.run_socket(key.fileobj)
            now = time.monotonic()
            if stats_interval and now - last >= stats_interval:
                last = now
                log.info("stats: %s", dict(engine.stats))
    finally:
        for q in queues:
            q.unbind()
        log.info("final stats: %s", dict(engine.stats))
