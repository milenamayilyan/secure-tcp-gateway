"""Control-plane threads: session establishment, keep-alive and rekeying."""
from __future__ import annotations

import logging
import socket
import threading
from typing import Callable, Optional

from .crypto import DEFAULT_REKEY_PACKETS
from .handshake import HandshakeError, initiator_handshake, responder_handshake
from .session import Session, SessionManager

log = logging.getLogger("scgw.control")


def load_psk(path: str) -> bytes:
    data = open(path, "rb").read().strip()
    try:
        key = bytes.fromhex(data.decode())
    except (ValueError, UnicodeDecodeError):
        key = data
    if len(key) < 16:
        raise ValueError("PSK must be at least 16 bytes (use: openssl rand -hex 32)")
    return key


class Initiator(threading.Thread):
    """Connects to the peer, handshakes, holds the connection open, rekeys on demand."""

    def __init__(self, mgr: SessionManager, peer: str, port: int, psk: Optional[bytes],
                 stop: threading.Event, rekey_seconds: float = 3600.0,
                 rekey_packets: int = DEFAULT_REKEY_PACKETS,
                 force_rekey: Optional[Callable[[], bool]] = None) -> None:
        super().__init__(name="scgw-initiator", daemon=True)
        self.mgr, self.peer, self.port, self.psk, self.stop = mgr, peer, port, psk, stop
        self.rekey_seconds, self.rekey_packets = rekey_seconds, rekey_packets
        self.force_rekey = force_rekey or (lambda: False)

    def _needs_rekey(self, s: Session) -> bool:
        forced = self.force_rekey()
        return (forced or s.age() > self.rekey_seconds or s.tx.count > self.rekey_packets
                or s.rx.highest > self.rekey_packets)

    def run(self) -> None:
        backoff = 1.0
        while not self.stop.is_set():
            try:
                with socket.create_connection((self.peer, self.port), timeout=10) as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    sess = initiator_handshake(sock, self.psk, max_age=self.rekey_seconds * 2)
                    self.mgr.install(sess)
                    log.info("session %s established (initiator)", sess.id)
                    backoff = 1.0
                    self._hold(sock, sess)
                if self.stop.is_set():
                    break
                continue  # rekey: reconnect immediately
            except (OSError, HandshakeError) as e:
                log.warning("handshake with %s:%d failed: %s", self.peer, self.port, e)
            self.stop.wait(backoff)
            backoff = min(backoff * 2, 30.0)

    def _hold(self, sock: socket.socket, sess: Session) -> None:
        sock.settimeout(1.0)
        while not self.stop.is_set():
            try:
                if sock.recv(1) == b"":
                    log.warning("control connection closed by peer; re-handshaking")
                    return
            except socket.timeout:
                pass
            except OSError:
                return
            if self._needs_rekey(sess):
                log.info("rekeying session %s", sess.id)
                return


class Responder(threading.Thread):
    """Listens for the initiator's handshake and installs the resulting session."""

    def __init__(self, mgr: SessionManager, listen: str, port: int, psk: Optional[bytes],
                 allowed_peer: Optional[str], stop: threading.Event,
                 max_age: float = 7200.0) -> None:
        super().__init__(name="scgw-responder", daemon=True)
        self.mgr, self.listen, self.port, self.psk = mgr, listen, port, psk
        self.allowed_peer, self.stop, self.max_age = allowed_peer, stop, max_age

    def run(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.listen, self.port))
        srv.listen(4)
        srv.settimeout(1.0)
        log.info("control channel listening on %s:%d", self.listen, self.port)
        while not self.stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self.allowed_peer and addr[0] != self.allowed_peer:
                log.warning("rejecting control connection from %s", addr[0])
                conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()
        srv.close()

    def _serve(self, conn: socket.socket) -> None:
        with conn:
            try:
                conn.settimeout(10)
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                sess = responder_handshake(conn, self.psk, self.max_age)
                self.mgr.install(sess)
                log.info("session %s established (responder)", sess.id)
                conn.settimeout(None)
                while conn.recv(1):  # hold until the initiator closes
                    pass
            except (OSError, HandshakeError) as e:
                log.warning("handshake failed: %s", e)
