"""scgw command line entry point."""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading

from . import __version__
from .control import Initiator, Responder, load_psk
from .crypto import DEFAULT_REKEY_PACKETS
from .engine import Engine
from .session import SessionManager


def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="scgw", description=__doc__)
    ap.add_argument("--role", required=True, choices=["initiator", "responder"],
                    help="initiator = Device1 (opens control connection); responder = Device2")
    ap.add_argument("--local-host", required=True, help="IP of the protected host behind THIS device")
    ap.add_argument("--remote-host", required=True, help="IP of the protected host behind the PEER device")
    ap.add_argument("--peer-addr", required=True, help="peer device IP (initiator connects to it; responder only accepts it)")
    ap.add_argument("--listen-addr", default="0.0.0.0", help="responder bind address")
    ap.add_argument("--control-port", type=int, default=4433)
    ap.add_argument("--psk-file", help="pre-shared key authenticating the DH handshake")
    ap.add_argument("--no-auth", action="store_true",
                    help="UNSAFE: plain unauthenticated DH (vulnerable to active MITM)")
    ap.add_argument("--queue-protect", type=int, default=0)
    ap.add_argument("--queue-unprotect", type=int, default=1)
    ap.add_argument("--rekey-seconds", type=float, default=3600.0)
    ap.add_argument("--rekey-packets", type=int, default=DEFAULT_REKEY_PACKETS)
    ap.add_argument("--stats-interval", type=float, default=0.0)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    if not a.psk_file and not a.no_auth:
        ap.error("--psk-file is required (or pass --no-auth to accept the MITM risk)")
    return a


def main(argv=None) -> int:
    a = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("scgw")
    if os.geteuid() != 0:
        log.error("must run as root (NFQUEUE + raw packet handling)")
        return 1
    psk = None if a.no_auth else load_psk(a.psk_file)
    if psk is None:
        log.warning("running WITHOUT handshake authentication: active MITM possible")

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    mgr = SessionManager()
    engine = Engine(mgr, a.local_host, a.remote_host)
    if a.role == "initiator":
        ctl = Initiator(mgr, a.peer_addr, a.control_port, psk, stop, a.rekey_seconds,
                        a.rekey_packets, force_rekey=engine.take_rekey_request)
    else:
        ctl = Responder(mgr, a.listen_addr, a.control_port, psk, a.peer_addr, stop,
                        max_age=a.rekey_seconds * 2)
    ctl.start()

    from . import nfq
    nfq.run(engine, a.queue_protect, a.queue_unprotect, stop, a.stats_interval)
    stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
