# Design notes

## 1. Planes

| Plane   | Transport                                  | Content |
|---------|--------------------------------------------|---------|
| Control | Ordinary TCP connection Device1 -> Device2 (port 4433), terminates on the devices themselves (iptables INPUT/OUTPUT, never forwarded) | DH handshake, key confirmation, liveness |
| Data    | The original PC1<->PC2 TCP packets, modified in place by the devices | Encrypted TCP payloads |

The data plane has **no UDP encapsulation and no custom header**: IP and TCP headers stay as they were
(addresses, ports, seq, ack, flags, window, options, TTL, DF, IP-ID).

## 2. Handshake (Diffie-Hellman)

```
Device1 (initiator)                                   Device2 (responder)
  x <- random(320 bit); X = 2^x mod p
  CH = ver || N_i || X            --- CH, HMAC_psk("CH",CH) --->
                                                      verify MAC; y <- random; Y = 2^y mod p
                                  <-- SH, HMAC_psk("SH",CH,SH) -- SH = ver || N_r || Y
  verify MAC
  K = Y^x mod p                                       K = X^y mod p
  TH = SHA256(CH || SH)
  okm = HKDF-SHA256(K, salt=SHA256(N_i||N_r), info="scgw/v1/keys"||TH)
  Finished_I = HMAC(k_confirm,"I"||TH)  -------------->  verify
                                  <-------------------  Finished_R = HMAC(k_confirm,"R"||TH)
  verify  => session installed on both sides
```

* Group: RFC 3526 #14 (2048-bit MODP safe prime, g = 2). Peer values are range- and
  subgroup-checked (`2 <= y <= p-2`, `y^q mod p == 1`).
* Plain DH is unauthenticated; therefore the hellos are MAC'd with a PSK
  (`--psk-file`). `--no-auth` exists for experiments only. For production replace the PSK by
  signatures / certificates.
* HKDF output (104 B): `key_i2r(32) | key_r2i(32) | fixed_i2r(4) | fixed_r2i(4) | k_confirm(32)`.
  Each direction has its own AES-256 key.

## 3. Data-plane packet transform

```
original : IP | TCP | P                                  (P = plaintext payload)
protected: IP'| TCP'| CT || TAG(16) || CTR(8)
            IP'  : total-length + header checksum recomputed
            TCP' : checksum recomputed (everything else identical)
            CT||TAG = AES-256-GCM(key_dir, nonce, P, AAD)
            nonce   = fixed_dir(4) || CTR(8)
            AAD     = "SCGW1" || src_ip || dst_ip || sport || dport || seq
```

Overhead: 24 bytes per data segment (16 tag + 8 explicit counter).

**Why an explicit 8-byte counter?** The receiver must know the nonce. With no extra header, the only
places to carry it are the payload or fields of the IP/TCP headers. Deriving it from header fields
(seq, IP-ID) is *not* unique: TCP retransmissions repeat the sequence number (and Linux often sets
IP-ID = 0 on DF packets), which would reuse a nonce under the same key -- catastrophic for GCM.
So the counter travels as a fixed 8-byte trailer *inside* the TCP payload area, after the tag;
`CT||TAG` is exactly the AES-GCM output. If you need the strict "payload = CT||TAG only" form, the
alternative is a lock-step counter, which breaks under loss/reordering and retransmission.

### Nonce uniqueness argument
1. Key is unique per (session, direction): fresh DH + nonces + HKDF.
2. Within a (key), nonce = fixed || counter; counter is taken from a lock-protected integer that is
   incremented *before* encrypting and never decremented, so each value is used at most once -- also for
   TCP retransmissions, which are simply new packets to the gateway.
3. At 2^32 packets the direction refuses to encrypt (fail closed) and the initiator rekeys
   (earlier, at `--rekey-packets`, default 2^30, or `--rekey-seconds`).
4. Session restart => new key, so counter reuse across sessions is harmless.

### Receiver
1. Parse, check flow == (remote -> local).
2. Zero-length segments (SYN/ACK/FIN/RST) -> pass unchanged. Anything shorter than 24 B -> drop.
3. Replay window pre-check, AES-GCM verify+decrypt (AAD recomputed from headers), then commit the
   counter to the window (forged packets cannot advance it). 4096-entry sliding window tolerates reordering.
4. Rebuild packet with plaintext, new lengths/checksums, forward. Failure of any step => drop.

## 4. Rekeying
The initiator reconnects and handshakes again (age, counters, or tx exhaustion). The responder keeps
the previous session for 30 s as a receive-only fallback so packets in flight are not lost.
The control connection is held open as a liveness signal; if it breaks the initiator re-handshakes.

## 5. Kernel integration
`iptables` diverts the selected flows to NFQUEUE (`FORWARD`, no `--queue-bypass`, so it fails closed).
Also installed: `CT --notrack` for selected flows (conntrack must not see length-changing mangling)
and `TCPMSS --set-mss` (default 1400) so payload + 24 B still fits a 1500-byte MTU.
NIC offloads GRO/LRO/GSO/TSO are disabled so the gateway sees real wire packets.

## 6. Limitations / non-goals
* IPv4 + TCP only. IPv6, UDP, ICMP are out of scope. IP fragments of selected flows are dropped.
* Headers are not encrypted (by requirement) -- IPs, ports, seq/ack, flags, lengths are visible and
  seq/ack/flags/window are *not* authenticated (only src/dst/ports/seq are in the AAD). An on-path
  attacker can still inject/alter bare ACK/RST/FIN segments or drop packets. Payload confidentiality
  and integrity are what is protected.
* Payload length leaks (GCM is length-preserving).
* PSK authentication is symmetric; a compromised device exposes the PSK.
* Pure-Python data path: tens of Mbit/s, not line rate. Use C + libnetfilter_queue / XDP for speed.
* Python `pow()` DH is not constant-time. Prefer X25519 in a hardened build.
* Packets that arrive on the LAN interface from spoofed sources are dropped by the engine's flow check.
