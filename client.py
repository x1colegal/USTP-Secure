import argparse
import errno
import ipaddress
import json
import os
import socket
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from packet import TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, mkp
from ustp import USTPReceiver, parse_packet
from aead_udp import AEADDatagramSocket, normalize_cipher_name


HELLO_PREFIX = b"USTPS-KEX1\0"
CHALLENGE_PREFIX = b"USTPS-CHALLENGE1\0"
RESPONSE_PREFIX = b"USTPS-CHALLENGE-REPLY1\0"
RESUME_PREFIX = b"USTPS-RESUME1\0"
SESSION_PREFIX = b"USTPS-SESSION1\0"
UDP_BUFFER_BYTES = 4 * 1024 * 1024


def public_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def derive_session_key(shared: bytes, client_pub: bytes, server_pub: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=client_pub + server_pub,
        info=b"USTPS-X25519-session-v1",
    ).derive(shared)


def encode_transport_hello(client_pub: bytes, cipher: str, cc_mode: str, cleartext_mode: str, prefix: bytes) -> bytes:
    return (
        prefix
        + client_pub
        + cipher.encode("ascii")
        + b"\0cc="
        + cc_mode.encode("ascii")
        + b"\0ct="
        + cleartext_mode.encode("ascii")
    )


def parse_hello_options(raw: bytes) -> tuple[str | None, str | None, str | None]:
    if not raw:
        return None, None, None
    try:
        text = raw.decode("ascii", "replace")
    except Exception:
        return None, None, None
    parts = text.split("\0")
    cipher_text = parts[0] if parts else ""
    cipher = None
    if cipher_text:
        try:
            cipher = normalize_cipher_name(cipher_text)
        except Exception:
            cipher = None
    cc_mode = None
    cleartext_mode = None
    for part in parts[1:]:
        if part.startswith("cc="):
            value = part[3:].strip().lower()
            if value in {"on", "off"}:
                cc_mode = value
        elif part.startswith("ct="):
            value = part[3:].strip().lower()
            if value in {"on", "off"}:
                cleartext_mode = value
    return cipher, cc_mode, cleartext_mode


def load_tofu(path: str) -> dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}
    return {}


def save_tofu(path: str, data: dict[str, str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def confirm_regen(peer_label: str) -> bool:
    if not os.isatty(0):
        return False
    answer = input(f"TOFU key changed for {peer_label}. Accept and replace stored key? [y/N] ").strip().lower()
    return answer in ("y", "yes")


def check_tofu(path: str, peer_label: str, server_pub: bytes, allow_regen: bool = False) -> None:
    db = load_tofu(path)
    fp = server_pub.hex()
    known = db.get(peer_label)
    if known is None:
        db[peer_label] = fp
        save_tofu(path, db)
        print(f"[USTP-CLIENT] TOFU trust established for {peer_label}")
        return
    if known != fp:
        if allow_regen and confirm_regen(peer_label):
            db[peer_label] = fp
            save_tofu(path, db)
            print(f"[USTP-CLIENT] TOFU key replaced for {peer_label}")
            return
        raise SystemExit(f"TOFU mismatch for {peer_label}: possible MITM or server key change")


def tune_udp_socket(sock: socket.socket) -> None:
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, UDP_BUFFER_BYTES)
        except OSError:
            pass


def resolve_peer_candidates(host: str, port: int):
    normalized = host.strip().strip("[]")
    try:
        ip = ipaddress.ip_address(normalized)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        sockaddr = (str(ip), port, 0, 0) if family == socket.AF_INET6 else (str(ip), port)
        return [(family, sockaddr)]
    except ValueError:
        pass
    infos = socket.getaddrinfo(normalized, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    candidates = []
    seen = set()
    for family in (socket.AF_INET6, socket.AF_INET):
        for fam, _, _, _, sockaddr in infos:
            if fam != family:
                continue
            key = (fam, sockaddr)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((fam, sockaddr))
    return candidates


def bind_udp_socket(bind_ip: str, bind_port: int, family: int) -> socket.socket:
    bind_host = bind_ip
    if family == socket.AF_INET6 and bind_host == "0.0.0.0":
        bind_host = "::"
    if family == socket.AF_INET and bind_host == "::":
        bind_host = "0.0.0.0"
    sock = socket.socket(family, socket.SOCK_DGRAM)
    tune_udp_socket(sock)
    if family == socket.AF_INET6:
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        except OSError:
            pass
        sock.bind((bind_host, bind_port, 0, 0))
    else:
        sock.bind((bind_host, bind_port))
    return sock


def is_temporary_network_error(exc: OSError) -> bool:
    return exc.errno in (
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        errno.ENETDOWN,
        errno.EADDRNOTAVAIL,
        errno.ENODEV,
    )


def is_recoverable_socket_error(exc: BaseException) -> bool:
    if isinstance(exc, socket.timeout):
        return True
    if not isinstance(exc, OSError):
        return False
    return is_temporary_network_error(exc) or exc.errno in (
        errno.EBADF,
        errno.ENOTCONN,
        errno.ECONNRESET,
        errno.ECONNREFUSED,
        errno.EPIPE,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="USTP Client: USTP/UDP -> TCP or UDP output")
    ap.add_argument("--peer-ip", required=True)
    ap.add_argument("--peer-port", type=int, default=40001)
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=0)
    ap.add_argument("--tcp-host", default="127.0.0.1")
    ap.add_argument("--tcp-port", type=int, default=1238)
    ap.add_argument("--output-mode", choices=["tcp", "udp"], default="tcp")
    ap.add_argument("--udp-ip", default="127.0.0.1")
    ap.add_argument("--udp-port", type=int, default=1238)
    ap.add_argument("--udp-unordered-live", action="store_true", help="Immediate out-of-order UDP output (may corrupt generic players)")
    ap.add_argument("--reorder-buffer-ms", type=int, default=1500, help="Initial local playout buffer delay for TCP output or ordered UDP mode")
    ap.add_argument("--keepalive-interval", type=float, default=0.12)
    ap.add_argument("--cipher", default="chacha20", help="chacha20 | aes-256-gcm | aes-128-gcm")
    ap.add_argument("--congestion-control", choices=["on", "off"], default="off", help="Request USTPS Congestion from the server")
    ap.add_argument("--cleartext", choices=["on", "off"], default="off", help="Request cleartext DATA with HMAC instead of AEAD")
    ap.add_argument("--tofu-file", default=os.path.expanduser("~/.ustps_known_hosts.json"))
    ap.add_argument("--regen-key", action="store_true", help="Allow replacing a stored TOFU server key after interactive confirmation")
    args = ap.parse_args()

    tofu_label = f"{args.peer_ip}:{args.peer_port}"
    selected_cipher = normalize_cipher_name(args.cipher)
    key_lock = threading.RLock()
    state_lock = threading.RLock()
    client_private = x25519.X25519PrivateKey.generate()
    client_pub = public_bytes(client_private.public_key())

    raw_usock = None
    usock = None
    peer = None
    recv = None
    active_family = None
    session_ready = False
    session_id = None
    challenge_token = None
    last_kex_ts = 0.0
    last_rx_ts = time.time()
    last_valid_data_ts = 0.0
    last_stall_log_ts = 0.0
    recovery_in_progress = False
    last_recovery_attempt_ts = 0.0
    last_recovery_was_temp_network = False
    running = True
    connection_epoch = 0
    stream_resync_needed = False
    out_by_pos = {}
    next_out_pos = 0
    ordered_release_at = time.time() + (args.reorder_buffer_ms / 1000.0)
    reorder_lock = threading.Lock()
    last_gap_log = 0.0

    def reset_local_stream_state(reason: str) -> None:
        nonlocal out_by_pos, next_out_pos, ordered_release_at, last_gap_log, stream_resync_needed
        with reorder_lock:
            out_by_pos.clear()
            next_out_pos = 0
            ordered_release_at = time.time() + (args.reorder_buffer_ms / 1000.0)
            last_gap_log = 0.0
            stream_resync_needed = True
        with state_lock:
            local_recv = recv
        if local_recv is not None:
            local_recv.reset_state()
        if running:
            print(f"[USTP-CLIENT] stream state reset reason={reason}")

    def connect_transport(prefer_resume: bool) -> bool:
        nonlocal raw_usock, usock, peer, recv, active_family
        nonlocal session_ready, session_id, challenge_token, last_valid_data_ts, last_rx_ts
        nonlocal connection_epoch, last_recovery_was_temp_network
        candidates = resolve_peer_candidates(args.peer_ip, args.peer_port)
        if not candidates:
            return False

        local_session_id = session_id
        local_challenge_token = challenge_token
        temp_network_blocked = False

        for idx, (family, sockaddr) in enumerate(candidates):
            raw_candidate = None
            try:
                raw_candidate = bind_udp_socket(args.bind_ip, args.bind_port, family)
                raw_candidate.settimeout(0.2)
                usock_candidate = AEADDatagramSocket(raw_candidate, cipher_name=selected_cipher)
                peer_candidate = sockaddr
                recv_candidate = USTPReceiver(sock=usock_candidate, peer=peer_candidate)
                ready = False
                deadline = time.time() + (0.7 if prefer_resume else 2.0)
                while time.time() < deadline and running:
                    try:
                        if prefer_resume and local_session_id:
                            hello_payload = RESUME_PREFIX + local_session_id.encode("ascii")
                        elif local_challenge_token and local_session_id:
                            hello_payload = (
                                RESPONSE_PREFIX
                                + local_challenge_token.encode("ascii")
                                + b"\0"
                                + local_session_id.encode("ascii")
                                + b"\0"
                                + selected_cipher.encode("ascii")
                                + b"\0cc="
                                + args.congestion_control.encode("ascii")
                                + b"\0ct="
                                + args.cleartext.encode("ascii")
                                + b"\0"
                                + client_pub
                            )
                        else:
                            hello_payload = encode_transport_hello(client_pub, selected_cipher, args.congestion_control, args.cleartext, HELLO_PREFIX)
                        usock_candidate.send_plain(mkp(TYPE_HELLO, payload=hello_payload).to_bytes(), peer_candidate)
                    except OSError as exc:
                        if is_temporary_network_error(exc):
                            temp_network_blocked = True
                            break
                        raise

                    try:
                        raw, addr = usock_candidate.recvfrom(65535)
                    except socket.timeout:
                        continue
                    except OSError as exc:
                        if is_recoverable_socket_error(exc):
                            temp_network_blocked = True
                            break
                        raise
                    pkt = parse_packet(raw)
                    if not pkt:
                        continue
                    if pkt.pkt_type == TYPE_HELLO and pkt.payload.startswith(CHALLENGE_PREFIX):
                        peer_candidate = addr
                        recv_candidate.peer = addr
                        rest = pkt.payload[len(CHALLENGE_PREFIX) :]
                        parts = rest.split(b"\0", 5)
                        if len(parts) != 6 or len(parts[5]) != 32:
                            continue
                        token = parts[0].decode("ascii", "replace")
                        new_session_id = parts[1].decode("ascii", "replace")
                        session_cipher, negotiated_cc, negotiated_cleartext = parse_hello_options(parts[2] + b"\0" + parts[3] + b"\0" + parts[4])
                        session_cipher = session_cipher or selected_cipher
                        server_pub = parts[5]
                        if session_cipher != selected_cipher:
                            raise SystemExit(f"Server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}")
                        if negotiated_cc not in ("on", "off"):
                            raise SystemExit(f"Server negotiated invalid congestion-control mode {negotiated_cc}")
                        if negotiated_cleartext not in ("on", "off"):
                            raise SystemExit(f"Server negotiated invalid cleartext mode {negotiated_cleartext}")
                        if negotiated_cleartext != args.cleartext:
                            raise SystemExit(f"Server negotiated unexpected cleartext mode {negotiated_cleartext}; expected {args.cleartext}")
                        check_tofu(args.tofu_file, tofu_label, server_pub, allow_regen=args.regen_key)
                        reply = (
                            RESPONSE_PREFIX
                            + token.encode("ascii")
                            + b"\0"
                            + new_session_id.encode("ascii")
                            + b"\0"
                            + session_cipher.encode("ascii")
                            + b"\0cc="
                            + negotiated_cc.encode("ascii")
                            + b"\0ct="
                            + negotiated_cleartext.encode("ascii")
                            + b"\0"
                            + client_pub
                        )
                        try:
                            usock_candidate.send_plain(mkp(TYPE_HELLO, payload=reply).to_bytes(), addr)
                        except OSError as exc:
                            if is_temporary_network_error(exc):
                                continue
                            raise
                        local_challenge_token = token
                        local_session_id = new_session_id
                        continue
                    if pkt.pkt_type == TYPE_HELLO and pkt.payload.startswith(SESSION_PREFIX):
                        peer_candidate = addr
                        recv_candidate.peer = addr
                        rest = pkt.payload[len(SESSION_PREFIX) :]
                        parts = rest.split(b"\0", 4)
                        if len(parts) != 5 or len(parts[4]) != 32:
                            continue
                        new_session_id = parts[0].decode("ascii", "replace")
                        session_cipher, negotiated_cc, negotiated_cleartext = parse_hello_options(parts[1] + b"\0" + parts[2] + b"\0" + parts[3])
                        session_cipher = session_cipher or selected_cipher
                        server_pub = parts[4]
                        if session_cipher != selected_cipher:
                            raise SystemExit(f"Server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}")
                        if negotiated_cc not in ("on", "off"):
                            raise SystemExit(f"Server negotiated invalid congestion-control mode {negotiated_cc}")
                        if negotiated_cleartext not in ("on", "off"):
                            raise SystemExit(f"Server negotiated invalid cleartext mode {negotiated_cleartext}")
                        if negotiated_cleartext != args.cleartext:
                            raise SystemExit(f"Server negotiated unexpected cleartext mode {negotiated_cleartext}; expected {args.cleartext}")
                        check_tofu(args.tofu_file, tofu_label, server_pub, allow_regen=args.regen_key)
                        server_public = x25519.X25519PublicKey.from_public_bytes(server_pub)
                        session_key = derive_session_key(client_private.exchange(server_public), client_pub, server_pub)
                        usock_candidate.set_peer_psk(addr, session_key, session_cipher, cleartext=(negotiated_cleartext == "on"))
                        print(f"[USTP-CLIENT] session ready cipher={session_cipher} cc={negotiated_cc} cleartext={negotiated_cleartext} session={new_session_id}")
                        with state_lock:
                            old_raw = raw_usock
                            old_session_id = session_id
                            raw_usock = raw_candidate
                            usock = usock_candidate
                            peer = addr
                            recv = recv_candidate
                            active_family = family
                            session_ready = True
                            session_id = new_session_id
                            challenge_token = None
                            last_rx_ts = time.time()
                            last_valid_data_ts = time.time()
                            connection_epoch += 1
                        if old_session_id != new_session_id:
                            reset_local_stream_state("path-recovery")
                        if old_raw is not None and old_raw is not raw_candidate:
                            try:
                                old_raw.close()
                            except Exception:
                                pass
                        print(f"[USTP-CLIENT] transport connected peer={addr[0]}:{addr[1]} family={'IPv6' if family == socket.AF_INET6 else 'IPv4'} session={new_session_id} protocol=USTP/1.1")
                        ready = True
                        break
                if ready:
                    return True
            except OSError as exc:
                if is_temporary_network_error(exc):
                    temp_network_blocked = True
                else:
                    raise
            finally:
                if raw_candidate is not None:
                    with state_lock:
                        keep_candidate = raw_candidate is raw_usock
                    if not keep_candidate:
                        try:
                            raw_candidate.close()
                        except Exception:
                            pass
            if temp_network_blocked:
                break
            if idx + 1 < len(candidates):
                print(f"[USTP-CLIENT] fallback to next address after trying {sockaddr[0]}")
        last_recovery_was_temp_network = temp_network_blocked
        return False

    if not connect_transport(prefer_resume=False):
        raise SystemExit("No USTPS session established (AAAA and A attempts failed)")

    with state_lock:
        local = usock.getsockname()
        local_peer = peer
        local_family = active_family
    print(f"[USTP-CLIENT] local bind {local[0]}:{local[1]}")
    print(f"[USTP-CLIENT] peer {args.peer_ip} resolved={local_peer[0]}:{local_peer[1]} family={'IPv6' if local_family == socket.AF_INET6 else 'IPv4'}")
    print(f"[USTP-CLIENT] aead cipher={selected_cipher} cleartext={args.cleartext}")

    clients = []
    cl_lock = threading.Lock()
    usock_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tune_udp_socket(usock_out)

    if args.output_mode == "tcp":
        tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tsock.bind((args.tcp_host, args.tcp_port))
        tsock.listen(5)

        def accept_loop() -> None:
            while running:
                try:
                    c, a = tsock.accept()
                except Exception:
                    if running:
                        continue
                    break
                with cl_lock:
                    clients.append(c)
                if running:
                    print(f"[USTP-CLIENT] TCP client {a}")

        def output_send(data: bytes) -> None:
            dead = []
            with cl_lock:
                for c in clients:
                    try:
                        c.sendall(data)
                    except Exception:
                        dead.append(c)
                for d in dead:
                    try:
                        d.close()
                    except Exception:
                        pass
                    clients.remove(d)
    else:
        def accept_loop() -> None:
            return

        def output_send(data: bytes) -> None:
            try:
                usock_out.sendto(data, (args.udp_ip, args.udp_port))
            except OSError:
                pass

    threads: list[threading.Thread] = []

    def keepalive_loop() -> None:
        nonlocal last_kex_ts
        while running:
            with state_lock:
                local_usock = usock
                local_peer = peer
                local_session_ready = session_ready
                local_session_id = session_id
                local_challenge_token = challenge_token
            if local_usock is None or local_peer is None:
                time.sleep(args.keepalive_interval)
                continue
            with key_lock:
                if local_session_ready and local_session_id:
                    hello_payload = RESUME_PREFIX + local_session_id.encode("ascii")
                elif local_challenge_token and local_session_id:
                    hello_payload = (
                        RESPONSE_PREFIX
                        + local_challenge_token.encode("ascii")
                        + b"\0"
                        + local_session_id.encode("ascii")
                        + b"\0"
                        + selected_cipher.encode("ascii")
                        + b"\0cc="
                        + args.congestion_control.encode("ascii")
                        + b"\0ct="
                        + args.cleartext.encode("ascii")
                        + b"\0"
                        + client_pub
                    )
                else:
                    hello_payload = encode_transport_hello(client_pub, selected_cipher, args.congestion_control, args.cleartext, HELLO_PREFIX)
            try:
                local_usock.send_plain(mkp(TYPE_HELLO, payload=hello_payload).to_bytes(), local_peer)
                last_kex_ts = time.time()
            except OSError as exc:
                if not is_temporary_network_error(exc):
                    pass
            except Exception:
                pass
            time.sleep(args.keepalive_interval)

    def nack_loop() -> None:
        while running:
            with state_lock:
                local_recv = recv
                local_session_ready = session_ready
            if local_session_ready and local_recv is not None:
                try:
                    local_recv.maybe_nack()
                except OSError:
                    pass
                except Exception:
                    pass
            time.sleep(0.03)

    def recv_loop() -> None:
        nonlocal next_out_pos, last_gap_log, last_rx_ts, last_valid_data_ts, ordered_release_at, stream_resync_needed
        nonlocal session_ready, session_id, challenge_token
        nonlocal running
        local_epoch = -1
        while running:
            with state_lock:
                local_usock = usock
                local_peer = peer
                current_epoch = connection_epoch
            if current_epoch != local_epoch:
                local_epoch = current_epoch
                time.sleep(0.05)
                continue
            if local_usock is None or local_peer is None:
                time.sleep(0.05)
                continue
            try:
                raw, addr = local_usock.recvfrom(65535)
            except OSError as exc:
                if exc.errno in (
                    errno.EBADF,
                    errno.ENOTCONN,
                    errno.ECONNRESET,
                    errno.ENETDOWN,
                    errno.ENETUNREACH,
                    errno.EHOSTUNREACH,
                ):
                    print(f"[USTP-CLIENT] network/socket unavailable: {exc}; exiting")
                    running = False
                    break
                continue
            except Exception:
                continue
            if addr != local_peer:
                continue
            pkt = parse_packet(raw)
            if not pkt:
                continue
            last_rx_ts = time.time()
            if pkt.pkt_type == TYPE_HELLO and pkt.payload.startswith(CHALLENGE_PREFIX):
                rest = pkt.payload[len(CHALLENGE_PREFIX) :]
                parts = rest.split(b"\0", 5)
                if len(parts) != 6 or len(parts[5]) != 32:
                    continue
                token = parts[0].decode("ascii", "replace")
                new_session_id = parts[1].decode("ascii", "replace")
                session_cipher, negotiated_cc, negotiated_cleartext = parse_hello_options(parts[2] + b"\0" + parts[3] + b"\0" + parts[4])
                session_cipher = session_cipher or selected_cipher
                server_pub = parts[5]
                if session_cipher != selected_cipher:
                    raise SystemExit(f"Server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}")
                if negotiated_cc not in ("on", "off"):
                    raise SystemExit(f"Server negotiated invalid congestion-control mode {negotiated_cc}")
                if negotiated_cleartext not in ("on", "off"):
                    raise SystemExit(f"Server negotiated invalid cleartext mode {negotiated_cleartext}")
                if negotiated_cleartext != args.cleartext:
                    raise SystemExit(f"Server negotiated unexpected cleartext mode {negotiated_cleartext}; expected {args.cleartext}")
                check_tofu(args.tofu_file, tofu_label, server_pub, allow_regen=args.regen_key)
                reply = (
                    RESPONSE_PREFIX
                    + token.encode("ascii")
                    + b"\0"
                    + new_session_id.encode("ascii")
                    + b"\0"
                    + session_cipher.encode("ascii")
                    + b"\0cc="
                    + negotiated_cc.encode("ascii")
                    + b"\0ct="
                    + negotiated_cleartext.encode("ascii")
                    + b"\0"
                    + client_pub
                )
                try:
                    local_usock.send_plain(mkp(TYPE_HELLO, payload=reply).to_bytes(), local_peer)
                except OSError as exc:
                    if is_temporary_network_error(exc):
                        continue
                    raise
                challenge_token = token
                session_id = new_session_id
                continue
            if pkt.pkt_type == TYPE_HELLO and pkt.payload.startswith(SESSION_PREFIX):
                rest = pkt.payload[len(SESSION_PREFIX) :]
                parts = rest.split(b"\0", 4)
                if len(parts) == 5 and len(parts[4]) == 32:
                    new_session_id = parts[0].decode("ascii", "replace")
                    session_cipher, negotiated_cc, negotiated_cleartext = parse_hello_options(parts[1] + b"\0" + parts[2] + b"\0" + parts[3])
                    session_cipher = session_cipher or selected_cipher
                    server_pub = parts[4]
                    with key_lock:
                        if session_cipher != selected_cipher:
                            raise SystemExit(f"Server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}")
                        if negotiated_cc not in ("on", "off"):
                            raise SystemExit(f"Server negotiated invalid congestion-control mode {negotiated_cc}")
                        if negotiated_cleartext not in ("on", "off"):
                            raise SystemExit(f"Server negotiated invalid cleartext mode {negotiated_cleartext}")
                        if negotiated_cleartext != args.cleartext:
                            raise SystemExit(f"Server negotiated unexpected cleartext mode {negotiated_cleartext}; expected {args.cleartext}")
                        check_tofu(args.tofu_file, tofu_label, server_pub, allow_regen=args.regen_key)
                        server_public = x25519.X25519PublicKey.from_public_bytes(server_pub)
                        session_key = derive_session_key(client_private.exchange(server_public), client_pub, server_pub)
                    local_usock.set_peer_psk(local_peer, session_key, session_cipher, cleartext=(negotiated_cleartext == "on"))
                    with state_lock:
                        session_ready = True
                        session_id = new_session_id
                        challenge_token = None
                        last_valid_data_ts = time.time()
                    if running:
                        print(
                            f"[USTP-CLIENT] session={session_id} aead cipher={session_cipher} "
                            f"cc={negotiated_cc} cleartext={negotiated_cleartext} protocol=USTP/1.1"
                        )
                continue
            if pkt.pkt_type == TYPE_CLOSE:
                continue
            if pkt.pkt_type != TYPE_DATA:
                continue

            last_valid_data_ts = time.time()
            with state_lock:
                local_recv = recv
            if local_recv is not None:
                if pkt.seq in local_recv.received_seq:
                    print(f"[USTP-CLIENT] DUPLICATE seq={pkt.seq}: packet already received; discarded")
                    local_recv.handle_data(pkt)
                    continue
                expected_seq = local_recv.last_max_seq + 1 if local_recv.last_max_seq else pkt.seq
                if pkt.seq != expected_seq:
                    print(
                        f"[USTP-CLIENT] UNORD seq={pkt.seq} expected={expected_seq}: "
                        "packet received out of order; no retransmission needed for this packet"
                    )
                local_recv.handle_data(pkt)
            if args.output_mode == "udp" and args.udp_unordered_live:
                output_send(pkt.payload)
                continue

            with reorder_lock:
                if stream_resync_needed and not out_by_pos and next_out_pos == 0:
                    next_out_pos = pkt.stream_pos
                    ordered_release_at = time.time() + (args.reorder_buffer_ms / 1000.0)
                    stream_resync_needed = False
                    if running:
                        print(f"[USTP-CLIENT] RESYNC stream_pos={next_out_pos} after path recovery")
                out_by_pos[pkt.stream_pos] = pkt.payload
                while next_out_pos in out_by_pos:
                    if args.output_mode == "tcp" and time.time() < ordered_release_at:
                        break
                    if args.output_mode == "udp" and not args.udp_unordered_live and time.time() < ordered_release_at:
                        break
                    chunk = out_by_pos.pop(next_out_pos)
                    if args.output_mode == "tcp" or (args.output_mode == "udp" and not args.udp_unordered_live):
                        output_send(chunk)
                    next_out_pos += len(chunk)

                if pkt.stream_pos > next_out_pos:
                    now = time.time()
                    if now - last_gap_log >= 0.25:
                        if running:
                            print(
                                f"[USTP-CLIENT] GAP next_pos={next_out_pos} "
                                f"arrived_pos={pkt.stream_pos} seq={pkt.seq} "
                                f"reorder_q={len(out_by_pos)}"
                            )
                        last_gap_log = now
                elif pkt.stream_pos < next_out_pos:
                    if running:
                        print(
                            f"[USTP-CLIENT] RECOVERY seq={pkt.seq} pos={pkt.stream_pos} "
                            f"reconstructed_until={next_out_pos}"
                        )

    if args.output_mode == "tcp":
        threads.append(threading.Thread(target=accept_loop, daemon=True, name="ustps-accept"))
    threads.append(threading.Thread(target=keepalive_loop, daemon=True, name="ustps-keepalive"))
    threads.append(threading.Thread(target=nack_loop, daemon=True, name="ustps-nack"))
    threads.append(threading.Thread(target=recv_loop, daemon=True, name="ustps-recv"))
    for thread in threads:
        thread.start()

    if args.output_mode == "tcp":
        print(f"[USTP-CLIENT] TCP output on tcp://{args.tcp_host}:{args.tcp_port}")
    else:
        print(f"[USTP-CLIENT] UDP output on udp://{args.udp_ip}:{args.udp_port}")

    try:
        while running:
            now = time.time()
            if session_ready and last_valid_data_ts and now - last_valid_data_ts > 6.0 and now - last_stall_log_ts > 6.0:
                if running:
                    print("[USTP-CLIENT] no data for 6s; waiting before clean reconnect exit")
                last_stall_log_ts = now
            if session_ready and last_valid_data_ts and now - last_valid_data_ts > 10.0:
                if running:
                    print("[USTP-CLIENT] no data for 10s; exiting so the session can reconnect cleanly")
                last_stall_log_ts = now
                break
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("[USTP-CLIENT] Interrupted")
    finally:
        running = False
        with state_lock:
            local_raw = raw_usock
            local_usock = usock
            local_peer = peer
        try:
            if local_usock is not None and local_peer is not None:
                local_usock.send_plain(mkp(TYPE_CLOSE, payload=b"BYE").to_bytes(), local_peer)
        except Exception:
            pass
        try:
            if local_raw is not None:
                local_raw.close()
        except Exception:
            pass
        try:
            usock_out.close()
        except Exception:
            pass
        if args.output_mode == "tcp":
            try:
                tsock.close()
            except Exception:
                pass
            with cl_lock:
                for c in clients:
                    try:
                        c.close()
                    except Exception:
                        pass
                clients.clear()
        for thread in threads:
            try:
                thread.join(timeout=0.2)
            except Exception:
                pass


if __name__ == "__main__":
    main()
