import argparse
import errno
import os
import shlex
import socket
import subprocess
import threading
import time
import traceback
from dataclasses import dataclass
import base64
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from packet import MAX_PAYLOAD, TYPE_ACK, TYPE_HELLO, TYPE_RETRANSMIT_REQUEST, mkp
from ustp import USTPSender, parse_packet
from aead_udp import AEADDatagramSocket, normalize_cipher_name
HELLO_PREFIX = b"USTPS-KEX1\0"
CHALLENGE_PREFIX = b"USTPS-CHALLENGE1\0"
RESPONSE_PREFIX = b"USTPS-CHALLENGE-REPLY1\0"
RESUME_PREFIX = b"USTPS-RESUME1\0"
SESSION_PREFIX = b"USTPS-SESSION1\0"
VIDEO_USER_AGENT = "USTPS Video Mode"
UDP_BUFFER_BYTES = 4 * 1024 * 1024


@dataclass
class ClientSession:
    addr: tuple[str, int]
    sender: USTPSender
    last_hello_ts: float
    last_seen_ts: float
    cipher: str
    session_psk: bytes
    client_pub: bytes
    server_pub: bytes
    session_id: str
    session_reply: bytes
    next_stream_pos: int = 0
    created_ts: float = 0.0


@dataclass
class PendingChallenge:
    addr: tuple[str, int]
    client_pub: bytes
    cipher: str
    session_id: str
    token: str
    created_ts: float


def public_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def derive_session_key(shared: bytes, client_pub: bytes, server_pub: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=client_pub + server_pub,
        info=b"USTPS-X25519-session-v1",
    ).derive(shared)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def parse_client_hello(payload: bytes):
    if payload.startswith(HELLO_PREFIX):
        rest = payload[len(HELLO_PREFIX) :]
        if len(rest) < 32:
            return None
        client_pub = rest[:32]
        cipher = None
        if len(rest) > 32:
            try:
                cipher = normalize_cipher_name(rest[32:].decode("ascii", "replace"))
            except Exception:
                cipher = None
        return ("init", client_pub, cipher)
    if payload.startswith(RESPONSE_PREFIX):
        rest = payload[len(RESPONSE_PREFIX) :]
        parts = rest.split(b"\0", 3)
        if len(parts) != 4 or len(parts[3]) != 32:
            return None
        try:
            token = parts[0].decode("ascii", "replace")
            session_id = parts[1].decode("ascii", "replace")
            cipher = normalize_cipher_name(parts[2].decode("ascii", "replace"))
        except Exception:
            return None
        return ("challenge_reply", token, session_id, parts[3], cipher)
    if payload.startswith(RESUME_PREFIX):
        rest = payload[len(RESUME_PREFIX) :]
        try:
            return ("resume", rest.decode("ascii", "replace"))
        except Exception:
            return None
    return None


def load_or_create_host_key(path: str) -> x25519.X25519PrivateKey:
    try:
        with open(path, "rb") as f:
            raw = f.read()
        if len(raw) == 32:
            return x25519.X25519PrivateKey.from_private_bytes(raw)
    except FileNotFoundError:
        pass
    key = x25519.X25519PrivateKey.generate()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return key


def create_new_host_key(path: str) -> x25519.X25519PrivateKey:
    key = x25519.X25519PrivateKey.generate()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return key


def maybe_regen_host_key(path: str, enabled: bool) -> None:
    if not enabled:
        return
    if not os.isatty(0):
        raise SystemExit("--regen-key requires interactive confirmation")
    answer = input(f"Regenerate USTPS host key at {path}? Existing clients will see a TOFU mismatch. [y/N] ").strip().lower()
    if answer not in ("y", "yes"):
        raise SystemExit("USTPS host key regeneration cancelled")
    create_new_host_key(path)
    print(f"[USTP-SERVER] regenerated host key at {path}")


def tune_udp_socket(sock: socket.socket) -> None:
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, UDP_BUFFER_BYTES)
        except OSError:
            pass


def create_server_udp_socket(bind_ip: str, bind_port: int) -> socket.socket:
    bind_host = bind_ip
    if bind_host == "0.0.0.0":
        bind_host = "::"
    infos = socket.getaddrinfo(bind_host, bind_port, socket.AF_UNSPEC, socket.SOCK_DGRAM, 0, socket.AI_PASSIVE)
    last_error = None
    for family, socktype, proto, _, sockaddr in infos:
        try:
            sock = socket.socket(family, socktype, proto)
            if family == socket.AF_INET6:
                try:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except OSError:
                    pass
            tune_udp_socket(sock)
            sock.bind(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            try:
                sock.close()
            except Exception:
                pass
    if last_error is not None:
        raise last_error
    raise OSError(errno.EADDRNOTAVAIL, "unable to bind UDP socket")


def main() -> None:
    ap = argparse.ArgumentParser(description="USTP Server: FFmpeg -> USTP/UDP")
    ap.add_argument("--peer-port", type=int, default=0, help="Optional fixed client port; 0 = learn from HELLO source port")
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=40001)
    ap.add_argument("--video", required=True)
    ap.add_argument(
        "--video-parameters",
        default="",
        help="Optional ffmpeg parameters to use instead of the default '-c copy -mpegts_flags +resend_headers'",
    )
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    ap.add_argument("--loss", type=int, default=0, help="Simulated outbound packet loss percent (0-100)")
    ap.add_argument("--cipher", default="auto", help="auto | chacha20 | aes-256-gcm | aes-128-gcm")
    ap.add_argument("--host-key-file", default=os.path.expanduser("~/.ustps_host_key"))
    ap.add_argument("--regen-key", action="store_true", help="Regenerate the persistent server host key after interactive confirmation")
    ap.add_argument("--stalled-progress-timeout", type=float, default=20.0, help="Drop a session if ACK progress stops for too long while queues keep growing")
    ap.add_argument("--max-pending-packets", type=int, default=4096, help="Per-session pending queue hard limit before the session is considered stalled")
    args = ap.parse_args()

    raw_sock = create_server_udp_socket(args.bind_ip, args.bind_port)
    selected_cipher = None if args.cipher == "auto" else normalize_cipher_name(args.cipher)
    maybe_regen_host_key(args.host_key_file, args.regen_key)
    host_private = load_or_create_host_key(args.host_key_file)
    host_public = public_bytes(host_private.public_key())
    sock = AEADDatagramSocket(raw_sock, cipher_name=selected_cipher)
    sessions: dict[tuple[str, int], ClientSession] = {}
    sessions_by_id: dict[str, ClientSession] = {}
    pending_challenges: dict[tuple[str, int], PendingChallenge] = {}
    sessions_lock = threading.Lock()

    print(
        f"[USTP-SERVER] listen={args.bind_ip}:{args.bind_port} default-aead={selected_cipher or 'auto'} multi-client=on"
    )

    running = True

    def send_challenge(addr: tuple[str, int], client_pub_raw: bytes, requested_cipher: str | None) -> None:
        cipher = selected_cipher or requested_cipher or "chacha20"
        challenge = pending_challenges.get(addr)
        if challenge is None or challenge.client_pub != client_pub_raw or challenge.cipher != cipher:
            challenge = PendingChallenge(
                addr=addr,
                client_pub=client_pub_raw,
                cipher=cipher,
                session_id=b64u(secrets.token_bytes(18)),
                token=b64u(secrets.token_bytes(18)),
                created_ts=time.time(),
            )
            pending_challenges[addr] = challenge
        payload = CHALLENGE_PREFIX + challenge.token.encode("ascii") + b"\0" + challenge.session_id.encode("ascii") + b"\0" + challenge.cipher.encode("ascii") + b"\0" + host_public
        sock.send_plain(mkp(TYPE_HELLO, payload=payload).to_bytes(), addr)

    def new_session(addr: tuple[str, int], challenge: PendingChallenge) -> ClientSession:
        client_pub = x25519.X25519PublicKey.from_public_bytes(challenge.client_pub)
        session_psk = derive_session_key(host_private.exchange(client_pub), challenge.client_pub, host_public)
        session_reply = SESSION_PREFIX + challenge.session_id.encode("ascii") + b"\0" + challenge.cipher.encode("ascii") + b"\0" + host_public
        sock.send_plain(mkp(TYPE_HELLO, payload=session_reply).to_bytes(), addr)
        sock.set_peer_psk(addr, session_psk, challenge.cipher)
        sender = USTPSender(
            sock=sock,
            peer=addr,
            window=args.window,
            rto=args.rto,
            loss_percent=args.loss,
        )
        sender.start()
        print(f"[USTP-SERVER] client joined {addr[0]}:{addr[1]} cipher={challenge.cipher} session={challenge.session_id}")
        now = time.time()
        session = ClientSession(
            addr=addr,
            sender=sender,
            last_hello_ts=now,
            last_seen_ts=now,
            cipher=challenge.cipher,
            session_psk=session_psk,
            client_pub=challenge.client_pub,
            server_pub=host_public,
            session_id=challenge.session_id,
            session_reply=session_reply,
            created_ts=now,
        )
        sessions[addr] = session
        sessions_by_id[challenge.session_id] = session
        pending_challenges.pop(addr, None)
        return session

    def find_session_by_client_pub(client_pub_raw: bytes) -> tuple[tuple[str, int], ClientSession] | tuple[None, None]:
        for existing_addr, existing_session in sessions.items():
            if existing_session.client_pub == client_pub_raw:
                return existing_addr, existing_session
        return None, None

    def migrate_session(old_addr: tuple[str, int], new_addr: tuple[str, int], session: ClientSession) -> None:
        if old_addr == new_addr:
            return
        sock.clear_peer(old_addr)
        sock.set_peer_psk(new_addr, session.session_psk, session.cipher)
        session.sender.peer = new_addr
        session.addr = new_addr
        sessions.pop(old_addr, None)
        sessions[new_addr] = session
        print(f"[USTP-SERVER] client migrated {old_addr[0]}:{old_addr[1]} -> {new_addr[0]}:{new_addr[1]} session={session.session_id}")

    def ctrl_loop() -> None:
        nonlocal running
        while running:
            try:
                raw, addr = sock.recvfrom(65535)
            except Exception:
                continue

            try:
                pkt = parse_packet(raw)
                if not pkt:
                    continue
                if args.peer_port and addr[1] != args.peer_port:
                    continue
                session = None
                complete_challenge = None
                issue_challenge = None
                now = time.time()

                with sessions_lock:
                    session = sessions.get(addr)
                    if pkt.pkt_type == TYPE_HELLO:
                        parsed = parse_client_hello(pkt.payload)
                        if parsed is not None:
                            kind = parsed[0]
                            if kind == "init":
                                _, client_pub, requested_cipher = parsed
                                old_addr, old_session = find_session_by_client_pub(client_pub)
                                if old_session is not None:
                                    migrate_session(old_addr, addr, old_session)
                                    session = old_session
                                    session.last_hello_ts = now
                                    session.last_seen_ts = now
                                else:
                                    issue_challenge = (client_pub, requested_cipher)
                            elif kind == "challenge_reply":
                                _, token, session_id, client_pub, requested_cipher = parsed
                                pending = pending_challenges.get(addr)
                                if pending and pending.token == token and pending.session_id == session_id and pending.client_pub == client_pub:
                                    complete_challenge = pending
                                else:
                                    continue
                            elif kind == "resume":
                                _, session_id = parsed
                                resume_session = sessions_by_id.get(session_id)
                                if resume_session is not None:
                                    if resume_session.addr != addr:
                                        migrate_session(resume_session.addr, addr, resume_session)
                                    session = resume_session
                                    session.last_hello_ts = now
                                    session.last_seen_ts = now
                        elif session is not None:
                            session.last_hello_ts = now
                            session.last_seen_ts = now
                    elif session is not None:
                        session.last_seen_ts = now

                if issue_challenge is not None:
                    with sessions_lock:
                        send_challenge(addr, issue_challenge[0], issue_challenge[1])
                    continue

                if complete_challenge is not None:
                    with sessions_lock:
                        old = sessions.get(addr)
                        if old is not None:
                            old.sender.stop()
                            sock.clear_peer(addr)
                            sessions_by_id.pop(old.session_id, None)
                        session = new_session(addr, complete_challenge)
                    continue

                if session is None:
                    continue
                if pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, TYPE_HELLO):
                    session.sender.on_control(pkt)
            except Exception:
                print("[USTP-SERVER] control-loop error:")
                traceback.print_exc()

    threading.Thread(target=ctrl_loop, daemon=True).start()

    ffmpeg_video_args = shlex.split(args.video_parameters) if args.video_parameters.strip() else [
        "-c",
        "copy",
        "-mpegts_flags",
        "+resend_headers",
    ]
    cmd = [
        "ffmpeg",
        "-re",
        "-user_agent",
        VIDEO_USER_AGENT,
        "-i",
        args.video,
        *ffmpeg_video_args,
        "-f",
        "mpegts",
        "-",
    ]
    print("[USTP-SERVER]", " ".join(cmd))

    proc = None
    try:
        while True:
            if proc is None or proc.poll() is not None:
                if proc is not None:
                    print(f"[USTP-SERVER] ffmpeg exited code={proc.returncode}, restarting in 1s")
                    time.sleep(1.0)
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)

            if proc.stdout is None:
                time.sleep(0.2)
                continue

            chunk = proc.stdout.read(MAX_PAYLOAD)
            if not chunk:
                try:
                    proc.terminate()
                except Exception:
                    pass
                proc = None
                continue

            now = time.time()
            with sessions_lock:
                snapshot = list(sessions.items())

            for addr, session in snapshot:
                try:
                    stats = session.sender.get_stats()
                    if stats["pending"] > args.max_pending_packets and stats["last_progress_age"] > args.stalled_progress_timeout:
                        session.sender.reset_session()
                        print(
                            f"[USTP-SERVER] stalled session reset {addr[0]}:{addr[1]} "
                            f"pending={int(stats['pending'])} inflight={int(stats['inflight'])} "
                            f"last_progress={stats['last_progress_age']:.1f}s"
                        )
                        continue
                    if (now - session.last_seen_ts) > 180.0:
                        with sessions_lock:
                            current = sessions.get(addr)
                            if current is session:
                                session.sender.stop()
                                sock.clear_peer(addr)
                                sessions_by_id.pop(session.session_id, None)
                                del sessions[addr]
                                print(f"[USTP-SERVER] client idle removed {addr[0]}:{addr[1]} last_seen={now - session.last_seen_ts:.1f}s")
                        continue
                    stream_pos = session.next_stream_pos
                    session.next_stream_pos += len(chunk)
                    session.sender.queue_payload(chunk, stream_pos=stream_pos)
                except Exception:
                    print(f"[USTP-SERVER] session send error {addr[0]}:{addr[1]}:")
                    traceback.print_exc()
                    with sessions_lock:
                        current = sessions.get(addr)
                        if current is session:
                            try:
                                session.sender.stop()
                                sock.clear_peer(addr)
                                sessions_by_id.pop(session.session_id, None)
                            finally:
                                sessions.pop(addr, None)
    except KeyboardInterrupt:
        print("[USTP-SERVER] Interrupted")
    finally:
        running = False
        with sessions_lock:
            for session in sessions.values():
                session.sender.stop()
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass
        time.sleep(0.2)


if __name__ == "__main__":
    main()
