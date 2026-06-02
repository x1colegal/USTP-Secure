import argparse
import random
import socket
import subprocess
import threading
import time
import traceback
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from packet import MAX_PAYLOAD, TYPE_ACK, TYPE_HELLO, TYPE_RETRANSMIT_REQUEST, mkp
from ustp import USTPSender, parse_packet
from aead_udp import AEADDatagramSocket, normalize_cipher_name


SUPPORTED_CIPHERS = ("chacha20", "aes-256-gcm", "aes-128-gcm")
HELLO_PREFIX = b"USTPS-KEX1\0"
SESSION_PREFIX = b"USTPS-SESSION1\0"


@dataclass
class ClientSession:
    sender: USTPSender
    last_hello_ts: float
    cipher: str
    session_psk: bytes
    client_pub: bytes
    server_pub: bytes
    session_reply: bytes
    next_stream_pos: int = 0
    created_ts: float = 0.0


def public_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def derive_session_key(shared: bytes, client_pub: bytes, server_pub: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=client_pub + server_pub,
        info=b"USTPS-X25519-session-v1",
    ).derive(shared)


def parse_client_pub(payload: bytes) -> bytes | None:
    if not payload.startswith(HELLO_PREFIX):
        return None
    rest = payload[len(HELLO_PREFIX) :]
    if len(rest) < 32:
        return None
    return rest[:32]


def main() -> None:
    ap = argparse.ArgumentParser(description="USTP Server: FFmpeg -> USTP/UDP")
    ap.add_argument("--peer-ip", default="0.0.0.0", help="Compatibility option; server accepts every valid AEAD client")
    ap.add_argument("--peer-port", type=int, default=0, help="Optional fixed client port; 0 = learn from HELLO source port")
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=40001)
    ap.add_argument("--video", required=True)
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    ap.add_argument("--loss", type=int, default=0, help="Simulated outbound packet loss percent (0-100)")
    ap.add_argument("--congestion-control", action="store_true", help="Enable optional AIMD congestion control")
    ap.add_argument("--cipher", default="chacha20", help="chacha20 | aes-256-gcm | aes-128-gcm")
    args = ap.parse_args()

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    selected_cipher = normalize_cipher_name(args.cipher)
    sock = AEADDatagramSocket(raw_sock, cipher_name=selected_cipher)
    sock.bind((args.bind_ip, args.bind_port))
    sessions: dict[tuple[str, int], ClientSession] = {}
    sessions_lock = threading.Lock()

    print(
        f"[USTP-SERVER] listen={args.bind_ip}:{args.bind_port} "
        f"cc={'on' if args.congestion_control else 'off'} default-aead={selected_cipher} multi-client=on"
    )

    running = True

    def new_session(addr: tuple[str, int], client_pub_raw: bytes) -> ClientSession:
        cipher = random.choice(SUPPORTED_CIPHERS)
        server_private = x25519.X25519PrivateKey.generate()
        server_pub = public_bytes(server_private.public_key())
        client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_raw)
        session_psk = derive_session_key(server_private.exchange(client_pub), client_pub_raw, server_pub)
        session_reply = SESSION_PREFIX + client_pub_raw + server_pub + cipher.encode("ascii")
        sock.send_plain(mkp(TYPE_HELLO, payload=session_reply).to_bytes(), addr)
        sock.set_peer_psk(addr, session_psk, cipher)
        sender = USTPSender(
            sock=sock,
            peer=addr,
            window=args.window,
            rto=args.rto,
            loss_percent=args.loss,
            congestion_control=args.congestion_control,
        )
        sender.start()
        print(f"[USTP-SERVER] client joined {addr[0]}:{addr[1]} cipher={cipher}")
        now = time.time()
        return ClientSession(
            sender=sender,
            last_hello_ts=now,
            cipher=cipher,
            session_psk=session_psk,
            client_pub=client_pub_raw,
            server_pub=server_pub,
            session_reply=session_reply,
            created_ts=now,
        )

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
                resend_reply = None
                create_pub = None
                now = time.time()

                with sessions_lock:
                    session = sessions.get(addr)
                    if pkt.pkt_type == TYPE_HELLO:
                        client_pub = parse_client_pub(pkt.payload)
                        if client_pub is not None:
                            if session is not None:
                                session.last_hello_ts = now
                                if client_pub == session.client_pub:
                                    resend_reply = session.session_reply
                                else:
                                    create_pub = client_pub
                            else:
                                create_pub = client_pub
                        elif session is not None:
                            session.last_hello_ts = now
                    elif session is not None:
                        session.last_hello_ts = now

                if resend_reply is not None:
                    sock.send_plain(mkp(TYPE_HELLO, payload=resend_reply).to_bytes(), addr)
                    continue

                if create_pub is not None:
                    new = new_session(addr, create_pub)
                    with sessions_lock:
                        old = sessions.get(addr)
                        if old is not None:
                            old.sender.stop()
                            sock.clear_peer(addr)
                        sessions[addr] = new
                    continue

                if session is None:
                    continue
                if pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, TYPE_HELLO):
                    session.sender.on_control(pkt)
            except Exception:
                print("[USTP-SERVER] control-loop error:")
                traceback.print_exc()

    threading.Thread(target=ctrl_loop, daemon=True).start()

    cmd = ["ffmpeg", "-re", "-i", args.video, "-c", "copy", "-mpegts_flags", "+resend_headers", "-f", "mpegts", "-"]
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
                    if (now - session.last_hello_ts) > 20.0:
                        with sessions_lock:
                            current = sessions.get(addr)
                            if current is session:
                                session.sender.stop()
                                sock.clear_peer(addr)
                                del sessions[addr]
                                print(f"[USTP-SERVER] client idle removed {addr[0]}:{addr[1]}")
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
