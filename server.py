import argparse
import random
import socket
import subprocess
import threading
import time
from dataclasses import dataclass

from packet import MAX_PAYLOAD, TYPE_ACK, TYPE_HELLO, TYPE_RETRANSMIT_REQUEST
from ustp import USTPSender, parse_packet
from aead_udp import AEADDatagramSocket, normalize_cipher_name


SUPPORTED_CIPHERS = ("chacha20", "aes-256-gcm", "aes-128-gcm")


@dataclass
class ClientSession:
    sender: USTPSender
    last_hello_ts: float
    cipher: str
    next_stream_pos: int = 0


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
    ap.add_argument("--psk", required=True, help="Pre-shared secret for mandatory AEAD")
    ap.add_argument("--cipher", default="chacha20", help="chacha20 | aes-256-gcm | aes-128-gcm")
    args = ap.parse_args()

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    selected_cipher = normalize_cipher_name(args.cipher)
    sock = AEADDatagramSocket(raw_sock, psk=args.psk, cipher_name=selected_cipher)
    sock.bind((args.bind_ip, args.bind_port))
    sessions: dict[tuple[str, int], ClientSession] = {}
    sessions_lock = threading.Lock()

    print(
        f"[USTP-SERVER] listen={args.bind_ip}:{args.bind_port} "
        f"cc={'on' if args.congestion_control else 'off'} default-aead={selected_cipher} multi-client=on"
    )

    running = True

    def new_session(addr: tuple[str, int]) -> ClientSession:
        cipher = random.choice(SUPPORTED_CIPHERS)
        sock.set_peer_cipher(addr, cipher)
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
        return ClientSession(sender=sender, last_hello_ts=time.time(), cipher=cipher)

    def ctrl_loop() -> None:
        nonlocal running
        while running:
            try:
                raw, addr = sock.recvfrom(65535)
            except Exception:
                continue

            pkt = parse_packet(raw)
            if not pkt:
                continue

            with sessions_lock:
                session = sessions.get(addr)
                if session is None and pkt.pkt_type == TYPE_HELLO:
                    session = new_session(addr)
                    sessions[addr] = session
                if session is None:
                    continue
                if pkt.pkt_type == TYPE_HELLO:
                    session.last_hello_ts = time.time()
                if pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, TYPE_HELLO):
                    session.sender.on_control(pkt)

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
                for addr, session in list(sessions.items()):
                    if (now - session.last_hello_ts) > 5.0:
                        session.sender.stop()
                        del sessions[addr]
                        print(f"[USTP-SERVER] client idle removed {addr[0]}:{addr[1]}")
                        continue
                    session.sender.queue_payload(chunk, stream_pos=session.next_stream_pos)
                    session.next_stream_pos += len(chunk)
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
