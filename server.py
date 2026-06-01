import argparse
import socket
import subprocess
import threading
import time

from packet import MAX_PAYLOAD, TYPE_ACK, TYPE_HELLO, TYPE_RETRANSMIT_REQUEST
from ustp import USTPSender, parse_packet
from aead_udp import AEADDatagramSocket


def main() -> None:
    ap = argparse.ArgumentParser(description="USTP Server: FFmpeg -> USTP/UDP")
    ap.add_argument("--peer-ip", required=True, help="Expected client public IP or domain")
    ap.add_argument("--peer-port", type=int, default=0, help="Optional fixed client port; 0 = learn from HELLO source port")
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=40001)
    ap.add_argument("--video", required=True)
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    ap.add_argument("--loss", type=int, default=0, help="Simulated outbound packet loss percent (0-100)")
    ap.add_argument("--congestion-control", action="store_true", help="Enable optional AIMD congestion control")
    ap.add_argument("--psk", required=True, help="Pre-shared secret for mandatory AEAD")
    ap.add_argument("--cipher", choices=["aesgcm", "chacha20"], default="chacha20")
    args = ap.parse_args()

    resolved_peer_ip = socket.gethostbyname(args.peer_ip)
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock = AEADDatagramSocket(raw_sock, psk=args.psk, cipher_name=args.cipher)
    sock.bind((args.bind_ip, args.bind_port))
    peer = (resolved_peer_ip, args.peer_port if args.peer_port > 0 else 40000)

    sender = USTPSender(
        sock=sock,
        peer=peer,
        window=args.window,
        rto=args.rto,
        loss_percent=args.loss,
        congestion_control=args.congestion_control,
    )
    sender.start()

    print(
        f"[USTP-SERVER] peer={args.peer_ip} resolved={resolved_peer_ip}:{peer[1]} "
        f"cc={'on' if args.congestion_control else 'off'}"
    )

    running = True
    last_hello_ts = 0.0
    session_active = False
    session_epoch = 0

    def ctrl_loop() -> None:
        nonlocal running, last_hello_ts, session_active, session_epoch
        while running:
            try:
                raw, addr = sock.recvfrom(65535)
            except Exception:
                continue
            if addr[0] != resolved_peer_ip:
                continue

            if args.peer_port == 0 and sender.peer != addr:
                sender.peer = addr
                print(f"[USTP-SERVER] learned client endpoint {addr[0]}:{addr[1]}")

            pkt = parse_packet(raw)
            if not pkt:
                continue

            if pkt.pkt_type == TYPE_HELLO:
                last_hello_ts = time.time()
                if not session_active:
                    session_active = True
                    session_epoch += 1
                    sender.reset_session()
                    print(f"[USTP-SERVER] session activated epoch={session_epoch}")

            if pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, TYPE_HELLO):
                sender.on_control(pkt)

    threading.Thread(target=ctrl_loop, daemon=True).start()

    cmd = ["ffmpeg", "-re", "-i", args.video, "-c", "copy", "-mpegts_flags", "+resend_headers", "-f", "mpegts", "-"]
    print("[USTP-SERVER]", " ".join(cmd))

    proc = None
    next_stream_pos = 0
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
            if (now - last_hello_ts) > 1.5:
                if session_active:
                    session_active = False
                    sender.reset_session()
                    print("[USTP-SERVER] session idle, paused TX until client HELLO")
                continue

            sender.queue_payload(chunk, stream_pos=next_stream_pos)
            next_stream_pos += len(chunk)
    except KeyboardInterrupt:
        print("[USTP-SERVER] Interrupted")
    finally:
        running = False
        sender.stop()
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass
        time.sleep(0.2)


if __name__ == "__main__":
    main()
