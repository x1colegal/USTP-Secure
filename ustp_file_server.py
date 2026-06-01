import argparse
import os
import pathlib
import socket
import struct
import threading
import time
from typing import Dict, Tuple

from ustp import USTPSender, parse_packet
from packet import MAX_PAYLOAD, TYPE_ACK, TYPE_HELLO, TYPE_RETRANSMIT_REQUEST, TYPE_DATA, TYPE_CLOSE, mkp

# app header inside USTP DATA payload
# kind(1): 1=meta,2=data,3=end
APP_HDR = "!BI"  # kind, name_len for meta OR chunk_len for data
APP_HDR_SIZE = struct.calcsize(APP_HDR)


def _safe_join(base: pathlib.Path, rel: str) -> pathlib.Path:
    target = (base / rel).resolve()
    if not str(target).startswith(str(base.resolve())):
        raise ValueError("path traversal blocked")
    return target


def make_meta_payload(rel_path: str, file_size: int) -> bytes:
    p = rel_path.encode("utf-8")
    return struct.pack(APP_HDR, 1, len(p)) + p + struct.pack("!Q", file_size)


def make_data_payload(chunk: bytes) -> bytes:
    return struct.pack(APP_HDR, 2, len(chunk)) + chunk


def make_end_payload() -> bytes:
    return struct.pack(APP_HDR, 3, 0)


class Session:
    def __init__(self, sock: socket.socket, peer: Tuple[str, int], window: int, rto: float, loss: int):
        self.sender = USTPSender(sock=sock, peer=peer, window=window, rto=rto, loss_percent=loss)
        self.sender.start()
        self.peer = peer

    def stop(self) -> None:
        self.sender.stop()


def main() -> None:
    ap = argparse.ArgumentParser(description="USTP file sender")
    ap.add_argument("--peer-ip", required=True)
    ap.add_argument("--peer-port", type=int, default=0, help="0 = learn from HELLO source port")
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=41001)
    ap.add_argument("--src", required=True, help="file or directory to send")
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    ap.add_argument("--loss", type=int, default=0)
    args = ap.parse_args()

    src = pathlib.Path(args.src).resolve()
    if not src.exists():
        raise SystemExit(f"src not found: {src}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind_ip, args.bind_port))

    peer = (args.peer_ip, args.peer_port if args.peer_port > 0 else 41000)
    session = Session(sock=sock, peer=peer, window=args.window, rto=args.rto, loss=args.loss)

    running = True
    ready = threading.Event()

    def ctrl_loop() -> None:
        nonlocal peer
        while running:
            try:
                raw, addr = sock.recvfrom(65535)
            except Exception:
                continue
            if addr[0] != args.peer_ip:
                continue
            if args.peer_port == 0 and session.sender.peer != addr:
                session.sender.peer = addr
                peer = addr
                print(f"[USTP-FILE-SERVER] learned endpoint {addr[0]}:{addr[1]}")
            pkt = parse_packet(raw)
            if not pkt:
                continue
            if pkt.pkt_type == TYPE_HELLO:
                ready.set()
            if pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, TYPE_HELLO):
                session.sender.on_control(pkt)

    threading.Thread(target=ctrl_loop, daemon=True).start()

    print("[USTP-FILE-SERVER] waiting HELLO from client...")
    ready.wait(timeout=30)

    def send_file(path: pathlib.Path, rel: str) -> None:
        size = path.stat().st_size
        session.sender.queue_payload(make_meta_payload(rel, size))
        with path.open("rb") as f:
            while True:
                chunk = f.read(MAX_PAYLOAD - APP_HDR_SIZE)
                if not chunk:
                    break
                session.sender.queue_payload(make_data_payload(chunk))
        session.sender.queue_payload(make_end_payload())
        print(f"[USTP-FILE-SERVER] queued file {rel} ({size} bytes)")

    try:
        if src.is_file():
            send_file(src, src.name)
        else:
            base = src
            for p in sorted(base.rglob("*")):
                if p.is_file():
                    rel = str(p.relative_to(base))
                    send_file(p, rel)

        # wait until most packets are acked
        while True:
            with session.sender.lock:
                in_flight = len(session.sender.sent)
                pending = len(session.sender.pending)
            print(f"[USTP-FILE-SERVER] in_flight={in_flight} pending={pending}")
            if in_flight == 0 and pending == 0:
                break
            time.sleep(1)

        close_pkt = mkp(TYPE_CLOSE).to_bytes()
        sock.sendto(close_pkt, peer)
        print("[USTP-FILE-SERVER] transfer complete")
    except KeyboardInterrupt:
        print("[USTP-FILE-SERVER] interrupted")
    finally:
        running = False
        session.stop()


if __name__ == "__main__":
    main()
