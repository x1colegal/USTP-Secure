import argparse
import gzip
import json
import pathlib
import socket
import struct
import threading
import time
from typing import Dict, Optional, Tuple

from aead_udp import AEADDatagramSocket, normalize_cipher_name
from packet import MAX_PAYLOAD, TYPE_ACK, TYPE_DATA, TYPE_HELLO, TYPE_RETRANSMIT_REQUEST, mkp
from ustp import USTPSender, USTPReceiver, parse_packet

APP_HDR = "!BI"
APP_HDR_SIZE = struct.calcsize(APP_HDR)
KIND_CTRL = 1
KIND_FILE_META = 2
KIND_FILE_DATA = 3
KIND_FILE_END = 4


def mk_frame(kind: int, blob: bytes) -> bytes:
    return struct.pack(APP_HDR, kind, len(blob)) + blob


def iter_frames(buf: bytes):
    i = 0
    while i + APP_HDR_SIZE <= len(buf):
        kind, ln = struct.unpack(APP_HDR, buf[i:i + APP_HDR_SIZE])
        i += APP_HDR_SIZE
        if i + ln > len(buf):
            break
        payload = buf[i:i + ln]
        i += ln
        yield kind, payload


def collect_files(src: pathlib.Path):
    if src.is_file():
        return [(src, src.name)]
    out = []
    for p in sorted(src.rglob("*")):
        if p.is_file():
            out.append((p, str(p.relative_to(src))))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="USTPS SCP Server")
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=42001)
    ap.add_argument("--peer-ip", required=True)
    ap.add_argument("--peer-port", type=int, default=0)
    ap.add_argument("--psk", required=True)
    ap.add_argument("--cipher", default="chacha20")
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    ap.add_argument("--loss", type=int, default=0)
    ap.add_argument("--congestion-control", action="store_true")
    ap.add_argument("--root", default=".")
    args = ap.parse_args()

    root = pathlib.Path(args.root).resolve()
    root.mkdir(parents=True, exist_ok=True)

    rip = socket.gethostbyname(args.peer_ip)
    raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock = AEADDatagramSocket(raw, psk=args.psk, cipher_name=normalize_cipher_name(args.cipher))
    sock.bind((args.bind_ip, args.bind_port))
    peer = (rip, args.peer_port if args.peer_port > 0 else 42000)

    tx = USTPSender(sock=sock, peer=peer, window=args.window, rto=args.rto, loss_percent=args.loss, congestion_control=args.congestion_control)
    rx = USTPReceiver(sock=sock, peer=peer)
    tx.start()

    active_cmd = None
    state = {"file": None, "path": None, "expected": 0, "written": 0, "start": 0.0, "retx0": 0.0}

    def send_ctrl(obj: Dict):
        tx.queue_payload(mk_frame(KIND_CTRL, json.dumps(obj, separators=(",", ":")).encode("utf-8")))

    def print_progress(name: str, done: int, total: int, start_ts: float, retx_base: float):
        elapsed = max(0.001, time.time() - start_ts)
        speed = done / elapsed
        st = tx.get_stats()
        rtx = int(st.get("rto", 0.0) - retx_base)
        print(f"{name} {done}/{total} {speed/1024:.1f}KB/s retx={rtx}")

    def handle_ctrl(obj: Dict):
        nonlocal active_cmd, peer
        cmd = obj.get("cmd")
        if cmd == "HELLO":
            send_ctrl({"cmd": "HELLO_ACK"})
            return

        if cmd == "UPLOAD_BEGIN":
            rel = obj["path"]
            size = int(obj["size"])
            partial = bool(obj.get("partial", False))
            target = (root / rel).resolve()
            if not str(target).startswith(str(root)):
                send_ctrl({"cmd": "ERROR", "msg": "path traversal"})
                return
            target.parent.mkdir(parents=True, exist_ok=True)
            offset = target.stat().st_size if (partial and target.exists()) else 0
            f = target.open("ab" if offset > 0 else "wb")
            state.update({"file": f, "path": target, "expected": size, "written": offset, "start": time.time(), "retx0": tx.get_stats().get("rto", 0.0)})
            active_cmd = "UPLOAD"
            send_ctrl({"cmd": "UPLOAD_OFFSET", "path": rel, "offset": offset})
            return

        if cmd == "UPLOAD_END":
            f = state.get("file")
            if f:
                f.close()
            name = str(state.get("path"))
            print_progress(name, int(state.get("written", 0)), int(state.get("expected", 0)), float(state.get("start", time.time())), float(state.get("retx0", 0.0)))
            state.update({"file": None, "path": None})
            active_cmd = None
            send_ctrl({"cmd": "UPLOAD_DONE"})
            return

        if cmd == "DOWNLOAD_BEGIN":
            rel = obj["path"]
            partial = bool(obj.get("partial", False))
            compress = bool(obj.get("compress", False))
            src = (root / rel).resolve()
            if not str(src).startswith(str(root)) or not src.exists() or not src.is_file():
                send_ctrl({"cmd": "ERROR", "msg": "file not found"})
                return
            size = src.stat().st_size
            send_ctrl({"cmd": "DOWNLOAD_META", "path": rel, "size": size, "compress": compress})
            # wait requester offset via DOWNLOAD_OFFSET
            active_cmd = ("DOWNLOAD", src, rel, compress, partial)
            return

        if cmd == "DOWNLOAD_OFFSET":
            if not (isinstance(active_cmd, tuple) and active_cmd and active_cmd[0] == "DOWNLOAD"):
                return
            _, src, rel, compress, _partial = active_cmd
            offset = int(obj.get("offset", 0))
            sent = 0
            st0 = tx.get_stats().get("rto", 0.0)
            t0 = time.time()
            with src.open("rb") as f:
                if offset > 0:
                    f.seek(offset)
                while True:
                    chunk = f.read(MAX_PAYLOAD - APP_HDR_SIZE - 64)
                    if not chunk:
                        break
                    if compress:
                        chunk = gzip.compress(chunk)
                    meta = json.dumps({"path": rel, "offset": offset + sent, "compressed": compress}, separators=(",", ":")).encode("utf-8")
                    tx.queue_payload(mk_frame(KIND_FILE_META, meta) + mk_frame(KIND_FILE_DATA, chunk))
                    sent += len(chunk) if not compress else 0
            tx.queue_payload(mk_frame(KIND_FILE_END, json.dumps({"path": rel}).encode("utf-8")))
            elapsed = max(0.001, time.time() - t0)
            rtx = int(tx.get_stats().get("rto", 0.0) - st0)
            print(f"{rel} sent speed={src.stat().st_size/elapsed/1024:.1f}KB/s retx={rtx}")
            active_cmd = None
            return

    last_hello = 0.0
    print(f"[USTPS-SCP-SERVER] listen {args.bind_ip}:{args.bind_port} root={root}")
    try:
        while True:
            rawp, addr = sock.recvfrom(65535)
            if addr[0] != rip:
                continue
            if args.peer_port == 0 and tx.peer != addr:
                tx.peer = addr
                rx.peer = addr
                peer = addr
                print(f"[USTPS-SCP-SERVER] learned client endpoint {addr[0]}:{addr[1]}")
            pkt = parse_packet(rawp)
            if not pkt:
                continue
            if pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, TYPE_HELLO):
                tx.on_control(pkt)
            if pkt.pkt_type != TYPE_DATA:
                continue
            out = rx.handle_data(pkt)
            if not out:
                continue
            for kind, payload in iter_frames(out):
                if kind == KIND_CTRL:
                    handle_ctrl(json.loads(payload.decode("utf-8")))
                elif kind == KIND_FILE_META:
                    pass
                elif kind == KIND_FILE_DATA:
                    if state.get("file"):
                        state["file"].write(payload)
                        state["written"] += len(payload)
                        if state["written"] % (256 * 1024) < len(payload):
                            print_progress(str(state.get("path")), int(state["written"]), int(state["expected"]), float(state["start"]), float(state["retx0"]))
                elif kind == KIND_FILE_END:
                    if state.get("file"):
                        state["file"].close()
                        print_progress(str(state.get("path")), int(state["written"]), int(state["expected"]), float(state["start"]), float(state["retx0"]))
                        state.update({"file": None, "path": None})
                        send_ctrl({"cmd": "UPLOAD_DONE"})
            if time.time() - last_hello > 0.2:
                tx.queue_payload(mk_frame(KIND_CTRL, json.dumps({"cmd": "HELLO"}).encode("utf-8")))
                last_hello = time.time()
    except KeyboardInterrupt:
        print("[USTPS-SCP-SERVER] interrupted")
    finally:
        tx.stop()


if __name__ == "__main__":
    main()
