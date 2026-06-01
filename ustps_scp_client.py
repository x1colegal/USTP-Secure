import argparse
import gzip
import json
import pathlib
import socket
import struct
import time
from typing import Dict

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
    ap = argparse.ArgumentParser(description="USTPS SCP Client")
    ap.add_argument("--peer-ip", required=True)
    ap.add_argument("--peer-port", type=int, default=42001)
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=42000)
    ap.add_argument("--psk", required=True)
    ap.add_argument("--cipher", default="chacha20")
    ap.add_argument("--mode", choices=["upload", "download"], required=True)
    ap.add_argument("--src", default=None)
    ap.add_argument("--dst", default=".")
    ap.add_argument("--partial", action="store_true")
    ap.add_argument("--compress", action="store_true")
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    args = ap.parse_args()

    rip = socket.gethostbyname(args.peer_ip)
    raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock = AEADDatagramSocket(raw, psk=args.psk, cipher_name=normalize_cipher_name(args.cipher))
    sock.bind((args.bind_ip, args.bind_port))
    peer = (rip, args.peer_port)

    tx = USTPSender(sock=sock, peer=peer, window=args.window, rto=args.rto)
    rx = USTPReceiver(sock=sock, peer=peer)
    tx.start()

    dst_root = pathlib.Path(args.dst).resolve()
    dst_root.mkdir(parents=True, exist_ok=True)

    ctrl_queue = []
    write_state: Dict[str, Dict] = {}

    def send_ctrl(obj: Dict):
        tx.queue_payload(mk_frame(KIND_CTRL, json.dumps(obj, separators=(",", ":")).encode("utf-8")))

    def pump(timeout: float = 0.1):
        end = time.time() + timeout
        while time.time() < end:
            rawp, addr = sock.recvfrom(65535)
            if addr[0] != rip:
                continue
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
                    ctrl_queue.append(json.loads(payload.decode("utf-8")))
                elif kind == KIND_FILE_META:
                    meta = json.loads(payload.decode("utf-8"))
                    p = meta["path"]
                    if p not in write_state:
                        continue
                    write_state[p]["offset"] = int(meta.get("offset", write_state[p]["offset"]))
                    write_state[p]["compressed"] = bool(meta.get("compressed", False))
                elif kind == KIND_FILE_DATA:
                    for p, st in write_state.items():
                        if st.get("expecting"):
                            chunk = payload
                            if st.get("compressed"):
                                chunk = gzip.decompress(chunk)
                            st["f"].write(chunk)
                            st["written"] += len(chunk)
                            st["expecting"] = False
                            elapsed = max(0.001, time.time() - st["start"])
                            rtx = int(tx.get_stats().get("rto", 0.0) - st["rtx0"])
                            print(f"{p} {st['written']}/{st['total']} {st['written']/elapsed/1024:.1f}KB/s retx={rtx}")
                            break
                elif kind == KIND_FILE_END:
                    meta = json.loads(payload.decode("utf-8"))
                    p = meta["path"]
                    if p in write_state:
                        st = write_state.pop(p)
                        st["f"].close()

            for p, st in write_state.items():
                st["expecting"] = True

    send_ctrl({"cmd": "HELLO"})
    t0 = time.time()
    while time.time() - t0 < 5:
        pump(0.2)
        if any(c.get("cmd") == "HELLO_ACK" for c in ctrl_queue):
            break

    if args.mode == "upload":
        if not args.src:
            raise SystemExit("--src required for upload")
        src = pathlib.Path(args.src).resolve()
        files = collect_files(src)
        for path, rel in files:
            size = path.stat().st_size
            send_ctrl({"cmd": "UPLOAD_BEGIN", "path": rel, "size": size, "partial": args.partial})
            offset = 0
            while True:
                pump(0.2)
                msg = next((c for c in ctrl_queue if c.get("cmd") == "UPLOAD_OFFSET" and c.get("path") == rel), None)
                if msg:
                    offset = int(msg.get("offset", 0))
                    ctrl_queue.remove(msg)
                    break
            sent = offset
            rtx0 = tx.get_stats().get("rto", 0.0)
            tstart = time.time()
            with path.open("rb") as f:
                if offset > 0:
                    f.seek(offset)
                while True:
                    chunk = f.read(MAX_PAYLOAD - APP_HDR_SIZE - 64)
                    if not chunk:
                        break
                    if args.compress:
                        chunk = gzip.compress(chunk)
                    tx.queue_payload(mk_frame(KIND_FILE_DATA, chunk))
                    sent += len(chunk) if not args.compress else 0
                    elapsed = max(0.001, time.time() - tstart)
                    rtx = int(tx.get_stats().get("rto", 0.0) - rtx0)
                    print(f"{rel} {min(sent,size)}/{size} {min(sent,size)/elapsed/1024:.1f}KB/s retx={rtx}")
                    pump(0.01)
            send_ctrl({"cmd": "UPLOAD_END", "path": rel})
            done = False
            while not done:
                pump(0.2)
                msg = next((c for c in ctrl_queue if c.get("cmd") == "UPLOAD_DONE"), None)
                if msg:
                    ctrl_queue.remove(msg)
                    done = True
    else:
        if not args.src:
            raise SystemExit("--src required for download (remote path)")
        rel = args.src
        send_ctrl({"cmd": "DOWNLOAD_BEGIN", "path": rel, "partial": args.partial, "compress": args.compress})
        size = None
        while size is None:
            pump(0.2)
            msg = next((c for c in ctrl_queue if c.get("cmd") == "DOWNLOAD_META" and c.get("path") == rel), None)
            if msg:
                ctrl_queue.remove(msg)
                size = int(msg["size"])
                break
        target = (dst_root / rel).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        offset = target.stat().st_size if (args.partial and target.exists()) else 0
        f = target.open("ab" if offset > 0 else "wb")
        write_state[rel] = {"f": f, "offset": offset, "written": offset, "total": size, "start": time.time(), "rtx0": tx.get_stats().get("rto", 0.0), "expecting": False, "compressed": args.compress}
        send_ctrl({"cmd": "DOWNLOAD_OFFSET", "path": rel, "offset": offset})
        while rel in write_state:
            pump(0.2)

    print("[USTPS-SCP-CLIENT] done")


if __name__ == "__main__":
    main()
