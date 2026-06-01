import argparse
import ssl
import struct
import subprocess
import threading
import time
from collections import deque

MAX_PAYLOAD = 1200


def send_frame(conn, pkt_type: int, seq: int, payload: bytes = b""):
    hdr = struct.pack("!BII", pkt_type, seq, len(payload))
    conn.sendall(hdr + payload)


def recv_exact(conn, n):
    b = bytearray()
    while len(b) < n:
        c = conn.recv(n - len(b))
        if not c:
            return None
        b.extend(c)
    return bytes(b)


def recv_frame(conn):
    h = recv_exact(conn, 9)
    if not h:
        return None
    pkt_type, seq, ln = struct.unpack("!BII", h)
    payload = recv_exact(conn, ln) if ln else b""
    if payload is None:
        return None
    return pkt_type, seq, payload


def main():
    ap = argparse.ArgumentParser(description="USTPS native server (TLS 1.3)")
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=5443)
    ap.add_argument("--certfile", required=True)
    ap.add_argument("--keyfile", required=True)
    ap.add_argument("--video", required=True)
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    args = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(args.certfile, args.keyfile)
    if hasattr(ctx, "set_ciphersuites"):
        try:
            ctx.set_ciphersuites("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256")
        except Exception:
            pass

    import socket
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((args.bind_ip, args.bind_port))
    ls.listen(5)
    print(f"[USTPS-SERVER] tls://{args.bind_ip}:{args.bind_port}")

    while True:
        raw_conn, addr = ls.accept()
        print(f"[USTPS-SERVER] client {addr}")
        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
        except Exception:
            raw_conn.close()
            continue

        cmd = ["ffmpeg", "-re", "-i", args.video, "-c", "copy", "-mpegts_flags", "+resend_headers", "-f", "mpegts", "-"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)

        sent = {}
        pending = deque()
        retx = deque()
        next_seq = 1
        running = True
        lock = threading.Lock()

        def ctrl_loop():
            nonlocal running
            while running:
                fr = recv_frame(conn)
                if fr is None:
                    break
                t, s, _p = fr
                with lock:
                    if t == 2:  # ACK
                        sent.pop(s, None)
                    elif t == 3:  # NACK
                        if s in sent:
                            retx.append(s)
            running = False

        threading.Thread(target=ctrl_loop, daemon=True).start()

        try:
            while running:
                with lock:
                    while retx and running:
                        rs = retx.popleft()
                        item = sent.get(rs)
                        if item:
                            payload, _ts = item
                            send_frame(conn, 1, rs, payload)
                            sent[rs] = (payload, time.time())

                if proc.stdout is None:
                    break
                chunk = proc.stdout.read(MAX_PAYLOAD)
                if not chunk:
                    break

                with lock:
                    if len(sent) >= args.window:
                        now = time.time()
                        # coarse timeout retransmit
                        for s, (p, ts) in list(sent.items()):
                            if now - ts >= args.rto:
                                send_frame(conn, 1, s, p)
                                sent[s] = (p, now)
                        continue

                    seq = next_seq
                    next_seq += 1
                    sent[seq] = (chunk, time.time())

                send_frame(conn, 1, seq, chunk)
        except Exception:
            pass
        finally:
            running = False
            try:
                send_frame(conn, 5, 0, b"")
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
            try:
                proc.terminate()
            except Exception:
                pass
            print("[USTPS-SERVER] client disconnected")


if __name__ == "__main__":
    main()
