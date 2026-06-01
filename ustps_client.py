import argparse
import socket
import ssl
import struct
import threading
import time


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
    ap = argparse.ArgumentParser(description="USTPS native client (TLS 1.3) -> TCP/UDP output")
    ap.add_argument("--server-ip", required=True)
    ap.add_argument("--server-port", type=int, default=5443)
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--cafile", default="")
    ap.add_argument("--output-mode", choices=["tcp", "udp"], default="tcp")
    ap.add_argument("--tcp-host", default="127.0.0.1")
    ap.add_argument("--tcp-port", type=int, default=1238)
    ap.add_argument("--udp-ip", default="127.0.0.1")
    ap.add_argument("--udp-port", type=int, default=1238)
    args = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if hasattr(ctx, "set_ciphersuites"):
        try:
            ctx.set_ciphersuites("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256")
        except Exception:
            pass
    if args.verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        if args.cafile:
            ctx.load_verify_locations(args.cafile)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    out_clients = []
    out_lock = threading.Lock()
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    if args.output_mode == "tcp":
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((args.tcp_host, args.tcp_port))
        ls.listen(5)

        def accept_loop():
            while True:
                c, a = ls.accept()
                with out_lock:
                    out_clients.append(c)
                print(f"[USTPS-CLIENT] TCP client {a}")

        threading.Thread(target=accept_loop, daemon=True).start()

        def output_send(b: bytes):
            dead = []
            with out_lock:
                for c in out_clients:
                    try:
                        c.sendall(b)
                    except Exception:
                        dead.append(c)
                for d in dead:
                    try:
                        d.close()
                    except Exception:
                        pass
                    out_clients.remove(d)
    else:
        def output_send(b: bytes):
            udp_sock.sendto(b, (args.udp_ip, args.udp_port))

    print(f"[USTPS-CLIENT] connecting tls://{args.server_ip}:{args.server_port}")

    while True:
        try:
            raw = socket.create_connection((args.server_ip, args.server_port), timeout=10)
            conn = ctx.wrap_socket(raw, server_hostname=args.server_ip)
        except Exception:
            time.sleep(1)
            continue

        print("[USTPS-CLIENT] connected")
        out_by_seq = {}
        next_seq = 1

        try:
            while True:
                fr = recv_frame(conn)
                if fr is None:
                    break
                t, seq, payload = fr
                if t == 5:
                    break
                if t != 1:
                    continue

                send_frame(conn, 2, seq, b"")
                out_by_seq[seq] = payload

                # selective-repair style: ask missing while keeping future packets
                if seq > next_seq:
                    for miss in range(next_seq, seq):
                        if miss not in out_by_seq:
                            send_frame(conn, 3, miss, b"")

                while next_seq in out_by_seq:
                    output_send(out_by_seq.pop(next_seq))
                    next_seq += 1
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
            print("[USTPS-CLIENT] disconnected, reconnecting...")
            time.sleep(1)


if __name__ == "__main__":
    main()
