import argparse
import socket
import ssl
import struct
import threading


def recv_exact(conn, n):
    b = bytearray()
    while len(b) < n:
        c = conn.recv(n - len(b))
        if not c:
            return None
        b.extend(c)
    return bytes(b)


def recv_frame(conn):
    h = recv_exact(conn, 2)
    if not h:
        return None
    ln = struct.unpack('!H', h)[0]
    if ln == 0:
        return b''
    return recv_exact(conn, ln)


def send_frame(conn, payload: bytes):
    conn.sendall(struct.pack('!H', len(payload)) + payload)


def main():
    ap = argparse.ArgumentParser(description='USTPS proxy server (TLS 1.3)')
    ap.add_argument('--bind-ip', default='0.0.0.0')
    ap.add_argument('--bind-port', type=int, default=5443)
    ap.add_argument('--certfile', required=True)
    ap.add_argument('--keyfile', required=True)
    ap.add_argument('--udp-upstream-ip', default='127.0.0.1')
    ap.add_argument('--udp-upstream-port', type=int, default=40001)
    args = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(args.certfile, args.keyfile)
    if hasattr(ctx, 'set_ciphersuites'):
        try:
            ctx.set_ciphersuites('TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256')
        except Exception:
            pass

    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((args.bind_ip, args.bind_port))
    ls.listen(5)
    print(f'[USTPS-SERVER] tls://{args.bind_ip}:{args.bind_port} -> udp://{args.udp_upstream_ip}:{args.udp_upstream_port}')

    while True:
        c, a = ls.accept()
        print(f'[USTPS-SERVER] client {a}')
        try:
            tls = ctx.wrap_socket(c, server_side=True)
        except Exception:
            c.close()
            continue

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(('0.0.0.0', 0))
        upstream = (args.udp_upstream_ip, args.udp_upstream_port)

        running = True

        def tls_to_udp():
            nonlocal running
            try:
                while running:
                    frame = recv_frame(tls)
                    if frame is None:
                        break
                    udp.sendto(frame, upstream)
            finally:
                running = False

        def udp_to_tls():
            nonlocal running
            try:
                while running:
                    b, _ = udp.recvfrom(65535)
                    send_frame(tls, b)
            except Exception:
                pass
            finally:
                running = False

        t1 = threading.Thread(target=tls_to_udp, daemon=True)
        t2 = threading.Thread(target=udp_to_tls, daemon=True)
        t1.start(); t2.start()
        t1.join(timeout=None)
        running = False
        try: tls.close()
        except Exception: pass
        udp.close()
        print('[USTPS-SERVER] client disconnected')


if __name__ == '__main__':
    main()
