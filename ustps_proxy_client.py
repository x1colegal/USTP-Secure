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
    ap = argparse.ArgumentParser(description='USTPS proxy client (TLS 1.3)')
    ap.add_argument('--server-ip', required=True)
    ap.add_argument('--server-port', type=int, default=5443)
    ap.add_argument('--verify', action='store_true')
    ap.add_argument('--cafile', default='')
    ap.add_argument('--udp-bind-ip', default='0.0.0.0')
    ap.add_argument('--udp-bind-port', type=int, default=40010)
    ap.add_argument('--udp-local-target-ip', default='127.0.0.1')
    ap.add_argument('--udp-local-target-port', type=int, default=40000)
    args = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if hasattr(ctx, 'set_ciphersuites'):
        try:
            ctx.set_ciphersuites('TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256')
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

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((args.udp_bind_ip, args.udp_bind_port))
    local_target = (args.udp_local_target_ip, args.udp_local_target_port)

    print(f'[USTPS-CLIENT] udp://{args.udp_bind_ip}:{args.udp_bind_port} <-> tls://{args.server_ip}:{args.server_port}')
    while True:
        tcp = socket.create_connection((args.server_ip, args.server_port), timeout=10)
        tls = ctx.wrap_socket(tcp, server_hostname=args.server_ip)
        running = True

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

        def tls_to_udp():
            nonlocal running
            try:
                while running:
                    frame = recv_frame(tls)
                    if frame is None:
                        break
                    udp.sendto(frame, local_target)
            finally:
                running = False

        t1 = threading.Thread(target=udp_to_tls, daemon=True)
        t2 = threading.Thread(target=tls_to_udp, daemon=True)
        t1.start(); t2.start()
        t2.join()
        running = False
        try: tls.close()
        except Exception: pass
        print('[USTPS-CLIENT] reconnecting...')


if __name__ == '__main__':
    main()
