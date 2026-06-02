import argparse
import socket
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from packet import TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, mkp
from ustp import USTPReceiver, parse_packet
from aead_udp import AEADDatagramSocket, normalize_cipher_name


HELLO_PREFIX = b"USTPS-KEX1\0"
SESSION_PREFIX = b"USTPS-SESSION1\0"


def public_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def derive_session_key(shared: bytes, client_pub: bytes, server_pub: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=client_pub + server_pub,
        info=b"USTPS-X25519-session-v1",
    ).derive(shared)


def main() -> None:
    ap = argparse.ArgumentParser(description="USTP Client: USTP/UDP -> TCP or UDP output")
    ap.add_argument("--peer-ip", required=True)
    ap.add_argument("--peer-port", type=int, default=40001)
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=0)
    ap.add_argument("--tcp-host", default="127.0.0.1")
    ap.add_argument("--tcp-port", type=int, default=1238)
    ap.add_argument("--output-mode", choices=["tcp", "udp"], default="tcp")
    ap.add_argument("--udp-ip", default="127.0.0.1")
    ap.add_argument("--udp-port", type=int, default=1238)
    ap.add_argument("--udp-unordered-live", action="store_true", help="Immediate out-of-order UDP output (may corrupt generic players)")
    ap.add_argument("--reorder-buffer-ms", type=int, default=80, help="Initial playout buffer delay for ordered UDP mode")
    ap.add_argument("--keepalive-interval", type=float, default=0.12)
    ap.add_argument("--cipher", default="chacha20", help="chacha20 | aes-256-gcm | aes-128-gcm")
    args = ap.parse_args()

    resolved_peer_ip = socket.gethostbyname(args.peer_ip)

    raw_usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    selected_cipher = normalize_cipher_name(args.cipher)
    usock = AEADDatagramSocket(raw_usock, cipher_name=selected_cipher)
    usock.bind((args.bind_ip, args.bind_port))
    peer = (resolved_peer_ip, args.peer_port)
    recv = USTPReceiver(sock=usock, peer=peer)
    key_lock = threading.Lock()
    client_private = x25519.X25519PrivateKey.generate()
    client_pub = public_bytes(client_private.public_key())
    session_ready = False
    last_kex_ts = 0.0

    local_ip, local_port = usock.getsockname()
    print(f"[USTP-CLIENT] local bind {local_ip}:{local_port}")
    print(f"[USTP-CLIENT] peer {args.peer_ip} resolved={resolved_peer_ip}:{peer[1]}")
    print(f"[USTP-CLIENT] aead cipher={selected_cipher}")

    out_by_pos = {}
    next_out_pos = 0
    ordered_release_at = time.time() + (args.reorder_buffer_ms / 1000.0)
    reorder_lock = threading.Lock()
    last_gap_log = 0.0

    clients = []
    cl_lock = threading.Lock()
    usock_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    if args.output_mode == "tcp":
        tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tsock.bind((args.tcp_host, args.tcp_port))
        tsock.listen(5)

        def accept_loop() -> None:
            while True:
                try:
                    c, a = tsock.accept()
                except Exception:
                    continue
                with cl_lock:
                    clients.append(c)
                print(f"[USTP-CLIENT] TCP client {a}")

        def output_send(data: bytes) -> None:
            dead = []
            with cl_lock:
                for c in clients:
                    try:
                        c.sendall(data)
                    except Exception:
                        dead.append(c)
                for d in dead:
                    try:
                        d.close()
                    except Exception:
                        pass
                    clients.remove(d)
    else:
        def accept_loop() -> None:
            return

        def output_send(data: bytes) -> None:
            usock_out.sendto(data, (args.udp_ip, args.udp_port))

    running = True
    last_rx_ts = time.time()
    last_valid_data_ts = 0.0
    last_rekey_ts = 0.0

    def rotate_key() -> None:
        nonlocal client_private, client_pub, session_ready, last_kex_ts, last_rekey_ts, last_rx_ts
        with key_lock:
            client_private = x25519.X25519PrivateKey.generate()
            client_pub = public_bytes(client_private.public_key())
            session_ready = False
            last_kex_ts = 0.0
            last_rx_ts = time.time()
            last_rekey_ts = time.time()
            usock.clear_peer(peer)
        print("[USTP-CLIENT] rekey requested")

    def keepalive_loop() -> None:
        nonlocal last_kex_ts
        while running:
            if session_ready:
                hello_payload = (48).to_bytes(2, "big")
            else:
                with key_lock:
                    hello_payload = HELLO_PREFIX + client_pub
            hello = mkp(TYPE_HELLO, payload=hello_payload)
            if session_ready:
                usock.sendto(hello.to_bytes(), peer)
            else:
                usock.send_plain(hello.to_bytes(), peer)
                last_kex_ts = time.time()
            time.sleep(args.keepalive_interval)

    def nack_loop() -> None:
        while running:
            if session_ready:
                recv.maybe_nack()
            time.sleep(0.03)

    def recv_loop() -> None:
        nonlocal next_out_pos, last_gap_log, last_rx_ts, last_valid_data_ts, session_ready
        while running:
            try:
                raw, addr = usock.recvfrom(65535)
            except Exception:
                continue
            if addr[0] != resolved_peer_ip:
                continue
            pkt = parse_packet(raw)
            if not pkt:
                continue
            last_rx_ts = time.time()
            if pkt.pkt_type == TYPE_HELLO and pkt.payload.startswith(SESSION_PREFIX):
                rest = pkt.payload[len(SESSION_PREFIX) :]
                if len(rest) >= 64:
                    echoed_client_pub = rest[:32]
                    server_pub = rest[32:64]
                    session_cipher = rest[64:].decode("ascii", "replace") or selected_cipher
                    with key_lock:
                        if echoed_client_pub != client_pub:
                            print("[USTP-CLIENT] ignored stale session response")
                            continue
                        server_public = x25519.X25519PublicKey.from_public_bytes(server_pub)
                        session_key = derive_session_key(client_private.exchange(server_public), client_pub, server_pub)
                    usock.set_peer_psk(peer, session_key, session_cipher)
                    session_ready = True
                    last_valid_data_ts = time.time()
                    print(f"[USTP-CLIENT] session aead cipher={session_cipher}")
                continue
            if pkt.pkt_type == TYPE_CLOSE:
                continue
            if pkt.pkt_type != TYPE_DATA:
                continue

            last_valid_data_ts = time.time()
            recv.handle_data(pkt)
            if args.output_mode == "udp" and args.udp_unordered_live:
                output_send(pkt.payload)

            with reorder_lock:
                out_by_pos[pkt.stream_pos] = pkt.payload
                while next_out_pos in out_by_pos:
                    if args.output_mode == "udp" and not args.udp_unordered_live and time.time() < ordered_release_at:
                        break
                    chunk = out_by_pos.pop(next_out_pos)
                    if args.output_mode == "tcp" or (args.output_mode == "udp" and not args.udp_unordered_live):
                        output_send(chunk)
                    next_out_pos += len(chunk)

                if pkt.stream_pos > next_out_pos:
                    now = time.time()
                    if now - last_gap_log >= 0.25:
                        print(
                            f"[USTP-CLIENT] GAP next_pos={next_out_pos} "
                            f"arrived_pos={pkt.stream_pos} seq={pkt.seq} "
                            f"reorder_q={len(out_by_pos)}"
                        )
                        last_gap_log = now
                elif pkt.stream_pos < next_out_pos:
                    print(
                        f"[USTP-CLIENT] RECOVERY seq={pkt.seq} pos={pkt.stream_pos} "
                        f"reconstructed_until={next_out_pos}"
                    )

    if args.output_mode == "tcp":
        threading.Thread(target=accept_loop, daemon=True).start()
    threading.Thread(target=keepalive_loop, daemon=True).start()
    threading.Thread(target=nack_loop, daemon=True).start()
    threading.Thread(target=recv_loop, daemon=True).start()

    if args.output_mode == "tcp":
        print(f"[USTP-CLIENT] TCP output on tcp://{args.tcp_host}:{args.tcp_port}")
    else:
        print(f"[USTP-CLIENT] UDP output on udp://{args.udp_ip}:{args.udp_port}")

    try:
        while True:
            now = time.time()
            if not session_ready and now - last_rx_ts > 12.0:
                raise SystemExit("No USTPS session established (server offline or handshake failed)")
            if session_ready and last_valid_data_ts and now - last_valid_data_ts > 6.0 and now - last_rekey_ts > 6.0:
                rotate_key()
            if session_ready and last_valid_data_ts and now - last_valid_data_ts > 60.0:
                raise SystemExit("No valid encrypted data received for 60s (server offline or session lost)")
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("[USTP-CLIENT] Interrupted")
    finally:
        running = False


if __name__ == "__main__":
    main()
