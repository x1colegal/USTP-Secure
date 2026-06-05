import argparse
import os
import threading
import time

from cryptography.hazmat.primitives.asymmetric import x25519

from aead_udp import AEADDatagramSocket, normalize_cipher_name
from packet import TYPE_ACK, TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, TYPE_RETRANSMIT_REQUEST, mkp
from tunnel_common import configure_tun, derive_session_key, load_private_key, load_public_key_value, open_tun, packet_summary, public_bytes, resolve_host_ip
from tunnel_proto import TYPE_AUTH, TYPE_AUTH_FAIL, TYPE_AUTH_OK, TYPE_CONFIG, TYPE_IP, TYPE_PING, TYPE_PONG, pack_tunnel_message, unpack_tunnel_message
from ustp import USTPReceiver, USTPSender, parse_packet

KEX_PREFIX = b"UTUN-KEX1\0"
SESSION_PREFIX = b"UTUN-SESSION1\0"


class TunnelSession:
    def __init__(self, addr, sender, receiver, session_key: bytes, cipher: str, client_pub: bytes, server_pub: bytes):
        self.addr = addr
        self.sender = sender
        self.receiver = receiver
        self.session_key = session_key
        self.cipher = cipher
        self.client_pub = client_pub
        self.server_pub = server_pub
        self.established = False
        self.last_rx = time.time()
        self.last_hello = time.time()
        self.closed = False


def parse_client_hello(payload: bytes):
    if not payload.startswith(KEX_PREFIX):
        return None
    rest = payload[len(KEX_PREFIX):]
    if len(rest) < 32:
        return None
    client_pub = rest[:32]
    cipher = None
    if len(rest) > 32:
        try:
            cipher = normalize_cipher_name(rest[32:].decode("ascii", "replace"))
        except Exception:
            cipher = None
    return client_pub, cipher


def main() -> None:
    ap = argparse.ArgumentParser(description="USTPS-Tunnel server")
    ap.add_argument("--bind-ip", required=True)
    ap.add_argument("--bind-port", type=int, default=5400)
    ap.add_argument("--server-private-key", required=True)
    ap.add_argument("--client-public-key", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--cipher", default="auto", help="auto | chacha20 | aes-256-gcm | aes-128-gcm")
    ap.add_argument("--tun-name", default="ustpst0")
    ap.add_argument("--tun-local-ip", default="10.77.0.1")
    ap.add_argument("--tun-peer-ip", default="10.77.0.2")
    ap.add_argument("--mtu", type=int, default=1100)
    ap.add_argument("--route", action="append", default=[])
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    ap.add_argument("--idle-timeout", type=float, default=15.0)
    ap.add_argument("--burst-limit", type=int, default=8)
    ap.add_argument("--pacing-ms", type=float, default=1.5)
    ap.add_argument("--max-pending", type=int, default=1024)
    ap.add_argument("--debug-packets", action="store_true")
    args = ap.parse_args()

    server_private = load_private_key(args.server_private_key)
    server_pub = public_bytes(server_private.public_key())
    allowed_client_pub = load_public_key_value(args.client_public_key)
    selected_cipher = None if args.cipher == "auto" else normalize_cipher_name(args.cipher)

    tun_fd, tun_name = open_tun(args.tun_name)
    configure_tun(tun_name, args.tun_local_ip, args.tun_peer_ip, args.mtu, args.route)
    print(f"[USTPS-TUNNEL-SERVER] tun={tun_name} local={args.tun_local_ip} peer={args.tun_peer_ip} mtu={args.mtu}")

    raw_sock = __import__("socket").socket(__import__("socket").AF_INET, __import__("socket").SOCK_DGRAM)
    raw_sock.settimeout(0.2)
    sock = AEADDatagramSocket(raw_sock, cipher_name=selected_cipher or "chacha20")
    sock.bind((args.bind_ip, args.bind_port))
    print(f"[USTPS-TUNNEL-SERVER] listen={args.bind_ip}:{args.bind_port} cipher={selected_cipher or 'auto'}")

    running = True
    session = None
    session_lock = threading.Lock()

    def close_session() -> None:
        nonlocal session
        with session_lock:
            current = session
            session = None
        if current is None or current.closed:
            return
        current.closed = True
        try:
            sock.clear_peer(current.addr)
        except Exception:
            pass
        try:
            current.sender.stop()
        except Exception:
            pass
        print("[USTPS-TUNNEL-SERVER] session closed")

    def send_tunnel(msg_type: int, payload: bytes = b"") -> None:
        with session_lock:
            current = session
        if current is None:
            return
        current.sender.queue_payload(pack_tunnel_message(msg_type, payload))

    def tun_loop() -> None:
        while running:
            try:
                packet = os.read(tun_fd, args.mtu)
            except OSError:
                break
            if not packet:
                continue
            with session_lock:
                current = session
            if current is None or not current.established:
                continue
            if args.debug_packets:
                print(f"[USTPS-TUNNEL-SERVER] TUN->NET {packet_summary(packet)}")
            current.sender.queue_payload(pack_tunnel_message(TYPE_IP, packet))

    def keepalive_loop() -> None:
        while running:
            with session_lock:
                current = session
            if current is not None:
                if time.time() - current.last_rx > args.idle_timeout:
                    close_session()
                    time.sleep(0.2)
                    continue
                if current.established:
                    current.sender.queue_payload(pack_tunnel_message(TYPE_PING, b"keepalive"))
            time.sleep(1.0)

    def nack_loop() -> None:
        while running:
            with session_lock:
                current = session
            if current is not None:
                current.receiver.maybe_nack()
            time.sleep(0.03)

    threading.Thread(target=tun_loop, daemon=True).start()
    threading.Thread(target=keepalive_loop, daemon=True).start()
    threading.Thread(target=nack_loop, daemon=True).start()

    try:
        while True:
            try:
                raw, addr = sock.recvfrom(65535)
            except Exception:
                continue
            pkt = parse_packet(raw)
            if not pkt:
                continue
            now = time.time()

            with session_lock:
                current = session

            if pkt.pkt_type == TYPE_HELLO:
                parsed = parse_client_hello(pkt.payload)
                if parsed is None:
                    continue
                client_pub, requested_cipher = parsed
                if client_pub != allowed_client_pub:
                    continue
                chosen_cipher = selected_cipher or requested_cipher or "chacha20"
                session_key = derive_session_key(server_private.exchange(x25519.X25519PublicKey.from_public_bytes(client_pub)), client_pub, server_pub, args.password)
                reply = SESSION_PREFIX + client_pub + server_pub + chosen_cipher.encode("ascii")
                if current is None:
                    sender = USTPSender(
                        sock=sock,
                        peer=addr,
                        window=args.window,
                        rto=args.rto,
                        congestion_control=True,
                        burst_limit=args.burst_limit,
                        pacing_interval=args.pacing_ms / 1000.0,
                        max_pending=args.max_pending,
                    )
                    receiver = USTPReceiver(sock=sock, peer=addr)
                    receiver.quiet_recv = True
                    sender.start()
                    current = TunnelSession(addr, sender, receiver, session_key, chosen_cipher, client_pub, server_pub)
                    session = current
                    print(f"[USTPS-TUNNEL-SERVER] client {addr[0]}:{addr[1]} cipher={chosen_cipher}")
                else:
                    if current.addr != addr:
                        sock.clear_peer(current.addr)
                        current.addr = addr
                        current.sender.peer = addr
                        current.receiver.peer = addr
                    current.session_key = session_key
                    current.cipher = chosen_cipher
                sock.set_peer_psk(addr, session_key, chosen_cipher)
                if args.debug_packets:
                    print(f"[USTPS-TUNNEL-SERVER] HELLO from {addr[0]}:{addr[1]} cipher={chosen_cipher}")
                sock.send_plain(mkp(TYPE_HELLO, payload=reply).to_bytes(), addr)
                current.last_hello = now
                current.last_rx = now
                continue

            if current is None or addr != current.addr:
                continue
            current.last_rx = now

            if pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, TYPE_HELLO):
                current.sender.on_control(pkt)
                continue
            if pkt.pkt_type == TYPE_CLOSE:
                close_session()
                continue
            if pkt.pkt_type != TYPE_DATA:
                continue

            payload = current.receiver.handle_data(pkt)
            if not payload:
                continue
            try:
                msg_type, msg_payload = unpack_tunnel_message(payload)
            except Exception:
                continue

            if msg_type == TYPE_AUTH:
                if args.debug_packets:
                    print("[USTPS-TUNNEL-SERVER] AUTH received")
                if msg_payload.decode("utf-8", "replace") != args.password:
                    current.sender.queue_payload(pack_tunnel_message(TYPE_AUTH_FAIL, b"bad password"))
                    print("[USTPS-TUNNEL-SERVER] auth failed")
                    continue
                if current.established:
                    if args.debug_packets:
                        print("[USTPS-TUNNEL-SERVER] re-sending CONFIG + AUTH_OK")
                    current.sender.queue_payload(pack_tunnel_message(TYPE_CONFIG, f"{args.tun_peer_ip},{args.tun_local_ip},{args.mtu}".encode("utf-8")))
                    current.sender.queue_payload(pack_tunnel_message(TYPE_AUTH_OK, b"ok"))
                    continue
                current.established = True
                config_payload = f"{args.tun_peer_ip},{args.tun_local_ip},{args.mtu}".encode("utf-8")
                current.sender.queue_payload(pack_tunnel_message(TYPE_CONFIG, config_payload))
                current.sender.queue_payload(pack_tunnel_message(TYPE_AUTH_OK, b"ok"))
                print("[USTPS-TUNNEL-SERVER] tunnel established")
                continue
            if not current.established:
                continue
            if msg_type == TYPE_IP:
                if args.debug_packets:
                    print(f"[USTPS-TUNNEL-SERVER] NET->TUN {packet_summary(msg_payload)}")
                os.write(tun_fd, msg_payload)
                continue
            if msg_type == TYPE_PING:
                current.sender.queue_payload(pack_tunnel_message(TYPE_PONG, b"pong"))
                continue
            if msg_type == TYPE_PONG:
                continue
    except KeyboardInterrupt:
        print("[USTPS-TUNNEL-SERVER] interrupted")
    finally:
        running = False
        close_session()
        try:
            os.close(tun_fd)
        except Exception:
            pass
        try:
            raw_sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
