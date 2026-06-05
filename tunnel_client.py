import argparse
import os
import threading
import time

from cryptography.hazmat.primitives.asymmetric import x25519

from aead_udp import AEADDatagramSocket, normalize_cipher_name
from packet import TYPE_ACK, TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, TYPE_RETRANSMIT_REQUEST, mkp
from tunnel_common import check_tofu, configure_tun, derive_session_key, load_private_key, load_public_key_value, open_tun, packet_summary, public_bytes, resolve_host_ip, tunnel_label
from tunnel_proto import TYPE_AUTH, TYPE_AUTH_FAIL, TYPE_AUTH_OK, TYPE_CONFIG, TYPE_IP, TYPE_PING, TYPE_PONG, pack_tunnel_message, unpack_tunnel_message
from ustp import USTPReceiver, USTPSender, parse_packet

KEX_PREFIX = b"UTUN-KEX1\0"
SESSION_PREFIX = b"UTUN-SESSION1\0"


def main() -> None:
    ap = argparse.ArgumentParser(description="USTPS-Tunnel client")
    ap.add_argument("--server-ip", required=True)
    ap.add_argument("--server-port", type=int, default=5400)
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=0)
    ap.add_argument("--client-private-key", required=True)
    ap.add_argument("--server-public-key", default=None, help="Optional pinned server public key file; if omitted, TOFU is used")
    ap.add_argument("--password", required=True)
    ap.add_argument("--cipher", default="aes-256-gcm")
    ap.add_argument("--tun-name", default="ustpt0")
    ap.add_argument("--route", action="append", default=[])
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    ap.add_argument("--burst-limit", type=int, default=8)
    ap.add_argument("--pacing-ms", type=float, default=1.5)
    ap.add_argument("--max-pending", type=int, default=1024)
    ap.add_argument("--tofu-file", default=os.path.expanduser("~/.ustps_tunnel_known_hosts.json"))
    ap.add_argument("--regen-key", action="store_true", help="Allow replacing a stored TOFU server key after interactive confirmation")
    ap.add_argument("--debug-packets", action="store_true")
    args = ap.parse_args()

    server_ip = resolve_host_ip(args.server_ip)
    selected_cipher = normalize_cipher_name(args.cipher)
    client_private = load_private_key(args.client_private_key)
    client_pub = public_bytes(client_private.public_key())
    expected_server_pub = load_public_key_value(args.server_public_key) if args.server_public_key else None
    server_label = tunnel_label(args.server_ip, args.server_port)

    tun_fd, tun_name = open_tun(args.tun_name)
    print(f"[USTPS-TUNNEL-CLIENT] tun={tun_name} awaiting config from server")

    raw_sock = __import__("socket").socket(__import__("socket").AF_INET, __import__("socket").SOCK_DGRAM)
    raw_sock.settimeout(0.2)
    sock = AEADDatagramSocket(raw_sock, cipher_name=selected_cipher)
    sock.bind((args.bind_ip, args.bind_port))
    peer = (server_ip, args.server_port)
    sender = USTPSender(
        sock=sock,
        peer=peer,
        window=args.window,
        rto=args.rto,
        congestion_control=True,
        burst_limit=args.burst_limit,
        pacing_interval=args.pacing_ms / 1000.0,
        max_pending=args.max_pending,
    )
    receiver = USTPReceiver(sock=sock, peer=peer)
    receiver.quiet_recv = True
    sender.start()

    running = True
    session_ready = False
    auth_ok = False
    config_done = False
    last_rx = time.time()

    def tun_loop() -> None:
        while running:
            if not auth_ok or not config_done:
                time.sleep(0.1)
                continue
            try:
                packet = os.read(tun_fd, 1100)
            except OSError:
                break
            if not packet:
                continue
            if args.debug_packets:
                print(f"[USTPS-TUNNEL-CLIENT] TUN->NET {packet_summary(packet)}")
            sender.queue_payload(pack_tunnel_message(TYPE_IP, packet))

    def keepalive_loop() -> None:
        while running:
            if not session_ready:
                hello_payload = KEX_PREFIX + client_pub + selected_cipher.encode("ascii")
                if args.debug_packets:
                    print("[USTPS-TUNNEL-CLIENT] sending HELLO")
                sock.send_plain(mkp(TYPE_HELLO, payload=hello_payload).to_bytes(), peer)
            if session_ready and not auth_ok:
                if args.debug_packets:
                    print("[USTPS-TUNNEL-CLIENT] sending AUTH")
                sender.queue_payload(pack_tunnel_message(TYPE_AUTH, args.password.encode("utf-8")))
            if auth_ok:
                sender.queue_payload(pack_tunnel_message(TYPE_PING, b"keepalive"))
            time.sleep(1.0)

    def nack_loop() -> None:
        while running:
            if session_ready:
                receiver.maybe_nack()
            time.sleep(0.03)

    threading.Thread(target=tun_loop, daemon=True).start()
    threading.Thread(target=keepalive_loop, daemon=True).start()
    threading.Thread(target=nack_loop, daemon=True).start()

    print(f"[USTPS-TUNNEL-CLIENT] peer={args.server_ip} resolved={server_ip}:{args.server_port} cipher={selected_cipher}")

    try:
        while True:
            try:
                raw, addr = sock.recvfrom(65535)
            except Exception:
                if time.time() - last_rx > 12.0 and not session_ready:
                    raise SystemExit("Tunnel server did not answer")
                continue
            if addr[0] != server_ip:
                continue
            pkt = parse_packet(raw)
            if not pkt:
                continue
            last_rx = time.time()
            if pkt.pkt_type == TYPE_HELLO and pkt.payload.startswith(SESSION_PREFIX):
                rest = pkt.payload[len(SESSION_PREFIX):]
                if len(rest) >= 64:
                    if session_ready:
                        continue
                    echoed_client_pub = rest[:32]
                    server_pub = rest[32:64]
                    session_cipher = rest[64:].decode("ascii", "replace") or selected_cipher
                    if echoed_client_pub != client_pub:
                        continue
                    if expected_server_pub is not None:
                        if server_pub != expected_server_pub:
                            raise SystemExit("Server public key mismatch")
                    else:
                        check_tofu(args.tofu_file, server_label, server_pub, allow_regen=args.regen_key)
                    if session_cipher != selected_cipher:
                        raise SystemExit(f"Server negotiated {session_cipher}, expected {selected_cipher}")
                    session_key = derive_session_key(client_private.exchange(x25519.X25519PublicKey.from_public_bytes(server_pub)), client_pub, server_pub, args.password)
                    sock.set_peer_psk(peer, session_key, session_cipher)
                    session_ready = True
                    print(f"[USTPS-TUNNEL-CLIENT] secure session aead={session_cipher}")
                    if args.debug_packets:
                        print("[USTPS-TUNNEL-CLIENT] session_ready=yes")
                    sender.queue_payload(pack_tunnel_message(TYPE_AUTH, args.password.encode("utf-8")))
                continue
            if pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, TYPE_HELLO):
                sender.on_control(pkt)
                continue
            if pkt.pkt_type == TYPE_CLOSE:
                continue
            if pkt.pkt_type != TYPE_DATA:
                continue
            payload = receiver.handle_data(pkt)
            if not payload:
                continue
            try:
                msg_type, msg_payload = unpack_tunnel_message(payload)
            except Exception:
                continue
            if msg_type == TYPE_AUTH_FAIL:
                raise SystemExit("Tunnel authentication failed")
            if msg_type == TYPE_CONFIG:
                parts = msg_payload.decode("utf-8", "replace").split(",")
                if len(parts) == 3:
                    local_ip, peer_ip, mtu_str = parts
                    mtu = int(mtu_str)
                    configure_tun(tun_name, local_ip, peer_ip, mtu, args.route)
                    config_done = True
                    print(f"[USTPS-TUNNEL-CLIENT] configured tun={tun_name} local={local_ip} peer={peer_ip} mtu={mtu}")
                    if args.debug_packets:
                        print("[USTPS-TUNNEL-CLIENT] config_done=yes")
                continue
            if msg_type == TYPE_AUTH_OK:
                auth_ok = True
                print("[USTPS-TUNNEL-CLIENT] tunnel established")
                if args.debug_packets:
                    print("[USTPS-TUNNEL-CLIENT] auth_ok=yes")
                continue
            if not auth_ok:
                continue
            if msg_type == TYPE_IP:
                if args.debug_packets:
                    print(f"[USTPS-TUNNEL-CLIENT] NET->TUN {packet_summary(msg_payload)}")
                os.write(tun_fd, msg_payload)
                continue
            if msg_type == TYPE_PING:
                sender.queue_payload(pack_tunnel_message(TYPE_PONG, b"pong"))
                continue
            if msg_type == TYPE_PONG:
                continue
    except KeyboardInterrupt:
        print("[USTPS-TUNNEL-CLIENT] interrupted")
    finally:
        running = False
        try:
            sock.sendto(mkp(TYPE_CLOSE).to_bytes(), peer)
        except Exception:
            pass
        sender.stop()
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
