import argparse
import json
import os
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


def load_tofu(path: str) -> dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}
    return {}


def save_tofu(path: str, data: dict[str, str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def confirm_regen(peer_label: str) -> bool:
    if not os.isatty(0):
        return False
    answer = input(f"TOFU key changed for {peer_label}. Accept and replace stored key? [y/N] ").strip().lower()
    return answer in ("y", "yes")


def check_tofu(path: str, peer_label: str, server_pub: bytes, allow_regen: bool = False) -> None:
    db = load_tofu(path)
    fp = server_pub.hex()
    known = db.get(peer_label)
    if known is None:
        db[peer_label] = fp
        save_tofu(path, db)
        print(f"[USTP-CLIENT] TOFU trust established for {peer_label}")
        return
    if known != fp:
        if allow_regen and confirm_regen(peer_label):
            db[peer_label] = fp
            save_tofu(path, db)
            print(f"[USTP-CLIENT] TOFU key replaced for {peer_label}")
            return
        raise SystemExit(f"TOFU mismatch for {peer_label}: possible MITM or server key change")


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
    ap.add_argument("--reorder-buffer-ms", type=int, default=350, help="Initial local playout buffer delay for TCP output or ordered UDP mode")
    ap.add_argument("--keepalive-interval", type=float, default=0.12)
    ap.add_argument("--cipher", default="chacha20", help="chacha20 | aes-256-gcm | aes-128-gcm")
    ap.add_argument("--tofu-file", default=os.path.expanduser("~/.ustps_known_hosts.json"))
    ap.add_argument("--regen-key", action="store_true", help="Allow replacing a stored TOFU server key after interactive confirmation")
    args = ap.parse_args()

    resolved_peer_ip = socket.gethostbyname(args.peer_ip)
    tofu_label = f"{args.peer_ip}:{args.peer_port}"

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
            while running:
                try:
                    c, a = tsock.accept()
                except Exception:
                    if running:
                        continue
                    break
                with cl_lock:
                    clients.append(c)
                if running:
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
    last_stall_log_ts = 0.0
    threads: list[threading.Thread] = []

    def keepalive_loop() -> None:
        nonlocal last_kex_ts
        while running:
            with key_lock:
                hello_payload = HELLO_PREFIX + client_pub + selected_cipher.encode("ascii")
            hello = mkp(TYPE_HELLO, payload=hello_payload)
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
                            if running:
                                print("[USTP-CLIENT] ignored stale session response")
                            continue
                        if session_cipher != selected_cipher:
                            raise SystemExit(
                                f"Server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}"
                            )
                        check_tofu(args.tofu_file, tofu_label, server_pub, allow_regen=args.regen_key)
                        server_public = x25519.X25519PublicKey.from_public_bytes(server_pub)
                        session_key = derive_session_key(client_private.exchange(server_public), client_pub, server_pub)
                    usock.set_peer_psk(peer, session_key, session_cipher)
                    session_ready = True
                    last_valid_data_ts = time.time()
                    if running:
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
                    if args.output_mode == "tcp" and time.time() < ordered_release_at:
                        break
                    if args.output_mode == "udp" and not args.udp_unordered_live and time.time() < ordered_release_at:
                        break
                    chunk = out_by_pos.pop(next_out_pos)
                    if args.output_mode == "tcp" or (args.output_mode == "udp" and not args.udp_unordered_live):
                        output_send(chunk)
                    next_out_pos += len(chunk)

                if pkt.stream_pos > next_out_pos:
                    now = time.time()
                    if now - last_gap_log >= 0.25:
                        if running:
                            print(
                                f"[USTP-CLIENT] GAP next_pos={next_out_pos} "
                                f"arrived_pos={pkt.stream_pos} seq={pkt.seq} "
                                f"reorder_q={len(out_by_pos)}"
                            )
                        last_gap_log = now
                elif pkt.stream_pos < next_out_pos:
                    if running:
                        print(
                            f"[USTP-CLIENT] RECOVERY seq={pkt.seq} pos={pkt.stream_pos} "
                            f"reconstructed_until={next_out_pos}"
                        )

    if args.output_mode == "tcp":
        threads.append(threading.Thread(target=accept_loop, daemon=True, name="ustps-accept"))
    threads.append(threading.Thread(target=keepalive_loop, daemon=True, name="ustps-keepalive"))
    threads.append(threading.Thread(target=nack_loop, daemon=True, name="ustps-nack"))
    threads.append(threading.Thread(target=recv_loop, daemon=True, name="ustps-recv"))
    for thread in threads:
        thread.start()

    if args.output_mode == "tcp":
        print(f"[USTP-CLIENT] TCP output on tcp://{args.tcp_host}:{args.tcp_port}")
    else:
        print(f"[USTP-CLIENT] UDP output on udp://{args.udp_ip}:{args.udp_port}")

    try:
        while True:
            now = time.time()
            if not session_ready and now - last_rx_ts > 12.0:
                raise SystemExit("No USTPS session established (server offline or handshake failed)")
            if session_ready and last_valid_data_ts and now - last_valid_data_ts > 6.0 and now - last_stall_log_ts > 6.0:
                if running:
                    print("[USTP-CLIENT] no data for 6s; keeping the same session key and waiting")
                last_stall_log_ts = now
            if session_ready and last_valid_data_ts and now - last_valid_data_ts > 60.0 and now - last_stall_log_ts > 6.0:
                if running:
                    print("[USTP-CLIENT] no data for 60s; session kept alive, still waiting for stream")
                last_stall_log_ts = now
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("[USTP-CLIENT] Interrupted")
    finally:
        running = False
        try:
            raw_usock.close()
        except Exception:
            pass
        try:
            usock_out.close()
        except Exception:
            pass
        if args.output_mode == "tcp":
            try:
                tsock.close()
            except Exception:
                pass
            with cl_lock:
                for c in clients:
                    try:
                        c.close()
                    except Exception:
                        pass
                clients.clear()
        for thread in threads:
            try:
                thread.join(timeout=0.2)
            except Exception:
                pass


if __name__ == "__main__":
    main()
