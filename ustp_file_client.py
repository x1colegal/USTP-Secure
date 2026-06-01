import argparse
import pathlib
import socket
import struct
import threading
import time
from typing import Optional, Tuple

from packet import TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, mkp
from ustp import USTPReceiver, parse_packet

APP_HDR = "!BI"  # kind, value
APP_HDR_SIZE = struct.calcsize(APP_HDR)


def main() -> None:
    ap = argparse.ArgumentParser(description="USTP file receiver")
    ap.add_argument("--peer-ip", required=True)
    ap.add_argument("--peer-port", type=int, default=41001)
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=41000)
    ap.add_argument("--dst", required=True, help="destination directory")
    ap.add_argument("--keepalive-interval", type=float, default=0.2)
    args = ap.parse_args()

    dst = pathlib.Path(args.dst).resolve()
    dst.mkdir(parents=True, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind_ip, args.bind_port))
    peer = (args.peer_ip, args.peer_port)

    recv = USTPReceiver(sock=sock, peer=peer)

    running = True

    def keepalive_loop() -> None:
        while running:
            sock.sendto(mkp(TYPE_HELLO, payload=(64).to_bytes(2, "big")).to_bytes(), peer)
            time.sleep(args.keepalive_interval)

    def nack_loop() -> None:
        while running:
            recv.maybe_nack()
            time.sleep(0.03)

    threading.Thread(target=keepalive_loop, daemon=True).start()
    threading.Thread(target=nack_loop, daemon=True).start()

    cur_file = None
    cur_path: Optional[pathlib.Path] = None
    cur_expected = 0
    cur_written = 0

    def close_current() -> None:
        nonlocal cur_file, cur_path, cur_expected, cur_written
        if cur_file:
            cur_file.close()
            print(f"[USTP-FILE-CLIENT] saved {cur_path} ({cur_written}/{cur_expected})")
        cur_file = None
        cur_path = None
        cur_expected = 0
        cur_written = 0

    try:
        while True:
            raw, addr = sock.recvfrom(65535)
            if addr[0] != args.peer_ip:
                continue
            pkt = parse_packet(raw)
            if not pkt:
                continue

            if pkt.pkt_type == TYPE_CLOSE:
                break

            if pkt.pkt_type != TYPE_DATA:
                continue

            out = recv.handle_data(pkt)
            if not out:
                continue

            # parse possibly multiple app frames in one ordered output block
            i = 0
            while i + APP_HDR_SIZE <= len(out):
                kind, val = struct.unpack(APP_HDR, out[i:i + APP_HDR_SIZE])
                i += APP_HDR_SIZE

                if kind == 1:
                    name_len = val
                    if i + name_len + 8 > len(out):
                        raise RuntimeError("meta frame split not supported in this PoC")
                    rel = out[i:i + name_len].decode("utf-8", errors="replace")
                    i += name_len
                    size = struct.unpack("!Q", out[i:i + 8])[0]
                    i += 8

                    close_current()
                    target = (dst / rel).resolve()
                    target.parent.mkdir(parents=True, exist_ok=True)
                    cur_file = target.open("wb")
                    cur_path = target
                    cur_expected = size
                    cur_written = 0
                    print(f"[USTP-FILE-CLIENT] receiving {rel} ({size} bytes)")

                elif kind == 2:
                    chunk_len = val
                    if i + chunk_len > len(out):
                        raise RuntimeError("data frame split not supported in this PoC")
                    if cur_file is None:
                        # ignore data until meta arrives
                        i += chunk_len
                        continue
                    cur_file.write(out[i:i + chunk_len])
                    cur_written += chunk_len
                    i += chunk_len

                elif kind == 3:
                    close_current()

                else:
                    raise RuntimeError(f"unknown frame kind {kind}")

        close_current()
        print("[USTP-FILE-CLIENT] transfer finished")
    except KeyboardInterrupt:
        print("[USTP-FILE-CLIENT] interrupted")
    finally:
        running = False


if __name__ == "__main__":
    main()
