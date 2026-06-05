import base64
import hashlib
import json
import os
import socket
import subprocess
from typing import Tuple

import fcntl
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


def public_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def private_bytes(privkey) -> bytes:
    return privkey.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def generate_keypair() -> tuple[bytes, bytes]:
    priv = x25519.X25519PrivateKey.generate()
    pub = public_bytes(priv.public_key())
    return private_bytes(priv), pub


def save_key_file(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(data).decode("ascii") + "\n")
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def load_key_file(path: str) -> bytes:
    with open(path, "r", encoding="utf-8") as f:
        data = f.read().strip()
    return base64.b64decode(data)


def load_private_key(path: str) -> x25519.X25519PrivateKey:
    raw = load_key_file(path)
    if len(raw) != 32:
        raise ValueError(f"bad private key length in {path}")
    return x25519.X25519PrivateKey.from_private_bytes(raw)


def load_public_key(path: str) -> bytes:
    raw = load_key_file(path)
    if len(raw) != 32:
        raise ValueError(f"bad public key length in {path}")
    return raw


def load_public_key_value(value: str) -> bytes:
    if os.path.exists(value):
        return load_public_key(value)
    raw = base64.b64decode(value.strip())
    if len(raw) != 32:
        raise ValueError("bad public key length")
    return raw


def derive_session_key(shared: bytes, client_pub: bytes, server_pub: bytes, password: str) -> bytes:
    salt = client_pub + server_pub + hashlib.sha256(password.encode("utf-8")).digest()
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        info=b"USTPS-TUNNEL-X25519-session-v1",
    ).derive(shared)


def resolve_host_ip(host: str) -> str:
    return socket.gethostbyname(host)


def open_tun(name: str) -> tuple[int, str]:
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifreq = struct.pack("16sH", name.encode("ascii")[:15], IFF_TUN | IFF_NO_PI)
    res = fcntl.ioctl(fd, TUNSETIFF, ifreq)
    real_name = struct.unpack("16sH", res)[0].split(b"\0", 1)[0].decode("ascii")
    return fd, real_name


def configure_tun(ifname: str, local_ip: str, peer_ip: str, mtu: int, routes: list[str] | None = None) -> None:
    subprocess.run(["ip", "link", "set", "dev", ifname, "mtu", str(mtu)], check=True)
    subprocess.run(["ip", "addr", "flush", "dev", ifname], check=True)
    subprocess.run(["ip", "addr", "replace", local_ip, "peer", peer_ip, "dev", ifname], check=True)
    subprocess.run(["ip", "link", "set", "dev", ifname, "up"], check=True)
    for route in routes or []:
        subprocess.run(["ip", "route", "replace", route, "dev", ifname], check=True)


def packet_summary(payload: bytes) -> str:
    if not payload:
        return "empty"
    version = payload[0] >> 4
    if version == 4 and len(payload) >= 20:
        proto = payload[9]
        src = socket.inet_ntoa(payload[12:16])
        dst = socket.inet_ntoa(payload[16:20])
        return f"IPv4 proto={proto} {src}->{dst} len={len(payload)}"
    return f"len={len(payload)}"


def tunnel_label(server_ip: str, server_port: int) -> str:
    return f"{server_ip}:{server_port}"


def load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except FileNotFoundError:
        return {}
    except Exception:
        return {}
    return {}


def save_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def confirm_regen(label: str) -> bool:
    if not os.isatty(0):
        return False
    answer = input(f"Server key changed for {label}. Accept and replace stored key? [y/N] ").strip().lower()
    return answer in ("y", "yes")


def check_tofu(path: str, label: str, server_pub: bytes, allow_regen: bool = False) -> None:
    db = load_json(path)
    fp = server_pub.hex()
    known = db.get(label)
    if known is None:
        db[label] = fp
        save_json(path, db)
        print(f"[USTPS-TUNNEL] TOFU trust established for {label}")
        return
    if known != fp:
        if allow_regen and confirm_regen(label):
            db[label] = fp
            save_json(path, db)
            print(f"[USTPS-TUNNEL] TOFU key replaced for {label}")
            return
        raise SystemExit(f"TOFU mismatch for {label}: possible MITM or server key change")
