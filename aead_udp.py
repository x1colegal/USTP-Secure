import os
import socket
import hashlib
from typing import Tuple

MAGIC = b"USS1"
CIPHER_AES128GCM = 1
CIPHER_AES256GCM = 2
CIPHER_CHACHA20 = 3


def _kdf(psk: str) -> bytes:
    return hashlib.sha256(psk.encode("utf-8")).digest()


class AEADDatagramSocket:
    def __init__(self, sock: socket.socket, psk: str, cipher_name: str = "chacha20"):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

        self.sock = sock
        base_key = _kdf(psk)
        c = cipher_name.lower().strip()
        if c in ("aes-128-gcm", "aes128", "aes128gcm"):
            self.cipher_id = CIPHER_AES128GCM
            self.key = base_key[:16]
            self.aead = AESGCM(self.key)
        elif c in ("aes", "aesgcm", "aes-gcm", "aes-256-gcm", "aes256", "aes256gcm"):
            self.cipher_id = CIPHER_AES256GCM
            self.key = base_key
            self.aead = AESGCM(self.key)
        else:
            self.cipher_id = CIPHER_CHACHA20
            self.key = base_key
            self.aead = ChaCha20Poly1305(self.key)

    def bind(self, addr: Tuple[str, int]):
        self.sock.bind(addr)

    def sendto(self, data: bytes, addr: Tuple[str, int]):
        nonce = os.urandom(12)
        ct = self.aead.encrypt(nonce, data, None)
        pkt = MAGIC + bytes([self.cipher_id]) + nonce + ct
        return self.sock.sendto(pkt, addr)

    def recvfrom(self, bufsize: int):
        while True:
            raw, addr = self.sock.recvfrom(max(bufsize, 65535))
            if len(raw) < 4 + 1 + 12 + 16:
                continue
            if raw[:4] != MAGIC:
                continue
            cid = raw[4]
            if cid != self.cipher_id:
                continue
            nonce = raw[5:17]
            ct = raw[17:]
            try:
                pt = self.aead.decrypt(nonce, ct, None)
            except Exception:
                continue
            return pt, addr

    def setsockopt(self, *args, **kwargs):
        return self.sock.setsockopt(*args, **kwargs)

    def getsockname(self):
        return self.sock.getsockname()
