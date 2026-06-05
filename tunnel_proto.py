TYPE_AUTH = 1
TYPE_AUTH_OK = 2
TYPE_AUTH_FAIL = 3
TYPE_CONFIG = 4
TYPE_IP = 5
TYPE_PING = 6
TYPE_PONG = 7


def pack_tunnel_message(msg_type: int, payload: bytes = b"") -> bytes:
    return bytes([msg_type]) + payload


def unpack_tunnel_message(raw: bytes) -> tuple[int, bytes]:
    if not raw:
        raise ValueError("empty tunnel payload")
    return raw[0], raw[1:]
