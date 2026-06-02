# USTP-Secure (USTPS)

USTPS means **UDP Speedy Transmission Protocol Secure**.

USTP-Secure keeps USTP on UDP and adds packet-level AEAD encryption/authentication.

Status: **Beta**

USTPS is no longer just a proof of concept. It is currently in the Beta phase.

## Security model
- Transport remains UDP (no TCP tunnel)
- AEAD ciphers:
  - `chacha20` (ChaCha20-Poly1305)
  - `aes-256-gcm`
  - `aes-128-gcm`
- AEAD is mandatory in USTPS (no plaintext mode)
- No static PSK is used.
- Each client performs an X25519 key exchange when it joins.
- Each client gets a separate ephemeral AEAD session key.
- Servers support multiple clients.
- The server chooses a random supported outbound cipher per client session.

## Server (AEAD enabled)
```bash
python3 server.py \
  --peer-ip 0.0.0.0 \
  --peer-port 0 \
  --bind-ip 0.0.0.0 \
  --bind-port 40001 \
  --video "<HLS_URL_OR_LOCAL_FILE>" \
  --cipher chacha20
```

## Client (AEAD enabled)
```bash
python3 client.py \
  --peer-ip <SERVER_IP_OR_DOMAIN> \
  --peer-port 40001 \
  --bind-ip 0.0.0.0 \
  --bind-port 0 \
  --output-mode tcp \
  --tcp-host 127.0.0.1 \
  --tcp-port 1238 \
  --cipher chacha20
```

VLC:
```text
tcp://127.0.0.1:1238
```

## USTP vs USTPS
- USTP: reliable UDP transport, no encryption by default.
- USTPS: same UDP transport plus AEAD encryption/authentication per packet.
- Client exits with explicit error if no valid encrypted packets are received (server offline or handshake failed).
