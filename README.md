# USTP-Secure (USTPS)

USTP-Secure keeps USTP on UDP and adds packet-level AEAD encryption/authentication.

## Security model
- Transport remains UDP (no TCP tunnel)
- AEAD ciphers:
  - `chacha20` (ChaCha20-Poly1305)
  - `aes-256-gcm`
  - `aes-128-gcm`
- AEAD is mandatory in USTPS (no plaintext mode)
- Shared secret is required with `--psk`
- Servers support multiple clients.
- `--psk` is the bootstrap AEAD secret.
- Every client receives its own derived session PSK after the encrypted HELLO handshake.
- The server chooses a random supported outbound cipher per client session.

## Server (AEAD enabled)
```bash
python3 server.py \
  --peer-ip 0.0.0.0 \
  --peer-port 0 \
  --bind-ip 0.0.0.0 \
  --bind-port 40001 \
  --video "<HLS_URL_OR_LOCAL_FILE>" \
  --psk "YOUR_SHARED_SECRET" \
  --cipher chacha20
```

## Client (AEAD enabled)
```bash
python3 client.py \
  --peer-ip <SERVER_IP_OR_DOMAIN> \
  --peer-port 40001 \
  --bind-ip 0.0.0.0 \
  --bind-port 40000 \
  --output-mode tcp \
  --tcp-host 127.0.0.1 \
  --tcp-port 1238 \
  --psk "YOUR_SHARED_SECRET" \
  --cipher chacha20
```

VLC:
```text
tcp://127.0.0.1:1238
```

## USTP vs USTPS
- USTP: reliable UDP transport, no encryption by default.
- USTPS: same UDP transport plus AEAD encryption/authentication per packet.
- Client exits with explicit error if no valid encrypted packets are received (wrong PSK/cipher or server offline).
