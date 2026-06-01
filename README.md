# USTP-Secure (USTPS)

USTP-Secure keeps USTP on UDP and adds packet-level AEAD encryption/authentication.

## Security model
- If `--aead` is not set, transport is plain USTP (no encryption).
- Transport remains UDP (no TCP tunnel)
- AEAD ciphers:
  - `chacha20` (ChaCha20-Poly1305)
  - `aesgcm` (AES-256-GCM)
- Shared secret with `--psk`

## Server (AEAD enabled)
```bash
python3 server.py \
  --peer-ip <CLIENT_IP_OR_DOMAIN> \
  --peer-port 0 \
  --bind-ip 0.0.0.0 \
  --bind-port 40001 \
  --video "<HLS_URL_OR_LOCAL_FILE>" \
  --aead \
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
  --aead \
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
