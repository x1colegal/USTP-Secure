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

## Server (AEAD enabled)
```bash
python3 server.py \
  --peer-ip <CLIENT_IP_OR_DOMAIN> \
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

## USTPS File Transfer
Server:
```bash
python3 ustps_file_server.py \
  --peer-ip <CLIENT_IP_OR_DOMAIN> \
  --peer-port 0 \
  --bind-ip 0.0.0.0 \
  --bind-port 41001 \
  --src <FILE_OR_DIR> \
  --psk "YOUR_SHARED_SECRET" \
  --cipher chacha20
```

Client:
```bash
python3 ustps_file_client.py \
  --peer-ip <SERVER_IP_OR_DOMAIN> \
  --peer-port 41001 \
  --bind-ip 0.0.0.0 \
  --bind-port 41000 \
  --dst <OUTPUT_DIR> \
  --psk "YOUR_SHARED_SECRET" \
  --cipher chacha20
```

Notes:
- Keep the same `--psk` on both sides.
- You can use `--cipher chacha20`, `--cipher aes-256-gcm`, or `--cipher aes-128-gcm`.
- Server can learn client source port dynamically with `--peer-port 0`.

## USTPS SCP (Secure File Transfer)
Server:
```bash
python3 ustps_scp_server.py \
  --bind-ip 0.0.0.0 \
  --bind-port 42001 \
  --peer-ip <CLIENT_IP_OR_DOMAIN> \
  --peer-port 0 \
  --root . \
  --psk "YOUR_SHARED_SECRET" \
  --cipher chacha20
```

Upload (client -> server):
```bash
python3 ustps_scp_client.py \
  --peer-ip <SERVER_IP_OR_DOMAIN> \
  --peer-port 42001 \
  --bind-ip 0.0.0.0 \
  --bind-port 42000 \
  --mode upload \
  --src <LOCAL_FILE_OR_DIR> \
  --psk "YOUR_SHARED_SECRET" \
  --cipher chacha20 \
  --partial \
  --compress
```

Download (server -> client):
```bash
python3 ustps_scp_client.py \
  --peer-ip <SERVER_IP_OR_DOMAIN> \
  --peer-port 42001 \
  --bind-ip 0.0.0.0 \
  --bind-port 42000 \
  --mode download \
  --src <REMOTE_FILE_PATH> \
  --dst <LOCAL_OUTPUT_DIR> \
  --psk "YOUR_SHARED_SECRET" \
  --cipher chacha20 \
  --partial \
  --compress
```

Per-file transfer log format:
- `<file_name> <transferred>/<total> <speed_kb_s>KB/s retx=<retransmissions>`
