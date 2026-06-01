# USTP-Secure (USTPS)

USTP-Secure (USTPS) is a native secure variant of USTP.

## Security
- TLS: **1.3 only**
- Preferred AEAD cipher suites:
  - `TLS_AES_256_GCM_SHA384`
  - `TLS_AES_128_GCM_SHA256`
  - `TLS_CHACHA20_POLY1305_SHA256`

## No proxy chain requirement
USTPS runs directly as its own server/client pair.
You do **not** need to start the regular USTP server first.

## Quick start
### 1) Generate cert/key on server
```bash
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout key.pem -out cert.pem -subj "/CN=ustps"
```

### 2) Start USTPS server (direct)
```bash
python3 ustps_server.py \
  --bind-ip 0.0.0.0 \
  --bind-port 5443 \
  --certfile cert.pem \
  --keyfile key.pem \
  --video "<HLS_URL_OR_LOCAL_FILE>"
```

### 3) Start USTPS client (direct)
```bash
python3 ustps_client.py \
  --server-ip <SERVER_IP_OR_DOMAIN> \
  --server-port 5443 \
  --output-mode tcp \
  --tcp-host 127.0.0.1 \
  --tcp-port 1238
```

VLC:
```text
tcp://127.0.0.1:1238
```

## USTP vs USTPS
- USTP: reliable UDP transport, no built-in TLS encryption.
- USTPS: transport secured end-to-end with TLS 1.3 AEAD ciphers.
