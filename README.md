# USTP-Secure (USTPS)

USTP-Secure (USTPS) adds a TLS 1.3 secure tunnel layer on top of USTP traffic.

## Security profile
- TLS version: **1.3 only**
- Cipher suites (preferred):
  - `TLS_AES_256_GCM_SHA384`
  - `TLS_AES_128_GCM_SHA256`
  - `TLS_CHACHA20_POLY1305_SHA256`

## How it works
- Your regular USTP app still speaks UDP locally.
- `ustps_proxy_client.py` wraps those UDP packets into TLS frames.
- `ustps_proxy_server.py` unwraps and forwards to UDP USTP server.

## Quick setup
### 1) Generate cert on server
```bash
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout key.pem -out cert.pem -subj "/CN=ustps"
```

### 2) Run USTP server (local UDP)
```bash
python3 server.py --peer-ip 127.0.0.1 --peer-port 40010 --bind-ip 127.0.0.1 --bind-port 40001 --video "https://x1co.com.br/hls/stream.m3u8"
```

### 3) Run USTPS server proxy
```bash
python3 ustps_proxy_server.py --bind-ip 0.0.0.0 --bind-port 5443 --certfile cert.pem --keyfile key.pem --udp-upstream-ip 127.0.0.1 --udp-upstream-port 40001
```

### 4) Run USTPS client proxy
```bash
python3 ustps_proxy_client.py --server-ip <VPS_IP> --server-port 5443 --udp-bind-ip 0.0.0.0 --udp-bind-port 40010 --udp-local-target-ip 127.0.0.1 --udp-local-target-port 40000
```

### 5) Run USTP client (local UDP)
```bash
python3 client.py --peer-ip 127.0.0.1 --peer-port 40010 --bind-ip 127.0.0.1 --bind-port 40000 --output-mode tcp --tcp-host 127.0.0.1 --tcp-port 1238
```

## USTP vs USTPS
- USTP: UDP transport with reliability logic, no built-in encryption.
- USTPS: USTP traffic tunneled over TLS 1.3 for confidentiality/integrity in transit.
