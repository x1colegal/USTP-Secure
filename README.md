# USTP-Secure (USTPS)

USTPS means **UDP Speedy Transmission Protocol Secure**.

USTP-Secure keeps USTP on UDP and adds packet-level AEAD encryption/authentication.

USTPS does not implement congestion control. If the network is congested, USTPS does not try to slow itself down like TCP. It is intentionally speed-first and UDP-like in that respect.

Status: **Beta**

USTPS is no longer just a proof of concept. It is currently in the Beta phase.

USTPS can be used for many kinds of applications and transports.

This repository, however, is focused specifically on **streaming over USTPS**.

## Build note
- Built with `Codex` using `GPT-5.4 (Low)`.
- Verified without freezing at `--loss 33`.
- Test path: `Brazil -> Canada` with about `140ms` RTT.

## Security model
- Transport remains UDP (no TCP tunnel)
- AEAD ciphers:
  - `chacha20` (ChaCha20-Poly1305)
  - `aes-256-gcm`
  - `aes-128-gcm`
- AEAD is mandatory for payload `DATA` in USTPS.
- Transport control packets (`HELLO`, `ACK`, `RETRANSMIT_REQUEST`, `CLOSE`) stay plaintext on purpose.
- Control packets are serialized as ASCII transport records.
- `DATA` packets use a binary frame format named `UPACK` (`UPAK` on the wire).
- No static PSK is used.
- Each client performs an X25519 key exchange when it joins.
- Each client gets a separate AEAD session key.
- Servers support multiple clients.
- The server first sees a client as `IP:port`, then promotes it to a generated Base64 `session_id` after challenge validation.
- If `--cipher` is set on the server, the server uses that exact cipher.
- If `--cipher` is omitted or set to `auto`, the server uses the cipher requested by the client.
- Clients reject unexpected cipher negotiation.
- TOFU (Trust On First Use) is enabled on the client to detect unexpected server key changes after the first connection.
- The server keeps a persistent X25519 host key in `~/.ustps_host_key` by default so TOFU remains stable across reconnects and restarts.
- A normal server restart does not change the host key.
- Use `--regen-key` on the server only when you intentionally want to rotate that host key.

## Packet magic values
- `UST1` means `UDP Speedy Transmission Protocol`, version 1.
- `USS1` means `UDP Speedy Secure`, version 1.
- `UPAK` is the binary `UPACK` DATA frame marker.
- In USTPS, `UST1` identifies plaintext ASCII control packets.
- In USTPS, `UPAK` identifies binary DATA packets after decryption.
- In USTPS, `USS1` is the outer secure AEAD envelope format.
- So, before decryption you normally see `USS1`, and after decryption you normally see either `UST1|...` for control or `UPAK...` for DATA.

## Transport model
- USTPS is reliable over UDP, but it is **unordered by design**.
- USTPS does **not** implement congestion control.
- Packets carry both a transport `seq` and an application-facing `stream_pos`.
- `seq` is used for ACK, loss detection, retransmission, and `RTT` sampling.
- `stream_pos` tells the application where the payload belongs in the logical byte stream.
- The receiver accepts out-of-order packets immediately instead of blocking delivery behind one missing packet.

Example:
- Physical arrival: `1 2 3 5 6`
- Packet `4` is missing, so the receiver buffers the gap information and sends `RETRANSMIT_REQUEST` for `4`.
- Packets `5` and `6` are still accepted immediately.
- When packet `4` arrives later, the application can reconstruct the logical order by using `stream_pos`, not by trusting arrival order.

## Handshake and session model
- The client starts with a plaintext transport `HELLO` carrying its X25519 public key and requested cipher.
- The server does not send media immediately. It first sends a plaintext challenge containing:
  - a random token
  - a generated Base64 `session_id`
  - the server public key
  - the selected cipher
- The client must answer with that same token.
- Only after that token round-trip succeeds does the server create the AEAD session and begin sending `DATA`.
- After validation, the session is tracked by the generated Base64 `session_id`, not just by the original `IP:port`.
- Future keepalives use that `session_id`, so the server can remap the session if the client source port changes.

## Network change support
- The USTPS client can recover when the device changes networks and the UDP path breaks.
- If the current path stalls, the client recreates its UDP socket, resolves the server address again, and tries to resume the existing session by `session_id`.
- If session resume is not possible, the client falls back to a fresh handshake automatically.
- This is designed so a mobile client can switch networks without immediately being forced to restart the client process.

## Wire format
- `HELLO`, `ACK`, `RETRANSMIT_REQUEST`, and `CLOSE` are ASCII control records.
- Their payload bytes are carried as Base64 inside the ASCII control line, so control stays text-friendly even when the logical payload contains binary material such as public keys or tokens.
- `DATA` uses the binary `UPACK` frame format instead of ASCII to avoid bloating media payload packets.
- This means captures typically look like plaintext `UST1|...` control plus encrypted `USS1...` datagrams that decrypt to `UPAK...` DATA frames.

## Retransmission model
- USTPS uses selective retransmission, not Go-Back-N.
- Every unique `DATA` packet is ACKed individually.
- Missing packets trigger `RETRANSMIT_REQUEST` only for the missing `seq`.
- The sender keeps sent packets in a retransmission buffer until ACKed.
- `RTO` is not fixed-only: it is adapted from measured `RTT` samples of non-retransmitted packets.
- Only the missing packets are retransmitted.

## Why it does not have HoL blocking
- TCP has transport-level Head-of-Line blocking: if one segment is missing, later data in the same byte stream cannot be delivered to the application yet.
- USTPS does not do that at the transport layer.
- A missing packet does not stop later packets from being received, ACKed, buffered, or passed upward.
- That is why USTPS can physically observe flows like `5, 6, 4, 7, 8` while still preserving enough metadata for the application to rebuild the logical order if it wants ordered output.

Important:
- If your final application output is a strict ordered byte stream, then reordering still has to happen somewhere above USTPS.
- In that case, the application layer may still choose to wait before emitting bytes, but that waiting is an application behavior, not transport-level HoL blocking inside USTPS itself.

## How to integrate USTPS into your application
- Treat USTPS as a reliable unordered datagram transport with stream position metadata.
- Do not assume packet arrival order is the real stream order.
- Use `stream_pos` to rebuild ordered output when your application needs a byte stream.
- If your application can consume unordered chunks directly, you can process payloads immediately and avoid ordered buffering entirely.
- If your application needs ordered output, keep a reorder buffer keyed by `stream_pos` and release data only when the required positions are available.
- Do not rebuild ordering by `seq`; use `seq` only for transport reliability logic.

## TCP and QUIC comparison
- TCP:
  TCP is reliable and ordered, but that ordering is enforced by the transport itself. A single missing segment blocks later data in the same stream.
- TCP with multiplexing above it:
  Even if an application multiplexes many logical channels over one TCP connection, loss in the underlying TCP byte stream still blocks progress behind the gap.
- QUIC:
  QUIC removes cross-stream HoL blocking between different streams, which is a big improvement over TCP for multiplexed applications.
- QUIC stream behavior:
  Inside one individual QUIC stream, ordering is still enforced. Missing data in that stream blocks later bytes for that same stream.
- USTPS:
  USTPS does not enforce ordered delivery at the transport layer. It accepts later packets without waiting for earlier missing ones, and relies on `stream_pos` metadata if the application wants to reconstruct ordered output. It also does not attempt congestion control; when the network is congested, USTPS does not intentionally back off like TCP.

## Server (AEAD enabled)
```bash
python3 server.py \
  --peer-port 0 \
  --bind-ip 0.0.0.0 \
  --bind-port 40001 \
  --video "<HLS_URL_OR_LOCAL_FILE>" \
  --cipher chacha20
```

If you want custom ffmpeg encoding/transcoding parameters instead of the default copy mode, use `--video-parameters`.

Example:
```bash
python3 server.py \
  --peer-port 0 \
  --bind-ip 0.0.0.0 \
  --bind-port 40001 \
  --video "<HLS_URL_OR_LOCAL_FILE>" \
  --video-parameters "-c:v libx264 -preset veryfast -b:v 2500k -c:a aac -b:a 128k -mpegts_flags +resend_headers" \
  --cipher chacha20
```

Behavior:
- without `--video-parameters`: uses `-c copy -mpegts_flags +resend_headers`
- with `--video-parameters`: uses exactly what you passed instead of the default copy settings

## About `--loss`
- `--loss` simulates outbound packet loss on the server side for testing recovery behavior.
- Value range: `0` to `100`
- Example:

```bash
python3 server.py \
  --peer-port 0 \
  --bind-ip 0.0.0.0 \
  --bind-port 40001 \
  --video "<HLS_URL_OR_LOCAL_FILE>" \
  --cipher chacha20 \
  --loss 40
```

- `--loss 0` means no simulated loss.
- `--loss 40` means the server randomly drops about 40% of its outbound packets before they leave the process.
- This is useful for validating:
  - retransmission behavior
  - gap detection
  - ACK/NACK handling
  - playback resilience under controlled packet loss
- In normal real-world usage, leave `--loss` at `0`.

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

Notes:
- The default playout/reorder delay is now `350ms`.
- The client stores the first seen server X25519 public key in `~/.ustps_known_hosts.json`.
- If that key changes later, the client aborts with a TOFU mismatch error instead of silently trusting the new key.
- If you intentionally rotated the server host key, run the client with `--regen-key` to allow replacing the stored TOFU key after interactive confirmation.
- TOFU entries are stored per `<peer-ip-or-domain>:<peer-port>`, so a different server at a different address/port is treated as a different host identity.

## About `--udp-unordered-live`
- `--udp-unordered-live` is dangerous and generally not recommended for normal media players.
- In that mode, payloads are forwarded immediately in raw arrival order.
- If a packet is retransmitted later, a generic player may treat that recovered payload as if it were a brand-new frame or packet instead of late data that belongs earlier in the logical stream.
- That can cause visible corruption, duplicated playback artifacts, decoder confusion, or unstable playback.
- For normal player compatibility, prefer local `TCP` output or ordered UDP output with a reorder buffer.

VLC:
```text
tcp://127.0.0.1:1238
```

## USTP vs USTPS
- USTP: reliable UDP transport, no encryption by default.
- USTPS: same UDP transport plus AEAD protection for `DATA`, plaintext transport control, challenge validation before data flow, and per-client session tracking by Base64 `session_id`.
- Client exits with explicit error if no valid encrypted packets are received after the handshake finishes.

## Internet-Drafts
- `USTPS` Internet-Draft: `https://datatracker.ietf.org/doc/draft-x1co-ustps/`

## Related projects
- `USSH`: a shell/remote terminal protocol implemented fully from scratch on top of USTPS:
  `https://github.com/x1colegal/USSH`
