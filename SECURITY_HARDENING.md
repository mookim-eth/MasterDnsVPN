# Security hardening notes

This branch applies a defensive hardening profile for hostile-network use. It
does **not** make DNS tunnelling indistinguishable from normal DNS traffic and it
should not be treated as a guarantee against a strong network adversary.

## Audit summary

Key risks found in the original implementation:

- Server-to-client VPN responses were returned as plaintext VPN frames inside
  DNS TXT answers. Packet type, session identifiers, sequence numbers and
  payload bytes were visible to passive observers.
- The async client accepted decrypted tunnel responses without requiring a
  matching pending DNS request or matching session id/cookie.
- Default configuration used unauthenticated XOR encryption, and the server
  logged the active key.
- Direct SOCKS targets rejected literal private/local IP addresses, but resolved
  addresses also need to be checked before connect.

## Changes in this branch

- Server responses now use the configured tunnel codec in both directions:
  `BuildEncryptedVPNResponsePacket` / `ExtractEncryptedVPNResponse`.
- Encrypted responses use an opaque TXT chunking format so large AEAD ciphertexts
  can be reassembled before decryption.
- The async client now dispatches tunnel responses only if:
  - the DNS response matches a pending resolver sample, and
  - post-session packets match the current session id and cookie.
- Invalid-session error replies echo the received session cookie so legitimate
  encrypted resets can still be authenticated by the client.
- Config defaults now use AES-256-GCM (`DATA_ENCRYPTION_METHOD = 5`).
- Config loading rejects unauthenticated legacy modes (`0=None`, `1=XOR`,
  `2=ChaCha20`).
- AES-128/192/256 key derivation now uses SHA-256 material instead of MD5 for
  AES-128.
- Server startup logs redact the active encryption key.
- Direct TCP/SOCKS dials install a `net.Dialer.ControlContext` guard to reject
  resolved private/local/link-local/multicast targets before connect.

## Remaining concerns

- DNS TXT tunnelling remains highly fingerprintable in principle: high-entropy
  TXT data, unusual answer sizes/chunking, low TTLs and EDNS behavior can stand
  out compared with ordinary DNS.
- `govulncheck` currently reports `GO-2026-4971` in the Go standard library used
  by the local toolchain (`go1.25.0`); build with Go `1.25.10` or newer when that
  toolchain is available.
- `staticcheck` and `gosec` still report pre-existing cleanup items, mostly
  unused code, integer-conversion false positives in protocol packing, and file
  permission/path warnings outside this patch's critical path.
