# MasterDnsVPN hardening iteration plan

## Objective

Harden this fork for safer use in hostile network environments, while keeping
changes testable and committing each iteration.

## Current branch / fork

- Branch: `hardening/strong-adversary-vpn`
- Fork remote: `fork https://github.com/mookim-eth/MasterDnsVPN.git`
- Baseline hardening commit: `fb6dc64 Harden DNS tunnel transport security`

## Completed in previous iteration

- [x] Fork configured and branch pushed.
- [x] Server-to-client VPN responses encrypted with the configured codec.
- [x] Opaque encrypted TXT response chunking implemented and tested.
- [x] Client response parsing switched to encrypted extraction.
- [x] Async inbound dispatch now requires matching pending DNS response state.
- [x] Post-session inbound packets now require matching session id/cookie.
- [x] Defaults and examples changed to AES-256-GCM (`DATA_ENCRYPTION_METHOD=5`).
- [x] Config rejects unauthenticated legacy modes (`0=None`, `1=XOR`, `2=ChaCha20`).
- [x] Server log redacts the active encryption key.
- [x] AES-128/192/256 key derivation uses SHA-256 material instead of MD5.
- [x] Direct SOCKS/TCP dials guard against resolved private/local targets.
- [x] `SECURITY_HARDENING.md` documents the audit and remaining risks.

## Completed in current iteration

- [x] Added this `plan.md` as the living implementation checklist.
- [x] Reduced local artifact exposure:
  - logger files are created as `0600`;
  - MTU output directories/files are `0700`/`0600`;
  - DNS cache persistence directories/files are `0700`/`0600`;
  - bench runtime directories/files are `0750`/`0600`;
  - DNS cache save now creates the target directory before the temp file.
- [x] Fixed simple startup-path staticcheck findings in `cmd/client` and
      `cmd/server`.
- [x] Hardened legacy TXT chunk assembly to reject duplicate chunks.
- [x] Added tests for private file modes and duplicate chunk rejection.
- [x] Verified with `go test ./...`, `go vet ./...`, and `git diff --check`.

## Next iteration queue

### P0/P1 security hardening

- [x] Reduce local artifact exposure:
  - use private permissions for logs/cache/MTU output/bench runtime files;
  - create persistence directories before writing temp files;
  - keep generated secrets at `0600`.
- [x] Remove or downgrade high-signal staticcheck findings in startup paths.
- [ ] Add bounded, configurable DNS response TTL/padding strategy if it can be
      done without breaking resolver compatibility.
- [x] Add tests around malformed encrypted TXT chunks and duplicate chunk ids.

### P2 cleanup / verification

- [x] Re-run `go test ./...` after every iteration.
- [x] Re-run `go vet ./...`.
- [x] Re-run `govulncheck ./...`; current blocker is Go stdlib
      `GO-2026-4971` in local `go1.25.0`, fixed upstream in Go `1.25.10`.
- [x] Re-run `staticcheck ./...` and track remaining pre-existing findings.
- [x] Re-run `gosec ./...` and track remaining pre-existing false positives.

## Next iteration target

1. Add a compatibility-safe DNS response TTL profile and tests.
2. Continue reducing `gosec` G115 false positives in protocol packing helpers.
3. Evaluate whether a Go toolchain bump to `1.25.10+` is feasible in CI/runtime.
4. Commit and push the iteration.
