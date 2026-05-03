# Changelog

All notable changes to **sing-ewp** are documented here. The project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## v0.1.2 — Hardening release

This release tightens the EWP/v2 handshake against three classes of
real-world threat (replay-based DoS, plaintext fingerprinting, and
malicious time-skewed peers) without changing the cryptographic core.

> **Wire format note**
>
> The 4-byte plaintext magic `EWP2` has been removed from both
> `ClientHello` and `ServerHello`. v0.1.2 servers and clients are
> **NOT wire-compatible with v0.1.1** — please upgrade in lockstep.
> The cryptographic primitives (X25519 + ML-KEM-768 hybrid,
> ChaCha20-Poly1305, HKDF-SHA-256, HMAC-SHA-256) are unchanged.

### Added

- **Anti-replay cache** for `ClientHello` (`anti_replay.go`).
  - New type `ReplayCache`, with a sharded mutex and opportunistic GC
    (every 1024 admits). No background goroutines.
  - New constant `ReplayWindow = HandshakeTimestampWindow + 60s`
    (= 180 s by default), covering clock skew on top of the existing
    timestamp window.
  - New error sentinel `ErrReplay` returned when a duplicate
    `(uuid, nonce)` pair is observed inside the window.
- **`AcceptClientHelloWithReplay`** — variant of `AcceptClientHello`
  that takes an optional `*ReplayCache`. Passing `nil` preserves the
  previous behaviour.
- **`Service.SetReplayCache`** — swap the default cache (e.g. to
  disable replay protection in tests, or to install a custom-sized
  one).
- **`ServerTime` is now validated on the client side**
  (`ClientHandshakeState.ReadServerHello`). Symmetric to the existing
  server-side `ClientHello.Timestamp` check, an out-of-window
  `ServerHello.ServerTime` now returns `ErrTimestamp` before any
  ECDH / ML-KEM decapsulation work is performed.

### Changed

- **`Service` enables anti-replay by default.** Calling `NewService`
  installs a `ReplayCache(ReplayWindow)`. Existing call sites
  automatically benefit; no API change.
- **Wire format: `Magic`/`MagicLen` removed.**
  - `ClientHello` now starts directly with the 12-byte handshake
    nonce (high-entropy random).
  - `ServerHello` now starts directly with the echoed nonce.
  - Authentication of the leading bytes is provided exclusively by
    the existing outer HMAC-SHA-256/16 (which already covers the
    full message) and by the `ClientHello`'s AEAD AAD binding.
  - `MagicLen` is preserved as a `const = 0` for source compatibility,
    but it no longer appears on the wire.
  - `ErrMagic` is now a `Deprecated` sentinel — the decoder no longer
    returns it. Tampered leading bytes produce `ErrOuterMAC` instead.

### Security rationale

| Attack vector                                   | Before (v0.1.1)                              | After (v0.1.2) |
|-------------------------------------------------|----------------------------------------------|----------------|
| DPI fingerprinting via fixed `EWP2` 4-byte tag  | Trivial (constant pattern at offset 0)       | Removed — the first 12 bytes are now uniformly random handshake nonce |
| Replay of a captured `ClientHello` to burn server CPU on X25519+ML-KEM-Encap | 1 full asymmetric round per replay, unlimited within 120 s | Rejected after one `(uuid,nonce)` map lookup; `O(1)` cost |
| Replay-based traffic-correlation probing        | "Same bytes accepted N times" reveals EWP    | Same bytes accepted exactly once per `ReplayWindow`        |
| Client tricked into handshaking with a peer holding an outdated `ServerHello` | Accepted without timestamp check             | `ErrTimestamp` if `|ServerTime − now| > 120 s`              |

The session-key derivation (`DeriveSessionKeys`) and frame-layer AEAD
discipline are intentionally unchanged. Forward secrecy still derives
from the pair of ephemeral X25519 + ML-KEM-768 key shares.

### Migration

- **Servers and clients must upgrade together.** A v0.1.1 client will
  send 4 bytes of `EWP2` at the front of its `ClientHello`; a v0.1.2
  server will treat those bytes as part of the handshake nonce, fail
  the AEAD/MAC, and close the connection.
- No configuration changes are required; UUIDs and configuration
  schemas are unchanged.
- Tests that constructed handshakes manually and verified the legacy
  magic should switch to verifying the outer MAC instead. See the
  refreshed `TestHandshake_TamperedLeadingBytesRejected` for an
  example.

### Tests

- New test file `anti_replay_test.go` covers:
  first-sight admit, duplicate reject, distinct-nonce / distinct-UUID
  isolation, post-window re-admit, race-free concurrent admits
  (exactly one winner under contention), and GC bound under sustained
  load.
- `TestHandshake_BadMagicRejected` renamed to
  `TestHandshake_TamperedLeadingBytesRejected` and reframed: any
  leading-byte tampering MUST be caught by the outer MAC (no longer
  by a magic check).
- Full suite, including the existing `hardening_test.go` and
  `v2_test.go`, passes with `-race`.

---

## v0.1.1

Initial public release of the EWP/v2 protocol library.

- X25519 + ML-KEM-768 hybrid handshake (post-quantum forward secrecy).
- ChaCha20-Poly1305 AEAD framing with strict per-direction counters.
- HKDF-SHA-256 session-key derivation bound to client+server nonces.
- HMAC-SHA-256/16 outer authentication on both `ClientHello` and
  `ServerHello`.
- Handshake & frame padding for traffic-shape masking.
- Frame types reserved for ping/pong, rekey, and UDP sub-sessions.
