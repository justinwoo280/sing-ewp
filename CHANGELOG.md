# Changelog

All notable changes to **sing-ewp** are documented here. The project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## v0.2.0 — Security audit response (EWP/v2.1)

This release closes a 12-finding security audit of the v0.1.x series.
It introduces the **EWP/v2.1** wire derivation, which is **NOT
compatible with v0.1.x**: keys are derived differently, the length
framer changed, and the high-level Client/Service constructors take a
new mandatory parameter (a server long-term static X25519 keypair).

> ⚠️ **Coordinated upgrade required.** A v0.2.0 server will reject
> every v0.1.x ClientHello, and vice-versa. There is no negotiation
> bit; the failure mode is a clean closed transport (`ErrOuterMAC`).
> See `UPGRADING.md` for the migration playbook.

### Added — server identity

- **Server long-term X25519 static keypair**, fed into both the
  outer-AEAD key and the outer-MAC key derivation. Holding the PSK
  alone is no longer sufficient to (a) decrypt a captured
  `ClientHello`, or (b) impersonate the server to a holding-out
  client.
- New high-level constructors that take the new credential:
  - `NewClientV21(uuidStr, serverStaticPubB64 string) (*ClientV21, error)`
  - `NewServiceV21(handler, staticPrivB64 string) (*ServiceV21, error)`
  - `GenerateServerStaticKeypair() (privB64, pubB64 string, error)`
- New low-level entry points (for callers that already manage their
  own message transport):
  - `WriteClientHelloV21` / `EncodeClientHelloV21Test`
  - `(*ClientHandshakeState).ReadServerHelloV21`
  - `AcceptClientHelloV21Strict` / `AcceptClientHelloV21WithReplay`
  - `MakeUUIDLookupV21`
- New error sentinels: `ErrStaticPub`, `ErrStaticPriv`.

### Added — protocol-level forward secrecy

- **`(*SecureStream).Rekey()`** rotates the per-direction send key
  using HKDF-Expand under the prior key, with the prior counter as
  part of the `info` string. The receiving side transparently rotates
  on `FrameRekeyReq` and the application never observes the frame.
- **`SessionKeys.SessionID [8]byte`** — opaque 8-byte identifier
  derived from the post-handshake PRK with the dedicated label
  `ewp/v2.1 sid`. Each handshake produces a fresh, unlinkable
  `SessionID`; safe for logging and connection tracking.

### Changed — anti-replay cache

- **`ReplayCache` is now genuinely sharded** (16 independent
  mutex-guarded maps). Concurrent admits scale near-linearly with
  contributors; the previous single-mutex implementation was
  documented as sharded but was not.
- Added a background sweeper goroutine; `(*ReplayCache).Close()`
  terminates it. Background period is `min(30s, window/3)`, never
  below 100 ms.
- `ReplayWindow` is now `HandshakeTimestampWindow + 30s = 60 s`
  (down from 180 s) to bound the in-memory live set.

### Changed — handshake hardening (M4 / H4)

- `HandshakeTimestampWindow` tightened from **120 s to 30 s**.
- Out-of-window timestamps now surface as **`ErrReplay`** instead of
  `ErrTimestamp`. The two failure modes are deliberately merged so
  that an on-path observer cannot distinguish "I have already seen
  this exact `ClientHello`" from "your clock is out of sync" — which
  removes a side-channel that previously revealed whether a captured
  packet had already been replayed elsewhere.
- `ErrTimestamp` is preserved as an exported sentinel for source
  compatibility, but no entry point in the package returns it any
  longer.

### Changed — outer MAC binds inner length (H2)

- `v21OuterMAC` now takes the explicit inner-ciphertext length as the
  first 8 bytes of HMAC input:
  `tag = HMAC(macKey, be64(innerCTLen) ‖ msg_minus_mac)`.
- Truncating or extending the inner ciphertext (or flipping the
  on-wire `ctLen` field) now invalidates the MAC even when the cuts
  cancel out at the byte level.

### Changed — length framer (M1)

- `LengthFramer` prefix narrowed from **4 bytes to 3 bytes**
  big-endian (max payload still 16 MiB, well above
  `MaxFrameSize = 65 KiB`). The high two bytes of the v0.1.x prefix
  were always zero, giving free DPI fingerprint material at the start
  of every record; the 3-byte prefix uses every byte for real entropy.

### Changed — KDF labels (M2)

- All v2.1-introduced HKDF info strings embed the version banner
  `ewp/v2.1` (e.g. `ewp/v2.1 outer aead`, `ewp/v2.1 sid`).
- The legacy v2.0 per-direction labels (`EWPv2 c2s key` etc.) are
  preserved verbatim for FrameAEAD bytewise interoperability of
  internal test fixtures, but no v0.2.0 wire path consumes a key
  derived under them — the post-handshake session keys are produced
  via the v2.1 chain.

### Removed

- **`tmp_rovodev_audit_test.go`** — the historical pre-fix
  vulnerability reproduction harness used during the audit. Its
  reproductions are now retained as inverse "fix-verifies" inside
  `audit_fixes_test.go` and `audit_fixes_v2_test.go`, which together
  contain 20 strict regression tests covering the 12 audit findings.

### Performance

Measured on `AMD EPYC 7543` (4 vCPU container), `go test -bench`,
`-benchtime=2s`:

| Benchmark                   | v0.1.x      | v0.2.0      | Δ      |
|-----------------------------|------------:|------------:|--------|
| Handshake encode (client)   | 184 µs      | 211 µs      | +15 %  |
| Handshake accept (server)   | 227 µs      | 304 µs      | +34 %  |
| Frame encode (1 KiB)        | 2 112 ns    | (identical) | 0 %    |
| Frame decode (1 KiB)        | 734 ns      | (identical) | 0 %    |
| ReplayCache admit (4 P)     | n/a (single-mutex) | 12.9 µs/op, 0 alloc | — |

The handshake adds two X25519 static-ECDHs (one per side); the data
path is unchanged and still pushes 1.4 GB/s decode on a single core.

### Security findings closed

| ID  | Severity | Finding                                             |
|-----|----------|-----------------------------------------------------|
| S1  | critical | UUID-only key derivation allowed offline ClientHello decryption |
| S2  | critical | PSK alone could impersonate the server              |
| H1  | high     | Destination address in clear-text (verified absent) |
| H2  | high     | OuterMAC did not bind the inner ciphertext length   |
| H3  | high     | session\_id was a stable per-user fingerprint       |
| H4  | high     | Unknown-PSK probes triggered ECDH/ML-KEM work       |
| H5  | high     | FrameRekey was a no-op                              |
| L1  | low      | UDP packet replay (already covered by frame counter) |
| M1  | medium   | 4-byte length prefix had two constant zero bytes    |
| M2  | medium   | KDF labels lacked version banner                    |
| M3  | medium   | ReplayCache claimed-but-not-actually sharded        |
| M4  | medium   | 120 s timestamp window + skew/replay error oracle   |

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
