# EWP Code Map (0.2.x branch)

This file is the authoritative inventory of which source files belong to
which protocol version and which are shared infrastructure. It exists so
contributors can navigate the single-package layout without guessing, and so
dead-version removal is a lookup rather than an archaeology project.

> **Why a single package with no subdirectories?** Go visibility is
> package-scoped. The versions share a dense web of unexported symbols
> (`FrameAEAD`, `deriveSessionKeys`, `writeClientHelloV2x`, `streamConn`,
> `packetConn`, padding/shaping internals). Splitting into subpackages would
> require exporting or duplicating that web — churn with no security or
> performance upside. Version ownership is therefore tracked *here*, not by
> directory.

## Layer diagram

```
┌─────────────────────────────────────────────────────────────┐
│ Application adapters (net.Conn / net.PacketConn)            │
│   client.go: streamConn, LengthFramer                       │
│   packetconn.go: packetConn (UDP)                           │
├─────────────────────────────────────────────────────────────┤
│ Data plane (record AEAD, streams, shaping)                  │
│   frame.go: FrameAEAD + legacy record codec                 │
│   frame_v22.go: opaque record codec                         │
│   securestream.go: SecureStream                             │
│   padding_policy.go, opening_scheme.go, traffic_shaper.go   │
├─────────────────────────────────────────────────────────────┤
│ Handshakes (per version)                                    │
│   v2.0: handshake.go                                        │
│   v2.1: handshake_v21.go (shared v2x core)                  │
│   v2.2: handshake_v22.go (thin wrapper over v2x core)       │
│   v2.3: handshake_v23.go (six-stage, self-contained)        │
├─────────────────────────────────────────────────────────────┤
│ High-level APIs (per version)                               │
│   v2.0: client.go + server.go                               │
│   v2.1: client_v21.go   v2.2: client_v22.go                 │
│   v2.3: client_v23.go                                       │
├─────────────────────────────────────────────────────────────┤
│ Shared crypto/utilities                                     │
│   kdf.go, aead.go, address.go, anti_replay.go,              │
│   handshake_context.go, protocol_v22.go, protocol_v23.go    │
└─────────────────────────────────────────────────────────────┘
```

## File-by-file ownership

### Shared infrastructure (every version depends on these)

| File | Contents | Consumers |
|------|----------|-----------|
| `address.go` | `Address` codec (IPv4/IPv6/domain), package doc | all versions |
| `aead.go` | `newHandshakeAEAD` (ChaCha20-Poly1305 for handshake) | v2.1/v2.2 (via v2x core), v2.3 |
| `kdf.go` | KDF constants, `uuidPSK`, `DeriveSessionKeys` (v2.0/2.1), `DeriveSessionKeysV22` (v2.2) | all; v2.3 uses `uuidPSK` only (own schedule in `handshake_v23.go`) |
| `frame.go` | `FrameAEAD` (per-direction AEAD + counter + scratch), legacy clear-header codec `EncodeFrame`/`DecodeFrame` | `FrameAEAD`: all versions; legacy codec: v2.0/v2.1 streams only |
| `securestream.go` | `SecureStream` (frame dispatch, rekey, stats, record selection) | all versions |
| `packetconn.go` | UDP `net.PacketConn` adapter, bounded-close UDP_END | all versions |
| `padding_policy.go` | bucket ladder + bucket-up + jitter, handshake floor | all versions (v2.2/v2.3 via `suggestStreamPadV22`) |
| `traffic_shaper.go` | write coalescing + idle cover traffic | client streams (v2.0/v2.1/v2.3 install it) |
| `client.go` (partial) | `streamConn` (net.Conn over SecureStream, onClose hook), `LengthFramer` | v2.0/v2.1/v2.3 |
| `server.go` (partial) | `Handler` interface | all Service types (v2.0/v2.1/v2.2/v2.3) |
| `anti_replay.go` | `ReplayCache` (sharded, bounded, GC'd) | v2.1/v2.2/v2.3 handshakes |
| `handshake_context.go` | `beginHandshake` deadline guard | v2.1, v2.3 |
| `protocol_v22.go` | `protocolVersion` type, `v21Suite`/`v22Suite`, `ErrProtocolVersion` | v2.1/v2.2/v2.3 (v2.3 tags sessions `protocolVersionV22`) — *misleading filename, it hosts both suites* |

### v2.0 (legacy, deprecated)

| File | Contents | Notes |
|------|----------|-------|
| `handshake.go` | v2.0 handshake: `WriteClientHello`, `AcceptClientHello`, `ClientHandshakeState.ReadServerHello`, shared `Metadata`/error set | used by v2.0 Client/Service; error values reused by later versions |
| `client.go` (partial) | legacy `Client`/`NewClient` | Deprecated |
| `server.go` (partial) | legacy `Service`/`NewService` | Deprecated |

### v2.1

| File | Contents | Notes |
|------|----------|-------|
| `handshake_v21.go` | v2.1 handshake API **plus the shared `writeClientHelloV2x`/`acceptClientHelloV2x` core used by v2.2**, v2.1 label constants | the v2x core is v2.1+v2.2 shared code physically hosted here |
| `client_v21.go` | `ClientV21`/`ServiceV21`, replay wiring | |

### v2.2

| File | Contents | Notes |
|------|----------|-------|
| `handshake_v22.go` | thin v2.2 wrappers (`WriteClientHelloV22`, `AcceptClientHelloV22Strict`, …) over the v2x core with `v22Suite` | no independent crypto here |
| `client_v22.go` | `ClientV22`/`ServiceV22` thin constructors | |
| `frame_v22.go` | **v2.2 opaque record codec** (`EncodeFrameV22`/`DecodeFrameV22`), `MaxV22RecordSize` | introduced by v2.2, **reused as the v2.3 data plane** — do not delete with v2.2 |

### v2.3 (current)

| File | Contents | Notes |
|------|----------|-------|
| `protocol_v23.go` | v2.3 label suite, wire-length constants, `ErrV23*` sentinels | |
| `handshake_v23.go` | six-stage handshake (ClientInit/HelloRetry/ClientHello/ServerHello/ClientFinished/ServerFinished), stateless cookie, outer-key store, admission control, transcript binding, replay cache wiring | self-contained except `aead.go`, `anti_replay.go`, `handshake_context.go` |
| `client_v23.go` | `ClientV23`/`ServiceV23`/`GenerateSigningIdentity`, transport handoff (onClose wait) | |
| `opening_scheme.go` | per-connection opening-phase refragmentation (AnyTLS-style) | used by v2.2/v2.3 SecureStreams |

### Version-reuse relationships (the subtle ones)

1. **v2.3 rides the v2.2 record layer.** `deriveV23SessionKeys` tags
   sessions `protocolVersionV22`, so `SecureStream.usesV22Records()` selects
   `frame_v22.go`. Deleting "v2.2" means deleting handshakes/clients, NOT
   `frame_v22.go` or `protocol_v22.go`.
2. **v2.2 handshake crypto lives in `handshake_v21.go`.** The `v2x` core is
   parameterised by `protocolSuite`; `handshake_v22.go` is a wrapper.
   Removing v2.1 means either keeping the v2x core (if v2.2 stays) or
   removing both together.
3. **`protocol_v22.go` hosts v2.1's suite too** (`v21Suite`,
   `protocolVersionV21`). The name is historical.
4. **`client.go`/`server.go` are v2.0 files that host shared types.**
   `streamConn`, `LengthFramer` (client.go) and `Handler` (server.go) are
   consumed by v2.1/v2.2/v2.3; deleting v2.0 means extracting those, which
   is why v2.0 was left in place.

## Test file ownership

| File(s) | Scope |
|---------|-------|
| `v2_test.go`, `client_server_test.go` | v2.0 + shared streams |
| `audit_fixes_test.go`, `audit_fixes_v2_test.go`, `security_regression_test.go`, `hardening_test.go`, `anti_replay_test.go` | cross-version security regressions |
| `v22_test.go`, `zz_flush_handshake_test.go` | v2.2 (+ shared v2x) |
| `v23_test.go`, `v23_fuzz_test.go`, `v23_invariants_fuzz_test.go`, `v23_crypto_kat_test.go`, `v23_bench_test.go` | v2.3 |
| `opening_scheme_test.go`, `padding_policy_test.go`, `padding_policy_bench_test.go`, `traffic_shaper_test.go`, `packetconn_close_test.go` | shared data-plane components |
| `bench_test.go`, `audit_bench_test.go` | cross-version benchmarks (v2.0/v2.1 paths) |

## If a version is ever retired

- **Retire v2.3**: delete `protocol_v23.go`, `handshake_v23.go`,
  `client_v23.go`, `v23_*_test.go`, `opening_scheme*` is v2.2-shared so it
  stays.
- **Retire v2.2**: delete `handshake_v22.go`, `client_v22.go`,
  `v22_test.go`, and the `v22Suite` half of `protocol_v22.go` — **keep**
  `frame_v22.go` and `protocolVersionV22` while v2.3 lives.
- **Retire v2.1**: delete `client_v21.go`, the v2.1 entry points in
  `handshake_v21.go` and `v21Suite`; the v2x core must be *kept* if v2.2
  stays (it is v2.2's implementation).
- **Retire v2.0**: extract `streamConn`, `LengthFramer`, `Handler` to a
  shared file first, then delete `handshake.go`, legacy Client/Service,
  `DeriveSessionKeys` (v2.0/2.1-only) and the legacy codec in `frame.go`
  (keep `FrameAEAD`).
