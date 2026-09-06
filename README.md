# `protocol/ewp/v2` — EWP v2 protocol package

> ## Security status
>
> EWP/v2.2 adds padded opaque data-plane records to the pinned-server-identity
> handshake. New deployments must use `NewClientV22` / `NewServiceV22`; v2.1
> remains only for coordinated migration and still exposes exact data-plane
> frame structure. The legacy `NewClient` / `NewService` APIs are deprecated
> and do not authenticate the server.
>
> The current implementation is **not approved for strict-security
> deployment**. v2.2 mitigates data-plane exact-length exposure, but it does
> not provide ClientHello metadata forward secrecy after a static-key
> compromise, distributed replay protection, a Finished exchange, or
> pre-authentication DoS resistance. See
> `SECURITY_AUDIT_BASELINE_AND_REMEDIATION_PLAN.md` before deployment.
>
> v2.2 protects post-handshake data frames against a later compromise of the
> server static key, subject to the stated cryptographic assumptions. It does
> not provide post-compromise recovery; `Rekey` is one-way key evolution.

This package is the **single source of truth** for EWP v2 wire bytes,
key derivation, framing, and the encrypted bidirectional stream that
sits on top of an outer transport.

The v2.2 record format is documented in [`EWP_V22.md`](EWP_V22.md).
This file is the **API surface contract** for callers in the same
binary (TUN handler, server dispatcher, transports, ewpmobile).

Source-file ownership (which files are v2.0/2.1/2.2/2.3-specific vs
shared, and the version-reuse relationships between them) is mapped in
[`CODE_MAP.md`](CODE_MAP.md).

## Protocol Layers

`ClientHello` and `ServerHello` in this package mean **EWP protocol messages**.
They are distinct from `TLS ClientHello` and `TLS ServerHello`. When TLS is
used, TLS is the optional outer transport and EWP starts after that transport
is established:

```text
TLS ClientHello / TLS ServerHello
    -> EWP ClientInit / EWP HelloRetry
    -> EWP ClientHello / EWP ServerHello
    -> EWP ClientFinished / EWP ServerFinished
    -> EWP encrypted records
```

The audit findings about ClientHello metadata, replay, cookies, and Finished
messages refer to the EWP layer. TLS adds transport protection but does not
replace those EWP protocol controls.

---

## Architectural rules — read these before touching anything

These are not suggestions. Future code that violates them will be
rejected on review.

### Rule 1 — One unified kernel, no client/server split

There is **one** `protocol/ewp/v2` implementation. Both the client side
and the server side use the same code path: same handshake helpers,
same SecureStream, same frame codec, same KDF.

The asymmetry between the two sides exists only at the **direction
labels** for the keys (`C2SKey` / `S2CKey`) and at the entry point
(`WriteClientHello` vs `AcceptClientHello`). Everything below is
shared.

DO NOT:

* fork this package into a `serverv2` / `clientv2` / `mobilev2`.
* duplicate handshake or frame logic in `internal/server/` or in
  `tun/` or in any `transport/*` directory.
* introduce a "client-only optimisation" or "server-only optimisation"
  that requires divergent code paths.

If a feature genuinely needs to behave differently on the two sides,
express that with a parameter or a small role-aware helper inside this
package, not by forking the package.

### Rule 2 — No plaintext fallback, ever

There is no "direct copy" / "vision" / "skip-AEAD" branch in this
package. If a future PR adds one, it is wrong. Reject it. The point
of v2 is that every byte after the handshake is authenticated and
encrypted.

### Rule 3 — Transports must not understand protocol bytes

Transports below this package (WebSocket, gRPC, H3-gRPC-Web, xhttp
stream-one) must implement only `MessageTransport`:

```go
type MessageTransport interface {
    SendMessage(b []byte) error
    ReadMessage() ([]byte, error)
    Close() error
}
```

A "message" is one atomic blob delivered as-is. Transports do not look
at the bytes, do not pad them, do not split them, do not coalesce
them. All padding / framing / encryption is this package's job.

### Rule 4 — No silent version fallback

Wire revisions have distinct derivations and no automatic fallback. A peer
that does not use the configured revision must fail closed; do not probe a
legacy revision after a v2.2 handshake failure.

---

## Public API at a glance

### Handshake

```go
// CLIENT side: serverStaticPub must be pinned from trusted configuration.
state, err := v2.WriteClientHelloV22(send, uuid, v2.CommandTCP|CommandUDP, addr, serverStaticPub)
//   send is the transport's SendMessage. Returns ClientHandshakeState
//   that holds the ephemeral keys until ServerHello arrives.

result, err := state.ReadServerHelloV22(serverHelloMsg, serverStaticPub)
//   result.Keys is the SessionKeys to feed NewClientSecureStreamV22.

// SERVER side
helloOut, result, err := v2.AcceptClientHelloV22WithReplay(clientHelloMsg, lookup, serverStaticPriv, replayCache)
//   lookup := v2.MakeUUIDLookupV21([]uuid)
//   server then SendMessage(helloOut) and uses result.Keys.
```

### SecureStream

```go
// One per outer transport connection.
ss, err := v2.NewClientSecureStreamV22(transport, sessionKeys)
ss, err := v2.NewServerSecureStreamV22(transport, sessionKeys)

// TCP-style bytes
err := ss.SendTCPData(payload)

// UDP sub-sessions multiplex inside one SecureStream
gid := v2.NewGlobalID()
err := ss.SendUDPNew(gid, target, initialDatagram)
err := ss.SendUDPData(gid, perFrameTarget, payload)  // perFrameTarget zero == use sub-session default
err := ss.SendUDPEnd(gid)

// NAT consistency
err := ss.SendProbeReq(gid)
err := ss.SendProbeResp(gid, observedAddr)

// Liveness
err := ss.SendPing(cookie)
err := ss.SendPong(cookie)

// Cover traffic
err := ss.SendCoverPad(padBytes)

// Receive (a single dispatcher is recommended for event ordering)
ev, err := ss.Recv()
//   ev.Type, ev.GlobalID, ev.Address, ev.HasAddr, ev.Payload

// Lifecycle
err := ss.Close()
b, B, fIn, fOut := ss.Stats()
```

### Address

```go
addr := v2.Address{Addr: netip.MustParseAddrPort("8.8.8.8:53")}
addr := v2.Address{Domain: "example.com", Port: 443}

buf, err := addr.Append(buf)
addr, n, err := v2.DecodeAddress(buf)
```

### Frame primitives (you almost never need these directly)

`FrameAEAD`, `EncodeFrameV22`, `DecodeFrameV22`, `SuggestPadLen`,
`NewGlobalID`. SecureStream wraps these. Direct use is reserved for
tests and the rare protocol diagnostic.

---

## Cryptographic primitives — fixed, not configurable

| Purpose | Algorithm |
|---|---|
| AEAD | ChaCha20-Poly1305 |
| Classical KEM | X25519 |
| PQ KEM | ML-KEM-768 |
| KDF | HKDF-SHA-256 |
| Outer handshake MAC | HMAC-SHA-256 / 16 |

These are not negotiated. They are nailed in §1 of the wire spec.

## Measured performance (AMD EPYC 7543, single core, Go 1.25.5)

| Op | ns/op | throughput | allocs |
|---|---|---|---|
| Handshake (client+server) | 605 µs | — | 197 |
| Handshake client-only | 174 µs | — | 42 |
| Frame encode 1 KiB | 2.1 µs | 477 MB/s | 4 |
| Frame encode 16 KiB | 21 µs | 772 MB/s | 4 |

Mobile ARM (extrapolated):
* Flagship A78 / Apple-M: handshake ~300 µs, 1 KiB frame ~3 µs.
* Mid-range A55: handshake ~700 µs, 1 KiB frame ~10 µs.

Both are an order of magnitude below TLS 1.3 setup latency itself, so
the PQ overhead is invisible to users.

---

## File layout

```
address.go      Address codec (IPv4 / IPv6 / domain).
aead.go         Tiny chacha20poly1305 wrapper to keep imports tidy.
frame.go        Legacy clear-header frame codec + per-direction AEAD.
frame_v22.go    Opaque v2.2 record codec.
handshake.go    ClientHello / ServerHello + X25519 + ML-KEM-768.
handshake_v22.go v2.2 handshake wrappers and version boundary.
kdf.go          HKDF-based key & MAC derivation; constants & magic.
securestream.go High-level Send*/Recv API used by everything else.
v2_test.go      11 tests covering correctness + replay + tampering +
                NoPlaintextOnWire.
bench_test.go   Microbenchmarks (handshake & frame throughput).
```

---

## Concurrency model

* `SecureStream.Send*` methods are safe for concurrent calls. They
  serialise internally via `writeMu` so the AEAD counter and the wire
  ordering stay consistent.
* `SecureStream.Recv` serializes concurrent calls internally. A single
  reader remains the recommended model for predictable event ordering.
* `SecureStream.Close` is idempotent and safe from any goroutine.
* `FrameAEAD` itself is not goroutine-safe. SecureStream is the only
  entry point that touches it; do not share a `FrameAEAD` across
  goroutines manually.

## Error contract

Any error returned by `SecureStream.Recv` other than the trivial
"transport closed cleanly" case (you'll see it as `io.EOF` or
`io.ErrClosedPipe`) means **the connection is dead**. Do not retry on
the same SecureStream. Specifically:

* `ErrCounterMismatch` — the peer is replaying or reordering. Tear
  down.
* AEAD open failure (wrapped as `ErrAEADOpen` from `frame.go`) — the
  peer is tampering or has a bug. Tear down.
* `ErrFrameType` / `ErrFrameTooLarge` / `ErrFrameTooShort` /
  `ErrMetaTooLarge` / `ErrPadTooLarge` — wire-format violation. Tear
  down.

These errors deliberately do not carry recovery hints. There is no
recovery.
