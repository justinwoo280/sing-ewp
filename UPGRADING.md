# Upgrading sing-ewp

## v0.1.1 → v0.1.2

> ⚠️ **Wire-format break.** Servers and clients running v0.1.2 cannot
> talk to peers still on v0.1.1. Plan a synchronized upgrade.

### What changed on the wire

| Field                          | v0.1.1                       | v0.1.2                       |
|--------------------------------|------------------------------|------------------------------|
| `ClientHello[0:4]`             | plaintext `"EWP2"` magic     | first 4 bytes of nonce       |
| `ServerHello[0:4]`             | plaintext `"EWP2"` magic     | first 4 bytes of `NonceEcho` |
| Total `ClientHello` length     | `4 + (rest)`                 | `(rest)` (4 bytes shorter)   |
| Total `ServerHello` length     | `4 + (rest)`                 | `(rest)` (4 bytes shorter)   |

Everything else — UUID format, AEAD primitive, KDF, frame layout, and
session-key derivation — is **identical**.

### What you have to do

1. **Update both ends to v0.1.2 in the same maintenance window.**
   A mixed deployment will look exactly like a peer with the wrong
   PSK: TLS connects, the handshake bytes flow once, then the server
   closes (it will treat your old `EWP2` bytes as a corrupted nonce
   and the outer MAC fails).
2. **No configuration changes.** UUIDs are unchanged; the option
   schemas in your front-end (e.g. sing-box) are unchanged.
3. **If you wrote your own tests against the magic field**, switch to
   asserting on `ErrOuterMAC` for tampered leading bytes (see
   `TestHandshake_TamperedLeadingBytesRejected`). The exported
   `ErrMagic` sentinel still exists for source-compatibility but the
   decoder no longer returns it.

### What you get

- **No more 4-byte protocol fingerprint at offset 0** of every
  ClientHello — the first 12 bytes are now uniformly random.
- **Replay-of-ClientHello is now `O(1)` to reject** instead of forcing
  the server through a full X25519 + ML-KEM-768 encapsulation.
- **Out-of-window `ServerHello.ServerTime`** now causes the client to
  abort the handshake before doing any decapsulation work.

See `CHANGELOG.md` (English) or `CHANGELOG.zh.md` (中文) for the full
list of changes and the security rationale.

### Optional: keep replay protection enabled (it is, by default)

`NewService` now installs a `ReplayCache(ReplayWindow)` automatically.
You only need to call `SetReplayCache` if you want to:

- Disable it (e.g. in benchmarks where you replay a captured
  handshake on purpose) — pass `nil`.
- Install a cache with a different window or your own GC strategy.

```go
svc := ewp.NewService(handler)
// Default: anti-replay on, window = 180s.

// Override for a high-RTT link with permissive ts-window:
svc.SetReplayCache(ewp.NewReplayCache(5 * time.Minute))

// Disable for tests only:
svc.SetReplayCache(nil)
```
