# Upgrading sing-ewp

## v0.1.x → v0.2.0  (EWP/v2 → EWP/v2.1)

> ⚠️ **Cryptographic break.** v0.2.0 derives every handshake key
> differently from v0.1.x and additionally requires a long-term
> server-side X25519 keypair. Mixed deployments **cannot interoperate**;
> a v0.2.0 server returns `ErrOuterMAC` to every v0.1.x ClientHello,
> and a v0.1.x server cannot decrypt a v0.2.0 ClientHello. Plan a
> synchronized upgrade.

### Why this break exists

v0.1.x derived the handshake AEAD key and outer MAC key purely from
the user UUID (= PSK). This made two practical attacks possible:

- **Offline decryption (S1).** Anyone who ever held the UUID could
  later, without observing the handshake live, decrypt every recorded
  `ClientHello` and recover its inner contents (timestamp, command,
  destination address, padding).
- **Server impersonation (S2).** Any holder of the UUID could complete
  a handshake from the server side; there was no notion of "server
  identity" to bind against.

v0.2.0 fixes both by mixing a long-term server X25519 static-ECDH
share into the handshake KDF chain. An attacker without the server's
static private key can neither decrypt a captured `ClientHello` nor
impersonate the server. See `CHANGELOG.md` for the full list of 12
findings closed.

### What changed on the wire

| Field                                | v0.1.2                       | v0.2.0                       |
|--------------------------------------|------------------------------|------------------------------|
| `ClientHello` byte layout            | nonce ‖ classical ‖ pq ‖ ctLen ‖ inner ‖ MAC | **identical** |
| `ServerHello` byte layout            | nonce ‖ classical ‖ pqCipher ‖ time ‖ status ‖ MAC | **identical** |
| Handshake-AEAD key derivation        | `HKDF(SHA256(UUID), nonce, "EWPv2 handshake aead")` | `HKDF(staticECDH ‖ SHA256(UUID), salt, "ewp/v2.1 outer aead")` |
| Outer MAC                            | `HMAC(SHA256(UUID), msg)[:16]` | `HMAC(macKey, be64(innerCTLen) ‖ msg)[:16]` where `macKey` is itself derived from `staticECDH` |
| `LengthFramer` prefix length         | 4 bytes big-endian (high 2 bytes always zero) | **3 bytes** big-endian |
| `SessionKeys` size                   | 4 fields                     | adds `SessionID [8]byte`     |

The wire bytes of `ClientHello` and `ServerHello` are arranged
identically; only the keys used to encrypt and authenticate them
differ. This means a v0.1.x packet on the wire is structurally
parseable by a v0.2.0 server, but the outer MAC fails closed.

### What you have to do

1. **Generate a server static keypair (once per deployment).**

   ```go
   privB64, pubB64, err := ewp.GenerateServerStaticKeypair()
   // privB64 → server config (file mode 0600)
   // pubB64  → distributed to every authorised client
   ```

   You can also generate offline:

   ```bash
   go run -tags none . <<'EOF'
   package main
   import (
       "fmt"
       "github.com/justinwoo280/sing-ewp"
   )
   func main() {
       priv, pub, _ := ewp.GenerateServerStaticKeypair()
       fmt.Println("priv =", priv)
       fmt.Println("pub  =", pub)
   }
   EOF
   ```

2. **Switch every server constructor to `NewServiceV21`.**

   ```diff
   - svc := ewp.NewService(handler)
   + svc, err := ewp.NewServiceV21(handler, staticPrivB64)
   + if err != nil { return err }
   ```

3. **Switch every client constructor to `NewClientV21`.**

   ```diff
   - cli, err := ewp.NewClient(uuidStr)
   + cli, err := ewp.NewClientV21(uuidStr, serverStaticPubB64)
   ```

4. **Distribute `serverStaticPubB64` to your clients out-of-band**
   (the same channel you already use to provision UUIDs).

5. **Coordinate the cutover.** A mixed deployment surfaces only as
   handshake failures (`ewp/v2.1: accept ClientHello: ewp/v2: outer
   MAC verification failed`). The wire bytes do flow once, but no
   data is exchanged.

6. **No persistent state needs to be migrated.** Replay caches,
   session keys, and per-stream counters all live for the lifetime of
   a single connection; restarting the process discards them. There
   is no on-disk format to upgrade.

7. **Tighten your timestamp budget.** `HandshakeTimestampWindow`
   dropped from 120 s to 30 s. Make sure NTP is running on every host
   that participates in the handshake.

### What you get

- **Server identity binding.** A leaked UUID no longer compromises
  past traffic and cannot impersonate the server going forward.
- **Truncation-resistant outer MAC.** Any byte-length mutation of the
  inner ciphertext is detected.
- **Unlinkable `SessionID`.** Two handshakes from the same user yield
  different session ids; safe for logs.
- **Real anti-replay sharding.** `ReplayCache` admits scale across
  cores; the previous single-mutex design did not.
- **Fewer DPI fingerprints.** The 3-byte length prefix removes the
  always-zero high bytes; the v2.1 KDF salt eliminates correlated
  bits in derived keys.
- **`Rekey()` actually rotates keys.** Long-lived sessions can ask
  for forward secrecy of session keys; the receiver rotates
  transparently.

### What can go wrong (and how to spot it)

| Symptom                                                     | Cause                                                    | Fix                                                        |
|-------------------------------------------------------------|----------------------------------------------------------|------------------------------------------------------------|
| `ewp/v2.1: accept ClientHello: outer MAC verification failed` on every connect | Mixed v0.1.x ↔ v0.2.0 deployment                        | Roll v0.2.0 to all peers in the same window                |
| `ewp/v2.1: server_static_priv: invalid server static private key` | Wrong-length scalar in server config                     | Re-generate via `GenerateServerStaticKeypair`              |
| `ewp/v2.1: x25519 keygen` errors on client                  | OS RNG unavailable                                       | Out-of-scope; investigate the host                         |
| `ErrReplay` on the very first handshake                     | Client clock skew > 30 s                                 | Run NTP, or temporarily widen via a future config knob     |
| Tests that asserted on `ErrTimestamp`                       | The sentinel still exists but is no longer returned      | Update assertions to `ErrReplay` (see `v2_test.go`)        |

---

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
